//! Exact on-disk cursor history. Only bounded pending payloads are materialized.
//!
//! The original journal path is a small versioned marker. Migration publishes
//! that marker only after the uniquely named database is committed, closed and
//! synchronized. An interrupted migration leaves the version-one source intact;
//! an interrupted acknowledgement is recovered by SQLite before custody is read.

use super::*;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

const DATABASE_VERSION: u32 = 2;
const APPLICATION_ID: i64 = 1_178_816_581;
const MIN_DATABASE_BYTES: u64 = 1024 * 1024;
const MAX_DATABASE_PAGES: u64 = 4_294_967_294;
const ROLLBACK_RETENTION_BYTES: u64 = 64 * 1024 * 1024;
const MARKER_MAX_BYTES: u64 = 4096;

pub(super) fn validate_database_budget(max_bytes: u64) -> HostResult<()> {
    if !(MIN_DATABASE_BYTES..=MAX_DATABASE_PAGES * 4096).contains(&max_bytes) {
        return Err(invalid(
            "event database budget must be between 1 MiB and SQLite's page limit",
        ));
    }
    Ok(())
}

// Sequences are unsigned protocol values, not SQLite signed integers. Both
// native and consumer sequences use fixed-width, big-endian eight-byte blobs.
// The rowid is only an insertion-order index, never a protocol identity.
const SCHEMA: &str = "
CREATE TABLE journal_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    identity TEXT NOT NULL CHECK(length(identity) = 64),
    pending_bytes INTEGER NOT NULL CHECK(pending_bytes BETWEEN 0 AND 16777216)
) STRICT;
CREATE TABLE streams (
    stream_id TEXT PRIMARY KEY NOT NULL CHECK(length(stream_id) BETWEEN 1 AND 128),
    principal TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    zone_id TEXT NOT NULL,
    topic TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    attachment_epoch INTEGER NOT NULL DEFAULT 0 CHECK(attachment_epoch >= 0),
    window_size INTEGER NOT NULL CHECK(window_size BETWEEN 1 AND 64),
    closed INTEGER NOT NULL CHECK(closed IN (0, 1)),
    pending_count INTEGER NOT NULL CHECK(pending_count BETWEEN 0 AND window_size),
    receipt_count INTEGER NOT NULL CHECK(receipt_count >= 0)
) STRICT;
CREATE UNIQUE INDEX active_source ON streams(connector_id, zone_id)
    WHERE closed = 0 OR pending_count > 0;
CREATE INDEX active_stream ON streams(stream_id)
    WHERE closed = 0 OR pending_count > 0;
CREATE TABLE events (
    ordinal INTEGER PRIMARY KEY,
    stream_id TEXT NOT NULL REFERENCES streams(stream_id),
    cursor TEXT NOT NULL CHECK(length(CAST(cursor AS BLOB)) BETWEEN 1 AND 1024),
    delivery_seq BLOB NOT NULL CHECK(length(delivery_seq) = 8),
    native_seq BLOB CHECK(native_seq IS NULL OR length(native_seq) = 8),
    native_instance TEXT,
    native_epoch INTEGER CHECK(native_epoch IS NULL OR native_epoch >= 0),
    digest TEXT NOT NULL CHECK(length(digest) = 64),
    event_json BLOB,
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes BETWEEN 0 AND 262144),
    delivered INTEGER NOT NULL CHECK(delivered IN (0, 1)),
    CHECK((native_seq IS NULL) = (native_instance IS NULL)),
    CHECK((native_seq IS NULL) = (native_epoch IS NULL)),
    CHECK((event_json IS NULL AND payload_bytes = 0 AND delivered = 1)
       OR (event_json IS NOT NULL AND length(event_json) = payload_bytes AND payload_bytes > 0)),
    UNIQUE(stream_id, cursor)
) STRICT;
CREATE INDEX pending_event ON events(stream_id, ordinal) WHERE event_json IS NOT NULL;
";

#[derive(Debug)]
pub(super) enum Failure {
    Rejected(HostError),
    Storage,
}

impl From<HostError> for Failure {
    fn from(error: HostError) -> Self {
        Self::Rejected(error)
    }
}

impl From<rusqlite::Error> for Failure {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

pub(super) type SqlResult<T> = Result<T, Failure>;

fn open_error(error: Failure) -> HostError {
    match error {
        Failure::Rejected(error) => error,
        Failure::Storage => unavailable("event journal database could not be safely opened"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u32,
    backend: String,
    database: String,
    identity: String,
}

impl Marker {
    fn validate(&self) -> HostResult<()> {
        if self.version != DATABASE_VERSION
            || self.backend != "sqlite"
            || self.identity.len() != 64
            || !self
                .identity
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.database != format!("native-events-{}.sqlite3", self.identity)
        {
            return Err(invalid("event journal database marker is invalid"));
        }
        Ok(())
    }
}

pub(super) struct SqliteJournal {
    connection: Connection,
    marker: Marker,
    marker_path: PathBuf,
    marker_file: File,
    database_path: PathBuf,
    database_file: File,
}

impl SqliteJournal {
    pub(super) fn open(path: &Path, max_bytes: u64, allow_initialize: bool) -> HostResult<Self> {
        validate_database_budget(max_bytes)?;
        let bytes = match std::fs::symlink_metadata(path) {
            Ok(_) => {
                let file = private_existing_file(path)?;
                let mut bytes = Vec::new();
                file.take((NATIVE_EVENT_MAX_SNAPSHOT_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| unavailable("event journal could not be read"))?;
                if bytes.len() > NATIVE_EVENT_MAX_SNAPSHOT_BYTES {
                    return Err(invalid(
                        "event journal exceeds its legacy snapshot byte limit",
                    ));
                }
                Some(bytes)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !allow_initialize {
                    return Err(unavailable(
                        "event journal marker is missing for an existing writer lock; restore or reconcile persisted state before reopening",
                    ));
                }
                None
            }
            Err(_) => return Err(unavailable("event journal could not be inspected")),
        };
        let marker = if let Some(bytes) = bytes {
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("event journal has invalid persisted data"))?;
            match value.get("version").and_then(serde_json::Value::as_u64) {
                Some(1) => {
                    let snapshot: JournalSnapshot = serde_json::from_value(value)
                        .map_err(|_| invalid("event journal has invalid legacy data"))?;
                    validate_snapshot(&snapshot)?;
                    snapshot_bytes(&snapshot)?;
                    Self::migrate(path, &snapshot, max_bytes).map_err(open_error)?
                }
                Some(2) => {
                    if bytes.len() as u64 > MARKER_MAX_BYTES {
                        return Err(invalid("event journal marker exceeds its byte limit"));
                    }
                    let marker: Marker = serde_json::from_value(value)
                        .map_err(|_| invalid("event journal database marker is invalid"))?;
                    marker.validate()?;
                    marker
                }
                _ => return Err(invalid("unsupported event journal format")),
            }
        } else {
            Self::migrate(path, &JournalSnapshot::default(), max_bytes).map_err(open_error)?
        };
        let database_path = parent_directory(path).join(&marker.database);
        let database_file = private_existing_file(&database_path)?;
        inspect_sidecars(&database_path).map_err(open_error)?;
        let connection = connect(&database_path, max_bytes).map_err(open_error)?;
        verify_database(&connection, &marker).map_err(open_error)?;
        database_file
            .sync_all()
            .map_err(|_| unavailable("event journal database cannot be synchronized"))?;
        sync_directory(parent_directory(path))?;
        let marker_file = private_existing_file(path)?;
        let backend = Self {
            connection,
            marker,
            marker_path: path.to_path_buf(),
            marker_file,
            database_path,
            database_file,
        };
        backend.guard_files().map_err(open_error)?;
        Ok(backend)
    }

    fn migrate(path: &Path, snapshot: &JournalSnapshot, max_bytes: u64) -> SqlResult<Marker> {
        // Never reuse a staged filename: a previous failed attempt may contain
        // an incomplete database. It cannot become authoritative without its
        // identity-bound marker, and is deliberately left untouched on failure.
        let identity = blake3::hash(InstanceId::new().as_str().as_bytes())
            .to_hex()
            .to_string();
        let marker = Marker {
            version: DATABASE_VERSION,
            backend: "sqlite".to_owned(),
            database: format!("native-events-{identity}.sqlite3"),
            identity,
        };
        let database_path = parent_directory(path).join(&marker.database);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&database_path).map_err(|_| Failure::Storage)?;
        let mut connection = connect(&database_path, max_bytes)?;
        {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(SCHEMA)?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", DATABASE_VERSION)?;
            transaction.execute(
                "INSERT INTO journal_meta(singleton, identity, pending_bytes) VALUES(1, ?1, ?2)",
                params![marker.identity, snapshot_pending_bytes(snapshot)? as i64],
            )?;
            for (stream_id, record) in &snapshot.streams {
                insert_stream(&transaction, stream_id, record)?;
                for pending in &record.pending {
                    let payload =
                        serde_json::to_vec(&pending.event).map_err(|_| Failure::Storage)?;
                    insert_event(
                        &transaction,
                        stream_id,
                        &pending.event.cursor,
                        pending.event.seq,
                        pending.native_seq,
                        &record.instance_id,
                        &pending.digest,
                        Some(&payload),
                        pending.delivered,
                    )?;
                }
                for receipt in record.acknowledged.values() {
                    insert_event(
                        &transaction,
                        stream_id,
                        &receipt.cursor,
                        receipt.delivery_seq,
                        receipt.native_seq,
                        &record.instance_id,
                        &receipt.digest,
                        None,
                        true,
                    )?;
                }
            }
            transaction.commit()?;
        }
        verify_database(&connection, &marker)?;
        connection.close().map_err(|_| Failure::Storage)?;
        file.sync_all().map_err(|_| Failure::Storage)?;
        sync_directory(parent_directory(path)).map_err(|_| Failure::Storage)?;
        let bytes = serde_json::to_vec(&marker).map_err(|_| Failure::Storage)?;
        persist_bytes(path, &bytes).map_err(|_| Failure::Storage)?;
        Ok(marker)
    }

    fn guard_files(&self) -> SqlResult<()> {
        same_file(&self.marker_path, &self.marker_file)?;
        same_file(&self.database_path, &self.database_file)?;
        inspect_sidecars(&self.database_path)?;
        let mut bytes = Vec::new();
        private_existing_file(&self.marker_path)
            .map_err(|_| Failure::Storage)?
            .take(MARKER_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Storage)?;
        let marker: Marker = serde_json::from_slice(&bytes).map_err(|_| Failure::Storage)?;
        if bytes.len() as u64 > MARKER_MAX_BYTES || marker != self.marker {
            return Err(Failure::Storage);
        }
        Ok(())
    }

    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&Transaction<'_>) -> SqlResult<T>,
    ) -> SqlResult<T> {
        self.guard_files()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        match operation(&transaction) {
            Ok(result) => {
                transaction.commit()?;
                self.guard_files()?;
                Ok(result)
            }
            Err(error) => {
                // A failed rollback fences even an ordinary validation denial.
                transaction.rollback()?;
                Err(error)
            }
        }
    }

    pub(super) fn register(
        &mut self,
        stream_id: &str,
        binding: NativeEventBinding,
        window_size: u32,
        instance_id: InstanceId,
    ) -> SqlResult<NativeEventStream> {
        self.transaction(|transaction| {
            if let Some(mut stream) = find_stream(transaction, stream_id)? {
                authorize(&stream, &binding, None)?;
                if stream.window_size != window_size {
                    return Err(invalid("retained stream window cannot change").into());
                }
                if stream.closed {
                    return Err(unavailable("closed event streams cannot be reopened").into());
                }
                // Native mappings carry their physical instance, so no scan or
                // rewrite of historical cursor receipts is needed on reattach.
                transaction.execute("UPDATE streams SET attachment_epoch = attachment_epoch + (instance_id != ?2), instance_id = ?2 WHERE stream_id = ?1",
                    params![stream_id, instance_id.as_str()])?;
                stream.instance_id = instance_id;
                return Ok(stream);
            }
            let active: i64 = transaction.query_row(
                "SELECT count(*) FROM streams INDEXED BY active_stream WHERE closed = 0 OR pending_count > 0",
                [], |row| row.get(0))?;
            if active >= NATIVE_EVENT_MAX_STREAMS as i64 {
                return Err(unavailable("event journal active stream limit reached").into());
            }
            let overlap: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM streams INDEXED BY active_source WHERE connector_id = ?1 AND zone_id = ?2 AND (closed = 0 OR pending_count > 0))",
                params![binding.connector_id.as_str(), binding.zone_id.as_str()], |row| row.get(0))?;
            if overlap {
                return Err(unavailable("connector already has a retained event consumer").into());
            }
            let record = StreamRecord { binding, instance_id, window_size, closed: false,
                pending: VecDeque::new(), acknowledged: BTreeMap::new() };
            insert_stream(transaction, stream_id, &record)?;
            Ok(stream_view(stream_id, &record, true))
        })
    }

    pub(super) fn describe(&mut self, stream_id: &str) -> SqlResult<NativeEventStream> {
        self.transaction(|transaction| required_stream(transaction, stream_id))
    }

    pub(super) fn ingest(
        &mut self,
        stream_id: &str,
        connector_id: &ConnectorId,
        zone_id: &ZoneId,
        event: EventEnvelope,
        bytes: usize,
        digest: &str,
    ) -> SqlResult<NativeEventAdmission> {
        self.transaction(|transaction| {
            let stream = required_stream(transaction, stream_id)?;
            if stream.binding.connector_id != *connector_id || stream.binding.zone_id != *zone_id
                || event.data.connector_id != *connector_id || event.data.zone_id != *zone_id
                || event.data.instance_id != stream.instance_id || event.topic != stream.binding.topic
            {
                return Err(denied("event source does not match the admitted stream").into());
            }
            if stream.closed { return Err(unavailable("event stream is closed").into()); }
            if let Some(existing) = find_event(transaction, stream_id, &event.cursor)? {
                check_digest(&existing.digest, digest)?;
                let epoch = attachment_epoch(transaction, stream_id)?;
                transaction.execute(
                    "UPDATE events SET native_seq = ?3, native_instance = ?4, native_epoch = ?5 WHERE stream_id = ?1 AND cursor = ?2",
                    params![stream_id, event.cursor, event.seq.to_be_bytes().as_slice(), stream.instance_id.as_str(), epoch])?;
                return Ok(if existing.pending { NativeEventAdmission::DuplicatePending } else {
                    NativeEventAdmission::AlreadyAcknowledged(
                        EventAck::new(&stream.binding.topic, vec![event.seq]).with_cursors(vec![event.cursor]))
                });
            }
            if stream.pending_events >= stream.window_size as usize {
                return Err(unavailable("event consumer acknowledgement window is full").into());
            }
            let pending_bytes: i64 = transaction.query_row(
                "SELECT pending_bytes FROM journal_meta WHERE singleton = 1", [], |row| row.get(0))?;
            if !(0..=NATIVE_EVENT_MAX_PENDING_BYTES as i64).contains(&pending_bytes) { return Err(Failure::Storage); }
            if pending_bytes as usize + bytes > NATIVE_EVENT_MAX_PENDING_BYTES {
                return Err(unavailable("event journal pending byte limit reached").into());
            }
            let payload = serde_json::to_vec(&event).map_err(|_| Failure::Storage)?;
            insert_event(transaction, stream_id, &event.cursor, event.seq, Some(event.seq),
                &stream.instance_id, digest, Some(&payload), false)?;
            transaction.execute("UPDATE streams SET pending_count = pending_count + 1 WHERE stream_id = ?1", [stream_id])?;
            transaction.execute("UPDATE journal_meta SET pending_bytes = pending_bytes + ?1 WHERE singleton = 1", [bytes as i64])?;
            Ok(NativeEventAdmission::Accepted)
        })
    }

    pub(super) fn poll(
        &mut self,
        stream_id: &str,
        binding: &NativeEventBinding,
        expected_instance: &InstanceId,
        limit: usize,
    ) -> SqlResult<NativeEventBatch> {
        self.transaction(|transaction| {
            let stream = required_stream(transaction, stream_id)?;
            authorize(&stream, binding, Some(expected_instance))?;
            let mut events = Vec::new();
            let mut ordinals = Vec::new();
            let mut total_bytes = 0usize;
            {
                let mut statement = transaction.prepare(
                    "SELECT ordinal, cursor, delivery_seq, digest, event_json, payload_bytes FROM events INDEXED BY pending_event WHERE stream_id = ?1 AND event_json IS NOT NULL ORDER BY ordinal LIMIT ?2")?;
                let mut rows = statement.query(params![stream_id, limit as i64])?;
                while let Some(row) = rows.next()? {
                    let bytes: i64 = row.get(5)?;
                    if bytes <= 0 || bytes > NATIVE_EVENT_MAX_BYTES as i64 { return Err(Failure::Storage); }
                    if total_bytes + bytes as usize > 4 * NATIVE_EVENT_MAX_BYTES { break; }
                    let event = pending_from_row(row, &stream)?;
                    total_bytes += bytes as usize;
                    ordinals.push(row.get::<_, i64>(0)?);
                    events.push(event);
                }
            }
            for ordinal in ordinals {
                transaction.execute("UPDATE events SET delivered = 1 WHERE ordinal = ?1", [ordinal])?;
            }
            Ok(NativeEventBatch { stream, events })
        })
    }

    pub(super) fn acknowledge(
        &mut self,
        stream_id: &str,
        binding: &NativeEventBinding,
        expected_instance: &InstanceId,
        ack: &EventAck,
    ) -> SqlResult<EventAck> {
        self.transaction(|transaction| {
            let stream = required_stream(transaction, stream_id)?;
            authorize(&stream, binding, Some(expected_instance))?;
            if ack.topic != stream.binding.topic {
                return Err(denied("acknowledgement topic differs from the admitted stream").into());
            }
            let mut native_seqs = Vec::with_capacity(ack.seqs.len());
            let mut native_cursors = Vec::with_capacity(ack.cursors.len());
            let epoch = attachment_epoch(transaction, stream_id)?;
            for (&sequence, cursor) in ack.seqs.iter().zip(&ack.cursors) {
                let existing = find_event(transaction, stream_id, cursor)?
                    .ok_or_else(|| invalid("acknowledgement identifies an unknown event"))?;
                if existing.delivery_seq != sequence || !existing.delivered {
                    return Err(invalid("acknowledgement must match an event delivered to this consumer").into());
                }
                if existing.native_instance.as_deref() == Some(stream.instance_id.as_str())
                    && existing.native_epoch == Some(epoch)
                    && let Some(native_seq) = existing.native_seq
                {
                    native_seqs.push(native_seq);
                    native_cursors.push(cursor.clone());
                }
                if existing.pending {
                    // The receipt is the same cursor row: ACK frees its payload
                    // instead of allocating a separate historical receipt.
                    transaction.execute(
                        "UPDATE events SET event_json = NULL, payload_bytes = 0 WHERE stream_id = ?1 AND cursor = ?2",
                        params![stream_id, cursor])?;
                    transaction.execute(
                        "UPDATE streams SET pending_count = pending_count - 1, receipt_count = receipt_count + 1 WHERE stream_id = ?1", [stream_id])?;
                    transaction.execute("UPDATE journal_meta SET pending_bytes = pending_bytes - ?1 WHERE singleton = 1", [existing.bytes])?;
                }
            }
            Ok(EventAck::new(&stream.binding.topic, native_seqs).with_cursors(native_cursors))
        })
    }

    pub(super) fn close(
        &mut self,
        stream_id: &str,
        binding: &NativeEventBinding,
        expected_instance: &InstanceId,
    ) -> SqlResult<NativeEventStream> {
        self.transaction(|transaction| {
            let mut stream = required_stream(transaction, stream_id)?;
            authorize(&stream, binding, Some(expected_instance))?;
            transaction.execute(
                "UPDATE streams SET closed = 1 WHERE stream_id = ?1",
                [stream_id],
            )?;
            stream.closed = true;
            Ok(stream)
        })
    }
}

fn connect(path: &Path, max_bytes: u64) -> SqlResult<Connection> {
    // A marker target is never opened with CREATE. A missing database must not
    // become a fresh empty journal that forgets prior acknowledgements.
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "mmap_size", 0)?;
    connection.pragma_update(None, "cache_size", -8192)?;
    connection.pragma_update(None, "journal_mode", "PERSIST")?;
    connection.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
    connection.pragma_update(None, "synchronous", "EXTRA")?;
    connection.pragma_update(None, "journal_size_limit", ROLLBACK_RETENTION_BYTES as i64)?;
    let page_size: u32 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let page_count: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    if page_size == 0 || page_count < 0 {
        return Err(Failure::Storage);
    }
    let pages = max_bytes / u64::from(page_size);
    let file_bytes = std::fs::metadata(path).map_err(|_| Failure::Storage)?.len();
    if pages == 0
        || pages > MAX_DATABASE_PAGES
        || page_count as u64 > pages
        || file_bytes > max_bytes
    {
        return Err(invalid("configured event database budget is smaller than the database or exceeds its page limit").into());
    }
    connection.pragma_update(None, "max_page_count", pages as i64)?;
    let actual: i64 = connection.pragma_query_value(None, "max_page_count", |row| row.get(0))?;
    if actual != pages as i64 {
        return Err(Failure::Storage);
    }
    Ok(connection)
}

fn insert_stream(
    transaction: &Transaction<'_>,
    stream_id: &str,
    record: &StreamRecord,
) -> SqlResult<()> {
    transaction.execute(
        "INSERT INTO streams(stream_id, principal, connector_id, zone_id, topic, instance_id, window_size, closed, pending_count, receipt_count) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![stream_id, record.binding.principal, record.binding.connector_id.as_str(), record.binding.zone_id.as_str(), record.binding.topic, record.instance_id.as_str(), record.window_size, record.closed, record.pending.len() as i64, record.acknowledged.len() as i64])?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_event(
    transaction: &Transaction<'_>,
    stream_id: &str,
    cursor: &str,
    delivery_seq: u64,
    native_seq: Option<u64>,
    instance: &InstanceId,
    digest: &str,
    payload: Option<&[u8]>,
    delivered: bool,
) -> SqlResult<()> {
    let delivery = delivery_seq.to_be_bytes();
    let native = native_seq.map(u64::to_be_bytes);
    let epoch = attachment_epoch(transaction, stream_id)?;
    transaction.execute(
        "INSERT INTO events(stream_id, cursor, delivery_seq, native_seq, native_instance, digest, event_json, payload_bytes, delivered, native_epoch) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![stream_id, cursor, delivery.as_slice(), native.as_ref().map(<[u8; 8]>::as_slice), native_seq.map(|_| instance.as_str()), digest, payload, payload.map_or(0, |bytes| bytes.len() as i64), delivered, native_seq.map(|_| epoch)])?;
    Ok(())
}

fn find_stream(connection: &Connection, stream_id: &str) -> SqlResult<Option<NativeEventStream>> {
    let row = connection.query_row(
        "SELECT principal, connector_id, zone_id, topic, instance_id, window_size, closed, pending_count, receipt_count FROM streams WHERE stream_id = ?1",
        [stream_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, u32>(5)?, row.get::<_, bool>(6)?, row.get::<_, i64>(7)?, row.get::<_, i64>(8)?))).optional()?;
    let Some((principal, connector, zone, topic, instance, window_size, closed, pending, receipts)) =
        row
    else {
        return Ok(None);
    };
    let binding = NativeEventBinding {
        principal,
        connector_id: connector.parse().map_err(|_| Failure::Storage)?,
        zone_id: zone.parse().map_err(|_| Failure::Storage)?,
        topic,
    };
    validate_stream_id(stream_id).map_err(|_| Failure::Storage)?;
    validate_binding(&binding).map_err(|_| Failure::Storage)?;
    validate_identifier(&instance, "connector instance identifier")
        .map_err(|_| Failure::Storage)?;
    if !(1..=NATIVE_EVENT_MAX_WINDOW).contains(&window_size)
        || pending < 0
        || pending > i64::from(window_size)
        || receipts < 0
    {
        return Err(Failure::Storage);
    }
    Ok(Some(NativeEventStream {
        stream_id: stream_id.to_owned(),
        binding,
        instance_id: instance.parse().map_err(|_| Failure::Storage)?,
        window_size,
        pending_events: usize::try_from(pending).map_err(|_| Failure::Storage)?,
        acknowledged_events: usize::try_from(receipts).map_err(|_| Failure::Storage)?,
        closed,
        durable: true,
    }))
}

fn required_stream(connection: &Connection, stream_id: &str) -> SqlResult<NativeEventStream> {
    find_stream(connection, stream_id)?.ok_or_else(|| invalid("event stream does not exist").into())
}

fn authorize(
    stream: &NativeEventStream,
    binding: &NativeEventBinding,
    expected: Option<&InstanceId>,
) -> HostResult<()> {
    if stream.binding != *binding {
        return Err(denied(
            "event stream belongs to a different consumer or scope",
        ));
    }
    if expected.is_some_and(|expected| stream.instance_id != *expected) {
        return Err(denied(
            "event stream instance changed after authorization; verify the current instance and retry",
        ));
    }
    Ok(())
}

struct StoredEvent {
    delivery_seq: u64,
    native_seq: Option<u64>,
    native_instance: Option<String>,
    native_epoch: Option<i64>,
    digest: String,
    bytes: i64,
    delivered: bool,
    pending: bool,
}

fn decode_sequence(bytes: &[u8]) -> SqlResult<u64> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| Failure::Storage)?,
    ))
}

fn find_event(
    connection: &Connection,
    stream_id: &str,
    cursor: &str,
) -> SqlResult<Option<StoredEvent>> {
    let row = connection.query_row(
        "SELECT delivery_seq, native_seq, native_instance, digest, payload_bytes, delivered, event_json IS NOT NULL, native_epoch FROM events WHERE stream_id = ?1 AND cursor = ?2",
        params![stream_id, cursor], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, String>(3)?, row.get::<_, i64>(4)?, row.get::<_, bool>(5)?, row.get::<_, bool>(6)?, row.get::<_, Option<i64>>(7)?))).optional()?;
    let Some((delivery, native, native_instance, digest, bytes, delivered, pending, native_epoch)) =
        row
    else {
        return Ok(None);
    };
    if native.is_some() != native_instance.is_some()
        || native.is_some() != native_epoch.is_some()
        || native_epoch.is_some_and(|epoch| epoch < 0)
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || bytes < 0
        || bytes > NATIVE_EVENT_MAX_BYTES as i64
        || (!pending && (bytes != 0 || !delivered))
    {
        return Err(Failure::Storage);
    }
    Ok(Some(StoredEvent {
        delivery_seq: decode_sequence(&delivery)?,
        native_seq: native.as_deref().map(decode_sequence).transpose()?,
        native_instance,
        native_epoch,
        digest,
        bytes,
        delivered,
        pending,
    }))
}

fn attachment_epoch(connection: &Connection, stream_id: &str) -> SqlResult<i64> {
    let epoch: i64 = connection.query_row(
        "SELECT attachment_epoch FROM streams WHERE stream_id = ?1",
        [stream_id],
        |row| row.get(0),
    )?;
    if epoch < 0 {
        return Err(Failure::Storage);
    }
    Ok(epoch)
}

fn pending_from_row(
    row: &rusqlite::Row<'_>,
    stream: &NativeEventStream,
) -> SqlResult<EventEnvelope> {
    let cursor: String = row.get(1)?;
    let sequence: Vec<u8> = row.get(2)?;
    let digest: String = row.get(3)?;
    let payload: Vec<u8> = row.get(4)?;
    let bytes: i64 = row.get(5)?;
    let event: EventEnvelope = serde_json::from_slice(&payload).map_err(|_| Failure::Storage)?;
    if bytes <= 0
        || bytes as usize != payload.len()
        || validate_event(&event).map_err(|_| Failure::Storage)? != bytes as usize
        || event.cursor != cursor
        || event.seq != decode_sequence(&sequence)?
        || event.topic != stream.binding.topic
        || event.data.connector_id != stream.binding.connector_id
        || event.data.zone_id != stream.binding.zone_id
        || event_digest(&event).map_err(|_| Failure::Storage)? != digest
    {
        return Err(Failure::Storage);
    }
    Ok(event)
}

fn verify_database(connection: &Connection, marker: &Marker) -> SqlResult<()> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if version != DATABASE_VERSION || application != APPLICATION_ID {
        return Err(Failure::Storage);
    }
    let integrity: String =
        connection.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(Failure::Storage);
    }
    if connection.prepare("PRAGMA foreign_key_check")?.exists([])? {
        return Err(Failure::Storage);
    }
    let (identity, pending_bytes): (String, i64) = connection.query_row(
        "SELECT identity, pending_bytes FROM journal_meta WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if identity != marker.identity {
        return Err(Failure::Storage);
    }
    let metadata_count: i64 =
        connection.query_row("SELECT count(*) FROM journal_meta", [], |row| row.get(0))?;
    let active: i64 = connection.query_row(
        "SELECT count(*) FROM streams INDEXED BY active_stream WHERE closed = 0 OR pending_count > 0", [], |row| row.get(0))?;
    let actual_bytes: i64 = connection.query_row(
        "SELECT coalesce(sum(payload_bytes), 0) FROM events INDEXED BY pending_event WHERE event_json IS NOT NULL", [], |row| row.get(0))?;
    if metadata_count != 1
        || active > NATIVE_EVENT_MAX_STREAMS as i64
        || pending_bytes != actual_bytes
        || !(0..=NATIVE_EVENT_MAX_PENDING_BYTES as i64).contains(&actual_bytes)
    {
        return Err(Failure::Storage);
    }
    let inconsistent: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM streams s WHERE s.pending_count != (SELECT count(*) FROM events e INDEXED BY pending_event WHERE e.stream_id = s.stream_id AND e.event_json IS NOT NULL) OR s.receipt_count != (SELECT count(*) FROM events e WHERE e.stream_id = s.stream_id) - s.pending_count)", [], |row| row.get(0))?;
    if inconsistent {
        return Err(Failure::Storage);
    }
    // Read metadata one record at a time, including retired IDs. Cursor history
    // stays in its disk index; only bounded pending payloads are decoded.
    let mut statement = connection.prepare("SELECT stream_id FROM streams")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let stream_id: String = row.get(0)?;
        let stream = required_stream(connection, &stream_id)?;
        let mut pending = connection.prepare(
            "SELECT ordinal, cursor, delivery_seq, digest, event_json, payload_bytes FROM events INDEXED BY pending_event WHERE stream_id = ?1 AND event_json IS NOT NULL ORDER BY ordinal")?;
        let mut pending_rows = pending.query([&stream_id])?;
        while let Some(pending_row) = pending_rows.next()? {
            pending_from_row(pending_row, &stream)?;
        }
    }
    Ok(())
}

fn private_existing_file(path: &Path) -> HostResult<File> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| unavailable("event journal storage path is absent or inaccessible"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("event journal storage must be a regular file"));
    }
    let file = open_private_file(path, false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|_| unavailable("event journal storage metadata is inaccessible"))?;
        if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(invalid(
                "event journal storage must be private and have one link",
            ));
        }
    }
    Ok(file)
}

fn same_file(path: &Path, expected: &File) -> SqlResult<()> {
    // Do not open and close another descriptor for the database here: POSIX
    // closes can release this process's SQLite byte-range locks on that inode.
    let actual = std::fs::symlink_metadata(path).map_err(|_| Failure::Storage)?;
    if !actual.is_file() || actual.file_type().is_symlink() {
        return Err(Failure::Storage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let expected = expected.metadata().map_err(|_| Failure::Storage)?;
        if actual.dev() != expected.dev()
            || actual.ino() != expected.ino()
            || actual.mode() & 0o077 != 0
            || actual.nlink() != 1
        {
            return Err(Failure::Storage);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (actual, expected);
        return Err(Failure::Storage);
    }
    Ok(())
}

fn inspect_sidecars(path: &Path) -> SqlResult<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                if suffix != "-journal" {
                    return Err(Failure::Storage);
                }
                private_existing_file(Path::new(&sidecar)).map_err(|_| Failure::Storage)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Failure::Storage),
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "sqlite_tests.rs"]
mod tests;
