//! Durable, bounded delivery custody for native connector events.
//!
//! Reading a batch never grants upstream credit. The authenticated consumer
//! must acknowledge the exact delivered sequence/cursor pair, and that decision
//! is synchronized to disk before the caller may relay an acknowledgement to
//! the connector. A lost HTTP response therefore causes redelivery, not loss.
//! This is a single-host journal, not a mesh-replicated replay service.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fcp_core::{ConnectorId, EventAck, EventEnvelope, InstanceId, ZoneId};
use serde::{Deserialize, Serialize};

use crate::{HostError, HostResult};

/// Maximum number of retained logical streams, including closed streams.
pub const NATIVE_EVENT_MAX_STREAMS: usize = 64;
/// Maximum outstanding events negotiated for one logical stream.
pub const NATIVE_EVENT_MAX_WINDOW: u32 = 64;
/// Maximum serialized size of an individual event.
pub const NATIVE_EVENT_MAX_BYTES: usize = 256 * 1024;
/// Maximum serialized event payload bytes retained across all streams.
pub const NATIVE_EVENT_MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;
/// Maximum persisted snapshot size, including acknowledgement receipts.
pub const NATIVE_EVENT_MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
/// Maximum exact cursor receipts retained by one logical stream.
///
/// Receipts are never silently evicted: exhaustion stops ingestion until the
/// stream is explicitly retired. This bounds the supported deduplication
/// horizon without treating an unknown old cursor as safely acknowledged.
pub const NATIVE_EVENT_MAX_RECEIPTS: usize = 16_384;

const SNAPSHOT_VERSION: u32 = 1;
const MAX_IDENTIFIER_BYTES: usize = 1024;
// A pending event's cursor becomes a map key as well as receipt metadata.
// Reserve more than that worst-case growth before accepting the event so a
// near-full snapshot cannot subsequently refuse its consumer acknowledgement.
const ACK_RESERVATION_BYTES: usize = MAX_IDENTIFIER_BYTES * 6 + 512;

/// Authority established by the host's capability and zone-policy admission.
///
/// Constructing this value does not verify a capability. Every consumer-facing
/// call must first establish fresh authority and then pass the resulting
/// binding. Tokens and credentials are deliberately absent from persisted data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEventBinding {
    /// Verified capability subject, never a caller-asserted header.
    pub principal: String,
    /// Connector admitted by the host.
    pub connector_id: ConnectorId,
    /// Exact zone admitted by the host.
    pub zone_id: ZoneId,
    /// Exact event topic; wildcard subscriptions are not supported here.
    pub topic: String,
}

/// Public metadata for an admitted logical stream.
#[derive(Debug, Clone, Serialize)]
pub struct NativeEventStream {
    /// Stable identifier retained across connector and host restarts.
    pub stream_id: String,
    /// Authenticated owner and exact subscription scope.
    pub binding: NativeEventBinding,
    /// Last process instance admitted by the host after bound verification.
    pub instance_id: InstanceId,
    /// Negotiated maximum outstanding event count.
    pub window_size: u32,
    /// Events still awaiting consumer acknowledgement.
    pub pending_events: usize,
    /// Retained exact acknowledgement receipts.
    pub acknowledged_events: usize,
    /// Whether new upstream events are refused.
    pub closed: bool,
    /// Whether the journal has filesystem durability.
    pub durable: bool,
}

/// A bounded batch. Repeated polling returns unacknowledged events again.
#[derive(Debug, Clone, Serialize)]
pub struct NativeEventBatch {
    /// Stream metadata, including the negotiated window and durability.
    pub stream: NativeEventStream,
    /// Event identities remain stable when a connector restarts its sequence.
    pub events: Vec<EventEnvelope>,
}

/// Result of admitting an event from an attached native connector process.
#[derive(Debug, Clone)]
pub enum NativeEventAdmission {
    /// A new event was durably retained for its consumer.
    Accepted,
    /// The cursor is already pending; it must not consume another credit.
    DuplicatePending,
    /// The consumer already acknowledged this cursor. Relay this acknowledgement
    /// with the current native sequence; do not expose the payload again.
    AlreadyAcknowledged(EventAck),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingEvent {
    event: EventEnvelope,
    native_seq: u64,
    digest: String,
    bytes: usize,
    delivered: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgedEvent {
    cursor: String,
    delivery_seq: u64,
    native_seq: u64,
    digest: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamRecord {
    binding: NativeEventBinding,
    instance_id: InstanceId,
    window_size: u32,
    closed: bool,
    pending: VecDeque<PendingEvent>,
    acknowledged: BTreeMap<String, AcknowledgedEvent>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalSnapshot {
    version: u32,
    streams: BTreeMap<String, StreamRecord>,
}

impl Default for JournalSnapshot {
    fn default() -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            streams: BTreeMap::new(),
        }
    }
}

struct JournalState {
    snapshot: JournalSnapshot,
    persistence_failed: bool,
}

/// Single-writer journal for native stream custody and consumer decisions.
///
/// Mutations perform no async suspension between validation and publication.
/// A failed or uncertain write fences the whole instance until reopened so an
/// old in-memory snapshot cannot erase a potentially committed acknowledgement.
pub struct NativeEventJournal {
    state: Mutex<JournalState>,
    path: Option<PathBuf>,
    _writer_lock: Option<File>,
}

impl NativeEventJournal {
    /// Construct a non-durable journal for explicitly ephemeral deployments.
    #[must_use]
    pub fn memory() -> Self {
        Self {
            state: Mutex::new(JournalState {
                snapshot: JournalSnapshot::default(),
                persistence_failed: false,
            }),
            path: None,
            _writer_lock: None,
        }
    }

    /// Open or create a private, exclusively owned durable journal.
    ///
    /// # Errors
    /// Fails on an occupied writer lock, invalid/oversized persisted state,
    /// symlinks, or an unsupported durable filesystem platform.
    pub fn open(path: PathBuf) -> HostResult<Self> {
        if !cfg!(unix) {
            return Err(unavailable(
                "durable event delivery requires directory synchronization",
            ));
        }
        let parent = parent_directory(&path);
        create_private_directories(parent)?;
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let writer_lock = open_private_file(Path::new(&lock_path), true)?;
        writer_lock
            .try_lock()
            .map_err(|_| unavailable("event journal already has a writer"))?;
        let snapshot = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(invalid("event journal must be a regular file"));
                }
                let file = open_private_file(&path, false)?;
                let mut bytes = Vec::new();
                file.take((NATIVE_EVENT_MAX_SNAPSHOT_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| unavailable("event journal could not be read"))?;
                if bytes.len() > NATIVE_EVENT_MAX_SNAPSHOT_BYTES {
                    return Err(invalid("event journal exceeds its snapshot byte limit"));
                }
                let snapshot: JournalSnapshot = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("event journal has invalid persisted data"))?;
                validate_snapshot(&snapshot)?;
                snapshot
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                JournalSnapshot::default()
            }
            Err(_) => return Err(unavailable("event journal could not be inspected")),
        };
        // Re-synchronize a valid recovered snapshot before trusting decisions
        // whose previous writer may have lost the result of its final sync.
        persist_snapshot(&path, &snapshot)?;
        Ok(Self {
            state: Mutex::new(JournalState {
                snapshot,
                persistence_failed: false,
            }),
            path: Some(path),
            _writer_lock: Some(writer_lock),
        })
    }

    /// Register a logical stream, or reattach an identical retained binding.
    ///
    /// A connector/zone has one active consumer. Existing payloads and exact
    /// receipts survive reattachment, including a new subprocess instance. The
    /// caller must verify the consumer capability against `instance_id` before
    /// calling this method; reattachment updates the persisted instance binding.
    ///
    /// # Errors
    /// Rejects conflicting ownership, scope/window changes and exhausted limits.
    pub fn register(
        &self,
        stream_id: &str,
        binding: NativeEventBinding,
        window_size: u32,
        instance_id: InstanceId,
    ) -> HostResult<NativeEventStream> {
        validate_stream_id(stream_id)?;
        validate_binding(&binding)?;
        validate_identifier(instance_id.as_str(), "connector instance identifier")?;
        if !(1..=NATIVE_EVENT_MAX_WINDOW).contains(&window_size) {
            return Err(invalid("event window must be between 1 and 64"));
        }
        self.mutate(|snapshot| {
            if let Some(record) = snapshot.streams.get_mut(stream_id) {
                check_binding(record, &binding)?;
                if record.window_size != window_size {
                    return Err(invalid("retained stream window cannot change"));
                }
                if record.closed {
                    return Err(unavailable("closed event streams cannot be reopened"));
                }
                // The host must verify the capability against the newly
                // observed instance before replacing this admission. Retained
                // payloads keep their original provenance and delivery IDs.
                record.instance_id = instance_id;
                return Ok(stream_view(stream_id, record, self.path.is_some()));
            }
            if snapshot.streams.len() >= NATIVE_EVENT_MAX_STREAMS {
                return Err(unavailable("event journal stream limit reached"));
            }
            if snapshot.streams.values().any(|record| {
                record.binding.connector_id == binding.connector_id
                    && record.binding.zone_id == binding.zone_id
                    && (!record.closed || !record.pending.is_empty())
            }) {
                return Err(unavailable(
                    "connector already has a retained event consumer",
                ));
            }
            let record = StreamRecord {
                binding,
                instance_id,
                window_size,
                closed: false,
                pending: VecDeque::new(),
                acknowledged: BTreeMap::new(),
            };
            let view = stream_view(stream_id, &record, self.path.is_some());
            snapshot.streams.insert(stream_id.to_owned(), record);
            Ok(view)
        })
    }

    /// Inspect a retained stream's scope before performing fresh authorization.
    ///
    /// This returns no event payload. The host must not use knowledge of the
    /// stream identifier itself as permission to read or acknowledge events.
    ///
    /// # Errors
    /// Fails if the stream is absent or persistence is fenced.
    pub fn describe(&self, stream_id: &str) -> HostResult<NativeEventStream> {
        let state = self.lock()?;
        let record = stream_record(&state.snapshot, stream_id)?;
        Ok(stream_view(stream_id, record, self.path.is_some()))
    }

    /// Admit one event from a process attached to the requested connector/zone.
    ///
    /// The transport must independently fence retired subprocess generations.
    /// A stable provider cursor is authoritative across process restarts; a new
    /// native sequence is remembered without changing the consumer's identity.
    ///
    /// # Errors
    /// Rejects authority mismatches, missing acknowledgement semantics,
    /// conflicting cursor payloads, full windows, and exhausted storage limits.
    pub fn ingest(
        &self,
        stream_id: &str,
        connector_id: &ConnectorId,
        zone_id: &ZoneId,
        event: EventEnvelope,
    ) -> HostResult<NativeEventAdmission> {
        let bytes = validate_event(&event)?;
        let digest = event_digest(&event)?;
        self.mutate(|snapshot| {
            let pending_bytes = snapshot_pending_bytes(snapshot)?;
            let record = stream_record_mut(snapshot, stream_id)?;
            if record.binding.connector_id != *connector_id
                || record.binding.zone_id != *zone_id
                || event.data.connector_id != *connector_id
                || event.data.zone_id != *zone_id
                || event.data.instance_id != record.instance_id
                || event.topic != record.binding.topic
            {
                return Err(denied("event source does not match the admitted stream"));
            }
            if record.closed {
                return Err(unavailable("event stream is closed"));
            }
            if let Some(receipt) = record.acknowledged.get_mut(&event.cursor) {
                check_digest(&receipt.digest, &digest)?;
                receipt.native_seq = event.seq;
                return Ok(NativeEventAdmission::AlreadyAcknowledged(
                    EventAck::new(&record.binding.topic, vec![event.seq])
                        .with_cursors(vec![event.cursor.clone()]),
                ));
            }
            if let Some(pending) = record
                .pending
                .iter_mut()
                .find(|pending| pending.event.cursor == event.cursor)
            {
                check_digest(&pending.digest, &digest)?;
                pending.native_seq = event.seq;
                return Ok(NativeEventAdmission::DuplicatePending);
            }
            if record.pending.len() >= record.window_size as usize {
                return Err(unavailable("event consumer acknowledgement window is full"));
            }
            // Reserve receipt capacity when admitting the event so exhaustion
            // can never prevent acknowledging an already delivered payload.
            if record.acknowledged.len() + record.pending.len() >= NATIVE_EVENT_MAX_RECEIPTS {
                return Err(unavailable("event cursor receipt capacity reached"));
            }
            if pending_bytes.saturating_add(bytes) > NATIVE_EVENT_MAX_PENDING_BYTES {
                return Err(unavailable("event journal pending byte limit reached"));
            }
            record.pending.push_back(PendingEvent {
                native_seq: event.seq,
                event,
                digest,
                bytes,
                delivered: false,
            });
            Ok(NativeEventAdmission::Accepted)
        })
    }

    /// Return a bounded batch without releasing connector credit.
    ///
    /// Delivery is recorded before the batch is returned. If the HTTP response
    /// is lost, polling again returns the same original sequence/cursor pairs.
    ///
    /// # Errors
    /// Rejects a changed consumer/scope, invalid limits, or persistence failure.
    pub fn poll(
        &self,
        stream_id: &str,
        binding: &NativeEventBinding,
        expected_instance: &InstanceId,
        limit: usize,
    ) -> HostResult<NativeEventBatch> {
        if limit == 0 || limit > NATIVE_EVENT_MAX_WINDOW as usize {
            return Err(invalid("event poll limit must be between 1 and 64"));
        }
        self.mutate(|snapshot| {
            let record = stream_record_mut(snapshot, stream_id)?;
            check_binding(record, binding)?;
            check_instance(record, expected_instance)?;
            let mut events = Vec::new();
            let mut bytes = 0usize;
            for pending in record.pending.iter_mut().take(limit) {
                // Bound one consumer response independently of the global
                // journal. At least one valid maximum-size event always fits.
                if bytes.saturating_add(pending.bytes) > 4 * NATIVE_EVENT_MAX_BYTES {
                    break;
                }
                bytes += pending.bytes;
                pending.delivered = true;
                events.push(pending.event.clone());
            }
            Ok(NativeEventBatch {
                stream: stream_view(stream_id, record, self.path.is_some()),
                events,
            })
        })
    }

    /// Commit consumer acknowledgement and return the current native identity.
    ///
    /// The caller may relay the returned acknowledgement only after this
    /// method succeeds. Duplicate consumer acknowledgements are idempotent;
    /// the connector must likewise release credit once per exact identity.
    ///
    /// # Errors
    /// Rejects mismatched authority, undelivered/unknown events, partial cursor
    /// lists, conflicting pairs, and persistence failure without releasing credit.
    pub fn acknowledge(
        &self,
        stream_id: &str,
        binding: &NativeEventBinding,
        expected_instance: &InstanceId,
        ack: &EventAck,
    ) -> HostResult<EventAck> {
        validate_ack(ack)?;
        self.mutate(|snapshot| {
            let record = stream_record_mut(snapshot, stream_id)?;
            check_binding(record, binding)?;
            check_instance(record, expected_instance)?;
            if ack.topic != record.binding.topic {
                return Err(denied(
                    "acknowledgement topic differs from the admitted stream",
                ));
            }
            let mut native_seqs = Vec::with_capacity(ack.seqs.len());
            for (&sequence, cursor) in ack.seqs.iter().zip(&ack.cursors) {
                if let Some(receipt) = record.acknowledged.get(cursor) {
                    if receipt.delivery_seq != sequence {
                        return Err(invalid(
                            "acknowledgement sequence/cursor pair does not match",
                        ));
                    }
                    native_seqs.push(receipt.native_seq);
                    continue;
                }
                let position = record
                    .pending
                    .iter()
                    .position(|pending| pending.event.cursor == *cursor)
                    .ok_or_else(|| invalid("acknowledgement identifies an unknown event"))?;
                let pending = &record.pending[position];
                if pending.event.seq != sequence || !pending.delivered {
                    return Err(invalid(
                        "acknowledgement must match an event delivered to this consumer",
                    ));
                }
                let pending = record.pending.remove(position).ok_or_else(|| {
                    unavailable("event custody changed while committing acknowledgement")
                })?;
                native_seqs.push(pending.native_seq);
                record.acknowledged.insert(
                    cursor.clone(),
                    AcknowledgedEvent {
                        cursor: cursor.clone(),
                        delivery_seq: sequence,
                        native_seq: pending.native_seq,
                        digest: pending.digest,
                    },
                );
            }
            Ok(EventAck::new(&record.binding.topic, native_seqs).with_cursors(ack.cursors.clone()))
        })
    }

    /// Stop upstream admission while retaining every pending consumer event.
    ///
    /// # Errors
    /// Rejects mismatched authority or persistence failure.
    pub fn close(
        &self,
        stream_id: &str,
        binding: &NativeEventBinding,
        expected_instance: &InstanceId,
    ) -> HostResult<NativeEventStream> {
        self.mutate(|snapshot| {
            let record = stream_record_mut(snapshot, stream_id)?;
            check_binding(record, binding)?;
            check_instance(record, expected_instance)?;
            record.closed = true;
            Ok(stream_view(stream_id, record, self.path.is_some()))
        })
    }

    fn lock(&self) -> HostResult<std::sync::MutexGuard<'_, JournalState>> {
        let state = self
            .state
            .lock()
            .map_err(|_| unavailable("event journal lock is poisoned"))?;
        if state.persistence_failed {
            return Err(unavailable(
                "event journal is fenced after a persistence failure; reopen before use",
            ));
        }
        Ok(state)
    }

    fn mutate<T>(
        &self,
        change: impl FnOnce(&mut JournalSnapshot) -> HostResult<T>,
    ) -> HostResult<T> {
        let mut state = self.lock()?;
        let mut next = state.snapshot.clone();
        let result = change(&mut next)?;
        validate_snapshot(&next)?;
        // Serialization capacity is checked even for an ephemeral journal.
        let bytes = snapshot_bytes(&next)?;
        if let Some(path) = &self.path
            && persist_bytes(path, &bytes).is_err()
        {
            state.persistence_failed = true;
            return Err(unavailable(
                "event journal persistence failed; no upstream acknowledgement is authorized",
            ));
        }
        state.snapshot = next;
        Ok(result)
    }
}

fn stream_view(stream_id: &str, record: &StreamRecord, durable: bool) -> NativeEventStream {
    NativeEventStream {
        stream_id: stream_id.to_owned(),
        binding: record.binding.clone(),
        instance_id: record.instance_id.clone(),
        window_size: record.window_size,
        pending_events: record.pending.len(),
        acknowledged_events: record.acknowledged.len(),
        closed: record.closed,
        durable,
    }
}

fn stream_record<'a>(
    snapshot: &'a JournalSnapshot,
    stream_id: &str,
) -> HostResult<&'a StreamRecord> {
    snapshot
        .streams
        .get(stream_id)
        .ok_or_else(|| invalid("event stream does not exist"))
}

fn stream_record_mut<'a>(
    snapshot: &'a mut JournalSnapshot,
    stream_id: &str,
) -> HostResult<&'a mut StreamRecord> {
    snapshot
        .streams
        .get_mut(stream_id)
        .ok_or_else(|| invalid("event stream does not exist"))
}

fn check_binding(record: &StreamRecord, binding: &NativeEventBinding) -> HostResult<()> {
    if record.binding != *binding {
        return Err(denied(
            "event stream belongs to a different consumer or scope",
        ));
    }
    Ok(())
}

fn check_instance(record: &StreamRecord, expected: &InstanceId) -> HostResult<()> {
    if record.instance_id != *expected {
        return Err(denied(
            "event stream instance changed after authorization; verify the current instance and retry",
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str, kind: &str) -> HostResult<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(invalid(format!("invalid {kind}")));
    }
    Ok(())
}

fn validate_stream_id(stream_id: &str) -> HostResult<()> {
    if stream_id.is_empty()
        || stream_id.len() > 128
        || !stream_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(invalid(
            "stream identifier must contain 1 to 128 ASCII letters, digits, underscores or hyphens",
        ));
    }
    Ok(())
}

fn validate_binding(binding: &NativeEventBinding) -> HostResult<()> {
    validate_identifier(&binding.principal, "consumer principal")?;
    validate_identifier(binding.connector_id.as_str(), "connector identifier")?;
    validate_identifier(binding.zone_id.as_str(), "zone identifier")?;
    validate_identifier(&binding.topic, "event topic")?;
    if binding.topic.contains(['*', '?', '#', '>']) {
        return Err(invalid("event topic must be exact, without wildcards"));
    }
    Ok(())
}

fn validate_event(event: &EventEnvelope) -> HostResult<usize> {
    validate_identifier(&event.cursor, "event cursor")?;
    validate_identifier(&event.topic, "event topic")?;
    if !event.requires_ack {
        return Err(invalid(
            "native event must require consumer acknowledgement",
        ));
    }
    let bytes = serde_json::to_vec(event)
        .map_err(|_| invalid("native event cannot be serialized"))?
        .len();
    if bytes > NATIVE_EVENT_MAX_BYTES {
        return Err(unavailable("native event exceeds its byte limit"));
    }
    Ok(bytes)
}

fn event_digest(event: &EventEnvelope) -> HostResult<String> {
    // Timestamps, subprocess instance IDs and transport sequences can change
    // when the provider redelivers a stable cursor after restart. None grants
    // authority to alter the provider payload or its provenance metadata.
    let data = serde_json::json!({
        "topic": event.topic,
        "cursor": event.cursor,
        "connector_id": event.data.connector_id,
        "zone_id": event.data.zone_id,
        "principal": event.data.principal,
        "payload": event.data.payload,
        "correlation_id": event.data.correlation_id,
        "resource_uris": event.data.resource_uris,
        "thread_info": event.data.thread_info,
        "stream_key": event.stream_key,
        "ordering": event.ordering,
    });
    let bytes = serde_json::to_vec(&data)
        .map_err(|_| invalid("native event identity cannot be serialized"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn check_digest(expected: &str, actual: &str) -> HostResult<()> {
    if expected != actual {
        return Err(invalid(
            "provider cursor was reused with conflicting event content",
        ));
    }
    Ok(())
}

fn validate_ack(ack: &EventAck) -> HostResult<()> {
    if ack.r#type != "ack"
        || ack.seqs.is_empty()
        || ack.seqs.len() > NATIVE_EVENT_MAX_WINDOW as usize
        || ack.seqs.len() != ack.cursors.len()
    {
        return Err(invalid(
            "acknowledgement requires 1 to 64 exact sequence/cursor pairs",
        ));
    }
    let mut cursors = std::collections::BTreeSet::new();
    for cursor in &ack.cursors {
        validate_identifier(cursor, "acknowledgement cursor")?;
        if !cursors.insert(cursor) {
            return Err(invalid("acknowledgement cursors must be unique"));
        }
    }
    Ok(())
}

fn snapshot_pending_bytes(snapshot: &JournalSnapshot) -> HostResult<usize> {
    snapshot
        .streams
        .values()
        .flat_map(|record| &record.pending)
        .try_fold(0usize, |total, pending| {
            total
                .checked_add(pending.bytes)
                .ok_or_else(|| invalid("event journal byte count overflowed"))
        })
}

fn validate_snapshot(snapshot: &JournalSnapshot) -> HostResult<()> {
    if snapshot.version != SNAPSHOT_VERSION || snapshot.streams.len() > NATIVE_EVENT_MAX_STREAMS {
        return Err(invalid("unsupported or oversized event journal snapshot"));
    }
    let mut active_sources = std::collections::BTreeSet::new();
    for (stream_id, record) in &snapshot.streams {
        validate_stream_id(stream_id)?;
        validate_binding(&record.binding)?;
        validate_identifier(record.instance_id.as_str(), "connector instance identifier")?;
        if !(1..=NATIVE_EVENT_MAX_WINDOW).contains(&record.window_size)
            || record.pending.len() > record.window_size as usize
            || record.acknowledged.len() + record.pending.len() > NATIVE_EVENT_MAX_RECEIPTS
        {
            return Err(invalid(
                "persisted event window or receipt limit is invalid",
            ));
        }
        if (!record.closed || !record.pending.is_empty())
            && !active_sources.insert((
                record.binding.connector_id.as_str(),
                record.binding.zone_id.as_str(),
            ))
        {
            return Err(invalid(
                "persisted connector has overlapping event consumers",
            ));
        }
        let mut cursors = std::collections::BTreeSet::new();
        for pending in &record.pending {
            let bytes = validate_event(&pending.event)?;
            if pending.event.topic != record.binding.topic
                || pending.event.data.connector_id != record.binding.connector_id
                || pending.event.data.zone_id != record.binding.zone_id
                || pending.bytes != bytes
                || !cursors.insert(&pending.event.cursor)
                || record.acknowledged.contains_key(&pending.event.cursor)
            {
                return Err(invalid("persisted event custody is inconsistent"));
            }
            check_digest(&pending.digest, &event_digest(&pending.event)?)?;
        }
        for (cursor, receipt) in &record.acknowledged {
            validate_identifier(cursor, "acknowledged cursor")?;
            if *cursor != receipt.cursor
                || receipt.digest.len() != 64
                || !receipt.digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(invalid("persisted event acknowledgement is inconsistent"));
            }
        }
    }
    if snapshot_pending_bytes(snapshot)? > NATIVE_EVENT_MAX_PENDING_BYTES {
        return Err(invalid(
            "persisted event custody exceeds pending byte limit",
        ));
    }
    Ok(())
}

fn snapshot_bytes(snapshot: &JournalSnapshot) -> HostResult<Vec<u8>> {
    let bytes = serde_json::to_vec(snapshot)
        .map_err(|_| invalid("event journal snapshot cannot be serialized"))?;
    let pending = snapshot
        .streams
        .values()
        .map(|record| record.pending.len())
        .sum::<usize>();
    if bytes
        .len()
        .saturating_add(pending.saturating_mul(ACK_RESERVATION_BYTES))
        > NATIVE_EVENT_MAX_SNAPSHOT_BYTES
    {
        return Err(unavailable("event journal snapshot byte limit reached"));
    }
    Ok(bytes)
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn create_private_directories(parent: &Path) -> HostResult<()> {
    let mut missing = Vec::new();
    let mut directory = parent;
    while !directory
        .try_exists()
        .map_err(|_| unavailable("event journal directory cannot be inspected"))?
    {
        missing.push(directory.to_path_buf());
        directory = parent_directory(directory);
    }
    for directory in missing.iter().rev() {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(unavailable("event journal directory cannot be created")),
        }
        sync_directory(parent_directory(directory))?;
    }
    Ok(())
}

fn open_private_file(path: &Path, create: bool) -> HostResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|_| unavailable("event journal file cannot be opened"))?;
    if !file
        .metadata()
        .map_err(|_| unavailable("event journal file cannot be inspected"))?
        .is_file()
    {
        return Err(invalid("event journal path must be a regular file"));
    }
    Ok(file)
}

fn persist_snapshot(path: &Path, snapshot: &JournalSnapshot) -> HostResult<()> {
    persist_bytes(path, &snapshot_bytes(snapshot)?)
}

fn persist_bytes(path: &Path, bytes: &[u8]) -> HostResult<()> {
    let parent = parent_directory(path);
    let mut temporary = tempfile::Builder::new()
        .prefix(".native-events-")
        .tempfile_in(parent)
        .map_err(|_| unavailable("event journal temporary file cannot be created"))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| unavailable("event journal snapshot cannot be synchronized"))?;
    temporary
        .persist(path)
        .map_err(|_| unavailable("event journal snapshot cannot be published"))?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> HostResult<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable("event journal directory cannot be synchronized"))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(unavailable(
            "durable event delivery requires directory synchronization",
        ))
    }
}

fn invalid(reason: impl Into<String>) -> HostError {
    HostError::InvalidFilter(reason.into())
}

fn unavailable(reason: impl Into<String>) -> HostError {
    HostError::Unavailable(reason.into())
}

fn denied(reason: impl Into<String>) -> HostError {
    HostError::PreflightFailed(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{EventData, InstanceId, Principal, TrustLevel};
    use serde_json::json;
    use std::sync::Arc;

    fn binding() -> NativeEventBinding {
        NativeEventBinding {
            principal: "agent:consumer".to_owned(),
            connector_id: ConnectorId::from_static("fcp.telegram:messaging:1.0.0"),
            zone_id: ZoneId::work(),
            topic: "telegram.message.new".to_owned(),
        }
    }

    fn instance_id() -> InstanceId {
        "inst_native_delivery_fixture".parse().unwrap()
    }

    fn event(sequence: u64) -> EventEnvelope {
        let binding = binding();
        EventEnvelope::new(
            &binding.topic,
            EventData::new(
                binding.connector_id,
                instance_id(),
                binding.zone_id,
                Principal {
                    kind: "telegram_user".to_owned(),
                    id: "100".to_owned(),
                    trust: TrustLevel::Untrusted,
                    display: None,
                },
                json!({"message_id":sequence,"text":"provider message"}),
            ),
        )
        .with_seq(sequence)
        .with_cursor(format!("update:{sequence}"))
        .requiring_ack()
    }

    fn register(journal: &NativeEventJournal, window: u32) {
        journal
            .register("stream-1", binding(), window, instance_id())
            .unwrap();
    }

    fn ingest(
        journal: &NativeEventJournal,
        event: EventEnvelope,
    ) -> HostResult<NativeEventAdmission> {
        let binding = binding();
        journal.ingest("stream-1", &binding.connector_id, &binding.zone_id, event)
    }

    fn ack(sequence: u64) -> EventAck {
        EventAck::new(binding().topic, vec![sequence])
            .with_cursors(vec![format!("update:{sequence}")])
    }

    #[test]
    fn polling_never_releases_credit_and_acknowledgement_is_idempotent() {
        let journal = NativeEventJournal::memory();
        register(&journal, 1);
        assert!(matches!(
            ingest(&journal, event(1)).unwrap(),
            NativeEventAdmission::Accepted
        ));
        assert!(ingest(&journal, event(2)).is_err());
        assert!(
            journal
                .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
                .is_err()
        );

        for _ in 0..2 {
            let batch = journal
                .poll("stream-1", &binding(), &instance_id(), 64)
                .unwrap();
            assert_eq!(batch.events.len(), 1);
            assert_eq!(batch.events[0].cursor, "update:1");
            assert_eq!(batch.stream.pending_events, 1);
            assert!(!batch.stream.durable);
            assert!(ingest(&journal, event(2)).is_err());
        }

        let acknowledged = journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .unwrap();
        assert_eq!(acknowledged.seqs, vec![1]);
        assert!(
            journal
                .poll("stream-1", &binding(), &instance_id(), 1)
                .unwrap()
                .events
                .is_empty()
        );
        assert!(matches!(
            ingest(&journal, event(2)).unwrap(),
            NativeEventAdmission::Accepted
        ));
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .unwrap();
        assert!(
            ingest(&journal, event(3)).is_err(),
            "duplicate ACK cannot release another event's slot"
        );
        let view = journal.describe("stream-1").unwrap();
        assert_eq!(view.pending_events, 1);
        assert_eq!(view.acknowledged_events, 1);
    }

    #[test]
    fn consumer_and_source_authority_are_bound_to_exact_scope() {
        let journal = NativeEventJournal::memory();
        register(&journal, 1);
        ingest(&journal, event(1)).unwrap();
        journal
            .poll("stream-1", &binding(), &instance_id(), 1)
            .unwrap();

        let mut wrong = binding();
        wrong.principal = "agent:other".to_owned();
        let mut zone = binding();
        zone.zone_id = ZoneId::owner();
        let mut connector = binding();
        connector.connector_id = ConnectorId::from_static("fcp.other:messaging:1.0.0");
        let mut topic = binding();
        topic.topic = "telegram.callback_query".to_owned();
        for forbidden in [wrong, zone, connector, topic] {
            assert!(
                journal
                    .register("stream-1", forbidden.clone(), 1, instance_id())
                    .is_err()
            );
            assert!(
                journal
                    .poll("stream-1", &forbidden, &instance_id(), 1)
                    .is_err()
            );
            assert!(
                journal
                    .acknowledge("stream-1", &forbidden, &instance_id(), &ack(1))
                    .is_err()
            );
            assert!(
                journal
                    .close("stream-1", &forbidden, &instance_id())
                    .is_err()
            );
        }

        let mut forged = event(2);
        forged.data.zone_id = ZoneId::owner();
        assert!(ingest(&journal, forged).is_err());
        let source = binding();
        assert!(
            journal
                .ingest("stream-1", &source.connector_id, &ZoneId::owner(), event(1))
                .is_err()
        );
        assert_eq!(journal.describe("stream-1").unwrap().pending_events, 1);
        assert_eq!(journal.describe("stream-1").unwrap().acknowledged_events, 0);
    }

    #[test]
    fn cursor_replay_preserves_consumer_identity_and_updates_native_sequence() {
        let journal = NativeEventJournal::memory();
        register(&journal, 1);
        let original = event(42);
        ingest(&journal, original.clone()).unwrap();
        let mut replay = original.clone();
        replay.seq = 1;
        replay.timestamp = chrono::Utc::now();
        replay.data.instance_id = InstanceId::new();
        assert!(ingest(&journal, replay.clone()).is_err());
        journal
            .register("stream-1", binding(), 1, replay.data.instance_id.clone())
            .unwrap();
        let replacement_instance = replay.data.instance_id.clone();
        assert!(matches!(
            ingest(&journal, replay.clone()).unwrap(),
            NativeEventAdmission::DuplicatePending
        ));
        let batch = journal
            .poll("stream-1", &binding(), &replacement_instance, 1)
            .unwrap();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].seq, 42);
        assert_eq!(batch.events[0].data.instance_id, original.data.instance_id);
        let native = journal
            .acknowledge("stream-1", &binding(), &replacement_instance, &ack(42))
            .unwrap();
        assert_eq!(native.seqs, vec![1]);
        assert_eq!(native.cursors, vec!["update:42"]);

        replay.seq = 7;
        match ingest(&journal, replay).unwrap() {
            NativeEventAdmission::AlreadyAcknowledged(native) => {
                assert_eq!(native.seqs, vec![7]);
                assert_eq!(native.cursors, vec!["update:42"]);
            }
            other => panic!("acknowledged replay must not be delivered again: {other:?}"),
        }
        assert!(
            journal
                .poll("stream-1", &binding(), &replacement_instance, 1)
                .unwrap()
                .events
                .is_empty()
        );
        assert_eq!(
            journal
                .acknowledge("stream-1", &binding(), &replacement_instance, &ack(42))
                .unwrap()
                .seqs,
            vec![7]
        );
    }

    #[test]
    fn cursor_conflicts_fail_closed_before_and_after_acknowledgement() {
        let journal = NativeEventJournal::memory();
        register(&journal, 1);
        ingest(&journal, event(1)).unwrap();
        let mut changed = event(1);
        changed.data.payload = json!({"message_id":1,"text":"different content"});
        assert!(ingest(&journal, changed.clone()).is_err());
        journal
            .poll("stream-1", &binding(), &instance_id(), 1)
            .unwrap();
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .unwrap();
        assert!(ingest(&journal, changed).is_err());
        let mut provenance = event(1);
        provenance.data.principal.id = "attacker".to_owned();
        assert!(ingest(&journal, provenance).is_err());
        assert_eq!(journal.describe("stream-1").unwrap().acknowledged_events, 1);
    }

    #[test]
    fn instance_reattachment_fences_previously_verified_consumer_decisions() {
        let journal = NativeEventJournal::memory();
        register(&journal, 1);
        ingest(&journal, event(1)).unwrap();
        let previously_verified = journal.describe("stream-1").unwrap().instance_id;
        journal
            .poll("stream-1", &binding(), &previously_verified, 1)
            .unwrap();
        let replacement = InstanceId::new();
        journal
            .register("stream-1", binding(), 1, replacement.clone())
            .unwrap();
        assert!(
            journal
                .poll("stream-1", &binding(), &previously_verified, 1)
                .is_err()
        );
        assert!(
            journal
                .acknowledge("stream-1", &binding(), &previously_verified, &ack(1))
                .is_err()
        );
        assert!(
            journal
                .close("stream-1", &binding(), &previously_verified)
                .is_err()
        );
        let retained = journal.describe("stream-1").unwrap();
        assert_eq!(retained.pending_events, 1);
        assert_eq!(retained.acknowledged_events, 0);
        assert!(!retained.closed);
        let batch = journal
            .poll("stream-1", &binding(), &replacement, 1)
            .unwrap();
        assert_eq!(batch.events[0].data.instance_id, previously_verified);
        journal
            .acknowledge("stream-1", &binding(), &replacement, &ack(1))
            .unwrap();
    }

    #[test]
    fn acknowledgement_batch_is_atomic_and_requires_exact_delivered_pairs() {
        let journal = NativeEventJournal::memory();
        register(&journal, 2);
        ingest(&journal, event(1)).unwrap();
        ingest(&journal, event(2)).unwrap();
        journal
            .poll("stream-1", &binding(), &instance_id(), 1)
            .unwrap();
        let both = EventAck::new(binding().topic, vec![1, 2])
            .with_cursors(vec!["update:1".to_owned(), "update:2".to_owned()]);
        assert!(
            journal
                .acknowledge("stream-1", &binding(), &instance_id(), &both)
                .is_err()
        );
        assert_eq!(journal.describe("stream-1").unwrap().pending_events, 2);
        assert_eq!(journal.describe("stream-1").unwrap().acknowledged_events, 0);
        let wrong =
            EventAck::new(binding().topic, vec![2]).with_cursors(vec!["update:1".to_owned()]);
        assert!(
            journal
                .acknowledge("stream-1", &binding(), &instance_id(), &wrong)
                .is_err()
        );
        let missing = EventAck::new(binding().topic, vec![1]);
        assert!(
            journal
                .acknowledge("stream-1", &binding(), &instance_id(), &missing)
                .is_err()
        );
        let repeated = EventAck::new(binding().topic, vec![1, 1])
            .with_cursors(vec!["update:1".to_owned(), "update:1".to_owned()]);
        assert!(
            journal
                .acknowledge("stream-1", &binding(), &instance_id(), &repeated)
                .is_err()
        );
        journal
            .poll("stream-1", &binding(), &instance_id(), 2)
            .unwrap();
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &both)
            .unwrap();
        assert_eq!(journal.describe("stream-1").unwrap().acknowledged_events, 2);
    }

    #[test]
    fn journal_rejects_unbounded_or_unacknowledgeable_inputs() {
        let journal = NativeEventJournal::memory();
        for window in [0, NATIVE_EVENT_MAX_WINDOW + 1] {
            assert!(
                journal
                    .register("stream-1", binding(), window, instance_id())
                    .is_err()
            );
        }
        let mut wildcard = binding();
        wildcard.topic = "telegram.*".to_owned();
        assert!(
            journal
                .register("stream-1", wildcard, 1, instance_id())
                .is_err()
        );
        register(&journal, 1);
        assert!(
            journal
                .poll("stream-1", &binding(), &instance_id(), 0)
                .is_err()
        );
        assert!(
            journal
                .poll("stream-1", &binding(), &instance_id(), 65)
                .is_err()
        );
        let mut no_ack = event(1);
        no_ack.requires_ack = false;
        assert!(ingest(&journal, no_ack).is_err());
        let mut no_cursor = event(1);
        no_cursor.cursor.clear();
        assert!(ingest(&journal, no_cursor).is_err());
        let mut oversized = event(1);
        oversized.data.payload = json!({"text":"x".repeat(NATIVE_EVENT_MAX_BYTES)});
        assert!(ingest(&journal, oversized).is_err());
        assert_eq!(journal.describe("stream-1").unwrap().pending_events, 0);
    }

    #[test]
    fn close_preserves_pending_custody_and_prevents_competing_consumer() {
        let journal = NativeEventJournal::memory();
        register(&journal, 1);
        assert!(
            journal
                .register("stream-2", binding(), 1, instance_id())
                .is_err()
        );
        ingest(&journal, event(1)).unwrap();
        journal
            .close("stream-1", &binding(), &instance_id())
            .unwrap();
        assert!(ingest(&journal, event(2)).is_err());
        assert!(
            journal
                .register("stream-1", binding(), 1, instance_id())
                .is_err()
        );
        assert!(
            journal
                .register("stream-2", binding(), 1, instance_id())
                .is_err()
        );
        let batch = journal
            .poll("stream-1", &binding(), &instance_id(), 1)
            .unwrap();
        assert!(batch.stream.closed);
        assert_eq!(batch.events.len(), 1);
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .unwrap();
        journal
            .register("stream-2", binding(), 1, instance_id())
            .unwrap();
        assert_eq!(journal.describe("stream-1").unwrap().acknowledged_events, 1);
    }

    #[test]
    fn receipt_capacity_is_reserved_before_delivery_without_evicting_history() {
        let journal = NativeEventJournal::memory();
        register(&journal, 1);
        {
            let mut state = journal.state.lock().unwrap();
            let record = state.snapshot.streams.get_mut("stream-1").unwrap();
            for seq in 0..NATIVE_EVENT_MAX_RECEIPTS - 1 {
                let cursor = format!("historical:{seq}");
                record.acknowledged.insert(
                    cursor.clone(),
                    AcknowledgedEvent {
                        cursor,
                        delivery_seq: seq as u64,
                        native_seq: seq as u64,
                        digest: "a".repeat(64),
                    },
                );
            }
        }
        ingest(&journal, event(999_999)).unwrap();
        journal
            .poll("stream-1", &binding(), &instance_id(), 1)
            .unwrap();
        journal
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(999_999))
            .unwrap();
        assert!(ingest(&journal, event(1_000_000)).is_err());
        assert_eq!(
            journal.describe("stream-1").unwrap().acknowledged_events,
            NATIVE_EVENT_MAX_RECEIPTS
        );
    }

    #[test]
    fn concurrent_acknowledgements_release_one_slot_and_retain_one_receipt() {
        let journal = Arc::new(NativeEventJournal::memory());
        register(&journal, 1);
        ingest(&journal, event(1)).unwrap();
        journal
            .poll("stream-1", &binding(), &instance_id(), 1)
            .unwrap();
        let threads = (0..4)
            .map(|_| {
                let journal = Arc::clone(&journal);
                std::thread::spawn(move || {
                    journal.acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        ingest(&journal, event(2)).unwrap();
        assert!(ingest(&journal, event(3)).is_err());
        assert_eq!(journal.describe("stream-1").unwrap().acknowledged_events, 1);
    }

    #[cfg(unix)]
    #[test]
    fn durable_restart_redelivers_pending_and_suppresses_acknowledged_cursors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("events.json");
        let journal = NativeEventJournal::open(path.clone()).unwrap();
        register(&journal, 1);
        ingest(&journal, event(42)).unwrap();
        let original = journal
            .poll("stream-1", &binding(), &instance_id(), 1)
            .unwrap();
        assert!(original.stream.durable);
        drop(journal);

        let journal = NativeEventJournal::open(path.clone()).unwrap();
        let replacement_instance = InstanceId::new();
        journal
            .register("stream-1", binding(), 1, replacement_instance.clone())
            .unwrap();
        let replay = journal
            .poll("stream-1", &binding(), &replacement_instance, 1)
            .unwrap();
        assert_eq!(
            serde_json::to_value(original.events).unwrap(),
            serde_json::to_value(replay.events).unwrap()
        );
        journal
            .acknowledge("stream-1", &binding(), &replacement_instance, &ack(42))
            .unwrap();
        drop(journal); // Consumer may not have received the acknowledgement response.

        let journal = NativeEventJournal::open(path).unwrap();
        assert_eq!(
            journal.describe("stream-1").unwrap().instance_id,
            replacement_instance
        );
        journal
            .register("stream-1", binding(), 1, replacement_instance.clone())
            .unwrap();
        assert!(
            journal
                .poll("stream-1", &binding(), &replacement_instance, 1)
                .unwrap()
                .events
                .is_empty()
        );
        let mut redelivered = event(42);
        redelivered.data.instance_id = replacement_instance.clone();
        assert!(matches!(
            ingest(&journal, redelivered).unwrap(),
            NativeEventAdmission::AlreadyAcknowledged(_)
        ));
        assert_eq!(
            journal
                .acknowledge("stream-1", &binding(), &replacement_instance, &ack(42))
                .unwrap()
                .cursors,
            vec!["update:42"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn persistent_writer_lock_excludes_second_writer_and_payload_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.json");
        let journal = NativeEventJournal::open(path.clone()).unwrap();
        register(&journal, 1);
        let before = std::fs::read(&path).unwrap();
        assert!(NativeEventJournal::open(path.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(journal);
        assert!(NativeEventJournal::open(path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn failed_persistence_fences_reads_and_acks_without_forgetting_pending_event() {
        let directory = tempfile::tempdir().unwrap();
        let original_directory = directory.path().join("original");
        let path = original_directory.join("events.json");
        let journal = NativeEventJournal::open(path).unwrap();
        register(&journal, 1);
        ingest(&journal, event(1)).unwrap();
        journal
            .poll("stream-1", &binding(), &instance_id(), 1)
            .unwrap();
        let moved_directory = directory.path().join("moved");
        std::fs::rename(&original_directory, &moved_directory).unwrap();
        assert!(
            journal
                .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
                .is_err()
        );
        assert!(journal.describe("stream-1").is_err());
        assert!(
            journal
                .poll("stream-1", &binding(), &instance_id(), 1)
                .is_err()
        );
        assert!(
            journal
                .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
                .is_err()
        );
        drop(journal);
        let restored = NativeEventJournal::open(moved_directory.join("events.json")).unwrap();
        assert_eq!(restored.describe("stream-1").unwrap().pending_events, 1);
        assert_eq!(
            restored.describe("stream-1").unwrap().acknowledged_events,
            0
        );
        restored
            .acknowledge("stream-1", &binding(), &instance_id(), &ack(1))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn corrupted_or_future_snapshot_is_rejected_without_rewriting_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.json");
        let journal = NativeEventJournal::open(path.clone()).unwrap();
        register(&journal, 1);
        ingest(&journal, event(1)).unwrap();
        drop(journal);
        let mut malformed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        malformed["streams"]["stream-1"]["pending"][0]["digest"] = json!("0".repeat(64));
        let bytes = serde_json::to_vec(&malformed).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(NativeEventJournal::open(path.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        malformed["version"] = json!(SNAPSHOT_VERSION + 1);
        let future = serde_json::to_vec(&malformed).unwrap();
        std::fs::write(&path, &future).unwrap();
        assert!(NativeEventJournal::open(path.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), future);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_journal_and_lock_are_refused_without_touching_targets() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, "do not modify").unwrap();
        let path = directory.path().join("events.json");
        symlink(&target, &path).unwrap();
        assert!(NativeEventJournal::open(path).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "do not modify");
        let lock_path = directory.path().join("other.json.lock");
        symlink(&target, lock_path).unwrap();
        assert!(NativeEventJournal::open(directory.path().join("other.json")).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "do not modify");
    }
}
