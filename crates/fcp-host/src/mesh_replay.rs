//! Restart-safe admission of signed mesh forwards.
//!
//! A nonce is committed and synced before the caller may dispatch its operation.
//! This gives at-most-once admission of an envelope, not exactly-once execution:
//! a crash after the commit but before dispatch can consume an unexecuted call.
//! Lost replies must therefore remain ambiguous; this journal never authorizes
//! resending an operation with a new nonce.
//!
//! The journal contains only domain-separated hashes of origin/nonce pairs and
//! expiry/observation timestamps, never requests, capabilities, or responses.
//! Checksums detect malformed records, not malicious filesystem rollback. Keep
//! the journal on persistent, trusted storage alongside the node identity. Do
//! not delete, restore an older copy, or switch paths while envelopes are live.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use fcp_core::TailscaleNodeId;
use fcp_mesh::invoke_route::{
    DEFAULT_MESH_FORWARD_REPLAY_CAPACITY, MeshForwardEnvelope, MeshForwardError, MeshPeerDirectory,
};

use crate::{HostError, HostResult};

/// Optional journal path for environment-configured mesh routers.
/// Defaults to the signing-key filename with `.mesh-replay` appended.
pub const MESH_REPLAY_JOURNAL_ENV: &str = "FCP_HOST_MESH_REPLAY_JOURNAL";

const MAGIC: &[u8; 8] = b"FCPMRP01";
const HEADER_BODY_LEN: usize = 64;
const HEADER_LEN: usize = HEADER_BODY_LEN + 32;
const RECORD_BODY_LEN: usize = 48;
const RECORD_LEN: usize = RECORD_BODY_LEN + 32;
const MAX_RECORDS: usize = DEFAULT_MESH_FORWARD_REPLAY_CAPACITY * 2;
const MAX_FILE_BYTES: usize = HEADER_LEN + MAX_RECORDS * RECORD_LEN;

type ReplayKey = [u8; 32];

/// An authenticated replay identity, stripped of request and credential bodies.
///
/// Private fields prevent queue callers from constructing an unchecked identity.
/// The receiving journal independently rechecks node scope and freshness after
/// queue/mutex waits; transport authentication alone does not authorize dispatch.
#[derive(Clone)]
pub(crate) struct VerifiedMeshReplayNonce {
    scope: [u8; 32],
    key: ReplayKey,
    origin: String,
    issued_at_ms: u64,
}

impl VerifiedMeshReplayNonce {
    pub(crate) fn verify(
        envelope: &MeshForwardEnvelope,
        directory: &MeshPeerDirectory,
        now_ms: u64,
        window_ms: u64,
    ) -> Result<Self, MeshForwardError> {
        envelope.verify(directory, now_ms, window_ms)?;
        let scope = hash_parts(
            b"FCP-MESH-REPLAY-NODE-V1",
            &[directory.local_node().as_str().as_bytes()],
        );
        Self::from_authenticated(envelope, scope)
    }

    fn from_authenticated(
        envelope: &MeshForwardEnvelope,
        scope: [u8; 32],
    ) -> Result<Self, MeshForwardError> {
        let mut nonce = [0_u8; 16];
        hex::decode_to_slice(&envelope.nonce, &mut nonce).map_err(|_| MeshForwardError::Malformed {
            field: "nonce",
            detail: "expected 16 bytes encoded as hex".to_owned(),
        })?;
        Ok(Self {
            scope,
            key: hash_parts(
                b"FCP-MESH-REPLAY-ID-V1",
                &[envelope.origin_node.as_str().as_bytes(), &nonce],
            ),
            origin: envelope.origin_node.as_str().to_owned(),
            issued_at_ms: envelope.issued_at_ms,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    expires_at_ms: u64,
    observed_at_ms: u64,
}

/// A single-writer, bounded, durable replay guard for one mesh node.
///
/// File locking, file sync, and directory sync must be supported by the backing
/// filesystem. A separate, never-replaced lock file protects the journal across
/// atomic compaction. Storage errors latch admission closed until the guard is
/// reopened; a damaged journal fails startup rather than becoming an empty cache.
pub struct DurableMeshReplayGuard {
    path: PathBuf,
    // This handle must remain owned across every compaction.
    _lock: File,
    file: File,
    scope: [u8; 32],
    window_ms: u64,
    capacity: usize,
    high_water_ms: u64,
    record_count: usize,
    entries: BTreeMap<ReplayKey, Entry>,
    expirations: BinaryHeap<Reverse<(u64, ReplayKey)>>,
    io_failed: bool,
}

impl std::fmt::Debug for DurableMeshReplayGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableMeshReplayGuard")
            .field("live_nonces", &self.entries.len())
            .field("capacity", &self.capacity)
            .field("io_failed", &self.io_failed)
            .finish_non_exhaustive()
    }
}

impl DurableMeshReplayGuard {
    /// Open or initialize a node-bound journal and recover unexpired nonces.
    ///
    /// The parent directory must already exist. The `.lock` and `.compact`
    /// companion names are reserved for this journal. Existing data is never
    /// truncated on startup, including an empty, torn, or corrupt existing file.
    ///
    /// # Errors
    ///
    /// Refuses invalid limits, another writer, an incorrect node/window binding,
    /// malformed or oversized data, clock rollback, and any required I/O failure.
    pub fn open(
        path: &Path,
        local_node: &TailscaleNodeId,
        window_ms: u64,
        capacity: usize,
        now_ms: u64,
    ) -> HostResult<Self> {
        if window_ms == 0 || capacity == 0 || capacity > DEFAULT_MESH_FORWARD_REPLAY_CAPACITY {
            return Err(HostError::InvalidFilter(
                "invalid durable mesh replay window or capacity".to_owned(),
            ));
        }
        if path.file_name().is_none() {
            return Err(HostError::InvalidFilter(
                "mesh replay journal requires a file path".to_owned(),
            ));
        }
        let lock_path = companion(path, ".lock");
        let lock = private_options()
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| startup_io("lock_open", &error))?;
        check_private_regular(&lock).map_err(|error| startup_io("lock_metadata", &error))?;
        lock.try_lock().map_err(|_| {
            HostError::Internal("mesh replay journal is locked or locking is unsupported".to_owned())
        })?;
        let scope = hash_parts(b"FCP-MESH-REPLAY-NODE-V1", &[local_node.as_str().as_bytes()]);
        let mut file = match private_options().append(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut file = private_options()
                    .append(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|error| startup_io("create", &error))?;
                let header = encode_header(&scope, window_ms, now_ms, 0);
                file.write_all(&header)
                    .and_then(|()| file.sync_all())
                    .and_then(|()| sync_parent(path))
                    .map_err(|error| startup_io("initialize", &error))?;
                // The read cursor on a newly written append handle is at EOF.
                drop(file);
                private_options()
                    .append(true)
                    .open(path)
                    .map_err(|error| startup_io("reopen", &error))?
            }
            Err(error) => return Err(startup_io("open", &error)),
        };
        check_private_regular(&file).map_err(|error| startup_io("metadata", &error))?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(u64::try_from(MAX_FILE_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(|error| startup_io("read", &error))?;
        let malformed = || {
            HostError::Internal("mesh replay journal is malformed; refusing admission".to_owned())
        };
        if bytes.len() < HEADER_LEN
            || bytes.len() > MAX_FILE_BYTES
            || (bytes.len() - HEADER_LEN) % RECORD_LEN != 0
        {
            return Err(malformed());
        }
        let header = &bytes[..HEADER_LEN];
        if &header[..8] != MAGIC
            || header[8..40] != scope
            || read_u64(header, 40) != window_ms
            || header[HEADER_BODY_LEN..]
                != hash_parts(b"FCP-MESH-REPLAY-HEADER-V1", &[&header[..HEADER_BODY_LEN]])
        {
            return Err(malformed());
        }
        let record_count = (bytes.len() - HEADER_LEN) / RECORD_LEN;
        let snapshot_count = read_u64(header, 56);
        if snapshot_count > u64::try_from(record_count).unwrap_or(u64::MAX) {
            return Err(malformed());
        }
        let mut high_water_ms = read_u64(header, 48);
        let mut entries = BTreeMap::<ReplayKey, Entry>::new();
        for bytes in bytes[HEADER_LEN..].chunks_exact(RECORD_LEN) {
            if bytes[RECORD_BODY_LEN..]
                != hash_parts(b"FCP-MESH-REPLAY-RECORD-V1", &[&scope, &bytes[..RECORD_BODY_LEN]])
            {
                return Err(malformed());
            }
            let mut key = [0; 32];
            key.copy_from_slice(&bytes[..32]);
            let entry = Entry {
                expires_at_ms: read_u64(bytes, 32),
                observed_at_ms: read_u64(bytes, 40),
            };
            if entry.expires_at_ms < entry.observed_at_ms
                || entry.expires_at_ms
                    > entry.observed_at_ms.saturating_add(window_ms.saturating_mul(2))
                || entries
                    .get(&key)
                    .is_some_and(|previous| previous.expires_at_ms >= entry.observed_at_ms)
            {
                return Err(malformed());
            }
            high_water_ms = high_water_ms.max(entry.observed_at_ms);
            entries.insert(key, entry);
        }
        if now_ms < high_water_ms {
            return Err(HostError::Internal(
                "mesh replay journal clock moved backwards; refusing admission".to_owned(),
            ));
        }
        entries.retain(|_, entry| entry.expires_at_ms >= now_ms);
        if entries.len() > capacity {
            return Err(HostError::InvalidFilter(
                "mesh replay capacity is below the recovered live nonce count".to_owned(),
            ));
        }
        let expirations = entries
            .iter()
            .map(|(key, entry)| Reverse((entry.expires_at_ms, *key)))
            .collect();
        Ok(Self {
            path: path.to_path_buf(),
            _lock: lock,
            file,
            scope,
            window_ms,
            capacity,
            high_water_ms: now_ms,
            record_count,
            entries,
            expirations,
            io_failed: false,
        })
    }

    /// Authenticate and durably admit a forward before executing its operation.
    ///
    /// # Errors
    ///
    /// Returns the ordinary signature/freshness/replay/capacity error, or a
    /// redaction-safe `Malformed { field: "replay_journal", .. }` storage refusal.
    /// A storage refusal does not prove that an earlier delivery did not execute.
    pub fn accept(
        &mut self,
        envelope: &MeshForwardEnvelope,
        directory: &MeshPeerDirectory,
        now_ms: u64,
    ) -> Result<(), MeshForwardError> {
        let scope = hash_parts(
            b"FCP-MESH-REPLAY-NODE-V1",
            &[directory.local_node().as_str().as_bytes()],
        );
        if scope != self.scope {
            return Err(replay_unavailable("node_scope_mismatch"));
        }
        envelope.verify(directory, now_ms, self.window_ms)?;
        self.record_authenticated(envelope, now_ms)
    }

    fn record_authenticated(
        &mut self,
        envelope: &MeshForwardEnvelope,
        now_ms: u64,
    ) -> Result<(), MeshForwardError> {
        let identity = VerifiedMeshReplayNonce::from_authenticated(envelope, self.scope)?;
        self.accept_verified(&identity, now_ms)
    }

    /// Commit an opaque, previously authenticated identity on the blocking worker.
    /// This does not permit execution until the existing journal sync completes.
    pub(crate) fn accept_verified(
        &mut self,
        identity: &VerifiedMeshReplayNonce,
        now_ms: u64,
    ) -> Result<(), MeshForwardError> {
        if identity.scope != self.scope {
            return Err(replay_unavailable("node_scope_mismatch"));
        }
        if self.io_failed {
            return Err(replay_unavailable("storage_failed"));
        }
        if now_ms < self.high_water_ms {
            return Err(replay_unavailable("clock_rollback"));
        }
        if identity.issued_at_ms.abs_diff(now_ms) > self.window_ms {
            return Err(MeshForwardError::Stale {
                what: "forward",
                issued_at_ms: identity.issued_at_ms,
                now_ms,
                window_ms: self.window_ms,
            });
        }
        let key = identity.key;
        self.high_water_ms = now_ms;
        self.expire(now_ms);
        if self.entries.contains_key(&key) {
            return Err(MeshForwardError::Replayed {
                origin: identity.origin.clone(),
            });
        }
        if self.entries.len() >= self.capacity {
            return Err(MeshForwardError::ReplayCacheSaturated {
                capacity: self.capacity,
            });
        }
        let entry = Entry {
            expires_at_ms: identity.issued_at_ms.saturating_add(self.window_ms),
            observed_at_ms: now_ms,
        };
        // Latch before any persistence or allocation that could unwind. Only a
        // fully synced append and published in-memory entry clear this latch.
        self.io_failed = true;
        let persisted = (|| -> io::Result<()> {
            if self.record_count >= self.capacity * 2 {
                self.compact()?;
            }
            self.file.write_all(&encode_record(&self.scope, &key, entry))?;
            self.file.sync_all()
        })();
        if let Err(error) = persisted {
            tracing::error!(
                event = "mesh_replay_journal_unavailable",
                reason = "commit_failed",
                error_kind = ?error.kind(),
                "mesh forward refused before dispatch"
            );
            return Err(replay_unavailable("commit_failed"));
        }
        self.record_count += 1;
        self.entries.insert(key, entry);
        self.expirations.push(Reverse((entry.expires_at_ms, key)));
        self.io_failed = false;
        Ok(())
    }

    fn expire(&mut self, now_ms: u64) {
        while let Some(Reverse((expires_at_ms, key))) = self.expirations.peek().copied() {
            // Freshness accepts the boundary, so a nonce expires strictly AFTER it.
            if expires_at_ms >= now_ms {
                break;
            }
            self.expirations.pop();
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.expires_at_ms == expires_at_ms)
            {
                self.entries.remove(&key);
            }
        }
    }

    fn compact(&mut self) -> io::Result<()> {
        let temporary = companion(&self.path, ".compact");
        let mut next = private_options()
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        check_private_regular(&next)?;
        next.write_all(&encode_header(
            &self.scope,
            self.window_ms,
            self.high_water_ms,
            self.entries.len(),
        ))?;
        for (key, entry) in &self.entries {
            next.write_all(&encode_record(&self.scope, key, *entry))?;
        }
        next.sync_all()?;
        drop(next);
        // The previous journal remains intact until the complete replacement is
        // synced. Either crash-visible version contains every still-live nonce.
        std::fs::rename(&temporary, &self.path)?;
        sync_parent(&self.path)?;
        self.file = private_options().append(true).open(&self.path)?;
        self.record_count = self.entries.len();
        Ok(())
    }
}

pub(crate) fn replay_unavailable(reason: &str) -> MeshForwardError {
    MeshForwardError::Malformed {
        field: "replay_journal",
        detail: format!("durable replay protection unavailable ({reason}); operation not admitted"),
    }
}

/// Append a reserved suffix without dropping the original filename extension.
pub(crate) fn companion(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(std::array::from_fn(|index| bytes[offset + index]))
}

fn encode_header(
    scope: &[u8; 32],
    window_ms: u64,
    high_water_ms: u64,
    count: usize,
) -> [u8; HEADER_LEN] {
    let mut bytes = [0; HEADER_LEN];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..40].copy_from_slice(scope);
    bytes[40..48].copy_from_slice(&window_ms.to_le_bytes());
    bytes[48..56].copy_from_slice(&high_water_ms.to_le_bytes());
    bytes[56..64].copy_from_slice(&u64::try_from(count).unwrap_or(u64::MAX).to_le_bytes());
    let checksum = hash_parts(b"FCP-MESH-REPLAY-HEADER-V1", &[&bytes[..HEADER_BODY_LEN]]);
    bytes[HEADER_BODY_LEN..].copy_from_slice(&checksum);
    bytes
}

fn encode_record(scope: &[u8; 32], key: &ReplayKey, entry: Entry) -> [u8; RECORD_LEN] {
    let mut bytes = [0; RECORD_LEN];
    bytes[..32].copy_from_slice(key);
    bytes[32..40].copy_from_slice(&entry.expires_at_ms.to_le_bytes());
    bytes[40..48].copy_from_slice(&entry.observed_at_ms.to_le_bytes());
    let checksum = hash_parts(b"FCP-MESH-REPLAY-RECORD-V1", &[scope, &bytes[..RECORD_BODY_LEN]]);
    bytes[RECORD_BODY_LEN..].copy_from_slice(&checksum);
    bytes
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    options
}

fn check_private_regular(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("journal must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "journal permissions must exclude group and other access",
            ));
        }
    }
    Ok(())
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

fn startup_io(action: &str, error: &io::Error) -> HostError {
    HostError::Internal(format!(
        "mesh replay journal {action} failed ({:?}); stable writable storage with file locking and directory sync is required",
        error.kind()
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::{MeshForwardBody, MeshPeerConfig};

    fn node() -> TailscaleNodeId {
        TailscaleNodeId::new("executor")
    }

    fn open(path: &Path, capacity: usize, now: u64) -> DurableMeshReplayGuard {
        DurableMeshReplayGuard::open(path, &node(), 100, capacity, now).unwrap()
    }

    // Journal-only tests enter the post-authentication boundary explicitly.
    // Public accept() authentication is covered separately below.
    fn envelope(nonce: u8, issued: u64) -> MeshForwardEnvelope {
        let mut envelope = MeshForwardEnvelope::sign(
            &Ed25519SigningKey::generate(),
            TailscaleNodeId::new("origin"),
            node(),
            issued,
            MeshForwardBody::Invoke {
                request_json: "secret-payload-canary".to_owned(),
                asserted_principal: Some("secret-principal-canary".to_owned()),
            },
        )
        .unwrap();
        envelope.nonce = hex::encode([nonce; 16]);
        envelope
    }

    #[test]
    fn replay_survives_reopen_without_retaining_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let request = envelope(1, 1000);
        let mut guard = open(&path, 2, 1000);
        guard.record_authenticated(&request, 1000).unwrap();
        assert!(matches!(
            guard.record_authenticated(&request, 1001),
            Err(MeshForwardError::Replayed { .. })
        ));
        drop(guard);
        let bytes = std::fs::read(&path).unwrap();
        for secret in [
            "secret-payload-canary",
            "secret-principal-canary",
            "origin",
            request.nonce.as_str(),
        ] {
            assert!(!bytes.windows(secret.len()).any(|window| window == secret.as_bytes()));
        }
        let mut reopened = open(&path, 2, 1002);
        assert!(matches!(
            reopened.record_authenticated(&request, 1002),
            Err(MeshForwardError::Replayed { .. })
        ));
    }

    #[test]
    fn future_nonce_is_retained_through_inclusive_freshness_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let request = envelope(1, 1100);
        open(&path, 1, 1000).record_authenticated(&request, 1000).unwrap();
        let mut guard = open(&path, 1, 1150);
        assert!(matches!(
            guard.record_authenticated(&request, 1200),
            Err(MeshForwardError::Replayed { .. })
        ));
        assert!(matches!(
            guard.record_authenticated(&request, 1201),
            Err(MeshForwardError::Stale { .. })
        ));
        guard.record_authenticated(&envelope(2, 1201), 1201).unwrap();
    }

    #[test]
    fn origin_is_part_of_key_and_nonce_hex_case_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut request = envelope(0xab, 1000);
        let mut guard = open(&path, 3, 1000);
        guard.record_authenticated(&request, 1000).unwrap();
        request.nonce.make_ascii_uppercase();
        assert!(matches!(
            guard.record_authenticated(&request, 1000),
            Err(MeshForwardError::Replayed { .. })
        ));
        request.origin_node = TailscaleNodeId::new("other-origin");
        guard.record_authenticated(&request, 1000).unwrap();
    }

    #[test]
    fn capacity_refusal_never_forgets_live_nonces_or_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 1, 1000);
        let first = envelope(1, 1000);
        guard.record_authenticated(&first, 1000).unwrap();
        let length = std::fs::metadata(&path).unwrap().len();
        assert!(matches!(
            guard.record_authenticated(&envelope(2, 1001), 1001),
            Err(MeshForwardError::ReplayCacheSaturated { capacity: 1 })
        ));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert!(matches!(
            guard.record_authenticated(&first, 1001),
            Err(MeshForwardError::Replayed { .. })
        ));
        drop(guard);
        assert_eq!(open(&path, 1, 1001).entries.len(), 1);
    }

    #[test]
    fn compaction_bounds_disk_and_preserves_live_future_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 2, 1000);
        let future = envelope(250, 1100);
        guard.record_authenticated(&future, 1000).unwrap();
        for index in 1_u8..20 {
            let now = 1000 + u64::from(index) * 10;
            guard.record_authenticated(&envelope(index, now - 100), now).unwrap();
            assert!(
                std::fs::metadata(&path).unwrap().len()
                    <= u64::try_from(HEADER_LEN + 4 * RECORD_LEN).unwrap()
            );
        }
        // Compaction replaces the data inode, but never the writer-lock inode.
        assert!(DurableMeshReplayGuard::open(&path, &node(), 100, 2, 1190).is_err());
        drop(guard);
        let mut guard = open(&path, 2, 1191);
        assert!(matches!(
            guard.record_authenticated(&future, 1191),
            Err(MeshForwardError::Replayed { .. })
        ));
    }

    #[test]
    fn clock_floor_survives_empty_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 1, 1000);
        guard.record_authenticated(&envelope(1, 1000), 1000).unwrap();
        guard.expire(2000);
        guard.high_water_ms = 2000;
        guard.compact().unwrap();
        assert!(guard.entries.is_empty());
        drop(guard);
        assert!(DurableMeshReplayGuard::open(&path, &node(), 100, 1, 1999).is_err());
        assert!(open(&path, 1, 2000).entries.is_empty());
    }

    #[test]
    fn clock_rollback_refuses_without_destroying_guard() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 2, 1000);
        guard.record_authenticated(&envelope(1, 1000), 1000).unwrap();
        assert!(guard.record_authenticated(&envelope(2, 999), 999).is_err());
        guard.record_authenticated(&envelope(2, 1001), 1001).unwrap();
    }

    #[test]
    fn header_scope_window_and_checksum_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        drop(open(&path, 2, 1000));
        assert!(
            DurableMeshReplayGuard::open(&path, &TailscaleNodeId::new("other"), 100, 2, 1000).is_err()
        );
        assert!(DurableMeshReplayGuard::open(&path, &node(), 101, 2, 1000).is_err());
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[48] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(DurableMeshReplayGuard::open(&path, &node(), 100, 2, 1000).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn torn_record_is_never_truncated_or_treated_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        open(&path, 2, 1000)
            .record_authenticated(&envelope(1, 1000), 1000)
            .unwrap();
        let valid = std::fs::read(&path).unwrap();
        for retained in 1..RECORD_LEN {
            let torn = &valid[..HEADER_LEN + retained];
            std::fs::write(&path, torn).unwrap();
            assert!(DurableMeshReplayGuard::open(&path, &node(), 100, 2, 1000).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), torn);
        }
    }

    #[test]
    fn malformed_record_checksum_and_snapshot_truncation_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 2, 1000);
        guard.record_authenticated(&envelope(1, 1000), 1000).unwrap();
        guard.compact().unwrap();
        drop(guard);
        let valid = std::fs::read(&path).unwrap();
        let mut bad = valid.clone();
        bad[HEADER_LEN] ^= 1;
        std::fs::write(&path, bad).unwrap();
        assert!(DurableMeshReplayGuard::open(&path, &node(), 100, 2, 1000).is_err());
        std::fs::write(&path, &valid[..HEADER_LEN]).unwrap();
        assert!(DurableMeshReplayGuard::open(&path, &node(), 100, 2, 1000).is_err());
    }

    #[test]
    fn empty_existing_journal_is_not_reinitialized() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(DurableMeshReplayGuard::open(&path, &node(), 100, 2, 1000).is_err());
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn append_failure_latches_admission_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 2, 1000);
        guard.file = File::open(&path).unwrap(); // deterministic write failure
        assert!(guard.record_authenticated(&envelope(1, 1000), 1000).is_err());
        assert!(guard.io_failed);
        assert!(guard.entries.is_empty());
        guard.file = private_options().append(true).open(&path).unwrap();
        assert!(guard.record_authenticated(&envelope(2, 1000), 1000).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), u64::try_from(HEADER_LEN).unwrap());
    }

    #[test]
    fn public_accept_verifies_before_committing_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let key = Ed25519SigningKey::generate();
        let directory = MeshPeerDirectory::from_configs(
            node(),
            &[MeshPeerConfig {
                node_id: "origin".to_owned(),
                endpoint: "http://127.0.0.1:1".to_owned(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            }],
        )
        .unwrap();
        let valid = MeshForwardEnvelope::sign(
            &key,
            TailscaleNodeId::new("origin"),
            node(),
            1000,
            MeshForwardBody::Introspect {
                connector_id: "fcp.test:utility:1.0.0".to_owned(),
            },
        )
        .unwrap();
        let mut forged = valid.clone();
        forged.issued_at_ms = 1001;
        let mut guard = open(&path, 1, 1000);
        assert!(matches!(
            guard.accept(&forged, &directory, 1001),
            Err(MeshForwardError::SignatureInvalid { .. })
        ));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), u64::try_from(HEADER_LEN).unwrap());
        guard.accept(&valid, &directory, 1001).unwrap();
        drop(guard);
        assert!(matches!(
            open(&path, 1, 1002).accept(&valid, &directory, 1002),
            Err(MeshForwardError::Replayed { .. })
        ));
    }

    #[test]
    fn stale_and_malformed_nonce_do_not_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut guard = open(&path, 2, 1000);
        let mut request = envelope(1, 1000);
        request.nonce = "bad".to_owned();
        assert!(guard.record_authenticated(&request, 1000).is_err());
        assert!(guard.record_authenticated(&envelope(2, 899), 1000).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), u64::try_from(HEADER_LEN).unwrap());
    }

    #[test]
    fn symlinks_and_insecure_permissions_are_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        let path = dir.path().join("journal");
        symlink(&target, &path).unwrap();
        assert!(DurableMeshReplayGuard::open(&path, &node(), 100, 2, 1000).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        let private = dir.path().join("private");
        drop(open(&private, 2, 1000));
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(DurableMeshReplayGuard::open(&private, &node(), 100, 2, 1000).is_err());
    }

    #[test]
    fn invalid_limits_and_oversized_journals_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        for capacity in [0, DEFAULT_MESH_FORWARD_REPLAY_CAPACITY + 1] {
            assert!(DurableMeshReplayGuard::open(&path, &node(), 100, capacity, 1000).is_err());
        }
        assert!(!path.exists());
        drop(open(&path, 2, 1000));
        private_options()
            .open(&path)
            .unwrap()
            .set_len(u64::try_from(MAX_FILE_BYTES + 1).unwrap())
            .unwrap();
        assert!(DurableMeshReplayGuard::open(&path, &node(), 100, 2, 1000).is_err());
    }
}
