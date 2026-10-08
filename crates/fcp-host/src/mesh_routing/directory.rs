//! Signed membership activation, trusted checkpoints, and runtime expiration.
//!
//! Startup commits the first checkpoint before publishing the router. File-backed
//! signed sources are subsequently checked by a dedicated worker; request handlers
//! never perform source or checkpoint I/O. The separate lock outlives that worker,
//! including across atomic checkpoint replacement.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fcp_crypto::ed25519::Ed25519VerifyingKey;
use fcp_mesh::invoke_route::MeshForwardError;
use fcp_mesh::peer_manifest::{
    MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES, MeshPeerDirectoryCheckpoint, SignedMeshPeerDirectory,
    VerifiedMeshPeerDirectory,
};
use serde::{Deserialize, Serialize};

use super::{MESH_PEERS_FILE_ENV, MeshRoutingSettings, unix_now_ms};
use crate::mesh_replay::companion;
use crate::{HostError, HostResult};

mod reload;

/// Independently pinned identity of an owner-signed mesh directory.
pub const MESH_DIRECTORY_ID_ENV: &str = "FCP_HOST_MESH_ID";
/// JSON array of independently trusted owner public keys (64 hex characters each).
pub const MESH_DIRECTORY_OWNER_KEYS_ENV: &str = "FCP_HOST_MESH_DIRECTORY_OWNER_KEYS";
/// Persistent anti-rollback checkpoint; its `.lock` and `.next` names are reserved.
pub const MESH_DIRECTORY_STATE_ENV: &str = "FCP_HOST_MESH_DIRECTORY_STATE";

pub(super) const DIRECTORY_ENV_KEYS: [&str; 3] = [
    MESH_DIRECTORY_ID_ENV,
    MESH_DIRECTORY_OWNER_KEYS_ENV,
    MESH_DIRECTORY_STATE_ENV,
];
const MAX_OWNER_KEYS: usize = 32;
const MAX_CHECKPOINT_BYTES: usize = 4096;
const INITIALIZED: &[u8] = b"FCP-MESH-DIRECTORY-INITIALIZED-V1\n";

/// Verified candidate, not yet published or committed to persistent storage.
pub(super) struct PreparedDirectory {
    verified: VerifiedMeshPeerDirectory,
    state_path: PathBuf,
    reload_source: Option<reload::ReloadSource>,
}

pub(super) struct DirectoryGuard {
    // Fields drop in order: stop/join the writer before releasing its lock.
    _worker: Option<reload::ReloadWorker>,
    state: Arc<reload::LiveMembership>,
    // A replaced data inode must never become a second lock/admission owner.
    _lock: File,
}

struct MembershipValidity {
    expires_at_ms: u64,
    deadline: Instant,
    expired: AtomicBool,
}

impl MembershipValidity {
    fn new(expires_at_ms: u64, now_ms: u64, now: Instant) -> HostResult<Self> {
        let remaining = expires_at_ms
            .checked_sub(now_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| invalid("signed membership expired before activation"))?;
        let deadline = now
            .checked_add(Duration::from_millis(remaining))
            .ok_or_else(|| invalid("signed membership lifetime is not representable"))?;
        Ok(Self {
            expires_at_ms,
            deadline,
            expired: AtomicBool::new(false),
        })
    }

    fn check_at(&self, now_ms: u64, now: Instant) -> Result<(), MeshForwardError> {
        if self.expired.load(Ordering::Acquire)
            || now_ms >= self.expires_at_ms
            || now >= self.deadline
        {
            // Neither a wall-clock rollback nor a later caller can revive a
            // directory whose expiration was already observed.
            self.expired.store(true, Ordering::Release);
            return Err(MeshForwardError::Malformed {
                field: "peer_directory",
                detail: "owner-signed membership expired; install a fresh signed generation"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

impl DirectoryGuard {
    pub(super) fn check(&self) -> Result<(), MeshForwardError> {
        self.state.snapshot().map(|_| ())
    }

    pub(super) fn snapshot(
        &self,
    ) -> Result<Arc<fcp_mesh::invoke_route::MeshPeerDirectory>, MeshForwardError> {
        self.state.snapshot()
    }
}

/// Preserve the existing explicit static configuration mode. Setting any signed
/// membership option selects signed mode and requires every option; it never
/// falls back to a raw array on parse, signature, validity, or storage failure.
pub(super) fn prepare(
    lookup: &impl Fn(&str) -> Option<String>,
    settings: &mut MeshRoutingSettings,
) -> HostResult<Option<PreparedDirectory>> {
    if !DIRECTORY_ENV_KEYS.iter().any(|key| lookup(key).is_some()) {
        return Ok(None);
    }
    let required = |name: &str| -> HostResult<String> {
        lookup(name)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid(&format!("signed membership requires nonempty {name}")))
    };
    let mesh_id = required(MESH_DIRECTORY_ID_ENV)?;
    let roots_json = required(MESH_DIRECTORY_OWNER_KEYS_ENV)?;
    if roots_json.len() > MAX_OWNER_KEYS * 128 {
        return Err(invalid("owner-key configuration exceeds its byte limit"));
    }
    let roots: Vec<String> = serde_json::from_str(&roots_json)
        .map_err(|_| invalid("directory owner keys must be a JSON array of hex public keys"))?;
    if roots.is_empty() || roots.len() > MAX_OWNER_KEYS {
        return Err(invalid("signed membership requires between 1 and 32 owner keys"));
    }
    let trusted_owners = roots
        .iter()
        .map(|root| {
            if root.len() != 64 {
                return Err(invalid("directory owner public key must contain 64 hex characters"));
            }
            let mut bytes = [0; 32];
            hex::decode_to_slice(root, &mut bytes)
                .map_err(|_| invalid("directory owner public key is not hex"))?;
            Ed25519VerifyingKey::from_bytes(&bytes)
                .map_err(|_| invalid("directory owner public key is invalid"))
        })
        .collect::<HostResult<Vec<_>>>()?;
    let state_path = PathBuf::from(required(MESH_DIRECTORY_STATE_ENV)?);
    if state_path.file_name().is_none() {
        return Err(invalid("directory state requires a persistent file path"));
    }
    let signed = SignedMeshPeerDirectory::from_json(&settings.peers_json)
        .map_err(|error| invalid(&error.to_string()))?;
    let verified = signed
        .verify(
            &trusted_owners,
            &mesh_id,
            settings.node_id.clone(),
            &settings.signing_key.verifying_key(),
            unix_now_ms(),
        )
        .map_err(|error| invalid(&error.to_string()))?;
    settings.peers_json = serde_json::to_string(&verified.payload().peers)
        .map_err(|_| invalid("verified directory could not be serialized"))?;
    let reload_source = lookup(MESH_PEERS_FILE_ENV)
        .map(|path| path.trim().to_owned())
        .filter(|path| !path.is_empty())
        .map(|path| reload::ReloadSource {
            path: PathBuf::from(path),
            mesh_id,
            trusted_owners,
            local_node: settings.node_id.clone(),
            local_key: settings.signing_key.verifying_key(),
        });
    Ok(Some(PreparedDirectory {
        verified,
        state_path,
        reload_source,
    }))
}

impl PreparedDirectory {
    /// Commit only after all other router initialization has succeeded.
    pub(super) fn activate(self) -> HostResult<DirectoryGuard> {
        let Self {
            verified,
            state_path,
            reload_source,
        } = self;
        let validity = MembershipValidity::new(
            verified.payload().expires_at_ms,
            unix_now_ms(),
            Instant::now(),
        )?;
        let lock_path = companion(&state_path, ".lock");
        let mut lock = private_options()
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| storage_error("lock_open", &error))?;
        check_private_regular(&lock).map_err(|error| storage_error("lock_metadata", &error))?;
        lock.try_lock()
            .map_err(|_| invalid("directory checkpoint is locked or locking is unsupported"))?;
        let mut marker = Vec::new();
        (&mut lock)
            .take(u64::try_from(INITIALIZED.len() + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut marker)
            .map_err(|error| storage_error("lock_read", &error))?;
        if !marker.is_empty() && marker != INITIALIZED {
            return Err(invalid("directory checkpoint initialization marker is corrupt"));
        }
        match read_checkpoint(&state_path) {
            Ok(previous) => verified
                .check_successor(&previous)
                .map_err(|error| invalid(&error.to_string()))?,
            Err(CheckpointReadError::Missing) if marker.is_empty() => {}
            Err(CheckpointReadError::Missing) => {
                return Err(invalid("initialized directory checkpoint is missing; refusing reset"));
            }
            Err(CheckpointReadError::Invalid(error)) => return Err(error),
        }
        let mut checkpoint = verified.checkpoint().clone();
        let now_ms = unix_now_ms();
        if now_ms < checkpoint.last_observed_ms {
            return Err(invalid("clock moved backwards during directory activation"));
        }
        validity
            .check_at(now_ms, Instant::now())
            .map_err(|error| invalid(&error.to_string()))?;
        checkpoint.last_observed_ms = now_ms;
        write_checkpoint(&state_path, &checkpoint)?;
        if marker.is_empty() {
            // Empty is accepted only before the first successful activation.
            // A later missing state file must never initialize from scratch.
            lock.write_all(INITIALIZED)
                .and_then(|()| lock.sync_all())
                .and_then(|()| sync_parent(&lock_path))
                .map_err(|error| storage_error("initialize_marker", &error))?;
        }
        validity
            .check_at(unix_now_ms(), Instant::now())
            .map_err(|error| invalid(&error.to_string()))?;
        let state = Arc::new(reload::LiveMembership::new(
            verified.directory().clone(),
            checkpoint,
            validity,
        ));
        let worker = reload_source
            .map(|source| reload::spawn(source, state_path, Arc::clone(&state), now_ms))
            .transpose()?;
        Ok(DirectoryGuard {
            _worker: worker,
            state,
            _lock: lock,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCheckpoint {
    checkpoint_json: String,
    checksum_hex: String,
}

enum CheckpointReadError {
    Missing,
    Invalid(HostError),
}

fn checksum(json: &str) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"FCP-MESH-DIRECTORY-CHECKPOINT-V1");
    hash.update(json.as_bytes());
    hash.finalize().to_hex().to_string()
}

fn read_checkpoint(path: &Path) -> Result<MeshPeerDirectoryCheckpoint, CheckpointReadError> {
    let mut file = match private_options().open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(CheckpointReadError::Missing);
        }
        Err(error) => return Err(CheckpointReadError::Invalid(storage_error("open", &error))),
    };
    check_private_regular(&file)
        .map_err(|error| CheckpointReadError::Invalid(storage_error("metadata", &error)))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(u64::try_from(MAX_CHECKPOINT_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|error| CheckpointReadError::Invalid(storage_error("read", &error)))?;
    let corrupt = || CheckpointReadError::Invalid(invalid("directory checkpoint is corrupt"));
    if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(corrupt());
    }
    let stored: StoredCheckpoint = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
    if stored.checksum_hex != checksum(&stored.checkpoint_json) {
        return Err(corrupt());
    }
    serde_json::from_str(&stored.checkpoint_json).map_err(|_| corrupt())
}

fn write_checkpoint(path: &Path, checkpoint: &MeshPeerDirectoryCheckpoint) -> HostResult<()> {
    let checkpoint_json = serde_json::to_string(checkpoint)
        .map_err(|_| invalid("directory checkpoint serialization failed"))?;
    let stored = StoredCheckpoint {
        checksum_hex: checksum(&checkpoint_json),
        checkpoint_json,
    };
    let bytes = serde_json::to_vec(&stored)
        .map_err(|_| invalid("directory checkpoint serialization failed"))?;
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(invalid("directory checkpoint exceeds its byte limit"));
    }
    let next_path = companion(path, ".next");
    let mut next = private_options()
        .create(true)
        .truncate(false)
        .open(&next_path)
        .map_err(|error| storage_error("staging_open", &error))?;
    // The reserved staging name may remain after a crash. Validate its inode
    // before truncation; never follow a symlink or overwrite a hard-linked file.
    check_private_regular(&next).map_err(|error| storage_error("staging_metadata", &error))?;
    next.set_len(0)
        .and_then(|()| next.write_all(&bytes))
        .and_then(|()| next.sync_all())
        .and_then(|()| std::fs::rename(&next_path, path))
        .and_then(|()| sync_parent(path))
        .map_err(|error| storage_error("commit", &error))
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
        return Err(io::Error::other("directory state must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory state must be private and not hard-linked",
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    Err(io::Error::other("signed directory persistence requires Unix file guarantees"))
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

/// Bound source reads before allocation. Signatures authorize signed sources;
/// static sources still require the operator's trusted configuration boundary.
pub(super) fn read_peer_file(path: &Path) -> HostResult<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|error| storage_error("source_open", &error))?;
    if !file
        .metadata()
        .map_err(|error| storage_error("source_metadata", &error))?
        .is_file()
    {
        return Err(invalid("peer directory source must be a regular file"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(u64::try_from(MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|error| storage_error("source_read", &error))?;
    if bytes.len() > MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES {
        return Err(invalid("peer directory source exceeds its byte limit"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("peer directory source is not UTF-8"))
}

fn invalid(detail: &str) -> HostError {
    HostError::InvalidFilter(format!("mesh membership: {detail}"))
}

fn storage_error(stage: &str, error: &io::Error) -> HostError {
    HostError::Internal(format!(
        "mesh membership storage {stage} failed ({:?}); trusted persistent storage with file locking and directory sync is required",
        error.kind()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_expiry_is_exclusive_and_cannot_be_revived_by_clock_rollback() {
        let now = Instant::now();
        let validity = MembershipValidity::new(2000, 1000, now).unwrap();
        assert!(validity.check_at(1999, now).is_ok());
        assert!(validity.check_at(2000, now).is_err());
        assert!(validity.check_at(1000, now).is_err());
    }

    #[test]
    fn monotonic_deadline_expires_membership_even_when_wall_time_stops() {
        let now = Instant::now();
        let validity = MembershipValidity::new(2000, 1000, now).unwrap();
        assert!(validity.check_at(1000, now + Duration::from_millis(999)).is_ok());
        assert!(validity.check_at(1000, now + Duration::from_millis(1000)).is_err());
        assert!(validity.check_at(1000, now).is_err());
    }

    #[test]
    fn already_expired_membership_is_not_activated() {
        assert!(MembershipValidity::new(1000, 1000, Instant::now()).is_err());
        assert!(MembershipValidity::new(999, 1000, Instant::now()).is_err());
    }

    #[test]
    fn expired_guard_blocks_router_admission_and_discovery_without_network() {
        use fcp_core::TailscaleNodeId;
        use fcp_crypto::ed25519::Ed25519SigningKey;
        use fcp_mesh::invoke_route::{MeshForwardBody, MeshForwardEnvelope};

        use super::super::{MeshForwardFailure, MeshRouter};

        let local = Ed25519SigningKey::from_bytes(&[21; 32]).unwrap();
        let peer = Ed25519SigningKey::from_bytes(&[22; 32]).unwrap();
        let settings = MeshRoutingSettings {
            node_id: TailscaleNodeId::new("local"),
            signing_key: local,
            peers_json: serde_json::json!([{
                "node_id": "peer",
                "endpoint": "http://127.0.0.1:1",
                "public_key_hex": hex::encode(peer.verifying_key().to_bytes()),
            }]).to_string(),
            forward_timeout: Duration::from_secs(1),
        };
        let mut router = MeshRouter::new(settings).unwrap();
        // Exercise the real router boundary with the actual guard latched,
        // without sleeps, a wall-clock race, or a network-service substitute.
        router.membership = Some(DirectoryGuard {
            _worker: None,
            state: Arc::new(reload::LiveMembership::new(
                router.directory().as_ref().clone(),
                MeshPeerDirectoryCheckpoint {
                    schema_version: 1,
                    mesh_id: "expiry-test".to_owned(),
                    local_node: "local".to_owned(),
                    generation: 1,
                    payload_hash_hex: "00".repeat(32),
                    last_observed_ms: 0,
                },
                MembershipValidity {
                    expires_at_ms: u64::MAX,
                    deadline: Instant::now() + Duration::from_secs(60),
                    expired: AtomicBool::new(true),
                },
            )),
            _lock: tempfile::tempfile().unwrap(),
        });
        let body = MeshForwardBody::Introspect {
            connector_id: "fcp.test:utility:1.0.0".to_owned(),
        };
        let envelope = MeshForwardEnvelope::sign(
            &peer,
            TailscaleNodeId::new("peer"),
            TailscaleNodeId::new("local"),
            unix_now_ms(),
            body.clone(),
        ).unwrap();
        assert!(matches!(
            router.accept_inbound(&envelope),
            Err(MeshForwardError::Malformed { field: "peer_directory", .. })
        ));
        fcp_async_core::runtime::block_on_sync(async {
            assert!(matches!(
                router.accept_inbound_async(&envelope).await,
                Err(MeshForwardError::Malformed { field: "peer_directory", .. })
            ));
            let error = router.forward(&TailscaleNodeId::new("peer"), body).await.unwrap_err();
            assert!(matches!(error, MeshForwardFailure::NotDelivered { .. }));
            assert!(error.summary().contains("membership expired"));
            assert!(router.peer_advertisements().await.is_empty());
        }).unwrap();
        assert!(router.has_owner_signed_membership());
        assert_eq!(
            router.forward_usage().unwrap(),
            super::super::MeshForwardUsage::default()
        );
    }
}
