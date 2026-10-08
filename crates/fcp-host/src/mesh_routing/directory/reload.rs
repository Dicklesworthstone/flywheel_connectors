//! Single-owner, off-executor publication of signed membership successors.

use std::sync::{Arc, RwLock, mpsc};
use std::thread::{self, JoinHandle};

use fcp_core::TailscaleNodeId;
use fcp_mesh::invoke_route::MeshPeerDirectory;

use super::*;

const RELOAD_INTERVAL: Duration = Duration::from_secs(1);

pub(super) struct ReloadSource {
    pub path: PathBuf,
    pub mesh_id: String,
    pub trusted_owners: Vec<Ed25519VerifyingKey>,
    pub local_node: TailscaleNodeId,
    pub local_key: Ed25519VerifyingKey,
}

struct Publication {
    directory: Arc<MeshPeerDirectory>,
    checkpoint: MeshPeerDirectoryCheckpoint,
    validity: MembershipValidity,
    failure: Option<&'static str>,
}

pub(super) struct LiveMembership {
    publication: RwLock<Publication>,
}

impl LiveMembership {
    pub(super) fn new(
        directory: MeshPeerDirectory,
        checkpoint: MeshPeerDirectoryCheckpoint,
        validity: MembershipValidity,
    ) -> Self {
        Self {
            publication: RwLock::new(Publication {
                directory: Arc::new(directory),
                checkpoint,
                validity,
                failure: None,
            }),
        }
    }

    pub(super) fn snapshot(&self) -> Result<Arc<MeshPeerDirectory>, MeshForwardError> {
        let current = self.publication.read().map_err(|_| unavailable("state_poisoned"))?;
        if let Some(reason) = current.failure {
            return Err(unavailable(reason));
        }
        current.validity.check_at(unix_now_ms(), Instant::now())?;
        Ok(Arc::clone(&current.directory))
    }

    fn refuse(&self, reason: &'static str) {
        if let Ok(mut current) = self.publication.write() {
            current.failure = Some(reason);
        }
    }
}

fn unavailable(reason: &str) -> MeshForwardError {
    MeshForwardError::Malformed {
        field: "peer_directory",
        detail: format!("owner-signed membership unavailable ({reason})"),
    }
}

/// The worker is dropped before the checkpoint's exclusive lock is released.
/// No router, replay journal, request body, or signing secret enters the worker.
pub(super) struct ReloadWorker {
    stop: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

struct WorkerExitFence(Arc<LiveMembership>);

impl Drop for WorkerExitFence {
    fn drop(&mut self) {
        self.0.refuse("reload_worker_stopped_requires_restart");
    }
}

impl Drop for ReloadWorker {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) fn spawn(
    source: ReloadSource,
    state_path: PathBuf,
    membership: Arc<LiveMembership>,
    last_observed_ms: u64,
) -> HostResult<ReloadWorker> {
    let (stop, stopped) = mpsc::channel();
    let thread = thread::Builder::new()
        .name("fcp-mesh-membership".to_owned())
        .spawn(move || {
            let _exit_fence = WorkerExitFence(Arc::clone(&membership));
            let mut refresher = Refresher {
                source,
                state_path,
                last_observed_ms,
                storage_failed: false,
            };
            let mut refusal_logged = false;
            loop {
                match stopped.recv_timeout(RELOAD_INTERVAL) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                if let Err(error) = refresher.refresh(&membership) {
                    membership.refuse(if refresher.storage_failed {
                        "checkpoint_failure_requires_restart"
                    } else {
                        "signed_source_rejected"
                    });
                    if !refusal_logged {
                        tracing::warn!(
                            event = "mesh_membership_reload_refused",
                            detail = %error,
                            "new mesh work is fenced until membership is available"
                        );
                    }
                    refusal_logged = true;
                } else {
                    refusal_logged = false;
                }
                if refresher.storage_failed {
                    // A failed rename/fsync may already have advanced persistent
                    // state. Never resume from an older in-memory checkpoint.
                    break;
                }
            }
        })
        .map_err(|error| storage_error("reload_worker_start", &error))?;
    Ok(ReloadWorker { stop, thread: Some(thread) })
}

struct Refresher {
    source: ReloadSource,
    state_path: PathBuf,
    last_observed_ms: u64,
    storage_failed: bool,
}

impl Refresher {
    fn refresh(&mut self, membership: &LiveMembership) -> HostResult<()> {
        if self.storage_failed {
            return Err(invalid("membership checkpoint failure requires restart"));
        }
        let now = Instant::now();
        let now_ms = unix_now_ms();
        if now_ms < self.last_observed_ms {
            return Err(invalid("clock moved backwards during membership reload"));
        }
        self.last_observed_ms = now_ms;
        let json = read_peer_file(&self.source.path)?;
        let signed = SignedMeshPeerDirectory::from_json(&json)
            .map_err(|error| invalid(&error.to_string()))?;
        let verified = signed
            .verify(
                &self.source.trusted_owners,
                &self.source.mesh_id,
                self.source.local_node.clone(),
                &self.source.local_key,
                now_ms,
            )
            .map_err(|error| invalid(&error.to_string()))?;
        let previous = membership.publication.read()
            .map_err(|_| invalid("membership publication is poisoned"))?
            .checkpoint.clone();
        verified.check_successor(&previous)
            .map_err(|error| invalid(&error.to_string()))?;
        {
            let current = membership.publication.read()
                .map_err(|_| invalid("membership publication is poisoned"))?;
            if !current.directory.peers().eq(verified.directory().peers()) {
                return Err(invalid("membership topology changed; restart required"));
            }
        }
        if verified.checkpoint().generation == previous.generation {
            // Same-generation reloads never renew the monotonic deadline. An
            // observed expiration cannot be undone by rewinding the wall clock.
            let mut current = membership.publication.write()
                .map_err(|_| invalid("membership publication is poisoned"))?;
            current.validity.check_at(now_ms, Instant::now())
                .map_err(|error| invalid(&error.to_string()))?;
            current.failure = None;
            return Ok(());
        }

        let validity = MembershipValidity::new(
            verified.payload().expires_at_ms,
            now_ms,
            now,
        )?;
        let mut checkpoint = verified.checkpoint().clone();
        let directory = Arc::new(verified.directory().clone());
        // Fence requests before any checkpoint mutation. If storage is
        // ambiguous, the old directory must not continue admitting work.
        membership.refuse("checkpoint_commit_in_progress");
        self.storage_failed = true;
        let persisted = match read_checkpoint(&self.state_path) {
            Ok(checkpoint) => checkpoint,
            Err(CheckpointReadError::Missing) => {
                return Err(invalid("initialized directory checkpoint is missing; refusing reset"));
            }
            Err(CheckpointReadError::Invalid(error)) => return Err(error),
        };
        if persisted != previous {
            return Err(invalid("membership checkpoint changed outside its owner"));
        }
        let committed_at = unix_now_ms();
        if committed_at < now_ms {
            return Err(invalid("clock moved backwards during membership commit"));
        }
        validity.check_at(committed_at, Instant::now())
            .map_err(|error| invalid(&error.to_string()))?;
        checkpoint.last_observed_ms = committed_at;
        write_checkpoint(&self.state_path, &checkpoint)?;
        validity.check_at(unix_now_ms(), Instant::now())
            .map_err(|error| invalid(&error.to_string()))?;
        let generation = checkpoint.generation;
        let peer_count = directory.len();
        *membership.publication.write()
            .map_err(|_| invalid("membership publication is poisoned"))? = Publication {
            directory,
            checkpoint,
            validity,
            failure: None,
        };
        self.last_observed_ms = committed_at;
        self.storage_failed = false;
        tracing::info!(
            event = "mesh_membership_reloaded",
            generation,
            peer_count,
            "owner-signed membership durably activated"
        );
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::MeshPeerConfig;
    use fcp_mesh::peer_manifest::{MESH_PEER_DIRECTORY_SCHEMA, MeshPeerDirectoryPayload};

    use super::*;

    struct Fixture {
        dir: tempfile::TempDir,
        owner: Ed25519SigningKey,
        payload: MeshPeerDirectoryPayload,
        refresher: Refresher,
        membership: LiveMembership,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let owner = Ed25519SigningKey::from_bytes(&[31; 32]).unwrap();
            let local = Ed25519SigningKey::from_bytes(&[32; 32]).unwrap();
            let peer = Ed25519SigningKey::from_bytes(&[33; 32]).unwrap();
            let now_ms = unix_now_ms();
            let payload = MeshPeerDirectoryPayload {
                schema_version: MESH_PEER_DIRECTORY_SCHEMA.to_owned(),
                mesh_id: "reload-test".to_owned(),
                generation: 1,
                issued_at_ms: now_ms.saturating_sub(1000),
                expires_at_ms: now_ms + 300_000,
                peers: vec![
                    MeshPeerConfig {
                        node_id: "local".to_owned(),
                        endpoint: "http://127.0.0.1:19001".to_owned(),
                        public_key_hex: hex::encode(local.verifying_key().to_bytes()),
                    },
                    MeshPeerConfig {
                        node_id: "peer".to_owned(),
                        endpoint: "http://127.0.0.1:19002".to_owned(),
                        public_key_hex: hex::encode(peer.verifying_key().to_bytes()),
                    },
                ],
            };
            let signed = SignedMeshPeerDirectory::sign(&owner, &payload).unwrap();
            let verified = signed.verify(
                &[owner.verifying_key()],
                &payload.mesh_id,
                TailscaleNodeId::new("local"),
                &local.verifying_key(),
                now_ms,
            ).unwrap();
            let state_path = dir.path().join("membership");
            write_checkpoint(&state_path, verified.checkpoint()).unwrap();
            let source = ReloadSource {
                path: dir.path().join("peers.json"),
                mesh_id: payload.mesh_id.clone(),
                trusted_owners: vec![owner.verifying_key()],
                local_node: TailscaleNodeId::new("local"),
                local_key: local.verifying_key(),
            };
            let membership = LiveMembership::new(
                verified.directory().clone(),
                verified.checkpoint().clone(),
                MembershipValidity::new(payload.expires_at_ms, now_ms, Instant::now()).unwrap(),
            );
            let fixture = Self {
                dir,
                owner,
                payload,
                refresher: Refresher {
                    source,
                    state_path,
                    last_observed_ms: now_ms,
                    storage_failed: false,
                },
                membership,
            };
            fixture.write_source();
            fixture
        }

        fn write_source(&self) {
            let signed = SignedMeshPeerDirectory::sign(&self.owner, &self.payload).unwrap();
            std::fs::write(&self.refresher.source.path, serde_json::to_vec(&signed).unwrap()).unwrap();
        }

        fn refresh(&mut self) -> HostResult<()> {
            self.refresher.refresh(&self.membership)
        }
    }

    #[test]
    fn higher_generation_renews_expired_membership_and_commits_its_checkpoint() {
        let mut fixture = Fixture::new();
        fixture.membership.publication.read().unwrap().validity.expired.store(true, Ordering::Release);
        assert!(fixture.membership.snapshot().is_err());
        fixture.payload.generation = 2;
        fixture.payload.expires_at_ms += 300_000;
        fixture.write_source();
        fixture.refresh().unwrap();
        assert_eq!(fixture.membership.snapshot().unwrap().len(), 1);
        let committed = read_checkpoint(&fixture.refresher.state_path).ok().unwrap();
        assert_eq!(committed.generation, 2);
        assert_eq!(committed, fixture.membership.publication.read().unwrap().checkpoint);
    }

    #[test]
    fn identical_generation_cannot_reset_an_observed_expiration() {
        let mut fixture = Fixture::new();
        let before = std::fs::read(&fixture.refresher.state_path).unwrap();
        fixture.membership.publication.read().unwrap().validity.expired.store(true, Ordering::Release);
        assert!(fixture.refresh().is_err());
        assert!(fixture.membership.snapshot().is_err());
        assert_eq!(std::fs::read(&fixture.refresher.state_path).unwrap(), before);
    }

    #[test]
    fn invalid_owner_rollback_and_equivocation_never_change_persistent_state() {
        for scenario in ["owner", "rollback", "equivocation", "signature"] {
            let mut fixture = Fixture::new();
            fixture.payload.generation = 2;
            fixture.write_source();
            fixture.refresh().unwrap();
            let before = std::fs::read(&fixture.refresher.state_path).unwrap();
            match scenario {
                "owner" => {
                    fixture.owner = Ed25519SigningKey::from_bytes(&[99; 32]).unwrap();
                    fixture.payload.generation = 3;
                }
                "rollback" => fixture.payload.generation = 1,
                _ => fixture.payload.expires_at_ms += 1,
            }
            fixture.write_source();
            if scenario == "signature" {
                let mut signed = SignedMeshPeerDirectory::sign(&fixture.owner, &fixture.payload).unwrap();
                signed.payload_json.push(' ');
                std::fs::write(&fixture.refresher.source.path, serde_json::to_vec(&signed).unwrap()).unwrap();
            }
            assert!(fixture.refresh().is_err(), "{scenario} must be refused");
            assert_eq!(std::fs::read(&fixture.refresher.state_path).unwrap(), before);
        }
    }

    #[test]
    fn missing_checkpoint_during_reload_cannot_initialize_from_scratch() {
        let mut fixture = Fixture::new();
        std::fs::rename(&fixture.refresher.state_path, fixture.dir.path().join("retained-state")).unwrap();
        fixture.payload.generation = 2;
        fixture.write_source();
        assert!(fixture.refresh().is_err());
        assert!(fixture.refresher.storage_failed);
        assert!(fixture.membership.snapshot().is_err());
        assert!(!fixture.refresher.state_path.exists());
    }

    #[test]
    fn staging_failure_fences_the_router_and_cannot_revert_to_old_memory() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = Fixture::new();
        let protected = fixture.dir.path().join("protected");
        std::fs::write(&protected, b"do not modify").unwrap();
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&protected, companion(&fixture.refresher.state_path, ".next")).unwrap();
        let before = std::fs::read(&fixture.refresher.state_path).unwrap();
        fixture.payload.generation = 2;
        fixture.write_source();
        assert!(fixture.refresh().is_err());
        assert!(fixture.refresher.storage_failed);
        assert!(fixture.membership.snapshot().is_err());
        fixture.payload.generation = 1;
        fixture.write_source();
        assert!(fixture.refresh().is_err());
        assert_eq!(std::fs::read(&fixture.refresher.state_path).unwrap(), before);
        assert_eq!(std::fs::read(&protected).unwrap(), b"do not modify");
    }

    #[test]
    fn changed_topology_requires_router_reconfiguration() {
        let mut fixture = Fixture::new();
        let before = std::fs::read(&fixture.refresher.state_path).unwrap();
        fixture.payload.generation = 2;
        fixture.payload.peers.truncate(1);
        fixture.write_source();
        assert!(fixture.refresh().unwrap_err().to_string().contains("topology changed"));
        assert_eq!(std::fs::read(&fixture.refresher.state_path).unwrap(), before);
    }

    #[test]
    fn reload_clock_rollback_does_not_advance_the_checkpoint() {
        let mut fixture = Fixture::new();
        let before = std::fs::read(&fixture.refresher.state_path).unwrap();
        fixture.refresher.last_observed_ms = u64::MAX;
        fixture.payload.generation = 2;
        fixture.write_source();
        assert!(fixture.refresh().unwrap_err().to_string().contains("clock moved backwards"));
        assert_eq!(std::fs::read(&fixture.refresher.state_path).unwrap(), before);
    }
}
