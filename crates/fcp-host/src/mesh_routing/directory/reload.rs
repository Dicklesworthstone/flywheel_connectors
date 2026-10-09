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
    continuity: PeerContinuity,
    checkpoint: MeshPeerDirectoryCheckpoint,
    validity: MembershipValidity,
    failure: Option<&'static str>,
}

impl Publication {
    fn check(&self) -> Result<(), MeshForwardError> {
        if let Some(reason) = self.failure {
            return Err(unavailable(reason));
        }
        self.validity.check_at(unix_now_ms(), Instant::now())
    }
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
                continuity: PeerContinuity::new(&directory),
                directory: Arc::new(directory),
                checkpoint,
                validity,
                failure: None,
            }),
        }
    }

    pub(super) fn snapshot(&self) -> Result<Arc<MeshPeerDirectory>, MeshForwardError> {
        let current = self.publication.read().map_err(|_| unavailable("state_poisoned"))?;
        current.check()?;
        Ok(Arc::clone(&current.directory))
    }

    pub(super) fn peer_snapshot(
        &self,
        node_id: &TailscaleNodeId,
    ) -> Result<PeerSnapshot, MeshForwardError> {
        let current = self.publication.read().map_err(|_| unavailable("state_poisoned"))?;
        current.check()?;
        // Capture keys and their continuity epoch under the same read lock.
        current.continuity.snapshot(Arc::clone(&current.directory), node_id)
    }

    pub(super) fn check_peer_snapshot(
        &self,
        snapshot: &PeerSnapshot,
    ) -> Result<(), MeshForwardError> {
        let current = self.publication.read().map_err(|_| unavailable("state_poisoned"))?;
        // Preserved peer authority never bypasses expiry or a storage/source fence.
        current.check()?;
        current.continuity.check(snapshot)
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
        {
            let mut current = membership.publication.write()
                .map_err(|_| invalid("membership publication is poisoned"))?;
            // Publish the successor epochs together with the durable directory.
            // No request sees a new key with an old epoch or an uncommitted peer.
            let published_at = unix_now_ms();
            let published_now = Instant::now();
            validity.check_at(published_at, published_now)
                .map_err(|error| invalid(&error.to_string()))?;
            let continuity = if current.validity.check_at(published_at, published_now).is_ok() {
                current.continuity.successor(&directory)
            } else {
                // A renewal after an authority gap admits new calls, but must
                // not revive snapshots held before expiration was observed.
                PeerContinuity::new(&directory)
            };
            *current = Publication {
                directory,
                continuity,
                checkpoint,
                validity,
                failure: None,
            };
        }
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
        membership: Arc<LiveMembership>,
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
                membership: Arc::new(membership),
            };
            fixture.write_source();
            fixture
        }

        fn write_source(&self) {
            let signed = SignedMeshPeerDirectory::sign(&self.owner, &self.payload).unwrap();
            let staged = self.refresher.source.path.with_extension("staged");
            std::fs::write(&staged, serde_json::to_vec(&signed).unwrap()).unwrap();
            std::fs::rename(staged, &self.refresher.source.path).unwrap();
        }

        fn refresh(&mut self) -> HostResult<()> {
            self.refresher.refresh(&self.membership)
        }

        fn router(&self) -> crate::mesh_routing::MeshRouter {
            let mut router = crate::mesh_routing::MeshRouter::with_replay_journal(
                MeshRoutingSettings {
                    node_id: TailscaleNodeId::new("local"),
                    signing_key: Ed25519SigningKey::from_bytes(&[32; 32]).unwrap(),
                    peers_json: serde_json::to_string(&self.payload.peers).unwrap(),
                    forward_timeout: Duration::from_secs(5),
                },
                crate::mesh_routing::MeshForwardLimits::default(),
                &self.dir.path().join("replay"),
            ).unwrap();
            router.membership = Some(DirectoryGuard {
                _worker: None,
                state: Arc::clone(&self.membership),
                _lock: tempfile::tempfile().unwrap(),
            });
            router
        }

        fn envelope(&self, peer_key: &Ed25519SigningKey) -> fcp_mesh::invoke_route::MeshForwardEnvelope {
            fcp_mesh::invoke_route::MeshForwardEnvelope::sign(
                peer_key,
                TailscaleNodeId::new("peer"),
                TailscaleNodeId::new("local"),
                unix_now_ms(),
                fcp_mesh::invoke_route::MeshForwardBody::Introspect {
                    connector_id: "fcp.test:utility:1.0.0".to_owned(),
                },
            ).unwrap()
        }

        fn start_file_router(&self) -> crate::mesh_routing::MeshRouter {
            use crate::mesh_routing::{
                MESH_NODE_ID_ENV, MESH_REPLAY_JOURNAL_ENV, MESH_SIGNING_KEY_FILE_ENV,
            };

            let key_path = self.dir.path().join("local.key");
            let key = Ed25519SigningKey::from_bytes(&[32; 32]).unwrap();
            let mut file = private_options().create(true).truncate(true).open(&key_path).unwrap();
            file.write_all(hex::encode(key.to_bytes()).as_bytes()).unwrap();
            crate::mesh_routing::MeshRouter::from_lookup(|name| match name {
                MESH_NODE_ID_ENV => Some("local".to_owned()),
                MESH_SIGNING_KEY_FILE_ENV => Some(key_path.display().to_string()),
                MESH_PEERS_FILE_ENV => Some(self.refresher.source.path.display().to_string()),
                MESH_DIRECTORY_ID_ENV => Some(self.payload.mesh_id.clone()),
                MESH_DIRECTORY_OWNER_KEYS_ENV => Some(serde_json::json!([
                    hex::encode(self.owner.verifying_key().to_bytes())
                ]).to_string()),
                MESH_DIRECTORY_STATE_ENV => Some(self.refresher.state_path.display().to_string()),
                MESH_REPLAY_JOURNAL_ENV => Some(self.dir.path().join("replay").display().to_string()),
                _ => None,
            }).unwrap().unwrap()
        }
    }

    fn wait_until(mut ready: impl FnMut() -> bool) {
        let start = Instant::now();
        while !ready() {
            assert!(start.elapsed() < Duration::from_secs(5), "membership worker did not converge");
            std::thread::sleep(Duration::from_millis(10));
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
    fn removed_peer_is_published_only_after_its_checkpoint_is_committed() {
        let mut fixture = Fixture::new();
        let router = fixture.router();
        let before = router.directory();
        let peer_key = Ed25519SigningKey::from_bytes(&[33; 32]).unwrap();
        fixture.payload.generation = 2;
        fixture.payload.peers.truncate(1);
        fixture.write_source();
        fixture.refresh().unwrap();
        assert_eq!(read_checkpoint(&fixture.refresher.state_path).ok().unwrap().generation, 2);
        assert!(router.directory().is_empty());
        assert_eq!(before.len(), 1, "retained snapshots must remain immutable");
        assert!(matches!(
            router.accept_inbound(&fixture.envelope(&peer_key)),
            Err(MeshForwardError::UnknownPeer(_)),
        ));
    }

    #[test]
    fn key_and_endpoint_rotation_update_existing_router_without_clearing_replays() {
        let mut fixture = Fixture::new();
        let router = fixture.router();
        let old_key = Ed25519SigningKey::from_bytes(&[33; 32]).unwrap();
        let new_key = Ed25519SigningKey::from_bytes(&[34; 32]).unwrap();
        let accepted = fixture.envelope(&old_key);
        router.accept_inbound(&accepted).unwrap();
        fixture.payload.generation = 2;
        fixture.payload.peers[1].public_key_hex = hex::encode(new_key.verifying_key().to_bytes());
        fixture.payload.peers[1].endpoint = "http://127.0.0.1:29999".to_owned();
        fixture.write_source();
        fixture.refresh().unwrap();
        assert_eq!(
            router.directory().peer(&TailscaleNodeId::new("peer")).unwrap().endpoint,
            "http://127.0.0.1:29999",
        );
        assert!(matches!(
            router.accept_inbound(&fixture.envelope(&old_key)),
            Err(MeshForwardError::SignatureInvalid { .. }),
        ));
        router.accept_inbound(&fixture.envelope(&new_key)).unwrap();
        fixture.payload.generation = 3;
        fixture.payload.peers[1].public_key_hex = hex::encode(old_key.verifying_key().to_bytes());
        fixture.write_source();
        fixture.refresh().unwrap();
        assert!(matches!(router.accept_inbound(&accepted), Err(MeshForwardError::Replayed { .. })));
        assert!(router.has_durable_replay());
        assert_eq!(router.forward_usage().unwrap(), crate::mesh_routing::MeshForwardUsage::default());
    }

    #[test]
    fn queued_inbound_nonce_remains_consumed_when_membership_changes_before_dispatch() {
        use std::future::Future;
        use std::task::{Context, Waker};

        let mut fixture = Fixture::new();
        let router = fixture.router();
        let peer_key = Ed25519SigningKey::from_bytes(&[33; 32]).unwrap();
        let envelope = fixture.envelope(&peer_key);
        let original_peers = fixture.payload.peers.clone();
        // Hold only the replay journal, not membership. The real worker queues
        // admission while the membership writer publishes a removal.
        let journal = router.durable_replay.as_ref().unwrap().lock().unwrap();
        let mut pending = Box::pin(router.accept_inbound_async(&envelope));
        assert!(pending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        fixture.payload.generation = 2;
        fixture.payload.peers.truncate(1);
        fixture.write_source();
        fixture.refresh().unwrap();
        drop(journal);
        let result = fcp_async_core::runtime::block_on_sync(
            fcp_async_core::time::timeout(Duration::from_secs(5), pending),
        ).unwrap().unwrap();
        assert!(matches!(result, Err(MeshForwardError::Malformed { field: "peer_directory", .. })));
        fixture.payload.generation = 3;
        fixture.payload.peers = original_peers;
        fixture.write_source();
        fixture.refresh().unwrap();
        assert!(matches!(
            fcp_async_core::runtime::block_on_sync(router.accept_inbound_async(&envelope)).unwrap(),
            Err(MeshForwardError::Replayed { .. }),
        ));
    }

    #[test]
    fn peer_authority_fences_old_snapshots_even_when_a_removed_peer_is_readded() {
        let mut fixture = Fixture::new();
        let router = fixture.router();
        let snapshot = router.trusted_peer(&TailscaleNodeId::new("peer")).unwrap();
        let original_peers = fixture.payload.peers.clone();
        fixture.payload.generation = 2;
        fixture.payload.peers.truncate(1);
        fixture.write_source();
        fixture.refresh().unwrap();
        fixture.payload.generation = 3;
        fixture.payload.peers = original_peers;
        fixture.write_source();
        fixture.refresh().unwrap();
        assert!(router.ensure_current_peer(&snapshot).is_err());
        assert_eq!(router.directory().len(), 1);
    }

    #[test]
    fn file_worker_rotates_removes_and_readds_peers_without_losing_nonce_history() {
        let mut fixture = Fixture::new();
        let router = fixture.start_file_router();
        let old_key = Ed25519SigningKey::from_bytes(&[33; 32]).unwrap();
        let new_key = Ed25519SigningKey::from_bytes(&[34; 32]).unwrap();
        let accepted = fixture.envelope(&old_key);
        router.accept_inbound(&accepted).unwrap();
        let original_peers = fixture.payload.peers.clone();
        fixture.payload.generation = 2;
        fixture.payload.peers[1].public_key_hex = hex::encode(new_key.verifying_key().to_bytes());
        fixture.payload.peers[1].endpoint = "http://127.0.0.1:29999".to_owned();
        fixture.write_source();
        wait_until(|| router.directory().peer(&TailscaleNodeId::new("peer"))
            .is_some_and(|peer| peer.verifying_key == new_key.verifying_key()));
        assert_eq!(read_checkpoint(&fixture.refresher.state_path).ok().unwrap().generation, 2);
        assert!(matches!(router.accept_inbound(&fixture.envelope(&old_key)),
            Err(MeshForwardError::SignatureInvalid { .. })));
        router.accept_inbound(&fixture.envelope(&new_key)).unwrap();
        fixture.payload.generation = 3;
        fixture.payload.peers.truncate(1);
        fixture.write_source();
        wait_until(|| read_checkpoint(&fixture.refresher.state_path).ok()
            .is_some_and(|state| state.generation == 3) && router.directory().is_empty());
        assert!(router.accept_inbound(&fixture.envelope(&new_key)).is_err());
        fixture.payload.generation = 4;
        fixture.payload.peers = original_peers;
        fixture.write_source();
        wait_until(|| router.directory().peer(&TailscaleNodeId::new("peer"))
            .is_some_and(|peer| peer.verifying_key == old_key.verifying_key()));
        assert!(matches!(router.accept_inbound(&accepted), Err(MeshForwardError::Replayed { .. })));
        drop(router);
        // Worker shutdown must release the checkpoint lock only after its last
        // possible write, and restart must preserve the same replay journal.
        let restarted = fixture.start_file_router();
        assert!(matches!(restarted.accept_inbound(&accepted), Err(MeshForwardError::Replayed { .. })));
        assert_eq!(read_checkpoint(&fixture.refresher.state_path).ok().unwrap().generation, 4);
    }

    #[test]
    fn file_worker_fences_untrusted_replacements_and_recovers_with_a_valid_successor() {
        let mut fixture = Fixture::new();
        let router = fixture.start_file_router();
        let accepted_checkpoint = read_checkpoint(&fixture.refresher.state_path).ok().unwrap();
        let peer_key = Ed25519SigningKey::from_bytes(&[33; 32]).unwrap();
        let pending = fixture.envelope(&peer_key);
        fixture.owner = Ed25519SigningKey::from_bytes(&[99; 32]).unwrap();
        fixture.payload.generation = 2;
        fixture.write_source();
        wait_until(|| router.directory().is_empty());
        assert!(router.accept_inbound(&pending).is_err());
        assert_eq!(read_checkpoint(&fixture.refresher.state_path).ok().unwrap(), accepted_checkpoint);
        fixture.owner = Ed25519SigningKey::from_bytes(&[31; 32]).unwrap();
        fixture.write_source();
        wait_until(|| router.directory().len() == 1);
        router.accept_inbound(&pending).unwrap();
        assert_eq!(read_checkpoint(&fixture.refresher.state_path).ok().unwrap().generation, 2);
    }

    #[test]
    fn delivered_forward_crossing_a_membership_change_is_never_retry_safe() {
        use std::io::{BufRead, BufReader};
        use fcp_mesh::invoke_route::{MeshForwardBody, MeshForwardEnvelope, MeshForwardReply};
        use crate::mesh_routing::{MeshForwardFailure, MeshForwardUsage};

        let mut fixture = Fixture::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        fixture.payload.generation = 2;
        fixture.payload.peers[1].endpoint = format!("http://{}", listener.local_addr().unwrap());
        fixture.write_source();
        fixture.refresh().unwrap();
        let router = fixture.router();
        let server = std::thread::spawn(move || {
            let start = Instant::now();
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(start.elapsed() < Duration::from_secs(5));
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let envelope = {
                let mut reader = BufReader::new(&mut socket);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line, "POST /rpc/mesh/forward HTTP/1.1\r\n");
                let mut length = None;
                let mut header_bytes = line.len();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    header_bytes += line.len();
                    assert!(!line.is_empty() && header_bytes <= 8192);
                    if line == "\r\n" { break; }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let length = length.unwrap();
                assert!(length <= 8192);
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                serde_json::from_slice::<MeshForwardEnvelope>(&bytes).unwrap()
            };
            assert!(matches!(&envelope.body, MeshForwardBody::Invoke { .. }));
            // Receipt precedes revocation. A signed answer from the old key is
            // still genuine evidence, but must not pass the current-generation gate.
            fixture.payload.generation = 3;
            fixture.payload.peers.truncate(1);
            fixture.write_source();
            fixture.refresh().unwrap();
            let key = Ed25519SigningKey::from_bytes(&[33; 32]).unwrap();
            let reply = MeshForwardReply::sign(
                &key, TailscaleNodeId::new("peer"), &envelope, 200, "{}".to_owned(),
            );
            let body = serde_json::to_vec(&reply).unwrap();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            socket.write_all(&body).unwrap();
            fixture
        });
        let result = fcp_async_core::runtime::block_on_sync(router.forward(
            &TailscaleNodeId::new("peer"),
            MeshForwardBody::Invoke {
                request_json: "{\"operation\":\"non_idempotent_write\"}".to_owned(),
                asserted_principal: None,
            },
        )).unwrap();
        let fixture = server.join().unwrap();
        let error = result.unwrap_err();
        assert!(matches!(error, MeshForwardFailure::OutcomeUnknown { .. }));
        assert!(!error.safe_to_retry());
        assert!(router.directory().is_empty());
        assert_eq!(router.forward_usage().unwrap(), MeshForwardUsage::default());
        drop(router);
        drop(fixture);
    }

    mod continuity {
        use std::future::Future;
        use std::io::{BufRead, BufReader};
        use std::task::{Context, Waker};

        use fcp_mesh::invoke_route::{MeshForwardBody, MeshForwardEnvelope, MeshForwardReply};
        use crate::mesh_routing::{MeshForwardFailure, MeshForwardUsage};

        use super::*;

        fn publish(fixture: &mut Fixture) {
            fixture.payload.generation += 1;
            fixture.write_source();
            fixture.refresh().unwrap();
        }

        fn add_other_peer(fixture: &mut Fixture) {
            let key = Ed25519SigningKey::from_bytes(&[35; 32]).unwrap();
            fixture.payload.peers.push(MeshPeerConfig {
                node_id: "other".to_owned(),
                endpoint: "http://127.0.0.1:19003".to_owned(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            });
        }

        #[test]
        fn queued_admission_survives_published_renewal_and_peer_join() {
            for join in [false, true] {
                let mut fixture = Fixture::new();
                let router = fixture.router();
                let key = Ed25519SigningKey::from_bytes(&[33; 32]).unwrap();
                let envelope = fixture.envelope(&key);
                let before = router.trusted_directory().unwrap();
                let journal = router.durable_replay.as_ref().unwrap().lock().unwrap();
                let mut pending = Box::pin(router.accept_inbound_async(&envelope));
                assert!(pending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
                fixture.payload.expires_at_ms += 60_000;
                if join {
                    add_other_peer(&mut fixture);
                }
                publish(&mut fixture);
                assert!(!Arc::ptr_eq(&before, &router.trusted_directory().unwrap()));
                drop(journal);
                fcp_async_core::runtime::block_on_sync(
                    fcp_async_core::time::timeout(Duration::from_secs(5), pending),
                ).unwrap().unwrap().unwrap();
                assert!(matches!(
                    router.accept_inbound(&envelope),
                    Err(MeshForwardError::Replayed { .. }),
                ), "successful continuity must not reset nonce history");
            }
        }

        #[test]
        fn renewal_after_expiration_does_not_revive_old_peer_snapshots() {
            for expiration in ["observed", "wall_clock", "monotonic"] {
                let mut fixture = Fixture::new();
                let router = fixture.router();
                let node = TailscaleNodeId::new("peer");
                let old = router.trusted_peer(&node).unwrap();
                {
                    let mut current = fixture.membership.publication.write().unwrap();
                    match expiration {
                        "observed" => current.validity.expired.store(true, Ordering::Release),
                        "wall_clock" => current.validity.expires_at_ms = 0,
                        _ => current.validity.deadline = Instant::now(),
                    }
                }
                // Do not check the old snapshot before publication: the writer
                // must notice an expiry gap even when no request latched it.
                fixture.payload.expires_at_ms += 60_000;
                publish(&mut fixture);
                assert!(router.ensure_current_peer(&old).is_err(),
                    "{expiration}: an authority gap breaks continuity");
                let fresh = router.trusted_peer(&node).unwrap();
                router.ensure_current_peer(&fresh).unwrap();
            }
        }

        #[test]
        fn source_and_checkpoint_fences_are_not_bypassed_by_peer_continuity() {
            let mut fixture = Fixture::new();
            let router = fixture.router();
            let node = TailscaleNodeId::new("peer");
            let snapshot = router.trusted_peer(&node).unwrap();
            for reason in ["signed_source_rejected", "checkpoint_commit_in_progress"] {
                fixture.membership.refuse(reason);
                assert!(router.ensure_current_peer(&snapshot).is_err());
                assert!(router.trusted_peer(&node).is_err());
                // Use the real same-generation revalidation to recover a
                // transient source fence, without creating a new authority.
                fixture.refresh().unwrap();
                router.ensure_current_peer(&snapshot).unwrap();
            }
            // The terminal storage-failure state must refuse preserved authority.
            fixture.refresher.storage_failed = true;
            fixture.membership.refuse("checkpoint_failure_requires_restart");
            fixture.payload.expires_at_ms += 60_000;
            assert!(fixture.refresh().is_err());
            assert!(router.ensure_current_peer(&snapshot).is_err());
        }

        // Receive a complete signed invoke before publishing changes, then
        // return a reply signed by the original executor. Every I/O is bounded.
        // This tests the actual forwarding path, not just an epoch comparison.
        fn forward_across_update(change: fn(&mut Fixture)) -> Result<MeshForwardReply, MeshForwardFailure> {
            let mut fixture = Fixture::new();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            fixture.payload.peers[1].endpoint = format!("http://{}", listener.local_addr().unwrap());
            publish(&mut fixture);
            let router = fixture.router();
            let server = std::thread::spawn(move || {
                let start = Instant::now();
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(start.elapsed() < Duration::from_secs(5), "forward did not connect");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let envelope = {
                    let mut reader = BufReader::new(&mut socket);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    assert_eq!(line, "POST /rpc/mesh/forward HTTP/1.1\r\n");
                    let mut length = None;
                    let mut header_bytes = line.len();
                    loop {
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                        header_bytes += line.len();
                        assert!(!line.is_empty() && header_bytes <= 8192);
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            length = Some(value.trim().parse::<usize>().unwrap());
                        }
                    }
                    let length = length.unwrap();
                    assert!(length <= 8192);
                    let mut bytes = vec![0; length];
                    reader.read_exact(&mut bytes).unwrap();
                    serde_json::from_slice::<MeshForwardEnvelope>(&bytes).unwrap()
                };
                assert!(matches!(&envelope.body, MeshForwardBody::Invoke { .. }));
                change(&mut fixture);
                publish(&mut fixture);
                let key = Ed25519SigningKey::from_bytes(&[33; 32]).unwrap();
                let reply = MeshForwardReply::sign(
                    &key,
                    TailscaleNodeId::new("peer"),
                    &envelope,
                    200,
                    "{\"committed\":true}".to_owned(),
                );
                let body = serde_json::to_vec(&reply).unwrap();
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                socket.write_all(&body).unwrap();
                fixture
            });
            let result = fcp_async_core::runtime::block_on_sync(router.forward(
                &TailscaleNodeId::new("peer"),
                MeshForwardBody::Invoke {
                    request_json: "{\"operation\":\"non_idempotent_write\"}".to_owned(),
                    asserted_principal: None,
                },
            )).unwrap();
            let fixture = server.join().unwrap();
            assert_eq!(router.forward_usage().unwrap(), MeshForwardUsage::default());
            drop(router);
            drop(fixture);
            result
        }

        #[test]
        fn delivered_reply_survives_renewal_and_unrelated_peer_churn() {
            fn renew(fixture: &mut Fixture) {
                fixture.payload.expires_at_ms += 60_000;
            }
            fn other_churn(fixture: &mut Fixture) {
                add_other_peer(fixture);
                publish(fixture);
                let key = Ed25519SigningKey::from_bytes(&[36; 32]).unwrap();
                fixture.payload.peers[2].public_key_hex = hex::encode(key.verifying_key().to_bytes());
                fixture.payload.peers[2].endpoint = "http://127.0.0.1:19004".to_owned();
                publish(fixture);
                fixture.payload.peers.truncate(2);
            }
            for change in [renew as fn(&mut Fixture), add_other_peer, other_churn] {
                let reply = forward_across_update(change).unwrap();
                assert_eq!(reply.status, 200);
                assert_eq!(reply.served_by.as_str(), "peer");
                assert_eq!(reply.body_json, "{\"committed\":true}");
            }
        }

        #[test]
        fn delivered_reply_cannot_cross_target_removal_or_key_and_endpoint_aba() {
            fn remove(fixture: &mut Fixture) {
                fixture.payload.peers.truncate(1);
            }
            fn rotate_and_restore(fixture: &mut Fixture) {
                let original = fixture.payload.peers[1].public_key_hex.clone();
                let replacement = Ed25519SigningKey::from_bytes(&[37; 32]).unwrap();
                fixture.payload.peers[1].public_key_hex = hex::encode(replacement.verifying_key().to_bytes());
                publish(fixture);
                fixture.payload.peers[1].public_key_hex = original;
            }
            fn move_endpoint_and_restore(fixture: &mut Fixture) {
                let original = fixture.payload.peers[1].endpoint.clone();
                fixture.payload.peers[1].endpoint = "http://127.0.0.1:19006".to_owned();
                publish(fixture);
                fixture.payload.peers[1].endpoint = original;
            }
            for change in [
                remove as fn(&mut Fixture), rotate_and_restore, move_endpoint_and_restore,
            ] {
                let error = forward_across_update(change).unwrap_err();
                assert!(matches!(error, MeshForwardFailure::OutcomeUnknown { .. }));
                assert!(!error.safe_to_retry(), "a delivered write must never fan out");
            }
        }
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
