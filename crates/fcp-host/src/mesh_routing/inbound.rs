//! Bounded blocking-I/O bridge for durable inbound mesh admission.
//!
//! Only verified nonce identities enter this queue. The worker never dispatches
//! a connector operation; success means the existing journal has synced the
//! nonce. Cancellation cannot undo a commit or permit a repeated dispatch.

use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;

use fcp_async_core::channel::oneshot;
use fcp_mesh::invoke_route::MeshForwardError;

use crate::mesh_replay::{DurableMeshReplayGuard, VerifiedMeshReplayNonce, replay_unavailable};
use crate::{HostError, HostResult};

const QUEUE_CAPACITY: usize = 32;
type AdmissionResult = Result<(), MeshForwardError>;

struct Request {
    identity: VerifiedMeshReplayNonce,
    reply: oneshot::Sender<AdmissionResult>,
}

pub(super) struct InboundReplayWorker {
    sender: Option<mpsc::SyncSender<Request>>,
    thread: Option<JoinHandle<()>>,
}

impl InboundReplayWorker {
    pub(super) fn spawn(state: Arc<Mutex<DurableMeshReplayGuard>>) -> HostResult<Self> {
        Self::spawn_with_clock(state, QUEUE_CAPACITY, super::unix_now_ms)
    }

    fn spawn_with_clock(
        state: Arc<Mutex<DurableMeshReplayGuard>>,
        capacity: usize,
        clock: impl Fn() -> u64 + Send + 'static,
    ) -> HostResult<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Request>(capacity);
        let thread = std::thread::Builder::new()
            .name("fcp-mesh-replay".to_owned())
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    let result = match state.lock() {
                        // Queue and mutex waits can outlive signed freshness.
                        // Sampling under the lock also preserves clock order
                        // with embedded synchronous admission callers.
                        Ok(mut guard) => guard.accept_verified(&request.identity, clock()),
                        Err(_) => Err(replay_unavailable("state_poisoned")),
                    };
                    // A dropped receiver does not undo durable consumption.
                    // No operation is ever executed by this worker.
                    let _ = request.reply.send(result);
                }
            })
            .map_err(|error| {
                HostError::Internal(format!("cannot start mesh replay admission worker: {error}"))
            })?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
        })
    }

    fn submit(
        &self,
        identity: VerifiedMeshReplayNonce,
    ) -> Result<oneshot::Receiver<AdmissionResult>, MeshForwardError> {
        let (reply, receiver) = oneshot::channel();
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| replay_unavailable("worker_stopped"))?;
        sender
            .try_send(Request { identity, reply })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => replay_unavailable("replay_admission_queue_full"),
                mpsc::TrySendError::Disconnected(_) => replay_unavailable("worker_stopped"),
            })?;
        Ok(receiver)
    }

    pub(super) async fn check(&self, identity: VerifiedMeshReplayNonce) -> AdmissionResult {
        self.submit(identity)?
            .await
            .map_err(|_| replay_unavailable("worker_stopped"))?
    }
}

impl Drop for InboundReplayWorker {
    fn drop(&mut self) {
        // Disconnect, drain previously queued work, and join before the last
        // worker-owned journal handle can be replaced. A stuck filesystem can
        // delay shutdown; detaching the writer would instead risk overlapping
        // owners of the node's replay state.
        drop(self.sender.take());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!(
                event = "mesh_inbound_replay_worker_failed",
                "mesh replay worker panicked; admission remained closed"
            );
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    use fcp_core::TailscaleNodeId;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::{MeshForwardBody, MeshForwardEnvelope, MeshPeerDirectory};

    const READY: u64 = 100;
    const WINDOW: u64 = 10;

    fn identity_for(target: &str, now_ms: u64) -> VerifiedMeshReplayNonce {
        let key = Ed25519SigningKey::generate();
        let directory = MeshPeerDirectory::from_json(
            TailscaleNodeId::new(target),
            &serde_json::json!([{
                "node_id": "origin",
                "endpoint": "http://127.0.0.1:1",
                "public_key_hex": hex::encode(key.verifying_key().to_bytes()),
            }])
            .to_string(),
        )
        .unwrap();
        let envelope = MeshForwardEnvelope::sign(
            &key,
            TailscaleNodeId::new("origin"),
            TailscaleNodeId::new(target),
            now_ms,
            MeshForwardBody::Introspect {
                connector_id: "fcp.test:utility:1.0.0".to_owned(),
            },
        )
        .unwrap();
        VerifiedMeshReplayNonce::verify(&envelope, &directory, now_ms, WINDOW).unwrap()
    }

    fn identity(now_ms: u64) -> VerifiedMeshReplayNonce {
        identity_for("executor", now_ms)
    }

    fn state(path: &Path) -> Arc<Mutex<DurableMeshReplayGuard>> {
        Arc::new(Mutex::new(
            DurableMeshReplayGuard::open(path, &TailscaleNodeId::new("executor"), WINDOW, 8, READY)
                .unwrap(),
        ))
    }

    fn result(receiver: oneshot::Receiver<AdmissionResult>) -> AdmissionResult {
        fcp_async_core::runtime::block_on_sync(receiver).unwrap().unwrap()
    }

    fn unavailable(error: &MeshForwardError, reason: &str) -> bool {
        matches!(error, MeshForwardError::Malformed { field: "replay_journal", detail }
            if detail.contains(reason))
    }

    #[test]
    fn cancellation_does_not_undo_a_queued_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let worker = InboundReplayWorker::spawn_with_clock(state, 2, || READY).unwrap();
        let nonce = identity(READY);
        drop(worker.submit(nonce.clone()).unwrap());
        assert!(matches!(
            result(worker.submit(nonce).unwrap()),
            Err(MeshForwardError::Replayed { .. })
        ));
    }

    #[test]
    fn worker_rechecks_freshness_after_mutex_wait() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let now = Arc::new(AtomicU64::new(READY));
        let clock = Arc::clone(&now);
        let worker = InboundReplayWorker::spawn_with_clock(Arc::clone(&state), 2, move || {
            clock.load(Ordering::SeqCst)
        })
        .unwrap();
        let held = state.lock().unwrap();
        let pending = worker.submit(identity(READY)).unwrap();
        now.store(READY + WINDOW + 1, Ordering::SeqCst);
        drop(held);
        assert!(matches!(result(pending), Err(MeshForwardError::Stale { .. })));
        result(worker.submit(identity(READY + WINDOW + 1)).unwrap()).unwrap();
    }

    #[test]
    fn full_queue_refuses_without_waiting_for_disk_or_mutex() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let worker = InboundReplayWorker::spawn_with_clock(Arc::clone(&state), 1, || READY).unwrap();
        let held = state.lock().unwrap();
        let mut receivers = Vec::new();
        let mut refused = Vec::new();
        // At most one request can leave the queue while the mutex is held.
        // Therefore three submissions include a refusal regardless of timing.
        for _ in 0..3 {
            let nonce = identity(READY);
            match worker.submit(nonce.clone()) {
                Ok(receiver) => receivers.push(receiver),
                Err(error) => {
                    assert!(unavailable(&error, "replay_admission_queue_full"));
                    refused.push(nonce);
                }
            }
        }
        drop(held);
        assert!(!refused.is_empty());
        for receiver in receivers {
            result(receiver).unwrap();
        }
        // A job refused before enqueueing has not consumed its nonce.
        for nonce in refused {
            result(worker.submit(nonce).unwrap()).unwrap();
        }
    }

    #[test]
    fn shutdown_drains_work_and_releases_the_file_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay");
        let state = state(&path);
        let worker = InboundReplayWorker::spawn_with_clock(state, 2, || READY).unwrap();
        let nonce = identity(READY);
        let pending = worker.submit(nonce.clone()).unwrap();
        drop(worker);
        result(pending).unwrap();
        let mut restored = DurableMeshReplayGuard::open(
            &path,
            &TailscaleNodeId::new("executor"),
            WINDOW,
            8,
            READY,
        )
        .unwrap();
        assert!(matches!(
            restored.accept_verified(&nonce, READY),
            Err(MeshForwardError::Replayed { .. })
        ));
    }

    #[test]
    fn poisoned_state_never_reports_admission_success() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = state.lock().unwrap();
            panic!("poison replay state");
        }));
        let worker = InboundReplayWorker::spawn_with_clock(state, 2, || READY).unwrap();
        let error = result(worker.submit(identity(READY)).unwrap()).unwrap_err();
        assert!(unavailable(&error, "state_poisoned"));
    }

    #[test]
    fn verified_identity_cannot_cross_node_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let worker = InboundReplayWorker::spawn_with_clock(state, 2, || READY).unwrap();
        let error = result(worker.submit(identity_for("another-executor", READY)).unwrap())
            .unwrap_err();
        assert!(unavailable(&error, "node_scope_mismatch"));
        result(worker.submit(identity(READY)).unwrap()).unwrap();
    }

    #[test]
    fn clock_rollback_is_not_reported_as_success() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let now = Arc::new(AtomicU64::new(READY + 1));
        let clock = Arc::clone(&now);
        let worker = InboundReplayWorker::spawn_with_clock(state, 2, move || {
            clock.load(Ordering::SeqCst)
        })
        .unwrap();
        result(worker.submit(identity(READY)).unwrap()).unwrap();
        now.store(READY, Ordering::SeqCst);
        let error = result(worker.submit(identity(READY)).unwrap()).unwrap_err();
        assert!(unavailable(&error, "clock_rollback"));
    }

    #[test]
    fn missing_sender_fails_closed() {
        let worker = InboundReplayWorker {
            sender: None,
            thread: None,
        };
        let result = worker.submit(identity(READY));
        assert!(matches!(result, Err(ref error) if unavailable(error, "worker_stopped")));
    }

    #[test]
    fn disconnected_worker_fails_closed() {
        let (sender, receiver) = mpsc::sync_channel::<Request>(1);
        drop(receiver);
        let worker = InboundReplayWorker {
            sender: Some(sender),
            thread: None,
        };
        let result = worker.submit(identity(READY));
        assert!(matches!(result, Err(ref error) if unavailable(error, "worker_stopped")));
    }
}
