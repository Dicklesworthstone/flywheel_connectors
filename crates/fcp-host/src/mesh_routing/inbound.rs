//! Bounded blocking-I/O bridge for durable inbound mesh admission.
//!
//! Only verified nonce identities enter this queue. The worker never dispatches
//! a connector operation; success means the existing journal has synced the
//! nonce. Cancellation cannot undo a commit or permit a repeated dispatch.
//! Reply waits have a deadline independent of filesystem progress. Expiry drops
//! only the caller's receiver, never the journal writer or its live nonce state.
//! Authenticated origins have separate occupancy limits covering both queued
//! and active journal work. Cancelling a waiter does not release its job's slot.
//! Already queued work is committed in groups without waiting to fill a batch.
//! Grouping does not increase the total number of admitted jobs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use fcp_async_core::channel::oneshot;
use fcp_mesh::invoke_route::MeshForwardError;

use crate::mesh_replay::{
    DurableMeshReplayGuard, MAX_REPLAY_GROUP_SIZE, VerifiedMeshReplayNonce, replay_unavailable,
};
use crate::{HostError, HostResult};

const QUEUE_CAPACITY: usize = 32;
const MAX_PENDING_TOTAL: usize = QUEUE_CAPACITY + 1;
const MAX_PENDING_PER_PEER: usize = 4;
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
type AdmissionResult = Result<(), MeshForwardError>;

/// Short-lived accounting only: never lock this state during journal I/O.
#[derive(Default)]
struct PeerAdmissions {
    pending: Mutex<BTreeMap<String, usize>>,
}

struct PeerPermit {
    admissions: Arc<PeerAdmissions>,
    origin: String,
}

impl PeerAdmissions {
    fn reserve(admissions: &Arc<Self>, origin: &str) -> Result<PeerPermit, MeshForwardError> {
        let origin = origin.to_owned();
        let mut pending = admissions
            .pending
            .lock()
            .map_err(|_| replay_unavailable("replay_peer_admission_poisoned"))?;
        if pending.get(&origin).copied().unwrap_or(0) >= MAX_PENDING_PER_PEER {
            return Err(replay_unavailable("replay_admission_peer_limit"));
        }
        // A group can leave the channel while its jobs still occupy the
        // journal. Bound queued PLUS active-group work, not just queue slots.
        if pending.values().copied().sum::<usize>() >= MAX_PENDING_TOTAL {
            return Err(replay_unavailable("replay_admission_total_limit"));
        }
        // Only a verified nonce can select the origin. Remove empty buckets
        // when reservations end; no historical peer IDs accumulate here.
        *pending.entry(origin.clone()).or_default() += 1;
        drop(pending);
        Ok(PeerPermit {
            admissions: Arc::clone(admissions),
            origin,
        })
    }
}

impl Drop for PeerPermit {
    fn drop(&mut self) {
        // Existing jobs must release during unwinding, but poison is not
        // cleared: new admissions still fail closed in reserve().
        let mut pending = self
            .admissions
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = pending.get_mut(&self.origin) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                pending.remove(&self.origin);
            }
        }
    }
}

struct Request {
    // Fields drop in declaration order. Release capacity before dropping the
    // sender can wake a waiter during channel teardown or rejected enqueue.
    permit: PeerPermit,
    identity: VerifiedMeshReplayNonce,
    reply: oneshot::Sender<AdmissionResult>,
}

pub(super) struct InboundReplayWorker {
    sender: Option<mpsc::SyncSender<Request>>,
    thread: Option<JoinHandle<()>>,
    peers: Arc<PeerAdmissions>,
}

fn extend_ready_group(group: &mut Vec<Request>, receiver: &mpsc::Receiver<Request>) {
    let remaining = MAX_REPLAY_GROUP_SIZE.saturating_sub(group.len());
    group.extend(receiver.try_iter().take(remaining));
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
                while let Ok(first) = receiver.recv() {
                    let mut group = Vec::with_capacity(MAX_REPLAY_GROUP_SIZE);
                    group.push(first);
                    let outcomes = state.lock().map_or_else(
                        |_| vec![Err(replay_unavailable("state_poisoned"))],
                        |mut guard| {
                            // Drain only after obtaining the journal lock so
                            // work accumulated during a mutex wait can share
                            // the sync. Never delay a lone request to fill up.
                            extend_ready_group(&mut group, &receiver);
                            let identities = group
                                .iter()
                                .map(|request| &request.identity)
                                .collect::<Vec<_>>();
                            // One clock sample under the lock preserves order
                            // with embedded synchronous admission callers.
                            guard.accept_verified_batch(&identities, clock())
                        },
                    );
                    // The journal lock and sync barrier end before any caller
                    // is notified. Cancellation never undoes a committed nonce.
                    for (request, result) in group.into_iter().zip(outcomes) {
                        let Request { permit, reply, .. } = request;
                        drop(permit);
                        let _ = reply.send(result);
                    }
                }
            })
            .map_err(|error| {
                HostError::Internal(format!(
                    "cannot start mesh replay admission worker: {error}"
                ))
            })?;
        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
            peers: Arc::new(PeerAdmissions::default()),
        })
    }

    fn submit(
        &self,
        identity: VerifiedMeshReplayNonce,
    ) -> Result<oneshot::Receiver<AdmissionResult>, MeshForwardError> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| replay_unavailable("worker_stopped"))?;
        let permit = PeerAdmissions::reserve(&self.peers, identity.origin())?;
        let (reply, receiver) = oneshot::channel();
        sender
            .try_send(Request {
                permit,
                identity,
                reply,
            })
            .map_err(|error| match error {
                // A rejected Request drops its permit. No nonce reached the
                // journal and no capacity remains reserved on these paths.
                mpsc::TrySendError::Full(_) => replay_unavailable("replay_admission_queue_full"),
                mpsc::TrySendError::Disconnected(_) => replay_unavailable("worker_stopped"),
            })?;
        Ok(receiver)
    }

    pub(super) async fn check(&self, identity: VerifiedMeshReplayNonce) -> AdmissionResult {
        wait_for_admission(self.submit(identity)?, ADMISSION_TIMEOUT).await
    }
}

async fn wait_for_admission(
    completion: oneshot::Receiver<AdmissionResult>,
    timeout: Duration,
) -> AdmissionResult {
    // A timeout may race a durable commit. Do not revoke the nonce, stop the
    // worker, or report provable non-delivery. The awaiting handler must not
    // execute on this error, and upstream unsigned-refusal rules still apply.
    fcp_async_core::time::timeout(timeout, completion)
        .await
        .map_err(|_| {
            tracing::warn!(
                event = "mesh_inbound_replay_deadline",
                timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                "mesh admission reply deadline elapsed; nonce may be consumed"
            );
            replay_unavailable("replay_admission_deadline")
        })?
        .map_err(|_| replay_unavailable("worker_stopped"))?
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
        identity_from("origin", target, now_ms)
    }

    fn identity_from(origin: &str, target: &str, now_ms: u64) -> VerifiedMeshReplayNonce {
        let key = Ed25519SigningKey::generate();
        let directory = MeshPeerDirectory::from_json(
            TailscaleNodeId::new(target),
            &serde_json::json!([{
                "node_id": origin,
                "endpoint": "http://127.0.0.1:1",
                "public_key_hex": hex::encode(key.verifying_key().to_bytes()),
            }])
            .to_string(),
        )
        .unwrap();
        let envelope = MeshForwardEnvelope::sign(
            &key,
            TailscaleNodeId::new(origin),
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
        fcp_async_core::runtime::block_on_sync(receiver)
            .unwrap()
            .unwrap()
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
        assert!(matches!(
            result(pending),
            Err(MeshForwardError::Stale { .. })
        ));
        result(worker.submit(identity(READY + WINDOW + 1)).unwrap()).unwrap();
    }

    #[test]
    fn full_queue_refuses_without_waiting_for_disk_or_mutex() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let worker =
            InboundReplayWorker::spawn_with_clock(Arc::clone(&state), 1, || READY).unwrap();
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
        let error = result(
            worker
                .submit(identity_for("another-executor", READY))
                .unwrap(),
        )
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
        let worker =
            InboundReplayWorker::spawn_with_clock(state, 2, move || clock.load(Ordering::SeqCst))
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
            peers: Arc::new(PeerAdmissions::default()),
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
            peers: Arc::new(PeerAdmissions::default()),
        };
        let result = worker.submit(identity(READY));
        assert!(matches!(result, Err(ref error) if unavailable(error, "worker_stopped")));
        assert!(worker.peers.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn deadline_releases_waiter_and_rejects_late_success() {
        let (sender, receiver) = oneshot::channel();
        let error = fcp_async_core::runtime::block_on_sync(wait_for_admission(
            receiver,
            Duration::from_millis(1),
        ))
        .unwrap()
        .unwrap_err();
        assert!(unavailable(&error, "replay_admission_deadline"));
        assert!(
            sender.send(Ok(())).is_err(),
            "late success cannot revive the caller"
        );
    }

    #[test]
    fn completed_admission_and_storage_errors_are_preserved() {
        for expected in [Ok(()), Err(replay_unavailable("commit_failed"))] {
            let (sender, receiver) = oneshot::channel();
            sender.send(expected.clone()).unwrap();
            let actual = fcp_async_core::runtime::block_on_sync(wait_for_admission(
                receiver,
                Duration::from_secs(5),
            ))
            .unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn closed_completion_is_not_misclassified_as_deadline() {
        let (sender, receiver) = oneshot::channel();
        drop(sender);
        let error = fcp_async_core::runtime::block_on_sync(wait_for_admission(
            receiver,
            Duration::from_secs(5),
        ))
        .unwrap()
        .unwrap_err();
        assert!(unavailable(&error, "worker_stopped"));
    }

    #[test]
    fn timed_out_job_can_commit_without_dispatch_or_replay() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let worker =
            InboundReplayWorker::spawn_with_clock(Arc::clone(&state), 2, || READY).unwrap();
        let held = state.lock().unwrap();
        let nonce = identity(READY);
        let receiver = worker.submit(nonce.clone()).unwrap();
        let outcome = fcp_async_core::runtime::block_on_sync(wait_for_admission(
            receiver,
            Duration::from_millis(1),
        ));
        // Release before asserting, so even a failed deadline cannot strand
        // the journal thread during stack unwinding.
        drop(held);
        assert!(unavailable(
            &outcome.unwrap().unwrap_err(),
            "replay_admission_deadline"
        ));
        assert!(matches!(
            result(worker.submit(nonce).unwrap()),
            Err(MeshForwardError::Replayed { .. })
        ));
        result(worker.submit(identity(READY)).unwrap()).unwrap();
    }

    #[test]
    fn one_origin_cannot_monopolize_the_journal_queue() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let worker =
            InboundReplayWorker::spawn_with_clock(Arc::clone(&state), QUEUE_CAPACITY, || READY)
                .unwrap();
        let held = state.lock().unwrap();
        let cancelled_nonce = identity(READY);
        let cancelled = worker.submit(cancelled_nonce.clone()).unwrap();
        let mut pending = Vec::new();
        for _ in 1..MAX_PENDING_PER_PEER {
            pending.push(worker.submit(identity(READY)).unwrap());
        }
        let refused_nonce = identity(READY);
        let refusal = worker
            .submit(refused_nonce.clone())
            .err()
            .expect("peer limit");
        assert!(unavailable(&refusal, "replay_admission_peer_limit"));
        let other = worker
            .submit(identity_from("other", "executor", READY))
            .unwrap();
        drop(cancelled);
        let refusal = worker
            .submit(identity(READY))
            .err()
            .expect("job still pending");
        assert!(unavailable(&refusal, "replay_admission_peer_limit"));
        assert_eq!(
            worker.peers.pending.lock().unwrap().get("origin").copied(),
            Some(MAX_PENDING_PER_PEER),
        );
        drop(held);
        for receiver in pending {
            result(receiver).unwrap();
        }
        result(other).unwrap();
        assert!(worker.peers.pending.lock().unwrap().is_empty());
        assert!(matches!(
            result(worker.submit(cancelled_nonce).unwrap()),
            Err(MeshForwardError::Replayed { .. }),
        ));
        result(worker.submit(refused_nonce).unwrap()).unwrap();
    }

    #[test]
    fn queue_refusal_refunds_only_the_rejected_jobs_peer_slot() {
        let (sender, receiver) = mpsc::sync_channel::<Request>(1);
        let worker = InboundReplayWorker {
            sender: Some(sender),
            thread: None,
            peers: Arc::new(PeerAdmissions::default()),
        };
        let accepted = worker.submit(identity(READY)).unwrap();
        let refusal = worker.submit(identity(READY)).err().expect("queue full");
        assert!(unavailable(&refusal, "replay_admission_queue_full"));
        assert_eq!(
            worker.peers.pending.lock().unwrap().get("origin").copied(),
            Some(1),
        );
        drop(receiver.try_recv().unwrap());
        assert!(worker.peers.pending.lock().unwrap().is_empty());
        assert!(
            fcp_async_core::runtime::block_on_sync(accepted)
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn tearing_down_an_unprocessed_channel_releases_every_peer_slot() {
        let (sender, receiver) = mpsc::sync_channel::<Request>(4);
        let mut worker = InboundReplayWorker {
            sender: Some(sender),
            thread: None,
            peers: Arc::new(PeerAdmissions::default()),
        };
        let first = worker.submit(identity(READY)).unwrap();
        let second = worker
            .submit(identity_from("other", "executor", READY))
            .unwrap();
        drop(receiver);
        drop(worker.sender.take());
        assert!(worker.peers.pending.lock().unwrap().is_empty());
        for response in [first, second] {
            assert!(
                fcp_async_core::runtime::block_on_sync(response)
                    .unwrap()
                    .is_err()
            );
        }
    }

    #[test]
    fn teardown_releases_the_slot_before_waking_a_closed_waiter() {
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::atomic::AtomicBool;
        use std::task::{Context, Wake, Waker};

        struct ObserveSlot {
            peers: Arc<PeerAdmissions>,
            available: AtomicBool,
        }
        impl Wake for ObserveSlot {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.available.store(
                    PeerAdmissions::reserve(&self.peers, "origin").is_ok(),
                    Ordering::SeqCst,
                );
            }
        }

        let (sender, receiver) = mpsc::sync_channel::<Request>(MAX_PENDING_PER_PEER);
        let worker = InboundReplayWorker {
            sender: Some(sender),
            thread: None,
            peers: Arc::new(PeerAdmissions::default()),
        };
        let mut first = worker.submit(identity(READY)).unwrap();
        let others = (1..MAX_PENDING_PER_PEER)
            .map(|_| worker.submit(identity(READY)).unwrap())
            .collect::<Vec<_>>();
        let observer = Arc::new(ObserveSlot {
            peers: Arc::clone(&worker.peers),
            available: AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&observer));
        assert!(
            Pin::new(&mut first)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(receiver.try_recv().unwrap());
        assert!(observer.available.load(Ordering::SeqCst));
        drop(receiver);
        drop(others);
        assert!(worker.peers.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn peer_slots_are_released_before_success_and_error_notifications() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let worker =
            InboundReplayWorker::spawn_with_clock(state, QUEUE_CAPACITY, || READY + WINDOW + 1)
                .unwrap();
        assert!(matches!(
            result(worker.submit(identity(READY)).unwrap()),
            Err(MeshForwardError::Stale { .. }),
        ));
        assert!(worker.peers.pending.lock().unwrap().is_empty());
        let fresh = identity(READY + WINDOW + 1);
        result(worker.submit(fresh.clone()).unwrap()).unwrap();
        assert!(worker.peers.pending.lock().unwrap().is_empty());
        assert!(matches!(
            result(worker.submit(fresh).unwrap()),
            Err(MeshForwardError::Replayed { .. }),
        ));
        assert!(worker.peers.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn peer_slot_is_released_during_unwinding() {
        let peers = Arc::new(PeerAdmissions::default());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = PeerAdmissions::reserve(&peers, "origin").unwrap();
            panic!("abandon a journal request during construction");
        }));
        assert!(outcome.is_err());
        assert!(peers.pending.lock().unwrap().is_empty());
        drop(PeerAdmissions::reserve(&peers, "origin").unwrap());
    }

    #[test]
    fn poisoned_peer_accounting_fails_closed_even_after_existing_jobs_release() {
        let peers = Arc::new(PeerAdmissions::default());
        let permit = PeerAdmissions::reserve(&peers, "origin").unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = peers.pending.lock().unwrap();
            panic!("poison admission accounting");
        }));
        assert!(outcome.is_err());
        drop(permit);
        let failure = PeerAdmissions::reserve(&peers, "other")
            .err()
            .expect("poison persists");
        assert!(unavailable(&failure, "replay_peer_admission_poisoned"));
        assert!(peers.pending.lock().unwrap_err().into_inner().is_empty());
    }

    #[test]
    fn parallel_reservations_cannot_exceed_the_origin_ceiling() {
        use std::sync::Barrier;
        use std::sync::atomic::AtomicUsize;

        let peers = Arc::new(PeerAdmissions::default());
        let admitted = Arc::new(AtomicUsize::new(0));
        let contenders = MAX_PENDING_PER_PEER * 2;
        let start = Arc::new(Barrier::new(contenders + 1));
        let reserved = Arc::new(Barrier::new(contenders + 1));
        let release = Arc::new(Barrier::new(contenders + 1));
        let mut threads = Vec::new();
        for _ in 0..contenders {
            let peers = Arc::clone(&peers);
            let admitted = Arc::clone(&admitted);
            let start = Arc::clone(&start);
            let reserved = Arc::clone(&reserved);
            let release = Arc::clone(&release);
            threads.push(std::thread::spawn(move || {
                start.wait();
                let permit = PeerAdmissions::reserve(&peers, "origin").ok();
                if permit.is_some() {
                    admitted.fetch_add(1, Ordering::SeqCst);
                }
                reserved.wait();
                release.wait();
                drop(permit);
            }));
        }
        start.wait();
        reserved.wait();
        let count = admitted.load(Ordering::SeqCst);
        let usage = peers.pending.lock().unwrap().get("origin").copied();
        release.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(count, MAX_PENDING_PER_PEER);
        assert_eq!(usage, Some(MAX_PENDING_PER_PEER));
        assert!(peers.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn active_groups_cannot_refill_the_queue_past_the_total_job_ceiling() {
        let (sender, receiver) = mpsc::sync_channel::<Request>(QUEUE_CAPACITY);
        let worker = InboundReplayWorker {
            sender: Some(sender),
            thread: None,
            peers: Arc::new(PeerAdmissions::default()),
        };
        let mut responses = Vec::new();
        for index in 0..QUEUE_CAPACITY {
            responses.push(
                worker
                    .submit(identity_from(&format!("origin-{index}"), "executor", READY))
                    .unwrap(),
            );
        }
        let first = receiver.try_recv().unwrap();
        responses.push(
            worker
                .submit(identity_from("last", "executor", READY))
                .unwrap(),
        );
        let mut group = vec![first];
        extend_ready_group(&mut group, &receiver);
        assert_eq!(group.len(), MAX_REPLAY_GROUP_SIZE);
        assert_eq!(
            worker.peers.pending.lock().unwrap().values().sum::<usize>(),
            MAX_PENDING_TOTAL
        );
        let failure = worker
            .submit(identity_from("overflow", "executor", READY))
            .err()
            .expect("group still occupies capacity");
        assert!(unavailable(&failure, "replay_admission_total_limit"));
        drop(group.pop().unwrap());
        responses.push(
            worker
                .submit(identity_from("overflow", "executor", READY))
                .unwrap(),
        );
        drop(group);
        drop(receiver);
        drop(responses);
        assert!(worker.peers.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn queued_burst_shares_one_group_and_keeps_individual_results() {
        use std::sync::atomic::AtomicUsize;

        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir.path().join("replay"));
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let worker =
            InboundReplayWorker::spawn_with_clock(Arc::clone(&state), QUEUE_CAPACITY, move || {
                observed.fetch_add(1, Ordering::SeqCst);
                READY
            })
            .unwrap();
        let held = state.lock().unwrap();
        let first = identity(READY);
        let accepted = worker.submit(first.clone()).unwrap();
        let other = worker
            .submit(identity_from("other", "executor", READY))
            .unwrap();
        let duplicate = worker.submit(first).unwrap();
        let stale = worker
            .submit(identity_from("stale", "executor", READY - WINDOW - 1))
            .unwrap();
        drop(held);
        result(accepted).unwrap();
        result(other).unwrap();
        assert!(matches!(
            result(duplicate),
            Err(MeshForwardError::Replayed { .. })
        ));
        assert!(matches!(result(stale), Err(MeshForwardError::Stale { .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(worker.peers.pending.lock().unwrap().is_empty());
    }
}
