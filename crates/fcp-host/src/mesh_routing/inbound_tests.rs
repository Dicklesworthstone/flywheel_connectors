//! Public-router regressions for bounded async durable admission.

use std::future::Future;
use std::sync::mpsc;
use std::task::{Context, Poll, Waker};

use futures_util::future::join_all;

use super::*;

struct Fixture {
    _dir: tempfile::TempDir,
    journal: PathBuf,
    origin_key: Ed25519SigningKey,
    executor_key: Ed25519SigningKey,
    peers: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let origin_key = Ed25519SigningKey::generate();
        let executor_key = Ed25519SigningKey::generate();
        let peers = serde_json::json!([{
            "node_id": "origin",
            "endpoint": "http://127.0.0.1:1",
            "public_key_hex": hex::encode(origin_key.verifying_key().to_bytes()),
        }])
        .to_string();
        Self {
            journal: dir.path().join("mesh-replay"),
            _dir: dir,
            origin_key,
            executor_key,
            peers,
        }
    }

    fn settings(&self) -> MeshRoutingSettings {
        MeshRoutingSettings {
            node_id: TailscaleNodeId::new("executor"),
            signing_key: Ed25519SigningKey::from_bytes(&self.executor_key.to_bytes()).unwrap(),
            peers_json: self.peers.clone(),
            forward_timeout: Duration::from_secs(1),
        }
    }

    fn router(&self) -> MeshRouter {
        MeshRouter::with_replay_journal(
            self.settings(),
            MeshForwardLimits::default(),
            &self.journal,
        )
        .unwrap()
    }

    fn envelope(&self) -> MeshForwardEnvelope {
        MeshForwardEnvelope::sign(
            &self.origin_key,
            TailscaleNodeId::new("origin"),
            TailscaleNodeId::new("executor"),
            unix_now_ms(),
            MeshForwardBody::Invoke {
                request_json: "{\"operation\":\"test.echo\",\"capability\":\"not-a-real-secret\"}".to_owned(),
                asserted_principal: Some("agent:test".to_owned()),
            },
        )
        .unwrap()
    }
}

fn run<F: Future>(future: F) -> F::Output {
    fcp_async_core::runtime::block_on_sync(future).expect("runtime")
}

#[test]
fn async_admission_survives_router_restart() {
    let fixture = Fixture::new();
    let envelope = fixture.envelope();
    {
        let router = fixture.router();
        assert!(router.has_durable_replay());
        run(router.accept_inbound_async(&envelope)).unwrap();
    }
    let restored = fixture.router();
    assert!(matches!(
        run(restored.accept_inbound_async(&envelope)),
        Err(MeshForwardError::Replayed { .. })
    ));
}

#[test]
fn synchronous_and_async_admission_share_one_nonce_history() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let sync_first = fixture.envelope();
    router.accept_inbound(&sync_first).unwrap();
    assert!(matches!(
        run(router.accept_inbound_async(&sync_first)),
        Err(MeshForwardError::Replayed { .. })
    ));
    let async_first = fixture.envelope();
    run(router.accept_inbound_async(&async_first)).unwrap();
    assert!(matches!(
        router.accept_inbound(&async_first),
        Err(MeshForwardError::Replayed { .. })
    ));
}

#[test]
fn forged_forward_does_not_consume_the_genuine_nonce() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let genuine = fixture.envelope();
    let mut forged = genuine.clone();
    forged.signature = "00".repeat(64);
    assert!(matches!(
        run(router.accept_inbound_async(&forged)),
        Err(MeshForwardError::SignatureInvalid { .. })
    ));
    run(router.accept_inbound_async(&genuine)).unwrap();
}

#[test]
fn concurrent_async_duplicates_have_exactly_one_admission() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let envelope = fixture.envelope();
    let results = run(join_all(
        (0..8).map(|_| router.accept_inbound_async(&envelope)),
    ));
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(MeshForwardError::Replayed { .. })))
            .count(),
        7
    );
}

#[test]
fn missing_worker_never_falls_back_to_blocking_or_volatile_admission() {
    let fixture = Fixture::new();
    let mut router = fixture.router();
    drop(router.inbound_worker.take());
    assert!(matches!(
        run(router.accept_inbound_async(&fixture.envelope())),
        Err(MeshForwardError::Malformed { field: "replay_journal", detail })
            if detail.contains("worker_not_configured")
    ));
}

#[test]
fn volatile_embedded_router_retains_async_replay_checks() {
    let fixture = Fixture::new();
    let router = MeshRouter::new(fixture.settings()).unwrap();
    assert!(!router.has_durable_replay());
    let envelope = fixture.envelope();
    run(router.accept_inbound_async(&envelope)).unwrap();
    assert!(matches!(
        run(router.accept_inbound_async(&envelope)),
        Err(MeshForwardError::Replayed { .. })
    ));
}

#[test]
fn first_async_poll_does_not_wait_for_the_journal_mutex() {
    let fixture = Fixture::new();
    let router = Arc::new(fixture.router());
    let envelope = fixture.envelope();
    let other = Arc::clone(&router);
    let (sender, receiver) = mpsc::channel();
    let held = router.durable_replay.as_ref().unwrap().lock().unwrap();
    let thread = std::thread::spawn(move || {
        let mut future = Box::pin(other.accept_inbound_async(&envelope));
        let first = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        let _ = sender.send(first.is_pending());
        match first {
            Poll::Ready(result) => result,
            Poll::Pending => run(future),
        }
    });
    // Release the mutex before joining even if the regression made polling
    // block. A failed timing assertion must not strand the worker in Drop.
    let first_poll = receiver.recv_timeout(Duration::from_secs(5));
    drop(held);
    let result = thread.join().unwrap();
    assert!(first_poll.unwrap(), "journal I/O must not block async polling");
    result.unwrap();
}
