//! Restart and concurrency regressions through the production MeshRouter admission API.
//! The subprocess case kills an executor after dispatch rather than relying on Drop.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Barrier;
use std::time::{Duration, Instant};

use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_host::mesh_routing::{
    MESH_NODE_ID_ENV, MESH_PEERS_ENV, MESH_REPLAY_JOURNAL_ENV, MESH_SIGNING_KEY_FILE_ENV,
    MeshForwardLimits, MeshRouter, MeshRoutingSettings, unix_now_ms,
};
use fcp_mesh::invoke_route::{MeshForwardBody, MeshForwardEnvelope, MeshForwardError};

struct Fixture {
    dir: tempfile::TempDir,
    values: BTreeMap<String, String>,
    origin_key: Ed25519SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("executor.key");
        std::fs::write(&key_path, hex::encode(Ed25519SigningKey::generate().to_bytes())).unwrap();
        let origin_key = Ed25519SigningKey::generate();
        let peers = serde_json::json!([{
            "node_id": "origin",
            "endpoint": "http://127.0.0.1:1",
            "public_key_hex": hex::encode(origin_key.verifying_key().to_bytes()),
        }]);
        let values = BTreeMap::from([
            (MESH_NODE_ID_ENV.to_owned(), "executor".to_owned()),
            (MESH_SIGNING_KEY_FILE_ENV.to_owned(), key_path.display().to_string()),
            (MESH_PEERS_ENV.to_owned(), peers.to_string()),
        ]);
        Self { dir, values, origin_key }
    }

    fn open(&self) -> fcp_host::HostResult<Option<MeshRouter>> {
        MeshRouter::from_lookup(|name| self.values.get(name).cloned())
    }

    fn router(&self) -> MeshRouter {
        self.open().unwrap().unwrap()
    }

    fn journal(&self) -> PathBuf {
        self.dir.path().join("executor.key.mesh-replay")
    }

    fn settings(&self) -> MeshRoutingSettings {
        MeshRoutingSettings::from_lookup(|name| self.values.get(name).cloned())
            .unwrap()
            .unwrap()
    }

    fn request(&self) -> MeshForwardEnvelope {
        MeshForwardEnvelope::sign(
            &self.origin_key,
            TailscaleNodeId::new("origin"),
            TailscaleNodeId::new("executor"),
            unix_now_ms(),
            MeshForwardBody::Invoke {
                request_json: "{\"operation\":\"non_idempotent_write\"}".to_owned(),
                asserted_principal: Some("test-principal".to_owned()),
            },
        )
        .unwrap()
    }
}

#[test]
fn environment_router_recovers_consumed_nonce_after_restart() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let router = fixture.router();
    assert!(router.has_durable_replay());
    assert!(fixture.journal().exists());
    router.accept_inbound(&request).unwrap();
    drop(router);
    let reopened = fixture.router();
    assert!(matches!(
        reopened.accept_inbound(&request),
        Err(MeshForwardError::Replayed { .. })
    ));
    reopened.accept_inbound(&fixture.request()).unwrap();
}

#[test]
fn explicit_journal_uses_state_volume_instead_of_secret_directory() {
    let mut fixture = Fixture::new();
    let path = fixture.dir.path().join("persistent-state");
    std::fs::create_dir(&path).unwrap();
    let journal = path.join("replay");
    fixture.values.insert(MESH_REPLAY_JOURNAL_ENV.to_owned(), journal.display().to_string());
    let request = fixture.request();
    fixture.router().accept_inbound(&request).unwrap();
    assert!(journal.exists());
    assert!(!fixture.journal().exists());
    let reopened = MeshRouter::with_replay_journal(
        fixture.settings(),
        MeshForwardLimits::default(),
        &journal,
    )
    .unwrap();
    assert!(matches!(
        reopened.accept_inbound(&request),
        Err(MeshForwardError::Replayed { .. })
    ));
}

#[test]
fn bad_signature_cannot_consume_nonce_or_change_persistent_journal() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let request = fixture.request();
    let mut forged = request.clone();
    forged.body = MeshForwardBody::Introspect { connector_id: "tampered".to_owned() };
    let before = std::fs::read(fixture.journal()).unwrap();
    assert!(matches!(
        router.accept_inbound(&forged),
        Err(MeshForwardError::SignatureInvalid { .. })
    ));
    assert_eq!(std::fs::read(fixture.journal()).unwrap(), before);
    router.accept_inbound(&request).unwrap();
}

#[test]
fn corrupted_journal_refuses_environment_startup_without_fallback() {
    let fixture = Fixture::new();
    fixture.router().accept_inbound(&fixture.request()).unwrap();
    let mut bytes = std::fs::read(fixture.journal()).unwrap();
    bytes[0] ^= 1;
    std::fs::write(fixture.journal(), &bytes).unwrap();
    assert!(fixture.open().is_err());
    assert_eq!(std::fs::read(fixture.journal()).unwrap(), bytes);
}

#[test]
fn partial_empty_missing_parent_and_locked_journals_fail_closed() {
    assert!(MeshRouter::from_lookup(|name| {
        (name == MESH_REPLAY_JOURNAL_ENV).then(|| "journal".to_owned())
    }).is_err());
    let mut fixture = Fixture::new();
    fixture.values.insert(MESH_REPLAY_JOURNAL_ENV.to_owned(), " ".to_owned());
    assert!(fixture.open().is_err());
    fixture.values.insert(
        MESH_REPLAY_JOURNAL_ENV.to_owned(),
        fixture.dir.path().join("absent/replay").display().to_string(),
    );
    assert!(fixture.open().is_err());
    fixture.values.remove(MESH_REPLAY_JOURNAL_ENV);
    let owner = fixture.router();
    assert!(fixture.open().is_err(), "a second executor must not share admission ownership");
    drop(owner);
    assert!(fixture.router().has_durable_replay());
}

#[test]
fn concurrent_duplicate_delivery_admits_one_and_remains_consumed_after_restart() {
    let fixture = Fixture::new();
    let router = fixture.router();
    let request = fixture.request();
    let barrier = Barrier::new(8);
    let results = std::thread::scope(|scope| {
        let handles = (0..8)
            .map(|_| scope.spawn(|| {
                barrier.wait();
                router.accept_inbound(&request)
            }))
            .collect::<Vec<_>>();
        handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| {
        matches!(result, Err(MeshForwardError::Replayed { .. }))
    }).count(), 7);
    drop(router);
    assert!(matches!(
        fixture.router().accept_inbound(&request),
        Err(MeshForwardError::Replayed { .. })
    ));
}

#[test]
fn embedded_volatile_constructor_is_explicit_and_does_not_create_state() {
    let fixture = Fixture::new();
    let router = MeshRouter::new(fixture.settings()).unwrap();
    assert!(!router.has_durable_replay());
    assert!(!fixture.journal().exists());
    let request = fixture.request();
    router.accept_inbound(&request).unwrap();
    assert!(matches!(router.accept_inbound(&request), Err(MeshForwardError::Replayed { .. })));
}

struct ChildGuard(Child);

impl ChildGuard {
    fn spawn(root: &Path, phase: &str) -> Self {
        Self(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "replay_child_process", "--test-threads=1"])
            .env("FCP_REPLAY_TEST_ROOT", root)
            .env("FCP_REPLAY_TEST_PHASE", phase)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap())
    }

    fn wait_bounded(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "child executor did not terminate");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn executor_killed_after_dispatch_cannot_readmit_same_signed_write() {
    let fixture = Fixture::new();
    let root = fixture.dir.path();
    std::fs::write(root.join("config.json"), serde_json::to_vec(&fixture.values).unwrap()).unwrap();
    std::fs::write(root.join("request.json"), serde_json::to_vec(&fixture.request()).unwrap()).unwrap();
    let mut first = ChildGuard::spawn(root, "accept");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if std::fs::read(root.join("ready")).ok().as_deref() == Some(b"ready") {
            break;
        }
        assert!(first.0.try_wait().unwrap().is_none(), "executor exited before dispatch");
        assert!(Instant::now() < deadline, "executor did not dispatch before deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
    // Abrupt termination: no Rust destructor can persist replay state for us.
    first.0.kill().unwrap();
    assert!(!first.wait_bounded().success());
    let mut second = ChildGuard::spawn(root, "reject");
    assert!(second.wait_bounded().success(), "restarted executor accepted a replay");
    assert_eq!(std::fs::read(root.join("dispatches")).unwrap(), b"dispatched\n");
}

// Invoked only by the bounded subprocess harness; an ordinary test run is a no-op.
#[test]
fn replay_child_process() {
    let Some(root) = std::env::var_os("FCP_REPLAY_TEST_ROOT") else { return; };
    let root = PathBuf::from(root);
    let values: BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(root.join("config.json")).unwrap()).unwrap();
    let request: MeshForwardEnvelope =
        serde_json::from_slice(&std::fs::read(root.join("request.json")).unwrap()).unwrap();
    let router = MeshRouter::from_lookup(|name| values.get(name).cloned()).unwrap().unwrap();
    assert!(router.has_durable_replay());
    match std::env::var("FCP_REPLAY_TEST_PHASE").unwrap().as_str() {
        "accept" => {
            router.accept_inbound(&request).unwrap();
            let mut dispatches = File::create(root.join("dispatches")).unwrap();
            dispatches.write_all(b"dispatched\n").unwrap();
            dispatches.sync_all().unwrap();
            let mut ready = File::create(root.join("ready")).unwrap();
            ready.write_all(b"ready").unwrap();
            ready.sync_all().unwrap();
            loop { std::thread::park_timeout(Duration::from_secs(1)); }
        }
        "reject" => assert!(matches!(
            router.accept_inbound(&request),
            Err(MeshForwardError::Replayed { .. })
        )),
        phase => panic!("unexpected child phase: {phase}"),
    }
}
