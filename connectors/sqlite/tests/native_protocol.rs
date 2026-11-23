//! Exercise the shipped SQLite executable, signed admission and real database effects.

#![allow(clippy::too_many_lines)]

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use fcp_core::{
    CapabilityConstraints, HealthSnapshot, InvokeRequest, InvokeResponse, SimulateResponse,
};
use fcp_crypto::ed25519::Ed25519SigningKey;
use serde_json::{Value, json};

mod support;

struct NativeProcess {
    child: Child,
    input: Option<ChildStdin>,
    responses: Receiver<Value>,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-sqlite"))
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start native SQLite executable");
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let response = serde_json::from_str(&line).expect("native JSONL response");
                if sender.send(response).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            responses,
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(
            &mut *input,
            &json!({
                "jsonrpc": "2.0", "id": 19, "method": method, "params": params,
            }),
        )
        .unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
        let response = self
            .responses
            .recv_timeout(Duration::from_secs(10))
            .expect("bounded native response");
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 19);
        response
    }

    fn establish(&mut self, key: &Ed25519SigningKey, config: Value) -> (String, String) {
        let response = self.rpc("configure", config);
        assert!(response.get("error").is_none(), "{response}");
        let pending = self.rpc("health", json!({}));
        let pending: HealthSnapshot = serde_json::from_value(pending["result"].clone()).unwrap();
        assert!(!pending.is_ready());
        self.handshake(key, &["sqlite.read", "sqlite.write", "sqlite.admin"])
    }

    fn handshake(&mut self, key: &Ed25519SigningKey, capabilities: &[&str]) -> (String, String) {
        let response = self.rpc("handshake", support::handshake(key, capabilities));
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["connector_id"], "fcp.sqlite");
        assert_eq!(response["result"]["nonce"], json!(vec![37_u8; 32]));
        assert!(
            response["result"]["manifest_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        (
            response["result"]["instance_id"].as_str().unwrap().into(),
            response["result"]["resource_uris"][0]
                .as_str()
                .unwrap()
                .into(),
        )
    }

    fn invoke(&mut self, request: Value) -> InvokeResponse {
        let id = request["id"].clone();
        let response = self.rpc("invoke", request);
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["id"], id);
        serde_json::from_value(response["result"].clone()).expect("canonical invoke response")
    }

    fn wait_for_exit(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "{status}");
                return;
            }
            assert!(Instant::now() < deadline, "native process did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn native_signed_admission_rejects_foreign_authority_and_stale_sessions() {
    let mut process = NativeProcess::start();
    let key = Ed25519SigningKey::generate();
    let foreign = Ed25519SigningKey::generate();
    let (instance, resource) = process.establish(&key, json!({"database_path": ":memory:"}));
    let request = support::request(
        &key,
        &instance,
        &resource,
        "sqlite.query",
        json!({"sql": "SELECT ?1", "params": [42]}),
    );
    let response = process.invoke(request.clone());
    assert_eq!(response.resource_uris, [resource.clone()]);
    assert_eq!(response.result.unwrap()["result"]["rows"], json!([[42]]));

    let mut rejected = vec![
        support::request(
            &foreign,
            &instance,
            &resource,
            "sqlite.query",
            json!({"sql": "SELECT 1"}),
        ),
        support::request(
            &key,
            "wrong-instance",
            &resource,
            "sqlite.query",
            json!({"sql": "SELECT 1"}),
        ),
        support::request(
            &key,
            &instance,
            "sqlite://another-database",
            "sqlite.query",
            json!({"sql": "SELECT 1"}),
        ),
    ];
    for (field, value) in [
        ("connector_id", json!("fcp.other")),
        ("zone_id", json!("z:work")),
        ("capability_token", Value::Null),
        ("lease_seq", Value::Null),
        ("deadline_ms", json!(0)),
    ] {
        let mut altered = request.clone();
        altered[field] = value;
        rejected.push(altered);
    }
    let mut wrong_operation = request.clone();
    wrong_operation["operation"] = json!("sqlite.execute");
    wrong_operation["input"] = json!({"sql": "CREATE TABLE forbidden (id INTEGER)"});
    rejected.push(wrong_operation);
    for denied in rejected {
        let response = process.rpc("invoke", denied);
        assert!(response.get("error").is_some(), "{response}");
    }
    let schema = process.invoke(support::request(
        &key,
        &instance,
        &resource,
        "sqlite.schema.tables",
        json!({}),
    ));
    assert_eq!(schema.result.unwrap()["tables"], json!([]));

    let (new_instance, _) = process.handshake(&key, &[]);
    assert_ne!(instance, new_instance);
    assert!(
        process
            .rpc("invoke", request.clone())
            .get("error")
            .is_some()
    );
    let no_grants = support::request(
        &key,
        &new_instance,
        &resource,
        "sqlite.query",
        json!({"sql": "SELECT 1"}),
    );
    assert!(process.rpc("invoke", no_grants).get("error").is_some());

    let (instance, _) = process.handshake(&key, &["sqlite.read"]);
    let valid = support::request(
        &key,
        &instance,
        &resource,
        "sqlite.query",
        json!({"sql": "SELECT 1"}),
    );
    assert!(
        process
            .rpc("handshake", json!({"protocol_version": "wrong"}))
            .get("error")
            .is_some()
    );
    assert!(process.rpc("invoke", valid.clone()).get("error").is_some());
    process.handshake(&key, &["sqlite.read"]);
    assert!(process.rpc("invoke", valid).get("error").is_some());

    let shutdown = process.rpc("shutdown", json!({"type": "shutdown", "drain": true}));
    assert_eq!(shutdown["result"]["status"], "shutdown");
    assert!(process.input.is_some(), "stdin intentionally remains open");
    process.wait_for_exit();
}

#[test]
fn native_simulation_preserves_signed_call_budget_and_database_state() {
    let mut process = NativeProcess::start();
    let key = Ed25519SigningKey::generate();
    let (instance, resource) = process.establish(&key, json!({"database_path": ":memory:"}));
    let mut invoke = support::request(
        &key,
        &instance,
        &resource,
        "sqlite.execute",
        json!({"sql": "CREATE TABLE once_only (id INTEGER)"}),
    );
    invoke["capability_token"] = json!(support::token(
        &key,
        &instance,
        "sqlite.execute",
        "user:sqlite-test",
        CapabilityConstraints {
            resource_allow: vec![resource.clone()],
            max_calls: Some(1),
            ..Default::default()
        }
    ));
    let mut simulate = invoke.clone();
    simulate["type"] = json!("simulate");
    for _ in 0..3 {
        let response = process.rpc("simulate", simulate.clone());
        let response: SimulateResponse =
            serde_json::from_value(response["result"].clone()).unwrap();
        assert!(response.would_succeed);
    }
    let schema = process.invoke(support::request(
        &key,
        &instance,
        &resource,
        "sqlite.schema.tables",
        json!({}),
    ));
    assert_eq!(schema.result.unwrap()["tables"], json!([]));
    process.invoke(invoke.clone());
    assert!(process.rpc("invoke", invoke).get("error").is_some());
    let denied = process.rpc("simulate", simulate);
    assert_eq!(denied["result"]["would_succeed"], false);

    let replaced = process.rpc("configure", json!({"database_path": "../invalid.sqlite"}));
    assert!(replaced.get("error").is_some());
    let health = process.rpc("health", json!({}));
    assert_eq!(health["result"]["details"]["configured"], false);
    let old = support::request(
        &key,
        &instance,
        &resource,
        "sqlite.query",
        json!({"sql": "SELECT 1"}),
    );
    assert!(process.rpc("invoke", old).get("error").is_some());
}

#[test]
fn native_sql_deadlines_and_signed_result_limits_interrupt_work_without_poisoning_session() {
    let mut process = NativeProcess::start();
    let key = Ed25519SigningKey::generate();
    let (instance, resource) = process.establish(&key, json!({"database_path": ":memory:"}));
    let mut endless = support::request(
        &key,
        &instance,
        &resource,
        "sqlite.query",
        json!({
            "sql": "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x + 1 FROM n) SELECT sum(x) FROM n"
        }),
    );
    endless["deadline_ms"] = json!(20);
    let started = Instant::now();
    let interrupted = process.rpc("invoke", endless);
    assert!(interrupted.get("error").is_some(), "{interrupted}");
    assert!(started.elapsed() < Duration::from_secs(5));

    let mut bounded = support::request(
        &key,
        &instance,
        &resource,
        "sqlite.query",
        json!({
            "sql": "SELECT printf('%5000s', 'x')"
        }),
    );
    bounded["capability_token"] = json!(support::token(
        &key,
        &instance,
        "sqlite.query",
        "user:sqlite-test",
        CapabilityConstraints {
            resource_allow: vec![resource.clone()],
            max_bytes: Some(2_048),
            ..Default::default()
        }
    ));
    let oversized = process.rpc("invoke", bounded);
    assert!(oversized.get("error").is_some(), "{oversized}");
    let recovered = process.invoke(support::request(
        &key,
        &instance,
        &resource,
        "sqlite.query",
        json!({"sql": "SELECT 42"}),
    ));
    assert_eq!(recovered.result.unwrap()["result"]["rows"], json!([[42]]));
}

#[test]
fn native_transaction_ownership_lease_fencing_and_eof_preserve_file_integrity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("native.sqlite");
    let mut process = NativeProcess::start();
    let key = Ed25519SigningKey::generate();
    let (instance, resource) = process.establish(&key, json!({"database_path": path}));
    assert!(!resource.contains(directory.path().to_str().unwrap()));
    let send = |operation, input| support::request(&key, &instance, &resource, operation, input);
    process.invoke(send(
        "sqlite.execute",
        json!({"sql": "CREATE TABLE effects (id INTEGER)"}),
    ));
    let begun = process.invoke(send("sqlite.transaction.begin", json!({})));
    let transaction = begun.result.unwrap()["transaction"]["txn_id"].clone();
    process.invoke(send(
        "sqlite.execute",
        json!({"sql": "INSERT INTO effects VALUES (1)", "txn_id": transaction}),
    ));

    let mut foreign_principal = send("sqlite.transaction.commit", json!({"txn_id": transaction}));
    foreign_principal["capability_token"] = json!(support::token(
        &key,
        &instance,
        "sqlite.transaction.commit",
        "user:other",
        CapabilityConstraints {
            resource_allow: vec![
                resource.clone(),
                format!("sqlite:transaction:{}", transaction.as_str().unwrap()),
            ],
            ..Default::default()
        }
    ));
    let denied_owner = process.rpc("invoke", foreign_principal);
    assert!(
        denied_owner["error"]
            .to_string()
            .contains("another authenticated principal"),
        "{denied_owner}"
    );

    let mut new_lease = send(
        "sqlite.query",
        json!({"sql": "SELECT count(*) FROM effects"}),
    );
    new_lease["lease_seq"] = json!(2);
    let after_handoff = process.invoke(new_lease.clone());
    assert_eq!(
        after_handoff.result.unwrap()["result"]["rows"],
        json!([[0]])
    );
    assert!(
        process
            .rpc("invoke", send("sqlite.query", json!({"sql": "SELECT 1"})))
            .get("error")
            .is_some()
    );

    let mut begin = send("sqlite.transaction.begin", json!({}));
    begin["lease_seq"] = json!(2);
    let begun = process.invoke(begin);
    let transaction = begun.result.unwrap()["transaction"]["txn_id"].clone();
    let mut insert = send(
        "sqlite.execute",
        json!({"sql": "INSERT INTO effects VALUES (9)", "txn_id": transaction}),
    );
    insert["lease_seq"] = json!(2);
    process.invoke(insert);
    assert!(process.rpc("handshake", json!({})).get("error").is_some());
    let (instance, _) = process.handshake(&key, &["sqlite.read", "sqlite.write"]);
    let send = |operation, input| {
        let mut request = support::request(&key, &instance, &resource, operation, input);
        request["lease_seq"] = json!(2);
        request
    };
    let after_rehandshake = process.invoke(send(
        "sqlite.query",
        json!({"sql": "SELECT count(*) FROM effects"}),
    ));
    assert_eq!(
        after_rehandshake.result.unwrap()["result"]["rows"],
        json!([[0]])
    );
    process.invoke(send(
        "sqlite.execute",
        json!({"sql": "INSERT INTO effects VALUES (2)"}),
    ));
    let begun = process.invoke(send("sqlite.transaction.begin", json!({})));
    let transaction = begun.result.unwrap()["transaction"]["txn_id"].clone();
    process.invoke(send(
        "sqlite.execute",
        json!({"sql": "INSERT INTO effects VALUES (3)", "txn_id": transaction}),
    ));
    process.input.take();
    process.wait_for_exit();
    let database = rusqlite::Connection::open(&path).unwrap();
    let values = database
        .prepare("SELECT id FROM effects ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        values,
        [2],
        "EOF rolls back uncommitted effects while preserving committed data"
    );
}

#[test]
fn native_unreturned_transaction_identifier_does_not_strand_a_transaction() {
    let mut process = NativeProcess::start();
    let key = Ed25519SigningKey::generate();
    let (instance, resource) = process.establish(&key, json!({"database_path": ":memory:"}));
    let mut ceiling = 4_096_u64;
    let mut selected = None;
    // The grant's own serialized bytes count toward its allowance. Calibrate
    // using the actual typed message until admission can fit a minimal response
    // but cannot fit BEGIN's larger transaction-ID envelope. COSE signatures
    // serialize as byte arrays, so their decimal lengths vary slightly.
    for _ in 0..128 {
        let mut request = support::request(
            &key,
            &instance,
            &resource,
            "sqlite.transaction.begin",
            json!({}),
        );
        request["capability_token"] = json!(support::token(
            &key,
            &instance,
            "sqlite.transaction.begin",
            "user:sqlite-test",
            CapabilityConstraints {
                resource_allow: vec![resource.clone()],
                max_bytes: Some(ceiling),
                ..Default::default()
            }
        ));
        let canonical: InvokeRequest = serde_json::from_value(request.clone()).unwrap();
        let request_bytes = serde_json::to_vec(&canonical).unwrap().len() as u64;
        let minimum_response = serde_json::to_vec(&InvokeResponse::ok(canonical.id, json!(0)))
            .unwrap()
            .len() as u64;
        let available = ceiling.saturating_sub(request_bytes);
        if (minimum_response..minimum_response + 64).contains(&available) {
            selected = Some(request);
            break;
        }
        ceiling = request_bytes + minimum_response + 32;
    }
    let response = process.rpc(
        "invoke",
        selected.expect("calibrate finite BEGIN response allowance"),
    );
    assert!(
        response["error"].to_string().contains("outcome is unknown"),
        "{response}"
    );
    let health = process.invoke(support::request(
        &key,
        &instance,
        &resource,
        "sqlite.health",
        json!({}),
    ));
    assert!(health.result.unwrap()["active_transaction_id"].is_null());
    let transaction = process.invoke(support::request(
        &key,
        &instance,
        &resource,
        "sqlite.transaction.begin",
        json!({}),
    ));
    let transaction = transaction.result.unwrap()["transaction"]["txn_id"].clone();
    process.invoke(support::request(
        &key,
        &instance,
        &resource,
        "sqlite.transaction.rollback",
        json!({"txn_id": transaction}),
    ));
}

#[test]
fn native_invalid_shutdown_revokes_access_and_read_only_simulation_fails_closed() {
    let mut process = NativeProcess::start();
    let key = Ed25519SigningKey::generate();
    let (instance, resource) = process.establish(
        &key,
        json!({"database_path": ":memory:", "read_only": true}),
    );
    let mut simulation = support::request(
        &key,
        &instance,
        &resource,
        "sqlite.execute",
        json!({"sql": "CREATE TABLE forbidden (id INTEGER)"}),
    );
    simulation["type"] = json!("simulate");
    assert_eq!(
        process.rpc("simulate", simulation)["result"]["would_succeed"],
        false
    );
    assert!(
        process
            .rpc("shutdown", json!({"type": "wrong"}))
            .get("error")
            .is_some()
    );
    let old = support::request(
        &key,
        &instance,
        &resource,
        "sqlite.query",
        json!({"sql": "SELECT 1"}),
    );
    assert!(process.rpc("invoke", old).get("error").is_some());
    assert_eq!(
        process.rpc("health", json!({}))["result"]["details"]["configured"],
        false
    );
    assert_eq!(
        process.rpc("shutdown", json!({"type": "shutdown"}))["result"]["status"],
        "shutdown"
    );
    process.wait_for_exit();
}
