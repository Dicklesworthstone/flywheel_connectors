//! Integration tests for the FCP `SQLite` connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use tempfile::tempdir;

use fcp_core::{CapabilityConstraints, FcpError, HealthSnapshot, InvokeResponse, SimulateResponse};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_sqlite::connector::SqliteConnector;
use serde_json::json;

mod common;
use common::{TestConnector, database_constraints, handshake_request, signed_request};

#[test]
fn manifest_ai_hints_cover_all_sqlite_operations() {
    let manifest = toml::from_str::<toml::Value>(include_str!("../manifest.toml"))
        .expect("sqlite manifest TOML should parse");
    let operations = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("sqlite manifest should declare operations");

    for (operation_id, operation) in operations {
        let ai_hints = operation.get("ai_hints").and_then(toml::Value::as_table);
        assert!(ai_hints.is_some(), "{operation_id} missing ai_hints");
        let Some(ai_hints) = ai_hints else {
            continue;
        };
        assert!(
            ai_hints
                .get("when_to_use")
                .and_then(toml::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "{operation_id} missing ai_hints.when_to_use"
        );
        assert!(
            ai_hints
                .get("examples")
                .and_then(toml::Value::as_array)
                .is_some_and(|examples| !examples.is_empty()),
            "{operation_id} missing ai_hints.examples"
        );
        assert!(
            ai_hints
                .get("common_mistakes")
                .and_then(toml::Value::as_array)
                .is_some_and(|mistakes| {
                    !mistakes.is_empty()
                        && mistakes.iter().all(|mistake| {
                            mistake
                                .as_str()
                                .is_some_and(|value| !value.trim().is_empty())
                        })
                }),
            "{operation_id} contains an empty ai_hints.common_mistakes entry"
        );
    }
}

async fn setup_memory_connector() -> TestConnector {
    let mut connector = TestConnector::new();
    connector
        .handle_configure(json!({ "database_path": ":memory:" }))
        .await
        .unwrap();
    connector.handshake().await;
    connector
}

async fn setup_configured_memory_connector() -> SqliteConnector {
    let mut connector = SqliteConnector::new();
    connector
        .handle_configure(json!({ "database_path": ":memory:" }))
        .await
        .unwrap();
    connector
}

async fn setup_file_connector() -> (tempfile::TempDir, String, TestConnector) {
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("integration.sqlite");
    let database_path = database_path.to_string_lossy().to_string();

    let mut connector = TestConnector::new();
    connector
        .handle_configure(json!({ "database_path": database_path }))
        .await
        .unwrap();
    connector.handshake().await;
    (directory, database_path, connector)
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_is_unconfigured_before_configure() {
    let connector = SqliteConnector::new();
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"]["state"], "degraded");
    assert_eq!(health["details"]["configured"], false);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_and_handshake_make_connector_healthy() {
    let connector = setup_memory_connector().await;
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"]["state"], "ready");
    assert_eq!(health["details"]["handshaken"], true);
}

#[fcp_async_core::runtime::test]
async fn doctor_reports_guidance_for_unconfigured_connector() {
    let connector = SqliteConnector::new();
    let doctor = connector.handle_doctor().await.unwrap();
    assert_eq!(doctor["status"], "unhealthy");
    assert_eq!(doctor["checks"][0]["name"], "configuration");
    assert_eq!(doctor["checks"][0]["passed"], false);
    assert_eq!(
        doctor["guidance"]["rerun_commands"][0],
        "rch exec -- cargo check -p fcp-sqlite --all-targets"
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_degrades_before_handshake() {
    let connector = setup_configured_memory_connector().await;
    let report = connector.handle_self_check().await.unwrap();
    assert_eq!(report["status"], "degraded");
    assert_eq!(report["reason_code"], "handshake_pending");
    assert_eq!(report["details"]["provisioning"]["path_kind"], "memory");
    assert_eq!(
        report["details"]["guidance"]["prerequisites"][0],
        "Use a filesystem path inside the connector sandbox or `:memory:` for ephemeral runs."
    );
}

#[fcp_async_core::runtime::test]
async fn introspect_includes_compliance_and_guidance() {
    let connector = setup_memory_connector().await;
    let introspect = connector.handle_introspect().await.unwrap();
    assert_eq!(introspect["compliance"]["local_filesystem_only"], true);
    assert!(
        introspect["guidance"]["redaction_rules"][0]
            .as_str()
            .unwrap()
            .contains("Redact absolute")
    );
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_parent_dir_paths() {
    let mut connector = SqliteConnector::new();
    let error = connector
        .handle_configure(json!({ "database_path": "../unsafe.sqlite" }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains(".."));
}

#[fcp_async_core::runtime::test]
async fn query_returns_rows_and_columns() {
    let mut connector = setup_memory_connector().await;
    let result = connector
        .invoke(json!({
            "operation": "sqlite.query",
            "input": {
                "sql": "SELECT ?1 AS name, ?2 AS count",
                "params": ["widgets", 3]
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["row_count"], 1);
    assert_eq!(result["result"]["columns"][0]["name"], "name");
    assert_eq!(result["result"]["rows"][0][0], "widgets");
    assert_eq!(result["result"]["rows"][0][1], 3);
}

#[fcp_async_core::runtime::test]
async fn query_rejects_mutating_statements() {
    let mut connector = setup_memory_connector().await;
    let error = connector
        .invoke(json!({
            "operation": "sqlite.query",
            "input": {
                "sql": "CREATE TABLE nope(id INTEGER)"
            }
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("read-only"));
}

#[fcp_async_core::runtime::test]
async fn execute_rejects_user_supplied_savepoint() {
    // The Write policy allows the batch wrapper's internal SAVEPOINT
    // `fcp_sqlite_batch`, but any other savepoint name supplied directly by a
    // caller must still be rejected so users cannot open nested transactions.
    let mut connector = setup_memory_connector().await;
    let error = connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "SAVEPOINT user_sp"
            }
        }))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("safety policy") || error.to_string().contains("denied"),
        "expected savepoint rejection, got: {error}",
    );
}

#[fcp_async_core::runtime::test]
async fn execute_creates_table_and_inserts_rows() {
    let mut connector = setup_memory_connector().await;
    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            }
        }))
        .await
        .unwrap();

    let result = connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["gizmo"]
            }
        }))
        .await
        .unwrap();

    assert_eq!(result["result"]["rows_affected"], 1);

    let query = connector
        .invoke(json!({
            "operation": "sqlite.query",
            "input": {
                "sql": "SELECT name FROM widgets"
            }
        }))
        .await
        .unwrap();
    assert_eq!(query["result"]["rows"][0][0], "gizmo");
}

#[fcp_async_core::runtime::test]
async fn execute_rejects_read_only_statements() {
    let mut connector = setup_memory_connector().await;
    let error = connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "SELECT 1"
            }
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("mutating"));
}

#[fcp_async_core::runtime::test]
async fn schema_operations_report_tables_and_columns() {
    let mut connector = setup_memory_connector().await;
    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT NOT NULL, qty INTEGER DEFAULT 0)"
            }
        }))
        .await
        .unwrap();

    let tables = connector
        .invoke(json!({
            "operation": "sqlite.schema.tables",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(tables["tables"][0]["name"], "widgets");

    let columns = connector
        .invoke(json!({
            "operation": "sqlite.schema.columns",
            "input": {
                "table": "widgets"
            }
        }))
        .await
        .unwrap();
    assert_eq!(columns["columns"][1]["name"], "name");
    assert_eq!(columns["columns"][2]["default_value"], "0");
}

#[fcp_async_core::runtime::test]
async fn explain_returns_query_plan_rows() {
    let mut connector = setup_memory_connector().await;
    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT)"
            }
        }))
        .await
        .unwrap();

    let explain = connector
        .invoke(json!({
            "operation": "sqlite.explain",
            "input": {
                "sql": "SELECT * FROM widgets WHERE id = ?1",
                "params": [1]
            }
        }))
        .await
        .unwrap();

    assert!(explain["plan"]["row_count"].as_u64().unwrap() >= 1);
}

#[fcp_async_core::runtime::test]
async fn transactions_require_matching_txn_id() {
    let mut connector = setup_memory_connector().await;
    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT)"
            }
        }))
        .await
        .unwrap();

    let begin = connector
        .invoke(json!({
            "operation": "sqlite.transaction.begin",
            "input": { "mode": "immediate" }
        }))
        .await
        .unwrap();
    let txn_id = begin["transaction"]["txn_id"].as_str().unwrap().to_string();

    let mismatch = connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["bad"],
                "txn_id": "wrong"
            }
        }))
        .await
        .unwrap_err();
    assert!(mismatch.to_string().contains("does not match"));

    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["good"],
                "txn_id": txn_id
            }
        }))
        .await
        .unwrap();
}

#[fcp_async_core::runtime::test]
async fn commit_persists_transaction_changes() {
    let mut connector = setup_memory_connector().await;
    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT)"
            }
        }))
        .await
        .unwrap();

    let begin = connector
        .invoke(json!({
            "operation": "sqlite.transaction.begin",
            "input": {}
        }))
        .await
        .unwrap();
    let txn_id = begin["transaction"]["txn_id"].as_str().unwrap().to_string();

    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["kept"],
                "txn_id": txn_id
            }
        }))
        .await
        .unwrap();

    connector
        .invoke(json!({
            "operation": "sqlite.transaction.commit",
            "input": {
                "txn_id": begin["transaction"]["txn_id"]
            }
        }))
        .await
        .unwrap();

    let result = connector
        .invoke(json!({
            "operation": "sqlite.query",
            "input": {
                "sql": "SELECT count(*) FROM widgets"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["result"]["rows"][0][0], 1);
}

#[fcp_async_core::runtime::test]
async fn rollback_discards_transaction_changes() {
    let mut connector = setup_memory_connector().await;
    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT)"
            }
        }))
        .await
        .unwrap();

    let begin = connector
        .invoke(json!({
            "operation": "sqlite.transaction.begin",
            "input": {}
        }))
        .await
        .unwrap();
    let txn_id = begin["transaction"]["txn_id"].as_str().unwrap().to_string();

    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "INSERT INTO widgets(name) VALUES (?1)",
                "params": ["discarded"],
                "txn_id": txn_id
            }
        }))
        .await
        .unwrap();

    connector
        .invoke(json!({
            "operation": "sqlite.transaction.rollback",
            "input": {
                "txn_id": begin["transaction"]["txn_id"]
            }
        }))
        .await
        .unwrap();

    let result = connector
        .invoke(json!({
            "operation": "sqlite.query",
            "input": {
                "sql": "SELECT count(*) FROM widgets"
            }
        }))
        .await
        .unwrap();
    assert_eq!(result["result"]["rows"][0][0], 0);
}

#[fcp_async_core::runtime::test]
async fn batch_is_atomic_on_error() {
    let mut connector = setup_memory_connector().await;
    connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": {
                "sql": "CREATE TABLE widgets(id INTEGER PRIMARY KEY, name TEXT UNIQUE)"
            }
        }))
        .await
        .unwrap();

    let error = connector
        .invoke(json!({
            "operation": "sqlite.batch",
            "input": {
                "statements": [
                    { "sql": "INSERT INTO widgets(name) VALUES (?1)", "params": ["dup"] },
                    { "sql": "INSERT INTO widgets(name) VALUES (?1)", "params": ["dup"] }
                ]
            }
        }))
        .await
        .unwrap_err();
    assert!(!error.to_string().is_empty());

    let query = connector
        .invoke(json!({
            "operation": "sqlite.query",
            "input": { "sql": "SELECT count(*) FROM widgets" }
        }))
        .await
        .unwrap();
    assert_eq!(query["result"]["rows"][0][0], 0);
}

#[fcp_async_core::runtime::test]
async fn pragma_reads_allowlisted_values() {
    let mut connector = setup_memory_connector().await;
    let result = connector
        .invoke(json!({
            "operation": "sqlite.pragma",
            "input": { "name": "journal_mode" }
        }))
        .await
        .unwrap();
    assert!(result["result"]["row_count"].as_u64().unwrap() >= 1);
}

#[fcp_async_core::runtime::test]
async fn execute_rejects_pragma_writes() {
    let mut connector = setup_memory_connector().await;
    let error = connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": { "sql": "PRAGMA journal_mode = delete" }
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("policy"));
}

#[fcp_async_core::runtime::test]
async fn execute_rejects_attach_database() {
    let mut connector = setup_memory_connector().await;
    let error = connector
        .invoke(json!({
            "operation": "sqlite.execute",
            "input": { "sql": "ATTACH DATABASE ':memory:' AS other" }
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("policy"));
}

#[fcp_async_core::runtime::test]
async fn health_and_vacuum_work_for_file_backed_database() {
    let (_dir, _path, mut connector) = setup_file_connector().await;
    let health = connector
        .invoke(json!({
            "operation": "sqlite.health",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(health["health"]["query_ok"], true);

    let result = connector
        .invoke(json!({
            "operation": "sqlite.vacuum",
            "input": {}
        }))
        .await
        .unwrap();
    assert_eq!(result["result"]["rows_affected"], 0);
}

#[fcp_async_core::runtime::test]
async fn vacuum_is_blocked_while_transaction_is_active() {
    let (_dir, _path, mut connector) = setup_file_connector().await;
    let begin = connector
        .invoke(json!({
            "operation": "sqlite.transaction.begin",
            "input": {}
        }))
        .await
        .unwrap();
    assert!(begin["transaction"]["active"].as_bool().unwrap());

    let error = connector
        .invoke(json!({
            "operation": "sqlite.vacuum",
            "input": {}
        }))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("transaction"));
}

#[fcp_async_core::runtime::test]
async fn canonical_session_requires_configuration_and_negotiated_authority() {
    let mut connector = TestConnector::new();
    let handshake = handshake_request(&connector.key, &["sqlite.read"]);
    assert!(matches!(
        connector.handle_handshake(handshake.clone()).await,
        Err(FcpError::NotConfigured)
    ));
    connector
        .handle_configure(json!({"database_path": ":memory:"}))
        .await
        .unwrap();
    let request = connector.request(
        "sqlite.query",
        json!({"sql": "SELECT 1"}),
        database_constraints(),
    );
    assert!(matches!(
        connector.handle_invoke(request).await,
        Err(FcpError::NotHandshaken)
    ));

    let mut handshake = handshake;
    handshake["capabilities_requested"] = json!(["sqlite.read", "sqlite.read", "unrelated.write"]);
    handshake["requested_instance_id"] = json!("caller-selected-instance");
    let reply = connector.handle_handshake(handshake).await.unwrap();
    assert_eq!(reply["status"], "accepted");
    assert_eq!(reply["capabilities_granted"].as_array().unwrap().len(), 1);
    assert_ne!(reply["instance_id"], "caller-selected-instance");
    let health = connector.handle_health().await.unwrap();
    let _: HealthSnapshot = serde_json::from_value(health.clone()).unwrap();
    assert_eq!(health["details"]["instance_id"], reply["instance_id"]);
    assert_eq!(health["details"]["connector_id"], "fcp.sqlite");
    let request = connector.request(
        "sqlite.query",
        json!({"sql": "SELECT 41 + 1"}),
        database_constraints(),
    );
    let response: InvokeResponse =
        serde_json::from_value(connector.handle_invoke(request.clone()).await.unwrap()).unwrap();
    assert_eq!(response.id.0, request["id"].as_str().unwrap());
    assert_eq!(response.result.unwrap()["result"]["rows"][0][0], 42);
    assert_eq!(response.resource_uris, ["sqlite:database"]);

    let denied = connector.request(
        "sqlite.execute",
        json!({"sql": "CREATE TABLE denied(id)"}),
        database_constraints(),
    );
    assert!(connector.handle_invoke(denied).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn canonical_invocation_rejects_tampered_scope_and_unsigned_legacy_requests() {
    let mut connector = setup_memory_connector().await;
    let request = connector.request(
        "sqlite.execute",
        json!({"sql": "CREATE TABLE forbidden(id)"}),
        database_constraints(),
    );
    for (field, value) in [
        ("connector_id", json!("fcp.postgresql")),
        ("zone_id", json!("z:work")),
        ("operation", json!("sqlite.query")),
        ("type", json!("simulate")),
        ("id", json!("")),
        ("deadline_ms", json!(0)),
        ("input", json!([])),
    ] {
        let mut altered = request.clone();
        altered[field] = value;
        assert!(
            connector.handle_invoke(altered).await.is_err(),
            "accepted tampered {field}"
        );
    }
    let forged = signed_request(
        &Ed25519SigningKey::generate(),
        connector.instance_id().as_str(),
        "sqlite.execute",
        json!({"sql": "CREATE TABLE forbidden(id)"}),
        database_constraints(),
    );
    assert!(connector.handle_invoke(forged).await.is_err());
    let wrong_instance = signed_request(
        &connector.key,
        "wrong-instance",
        "sqlite.execute",
        json!({"sql": "CREATE TABLE forbidden(id)"}),
        database_constraints(),
    );
    assert!(connector.handle_invoke(wrong_instance).await.is_err());
    assert!(
        connector
            .handle_invoke(json!({
                "operation_id": "sqlite.execute", "input": {"sql": "CREATE TABLE forbidden(id)"}
            }))
            .await
            .is_err()
    );
    let tables = connector
        .invoke(json!({"operation": "sqlite.schema.tables", "input": {}}))
        .await
        .unwrap();
    assert!(tables["tables"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn database_resource_scope_and_input_schema_are_enforced_before_execution() {
    let mut connector = setup_memory_connector().await;
    let scoped_elsewhere = connector.request(
        "sqlite.query",
        json!({"sql": "SELECT 1"}),
        CapabilityConstraints {
            resource_allow: vec!["sqlite:table:public".into()],
            ..Default::default()
        },
    );
    assert!(connector.handle_invoke(scoped_elsewhere).await.is_err());
    let request = connector.request(
        "sqlite.query",
        json!({"sql": "SELECT ?1", "params": [42]}),
        CapabilityConstraints {
            max_calls: Some(1),
            ..database_constraints()
        },
    );
    for input in [
        json!({}),
        json!({"sql": 7}),
        json!({"sql": "SELECT ?1", "params": "not an array"}),
    ] {
        let mut malformed = request.clone();
        malformed["input"] = input;
        assert!(connector.handle_invoke(malformed).await.is_err());
    }
    // Invalid input does not consume the only signed call admission.
    assert!(connector.handle_invoke(request).await.is_ok());
}

#[fcp_async_core::runtime::test]
async fn simulate_is_side_effect_free_and_does_not_spend_signed_call_budget() {
    let mut connector = setup_memory_connector().await;
    let request = connector.request(
        "sqlite.execute",
        json!({"sql": "CREATE TABLE once_only(id)"}),
        CapabilityConstraints {
            max_calls: Some(1),
            ..database_constraints()
        },
    );
    let mut simulate = request.clone();
    simulate["type"] = json!("simulate");
    let response: SimulateResponse =
        serde_json::from_value(connector.handle_simulate(simulate.clone()).await.unwrap()).unwrap();
    assert!(response.would_succeed);
    let tables = connector
        .invoke(json!({"operation": "sqlite.schema.tables", "input": {}}))
        .await
        .unwrap();
    assert!(tables["tables"].as_array().unwrap().is_empty());
    assert!(connector.handle_invoke(request.clone()).await.is_ok());
    assert!(connector.handle_invoke(request).await.is_err());
    let response: SimulateResponse =
        serde_json::from_value(connector.handle_simulate(simulate).await.unwrap()).unwrap();
    assert!(!response.would_succeed);
}

#[fcp_async_core::runtime::test]
async fn signed_byte_budget_and_idempotency_scope_deny_before_mutation() {
    let mut connector = setup_memory_connector().await;
    let request = connector.request(
        "sqlite.execute",
        json!({"sql": "CREATE TABLE denied(id)"}),
        CapabilityConstraints {
            max_bytes: Some(1),
            ..database_constraints()
        },
    );
    assert!(connector.handle_invoke(request).await.is_err());
    let mut request = connector.request(
        "sqlite.execute",
        json!({"sql": "CREATE TABLE keyed(id)"}),
        CapabilityConstraints {
            idempotency_key: Some("authorized-key".into()),
            max_calls: Some(1),
            ..database_constraints()
        },
    );
    request["idempotency_key"] = json!("different-key");
    assert!(connector.handle_invoke(request.clone()).await.is_err());
    let tables = connector
        .invoke(json!({"operation": "sqlite.schema.tables", "input": {}}))
        .await
        .unwrap();
    assert!(tables["tables"].as_array().unwrap().is_empty());
    request["idempotency_key"] = json!("authorized-key");
    assert!(connector.handle_invoke(request).await.is_ok());
}

#[fcp_async_core::runtime::test]
async fn simulate_refuses_known_database_policy_failures_without_running_sql() {
    let mut connector = TestConnector::new();
    connector
        .handle_configure(json!({"database_path": ":memory:", "read_only": true}))
        .await
        .unwrap();
    connector.handshake().await;
    for (operation, input) in [
        (
            "sqlite.execute",
            json!({"sql": "CREATE TABLE forbidden(id)"}),
        ),
        (
            "sqlite.batch",
            json!({"statements": [{"sql": "CREATE TABLE forbidden(id)"}]}),
        ),
        ("sqlite.transaction.begin", json!({})),
        ("sqlite.vacuum", json!({})),
        ("sqlite.pragma", json!({"name": "writable_schema"})),
    ] {
        let request = connector.request(operation, input, database_constraints());
        let mut simulate = request.clone();
        simulate["type"] = json!("simulate");
        let response: SimulateResponse =
            serde_json::from_value(connector.handle_simulate(simulate).await.unwrap()).unwrap();
        assert!(!response.would_succeed, "simulation admitted {operation}");
        assert!(connector.handle_invoke(request).await.is_err());
    }
    let query = connector
        .invoke(json!({"operation": "sqlite.query", "input": {"sql": "SELECT 1"}}))
        .await
        .unwrap();
    assert_eq!(query["result"]["rows"][0][0], 1);
}

#[fcp_async_core::runtime::test]
async fn failed_handshakes_revoke_old_tokens_and_cannot_rebind_database_zone() {
    let mut connector = setup_memory_connector().await;
    for (field, value) in [
        ("protocol_version", json!("3.0")),
        ("zone", json!("z:work")),
        ("zone", json!("z:owner")),
        ("zone", json!("z:public")),
        ("host_public_key", json!([0])),
    ] {
        let old = connector.request(
            "sqlite.query",
            json!({"sql": "SELECT 1"}),
            database_constraints(),
        );
        let old_instance = connector.instance_id().clone();
        let mut handshake = handshake_request(&connector.key, &["sqlite.read"]);
        handshake[field] = value;
        assert!(connector.handle_handshake(handshake).await.is_err());
        assert_ne!(connector.instance_id(), &old_instance);
        assert!(connector.handle_invoke(old.clone()).await.is_err());
        connector.handshake().await;
        assert!(connector.handle_invoke(old).await.is_err());
    }
}

#[fcp_async_core::runtime::test]
async fn session_replacement_rolls_back_uncommitted_writes_and_rotates_transaction_identity() {
    let mut connector = setup_memory_connector().await;
    connector
        .invoke(
            json!({"operation": "sqlite.execute", "input": {"sql": "CREATE TABLE records(value)"}}),
        )
        .await
        .unwrap();
    let begin = connector
        .invoke(json!({"operation": "sqlite.transaction.begin", "input": {}}))
        .await
        .unwrap();
    let txn_id = begin["transaction"]["txn_id"].as_str().unwrap();
    connector
        .invoke(json!({"operation": "sqlite.execute", "input": {
            "sql": "INSERT INTO records VALUES (1)", "txn_id": txn_id,
        }}))
        .await
        .unwrap();
    let stale_commit = connector.request(
        "sqlite.transaction.commit",
        json!({"txn_id": txn_id}),
        database_constraints(),
    );
    assert!(
        connector
            .handle_handshake(json!({"session_id": "legacy-session"}))
            .await
            .is_err()
    );
    connector.handshake().await;
    assert!(connector.handle_invoke(stale_commit).await.is_err());
    let query = connector
        .invoke(
            json!({"operation": "sqlite.query", "input": {"sql": "SELECT count(*) FROM records"}}),
        )
        .await
        .unwrap();
    assert_eq!(query["result"]["rows"][0][0], 0);
    assert!(
        connector
            .invoke(json!({"operation": "sqlite.transaction.commit", "input": {"txn_id": txn_id}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn rejected_reconfiguration_and_shutdown_discard_old_session_authority() {
    let mut connector = setup_memory_connector().await;
    let old = connector.request(
        "sqlite.query",
        json!({"sql": "SELECT 1"}),
        database_constraints(),
    );
    assert!(
        connector
            .handle_configure(json!({"database_path": "../forbidden.sqlite"}))
            .await
            .is_err()
    );
    assert!(connector.handle_invoke(old.clone()).await.is_err());
    assert_eq!(
        connector.handle_health().await.unwrap()["details"]["configured"],
        false
    );
    connector
        .handle_configure(json!({"database_path": ":memory:"}))
        .await
        .unwrap();
    connector.handshake().await;
    assert!(connector.handle_invoke(old).await.is_err());
    let old = connector.request(
        "sqlite.query",
        json!({"sql": "SELECT 1"}),
        database_constraints(),
    );
    connector.handle_shutdown(json!({})).await.unwrap();
    assert!(connector.handle_invoke(old).await.is_err());
    assert_eq!(
        connector.handle_health().await.unwrap()["details"]["handshaken"],
        false
    );
}

struct NativeProcess {
    child: Child,
    input: Option<ChildStdin>,
    replies: Receiver<serde_json::Value>,
    next_id: u64,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-sqlite"))
            .env("RUST_LOG", "error")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start real SQLite connector executable");
        let input = child.stdin.take();
        let output = child.stdout.take().unwrap();
        let (sender, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let value = serde_json::from_str(&line.expect("read native response"))
                    .expect("native stdout contains only JSON protocol frames");
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            replies,
            next_id: 0,
        }
    }

    fn rpc(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let id = format!("rpc-{}", self.next_id);
        let input = self.input.as_mut().unwrap();
        writeln!(
            input,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        )
        .unwrap();
        input.flush().unwrap();
        let response = self
            .replies
            .recv_timeout(Duration::from_secs(10))
            .expect("bounded native response wait");
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], id);
        response
    }

    fn invoke(
        &mut self,
        key: &Ed25519SigningKey,
        instance: &str,
        operation: &str,
        input: serde_json::Value,
    ) -> serde_json::Value {
        let request = signed_request(key, instance, operation, input, database_constraints());
        let response = self.rpc("invoke", request.clone());
        assert!(response.get("error").is_none(), "{response}");
        let response: InvokeResponse = serde_json::from_value(response["result"].clone()).unwrap();
        assert_eq!(response.id.0, request["id"].as_str().unwrap());
        assert!(response.error.is_none());
        response.result.unwrap()
    }

    fn wait_for_exit(&mut self) {
        self.input = None;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "native connector exited with {status}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "native connector failed to terminate"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn native_protocol_executes_signed_database_operations_and_acknowledges_shutdown() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("native.sqlite");
    let mut process = NativeProcess::start();
    let health = process.rpc("health", json!({}));
    let _: HealthSnapshot = serde_json::from_value(health["result"].clone()).unwrap();
    assert_eq!(health["result"]["details"]["configured"], false);
    let configured = process.rpc("configure", json!({"database_path": database}));
    assert!(configured.get("error").is_none(), "{configured}");
    let key = Ed25519SigningKey::generate();
    let handshake = process.rpc(
        "handshake",
        handshake_request(&key, &["sqlite.read", "sqlite.write"]),
    );
    assert_eq!(handshake["result"]["status"], "accepted", "{handshake}");
    let instance = handshake["result"]["instance_id"].as_str().unwrap();
    let introspection = process.rpc("introspect", json!({}));
    let introspection: fcp_core::Introspection =
        serde_json::from_value(introspection["result"].clone()).unwrap();
    assert_eq!(introspection.operations.len(), 12);
    process.invoke(
        &key,
        instance,
        "sqlite.execute",
        json!({"sql": "CREATE TABLE native_values(value INTEGER)"}),
    );
    process.invoke(
        &key,
        instance,
        "sqlite.execute",
        json!({"sql": "INSERT INTO native_values VALUES (?1)", "params": [42]}),
    );
    let query = process.invoke(
        &key,
        instance,
        "sqlite.query",
        json!({"sql": "SELECT value FROM native_values"}),
    );
    assert_eq!(query["result"]["rows"][0][0], 42);
    let unsigned = process.rpc(
        "invoke",
        json!({"operation_id": "sqlite.execute", "input": {"sql": "DROP TABLE native_values"}}),
    );
    assert!(unsigned.get("error").is_some());
    let shutdown = process.rpc(
        "shutdown",
        json!({"type": "shutdown", "drain": true, "deadline_ms": 1000}),
    );
    assert!(shutdown.get("error").is_none(), "{shutdown}");
    // The shared JSONL transport must terminate after flushing its ack, even
    // while the caller is still holding the stdin pipe open.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if process.child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "shutdown acknowledgement did not terminate the loop"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    process.wait_for_exit();
    let connection = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT value FROM native_values", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        42
    );
}

#[test]
fn native_eof_rolls_back_uncommitted_transaction() {
    let directory = tempdir().unwrap();
    let database = directory.path().join("eof.sqlite");
    let mut process = NativeProcess::start();
    assert!(
        process
            .rpc("configure", json!({"database_path": database}))
            .get("error")
            .is_none()
    );
    let key = Ed25519SigningKey::generate();
    let handshake = process.rpc(
        "handshake",
        handshake_request(&key, &["sqlite.read", "sqlite.write"]),
    );
    let instance = handshake["result"]["instance_id"].as_str().unwrap();
    process.invoke(
        &key,
        instance,
        "sqlite.execute",
        json!({"sql": "CREATE TABLE native_values(value INTEGER)"}),
    );
    let transaction = process.invoke(&key, instance, "sqlite.transaction.begin", json!({}));
    process.invoke(&key, instance, "sqlite.execute", json!({"sql": "INSERT INTO native_values VALUES (7)", "txn_id": transaction["transaction"]["txn_id"]}));
    process.wait_for_exit();
    let connection = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM native_values", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
