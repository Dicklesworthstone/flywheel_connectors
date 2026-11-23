//! Local acceptance coverage for the `SQLite` connector.

#![allow(clippy::future_not_send)]

use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};
use tempfile::tempdir;

mod common;
use common::TestConnector;

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "fcp.sqlite";
const FIXTURE_ID: &str = "sqlite-file-backed-local-acceptance";
const NAMESPACE: &str = "fcp_sqlite_local_acceptance";
const TABLE_NAME: &str = "fcp_acceptance_items";

async fn configured_file_connector(database_path: &str) -> TestConnector {
    let mut connector = TestConnector::new();
    connector
        .handle_configure(json!({ "database_path": database_path }))
        .await
        .unwrap();
    connector.handshake().await;
    connector
}

async fn invoke(
    connector: &mut TestConnector,
    operation_id: &str,
    input: Value,
) -> serde_json::Value {
    connector
        .invoke(json!({
            "operation": operation_id,
            "input": input
        }))
        .await
        .unwrap()
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::Embedded,
        "sqlite-file-backed",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "sqlite-health",
        FixtureStartupProbeKind::SqlPing,
        "redacted-tempfile/sqlite-local-acceptance.sqlite",
        1_000,
        "file-backed SQLite connector answers a health query before mutations",
    ))
    .with_seed(FixtureSeedRecord::new(
        TABLE_NAME,
        "seed-row",
        json!({
            "namespace": NAMESPACE,
            "label": "seeded",
            "quantity": 1
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "transactional-update",
            TABLE_NAME,
            "seed-row",
            "connector updates a seeded row through the real SQLite file boundary",
        )
        .with_before(json!({"label": "seeded", "quantity": 1}))
        .with_after(json!({"label": "updated", "quantity": 2})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-namespace",
        TABLE_NAME,
        "query_namespace_count",
        "zero rows remain for the acceptance namespace",
    ))
}

#[fcp_async_core::runtime::test]
async fn file_backed_sqlite_acceptance_exercises_real_local_boundary() {
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("sqlite-local-acceptance.sqlite");
    let database_path = database_path.to_string_lossy().to_string();
    let fixture = fixture_contract();
    assert_stateful_fixture_pack_complete(&fixture);

    let mut connector = configured_file_connector(&database_path).await;
    let health = invoke(&mut connector, "sqlite.health", json!({})).await;
    assert_eq!(health["health"]["query_ok"], true);

    invoke(
        &mut connector,
        "sqlite.execute",
        json!({
            "sql": format!(
                "CREATE TABLE {TABLE_NAME}(namespace TEXT NOT NULL, label TEXT NOT NULL, quantity INTEGER NOT NULL)"
            )
        }),
    )
    .await;
    invoke(
        &mut connector,
        "sqlite.execute",
        json!({
            "sql": format!("INSERT INTO {TABLE_NAME}(namespace, label, quantity) VALUES (?1, ?2, ?3)"),
            "params": [NAMESPACE, "seeded", 1]
        }),
    )
    .await;

    let seeded = invoke(
        &mut connector,
        "sqlite.query",
        json!({
            "sql": format!("SELECT label, quantity FROM {TABLE_NAME} WHERE namespace = ?1"),
            "params": [NAMESPACE]
        }),
    )
    .await;
    assert_eq!(seeded["result"]["row_count"], 1);
    assert_eq!(seeded["result"]["rows"][0][0], "seeded");
    assert_eq!(seeded["result"]["rows"][0][1], 1);

    let begin = invoke(
        &mut connector,
        "sqlite.transaction.begin",
        json!({ "mode": "immediate" }),
    )
    .await;
    let txn_id = begin["transaction"]["txn_id"].as_str().unwrap();
    invoke(
        &mut connector,
        "sqlite.execute",
        json!({
            "sql": format!("UPDATE {TABLE_NAME} SET label = ?1, quantity = ?2 WHERE namespace = ?3"),
            "params": ["updated", 2, NAMESPACE],
            "txn_id": txn_id
        }),
    )
    .await;
    invoke(
        &mut connector,
        "sqlite.transaction.commit",
        json!({ "txn_id": txn_id }),
    )
    .await;

    connector.handle_shutdown(json!({})).await.unwrap();
    let mut reopened = configured_file_connector(&database_path).await;
    let persisted = invoke(
        &mut reopened,
        "sqlite.query",
        json!({
            "sql": format!("SELECT label, quantity FROM {TABLE_NAME} WHERE namespace = ?1"),
            "params": [NAMESPACE]
        }),
    )
    .await;
    assert_eq!(persisted["result"]["row_count"], 1);
    assert_eq!(persisted["result"]["rows"][0][0], "updated");
    assert_eq!(persisted["result"]["rows"][0][1], 2);

    let blocked = reopened
        .invoke(json!({
            "operation": "sqlite.query",
            "input": {
                "sql": format!("DELETE FROM {TABLE_NAME} WHERE namespace = ?1"),
                "params": [NAMESPACE]
            }
        }))
        .await
        .unwrap_err();
    assert!(blocked.to_string().contains("read-only"));

    invoke(
        &mut reopened,
        "sqlite.execute",
        json!({
            "sql": format!("DELETE FROM {TABLE_NAME} WHERE namespace = ?1"),
            "params": [NAMESPACE]
        }),
    )
    .await;
    let cleanup_query = invoke(
        &mut reopened,
        "sqlite.query",
        json!({
            "sql": format!("SELECT count(*) FROM {TABLE_NAME} WHERE namespace = ?1"),
            "params": [NAMESPACE]
        }),
    )
    .await;
    assert_eq!(cleanup_query["result"]["rows"][0][0], 0);

    let cleanup = CleanupVerificationResult::new(
        "cleanup-namespace",
        TABLE_NAME,
        "query_namespace_count",
        "zero rows remain for the acceptance namespace",
        json!({ "remaining_rows": cleanup_query["result"]["rows"][0][0] }),
        true,
    );
    let evidence = json!({
        "schema_version": "fcp-sqlite-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "database_path": "redacted-tempfile/sqlite-local-acceptance.sqlite",
        "operations": [
            "sqlite.health",
            "sqlite.execute:create_table",
            "sqlite.execute:seed_row",
            "sqlite.query:seed_row",
            "sqlite.transaction.begin",
            "sqlite.execute:update_row",
            "sqlite.transaction.commit",
            "sqlite.query:persistence_after_reopen",
            "sqlite.query:write_denial",
            "sqlite.execute:cleanup_namespace",
            "sqlite.query:cleanup_verify"
        ],
        "fixture_contract": fixture.to_json(),
        "cleanup": cleanup
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(evidence["cleanup"]["passed"], true);
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains(directory.path().to_string_lossy().as_ref()),
        "acceptance evidence must not expose absolute temp paths"
    );
}
