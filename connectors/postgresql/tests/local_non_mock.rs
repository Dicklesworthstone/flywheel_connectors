//! Local non-mock acceptance coverage for the `PostgreSQL` connector.

#![allow(clippy::future_not_send, clippy::too_many_lines)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

use fcp_postgresql::connector::PostgreSqlConnector;
use serde_json::{Value, json};

const LOOPBACK_TOKEN: &str = "local-acceptance-token";

fn read_loopback_request(stream: &mut TcpStream) -> (String, String) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut buffer).expect("read request bytes");
        assert!(read > 0, "connector should send request headers");
        request.extend_from_slice(&buffer[..read]);
        if let Some(pos) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos;
        }
    };
    let headers = String::from_utf8_lossy(&request[..header_end + 4]).to_string();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = request[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut buffer).expect("read request body");
        assert!(read > 0, "connector should send full request body");
        body.extend_from_slice(&buffer[..read]);
    }
    body.truncate(content_length);
    (headers, String::from_utf8_lossy(&body).to_string())
}

#[fcp_async_core::runtime::test]
async fn loopback_postgrest_health_and_query_uses_production_connector_boundary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let addr = listener.local_addr().expect("read loopback address");
    let handle = thread::spawn(move || {
        let mut observed_lines = Vec::new();
        for expected in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept connector request");
            let (headers, body) = read_loopback_request(&mut stream);
            let request_line = headers.lines().next().unwrap_or_default().to_string();
            assert!(
                headers.to_ascii_lowercase().contains(&format!(
                    "authorization: bearer {}",
                    LOOPBACK_TOKEN.to_ascii_lowercase()
                )) || headers
                    .to_ascii_lowercase()
                    .contains(&format!("apikey: {}", LOOPBACK_TOKEN.to_ascii_lowercase())),
                "expected PostgREST auth header on request {expected}"
            );
            let response_body = if expected == 0 {
                r#"{"status":"ok","postgres_ping":1}"#
            } else {
                assert!(body.contains("SELECT label, amount FROM fcp_acceptance_items"));
                r#"{"rows":[{"label":"alpha","amount":7}],"row_count":1}"#
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
                response_body.len()
            )
            .expect("write loopback response");
            observed_lines.push(request_line);
        }
        observed_lines
    });

    let base_url = format!("http://{addr}");
    let mut connector = PostgreSqlConnector::new();
    connector
        .handle_configure(json!({
            "api_key": LOOPBACK_TOKEN,
            "base_url": base_url
        }))
        .await
        .expect("configure postgresql connector");
    connector
        .handle_handshake(json!({ "session_id": "postgresql-loopback-acceptance" }))
        .await
        .expect("handshake postgresql connector");

    let provider_health: Value = connector
        .handle_invoke(json!({
            "operation_id": "pg.health",
            "input": {}
        }))
        .await
        .expect("invoke pg.health");
    assert_eq!(provider_health["health"]["status"], "ok");

    let queried: Value = connector
        .handle_invoke(json!({
            "operation_id": "pg.query",
            "input": {
                "sql": "SELECT label, amount FROM fcp_acceptance_items ORDER BY amount"
            }
        }))
        .await
        .expect("invoke pg.query");
    assert_eq!(queried["result"]["row_count"], 1);
    assert_eq!(queried["result"]["rows"][0]["label"], "alpha");

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown postgresql connector");

    let observed_lines = handle.join().expect("join loopback server");
    assert_eq!(
        observed_lines,
        vec![
            "GET /rest/v1/health HTTP/1.1".to_string(),
            "POST /rest/v1/rpc/query HTTP/1.1".to_string()
        ]
    );

    let artifact = json!({
        "connector": "postgresql",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operations": ["pg.health", "pg.query"],
        "requests_observed": 2,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[cfg(feature = "integration-testcontainer")]
mod testcontainer_acceptance {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{
        Json, Router,
        extract::{Query, State},
        http::StatusCode,
        routing::{get, post},
    };
    use fcp_async_core::sync::Mutex;
    use fcp_postgresql::connector::PostgreSqlConnector;
    use fcp_testkit::database_helpers::{
        CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
        FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack,
        StatefulFixtureFamily, assert_stateful_fixture_pack_complete,
    };
    use serde_json::{Value, json};
    use testcontainers::{
        GenericImage, ImageExt,
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
    };
    use tokio_postgres::{Client as PgClient, NoTls};

    const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
    const CONNECTOR_ID: &str = "postgresql";
    const FIXTURE_ID: &str = "postgresql-testcontainer-local-acceptance";
    const NAMESPACE: &str = "fcp_postgresql_local_acceptance";
    const TABLE_NAME: &str = "fcp_acceptance_items";

    struct HarnessState {
        conn_str: String,
        active_transactions: Mutex<HashMap<String, PgClient>>,
        next_transaction_id: Mutex<u64>,
    }

    async fn try_connect(conn_str: &str) -> Result<PgClient, tokio_postgres::Error> {
        let (client, connection) = tokio_postgres::connect(conn_str, NoTls).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("tokio-postgres driver task error: {error}");
            }
        });
        Ok(client)
    }

    async fn connect(conn_str: &str) -> PgClient {
        try_connect(conn_str)
            .await
            .expect("connect to testcontainer postgres")
    }

    async fn wait_for_postgres_ready(conn_str: &str) {
        let mut last_error = String::from("no readiness attempt completed");

        for _ in 0..300 {
            match try_connect(conn_str).await {
                Ok(client) => match client.query_one("SELECT 1 AS ready", &[]).await {
                    Ok(_) => return,
                    Err(error) => {
                        last_error = error.to_string();
                    }
                },
                Err(error) => {
                    last_error = error.to_string();
                }
            }

            fcp_async_core::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        panic!("postgres testcontainer did not become queryable: {last_error}");
    }

    async fn handle_query(
        State(state): State<Arc<HarnessState>>,
        Json(body): Json<Value>,
    ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
        let sql = require_str(&body, "sql")?;
        let client = connect(&state.conn_str).await;

        if body.get("mode").and_then(Value::as_str) == Some("execute") {
            client
                .batch_execute(&sql)
                .await
                .map_err(|error| internal(&format!("execute failed: {error}")))?;
            return Ok(Json(json!({
                "affected_rows": 0,
                "status": "executed"
            })));
        }

        let rows = client
            .query(&sql, &[])
            .await
            .map_err(|error| internal(&format!("query failed: {error}")))?;
        let result_rows = rows
            .iter()
            .map(|row| {
                json!({
                    "label": row.get::<_, String>("label"),
                    "amount": row.get::<_, i32>("amount"),
                })
            })
            .collect::<Vec<_>>();

        Ok(Json(json!({
            "rows": result_rows,
            "row_count": result_rows.len()
        })))
    }

    async fn handle_tables(
        State(state): State<Arc<HarnessState>>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
        let schema = params.get("schema").map_or("public", String::as_str);
        let client = connect(&state.conn_str).await;
        let rows = client
            .query(
                "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = $1 AND table_type = 'BASE TABLE' ORDER BY table_name",
                &[&schema],
            )
            .await
            .map_err(|error| internal(&format!("table list failed: {error}")))?;
        let tables = rows
            .iter()
            .map(|row| json!({ "name": row.get::<_, String>("table_name") }))
            .collect::<Vec<_>>();
        Ok(Json(json!({ "tables": tables })))
    }

    async fn handle_health(
        State(state): State<Arc<HarnessState>>,
    ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
        let client = connect(&state.conn_str).await;
        let row = client
            .query_one("SELECT 1 AS ok", &[])
            .await
            .map_err(|error| internal(&format!("health query failed: {error}")))?;
        let ok = row.get::<_, i32>("ok");
        Ok(Json(json!({ "status": "ok", "postgres_ping": ok })))
    }

    async fn handle_transaction(
        State(state): State<Arc<HarnessState>>,
        Json(body): Json<Value>,
    ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
        let action = require_str(&body, "action")?;

        match action.as_str() {
            "begin" => {
                let client = connect(&state.conn_str).await;
                let isolation = body
                    .get("isolation_level")
                    .and_then(Value::as_str)
                    .unwrap_or("READ COMMITTED");
                let begin_sql = format!("BEGIN ISOLATION LEVEL {isolation}");
                client
                    .batch_execute(&begin_sql)
                    .await
                    .map_err(|error| internal(&format!("BEGIN failed: {error}")))?;

                let mut next = state.next_transaction_id.lock().await;
                *next += 1;
                let txn_id = format!("txn-{}", *next);
                drop(next);

                state
                    .active_transactions
                    .lock()
                    .await
                    .insert(txn_id.clone(), client);
                Ok(Json(json!({ "txn_id": txn_id })))
            }
            "commit" => {
                let txn_id = require_str(&body, "txn_id")?;
                let client = state
                    .active_transactions
                    .lock()
                    .await
                    .remove(&txn_id)
                    .ok_or_else(|| not_found(&format!("unknown txn_id {txn_id}")))?;
                client
                    .batch_execute("COMMIT")
                    .await
                    .map_err(|error| internal(&format!("COMMIT failed: {error}")))?;
                Ok(Json(json!({ "status": "committed", "txn_id": txn_id })))
            }
            "rollback" => {
                let txn_id = require_str(&body, "txn_id")?;
                let client = state
                    .active_transactions
                    .lock()
                    .await
                    .remove(&txn_id)
                    .ok_or_else(|| not_found(&format!("unknown txn_id {txn_id}")))?;
                client
                    .batch_execute("ROLLBACK")
                    .await
                    .map_err(|error| internal(&format!("ROLLBACK failed: {error}")))?;
                Ok(Json(json!({ "status": "rolled_back", "txn_id": txn_id })))
            }
            other => Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("unknown action {other}") })),
            )),
        }
    }

    fn require_str(body: &Value, field: &str) -> Result<String, (StatusCode, Json<Value>)> {
        body.get(field)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("missing {field}") })),
                )
            })
    }

    fn internal(message: &str) -> (StatusCode, Json<Value>) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": message })),
        )
    }

    fn not_found(message: &str) -> (StatusCode, Json<Value>) {
        (StatusCode::NOT_FOUND, Json(json!({ "error": message })))
    }

    async fn bring_up() -> (
        String,
        testcontainers::ContainerAsync<GenericImage>,
        Arc<HarnessState>,
    ) {
        let pg_container = GenericImage::new("postgres", "15-alpine")
            .with_exposed_port(5432.tcp())
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_PASSWORD", "test_pw")
            .with_env_var("POSTGRES_USER", "test_user")
            .with_env_var("POSTGRES_DB", "test_db")
            .start()
            .await
            .expect("start postgres testcontainer");

        let host_port = pg_container
            .get_host_port_ipv4(5432.tcp())
            .await
            .expect("get mapped postgres port");
        let conn_str = format!(
            "host=127.0.0.1 port={host_port} user=test_user password=test_pw dbname=test_db"
        );

        wait_for_postgres_ready(&conn_str).await;

        let state = Arc::new(HarnessState {
            conn_str,
            active_transactions: Mutex::new(HashMap::new()),
            next_transaction_id: Mutex::new(0),
        });

        let app = Router::new()
            .route("/rest/v1/rpc/query", post(handle_query))
            .route("/rest/v1/rpc/transaction", post(handle_transaction))
            .route("/rest/v1/schema/tables", get(handle_tables))
            .route("/rest/v1/health", get(handle_health))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local acceptance shim");
        let shim_addr: SocketAddr = listener.local_addr().expect("local shim addr");
        fcp_async_core::task::spawn_detached(async move {
            if let Err(error) = axum::serve(listener, app.into_make_service()).await {
                eprintln!("axum local acceptance shim error: {error}");
            }
        });

        let base_url = format!("http://{shim_addr}");
        wait_for_shim_ready(&base_url).await;
        (base_url, pg_container, state)
    }

    async fn wait_for_shim_ready(base_url: &str) {
        let health_url = format!("{base_url}/rest/v1/health");
        let client = reqwest::Client::new();

        for _ in 0..40 {
            match client.get(&health_url).send().await {
                Ok(response) if response.status().is_success() => return,
                Ok(_) | Err(_) => {
                    fcp_async_core::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            }
        }

        panic!("local postgresql acceptance shim did not become ready");
    }

    fn fixture_contract() -> SeededStatefulFixturePack {
        SeededStatefulFixturePack::new(
            FIXTURE_ID,
            StatefulFixtureFamily::Relational,
            "postgresql-testcontainer",
        )
        .with_startup_probe(FixtureStartupProbe::new(
            "postgres-health",
            FixtureStartupProbeKind::SqlPing,
            "redacted-localhost/postgresql-testcontainer",
            5_000,
            "real Postgres testcontainer answers a health query through the connector",
        ))
        .with_seed(FixtureSeedRecord::new(
            TABLE_NAME,
            "seed-rows",
            json!({
                "namespace": NAMESPACE,
                "rows": [
                    {"label": "alpha", "amount": 7},
                    {"label": "beta", "amount": 11}
                ]
            }),
        ))
        .with_mutation(
            FixtureMutationRecord::new(
                "transactional-commit",
                TABLE_NAME,
                "gamma-row",
                "connector commit makes a row written on the pinned Postgres session visible",
            )
            .with_before(json!({"label": "gamma", "visible": false}))
            .with_after(json!({"label": "gamma", "visible": true})),
        )
        .with_cleanup_check(FixtureCleanupCheck::new(
            "cleanup-table",
            TABLE_NAME,
            "to_regclass",
            "acceptance table is dropped from the disposable Postgres database",
        ))
    }

    async fn configured_connector(base_url: &str) -> PostgreSqlConnector {
        let mut connector = PostgreSqlConnector::new();
        connector
            .handle_configure(json!({
                "api_key": "local-acceptance-token",
                "base_url": base_url
            }))
            .await
            .unwrap();
        connector
            .handle_handshake(json!({ "session_id": "postgresql-local-acceptance" }))
            .await
            .unwrap();
        connector
    }

    async fn invoke(
        connector: &PostgreSqlConnector,
        operation_id: &str,
        input: Value,
    ) -> serde_json::Value {
        connector
            .handle_invoke(json!({
                "operation_id": operation_id,
                "input": input
            }))
            .await
            .unwrap()
    }

    async fn direct_row_count(conn_str: &str, label: &str) -> i64 {
        let client = connect(conn_str).await;
        let row = client
            .query_one(
                &format!("SELECT count(*) AS count FROM {TABLE_NAME} WHERE label = $1"),
                &[&label],
            )
            .await
            .expect("count rows by label");
        row.get::<_, i64>("count")
    }

    async fn table_exists(conn_str: &str) -> bool {
        let client = connect(conn_str).await;
        let row = client
            .query_one(
                "SELECT to_regclass($1) IS NOT NULL AS present",
                &[&TABLE_NAME],
            )
            .await
            .expect("query table presence");
        row.get::<_, bool>("present")
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn postgresql_testcontainer_acceptance_exercises_connector_boundary() {
        let fixture = fixture_contract();
        assert_stateful_fixture_pack_complete(&fixture);

        let (base_url, _pg_container, state) = bring_up().await;
        let mut connector = configured_connector(&base_url).await;

        let health = connector.handle_health().await.unwrap();
        assert_eq!(health["status"], "healthy");
        let provider_health = invoke(&connector, "pg.health", json!({})).await;
        assert_eq!(provider_health["health"]["status"], "ok");
        assert_eq!(provider_health["health"]["postgres_ping"], 1);

        invoke(
        &connector,
        "pg.execute",
        json!({
            "sql": format!(
                "CREATE TABLE {TABLE_NAME}(namespace TEXT NOT NULL, label TEXT NOT NULL, amount INTEGER NOT NULL)"
            )
        }),
    )
    .await;
        invoke(
            &connector,
            "pg.execute",
            json!({
                "sql": format!(
                    "INSERT INTO {TABLE_NAME}(namespace, label, amount) VALUES \
                     ('{NAMESPACE}', 'alpha', 7), ('{NAMESPACE}', 'beta', 11)"
                )
            }),
        )
        .await;

        let queried = invoke(
        &connector,
        "pg.query",
        json!({
            "sql": format!("SELECT label, amount FROM {TABLE_NAME} WHERE namespace = '{NAMESPACE}' ORDER BY amount")
        }),
    )
    .await;
        assert_eq!(queried["result"]["row_count"], 2);
        assert_eq!(queried["result"]["rows"][0]["label"], "alpha");
        assert_eq!(queried["result"]["rows"][0]["amount"], 7);

        let tables = invoke(
            &connector,
            "pg.schema.tables",
            json!({ "schema": "public" }),
        )
        .await;
        let table_rows = tables["tables"]["tables"]
            .as_array()
            .expect("schema table array");
        assert!(table_rows.iter().any(|table| table["name"] == TABLE_NAME));

        let begin = invoke(
            &connector,
            "pg.transaction.begin",
            json!({ "isolation_level": "READ COMMITTED" }),
        )
        .await;
        let txn_id = begin["result"]["txn_id"].as_str().unwrap().to_string();
        {
            let active = state.active_transactions.lock().await;
            let pg = active.get(&txn_id).expect("pinned transaction session");
            pg.batch_execute(&format!(
            "INSERT INTO {TABLE_NAME}(namespace, label, amount) VALUES ('{NAMESPACE}', 'gamma', 13)"
        ))
        .await
        .expect("insert through pinned transaction session");
        }
        invoke(
            &connector,
            "pg.transaction.commit",
            json!({ "txn_id": txn_id }),
        )
        .await;
        assert_eq!(direct_row_count(&state.conn_str, "gamma").await, 1);

        let rollback = invoke(&connector, "pg.transaction.begin", json!({})).await;
        let rollback_txn_id = rollback["result"]["txn_id"].as_str().unwrap().to_string();
        {
            let active = state.active_transactions.lock().await;
            let pg = active
                .get(&rollback_txn_id)
                .expect("pinned rollback transaction session");
            pg.batch_execute(&format!(
            "INSERT INTO {TABLE_NAME}(namespace, label, amount) VALUES ('{NAMESPACE}', 'delta', 17)"
        ))
        .await
        .expect("insert rollback row through pinned session");
        }
        invoke(
            &connector,
            "pg.transaction.rollback",
            json!({ "txn_id": rollback_txn_id }),
        )
        .await;
        assert_eq!(direct_row_count(&state.conn_str, "delta").await, 0);

        invoke(
            &connector,
            "pg.execute",
            json!({ "sql": format!("DROP TABLE {TABLE_NAME}") }),
        )
        .await;
        let cleanup_passed = !table_exists(&state.conn_str).await;
        let cleanup = CleanupVerificationResult::new(
            "cleanup-table",
            TABLE_NAME,
            "to_regclass",
            "acceptance table is absent after cleanup",
            json!({ "table_present": !cleanup_passed }),
            cleanup_passed,
        );

        connector.handle_shutdown(json!({})).await.unwrap();

        let evidence = json!({
            "schema_version": "fcp-postgresql-local-acceptance/v1",
            "suite_class": ACCEPTANCE_SUITE_CLASS,
            "connector": CONNECTOR_ID,
            "fixture_id": FIXTURE_ID,
            "service_fixture": "postgres:15-alpine-testcontainer",
            "endpoint": "redacted-localhost/postgrest-compatible-shim",
            "operations": [
                "pg.health",
                "pg.execute:create_table",
                "pg.execute:seed_rows",
                "pg.query:read_seed_rows",
                "pg.schema.tables",
                "pg.transaction.begin",
                "pg.transaction.commit",
                "pg.transaction.rollback",
                "pg.execute:cleanup_table"
            ],
            "fixture_contract": fixture.to_json(),
            "cleanup": cleanup,
        });

        assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
        assert_eq!(evidence["cleanup"]["passed"], true);
        assert!(
            !serde_json::to_string(&evidence)
                .unwrap()
                .contains(&state.conn_str),
            "acceptance evidence must not expose the local Postgres connection string"
        );
    }
}
