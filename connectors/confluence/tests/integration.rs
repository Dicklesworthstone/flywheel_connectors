//! Connector-local no-mock Confluence integration proof.
//!
//! These tests exercise the real Confluence client against a local HTTP server.
//! No live Atlassian or Confluence service is called.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use base64::Engine;
use fcp_async_core::AsyncError;
use fcp_confluence::ConfluenceConnector;
use fcp_confluence::client::ConfluenceClient;
use fcp_confluence::connector::operations_info;
use fcp_confluence::error::Error;
use fcp_prelude::{ApprovalMode, FcpConnector, FcpError, IdempotencyClass, RiskLevel, SafetyTier};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorErrorMapping, ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_EMAIL: &str = "user@example.com";
const TEST_TOKEN: &str = "confluence-token-for-tests";
const OP_SPACES_LIST: &str = "confluence.spaces.list";
const OP_SPACES_GET: &str = "confluence.spaces.get";
const OP_PAGES_LIST: &str = "confluence.pages.list";
const OP_PAGES_GET: &str = "confluence.pages.get";
const OP_PAGES_CREATE: &str = "confluence.pages.create";
const OP_PAGES_UPDATE: &str = "confluence.pages.update";
const OP_PAGES_DELETE: &str = "confluence.pages.delete";
const OP_SEARCH: &str = "confluence.search";
const OP_HEALTH: &str = "confluence.health";
const EXPECTED_MANIFEST_SCHEMA_OPS: [(&str, &str); 9] = [
    ("spaces_list", OP_SPACES_LIST),
    ("spaces_get", OP_SPACES_GET),
    ("pages_list", OP_PAGES_LIST),
    ("pages_get", OP_PAGES_GET),
    ("pages_create", OP_PAGES_CREATE),
    ("pages_update", OP_PAGES_UPDATE),
    ("pages_delete", OP_PAGES_DELETE),
    ("search", OP_SEARCH),
    ("health", OP_HEALTH),
];

fn expected_auth_header() -> String {
    let credentials = format!("{TEST_EMAIL}:{TEST_TOKEN}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
    format!("Basic {encoded}")
}

fn no_retry_config() -> HttpRetryConfig {
    HttpRetryConfig {
        max_retries: 0,
        initial_delay_ms: 1,
        max_delay_ms: 1,
        jitter_enabled: false,
    }
}

fn test_runtime() -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(500)),
    )
}

fn client(server: &MockServer) -> ConfluenceClient {
    ConfluenceClient::new(&server.uri(), TEST_EMAIL, TEST_TOKEN, no_retry_config())
        .expect("wiremock URI should build a Confluence client")
}

fn space_json(key: &str) -> Value {
    json!({
        "id": "space-1",
        "key": key,
        "name": "Engineering",
        "type": "global",
        "status": "current",
        "_links": {
            "self": "/rest/api/space/ENG",
            "webui": "/spaces/ENG"
        }
    })
}

fn page_json(page_id: &str, title: &str) -> Value {
    json!({
        "id": page_id,
        "title": title,
        "type": "page",
        "status": "current",
        "space": { "key": "ENG", "name": "Engineering" },
        "version": { "number": 2, "message": "updated" },
        "body": {
            "storage": {
                "value": "<p>Hello from FCP</p>",
                "representation": "storage"
            }
        },
        "_links": { "webui": "/spaces/ENG/pages/123" }
    })
}

fn confluence_manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml")).expect("Confluence manifest TOML should parse")
}

fn manifest_operations(manifest: &toml::Value) -> &toml::Table {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest should contain provides.operations")
}

fn operation_schema(manifest: &toml::Value, operation_key: &str, schema_key: &str) -> Value {
    let schema = manifest_operations(manifest)
        .get(operation_key)
        .and_then(|operation| operation.get(schema_key))
        .expect("operation should define requested schema");

    serde_json::to_value(schema).expect("manifest schema should convert to JSON")
}

fn assert_schema_accepts(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "schema should accept payload {payload:#}: {errors:#?}"
    );
}

fn assert_schema_rejects(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        !errors.is_empty(),
        "schema should reject payload {payload:#}"
    );
}

fn assert_manifest_schema_catalog_matches_runtime(manifest: &toml::Value) {
    let introspection = ConfluenceConnector::new().introspect();
    assert_eq!(
        introspection.operations.len(),
        EXPECTED_MANIFEST_SCHEMA_OPS.len(),
        "runtime operation catalog should stay aligned with manifest schema coverage"
    );

    for (manifest_key, operation_id) in EXPECTED_MANIFEST_SCHEMA_OPS {
        let operation = introspection
            .operations
            .iter()
            .find(|entry| entry.id.as_str() == operation_id)
            .expect("runtime catalog should include manifest operation");
        let input_schema = operation_schema(manifest, manifest_key, "input_schema");
        let output_schema = operation_schema(manifest, manifest_key, "output_schema");

        assert_eq!(
            input_schema, operation.input_schema,
            "{operation_id} manifest input_schema should match runtime OperationInfo"
        );
        assert_eq!(
            output_schema, operation.output_schema,
            "{operation_id} manifest output_schema should match runtime OperationInfo"
        );
        assert!(
            jsonschema::validator_for(&input_schema).is_ok(),
            "{operation_id} manifest input_schema should compile"
        );
        assert!(
            jsonschema::validator_for(&output_schema).is_ok(),
            "{operation_id} manifest output_schema should compile"
        );
    }
}

fn assert_input_schema_examples(manifest: &toml::Value) {
    let spaces_list = operation_schema(manifest, "spaces_list", "input_schema");
    assert_schema_accepts(&spaces_list, &json!({}));
    assert_schema_accepts(&spaces_list, &json!({ "start": 0, "limit": 2 }));
    assert_schema_rejects(&spaces_list, &json!({ "limit": "two" }));
    assert_schema_rejects(&spaces_list, &json!({ "start": 0, "unexpected": true }));

    let spaces_get = operation_schema(manifest, "spaces_get", "input_schema");
    assert_schema_accepts(&spaces_get, &json!({ "space_key": "ENG" }));
    assert_schema_rejects(&spaces_get, &json!({}));
    assert_schema_rejects(&spaces_get, &json!({ "space_key": "../ENG" }));
    assert_schema_rejects(&spaces_get, &json!({ "space_key": "ENG", "extra": true }));

    let pages_list = operation_schema(manifest, "pages_list", "input_schema");
    assert_schema_accepts(&pages_list, &json!({ "space_key": "ENG", "start": 2 }));
    assert_schema_rejects(&pages_list, &json!({ "limit": 10 }));
    assert_schema_rejects(&pages_list, &json!({ "space_key": "ENG", "limit": 0 }));

    let pages_get = operation_schema(manifest, "pages_get", "input_schema");
    assert_schema_accepts(&pages_get, &json!({ "page_id": "page-1" }));
    assert_schema_rejects(&pages_get, &json!({ "page_id": 42 }));
    assert_schema_rejects(&pages_get, &json!({ "page_id": "page/1" }));

    let pages_create = operation_schema(manifest, "pages_create", "input_schema");
    assert_schema_accepts(
        &pages_create,
        &json!({
            "space_key": "ENG",
            "title": "Runbook",
            "body": "<p>Hello</p>",
            "parent_id": "parent-1"
        }),
    );
    assert_schema_rejects(
        &pages_create,
        &json!({ "space_key": "ENG", "title": "Runbook" }),
    );
    assert_schema_rejects(
        &pages_create,
        &json!({ "space_key": "ENG", "title": "Runbook", "body": "<p>Hello</p>", "draft": true }),
    );

    let pages_update = operation_schema(manifest, "pages_update", "input_schema");
    assert_schema_accepts(
        &pages_update,
        &json!({
            "page_id": "page-1",
            "title": "Runbook",
            "body": "<p>Hello</p>",
            "version_number": 2
        }),
    );
    assert_schema_rejects(
        &pages_update,
        &json!({
            "page_id": "page-1",
            "title": "Runbook",
            "body": "<p>Hello</p>",
            "version_number": "2"
        }),
    );
    assert_schema_rejects(
        &pages_update,
        &json!({
            "page_id": "page-1",
            "title": "Runbook",
            "body": "<p>Hello</p>",
            "version_number": 2,
            "extra": true
        }),
    );

    let pages_delete = operation_schema(manifest, "pages_delete", "input_schema");
    assert_schema_accepts(&pages_delete, &json!({ "page_id": "page-1" }));
    assert_schema_rejects(&pages_delete, &json!({}));
    assert_schema_rejects(&pages_delete, &json!({ "page_id": ".." }));

    let search = operation_schema(manifest, "search", "input_schema");
    assert_schema_accepts(
        &search,
        &json!({ "cql": "space = ENG and text ~ \"runbook\"", "limit": 10 }),
    );
    assert_schema_rejects(&search, &json!({ "limit": 10 }));
    assert_schema_rejects(&search, &json!({ "cql": "" }));
    assert_schema_rejects(&search, &json!({ "cql": "space = ENG", "extra": true }));

    let health = operation_schema(manifest, "health", "input_schema");
    assert_schema_accepts(&health, &json!({}));
    assert_schema_rejects(&health, &json!({ "extra": true }));
}

fn assert_output_schema_examples(manifest: &toml::Value) {
    let paginated_output = json!({
        "results": [space_json("ENG")],
        "size": 1
    });

    let spaces_list = operation_schema(manifest, "spaces_list", "output_schema");
    assert_schema_accepts(&spaces_list, &paginated_output);
    assert_schema_rejects(&spaces_list, &json!({ "results": {}, "size": 1 }));
    assert_schema_rejects(
        &spaces_list,
        &json!({ "results": [], "size": 1, "extra": true }),
    );

    let spaces_get = operation_schema(manifest, "spaces_get", "output_schema");
    assert_schema_accepts(&spaces_get, &space_json("ENG"));
    assert_schema_rejects(
        &spaces_get,
        &json!({ "id": 1, "key": "ENG", "name": "Engineering" }),
    );
    assert_schema_rejects(
        &spaces_get,
        &json!({ "id": "space-1", "key": "ENG", "name": "Engineering", "extra": true }),
    );

    let pages_list = operation_schema(manifest, "pages_list", "output_schema");
    assert_schema_accepts(
        &pages_list,
        &json!({ "results": [page_json("page-1", "Runbook")], "size": 1 }),
    );
    assert_schema_rejects(
        &pages_list,
        &json!({ "results": "not an array", "size": 1 }),
    );

    let pages_get = operation_schema(manifest, "pages_get", "output_schema");
    assert_schema_accepts(&pages_get, &page_json("page-1", "Runbook"));
    assert_schema_rejects(&pages_get, &json!({ "id": "page-1", "title": 42 }));

    let pages_create = operation_schema(manifest, "pages_create", "output_schema");
    assert_schema_accepts(&pages_create, &page_json("page-created", "Created by FCP"));
    assert_schema_rejects(
        &pages_create,
        &json!({ "id": 1, "title": "Created by FCP" }),
    );

    let pages_update = operation_schema(manifest, "pages_update", "output_schema");
    assert_schema_accepts(&pages_update, &page_json("page-1", "Runbook updated"));
    assert_schema_rejects(&pages_update, &json!({ "id": "page-1", "version": "3" }));

    let pages_delete = operation_schema(manifest, "pages_delete", "output_schema");
    assert_schema_accepts(&pages_delete, &json!({ "deleted": true }));
    assert_schema_rejects(&pages_delete, &json!({ "deleted": "true" }));

    let search = operation_schema(manifest, "search", "output_schema");
    assert_schema_accepts(
        &search,
        &json!({
            "results": [{
                "title": "Runbook",
                "excerpt": "Operational runbook",
                "url": "/wiki/spaces/ENG/pages/page-1",
                "content": page_json("page-1", "Runbook")
            }],
            "size": 1
        }),
    );
    assert_schema_rejects(&search, &json!({ "results": {}, "size": 1 }));

    let health = operation_schema(manifest, "health", "output_schema");
    assert_schema_accepts(&health, &json!({ "status": "ok" }));
    assert_schema_rejects(&health, &json!({ "status": 200 }));
    assert_schema_rejects(&health, &json!({ "status": "degraded" }));
}

#[test]
fn manifest_operation_schemas_compile_and_validate_core_payloads() {
    let manifest = confluence_manifest();
    assert_manifest_schema_catalog_matches_runtime(&manifest);
    assert_input_schema_examples(&manifest);
    assert_output_schema_examples(&manifest);
}

#[fcp_async_core::runtime::test]
async fn spaces_pages_search_and_health_success_paths_use_confluence_contracts() {
    tracing::info!(
        scenario = "confluence_success_contracts",
        "starting Confluence success-path integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/rest/api/space"))
        .and(query_param("start", "0"))
        .and(query_param("limit", "2"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [space_json("ENG")],
            "start": 0,
            "limit": 2,
            "size": 1,
            "_links": { "next": "/rest/api/space?start=2", "base": "/wiki" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/space/ENG"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(space_json("ENG")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/space/ENG/content/page"))
        .and(query_param("start", "2"))
        .and(query_param("limit", "3"))
        .and(query_param("expand", "version,space"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [page_json("page-1", "Runbook")],
            "start": 2,
            "limit": 3,
            "size": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/content/page-1"))
        .and(query_param("expand", "body.storage,version,space"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("page-1", "Runbook")))
        .expect(1)
        .mount(&server)
        .await;

    let create_body = json!({
        "type": "page",
        "title": "Created by FCP",
        "space": { "key": "ENG" },
        "body": {
            "storage": {
                "value": "<p>Created</p>",
                "representation": "storage"
            }
        }
    });
    Mock::given(method("POST"))
        .and(path("/rest/api/content"))
        .and(header("Authorization", expected_auth_header()))
        .and(body_json(create_body.clone()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_json("page-created", "Created by FCP")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let update_body = json!({
        "id": "page-1",
        "type": "page",
        "title": "Runbook updated",
        "body": {
            "storage": {
                "value": "<p>Updated</p>",
                "representation": "storage"
            }
        },
        "version": {
            "number": 3,
            "message": "proof update"
        }
    });
    Mock::given(method("PUT"))
        .and(path("/rest/api/content/page-1"))
        .and(header("Authorization", expected_auth_header()))
        .and(body_json(update_body.clone()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_json("page-1", "Runbook updated")),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/rest/api/content/page-1"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/search"))
        .and(query_param("cql", "space = ENG and text ~ \"runbook\""))
        .and(query_param("start", "5"))
        .and(query_param("limit", "10"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "title": "Runbook",
                "excerpt": "Operational runbook",
                "url": "/wiki/spaces/ENG/pages/page-1",
                "content": page_json("page-1", "Runbook")
            }],
            "start": 5,
            "limit": 10,
            "size": 1,
            "_links": { "next": "/rest/api/search?start=15" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/space"))
        .and(query_param("limit", "1"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [],
            "start": 0,
            "limit": 1,
            "size": 0
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let spaces = client
        .list_spaces(&runtime, 0, 2)
        .await
        .expect("spaces should decode");
    let first_space = spaces.results.first().expect("space result");
    assert_eq!(first_space.key, "ENG");
    assert_eq!(
        spaces.links.and_then(|links| links.next).as_deref(),
        Some("/rest/api/space?start=2")
    );

    let space = client
        .get_space(&runtime, "ENG")
        .await
        .expect("space should decode");
    assert_eq!(space.name, "Engineering");

    let pages = client
        .list_pages(&runtime, "ENG", 2, 3)
        .await
        .expect("pages should decode");
    let first_page = pages.results.first().expect("page result");
    assert_eq!(first_page.id, "page-1");
    assert_eq!(pages.start, 2);

    let page = client
        .get_page(&runtime, "page-1")
        .await
        .expect("page should decode");
    assert_eq!(page.title, "Runbook");
    assert_eq!(page.space.expect("space ref").key, "ENG");

    let created = client
        .create_page(&runtime, &create_body)
        .await
        .expect("create page should decode");
    assert_eq!(created.id, "page-created");

    let updated = client
        .update_page(&runtime, "page-1", &update_body)
        .await
        .expect("update page should decode");
    assert_eq!(updated.title, "Runbook updated");

    client
        .delete_page(&runtime, "page-1")
        .await
        .expect("delete page should accept 204");

    let results = client
        .search(&runtime, "space = ENG and text ~ \"runbook\"", 5, 10)
        .await
        .expect("search results should decode");
    let first_result = results.results.first().expect("search result");
    assert_eq!(first_result.title, "Runbook");
    assert_eq!(
        results.links.and_then(|links| links.next).as_deref(),
        Some("/rest/api/search?start=15")
    );

    client
        .health_check()
        .await
        .expect("health check should pass");
}

#[fcp_async_core::runtime::test]
async fn auth_rate_limit_malformed_json_and_invalid_input_are_typed() {
    tracing::info!(
        scenario = "confluence_error_taxonomy",
        "starting Confluence error-taxonomy integration proof",
    );

    let server = MockServer::start().await;
    let runtime = test_runtime();

    Mock::given(method("GET"))
        .and(path("/rest/api/space/BAD"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "message": "Invalid credentials"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/search"))
        .and(query_param("cql", "text ~ \"rate\""))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(json!({ "message": "rate limited" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/rest/api/content/malformed"))
        .and(query_param("expand", "body.storage,version,space"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let unauthorized = client
        .get_space(&runtime, "BAD")
        .await
        .expect_err("401 should map to unauthorized");
    assert!(matches!(unauthorized, Error::Unauthorized(_)));
    assert!(!unauthorized.is_retryable());
    assert!(matches!(
        unauthorized.to_fcp_error(),
        FcpError::Unauthorized { code: 2001, .. }
    ));

    let rate_limited = client
        .search(&runtime, "text ~ \"rate\"", 0, 25)
        .await
        .expect_err("429 should map to rate limit");
    assert!(matches!(
        rate_limited,
        Error::RateLimited {
            retry_after_ms: 2_000
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::from_secs(2)));
    assert!(matches!(
        rate_limited.to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 2_000,
            ..
        }
    ));

    let malformed = client
        .get_page(&runtime, "malformed")
        .await
        .expect_err("malformed JSON should be surfaced by reqwest decode");
    assert!(matches!(malformed, Error::Http(ref error) if error.is_decode()));
    assert!(matches!(
        malformed.to_fcp_error(),
        FcpError::External {
            service,
            retryable: true,
            ..
        } if service == "confluence"
    ));

    let traversal = client
        .get_space(&runtime, "../ENG")
        .await
        .expect_err("path traversal should be rejected before outbound call");
    assert!(matches!(traversal, Error::InvalidInput(_)));
    assert!(matches!(
        traversal.to_fcp_error(),
        FcpError::InvalidRequest { code: 1005, .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn health_check_status_errors_are_typed() {
    let unauthorized_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/space"))
        .and(query_param("limit", "1"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&unauthorized_server)
        .await;

    let unauthorized = client(&unauthorized_server)
        .health_check()
        .await
        .expect_err("401 health check should map to unauthorized");
    assert!(matches!(unauthorized, Error::Unauthorized(_)));

    let rate_limit_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/space"))
        .and(query_param("limit", "1"))
        .and(header("Authorization", expected_auth_header()))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
        .expect(1)
        .mount(&rate_limit_server)
        .await;

    let rate_limited = client(&rate_limit_server)
        .health_check()
        .await
        .expect_err("429 health check should map to rate limit");
    assert!(matches!(
        rate_limited,
        Error::RateLimited {
            retry_after_ms: 60_000
        }
    ));
}

#[test]
fn async_timeout_and_cancellation_mapping_is_bounded() {
    let timeout = Error::from_async_error(AsyncError::Timeout { timeout_ms: 250 });
    assert_eq!(
        timeout.to_string(),
        "Async error: operation timed out after 250ms"
    );
    assert!(timeout.is_retryable());

    let cancelled = Error::from_async_error(AsyncError::Cancelled);
    assert_eq!(cancelled.to_string(), "Async error: operation cancelled");
    assert!(cancelled.is_retryable());
}

#[test]
fn operation_catalog_manifest_and_redaction_preserve_security_posture() {
    let connector = ConfluenceConnector::new();
    let introspection = connector.introspect();
    assert_eq!(introspection.operations.len(), 9);
    assert!(
        !introspection
            .event_caps
            .as_ref()
            .expect("event caps")
            .streaming
    );

    let operations = operations_info();
    let operation = |id: &str| {
        operations
            .iter()
            .find(|entry| entry.id.as_str() == id)
            .expect("operation catalog should contain required Confluence operation")
    };

    let spaces_list = operation("confluence.spaces.list");
    assert_eq!(spaces_list.risk_level, RiskLevel::Low);
    assert_eq!(spaces_list.safety_tier, SafetyTier::Safe);
    assert_eq!(spaces_list.requires_approval, Some(ApprovalMode::None));

    let pages_create = operation("confluence.pages.create");
    assert_eq!(pages_create.risk_level, RiskLevel::Medium);
    assert_eq!(pages_create.safety_tier, SafetyTier::Risky);
    assert_eq!(pages_create.idempotency, IdempotencyClass::BestEffort);

    let pages_delete = operation("confluence.pages.delete");
    assert_eq!(pages_delete.risk_level, RiskLevel::High);
    assert_eq!(pages_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(
        pages_delete.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let health = operation("confluence.health");
    assert_eq!(health.risk_level, RiskLevel::Low);
    assert_eq!(health.safety_tier, SafetyTier::Safe);
    assert_eq!(health.idempotency, IdempotencyClass::Strict);

    let capability_section = manifest_capability_section();
    assert!(capability_section.contains("\"network.dns\""));
    assert!(capability_section.contains("\"network.outbound\""));
    assert!(capability_section.contains("\"system.exec\""));
    assert!(capability_section.contains("\"system.privileged\""));
    assert!(!capability_section.contains("network.listen"));
    assert!(include_str!("../manifest.toml").contains("deny_localhost = true"));

    let client = ConfluenceClient::new(
        "https://example.atlassian.net/wiki",
        TEST_EMAIL,
        "super-secret-confluence-token",
        no_retry_config(),
    )
    .expect("redaction proof client should build");
    let debug_output = format!("{client:?}");
    assert!(!debug_output.contains("super-secret-confluence-token"));
    assert!(debug_output.contains("[REDACTED]"));
}

fn manifest_capability_section() -> &'static str {
    let manifest = include_str!("../manifest.toml");
    let (_, capabilities) = manifest
        .split_once("[capabilities]")
        .expect("Confluence manifest should define capabilities");
    let (capability_section, _) = capabilities
        .split_once("[provides.operations.")
        .expect("Confluence manifest should separate capabilities from operations");
    capability_section
}

// ── Replay safety on retry (br-kxd3e) ────────────────────────────────
//
// Confluence has no idempotency key, so a 5xx retry on create_page publishes
// a second page. The assertion is the REQUEST COUNT.

fn retrying_client(server: &MockServer) -> ConfluenceClient {
    ConfluenceClient::new(
        &server.uri(),
        TEST_EMAIL,
        TEST_TOKEN,
        HttpRetryConfig {
            max_retries: 3,
            initial_delay_ms: 1,
            max_delay_ms: 5,
            jitter_enabled: false,
        },
    )
    .expect("wiremock URI should build a Confluence client")
}

#[fcp_async_core::runtime::test]
async fn create_page_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/content"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let result = retrying_client(&server)
        .create_page(&test_runtime(), &json!({ "title": "Page" }))
        .await;
    assert!(result.is_err());

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a 503 means Confluence received the create — retrying publishes a \
         SECOND page"
    );
}

#[fcp_async_core::runtime::test]
async fn create_page_still_retries_a_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/content"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/api/content"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1",
            "type": "page",
            "status": "current",
            "title": "Page"
        })))
        .mount(&server)
        .await;

    retrying_client(&server)
        .create_page(&test_runtime(), &json!({ "title": "Page" }))
        .await
        .expect("a rate-limited create was refused without publishing anything");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "429 means Confluence did NOT create the page, so backoff is preserved"
    );
}
