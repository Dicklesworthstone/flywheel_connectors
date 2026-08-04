//! Integration tests for the Notion connector.
//!
//! Covers the connector testing requirements (u56.5):
//! - Error taxonomy mapping (`NotionError` -> `FcpError`)
//! - Redaction (integration token not leaked in errors)
//! - Pagination handling
//! - Operation dispatch through connector
//! - Capability verification
//!
//! All tests are deterministic -- no real API calls.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

use fcp_notion::{
    client::{DEFAULT_NOTION_VERSION, NotionClient},
    connector::NotionConnector,
    error::NotionError,
};

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &str,
    connector: &NotionConnector,
) -> CapabilityToken {
    let cap = match op {
        "notion.create_page"
        | "notion.update_page"
        | "notion.create_database"
        | "notion.update_database"
        | "notion.update_block"
        | "notion.append_blocks"
        | "notion.add_comment" => "notion.write",
        "notion.delete_page" | "notion.delete_block" => "notion.delete",
        "notion.search" => "notion.search",
        _ => "notion.read",
    };
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .target_instance(connector.instance_id().as_str())
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut NotionConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

async fn setup_configure(connector: &mut NotionConnector, api_url: &str) {
    connector
        .handle_configure(json!({
            "token": "ntn_test_integration_key",
            "api_url": api_url
        }))
        .await
        .expect("configure should succeed");
}

fn page_json(id: &str, title: &str) -> serde_json::Value {
    json!({
        "object": "page",
        "id": id,
        "properties": {
            "title": {
                "title": [{ "text": { "content": title } }]
            }
        },
        "created_time": "2026-01-01T00:00:00.000Z",
        "last_edited_time": "2026-01-01T00:00:00.000Z"
    })
}

// ============================================================================
// Error taxonomy mapping tests
// ============================================================================

/// 401 Unauthorized maps to `NotionError::Unauthorized` -> `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("bad-token")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    assert!(matches!(err, NotionError::Unauthorized));

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 403 Forbidden also maps to Unauthorized.
#[fcp_async_core::runtime::test]
async fn error_403_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("bad-token")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    assert!(matches!(err, NotionError::Unauthorized));
}

/// 404 Not Found maps to `NotionError::NotFound`.
#[fcp_async_core::runtime::test]
async fn error_404_maps_to_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "object": "error",
            "status": 404,
            "code": "object_not_found",
            "message": "Could not find page"
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("missing").await.unwrap_err();

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::ResourceNotFound { .. }),
        "expected ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    assert!(err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::RateLimited { .. }),
        "expected RateLimited, got: {fcp_err:?}"
    );
}

/// 500 Server Error is retryable.
#[fcp_async_core::runtime::test]
async fn error_500_server_is_retryable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    assert!(err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::External {
                retryable: true,
                ..
            }
        ),
        "expected External retryable, got: {fcp_err:?}"
    );
}

/// Resource not found via error enum.
#[test]
fn error_not_found_maps_correctly() {
    let err = NotionError::NotFound {
        resource: "page:abc-123".into(),
    };
    assert!(!err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, FcpError::ResourceNotFound { .. }));
}

/// Validation error maps to `InvalidRequest`.
#[test]
fn error_validation_maps_to_invalid_request() {
    let err = NotionError::Validation {
        message: "Title is required".into(),
    };
    assert!(!err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::InvalidRequest { .. }),
        "expected InvalidRequest, got: {fcp_err:?}"
    );
}

// ============================================================================
// Redaction tests
// ============================================================================

/// Integration token should not appear in error messages.
#[fcp_async_core::runtime::test]
async fn redaction_token_not_in_error_message() {
    let mock_server = MockServer::start().await;
    let secret = "ntn_SuperSecretIntegrationTokenThatShouldNotLeak";

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new(secret)
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_page("page-1").await.unwrap_err();
    let err_string = format!("{err:?}");
    assert!(
        !err_string.contains(secret),
        "Token should not appear in error debug output"
    );

    let fcp_err = err.to_fcp_error();
    let fcp_err_string = format!("{fcp_err:?}");
    assert!(
        !fcp_err_string.contains(secret),
        "Token should not appear in FCP error debug output"
    );
}

/// Token is sent as Bearer auth header.
#[fcp_async_core::runtime::test]
async fn token_sent_as_bearer_auth() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("authorization", "Bearer ntn_test_auth"))
        .and(header("notion-version", DEFAULT_NOTION_VERSION))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test_auth")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let result = client.search(None, None).await.unwrap();
    assert!(result.results.is_empty());
}

// ============================================================================
// Client operation tests
// ============================================================================

/// `get_page` returns a parsed page.
#[fcp_async_core::runtime::test]
async fn get_page_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/page-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("page-42", "My Page")))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let page = client.get_page("page-42").await.unwrap();
    assert_eq!(page.id, "page-42");
}

/// `create_page` returns the created page.
#[fcp_async_core::runtime::test]
async fn create_page_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("page-new", "New Page")))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let page = client
        .create_page(json!({
            "parent": { "database_id": "db-1" },
            "properties": { "title": { "title": [{ "text": { "content": "New Page" } }] } }
        }))
        .await
        .unwrap();
    assert_eq!(page.id, "page-new");
}

/// `update_page` returns the updated page.
#[fcp_async_core::runtime::test]
async fn update_page_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/pages/page-42"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_json("page-42", "Updated Title")),
        )
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let page = client
        .update_page("page-42", json!({ "properties": {} }))
        .await
        .unwrap();
    assert_eq!(page.id, "page-42");
}

/// `delete_page` archives the page.
#[fcp_async_core::runtime::test]
async fn delete_page_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/pages/page-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json({
            let mut p = page_json("page-42", "Archived");
            p["archived"] = json!(true);
            p
        }))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let page = client.delete_page("page-42").await.unwrap();
    assert_eq!(page.id, "page-42");
}

/// `query_database` returns paginated results.
#[fcp_async_core::runtime::test]
async fn query_database_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/databases/db-1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                page_json("page-1", "Result 1"),
                page_json("page-2", "Result 2")
            ],
            "has_more": true,
            "next_cursor": "cursor-abc"
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client.query_database("db-1", None, None).await.unwrap();
    assert_eq!(result.results.len(), 2);
    assert!(result.has_more);
    assert_eq!(result.next_cursor.as_deref(), Some("cursor-abc"));
}

/// `search` returns results.
#[fcp_async_core::runtime::test]
async fn search_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [page_json("page-found", "Found")],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client.search(Some("test"), None).await.unwrap();
    assert_eq!(result.results.len(), 1);
    assert!(!result.has_more);
}

/// `get_block_children` returns block list.
#[fcp_async_core::runtime::test]
async fn get_block_children_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/blocks/block-1/children"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                { "object": "block", "id": "child-1", "type": "paragraph" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client.get_block_children("block-1").await.unwrap();
    assert_eq!(result.results.len(), 1);
}

/// `list_comments` returns comments.
#[fcp_async_core::runtime::test]
async fn list_comments_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                { "object": "comment", "id": "cmt-1" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = NotionClient::new("ntn_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client.list_comments("block-1").await.unwrap();
    assert_eq!(result.results.len(), 1);
}

// ============================================================================
// Connector-level invoke tests
// ============================================================================

/// Invoke `notion.search` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_search_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [page_json("pg-1", "Found Page")],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.search"]).await;
    let token = generate_valid_token(&signing_key, "notion.search", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.search",
            "input": { "query": "test" },
            "capability_token": token
        }))
        .await
        .unwrap();

    let results = result["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
}

/// Invoke `notion.get_page` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_page_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/pages/pg-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("pg-42", "My Page")))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.get_page"]).await;
    let token = generate_valid_token(&signing_key, "notion.get_page", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.get_page",
            "input": { "page_id": "pg-42" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["page"]["id"], "pg-42");
}

/// Invoke `notion.query_database` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_query_database_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/databases/db-1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [page_json("pg-r1", "Row 1")],
            "has_more": false,
            "next_cursor": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.query_database"]).await;
    let token = generate_valid_token(&signing_key, "notion.query_database", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.query_database",
            "input": { "database_id": "db-1" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["results"].as_array().unwrap().len(), 1);
    assert_eq!(result["has_more"], false);
}

/// Invoke `notion.create_page` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_create_page_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/pages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("pg-new", "New Page")))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.create_page"]).await;
    let token = generate_valid_token(&signing_key, "notion.create_page", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.create_page",
            "input": {
                "parent": { "database_id": "db-1" },
                "properties": { "Name": { "title": [{ "text": { "content": "New Page" } }] } }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["page"]["id"], "pg-new");
}

/// Invoke `notion.update_page` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_update_page_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/pages/pg-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_json("pg-42", "Updated Title")))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.update_page"]).await;
    let token = generate_valid_token(&signing_key, "notion.update_page", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.update_page",
            "input": {
                "page_id": "pg-42",
                "properties": { "Status": { "select": { "name": "Done" } } }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["page"]["id"], "pg-42");
}

/// Invoke `notion.delete_page` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_delete_page_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/pages/pg-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json({
            let mut p = page_json("pg-42", "Archived");
            p["archived"] = json!(true);
            p
        }))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.delete_page"]).await;
    let token = generate_valid_token(&signing_key, "notion.delete_page", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.delete_page",
            "input": { "page_id": "pg-42" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["page"]["id"], "pg-42");
}

/// Invoke `notion.get_database` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_database_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/databases/db-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "db-1",
            "object": "database",
            "title": [{"text": {"content": "Tasks"}, "plain_text": "Tasks"}],
            "properties": { "Name": {"type": "title", "title": {}} }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.get_database"]).await;
    let token = generate_valid_token(&signing_key, "notion.get_database", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.get_database",
            "input": { "database_id": "db-1" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["database"]["id"], "db-1");
    assert_eq!(result["database"]["object"], "database");
}

/// Invoke `notion.create_database` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_create_database_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/databases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "db-new",
            "object": "database",
            "title": [{"text": {"content": "New DB"}, "plain_text": "New DB"}],
            "properties": { "Name": {"type": "title", "title": {}} }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.create_database"]).await;
    let token = generate_valid_token(&signing_key, "notion.create_database", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.create_database",
            "input": {
                "parent": { "page_id": "pg-1" },
                "title": [{ "text": { "content": "New DB" } }],
                "properties": { "Name": { "title": {} } }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["database"]["id"], "db-new");
}

/// Invoke `notion.update_database` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_update_database_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/databases/db-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "db-1",
            "object": "database",
            "title": [{"text": {"content": "Updated"}, "plain_text": "Updated"}],
            "properties": { "Name": {"type": "title", "title": {}} }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.update_database"]).await;
    let token = generate_valid_token(&signing_key, "notion.update_database", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.update_database",
            "input": {
                "database_id": "db-1",
                "title": [{ "text": { "content": "Updated" } }]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["database"]["id"], "db-1");
}

/// Invoke `notion.get_block` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_block_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/blocks/blk-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "blk-1",
            "object": "block",
            "type": "paragraph",
            "has_children": false,
            "paragraph": {
                "rich_text": [{"text": {"content": "Hello"}, "plain_text": "Hello"}]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.get_block"]).await;
    let token = generate_valid_token(&signing_key, "notion.get_block", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.get_block",
            "input": { "block_id": "blk-1" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["block"]["id"], "blk-1");
    assert_eq!(result["block"]["type"], "paragraph");
}

/// Invoke `notion.update_block` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_update_block_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/blocks/blk-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "blk-1",
            "object": "block",
            "type": "paragraph",
            "paragraph": {
                "rich_text": [{"text": {"content": "Updated"}, "plain_text": "Updated"}]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.update_block"]).await;
    let token = generate_valid_token(&signing_key, "notion.update_block", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.update_block",
            "input": {
                "block_id": "blk-1",
                "paragraph": { "rich_text": [{ "text": { "content": "Updated" } }] }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["block"]["id"], "blk-1");
}

/// Invoke `notion.delete_block` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_delete_block_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/blocks/blk-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "blk-1",
            "object": "block",
            "type": "paragraph",
            "archived": true
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.delete_block"]).await;
    let token = generate_valid_token(&signing_key, "notion.delete_block", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.delete_block",
            "input": { "block_id": "blk-1" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["block"]["id"], "blk-1");
}

/// Invoke `notion.get_block_children` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_block_children_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/blocks/blk-1/children"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                { "object": "block", "id": "child-1", "type": "paragraph" },
                { "object": "block", "id": "child-2", "type": "heading_1" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.get_block_children"]).await;
    let token = generate_valid_token(&signing_key, "notion.get_block_children", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.get_block_children",
            "input": { "block_id": "blk-1" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["results"].as_array().unwrap().len(), 2);
    assert_eq!(result["has_more"], false);
}

/// Invoke `notion.append_blocks` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_append_blocks_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/blocks/blk-1/children"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                { "object": "block", "id": "new-blk-1", "type": "paragraph" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.append_blocks"]).await;
    let token = generate_valid_token(&signing_key, "notion.append_blocks", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.append_blocks",
            "input": {
                "block_id": "blk-1",
                "children": [
                    {
                        "object": "block",
                        "type": "paragraph",
                        "paragraph": {
                            "rich_text": [{ "text": { "content": "Hello world" } }]
                        }
                    }
                ]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["results"].as_array().unwrap().len(), 1);
}

/// Invoke `notion.add_comment` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_add_comment_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "comment",
            "id": "cmt-new",
            "parent": { "page_id": "pg-1" },
            "rich_text": [{ "text": { "content": "Looks good!" }, "plain_text": "Looks good!" }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.add_comment"]).await;
    let token = generate_valid_token(&signing_key, "notion.add_comment", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.add_comment",
            "input": {
                "parent": { "page_id": "pg-1" },
                "rich_text": [{ "text": { "content": "Looks good!" } }]
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["comment"]["id"], "cmt-new");
}

/// Invoke `notion.list_comments` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_list_comments_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                { "object": "comment", "id": "cmt-1" },
                { "object": "comment", "id": "cmt-2" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.list_comments"]).await;
    let token = generate_valid_token(&signing_key, "notion.list_comments", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.list_comments",
            "input": { "block_id": "pg-1" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["results"].as_array().unwrap().len(), 2);
    assert_eq!(result["has_more"], false);
}

/// Wrong capability token is rejected.
#[fcp_async_core::runtime::test]
async fn wrong_capability_rejected() {
    let mock_server = MockServer::start().await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.search"]).await;
    let token = generate_valid_token(&signing_key, "notion.search", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.get_page",
            "input": { "page_id": "pg-1" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject mismatched capability");
}

/// Missing required field returns `InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn missing_required_field_returns_invalid_request() {
    let mock_server = MockServer::start().await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.get_page"]).await;
    let token = generate_valid_token(&signing_key, "notion.get_page", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.get_page",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing page_id"
    );
}

/// Unknown operation is rejected.
#[fcp_async_core::runtime::test]
async fn unknown_operation_rejected() {
    let mock_server = MockServer::start().await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "notion.nonexistent", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Search sensitivity tests (u56.4)
// ============================================================================

/// Search results include provenance and taint metadata.
#[fcp_async_core::runtime::test]
async fn search_includes_sensitivity_metadata() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [page_json("pg-1", "Sensitive Doc")],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.search"]).await;
    let token = generate_valid_token(&signing_key, "notion.search", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.search",
            "input": { "query": "sensitive" },
            "capability_token": token
        }))
        .await
        .unwrap();

    // Verify sensitivity metadata
    assert_eq!(result["sensitivity"], "workspace_wide");
    assert_eq!(result["provenance"]["source"], "notion.search");
    assert_eq!(result["provenance"]["scope"], "workspace");

    let taint = result["taint"].as_array().unwrap();
    assert!(taint.iter().any(|t| t == "external_input"));
    assert!(taint.iter().any(|t| t == "cross_workspace"));

    assert_eq!(result["result_count"], 1);
}

/// Search with filter restricting to pages only.
#[fcp_async_core::runtime::test]
async fn search_with_filter() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [
                page_json("pg-1", "Page Result"),
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.search"]).await;
    let token = generate_valid_token(&signing_key, "notion.search", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.search",
            "input": {
                "query": "meeting",
                "filter": { "value": "page", "property": "object" }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["results"].as_array().unwrap().len(), 1);
    assert_eq!(result["has_more"], false);
}

/// Search with empty results.
#[fcp_async_core::runtime::test]
async fn search_empty_results() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.search"]).await;
    let token = generate_valid_token(&signing_key, "notion.search", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.search",
            "input": { "query": "nonexistent" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["results"].as_array().unwrap().len(), 0);
    assert_eq!(result["result_count"], 0);
    assert_eq!(result["sensitivity"], "workspace_wide");
}

/// Search redacts person email addresses from results.
#[fcp_async_core::runtime::test]
async fn search_redacts_person_emails() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [{
                "object": "page",
                "id": "pg-pii",
                "properties": {
                    "Assignee": {
                        "type": "people",
                        "people": [{
                            "object": "user",
                            "id": "user-1",
                            "name": "Alice",
                            "person": { "email": "alice@example.com" }
                        }]
                    },
                    "Title": {
                        "type": "title",
                        "title": [{ "text": { "content": "Secret Doc" } }]
                    }
                },
                "created_by": {
                    "object": "user",
                    "id": "user-1",
                    "name": "Alice",
                    "person": { "email": "alice@example.com" }
                },
                "last_edited_by": {
                    "object": "user",
                    "id": "user-2",
                    "name": "Bob",
                    "person": { "email": "bob@example.com" }
                }
            }],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.search"]).await;
    let token = generate_valid_token(&signing_key, "notion.search", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.search",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    let results = result["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);

    let page = &results[0];

    // Person property emails should be redacted
    let assignee_email = &page["properties"]["Assignee"]["people"][0]["person"]["email"];
    assert_eq!(assignee_email, "[redacted]");

    // created_by email should be redacted
    let created_email = &page["created_by"]["person"]["email"];
    assert_eq!(created_email, "[redacted]");

    // last_edited_by email should be redacted
    let edited_email = &page["last_edited_by"]["person"]["email"];
    assert_eq!(edited_email, "[redacted]");

    // Non-PII fields preserved
    assert_eq!(page["id"], "pg-pii");
    assert_eq!(page["created_by"]["name"], "Alice");
}

/// Search with `notion.read` capability is rejected — requires `notion.search`.
#[fcp_async_core::runtime::test]
async fn search_requires_search_capability() {
    let mock_server = MockServer::start().await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.read"]).await;
    let token = generate_valid_token(&signing_key, "notion.read", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.search",
            "input": { "query": "test" },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "notion.read should not grant access to search"
    );
}

/// Search with `created_by`/`last_edited_by` redaction on type variants.
#[fcp_async_core::runtime::test]
async fn search_redacts_created_by_last_edited_by_property_types() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [{
                "object": "page",
                "id": "pg-prop",
                "properties": {
                    "Creator": {
                        "type": "created_by",
                        "created_by": {
                            "object": "user",
                            "id": "user-3",
                            "name": "Carol",
                            "person": { "email": "carol@example.com" }
                        }
                    },
                    "Editor": {
                        "type": "last_edited_by",
                        "last_edited_by": {
                            "object": "user",
                            "id": "user-4",
                            "name": "Dave",
                            "person": { "email": "dave@example.com" }
                        }
                    }
                }
            }],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = NotionConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["notion.search"]).await;
    let token = generate_valid_token(&signing_key, "notion.search", &connector);

    let result = connector
        .handle_invoke(json!({
            "operation": "notion.search",
            "input": { "query": "prop test" },
            "capability_token": token
        }))
        .await
        .unwrap();

    let page = &result["results"][0];

    // created_by property type should have email redacted
    assert_eq!(
        page["properties"]["Creator"]["created_by"]["person"]["email"],
        "[redacted]"
    );
    // last_edited_by property type should have email redacted
    assert_eq!(
        page["properties"]["Editor"]["last_edited_by"]["person"]["email"],
        "[redacted]"
    );
    // Names preserved
    assert_eq!(page["properties"]["Creator"]["created_by"]["name"], "Carol");
    assert_eq!(
        page["properties"]["Editor"]["last_edited_by"]["name"],
        "Dave"
    );
}

// ============================================================================
// Replay safety on retry (br-kxd3e)
// ============================================================================
//
// Notion is the connector where BOTH directions of the "verb decides nothing"
// trap appear in one client:
//
//   - `/search` and `/databases/{id}/query` are POSTs that only READ, so
//     refusing their retries would be a pure availability loss.
//   - `PATCH /blocks/{id}/children` APPENDS, so it is a PATCH that is NOT
//     idempotent — replaying it adds the blocks a second time.
//
// The three tests below pin one case each.

fn retrying_client(mock_server: &MockServer) -> NotionClient {
    NotionClient::new("test-token")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(3)
}

#[fcp_async_core::runtime::test]
async fn create_page_is_not_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/pages"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let result = retrying_client(&mock_server)
        .create_page(json!({ "parent": { "page_id": "p" } }))
        .await;
    assert!(result.is_err());

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a 503 means Notion received the create — retrying makes a SECOND page"
    );
}

#[fcp_async_core::runtime::test]
async fn append_blocks_is_not_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/v1/blocks/block-1/children"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&mock_server)
        .await;

    let result = retrying_client(&mock_server)
        .append_blocks("block-1", json!([{ "type": "paragraph" }]))
        .await;
    assert!(result.is_err());

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "this PATCH APPENDS rather than setting state, so it is not idempotent \
         despite the verb — a retry adds the blocks twice"
    );
}

#[fcp_async_core::runtime::test]
async fn search_is_still_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "results": [],
            "has_more": false,
            "next_cursor": null
        })))
        .mount(&mock_server)
        .await;

    retrying_client(&mock_server)
        .search(Some("q"), None)
        .await
        .expect("search only reads, so the retry must be preserved");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "Notion models search as a POST but it only reads — refusing this \
         retry would cost availability for no safety gain"
    );
}
