//! Zendesk connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the Zendesk API.
//! No real API calls. Covers:
//! - Happy-path operations (tickets, search, comments, articles, macros)
//! - Error taxonomy (401/404/429/500)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, introspect, shutdown)
//! - Input validation (missing required fields)

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_zendesk::connector::ZendeskConnector;

// ============================================================================
// Helpers
// ============================================================================

/// Generate a valid COSE capability token signed by the given key.
fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &str,
) -> fcp_core::CapabilityToken {
    let cap = match op {
        "zendesk.create_ticket" | "zendesk.update_ticket" | "zendesk.apply_macro" => {
            "zendesk.write"
        }
        "zendesk.delete_ticket" => "zendesk.delete",
        _ => "zendesk.read",
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
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

/// Perform handshake on a connector, returning the signing key for token generation.
async fn setup_handshake(connector: &mut ZendeskConnector, caps: &[&str]) -> Ed25519SigningKey {
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

/// Configure connector with a mock server URL.
async fn setup_configure(connector: &mut ZendeskConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "subdomain": "testco",
            "email": "agent@testco.com",
            "api_token": "test-api-token-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_create_ticket() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-create-ticket");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v2/tickets.json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "ticket": {
                "id": 42,
                "subject": "Login broken after update",
                "status": "new",
                "priority": "high",
                "requester_id": 1001
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.create_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.create_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.create_ticket",
            "input": {
                "subject": "Login broken after update",
                "description": "Cannot log in since the 2.0 update",
                "priority": "high",
                "type": "problem"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["ticket"]["id"], 42);
    assert_eq!(result["ticket"]["subject"], "Login broken after update");
    assert_eq!(result["ticket"]["priority"], "high");
}

#[fcp_async_core::runtime::test]
async fn test_get_ticket() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-get-ticket");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/123.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ticket": {
                "id": 123,
                "subject": "Password reset help",
                "status": "open",
                "priority": "normal",
                "tags": ["password", "account"]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 123 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["ticket"]["id"], 123);
    assert_eq!(result["ticket"]["status"], "open");
    assert_eq!(result["ticket"]["tags"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn test_update_ticket() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-update-ticket");
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/api/v2/tickets/123.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ticket": {
                "id": 123,
                "subject": "Password reset help",
                "status": "solved",
                "priority": "normal"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.update_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.update_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.update_ticket",
            "input": {
                "ticket_id": 123,
                "status": "solved",
                "comment": { "body": "Issue resolved.", "public": true }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["ticket"]["id"], 123);
    assert_eq!(result["ticket"]["status"], "solved");
}

#[fcp_async_core::runtime::test]
async fn test_delete_ticket() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-delete-ticket");
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/api/v2/tickets/999.json"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.delete_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.delete_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.delete_ticket",
            "input": { "ticket_id": 999 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn test_search_tickets() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-search-tickets");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/search.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                { "id": 1, "subject": "Urgent: Server down" },
                { "id": 2, "subject": "Performance degraded" }
            ],
            "count": 2,
            "next_page": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.search_tickets"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.search_tickets");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.search_tickets",
            "input": {
                "query": "status:open priority:urgent",
                "sort_by": "created_at",
                "sort_order": "desc"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["count"], 2);
    let results = result["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["subject"], "Urgent: Server down");
}

#[fcp_async_core::runtime::test]
async fn test_list_ticket_comments() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-list-comments");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/123/comments.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "comments": [
                { "id": 1, "body": "Customer: I cannot log in", "public": true, "author_id": 1001 },
                { "id": 2, "body": "Agent: Please try clearing cache", "public": true, "author_id": 2001 }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.list_ticket_comments"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(
        &key,
        connector.instance_id(),
        "zendesk.list_ticket_comments",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.list_ticket_comments",
            "input": { "ticket_id": 123, "sort_order": "asc" },
            "capability_token": token
        }))
        .await
        .unwrap();

    let comments = result["comments"].as_array().unwrap();
    assert_eq!(comments.len(), 2);
    assert_eq!(comments[0]["author_id"], 1001);
}

#[fcp_async_core::runtime::test]
async fn test_search_articles() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-search-articles");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/help_center/articles/search.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                { "id": 360_001_234_567_i64, "title": "How to Reset Your Password", "locale": "en-us" }
            ],
            "count": 1
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.search_articles"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.search_articles");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.search_articles",
            "input": { "query": "password reset", "locale": "en-us" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["count"], 1);
    let articles = result["results"].as_array().unwrap();
    assert_eq!(articles[0]["title"], "How to Reset Your Password");
}

#[fcp_async_core::runtime::test]
async fn test_get_article() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-get-article");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/help_center/articles/100.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "article": {
                "id": 100,
                "title": "Password Reset Guide",
                "body": "<p>To reset your password, go to Settings...</p>",
                "locale": "en-us"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_article"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.get_article");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_article",
            "input": { "article_id": 100 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["article"]["id"], 100);
    assert_eq!(result["article"]["title"], "Password Reset Guide");
}

#[fcp_async_core::runtime::test]
async fn test_apply_macro() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-apply-macro");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/123/macros/456/apply.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {
                "ticket": {
                    "id": 123,
                    "status": "solved",
                    "comment": { "body": "Resolved via macro" }
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.apply_macro"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.apply_macro");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.apply_macro",
            "input": { "ticket_id": 123, "macro_id": 456 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(result["result"]["ticket"].is_object());
    assert_eq!(result["result"]["ticket"]["status"], "solved");
}

// ============================================================================
// Error taxonomy
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_error_401_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-error-401");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/1.json"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "Couldn't authenticate you"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 1 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::Unauthorized { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn test_error_404_not_found() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-error-404");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/999_999.json"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "RecordNotFound",
            "description": "Not found"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 999_999 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::ResourceNotFound { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn test_error_429_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-error-429");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/1.json"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 1 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::RateLimited { .. })
            || matches!(err, fcp_core::FcpError::UpstreamTimeout { .. })
            || matches!(err, fcp_core::FcpError::External { .. }),
        "expected RateLimited, UpstreamTimeout, or External after 429 retry exhaustion, got: {err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn test_error_500_server_error() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-error-500");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v2/tickets.json"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.create_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.create_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.create_ticket",
            "input": { "subject": "Test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::External {
            retryable, service, ..
        } => {
            assert!(retryable);
            assert_eq!(service, "zendesk");
        }
        e => panic!("Expected External(retryable), got: {e:?}"),
    }
}

// ============================================================================
// FCP2 default-deny
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_invoke_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-not-configured");

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    // Skip configure

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": { "ticket_id": 1 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::NotConfigured
    ));
}

#[fcp_async_core::runtime::test]
async fn test_invoke_wrong_capability() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-wrong-capability");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    // Try to invoke create_ticket with a get_ticket token
    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.create_ticket",
            "input": { "subject": "Sneaky ticket" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn test_invoke_unknown_operation() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-unknown-operation");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.nonexistent"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::OperationNotGranted { operation } => {
            assert_eq!(operation, "zendesk.nonexistent");
        }
        e => panic!("Expected OperationNotGranted, got: {e:?}"),
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-health-not-configured");
    let connector = ZendeskConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn test_health_configured() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-health-configured");
    let mut connector = ZendeskConnector::new();
    setup_configure(&mut connector, "https://testco.zendesk.com/api/v2").await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn test_introspect_operations() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-introspect");
    let connector = ZendeskConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 14);

    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
    assert!(op_ids.contains(&"zendesk.create_ticket"));
    assert!(op_ids.contains(&"zendesk.get_ticket"));
    assert!(op_ids.contains(&"zendesk.update_ticket"));
    assert!(op_ids.contains(&"zendesk.delete_ticket"));
    assert!(op_ids.contains(&"zendesk.search_tickets"));
    assert!(op_ids.contains(&"zendesk.list_ticket_comments"));
    assert!(op_ids.contains(&"zendesk.search_articles"));
    assert!(op_ids.contains(&"zendesk.get_article"));
    assert!(op_ids.contains(&"zendesk.search_users"));
    assert!(op_ids.contains(&"zendesk.apply_macro"));
    assert!(op_ids.contains(&"zendesk.sla.policies"));
    assert!(op_ids.contains(&"zendesk.sla.ticket_status"));
    assert!(op_ids.contains(&"zendesk.analytics.ticket_metrics"));
    assert!(op_ids.contains(&"zendesk.analytics.satisfaction_ratings"));
}

#[fcp_async_core::runtime::test]
async fn test_shutdown() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-shutdown");
    let connector = ZendeskConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Input validation
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_create_ticket_missing_subject() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-missing-subject");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.create_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.create_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.create_ticket",
            "input": { "priority": "high" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("subject"));
        }
        e => panic!("Expected InvalidRequest about 'subject', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_get_ticket_missing_ticket_id() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-missing-ticket-id");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.get_ticket"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.get_ticket");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.get_ticket",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("ticket_id"));
        }
        e => panic!("Expected InvalidRequest about 'ticket_id', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_search_tickets_missing_query() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-missing-query");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.search_tickets"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.search_tickets");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.search_tickets",
            "input": { "sort_by": "created_at" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("query"));
        }
        e => panic!("Expected InvalidRequest about 'query', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_apply_macro_missing_macro_id() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-missing-macro-id");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.apply_macro"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.apply_macro");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.apply_macro",
            "input": { "ticket_id": 123 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("macro_id"));
        }
        e => panic!("Expected InvalidRequest about 'macro_id', got: {e:?}"),
    }
}

// ============================================================================
// SLA Tracking operations
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_list_sla_policies() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-list-sla-policies");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/slas/policies.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sla_policies": [
                {
                    "id": 1,
                    "title": "Urgent SLA",
                    "filter": { "all": [{ "field": "priority", "operator": "is", "value": "urgent" }] },
                    "policy_metrics": [
                        { "priority": "urgent", "metric": "first_reply_time", "target": 60, "business_hours": false }
                    ]
                },
                {
                    "id": 2,
                    "title": "High Priority SLA",
                    "policy_metrics": [
                        { "priority": "high", "metric": "first_reply_time", "target": 240, "business_hours": true }
                    ]
                }
            ],
            "count": 2
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.sla.policies"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.sla.policies");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.sla.policies",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    let policies = result["sla_policies"].as_array().unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0]["title"], "Urgent SLA");
    assert_eq!(policies[1]["title"], "High Priority SLA");
}

#[fcp_async_core::runtime::test]
async fn test_get_ticket_sla() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-get-ticket-sla");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v2/tickets/456/metrics.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ticket_metric": {
                "id": 9001,
                "ticket_id": 456,
                "reply_time_in_minutes": { "calendar": 15, "business": 10 },
                "first_resolution_time_in_minutes": { "calendar": 120, "business": 60 },
                "full_resolution_time_in_minutes": { "calendar": 240, "business": 120 },
                "agent_wait_time_in_minutes": { "calendar": 5, "business": 3 }
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.sla.ticket_status"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.sla.ticket_status");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.sla.ticket_status",
            "input": { "ticket_id": 456 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["ticket_metric"]["ticket_id"], 456);
    assert_eq!(
        result["ticket_metric"]["reply_time_in_minutes"]["calendar"],
        15
    );
    assert_eq!(
        result["ticket_metric"]["first_resolution_time_in_minutes"]["business"],
        60
    );
}

#[fcp_async_core::runtime::test]
async fn test_get_ticket_sla_missing_ticket_id() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-sla-missing-ticket-id");
    let mock_server = MockServer::start().await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.sla.ticket_status"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(&key, connector.instance_id(), "zendesk.sla.ticket_status");
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.sla.ticket_status",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("ticket_id"));
        }
        e => panic!("Expected InvalidRequest about 'ticket_id', got: {e:?}"),
    }
}

// ============================================================================
// Analytics operations
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_list_ticket_metrics() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-list-ticket-metrics");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ticket_metrics": [
                { "id": 1, "ticket_id": 100, "reply_time_in_minutes": { "calendar": 30 } },
                { "id": 2, "ticket_id": 101, "reply_time_in_minutes": { "calendar": 45 } },
                { "id": 3, "ticket_id": 102, "reply_time_in_minutes": { "calendar": 10 } }
            ],
            "count": 3
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.analytics.ticket_metrics"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(
        &key,
        connector.instance_id(),
        "zendesk.analytics.ticket_metrics",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.analytics.ticket_metrics",
            "input": { "page_size": 100 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["count"], 3);
    let metrics = result["ticket_metrics"].as_array().unwrap();
    assert_eq!(metrics.len(), 3);
    assert_eq!(metrics[0]["ticket_id"], 100);
}

#[fcp_async_core::runtime::test]
async fn test_list_satisfaction_ratings() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-list-satisfaction-ratings");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "satisfaction_ratings": [
                { "id": 1, "score": "good", "comment": "Great support!", "ticket_id": 100 },
                { "id": 2, "score": "good", "comment": "Quick resolution", "ticket_id": 101 }
            ],
            "count": 2
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.analytics.satisfaction_ratings"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(
        &key,
        connector.instance_id(),
        "zendesk.analytics.satisfaction_ratings",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.analytics.satisfaction_ratings",
            "input": { "score": "good", "page_size": 100 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["count"], 2);
    let ratings = result["satisfaction_ratings"].as_array().unwrap();
    assert_eq!(ratings.len(), 2);
    assert_eq!(ratings[0]["score"], "good");
    assert_eq!(ratings[0]["comment"], "Great support!");
}

#[fcp_async_core::runtime::test]
async fn test_list_satisfaction_ratings_no_filter() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-satisfaction-no-filter");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "satisfaction_ratings": [
                { "id": 1, "score": "good", "ticket_id": 100 },
                { "id": 2, "score": "bad", "ticket_id": 101 },
                { "id": 3, "score": "offered", "ticket_id": 102 }
            ],
            "count": 3
        })))
        .mount(&mock_server)
        .await;

    let mut connector = ZendeskConnector::new();
    let key = setup_handshake(&mut connector, &["zendesk.analytics.satisfaction_ratings"]).await;
    setup_configure(&mut connector, &format!("{}/api/v2", mock_server.uri())).await;

    let token = generate_valid_token(
        &key,
        connector.instance_id(),
        "zendesk.analytics.satisfaction_ratings",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "zendesk.analytics.satisfaction_ratings",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["count"], 3);
    let ratings = result["satisfaction_ratings"].as_array().unwrap();
    assert_eq!(ratings.len(), 3);
}

// ============================================================================
// Replay safety on retry (br-kxd3e)
// ============================================================================
//
// Zendesk has no idempotency key wired here, so a 5xx retry on create_ticket
// files a second support ticket. The assertion is the REQUEST COUNT.

#[fcp_async_core::runtime::test]
async fn create_ticket_is_not_retried_after_a_5xx() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-create-ticket-replay-safety");
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tickets.json"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let client = fcp_zendesk::client::ZendeskClient::new("testco", "agent@testco.com", "tok")
        .unwrap()
        .with_base_url(&mock_server.uri())
        .with_retry_config(3);

    let result = client
        .create_ticket(&json!({ "subject": "help", "comment": { "body": "x" } }))
        .await;
    assert!(result.is_err());

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a 503 means Zendesk received the create — retrying files a SECOND \
         support ticket"
    );
}

#[fcp_async_core::runtime::test]
async fn create_ticket_still_retries_a_429() {
    let _ctx = AsyncTestContext::for_scenario("zendesk-create-ticket-429");
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/tickets.json"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tickets.json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "ticket": { "id": 1, "subject": "help", "status": "new" }
        })))
        .mount(&mock_server)
        .await;

    let client = fcp_zendesk::client::ZendeskClient::new("testco", "agent@testco.com", "tok")
        .unwrap()
        .with_base_url(&mock_server.uri())
        .with_retry_config(3);

    client
        .create_ticket(&json!({ "subject": "help", "comment": { "body": "x" } }))
        .await
        .expect("a rate-limited create was refused without filing anything");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "429 means Zendesk did NOT file the ticket, so backoff must be preserved"
    );
}
