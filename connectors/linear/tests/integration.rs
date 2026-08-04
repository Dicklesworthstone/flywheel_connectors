//! Integration tests for the Linear connector.
//!
//! Covers the connector testing requirements (hwo.6):
//! - Error taxonomy mapping (`LinearError` -> `FcpError`)
//! - GraphQL request/response parsing
//! - Redaction (API key not leaked in error messages)
//! - Operation dispatch through connector
//! - Capability verification
//!
//! All tests are deterministic -- no real API calls.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError, InstanceId};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

use fcp_linear::{client::LinearClient, connector::LinearConnector, error::LinearError};

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    operation: &str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let capability = match operation {
        "linear.create_issue" | "linear.update_issue" | "linear.add_comment" => "linear.write",
        "linear.process_webhook" => "linear.process_webhook",
        _ => "linear.read",
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
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should be valid")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut LinearConnector, caps: &[&str]) -> Ed25519SigningKey {
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

async fn setup_configure(connector: &mut LinearConnector, graphql_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-linear-api-key",
            "api_url": graphql_url
        }))
        .await
        .expect("configure should succeed");
}

fn graphql_success(data: &serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({ "data": data }))
}

fn issue_json(id: &str, identifier: &str, title: &str) -> serde_json::Value {
    json!({
        "id": id,
        "identifier": identifier,
        "title": title,
        "state": { "id": "s1", "name": "In Progress" },
        "team": { "id": "t1", "name": "Engineering", "key": "ENG" }
    })
}

// ============================================================================
// Error taxonomy mapping tests
// ============================================================================

/// 401 Unauthorized maps to `LinearError::Unauthorized` -> `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("bad-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(0);

    let err = client.list_teams().await.unwrap_err();
    assert!(matches!(err, LinearError::Unauthorized));

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

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("bad-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(0);

    let err = client.list_teams().await.unwrap_err();
    assert!(matches!(err, LinearError::Unauthorized));
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(0);

    let err = client.list_teams().await.unwrap_err();
    assert!(err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::RateLimited { .. }),
        "expected RateLimited, got: {fcp_err:?}"
    );
}

/// 500 Server Error is retryable via `LinearError::Api`.
#[fcp_async_core::runtime::test]
async fn error_500_server_is_retryable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(0);

    let err = client.list_teams().await.unwrap_err();
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

/// Resource not found maps to `FcpError::ResourceNotFound`.
#[test]
fn error_not_found_maps_correctly() {
    let err = LinearError::NotFound {
        resource: "issue:LIN-999".into(),
    };
    assert!(!err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::ResourceNotFound { .. }),
        "expected ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 400 Bad Request is NOT retryable.
#[test]
fn error_400_not_retryable() {
    let err = LinearError::Api {
        message: "Bad Request".into(),
        status_code: Some(400),
    };
    assert!(!err.is_retryable());
}

/// `RateLimited` error carries correct `retry_after`.
#[test]
fn error_rate_limited_retry_after() {
    let err = LinearError::RateLimited {
        retry_after_ms: 60_000,
    };
    assert!(err.is_retryable());
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(60)));

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::RateLimited {
                retry_after_ms: 60_000,
                ..
            }
        ),
        "expected RateLimited with 60s, got: {fcp_err:?}"
    );
}

// ============================================================================
// GraphQL parsing tests
// ============================================================================

/// GraphQL errors in a 200 response are parsed correctly.
#[fcp_async_core::runtime::test]
async fn graphql_error_in_200_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "errors": [
                { "message": "Variable '$id' is not defined" },
                { "message": "Cannot query field 'foo'" }
            ]
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_issue("bad-id").await.unwrap_err();
    match &err {
        LinearError::Api { message, .. } => {
            assert!(message.contains("not defined"));
            assert!(message.contains("Cannot query"));
        }
        e => panic!("Expected Api error, got: {e:?}"),
    }
}

/// Empty data in GraphQL response returns an error.
#[fcp_async_core::runtime::test]
async fn graphql_empty_data_returns_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": null
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(0);

    let result = client.list_teams().await;
    assert!(result.is_err());
}

/// Issue not found returns `NotFound` when data.issue is null.
#[fcp_async_core::runtime::test]
async fn issue_not_found_returns_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({ "issue": null })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_issue("nonexistent").await.unwrap_err();
    assert!(matches!(err, LinearError::NotFound { .. }));
}

// ============================================================================
// Redaction tests
// ============================================================================

/// API key should not appear in error messages.
#[fcp_async_core::runtime::test]
async fn redaction_api_key_not_in_error_message() {
    let mock_server = MockServer::start().await;
    let secret_key = "lin_api_SuperSecretKeyThatShouldNotLeak12345";

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new(secret_key)
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(0);

    let err = client.list_teams().await.unwrap_err();
    let err_string = format!("{err:?}");
    assert!(
        !err_string.contains(secret_key),
        "API key should not appear in error debug output"
    );

    let fcp_err = err.to_fcp_error();
    let fcp_err_string = format!("{fcp_err:?}");
    assert!(
        !fcp_err_string.contains(secret_key),
        "API key should not appear in FCP error debug output"
    );
}

/// API key is sent as Bearer auth header.
#[fcp_async_core::runtime::test]
async fn api_key_sent_as_bearer_auth() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("authorization", "Bearer test-api-key"))
        .respond_with(graphql_success(&json!({
            "teams": { "nodes": [] }
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-api-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(0);

    let teams = client.list_teams().await.unwrap();
    assert!(teams.is_empty());
}

// ============================================================================
// Client operation tests via mock GraphQL
// ============================================================================

/// `get_issue` returns a parsed issue.
#[fcp_async_core::runtime::test]
async fn get_issue_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "issue": issue_json("issue-1", "LIN-42", "Fix the widget")
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()));

    let issue = client.get_issue("issue-1").await.unwrap();
    assert_eq!(issue.id, "issue-1");
    assert_eq!(issue.identifier, "LIN-42");
    assert_eq!(issue.title, "Fix the widget");
}

/// `create_issue` returns the created issue.
#[fcp_async_core::runtime::test]
async fn create_issue_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "issueCreate": {
                "success": true,
                "issue": issue_json("issue-new", "LIN-99", "New feature")
            }
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()));

    let issue = client
        .create_issue("New feature", "t1", Some("A description"))
        .await
        .unwrap();
    assert_eq!(issue.identifier, "LIN-99");
}

/// `update_issue` returns the updated issue.
#[fcp_async_core::runtime::test]
async fn update_issue_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "issueUpdate": {
                "success": true,
                "issue": issue_json("issue-1", "LIN-42", "Updated title")
            }
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()));

    let issue = client
        .update_issue("issue-1", Some("Updated title"), None, None)
        .await
        .unwrap();
    assert_eq!(issue.title, "Updated title");
}

/// `search_issues` returns matching issues.
#[fcp_async_core::runtime::test]
async fn search_issues_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "searchIssues": {
                "nodes": [
                    issue_json("i1", "LIN-1", "Login bug"),
                    issue_json("i2", "LIN-2", "Logout bug")
                ]
            }
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()));

    let issues = client.search_issues("bug").await.unwrap();
    assert_eq!(issues.len(), 2);
}

/// `list_teams` returns all teams.
#[fcp_async_core::runtime::test]
async fn list_teams_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "teams": {
                "nodes": [
                    { "id": "t1", "name": "Engineering", "key": "ENG" },
                    { "id": "t2", "name": "Design", "key": "DES" }
                ]
            }
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()));

    let teams = client.list_teams().await.unwrap();
    assert_eq!(teams.len(), 2);
    assert_eq!(teams[0].key, "ENG");
}

/// `list_cycles` returns cycles for a team.
#[fcp_async_core::runtime::test]
async fn list_cycles_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "team": {
                "cycles": {
                    "nodes": [
                        { "id": "c1", "number": 1, "name": "Sprint 1" }
                    ]
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()));

    let cycles = client.list_cycles("t1").await.unwrap();
    assert_eq!(cycles.len(), 1);
    assert_eq!(cycles[0].number, 1);
}

/// `add_comment` returns the created comment.
#[fcp_async_core::runtime::test]
async fn add_comment_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "commentCreate": {
                "success": true,
                "comment": {
                    "id": "comment-1",
                    "body": "Working on this",
                    "user": { "id": "u1", "name": "Agent" }
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()));

    let comment = client
        .add_comment("issue-1", "Working on this")
        .await
        .unwrap();
    assert_eq!(comment.id, "comment-1");
    assert_eq!(comment.body, "Working on this");
}

/// `list_projects` returns projects.
#[fcp_async_core::runtime::test]
async fn list_projects_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "projects": {
                "nodes": [
                    { "id": "p1", "name": "Q1 Goals" }
                ]
            }
        })))
        .mount(&mock_server)
        .await;

    let client = LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()));

    let projects = client.list_projects().await.unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "Q1 Goals");
}

// ============================================================================
// Connector-level invoke tests
// ============================================================================

/// Invoke `linear.list_teams` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_list_teams_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "teams": {
                "nodes": [
                    { "id": "t1", "name": "Engineering", "key": "ENG" }
                ]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = LinearConnector::new();
    setup_configure(&mut connector, &format!("{}/graphql", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["linear.list_teams"]).await;
    let token = generate_valid_token(&signing_key, "linear.list_teams", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.list_teams",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    let teams = result["teams"].as_array().unwrap();
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0]["key"], "ENG");
}

/// Invoke `linear.get_issue` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_issue_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "issue": issue_json("issue-42", "LIN-42", "Important bug")
        })))
        .mount(&mock_server)
        .await;

    let mut connector = LinearConnector::new();
    setup_configure(&mut connector, &format!("{}/graphql", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["linear.get_issue"]).await;
    let token = generate_valid_token(&signing_key, "linear.get_issue", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.get_issue",
            "input": { "issue_id": "issue-42" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["issue"]["identifier"], "LIN-42");
    assert_eq!(result["issue"]["title"], "Important bug");
}

/// Invoke `linear.create_issue` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_create_issue_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "issueCreate": {
                "success": true,
                "issue": issue_json("new-issue", "LIN-100", "Brand new")
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = LinearConnector::new();
    setup_configure(&mut connector, &format!("{}/graphql", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["linear.create_issue"]).await;
    let token = generate_valid_token(&signing_key, "linear.create_issue", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.create_issue",
            "input": { "title": "Brand new", "team_id": "t1" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["issue"]["identifier"], "LIN-100");
}

/// Invoke `linear.plan_sync` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_plan_sync_through_connector() {
    let mut connector = LinearConnector::new();
    let signing_key = setup_handshake(&mut connector, &["linear.plan_sync"]).await;
    let token = generate_valid_token(&signing_key, "linear.plan_sync", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.plan_sync",
            "input": {
                "planned_at": "2026-03-15T00:00:00Z",
                "policy": "prefer_freshest",
                "bead": {
                    "bead_id": "br-123",
                    "linear_issue_id": "lin-1",
                    "title": "New bead title",
                    "description": "Body",
                    "status": "open",
                    "priority": 1,
                    "updated_at": "2026-03-15T00:00:00Z"
                },
                "linear": {
                    "issue_id": "lin-1",
                    "identifier": "LIN-123",
                    "bead_id": "br-123",
                    "title": "Old linear title",
                    "description": "Body",
                    "status": "open",
                    "priority": 1,
                    "updated_at": "2026-03-14T23:00:00Z"
                }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["intent"]["operation"], "update_linear");
    assert_eq!(
        result["intent"]["plan"]["update_linear_fields"],
        json!(["title"])
    );
    assert!(
        result["intent"]["idempotency_key"]
            .as_str()
            .unwrap()
            .starts_with("fcp2:linear-sync:update_linear:")
    );
}

/// Invoke `linear.plan_sync` when provided snapshots disagree on linkage.
#[fcp_async_core::runtime::test]
async fn invoke_plan_sync_surfaces_linkage_conflict() {
    let mut connector = LinearConnector::new();
    let signing_key = setup_handshake(&mut connector, &["linear.plan_sync"]).await;
    let token = generate_valid_token(&signing_key, "linear.plan_sync", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.plan_sync",
            "input": {
                "planned_at": "2026-03-15T00:00:00Z",
                "policy": "prefer_bead",
                "bead": {
                    "bead_id": "br-123",
                    "linear_issue_id": "lin-other",
                    "title": "Current bead title",
                    "description": "Body",
                    "status": "open",
                    "priority": 1,
                    "updated_at": "2026-03-15T00:00:00Z"
                },
                "linear": {
                    "issue_id": "lin-1",
                    "identifier": "LIN-123",
                    "bead_id": "br-123",
                    "title": "Current linear title",
                    "description": "Body",
                    "status": "open",
                    "priority": 1,
                    "updated_at": "2026-03-14T23:00:00Z"
                }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["intent"]["operation"], "conflict");
    assert_eq!(result["intent"]["plan"]["update_linear_fields"], json!([]));
    assert_eq!(result["intent"]["plan"]["update_bead_fields"], json!([]));
    assert_eq!(result["intent"]["plan"]["conflicts"][0]["field"], "linkage");
    assert!(
        result["intent"]["idempotency_key"]
            .as_str()
            .unwrap()
            .starts_with("fcp2:linear-sync:conflict:")
    );
}

/// Invoke `linear.plan_sync` when only one side is provided but it already claims a link.
#[fcp_async_core::runtime::test]
async fn invoke_plan_sync_conflicts_on_single_sided_claimed_linkage() {
    let mut connector = LinearConnector::new();
    let signing_key = setup_handshake(&mut connector, &["linear.plan_sync"]).await;
    let token = generate_valid_token(&signing_key, "linear.plan_sync", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.plan_sync",
            "input": {
                "planned_at": "2026-03-15T00:00:00Z",
                "policy": "prefer_freshest",
                "bead": {
                    "bead_id": "br-123",
                    "linear_issue_id": "lin-1",
                    "title": "Current bead title",
                    "description": "Body",
                    "status": "open",
                    "priority": 1,
                    "updated_at": "2026-03-15T00:00:00Z"
                }
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["intent"]["operation"], "conflict");
    assert_eq!(result["intent"]["linear_issue_id"], "lin-1");
    assert_eq!(result["intent"]["plan"]["update_linear_fields"], json!([]));
    assert_eq!(result["intent"]["plan"]["update_bead_fields"], json!([]));
    assert_eq!(result["intent"]["plan"]["conflicts"][0]["field"], "linkage");
    assert_eq!(
        result["intent"]["plan"]["conflicts"][0]["linear_updated_at"],
        "unknown"
    );
}

/// Invoke `linear.add_comment` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_add_comment_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(graphql_success(&json!({
            "commentCreate": {
                "success": true,
                "comment": {
                    "id": "c1",
                    "body": "Done!",
                    "user": { "id": "u1", "name": "Agent" }
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = LinearConnector::new();
    setup_configure(&mut connector, &format!("{}/graphql", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["linear.add_comment"]).await;
    let token = generate_valid_token(&signing_key, "linear.add_comment", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.add_comment",
            "input": { "issue_id": "issue-1", "body": "Done!" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["comment"]["body"], "Done!");
}

/// Wrong capability token is rejected.
#[fcp_async_core::runtime::test]
async fn wrong_capability_rejected() {
    let mock_server = MockServer::start().await;

    let mut connector = LinearConnector::new();
    setup_configure(&mut connector, &format!("{}/graphql", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["linear.list_teams"]).await;
    let token = generate_valid_token(&signing_key, "linear.list_teams", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.get_issue",
            "input": { "issue_id": "LIN-1" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject mismatched capability");
}

/// Missing required field returns `InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn missing_required_field_returns_invalid_request() {
    let mock_server = MockServer::start().await;

    let mut connector = LinearConnector::new();
    setup_configure(&mut connector, &format!("{}/graphql", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["linear.create_issue"]).await;
    let token = generate_valid_token(&signing_key, "linear.create_issue", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.create_issue",
            "input": { "title": "Bug" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing team_id"
    );
}

/// Unknown operation is rejected.
#[fcp_async_core::runtime::test]
async fn unknown_operation_rejected() {
    let mock_server = MockServer::start().await;

    let mut connector = LinearConnector::new();
    setup_configure(&mut connector, &format!("{}/graphql", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["linear.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "linear.nonexistent", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "linear.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Replay safety on retry (br-kxd3e)
// ============================================================================
//
// Linear speaks GraphQL: every query AND every mutation is the same
// `POST /graphql` request. The HTTP verb therefore carries no information
// about whether a replay is safe, which makes this the clearest case in the
// sweep for gating on the OPERATION rather than on the transport.
//
// These two tests are a matched pair — identical mock, identical retry
// budget, different GraphQL document — so what they pin is exactly that
// distinction. A gate written at the helper level would make both behave the
// same and one of these would fail.

fn replay_test_client(mock_server: &MockServer) -> LinearClient {
    LinearClient::new("test-key")
        .unwrap()
        .with_api_url(&format!("{}/graphql", mock_server.uri()))
        .with_retry_config(3)
}

#[fcp_async_core::runtime::test]
async fn create_issue_mutation_is_not_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let result = replay_test_client(&mock_server)
        .create_issue("Test issue", "team-1", None)
        .await;
    assert!(result.is_err());

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a 503 means Linear received the issueCreate mutation — retrying files \
         a SECOND issue"
    );
}

#[fcp_async_core::runtime::test]
async fn list_teams_query_is_still_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "teams": { "nodes": [] } }
        })))
        .mount(&mock_server)
        .await;

    replay_test_client(&mock_server)
        .list_teams()
        .await
        .expect("a read-only query must keep its retry");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "the SAME endpoint and the SAME 503 — only the GraphQL document \
         differs, which is why the gate has to live at the operation"
    );
}
