//! Jira connector integration tests (flywheel_connectors-x9af.3).
//!
//! Deterministic integration tests using wiremock to mock the Jira REST API.
//! No real API calls. Covers:
//! - Issue CRUD (create, get, update, delete)
//! - JQL search with pagination
//! - Transitions (list + execute)
//! - Sprints (list + move)
//! - Comments (add + list)
//! - Attachments (base64 upload)
//! - Error taxonomy (401/404/429/500 → `FcpError` mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]

use base64::Engine;
use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_jira::client::JiraClient;
use fcp_jira::connector::JiraConnector;

// ============================================================================
// Helpers
// ============================================================================

/// Generate a valid COSE capability token signed by the given key.
fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &str,
    instance_id: &fcp_core::InstanceId,
) -> fcp_core::CapabilityToken {
    let cap = match op {
        "jira.create_issue"
        | "jira.update_issue"
        | "jira.transition_issue"
        | "jira.move_to_sprint"
        | "jira.add_comment"
        | "jira.add_attachment"
        | "jira.worklog.add"
        | "jira.worklog.update"
        | "jira.automation.rule.create"
        | "jira.automation.rule.update"
        | "jira.automation.rule.enable"
        | "jira.automation.rule.disable"
        | "jira.sync.push_bead" => "jira.write",
        "jira.delete_issue" | "jira.worklog.delete" | "jira.automation.rule.delete" => {
            "jira.delete"
        }
        _ => "jira.read",
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
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

/// Perform handshake on a connector, returning the signing key for token generation.
async fn setup_handshake(connector: &mut JiraConnector, caps: &[&str]) -> Ed25519SigningKey {
    setup_handshake_with_zone(connector, caps, None).await
}

/// Perform handshake with an optional persisted `zone_dir`.
async fn setup_handshake_with_zone(
    connector: &mut JiraConnector,
    caps: &[&str],
    zone_dir: Option<&str>,
) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "zone_dir": zone_dir,
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

/// Configure connector with mock server URL.
async fn setup_configure(connector: &mut JiraConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "domain": "test-org",
            "email": "user@example.com",
            "api_token": "test-token-xyz",
            "base_url": base_url,
            "agile_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

/// Standard Jira issue response.
fn jira_issue_response(id: &str, key: &str, summary: &str) -> serde_json::Value {
    json!({
        "id": id,
        "key": key,
        "self": format!("https://test-org.atlassian.net/rest/api/3/issue/{id}"),
        "fields": {
            "summary": summary,
            "status": { "name": "Open" },
            "issuetype": { "name": "Task" },
            "project": { "key": key.split('-').next().unwrap_or("PROJ") }
        }
    })
}

/// Jira API error response.
fn jira_error_response(messages: &[&str]) -> serde_json::Value {
    json!({
        "errorMessages": messages,
        "errors": {}
    })
}

fn simulate_request(
    operation: &str,
    input: &serde_json::Value,
    token: &fcp_core::CapabilityToken,
) -> serde_json::Value {
    json!({
        "type": "simulate",
        "id": "sim-test",
        "connector_id": "fcp.jira",
        "operation": operation,
        "zone_id": "z:work",
        "input": input,
        "capability_token": token
    })
}

// ============================================================================
// Issue CRUD Tests
// ============================================================================

/// Happy path: create issue returns key and id.
#[fcp_async_core::runtime::test]
async fn create_issue_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.create_issue.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-100",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10001"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.create_issue"]).await;
    let token = generate_valid_token(&signing_key, "jira.create_issue", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.create_issue",
            "input": {
                "project_key": "PROJ",
                "issue_type": "Task",
                "summary": "Test issue from FCP"
            },
            "capability_token": token
        }))
        .await
        .expect("create_issue should succeed");

    assert_eq!(result["key"], "PROJ-100");
    assert_eq!(result["id"], "10001");
}

/// Create issue with optional fields (description, priority, labels, assignee).
#[fcp_async_core::runtime::test]
async fn create_issue_with_optional_fields() {
    let _ctx = AsyncTestContext::for_scenario("jira.create_issue.optional_fields");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10002",
            "key": "PROJ-101",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10002"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.create_issue"]).await;
    let token = generate_valid_token(&signing_key, "jira.create_issue", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.create_issue",
            "input": {
                "project_key": "PROJ",
                "issue_type": "Bug",
                "summary": "Bug with all fields",
                "description": "A detailed bug description",
                "priority": "High",
                "assignee": "abc123",
                "labels": ["bug", "critical"],
                "components": ["Backend", "API"]
            },
            "capability_token": token
        }))
        .await
        .expect("create_issue with optional fields should succeed");

    assert_eq!(result["key"], "PROJ-101");
}

/// Get issue returns full issue data.
#[fcp_async_core::runtime::test]
async fn get_issue_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.get_issue.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-123"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(jira_issue_response(
                "10001",
                "PROJ-123",
                "Test issue",
            )),
        )
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.get_issue"]).await;
    let token = generate_valid_token(&signing_key, "jira.get_issue", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.get_issue",
            "input": { "issue_key": "PROJ-123" },
            "capability_token": token
        }))
        .await
        .expect("get_issue should succeed");

    assert_eq!(result["key"], "PROJ-123");
    assert_eq!(result["id"], "10001");
}

/// Update issue returns updated status.
#[fcp_async_core::runtime::test]
async fn update_issue_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.update_issue.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/issue/PROJ-123"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.update_issue"]).await;
    let token = generate_valid_token(&signing_key, "jira.update_issue", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.update_issue",
            "input": {
                "issue_key": "PROJ-123",
                "fields": { "summary": "Updated summary" }
            },
            "capability_token": token
        }))
        .await
        .expect("update_issue should succeed");

    assert_eq!(result["updated"], true);
}

/// Delete issue returns deleted status.
#[fcp_async_core::runtime::test]
async fn delete_issue_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.delete_issue.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/issue/PROJ-123"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.delete_issue"]).await;
    let token = generate_valid_token(&signing_key, "jira.delete_issue", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.delete_issue",
            "input": { "issue_key": "PROJ-123" },
            "capability_token": token
        }))
        .await
        .expect("delete_issue should succeed");

    assert_eq!(result["deleted"], true);
}

// ============================================================================
// JQL Search Tests
// ============================================================================

/// JQL search returns paginated results.
#[fcp_async_core::runtime::test]
async fn search_jql_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.search_jql.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [
                { "id": "10001", "key": "PROJ-1", "fields": { "summary": "Bug #1" } },
                { "id": "10002", "key": "PROJ-2", "fields": { "summary": "Feature #2" } }
            ],
            "total": 25,
            "maxResults": 2,
            "startAt": 0
        })))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.search_jql"]).await;
    let token = generate_valid_token(&signing_key, "jira.search_jql", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.search_jql",
            "input": {
                "jql": "project = PROJ ORDER BY created DESC",
                "max_results": 2,
                "start_at": 0
            },
            "capability_token": token
        }))
        .await
        .expect("search_jql should succeed");

    assert_eq!(result["total"], 25);
    assert_eq!(result["issues"].as_array().unwrap().len(), 2);
    assert_eq!(result["issues"][0]["key"], "PROJ-1");
}

/// JQL search with fields filter.
#[fcp_async_core::runtime::test]
async fn search_jql_with_fields_filter() {
    let _ctx = AsyncTestContext::for_scenario("jira.search_jql.fields_filter");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [
                { "id": "10001", "key": "PROJ-1", "fields": { "summary": "Bug" } }
            ],
            "total": 1,
            "maxResults": 50,
            "startAt": 0
        })))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.search_jql"]).await;
    let token = generate_valid_token(&signing_key, "jira.search_jql", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.search_jql",
            "input": {
                "jql": "project = PROJ AND status = Open",
                "fields": "summary,status"
            },
            "capability_token": token
        }))
        .await
        .expect("search with fields should succeed");

    assert_eq!(result["total"], 1);
}

// ============================================================================
// Transition Tests
// ============================================================================

/// List transitions for an issue.
#[fcp_async_core::runtime::test]
async fn list_transitions_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.list_transitions.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-1/transitions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "transitions": [
                { "id": "11", "name": "To Do", "to": { "id": "1", "name": "To Do" } },
                { "id": "21", "name": "In Progress", "to": { "id": "2", "name": "In Progress" } },
                { "id": "31", "name": "Done", "to": { "id": "3", "name": "Done" } }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.list_transitions"]).await;
    let token = generate_valid_token(
        &signing_key,
        "jira.list_transitions",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.list_transitions",
            "input": { "issue_key": "PROJ-1" },
            "capability_token": token
        }))
        .await
        .expect("list_transitions should succeed");

    let transitions = result["transitions"].as_array().unwrap();
    assert_eq!(transitions.len(), 3);
    assert_eq!(transitions[0]["name"], "To Do");
    assert_eq!(transitions[2]["name"], "Done");
}

/// Execute a transition on an issue.
#[fcp_async_core::runtime::test]
async fn transition_issue_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.transition_issue.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/issue/PROJ-1/transitions"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.transition_issue"]).await;
    let token = generate_valid_token(
        &signing_key,
        "jira.transition_issue",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.transition_issue",
            "input": {
                "issue_key": "PROJ-1",
                "transition_id": "21"
            },
            "capability_token": token
        }))
        .await
        .expect("transition_issue should succeed");

    assert_eq!(result["transitioned"], true);
}

// ============================================================================
// Sprint Tests
// ============================================================================

/// List sprints for a board.
#[fcp_async_core::runtime::test]
async fn list_sprints_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.list_sprints.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/board/42/sprint"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "values": [
                { "id": 1, "name": "Sprint 1", "state": "active", "startDate": "2026-01-01", "endDate": "2026-01-14" },
                { "id": 2, "name": "Sprint 2", "state": "future" }
            ],
            "isLast": true,
            "maxResults": 50,
            "startAt": 0
        })))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.list_sprints"]).await;
    let token = generate_valid_token(&signing_key, "jira.list_sprints", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.list_sprints",
            "input": { "board_id": 42 },
            "capability_token": token
        }))
        .await
        .expect("list_sprints should succeed");

    let sprints = result["values"].as_array().unwrap();
    assert_eq!(sprints.len(), 2);
    assert_eq!(sprints[0]["name"], "Sprint 1");
    assert_eq!(sprints[0]["state"], "active");
}

/// Move issues to a sprint.
#[fcp_async_core::runtime::test]
async fn move_to_sprint_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.move_to_sprint.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/sprint/42/issue"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.move_to_sprint"]).await;
    let token = generate_valid_token(&signing_key, "jira.move_to_sprint", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.move_to_sprint",
            "input": {
                "sprint_id": 42,
                "issues": ["PROJ-1", "PROJ-2", "PROJ-3"]
            },
            "capability_token": token
        }))
        .await
        .expect("move_to_sprint should succeed");

    assert_eq!(result["moved"], true);
}

// ============================================================================
// Comment Tests
// ============================================================================

/// Add comment to an issue.
#[fcp_async_core::runtime::test]
async fn add_comment_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.add_comment.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/issue/PROJ-1/comment"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10100",
            "body": { "type": "doc", "content": [{ "type": "paragraph", "content": [{ "type": "text", "text": "Test comment" }] }] },
            "created": "2026-01-15T10:00:00.000+0000",
            "author": { "displayName": "Test User", "accountId": "abc123" }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.add_comment"]).await;
    let token = generate_valid_token(&signing_key, "jira.add_comment", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.add_comment",
            "input": {
                "issue_key": "PROJ-1",
                "body": "Test comment"
            },
            "capability_token": token
        }))
        .await
        .expect("add_comment should succeed");

    assert_eq!(result["id"], "10100");
}

/// List comments on an issue with pagination.
#[fcp_async_core::runtime::test]
async fn list_comments_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.list_comments.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-1/comment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "comments": [
                { "id": "100", "body": { "type": "doc", "content": [] }, "created": "2026-01-01T00:00:00.000+0000" },
                { "id": "101", "body": { "type": "doc", "content": [] }, "created": "2026-01-02T00:00:00.000+0000" }
            ],
            "total": 2,
            "startAt": 0,
            "maxResults": 50
        })))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.list_comments"]).await;
    let token = generate_valid_token(&signing_key, "jira.list_comments", connector.instance_id());

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.list_comments",
            "input": {
                "issue_key": "PROJ-1",
                "max_results": 50
            },
            "capability_token": token
        }))
        .await
        .expect("list_comments should succeed");

    assert_eq!(result["total"], 2);
    assert_eq!(result["comments"].as_array().unwrap().len(), 2);
}

// ============================================================================
// Attachment Tests
// ============================================================================

/// Upload base64-encoded attachment to an issue.
#[fcp_async_core::runtime::test]
async fn add_attachment_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("jira.add_attachment.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/issue/PROJ-1/attachments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "id": "att-001",
                "filename": "screenshot.png",
                "size": 12345,
                "mimeType": "image/png",
                "created": "2026-01-15T10:00:00.000+0000"
            }
        ])))
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.add_attachment"]).await;
    let token = generate_valid_token(&signing_key, "jira.add_attachment", connector.instance_id());

    // base64 encode some test data
    let test_data = base64::engine::general_purpose::STANDARD.encode(b"fake png data");

    let result = connector
        .handle_invoke(json!({
            "operation": "jira.add_attachment",
            "input": {
                "issue_key": "PROJ-1",
                "filename": "screenshot.png",
                "data": test_data
            },
            "capability_token": token
        }))
        .await
        .expect("add_attachment should succeed");

    let attachments = result["attachments"].as_array().unwrap();
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0]["filename"], "screenshot.png");
}

/// Attachment with invalid base64 fails.
#[fcp_async_core::runtime::test]
async fn add_attachment_invalid_base64_fails() {
    let _ctx = AsyncTestContext::for_scenario("jira.add_attachment.invalid_base64");
    let mock_server = MockServer::start().await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.add_attachment"]).await;
    let token = generate_valid_token(&signing_key, "jira.add_attachment", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.add_attachment",
            "input": {
                "issue_key": "PROJ-1",
                "filename": "bad.txt",
                "data": "not-valid-base64!!!"
            },
            "capability_token": token
        }))
        .await
        .expect_err("invalid base64 should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("base64") || message.contains("Base64"),
                "error should mention base64: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

// ============================================================================
// Error Taxonomy Tests (401/404/429/500 → FcpError mapping)
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
/// Uses client directly with zero retries to avoid slow backoff.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("jira.error.401");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = JiraClient::new("test", "user@example.com", "bad-token")
        .unwrap()
        .with_base_url(&mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_issue("PROJ-1", None, None)
        .await
        .expect_err("should fail with 401");

    assert!(
        matches!(err, fcp_jira::error::JiraError::Unauthorized),
        "expected Unauthorized, got: {err:?}"
    );

    // Verify FCP mapping
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "expected FcpError::Unauthorized, got: {fcp_err:?}"
    );
}

/// 404 Not Found maps to `FcpError::ResourceNotFound`.
#[fcp_async_core::runtime::test]
async fn error_404_maps_to_not_found() {
    let _ctx = AsyncTestContext::for_scenario("jira.error.404");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-999"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(jira_error_response(&[
                "Issue does not exist or you do not have permission to see it.",
            ])),
        )
        .mount(&mock_server)
        .await;

    let client = JiraClient::new("test", "user@example.com", "token")
        .unwrap()
        .with_base_url(&mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_issue("PROJ-999", None, None)
        .await
        .expect_err("should fail with 404");

    assert!(
        matches!(err, fcp_jira::error::JiraError::NotFound { .. }),
        "expected NotFound, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "expected FcpError::ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
/// Uses client directly with zero retries to avoid slow backoff.
#[fcp_async_core::runtime::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("jira.error.429");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
        .mount(&mock_server)
        .await;

    let client = JiraClient::new("test", "user@example.com", "token")
        .unwrap()
        .with_base_url(&mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_issue("PROJ-1", None, None)
        .await
        .expect_err("should fail with 429");

    assert!(
        matches!(err, fcp_jira::error::JiraError::RateLimited { .. }),
        "expected RateLimited, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "expected FcpError::RateLimited, got: {fcp_err:?}"
    );
}

/// 500 Server Error maps to `FcpError::External` with retryable=true.
/// Uses client directly with zero retries.
#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external() {
    let _ctx = AsyncTestContext::for_scenario("jira.error.500");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-1"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(jira_error_response(&["Internal server error"])),
        )
        .mount(&mock_server)
        .await;

    let client = JiraClient::new("test", "user@example.com", "token")
        .unwrap()
        .with_base_url(&mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_issue("PROJ-1", None, None)
        .await
        .expect_err("should fail with 500");

    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            service,
            retryable,
            status_code,
            ..
        } => {
            assert_eq!(service, "jira");
            assert!(retryable, "500 should be retryable");
            assert_eq!(*status_code, Some(500));
        }
        other => panic!("expected FcpError::External, got: {other:?}"),
    }
}

/// Error `is_retryable` classification is correct.
#[test]
fn error_retryable_classification() {
    use fcp_jira::error::JiraError;

    // Retryable errors
    assert!(
        JiraError::RateLimited {
            retry_after_ms: 1000
        }
        .is_retryable()
    );
    assert!(
        JiraError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        }
        .is_retryable()
    );
    assert!(
        JiraError::Api {
            message: "Bad gateway".into(),
            status_code: Some(502),
        }
        .is_retryable()
    );
    assert!(
        JiraError::Api {
            message: "Service unavailable".into(),
            status_code: Some(503),
        }
        .is_retryable()
    );

    // Non-retryable errors
    assert!(!JiraError::Unauthorized.is_retryable());
    assert!(
        !JiraError::NotFound {
            resource: "test".into()
        }
        .is_retryable()
    );
    assert!(
        !JiraError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
        }
        .is_retryable()
    );
}

// ============================================================================
// FCP2 Default-Deny / Capability Verification Tests
// ============================================================================

/// Invoke without `capability_token` fails.
#[fcp_async_core::runtime::test]
async fn capability_missing_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("jira.capability.missing_token");
    let mock_server = MockServer::start().await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    setup_handshake(&mut connector, &["jira.get_issue"]).await;

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.get_issue",
            "input": { "issue_key": "PROJ-1" }
        }))
        .await
        .expect_err("invoke without token should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing token, got: {err:?}"
    );
}

/// Invoke before handshake fails (no verifier).
#[fcp_async_core::runtime::test]
async fn capability_no_handshake_fails() {
    let _ctx = AsyncTestContext::for_scenario("jira.capability.no_handshake");
    let mock_server = MockServer::start().await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, "jira.get_issue", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.get_issue",
            "input": { "issue_key": "PROJ-1" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without handshake should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotHandshaken),
        "expected NotHandshaken, got: {err:?}"
    );
}

/// Invoke before configure fails (no client).
#[fcp_async_core::runtime::test]
async fn capability_no_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("jira.capability.no_configure");

    let mut connector = JiraConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let err = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["jira.get_issue"]
        }))
        .await
        .expect_err("handshake without configure should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Token signed for wrong operation fails verification.
#[fcp_async_core::runtime::test]
async fn capability_wrong_operation_fails() {
    let _ctx = AsyncTestContext::for_scenario("jira.capability.wrong_op");
    let mock_server = MockServer::start().await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["jira.get_issue", "jira.create_issue"]).await;

    // Token signed for create_issue, used on get_issue
    let wrong_token =
        generate_valid_token(&signing_key, "jira.create_issue", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.get_issue",
            "input": { "issue_key": "PROJ-1" },
            "capability_token": wrong_token
        }))
        .await
        .expect_err("wrong capability should fail");

    let is_cap_error = matches!(
        &err,
        fcp_core::FcpError::CapabilityDenied { .. }
            | fcp_core::FcpError::Unauthorized { .. }
            | fcp_core::FcpError::OperationNotGranted { .. }
    );
    assert!(
        is_cap_error,
        "expected capability/operation denial, got: {err:?}"
    );
}

/// Unknown operation fails with `OperationNotGranted`.
#[fcp_async_core::runtime::test]
async fn capability_unknown_operation_fails() {
    let mock_server = MockServer::start().await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "jira.nonexistent", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("unknown operation should fail");

    assert!(
        matches!(err, fcp_core::FcpError::OperationNotGranted { .. }),
        "expected OperationNotGranted, got: {err:?}"
    );
}

/// Simulate validates the same capability token path as invoke.
#[fcp_async_core::runtime::test]
async fn simulate_valid_capability_is_allowed() {
    let _ctx = AsyncTestContext::for_scenario("jira.simulate.valid_capability");
    let mock_server = MockServer::start().await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.get_issue"]).await;
    let token = generate_valid_token(&signing_key, "jira.get_issue", connector.instance_id());

    let result = connector
        .handle_simulate(simulate_request(
            "jira.get_issue",
            &json!({"issue_key": "PROJ-1"}),
            &token,
        ))
        .await
        .expect("simulate should serialize");

    assert_eq!(result["would_succeed"], true);
    assert_eq!(result["failure_reason"], serde_json::Value::Null);
}

/// Simulate denies tokens that do not authorize the requested operation.
#[fcp_async_core::runtime::test]
async fn simulate_wrong_capability_is_denied() {
    let _ctx = AsyncTestContext::for_scenario("jira.simulate.wrong_capability");
    let mock_server = MockServer::start().await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["jira.get_issue", "jira.create_issue"]).await;
    let wrong_token =
        generate_valid_token(&signing_key, "jira.create_issue", connector.instance_id());

    let result = connector
        .handle_simulate(simulate_request(
            "jira.get_issue",
            &json!({"issue_key": "PROJ-1"}),
            &wrong_token,
        ))
        .await
        .expect("simulate should serialize");

    assert_eq!(result["would_succeed"], false);
    assert_eq!(result["missing_capabilities"][0], "jira.read");
}

/// Unknown operations are denied during simulation, not optimistically allowed.
#[fcp_async_core::runtime::test]
async fn simulate_unknown_operation_is_denied() {
    let mock_server = MockServer::start().await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.nonexistent"]).await;
    let token = generate_valid_token(&signing_key, "jira.nonexistent", connector.instance_id());

    let result = connector
        .handle_simulate(simulate_request("jira.nonexistent", &json!({}), &token))
        .await
        .expect("simulate should serialize");

    assert_eq!(result["would_succeed"], false);
    assert!(
        result["failure_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("jira.nonexistent")
    );
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health check before configure reports `not_configured`.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let connector = JiraConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

/// Health check after configure reports healthy.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let mock_server = MockServer::start().await;
    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

/// Handshake returns accepted with capabilities granted.
#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_grants_capabilities() {
    let mock_server = MockServer::start().await;
    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["jira.read", "jira.write", "jira.delete"]
        }))
        .await
        .expect("handshake should succeed");

    assert_eq!(result["status"], "accepted");
    let caps = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

/// Shutdown returns clean status.
#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_clean() {
    let mut connector = JiraConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

/// Introspect exposes all 23 operations with schemas.
#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_all_operations() {
    let connector = JiraConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    let expected_ops = [
        "jira.create_issue",
        "jira.get_issue",
        "jira.update_issue",
        "jira.delete_issue",
        "jira.search_jql",
        "jira.list_transitions",
        "jira.transition_issue",
        "jira.list_sprints",
        "jira.move_to_sprint",
        "jira.add_comment",
        "jira.list_comments",
        "jira.add_attachment",
        "jira.automation.rule.list",
        "jira.automation.rule.get",
        "jira.automation.rule.create",
        "jira.automation.rule.update",
        "jira.automation.rule.enable",
        "jira.automation.rule.disable",
        "jira.automation.rule.delete",
        "jira.sync.pull_issue",
        "jira.sync.push_bead",
        "jira.sync.reconcile",
        "jira.server.info",
    ];

    for expected in &expected_ops {
        assert!(op_ids.contains(expected), "missing operation: {expected}");
    }
    assert_eq!(ops.len(), 27);

    // Verify schemas are present on all operations
    for op in ops {
        assert!(
            op["input_schema"].is_object(),
            "input_schema should be object for {}",
            op["id"]
        );
        assert!(
            op["output_schema"].is_object(),
            "output_schema should be object for {}",
            op["id"]
        );
    }
}

// ============================================================================
// Input Validation Edge Cases
// ============================================================================

/// Missing required field in `create_issue` fails.
#[fcp_async_core::runtime::test]
async fn validation_create_issue_missing_summary() {
    let mock_server = MockServer::start().await;
    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.create_issue"]).await;
    let token = generate_valid_token(&signing_key, "jira.create_issue", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.create_issue",
            "input": { "project_key": "PROJ", "issue_type": "Task" },
            "capability_token": token
        }))
        .await
        .expect_err("missing summary should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("summary"),
                "error should mention summary: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `issue_key` in `get_issue` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_issue_missing_key() {
    let mock_server = MockServer::start().await;
    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.get_issue"]).await;
    let token = generate_valid_token(&signing_key, "jira.get_issue", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.get_issue",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing issue_key should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("issue_key"),
                "error should mention issue_key: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing jql in `search_jql` fails.
#[fcp_async_core::runtime::test]
async fn validation_search_jql_missing_query() {
    let mock_server = MockServer::start().await;
    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.search_jql"]).await;
    let token = generate_valid_token(&signing_key, "jira.search_jql", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.search_jql",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing jql should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("jql"),
                "error should mention jql: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `board_id` in `list_sprints` fails.
#[fcp_async_core::runtime::test]
async fn validation_list_sprints_missing_board_id() {
    let mock_server = MockServer::start().await;
    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.list_sprints"]).await;
    let token = generate_valid_token(&signing_key, "jira.list_sprints", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.list_sprints",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing board_id should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("board_id"),
                "error should mention board_id: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `transition_id` in `transition_issue` fails.
#[fcp_async_core::runtime::test]
async fn validation_transition_issue_missing_id() {
    let mock_server = MockServer::start().await;
    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.transition_issue"]).await;
    let token = generate_valid_token(
        &signing_key,
        "jira.transition_issue",
        connector.instance_id(),
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.transition_issue",
            "input": { "issue_key": "PROJ-1" },
            "capability_token": token
        }))
        .await
        .expect_err("missing transition_id should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("transition_id"),
                "error should mention transition_id: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Update issue missing fields object fails.
#[fcp_async_core::runtime::test]
async fn validation_update_issue_missing_fields() {
    let mock_server = MockServer::start().await;
    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.update_issue"]).await;
    let token = generate_valid_token(&signing_key, "jira.update_issue", connector.instance_id());

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.update_issue",
            "input": { "issue_key": "PROJ-1" },
            "capability_token": token
        }))
        .await
        .expect_err("missing fields should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("fields"),
                "error should mention fields: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Sync operations require a `zone_dir` because they persist connector state.
#[fcp_async_core::runtime::test]
async fn sync_operations_require_zone_dir() {
    let mock_server = MockServer::start().await;
    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["jira.sync.pull_issue"]).await;
    let token = generate_valid_token(
        &signing_key,
        "jira.sync.pull_issue",
        connector.instance_id(),
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "jira.sync.pull_issue",
            "input": { "issue_key": "PROJ-100" },
            "capability_token": token
        }))
        .await
        .expect_err("sync pull without zone_dir should fail");

    match err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("zone_dir"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Sync state persists across restarts and prevents duplicate issue creation.
#[fcp_async_core::runtime::test]
async fn sync_push_bead_persists_across_restart_and_is_idempotent() {
    let _ctx = AsyncTestContext::for_scenario("jira.sync.push_bead.persistence");
    let mock_server = MockServer::start().await;
    let zone_dir = std::env::temp_dir()
        .join(format!("jira-sync-int-push-persist-{}", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned();

    Mock::given(method("POST"))
        .and(path("/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-100",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10001"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [],
            "total": 0,
            "startAt": 0,
            "maxResults": 2
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-100",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10001",
            "fields": {
                "summary": "Ship Jira sync",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{ "type": "text", "text": "Normalize records" }]
                    }]
                },
                "status": { "name": "In Progress" },
                "priority": { "name": "High" },
                "labels": ["backend", "bead:br-123"],
                "assignee": { "accountId": "acct-1" },
                "duedate": "2026-03-31",
                "updated": "2026-03-09T10:00:00+00:00",
                "timetracking": { "originalEstimateSeconds": 5400 }
            }
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    let mut first = JiraConnector::new();
    setup_configure(&mut first, &mock_server.uri()).await;
    let first_key =
        setup_handshake_with_zone(&mut first, &["jira.sync.push_bead"], Some(&zone_dir)).await;
    let first_token = generate_valid_token(&first_key, "jira.sync.push_bead", first.instance_id());
    let first_result = first
        .handle_invoke(json!({
            "operation": "jira.sync.push_bead",
            "input": {
                "project_key": "PROJ",
                "issue_type": "Task",
                "bead": {
                    "beadId": "br-123",
                    "title": "Ship Jira sync",
                    "description": "Normalize records",
                    "status": "In Progress",
                    "priority": "High",
                    "labels": ["backend"],
                    "assignee": "acct-1",
                    "dueDate": "2026-03-31",
                    "estimateSeconds": 5400,
                    "revision": "2026-03-09T10:00:00+00:00"
                }
            },
            "capability_token": first_token
        }))
        .await
        .expect("initial sync push should succeed");

    assert_eq!(first_result["action"], "push_bead");
    assert_eq!(first_result["created"], true);

    let state_path = std::path::PathBuf::from(&zone_dir).join("jira_sync_state.json");
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).expect("state file should exist"))
            .expect("state file should be valid json");
    assert_eq!(persisted["mappings"]["br-123"]["issueKey"], "PROJ-100");

    let mut second = JiraConnector::new();
    setup_configure(&mut second, &mock_server.uri()).await;
    let second_key =
        setup_handshake_with_zone(&mut second, &["jira.sync.push_bead"], Some(&zone_dir)).await;
    let second_token =
        generate_valid_token(&second_key, "jira.sync.push_bead", second.instance_id());
    let second_result = second
        .handle_invoke(json!({
            "operation": "jira.sync.push_bead",
            "input": {
                "bead": {
                    "beadId": "br-123",
                    "title": "Ship Jira sync",
                    "description": "Normalize records",
                    "status": "In Progress",
                    "priority": "High",
                    "labels": ["backend"],
                    "assignee": "acct-1",
                    "dueDate": "2026-03-31",
                    "estimateSeconds": 5400,
                    "revision": "2026-03-09T10:00:00+00:00"
                }
            },
            "capability_token": second_token
        }))
        .await
        .expect("repeat sync push should converge");

    assert_eq!(second_result["action"], "noop");
    assert_eq!(second_result["created"], false);
    assert_eq!(second_result["updated"], false);
}

/// A Jira webhook replay after a Beads-origin push is treated as a noop.
#[fcp_async_core::runtime::test]
async fn sync_pull_issue_replay_is_noop_after_push() {
    let _ctx = AsyncTestContext::for_scenario("jira.sync.pull_issue.loop_prevention");
    let mock_server = MockServer::start().await;
    let zone_dir = std::env::temp_dir()
        .join(format!("jira-sync-int-pull-replay-{}", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned();

    Mock::given(method("POST"))
        .and(path("/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-100",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10001"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [],
            "total": 0,
            "startAt": 0,
            "maxResults": 2
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-100",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10001",
            "fields": {
                "summary": "Ship Jira sync",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{ "type": "text", "text": "Normalize records" }]
                    }]
                },
                "status": { "name": "In Progress" },
                "priority": { "name": "High" },
                "labels": ["backend", "bead:br-123"],
                "assignee": { "accountId": "acct-1" },
                "duedate": "2026-03-31",
                "updated": "2026-03-09T10:00:00+00:00",
                "timetracking": { "originalEstimateSeconds": 5400 }
            }
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    let mut connector = JiraConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake_with_zone(
        &mut connector,
        &["jira.sync.push_bead", "jira.sync.pull_issue"],
        Some(&zone_dir),
    )
    .await;

    let push_token =
        generate_valid_token(&signing_key, "jira.sync.push_bead", connector.instance_id());
    connector
        .handle_invoke(json!({
            "operation": "jira.sync.push_bead",
            "input": {
                "project_key": "PROJ",
                "issue_type": "Task",
                "bead": {
                    "beadId": "br-123",
                    "title": "Ship Jira sync",
                    "description": "Normalize records",
                    "status": "In Progress",
                    "priority": "High",
                    "labels": ["backend"],
                    "assignee": "acct-1",
                    "dueDate": "2026-03-31",
                    "estimateSeconds": 5400,
                    "revision": "2026-03-09T10:00:00+00:00"
                }
            },
            "capability_token": push_token
        }))
        .await
        .expect("push should succeed");

    let pull_token = generate_valid_token(
        &signing_key,
        "jira.sync.pull_issue",
        connector.instance_id(),
    );
    let pull_result = connector
        .handle_invoke(json!({
            "operation": "jira.sync.pull_issue",
            "input": { "issue_key": "PROJ-100" },
            "capability_token": pull_token
        }))
        .await
        .expect("pull should succeed");

    assert_eq!(pull_result["action"], "noop");
    assert_eq!(pull_result["bead"]["beadId"], "br-123");
}

/// Concurrent edits surface an explicit conflict and the divergence is persisted.
#[fcp_async_core::runtime::test]
async fn sync_reconcile_conflict_is_explicit_and_persisted() {
    let _ctx = AsyncTestContext::for_scenario("jira.sync.reconcile.conflict");
    let initial_server = MockServer::start().await;
    let reconcile_server = MockServer::start().await;
    let zone_dir = std::env::temp_dir()
        .join(format!(
            "jira-sync-int-reconcile-conflict-{}",
            Uuid::new_v4()
        ))
        .to_string_lossy()
        .into_owned();

    Mock::given(method("POST"))
        .and(path("/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-100",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10001"
        })))
        .expect(1)
        .mount(&initial_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [],
            "total": 0,
            "startAt": 0,
            "maxResults": 2
        })))
        .expect(1)
        .mount(&initial_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-100",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10001",
            "fields": {
                "summary": "Ship Jira sync",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{ "type": "text", "text": "Normalize records" }]
                    }]
                },
                "status": { "name": "In Progress" },
                "priority": { "name": "High" },
                "labels": ["backend", "bead:br-123"],
                "assignee": { "accountId": "acct-1" },
                "duedate": "2026-03-31",
                "updated": "2026-03-09T10:00:00+00:00",
                "timetracking": { "originalEstimateSeconds": 5400 }
            }
        })))
        .expect(1)
        .mount(&initial_server)
        .await;

    let mut push_connector = JiraConnector::new();
    setup_configure(&mut push_connector, &initial_server.uri()).await;
    let push_key = setup_handshake_with_zone(
        &mut push_connector,
        &["jira.sync.push_bead"],
        Some(&zone_dir),
    )
    .await;
    let push_token = generate_valid_token(
        &push_key,
        "jira.sync.push_bead",
        push_connector.instance_id(),
    );
    push_connector
        .handle_invoke(json!({
            "operation": "jira.sync.push_bead",
            "input": {
                "project_key": "PROJ",
                "issue_type": "Task",
                "bead": {
                    "beadId": "br-123",
                    "title": "Ship Jira sync",
                    "description": "Normalize records",
                    "status": "In Progress",
                    "priority": "High",
                    "labels": ["backend"],
                    "assignee": "acct-1",
                    "dueDate": "2026-03-31",
                    "estimateSeconds": 5400,
                    "revision": "2026-03-09T10:00:00+00:00"
                }
            },
            "capability_token": push_token
        }))
        .await
        .expect("initial push should seed sync state");

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-100",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10001",
            "fields": {
                "summary": "Remote Jira edit",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{ "type": "text", "text": "Normalize records" }]
                    }]
                },
                "status": { "name": "In Progress" },
                "priority": { "name": "High" },
                "labels": ["backend", "bead:br-123"],
                "assignee": { "accountId": "acct-1" },
                "duedate": "2026-03-31",
                "updated": "2026-03-09T10:30:00+00:00",
                "timetracking": { "originalEstimateSeconds": 5400 }
            }
        })))
        .expect(1)
        .mount(&reconcile_server)
        .await;

    let mut reconcile_connector = JiraConnector::new();
    setup_configure(&mut reconcile_connector, &reconcile_server.uri()).await;
    let reconcile_key = setup_handshake_with_zone(
        &mut reconcile_connector,
        &["jira.sync.reconcile"],
        Some(&zone_dir),
    )
    .await;
    let reconcile_token = generate_valid_token(
        &reconcile_key,
        "jira.sync.reconcile",
        reconcile_connector.instance_id(),
    );
    let reconcile_result = reconcile_connector
        .handle_invoke(json!({
            "operation": "jira.sync.reconcile",
            "input": {
                "issue_key": "PROJ-100",
                "bead": {
                    "beadId": "br-123",
                    "title": "Local Bead Edit",
                    "description": "Normalize records",
                    "status": "In Progress",
                    "priority": "High",
                    "labels": ["backend"],
                    "assignee": "acct-1",
                    "dueDate": "2026-03-31",
                    "estimateSeconds": 5400,
                    "revision": "2026-03-09T11:00:00+00:00"
                },
                "conflict_policy": "fail_closed"
            },
            "capability_token": reconcile_token
        }))
        .await
        .expect("reconcile should return an explicit conflict");

    assert_eq!(reconcile_result["action"], "conflict");
    assert_eq!(
        reconcile_result["conflict"]["reasonCode"],
        "concurrent_changes_detected"
    );

    let state_path = std::path::PathBuf::from(&zone_dir).join("jira_sync_state.json");
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).expect("state file should exist"))
            .expect("state file should be valid json");
    assert_eq!(persisted["mappings"]["br-123"]["issueKey"], "PROJ-100");
    assert_ne!(
        persisted["mappings"]["br-123"]["beadFingerprint"],
        persisted["mappings"]["br-123"]["jiraFingerprint"]
    );
}

// ============================================================================
// Replay safety on retry (br-kxd3e)
// ============================================================================
//
// Jira has no idempotency key, so a 5xx retry on a create endpoint files a
// second issue, posts a second comment, or logs the same work twice. The last
// one flows into billing and capacity reports, which is why worklog is the
// case worth naming.
//
// The 429 test is not optional: `JiraError::is_retryable()` returns true for
// BOTH rate limits and 5xx, so a gate written as "did it reach the service"
// would silently disable rate-limit backoff on every write. The predicate is
// phrased as "can replaying duplicate a side effect" precisely to avoid that.

fn replay_test_client(mock_server: &MockServer) -> JiraClient {
    JiraClient::new("test", "user@example.com", "token")
        .unwrap()
        .with_base_url(&mock_server.uri())
        .with_retry_config(3, 1, 5)
}

#[fcp_async_core::runtime::test]
async fn create_issue_is_not_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/issue"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_json(jira_error_response(&["Service temporarily unavailable"])),
        )
        .mount(&mock_server)
        .await;

    let result = replay_test_client(&mock_server)
        .create_issue(&json!({ "fields": { "summary": "x" } }))
        .await;
    assert!(result.is_err());

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a 503 means Jira received the create — retrying files a SECOND issue"
    );
}

#[fcp_async_core::runtime::test]
async fn add_worklog_is_not_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/issue/PROJ-1/worklog"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(jira_error_response(&["Internal error"])),
        )
        .mount(&mock_server)
        .await;

    let result = replay_test_client(&mock_server)
        .add_worklog("PROJ-1", &json!({ "timeSpentSeconds": 3600 }))
        .await;
    assert!(result.is_err());

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a duplicate worklog double-counts logged time into billing and \
         capacity reports"
    );
}

#[fcp_async_core::runtime::test]
async fn create_issue_still_retries_a_429() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/issue"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "10001",
            "key": "PROJ-100",
            "self": "https://test-org.atlassian.net/rest/api/3/issue/10001"
        })))
        .mount(&mock_server)
        .await;

    replay_test_client(&mock_server)
        .create_issue(&json!({ "fields": { "summary": "x" } }))
        .await
        .expect("a rate-limited create was refused without filing anything");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "429 means Jira did NOT create the issue, so backoff must be preserved"
    );
}

#[fcp_async_core::runtime::test]
async fn search_jql_is_still_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(502))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "startAt": 0,
            "maxResults": 50,
            "total": 0,
            "issues": []
        })))
        .mount(&mock_server)
        .await;

    replay_test_client(&mock_server)
        .search_jql(&json!({ "jql": "project = PROJ" }))
        .await
        .expect("JQL search is read-only, so the retry must be preserved");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "Jira models JQL search as a POST but it only reads — refusing this \
         retry would be a pure availability loss"
    );
}
