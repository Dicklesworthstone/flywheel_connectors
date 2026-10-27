//! GitHub connector integration tests (flywheel_connectors-s73.6).
//!
//! Deterministic integration tests using wiremock to mock the GitHub REST API.
//! No real API calls. Covers:
//! - Issues (create, get, search)
//! - Pull Requests (create, get, merge)
//! - Repositories (get, search)
//! - Actions (list workflows, trigger workflow)
//! - Content (get file, search code)
//! - Error taxonomy (401/404/422/429/409/500 -> `FcpError` mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

use fcp_github::client::GitHubClient;
use fcp_github::connector::GitHubConnector;

// ============================================================================
// Helpers
// ============================================================================

const TEST_CREDENTIAL_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

fn generate_valid_bound_token(
    signing_key: &Ed25519SigningKey,
    connector: &GitHubConnector,
    op: &str,
) -> fcp_core::CapabilityToken {
    let cap = match op {
        "github.create_issue" | "github.create_pull_request" => "github.write",
        "github.merge_pull_request" | "github.trigger_workflow" => "github.admin",
        "github.process_webhook" => "github.process_webhook",
        _ => "github.read",
    };
    let now = Utc::now();
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
        .validity(now, now + Duration::hours(1))
        .target_instance(connector.instance_id().as_str())
        .try_constraints_cbor(&cbor)
        .expect("test constraints CBOR should be valid")
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut GitHubConnector, caps: &[&str]) -> Ed25519SigningKey {
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

async fn setup_configure(connector: &mut GitHubConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

/// Standard GitHub issue response.
fn github_issue_response(number: u32, title: &str, state: &str) -> serde_json::Value {
    json!({
        "id": 1000 + u64::from(number),
        "number": number,
        "title": title,
        "state": state,
        "body": "Issue body",
        "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
        "labels": [],
        "assignees": [],
        "created_at": "2026-01-15T10:00:00Z",
        "updated_at": "2026-01-15T10:00:01Z",
        "html_url": format!("https://github.com/octocat/hello-world/issues/{number}"),
        "comments": 0
    })
}

/// Standard GitHub pull request response.
fn github_pr_response(number: u32, title: &str, state: &str) -> serde_json::Value {
    json!({
        "id": 2000 + u64::from(number),
        "number": number,
        "title": title,
        "state": state,
        "body": "PR body",
        "user": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
        "head": { "label": "octocat:feature", "ref": "feature", "sha": "abc123" },
        "base": { "label": "octocat:main", "ref": "main", "sha": "def456" },
        "labels": [],
        "assignees": [],
        "merged": false,
        "created_at": "2026-01-15T10:00:00Z",
        "updated_at": "2026-01-15T10:00:01Z",
        "html_url": format!("https://github.com/octocat/hello-world/pull/{number}"),
        "draft": false
    })
}

/// GitHub API error response.
fn github_error_response(message: &str) -> serde_json::Value {
    json!({
        "message": message,
        "documentation_url": "https://docs.github.com"
    })
}

// ============================================================================
// Issue Tests
// ============================================================================

/// Create issue happy path.
#[fcp_async_core::test]
async fn create_issue_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.create_issue.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/issues"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(github_issue_response(
                43,
                "Bug report",
                "open",
            )),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.create_issue"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.create_issue");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.create_issue",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "title": "Bug report",
                "body": "Found a bug"
            },
            "capability_token": token
        }))
        .await
        .expect("create_issue should succeed");

    assert_eq!(result["issue"]["number"], 43);
    assert_eq!(result["issue"]["title"], "Bug report");
}

/// Get issue happy path.
#[fcp_async_core::test]
async fn get_issue_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.get_issue.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world/issues/42"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(github_issue_response(
                42,
                "Found a bug",
                "open",
            )),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_issue"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_issue");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_issue",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "issue_number": 42
            },
            "capability_token": token
        }))
        .await
        .expect("get_issue should succeed");

    assert_eq!(result["issue"]["number"], 42);
    assert_eq!(result["issue"]["state"], "open");
}

/// Search issues happy path.
#[fcp_async_core::test]
async fn search_issues_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.search_issues.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search/issues"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1,
            "incomplete_results": false,
            "items": [github_issue_response(42, "Found a bug", "open")]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_issues"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.search_issues");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.search_issues",
            "input": { "query": "is:open is:issue repo:octocat/hello-world" },
            "capability_token": token
        }))
        .await
        .expect("search_issues should succeed");

    assert_eq!(result["total_count"], 1);
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
}

// ============================================================================
// Pull Request Tests
// ============================================================================

/// Create pull request happy path.
#[fcp_async_core::test]
async fn create_pull_request_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.create_pull_request.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/pulls"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(github_pr_response(1, "Fix typo", "open")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.create_pull_request"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.create_pull_request");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.create_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "title": "Fix typo",
                "head": "feature",
                "base": "main"
            },
            "capability_token": token
        }))
        .await
        .expect("create_pull_request should succeed");

    assert_eq!(result["pull_request"]["number"], 1);
    assert_eq!(result["pull_request"]["title"], "Fix typo");
}

/// Get pull request happy path.
#[fcp_async_core::test]
async fn get_pull_request_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.get_pull_request.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world/pulls/1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(github_pr_response(1, "Fix typo", "open")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_pull_request"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_pull_request");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "pull_number": 1
            },
            "capability_token": token
        }))
        .await
        .expect("get_pull_request should succeed");

    assert_eq!(result["pull_request"]["number"], 1);
    assert_eq!(result["pull_request"]["head"]["ref"], "feature");
}

/// Merge pull request happy path.
#[fcp_async_core::test]
async fn merge_pull_request_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.merge_pull_request.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/repos/octocat/hello-world/pulls/1/merge"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sha": "abc123def456",
            "merged": true,
            "message": "Pull Request successfully merged"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.merge_pull_request"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.merge_pull_request");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.merge_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "pull_number": 1,
                "merge_method": "squash"
            },
            "capability_token": token
        }))
        .await
        .expect("merge_pull_request should succeed");

    assert!(result["merged"].as_bool().unwrap());
    assert_eq!(result["sha"], "abc123def456");
}

// ============================================================================
// Repository Tests
// ============================================================================

/// Get repository metadata.
#[fcp_async_core::test]
async fn get_repo_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.get_repo.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1_296_269,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
            "description": "Test repo",
            "private": false,
            "fork": false,
            "html_url": "https://github.com/octocat/hello-world",
            "default_branch": "main",
            "language": "Rust",
            "stargazers_count": 42,
            "forks_count": 10,
            "open_issues_count": 5,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_repo"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_repo");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect("get_repo should succeed");

    assert_eq!(result["repository"]["name"], "hello-world");
    assert_eq!(result["repository"]["stargazers_count"], 42);
}

/// Search repositories.
#[fcp_async_core::test]
async fn search_repos_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.search_repos.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search/repositories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1,
            "incomplete_results": false,
            "items": [{
                "id": 1_296_269,
                "name": "hello-world",
                "full_name": "octocat/hello-world",
                "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
                "private": false,
                "fork": false,
                "html_url": "https://github.com/octocat/hello-world",
                "default_branch": "main",
                "stargazers_count": 42,
                "forks_count": 10,
                "open_issues_count": 5,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-06-01T00:00:00Z"
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_repos"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.search_repos");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.search_repos",
            "input": { "query": "language:rust stars:>1000" },
            "capability_token": token
        }))
        .await
        .expect("search_repos should succeed");

    assert_eq!(result["total_count"], 1);
}

// ============================================================================
// Actions Tests
// ============================================================================

/// List workflows.
#[fcp_async_core::test]
async fn list_workflows_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.list_workflows.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world/actions/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1,
            "workflows": [{
                "id": 1,
                "name": "CI",
                "path": ".github/workflows/ci.yml",
                "state": "active",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-06-01T00:00:00Z"
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.list_workflows"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.list_workflows");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.list_workflows",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect("list_workflows should succeed");

    assert_eq!(result["total_count"], 1);
    assert_eq!(result["workflows"].as_array().unwrap().len(), 1);
}

/// Trigger workflow dispatch.
#[fcp_async_core::test]
async fn trigger_workflow_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.trigger_workflow.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/repos/octocat/hello-world/actions/workflows/ci.yml/dispatches",
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.trigger_workflow"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.trigger_workflow");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.trigger_workflow",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "workflow_id": "ci.yml",
                "ref": "main"
            },
            "capability_token": token
        }))
        .await
        .expect("trigger_workflow should succeed");

    assert!(result["triggered"].as_bool().unwrap());
}

#[fcp_async_core::test]
async fn workflow_dispatch_preserves_inputs_and_accepts_success_without_replay() {
    for status in [200, 202, 204] {
        let server = MockServer::start().await;
        let inputs = json!({ "environment": "staging", "dry_run": true, "count": 3 });
        Mock::given(method("POST"))
            .and(path(
                "/repos/octocat/hello-world/actions/workflows/ci.yml/dispatches",
            ))
            .and(body_json(
                json!({ "ref": "release/next", "inputs": inputs }),
            ))
            .respond_with(ResponseTemplate::new(status))
            .expect(1)
            .mount(&server)
            .await;
        let mut connector = GitHubConnector::new();
        setup_configure(&mut connector, &server.uri()).await;
        let key = setup_handshake(&mut connector, &["github.trigger_workflow"]).await;
        let token = generate_valid_bound_token(&key, &connector, "github.trigger_workflow");
        let result = connector
            .handle_invoke(json!({
                "operation": "github.trigger_workflow",
                "input": { "owner": "octocat", "repo": "hello-world", "workflow_id": "ci.yml",
                    "ref": "release/next", "inputs": inputs },
                "capability_token": token
            }))
            .await
            .expect("a successful dispatch must not become an error while decoding an empty body");
        assert_eq!(result["triggered"], true);
        server.verify().await;
    }
}

#[fcp_async_core::test]
async fn workflow_dispatch_does_not_replay_ambiguous_provider_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/repos/octocat/hello-world/actions/workflows/ci.yml/dispatches",
        ))
        .respond_with(
            ResponseTemplate::new(502).set_body_json(github_error_response("upstream failure")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let client = GitHubClient::new("test-token")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(3, 1, 1);
    assert!(
        client
            .trigger_workflow("octocat", "hello-world", "ci.yml", "main", None)
            .await
            .is_err()
    );
    server.verify().await;
}

// ============================================================================
// Content Tests
// ============================================================================

/// Get file content.
#[fcp_async_core::test]
async fn get_file_content_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.get_file_content.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world/contents/README.md"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "README.md",
            "path": "README.md",
            "sha": "abc123",
            "size": 100,
            "type": "file",
            "content": "SGVsbG8gV29ybGQ=",
            "encoding": "base64",
            "html_url": "https://github.com/octocat/hello-world/blob/main/README.md"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_file_content"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_file_content");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_file_content",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "path": "README.md"
            },
            "capability_token": token
        }))
        .await
        .expect("get_file_content should succeed");

    assert_eq!(result["content"]["name"], "README.md");
    assert_eq!(result["content"]["encoding"], "base64");
}

#[fcp_async_core::test]
async fn repository_content_lists_root_and_directory_at_explicit_ref() {
    let server = MockServer::start().await;
    let git_ref = "feature/a &b#c";
    let entries = json!([
        { "name": "src", "path": "src", "sha": "abc", "size": 0, "type": "dir",
            "html_url": "https://github.com/octocat/hello-world/tree/main/src" },
        { "name": "vendor", "path": "vendor", "sha": "def", "size": 0, "type": "file",
            "html_url": null, "submodule_git_url": "https://example.org/vendor.git" }
    ]);
    for (requested_path, response) in [("", entries.clone()), ("empty", json!([]))] {
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/octocat/hello-world/contents/{requested_path}"
            )))
            .and(query_param("ref", git_ref))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
    }
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let key = setup_handshake(&mut connector, &["github.get_file_content"]).await;
    for requested_path in ["", "empty"] {
        let token = generate_valid_bound_token(&key, &connector, "github.get_file_content");
        let result = connector.handle_invoke(json!({
            "operation": "github.get_file_content",
            "input": { "owner": "octocat", "repo": "hello-world", "path": requested_path, "ref": git_ref },
            "capability_token": token
        })).await.expect("directory arrays must deserialize, including an empty root path");
        let items = result["content"]
            .as_array()
            .expect("directory response stays an array");
        if requested_path.is_empty() {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0]["type"], "dir");
            assert!(items[1]["html_url"].is_null());
            assert_eq!(
                items[1]["submodule_git_url"],
                "https://example.org/vendor.git"
            );
        } else {
            assert!(items.is_empty());
        }
    }
    server.verify().await;
}

#[fcp_async_core::test]
async fn searches_expose_bounded_continuation_and_incomplete_results() {
    let server = MockServer::start().await;
    let query = "repo:octocat/hello-world bug &feature";
    let operations = [
        ("github.search_issues", "/search/issues"),
        ("github.search_repos", "/search/repositories"),
        ("github.search_code", "/search/code"),
    ];
    for (_, endpoint) in operations {
        for page in [2, 3] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .and(query_param("q", query))
                .and(query_param("page", page.to_string()))
                .and(query_param("per_page", "2"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "total_count": 5, "incomplete_results": page == 2, "items": []
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
    }
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let key = setup_handshake(&mut connector, &operations.map(|(op, _)| op)).await;
    for (operation, _) in operations {
        for page in [2, 3] {
            let token = generate_valid_bound_token(&key, &connector, operation);
            let result = connector
                .handle_invoke(json!({
                    "operation": operation,
                    "input": { "query": query, "page": page, "per_page": 2 },
                    "capability_token": token
                }))
                .await
                .expect("each invocation should retrieve the selected provider page");
            assert_eq!(result["total_count"], 5);
            assert_eq!(result["incomplete_results"], page == 2);
            assert_eq!(result["pagination"]["page"], page);
            assert_eq!(result["pagination"]["per_page"], 2);
            assert_eq!(
                result["pagination"]["next_page"],
                if page == 2 { json!(3) } else { json!(null) }
            );
            assert_eq!(result["pagination"]["accessible_total_count"], 5);
        }
    }
    server.verify().await;
}

#[fcp_async_core::test]
async fn search_result_limit_is_explicit_without_hiding_provider_total() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search/issues"))
        .and(query_param("page", "10"))
        .and(query_param("per_page", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1200, "incomplete_results": false,
            "items": [github_issue_response(1000, "Last accessible issue", "open")]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let key = setup_handshake(&mut connector, &["github.search_issues"]).await;
    let token = generate_valid_bound_token(&key, &connector, "github.search_issues");
    let result = connector
        .handle_invoke(json!({
            "operation": "github.search_issues", "input": { "query": "bug", "page": 10 },
            "capability_token": token
        }))
        .await
        .unwrap();
    assert_eq!(result["total_count"], 1200);
    assert_eq!(result["items"][0]["number"], 1000);
    assert_eq!(result["pagination"]["returned"], 1);
    assert_eq!(result["pagination"]["accessible_total_count"], 1000);
    assert_eq!(result["pagination"]["result_limit"], 1000);
    assert_eq!(result["pagination"]["result_limit_exceeded"], true);
    assert!(result["pagination"]["next_page"].is_null());
    server.verify().await;
}

#[fcp_async_core::test]
async fn workflow_inventory_continues_past_search_window() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world/actions/workflows"))
        .and(query_param("page", "11"))
        .and(query_param("per_page", "100"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "total_count": 1101, "workflows": [] })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let key = setup_handshake(&mut connector, &["github.list_workflows"]).await;
    let token = generate_valid_bound_token(&key, &connector, "github.list_workflows");
    let result = connector.handle_invoke(json!({
        "operation": "github.list_workflows", "input": { "owner": "octocat", "repo": "hello-world", "page": 11 },
        "capability_token": token
    })).await.unwrap();
    assert_eq!(result["pagination"]["next_page"], 12);
    assert_eq!(result["pagination"]["accessible_total_count"], 1101);
    assert!(result["pagination"]["result_limit"].is_null());
    assert_eq!(result["pagination"]["result_limit_exceeded"], false);
    server.verify().await;
}

#[fcp_async_core::test]
async fn invalid_pagination_fails_before_network_or_simulation() {
    let server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let operations = [
        "github.search_issues",
        "github.search_repos",
        "github.search_code",
        "github.list_workflows",
    ];
    let key = setup_handshake(&mut connector, &operations).await;
    for operation in operations {
        for invalid in [
            json!({ "page": 0 }),
            json!({ "page": -1 }),
            json!({ "page": "2" }),
            json!({ "page": null }),
            json!({ "page": 4_294_967_296_u64 }),
            json!({ "per_page": 0 }),
            json!({ "per_page": 101 }),
            json!({ "per_page": 1.5 }),
        ] {
            let mut input = json!({ "owner": "octocat", "repo": "hello-world", "query": "test" });
            input
                .as_object_mut()
                .unwrap()
                .extend(invalid.as_object().unwrap().clone());
            let token = generate_valid_bound_token(&key, &connector, operation);
            let simulation = connector
                .handle_simulate(json!({
                    "type": "simulate", "id": "invalid-page", "connector_id": "github",
                    "operation": operation, "zone_id": "z:work", "input": input,
                    "capability_token": token, "estimate_cost": false, "check_availability": false
                }))
                .await
                .unwrap();
            assert_eq!(
                simulation["would_succeed"], false,
                "simulation must reject {input}"
            );
            let error = connector
                .handle_invoke(json!({
                    "operation": operation, "input": input, "capability_token": token
                }))
                .await
                .unwrap_err();
            assert!(
                matches!(error, fcp_core::FcpError::InvalidRequest { .. }),
                "{operation}: {error}"
            );
        }
        if operation != "github.list_workflows" {
            let token = generate_valid_bound_token(&key, &connector, operation);
            let error = connector.handle_invoke(json!({
                "operation": operation, "input": { "query": "test", "page": 11 }, "capability_token": token
            })).await.unwrap_err();
            assert!(matches!(error, fcp_core::FcpError::InvalidRequest { .. }));
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::test]
async fn content_ref_and_workflow_inputs_reject_invalid_shapes_before_network() {
    let server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let key = setup_handshake(
        &mut connector,
        &["github.get_file_content", "github.trigger_workflow"],
    )
    .await;
    for git_ref in [json!(null), json!(4), json!(""), json!("  ")] {
        let token = generate_valid_bound_token(&key, &connector, "github.get_file_content");
        let error = connector.handle_invoke(json!({
            "operation": "github.get_file_content",
            "input": { "owner": "octocat", "repo": "hello-world", "path": "README.md", "ref": git_ref },
            "capability_token": token
        })).await.unwrap_err();
        assert!(matches!(error, fcp_core::FcpError::InvalidRequest { .. }));
    }
    let too_many: serde_json::Map<String, serde_json::Value> = (0..26)
        .map(|index| (format!("input{index}"), json!("value")))
        .collect();
    for inputs in [json!(null), json!([]), json!("a=b"), json!(too_many)] {
        let token = generate_valid_bound_token(&key, &connector, "github.trigger_workflow");
        let error = connector.handle_invoke(json!({
            "operation": "github.trigger_workflow",
            "input": { "owner": "octocat", "repo": "hello-world", "workflow_id": "ci.yml", "ref": "main", "inputs": inputs },
            "capability_token": token
        })).await.unwrap_err();
        assert!(matches!(error, fcp_core::FcpError::InvalidRequest { .. }));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::test]
async fn pagination_and_content_schemas_match_manifest_and_introspection() {
    let manifest =
        fcp_manifest::ConnectorManifest::parse_str_unchecked(include_str!("../manifest.toml"))
            .unwrap();
    let introspection = GitHubConnector::new().handle_introspect().await.unwrap();
    for operation in [
        "github.search_issues",
        "github.search_repos",
        "github.search_code",
        "github.list_workflows",
        "github.get_file_content",
    ] {
        let runtime = introspection["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == operation)
            .unwrap();
        let declared = &manifest.provides.operations[operation];
        assert_eq!(
            runtime["input_schema"], declared.input_schema,
            "input schema for {operation}"
        );
        assert_eq!(
            runtime["output_schema"], declared.output_schema,
            "output schema for {operation}"
        );
    }
}

/// Search code.
#[fcp_async_core::test]
async fn search_code_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("github.search_code.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1,
            "incomplete_results": false,
            "items": [{
                "name": "main.rs",
                "path": "src/main.rs",
                "sha": "def456",
                "html_url": "https://github.com/octocat/hello-world/blob/main/src/main.rs",
                "repository": {
                    "id": 1_296_269,
                    "name": "hello-world",
                    "full_name": "octocat/hello-world",
                    "html_url": "https://github.com/octocat/hello-world"
                }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_code"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.search_code");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.search_code",
            "input": { "query": "addClass repo:octocat/hello-world" },
            "capability_token": token
        }))
        .await
        .expect("search_code should succeed");

    assert_eq!(result["total_count"], 1);
    assert_eq!(result["items"].as_array().unwrap().len(), 1);
}

// ============================================================================
// Error Taxonomy Tests (401/404/422/429/409/500 -> `FcpError` mapping)
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
#[fcp_async_core::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("github.error.401");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(github_error_response("Bad credentials")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
        .await
        .expect_err("should fail with 401");

    assert!(
        matches!(err, fcp_github::error::GitHubError::Unauthorized),
        "expected Unauthorized, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "expected FcpError::Unauthorized, got: {fcp_err:?}"
    );
}

/// 404 Not Found maps to `FcpError::ResourceNotFound`.
#[fcp_async_core::test]
async fn error_404_maps_to_not_found() {
    let _ctx = AsyncTestContext::for_scenario("github.error.404");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(github_error_response("Not Found")))
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "nonexistent")
        .await
        .expect_err("should fail with 404");

    assert!(
        matches!(err, fcp_github::error::GitHubError::NotFound { .. }),
        "expected NotFound, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "expected FcpError::ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 422 Validation Error maps to `FcpError::InvalidRequest`.
#[fcp_async_core::test]
async fn error_422_maps_to_invalid_request() {
    let _ctx = AsyncTestContext::for_scenario("github.error.422");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/repos/octocat/hello-world/issues"))
        .respond_with(
            ResponseTemplate::new(422).set_body_json(github_error_response("Validation Failed")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .create_issue(
            "octocat",
            "hello-world",
            &fcp_github::types::CreateIssueRequest {
                title: String::new(),
                body: None,
                assignees: None,
                labels: None,
                milestone: None,
            },
        )
        .await
        .expect_err("should fail with 422");

    assert!(
        matches!(err, fcp_github::error::GitHubError::ValidationError { .. }),
        "expected ValidationError, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected FcpError::InvalidRequest, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[fcp_async_core::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("github.error.429");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(github_error_response("API rate limit exceeded")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
        .await
        .expect_err("should fail with 429");

    assert!(
        matches!(err, fcp_github::error::GitHubError::RateLimited { .. }),
        "expected RateLimited, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "expected FcpError::RateLimited, got: {fcp_err:?}"
    );
}

/// 409 Conflict maps to `FcpError::Conflict`.
#[fcp_async_core::test]
async fn error_409_maps_to_conflict() {
    let _ctx = AsyncTestContext::for_scenario("github.error.409");
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/repos/octocat/hello-world/pulls/1/merge"))
        .respond_with(
            ResponseTemplate::new(409)
                .set_body_json(github_error_response("Pull Request is not mergeable")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .merge_pull_request(
            "octocat",
            "hello-world",
            1,
            &fcp_github::types::MergePullRequestRequest {
                commit_title: None,
                commit_message: None,
                merge_method: Some("merge".into()),
                sha: None,
            },
        )
        .await
        .expect_err("should fail with 409");

    assert!(
        matches!(err, fcp_github::error::GitHubError::MergeConflict { .. }),
        "expected MergeConflict, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Conflict { .. }),
        "expected FcpError::Conflict, got: {fcp_err:?}"
    );
}

/// 500 Server Error maps to `FcpError::External` with `retryable`=true.
#[fcp_async_core::test]
async fn error_500_maps_to_external() {
    let _ctx = AsyncTestContext::for_scenario("github.error.500");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(github_error_response("Internal server error")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
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
            assert_eq!(service, "github");
            assert!(retryable, "500 should be retryable");
            assert_eq!(*status_code, Some(500));
        }
        other => panic!("expected FcpError::External, got: {other:?}"),
    }
}

/// Error `is_retryable` classification is correct.
#[test]
fn error_retryable_classification() {
    use fcp_github::error::GitHubError;

    assert!(
        GitHubError::RateLimited {
            retry_after_ms: 1000
        }
        .is_retryable()
    );
    assert!(
        GitHubError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            documentation_url: None,
        }
        .is_retryable()
    );
    assert!(
        GitHubError::Api {
            message: "Service unavailable".into(),
            status_code: Some(503),
            documentation_url: None,
        }
        .is_retryable()
    );

    assert!(!GitHubError::Unauthorized.is_retryable());
    assert!(
        !GitHubError::NotFound {
            resource: "test".into()
        }
        .is_retryable()
    );
    assert!(
        !GitHubError::ValidationError {
            message: "bad input".into()
        }
        .is_retryable()
    );
}

// ============================================================================
// FCP2 Default-Deny / Capability Verification Tests
// ============================================================================

/// Invoke without `capability_token` fails.
#[fcp_async_core::test]
async fn capability_missing_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.capability.missing_token");
    let mock_server = MockServer::start().await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    setup_handshake(&mut connector, &["github.get_repo"]).await;

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" }
        }))
        .await
        .expect_err("invoke without token should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing token, got: {err:?}"
    );
}

/// Invoke before handshake fails (no verifier).
#[fcp_async_core::test]
async fn capability_no_handshake_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.capability.no_handshake");
    let mock_server = MockServer::start().await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_repo");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
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
#[fcp_async_core::test]
async fn capability_no_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.capability.no_configure");

    let mut connector = GitHubConnector::new();
    let signing_key = setup_handshake(&mut connector, &["github.get_repo"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_repo");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without configure should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Token signed for wrong operation fails.
#[fcp_async_core::test]
async fn capability_wrong_operation_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.capability.wrong_op");
    let mock_server = MockServer::start().await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["github.get_repo", "github.create_issue"]).await;

    let wrong_token = generate_valid_bound_token(&signing_key, &connector, "github.create_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
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
#[fcp_async_core::test]
async fn capability_unknown_operation_fails() {
    let mock_server = MockServer::start().await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.nonexistent"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.nonexistent");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.nonexistent",
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

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health check before configure reports `not_configured`.
#[fcp_async_core::test]
async fn lifecycle_health_before_configure() {
    let connector = GitHubConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

/// Health check after configure reports healthy.
#[fcp_async_core::test]
async fn lifecycle_health_after_configure() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

/// Handshake returns accepted with capabilities granted.
#[fcp_async_core::test]
async fn lifecycle_handshake_grants_capabilities() {
    let mut connector = GitHubConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["github.read", "github.write", "github.admin"]
        }))
        .await
        .expect("handshake should succeed");

    assert_eq!(result["status"], "accepted");
    let caps = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

/// Shutdown returns clean status.
#[fcp_async_core::test]
async fn lifecycle_shutdown_clean() {
    let connector = GitHubConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

/// Introspect exposes all 12 operations with schemas.
#[fcp_async_core::test]
async fn lifecycle_introspect_all_operations() {
    let connector = GitHubConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    let expected_ops = [
        "github.create_issue",
        "github.get_issue",
        "github.search_issues",
        "github.create_pull_request",
        "github.get_pull_request",
        "github.merge_pull_request",
        "github.get_repo",
        "github.search_repos",
        "github.list_workflows",
        "github.trigger_workflow",
        "github.get_file_content",
        "github.search_code",
        "github.process_webhook",
    ];

    for expected in &expected_ops {
        assert!(op_ids.contains(expected), "missing operation: {expected}");
    }
    assert_eq!(ops.len(), 13);

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

/// Missing `owner` in `get_issue` fails.
#[fcp_async_core::test]
async fn validation_get_issue_missing_owner() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_issue"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_issue",
            "input": { "repo": "hello-world", "issue_number": 42 },
            "capability_token": token
        }))
        .await
        .expect_err("missing owner should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("owner"),
                "error should mention `owner`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `repo` in `get_issue` fails.
#[fcp_async_core::test]
async fn validation_get_issue_missing_repo() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_issue"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_issue",
            "input": { "owner": "octocat", "issue_number": 42 },
            "capability_token": token
        }))
        .await
        .expect_err("missing repo should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("repo"),
                "error should mention `repo`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `issue_number` in `get_issue` fails.
#[fcp_async_core::test]
async fn validation_get_issue_missing_number() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_issue"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_issue",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect_err("missing issue_number should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("issue_number"),
                "error should mention `issue_number`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `title` in `create_issue` fails.
#[fcp_async_core::test]
async fn validation_create_issue_missing_title() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.create_issue"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.create_issue");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.create_issue",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect_err("missing title should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("title"),
                "error should mention `title`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `head` in `create_pull_request` fails.
#[fcp_async_core::test]
async fn validation_create_pr_missing_head() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.create_pull_request"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.create_pull_request");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.create_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "title": "Fix typo",
                "base": "main"
            },
            "capability_token": token
        }))
        .await
        .expect_err("missing head should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("head"),
                "error should mention `head`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `query` in `search_issues` fails.
#[fcp_async_core::test]
async fn validation_search_issues_missing_query() {
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_issues"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.search_issues");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.search_issues",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing query should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("query"),
                "error should mention `query`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

// ============================================================================
// Additional Error Taxonomy Tests
// ============================================================================

/// 403 with x-ratelimit-remaining: 0 is a secondary rate limit.
#[fcp_async_core::test]
async fn error_403_secondary_rate_limit() {
    let _ctx = AsyncTestContext::for_scenario("github.error.403_secondary_rate_limit");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(github_error_response(
                    "You have exceeded a secondary rate limit",
                ))
                .insert_header("x-ratelimit-remaining", "0")
                .insert_header("retry-after", "120"),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
        .await
        .expect_err("should fail with 403 secondary rate limit");

    assert!(
        matches!(err, fcp_github::error::GitHubError::RateLimited { .. }),
        "expected RateLimited for secondary rate limit, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "expected FcpError::RateLimited, got: {fcp_err:?}"
    );
}

/// 403 without rate-limit headers is a permission denied (maps to Unauthorized).
#[fcp_async_core::test]
async fn error_403_permission_denied() {
    let _ctx = AsyncTestContext::for_scenario("github.error.403_permission");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(github_error_response(
                "Resource not accessible by integration",
            )),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
        .await
        .expect_err("should fail with 403 permission denied");

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "expected FcpError::Unauthorized for 403 without rate limit headers, got: {fcp_err:?}"
    );
}

/// 503 Service Unavailable maps to retryable External error.
#[fcp_async_core::test]
async fn error_503_maps_to_external_retryable() {
    let _ctx = AsyncTestContext::for_scenario("github.error.503");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_json(github_error_response("Service temporarily unavailable")),
        )
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
        .await
        .expect_err("should fail with 503");

    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            service,
            retryable,
            status_code,
            ..
        } => {
            assert_eq!(service, "github");
            assert!(retryable, "503 should be retryable");
            assert_eq!(*status_code, Some(503));
        }
        other => panic!("expected FcpError::External, got: {other:?}"),
    }
}

/// Non-JSON error body is handled gracefully.
#[fcp_async_core::test]
async fn error_non_json_response_body() {
    let _ctx = AsyncTestContext::for_scenario("github.error.non_json");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .mount(&mock_server)
        .await;

    let client = GitHubClient::new("token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let err = client
        .get_repo("octocat", "hello-world")
        .await
        .expect_err("should fail with 502 non-JSON");

    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            service,
            status_code,
            ..
        } => {
            assert_eq!(service, "github");
            assert_eq!(*status_code, Some(502));
        }
        other => panic!("expected FcpError::External, got: {other:?}"),
    }
}

// ============================================================================
// Configuration Tests
// ============================================================================

/// Providing a raw token field fails even when credential_id is also present.
#[fcp_async_core::test]
async fn config_both_token_and_credential_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.config.both_auth");
    let mut connector = GitHubConnector::new();

    let err = connector
        .handle_configure(json!({
            "token": "ghp_test",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await
        .expect_err("should fail when both token and credential_id provided");

    match &err {
        fcp_core::FcpError::ConfigurationLeakedSecret { detector, .. } => {
            assert_eq!(detector, "raw_secret_config_field");
        }
        other => panic!("expected ConfigurationLeakedSecret, got: {other:?}"),
    }
}

/// Missing both token and credential_id fails.
#[fcp_async_core::test]
async fn config_missing_auth_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.config.no_auth");
    let mut connector = GitHubConnector::new();

    let err = connector
        .handle_configure(json!({
            "base_url": "https://api.example.com"
        }))
        .await
        .expect_err("should fail when no auth provided");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("token") || message.contains("credential_id"),
                "error should mention missing auth: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Configure with credential_id succeeds.
#[fcp_async_core::test]
async fn config_credential_id_mode() {
    let _ctx = AsyncTestContext::for_scenario("github.config.credential_id");
    let mut connector = GitHubConnector::new();

    let result = connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await
        .expect("credential_id config should succeed");

    assert_eq!(result["status"], "configured");
}

/// Invalid credential_id (bad UUID) fails.
#[fcp_async_core::test]
async fn config_invalid_credential_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("github.config.bad_credential");
    let mut connector = GitHubConnector::new();

    let err = connector
        .handle_configure(json!({
            "credential_id": "not-a-valid-uuid"
        }))
        .await
        .expect_err("invalid credential_id should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("credential_id"),
                "error should mention credential_id: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Custom base_url is used for API requests.
#[fcp_async_core::test]
async fn config_custom_base_url() {
    let _ctx = AsyncTestContext::for_scenario("github.config.custom_base_url");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .and(header("X-FCP-Credential-ID", TEST_CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1_296_269,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
            "description": "Custom endpoint",
            "private": false,
            "fork": false,
            "html_url": "https://github.example.com/octocat/hello-world",
            "default_branch": "main",
            "language": "Rust",
            "stargazers_count": 99,
            "forks_count": 10,
            "open_issues_count": 5,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": mock_server.uri()
        }))
        .await
        .expect("configure with custom base_url should succeed");

    let signing_key = setup_handshake(&mut connector, &["github.get_repo"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_repo");

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect("get_repo via custom base_url should succeed");

    assert_eq!(result["repository"]["stargazers_count"], 99);
}

// ============================================================================
// Doctor & SelfCheck Tests
// ============================================================================

/// Doctor before configure reports unhealthy.
#[fcp_async_core::test]
async fn doctor_before_configure() {
    let _ctx = AsyncTestContext::for_scenario("github.doctor.before_configure");
    let connector = GitHubConnector::new();

    let result = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed even unconfigured");

    assert_eq!(result["status"], "unhealthy");
    let checks = result["checks"].as_array().unwrap();
    let config_check = checks
        .iter()
        .find(|c| c["name"] == "configuration")
        .unwrap();
    assert_eq!(config_check["status"], "fail");
}

/// Doctor after secretless configure reports degraded until an egress injector is present.
#[fcp_async_core::test]
async fn doctor_after_configure() {
    let _ctx = AsyncTestContext::for_scenario("github.doctor.after_configure");
    let mock_server = MockServer::start().await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed");

    assert_eq!(result["status"], "degraded");
    let checks = result["checks"].as_array().unwrap();
    let config_check = checks
        .iter()
        .find(|c| c["name"] == "configuration")
        .unwrap();
    assert_eq!(config_check["status"], "pass");
    let client_check = checks
        .iter()
        .find(|c| c["name"] == "client_initialized")
        .unwrap();
    assert_eq!(client_check["status"], "pass");
    let cred_check = checks
        .iter()
        .find(|c| c["name"] == "credential_injection")
        .unwrap();
    assert_eq!(cred_check["status"], "warn");
}

/// Doctor with credential_id mode reports degraded (warn on credential_injection).
#[fcp_async_core::test]
async fn doctor_credential_id_mode_degraded() {
    let _ctx = AsyncTestContext::for_scenario("github.doctor.credential_id");
    let mut connector = GitHubConnector::new();

    connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await
        .expect("configure should succeed");

    let result = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed");

    // All pass except credential_injection is warn => overall "degraded"
    assert_eq!(
        result["status"], "degraded",
        "doctor should be degraded with credential_id auth: {result}"
    );

    let checks = result["checks"].as_array().unwrap();
    let cred_check = checks
        .iter()
        .find(|c| c["name"] == "credential_injection")
        .unwrap();
    assert_eq!(cred_check["status"], "warn");
}

/// SelfCheck before configure reports failed.
#[fcp_async_core::test]
async fn self_check_before_configure() {
    let _ctx = AsyncTestContext::for_scenario("github.self_check.before_configure");
    let connector = GitHubConnector::new();

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should return a report");

    assert_eq!(result["status"], "failed");
}

/// SelfCheck with credential_id mode reports degraded.
#[fcp_async_core::test]
async fn self_check_credential_id_mode() {
    let _ctx = AsyncTestContext::for_scenario("github.self_check.credential_id");
    let mut connector = GitHubConnector::new();

    connector
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await
        .expect("configure should succeed");

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should return a report");

    assert_eq!(result["status"], "degraded");
}

/// SelfCheck in secretless mode reports degraded without an egress injector.
#[fcp_async_core::test]
async fn self_check_connectivity_ok() {
    let _ctx = AsyncTestContext::for_scenario("github.self_check.ok");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "login": "octocat",
            "id": 1
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should return a report");

    assert_eq!(result["status"], "degraded");
    assert_eq!(result["reason_code"], "credential_injection_required");
}

/// SelfCheck does not expose raw connectivity status before credential injection.
#[fcp_async_core::test]
async fn self_check_connectivity_failed() {
    let _ctx = AsyncTestContext::for_scenario("github.self_check.failed");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(github_error_response("Bad credentials")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should return a report");

    assert_eq!(result["status"], "degraded");
    assert_eq!(result["reason_code"], "credential_injection_required");
}

// ============================================================================
// Simulate Tests
// ============================================================================

/// Simulate returns allowed for known operation.
#[fcp_async_core::test]
async fn simulate_returns_allowed() {
    let _ctx = AsyncTestContext::for_scenario("github.simulate.allowed");
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.read"]).await;

    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_repo");

    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "req-001",
            "connector_id": "github",
            "operation": "github.get_repo",
            "zone_id": "z:work",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token,
            "estimate_cost": false,
            "check_availability": false
        }))
        .await
        .expect("simulate should succeed");

    assert!(
        result["would_succeed"].as_bool().unwrap(),
        "simulate should return would_succeed=true"
    );
}

// ============================================================================
// Additional Lifecycle Tests
// ============================================================================

/// Health check includes metrics fields.
#[fcp_async_core::test]
async fn health_includes_metrics() {
    let _ctx = AsyncTestContext::for_scenario("github.health.metrics");
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");

    assert!(result["metrics"].is_object(), "metrics should be an object");
    assert!(
        result["metrics"]["requests_total"].is_number(),
        "requests_total should be present"
    );
    assert!(
        result["metrics"]["requests_error"].is_number(),
        "requests_error should be present"
    );
}

/// Health check reports auth_mode field.
#[fcp_async_core::test]
async fn health_auth_mode_field() {
    let _ctx = AsyncTestContext::for_scenario("github.health.auth_mode");
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");

    assert_eq!(result["auth_mode"], "credential_id");

    // Also check credential_id mode
    let mut connector2 = GitHubConnector::new();
    connector2
        .handle_configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .await
        .expect("configure should succeed");

    let result2 = connector2
        .handle_health()
        .await
        .expect("health should succeed");

    assert_eq!(result2["auth_mode"], "credential_id");
}

/// Shutdown transitions the connector out of the invokable lifecycle state.
#[fcp_async_core::test]
async fn shutdown_then_reinvoke() {
    let _ctx = AsyncTestContext::for_scenario("github.lifecycle.shutdown_reinvoke");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1_296_269,
            "name": "hello-world",
            "full_name": "octocat/hello-world",
            "owner": { "login": "octocat", "id": 1, "avatar_url": "", "type": "User" },
            "description": "Test",
            "private": false,
            "fork": false,
            "html_url": "https://github.com/octocat/hello-world",
            "default_branch": "main",
            "language": "Rust",
            "stargazers_count": 1,
            "forks_count": 0,
            "open_issues_count": 0,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_repo"]).await;

    // Shutdown
    let shutdown_result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(shutdown_result["status"], "shutdown");

    // Verify that health reports the lifecycle transition.
    let health_result = connector
        .handle_health()
        .await
        .expect("health after shutdown should still work");
    assert_eq!(health_result["status"], "shutdown");

    // Invoke fails at the connector lifecycle gate instead of leaking a cancelled HTTP request.
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_repo");
    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": { "owner": "octocat", "repo": "hello-world" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke after shutdown should fail");
    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured after shutdown, got: {err:?}"
    );
}

// ============================================================================
// Additional Input Validation Edge Cases
// ============================================================================

/// Missing `base` in `create_pull_request` fails.
#[fcp_async_core::test]
async fn validation_create_pr_missing_base() {
    let _ctx = AsyncTestContext::for_scenario("github.validation.create_pr.missing_base");
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.create_pull_request"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.create_pull_request");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.create_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "title": "Fix typo",
                "head": "feature"
            },
            "capability_token": token
        }))
        .await
        .expect_err("missing base should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("base"),
                "error should mention `base`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `ref` in `trigger_workflow` fails.
#[fcp_async_core::test]
async fn validation_trigger_workflow_missing_ref() {
    let _ctx = AsyncTestContext::for_scenario("github.validation.trigger_workflow.missing_ref");
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.trigger_workflow"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.trigger_workflow");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.trigger_workflow",
            "input": {
                "owner": "octocat",
                "repo": "hello-world",
                "workflow_id": "ci.yml"
            },
            "capability_token": token
        }))
        .await
        .expect_err("missing ref should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("ref"),
                "error should mention `ref`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `path` in `get_file_content` fails.
#[fcp_async_core::test]
async fn validation_get_file_content_missing_path() {
    let _ctx = AsyncTestContext::for_scenario("github.validation.get_file_content.missing_path");
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.get_file_content"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.get_file_content");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_file_content",
            "input": {
                "owner": "octocat",
                "repo": "hello-world"
            },
            "capability_token": token
        }))
        .await
        .expect_err("missing path should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("path"),
                "error should mention `path`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `pull_number` in `merge_pull_request` fails.
#[fcp_async_core::test]
async fn validation_merge_pr_missing_pull_number() {
    let _ctx = AsyncTestContext::for_scenario("github.validation.merge_pr.missing_pull_number");
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.merge_pull_request"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.merge_pull_request");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.merge_pull_request",
            "input": {
                "owner": "octocat",
                "repo": "hello-world"
            },
            "capability_token": token
        }))
        .await
        .expect_err("missing pull_number should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("pull_number"),
                "error should mention `pull_number`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `query` in `search_repos` fails.
#[fcp_async_core::test]
async fn validation_search_repos_missing_query() {
    let _ctx = AsyncTestContext::for_scenario("github.validation.search_repos.missing_query");
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_repos"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.search_repos");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.search_repos",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing query should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("query"),
                "error should mention `query`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing `query` in `search_code` fails.
#[fcp_async_core::test]
async fn validation_search_code_missing_query() {
    let _ctx = AsyncTestContext::for_scenario("github.validation.search_code.missing_query");
    let mock_server = MockServer::start().await;
    let mut connector = GitHubConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["github.search_code"]).await;
    let token = generate_valid_bound_token(&signing_key, &connector, "github.search_code");

    let err = connector
        .handle_invoke(json!({
            "operation": "github.search_code",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing query should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("query"),
                "error should mention `query`: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

// ============================================================================
// Introspect Detail Tests
// ============================================================================

/// Introspect operations have ai_hints with when_to_use for all ops.
#[fcp_async_core::test]
async fn introspect_operations_have_ai_hints() {
    let _ctx = AsyncTestContext::for_scenario("github.introspect.ai_hints");
    let connector = GitHubConnector::new();

    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();
    for op in ops {
        let id = op["id"].as_str().unwrap();
        assert!(
            op["ai_hints"].is_object(),
            "ai_hints should be object for {id}"
        );
        let when_to_use = op["ai_hints"]["when_to_use"].as_str();
        assert!(
            when_to_use.is_some() && !when_to_use.unwrap().is_empty(),
            "ai_hints.when_to_use should be non-empty for {id}"
        );
    }
}

/// Introspect operations have correct capability groupings.
#[fcp_async_core::test]
async fn introspect_capability_groupings() {
    let _ctx = AsyncTestContext::for_scenario("github.introspect.capability_groups");
    let connector = GitHubConnector::new();

    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();

    // Read operations should have github.read capability
    let read_ops = [
        "github.get_issue",
        "github.search_issues",
        "github.get_pull_request",
        "github.get_repo",
        "github.search_repos",
        "github.list_workflows",
        "github.get_file_content",
        "github.search_code",
    ];
    for op_id in &read_ops {
        let op = ops
            .iter()
            .find(|o| o["id"].as_str() == Some(op_id))
            .unwrap();
        assert_eq!(
            op["capability"].as_str(),
            Some("github.read"),
            "{op_id} should have github.read capability"
        );
    }

    // Write operations should have github.write capability
    let write_ops = ["github.create_issue", "github.create_pull_request"];
    for op_id in &write_ops {
        let op = ops
            .iter()
            .find(|o| o["id"].as_str() == Some(op_id))
            .unwrap();
        assert_eq!(
            op["capability"].as_str(),
            Some("github.write"),
            "{op_id} should have github.write capability"
        );
    }

    // Admin operations should have github.admin capability
    let admin_ops = ["github.merge_pull_request", "github.trigger_workflow"];
    for op_id in &admin_ops {
        let op = ops
            .iter()
            .find(|o| o["id"].as_str() == Some(op_id))
            .unwrap();
        assert_eq!(
            op["capability"].as_str(),
            Some("github.admin"),
            "{op_id} should have github.admin capability"
        );
    }
}

/// Introspect operations have risk_level and safety_tier fields.
#[fcp_async_core::test]
async fn introspect_risk_and_safety() {
    let _ctx = AsyncTestContext::for_scenario("github.introspect.risk_safety");
    let connector = GitHubConnector::new();

    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();
    for op in ops {
        let id = op["id"].as_str().unwrap();
        assert!(
            op["risk_level"].as_str().is_some(),
            "risk_level should be present for {id}"
        );
        assert!(
            op["safety_tier"].as_str().is_some(),
            "safety_tier should be present for {id}"
        );
    }

    // Merge PR should be high risk
    let merge_op = ops
        .iter()
        .find(|o| o["id"].as_str() == Some("github.merge_pull_request"))
        .unwrap();
    assert_eq!(merge_op["risk_level"].as_str(), Some("high"));
}
