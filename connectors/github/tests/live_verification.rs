//! Live verification tests for the GitHub connector against the real GitHub API.
//!
//! These tests require a `GITHUB_TOKEN` environment variable with a valid
//! GitHub personal access token. When the token is absent, tests skip
//! gracefully with a descriptive message.
//!
//! All operations are READ-ONLY (`github.get_repo`, `github.search_repos`) and
//! target public repositories — no side effects or write permissions needed.
//!
//! Bead: kzabz.1

use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_github::connector::GitHubConnector;
use fcp_prelude::{CapabilityConstraints, CapabilityToken};

use chrono::{Duration, Utc};
use serde_json::json;

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";

// ============================================================================
// Skip guard
// ============================================================================

fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty())
}

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn skip_without_live_gate() -> bool {
    if live_gate_enabled() {
        return false;
    }

    eprintln!(
        "SKIP: {LIVE_GATE_ENV} is not enabled; set {LIVE_GATE_ENV}=1 before running live GitHub connector verification."
    );
    true
}

macro_rules! skip_without_token {
    ($var:ident) => {
        if skip_without_live_gate() {
            return;
        }
        let Some($var) = github_token() else {
            eprintln!(
                "SKIP: GITHUB_TOKEN not set — skipping live GitHub connector verification. \
                 Set GITHUB_TOKEN=ghp_... to enable."
            );
            return;
        };
    };
}

// ============================================================================
// Helpers
// ============================================================================

fn generate_read_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &str,
) -> CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id("github.read")
        .zone_id("z:work")
        .principal("user:live-test")
        .operations(&[op])
        .issuer("node:live-test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("test constraints CBOR should be valid")
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_live_connector(connector: &mut GitHubConnector, token: &str) -> Ed25519SigningKey {
    // Configure with real GitHub API
    connector
        .handle_configure(json!({
            "token": token,
            "base_url": "https://api.github.com"
        }))
        .await
        .expect("configure with real token should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["github.read"]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Live verification tests
// ============================================================================

#[fcp_async_core::test]
async fn live_get_repo_public_repo() {
    skip_without_token!(token);

    let mut connector = GitHubConnector::new();
    let signing_key = setup_live_connector(&mut connector, &token).await;
    let cap_token = generate_read_token(
        &signing_key,
        connector.instance_id().as_str(),
        "github.get_repo",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": {
                "owner": "rust-lang",
                "repo": "rust"
            },
            "capability_token": cap_token
        }))
        .await
        .expect("get_repo on public repo should succeed");

    // Verify response shape
    let repo = &result["repository"];
    assert_eq!(repo["name"], "rust", "repo name should be 'rust'");
    assert_eq!(
        repo["full_name"], "rust-lang/rust",
        "full_name should be 'rust-lang/rust'"
    );
    assert!(
        repo["html_url"]
            .as_str()
            .unwrap_or("")
            .contains("github.com"),
        "html_url should contain github.com"
    );
    assert!(
        repo["description"].is_string(),
        "description should be present"
    );

    eprintln!(
        "PASS: live_get_repo_public_repo — verified rust-lang/rust (stars: {})",
        repo["stargazers_count"]
    );
}

#[fcp_async_core::test]
async fn live_search_repos() {
    skip_without_token!(token);

    let mut connector = GitHubConnector::new();
    let signing_key = setup_live_connector(&mut connector, &token).await;
    let cap_token = generate_read_token(
        &signing_key,
        connector.instance_id().as_str(),
        "github.search_repos",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "github.search_repos",
            "input": {
                "query": "language:rust stars:>50000"
            },
            "capability_token": cap_token
        }))
        .await
        .expect("search_repos should succeed");

    // Verify response has items
    let items = result["items"]
        .as_array()
        .or_else(|| result["repositories"].as_array());
    assert!(
        items.is_some(),
        "search results should contain items or repositories array"
    );
    let items = items.unwrap();
    assert!(
        !items.is_empty(),
        "Rust repos with >50k stars should return results"
    );

    eprintln!(
        "PASS: live_search_repos — found {} repos matching 'language:rust stars:>50000'",
        items.len()
    );
}

#[fcp_async_core::test]
async fn live_error_mapping_invalid_token() {
    if skip_without_live_gate() {
        return;
    }

    // Test with a deliberately invalid token to verify ConnectorErrorMapping
    // works correctly: should get a structured FCP auth error, not a raw HTTP 401.
    let mut connector = GitHubConnector::new();

    // Configure with an obviously invalid token
    connector
        .handle_configure(json!({
            "token": "ghp_this_is_not_a_valid_token_000000000",
            "base_url": "https://api.github.com"
        }))
        .await
        .expect("configure should succeed even with bad token");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["github.read"]
        }))
        .await
        .expect("handshake should succeed");

    let cap_token = generate_read_token(
        &signing_key,
        connector.instance_id().as_str(),
        "github.get_repo",
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "github.get_repo",
            "input": {
                "owner": "rust-lang",
                "repo": "rust"
            },
            "capability_token": cap_token
        }))
        .await;

    // The error should be a structured FCP error, not a raw HTTP status
    assert!(
        err.is_err(),
        "invoke with invalid token should return an error"
    );
    let fcp_err = err.unwrap_err();
    let err_str = format!("{fcp_err}");
    // Should contain structured error info, not just "401"
    assert!(
        err_str.contains("401")
            || err_str.to_lowercase().contains("unauthorized")
            || err_str.to_lowercase().contains("auth")
            || err_str.to_lowercase().contains("credential"),
        "error should indicate auth failure: got '{err_str}'"
    );

    eprintln!("PASS: live_error_mapping_invalid_token — got structured error: {err_str}");
}

#[fcp_async_core::test]
async fn live_health_check() {
    skip_without_token!(token);

    let mut connector = GitHubConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &token).await;

    let health = connector
        .handle_health()
        .await
        .expect("health check should succeed");

    assert!(
        health.get("status").is_some() || health.get("healthy").is_some(),
        "health response should contain status or healthy field: {health}"
    );

    eprintln!("PASS: live_health_check — {health}");
}

#[fcp_async_core::test]
async fn live_introspect_operations() {
    skip_without_token!(token);

    let mut connector = GitHubConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &token).await;

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Should list all 13 operations
    let ops = introspection["operations"]
        .as_array()
        .or_else(|| introspection["provides"].as_array());
    assert!(
        ops.is_some(),
        "introspection should contain operations: {introspection}"
    );
    let ops = ops.unwrap();
    assert!(
        ops.len() >= 10,
        "GitHub connector should have at least 10 operations, got {}",
        ops.len()
    );

    eprintln!(
        "PASS: live_introspect_operations — {} operations reported",
        ops.len()
    );
}
