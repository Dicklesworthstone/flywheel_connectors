//! Live verification tests for the `OpenAI` connector against the real `OpenAI` API.
//!
//! These tests require an `OPENAI_API_KEY` environment variable with a valid
//! `OpenAI` API key. When the key is absent, tests skip gracefully with a
//! descriptive message.
//!
//! The chat completion test uses `openai.simple_chat` with a trivial prompt
//! and `max_tokens: 5` to minimise cost. No fine-tuning, image generation,
//! or other write-heavy operations are exercised.

use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_openai::connector::OpenAIConnector;
use fcp_prelude::{CapabilityConstraints, CapabilityToken};

use chrono::{Duration, Utc};
use serde_json::json;

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";

// ============================================================================
// Skip guard
// ============================================================================

fn openai_api_key() -> Option<String> {
    std::env::var("OPENAI_API_KEY")
        .ok()
        .filter(|k| !k.is_empty())
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
        "SKIP: {LIVE_GATE_ENV} is not enabled; set {LIVE_GATE_ENV}=1 before running live OpenAI connector verification."
    );
    true
}

macro_rules! skip_without_token {
    ($var:ident) => {
        if skip_without_live_gate() {
            return;
        }
        let Some($var) = openai_api_key() else {
            eprintln!(
                "SKIP: OPENAI_API_KEY not set — skipping live OpenAI connector verification. \
                 Set OPENAI_API_KEY before running this test to enable it."
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
        .capability_id("openai.chat")
        .zone_id("z:work")
        .principal("user:live-test")
        .operations(&[op])
        .issuer("node:live-test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_live_connector(connector: &mut OpenAIConnector, api_key: &str) -> Ed25519SigningKey {
    // Configure with real OpenAI API key
    connector
        .handle_configure(json!({
            "api_key": api_key,
        }))
        .await
        .expect("configure with real API key should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["openai.chat"]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Live verification tests
// ============================================================================

#[fcp_async_core::test]
async fn live_chat_completions() {
    skip_without_token!(api_key);

    let mut connector = OpenAIConnector::new();
    let signing_key = setup_live_connector(&mut connector, &api_key).await;
    let capability =
        generate_read_token(&signing_key, connector.instance_id(), "openai.simple_chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": {
                "message": "Say the word 'hello' and nothing else.",
                "max_tokens": 5
            },
            "capability_token": capability
        }))
        .await
        .expect("simple_chat invoke should succeed");

    // Verify response has content
    let reply = result["reply"]
        .as_str()
        .or_else(|| result["content"].as_str())
        .or_else(|| result["message"].as_str())
        .or_else(|| result["text"].as_str());
    assert!(
        reply.is_some(),
        "response should contain a text reply field: {result}"
    );
    let reply = reply.unwrap();
    assert!(!reply.is_empty(), "reply should not be empty");

    eprintln!(
        "PASS: live_chat_completions — got reply: {:?}",
        &reply[..reply.len().min(80)]
    );
}

#[fcp_async_core::test]
async fn live_error_mapping_invalid_key() {
    if skip_without_live_gate() {
        return;
    }

    // Test with a deliberately invalid API key to verify ConnectorErrorMapping
    // works correctly: should get a structured FCP auth error, not a raw HTTP 401.
    let mut connector = OpenAIConnector::new();

    // Configure with an obviously invalid key
    connector
        .handle_configure(json!({
            "api_key": "sk-invalid-key-000000000000000000000000000000000000000000",
        }))
        .await
        .expect("configure should succeed even with bad key");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["openai.chat"]
        }))
        .await
        .expect("handshake should succeed");

    let capability =
        generate_read_token(&signing_key, connector.instance_id(), "openai.simple_chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": {
                "message": "Hello"
            },
            "capability_token": capability
        }))
        .await;

    // The error should be a structured FCP error, not a raw HTTP status
    assert!(
        err.is_err(),
        "invoke with invalid API key should return an error"
    );
    let fcp_err = err.unwrap_err();
    let err_str = format!("{fcp_err}");
    // Should contain structured error info indicating auth failure
    assert!(
        err_str.contains("401")
            || err_str.to_lowercase().contains("unauthorized")
            || err_str.to_lowercase().contains("auth")
            || err_str.to_lowercase().contains("credential")
            || err_str.to_lowercase().contains("invalid")
            || err_str.to_lowercase().contains("incorrect"),
        "error should indicate auth failure: got '{err_str}'"
    );

    eprintln!("PASS: live_error_mapping_invalid_key — got structured error: {err_str}");
}

#[fcp_async_core::test]
async fn live_health_check() {
    skip_without_token!(api_key);

    let mut connector = OpenAIConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &api_key).await;

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
async fn live_introspect() {
    skip_without_token!(api_key);

    let mut connector = OpenAIConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &api_key).await;

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Should list operations (OpenAI has 22+)
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
        "OpenAI connector should have at least 10 operations, got {}",
        ops.len()
    );

    eprintln!("PASS: live_introspect — {} operations reported", ops.len());
}
