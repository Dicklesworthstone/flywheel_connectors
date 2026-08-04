//! Live verification tests for the Telegram connector against the real Telegram Bot API.
//!
//! These tests require a `TELEGRAM_BOT_TOKEN` environment variable with a valid
//! Telegram bot token (e.g. `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`).
//! When the token is absent, tests skip gracefully with a descriptive message.
//!
//! All operations are READ-ONLY (health check calls `getMe`, `get_file` with a
//! nonexistent ID) — no messages are sent.

use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_prelude::{CapabilityConstraints, CapabilityToken};
use fcp_telegram::connector::TelegramConnector;

use chrono::{Duration, Utc};
use serde_json::json;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";

// ============================================================================
// Skip guard
// ============================================================================

fn telegram_token() -> Option<String> {
    std::env::var("TELEGRAM_BOT_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
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
        "SKIP: {LIVE_GATE_ENV} is not enabled; set {LIVE_GATE_ENV}=1 before running live Telegram bot verification."
    );
    true
}

macro_rules! skip_without_token {
    ($var:ident) => {
        if skip_without_live_gate() {
            return;
        }
        let Some($var) = telegram_token() else {
            eprintln!(
                "SKIP: TELEGRAM_BOT_TOKEN not set — skipping live Telegram connector verification. \
                 Set TELEGRAM_BOT_TOKEN to enable."
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
        .capability_id("telegram.read")
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

async fn setup_live_connector(connector: &mut TelegramConnector, token: &str) -> Ed25519SigningKey {
    // Configure with real Telegram Bot API — this calls getMe to validate
    connector
        .handle_configure(json!({
            "credential": token
        }))
        .await
        .expect("configure with real bot token should succeed");

    // Handshake — Telegram requires zone_dir for polling cursor persistence
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let zone_dir =
        std::env::temp_dir().join(format!("fcp-telegram-live-test-{}", std::process::id()));

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "zone_dir": zone_dir.to_string_lossy(),
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["telegram.read", "telegram.send"]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Live verification tests
// ============================================================================

#[fcp_async_core::test]
async fn live_get_me() {
    skip_without_token!(token);

    let mut connector = TelegramConnector::new();
    // configure calls getMe internally — success means the bot is reachable
    let result = connector
        .handle_configure(json!({
            "credential": token
        }))
        .await
        .expect("configure should succeed with valid bot token");

    // The configure response includes bot details
    assert_eq!(
        result["status"], "configured",
        "status should be 'configured'"
    );
    let details = &result["details"];
    assert!(
        details.get("bot_id").is_some(),
        "details should contain bot_id: {result}"
    );
    assert!(
        details.get("username").is_some(),
        "details should contain username: {result}"
    );

    eprintln!(
        "PASS: live_get_me — verified bot_id={}, username={}",
        details["bot_id"], details["username"]
    );
}

#[fcp_async_core::test]
async fn live_error_mapping_invalid_token() {
    if skip_without_live_gate() {
        return;
    }

    // Test with a deliberately invalid token to verify error handling.
    // Telegram's handle_configure calls getMe, so an invalid token produces
    // a structured FCP error at configure time (not at invoke time).
    let mut connector = TelegramConnector::new();

    // Use a token that passes syntax validation but is rejected by the API
    let err = connector
        .handle_configure(json!({
            "credential": "999999999:ABCDEFGHIJKLMNOPQRSTUVWXyz_invalid_00"
        }))
        .await;

    // Configure should fail because getMe returns 401/unauthorized
    assert!(
        err.is_err(),
        "configure with invalid token should return an error"
    );
    let fcp_err = err.unwrap_err();
    let err_str = format!("{fcp_err}");
    // Should contain structured error info indicating auth/credential failure
    assert!(
        err_str.contains("401")
            || err_str.to_lowercase().contains("unauthorized")
            || err_str.to_lowercase().contains("auth")
            || err_str.to_lowercase().contains("credential")
            || err_str.to_lowercase().contains("not found"),
        "error should indicate auth failure: got '{err_str}'"
    );

    eprintln!("PASS: live_error_mapping_invalid_token — got structured error: {err_str}");
}

#[fcp_async_core::test]
async fn live_get_file_nonexistent() {
    skip_without_token!(token);

    let mut connector = TelegramConnector::new();
    let signing_key = setup_live_connector(&mut connector, &token).await;
    let capability = generate_read_token(
        &signing_key,
        connector.instance_id().as_str(),
        "telegram.get_file",
    );

    // Invoke get_file with a nonexistent file_id — should return a structured
    // Telegram API error (400 "Bad Request: invalid file_id"), not a panic.
    let err = connector
        .handle_invoke(json!({
            "operation": "telegram.get_file",
            "input": {
                "file_id": "nonexistent_file_id_for_live_test"
            },
            "capability_token": capability
        }))
        .await;

    assert!(
        err.is_err(),
        "get_file with nonexistent ID should return an error"
    );
    let fcp_err = err.unwrap_err();
    let err_str = format!("{fcp_err}");
    // Telegram should return a structured API error, not a raw panic or timeout
    assert!(
        err_str.to_lowercase().contains("bad request")
            || err_str.to_lowercase().contains("invalid")
            || err_str.to_lowercase().contains("not found")
            || err_str.contains("400"),
        "error should indicate invalid file_id: got '{err_str}'"
    );

    eprintln!("PASS: live_get_file_nonexistent — got structured error: {err_str}");
}

#[fcp_async_core::test]
async fn live_health_check() {
    skip_without_token!(token);

    let mut connector = TelegramConnector::new();
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
async fn live_introspect() {
    skip_without_token!(token);

    let mut connector = TelegramConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &token).await;

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Should list operations
    let ops = introspection["operations"]
        .as_array()
        .or_else(|| introspection["provides"].as_array());
    assert!(
        ops.is_some(),
        "introspection should contain operations: {introspection}"
    );
    let ops = ops.unwrap();
    assert!(
        ops.len() >= 3,
        "Telegram connector should have at least 3 operations, got {}",
        ops.len()
    );

    // Verify expected operations are present
    let op_ids: Vec<&str> = ops
        .iter()
        .filter_map(|o| o.get("id").and_then(|id| id.as_str()))
        .collect();
    assert!(
        op_ids.contains(&"telegram.send_message"),
        "should contain telegram.send_message: {op_ids:?}"
    );
    assert!(
        op_ids.contains(&"telegram.get_file"),
        "should contain telegram.get_file: {op_ids:?}"
    );

    eprintln!("PASS: live_introspect — {} operations reported", ops.len());
}
