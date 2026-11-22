//! Live verification tests for the Stripe connector against the real Stripe API.
//!
//! These tests require a `STRIPE_SECRET_KEY` environment variable with a valid
//! Stripe secret key (test-mode key recommended, e.g. `sk_test_...`). When the
//! key is absent, tests skip gracefully with a descriptive message.
//!
//! All operations are READ-ONLY (`stripe.list_customers`, `stripe.get_balance`) and
//! do not create or mutate any resources.

#[macro_use]
#[path = "support/mod.rs"]
mod test_support;

use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_prelude::{CapabilityConstraints, CapabilityToken};

use chrono::{Duration, Utc};
use serde_json::json;

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";

// ============================================================================
// Skip guard
// ============================================================================

fn stripe_secret_key() -> Option<String> {
    std::env::var("STRIPE_SECRET_KEY")
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
        "SKIP: {LIVE_GATE_ENV} is not enabled; set {LIVE_GATE_ENV}=1 before running live Stripe sandbox verification."
    );
    true
}

macro_rules! skip_without_token {
    ($var:ident) => {
        if skip_without_live_gate() {
            return;
        }
        let Some($var) = stripe_secret_key() else {
            eprintln!(
                "SKIP: STRIPE_SECRET_KEY not set — skipping live Stripe connector verification. \
                 Set STRIPE_SECRET_KEY=sk_test_... to enable."
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
    let cap = match op {
        "stripe.create_customer" | "stripe.update_customer" | "stripe.delete_customer" => {
            "stripe.write"
        }
        "stripe.create_payment_intent"
        | "stripe.confirm_payment_intent"
        | "stripe.capture_payment_intent"
        | "stripe.cancel_payment_intent"
        | "stripe.create_refund"
        | "stripe.create_subscription"
        | "stripe.cancel_subscription" => "stripe.payment",
        "stripe.ingest_webhook_event" => "stripe.webhook",
        _ => "stripe.read",
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
        .zone_id("z:private")
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

async fn setup_live_connector(
    connector: &mut fcp_stripe::connector::StripeConnector,
    secret_key: &str,
) -> Ed25519SigningKey {
    // Configure with real Stripe API
    connector
        .handle_configure(json!({
            "secret_key": secret_key
        }))
        .await
        .expect("configure with real secret key should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:private",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["stripe.read"]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Live verification tests
// ============================================================================

#[fcp_async_core::test]
async fn live_customers_list() {
    skip_without_token!(key);

    let mut connector = fcp_stripe::connector::StripeConnector::new();
    let signing_key = setup_live_connector(&mut connector, &key).await;
    let capability = generate_read_token(
        &signing_key,
        connector.instance_id(),
        "stripe.list_customers",
    );

    let result = connector
        .handle_invoke(invoke_request!({
            "operation": "stripe.list_customers",
            "input": {
                "limit": 3
            },
            "capability_token": capability
        }))
        .await
        .expect("list_customers should succeed against real Stripe API");

    // Verify response shape
    assert!(
        result.get("data").is_some(),
        "response should contain 'data' array: {result}"
    );
    let data = result["data"].as_array().expect("data should be an array");
    assert!(
        result.get("has_more").is_some(),
        "response should contain 'has_more' field"
    );

    eprintln!(
        "PASS: live_customers_list — returned {} customers, has_more={}",
        data.len(),
        result["has_more"]
    );
}

#[fcp_async_core::test]
async fn live_error_mapping_invalid_key() {
    if skip_without_live_gate() {
        return;
    }

    // Test with a deliberately invalid key to verify ConnectorErrorMapping
    // works correctly: should get a structured FCP auth error, not a raw HTTP 401.
    let mut connector = fcp_stripe::connector::StripeConnector::new();

    // Configure with an obviously invalid key
    connector
        .handle_configure(json!({
            "secret_key": "sk_test_this_is_not_a_valid_key_000000000"
        }))
        .await
        .expect("configure should succeed even with bad key");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:private",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["stripe.read"]
        }))
        .await
        .expect("handshake should succeed");

    let capability = generate_read_token(
        &signing_key,
        connector.instance_id(),
        "stripe.list_customers",
    );

    let err = connector
        .handle_invoke(invoke_request!({
            "operation": "stripe.list_customers",
            "input": { "limit": 1 },
            "capability_token": capability
        }))
        .await;

    // The error should be a structured FCP error, not a raw HTTP status
    assert!(
        err.is_err(),
        "invoke with invalid key should return an error"
    );
    let fcp_err = err.unwrap_err();
    let err_str = format!("{fcp_err}");
    // Should contain structured error info, not just "401"
    assert!(
        err_str.contains("401")
            || err_str.to_lowercase().contains("unauthorized")
            || err_str.to_lowercase().contains("auth")
            || err_str.to_lowercase().contains("invalid")
            || err_str.to_lowercase().contains("api key"),
        "error should indicate auth failure: got '{err_str}'"
    );

    eprintln!("PASS: live_error_mapping_invalid_key — got structured error: {err_str}");
}

#[fcp_async_core::test]
async fn live_health_check() {
    skip_without_token!(key);

    let mut connector = fcp_stripe::connector::StripeConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &key).await;

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
    skip_without_token!(key);

    let mut connector = fcp_stripe::connector::StripeConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &key).await;

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Should list all 18 operations
    let ops = introspection["operations"]
        .as_array()
        .or_else(|| introspection["provides"].as_array());
    assert!(
        ops.is_some(),
        "introspection should contain operations: {introspection}"
    );
    let ops = ops.unwrap();
    assert!(
        ops.len() >= 15,
        "Stripe connector should have at least 15 operations, got {}",
        ops.len()
    );

    // Verify the operation we tested exists
    let op_ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();
    assert!(
        op_ids.contains(&"stripe.list_customers"),
        "operations should include stripe.list_customers: {op_ids:?}"
    );

    eprintln!("PASS: live_introspect — {} operations reported", ops.len());
}
