//! Live verification tests for the Gmail connector against the real Gmail API.
//!
//! Live connector invocation requires a secretless egress surface that accepts
//! `x-fcp-credential-id`; raw OAuth access tokens are intentionally rejected at
//! connector configure time.
//!
//! All operations are READ-ONLY (`gmail.list_labels`) and do not create, modify,
//! or delete any data.

use fcp_crypto::Ed25519SigningKey;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError};

use chrono::{Duration, Utc};
use serde_json::json;

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";

// ============================================================================
// Skip guard
// ============================================================================

fn gmail_credential_id() -> Option<String> {
    std::env::var("GMAIL_CREDENTIAL_ID")
        .ok()
        .filter(|t| !t.is_empty())
}

fn gmail_secretless_base_url() -> Option<String> {
    std::env::var("GMAIL_SECRETLESS_BASE_URL")
        .ok()
        .filter(|value| !value.is_empty())
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
        "SKIP: {LIVE_GATE_ENV} is not enabled; set {LIVE_GATE_ENV}=1 before running live Gmail connector verification."
    );
    true
}

macro_rules! skip_without_secretless_config {
    ($var:ident) => {
        if skip_without_live_gate() {
            return;
        }
        let Some($var) = gmail_credential_id() else {
            eprintln!(
                "SKIP: GMAIL_CREDENTIAL_ID not set — skipping live Gmail connector verification. \
                 Configure an FCP secretless credential and set GMAIL_SECRETLESS_BASE_URL when \
                 live egress proxying is required."
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
    connector: &fcp_gmail::connector::GmailConnector,
    op: &str,
) -> CapabilityToken {
    let cap = match op {
        "gmail.send_message" | "gmail.send_draft" => "gmail.send",
        "gmail.sync_history" => "gmail.history.read",
        "gmail.modify_message" | "gmail.get_draft" | "gmail.create_draft" => "gmail.write",
        "gmail.trash_message" => "gmail.delete",
        _ => "gmail.read",
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
        .target_instance(connector.instance_id().as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_live_connector(
    connector: &mut fcp_gmail::connector::GmailConnector,
    credential_id: &str,
) -> Ed25519SigningKey {
    let mut config = json!({ "credential_id": credential_id });
    if let Some(base_url) = gmail_secretless_base_url() {
        config["base_url"] = json!(base_url);
    }

    connector
        .handle_configure(config)
        .await
        .expect("configure with credential_id should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:private",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["gmail.read"]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

// ============================================================================
// Live verification tests
// ============================================================================

#[fcp_async_core::test]
async fn live_labels_list() {
    skip_without_secretless_config!(credential_id);
    if gmail_secretless_base_url().is_none() {
        eprintln!(
            "SKIP: GMAIL_SECRETLESS_BASE_URL not set — live Gmail invocation requires a \
             secretless egress proxy that materializes GMAIL_CREDENTIAL_ID."
        );
        return;
    }

    let mut connector = fcp_gmail::connector::GmailConnector::new();
    let signing_key = setup_live_connector(&mut connector, &credential_id).await;
    let cap_token = generate_read_token(&signing_key, &connector, "gmail.list_labels");

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "live-labels",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.list_labels",
            "input": {},
            "capability_token": cap_token
        }))
        .await
        .expect("list_labels should succeed against real Gmail API");

    // Verify response shape
    let labels = result["labels"]
        .as_array()
        .expect("response should contain 'labels' array");
    assert!(
        !labels.is_empty(),
        "Gmail account should have at least one label (INBOX, etc.)"
    );

    eprintln!("PASS: live_labels_list — returned {} labels", labels.len());
}

#[fcp_async_core::test]
async fn live_raw_token_config_rejected() {
    let mut connector = fcp_gmail::connector::GmailConnector::new();

    let result = connector
        .handle_configure(json!({
            "token": "ya29.this_is_not_a_valid_access_token_000000000"
        }))
        .await;

    assert!(matches!(
        result,
        Err(FcpError::ConfigurationLeakedSecret { .. })
    ));
}

#[fcp_async_core::test]
async fn live_health_check() {
    skip_without_secretless_config!(credential_id);

    let mut connector = fcp_gmail::connector::GmailConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &credential_id).await;

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
    skip_without_secretless_config!(credential_id);

    let mut connector = fcp_gmail::connector::GmailConnector::new();
    let _signing_key = setup_live_connector(&mut connector, &credential_id).await;

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Should list all 10 operations
    let ops = introspection["operations"]
        .as_array()
        .or_else(|| introspection["provides"].as_array());
    assert!(
        ops.is_some(),
        "introspection should contain operations: {introspection}"
    );
    let ops = ops.unwrap();
    assert!(
        ops.len() >= 8,
        "Gmail connector should have at least 8 operations, got {}",
        ops.len()
    );

    // Verify the operation we tested exists
    let op_ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();
    assert!(
        op_ids.contains(&"gmail.list_labels"),
        "operations should include gmail.list_labels: {op_ids:?}"
    );

    eprintln!("PASS: live_introspect — {} operations reported", ops.len());
}
