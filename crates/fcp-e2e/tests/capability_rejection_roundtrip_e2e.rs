//! Capability-rejection roundtrip E2E (host-backed).
//!
//! `full_system_e2e::e2e_capability_verification` only covers one
//! rejection path (`capability_id` mismatch surfaced as reason FCP-3003).
//! The remaining gateway-level rejection invariants live inline in
//! `fcp-core/src/capability.rs` but had no E2E roundtrip showing each
//! rejection class flowing through the production `CapabilityVerifier`
//! that `fcp-host` uses at the gateway boundary.
//!
//! Each scenario below mints a valid COSE-signed `CapabilityToken` with
//! exactly one tampered field, drives it through `verify_unbound` (the
//! same call the gateway makes), and asserts the expected rejection
//! variant. JSONL log lines are emitted per scenario so triage tooling
//! can parse the run history without re-running tests.
//!
//! Property under test: each of the six rejection classes
//! (`TokenExpired`, `TokenNotYetValid`, `InvalidSignature`, `ZoneViolation`,
//! OperationNotGranted-on-capability, OperationNotGranted-on-operation)
//! is surfaced by the production `CapabilityVerifier`. A regression that
//! silently accepts a tampered token in any class fails this E2E
//! immediately.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fcp_crypto::{Ed25519SigningKey, cose::CapabilityTokenBuilder};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, CapabilityVerifier, FcpError,
    OperationId, ZoneId,
};
use serde_json::json;

/// Emit a structured JSONL log entry matching the /testing-perfect-e2e
/// triage pattern: `{ts, scenario_id, phase, outcome, error_class}`.
/// Visible under `cargo test -- --nocapture` and captured by CI test logs.
fn log_event(scenario_id: &str, phase: &str, outcome: &str, error_class: Option<&str>) {
    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "scenario_id": scenario_id,
        "phase": phase,
        "outcome": outcome,
        "error_class": error_class,
    });
    println!("{entry}");
}

fn default_constraints_cbor() -> Vec<u8> {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&constraints, &mut bytes).expect("serialize default constraints");
    bytes
}

#[allow(clippy::too_many_arguments)]
fn build_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    zone: &str,
    operations: &[&str],
    nbf: DateTime<Utc>,
    exp: DateTime<Utc>,
) -> CapabilityToken {
    let constraints_cbor = default_constraints_cbor();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone)
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(nbf, exp)
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(cose)
}

#[test]
fn happy_path_capability_token_verifies_through_gateway() {
    let scenario = "capability.happy_path";
    log_event(scenario, "setup", "started", None);

    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let token = build_token(
        &signing_key,
        "cap.test",
        "z:work",
        &["op.read"],
        now - ChronoDuration::minutes(1),
        now + ChronoDuration::hours(1),
    );

    let verifier = CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        ZoneId::work(),
    );
    let cap = CapabilityId::new("cap.test").expect("valid capability id");
    let op = OperationId::new("op.read").expect("valid operation id");

    log_event(scenario, "verify", "running", None);
    verifier
        .verify_unbound(token, &cap, &op, &[])
        .expect("well-formed token must verify through verify_unbound");
    log_event(scenario, "verify", "passed", None);
}

#[test]
fn expired_token_is_rejected_with_token_expired() {
    let scenario = "capability.rejection.expired";
    log_event(scenario, "setup", "started", None);

    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    // Validity window ended an hour ago.
    let token = build_token(
        &signing_key,
        "cap.test",
        "z:work",
        &["op.read"],
        now - ChronoDuration::hours(2),
        now - ChronoDuration::hours(1),
    );

    let verifier = CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        ZoneId::work(),
    );
    let cap = CapabilityId::new("cap.test").expect("valid capability id");
    let op = OperationId::new("op.read").expect("valid operation id");

    log_event(scenario, "verify", "running", None);
    let err = verifier
        .verify_unbound(token, &cap, &op, &[])
        .expect_err("expired token must be rejected");
    let class = match &err {
        FcpError::TokenExpired => "TokenExpired",
        other => panic!("expected FcpError::TokenExpired, got {other:?}"),
    };
    log_event(scenario, "verify", "rejected", Some(class));
}

#[test]
fn not_yet_valid_token_is_rejected_with_token_not_yet_valid() {
    let scenario = "capability.rejection.not_yet_valid";
    log_event(scenario, "setup", "started", None);

    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    // Validity window starts in the future.
    let token = build_token(
        &signing_key,
        "cap.test",
        "z:work",
        &["op.read"],
        now + ChronoDuration::hours(1),
        now + ChronoDuration::hours(2),
    );

    let verifier = CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        ZoneId::work(),
    );
    let cap = CapabilityId::new("cap.test").expect("valid capability id");
    let op = OperationId::new("op.read").expect("valid operation id");

    log_event(scenario, "verify", "running", None);
    let err = verifier
        .verify_unbound(token, &cap, &op, &[])
        .expect_err("nbf-in-future token must be rejected");
    let class = match &err {
        FcpError::TokenNotYetValid => "TokenNotYetValid",
        other => panic!("expected FcpError::TokenNotYetValid, got {other:?}"),
    };
    log_event(scenario, "verify", "rejected", Some(class));
}

#[test]
fn forged_signer_token_is_rejected_with_invalid_signature() {
    let scenario = "capability.rejection.forged_signer";
    log_event(scenario, "setup", "started", None);

    // Token is signed by `attacker`, but the verifier expects the
    // gateway's `legitimate` public key. The signature must fail to
    // verify even though every other claim is well-formed.
    let attacker = Ed25519SigningKey::generate();
    let legitimate = Ed25519SigningKey::generate();
    assert_ne!(
        attacker.verifying_key().to_bytes(),
        legitimate.verifying_key().to_bytes(),
        "fixture sanity: attacker and legitimate keys must differ"
    );
    let now = Utc::now();
    let forged_token = build_token(
        &attacker,
        "cap.test",
        "z:work",
        &["op.read"],
        now - ChronoDuration::minutes(1),
        now + ChronoDuration::hours(1),
    );

    let verifier = CapabilityVerifier::without_instance_binding(
        legitimate.verifying_key().to_bytes(),
        ZoneId::work(),
    );
    let cap = CapabilityId::new("cap.test").expect("valid capability id");
    let op = OperationId::new("op.read").expect("valid operation id");

    log_event(scenario, "verify", "running", None);
    let err = verifier
        .verify_unbound(forged_token, &cap, &op, &[])
        .expect_err("token signed by the wrong key must be rejected");
    let class = match &err {
        FcpError::InvalidSignature => "InvalidSignature",
        other => panic!("expected FcpError::InvalidSignature, got {other:?}"),
    };
    log_event(scenario, "verify", "rejected", Some(class));
}

#[test]
fn wrong_zone_token_is_rejected_with_zone_violation() {
    let scenario = "capability.rejection.wrong_zone";
    log_event(scenario, "setup", "started", None);

    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    // Token is for z:public, verifier guards z:work.
    let token = build_token(
        &signing_key,
        "cap.test",
        "z:public",
        &["op.read"],
        now - ChronoDuration::minutes(1),
        now + ChronoDuration::hours(1),
    );

    let verifier = CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        ZoneId::work(),
    );
    let cap = CapabilityId::new("cap.test").expect("valid capability id");
    let op = OperationId::new("op.read").expect("valid operation id");

    log_event(scenario, "verify", "running", None);
    let err = verifier
        .verify_unbound(token, &cap, &op, &[])
        .expect_err("cross-zone token must be rejected");
    let class = match &err {
        FcpError::ZoneViolation { .. } => "ZoneViolation",
        other => panic!("expected FcpError::ZoneViolation, got {other:?}"),
    };
    log_event(scenario, "verify", "rejected", Some(class));
}

#[test]
fn wrong_capability_id_token_is_rejected_with_operation_not_granted() {
    let scenario = "capability.rejection.wrong_capability_id";
    log_event(scenario, "setup", "started", None);

    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    let token = build_token(
        &signing_key,
        "cap.read",
        "z:work",
        &["op.read"],
        now - ChronoDuration::minutes(1),
        now + ChronoDuration::hours(1),
    );

    let verifier = CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        ZoneId::work(),
    );
    // Verifier requires cap.write; the token only grants cap.read.
    let cap = CapabilityId::new("cap.write").expect("valid capability id");
    let op = OperationId::new("op.read").expect("valid operation id");

    log_event(scenario, "verify", "running", None);
    let err = verifier
        .verify_unbound(token, &cap, &op, &[])
        .expect_err("token with the wrong capability_id must be rejected");
    let class = match &err {
        FcpError::OperationNotGranted { .. } => "OperationNotGranted",
        other => panic!("expected FcpError::OperationNotGranted, got {other:?}"),
    };
    log_event(scenario, "verify", "rejected", Some(class));
}

#[test]
fn wrong_operation_token_is_rejected_with_operation_not_granted() {
    let scenario = "capability.rejection.wrong_operation";
    log_event(scenario, "setup", "started", None);

    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
    // Token grants cap.test for op.list, but verifier checks op.delete.
    let token = build_token(
        &signing_key,
        "cap.test",
        "z:work",
        &["op.list"],
        now - ChronoDuration::minutes(1),
        now + ChronoDuration::hours(1),
    );

    let verifier = CapabilityVerifier::without_instance_binding(
        signing_key.verifying_key().to_bytes(),
        ZoneId::work(),
    );
    let cap = CapabilityId::new("cap.test").expect("valid capability id");
    let op = OperationId::new("op.delete").expect("valid operation id");

    log_event(scenario, "verify", "running", None);
    let err = verifier
        .verify_unbound(token, &cap, &op, &[])
        .expect_err("token granting a different operation must be rejected");
    let class = match &err {
        FcpError::OperationNotGranted { operation } => {
            assert_eq!(
                operation, "op.delete",
                "OperationNotGranted must report the requested operation, not the granted one"
            );
            "OperationNotGranted"
        }
        other => panic!("expected FcpError::OperationNotGranted, got {other:?}"),
    };
    log_event(scenario, "verify", "rejected", Some(class));
}
