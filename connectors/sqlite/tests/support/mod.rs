//! Signed protocol fixtures shared by SQL, file-backed and native-process tests.

#![allow(
    dead_code,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use chrono::{Duration, Utc};
use fcp_core::{CapabilityConstraints, CapabilityToken};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::{Value, json};

pub fn handshake(key: &Ed25519SigningKey, capabilities: &[&str]) -> Value {
    json!({
        "protocol_version": "2.0.0",
        "zone": "z:private",
        "host_public_key": key.verifying_key().to_bytes(),
        "nonce": vec![37_u8; 32],
        "capabilities_requested": capabilities,
    })
}

pub fn capability(operation: &str) -> &'static str {
    match operation {
        "sqlite.execute"
        | "sqlite.batch"
        | "sqlite.transaction.begin"
        | "sqlite.transaction.commit"
        | "sqlite.transaction.rollback" => "sqlite.write",
        "sqlite.vacuum" => "sqlite.admin",
        _ => "sqlite.read",
    }
}

pub fn token(
    key: &Ed25519SigningKey,
    instance: &str,
    operation: &str,
    principal: &str,
    constraints: CapabilityConstraints,
) -> CapabilityToken {
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let id = uuid::Uuid::new_v4();
    CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .token_id(id.as_bytes())
            .capability_id(capability(operation))
            .zone_id("z:private")
            .principal(principal)
            .operations(&[operation])
            .issuer("node:sqlite-test")
            .target_instance(instance)
            .validity(now - Duration::seconds(5), now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(key)
            .unwrap(),
    )
}

pub fn request(
    key: &Ed25519SigningKey,
    instance: &str,
    resource: &str,
    operation: &str,
    input: Value,
) -> Value {
    let mut resource_allow = vec![resource.into()];
    if let Some(transaction) = input["txn_id"].as_str() {
        resource_allow.push(format!("sqlite:transaction:{transaction}"));
    }
    let token = token(
        key,
        instance,
        operation,
        "user:sqlite-test",
        CapabilityConstraints {
            resource_allow,
            ..Default::default()
        },
    );
    json!({
        "type": "invoke", "id": "sqlite-test-request",
        "connector_id": "fcp.sqlite", "zone_id": "z:private",
        "operation": operation, "input": input,
        "capability_token": token,
        "lease_seq": 1, "deadline_ms": 5_000,
        "idempotency_key": uuid::Uuid::new_v4().to_string(),
    })
}
