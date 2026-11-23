//! Signed host-session fixtures shared by the real SQLite integration suites.

#![allow(dead_code)]

use std::ops::{Deref, DerefMut};

use chrono::Utc;
use fcp_core::{CapabilityConstraints, CapabilityToken, FcpResult, InvokeResponse};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_sqlite::connector::SqliteConnector;
use serde_json::{Value, json};

pub fn handshake_request(key: &Ed25519SigningKey, capabilities: &[&str]) -> Value {
    json!({
        "protocol_version": "2.0",
        "zone": "z:private",
        "host_public_key": key.verifying_key().to_bytes(),
        "nonce": vec![7_u8; 32],
        "capabilities_requested": capabilities,
    })
}

pub fn capability_for(operation: &str) -> &str {
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

pub fn signed_request(
    key: &Ed25519SigningKey,
    instance_id: &str,
    operation: &str,
    input: Value,
    constraints: CapabilityConstraints,
) -> Value {
    let now = Utc::now();
    let mut encoded = Vec::new();
    ciborium::into_writer(&constraints, &mut encoded).unwrap();
    let token = CapabilityTokenBuilder::new()
        .token_id(uuid::Uuid::new_v4().as_bytes())
        .capability_id(capability_for(operation))
        .zone_id("z:private")
        .principal("user:sqlite-test")
        .operations(&[operation])
        .issuer("node:sqlite-test")
        .validity(now, now + chrono::Duration::hours(1))
        .target_instance(instance_id)
        .try_constraints_cbor(&encoded)
        .unwrap()
        .sign(key)
        .unwrap();
    json!({
        "type": "invoke",
        "id": uuid::Uuid::new_v4().to_string(),
        "connector_id": "fcp.sqlite",
        "zone_id": "z:private",
        "operation": operation,
        "input": input,
        "capability_token": CapabilityToken::from_raw(token),
        "lease_seq": 1,
    })
}

pub fn database_constraints() -> CapabilityConstraints {
    CapabilityConstraints {
        resource_allow: vec!["sqlite:database".into(), "sqlite:transaction:*".into()],
        ..Default::default()
    }
}

pub struct TestConnector {
    pub connector: SqliteConnector,
    pub key: Ed25519SigningKey,
}

impl TestConnector {
    pub fn new() -> Self {
        Self {
            connector: SqliteConnector::new(),
            key: Ed25519SigningKey::generate(),
        }
    }

    pub async fn handshake(&mut self) -> Value {
        self.connector
            .handle_handshake(handshake_request(
                &self.key,
                &["sqlite.read", "sqlite.write", "sqlite.admin"],
            ))
            .await
            .unwrap()
    }

    pub fn request(
        &self,
        operation: &str,
        input: Value,
        constraints: CapabilityConstraints,
    ) -> Value {
        signed_request(
            &self.key,
            self.instance_id().as_str(),
            operation,
            input,
            constraints,
        )
    }

    /// Sign a test operation descriptor and return its successful payload.
    pub async fn invoke(&mut self, operation: Value) -> FcpResult<Value> {
        let request = self.request(
            operation["operation"].as_str().unwrap(),
            operation["input"].clone(),
            database_constraints(),
        );
        let expected_id = request["id"].as_str().unwrap().to_owned();
        let response: InvokeResponse =
            serde_json::from_value(self.connector.handle_invoke(request).await?)
                .expect("canonical invocation response");
        assert_eq!(response.id.0, expected_id);
        assert!(response.error.is_none());
        Ok(response.result.expect("successful SQLite payload"))
    }
}

impl Deref for TestConnector {
    type Target = SqliteConnector;

    fn deref(&self) -> &Self::Target {
        &self.connector
    }
}

impl DerefMut for TestConnector {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connector
    }
}
