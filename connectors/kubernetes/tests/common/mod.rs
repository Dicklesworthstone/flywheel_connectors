//! Signed fixture sessions for provider-focused integration tests.
//! Native protocol acceptance tests call the real executable without this wrapper.

#![allow(dead_code)]

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{Duration, Utc};
use fcp_core::{CapabilityConstraints, CapabilityToken, FcpResult, InstanceId};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_kubernetes::connector::KubernetesConnector;
use serde_json::{Value, json};

pub fn handshake_params(key: &Ed25519SigningKey, capabilities: &[&str]) -> Value {
    json!({
        "protocol_version": "2.0", "zone": "z:infra",
        "host_public_key": key.verifying_key().to_bytes(),
        "nonce": vec![19_u8; 32], "capabilities_requested": capabilities,
    })
}

pub fn capability(operation: &str) -> &'static str {
    match operation {
        "kubernetes.get_secret"
        | "kubernetes.secret.get"
        | "kubernetes.secret.create"
        | "kubernetes.secret.delete" => "kubernetes.secrets",
        "kubernetes.create_pod"
        | "kubernetes.delete_pod"
        | "kubernetes.apply_deployment"
        | "kubernetes.delete_deployment"
        | "kubernetes.exec"
        | "kubernetes.configmap.create"
        | "kubernetes.configmap.delete" => "kubernetes.admin",
        "kubernetes.scale_deployment"
        | "kubernetes.rollout_restart"
        | "kubernetes.update_configmap"
        | "kubernetes.configmap.update"
        | "kubernetes.rollout.rollback" => "kubernetes.write",
        _ => "kubernetes.read",
    }
}

pub fn token(
    key: &Ed25519SigningKey,
    instance: &InstanceId,
    operation: &str,
    token_id: &[u8],
    constraints: &CapabilityConstraints,
) -> CapabilityToken {
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).unwrap();
    let now = Utc::now();
    CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(capability(operation))
            .operations(&[operation])
            .zone_id("z:infra")
            .principal("user:kubernetes-test")
            .issuer("node:kubernetes-test")
            .target_instance(instance.as_str())
            .token_id(token_id)
            .validity(now - Duration::minutes(1), now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(key)
            .unwrap(),
    )
}

pub fn request(operation: &str, input: Value, token: CapabilityToken) -> Value {
    json!({
        "type": "invoke", "id": "kubernetes-fixture-invocation",
        "connector_id": "fcp.kubernetes", "zone_id": "z:infra",
        "operation": operation, "input": input, "capability_token": token,
    })
}

/// Build real signed envelopes while keeping HTTP fixture assertions on outputs.
pub struct TestConnector {
    inner: KubernetesConnector,
    key: Ed25519SigningKey,
    instance: InstanceId,
    sequence: AtomicU64,
}

impl TestConnector {
    pub fn new() -> Self {
        Self {
            inner: KubernetesConnector::new(),
            key: Ed25519SigningKey::generate(),
            instance: InstanceId::new(),
            sequence: AtomicU64::new(0),
        }
    }

    pub async fn handle_handshake(&mut self, _fixture_label: Value) -> FcpResult<Value> {
        let response = self
            .inner
            .handle_handshake(handshake_params(
                &self.key,
                &[
                    "kubernetes.read",
                    "kubernetes.write",
                    "kubernetes.admin",
                    "kubernetes.secrets",
                ],
            ))
            .await?;
        self.instance = serde_json::from_value(response["instance_id"].clone()).unwrap();
        Ok(response)
    }

    fn signed(&self, params: Value) -> Value {
        let operation = params["operation_id"].as_str().unwrap_or("");
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        request(
            operation,
            params.get("input").cloned().unwrap_or_else(|| json!({})),
            token(
                &self.key,
                &self.instance,
                operation,
                &sequence.to_le_bytes(),
                &CapabilityConstraints {
                    resource_allow: vec!["*".into()],
                    ..Default::default()
                },
            ),
        )
    }

    pub async fn handle_invoke(&self, params: Value) -> FcpResult<Value> {
        let response = self.inner.handle_invoke(self.signed(params)).await?;
        Ok(response["result"].clone())
    }

    pub async fn handle_simulate(&self, mut params: Value) -> FcpResult<Value> {
        if params.get("input").is_none() {
            // These legacy provider tests ask whether the operation is supported.
            // Supply a valid scoped fixture input now that simulation validates it.
            params["input"] = json!({
                "namespace": "default", "name": "fixture", "data": {},
                "command": ["id"], "replicas": 1,
                "spec": {
                    "containers": [{"name": "fixture", "image": "fixture:v1"}],
                    "selector": {"matchLabels": {"app": "fixture"}},
                    "template": {"metadata": {"labels": {"app": "fixture"}},
                        "spec": {"containers": [{"name": "fixture", "image": "fixture:v1"}]}},
                },
            });
        }
        let mut envelope = self.signed(params);
        envelope["type"] = json!("simulate");
        self.inner.handle_simulate(envelope).await
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        self.inner
            .handle_shutdown(json!({
                "type": "shutdown", "deadline_ms": 1_000, "drain": false,
            }))
            .await
    }
}

impl Deref for TestConnector {
    type Target = KubernetesConnector;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TestConnector {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
