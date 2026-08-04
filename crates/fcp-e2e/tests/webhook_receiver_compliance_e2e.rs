//! E2E Webhook Receiver connector compliance tests.
//!
//! Exercises the Webhook Receiver connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features webhook_receiver`

#![cfg(feature = "webhook_receiver")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::sync::Mutex;
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot,
    IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus,
    OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest,
    SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
    ZoneId,
};
use fcp_webhook_receiver::connector::WebhookReceiverConnector;
use serde_json::json;
use std::sync::Arc;

struct WebhookReceiverConnectorAdapter {
    connector: Arc<Mutex<WebhookReceiverConnector>>,
    id: ConnectorId,
    instance_id: InstanceId,
    verifier: Option<CapabilityVerifier>,
}

impl WebhookReceiverConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: Arc::new(Mutex::new(WebhookReceiverConnector::new())),
            id: ConnectorId::from_static("webhook-receiver"),
            instance_id: InstanceId::new(),
            verifier: None,
        }
    }
}

fcp_core::impl_fcp_sealed!(WebhookReceiverConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for WebhookReceiverConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector
            .lock()
            .await
            .handle_configure(config)
            .await
            .map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let session_id = SessionId::new();
        let mut params = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        if let Some(obj) = params.as_object_mut() {
            obj.insert(
                "session_id".to_string(),
                serde_json::Value::String(session_id.0.to_string()),
            );
        }

        let response = self.connector.lock().await.handle_handshake(params).await?;
        let protocol_version = response
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "webhook-receiver handshake response missing protocol_version".into(),
            })?;
        if protocol_version != "2.0" {
            return Err(FcpError::Internal {
                message: format!(
                    "webhook-receiver handshake protocol_version expected 2.0, got {protocol_version}"
                ),
            });
        }
        let _connector_id = response
            .get("connector_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "webhook-receiver handshake response missing connector_id".into(),
            })?;
        let connector_caps: std::collections::BTreeSet<String> = response
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| FcpError::Internal {
                message: "webhook-receiver handshake response missing capabilities array".into(),
            })?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .iter()
            .filter(|cap| connector_caps.contains(cap.as_str()))
            .cloned()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.instance_id.clone(),
        ));

        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:webhook-receiver-e2e".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "degraded" => HealthSnapshot::degraded("not_handshaken"),
                    "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("webhook_receiver_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<fcp_core::SelfCheckReport> {
        let value = self.connector.lock().await.handle_self_check().await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize Webhook Receiver self_check: {err}"),
        })
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.verifier = None;
        self.connector
            .lock()
            .await
            .handle_shutdown(json!({}))
            .await
            .map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("webhook.endpoints.list"),
                summary: "webhook.endpoints.list".to_string(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("webhook.endpoints.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: String::new(),
                    common_mistakes: Vec::new(),
                    examples: Vec::new(),
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Webhook Receiver verifier not initialized; handshake required".into(),
        })?;
        let required_capability = required_capability(req.operation.as_str())?;
        verifier.verify_bound(
            req.capability_token.clone(),
            &required_capability,
            &req.operation,
            &[],
        )?;

        let request_id = req.id.clone();
        let value = self
            .connector
            .lock()
            .await
            .handle_invoke(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "Webhook Receiver verifier not initialized; handshake required".into(),
        })?;
        let required_capability = required_capability(req.operation.as_str())?;
        verifier.verify_bound(
            req.capability_token.clone(),
            &required_capability,
            &req.operation,
            &[],
        )?;

        let value = self
            .connector
            .lock()
            .await
            .handle_simulate(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;

        Ok(SimulateResponse {
            r#type: "simulate_response".to_string(),
            id: req.id,
            would_succeed: value
                .get("allowed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            failure_reason: value
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .filter(|_| {
                    !value
                        .get("allowed")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                })
                .map(str::to_string),
            denial_code: None,
            missing_capabilities: Vec::new(),
            estimated_cost: None,
            availability: None,
            response_metadata: None,
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

fn required_capability(operation: &str) -> fcp_core::FcpResult<CapabilityId> {
    let capability = match operation {
        "webhook.endpoints.create" | "webhook.endpoints.delete" => "webhook.endpoints.write",
        "webhook.endpoints.list" => "webhook.endpoints.read",
        "webhook.events.recent" => "webhook.events.read",
        _ => {
            return Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            });
        }
    };

    capability
        .parse::<CapabilityId>()
        .map_err(|err| FcpError::Internal {
            message: format!("invalid capability id mapping for {operation}: {err}"),
        })
}

fn webhook_receiver_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/webhook-receiver/manifest.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn webhook_receiver_manifest_toml() -> toml::Value {
    toml::from_str(include_str!(
        "../../../connectors/webhook-receiver/manifest.toml"
    ))
    .expect("Webhook Receiver manifest TOML")
}

fn webhook_receiver_config() -> serde_json::Value {
    json!({})
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [19_u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|capability| {
                capability
                    .parse::<CapabilityId>()
                    .expect("capability id parse")
            })
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
    instance_id: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize test constraints");
    let token = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
        // dja9u typestate ratchet: tokens MUST carry target_instance matching the connector.
        .target_instance(instance_id)
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(token)
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("webhook-receiver-e2e"),
        connector_id: ConnectorId::from_static("webhook-receiver"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn assert_endpoint_listing_schema(endpoint: &serde_json::Value) {
    assert!(
        endpoint
            .get("endpoint_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.is_empty()),
        "endpoint_id should be a non-empty string: {endpoint:#?}"
    );
    assert_eq!(endpoint.get("path"), Some(&json!("/hooks/github")));
    assert_eq!(
        endpoint.get("url"),
        Some(&json!("http://localhost:8080/hooks/github"))
    );
    assert_eq!(endpoint.get("provider"), Some(&json!("github")));
    assert_eq!(
        endpoint.get("signature_header"),
        Some(&json!("X-Hub-Signature-256"))
    );
    assert_eq!(
        endpoint.get("signature_algorithm"),
        Some(&json!("hmac-sha256"))
    );
    assert_eq!(
        endpoint.get("allowed_sources"),
        Some(&json!(["192.168.1.0/24"]))
    );
    assert_eq!(
        endpoint.get("signing_secret_configured"),
        Some(&json!(true))
    );
    assert_eq!(endpoint.get("active"), Some(&json!(true)));
    assert_eq!(endpoint.get("event_count"), Some(&json!(0)));
    assert!(
        endpoint.get("signing_secret").is_none(),
        "list output should not expose the raw signing secret: {endpoint:#?}"
    );

    let secret_last_rotated_at = endpoint
        .get("secret_last_rotated_at")
        .and_then(serde_json::Value::as_str)
        .expect("secret_last_rotated_at should be present");
    chrono::DateTime::parse_from_rfc3339(secret_last_rotated_at)
        .expect("secret_last_rotated_at should be RFC3339");

    let created_at = endpoint
        .get("created_at")
        .and_then(serde_json::Value::as_str)
        .expect("created_at should be present");
    chrono::DateTime::parse_from_rfc3339(created_at).expect("created_at should be RFC3339");
}

fn operation_network_constraints<'a>(
    manifest: &'a toml::Value,
    operation_name: &str,
) -> &'a toml::value::Table {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .expect("operation network_constraints")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    operation_network_constraints(manifest, operation_name)
        .get("host_allow")
        .and_then(toml::Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .expect("operation host_allow")
}

fn host_allowed(host: &str, host_allow: &[String]) -> bool {
    fcp_sandbox::host_matches_allow_list(host, host_allow)
}

#[fcp_async_core::runtime::test]
async fn webhook_receiver_default_deny_compliance_suite_passes() {
    let mut connector = WebhookReceiverConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["webhook.endpoints.read"],
    );
    // Token grants webhook.endpoints.read capability but only for webhook.endpoints.list operation.
    // Invoke targets webhook.endpoints.delete which requires webhook.endpoints.write -- denied.
    let token = build_token(
        &signing_key,
        "webhook.endpoints.read",
        &["webhook.endpoints.list"],
        connector.instance_id.as_str(),
    );
    let invoke = invoke_request(
        "webhook.endpoints.delete",
        json!({ "endpoint_id": "ep_abc123" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: webhook_receiver_config(),
        handshake,
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new(
        "webhook_receiver_default_deny",
        webhook_receiver_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-webhook-receiver");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(
        report.passed,
        "default deny compliance should pass: {report:#?}"
    );
}

#[fcp_async_core::runtime::test]
async fn webhook_receiver_happy_path_connector_suite_passes() {
    let mut connector = WebhookReceiverConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let seed_handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["webhook.endpoints.read", "webhook.endpoints.write"],
    );
    connector
        .configure(webhook_receiver_config())
        .await
        .expect("seed configure");
    connector
        .handshake(seed_handshake)
        .await
        .expect("seed handshake");

    let seed_token = build_token(
        &signing_key,
        "webhook.endpoints.write",
        &["webhook.endpoints.create"],
        connector.instance_id.as_str(),
    );
    let seed_create = invoke_request(
        "webhook.endpoints.create",
        json!({
            "path": "/hooks/github",
            "provider": "github",
            "allowed_sources": ["192.168.1.0/24"],
        }),
        seed_token,
    );
    let seed_response = connector
        .invoke(seed_create)
        .await
        .expect("seed endpoint create");
    assert_eq!(seed_response.status, InvokeStatus::Ok);

    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["webhook.endpoints.read"],
    );
    let token = build_token(
        &signing_key,
        "webhook.endpoints.read",
        &["webhook.endpoints.list"],
        connector.instance_id.as_str(),
    );
    let invoke = invoke_request("webhook.endpoints.list", json!({}), token);

    let suite = ConnectorSuite {
        test_name: "webhook_receiver_happy_path".to_string(),
        config: webhook_receiver_config(),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-webhook-receiver-happy");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "happy path should pass: {report:#?}");
    let invoke_entry = report
        .logs
        .iter()
        .find(|entry| entry.context.get("operation") == Some(&json!("invoke")))
        .expect("invoke entry");
    assert_eq!(invoke_entry.result, "pass");
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );

    let list_response = connector
        .invoke(invoke_request(
            "webhook.endpoints.list",
            json!({}),
            build_token(
                &signing_key,
                "webhook.endpoints.read",
                &["webhook.endpoints.list"],
                connector.instance_id.as_str(),
            ),
        ))
        .await
        .expect("list endpoints after suite");
    assert_eq!(list_response.status, InvokeStatus::Ok);

    let list_result = list_response.result.expect("list result payload");
    let endpoints = list_result
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
        .expect("list response should include endpoints array");
    assert_eq!(
        endpoints.len(),
        1,
        "seeded endpoint should appear in list result: {list_result:#?}"
    );
    assert_endpoint_listing_schema(&endpoints[0]);
}

#[test]
fn webhook_receiver_manifest_network_guard_allows_and_denies() {
    let manifest = webhook_receiver_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    assert_eq!(
        operations.len(),
        6,
        "Webhook Receiver manifest should declare 6 operations"
    );

    let expected_hosts = vec!["localhost.localdomain".to_string()];

    for operation_name in operations.keys() {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should use exact Webhook Receiver host allowlist"
        );

        assert!(host_allowed("localhost.localdomain", &host_allow));
        assert!(!host_allowed("example.com", &host_allow));
        assert!(!host_allowed("webhook.site", &host_allow));
        assert!(!host_allowed("127.0.0.1", &host_allow));

        // Webhook Receiver is a local listener so it intentionally allows localhost/private
        let constraints = operation_network_constraints(&manifest, operation_name);
        assert_eq!(
            constraints
                .get("deny_localhost")
                .and_then(toml::Value::as_bool),
            Some(false),
            "operation {operation_name} should allow localhost (local webhook listener)"
        );
        assert_eq!(
            constraints
                .get("deny_private_ranges")
                .and_then(toml::Value::as_bool),
            Some(false),
            "operation {operation_name} should allow private ranges (local webhook listener)"
        );
        assert_eq!(
            constraints
                .get("deny_tailnet_ranges")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must deny tailnet ranges"
        );
    }
}
