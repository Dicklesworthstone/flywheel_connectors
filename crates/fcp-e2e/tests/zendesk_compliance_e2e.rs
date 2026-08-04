//! E2E Zendesk connector compliance tests (flywheel_connectors-pwff.4).
//!
//! Exercises the Zendesk connector through the E2E compliance harness:
//! - Default deny (missing capability -> error)
//! - Allow with valid token (happy path invoke via mock API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//! - Dangerous action gating (risk level verification)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features zendesk`

#![cfg(feature = "zendesk")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    AgentHint, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector,
    FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use fcp_zendesk::connector::ZendeskConnector;

// ============================================================================
// FcpConnector adapter for ZendeskConnector
// ============================================================================

struct ZendeskConnectorAdapter {
    connector: ZendeskConnector,
    id: ConnectorId,
}

impl ZendeskConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: ZendeskConnector::new(),
            id: ConnectorId::from_static("zendesk"),
        }
    }
}

fcp_core::impl_fcp_sealed!(ZendeskConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for ZendeskConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self.connector.handle_handshake(request).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "not_configured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("zendesk_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("zendesk.get_ticket"),
                summary: "Get a single ticket by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["ticket_id"],
                    "properties": {
                        "ticket_id": { "type": "integer" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["ticket"],
                    "properties": {
                        "ticket": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("zendesk.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Retrieve a ticket by ID.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"ticket_id": 12345}"#.to_string()],
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let request_id = req.id;
        let params = json!({
            "operation": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        });
        let value = self.connector.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let value = self.connector.handle_simulate(request).await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize simulate response: {err}"),
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn reference_manifest_with_hash() -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [13u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
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
    let resolved_capability = match capability {
        "zendesk.get_ticket" => "zendesk.read",
        _ => capability,
    };
    let cose = CapabilityTokenBuilder::new()
        .capability_id(resolved_capability)
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
    CapabilityToken::from_raw(cose)
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("zendesk-e2e"),
        connector_id: ConnectorId::from_static("zendesk"),
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

fn zendesk_config(base_url: &str) -> serde_json::Value {
    json!({
        "subdomain": "testcorp",
        "email": "agent@testcorp.com",
        "api_token": "fake-token-xyz",
        "base_url": base_url,
    })
}

fn zendesk_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/zendesk/manifest.toml"))
        .expect("zendesk manifest toml")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .and_then(|constraints| constraints.get("host_allow"))
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

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "zendesk.delete" but invoke targets "zendesk.get_ticket"
/// (which requires "zendesk.read").
#[fcp_async_core::runtime::test]
async fn zendesk_default_deny_compliance_suite_passes() {
    let mut connector = ZendeskConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["zendesk.delete"]);
    let token = build_token(
        &signing_key,
        "zendesk.delete",
        &["zendesk.delete"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request("zendesk.get_ticket", json!({ "ticket_id": 12345 }), token);

    let dynamic = DynamicSuite {
        config: json!({
            "subdomain": "testcorp",
            "email": "agent@testcorp.com",
            "api_token": "fake-token-xyz",
            "base_url": "http://localhost:9999",
        }),
        handshake: handshake.clone(),
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new(
        "zendesk_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-zendesk");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock API.
#[fcp_async_core::runtime::test]
async fn zendesk_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path("/tickets/12345.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ticket": {
                "id": 12345,
                "subject": "Login issue",
                "description": "Cannot log in since update",
                "status": "open",
                "priority": "high",
                "requester_id": 100,
                "assignee_id": 200,
                "created_at": "2026-03-01T10:00:00Z",
                "updated_at": "2026-03-02T12:00:00Z"
            }
        })))
        .mount(mock.inner())
        .await;

    let mut connector = ZendeskConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["zendesk.get_ticket"],
    );
    let token = build_token(
        &signing_key,
        "zendesk.get_ticket",
        &["zendesk.get_ticket"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request("zendesk.get_ticket", json!({ "ticket_id": 12345 }), token);
    let suite = ConnectorSuite {
        test_name: "zendesk_allow_valid_token".to_string(),
        config: zendesk_config(&mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-zendesk");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
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
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|r| r.url.path() == "/tickets/12345.json")
        .count();
    assert_eq!(hits, 1, "expected exactly one GET to /tickets/12345.json");
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: all Zendesk operations use `*.zendesk.com` wildcard.
#[test]
fn zendesk_manifest_network_guard_allows_and_denies() {
    let manifest = zendesk_manifest_toml();

    let all_operations = [
        "zendesk.create_ticket",
        "zendesk.get_ticket",
        "zendesk.update_ticket",
        "zendesk.delete_ticket",
        "zendesk.search_tickets",
        "zendesk.list_ticket_comments",
        "zendesk.search_articles",
        "zendesk.get_article",
        "zendesk.search_users",
        "zendesk.apply_macro",
    ];

    for operation_name in all_operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow,
            vec!["*.zendesk.com".to_string()],
            "operation {operation_name} should allow only *.zendesk.com"
        );

        // Allowed: any subdomain of zendesk.com
        assert!(
            host_allowed("testcorp.zendesk.com", &host_allow),
            "testcorp.zendesk.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("support.zendesk.com", &host_allow),
            "support.zendesk.com should be allowed for {operation_name}"
        );

        // Denied: bare domain, other domains, subdomain tricks
        assert!(
            !host_allowed("zendesk.com", &host_allow),
            "zendesk.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("zendesk.com.evil.com", &host_allow),
            "zendesk.com.evil.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("localhost", &host_allow),
            "localhost should be denied for {operation_name}"
        );
    }
}

// ============================================================================
// Test 4: Dangerous action gating -- risk level verification
// ============================================================================

/// delete_ticket should be high risk + dangerous + interactive approval.
/// Write operations should be medium/risky. Read operations should be low/safe.
#[test]
fn zendesk_operation_risk_levels_properly_gated() {
    let manifest = zendesk_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    // Dangerous: high risk + dangerous + interactive
    let dangerous_ops = ["zendesk.delete_ticket"];
    for op_name in dangerous_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        let approval = op
            .get("requires_approval")
            .and_then(toml::Value::as_str)
            .unwrap();

        assert_eq!(risk, "high", "{op_name} should be high risk, got {risk}");
        assert_eq!(
            safety, "dangerous",
            "{op_name} should be dangerous, got {safety}"
        );
        assert_eq!(
            approval, "interactive",
            "{op_name} should require interactive approval, got {approval}"
        );
    }

    // Write: medium risk + risky + policy
    let write_ops = [
        "zendesk.create_ticket",
        "zendesk.update_ticket",
        "zendesk.apply_macro",
    ];
    for op_name in write_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        let approval = op
            .get("requires_approval")
            .and_then(toml::Value::as_str)
            .unwrap();

        assert_eq!(
            risk, "medium",
            "{op_name} should be medium risk, got {risk}"
        );
        assert_eq!(safety, "risky", "{op_name} should be risky, got {safety}");
        assert_eq!(
            approval, "policy",
            "{op_name} should require policy approval, got {approval}"
        );
    }

    // Read: low risk + safe + no approval
    let read_ops = [
        "zendesk.get_ticket",
        "zendesk.search_tickets",
        "zendesk.list_ticket_comments",
        "zendesk.search_articles",
        "zendesk.get_article",
        "zendesk.search_users",
    ];
    for op_name in read_ops {
        let op = operations.get(op_name).unwrap_or_else(|| {
            panic!("operation {op_name} should exist in manifest");
        });
        let risk = op.get("risk_level").and_then(toml::Value::as_str).unwrap();
        let safety = op.get("safety_tier").and_then(toml::Value::as_str).unwrap();
        let approval = op
            .get("requires_approval")
            .and_then(toml::Value::as_str)
            .unwrap();

        assert_eq!(risk, "low", "{op_name} should be low risk, got {risk}");
        assert_eq!(safety, "safe", "{op_name} should be safe, got {safety}");
        assert_eq!(
            approval, "none",
            "{op_name} should need no approval, got {approval}"
        );
    }

    // Total operation count
    assert_eq!(
        operations.len(),
        14,
        "Zendesk manifest should have 14 operations"
    );
}
