//! E2E Terraform connector compliance tests.
//!
//! Exercises the Terraform connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features terraform`

#![cfg(feature = "terraform")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
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
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

use fcp_terraform::connector::TerraformConnector;

// ============================================================================
// FcpConnector adapter for TerraformConnector
// ============================================================================

struct TerraformConnectorAdapter {
    connector: TerraformConnector,
    id: ConnectorId,
    instance_id: InstanceId,
    verifier: Option<CapabilityVerifier>,
}

impl TerraformConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: TerraformConnector::new(),
            id: ConnectorId::from_static("terraform"),
            instance_id: InstanceId::new(),
            verifier: None,
        }
    }
}

fcp_core::impl_fcp_sealed!(TerraformConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for TerraformConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        // br-619oy: serialize the REAL HandshakeRequest into the
        // connector and assert on the connector-returned payload
        // instead of fabricating a compliant HandshakeResponse in the
        // adapter. The previous implementation discarded the
        // connector's reply and synthesized a fresh response that
        // would pass even if the connector's handshake contract drifted
        // (e.g., protocol_version change, capability list regression).
        let session_id = SessionId::new();
        let mut params = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        // The terraform connector tracks a session_id internally; inject
        // ours into the params bag so the connector's session state
        // matches the adapter-level session reported back to the host.
        if let Some(obj) = params.as_object_mut() {
            obj.insert(
                "session_id".to_string(),
                serde_json::Value::String(session_id.0.to_string()),
            );
        }

        let response = self.connector.handle_handshake(params).await?;

        // Assert the connector-returned contract shape (protocol
        // version, connector identity, capabilities list). Any drift
        // in these must surface as a handshake failure at the adapter
        // boundary, not silently pass.
        let protocol_version = response
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "terraform handshake response missing protocol_version".into(),
            })?;
        if protocol_version != "2.0" {
            return Err(FcpError::Internal {
                message: format!(
                    "terraform handshake protocol_version expected 2.0, got {protocol_version}"
                ),
            });
        }
        let _connector_id = response
            .get("connector_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "terraform handshake response missing connector_id".into(),
            })?;
        let connector_caps: std::collections::BTreeSet<String> = response
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| FcpError::Internal {
                message: "terraform handshake response missing capabilities array".into(),
            })?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();

        // Only grant capabilities the connector actually declared. A
        // request for a capability the connector does not publish is
        // silently dropped from `capabilities_granted` — matching the
        // production host's expected behavior.
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
            manifest_hash: "sha256:terraform-e2e".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
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
                    "degraded" => HealthSnapshot::degraded("not_handshaken"),
                    "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("terraform_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.verifier = None;
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("terraform.state_list"),
                summary: "List all resources in the Terraform state".to_string(),
                description: None,
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["working_dir"],
                    "properties": {
                        "working_dir": { "type": "string" }
                    }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "resources": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static("terraform.state"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List all resources tracked in Terraform state.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"working_dir": "/infra/production"}"#.to_string()],
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
            message: "terraform verifier not initialized; handshake required".into(),
        })?;
        let required_cap = required_capability(req.operation.as_str())?;
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let request_id = req.id.clone();
        let value = self
            .connector
            .handle_invoke(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let verifier = self.verifier.as_ref().ok_or(FcpError::Internal {
            message: "terraform verifier not initialized; handshake required".into(),
        })?;
        let required_cap = required_capability(req.operation.as_str())?;
        verifier.verify_bound(req.capability_token, &required_cap, &req.operation, &[])?;

        let value = self
            .connector
            .handle_simulate(json!({
                "operation_id": req.operation.as_str(),
                "input": req.input,
            }))
            .await?;
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

fn required_capability(operation: &str) -> fcp_core::FcpResult<CapabilityId> {
    let capability = match operation {
        "terraform.init"
        | "terraform.validate"
        | "terraform.plan"
        | "terraform.show_plan"
        | "terraform.detect_drift"
        | "terraform.list_modules" => "terraform.plan",
        "terraform.apply" | "terraform.destroy" => "terraform.apply",
        "terraform.state_list" | "terraform.state_show" | "terraform.output" => "terraform.state",
        "terraform.import" => "terraform.state_write",
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
        nonce: [7u8; 32],
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
    let cose = CapabilityTokenBuilder::new()
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
    CapabilityToken::from_raw(cose)
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("terraform-e2e"),
        connector_id: ConnectorId::from_static("terraform"),
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

fn terraform_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/terraform/manifest.toml"))
        .expect("terraform manifest toml")
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
/// Token grants "terraform.apply" but invoke targets "terraform.state_list"
/// (which requires "terraform.state").
#[fcp_async_core::runtime::test]
async fn terraform_default_deny_compliance_suite_passes() {
    let mut connector = TerraformConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["terraform.apply"]);
    // Token grants "terraform.apply" but invoke targets "terraform.state_list" -> denial
    let token = build_token(
        &signing_key,
        "terraform.apply",
        &["terraform.apply"],
        connector.instance_id.as_str(),
    );
    let invoke = invoke_request(
        "terraform.state_list",
        json!({ "working_dir": "/infra/test-ws" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "api_token": "test-token-000",
            "organization": "test-org",
            "base_url": "http://localhost:9999"
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
        "terraform_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-terraform");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock REST API.
#[fcp_async_core::runtime::test]
async fn terraform_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mock 1: GET /organizations/{org}/workspaces/{ws_name} -> workspace with id
    Mock::given(method("GET"))
        .and(path_regex(r"^/organizations/.*/workspaces/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "ws-test-001",
                "type": "workspaces",
                "attributes": { "name": "test-ws" }
            }
        })))
        .mount(mock.inner())
        .await;

    // Mock 2: GET /workspaces/{ws_id}/current-state-version -> state version
    Mock::given(method("GET"))
        .and(path_regex(r"^/workspaces/.*/current-state-version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "id": "sv-test-001",
                "type": "state-versions",
                "attributes": { "serial": 1 }
            }
        })))
        .mount(mock.inner())
        .await;

    // Mock 3: GET /state-versions/{sv_id}/resources -> resource list
    Mock::given(method("GET"))
        .and(path_regex(r"^/state-versions/.*/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "id": "res-1",
                "type": "state-version-resources",
                "attributes": {
                    "address": "aws_instance.web",
                    "provider": "provider.aws"
                }
            }]
        })))
        .mount(mock.inner())
        .await;

    let mut connector = TerraformConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["terraform.state"]);
    let token = build_token(
        &signing_key,
        "terraform.state",
        &["terraform.state_list"],
        connector.instance_id.as_str(),
    );
    let invoke = invoke_request(
        "terraform.state_list",
        json!({ "working_dir": "/infra/test-ws" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "terraform_allow_valid_token".to_string(),
        config: json!({
            "api_token": "test-token-e2e",
            "organization": "test-org",
            "base_url": mock.base_url(),
        }),
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

    let mut runner = E2eRunner::new("fcp-e2e-terraform");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    let received = mock.received_requests().await;
    let workspace_hits = received
        .iter()
        .filter(|r| r.url.path() == "/organizations/test-org/workspaces/test-ws")
        .count();
    assert_eq!(
        workspace_hits, 1,
        "expected exactly one GET to /organizations/test-org/workspaces/test-ws"
    );
    let state_version_hits = received
        .iter()
        .filter(|r| r.url.path() == "/workspaces/ws-test-001/current-state-version")
        .count();
    assert_eq!(
        state_version_hits, 1,
        "expected exactly one GET to /workspaces/ws-test-001/current-state-version"
    );
    let resource_hits = received
        .iter()
        .filter(|r| r.url.path() == "/state-versions/sv-test-001/resources")
        .count();
    assert_eq!(
        resource_hits, 1,
        "expected exactly one GET to /state-versions/sv-test-001/resources"
    );
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
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Terraform manifest restricts operations to
/// `app.terraform.io` and `*.terraform.io`.
/// Verify that matching hosts pass and non-matching hosts are denied.
#[test]
fn terraform_manifest_network_guard_allows_and_denies() {
    let manifest = terraform_manifest_toml();

    let operations = [
        "terraform.init",
        "terraform.validate",
        "terraform.plan",
        "terraform.apply",
        "terraform.state_list",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);

        // All operations should allow app.terraform.io
        assert!(
            host_allowed("app.terraform.io", &host_allow),
            "app.terraform.io should be allowed for {operation_name}"
        );

        // All operations should allow subdomains via *.terraform.io
        assert!(
            host_allowed("registry.terraform.io", &host_allow),
            "registry.terraform.io should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("archivist.terraform.io", &host_allow),
            "archivist.terraform.io should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("evil.com", &host_allow),
            "evil.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("notterraform.io", &host_allow),
            "notterraform.io should be denied for {operation_name}"
        );
    }
}
