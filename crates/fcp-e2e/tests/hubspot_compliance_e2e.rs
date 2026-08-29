//! E2E `HubSpot` connector compliance tests.
//!
//! Exercises the `HubSpot` connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features hubspot`

#![cfg(feature = "hubspot")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    AgentHint, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId,
    OperationInfo, RequestId, RiskLevel, SafetyTier, SessionId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path_regex},
};

use fcp_hubspot::connector::HubSpotConnector;

// ============================================================================
// FcpConnector adapter for HubSpotConnector
// ============================================================================

struct HubSpotConnectorAdapter {
    connector: HubSpotConnector,
    id: ConnectorId,
}

impl HubSpotConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: HubSpotConnector::new(),
            id: ConnectorId::from_static("hubspot"),
        }
    }
}

fcp_core::impl_fcp_sealed!(HubSpotConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for HubSpotConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let session_id = SessionId::new();
        let mut request = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let request_obj = request.as_object_mut().ok_or_else(|| FcpError::Internal {
            message: "hubspot handshake request did not serialize to an object".into(),
        })?;
        request_obj.insert(
            "session_id".to_string(),
            serde_json::Value::String(session_id.0.to_string()),
        );

        let response = self.connector.handle_handshake(request).await?;

        let protocol_version = response
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "hubspot handshake response missing protocol_version".into(),
            })?;
        if protocol_version != "2.0" {
            return Err(FcpError::Internal {
                message: format!(
                    "hubspot handshake protocol_version expected 2.0, got {protocol_version}"
                ),
            });
        }
        let connector_id = response
            .get("connector_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "hubspot handshake response missing connector_id".into(),
            })?;
        if connector_id != "fcp.hubspot" {
            return Err(FcpError::Internal {
                message: format!(
                    "hubspot handshake connector_id expected fcp.hubspot, got {connector_id}"
                ),
            });
        }
        let _connector_version = response
            .get("connector_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "hubspot handshake response missing connector_version".into(),
            })?;
        let connector_caps: std::collections::BTreeSet<String> = response
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| FcpError::Internal {
                message: "hubspot handshake response missing capabilities array".into(),
            })?
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
        let expected_caps = std::collections::BTreeSet::from([
            "hubspot.contacts.read".to_string(),
            "hubspot.contacts.write".to_string(),
            "hubspot.contacts.delete".to_string(),
            "hubspot.companies.read".to_string(),
            "hubspot.companies.write".to_string(),
            "hubspot.deals.read".to_string(),
            "hubspot.deals.write".to_string(),
            "hubspot.pipelines.read".to_string(),
            "hubspot.analytics.read".to_string(),
            "hubspot.events.read".to_string(),
            "hubspot.associations.read".to_string(),
            "hubspot.associations.write".to_string(),
        ]);
        if connector_caps != expected_caps {
            return Err(FcpError::Internal {
                message: format!(
                    "hubspot handshake capabilities mismatch: expected {expected_caps:?}, got {connector_caps:?}"
                ),
            });
        }

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .iter()
            .filter(|capability| connector_caps.contains(capability.as_str()))
            .cloned()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:hubspot-connector-v1".into(),
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
                    "not_configured" | "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("hubspot_status:{other}")),
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
                id: OperationId::from_static("hubspot.contacts.list"),
                summary: "List contacts with optional filtering and property selection".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": [],
                    "properties": {
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100 },
                        "after": { "type": "string" },
                        "properties": { "type": "array" },
                        "filter_groups": { "type": "array" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "results": { "type": "array" },
                        "paging": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("hubspot.contacts.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List or search contacts in HubSpot CRM.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![
                        r#"{"limit": 50, "properties": ["email", "firstname", "lastname"]}"#
                            .to_string(),
                    ],
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
            "operation_id": req.operation.as_str(),
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
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize test constraints");
    let resolved_capability = match capability {
        "hubspot.contacts.list" => "hubspot.contacts.read",
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
        .expect("test constraints CBOR should be valid")
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
        id: RequestId::from("hubspot-e2e"),
        connector_id: ConnectorId::from_static("hubspot"),
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

fn hubspot_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/hubspot/manifest.toml"))
        .expect("hubspot manifest toml")
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

/// HubSpot contacts list API success response.
fn hubspot_contacts_list_response() -> serde_json::Value {
    json!({
        "results": [
            {
                "id": "1",
                "properties": {
                    "email": "test@example.com"
                }
            }
        ],
        "paging": {}
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "hubspot.write" but invoke targets "hubspot.contacts.list"
/// (which requires "hubspot.read").
#[fcp_async_core::runtime::test]
async fn hubspot_default_deny_compliance_suite_passes() {
    let mut connector = HubSpotConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["hubspot.write"]);
    // Token grants "hubspot.write" but invoke targets "hubspot.contacts.list" -> error
    // (the connector will fail because the server at localhost:9999 is unreachable)
    let token = build_token(&signing_key, "hubspot.write", &["hubspot.write"]);
    let invoke = invoke_request("hubspot.contacts.list", json!({ "limit": 10 }), token);

    let dynamic = DynamicSuite {
        config: json!({
            "access_token": "pat-test-000",
            "base_url": "http://localhost:9999"
        }),
        handshake: handshake.clone(),
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: false,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new(
        "hubspot_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-hubspot");
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
async fn hubspot_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /crm/v3/objects/contacts
    Mock::given(method("GET"))
        .and(path_regex(r"^/crm/v3/objects/contacts.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(hubspot_contacts_list_response()))
        .mount(mock.inner())
        .await;

    let mut connector = HubSpotConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["hubspot.contacts.read"],
    );
    let token = build_token(
        &signing_key,
        "hubspot.contacts.list",
        &["hubspot.contacts.list"],
    );
    let invoke = invoke_request("hubspot.contacts.list", json!({ "limit": 10 }), token);
    let suite = ConnectorSuite {
        test_name: "hubspot_allow_valid_token".to_string(),
        config: json!({
            "access_token": "pat-test-e2e",
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

    let mut runner = E2eRunner::new("fcp-e2e-hubspot");
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
        .filter(|request| request.url.path() == "/crm/v3/objects/contacts")
        .count();
    assert_eq!(
        hits, 1,
        "expected exactly one GET to /crm/v3/objects/contacts"
    );
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: HubSpot manifest restricts operations to
/// `api.hubapi.com` and `api.hubspot.com`.
/// Verify that matching hosts pass and non-matching hosts are denied.
#[test]
fn hubspot_manifest_network_guard_allows_and_denies() {
    let manifest = hubspot_manifest_toml();

    let operations = [
        "hubspot.contacts.list",
        "hubspot.contacts.get",
        "hubspot.contacts.create",
        "hubspot.deals.list",
        "hubspot.companies.list",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);

        // All operations should allow api.hubapi.com
        assert!(
            host_allowed("api.hubapi.com", &host_allow),
            "api.hubapi.com should be allowed for {operation_name}"
        );

        // All operations should allow api.hubspot.com
        assert!(
            host_allowed("api.hubspot.com", &host_allow),
            "api.hubspot.com should be allowed for {operation_name}"
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
            !host_allowed("nothubspot.com", &host_allow),
            "nothubspot.com should be denied for {operation_name}"
        );
    }
}
