//! E2E `DocuSign` connector compliance tests.
//!
//! Exercises the `DocuSign` connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` wildcard validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features docusign`

#![cfg(feature = "docusign")]
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

use fcp_docusign::connector::DocuSignConnector;

// ============================================================================
// Operation -> capability mapping
// ============================================================================

fn required_capability_for_operation(operation: &str) -> &'static str {
    match operation {
        "docusign.list_envelopes"
        | "docusign.get_envelope"
        | "docusign.download_documents"
        | "docusign.list_templates"
        | "docusign.get_template"
        | "docusign.stream_connect_events" => "docusign.read",
        "docusign.create_envelope" | "docusign.add_recipients" => "docusign.write",
        "docusign.send_envelope" | "docusign.void_envelope" => "docusign.send",
        _ => "docusign.read",
    }
}

// ============================================================================
// FcpConnector adapter for DocuSignConnector
// ============================================================================

struct DocuSignConnectorAdapter {
    connector: DocuSignConnector,
    id: ConnectorId,
    verifier: Option<CapabilityVerifier>,
}

impl DocuSignConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: DocuSignConnector::new(),
            id: ConnectorId::from_static("docusign"),
            verifier: None,
        }
    }
}

fcp_core::impl_fcp_sealed!(DocuSignConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for DocuSignConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        // flywheel_connectors-cuqvo: serialize the REAL HandshakeRequest into
        // the connector and assert on the connector-returned payload instead
        // of fabricating a compliant HandshakeResponse.
        let session_id = SessionId::new();
        let mut request = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        if let Some(obj) = request.as_object_mut() {
            obj.insert(
                "session_id".to_string(),
                serde_json::Value::String(session_id.0.to_string()),
            );
        }

        let response = self.connector.handle_handshake(request).await?;

        let protocol_version = response
            .get("protocol_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "docusign handshake response missing protocol_version".into(),
            })?;
        if protocol_version != "2.0" {
            return Err(FcpError::Internal {
                message: format!(
                    "docusign handshake protocol_version expected 2.0, got {protocol_version}"
                ),
            });
        }
        let _connector_id = response
            .get("connector_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| FcpError::Internal {
                message: "docusign handshake response missing connector_id".into(),
            })?;
        let connector_caps: std::collections::BTreeSet<String> = response
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| FcpError::Internal {
                message: "docusign handshake response missing capabilities array".into(),
            })?
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
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
            req.requested_instance_id.clone().unwrap_or_default(),
        ));

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: "sha256:docusign-connector-v1".into(),
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
                    other => HealthSnapshot::degraded(format!("docusign_status:{other}")),
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
                id: OperationId::from_static("docusign.list_envelopes"),
                summary: "List envelopes with optional status and date filters".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["account_id"],
                    "properties": {
                        "account_id": { "type": "string" },
                        "status": { "type": "string" },
                        "from_date": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "envelopes": { "type": "array" }
                    }
                }),
                capability: CapabilityId::from_static("docusign.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List envelopes with optional filtering by status, date range, or search text.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"account_id": "abc-123", "from_date": "2026-01-01T00:00:00Z"}"#.to_string()],
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
        // Verify capability token before delegating to the connector.
        let cap_id: CapabilityId = required_capability_for_operation(req.operation.as_str())
            .parse()
            .map_err(|_| FcpError::Internal {
                message: "invalid capability id".into(),
            })?;
        if let Some(verifier) = &self.verifier {
            verifier.verify_bound(req.capability_token.clone(), &cap_id, &req.operation, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

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
        // Mirror the invoke path: verify the capability token before
        // delegating to the connector. The 17 sibling compliance-e2e
        // suites all verify in BOTH invoke and simulate; docusign was
        // the lone outlier that verified in invoke but skipped simulate.
        // Compliance tests currently set `simulate: None` so this path
        // is not exercised today, but a future test that enables simulate
        // must not observe a weaker auth posture than invoke.
        let cap_id: CapabilityId = required_capability_for_operation(req.operation.as_str())
            .parse()
            .map_err(|_| FcpError::Internal {
                message: "invalid capability id".into(),
            })?;
        if let Some(verifier) = &self.verifier {
            verifier.verify_bound(req.capability_token.clone(), &cap_id, &req.operation, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

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
        // dja9u typestate ratchet: connector verifier binds to this id; the
        // capability token's target_instance must match it (see build_token).
        requested_instance_id: Some(
            InstanceId::try_from("inst_e2e_test_fixture".to_string())
                .expect("valid test instance id"),
        ),
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
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
        .target_instance("inst_e2e_test_fixture")
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
        id: RequestId::from("docusign-e2e"),
        connector_id: ConnectorId::from_static("docusign"),
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

fn docusign_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/docusign/manifest.toml"))
        .expect("docusign manifest toml")
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

/// DocuSign `list_envelopes` API success response.
fn docusign_list_envelopes_response() -> serde_json::Value {
    json!({
        "envelopes": [
            {
                "envelopeId": "abc-123",
                "status": "sent"
            }
        ],
        "resultSetSize": "1"
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "docusign.send" but invoke targets "docusign.list_envelopes"
/// (which requires "docusign.read").
#[fcp_async_core::runtime::test]
async fn default_deny_compliance_suite_passes() {
    let mut connector = DocuSignConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["docusign.send"]);
    // Token grants "docusign.send" but invoke targets "docusign.list_envelopes" -> denial
    let token = build_token(&signing_key, "docusign.send", &["docusign.send"]);
    let invoke = invoke_request(
        "docusign.list_envelopes",
        json!({ "account_id": "12345678" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "access_token": "ey_test_token",
            "account_id": "12345678",
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
        "docusign_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-docusign");
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
async fn allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /{accountId}/envelopes (base_url already includes path prefix)
    Mock::given(method("GET"))
        .and(path_regex(r"^/.*/envelopes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(docusign_list_envelopes_response()))
        .mount(mock.inner())
        .await;

    let mut connector = DocuSignConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["docusign.read"]);
    let token = build_token(&signing_key, "docusign.read", &["docusign.list_envelopes"]);
    let invoke = invoke_request(
        "docusign.list_envelopes",
        json!({ "account_id": "12345678" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "docusign_allow_valid_token".to_string(),
        config: json!({
            "access_token": "ey_test_token",
            "account_id": "12345678",
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

    let mut runner = E2eRunner::new("fcp-e2e-docusign");
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
        .filter(|request| request.url.path() == "/12345678/envelopes")
        .count();
    assert_eq!(hits, 1, "expected exactly one GET to /12345678/envelopes");
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: DocuSign manifest restricts operations to
/// `*.docusign.net`, `*.docusign.com`, and `demo.docusign.net`.
/// Verify that matching hosts pass and non-matching hosts are denied.
#[test]
fn manifest_network_guard_allows_and_denies() {
    let manifest = docusign_manifest_toml();

    let operations = [
        "docusign.list_envelopes",
        "docusign.get_envelope",
        "docusign.create_envelope",
        "docusign.send_envelope",
        "docusign.list_templates",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);

        // All operations should allow docusign.net via *.docusign.net
        assert!(
            host_allowed("na4.docusign.net", &host_allow),
            "na4.docusign.net should be allowed for {operation_name}"
        );

        // All operations should allow demo.docusign.net (exact match or wildcard)
        assert!(
            host_allowed("demo.docusign.net", &host_allow),
            "demo.docusign.net should be allowed for {operation_name}"
        );

        // All operations should allow subdomains via *.docusign.com
        assert!(
            host_allowed("app.docusign.com", &host_allow),
            "app.docusign.com should be allowed for {operation_name}"
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
            !host_allowed("notdocusign.net", &host_allow),
            "notdocusign.net should be denied for {operation_name}"
        );
    }
}
