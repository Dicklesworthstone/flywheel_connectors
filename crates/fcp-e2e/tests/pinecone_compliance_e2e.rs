//! E2E Pinecone connector compliance tests (flywheel_connectors-gif.4).
//!
//! Exercises the Pinecone connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock data plane)
//! - Network guard allow/deny (manifest `host_allow` wildcard validation)
//!
//! Pinecone has streaming=false, so no streaming backpressure test.
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features pinecone`

#![cfg(feature = "pinecone")]
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
use wiremock::{Mock, ResponseTemplate, matchers::method};

use fcp_pinecone::connector::PineconeConnector;

// ============================================================================
// FcpConnector adapter for PineconeConnector
// ============================================================================

struct PineconeConnectorAdapter {
    connector: PineconeConnector,
    id: ConnectorId,
}

impl PineconeConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: PineconeConnector::new(),
            id: ConnectorId::from_static("pinecone"),
        }
    }
}

fcp_core::impl_fcp_sealed!(PineconeConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for PineconeConnectorAdapter {
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
                    other => HealthSnapshot::degraded(format!("pinecone_status:{other}")),
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
                id: OperationId::from_static("pinecone.query"),
                summary: "Query vectors by similarity".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["index_name", "top_k"],
                    "properties": {
                        "index_name": { "type": "string" },
                        "vector": { "type": "array" },
                        "top_k": { "type": "integer" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["matches"],
                    "properties": {
                        "matches": { "type": "array" },
                        "namespace": { "type": "string" }
                    }
                }),
                capability: CapabilityId::from_static("pinecone.vectors.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Find similar vectors by similarity search".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![
                        r#"{"index_name": "my-index", "vector": [0.1, 0.2], "top_k": 10}"#
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
    let resolved_capability = match capability {
        "pinecone.query" => "pinecone.vectors.read",
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
        id: RequestId::from("pinecone-e2e"),
        connector_id: ConnectorId::from_static("pinecone"),
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

fn pinecone_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/pinecone/manifest.toml"))
        .expect("pinecone manifest toml")
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

/// Pinecone query success response.
fn pinecone_query_success_response() -> serde_json::Value {
    json!({
        "matches": [
            {
                "id": "vec-1",
                "score": 0.95,
                "metadata": { "text": "hello from pinecone mock" }
            },
            {
                "id": "vec-2",
                "score": 0.82
            }
        ],
        "namespace": ""
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "pinecone.indexes.read" but invoke targets "pinecone.query"
/// (which requires "pinecone.vectors.read").
#[fcp_async_core::runtime::test]
async fn pinecone_default_deny_compliance_suite_passes() {
    let mut connector = PineconeConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["pinecone.indexes.read"],
    );
    // Token grants "pinecone.indexes.read" but invoke targets "pinecone.query" -> denial
    let token = build_token(
        &signing_key,
        "pinecone.indexes.read",
        &["pinecone.indexes.read"],
        connector.connector.instance_id().as_str(),
    );
    let invoke = invoke_request(
        "pinecone.query",
        json!({
            "index_name": "my-index",
            "vector": [0.1, 0.2, 0.3],
            "top_k": 10
        }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "api_key": "test-pinecone-key",
            "data_plane_url": "http://localhost:9999"
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
        "pinecone_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-pinecone");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock data plane.
#[fcp_async_core::runtime::test]
async fn pinecone_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for the data plane query endpoint (POST /query)
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(pinecone_query_success_response()))
        .mount(mock.inner())
        .await;

    let mut connector = PineconeConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["pinecone.query"]);
    let token = build_token(
        &signing_key,
        "pinecone.query",
        &["pinecone.query"],
        connector.connector.instance_id().as_str(),
    );
    let invoke = invoke_request(
        "pinecone.query",
        json!({
            "index_name": "my-index",
            "vector": [0.1, 0.2, 0.3],
            "top_k": 10,
            "include_metadata": true
        }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "pinecone_allow_valid_token".to_string(),
        config: json!({
            "api_key": "test-pinecone-key",
            "data_plane_url": mock.base_url(),
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

    let mut runner = E2eRunner::new("fcp-e2e-pinecone");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|request| request.url.path() == "/query")
        .count();
    assert_eq!(hits, 1, "expected exactly one POST to /query");
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
// Test 3: Network guard -- manifest host_allow wildcard validation
// ============================================================================

/// Network guard: Pinecone manifest restricts all operations to `*.pinecone.io`
/// (wildcard pattern). Verify that matching subdomains are allowed and
/// non-matching hosts are denied.
#[test]
fn pinecone_manifest_network_guard_allows_and_denies() {
    let manifest = pinecone_manifest_toml();

    let operations = [
        "pinecone.list_indexes",
        "pinecone.describe_index",
        "pinecone.describe_index_stats",
        "pinecone.query",
        "pinecone.fetch",
        "pinecone.upsert",
        "pinecone.delete",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow,
            vec!["*.pinecone.io".to_string()],
            "operation {operation_name} should only allow *.pinecone.io"
        );

        // Subdomains of pinecone.io should be allowed
        assert!(
            host_allowed("api.pinecone.io", &host_allow),
            "api.pinecone.io should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("my-index-abc123.svc.pinecone.io", &host_allow),
            "my-index-abc123.svc.pinecone.io should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("us-east1-gcp.pinecone.io", &host_allow),
            "us-east1-gcp.pinecone.io should be allowed for {operation_name}"
        );

        // Non-matching hosts should be denied
        assert!(
            !host_allowed("pinecone.io", &host_allow),
            "pinecone.io (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.pinecone.io.attacker.com", &host_allow),
            "evil.pinecone.io.attacker.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.openai.com", &host_allow),
            "api.openai.com should be denied for {operation_name}"
        );
    }
}
