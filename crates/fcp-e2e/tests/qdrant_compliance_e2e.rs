//! E2E Qdrant connector compliance tests (flywheel_connectors-wke.4).
//!
//! Exercises the Qdrant connector through the E2E compliance harness:
//! - Default deny (missing capability -> error)
//! - Allow reads with valid token (happy path `list_collections` invoke)
//! - Allow writes with valid token (happy path `upsert_points` invoke)
//! - Network guard allow/deny (manifest `host_allow` validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features qdrant`

#![cfg(feature = "qdrant")]
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

use fcp_qdrant::connector::QdrantConnector;

// ============================================================================
// FcpConnector adapter for QdrantConnector
// ============================================================================

struct QdrantConnectorAdapter {
    connector: QdrantConnector,
    id: ConnectorId,
}

impl QdrantConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: QdrantConnector::new(),
            id: ConnectorId::from_static("qdrant"),
        }
    }
}

fcp_core::impl_fcp_sealed!(QdrantConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for QdrantConnectorAdapter {
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
                    other => HealthSnapshot::degraded(format!("qdrant_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("qdrant.list_collections"),
                summary: "List all collections".to_string(),
                description: None,
                input_schema: json!({ "type": "object", "properties": {} }),
                output_schema: json!({
                    "type": "object",
                    "properties": { "collections": { "type": "array" } }
                }),
                capability: CapabilityId::from_static("qdrant.collections.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List all collections in the Qdrant instance.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r"{}".to_string()],
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
        "qdrant.list_collections" => "qdrant.collections.read",
        "qdrant.upsert_points" => "qdrant.points.write",
        "qdrant.search" => "qdrant.points.read",
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
        // dja9u typestate ratchet: verifier binds to handshake instance.
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
        id: RequestId::from("qdrant-e2e"),
        connector_id: ConnectorId::from_static("qdrant"),
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

fn qdrant_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/qdrant/manifest.toml"))
        .expect("qdrant manifest toml")
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
/// Token grants "qdrant.collections.read" but invoke targets "qdrant.upsert_points"
/// (which requires "qdrant.points.write") -> denial.
#[fcp_async_core::runtime::test]
async fn qdrant_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;

    let mut connector = QdrantConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["qdrant.collections.read"],
    );
    // Token grants "qdrant.collections.read" but invoke targets "qdrant.upsert_points" -> denial
    let token = build_token(
        &signing_key,
        "qdrant.collections.read",
        &["qdrant.collections.read"],
        handshake
            .requested_instance_id
            .as_ref()
            .expect("handshake instance id")
            .as_str(),
    );
    let invoke = invoke_request(
        "qdrant.upsert_points",
        json!({
            "collection_name": "test-collection",
            "points": [{"id": 1, "vector": [0.1, 0.2, 0.3], "payload": {"text": "hello"}}]
        }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "api_key": "test-api-key",
            "cluster_url": mock.base_url(),
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
        "qdrant_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-qdrant");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow reads with valid token -- connector suite
// ============================================================================

/// Allow: list_collections invoke with valid capability token succeeds against mock API.
#[fcp_async_core::runtime::test]
async fn qdrant_allow_read_with_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mock the list_collections endpoint
    Mock::given(method("GET"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": {
                "collections": [
                    { "name": "documents" },
                    { "name": "embeddings" }
                ]
            },
            "time": 0.001
        })))
        .mount(mock.inner())
        .await;

    let mut connector = QdrantConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["qdrant.list_collections"],
    );
    let token = build_token(
        &signing_key,
        "qdrant.list_collections",
        &["qdrant.list_collections"],
        handshake
            .requested_instance_id
            .as_ref()
            .expect("handshake instance id")
            .as_str(),
    );
    let invoke = invoke_request("qdrant.list_collections", json!({}), token);
    let suite = ConnectorSuite {
        test_name: "qdrant_allow_read_valid_token".to_string(),
        config: json!({
            "api_key": "test-api-key",
            "cluster_url": mock.base_url(),
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

    let mut runner = E2eRunner::new("fcp-e2e-qdrant");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow read suite should pass");
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|r| r.url.path() == "/collections")
        .count();
    assert_eq!(hits, 1, "expected exactly one GET to /collections");
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
// Test 3: Allow writes with valid token -- connector suite
// ============================================================================

/// Allow: upsert_points invoke with valid capability token succeeds against mock API.
/// Write operations should emit a receipt.
#[fcp_async_core::runtime::test]
async fn qdrant_allow_write_with_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mock the upsert points endpoint
    Mock::given(method("PUT"))
        .and(path("/collections/test-collection/points"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": {
                "operation_id": 42,
                "status": "completed"
            },
            "time": 0.003
        })))
        .mount(mock.inner())
        .await;

    let mut connector = QdrantConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["qdrant.upsert_points"],
    );
    let token = build_token(
        &signing_key,
        "qdrant.upsert_points",
        &["qdrant.upsert_points"],
        handshake
            .requested_instance_id
            .as_ref()
            .expect("handshake instance id")
            .as_str(),
    );
    let invoke = invoke_request(
        "qdrant.upsert_points",
        json!({
            "collection_name": "test-collection",
            "points": [
                {
                    "id": 1,
                    "vector": [0.1, 0.2, 0.3],
                    "payload": { "text": "hello world" }
                }
            ]
        }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "qdrant_allow_write_valid_token".to_string(),
        config: json!({
            "api_key": "test-api-key",
            "cluster_url": mock.base_url(),
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

    let mut runner = E2eRunner::new("fcp-e2e-qdrant");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow write suite should pass");
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|r| r.url.path() == "/collections/test-collection/points")
        .count();
    assert_eq!(
        hits, 1,
        "expected exactly one PUT to /collections/test-collection/points"
    );
}

// ============================================================================
// Test 4: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Qdrant manifest restricts all operations to *.cloud.qdrant.io
/// and denies all other hosts.
#[test]
fn qdrant_manifest_network_guard_allows_and_denies() {
    let manifest = qdrant_manifest_toml();

    let operations = [
        "qdrant.list_collections",
        "qdrant.collection_info",
        "qdrant.create_collection",
        "qdrant.delete_collection",
        "qdrant.search",
        "qdrant.query_points",
        "qdrant.batch_query_points",
        "qdrant.get_points",
        "qdrant.scroll",
        "qdrant.count",
        "qdrant.upsert_points",
        "qdrant.delete_points",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow,
            vec!["*.cloud.qdrant.io".to_string()],
            "operation {operation_name} should allow *.cloud.qdrant.io"
        );

        // Wildcard subdomain match
        assert!(
            host_allowed("my-cluster.cloud.qdrant.io", &host_allow),
            "my-cluster.cloud.qdrant.io should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("abc123.cloud.qdrant.io", &host_allow),
            "abc123.cloud.qdrant.io should be allowed for {operation_name}"
        );
        // Foreign hosts denied
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.openai.com", &host_allow),
            "api.openai.com should be denied for {operation_name}"
        );
        // Subdomain spoofing denied
        assert!(
            !host_allowed("evil-cloud.qdrant.io", &host_allow),
            "evil-cloud.qdrant.io should be denied for {operation_name}"
        );
        // Base domain without subdomain denied (wildcard requires subdomain)
        assert!(
            !host_allowed("cloud.qdrant.io", &host_allow),
            "cloud.qdrant.io (bare) should be denied - wildcard requires a subdomain for {operation_name}"
        );
    }
}

// ============================================================================
// Test 5: Search with valid token -- direct connector test
// ============================================================================

/// Search: invoke qdrant.search with valid token succeeds and returns scored results.
#[fcp_async_core::runtime::test]
async fn qdrant_search_with_valid_token_returns_results() {
    let mock = MockApiServer::start().await;

    // Mock the search endpoint
    Mock::given(method("POST"))
        .and(path("/collections/docs/points/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "result": [
                {
                    "id": 42,
                    "version": 1,
                    "score": 0.95,
                    "payload": { "text": "hello world" },
                    "vector": null
                },
                {
                    "id": 17,
                    "version": 1,
                    "score": 0.82,
                    "payload": { "text": "foo bar" },
                    "vector": null
                }
            ],
            "time": 0.005
        })))
        .mount(mock.inner())
        .await;

    let mut connector = QdrantConnector::new();

    // Configure
    connector
        .handle_configure(json!({
            "api_key": "test-api-key",
            "cluster_url": mock.base_url(),
        }))
        .await
        .expect("configure should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes().to_vec(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["qdrant.search"]
        }))
        .await
        .expect("handshake should succeed");

    // Build valid token and invoke search
    let token = build_token(
        &signing_key,
        "qdrant.search",
        &["qdrant.search"],
        connector.instance_id(),
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "qdrant.search",
            "input": {
                "collection_name": "docs",
                "vector": [0.1, 0.2, 0.3],
                "limit": 5,
                "with_payload": true
            },
            "capability_token": token
        }))
        .await
        .expect("search invoke should succeed");

    let results = result["result"].as_array().expect("result should be array");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["id"], 42);
    assert_eq!(results[1]["id"], 17);
}
