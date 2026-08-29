//! E2E vectordb connector compliance tests (flywheel_connectors-lszk.26.4).
//!
//! Exercises the vectordb connector through the E2E compliance harness:
//! - Default deny (missing capability -> `OperationNotGranted` error)
//! - Allow with valid token (happy path invoke via capability verification)
//! - Network guard allow/deny (manifest `host_allow` validation)
//! - Operation risk level gating (risk level verification)
//!
//! Adapter delegates to the real connector invoke/introspection paths.
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features vectordb`

#![cfg(feature = "vectordb")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector, FcpError,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, InstanceId, Introspection, InvokeRequest,
    InvokeResponse, InvokeStatus, OperationId, RequestId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::json;

use fcp_vectordb::VectorDbConnector;

// ============================================================================
// FcpConnector adapter for VectorDbConnector
// ============================================================================

struct VectorDbConnectorAdapter {
    connector: VectorDbConnector,
    id: ConnectorId,
}

impl VectorDbConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: VectorDbConnector::new(),
            id: ConnectorId::from_static("vectordb"),
        }
    }
}

fcp_core::impl_fcp_sealed!(VectorDbConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for VectorDbConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let request = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self.connector.handle_handshake(request).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let payload = self.connector.handle_health();
        let status = payload
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        match status {
            "healthy" => HealthSnapshot::ready(),
            "not_configured" => HealthSnapshot::degraded("not_configured"),
            other => HealthSnapshot::degraded(format!("vectordb_status:{other}")),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        self.connector.handle_introspect()
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let payload = self
            .connector
            .handle_invoke(json!({
                "operation": req.operation.as_str(),
                "input": req.input,
                "capability_token": req.capability_token
            }))
            .await?;
        Ok(InvokeResponse::ok(req.id, payload))
    }

    async fn simulate(&self, _req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        Err(FcpError::StreamingNotSupported)
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
        id: RequestId::from("vectordb-e2e"),
        connector_id: ConnectorId::from_static("vectordb"),
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

fn vectordb_config() -> serde_json::Value {
    json!({
        "provider": "qdrant",
        "endpoint": "localhost:6333",
        "credential_id": "11223344-5566-7788-99aa-bbccddeeff00",
        "use_tls": false,
    })
}

fn vectordb_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/vectordb/manifest.toml"))
        .expect("vectordb manifest toml")
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

/// Default deny: invoke without matching capability triggers OperationNotGranted.
/// Token grants "vectordb.collections.delete" but invoke targets "vectordb.list_collections"
/// (which requires "vectordb.collections.read").
#[fcp_async_core::runtime::test]
async fn vectordb_default_deny_compliance_suite_passes() {
    let mut connector = VectorDbConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["vectordb.collections.delete"],
    );
    let token = build_token(
        &signing_key,
        "vectordb.collections.delete",
        &["vectordb.collections.delete"],
        connector.connector.instance_id().as_str(),
    );
    let invoke = invoke_request(
        "vectordb.list_collections",
        json!({ "namespace": "test" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: vectordb_config(),
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
        "vectordb_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-vectordb");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds (stub data).
#[fcp_async_core::runtime::test]
async fn vectordb_allow_valid_token_connector_suite_passes() {
    let mut connector = VectorDbConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["vectordb.list_collections"],
    );
    let token = build_token(
        &signing_key,
        "vectordb.collections.read",
        &["vectordb.list_collections"],
        connector.connector.instance_id().as_str(),
    );
    let invoke = invoke_request(
        "vectordb.list_collections",
        json!({ "namespace": "test" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "vectordb_allow_valid_token".to_string(),
        config: vectordb_config(),
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

    let mut runner = E2eRunner::new("fcp-e2e-vectordb");
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
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: vectordb operations with network_constraints use *.pinecone.io, *.qdrant.io, *.qdrant.tech.
#[test]
fn vectordb_manifest_network_guard_allows_and_denies() {
    let manifest = vectordb_manifest_toml();

    // Only operations that declare network_constraints in the manifest.
    // describe_collection and list_collections are read-only metadata operations
    // without explicit network_constraints sections.
    let constrained_operations = [
        "create_collection",
        "delete_collection",
        "delete_vectors",
        "fetch_vectors",
        "query_vectors",
        "update_vector_metadata",
        "upsert_vectors",
    ];

    let expected_hosts = vec![
        "*.pinecone.io".to_string(),
        "*.qdrant.io".to_string(),
        "*.qdrant.tech".to_string(),
    ];

    for operation_name in constrained_operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow pinecone+qdrant hosts"
        );

        // Allowed: subdomain matches
        assert!(
            host_allowed("my-index.svc.us-east-1.pinecone.io", &host_allow),
            "pinecone subdomain should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("my-cluster.qdrant.io", &host_allow),
            "qdrant.io subdomain should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("cloud.qdrant.tech", &host_allow),
            "qdrant.tech subdomain should be allowed for {operation_name}"
        );

        // Denied: bare domains, other domains, subdomain tricks
        assert!(
            !host_allowed("pinecone.io", &host_allow),
            "pinecone.io (bare) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("qdrant.io", &host_allow),
            "qdrant.io (bare) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("pinecone.io.evil.com", &host_allow),
            "pinecone.io.evil.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("localhost", &host_allow),
            "localhost should be denied for {operation_name}"
        );
    }
}

// ============================================================================
// Test 4: Operation risk levels -- manifest gating verification
// ============================================================================

/// delete_collection: high/dangerous/interactive.
/// create_collection, delete_vectors, upsert_vectors: medium/risky/policy.
/// Rest: low/safe/none.
#[test]
fn vectordb_operation_risk_levels_properly_gated() {
    let manifest = vectordb_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    // Dangerous: high/dangerous/interactive
    let dangerous_ops = ["delete_collection"];
    for op_name in dangerous_ops {
        let op = operations
            .get(op_name)
            .unwrap_or_else(|| panic!("operation {op_name} should exist"));
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

    // Write/risky: medium/risky/policy
    let risky_ops = ["create_collection", "delete_vectors", "upsert_vectors"];
    for op_name in risky_ops {
        let op = operations
            .get(op_name)
            .unwrap_or_else(|| panic!("operation {op_name} should exist"));
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

    // Read/safe: low/safe/none
    let safe_ops = [
        "describe_collection",
        "fetch_vectors",
        "list_collections",
        "query_vectors",
        "update_vector_metadata",
    ];
    for op_name in safe_ops {
        let op = operations
            .get(op_name)
            .unwrap_or_else(|| panic!("operation {op_name} should exist"));
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
        9,
        "vectordb manifest should have 9 operations"
    );
}
