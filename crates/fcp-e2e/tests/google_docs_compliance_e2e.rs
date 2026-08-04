//! E2E Google Docs connector compliance tests.
//!
//! Exercises the Google Docs connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints

#![cfg(feature = "google_docs")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::sync::Mutex;
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
    matchers::{method, path_regex},
};

use fcp_google_docs::connector::DocsConnector;

struct GoogleDocsConnectorAdapter {
    connector: Mutex<DocsConnector>,
    id: ConnectorId,
}

impl GoogleDocsConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(DocsConnector::new()),
            id: ConnectorId::from_static("google-docs"),
        }
    }
}

fcp_core::impl_fcp_sealed!(GoogleDocsConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GoogleDocsConnectorAdapter {
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
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self
            .connector
            .lock()
            .await
            .handle_handshake(request)
            .await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
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
                    "not_configured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("docs_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
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
                id: OperationId::from_static("docs.get"),
                summary: "Get a document by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["document_id"],
                    "properties": {
                        "document_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "document": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("docs.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Retrieve a Google Docs document by ID.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"document_id":"doc_123"}"#.to_string()],
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
        let value = self.connector.lock().await.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let value = self.connector.lock().await.handle_simulate(request).await?;
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

fn docs_manifest_with_hash() -> String {
    const PLACEHOLDER_HASH: &str = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";
    let raw = include_str!("../../../connectors/google-docs/manifest.toml");
    let current_manifest: toml::Value = toml::from_str(raw).expect("google-docs manifest TOML");
    let current_hash = current_manifest
        .get("manifest")
        .and_then(|manifest| manifest.get("interface_hash"))
        .and_then(toml::Value::as_str)
        .expect("manifest.interface_hash");
    assert!(
        !current_hash.is_empty(),
        "manifest.interface_hash must not be empty"
    );
    let normalized = raw.replacen(current_hash, PLACEHOLDER_HASH, 1);
    assert!(
        normalized.contains(PLACEHOLDER_HASH),
        "manifest interface_hash placeholder was not inserted"
    );
    let unchecked =
        ConnectorManifest::parse_str_unchecked(&normalized).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    normalized.replace(PLACEHOLDER_HASH, &computed.to_string())
}

fn docs_manifest_toml() -> toml::Value {
    toml::from_str(include_str!(
        "../../../connectors/google-docs/manifest.toml"
    ))
    .expect("google-docs manifest TOML")
}

fn docs_config(base_url: &str) -> serde_json::Value {
    json!({
        "access_token": "ya29_test_e2e",
        "base_url": format!("{base_url}/v1"),
    })
}

fn handshake_request(
    host_public_key: [u8; 32],
    capabilities: &[&str],
    instance_id: InstanceId,
) -> HandshakeRequest {
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
        // The connector honors requested_instance_id and verifies with
        // verify_bound; pin it to the test instance so the token's INSTANCE_ID
        // claim matches (instance-binding pattern, commit 16171621d).
        requested_instance_id: Some(instance_id),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
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
        // dja9u typestate ratchet: connector verifies with verify_bound, which
        // requires an INSTANCE_ID claim; bind to the test instance
        // (instance-binding pattern, commit 16171621d).
        .target_instance(instance_id)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("attach token constraints")
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
        id: RequestId::from("docs-e2e"),
        connector_id: ConnectorId::from_static("google-docs"),
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

fn docs_get_response() -> serde_json::Value {
    json!({
        "documentId": "doc_123",
        "title": "Docs E2E",
        "body": {
            "content": []
        }
    })
}

#[fcp_async_core::runtime::test]
async fn google_docs_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;

    let mut connector = GoogleDocsConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["docs.write"],
        instance_id.clone(),
    );
    let token = build_token(
        &signing_key,
        instance_id.as_str(),
        "docs.write",
        &["docs.create"],
    );
    let invoke = invoke_request("docs.get", json!({ "document_id": "doc_123" }), token);

    let dynamic = DynamicSuite {
        config: docs_config(&mock.base_url()),
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
        "google_docs_default_deny",
        docs_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-google-docs");
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
async fn google_docs_happy_path_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/v1/documents/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(docs_get_response()))
        .mount(mock.inner())
        .await;

    let mut connector = GoogleDocsConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["docs.read"],
        instance_id.clone(),
    );
    let token = build_token(
        &signing_key,
        instance_id.as_str(),
        "docs.read",
        &["docs.get"],
    );
    let invoke = invoke_request("docs.get", json!({ "document_id": "doc_123" }), token);

    let suite = ConnectorSuite {
        test_name: "google_docs_happy_path".to_string(),
        config: docs_config(&mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-google-docs-happy");
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
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|request| request.url.path() == "/v1/documents/doc_123")
        .count();
    assert_eq!(hits, 1, "expected exactly one GET to /v1/documents/doc_123");
}

#[test]
fn google_docs_manifest_network_guard_allows_and_denies() {
    let manifest = docs_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    assert_eq!(
        operations.len(),
        3,
        "Google Docs manifest should declare 3 operations"
    );

    let expected_hosts = vec!["docs.googleapis.com".to_string()];

    for operation_name in operations.keys() {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow only docs.googleapis.com"
        );
        assert!(host_allowed("docs.googleapis.com", &host_allow));
        assert!(!host_allowed("www.googleapis.com", &host_allow));
        assert!(!host_allowed("example.com", &host_allow));
        assert!(!host_allowed("127.0.0.1", &host_allow));

        let constraints = operation_network_constraints(&manifest, operation_name);
        assert_eq!(
            constraints
                .get("deny_localhost")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            constraints
                .get("deny_private_ranges")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            constraints
                .get("require_sni")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
    }
}
