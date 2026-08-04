//! E2E Jira connector compliance tests.
//!
//! Exercises the Jira connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints
//! - Dangerous operation gating for issue deletion
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features jira`

#![cfg(feature = "jira")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_async_core::sync::Mutex;
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_jira::connector::JiraConnector;
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

// ============================================================================
// FcpConnector adapter for JiraConnector
// ============================================================================

struct JiraConnectorAdapter {
    connector: Mutex<JiraConnector>,
    id: ConnectorId,
}

impl JiraConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: Mutex::new(JiraConnector::new()),
            id: ConnectorId::from_static("jira"),
        }
    }

    /// The Jira connector verifies tokens with `verify_bound` against its own
    /// (fixed) instance_id; expose it so test tokens can bind to it
    /// (instance-binding pattern, commit 16171621d).
    async fn connector_instance_id(&self) -> String {
        self.connector
            .lock()
            .await
            .instance_id()
            .as_str()
            .to_string()
    }
}

fcp_core::impl_fcp_sealed!(JiraConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for JiraConnectorAdapter {
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
        let req_json = serde_json::to_value(&req).map_err(|e| FcpError::Internal {
            message: format!("failed to serialize handshake request: {e}"),
        })?;
        let resp_val = self
            .connector
            .lock()
            .await
            .handle_handshake(req_json)
            .await?;
        serde_json::from_value(resp_val).map_err(|e| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {e}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.lock().await.handle_health().await {
            Ok(val) => {
                let status = val
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "degraded" => HealthSnapshot::degraded("not_handshaken"),
                    "unconfigured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("jira_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<fcp_core::SelfCheckReport> {
        let value = self.connector.lock().await.handle_self_check().await?;
        serde_json::from_value(value).map_err(|e| FcpError::Internal {
            message: format!("Failed to parse self_check result: {e}"),
        })
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
                id: OperationId::from_static("jira.get_issue"),
                summary: "jira.get_issue".to_string(),
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("jira.get_issue"),
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
        let request_id = req.id.clone();
        let value = self
            .connector
            .lock()
            .await
            .handle_invoke(json!({
                "operation": req.operation.as_str(),
                "input": req.input,
                "capability_token": req.capability_token,
            }))
            .await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
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

// ============================================================================
// Helpers
// ============================================================================

fn jira_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/jira/manifest.toml");
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
        nonce: [11u8; 32],
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
    let resolved_capability = match capability {
        "jira.get_issue" => "jira.read",
        "jira.delete_issue" => "jira.delete",
        _ => capability,
    };
    let cose = CapabilityTokenBuilder::new()
        .capability_id(resolved_capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        // dja9u typestate ratchet: the Jira connector verifies with
        // verify_bound, which requires an INSTANCE_ID claim; bind to the
        // connector instance (instance-binding pattern, commit 16171621d).
        .target_instance(instance_id)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
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
        id: RequestId::from("jira-e2e"),
        connector_id: ConnectorId::from_static("jira"),
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

fn jira_config(base_url: &str) -> serde_json::Value {
    json!({
        "domain": "test-org",
        "email": "user@example.com",
        "api_token": "test-token-xyz",
        "base_url": base_url,
        "agile_url": base_url
    })
}

fn jira_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/jira/manifest.toml"))
        .expect("jira manifest toml")
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

fn jira_issue_response() -> serde_json::Value {
    json!({
        "id": "10001",
        "key": "PROJ-123",
        "self": "https://test-org.atlassian.net/rest/api/3/issue/10001",
        "fields": {
            "summary": "Issue from E2E",
            "status": { "name": "Open" }
        }
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

#[fcp_async_core::runtime::test]
async fn jira_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;

    let mut connector = JiraConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = connector.connector_instance_id().await;
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["jira.get_issue"]);
    let token = build_token(
        &signing_key,
        &instance_id,
        "jira.get_issue",
        &["jira.get_issue"],
    );
    let invoke = invoke_request(
        "jira.create_issue",
        json!({
            "project_key": "PROJ",
            "issue_type": "Task",
            "summary": "Denied create"
        }),
        token,
    );

    let dynamic = DynamicSuite {
        config: jira_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new("jira_default_deny", jira_manifest_with_hash(), dynamic);

    let mut runner = E2eRunner::new("fcp-e2e-jira");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

#[fcp_async_core::runtime::test]
async fn jira_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path("/issue/PROJ-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jira_issue_response()))
        .mount(mock.inner())
        .await;

    let mut connector = JiraConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = connector.connector_instance_id().await;
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["jira.get_issue"]);
    let token = build_token(
        &signing_key,
        &instance_id,
        "jira.get_issue",
        &["jira.get_issue"],
    );
    let invoke = invoke_request("jira.get_issue", json!({ "issue_key": "PROJ-123" }), token);
    let suite = ConnectorSuite {
        test_name: "jira_allow_valid_token".to_string(),
        config: jira_config(&mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-jira");
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
        .filter(|request| request.url.path() == "/issue/PROJ-123")
        .count();
    assert_eq!(hits, 1, "expected exactly one GET to /issue/PROJ-123");
}

// ============================================================================
// Test 3: Network guard -- manifest host allow/deny checks
// ============================================================================

#[test]
fn jira_manifest_network_guard_allows_and_denies() {
    let manifest = jira_manifest_toml();
    let operations = [
        "jira.create_issue",
        "jira.get_issue",
        "jira.update_issue",
        "jira.delete_issue",
        "jira.search_jql",
        "jira.list_transitions",
        "jira.transition_issue",
        "jira.list_sprints",
        "jira.move_to_sprint",
        "jira.add_comment",
        "jira.list_comments",
        "jira.add_attachment",
    ];

    let expected_hosts = vec!["*.atlassian.net".to_string()];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should use *.atlassian.net host allowlist"
        );

        // Allowlisted hosts.
        assert!(host_allowed("test-org.atlassian.net", &host_allow));
        assert!(host_allowed("acme-prod.atlassian.net", &host_allow));

        // Denied hosts.
        assert!(!host_allowed("atlassian.net", &host_allow));
        assert!(!host_allowed("localhost", &host_allow));
        assert!(!host_allowed("example.com", &host_allow));

        let constraints = operation_network_constraints(&manifest, operation_name);
        assert_eq!(
            constraints
                .get("deny_localhost")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must deny localhost"
        );
        assert_eq!(
            constraints
                .get("deny_private_ranges")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must deny private ranges"
        );
    }
}

// ============================================================================
// Test 4: Dangerous operation gating (delete issue)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn jira_dangerous_delete_requires_delete_capability() {
    let mock = MockApiServer::start().await;
    let mut adapter = JiraConnectorAdapter::new();
    adapter
        .configure(jira_config(&mock.base_url()))
        .await
        .expect("configure");

    let signing_key = Ed25519SigningKey::generate();
    adapter
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["jira.get_issue"],
        ))
        .await
        .expect("handshake");

    let token = build_token(
        &signing_key,
        &adapter.connector_instance_id().await,
        "jira.get_issue",
        &["jira.get_issue"],
    );
    let req = invoke_request(
        "jira.delete_issue",
        json!({ "issue_key": "PROJ-123" }),
        token,
    );
    let err = adapter
        .invoke(req)
        .await
        .expect_err("delete should fail without jira.delete_issue capability");

    match err {
        FcpError::CapabilityDenied { capability, reason } => {
            assert_eq!(capability, "jira.delete_issue");
            assert!(reason.to_lowercase().contains("capability"));
        }
        FcpError::OperationNotGranted { operation } => {
            assert_eq!(operation, "jira.delete_issue");
        }
        other => panic!("expected capability denial, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn jira_dangerous_delete_allows_with_delete_capability() {
    let mock = MockApiServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/issue/PROJ-123"))
        .respond_with(ResponseTemplate::new(204))
        .mount(mock.inner())
        .await;

    let mut adapter = JiraConnectorAdapter::new();
    adapter
        .configure(jira_config(&mock.base_url()))
        .await
        .expect("configure");

    let signing_key = Ed25519SigningKey::generate();
    adapter
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["jira.delete_issue"],
        ))
        .await
        .expect("handshake");

    let token = build_token(
        &signing_key,
        &adapter.connector_instance_id().await,
        "jira.delete_issue",
        &["jira.delete_issue"],
    );
    let req = invoke_request(
        "jira.delete_issue",
        json!({ "issue_key": "PROJ-123" }),
        token,
    );
    let response = adapter.invoke(req).await.expect("delete invoke");
    assert_eq!(response.status, InvokeStatus::Ok);
}
