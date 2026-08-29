//! E2E Browser connector compliance tests.
//!
//! Exercises the Browser connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints
//! - Dangerous operation approval gating for `evaluate_js` / form submit
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features browser`

#![cfg(feature = "browser")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_browser::connector::BrowserConnector;
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    AgentHint, ApprovalScope, ApprovalToken, CapabilityId, CapabilityToken, ConnectorId,
    ConnectorMetrics, ExecutionScope, FcpConnector, FcpError, HandshakeRequest, HandshakeResponse,
    HealthSnapshot, IdempotencyClass, InstanceId, Introspection, InvokeRequest, InvokeResponse,
    InvokeStatus, OperationId, OperationInfo, RequestId, RiskLevel, SafetyTier, ShutdownRequest,
    SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
    ZoneId,
};
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

// ============================================================================
// FcpConnector adapter for BrowserConnector
// ============================================================================

struct BrowserConnectorAdapter {
    connector: BrowserConnector,
    id: ConnectorId,
}

impl BrowserConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: BrowserConnector::new(),
            id: ConnectorId::from_static("browser"),
        }
    }

    fn instance_id(&self) -> &str {
        self.connector.instance_id()
    }
}

fcp_core::impl_fcp_sealed!(BrowserConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for BrowserConnectorAdapter {
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
                    other => HealthSnapshot::degraded(format!("browser_status:{other}")),
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
                id: OperationId::from_static("browser.navigate"),
                summary: "Navigate to a URL and wait for page load".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": { "type": "string" },
                        "wait_until": { "type": "string" },
                        "timeout_ms": { "type": "integer" },
                        "user_agent": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["url", "status"],
                    "properties": {
                        "url": { "type": "string" },
                        "status": { "type": "integer" },
                        "title": { "type": "string" }
                    }
                }),
                capability: CapabilityId::from_static("browser.navigate"),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Navigate the browser before extraction or screenshots."
                        .to_string(),
                    common_mistakes: vec![
                        "Using a URL outside network constraints".to_string(),
                        "Not waiting for load conditions".to_string(),
                    ],
                    examples: vec![r#"{"url":"https://docs.github.com"}"#.to_string()],
                    related: vec![CapabilityId::from_static("browser.extract_text")],
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
        let mut params = json!({
            "operation": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        });
        if let Some(token) = req.approval_tokens.first() {
            params["approval_token"] =
                serde_json::to_value(token).map_err(|err| FcpError::Internal {
                    message: format!("failed to serialize approval token: {err}"),
                })?;
        }
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

fn browser_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/browser/manifest.toml");
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
        nonce: [9u8; 32],
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
        "browser.evaluate_js" => "browser.execute",
        "browser.extract_text" => "browser.extract",
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
        // dja9u typestate ratchet: the connector verifies bound tokens against
        // its own base.instance_id, so target_instance must be that id.
        .target_instance(instance_id)
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(cose)
}

fn build_execution_approval(method_pattern: &str) -> ApprovalToken {
    let now_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0);
    ApprovalToken::approved(
        format!("approval-{method_pattern}-{now_ms}"),
        now_ms.saturating_sub(1_000),
        now_ms + 300_000,
        "owner:test",
        ApprovalScope::Execution(ExecutionScope {
            connector_id: "fcp.browser".to_string(),
            method_pattern: method_pattern.to_string(),
            request_object_id: None,
            input_hash: None,
            input_constraints: Vec::new(),
        }),
        ZoneId::work(),
        None,
    )
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
    approval_tokens: Vec<ApprovalToken>,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("browser-e2e"),
        connector_id: ConnectorId::from_static("browser"),
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
        approval_tokens,
    }
}

fn browser_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/browser/manifest.toml"))
        .expect("browser manifest toml")
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

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

#[fcp_async_core::runtime::test]
async fn browser_default_deny_compliance_suite_passes() {
    let mut connector = BrowserConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["browser.extract_text"],
    );

    let token = build_token(
        &signing_key,
        "browser.extract_text",
        &["browser.extract_text"],
        connector.instance_id(),
    );
    let invoke = invoke_request(
        "browser.navigate",
        json!({ "url": "https://docs.github.com" }),
        token,
        Vec::new(),
    );

    let dynamic = DynamicSuite {
        config: json!({
            "browser_url": "http://localhost:9222"
        }),
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
        "browser_default_deny",
        browser_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-browser");
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
async fn browser_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    Mock::given(method("POST"))
        .and(path("/navigate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "url": "https://docs.github.com/en",
            "status": 200,
            "title": "GitHub Docs"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = BrowserConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["browser.navigate"],
    );
    let token = build_token(
        &signing_key,
        "browser.navigate",
        &["browser.navigate"],
        connector.instance_id(),
    );
    let invoke = invoke_request(
        "browser.navigate",
        json!({ "url": "https://docs.github.com" }),
        token,
        Vec::new(),
    );
    let suite = ConnectorSuite {
        test_name: "browser_allow_valid_token".to_string(),
        config: json!({
            "browser_url": mock.base_url(),
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

    let mut runner = E2eRunner::new("fcp-e2e-browser");
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
        .filter(|request| request.url.path() == "/navigate")
        .count();
    assert_eq!(hits, 1, "expected exactly one POST to /navigate");
}

// ============================================================================
// Test 3: Network guard -- manifest host allow/deny checks
// ============================================================================

#[test]
fn browser_manifest_network_guard_allows_and_denies() {
    let manifest = browser_manifest_toml();
    let operations = [
        "browser.navigate",
        "browser.wait_for_selector",
        "browser.extract_text",
        "browser.extract_links",
        "browser.screenshot",
        "browser.render_pdf",
        "browser.click",
        "browser.fill_form",
        "browser.evaluate_js",
        "browser.get_cookies",
        "browser.set_cookies",
        "browser.set_proxy",
        "browser.clear_proxy",
        "browser.session.save",
        "browser.session.restore",
        "browser.session.describe",
    ];

    let expected_hosts = vec![
        "*.github.com".to_string(),
        "*.google.com".to_string(),
        "*.wikipedia.org".to_string(),
        "*.amazonaws.com".to_string(),
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should use the browser network host allowlist"
        );

        // Allowlisted hosts.
        assert!(host_allowed("docs.github.com", &host_allow));
        assert!(host_allowed("www.google.com", &host_allow));

        // Denied hosts.
        assert!(!host_allowed("localhost", &host_allow));
        assert!(!host_allowed("127.0.0.1", &host_allow));
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
// Test 4: Dangerous operation approval gating (execute_js + form submit)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn browser_dangerous_operations_require_approval_tokens() {
    let mock = MockApiServer::start().await;
    let mut adapter = BrowserConnectorAdapter::new();
    adapter
        .configure(json!({ "browser_url": mock.base_url() }))
        .await
        .expect("configure");

    let signing_key = Ed25519SigningKey::generate();
    adapter
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["browser.execute", "browser.interact"],
        ))
        .await
        .expect("handshake");

    let cases = [
        (
            "browser.evaluate_js",
            "browser.execute",
            json!({ "expression": "document.title" }),
        ),
        (
            "browser.fill_form",
            "browser.interact",
            json!({ "fields": { "#email": "alice@example.com" } }),
        ),
    ];

    for (operation, expected_capability, input) in cases {
        let token = build_token(
            &signing_key,
            expected_capability,
            &[operation],
            adapter.instance_id(),
        );
        let req = invoke_request(operation, input, token, Vec::new());
        let result = adapter.invoke(req).await;
        assert!(result.is_err(), "{operation} should require approval token");
        match result.expect_err("dangerous operation should fail without approval") {
            FcpError::CapabilityDenied { capability, reason } => {
                assert_eq!(capability, operation);
                assert!(reason.contains("ApprovalToken"));
            }
            err => panic!("expected capability denial, got {err:?}"),
        }
    }
}

#[fcp_async_core::runtime::test]
async fn browser_dangerous_operation_allows_with_approval_token() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/evaluate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "GitHub Docs"
        })))
        .mount(mock.inner())
        .await;

    let mut adapter = BrowserConnectorAdapter::new();
    adapter
        .configure(json!({ "browser_url": mock.base_url() }))
        .await
        .expect("configure");

    let signing_key = Ed25519SigningKey::generate();
    adapter
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &["browser.execute"],
        ))
        .await
        .expect("handshake");

    let token = build_token(
        &signing_key,
        "browser.execute",
        &["browser.evaluate_js"],
        adapter.instance_id(),
    );
    let approval = build_execution_approval("browser.evaluate_js");
    let req = invoke_request(
        "browser.evaluate_js",
        json!({ "expression": "document.title" }),
        token,
        vec![approval],
    );
    let response = adapter.invoke(req).await.expect("invoke with approval");
    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("result payload");
    assert_eq!(result["result"], "GitHub Docs");
}
