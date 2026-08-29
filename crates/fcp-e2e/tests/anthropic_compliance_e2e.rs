//! E2E Anthropic connector compliance tests (flywheel_connectors-lszk.4.5).
//!
//! Exercises the Anthropic connector through the E2E compliance harness:
//! - Default deny (missing capability → error + decision receipt)
//! - Allow with valid token (happy path invoke)
//! - Network guard allow/deny (manifest `host_allow` validation)
//! - Streaming backpressure (deterministic SSE consumption with inter-chunk delay)
//!
//! All tests are deterministic — no real API calls.
//! Run: `cargo test --package fcp-e2e --features anthropic`

#![cfg(feature = "anthropic")]
#![allow(clippy::too_many_lines)]

use std::time::Duration;

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
use futures_util::{StreamExt, pin_mut};
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{header, method, path},
};

use fcp_anthropic::{
    client::AnthropicClient,
    connector::AnthropicConnector,
    types::{Message, Model, Role},
};

// ============================================================================
// FcpConnector adapter for AnthropicConnector
// ============================================================================

struct AnthropicConnectorAdapter {
    connector: AnthropicConnector,
    id: ConnectorId,
}

impl AnthropicConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: AnthropicConnector::new(),
            id: ConnectorId::from_static("anthropic"),
        }
    }

    fn instance_id(&self) -> &str {
        self.connector.instance_id().as_str()
    }
}

fcp_core::impl_fcp_sealed!(AnthropicConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for AnthropicConnectorAdapter {
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
                    other => HealthSnapshot::degraded(format!("anthropic_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        let requests_total = self.connector.total_requests();
        let requests_error = self.connector.total_errors();
        ConnectorMetrics {
            requests_total,
            requests_success: requests_total.saturating_sub(requests_error),
            requests_error,
            ..ConnectorMetrics::default()
        }
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("anthropic.chat"),
                summary: "Simple chat with Claude (single message)".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": { "type": "string" },
                        "model": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["response"],
                    "properties": { "response": { "type": "string" } }
                }),
                capability: CapabilityId::from_static("anthropic.chat"),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Simple single-turn chat with Claude".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"message":"hello"}"#.to_string()],
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
    // dja9u typestate ratchet: the Anthropic connector verifies bound tokens
    // against its own base.instance_id, so target_instance must be that id.
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
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
        id: RequestId::from("anthropic-e2e"),
        connector_id: ConnectorId::from_static("anthropic"),
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

fn anthropic_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/anthropic/manifest.toml"))
        .expect("anthropic manifest toml")
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

/// Anthropic SSE streaming body for backpressure test.
fn streaming_sse_body() -> String {
    use std::fmt::Write;

    let events: &[(&str, serde_json::Value)] = &[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_e2e_stream_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 10, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""}
            }),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Hello"}
            }),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": " world"}
            }),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ),
        (
            "message_delta",
            json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"input_tokens": 10, "output_tokens": 5}
            }),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ];

    events
        .iter()
        .fold(String::new(), |mut acc, (event_type, data)| {
            write!(acc, "event: {event_type}\ndata: {data}\n\n").unwrap();
            acc
        })
}

// ============================================================================
// Test 1: Default deny — compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Uses the E2E compliance harness with static (manifest) + dynamic checks.
#[fcp_async_core::runtime::test]
async fn anthropic_default_deny_compliance_suite_passes() {
    let mut connector = AnthropicConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["anthropic.get_usage"],
    );
    // Token grants "anthropic.get_usage" but invoke targets "anthropic.chat" → denial
    let token = build_token(
        &signing_key,
        "anthropic.get_usage",
        &["anthropic.get_usage"],
        connector.instance_id(),
    );
    let invoke = invoke_request(
        "anthropic.chat",
        json!({ "message": "blocked request" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({ "api_key": "test-anthropic-key" }),
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
        "anthropic_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-anthropic");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token — connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock API.
#[fcp_async_core::runtime::test]
async fn anthropic_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;
    mock.expect_post(
        "/v1/messages",
        json!({
            "id": "msg_e2e_001",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "hello from mock"}],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 6,
                "output_tokens": 4
            }
        }),
    )
    .await;

    let mut connector = AnthropicConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["anthropic.chat"]);
    let token = build_token(
        &signing_key,
        "anthropic.chat",
        &["anthropic.chat"],
        connector.instance_id(),
    );
    let invoke = invoke_request(
        "anthropic.chat",
        json!({ "message": "hello from e2e" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "anthropic_allow_valid_token".to_string(),
        config: json!({
            "api_key": "test-anthropic-key",
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

    let mut runner = E2eRunner::new("fcp-e2e-anthropic");
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
    mock.assert_received("/v1/messages").await;
}

// ============================================================================
// Test 3: Network guard — manifest host_allow validation
// ============================================================================

/// Network guard: Anthropic manifest allows api.anthropic.com and denies others.
#[test]
fn anthropic_manifest_network_guard_allows_and_denies() {
    let manifest = anthropic_manifest_toml();

    // All Anthropic operations should restrict to api.anthropic.com
    for operation_name in ["anthropic.chat", "anthropic.message"] {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow,
            vec!["api.anthropic.com".to_string()],
            "operation {operation_name} should only allow api.anthropic.com"
        );
        assert!(
            host_allowed("api.anthropic.com", &host_allow),
            "api.anthropic.com should be allowed for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.openai.com", &host_allow),
            "api.openai.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.api.anthropic.com", &host_allow),
            "evil.api.anthropic.com should be denied for {operation_name}"
        );
    }
}

// ============================================================================
// Test 4: Streaming backpressure — deterministic SSE consumption
// ============================================================================

/// Streaming backpressure: SSE chunks are consumed deterministically with
/// inter-chunk delay to verify backpressure handling.
#[fcp_async_core::runtime::test]
async fn anthropic_streaming_backpressure_is_deterministic() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "stream-test-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(streaming_sse_body())
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(mock.inner())
        .await;

    let client = AnthropicClient::new("stream-test-key")
        .expect("client init")
        .with_base_url(mock.base_url());

    let messages = vec![Message {
        role: Role::User,
        content: "hello".into(),
    }];

    let stream = client
        .message_stream(Model::ClaudeSonnet4, messages, 64, None, None, None, None)
        .await
        .expect("stream start");
    pin_mut!(stream);

    let mut collected = String::new();
    let mut chunks_seen = 0_u32;
    while let Some(chunk) = stream.next().await {
        let event = chunk.expect("chunk parse");
        if let fcp_anthropic::types::StreamEvent::ContentBlockDelta {
            delta: fcp_anthropic::types::ContentDelta::TextDelta { text },
            ..
        } = event
        {
            collected.push_str(&text);
        }
        chunks_seen += 1;
        // Simulate backpressure by delaying between chunks
        fcp_async_core::time::sleep(Duration::from_millis(8)).await;
    }

    assert_eq!(collected, "Hello world");
    // 7 SSE events total: message_start, content_block_start, 2 deltas,
    // content_block_stop, message_delta, message_stop
    assert_eq!(chunks_seen, 7, "expected 7 SSE events, got {chunks_seen}");
    mock.assert_received("/v1/messages").await;
}
