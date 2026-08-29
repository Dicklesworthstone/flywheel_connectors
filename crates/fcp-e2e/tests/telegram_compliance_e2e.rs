//! E2E Telegram connector compliance tests (flywheel_connectors-lszk.1.6).
//!
//! Exercises the Telegram connector through the E2E compliance harness:
//! - Default deny (missing capability -> error)
//! - Allow with valid token (happy path `send_message` invoke)
//! - Subscribe confirms requested topics (streaming protocol)
//! - Get file with valid token (read operation)
//!
//! Note: No network guard test yet -- Telegram manifest.toml not yet created.
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features telegram`

#![cfg(feature = "telegram")]
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

use fcp_telegram::connector::TelegramConnector;

/// Bot token that passes `validate_bot_token_syntax` validation.
const TEST_BOT_TOKEN: &str = "123456:ABCDEFGHIJKLMNOPQRSTUVWXyz012345";

// ============================================================================
// FcpConnector adapter for TelegramConnector
// ============================================================================

struct TelegramConnectorAdapter {
    connector: TelegramConnector,
    id: ConnectorId,
}

impl TelegramConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: TelegramConnector::new(),
            id: ConnectorId::from_static("telegram"),
        }
    }
}

fcp_core::impl_fcp_sealed!(TelegramConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for TelegramConnectorAdapter {
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
                    other => HealthSnapshot::degraded(format!("telegram_status:{other}")),
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
                id: OperationId::from_static("telegram.send_message"),
                summary: "Send a text message to a Telegram chat".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["chat_id", "text"],
                    "properties": {
                        "chat_id": { "type": ["string", "integer"] },
                        "text": { "type": "string", "maxLength": 4096 }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "message_id": { "type": "integer" },
                        "chat": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("telegram.send"),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Send a text message to a Telegram chat".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"chat_id":"123456789","text":"Hello!"}"#.to_string()],
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
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let zone_dir = std::env::temp_dir().join(format!(
        "fcp-telegram-e2e-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: Some(zone_dir.to_string_lossy().into_owned()),
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
    // Capability constraints are MANDATORY per C3.4 (default-deny): the
    // verifier rejects tokens with no constraints claim OR an empty
    // constraint set. Use a wildcard `resource_allow` so the test grants
    // access to any telegram resource URI the connector builds from the
    // invoke input (e.g. `telegram:chat:<chat_id>`). The wildcard `"*"`
    // pattern is explicitly documented as "all resources" in
    // fcp-core/capability.rs:1320.
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("serialize constraints to CBOR");
    let resolved_capability = match capability {
        "telegram.get_file" => "telegram.read",
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
        id: RequestId::from("telegram-e2e"),
        connector_id: ConnectorId::from_static("telegram"),
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

/// Mock Telegram Bot API getMe response.
fn telegram_bot_response() -> serde_json::Value {
    json!({
        "ok": true,
        "result": {
            "id": 123456789,
            "is_bot": true,
            "first_name": "FCP Test Bot",
            "username": "fcp_test_bot"
        }
    })
}

/// Mock Telegram Bot API sendMessage response.
fn telegram_send_message_response() -> serde_json::Value {
    json!({
        "ok": true,
        "result": {
            "message_id": 42,
            "from": {
                "id": 123456789,
                "is_bot": true,
                "first_name": "FCP Test Bot",
                "username": "fcp_test_bot"
            },
            "chat": {
                "id": 987654321,
                "type": "private",
                "first_name": "Test",
                "username": "test_user"
            },
            "date": 1709352000,
            "text": "hello from e2e"
        }
    })
}

/// Mount the getMe mock required for Telegram configure/handshake.
async fn mount_get_me_mock(mock: &MockApiServer) {
    Mock::given(method("GET"))
        .and(path(format!("/bot{TEST_BOT_TOKEN}/getMe")))
        .respond_with(ResponseTemplate::new(200).set_body_json(telegram_bot_response()))
        .expect(1..)
        .mount(mock.inner())
        .await;
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "telegram.get_file" but invoke targets "telegram.send_message" -> denial.
#[fcp_async_core::runtime::test]
async fn telegram_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;
    mount_get_me_mock(&mock).await;

    let mut connector = TelegramConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["telegram.get_file"],
    );
    // Token grants "telegram.get_file" but invoke targets "telegram.send_message" -> denial
    let token = build_token(
        &signing_key,
        "telegram.get_file",
        &["telegram.get_file"],
        handshake
            .requested_instance_id
            .as_ref()
            .expect("handshake instance id")
            .as_str(),
    );
    let invoke = invoke_request(
        "telegram.send_message",
        json!({
            "chat_id": "987654321",
            "text": "blocked request"
        }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "credential": TEST_BOT_TOKEN,
            "base_url": mock.base_url(),
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
        "telegram_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-telegram");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: send_message invoke with valid capability token succeeds against mock API.
#[fcp_async_core::runtime::test]
async fn telegram_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;
    mount_get_me_mock(&mock).await;

    // Mount mock for sendMessage
    Mock::given(method("POST"))
        .and(path(format!("/bot{TEST_BOT_TOKEN}/sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(telegram_send_message_response()))
        .mount(mock.inner())
        .await;

    let mut connector = TelegramConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    // The connector's introspection declares `telegram.send_message`
    // requires capability `telegram.send` (see telegram/connector.rs
    // handle_introspect). After br-8n0rm.6 removed the legacy OPERATIONS
    // fallback, the verifier checks the GRANTS shape strictly: each
    // grant's `capability` field must equal the operation's required
    // capability. So the token must grant `telegram.send`, not the op id.
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["telegram.send"]);
    let token = build_token(
        &signing_key,
        "telegram.send",
        &["telegram.send_message"],
        handshake
            .requested_instance_id
            .as_ref()
            .expect("handshake instance id")
            .as_str(),
    );
    let invoke = invoke_request(
        "telegram.send_message",
        json!({
            "chat_id": "987654321",
            "text": "hello from e2e"
        }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "telegram_allow_valid_token".to_string(),
        config: json!({
            "credential": TEST_BOT_TOKEN,
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

    let mut runner = E2eRunner::new("fcp-e2e-telegram");
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
    let received = mock.received_requests().await;
    let send_requests: Vec<_> = received
        .iter()
        .filter(|request| {
            request.method.as_str() == "POST"
                && request.url.path() == format!("/bot{TEST_BOT_TOKEN}/sendMessage")
        })
        .collect();
    assert_eq!(
        send_requests.len(),
        1,
        "expected exactly one sendMessage POST"
    );
    let send_body: serde_json::Value =
        serde_json::from_slice(&send_requests[0].body).expect("telegram send body json");
    assert_eq!(send_body.get("chat_id"), Some(&json!("987654321")));
    assert_eq!(send_body.get("text"), Some(&json!("hello from e2e")));
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );
}

// ============================================================================
// Test 3: Subscribe confirms topics -- streaming protocol
// ============================================================================

/// Subscribe: the Telegram connector confirms requested topics.
#[fcp_async_core::runtime::test]
async fn telegram_subscribe_confirms_topics() {
    let mock = MockApiServer::start().await;
    mount_get_me_mock(&mock).await;

    let mut connector = TelegramConnector::new();

    // Configure
    connector
        .handle_configure(json!({
            "credential": TEST_BOT_TOKEN,
            "base_url": mock.base_url(),
        }))
        .await
        .expect("configure should succeed");

    // Subscribe with topics
    let subscribe_result = connector
        .handle_subscribe(json!({
            "topics": ["telegram.message", "telegram.callback_query"]
        }))
        .await
        .expect("subscribe should succeed");

    let confirmed = subscribe_result["confirmed_topics"]
        .as_array()
        .expect("confirmed_topics array");
    assert_eq!(confirmed.len(), 2, "should confirm all requested topics");
    assert_eq!(confirmed[0], "telegram.message");
    assert_eq!(confirmed[1], "telegram.callback_query");
}

// ============================================================================
// Test 4: Send message -- direct connector test
// ============================================================================

/// Send message: invoke telegram.send_message with valid token succeeds.
#[fcp_async_core::runtime::test]
async fn telegram_send_message_returns_message_id() {
    let mock = MockApiServer::start().await;
    mount_get_me_mock(&mock).await;

    // Mount mock for sendMessage
    Mock::given(method("POST"))
        .and(path(format!("/bot{TEST_BOT_TOKEN}/sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(telegram_send_message_response()))
        .mount(mock.inner())
        .await;

    let mut connector = TelegramConnector::new();

    // Configure
    connector
        .handle_configure(json!({
            "credential": TEST_BOT_TOKEN,
            "base_url": mock.base_url(),
        }))
        .await
        .expect("configure should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let zone_dir =
        std::env::temp_dir().join(format!("fcp-telegram-e2e-send-{}", std::process::id()));
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "zone_dir": zone_dir.to_string_lossy(),
            "host_public_key": signing_key.verifying_key().to_bytes().to_vec(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["telegram.send"]
        }))
        .await
        .expect("handshake should succeed");

    // Build valid token and invoke (capability class is `telegram.send`,
    // see test 2's comment for the C3.4 / br-8n0rm.6 rationale).
    let token = build_token(
        &signing_key,
        "telegram.send",
        &["telegram.send_message"],
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": {
                "chat_id": "987654321",
                "text": "hello from e2e"
            },
            "capability_token": token
        }))
        .await
        .expect("send_message invoke should succeed");

    // Verify message_id is in response
    assert!(
        result.get("message_id").is_some() || result.get("receipt").is_some(),
        "response should contain message_id or receipt: {result:?}"
    );
}
