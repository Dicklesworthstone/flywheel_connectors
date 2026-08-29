//! E2E Discord connector compliance tests (flywheel_connectors-lszk.2.6).
//!
//! Exercises the Discord connector through the E2E compliance harness:
//! - Default deny (missing capability -> error)
//! - Allow with valid token (happy path `send_message` invoke)
//! - Network guard allow/deny (manifest `host_allow` validation)
//! - Gateway streaming subscribe protocol (topic confirmation)
//! - Rate limit behavior (429 response handling)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features discord`

#![cfg(feature = "discord")]
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

use fcp_discord::DiscordConnector;

// ============================================================================
// FcpConnector adapter for DiscordConnector
// ============================================================================

struct DiscordConnectorAdapter {
    connector: DiscordConnector,
    id: ConnectorId,
}

impl DiscordConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: DiscordConnector::new(),
            id: ConnectorId::from_static("discord"),
        }
    }

    fn instance_id(&self) -> &str {
        self.connector.instance_id().as_str()
    }
}

fcp_core::impl_fcp_sealed!(DiscordConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for DiscordConnectorAdapter {
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
                    other => HealthSnapshot::degraded(format!("discord_status:{other}")),
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
                id: OperationId::from_static("discord.send_message"),
                summary: "Send a message to a Discord channel".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["channel_id"],
                    "properties": {
                        "channel_id": { "type": "string" },
                        "content": { "type": "string", "maxLength": 2000 }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["id", "channel_id"],
                    "properties": {
                        "id": { "type": "string" },
                        "channel_id": { "type": "string" },
                        "content": { "type": "string" }
                    }
                }),
                capability: CapabilityId::from_static("discord.send"),
                risk_level: RiskLevel::Medium,
                safety_tier: SafetyTier::Risky,
                idempotency: IdempotencyClass::None,
                ai_hints: AgentHint {
                    when_to_use: "Send a message to a Discord channel".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"channel_id":"123456789","content":"Hello!"}"#.to_string()],
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
        "fcp-discord-e2e-{}-{}",
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
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("serialize constraints to CBOR");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
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

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("discord-e2e"),
        connector_id: ConnectorId::from_static("discord"),
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

fn discord_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/discord/manifest.toml"))
        .expect("discord manifest toml")
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

/// Mock Discord bot user response for /users/@me.
fn discord_bot_user_response() -> serde_json::Value {
    json!({
        "id": "111222333444555666",
        "username": "FcpTestBot",
        "discriminator": "0000",
        "avatar": null,
        "bot": true,
        "flags": 0,
        "public_flags": 0
    })
}

/// Mock Discord message response for send_message.
fn discord_message_response() -> serde_json::Value {
    json!({
        "id": "999888777666555444",
        "channel_id": "123456789012345678",
        "content": "hello from e2e",
        "author": {
            "id": "111222333444555666",
            "username": "FcpTestBot",
            "discriminator": "0000",
            "bot": true
        },
        "timestamp": "2026-03-02T07:00:00.000000+00:00",
        "type": 0
    })
}

/// Mount the /users/@me mock required for Discord configure step.
async fn mount_bot_user_mock(mock: &MockApiServer) {
    Mock::given(method("GET"))
        .and(path("/api/v10/users/@me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discord_bot_user_response()))
        .mount(mock.inner())
        .await;
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "discord.read" but invoke targets "discord.send_message" -> denial.
#[fcp_async_core::runtime::test]
async fn discord_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;
    mount_bot_user_mock(&mock).await;

    let mut connector = DiscordConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["discord.read"]);
    // Token grants "discord.read" but invoke targets "discord.send_message" -> denial
    let token = build_token(
        &signing_key,
        "discord.read",
        &["discord.read"],
        connector.instance_id(),
    );
    let invoke = invoke_request(
        "discord.send_message",
        json!({
            "channel_id": "123456789012345678",
            "content": "blocked request"
        }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "bot_credential": "test-bot-token",
            "api_url": format!("{}/api/v10", mock.base_url()),
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
        "discord_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-discord");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock API.
#[fcp_async_core::runtime::test]
async fn discord_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;
    mount_bot_user_mock(&mock).await;

    // Mount mock for send_message
    Mock::given(method("POST"))
        .and(path("/api/v10/channels/123456789012345678/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discord_message_response()))
        .mount(mock.inner())
        .await;

    let mut connector = DiscordConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["discord.send"]);
    let token = build_token(
        &signing_key,
        "discord.send",
        &["discord.send_message"],
        connector.instance_id(),
    );
    let invoke = invoke_request(
        "discord.send_message",
        json!({
            "channel_id": "123456789012345678",
            "content": "hello from e2e"
        }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "discord_allow_valid_token".to_string(),
        config: json!({
            "bot_credential": "test-bot-token",
            "api_url": format!("{}/api/v10", mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-discord");
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
                && request.url.path() == "/api/v10/channels/123456789012345678/messages"
        })
        .collect();
    assert_eq!(
        send_requests.len(),
        1,
        "expected exactly one Discord send_message POST"
    );
    let send_body: serde_json::Value =
        serde_json::from_slice(&send_requests[0].body).expect("discord send body json");
    assert_eq!(send_body.get("content"), Some(&json!("hello from e2e")));
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Discord manifest restricts operations to discord.com
/// and *.discord.com, and denies all other hosts.
#[test]
fn discord_manifest_network_guard_allows_and_denies() {
    let manifest = discord_manifest_toml();

    // Manifest operation names (without discord. prefix)
    let operations = [
        "send_message",
        "edit_message",
        "delete_message",
        "get_channel",
        "get_guild",
        "trigger_typing",
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow,
            vec!["discord.com".to_string(), "*.discord.com".to_string()],
            "operation {operation_name} should allow discord.com + *.discord.com"
        );

        // Exact match
        assert!(
            host_allowed("discord.com", &host_allow),
            "discord.com should be allowed for {operation_name}"
        );
        // Wildcard subdomain match
        assert!(
            host_allowed("cdn.discord.com", &host_allow),
            "cdn.discord.com should be allowed for {operation_name}"
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
        // Subdomain spoofing denied (exact match doesn't allow prefix)
        assert!(
            !host_allowed("evil-discord.com", &host_allow),
            "evil-discord.com should be denied for {operation_name}"
        );
    }

    // Also verify the gateway streaming constraints
    let gateway_host_allow = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|p| p.get("streaming"))
        .and_then(toml::Value::as_table)
        .and_then(|s| s.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .and_then(|c| c.get("host_allow"))
        .and_then(toml::Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .expect("gateway host_allow");

    assert!(host_allowed("gateway.discord.gg", &gateway_host_allow));
    assert!(!host_allowed("evil.example.com", &gateway_host_allow));
}

// ============================================================================
// Test 4: Gateway streaming subscribe protocol
// ============================================================================

/// Gateway streaming: the subscribe handler confirms requested topics.
/// Validates the subscribe/unsubscribe protocol contract.
#[fcp_async_core::runtime::test]
async fn discord_subscribe_confirms_topics() {
    let connector = DiscordConnector::new();

    // Subscribe with specific topics
    let subscribe_result = connector
        .handle_subscribe(json!({
            "topics": ["discord.message", "discord.typing", "discord.guild_create"]
        }))
        .await
        .expect("subscribe should succeed");

    let confirmed = subscribe_result["confirmed_topics"]
        .as_array()
        .expect("confirmed_topics array");
    assert_eq!(confirmed.len(), 3, "should confirm all 3 requested topics");
    assert_eq!(confirmed[0], "discord.message");
    assert_eq!(confirmed[1], "discord.typing");
    assert_eq!(confirmed[2], "discord.guild_create");
    assert_eq!(subscribe_result["replay_supported"], false);

    // Handshake should advertise streaming support (requires configure first)
    let mock = MockApiServer::start().await;
    mount_bot_user_mock(&mock).await;

    let mut handshake_connector = DiscordConnector::new();
    handshake_connector
        .handle_configure(json!({
            "bot_credential": "test-bot-token",
            "api_url": format!("{}/api/v10", mock.base_url()),
        }))
        .await
        .expect("configure for handshake");

    let signing_key = Ed25519SigningKey::generate();
    let zone_dir =
        std::env::temp_dir().join(format!("fcp-discord-e2e-subscribe-{}", std::process::id()));
    let response = handshake_connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "zone_dir": zone_dir.to_string_lossy(),
            "host_public_key": signing_key.verifying_key().to_bytes().to_vec(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["discord.send"]
        }))
        .await
        .expect("handshake should succeed");

    assert_eq!(response["status"], "accepted");
    let event_caps = response.get("event_caps").expect("event_caps in handshake");
    assert_eq!(event_caps["streaming"], true, "streaming should be enabled");
}

// ============================================================================
// Test 5: Rate limit behavior
// ============================================================================

/// Rate limit: connector surfaces 429 responses as FcpError::RateLimited.
#[fcp_async_core::runtime::test]
async fn discord_rate_limit_surfaces_correctly() {
    let mock = MockApiServer::start().await;
    mount_bot_user_mock(&mock).await;

    // Mount 429 response for send_message
    Mock::given(method("POST"))
        .and(path("/api/v10/channels/123456789012345678/messages"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({
                    "message": "You are being rate limited.",
                    "retry_after": 1.5,
                    "global": false
                }))
                .insert_header("retry-after", "2"),
        )
        .mount(mock.inner())
        .await;

    let mut connector = DiscordConnector::new();

    // Configure with mock
    connector
        .handle_configure(json!({
            "bot_credential": "test-bot-token",
            "api_url": format!("{}/api/v10", mock.base_url()),
            "retry": { "max_attempts": 1 }
        }))
        .await
        .expect("configure should succeed");

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let zone_dir =
        std::env::temp_dir().join(format!("fcp-discord-e2e-ratelimit-{}", std::process::id()));
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "zone_dir": zone_dir.to_string_lossy(),
            "host_public_key": signing_key.verifying_key().to_bytes().to_vec(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["discord.send"]
        }))
        .await
        .expect("handshake should succeed");

    // Build valid token and invoke -- should get rate limited
    let token = build_token(
        &signing_key,
        "discord.send",
        &["discord.send_message"],
        connector.instance_id().as_str(),
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "123456789012345678",
                "content": "rate limit test"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "rate-limited invoke should error");
    let err = result.unwrap_err();
    // The error should indicate rate limiting or be an external error with 429
    let is_rate_limited = matches!(err, FcpError::RateLimited { .. });
    let is_external_429 = matches!(
        &err,
        FcpError::External {
            status_code: Some(429),
            ..
        }
    );
    assert!(
        is_rate_limited || is_external_429,
        "expected RateLimited or External(429), got: {err:?}"
    );
}
