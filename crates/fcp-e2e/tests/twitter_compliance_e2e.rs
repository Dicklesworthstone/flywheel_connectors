//! E2E Twitter/X connector compliance tests.
//!
//! Exercises the Twitter connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` exact-host validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features twitter`

#![cfg(feature = "twitter")]
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
    matchers::{method, path_regex},
};

use fcp_twitter::TwitterConnector;

// ============================================================================
// FcpConnector adapter for TwitterConnector
// ============================================================================

struct TwitterConnectorAdapter {
    connector: TwitterConnector,
    id: ConnectorId,
}

impl TwitterConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: TwitterConnector::new(),
            id: ConnectorId::from_static("twitter"),
        }
    }
}

fcp_core::impl_fcp_sealed!(TwitterConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for TwitterConnectorAdapter {
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
                    "not_configured" | "not_ready" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("twitter_status:{other}")),
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
                id: OperationId::from_static("twitter.tweet.get"),
                summary: "Get a tweet by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["tweet_id"],
                    "properties": {
                        "tweet_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "tweet": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("twitter.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Get a specific tweet by its ID.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"tweet_id": "1234567890"}"#.to_string()],
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
        // Twitter connector reads "args" not "input"
        let params = json!({
            "operation": req.operation.as_str(),
            "args": req.input,
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
        // twitter.tweet.get's introspected capability is twitter.read.public.
        "twitter.tweet.get" => "twitter.read.public",
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
        id: RequestId::from("twitter-e2e"),
        connector_id: ConnectorId::from_static("twitter"),
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

fn twitter_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/twitter/manifest.toml"))
        .expect("twitter manifest toml")
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

fn twitter_config(api_url: &str) -> serde_json::Value {
    json!({
        "consumer_key": "ck_test_e2e",
        "consumer_secret": "cs_test_e2e",
        "access_token": "at_test_e2e",
        "access_token_secret": "ats_test_e2e",
        "api_url": api_url,
    })
}

/// Twitter user.me API response (used during handshake).
fn twitter_user_me_response() -> serde_json::Value {
    json!({
        "data": {
            "id": "12345678",
            "name": "Test User",
            "username": "testuser",
            "description": "E2E test account",
            "profile_image_url": "https://pbs.twimg.com/profile_images/test.jpg",
            "verified": false,
            "created_at": "2020-01-15T10:00:00.000Z",
            "public_metrics": {
                "followers_count": 100,
                "following_count": 50,
                "tweet_count": 1000,
                "listed_count": 5
            }
        }
    })
}

/// Twitter tweet.get API response.
fn twitter_get_tweet_response() -> serde_json::Value {
    json!({
        "data": {
            "id": "1234567890123456789",
            "text": "Hello from the E2E test!",
            "author_id": "12345678",
            "created_at": "2026-02-28T12:00:00.000Z",
            "public_metrics": {
                "retweet_count": 5,
                "reply_count": 2,
                "like_count": 42,
                "quote_count": 1,
                "bookmark_count": 3,
                "impression_count": 1000
            },
            "conversation_id": "1234567890123456789"
        },
        "includes": {
            "users": [{
                "id": "12345678",
                "name": "Test User",
                "username": "testuser",
                "profile_image_url": "https://pbs.twimg.com/profile_images/test.jpg"
            }]
        }
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "twitter.write" but invoke targets "twitter.tweet.get"
/// (which requires "twitter.read").
#[fcp_async_core::runtime::test]
async fn twitter_default_deny_compliance_suite_passes() {
    // Twitter handshake calls get_me(), so we need a mock server even for deny
    let mock = MockApiServer::start().await;

    // Mount mock for handshake's get_me call
    Mock::given(method("GET"))
        .and(path_regex(r"^/2/users/me.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(twitter_user_me_response()))
        .mount(mock.inner())
        .await;

    let mut connector = TwitterConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["twitter.write"]);
    // Token grants "twitter.write" but invoke targets "twitter.tweet.get" -> denial
    let token = build_token(
        &signing_key,
        "twitter.write",
        &["twitter.write"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request(
        "twitter.tweet.get",
        json!({ "tweet_id": "1234567890123456789" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: twitter_config(&mock.base_url()),
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
        "twitter_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-twitter");
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
async fn twitter_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for handshake's get_me call
    Mock::given(method("GET"))
        .and(path_regex(r"^/2/users/me.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(twitter_user_me_response()))
        .mount(mock.inner())
        .await;

    // Mount mock for tweet.get: GET /2/tweets/{id}
    Mock::given(method("GET"))
        .and(path_regex(r"^/2/tweets/\d+.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(twitter_get_tweet_response()))
        .mount(mock.inner())
        .await;

    let mut connector = TwitterConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["twitter.tweet.get"],
    );
    let token = build_token(
        &signing_key,
        "twitter.tweet.get",
        &["twitter.tweet.get"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request(
        "twitter.tweet.get",
        json!({ "tweet_id": "1234567890123456789" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "twitter_allow_valid_token".to_string(),
        config: twitter_config(&mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-twitter");
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
    let users_me_hits = received
        .iter()
        .filter(|r| r.url.path() == "/2/users/me")
        .count();
    assert_eq!(users_me_hits, 1, "expected exactly one GET to /2/users/me");
    let tweet_hits = received
        .iter()
        .filter(|r| r.url.path() == "/2/tweets/1234567890123456789")
        .count();
    assert_eq!(
        tweet_hits, 1,
        "expected exactly one GET to /2/tweets/1234567890123456789"
    );
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow exact-host validation
// ============================================================================

/// Network guard: Twitter manifest restricts operations to
/// `api.twitter.com`, `api.x.com`, and `stream.twitter.com`.
/// Verify that allowed hosts pass and non-matching hosts are denied.
#[test]
fn twitter_manifest_network_guard_allows_and_denies() {
    let manifest = twitter_manifest_toml();

    let operations = [
        "twitter.user.me",
        "twitter.user.get",
        "twitter.user.by_username",
        "twitter.tweet.get",
        "twitter.tweet.search",
        "twitter.user.timeline",
        "twitter.user.mentions",
        "twitter.tweet.create",
        "twitter.tweet.reply",
        "twitter.tweet.delete",
        "twitter.stream.rules.list",
        "twitter.stream.rules.add",
        "twitter.stream.rules.delete",
    ];

    let expected_hosts = vec![
        "api.twitter.com".to_string(),
        "api.x.com".to_string(),
        "stream.twitter.com".to_string(),
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow api.twitter.com, api.x.com, stream.twitter.com"
        );

        // Allowed hosts
        assert!(
            host_allowed("api.twitter.com", &host_allow),
            "api.twitter.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("api.x.com", &host_allow),
            "api.x.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("stream.twitter.com", &host_allow),
            "stream.twitter.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("twitter.com", &host_allow),
            "twitter.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.api.twitter.com", &host_allow),
            "evil.api.twitter.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("upload.twitter.com", &host_allow),
            "upload.twitter.com should be denied for {operation_name}"
        );
    }
}
