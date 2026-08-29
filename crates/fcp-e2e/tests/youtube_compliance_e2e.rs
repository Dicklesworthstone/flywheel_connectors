//! E2E `YouTube` connector compliance tests.
//!
//! Exercises the `YouTube` connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` exact-host validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features youtube`

#![cfg(feature = "youtube")]
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

use fcp_youtube::connector::YouTubeConnector;

// ============================================================================
// FcpConnector adapter for YouTubeConnector
// ============================================================================

struct YouTubeConnectorAdapter {
    connector: YouTubeConnector,
    id: ConnectorId,
}

impl YouTubeConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: YouTubeConnector::new(),
            id: ConnectorId::from_static("youtube"),
        }
    }
}

fcp_core::impl_fcp_sealed!(YouTubeConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for YouTubeConnectorAdapter {
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
                    other => HealthSnapshot::degraded(format!("youtube_status:{other}")),
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
                id: OperationId::from_static("youtube.get_video"),
                summary: "Get video details by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["video_id"],
                    "properties": {
                        "video_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "video": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("youtube.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Get details about a specific video.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"video_id": "dQw4w9WgXcQ"}"#.to_string()],
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
    // C3.4 default-deny: constraints claim is mandatory. (br-1maun)
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
        id: RequestId::from("youtube-e2e"),
        connector_id: ConnectorId::from_static("youtube"),
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

fn youtube_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/youtube/manifest.toml"))
        .expect("youtube manifest toml")
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

/// YouTube `get_video` API success response (videos.list format).
fn youtube_get_video_response() -> serde_json::Value {
    json!({
        "kind": "youtube#videoListResponse",
        "etag": "abc123etag",
        "pageInfo": {
            "totalResults": 1,
            "resultsPerPage": 1
        },
        "items": [{
            "kind": "youtube#video",
            "etag": "video-etag-123",
            "id": "dQw4w9WgXcQ",
            "snippet": {
                "publishedAt": "2009-10-25T06:57:33Z",
                "channelId": "UCuAXFkgsw1L7xaCfnd5JJOw",
                "title": "Rick Astley - Never Gonna Give You Up (Official Music Video)",
                "description": "The official video for Rick Astley",
                "thumbnails": {},
                "channelTitle": "Rick Astley",
                "tags": ["rick astley", "never gonna give you up"],
                "categoryId": "10",
                "liveBroadcastContent": "none"
            },
            "contentDetails": {
                "duration": "PT3M33S",
                "dimension": "2d",
                "definition": "hd",
                "caption": "true",
                "licensedContent": true,
                "projection": "rectangular"
            },
            "statistics": {
                "viewCount": "1500000000",
                "likeCount": "16000000",
                "favoriteCount": "0",
                "commentCount": "3000000"
            }
        }]
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "youtube.write" but invoke targets "youtube.get_video"
/// (which requires "youtube.read").
#[fcp_async_core::runtime::test]
async fn youtube_default_deny_compliance_suite_passes() {
    let mut connector = YouTubeConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["youtube.write"]);
    // Token grants "youtube.write" but invoke targets "youtube.get_video" -> denial
    let token = build_token(
        &signing_key,
        "youtube.write",
        &["youtube.write"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request(
        "youtube.get_video",
        json!({ "video_id": "dQw4w9WgXcQ" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "api_key": "AIza_test_000",
            "base_url": "http://localhost:9999/youtube/v3"
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
        "youtube_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-youtube");
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
async fn youtube_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /videos?... endpoint
    // The YouTube client builds: {base_url}/videos?part=...&id=...&key=...
    Mock::given(method("GET"))
        .and(path_regex(r"^/videos.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(youtube_get_video_response()))
        .mount(mock.inner())
        .await;

    let mut connector = YouTubeConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    // Introspection declares `youtube.get_video` requires capability
    // `youtube.read` (permission class), not the op id itself.
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["youtube.read"]);
    let token = build_token(
        &signing_key,
        "youtube.read",
        &["youtube.get_video"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request(
        "youtube.get_video",
        json!({ "video_id": "dQw4w9WgXcQ" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "youtube_allow_valid_token".to_string(),
        config: json!({
            "api_key": "AIza_test_e2e",
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

    let mut runner = E2eRunner::new("fcp-e2e-youtube");
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

    // br-7e15h: independently verify the connector hit the /videos
    // endpoint. Filter on path prefix since the client appends a
    // query string (part, id, key) that varies per request.
    let received = mock.received_requests().await;
    let videos_hits = received
        .iter()
        .filter(|r| r.method == wiremock::http::Method::GET && r.url.path().starts_with("/videos"))
        .count();
    assert_eq!(
        videos_hits,
        1,
        "expected exactly one GET to /videos*; got {videos_hits} \
         (received: {:?})",
        received
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow exact-host validation
// ============================================================================

/// Network guard: YouTube manifest restricts all operations to `www.googleapis.com`.
/// Verify that the allowed host passes and non-matching hosts are denied.
#[test]
fn youtube_manifest_network_guard_allows_and_denies() {
    let manifest = youtube_manifest_toml();

    let operations = [
        "youtube.search",
        "youtube.get_video",
        "youtube.list_videos",
        "youtube.get_channel",
        "youtube.list_playlists",
        "youtube.list_playlist_items",
        "youtube.list_comments",
        "youtube.post_comment",
        "youtube.get_captions",
        "youtube.get_caption_transcript",
        "youtube.upload_caption",
    ];

    let expected_hosts = vec!["www.googleapis.com".to_string()];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow only www.googleapis.com"
        );

        // Allowed host
        assert!(
            host_allowed("www.googleapis.com", &host_allow),
            "www.googleapis.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("googleapis.com", &host_allow),
            "googleapis.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.www.googleapis.com", &host_allow),
            "evil.www.googleapis.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("youtube.googleapis.com", &host_allow),
            "youtube.googleapis.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.youtube.com", &host_allow),
            "api.youtube.com should be denied for {operation_name}"
        );
    }
}
