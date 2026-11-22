#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener as StdTcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_openrouter::OpenRouterConnector;
use fcp_prelude::{
    AgentHint, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const OP_MODELS_LIST: &str = "openrouter.models.list";
const CAP_MODELS: &str = "openrouter.models";
const OP_VIDEO_GENERATE: &str = "openrouter.videos.generate";

#[derive(Clone, Debug)]
struct LoopbackRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl LoopbackRequest {
    fn authorization(&self) -> Option<&str> {
        self.headers.get("authorization").map(String::as_str)
    }

    fn json_body(&self) -> Value {
        serde_json::from_slice(&self.body).expect("loopback request body should be valid JSON")
    }
}

#[derive(Clone, Debug)]
struct LoopbackResponse {
    status: u16,
    reason: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
}

impl LoopbackResponse {
    fn json(status: u16, body: &Value) -> Self {
        Self {
            status,
            reason: status_reason(status),
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_string().into_bytes(),
            delay: Duration::ZERO,
        }
    }

    fn raw_json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            reason: status_reason(status),
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            delay: Duration::ZERO,
        }
    }

    fn bytes(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason: status_reason(status),
            headers: vec![("content-type".into(), content_type.into())],
            body,
            delay: Duration::ZERO,
        }
    }

    fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    const fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

struct ScriptedLoopbackServer {
    base_url: String,
    requests: Arc<Mutex<Vec<LoopbackRequest>>>,
    logs: Arc<Mutex<Vec<Value>>>,
    join: Option<thread::JoinHandle<()>>,
}

impl ScriptedLoopbackServer {
    fn spawn(name: &'static str, responses: Vec<LoopbackResponse>) -> Self {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind loopback server");
        let addr = listener.local_addr().expect("loopback server addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let logs = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let logs_for_thread = Arc::clone(&logs);

        let join = thread::spawn(move || {
            for (idx, response) in responses.into_iter().enumerate() {
                let (mut stream, _) = listener.accept().expect("accept loopback connection");
                let request = read_loopback_request(&mut stream);
                logs_for_thread
                    .lock()
                    .expect("lock loopback logs")
                    .push(json!({
                        "event": "openrouter-video-loopback",
                        "server": name,
                        "sequence": idx,
                        "method": &request.method,
                        "path": &request.path,
                        "authorization_present": request.authorization().is_some(),
                        "request_body_len": request.body.len(),
                        "response_status": response.status,
                        "response_body_len": response.body.len(),
                    }));
                requests_for_thread
                    .lock()
                    .expect("lock loopback requests")
                    .push(request);
                if !response.delay.is_zero() {
                    thread::sleep(response.delay);
                }
                let _ = write_loopback_response(&mut stream, response);
            }
        });

        Self {
            base_url: format!("http://{addr}"),
            requests,
            logs,
            join: Some(join),
        }
    }

    fn uri(&self) -> &str {
        &self.base_url
    }

    fn finish(mut self) -> (Vec<LoopbackRequest>, Vec<Value>) {
        if let Some(join) = self.join.take() {
            join.join().expect("loopback server thread should exit");
        }
        let requests = self
            .requests
            .lock()
            .expect("lock loopback requests")
            .clone();
        let logs = self.logs.lock().expect("lock loopback logs").clone();
        (requests, logs)
    }
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        401 => "Unauthorized",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn read_loopback_request(stream: &mut TcpStream) -> LoopbackRequest {
    let mut buffer = Vec::new();
    let mut scratch = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut scratch).expect("read loopback request");
        assert!(read > 0, "unexpected EOF before HTTP headers");
        buffer.extend_from_slice(&scratch[..read]);
        if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };

    let header_text = std::str::from_utf8(&buffer[..header_end]).expect("HTTP headers are UTF-8");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().expect("method").to_string();
    let path = request_parts.next().expect("path").to_string();

    let mut headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').expect("header separator");
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut scratch).expect("read loopback body");
        assert!(read > 0, "unexpected EOF before HTTP body");
        body.extend_from_slice(&scratch[..read]);
    }
    body.truncate(content_length);

    LoopbackRequest {
        method,
        path,
        headers,
        body,
    }
}

fn write_loopback_response(
    stream: &mut TcpStream,
    response: LoopbackResponse,
) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        response.reason,
        response.body.len()
    );
    for (name, value) in response.headers {
        head.push_str(&name);
        head.push_str(": ");
        head.push_str(&value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

struct OpenRouterSuiteAdapter {
    connector: OpenRouterConnector,
    id: ConnectorId,
}

impl OpenRouterSuiteAdapter {
    fn new() -> Self {
        Self {
            connector: OpenRouterConnector::new(),
            id: ConnectorId::from_static("fcp.openrouter"),
        }
    }
}

fcp_core::impl_fcp_sealed!(OpenRouterSuiteAdapter);

#[fcp_core::async_trait]
impl FcpConnector for OpenRouterSuiteAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let request = serde_json::to_value(req).map_err(|error| FcpError::Internal {
            message: format!("Failed to encode handshake: {error}"),
        })?;
        let response = self.connector.handle_handshake(request).await?;
        serde_json::from_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to decode handshake: {error}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => serde_json::from_value(payload).unwrap_or_else(|error| {
                HealthSnapshot::error(format!("Invalid OpenRouter health snapshot: {error}"))
            }),
            Err(error) => HealthSnapshot::error(error.to_string()),
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
                id: OperationId::from_static(OP_MODELS_LIST),
                summary: "List OpenRouter models".into(),
                description: None,
                input_schema: json!({ "type": "object", "properties": {} }),
                output_schema: json!({ "type": "object" }),
                capability: CapabilityId::from_static(CAP_MODELS),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Use to discover OpenRouter model identifiers.".into(),
                    common_mistakes: Vec::new(),
                    examples: vec!["{}".into()],
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
        let request_id = req.id.clone();
        let request = serde_json::to_value(req).map_err(|error| FcpError::Internal {
            message: format!("Failed to encode invocation: {error}"),
        })?;
        let value = self.connector.handle_invoke(request).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|error| FcpError::Internal {
            message: format!("Failed to encode simulation: {error}"),
        })?;
        let response = self.connector.handle_simulate(request).await?;
        serde_json::from_value(response).map_err(|error| FcpError::Internal {
            message: format!("Failed to decode simulation: {error}"),
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [37u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_MODELS)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn signed_token(
    key: &Ed25519SigningKey,
    instance: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
    let now = Utc::now();
    CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(capability)
            .operations(&[operation])
            .zone_id("z:work")
            .principal("user:connector-suite")
            .issuer("node:connector-suite")
            .target_instance(instance.as_str())
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .sign(key)
            .unwrap(),
    )
}

fn models_invoke(id: &'static str, token: CapabilityToken) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static("fcp.openrouter"),
        operation: OperationId::from_static(OP_MODELS_LIST),
        zone_id: ZoneId::work(),
        input: json!({}),
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

fn suite(server: &MockServer, test_name: &'static str, key: &Ed25519SigningKey) -> ConnectorSuite {
    ConnectorSuite {
        test_name: test_name.into(),
        config: json!({
            "api_key": "openrouter_test_key",
            "base_url": server.uri()
        }),
        handshake: handshake_request(key.verifying_key().to_bytes()),
        // The host signs for the identity learned from this handshake.
        invoke: None,
        invoke_expectations: InvokeExpectations::default(),
    }
}

#[fcp_async_core::runtime::test]
async fn connector_suite_models_happy_path_uses_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("Authorization", "Bearer openrouter_test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"id": "openai/gpt-4.1-mini", "name": "GPT 4.1 Mini"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = OpenRouterSuiteAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let mut runner = E2eRunner::new("fcp-openrouter");
    let report = runner
        .run_connector_suite(
            &mut connector,
            suite(
                &server,
                "openrouter_models_connector_suite_happy_path",
                &signing_key,
            ),
        )
        .await
        .expect("connector suite run");

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
    assert!(connector.health().await.is_ready());
    let token = signed_token(
        &signing_key,
        connector.connector.instance_id(),
        CAP_MODELS,
        OP_MODELS_LIST,
    );
    let response = connector
        .invoke(models_invoke("models-happy-path", token))
        .await
        .expect("authorized model listing should reach the provider");
    assert_eq!(response.status, fcp_core::InvokeStatus::Ok);
    assert_eq!(
        response.result.unwrap()["data"][0]["id"],
        "openai/gpt-4.1-mini"
    );
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn connector_suite_models_error_path_is_expected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("Authorization", "Bearer openrouter_test_key"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({
                    "error": { "message": "rate limited" }
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = OpenRouterSuiteAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let mut runner = E2eRunner::new("fcp-openrouter");
    let report = runner
        .run_connector_suite(
            &mut connector,
            suite(
                &server,
                "openrouter_models_connector_suite_error_path",
                &signing_key,
            ),
        )
        .await
        .expect("connector suite run");

    assert!(report.passed, "connector lifecycle should pass");
    let token = signed_token(
        &signing_key,
        connector.connector.instance_id(),
        CAP_MODELS,
        OP_MODELS_LIST,
    );
    let error = connector
        .invoke(models_invoke("models-provider-rate-limit", token))
        .await
        .expect_err("authorized invocation should preserve provider rate limiting");
    assert!(matches!(error, FcpError::RateLimited { .. }));
    server.verify().await;
}

async fn invoke_video_generate(
    base_url: &str,
    input: Value,
    request_timeout_ms: Option<u64>,
) -> fcp_core::FcpResult<Value> {
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("openrouter_test_key"));
    config.insert("base_url".into(), json!(base_url));
    if let Some(timeout_ms) = request_timeout_ms {
        config.insert("request_timeout_ms".into(), json!(timeout_ms));
    }

    let mut connector = OpenRouterConnector::new();
    connector.handle_configure(Value::Object(config)).await?;
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![7_u8; 32],
            "capabilities_requested": ["openrouter.video"]
        }))
        .await?;
    let token = signed_token(
        &signing_key,
        connector.instance_id(),
        "openrouter.video",
        OP_VIDEO_GENERATE,
    );
    connector
        .handle_invoke(json!({
            "type": "invoke",
            "id": "video-loopback",
            "connector_id": "fcp.openrouter",
            "zone_id": "z:work",
            "operation": OP_VIDEO_GENERATE,
            "capability_token": token,
            "input": input,
        }))
        .await
}

#[fcp_async_core::runtime::test]
async fn video_generate_real_loopback_e2e_success_logs_and_strips_cross_origin_auth() {
    let cdn = ScriptedLoopbackServer::spawn(
        "unsigned-cdn",
        vec![LoopbackResponse::bytes(
            200,
            "video/mp4",
            b"loopback-mp4-bytes".to_vec(),
        )],
    );
    let status = ScriptedLoopbackServer::spawn(
        "status",
        vec![LoopbackResponse::json(
            200,
            &json!({
                "id": "job-loopback-1",
                "generation_id": "gen-loopback-1",
                "status": "completed",
                "model": "google/veo-3.1",
                "unsigned_urls": [format!("{}/video.mp4", cdn.uri())],
                "usage": {"cost": 0.42, "is_byok": false}
            }),
        )],
    );
    let api = ScriptedLoopbackServer::spawn(
        "openrouter-api",
        vec![LoopbackResponse::json(
            200,
            &json!({
                "id": "job-loopback-1",
                "polling_url": format!("{}/videos/job-loopback-1", status.uri()),
                "status": "pending"
            }),
        )],
    );

    let result = invoke_video_generate(
        api.uri(),
        json!({
            "prompt": "A chrome sphere glides across a quiet moonlit beach",
            "model": "google/veo-3.1",
            "duration_seconds": 5,
            "resolution": "720P",
            "aspect_ratio": "16:9",
            "provider_options": {
                "callback_url": "https://example.com/openrouter-video-hook",
                "seed": 42
            },
            "poll_interval_ms": 0,
            "max_poll_attempts": 3
        }),
        None,
    )
    .await
    .expect("video generation should succeed against real loopback servers");

    let (api_requests, api_logs) = api.finish();
    let (status_requests, status_logs) = status.finish();
    let (cdn_requests, cdn_logs) = cdn.finish();
    let transcript = json!({
        "api": api_logs,
        "status": status_logs,
        "cdn": cdn_logs,
    });

    assert_eq!(result["job_id"], "job-loopback-1");
    assert_eq!(result["generation_id"], "gen-loopback-1");
    assert_eq!(result["video"]["mime_type"], "video/mp4");
    assert_eq!(result["video"]["byte_len"], 18);

    assert_eq!(api_requests.len(), 1);
    assert_eq!(api_requests[0].method, "POST");
    assert_eq!(api_requests[0].path, "/videos");
    assert_eq!(
        api_requests[0].authorization(),
        Some("Bearer openrouter_test_key")
    );
    let submit_body = api_requests[0].json_body();
    assert_eq!(submit_body["duration"], 6);
    assert_eq!(submit_body["resolution"], "720p");
    assert_eq!(
        submit_body["callback_url"],
        "https://example.com/openrouter-video-hook"
    );
    assert_eq!(submit_body["seed"], 42);

    assert_eq!(status_requests.len(), 1);
    assert_eq!(status_requests[0].method, "GET");
    assert_eq!(status_requests[0].path, "/videos/job-loopback-1");
    assert!(
        status_requests[0].authorization().is_none(),
        "cross-origin polling URL must not receive OpenRouter bearer credentials"
    );

    assert_eq!(cdn_requests.len(), 1);
    assert_eq!(cdn_requests[0].method, "GET");
    assert_eq!(cdn_requests[0].path, "/video.mp4");
    assert!(
        cdn_requests[0].authorization().is_none(),
        "cross-origin unsigned download URL must not receive OpenRouter bearer credentials"
    );
    assert!(
        transcript.to_string().contains("openrouter-video-loopback"),
        "machine-readable loopback transcript should include structured events"
    );
}

#[fcp_async_core::runtime::test]
async fn video_generate_real_loopback_e2e_error_modes_are_logged() {
    let auth_failure = ScriptedLoopbackServer::spawn(
        "auth-failure",
        vec![LoopbackResponse::json(
            401,
            &json!({"error": {"message": "bad key"}}),
        )],
    );
    let auth_error =
        invoke_video_generate(auth_failure.uri(), json!({"prompt": "auth failure"}), None)
            .await
            .expect_err("401 should map to an external service error");
    assert!(matches!(
        auth_error,
        FcpError::External {
            status_code: Some(401),
            retryable: false,
            ..
        }
    ));
    let (_, auth_logs) = auth_failure.finish();
    assert_eq!(auth_logs[0]["response_status"], 401);

    let rate_limited_status = ScriptedLoopbackServer::spawn(
        "rate-limit-status",
        vec![
            LoopbackResponse::json(429, &json!({"error": {"message": "slow down"}}))
                .with_header("retry-after", "1"),
        ],
    );
    let rate_limited_api = ScriptedLoopbackServer::spawn(
        "rate-limit-api",
        vec![LoopbackResponse::json(
            200,
            &json!({
                "id": "job-rate-limited",
                "polling_url": format!("{}/videos/job-rate-limited", rate_limited_status.uri()),
                "status": "pending"
            }),
        )],
    );
    let rate_error = invoke_video_generate(
        rate_limited_api.uri(),
        json!({
            "prompt": "rate limited",
            "poll_interval_ms": 0,
            "max_poll_attempts": 1
        }),
        None,
    )
    .await
    .expect_err("polling failure must not authorize another video generation");
    assert!(matches!(
        &rate_error,
        FcpError::External {
            retryable: false,
            ..
        }
    ));
    assert!(rate_error.to_string().contains("job-rate-limited"));
    assert!(
        rate_error
            .to_string()
            .to_lowercase()
            .contains("rate limited")
    );
    let _ = rate_limited_api.finish();
    let (_, rate_logs) = rate_limited_status.finish();
    assert_eq!(rate_logs[0]["response_status"], 429);

    let malformed_status = ScriptedLoopbackServer::spawn(
        "malformed-status",
        vec![LoopbackResponse::raw_json(200, "{not-json")],
    );
    let malformed_api = ScriptedLoopbackServer::spawn(
        "malformed-api",
        vec![LoopbackResponse::json(
            200,
            &json!({
                "id": "job-malformed",
                "polling_url": format!("{}/videos/job-malformed", malformed_status.uri()),
                "status": "pending"
            }),
        )],
    );
    let malformed_error = invoke_video_generate(
        malformed_api.uri(),
        json!({
            "prompt": "malformed",
            "poll_interval_ms": 0,
            "max_poll_attempts": 1
        }),
        None,
    )
    .await
    .expect_err("malformed JSON should fail closed");
    assert!(
        malformed_error
            .to_string()
            .contains("Failed to decode JSON response")
    );
    let _ = malformed_api.finish();
    let (_, malformed_logs) = malformed_status.finish();
    assert_eq!(malformed_logs[0]["response_status"], 200);

    let oversized_cdn = ScriptedLoopbackServer::spawn(
        "oversized-cdn",
        vec![LoopbackResponse::bytes(
            200,
            "video/mp4",
            b"too-many-bytes".to_vec(),
        )],
    );
    let oversized_api = ScriptedLoopbackServer::spawn(
        "oversized-api",
        vec![LoopbackResponse::json(
            200,
            &json!({
                "id": "job-oversized",
                "status": "completed",
                "unsigned_urls": [format!("{}/video.mp4", oversized_cdn.uri())]
            }),
        )],
    );
    let oversized_error = invoke_video_generate(
        oversized_api.uri(),
        json!({
            "prompt": "oversized",
            "max_download_bytes": 4
        }),
        None,
    )
    .await
    .expect_err("oversized video should fail before returning bytes");
    assert!(matches!(
        &oversized_error,
        FcpError::External {
            retryable: false,
            ..
        }
    ));
    assert!(oversized_error.to_string().contains("byte limit"));
    let _ = oversized_api.finish();
    let (_, oversized_logs) = oversized_cdn.finish();
    assert_eq!(oversized_logs[0]["response_status"], 200);

    let timeout_api = ScriptedLoopbackServer::spawn(
        "timeout-api",
        vec![
            LoopbackResponse::json(200, &json!({"id": "too-late", "status": "completed"}))
                .with_delay(Duration::from_millis(100)),
        ],
    );
    let timeout_error =
        invoke_video_generate(timeout_api.uri(), json!({"prompt": "timeout"}), Some(10))
            .await
            .expect_err("delayed loopback response should trip request timeout");
    assert!(matches!(
        &timeout_error,
        FcpError::External {
            retryable: false,
            ..
        }
    ));
    assert!(
        timeout_error
            .to_string()
            .contains("provider outcome may be unknown")
    );
    let (_, timeout_logs) = timeout_api.finish();
    assert_eq!(timeout_logs[0]["response_status"], 200);
}
