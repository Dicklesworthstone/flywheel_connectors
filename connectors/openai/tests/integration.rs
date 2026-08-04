//! `OpenAI` connector integration tests (flywheel_connectors-7hb.8).
//!
//! Deterministic integration tests using wiremock to mock the `OpenAI` API.
//! No real API calls. Covers:
//! - Non-streaming generation (chat + `simple_chat`)
//! - Streaming SSE (chunk parsing, error mid-stream)
//! - Tool/function calling shapes
//! - Error taxonomy (401/429/503/5xx)
//! - Usage metrics & cost extraction
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, doctor, `self_check`, shutdown)
//! - Input validation

#![allow(clippy::too_many_lines)]

use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::websocket::{
    CloseReason, Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor,
};
use chrono::{Duration, Utc};
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{CapabilityConstraints, FcpError};
use fcp_testkit::{AsyncTestContext, LogCapture, MockApiServer};
use futures_util::StreamExt;
use serde_json::json;
use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::{LazyLock, Mutex};
use std::task::Poll;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

// ──────────────── re-export the connector under test ────────────────
use base64::Engine;
use fcp_manifest::{ConnectorManifest, NetworkConstraints};
use fcp_openai::client::{OpenAIClient, VideoPollingOptions};
use fcp_openai::connector::OpenAIConnector;
use fcp_openai::error::OpenAIError;
use fcp_openai::types::{Model, VideoDurationSeconds, VideoModel, VideoSize, VideoStatus};

// ============================================================================
// Helpers
// ============================================================================

/// Map an operation ID to the capability ID that governs it.
fn capability_for_operation(op: &str) -> &str {
    match op {
        "openai.simple_chat" | "openai.get_usage" => "openai.chat",
        "openai.images.generate" => "openai.images",
        "openai.videos.generate" => "openai.videos",
        // All other operations have capability == operation ID
        other => other,
    }
}

static TOKEN_INSTANCE_BINDINGS: LazyLock<Mutex<HashMap<[u8; 32], String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[test]
fn manifest_declares_strict_per_operation_network_constraints() {
    let manifest = ConnectorManifest::parse_str_unchecked(include_str!("../manifest.toml"))
        .expect("OpenAI manifest should parse");
    assert_eq!(
        manifest.manifest.interface_hash,
        manifest
            .compute_interface_hash()
            .expect("OpenAI interface hash should compute")
    );

    for operation_id in ["chat", "simple_chat", "embeddings"] {
        let constraints = network_constraints(&manifest, operation_id);
        assert_openai_or_compatible_api_constraints(constraints, 10_485_760);
    }
    assert_openai_or_compatible_api_constraints(
        network_constraints(&manifest, "images_generate"),
        52_428_800,
    );

    for operation_id in [
        "audio_transcribe",
        "audio_tts",
        "finetune_create",
        "finetune_list",
        "finetune_get",
        "finetune_cancel",
        "finetune_events",
        "assistants_create",
        "assistants_list",
        "assistants_get",
        "assistants_delete",
        "threads_create",
        "threads_get",
        "threads_messages_create",
        "threads_messages_list",
        "threads_runs_create",
        "threads_runs_get",
        "threads_runs_cancel",
    ] {
        let constraints = network_constraints(&manifest, operation_id);
        assert_openai_or_compatible_api_constraints(constraints, constraints.max_response_bytes);
    }

    for operation_id in [
        "videos_generate",
        "realtime_transcribe",
        "realtime_voice",
        "realtime_browser_session",
    ] {
        let constraints = network_constraints(&manifest, operation_id);
        assert_openai_api_only_constraints(operation_id, constraints);
    }

    assert_no_egress_constraints(network_constraints(&manifest, "get_usage"));
    assert_eq!(
        manifest.provides.operations.len(),
        27,
        "update network constraint assertions when OpenAI operations change"
    );
}

fn network_constraints<'a>(
    manifest: &'a ConnectorManifest,
    operation_id: &str,
) -> &'a NetworkConstraints {
    manifest
        .provides
        .operations
        .get(operation_id)
        .unwrap_or_else(|| panic!("missing {operation_id} operation"))
        .network_constraints
        .as_ref()
        .unwrap_or_else(|| panic!("{operation_id} missing network_constraints"))
}

fn assert_openai_or_compatible_api_constraints(
    constraints: &NetworkConstraints,
    max_response_bytes: u64,
) {
    assert_eq!(
        constraints.host_allow.as_slice(),
        ["api.openai.com", "api.deepseek.com"]
    );
    assert_common_provider_constraints(constraints);
    assert_eq!(constraints.max_redirects, 5);
    assert_eq!(constraints.total_timeout_ms, 120_000);
    assert_eq!(constraints.max_response_bytes, max_response_bytes);
}

fn assert_openai_api_only_constraints(operation_id: &str, constraints: &NetworkConstraints) {
    assert_eq!(constraints.host_allow.as_slice(), ["api.openai.com"]);
    assert_common_provider_constraints(constraints);
    match operation_id {
        "videos_generate" => {
            assert_eq!(constraints.max_redirects, 5);
            assert_eq!(constraints.total_timeout_ms, 120_000);
            assert_eq!(constraints.max_response_bytes, 104_857_600);
        }
        "realtime_transcribe" | "realtime_voice" => {
            assert_eq!(constraints.max_redirects, 0);
            assert_eq!(constraints.total_timeout_ms, 300_000);
            assert_eq!(constraints.max_response_bytes, 10_485_760);
        }
        "realtime_browser_session" => {
            assert_eq!(constraints.max_redirects, 0);
            assert_eq!(constraints.total_timeout_ms, 120_000);
            assert_eq!(constraints.max_response_bytes, 10_485_760);
        }
        other => panic!("unexpected OpenAI-only operation {other}"),
    }
}

fn assert_common_provider_constraints(constraints: &NetworkConstraints) {
    assert_eq!(constraints.port_allow.as_slice(), [443]);
    assert!(constraints.ip_allow.is_empty());
    assert!(constraints.cidr_deny.is_empty());
    assert!(constraints.deny_localhost);
    assert!(constraints.deny_private_ranges);
    assert!(constraints.deny_tailnet_ranges);
    assert!(constraints.require_sni);
    assert!(constraints.spki_pins.is_empty());
    assert!(constraints.deny_ip_literals);
    assert!(constraints.require_host_canonicalization);
    assert_eq!(constraints.dns_max_ips, 16);
    assert_eq!(constraints.connect_timeout_ms, 10_000);
}

fn assert_no_egress_constraints(constraints: &NetworkConstraints) {
    assert_eq!(constraints.host_allow.as_slice(), ["none.invalid"]);
    assert_eq!(constraints.port_allow.as_slice(), [0]);
    assert!(constraints.ip_allow.is_empty());
    assert!(constraints.cidr_deny.is_empty());
    assert!(constraints.deny_localhost);
    assert!(constraints.deny_private_ranges);
    assert!(constraints.deny_tailnet_ranges);
    assert!(!constraints.require_sni);
    assert!(constraints.spki_pins.is_empty());
    assert!(constraints.deny_ip_literals);
    assert!(constraints.require_host_canonicalization);
    assert_eq!(constraints.dns_max_ips, 0);
    assert_eq!(constraints.max_redirects, 0);
    assert_eq!(constraints.connect_timeout_ms, 10_000);
    assert_eq!(constraints.total_timeout_ms, 30_000);
    assert_eq!(constraints.max_response_bytes, 65_536);
}

/// Generate a valid COSE capability token signed by the given key.
fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> fcp_core::CapabilityToken {
    generate_valid_token_with_instance(signing_key, op, None)
}

/// Generate a valid COSE capability token with an explicit connector instance binding.
fn generate_valid_bound_token(
    signing_key: &Ed25519SigningKey,
    op: &str,
    instance_id: &str,
) -> fcp_core::CapabilityToken {
    generate_valid_token_with_instance(signing_key, op, Some(instance_id))
}

fn generate_valid_token_with_instance(
    signing_key: &Ed25519SigningKey,
    op: &str,
    instance_id: Option<&str>,
) -> fcp_core::CapabilityToken {
    let cap = capability_for_operation(op);
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate");
    let target_instance = instance_id.map(str::to_owned).or_else(|| {
        TOKEN_INSTANCE_BINDINGS
            .lock()
            .expect("token instance binding registry should not be poisoned")
            .get(&signing_key.verifying_key().to_bytes())
            .cloned()
    });
    if let Some(instance_id) = target_instance.as_deref() {
        builder = builder.target_instance(instance_id);
    }
    let cose = builder.sign(signing_key).unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

/// Perform handshake on a connector, returning the signing key for token generation.
async fn setup_handshake(connector: &mut OpenAIConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let mapped: Vec<&str> = caps.iter().map(|c| capability_for_operation(c)).collect();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": mapped
        }))
        .await
        .expect("handshake should succeed");

    TOKEN_INSTANCE_BINDINGS
        .lock()
        .expect("token instance binding registry should not be poisoned")
        .insert(verifying_key.to_bytes(), connector.instance_id().to_owned());

    signing_key
}

/// Configure connector with a mock server URL.
async fn setup_configure(connector: &mut OpenAIConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-api-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

type TestServerWebSocket = ServerWebSocket<TcpStream>;

async fn read_http_headers<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<Vec<u8>> {
    const MAX_HEADERS: usize = 16 * 1024;

    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0_u8; 256];

    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before websocket handshake completed",
            ));
        }

        buf.extend_from_slice(&temp[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake headers too large",
            ));
        }
    }
}

async fn accept_openai_test_websocket(mut stream: TcpStream) -> (TestServerWebSocket, String) {
    let request = read_http_headers(&mut stream)
        .await
        .expect("read websocket handshake");
    let headers = String::from_utf8_lossy(&request).into_owned();
    let ws = WebSocketAcceptor::new()
        .accept(&fcp_async_core::compatibility_cx(), &request, stream)
        .await
        .expect("accept websocket");
    (ws, headers)
}

async fn send_json_frame(ws: &mut TestServerWebSocket, value: serde_json::Value, context: &str) {
    ws.send(
        &fcp_async_core::compatibility_cx(),
        ServerWsMessage::text(value.to_string()),
    )
    .await
    .expect(context);
}

async fn recv_text_frame(ws: &mut TestServerWebSocket, context: &str) -> Option<String> {
    match ws.recv(&fcp_async_core::compatibility_cx()).await {
        Ok(Some(ServerWsMessage::Text(text))) => Some(text),
        Ok(Some(other)) => panic!("expected text frame for {context}, got {other:?}"),
        Ok(None) => None,
        Err(err) => panic!("{context}: {err}"),
    }
}

async fn close_test_websocket(ws: &mut TestServerWebSocket) {
    let _ = ws
        .close(&fcp_async_core::compatibility_cx(), CloseReason::normal())
        .await;
}

/// Standard `OpenAI` chat completion success response.
fn openai_success_response(
    resp_id: &str,
    text: &str,
    prompt_tokens: u32,
    completion_tokens: u32,
) -> serde_json::Value {
    json!({
        "id": resp_id,
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": text
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    })
}

/// `OpenAI` `tool_calls` response.
fn openai_tool_use_response(
    resp_id: &str,
    call_id: &str,
    fn_name: &str,
    fn_args: &str,
    prompt_tokens: u32,
    completion_tokens: u32,
) -> serde_json::Value {
    json!({
        "id": resp_id,
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": fn_name,
                        "arguments": fn_args
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    })
}

/// `OpenAI` API error envelope.
fn openai_error(error_type: &str, message: &str, code: Option<&str>) -> serde_json::Value {
    json!({
        "error": {
            "message": message,
            "type": error_type,
            "param": null,
            "code": code
        }
    })
}

/// Build SSE body from data-only events (`OpenAI` uses `data: {json}\n\n`).
fn build_sse_body(events: &[serde_json::Value]) -> String {
    use std::fmt::Write;
    let mut body = String::new();
    for event in events {
        let _ = write!(body, "data: {event}\n\n");
    }
    body.push_str("data: [DONE]\n\n");
    body
}

// ============================================================================
// Client HTTP Boundary Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn client_chat_success_tracks_usage() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("Authorization", "Bearer test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1_677_652_288,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello! How can I help you today?"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 8,
                "total_tokens": 18
            }
        })))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test_key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let response = client
        .chat(Model::Gpt4o, "Hi", None, Some(1024))
        .await
        .unwrap();

    assert_eq!(response, "Hello! How can I help you today?");
    assert_eq!(client.total_prompt_tokens(), 10);
    assert_eq!(client.total_completion_tokens(), 8);
}

#[fcp_async_core::runtime::test]
async fn client_unauthorized_maps_invalid_key() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "message": "Incorrect API key provided",
                "type": "invalid_request_error",
                "param": null,
                "code": "invalid_api_key"
            }
        })))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("bad_key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), OpenAIError::InvalidApiKey));
}

#[fcp_async_core::runtime::test]
async fn client_rate_limited_maps_retryable_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "error": {
                "message": "Rate limit exceeded",
                "type": "rate_limit_error",
                "param": null,
                "code": null
            }
        })))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test_key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        OpenAIError::RateLimited { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn client_overloaded_maps_retryable_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": {
                "message": "Server overloaded",
                "type": "server_error",
                "param": null,
                "code": null
            }
        })))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test_key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        OpenAIError::Overloaded { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn client_context_length_exceeded_maps_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "message": "maximum context length exceeded",
                "type": "invalid_request_error",
                "param": null,
                "code": null
            }
        })))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test_key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        OpenAIError::ContextLengthExceeded { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn client_content_filtered_maps_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "message": "Content filtered",
                "type": "invalid_request_error",
                "param": null,
                "code": "content_filter"
            }
        })))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test_key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        OpenAIError::ContentFiltered { .. }
    ));
}

#[fcp_async_core::runtime::test]
async fn client_logs_redact_api_key_and_prompt() {
    let capture = LogCapture::new();
    let _guard = capture.install_json_with_filter("debug");
    let scenario = AsyncTestContext::for_scenario("openai.client.log_redaction");
    tracing::debug!(
        run_id = %scenario.run_id(),
        scenario_id = %scenario.scenario_id(),
        correlation_id = %scenario.correlation_id(),
        "log_capture_ready"
    );

    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("Authorization", "Bearer test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1_677_652_288,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello! How can I help you today?"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 8,
                "total_tokens": 18
            }
        })))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test_key")
        .unwrap()
        .with_base_url(mock_server.uri());
    let secret_prompt = "TopSecretPrompt";
    let _ = client
        .chat(Model::Gpt4o, secret_prompt, None, Some(1024))
        .await
        .unwrap();

    let logs = capture.jsonl();
    assert!(
        logs.contains("log_capture_ready"),
        "expected debug logs to be captured"
    );
    assert!(
        logs.contains(scenario.correlation_id()),
        "scenario correlation id should be present in logs"
    );
    assert!(
        !logs.contains("test_key"),
        "API key should not appear in logs"
    );
    assert!(
        !logs.contains(secret_prompt),
        "prompt text should not appear in logs"
    );
}

#[fcp_async_core::runtime::test]
async fn client_generate_video_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/videos"))
        .and(header("Authorization", "Bearer test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "video-123",
            "model": "sora-2",
            "status": "queued",
            "seconds": "4",
            "size": "1280x720"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/videos/video-123"))
        .and(header("Authorization", "Bearer test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "video-123",
            "model": "sora-2",
            "status": "completed",
            "seconds": "4",
            "size": "1280x720"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/videos/video-123/content"))
        .and(header("Authorization", "Bearer test_key"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "video/mp4")
                .set_body_bytes(b"video-bytes".to_vec()),
        )
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test_key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let video = client
        .generate_video(
            VideoModel::Sora2,
            "A quiet product shot",
            Some(VideoDurationSeconds::Seconds4),
            Some(VideoSize::Size1280x720),
            VideoPollingOptions {
                poll_interval_ms: 1,
                max_poll_attempts: 2,
            },
        )
        .await
        .unwrap();

    assert_eq!(video.video_id, "video-123");
    assert_eq!(video.model, "sora-2");
    assert_eq!(video.status, VideoStatus::Completed);
    assert_eq!(video.seconds.as_deref(), Some("4"));
    assert_eq!(video.size.as_deref(), Some("1280x720"));
    assert_eq!(video.mime_type, "video/mp4");
    assert_eq!(video.bytes, b"video-bytes");
}

// ============================================================================
// Non-Streaming Generation Tests
// ============================================================================

/// Happy path: `openai.simple_chat` invoke returns text response.
#[fcp_async_core::runtime::test]
async fn simple_chat_invoke_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("openai.simple_chat.happy_path");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/chat/completions",
        openai_success_response("chatcmpl-001", "Hello from GPT!", 12, 8),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.simple_chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": { "message": "Hi there" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["response"], "Hello from GPT!");
    assert_eq!(result["usage"]["prompt_tokens"], 12);
    assert_eq!(result["usage"]["completion_tokens"], 8);
    let cost = result["cost_usd"].as_f64().unwrap();
    assert!(cost > 0.0, "cost should be positive: {cost}");
    mock.assert_received("/v1/chat/completions").await;
}

/// Happy path: openai.chat invoke with multi-turn messages.
#[fcp_async_core::runtime::test]
async fn chat_invoke_multi_turn() {
    let _ctx = AsyncTestContext::for_scenario("openai.chat.multi_turn");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/chat/completions",
        openai_success_response("chatcmpl-002", "The capital of France is Paris.", 25, 12),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [
                    {"role": "user", "content": "What is the capital of France?"},
                    {"role": "assistant", "content": "Let me think..."},
                    {"role": "user", "content": "Go ahead."}
                ],
                "max_tokens": 1024
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["content"], "The capital of France is Paris.");
    assert_eq!(result["id"], "chatcmpl-002");
}

/// `openai.simple_chat` with system prompt.
#[fcp_async_core::runtime::test]
async fn simple_chat_invoke_with_system() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/chat/completions",
        openai_success_response("chatcmpl-003", "42", 30, 3),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.simple_chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": {
                "message": "What is 6*7?",
                "system": "You are a calculator. Reply with only the number.",
                "max_tokens": 16
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["response"], "42");
}

// ============================================================================
// Streaming SSE Tests
// ============================================================================

/// Streaming: parse complete SSE chunks.
#[fcp_async_core::runtime::test]
async fn streaming_sse_chunk_parsing() {
    let _ctx = AsyncTestContext::for_scenario("openai.stream.chunk_parsing");
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        json!({
            "id": "chatcmpl-stream-001",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {"role": "assistant", "content": ""},
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-stream-001",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {"content": "Hello"},
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-stream-001",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {"content": " World"},
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-stream-001",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }]
        }),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("Authorization", "Bearer test-stream-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-stream-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_openai::types::Message::user("Hello")];

    let stream = client
        .chat_completion_stream(Model::Gpt4o, messages, Some(1024), None, None, None)
        .await
        .expect("stream should start");

    let chunks: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.expect("each chunk should parse"))
        .collect();

    assert_eq!(
        chunks.len(),
        4,
        "expected 4 SSE chunks, got {}",
        chunks.len()
    );

    // Verify text deltas
    let mut text_acc = String::new();
    for chunk in &chunks {
        if let Some(choice) = chunk.choices.first() {
            if let Some(content) = &choice.delta.content {
                text_acc.push_str(content);
            }
        }
    }
    assert_eq!(text_acc, "Hello World");
}

/// Streaming: SSE error mid-stream (non-200 status).
#[fcp_async_core::runtime::test]
async fn streaming_sse_error_mid_stream() {
    let _ctx = AsyncTestContext::for_scenario("openai.stream.error_mid_stream");
    let mock_server = MockServer::start().await;

    // OpenAI returns a non-200 status for errors, even on stream requests
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_json(openai_error(
            "server_error",
            "Internal server error",
            None,
        )))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_openai::types::Message::user("Hello")];

    let result = client
        .chat_completion_stream(Model::Gpt4o, messages, Some(1024), None, None, None)
        .await;

    assert!(result.is_err(), "stream should fail on non-200 status");
}

/// Streaming: [DONE] terminates the stream cleanly.
#[fcp_async_core::runtime::test]
async fn streaming_sse_done_terminates() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[json!({
        "id": "chatcmpl-done-001",
        "object": "chat.completion.chunk",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "delta": {"role": "assistant", "content": "Hi"},
            "finish_reason": null
        }]
    })]);

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_openai::types::Message::user("Hi")];

    let stream = client
        .chat_completion_stream(Model::Gpt4o, messages, Some(256), None, None, None)
        .await
        .expect("stream should start");

    let chunks: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(std::result::Result::ok)
        .collect();

    // Should have exactly 1 chunk (the [DONE] produces None, ending the stream)
    assert_eq!(chunks.len(), 1, "should have 1 chunk before [DONE]");
}

// ============================================================================
// Tool/Function Calling Tests
// ============================================================================

/// Tool use: model requests tool call and response includes `tool_calls`.
#[fcp_async_core::runtime::test]
async fn tool_use_invoke_shape() {
    let _ctx = AsyncTestContext::for_scenario("openai.tool_use.shape");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/chat/completions",
        openai_tool_use_response(
            "chatcmpl-tool-001",
            "call_abc123",
            "get_weather",
            r#"{"city":"San Francisco","unit":"celsius"}"#,
            20,
            15,
        ),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "What's the weather in SF?"}],
                "tools": [{
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "Get the weather",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "city": {"type": "string"},
                                "unit": {"type": "string"}
                            }
                        }
                    }
                }]
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    // finish_reason is formatted via `format!("{r:?}").to_lowercase()` -> "toolcalls"
    let fr = result["finish_reason"].as_str().unwrap();
    assert!(
        fr == "tool_calls" || fr == "toolcalls",
        "expected tool_calls or toolcalls, got: {fr}"
    );
    assert_eq!(result["usage"]["prompt_tokens"], 20);
    assert_eq!(result["usage"]["completion_tokens"], 15);
}

/// Tool use streaming: streaming response with tool call deltas.
#[fcp_async_core::runtime::test]
async fn tool_use_streaming_shape() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        json!({
            "id": "chatcmpl-tool-stream",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {
                    "role": "assistant",
                    "tool_calls": [{
                        "index": 0,
                        "id": "call_xyz",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": ""}
                    }]
                },
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-tool-stream",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": {"arguments": "{\"city\":\"SF\"}"}
                    }]
                },
                "finish_reason": null
            }]
        }),
        json!({
            "id": "chatcmpl-tool-stream",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "tool_calls"
            }]
        }),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_openai::types::Message::user("Weather?")];

    let stream = client
        .chat_completion_stream(Model::Gpt4o, messages, Some(1024), None, None, None)
        .await
        .expect("stream should start");

    let chunks: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.expect("each chunk should parse"))
        .collect();

    assert_eq!(chunks.len(), 3, "expected 3 tool streaming chunks");

    // First chunk has tool call ID
    let first_tc = chunks[0].choices[0].delta.tool_calls.as_ref().unwrap();
    assert_eq!(first_tc[0].id.as_deref(), Some("call_xyz"));

    // Last chunk has finish_reason = tool_calls
    assert_eq!(
        chunks[2].choices[0].finish_reason,
        Some(fcp_openai::types::FinishReason::ToolCalls)
    );
}

// ============================================================================
// Error Taxonomy Tests
// ============================================================================

/// 401 maps to `OpenAIError::InvalidApiKey` -> `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("openai.error.401_unauthorized");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(openai_error(
            "invalid_request_error",
            "Incorrect API key",
            Some("invalid_api_key"),
        )))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("bad-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    let err = result.unwrap_err();
    assert!(matches!(err, fcp_openai::error::OpenAIError::InvalidApiKey));

    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }));
}

/// 429 maps to `OpenAIError::RateLimited` -> `FcpError::RateLimited`.
/// Constructs the error directly to avoid the 30s `retry_after` delay from `RateLimited`
/// that the `RetryLoop` honors during retries.
#[fcp_async_core::runtime::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("openai.error.429_rate_limited");

    let err = fcp_openai::error::OpenAIError::RateLimited {
        retry_after_ms: 30_000,
    };

    assert!(err.is_retryable());
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(30)));

    let fcp_err = err.to_fcp_error();
    match fcp_err {
        fcp_core::FcpError::RateLimited { retry_after_ms, .. } => {
            assert_eq!(retry_after_ms, 30_000);
        }
        other => panic!("expected RateLimited, got: {other:?}"),
    }
}

/// 503 maps to `OpenAIError::Overloaded` -> `FcpError::External` (retryable).
/// Constructs the error directly to avoid the 60s `retry_after` delay from Overloaded
/// that the `RetryLoop` honors during retries.
#[fcp_async_core::runtime::test]
async fn error_503_maps_to_overloaded() {
    let _ctx = AsyncTestContext::for_scenario("openai.error.503_overloaded");

    // Verify the error type and FCP mapping directly (avoids 60s retry delay)
    let err = fcp_openai::error::OpenAIError::Overloaded {
        retry_after_ms: 60_000,
    };

    assert!(err.is_retryable());
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(60)));

    let fcp_err = err.to_fcp_error();
    match fcp_err {
        fcp_core::FcpError::External {
            retryable,
            service,
            status_code,
            ..
        } => {
            assert!(retryable, "Overloaded should map to retryable External");
            assert_eq!(service, "openai");
            assert_eq!(status_code, Some(503));
        }
        other => panic!("expected External, got: {other:?}"),
    }
}

/// Context length exceeded maps to `FcpError::InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn error_context_length_maps_to_invalid_request() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(openai_error(
            "invalid_request_error",
            "maximum context length exceeded",
            None,
        )))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    let err = result.unwrap_err();
    assert!(matches!(
        err,
        fcp_openai::error::OpenAIError::ContextLengthExceeded { .. }
    ));

    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, fcp_core::FcpError::InvalidRequest { .. }));
}

/// Content filter error maps to `FcpError::InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn error_content_filter_maps_to_invalid_request() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(openai_error(
            "invalid_request_error",
            "Content filtered",
            Some("content_filter"),
        )))
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::Gpt4o, "Hi", None, Some(1024)).await;

    let err = result.unwrap_err();
    assert!(matches!(
        err,
        fcp_openai::error::OpenAIError::ContentFiltered { .. }
    ));

    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, fcp_core::FcpError::InvalidRequest { .. }));
}

// ============================================================================
// Usage Metrics Tests
// ============================================================================

/// Usage metrics accumulate across requests.
#[fcp_async_core::runtime::test]
async fn usage_metrics_accumulate() {
    let _ctx = AsyncTestContext::for_scenario("openai.usage.accumulate");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_success_response(
                "chatcmpl-usage-001",
                "First response",
                100,
                50,
            )),
        )
        .expect(2)
        .mount(&mock_server)
        .await;

    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    client
        .chat(Model::Gpt4o, "Hi", None, Some(1024))
        .await
        .unwrap();
    client
        .chat(Model::Gpt4o, "Hi again", None, Some(1024))
        .await
        .unwrap();

    assert_eq!(client.total_prompt_tokens(), 200);
    assert_eq!(client.total_completion_tokens(), 100);
}

/// Usage cost is model-dependent.
#[fcp_async_core::runtime::test]
async fn usage_cost_is_model_dependent() {
    let usage = fcp_openai::types::Usage {
        prompt_tokens: 1_000_000,
        completion_tokens: 1_000_000,
        total_tokens: 2_000_000,
        prompt_tokens_details: None,
    };

    let cost_4o = usage.calculate_cost(Model::Gpt4o);
    let cost_mini = usage.calculate_cost(Model::Gpt4oMini);

    // GPT-4o: $2.50 input + $10.00 output = $12.50
    assert!((cost_4o - 12.50).abs() < 0.01, "gpt-4o cost = {cost_4o}");
    // GPT-4o-mini: $0.15 input + $0.60 output = $0.75
    assert!(
        (cost_mini - 0.75).abs() < 0.01,
        "gpt-4o-mini cost = {cost_mini}"
    );
    assert!(
        cost_4o > cost_mini,
        "gpt-4o should be more expensive than mini"
    );
}

// ============================================================================
// FCP2 Default-Deny Tests
// ============================================================================

/// Missing `capability_token` in invoke fails.
#[fcp_async_core::runtime::test]
async fn capability_missing_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("openai.cap.missing_token");
    let mock = MockApiServer::start().await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let _signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}]
            }
            // no capability_token
        }))
        .await;

    assert!(result.is_err(), "should fail without capability token");
}

/// Invoke without handshake fails.
#[fcp_async_core::runtime::test]
async fn capability_no_handshake_fails() {
    let mock = MockApiServer::start().await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    // no handshake

    let signing_key = Ed25519SigningKey::generate();
    let capability = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}]
            },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::NotHandshaken),
        "should get NotHandshaken without handshake"
    );
}

/// Invoke without configure fails.
#[fcp_async_core::runtime::test]
async fn capability_no_configure_fails() {
    let mut connector = OpenAIConnector::new();
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.simple_chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::NotConfigured
    ));
}

/// Wrong operation returns `OperationNotGranted`.
#[fcp_async_core::runtime::test]
async fn capability_wrong_operation_fails() {
    let mock = MockApiServer::start().await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.nonexistent_op",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            fcp_core::FcpError::OperationNotGranted { .. }
                | fcp_core::FcpError::Unauthorized { .. }
                | fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "expected denial error, got: {err:?}"
    );
}

/// Unknown operation is rejected.
#[fcp_async_core::runtime::test]
async fn capability_unknown_operation_fails() {
    let mock = MockApiServer::start().await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.unknown");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.unknown",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health before configure returns `not_configured`.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let connector = OpenAIConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

/// Health after configure returns healthy.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
    assert!(result.get("metrics").is_some());
}

/// Configure rejects off-policy public hosts before any bearer token can be used.
#[fcp_async_core::runtime::test]
async fn lifecycle_configure_rejects_untrusted_base_url() {
    let mut connector = OpenAIConnector::new();
    let error = connector
        .handle_configure(json!({
            "api_key": "test-api-key-xyz",
            "base_url": "https://evil.example.com/v1"
        }))
        .await
        .expect_err("configure should reject untrusted hosts");

    match error {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("not allowed"));
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

/// Handshake grants capabilities.
#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_grants_capabilities() {
    let mut connector = OpenAIConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["openai.chat"]
        }))
        .await
        .unwrap();

    assert_eq!(result["status"], "accepted");
    assert!(result.get("session_id").is_some());
    let caps = result["capabilities_granted"].as_array().unwrap();
    assert!(!caps.is_empty(), "should grant capabilities");
}

/// Shutdown returns clean status.
#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_clean() {
    let connector = OpenAIConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

/// Introspect lists operations.
#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_operations() {
    let connector = OpenAIConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    let op_ids: Vec<&str> = ops.iter().filter_map(|o| o["id"].as_str()).collect();

    assert!(
        op_ids.contains(&"openai.chat"),
        "should include openai.chat"
    );
    assert!(
        op_ids.contains(&"openai.simple_chat"),
        "should include openai.simple_chat"
    );
    assert!(
        op_ids.contains(&"openai.get_usage"),
        "should include openai.get_usage"
    );
    assert!(
        op_ids.contains(&"openai.embeddings"),
        "should include openai.embeddings"
    );
    assert!(
        op_ids.contains(&"openai.images.generate"),
        "should include openai.images.generate"
    );
    assert!(
        op_ids.contains(&"openai.videos.generate"),
        "should include openai.videos.generate"
    );
    assert!(
        op_ids.contains(&"openai.audio.transcribe"),
        "should include openai.audio.transcribe"
    );
    assert!(
        op_ids.contains(&"openai.realtime.transcribe"),
        "should include openai.realtime.transcribe"
    );
    assert!(
        op_ids.contains(&"openai.realtime.voice"),
        "should include openai.realtime.voice"
    );
    assert!(
        op_ids.contains(&"openai.realtime.browser_session"),
        "should include openai.realtime.browser_session"
    );
    assert!(
        op_ids.contains(&"openai.audio.tts"),
        "should include openai.audio.tts"
    );
    assert!(
        op_ids.contains(&"openai.finetune.create"),
        "should include openai.finetune.create"
    );
    assert!(
        op_ids.contains(&"openai.finetune.list"),
        "should include openai.finetune.list"
    );
    assert!(
        op_ids.contains(&"openai.finetune.get"),
        "should include openai.finetune.get"
    );
    assert!(
        op_ids.contains(&"openai.finetune.cancel"),
        "should include openai.finetune.cancel"
    );
    assert!(
        op_ids.contains(&"openai.finetune.events"),
        "should include openai.finetune.events"
    );
}

/// Doctor before configure shows unhealthy.
#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_before_configure() {
    let connector = OpenAIConnector::new();
    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "unhealthy");
}

/// Doctor after configure shows healthy (with API key).
#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_after_configure() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

// ============================================================================
// Input Validation Tests
// ============================================================================

/// Empty messages array is rejected.
#[fcp_async_core::runtime::test]
async fn validation_empty_messages_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": { "messages": [] },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::InvalidRequest { .. }
    ));
}

/// Unknown model string is rejected.
#[fcp_async_core::runtime::test]
async fn validation_unknown_model_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "model": "gpt-99-turbo"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::InvalidRequest { .. }
    ));
}

/// Missing message in `simple_chat` is rejected.
#[fcp_async_core::runtime::test]
async fn validation_simple_chat_missing_message_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.simple_chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.simple_chat",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("message"),
                "error should mention missing message: {message}"
            );
        }
        _ => panic!("expected InvalidRequest, got: {err:?}"),
    }
}

// ============================================================================
// Metrics Tests
// ============================================================================

/// Error counter increments on non-retryable errors.
#[fcp_async_core::runtime::test]
async fn metrics_error_counter_increments() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(openai_error(
            "invalid_request_error",
            "Incorrect API key",
            Some("invalid_api_key"),
        )))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    assert_eq!(connector.total_errors(), 0);

    let _result = connector
        .handle_invoke(json!({
            "operation": "openai.chat",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}]
            },
            "capability_token": token
        }))
        .await;

    assert_eq!(
        connector.total_errors(),
        1,
        "error counter should increment"
    );
}

// ============================================================================
// Get Usage Tests
// ============================================================================

/// `get_usage` returns token and cost stats via invoke.
#[fcp_async_core::runtime::test]
async fn get_usage_returns_stats() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.get_usage");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.get_usage",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["total_prompt_tokens"], 0);
    assert_eq!(result["total_completion_tokens"], 0);
    assert!(result.get("requests_total").is_some());
    assert!(result.get("total_cost_usd").is_some());
}

// ============================================================================
// Embeddings Tests
// ============================================================================

/// Helper: standard `OpenAI` embeddings success response.
fn openai_embedding_response(
    model: &str,
    embeddings: &[Vec<f64>],
    prompt_tokens: u32,
) -> serde_json::Value {
    json!({
        "object": "list",
        "data": embeddings.iter().enumerate().map(|(i, emb)| json!({
            "object": "embedding",
            "index": i,
            "embedding": emb
        })).collect::<Vec<_>>(),
        "model": model,
        "usage": {
            "prompt_tokens": prompt_tokens,
            "total_tokens": prompt_tokens
        }
    })
}

/// Happy path: single text embedding.
#[fcp_async_core::runtime::test]
async fn embeddings_single_text_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("openai.embeddings.single_text");

    let mock_server = MockServer::start().await;
    let embedding_vec = vec![0.1, 0.2, 0.3, -0.1, 0.0];
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(header("Authorization", "Bearer test-api-key-xyz"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(
                "text-embedding-3-small",
                std::slice::from_ref(&embedding_vec),
                5,
            )),
        )
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.embeddings"]).await;
    let token = generate_valid_token(&signing_key, "openai.embeddings");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.embeddings",
            "input": { "input": "Hello world" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["model"], "text-embedding-3-small");
    let data = result["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["index"], 0);
    let emb = data[0]["embedding"].as_array().unwrap();
    assert_eq!(emb.len(), 5);
    assert_eq!(result["usage"]["prompt_tokens"], 5);
    assert_eq!(result["usage"]["total_tokens"], 5);
    assert!(result.get("cost_usd").is_some());
    assert_eq!(result["provenance"]["source"], "openai.embeddings");
    assert!(
        result["taint"]
            .as_array()
            .unwrap()
            .contains(&json!("external_input"))
    );
}

/// Happy path: batch embedding (multiple texts).
#[fcp_async_core::runtime::test]
async fn embeddings_batch_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("openai.embeddings.batch");

    let mock_server = MockServer::start().await;
    let emb1 = vec![0.1, 0.2, 0.3];
    let emb2 = vec![0.4, 0.5, 0.6];
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(
                "text-embedding-3-large",
                &[emb1, emb2],
                12,
            )),
        )
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.embeddings"]).await;
    let token = generate_valid_token(&signing_key, "openai.embeddings");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.embeddings",
            "input": {
                "input": ["text one", "text two"],
                "model": "text-embedding-3-large"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    let data = result["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0]["index"], 0);
    assert_eq!(data[1]["index"], 1);
    assert_eq!(result["usage"]["prompt_tokens"], 12);
}

/// Embeddings with custom dimensions parameter.
#[fcp_async_core::runtime::test]
async fn embeddings_with_dimensions() {
    let _ctx = AsyncTestContext::for_scenario("openai.embeddings.dimensions");

    let mock_server = MockServer::start().await;
    let emb = vec![0.1, 0.2]; // 2-d output
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(openai_embedding_response(
                "text-embedding-3-small",
                &[emb],
                3,
            )),
        )
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.embeddings"]).await;
    let token = generate_valid_token(&signing_key, "openai.embeddings");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.embeddings",
            "input": {
                "input": "Test",
                "dimensions": 2
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    let data = result["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["embedding"].as_array().unwrap().len(), 2);
}

/// Missing input field returns error.
#[fcp_async_core::runtime::test]
async fn embeddings_missing_input() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.embeddings"]).await;
    let token = generate_valid_token(&signing_key, "openai.embeddings");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.embeddings",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("input"),
                "error should mention 'input': {message}"
            );
        }
        other => panic!("Expected InvalidRequest, got: {other:?}"),
    }
}

/// Empty input string returns error.
#[fcp_async_core::runtime::test]
async fn embeddings_empty_input_string() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.embeddings"]).await;
    let token = generate_valid_token(&signing_key, "openai.embeddings");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.embeddings",
            "input": { "input": "" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("empty"),
                "error should mention 'empty': {message}"
            );
        }
        other => panic!("Expected InvalidRequest, got: {other:?}"),
    }
}

/// Empty input array returns error.
#[fcp_async_core::runtime::test]
async fn embeddings_empty_input_array() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.embeddings"]).await;
    let token = generate_valid_token(&signing_key, "openai.embeddings");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.embeddings",
            "input": { "input": [] },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("empty"),
                "error should mention 'empty': {message}"
            );
        }
        other => panic!("Expected InvalidRequest, got: {other:?}"),
    }
}

/// Wrong capability token is rejected.
#[fcp_async_core::runtime::test]
async fn embeddings_requires_correct_capability() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    // Handshake with chat capability only
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    // Generate token for chat, not embeddings
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.embeddings",
            "input": { "input": "Hello" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Rate limit error maps correctly for embeddings.
/// Constructs the error directly to avoid the 30s `retry_after` delay.
#[fcp_async_core::runtime::test]
async fn embeddings_rate_limited_error_mapping() {
    let err = fcp_openai::error::OpenAIError::RateLimited {
        retry_after_ms: 30_000,
    };

    let fcp_err = err.to_fcp_error();
    match fcp_err {
        fcp_core::FcpError::RateLimited { retry_after_ms, .. } => {
            assert_eq!(retry_after_ms, 30_000);
        }
        other => panic!("Expected RateLimited, got: {other:?}"),
    }
}

/// Unknown embedding model returns error.
#[fcp_async_core::runtime::test]
async fn embeddings_unknown_model() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.embeddings"]).await;
    let token = generate_valid_token(&signing_key, "openai.embeddings");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.embeddings",
            "input": { "input": "Hello", "model": "not-a-real-model" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("Unknown embedding model"),
                "error should mention unknown model: {message}"
            );
        }
        other => panic!("Expected InvalidRequest, got: {other:?}"),
    }
}

// ============================================================================
// Image Generation Tests
// ============================================================================

/// Helper: standard `OpenAI` image generation success response.
fn openai_image_response(revised_prompt: Option<&str>) -> serde_json::Value {
    json!({
        "created": 1_700_000_000,
        "data": [{
            "b64_json": "iVBORw0KGgoAAAANSUhEUg==",
            "revised_prompt": revised_prompt
        }]
    })
}

/// Happy path: generate an image with `DALL-E` 3.
#[fcp_async_core::runtime::test]
async fn images_generate_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("openai.images.generate.happy_path");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/images/generations"))
        .and(header("Authorization", "Bearer test-api-key-xyz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(openai_image_response(Some("A beautiful sunset"))),
        )
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.images"]).await;
    let token = generate_valid_token(&signing_key, "openai.images.generate");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.images.generate",
            "input": { "prompt": "A sunset over mountains" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["created"], 1_700_000_000);
    let data = result["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert!(data[0]["b64_json"].as_str().is_some());
    assert_eq!(data[0]["revised_prompt"], "A beautiful sunset");
    assert_eq!(result["provenance"]["source"], "openai.images");
    assert!(result["provenance"]["derived"].as_bool().unwrap());
    let taint = result["taint"].as_array().unwrap();
    assert!(taint.contains(&json!("external_input")));
    assert!(taint.contains(&json!("ai_generated")));
}

/// Image generation with custom size and quality.
#[fcp_async_core::runtime::test]
async fn images_generate_with_options() {
    let _ctx = AsyncTestContext::for_scenario("openai.images.generate.options");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/images/generations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_image_response(None)))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.images"]).await;
    let token = generate_valid_token(&signing_key, "openai.images.generate");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.images.generate",
            "input": {
                "prompt": "A cat",
                "model": "dall-e-3",
                "size": "1792x1024",
                "quality": "hd",
                "n": 1
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["created"], 1_700_000_000);
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
}

/// Missing prompt returns error.
#[fcp_async_core::runtime::test]
async fn images_generate_missing_prompt() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.images"]).await;
    let token = generate_valid_token(&signing_key, "openai.images.generate");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.images.generate",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("prompt"),
                "error should mention 'prompt': {message}"
            );
        }
        other => panic!("Expected InvalidRequest for missing prompt, got: {other:?}"),
    }
}

/// Empty prompt string returns error.
#[fcp_async_core::runtime::test]
async fn images_generate_empty_prompt() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.images"]).await;
    let token = generate_valid_token(&signing_key, "openai.images.generate");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.images.generate",
            "input": { "prompt": "" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("empty"),
                "error should mention 'empty': {message}"
            );
        }
        other => panic!("Expected InvalidRequest for empty prompt, got: {other:?}"),
    }
}

/// Unknown image model returns error.
#[fcp_async_core::runtime::test]
async fn images_generate_unknown_model() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.images"]).await;
    let token = generate_valid_token(&signing_key, "openai.images.generate");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.images.generate",
            "input": { "prompt": "A cat", "model": "dall-e-99" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("Unknown image model"),
                "error should mention unknown image model: {message}"
            );
        }
        other => panic!("Expected InvalidRequest for unknown model, got: {other:?}"),
    }
}

/// Unknown image size returns error.
#[fcp_async_core::runtime::test]
async fn images_generate_unknown_size() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.images"]).await;
    let token = generate_valid_token(&signing_key, "openai.images.generate");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.images.generate",
            "input": { "prompt": "A cat", "size": "9999x9999" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("Unknown image size"),
                "error should mention unknown size: {message}"
            );
        }
        other => panic!("Expected InvalidRequest for unknown size, got: {other:?}"),
    }
}

/// Wrong capability token is rejected for image generation.
#[fcp_async_core::runtime::test]
async fn images_generate_requires_correct_capability() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.images.generate",
            "input": { "prompt": "A cat" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Video Generation Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn videos_generate_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("openai.videos.generate.happy_path");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/videos"))
        .and(header("Authorization", "Bearer test-api-key-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "video-abc123",
            "model": "sora-2",
            "status": "queued",
            "seconds": "4",
            "size": "1280x720"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/videos/video-abc123"))
        .and(header("Authorization", "Bearer test-api-key-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "video-abc123",
            "model": "sora-2",
            "status": "completed",
            "seconds": "4",
            "size": "1280x720"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/videos/video-abc123/content"))
        .and(header("Authorization", "Bearer test-api-key-xyz"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "video/mp4")
                .set_body_bytes(b"video-bytes".to_vec()),
        )
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.videos"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.videos.generate",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.videos.generate",
            "input": {
                "prompt": "A product shot rotating on a white table",
                "duration_seconds": 4,
                "size": "1280x720",
                "poll_interval_ms": 1,
                "max_poll_attempts": 2
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["video_id"], "video-abc123");
    assert_eq!(result["model"], "sora-2");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["seconds"], "4");
    assert_eq!(result["size"], "1280x720");
    assert_eq!(result["mime_type"], "video/mp4");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(result["video_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, b"video-bytes");
    assert_eq!(result["provenance"]["source"], "openai.videos");
    assert!(result["provenance"]["derived"].as_bool().unwrap());
}

#[fcp_async_core::runtime::test]
async fn videos_generate_rejects_unsupported_duration() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.videos"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.videos.generate",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.videos.generate",
            "input": {
                "prompt": "A cat",
                "duration_seconds": 6
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("duration_seconds"),
                "error should mention duration_seconds: {message}"
            );
        }
        other => panic!("Expected InvalidRequest for unsupported duration, got: {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn videos_generate_requires_correct_capability() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.images"]).await;
    let token = generate_valid_token(&signing_key, "openai.images.generate");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.videos.generate",
            "input": { "prompt": "A cat", "poll_interval_ms": 1, "max_poll_attempts": 1 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Audio Transcription Tests
// ============================================================================

/// Happy path: transcribe audio via Whisper.
#[fcp_async_core::runtime::test]
async fn transcribe_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("openai.audio.transcribe.happy_path");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .and(header("Authorization", "Bearer test-api-key-xyz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"text": "Hello, this is a test transcription."})),
        )
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.transcribe"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.transcribe");

    // Create small fake audio data and base64 encode it
    let fake_audio = vec![0xFF, 0xFB, 0x90, 0x00]; // fake MP3 header bytes
    let audio_b64 = base64::engine::general_purpose::STANDARD.encode(&fake_audio);

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.transcribe",
            "input": {
                "audio_b64": audio_b64,
                "filename": "test.mp3"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["text"], "Hello, this is a test transcription.");
    assert_eq!(result["provenance"]["source"], "openai.audio.transcribe");
    assert!(
        result["taint"]
            .as_array()
            .unwrap()
            .contains(&json!("external_input"))
    );
}

/// Transcription with language parameter.
#[fcp_async_core::runtime::test]
async fn transcribe_with_language() {
    let _ctx = AsyncTestContext::for_scenario("openai.audio.transcribe.language");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/transcriptions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"text": "Bonjour le monde."})),
        )
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.transcribe"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.transcribe");

    let audio_b64 = base64::engine::general_purpose::STANDARD.encode([0xFF, 0xFB, 0x90]);

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.transcribe",
            "input": {
                "audio_b64": audio_b64,
                "filename": "french.mp3",
                "language": "fr"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["text"], "Bonjour le monde.");
}

/// Missing `audio_b64` field.
#[fcp_async_core::runtime::test]
async fn transcribe_missing_audio() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.transcribe"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.transcribe");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.transcribe",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("audio_b64"),
        "error should mention audio_b64: {message}"
    );
}

/// Empty `audio_b64` field.
#[fcp_async_core::runtime::test]
async fn transcribe_empty_audio() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.transcribe"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.transcribe");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.transcribe",
            "input": { "audio_b64": "" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Invalid base64 audio data.
#[fcp_async_core::runtime::test]
async fn transcribe_invalid_base64() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.transcribe"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.transcribe");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.transcribe",
            "input": { "audio_b64": "not-valid-base64!!!" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("base64"),
        "error should mention base64: {message}"
    );
}

/// Transcription requires correct capability.
#[fcp_async_core::runtime::test]
async fn transcribe_requires_correct_capability() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let audio_b64 = base64::engine::general_purpose::STANDARD.encode([0xFF, 0xFB]);

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.transcribe",
            "input": { "audio_b64": audio_b64 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Realtime transcription uses a supervised WebSocket session and returns completed events.
#[fcp_async_core::runtime::test]
async fn realtime_transcribe_loopback_websocket_session() {
    let _ctx = AsyncTestContext::for_scenario("openai.realtime.transcribe.loopback");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );
    let expected_audio = base64::engine::general_purpose::STANDARD.encode(b"pcm16-audio");

    let ws_task = fcp_async_core::task::spawn({
        let expected_audio = expected_audio.clone();
        async move {
            let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
            let (mut ws, headers) = accept_openai_test_websocket(tcp_stream).await;
            assert!(
                headers.starts_with("GET /v1/realtime?intent=transcription HTTP/1.1"),
                "unexpected realtime websocket request: {headers}"
            );
            assert!(
                headers.contains("Authorization: Bearer test-api-key-xyz"),
                "missing authorization header: {headers}"
            );
            assert!(
                headers.contains("OpenAI-Beta: realtime=v1"),
                "missing realtime beta header: {headers}"
            );

            let update = recv_text_frame(&mut ws, "receive realtime session update")
                .await
                .expect("session update frame");
            let update: serde_json::Value =
                serde_json::from_str(&update).expect("session update json");
            assert_eq!(update["type"], "transcription_session.update");
            assert_eq!(update["input_audio_format"], "pcm16");
            assert_eq!(
                update["input_audio_transcription"]["model"],
                "gpt-4o-transcribe"
            );
            assert_eq!(update["input_audio_transcription"]["language"], "en");
            assert_eq!(
                update["input_audio_transcription"]["prompt"],
                "expect FCP names"
            );
            assert_eq!(update["turn_detection"]["type"], "server_vad");
            assert_eq!(update["turn_detection"]["threshold"], 0.45);
            assert_eq!(update["turn_detection"]["silence_duration_ms"], 900);
            assert_eq!(
                update["include"],
                json!(["item.input_audio_transcription.logprobs"])
            );

            send_json_frame(
                &mut ws,
                json!({
                    "type": "session.updated",
                    "session": {
                        "id": "sess_loopback",
                        "type": "transcription"
                    }
                }),
                "send session.updated",
            )
            .await;

            let append = recv_text_frame(&mut ws, "receive audio append")
                .await
                .expect("audio append frame");
            let append: serde_json::Value = serde_json::from_str(&append).expect("append json");
            assert_eq!(append["type"], "input_audio_buffer.append");
            assert_eq!(append["audio"], expected_audio);

            let commit = recv_text_frame(&mut ws, "receive audio commit")
                .await
                .expect("audio commit frame");
            let commit: serde_json::Value = serde_json::from_str(&commit).expect("commit json");
            assert_eq!(commit["type"], "input_audio_buffer.commit");

            send_json_frame(
                &mut ws,
                json!({
                    "type": "input_audio_buffer.committed",
                    "event_id": "event_commit",
                    "item_id": "item_1",
                    "previous_item_id": null
                }),
                "send audio committed",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "type": "conversation.item.input_audio_transcription.delta",
                    "event_id": "event_delta_1",
                    "item_id": "item_1",
                    "content_index": 0,
                    "delta": "Hello"
                }),
                "send transcript delta",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "type": "conversation.item.input_audio_transcription.completed",
                    "event_id": "event_done",
                    "item_id": "item_1",
                    "content_index": 0,
                    "transcript": "Hello from realtime"
                }),
                "send transcript completed",
            )
            .await;
            close_test_websocket(&mut ws).await;
        }
    });

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &base_url).await;
    let signing_key = setup_handshake(&mut connector, &["openai.realtime.transcribe"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.realtime.transcribe",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.realtime.transcribe",
            "input": {
                "audio_b64": expected_audio,
                "language": "en",
                "prompt": "expect FCP names",
                "vad_threshold": 0.45,
                "silence_duration_ms": 900,
                "include_logprobs": true,
                "timeout_ms": 2_000,
                "connect_timeout_ms": 1_000
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(
        result["session_id"]
            .as_str()
            .unwrap()
            .starts_with("fcp-rt-")
    );
    assert_eq!(result["provider_session_id"], "sess_loopback");
    assert_eq!(result["model"], "gpt-4o-transcribe");
    assert_eq!(result["audio_format"], "pcm16");
    assert_eq!(result["text"], "Hello from realtime");
    assert_eq!(result["transcripts"].as_array().unwrap().len(), 1);
    assert_eq!(result["partials"].as_array().unwrap().len(), 1);
    assert_eq!(result["audio_commits"].as_array().unwrap().len(), 1);
    assert_eq!(result["stats"]["reconnect_attempts"], 0);
    assert_eq!(result["provenance"]["source"], "openai.realtime.transcribe");

    ws_task.await.expect("websocket task");
}

/// Realtime transcription validates audio format before opening a socket.
#[fcp_async_core::runtime::test]
async fn realtime_transcribe_rejects_invalid_audio_format() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.realtime.transcribe"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.realtime.transcribe",
        connector.instance_id(),
    );
    let audio_b64 = base64::engine::general_purpose::STANDARD.encode(b"audio");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.realtime.transcribe",
            "input": {
                "audio_b64": audio_b64,
                "audio_format": "flac"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("audio_format"),
        "error should mention audio_format: {message}"
    );
}

/// Realtime transcription requires its own streaming capability.
#[fcp_async_core::runtime::test]
async fn realtime_transcribe_requires_correct_capability() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.transcribe"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.audio.transcribe",
        connector.instance_id(),
    );
    let audio_b64 = base64::engine::general_purpose::STANDARD.encode(b"audio");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.realtime.transcribe",
            "input": { "audio_b64": audio_b64 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Provider errors before readiness fail the supervised realtime session.
#[fcp_async_core::runtime::test]
async fn realtime_transcribe_provider_error_before_ready() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );

    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let (mut ws, _) = accept_openai_test_websocket(tcp_stream).await;
        let _ = recv_text_frame(&mut ws, "receive session update").await;
        send_json_frame(
            &mut ws,
            json!({
                "type": "error",
                "error": {
                    "message": "invalid realtime key",
                    "code": "invalid_api_key"
                }
            }),
            "send provider error",
        )
        .await;
        close_test_websocket(&mut ws).await;
    });

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &base_url).await;
    let signing_key = setup_handshake(&mut connector, &["openai.realtime.transcribe"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.realtime.transcribe",
        connector.instance_id(),
    );
    let audio_b64 = base64::engine::general_purpose::STANDARD.encode(b"audio");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.realtime.transcribe",
            "input": {
                "audio_b64": audio_b64,
                "timeout_ms": 2_000,
                "connect_timeout_ms": 1_000
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("invalid realtime key"),
        "error should include provider detail: {message}"
    );
    ws_task.await.expect("websocket task");
}

/// Realtime voice waits for session readiness, drains queued audio, and returns output events.
#[fcp_async_core::runtime::test]
async fn realtime_voice_loopback_websocket_session() {
    let _ctx = AsyncTestContext::for_scenario("openai.realtime.voice.loopback");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );
    let input_audio = base64::engine::general_purpose::STANDARD.encode(b"voice-in");
    let output_audio = base64::engine::general_purpose::STANDARD.encode(b"assistant-audio");

    let ws_task = fcp_async_core::task::spawn({
        let input_audio = input_audio.clone();
        let output_audio = output_audio.clone();
        async move {
            let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
            let (mut ws, headers) = accept_openai_test_websocket(tcp_stream).await;
            assert!(
                headers.starts_with("GET /v1/realtime?model=gpt-realtime HTTP/1.1"),
                "unexpected realtime voice websocket request: {headers}"
            );
            assert!(
                headers.contains("Authorization: Bearer test-api-key-xyz"),
                "missing authorization header: {headers}"
            );
            assert!(
                headers.contains("OpenAI-Beta: realtime=v1"),
                "missing realtime beta header: {headers}"
            );

            let update = recv_text_frame(&mut ws, "receive realtime voice session update")
                .await
                .expect("session update frame");
            let update: serde_json::Value =
                serde_json::from_str(&update).expect("session update json");
            assert_eq!(update["type"], "session.update");
            assert_eq!(update["session"]["type"], "realtime");
            assert_eq!(update["session"]["model"], "gpt-realtime");
            assert_eq!(update["session"]["instructions"], "Be concise.");
            assert_eq!(update["session"]["audio"]["output"]["voice"], "marin");
            assert_eq!(
                update["session"]["audio"]["input"]["format"],
                json!({ "type": "audio/pcm", "rate": 24_000 })
            );
            assert_eq!(
                update["session"]["audio"]["output"]["format"],
                json!({ "type": "audio/pcm", "rate": 24_000 })
            );
            assert!(update["session"]["audio"]["input"]["turn_detection"].is_null());

            send_json_frame(
                &mut ws,
                json!({
                    "type": "session.updated",
                    "session": {
                        "id": "sess_voice",
                        "type": "realtime"
                    }
                }),
                "send session.updated",
            )
            .await;

            let append = recv_text_frame(&mut ws, "receive voice audio append")
                .await
                .expect("audio append frame");
            let append: serde_json::Value = serde_json::from_str(&append).expect("append json");
            assert_eq!(append["type"], "input_audio_buffer.append");
            assert_eq!(append["audio"], input_audio);

            let commit = recv_text_frame(&mut ws, "receive voice audio commit")
                .await
                .expect("audio commit frame");
            let commit: serde_json::Value = serde_json::from_str(&commit).expect("commit json");
            assert_eq!(commit["type"], "input_audio_buffer.commit");

            let create = recv_text_frame(&mut ws, "receive response create")
                .await
                .expect("response create frame");
            let create: serde_json::Value = serde_json::from_str(&create).expect("create json");
            assert_eq!(create["type"], "response.create");

            send_json_frame(
                &mut ws,
                json!({
                    "type": "input_audio_buffer.committed",
                    "event_id": "event_commit",
                    "item_id": "item_1"
                }),
                "send audio committed",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "type": "response.output_audio.delta",
                    "event_id": "event_audio",
                    "item_id": "assistant_1",
                    "delta": output_audio
                }),
                "send assistant audio",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "type": "response.output_audio_transcript.delta",
                    "event_id": "event_transcript_delta",
                    "item_id": "assistant_1",
                    "delta": "Hello"
                }),
                "send assistant transcript delta",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "type": "response.output_audio_transcript.done",
                    "event_id": "event_transcript_done",
                    "item_id": "assistant_1",
                    "transcript": "Hello from realtime voice"
                }),
                "send assistant transcript done",
            )
            .await;
            send_json_frame(
                &mut ws,
                json!({
                    "type": "response.done",
                    "response": {
                        "id": "resp_voice",
                        "status": "completed"
                    }
                }),
                "send response done",
            )
            .await;
            close_test_websocket(&mut ws).await;
        }
    });

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &base_url).await;
    let signing_key = setup_handshake(&mut connector, &["openai.realtime.voice"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.realtime.voice",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.realtime.voice",
            "input": {
                "audio_b64": input_audio,
                "voice": "marin",
                "instructions": "Be concise.",
                "timeout_ms": 2_000,
                "connect_timeout_ms": 1_000
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert!(
        result["session_id"]
            .as_str()
            .unwrap()
            .starts_with("fcp-rtv-")
    );
    assert_eq!(result["provider_session_id"], "sess_voice");
    assert_eq!(result["model"], "gpt-realtime");
    assert_eq!(result["voice"], "marin");
    assert_eq!(result["assistant_transcript"], "Hello from realtime voice");
    assert_eq!(result["audio_chunks_b64"].as_array().unwrap().len(), 1);
    assert_eq!(result["audio_b64"], output_audio);
    assert_eq!(result["stats"]["response_status"], "completed");
    assert_eq!(result["stats"]["reconnect_attempts"], 0);
    assert_eq!(result["provenance"]["source"], "openai.realtime.voice");

    ws_task.await.expect("websocket task");
}

/// Realtime voice rejects malformed provider frames before returning partial output.
#[fcp_async_core::runtime::test]
async fn realtime_voice_malformed_event_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let base_url = format!(
        "http://{}",
        listener.local_addr().expect("listener local addr")
    );

    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let (mut ws, _) = accept_openai_test_websocket(tcp_stream).await;
        let _ = recv_text_frame(&mut ws, "receive session update").await;
        send_json_frame(
            &mut ws,
            json!({
                "event_id": "missing-type"
            }),
            "send malformed realtime event",
        )
        .await;
        close_test_websocket(&mut ws).await;
    });

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &base_url).await;
    let signing_key = setup_handshake(&mut connector, &["openai.realtime.voice"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.realtime.voice",
        connector.instance_id(),
    );
    let audio_b64 = base64::engine::general_purpose::STANDARD.encode(b"audio");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.realtime.voice",
            "input": {
                "audio_b64": audio_b64,
                "timeout_ms": 2_000,
                "connect_timeout_ms": 1_000
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("Malformed realtime voice event"),
        "error should mention malformed frame: {message}"
    );
    ws_task.await.expect("websocket task");
}

/// Browser Realtime sessions mint an ephemeral client secret with redacted auth handling.
#[fcp_async_core::runtime::test]
async fn realtime_browser_session_client_secret_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("openai.realtime.browser_session.client_secret");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/realtime/client_secrets"))
        .and(header("Authorization", "Bearer test-api-key-xyz"))
        .and(body_partial_json(json!({
            "expires_after": {
                "anchor": "created_at",
                "seconds": 120
            },
            "session": {
                "type": "realtime",
                "model": "gpt-realtime",
                "instructions": "Keep replies short.",
                "audio": {
                    "output": {
                        "voice": "cedar"
                    }
                }
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "client_secret": {
                "value": "ek_test_client_secret",
                "expires_at": 1_765_000_000_u64
            },
            "session": {
                "id": "sess_browser",
                "type": "realtime",
                "model": "gpt-realtime"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.realtime.browser_session"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.realtime.browser_session",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.realtime.browser_session",
            "input": {
                "voice": "cedar",
                "instructions": "Keep replies short.",
                "expires_after_seconds": 120,
                "audit_context": "unit-test-browser-session"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["provider"], "openai");
    assert_eq!(result["transport"], "webrtc-sdp");
    assert_eq!(result["client_secret"], "ek_test_client_secret");
    assert_eq!(
        result["offer_url"],
        format!("{}/v1/realtime/calls", mock_server.uri())
    );
    assert_eq!(result["model"], "gpt-realtime");
    assert_eq!(result["voice"], "cedar");
    assert_eq!(result["expires_at"], 1_765_000_000_u64);
    assert_eq!(result["audit_context"], "unit-test-browser-session");
    assert_eq!(result["taint"], json!(["secret_material"]));
}

/// Browser session creation validates voice names before making network calls.
#[fcp_async_core::runtime::test]
async fn realtime_browser_session_rejects_invalid_voice() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.realtime.browser_session"]).await;
    let token = generate_valid_bound_token(
        &signing_key,
        "openai.realtime.browser_session",
        connector.instance_id(),
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.realtime.browser_session",
            "input": { "voice": "nova" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("realtime voice"),
        "error should mention realtime voice validation: {message}"
    );
}

// ============================================================================
// Audio TTS Tests
// ============================================================================

/// Happy path: text-to-speech.
#[fcp_async_core::runtime::test]
async fn tts_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("openai.audio.tts.happy_path");

    let mock_server = MockServer::start().await;
    // TTS returns raw audio bytes (not JSON)
    let fake_audio_bytes: Vec<u8> = vec![0xFF, 0xFB, 0x90, 0x00, 0x01, 0x02];
    Mock::given(method("POST"))
        .and(path("/v1/audio/speech"))
        .and(header("Authorization", "Bearer test-api-key-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fake_audio_bytes.clone()))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.tts"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.tts");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.tts",
            "input": { "input": "Hello, world!" },
            "capability_token": token
        }))
        .await
        .unwrap();

    // Verify output structure
    assert!(result.get("audio_b64").is_some());
    let audio_b64 = result["audio_b64"].as_str().unwrap();
    assert!(!audio_b64.is_empty());

    // Verify the base64 decodes to our fake audio
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(audio_b64)
        .unwrap();
    assert_eq!(decoded, fake_audio_bytes);

    assert_eq!(result["format"], "mp3");
    assert_eq!(result["mime_type"], "audio/mpeg");
    assert_eq!(result["input_chars"], 13); // "Hello, world!".len()
    assert_eq!(result["provenance"]["source"], "openai.audio.tts");
    assert!(
        result["taint"]
            .as_array()
            .unwrap()
            .contains(&json!("ai_generated"))
    );
}

/// TTS with all options specified.
#[fcp_async_core::runtime::test]
async fn tts_with_options() {
    let _ctx = AsyncTestContext::for_scenario("openai.audio.tts.options");

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/audio/speech"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0x00, 0x01]))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.tts"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.tts");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.tts",
            "input": {
                "input": "Test speech",
                "model": "tts-1-hd",
                "voice": "nova",
                "response_format": "opus",
                "speed": 1.5
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["format"], "opus");
    assert_eq!(result["mime_type"], "audio/opus");
}

/// TTS missing input text.
#[fcp_async_core::runtime::test]
async fn tts_missing_input() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.tts"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.tts");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.tts",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("input"),
        "error should mention input: {message}"
    );
}

/// TTS empty input text.
#[fcp_async_core::runtime::test]
async fn tts_empty_input() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.tts"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.tts");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.tts",
            "input": { "input": "" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// TTS input exceeding 4096 chars.
#[fcp_async_core::runtime::test]
async fn tts_input_too_long() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.tts"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.tts");

    let long_text = "a".repeat(4097);
    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.tts",
            "input": { "input": long_text },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("4096"),
        "error should mention limit: {message}"
    );
}

/// TTS unknown voice.
#[fcp_async_core::runtime::test]
async fn tts_unknown_voice() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.tts"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.tts");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.tts",
            "input": { "input": "Test", "voice": "nonexistent" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("voice"),
        "error should mention voice: {message}"
    );
}

/// TTS invalid speed.
#[fcp_async_core::runtime::test]
async fn tts_invalid_speed() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.audio.tts"]).await;
    let token = generate_valid_token(&signing_key, "openai.audio.tts");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.tts",
            "input": { "input": "Test", "speed": 5.0 },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("speed") || message.contains("Speed"),
        "error should mention speed: {message}"
    );
}

/// TTS requires correct capability.
#[fcp_async_core::runtime::test]
async fn tts_requires_correct_capability() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.audio.tts",
            "input": { "input": "Hello" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Fine-tuning tests
// ============================================================================

/// Create fine-tuning job: happy path.
#[fcp_async_core::runtime::test]
async fn finetune_create_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/fine_tuning/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "ftjob-abc123",
            "object": "fine_tuning.job",
            "model": "gpt-4o-mini-2024-07-18",
            "status": "validating_files",
            "training_file": "file-train123",
            "validation_file": null,
            "fine_tuned_model": null,
            "created_at": 1_709_900_000,
            "finished_at": null,
            "hyperparameters": { "n_epochs": "auto" },
            "trained_tokens": null,
            "error": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.create",
            "input": {
                "training_file": "file-train123",
                "model": "gpt-4o-mini-2024-07-18"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["id"], "ftjob-abc123");
    assert_eq!(result["status"], "validating_files");
    assert_eq!(result["training_file"], "file-train123");
    assert_eq!(result["provenance"]["source"], "openai.finetune.create");
}

/// Create fine-tuning job with suffix and hyperparameters.
#[fcp_async_core::runtime::test]
async fn finetune_create_with_options() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/fine_tuning/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "ftjob-def456",
            "object": "fine_tuning.job",
            "model": "gpt-3.5-turbo-0125",
            "status": "validating_files",
            "training_file": "file-train456",
            "validation_file": "file-val789",
            "fine_tuned_model": null,
            "created_at": 1_709_900_100,
            "finished_at": null,
            "hyperparameters": { "n_epochs": 3 },
            "trained_tokens": null,
            "error": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.create",
            "input": {
                "training_file": "file-train456",
                "model": "gpt-3.5-turbo-0125",
                "validation_file": "file-val789",
                "suffix": "my-custom",
                "n_epochs": 3
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["id"], "ftjob-def456");
    assert_eq!(result["model"], "gpt-3.5-turbo-0125");
}

/// Create fine-tuning job: missing `training_file`.
#[fcp_async_core::runtime::test]
async fn finetune_create_missing_training_file() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.create",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("training_file"),
        "error should mention training_file: {message}"
    );
}

/// Create fine-tuning job: empty `training_file`.
#[fcp_async_core::runtime::test]
async fn finetune_create_empty_training_file() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.create",
            "input": { "training_file": "" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Create fine-tuning job: suffix too long.
#[fcp_async_core::runtime::test]
async fn finetune_create_suffix_too_long() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.create",
            "input": {
                "training_file": "file-abc",
                "suffix": "this-suffix-is-way-too-long"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("Suffix") || message.contains("suffix"),
        "error should mention suffix: {message}"
    );
}

/// List fine-tuning jobs: happy path.
#[fcp_async_core::runtime::test]
async fn finetune_list_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/fine_tuning/jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "ftjob-abc123",
                    "object": "fine_tuning.job",
                    "model": "gpt-4o-mini-2024-07-18",
                    "status": "succeeded",
                    "training_file": "file-train123",
                    "validation_file": null,
                    "fine_tuned_model": "ft:gpt-4o-mini-2024-07-18:org::abc123",
                    "created_at": 1_709_900_000,
                    "finished_at": 1_709_903_600,
                    "hyperparameters": { "n_epochs": 3 },
                    "trained_tokens": 50000,
                    "error": null
                }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.list"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.list");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.list",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    let data = result["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["id"], "ftjob-abc123");
    assert_eq!(data[0]["status"], "succeeded");
    assert!(!result["has_more"].as_bool().unwrap());
}

/// Get fine-tuning job: happy path.
#[fcp_async_core::runtime::test]
async fn finetune_get_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/fine_tuning/jobs/ftjob-abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "ftjob-abc123",
            "object": "fine_tuning.job",
            "model": "gpt-4o-mini-2024-07-18",
            "status": "succeeded",
            "training_file": "file-train123",
            "validation_file": null,
            "fine_tuned_model": "ft:gpt-4o-mini-2024-07-18:org::abc123",
            "created_at": 1_709_900_000,
            "finished_at": 1_709_903_600,
            "hyperparameters": { "n_epochs": 3 },
            "trained_tokens": 50000,
            "error": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.get",
            "input": { "job_id": "ftjob-abc123" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["id"], "ftjob-abc123");
    assert_eq!(result["status"], "succeeded");
    assert_eq!(
        result["fine_tuned_model"],
        "ft:gpt-4o-mini-2024-07-18:org::abc123"
    );
    assert_eq!(result["trained_tokens"], 50000);
    assert_eq!(result["provenance"]["source"], "openai.finetune.get");
}

/// Get fine-tuning job: missing `job_id`.
#[fcp_async_core::runtime::test]
async fn finetune_get_missing_job_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.get",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    let message = format!("{:?}", result.unwrap_err());
    assert!(
        message.contains("job_id"),
        "error should mention job_id: {message}"
    );
}

/// Get fine-tuning job: empty `job_id`.
#[fcp_async_core::runtime::test]
async fn finetune_get_empty_job_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.get",
            "input": { "job_id": "" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Cancel fine-tuning job: happy path.
#[fcp_async_core::runtime::test]
async fn finetune_cancel_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/fine_tuning/jobs/ftjob-abc123/cancel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "ftjob-abc123",
            "object": "fine_tuning.job",
            "model": "gpt-4o-mini-2024-07-18",
            "status": "cancelled",
            "training_file": "file-train123",
            "validation_file": null,
            "fine_tuned_model": null,
            "created_at": 1_709_900_000,
            "finished_at": 1_709_901_000,
            "hyperparameters": { "n_epochs": "auto" },
            "trained_tokens": null,
            "error": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.cancel"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.cancel");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.cancel",
            "input": { "job_id": "ftjob-abc123" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["id"], "ftjob-abc123");
    assert_eq!(result["status"], "cancelled");
    assert_eq!(result["provenance"]["source"], "openai.finetune.cancel");
}

/// Cancel fine-tuning job: missing `job_id`.
#[fcp_async_core::runtime::test]
async fn finetune_cancel_missing_job_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.cancel"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.cancel");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.cancel",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// List fine-tuning events: happy path.
#[fcp_async_core::runtime::test]
async fn finetune_events_happy_path() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/fine_tuning/jobs/ftjob-abc123/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "fte-event1",
                    "object": "fine_tuning.job.event",
                    "created_at": 1_709_900_100,
                    "level": "info",
                    "message": "Validating training file"
                },
                {
                    "id": "fte-event2",
                    "object": "fine_tuning.job.event",
                    "created_at": 1_709_900_200,
                    "level": "info",
                    "message": "Training started"
                }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.events"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.events");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.events",
            "input": { "job_id": "ftjob-abc123" },
            "capability_token": token
        }))
        .await
        .unwrap();

    let events = result["data"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["level"], "info");
    assert_eq!(events[0]["message"], "Validating training file");
    assert!(!result["has_more"].as_bool().unwrap());
    assert_eq!(result["provenance"]["source"], "openai.finetune.events");
}

/// List fine-tuning events: missing `job_id`.
#[fcp_async_core::runtime::test]
async fn finetune_events_missing_job_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.finetune.events"]).await;
    let token = generate_valid_token(&signing_key, "openai.finetune.events");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.events",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Fine-tuning requires correct capability.
#[fcp_async_core::runtime::test]
async fn finetune_requires_correct_capability() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.finetune.create",
            "input": { "training_file": "file-abc123" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Assistants API tests
// ============================================================================

/// Happy path: create an assistant.
#[fcp_async_core::runtime::test]
async fn assistants_create_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/assistants",
        json!({
            "id": "asst_abc123",
            "object": "assistant",
            "created_at": 1_709_900_000,
            "model": "gpt-4o",
            "name": "Math Tutor",
            "instructions": "You are a math tutor.",
            "tools": [],
            "metadata": null
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.assistants.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.assistants.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.create",
            "input": {
                "model": "gpt-4o",
                "name": "Math Tutor",
                "instructions": "You are a math tutor."
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "asst_abc123");
    assert_eq!(result["model"], "gpt-4o");
    assert_eq!(result["name"], "Math Tutor");
    assert_eq!(result["provenance"]["source"], "openai.assistants.create");
}

/// Validation: create assistant missing model.
#[fcp_async_core::runtime::test]
async fn assistants_create_missing_model() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.assistants.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.assistants.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.create",
            "input": { "name": "No Model" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Validation: create assistant with empty model.
#[fcp_async_core::runtime::test]
async fn assistants_create_empty_model() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.assistants.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.assistants.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.create",
            "input": { "model": "" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Happy path: list assistants.
#[fcp_async_core::runtime::test]
async fn assistants_list_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_get(
        "/v1/assistants",
        json!({
            "data": [
                {
                    "id": "asst_001",
                    "object": "assistant",
                    "created_at": 1_709_900_000,
                    "model": "gpt-4o",
                    "name": "Helper",
                    "instructions": null,
                    "tools": [],
                    "metadata": null
                }
            ],
            "has_more": false
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.assistants.list"]).await;
    let token = generate_valid_token(&signing_key, "openai.assistants.list");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.list",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["data"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"][0]["id"], "asst_001");
    assert_eq!(result["has_more"], false);
    assert_eq!(result["provenance"]["source"], "openai.assistants.list");
}

/// Happy path: get an assistant by ID.
#[fcp_async_core::runtime::test]
async fn assistants_get_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_get(
        "/v1/assistants/asst_abc123",
        json!({
            "id": "asst_abc123",
            "object": "assistant",
            "created_at": 1_709_900_000,
            "model": "gpt-4o",
            "name": "Tutor",
            "instructions": "Help students.",
            "tools": [],
            "metadata": null
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.assistants.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.assistants.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.get",
            "input": { "assistant_id": "asst_abc123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "asst_abc123");
    assert_eq!(result["name"], "Tutor");
    assert_eq!(result["provenance"]["source"], "openai.assistants.get");
}

/// Validation: get assistant missing ID.
#[fcp_async_core::runtime::test]
async fn assistants_get_missing_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.assistants.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.assistants.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.get",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Validation: get assistant empty ID.
#[fcp_async_core::runtime::test]
async fn assistants_get_empty_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.assistants.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.assistants.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.get",
            "input": { "assistant_id": "" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Happy path: delete an assistant.
#[fcp_async_core::runtime::test]
async fn assistants_delete_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_json(
        "/v1/assistants/asst_abc123",
        json!({
            "id": "asst_abc123",
            "object": "assistant.deleted",
            "deleted": true
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.assistants.delete"]).await;
    let token = generate_valid_token(&signing_key, "openai.assistants.delete");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.delete",
            "input": { "assistant_id": "asst_abc123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "asst_abc123");
    assert_eq!(result["deleted"], true);
    assert_eq!(result["provenance"]["source"], "openai.assistants.delete");
}

/// Validation: delete assistant missing ID.
#[fcp_async_core::runtime::test]
async fn assistants_delete_missing_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.assistants.delete"]).await;
    let token = generate_valid_token(&signing_key, "openai.assistants.delete");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.delete",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Capability: assistants require correct capability token.
#[fcp_async_core::runtime::test]
async fn assistants_requires_correct_capability() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.chat"]).await;
    let token = generate_valid_token(&signing_key, "openai.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.assistants.create",
            "input": { "model": "gpt-4o" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Threads API tests
// ============================================================================

/// Happy path: create a thread.
#[fcp_async_core::runtime::test]
async fn threads_create_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/threads",
        json!({
            "id": "thread_abc123",
            "object": "thread",
            "created_at": 1_709_900_000,
            "metadata": null
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.create",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "thread_abc123");
    assert_eq!(result["object"], "thread");
    assert_eq!(result["provenance"]["source"], "openai.threads.create");
}

/// Happy path: get a thread by ID.
#[fcp_async_core::runtime::test]
async fn threads_get_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_get(
        "/v1/threads/thread_abc123",
        json!({
            "id": "thread_abc123",
            "object": "thread",
            "created_at": 1_709_900_000,
            "metadata": null
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.get",
            "input": { "thread_id": "thread_abc123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "thread_abc123");
    assert_eq!(result["provenance"]["source"], "openai.threads.get");
}

/// Validation: get thread missing ID.
#[fcp_async_core::runtime::test]
async fn threads_get_missing_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.get",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Validation: get thread empty ID.
#[fcp_async_core::runtime::test]
async fn threads_get_empty_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.get",
            "input": { "thread_id": "" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Thread Messages API tests
// ============================================================================

/// Happy path: create a thread message.
#[fcp_async_core::runtime::test]
async fn threads_messages_create_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/threads/thread_abc123/messages",
        json!({
            "id": "msg_abc123",
            "object": "thread.message",
            "created_at": 1_709_900_000,
            "thread_id": "thread_abc123",
            "role": "user",
            "content": [{"type": "text", "text": {"value": "Hello!", "annotations": []}}],
            "assistant_id": null,
            "run_id": null,
            "metadata": null
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.messages.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.messages.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.messages.create",
            "input": {
                "thread_id": "thread_abc123",
                "role": "user",
                "content": "Hello!"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "msg_abc123");
    assert_eq!(result["thread_id"], "thread_abc123");
    assert_eq!(result["role"], "user");
    assert_eq!(
        result["provenance"]["source"],
        "openai.threads.messages.create"
    );
}

/// Validation: create thread message missing content.
#[fcp_async_core::runtime::test]
async fn threads_messages_create_missing_content() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.messages.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.messages.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.messages.create",
            "input": {
                "thread_id": "thread_abc123",
                "role": "user"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Validation: create thread message empty content.
#[fcp_async_core::runtime::test]
async fn threads_messages_create_empty_content() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.messages.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.messages.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.messages.create",
            "input": {
                "thread_id": "thread_abc123",
                "role": "user",
                "content": ""
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Validation: create thread message missing role.
#[fcp_async_core::runtime::test]
async fn threads_messages_create_missing_role() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.messages.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.messages.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.messages.create",
            "input": {
                "thread_id": "thread_abc123",
                "content": "Hello!"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Happy path: list thread messages.
#[fcp_async_core::runtime::test]
async fn threads_messages_list_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_get(
        "/v1/threads/thread_abc123/messages",
        json!({
            "data": [
                {
                    "id": "msg_001",
                    "object": "thread.message",
                    "created_at": 1_709_900_000,
                    "thread_id": "thread_abc123",
                    "role": "user",
                    "content": [{"type": "text", "text": {"value": "Hi", "annotations": []}}],
                    "assistant_id": null,
                    "run_id": null,
                    "metadata": null
                }
            ],
            "has_more": false
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.messages.list"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.messages.list");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.messages.list",
            "input": { "thread_id": "thread_abc123" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["data"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"][0]["id"], "msg_001");
    assert_eq!(result["has_more"], false);
    assert_eq!(
        result["provenance"]["source"],
        "openai.threads.messages.list"
    );
}

/// Validation: list thread messages missing `thread_id`.
#[fcp_async_core::runtime::test]
async fn threads_messages_list_missing_thread_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.messages.list"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.messages.list");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.messages.list",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Runs API tests
// ============================================================================

/// Happy path: create a run.
#[fcp_async_core::runtime::test]
async fn runs_create_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/threads/thread_abc123/runs",
        json!({
            "id": "run_abc123",
            "object": "thread.run",
            "created_at": 1_709_900_000,
            "thread_id": "thread_abc123",
            "assistant_id": "asst_abc123",
            "status": "queued",
            "model": "gpt-4o",
            "instructions": null,
            "tools": [],
            "started_at": null,
            "completed_at": null,
            "failed_at": null,
            "cancelled_at": null,
            "last_error": null,
            "usage": null,
            "metadata": null
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.runs.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.runs.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.runs.create",
            "input": {
                "thread_id": "thread_abc123",
                "assistant_id": "asst_abc123"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "run_abc123");
    assert_eq!(result["thread_id"], "thread_abc123");
    assert_eq!(result["assistant_id"], "asst_abc123");
    assert_eq!(result["status"], "queued");
    assert_eq!(result["provenance"]["source"], "openai.threads.runs.create");
}

/// Validation: create run missing `thread_id`.
#[fcp_async_core::runtime::test]
async fn runs_create_missing_thread_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.runs.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.runs.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.runs.create",
            "input": { "assistant_id": "asst_abc123" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Validation: create run missing `assistant_id`.
#[fcp_async_core::runtime::test]
async fn runs_create_missing_assistant_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.runs.create"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.runs.create");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.runs.create",
            "input": { "thread_id": "thread_abc123" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Happy path: get a run by ID.
#[fcp_async_core::runtime::test]
async fn runs_get_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_get(
        "/v1/threads/thread_abc123/runs/run_abc123",
        json!({
            "id": "run_abc123",
            "object": "thread.run",
            "created_at": 1_709_900_000,
            "thread_id": "thread_abc123",
            "assistant_id": "asst_abc123",
            "status": "completed",
            "model": "gpt-4o",
            "instructions": null,
            "tools": [],
            "started_at": 1_709_900_100,
            "completed_at": 1_709_900_200,
            "failed_at": null,
            "cancelled_at": null,
            "last_error": null,
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            },
            "metadata": null
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.runs.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.runs.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.runs.get",
            "input": {
                "thread_id": "thread_abc123",
                "run_id": "run_abc123"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "run_abc123");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["usage"]["total_tokens"], 150);
    assert_eq!(result["provenance"]["source"], "openai.threads.runs.get");
}

/// Validation: get run missing `run_id`.
#[fcp_async_core::runtime::test]
async fn runs_get_missing_run_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.runs.get"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.runs.get");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.runs.get",
            "input": { "thread_id": "thread_abc123" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Happy path: cancel a run.
#[fcp_async_core::runtime::test]
async fn runs_cancel_happy_path() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/threads/thread_abc123/runs/run_abc123/cancel",
        json!({
            "id": "run_abc123",
            "object": "thread.run",
            "created_at": 1_709_900_000,
            "thread_id": "thread_abc123",
            "assistant_id": "asst_abc123",
            "status": "cancelling",
            "model": "gpt-4o",
            "instructions": null,
            "tools": [],
            "started_at": 1_709_900_100,
            "completed_at": null,
            "failed_at": null,
            "cancelled_at": null,
            "last_error": null,
            "usage": null,
            "metadata": null
        }),
    )
    .await;

    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.runs.cancel"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.runs.cancel");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.runs.cancel",
            "input": {
                "thread_id": "thread_abc123",
                "run_id": "run_abc123"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["id"], "run_abc123");
    assert_eq!(result["status"], "cancelling");
    assert_eq!(result["provenance"]["source"], "openai.threads.runs.cancel");
}

/// Validation: cancel run missing `thread_id`.
#[fcp_async_core::runtime::test]
async fn runs_cancel_missing_thread_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.runs.cancel"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.runs.cancel");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.runs.cancel",
            "input": { "run_id": "run_abc123" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

/// Validation: cancel run missing `run_id`.
#[fcp_async_core::runtime::test]
async fn runs_cancel_missing_run_id() {
    let mock = MockApiServer::start().await;
    let mut connector = OpenAIConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["openai.threads.runs.cancel"]).await;
    let token = generate_valid_token(&signing_key, "openai.threads.runs.cancel");

    let result = connector
        .handle_invoke(json!({
            "operation": "openai.threads.runs.cancel",
            "input": { "thread_id": "thread_abc123" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}
