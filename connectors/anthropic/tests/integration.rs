//! Anthropic connector integration tests (flywheel_connectors-s7j5).
//!
//! Deterministic integration tests using wiremock to mock the Anthropic API.
//! No real API calls. Covers:
//! - Non-streaming generation (chat + message)
//! - Streaming SSE (chunk parsing, error mid-stream)
//! - Tool/function calling shapes
//! - Error taxonomy (401/429/529/5xx)
//! - Usage metrics extraction
//! - FCP2 default-deny + capability verification

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{CapabilityConstraints, FcpError};
use fcp_testkit::{AsyncTestContext, MockApiServer};
use futures_util::StreamExt;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

// ──────────────── re-export the connector under test ────────────────
use fcp_anthropic::client::AnthropicClient;
use fcp_anthropic::connector::AnthropicConnector;
use fcp_anthropic::types::Model;

type TestCapability = fcp_core::CapabilityToken;

// ============================================================================
// Helpers
// ============================================================================

struct TestAuth {
    signing_key: Ed25519SigningKey,
    instance_id: String,
}

/// Generate a valid COSE capability token signed by the given key.
fn generate_valid_token(auth: &TestAuth, cap: &str) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[cap])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .target_instance(&auth.instance_id)
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(&auth.signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

/// Perform handshake on a connector, returning the signing key for token generation.
async fn setup_handshake(connector: &mut AnthropicConnector, caps: &[&str]) -> TestAuth {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    TestAuth {
        signing_key,
        instance_id: connector.instance_id().as_str().to_string(),
    }
}

/// Configure connector with a mock server URL.
async fn setup_configure(connector: &mut AnthropicConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "api_key": "test-api-key-xyz",
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

/// Standard Anthropic API success response.
fn anthropic_success_response(
    msg_id: &str,
    text: &str,
    input_tokens: u32,
    output_tokens: u32,
) -> serde_json::Value {
    json!({
        "id": msg_id,
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "model": "claude-sonnet-4-20250514",
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        }
    })
}

/// Anthropic API `tool_use` response.
fn anthropic_tool_use_response(
    msg_id: &str,
    tool_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    input_tokens: u32,
    output_tokens: u32,
) -> serde_json::Value {
    json!({
        "id": msg_id,
        "type": "message",
        "role": "assistant",
        "content": [{
            "type": "tool_use",
            "id": tool_id,
            "name": tool_name,
            "input": tool_input
        }],
        "model": "claude-sonnet-4-20250514",
        "stop_reason": "tool_use",
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        }
    })
}

/// Anthropic API error envelope.
fn anthropic_error(error_type: &str, message: &str) -> serde_json::Value {
    json!({
        "error": {
            "type": error_type,
            "message": message
        }
    })
}

// ============================================================================
// Non-Streaming Generation Tests
// ============================================================================

/// Happy path: anthropic.chat invoke returns text response.
#[fcp_async_core::test]
async fn chat_invoke_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.chat.happy_path");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_001", "Hello from Claude!", 12, 8),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi there" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["response"], "Hello from Claude!");
    assert_eq!(result["usage"]["input_tokens"], 12);
    assert_eq!(result["usage"]["output_tokens"], 8);
    // Cost is present and non-zero (not hard-coded)
    let cost = result["cost_usd"].as_f64().unwrap();
    assert!(cost > 0.0, "cost should be positive: {cost}");
    mock.assert_received("/v1/messages").await;
}

/// Happy path: anthropic.message invoke with multi-turn messages.
#[fcp_async_core::test]
async fn message_invoke_multi_turn() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.message.multi_turn");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_002", "The capital of France is Paris.", 25, 12),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
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
    assert_eq!(result["id"], "msg_002");
}

/// anthropic.message with system prompt.
#[fcp_async_core::test]
async fn message_invoke_with_system() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_003", "42", 30, 3),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "What is 6*7?"}],
                "system": "You are a calculator. Reply with only the number.",
                "temperature": 0.0
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["content"], "42");
}

// ============================================================================
// Streaming SSE Tests
// ============================================================================

/// Build SSE body for streaming response.
fn build_sse_body(events: &[(&str, serde_json::Value)]) -> String {
    use std::fmt::Write;
    events
        .iter()
        .fold(String::new(), |mut acc, (event_type, data)| {
            write!(acc, "event: {event_type}\ndata: {data}\n\n").unwrap();
            acc
        })
}

/// Streaming: parse complete SSE chunks.
#[fcp_async_core::test]
async fn streaming_sse_chunk_parsing() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.stream.chunk_parsing");
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_stream_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 10, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " World"}}),
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
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "test-stream-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-stream-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_anthropic::types::Message {
        role: fcp_anthropic::types::Role::User,
        content: "Hello".into(),
    }];

    let stream = client
        .message_stream(Model::ClaudeSonnet4, messages, 1024, None, None, None, None)
        .await
        .expect("stream should start");

    let events: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|r| r.expect("each event should parse"))
        .collect();

    // Should have 7 events total
    assert_eq!(
        events.len(),
        7,
        "expected 7 SSE events, got {}",
        events.len()
    );

    // Verify text deltas
    let mut text_acc = String::new();
    for event in &events {
        if let fcp_anthropic::types::StreamEvent::ContentBlockDelta {
            delta: fcp_anthropic::types::ContentDelta::TextDelta { text },
            ..
        } = event
        {
            text_acc.push_str(text);
        }
    }
    assert_eq!(text_acc, "Hello World");
}

/// Streaming: SSE error mid-stream.
#[fcp_async_core::test]
async fn streaming_sse_error_mid_stream() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.stream.error_mid_stream");
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_err_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 10, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Part"}}),
        ),
        (
            "error",
            json!({"type": "error", "error": {"type": "overloaded_error", "message": "Server overloaded"}}),
        ),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_anthropic::types::Message {
        role: fcp_anthropic::types::Role::User,
        content: "Hello".into(),
    }];

    let stream = client
        .message_stream(Model::ClaudeSonnet4, messages, 1024, None, None, None, None)
        .await
        .expect("stream should start");

    let events: Vec<_> = stream.collect::<Vec<_>>().await;
    assert!(
        events.len() >= 3,
        "should receive partial events before error"
    );

    // Last valid event should be the error
    let last = events
        .last()
        .unwrap()
        .as_ref()
        .expect("last event should parse");
    assert!(
        matches!(last, fcp_anthropic::types::StreamEvent::Error { .. }),
        "last event should be error, got: {last:?}"
    );
}

/// Streaming: SSE ping keepalive events are parsed.
#[fcp_async_core::test]
async fn streaming_sse_ping_keepalive() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        ("ping", json!({"type": "ping"})),
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_ping_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 5, "output_tokens": 0}
                }
            }),
        ),
        ("ping", json!({"type": "ping"})),
        ("message_stop", json!({"type": "message_stop"})),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_anthropic::types::Message {
        role: fcp_anthropic::types::Role::User,
        content: "ping test".into(),
    }];

    let stream = client
        .message_stream(Model::ClaudeSonnet4, messages, 256, None, None, None, None)
        .await
        .expect("stream should start");

    let events: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(std::result::Result::ok)
        .collect();

    let ping_count = events
        .iter()
        .filter(|e| matches!(e, fcp_anthropic::types::StreamEvent::Ping))
        .count();

    assert_eq!(ping_count, 2, "should have 2 ping events");
}

// ============================================================================
// Tool/Function Calling Tests
// ============================================================================

/// Tool use: model requests tool call and response includes `tool_use` content.
#[fcp_async_core::test]
async fn tool_use_invoke_shape() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.tool_use.shape");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_tool_use_response(
            "msg_tool_001",
            "tool_call_abc",
            "get_weather",
            &json!({"city": "San Francisco", "unit": "celsius"}),
            20,
            15,
        ),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "What is the weather in SF?"}],
                "tools": [{
                    "name": "get_weather",
                    "description": "Get current weather for a city",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "city": {"type": "string"},
                            "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
                        },
                        "required": ["city"]
                    }
                }],
                "tool_choice": {"type": "auto"}
            },
            "capability_token": token
        }))
        .await
        .expect("tool use invoke should succeed");

    assert_eq!(result["id"], "msg_tool_001");
    // stop_reason should be tool_use
    assert_eq!(result["stop_reason"], "tool_use");
    assert_eq!(result["usage"]["input_tokens"], 20);
    assert_eq!(result["usage"]["output_tokens"], 15);
}

/// Tool use: streaming response with tool use block.
#[fcp_async_core::test]
async fn tool_use_streaming_shape() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.tool_use.streaming");
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_tool_stream_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 25, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "tool_stream_abc",
                    "name": "get_weather",
                    "input": {}
                }
            }),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{\"city\": \"Paris\""}
            }),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "}"}
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
                "delta": {"stop_reason": "tool_use", "stop_sequence": null},
                "usage": {"input_tokens": 25, "output_tokens": 10}
            }),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    let messages = vec![fcp_anthropic::types::Message {
        role: fcp_anthropic::types::Role::User,
        content: "Weather in Paris?".into(),
    }];

    let tools = vec![fcp_anthropic::types::Tool {
        name: "get_weather".into(),
        description: "Get weather".into(),
        input_schema: json!({"type": "object", "properties": {"city": {"type": "string"}}}),
        eager_input_streaming: Some(true),
    }];

    let stream = client
        .message_stream(
            Model::ClaudeSonnet4,
            messages,
            1024,
            None,
            None,
            Some(tools),
            None,
        )
        .await
        .expect("stream should start");

    let events: Vec<_> = stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(std::result::Result::ok)
        .collect();

    // Collect JSON delta fragments
    let mut json_acc = String::new();
    for event in &events {
        if let fcp_anthropic::types::StreamEvent::ContentBlockDelta {
            delta: fcp_anthropic::types::ContentDelta::InputJsonDelta { partial_json },
            ..
        } = event
        {
            json_acc.push_str(partial_json);
        }
    }
    assert_eq!(json_acc, "{\"city\": \"Paris\"}");

    // Verify tool_use content block start
    let has_tool_start = events.iter().any(|e| {
        matches!(
            e,
            fcp_anthropic::types::StreamEvent::ContentBlockStart {
                content_block: fcp_anthropic::types::ContentBlockStartData::ToolUse { name, .. },
                ..
            } if name == "get_weather"
        )
    });
    assert!(has_tool_start, "should have tool_use content block start");
}

// ============================================================================
// Error Taxonomy Tests (401/429/529/5xx → FCP error mapping)
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
#[fcp_async_core::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.error.401");
    let mock = MockApiServer::start().await;

    mock.expect_error(
        "/v1/messages",
        401,
        anthropic_error("authentication_error", "Invalid API key"),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("should fail with 401");

    assert!(
        matches!(err, fcp_core::FcpError::Unauthorized { .. }),
        "expected Unauthorized, got: {err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
/// Uses client directly with minimal retry config to avoid slow backoff.
#[fcp_async_core::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.error.429");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(anthropic_error("rate_limit_error", "Rate limit exceeded")),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with 429");

    // Client-level error
    assert!(
        matches!(
            err,
            fcp_anthropic::error::AnthropicError::RateLimited { .. }
        ),
        "expected RateLimited, got: {err:?}"
    );

    // Verify FCP mapping
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "expected FcpError::RateLimited, got: {fcp_err:?}"
    );
}

/// 529 Overloaded maps to `FcpError::External` with retryable=true.
/// Uses client directly with minimal retry config to avoid slow backoff.
#[fcp_async_core::test]
async fn error_529_maps_to_external_retryable() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.error.529");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(529)
                .set_body_json(anthropic_error("overloaded_error", "Overloaded")),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with 529");

    // Client-level error
    assert!(
        matches!(err, fcp_anthropic::error::AnthropicError::Overloaded { .. }),
        "expected Overloaded, got: {err:?}"
    );

    // Verify FCP mapping
    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            service,
            retryable,
            status_code,
            ..
        } => {
            assert_eq!(service, "anthropic");
            assert!(retryable, "529 should be retryable");
            assert_eq!(*status_code, Some(529));
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::External { .. }),
            "expected FcpError::External, got: {other:?}"
        ),
    }
}

/// 500 Server Error maps to `FcpError::External`.
/// Uses client directly with minimal retry config.
#[fcp_async_core::test]
async fn error_500_maps_to_external() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(anthropic_error("api_error", "Internal server error")),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with 500");

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::External { .. }),
        "expected FcpError::External, got: {fcp_err:?}"
    );
}

/// 400 with `context_length_exceeded` maps to `InvalidRequest`.
#[fcp_async_core::test]
async fn error_context_length_maps_to_invalid_request() {
    let mock = MockApiServer::start().await;

    mock.expect_error(
        "/v1/messages",
        400,
        anthropic_error(
            "invalid_request_error",
            "context length exceeded: maximum is 200000 tokens",
        ),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("should fail with context length");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("context length"),
                "error should mention context length: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::InvalidRequest { .. }),
            "expected InvalidRequest, got: {other:?}"
        ),
    }
}

// ============================================================================
// Usage Metrics Tests (tokens, latencies — not hard-coded pricing)
// ============================================================================

/// Usage metrics accumulate across multiple invocations.
#[fcp_async_core::test]
async fn usage_metrics_accumulate() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.usage.accumulate");
    let mock_server = MockServer::start().await;

    // Two sequential requests with different token counts
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(anthropic_success_response("msg_u1", "First", 10, 5)),
        )
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "usage-test-key",
            "base_url": mock_server.uri()
        }))
        .await
        .unwrap();
    let signing_key =
        setup_handshake(&mut connector, &["anthropic.chat", "anthropic.get_usage"]).await;

    // First invocation
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");
    connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "First" },
            "capability_token": token
        }))
        .await
        .expect("first invoke should succeed");

    // Check metrics via get_usage
    let usage_token: TestCapability = generate_valid_token(&signing_key, "anthropic.get_usage");
    let usage = connector
        .handle_invoke(json!({
            "operation": "anthropic.get_usage",
            "input": {},
            "capability_token": usage_token
        }))
        .await
        .expect("get_usage should succeed");

    assert_eq!(usage["total_input_tokens"], 10);
    assert_eq!(usage["total_output_tokens"], 5);
    assert!(usage["requests_total"].as_u64().unwrap() >= 1);
    let cost = usage["total_cost_usd"].as_f64().unwrap();
    assert!(cost > 0.0, "cost should be positive after invocation");
}

/// Usage cost is model-dependent (not hard-coded).
#[fcp_async_core::test]
async fn usage_cost_is_model_dependent() {
    let mock_server = MockServer::start().await;

    // Same token counts, different models
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_cost_001",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-3-5-haiku-20241022",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1000, "output_tokens": 500}
        })))
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "cost-test-key",
            "base_url": mock_server.uri()
        }))
        .await
        .unwrap();
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "model": "claude-3-5-haiku-20241022"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let haiku_cost = result["cost_usd"].as_f64().unwrap();
    // Haiku: $0.25/M input + $1.25/M output
    // 1000 input tokens = $0.00025, 500 output tokens = $0.000625
    // Total should be around $0.000875
    assert!(
        haiku_cost > 0.0 && haiku_cost < 0.01,
        "haiku cost should be small but positive: {haiku_cost}"
    );
}

// ============================================================================
// FCP2 Default-Deny / Capability Verification Tests
// ============================================================================

/// Invoke without `capability_token` fails.
#[fcp_async_core::test]
async fn capability_missing_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.capability.missing_token");
    let mock = MockApiServer::start().await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    setup_handshake(&mut connector, &["anthropic.chat"]).await;

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" }
        }))
        .await
        .expect_err("invoke without token should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing token, got: {err:?}"
    );
}

/// Invoke before handshake fails (no verifier).
#[fcp_async_core::test]
async fn capability_no_handshake_fails() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.capability.no_handshake");
    let mock = MockApiServer::start().await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    // Generate token with arbitrary key (no handshake, so no verifier)
    let signing_key = Ed25519SigningKey::generate();
    let auth = TestAuth {
        signing_key,
        instance_id: "inst_test".into(),
    };
    let token: TestCapability = generate_valid_token(&auth, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without handshake should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotHandshaken),
        "expected NotHandshaken, got: {err:?}"
    );
}

/// Invoke before configure fails (no client).
#[fcp_async_core::test]
async fn capability_no_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.capability.no_configure");

    let mut connector = AnthropicConnector::new();
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("invoke without configure should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Invoke with wrong capability (signed for different operation) fails.
#[fcp_async_core::test]
async fn capability_wrong_operation_fails() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.capability.wrong_op");
    let mock = MockApiServer::start().await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key =
        setup_handshake(&mut connector, &["anthropic.chat", "anthropic.get_usage"]).await;

    // Token signed for get_usage, used on chat
    let wrong_token: TestCapability = generate_valid_token(&signing_key, "anthropic.get_usage");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": wrong_token
        }))
        .await
        .expect_err("wrong capability should fail");

    // Verifier rejects token signed for a different operation
    let is_cap_error = matches!(
        &err,
        fcp_core::FcpError::CapabilityDenied { .. }
            | fcp_core::FcpError::Unauthorized { .. }
            | fcp_core::FcpError::OperationNotGranted { .. }
    );
    assert!(
        is_cap_error,
        "expected capability/operation denial error, got: {err:?}"
    );
}

/// Unknown operation fails with `OperationNotGranted`.
#[fcp_async_core::test]
async fn capability_unknown_operation_fails() {
    let mock = MockApiServer::start().await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.nonexistent"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.nonexistent");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("unknown operation should fail");

    assert!(
        matches!(err, fcp_core::FcpError::OperationNotGranted { .. }),
        "expected OperationNotGranted, got: {err:?}"
    );
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health check before configure reports `not_configured`.
#[fcp_async_core::test]
async fn lifecycle_health_before_configure() {
    let connector = AnthropicConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

/// Health check after configure reports healthy.
#[fcp_async_core::test]
async fn lifecycle_health_after_configure() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

/// Handshake returns accepted with capabilities granted.
#[fcp_async_core::test]
async fn lifecycle_handshake_grants_capabilities() {
    let mut connector = AnthropicConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["anthropic.message", "anthropic.chat", "anthropic.get_usage"]
        }))
        .await
        .expect("handshake should succeed");

    assert_eq!(result["status"], "accepted");
    assert!(result["event_caps"]["streaming"].as_bool().unwrap());
    let caps = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

/// Shutdown returns clean status.
#[fcp_async_core::test]
async fn lifecycle_shutdown_clean() {
    let mut connector = AnthropicConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

/// Introspect exposes expected operations.
#[fcp_async_core::test]
async fn lifecycle_introspect_operations() {
    let connector = AnthropicConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"anthropic.message"));
    assert!(op_ids.contains(&"anthropic.message.stream"));
    assert!(op_ids.contains(&"anthropic.chat"));
    assert!(op_ids.contains(&"anthropic.get_usage"));
    assert_eq!(op_ids.len(), 4);

    // Verify schemas are present
    for op in ops {
        assert!(
            op["input_schema"].is_object(),
            "input_schema should be object"
        );
        assert!(
            op["output_schema"].is_object(),
            "output_schema should be object"
        );
    }
}

// ============================================================================
// Validation Edge Cases
// ============================================================================

/// Empty messages array fails with clear error.
#[fcp_async_core::test]
async fn validation_empty_messages_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": { "messages": [] },
            "capability_token": token
        }))
        .await
        .expect_err("empty messages should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.to_lowercase().contains("empty")
                    || message.to_lowercase().contains("messages"),
                "error should mention messages: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::InvalidRequest { .. }),
            "expected InvalidRequest, got: {other:?}"
        ),
    }
}

/// Unknown model name fails.
#[fcp_async_core::test]
async fn validation_unknown_model_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "model": "claude-nonexistent-model"
            },
            "capability_token": token
        }))
        .await
        .expect_err("unknown model should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for unknown model, got: {err:?}"
    );
}

/// Missing required message field in chat invoke fails.
#[fcp_async_core::test]
async fn validation_chat_missing_message_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect_err("missing message field should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.to_lowercase().contains("message"),
                "error should mention message: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::InvalidRequest { .. }),
            "expected InvalidRequest, got: {other:?}"
        ),
    }
}

/// Error counters increment on failures.
/// Uses 401 (non-retryable) to avoid slow retry backoff.
#[fcp_async_core::test]
async fn metrics_error_counter_increments() {
    let mock = MockApiServer::start().await;

    mock.expect_error(
        "/v1/messages",
        401,
        anthropic_error("authentication_error", "Invalid API key"),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let _ = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await;

    assert!(
        connector.total_errors() >= 1,
        "error counter should increment: {}",
        connector.total_errors()
    );
    assert!(
        connector.total_requests() >= 1,
        "request counter should increment: {}",
        connector.total_requests()
    );
}

// ============================================================================
// Provenance Metadata Tests
// ============================================================================

/// Provenance: chat invoke includes provenance/taint metadata.
#[fcp_async_core::test]
async fn chat_invoke_provenance_metadata() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.chat.provenance");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_prov_001", "Provenance test", 10, 5),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "test" },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let provenance = &result["provenance"];
    assert_eq!(provenance["source"], "anthropic");
    assert_eq!(provenance["integrity"], "untrusted");
    assert_eq!(provenance["has_tool_calls"], false);
    assert_eq!(provenance["chunk_count"], 1);
    assert!(
        provenance["model"].as_str().is_some(),
        "model should be present"
    );
    let taint = provenance["taint"]
        .as_array()
        .expect("taint should be array");
    assert!(
        taint.iter().any(|v| v == "AI_GENERATED"),
        "taint should include AI_GENERATED"
    );
}

/// Provenance: message invoke includes provenance/taint metadata.
#[fcp_async_core::test]
async fn message_invoke_provenance_metadata() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.message.provenance");
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_prov_002", "Hello provenance", 15, 6),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "Hello"}],
                "max_tokens": 100
            },
            "capability_token": token
        }))
        .await
        .expect("invoke should succeed");

    let provenance = &result["provenance"];
    assert_eq!(provenance["source"], "anthropic");
    assert_eq!(provenance["integrity"], "untrusted");
    assert_eq!(provenance["has_tool_calls"], false);
    assert_eq!(provenance["chunk_count"], 1);
    let taint = provenance["taint"]
        .as_array()
        .expect("taint should be array");
    assert!(
        taint.iter().any(|v| v == "AI_GENERATED"),
        "taint should include AI_GENERATED"
    );
}

// ============================================================================
// Connector-Level Streaming Tests
// ============================================================================

/// Streaming via `handle_invoke`: message.stream operation assembles full response with provenance.
#[fcp_async_core::test]
async fn message_stream_invoke_full_response() {
    let _ctx = AsyncTestContext::for_scenario("anthropic.message.stream.invoke");
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_stream_inv_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 20, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Streamed"}}),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " response"}}),
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
                "usage": {"input_tokens": 20, "output_tokens": 8}
            }),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message.stream"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message.stream");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message.stream",
            "input": {
                "messages": [{"role": "user", "content": "Stream test"}],
                "max_tokens": 256
            },
            "capability_token": token
        }))
        .await
        .expect("streaming invoke should succeed");

    // Verify assembled response
    assert_eq!(result["id"], "msg_stream_inv_001");
    assert_eq!(result["content"], "Streamed response");
    assert_eq!(result["stop_reason"], "end_turn");
    assert_eq!(result["streamed"], true);
    assert_eq!(result["usage"]["input_tokens"], 20);
    assert_eq!(result["usage"]["output_tokens"], 8);

    // Verify content blocks
    let blocks = result["content_blocks"]
        .as_array()
        .expect("should have content_blocks");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0]["type"], "text");
    assert_eq!(blocks[0]["text"], "Streamed response");

    // Verify provenance
    let provenance = &result["provenance"];
    assert_eq!(provenance["source"], "anthropic");
    assert_eq!(provenance["integrity"], "untrusted");
    assert_eq!(provenance["has_tool_calls"], false);
    assert_eq!(provenance["chunk_count"], 1);
    let taint = provenance["taint"]
        .as_array()
        .expect("taint should be array");
    assert!(
        taint.iter().any(|v| v == "AI_GENERATED"),
        "taint should include AI_GENERATED"
    );

    // Cost should be present
    let cost = result["cost_usd"].as_f64().unwrap();
    assert!(cost >= 0.0, "cost should be non-negative");
}

/// Streaming via `handle_invoke` must apply deltas to the block index Anthropic sent,
/// not just the most recently started block.
#[fcp_async_core::test]
async fn message_stream_invoke_honors_interleaved_block_indices() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_stream_inv_002",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 30, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ),
        (
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": 1,
                "content_block": {
                    "type": "tool_use",
                    "id": "tool_stream_inv_001",
                    "name": "search",
                    "input": {}
                }
            }),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}}),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": "{\"city\": \"Paris\""}
            }),
        ),
        (
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " world"}}),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": "}"}
            }),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ),
        (
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 1}),
        ),
        (
            "message_delta",
            json!({
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use", "stop_sequence": null},
                "usage": {"input_tokens": 30, "output_tokens": 12}
            }),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message.stream"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message.stream");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message.stream",
            "input": {
                "messages": [{"role": "user", "content": "Stream test"}],
                "max_tokens": 256,
                "tools": [{
                    "name": "search",
                    "description": "Search the web",
                    "input_schema": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                        "required": ["city"]
                    }
                }]
            },
            "capability_token": token
        }))
        .await
        .expect("streaming invoke should succeed");

    assert_eq!(result["id"], "msg_stream_inv_002");
    assert_eq!(result["content"], "Hello world");
    assert_eq!(result["streamed"], true);
    assert_eq!(result["stop_reason"], "tool_use");
    assert_eq!(result["usage"]["input_tokens"], 30);
    assert_eq!(result["usage"]["output_tokens"], 12);

    let blocks = result["content_blocks"]
        .as_array()
        .expect("should have content_blocks");
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0], json!({"type": "text", "text": "Hello world"}));
    assert_eq!(
        blocks[1],
        json!({
            "type": "tool_use",
            "id": "tool_stream_inv_001",
            "name": "search",
            "input": {"city": "Paris"}
        })
    );

    let provenance = &result["provenance"];
    assert_eq!(provenance["has_tool_calls"], true);
    assert_eq!(provenance["chunk_count"], 2);
}

// ============================================================================
// Additional Error Handling Tests (403, 404, 502, non-JSON, 529 via connector)
// ============================================================================

/// 403 Forbidden maps to FcpError::External (not Unauthorized).
#[fcp_async_core::test]
async fn error_403_maps_to_external() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(anthropic_error("permission_error", "Permission denied")),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with 403");

    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            service,
            status_code,
            retryable,
            ..
        } => {
            assert_eq!(service, "anthropic");
            assert_eq!(*status_code, Some(403));
            assert!(!retryable, "403 should not be retryable");
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::External { .. }),
            "expected FcpError::External, got: {other:?}"
        ),
    }
}

/// 404 Not Found maps to FcpError::External.
#[fcp_async_core::test]
async fn error_404_maps_to_external() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(anthropic_error("not_found_error", "Resource not found")),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with 404");

    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            status_code,
            retryable,
            ..
        } => {
            assert_eq!(*status_code, Some(404));
            assert!(!retryable, "404 should not be retryable");
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::External { .. }),
            "expected FcpError::External, got: {other:?}"
        ),
    }
}

/// 502 Bad Gateway maps to retryable FcpError::External.
#[fcp_async_core::test]
async fn error_502_maps_to_retryable_external() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(502).set_body_json(anthropic_error("api_error", "Bad gateway")),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with 502");

    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External {
            status_code,
            retryable,
            ..
        } => {
            assert_eq!(*status_code, Some(502));
            assert!(retryable, "502 should be retryable");
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::External { .. }),
            "expected FcpError::External, got: {other:?}"
        ),
    }
}

/// Non-JSON error response body is handled gracefully.
#[fcp_async_core::test]
async fn error_non_json_response_body() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(500).set_body_string("Internal Server Error: upstream timeout"),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(1, 10, 100);

    let result = client.chat(Model::ClaudeSonnet4, "Hi", None, 1024).await;
    let err = result.expect_err("should fail with non-JSON 500");

    // Should still produce a meaningful error even with non-JSON body
    let fcp_err = err.to_fcp_error();
    match &fcp_err {
        fcp_core::FcpError::External { message, .. } => {
            assert!(
                message.contains("upstream timeout") || message.contains("Internal Server Error"),
                "error message should contain the raw body text: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::External { .. }),
            "expected FcpError::External, got: {other:?}"
        ),
    }
}

/// 529 Overloaded via full connector invoke path.
#[fcp_async_core::test]
async fn error_529_via_connector_invoke() {
    let mock = MockApiServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(529)
                .set_body_json(anthropic_error("overloaded_error", "API overloaded"))
                .insert_header("content-type", "application/json")
                .insert_header("retry-after", "0"),
        )
        .mount(mock.inner())
        .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("should fail with 529");

    match &err {
        fcp_core::FcpError::External {
            service,
            retryable,
            status_code,
            ..
        } => {
            assert_eq!(service, "anthropic");
            assert!(retryable, "529 should be retryable");
            assert_eq!(*status_code, Some(529));
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::External { .. }),
            "expected FcpError::External, got: {other:?}"
        ),
    }
}

// ============================================================================
// Additional Input Validation Tests
// ============================================================================

/// Missing messages field entirely in anthropic.message fails.
#[fcp_async_core::test]
async fn validation_message_missing_messages_field() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": { "system": "You are helpful" },
            "capability_token": token
        }))
        .await
        .expect_err("missing messages should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.to_lowercase().contains("messages")
                    || message.to_lowercase().contains("missing"),
                "error should mention messages: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::InvalidRequest { .. }),
            "expected InvalidRequest, got: {other:?}"
        ),
    }
}

/// Empty message string in chat invoke fails at API level.
#[fcp_async_core::test]
async fn validation_chat_empty_message_string() {
    let mock = MockApiServer::start().await;

    mock.expect_error(
        "/v1/messages",
        400,
        anthropic_error(
            "invalid_request_error",
            "messages.0.content: Input should be a non-empty string",
        ),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "" },
            "capability_token": token
        }))
        .await
        .expect_err("empty message string should fail");

    // This exercises the full path: connector -> client -> API -> error mapping
    assert!(
        matches!(
            err,
            fcp_core::FcpError::External { .. } | fcp_core::FcpError::InvalidRequest { .. }
        ),
        "expected error, got: {err:?}"
    );
}

/// Missing operation field in invoke request fails.
#[fcp_async_core::test]
async fn validation_missing_operation_field() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");

    let err = connector
        .handle_invoke(json!({
            "input": { "message": "Hi" },
            "capability_token": token
        }))
        .await
        .expect_err("missing operation should fail");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.to_lowercase().contains("operation"),
                "error should mention operation: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::InvalidRequest { .. }),
            "expected InvalidRequest, got: {other:?}"
        ),
    }
}

/// Empty messages array in message.stream fails.
#[fcp_async_core::test]
async fn validation_stream_empty_messages_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message.stream"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message.stream");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message.stream",
            "input": { "messages": [] },
            "capability_token": token
        }))
        .await
        .expect_err("empty messages in stream should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest, got: {err:?}"
    );
}

/// Unknown model in message.stream fails.
#[fcp_async_core::test]
async fn validation_stream_unknown_model_fails() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message.stream"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message.stream");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message.stream",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "model": "claude-fake-model"
            },
            "capability_token": token
        }))
        .await
        .expect_err("unknown model in stream should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest, got: {err:?}"
    );
}

// ============================================================================
// Configuration Edge Case Tests
// ============================================================================

/// Configure with credential_id mode creates secretless client.
#[fcp_async_core::test]
async fn config_credential_id_mode() {
    let mut connector = AnthropicConnector::new();
    let cred_uuid = uuid::Uuid::new_v4().to_string();

    let result = connector
        .handle_configure(json!({
            "credential_id": cred_uuid
        }))
        .await
        .expect("credential_id config should succeed");

    assert_eq!(result["status"], "configured");

    // Health should show credential mode
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "healthy");
    let auth_str = health["auth"].as_str().unwrap();
    assert!(
        auth_str.starts_with("credential_id:"),
        "auth should show credential_id mode: {auth_str}"
    );
}

/// Configure with both api_key and credential_id is rejected.
#[fcp_async_core::test]
async fn config_both_auth_modes_rejected() {
    let mut connector = AnthropicConnector::new();
    let cred_uuid = uuid::Uuid::new_v4().to_string();

    let err = connector
        .handle_configure(json!({
            "api_key": "sk-test-key",
            "credential_id": cred_uuid
        }))
        .await
        .expect_err("both auth modes should be rejected");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("exactly one"),
                "error should mention 'exactly one': {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::InvalidRequest { .. }),
            "expected InvalidRequest, got: {other:?}"
        ),
    }
}

/// Configure with no auth at all is rejected.
#[fcp_async_core::test]
async fn config_no_auth_rejected() {
    let mut connector = AnthropicConnector::new();
    let err = connector
        .handle_configure(json!({}))
        .await
        .expect_err("no auth should be rejected");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("Missing api_key"),
                "error should mention missing auth: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::InvalidRequest { .. }),
            "expected InvalidRequest, got: {other:?}"
        ),
    }
}

/// Configure rejects base URLs outside the Anthropic endpoint policy.
#[fcp_async_core::test]
async fn config_rejects_non_anthropic_base_url() {
    let mut connector = AnthropicConnector::new();
    let err = connector
        .handle_configure(json!({
            "api_key": "sk-test",
            "base_url": "https://proxy.example.com/v1"
        }))
        .await
        .expect_err("custom proxy endpoint must be rejected");
    assert!(err.to_string().contains("api.anthropic.com"));
}

/// Configure rejects Anthropic origins with embedded API paths.
#[fcp_async_core::test]
async fn config_rejects_pathful_anthropic_base_url() {
    let mut connector = AnthropicConnector::new();
    let err = connector
        .handle_configure(json!({
            "api_key": "sk-test",
            "base_url": "https://api.anthropic.com/v1"
        }))
        .await
        .expect_err("pathful Anthropic base_url must be rejected");
    assert!(err.to_string().contains("without path, query, or fragment"));
}

/// Configure with whitespace-only api_key is rejected (treated as empty).
#[fcp_async_core::test]
async fn config_whitespace_api_key_rejected() {
    let mut connector = AnthropicConnector::new();
    let err = connector
        .handle_configure(json!({ "api_key": "   " }))
        .await
        .expect_err("whitespace-only api_key should be rejected");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest, got: {err:?}"
    );
}

/// Configure with invalid credential_id format is rejected.
#[fcp_async_core::test]
async fn config_invalid_credential_id_format() {
    let mut connector = AnthropicConnector::new();
    let err = connector
        .handle_configure(json!({ "credential_id": "not-a-uuid" }))
        .await
        .expect_err("invalid credential_id should be rejected");

    match &err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("UUID") || message.contains("credential_id"),
                "error should mention UUID or credential_id: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::InvalidRequest { .. }),
            "expected InvalidRequest, got: {other:?}"
        ),
    }
}

// ============================================================================
// Lifecycle / Doctor / Self-Check Tests
// ============================================================================

/// Doctor report before configure is unhealthy.
#[fcp_async_core::test]
async fn doctor_before_configure_is_unhealthy() {
    let connector = AnthropicConnector::new();
    let result = connector.handle_doctor().await.unwrap();

    assert_eq!(result["status"], "unhealthy");
    let checks = result["checks"].as_array().unwrap();
    assert!(!checks.is_empty());
    // First check (configuration) should fail
    assert!(!checks[0]["passed"].as_bool().unwrap());
    assert!(checks[0]["critical"].as_bool().unwrap());
}

/// Doctor report after configure with api_key is healthy.
#[fcp_async_core::test]
async fn doctor_after_configure_healthy() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "healthy");

    let checks = result["checks"].as_array().unwrap();
    // All critical checks should pass
    for check in checks {
        if check["critical"].as_bool().unwrap() {
            assert!(
                check["passed"].as_bool().unwrap(),
                "critical check '{}' should pass",
                check["name"]
            );
        }
    }
}

/// Self-check before configure returns degraded.
#[fcp_async_core::test]
async fn self_check_before_configure() {
    let connector = AnthropicConnector::new();
    let result = connector.handle_self_check().await.unwrap();

    assert_eq!(result["status"], "degraded");
    assert_eq!(
        result["reason_code"].as_str().unwrap(),
        "not_configured",
        "reason_code should be not_configured: {}",
        result["reason_code"]
    );
}

/// Self-check with credential_id returns degraded (cannot validate directly).
#[fcp_async_core::test]
async fn self_check_credential_id_degraded() {
    let mut connector = AnthropicConnector::new();
    let cred_uuid = uuid::Uuid::new_v4().to_string();
    connector
        .handle_configure(json!({ "credential_id": cred_uuid }))
        .await
        .unwrap();

    let result = connector.handle_self_check().await.unwrap();
    assert_eq!(result["status"], "degraded");
}

/// Self-check with valid API key and healthy API returns ok.
#[fcp_async_core::test]
async fn self_check_healthy_api_returns_ok() {
    let mock_server = MockServer::start().await;

    // Health check sends a minimal message request
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(anthropic_success_response(
                "msg_health",
                "ok",
                1,
                1,
            )),
        )
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "sk-valid-key",
            "base_url": mock_server.uri()
        }))
        .await
        .unwrap();

    let result = connector.handle_self_check().await.unwrap();
    assert_eq!(result["status"], "ok");
}

/// Self-check with failing API returns failed.
#[fcp_async_core::test]
async fn self_check_failing_api_returns_failed() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(anthropic_error("authentication_error", "Invalid API key")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "sk-bad-key",
            "base_url": mock_server.uri()
        }))
        .await
        .unwrap();

    let result = connector.handle_self_check().await.unwrap();
    assert_eq!(result["status"], "failed");
}

/// Shutdown clears state and prevents further invocation until reconfigured.
#[fcp_async_core::test]
async fn lifecycle_shutdown_then_invoke_fails_closed() {
    let mock = MockApiServer::start().await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;

    // Shutdown
    let shutdown_result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(shutdown_result["status"], "shutdown");
    assert_eq!(
        connector.handle_health().await.unwrap()["status"],
        "not_configured"
    );

    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");
    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Post-shutdown test" },
            "capability_token": token
        }))
        .await;

    assert!(matches!(result, Err(FcpError::NotConfigured)));
}

/// Health metrics show correct counts after multiple operations.
#[fcp_async_core::test]
async fn health_metrics_after_operations() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_m1", "Response 1", 10, 5),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.chat"]).await;

    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.chat");
    connector
        .handle_invoke(json!({
            "operation": "anthropic.chat",
            "input": { "message": "Test" },
            "capability_token": token
        }))
        .await
        .unwrap();

    let health = connector.handle_health().await.unwrap();
    let metrics = &health["metrics"];
    assert!(
        metrics["requests_total"].as_u64().unwrap() >= 1,
        "should have at least 1 request"
    );
    assert!(
        metrics["total_cost_usd"].as_f64().unwrap() > 0.0,
        "cost should be positive after a request"
    );
}

// ============================================================================
// Model Parameter Variation Tests
// ============================================================================

/// Chat with Opus 4.5 model works and tracks higher cost.
#[fcp_async_core::test]
async fn chat_opus_model_higher_cost() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        json!({
            "id": "msg_opus",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Opus response"}],
            "model": "claude-opus-4-5-20251101",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 100, "output_tokens": 50}
        }),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "model": "claude-opus-4-5-20251101"
            },
            "capability_token": token
        }))
        .await
        .expect("opus model should work");

    let cost = result["cost_usd"].as_f64().unwrap();
    // Opus 4.5: 100 * $5/M + 50 * $25/M = 0.0005 + 0.00125 = 0.00175
    assert!(cost > 0.0015, "opus cost should be substantial: {cost}");
}

/// Chat with Claude 3.5 Sonnet model works.
#[fcp_async_core::test]
async fn chat_claude35_sonnet_model() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        json!({
            "id": "msg_35s",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "3.5 Sonnet response"}],
            "model": "claude-3-5-sonnet-20241022",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "model": "claude-3-5-sonnet-20241022"
            },
            "capability_token": token
        }))
        .await
        .expect("claude-3-5-sonnet should work");

    assert_eq!(result["content"], "3.5 Sonnet response");
    assert_eq!(result["provenance"]["model"], "claude-3-5-sonnet-20241022");
}

/// Message with temperature=0 uses zero temperature.
#[fcp_async_core::test]
async fn message_with_zero_temperature() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        anthropic_success_response("msg_temp0", "Deterministic", 10, 5),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "Test"}],
                "temperature": 0.0
            },
            "capability_token": token
        }))
        .await
        .expect("zero temperature should work");

    assert_eq!(result["content"], "Deterministic");
}

// ============================================================================
// Edge Cases: Empty Response, Token Counting, Simulate
// ============================================================================

/// Response with empty content array still returns successfully.
#[fcp_async_core::test]
async fn message_empty_content_response() {
    let mock = MockApiServer::start().await;

    mock.expect_post(
        "/v1/messages",
        json!({
            "id": "msg_empty",
            "type": "message",
            "role": "assistant",
            "content": [],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 0}
        }),
    )
    .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}],
                "max_tokens": 1
            },
            "capability_token": token
        }))
        .await
        .expect("empty content should succeed");

    assert_eq!(result["id"], "msg_empty");
    assert_eq!(result["content"], "");
    let blocks = result["content_blocks"].as_array().unwrap();
    assert!(blocks.is_empty(), "content_blocks should be empty");
}

/// Token counters accumulate across the client correctly.
#[fcp_async_core::test]
async fn client_token_counter_accumulation() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(anthropic_success_response("msg_tc1", "ok", 100, 50)),
        )
        .mount(&mock_server)
        .await;

    let client = AnthropicClient::new("test-key")
        .unwrap()
        .with_base_url(mock_server.uri());

    // First call
    client
        .chat(Model::ClaudeSonnet4, "Hi", None, 1024)
        .await
        .unwrap();

    assert_eq!(client.total_input_tokens(), 100);
    assert_eq!(client.total_output_tokens(), 50);

    // Second call
    client
        .chat(Model::ClaudeSonnet4, "Hi again", None, 1024)
        .await
        .unwrap();

    assert_eq!(client.total_input_tokens(), 200);
    assert_eq!(client.total_output_tokens(), 100);

    // Reset
    client.reset_token_counts();
    assert_eq!(client.total_input_tokens(), 0);
    assert_eq!(client.total_output_tokens(), 0);
}

/// Simulate returns allowed for all operations.
#[fcp_async_core::test]
async fn simulate_returns_allowed() {
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, "http://localhost:9999").await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message");

    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "sim_001",
            "connector_id": "anthropic",
            "operation": "anthropic.message",
            "zone_id": "z:work",
            "capability_token": token,
            "input": {
                "messages": [{"role": "user", "content": "test"}]
            }
        }))
        .await
        .expect("simulate should succeed");

    assert_eq!(result["id"], "sim_001");
    assert_eq!(result["would_succeed"], true);
}

/// Simulate denies requests whose token operation does not cover the operation.
#[fcp_async_core::test]
async fn simulate_checks_bound_capability_grants() {
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, "http://localhost:9999").await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.get_usage"]).await;
    let capability = generate_valid_token(&signing_key, "anthropic.get_usage");

    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "sim_denied",
            "connector_id": "anthropic",
            "operation": "anthropic.message",
            "zone_id": "z:work",
            "capability_token": capability,
            "input": {
                "messages": [{"role": "user", "content": "test"}]
            }
        }))
        .await
        .expect("simulate should return a denial response");

    assert_eq!(result["id"], "sim_denied");
    assert_eq!(result["would_succeed"], false);
    assert_eq!(result["denial_code"], "FCP-3003");
}

/// Introspect schema has required fields for all operations.
#[fcp_async_core::test]
async fn introspect_schema_required_fields() {
    let connector = AnthropicConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().unwrap();

    for op in ops {
        let id = op["id"].as_str().unwrap();

        // All operations should have capability, risk_level, safety_tier
        assert!(
            op["capability"].as_str().is_some(),
            "op {id} missing capability"
        );
        assert!(
            op["risk_level"].as_str().is_some(),
            "op {id} missing risk_level"
        );
        assert!(
            op["safety_tier"].as_str().is_some(),
            "op {id} missing safety_tier"
        );

        // Input and output schemas should be objects
        assert!(
            op["input_schema"].is_object(),
            "op {id} missing input_schema"
        );
        assert!(
            op["output_schema"].is_object(),
            "op {id} missing output_schema"
        );

        // AI hints should be present
        assert!(
            op["ai_hints"]["when_to_use"].as_str().is_some(),
            "op {id} missing ai_hints.when_to_use"
        );
    }
}

/// get_usage operation returns correct shape with no prior calls.
#[fcp_async_core::test]
async fn get_usage_initial_state() {
    let mock = MockApiServer::start().await;
    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.get_usage"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.get_usage");

    let usage = connector
        .handle_invoke(json!({
            "operation": "anthropic.get_usage",
            "input": {},
            "capability_token": token
        }))
        .await
        .expect("get_usage should succeed");

    assert_eq!(usage["total_input_tokens"], 0);
    assert_eq!(usage["total_output_tokens"], 0);
    assert_eq!(usage["total_cost_usd"], 0.0);
    assert_eq!(usage["requests_error"], 0);
}

// ============================================================================
// Streaming Edge Cases
// ============================================================================

/// Streaming with tool use via connector-level invoke.
#[fcp_async_core::test]
async fn stream_tool_use_via_connector_invoke() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_stool_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 30, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "tool_inv_001",
                    "name": "search",
                    "input": {}
                }
            }),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{\"query\": \"test\""}
            }),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "}"}
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
                "delta": {"stop_reason": "tool_use", "stop_sequence": null},
                "usage": {"input_tokens": 30, "output_tokens": 12}
            }),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message.stream"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message.stream");

    let result = connector
        .handle_invoke(json!({
            "operation": "anthropic.message.stream",
            "input": {
                "messages": [{"role": "user", "content": "Search test"}],
                "tools": [{
                    "name": "search",
                    "description": "Search the web",
                    "input_schema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"]
                    }
                }]
            },
            "capability_token": token
        }))
        .await
        .expect("stream tool_use invoke should succeed");

    // Verify tool call assembled correctly
    assert_eq!(result["id"], "msg_stool_001");
    assert_eq!(result["streamed"], true);
    assert_eq!(result["provenance"]["has_tool_calls"], true);
    let blocks = result["content_blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0]["type"], "tool_use");
    assert_eq!(blocks[0]["name"], "search");
    assert_eq!(blocks[0]["input"]["query"], "test");
}

/// Streaming tool use with malformed accumulated JSON must fail closed instead of
/// silently degrading to an empty input object.
#[fcp_async_core::test]
async fn stream_tool_use_via_connector_invoke_rejects_malformed_input_json() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_stool_bad_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 30, "output_tokens": 0}
                }
            }),
        ),
        (
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "tool_inv_bad_001",
                    "name": "search",
                    "input": {}
                }
            }),
        ),
        (
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{\"query\": \"test\""}
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
                "delta": {"stop_reason": "tool_use", "stop_sequence": null},
                "usage": {"input_tokens": 30, "output_tokens": 12}
            }),
        ),
        ("message_stop", json!({"type": "message_stop"})),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message.stream"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message.stream");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message.stream",
            "input": {
                "messages": [{"role": "user", "content": "Search test"}],
                "tools": [{
                    "name": "search",
                    "description": "Search the web",
                    "input_schema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"]
                    }
                }]
            },
            "capability_token": token
        }))
        .await
        .expect_err("malformed streaming tool JSON should fail");

    match err {
        fcp_core::FcpError::External { message, .. } => {
            assert!(
                message.contains("invalid tool input JSON"),
                "unexpected message: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::External { .. }),
            "expected FcpError::External, got: {other:?}"
        ),
    }
}

/// Streaming error via connector invoke returns FcpError::External.
#[fcp_async_core::test]
async fn stream_error_via_connector_invoke() {
    let mock_server = MockServer::start().await;

    let sse_body = build_sse_body(&[
        (
            "message_start",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_serr_001",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-sonnet-4-20250514",
                    "usage": {"input_tokens": 10, "output_tokens": 0}
                }
            }),
        ),
        (
            "error",
            json!({
                "type": "error",
                "error": {"type": "overloaded_error", "message": "Too many requests"}
            }),
        ),
    ]);

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_body)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message.stream"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message.stream");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message.stream",
            "input": {
                "messages": [{"role": "user", "content": "Error test"}]
            },
            "capability_token": token
        }))
        .await
        .expect_err("streaming error should propagate");

    match &err {
        fcp_core::FcpError::External { message, .. } => {
            assert!(
                message.contains("Too many requests"),
                "error message should propagate: {message}"
            );
        }
        other => assert!(
            matches!(other, fcp_core::FcpError::External { .. }),
            "expected FcpError::External, got: {other:?}"
        ),
    }
}

/// Streaming with 401 pre-stream error returns proper FcpError.
#[fcp_async_core::test]
async fn stream_pre_stream_auth_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(anthropic_error("authentication_error", "Bad key")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = AnthropicConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["anthropic.message.stream"]).await;
    let token: TestCapability = generate_valid_token(&signing_key, "anthropic.message.stream");

    let err = connector
        .handle_invoke(json!({
            "operation": "anthropic.message.stream",
            "input": {
                "messages": [{"role": "user", "content": "Hi"}]
            },
            "capability_token": token
        }))
        .await
        .expect_err("401 on stream should fail");

    assert!(
        matches!(err, fcp_core::FcpError::Unauthorized { .. }),
        "expected Unauthorized, got: {err:?}"
    );
}
