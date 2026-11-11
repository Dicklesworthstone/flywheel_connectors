#![allow(clippy::too_many_lines)]

use std::fs::{OpenOptions, create_dir_all};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_openai_compat::{NetworkError, OpenAiError, RateLimitPolicy};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use fcp_xai::XaiConnector;
use fcp_xai::client::{XaiAuth, XaiClient, XaiProvider};
use fcp_xai::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_xai::types::responses_request_from_value;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "xai.chat.completions";
const OP_CHAT_STREAM: &str = "xai.chat.completions_stream";
const OP_MODELS: &str = "xai.models.list";
const OP_RESPONSES: &str = "xai.responses.create";
const OP_HEALTH: &str = "xai.health";
const CAP_CHAT: &str = "xai.chat";
const CAP_MODELS: &str = "xai.models.read";
const CAP_RESPONSES: &str = "xai.responses.web_search";
const CAP_HEALTH: &str = "xai.health.read";

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> fcp_prelude::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    fcp_prelude::CapabilityToken::from_raw(cose)
}

async fn configured_connector(
    server: &MockServer,
    capabilities: &[&'static str],
    extra_config: Value,
) -> (XaiConnector, Ed25519SigningKey) {
    let mut connector = XaiConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("xai-test-key"));
    config.insert("base_url".into(), json!(format!("{}/v1", server.uri())));
    if let Some(extra) = extra_config.as_object() {
        for (key, value) in extra {
            config.insert(key.clone(), value.clone());
        }
    }
    connector
        .handle_configure(Value::Object(config))
        .await
        .expect("configure should succeed");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let caps = capabilities
        .iter()
        .map(|cap| CapabilityId::from_static(cap))
        .collect();
    connector
        .handshake(test_handshake_request(caps, verifying_key.to_bytes()))
        .await
        .expect("handshake should succeed");
    (connector, signing_key)
}

async fn configured_live_connector(
    api_key: &str,
    capabilities: &[&'static str],
) -> (XaiConnector, Ed25519SigningKey) {
    let mut connector = XaiConnector::new();
    connector
        .handle_configure(json!({
            "api_key": api_key,
            "request_timeout_ms": 30_000,
            "model_cache_ttl_seconds": 1
        }))
        .await
        .expect("live configure should succeed");
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let caps = capabilities
        .iter()
        .map(|cap| CapabilityId::from_static(cap))
        .collect();
    connector
        .handshake(test_handshake_request(caps, verifying_key.to_bytes()))
        .await
        .expect("live handshake should succeed");
    (connector, signing_key)
}

async fn invoke(
    connector: &XaiConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_grant,
        }))
        .await
}

fn e2e_log_path() -> Option<PathBuf> {
    std::env::var_os("XAI_CONNECTOR_E2E_JSONL").map(PathBuf::from)
}

fn append_e2e_record(record: &Value) {
    let Some(path) = e2e_log_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        create_dir_all(parent).expect("e2e artifact directory should be created");
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("e2e JSONL should open");
    writeln!(file, "{record}").expect("e2e JSONL line should write");
    println!("XAI_CONNECTOR_E2E_JSONL={}", path.display());
}

fn command_line() -> String {
    std::env::var("XAI_E2E_COMMAND_LINE")
        .unwrap_or_else(|_| std::env::args().collect::<Vec<_>>().join(" "))
}

fn git_revision() -> String {
    std::env::var("XAI_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".into())
}

fn log_operation(
    mode: &str,
    operation: &str,
    model: &str,
    tool_mode: &str,
    outcome: &str,
    details: &Value,
) {
    append_e2e_record(&json!({
        "record_type": "xai_connector_e2e",
        "command_line": command_line(),
        "git_revision": git_revision(),
        "fixture_or_live_mode": mode,
        "operation": operation,
        "provider": "xai",
        "model": model,
        "search_or_tool_mode": tool_mode,
        "citation_count": details.get("citation_count").and_then(Value::as_u64).unwrap_or(0),
        "citation_hostnames": details.get("citation_hostnames").cloned().unwrap_or_else(|| json!([])),
        "token_count": details.get("token_count").cloned().unwrap_or(Value::Null),
        "byte_count": details.get("byte_count").and_then(Value::as_u64).unwrap_or(0),
        "stream_chunk_count": details.get("stream_chunk_count").and_then(Value::as_u64).unwrap_or(0),
        "http_status": details.get("http_status").and_then(Value::as_u64).unwrap_or(200),
        "retry_decision": details.get("retry_decision").and_then(Value::as_str).unwrap_or("not_retried"),
        "fcp_error_mapping": details.get("fcp_error_mapping").and_then(Value::as_str).unwrap_or("none"),
        "cleanup_result": details.get("cleanup_result").cloned().unwrap_or_else(|| json!({"status": "wiremock_dropped"})),
        "skip_reason": details.get("skip_reason").and_then(Value::as_str).unwrap_or("not_skipped"),
        "outcome": outcome
    }));
}

fn response_fixture() -> Value {
    json!({
        "id": "resp_xai_fixture",
        "object": "response",
        "created_at": 1,
        "model": "grok-4.3",
        "status": "completed",
        "output": [{
            "type": "message",
            "id": "msg_fixture",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": "xAI publishes Grok updates.[[1]](https://x.ai/news/grok-4-fast)",
                "annotations": [{
                    "type": "url_citation",
                    "url": "https://x.ai/news/grok-4-fast",
                    "title": "1",
                    "start_index": 27,
                    "end_index": 66
                }]
            }]
        }],
        "usage": {
            "input_tokens": 11,
            "output_tokens": 12,
            "total_tokens": 23
        },
        "server_side_tool_usage": {
            "web_search": 1
        }
    })
}

#[fcp_async_core::runtime::test]
async fn xai_connector_wiremock_e2e() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer xai-test-key"))
        .and(body_partial_json(json!({
            "model": "grok-4.3",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-xai",
            "object": "chat.completion",
            "created": 1,
            "model": "grok-4.3",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from xAI"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"grok-4.3\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"grok-4.3\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer xai-test-key"))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", "Bearer xai-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "grok-4.3", "object": "model", "owned_by": "xai"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .and(header("authorization", "Bearer xai-test-key"))
        .and(body_partial_json(json!({
            "model": "grok-4.3",
            "tools": [{
                "type": "web_search",
                "filters": {"allowed_domains": ["x.ai"]},
                "enable_image_understanding": true
            }],
            "include": ["no_inline_citations"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_fixture()))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(
        &server,
        &[CAP_CHAT, CAP_MODELS, CAP_RESPONSES, CAP_HEALTH],
        json!({}),
    )
    .await;

    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect("chat invoke should succeed");
    assert_eq!(chat["content"], "hello from xAI");
    assert!(
        !chat.to_string().contains("search_parameters"),
        "chat should not default to legacy live search"
    );
    log_operation(
        "fixture",
        OP_CHAT,
        "grok-4.3",
        "chat_no_search",
        "passed",
        &json!({"token_count": 5, "byte_count": chat.to_string().len()}),
    );

    let stream = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private prompt"}]}),
    )
    .await
    .expect("stream invoke should succeed");
    assert_eq!(stream["content"], "hello");
    assert_eq!(stream["chunk_count"], 2);
    assert!(
        !stream.to_string().contains("private prompt"),
        "stream response should not echo prompt"
    );
    log_operation(
        "fixture",
        OP_CHAT_STREAM,
        "grok-4.3",
        "stream_no_search",
        "passed",
        &json!({"stream_chunk_count": 2, "byte_count": stream.to_string().len()}),
    );

    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should load");
    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health should reuse cached models");
    assert_eq!(models["data"][0]["id"], "grok-4.3");
    assert_eq!(health["status"], "ok");
    log_operation(
        "fixture",
        OP_MODELS,
        "grok-4.3",
        "models",
        "passed",
        &json!({"byte_count": models.to_string().len()}),
    );

    let responses = invoke(
        &connector,
        &signing_key,
        OP_RESPONSES,
        CAP_RESPONSES,
        json!({
            "model": "grok-4.3",
            "input": [{"role": "user", "content": "What is xAI?"}],
            "include": ["no_inline_citations"],
            "web_search": {
                "allowed_domains": ["x.ai"],
                "enable_image_understanding": true
            }
        }),
    )
    .await
    .expect("responses invoke should succeed");
    assert_eq!(responses["citation_count"], 1);
    assert_eq!(responses["citation_hosts"][0], "x.ai");
    assert_eq!(responses["usage"]["total_tokens"], 23);
    log_operation(
        "fixture",
        OP_RESPONSES,
        "grok-4.3",
        "responses_web_search",
        "passed",
        &json!({
            "citation_count": 1,
            "citation_hostnames": ["x.ai"],
            "token_count": 23,
            "byte_count": responses["output_text_bytes"],
            "http_status": 200
        }),
    );

    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(!doctor.to_string().contains("xai-test-key"));
}

#[fcp_async_core::runtime::test]
async fn responses_without_citations_returns_empty_citation_summary() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "resp_no_cites",
            "object": "response",
            "created_at": 1,
            "model": "grok-4.3",
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "No citations here.", "annotations": []}]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_RESPONSES], json!({})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_RESPONSES,
        CAP_RESPONSES,
        json!({"input": "hello", "tools": [{"type": "web_search"}]}),
    )
    .await
    .expect("responses should succeed");

    assert_eq!(result["citation_count"], 0);
    assert_eq!(result["citation_hosts"], json!([]));
    assert_eq!(result["output_text"], "No citations here.");
}

#[fcp_async_core::runtime::test]
async fn rate_limit_retry_waits_once_then_succeeds_for_responses_api() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .insert_header("x-ratelimit-remaining-requests", "0")
                .set_body_json(json!({
                    "error": {"type": "rate_limit_error", "message": "slow down"}
                })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_fixture()))
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(
        &server,
        &[CAP_RESPONSES],
        json!({"wait_on_rate_limit_ms": 1000}),
    )
    .await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_RESPONSES,
        CAP_RESPONSES,
        json!({"input": "hello", "tools": [{"type": "web_search"}]}),
    )
    .await
    .expect("retry should recover");

    assert_eq!(result["citation_count"], 1);
}

#[fcp_async_core::runtime::test]
async fn provider_errors_map_to_fcp_and_redact_sensitive_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "type": "authentication_error",
                "message": "bad Bearer should-not-leak",
                "prompt": "private prompt"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect_err("401 should fail");

    assert!(matches!(error, FcpError::Unauthorized { .. }));
    let display = error.to_string();
    assert!(!display.contains("should-not-leak"));
    assert!(!display.contains("private prompt"));
}

#[fcp_async_core::runtime::test]
async fn responses_timeout_and_cancellation_are_bounded() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(75))
                .set_body_json(response_fixture()),
        )
        .mount(&server)
        .await;

    let provider = XaiProvider::new(
        format!("{}/v1", server.uri()),
        XaiAuth::ApiKey("key".into()),
    );
    let client = XaiClient::new(
        provider.clone(),
        Duration::from_millis(5),
        Duration::from_secs(60),
        RateLimitPolicy::FailFast,
    );
    let request = responses_request_from_value(
        json!({"input": "hello", "tools": [{"type": "web_search"}]}),
        "grok-4.3",
    )
    .expect("request should build");
    let timeout_error = client
        .responses_create(&fcp_async_core::compatibility_cx(), request)
        .await
        .expect_err("slow server should time out");
    assert!(matches!(
        timeout_error,
        OpenAiError::Network(NetworkError::DeadlineExceeded { .. })
    ));

    let cx = fcp_async_core::compatibility_cx();
    cx.set_cancel_requested(true);
    let client = XaiClient::new(
        provider,
        Duration::from_secs(5),
        Duration::from_secs(60),
        RateLimitPolicy::FailFast,
    );
    let request = responses_request_from_value(
        json!({"input": "hello", "tools": [{"type": "web_search"}]}),
        "grok-4.3",
    )
    .expect("request should build");
    let cancel_error = client
        .responses_create(&cx, request)
        .await
        .expect_err("cancelled context should fail before dispatch");
    assert!(matches!(
        cancel_error,
        OpenAiError::Network(NetworkError::Cancelled { .. })
    ));
    // compatibility_cx() returns the shared ambient runtime context; clear the
    // cancel flag so runtime teardown is not poisoned by the cancellation.
    cx.set_cancel_requested(false);
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token_and_shutdown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "grok-4.3", "object": "model", "owned_by": "xai"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (mut connector, signing_key) =
        configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let capability_grant =
        valid_token(&signing_key, connector.instance_id(), CAP_MODELS, OP_MODELS);
    let response = connector
        .invoke(test_invoke_request(
            "xai-models-suite",
            OP_MODELS,
            json!({}),
            capability_grant,
        ))
        .await
        .expect("invoke should return response");

    assert!(response.error.is_none(), "response should not carry error");
    assert_eq!(
        response.result.expect("result present")["data"][0]["id"],
        "grok-4.3"
    );
    connector
        .shutdown(fcp_prelude::ShutdownRequest {
            r#type: "shutdown".into(),
            reason: Some("test".into()),
            deadline_ms: 1_000,
            drain: false,
        })
        .await
        .expect("shutdown should pass");
    let health = connector.health().await;
    assert!(matches!(health.status.as_str(), "error" | "degraded"));
}

#[fcp_async_core::runtime::test]
async fn xai_connector_live_smoke_e2e() {
    let Some(api_key) = std::env::var("XAI_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        log_operation(
            "live",
            OP_MODELS,
            "grok-4.3",
            "models",
            "skipped",
            &json!({
                "http_status": 0,
                "retry_decision": "not_started",
                "fcp_error_mapping": "not_applicable",
                "cleanup_result": {"status": "not_started"},
                "skip_reason": "XAI_API_KEY not set"
            }),
        );
        return;
    };

    let (connector, signing_key) = configured_live_connector(&api_key, &[CAP_MODELS]).await;
    let result = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("live models smoke should succeed");
    assert!(
        result["data"]
            .as_array()
            .is_some_and(|models| !models.is_empty())
    );
    log_operation(
        "live",
        OP_MODELS,
        "provider-enabled",
        "models",
        "passed",
        &json!({"byte_count": result.to_string().len(), "http_status": 200}),
    );
}

#[test]
fn connector_id_matches_manifest_contract() {
    assert_eq!(CONNECTOR_ID, "fcp.xai");
}
