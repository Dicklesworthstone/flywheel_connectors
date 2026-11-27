#![allow(clippy::too_many_lines)]

use std::fs::{OpenOptions, create_dir_all};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_openai_compat::{NetworkError, OpenAiError, RateLimitPolicy};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, ConnectorId, FcpConnector, FcpError, InstanceId,
    InvokeRequest, OperationId, SimulateRequest, ZoneId,
};
use fcp_xai::XaiConnector;
use fcp_xai::client::{XaiAuth, XaiClient, XaiProvider};
use fcp_xai::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_xai::types::responses_request_from_value;
use futures_util::FutureExt;
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
    constrained_token(
        signing_key,
        instance_id,
        capability,
        operation,
        None,
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        },
    )
}

fn constrained_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
    token_id: Option<&[u8]>,
    constraints: &CapabilityConstraints,
) -> fcp_prelude::CapabilityToken {
    let now = Utc::now();
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).expect("serialize constraints");
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate");
    if let Some(id) = token_id {
        builder = builder.token_id(id);
    }
    let cose = builder
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
        .handle_invoke(
            serde_json::to_value(test_invoke_request(
                "xai-integration",
                operation,
                input,
                capability_grant,
            ))
            .expect("canonical invoke request"),
        )
        .await
}

async fn invoke_request(
    connector: &XaiConnector,
    request: &InvokeRequest,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(serde_json::to_value(request).expect("canonical invoke request"))
        .await
}

fn chat_fixture(content: &str) -> Value {
    json!({
        "id": "chatcmpl-boundary", "object": "chat.completion", "created": 1,
        "model": "grok-4.3",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
    })
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

    let cx = fcp_async_core::Cx::for_testing();
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
async fn canonical_admission_preserves_grants_after_route_and_contract_rejection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("connection", "close")
                .set_body_json(chat_fixture("accepted")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_CHAT,
        OP_CHAT,
        Some(b"canonical-once"),
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_calls: Some(1),
            ..Default::default()
        },
    );
    let request = test_invoke_request(
        "canonical",
        OP_CHAT,
        json!({"messages":[{"role":"user","content":"hello"}]}),
        token,
    );
    for (field, value) in [
        ("type", json!("simulate")),
        ("id", json!("")),
        ("connector_id", json!("fcp.groq")),
        ("zone_id", json!("z:private")),
        ("deadline_ms", json!(0)),
        ("input", json!([])),
        ("input", json!({"messages":[]})),
        (
            "input",
            json!({"messages":[{"role":"invented","content":"hello"}]}),
        ),
        (
            "input",
            json!({"messages":[{"role":"user","content":"hello"}],"temperature":3}),
        ),
    ] {
        let mut invalid = serde_json::to_value(&request).unwrap();
        invalid[field] = value;
        assert!(
            connector.handle_invoke(invalid).await.is_err(),
            "accepted invalid {field}"
        );
    }
    assert!(
        connector
            .handle_invoke(json!({"operation":OP_CHAT,"input":{}}))
            .await
            .is_err()
    );
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
    assert!(server.received_requests().await.unwrap().is_empty());
    let response = connector.invoke(request.clone()).await.unwrap();
    assert_eq!(response.result.unwrap()["content"], "accepted");
    assert_eq!(response.resource_uris, vec!["xai:model:grok-4.3"]);
    assert!(
        invoke_request(&connector, &request).await.is_err(),
        "raw path reused an admitted grant"
    );
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
}

#[fcp_async_core::runtime::test]
async fn effective_models_and_web_search_resources_cannot_be_overridden_by_extensions() {
    for (operation, capability, endpoint, input, resources, shadows) in [
        (
            OP_CHAT,
            CAP_CHAT,
            "/v1/chat/completions",
            json!({"messages":[{"role":"user","content":"hello"}]}),
            vec!["xai:model:grok-configured"],
            vec![
                "model",
                "messages",
                "stream",
                "temperature",
                "reasoning_effort",
                "search_parameters",
            ],
        ),
        (
            OP_RESPONSES,
            CAP_RESPONSES,
            "/v1/responses",
            json!({"input":"hello", "tools":[{"type":"web_search"}]}),
            vec!["xai:responses:model:grok-configured", "xai:web_search"],
            vec![
                "model",
                "input",
                "tools",
                "stream",
                "store",
                "previous_response_id",
                "temperature",
            ],
        ),
    ] {
        let server = MockServer::start().await;
        let fixture = if operation == OP_CHAT {
            chat_fixture("configured model")
        } else {
            response_fixture()
        };
        Mock::given(method("POST"))
            .and(path(endpoint))
            .and(body_partial_json(json!({"model":"grok-configured"})))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("connection", "close")
                    .set_body_json(fixture),
            )
            .expect(1)
            .mount(&server)
            .await;
        let (connector, key) = configured_connector(
            &server,
            &[capability],
            json!({"default_model":"grok-configured"}),
        )
        .await;
        let wrong_default = constrained_token(
            &key,
            connector.instance_id(),
            capability,
            operation,
            Some(b"wrong-default"),
            &CapabilityConstraints {
                resource_allow: vec![
                    "xai:model:grok-4.3".into(),
                    "xai:responses:model:grok-4.3".into(),
                    "xai:web_search".into(),
                ],
                ..Default::default()
            },
        );
        assert!(
            invoke_request(
                &connector,
                &test_invoke_request("wrong-model", operation, input.clone(), wrong_default)
            )
            .await
            .is_err()
        );
        if operation == OP_RESPONSES {
            for allowed in &resources {
                let partial = constrained_token(
                    &key,
                    connector.instance_id(),
                    capability,
                    operation,
                    None,
                    &CapabilityConstraints {
                        resource_allow: vec![(*allowed).into()],
                        ..Default::default()
                    },
                );
                assert!(
                    invoke_request(
                        &connector,
                        &test_invoke_request(
                            "partial-resources",
                            operation,
                            input.clone(),
                            partial
                        )
                    )
                    .await
                    .is_err()
                );
            }
        }
        let token = constrained_token(
            &key,
            connector.instance_id(),
            capability,
            operation,
            Some(b"effective-model-once"),
            &CapabilityConstraints {
                resource_allow: resources
                    .iter()
                    .map(|resource| (*resource).into())
                    .collect(),
                max_calls: Some(1),
                ..Default::default()
            },
        );
        let request = test_invoke_request("effective-model", operation, input, token);
        for field in shadows {
            let mut invalid = request.clone();
            let mut extensions = serde_json::Map::new();
            extensions.insert(field.into(), json!("unchecked-override"));
            invalid.input["provider_extensions"] = json!(extensions);
            assert!(
                invoke_request(&connector, &invalid).await.is_err(),
                "accepted shadow {field}"
            );
        }
        assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
        assert!(server.received_requests().await.unwrap().is_empty());
        let response = connector.invoke(request).await.unwrap();
        assert!(response.error.is_none());
        assert_eq!(response.resource_uris, resources);
        assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
    }
}

#[fcp_async_core::runtime::test]
async fn remote_images_files_and_previous_responses_require_their_actual_resource_scopes() {
    for (operation, capability, endpoint, input, expected_body, mut resources) in [
        (
            OP_CHAT,
            CAP_CHAT,
            "/v1/chat/completions",
            json!({"messages":[{"role":"user","content":[
                {"type":"text","text":"inspect"},
                {"type":"image_url","image_url":{"url":"HTTPS://EXAMPLE.COM:443/images/../scan.png"}},
                {"type":"image_url","image_url":{"url":"data:image/png;base64,AA=="}}
            ]}]}),
            json!({"messages":[{"role":"user","content":[
                {"type":"text","text":"inspect"},
                {"type":"image_url","image_url":{"url":"https://example.com/scan.png"}},
                {"type":"image_url","image_url":{"url":"data:image/png;base64,AA=="}}
            ]}]}),
            vec![
                "xai:model:grok-4.3",
                "xai:image_url:https://example.com/scan.png",
            ],
        ),
        (
            OP_RESPONSES,
            CAP_RESPONSES,
            "/v1/responses",
            json!({"input":[{"role":"user","content":[
                {"type":"input_text","text":"inspect"},
                {"type":"input_image","image_url":"HTTPS://EXAMPLE.COM:443/images/../scan.png"},
                {"type":"input_file","file_url":"HTTPS://EXAMPLE.COM:443/files/../report.pdf"},
                {"type":"input_file","file_id":"file-1"}
            ]}], "previous_response_id":"resp-1", "tools":[{"type":"web_search"}]}),
            json!({"input":[{"role":"user","content":[
                {"type":"input_text","text":"inspect"},
                {"type":"input_image","image_url":"https://example.com/scan.png"},
                {"type":"input_file","file_url":"https://example.com/report.pdf"},
                {"type":"input_file","file_id":"file-1"}
            ]}], "previous_response_id":"resp-1"}),
            vec![
                "xai:responses:model:grok-4.3",
                "xai:web_search",
                "xai:image_url:https://example.com/scan.png",
                "xai:file_url:https://example.com/report.pdf",
                "xai:file:file-1",
                "xai:response:resp-1",
            ],
        ),
    ] {
        let server = MockServer::start().await;
        let fixture = if operation == OP_CHAT {
            chat_fixture("scoped")
        } else {
            response_fixture()
        };
        Mock::given(method("POST"))
            .and(path(endpoint))
            .and(body_partial_json(expected_body))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("connection", "close")
                    .set_body_json(fixture),
            )
            .expect(1)
            .mount(&server)
            .await;
        let (connector, key) = configured_connector(&server, &[capability], json!({})).await;
        for missing in &resources {
            let token = constrained_token(
                &key,
                connector.instance_id(),
                capability,
                operation,
                None,
                &CapabilityConstraints {
                    resource_allow: resources
                        .iter()
                        .filter(|resource| *resource != missing)
                        .map(|resource| (*resource).into())
                        .collect(),
                    ..Default::default()
                },
            );
            assert!(
                invoke_request(
                    &connector,
                    &test_invoke_request("missing-resource", operation, input.clone(), token)
                )
                .await
                .is_err(),
                "authorized a request without {missing}"
            );
        }
        let token = constrained_token(
            &key,
            connector.instance_id(),
            capability,
            operation,
            Some(b"remote-resources-once"),
            &CapabilityConstraints {
                resource_allow: resources
                    .iter()
                    .map(|resource| (*resource).into())
                    .collect(),
                max_calls: Some(1),
                ..Default::default()
            },
        );
        let request = test_invoke_request("remote-resources", operation, input, token);
        let mut unsupported_control = request.clone();
        if operation == OP_CHAT {
            unsupported_control.input["search_parameters"] = json!({"mode":"auto"});
        } else {
            unsupported_control.input["tools"] =
                json!([{"type":"web_search"}, {"type":"code_interpreter"}]);
        }
        assert!(
            invoke_request(&connector, &unsupported_control)
                .await
                .is_err()
        );
        assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
        assert!(server.received_requests().await.unwrap().is_empty());
        let mut response = connector.invoke(request).await.unwrap();
        assert!(response.error.is_none());
        response.resource_uris.sort();
        resources.sort();
        assert_eq!(response.resource_uris, resources);
    }
}

#[fcp_async_core::runtime::test]
async fn negotiation_rotation_and_failed_reconfiguration_revoke_old_authority() {
    let server = MockServer::start().await;
    let (mut connector, key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let previous_instance = connector.instance_id().clone();
    let old = test_invoke_request(
        "old-session",
        OP_MODELS,
        json!({}),
        valid_token(&key, &previous_instance, CAP_MODELS, OP_MODELS),
    );
    assert!(
        invoke_request(&connector, &old).await.is_err(),
        "unnegotiated capability was accepted"
    );
    let handshake = test_handshake_request(
        vec![
            CapabilityId::from_static(CAP_MODELS),
            CapabilityId::from_static("unknown.capability"),
        ],
        key.verifying_key().to_bytes(),
    );
    let response = connector
        .handle_handshake(serde_json::to_value(handshake).unwrap())
        .await
        .unwrap();
    assert_eq!(
        response["capabilities_granted"].as_array().unwrap().len(),
        1
    );
    assert_eq!(response["instance_id"], json!(connector.instance_id()));
    assert_ne!(connector.instance_id(), &previous_instance);
    assert!(
        invoke_request(&connector, &old).await.is_err(),
        "old token survived rehandshake"
    );
    let current = test_invoke_request(
        "before-failed-handshake",
        OP_MODELS,
        json!({}),
        valid_token(&key, connector.instance_id(), CAP_MODELS, OP_MODELS),
    );
    let mut forbidden = test_handshake_request(
        vec![CapabilityId::from_static(CAP_MODELS)],
        key.verifying_key().to_bytes(),
    );
    forbidden.zone = ZoneId::private();
    assert!(connector.handshake(forbidden).await.is_err());
    assert!(matches!(
        invoke_request(&connector, &current).await,
        Err(FcpError::NotHandshaken)
    ));
    assert_eq!(
        connector.handle_health().await.unwrap()["handshaken"],
        false
    );
    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_MODELS)],
            key.verifying_key().to_bytes(),
        ))
        .await
        .unwrap();
    let current = test_invoke_request(
        "before-failed-configure",
        OP_MODELS,
        json!({}),
        valid_token(&key, connector.instance_id(), CAP_MODELS, OP_MODELS),
    );
    assert!(
        connector
            .handle_configure(json!({"api_key":""}))
            .await
            .is_err()
    );
    assert!(matches!(
        invoke_request(&connector, &current).await,
        Err(FcpError::NotConfigured)
    ));
    assert_eq!(
        connector.handle_health().await.unwrap()["configured"],
        false
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn signed_keys_and_byte_limits_withhold_oversized_responses_without_refunds() {
    let server = MockServer::start().await;
    let mut fixture = response_fixture();
    fixture["output"][0]["content"][0]["text"] = json!("x".repeat(8_000));
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("connection", "close")
                .set_body_json(fixture),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_RESPONSES], json!({})).await;
    let input = json!({"input":"hello", "tools":[{"type":"web_search"}]});
    for (id, max_calls, max_bytes) in [("zero-calls", Some(0), None), ("tiny-bytes", None, Some(1))]
    {
        let token = constrained_token(
            &key,
            connector.instance_id(),
            CAP_RESPONSES,
            OP_RESPONSES,
            Some(id.as_bytes()),
            &CapabilityConstraints {
                resource_allow: vec!["*".into()],
                max_calls,
                max_bytes,
                ..Default::default()
            },
        );
        assert!(
            invoke_request(
                &connector,
                &test_invoke_request(id, OP_RESPONSES, input.clone(), token)
            )
            .await
            .is_err()
        );
    }
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_RESPONSES,
        OP_RESPONSES,
        Some(b"key-and-bytes"),
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_calls: Some(1),
            max_bytes: Some(4096),
            idempotency_key: Some("required-key".into()),
            ..Default::default()
        },
    );
    let mut request = test_invoke_request("bounded-output", OP_RESPONSES, input, token);
    for key in [None, Some("wrong-key".to_string())] {
        request.idempotency_key = key;
        assert!(invoke_request(&connector, &request).await.is_err());
    }
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
    assert!(server.received_requests().await.unwrap().is_empty());
    request.idempotency_key = Some("required-key".into());
    let error = invoke_request(&connector, &request)
        .await
        .expect_err("oversized response must be withheld");
    assert!(matches!(
        error,
        FcpError::External {
            retryable: false,
            ..
        }
    ));
    assert!(
        invoke_request(&connector, &request).await.is_err(),
        "oversized response refunded the grant"
    );
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
}

#[fcp_async_core::runtime::test]
async fn simulations_and_invalid_strict_keys_do_not_consume_call_budget() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("connection", "close")
                .set_body_json(json!({"object":"list", "data":[]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_MODELS,
        OP_MODELS,
        Some(b"preview-once"),
        &CapabilityConstraints {
            resource_allow: vec!["xai:models".into()],
            max_calls: Some(1),
            ..Default::default()
        },
    );
    let simulate = SimulateRequest::new(
        ConnectorId::from_static(CONNECTOR_ID),
        OperationId::from_static(OP_MODELS),
        ZoneId::work(),
        json!({}),
        token.clone(),
    );
    for _ in 0..2 {
        assert!(
            connector
                .simulate(simulate.clone())
                .await
                .unwrap()
                .would_succeed
        );
    }
    for (field, value) in [
        ("type", json!("invoke")),
        ("id", json!("")),
        ("connector_id", json!("fcp.groq")),
        ("zone_id", json!("z:private")),
        ("input", json!([])),
    ] {
        let mut invalid = serde_json::to_value(&simulate).unwrap();
        invalid[field] = value;
        let result = connector.handle_simulate(invalid).await;
        assert!(
            !result.is_ok_and(|response| response["would_succeed"] == true),
            "simulation accepted invalid {field}"
        );
    }
    let mut request = test_invoke_request("after-preview", OP_MODELS, json!({}), token);
    for key in [None, Some("  ".into())] {
        request.idempotency_key = key;
        assert!(invoke_request(&connector, &request).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
    request.idempotency_key = Some("after-preview".into());
    assert!(invoke_request(&connector, &request).await.is_ok());
    assert!(!connector.simulate(simulate).await.unwrap().would_succeed);
}

#[fcp_async_core::runtime::test]
async fn expired_or_cancelled_native_context_refuses_before_debit_or_cache_access() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("connection", "close")
                .set_body_json(json!({"object":"list", "data":[]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_MODELS,
        OP_MODELS,
        Some(b"native-budget"),
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_calls: Some(1),
            ..Default::default()
        },
    );
    let request = test_invoke_request("native-budget", OP_MODELS, json!({"refresh":true}), token);
    let parent = fcp_async_core::compatibility_cx();
    let expired =
        fcp_async_core::Cx::for_testing_with_budget(parent.budget_for_timeout(Duration::ZERO));
    let cancelled = fcp_async_core::Cx::for_testing();
    cancelled.set_cancel_requested(true);
    for context in [expired, cancelled] {
        let guard = fcp_async_core::Cx::set_current(Some(context));
        let error = connector
            .invoke(request.clone())
            .now_or_never()
            .expect("invalid native budget must not poll I/O")
            .expect_err("invalid native budget must reject admission");
        drop(guard);
        assert!(!error.is_retryable());
    }
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(
        invoke_request(&connector, &request).await.is_ok(),
        "pre-admission interruption spent the grant"
    );
}

#[fcp_async_core::runtime::test]
async fn credential_id_refuses_provider_work_without_host_injection() {
    let server = MockServer::start().await;
    let mut connector = XaiConnector::new();
    connector
        .handle_configure(json!({
            "credential_id":"vault-ref", "base_url":format!("{}/v1", server.uri()),
        }))
        .await
        .unwrap();
    let key = Ed25519SigningKey::generate();
    connector
        .handshake(test_handshake_request(
            vec![
                CapabilityId::from_static(CAP_MODELS),
                CapabilityId::from_static(CAP_CHAT),
                CapabilityId::from_static(CAP_RESPONSES),
            ],
            key.verifying_key().to_bytes(),
        ))
        .await
        .unwrap();
    for (operation, capability, input) in [
        (OP_MODELS, CAP_MODELS, json!({})),
        (
            OP_CHAT,
            CAP_CHAT,
            json!({"messages":[{"role":"user","content":"hello"}]}),
        ),
        (
            OP_RESPONSES,
            CAP_RESPONSES,
            json!({"input":"hello", "tools":[{"type":"web_search"}]}),
        ),
    ] {
        let error = invoke(&connector, &key, operation, capability, input)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("credential injection"));
    }
    assert_eq!(
        connector.handle_health().await.unwrap()["credential_injection_required"],
        true
    );
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
    assert!(server.received_requests().await.unwrap().is_empty());
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

#[fcp_async_core::runtime::test]
async fn ambiguous_responses_posts_are_never_replayed_or_exposed_as_retryable() {
    for (status, body) in [
        (503, r#"{"error":{"type":"service_unavailable"}}"#),
        (409, r#"{"error":{"type":"rate_limit_error"}}"#),
        (200, "private malformed response"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("retry-after", "0")
                    .set_body_string(body),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = XaiClient::new(
            XaiProvider::new(
                format!("{}/v1", server.uri()),
                XaiAuth::ApiKey("key".into()),
            ),
            Duration::from_secs(5),
            Duration::from_secs(60),
            RateLimitPolicy::WaitForever,
        );
        let request = responses_request_from_value(
            json!({"input": "hello", "tools": [{"type": "web_search"}]}),
            "grok-4.3",
        )
        .expect("request should build");
        let error = client
            .responses_create(&fcp_async_core::compatibility_cx(), request)
            .await
            .expect_err("an ambiguous provider response must not authorize replay");
        assert_eq!(
            error,
            OpenAiError::OutcomeUnknown {
                status: Some(status)
            }
        );
        let mapped = fcp_xai::error::openai_error_to_fcp(&error);
        assert!(matches!(
            mapped,
            FcpError::External {
                retryable: false,
                retry_after: None,
                status_code: Some(observed),
                ..
            } if observed == status
        ));
        assert!(!mapped.to_string().contains("private malformed response"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
