#![allow(clippy::too_many_lines)]

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_deepseek::DeepSeekConnector;
use fcp_deepseek::client::{DeepSeekAuth, DeepSeekProvider, normalize_deepseek_base_url};
use fcp_deepseek::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_openai_compat::{OpenAiCompatProvider, header_value, redact_sensitive_text};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, ConnectorId, FcpConnector, FcpError, InstanceId,
    InvokeRequest, OperationId, SimulateRequest, ZoneId,
};
use futures_util::FutureExt;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{any, body_partial_json, header, method, path},
};

const OP_CHAT: &str = "deepseek.chat.completions";
const OP_CHAT_STREAM: &str = "deepseek.chat.completions_stream";
const OP_MODELS: &str = "deepseek.models.list";
const OP_HEALTH: &str = "deepseek.health";
const OP_EMBEDDINGS: &str = "deepseek.embeddings.create";
const CAP_CHAT: &str = "deepseek.chat";
const CAP_MODELS: &str = "deepseek.models.read";
const CAP_HEALTH: &str = "deepseek.health.read";
const CAP_EMBEDDINGS: &str = "deepseek.embeddings";

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
        &[operation],
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
    operations: &[&str],
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
        .operations(operations)
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
) -> (DeepSeekConnector, Ed25519SigningKey) {
    let mut connector = DeepSeekConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("deepseek-test-key"));
    config.insert("base_url".into(), json!(server.uri()));
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

async fn invoke(
    connector: &DeepSeekConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(
            serde_json::to_value(test_invoke_request(
                "deepseek-fixture",
                operation,
                input,
                capability_grant,
            ))
            .expect("canonical invoke encodes"),
        )
        .await
}

async fn invoke_request(
    connector: &DeepSeekConnector,
    request: &InvokeRequest,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(serde_json::to_value(request).expect("invoke encodes"))
        .await
}

fn chat_fixture(content: &str) -> Value {
    json!({
        "id": "chatcmpl-boundary", "object": "chat.completion", "created": 1,
        "model": "deepseek-v4-flash",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
    })
}

fn emit_fixture(event: &str, payload: &Value) {
    let mut object = serde_json::Map::new();
    object.insert("event".into(), json!(event));
    object.insert("connector".into(), json!("fcp-deepseek"));
    object.insert("fixture_mode".into(), json!("wiremock"));
    object.insert(
        "git_revision".into(),
        json!(option_env!("GIT_REVISION").unwrap_or("unknown")),
    );
    object.insert(
        "command_line".into(),
        json!(std::env::args().collect::<Vec<_>>().join(" ")),
    );
    if let Some(payload) = payload.as_object() {
        for (key, value) in payload {
            object.insert(key.clone(), value.clone());
        }
    }
    eprintln!("DEEPSEEK_FIXTURE_JSONL {}", Value::Object(object));
}

fn closed_response(status: u16) -> ResponseTemplate {
    ResponseTemplate::new(status).insert_header("connection", "close")
}

fn closed_json_response(status: u16, body: Value) -> ResponseTemplate {
    closed_response(status).set_body_json(body)
}

async fn mount_unmatched_request_guard(server: &MockServer) {
    Mock::given(any())
        .respond_with(closed_json_response(
            599,
            json!({
                "error": {
                    "type": "unexpected_wiremock_request",
                    "message": "DeepSeek integration test received an unmatched HTTP request"
                }
            }),
        ))
        .with_priority(255)
        .mount(server)
        .await;
}

#[test]
fn provider_construction_base_url_and_auth_policy() {
    let provider = DeepSeekProvider::new(
        "https://api.deepseek.com",
        DeepSeekAuth::ApiKey("direct-key".into()),
    );
    let mut request = fcp_openai_compat::HttpRequest::default();
    provider.auth_header(&mut request);

    assert_eq!(provider.provider_name(), "deepseek");
    assert_eq!(
        normalize_deepseek_base_url(None).unwrap(),
        "https://api.deepseek.com"
    );
    assert_eq!(
        normalize_deepseek_base_url(Some("https://api.deepseek.com/v1")).unwrap(),
        "https://api.deepseek.com/v1"
    );
    assert_eq!(
        header_value(&request.headers, "authorization"),
        Some("Bearer direct-key")
    );
    assert_eq!(
        provider.extra_request_headers("deepseek-v4-pro"),
        Vec::new()
    );

    assert!(normalize_deepseek_base_url(Some("https://example.com")).is_err());
    assert!(normalize_deepseek_base_url(Some("http://api.deepseek.com")).is_err());
}

#[fcp_async_core::runtime::test]
async fn chat_completions_v4_flash_without_reasoning_content() {
    let server = MockServer::start().await;
    mount_unmatched_request_guard(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer deepseek-test-key"))
        .and(body_partial_json(json!({
            "model": "deepseek-v4-flash",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false,
            "thinking": {"type": "disabled"}
        })))
        .respond_with(closed_json_response(
            200,
            json!({
                "id": "chatcmpl-deepseek-v4-flash",
                "object": "chat.completion",
                "created": 1,
                "model": "deepseek-v4-flash",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "hello from DeepSeek"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "model": "deepseek-v4-flash",
            "messages": [{"role": "user", "content": "hello"}],
            "thinking": {"type": "disabled"}
        }),
    )
    .await
    .expect("chat invoke should succeed");

    assert_eq!(result["content"], "hello from DeepSeek");
    assert!(result["reasoning_content"].is_null());
    assert_eq!(result["reasoning_content_bytes"], 0);
    assert_eq!(result["usage"]["total_tokens"], 5);
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(!doctor.to_string().contains("deepseek-test-key"));
    emit_fixture(
        "chat_v4_flash_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-flash",
            "content_bytes": result["content_bytes"],
            "reasoning_content_bytes": result["reasoning_content_bytes"],
            "stream_chunk_count": 0,
            "http_status": 200,
            "retry_decision": "none",
            "error_mapping": "none",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn chat_completions_reasoning_content_stays_separate_for_v4_pro() {
    let server = MockServer::start().await;
    mount_unmatched_request_guard(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer deepseek-test-key"))
        .and(body_partial_json(json!({
            "model": "deepseek-v4-pro",
            "reasoning_effort": "high",
            "thinking": {"type": "enabled"}
        })))
        .respond_with(closed_json_response(
            200,
            json!({
                "id": "chatcmpl-deepseek-v4-pro",
                "object": "chat.completion",
                "created": 1,
                "model": "deepseek-v4-pro",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "reasoning_content": "private reasoning",
                        "content": "final answer"
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 3,
                    "completion_tokens": 4,
                    "total_tokens": 7,
                    "completion_tokens_details": {"reasoning_tokens": 2}
                }
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "reason briefly"}],
            "thinking": {"type": "enabled"},
            "reasoning_effort": "high"
        }),
    )
    .await
    .expect("reasoning chat should succeed");

    assert_eq!(result["content"], "final answer");
    assert_eq!(result["reasoning_content"], "private reasoning");
    assert_eq!(result["content_bytes"], 12);
    assert_eq!(result["reasoning_content_bytes"], 17);
    assert!(!result.to_string().contains("reason briefly"));
    emit_fixture(
        "chat_reasoning_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-pro",
            "content_bytes": result["content_bytes"],
            "reasoning_content_bytes": result["reasoning_content_bytes"],
            "stream_chunk_count": 0,
            "http_status": 200,
            "retry_decision": "none",
            "error_mapping": "none",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn streaming_chat_assembles_reasoning_and_final_content_separately() {
    let server = MockServer::start().await;
    mount_unmatched_request_guard(&server).await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"deepseek-v4-pro\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"private \"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"deepseek-v4-pro\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"trace\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-3\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"deepseek-v4-pro\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"final\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-4\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"deepseek-v4-pro\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" answer\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(
            closed_response(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private prompt"}]}),
    )
    .await
    .expect("stream invoke should succeed");

    assert_eq!(result["content"], "final answer");
    assert_eq!(result["reasoning_content"], "private trace");
    assert_eq!(result["chunk_count"], 4);
    assert!(
        !result["chunks"].to_string().contains("private trace"),
        "chunk metadata must only log byte counts"
    );
    assert!(!result.to_string().contains("private prompt"));
    emit_fixture(
        "chat_stream_reasoning_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT_STREAM,
            "model_id": "deepseek-v4-pro",
            "content_bytes": result["content_bytes"],
            "reasoning_content_bytes": result["reasoning_content_bytes"],
            "stream_chunk_count": result["chunk_count"],
            "http_status": 200,
            "retry_decision": "none",
            "error_mapping": "none",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn models_list_is_cached_and_health_reuses_shared_client() {
    let server = MockServer::start().await;
    mount_unmatched_request_guard(&server).await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(header("authorization", "Bearer deepseek-test-key"))
        .respond_with(closed_json_response(
            200,
            json!({
                "object": "list",
                "data": [
                    {"id": "deepseek-v4-flash", "object": "model", "owned_by": "deepseek"},
                    {"id": "deepseek-v4-pro", "object": "model", "owned_by": "deepseek"}
                ]
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) =
        configured_connector(&server, &[CAP_MODELS, CAP_HEALTH], json!({})).await;
    let models_first = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should load");
    let models_cached = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should cache");
    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health should use cached models");

    assert_eq!(models_first["data"][0]["id"], "deepseek-v4-flash");
    assert_eq!(models_cached["data"][1]["id"], "deepseek-v4-pro");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["model_count"], 2);
    emit_fixture(
        "models_list_fixture",
        &json!({
            "status": "passed",
            "operation": OP_MODELS,
            "model_id": "deepseek-v4-flash,deepseek-v4-pro",
            "content_bytes": 0,
            "reasoning_content_bytes": 0,
            "stream_chunk_count": 0,
            "http_status": 200,
            "retry_decision": "cache-hit-after-miss",
            "error_mapping": "none",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn rate_limit_retry_waits_once_then_succeeds() {
    let server = MockServer::start().await;
    mount_unmatched_request_guard(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            closed_response(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({
                    "error": {"type": "rate_limit_error", "message": "too fast"}
                })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(closed_json_response(
            200,
            json!({
                "id": "chatcmpl-retry",
                "object": "chat.completion",
                "created": 1,
                "model": "deepseek-v4-flash",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "recovered"},
                    "finish_reason": "stop"
                }]
            }),
        ))
        .mount(&server)
        .await;

    let (connector, signing_key) =
        configured_connector(&server, &[CAP_CHAT], json!({"wait_on_rate_limit_ms": 1000})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect("retry should recover");

    assert_eq!(result["content"], "recovered");
    emit_fixture(
        "rate_limit_retry_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-pro",
            "content_bytes": result["content_bytes"],
            "reasoning_content_bytes": result["reasoning_content_bytes"],
            "stream_chunk_count": 0,
            "http_status": 429,
            "retry_decision": "retry-after-zero-once",
            "error_mapping": "rate_limit",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn provider_errors_map_to_fcp_and_redact_reasoning_content() {
    let server = MockServer::start().await;
    mount_unmatched_request_guard(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(closed_json_response(
            401,
            json!({
                "error": {
                    "type": "authentication_error",
                    "message": "bad Bearer should-not-leak",
                    "prompt": "private prompt",
                    "reasoning_content": "private reasoning"
                }
            }),
        ))
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
    assert!(!display.contains("private reasoning"));
    assert!(
        !redact_sensitive_text(r#"{"reasoning_content":"private reasoning"}"#)
            .contains("private reasoning")
    );
    emit_fixture(
        "provider_error_redaction_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-pro",
            "content_bytes": 0,
            "reasoning_content_bytes": 0,
            "stream_chunk_count": 0,
            "http_status": 401,
            "retry_decision": "none",
            "error_mapping": "unauthorized-redacted",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn request_timeout_maps_to_retryable_external_error() {
    let server = MockServer::start().await;
    mount_unmatched_request_guard(&server).await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            closed_response(200)
                .set_delay(Duration::from_millis(500))
                .set_body_json(json!({
                    "id": "late",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "deepseek-v4-pro",
                    "choices": []
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) =
        configured_connector(&server, &[CAP_CHAT], json!({"request_timeout_ms": 100})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect_err("timeout should fail");

    assert!(matches!(error, FcpError::External { .. }));
    emit_fixture(
        "timeout_fixture",
        &json!({
            "status": "passed",
            "operation": OP_CHAT,
            "model_id": "deepseek-v4-pro",
            "content_bytes": 0,
            "reasoning_content_bytes": 0,
            "stream_chunk_count": 0,
            "http_status": "timeout",
            "retry_decision": "retryable-external",
            "error_mapping": "timeout",
            "cleanup_result": "wiremock-dropped"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn embeddings_are_introspection_only_and_fail_before_network() {
    let server = MockServer::start().await;
    let (connector, signing_key) =
        configured_connector(&server, &[CAP_EMBEDDINGS], json!({})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"model": "text-embedding", "input": "hello"}),
    )
    .await
    .expect_err("embeddings are not supported");

    assert!(matches!(error, FcpError::InvalidRequest { .. }));
    assert!(error.to_string().contains("not supported"));
    emit_fixture(
        "embeddings_not_supported_fixture",
        &json!({
            "status": "passed",
            "operation": OP_EMBEDDINGS,
            "model_id": "n/a",
            "content_bytes": 0,
            "reasoning_content_bytes": 0,
            "stream_chunk_count": 0,
            "http_status": "not_dispatched",
            "retry_decision": "none",
            "error_mapping": "not_supported",
            "cleanup_result": "no-http-request"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(closed_json_response(
            200,
            json!({
                "object": "list",
                "data": [{"id": "deepseek-v4-pro", "object": "model", "owned_by": "deepseek"}]
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let (mut connector, signing_key) =
        configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let capability_grant =
        valid_token(&signing_key, connector.instance_id(), CAP_MODELS, OP_MODELS);
    let response = connector
        .invoke(test_invoke_request(
            "deepseek-models-suite",
            OP_MODELS,
            json!({}),
            capability_grant,
        ))
        .await
        .expect("invoke should return response");

    assert!(response.error.is_none(), "response should not carry error");
    assert_eq!(
        response.result.expect("result present")["data"][0]["id"],
        "deepseek-v4-pro"
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
}

#[test]
fn connector_id_matches_manifest_contract() {
    assert_eq!(CONNECTOR_ID, "fcp.deepseek");
}

#[fcp_async_core::runtime::test]
async fn canonical_admission_rejects_route_and_contract_changes_without_spending_grant() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(closed_json_response(200, chat_fixture("accepted")))
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_CHAT,
        &[OP_CHAT],
        Some(b"canonical-one-call"),
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
        ("input", json!({"messages": []})),
        (
            "input",
            json!({"messages": [{"role": "user", "content": "hello"}], "temperature": 3}),
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
            .handle_invoke(json!({"operation": OP_CHAT, "input": {}}))
            .await
            .is_err()
    );
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
    assert!(server.received_requests().await.unwrap().is_empty());
    let response = connector.invoke(request.clone()).await.unwrap();
    assert_eq!(response.result.unwrap()["content"], "accepted");
    assert_eq!(
        response.resource_uris,
        vec!["deepseek:model:deepseek-v4-pro"]
    );
    assert!(
        invoke_request(&connector, &request).await.is_err(),
        "raw path reused a consumed trait grant"
    );
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
}

#[fcp_async_core::runtime::test]
async fn effective_default_model_and_extension_shadowing_are_checked_before_dispatch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(body_partial_json(json!({"model":"deepseek-v4-flash"})))
        .respond_with(closed_json_response(200, chat_fixture("default")))
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(
        &server,
        &[CAP_CHAT],
        json!({"default_model":"deepseek-v4-flash"}),
    )
    .await;
    let input = json!({"messages":[{"role":"user","content":"hello"}]});
    let wrong_model_token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_CHAT,
        &[OP_CHAT],
        None,
        &CapabilityConstraints {
            resource_allow: vec!["deepseek:model:deepseek-v4-pro".into()],
            ..Default::default()
        },
    );
    assert!(
        invoke_request(
            &connector,
            &test_invoke_request("wrong-model", OP_CHAT, input.clone(), wrong_model_token)
        )
        .await
        .is_err()
    );
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_CHAT,
        &[OP_CHAT],
        Some(b"default-model-once"),
        &CapabilityConstraints {
            resource_allow: vec!["deepseek:model:deepseek-v4-flash".into()],
            max_calls: Some(1),
            ..Default::default()
        },
    );
    let request = test_invoke_request("default-model", OP_CHAT, input, token);
    let mut image_request = request.clone();
    image_request.input["messages"] = json!([{
        "role": "user",
        "content": [{"type":"image_url", "image_url":{"url":"https://example.com/input.png"}}]
    }]);
    assert!(
        invoke_request(&connector, &image_request).await.is_err(),
        "model-only grant authorized a remote image"
    );
    for (field, value) in [
        ("model", json!("deepseek-v4-pro")),
        ("messages", json!([])),
        ("stream", json!(true)),
        ("temperature", json!(3)),
        ("thinking", json!({"type":"unchecked"})),
        ("reasoning_effort", json!("unchecked")),
    ] {
        let mut invalid = request.clone();
        let mut extensions = serde_json::Map::new();
        extensions.insert(field.into(), value);
        invalid.input["provider_extensions"] = json!(extensions);
        assert!(
            invoke_request(&connector, &invalid).await.is_err(),
            "accepted shadow {field}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(
        invoke_request(&connector, &request).await.unwrap()["content"],
        "default"
    );
}

#[fcp_async_core::runtime::test]
async fn handshake_negotiation_rotation_and_failed_configuration_revoke_authority() {
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
    let value = connector
        .handle_handshake(serde_json::to_value(handshake).unwrap())
        .await
        .unwrap();
    assert_eq!(value["capabilities_granted"].as_array().unwrap().len(), 1);
    assert_eq!(value["instance_id"], json!(connector.instance_id()));
    assert_ne!(connector.instance_id(), &previous_instance);
    assert!(
        invoke_request(&connector, &old).await.is_err(),
        "old instance token survived rehandshake"
    );

    let current = test_invoke_request(
        "current",
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
    assert!(
        !connector.handle_health().await.unwrap()["handshaken"]
            .as_bool()
            .unwrap()
    );

    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_MODELS)],
            key.verifying_key().to_bytes(),
        ))
        .await
        .unwrap();
    let current = test_invoke_request(
        "configured",
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
async fn simulation_checks_authority_and_does_not_consume_call_budget() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(closed_json_response(
            200,
            json!({"object":"list", "data":[]}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_MODELS,
        &[OP_MODELS],
        Some(b"preview-once"),
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
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
    let mut wrong_zone = simulate.clone();
    wrong_zone.zone_id = ZoneId::private();
    assert!(!connector.simulate(wrong_zone).await.unwrap().would_succeed);
    assert!(server.received_requests().await.unwrap().is_empty());
    let request = test_invoke_request("after-preview", OP_MODELS, json!({}), token);
    assert!(invoke_request(&connector, &request).await.is_ok());
    assert!(!connector.simulate(simulate).await.unwrap().would_succeed);
}

#[fcp_async_core::runtime::test]
async fn signed_key_and_message_byte_limits_fence_requests_and_withhold_oversized_results() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(closed_json_response(200, chat_fixture(&"x".repeat(8_000))))
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let input = json!({"messages":[{"role":"user","content":"hello"}]});
    for (id, max_calls, max_bytes) in [("zero", Some(0), None), ("tiny", None, Some(1))] {
        let token = constrained_token(
            &key,
            connector.instance_id(),
            CAP_CHAT,
            &[OP_CHAT],
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
                &test_invoke_request(id, OP_CHAT, input.clone(), token)
            )
            .await
            .is_err()
        );
    }
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_CHAT,
        &[OP_CHAT],
        Some(b"key-and-bytes"),
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_calls: Some(1),
            max_bytes: Some(4096),
            idempotency_key: Some("required-key".into()),
            ..Default::default()
        },
    );
    let mut request = test_invoke_request("bounded-output", OP_CHAT, input, token);
    assert!(invoke_request(&connector, &request).await.is_err());
    request.idempotency_key = Some("wrong-key".into());
    assert!(invoke_request(&connector, &request).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
    request.idempotency_key = Some("required-key".into());
    let error = invoke_request(&connector, &request)
        .await
        .expect_err("oversized completion must be withheld");
    assert!(matches!(
        error,
        FcpError::External {
            retryable: false,
            ..
        }
    ));
    assert!(
        invoke_request(&connector, &request).await.is_err(),
        "oversized completion refunded a grant"
    );
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
}

#[fcp_async_core::runtime::test]
async fn caller_deadline_bounds_both_chat_and_stream_setup_without_refunding_calls() {
    for operation in [OP_CHAT, OP_CHAT_STREAM] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                closed_json_response(200, chat_fixture("late")).set_delay(Duration::from_secs(2)),
            )
            .expect(1)
            .mount(&server)
            .await;
        let (connector, key) =
            configured_connector(&server, &[CAP_CHAT], json!({"request_timeout_ms":2_000})).await;
        let token = constrained_token(
            &key,
            connector.instance_id(),
            CAP_CHAT,
            &[operation],
            Some(b"deadline-one-call"),
            &CapabilityConstraints {
                resource_allow: vec!["*".into()],
                max_calls: Some(1),
                ..Default::default()
            },
        );
        let mut request = test_invoke_request(
            "short-deadline",
            operation,
            json!({"messages":[{"role":"user","content":"hello"}]}),
            token,
        );
        request.deadline_ms = Some(200);
        let started = std::time::Instant::now();
        let error = invoke_request(&connector, &request)
            .await
            .expect_err("caller budget must win");
        assert!(matches!(
            error,
            FcpError::External {
                retryable: false,
                ..
            }
        ));
        assert!(started.elapsed() < Duration::from_millis(1_500));
        assert!(invoke_request(&connector, &request).await.is_err());
        assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
    }
}

#[fcp_async_core::runtime::test]
async fn expired_or_cancelled_native_context_refuses_before_debit_or_cache_access() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .respond_with(closed_json_response(
            200,
            json!({"object":"list", "data":[]}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_MODELS,
        &[OP_MODELS],
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
        // Both checkpoints are synchronous and must return before any await.
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
async fn credential_id_cannot_silently_bypass_missing_host_injection() {
    let server = MockServer::start().await;
    let mut connector = DeepSeekConnector::new();
    connector
        .handle_configure(json!({"credential_id":"vault-ref", "base_url":server.uri()}))
        .await
        .unwrap();
    let key = Ed25519SigningKey::generate();
    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_MODELS)],
            key.verifying_key().to_bytes(),
        ))
        .await
        .unwrap();
    let error = invoke(&connector, &key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("credential injection"));
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
}
