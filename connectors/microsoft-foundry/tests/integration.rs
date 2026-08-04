#![allow(clippy::too_many_lines)]

use std::fs::{OpenOptions, create_dir_all};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_microsoft_foundry::MicrosoftFoundryConnector;
use fcp_microsoft_foundry::client::{
    MicrosoftFoundryAuth, MicrosoftFoundryClient, MicrosoftFoundryEndpointClass,
    MicrosoftFoundryProvider,
};
use fcp_microsoft_foundry::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_microsoft_foundry::types::responses_request_from_value;
use fcp_openai_compat::{NetworkError, OpenAiError, RateLimitPolicy};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "microsoft_foundry.chat.completions";
const OP_CHAT_STREAM: &str = "microsoft_foundry.chat.completions_stream";
const OP_EMBEDDINGS: &str = "microsoft_foundry.embeddings.create";
const OP_MODELS: &str = "microsoft_foundry.deployments.list";
const OP_RESPONSES_CREATE: &str = "microsoft_foundry.responses.create";
const OP_RESPONSES_CANCEL: &str = "microsoft_foundry.responses.cancel";
const OP_RESPONSES_INPUT_ITEMS: &str = "microsoft_foundry.responses.input_items.list";
const OP_HEALTH: &str = "microsoft_foundry.health";
const CAP_CHAT: &str = "microsoft_foundry.chat";
const CAP_EMBEDDINGS: &str = "microsoft_foundry.embeddings";
const CAP_MODELS: &str = "microsoft_foundry.deployments.read";
const CAP_RESPONSES: &str = "microsoft_foundry.responses";
const CAP_HEALTH: &str = "microsoft_foundry.health";

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
) -> (MicrosoftFoundryConnector, Ed25519SigningKey) {
    let mut connector = MicrosoftFoundryConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("foundry-test-key"));
    config.insert(
        "base_url".into(),
        json!(format!("{}/openai/v1", server.uri())),
    );
    config.insert("default_model".into(), json!("prod-gpt4o"));
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
    connector: &MicrosoftFoundryConnector,
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
    std::env::var_os("MICROSOFT_FOUNDRY_CONNECTOR_E2E_JSONL").map(PathBuf::from)
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
    println!("MICROSOFT_FOUNDRY_CONNECTOR_E2E_JSONL={}", path.display());
    println!("MICROSOFT_FOUNDRY_CONNECTOR_E2E_RECORD={record}");
}

fn command_line() -> String {
    std::env::var("MICROSOFT_FOUNDRY_E2E_COMMAND_LINE")
        .unwrap_or_else(|_| std::env::args().collect::<Vec<_>>().join(" "))
}

fn git_revision() -> String {
    std::env::var("MICROSOFT_FOUNDRY_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".into())
}

fn log_operation(mode: &str, operation: &str, model: &str, outcome: &str, details: &Value) {
    append_e2e_record(&json!({
        "record_type": "microsoft_foundry_connector_e2e",
        "command_line": command_line(),
        "git_revision": git_revision(),
        "fixture_or_live_mode": mode,
        "provider_fixture_id": details.get("provider_fixture_id").and_then(Value::as_str).unwrap_or("foundry-loopback-v1"),
        "operation": operation,
        "provider": "microsoft_foundry",
        "model_or_deployment_id": model,
        "endpoint_class": details.get("endpoint_class").and_then(Value::as_str).unwrap_or("loopback_fixture"),
        "host_hash": details.get("host_hash").and_then(Value::as_str).unwrap_or("loopback"),
        "auth_policy": details.get("auth_policy").and_then(Value::as_str).unwrap_or("api_key"),
        "token_source_class": details.get("token_source_class").and_then(Value::as_str).unwrap_or("api_key_fixture"),
        "request_byte_count": details.get("request_byte_count").and_then(Value::as_u64).unwrap_or(0),
        "response_byte_count": details.get("response_byte_count").and_then(Value::as_u64).unwrap_or(0),
        "content_type": details.get("content_type").and_then(Value::as_str).unwrap_or("application/json"),
        "http_status": details.get("http_status").and_then(Value::as_u64).unwrap_or(200),
        "retry_decision": details.get("retry_decision").and_then(Value::as_str).unwrap_or("not_retried"),
        "fcp_error_mapping": details.get("fcp_error_mapping").and_then(Value::as_str).unwrap_or("none"),
        "cache_state": details.get("cache_state").and_then(Value::as_str).unwrap_or("not_applicable"),
        "cancellation_checkpoint": details.get("cancellation_checkpoint").and_then(Value::as_str).unwrap_or("not_cancelled"),
        "artifact_paths": details.get("artifact_paths").cloned().unwrap_or_else(|| json!([])),
        "cleanup_result": details.get("cleanup_result").cloned().unwrap_or_else(|| json!({"status": "wiremock_dropped"})),
        "skip_reason": details.get("skip_reason").and_then(Value::as_str).unwrap_or("not_skipped"),
        "outcome": outcome
    }));
}

fn response_fixture() -> Value {
    json!({
        "id": "resp_foundry_fixture",
        "object": "response",
        "created_at": 1,
        "model": "prod-gpt4o",
        "status": "completed",
        "output": [{
            "type": "message",
            "id": "msg_fixture",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "Foundry response ready."}]
        }],
        "usage": {
            "input_tokens": 11,
            "output_tokens": 12,
            "total_tokens": 23
        }
    })
}

#[fcp_async_core::runtime::test]
async fn microsoft_foundry_connector_wiremock_e2e() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(header("api-key", "foundry-test-key"))
        .and(body_partial_json(json!({
            "model": "prod-gpt4o",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-foundry",
            "object": "chat.completion",
            "created": 1,
            "model": "prod-gpt4o",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from Foundry"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"prod-gpt4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"prod-gpt4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(header("api-key", "foundry-test-key"))
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
        .and(path("/openai/v1/models"))
        .and(header("api-key", "foundry-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "prod-gpt4o", "object": "model", "owned_by": "azure"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/openai/v1/responses"))
        .and(header("api-key", "foundry-test-key"))
        .and(body_partial_json(
            json!({"model": "prod-gpt4o", "background": true}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(response_fixture()))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/openai/v1/responses/resp_foundry_fixture/cancel"))
        .and(header("api-key", "foundry-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "resp_foundry_fixture",
            "status": "cancelled"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(
            "/openai/v1/responses/resp_foundry_fixture/input_items",
        ))
        .and(header("api-key", "foundry-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "item_1", "type": "message"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/openai/v1/embeddings"))
        .and(header("api-key", "foundry-test-key"))
        .and(body_partial_json(
            json!({"model": "prod-embedding", "input": "hello"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "model": "prod-embedding",
            "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
            "usage": {"prompt_tokens": 1, "total_tokens": 1}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(
        &server,
        &[
            CAP_CHAT,
            CAP_MODELS,
            CAP_RESPONSES,
            CAP_EMBEDDINGS,
            CAP_HEALTH,
        ],
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
    assert_eq!(chat["content"], "hello from Foundry");
    log_operation(
        "fixture",
        OP_CHAT,
        "prod-gpt4o",
        "passed",
        &json!({"response_byte_count": chat.to_string().len()}),
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
    assert!(!stream.to_string().contains("private prompt"));
    log_operation(
        "fixture",
        OP_CHAT_STREAM,
        "prod-gpt4o",
        "passed",
        &json!({"response_byte_count": stream.to_string().len(), "content_type": "text/event-stream"}),
    );

    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should load");
    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health should reuse cached models");
    assert_eq!(models["data"][0]["id"], "prod-gpt4o");
    assert_eq!(health["status"], "ok");
    log_operation(
        "fixture",
        OP_MODELS,
        "prod-gpt4o",
        "passed",
        &json!({"response_byte_count": models.to_string().len(), "cache_state": "miss_then_cached"}),
    );

    let responses = invoke(
        &connector,
        &signing_key,
        OP_RESPONSES_CREATE,
        CAP_RESPONSES,
        json!({
            "model": "prod-gpt4o",
            "input": [{"role": "user", "content": "Summarize privately"}],
            "background": true,
            "store": false
        }),
    )
    .await
    .expect("responses invoke should succeed");
    assert_eq!(responses["status"], "completed");
    assert_eq!(responses["usage"]["total_tokens"], 23);
    log_operation(
        "fixture",
        OP_RESPONSES_CREATE,
        "prod-gpt4o",
        "passed",
        &json!({"response_byte_count": responses.to_string().len()}),
    );

    let cancel = invoke(
        &connector,
        &signing_key,
        OP_RESPONSES_CANCEL,
        CAP_RESPONSES,
        json!({"response_id": "resp_foundry_fixture"}),
    )
    .await
    .expect("cancel should succeed");
    assert_eq!(cancel["raw"]["status"], "cancelled");
    log_operation(
        "fixture",
        OP_RESPONSES_CANCEL,
        "prod-gpt4o",
        "passed",
        &json!({"response_byte_count": cancel.to_string().len()}),
    );

    let input_items = invoke(
        &connector,
        &signing_key,
        OP_RESPONSES_INPUT_ITEMS,
        CAP_RESPONSES,
        json!({"response_id": "resp_foundry_fixture"}),
    )
    .await
    .expect("input items should succeed");
    assert_eq!(input_items["raw"]["data"][0]["type"], "message");
    log_operation(
        "fixture",
        OP_RESPONSES_INPUT_ITEMS,
        "prod-gpt4o",
        "passed",
        &json!({"response_byte_count": input_items.to_string().len()}),
    );

    let embeddings = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"model": "prod-embedding", "input": "hello"}),
    )
    .await
    .expect("embeddings should succeed");
    assert_eq!(embeddings["embedding_count"], 1);
    assert_eq!(embeddings["dimensions"], 3);
    assert!(!embeddings.to_string().contains("private prompt"));
    log_operation(
        "fixture",
        OP_EMBEDDINGS,
        "prod-embedding",
        "passed",
        &json!({"response_byte_count": embeddings.to_string().len()}),
    );

    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(!doctor.to_string().contains("foundry-test-key"));
}

#[fcp_async_core::runtime::test]
async fn auth_modes_emit_expected_headers_and_redacted_doctor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openai/v1/models"))
        .and(header("authorization", "Bearer entra-test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "prod-gpt4o", "object": "model"}]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(
        &server,
        &[CAP_MODELS],
        json!({"api_key": Value::Null, "entra_access_token": "entra-test-token"}),
    )
    .await;
    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("entra token should work");
    assert_eq!(models["data"][0]["id"], "prod-gpt4o");
    let doctor = connector.handle_doctor().await.expect("doctor should work");
    assert!(!doctor.to_string().contains("entra-test-token"));
}

#[fcp_async_core::runtime::test]
async fn rate_limit_retry_waits_once_then_succeeds_for_responses_api() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/responses"))
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
        .and(path("/openai/v1/responses"))
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
        OP_RESPONSES_CREATE,
        CAP_RESPONSES,
        json!({"input": "hello"}),
    )
    .await
    .expect("retry should recover");

    assert_eq!(result["status"], "completed");
}

#[fcp_async_core::runtime::test]
async fn provider_errors_map_to_fcp_and_redact_sensitive_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
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
        .and(path("/openai/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(75))
                .set_body_json(response_fixture()),
        )
        .mount(&server)
        .await;

    let provider = MicrosoftFoundryProvider::new(
        format!("{}/openai/v1", server.uri()),
        MicrosoftFoundryEndpointClass::Loopback,
        MicrosoftFoundryAuth::ApiKey("key".into()),
    );
    let client = MicrosoftFoundryClient::new(
        provider.clone(),
        Duration::from_millis(5),
        Duration::from_secs(60),
        RateLimitPolicy::FailFast,
    );
    let request =
        responses_request_from_value(json!({"input": "hello"}), "prod-gpt4o").expect("request");
    let timeout_error = client
        .responses_create(&fcp_async_core::compatibility_cx(), request)
        .await
        .expect_err("slow server should time out");
    assert!(matches!(
        timeout_error,
        OpenAiError::Network(NetworkError::Http { .. })
    ));

    let cx = fcp_async_core::compatibility_cx();
    cx.set_cancel_requested(true);
    let client = MicrosoftFoundryClient::new(
        provider,
        Duration::from_secs(5),
        Duration::from_secs(60),
        RateLimitPolicy::FailFast,
    );
    let request =
        responses_request_from_value(json!({"input": "hello"}), "prod-gpt4o").expect("request");
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
    log_operation(
        "fixture",
        OP_RESPONSES_CREATE,
        "prod-gpt4o",
        "passed",
        &json!({
            "http_status": 0,
            "retry_decision": "not_retried",
            "fcp_error_mapping": "cancelled",
            "cancellation_checkpoint": "pre_dispatch"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token_and_shutdown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openai/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "prod-gpt4o", "object": "model", "owned_by": "azure"}]
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
            "foundry-models-suite",
            OP_MODELS,
            json!({}),
            capability_grant,
        ))
        .await
        .expect("invoke should return response");

    assert!(response.error.is_none(), "response should not carry error");
    assert_eq!(
        response.result.expect("result present")["data"][0]["id"],
        "prod-gpt4o"
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

#[fcp_async_core::runtime::test]
async fn microsoft_foundry_live_smoke_e2e() {
    let Some(base_url) = std::env::var("MICROSOFT_FOUNDRY_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        log_operation(
            "live",
            OP_MODELS,
            "provider-enabled",
            "skipped",
            &json!({
                "http_status": 0,
                "retry_decision": "not_started",
                "fcp_error_mapping": "not_applicable",
                "cleanup_result": {"status": "not_started"},
                "skip_reason": "MICROSOFT_FOUNDRY_BASE_URL not set"
            }),
        );
        return;
    };
    let Some(api_key) = std::env::var("MICROSOFT_FOUNDRY_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        log_operation(
            "live",
            OP_MODELS,
            "provider-enabled",
            "skipped",
            &json!({
                "http_status": 0,
                "retry_decision": "not_started",
                "fcp_error_mapping": "not_applicable",
                "cleanup_result": {"status": "not_started"},
                "skip_reason": "MICROSOFT_FOUNDRY_API_KEY not set"
            }),
        );
        return;
    };

    let mut connector = MicrosoftFoundryConnector::new();
    connector
        .handle_configure(json!({
            "api_key": api_key,
            "base_url": base_url,
            "request_timeout_ms": 30_000,
            "model_cache_ttl_seconds": 1
        }))
        .await
        .expect("live configure should succeed");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_MODELS)],
            signing_key.verifying_key().to_bytes(),
        ))
        .await
        .expect("live handshake should succeed");
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
        "passed",
        &json!({"response_byte_count": result.to_string().len(), "http_status": 200}),
    );
}

#[test]
fn connector_id_matches_manifest_contract() {
    assert_eq!(CONNECTOR_ID, "fcp.microsoft-foundry");
}
