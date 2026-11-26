#![allow(clippy::too_many_lines)]

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_cerebras::client::{CerebrasAuth, CerebrasProvider, normalize_cerebras_base_url};
use fcp_cerebras::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_cerebras::{CerebrasConnector, DEFAULT_MODEL};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_openai_compat::{
    OpenAiCompatProvider, RateLimitConfig, header_value, parse_rate_limit_headers,
};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, ConnectorId, FcpConnector, FcpError, InstanceId,
    InvokeRequest, OperationId, SimulateRequest, ZoneId,
};
use futures_util::FutureExt;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "cerebras.chat.completions";
const OP_CHAT_STREAM: &str = "cerebras.chat.completions_stream";
const OP_MODELS: &str = "cerebras.models.list";
const OP_HEALTH: &str = "cerebras.health";
const OP_EMBEDDINGS: &str = "cerebras.embeddings.create";
const CAP_CHAT: &str = "cerebras.chat";
const CAP_MODELS: &str = "cerebras.models.read";
const CAP_HEALTH: &str = "cerebras.health.read";
const CAP_EMBEDDINGS: &str = "cerebras.embeddings";

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
) -> (CerebrasConnector, Ed25519SigningKey) {
    let mut connector = CerebrasConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("cerebras-test-key"));
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

async fn invoke(
    connector: &CerebrasConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    invoke_request(
        connector,
        &test_invoke_request("cerebras-test", operation, input, capability_grant),
    )
    .await
}

async fn invoke_request(
    connector: &CerebrasConnector,
    request: &InvokeRequest,
) -> fcp_core::FcpResult<Value> {
    connector
        .handle_invoke(serde_json::to_value(request).expect("canonical invoke envelope"))
        .await
}

fn chat_fixture(content: &str) -> Value {
    json!({
        "id": "chatcmpl-admission",
        "object": "chat.completion",
        "created": 1,
        "model": DEFAULT_MODEL,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }]
    })
}

fn closed_json_response(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("connection", "close")
        .set_body_json(body)
}

#[test]
fn provider_construction_and_base_url_policy_are_strict() {
    let provider = CerebrasProvider::new(
        "https://api.cerebras.ai/v1",
        CerebrasAuth::ApiKey("secret".into()),
    );
    let mut request = fcp_openai_compat::HttpRequest::default();
    provider.auth_header(&mut request);

    assert_eq!(provider.provider_name(), "cerebras");
    assert_eq!(
        normalize_cerebras_base_url(None).unwrap(),
        "https://api.cerebras.ai/v1"
    );
    assert_eq!(
        header_value(&request.headers, "authorization"),
        Some("Bearer secret")
    );
    assert!(normalize_cerebras_base_url(Some("https://api.cerebras.ai/openai/v1")).is_err());
    assert!(normalize_cerebras_base_url(Some("https://example.com/v1")).is_err());
}

#[test]
fn cerebras_rate_limit_headers_parse_documented_and_cloudflare_shapes() {
    let provider = CerebrasProvider::new(
        "https://api.cerebras.ai/v1",
        CerebrasAuth::CredentialId("cred:cerebras".into()),
    );
    let headers = vec![
        (
            "x-ratelimit-limit-requests-day".to_string(),
            "30".to_string(),
        ),
        (
            "x-ratelimit-remaining-requests-day".to_string(),
            "7".to_string(),
        ),
        (
            "x-ratelimit-reset-requests-day".to_string(),
            "0.25".to_string(),
        ),
        (
            "x-ratelimit-limit-tokens-minute".to_string(),
            "64000".to_string(),
        ),
        (
            "x-ratelimit-remaining-tokens-minute".to_string(),
            "31999".to_string(),
        ),
        (
            "x-ratelimit-reset-tokens-minute".to_string(),
            "11.5".to_string(),
        ),
    ];
    let parsed = parse_rate_limit_headers(&headers, provider.rate_limit_overrides().as_ref());
    assert_eq!(parsed.request_limit, Some(30));
    assert_eq!(parsed.request_remaining, Some(7));
    assert_eq!(parsed.request_reset_after, Some(Duration::from_millis(250)));
    assert_eq!(parsed.token_limit, Some(64_000));
    assert_eq!(parsed.token_remaining, Some(31_999));
    assert_eq!(
        parsed.token_reset_after,
        Some(Duration::from_millis(11_500))
    );

    let cloudflare_headers = vec![("cf-ratelimit-remaining".to_string(), "5".to_string())];
    let cloudflare =
        parse_rate_limit_headers(&cloudflare_headers, Some(&RateLimitConfig::default()));
    assert_eq!(cloudflare.request_remaining, Some(5));
}

#[fcp_async_core::runtime::test]
async fn chat_completions_uses_shared_oai_surface_and_redacted_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer cerebras-test-key"))
        .and(body_partial_json(json!({
            "model": DEFAULT_MODEL,
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false,
            "max_completion_tokens": 8
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-cerebras",
            "object": "chat.completion",
            "created": 1,
            "model": DEFAULT_MODEL,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from Cerebras"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 3,
                "total_tokens": 5,
                "time_info": {"total_time": 0.006}
            }
        })))
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
            "messages": [{"role": "user", "content": "hello"}],
            "max_completion_tokens": 8
        }),
    )
    .await
    .expect("chat invoke should succeed");

    assert_eq!(result["content"], "hello from Cerebras");
    assert_eq!(result["finish_reason"], "stop");
    assert_eq!(result["usage"]["total_tokens"], 5);
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(
        !doctor.to_string().contains("cerebras-test-key"),
        "doctor output must not leak API key"
    );
}

#[fcp_async_core::runtime::test]
async fn streaming_chat_assembles_sse_chunks_without_prompt_logs() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.1-8b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"wafer\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.1-8b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" scale\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer cerebras-test-key"))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(
            ResponseTemplate::new(200)
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

    assert_eq!(result["content"], "wafer scale");
    assert_eq!(result["chunk_count"], 2);
    assert!(
        !result.to_string().contains("private prompt"),
        "stream response should not echo prompt"
    );
}

#[fcp_async_core::runtime::test]
async fn models_list_is_cached_and_health_reuses_shared_client() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", "Bearer cerebras-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{
                "id": DEFAULT_MODEL,
                "object": "model",
                "created": 1_721_692_800,
                "owned_by": "Meta"
            }]
        })))
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

    assert_eq!(models_first["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(models_cached["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(health["status"], "ok");
    assert_eq!(health["model_count"], 1);
}

#[fcp_async_core::runtime::test]
async fn rate_limit_retry_waits_once_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .insert_header("x-ratelimit-remaining-requests-day", "0")
                .set_body_json(json!({
                    "error": {"type": "rate_limit_error", "message": "too fast"}
                })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-retry",
            "object": "chat.completion",
            "created": 1,
            "model": DEFAULT_MODEL,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "recovered"},
                "finish_reason": "stop"
            }]
        })))
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
}

#[fcp_async_core::runtime::test]
async fn long_completion_response_is_handled_without_prompt_leakage() {
    let server = MockServer::start().await;
    let long_text = "x".repeat(1_024);
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-long",
            "object": "chat.completion",
            "created": 1,
            "model": DEFAULT_MODEL,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": long_text},
                "finish_reason": "length"
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1024, "total_tokens": 1026}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private prompt"}]}),
    )
    .await
    .expect("long response should succeed");

    assert_eq!(
        result["content"].as_str().expect("content string").len(),
        1_024
    );
    assert_eq!(result["usage"]["completion_tokens"], 1024);
    assert!(!result.to_string().contains("private prompt"));
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
}

#[fcp_async_core::runtime::test]
async fn invalid_chat_fields_are_rejected_before_network() {
    let server = MockServer::start().await;
    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 8,
            "max_completion_tokens": 8
        }),
    )
    .await
    .expect_err("duplicate token budgets should fail locally");

    assert!(matches!(error, FcpError::InvalidRequest { .. }));
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token_and_shutdown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": DEFAULT_MODEL, "object": "model", "owned_by": "Meta"}]
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
            "cerebras-models-suite",
            OP_MODELS,
            json!({}),
            capability_grant,
        ))
        .await
        .expect("invoke should return response");

    assert!(response.error.is_none(), "response should not carry error");
    assert_eq!(
        response.result.expect("result present")["data"][0]["id"],
        DEFAULT_MODEL
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
    assert!(matches!(
        health.status,
        fcp_prelude::HealthState::Error { .. }
    ));
}

#[test]
fn connector_id_matches_manifest_contract() {
    assert_eq!(CONNECTOR_ID, "fcp.cerebras");
}

#[fcp_async_core::runtime::test]
async fn canonical_admission_rejects_route_and_schema_changes_without_spending_grant() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(closed_json_response(200, chat_fixture("accepted")))
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_CHAT,
        OP_CHAT,
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
        ("connector_id", json!("fcp.deepseek")),
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
        vec![format!("cerebras:model:{DEFAULT_MODEL}")]
    );
    assert!(
        invoke_request(&connector, &request).await.is_err(),
        "raw invocation reused a grant consumed by the trait path"
    );
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
}

#[fcp_async_core::runtime::test]
async fn authorization_uses_configured_model_and_canonical_image_resources() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"model":"configured-model"})))
        .respond_with(closed_json_response(200, chat_fixture("default")))
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(
        &server,
        &[CAP_CHAT],
        json!({"default_model":"configured-model"}),
    )
    .await;
    let input = json!({"messages":[{"role":"user","content":"hello"}]});
    let wrong_model_token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_CHAT,
        OP_CHAT,
        None,
        &CapabilityConstraints {
            resource_allow: vec![format!("cerebras:model:{DEFAULT_MODEL}")],
            ..Default::default()
        },
    );
    assert!(
        invoke_request(
            &connector,
            &test_invoke_request("wrong-model", OP_CHAT, input.clone(), wrong_model_token),
        )
        .await
        .is_err()
    );
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_CHAT,
        OP_CHAT,
        Some(b"configured-model-once"),
        &CapabilityConstraints {
            resource_allow: vec!["cerebras:model:configured-model".into()],
            max_calls: Some(1),
            ..Default::default()
        },
    );
    let request = test_invoke_request("configured-model", OP_CHAT, input, token);
    let mut remote_image = request.clone();
    remote_image.input["messages"] = json!([{
        "role": "user",
        "content": [{"type":"image_url", "image_url":{"url":"https://example.com/input.png"}}]
    }]);
    assert!(
        invoke_request(&connector, &remote_image).await.is_err(),
        "model-only grant authorized a remote image"
    );
    for (field, value) in [
        ("model", json!(DEFAULT_MODEL)),
        ("messages", json!([])),
        ("stream", json!(true)),
        ("temperature", json!(3)),
    ] {
        let mut invalid = request.clone();
        let mut extensions = serde_json::Map::new();
        extensions.insert(field.into(), value);
        invalid.input["provider_extensions"] = json!(extensions);
        assert!(
            invoke_request(&connector, &invalid).await.is_err(),
            "accepted reserved extension {field}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(
        invoke_request(&connector, &request).await.unwrap()["content"],
        "default"
    );
}

#[fcp_async_core::runtime::test]
async fn handshake_filters_grants_and_retires_old_authority_even_on_failed_replacement() {
    let server = MockServer::start().await;
    let (mut connector, key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let previous_instance = connector.instance_id().clone();
    let old = test_invoke_request(
        "unnegotiated",
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
    assert!(invoke_request(&connector, &old).await.is_err());

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
        "before-configure",
        OP_MODELS,
        json!({}),
        valid_token(&key, connector.instance_id(), CAP_MODELS, OP_MODELS),
    );
    assert!(
        connector
            .handle_configure(json!({"api_key": ""}))
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
async fn simulation_checks_authority_without_consuming_call_allowance() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
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
        OP_MODELS,
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
    let mut request = test_invoke_request("after-preview", OP_MODELS, json!({}), token);
    request.idempotency_key = None;
    assert!(invoke_request(&connector, &request).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
    request.idempotency_key = Some("model-read".into());
    assert!(invoke_request(&connector, &request).await.is_ok());
    assert!(!connector.simulate(simulate).await.unwrap().would_succeed);
}

#[fcp_async_core::runtime::test]
async fn signed_key_and_byte_limits_withhold_oversized_responses_without_refund() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
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
            OP_CHAT,
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
                &test_invoke_request(id, OP_CHAT, input.clone(), token),
            )
            .await
            .is_err()
        );
    }
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CAP_CHAT,
        OP_CHAT,
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
async fn caller_deadline_bounds_chat_and_stream_setup_without_refunding_calls() {
    for operation in [OP_CHAT, OP_CHAT_STREAM] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
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
            operation,
            Some(b"deadline-once"),
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
async fn expired_and_cancelled_native_contexts_refuse_before_debit_or_provider_work() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
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
        OP_MODELS,
        Some(b"native-context-once"),
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
            .expect("invalid context must not poll I/O")
            .expect_err("invalid context must reject admission");
        drop(guard);
        assert!(!error.is_retryable());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
    assert!(invoke_request(&connector, &request).await.is_ok());
}

#[fcp_async_core::runtime::test]
async fn unsupported_credential_injection_fails_before_provider_dispatch() {
    let server = MockServer::start().await;
    let mut connector = CerebrasConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": "cred:cerebras",
            "base_url": format!("{}/v1", server.uri()),
        }))
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
        .expect_err("direct transport cannot inject a host credential");
    assert!(matches!(error, FcpError::InvalidRequest { .. }));
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);
}
