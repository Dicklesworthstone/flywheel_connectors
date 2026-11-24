#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_groq::GroqConnector;
use fcp_groq::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    InstanceId, RequestId, SimulateRequest, ZoneId,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "groq.chat.completions";
const OP_CHAT_STREAM: &str = "groq.chat.completions_stream";
const OP_MODELS: &str = "groq.models.list";
const OP_HEALTH: &str = "groq.health";
const OP_EMBEDDINGS: &str = "groq.embeddings.create";
const CAP_CHAT: &str = "groq.chat";
const CAP_MODELS: &str = "groq.models.read";
const CAP_HEALTH: &str = "groq.health.read";
const CAP_EMBEDDINGS: &str = "groq.embeddings";

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
) -> (GroqConnector, Ed25519SigningKey) {
    let mut connector = GroqConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("api_key".into(), json!("groq-test-key"));
    config.insert(
        "base_url".into(),
        json!(format!("{}/openai/v1", server.uri())),
    );
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
    connector: &GroqConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!(test_invoke_request(
            "groq-integration",
            operation,
            input,
            capability_grant,
        )))
        .await
}

#[fcp_async_core::runtime::test]
async fn chat_completions_uses_shared_oai_surface_and_redacted_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(header("authorization", "Bearer groq-test-key"))
        .and(body_partial_json(json!({
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-groq",
            "object": "chat.completion",
            "created": 1,
            "model": "llama-3.1-8b-instant",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "hello from Groq"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 3,
                "total_tokens": 5,
                "queue_time": 0.001,
                "prompt_time": 0.002,
                "completion_time": 0.003,
                "total_time": 0.006
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
        json!({"messages": [{"role": "user", "content": "hello"}]}),
    )
    .await
    .expect("chat invoke should succeed");

    assert_eq!(result["content"], "hello from Groq");
    assert_eq!(result["finish_reason"], "stop");
    assert_eq!(result["usage"]["total_tokens"], 5);
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(
        !doctor.to_string().contains("groq-test-key"),
        "doctor output must not leak API key"
    );
}

#[fcp_async_core::runtime::test]
async fn streaming_chat_assembles_sse_chunks_without_prompt_logs() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(header("authorization", "Bearer groq-test-key"))
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

    assert_eq!(result["content"], "hello");
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
        .and(path("/openai/v1/models"))
        .and(header("authorization", "Bearer groq-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{
                "id": "llama-3.1-8b-instant",
                "object": "model",
                "created": 1_693_721_698,
                "owned_by": "Meta",
                "active": true,
                "context_window": 131_072
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

    assert_eq!(models_first["data"][0]["id"], "llama-3.1-8b-instant");
    assert_eq!(models_cached["data"][0]["id"], "llama-3.1-8b-instant");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["model_count"], 1);
}

#[fcp_async_core::runtime::test]
async fn rate_limit_retry_waits_once_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .insert_header("x-ratelimit-remaining-requests", "0")
                .set_body_json(json!({
                    "error": {"type": "rate_limit_error", "message": "too fast"}
                })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "chatcmpl-retry",
            "object": "chat.completion",
            "created": 1,
            "model": "llama-3.1-8b-instant",
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
async fn unsupported_openai_fields_are_rejected_before_network() {
    let server = MockServer::start().await;
    let (connector, signing_key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello", "name": "operator"}],
            "logprobs": true
        }),
    )
    .await
    .expect_err("unsupported fields should fail locally");

    assert!(matches!(error, FcpError::InvalidRequest { .. }));
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openai/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{"id": "llama-3.1-8b-instant", "object": "model", "owned_by": "Meta"}]
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
            "groq-models-suite",
            OP_MODELS,
            json!({}),
            capability_grant,
        ))
        .await
        .expect("invoke should return response");

    assert!(response.error.is_none(), "response should not carry error");
    assert_eq!(
        response.result.expect("result present")["data"][0]["id"],
        "llama-3.1-8b-instant"
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
    assert_eq!(CONNECTOR_ID, "fcp.groq");
}

fn constrained_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    constraints: CapabilityConstraints,
    token_id: &[u8],
) -> CapabilityToken {
    let now = Utc::now();
    let mut encoded = Vec::new();
    ciborium::into_writer(&constraints, &mut encoded).unwrap();
    CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(CAP_CHAT)
            .zone_id("z:work")
            .principal("user:limited")
            .operations(&[OP_CHAT, OP_CHAT_STREAM])
            .issuer("node:test")
            .target_instance(instance_id.as_str())
            .token_id(token_id)
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&encoded)
            .unwrap()
            .sign(signing_key)
            .unwrap(),
    )
}

fn chat_reply(model: &str, content: &str) -> Value {
    json!({
        "id": "chatcmpl-admission", "object": "chat.completion", "created": 1,
        "model": model,
        "choices": [{"index":0, "message":{"role":"assistant", "content":content},
            "finish_reason":"stop"}]
    })
}

#[fcp_async_core::runtime::test]
async fn canonical_authority_and_input_denials_do_not_spend_the_same_finite_grant() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .and(body_partial_json(json!({"model":"configured-model"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(chat_reply("configured-model", "ok")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(
        &server,
        &[CAP_CHAT],
        json!({"default_model":"configured-model"}),
    )
    .await;
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CapabilityConstraints {
            resource_allow: vec!["groq:model:configured-model".into()],
            max_calls: Some(1),
            idempotency_key: Some("scope".into()),
            ..Default::default()
        },
        b"shared-finite-grant",
    );
    let mut valid = test_invoke_request(
        "valid",
        OP_CHAT,
        json!({"messages":[{"role":"user","content":"hello"}]}),
        token,
    );
    valid.idempotency_key = Some("scope".into());

    let mut invalid = valid.clone();
    invalid.connector_id = ConnectorId::from_static("fcp.deepseek");
    assert!(connector.invoke(invalid).await.is_err());
    let mut invalid = valid.clone();
    invalid.zone_id = ZoneId::owner();
    assert!(connector.invoke(invalid).await.is_err());
    let mut invalid = valid.clone();
    invalid.r#type = "simulate".into();
    assert!(connector.invoke(invalid).await.is_err());
    let mut invalid = valid.clone();
    invalid.id = RequestId::new("");
    assert!(connector.invoke(invalid).await.is_err());
    let mut invalid = valid.clone();
    invalid.deadline_ms = Some(0);
    assert!(connector.invoke(invalid).await.is_err());
    let mut invalid = valid.clone();
    invalid.idempotency_key = Some("different".into());
    assert!(connector.invoke(invalid).await.is_err());
    for input in [
        json!({"messages":[]}),
        json!({"messages":[{"role":"user","content":"hello"}],"top_p":2}),
        json!({"messages":[{"role":"user","content":"hello"}],"model":"llama-3.1-8b-instant"}),
        json!({"messages":[{"role":"user","content":"hello"}],
            "provider_extensions":{"model":"ungranted-model"}}),
        json!({"messages":[{"role":"user","content":[
            {"type":"image_url","image_url":{"url":"https://example.com/ungranted.png"}}
        ]}]}),
    ] {
        let mut invalid = valid.clone();
        invalid.input = input;
        assert!(connector.handle_invoke(json!(invalid)).await.is_err());
    }
    assert!(
        connector
            .handle_invoke(json!({
                "operation":OP_CHAT,"input":valid.input,"capability_token":valid.capability_token,
            }))
            .await
            .is_err(),
        "ad hoc invocation must not acquire implicit route authority"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 0);

    let simulation = SimulateRequest::new(
        valid.connector_id.clone(),
        valid.operation.clone(),
        valid.zone_id.clone(),
        valid.input.clone(),
        valid.capability_token.clone(),
    );
    assert!(
        connector
            .simulate(simulation.clone())
            .await
            .unwrap()
            .would_succeed
    );
    let output = connector.handle_invoke(json!(valid)).await.unwrap();
    assert_eq!(output["content"], "ok");
    let mut replay = valid;
    replay.id = RequestId::new("changed-request-id");
    assert!(
        connector.invoke(replay).await.is_err(),
        "raw and typed entry points share accounting"
    );
    assert!(!connector.simulate(simulation).await.unwrap().would_succeed);
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn handshake_negotiation_and_failed_lifecycle_changes_revoke_prior_tokens() {
    let server = MockServer::start().await;
    let (mut connector, key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let old = test_invoke_request(
        "old",
        OP_CHAT,
        json!({"messages":[{"role":"user","content":"hello"}]}),
        valid_token(&key, connector.instance_id(), CAP_CHAT, OP_CHAT),
    );
    let instance = connector.instance_id().clone();
    let response = connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static("unrelated.capability")],
            key.verifying_key().to_bytes(),
        ))
        .await
        .unwrap();
    assert!(response.capabilities_granted.is_empty());
    assert_ne!(connector.instance_id(), &instance);
    assert!(connector.invoke(old.clone()).await.is_err());
    let fresh = test_invoke_request(
        "unnegotiated",
        OP_CHAT,
        old.input.clone(),
        valid_token(&key, connector.instance_id(), CAP_CHAT, OP_CHAT),
    );
    assert!(connector.invoke(fresh).await.is_err());

    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_CHAT)],
            key.verifying_key().to_bytes(),
        ))
        .await
        .unwrap();
    let current = test_invoke_request(
        "current",
        OP_CHAT,
        old.input.clone(),
        valid_token(&key, connector.instance_id(), CAP_CHAT, OP_CHAT),
    );
    let mut wrong_zone = test_handshake_request(
        vec![CapabilityId::from_static(CAP_CHAT)],
        key.verifying_key().to_bytes(),
    );
    wrong_zone.zone = ZoneId::owner();
    assert!(connector.handshake(wrong_zone).await.is_err());
    assert!(matches!(
        connector.invoke(current).await,
        Err(FcpError::NotHandshaken)
    ));
    assert_eq!(
        connector.handle_health().await.unwrap()["handshaken"],
        false
    );

    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_CHAT)],
            key.verifying_key().to_bytes(),
        ))
        .await
        .unwrap();
    let mut unsupported = test_handshake_request(Vec::new(), key.verifying_key().to_bytes());
    unsupported.protocol_version = "1.0".into();
    assert!(connector.handshake(unsupported).await.is_err());
    assert_eq!(
        connector.handle_health().await.unwrap()["handshaken"],
        false
    );
    assert!(
        connector
            .handle_configure(json!({"api_key":false}))
            .await
            .is_err()
    );
    assert_eq!(
        connector.handle_health().await.unwrap()["configured"],
        false
    );
    assert!(matches!(
        connector.invoke(old).await,
        Err(FcpError::NotConfigured)
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn finite_byte_grants_withhold_oversized_results_and_remain_spent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_reply(
            "llama-3.1-8b-instant",
            &"private-output-sentinel".repeat(1024),
        )))
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = configured_connector(&server, &[CAP_CHAT], json!({})).await;
    let input = json!({"messages":[{"role":"user","content":"hello"}]});
    for (token_id, limit) in [(b"zero-calls".as_slice(), 0), (b"one-byte".as_slice(), 1)] {
        let token = constrained_token(
            &key,
            connector.instance_id(),
            CapabilityConstraints {
                resource_allow: vec!["*".into()],
                max_calls: Some(u32::from(limit != 0)),
                max_bytes: Some(limit),
                ..Default::default()
            },
            token_id,
        );
        assert!(
            connector
                .invoke(test_invoke_request("denied", OP_CHAT, input.clone(), token))
                .await
                .is_err()
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    let token = constrained_token(
        &key,
        connector.instance_id(),
        CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_calls: Some(1),
            max_bytes: Some(16_384),
            ..Default::default()
        },
        b"bounded-output",
    );
    let request = test_invoke_request("oversized", OP_CHAT, input, token);
    let error = connector.invoke(request.clone()).await.unwrap_err();
    assert!(matches!(
        error,
        FcpError::External {
            retryable: false,
            ..
        }
    ));
    assert!(!error.to_string().contains("private-output-sentinel"));
    assert!(connector.invoke(request).await.is_err());
    assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn secretless_configuration_cannot_send_credentials_or_direct_requests() {
    let server = MockServer::start().await;
    let mut connector = GroqConnector::new();
    connector
        .handle_configure(json!({"credential_id":"host-owned-credential",
        "base_url":format!("{}/openai/v1",server.uri())}))
        .await
        .unwrap();
    let key = Ed25519SigningKey::generate();
    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_CHAT)],
            key.verifying_key().to_bytes(),
        ))
        .await
        .unwrap();
    let request = test_invoke_request(
        "secretless",
        OP_CHAT,
        json!({"messages":[{"role":"user","content":"hello"}]}),
        valid_token(&key, connector.instance_id(), CAP_CHAT, OP_CHAT),
    );
    assert!(connector.invoke(request).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["requests"], 0);
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["auth_ready"], false);
    assert!(!connector.health().await.is_ready());
    let doctor = connector.handle_doctor().await.unwrap();
    assert_eq!(doctor["status"], "degraded");
    assert!(!doctor.to_string().contains("host-owned-credential"));
}
