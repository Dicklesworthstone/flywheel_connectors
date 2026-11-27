#![allow(clippy::too_many_lines)]

use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_nvidia_nim::client::{
    DEFAULT_BASE_URL, DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, DEFAULT_RERANK_BASE_URL,
    DEFAULT_RERANK_MODEL, NvidiaNimAuth, NvidiaNimClient, NvidiaNimDeploymentMode,
    NvidiaNimProvider, NvidiaNimUrlPolicy, classify_nim_base_url, normalize_nim_base_url,
    normalize_nim_rerank_base_url,
};
use fcp_nvidia_nim::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_nvidia_nim::types::{
    RerankTruncate, chat_request_from_value, embeddings_request_from_value,
    rerank_request_from_value, validate_nim_model_id,
};
use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, EmbeddingInput, HttpRequest, OpenAiCompatProvider,
    RateLimitPolicy, header_value,
};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_CHAT: &str = "nvidia_nim.chat.completions";
const OP_CHAT_STREAM: &str = "nvidia_nim.chat.completions_stream";
const OP_EMBEDDINGS: &str = "nvidia_nim.embeddings.create";
const OP_RERANK: &str = "nvidia_nim.rerank";
const OP_MODELS: &str = "nvidia_nim.models.list";
const OP_HEALTH: &str = "nvidia_nim.health";

const CAP_CHAT: &str = "nvidia_nim.chat";
const CAP_EMBEDDINGS: &str = "nvidia_nim.embeddings";
const CAP_RERANK: &str = "nvidia_nim.rerank";
const CAP_MODELS: &str = "nvidia_nim.models.read";
const CAP_HEALTH: &str = "nvidia_nim.health.read";

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
        .zone_id("z:owner")
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
) -> (fcp_nvidia_nim::NvidiaNimConnector, Ed25519SigningKey) {
    let mut connector = fcp_nvidia_nim::NvidiaNimConnector::new();
    let mut config = serde_json::Map::new();
    config.insert("deployment_mode".into(), json!("self_hosted"));
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
    connector: &fcp_nvidia_nim::NvidiaNimConnector,
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

#[test]
fn provider_construction_auth_and_endpoint_policy_are_explicit() {
    let provider =
        NvidiaNimProvider::new(DEFAULT_BASE_URL, NvidiaNimAuth::ApiKey("nvidia-key".into()));
    let mut request = HttpRequest::default();
    provider.auth_header(&mut request);
    assert_eq!(
        header_value(&request.headers, "authorization"),
        Some("Bearer nvidia-key")
    );
    assert_eq!(provider.provider_name(), "nvidia_nim");

    let credential_provider = NvidiaNimProvider::new(
        DEFAULT_BASE_URL,
        NvidiaNimAuth::CredentialId("cred:nim".into()),
    );
    let mut credential_request = HttpRequest::default();
    credential_provider.auth_header(&mut credential_request);
    assert_eq!(
        header_value(&credential_request.headers, "x-fcp-credential-id"),
        Some("cred:nim")
    );

    let hosted_policy =
        NvidiaNimUrlPolicy::new(NvidiaNimDeploymentMode::Hosted, false, false, Vec::new());
    assert_eq!(
        normalize_nim_base_url(None, &hosted_policy).unwrap(),
        DEFAULT_BASE_URL
    );
    assert_eq!(classify_nim_base_url(DEFAULT_BASE_URL), "hosted_api");
    let (rerank_base, rerank_path) =
        normalize_nim_rerank_base_url(None, DEFAULT_BASE_URL, &hosted_policy).unwrap();
    assert_eq!(rerank_base, DEFAULT_RERANK_BASE_URL);
    assert_eq!(rerank_path, "/retrieval/nvidia/reranking");
    assert!(
        normalize_nim_base_url(Some("http://integrate.api.nvidia.com/v1"), &hosted_policy).is_err()
    );

    let self_hosted = NvidiaNimUrlPolicy::new(
        NvidiaNimDeploymentMode::SelfHosted,
        false,
        false,
        Vec::new(),
    );
    assert_eq!(
        normalize_nim_base_url(Some("http://localhost:8000/v1"), &self_hosted).unwrap(),
        "http://localhost:8000/v1"
    );
    let tailnet_only =
        NvidiaNimUrlPolicy::new(NvidiaNimDeploymentMode::SelfHosted, true, false, Vec::new());
    assert!(normalize_nim_base_url(Some("http://localhost:8000/v1"), &tailnet_only).is_err());
    let private_denied = NvidiaNimUrlPolicy::new(
        NvidiaNimDeploymentMode::SelfHosted,
        false,
        false,
        vec!["100.64.12.8".into()],
    );
    assert!(normalize_nim_base_url(Some("http://100.64.12.8:8000/v1"), &private_denied).is_err());
    let private_allowed = NvidiaNimUrlPolicy::new(
        NvidiaNimDeploymentMode::SelfHosted,
        false,
        true,
        vec!["100.64.12.8".into()],
    );
    assert_eq!(
        normalize_nim_base_url(Some("http://100.64.12.8:8000/v1"), &private_allowed).unwrap(),
        "http://100.64.12.8:8000/v1"
    );
    assert!(validate_nim_model_id("model", "nvidia/llama-nemotron-rerank-1b-v2").is_ok());
    assert!(validate_nim_model_id("model", "bad model").is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_hosted_without_auth_and_allows_self_hosted_no_auth() {
    let mut connector = fcp_nvidia_nim::NvidiaNimConnector::new();
    assert!(
        connector
            .handle_configure(json!({"deployment_mode": "hosted"}))
            .await
            .is_err()
    );
    let configured = connector
        .handle_configure(json!({
            "deployment_mode": "self_hosted",
            "base_url": "http://localhost:8000/v1"
        }))
        .await
        .expect("self-hosted local NIM may be unauthenticated");
    assert_eq!(configured["auth_mode"], "none");
    assert_eq!(configured["deployment_mode"], "self_hosted");
    assert_eq!(configured["rerank_endpoint"], "self_hosted_openai_ranking");
}

#[test]
fn request_builders_validate_nvext_embeddings_and_rerank_shapes() {
    let chat = chat_request_from_value(
        json!({
            "messages": [{"role": "user", "content": "private prompt"}],
            "nvext": {"hot_words": ["FCP"], "beam_width": 4}
        }),
        DEFAULT_MODEL,
    )
    .expect("chat request should parse");
    assert_eq!(chat.model, DEFAULT_MODEL);
    assert_eq!(chat.provider_extensions["nvext"]["beam_width"], 4);
    assert!(chat_request_from_value(json!({"messages": []}), DEFAULT_MODEL).is_err());

    let embeddings = embeddings_request_from_value(
        json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input": ["doc one", "doc two"],
            "encoding_format": "float"
        }),
        DEFAULT_EMBEDDING_MODEL,
    )
    .expect("embeddings request should parse");
    assert_eq!(
        embeddings.input,
        EmbeddingInput::Batch(vec!["doc one".into(), "doc two".into()])
    );
    assert!(embeddings_request_from_value(json!({"input": ""}), DEFAULT_EMBEDDING_MODEL).is_err());

    let rerank = rerank_request_from_value(
        json!({
            "query": {"text": "which passage?"},
            "passages": ["first", {"text": "second"}],
            "truncate": "END"
        }),
        DEFAULT_RERANK_MODEL,
    )
    .expect("rerank request should parse");
    assert_eq!(rerank.model, DEFAULT_RERANK_MODEL);
    assert_eq!(rerank.passages.len(), 2);
    assert_eq!(rerank.truncate, Some(RerankTruncate::End));
    assert!(
        rerank_request_from_value(
            json!({"query": "", "passages": ["a"]}),
            DEFAULT_RERANK_MODEL
        )
        .is_err()
    );
    assert!(
        rerank_request_from_value(json!({"query": "q", "passages": []}), DEFAULT_RERANK_MODEL)
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn chat_stream_embeddings_rerank_models_health_and_redaction_work_through_connector() {
    let server = MockServer::start().await;
    mount_models(&server, DEFAULT_MODEL, 1).await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({
            "model": DEFAULT_MODEL,
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false,
            "nvext": {"hot_words": ["FCP"]}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_body("fixture-response")))
        .expect(1)
        .mount(&server)
        .await;
    let sse = concat!(
        "data: {\"id\":\"chunk-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"meta/llama-3.1-8b-instruct\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chunk-2\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"meta/llama-3.1-8b-instruct\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(body_partial_json(json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input": "private embedding input"
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(embedding_body(DEFAULT_EMBEDDING_MODEL, 3)),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/ranking"))
        .and(body_partial_json(json!({
            "model": DEFAULT_RERANK_MODEL,
            "query": {"text": "secret query"},
            "passages": [{"text": "secret passage"}],
            "truncate": "END"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(rerank_body()))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = configured_connector(
        &server,
        &[CAP_CHAT, CAP_EMBEDDINGS, CAP_RERANK, CAP_MODELS, CAP_HEALTH],
        json!({}),
    )
    .await;
    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "nvext": {"hot_words": ["FCP"]}
        }),
    )
    .await
    .expect("chat should succeed");
    let stream = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private stream prompt"}]}),
    )
    .await
    .expect("stream should succeed");
    let embeddings = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"input": "private embedding input"}),
    )
    .await
    .expect("embeddings should succeed");
    let rerank = invoke(
        &connector,
        &signing_key,
        OP_RERANK,
        CAP_RERANK,
        json!({
            "query": "secret query",
            "passages": ["secret passage"],
            "truncate": "END"
        }),
    )
    .await
    .expect("rerank should succeed");
    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models should succeed");
    let health = invoke(&connector, &signing_key, OP_HEALTH, CAP_HEALTH, json!({}))
        .await
        .expect("health should reuse cached models");

    assert_eq!(chat["content"], "fixture-response");
    assert_eq!(stream["content"], "hello");
    assert_eq!(stream["chunk_count"], 2);
    assert_eq!(embeddings["dimensions"], 3);
    assert_eq!(rerank["ranking_count"], 2);
    assert_eq!(models["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(models["base_url_class"], "loopback");
    assert_eq!(health["status"], "ok");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");
    assert!(!doctor.to_string().contains("secret query"));
    assert!(!rerank.to_string().contains("secret passage"));
    assert!(!stream.to_string().contains("private stream prompt"));
}

#[fcp_async_core::runtime::test]
async fn auth_rate_limit_cancellation_and_shutdown_are_safe() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/ranking"))
        .and(header("authorization", "Bearer nim-key"))
        .and(body_partial_json(json!({"query": {"text": "retry query"}})))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({"error": {"message": "slow down"}})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/ranking"))
        .and(body_partial_json(json!({"query": {"text": "retry query"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(rerank_body()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "provider_error"})))
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

    let (mut connector, signing_key) = configured_connector(
        &server,
        &[CAP_CHAT, CAP_RERANK],
        json!({"api_key": "nim-key", "wait_on_rate_limit_ms": 1000}),
    )
    .await;
    let recovered = invoke(
        &connector,
        &signing_key,
        OP_RERANK,
        CAP_RERANK,
        json!({
            "query": "retry query",
            "passages": ["a", "b"]
        }),
    )
    .await
    .expect("retry should recover");
    assert_eq!(recovered["ranking_count"], 2);

    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "hello"}],
            "provider_extensions": {"fixture_case": "provider_error"}
        }),
    )
    .await
    .expect_err("401 should fail");
    assert!(matches!(error, FcpError::Unauthorized { .. }));
    assert!(!error.to_string().contains("should-not-leak"));
    assert!(!error.to_string().contains("private prompt"));

    let cx = fcp_async_core::compatibility_cx();
    cx.set_cancel_requested(true);
    let client = NvidiaNimClient::new(
        NvidiaNimProvider::new(format!("{}/v1", server.uri()), NvidiaNimAuth::None),
        format!("{}/v1", server.uri()),
        "/ranking",
        StdDuration::from_secs(5),
        StdDuration::from_secs(60),
        RateLimitPolicy::FailFast,
    );
    let cancelled = client
        .chat_completions(
            &cx,
            ChatCompletionsRequest::new(DEFAULT_MODEL, vec![ChatMessage::user_text("hello")]),
        )
        .await
        .expect_err("cancelled context should fail before dispatch");
    assert!(cancelled.to_string().contains("cancelled"));
    // compatibility_cx() returns the shared ambient runtime context, so clear
    // the cancel flag before the rest of the test drives the runtime again
    // (otherwise async Mutex locks observe the cancellation and panic).
    cx.set_cancel_requested(false);

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should pass");
    let health = connector
        .handle_health()
        .await
        .expect("health should serialize");
    assert_eq!(health["configured"], false);
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_validates_capability_token() {
    let server = MockServer::start().await;
    mount_models(&server, DEFAULT_MODEL, 1).await;

    let (mut connector, signing_key) =
        configured_connector(&server, &[CAP_MODELS], json!({})).await;
    let capability_grant =
        valid_token(&signing_key, connector.instance_id(), CAP_MODELS, OP_MODELS);
    let response = connector
        .invoke(test_invoke_request(
            "nvidia-nim-models-suite",
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
}

#[fcp_async_core::runtime::test]
async fn nvidia_nim_loopback_e2e_jsonl_matrix() {
    let git_revision =
        std::env::var("NVIDIA_NIM_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let server = MockServer::start().await;
    mount_models(&server, DEFAULT_MODEL, 1).await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "jsonl_chat"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(chat_body("jsonl-ok")))
        .mount(&server)
        .await;
    let sse = concat!(
        "data: {\"id\":\"chunk-a\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"meta/llama-3.1-8b-instruct\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(json!({"fixture_case": "jsonl_stream"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(embedding_body(DEFAULT_EMBEDDING_MODEL, 4)),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/ranking"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rerank_body()))
        .mount(&server)
        .await;

    let (mut connector, signing_key) = configured_connector(
        &server,
        &[CAP_CHAT, CAP_EMBEDDINGS, CAP_RERANK, CAP_MODELS, CAP_HEALTH],
        json!({"wait_on_rate_limit_ms": 1000}),
    )
    .await;

    let chat = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "private jsonl prompt"}],
            "provider_extensions": {"fixture_case": "jsonl_chat"}
        }),
    )
    .await
    .expect("jsonl chat should pass");
    emit_jsonl(
        &git_revision,
        "chat",
        "wiremock",
        "passed",
        json!({
            "deployment_mode": "self_hosted",
            "base_url_class": "loopback",
            "model_id_hash": blake3::hash(DEFAULT_MODEL.as_bytes()).to_hex().to_string(),
            "input_bytes": "private jsonl prompt".len(),
            "completion_bytes": chat["content"].as_str().unwrap_or_default().len(),
            "http_status": 200,
            "retry_decision": "not_retried"
        }),
    );

    let stream = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "private jsonl stream prompt"}],
            "provider_extensions": {"fixture_case": "jsonl_stream"}
        }),
    )
    .await
    .expect("jsonl stream should pass");
    emit_jsonl(
        &git_revision,
        "stream",
        "wiremock",
        "passed",
        json!({
            "deployment_mode": "self_hosted",
            "base_url_class": "loopback",
            "stream_chunk_count": stream["chunk_count"],
            "completion_bytes": stream["content"].as_str().unwrap_or_default().len(),
            "http_status": 200,
            "retry_decision": "not_retried"
        }),
    );

    let embeddings = invoke(
        &connector,
        &signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"input": "private jsonl embedding input"}),
    )
    .await
    .expect("jsonl embeddings should pass");
    emit_jsonl(
        &git_revision,
        "embeddings",
        "wiremock",
        "passed",
        json!({
            "deployment_mode": "self_hosted",
            "base_url_class": "loopback",
            "model_id_hash": blake3::hash(DEFAULT_EMBEDDING_MODEL.as_bytes()).to_hex().to_string(),
            "input_bytes": "private jsonl embedding input".len(),
            "embedding_dimensions": embeddings["dimensions"],
            "data_count": embeddings["data_count"],
            "http_status": 200,
            "retry_decision": "not_retried"
        }),
    );

    let rerank = invoke(
        &connector,
        &signing_key,
        OP_RERANK,
        CAP_RERANK,
        json!({
            "query": "private jsonl rerank query",
            "passages": ["private jsonl rerank passage"],
            "truncate": "END"
        }),
    )
    .await
    .expect("jsonl rerank should pass");
    emit_jsonl(
        &git_revision,
        "rerank",
        "wiremock",
        "passed",
        json!({
            "deployment_mode": "self_hosted",
            "rerank_endpoint": "self_hosted_openai_ranking",
            "rerank_base_url_class": "loopback",
            "model_id_hash": blake3::hash(DEFAULT_RERANK_MODEL.as_bytes()).to_hex().to_string(),
            "query_bytes": "private jsonl rerank query".len(),
            "passage_count": 1,
            "rerank_result_count": rerank["ranking_count"],
            "http_status": 200,
            "retry_decision": "not_retried"
        }),
    );

    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("jsonl models should pass");
    emit_jsonl(
        &git_revision,
        "models.list",
        "wiremock",
        "passed",
        json!({
            "deployment_mode": "self_hosted",
            "base_url_class": "loopback",
            "model_count": models["data"].as_array().map(Vec::len).unwrap_or_default(),
            "http_status": 200,
            "retry_decision": "not_retried"
        }),
    );

    let cx = fcp_async_core::compatibility_cx();
    cx.set_cancel_requested(true);
    let cancelled = NvidiaNimClient::new(
        NvidiaNimProvider::new(format!("{}/v1", server.uri()), NvidiaNimAuth::None),
        format!("{}/v1", server.uri()),
        "/ranking",
        StdDuration::from_secs(5),
        StdDuration::from_secs(60),
        RateLimitPolicy::FailFast,
    )
    .chat_completions(
        &cx,
        ChatCompletionsRequest::new(DEFAULT_MODEL, vec![ChatMessage::user_text("private")]),
    )
    .await
    .expect_err("cancelled context should fail");
    // Restore the shared ambient runtime context before further runtime use.
    cx.set_cancel_requested(false);
    emit_jsonl(
        &git_revision,
        "cancellation",
        "wiremock",
        "passed",
        json!({
            "deployment_mode": "self_hosted",
            "base_url_class": "loopback",
            "fcp_error_mapping": cancelled.to_string(),
            "retry_decision": "not_retried"
        }),
    );

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should pass");
    emit_jsonl(
        &git_revision,
        "cleanup",
        "wiremock",
        "passed",
        json!({
            "cleanup_result": "shutdown"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn nvidia_nim_hosted_smoke_or_structured_skip_jsonl() {
    let git_revision =
        std::env::var("NVIDIA_NIM_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let Ok(api_key) = std::env::var("NVIDIA_API_KEY") else {
        emit_jsonl(
            &git_revision,
            "hosted_smoke",
            "hosted",
            "skipped",
            json!({
                "deployment_mode": "hosted",
                "base_url_class": "hosted_api",
                "rerank_base_url_class": "hosted_retrieval",
                "skip_reason": "hosted credential environment variable is not set",
                "cleanup_result": "not_started_by_test"
            }),
        );
        return;
    };
    let model = std::env::var("NVIDIA_NIM_E2E_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.into());
    let mut connector = fcp_nvidia_nim::NvidiaNimConnector::new();
    connector
        .handle_configure(json!({
            "deployment_mode": "hosted",
            "api_key": api_key,
            "default_model": model,
            "request_timeout_ms": 30_000
        }))
        .await
        .expect("hosted configure should pass with NVIDIA_API_KEY");
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handshake(test_handshake_request(
            vec![CapabilityId::from_static(CAP_MODELS)],
            verifying_key.to_bytes(),
        ))
        .await
        .expect("handshake should succeed");
    let models = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({})).await;
    match models {
        Ok(models) => emit_jsonl(
            &git_revision,
            "hosted_models.list",
            "hosted",
            "passed",
            json!({
                "deployment_mode": "hosted",
                "base_url_class": "hosted_api",
                "model_count": models["data"].as_array().map(Vec::len).unwrap_or_default(),
                "http_status": 200,
                "cleanup_result": "shutdown_after_probe"
            }),
        ),
        Err(error) => emit_jsonl(
            &git_revision,
            "hosted_models.list",
            "hosted",
            "skipped",
            json!({
                "deployment_mode": "hosted",
                "base_url_class": "hosted_api",
                "skip_reason": error.to_string(),
                "cleanup_result": "shutdown_after_probe"
            }),
        ),
    }
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should pass");
}

#[test]
fn connector_id_matches_manifest_contract() {
    assert_eq!(CONNECTOR_ID, "fcp.nvidia_nim");
}

async fn mount_models(server: &MockServer, model: &str, expected_calls: u64) {
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [{
                "id": model,
                "object": "model",
                "owned_by": "nvidia",
                "created": 1_693_721_698
            }]
        })))
        .expect(expected_calls)
        .mount(server)
        .await;
}

fn chat_body(content: &str) -> Value {
    json!({
        "id": "chatcmpl-nim",
        "object": "chat.completion",
        "created": 1,
        "model": DEFAULT_MODEL,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
    })
}

fn embedding_body(model: &str, dimensions: usize) -> Value {
    json!({
        "object": "list",
        "model": model,
        "data": [{
            "object": "embedding",
            "index": 0,
            "embedding": vec![0.1_f32; dimensions]
        }],
        "usage": {"prompt_tokens": 2, "total_tokens": 2}
    })
}

fn rerank_body() -> Value {
    json!({
        "rankings": [
            {"index": 0, "logit": 0.75},
            {"index": 1, "logit": -1.0}
        ],
        "usage": {"prompt_tokens": 12, "total_tokens": 12}
    })
}

#[allow(clippy::needless_pass_by_value)]
fn emit_jsonl(
    git_revision: &str,
    operation: &str,
    fixture_mode: &str,
    status: &str,
    fields: Value,
) {
    let mut record = serde_json::Map::new();
    record.insert("event".into(), json!("nvidia_nim_fixture_operation"));
    record.insert("git_revision".into(), json!(git_revision));
    record.insert("fixture_mode".into(), json!(fixture_mode));
    record.insert("operation".into(), json!(operation));
    record.insert("status".into(), json!(status));
    record.insert(
        "command_line".into(),
        json!("cargo test -p fcp-nvidia-nim --test integration nvidia_nim_loopback_e2e_jsonl_matrix -- --nocapture"),
    );
    if let Some(fields) = fields.as_object() {
        for (key, value) in fields {
            record.insert(key.clone(), value.clone());
        }
    }
    println!("NVIDIA_NIM_E2E_JSONL {}", Value::Object(record));
}

#[fcp_async_core::runtime::test]
async fn ambiguous_rerank_posts_are_never_replayed_or_exposed_as_retryable() {
    for (status, body) in [
        (503, r#"{"error":{"message":"unavailable"}}"#),
        (502, r#"{"error":{"message":"upstream outcome unknown"}}"#),
        (200, "private malformed response"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/ranking"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("retry-after", "0")
                    .set_body_string(body),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = NvidiaNimClient::new(
            NvidiaNimProvider::new(format!("{}/v1", server.uri()), NvidiaNimAuth::None),
            format!("{}/v1", server.uri()),
            "/ranking",
            StdDuration::from_secs(5),
            StdDuration::from_secs(60),
            RateLimitPolicy::WaitForever,
        );
        let error = client
            .rerank(
                &fcp_async_core::compatibility_cx(),
                rerank_request_from_value(
                    json!({"query": "query", "passages": ["document"]}),
                    DEFAULT_RERANK_MODEL,
                )
                .unwrap(),
            )
            .await
            .expect_err("an ambiguous rerank outcome must not authorize replay");
        assert_eq!(
            error,
            fcp_openai_compat::OpenAiError::OutcomeUnknown {
                status: Some(status)
            }
        );
        let mapped = fcp_nvidia_nim::error::openai_error_to_fcp(&error);
        assert!(matches!(
            mapped,
            FcpError::External {
                retryable: false,
                retry_after: None,
                status_code: Some(observed),
                ..
            } if observed == status
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
