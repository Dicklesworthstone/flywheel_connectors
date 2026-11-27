#![allow(clippy::too_many_lines)]

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_openai_compat::{
    EmbeddingInput, HttpRequest, OpenAiCompatProvider, RateLimitPolicy, header_value,
};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, InstanceId,
};
use fcp_voyage::client::{
    DEFAULT_BASE_URL, DEFAULT_EMBEDDING_MODEL, DEFAULT_MULTIMODAL_MODEL, DEFAULT_RERANK_MODEL,
    VoyageAuth, VoyageClient, VoyageProvider, normalize_voyage_base_url,
};
use fcp_voyage::connector::{CONNECTOR_ID, test_handshake_request, test_invoke_request};
use fcp_voyage::types::{
    documented_model_catalog_value, embeddings_request_from_value, multimodal_request_from_value,
    rerank_request_from_value,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

const OP_EMBEDDINGS: &str = "voyage.embeddings.create";
const OP_RERANK: &str = "voyage.rerank";
const OP_MODELS: &str = "voyage.models.list";
const OP_HEALTH: &str = "voyage.health";

const CAP_EMBEDDINGS: &str = "voyage.embeddings";
const CAP_RERANK: &str = "voyage.rerank";
const CAP_MODELS: &str = "voyage.models.read";
const CAP_HEALTH: &str = "voyage.health.read";

#[test]
fn provider_construction_auth_and_base_url_policy() {
    let provider = VoyageProvider::new(DEFAULT_BASE_URL, VoyageAuth::ApiKey("voyage-key".into()));
    let mut request = HttpRequest::default();
    provider.auth_header(&mut request);
    assert_eq!(
        header_value(&request.headers, "authorization"),
        Some("Bearer voyage-key")
    );
    assert_eq!(provider.provider_name(), "voyage");
    assert_eq!(normalize_voyage_base_url(None).unwrap(), DEFAULT_BASE_URL);
    assert!(normalize_voyage_base_url(Some("https://api.voyageai.com/v2")).is_err());
    assert!(normalize_voyage_base_url(Some("https://example.com/v1")).is_err());

    let credential_provider = VoyageProvider::new(
        DEFAULT_BASE_URL,
        VoyageAuth::CredentialId("cred:voyage".into()),
    );
    let mut credential_request = HttpRequest::default();
    credential_provider.auth_header(&mut credential_request);
    assert_eq!(
        header_value(&credential_request.headers, "x-fcp-credential-id"),
        Some("cred:voyage")
    );
}

#[test]
fn request_builders_validate_voyage_specific_fields() {
    let request = embeddings_request_from_value(
        json!({
            "model": "voyage-3.5",
            "input": ["query one", "query two"],
            "input_type": "query",
            "truncation": false,
            "output_dimension": 512,
            "output_dtype": "float"
        }),
        DEFAULT_EMBEDDING_MODEL,
    )
    .expect("embeddings request should parse");
    assert_eq!(
        request.input,
        EmbeddingInput::Batch(vec!["query one".into(), "query two".into()])
    );
    assert_eq!(request.provider_extensions["input_type"], "query");
    assert_eq!(request.provider_extensions["output_dimension"], 512);
    assert!(request.dimensions.is_none());

    assert!(
        embeddings_request_from_value(
            json!({"input": "", "input_type": "document"}),
            DEFAULT_EMBEDDING_MODEL
        )
        .is_err()
    );
    assert!(
        embeddings_request_from_value(
            json!({"input": "x", "output_dimension": 123}),
            DEFAULT_EMBEDDING_MODEL,
        )
        .is_err()
    );

    let rerank = rerank_request_from_value(
        json!({"query": "find", "documents": ["a", "b"], "top_k": 1}),
        DEFAULT_RERANK_MODEL,
    )
    .expect("rerank request should parse");
    assert_eq!(rerank.model, DEFAULT_RERANK_MODEL);
    assert_eq!(rerank.top_k, Some(1));
    assert!(
        rerank_request_from_value(
            json!({"query": "", "documents": ["a"]}),
            DEFAULT_RERANK_MODEL
        )
        .is_err()
    );
    assert!(
        rerank_request_from_value(
            json!({"query": "q", "documents": ["a"], "top_k": 2}),
            DEFAULT_RERANK_MODEL
        )
        .is_err()
    );

    let multimodal = multimodal_request_from_value(
        json!({
            "inputs": [{"content": [{"type": "text", "text": "chart"}]}],
            "input_type": "document",
            "output_encoding": "base64"
        }),
        DEFAULT_MULTIMODAL_MODEL,
    )
    .expect("multimodal request should parse");
    assert_eq!(multimodal.model, DEFAULT_MULTIMODAL_MODEL);
    assert_eq!(multimodal.inputs.len(), 1);
}

#[fcp_async_core::runtime::test]
async fn embeddings_request_uses_voyage_endpoint_and_redacts_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(header("authorization", "Bearer voyage-fixture-key"))
        .and(body_partial_json(json!({
            "model": DEFAULT_EMBEDDING_MODEL,
            "input_type": "document",
            "output_dimension": 512
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(embedding_body(DEFAULT_EMBEDDING_MODEL, 2)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = VoyageClient::new(
        VoyageProvider::new(
            format!("{}/v1", server.uri()),
            VoyageAuth::ApiKey("voyage-fixture-key".into()),
        ),
        Duration::from_secs(5),
        Duration::from_secs(60),
        RateLimitPolicy::FailFast,
    );
    let response = client
        .embeddings(
            &fcp_async_core::compatibility_cx(),
            embeddings_request_from_value(
                json!({
                    "model": DEFAULT_EMBEDDING_MODEL,
                    "input": ["private query", "private doc"],
                    "input_type": "document",
                    "output_dimension": 512
                }),
                DEFAULT_EMBEDDING_MODEL,
            )
            .unwrap(),
        )
        .await
        .expect("embeddings should succeed");
    assert_eq!(response.data.len(), 1);
    assert_eq!(response.data[0].embedding.len(), 2);
    assert!(!format!("{:?}", client.provider().auth()).contains("private query"));
}

#[fcp_async_core::runtime::test]
async fn rerank_and_multimodal_use_direct_voyage_endpoints() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/rerank"))
        .and(header("authorization", "Bearer voyage-fixture-key"))
        .and(body_partial_json(json!({
            "model": DEFAULT_RERANK_MODEL,
            "top_k": 1,
            "return_documents": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "model": DEFAULT_RERANK_MODEL,
            "data": [{"index": 1, "relevance_score": 0.91}],
            "usage": {"total_tokens": 8}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/multimodalembeddings"))
        .and(header("authorization", "Bearer voyage-fixture-key"))
        .and(body_partial_json(json!({
            "model": DEFAULT_MULTIMODAL_MODEL,
            "input_type": "query",
            "output_encoding": "base64"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "model": DEFAULT_MULTIMODAL_MODEL,
            "data": [{"index": 0, "embedding": [0.1, 0.2]}],
            "usage": {"total_tokens": 3}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = VoyageClient::new(
        VoyageProvider::new(
            format!("{}/v1", server.uri()),
            VoyageAuth::ApiKey("voyage-fixture-key".into()),
        ),
        Duration::from_secs(5),
        Duration::from_secs(60),
        RateLimitPolicy::FailFast,
    );
    let rerank = client
        .rerank(
            &fcp_async_core::compatibility_cx(),
            rerank_request_from_value(
                json!({
                    "query": "private query",
                    "documents": ["private a", "private b"],
                    "top_k": 1,
                    "return_documents": false
                }),
                DEFAULT_RERANK_MODEL,
            )
            .unwrap(),
        )
        .await
        .expect("rerank should succeed");
    assert_eq!(rerank["data"][0]["index"], 1);

    let multimodal = client
        .multimodal_embeddings(
            &fcp_async_core::compatibility_cx(),
            multimodal_request_from_value(
                json!({
                    "inputs": [{"content": [{"type": "text", "text": "private chart"}]}],
                    "input_type": "query",
                    "output_encoding": "base64"
                }),
                DEFAULT_MULTIMODAL_MODEL,
            )
            .unwrap(),
        )
        .await
        .expect("multimodal embeddings should succeed");
    assert_eq!(multimodal["data"][0]["index"], 0);
}

#[fcp_async_core::runtime::test]
async fn voyage_rate_limit_maps_to_fcp_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "1")
                .set_body_json(json!({"detail": "rate limited"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut connector = configured_connector(
        json!({
            "api_key": "voyage-fixture-key",
            "base_url": format!("{}/v1", server.uri()),
            "wait_on_rate_limit_ms": 1
        }),
        &[CAP_EMBEDDINGS],
    )
    .await;
    let error = invoke(
        &connector.connector,
        &connector.signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"input": "private text"}),
    )
    .await
    .expect_err("rate limit should map to FCP error");
    assert!(matches!(error, FcpError::RateLimited { .. }));
    connector
        .connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
}

#[fcp_async_core::runtime::test]
async fn fcp_connector_trait_happy_path_and_catalogs() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(embedding_body(DEFAULT_EMBEDDING_MODEL, 2)),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/rerank"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "model": DEFAULT_RERANK_MODEL,
            "data": [{"index": 0, "relevance_score": 0.99}],
            "usage": {"total_tokens": 5}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let configured = configured_connector(
        json!({
            "api_key": "voyage-fixture-key",
            "base_url": format!("{}/v1", server.uri())
        }),
        &[CAP_EMBEDDINGS, CAP_RERANK, CAP_MODELS, CAP_HEALTH],
    )
    .await;
    assert_eq!(configured.connector.id().as_str(), CONNECTOR_ID);
    let embeddings = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_EMBEDDINGS,
        CAP_EMBEDDINGS,
        json!({"input": "private text", "input_type": "document"}),
    )
    .await
    .expect("embeddings should succeed");
    let first_embedding = embeddings["data"][0]["embedding"][0]
        .as_f64()
        .expect("embedding element should be numeric");
    assert!((first_embedding - 0.1).abs() < 1e-6);

    let rerank = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_RERANK,
        CAP_RERANK,
        json!({"query": "private q", "documents": ["private d"]}),
    )
    .await
    .expect("rerank should succeed");
    assert_eq!(rerank["result_count"], 1);

    let models = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_MODELS,
        CAP_MODELS,
        json!({}),
    )
    .await
    .expect("models should succeed");
    assert!(
        models["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|model| model["id"] == "voyage-code-3")
    );

    let health = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_HEALTH,
        CAP_HEALTH,
        json!({}),
    )
    .await
    .expect("health should succeed");
    assert_eq!(
        health["model_count"].as_u64().unwrap(),
        u64::try_from(documented_model_catalog_value().len()).unwrap()
    );
}

fn embedding_body(model: &str, total_tokens: u32) -> Value {
    json!({
        "object": "list",
        "model": model,
        "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
        "usage": {"prompt_tokens": total_tokens, "total_tokens": total_tokens}
    })
}

async fn configured_connector(config: Value, capabilities: &[&'static str]) -> ConfiguredVoyage {
    let mut connector = fcp_voyage::VoyageConnector::new();
    connector
        .handle_configure(config)
        .await
        .expect("Voyage connector should configure");
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let requested = capabilities
        .iter()
        .map(|capability| CapabilityId::from_static(capability))
        .collect();
    connector
        .handshake(test_handshake_request(requested, verifying_key.to_bytes()))
        .await
        .expect("Voyage connector handshake should succeed");
    ConfiguredVoyage {
        connector,
        signing_key,
    }
}

struct ConfiguredVoyage {
    connector: fcp_voyage::VoyageConnector,
    signing_key: Ed25519SigningKey,
}

async fn invoke(
    connector: &fcp_voyage::VoyageConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let capability_grant = valid_token(signing_key, connector.instance_id(), capability, operation);
    let response = connector
        .invoke(test_invoke_request(
            "voyage-test",
            operation,
            input,
            capability_grant,
        ))
        .await?;
    if let Some(error) = response.error {
        Err(error)
    } else {
        response.result.ok_or_else(|| FcpError::Internal {
            message: "Voyage invoke response had neither result nor error".into(),
        })
    }
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints serialize");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:voyage-test")
        .operations(&[operation])
        .issuer("node:voyage-test")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(cose)
}

#[fcp_async_core::runtime::test]
async fn ambiguous_direct_inference_posts_are_never_replayed() {
    for multimodal in [false, true] {
        for (status, body) in [
            (503, r#"{"error":{"type":"service_unavailable"}}"#),
            (409, r#"{"error":{"type":"rate_limit_error"}}"#),
            (200, "private malformed response"),
        ] {
            let server = MockServer::start().await;
            let endpoint = if multimodal {
                "/v1/multimodalembeddings"
            } else {
                "/v1/rerank"
            };
            Mock::given(method("POST"))
                .and(path(endpoint))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("retry-after", "0")
                        .set_body_string(body),
                )
                .expect(1)
                .mount(&server)
                .await;
            let client = VoyageClient::new(
                VoyageProvider::new(
                    format!("{}/v1", server.uri()),
                    VoyageAuth::ApiKey("key".into()),
                ),
                Duration::from_secs(5),
                Duration::from_secs(60),
                RateLimitPolicy::WaitForever,
            );
            let cx = fcp_async_core::compatibility_cx();
            let error = if multimodal {
                client
                    .multimodal_embeddings(
                        &cx,
                        multimodal_request_from_value(
                            json!({"inputs": [{"content": [{"type": "text", "text": "chart"}]}]}),
                            DEFAULT_MULTIMODAL_MODEL,
                        )
                        .unwrap(),
                    )
                    .await
                    .expect_err("ambiguous multimodal embedding outcome must fail")
            } else {
                client
                    .rerank(
                        &cx,
                        rerank_request_from_value(
                            json!({"query": "query", "documents": ["document"]}),
                            DEFAULT_RERANK_MODEL,
                        )
                        .unwrap(),
                    )
                    .await
                    .expect_err("ambiguous rerank outcome must fail")
            };
            assert_eq!(
                error,
                fcp_openai_compat::OpenAiError::OutcomeUnknown {
                    status: Some(status)
                }
            );
            let mapped = fcp_voyage::error::openai_error_to_fcp(&error);
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
}

#[fcp_async_core::runtime::test]
async fn explicit_rerank_rate_limit_refusal_still_permits_one_retry() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/rerank"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({"detail": "rate limited"})),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/rerank"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;
    let client = VoyageClient::new(
        VoyageProvider::new(
            format!("{}/v1", server.uri()),
            VoyageAuth::ApiKey("key".into()),
        ),
        Duration::from_secs(5),
        Duration::from_secs(60),
        RateLimitPolicy::WaitForever,
    );
    let response = client
        .rerank(
            &fcp_async_core::compatibility_cx(),
            rerank_request_from_value(
                json!({"query": "query", "documents": ["document"]}),
                DEFAULT_RERANK_MODEL,
            )
            .unwrap(),
        )
        .await
        .expect("HTTP 429 is an explicit refusal");
    assert_eq!(response, json!({"data": []}));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
