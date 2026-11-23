use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityToken, FcpError, InvokeResponse, InvokeStatus,
    SimulateResponse,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_huggingface::connector::HuggingfaceConnector;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use serde_json::{Value, json};
use wiremock::matchers::{bearer_token, body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_TEXT: &str = "huggingface.inference.text_generation";
const OP_SUMMARY: &str = "huggingface.inference.summarization";
const OP_LIST: &str = "huggingface.models.list";
const OP_INFO: &str = "huggingface.models.info";

fn signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[73; 32]).expect("valid fixture signing key")
}

fn handshake_request() -> Value {
    json!({
        "protocol_version": "2.0",
        "zone": "z:work",
        "host_public_key": signing_key().verifying_key().to_bytes(),
        "nonce": vec![17_u8; 32],
        "capabilities_requested": ["huggingface.inference", "huggingface.models"]
    })
}

fn signed_request(connector: &HuggingfaceConnector, operation: &str, input: Value) -> Value {
    signed_request_with_constraints(
        connector,
        operation,
        input,
        &CapabilityConstraints::default(),
    )
}

fn signed_request_with_constraints(
    connector: &HuggingfaceConnector,
    operation: &str,
    input: Value,
    constraints: &CapabilityConstraints,
) -> Value {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = format!(
        "huggingface-contract-{}",
        NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let capability = if operation.starts_with("huggingface.inference.") {
        "huggingface.inference"
    } else {
        "huggingface.models"
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).expect("serialize signed constraints");
    let now = Utc::now();
    let token = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:huggingface-contract")
        .operations(&[operation])
        .issuer("node:huggingface-contract")
        .target_instance(connector.instance_id().as_str())
        .token_id(id.as_bytes())
        .validity(
            now - ChronoDuration::minutes(1),
            now + ChronoDuration::hours(1),
        )
        .try_constraints_cbor(&cbor)
        .expect("valid signed constraints")
        .sign(&signing_key())
        .expect("sign capability");
    json!({
        "type": "invoke",
        "id": id,
        "connector_id": "fcp.huggingface",
        "operation": operation,
        "zone_id": "z:work",
        "input": input,
        "idempotency_key": id,
        "capability_token": CapabilityToken::from_raw(token)
    })
}

fn simulate_request(mut request: Value) -> Value {
    request["type"] = json!("simulate");
    request
        .as_object_mut()
        .expect("request object")
        .remove("idempotency_key");
    request
}

fn loopback_config(server: &MockServer, request_timeout_ms: u64, max_retries: u32) -> Value {
    json!({
        "api_token": "hf_loopback_token",
        "inference_url": server.uri(),
        "hub_url": server.uri(),
        "request_timeout_ms": request_timeout_ms,
        "retry": {
            "max_retries": max_retries,
            "initial_delay_ms": 1,
            "max_delay_ms": 1,
            "jitter_enabled": false
        }
    })
}

async fn configured_loopback_connector(server: &MockServer) -> HuggingfaceConnector {
    configured_loopback_connector_with(server, 5_000, 0).await
}

async fn configured_loopback_connector_with(
    server: &MockServer,
    request_timeout_ms: u64,
    max_retries: u32,
) -> HuggingfaceConnector {
    let mut connector = HuggingfaceConnector::new();
    connector
        .handle_configure(loopback_config(server, request_timeout_ms, max_retries))
        .await
        .expect("loopback configure should succeed");
    connector
        .handle_handshake(handshake_request())
        .await
        .expect("loopback handshake should succeed");
    connector
}

fn model_id_hash(model_id: &str) -> String {
    format!("blake3:{}", blake3::hash(model_id.as_bytes()).to_hex())
}

fn emit_huggingface_e2e_jsonl(record: &Value) {
    println!(
        "HUGGINGFACE_E2E_JSONL {}",
        serde_json::to_string(record).expect("record should serialize")
    );
}

#[fcp_async_core::runtime::test]
async fn huggingface_provider_contract_is_advertised() {
    let redaction_marker = "huggingface-provider-contract-marker";
    let mut connector = HuggingfaceConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let configure = connector
        .handle_configure(json!({
            "api_token": redaction_marker,
            "inference_url": "http://127.0.0.1:1",
            "hub_url": "http://127.0.0.1:2/api"
        }))
        .await
        .expect("loopback configure should succeed");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");

    assert_provider_contract(
        &ProviderContract::new("huggingface", "Hugging Face")
            .with_docs_path("/connectors/huggingface/manifest.toml")
            .with_config_key("api_token")
            .with_config_key("credential_id")
            .with_config_key("inference_url")
            .with_config_key("hub_url")
            .with_config_key("retry")
            .with_config_key("request_timeout_ms")
            .with_auth_method(
                ProviderAuthMethodContract::new("api_token", "API token")
                    .with_config_key("api_token"),
            )
            .with_auth_method(
                ProviderAuthMethodContract::new("credential_id", "Host-injected credential")
                    .with_config_key("credential_id"),
            )
            .with_model_picker_method("api_token")
            .with_default_model("gpt2")
            .with_model_catalog(
                ProviderModelCatalogContract::new("inference")
                    .with_model(ProviderModelContract::new("gpt2"))
                    .with_model(ProviderModelContract::new("facebook/bart-large-cnn")),
            )
            .with_operation(
                ProviderOperationContract::new(OP_TEXT)
                    .with_catalog_id("inference")
                    .with_default_model("gpt2")
                    .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::new(OP_SUMMARY)
                    .with_catalog_id("inference")
                    .with_default_model("facebook/bart-large-cnn")
                    .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::new(OP_LIST)
                    .with_catalog_id("inference")
                    .with_default_model_deferral(
                        "Hub catalog listing is filter-selected rather than tied to one model",
                    )
                    .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::new(OP_INFO)
                    .with_catalog_id("inference")
                    .with_default_model_deferral(
                        "model_id is caller-selected; model metadata has no default model",
                    )
                    .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "inference",
                "https://router.huggingface.co/hf-inference",
            ))
            .with_base_url(ProviderBaseUrlContract::new(
                "hub",
                "https://huggingface.co/api",
            ))
            .with_base_url(
                ProviderBaseUrlContract::new("loopback-inference", "http://127.0.0.1:1")
                    .allow_loopback_http(),
            )
            .with_secret_marker(redaction_marker)
            .with_redaction_payload(ProviderRedactionPayload::new("configure", configure))
            .with_redaction_payload(ProviderRedactionPayload::new("doctor", doctor))
            .with_redaction_payload(ProviderRedactionPayload::new(
                "introspection",
                introspection,
            ))
            .with_import_side_effect(ProviderImportSideEffectContract::new(
                "fcp_huggingface",
                "provider registry",
            )),
    );
}

#[fcp_async_core::runtime::test]
async fn huggingface_model_list_loopback_catalog_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(query_param("search", "bart"))
        .and(query_param("pipeline_tag", "summarization"))
        .and(query_param("limit", "2"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "_id": "model-1",
                "modelId": "facebook/bart-large-cnn",
                "pipeline_tag": "summarization",
                "tags": ["summarization"],
                "downloads": 123,
                "likes": 4
            }
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_loopback_connector(&server).await;
    let request = signed_request(
        &connector,
        OP_LIST,
        json!({
            "search": "bart",
            "pipeline_tag": "summarization",
            "limit": 2
        }),
    );
    let result = connector
        .handle_invoke(request.clone())
        .await
        .expect("model list should succeed");
    let typed: InvokeResponse = serde_json::from_value(result.clone()).unwrap();
    assert_eq!(typed.r#type, "response");
    assert_eq!(typed.status, InvokeStatus::Ok);
    assert_eq!(typed.id.0, request["id"].as_str().unwrap());
    assert_eq!(result["result"]["catalog"], "hub");
    assert_eq!(result["result"]["limit"], 2);
    assert_eq!(
        result["result"]["models"][0]["modelId"],
        "facebook/bart-large-cnn"
    );
}

#[fcp_async_core::runtime::test]
async fn huggingface_text_generation_loopback_request_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/models/gpt2"))
        .and(bearer_token("hf_loopback_token"))
        .and(body_json(json!({
            "inputs": "hello",
            "parameters": {
                "max_new_tokens": 12,
                "temperature": 0.7,
                "return_full_text": false
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"generated_text": "hello world"}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_loopback_connector(&server).await;
    let result = connector
        .handle_invoke(signed_request(
            &connector,
            OP_TEXT,
            json!({
                "model_id": "gpt2",
                "prompt": "hello",
                "max_new_tokens": 12,
                "temperature": 0.7,
                "return_full_text": false
            }),
        ))
        .await
        .expect("text generation should succeed");

    assert_eq!(result["result"][0]["generated_text"], "hello world");
}

#[fcp_async_core::runtime::test]
async fn huggingface_singleton_inference_results_normalize_to_native_arrays() {
    for (operation, model, input, body, response) in [
        (
            OP_TEXT,
            "gpt2",
            json!({"model_id": "gpt2", "prompt": "hello", "max_new_tokens": 12}),
            json!({"inputs": "hello", "parameters": {"max_new_tokens": 12}}),
            json!({"generated_text": "hello world"}),
        ),
        (
            OP_SUMMARY,
            "facebook/bart-large-cnn",
            json!({
                "model_id": "facebook/bart-large-cnn",
                "text": "A provider response should honor its native output contract.",
                "max_length": 32,
                "min_length": 4,
                "do_sample": false
            }),
            json!({
                "inputs": "A provider response should honor its native output contract.",
                "parameters": {
                    "generate_parameters": {
                        "max_length": 32,
                        "min_length": 4,
                        "do_sample": false
                    }
                }
            }),
            json!({"summary_text": "Provider outputs honor native contracts."}),
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/models/{model}")))
            .and(bearer_token("hf_loopback_token"))
            .and(body_json(body))
            .respond_with(ResponseTemplate::new(200).set_body_json(response.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let connector = configured_loopback_connector(&server).await;
        let request = signed_request(&connector, operation, input);
        let result = connector.handle_invoke(request.clone()).await.unwrap();
        let result: InvokeResponse = serde_json::from_value(result).unwrap();
        assert_eq!(result.status, InvokeStatus::Ok);
        assert_eq!(result.id.0, request["id"].as_str().unwrap());
        assert_eq!(result.result.unwrap(), json!([response]));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn huggingface_model_info_auth_failure_maps_to_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models/gated/model"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid token"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let connector = configured_loopback_connector(&server).await;
    let err = connector
        .handle_invoke(signed_request(
            &connector,
            OP_INFO,
            json!({"model_id": "gated/model"}),
        ))
        .await
        .expect_err("401 should map to an authorization failure");

    assert!(err.to_string().contains("Authentication failed"));
}

#[fcp_async_core::runtime::test]
async fn huggingface_loopback_e2e_jsonl_matrix() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/whoami-v2"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "loopback-user"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(query_param("search", "bart"))
        .and(query_param("pipeline_tag", "summarization"))
        .and(query_param("limit", "2"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "_id": "model-1",
                "modelId": "facebook/bart-large-cnn",
                "pipeline_tag": "summarization",
                "tags": ["summarization"],
                "downloads": 123,
                "likes": 4
            }
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/models"))
        .and(query_param("search", "broken"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw("{\"not\":\"a-list\"}", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/models/gpt2"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"generated_text": "hello world"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/models/gated/model"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid token"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/models/missing/model"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "not found"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/models/limited/model"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/models/slow/model"))
        .and(bearer_token("hf_loopback_token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(json!([{"generated_text": "slow"}])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = configured_loopback_connector_with(&server, 5_000, 1).await;
    let git_revision =
        std::env::var("HUGGINGFACE_E2E_GIT_REVISION").unwrap_or_else(|_| "test-worktree".into());
    let health = connector
        .handle_health()
        .await
        .expect("health should serialize");
    assert_eq!(health["status"], "healthy");
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "onboarding-readiness",
        "operation": "health",
        "model_id_hash": null,
        "endpoint_class": "control",
        "auth_decision": health["auth_mode"],
        "request_bytes": 0,
        "response_bytes": health.to_string().len(),
        "capability_classification": "readiness",
        "retry_decision": "none",
        "http_status": null,
        "fcp_error_mapping": null,
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let list_input = signed_request(
        &connector,
        OP_LIST,
        json!({
            "search": "bart", "pipeline_tag": "summarization", "limit": 2
        }),
    );
    let list = connector
        .handle_invoke(list_input.clone())
        .await
        .expect("model list should succeed");
    assert_eq!(
        list["result"]["models"][0]["modelId"],
        "facebook/bart-large-cnn"
    );
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "model-list-success",
        "operation": OP_LIST,
        "model_id_hash": null,
        "endpoint_class": "hub",
        "auth_decision": "bearer",
        "request_bytes": list_input.to_string().len(),
        "response_bytes": list.to_string().len(),
        "capability_classification": "catalog-read",
        "retry_decision": "none",
        "http_status": 200,
        "fcp_error_mapping": null,
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let inference_input = signed_request(
        &connector,
        OP_TEXT,
        json!({
            "model_id": "gpt2", "prompt": "hello", "max_new_tokens": 12
        }),
    );
    let inference = connector
        .handle_invoke(inference_input.clone())
        .await
        .expect("text generation should succeed");
    assert_eq!(inference["result"][0]["generated_text"], "hello world");
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "inference-request-success",
        "operation": OP_TEXT,
        "model_id_hash": model_id_hash("gpt2"),
        "endpoint_class": "inference-api",
        "auth_decision": "bearer",
        "request_bytes": inference_input.to_string().len(),
        "response_bytes": inference.to_string().len(),
        "capability_classification": "model-invoke",
        "retry_decision": "none",
        "http_status": 200,
        "fcp_error_mapping": null,
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let auth_err = connector
        .handle_invoke(signed_request(
            &connector,
            OP_INFO,
            json!({"model_id": "gated/model"}),
        ))
        .await
        .expect_err("auth denial should fail");
    assert!(auth_err.to_string().contains("Authentication failed"));
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "auth-denial",
        "operation": OP_INFO,
        "model_id_hash": model_id_hash("gated/model"),
        "endpoint_class": "hub",
        "auth_decision": "bearer-denied",
        "request_bytes": 90,
        "response_bytes": 25,
        "capability_classification": "catalog-read",
        "retry_decision": "terminal",
        "http_status": 401,
        "fcp_error_mapping": "Unauthorized",
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let missing_err = connector
        .handle_invoke(signed_request(
            &connector,
            OP_INFO,
            json!({"model_id": "missing/model"}),
        ))
        .await
        .expect_err("missing model should fail");
    assert!(missing_err.to_string().contains("not found"));
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "missing-model",
        "operation": OP_INFO,
        "model_id_hash": model_id_hash("missing/model"),
        "endpoint_class": "hub",
        "auth_decision": "bearer",
        "request_bytes": 91,
        "response_bytes": 21,
        "capability_classification": "catalog-read",
        "retry_decision": "terminal",
        "http_status": 404,
        "fcp_error_mapping": "ResourceNotFound",
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let rate_err = connector
        .handle_invoke(signed_request(
            &connector,
            OP_INFO,
            json!({"model_id": "limited/model"}),
        ))
        .await
        .expect_err("rate limit should fail after retry budget");
    assert!(rate_err.to_string().contains("Rate limited"));
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "rate-limit-retry",
        "operation": OP_INFO,
        "model_id_hash": model_id_hash("limited/model"),
        "endpoint_class": "hub",
        "auth_decision": "bearer",
        "request_bytes": 91,
        "response_bytes": 0,
        "capability_classification": "catalog-read",
        "retry_decision": "retry-after",
        "http_status": 429,
        "fcp_error_mapping": "RateLimited",
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let malformed_err = connector
        .handle_invoke(signed_request(
            &connector,
            OP_LIST,
            json!({"search": "broken", "limit": 1}),
        ))
        .await
        .expect_err("malformed model catalog should fail");
    assert!(matches!(
        malformed_err,
        FcpError::External {
            status_code: Some(200),
            retryable: false,
            ref message,
            ..
        } if message.contains("JSON contract")
    ));
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "malformed-catalog",
        "operation": OP_LIST,
        "model_id_hash": null,
        "endpoint_class": "hub",
        "auth_decision": "bearer",
        "request_bytes": 88,
        "response_bytes": 16,
        "capability_classification": "catalog-read",
        "retry_decision": "terminal",
        "http_status": 200,
        "fcp_error_mapping": "ExternalJsonContract",
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let timeout_connector = configured_loopback_connector_with(&server, 50, 0).await;
    let timeout_err = timeout_connector
        .handle_invoke(signed_request(
            &timeout_connector,
            OP_TEXT,
            json!({"model_id": "slow/model", "prompt": "hello"}),
        ))
        .await
        .expect_err("slow response should hit timeout");
    let timeout_like = match &timeout_err {
        FcpError::External {
            service,
            retryable,
            message,
            ..
        } => {
            service == "huggingface"
                && !*retryable
                && message.contains("outcome")
                && message.contains("unknown")
        }
        FcpError::Internal { message } => {
            message.contains("deadline") || message.contains("timeout")
        }
        _ => false,
    };
    assert!(
        timeout_like,
        "Expected timeout-like failure, got {timeout_err:?}"
    );
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "timeout-cancellation",
        "operation": OP_TEXT,
        "model_id_hash": model_id_hash("slow/model"),
        "endpoint_class": "inference-api",
        "auth_decision": "bearer",
        "request_bytes": 112,
        "response_bytes": 0,
        "capability_classification": "model-invoke",
        "retry_decision": "no-replay-after-timeout",
        "http_status": null,
        "fcp_error_mapping": "InferenceOutcomeUnknownOrDeadline",
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let self_check = connector
        .handle_self_check()
        .await
        .expect("self-check should use loopback whoami");
    assert_eq!(self_check["status"], "ok");
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "self-check",
        "operation": "self_check",
        "model_id_hash": null,
        "endpoint_class": "control",
        "auth_decision": "bearer",
        "request_bytes": 0,
        "response_bytes": self_check.to_string().len(),
        "capability_classification": "readiness",
        "retry_decision": "none",
        "http_status": 200,
        "fcp_error_mapping": null,
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let shutdown = connector
        .handle_shutdown(json!({"type": "shutdown"}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(shutdown["type"], "shutdown_ack");
    assert_eq!(shutdown["status"], "completed");
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "shutdown-cleanup",
        "operation": "shutdown",
        "model_id_hash": null,
        "endpoint_class": "control",
        "auth_decision": "not_applicable",
        "request_bytes": 0,
        "response_bytes": shutdown.to_string().len(),
        "capability_classification": "cleanup",
        "retry_decision": "none",
        "http_status": null,
        "fcp_error_mapping": null,
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "completed",
        "skip_reason": null,
        "status": "passed"
    }));
}

#[fcp_async_core::runtime::test]
async fn huggingface_inference_server_errors_are_not_replayed() {
    for operation in [OP_TEXT, OP_SUMMARY] {
        for status in [408, 500, 502, 503, 504] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/models/gpt2"))
                .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                    "error": "private-prompt-reflected-by-upstream"
                })))
                .expect(1)
                .mount(&server)
                .await;
            let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
            let input = if operation == OP_TEXT {
                json!({"model_id": "gpt2", "prompt": "hello"})
            } else {
                json!({"model_id": "gpt2", "text": "summarize this text"})
            };
            let err = connector
                .handle_invoke(signed_request(&connector, operation, input))
                .await
                .expect_err("ambiguous inference must not be replayed");
            assert!(matches!(
                &err,
                FcpError::External {
                    status_code: Some(code),
                    retryable: false,
                    retry_after: None,
                    message,
                    ..
                } if *code == status && message.contains("outcome unknown")
            ));
            assert!(
                !err.to_string()
                    .contains("private-prompt-reflected-by-upstream")
            );
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }
}

#[fcp_async_core::runtime::test]
async fn huggingface_inference_invalid_loading_estimates_are_not_replayed() {
    for estimate in [json!(null), json!(-1.0), json!("not-a-duration")] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/models/gpt2"))
            .respond_with(ResponseTemplate::new(503).set_body_json(json!({
                "error": "upstream error",
                "estimated_time": estimate
            })))
            .expect(1)
            .mount(&server)
            .await;
        let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
        let err = connector
            .handle_invoke(signed_request(
                &connector,
                OP_TEXT,
                json!({"model_id": "gpt2", "prompt": "hello"}),
            ))
            .await
            .expect_err("an invalid estimate is not proof that inference did not run");
        assert!(matches!(
            err,
            FcpError::External {
                status_code: Some(503),
                retryable: false,
                ..
            }
        ));
    }
}

#[fcp_async_core::runtime::test]
async fn huggingface_inference_malformed_success_is_not_replayed() {
    for body in ["{malformed-json", r#"[{"generated_text":42}]"#] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/models/gpt2"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&server)
            .await;
        let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
        let err = connector
            .handle_invoke(signed_request(
                &connector,
                OP_TEXT,
                json!({"model_id": "gpt2", "prompt": "hello"}),
            ))
            .await
            .expect_err("a malformed response must not repeat completed inference");
        assert!(matches!(
            err,
            FcpError::External {
                status_code: Some(200),
                retryable: false,
                retry_after: None,
                ..
            }
        ));
    }
}

#[fcp_async_core::runtime::test]
async fn huggingface_inference_rate_limit_retries_once_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/models/gpt2"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .with_priority(1)
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/models/gpt2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"generated_text": "success after admission"}
        ])))
        .with_priority(2)
        .expect(1)
        .mount(&server)
        .await;
    let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
    let result = connector
        .handle_invoke(signed_request(
            &connector,
            OP_TEXT,
            json!({"model_id": "gpt2", "prompt": "hello"}),
        ))
        .await
        .expect("a refused request is safe to retry");
    assert_eq!(
        result["result"][0]["generated_text"],
        "success after admission"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn huggingface_inference_loading_retries_once_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/models/gpt2"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": "Model gpt2 is currently loading",
            "estimated_time": 0.0
        })))
        .with_priority(1)
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/models/gpt2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"generated_text": "success after loading"}
        ])))
        .with_priority(2)
        .expect(1)
        .mount(&server)
        .await;
    let mut connector = HuggingfaceConnector::new();
    let mut config = loopback_config(&server, 5_000, 3);
    config["retry"]["max_delay_ms"] = json!(2_000);
    connector.handle_configure(config).await.unwrap();
    connector
        .handle_handshake(handshake_request())
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let result = connector
        .handle_invoke(signed_request(
            &connector,
            OP_TEXT,
            json!({"model_id": "gpt2", "prompt": "hello"}),
        ))
        .await
        .expect("a model-loading refusal is safe to retry");
    assert_eq!(
        result["result"][0]["generated_text"],
        "success after loading"
    );
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn huggingface_hub_reads_keep_transient_retries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models/gpt2"))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(1)
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/models/gpt2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_id": "model-1",
            "modelId": "gpt2",
            "pipeline_tag": "text-generation",
            "tags": [],
            "downloads": 1,
            "likes": 1
        })))
        .with_priority(2)
        .expect(1)
        .mount(&server)
        .await;
    let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
    connector
        .handle_invoke(signed_request(
            &connector,
            OP_INFO,
            json!({"model_id": "gpt2"}),
        ))
        .await
        .expect("read-only Hub operations should keep retrying transient failures");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn huggingface_inference_timeout_is_not_replayed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/models/gpt2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(250))
                .set_body_json(json!([{"generated_text": "already computed"}])),
        )
        .expect(1)
        .mount(&server)
        .await;
    let connector = configured_loopback_connector_with(&server, 50, 3).await;
    let err = connector
        .handle_invoke(signed_request(
            &connector,
            OP_TEXT,
            json!({"model_id": "gpt2", "prompt": "hello"}),
        ))
        .await
        .expect_err("a timed-out inference must not be replayed");
    match err {
        FcpError::External {
            retryable: false,
            retry_after: None,
            message,
            ..
        } => assert!(message.contains("outcome") && message.contains("unknown")),
        // The enclosing execution deadline can win the race with the HTTP
        // timeout; it must also terminate the operation without another send.
        FcpError::Internal { message } => assert!(message.contains("deadline")),
        other => panic!("expected a non-retryable timeout, got {other:?}"),
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn huggingface_inference_redirects_do_not_forward_or_replay_prompts() {
    for status in [301, 302, 303, 307, 308] {
        let server = MockServer::start().await;
        let redirect_target = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/models/gpt2"))
            .respond_with(ResponseTemplate::new(status).insert_header(
                "location",
                format!("{}/models/redirected", redirect_target.uri()),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
        let err = connector
            .handle_invoke(signed_request(
                &connector,
                OP_TEXT,
                json!({
                    "model_id": "gpt2",
                    "prompt": "private-prompt-must-stay-at-origin"
                }),
            ))
            .await
            .expect_err("redirects require an explicit endpoint change");
        assert!(matches!(
            err,
            FcpError::External {
                status_code: Some(code),
                retryable: false,
                ref message,
                ..
            } if code == status && message.contains("redirect refused")
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert!(
            redirect_target
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[fcp_async_core::runtime::test]
async fn huggingface_hub_redirects_do_not_escape_the_configured_endpoint() {
    let server = MockServer::start().await;
    let redirect_target = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models/gpt2"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", redirect_target.uri()))
        .expect(1)
        .mount(&server)
        .await;
    let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
    let err = connector
        .handle_invoke(signed_request(
            &connector,
            OP_INFO,
            json!({"model_id": "gpt2"}),
        ))
        .await
        .expect_err("Hub redirects must not bypass endpoint selection");
    assert!(matches!(
        err,
        FcpError::External {
            status_code: Some(302),
            retryable: false,
            ref message,
            ..
        } if message.contains("hub_url")
    ));
    assert!(
        redirect_target
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[fcp_async_core::runtime::test]
async fn huggingface_rejects_model_url_injection_before_any_send() {
    let server = MockServer::start().await;
    let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
    for operation in [OP_TEXT, OP_SUMMARY, OP_INFO] {
        for model_id in [
            "gpt2?admin=true",
            "gpt2#discarded",
            "org/%2e%2e",
            "org/%252e%252e",
            ".",
            "/gpt2",
            "org/",
            "org/.",
        ] {
            let input = match operation {
                OP_TEXT => json!({"model_id": model_id, "prompt": "hello"}),
                OP_SUMMARY => json!({"model_id": model_id, "text": "summarize this text"}),
                _ => json!({"model_id": model_id}),
            };
            let err = connector
                .handle_invoke(signed_request(&connector, operation, input))
                .await
                .expect_err("model IDs must not change URL structure");
            assert!(matches!(err, FcpError::InvalidRequest { .. }));
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn huggingface_authority_failures_never_reach_the_provider() {
    let server = MockServer::start().await;
    let connector = configured_loopback_connector(&server).await;
    let other_instance = configured_loopback_connector(&server).await;
    let valid = signed_request(&connector, OP_INFO, json!({"model_id": "gpt2"}));

    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("capability_token");
    assert!(connector.handle_invoke(missing).await.is_err());

    let mut invalid_token = valid.clone();
    invalid_token["capability_token"] = json!(CapabilityToken::from_raw(vec![0_u8; 64]));
    assert!(connector.handle_invoke(invalid_token).await.is_err());

    let wrong_instance = signed_request(&other_instance, OP_INFO, json!({"model_id": "gpt2"}));
    assert!(connector.handle_invoke(wrong_instance).await.is_err());

    let mut wrong_zone = valid.clone();
    wrong_zone["zone_id"] = json!("z:private");
    assert!(connector.handle_invoke(wrong_zone).await.is_err());

    let mut wrong_connector = valid.clone();
    wrong_connector["connector_id"] = json!("fcp.github");
    assert!(connector.handle_invoke(wrong_connector).await.is_err());

    let mut wrong_operation = valid.clone();
    wrong_operation["operation"] = json!(OP_LIST);
    wrong_operation["input"] = json!({"limit": 1});
    assert!(connector.handle_invoke(wrong_operation).await.is_err());

    // These tokens have valid COSE structure but wrong authority, time or zone.
    for (key, zone, expiration) in [
        (
            Ed25519SigningKey::from_bytes(&[74; 32]).unwrap(),
            "z:work",
            3_600,
        ),
        (signing_key(), "z:work", -3_600),
        (signing_key(), "z:private", 3_600),
    ] {
        let now = Utc::now();
        let token = CapabilityTokenBuilder::new()
            .capability_id("huggingface.models")
            .zone_id(zone)
            .principal("user:huggingface-contract")
            .operations(&[OP_INFO])
            .issuer("node:huggingface-contract")
            .target_instance(connector.instance_id().as_str())
            .validity(
                now - ChronoDuration::hours(2),
                now + ChronoDuration::seconds(expiration),
            )
            .sign(&key)
            .unwrap();
        let mut request = valid.clone();
        request["capability_token"] = json!(CapabilityToken::from_raw(token));
        assert!(connector.handle_invoke(request).await.is_err());
    }

    let mut unnegotiated = configured_loopback_connector(&server).await;
    let mut handshake = handshake_request();
    handshake["capabilities_requested"] = json!([]);
    unnegotiated.handle_handshake(handshake).await.unwrap();
    let request = signed_request(&unnegotiated, OP_INFO, json!({"model_id": "gpt2"}));
    assert!(unnegotiated.handle_invoke(request).await.is_err());

    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "denials must precede every provider request"
    );
}

#[fcp_async_core::runtime::test]
async fn huggingface_resource_scope_uses_actual_model_and_default_before_dispatch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/models/gpt2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"generated_text": "default model admitted"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let connector = configured_loopback_connector(&server).await;
    let constraints = CapabilityConstraints {
        resource_allow: vec!["huggingface:model:gpt2".into()],
        ..Default::default()
    };
    let default_model = signed_request_with_constraints(
        &connector,
        OP_TEXT,
        json!({"prompt": "hello"}),
        &constraints,
    );
    connector.handle_invoke(default_model).await.unwrap();

    let mut other_model = signed_request_with_constraints(
        &connector,
        OP_TEXT,
        json!({"model_id": "another/model", "prompt": "hello"}),
        &constraints,
    );
    other_model["resource_uris"] = json!(["huggingface:model:gpt2"]);
    assert!(connector.handle_invoke(other_model).await.is_err());

    let denied = signed_request_with_constraints(
        &connector,
        OP_TEXT,
        json!({"model_id": "gpt2", "prompt": "hello"}),
        &CapabilityConstraints {
            resource_allow: vec!["huggingface:model:*".into()],
            resource_deny: vec!["huggingface:model:gpt2".into()],
            ..Default::default()
        },
    );
    assert!(connector.handle_invoke(denied).await.is_err());

    let listing =
        signed_request_with_constraints(&connector, OP_LIST, json!({"limit": 1}), &constraints);
    assert!(connector.handle_invoke(listing).await.is_err());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn huggingface_simulation_verifies_authority_without_spending_calls_or_using_http() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/models/gpt2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_id": "model-1", "modelId": "gpt2", "tags": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    let connector = configured_loopback_connector(&server).await;
    let request = signed_request_with_constraints(
        &connector,
        OP_INFO,
        json!({"model_id": "gpt2"}),
        &CapabilityConstraints {
            max_calls: Some(1),
            ..Default::default()
        },
    );
    let preview = simulate_request(request.clone());
    for _ in 0..2 {
        let result = connector.handle_simulate(preview.clone()).await.unwrap();
        let response: SimulateResponse = serde_json::from_value(result).unwrap();
        assert_eq!(response.r#type, "simulate_response");
        assert!(response.would_succeed);
        assert_eq!(response.id.0, request["id"].as_str().unwrap());
    }
    assert!(server.received_requests().await.unwrap().is_empty());

    connector.handle_invoke(request.clone()).await.unwrap();
    assert!(connector.handle_invoke(request.clone()).await.is_err());
    let result = connector.handle_simulate(preview).await.unwrap();
    let denied: SimulateResponse = serde_json::from_value(result).unwrap();
    assert!(!denied.would_succeed);
    assert!(denied.denial_code.is_some());

    let mut invalid = simulate_request(request);
    invalid["capability_token"] = json!(CapabilityToken::from_raw(vec![0_u8; 64]));
    let denied: SimulateResponse =
        serde_json::from_value(connector.handle_simulate(invalid).await.unwrap()).unwrap();
    assert!(!denied.would_succeed);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn huggingface_failed_lifecycle_changes_revoke_previous_authority() {
    let server = MockServer::start().await;
    let mut connector = configured_loopback_connector(&server).await;
    let stale = signed_request(&connector, OP_INFO, json!({"model_id": "gpt2"}));
    let previous_instance = connector.instance_id().clone();
    connector
        .handle_handshake(handshake_request())
        .await
        .unwrap();
    assert_ne!(connector.instance_id(), &previous_instance);
    assert!(connector.handle_invoke(stale).await.is_err());

    let stale = signed_request(&connector, OP_INFO, json!({"model_id": "gpt2"}));
    assert!(connector.handle_handshake(json!({})).await.is_err());
    assert!(connector.handle_invoke(stale).await.is_err());

    connector
        .handle_handshake(handshake_request())
        .await
        .unwrap();
    let stale = signed_request(&connector, OP_INFO, json!({"model_id": "gpt2"}));
    let mut invalid_config = loopback_config(&server, 5_000, 0);
    invalid_config["request_timeout_ms"] = json!(0);
    assert!(connector.handle_configure(invalid_config).await.is_err());
    assert!(connector.handle_invoke(stale).await.is_err());

    connector
        .handle_configure(loopback_config(&server, 5_000, 0))
        .await
        .unwrap();
    connector
        .handle_handshake(handshake_request())
        .await
        .unwrap();
    let stale = signed_request(&connector, OP_INFO, json!({"model_id": "gpt2"}));
    assert!(
        connector
            .handle_shutdown(json!({"type": "wrong"}))
            .await
            .is_err()
    );
    assert!(connector.handle_invoke(stale).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn huggingface_invalid_request_shapes_and_ranges_never_dispatch() {
    let server = MockServer::start().await;
    let connector = configured_loopback_connector(&server).await;
    let valid = signed_request(&connector, OP_INFO, json!({"model_id": "gpt2"}));
    for (field, value) in [
        ("type", json!("simulate")),
        ("id", json!("")),
        ("operation", json!("huggingface.unknown")),
    ] {
        let mut request = valid.clone();
        request[field] = value;
        assert!(connector.handle_invoke(request).await.is_err());
    }
    for (operation, input) in [
        (OP_TEXT, json!({"prompt": "hello"})),
        (OP_SUMMARY, json!({"text": "hello"})),
        (OP_LIST, json!({"limit": 1})),
        (OP_INFO, json!({"model_id": "gpt2"})),
    ] {
        for key in [
            None,
            Some(json!("")),
            Some(json!(" \t\n")),
            Some(json!("a".repeat(129))),
        ] {
            let mut request = signed_request(&connector, operation, input.clone());
            match key {
                Some(key) => request["idempotency_key"] = key,
                None => {
                    request.as_object_mut().unwrap().remove("idempotency_key");
                }
            }
            assert!(matches!(
                connector.handle_invoke(request).await,
                Err(FcpError::InvalidRequest { code: 1003, .. })
            ));
        }
    }
    for (operation, input) in [
        (
            OP_TEXT,
            json!({"prompt": "hello", "max_new_tokens": 4_294_967_296_u64}),
        ),
        (OP_TEXT, json!({"prompt": "hello", "max_new_tokens": -1})),
        (OP_TEXT, json!({"prompt": "hello", "max_new_tokens": "8"})),
        (OP_TEXT, json!({"prompt": "hello", "do_sample": "true"})),
        (OP_SUMMARY, json!({"text": "hello", "max_length": 0})),
        (
            OP_SUMMARY,
            json!({"text": "hello", "min_length": 9, "max_length": 8}),
        ),
        (OP_SUMMARY, json!({"text": "hello", "do_sample": 1})),
        (OP_LIST, json!({"limit": 0})),
        (OP_LIST, json!({"limit": 101})),
        (OP_LIST, json!({"limit": -1})),
        (OP_LIST, json!({"limit": "2"})),
        (OP_INFO, json!({})),
    ] {
        let request = signed_request(&connector, operation, input);
        let invoke = connector.handle_invoke(request.clone()).await;
        assert!(invoke.is_err(), "{operation} accepted invalid input");
        let result = connector
            .handle_simulate(simulate_request(request))
            .await
            .unwrap();
        let simulation: SimulateResponse = serde_json::from_value(result).unwrap();
        assert!(
            !simulation.would_succeed,
            "simulation accepted invalid input"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
