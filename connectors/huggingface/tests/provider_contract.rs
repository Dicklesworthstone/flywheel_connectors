use std::time::Duration;

use fcp_core::FcpError;
use fcp_huggingface::connector::HuggingfaceConnector;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use serde_json::json;
use wiremock::matchers::{bearer_token, body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
                ProviderOperationContract::new("huggingface.inference.text_generation")
                    .with_catalog_id("inference")
                    .with_default_model("gpt2")
                    .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::new("huggingface.inference.summarization")
                    .with_catalog_id("inference")
                    .with_default_model("facebook/bart-large-cnn")
                    .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::new("huggingface.models.list")
                    .with_catalog_id("inference")
                    .with_default_model_deferral(
                        "Hub catalog listing is filter-selected rather than tied to one model",
                    )
                    .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::new("huggingface.models.info")
                    .with_catalog_id("inference")
                    .with_default_model_deferral(
                        "model_id is caller-selected; this incubating connector does not publish a default for model metadata lookup",
                    )
                    .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "inference",
                "https://api-inference.huggingface.co",
            ))
            .with_base_url(ProviderBaseUrlContract::new("hub", "https://huggingface.co/api"))
            .with_base_url(
                ProviderBaseUrlContract::new("loopback-inference", "http://127.0.0.1:1")
                    .allow_loopback_http(),
            )
            .with_secret_marker(redaction_marker)
            .with_redaction_payload(ProviderRedactionPayload::new("configure", configure))
            .with_redaction_payload(ProviderRedactionPayload::new("doctor", doctor))
            .with_redaction_payload(ProviderRedactionPayload::new("introspection", introspection))
            .with_import_side_effect(ProviderImportSideEffectContract::new(
                "fcp_huggingface",
                "provider registry",
            )),
    );
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
        .handle_configure(json!({
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
        }))
        .await
        .expect("loopback configure should succeed");
    connector
        .handle_handshake(json!({}))
        .await
        .expect("loopback handshake should succeed");
    connector
}

fn model_id_hash(model_id: &str) -> String {
    format!("blake3:{}", blake3::hash(model_id.as_bytes()).to_hex())
}

fn emit_huggingface_e2e_jsonl(record: &serde_json::Value) {
    println!(
        "HUGGINGFACE_E2E_JSONL {}",
        serde_json::to_string(&record).expect("record should serialize")
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
    let result = connector
        .handle_invoke(json!({
            "operation_id": "huggingface.models.list",
            "input": {
                "search": "bart",
                "pipeline_tag": "summarization",
                "limit": 2
            }
        }))
        .await
        .expect("model list should succeed");

    assert_eq!(result["output"]["catalog"], "hub");
    assert_eq!(result["output"]["limit"], 2);
    assert_eq!(
        result["output"]["models"][0]["modelId"],
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
        .handle_invoke(json!({
            "operation_id": "huggingface.inference.text_generation",
            "input": {
                "model_id": "gpt2",
                "prompt": "hello",
                "max_new_tokens": 12,
                "temperature": 0.7,
                "return_full_text": false
            }
        }))
        .await
        .expect("text generation should succeed");

    assert_eq!(result["output"][0]["generated_text"], "hello world");
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
        .handle_invoke(json!({
            "operation_id": "huggingface.models.info",
            "input": {"model_id": "gated/model"}
        }))
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
                .set_delay(Duration::from_millis(50))
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
    assert_eq!(health["status"], "ready");
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

    let list_input = json!({
        "operation_id": "huggingface.models.list",
        "input": {
            "search": "bart",
            "pipeline_tag": "summarization",
            "limit": 2
        }
    });
    let list = connector
        .handle_invoke(list_input.clone())
        .await
        .expect("model list should succeed");
    assert_eq!(
        list["output"]["models"][0]["modelId"],
        "facebook/bart-large-cnn"
    );
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "model-list-success",
        "operation": "huggingface.models.list",
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

    let inference_input = json!({
        "operation_id": "huggingface.inference.text_generation",
        "input": {
            "model_id": "gpt2",
            "prompt": "hello",
            "max_new_tokens": 12
        }
    });
    let inference = connector
        .handle_invoke(inference_input.clone())
        .await
        .expect("text generation should succeed");
    assert_eq!(inference["output"][0]["generated_text"], "hello world");
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "inference-request-success",
        "operation": "huggingface.inference.text_generation",
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
        .handle_invoke(json!({
            "operation_id": "huggingface.models.info",
            "input": {"model_id": "gated/model"}
        }))
        .await
        .expect_err("auth denial should fail");
    assert!(auth_err.to_string().contains("Authentication failed"));
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "auth-denial",
        "operation": "huggingface.models.info",
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
        .handle_invoke(json!({
            "operation_id": "huggingface.models.info",
            "input": {"model_id": "missing/model"}
        }))
        .await
        .expect_err("missing model should fail");
    assert!(missing_err.to_string().contains("not found"));
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "missing-model",
        "operation": "huggingface.models.info",
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
        .handle_invoke(json!({
            "operation_id": "huggingface.models.info",
            "input": {"model_id": "limited/model"}
        }))
        .await
        .expect_err("rate limit should fail after retry budget");
    assert!(rate_err.to_string().contains("Rate limited"));
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "rate-limit-retry",
        "operation": "huggingface.models.info",
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
        .handle_invoke(json!({
            "operation_id": "huggingface.models.list",
            "input": {"search": "broken", "limit": 1}
        }))
        .await
        .expect_err("malformed model catalog should fail");
    assert!(malformed_err.to_string().contains("JSON parse error"));
    emit_huggingface_e2e_jsonl(&json!({
        "event": "huggingface_loopback_fixture",
        "command_line": "cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture",
        "git_revision": git_revision.as_str(),
        "fixture_id": "malformed-catalog",
        "operation": "huggingface.models.list",
        "model_id_hash": null,
        "endpoint_class": "hub",
        "auth_decision": "bearer",
        "request_bytes": 88,
        "response_bytes": 16,
        "capability_classification": "catalog-read",
        "retry_decision": "terminal",
        "http_status": 200,
        "fcp_error_mapping": "InternalJsonParse",
        "artifact_path": "connectors/huggingface/tests/provider_contract.rs",
        "cleanup_result": "not_applicable",
        "skip_reason": null,
        "status": "passed"
    }));

    let timeout_connector = configured_loopback_connector_with(&server, 5, 0).await;
    let timeout_err = timeout_connector
        .handle_invoke(json!({
            "operation_id": "huggingface.inference.text_generation",
            "input": {"model_id": "slow/model", "prompt": "hello"}
        }))
        .await
        .expect_err("slow response should hit timeout");
    let timeout_like = match &timeout_err {
        FcpError::External {
            service,
            retryable,
            message,
            ..
        } => service == "huggingface" && !*retryable && message.contains("outcome unknown"),
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
        "operation": "huggingface.inference.text_generation",
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
    assert_eq!(self_check["status"], "ready");
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
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(shutdown, json!({}));
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
    for operation in [
        "huggingface.inference.text_generation",
        "huggingface.inference.summarization",
    ] {
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
            let input = if operation.ends_with("text_generation") {
                json!({"model_id": "gpt2", "prompt": "hello"})
            } else {
                json!({"model_id": "gpt2", "text": "summarize this text"})
            };
            let err = connector
                .handle_invoke(json!({"operation_id": operation, "input": input}))
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
            assert!(!err.to_string().contains("private-prompt-reflected-by-upstream"));
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
            .handle_invoke(json!({
                "operation_id": "huggingface.inference.text_generation",
                "input": {"model_id": "gpt2", "prompt": "hello"}
            }))
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
            .handle_invoke(json!({
                "operation_id": "huggingface.inference.text_generation",
                "input": {"model_id": "gpt2", "prompt": "hello"}
            }))
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
        .handle_invoke(json!({
            "operation_id": "huggingface.inference.text_generation",
            "input": {"model_id": "gpt2", "prompt": "hello"}
        }))
        .await
        .expect("a refused request is safe to retry");
    assert_eq!(result["output"][0]["generated_text"], "success after admission");
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
    let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
    let result = connector
        .handle_invoke(json!({
            "operation_id": "huggingface.inference.text_generation",
            "input": {"model_id": "gpt2", "prompt": "hello"}
        }))
        .await
        .expect("a model-loading refusal is safe to retry");
    assert_eq!(result["output"][0]["generated_text"], "success after loading");
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
        .handle_invoke(json!({
            "operation_id": "huggingface.models.info",
            "input": {"model_id": "gpt2"}
        }))
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
        .handle_invoke(json!({
            "operation_id": "huggingface.inference.text_generation",
            "input": {"model_id": "gpt2", "prompt": "hello"}
        }))
        .await
        .expect_err("a timed-out inference must not be replayed");
    match err {
        FcpError::External {
            retryable: false,
            retry_after: None,
            message,
            ..
        } => assert!(message.contains("outcome unknown")),
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
            .handle_invoke(json!({
                "operation_id": "huggingface.inference.text_generation",
                "input": {"model_id": "gpt2", "prompt": "private-prompt-must-stay-at-origin"}
            }))
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
        assert!(redirect_target.received_requests().await.unwrap().is_empty());
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
        .handle_invoke(json!({
            "operation_id": "huggingface.models.info",
            "input": {"model_id": "gpt2"}
        }))
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
    assert!(redirect_target.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn huggingface_rejects_model_url_injection_before_any_send() {
    let server = MockServer::start().await;
    let connector = configured_loopback_connector_with(&server, 5_000, 3).await;
    for operation in [
        "huggingface.inference.text_generation",
        "huggingface.inference.summarization",
        "huggingface.models.info",
    ] {
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
                "huggingface.inference.text_generation" => {
                    json!({"model_id": model_id, "prompt": "hello"})
                }
                "huggingface.inference.summarization" => {
                    json!({"model_id": model_id, "text": "summarize this text"})
                }
                _ => json!({"model_id": model_id}),
            };
            let err = connector
                .handle_invoke(json!({"operation_id": operation, "input": input}))
                .await
                .expect_err("model IDs must not change URL structure");
            assert!(matches!(err, FcpError::InvalidRequest { .. }));
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
