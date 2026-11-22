use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{Duration, Utc};
use fcp_core::{CapabilityConstraints, CapabilityToken};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_openrouter::OpenRouterConnector;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

fn input_schema<'a>(introspection: &'a Value, operation_id: &str) -> &'a Value {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .and_then(|operations| {
            operations
                .iter()
                .find(|operation| operation.get("id").and_then(Value::as_str) == Some(operation_id))
        })
        .and_then(|operation| operation.get("input_schema"))
        .expect("operation input_schema should be present")
}

#[fcp_async_core::runtime::test]
async fn openrouter_provider_contract_is_advertised() {
    let redaction_marker = "openrouter-provider-contract-marker";
    let mut connector = OpenRouterConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let configure = connector
        .handle_configure(json!({
            "api_key": redaction_marker,
            "base_url": "http://127.0.0.1:1/api/v1",
            "app_name": "FCP provider contract",
            "app_url": "https://example.com/fcp"
        }))
        .await
        .expect("loopback configure should succeed");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");

    assert_provider_contract(
        &ProviderContract::new("openrouter", "OpenRouter")
            .with_docs_path("/connectors/openrouter/manifest.toml")
            .with_config_key("api_key")
            .with_config_key("credential_id")
            .with_config_key("base_url")
            .with_config_key("request_timeout_ms")
            .with_config_key("app_name")
            .with_config_key("app_url")
            .with_auth_method(
                ProviderAuthMethodContract::new("api_key", "API key").with_config_key("api_key"),
            )
            .with_auth_method(
                ProviderAuthMethodContract::new("credential_id", "Host credential reference")
                    .with_config_key("credential_id"),
            )
            .with_model_picker_method("api_key")
            .with_default_model("openai/gpt-4.1-mini")
            .with_model_catalog(
                ProviderModelCatalogContract::new("models")
                    .with_model(ProviderModelContract::new("openai/gpt-4.1-mini"))
                    .with_model(ProviderModelContract::new("google/veo-3.1-fast")),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "openrouter.chat.completions",
                    "models",
                    input_schema(&introspection, "openrouter.chat.completions"),
                )
                .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "openrouter.videos.generate",
                    "models",
                    input_schema(&introspection, "openrouter.videos.generate"),
                )
                .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "api",
                "https://openrouter.ai/api/v1",
            ))
            .with_base_url(
                ProviderBaseUrlContract::new("loopback-test", "http://127.0.0.1:1/api/v1")
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
                "fcp_openrouter",
                "provider registry",
            )),
    );
}

#[fcp_async_core::runtime::test]
async fn video_generate_polls_and_strips_auth_from_cross_origin_urls() {
    let openrouter = MockServer::start().await;
    let status_server = MockServer::start().await;
    let cdn_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/videos"))
        .and(header("Authorization", "Bearer openrouter_test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "job-123",
            "polling_url": format!("{}/videos/job-123", status_server.uri()),
            "status": "pending"
        })))
        .expect(1)
        .mount(&openrouter)
        .await;

    Mock::given(method("GET"))
        .and(path("/videos/job-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "job-123",
            "generation_id": "gen-123",
            "status": "completed",
            "model": "google/veo-3.1",
            "unsigned_urls": [format!("{}/video.mp4", cdn_server.uri())],
            "usage": {"cost": 0.25, "is_byok": false}
        })))
        .expect(1)
        .mount(&status_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/video.mp4"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "video/mp4")
                .set_body_bytes(b"mp4-bytes".to_vec()),
        )
        .expect(1)
        .mount(&cdn_server)
        .await;

    let mut connector = OpenRouterConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "openrouter_test_key",
            "base_url": openrouter.uri()
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![3_u8; 32],
            "capabilities_requested": ["openrouter.video"]
        }))
        .await
        .expect("handshake");
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
    let now = Utc::now();
    let token = CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id("openrouter.video")
            .operations(&["openrouter.videos.generate"])
            .zone_id("z:work")
            .principal("user:provider-contract")
            .issuer("node:provider-contract")
            .target_instance(connector.instance_id().as_str())
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .sign(&signing_key)
            .unwrap(),
    );

    let result = connector
        .handle_invoke(json!({
            "type": "invoke",
            "id": "provider-video",
            "connector_id": "fcp.openrouter",
            "zone_id": "z:work",
            "operation": "openrouter.videos.generate",
            "capability_token": token,
            "input": {
                "prompt": "A chrome sphere glides across a quiet moonlit beach",
                "model": "google/veo-3.1",
                "duration_seconds": 6,
                "aspect_ratio": "16:9",
                "resolution": "720P",
                "poll_interval_ms": 0,
                "max_poll_attempts": 3
            }
        }))
        .await
        .expect("video generate");

    assert_eq!(result["job_id"], "job-123");
    assert_eq!(result["generation_id"], "gen-123");
    assert_eq!(result["video"]["mime_type"], "video/mp4");
    assert_eq!(
        result["video"]["base64"],
        BASE64_STANDARD.encode("mp4-bytes")
    );

    let status_requests = status_server.received_requests().await.unwrap_or_default();
    assert_eq!(status_requests.len(), 1);
    assert!(status_requests[0].headers.get("authorization").is_none());

    let download_requests = cdn_server.received_requests().await.unwrap_or_default();
    assert_eq!(download_requests.len(), 1);
    assert!(download_requests[0].headers.get("authorization").is_none());
}
