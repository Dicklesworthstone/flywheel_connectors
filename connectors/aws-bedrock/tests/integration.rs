//! Integration tests for the AWS Bedrock connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration, Utc};
use fcp_aws_bedrock::connector::BedrockConnector;
use fcp_aws_bedrock::event_stream::encode_event_stream_message;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use wiremock::matchers::{body_json, header, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const OP_CONVERSE: &str = "aws_bedrock.converse";
const OP_CONVERSE_STREAM: &str = "aws_bedrock.converse_stream";
const OP_INVOKE_MODEL: &str = "aws_bedrock.invoke_model";
const OP_INVOKE_MODEL_STREAM: &str = "aws_bedrock.invoke_model_stream";
const OP_MODELS_LIST: &str = "aws_bedrock.models.list";
const OP_HEALTH: &str = "aws_bedrock.health";
const TEST_ACCESS_KEY_ID: &str = "fcp-test-access-key";
const TEST_SIGNING_MATERIAL: &str = "fcp-test-signing-material";
const TEST_MANTLE_TOKEN: &str = "fcp-test-mantle-token";

#[test]
fn manifest_ai_hints_cover_all_aws_bedrock_operations() {
    let manifest = toml::from_str::<toml::Value>(include_str!("../manifest.toml"))
        .expect("AWS Bedrock manifest TOML should parse");
    let operations = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("AWS Bedrock manifest should declare operations");

    for (operation_id, operation) in operations {
        let hints = operation.get("ai_hints").and_then(toml::Value::as_table);
        assert!(hints.is_some(), "{operation_id} missing ai_hints");
        let Some(hints) = hints else {
            continue;
        };
        assert!(
            hints
                .get("when_to_use")
                .and_then(toml::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "{operation_id} missing ai_hints.when_to_use"
        );
        assert!(
            hints
                .get("common_mistakes")
                .and_then(toml::Value::as_array)
                .is_some_and(|mistakes| {
                    !mistakes.is_empty()
                        && mistakes.iter().all(|mistake| {
                            mistake
                                .as_str()
                                .is_some_and(|value| !value.trim().is_empty())
                        })
                }),
            "{operation_id} missing ai_hints.common_mistakes"
        );
        assert!(
            hints
                .get("examples")
                .and_then(toml::Value::as_array)
                .is_some_and(|examples| !examples.is_empty()),
            "{operation_id} missing ai_hints.examples"
        );
    }
}

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("aws_bedrock.chat"),
            CapabilityId::from_static("aws_bedrock.models.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &'static str,
) -> CapabilityToken {
    let capability = match op {
        OP_CONVERSE | OP_CONVERSE_STREAM | OP_INVOKE_MODEL | OP_INVOKE_MODEL_STREAM => {
            Some("aws_bedrock.chat")
        }
        OP_MODELS_LIST | OP_HEALTH => Some("aws_bedrock.models.read"),
        _ => None,
    }
    .expect("unsupported test operation");
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .target_instance(instance_id)
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("aws-bedrock-integration-1"),
        connector_id: ConnectorId::from_static("fcp.aws-bedrock"),
        operation: OperationId::from_static(op),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

async fn setup_connector(mock_url: &str) -> (BedrockConnector, Ed25519SigningKey) {
    setup_connector_with_retry(mock_url, 0).await
}

async fn setup_connector_with_retry(
    mock_url: &str,
    max_retries: u32,
) -> (BedrockConnector, Ed25519SigningKey) {
    setup_connector_with_retry_and_timeout(mock_url, max_retries, 5_000).await
}

async fn setup_connector_with_retry_and_timeout(
    mock_url: &str,
    max_retries: u32,
    request_timeout_ms: u64,
) -> (BedrockConnector, Ed25519SigningKey) {
    let mut connector = BedrockConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "access_key_id": TEST_ACCESS_KEY_ID,
            "secret_access_key": TEST_SIGNING_MATERIAL,
            "region": "us-east-1",
            "runtime_base_url": mock_url,
            "control_base_url": mock_url,
            "retry": {
                "max_retries": max_retries,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": request_timeout_ms
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

async fn setup_mantle_connector(mock_url: &str) -> (BedrockConnector, Ed25519SigningKey) {
    let mut connector = BedrockConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "region": "us-east-1",
            "mantle_bearer_token": TEST_MANTLE_TOKEN,
            "mantle_base_url": mock_url,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 5_000
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

fn assert_sigv4_headers(request: &wiremock::Request) {
    let authorization = request
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("authorization header should be present");
    assert!(
        authorization.starts_with(&format!(
            "AWS4-HMAC-SHA256 Credential={TEST_ACCESS_KEY_ID}/"
        )),
        "unexpected authorization header: {authorization}"
    );
    assert!(authorization.contains("SignedHeaders="));
    assert!(authorization.contains("Signature="));
    assert!(request.headers.get("x-amz-date").is_some());
    assert!(request.headers.get("x-amz-content-sha256").is_some());
    assert!(request.headers.get("x-aws-access-key-id").is_none());
    assert!(request.headers.get("x-aws-secret-access-key").is_none());
}

fn assert_mantle_bearer_headers(request: &wiremock::Request) {
    let authorization = request
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("authorization header should be present");
    assert_eq!(authorization, format!("Bearer {TEST_MANTLE_TOKEN}"));
    assert!(request.headers.get("x-amz-date").is_none());
    assert!(request.headers.get("x-amz-content-sha256").is_none());
    assert!(request.headers.get("x-aws-access-key-id").is_none());
    assert!(request.headers.get("x-aws-secret-access-key").is_none());
}

fn fixture_jsonl_record(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(object) = value.as_object_mut() {
        object
            .entry("schema_version")
            .or_insert_with(|| json!("1.0.0"));
        object
            .entry("redaction_scope")
            .or_insert_with(|| json!("hashed"));
    }
    value
}

fn emit_fixture_jsonl(value: serde_json::Value) {
    println!("AWS_BEDROCK_FIXTURE_JSONL {}", fixture_jsonl_record(value));
}

fn digest16(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(&digest[..8])
}

fn body_size(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value)
        .expect("fixture input should serialize")
        .len()
}

fn request_for_path<'a>(requests: &'a [Request], expected_path: &str) -> &'a Request {
    requests
        .iter()
        .find(|request| request.url.path() == expected_path)
        .expect("missing fixture request")
}

fn request_count_for_path(requests: &[Request], expected_path: &str) -> usize {
    requests
        .iter()
        .filter(|request| request.url.path() == expected_path)
        .count()
}

fn signature_prefix_hash(request: &Request) -> String {
    let authorization = request
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("authorization header should be present");
    let signature = authorization
        .split("Signature=")
        .nth(1)
        .expect("SigV4 signature should be present");
    let first8 = &signature[..signature.len().min(8)];
    digest16(first8)
}

#[test]
fn fixture_jsonl_records_are_schema_versioned_and_redacted() {
    let record = fixture_jsonl_record(json!({
        "event": "bedrock_fixture_contract_check"
    }));
    assert_eq!(record["schema_version"], "1.0.0");
    assert_eq!(record["redaction_scope"], "hashed");
    assert_eq!(record["event"], "bedrock_fixture_contract_check");
}

fn foundation_models_response() -> serde_json::Value {
    json!({
        "modelSummaries": [
            {
                "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1",
                "modelId": "amazon.titan-text-express-v1",
                "modelName": "Titan Text Express",
                "providerName": "Amazon",
                "inputModalities": ["TEXT"],
                "outputModalities": ["TEXT"],
                "responseStreamingSupported": true,
                "customizationsSupported": [],
                "inferenceTypesSupported": ["ON_DEMAND"]
            }
        ]
    })
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured_includes_guidance() {
    let connector = BedrockConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert_eq!(
        details["verification_script"],
        "scripts/e2e/aws_bedrock_connector_verification.sh"
    );
    println!(
        "aws_bedrock_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_remediation() {
    let connector = BedrockConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert!(doctor["operator_guidance"]["redaction_rules"].is_array());
    println!(
        "aws_bedrock_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_custom_control_plane_override() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foundation-models"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_json(foundation_models_response()))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
}

#[fcp_async_core::runtime::test]
async fn self_check_abstains_without_control_plane_override() {
    let mut connector = BedrockConnector::new();
    connector
        .configure(json!({
            "access_key_id": TEST_ACCESS_KEY_ID,
            "secret_access_key": TEST_SIGNING_MATERIAL,
            "region": "us-east-1",
            "retry": { "max_retries": 0 }
        }))
        .await
        .unwrap();

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(
        value["reason_code"],
        "self_check_unsupported_on_default_bedrock"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_converse_signs_sigv4_and_returns_json() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/model/anthropic.claude-3-sonnet-20240229-v1:0/converse",
        ))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .and(body_json(json!({
            "messages": [{
                "role": "user",
                "content": [{"text": "hello"}]
            }],
            "inferenceConfig": {"maxTokens": 64}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "hi"}]
                }
            },
            "usage": {"inputTokens": 1, "outputTokens": 1}
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_CONVERSE,
            json!({
                "model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
                "messages": [{
                    "role": "user",
                    "content": [{"text": "hello"}]
                }],
                "inference_config": {"maxTokens": 64}
            }),
            generate_valid_token(&signing_key, connector.instance_id().as_str(), OP_CONVERSE),
        ))
        .await
        .unwrap();

    let result = response.result.expect("converse result");
    assert_eq!(result["output"]["message"]["role"], "assistant");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
    let request_text = String::from_utf8_lossy(&requests[0].body);
    assert!(!request_text.contains(TEST_SIGNING_MATERIAL));
}

#[fcp_async_core::runtime::test]
async fn invoke_model_uses_per_family_builder() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/model/amazon.titan-text-express-v1/invoke"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .and(body_json(json!({
            "inputText": "hello",
            "textGenerationConfig": {
                "maxTokenCount": 32,
                "temperature": 0.3
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"outputText": "hi"}],
            "inputTextTokenCount": 1
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_INVOKE_MODEL,
            json!({
                "model_id": "amazon.titan-text-express-v1",
                "model_family": "amazon_titan",
                "prompt": "hello",
                "max_tokens": 32,
                "temperature": 0.3
            }),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_INVOKE_MODEL,
            ),
        ))
        .await
        .unwrap();

    let result = response.result.expect("invoke result");
    assert_eq!(result["results"][0]["outputText"], "hi");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
}

#[fcp_async_core::runtime::test]
async fn invoke_model_stream_decodes_event_stream_frames() {
    let server = MockServer::start().await;
    let mut headers = BTreeMap::new();
    headers.insert(":message-type".into(), "event".into());
    headers.insert(":event-type".into(), "chunk".into());
    let frame =
        encode_event_stream_message(&headers, br#"{"bytes":"eyJvdXRwdXRUZXh0IjoiaGkifQ=="}"#);
    Mock::given(method("POST"))
        .and(path(
            "/model/amazon.titan-text-express-v1/invoke-with-response-stream",
        ))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/vnd.amazon.eventstream")
                .set_body_bytes(frame),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_INVOKE_MODEL_STREAM,
            json!({
                "model_id": "amazon.titan-text-express-v1",
                "body": {"inputText": "hello"}
            }),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_INVOKE_MODEL_STREAM,
            ),
        ))
        .await
        .unwrap();

    let result = response.result.expect("stream result");
    assert_eq!(result["chunk_count"], 1);
    assert_eq!(result["events"][0]["event_type"], "chunk");
    assert_eq!(
        result["events"][0]["payload_json"]["bytes"],
        "eyJvdXRwdXRUZXh0IjoiaGkifQ=="
    );
}

#[fcp_async_core::runtime::test]
async fn list_models_invocation_returns_control_plane_models() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/foundation-models"))
        .and(header_exists("Authorization"))
        .and(header_exists("X-Amz-Date"))
        .and(header_exists("X-Amz-Content-Sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_json(foundation_models_response()))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_MODELS_LIST,
            json!({}),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_MODELS_LIST,
            ),
        ))
        .await
        .unwrap();

    let result = response.result.expect("models result");
    assert_eq!(
        result["modelSummaries"][0]["modelId"],
        "amazon.titan-text-express-v1"
    );
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_sigv4_headers(&requests[0]);
}

#[fcp_async_core::runtime::test]
async fn mantle_models_list_uses_bearer_catalog_and_normalizes_models() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header(
            "Authorization",
            format!("Bearer {TEST_MANTLE_TOKEN}"),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "id": "anthropic.claude-opus-4-7",
                    "object": "model",
                    "owned_by": "anthropic"
                }
            ]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_mantle_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_MODELS_LIST,
            json!({"source": "mantle"}),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_MODELS_LIST,
            ),
        ))
        .await
        .unwrap();

    let result = response.result.expect("mantle models result");
    assert_eq!(
        result["modelSummaries"][0]["modelId"],
        "anthropic.claude-opus-4-7"
    );
    assert_eq!(result["modelSummaries"][0]["providerName"], "anthropic");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_mantle_bearer_headers(&requests[0]);
    emit_fixture_jsonl(json!({
        "event": "bedrock_mantle_models_catalog",
        "fixture_mode": true,
        "operation": OP_MODELS_LIST,
        "route": requests[0].url.path(),
        "auth_mode": "mantle_bearer",
        "http_status": 200,
        "normalized_model_count": result["modelSummaries"].as_array().map_or(0, Vec::len),
        "token_material_logged": false
    }));
}

#[fcp_async_core::runtime::test]
async fn mantle_anthropic_messages_uses_bearer_auth_and_default_beta_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/anthropic/v1/messages"))
        .and(header(
            "Authorization",
            format!("Bearer {TEST_MANTLE_TOKEN}"),
        ))
        .and(header(
            "anthropic-beta",
            "fine-grained-tool-streaming-2025-05-14",
        ))
        .and(body_json(json!({
            "model": "anthropic.claude-opus-4-7",
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": "hello"}]
            }],
            "max_tokens": 1024,
            "stream": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_fixture",
            "type": "message",
            "role": "assistant",
            "model": "anthropic.claude-opus-4-7",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_mantle_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_INVOKE_MODEL,
            json!({
                "model_id": "anthropic.claude-opus-4-7",
                "model_family": "mantle_anthropic_messages",
                "messages": [{
                    "role": "user",
                    "content": [{"type": "text", "text": "hello"}]
                }],
                "max_tokens": 1024
            }),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_INVOKE_MODEL,
            ),
        ))
        .await
        .unwrap();

    let result = response.result.expect("mantle anthropic result");
    assert_eq!(result["model"], "anthropic.claude-opus-4-7");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_mantle_bearer_headers(&requests[0]);
    let request_text = String::from_utf8_lossy(&requests[0].body);
    assert!(!request_text.contains(TEST_MANTLE_TOKEN));
    assert!(!request_text.contains(TEST_SIGNING_MATERIAL));
    let request_json: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("mantle request body should be JSON");
    emit_fixture_jsonl(json!({
        "event": "bedrock_mantle_anthropic_request",
        "fixture_mode": true,
        "operation": OP_INVOKE_MODEL,
        "route": requests[0].url.path(),
        "auth_mode": "mantle_bearer",
        "model_id": "anthropic.claude-opus-4-7",
        "request_body_size": body_size(&request_json),
        "stream": request_json["stream"].as_bool(),
        "default_beta_header": true,
        "http_status": 200,
        "token_material_logged": false,
        "prompt_text_logged": false
    }));
}

#[fcp_async_core::runtime::test]
async fn mantle_anthropic_stream_decodes_sse_into_stream_envelope() {
    let server = MockServer::start().await;
    let sse = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fixture\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
        "data: [DONE]\n\n",
    );
    Mock::given(method("POST"))
        .and(path("/anthropic/v1/messages"))
        .and(header(
            "Authorization",
            format!("Bearer {TEST_MANTLE_TOKEN}"),
        ))
        .and(body_json(json!({
            "model": "anthropic.claude-opus-4-7",
            "messages": [{
                "role": "user",
                "content": [{"type": "text", "text": "hello"}]
            }],
            "max_tokens": 1024,
            "stream": true
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_mantle_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_INVOKE_MODEL_STREAM,
            json!({
                "model_id": "anthropic.claude-opus-4-7",
                "model_family": "mantle_anthropic_messages",
                "messages": [{
                    "role": "user",
                    "content": [{"type": "text", "text": "hello"}]
                }],
                "max_tokens": 1024
            }),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_INVOKE_MODEL_STREAM,
            ),
        ))
        .await
        .unwrap();

    let result = response.result.expect("mantle stream result");
    assert_eq!(result["chunk_count"], 2);
    assert_eq!(result["events"][0]["event_type"], "message_start");
    assert_eq!(result["events"][1]["payload_json"]["delta"]["text"], "hi");
    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_mantle_bearer_headers(&requests[0]);
    let request_json: serde_json::Value =
        serde_json::from_slice(&requests[0].body).expect("mantle stream body should be JSON");
    emit_fixture_jsonl(json!({
        "event": "bedrock_mantle_anthropic_sse",
        "fixture_mode": true,
        "operation": OP_INVOKE_MODEL_STREAM,
        "route": requests[0].url.path(),
        "auth_mode": "mantle_bearer",
        "model_id": "anthropic.claude-opus-4-7",
        "request_body_size": body_size(&request_json),
        "stream": request_json["stream"].as_bool(),
        "chunk_count": result["chunk_count"],
        "sse_done_marker_seen": true,
        "http_status": 200,
        "token_material_logged": false,
        "prompt_text_logged": false
    }));
}

#[fcp_async_core::runtime::test]
async fn aws_error_envelope_maps_to_fcp_external_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/model/anthropic.claude-3-sonnet-20240229-v1:0/converse",
        ))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "__type": "ValidationException",
            "message": "bad request shape"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri()).await;
    let err = connector
        .invoke(invoke_req(
            OP_CONVERSE,
            json!({
                "model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
                "messages": [{
                    "role": "user",
                    "content": [{"text": "hello"}]
                }]
            }),
            generate_valid_token(&signing_key, connector.instance_id().as_str(), OP_CONVERSE),
        ))
        .await
        .unwrap_err();

    let text = err.to_string();
    assert!(text.contains("ValidationException"));
    assert!(text.contains("bad request shape"));
}

#[fcp_async_core::runtime::test]
async fn fixture_e2e_jsonl_exercises_connector_boundary() {
    let server = MockServer::start().await;

    let converse_model = "anthropic.claude-3-sonnet-20240229-v1:0";
    let converse_path = format!("/model/{converse_model}/converse");
    let converse_stream_model = "anthropic.claude-3-haiku-20240307-v1:0";
    let converse_stream_path = format!("/model/{converse_stream_model}/converse-stream");
    let invoke_model = "amazon.titan-text-express-v1";
    let invoke_path = format!("/model/{invoke_model}/invoke");
    let invoke_stream_path = format!("/model/{invoke_model}/invoke-with-response-stream");
    let retry_model = "meta.llama3-8b-instruct-v1:0";
    let retry_path = format!("/model/{retry_model}/converse");
    let error_model = "mistral.mistral-7b-instruct-v0:2";
    let error_path = format!("/model/{error_model}/converse");
    let timeout_model = "cohere.command-r-v1:0";
    let timeout_path = format!("/model/{timeout_model}/converse");

    Mock::given(method("GET"))
        .and(path("/foundation-models"))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(foundation_models_response()))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(converse_path.as_str()))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "fixture"}]
                }
            },
            "usage": {"inputTokens": 3, "outputTokens": 1}
        })))
        .mount(&server)
        .await;

    let mut converse_stream_headers = BTreeMap::new();
    converse_stream_headers.insert(":message-type".into(), "event".into());
    converse_stream_headers.insert(":event-type".into(), "contentBlockDelta".into());
    let converse_stream_frame =
        encode_event_stream_message(&converse_stream_headers, br#"{"delta":{"text":"x"}}"#);
    Mock::given(method("POST"))
        .and(path(converse_stream_path.as_str()))
        .and(header_exists("Authorization"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/vnd.amazon.eventstream")
                .set_body_bytes(converse_stream_frame),
        )
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(invoke_path.as_str()))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"outputText": "fixture"}],
            "inputTextTokenCount": 3
        })))
        .mount(&server)
        .await;

    let mut invoke_stream_headers = BTreeMap::new();
    invoke_stream_headers.insert(":message-type".into(), "event".into());
    invoke_stream_headers.insert(":event-type".into(), "chunk".into());
    let invoke_stream_frame =
        encode_event_stream_message(&invoke_stream_headers, br#"{"bytes":"eyJ0ZXh0IjoieCJ9"}"#);
    Mock::given(method("POST"))
        .and(path(invoke_stream_path.as_str()))
        .and(header_exists("Authorization"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/vnd.amazon.eventstream")
                .set_body_bytes(invoke_stream_frame),
        )
        .mount(&server)
        .await;

    let retry_attempts = Arc::new(AtomicUsize::new(0));
    let retry_responder_attempts = Arc::clone(&retry_attempts);
    Mock::given(method("POST"))
        .and(path(retry_path.as_str()))
        .and(header_exists("Authorization"))
        .respond_with(move |_request: &Request| {
            if retry_responder_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "0")
                    .set_body_json(json!({
                        "__type": "ThrottlingException",
                        "message": "fixture retry"
                    }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "output": {
                        "message": {
                            "role": "assistant",
                            "content": [{"text": "retried"}]
                        }
                    },
                    "usage": {"inputTokens": 3, "outputTokens": 1}
                }))
            }
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(error_path.as_str()))
        .and(header_exists("Authorization"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "__type": "ValidationException",
            "message": "fixture provider error"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(timeout_path.as_str()))
        .and(header_exists("Authorization"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(StdDuration::from_millis(150))
                .set_body_json(json!({
                    "output": {
                        "message": {
                            "role": "assistant",
                            "content": [{"text": "late fixture response"}]
                        }
                    }
                })),
        )
        .mount(&server)
        .await;

    let (mut connector, signing_key) = setup_connector_with_retry(&server.uri(), 1).await;
    let (mut timeout_connector, timeout_signing_key) =
        setup_connector_with_retry_and_timeout(&server.uri(), 0, 20).await;
    let git_revision = option_env!("GIT_REVISION").unwrap_or("unknown");
    let command_line = "cargo test -p fcp-aws-bedrock --test integration fixture_e2e_jsonl_exercises_connector_boundary -- --nocapture";

    let models_input = json!({});
    let started = Instant::now();
    let models_response = connector
        .invoke(invoke_req(
            OP_MODELS_LIST,
            models_input.clone(),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_MODELS_LIST,
            ),
        ))
        .await
        .unwrap();
    let models_latency_ms = started.elapsed().as_millis();
    let models_result = models_response.result.expect("models.list fixture result");

    let converse_input = json!({
        "model_id": converse_model,
        "messages": [{
            "role": "user",
            "content": [{"text": "redacted fixture prompt"}]
        }],
        "inference_config": {"maxTokens": 4}
    });
    let started = Instant::now();
    let converse_response = connector
        .invoke(invoke_req(
            OP_CONVERSE,
            converse_input.clone(),
            generate_valid_token(&signing_key, connector.instance_id().as_str(), OP_CONVERSE),
        ))
        .await
        .unwrap();
    let converse_latency_ms = started.elapsed().as_millis();
    let converse_result = converse_response.result.expect("converse fixture result");

    let converse_stream_input = json!({
        "model_id": converse_stream_model,
        "messages": [{
            "role": "user",
            "content": [{"text": "redacted fixture stream prompt"}]
        }],
        "inference_config": {"maxTokens": 4}
    });
    let started = Instant::now();
    let converse_stream_response = connector
        .invoke(invoke_req(
            OP_CONVERSE_STREAM,
            converse_stream_input.clone(),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_CONVERSE_STREAM,
            ),
        ))
        .await
        .unwrap();
    let converse_stream_latency_ms = started.elapsed().as_millis();
    let converse_stream_result = converse_stream_response
        .result
        .expect("converse stream fixture result");

    let invoke_input = json!({
        "model_id": invoke_model,
        "model_family": "amazon_titan",
        "prompt": "redacted fixture invoke prompt",
        "max_tokens": 4
    });
    let started = Instant::now();
    let invoke_response = connector
        .invoke(invoke_req(
            OP_INVOKE_MODEL,
            invoke_input.clone(),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_INVOKE_MODEL,
            ),
        ))
        .await
        .unwrap();
    let invoke_latency_ms = started.elapsed().as_millis();
    let invoke_result = invoke_response.result.expect("invoke fixture result");

    let invoke_stream_input = json!({
        "model_id": invoke_model,
        "body": {"inputText": "redacted fixture invoke stream prompt"}
    });
    let started = Instant::now();
    let invoke_stream_response = connector
        .invoke(invoke_req(
            OP_INVOKE_MODEL_STREAM,
            invoke_stream_input.clone(),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_INVOKE_MODEL_STREAM,
            ),
        ))
        .await
        .unwrap();
    let invoke_stream_latency_ms = started.elapsed().as_millis();
    let invoke_stream_result = invoke_stream_response
        .result
        .expect("invoke stream fixture result");

    let denied_error = connector
        .invoke(invoke_req(
            OP_MODELS_LIST,
            json!({}),
            generate_valid_token(&signing_key, connector.instance_id().as_str(), OP_CONVERSE),
        ))
        .await
        .unwrap_err();

    let error_input = json!({
        "model_id": error_model,
        "messages": [{
            "role": "user",
            "content": [{"text": "redacted fixture provider-error prompt"}]
        }]
    });
    let provider_error = connector
        .invoke(invoke_req(
            OP_CONVERSE,
            error_input.clone(),
            generate_valid_token(&signing_key, connector.instance_id().as_str(), OP_CONVERSE),
        ))
        .await
        .unwrap_err();

    let retry_input = json!({
        "model_id": retry_model,
        "messages": [{
            "role": "user",
            "content": [{"text": "redacted fixture retry prompt"}]
        }],
        "inference_config": {"maxTokens": 4}
    });
    let retry_response = connector
        .invoke(invoke_req(
            OP_CONVERSE,
            retry_input.clone(),
            generate_valid_token(&signing_key, connector.instance_id().as_str(), OP_CONVERSE),
        ))
        .await
        .unwrap();
    let retry_result = retry_response.result.expect("retry fixture result");
    assert_eq!(retry_attempts.load(Ordering::SeqCst), 2);

    let timeout_input = json!({
        "model_id": timeout_model,
        "messages": [{
            "role": "user",
            "content": [{"text": "redacted fixture timeout prompt"}]
        }],
        "inference_config": {"maxTokens": 4}
    });
    let timeout_started = Instant::now();
    let timeout_error = timeout_connector
        .invoke(invoke_req(
            OP_CONVERSE,
            timeout_input.clone(),
            generate_valid_token(
                &timeout_signing_key,
                timeout_connector.instance_id().as_str(),
                OP_CONVERSE,
            ),
        ))
        .await
        .expect_err("slow Bedrock fixture response should exceed request timeout");
    let timeout_elapsed_ms =
        u64::try_from(timeout_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let timeout_error_text = timeout_error.to_string();
    assert!(
        timeout_error_text.contains("timed out")
            || timeout_error_text.contains("timeout")
            || timeout_error_text.contains("deadline exceeded"),
        "unexpected timeout mapping: {timeout_error_text}"
    );

    connector
        .shutdown(fcp_prelude::ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: false,
            reason: Some("fixture boundary cleanup".into()),
        })
        .await
        .unwrap();
    timeout_connector
        .shutdown(fcp_prelude::ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: false,
            reason: Some("fixture timeout cleanup".into()),
        })
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap_or_default();
    for request in &requests {
        assert_sigv4_headers(request);
        let request_text = String::from_utf8_lossy(&request.body);
        assert!(!request_text.contains(TEST_SIGNING_MATERIAL));
    }

    let models_request = request_for_path(&requests, "/foundation-models");
    let converse_request = request_for_path(&requests, &converse_path);
    let converse_stream_request = request_for_path(&requests, &converse_stream_path);
    let invoke_request = request_for_path(&requests, &invoke_path);
    let invoke_stream_request = request_for_path(&requests, &invoke_stream_path);
    let retry_request_count = request_count_for_path(&requests, &retry_path);
    let error_request = request_for_path(&requests, &error_path);
    let timeout_request = request_for_path(&requests, &timeout_path);
    let timeout_request_count = request_count_for_path(&requests, &timeout_path);
    assert_eq!(timeout_request_count, 1);

    emit_fixture_jsonl(json!({
        "event": "bedrock_fixture_start",
        "status": "running",
        "fixture_mode": "wiremock",
        "command_line": command_line,
        "git_revision": git_revision,
        "region": "us-east-1",
        "connector_id": "fcp.aws-bedrock",
        "redaction": "no prompts, completions, AWS keys, session tokens, or full signatures are emitted"
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_built",
        "op": OP_MODELS_LIST,
        "api": "control",
        "fixture_mode": "wiremock",
        "region": "us-east-1",
        "body_size": body_size(&models_input)
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_signed",
        "op": OP_MODELS_LIST,
        "api": "control",
        "signature_prefix_hash": signature_prefix_hash(models_request),
        "full_signature_logged": false
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_response_decoded",
        "op": OP_MODELS_LIST,
        "api": "control",
        "http_status": 200,
        "model_count": models_result["modelSummaries"].as_array().map_or(0, Vec::len),
        "latency_ms": models_latency_ms,
        "retry_decision": "not_retryable_success",
        "audit_receipt_id_hash": digest16("fixture:bedrock:models.list")
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_built",
        "op": OP_CONVERSE,
        "api": "converse",
        "fixture_mode": "wiremock",
        "region": "us-east-1",
        "model_id": converse_model,
        "body_size": body_size(&converse_input)
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_signed",
        "op": OP_CONVERSE,
        "api": "converse",
        "model_id": converse_model,
        "signature_prefix_hash": signature_prefix_hash(converse_request),
        "full_signature_logged": false
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_response_decoded",
        "op": OP_CONVERSE,
        "api": "converse",
        "model_id": converse_model,
        "http_status": 200,
        "output_token_count": converse_result.pointer("/usage/outputTokens").and_then(serde_json::Value::as_u64),
        "latency_ms": converse_latency_ms,
        "retry_decision": "not_retryable_success",
        "audit_receipt_id_hash": digest16("fixture:bedrock:converse")
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_built",
        "op": OP_CONVERSE_STREAM,
        "api": "converse_stream",
        "fixture_mode": "wiremock",
        "region": "us-east-1",
        "model_id": converse_stream_model,
        "body_size": body_size(&converse_stream_input)
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_signed",
        "op": OP_CONVERSE_STREAM,
        "api": "converse_stream",
        "model_id": converse_stream_model,
        "signature_prefix_hash": signature_prefix_hash(converse_stream_request),
        "full_signature_logged": false
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_streaming_chunk_count",
        "op": OP_CONVERSE_STREAM,
        "api": "converse_stream",
        "model_id": converse_stream_model,
        "http_status": 200,
        "chunk_count": converse_stream_result["chunk_count"].as_u64(),
        "total_chars": 0,
        "latency_ms": converse_stream_latency_ms,
        "audit_receipt_id_hash": digest16("fixture:bedrock:converse_stream")
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_built",
        "op": OP_INVOKE_MODEL,
        "api": "invoke_model",
        "fixture_mode": "wiremock",
        "region": "us-east-1",
        "model_id": invoke_model,
        "body_size": body_size(&invoke_input)
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_signed",
        "op": OP_INVOKE_MODEL,
        "api": "invoke_model",
        "model_id": invoke_model,
        "signature_prefix_hash": signature_prefix_hash(invoke_request),
        "full_signature_logged": false
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_response_decoded",
        "op": OP_INVOKE_MODEL,
        "api": "invoke_model",
        "model_id": invoke_model,
        "http_status": 200,
        "output_token_count": invoke_result["results"].as_array().map_or(0, Vec::len),
        "latency_ms": invoke_latency_ms,
        "retry_decision": "not_retryable_success",
        "audit_receipt_id_hash": digest16("fixture:bedrock:invoke_model")
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_built",
        "op": OP_INVOKE_MODEL_STREAM,
        "api": "invoke_model_stream",
        "fixture_mode": "wiremock",
        "region": "us-east-1",
        "model_id": invoke_model,
        "body_size": body_size(&invoke_stream_input)
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_request_signed",
        "op": OP_INVOKE_MODEL_STREAM,
        "api": "invoke_model_stream",
        "model_id": invoke_model,
        "signature_prefix_hash": signature_prefix_hash(invoke_stream_request),
        "full_signature_logged": false
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_streaming_chunk_count",
        "op": OP_INVOKE_MODEL_STREAM,
        "api": "invoke_model_stream",
        "model_id": invoke_model,
        "http_status": 200,
        "chunk_count": invoke_stream_result["chunk_count"].as_u64(),
        "total_chars": 0,
        "latency_ms": invoke_stream_latency_ms,
        "audit_receipt_id_hash": digest16("fixture:bedrock:invoke_model_stream")
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_auth_denied",
        "op": OP_MODELS_LIST,
        "fixture_mode": "wiremock",
        "http_request_sent": false,
        "fcp_error_code": denied_error.error_code(),
        "fcp_error_mapping": denied_error.to_string()
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_provider_error",
        "op": OP_CONVERSE,
        "api": "converse",
        "model_id": error_model,
        "http_status": 400,
        "signature_prefix_hash": signature_prefix_hash(error_request),
        "retry_decision": "terminal_validation_error",
        "fcp_error_code": provider_error.error_code(),
        "fcp_error_mapping": provider_error.to_string()
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_retry_decision",
        "op": OP_CONVERSE,
        "api": "converse",
        "model_id": retry_model,
        "http_status_sequence": [429, 200],
        "retry_decision": "retry_after_then_success",
        "attempt_count": retry_request_count,
        "output_token_count": retry_result.pointer("/usage/outputTokens").and_then(serde_json::Value::as_u64)
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_timeout_cancellation",
        "op": OP_CONVERSE,
        "api": "converse",
        "fixture_mode": "wiremock",
        "model_id": timeout_model,
        "http_status": "client_timeout",
        "retry_decision": "request_timeout_no_retry",
        "elapsed_ms": timeout_elapsed_ms,
        "fcp_error_code": timeout_error.error_code(),
        "fcp_error_mapping": timeout_error_text,
        "signature_prefix_hash": signature_prefix_hash(timeout_request)
    }));
    emit_fixture_jsonl(json!({
        "event": "bedrock_cleanup",
        "status": "ok",
        "cleanup_result": "shutdown_completed_no_durable_state",
        "fixture_mode": "wiremock"
    }));
}
