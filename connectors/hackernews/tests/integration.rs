//! Integration tests for the Hacker News connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_hackernews::client::HackerNewsClient;
use fcp_hackernews::connector::{HackerNewsConnector, operations_info};
use fcp_hackernews::error::HackerNewsError;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, IdempotencyClass, InstanceId, InvokeRequest, InvokeStatus, OperationId,
    RequestId, ZoneId,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_ITEM_GET: &str = "hackernews.item.get";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/hackernews_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/hackernews_connector/<timestamp>";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [31u8; 32],
        capabilities_requested: vec![CapabilityId::from_static("hackernews.read")],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    op: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id("hackernews.read")
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should be valid")
        .target_instance(instance_id.as_str())
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
        id: RequestId::new("hackernews-integration-1"),
        connector_id: ConnectorId::from_static("fcp.hackernews"),
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

async fn setup_connector(base_url: &str) -> (HackerNewsConnector, Ed25519SigningKey) {
    let mut connector = HackerNewsConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "base_url": base_url,
            "request_timeout_ms": 1_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

fn test_client(server: &MockServer) -> HackerNewsClient {
    HackerNewsClient::new(
        Some(&format!("{}/v0", server.uri())),
        HttpRetryConfig::default(),
    )
    .expect("wiremock URI should build Hacker News client")
}

fn test_runtime() -> ConnectorRuntime {
    ConnectorRuntime::new(ConnectorRuntimeConfig::default())
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = HackerNewsConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["limitations"].is_array());
    println!(
        "hackernews_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn client_health_check_statuses_are_typed() {
    let success_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/topstories.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([1, 2, 3])))
        .mount(&success_server)
        .await;
    assert!(test_client(&success_server).health_check().await.is_ok());

    let failure_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/topstories.json"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream unavailable"))
        .mount(&failure_server)
        .await;
    let err = test_client(&failure_server)
        .health_check()
        .await
        .expect_err("500 health check should fail");
    assert!(matches!(
        err,
        HackerNewsError::Api {
            status: 500,
            message
        } if message.contains("500")
    ));
}

#[fcp_async_core::runtime::test]
async fn client_item_user_and_story_endpoints_decode_contracts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/item/8863.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 8863,
            "type": "story",
            "by": "dhouston",
            "time": 1_175_714_200,
            "title": "My YC app: Dropbox",
            "url": "http://www.getdropbox.com",
            "score": 111,
            "descendants": 71,
            "kids": [8952, 9224]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v0/item/99999999.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string("null"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v0/user/jl.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "jl",
            "created": 1_173_923_446,
            "karma": 2937,
            "about": "Test user"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v0/topstories.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([100, 200, 300])))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let runtime = test_runtime();
    let item = client.get_item(&runtime, 8863).await.unwrap();
    assert_eq!(item.title.as_deref(), Some("My YC app: Dropbox"));
    let missing = client.get_item(&runtime, 99_999_999).await.unwrap_err();
    assert!(matches!(missing, HackerNewsError::NotFound(_)));
    let user = client.get_user(&runtime, "jl").await.unwrap();
    assert_eq!(user.karma, 2937);
    let ids = client.top_stories(&runtime).await.unwrap();
    assert_eq!(ids, vec![100, 200, 300]);
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let connector = HackerNewsConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "hackernews_doctor_unconfigured={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_public_probe_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/topstories.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([1, 2, 3])))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&format!("{}/v0", server.uri())).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert_eq!(value["details"]["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert_eq!(
        value["details"]["provisioning"]["auth_mode"],
        "anonymous_public_api"
    );
    assert_eq!(value["details"]["provisioning"]["search_supported"], false);
    assert_eq!(
        value["details"]["live_probe"]["base_url"],
        format!("{}/v0", server.uri())
    );
    println!(
        "hackernews_self_check_ready={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_api_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/topstories.json"))
        .respond_with(ResponseTemplate::new(503).set_body_string("temporary upstream outage"))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&format!("{}/v0", server.uri())).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
    assert_eq!(value["details"]["live_probe"]["retryable"], true);
    println!(
        "hackernews_self_check_retryable={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_item_get_preserves_public_item_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/item/8863.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 8863,
            "type": "story",
            "by": "dhouston",
            "time": 1_175_714_200,
            "title": "My YC app: Dropbox",
            "url": "http://www.getdropbox.com",
            "score": 111,
            "descendants": 71,
            "kids": [8952, 9224]
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&format!("{}/v0", server.uri())).await;
    let response = connector
        .invoke(invoke_req(
            OP_ITEM_GET,
            json!({ "id": 8863 }),
            generate_valid_token(&signing_key, OP_ITEM_GET, connector.instance_id()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("item get result");
    assert_eq!(result["id"], 8863);
    assert_eq!(result["type"], "story");
    assert_eq!(result["title"], "My YC app: Dropbox");
    println!(
        "hackernews_item_get_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = HackerNewsConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");
    let resource_types = value["resource_types"]
        .as_array()
        .expect("resource types array");

    assert_eq!(operations.len(), 9);
    assert_eq!(resource_types.len(), 3);
    assert!(value["auth_caps"].is_null());
    assert!(value["events"].as_array().is_some_and(Vec::is_empty));
    assert!(operations.iter().all(|operation| {
        operation["id"]
            .as_str()
            .is_some_and(|id| !id.contains("search"))
    }));

    let item_get = operations_info()
        .into_iter()
        .find(|operation| operation.id.as_str() == OP_ITEM_GET)
        .expect("item.get operation");
    assert_eq!(item_get.idempotency, IdempotencyClass::Strict);

    println!(
        "hackernews_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}
