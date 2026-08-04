//! Integration tests for the FCP Zoom connector.

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
use fcp_prelude::{
    ApprovalMode, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, IdempotencyClass, InvokeRequest, InvokeStatus, OperationId, RequestId,
    SafetyTier, ZoneId,
};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use fcp_zoom::ZoomConnector;
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_MEETINGS_LIST: &str = "zoom.meetings.list";
const OP_MEETINGS_DELETE: &str = "zoom.meetings.delete";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/zoom_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/zoom_connector/<timestamp>";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [17u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("zoom.meetings.read"),
            CapabilityId::from_static("zoom.meetings.write"),
            CapabilityId::from_static("zoom.users.read"),
            CapabilityId::from_static("zoom.recordings.read"),
            CapabilityId::from_static("zoom.webinars.read"),
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
        OP_MEETINGS_LIST => "zoom.meetings.read",
        OP_MEETINGS_DELETE => "zoom.meetings.write",
        _ => panic!("unsupported Zoom integration operation: {op}"),
    };
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints should serialize into capability token")
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
        id: RequestId::new("zoom-integration-1"),
        connector_id: ConnectorId::from_static("fcp.zoom"),
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

async fn mock_oauth_token(server: &MockServer, access_token: &str) {
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .mount(server)
        .await;
}

async fn setup_connector(server: &MockServer) -> (ZoomConnector, Ed25519SigningKey) {
    let mut connector = ZoomConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "base_url": format!("{}/v2", server.uri()),
            "oauth_base_url": server.uri(),
            "account_id": "acc_123",
            "client_id": "cid_test",
            "client_secret": "csec_test",
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

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = ZoomConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "zoom_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let connector = ZoomConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "zoom_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_zoom_api_and_evidence() {
    let server = MockServer::start().await;
    mock_oauth_token(&server, "t-ready").await;
    Mock::given(method("GET"))
        .and(path("/v2/users/me"))
        .and(header("authorization", "Bearer t-ready"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "user_123",
            "email": "zoom-test@example.com"
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "zoom_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

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
        "server_to_server_oauth"
    );
    println!(
        "zoom_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_zoom_failure_reports_degraded() {
    let server = MockServer::start().await;
    mock_oauth_token(&server, "t-retry").await;
    Mock::given(method("GET"))
        .and(path("/v2/users/me"))
        .and(header("authorization", "Bearer t-retry"))
        .respond_with(ResponseTemplate::new(503).set_body_string("zoom unavailable"))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
}

#[fcp_async_core::runtime::test]
async fn invoke_meetings_list_preserves_pagination_evidence() {
    let server = MockServer::start().await;
    mock_oauth_token(&server, "t-list").await;
    Mock::given(method("GET"))
        .and(path("/v2/users/me/meetings"))
        .and(query_param("page_size", "2"))
        .and(query_param("next_page_token", "next-1"))
        .and(header("authorization", "Bearer t-list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "meetings": [{
                "id": 123456789,
                "topic": "Sprint sync"
            }],
            "total_records": 3,
            "next_page_token": "next-2"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server).await;
    let response = connector
        .invoke(invoke_req(
            OP_MEETINGS_LIST,
            json!({
                "user_id": "me",
                "page_size": 2,
                "next_page_token": "next-1"
            }),
            generate_valid_token(&signing_key, connector.instance_id(), OP_MEETINGS_LIST),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("meetings list result");
    assert_eq!(result["next_page_token"], "next-2");
    assert_eq!(result["total_records"], 3);
    println!(
        "zoom_pagination_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_dangerous_meetings_delete_preserves_artifact_evidence() {
    let server = MockServer::start().await;
    mock_oauth_token(&server, "t-delete").await;
    Mock::given(method("DELETE"))
        .and(path("/v2/meetings/987654321"))
        .and(header("authorization", "Bearer t-delete"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server).await;
    let response = connector
        .invoke(invoke_req(
            OP_MEETINGS_DELETE,
            json!({ "meeting_id": "987654321" }),
            generate_valid_token(&signing_key, connector.instance_id(), OP_MEETINGS_DELETE),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("meetings delete result");
    assert_eq!(result["status"], "deleted");
    println!(
        "zoom_dangerous_delete_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = ZoomConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");
    assert_eq!(operations.len(), 10);
    assert!(operations.iter().all(|operation| {
        operation["ai_hints"]["when_to_use"]
            .as_str()
            .is_some_and(|when_to_use| !when_to_use.is_empty())
    }));

    let delete = operations
        .iter()
        .find(|operation| operation["id"] == OP_MEETINGS_DELETE)
        .expect("meetings delete operation");
    assert_eq!(
        delete["safety_tier"],
        serde_json::to_value(SafetyTier::Dangerous).unwrap()
    );
    assert_eq!(
        delete["requires_approval"],
        serde_json::to_value(ApprovalMode::Interactive).unwrap()
    );

    let health = operations
        .iter()
        .find(|operation| operation["id"] == "zoom.health")
        .expect("health operation");
    assert_eq!(
        health["idempotency"],
        serde_json::to_value(IdempotencyClass::Strict).unwrap()
    );

    println!(
        "zoom_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

// ============================================================================
// Replay safety on retry (br-kxd3e)
// ============================================================================
//
// Zoom has no idempotency key, so a 5xx retry on create_meeting schedules a
// second meeting and sends a second set of invitations.
//
// The token-mint step inside this helper is deliberately NOT gated: if minting
// the OAuth token failed, the create request was never sent, so retrying it is
// safe. Only the create request itself is.

fn zoom_replay_client(server: &MockServer) -> fcp_zoom::client::ZoomClient {
    fcp_zoom::client::ZoomClient::new(
        &server.uri(),
        &server.uri(),
        "acct",
        "cid",
        "csecret",
        fcp_sdk::migration::HttpRetryConfig {
            max_retries: 3,
            initial_delay_ms: 1,
            max_delay_ms: 5,
            jitter_enabled: false,
        },
    )
    .expect("wiremock URI should build a Zoom client")
}

async fn mount_zoom_token(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .mount(server)
        .await;
}

#[fcp_async_core::runtime::test]
async fn create_meeting_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    mount_zoom_token(&server).await;
    Mock::given(method("POST"))
        .and(path("/users/me/meetings"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let runtime = fcp_sdk::ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default());
    let request = fcp_zoom::types::CreateMeetingRequest {
        topic: "Standup".into(),
        meeting_type: Some(2),
        start_time: None,
        duration: None,
        timezone: None,
        agenda: None,
        password: None,
    };
    let result = zoom_replay_client(&server)
        .create_meeting(&runtime, "me", &request)
        .await;
    assert!(result.is_err());

    let meeting_posts = server
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path().ends_with("/meetings"))
        .count();
    assert_eq!(
        meeting_posts, 1,
        "a 503 means Zoom received the create — retrying schedules a SECOND \
         meeting and sends a second set of invitations"
    );
}
