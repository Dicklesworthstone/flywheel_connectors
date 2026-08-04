//! Integration tests for the LINE connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::{sync::Arc, time::Duration as StdDuration};

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_line::client::LineClient;
use fcp_line::connector::{LineConnector, operations_info};
use fcp_line::error::LineError;
use fcp_prelude::{
    ApprovalMode, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    FcpError, HandshakeRequest, IdempotencyClass, InstanceId, InvokeRequest, InvokeStatus,
    OperationId, RequestId, SafetyTier, ZoneId,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ChatCoordinationBackend, InMemoryThreadOwnershipChecker};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_PUSH: &str = "line.messages.push";
const OP_REPLY: &str = "line.messages.reply";
const OP_MULTICAST: &str = "line.messages.multicast";
const OP_GROUP_MEMBERS: &str = "line.group.members";
const OP_RICH_MENU_DELETE: &str = "line.rich_menu.delete";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/line_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/line_connector/<timestamp>";
const TOKEN: &str = "line_test_token";

fn handshake_req(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [29u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("line.messages.write"),
            CapabilityId::from_static("line.profile.read"),
            CapabilityId::from_static("line.menu.read"),
            CapabilityId::from_static("line.menu.write"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    op: &'static str,
) -> CapabilityToken {
    let capability = capability_for_operation(op).expect("LINE integration operation supported");
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
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor accepted")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn capability_for_operation(op: &str) -> Option<&'static str> {
    match op {
        OP_PUSH | OP_REPLY | OP_MULTICAST => Some("line.messages.write"),
        OP_GROUP_MEMBERS => Some("line.profile.read"),
        OP_RICH_MENU_DELETE => Some("line.menu.write"),
        _ => None,
    }
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("line-integration-1"),
        connector_id: ConnectorId::from_static("fcp.line"),
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

async fn setup_connector(base_url: &str) -> (LineConnector, Ed25519SigningKey, InstanceId) {
    setup_connector_with_checker(base_url, None).await
}

async fn setup_connector_with_checker(
    base_url: &str,
    checker: Option<Arc<InMemoryThreadOwnershipChecker>>,
) -> (LineConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = match checker {
        Some(checker) => LineConnector::new()
            .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory),
        None => LineConnector::new(),
    };
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    connector
        .configure(json!({
            "base_url": base_url,
            "channel_access_token": TOKEN,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            },
            "request_timeout_ms": 1_000
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(
            signing_key.verifying_key().to_bytes(),
            instance_id.clone(),
        ))
        .await
        .unwrap();
    (connector, signing_key, instance_id)
}

async fn recorded_json_body(server: &MockServer) -> serde_json::Value {
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 1);
    serde_json::from_slice(&requests[0].body).expect("request body should be JSON")
}

async fn mock_bot_info(server: &MockServer, status: u16) {
    let response = match status {
        200 => ResponseTemplate::new(200).set_body_json(json!({
            "userId": "Ubot123",
            "basicId": "@fcp-line-test",
            "displayName": "FCP LINE Test Bot"
        })),
        429 => ResponseTemplate::new(429).insert_header("retry-after", "2"),
        _ => ResponseTemplate::new(status),
    };

    Mock::given(method("GET"))
        .and(path("/v2/bot/info"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(response)
        .mount(server)
        .await;
}

fn line_client(server: &MockServer, token: &str) -> LineClient {
    LineClient::new(
        &server.uri(),
        token,
        HttpRetryConfig::default(),
        StdDuration::from_secs(30),
    )
    .expect("wiremock URI should build LINE client")
}

fn client_runtime() -> ConnectorRuntime {
    ConnectorRuntime::new(ConnectorRuntimeConfig::default())
}

#[fcp_async_core::runtime::test]
async fn client_health_check_statuses_and_secretless_auth_contracts() {
    let success_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/bot/info"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&success_server)
        .await;
    assert!(
        line_client(&success_server, TOKEN)
            .health_check()
            .await
            .is_ok()
    );

    let unauthorized_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/bot/info"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&unauthorized_server)
        .await;
    let unauthorized = line_client(&unauthorized_server, "bad_tok")
        .health_check()
        .await;
    assert!(matches!(unauthorized, Err(LineError::Unauthorized(_))));

    let secretless_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/bot/info"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&secretless_server)
        .await;
    assert!(
        line_client(&secretless_server, "")
            .health_check()
            .await
            .is_ok()
    );
    let requests = secretless_server
        .received_requests()
        .await
        .unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers.get("authorization").is_none());
}

#[fcp_async_core::runtime::test]
async fn client_group_members_start_query_is_percent_encoded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/bot/group/C123/members/ids"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "memberIds": [],
            "next": null
        })))
        .mount(&server)
        .await;

    line_client(&server, TOKEN)
        .get_group_members(&client_runtime(), "C123", Some("tok&other=value"))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.query(), Some("start=tok%26other%3Dvalue"));
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = LineConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "line_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_reports_operator_guidance() {
    let connector = LineConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "line_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_line_api_and_evidence() {
    let server = MockServer::start().await;
    mock_bot_info(&server, 200).await;

    let (connector, _signing_key, _instance_id) = setup_connector(&server.uri()).await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "line_doctor_evidence={}",
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
        "bearer_channel_access_token"
    );
    assert_eq!(
        value["details"]["live_probe"]["endpoint"],
        "GET /v2/bot/info"
    );
    assert_eq!(value["details"]["live_probe"]["status"], "ok");
    println!(
        "line_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_line_failure_reports_degraded() {
    let server = MockServer::start().await;
    mock_bot_info(&server, 429).await;

    let (connector, _signing_key, _instance_id) = setup_connector(&server.uri()).await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
    assert_eq!(value["details"]["live_probe"]["retryable"], true);
}

#[fcp_async_core::runtime::test]
async fn invoke_reply_sends_template_message_json() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/reply"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_REPLY,
            json!({
                "reply_token": "reply-token-1",
                "messages": [{
                    "type": "template",
                    "altText": "Confirm deployment",
                    "template": {
                        "type": "confirm",
                        "text": "Deploy now?",
                        "actions": [
                            { "type": "message", "label": "Yes", "text": "deploy yes" },
                            { "type": "postback", "label": "No", "data": "deploy=no", "displayText": "No" }
                        ]
                    }
                }]
            }),
            generate_valid_token(&signing_key, &instance_id, OP_REPLY),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let body = recorded_json_body(&server).await;
    assert_eq!(body["replyToken"], "reply-token-1");
    assert_eq!(body["messages"][0]["type"], "template");
    assert_eq!(body["messages"][0]["template"]["type"], "confirm");
    assert_eq!(
        body["messages"][0]["template"]["actions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_push_sends_flex_message_json() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/push"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_PUSH,
            json!({
                "to": "U123",
                "messages": [{
                    "type": "flex",
                    "altText": "Status card",
                    "contents": {
                        "type": "bubble",
                        "body": {
                            "type": "box",
                            "layout": "vertical",
                            "contents": [
                                { "type": "text", "text": "Ready" }
                            ]
                        }
                    }
                }]
            }),
            generate_valid_token(&signing_key, &instance_id, OP_PUSH),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let body = recorded_json_body(&server).await;
    assert_eq!(body["to"], "U123");
    assert_eq!(body["messages"][0]["type"], "flex");
    assert_eq!(body["messages"][0]["altText"], "Status card");
    assert_eq!(body["messages"][0]["contents"]["type"], "bubble");
    let result = response.result.expect("push result");
    assert_eq!(result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(result["coordination"][1]["outcome"], "granted");
    assert_eq!(result["coordination"][2]["event"], "send_executed");
    assert!(
        !serde_json::to_string(&result["coordination"])
            .unwrap()
            .contains("U123")
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_push_claims_recipient_and_denies_duplicate_before_http() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/push"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let (connector_a, signing_key_a, instance_id_a) =
        setup_connector_with_checker(&server.uri(), Some(checker.clone())).await;
    let (connector_b, signing_key_b, instance_id_b) =
        setup_connector_with_checker(&server.uri(), Some(checker)).await;

    let input = json!({
        "to": "Ucoord",
        "messages": [{ "type": "text", "text": "claimed once" }]
    });
    let first = connector_a
        .invoke(invoke_req(
            OP_PUSH,
            input.clone(),
            generate_valid_token(&signing_key_a, &instance_id_a, OP_PUSH),
        ))
        .await
        .unwrap();
    assert_eq!(first.status, InvokeStatus::Ok);

    let err = connector_b
        .invoke(invoke_req(
            OP_PUSH,
            input,
            generate_valid_token(&signing_key_b, &instance_id_b, OP_PUSH),
        ))
        .await
        .unwrap_err();
    match err {
        FcpError::Unauthorized { code, message } => {
            assert_eq!(code, 4090);
            assert!(message.starts_with("thread_owned_by_peer:"));
            assert!(message.contains(instance_id_a.as_str()));
        }
        other => panic!("expected duplicate claim unauthorized error, got {other:?}"),
    }

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "duplicate claim must be denied before HTTP"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_multicast_sends_carousel_and_rejects_oversized_carousel() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/multicast"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let column = json!({
        "text": "Column",
        "actions": [{ "type": "message", "label": "Pick", "text": "pick" }]
    });
    let ten_columns = vec![column.clone(); 10];
    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_MULTICAST,
            json!({
                "to": ["U1", "U2"],
                "messages": [{
                    "type": "template",
                    "altText": "Carousel",
                    "template": {
                        "type": "carousel",
                        "columns": ten_columns
                    }
                }]
            }),
            generate_valid_token(&signing_key, &instance_id, OP_MULTICAST),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let body = recorded_json_body(&server).await;
    assert_eq!(
        body["messages"][0]["template"]["columns"]
            .as_array()
            .unwrap()
            .len(),
        10
    );

    let too_many_columns = vec![column; 11];
    let err = connector
        .invoke(invoke_req(
            OP_MULTICAST,
            json!({
                "to": ["U1"],
                "messages": [{
                    "type": "template",
                    "altText": "Too many",
                    "template": {
                        "type": "carousel",
                        "columns": too_many_columns
                    }
                }]
            }),
            generate_valid_token(&signing_key, &instance_id, OP_MULTICAST),
        ))
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("at most 10 columns"),
        "unexpected error: {err}"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_group_members_preserves_pagination_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/bot/group/C123/members/ids"))
        .and(query_param("start", "next-1"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "memberIds": ["U1", "U2"],
            "next": "next-2"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_GROUP_MEMBERS,
            json!({
                "group_id": "C123",
                "start": "next-1"
            }),
            generate_valid_token(&signing_key, &instance_id, OP_GROUP_MEMBERS),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("group members result");
    assert_eq!(result["memberIds"].as_array().unwrap().len(), 2);
    assert_eq!(result["next"], "next-2");
    println!(
        "line_group_members_pagination_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_rich_menu_delete_emits_destructive_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v2/bot/richmenu/richmenu-abc123"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let (connector, signing_key, instance_id) = setup_connector(&server.uri()).await;
    let response = connector
        .invoke(invoke_req(
            OP_RICH_MENU_DELETE,
            json!({
                "rich_menu_id": "richmenu-abc123"
            }),
            generate_valid_token(&signing_key, &instance_id, OP_RICH_MENU_DELETE),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("rich menu delete result");
    assert_eq!(result["deleted"], true);
    println!(
        "line_rich_menu_delete_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = LineConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 10);
    assert!(operations.iter().all(|operation| {
        operation["ai_hints"]["when_to_use"]
            .as_str()
            .is_some_and(|when_to_use| !when_to_use.is_empty())
    }));

    let delete = operations_info()
        .into_iter()
        .find(|operation| operation.id.as_str() == OP_RICH_MENU_DELETE)
        .expect("rich menu delete operation");
    assert_eq!(delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(delete.requires_approval, Some(ApprovalMode::Interactive));

    let group_members = operations
        .iter()
        .find(|operation| operation["id"] == "line.group.members")
        .expect("group members operation");
    assert_eq!(
        group_members["idempotency"],
        serde_json::to_value(IdempotencyClass::Strict).unwrap()
    );

    let push = operations
        .iter()
        .find(|operation| operation["id"] == OP_PUSH)
        .expect("push operation");
    let message_schema = &push["input_schema"]["properties"]["messages"]["items"]["oneOf"];
    assert!(
        message_schema
            .as_array()
            .expect("message schema oneOf")
            .iter()
            .any(|variant| variant["properties"]["type"]["const"] == "template")
    );
    assert!(
        message_schema
            .as_array()
            .expect("message schema oneOf")
            .iter()
            .any(|variant| variant["properties"]["type"]["const"] == "flex")
    );

    println!(
        "line_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

// ── Replay safety on retry (br-kxd3e) ────────────────────────────────
//
// Retrying a send after a 5xx or a timeout duplicates the message unless
// something deduplicates it, because both failures can be reported after LINE
// already delivered. LINE offers `X-Line-Retry-Key` on push/multicast, so the
// fix makes the retry SAFE rather than merely refusing it.
//
// What these pin is the DISTINCTION. Asserting only "the call still succeeds"
// would pass with a per-attempt key, which looks like protection and provides
// exactly zero.

/// A fast retry budget so the 5xx-then-200 tests do not sleep.
fn fast_retry_client(server: &MockServer) -> LineClient {
    LineClient::new(
        &server.uri(),
        TOKEN,
        HttpRetryConfig {
            max_retries: 3,
            initial_delay_ms: 1,
            max_delay_ms: 5,
            jitter_enabled: false,
        },
        StdDuration::from_secs(30),
    )
    .expect("wiremock URI should build LINE client")
}

fn sample_rich_menu() -> fcp_line::types::RichMenu {
    fcp_line::types::RichMenu {
        rich_menu_id: None,
        size: fcp_line::types::RichMenuSize {
            width: 2500,
            height: 1686,
        },
        selected: false,
        name: "kxd3e menu".into(),
        chat_bar_text: "Menu".into(),
        areas: Vec::new(),
    }
}

fn retry_keys_of(requests: &[wiremock::Request]) -> Vec<String> {
    requests
        .iter()
        .map(|r| {
            r.headers
                .get("x-line-retry-key")
                .map(|v| v.to_str().expect("header is ASCII").to_string())
                .unwrap_or_default()
        })
        .collect()
}

#[fcp_async_core::runtime::test]
async fn push_message_presents_one_stable_retry_key_across_attempts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/push"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/push"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "sentMessages": [] })))
        .mount(&server)
        .await;

    fast_retry_client(&server)
        .push_message(
            &client_runtime(),
            "U1",
            vec![fcp_line::types::Message::Text { text: "hi".into() }],
        )
        .await
        .expect("the retry should succeed");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 2, "the 500 should have been retried");

    let keys = retry_keys_of(&requests);
    assert!(
        !keys[0].is_empty(),
        "push must carry {} so LINE can deduplicate the retry",
        "X-Line-Retry-Key"
    );
    assert_eq!(
        keys[0], keys[1],
        "both attempts must present the SAME key — a per-attempt key would \
         let LINE treat the retry as a new message and deliver it twice"
    );
    assert!(
        uuid::Uuid::parse_str(&keys[0]).is_ok(),
        "LINE rejects a retry key that is not a UUID, got {:?}",
        keys[0]
    );
}

#[fcp_async_core::runtime::test]
async fn reply_message_sends_no_retry_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/reply"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "sentMessages": [] })))
        .mount(&server)
        .await;

    fast_retry_client(&server)
        .reply_message(
            &client_runtime(),
            "reply-token",
            vec![fcp_line::types::Message::Text { text: "hi".into() }],
        )
        .await
        .expect("reply should succeed");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        retry_keys_of(&requests)[0],
        "",
        "the reply endpoint takes no retry key — its safety comes from the \
         reply token being single-use"
    );
}

#[fcp_async_core::runtime::test]
async fn push_message_treats_409_as_the_original_send_succeeding() {
    let server = MockServer::start().await;
    // LINE answers a repeat of a key it has already seen with 409 and does NOT
    // send the message again.
    Mock::given(method("POST"))
        .and(path("/v2/bot/message/push"))
        .respond_with(ResponseTemplate::new(409))
        .mount(&server)
        .await;

    let result = fast_retry_client(&server)
        .push_message(
            &client_runtime(),
            "U1",
            vec![fcp_line::types::Message::Text { text: "hi".into() }],
        )
        .await;

    assert!(
        result.is_ok(),
        "409 against our own retry key means LINE already accepted the \
         message; reporting an error would invite an invoke-level retry that \
         mints a fresh key and genuinely duplicates it — got {result:?}"
    );
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 1, "a 409 is final, not retried");
}

#[fcp_async_core::runtime::test]
async fn create_rich_menu_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/richmenu"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let result = fast_retry_client(&server)
        .create_rich_menu(&client_runtime(), &sample_rich_menu())
        .await;
    assert!(result.is_err());

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "LINE has no dedup key for rich-menu creation, and a 503 means LINE \
         received the request — a retry would create a SECOND menu"
    );
}

#[fcp_async_core::runtime::test]
async fn create_rich_menu_still_retries_a_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/richmenu"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/bot/richmenu"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "richMenuId": "rm-1" })))
        .mount(&server)
        .await;

    fast_retry_client(&server)
        .create_rich_menu(&client_runtime(), &sample_rich_menu())
        .await
        .expect("a rate-limited request was refused without creating anything");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "429 means LINE did NOT create the menu, so backoff must be preserved"
    );
}
