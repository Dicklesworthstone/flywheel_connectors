//! Integration tests for the Feishu/Lark connector readiness and compliance surface.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use std::sync::Arc;

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_feishu::connector::{FeishuConnector, operations_info};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, IdempotencyClass, InstanceId, InvokeRequest, InvokeStatus, OperationId,
    RequestId, SafetyTier, ZoneId,
};
use fcp_sdk::{ChatCoordinationBackend, InMemoryThreadOwnershipChecker, ThreadOwnershipChecker};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_CHATS_LIST: &str = "feishu.chats.list";
const OP_COMMENTS_CONTEXT_GET: &str = "feishu.comments.context.get";
const OP_COMMENTS_PAIRINGS_MANAGE: &str = "feishu.comments.pairings.manage";
const OP_COMMENTS_REACTION: &str = "feishu.comments.reaction";
const OP_COMMENTS_REPLY: &str = "feishu.comments.reply";
const OP_MESSAGES_REPLY: &str = "feishu.messages.reply";
const OP_MESSAGES_SEND: &str = "feishu.messages.send";
const OP_WEBHOOK_INGEST_REQUEST: &str = "feishu.webhook.ingest_request";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/feishu_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/feishu_connector/<timestamp>";
const APP_ID: &str = "cli_test_app";
const APP_SECRET: &str = "cli_test_secret";
const TENANT_TOKEN: &str = "tenant-token-123";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [17u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("feishu.messages.write"),
            CapabilityId::from_static("feishu.messages.read"),
            CapabilityId::from_static("feishu.chats.read"),
            CapabilityId::from_static("feishu.users.read"),
            CapabilityId::from_static("feishu.docs.read"),
            CapabilityId::from_static("feishu.calendar.read"),
            CapabilityId::from_static("feishu.webhook.ingest"),
            CapabilityId::from_static("feishu.comments.read"),
            CapabilityId::from_static("feishu.comments.write"),
        ],
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
    let capability = match op {
        OP_CHATS_LIST => "feishu.chats.read",
        OP_MESSAGES_SEND | OP_MESSAGES_REPLY => "feishu.messages.write",
        OP_WEBHOOK_INGEST_REQUEST => "feishu.webhook.ingest",
        OP_COMMENTS_CONTEXT_GET => "feishu.comments.read",
        OP_COMMENTS_PAIRINGS_MANAGE | OP_COMMENTS_REPLY | OP_COMMENTS_REACTION => {
            "feishu.comments.write"
        }
        _ => "feishu.webhook.ingest",
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
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn feishu_webhook_signature(
    timestamp: &str,
    nonce: &str,
    encrypt_key: &str,
    raw_body: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(timestamp.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(encrypt_key.as_bytes());
    hasher.update(raw_body.as_bytes());
    hex::encode(hasher.finalize())
}

fn signed_webhook_input(raw_body: String, policy: serde_json::Value) -> serde_json::Value {
    let timestamp = "1715000000";
    let nonce = "integration-nonce";
    let encrypt_key = "integration-encrypt-key";
    json!({
        "method": "POST",
        "headers": {
            "x-lark-request-timestamp": timestamp,
            "x-lark-request-nonce": nonce,
            "x-lark-signature": feishu_webhook_signature(timestamp, nonce, encrypt_key, &raw_body),
        },
        "raw_body": raw_body,
        "verification_token": "integration-token",
        "encrypt_key": encrypt_key,
        "policy": policy,
    })
}

fn configured_ingress_webhook_input(raw_body: String, policy: Value) -> Value {
    let mut input = signed_webhook_input(raw_body, policy);
    let input_object = input.as_object_mut().expect("webhook input object");
    input_object.remove("verification_token");
    input_object.remove("encrypt_key");
    input_object.insert("path".to_owned(), json!("/feishu/webhook"));
    input
        .get_mut("headers")
        .and_then(Value::as_object_mut)
        .expect("headers object")
        .insert(
            "content-type".to_owned(),
            json!("application/json; charset=utf-8"),
        );
    input
}

fn feishu_event_body(event_id: &str, event_type: &str, event: Value) -> String {
    serde_json::to_string(&json!({
        "schema": "2.0",
        "header": {
            "event_id": event_id,
            "event_type": event_type,
            "token": "integration-token",
        },
        "event": event,
    }))
    .expect("serialize Feishu event body")
}

fn feishu_message_event(event_id: &str, sender: &str, chat: &str, mention_bot: bool) -> String {
    let mentions = if mention_bot {
        json!([{ "id": { "open_id": "ou_bot" } }])
    } else {
        json!([])
    };
    feishu_event_body(
        event_id,
        "im.message.receive_v1",
        json!({
            "sender": { "sender_id": { "open_id": sender } },
            "message": {
                "message_id": format!("om_{event_id}"),
                "chat_id": chat,
                "chat_type": "group",
                "message_type": "text",
                "content": "{\"text\":\"sensitive loopback text\"}",
                "mentions": mentions,
            }
        }),
    )
}

fn feishu_read_event(event_id: &str, reader: &str, chat: &str) -> String {
    feishu_event_body(
        event_id,
        "im.message.message_read_v1",
        json!({
            "reader": { "reader_id": { "open_id": reader } },
            "message_id": format!("om_{event_id}"),
            "chat_id": chat,
        }),
    )
}

fn feishu_reaction_event(event_id: &str, event_type: &str, operator: &str, chat: &str) -> String {
    feishu_event_body(
        event_id,
        event_type,
        json!({
            "operator": { "operator_id": { "open_id": operator } },
            "message_id": format!("om_{event_id}"),
            "chat_id": chat,
            "reaction": { "emoji_type": "OK" },
        }),
    )
}

fn feishu_comment_event(event_id: &str, actor: &str, mentioned: bool) -> String {
    feishu_event_body(
        event_id,
        "drive.notice.comment_add_v1",
        json!({
            "file_token": "doc_fixture_token",
            "file_type": "docx",
            "comment_id": "comment_fixture_card",
            "reply_id": "reply_fixture_card",
            "notice_type": "add_reply",
            "is_mentioned": mentioned,
            "user_id": { "open_id": actor },
        }),
    )
}

fn short_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("sha256:{}", &digest[..16])
}

fn string_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str()
}

fn hashed_or_null(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |item| json!(short_hash(item)))
}

fn jsonl_command() -> &'static str {
    "cargo test -p fcp-feishu --test integration feishu_webhook_comment_loopback_evidence_bundle -- --nocapture"
}

fn webhook_loopback_evidence_line(scenario: &str, response: &Value) -> Value {
    let normalized = &response["normalized_event"];
    let policy = &response["policy_decision"];
    let actor = string_path(normalized, &["sender_open_id"])
        .or_else(|| string_path(normalized, &["reader_open_id"]))
        .or_else(|| string_path(normalized, &["operator_open_id"]))
        .or_else(|| string_path(normalized, &["actor_open_id"]))
        .or_else(|| string_path(policy, &["actor_open_id"]));
    let status_code = response["status_code"].as_u64().unwrap_or_default();
    let reason_code = response["reason_code"].as_str().unwrap_or("unknown");
    let signature_verified = response["request_region"]["signature_verified"]
        .as_bool()
        .unwrap_or(false);
    let retry_decision = match reason_code {
        "rate_limited" => "host_rate_limit_rejected_before_connector_retry",
        "body_timeout" => "request_cancelled_before_dispatch",
        _ => "not_applicable",
    };

    json!({
        "event": "feishu_loopback_webhook_result",
        "schema": "feishu.loopback.evidence.v1",
        "command_line": jsonl_command(),
        "git_revision": option_env!("FCP_TEST_GIT_REVISION").unwrap_or("test-runtime"),
        "fixture_id": "feishu-webhook-comment-loopback-v1",
        "scenario": scenario,
        "tenant_app_id_hash": short_hash(APP_ID),
        "tenant_id_hash": short_hash("tenant-loopback"),
        "user_id_hash": hashed_or_null(actor),
        "comment_id_hash": hashed_or_null(string_path(normalized, &["comment_id"])),
        "event_id_hash": hashed_or_null(response["event_id"].as_str()),
        "dedupe_key_hash": hashed_or_null(response["dedupe_key"].as_str()),
        "request_region": {
            "transport": response["request_region"]["transport"],
            "route": response["request_region"]["path"],
            "configured_ingress": response["request_region"]["configured_ingress"],
            "route_checked": response["request_region"]["route_checked"],
            "content_type_checked": response["request_region"]["content_type_checked"],
            "listener_socket_opened": response["request_region"]["listener_socket_opened"],
            "event_fanout": response["request_region"]["event_fanout"],
        },
        "signature_result": if signature_verified { "verified" } else { reason_code },
        "sender_policy_decision": policy.get("reason_code").and_then(Value::as_str).unwrap_or(reason_code),
        "capability_decision": "invoke_capability_token_accepted",
        "retry_backoff": retry_decision,
        "http_status": status_code,
        "event_topic": string_path(normalized, &["topic"]),
        "event_emitted": response["event_emitted"],
        "fcp_error_mapping": reason_code,
        "cleanup_result": "connector_drop_no_external_state",
        "artifact_paths": ["stdout:feishu_webhook_comment_loopback_jsonl"],
        "redaction": {
            "raw_message_content_included": false,
            "raw_comment_content_included": false,
            "display_names_included": false,
            "tokens_included": false,
        },
    })
}

fn operation_loopback_evidence_line(scenario: &str, operation: &str, result: &Value) -> Value {
    json!({
        "event": "feishu_loopback_operation_result",
        "schema": "feishu.loopback.evidence.v1",
        "command_line": jsonl_command(),
        "git_revision": option_env!("FCP_TEST_GIT_REVISION").unwrap_or("test-runtime"),
        "fixture_id": "feishu-webhook-comment-loopback-v1",
        "scenario": scenario,
        "operation": operation,
        "tenant_app_id_hash": short_hash(APP_ID),
        "user_id_hash": hashed_or_null(
            result.get("actor_open_id").and_then(Value::as_str)
                .or_else(|| result.get("paired_open_ids").and_then(Value::as_array).and_then(|ids| ids.first()).and_then(Value::as_str))
        ),
        "comment_id_hash": short_hash("comment_fixture_card"),
        "capability_decision": "invoke_capability_token_accepted",
        "http_status": 200,
        "retry_backoff": "not_applicable",
        "fcp_error_mapping": "ok",
        "operation_summary": {
            "changed": result.get("changed").cloned().unwrap_or(Value::Null),
            "paired_user_count": result.get("paired_open_ids").and_then(Value::as_array).map_or(0, Vec::len),
            "delivered": result.get("delivered").cloned().unwrap_or(Value::Null),
            "delivery_mode": result.get("delivery_mode").cloned().unwrap_or(Value::Null),
            "fallback_used": result.get("fallback_used").cloned().unwrap_or(Value::Null),
            "action": result.get("action").cloned().unwrap_or(Value::Null),
            "reaction_type": result.get("reaction_type").cloned().unwrap_or(Value::Null),
            "raw_content_logged": result.get("raw_content_logged").cloned().unwrap_or(Value::Null),
        },
        "cleanup_result": if scenario.contains("cleanup") { "reaction_removed" } else { "not_applicable" },
        "artifact_paths": ["stdout:feishu_webhook_comment_loopback_jsonl"],
        "redaction": {
            "raw_message_content_included": false,
            "raw_comment_content_included": false,
            "display_names_included": false,
            "tokens_included": false,
        },
    })
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("feishu-integration-1"),
        connector_id: ConnectorId::from_static("fcp.feishu"),
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

async fn mock_auth_endpoint_with_expect(
    server: &MockServer,
    status: u16,
    expected_calls: Option<u64>,
) {
    let response = match status {
        200 => ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "tenant_access_token": TENANT_TOKEN,
            "expire": 7200
        })),
        429 => ResponseTemplate::new(429).insert_header("retry-after", "2"),
        401 => ResponseTemplate::new(401).set_body_string("unauthorized"),
        _ => ResponseTemplate::new(status).set_body_string("upstream failure"),
    };

    let mock = Mock::given(method("POST"))
        .and(path("/open-apis/auth/v3/tenant_access_token/internal"))
        .respond_with(response);
    let mock = if let Some(expected_calls) = expected_calls {
        mock.expect(expected_calls)
    } else {
        mock
    };
    mock.mount(server).await;
}

async fn mock_auth_endpoint(server: &MockServer, status: u16) {
    mock_auth_endpoint_with_expect(server, status, None).await;
}

async fn setup_connector_with_extra_config(
    server: &MockServer,
    extra_config: serde_json::Value,
) -> (FeishuConnector, Ed25519SigningKey) {
    mock_auth_endpoint(server, 200).await;

    let mut connector = FeishuConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let mut config = json!({
        "base_url": server.uri(),
        "app_id": APP_ID,
        "app_secret": APP_SECRET,
        "retry": {
            "max_retries": 0,
            "initial_delay_ms": 1,
            "max_delay_ms": 1,
            "jitter_enabled": false
        },
        "request_timeout_ms": 1_000
    });
    if let (Some(config), serde_json::Value::Object(extra_config)) =
        (config.as_object_mut(), extra_config)
    {
        config.extend(extra_config);
    }
    connector.configure(config).await.unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

async fn setup_connector(server: &MockServer) -> (FeishuConnector, Ed25519SigningKey) {
    setup_connector_with_extra_config(server, json!({})).await
}

async fn configure_connector_without_auth_mock(
    connector: &mut FeishuConnector,
    server: &MockServer,
    signing_key: &Ed25519SigningKey,
) {
    connector
        .configure(json!({
            "base_url": server.uri(),
            "app_id": APP_ID,
            "app_secret": APP_SECRET,
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
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
}

async fn invoke_ok_result(
    connector: &FeishuConnector,
    signing_key: &Ed25519SigningKey,
    op: &'static str,
    input: Value,
) -> Value {
    let response = connector
        .invoke(invoke_req(
            op,
            input,
            generate_valid_token(signing_key, op, connector.instance_id()),
        ))
        .await
        .expect("operation should invoke");
    assert_eq!(response.status, InvokeStatus::Ok);
    response.result.expect("operation result")
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = FeishuConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "feishu_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[test]
fn doctor_unconfigured_reports_operator_guidance() {
    let connector = FeishuConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "feishu_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_feishu_api_and_evidence() {
    let server = MockServer::start().await;
    let (connector, _signing_key) = setup_connector(&server).await;

    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    println!(
        "feishu_doctor_evidence={}",
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
        "tenant_app_credentials"
    );
    assert_eq!(
        value["details"]["live_probe"]["endpoint"],
        "POST /open-apis/auth/v3/tenant_access_token/internal"
    );
    assert_eq!(value["details"]["live_probe"]["status"], "ok");
    println!(
        "feishu_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_feishu_failure_reports_degraded() {
    let server = MockServer::start().await;
    mock_auth_endpoint(&server, 429).await;

    let mut connector = FeishuConnector::new();
    connector
        .configure(json!({
            "base_url": server.uri(),
            "app_id": APP_ID,
            "app_secret": APP_SECRET,
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

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
    assert_eq!(value["details"]["live_probe"]["retryable"], true);
    assert_eq!(value["details"]["live_probe"]["retry_after_ms"], 2000);
}

#[fcp_async_core::runtime::test]
async fn invoke_chats_list_preserves_pagination_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/open-apis/im/v1/chats"))
        .and(query_param("page_token", "page-1"))
        .and(query_param("page_size", "50"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "items": [
                    {"chat_id": "oc_chat_1", "name": "Platform Team"},
                    {"chat_id": "oc_chat_2", "name": "Ops"}
                ],
                "page_token": "page-2",
                "has_more": true
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server).await;
    let response = connector
        .invoke(invoke_req(
            OP_CHATS_LIST,
            json!({
                "page_token": "page-1",
                "page_size": 50
            }),
            generate_valid_token(&signing_key, OP_CHATS_LIST, connector.instance_id()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("chat list result");
    assert_eq!(result["items"].as_array().unwrap().len(), 2);
    assert_eq!(result["page_token"], "page-2");
    assert_eq!(result["has_more"], true);
    println!(
        "feishu_chat_pagination_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_messages_send_emits_mutation_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/open-apis/im/v1/messages"))
        .and(query_param("receive_id_type", "open_id"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "message_id": "om_dc13264520392913993dd051dba21dcf",
                "msg_type": "text"
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server).await;
    let response = connector
        .invoke(invoke_req(
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_123456",
                "receive_id_type": "open_id",
                "msg_type": "text",
                "content": "{\"text\":\"hello from integration\"}"
            }),
            generate_valid_token(&signing_key, OP_MESSAGES_SEND, connector.instance_id()),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("send result");
    assert_eq!(result["message_id"], "om_dc13264520392913993dd051dba21dcf");
    assert_eq!(result["msg_type"], "text");
    assert_eq!(result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(result["coordination"][1]["outcome"], "granted");
    assert_eq!(result["coordination"][2]["event"], "send_executed");
    let coordination_text =
        serde_json::to_string(&result["coordination"]).expect("serialize coordination");
    assert!(
        !coordination_text.contains("ou_123456"),
        "coordination audit must not leak raw Feishu receiver IDs"
    );
    assert!(
        !coordination_text.contains("hello from integration"),
        "coordination audit must not leak message bodies"
    );
    println!(
        "feishu_message_send_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_messages_send_claims_recipient_and_denies_duplicate_before_http() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/open-apis/im/v1/messages"))
        .and(query_param("receive_id_type", "open_id"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "message_id": "om_claimed_once",
                "msg_type": "text"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let checker: Arc<dyn ThreadOwnershipChecker> = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut first = FeishuConnector::new()
        .with_thread_ownership_checker(Arc::clone(&checker), ChatCoordinationBackend::InMemory);
    let mut second = FeishuConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    let first_key = Ed25519SigningKey::generate();
    let second_key = Ed25519SigningKey::generate();
    configure_connector_without_auth_mock(&mut first, &server, &first_key).await;
    configure_connector_without_auth_mock(&mut second, &server, &second_key).await;
    let first_id = first.instance_id().clone();
    let second_id = second.instance_id().clone();
    mock_auth_endpoint_with_expect(&server, 200, Some(1)).await;

    let first_response = first
        .invoke(invoke_req(
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_secret_claim_target",
                "receive_id_type": "open_id",
                "msg_type": "text",
                "content": "{\"text\":\"secret Feishu body\"}"
            }),
            generate_valid_token(&first_key, OP_MESSAGES_SEND, &first_id),
        ))
        .await
        .expect("first send should claim and reach provider");
    assert_eq!(first_response.status, InvokeStatus::Ok);
    let first_result = first_response.result.expect("first send result");
    assert_eq!(first_result["message_id"], "om_claimed_once");
    assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(first_result["coordination"][1]["outcome"], "granted");
    assert_eq!(first_result["coordination"][2]["event"], "send_executed");
    let coordination_text =
        serde_json::to_string(&first_result["coordination"]).expect("serialize coordination");
    assert!(
        !coordination_text.contains("ou_secret_claim_target"),
        "coordination audit must not leak raw Feishu receiver IDs"
    );
    assert!(
        !coordination_text.contains("secret Feishu body"),
        "coordination audit must not leak message bodies"
    );

    let duplicate = second
        .invoke(invoke_req(
            OP_MESSAGES_SEND,
            json!({
                "receive_id": "ou_secret_claim_target",
                "receive_id_type": "open_id",
                "msg_type": "text",
                "content": "{\"text\":\"secret Feishu body\"}"
            }),
            generate_valid_token(&second_key, OP_MESSAGES_SEND, &second_id),
        ))
        .await
        .expect_err("duplicate active owner should be denied before Feishu HTTP");
    assert!(matches!(
        duplicate,
        FcpError::Unauthorized { code: 4090, ref message }
            if message.starts_with("thread_owned_by_peer:") && message.contains(first_id.as_str())
    ));
}

#[fcp_async_core::runtime::test]
async fn invoke_messages_reply_claims_message_and_includes_coordination() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/open-apis/im/v1/messages/om_parent/reply"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "message_id": "om_reply_created",
                "root_id": "om_parent",
                "msg_type": "text"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server).await;
    let response = connector
        .invoke(invoke_req(
            OP_MESSAGES_REPLY,
            json!({
                "message_id": "om_parent",
                "msg_type": "text",
                "content": "{\"text\":\"thread reply body\"}"
            }),
            generate_valid_token(&signing_key, OP_MESSAGES_REPLY, connector.instance_id()),
        ))
        .await
        .expect("reply should invoke");
    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("reply result");
    assert_eq!(result["message_id"], "om_reply_created");
    assert_eq!(result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(result["coordination"][1]["outcome"], "granted");
    assert_eq!(result["coordination"][2]["event"], "send_executed");
    let coordination_text =
        serde_json::to_string(&result["coordination"]).expect("serialize coordination");
    assert!(
        !coordination_text.contains("om_parent"),
        "coordination audit must not leak raw Feishu message IDs"
    );
    assert!(
        !coordination_text.contains("thread reply body"),
        "coordination audit must not leak reply bodies"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_webhook_ingest_validates_and_normalizes_event_evidence() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server).await;
    let raw_body = serde_json::to_string(&json!({
        "schema": "2.0",
        "header": {
            "event_id": "evt-integration-1",
            "event_type": "im.message.receive_v1",
            "token": "integration-token",
        },
        "event": {
            "sender": { "sender_id": { "open_id": "ou_allowed" } },
            "message": {
                "message_id": "om_integration",
                "chat_id": "oc_allowed",
                "chat_type": "group",
                "message_type": "text",
                "content": "{\"text\":\"hello\"}",
                "mentions": [{ "id": { "open_id": "ou_bot" } }]
            }
        }
    }))
    .unwrap();

    let webhook_input = signed_webhook_input(
        raw_body,
        json!({
            "allowed_sender_open_ids": ["ou_allowed"],
            "allowed_chat_ids": ["oc_allowed"],
            "require_mention": true,
            "bot_open_id": "ou_bot",
        }),
    );

    let response = connector
        .invoke(invoke_req(
            OP_WEBHOOK_INGEST_REQUEST,
            webhook_input.clone(),
            generate_valid_token(
                &signing_key,
                OP_WEBHOOK_INGEST_REQUEST,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("webhook result");
    assert_eq!(result["status_code"], 200);
    assert_eq!(result["reason_code"], "event_accepted");
    assert_eq!(result["event_emitted"], true);
    assert_eq!(
        result["normalized_event"]["topic"],
        "feishu.webhook.message_received"
    );
    assert_eq!(result["normalized_event"]["raw_content_included"], false);
    println!(
        "feishu_webhook_ingest_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );

    let duplicate = connector
        .invoke(invoke_req(
            OP_WEBHOOK_INGEST_REQUEST,
            webhook_input,
            generate_valid_token(
                &signing_key,
                OP_WEBHOOK_INGEST_REQUEST,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap();
    let duplicate = duplicate.result.expect("duplicate result");
    assert_eq!(duplicate["reason_code"], "duplicate_event");
    assert_eq!(duplicate["event_emitted"], false);
    assert_eq!(duplicate["state_summary"]["finalized_entries"], 1);
}

#[fcp_async_core::runtime::test]
async fn invoke_webhook_ingest_configured_host_ingress_emits_fanout_contract() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector_with_extra_config(
        &server,
        json!({
            "webhook_ingress": {
                "enabled": true,
                "path": "/feishu/webhook",
                "verification_token": "integration-token",
                "encrypt_key": "integration-encrypt-key",
                "max_body_bytes": 4096
            }
        }),
    )
    .await;

    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_eq!(doctor["provisioning"]["webhook_ingress"]["enabled"], true);
    assert_eq!(
        doctor["provisioning"]["webhook_ingress"]["listener_socket_opened"],
        false
    );

    let raw_body = serde_json::to_string(&json!({
        "schema": "2.0",
        "header": {
            "event_id": "evt-configured-ingress-1",
            "event_type": "im.message.receive_v1",
            "token": "integration-token",
        },
        "event": {
            "sender": { "sender_id": { "open_id": "ou_allowed" } },
            "message": {
                "message_id": "om_configured_ingress",
                "chat_id": "oc_allowed",
                "chat_type": "group",
                "message_type": "text",
                "content": "{\"text\":\"hello\"}",
                "mentions": [{ "id": { "open_id": "ou_bot" } }]
            }
        }
    }))
    .unwrap();
    let mut webhook_input = signed_webhook_input(
        raw_body,
        json!({
            "allowed_sender_open_ids": ["ou_allowed"],
            "allowed_chat_ids": ["oc_allowed"],
            "require_mention": true,
            "bot_open_id": "ou_bot",
        }),
    );
    let webhook_object = webhook_input.as_object_mut().unwrap();
    webhook_object.remove("verification_token");
    webhook_object.remove("encrypt_key");
    webhook_object.insert("path".to_owned(), json!("/feishu/webhook"));
    webhook_object
        .get_mut("headers")
        .and_then(serde_json::Value::as_object_mut)
        .unwrap()
        .insert(
            "content-type".to_owned(),
            json!("application/json; charset=utf-8"),
        );

    let response = connector
        .invoke(invoke_req(
            OP_WEBHOOK_INGEST_REQUEST,
            webhook_input,
            generate_valid_token(
                &signing_key,
                OP_WEBHOOK_INGEST_REQUEST,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("configured ingress webhook result");
    assert_eq!(result["reason_code"], "event_accepted");
    assert_eq!(result["event_emitted"], true);
    assert_eq!(
        result["normalized_event"]["topic"],
        "feishu.webhook.message_received"
    );
    assert_eq!(result["request_region"]["configured_ingress"], true);
    assert_eq!(
        result["request_region"]["transport"],
        "host_forwarded_request_region"
    );
    assert_eq!(result["request_region"]["listener_socket_opened"], false);
    assert_eq!(
        result["request_region"]["event_fanout"],
        "host_consumes_returned_event_record"
    );
    assert_eq!(
        result["request_region"]["security_material_source"],
        "webhook_ingress_config"
    );
    println!(
        "feishu_configured_webhook_ingress_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn feishu_webhook_comment_loopback_evidence_bundle() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/open-apis/drive/v1/files/doc_fixture_token/comments/comment_fixture_card/replies",
        ))
        .and(query_param("file_type", "docx"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": { "reply_id": "reply_fixture_created" }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/open-apis/drive/v2/files/doc_fixture_token/comments/reaction",
        ))
        .and(query_param("file_type", "docx"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": { "reaction_id": "reaction_loopback_ok" }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector_with_extra_config(
        &server,
        json!({
            "webhook_ingress": {
                "enabled": true,
                "path": "/feishu/webhook",
                "verification_token": "integration-token",
                "encrypt_key": "integration-encrypt-key",
                "max_body_bytes": 4096
            }
        }),
    )
    .await;

    let message_policy = json!({
        "allowed_sender_open_ids": ["ou_allowed"],
        "allowed_chat_ids": ["oc_allowed"],
        "require_mention": true,
        "bot_open_id": "ou_bot",
    });
    let comment_policy = json!({
        "comment": {
            "enabled": true,
            "policy": "pairing",
            "require_mention": true,
            "document_allowlist": ["doc_fixture_token"]
        }
    });
    let mut transcript = Vec::new();

    let mut invalid_signature = configured_ingress_webhook_input(
        feishu_message_event(
            "evt-loopback-invalid-signature",
            "ou_allowed",
            "oc_allowed",
            true,
        ),
        message_policy.clone(),
    );
    invalid_signature["headers"]["x-lark-signature"] = json!("00");
    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        invalid_signature,
    )
    .await;
    assert_eq!(result["status_code"], 401);
    assert_eq!(result["reason_code"], "invalid_signature");
    transcript.push(webhook_loopback_evidence_line("invalid_signature", &result));

    let mut missing_signature = configured_ingress_webhook_input(
        feishu_message_event(
            "evt-loopback-missing-signature",
            "ou_allowed",
            "oc_allowed",
            true,
        ),
        message_policy.clone(),
    );
    missing_signature["headers"]
        .as_object_mut()
        .expect("headers object")
        .remove("x-lark-signature");
    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        missing_signature,
    )
    .await;
    assert_eq!(result["status_code"], 401);
    assert_eq!(result["reason_code"], "missing_signature");
    transcript.push(webhook_loopback_evidence_line("missing_signature", &result));

    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        configured_ingress_webhook_input("{not-json".into(), json!({})),
    )
    .await;
    assert_eq!(result["status_code"], 400);
    assert_eq!(result["reason_code"], "malformed_json");
    transcript.push(webhook_loopback_evidence_line(
        "signed_invalid_json",
        &result,
    ));

    let challenge_body = serde_json::to_string(&json!({
        "type": "url_verification",
        "token": "integration-token",
        "challenge": "loopback-challenge",
    }))
    .expect("serialize challenge");
    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        configured_ingress_webhook_input(challenge_body, json!({})),
    )
    .await;
    assert_eq!(result["reason_code"], "challenge_response");
    assert_eq!(result["response_body"]["challenge"], "loopback-challenge");
    transcript.push(webhook_loopback_evidence_line(
        "challenge_response",
        &result,
    ));

    let mut rate_limited = configured_ingress_webhook_input(
        feishu_message_event(
            "evt-loopback-rate-limited",
            "ou_allowed",
            "oc_allowed",
            true,
        ),
        message_policy.clone(),
    );
    rate_limited["rate_limited"] = json!(true);
    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        rate_limited,
    )
    .await;
    assert_eq!(result["status_code"], 429);
    assert_eq!(result["reason_code"], "rate_limited");
    transcript.push(webhook_loopback_evidence_line(
        "request_region_rate_limit",
        &result,
    ));

    let mut timed_out = configured_ingress_webhook_input(
        feishu_message_event("evt-loopback-timeout", "ou_allowed", "oc_allowed", true),
        message_policy.clone(),
    );
    timed_out["deadline_exceeded"] = json!(true);
    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        timed_out,
    )
    .await;
    assert_eq!(result["status_code"], 408);
    assert_eq!(result["reason_code"], "body_timeout");
    transcript.push(webhook_loopback_evidence_line(
        "request_region_cancellation",
        &result,
    ));

    let accepted_message = configured_ingress_webhook_input(
        feishu_message_event("evt-loopback-message", "ou_allowed", "oc_allowed", true),
        message_policy.clone(),
    );
    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        accepted_message.clone(),
    )
    .await;
    assert_eq!(result["reason_code"], "event_accepted");
    assert_eq!(
        result["normalized_event"]["topic"],
        "feishu.webhook.message_received"
    );
    transcript.push(webhook_loopback_evidence_line(
        "authorized_message",
        &result,
    ));

    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        accepted_message,
    )
    .await;
    assert_eq!(result["reason_code"], "duplicate_event");
    assert_eq!(result["event_emitted"], false);
    transcript.push(webhook_loopback_evidence_line("duplicate_replay", &result));

    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        configured_ingress_webhook_input(
            feishu_message_event(
                "evt-loopback-denied-sender",
                "ou_intruder",
                "oc_allowed",
                true,
            ),
            message_policy.clone(),
        ),
    )
    .await;
    assert_eq!(result["reason_code"], "sender_not_allowed");
    assert_eq!(result["event_emitted"], false);
    transcript.push(webhook_loopback_evidence_line("denied_sender", &result));

    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        configured_ingress_webhook_input(
            feishu_message_event("evt-loopback-denied-chat", "ou_allowed", "oc_denied", true),
            message_policy.clone(),
        ),
    )
    .await;
    assert_eq!(result["reason_code"], "chat_not_allowed");
    assert_eq!(result["event_emitted"], false);
    transcript.push(webhook_loopback_evidence_line("denied_group", &result));

    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        configured_ingress_webhook_input(
            feishu_read_event("evt-loopback-read", "ou_reader", "oc_allowed"),
            json!({ "allowed_chat_ids": ["oc_allowed"] }),
        ),
    )
    .await;
    assert_eq!(result["reason_code"], "event_accepted");
    assert_eq!(
        result["normalized_event"]["topic"],
        "feishu.webhook.message_read"
    );
    transcript.push(webhook_loopback_evidence_line("read_event", &result));

    for (scenario, event_type, expected_topic) in [
        (
            "reaction_created",
            "im.message.reaction.created_v1",
            "feishu.webhook.reaction_created",
        ),
        (
            "reaction_deleted",
            "im.message.reaction.deleted_v1",
            "feishu.webhook.reaction_deleted",
        ),
    ] {
        let result = invoke_ok_result(
            &connector,
            &signing_key,
            OP_WEBHOOK_INGEST_REQUEST,
            configured_ingress_webhook_input(
                feishu_reaction_event(
                    &format!("evt-loopback-{scenario}"),
                    event_type,
                    "ou_reactor",
                    "oc_allowed",
                ),
                json!({
                    "allowed_sender_open_ids": ["ou_reactor"],
                    "allowed_chat_ids": ["oc_allowed"]
                }),
            ),
        )
        .await;
        assert_eq!(result["reason_code"], "event_accepted");
        assert_eq!(result["normalized_event"]["topic"], expected_topic);
        transcript.push(webhook_loopback_evidence_line(scenario, &result));
    }

    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        configured_ingress_webhook_input(
            feishu_comment_event("evt-loopback-comment-denied", "ou_commenter", true),
            comment_policy.clone(),
        ),
    )
    .await;
    assert_eq!(result["reason_code"], "comment_actor_not_allowed");
    assert_eq!(result["event_emitted"], false);
    transcript.push(webhook_loopback_evidence_line("denied_comment", &result));

    let pairing = invoke_ok_result(
        &connector,
        &signing_key,
        OP_COMMENTS_PAIRINGS_MANAGE,
        json!({
            "action": "add",
            "actor_open_id": "ou_commenter"
        }),
    )
    .await;
    assert_eq!(pairing["changed"], true);
    transcript.push(operation_loopback_evidence_line(
        "policy_reload_pairing_add",
        OP_COMMENTS_PAIRINGS_MANAGE,
        &pairing,
    ));

    let result = invoke_ok_result(
        &connector,
        &signing_key,
        OP_WEBHOOK_INGEST_REQUEST,
        configured_ingress_webhook_input(
            feishu_comment_event("evt-loopback-comment-authorized", "ou_commenter", true),
            comment_policy,
        ),
    )
    .await;
    assert_eq!(result["reason_code"], "event_accepted");
    assert_eq!(
        result["policy_decision"]["reason_code"],
        "comment_pairing_match"
    );
    assert_eq!(
        result["normalized_event"]["topic"],
        "feishu.webhook.document_comment_added"
    );
    transcript.push(webhook_loopback_evidence_line(
        "authorized_comment",
        &result,
    ));

    let reply = invoke_ok_result(
        &connector,
        &signing_key,
        OP_COMMENTS_REPLY,
        json!({
            "file_token": "doc_fixture_token",
            "file_type": "docx",
            "comment_id": "comment_fixture_card",
            "content": "sensitive reply text",
            "fallback_to_whole_comment": false
        }),
    )
    .await;
    assert_eq!(reply["delivered"], true);
    assert_eq!(reply["delivery_mode"], "thread_reply");
    assert_eq!(reply["raw_content_logged"], false);
    transcript.push(operation_loopback_evidence_line(
        "comment_reply_delivery",
        OP_COMMENTS_REPLY,
        &reply,
    ));

    let cleanup = invoke_ok_result(
        &connector,
        &signing_key,
        OP_COMMENTS_REACTION,
        json!({
            "file_token": "doc_fixture_token",
            "file_type": "docx",
            "reply_id": "reply_fixture_card",
            "action": "delete",
            "reaction_type": "OK"
        }),
    )
    .await;
    assert_eq!(cleanup["action"], "delete");
    assert_eq!(cleanup["reaction_type"], "OK");
    assert_eq!(cleanup["raw_content_logged"], false);
    transcript.push(operation_loopback_evidence_line(
        "comment_reaction_cleanup",
        OP_COMMENTS_REACTION,
        &cleanup,
    ));

    let jsonl = transcript
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .expect("serialize JSONL")
        .join("\n");
    assert_eq!(transcript.len(), 18);
    for line in jsonl.lines() {
        let parsed: Value = serde_json::from_str(line).expect("JSONL line should parse");
        assert_eq!(parsed["schema"], "feishu.loopback.evidence.v1");
        assert_eq!(parsed["fixture_id"], "feishu-webhook-comment-loopback-v1");
        assert_eq!(parsed["redaction"]["raw_message_content_included"], false);
        assert_eq!(parsed["redaction"]["raw_comment_content_included"], false);
        assert_eq!(parsed["redaction"]["tokens_included"], false);
    }
    for forbidden in [
        "integration-token",
        "integration-encrypt-key",
        APP_SECRET,
        TENANT_TOKEN,
        "sensitive loopback text",
        "sensitive reply text",
        "ou_allowed",
        "ou_intruder",
        "ou_commenter",
        "oc_allowed",
        "doc_fixture_token",
        "comment_fixture_card",
        "reply_fixture_card",
    ] {
        assert!(
            !jsonl.contains(forbidden),
            "loopback evidence JSONL leaked `{forbidden}`"
        );
    }

    println!("feishu_webhook_comment_loopback_jsonl=\n{jsonl}");
}

#[fcp_async_core::runtime::test]
async fn invoke_comment_automation_operations_emit_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/open-apis/drive/v1/metas/batch_query"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "metas": [{
                    "doc_token": "doc_context",
                    "doc_type": "docx",
                    "title": "Incident Runbook",
                    "url": "https://example.feishu.cn/docx/doc_context"
                }]
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/open-apis/drive/v1/files/doc_context/comments/batch_query",
        ))
        .and(query_param("file_type", "docx"))
        .and(query_param("user_id_type", "open_id"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "items": [{
                    "comment_id": "comment_context",
                    "user_id": "ou_commenter",
                    "is_whole": false,
                    "quote": "restart failed",
                    "reply_list": {
                        "replies": [{
                            "reply_id": "reply_root",
                            "user_id": "ou_commenter",
                            "content": {
                                "elements": [{
                                    "type": "text_run",
                                    "text_run": { "text": "Can you check this?" }
                                }]
                            }
                        }]
                    }
                }]
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/open-apis/drive/v1/files/doc_context/comments/comment_context/replies",
        ))
        .and(query_param("file_type", "docx"))
        .and(query_param("page_size", "100"))
        .and(query_param("user_id_type", "open_id"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "items": [{
                    "reply_id": "reply_current",
                    "user_id": "ou_commenter",
                    "content": {
                        "elements": [{
                            "type": "text_run",
                            "text_run": { "text": "Stack trace is in the linked doc" }
                        }]
                    }
                }],
                "has_more": false
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/open-apis/drive/v1/files/doc_context/comments/comment_context/replies",
        ))
        .and(query_param("file_type", "docx"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 1069302,
            "msg": "reply is not allowed for whole-comment fallback"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/open-apis/drive/v1/files/doc_context/new_comments"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "comment_id": "comment_fallback"
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/open-apis/drive/v2/files/doc_context/comments/reaction",
        ))
        .and(query_param("file_type", "docx"))
        .and(header("authorization", &format!("Bearer {TENANT_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "success",
            "data": {
                "reaction_id": "reaction_typing"
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server).await;

    let pairing = connector
        .invoke(invoke_req(
            OP_COMMENTS_PAIRINGS_MANAGE,
            json!({
                "action": "add",
                "actor_open_id": "ou_commenter"
            }),
            generate_valid_token(
                &signing_key,
                OP_COMMENTS_PAIRINGS_MANAGE,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap()
        .result
        .expect("pairing result");
    assert_eq!(pairing["changed"], true);
    assert_eq!(pairing["paired_open_ids"][0], "ou_commenter");

    let context = connector
        .invoke(invoke_req(
            OP_COMMENTS_CONTEXT_GET,
            json!({
                "file_token": "doc_context",
                "file_type": "docx",
                "comment_id": "comment_context",
                "reply_id": "reply_current"
            }),
            generate_valid_token(
                &signing_key,
                OP_COMMENTS_CONTEXT_GET,
                connector.instance_id(),
            ),
        ))
        .await
        .unwrap()
        .result
        .expect("context result");
    assert_eq!(context["document"]["title"], "Incident Runbook");
    assert_eq!(context["root_comment_text"], "Can you check this?");
    assert_eq!(
        context["target_reply_text"],
        "Stack trace is in the linked doc"
    );
    assert_eq!(context["raw_payload_included"], false);

    let reply = connector
        .invoke(invoke_req(
            OP_COMMENTS_REPLY,
            json!({
                "file_token": "doc_context",
                "file_type": "docx",
                "comment_id": "comment_context",
                "content": "Investigating <safe>",
                "fallback_to_whole_comment": true
            }),
            generate_valid_token(&signing_key, OP_COMMENTS_REPLY, connector.instance_id()),
        ))
        .await
        .unwrap()
        .result
        .expect("reply result");
    assert_eq!(reply["delivered"], true);
    assert_eq!(reply["delivery_mode"], "whole_comment");
    assert_eq!(reply["fallback_used"], true);

    let reaction = connector
        .invoke(invoke_req(
            OP_COMMENTS_REACTION,
            json!({
                "file_token": "doc_context",
                "file_type": "docx",
                "reply_id": "reply_current",
                "action": "add",
                "reaction_type": "Typing"
            }),
            generate_valid_token(&signing_key, OP_COMMENTS_REACTION, connector.instance_id()),
        ))
        .await
        .unwrap()
        .result
        .expect("reaction result");
    assert_eq!(reaction["action"], "add");
    assert_eq!(reaction["reaction_type"], "Typing");

    println!(
        "feishu_comment_automation_evidence={}",
        serde_json::to_string_pretty(&json!({
            "pairing": pairing,
            "context": context,
            "reply": reply,
            "reaction": reaction
        }))
        .unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = FeishuConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 15);
    assert!(operations.iter().all(|operation| {
        operation["ai_hints"]["when_to_use"]
            .as_str()
            .is_some_and(|when_to_use| !when_to_use.is_empty())
    }));

    let send = operations_info()
        .into_iter()
        .find(|operation| operation.id.as_str() == OP_MESSAGES_SEND)
        .expect("messages.send operation");
    assert_eq!(send.safety_tier, SafetyTier::Risky);
    assert_eq!(
        send.output_schema["required"],
        json!(["message_id", "coordination"])
    );
    let reply = operations
        .iter()
        .find(|operation| operation["id"] == OP_MESSAGES_REPLY)
        .expect("messages.reply operation");
    assert_eq!(
        reply["output_schema"]["required"],
        json!(["message_id", "coordination"])
    );

    let chats_list = operations
        .iter()
        .find(|operation| operation["id"] == OP_CHATS_LIST)
        .expect("chats.list operation");
    assert_eq!(
        chats_list["idempotency"],
        serde_json::to_value(IdempotencyClass::Strict).unwrap()
    );
    let webhook = operations
        .iter()
        .find(|operation| operation["id"] == OP_WEBHOOK_INGEST_REQUEST)
        .expect("webhook ingest operation");
    assert_eq!(
        webhook["idempotency"],
        serde_json::to_value(IdempotencyClass::BestEffort).unwrap()
    );
    assert_eq!(
        webhook["input_schema"]["required"],
        json!(["method", "headers", "raw_body", "policy"])
    );
    let comment_context = operations
        .iter()
        .find(|operation| operation["id"] == OP_COMMENTS_CONTEXT_GET)
        .expect("comment context operation");
    assert_eq!(
        comment_context["safety_tier"],
        serde_json::to_value(SafetyTier::Safe).unwrap()
    );
    assert!(value["event_caps"]["replay"].as_bool().unwrap());
    assert!(
        value["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["topic"] == "feishu.webhook.message_received")
    );
    assert_eq!(value["auth_caps"]["methods"].as_array().unwrap().len(), 2);

    println!(
        "feishu_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

// ── Replay safety on retry (br-kxd3e) ────────────────────────────────
//
// A 5xx or a timeout can both be reported after Feishu already delivered the
// message, so a bare retry sends it twice. Feishu deduplicates messaging
// requests on a `uuid` BODY field (not a header, unlike Stripe/Mastodon),
// which makes the retry genuinely safe rather than merely refused.
//
// These pin the DISTINCTION: a per-attempt uuid would still "succeed" here,
// so what is asserted is that both attempts carry the SAME value.

fn test_runtime() -> fcp_sdk::ConnectorRuntime {
    fcp_sdk::ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default())
}

fn replay_test_client(server: &MockServer) -> fcp_feishu::client::FeishuClient {
    fcp_feishu::client::FeishuClient::new(
        &server.uri(),
        APP_ID,
        APP_SECRET,
        fcp_sdk::migration::HttpRetryConfig {
            max_retries: 3,
            initial_delay_ms: 1,
            max_delay_ms: 5,
            jitter_enabled: false,
        },
        std::time::Duration::from_secs(5),
    )
    .expect("wiremock URI should build a Feishu client")
}

/// Request bodies for the message endpoints, in arrival order.
async fn message_request_bodies(server: &MockServer) -> Vec<serde_json::Value> {
    server
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path().contains("/im/v1/messages"))
        .map(|r| serde_json::from_slice(&r.body).expect("request body should be JSON"))
        .collect()
}

#[fcp_async_core::runtime::test]
async fn send_message_presents_one_stable_dedup_uuid_across_attempts() {
    let server = MockServer::start().await;
    mock_auth_endpoint(&server, 200).await;
    Mock::given(method("POST"))
        .and(path("/open-apis/im/v1/messages"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/open-apis/im/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "code": 0,
            "msg": "ok",
            "data": { "message_id": "om_1" }
        })))
        .mount(&server)
        .await;

    let request = fcp_feishu::types::SendMessageRequest {
        receive_id: "ou_1".into(),
        msg_type: "text".into(),
        content: "{\"text\":\"hi\"}".into(),
    };
    replay_test_client(&server)
        .send_message(&test_runtime(), "open_id", &request)
        .await
        .expect("the retry should succeed");

    let bodies = message_request_bodies(&server).await;
    assert_eq!(bodies.len(), 2, "the 503 should have been retried");

    let first = bodies[0]["uuid"].as_str().unwrap_or_default();
    assert!(
        !first.is_empty(),
        "send_message must carry a `uuid` so Feishu can deduplicate the retry"
    );
    assert_eq!(
        first,
        bodies[1]["uuid"].as_str().unwrap_or_default(),
        "both attempts must present the SAME uuid — a per-attempt value would \
         let Feishu treat the retry as a new message and deliver it twice"
    );
}

#[fcp_async_core::runtime::test]
async fn add_whole_comment_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    mock_auth_endpoint(&server, 200).await;
    Mock::given(method("POST"))
        .and(path("/open-apis/drive/v1/files/doc-1/new_comments"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let result = replay_test_client(&server)
        .add_whole_comment(&test_runtime(), "doc-1", "docx", "hello")
        .await;
    assert!(result.is_err());

    let comment_requests = server
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path().ends_with("/new_comments"))
        .count();
    assert_eq!(
        comment_requests, 1,
        "Drive comments take no dedup key, and a 503 means Feishu received the \
         request — a retry posts a SECOND comment"
    );
}
