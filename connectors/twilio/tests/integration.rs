//! Twilio connector integration tests (flywheel_connectors-otqy.3).
//!
//! Deterministic integration tests using wiremock to mock the Twilio REST API.
//! No real API calls. Covers:
//! - Messaging (send, get, list)
//! - Voice (create call, get call)
//! - Recordings (list, download)
//! - Media download
//! - Account and phone numbers
//! - Error taxonomy (401/404/429/500 → `FcpError` mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]

use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_manifest::{ConnectorManifest, OperationSection};
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use fcp_voice_call::stable_redacted_hash;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha1::Sha1;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path_regex},
};

use fcp_twilio::client::TwilioClient;
use fcp_twilio::connector::TwilioConnector;

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

// ============================================================================
// Helpers
// ============================================================================

type HmacSha1 = Hmac<Sha1>;

const TWILIO_TEST_HMAC_KEY: &str = "fixture_hmac_key_for_signature_tests";

fn twilio_signature(hmac_key: &str, url: &str, params: &[(&str, &str)]) -> String {
    let mut sorted = params.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(right.0));
    let mut data_to_sign = String::from(url);
    for (key, value) in sorted {
        data_to_sign.push_str(key);
        data_to_sign.push_str(value);
    }

    let mut mac = HmacSha1::new_from_slice(hmac_key.as_bytes()).expect("hmac key accepted");
    mac.update(data_to_sign.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &str,
) -> fcp_core::CapabilityToken {
    let cap = match op {
        "twilio.send_message" => "twilio.message",
        "twilio.create_call"
        | "twilio.hangup_call"
        | "twilio.generate_twiml"
        | "twilio.media_stream.process_events" => "twilio.voice",
        "twilio.whatsapp_send" | "twilio.whatsapp_send_template" => "twilio.whatsapp",
        "twilio.conversation.create" | "twilio.conversation.message.send" => "twilio.conversations",
        "twilio.conversation.participant.add" | "twilio.conversation.participant.remove" => {
            "twilio.conversations.participants"
        }
        "twilio.verify.send" | "twilio.verify.check" | "twilio.verify.cancel" => "twilio.verify",
        "twilio.video.room.create" | "twilio.video.room.end" => "twilio.video.rooms.write",
        "twilio.video.room.get" | "twilio.video.room.list" => "twilio.video.rooms.read",
        "twilio.video.room.participants" => "twilio.video.participants.read",
        "twilio.video.recording.list" => "twilio.video.recordings.read",
        "twilio.webhook.validate_signature"
        | "twilio.webhook.evaluate_inbound_policy"
        | "twilio.webhook.ingest_request"
        | "twilio.webhook.parse_sms_event"
        | "twilio.webhook.parse_status_callback"
        | "twilio.webhook.parse_voice_event" => "twilio.webhook",
        _ => "twilio.read",
    };
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut TwilioConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

fn assert_invalid_request_contains(error: &fcp_core::FcpError, expected: &str) {
    assert!(matches!(
        error,
        fcp_core::FcpError::InvalidRequest { message, .. } if message.contains(expected)
    ));
}

fn assert_invalid_request_any_contains(error: &fcp_core::FcpError, expected: &[&str]) {
    assert!(matches!(error, fcp_core::FcpError::InvalidRequest { .. }));
    if let fcp_core::FcpError::InvalidRequest { message, .. } = error {
        assert!(
            expected.iter().any(|needle| message.contains(needle)),
            "got: {message}"
        );
    }
}

/// Account SID used in integration tests.
const TEST_ACCOUNT_SID: &str = "ACtest123456789";

async fn setup_configure(connector: &mut TwilioConnector, base_url: &str) {
    let full_base = format!("{base_url}/2010-04-01/Accounts/{TEST_ACCOUNT_SID}");
    connector
        .handle_configure(json!({
            "account_sid": TEST_ACCOUNT_SID,
            "auth_token": "test_auth_token_xyz",
            "base_url": full_base
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_webhook_ingest_connector() -> (TwilioConnector, fcp_core::CapabilityToken) {
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, "http://localhost").await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.ingest_request"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.ingest_request",
    );
    (connector, capability)
}

/// Standard Twilio message response.
fn twilio_message_response(sid: &str, status: &str) -> serde_json::Value {
    json!({
        "sid": sid,
        "status": status,
        "to": "+15551234567",
        "from": "+15559876543",
        "body": "Hello from FCP!",
        "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
        "date_updated": "Wed, 15 Jan 2026 10:00:01 +0000",
        "date_sent": "Wed, 15 Jan 2026 10:00:01 +0000",
        "price": "-0.0075",
        "price_unit": "USD",
        "num_media": "0",
        "num_segments": "1",
        "direction": "outbound-api",
        "uri": format!("/2010-04-01/Accounts/ACtest/Messages/{sid}.json")
    })
}

/// Standard Twilio call response.
fn twilio_call_response(sid: &str, status: &str) -> serde_json::Value {
    json!({
        "sid": sid,
        "status": status,
        "to": "+15551234567",
        "from": "+15559876543",
        "duration": "30",
        "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
        "date_updated": "Wed, 15 Jan 2026 10:00:30 +0000",
        "start_time": "Wed, 15 Jan 2026 10:00:00 +0000",
        "end_time": "Wed, 15 Jan 2026 10:00:30 +0000",
        "price": "-0.0085",
        "price_unit": "USD",
        "direction": "outbound-api",
        "uri": format!("/2010-04-01/Accounts/ACtest/Calls/{sid}.json")
    })
}

/// Twilio API error response.
fn twilio_error_response(code: u32, message: &str) -> serde_json::Value {
    json!({
        "code": code,
        "message": message,
        "status": 400,
        "more_info": "https://www.twilio.com/docs/errors"
    })
}

fn twilio_manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str(MANIFEST_TOML).expect("Twilio manifest should validate")
}

fn manifest_operation<'a>(manifest: &'a ConnectorManifest, id: &str) -> &'a OperationSection {
    manifest
        .provides
        .operations
        .get(id)
        .unwrap_or_else(|| panic!("Twilio manifest missing operation {id}"))
}

fn assert_provider_network_constraints(
    id: &str,
    operation: &OperationSection,
    expected_hosts: &[&str],
) {
    let constraints = operation
        .network_constraints
        .as_ref()
        .unwrap_or_else(|| panic!("{id} missing network_constraints"));
    let actual_hosts = constraints
        .host_allow
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(actual_hosts, expected_hosts, "{id} host_allow");
    assert_eq!(constraints.port_allow, vec![443], "{id} port_allow");
    assert!(constraints.deny_localhost, "{id} should deny localhost");
    assert!(
        constraints.deny_private_ranges,
        "{id} should deny private ranges"
    );
    assert!(
        constraints.deny_tailnet_ranges,
        "{id} should deny tailnet ranges"
    );
    assert!(constraints.require_sni, "{id} should require SNI");
    assert!(
        constraints.deny_ip_literals,
        "{id} should deny IP literal hosts"
    );
    assert!(
        constraints.require_host_canonicalization,
        "{id} should require host canonicalization"
    );
    assert_eq!(constraints.dns_max_ips, 16, "{id} dns_max_ips");
    assert!(
        constraints.max_response_bytes > 0,
        "{id} max_response_bytes"
    );
}

fn assert_no_connector_egress_network_constraints(id: &str, operation: &OperationSection) {
    let constraints = operation
        .network_constraints
        .as_ref()
        .unwrap_or_else(|| panic!("{id} missing network_constraints"));
    assert_eq!(
        constraints.host_allow,
        vec!["none.invalid"],
        "{id} host_allow"
    );
    assert_eq!(constraints.port_allow, vec![0], "{id} port_allow");
    assert!(constraints.ip_allow.is_empty(), "{id} ip_allow");
    assert!(constraints.cidr_deny.is_empty(), "{id} cidr_deny");
    assert!(constraints.deny_localhost, "{id} should deny localhost");
    assert!(
        constraints.deny_private_ranges,
        "{id} should deny private ranges"
    );
    assert!(
        constraints.deny_tailnet_ranges,
        "{id} should deny tailnet ranges"
    );
    assert!(!constraints.require_sni, "{id} should not require SNI");
    assert!(constraints.spki_pins.is_empty(), "{id} spki_pins");
    assert!(
        constraints.deny_ip_literals,
        "{id} should deny IP literal hosts"
    );
    assert!(
        constraints.require_host_canonicalization,
        "{id} should require host canonicalization"
    );
    assert_eq!(constraints.dns_max_ips, 0, "{id} dns_max_ips");
    assert_eq!(constraints.max_redirects, 0, "{id} max_redirects");
    assert_eq!(
        constraints.connect_timeout_ms, 1000,
        "{id} connect_timeout_ms"
    );
    assert_eq!(constraints.total_timeout_ms, 10000, "{id} total_timeout_ms");
    assert_eq!(
        constraints.max_response_bytes, 65536,
        "{id} max_response_bytes"
    );
}

fn twilio_media_start_frame(stream_sid: &str, call_sid: &str) -> serde_json::Value {
    json!({
        "event": "start",
        "sequenceNumber": "1",
        "streamSid": stream_sid,
        "start": {
            "streamSid": stream_sid,
            "accountSid": TEST_ACCOUNT_SID,
            "callSid": call_sid,
            "tracks": ["inbound"],
            "customParameters": { "token": "AAAAAAAAAAAAAAAAAAAAAA" },
            "mediaFormat": {
                "encoding": "audio/x-mulaw",
                "sampleRate": 8000,
                "channels": 1
            }
        }
    })
}

fn twilio_media_frame(
    stream_sid: &str,
    sequence: u64,
    chunk: u64,
    timestamp: u64,
) -> serde_json::Value {
    json!({
        "event": "media",
        "sequenceNumber": sequence.to_string(),
        "streamSid": stream_sid,
        "media": {
            "track": "inbound",
            "chunk": chunk.to_string(),
            "timestamp": timestamp.to_string(),
            "payload": base64::engine::general_purpose::STANDARD.encode(vec![0x7f; 160])
        }
    })
}

fn open_media_stream_e2e_log() -> (File, PathBuf) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fcp-twilio-media-stream-e2e-{}-{now}",
        std::process::id()
    ));
    create_dir_all(&dir).expect("create Twilio media stream e2e log dir");
    let path = dir.join("twilio_media_stream_e2e.jsonl");
    let file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .expect("open Twilio media stream e2e log");
    (file, path)
}

fn log_media_stream_e2e(
    logs: &mut File,
    scenario: &str,
    result: &serde_json::Value,
    latency_ms: u128,
    details: &serde_json::Value,
) {
    let latency_ms = u64::try_from(latency_ms).unwrap_or(u64::MAX);
    let record = json!({
        "record_type": "twilio_media_stream_connector_boundary_e2e",
        "scenario": scenario,
        "status": if result["accepted"].as_bool().unwrap_or(false) { "accepted" } else { "denied" },
        "transport": "host_forwarded_twilio_websocket_frames",
        "runtime": "fcp_async_core::runtime::test",
        "call_sid": result.get("call_sid").cloned().unwrap_or(serde_json::Value::Null),
        "stream_sid": result.get("stream_sid").cloned().unwrap_or(serde_json::Value::Null),
        "sequence_numbers": details.get("sequence_numbers").cloned().unwrap_or_else(|| json!([])),
        "queue_depth": result.get("queue_depth").cloned().unwrap_or_else(|| json!(0)),
        "max_queue_depth": result.get("max_queue_depth").cloned().unwrap_or_else(|| json!(0)),
        "pacing_decisions": result.get("pacing_decisions").cloned().unwrap_or_else(|| json!([])),
        "reconnect_plan": result.get("reconnect_plan").cloned().unwrap_or_else(|| json!([])),
        "latency_ms": latency_ms,
        "cleanup": {
            "clean_shutdown": result
                .get("clean_shutdown")
                .cloned()
                .unwrap_or(serde_json::Value::Bool(false)),
            "tainted": result
                .get("tainted")
                .cloned()
                .unwrap_or(serde_json::Value::Bool(true)),
        },
        "final_result": {
            "accepted": result
                .get("accepted")
                .cloned()
                .unwrap_or(serde_json::Value::Bool(false)),
            "status_code": result.get("status_code").cloned().unwrap_or_else(|| json!(0)),
            "reason_code": result.get("reason_code").cloned().unwrap_or_else(|| json!("missing")),
        },
        "skip_reason": serde_json::Value::Null,
        "details": details.clone(),
    });
    writeln!(logs, "{record}").expect("write Twilio media stream e2e log line");
    logs.flush()
        .expect("flush Twilio media stream e2e log line");
}

fn open_webhook_ingest_e2e_log() -> (File, PathBuf) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fcp-twilio-webhook-ingest-e2e-{}-{now}",
        std::process::id()
    ));
    create_dir_all(&dir).expect("create Twilio webhook ingest e2e log dir");
    let path = dir.join("twilio_webhook_ingest_e2e.jsonl");
    let file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&path)
        .expect("open Twilio webhook ingest e2e log");
    (file, path)
}

fn hashed_event_field(result: &serde_json::Value, field: &str) -> serde_json::Value {
    let event = result.get("event").unwrap_or(&serde_json::Value::Null);
    if field == "call_sid"
        && event
            .get("resource_type")
            .and_then(serde_json::Value::as_str)
            == Some("call")
    {
        return event
            .get("resource_sid")
            .and_then(serde_json::Value::as_str)
            .map(stable_redacted_hash)
            .map_or(serde_json::Value::Null, serde_json::Value::String);
    }
    if field == "message_sid"
        && event
            .get("resource_type")
            .and_then(serde_json::Value::as_str)
            == Some("message")
    {
        return event
            .get("resource_sid")
            .and_then(serde_json::Value::as_str)
            .map(stable_redacted_hash)
            .map_or(serde_json::Value::Null, serde_json::Value::String);
    }
    event
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(stable_redacted_hash)
        .map_or(serde_json::Value::Null, serde_json::Value::String)
}

fn log_webhook_ingest_e2e(
    logs: &mut File,
    scenario: &str,
    result: &serde_json::Value,
    fixture_id: &str,
    artifact_path: &Path,
) {
    let command_line = std::env::args().collect::<Vec<_>>().join(" ");
    let record = json!({
        "record_type": "twilio_webhook_ingest_connector_boundary_e2e",
        "command_line": command_line,
        "git_revision": option_env!("GIT_REVISION").unwrap_or("unknown"),
        "provider": "twilio",
        "provider_fixture_id": fixture_id,
        "scenario": scenario,
        "webhook_event": result.get("event_type").cloned().unwrap_or(serde_json::Value::Null),
        "auth_decision": {
            "signature_valid": result
                .get("signature")
                .and_then(|signature| signature.get("valid"))
                .cloned()
                .unwrap_or(serde_json::Value::Bool(false)),
            "request_key_hash": result
                .get("signature")
                .and_then(|signature| signature.get("verified_request_key"))
                .and_then(serde_json::Value::as_str)
                .map(stable_redacted_hash)
                .map_or(serde_json::Value::Null, serde_json::Value::String),
        },
        "replay_decision": result
            .get("signature")
            .and_then(|signature| signature.get("is_replay"))
            .cloned()
            .unwrap_or(serde_json::Value::Bool(false)),
        "call_id_hash": hashed_event_field(result, "call_sid"),
        "message_id_hash": hashed_event_field(result, "message_sid"),
        "from_hash": hashed_event_field(result, "from"),
        "to_hash": hashed_event_field(result, "to"),
        "http_status": result.get("status_code").cloned().unwrap_or_else(|| json!(0)),
        "fcp_error_mapping": result.get("reason_code").cloned().unwrap_or_else(|| json!("missing")),
        "media": {
            "frame_count": 0,
            "byte_count": 0
        },
        "retry_decision": "not_retried",
        "cleanup_result": {
            "clean_shutdown": result
                .get("clean_shutdown")
                .cloned()
                .unwrap_or(serde_json::Value::Bool(false))
        },
        "artifact_path": artifact_path.display().to_string(),
        "skip_reason": serde_json::Value::Null,
    });
    writeln!(logs, "{record}").expect("write Twilio webhook ingest e2e log line");
    logs.flush()
        .expect("flush Twilio webhook ingest e2e log line");
}

async fn invoke_media_stream_process_events(
    connector: &mut TwilioConnector,
    capability: fcp_core::CapabilityToken,
    input: serde_json::Value,
) -> serde_json::Value {
    connector
        .handle_invoke(json!({
            "operation": "twilio.media_stream.process_events",
            "input": input,
            "capability_token": capability
        }))
        .await
        .expect("media stream process_events should return structured output")
}

async fn invoke_webhook_ingest_request(
    connector: &mut TwilioConnector,
    capability: &fcp_core::CapabilityToken,
    input: serde_json::Value,
) -> serde_json::Value {
    connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": input,
            "capability_token": capability.clone()
        }))
        .await
        .expect("webhook ingest should return structured output")
}

// ============================================================================
// Messaging Tests
// ============================================================================

/// Send SMS happy path.
#[fcp_async_core::runtime::test]
async fn send_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.send_message.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/Accounts/.*/Messages\\.json"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(twilio_message_response("SMtest001", "queued")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.send_message"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.send_message",
            "input": {
                "to": "+15551234567",
                "from": "+15559876543",
                "body": "Hello from FCP!"
            },
            "capability_token": capability
        }))
        .await
        .expect("send_message should succeed");

    assert_eq!(result["sid"], "SMtest001");
    assert_eq!(result["status"], "queued");
}

/// Get message details.
#[fcp_async_core::runtime::test]
async fn get_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.get_message.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/SMtest001\\.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(twilio_message_response("SMtest001", "delivered")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_message"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.get_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" },
            "capability_token": capability
        }))
        .await
        .expect("get_message should succeed");

    assert_eq!(result["sid"], "SMtest001");
    assert_eq!(result["status"], "delivered");
}

/// List messages with pagination.
#[fcp_async_core::runtime::test]
async fn list_messages_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_messages.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                twilio_message_response("SMtest001", "delivered"),
                twilio_message_response("SMtest002", "sent")
            ],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_messages"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.list_messages",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_messages",
            "input": { "page_size": 20 },
            "capability_token": capability
        }))
        .await
        .expect("list_messages should succeed");

    assert_eq!(result["messages"].as_array().unwrap().len(), 2);
}

// ============================================================================
// Voice Tests
// ============================================================================

/// Create outbound call.
#[fcp_async_core::runtime::test]
async fn create_call_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.create_call.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/Accounts/.*/Calls\\.json"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(twilio_call_response("CAtest001", "queued")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.create_call"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.create_call");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.create_call",
            "input": {
                "to": "+15551234567",
                "from": "+15559876543",
                "url": "https://example.com/twiml"
            },
            "capability_token": capability
        }))
        .await
        .expect("create_call should succeed");

    assert_eq!(result["sid"], "CAtest001");
    assert_eq!(result["status"], "queued");
}

/// Get call details.
#[fcp_async_core::runtime::test]
async fn get_call_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.get_call.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Calls/CAtest001\\.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(twilio_call_response("CAtest001", "completed")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_call"]).await;
    let capability = generate_valid_token(&signing_key, connector.instance_id(), "twilio.get_call");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.get_call",
            "input": { "call_sid": "CAtest001" },
            "capability_token": capability
        }))
        .await
        .expect("get_call should succeed");

    assert_eq!(result["sid"], "CAtest001");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["duration"], "30");
}

// ============================================================================
// Recordings Tests
// ============================================================================

/// List recordings.
#[fcp_async_core::runtime::test]
async fn list_recordings_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_recordings.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Recordings\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "recordings": [{
                "sid": "REtest001",
                "call_sid": "CAtest001",
                "duration": "30",
                "status": "completed",
                "date_created": "Wed, 15 Jan 2026 10:00:00 +0000"
            }],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_recordings"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.list_recordings",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_recordings",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect("list_recordings should succeed");

    assert_eq!(result["recordings"].as_array().unwrap().len(), 1);
}

/// Get account info.
#[fcp_async_core::runtime::test]
async fn get_account_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.get_account.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/ACtest.*\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sid": "ACtest123456789",
            "friendly_name": "Test Account",
            "status": "active",
            "type": "Full",
            "date_created": "Wed, 01 Jan 2025 00:00:00 +0000"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_account"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.get_account");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.get_account",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect("get_account should succeed");

    assert_eq!(result["sid"], "ACtest123456789");
    assert_eq!(result["status"], "active");
}

/// List phone numbers.
#[fcp_async_core::runtime::test]
async fn list_phone_numbers_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_phone_numbers.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/IncomingPhoneNumbers\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "incoming_phone_numbers": [{
                "sid": "PNtest001",
                "phone_number": "+15559876543",
                "friendly_name": "Main Number",
                "capabilities": { "sms": true, "mms": true, "voice": true, "fax": false }
            }],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_phone_numbers"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.list_phone_numbers",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_phone_numbers",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect("list_phone_numbers should succeed");

    assert_eq!(
        result["incoming_phone_numbers"].as_array().unwrap().len(),
        1
    );
}

// ============================================================================
// Error Taxonomy Tests (401/404/429/500 → `FcpError` mapping)
// ============================================================================

/// 401 Unauthorized maps to `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("twilio.error.401");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*\\.json"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(twilio_error_response(20003, "Authenticate")),
        )
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "bad-token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(0);

    let err = client
        .get_message("SMtest001")
        .await
        .expect_err("should fail with 401");

    assert!(
        matches!(err, fcp_twilio::error::TwilioError::Unauthorized),
        "expected Unauthorized, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "expected FcpError::Unauthorized, got: {fcp_err:?}"
    );
}

/// A 5xx on `POST /Messages.json` is NOT retried.
///
/// A 5xx means Twilio received the request, and Twilio has no idempotency key
/// for the Messages API — so replaying it sends and bills a second SMS. With
/// `max_retries = 3` one invoke could send four messages. `expect(1)` is the
/// assertion: the mock server panics on drop if a second request arrives.
/// See br-kxd3e.
#[fcp_async_core::runtime::test]
async fn server_error_on_message_send_is_not_retried() {
    let _ctx = AsyncTestContext::for_scenario("twilio.retry.post_5xx_terminal");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/Accounts/.*/Messages\\.json"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(3);

    client
        .send_message("+15550002", "+15550001", "hello", None, None)
        .await
        .expect_err("a 503 on a message send must surface, not silently resend");
}

/// The same 5xx on a GET IS still retried — the fix must not disable retries
/// for requests that are safe to replay.
#[fcp_async_core::runtime::test]
async fn server_error_on_read_is_still_retried() {
    let _ctx = AsyncTestContext::for_scenario("twilio.retry.get_5xx_retried");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*\\.json"))
        .respond_with(ResponseTemplate::new(503))
        .expect(2)
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(1);

    client
        .get_message("SMtest001")
        .await
        .expect_err("still fails after exhausting retries");
}

/// 404 Not Found maps to `FcpError::ResourceNotFound`.
#[fcp_async_core::runtime::test]
async fn error_404_maps_to_not_found() {
    let _ctx = AsyncTestContext::for_scenario("twilio.error.404");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*\\.json"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(twilio_error_response(
                20404,
                "The requested resource was not found",
            )),
        )
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(0);

    let err = client
        .get_message("SMnonexistent")
        .await
        .expect_err("should fail with 404");

    assert!(
        matches!(err, fcp_twilio::error::TwilioError::NotFound { .. }),
        "expected NotFound, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "expected FcpError::ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[fcp_async_core::runtime::test]
async fn error_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("twilio.error.429");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*\\.json"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(twilio_error_response(20429, "Too Many Requests"))
                .insert_header("retry-after", "0"),
        )
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(0);

    let err = client
        .get_message("SMtest001")
        .await
        .expect_err("should fail with 429");

    assert!(
        matches!(err, fcp_twilio::error::TwilioError::RateLimited { .. }),
        "expected RateLimited, got: {err:?}"
    );

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "expected FcpError::RateLimited, got: {fcp_err:?}"
    );
}

/// 500 Server Error maps to `FcpError::External` with retryable=true.
#[fcp_async_core::runtime::test]
async fn error_500_maps_to_external() {
    let _ctx = AsyncTestContext::for_scenario("twilio.error.500");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*\\.json"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(twilio_error_response(20500, "Internal server error")),
        )
        .mount(&mock_server)
        .await;

    let base = format!("{}/2010-04-01/Accounts/ACtest", mock_server.uri());
    let client = TwilioClient::new("ACtest", "token")
        .unwrap()
        .with_base_url(&base)
        .with_retry_config(0);

    let err = client
        .get_message("SMtest001")
        .await
        .expect_err("should fail with 500");

    let fcp_err = err.to_fcp_error();
    assert!(matches!(
        &fcp_err,
        fcp_core::FcpError::External {
            service,
            retryable: true,
            status_code: Some(500),
            ..
        } if service == "twilio"
    ));
}

/// Error `is_retryable` classification is correct.
#[test]
fn error_retryable_classification() {
    use fcp_twilio::error::TwilioError;

    assert!(
        TwilioError::RateLimited {
            retry_after_ms: 1000
        }
        .is_retryable()
    );
    assert!(
        TwilioError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_code: None,
        }
        .is_retryable()
    );
    assert!(
        TwilioError::Api {
            message: "Service unavailable".into(),
            status_code: Some(503),
            error_code: None,
        }
        .is_retryable()
    );

    assert!(!TwilioError::Unauthorized.is_retryable());
    assert!(
        !TwilioError::NotFound {
            resource: "test".into()
        }
        .is_retryable()
    );
    assert!(
        !TwilioError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
            error_code: None,
        }
        .is_retryable()
    );
}

// ============================================================================
// FCP2 Default-Deny / Capability Verification Tests
// ============================================================================

/// Invoke without `capability_token` fails.
#[fcp_async_core::runtime::test]
async fn capability_missing_token_fails() {
    let _ctx = AsyncTestContext::for_scenario("twilio.capability.missing_token");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    setup_handshake(&mut connector, &["twilio.get_message"]).await;

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" }
        }))
        .await
        .expect_err("invoke without token should fail");

    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing token, got: {err:?}"
    );
}

/// Invoke before handshake fails (no verifier).
#[fcp_async_core::runtime::test]
async fn capability_no_handshake_fails() {
    let _ctx = AsyncTestContext::for_scenario("twilio.capability.no_handshake");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let signing_key = Ed25519SigningKey::generate();
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.get_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" },
            "capability_token": capability
        }))
        .await
        .expect_err("invoke without handshake should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotHandshaken),
        "expected NotHandshaken, got: {err:?}"
    );
}

/// Invoke before configure fails (no client).
#[fcp_async_core::runtime::test]
async fn capability_no_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("twilio.capability.no_configure");

    let mut connector = TwilioConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.get_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" },
            "capability_token": capability
        }))
        .await
        .expect_err("invoke without configure should fail");

    assert!(
        matches!(err, fcp_core::FcpError::NotConfigured),
        "expected NotConfigured, got: {err:?}"
    );
}

/// Token signed for wrong operation fails.
#[fcp_async_core::runtime::test]
async fn capability_wrong_operation_fails() {
    let _ctx = AsyncTestContext::for_scenario("twilio.capability.wrong_op");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(
        &mut connector,
        &["twilio.get_message", "twilio.send_message"],
    )
    .await;

    let wrong_capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.send_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": { "message_sid": "SMtest001" },
            "capability_token": wrong_capability
        }))
        .await
        .expect_err("wrong capability should fail");

    let is_cap_error = matches!(
        &err,
        fcp_core::FcpError::CapabilityDenied { .. }
            | fcp_core::FcpError::Unauthorized { .. }
            | fcp_core::FcpError::OperationNotGranted { .. }
    );
    assert!(
        is_cap_error,
        "expected capability/operation denial, got: {err:?}"
    );
}

/// Unknown operation fails with `OperationNotGranted`.
#[fcp_async_core::runtime::test]
async fn capability_unknown_operation_fails() {
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.nonexistent"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.nonexistent");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.nonexistent",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect_err("unknown operation should fail");

    assert!(
        matches!(err, fcp_core::FcpError::OperationNotGranted { .. }),
        "expected OperationNotGranted, got: {err:?}"
    );
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

/// Health check before configure reports `not_configured`.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let connector = TwilioConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

/// Health check after configure reports healthy.
#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "healthy");
}

/// Handshake returns accepted with capabilities granted.
#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_grants_capabilities() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["twilio.read", "twilio.message", "twilio.voice"]
        }))
        .await
        .expect("handshake should succeed");

    assert_eq!(result["status"], "accepted");
    let caps = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(caps.len(), 3);
}

/// Shutdown returns clean status.
#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_clean() {
    let mut connector = TwilioConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

/// Introspect exposes all 10 operations with schemas.
#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_all_operations() {
    let connector = TwilioConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().unwrap();
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    let expected_ops = [
        "twilio.send_message",
        "twilio.get_message",
        "twilio.list_messages",
        "twilio.list_media",
        "twilio.get_media",
        "twilio.create_call",
        "twilio.get_call",
        "twilio.hangup_call",
        "twilio.list_calls",
        "twilio.generate_twiml",
        "twilio.media_stream.process_events",
        "twilio.list_recordings",
        "twilio.download_recording",
        "twilio.download_media",
        "twilio.get_account",
        "twilio.list_phone_numbers",
        "twilio.whatsapp_send",
        "twilio.whatsapp_send_template",
        "twilio.whatsapp_get",
        "twilio.whatsapp_list",
        // Conversations API
        "twilio.conversation.create",
        "twilio.conversation.get",
        "twilio.conversation.list",
        "twilio.conversation.participant.add",
        "twilio.conversation.participant.remove",
        "twilio.conversation.message.send",
        "twilio.conversation.message.list",
        // Verify API
        "twilio.verify.send",
        "twilio.verify.check",
        "twilio.verify.cancel",
        // Video API
        "twilio.video.room.create",
        "twilio.video.room.get",
        "twilio.video.room.list",
        "twilio.video.room.end",
        "twilio.video.room.participants",
        "twilio.video.recording.list",
        // Webhook handling
        "twilio.webhook.validate_signature",
        "twilio.webhook.evaluate_inbound_policy",
        "twilio.webhook.ingest_request",
        "twilio.webhook.parse_sms_event",
        "twilio.webhook.parse_status_callback",
        "twilio.webhook.parse_voice_event",
    ];

    for expected in &expected_ops {
        assert!(op_ids.contains(expected), "missing operation: {expected}");
    }
    assert_eq!(ops.len(), 42);

    for op in ops {
        assert!(
            op["input_schema"].is_object(),
            "input_schema should be object for {}",
            op["id"]
        );
        assert!(
            op["output_schema"].is_object(),
            "output_schema should be object for {}",
            op["id"]
        );
    }
}

#[test]
fn manifest_declares_strict_per_operation_network_constraints() {
    let manifest = twilio_manifest();
    assert_eq!(
        manifest.provides.operations.len(),
        42,
        "Twilio manifest operation count should match introspection"
    );

    for id in [
        "twilio.send_message",
        "twilio.get_message",
        "twilio.list_messages",
        "twilio.list_media",
        "twilio.get_media",
        "twilio.create_call",
        "twilio.get_call",
        "twilio.hangup_call",
        "twilio.list_calls",
        "twilio.list_recordings",
        "twilio.get_account",
        "twilio.list_phone_numbers",
        "twilio.whatsapp_send",
        "twilio.whatsapp_send_template",
        "twilio.whatsapp_get",
        "twilio.whatsapp_list",
    ] {
        assert_provider_network_constraints(
            id,
            manifest_operation(&manifest, id),
            &["api.twilio.com"],
        );
    }

    for id in ["twilio.download_recording", "twilio.download_media"] {
        assert_provider_network_constraints(
            id,
            manifest_operation(&manifest, id),
            &["api.twilio.com", "media.twiliocdn.com"],
        );
    }

    for id in [
        "twilio.conversation.create",
        "twilio.conversation.get",
        "twilio.conversation.list",
        "twilio.conversation.participant.add",
        "twilio.conversation.participant.remove",
        "twilio.conversation.message.send",
        "twilio.conversation.message.list",
    ] {
        assert_provider_network_constraints(
            id,
            manifest_operation(&manifest, id),
            &["conversations.twilio.com"],
        );
    }

    for id in [
        "twilio.verify.send",
        "twilio.verify.check",
        "twilio.verify.cancel",
    ] {
        assert_provider_network_constraints(
            id,
            manifest_operation(&manifest, id),
            &["verify.twilio.com"],
        );
    }

    for id in [
        "twilio.video.room.create",
        "twilio.video.room.get",
        "twilio.video.room.list",
        "twilio.video.room.end",
        "twilio.video.room.participants",
        "twilio.video.recording.list",
    ] {
        assert_provider_network_constraints(
            id,
            manifest_operation(&manifest, id),
            &["video.twilio.com"],
        );
    }

    for id in [
        "twilio.generate_twiml",
        "twilio.media_stream.process_events",
        "twilio.webhook.validate_signature",
        "twilio.webhook.evaluate_inbound_policy",
        "twilio.webhook.ingest_request",
        "twilio.webhook.parse_sms_event",
        "twilio.webhook.parse_status_callback",
        "twilio.webhook.parse_voice_event",
    ] {
        assert_no_connector_egress_network_constraints(id, manifest_operation(&manifest, id));
    }

    for (id, operation) in &manifest.provides.operations {
        assert!(
            operation.network_constraints.is_some(),
            "{id} should declare per-operation network_constraints"
        );
    }
}

// ============================================================================
// Twilio Media Streams Tests
// ============================================================================

/// Media stream processing accepts a fake Twilio-compatible frame session.
#[fcp_async_core::runtime::test]
async fn media_stream_process_events_accepts_fake_twilio_session() {
    let _ctx = AsyncTestContext::for_scenario("twilio.media_stream.process_events.fake_session");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.media_stream.process_events"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.media_stream.process_events",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.media_stream.process_events",
            "input": {
                "frames": [
                    { "event": "connected", "protocol": "Call", "version": "1.0.0" },
                    twilio_media_start_frame("MZfake001", "CAfake001"),
                    twilio_media_frame("MZfake001", 2, 1, 0),
                    twilio_media_frame("MZfake001", 3, 2, 20),
                    {
                        "event": "dtmf",
                        "sequenceNumber": "4",
                        "streamSid": "MZfake001",
                        "dtmf": { "track": "inbound_track", "digit": "5" }
                    },
                    {
                        "event": "mark",
                        "sequenceNumber": "5",
                        "streamSid": "MZfake001",
                        "mark": { "name": "audio-ack" }
                    },
                    {
                        "event": "stop",
                        "sequenceNumber": "6",
                        "streamSid": "MZfake001",
                        "stop": { "accountSid": TEST_ACCOUNT_SID, "callSid": "CAfake001" }
                    }
                ],
                "expected_stream_token": "AAAAAAAAAAAAAAAAAAAAAA",
                "allowed_call_sids": ["CAfake001"],
                "stream_token_issued_at_ms": 1000,
                "now_ms": 1200,
                "request_region": { "source": "fake_twilio_media_stream_harness" }
            },
            "capability_token": capability
        }))
        .await
        .expect("fake Twilio media stream should be accepted");

    assert_eq!(result["accepted"], true);
    assert_eq!(result["status_code"], 200);
    assert_eq!(result["reason_code"], "stream_stopped");
    assert_eq!(result["stream_sid"], "MZfake001");
    assert_eq!(result["call_sid"], "CAfake001");
    assert_eq!(result["media_frames"], 2);
    assert_eq!(result["duplicate_frames"], 0);
    assert_eq!(result["dtmf_digits"][0], "5");
    assert_eq!(result["marks_received"][0], "audio-ack");
    assert_eq!(
        result["supervision"]["builder"],
        "fcp_sdk::runtime::SupervisorConfig"
    );
    assert_eq!(
        result["supervision"]["app_spec"]["child_scope"],
        "twilio.media_stream.session"
    );
    assert_eq!(result["clean_shutdown"], true);
}

/// Media stream processing paces bidirectional outbound audio as 20 ms frames.
#[fcp_async_core::runtime::test]
async fn media_stream_process_events_paces_outbound_audio_and_marks() {
    let _ctx = AsyncTestContext::for_scenario("twilio.media_stream.process_events.pacing");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.media_stream.process_events"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.media_stream.process_events",
    );
    let outbound_payload = base64::engine::general_purpose::STANDARD.encode(vec![0x7f; 320]);

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.media_stream.process_events",
            "input": {
                "frames": [twilio_media_start_frame("MZpace001", "CApace001")],
                "outbound": [
                    { "type": "audio", "payload": outbound_payload, "mark": "tts-1" }
                ]
            },
            "capability_token": capability
        }))
        .await
        .expect("outbound audio should be paced");

    assert_eq!(result["accepted"], true);
    assert_eq!(result["outbound_messages"].as_array().unwrap().len(), 3);
    assert_eq!(result["outbound_messages"][0]["event"], "media");
    assert_eq!(result["outbound_messages"][1]["event"], "media");
    assert_eq!(result["outbound_messages"][2]["event"], "mark");
    assert_eq!(result["pacing_decisions"][0]["scheduled_after_ms"], 0);
    assert_eq!(result["pacing_decisions"][1]["scheduled_after_ms"], 20);
    assert_eq!(result["pacing_decisions"][2]["scheduled_after_ms"], 40);
    assert_eq!(result["queue_depth"], 0);
    assert_eq!(result["clean_shutdown"], true);
}

/// Media stream processing rejects stale callbacks and suppresses duplicate media frames.
#[fcp_async_core::runtime::test]
async fn media_stream_process_events_rejects_stale_and_suppresses_duplicates() {
    let _ctx = AsyncTestContext::for_scenario("twilio.media_stream.process_events.stale_duplicate");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.media_stream.process_events"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.media_stream.process_events",
    );

    let duplicate = connector
        .handle_invoke(json!({
            "operation": "twilio.media_stream.process_events",
            "input": {
                "frames": [
                    twilio_media_start_frame("MZdup001", "CAdup001"),
                    twilio_media_frame("MZdup001", 2, 1, 0),
                    twilio_media_frame("MZdup001", 2, 1, 0),
                    twilio_media_frame("MZdup001", 3, 2, 20)
                ]
            },
            "capability_token": capability.clone()
        }))
        .await
        .expect("duplicate media frame should be structured");

    let stale = connector
        .handle_invoke(json!({
            "operation": "twilio.media_stream.process_events",
            "input": {
                "frames": [twilio_media_start_frame("MZstale001", "CAstale001")],
                "expected_stream_token": "AAAAAAAAAAAAAAAAAAAAAA",
                "stream_token_issued_at_ms": 1_000,
                "now_ms": 60_000,
                "stream_token_ttl_ms": 30_000
            },
            "capability_token": capability
        }))
        .await
        .expect("stale media callback should be structured");

    assert_eq!(duplicate["accepted"], true);
    assert_eq!(duplicate["media_frames"], 2);
    assert_eq!(duplicate["duplicate_frames"], 1);
    assert_eq!(duplicate["suppressed_frames"], 1);
    assert_eq!(stale["accepted"], false);
    assert_eq!(stale["status_code"], 403);
    assert_eq!(stale["reason_code"], "stale_stream_token");
}

/// Media stream processing reports queue backpressure, timeout, and capped backoff.
#[fcp_async_core::runtime::test]
async fn media_stream_process_events_reports_backpressure_timeout_and_backoff_caps() {
    let _ctx = AsyncTestContext::for_scenario("twilio.media_stream.process_events.bounds");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.media_stream.process_events"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.media_stream.process_events",
    );
    let large_payload = base64::engine::general_purpose::STANDARD.encode(vec![0x7f; 480]);

    let backpressure = connector
        .handle_invoke(json!({
            "operation": "twilio.media_stream.process_events",
            "input": {
                "frames": [twilio_media_start_frame("MZbounds001", "CAbounds001")],
                "max_queued_audio_bytes": 200,
                "reconnect_attempts": 4,
                "max_reconnect_attempts": 4,
                "base_backoff_ms": 100,
                "max_backoff_ms": 250,
                "outbound": [{ "type": "audio", "payload": large_payload }]
            },
            "capability_token": capability.clone()
        }))
        .await
        .expect("backpressure should be structured");

    let timeout = connector
        .handle_invoke(json!({
            "operation": "twilio.media_stream.process_events",
            "input": {
                "frames": [twilio_media_start_frame("MZtimeout001", "CAtimeout001")],
                "deadline_exceeded": true
            },
            "capability_token": capability
        }))
        .await
        .expect("timeout should be structured");

    assert_eq!(backpressure["accepted"], false);
    assert_eq!(backpressure["status_code"], 429);
    assert_eq!(backpressure["reason_code"], "audio_backpressure");
    assert_eq!(backpressure["backpressure"], true);
    assert_eq!(backpressure["reconnect_plan"][0]["delay_ms"], 100);
    assert_eq!(backpressure["reconnect_plan"][1]["delay_ms"], 200);
    assert_eq!(backpressure["reconnect_plan"][2]["delay_ms"], 250);
    assert_eq!(backpressure["reconnect_plan"][2]["capped"], true);
    assert_eq!(timeout["accepted"], false);
    assert_eq!(timeout["status_code"], 408);
    assert_eq!(timeout["reason_code"], "request_timeout");
    assert_eq!(timeout["clean_shutdown"], false);
}

/// Connector-boundary media stream evidence covers fake Twilio WebSocket frames and callback edges.
#[fcp_async_core::runtime::test]
async fn media_stream_process_events_no_mock_e2e_jsonl_covers_callback_edges() {
    let _ctx = AsyncTestContext::for_scenario("twilio.media_stream.process_events.no_mock_e2e");
    let (mut logs, log_path) = open_media_stream_e2e_log();
    println!("twilio_media_stream_e2e_log={}", log_path.display());

    let callback_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &callback_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.media_stream.process_events"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.media_stream.process_events",
    );
    let outbound_payload = base64::engine::general_purpose::STANDARD.encode(vec![0x7f; 320]);
    let large_payload = base64::engine::general_purpose::STANDARD.encode(vec![0x7f; 480]);

    let scenarios = vec![
        (
            "start_media_mark_stop",
            json!({
                "frames": [
                    { "event": "connected", "protocol": "Call", "version": "1.0.0" },
                    twilio_media_start_frame("MZe2e001", "CAe2e001"),
                    twilio_media_frame("MZe2e001", 2, 1, 0),
                    twilio_media_frame("MZe2e001", 3, 2, 20),
                    {
                        "event": "mark",
                        "sequenceNumber": "4",
                        "streamSid": "MZe2e001",
                        "mark": { "name": "tts-ack" }
                    },
                    {
                        "event": "stop",
                        "sequenceNumber": "5",
                        "streamSid": "MZe2e001",
                        "stop": { "accountSid": TEST_ACCOUNT_SID, "callSid": "CAe2e001" }
                    }
                ],
                "expected_stream_token": "AAAAAAAAAAAAAAAAAAAAAA",
                "allowed_call_sids": ["CAe2e001"],
                "stream_token_issued_at_ms": 1_000,
                "now_ms": 1_100,
                "reconnect_attempts": 3,
                "max_reconnect_attempts": 3,
                "base_backoff_ms": 100,
                "max_backoff_ms": 250,
                "request_region": {
                    "callback_server": callback_server.uri(),
                    "surface": "fake_twilio_media_stream_websocket"
                }
            }),
            true,
            200,
            "stream_stopped",
            json!({
                "sequence_numbers": [1, 2, 3, 4, 5],
                "callback_server": callback_server.uri(),
                "path": "/twilio/media-stream"
            }),
        ),
        (
            "duplicate_frame_suppressed",
            json!({
                "frames": [
                    twilio_media_start_frame("MZe2e002", "CAe2e002"),
                    twilio_media_frame("MZe2e002", 2, 1, 0),
                    twilio_media_frame("MZe2e002", 2, 1, 0),
                    twilio_media_frame("MZe2e002", 3, 2, 20)
                ],
                "request_region": { "callback_server": callback_server.uri() }
            }),
            true,
            200,
            "stream_active",
            json!({
                "sequence_numbers": [1, 2, 2, 3],
                "expected_suppressed_frames": 1,
                "callback_server": callback_server.uri()
            }),
        ),
        (
            "outbound_queue_drain",
            json!({
                "frames": [twilio_media_start_frame("MZe2e003", "CAe2e003")],
                "outbound": [{ "type": "audio", "payload": outbound_payload.clone(), "mark": "tts-1" }],
                "request_region": { "callback_server": callback_server.uri() }
            }),
            true,
            200,
            "stream_active",
            json!({
                "sequence_numbers": [1],
                "expected_pacing_ms": [0, 20, 40],
                "callback_server": callback_server.uri()
            }),
        ),
        (
            "rate_limit_denied",
            json!({
                "frames": [twilio_media_start_frame("MZe2e004", "CAe2e004")],
                "rate_limited": true,
                "request_region": { "callback_server": callback_server.uri() }
            }),
            false,
            429,
            "rate_limited",
            json!({
                "sequence_numbers": [],
                "callback_server": callback_server.uri()
            }),
        ),
        (
            "timeout_denied",
            json!({
                "frames": [twilio_media_start_frame("MZe2e005", "CAe2e005")],
                "deadline_exceeded": true,
                "request_region": { "callback_server": callback_server.uri() }
            }),
            false,
            408,
            "request_timeout",
            json!({
                "sequence_numbers": [],
                "callback_server": callback_server.uri()
            }),
        ),
        (
            "cancellation_denied",
            json!({
                "frames": [twilio_media_start_frame("MZe2e006", "CAe2e006")],
                "cancelled": true,
                "request_region": { "callback_server": callback_server.uri() }
            }),
            false,
            408,
            "request_cancelled",
            json!({
                "sequence_numbers": [],
                "callback_server": callback_server.uri()
            }),
        ),
        (
            "malformed_inbound_clear_denied",
            json!({
                "frames": [
                    twilio_media_start_frame("MZe2e007", "CAe2e007"),
                    { "event": "clear", "sequenceNumber": "2", "streamSid": "MZe2e007" }
                ],
                "request_region": { "callback_server": callback_server.uri() }
            }),
            false,
            400,
            "unsupported_inbound_clear",
            json!({
                "sequence_numbers": [1, 2],
                "callback_server": callback_server.uri()
            }),
        ),
        (
            "backpressure_denied",
            json!({
                "frames": [twilio_media_start_frame("MZe2e008", "CAe2e008")],
                "max_queued_audio_bytes": 200,
                "outbound": [{ "type": "audio", "payload": large_payload.clone() }],
                "reconnect_attempts": 4,
                "max_reconnect_attempts": 4,
                "base_backoff_ms": 100,
                "max_backoff_ms": 250,
                "request_region": { "callback_server": callback_server.uri() }
            }),
            false,
            429,
            "audio_backpressure",
            json!({
                "sequence_numbers": [1],
                "callback_server": callback_server.uri()
            }),
        ),
        (
            "send_failure_tainted_cleanup",
            json!({
                "frames": [twilio_media_start_frame("MZe2e009", "CAe2e009")],
                "simulate_send_failure_after": 1,
                "outbound": [{ "type": "audio", "payload": outbound_payload.clone(), "mark": "tts-2" }],
                "request_region": { "callback_server": callback_server.uri() }
            }),
            true,
            200,
            "stream_active",
            json!({
                "sequence_numbers": [1],
                "expected_failure_code": "send_failed",
                "callback_server": callback_server.uri()
            }),
        ),
    ];

    for (scenario, input, expected_accepted, expected_status, expected_reason, details) in scenarios
    {
        let started = Instant::now();
        let result =
            invoke_media_stream_process_events(&mut connector, capability.clone(), input).await;
        let latency_ms = started.elapsed().as_millis();

        assert_eq!(result["accepted"], expected_accepted, "{scenario}");
        assert_eq!(result["status_code"], expected_status, "{scenario}");
        assert_eq!(result["reason_code"], expected_reason, "{scenario}");
        assert!(result["logs"].as_array().is_some(), "{scenario}");
        assert!(
            result["supervision"]["app_spec"]["child_scope"] == "twilio.media_stream.session",
            "{scenario}"
        );
        log_media_stream_e2e(&mut logs, scenario, &result, latency_ms, &details);
    }

    let jsonl = std::fs::read_to_string(&log_path).expect("read Twilio media stream e2e JSONL");
    assert!(!jsonl.trim().is_empty());
    assert!(!jsonl.contains("AAAAAAAAAAAAAAAAAAAAAA"));
    for scenario in [
        "start_media_mark_stop",
        "duplicate_frame_suppressed",
        "outbound_queue_drain",
        "rate_limit_denied",
        "timeout_denied",
        "cancellation_denied",
        "malformed_inbound_clear_denied",
        "backpressure_denied",
        "send_failure_tainted_cleanup",
    ] {
        assert!(
            jsonl.contains(scenario),
            "missing JSONL scenario {scenario}"
        );
    }
    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("JSONL line parses");
        assert_eq!(
            value["record_type"],
            "twilio_media_stream_connector_boundary_e2e"
        );
        assert_eq!(value["transport"], "host_forwarded_twilio_websocket_frames");
        assert!(value["latency_ms"].as_u64().is_some());
        assert!(value["final_result"]["reason_code"].as_str().is_some());
        assert!(value["cleanup"]["clean_shutdown"].as_bool().is_some());
        assert!(value["pacing_decisions"].as_array().is_some());
        assert!(value["reconnect_plan"].as_array().is_some());
    }
}

// ============================================================================
// Input Validation Edge Cases
// ============================================================================

/// Missing `to` in `send_message` fails.
#[fcp_async_core::runtime::test]
async fn validation_send_message_missing_to() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.send_message"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.send_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.send_message",
            "input": { "from": "+15559876543", "body": "Hi" },
            "capability_token": capability
        }))
        .await
        .expect_err("missing 'to' should fail");

    assert_invalid_request_contains(&err, "to");
}

/// Missing `body` in `send_message` fails.
#[fcp_async_core::runtime::test]
async fn validation_send_message_missing_body() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.send_message"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.send_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.send_message",
            "input": { "to": "+15551234567", "from": "+15559876543" },
            "capability_token": capability
        }))
        .await
        .expect_err("missing 'body' should fail");

    assert_invalid_request_contains(&err, "body");
}

/// Missing `message_sid` in `get_message` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_message_missing_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_message"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.get_message");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_message",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect_err("missing message_sid should fail");

    assert_invalid_request_contains(&err, "message_sid");
}

/// Missing `call_sid` in `get_call` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_call_missing_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_call"]).await;
    let capability = generate_valid_token(&signing_key, connector.instance_id(), "twilio.get_call");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_call",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect_err("missing call_sid should fail");

    assert_invalid_request_contains(&err, "call_sid");
}

/// Missing `url` in `create_call` fails.
#[fcp_async_core::runtime::test]
async fn validation_create_call_missing_url() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.create_call"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.create_call");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.create_call",
            "input": { "to": "+15551234567", "from": "+15559876543" },
            "capability_token": capability
        }))
        .await
        .expect_err("missing url should fail");

    assert_invalid_request_contains(&err, "url");
}

// ============================================================================
// SMS Media Tests
// ============================================================================

/// List media attachments for a message.
#[fcp_async_core::runtime::test]
async fn list_media_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_media.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/SMtest001/Media\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "media_list": [
                {
                    "sid": "MEtest001",
                    "account_sid": "ACtest123456789",
                    "parent_sid": "SMtest001",
                    "content_type": "image/jpeg",
                    "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
                    "date_updated": "Wed, 15 Jan 2026 10:00:01 +0000",
                    "uri": "/2010-04-01/Accounts/ACtest/Messages/SMtest001/Media/MEtest001.json"
                },
                {
                    "sid": "MEtest002",
                    "account_sid": "ACtest123456789",
                    "parent_sid": "SMtest001",
                    "content_type": "image/png",
                    "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
                    "date_updated": "Wed, 15 Jan 2026 10:00:01 +0000",
                    "uri": "/2010-04-01/Accounts/ACtest/Messages/SMtest001/Media/MEtest002.json"
                }
            ],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_media"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.list_media");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_media",
            "input": { "message_sid": "SMtest001" },
            "capability_token": capability
        }))
        .await
        .expect("list_media should succeed");

    assert_eq!(result["media_list"].as_array().unwrap().len(), 2);
    assert!(result["next_page_uri"].is_null());
}

/// Get a specific media resource.
#[fcp_async_core::runtime::test]
async fn get_media_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.get_media.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(
            "/Accounts/.*/Messages/SMtest001/Media/MEtest001\\.json",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sid": "MEtest001",
            "account_sid": "ACtest123456789",
            "parent_sid": "SMtest001",
            "content_type": "image/jpeg",
            "date_created": "Wed, 15 Jan 2026 10:00:00 +0000",
            "date_updated": "Wed, 15 Jan 2026 10:00:01 +0000",
            "uri": "/2010-04-01/Accounts/ACtest/Messages/SMtest001/Media/MEtest001.json"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_media"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.get_media");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.get_media",
            "input": { "message_sid": "SMtest001", "media_sid": "MEtest001" },
            "capability_token": capability
        }))
        .await
        .expect("get_media should succeed");

    assert_eq!(result["sid"], "MEtest001");
    assert_eq!(result["content_type"], "image/jpeg");
    assert_eq!(result["parent_sid"], "SMtest001");
}

/// List media with empty result.
#[fcp_async_core::runtime::test]
async fn list_media_empty_result() {
    let _ctx = AsyncTestContext::for_scenario("twilio.list_media.empty");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/Accounts/.*/Messages/.*/Media\\.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "media_list": [],
            "next_page_uri": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_media"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.list_media");

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.list_media",
            "input": { "message_sid": "SMtest999" },
            "capability_token": capability
        }))
        .await
        .expect("list_media with empty result should succeed");

    assert_eq!(result["media_list"].as_array().unwrap().len(), 0);
}

/// Missing `message_sid` in `list_media` fails.
#[fcp_async_core::runtime::test]
async fn validation_list_media_missing_message_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.list_media"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.list_media");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.list_media",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect_err("missing message_sid should fail");

    assert_invalid_request_contains(&err, "message_sid");
}

/// Missing `media_sid` in `get_media` fails.
#[fcp_async_core::runtime::test]
async fn validation_get_media_missing_media_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.get_media"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "twilio.get_media");

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.get_media",
            "input": { "message_sid": "SMtest001" },
            "capability_token": capability
        }))
        .await
        .expect_err("missing media_sid should fail");

    assert_invalid_request_contains(&err, "media_sid");
}

/// Missing `recording_sid` in `download_recording` fails.
#[fcp_async_core::runtime::test]
async fn validation_download_recording_missing_sid() {
    let mock_server = MockServer::start().await;
    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.download_recording"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.download_recording",
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.download_recording",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect_err("missing recording_sid should fail");

    assert_invalid_request_contains(&err, "recording_sid");
}

// ============================================================================
// Webhook Handling Tests
// ============================================================================

/// Parse SMS webhook event — happy path.
#[fcp_async_core::runtime::test]
async fn webhook_parse_sms_event_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_sms_event.happy_path");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_sms_event"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_sms_event",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_sms_event",
            "input": {
                "body": {
                    "MessageSid": "SM1234567890abcdef1234567890abcdef",
                    "From": "+15551234567",
                    "To": "+15559876543",
                    "Body": "Hello from webhook!",
                    "NumMedia": "2",
                    "AccountSid": "ACtest123456789",
                    "SmsSid": "SM1234567890abcdef1234567890abcdef",
                    "NumSegments": "1"
                }
            },
            "capability_token": capability
        }))
        .await
        .expect("parse_sms_event should succeed");

    assert_eq!(result["event_type"], "sms.inbound");
    assert_eq!(result["message_sid"], "SM1234567890abcdef1234567890abcdef");
    assert_eq!(result["from"], "+15551234567");
    assert_eq!(result["to"], "+15559876543");
    assert_eq!(result["body"], "Hello from webhook!");
    assert_eq!(result["num_media"], 2);
    assert_eq!(result["account_sid"], "ACtest123456789");
    assert_eq!(result["tainted"], true);
    assert_eq!(result["event_id"], "evt_SM1234567890abcdef1234567890abcdef");
}

/// Parse SMS webhook event — missing required `MessageSid`.
#[fcp_async_core::runtime::test]
async fn webhook_parse_sms_event_missing_message_sid() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_sms_event.missing_message_sid");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_sms_event"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_sms_event",
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_sms_event",
            "input": {
                "body": {
                    "From": "+15551234567",
                    "To": "+15559876543"
                }
            },
            "capability_token": capability
        }))
        .await
        .expect_err("should fail without MessageSid");

    assert_invalid_request_contains(&err, "MessageSid");
}

/// Parse SMS webhook event — minimal fields (no optional fields).
#[fcp_async_core::runtime::test]
async fn webhook_parse_sms_event_minimal() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_sms_event.minimal");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_sms_event"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_sms_event",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_sms_event",
            "input": {
                "body": {
                    "MessageSid": "SMminimal",
                    "From": "+15550001111",
                    "To": "+15552223333"
                }
            },
            "capability_token": capability
        }))
        .await
        .expect("parse_sms_event should succeed with minimal fields");

    assert_eq!(result["event_type"], "sms.inbound");
    assert_eq!(result["message_sid"], "SMminimal");
    assert!(result["body"].is_null());
    assert!(result["num_media"].is_null());
    assert_eq!(result["tainted"], true);
}

/// Parse status callback — message delivered.
#[fcp_async_core::runtime::test]
async fn webhook_parse_status_callback_message_delivered() {
    let _ctx =
        AsyncTestContext::for_scenario("twilio.webhook.parse_status_callback.message_delivered");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.parse_status_callback"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_status_callback",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_status_callback",
            "input": {
                "body": {
                    "MessageSid": "SM9876543210",
                    "MessageStatus": "delivered",
                    "Timestamp": "2026-01-15T10:00:00Z"
                }
            },
            "capability_token": capability
        }))
        .await
        .expect("parse_status_callback should succeed");

    assert_eq!(result["event_type"], "message.status");
    assert_eq!(result["resource_sid"], "SM9876543210");
    assert_eq!(result["resource_type"], "message");
    assert_eq!(result["status"], "delivered");
    assert_eq!(result["timestamp"], "2026-01-15T10:00:00Z");
    assert_eq!(result["tainted"], true);
}

/// Parse status callback — call completed.
#[fcp_async_core::runtime::test]
async fn webhook_parse_status_callback_call_completed() {
    let _ctx =
        AsyncTestContext::for_scenario("twilio.webhook.parse_status_callback.call_completed");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.parse_status_callback"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_status_callback",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_status_callback",
            "input": {
                "body": {
                    "CallSid": "CA1234567890",
                    "CallStatus": "completed"
                }
            },
            "capability_token": capability
        }))
        .await
        .expect("parse_status_callback for call should succeed");

    assert_eq!(result["event_type"], "call.status");
    assert_eq!(result["resource_sid"], "CA1234567890");
    assert_eq!(result["resource_type"], "call");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["tainted"], true);
}

/// Parse status callback — message failed with error code.
#[fcp_async_core::runtime::test]
async fn webhook_parse_status_callback_with_error() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_status_callback.with_error");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.parse_status_callback"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_status_callback",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_status_callback",
            "input": {
                "body": {
                    "MessageSid": "SMfailed001",
                    "MessageStatus": "failed",
                    "ErrorCode": "30006",
                    "ErrorMessage": "Landline or unreachable carrier"
                }
            },
            "capability_token": capability
        }))
        .await
        .expect("parse_status_callback with error should succeed");

    assert_eq!(result["status"], "failed");
    assert_eq!(result["error_code"], "30006");
    assert_eq!(result["error_message"], "Landline or unreachable carrier");
}

/// Parse status callback — missing both `MessageSid` and `CallSid`.
#[fcp_async_core::runtime::test]
async fn webhook_parse_status_callback_missing_sid() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_status_callback.missing_sid");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.parse_status_callback"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_status_callback",
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_status_callback",
            "input": {
                "body": {
                    "SomeOtherField": "value"
                }
            },
            "capability_token": capability
        }))
        .await
        .expect_err("should fail without MessageSid or CallSid");

    assert_invalid_request_any_contains(&err, &["MessageSid", "CallSid"]);
}

/// Parse voice webhook event — happy path.
#[fcp_async_core::runtime::test]
async fn webhook_parse_voice_event_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_voice_event.happy_path");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_voice_event"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_voice_event",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_voice_event",
            "input": {
                "body": {
                    "CallSid": "CA0000111122223333",
                    "From": "+15551112222",
                    "To": "+15553334444",
                    "CallStatus": "ringing",
                    "Direction": "inbound",
                    "AccountSid": "ACtest123456789",
                    "CallerCity": "San Francisco",
                    "CallerState": "CA",
                    "CallerCountry": "US"
                }
            },
            "capability_token": capability
        }))
        .await
        .expect("parse_voice_event should succeed");

    assert_eq!(result["event_type"], "voice.inbound");
    assert_eq!(result["call_sid"], "CA0000111122223333");
    assert_eq!(result["from"], "+15551112222");
    assert_eq!(result["to"], "+15553334444");
    assert_eq!(result["call_status"], "ringing");
    assert_eq!(result["direction"], "inbound");
    assert_eq!(result["caller_city"], "San Francisco");
    assert_eq!(result["caller_country"], "US");
    assert_eq!(result["tainted"], true);
}

/// Parse voice webhook event — missing `CallSid`.
#[fcp_async_core::runtime::test]
async fn webhook_parse_voice_event_missing_call_sid() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_voice_event.missing_call_sid");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_voice_event"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_voice_event",
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_voice_event",
            "input": {
                "body": {
                    "From": "+15551112222",
                    "To": "+15553334444"
                }
            },
            "capability_token": capability
        }))
        .await
        .expect_err("should fail without CallSid");

    assert_invalid_request_contains(&err, "CallSid");
}

/// Evaluate inbound policy — exact E.164 allowlist accepts the caller.
#[fcp_async_core::runtime::test]
async fn webhook_evaluate_inbound_policy_allowlist_accepts_exact_e164() {
    let _ctx =
        AsyncTestContext::for_scenario("twilio.webhook.evaluate_inbound_policy.allowlist_accept");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.evaluate_inbound_policy"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.evaluate_inbound_policy",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.evaluate_inbound_policy",
            "input": {
                "body": {
                    "MessageSid": "SMallow",
                    "From": "+15551234567",
                    "To": "+15559876543"
                },
                "inbound_policy": "allowlist",
                "allowed_from": ["+15551234567"]
            },
            "capability_token": capability
        }))
        .await
        .expect("allowlisted sender should be evaluated");

    assert_eq!(result["allowed"], true);
    assert_eq!(result["policy"], "allowlist");
    assert_eq!(result["reason_code"], "allowed_exact_from");
    assert_eq!(result["normalized_from"], "+15551234567");
    assert_eq!(result["matched_from"], "+15551234567");
    assert_eq!(result["event_type"], "sms.inbound");
    assert_eq!(result["audit_event_type"], "twilio.inbound_policy.allowed");
    assert_eq!(result["tainted"], true);
}

/// Evaluate inbound policy — disabled policy denies even valid E.164 callers.
#[fcp_async_core::runtime::test]
async fn webhook_evaluate_inbound_policy_disabled_rejects() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.evaluate_inbound_policy.disabled");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.evaluate_inbound_policy"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.evaluate_inbound_policy",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.evaluate_inbound_policy",
            "input": {
                "body": {
                    "CallSid": "CAdisabled",
                    "From": "+15551234567",
                    "To": "+15559876543"
                },
                "inbound_policy": "disabled"
            },
            "capability_token": capability
        }))
        .await
        .expect("disabled policy should return structured denial");

    assert_eq!(result["allowed"], false);
    assert_eq!(result["reason_code"], "inbound_disabled");
    assert_eq!(result["event_type"], "voice.inbound");
    assert_eq!(result["audit_event_type"], "twilio.inbound_policy.denied");
}

/// Evaluate inbound policy — no suffix or punctuation-insensitive matching.
#[fcp_async_core::runtime::test]
async fn webhook_evaluate_inbound_policy_rejects_non_e164_suffix_match() {
    let _ctx = AsyncTestContext::for_scenario(
        "twilio.webhook.evaluate_inbound_policy.rejects_suffix_match",
    );
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.evaluate_inbound_policy"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.evaluate_inbound_policy",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.evaluate_inbound_policy",
            "input": {
                "body": {
                    "MessageSid": "SMsuffix",
                    "From": "5551234567",
                    "To": "+15559876543"
                },
                "inbound_policy": "allowlist",
                "allowed_from": ["+15551234567"]
            },
            "capability_token": capability
        }))
        .await
        .expect("invalid caller format should return structured denial");

    assert_eq!(result["allowed"], false);
    assert_eq!(result["reason_code"], "invalid_from");
    assert!(result["normalized_from"].is_null());
}

/// Evaluate inbound policy — exact E.164 mismatch is denied.
#[fcp_async_core::runtime::test]
async fn webhook_evaluate_inbound_policy_rejects_not_allowlisted() {
    let _ctx =
        AsyncTestContext::for_scenario("twilio.webhook.evaluate_inbound_policy.not_allowlisted");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.evaluate_inbound_policy"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.evaluate_inbound_policy",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.evaluate_inbound_policy",
            "input": {
                "body": {
                    "MessageSid": "SMdeny",
                    "From": "+15550000000",
                    "To": "+15559876543"
                },
                "inbound_policy": "allowlist",
                "allowed_from": ["+15551234567"]
            },
            "capability_token": capability
        }))
        .await
        .expect("non-allowlisted sender should return structured denial");

    assert_eq!(result["allowed"], false);
    assert_eq!(result["reason_code"], "not_allowlisted");
    assert_eq!(result["normalized_from"], "+15550000000");
    assert!(result["matched_from"].is_null());
}

/// Evaluate inbound policy — missing and anonymous callers fail closed.
#[fcp_async_core::runtime::test]
async fn webhook_evaluate_inbound_policy_rejects_missing_and_anonymous_from() {
    let _ctx =
        AsyncTestContext::for_scenario("twilio.webhook.evaluate_inbound_policy.missing_anonymous");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.evaluate_inbound_policy"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.evaluate_inbound_policy",
    );

    let missing = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.evaluate_inbound_policy",
            "input": {
                "body": {
                    "MessageSid": "SMmissing",
                    "To": "+15559876543"
                },
                "inbound_policy": "open"
            },
            "capability_token": capability.clone()
        }))
        .await
        .expect("missing From should return structured denial");
    let anonymous = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.evaluate_inbound_policy",
            "input": {
                "body": {
                    "CallSid": "CAanonymous",
                    "From": "anonymous",
                    "To": "+15559876543"
                },
                "inbound_policy": "open"
            },
            "capability_token": capability
        }))
        .await
        .expect("anonymous From should return structured denial");

    assert_eq!(missing["allowed"], false);
    assert_eq!(missing["reason_code"], "missing_from");
    assert_eq!(anonymous["allowed"], false);
    assert_eq!(anonymous["reason_code"], "anonymous_from");
}

/// Evaluate inbound policy — invalid allowlist entries are configuration errors.
#[fcp_async_core::runtime::test]
async fn webhook_evaluate_inbound_policy_rejects_invalid_allowlist_entry() {
    let _ctx =
        AsyncTestContext::for_scenario("twilio.webhook.evaluate_inbound_policy.bad_allowlist");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key =
        setup_handshake(&mut connector, &["twilio.webhook.evaluate_inbound_policy"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.evaluate_inbound_policy",
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.evaluate_inbound_policy",
            "input": {
                "body": {
                    "MessageSid": "SMbadconfig",
                    "From": "+15551234567",
                    "To": "+15559876543"
                },
                "inbound_policy": "allowlist",
                "allowed_from": ["5551234567"]
            },
            "capability_token": capability
        }))
        .await
        .expect_err("bad allowlist entries should be rejected");

    assert_invalid_request_contains(&err, "exact E.164");
}

/// Evaluate inbound policy — replay marking does not bypass caller policy.
#[fcp_async_core::runtime::test]
async fn webhook_evaluate_inbound_policy_keeps_replay_and_policy_separate() {
    let _ctx =
        AsyncTestContext::for_scenario("twilio.webhook.evaluate_inbound_policy.replay_interaction");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(
        &mut connector,
        &[
            "twilio.webhook.validate_signature",
            "twilio.webhook.evaluate_inbound_policy",
        ],
    )
    .await;
    let validate_capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.validate_signature",
    );
    let policy_capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.evaluate_inbound_policy",
    );
    let url = "https://example.com/webhook";
    let params = json!({
        "MessageSid": "SMreplaypolicy",
        "From": "+15551234567",
        "To": "+15559876543",
        "Body": "Hello"
    });
    let signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        url,
        &[
            ("Body", "Hello"),
            ("From", "+15551234567"),
            ("MessageSid", "SMreplaypolicy"),
            ("To", "+15559876543"),
        ],
    );
    let validate_request = json!({
        "operation": "twilio.webhook.validate_signature",
        "input": {
            "url": url,
            "params": params,
            "signature": signature,
            "auth_token": TWILIO_TEST_HMAC_KEY
        },
        "capability_token": validate_capability
    });

    let first = connector
        .handle_invoke(validate_request.clone())
        .await
        .expect("first signature validation should succeed");
    let replay = connector
        .handle_invoke(validate_request)
        .await
        .expect("duplicate signature validation should still be structured");
    let policy = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.evaluate_inbound_policy",
            "input": {
                "body": {
                    "MessageSid": "SMreplaypolicy",
                    "From": "+15551234567",
                    "To": "+15559876543"
                },
                "inbound_policy": "allowlist",
                "allowed_from": ["+15551234567"]
            },
            "capability_token": policy_capability
        }))
        .await
        .expect("policy evaluation should still run for signed request");

    assert_eq!(first["valid"], true);
    assert_eq!(first["is_replay"], false);
    assert_eq!(replay["valid"], true);
    assert_eq!(replay["is_replay"], true);
    assert_eq!(policy["allowed"], true);
    assert_eq!(policy["reason_code"], "allowed_exact_from");
}

/// Ingest request — no-mock loopback accepts valid SMS and voice status callbacks.
#[fcp_async_core::runtime::test]
async fn webhook_ingest_request_accepts_valid_sms_and_voice_status() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.ingest_request.accepts");
    let (mut connector, capability) = setup_webhook_ingest_connector().await;
    let sms_url = "https://example.com/twilio/sms";
    let sms_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        sms_url,
        &[
            ("Body", "hello from ingress"),
            ("From", "+15551234567"),
            ("MessageSid", "SMingresssms"),
            ("To", "+15559876543"),
        ],
    );

    let sms = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": {
                "method": "POST",
                "url": sms_url,
                "headers": { "X-Twilio-Signature": sms_signature },
                "body": {
                    "MessageSid": "SMingresssms",
                    "From": "+15551234567",
                    "To": "+15559876543",
                    "Body": "hello from ingress"
                },
                "auth_token": TWILIO_TEST_HMAC_KEY,
                "inbound_policy": "allowlist",
                "allowed_from": ["+15551234567"],
                "request_region": { "source": "loopback_harness" }
            },
            "capability_token": capability.clone()
        }))
        .await
        .expect("valid signed SMS ingress should be accepted");

    assert_eq!(sms["accepted"], true);
    assert_eq!(sms["status_code"], 200);
    assert_eq!(sms["event_type"], "sms.inbound");
    assert_eq!(sms["event"]["message_sid"], "SMingresssms");
    assert_eq!(sms["signature"]["valid"], true);
    assert_eq!(sms["signature"]["is_replay"], false);
    assert_eq!(sms["policy"]["allowed"], true);
    assert_eq!(sms["policy"]["reason_code"], "allowed_exact_from");
    assert_eq!(
        sms["request_region"]["surface"],
        "fcp.webhook.request_region"
    );
    assert_eq!(
        sms["service_layers"]["builder"],
        "fcp.webhook.ServiceBuilder"
    );
    assert_eq!(sms["service_layers"]["layers"].as_array().unwrap().len(), 4);
    assert_eq!(sms["clean_shutdown"], true);

    let voice_status_url = "https://example.com/twilio/voice-status";
    let voice_status_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        voice_status_url,
        &[
            ("CallSid", "CAstatusingress"),
            ("CallStatus", "completed"),
            ("Timestamp", "2026-01-15T10:00:00Z"),
        ],
    );
    let voice_status = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": {
                "method": "POST",
                "url": voice_status_url,
                "headers": { "x-twilio-signature": voice_status_signature },
                "body": {
                    "CallSid": "CAstatusingress",
                    "CallStatus": "completed",
                    "Timestamp": "2026-01-15T10:00:00Z"
                },
                "auth_token": TWILIO_TEST_HMAC_KEY
            },
            "capability_token": capability
        }))
        .await
        .expect("valid signed voice status callback should be accepted");

    assert_eq!(voice_status["accepted"], true);
    assert_eq!(voice_status["event_type"], "call.status");
    assert_eq!(voice_status["event"]["resource_type"], "call");
    assert!(voice_status["policy"].is_null());
    assert!(
        voice_status["logs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["code"] == "status_callback_not_inbound")
    );
}

/// Ingest request — invalid signatures fail and duplicate signed requests are suppressed.
#[fcp_async_core::runtime::test]
async fn webhook_ingest_request_rejects_invalid_signature_and_replay() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.ingest_request.signature_replay");
    let (mut connector, capability) = setup_webhook_ingest_connector().await;
    let url = "https://example.com/twilio/replay";
    let signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        url,
        &[
            ("Body", "dedupe"),
            ("From", "+15551234567"),
            ("MessageSid", "SMingressreplay"),
            ("To", "+15559876543"),
        ],
    );
    let request = json!({
        "operation": "twilio.webhook.ingest_request",
        "input": {
            "method": "POST",
            "url": url,
            "headers": { "X-Twilio-Signature": signature },
            "body": {
                "MessageSid": "SMingressreplay",
                "From": "+15551234567",
                "To": "+15559876543",
                "Body": "dedupe"
            },
            "auth_token": TWILIO_TEST_HMAC_KEY,
            "inbound_policy": "open"
        },
        "capability_token": capability.clone()
    });

    let first = connector
        .handle_invoke(request.clone())
        .await
        .expect("first signed request should be accepted");
    let replay = connector
        .handle_invoke(request)
        .await
        .expect("duplicate signed request should return structured suppression");
    let invalid = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": {
                "method": "POST",
                "url": "https://example.com/twilio/invalid",
                "headers": { "X-Twilio-Signature": "not-valid-base64!!!@@@" },
                "body": {
                    "MessageSid": "SMingressinvalid",
                    "From": "+15551234567",
                    "To": "+15559876543",
                    "Body": "bad signature"
                },
                "auth_token": TWILIO_TEST_HMAC_KEY,
                "inbound_policy": "open"
            },
            "capability_token": capability
        }))
        .await
        .expect("bad signature should return structured denial");

    assert_eq!(first["accepted"], true);
    assert_eq!(replay["accepted"], false);
    assert_eq!(replay["status_code"], 409);
    assert_eq!(replay["reason_code"], "replay_suppressed");
    assert_eq!(replay["signature"]["is_replay"], true);
    assert_eq!(invalid["accepted"], false);
    assert_eq!(invalid["status_code"], 401);
    assert_eq!(invalid["reason_code"], "invalid_signature");
}

/// Ingest request — inbound policy gates unauthorized and authorized callers.
#[fcp_async_core::runtime::test]
async fn webhook_ingest_request_applies_inbound_policy() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.ingest_request.policy");
    let (mut connector, capability) = setup_webhook_ingest_connector().await;
    let denied_url = "https://example.com/twilio/policy-denied";
    let denied_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        denied_url,
        &[
            ("Body", "blocked"),
            ("From", "+15550000000"),
            ("MessageSid", "SMingressdenied"),
            ("To", "+15559876543"),
        ],
    );
    let denied = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": {
                "method": "POST",
                "url": denied_url,
                "headers": { "X-Twilio-Signature": denied_signature },
                "body": {
                    "MessageSid": "SMingressdenied",
                    "From": "+15550000000",
                    "To": "+15559876543",
                    "Body": "blocked"
                },
                "auth_token": TWILIO_TEST_HMAC_KEY,
                "inbound_policy": "allowlist",
                "allowed_from": ["+15551234567"]
            },
            "capability_token": capability.clone()
        }))
        .await
        .expect("policy denial should be structured");

    let allowed_url = "https://example.com/twilio/policy-allowed";
    let allowed_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        allowed_url,
        &[
            ("Body", "allowed"),
            ("From", "+15551234567"),
            ("MessageSid", "SMingressallowed"),
            ("To", "+15559876543"),
        ],
    );
    let allowed = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": {
                "method": "POST",
                "url": allowed_url,
                "headers": { "X-Twilio-Signature": allowed_signature },
                "body": {
                    "MessageSid": "SMingressallowed",
                    "From": "+15551234567",
                    "To": "+15559876543",
                    "Body": "allowed"
                },
                "auth_token": TWILIO_TEST_HMAC_KEY,
                "inbound_policy": "allowlist",
                "allowed_from": ["+15551234567"]
            },
            "capability_token": capability
        }))
        .await
        .expect("allowlisted caller should be accepted");

    assert_eq!(denied["accepted"], false);
    assert_eq!(denied["status_code"], 403);
    assert_eq!(denied["reason_code"], "not_allowlisted");
    assert!(denied["event"].is_null());
    assert_eq!(denied["policy"]["allowed"], false);
    assert_eq!(allowed["accepted"], true);
    assert_eq!(allowed["event"]["message_sid"], "SMingressallowed");
}

/// Ingest request — malformed and oversized payloads are denied before emission.
#[fcp_async_core::runtime::test]
async fn webhook_ingest_request_rejects_malformed_and_oversized_payloads() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.ingest_request.malformed_oversized");
    let (mut connector, capability) = setup_webhook_ingest_connector().await;
    let malformed_url = "https://example.com/twilio/malformed";
    let malformed_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        malformed_url,
        &[("Unexpected", "value")],
    );
    let malformed = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": {
                "method": "POST",
                "url": malformed_url,
                "headers": { "X-Twilio-Signature": malformed_signature },
                "body": { "Unexpected": "value" },
                "auth_token": TWILIO_TEST_HMAC_KEY,
                "inbound_policy": "open"
            },
            "capability_token": capability.clone()
        }))
        .await
        .expect("malformed payload should return structured denial");
    let oversized = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": {
                "method": "POST",
                "url": "https://example.com/twilio/oversized",
                "headers": {},
                "body": {
                    "MessageSid": "SMingressoversized",
                    "From": "+15551234567",
                    "To": "+15559876543"
                },
                "body_size_bytes": 65_536,
                "max_body_bytes": 32
            },
            "capability_token": capability
        }))
        .await
        .expect("oversized payload should return structured denial");

    assert_eq!(malformed["accepted"], false);
    assert_eq!(malformed["status_code"], 400);
    assert_eq!(malformed["reason_code"], "malformed_payload");
    assert_eq!(oversized["accepted"], false);
    assert_eq!(oversized["status_code"], 413);
    assert_eq!(oversized["reason_code"], "payload_too_large");
    assert!(oversized["signature"].is_null());
}

/// Ingest request — request-region timeout/cancellation returns clean shutdown metadata.
#[fcp_async_core::runtime::test]
async fn webhook_ingest_request_reports_timeout_cancellation_and_clean_shutdown() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.ingest_request.timeout_cancel");
    let (mut connector, capability) = setup_webhook_ingest_connector().await;
    let cancelled = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": {
                "method": "POST",
                "url": "https://example.com/twilio/cancelled",
                "headers": {},
                "body": {},
                "request_region": {
                    "source": "loopback_harness",
                    "cancelled": true
                }
            },
            "capability_token": capability.clone()
        }))
        .await
        .expect("cancelled request should return structured denial");
    let timed_out = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.ingest_request",
            "input": {
                "method": "POST",
                "url": "https://example.com/twilio/timeout",
                "headers": {},
                "body": {},
                "request_region": {
                    "source": "loopback_harness",
                    "deadline_exceeded": true
                },
                "timeout_ms": 1,
                "concurrency_limit": 1
            },
            "capability_token": capability
        }))
        .await
        .expect("timed-out request should return structured denial");

    assert_eq!(cancelled["accepted"], false);
    assert_eq!(cancelled["status_code"], 408);
    assert_eq!(cancelled["reason_code"], "request_cancelled");
    assert_eq!(cancelled["clean_shutdown"], true);
    assert_eq!(timed_out["accepted"], false);
    assert_eq!(timed_out["reason_code"], "request_timeout");
    assert_eq!(timed_out["clean_shutdown"], true);
    assert_eq!(timed_out["service_layers"]["layers"][0]["name"], "timeout");
    assert_eq!(
        timed_out["service_layers"]["layers"][1]["name"],
        "concurrency_limit"
    );
    assert_eq!(
        timed_out["service_layers"]["layers"][2]["name"],
        "load_shed"
    );
    assert_eq!(
        timed_out["service_layers"]["layers"][3]["name"],
        "rate_limit"
    );
}

/// Ingest request — loopback e2e harness emits redaction-safe JSONL for all webhook gates.
#[fcp_async_core::runtime::test]
async fn webhook_ingest_request_loopback_e2e_logs_redaction_safe_jsonl() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.ingest_request.e2e_jsonl");
    let (mut connector, capability) = setup_webhook_ingest_connector().await;
    let (mut logs, jsonl_path) = open_webhook_ingest_e2e_log();
    let fixture_id = "twilio-loopback-hmac-sha1-shared-core-v1";

    let sms_url = "https://example.com/twilio/e2e/sms";
    let sms_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        sms_url,
        &[
            ("Body", "private sms fixture"),
            ("From", "+15551234567"),
            ("MessageSid", "SMe2esms"),
            ("To", "+15559876543"),
        ],
    );
    let valid_sms = invoke_webhook_ingest_request(
        &mut connector,
        &capability,
        json!({
            "method": "POST",
            "url": sms_url,
            "headers": { "X-Twilio-Signature": sms_signature },
            "body": {
                "MessageSid": "SMe2esms",
                "From": "+15551234567",
                "To": "+15559876543",
                "Body": "private sms fixture"
            },
            "auth_token": TWILIO_TEST_HMAC_KEY,
            "inbound_policy": "allowlist",
            "allowed_from": ["+15551234567"],
            "request_region": { "source": "twilio_loopback_jsonl_harness" }
        }),
    )
    .await;
    log_webhook_ingest_e2e(&mut logs, "valid_sms", &valid_sms, fixture_id, &jsonl_path);

    let voice_status_url = "https://example.com/twilio/e2e/voice-status";
    let voice_status_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        voice_status_url,
        &[
            ("CallSid", "CAe2evoice"),
            ("CallStatus", "completed"),
            ("Timestamp", "2026-01-15T10:00:00Z"),
        ],
    );
    let valid_voice_status = invoke_webhook_ingest_request(
        &mut connector,
        &capability,
        json!({
            "method": "POST",
            "url": voice_status_url,
            "headers": { "X-Twilio-Signature": voice_status_signature },
            "body": {
                "CallSid": "CAe2evoice",
                "CallStatus": "completed",
                "Timestamp": "2026-01-15T10:00:00Z"
            },
            "auth_token": TWILIO_TEST_HMAC_KEY,
            "inbound_policy": "allowlist",
            "allowed_from": ["+15551234567"]
        }),
    )
    .await;
    log_webhook_ingest_e2e(
        &mut logs,
        "valid_voice_status",
        &valid_voice_status,
        fixture_id,
        &jsonl_path,
    );

    let invalid_signature = invoke_webhook_ingest_request(
        &mut connector,
        &capability,
        json!({
            "method": "POST",
            "url": "https://example.com/twilio/e2e/invalid-signature",
            "headers": { "X-Twilio-Signature": "not-valid-base64!!!@@@" },
            "body": {
                "MessageSid": "SMe2einvalid",
                "From": "+15551234567",
                "To": "+15559876543",
                "Body": "private invalid fixture"
            },
            "auth_token": TWILIO_TEST_HMAC_KEY,
            "inbound_policy": "open"
        }),
    )
    .await;
    log_webhook_ingest_e2e(
        &mut logs,
        "invalid_signature_denial",
        &invalid_signature,
        fixture_id,
        &jsonl_path,
    );

    let replay_url = "https://example.com/twilio/e2e/replay";
    let replay_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        replay_url,
        &[
            ("Body", "private replay fixture"),
            ("From", "+15551234567"),
            ("MessageSid", "SMe2ereplay"),
            ("To", "+15559876543"),
        ],
    );
    let replay_request = json!({
        "method": "POST",
        "url": replay_url,
        "headers": { "X-Twilio-Signature": replay_signature },
        "body": {
            "MessageSid": "SMe2ereplay",
            "From": "+15551234567",
            "To": "+15559876543",
            "Body": "private replay fixture"
        },
        "auth_token": TWILIO_TEST_HMAC_KEY,
        "inbound_policy": "open"
    });
    let replay_first =
        invoke_webhook_ingest_request(&mut connector, &capability, replay_request.clone()).await;
    let duplicate_replay =
        invoke_webhook_ingest_request(&mut connector, &capability, replay_request).await;
    assert_eq!(replay_first["accepted"], true);
    log_webhook_ingest_e2e(
        &mut logs,
        "duplicate_replay_denial",
        &duplicate_replay,
        fixture_id,
        &jsonl_path,
    );

    let unauthorized_url = "https://example.com/twilio/e2e/unauthorized";
    let unauthorized_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        unauthorized_url,
        &[
            ("Body", "private blocked fixture"),
            ("From", "+15550000000"),
            ("MessageSid", "SMe2eblocked"),
            ("To", "+15559876543"),
        ],
    );
    let unauthorized = invoke_webhook_ingest_request(
        &mut connector,
        &capability,
        json!({
            "method": "POST",
            "url": unauthorized_url,
            "headers": { "X-Twilio-Signature": unauthorized_signature },
            "body": {
                "MessageSid": "SMe2eblocked",
                "From": "+15550000000",
                "To": "+15559876543",
                "Body": "private blocked fixture"
            },
            "auth_token": TWILIO_TEST_HMAC_KEY,
            "inbound_policy": "allowlist",
            "allowed_from": ["+15551234567"]
        }),
    )
    .await;
    log_webhook_ingest_e2e(
        &mut logs,
        "unauthorized_caller",
        &unauthorized,
        fixture_id,
        &jsonl_path,
    );

    let authorized_url = "https://example.com/twilio/e2e/authorized";
    let authorized_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        authorized_url,
        &[
            ("Body", "private allowed fixture"),
            ("From", "+15551234567"),
            ("MessageSid", "SMe2eallowed"),
            ("To", "+15559876543"),
        ],
    );
    let authorized = invoke_webhook_ingest_request(
        &mut connector,
        &capability,
        json!({
            "method": "POST",
            "url": authorized_url,
            "headers": { "X-Twilio-Signature": authorized_signature },
            "body": {
                "MessageSid": "SMe2eallowed",
                "From": "+15551234567",
                "To": "+15559876543",
                "Body": "private allowed fixture"
            },
            "auth_token": TWILIO_TEST_HMAC_KEY,
            "inbound_policy": "allowlist",
            "allowed_from": ["+15551234567"]
        }),
    )
    .await;
    log_webhook_ingest_e2e(
        &mut logs,
        "authorized_caller",
        &authorized,
        fixture_id,
        &jsonl_path,
    );

    let malformed_url = "https://example.com/twilio/e2e/malformed";
    let malformed_signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        malformed_url,
        &[("Unexpected", "value")],
    );
    let malformed = invoke_webhook_ingest_request(
        &mut connector,
        &capability,
        json!({
            "method": "POST",
            "url": malformed_url,
            "headers": { "X-Twilio-Signature": malformed_signature },
            "body": { "Unexpected": "value" },
            "auth_token": TWILIO_TEST_HMAC_KEY,
            "inbound_policy": "open"
        }),
    )
    .await;
    log_webhook_ingest_e2e(
        &mut logs,
        "malformed_payload",
        &malformed,
        fixture_id,
        &jsonl_path,
    );

    let cancelled = invoke_webhook_ingest_request(
        &mut connector,
        &capability,
        json!({
            "method": "POST",
            "url": "https://example.com/twilio/e2e/cancelled",
            "headers": {},
            "body": {},
            "request_region": {
                "source": "twilio_loopback_jsonl_harness",
                "cancelled": true
            }
        }),
    )
    .await;
    log_webhook_ingest_e2e(
        &mut logs,
        "cancellation",
        &cancelled,
        fixture_id,
        &jsonl_path,
    );

    let timed_out = invoke_webhook_ingest_request(
        &mut connector,
        &capability,
        json!({
            "method": "POST",
            "url": "https://example.com/twilio/e2e/timeout",
            "headers": {},
            "body": {},
            "request_region": {
                "source": "twilio_loopback_jsonl_harness",
                "deadline_exceeded": true
            },
            "timeout_ms": 1,
            "concurrency_limit": 1
        }),
    )
    .await;
    log_webhook_ingest_e2e(&mut logs, "timeout", &timed_out, fixture_id, &jsonl_path);

    assert_eq!(valid_sms["accepted"], true);
    assert_eq!(valid_voice_status["accepted"], true);
    assert_eq!(invalid_signature["reason_code"], "invalid_signature");
    assert_eq!(duplicate_replay["reason_code"], "replay_suppressed");
    assert_eq!(unauthorized["reason_code"], "not_allowlisted");
    assert_eq!(authorized["accepted"], true);
    assert_eq!(malformed["reason_code"], "malformed_payload");
    assert_eq!(cancelled["reason_code"], "request_cancelled");
    assert_eq!(timed_out["reason_code"], "request_timeout");

    let jsonl = std::fs::read_to_string(&jsonl_path).expect("read webhook ingest e2e jsonl");
    println!("twilio_webhook_ingest_e2e_jsonl={}", jsonl_path.display());
    for scenario in [
        "valid_sms",
        "valid_voice_status",
        "invalid_signature_denial",
        "duplicate_replay_denial",
        "unauthorized_caller",
        "authorized_caller",
        "malformed_payload",
        "cancellation",
        "timeout",
    ] {
        assert!(jsonl.contains(scenario), "missing scenario {scenario}");
    }
    assert!(!jsonl.contains("+15551234567"));
    assert!(!jsonl.contains("+15559876543"));
    assert!(!jsonl.contains("+15550000000"));
    assert!(!jsonl.contains(TWILIO_TEST_HMAC_KEY));
    assert!(!jsonl.contains("private sms fixture"));
    assert!(!jsonl.contains("private blocked fixture"));
    assert!(!jsonl.contains("private allowed fixture"));
    assert!(!jsonl.contains("private replay fixture"));
    for line in jsonl.lines() {
        let record: serde_json::Value = serde_json::from_str(line).expect("JSONL record parses");
        assert_eq!(record["skip_reason"], serde_json::Value::Null);
        assert_eq!(record["cleanup_result"]["clean_shutdown"], true);
    }
}

/// Validate signature — empty signature.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_empty() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.empty");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.validate_signature",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "params": {"Body": "Hello"},
                "signature": ""
            },
            "capability_token": capability
        }))
        .await
        .expect("validate_signature should succeed (returns valid=false)");

    assert_eq!(result["valid"], false);
    assert!(result["reason"].as_str().unwrap().contains("empty"));
}

/// Validate signature — invalid base64.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_invalid_base64() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.invalid_base64");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.validate_signature",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "params": {"Body": "Hello"},
                "signature": "not-valid-base64!!!@@@"
            },
            "capability_token": capability
        }))
        .await
        .expect("validate_signature should succeed (returns valid=false)");

    assert_eq!(result["valid"], false);
    assert!(result["reason"].as_str().unwrap().contains("base64"));
}

/// Validate signature — valid base64 but no `auth_token`.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_no_auth_token() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.no_auth_token");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.validate_signature",
    );
    let signature = base64::engine::general_purpose::STANDARD.encode([0_u8; 20]);

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "params": {"Body": "Hello"},
                "signature": signature
            },
            "capability_token": capability
        }))
        .await
        .expect("validate_signature should succeed (returns valid=false)");

    assert_eq!(result["valid"], false);
    assert!(result["reason"].as_str().unwrap().contains("auth_token"));
}

/// Validate signature — real HMAC-SHA1 accepts sorted Twilio parameters.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_valid_hmac_sha1() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.valid_hmac_sha1");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.validate_signature",
    );
    let url = "https://example.com/webhook";
    let signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        url,
        &[("From", "+15551234567"), ("Body", "Hello")],
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": url,
                "params": {"Body": "Hello", "From": "+15551234567"},
                "signature": signature,
                "auth_token": TWILIO_TEST_HMAC_KEY
            },
            "capability_token": capability
        }))
        .await
        .expect("validate_signature should succeed");

    assert_eq!(result["valid"], true);
    assert_eq!(result["is_replay"], false);
    assert_eq!(result["verification_url"], url);
    assert!(
        result["verified_request_key"]
            .as_str()
            .unwrap()
            .starts_with("twilio:req:")
    );
    assert_eq!(result["reason"], "Signature is valid");
}

/// Validate signature — arbitrary base64 is rejected even with `auth_token`.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_rejects_wrong_hmac_sha1() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.wrong_hmac_sha1");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.validate_signature",
    );
    let signature = base64::engine::general_purpose::STANDARD.encode([1_u8; 20]);

    let result = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "params": {"Body": "Hello", "From": "+15551234567"},
                "signature": signature,
                "auth_token": TWILIO_TEST_HMAC_KEY
            },
            "capability_token": capability
        }))
        .await
        .expect("validate_signature should return valid=false for bad HMAC");

    assert_eq!(result["valid"], false);
    assert_eq!(result["is_replay"], false);
    assert!(
        result["reason"]
            .as_str()
            .unwrap()
            .contains("Invalid Twilio HMAC-SHA1")
    );
}

/// Validate signature — duplicate signed requests are marked as replay.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_marks_replay() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.replay");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.validate_signature",
    );
    let url = "https://example.com/webhook";
    let signature = twilio_signature(
        TWILIO_TEST_HMAC_KEY,
        url,
        &[("Body", "Hello"), ("From", "+15551234567")],
    );
    let request = json!({
        "operation": "twilio.webhook.validate_signature",
        "input": {
            "url": url,
            "params": {"From": "+15551234567", "Body": "Hello"},
            "signature": signature,
            "auth_token": TWILIO_TEST_HMAC_KEY
        },
        "capability_token": capability
    });

    let first = connector
        .handle_invoke(request.clone())
        .await
        .expect("first validation should succeed");
    let second = connector
        .handle_invoke(request)
        .await
        .expect("duplicate validation should still return structured result");

    assert_eq!(first["valid"], true);
    assert_eq!(first["is_replay"], false);
    assert_eq!(second["valid"], true);
    assert_eq!(second["is_replay"], true);
    assert_eq!(
        first["verified_request_key"], second["verified_request_key"],
        "duplicate request must keep the same replay key"
    );
}

/// Validate signature — URL host allowlist blocks host-header injection mistakes.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_rejects_disallowed_url_host() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.allowed_hosts");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.validate_signature",
    );
    let url = "https://evil.example/webhook";
    let signature = twilio_signature(TWILIO_TEST_HMAC_KEY, url, &[("Body", "Hello")]);

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": url,
                "params": {"Body": "Hello"},
                "signature": signature,
                "auth_token": TWILIO_TEST_HMAC_KEY,
                "allowed_hosts": ["example.com"]
            },
            "capability_token": capability
        }))
        .await
        .expect_err("disallowed host must fail closed");

    assert_invalid_request_contains(&err, "allowed_hosts");
}

/// Validate signature — missing required params field.
#[fcp_async_core::runtime::test]
async fn webhook_validate_signature_missing_params() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.validate_signature.missing_params");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.validate_signature"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.validate_signature",
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.validate_signature",
            "input": {
                "url": "https://example.com/webhook",
                "signature": "dGVzdA=="
            },
            "capability_token": capability
        }))
        .await
        .expect_err("should fail without params");

    assert_invalid_request_contains(&err, "params");
}

/// Parse SMS event — missing body field.
#[fcp_async_core::runtime::test]
async fn webhook_parse_sms_event_missing_body() {
    let _ctx = AsyncTestContext::for_scenario("twilio.webhook.parse_sms_event.missing_body");
    let mock_server = MockServer::start().await;

    let mut connector = TwilioConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["twilio.webhook.parse_sms_event"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "twilio.webhook.parse_sms_event",
    );

    let err = connector
        .handle_invoke(json!({
            "operation": "twilio.webhook.parse_sms_event",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect_err("should fail without body");

    assert_invalid_request_contains(&err, "body");
}
