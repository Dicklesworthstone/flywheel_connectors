#![allow(
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::unwrap_used
)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::str::FromStr as _;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, HealthState, InstanceId, InvokeRequest, OperationId, RequestId,
    ShutdownRequest, SimulateRequest, SubscribeRequest, UnsubscribeRequest, ZoneId,
};
use fcp_signal::SignalConnector;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CONNECTOR_ID: &str = "fcp.signal";
const ACCOUNT: &str = "+15551234567";
const RECIPIENT: &str = "+15559876543";
const SEALED_SENDER_UUID: &str = "uuid-sealed-sender-fixture";
const PROFILE_NAME: &str = "Confidential Contact";
const GROUP_ID: &str = "group-fixture-1";
const DENIED_GROUP_ID: &str = "group-denied";
const GROUP_NAME: &str = "Private Group";
const MESSAGE_BODY: &str = "sensitive Signal message body";
const SAFETY_NUMBER: &str = "12345 67890";

const OP_SEND_MESSAGE: &str = "signal.send_message";
const OP_RECEIVE_MESSAGES: &str = "signal.receive_messages";
const OP_LIST_GROUPS: &str = "signal.list_groups";
const OP_GET_GROUP: &str = "signal.get_group";
const OP_GET_IDENTITY: &str = "signal.get_identity";
const OP_TRUST_IDENTITY: &str = "signal.trust_identity";

const CAP_SEND: &str = "signal.send";
const CAP_READ: &str = "signal.read";
const CAP_ADMIN: &str = "signal.admin";

const EVENT_MESSAGE_RECEIVED: &str = "signal.message.received";
const EVENT_REACTION_RECEIVED: &str = "signal.reaction.received";
const EVENT_TYPING_RECEIVED: &str = "signal.typing.received";
const EVENT_POLICY_DENIED: &str = "signal.policy.denied";

#[fcp_async_core::runtime::test]
async fn lifecycle_loopback_send_receive_health_shutdown_and_jsonl_logging() {
    let server = MockServer::start().await;
    mount_health(&server).await;
    Mock::given(method("POST"))
        .and(path("/v2/send"))
        .and(body_partial_json(json!({
            "number": ACCOUNT,
            "recipients": [RECIPIENT],
            "message": MESSAGE_BODY,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "timestamp": 1_700_000_002_000_u64
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/receive/%2B15551234567"))
        .and(query_param("timeout", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "sourceNumber": RECIPIENT,
                "sourceName": PROFILE_NAME,
                "timestamp": 1_700_000_003_000_u64,
                "dataMessage": {
                    "timestamp": 1_700_000_003_000_u64,
                    "message": MESSAGE_BODY,
                    "groupInfo": {
                        "id": GROUP_ID,
                        "name": GROUP_NAME,
                        "members": [ACCOUNT, RECIPIENT],
                        "admins": [ACCOUNT]
                    },
                    "attachments": []
                }
            }
        ])))
        .expect(1)
        .mount(&server)
        .await;
    mount_group_list(&server).await;

    let instance_id = make_instance_id("lifecycle");
    let (mut connector, signing_key) =
        configure_and_handshake(loopback_config(&server.uri()), &instance_id).await;

    assert_eq!(connector.id().as_str(), CONNECTOR_ID);
    assert!(matches!(
        connector.health().await.status,
        HealthState::Ready
    ));
    assert!(connector.doctor().passed);

    let started_at = Instant::now();
    let send_output = connector
        .invoke(invoke_request(
            connector.id(),
            OP_SEND_MESSAGE,
            &ZoneId::work(),
            json!({
                "recipients": [RECIPIENT],
                "message": MESSAGE_BODY
            }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_SEND_MESSAGE,
                CAP_SEND,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("send-message invoke should succeed against loopback")
        .result
        .expect("send-message invoke should include output");
    assert_eq!(send_output["timestamp"], 1_700_000_002_000_u64);

    let receive_output = connector
        .invoke(invoke_request(
            connector.id(),
            OP_RECEIVE_MESSAGES,
            &ZoneId::work(),
            json!({ "timeout_seconds": 1 }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_RECEIVE_MESSAGES,
                CAP_READ,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("receive-messages invoke should succeed against loopback")
        .result
        .expect("receive-messages invoke should include output");
    assert_eq!(receive_output["count"], 1);
    assert_eq!(receive_output["receive_cursor"], "1700000003000");
    assert_eq!(receive_output["cached_group_count"], 1);

    let simulation = connector
        .simulate(SimulateRequest::new(
            connector.id().clone(),
            OperationId::from_static(OP_SEND_MESSAGE),
            ZoneId::work(),
            json!({
                "recipients": [RECIPIENT],
                "message": MESSAGE_BODY
            }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_SEND_MESSAGE,
                CAP_SEND,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("simulation should return an allowed response");
    assert!(simulation.would_succeed);

    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 1_000,
            drain: true,
            reason: Some("signal loopback lifecycle test complete".into()),
        })
        .await
        .expect("shutdown should drain cleanly");

    emit_proof_log(&ProofLog {
        event: "lifecycle_loopback",
        operation: OP_RECEIVE_MESSAGES,
        capability: CAP_READ,
        zone: ZoneId::work().as_str(),
        instance_id: instance_id.as_str(),
        fixture_id: "signal-lifecycle-loopback-v1",
        stream_id_hash: Some(&hash_pii(GROUP_ID)),
        event_kind: "poll_receive",
        lifecycle_phase: "configure-handshake-send-receive-simulate-health-shutdown",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        audit_receipt_id: "not-issued:connector-local-loopback",
        shutdown_drain_result: "drained",
        cleanup_result: "wiremock-server-dropped",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn sse_subscription_emits_message_reaction_typing_policy_and_redaction_edges() {
    let body = signal_sse_body(&[
        (
            "evt-message",
            json!({
                "envelope": {
                    "sourceNumber": RECIPIENT,
                    "sourceName": PROFILE_NAME,
                    "timestamp": 1_700_000_010_000_u64,
                    "dataMessage": {
                        "timestamp": 1_700_000_010_000_u64,
                        "message": MESSAGE_BODY,
                        "attachments": []
                    }
                }
            }),
        ),
        (
            "evt-reaction",
            json!({
                "envelope": {
                    "sourceUuid": SEALED_SENDER_UUID,
                    "timestamp": 1_700_000_010_100_u64,
                    "reactionMessage": {
                        "emoji": "+1",
                        "targetAuthor": ACCOUNT,
                        "targetSentTimestamp": 1_700_000_010_000_u64,
                        "isRemove": false
                    }
                }
            }),
        ),
        (
            "evt-typing",
            json!({
                "envelope": {
                    "sourceNumber": RECIPIENT,
                    "timestamp": 1_700_000_010_200_u64,
                    "typingMessage": {
                        "action": "STARTED",
                        "timestamp": 1_700_000_010_200_u64
                    }
                }
            }),
        ),
        (
            "evt-denied",
            json!({
                "envelope": {
                    "sourceNumber": RECIPIENT,
                    "timestamp": 1_700_000_010_300_u64,
                    "dataMessage": {
                        "message": MESSAGE_BODY,
                        "groupInfo": {
                            "id": DENIED_GROUP_ID,
                            "name": GROUP_NAME,
                            "members": [RECIPIENT],
                            "admins": []
                        },
                        "attachments": []
                    }
                }
            }),
        ),
    ]);
    let (daemon_url, server) = spawn_signal_sse_server(body);

    let instance_id = make_instance_id("sse");
    let (connector, signing_key) =
        configure_and_handshake(sse_config(&daemon_url), &instance_id).await;
    let mut event_rx = connector.subscribe_events_for_test();

    let started_at = Instant::now();
    let response = connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("sub_signal_sse"),
            topics: vec!["*".into()],
            since: None,
            max_events_per_sec: Some(100),
            batch_ms: Some(5),
            window_size: Some(64),
            capability_token: Some(valid_token(
                &signing_key,
                &instance_id,
                OP_RECEIVE_MESSAGES,
                CAP_READ,
                &ZoneId::work(),
            )),
        })
        .await
        .expect("subscribe should confirm Signal SSE topics");
    assert_eq!(response.result.confirmed_topics.len(), 5);
    assert!(!response.result.replay_supported);
    assert_eq!(response.result.buffer.expect("buffer info").min_events, 100);

    let mut observed = Vec::new();
    for _ in 0..4 {
        let event = fcp_async_core::time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("SSE event timeout")
            .expect("broadcast event")
            .expect("Signal event");
        observed.push(event);
    }

    let topics = observed
        .iter()
        .map(|event| event.topic.as_str())
        .collect::<Vec<_>>();
    assert!(topics.contains(&EVENT_MESSAGE_RECEIVED));
    assert!(topics.contains(&EVENT_REACTION_RECEIVED));
    assert!(topics.contains(&EVENT_TYPING_RECEIVED));
    assert!(topics.contains(&EVENT_POLICY_DENIED));

    let message_event = observed
        .iter()
        .find(|event| event.topic == EVENT_MESSAGE_RECEIVED)
        .expect("message event should be emitted");
    assert_eq!(message_event.cursor, "evt-message");
    assert_eq!(message_event.data.principal.id, RECIPIENT);
    assert_eq!(
        message_event.data.principal.display.as_deref(),
        Some(PROFILE_NAME)
    );
    assert_eq!(message_event.data.payload["body"], MESSAGE_BODY);

    let reaction_event = observed
        .iter()
        .find(|event| event.topic == EVENT_REACTION_RECEIVED)
        .expect("sealed-sender reaction event should be emitted");
    assert_eq!(reaction_event.data.principal.id, SEALED_SENDER_UUID);
    assert_eq!(reaction_event.data.payload["reaction"]["emoji"], "+1");

    let policy_denial = observed
        .iter()
        .find(|event| event.topic == EVENT_POLICY_DENIED)
        .expect("group policy denial should be emitted");
    assert_eq!(policy_denial.data.payload["reason"], "group_not_allowed");
    assert_eq!(policy_denial.cursor, "evt-denied");

    connector
        .unsubscribe(UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("unsub_signal_sse"),
            topics: vec!["*".into()],
            capability_token: None,
        })
        .await
        .expect("unsubscribe should stop the stream task");
    server
        .join()
        .expect("Signal SSE server thread should finish");

    emit_proof_log(&ProofLog {
        event: "sse_loopback",
        operation: OP_RECEIVE_MESSAGES,
        capability: CAP_READ,
        zone: ZoneId::work().as_str(),
        instance_id: instance_id.as_str(),
        fixture_id: "signal-sse-message-reaction-typing-policy-v1",
        stream_id_hash: Some(&hash_pii("evt-message,evt-reaction,evt-typing,evt-denied")),
        event_kind: "message,reaction,typing,policy_denied,sealed_sender_uuid",
        lifecycle_phase: "configure-handshake-subscribe-sse-unsubscribe",
        latency_ms: elapsed_ms(started_at),
        result: "ok",
        error_code: None,
        audit_receipt_id: "not-issued:connector-local-sse-loopback",
        shutdown_drain_result: "unsubscribe-aborted-supervised-stream",
        cleanup_result: "sse-thread-joined",
        skip_reason: None,
    });
}

#[fcp_async_core::runtime::test]
async fn capability_zone_instance_and_missing_instance_denials_are_explicit() {
    let instance_id = make_instance_id("denials");
    let (connector, signing_key) =
        configure_and_handshake(loopback_config("http://127.0.0.1:1"), &instance_id).await;

    let wrong_zone = connector
        .invoke(invoke_request(
            connector.id(),
            OP_LIST_GROUPS,
            &ZoneId::work(),
            json!({}),
            valid_token(
                &signing_key,
                &instance_id,
                OP_LIST_GROUPS,
                CAP_READ,
                &ZoneId::private(),
            ),
        ))
        .await
        .expect_err("wrong-zone token should fail before network access");
    assert!(matches!(
        wrong_zone,
        FcpError::ZoneViolation {
            message,
            ..
        } if message.contains("Token audience mismatch") || message.contains("Token zone mismatch")
    ));

    let wrong_instance = connector
        .invoke(invoke_request(
            connector.id(),
            OP_LIST_GROUPS,
            &ZoneId::work(),
            json!({}),
            valid_token(
                &signing_key,
                &make_instance_id("other"),
                OP_LIST_GROUPS,
                CAP_READ,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect_err("wrong-instance token should fail before network access");
    assert!(matches!(
        wrong_instance,
        FcpError::ZoneViolation {
            message,
            ..
        } if message.contains("Token instance mismatch")
    ));

    let missing_instance = connector
        .invoke(invoke_request(
            connector.id(),
            OP_LIST_GROUPS,
            &ZoneId::work(),
            json!({}),
            token_without_instance(&signing_key, OP_LIST_GROUPS, CAP_READ, &ZoneId::work()),
        ))
        .await
        .expect_err("missing-instance token should fail before network access");
    assert!(matches!(
        missing_instance,
        FcpError::MissingField { field } if field.contains("instance_id")
    ));
}

#[fcp_async_core::runtime::test]
async fn malformed_unauthorized_rate_limited_provider_network_and_timeout_errors_are_mapped() {
    let mut malformed_connector = SignalConnector::new();
    let malformed = malformed_connector
        .configure(json!({
            "daemon_url": "http://127.0.0.1:1",
            "phone_number": "not-a-phone-number"
        }))
        .await
        .expect_err("invalid phone number should be rejected during configure");
    assert!(matches!(
        malformed,
        FcpError::InvalidRequest { code: 1001, .. }
    ));

    let unauthorized = invoke_send_against_server(
        ResponseTemplate::new(401).set_body_string("unauthorized"),
        "unauthorized",
    )
    .await
    .expect_err("401 should map to unauthorized");
    assert!(matches!(
        unauthorized,
        FcpError::Unauthorized { code: 2001, .. }
    ));

    let rate_limited = invoke_send_against_server(
        ResponseTemplate::new(429)
            .insert_header("retry-after", "2")
            .set_body_string("too many requests"),
        "rate_limited",
    )
    .await
    .expect_err("429 should map to rate limited");
    assert!(matches!(
        rate_limited,
        FcpError::RateLimited {
            retry_after_ms: 2_000,
            ..
        }
    ));

    let provider_error = invoke_send_against_server(
        ResponseTemplate::new(500).set_body_string("bridge unavailable"),
        "provider",
    )
    .await
    .expect_err("500 should surface as a provider error");
    assert!(matches!(
        provider_error,
        FcpError::External {
            service,
            status_code: Some(500),
            retryable: true,
            ..
        } if service == "signal"
    ));

    let network_instance = make_instance_id("network");
    let (network_connector, network_key) =
        configure_and_handshake(loopback_config("http://127.0.0.1:1"), &network_instance).await;
    let network_error = network_connector
        .invoke(invoke_request(
            network_connector.id(),
            OP_SEND_MESSAGE,
            &ZoneId::work(),
            json!({
                "recipients": [RECIPIENT],
                "message": MESSAGE_BODY
            }),
            valid_token(
                &network_key,
                &network_instance,
                OP_SEND_MESSAGE,
                CAP_SEND,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect_err("refused loopback daemon should surface as external network error");
    assert!(matches!(
        network_error,
        FcpError::External {
            service,
            retryable: false,
            ..
        } if service == "signal"
    ));

    let timeout_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/about"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(250)))
        .expect(1)
        .mount(&timeout_server)
        .await;
    let timeout_instance = make_instance_id("timeout");
    let (timeout_connector, timeout_key) =
        configure_and_handshake(timeout_config(&timeout_server.uri()), &timeout_instance).await;
    let timeout_error = timeout_connector
        .invoke(invoke_request(
            timeout_connector.id(),
            OP_SEND_MESSAGE,
            &ZoneId::work(),
            json!({
                "recipients": [RECIPIENT],
                "message": MESSAGE_BODY
            }),
            valid_token(
                &timeout_key,
                &timeout_instance,
                OP_SEND_MESSAGE,
                CAP_SEND,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect_err("delayed loopback health check should hit request timeout");
    assert!(matches!(
        timeout_error,
        FcpError::External {
            service,
            retryable: false,
            ..
        } if service == "signal"
    ));
}

#[fcp_async_core::runtime::test]
async fn admin_identity_trust_get_group_and_attachment_boundaries_are_loopback_safe() {
    let server = MockServer::start().await;
    mount_health(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1/groups/%2B15551234567"))
        .and(query_param("id", GROUP_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(group_fixture()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/identities/%2B15551234567/%2B15559876543"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "number": RECIPIENT,
            "uuid": SEALED_SENDER_UUID,
            "trust_level": "TRUSTED_VERIFIED"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/v1/identities/%2B15551234567/trust/%2B15559876543"))
        .and(body_partial_json(json!({
            "verified_safety_number": SAFETY_NUMBER
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let instance_id = make_instance_id("admin");
    let (connector, signing_key) =
        configure_and_handshake(loopback_config(&server.uri()), &instance_id).await;

    let group = connector
        .invoke(invoke_request(
            connector.id(),
            OP_GET_GROUP,
            &ZoneId::work(),
            json!({ "group_id": GROUP_ID }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_GET_GROUP,
                CAP_READ,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("get_group should use loopback daemon")
        .result
        .expect("get_group should return payload");
    assert_eq!(group["id"], GROUP_ID);
    assert_eq!(group["admins"][0], ACCOUNT);

    let identity = connector
        .invoke(invoke_request(
            connector.id(),
            OP_GET_IDENTITY,
            &ZoneId::work(),
            json!({ "number": RECIPIENT }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_GET_IDENTITY,
                CAP_READ,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("get_identity should use loopback daemon")
        .result
        .expect("get_identity should return payload");
    assert_eq!(identity["uuid"], SEALED_SENDER_UUID);
    assert_eq!(identity["trust_level"], "TRUSTED_VERIFIED");

    let trust = connector
        .invoke(invoke_request(
            connector.id(),
            OP_TRUST_IDENTITY,
            &ZoneId::work(),
            json!({
                "number": RECIPIENT,
                "verified_safety_number": SAFETY_NUMBER
            }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_TRUST_IDENTITY,
                CAP_ADMIN,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect("trust_identity should use loopback daemon")
        .result
        .expect("trust_identity should return payload");
    assert_eq!(trust["status"], "trusted");

    let oversized_attachment = base64::engine::general_purpose::STANDARD.encode(b"too-large");
    let blocked = connector
        .invoke(invoke_request(
            connector.id(),
            OP_SEND_MESSAGE,
            &ZoneId::work(),
            json!({
                "recipients": [RECIPIENT],
                "message": MESSAGE_BODY,
                "attachments": [oversized_attachment],
            }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_SEND_MESSAGE,
                CAP_SEND,
                &ZoneId::work(),
            ),
        ))
        .await
        .expect_err("oversized attachment should fail before upload");
    assert!(matches!(
        blocked,
        FcpError::InvalidRequest { code: 1006, .. }
    ));
}

async fn configure_and_handshake(
    config: Value,
    instance_id: &InstanceId,
) -> (SignalConnector, Ed25519SigningKey) {
    let mut connector = SignalConnector::new();
    assert!(
        !matches!(connector.health().await.status, HealthState::Ready),
        "connector must not start ready before configure"
    );
    connector
        .configure(config)
        .await
        .expect("Signal connector should accept deterministic test config");
    let signing_key = Ed25519SigningKey::generate();
    let response = connector
        .handshake(handshake_request(&signing_key, instance_id))
        .await
        .expect("handshake should accept deterministic requested instance id");
    assert_eq!(response.status, "accepted");
    assert!(
        response
            .capabilities_granted
            .iter()
            .any(|grant| grant.capability.as_str() == CAP_ADMIN)
    );
    (connector, signing_key)
}

fn handshake_request(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: signing_key.verifying_key().to_bytes(),
        nonce: [9; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_SEND),
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_ADMIN),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn invoke_request(
    connector_id: &ConnectorId,
    operation: &'static str,
    zone_id: &ZoneId,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(format!("req_{}", operation.replace('.', "_"))),
        connector_id: connector_id.clone(),
        operation: OperationId::from_static(operation),
        zone_id: zone_id.clone(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: Some(format!("idem_{}", operation.replace('.', "_"))),
        lease_seq: None,
        deadline_ms: Some(5_000),
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &'static str,
    capability: &'static str,
    zone_id: &ZoneId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should serialize to CBOR");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone_id.as_str())
        .principal("user:signal-test")
        .operations(&[operation])
        .issuer("node:signal-test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

fn token_without_instance(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    zone_id: &ZoneId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should serialize to CBOR");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id(zone_id.as_str())
        .principal("user:signal-test")
        .operations(&[operation])
        .issuer("node:signal-test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

async fn invoke_send_against_server(
    response: ResponseTemplate,
    instance_suffix: &str,
) -> Result<fcp_prelude::InvokeResponse, FcpError> {
    let server = MockServer::start().await;
    mount_health(&server).await;
    Mock::given(method("POST"))
        .and(path("/v2/send"))
        .respond_with(response)
        .expect(1)
        .mount(&server)
        .await;

    let instance_id = make_instance_id(instance_suffix);
    let (connector, signing_key) =
        configure_and_handshake(loopback_config(&server.uri()), &instance_id).await;
    connector
        .invoke(invoke_request(
            connector.id(),
            OP_SEND_MESSAGE,
            &ZoneId::work(),
            json!({
                "recipients": [RECIPIENT],
                "message": MESSAGE_BODY
            }),
            valid_token(
                &signing_key,
                &instance_id,
                OP_SEND_MESSAGE,
                CAP_SEND,
                &ZoneId::work(),
            ),
        ))
        .await
}

async fn mount_health(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/about"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "versions": ["v1", "v2"],
            "build": "signal-test"
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_group_list(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/groups/%2B15551234567"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([group_fixture()])))
        .expect(1)
        .mount(server)
        .await;
}

fn loopback_config(server_url: &str) -> Value {
    json!({
        "daemon_url": server_url,
        "phone_number": ACCOUNT,
        "request_timeout_ms": 2_000,
        "receive_timeout_ms": 1_000,
        "poll_interval_ms": 1_000,
        "health_check_interval_ms": 30_000,
        "max_reconnect_delay_ms": 1_000,
        "max_attachment_bytes": 4,
        "retry": {
            "max_retries": 0,
            "initial_delay_ms": 0,
            "max_delay_ms": 0,
            "jitter_enabled": false
        }
    })
}

fn timeout_config(server_url: &str) -> Value {
    let mut config = loopback_config(server_url);
    config["request_timeout_ms"] = json!(25_u64);
    config
}

fn sse_config(server_url: &str) -> Value {
    let mut config = loopback_config(server_url);
    config["streaming"] = json!({
        "enabled": true,
        "stale_after_ms": 1_000,
        "reconnect_initial_ms": 100,
        "reconnect_max_ms": 1_000,
        "min_buffer_events": 100
    });
    config["inbound_policy"] = json!({
        "dm_policy": "open",
        "group_policy": "allowlist",
        "group_allow_from": [GROUP_ID],
        "emit_reactions": true,
        "emit_typing": true,
        "emit_read_receipts": true,
        "suppress_self_echo": true
    });
    config
}

fn group_fixture() -> Value {
    json!({
        "id": GROUP_ID,
        "name": GROUP_NAME,
        "members": [ACCOUNT, RECIPIENT],
        "admins": [ACCOUNT]
    })
}

fn signal_sse_body(events: &[(&str, Value)]) -> String {
    let mut body = String::new();
    for (event_id, payload) in events {
        let payload = serde_json::to_string(payload).expect("SSE payload should serialize");
        write!(
            &mut body,
            "id: {event_id}\nevent: receive\ndata: {payload}\n\n"
        )
        .expect("writing to string should not fail");
    }
    body
}

fn spawn_signal_sse_server(body: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind Signal SSE listener");
    let address = listener.local_addr().expect("listener address");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept Signal SSE client");
        let mut request = Vec::new();
        let mut buf = [0_u8; 512];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buf).expect("read Signal SSE request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..read]);
        }
        let request = String::from_utf8_lossy(&request);
        assert!(
            request.contains("GET /api/v1/events?account=%2B15551234567 HTTP/1.1"),
            "unexpected Signal SSE request: {request:?}",
        );

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/event-stream\r\n\
             Cache-Control: no-cache\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        stream
            .write_all(response.as_bytes())
            .expect("write Signal SSE response");
        stream.flush().expect("flush Signal SSE response");
    });

    (format!("http://{address}"), handle)
}

fn make_instance_id(suffix: &str) -> InstanceId {
    InstanceId::from_str(&format!("inst_signal_{suffix}"))
        .expect("test instance id should be canonical")
}

fn elapsed_ms(started_at: Instant) -> u128 {
    started_at.elapsed().as_millis()
}

fn hash_pii(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::from("sha256:");
    for byte in digest.iter().take(8) {
        write!(&mut out, "{byte:02x}").expect("writing to string should not fail");
    }
    out
}

struct ProofLog<'a> {
    event: &'a str,
    operation: &'a str,
    capability: &'a str,
    zone: &'a str,
    instance_id: &'a str,
    fixture_id: &'a str,
    stream_id_hash: Option<&'a str>,
    event_kind: &'a str,
    lifecycle_phase: &'a str,
    latency_ms: u128,
    result: &'a str,
    error_code: Option<&'a str>,
    audit_receipt_id: &'a str,
    shutdown_drain_result: &'a str,
    cleanup_result: &'a str,
    skip_reason: Option<&'a str>,
}

fn emit_proof_log(proof: &ProofLog<'_>) {
    let line = serde_json::to_string(&json!({
        "command_line": "cargo test -p fcp-signal --tests -- --nocapture",
        "git_revision": git_revision(),
        "connector_id": CONNECTOR_ID,
        "event": proof.event,
        "op_id": proof.operation,
        "capability": proof.capability,
        "zone": proof.zone,
        "instance_id": proof.instance_id,
        "fixture_id": proof.fixture_id,
        "stream_id_hash": proof.stream_id_hash,
        "event_kind": proof.event_kind,
        "lifecycle_phase": proof.lifecycle_phase,
        "latency_ms": proof.latency_ms,
        "result": proof.result,
        "error_code": proof.error_code,
        "audit_receipt_id": proof.audit_receipt_id,
        "shutdown_drain_result": proof.shutdown_drain_result,
        "cleanup_result": proof.cleanup_result,
        "skip_reason": proof.skip_reason,
        "pii_redaction": {
            "phone_numbers": "hashed_or_omitted",
            "message_bodies": "omitted",
            "profile_names": "omitted",
            "attachment_bytes": "omitted",
            "credentials": "omitted",
            "local_paths": "omitted",
            "transcripts": "omitted"
        }
    }))
    .expect("proof log should serialize");
    assert_redacted(&line);
    println!("SIGNAL_E2E_JSONL {line}");
}

fn assert_redacted(line: &str) {
    for forbidden in [
        ACCOUNT,
        RECIPIENT,
        SEALED_SENDER_UUID,
        PROFILE_NAME,
        GROUP_ID,
        DENIED_GROUP_ID,
        GROUP_NAME,
        MESSAGE_BODY,
        SAFETY_NUMBER,
        "/Users/",
        "/tmp/",
    ] {
        assert!(
            !line.contains(forbidden),
            "proof log leaked forbidden value: {forbidden}"
        );
    }
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_string(), |value| value.trim().to_string())
}

// ── Replay safety on retry (br-kxd3e) ────────────────────────────────
//
// signal-cli's REST daemon has no idempotency key, so a 5xx retry delivers the
// message a second time. The assertion is the REQUEST COUNT — "it still
// errors" would pass with the bug present.

fn replay_test_client(server: &MockServer) -> fcp_signal::client::SignalClient {
    let config: fcp_signal::types::SignalConfig = serde_json::from_value(json!({
        "daemon_url": server.uri(),
        "phone_number": ACCOUNT,
        "retry": {
            "max_retries": 3,
            "initial_delay_ms": 1,
            "max_delay_ms": 5,
            "jitter_enabled": false
        }
    }))
    .expect("signal config should deserialize");
    fcp_signal::client::SignalClient::new(&config).expect("client should build")
}

fn replay_test_runtime() -> fcp_sdk::ConnectorRuntime {
    fcp_sdk::ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default())
}

fn replay_test_send_request() -> fcp_signal::types::SendMessageRequest {
    fcp_signal::types::SendMessageRequest {
        recipients: vec![RECIPIENT.to_string()],
        message: MESSAGE_BODY.to_string(),
        attachments: Vec::new(),
        quote_timestamp: None,
    }
}

#[fcp_async_core::runtime::test]
async fn send_message_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/send"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": "daemon temporarily unavailable"
        })))
        .mount(&server)
        .await;

    let result = replay_test_client(&server)
        .send_message(&replay_test_runtime(), &replay_test_send_request())
        .await;
    assert!(result.is_err());

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a 503 means the daemon received the send — retrying delivers the \
         message a SECOND time, and signal-cli offers no dedup key"
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_still_retries_a_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/send"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/send"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "timestamp": 1_700_000_002_000_u64
        })))
        .mount(&server)
        .await;

    replay_test_client(&server)
        .send_message(&replay_test_runtime(), &replay_test_send_request())
        .await
        .expect("a rate-limited send was refused without delivering anything");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "429 means the message was NOT sent, so backoff must be preserved"
    );
}
