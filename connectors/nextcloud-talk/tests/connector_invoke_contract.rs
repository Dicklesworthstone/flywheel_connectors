use std::sync::Arc;
use std::time::Instant;

use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_nextcloud_talk::NextcloudTalkConnector;
use fcp_prelude::{
    CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError, HandshakeRequest,
    InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, SimulateRequest, ZoneId,
};
use fcp_sdk::prelude::{AgentId, ChannelId, ClaimKey, InMemoryThreadOwnershipChecker, ThreadId};
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CAP_READ: &str = "nextcloud_talk.read";
const CAP_WRITE: &str = "nextcloud_talk.write";
const CAP_MANAGE: &str = "nextcloud_talk.manage";
const CAP_WEBHOOK: &str = "nextcloud_talk.webhook";
const OP_HEALTH: &str = "nextcloud_talk.health";
const OP_LIST_CONVERSATIONS: &str = "nextcloud_talk.list_conversations";
const OP_GET_MESSAGES: &str = "nextcloud_talk.get_messages";
const OP_POLL_CONVERSATION_EVENTS: &str = "nextcloud_talk.poll_conversation_events";
const OP_SEND_MESSAGE: &str = "nextcloud_talk.send_message";
const OP_DELETE_MESSAGE: &str = "nextcloud_talk.delete_message";

fn test_instance_id() -> InstanceId {
    "inst_nextcloud_talk_invoke_contract"
        .parse()
        .expect("canonical test instance id")
}

fn base_handshake(instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key: [0u8; 32],
        nonce: [0u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_WRITE),
            CapabilityId::from_static(CAP_MANAGE),
            CapabilityId::from_static(CAP_WEBHOOK),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn base_invoke(
    connector_id: &ConnectorId,
    operation: &'static str,
    capability_token: CapabilityToken,
    input: serde_json::Value,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("req_nextcloud_talk"),
        connector_id: connector_id.clone(),
        operation: OperationId::from_static(operation),
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
        approval_tokens: Vec::new(),
    }
}

fn base_simulate(
    connector_id: &ConnectorId,
    operation: &'static str,
    capability_token: CapabilityToken,
) -> SimulateRequest {
    SimulateRequest {
        r#type: "simulate".into(),
        id: RequestId::new("sim_nextcloud_talk"),
        connector_id: connector_id.clone(),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input: json!({}),
        capability_token,
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    capability: &'static str,
    operations: &[&'static str],
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = chrono::Utc::now();
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + chrono::Duration::hours(1))
        .target_instance(instance_id.as_str())
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

async fn handshake_connector(
    connector: &mut NextcloudTalkConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
) {
    let verifying_key = signing_key.verifying_key();
    let mut handshake = base_handshake(instance_id);
    handshake.host_public_key = verifying_key.to_bytes();
    connector.handshake(handshake).await.expect("handshake");
}

#[fcp_async_core::runtime::test]
async fn simulate_checks_bound_capability_token() {
    let server = MockServer::start().await;
    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "bearer_token",
                "access_token": "oauth-test-material"
            },
            "network": { "allow_private_networks": true }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let grant = generate_valid_token(&signing_key, CAP_READ, &[OP_SEND_MESSAGE], &instance_id);
    let response = connector
        .simulate(base_simulate(connector.id(), OP_SEND_MESSAGE, grant))
        .await
        .expect("simulate");

    assert!(!response.would_succeed);
    assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));
    assert!(response.missing_capabilities.is_empty());
}

#[fcp_async_core::runtime::test]
async fn invoke_health_uses_capabilities_probe() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ocs/v1.php/cloud/capabilities"))
        .and(query_param("format", "json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ocs": {
                "meta": {
                    "status": "ok",
                    "statuscode": 100,
                    "message": "OK"
                },
                "data": {
                    "version": {
                        "major": 29,
                        "minor": 0,
                        "micro": 0,
                        "string": "29.0.0"
                    },
                    "capabilities": {
                        "spreed": {
                            "features": ["chat-read-marker", "reactions"],
                            "config": {
                                "chat": {
                                    "max-length": 32000
                                }
                            }
                        }
                    }
                }
            }
        })))
        .mount(&server)
        .await;

    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "bearer_token",
                "access_token": "oidc"
            },
            "network": { "allow_private_networks": true }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let grant = generate_valid_token(&signing_key, CAP_READ, &[OP_HEALTH], &instance_id);
    let response = connector
        .invoke(base_invoke(connector.id(), OP_HEALTH, grant, json!({})))
        .await
        .expect("invoke");

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["version"], "29.0.0");
    assert_eq!(result["has_talk"], true);
    assert_eq!(result["features"][0], "chat-read-marker");
}

#[fcp_async_core::runtime::test]
async fn invoke_list_conversations_returns_conversations() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ocs/v2.php/apps/spreed/api/v4/room"))
        .and(query_param("format", "json"))
        .and(query_param("includeStatus", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ocs": {
                "meta": {
                    "status": "ok",
                    "statuscode": 100,
                    "message": "OK"
                },
                "data": [
                    {
                        "token": "room123",
                        "type": 2,
                        "displayName": "Engineering",
                        "unreadMessages": 3
                    }
                ]
            }
        })))
        .mount(&server)
        .await;

    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "app_password",
                "username": "alice",
                "app_password": "app-material"
            },
            "network": { "allow_private_networks": true }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let grant = generate_valid_token(
        &signing_key,
        CAP_READ,
        &[OP_LIST_CONVERSATIONS],
        &instance_id,
    );
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_LIST_CONVERSATIONS,
            grant,
            json!({ "include_status": true }),
        ))
        .await
        .expect("invoke");

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["conversations"][0]["token"], "room123");
    assert_eq!(result["conversations"][0]["displayName"], "Engineering");
}

#[fcp_async_core::runtime::test]
async fn invoke_send_message_returns_chat_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
        .and(query_param("format", "json"))
        .and(body_string_contains("message=hello+world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ocs": {
                "meta": {
                    "status": "ok",
                    "statuscode": 100,
                    "message": "OK"
                },
                "data": {
                    "id": 42,
                    "token": "room123",
                    "actorType": "users",
                    "actorId": "alice",
                    "actorDisplayName": "Alice",
                    "timestamp": 1_710_000_000u64,
                    "systemMessage": "",
                    "messageType": "comment",
                    "message": "hello world",
                    "messageParameters": {},
                    "reactions": {},
                    "reactionsSelf": []
                }
            }
        })))
        .mount(&server)
        .await;

    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "app_password",
                "username": "alice",
                "app_password": "app-material"
            },
            "network": { "allow_private_networks": true }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let grant = generate_valid_token(&signing_key, CAP_WRITE, &[OP_SEND_MESSAGE], &instance_id);
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_SEND_MESSAGE,
            grant,
            json!({
                "token": "room123",
                "message": "hello world",
                "silent": true
            }),
        ))
        .await
        .expect("invoke");

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["message"]["id"], 42);
    assert_eq!(result["message"]["message"], "hello world");
    let coordination = result["coordination"]
        .as_array()
        .expect("coordination audit records");
    assert_eq!(coordination[0]["event"], "claim_attempt");
    assert_eq!(coordination[1]["event"], "claim_outcome");
    assert_eq!(coordination[1]["outcome"], "granted");
    assert_eq!(coordination[2]["event"], "send_executed");
}

#[fcp_async_core::runtime::test]
async fn invoke_send_message_denies_duplicate_owner_before_http_post() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
        .and(query_param("format", "json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ocs": {
                "meta": {
                    "status": "ok",
                    "statuscode": 100,
                    "message": "OK"
                },
                "data": {}
            }
        })))
        .expect(0)
        .mount(&server)
        .await;

    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut connector =
        NextcloudTalkConnector::new().with_thread_ownership_checker(checker.clone());
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "app_password",
                "username": "alice",
                "app_password": "app-material"
            },
            "network": { "allow_private_networks": true }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let claim_key = ClaimKey::new(
        ZoneId::work(),
        connector.id().clone(),
        ChannelId::new("room123"),
        ThreadId::new("reply_to:41"),
    );
    checker.claim_now(claim_key, AgentId::new("peer-agent"), Instant::now());

    let grant = generate_valid_token(&signing_key, CAP_WRITE, &[OP_SEND_MESSAGE], &instance_id);
    let error = connector
        .invoke(base_invoke(
            connector.id(),
            OP_SEND_MESSAGE,
            grant,
            json!({
                "token": "room123",
                "message": "duplicate owner should block this send",
                "reply_to": 41
            }),
        ))
        .await
        .expect_err("duplicate owner should be denied before HTTP POST");

    assert!(matches!(error, FcpError::Unauthorized { code: 4090, .. }));
    if let FcpError::Unauthorized { message, .. } = error {
        assert!(message.contains("thread_owned_by_peer:peer-agent"));
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_delete_message_returns_deleted_system_message() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123/42"))
        .and(query_param("format", "json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ocs": {
                "meta": {
                    "status": "ok",
                    "statuscode": 100,
                    "message": "OK"
                },
                "data": {
                    "id": 43,
                    "token": "room123",
                    "actorType": "users",
                    "actorId": "alice",
                    "actorDisplayName": "Alice",
                    "timestamp": 1_710_000_100u64,
                    "systemMessage": "message_deleted",
                    "messageType": "system",
                    "message": "",
                    "messageParameters": {},
                    "parent": {
                        "id": 42,
                        "message": "Message deleted by you"
                    },
                    "reactions": {},
                    "reactionsSelf": []
                }
            }
        })))
        .mount(&server)
        .await;

    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "app_password",
                "username": "alice",
                "app_password": "app-material"
            },
            "network": { "allow_private_networks": true }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let grant = generate_valid_token(&signing_key, CAP_MANAGE, &[OP_DELETE_MESSAGE], &instance_id);
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_DELETE_MESSAGE,
            grant,
            json!({
                "token": "room123",
                "message_id": 42
            }),
        ))
        .await
        .expect("invoke");

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["message"]["id"], 43);
    assert_eq!(result["message"]["systemMessage"], "message_deleted");
    assert_eq!(result["message"]["parent"]["id"], 42);
}

#[fcp_async_core::runtime::test]
async fn invoke_get_messages_uses_configured_long_poll_timeout_by_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
        .and(query_param("format", "json"))
        .and(query_param("lookIntoFuture", "1"))
        .and(query_param("timeout", "17"))
        .and(query_param("setReadMarker", "1"))
        .and(query_param("includeLastKnown", "0"))
        .and(query_param("noStatusUpdate", "0"))
        .and(query_param("markNotificationsAsRead", "1"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "bearer_token",
                "access_token": "oidc"
            },
            "long_poll_timeout_secs": 17,
            "network": { "allow_private_networks": true }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let grant = generate_valid_token(&signing_key, CAP_READ, &[OP_GET_MESSAGES], &instance_id);
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_GET_MESSAGES,
            grant,
            json!({
                "token": "room123",
                "look_into_future": true
            }),
        ))
        .await
        .expect("invoke");

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["messages"], json!([]));
    assert_eq!(result["not_modified"], true);
}

#[fcp_async_core::runtime::test]
async fn poll_conversation_events_returns_event_envelopes_and_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
        .and(query_param("format", "json"))
        .and(query_param("lookIntoFuture", "1"))
        .and(query_param("timeout", "11"))
        .and(query_param("setReadMarker", "0"))
        .and(query_param("includeLastKnown", "0"))
        .and(query_param("noStatusUpdate", "1"))
        .and(query_param("markNotificationsAsRead", "0"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Chat-Last-Given", "42")
                .insert_header("X-Chat-Last-Common-Read", "41")
                .set_body_json(json!({
                    "ocs": {
                        "meta": {
                            "status": "ok",
                            "statuscode": 100,
                            "message": "OK"
                        },
                        "data": [
                            {
                                "id": 42,
                                "token": "room123",
                                "actorType": "users",
                                "actorId": "alice",
                                "actorDisplayName": "Alice",
                                "timestamp": 1_710_000_200u64,
                                "systemMessage": "",
                                "messageType": "comment",
                                "message": "hello from poll",
                                "messageParameters": {},
                                "reactions": {},
                                "reactionsSelf": []
                            }
                        ]
                    }
                })),
        )
        .mount(&server)
        .await;

    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "bearer_token",
                "access_token": "oidc"
            },
            "long_poll_timeout_secs": 11,
            "network": { "allow_private_networks": true }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let grant = generate_valid_token(
        &signing_key,
        CAP_READ,
        &[OP_POLL_CONVERSATION_EVENTS],
        &instance_id,
    );
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_POLL_CONVERSATION_EVENTS,
            grant,
            json!({
                "token": "room123",
                "look_into_future": true
            }),
        ))
        .await
        .expect("invoke");

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["events"][0]["type"], "chat_message");
    assert_eq!(result["events"][0]["message_id"], 42);
    assert_eq!(result["events"][0]["message"]["message"], "hello from poll");
    assert_eq!(result["cursor"]["last_known_message_id"], 42);
    assert_eq!(result["cursor"]["last_common_read_id"], 41);
    assert_eq!(result["not_modified"], false);
}

#[fcp_async_core::runtime::test]
async fn poll_conversation_events_preserves_cursor_when_not_modified() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
        .and(query_param("format", "json"))
        .and(query_param("lookIntoFuture", "1"))
        .and(query_param("timeout", "11"))
        .and(query_param("lastKnownMessageId", "42"))
        .and(query_param("lastCommonReadId", "41"))
        .and(query_param("setReadMarker", "0"))
        .and(query_param("includeLastKnown", "0"))
        .and(query_param("noStatusUpdate", "1"))
        .and(query_param("markNotificationsAsRead", "0"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;

    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "bearer_token",
                "access_token": "oidc"
            },
            "long_poll_timeout_secs": 11,
            "network": { "allow_private_networks": true }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let grant = generate_valid_token(
        &signing_key,
        CAP_READ,
        &[OP_POLL_CONVERSATION_EVENTS],
        &instance_id,
    );
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_POLL_CONVERSATION_EVENTS,
            grant,
            json!({
                "token": "room123",
                "look_into_future": true,
                "last_known_message_id": 42,
                "last_common_read_id": 41
            }),
        ))
        .await
        .expect("invoke");

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.as_ref().expect("invoke result");
    assert_eq!(result["events"], json!([]));
    assert_eq!(result["cursor"]["last_known_message_id"], 42);
    assert_eq!(result["cursor"]["last_common_read_id"], 41);
    assert_eq!(result["not_modified"], true);
}

// ── Replay safety on retry (br-kxd3e) ────────────────────────────────
//
// `request_raw` is method-generic, so replay safety is derived from the HTTP
// method and POST fails closed. A 5xx on a chat POST means the server received
// the message; replaying it posts a duplicate into the room. Nextcloud Talk's
// `referenceId` is documented for identifying a message afterwards, not as a
// server-side dedup key, so there is no shape-(A) fix available here.
//
// The assertion is the REQUEST COUNT — "it still errors" would pass with the
// bug present.

#[fcp_async_core::runtime::test]
async fn send_message_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/ocs/v2.php/apps/spreed/api/v1/chat/room123"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let mut connector = NextcloudTalkConnector::new();
    connector
        .configure(json!({
            "server_url": server.uri(),
            "auth": {
                "mode": "app_password",
                "username": "alice",
                "app_password": "app-material"
            },
            "network": { "allow_private_networks": true },
            "retry": {
                "max_retries": 3,
                "initial_delay_ms": 1,
                "max_delay_ms": 5,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure");
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = test_instance_id();
    handshake_connector(&mut connector, &signing_key, &instance_id).await;

    let grant = generate_valid_token(&signing_key, CAP_WRITE, &[OP_SEND_MESSAGE], &instance_id);
    let response = connector
        .invoke(base_invoke(
            connector.id(),
            OP_SEND_MESSAGE,
            grant,
            json!({ "token": "room123", "message": "hello world" }),
        ))
        .await;
    assert!(
        response.is_err() || response.expect("invoke").status != InvokeStatus::Ok,
        "the 503 should surface as a failure"
    );

    let chat_posts = server
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST)
        .count();
    assert_eq!(
        chat_posts, 1,
        "a 503 means the server received the chat message — retrying posts a \
         DUPLICATE into the room, and Talk has no server-side dedup key"
    );
}
