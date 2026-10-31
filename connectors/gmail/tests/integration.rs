//! Integration tests for the Gmail connector.
//!
//! Covers the connector testing requirements (ofw.5):
//! - Error taxonomy mapping (`GmailError` → `FcpError`)
//! - OAuth credential handling (mocked)
//! - Redaction (tokens not leaked in error messages)
//! - Operation dispatch (get, list, send, modify, trash, threads, labels, drafts)
//! - Rate limit handling
//!
//! All tests are deterministic — no real API calls.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_discovery::{
    DiscoveryEndpointKind, DiscoveryServiceId, auth::FCP_CREDENTIAL_ID_HEADER,
    generator::generate_google_service_artifacts, normalize_snapshot_bytes,
    policy::GooglePolicyCatalog,
};
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::ApprovalMode;
use fcp_prelude::{CapabilityConstraints, CapabilityToken, CredentialId, FcpError};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration as StdDuration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

use fcp_gmail::{client::GmailClient, connector::GmailConnector, error::GmailError};

const TEST_CREDENTIAL_ID: &str = "00000000-0000-0000-0000-000000000001";

// ============================================================================
// Helpers
// ============================================================================

/// Map an operation ID to the capability ID that governs it.
fn capability_for_operation(op: &str) -> &str {
    match op {
        "gmail.read" | "gmail.send" | "gmail.write" | "gmail.delete" | "gmail.history.read" => op,
        "gmail.send_message" | "gmail.send_draft" => "gmail.send",
        "gmail.sync_history" => "gmail.history.read",
        "gmail.modify_message" | "gmail.get_draft" | "gmail.create_draft" => "gmail.write",
        "gmail.trash_message" => "gmail.delete",
        _ => "gmail.read",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &GmailConnector,
    op: &str,
) -> CapabilityToken {
    let cap = capability_for_operation(op);
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
        .zone_id("z:private")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .target_instance(connector.instance_id().as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut GmailConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let mapped: Vec<&str> = caps.iter().map(|c| capability_for_operation(c)).collect();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:private",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": mapped
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

async fn setup_configure(connector: &mut GmailConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

fn invoke_request(
    operation: &str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> serde_json::Value {
    json!({
        "type": "invoke", "id": "gmail-integration",
        "connector_id": "fcp.gmail", "zone_id": "z:private",
        "operation": operation, "input": input, "capability_token": token,
    })
}

fn message_response(id: &str, thread_id: &str) -> serde_json::Value {
    json!({
        "id": id,
        "threadId": thread_id,
        "labelIds": ["INBOX"],
        "snippet": "Test message content",
        "historyId": "12345",
        "internalDate": "1700000000000",
        "sizeEstimate": 1234,
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "Subject", "value": "Test Subject"},
                {"name": "From", "value": "sender@example.com"},
                {"name": "To", "value": "recipient@example.com"}
            ],
            "body": {
                "size": 100,
                "data": "SGVsbG8gV29ybGQ="
            }
        }
    })
}

// ============================================================================
// Error taxonomy mapping tests
// ============================================================================

/// 401 Unauthorized maps to `GmailError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages/msg1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 100, 100);

    let err = client.get_message("msg1").await.unwrap_err();
    assert!(matches!(err, GmailError::Unauthorized));

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 403 Forbidden scope/auth failures also map to `GmailError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_403_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages/msg1"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 100, 100);

    let err = client.get_message("msg1").await.unwrap_err();
    assert!(matches!(err, GmailError::Unauthorized));

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 404 Not Found for a message maps to `FcpError::ResourceNotFound`.
#[test]
fn error_404_message_not_found() {
    let err = GmailError::MessageNotFound {
        message_id: "msg-gone".into(),
    };
    assert!(!err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::ResourceNotFound { .. }),
        "expected ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[test]
fn error_429_rate_limited() {
    let err = GmailError::RateLimited {
        retry_after_secs: 30,
    };
    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::RateLimited {
                retry_after_ms: 30_000,
                ..
            }
        ),
        "expected RateLimited with 30s, got: {fcp_err:?}"
    );
}

/// 500 Server Error is retryable via `GmailError::Api`.
#[test]
fn error_500_server_is_retryable() {
    let err = GmailError::Api {
        code: 500,
        message: "Internal Server Error".into(),
    };
    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::External {
                retryable: true,
                ..
            }
        ),
        "expected External retryable, got: {fcp_err:?}"
    );
}

/// 400 Bad Request is NOT retryable.
#[test]
fn error_400_not_retryable() {
    let err = GmailError::Api {
        code: 400,
        message: "Bad Request".into(),
    };
    assert!(!err.is_retryable());
}

/// Thread not found maps correctly.
#[test]
fn error_thread_not_found() {
    let err = GmailError::ThreadNotFound {
        thread_id: "thread-123".into(),
    };
    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, FcpError::ResourceNotFound { .. }));
}

/// Label not found maps correctly.
#[test]
fn error_label_not_found() {
    let err = GmailError::LabelNotFound {
        label: "CUSTOM_LABEL".into(),
    };
    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, FcpError::ResourceNotFound { .. }));
}

// ============================================================================
// Redaction tests
// ============================================================================

/// OAuth token should not appear in error messages from the client.
#[fcp_async_core::runtime::test]
async fn redaction_token_not_in_error_message() {
    let mock_server = MockServer::start().await;
    let secret_token = "ya29.SuperSecretOAuthTokenThatShouldNotLeak";

    Mock::given(method("GET"))
        .and(path("/users/me/labels"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new(secret_token)
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 100, 100);

    let err = client.list_labels().await.unwrap_err();
    let err_string = format!("{err:?}");
    assert!(
        !err_string.contains(secret_token),
        "OAuth token should not appear in error debug output"
    );

    let fcp_err = err.to_fcp_error();
    let fcp_err_string = format!("{fcp_err:?}");
    assert!(
        !fcp_err_string.contains(secret_token),
        "OAuth token should not appear in FCP error debug output"
    );
}

/// OAuth token is sent as Bearer auth header (not in URL).
#[fcp_async_core::runtime::test]
async fn token_sent_as_bearer_auth() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/labels"))
        .and(header("authorization", "Bearer test-oauth-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"labels": []})))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-oauth-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 100, 100);

    let labels = client.list_labels().await.unwrap();
    assert!(labels.is_empty());
}

// ============================================================================
// Client operation tests
// ============================================================================

/// `get_message` returns a parsed message with all fields.
#[fcp_async_core::runtime::test]
async fn get_message_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages/msg123"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(message_response("msg123", "thread456")),
        )
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let msg = client.get_message("msg123").await.unwrap();
    assert_eq!(msg.id, "msg123");
    assert_eq!(msg.thread_id.as_deref(), Some("thread456"));
    assert!(msg.label_ids.contains(&"INBOX".to_string()));
    assert_eq!(msg.snippet, "Test message content");
}

/// `list_messages` with query parameter.
#[fcp_async_core::runtime::test]
async fn list_messages_with_query() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages"))
        .and(query_param("q", "is:unread"))
        .and(query_param("maxResults", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                {"id": "msg1", "threadId": "t1"},
                {"id": "msg2", "threadId": "t2"}
            ],
            "nextPageToken": "page2token",
            "resultSizeEstimate": 100
        })))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let result = client
        .list_messages(Some("is:unread"), Some(5), None)
        .await
        .unwrap();

    assert_eq!(result.messages.len(), 2);
    assert_eq!(result.next_page_token.as_deref(), Some("page2token"));
    assert_eq!(result.result_size_estimate, 100);
}

/// `list_messages` with pagination token.
#[fcp_async_core::runtime::test]
async fn list_messages_pagination() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages"))
        .and(query_param("pageToken", "page2token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                {"id": "msg3", "threadId": "t3"}
            ],
            "resultSizeEstimate": 50
        })))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let result = client
        .list_messages(None, None, Some("page2token"))
        .await
        .unwrap();

    assert_eq!(result.messages.len(), 1);
    assert!(result.next_page_token.is_none());
}

/// `send_message` posts an RFC 2822 base64url message.
#[fcp_async_core::runtime::test]
async fn send_message_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/messages/send"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(message_response("sent-msg", "new-thread")),
        )
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let raw = "RnJvbTogdGVzdEBleGFtcGxlLmNvbQ=="; // base64url RFC 2822
    let msg = client.send_message(raw).await.unwrap();
    assert_eq!(msg.id, "sent-msg");
}

/// `modify_message` adds and removes labels.
#[fcp_async_core::runtime::test]
async fn modify_message_labels() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/messages/msg1/modify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg1",
            "threadId": "t1",
            "labelIds": ["STARRED"]
        })))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let msg = client
        .modify_message("msg1", &["STARRED".to_string()], &["INBOX".to_string()])
        .await
        .unwrap();

    assert!(msg.label_ids.contains(&"STARRED".to_string()));
}

/// `trash_message` moves a message to trash.
#[fcp_async_core::runtime::test]
async fn trash_message_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/messages/msg1/trash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg1",
            "threadId": "t1",
            "labelIds": ["TRASH"]
        })))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let msg = client.trash_message("msg1").await.unwrap();
    assert!(msg.label_ids.contains(&"TRASH".to_string()));
}

/// `get_thread` returns thread with messages.
#[fcp_async_core::runtime::test]
async fn get_thread_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/threads/thread1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "thread1",
            "historyId": "99999",
            "messages": [
                message_response("msg1", "thread1"),
                message_response("msg2", "thread1")
            ]
        })))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let thread = client.get_thread("thread1").await.unwrap();
    assert_eq!(thread.id, "thread1");
    assert_eq!(thread.messages.len(), 2);
}

/// `list_labels` returns all labels.
#[fcp_async_core::runtime::test]
async fn list_labels_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                {"id": "INBOX", "name": "INBOX", "type": "system"},
                {"id": "SENT", "name": "SENT", "type": "system"},
                {"id": "Label_1", "name": "Custom", "type": "user"}
            ]
        })))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let labels = client.list_labels().await.unwrap();
    assert_eq!(labels.len(), 3);
}

/// `get_draft` returns a draft with optional message.
#[fcp_async_core::runtime::test]
async fn get_draft_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/drafts/draft1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "draft1",
            "message": message_response("draft-msg", "draft-thread")
        })))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let draft = client.get_draft("draft1").await.unwrap();
    assert_eq!(draft.id, "draft1");
    assert!(draft.message.is_some());
}

/// `create_draft` creates a saved draft without sending it.
#[fcp_async_core::runtime::test]
async fn create_draft_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "draft-created",
            "message": message_response("draft-msg", "draft-thread")
        })))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let raw = "RnJvbTogdGVzdEBleGFtcGxlLmNvbQ==";
    let draft = client.create_draft(raw).await.unwrap();
    assert_eq!(draft.id, "draft-created");
    assert!(draft.message.is_some());
}

/// `send_draft` sends a draft and returns the sent message.
#[fcp_async_core::runtime::test]
async fn send_draft_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/drafts/send"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(message_response("sent-from-draft", "draft-thread")),
        )
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    let msg = client.send_draft("draft1").await.unwrap();
    assert_eq!(msg.id, "sent-from-draft");
}

/// Request counter tracks total requests.
#[fcp_async_core::runtime::test]
async fn request_counter_tracks_total() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"labels": []})))
        .mount(&mock_server)
        .await;

    let client = GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri());

    assert_eq!(client.total_requests(), 0);
    client.list_labels().await.unwrap();
    assert_eq!(client.total_requests(), 1);
    client.list_labels().await.unwrap();
    assert_eq!(client.total_requests(), 2);
}

// ============================================================================
// Connector-level invoke tests
// ============================================================================

/// Invoke `gmail.list_labels` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_list_labels_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/labels"))
        .and(header(FCP_CREDENTIAL_ID_HEADER, TEST_CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "labels": [
                {"id": "INBOX", "name": "INBOX", "type": "system"}
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GmailConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["gmail.read"]).await;
    let token = generate_valid_token(&signing_key, &connector, "gmail.list_labels");

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "list-labels",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.list_labels",
            "input": {},
            "capability_token": token
        }))
        .await
        .unwrap();

    let labels = result["labels"].as_array().unwrap();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0]["id"], "INBOX");
}

/// Invoke `gmail.get_message` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_message_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/me/messages/msg42"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(message_response("msg42", "thread42")),
        )
        .mount(&mock_server)
        .await;

    let mut connector = GmailConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["gmail.read"]).await;
    let token = generate_valid_token(&signing_key, &connector, "gmail.get_message");

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "get-message",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.get_message",
            "input": {"message_id": "msg42"},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["message"]["id"], "msg42");
    assert_eq!(result["message"]["threadId"], "thread42");
}

#[fcp_async_core::runtime::test]
async fn attachment_invoke_is_bound_to_both_ids_and_host_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/me/messages/m1/attachments/a1"))
        .and(header(FCP_CREDENTIAL_ID_HEADER, TEST_CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"size":2,"data":"-_8"})))
        .expect(1)
        .mount(&server)
        .await;
    let mut connector = GmailConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["gmail.get_attachment"]).await;
    let operation = "gmail.get_attachment";
    let input = json!({"message_id":"m1", "attachment_id":"a1", "max_bytes":2});
    let make_token = |capability: &str, granted_operation: &str, resource: &str, instance: &str| {
        let constraints = CapabilityConstraints {
            resource_allow: vec![resource.into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id(capability)
                .zone_id("z:private")
                .principal("user:test")
                .operations(&[granted_operation])
                .issuer("node:test")
                .target_instance(instance)
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&cbor)
                .unwrap()
                .sign(&signing_key)
                .unwrap(),
        )
    };
    let instance = connector.instance_id().as_str();
    for (capability, granted_operation, resource, target) in [
        ("gmail.send", operation, "*", instance),
        ("gmail.read", "gmail.get_message", "*", instance),
        (
            "gmail.read",
            operation,
            "gmail:message:other:attachment:a1",
            instance,
        ),
        (
            "gmail.read",
            operation,
            "gmail:message:m1:attachment:other",
            instance,
        ),
        ("gmail.read", operation, "*", "wrong-attachment-instance"),
    ] {
        let token = make_token(capability, granted_operation, resource, target);
        let result = connector
            .handle_invoke(invoke_request(operation, input.clone(), token))
            .await;
        assert!(
            result.is_err(),
            "authority mismatch must be rejected before egress"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    let token = make_token(
        "gmail.read",
        operation,
        "gmail:message:m1:attachment:a1",
        instance,
    );
    let result = connector
        .handle_invoke(invoke_request(operation, input, token))
        .await
        .unwrap();
    assert_eq!(result, json!({"attachment":{"size":2,"data":"-_8"}}));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].body.is_empty());
    assert!(!requests[0].headers.contains_key("authorization"));
}

/// Invoke `gmail.send_message` through the connector with structured fields.
#[fcp_async_core::runtime::test]
async fn invoke_send_message_accepts_structured_fields() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/messages/send"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg-sent",
            "threadId": "thread-sent",
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GmailConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["gmail.send"]).await;
    let token = generate_valid_token(&signing_key, &connector, "gmail.send_message");

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "send-message",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.send_message",
            "input": {
                "to": "recipient@example.com",
                "subject": "Structured test",
                "body": "Hello!"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["message"]["id"], "msg-sent");
    assert_eq!(result["message"]["threadId"], "thread-sent");
}

/// Invoke `gmail.create_draft` through the connector with structured fields.
#[fcp_async_core::runtime::test]
async fn invoke_create_draft_accepts_structured_fields() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "draft-created",
            "message": message_response("draft-msg", "draft-thread"),
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GmailConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["gmail.write"]).await;
    let token = generate_valid_token(&signing_key, &connector, "gmail.create_draft");

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "create-draft",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.create_draft",
            "input": {
                "to": "recipient@example.com",
                "subject": "Structured draft",
                "body": "Hello draft!"
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["draft"]["id"], "draft-created");
    assert_eq!(result["draft"]["message"]["id"], "draft-msg");
}

/// Invoke `gmail.trash_message` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_trash_message_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/users/me/messages/msg-to-trash/trash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg-to-trash",
            "threadId": "t1",
            "labelIds": ["TRASH"]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = GmailConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["gmail.delete"]).await;
    let token = generate_valid_token(&signing_key, &connector, "gmail.trash_message");

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "trash-message",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.trash_message",
            "input": {"message_id": "msg-to-trash"},
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["message"]["id"], "msg-to-trash");
}

/// Wrong capability token is rejected.
#[fcp_async_core::runtime::test]
async fn wrong_capability_rejected() {
    let mock_server = MockServer::start().await;

    let mut connector = GmailConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["gmail.send"]).await;
    let token = generate_valid_token(&signing_key, &connector, "gmail.send_message");

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "wrong-capability",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.get_message",
            "input": {"message_id": "msg1"},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject mismatched capability");
}

/// Missing required field returns `InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn missing_required_field_returns_invalid_request() {
    let mock_server = MockServer::start().await;

    let mut connector = GmailConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["gmail.read"]).await;
    let token = generate_valid_token(&signing_key, &connector, "gmail.get_message");

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "missing-message-id",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.get_message",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing message_id"
    );
}

/// Malformed optional label arrays are rejected before Gmail API calls.
#[fcp_async_core::runtime::test]
async fn invoke_modify_message_rejects_malformed_label_arrays() {
    let mock_server = MockServer::start().await;

    let mut connector = GmailConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(&mut connector, &["gmail.modify_message"]).await;
    let token = generate_valid_token(&signing_key, &connector, "gmail.modify_message");

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "modify-message",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.modify_message",
            "input": {
                "message_id": "msg1",
                "add_label_ids": "STARRED"
            },
            "capability_token": token
        }))
        .await;

    assert!(matches!(result, Err(FcpError::InvalidRequest { .. })));
}

/// Doctor reports credential injection requirement for `credential_id` mode.
#[fcp_async_core::runtime::test]
async fn doctor_reports_pending_materialization_for_credential_mode() {
    let mut connector = GmailConnector::new();

    let doctor_before = connector.handle_doctor().await.unwrap();
    assert_eq!(doctor_before["status"], "unhealthy");

    connector
        .handle_configure(json!({
            "credential_id": "00000000-0000-0000-0000-000000000001"
        }))
        .await
        .unwrap();

    let doctor_after = connector.handle_doctor().await.unwrap();
    assert_eq!(doctor_after["status"], "degraded");

    let self_check = connector.handle_self_check().await.unwrap();
    assert_eq!(self_check["status"], "degraded");
    assert_eq!(self_check["reason_code"], "credential_injection_required");
}

/// OAuth refresh mode is not allowed to carry raw secret material in connector config.
#[fcp_async_core::runtime::test]
async fn oauth_refresh_mode_rejects_raw_secret_material() {
    let mut connector = GmailConnector::new();
    let result = connector
        .handle_configure(json!({
            "base_url": "http://localhost:9999",
            "required_scopes": ["https://mail.google.com/"],
            "oauth_refresh": {
                "client_id": "integration-client",
                "client_secret": "integration-secret",
                "refresh_token": "integration-refresh",
                "token_url": "http://localhost:9999/oauth/token"
            }
        }))
        .await;

    assert!(matches!(
        result,
        Err(FcpError::ConfigurationLeakedSecret { .. })
    ));
}

fn history_state_path() -> PathBuf {
    std::env::temp_dir().join(format!("fcp-gmail-history-{}.json", uuid::Uuid::new_v4()))
}

fn history_cursor_state(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).expect("read history checkpoint"))
        .expect("parse history checkpoint")
}

async fn history_connector(
    server: &MockServer,
    state_path: &Path,
    credential_id: &str,
) -> (GmailConnector, Ed25519SigningKey) {
    let mut connector = GmailConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": credential_id,
            "base_url": server.uri(),
            "history_cursor_path": state_path.to_string_lossy().to_string(),
        }))
        .await
        .expect("configure history connector");
    let key = setup_handshake(&mut connector, &["gmail.sync_history"]).await;
    (connector, key)
}

async fn invoke_history(
    connector: &GmailConnector,
    key: &Ed25519SigningKey,
    input: serde_json::Value,
) -> Result<serde_json::Value, FcpError> {
    connector
        .handle_invoke(json!({
            "type": "invoke", "id": "sync-history",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.sync_history",
            "input": input,
            "capability_token": generate_valid_token(key, connector, "gmail.sync_history"),
        }))
        .await
}

/// A lost response must replay after restart until the caller confirms progress.
#[fcp_async_core::runtime::test]
async fn invoke_sync_history_replays_until_caller_confirms_consumption() {
    let mock_server = MockServer::start().await;
    let state_path = history_state_path();

    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "500"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "history": [
                { "id": "501", "messagesAdded": [{ "message": { "id": "m501" } }] }
            ],
            "historyId": "600"
        })))
        .expect(3)
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "600"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "history": [],
            "historyId": "600"
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    let (connector, signing_key) =
        history_connector(&mock_server, &state_path, TEST_CREDENTIAL_ID).await;
    let first = invoke_history(
        &connector,
        &signing_key,
        json!({
            "start_history_id": "500",
            "lease_seq": 1,
            "lease_object_id": "lease-a",
        }),
    )
    .await
    .unwrap();

    assert_eq!(first["effective_start_history_id"], "500");
    assert_eq!(first["latest_history_id"], "600");
    assert_eq!(first["acknowledged_history_id"], "500");
    assert_eq!(first["history_count"], 1);
    assert_eq!(history_cursor_state(&state_path)["next_history_id"], "500");
    drop(first);
    drop(connector);

    let (restarted, signing_key2) =
        history_connector(&mock_server, &state_path, TEST_CREDENTIAL_ID).await;
    let resumed = invoke_history(
        &restarted,
        &signing_key2,
        json!({
            "lease_seq": 2,
            "lease_object_id": "lease-b",
        }),
    )
    .await
    .unwrap();
    assert_eq!(resumed["effective_start_history_id"], "500");
    assert_eq!(resumed["latest_history_id"], "600");
    assert_eq!(resumed["history"][0]["id"], "501");
    assert_eq!(resumed["history_count"], 1);
    assert_eq!(resumed["used_persisted_cursor"], true);
    assert_eq!(history_cursor_state(&state_path)["next_history_id"], "500");

    let advanced = invoke_history(
        &restarted,
        &signing_key2,
        json!({
            "start_history_id": resumed["latest_history_id"],
            "lease_seq": 2,
            "lease_object_id": "lease-b",
        }),
    )
    .await
    .unwrap();
    assert_eq!(advanced["effective_start_history_id"], "600");
    assert_eq!(advanced["acknowledged_history_id"], "600");
    assert_eq!(advanced["history_count"], 0);

    let replay = invoke_history(
        &restarted,
        &signing_key2,
        json!({
            "start_history_id": "500",
            "lease_seq": 2,
            "lease_object_id": "lease-b",
        }),
    )
    .await
    .unwrap();
    assert_eq!(replay["effective_start_history_id"], "500");
    assert_eq!(replay["history"][0]["id"], "501");
    assert_eq!(replay["acknowledged_history_id"], "600");
    assert_eq!(replay["dedup_applied"], false);
    assert_eq!(replay["used_persisted_cursor"], false);
    assert_eq!(history_cursor_state(&state_path)["next_history_id"], "600");

    let resumed_after_replay = invoke_history(
        &restarted,
        &signing_key2,
        json!({
            "lease_seq": 2,
            "lease_object_id": "lease-b",
        }),
    )
    .await
    .unwrap();
    assert_eq!(resumed_after_replay["effective_start_history_id"], "600");
    assert_eq!(resumed_after_replay["history_count"], 0);
    mock_server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_history_collects_all_pages_before_offering_checkpoint() {
    let server = MockServer::start().await;
    let state_path = history_state_path();
    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "500"))
        .and(query_param("maxResults", "2"))
        .respond_with(|request: &wiremock::Request| {
            let token = request.url.query_pairs()
                .find_map(|(key, value)| (key == "pageToken").then(|| value.into_owned()));
            match token.as_deref() {
                None => ResponseTemplate::new(200).set_body_json(json!({
                    "history": [{"id": "501", "messagesAdded": [{"message": {"id": "m501"}}]}],
                    "historyId": "900",
                    "nextPageToken": "opaque-second-page",
                })),
                Some("opaque-second-page") => ResponseTemplate::new(200).set_body_json(json!({
                    "history": [{"id": "701", "labelsRemoved": [{"message": {"id": "m701"}, "labelIds": ["UNREAD"]}]}],
                    "historyId": "950",
                })),
                _ => ResponseTemplate::new(400),
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let (connector, key) = history_connector(&server, &state_path, TEST_CREDENTIAL_ID).await;
    let result = invoke_history(
        &connector,
        &key,
        json!({
            "start_history_id": "500",
            "max_results": 2,
            "history_types": ["messageAdded", "labelRemoved"],
            "lease_seq": 1,
            "lease_object_id": "reader",
        }),
    )
    .await
    .unwrap();
    assert_eq!(result["history_count"], 2);
    assert_eq!(result["history"][0]["id"], "501");
    assert_eq!(result["history"][1]["id"], "701");
    assert_eq!(result["latest_history_id"], "950");
    assert_eq!(result["acknowledged_history_id"], "500");
    assert_eq!(history_cursor_state(&state_path)["next_history_id"], "500");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        !requests[0]
            .url
            .query_pairs()
            .any(|(key, _)| key == "pageToken")
    );
    assert!(
        requests[1]
            .url
            .query_pairs()
            .any(|(key, value)| { key == "pageToken" && value == "opaque-second-page" })
    );
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_history_final_page_failure_preserves_checkpoint() {
    let server = MockServer::start().await;
    let state_path = history_state_path();
    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "history": [], "historyId": "100",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "200"))
        .respond_with(|request: &wiremock::Request| {
            if request.url.query_pairs().any(|(key, _)| key == "pageToken") {
                ResponseTemplate::new(404).set_body_json(json!({
                    "error": {"code": 404, "message": "Requested entity was not found."},
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "history": [{"id": "201"}],
                    "historyId": "900",
                    "nextPageToken": "last-page-unavailable",
                }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let (connector, key) = history_connector(&server, &state_path, TEST_CREDENTIAL_ID).await;
    invoke_history(
        &connector,
        &key,
        json!({
            "start_history_id": "100", "lease_seq": 1, "lease_object_id": "reader-a",
        }),
    )
    .await
    .unwrap();
    let before = std::fs::read(&state_path).unwrap();
    let error = invoke_history(
        &connector,
        &key,
        json!({
            "start_history_id": "200", "lease_seq": 2, "lease_object_id": "reader-b",
        }),
    )
    .await
    .expect_err("a partial traversal is not a completed sync");
    assert!(
        error.to_string().to_ascii_lowercase().contains("full"),
        "expired provider history must explain full-sync recovery: {error}"
    );
    assert_eq!(std::fs::read(&state_path).unwrap(), before);
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_history_legacy_cursor_requires_explicit_confirmed_start() {
    let server = MockServer::start().await;
    let state_path = history_state_path();
    let legacy = json!({
        "next_history_id": "900",
        "lease_seq": 7,
        "lease_object_id": "legacy-owner",
        "updated_at": 0,
    });
    std::fs::write(&state_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "500"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "history": [{"id": "501"}], "historyId": "950",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (connector, key) = history_connector(&server, &state_path, TEST_CREDENTIAL_ID).await;
    let missing_start = invoke_history(
        &connector,
        &key,
        json!({
            "lease_seq": 8, "lease_object_id": "new-owner",
        }),
    )
    .await
    .unwrap_err();
    assert!(matches!(missing_start, FcpError::InvalidRequest { .. }));
    assert!(missing_start.to_string().contains("legacy"));
    assert_eq!(history_cursor_state(&state_path), legacy);

    for (lease_seq, owner) in [(6, "stale-owner"), (7, "different-owner")] {
        let error = invoke_history(
            &connector,
            &key,
            json!({
                "start_history_id": "500", "lease_seq": lease_seq, "lease_object_id": owner,
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, FcpError::Conflict { .. }));
        assert_eq!(history_cursor_state(&state_path), legacy);
    }
    let migrated = invoke_history(
        &connector,
        &key,
        json!({
            "start_history_id": "500", "lease_seq": 8, "lease_object_id": "new-owner",
        }),
    )
    .await
    .unwrap();
    assert_eq!(migrated["effective_start_history_id"], "500");
    assert_eq!(migrated["acknowledged_history_id"], "500");
    assert_eq!(migrated["history"][0]["id"], "501");
    let state = history_cursor_state(&state_path);
    assert_eq!(state["cursor_version"], 2);
    assert_eq!(state["next_history_id"], "500");
    assert_eq!(state["lease_seq"], 8);
    assert_eq!(state["lease_object_id"], "new-owner");
    assert!(
        state["scope"]
            .as_str()
            .is_some_and(|scope| !scope.is_empty())
    );
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_history_checkpoint_cannot_cross_mailbox_or_filter_scope() {
    let server = MockServer::start().await;
    let state_path = history_state_path();
    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "history": [], "historyId": "300",
        })))
        .expect(2)
        .mount(&server)
        .await;
    let (connector, key) = history_connector(&server, &state_path, TEST_CREDENTIAL_ID).await;
    invoke_history(
        &connector,
        &key,
        json!({
            "start_history_id": "100", "lease_seq": 1, "lease_object_id": "owner",
            "history_types": ["messageAdded", "labelRemoved"],
        }),
    )
    .await
    .unwrap();
    let equivalent = invoke_history(
        &connector,
        &key,
        json!({
            "lease_seq": 1, "lease_object_id": "owner",
            "history_types": ["labelRemoved", "messageAdded", "messageAdded"],
        }),
    )
    .await
    .expect("filter order and duplicates do not change logical scope");
    assert_eq!(equivalent["effective_start_history_id"], "100");
    let before = std::fs::read(&state_path).unwrap();

    for mut input in [json!({}), json!({"start_history_id": "200"})] {
        input["lease_seq"] = json!(2);
        input["lease_object_id"] = json!("owner");
        input["history_types"] = json!(["messageDeleted"]);
        let error = invoke_history(&connector, &key, input).await.unwrap_err();
        assert!(matches!(error, FcpError::Conflict { .. }));
    }
    let other_credential = CredentialId::new().to_string();
    let (other_mailbox, other_key) =
        history_connector(&server, &state_path, &other_credential).await;
    let error = invoke_history(
        &other_mailbox,
        &other_key,
        json!({
            "lease_seq": 2, "lease_object_id": "owner",
            "history_types": ["messageAdded", "labelRemoved"],
        }),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, FcpError::Conflict { .. }));
    assert_eq!(std::fs::read(&state_path).unwrap(), before);
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_history_repeated_page_token_fails_without_checkpoint() {
    let server = MockServer::start().await;
    let state_path = history_state_path();
    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "history": [{"id": "101"}], "historyId": "200", "nextPageToken": "repeated",
        })))
        .expect(2)
        .mount(&server)
        .await;
    let (connector, key) = history_connector(&server, &state_path, TEST_CREDENTIAL_ID).await;
    let result = fcp_async_core::time::timeout(
        StdDuration::from_secs(3),
        invoke_history(
            &connector,
            &key,
            json!({"start_history_id": "100", "lease_seq": 1}),
        ),
    )
    .await
    .expect("provider pagination cycle must terminate");
    assert!(matches!(
        result,
        Err(FcpError::External {
            retryable: false,
            ..
        })
    ));
    assert!(!state_path.exists());
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_history_invalid_terminal_cursor_fails_without_checkpoint() {
    for response in [
        json!({"history": [{"id": "51"}]}),
        json!({"history": [{"id": "51"}], "historyId": "not-a-history-id"}),
        json!({"history": [], "historyId": "49"}),
    ] {
        let server = MockServer::start().await;
        let state_path = history_state_path();
        Mock::given(method("GET"))
            .and(path("/users/me/history"))
            .and(query_param("startHistoryId", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let (connector, key) = history_connector(&server, &state_path, TEST_CREDENTIAL_ID).await;
        let result = invoke_history(
            &connector,
            &key,
            json!({
                "start_history_id": "50", "lease_seq": 1,
            }),
        )
        .await;
        assert!(matches!(
            result,
            Err(FcpError::External {
                retryable: false,
                ..
            })
        ));
        assert!(!state_path.exists());
        server.verify().await;
    }
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_history_cumulative_byte_limit_does_not_publish_checkpoint() {
    let server = MockServer::start().await;
    let state_path = history_state_path();
    let page_payload = "x".repeat(5 * 1024 * 1024);
    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "100"))
        .respond_with(move |request: &wiremock::Request| {
            let second_page = request.url.query_pairs().any(|(key, _)| key == "pageToken");
            let mut response = json!({
                "history": [{
                    "id": if second_page { "102" } else { "101" },
                    "provider_data": page_payload,
                }],
                "historyId": "200",
            });
            if !second_page {
                response["nextPageToken"] = json!("second-large-page");
            }
            ResponseTemplate::new(200).set_body_json(response)
        })
        .expect(2)
        .mount(&server)
        .await;
    let (connector, key) = history_connector(&server, &state_path, TEST_CREDENTIAL_ID).await;
    let result = invoke_history(
        &connector,
        &key,
        json!({
            "start_history_id": "100", "lease_seq": 1,
        }),
    )
    .await;
    assert!(matches!(
        result,
        Err(FcpError::External {
            retryable: false,
            ..
        })
    ));
    assert!(!state_path.exists());
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn invoke_sync_history_stale_writer_cannot_overwrite_newer_completion() {
    let server = MockServer::start().await;
    let state_path = history_state_path();
    let old_started = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&old_started);
    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "100"))
        .respond_with(move |_request: &wiremock::Request| {
            signal.store(true, Ordering::Release);
            ResponseTemplate::new(200)
                .set_body_json(json!({"history": [{"id": "101"}], "historyId": "300"}))
                .set_delay(StdDuration::from_secs(1))
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/users/me/history"))
        .and(query_param("startHistoryId", "200"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "history": [{"id": "201"}], "historyId": "400",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (older, old_key) = history_connector(&server, &state_path, TEST_CREDENTIAL_ID).await;
    let (newer, new_key) = history_connector(&server, &state_path, TEST_CREDENTIAL_ID).await;
    let mut old_request = Box::pin(invoke_history(
        &older,
        &old_key,
        json!({
            "start_history_id": "100", "lease_seq": 1, "lease_object_id": "old-owner",
        }),
    ));
    fcp_async_core::time::timeout(StdDuration::from_secs(3), async {
        fcp_async_core::select! {
            result = &mut old_request => panic!("older request completed before overlap: {result:?}"),
            () = async {
                while !old_started.load(Ordering::Acquire) {
                    fcp_async_core::time::sleep(StdDuration::from_millis(5)).await;
                }
            } => {},
        }
    }).await.expect("older writer should reach the provider");
    let newest = invoke_history(
        &newer,
        &new_key,
        json!({
            "start_history_id": "200", "lease_seq": 2, "lease_object_id": "new-owner",
        }),
    )
    .await
    .unwrap();
    assert_eq!(newest["acknowledged_history_id"], "200");
    let committed = std::fs::read(&state_path).unwrap();
    let stale = old_request.await.unwrap_err();
    assert!(matches!(stale, FcpError::Conflict { .. }));
    assert_eq!(std::fs::read(&state_path).unwrap(), committed);
    assert_eq!(history_cursor_state(&state_path)["next_history_id"], "200");
    assert_eq!(history_cursor_state(&state_path)["lease_seq"], 2);
    server.verify().await;
}

const fn generated_approval_name(mode: Option<ApprovalMode>) -> &'static str {
    match mode {
        None | Some(ApprovalMode::None) => "none",
        Some(ApprovalMode::Policy) => "policy",
        Some(ApprovalMode::Interactive) => "interactive",
        Some(ApprovalMode::ElevationToken) => "elevation_token",
    }
}

const fn manifest_approval_name(mode: ManifestApprovalMode) -> &'static str {
    match mode {
        ManifestApprovalMode::None => "none",
        ManifestApprovalMode::Policy => "policy",
        ManifestApprovalMode::Interactive => "interactive",
        ManifestApprovalMode::ElevationToken => "elevation_token",
    }
}

/// Shared Gmail generation now matches the canonical list/send/history metadata
/// surface.
///
/// `sync_history` is a connector-local operation over the generated Discovery
/// history endpoint, and intentionally keeps a more granular
/// `gmail.history.read` capability than `gmail.users.messages.list_history`.
#[fcp_async_core::runtime::test]
async fn shared_generation_overlap_matches_canonical_gmail_metadata() {
    let service = DiscoveryServiceId::new("gmail", "v1").expect("valid gmail service id");
    let snapshot = normalize_snapshot_bytes(
        &service,
        include_bytes!(
            "../../../crates/fcp-google-discovery/data/fixtures/gmail_discovery.v1.json"
        ),
        DiscoveryEndpointKind::Standard,
        "https://example.test/discovery/gmail",
    )
    .expect("gmail discovery fixture should normalize")
    .snapshot;
    let policy = GooglePolicyCatalog::load_default().expect("google policy catalog");
    let generated = generate_google_service_artifacts(&snapshot, &policy)
        .expect("gmail generation should succeed");
    let manifest =
        ConnectorManifest::parse_str(include_str!("../manifest.toml")).expect("gmail manifest");

    let connector = GmailConnector::new();
    let introspection = connector.handle_introspect().await.unwrap();
    let introspection_ops = introspection["operations"]
        .as_array()
        .expect("introspection operations array");

    let generated_list = generated
        .manifest_fragment
        .operations
        .iter()
        .find(|op| op.operation_id == "gmail.users.messages.list")
        .expect("generated list op");
    let manifest_list = manifest
        .provides
        .operations
        .get("gmail.list_messages")
        .expect("manifest list op");
    let introspection_list = introspection_ops
        .iter()
        .find(|op| op["id"] == "gmail.list_messages")
        .expect("introspection list op");

    assert_eq!(generated_list.capability, "gmail.read");
    assert_eq!(manifest_list.capability.as_str(), generated_list.capability);
    assert_eq!(
        generated_approval_name(generated_list.approval_mode),
        manifest_approval_name(manifest_list.requires_approval)
    );
    assert_eq!(introspection_list["capability"], "gmail.read");
    assert!(introspection_list["requires_approval"].is_null());

    let generated_send = generated
        .manifest_fragment
        .operations
        .iter()
        .find(|op| op.operation_id == "gmail.users.messages.send")
        .expect("generated send op");
    let manifest_send = manifest
        .provides
        .operations
        .get("gmail.send_message")
        .expect("manifest send op");
    let introspection_send = introspection_ops
        .iter()
        .find(|op| op["id"] == "gmail.send_message")
        .expect("introspection send op");

    assert_eq!(generated_send.capability, "gmail.send");
    assert_eq!(manifest_send.capability.as_str(), generated_send.capability);
    assert_eq!(
        generated_approval_name(generated_send.approval_mode),
        manifest_approval_name(manifest_send.requires_approval)
    );
    assert_eq!(introspection_send["capability"], "gmail.send");
    assert_eq!(introspection_send["requires_approval"], "interactive");

    let generated_history = generated
        .manifest_fragment
        .operations
        .iter()
        .find(|op| op.operation_id == "gmail.users.messages.list_history")
        .expect("generated history op");
    let introspection_history = introspection_ops
        .iter()
        .find(|op| op["id"] == "gmail.sync_history")
        .expect("introspection history op");
    let manifest_history = manifest
        .provides
        .operations
        .get("gmail.sync_history")
        .expect("manifest history op");

    assert_eq!(generated_history.capability, "gmail.read");
    assert_eq!(manifest_history.capability.as_str(), "gmail.history.read");
    assert_eq!(
        manifest_approval_name(manifest_history.requires_approval),
        "none"
    );
    assert_eq!(introspection_history["capability"], "gmail.history.read");
    assert!(introspection_history["requires_approval"].is_null());
}

// ============================================================================
// Replay safety on retry (br-kxd3e)
// ============================================================================
//
// Gmail is the highest-harm case in this sweep: a retried send does not
// duplicate a record somewhere, it puts a SECOND email in a real person's
// inbox, and there is no idempotency key and no way to take it back.
//
// Gmail also models several state changes as POSTs (`modify`, `trash`) which
// only name a target state, so those keep their retries. The pair of tests
// below pins both halves of that distinction.

fn replay_test_client(mock_server: &MockServer) -> GmailClient {
    GmailClient::new("test-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(3, 1, 5)
}

#[fcp_async_core::runtime::test]
async fn send_message_is_not_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/users/me/messages/send"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&mock_server)
        .await;

    let result = replay_test_client(&mock_server).send_message("raw").await;
    assert!(result.is_err());

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a 503 means Gmail received the send — retrying delivers a SECOND \
         email, which cannot be undone"
    );
}

#[fcp_async_core::runtime::test]
async fn modify_message_is_still_retried_after_a_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/users/me/messages/msg1/modify"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/users/me/messages/msg1/modify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg1",
            "threadId": "t1",
            "labelIds": ["INBOX"]
        })))
        .mount(&mock_server)
        .await;

    replay_test_client(&mock_server)
        .modify_message("msg1", &["INBOX".to_string()], &[])
        .await
        .expect("modify names a target label set, so the retry converges");

    let requests = mock_server
        .received_requests()
        .await
        .expect("recorded requests");
    assert_eq!(
        requests.len(),
        2,
        "a POST that names a target state rather than appending keeps its retry"
    );
}
