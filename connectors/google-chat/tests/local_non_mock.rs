//! Local loopback acceptance coverage for the Google Chat connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_chat::connector::ChatConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpError, HandshakeRequest, InstanceId,
    ZoneId,
};
use serde_json::{Value, json};

const LOOPBACK_AUTH_VALUE: &str = "local-loopback-auth-value";
const OP_LIST_SPACES: &str = "chat.list_spaces";
const OP_SEND_MESSAGE: &str = "chat.send_message";
const READ_CAPABILITY: &str = "chat.read";
const WRITE_CAPABILITY: &str = "chat.write";
const SPACE_NAME: &str = "spaces/AAAA";
const SEND_TEXT: &str = "Hello from Chat";
const EXPECTED_LIST_PATH: &str = "/v1/spaces";
const EXPECTED_SEND_PATH: &str = "/v1/spaces/AAAA/messages";

const LIST_SPACES_RESPONSE: &str = r#"{
  "spaces": [
    {
      "name": "spaces/AAAA",
      "displayName": "Engineering",
      "spaceType": "ROOM",
      "threaded": true
    }
  ]
}"#;

const SEND_MESSAGE_RESPONSE: &str = r#"{
  "name": "spaces/AAAA/messages/msg1",
  "text": "Hello from Chat",
  "createTime": "2026-05-14T00:00:00Z"
}"#;

const UNAUTHORIZED_RESPONSE: &str = r#"{
  "error": {
    "code": 401,
    "message": "invalid credentials",
    "status": "UNAUTHENTICATED"
  }
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    user_agent_seen: bool,
    content_type_json_seen: bool,
    body: String,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start(response_status: &'static str, response_body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream, response_status, response_body)
        });

        Self {
            base_url: format!("http://{address}/v1"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> FixtureObservation {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(
    mut stream: TcpStream,
    response_status: &str,
    response_body: &str,
) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let authorization_seen = header_seen(
        &request.headers,
        "authorization",
        &format!("Bearer {LOOPBACK_AUTH_VALUE}"),
    );
    let user_agent_seen =
        header_value_contains(&request.headers, "user-agent", "fcp-google-chat/0.1.0");
    let content_type_json_seen =
        header_value_contains(&request.headers, "content-type", "application/json");

    write!(
        stream,
        "HTTP/1.1 {response_status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    )
    .expect("write connector response");

    FixtureObservation {
        request_line: request.request_line,
        authorization_seen,
        user_agent_seen,
        content_type_json_seen,
        body: request.body,
    }
}

struct HttpRequest {
    request_line: String,
    headers: String,
    body: String,
}

fn read_http_request(stream: &mut TcpStream) -> HttpRequest {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector should send request bytes");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = find_header_end(&request) {
            break header_end;
        }
        assert!(request.len() < 8192, "request headers should stay bounded");
    };

    let header_bytes = &request[..header_end + 4];
    let headers = String::from_utf8_lossy(header_bytes).to_string();
    let content_length = content_length_from_headers(&headers);
    let mut body = request[header_end + 4..].to_vec();
    while body.len() < content_length {
        let bytes_read = stream.read(&mut buffer).expect("read connector body");
        assert!(bytes_read > 0, "connector body should match content-length");
        body.extend_from_slice(&buffer[..bytes_read]);
        assert!(body.len() <= 8192, "request body should stay bounded");
    }
    body.truncate(content_length);

    HttpRequest {
        request_line: headers.lines().next().unwrap_or_default().to_string(),
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length_from_headers(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn header_seen(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn header_value_contains(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name)
            && value
                .to_ascii_lowercase()
                .contains(&expected_value.to_ascii_lowercase())
    })
}

fn assert_request_boundary(request_line: &str, expected_method: &str, expected_path: &str) {
    let mut parts = request_line.split_whitespace();
    assert_eq!(parts.next(), Some(expected_method));
    let target = parts.next().expect("request target should be present");
    assert_eq!(parts.next(), Some("HTTP/1.1"));
    assert_eq!(parts.next(), None);

    let target_without_empty_query = target.strip_suffix('?').unwrap_or(target);
    assert_eq!(target_without_empty_query, expected_path);
    assert!(
        !target_without_empty_query.contains('?'),
        "request target should not include query parameters"
    );
}

fn handshake_req(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "1.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [41_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(READ_CAPABILITY),
            CapabilityId::from_static(WRITE_CAPABILITY),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (ChatConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = ChatConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = connector
        .instance_id()
        .parse::<InstanceId>()
        .expect("connector instance id should parse");

    connector
        .handle_configure(json!({
            "access_token": LOOPBACK_AUTH_VALUE,
            "base_url": base_url
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(
            serde_json::to_value(handshake_req(
                signing_key.verifying_key().to_bytes(),
                &instance_id,
            ))
            .expect("serialize handshake request"),
        )
        .await
        .expect("handshake connector");

    (connector, signing_key, instance_id)
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_spaces_uses_chat_request_boundary() {
    let fixture = LoopbackFixture::start("200 OK", LIST_SPACES_RESPONSE);
    let (mut connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": OP_LIST_SPACES,
            "input": {},
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                READ_CAPABILITY,
                OP_LIST_SPACES,
            )
        }))
        .await
        .expect("list spaces through connector");
    let observation = fixture.join();

    assert_request_boundary(&observation.request_line, "GET", EXPECTED_LIST_PATH);
    assert!(observation.authorization_seen);
    assert!(observation.user_agent_seen);
    assert_eq!(result["spaces"][0]["name"], SPACE_NAME);
    assert_eq!(result["spaces"][0]["displayName"], "Engineering");
    assert_eq!(result["spaces"][0]["spaceType"], "ROOM");
    assert_eq!(result["spaces"][0]["threaded"], true);
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-chat",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.32",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_LIST_SPACES,
        "method": "GET",
        "path": EXPECTED_LIST_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen
        },
        "headers": {
            "user_agent_seen": observation.user_agent_seen
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_send_message_posts_json_boundary() {
    let fixture = LoopbackFixture::start("200 OK", SEND_MESSAGE_RESPONSE);
    let (mut connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": OP_SEND_MESSAGE,
            "input": {
                "space_name": SPACE_NAME,
                "text": SEND_TEXT
            },
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                WRITE_CAPABILITY,
                OP_SEND_MESSAGE,
            )
        }))
        .await
        .expect("send message through connector");
    let observation = fixture.join();
    let body: Value = serde_json::from_str(&observation.body).expect("parse request body");

    assert_request_boundary(&observation.request_line, "POST", EXPECTED_SEND_PATH);
    assert!(observation.authorization_seen);
    assert!(observation.user_agent_seen);
    assert!(observation.content_type_json_seen);
    assert_eq!(body["text"], SEND_TEXT);
    assert_eq!(result["message"]["name"], "spaces/AAAA/messages/msg1");
    assert_eq!(result["message"]["text"], SEND_TEXT);
    assert_eq!(result["message"]["createTime"], "2026-05-14T00:00:00Z");
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-chat",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.32",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_SEND_MESSAGE,
        "method": "POST",
        "path": EXPECTED_SEND_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen
        },
        "headers": {
            "content_type_json_seen": observation.content_type_json_seen,
            "user_agent_seen": observation.user_agent_seen
        },
        "body": {
            "text_verified": body["text"] == SEND_TEXT
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_error_does_not_leak_auth_material() {
    let fixture = LoopbackFixture::start("401 Unauthorized", UNAUTHORIZED_RESPONSE);
    let (mut connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation": OP_LIST_SPACES,
            "input": {},
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                READ_CAPABILITY,
                OP_LIST_SPACES,
            )
        }))
        .await
        .expect_err("401 should map to unauthorized");
    let observation = fixture.join();

    assert!(observation.authorization_seen);
    assert!(matches!(error, FcpError::Unauthorized { .. }));
    assert!(!error.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-chat",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.32",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_LIST_SPACES,
        "error_mapping": "unauthorized",
        "authorization_header_verified": observation.authorization_seen,
        "auth_material_leaked": false,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_wrong_capability_fails_before_loopback_egress() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let base_url = format!(
        "http://{}/v1",
        listener.local_addr().expect("read listener address")
    );
    let (mut connector, signing_key, instance_id) = setup_connector(&base_url).await;

    let error = connector
        .handle_invoke(json!({
            "operation": OP_LIST_SPACES,
            "input": {},
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                WRITE_CAPABILITY,
                OP_LIST_SPACES,
            )
        }))
        .await
        .expect_err("write capability should not authorize space listing");

    assert!(matches!(
        error,
        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
    ));
    let accept_error = listener
        .accept()
        .expect_err("capability denial should happen before loopback egress");
    assert_eq!(accept_error.kind(), io::ErrorKind::WouldBlock);

    let artifact = json!({
        "connector": "google-chat",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.32",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_LIST_SPACES,
        "denial": "wrong_capability",
        "loopback_egress_attempted": false,
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn send_message_lost_receipt_exposes_a_terminal_unknown_outcome() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/v1", listener.local_addr().unwrap());
    let (mut connector, signer, instance) = setup_connector(&base).await;
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        read_http_request(&mut stream)
    });
    let error = connector.handle_invoke(json!({
        "operation": OP_SEND_MESSAGE,
        "input": { "space_name": SPACE_NAME, "text": SEND_TEXT },
        "capability_token": capability_token(&signer, &instance, WRITE_CAPABILITY, OP_SEND_MESSAGE)
    })).await.unwrap_err();
    let request = peer.join().unwrap();
    assert_request_boundary(&request.request_line, "POST", EXPECTED_SEND_PATH);
    assert_eq!(serde_json::from_str::<Value>(&request.body).unwrap()["text"], SEND_TEXT);
    assert!(matches!(error, FcpError::External { retryable: false, retry_after: None, message, .. }
        if message.contains("message creation outcome unknown")));
}

#[fcp_async_core::runtime::test]
async fn compound_media_send_records_which_write_completed() {
    use wiremock::{MockServer, Mock, ResponseTemplate, matchers::{method, path}};

    let op = "chat.send_media_message";
    let token = "opaque-upload-token";
    for (upload_status, send_status, expected_count) in [(429, 0, 1), (500, 0, 1), (200, 429, 2), (200, 500, 2), (200, 200, 2)] {
        let server = MockServer::start().await;
        let upload = if upload_status == 200 {
            json!({"attachmentDataRef": {"attachmentUploadToken": token}})
        } else {
            json!({"error": {"code": if upload_status == 500 { 429 } else { 500 }, "message": "rejected"}})
        };
        Mock::given(method("POST"))
            .and(path("/adapter/upload/v1/spaces/AAAA/attachments:upload"))
            .respond_with(ResponseTemplate::new(upload_status).insert_header("Retry-After", "121").set_body_json(upload))
            .expect(1).mount(&server).await;
        if send_status != 0 {
            Mock::given(method("POST"))
                .and(path("/adapter/spaces/AAAA/messages"))
                .respond_with(ResponseTemplate::new(send_status).set_body_json(json!({"error":{"code":429,"message":token}})))
                .expect(1).mount(&server).await;
        }
        // The configured prefix deliberately does not end in /v1. Upload
        // and send must both use the explicitly configured origin and prefix.
        let (mut connector, signer, instance) = setup_connector(&format!("{}/adapter", server.uri())).await;
        let error = connector.handle_invoke(json!({
            "operation": op,
            "input": {"space_name": SPACE_NAME, "filename":"a.txt", "content_type":"text/plain", "content_base64":"YQ=="},
            "capability_token": capability_token(&signer, &instance, WRITE_CAPABILITY, op)
        })).await.unwrap_err();
        if upload_status == 429 {
            assert!(matches!(error, FcpError::RateLimited { retry_after_ms: 121_000, .. }));
        } else {
            assert!(!error.is_retryable());
            let diagnostic = error.to_string();
            assert!(!diagnostic.contains(token));
            if upload_status == 500 {
                assert!(diagnostic.contains("attachment upload outcome unknown"));
            } else {
                assert!(diagnostic.contains("accepted the attachment upload"));
                assert!(diagnostic.contains(if send_status == 429 { "message was not sent" } else { "delivery is unknown" }));
            }
        }
        assert_eq!(server.received_requests().await.unwrap().len(), expected_count);
        server.verify().await;
    }
}
