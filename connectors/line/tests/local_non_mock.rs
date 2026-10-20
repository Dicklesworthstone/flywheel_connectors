#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration as StdDuration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_line::connector::LineConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    HandshakeRequest, InstanceId, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const TOKEN: &str = "line-local-token";
const OP_PUSH: &str = "line.messages.push";
const OP_GROUP_MEMBERS: &str = "line.group.members";

#[derive(Debug)]
struct RecordedRequest {
    label: &'static str,
    request_line: String,
    headers: String,
    body: String,
}

struct LoopbackResponse {
    label: &'static str,
    status: u16,
    body: &'static str,
}

impl LoopbackResponse {
    const fn json(label: &'static str, status: u16, body: &'static str) -> Self {
        Self {
            label,
            status,
            body,
        }
    }
}

fn spawn_loopback_server(
    responses: Vec<LoopbackResponse>,
) -> (String, Receiver<RecordedRequest>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind LINE loopback server");
    let address = listener.local_addr().expect("read loopback server address");
    let (sender, receiver) = mpsc::channel();

    let handle = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().expect("accept LINE loopback request");
            let (request_line, headers, body) = read_http_request(&mut stream);
            sender
                .send(RecordedRequest {
                    label: response.label,
                    request_line,
                    headers,
                    body,
                })
                .expect("record LINE loopback request");
            write_http_response(&mut stream, &response);
        }
    });

    (format!("http://{address}"), receiver, handle)
}

fn read_http_request(stream: &mut TcpStream) -> (String, String, String) {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set LINE loopback read timeout");

    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let headers_end = loop {
        let count = stream.read(&mut chunk).expect("read LINE HTTP request");
        assert_ne!(count, 0, "connection closed before HTTP headers arrived");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = find_headers_end(&bytes) {
            break end;
        }
    };

    let headers = String::from_utf8(bytes[..headers_end].to_vec()).expect("headers are UTF-8");
    let request_line = headers
        .lines()
        .next()
        .expect("request line present")
        .to_owned();
    let expected_body_len = content_length(&headers);
    let mut body_bytes = bytes[(headers_end + 4)..].to_vec();
    while body_bytes.len() < expected_body_len {
        let count = stream
            .read(&mut chunk)
            .expect("read LINE HTTP request body");
        assert_ne!(count, 0, "connection closed before request body arrived");
        body_bytes.extend_from_slice(&chunk[..count]);
    }
    body_bytes.truncate(expected_body_len);
    let body = String::from_utf8(body_bytes).expect("body is UTF-8");

    (request_line, headers, body)
}

fn find_headers_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content-length"))
        })
        .unwrap_or(0)
}

fn write_http_response(stream: &mut TcpStream, response: &LoopbackResponse) {
    let body = response.body.as_bytes();
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        status_reason(response.status),
        body.len()
    )
    .expect("write LINE HTTP response headers");
    stream
        .write_all(body)
        .expect("write LINE HTTP response body");
    stream.flush().expect("flush LINE HTTP response");
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        401 => "Unauthorized",
        429 => "Too Many Requests",
        _ => "OK",
    }
}

fn recv_request(receiver: &Receiver<RecordedRequest>, label: &'static str) -> RecordedRequest {
    let request = receiver
        .recv_timeout(StdDuration::from_secs(5))
        .expect("LINE loopback request recorded");
    assert_eq!(request.label, label);
    request
}

fn handshake_req(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [17_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("line.messages.write"),
            CapabilityId::from_static("line.profile.read"),
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
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize capability constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(op))
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor accepted")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("capability token signing succeeds");
    CapabilityToken::from_raw(raw)
}

fn capability_for_operation(op: &str) -> &'static str {
    match op {
        OP_PUSH => "line.messages.write",
        OP_GROUP_MEMBERS => "line.profile.read",
        _ => panic!("unsupported LINE operation in local acceptance harness: {op}"),
    }
}

fn invoke_req(op: &'static str, input: Value, capability_token: CapabilityToken) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new(format!("line-local-{op}")),
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
    let mut connector = LineConnector::new();
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

#[fcp_async_core::runtime::test]
async fn line_loopback_covers_push_and_group_members() {
    let (base_url, requests, server) = spawn_loopback_server(vec![
        LoopbackResponse::json("push", 200, ""),
        LoopbackResponse::json(
            "members",
            200,
            r#"{"memberIds":["U1","U2"],"next":"next-2"}"#,
        ),
    ]);
    let (connector, signing_key, instance_id) = setup_connector(&base_url).await;

    let push = connector
        .invoke(invoke_req(
            OP_PUSH,
            json!({
                "to": "U123",
                "messages": [{
                    "type": "text",
                    "text": "hello from local LINE acceptance"
                }]
            }),
            generate_valid_token(&signing_key, &instance_id, OP_PUSH),
        ))
        .await
        .unwrap();
    assert_eq!(push.status, InvokeStatus::Ok);
    let push_result = push.result.expect("push result");
    assert_eq!(push_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(push_result["coordination"][1]["outcome"], "granted");
    assert_eq!(push_result["coordination"][2]["event"], "send_executed");

    let push_request = recv_request(&requests, "push");
    assert_eq!(
        push_request.request_line,
        "POST /v2/bot/message/push HTTP/1.1"
    );
    assert!(
        push_request
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer line-local-token")
    );
    let push_body: Value = serde_json::from_str(&push_request.body).unwrap();
    assert_eq!(push_body["to"], "U123");
    assert_eq!(push_body["messages"][0]["type"], "text");
    assert_eq!(
        push_body["messages"][0]["text"],
        "hello from local LINE acceptance"
    );

    let members = connector
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
    assert_eq!(members.status, InvokeStatus::Ok);
    let members_result = members.result.expect("group members result");
    assert_eq!(members_result["memberIds"].as_array().unwrap().len(), 2);
    assert_eq!(members_result["memberIds"][0], "U1");
    assert_eq!(members_result["next"], "next-2");

    let members_request = recv_request(&requests, "members");
    assert_eq!(
        members_request.request_line,
        "GET /v2/bot/group/C123/members/ids?start=next-1 HTTP/1.1"
    );
    assert!(
        members_request
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer line-local-token")
    );
    assert!(members_request.body.is_empty());

    server.join().expect("LINE loopback server joins cleanly");
}

#[test]
fn acceptance_suite_class_is_declared() {
    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
}
