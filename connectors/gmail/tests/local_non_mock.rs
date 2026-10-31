//! Local loopback acceptance coverage for the Gmail connector.

#![allow(clippy::too_many_lines)]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration as StdDuration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_gmail::connector::GmailConnector;
use fcp_google_discovery::auth::FCP_CREDENTIAL_ID_HEADER;
use fcp_prelude::{CapabilityConstraints, CapabilityToken};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "gmail";
const FIXTURE_ID: &str = "gmail-loopback-local-acceptance";
const TEST_CREDENTIAL_ID: &str = "00000000-0000-0000-0000-000000000001";
const MESSAGE_ID: &str = "msg-local-acceptance";
const THREAD_ID: &str = "thread-local-acceptance";
const RAW_MESSAGE: &str = "RnJvbTogbG9vcGJhY2tAZXhhbXBsZS5pbnZhbGlkDQpUbzogbG9vcGJhY2tAZXhhbXBsZS5pbnZhbGlkDQoNCkxvY2FsIGFjY2VwdGFuY2U=";

#[derive(Clone, Debug)]
struct ObservedGmailRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl ObservedGmailRequest {
    fn path_without_query(&self) -> &str {
        self.path.split('?').next().unwrap_or(self.path.as_str())
    }

    fn credential_header_matches(&self) -> bool {
        self.headers
            .get(FCP_CREDENTIAL_ID_HEADER)
            .is_some_and(|value| value == TEST_CREDENTIAL_ID)
    }

    fn accepts_json(&self) -> bool {
        self.headers
            .get("accept")
            .is_some_and(|value| value == "application/json")
    }

    fn body_json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("Gmail loopback request body should be JSON")
    }
}

struct LoopbackGmailFixture {
    base_url: String,
    observations: Arc<Mutex<Vec<ObservedGmailRequest>>>,
    _join: JoinHandle<()>,
}

impl LoopbackGmailFixture {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Gmail loopback listener");
        let address = listener.local_addr().expect("read Gmail loopback address");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let observations_for_thread = Arc::clone(&observations);

        let join = thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept Gmail loopback request");
                let request = read_http_request(&mut stream);
                let response = response_for_request(&request);
                observations_for_thread
                    .lock()
                    .expect("record Gmail loopback request")
                    .push(request);
                write_http_response(&mut stream, &response);
            }
        });

        Self {
            base_url: format!("http://{address}"),
            observations,
            _join: join,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn observations(&self) -> Vec<ObservedGmailRequest> {
        self.observations
            .lock()
            .expect("read Gmail loopback observations")
            .clone()
    }
}

#[derive(Debug)]
struct HttpFixtureResponse {
    status: u16,
    body: Value,
}

fn read_http_request(stream: &mut TcpStream) -> ObservedGmailRequest {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(2)))
        .expect("set Gmail loopback read timeout");
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut temp).expect("read Gmail HTTP request");
        assert!(read > 0, "unexpected EOF while reading Gmail request");
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let header_text = std::str::from_utf8(&buffer[..header_end]).expect("headers are UTF-8");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line present");
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts
        .next()
        .expect("method present")
        .to_string();
    let path = request_line_parts.next().expect("path present").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').expect("header separator");
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut temp).expect("read Gmail request body");
        assert!(read > 0, "unexpected EOF while reading Gmail body");
        body.extend_from_slice(&temp[..read]);
    }
    body.truncate(content_length);

    ObservedGmailRequest {
        method,
        path,
        headers,
        body,
    }
}

fn response_for_request(request: &ObservedGmailRequest) -> HttpFixtureResponse {
    match (request.method.as_str(), request.path_without_query()) {
        ("GET", "/users/me/labels") => HttpFixtureResponse {
            status: 200,
            body: json!({
                "labels": [
                    {"id": "INBOX", "name": "INBOX", "type": "system"},
                    {"id": "SENT", "name": "SENT", "type": "system"}
                ]
            }),
        },
        ("GET", "/users/me/messages/msg-local-acceptance") => HttpFixtureResponse {
            status: 200,
            body: gmail_message_response(MESSAGE_ID, THREAD_ID),
        },
        ("POST", "/users/me/messages/send") => HttpFixtureResponse {
            status: 200,
            body: gmail_message_response("msg-local-sent", "thread-local-sent"),
        },
        _ => HttpFixtureResponse {
            status: 500,
            body: json!({
                "error": {
                    "code": 500,
                    "message": "unexpected Gmail local acceptance route"
                }
            }),
        },
    }
}

fn gmail_message_response(message_id: &str, thread_id: &str) -> Value {
    json!({
        "id": message_id,
        "threadId": thread_id,
        "labelIds": ["INBOX"],
        "snippet": "Local acceptance snippet",
        "historyId": "12345",
        "internalDate": "1700000000000",
        "sizeEstimate": 1234,
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "Subject", "value": "Local acceptance"},
                {"name": "From", "value": "loopback@example.invalid"},
                {"name": "To", "value": "loopback@example.invalid"}
            ],
            "body": {
                "size": 100,
                "data": "TG9jYWwgYWNjZXB0YW5jZQ"
            }
        }
    })
}

fn write_http_response(stream: &mut TcpStream, response: &HttpFixtureResponse) {
    let reason = match response.status {
        200 => "OK",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let body = response.body.to_string();
    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        reason,
        body.len(),
        body
    )
    .expect("write Gmail loopback response");
    stream.flush().expect("flush Gmail loopback response");
}

fn capability_for_operation(operation: &str) -> &'static str {
    match operation {
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
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:private")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign local acceptance token");
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut GmailConnector) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:private",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": [
                "gmail.read",
                "gmail.send"
            ]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

#[fcp_async_core::runtime::test]
async fn loopback_acceptance_exercises_label_read_message_read_and_send_paths() {
    let fixture = LoopbackGmailFixture::start(3);
    let mut connector = GmailConnector::new();

    connector
        .handle_configure(json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": fixture.base_url()
        }))
        .await
        .expect("configure connector against loopback Gmail fixture");
    let signing_key = setup_handshake(&mut connector).await;

    let labels = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "loopback-labels",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.list_labels",
            "input": {},
            "capability_token": generate_valid_token(
                &signing_key,
                &connector,
                "gmail.list_labels"
            )
        }))
        .await
        .expect("list labels through loopback fixture");
    let read_message = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "loopback-message",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.get_message",
            "input": {
                "message_id": MESSAGE_ID
            },
            "capability_token": generate_valid_token(
                &signing_key,
                &connector,
                "gmail.get_message"
            )
        }))
        .await
        .expect("get message through loopback fixture");
    let sent_message = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "loopback-send",
            "connector_id": "fcp.gmail", "zone_id": "z:private",
            "operation": "gmail.send_message",
            "input": {
                "raw": RAW_MESSAGE
            },
            "capability_token": generate_valid_token(
                &signing_key,
                &connector,
                "gmail.send_message"
            )
        }))
        .await
        .expect("send message through loopback fixture");

    assert_eq!(labels["labels"][0]["id"], "INBOX");
    assert_eq!(read_message["message"]["id"], MESSAGE_ID);
    assert_eq!(read_message["message"]["threadId"], THREAD_ID);
    assert_eq!(sent_message["message"]["id"], "msg-local-sent");

    let observations = fixture.observations();
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].method, "GET");
    assert_eq!(observations[0].path_without_query(), "/users/me/labels");
    assert_eq!(observations[1].method, "GET");
    assert_eq!(
        observations[1].path_without_query(),
        "/users/me/messages/msg-local-acceptance"
    );
    assert_eq!(observations[2].method, "POST");
    assert_eq!(
        observations[2].path_without_query(),
        "/users/me/messages/send"
    );
    assert!(
        observations
            .iter()
            .all(ObservedGmailRequest::credential_header_matches)
    );
    assert!(observations.iter().all(ObservedGmailRequest::accepts_json));

    let send_body = observations[2].body_json();
    assert_eq!(send_body["raw"], RAW_MESSAGE);

    let artifact = json!({
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "fixture_mode": "loopback_http",
        "operations": [
            "gmail.list_labels",
            "gmail.get_message",
            "gmail.send_message"
        ],
        "requests_observed": observations.len(),
        "path_classes": [
            "labels_list",
            "message_read",
            "message_send"
        ],
        "credential_header_seen": observations
            .iter()
            .all(ObservedGmailRequest::credential_header_matches),
        "message_ids_redacted": true,
        "thread_ids_redacted": true,
        "email_addresses_redacted": true,
        "message_content_redacted": true,
        "cleanup": "loopback_fixture_completed_expected_requests",
        "result": "passed"
    });
    println!("{artifact}");
}
