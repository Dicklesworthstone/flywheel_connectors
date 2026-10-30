//! Local loopback acceptance coverage for the Slack connector.

#![allow(clippy::too_many_lines)]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::CapabilityConstraints;
use fcp_slack::connector::SlackConnector;
use serde_json::{Value, json};
use url::form_urlencoded;

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "fcp.slack";
const FIXTURE_ID: &str = "slack-loopback-local-acceptance";
const TEST_CREDENTIAL_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const CHANNEL_ID: &str = "CLOCALACCEPT";

#[derive(Clone, Debug)]
struct ObservedSlackRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl ObservedSlackRequest {
    fn path_without_query(&self) -> &str {
        self.path.split('?').next().unwrap_or(self.path.as_str())
    }

    fn credential_header_matches(&self) -> bool {
        self.headers
            .get("x-fcp-credential-id")
            .is_some_and(|value| value == TEST_CREDENTIAL_ID)
    }

    fn accepts_json(&self) -> bool {
        self.headers
            .get("accept")
            .is_some_and(|value| value == "application/json")
    }

    fn body_json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("Slack loopback request body should be JSON")
    }
}

struct LoopbackSlackFixture {
    base_url: String,
    observations: Arc<Mutex<Vec<ObservedSlackRequest>>>,
    _join: JoinHandle<()>,
}

impl LoopbackSlackFixture {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Slack loopback listener");
        let address = listener.local_addr().expect("read Slack loopback address");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let observations_for_thread = Arc::clone(&observations);

        let join = thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept Slack loopback request");
                let request = read_http_request(&mut stream);
                let response = response_for_request(&request);
                observations_for_thread
                    .lock()
                    .expect("record Slack loopback request")
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

    fn observations(&self) -> Vec<ObservedSlackRequest> {
        self.observations
            .lock()
            .expect("read Slack loopback observations")
            .clone()
    }
}

#[derive(Debug)]
struct HttpFixtureResponse {
    status: u16,
    body: Value,
}

fn read_http_request(stream: &mut TcpStream) -> ObservedSlackRequest {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut temp).expect("read Slack HTTP request");
        assert!(read > 0, "unexpected EOF while reading Slack request");
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
        let read = stream.read(&mut temp).expect("read Slack request body");
        assert!(read > 0, "unexpected EOF while reading Slack body");
        body.extend_from_slice(&temp[..read]);
    }
    body.truncate(content_length);

    ObservedSlackRequest {
        method,
        path,
        headers,
        body,
    }
}

fn response_for_request(request: &ObservedSlackRequest) -> HttpFixtureResponse {
    match (request.method.as_str(), request.path_without_query()) {
        ("POST", "/chat.postMessage") => HttpFixtureResponse {
            status: 200,
            body: json!({
                "ok": true,
                "channel": CHANNEL_ID,
                "ts": "1700000300.000100",
                "message": {
                    "type": "message",
                    "user": "ULOOPBACK",
                    "text": "Local acceptance message",
                    "ts": "1700000300.000100"
                }
            }),
        },
        ("GET", "/conversations.list") => {
            let query = request.path.split_once('?').map_or("", |(_, query)| query);
            let query_params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect();
            assert_eq!(
                query_params.get("types").map(String::as_str),
                Some("public_channel")
            );
            HttpFixtureResponse {
                status: 200,
                body: json!({
                    "ok": true,
                    "channels": [
                        {
                            "id": CHANNEL_ID,
                            "name": "local-acceptance",
                            "is_channel": true,
                            "is_group": false,
                            "is_im": false,
                            "is_archived": false,
                            "is_private": false,
                            "num_members": 3
                        }
                    ]
                }),
            }
        }
        ("POST", "/conversations.setTopic") => HttpFixtureResponse {
            status: 200,
            body: json!({
                "ok": true,
                "topic": "Local acceptance topic"
            }),
        },
        _ => HttpFixtureResponse {
            status: 500,
            body: json!({
                "ok": false,
                "error": "unexpected_local_acceptance_route"
            }),
        },
    }
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
    .expect("write Slack loopback response");
    stream.flush().expect("flush Slack loopback response");
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &SlackConnector,
    capability: &str,
    operation: &str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id())
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign local acceptance token");
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut SlackConnector) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": [
                "slack.read",
                "slack.write"
            ]
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

#[fcp_async_core::runtime::test]
async fn loopback_acceptance_exercises_write_list_and_topic_paths() {
    let fixture = LoopbackSlackFixture::start(3);
    let mut connector = SlackConnector::new();

    connector
        .handle_configure(json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": fixture.base_url()
        }))
        .await
        .expect("configure connector against loopback Slack fixture");
    let signing_key = setup_handshake(&mut connector).await;

    let posted = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": {
                "channel": CHANNEL_ID,
                "text": "Local acceptance message"
            },
            "capability_token": generate_valid_token(
                &signing_key,
                &connector,
                "slack.write",
                "slack.post_message"
            )
        }))
        .await
        .expect("post message through loopback fixture");
    let channels = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {
                "types": "public_channel"
            },
            "capability_token": generate_valid_token(
                &signing_key,
                &connector,
                "slack.read",
                "slack.list_channels"
            )
        }))
        .await
        .expect("list channels through loopback fixture");
    let topic = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": {
                "channel": CHANNEL_ID,
                "topic": "Local acceptance topic"
            },
            "capability_token": generate_valid_token(
                &signing_key,
                &connector,
                "slack.write",
                "slack.set_channel_topic"
            )
        }))
        .await
        .expect("set channel topic through loopback fixture");

    assert_eq!(posted["message"]["text"], "Local acceptance message");
    assert_eq!(posted["receipt"]["operation"], "slack.post_message");
    assert_eq!(channels["channels"][0]["name"], "local-acceptance");
    assert_eq!(topic["topic"], "Local acceptance topic");
    assert_eq!(topic["receipt"]["operation"], "slack.set_channel_topic");

    let observations = fixture.observations();
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].method, "POST");
    assert_eq!(observations[0].path, "/chat.postMessage");
    assert_eq!(observations[1].method, "GET");
    assert!(observations[1].path.starts_with("/conversations.list?"));
    assert_eq!(observations[2].method, "POST");
    assert_eq!(observations[2].path, "/conversations.setTopic");
    assert!(
        observations
            .iter()
            .all(ObservedSlackRequest::credential_header_matches)
    );
    assert!(observations.iter().all(ObservedSlackRequest::accepts_json));

    let post_body = observations[0].body_json();
    assert_eq!(post_body["channel"], CHANNEL_ID);
    assert_eq!(post_body["text"], "Local acceptance message");

    let topic_body = observations[2].body_json();
    assert_eq!(topic_body["channel"], CHANNEL_ID);
    assert_eq!(topic_body["topic"], "Local acceptance topic");

    let artifact = json!({
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "fixture_mode": "loopback_http",
        "operations": [
            "slack.post_message",
            "slack.list_channels",
            "slack.set_channel_topic"
        ],
        "requests_observed": observations.len(),
        "paths": observations.iter().map(|request| {
            request.path_without_query().to_string()
        }).collect::<Vec<_>>(),
        "credential_header_seen": observations
            .iter()
            .all(ObservedSlackRequest::credential_header_matches),
        "message_text_redacted": true,
        "channel_identifier_redacted": true,
        "topic_text_redacted": true,
        "cleanup": "loopback_fixture_completed_expected_requests",
        "result": "passed"
    });
    println!("{artifact}");
}
