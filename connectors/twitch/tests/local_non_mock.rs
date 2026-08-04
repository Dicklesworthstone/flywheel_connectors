//! Local loopback acceptance coverage for the FCP Twitch connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_twitch::TwitchConnector;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.49";
const CONNECTOR_ID: &str = "fcp.twitch";
const CLIENT_ID: &str = "local-twitch-client";
const CLIENT_SECRET: &str = "local_twitch_acceptance_secret";
const ACCESS_TOKEN: &str = "local-twitch-access-token";
const READ_CAPABILITY: &str = "twitch.read";
const ZONE: &str = "z:private";
const OP_STREAMS_LIST: &str = "twitch.streams.list";
const OP_USERS_GET: &str = "twitch.users.get";

const TOKEN_RESPONSE_BODY: &str = r#"{
  "access_token": "local-twitch-access-token",
  "expires_in": 3600,
  "token_type": "bearer"
}"#;

const STREAMS_RESPONSE_BODY: &str = r#"{
  "data": [
    {
      "id": "stream-1",
      "user_id": "12345",
      "user_login": "fixture_login",
      "user_name": "FixtureBroadcaster",
      "game_id": "509658",
      "game_name": "Just Chatting",
      "type": "live",
      "title": "Fixture stream",
      "viewer_count": 42,
      "started_at": "2026-05-14T02:00:00Z",
      "language": "en",
      "tags": ["English"],
      "is_mature": false
    }
  ],
  "pagination": {
    "cursor": "next"
  }
}"#;

const USERS_RESPONSE_BODY: &str = r#"{
  "data": [
    {
      "id": "12345",
      "login": "fixture_login",
      "display_name": "FixtureBroadcaster",
      "type": "",
      "broadcaster_type": "partner",
      "description": "fixture user",
      "profile_image_url": "https://static-cdn.jtvnw.net/user.png",
      "offline_image_url": "https://static-cdn.jtvnw.net/offline.png",
      "view_count": 99,
      "created_at": "2026-05-14T01:00:00Z"
    }
  ]
}"#;

const RATE_LIMIT_BODY: &str = r#"{
  "status": 429,
  "message": "rate limited"
}"#;

#[derive(Debug, Clone, Copy)]
struct ResponseSpec {
    status: u16,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
}

impl ResponseSpec {
    const fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            headers: &[],
            body,
        }
    }

    const fn with_headers(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: &'static str,
    ) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Twitch listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, response)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn token_url(&self) -> String {
        format!("{}/oauth2/token", self.base_url)
    }

    fn validate_url(&self) -> String {
        format!("{}/oauth2/validate", self.base_url)
    }

    fn join(mut self) -> Vec<RequestObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set read timeout");

    let raw = read_http_message(&mut stream);
    let header_end = find_header_end(&raw).expect("request contains header terminator");
    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();
    let body = String::from_utf8_lossy(&raw[header_end + 4..]).to_string();

    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        status_reason(response.status),
        response.body.len()
    )
    .expect("write response headers");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write extra response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");

    RequestObservation {
        request_line,
        headers,
        body,
    }
}

fn read_http_message(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let total_len = header_end + 4 + content_length(&headers);
            while request.len() < total_len {
                let bytes_read = stream
                    .read(&mut buffer)
                    .expect("read connector request body");
                assert!(bytes_read > 0, "connector body should not close early");
                request.extend_from_slice(&buffer[..bytes_read]);
                assert!(request.len() < 16384, "request body should stay bounded");
            }
            request.truncate(total_len);
            return request;
        }

        assert!(request.len() < 16384, "request headers should stay bounded");
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("content-length is usize")
            })
        })
        .unwrap_or(0)
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        429 => "Too Many Requests",
        _ => "Status",
    }
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    headers.iter().any(|line| {
        let Some((actual_name, actual_value)) = line.split_once(':') else {
            return false;
        };
        actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == expected_value
    })
}

fn assert_header(headers: &[String], name: &str, expected_value: &str) {
    assert!(
        has_header(headers, name, expected_value),
        "expected header {name}: {expected_value}, got {headers:?}"
    );
}

fn assert_helix_headers(observation: &RequestObservation) {
    let expected_auth = format!("Bearer {ACCESS_TOKEN}");
    assert_header(&observation.headers, "authorization", &expected_auth);
    assert_header(&observation.headers, "client-id", CLIENT_ID);
}

fn request_path(request_line: &str) -> &str {
    request_line.split_whitespace().nth(1).unwrap_or_default()
}

fn request_route(request_line: &str) -> &str {
    request_path(request_line)
        .split_once('?')
        .map_or_else(|| request_path(request_line), |(path, _)| path)
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    operation: &str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(READ_CAPABILITY)
        .zone_id(ZONE)
        .principal("twitch-local-acceptance")
        .issuer("node:loopback")
        .operations(&[operation])
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
        .target_instance(instance_id.as_str())
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str, token_url: &str, validate_url: &str) -> TwitchConnector {
    let mut connector = TwitchConnector::new();
    connector
        .configure(json!({
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "base_url": base_url,
            "token_url": token_url,
            "validate_url": validate_url,
            "request_timeout_ms": 1_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter": false
            }
        }))
        .await
        .expect("configure connector");
    connector
}

async fn handshake(connector: &mut TwitchConnector) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let response = connector
        .handshake(HandshakeRequest {
            protocol_version: "1.0.0".into(),
            zone: ZoneId::private(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [7; 32],
            capabilities_requested: vec![CapabilityId::from_static(READ_CAPABILITY)],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake connector");
    assert_eq!(response.status, "accepted");
    signing_key
}

async fn invoke(
    connector: &TwitchConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let token = capability_token(signing_key, operation, connector.instance_id());
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::random(),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::new(operation).expect("operation id should be canonical"),
            zone_id: ZoneId::private(),
            input,
            capability_token: token,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: Some(1_000),
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await?;
    Ok(response.result.unwrap_or_else(|| json!({})))
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_oauth_streams_and_user_requests_cross_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, TOKEN_RESPONSE_BODY),
        ResponseSpec::json(200, STREAMS_RESPONSE_BODY),
        ResponseSpec::json(200, USERS_RESPONSE_BODY),
    ]);
    let mut connector = setup_connector(
        fixture.base_url(),
        &fixture.token_url(),
        &fixture.validate_url(),
    )
    .await;
    let signing_key = handshake(&mut connector).await;

    let streams = invoke(
        &connector,
        &signing_key,
        OP_STREAMS_LIST,
        json!({"game_id": "509658", "user_login": "fixture_login", "first": 2}),
    )
    .await
    .expect("streams list should succeed");
    assert_eq!(streams["count"], 1);
    assert_eq!(streams["streams"][0]["id"], "stream-1");
    assert_eq!(streams["streams"][0]["viewer_count"], 42);

    let user = invoke(
        &connector,
        &signing_key,
        OP_USERS_GET,
        json!({"login": "fixture_login"}),
    )
    .await
    .expect("user lookup should succeed");
    assert_eq!(user["id"], "12345");
    assert_eq!(user["login"], "fixture_login");
    assert_eq!(user["display_name"], "FixtureBroadcaster");

    let observations = fixture.join();
    assert_eq!(observations.len(), 3);

    // The client-credentials parameters travel in a form-encoded BODY, never in
    // the query string. That is a deliberate secrecy property, not a style
    // choice: reqwest's `Error` `Display` impl appends the full request URL, so
    // a `client_secret` in the query would leak into every transport-error
    // message and log line. See the comment on `TwitchClient::acquire_token`.
    let token_request = &observations[0];
    assert_eq!(token_request.request_line, "POST /oauth2/token HTTP/1.1");
    assert_header(
        &token_request.headers,
        "content-type",
        "application/x-www-form-urlencoded",
    );
    assert!(
        token_request
            .body
            .contains(&format!("client_id={CLIENT_ID}"))
    );
    assert!(token_request.body.contains("grant_type=client_credentials"));
    assert!(
        token_request
            .body
            .contains(&format!("client_secret={CLIENT_SECRET}"))
    );
    // Pin the leak-safety property itself: nothing secret may reach the URL.
    assert!(
        !token_request.request_line.contains(CLIENT_SECRET),
        "client_secret must never appear in the request line: {}",
        token_request.request_line
    );
    assert!(
        !token_request.request_line.contains(CLIENT_ID),
        "client_id must never appear in the request line: {}",
        token_request.request_line
    );

    let streams_request = &observations[1];
    assert_eq!(
        streams_request.request_line,
        "GET /helix/streams?game_id=509658&user_login=fixture_login&first=2 HTTP/1.1"
    );
    assert_helix_headers(streams_request);
    assert!(streams_request.body.is_empty());

    let user_request = &observations[2];
    assert_eq!(
        user_request.request_line,
        "GET /helix/users?login=fixture_login HTTP/1.1"
    );
    assert_helix_headers(user_request);
    assert!(user_request.body.is_empty());

    let evidence = json!({
        "suite": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "connector": "twitch",
        "operations": [OP_STREAMS_LIST, OP_USERS_GET],
        "request_paths": [
            request_route(&token_request.request_line),
            request_path(&streams_request.request_line),
            request_path(&user_request.request_line),
        ],
        "capability_token_verified": true,
        "required_headers_verified": ["authorization", "client-id"],
        "stream_count": streams["count"],
        "user_id": user["id"],
    });
    let evidence_text = evidence.to_string();
    assert!(!evidence_text.contains(CLIENT_SECRET));
    assert!(!evidence_text.contains(ACCESS_TOKEN));
    println!("{evidence}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_metadata() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, TOKEN_RESPONSE_BODY),
        ResponseSpec::with_headers(429, &[("ratelimit-reset", "2")], RATE_LIMIT_BODY),
    ]);
    let mut connector = setup_connector(
        fixture.base_url(),
        &fixture.token_url(),
        &fixture.validate_url(),
    )
    .await;
    let signing_key = handshake(&mut connector).await;

    let limited = invoke(
        &connector,
        &signing_key,
        OP_STREAMS_LIST,
        json!({"user_login": "fixture_login"}),
    )
    .await
    .expect_err("rate limit should fail");
    let limited_debug = format!("{limited:?}");
    assert!(!limited_debug.contains(CLIENT_SECRET));
    assert!(!limited_debug.contains(ACCESS_TOKEN));
    let retry_after_ms = match limited {
        FcpError::RateLimited {
            retry_after_ms,
            violation,
        } => {
            assert!(violation.is_none());
            retry_after_ms
        }
        other => panic!("expected rate limit, got {other:?}"),
    };
    assert_eq!(retry_after_ms, 2_000);

    let observations = fixture.join();
    assert_eq!(observations.len(), 2);
    let request = &observations[1];
    assert_eq!(
        request.request_line,
        "GET /helix/streams?user_login=fixture_login HTTP/1.1"
    );
    assert_helix_headers(request);
    assert!(request.body.is_empty());

    let evidence = json!({
        "suite": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "connector": "twitch",
        "operation": OP_STREAMS_LIST,
        "request_path": request_path(&request.request_line),
        "error_class": "rate_limited",
        "retry_after_ms": retry_after_ms,
        "secret_redaction_checked": true,
    });
    let evidence_text = evidence.to_string();
    assert!(!evidence_text.contains(CLIENT_SECRET));
    assert!(!evidence_text.contains(ACCESS_TOKEN));
    assert!(!evidence_text.contains("rate limited"));
    println!("{evidence}");
}
