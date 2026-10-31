//! Local loopback acceptance coverage for the Google Calendar connector.

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
use fcp_google_calendar::connector::GoogleCalendarConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpError, HandshakeRequest, InstanceId,
    ZoneId,
};
use serde_json::{Value, json};

const LOOPBACK_AUTH_VALUE: &str = "local-calendar-auth-value";
const OP_LIST_CALENDARS: &str = "gcal.list_calendars";
const OP_CREATE_EVENT: &str = "gcal.create_event";
const READ_CAPABILITY: &str = "gcal.read";
const WRITE_CAPABILITY: &str = "gcal.write";
const EXPECTED_LIST_PATH: &str = "/calendar/v3/users/me/calendarList?";
const EXPECTED_SELF_CHECK_PATH: &str = "/calendar/v3/users/me/calendarList?maxResults=1";
const EXPECTED_CREATE_PATH: &str = "/calendar/v3/calendars/primary/events?";

const CALENDAR_LIST_RESPONSE: &str = r#"{
  "kind": "calendar#calendarList",
  "items": [
    {
      "kind": "calendar#calendarListEntry",
      "id": "primary",
      "summary": "Primary Calendar",
      "primary": true,
      "timeZone": "America/New_York"
    },
    {
      "kind": "calendar#calendarListEntry",
      "id": "team@example.com",
      "summary": "Team Calendar",
      "timeZone": "America/Los_Angeles"
    }
  ]
}"#;

const EVENT_CREATE_RESPONSE: &str = r#"{
  "kind": "calendar#event",
  "id": "evt-local-001",
  "status": "confirmed",
  "summary": "Planning review",
  "htmlLink": "https://calendar.google.com/event?eid=evt-local-001",
  "start": {
    "dateTime": "2026-04-01T15:00:00Z"
  },
  "end": {
    "dateTime": "2026-04-01T15:30:00Z"
  }
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: String,
    body: String,
}

impl FixtureObservation {
    fn authorization_seen(&self) -> bool {
        header_seen(
            &self.headers,
            "authorization",
            &format!("Bearer {LOOPBACK_AUTH_VALUE}"),
        )
    }

    fn accept_seen(&self) -> bool {
        header_value_contains(&self.headers, "accept", "application/json")
    }

    fn content_type_json_seen(&self) -> bool {
        header_value_contains(&self.headers, "content-type", "application/json")
    }

    fn user_agent_seen(&self) -> bool {
        header_value_contains(&self.headers, "user-agent", "fcp-google-calendar/0.1.0")
    }
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
            base_url: format!("http://{address}/calendar/v3"),
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

    let (headers, body) = read_http_request(&mut stream);
    let request_line = headers.lines().next().unwrap_or_default().to_string();

    write!(
        stream,
        "HTTP/1.1 {response_status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers,
        body,
    }
}

fn read_http_request(stream: &mut TcpStream) -> (String, String) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector should send request headers");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        assert!(request.len() < 8192, "request headers should stay bounded");
    };

    let header_text = String::from_utf8_lossy(&request[..header_end]).to_string();
    let content_length = content_length(&header_text);
    while request.len() < header_end + content_length {
        let bytes_read = stream.read(&mut buffer).expect("read connector body");
        assert!(bytes_read > 0, "connector body ended before content-length");
        request.extend_from_slice(&buffer[..bytes_read]);
        assert!(request.len() < 65536, "request body should stay bounded");
    }

    let body =
        String::from_utf8_lossy(&request[header_end..header_end + content_length]).to_string();
    (header_text, body)
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                Some(value.trim().parse::<usize>().expect("valid content-length"))
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

fn handshake_req(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [31_u8; 32],
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

async fn setup_connector(
    base_url: &str,
) -> (GoogleCalendarConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = GoogleCalendarConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    connector
        .handle_configure(json!({
            "access_token": LOOPBACK_AUTH_VALUE,
            "base_url": base_url,
            "required_scopes": [
                "https://www.googleapis.com/auth/calendar",
                "https://www.googleapis.com/auth/calendar.events"
            ]
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

    let instance_id = connector.instance_id().parse().expect("actual instance ID");
    (connector, signing_key, instance_id)
}

fn create_event_input() -> Value {
    json!({
        "calendar_id": "primary",
        "summary": "Planning review",
        "description": "Review connector acceptance evidence",
        "location": "Conference room",
        "start": "2026-04-01T15:00:00Z",
        "end": "2026-04-01T15:30:00Z",
        "attendees": [
            { "email": "team@example.com" }
        ]
    })
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_calendars_uses_calendar_request_boundary() {
    let fixture = LoopbackFixture::start("200 OK", CALENDAR_LIST_RESPONSE);
    let (connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let health = connector.handle_health().await.expect("health response");
    assert_eq!(health["status"]["state"], "ready");
    assert_eq!(health["details"]["service_identity"], "calendar:v3");
    assert_eq!(health["details"]["instance_id"], instance_id.as_str());

    let doctor = connector.handle_doctor().await.expect("doctor response");
    assert_eq!(doctor["status"], "healthy");

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection response");
    let operations = introspection["operations"].as_array().expect("operations");
    assert!(operations.iter().any(|operation| {
        operation["id"] == OP_LIST_CALENDARS && operation["capability"] == READ_CAPABILITY
    }));

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "loopback-list",
            "connector_id": "fcp.google-calendar", "zone_id": "z:work",
            "operation": OP_LIST_CALENDARS,
            "input": {},
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                READ_CAPABILITY,
                OP_LIST_CALENDARS,
            )
        }))
        .await
        .expect("list calendars through connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_LIST_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen());
    assert!(observation.accept_seen());
    assert!(!observation.content_type_json_seen());
    assert!(observation.user_agent_seen());
    assert!(observation.body.is_empty());
    assert_eq!(result["calendars"][0]["id"], "primary");
    assert_eq!(result["calendars"][1]["summary"], "Team Calendar");
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-calendar",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.30",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_LIST_CALENDARS,
        "method": "GET",
        "path": EXPECTED_LIST_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen(),
            "instance_bound_token_verified": true
        },
        "headers": {
            "accept_json_seen": observation.accept_seen(),
            "user_agent_seen": observation.user_agent_seen()
        },
        "diagnostics": {
            "health_status": health["status"],
            "doctor_status": doctor["status"]
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_self_check_uses_health_probe_without_secret_leakage() {
    let fixture = LoopbackFixture::start("200 OK", CALENDAR_LIST_RESPONSE);
    let (connector, _, _) = setup_connector(fixture.base_url()).await;

    let report = connector
        .handle_self_check()
        .await
        .expect("self-check response");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_SELF_CHECK_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen());
    assert_eq!(report["status"], "ok");
    assert!(!report.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-calendar",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.30",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": "self_check",
        "method": "GET",
        "path": EXPECTED_SELF_CHECK_PATH,
        "authorization_header_verified": observation.authorization_seen(),
        "secret_leaked": false,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_create_event_posts_calendar_event_body() {
    let fixture = LoopbackFixture::start("200 OK", EVENT_CREATE_RESPONSE);
    let (connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "loopback-create",
            "connector_id": "fcp.google-calendar", "zone_id": "z:work",
            "operation": OP_CREATE_EVENT,
            "input": create_event_input(),
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                WRITE_CAPABILITY,
                OP_CREATE_EVENT,
            )
        }))
        .await
        .expect("create event through connector");
    let observation = fixture.join();
    let body: Value = serde_json::from_str(&observation.body).expect("request body json");

    assert_eq!(
        observation.request_line,
        format!("POST {EXPECTED_CREATE_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen());
    assert!(observation.accept_seen());
    assert!(observation.content_type_json_seen());
    assert!(observation.user_agent_seen());
    assert_eq!(body["summary"], "Planning review");
    assert_eq!(body["description"], "Review connector acceptance evidence");
    assert_eq!(body["start"]["dateTime"], "2026-04-01T15:00:00Z");
    assert_eq!(body["end"]["dateTime"], "2026-04-01T15:30:00Z");
    assert_eq!(body["attendees"][0]["email"], "team@example.com");
    assert_eq!(result["event"]["id"], "evt-local-001");
    assert_eq!(result["event"]["summary"], "Planning review");
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-calendar",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.30",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_CREATE_EVENT,
        "method": "POST",
        "path": EXPECTED_CREATE_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen(),
            "instance_bound_token_verified": true
        },
        "body_shape": {
            "summary_present": body["summary"].is_string(),
            "start_datetime_seen": body["start"]["dateTime"].is_string(),
            "end_datetime_seen": body["end"]["dateTime"].is_string(),
            "attendee_count": body["attendees"].as_array().map_or(0, std::vec::Vec::len)
        },
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
        "http://{}/calendar/v3",
        listener.local_addr().expect("read listener address")
    );
    let (connector, signing_key, instance_id) = setup_connector(&base_url).await;

    let error = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "loopback-denied",
            "connector_id": "fcp.google-calendar", "zone_id": "z:work",
            "operation": OP_CREATE_EVENT,
            "input": create_event_input(),
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                READ_CAPABILITY,
                OP_CREATE_EVENT,
            )
        }))
        .await
        .expect_err("read capability should not authorize event creation");

    assert!(matches!(
        error,
        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
    ));
    let accept_error = listener
        .accept()
        .expect_err("capability denial should happen before loopback egress");
    assert_eq!(accept_error.kind(), io::ErrorKind::WouldBlock);

    let artifact = json!({
        "connector": "google-calendar",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.30",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_CREATE_EVENT,
        "denial": "wrong_capability",
        "loopback_egress_attempted": false,
        "result": "passed"
    });
    println!("{artifact}");
}
