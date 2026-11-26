//! Local loopback acceptance coverage for the Google Admin Reports connector.

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
use fcp_google_admin_reports::connector::AdminReportsConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpError, HandshakeRequest, InstanceId,
    ZoneId,
};
use serde_json::{Value, json};

const LOOPBACK_AUTH_VALUE: &str = "local-loopback-auth-value";
const OP_LIST_ACTIVITIES: &str = "admin.list_activities";
const AUDIT_CAPABILITY: &str = "admin.reports.audit.read";
const USAGE_CAPABILITY: &str = "admin.reports.usage.read";
const EXPECTED_PATH: &str = "/admin/reports/v1/activity/users/all/applications/login?customerId=C123&endTime=2026-03-26T00%3A00%3A00Z&eventName=login_success&filters=ip_address%3D%3D203.0.113.10&groupIdFilter=engineering%40example.com&maxResults=2&orgUnitID=%2FEngineering&pageToken=activity-page-1&startTime=2026-03-25T00%3A00%3A00Z";

const SUCCESS_RESPONSE: &str = r#"{
  "kind": "admin#reports#activities",
  "nextPageToken": "activity-page-2",
  "items": [
    {
      "kind": "admin#reports#activity",
      "id": {
        "time": "2026-03-25T12:00:00Z",
        "uniqueQualifier": "activity-1",
        "applicationName": "login",
        "customerId": "C123"
      },
      "actor": {
        "email": "admin@example.com",
        "callerType": "USER"
      },
      "events": [
        {
          "type": "login",
          "name": "login_success",
          "parameters": [
            {
              "name": "login_type",
              "value": "google_password"
            }
          ]
        }
      ],
      "ipAddress": "203.0.113.10"
    }
  ]
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
    accept_seen: bool,
    user_agent_seen: bool,
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
            base_url: format!("http://{address}/admin/reports/v1"),
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

    let request = read_http_headers(&mut stream);
    let headers = String::from_utf8_lossy(&request);
    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let authorization_seen = header_seen(
        &headers,
        "authorization",
        &format!("Bearer {LOOPBACK_AUTH_VALUE}"),
    );
    let accept_seen = header_value_contains(&headers, "accept", "application/json");
    let user_agent_seen =
        header_value_contains(&headers, "user-agent", "fcp-google-admin-reports/0.1.0");

    write!(
        stream,
        "HTTP/1.1 {response_status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        accept_seen,
        user_agent_seen,
    }
}

fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector should send request headers");
        request.extend_from_slice(&buffer[..bytes_read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return request;
        }
        assert!(request.len() < 8192, "request headers should stay bounded");
    }
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
        protocol_version: "1.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [29_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(AUDIT_CAPABILITY)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
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
        .operations(&[OP_LIST_ACTIVITIES])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (AdminReportsConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = AdminReportsConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    connector
        .handle_configure(json!({
            "access_token": LOOPBACK_AUTH_VALUE,
            "base_url": base_url,
            "required_scopes": [
                "https://www.googleapis.com/auth/admin.reports.audit.readonly"
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

    (connector, signing_key, instance_id)
}

fn activity_input() -> Value {
    json!({
        "user_key": "all",
        "application_name": "login",
        "start_time": "2026-03-25T00:00:00Z",
        "end_time": "2026-03-26T00:00:00Z",
        "event_name": "login_success",
        "filters": "ip_address==203.0.113.10",
        "max_results": 2,
        "page_token": "activity-page-1",
        "customer_id": "C123",
        "org_unit_id": "/Engineering",
        "group_id_filter": "engineering@example.com"
    })
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_activities_uses_admin_reports_request_boundary() {
    let fixture = LoopbackFixture::start("200 OK", SUCCESS_RESPONSE);
    let (connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": OP_LIST_ACTIVITIES,
            "input": activity_input(),
            "capability_token": capability_token(&signing_key, &instance_id, AUDIT_CAPABILITY)
        }))
        .await
        .expect("list activities through connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert!(observation.accept_seen);
    assert!(observation.user_agent_seen);
    assert_eq!(result["next_page_token"], "activity-page-2");
    assert_eq!(result["items"][0]["id"]["applicationName"], "login");
    assert_eq!(result["items"][0]["actor"]["email"], "admin@example.com");
    assert_eq!(result["items"][0]["ipAddress"], "203.0.113.10");
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-admin-reports",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.29",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_LIST_ACTIVITIES,
        "method": "GET",
        "path": EXPECTED_PATH,
        "request_line": observation.request_line,
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen
        },
        "headers": {
            "accept_json_seen": observation.accept_seen,
            "user_agent_seen": observation.user_agent_seen
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_unauthorized_error_does_not_leak_secret_material() {
    let fixture = LoopbackFixture::start("401 Unauthorized", UNAUTHORIZED_RESPONSE);
    let (connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let error = connector
        .handle_invoke(json!({
            "operation": OP_LIST_ACTIVITIES,
            "input": {
                "user_key": "all",
                "application_name": "login"
            },
            "capability_token": capability_token(&signing_key, &instance_id, AUDIT_CAPABILITY)
        }))
        .await
        .expect_err("401 should map to unauthorized");
    let observation = fixture.join();

    assert!(observation.authorization_seen);
    assert!(matches!(error, FcpError::Unauthorized { .. }));
    assert!(!error.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-admin-reports",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.29",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_LIST_ACTIVITIES,
        "error_mapping": "unauthorized",
        "authorization_header_verified": observation.authorization_seen,
        "secret_leaked": false,
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
        "http://{}/admin/reports/v1",
        listener.local_addr().expect("read listener address")
    );
    let (connector, signing_key, instance_id) = setup_connector(&base_url).await;

    let error = connector
        .handle_invoke(json!({
            "operation": OP_LIST_ACTIVITIES,
            "input": activity_input(),
            "capability_token": capability_token(&signing_key, &instance_id, USAGE_CAPABILITY)
        }))
        .await
        .expect_err("usage capability should not authorize audit activity listing");

    assert!(matches!(
        error,
        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
    ));
    let accept_error = listener
        .accept()
        .expect_err("capability denial should happen before loopback egress");
    assert_eq!(accept_error.kind(), io::ErrorKind::WouldBlock);

    let artifact = json!({
        "connector": "google-admin-reports",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.29",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_LIST_ACTIVITIES,
        "denial": "wrong_capability",
        "loopback_egress_attempted": false,
        "result": "passed"
    });
    println!("{artifact}");
}
