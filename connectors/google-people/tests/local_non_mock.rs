//! Local loopback acceptance coverage for the Google People connector.

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
use fcp_google_people::connector::GooglePeopleConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpError, HandshakeRequest, InstanceId,
    ZoneId,
};
use serde_json::{Value, json};

const LOOPBACK_AUTH_VALUE: &str = "local-people-auth-value";
const OP_LIST_CONNECTIONS: &str = "people.list_connections";
const OP_CREATE_CONTACT: &str = "people.create_contact";
const READ_CAPABILITY: &str = "people.contacts.read";
const GROUPS_READ_CAPABILITY: &str = "people.contact_groups.read";
const WRITE_CAPABILITY: &str = "people.contacts.write";

const LIST_CONNECTIONS_RESPONSE: &str = r#"{
  "connections": [
    {
      "resourceName": "people/contact-1",
      "etag": "%EgUBAQMEBQY=",
      "names": [{ "displayName": "Ada Lovelace" }],
      "emailAddresses": [{ "value": "ada@example.com" }]
    }
  ],
  "nextPageToken": "contacts-page-2",
  "totalPeople": 1,
  "totalItems": 1
}"#;

const CONTACT_GROUPS_RESPONSE: &str = r#"{
  "contactGroups": [
    {
      "resourceName": "contactGroups/myContacts",
      "name": "contactGroups/myContacts",
      "formattedName": "My Contacts",
      "groupType": "USER_CONTACT_GROUP",
      "memberCount": 1
    }
  ],
  "totalItems": 1
}"#;

const CREATE_CONTACT_RESPONSE: &str = r#"{
  "resourceName": "people/contact-created",
  "etag": "%EgUBAQMEBQY=",
  "names": [{ "givenName": "Grace", "familyName": "Hopper", "displayName": "Grace Hopper" }],
  "emailAddresses": [{ "value": "grace@example.com" }]
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
        header_value_contains(&self.headers, "user-agent", "fcp-google-people/0.1.0")
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

fn request_line_contains_query_pair(request_line: &str, name: &str, value: &str) -> bool {
    request_line
        .split_whitespace()
        .nth(1)
        .and_then(|target| target.split_once('?').map(|(_, query)| query))
        .is_some_and(|query| {
            query
                .split('&')
                .any(|pair| pair == format!("{name}={value}"))
        })
}

fn handshake_req(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [43_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(READ_CAPABILITY),
            CapabilityId::from_static(GROUPS_READ_CAPABILITY),
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
        .principal("user:local-people")
        .operations(&[operation])
        .issuer("node:local-people")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (GooglePeopleConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = GooglePeopleConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    connector
        .handle_configure(json!({
            "access_token": LOOPBACK_AUTH_VALUE,
            "base_url": base_url,
            "required_scopes": [
                "https://www.googleapis.com/auth/contacts.readonly",
                "https://www.googleapis.com/auth/contacts"
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

fn create_contact_input() -> Value {
    json!({
        "person": {
            "names": [
                { "givenName": "Grace", "familyName": "Hopper" }
            ],
            "emailAddresses": [
                { "value": "grace@example.com" }
            ]
        }
    })
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_list_connections_uses_people_request_boundary() {
    let fixture = LoopbackFixture::start("200 OK", LIST_CONNECTIONS_RESPONSE);
    let (connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let health = connector.handle_health().await.expect("health response");
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["service_identity"], "people:v1");

    let doctor = connector.handle_doctor().await.expect("doctor response");
    assert_eq!(doctor["status"], "healthy");

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection response");
    let operations = introspection["operations"].as_array().expect("operations");
    assert!(operations.iter().any(|operation| {
        operation["id"] == OP_LIST_CONNECTIONS && operation["capability"] == READ_CAPABILITY
    }));

    let result = connector
        .handle_invoke(json!({
            "operation": OP_LIST_CONNECTIONS,
            "input": {
                "person_fields": ["names", "emailAddresses"],
                "page_size": 2
            },
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                READ_CAPABILITY,
                OP_LIST_CONNECTIONS,
            )
        }))
        .await
        .expect("list connections through connector");
    let observation = fixture.join();

    assert!(
        observation
            .request_line
            .starts_with("GET /v1/people/me/connections?")
    );
    assert!(observation.request_line.contains("personFields="));
    assert!(observation.request_line.contains("names"));
    assert!(observation.request_line.contains("emailAddresses"));
    assert!(request_line_contains_query_pair(
        &observation.request_line,
        "pageSize",
        "2",
    ));
    assert!(observation.authorization_seen());
    assert!(observation.accept_seen());
    assert!(!observation.content_type_json_seen());
    assert!(observation.user_agent_seen());
    assert!(observation.body.is_empty());
    assert_eq!(result["connections"][0]["resourceName"], "people/contact-1");
    assert_eq!(
        result["connections"][0]["emailAddresses"][0]["value"],
        "ada@example.com"
    );
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-people",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.34",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_LIST_CONNECTIONS,
        "method": "GET",
        "endpoint_shape": "GET /v1/people/me/connections?<redacted_query>",
        "query_shape": {
            "person_fields_present": observation.request_line.contains("personFields="),
            "page_size_present": request_line_contains_query_pair(
                &observation.request_line,
                "pageSize",
                "2",
            )
        },
        "path_segment_policy": {
            "loopback_endpoint_redacted": true,
            "contact_resource_names_redacted": true,
            "query_values_shape_only": true
        },
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
async fn local_non_mock_self_check_uses_contact_groups_health_probe() {
    let fixture = LoopbackFixture::start("200 OK", CONTACT_GROUPS_RESPONSE);
    let (connector, _, _) = setup_connector(fixture.base_url()).await;

    let report = connector
        .handle_self_check()
        .await
        .expect("self-check response");
    let observation = fixture.join();

    assert!(
        observation
            .request_line
            .starts_with("GET /v1/contactGroups?")
    );
    assert!(request_line_contains_query_pair(
        &observation.request_line,
        "groupFields",
        "name",
    ));
    assert!(request_line_contains_query_pair(
        &observation.request_line,
        "pageSize",
        "1",
    ));
    assert!(observation.authorization_seen());
    assert!(observation.accept_seen());
    assert_eq!(report["status"], "ok");
    assert!(!report.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-people",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.34",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": "self_check",
        "method": "GET",
        "endpoint_shape": "GET /v1/contactGroups?<redacted_query>",
        "query_shape": {
            "group_fields_present": request_line_contains_query_pair(
                &observation.request_line,
                "groupFields",
                "name",
            ),
            "page_size_present": request_line_contains_query_pair(
                &observation.request_line,
                "pageSize",
                "1",
            )
        },
        "path_segment_policy": {
            "loopback_endpoint_redacted": true,
            "contact_group_resource_names_redacted": true,
            "query_values_shape_only": true
        },
        "authorization_header_verified": observation.authorization_seen(),
        "secret_leaked": false,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_create_contact_posts_people_body() {
    let fixture = LoopbackFixture::start("200 OK", CREATE_CONTACT_RESPONSE);
    let (connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": OP_CREATE_CONTACT,
            "input": create_contact_input(),
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                WRITE_CAPABILITY,
                OP_CREATE_CONTACT,
            )
        }))
        .await
        .expect("create contact through connector");
    let observation = fixture.join();
    let body: Value = serde_json::from_str(&observation.body).expect("request body json");

    assert!(
        matches!(
            observation.request_line.as_str(),
            "POST /v1/people:createContact HTTP/1.1" | "POST /v1/people:createContact? HTTP/1.1"
        ),
        "unexpected createContact request line: {}",
        observation.request_line
    );
    assert!(observation.authorization_seen());
    assert!(observation.accept_seen());
    assert!(observation.content_type_json_seen());
    assert!(observation.user_agent_seen());
    assert_eq!(body["names"][0]["givenName"], "Grace");
    assert_eq!(body["names"][0]["familyName"], "Hopper");
    assert_eq!(body["emailAddresses"][0]["value"], "grace@example.com");
    assert_eq!(result["person"]["resourceName"], "people/contact-created");
    assert_eq!(
        result["person"]["emailAddresses"][0]["value"],
        "grace@example.com"
    );
    assert!(!result.to_string().contains(LOOPBACK_AUTH_VALUE));

    let artifact = json!({
        "connector": "google-people",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.34",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_CREATE_CONTACT,
        "method": "POST",
        "endpoint_shape": "POST /v1/people:createContact",
        "auth_gate": {
            "mode": "bearer",
            "authorization_header_verified": observation.authorization_seen(),
            "instance_bound_token_verified": true
        },
        "body_shape": {
            "name_count": body["names"].as_array().map_or(0, Vec::len),
            "email_count": body["emailAddresses"].as_array().map_or(0, Vec::len),
            "contact_names_redacted": true,
            "contact_emails_redacted": true
        },
        "path_segment_policy": {
            "loopback_endpoint_redacted": true,
            "contact_resource_names_redacted": true,
            "contact_payload_redacted": true
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
        "http://{}/v1",
        listener.local_addr().expect("read listener address")
    );
    let (connector, signing_key, instance_id) = setup_connector(&base_url).await;

    let error = connector
        .handle_invoke(json!({
            "operation": OP_CREATE_CONTACT,
            "input": create_contact_input(),
            "capability_token": capability_token(
                &signing_key,
                &instance_id,
                READ_CAPABILITY,
                OP_CREATE_CONTACT,
            )
        }))
        .await
        .expect_err("read capability should not authorize contact creation");

    assert!(matches!(
        error,
        FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
    ));
    let accept_error = listener
        .accept()
        .expect_err("capability denial should happen before loopback egress");
    assert_eq!(accept_error.kind(), io::ErrorKind::WouldBlock);

    let artifact = json!({
        "connector": "google-people",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "bead_id": "flywheel_connectors-bky21.3.6.34",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_CREATE_CONTACT,
        "denial": "wrong_capability",
        "loopback_egress_attempted": false,
        "path_segment_policy": {
            "loopback_endpoint_redacted": true,
            "contact_resource_names_redacted": true,
            "contact_payload_redacted": true
        },
        "result": "passed"
    });
    println!("{artifact}");
}
