//! Local loopback acceptance coverage for the FCP Google Drive connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_google_drive::connector::DriveConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, HandshakeRequest, InstanceId, ZoneId,
};
use serde_json::json;

const OP_GET_FILE: &str = "drive.get_file";
const EXPECTED_PATH_PREFIX: &str = "/drive/v3/files/file-123?fields=";
const RESPONSE_BODY: &str = r#"{
  "id": "file-123",
  "name": "acceptance-report.pdf",
  "mimeType": "application/pdf",
  "size": "4096",
  "parents": ["root"],
  "webViewLink": "https://drive.google.com/file/d/file-123/view",
  "trashed": false,
  "shared": true
}"#;

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    accept_seen: bool,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream)
        });

        Self {
            base_url: format!("http://{address}/drive/v3"),
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

fn handle_request(mut stream: TcpStream) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let mut buffer = [0_u8; 4096];
    let bytes_read = stream.read(&mut buffer).expect("read connector request");
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let authorization_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("authorization: Bearer ya29.local-drive-token"));
    let accept_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("accept: application/json"));

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        accept_seen,
    }
}

fn handshake_req(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [23_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static("drive.read")],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn capability_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id("drive.read")
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:local-non-mock")
        .operations(&[OP_GET_FILE])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (DriveConnector, Ed25519SigningKey, InstanceId) {
    let mut connector = DriveConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    connector
        .handle_configure(json!({
            "access_token": "ya29.local-drive-token",
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

    let instance_id = connector.instance_id().parse().expect("actual instance ID");
    (connector, signing_key, instance_id)
}

#[fcp_async_core::runtime::test]
async fn loopback_get_file_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let (connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "type": "invoke",
            "id": "drive-local-get-file",
            "connector_id": "fcp.google_drive",
            "zone_id": "z:work",
            "operation": OP_GET_FILE,
            "input": {
                "file_id": "file-123"
            },
            "capability_token": capability_token(&signing_key, &instance_id)
        }))
        .await
        .expect("get Drive file through connector");
    let observation = fixture.join();

    assert!(observation.request_line.starts_with("GET "));
    assert!(observation.request_line.contains(EXPECTED_PATH_PREFIX));
    assert!(observation.request_line.ends_with(" HTTP/1.1"));
    assert!(observation.authorization_seen);
    assert!(observation.accept_seen);
    assert_eq!(result["file"]["id"], "file-123");
    assert_eq!(result["file"]["name"], "acceptance-report.pdf");
    assert_eq!(result["file"]["mimeType"], "application/pdf");
    assert_eq!(result["file"]["shared"], true);

    let artifact = json!({
        "connector": "google-drive",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": OP_GET_FILE,
        "method": "GET",
        "path_prefix": EXPECTED_PATH_PREFIX,
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "accept_seen": observation.accept_seen,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}
