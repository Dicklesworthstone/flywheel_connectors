//! Local loopback acceptance coverage for the FCP S3 connector.

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
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, HandshakeRequest, InstanceId, ZoneId,
};
use fcp_s3::connector::S3Connector;
use serde_json::json;

const OP_GET_OBJECT: &str = "s3.get_object";
const EXPECTED_PATH: &str = "/test-bucket/artifact.txt";
const ACCESS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const RESPONSE_BODY: &str = "hello from loopback";

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    payload_digest_seen: bool,
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
            base_url: format!("http://{address}"),
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

    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        if bytes_read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..bytes_read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        assert!(request.len() < 8192, "request headers should stay bounded");
    }

    let request = String::from_utf8_lossy(&request);
    let request_line = request.lines().next().unwrap_or_default().to_string();
    let authorization_seen = request.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("authorization: aws4-hmac-sha256 ")
            && line.contains(&format!("Credential={ACCESS_KEY_ID}/"))
            && line.contains("/us-east-1/s3/aws4_request")
            && line.contains("Signature=")
    });
    let payload_digest_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case("x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        RESPONSE_BODY.len(),
        RESPONSE_BODY
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        payload_digest_seen,
    }
}

fn handshake_req(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [31_u8; 32],
        capabilities_requested: vec![CapabilityId::from_static("s3.read")],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn capability_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["s3://test-bucket/artifact.txt".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id("s3.read")
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:local-non-mock")
        .operations(&[OP_GET_OBJECT])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

async fn setup_connector(base_url: &str) -> (S3Connector, Ed25519SigningKey, InstanceId) {
    let mut connector = S3Connector::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();

    connector
        .handle_configure(json!({
            "access_key_id": ACCESS_KEY_ID,
            "secret_access_key": SECRET_ACCESS_KEY,
            "region": "us-east-1",
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

    let actual_instance = connector.instance_id().clone();
    assert_ne!(
        actual_instance, instance_id,
        "handshake rotates the requested binding"
    );
    (connector, signing_key, actual_instance)
}

#[fcp_async_core::runtime::test]
async fn loopback_get_object_uses_production_client_request() {
    let fixture = LoopbackFixture::start();
    let (connector, signing_key, instance_id) = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(json!({
            "type": "invoke", "id": "loopback-get",
            "connector_id": "fcp.s3", "zone_id": "z:work",
            "operation": OP_GET_OBJECT,
            "input": {
                "bucket": "test-bucket",
                "key": "artifact.txt"
            },
            "capability_token": capability_token(&signing_key, &instance_id)
        }))
        .await
        .expect("get S3 object through connector");
    let observation = fixture.join();

    assert_eq!(
        observation.request_line,
        format!("GET {EXPECTED_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert!(observation.payload_digest_seen);
    assert_eq!(result["id"], "loopback-get");
    assert_eq!(result["result"]["body"], "hello from loopback");
    assert_eq!(result["result"]["content_type"], "text/plain");
    assert_eq!(result["result"]["body_encoding"], "utf8");
    assert_eq!(
        result["resource_uris"],
        json!(["s3://test-bucket/artifact.txt"])
    );

    let artifact = json!({
        "connector": "s3",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operation": OP_GET_OBJECT,
        "method": "GET",
        "path": EXPECTED_PATH,
        "request_line": observation.request_line,
        "authorization_seen": observation.authorization_seen,
        "payload_digest_seen": observation.payload_digest_seen,
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

struct NativeProcess {
    child: Child,
    stdin: ChildStdin,
    replies: Receiver<serde_json::Value>,
    reader: Option<JoinHandle<()>>,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-s3"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start native S3 connector");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, replies) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let response =
                    serde_json::from_str(&line).expect("stdout contains only JSONL replies");
                if sender.send(response).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            replies,
            reader: Some(reader),
        }
    }

    fn call(&mut self, id: u64, method: &str, params: serde_json::Value) -> serde_json::Value {
        writeln!(
            self.stdin,
            "{}",
            json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params})
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let response = self
            .replies
            .recv_timeout(Duration::from_secs(5))
            .expect("native response arrives within five seconds");
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], id);
        assert!(
            response.get("error").is_none(),
            "native method failed: {response}"
        );
        response["result"].clone()
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn native_executable_negotiates_signed_read_and_exits_with_stdin_open() {
    let fixture = LoopbackFixture::start();
    let signing_key = Ed25519SigningKey::generate();
    let mut process = NativeProcess::start();
    let configured = process.call(
        1,
        "configure",
        json!({
            "access_key_id": ACCESS_KEY_ID,
            "secret_access_key": SECRET_ACCESS_KEY,
            "region": "us-east-1",
            "base_url": fixture.base_url(),
        }),
    );
    assert_eq!(configured["status"], "configured");
    let preferred = InstanceId::new();
    let handshake = process.call(
        2,
        "handshake",
        serde_json::to_value(handshake_req(
            signing_key.verifying_key().to_bytes(),
            &preferred,
        ))
        .unwrap(),
    );
    assert_eq!(handshake["connector_id"], "fcp.s3");
    assert_eq!(handshake["protocol_version"], "2.0");
    let actual: InstanceId = serde_json::from_value(handshake["instance_id"].clone()).unwrap();
    assert_ne!(actual, preferred);
    let response = process.call(
        3,
        "invoke",
        json!({
            "type": "invoke", "id": "native-read",
            "connector_id": "fcp.s3", "zone_id": "z:work",
            "operation": OP_GET_OBJECT,
            "input": {"bucket": "test-bucket", "key": "artifact.txt"},
            "capability_token": capability_token(&signing_key, &actual),
            "deadline_ms": 3000,
        }),
    );
    assert_eq!(response["type"], "response");
    assert_eq!(response["id"], "native-read");
    assert_eq!(response["result"]["body"], RESPONSE_BODY);
    assert_eq!(response["result"]["body_encoding"], "utf8");
    assert!(
        response["result"].get("type").is_none(),
        "must not nest response envelopes"
    );
    assert_eq!(
        response["resource_uris"],
        json!(["s3://test-bucket/artifact.txt"])
    );
    let observation = fixture.join();
    assert!(observation.authorization_seen);
    assert!(observation.payload_digest_seen);

    let shutdown = process.call(4, "shutdown", json!({"type":"shutdown"}));
    assert_eq!(shutdown["status"], "shutdown");
    let stop_by = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < stop_by,
            "shutdown must not wait for stdin EOF"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
