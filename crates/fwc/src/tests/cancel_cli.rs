//! Exercise owner cancellation through the actual CLI and a local HTTP peer.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use fcp_core::CapabilityToken;
use serde_json::{Value, json};

use super::{execute_json, execute_text};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

struct HostPeer {
    endpoint: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Vec<RecordedRequest>>>,
}

impl HostPeer {
    fn start(status: u16, response: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let body = serde_json::to_vec(&response).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + TEST_TIMEOUT;
            let mut requests = Vec::new();
            while !stopping.load(Ordering::SeqCst) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("local cancellation peer accept failed: {error}"),
                };
                stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
                requests.push(read_request(&stream));
                let headers = format!(
                    "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(headers.as_bytes()).is_ok() {
                    let _ = stream.write_all(&body);
                }
            }
            requests
        });
        Self {
            endpoint,
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<RecordedRequest> {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.take().unwrap().join().unwrap()
    }
}

impl Drop for HostPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_request(stream: &TcpStream) -> RecordedRequest {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap().to_owned();
    let path = parts.next().unwrap().to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        if header == "\r\n" || header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').unwrap();
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .map_or(0, |length| length.parse::<usize>().unwrap());
    assert!(length <= 128 * 1024);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    RecordedRequest {
        method,
        path,
        headers,
        body: serde_json::from_slice(&body).unwrap(),
    }
}

fn token(capability: &str, holder: Option<&str>) -> CapabilityToken {
    let mut claims = CapabilityToken::test_token()
        .raw()
        .claims_unverified()
        .unwrap()
        .subject("cancel-cli-owner")
        .principal_id("cancel-cli-owner")
        .zone_id("z:work")
        .capability_id(capability)
        .operations(&["host.cancel-self"]);
    if let Some(holder) = holder {
        claims = claims.holder_node(holder);
    }
    let key = fcp_crypto::Ed25519SigningKey::from_bytes(&[0x69; 32]).unwrap();
    CapabilityToken::from_raw(fcp_crypto::cose::CoseToken::sign(&key, &claims).unwrap())
}

fn token_argument(token: &CapabilityToken) -> String {
    base64::engine::general_purpose::STANDARD.encode(token.raw().to_cbor().unwrap())
}

fn assert_token_absent(text: &str, token: &CapabilityToken) {
    assert!(!text.contains(&token_argument(token)));
    assert!(!text.contains(&serde_json::to_string(token).unwrap()));
    assert!(!text.contains("\"capability_token\""));
    assert!(!text.contains("capability_token["));
}

fn assert_owner_request(requests: &[RecordedRequest], id: &str, token: &CapabilityToken) {
    assert_eq!(
        requests.len(),
        1,
        "cancel must not retry or use an admin fallback"
    );
    let request = &requests[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/rpc/cancel-self");
    assert_eq!(request.body["operation_id"], id);
    assert_eq!(
        request.body["capability_token"],
        serde_json::to_value(token).unwrap()
    );
    assert!(!request.headers.contains_key("authorization"));
    assert!(!request.headers.contains_key("x-principal"));
    assert!(!request.headers.contains_key("x-fcp-zone"));
}

fn unused_host() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    (listener, endpoint)
}

fn assert_no_connection(listener: &TcpListener) {
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn missing_cancellation_capability_is_rejected_before_host_access() {
    let (listener, endpoint) = unused_host();
    let (exit, payload) = execute_json(&[
        "fwc",
        "--json",
        "--host",
        &endpoint,
        "cancel",
        "op-no-grant",
    ]);
    assert_ne!(exit, std::process::ExitCode::SUCCESS);
    assert_eq!(payload["error"]["type"], "missing-cancellation-capability");
    assert_no_connection(&listener);
}

#[test]
fn wrong_scope_and_holder_bound_tokens_are_rejected_before_host_access() {
    for (capability, holder) in [
        ("test.echo", None),
        ("host.cancel-self", Some("node:holder")),
    ] {
        let (listener, endpoint) = unused_host();
        let grant = token(capability, holder);
        let encoded = token_argument(&grant);
        let (exit, payload) = execute_json(&[
            "fwc",
            "--json",
            "--host",
            &endpoint,
            "cancel",
            "op-invalid-grant",
            "--cancel-capability-token",
            &encoded,
        ]);
        assert_ne!(exit, std::process::ExitCode::SUCCESS);
        assert_eq!(payload["error"]["type"], "invalid-cancellation-capability");
        assert_token_absent(&payload.to_string(), &grant);
        assert_no_connection(&listener);
    }
}

#[test]
fn oversized_cancellation_token_file_is_rejected_without_network_or_secret_output() {
    let (listener, endpoint) = unused_host();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("CANCEL_TOKEN_PATH_SECRET.token");
    let secret = "CANCEL_FILE_CONTENT_SECRET".repeat(3_000);
    std::fs::write(&path, &secret).unwrap();
    let (exit, payload) = execute_json(&[
        "fwc",
        "--json",
        "--host",
        &endpoint,
        "cancel",
        "op-large-grant",
        "--cancel-capability-token-file",
        path.to_str().unwrap(),
    ]);
    assert_ne!(exit, std::process::ExitCode::SUCCESS);
    assert_eq!(payload["error"]["type"], "invalid-cancellation-capability");
    let output = payload.to_string();
    assert!(!output.contains("CANCEL_FILE_CONTENT_SECRET"));
    assert!(!output.contains("CANCEL_TOKEN_PATH_SECRET"));
    assert_no_connection(&listener);
}

#[test]
fn token_file_authenticates_one_request_without_leaking_into_json_or_text() {
    let grant = token("host.cancel-self", None);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("CANCEL_TOKEN_PATH_SECRET.cbor");
    std::fs::write(&path, grant.raw().to_cbor().unwrap()).unwrap();
    for json_output in [true, false] {
        let peer = HostPeer::start(
            200,
            json!({
                "operation_id": "op-owned",
                "outcome": "cancelled",
                "duration_ms": 1,
            }),
        );
        let mut args = vec!["fwc"];
        if json_output {
            args.push("--json");
        }
        args.extend([
            "--host",
            peer.endpoint.as_str(),
            "cancel",
            "op-owned",
            "--cancel-capability-token-file",
            path.to_str().unwrap(),
            "--reason",
            "agent-abort",
            "--detail",
            "operator cancelled this job",
            "--cleanup",
            "full",
            "--cleanup-timeout-ms",
            "250",
            "--return-partial",
        ]);
        let (exit, text) = execute_text(&args);
        assert_eq!(exit, std::process::ExitCode::SUCCESS);
        assert_token_absent(&text, &grant);
        assert!(!text.contains("CANCEL_TOKEN_PATH_SECRET"));
        if json_output {
            let payload: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(payload["request"]["operation_id"], "op-owned");
            assert!(payload["request"].get("capability_token").is_none());
            assert_eq!(payload["response"]["outcome"], "cancelled");
            assert!(payload["message"].as_str().unwrap().contains("accepted"));
        }
        let requests = peer.finish();
        assert_owner_request(&requests, "op-owned", &grant);
        assert_eq!(
            requests[0].body["reason"],
            json!({
                "type": "agent_abort", "reason": "operator cancelled this job",
            })
        );
        assert_eq!(
            requests[0].body["cleanup"],
            json!({"type": "full", "timeout_ms": 250})
        );
        assert_eq!(requests[0].body["return_partial"], true);
    }
}

#[test]
fn denied_and_unknown_operations_send_once_without_fallback_or_error_body_leakage() {
    let grant = token("host.cancel-self", None);
    let encoded = token_argument(&grant);
    for (status, error_kind) in [
        (401, "cancel-request-denied"),
        (403, "cancel-request-denied"),
        (404, "cancel-operation-unavailable"),
    ] {
        for json_output in [true, false] {
            let peer = HostPeer::start(
                status,
                json!({
                    "error": "HOST_PRIVATE_ERROR_SECRET",
                    "echoed_capability": &encoded,
                }),
            );
            let mut args = vec!["fwc"];
            if json_output {
                args.push("--json");
            }
            args.extend([
                "--host",
                peer.endpoint.as_str(),
                "cancel",
                "op-unsettled",
                "--cancel-capability-token",
                encoded.as_str(),
            ]);
            let (exit, text) = execute_text(&args);
            assert_ne!(exit, std::process::ExitCode::SUCCESS);
            assert_token_absent(&text, &grant);
            assert!(!text.contains("HOST_PRIVATE_ERROR_SECRET"));
            assert!(text.contains("op-unsettled"));
            if json_output {
                let payload: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(payload["error"]["type"], error_kind);
            }
            assert_owner_request(&peer.finish(), "op-unsettled", &grant);
        }
    }
}

#[test]
fn mismatched_cancellation_response_reports_unknown_without_claiming_success() {
    let grant = token("host.cancel-self", None);
    let encoded = token_argument(&grant);
    let peer = HostPeer::start(
        200,
        json!({
            "operation_id": "unrelated-operation",
            "outcome": "cancelled",
            "duration_ms": 1,
        }),
    );
    let (exit, payload) = execute_json(&[
        "fwc",
        "--json",
        "--host",
        &peer.endpoint,
        "cancel",
        "op-expected",
        "--cancel-capability-token",
        &encoded,
    ]);
    assert_ne!(exit, std::process::ExitCode::SUCCESS);
    assert_eq!(payload["error"]["type"], "cancel-outcome-unknown");
    let output = payload.to_string();
    assert!(output.contains("op-expected"));
    assert!(!output.contains("unrelated-operation"));
    assert_token_absent(&output, &grant);
    assert_owner_request(&peer.finish(), "op-expected", &grant);
}
