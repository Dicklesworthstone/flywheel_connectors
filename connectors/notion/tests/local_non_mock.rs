//! Local loopback acceptance coverage for the FCP Notion connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

use std::{
    fmt::Write as FmtWrite,
    io::{BufRead, BufReader, Read, Write as IoWrite},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{HealthSnapshot, Introspection, InvokeResponse, InvokeStatus, SimulateResponse};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_notion::{client::DEFAULT_NOTION_VERSION, connector::NotionConnector};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError, InstanceId};
use serde_json::{Value, json};

const CONNECTOR: &str = "notion";
const PACKAGE: &str = "fcp-notion";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.15";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const LOOPBACK_BEARER_VALUE: &str = "ntn_local_non_mock_marker";
const OP_SEARCH: &str = "notion.search";
const CAP_SEARCH: &str = "notion.search";
const CAP_READ: &str = "notion.read";
const EXPECTED_PATH: &str = "/v1/search";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Value,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(response: HttpResponse) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        listener
            .set_nonblocking(true)
            .expect("loopback listener should be nonblocking");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its address")
        );
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            let deadline = Instant::now() + StdDuration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "loopback request timed out");
                        thread::sleep(StdDuration::from_millis(5));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(StdDuration::from_secs(5)))
                .expect("loopback stream should set read timeout");

            let request = read_complete_request(&mut stream);
            request_tx
                .send(request)
                .expect("captured request should be delivered to test");

            let mut raw_response = format!("HTTP/1.1 {}\r\n", response.status);
            raw_response.push_str("content-type: application/json\r\n");
            write!(
                &mut raw_response,
                "content-length: {}\r\n",
                response.body.len()
            )
            .expect("content-length should format");
            raw_response.push_str("connection: close\r\n\r\n");
            raw_response.push_str(response.body);

            stream
                .write_all(raw_response.as_bytes())
                .expect("loopback response should be writable");
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn notion_api_url(&self) -> String {
        format!("{}/v1", self.base_url)
    }

    fn take(&self) -> CapturedRequest {
        self.received
            .recv_timeout(StdDuration::from_secs(5))
            .expect("loopback request should arrive")
    }

    fn join(self) {
        self.join
            .join()
            .expect("loopback server thread should finish");
    }
}

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

impl HttpResponse {
    const fn json(status: &'static str, body: &'static str) -> Self {
        Self { status, body }
    }
}

fn read_complete_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let read = stream
            .read(&mut buffer)
            .expect("loopback request should be readable");
        assert!(read > 0, "connector request should not close early");
        bytes.extend_from_slice(&buffer[..read]);

        if header_end.is_none() {
            header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n");
            if let Some(end) = header_end {
                let head = String::from_utf8_lossy(&bytes[..end]).to_string();
                content_length = parse_content_length(&head);
            }
        }

        if let Some(end) = header_end {
            let body_start = end + 4;
            if bytes.len() >= body_start + content_length {
                let head = String::from_utf8(bytes[..end].to_vec())
                    .expect("request headers should be UTF-8");
                let body = serde_json::from_slice(&bytes[body_start..body_start + content_length])
                    .expect("request body should be JSON");
                return CapturedRequest { head, body };
            }
        }

        assert!(bytes.len() < 65_536, "loopback request should stay bounded");
    }
}

fn parse_content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .expect("request should carry content-length")
}

fn header_seen(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn assert_request(captured: &CapturedRequest) {
    let request_line = captured
        .head
        .lines()
        .next()
        .expect("captured request should include request line");
    assert_eq!(request_line, format!("POST {EXPECTED_PATH} HTTP/1.1"));
    assert!(
        header_seen(
            &captured.head,
            "authorization",
            &format!("Bearer {LOOPBACK_BEARER_VALUE}")
        ),
        "request should carry configured Notion bearer token; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "notion-version", DEFAULT_NOTION_VERSION),
        "request should carry Notion-Version header; head={}",
        captured.head
    );
    assert!(
        header_seen(&captured.head, "content-type", "application/json"),
        "request should carry JSON content type; head={}",
        captured.head
    );
}

fn valid_capability_grant(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    scoped_capability_grant(
        signing_key,
        instance_id,
        capability,
        operation,
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        },
    )
}

fn scoped_capability_grant(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
    constraints: &CapabilityConstraints,
) -> CapabilityToken {
    let now = Utc::now();
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).expect("serialize capability constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .target_instance(instance_id.as_str())
        .token_id(b"notion-local-non-mock-grant")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

async fn setup_connector(
    api_url: &str,
    capabilities: &[&str],
) -> (NotionConnector, Ed25519SigningKey) {
    let mut connector = NotionConnector::new();
    connector
        .handle_configure(json!({
            "token": LOOPBACK_BEARER_VALUE,
            "api_url": api_url
        }))
        .await
        .expect("configure connector");

    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![7_u8; 32],
            "capabilities_requested": capabilities
        }))
        .await
        .expect("handshake connector");

    (connector, signing_key)
}

struct NativeProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Result<Value, String>>,
    reader: Option<JoinHandle<()>>,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-notion"))
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("shipped Notion binary should start");
        let input = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let (sender, output) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let response = line.map_err(|error| error.to_string()).and_then(|line| {
                    serde_json::from_str(&line).map_err(|error| error.to_string())
                });
                if sender.send(response).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input: Some(input),
            output,
            reader: Some(reader),
        }
    }

    fn send_bytes(&mut self, frame: &[u8]) -> std::io::Result<()> {
        let input = self.input.as_mut().expect("live child stdin");
        input.write_all(frame)?;
        input.flush()
    }

    fn send(&mut self, frame: &Value) {
        let mut bytes = serde_json::to_vec(frame).expect("serialize RPC");
        bytes.push(b'\n');
        self.send_bytes(&bytes).expect("write RPC");
    }

    fn receive(&self) -> Value {
        self.output
            .recv_timeout(StdDuration::from_secs(10))
            .expect("native response should arrive within deadline")
            .expect("stdout must contain only JSONL responses")
    }

    fn rpc(&mut self, id: &str, method: &str, params: Value) -> Value {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }));
        let response = self.receive();
        assert_eq!(response["id"], id);
        response
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        // Keep stdin open while waiting: a successful shutdown must exit by
        // itself, rather than depending on the host closing the pipe.
        let deadline = Instant::now() + StdDuration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll native process") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "native process did not terminate"
            );
            thread::sleep(StdDuration::from_millis(10));
        };
        self.input.take();
        if let Some(reader) = self.reader.take() {
            reader.join().expect("stdout reader should finish");
        }
        status
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn capability_denied_code() -> String {
    FcpError::CapabilityDenied {
        capability: CAP_SEARCH.into(),
        reason: "test".into(),
    }
    .error_code()
}

#[test]
fn native_binary_host_contract_and_signed_budgets_reach_real_http() {
    let server = LoopbackServer::start(HttpResponse::json(
        "200 OK",
        r#"{"object":"list","results":[],"has_more":false,"next_cursor":null}"#,
    ));
    let mut process = NativeProcess::start();
    let initial: HealthSnapshot =
        serde_json::from_value(process.rpc("boot", "health", json!({}))["result"].clone())
            .expect("initial health must use the host health schema");
    assert_eq!(initial.details.as_ref().unwrap()["configured"], false);

    let configured = process.rpc(
        "configure",
        "configure",
        json!({"token": LOOPBACK_BEARER_VALUE, "api_url": server.notion_api_url()}),
    );
    assert_eq!(configured["result"]["status"], "configured");
    let key = Ed25519SigningKey::generate();
    let handshake = process.rpc(
        "handshake",
        "handshake",
        json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![9_u8; 32],
            "capabilities_requested": [CAP_SEARCH, CAP_SEARCH, "notion.admin"]
        }),
    );
    assert_eq!(handshake["result"]["status"], "accepted");
    assert_eq!(
        handshake["result"]["capabilities_granted"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let health: HealthSnapshot =
        serde_json::from_value(process.rpc("ready", "health", json!({}))["result"].clone())
            .expect("negotiated health must use the host health schema");
    let details = health.details.unwrap();
    assert_eq!(details["configured"], true);
    assert_eq!(details["handshaken"], true);
    assert_eq!(details["instance_id"], handshake["result"]["instance_id"]);
    let instance: InstanceId = serde_json::from_value(details["instance_id"].clone()).unwrap();
    assert_ne!(
        json!(instance),
        initial.details.unwrap()["instance_id"],
        "handshake must rotate the real instance"
    );
    let catalog: Introspection =
        serde_json::from_value(process.rpc("catalog", "introspect", json!({}))["result"].clone())
            .expect("binary must expose typed operation metadata");
    assert_eq!(catalog.operations.len(), 16);

    let token = scoped_capability_grant(
        &key,
        &instance,
        CAP_SEARCH,
        OP_SEARCH,
        &CapabilityConstraints {
            resource_allow: vec!["notion://workspace/search".into()],
            max_calls: Some(1),
            max_bytes: Some(1_000_000),
            ..Default::default()
        },
    );
    let mut request = json!({
        "type": "simulate",
        "id": "search-preview",
        "connector_id": "fcp.notion",
        "zone_id": "z:work",
        "operation": OP_SEARCH,
        "input": {"query": "FCP binary proof"},
        "capability_token": token
    });
    for _ in 0..3 {
        let preview: SimulateResponse = serde_json::from_value(
            process.rpc("preview", "simulate", request.clone())["result"].clone(),
        )
        .unwrap();
        assert!(preview.would_succeed);
    }
    assert!(matches!(
        server.received.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    request["type"] = json!("invoke");
    request["id"] = json!("provider-invocation");
    let mut malformed = request.clone();
    malformed.as_object_mut().unwrap().remove("connector_id");
    assert_eq!(
        process.rpc("missing-target", "invoke", malformed)["error"]["code"],
        "FCP-1003"
    );
    let mut expired = request.clone();
    expired["deadline_ms"] = json!(0);
    assert_eq!(
        process.rpc("expired", "invoke", expired)["error"]["code"],
        "FCP-1003"
    );
    let tiny_grant = scoped_capability_grant(
        &key,
        &instance,
        CAP_SEARCH,
        OP_SEARCH,
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            max_bytes: Some(1),
            ..Default::default()
        },
    );
    let mut too_large = request.clone();
    too_large["capability_token"] = json!(tiny_grant);
    assert_eq!(
        process.rpc("tiny-byte-budget", "invoke", too_large)["error"]["code"],
        capability_denied_code()
    );
    assert!(matches!(
        server.received.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    let outer = process.rpc("transport-invocation", "invoke", request.clone());
    let response: InvokeResponse = serde_json::from_value(outer["result"].clone())
        .expect("binary must return a complete InvokeResponse");
    assert_eq!(response.r#type, "response");
    assert_eq!(response.id.0, "provider-invocation");
    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.unwrap();
    assert_eq!(result["result_count"], 0);
    assert_eq!(result["sensitivity"], "workspace_wide");
    let captured = server.take();
    assert_request(&captured);
    assert_eq!(captured.body, json!({"query": "FCP binary proof"}));

    let replay = process.rpc("spent-grant", "invoke", request.clone());
    assert_eq!(replay["error"]["code"], capability_denied_code());
    request["type"] = json!("simulate");
    let spent_preview: SimulateResponse =
        serde_json::from_value(process.rpc("spent-preview", "simulate", request)["result"].clone())
            .unwrap();
    assert!(!spent_preview.would_succeed);
    assert_eq!(
        process.rpc("shutdown", "shutdown", json!({}))["result"]["status"],
        "shutdown"
    );
    assert!(process.wait_for_exit().success());
    assert!(process.output.try_recv().is_err());
    server.join();
}

#[test]
fn native_binary_recovers_from_bad_frames_and_shutdown_stops_buffered_work() {
    let mut process = NativeProcess::start();
    process.send_bytes(b"{broken json\n").unwrap();
    assert!(process.receive().get("error").is_some());
    process.send(&json!({"jsonrpc": "2.0", "id": null, "method": "health", "params": {}}));
    let health = process.receive();
    assert_eq!(health["id"], Value::Null);
    serde_json::from_value::<HealthSnapshot>(health["result"].clone()).unwrap();

    process.send(&json!({"jsonrpc": "2.0", "id": {}, "method": "health", "params": {}}));
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");
    process.send(&json!({"jsonrpc": "1.0", "id": 7, "method": "health", "params": {}}));
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");

    process
        .send_bytes(
            b"{\"jsonrpc\":\"2.0\",\"id\":\"quit\",\"method\":\"shutdown\",\"params\":{}}\n\
              {\"jsonrpc\":\"2.0\",\"id\":\"must-not-run\",\"method\":\"health\",\"params\":{}}\n",
        )
        .unwrap();
    let shutdown = process.receive();
    assert_eq!(shutdown["id"], "quit");
    assert_eq!(shutdown["result"]["status"], "shutdown");
    assert!(process.wait_for_exit().success());
    assert!(
        process.output.try_recv().is_err(),
        "buffered work ran after shutdown"
    );
}

#[test]
fn native_binary_closes_the_stream_after_an_oversized_frame() {
    let mut process = NativeProcess::start();
    let mut frame = vec![b'x'; fcp_sdk::prelude::JsonlConfig::default().max_request_bytes + 1];
    frame.push(b'\n');
    if let Err(error) = process.send_bytes(&frame) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    assert_eq!(process.receive()["error"]["code"], "FCP-1004");
    assert!(!process.wait_for_exit().success());
    assert!(process.output.try_recv().is_err());
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_posts_body_headers_and_redacts_output() {
    let server = LoopbackServer::start(HttpResponse::json(
        "200 OK",
        r#"{
            "object": "list",
            "results": [{
                "object": "page",
                "id": "page-local-proof",
                "created_by": {
                    "object": "user",
                    "id": "user-created",
                    "type": "person",
                    "person": {"email": "owner@example.com"}
                },
                "last_edited_by": {
                    "object": "user",
                    "id": "user-edited",
                    "type": "person",
                    "person": {"email": "editor@example.com"}
                },
                "properties": {
                    "Owner": {
                        "id": "owner",
                        "type": "people",
                        "people": [{
                            "object": "user",
                            "id": "user-owner",
                            "type": "person",
                            "person": {"email": "workspace-owner@example.com"}
                        }]
                    }
                }
            }],
            "has_more": false,
            "next_cursor": null
        }"#,
    ));
    let (mut connector, signing_key) =
        setup_connector(&server.notion_api_url(), &[CAP_SEARCH]).await;
    let grant =
        valid_capability_grant(&signing_key, connector.instance_id(), CAP_SEARCH, OP_SEARCH);

    let result = connector
        .handle_invoke(json!({
            "type": "invoke",
            "id": "loopback-search",
            "connector_id": "fcp.notion",
            "zone_id": "z:work",
            "operation": OP_SEARCH,
            "input": {
                "query": "FCP local proof",
                "filter": {"property": "object", "value": "page"}
            },
            "capability_token": grant
        }))
        .await
        .expect("search should succeed through loopback fixture");
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown connector");

    let captured = server.take();
    server.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_request(&captured);
    assert_eq!(
        captured.body,
        json!({
            "query": "FCP local proof",
            "filter": {"property": "object", "value": "page"}
        })
    );
    assert_eq!(result["result_count"], 1);
    assert_eq!(result["sensitivity"], "workspace_wide");
    assert_eq!(result["provenance"]["source"], "notion.search");
    assert_eq!(
        result["results"][0]["created_by"]["person"]["email"],
        "[redacted]"
    );
    assert_eq!(
        result["results"][0]["last_edited_by"]["person"]["email"],
        "[redacted]"
    );
    assert_eq!(
        result["results"][0]["properties"]["Owner"]["people"][0]["person"]["email"],
        "[redacted]"
    );
    let rendered_result = result.to_string();
    assert!(!rendered_result.contains("owner@example.com"));
    assert!(!rendered_result.contains("editor@example.com"));
    assert!(!rendered_result.contains("workspace-owner@example.com"));
    assert!(!rendered_result.contains(LOOPBACK_BEARER_VALUE));

    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-notion --test local_non_mock -- --nocapture",
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "POST",
            "path": EXPECTED_PATH
        },
        "auth_gate": {
            "mode": "bearer_and_capability_token",
            "authorization_header_verified": header_seen(
                &captured.head,
                "authorization",
                &format!("Bearer {LOOPBACK_BEARER_VALUE}")
            ),
            "notion_version_header_verified": header_seen(
                &captured.head,
                "notion-version",
                DEFAULT_NOTION_VERSION
            )
        },
        "request_body": captured.body,
        "redaction": {
            "email_fields_redacted": true,
            "token_redacted_from_output": true
        },
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_search_rejects_wrong_capability_token() {
    let (connector, signing_key) = setup_connector("http://127.0.0.1:1/v1", &[CAP_SEARCH]).await;
    let grant = valid_capability_grant(&signing_key, connector.instance_id(), CAP_READ, OP_SEARCH);

    let err = connector
        .handle_invoke(json!({
            "type": "invoke",
            "id": "loopback-wrong-capability",
            "connector_id": "fcp.notion",
            "zone_id": "z:work",
            "operation": OP_SEARCH,
            "input": {"query": "should not leave connector"},
            "capability_token": grant
        }))
        .await
        .expect_err("wrong capability must be rejected before HTTP egress");

    assert!(
        matches!(
            err,
            FcpError::Unauthorized { .. } | FcpError::OperationNotGranted { .. }
        ),
        "expected capability denial, got {err:?}"
    );

    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command": "cargo test -p fcp-notion --test local_non_mock -- --nocapture",
        "capability_token_gate": {
            "wrong_capability": CAP_READ,
            "required_capability": CAP_SEARCH,
            "http_egress_attempted": false
        },
        "result": "passed"
    });
    println!("{artifact}");
}
