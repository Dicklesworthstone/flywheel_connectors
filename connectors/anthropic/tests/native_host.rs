//! Acceptance tests for the shipped Anthropic JSONL executable and real loopback HTTP.

#![allow(
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityToken, HealthSnapshot, InstanceId, Introspection,
    InvokeResponse, InvokeStatus, SimulateResponse,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::{Value, json};

const MODEL: &str = "claude-sonnet-4-6";
const API_KEY: &str = "anthropic-loopback-key";
const MESSAGE_RESPONSE: &str = r#"{"id":"msg-native","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"Checking the weather."},{"type":"tool_use","id":"tool-native","name":"weather","input":{"city":"Paris"}}],"stop_reason":"tool_use","usage":{"input_tokens":12,"output_tokens":8}}"#;
const STREAM_RESPONSE: &str = concat!(
    "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-native\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\n",
    "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Checking the weather.\"}}\n\n",
    "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
    "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tool-native\",\"name\":\"weather\",\"input\":{}}}\n\n",
    "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\\\"Paris\\\"}\"}}\n\n",
    "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
    "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":8}}\n\n",
    "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
);

struct CapturedRequest {
    headers: String,
    body: Value,
}

struct LoopbackServer {
    url: String,
    requests: Receiver<CapturedRequest>,
    thread: Option<JoinHandle<()>>,
    stop: Option<mpsc::Sender<()>>,
}

impl LoopbackServer {
    fn start(content_type: &'static str, body: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let thread = thread::spawn(move || {
            let deadline = Instant::now() + StdDuration::from_secs(15);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "provider request timed out");
                        thread::sleep(StdDuration::from_millis(5));
                    }
                    Err(error) => panic!("provider accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(StdDuration::from_secs(5)))
                .unwrap();
            sender.send(read_request(&mut stream)).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            ).unwrap();
            stream.flush().unwrap();
        });
        Self {
            url,
            requests,
            thread: Some(thread),
            stop: None,
        }
    }

    /// Keep serving until explicitly released so unexpected retries are observable.
    fn scripted(response: String, hold_open: bool) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let (stop, stopped) = mpsc::channel();
        let thread = thread::spawn(move || {
            let deadline = Instant::now() + StdDuration::from_secs(15);
            loop {
                if stopped.try_recv().is_ok() {
                    break;
                }
                assert!(Instant::now() < deadline, "scripted provider was not released");
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(StdDuration::from_secs(5)))
                            .unwrap();
                        sender.send(read_request(&mut stream)).unwrap();
                        stream
                            .set_write_timeout(Some(StdDuration::from_secs(5)))
                            .unwrap();
                        if let Err(error) = stream
                            .write_all(response.as_bytes())
                            .and_then(|()| stream.flush())
                        {
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                            ) {
                                // Bounded readers intentionally stop an oversized
                                // provider body before the server finishes sending.
                                continue;
                            }
                            panic!("scripted provider write failed: {error}");
                        }
                        if hold_open {
                            // No EOF is supplied until the test has observed the
                            // invocation result. This exercises body/terminal-event
                            // handling rather than only HTTP response headers.
                            let _ = stopped.recv_timeout(StdDuration::from_secs(5));
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(StdDuration::from_millis(5));
                    }
                    Err(error) => panic!("scripted provider accept failed: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            thread: Some(thread),
            stop: Some(stop),
        }
    }

    fn assert_no_requests(&self) {
        assert!(matches!(
            self.requests.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    fn receive(&self) -> CapturedRequest {
        self.requests
            .recv_timeout(StdDuration::from_secs(5))
            .unwrap()
    }

    fn finish(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.thread.take().unwrap().join().unwrap();
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "provider request closed before its body");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 65_536, "test request exceeded its bound");
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .expect("request content-length");
            if bytes.len() >= end + 4 + length {
                return CapturedRequest {
                    headers,
                    body: serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap(),
                };
            }
        }
    }
}

fn has_header(headers: &str, name: &str, value: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(actual_name, actual_value)| {
                actual_name.eq_ignore_ascii_case(name) && actual_value.trim() == value
            })
    })
}

struct NativeProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Result<Value, String>>,
    reader: Option<JoinHandle<()>>,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-anthropic"))
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("shipped Anthropic executable should start");
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
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

    fn send_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let input = self.input.as_mut().unwrap();
        input.write_all(bytes)?;
        input.flush()
    }

    fn receive(&self) -> Value {
        self.output
            .recv_timeout(StdDuration::from_secs(10))
            .expect("native response deadline")
            .expect("stdout must contain only JSONL responses")
    }

    fn rpc(&mut self, id: &str, method: &str, params: Value) -> Value {
        let mut bytes = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        }))
        .unwrap();
        bytes.push(b'\n');
        self.send_bytes(&bytes).unwrap();
        let response = self.receive();
        assert_eq!(response["id"], id);
        response
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        // Keep stdin open: shutdown must terminate without depending on EOF.
        let deadline = Instant::now() + StdDuration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "native process did not exit");
            thread::sleep(StdDuration::from_millis(10));
        };
        self.input.take();
        self.reader.take().unwrap().join().unwrap();
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

fn grant(
    key: &Ed25519SigningKey,
    instance: &InstanceId,
    operation: &str,
    token_id: &[u8],
    constraints: &CapabilityConstraints,
) -> CapabilityToken {
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let signed = CapabilityTokenBuilder::new()
        .capability_id(operation)
        .operations(&[operation])
        .zone_id("z:work")
        .principal("user:native-test")
        .issuer("node:native-test")
        .target_instance(instance.as_str())
        .token_id(token_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(key)
        .unwrap();
    CapabilityToken::from_raw(signed)
}

#[test]
fn native_messages_and_buffered_sse_preserve_tools_and_enforce_signed_budgets() {
    for (operation, content_type, body) in [
        ("anthropic.message", "application/json", MESSAGE_RESPONSE),
        (
            "anthropic.message.stream",
            "text/event-stream",
            STREAM_RESPONSE,
        ),
    ] {
        let server = LoopbackServer::start(content_type, body);
        let mut process = NativeProcess::start();
        let initial: HealthSnapshot =
            serde_json::from_value(process.rpc("boot", "health", json!({}))["result"].clone())
                .unwrap();
        assert!(!initial.is_ready());
        assert_eq!(initial.details.unwrap()["configured"], false);
        let config = process.rpc(
            "config",
            "configure",
            json!({
                "api_key": API_KEY,
                "base_url": server.url,
                "api_version": "2023-06-01"
            }),
        );
        assert_eq!(config["result"]["status"], "configured");
        let awaiting: HealthSnapshot =
            serde_json::from_value(process.rpc("awaiting", "health", json!({}))["result"].clone())
                .unwrap();
        assert!(!awaiting.is_ready());

        let key = Ed25519SigningKey::generate();
        let handshake = process.rpc(
            "handshake",
            "handshake",
            json!({
                "protocol_version": "2.0.0",
                "zone": "z:work",
                "host_public_key": key.verifying_key().to_bytes(),
                "nonce": vec![3_u8; 32],
                "capabilities_requested": [operation, operation, "anthropic.unknown"]
            }),
        );
        assert_eq!(
            handshake["result"]["capabilities_granted"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(handshake["result"]["connector_id"], "fcp.anthropic");
        assert_eq!(handshake["result"]["event_caps"]["streaming"], false);
        let ready: HealthSnapshot =
            serde_json::from_value(process.rpc("ready", "health", json!({}))["result"].clone())
                .unwrap();
        assert!(ready.is_ready());
        assert_eq!(
            ready.details.as_ref().unwrap()["instance_id"],
            handshake["result"]["instance_id"]
        );
        let instance: InstanceId =
            serde_json::from_value(handshake["result"]["instance_id"].clone()).unwrap();
        let catalog: Introspection = serde_json::from_value(
            process.rpc("catalog", "introspect", json!({}))["result"].clone(),
        )
        .unwrap();
        assert_eq!(catalog.operations.len(), 7);
        assert!(
            catalog
                .operations
                .iter()
                .any(|op| op.id.as_str() == "anthropic.models.normalize")
        );

        let token = grant(
            &key,
            &instance,
            operation,
            b"single-call",
            &CapabilityConstraints {
                resource_allow: vec![format!("anthropic:model:{MODEL}")],
                max_calls: Some(1),
                max_bytes: Some(1_000_000),
                ..Default::default()
            },
        );
        let mut request = json!({
            "type": "simulate",
            "id": "message-preview",
            "connector_id": "fcp.anthropic",
            "zone_id": "z:work",
            "operation": operation,
            "input": {
                "model": "sonnet-4.6",
                "messages": [{"role": "user", "content": [{"type": "text", "text": "Weather?"}]}],
                "system": [{"type": "text", "text": "Use the weather tool."}],
                "tools": [{"name": "weather", "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}}],
                "max_tokens": 256
            },
            "capability_token": token
        });
        for _ in 0..3 {
            let preview: SimulateResponse = serde_json::from_value(
                process.rpc("preview", "simulate", request.clone())["result"].clone(),
            )
            .unwrap();
            assert!(preview.would_succeed);
        }
        server.assert_no_requests();

        request["type"] = json!("invoke");
        request["id"] = json!("provider-request");
        let mut malformed = request.clone();
        malformed.as_object_mut().unwrap().remove("connector_id");
        assert_eq!(
            process.rpc("malformed", "invoke", malformed)["error"]["code"],
            "FCP-1003"
        );
        for (field, value) in [("connector_id", "fcp.other"), ("zone_id", "z:private")] {
            let mut wrong_target = request.clone();
            wrong_target[field] = json!(value);
            assert_eq!(
                process.rpc("wrong-target", "invoke", wrong_target)["error"]["code"],
                "FCP-3001"
            );
        }
        let mut zero_deadline = request.clone();
        zero_deadline["deadline_ms"] = json!(0);
        assert_eq!(
            process.rpc("zero-deadline", "invoke", zero_deadline)["error"]["code"],
            "FCP-1003"
        );
        let mut wrong_model = request.clone();
        wrong_model["input"]["model"] = json!("claude-opus-4-6");
        assert_eq!(
            process.rpc("model-scope", "invoke", wrong_model)["error"]["code"],
            "FCP-3004"
        );
        let mut invalid = request.clone();
        invalid["input"]["max_tokens"] = json!(0);
        assert_eq!(
            process.rpc("schema", "invoke", invalid)["error"]["code"],
            "FCP-1003"
        );
        let mut short_budget = request.clone();
        short_budget["capability_token"] = json!(grant(
            &key,
            &instance,
            operation,
            b"too-few-bytes",
            &CapabilityConstraints {
                resource_allow: vec!["*".into()],
                max_bytes: Some(1),
                ..Default::default()
            }
        ));
        assert_eq!(
            process.rpc("short-budget", "invoke", short_budget)["error"]["code"],
            "FCP-3001"
        );
        server.assert_no_requests();

        let response: InvokeResponse = serde_json::from_value(
            process.rpc("transport-request", "invoke", request.clone())["result"].clone(),
        )
        .expect("native invocation must carry a complete host response");
        assert_eq!(response.r#type, "response");
        assert_eq!(response.id.0, "provider-request");
        assert_eq!(response.status, InvokeStatus::Ok);
        let result = response.result.unwrap();
        assert_eq!(result["id"], "msg-native");
        assert_eq!(result["content"], "Checking the weather.");
        assert_eq!(result["content_blocks"][1]["type"], "tool_use");
        assert_eq!(
            result["content_blocks"][1]["input"],
            json!({"city": "Paris"})
        );
        assert_eq!(result["stop_reason"], "tool_use");
        assert_eq!(result["usage"]["input_tokens"], 12);
        assert_eq!(result["usage"]["output_tokens"], 8);
        assert!(result["usage"]["service_tier"].is_null());
        assert_eq!(result["provenance"]["has_tool_calls"], true);
        if operation.ends_with(".stream") {
            assert_eq!(result["streamed"], true);
        }
        let captured = server.receive();
        assert_eq!(
            captured.headers.lines().next(),
            Some("POST /v1/messages HTTP/1.1")
        );
        assert!(has_header(&captured.headers, "x-api-key", API_KEY));
        assert!(has_header(
            &captured.headers,
            "anthropic-version",
            "2023-06-01"
        ));
        assert_eq!(captured.body["model"], MODEL);
        assert!(captured.body["messages"][0]["content"].is_array());
        assert!(captured.body["system"].is_array());
        assert_eq!(captured.body["tools"][0]["name"], "weather");
        assert_eq!(
            captured.body["stream"].as_bool().unwrap_or(false),
            operation.ends_with(".stream")
        );

        assert_eq!(
            process.rpc("spent", "invoke", request.clone())["error"]["code"],
            "FCP-3001"
        );
        request["type"] = json!("simulate");
        let spent: SimulateResponse = serde_json::from_value(
            process.rpc("spent-preview", "simulate", request)["result"].clone(),
        )
        .unwrap();
        assert!(!spent.would_succeed);
        assert_eq!(
            process.rpc("shutdown", "shutdown", json!({}))["result"]["status"],
            "shutdown"
        );
        assert!(process.wait_for_exit().success());
        assert!(process.output.try_recv().is_err());
        server.finish();
    }
}

#[test]
fn native_framing_recovers_and_shutdown_stops_buffered_work() {
    let mut process = NativeProcess::start();
    process.send_bytes(b"{bad json\n").unwrap();
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");
    process
        .send_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"health\",\"params\":{}}\n")
        .unwrap();
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");
    process
        .send_bytes(b"{\"jsonrpc\":\"1.0\",\"id\":7,\"method\":\"health\",\"params\":{}}\n")
        .unwrap();
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");
    let health: HealthSnapshot =
        serde_json::from_value(process.rpc("after-errors", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(!health.is_ready());
    process.send_bytes(
        b"{\"jsonrpc\":\"2.0\",\"id\":\"quit\",\"method\":\"shutdown\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":\"must-not-run\",\"method\":\"health\",\"params\":{}}\n"
    ).unwrap();
    assert_eq!(process.receive()["id"], "quit");
    assert!(process.wait_for_exit().success());
    assert!(process.output.try_recv().is_err());
}

#[test]
fn native_oversized_frame_closes_transport() {
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


fn prepared_deadline_process(
    server: &LoopbackServer,
    operation: &str,
) -> (NativeProcess, Ed25519SigningKey, InstanceId) {
    let mut process = NativeProcess::start();
    assert_eq!(
        process.rpc(
            "configure",
            "configure",
            json!({"api_key": API_KEY, "base_url": server.url}),
        )["result"]["status"],
        "configured"
    );
    let key = Ed25519SigningKey::generate();
    let handshake = process.rpc(
        "handshake",
        "handshake",
        json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![9_u8; 32],
            "capabilities_requested": [operation, "anthropic.get_usage"]
        }),
    );
    let instance = serde_json::from_value(handshake["result"]["instance_id"].clone()).unwrap();
    (process, key, instance)
}

fn bounded_provider_request(
    key: &Ed25519SigningKey,
    instance: &InstanceId,
    operation: &str,
) -> Value {
    json!({
        "type": "invoke",
        "id": "bounded-provider",
        "connector_id": "fcp.anthropic",
        "zone_id": "z:work",
        "operation": operation,
        "deadline_ms": 500,
        "input": {
            "model": MODEL,
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 64
        },
        "capability_token": grant(
            key,
            instance,
            operation,
            b"bounded-provider-budget",
            &CapabilityConstraints {
                resource_allow: vec![format!("anthropic:model:{MODEL}")],
                // A second call still has a call slot, but an uncertain first
                // invocation must retain its entire signed byte reservation.
                max_calls: Some(2),
                max_bytes: Some(1_000_000),
                ..Default::default()
            },
        )
    })
}

fn assert_uncertain_budget_is_retained(
    process: &mut NativeProcess,
    server: &LoopbackServer,
    mut request: Value,
    key: &Ed25519SigningKey,
    instance: &InstanceId,
) {
    request["id"] = json!("would-repeat-provider");
    request["deadline_ms"] = json!(5_000);
    assert_eq!(
        process.rpc("spent-byte-budget", "invoke", request)["error"]["code"],
        "FCP-3001"
    );
    server.assert_no_requests();

    // Timing out one invocation must not cancel the client runtime or prevent
    // independent work under a fresh grant in the same negotiated session.
    let recovery: InvokeResponse = serde_json::from_value(
        process.rpc(
            "after-interruption",
            "invoke",
            json!({
                "type": "invoke",
                "id": "independent-local-operation",
                "connector_id": "fcp.anthropic",
                "zone_id": "z:work",
                "operation": "anthropic.get_usage",
                "input": {},
                "capability_token": grant(
                    key,
                    instance,
                    "anthropic.get_usage",
                    b"fresh-local-budget",
                    &CapabilityConstraints {
                        resource_allow: vec!["*".into()],
                        ..Default::default()
                    },
                )
            }),
        )["result"]
            .clone(),
    )
    .unwrap();
    assert_eq!(recovery.status, InvokeStatus::Ok);
}

#[test]
fn native_deadline_bounds_retry_wait_and_http_and_sse_body_reads() {
    let partial_stream = STREAM_RESPONSE
        .split_once("event: message_stop")
        .unwrap()
        .0;
    let rate_limit_body =
        r#"{"type":"error","error":{"type":"rate_limit_error","message":"try later"}}"#;
    let scenarios = [
        (
            "anthropic.message",
            format!(
                "HTTP/1.1 429 Too Many Requests\r\nretry-after: 60\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{rate_limit_body}",
                rate_limit_body.len()
            ),
            false,
        ),
        (
            "anthropic.message",
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{\"id\":"
                .to_string(),
            true,
        ),
        (
            "anthropic.message.stream",
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n{partial_stream}"
            ),
            true,
        ),
    ];
    for (operation, response, hold_open) in scenarios {
        let server = LoopbackServer::scripted(response, hold_open);
        let (mut process, key, instance) = prepared_deadline_process(&server, operation);
        let request = bounded_provider_request(&key, &instance, operation);
        let started = Instant::now();
        let response = process.rpc("deadline", "invoke", request.clone());
        assert!(
            started.elapsed() < StdDuration::from_secs(3),
            "host deadline did not bound the complete provider operation"
        );
        assert_eq!(response["error"]["retryable"], false);
        let message = response["error"]["message"].as_str().unwrap();
        assert!(message.contains("deadline"), "{response}");
        assert!(message.contains("outcome may be unknown"), "{response}");
        let captured = server.receive();
        assert_eq!(
            captured.body["stream"].as_bool().unwrap_or(false),
            operation.ends_with(".stream")
        );
        assert_uncertain_budget_is_retained(
            &mut process,
            &server,
            request,
            &key,
            &instance,
        );
        server.finish();
    }
}

#[test]
fn native_sse_requires_terminal_message_and_closed_content() {
    let without_stop = STREAM_RESPONSE
        .split_once("event: message_stop")
        .unwrap()
        .0;
    let before_first_block_stop = STREAM_RESPONSE
        .split_once("event: content_block_stop")
        .unwrap()
        .0;
    let terminal = concat!(
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":8}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );
    let without_final_delta = STREAM_RESPONSE
        .split_once("event: message_delta")
        .unwrap()
        .0;
    for (body, expected_error, missing_bytes) in [
        (without_stop.to_string(), "ended before message_stop", 0),
        (without_stop.to_string(), "failed before message_stop", 50),
        (
            format!("{before_first_block_stop}{terminal}"),
            "before final message_delta or content_block_stop",
            0,
        ),
        (
            format!(
                "{without_final_delta}event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
            ),
            "before final message_delta or content_block_stop",
            0,
        ),
        (
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
            "before message_start",
            0,
        ),
    ] {
        let server = LoopbackServer::scripted(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len() + missing_bytes
            ),
            false,
        );
        let (mut process, key, instance) =
            prepared_deadline_process(&server, "anthropic.message.stream");
        let request = bounded_provider_request(&key, &instance, "anthropic.message.stream");
        let response = process.rpc("incomplete-stream", "invoke", request.clone());
        assert_eq!(response["error"]["retryable"], false);
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains(expected_error),
            "{response}"
        );
        server.receive();
        assert_uncertain_budget_is_retained(
            &mut process,
            &server,
            request,
            &key,
            &instance,
        );
        server.finish();
    }
}

#[test]
fn native_sse_terminal_event_finishes_without_waiting_for_http_eof() {
    let start = STREAM_RESPONSE.split_once("event: content_block_start").unwrap().0;
    let empty_message = format!(
        "{start}{}",
        concat!(
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":null},\"usage\":{\"output_tokens\":8}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        )
    );
    for (body, reason, has_tool) in [
        (STREAM_RESPONSE, "tool_use", true),
        (empty_message.as_str(), "end_turn", false),
    ] {
        let server = LoopbackServer::scripted(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n{body}"
            ),
            true,
        );
        let (mut process, key, instance) =
            prepared_deadline_process(&server, "anthropic.message.stream");
        let request = bounded_provider_request(&key, &instance, "anthropic.message.stream");
        let response: InvokeResponse = serde_json::from_value(
            process.rpc("complete-open-stream", "invoke", request)["result"].clone(),
        )
        .expect("message_stop must complete without waiting for transport EOF");
        assert_eq!(response.status, InvokeStatus::Ok);
        let result = response.result.unwrap();
        assert_eq!(result["stop_reason"], reason);
        assert_eq!(result["usage"]["output_tokens"], 8);
        if has_tool {
            assert_eq!(result["content_blocks"][1]["input"], json!({"city": "Paris"}));
        } else {
            assert_eq!(result["content"], "");
            assert_eq!(result["content_blocks"], json!([]));
        }
        server.receive();
        server.finish();
    }
}


fn append_provider_event(body: &mut String, event: Value) {
    body.push_str("event: ");
    body.push_str(event["type"].as_str().unwrap());
    body.push_str("\ndata: ");
    body.push_str(&event.to_string());
    body.push_str("\n\n");
}

fn provider_stream_start() -> String {
    STREAM_RESPONSE
        .split_once("event: content_block_start")
        .unwrap()
        .0
        .to_string()
}

fn finish_provider_stream(body: &mut String) {
    append_provider_event(
        body,
        json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn"},
            "usage": {"output_tokens": 8}
        }),
    );
    append_provider_event(body, json!({"type": "message_stop"}));
}

fn full_stream_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn assert_provider_limit(
    server: &LoopbackServer,
    operation: &str,
    expected_message: &str,
) {
    let (mut process, key, instance) = prepared_deadline_process(server, operation);
    let mut request = bounded_provider_request(&key, &instance, operation);
    request["deadline_ms"] = json!(5_000);
    let response = process.rpc("bounded-provider-output", "invoke", request.clone());
    assert_eq!(response["error"]["retryable"], false, "{response}");
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains(expected_message),
        "{response}"
    );
    server.receive();
    assert_uncertain_budget_is_retained(&mut process, server, request, &key, &instance);
}

#[test]
fn native_sse_rejects_sparse_reopened_and_excessive_blocks() {
    for (scenario, expected_message) in [
        ("huge", "non-contiguous content block index"),
        ("gap", "non-contiguous content block index"),
        ("reopen", "reopened content block"),
        ("count", "content block count limit"),
    ] {
        let mut body = provider_stream_start();
        let indices = match scenario {
            "huge" => vec![u32::MAX],
            "gap" => vec![1],
            "reopen" => vec![0, 0],
            "count" => (0..1025).collect(),
            _ => unreachable!(),
        };
        for index in indices {
            append_provider_event(
                &mut body,
                json!({
                    "type": "content_block_start",
                    "index": index,
                    "content_block": {"type": "text", "text": ""}
                }),
            );
            append_provider_event(
                &mut body,
                json!({"type": "content_block_stop", "index": index}),
            );
        }
        finish_provider_stream(&mut body);
        let server = LoopbackServer::scripted(full_stream_response(&body), false);
        assert_provider_limit(&server, "anthropic.message.stream", expected_message);
        server.finish();
    }
}

#[test]
fn native_sse_bounds_aggregate_text_and_tool_json_before_growth() {
    for (scenario, expected_message) in [
        ("text", "assembly byte limit"),
        ("single_event", "stream limit exceeded"),
        ("escaped_text", "assembly byte limit"),
        ("initial_text", "assembly byte limit"),
        ("per_tool", "per-block tool JSON byte limit"),
        ("aggregate_tool", "aggregate tool JSON byte limit"),
    ] {
        let mut body = provider_stream_start();
        match scenario {
            "single_event" => {
                append_provider_event(
                    &mut body,
                    json!({
                        "type": "content_block_start",
                        "index": 0,
                        "content_block": {"type": "text", "text": "x".repeat(1024 * 1024)}
                    }),
                );
                append_provider_event(
                    &mut body,
                    json!({"type": "content_block_stop", "index": 0}),
                );
            }
            "text" | "escaped_text" => {
                append_provider_event(
                    &mut body,
                    json!({
                        "type": "content_block_start",
                        "index": 0,
                        "content_block": {"type": "text", "text": ""}
                    }),
                );
                let (fragment, count) = if scenario == "text" {
                    ("x".repeat(256 * 1024), 36)
                } else {
                    // Raw text is small, but JSON escaping and duplicate output
                    // representations must both count against assembly capacity.
                    ("\u{0001}".repeat(64 * 1024), 24)
                };
                for _ in 0..count {
                    append_provider_event(
                        &mut body,
                        json!({
                            "type": "content_block_delta",
                            "index": 0,
                            "delta": {"type": "text_delta", "text": fragment}
                        }),
                    );
                }
                append_provider_event(
                    &mut body,
                    json!({"type": "content_block_stop", "index": 0}),
                );
            }
            "initial_text" => {
                for index in 0..34 {
                    append_provider_event(
                        &mut body,
                        json!({
                            "type": "content_block_start",
                            "index": index,
                            "content_block": {"type": "text", "text": "x".repeat(256 * 1024)}
                        }),
                    );
                    append_provider_event(
                        &mut body,
                        json!({"type": "content_block_stop", "index": index}),
                    );
                }
            }
            "per_tool" | "aggregate_tool" => {
                let (payload_bytes, blocks) = if scenario == "per_tool" {
                    (256 * 1024, 1)
                } else {
                    (128 * 1024, 9)
                };
                let input = json!({"payload": "x".repeat(payload_bytes)}).to_string();
                for index in 0..blocks {
                    append_provider_event(
                        &mut body,
                        json!({
                            "type": "content_block_start",
                            "index": index,
                            "content_block": {
                                "type": "tool_use",
                                "id": format!("tool-{index}"),
                                "name": "lookup",
                                "input": {}
                            }
                        }),
                    );
                    for partial in input.as_bytes().chunks(128 * 1024) {
                        append_provider_event(
                            &mut body,
                            json!({
                                "type": "content_block_delta",
                                "index": index,
                                "delta": {
                                    "type": "input_json_delta",
                                    "partial_json": std::str::from_utf8(partial).unwrap()
                                }
                            }),
                        );
                    }
                    append_provider_event(
                        &mut body,
                        json!({"type": "content_block_stop", "index": index}),
                    );
                }
            }
            _ => unreachable!(),
        }
        finish_provider_stream(&mut body);
        let server = LoopbackServer::scripted(full_stream_response(&body), false);
        assert_provider_limit(&server, "anthropic.message.stream", expected_message);
        server.finish();
    }
}

#[test]
fn native_sse_preserves_normal_multiple_text_and_tool_blocks() {
    let mut body = provider_stream_start();
    append_provider_event(
        &mut body,
        json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": "Hello"}
        }),
    );
    append_provider_event(&mut body, json!({"type": "content_block_stop", "index": 0}));
    for index in 1..=3 {
        append_provider_event(
            &mut body,
            json!({
                "type": "content_block_start",
                "index": index,
                "content_block": {
                    "type": "tool_use",
                    "id": format!("tool-{index}"),
                    "name": "weather",
                    "input": {}
                }
            }),
        );
        append_provider_event(
            &mut body,
            json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": json!({"city": "Paris", "day": index}).to_string()
                }
            }),
        );
        append_provider_event(
            &mut body,
            json!({"type": "content_block_stop", "index": index}),
        );
    }
    append_provider_event(
        &mut body,
        json!({
            "type": "content_block_start",
            "index": 4,
            "content_block": {"type": "text", "text": " done"}
        }),
    );
    append_provider_event(&mut body, json!({"type": "content_block_stop", "index": 4}));
    finish_provider_stream(&mut body);
    let server = LoopbackServer::scripted(full_stream_response(&body), false);
    let (mut process, key, instance) =
        prepared_deadline_process(&server, "anthropic.message.stream");
    let request = bounded_provider_request(&key, &instance, "anthropic.message.stream");
    let response: InvokeResponse = serde_json::from_value(
        process.rpc("bounded-multiple-blocks", "invoke", request)["result"].clone(),
    )
    .unwrap();
    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.unwrap();
    assert_eq!(result["content"], "Hello done");
    assert_eq!(result["content_blocks"].as_array().unwrap().len(), 5);
    for index in 1..=3 {
        assert_eq!(
            result["content_blocks"][index]["input"],
            json!({"city": "Paris", "day": index})
        );
    }
    server.receive();
    server.finish();
}

fn oversized_chunked_json_response(status: &str) -> String {
    let mut response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
    );
    // Individually small chunks cumulatively exceed the 2 MiB decoded-body cap.
    let chunk = "x".repeat(64 * 1024);
    for _ in 0..33 {
        response.push_str(&format!("{:X}\r\n{chunk}\r\n", chunk.len()));
    }
    response.push_str("0\r\n\r\n");
    response
}

#[test]
fn native_provider_body_limits_are_terminal_for_success_and_retryable_statuses() {
    let raw_limit = 2 * 1024 * 1024;
    for (operation, response, hold_open, expected) in [
        (
            "anthropic.message",
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                raw_limit + 1
            ),
            true,
            "response exceeded",
        ),
        (
            "anthropic.message.stream",
            format!(
                "HTTP/1.1 529 Overloaded\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                raw_limit + 1
            ),
            true,
            "response exceeded",
        ),
        (
            "anthropic.message",
            oversized_chunked_json_response("429 Too Many Requests"),
            false,
            "response exceeded",
        ),
        (
            "anthropic.message.stream",
            oversized_chunked_json_response("503 Service Unavailable"),
            false,
            "response exceeded",
        ),
        (
            "anthropic.message",
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{MESSAGE_RESPONSE}",
                MESSAGE_RESPONSE.len() + 50
            ),
            false,
            "could not be read completely",
        ),
    ] {
        let server = LoopbackServer::scripted(response, hold_open);
        assert_provider_limit(&server, operation, expected);
        server.finish();
    }
}
