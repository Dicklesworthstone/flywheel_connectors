//! Acceptance tests for the shipped Bedrock JSONL executable and real loopback HTTP.

#![allow(
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
    CapabilityConstraints, CapabilityToken, FcpErrorResponse, HealthSnapshot, InstanceId,
    InvokeResponse, InvokeStatus, SimulateResponse,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::{Value, json};

const MODEL: &str = "anthropic.claude-3-sonnet-20240229-v1:0";
const MODEL_URI: &str =
    "aws-bedrock://model/anthropic.claude-3-sonnet-20240229-v1%3A0";
const OP_CONVERSE: &str = "aws_bedrock.converse";
const OP_INVOKE_MODEL: &str = "aws_bedrock.invoke_model";
const ACCESS_KEY: &str = "bedrock-native-access-key";
const SIGNING_MATERIAL: &str = "bedrock-native-signing-material";
const MANTLE_TOKEN: &str = "bedrock-native-mantle-token";
const MANTLE_MODEL: &str = "anthropic.claude-opus-4-7";
const MANTLE_MODEL_URI: &str = "aws-bedrock://model/anthropic.claude-opus-4-7";

fn converse_output() -> Value {
    json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "native fixture"}]}},
        "usage": {"inputTokens": 3, "outputTokens": 1}
    })
}

#[derive(Clone)]
struct CapturedRequest {
    method: String,
    target: String,
    headers: String,
    body: Value,
}

struct ProviderResponse {
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    body: Value,
}

impl ProviderResponse {
    fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    fn retry_after(mut self, seconds: &'static str) -> Self {
        self.headers.push(("retry-after", seconds));
        self
    }
}

struct LoopbackServer {
    url: String,
    requests: Receiver<CapturedRequest>,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl LoopbackServer {
    fn start(responses: Vec<ProviderResponse>) -> Self {
        assert!(!responses.is_empty());
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let expires = Instant::now() + StdDuration::from_secs(20);
            let mut count = 0;
            loop {
                if stopped.try_recv().is_ok() {
                    break;
                }
                assert!(Instant::now() < expires, "loopback provider was not released");
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(StdDuration::from_secs(3))).unwrap();
                        stream.set_write_timeout(Some(StdDuration::from_secs(3))).unwrap();
                        sender.send(read_request(&mut stream)).unwrap();
                        let response = &responses[count.min(responses.len() - 1)];
                        count += 1;
                        let body = response.body.to_string();
                        let mut wire = format!(
                            "HTTP/1.1 {} Fixture\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                            response.status,
                            body.len()
                        );
                        for (name, value) in &response.headers {
                            wire.push_str(&format!("{name}: {value}\r\n"));
                        }
                        wire.push_str("\r\n");
                        wire.push_str(&body);
                        if let Err(error) = stream
                            .write_all(wire.as_bytes())
                            .and_then(|()| stream.flush())
                        {
                            assert!(
                                matches!(
                                    error.kind(),
                                    std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::ConnectionReset
                                ),
                                "provider write failed: {error}"
                            );
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(StdDuration::from_millis(5));
                    }
                    Err(error) => panic!("provider accept failed: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop: Some(stop),
            worker: Some(worker),
        }
    }

    fn success() -> Self {
        Self::start(vec![ProviderResponse::json(200, converse_output())])
    }

    fn assert_no_requests(&self) {
        assert!(
            matches!(self.requests.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "an unadmitted or repeated invocation reached the provider"
        );
    }

    fn receive(&self) -> CapturedRequest {
        self.requests.recv_timeout(StdDuration::from_secs(5)).unwrap()
    }

    fn finish(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.worker.take().unwrap().join().unwrap();
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "provider connection closed before request completed");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 65_536, "fixture request exceeded its bound");
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                let mut request_line = headers.lines().next().unwrap().split_whitespace();
                let method = request_line.next().unwrap().to_string();
                let target = request_line.next().unwrap().to_string();
                let body = if length == 0 {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap()
                };
                return CapturedRequest {
                    method,
                    target,
                    headers,
                    body,
                };
            }
        }
    }
}

fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (actual, value) = line.split_once(':')?;
        actual.eq_ignore_ascii_case(name).then(|| value.trim())
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-aws-bedrock"))
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("shipped Bedrock executable should start");
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let parsed = line
                    .map_err(|error| error.to_string())
                    .and_then(|line| serde_json::from_str(&line).map_err(|error| error.to_string()));
                if sender.send(parsed).is_err() {
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
            .expect("stdout must contain JSONL protocol responses only")
    }

    fn rpc(&mut self, id: &str, method: &str, params: Value) -> Value {
        let mut bytes = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))
        .unwrap();
        bytes.push(b'\n');
        self.send_bytes(&bytes).unwrap();
        let response = self.receive();
        assert_eq!(response["id"], id);
        response
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + StdDuration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "native process failed to exit");
            thread::sleep(StdDuration::from_millis(10));
        };
        self.input.take();
        self.reader.take().unwrap().join().unwrap();
        status
    }

    fn shutdown(&mut self) {
        assert_eq!(
            self.rpc(
                "shutdown",
                "shutdown",
                json!({
                    "type": "shutdown",
                    "deadline_ms": 1000,
                    "drain": false,
                    "reason": "native fixture complete"
                }),
            )["result"]["status"],
            "shutdown"
        );
        assert!(self.wait_for_exit().success());
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

fn native_config(server: Option<&LoopbackServer>) -> Value {
    let mut config = json!({
        "access_key_id": ACCESS_KEY,
        "secret_access_key": SIGNING_MATERIAL,
        "region": "us-east-1",
        "request_timeout_ms": 5_000,
        "retry": {
            "max_retries": 0,
            "initial_delay_ms": 1,
            "max_delay_ms": 1,
            "jitter_enabled": false
        }
    });
    if let Some(server) = server {
        config["runtime_base_url"] = json!(server.url);
        config["control_base_url"] = json!(server.url);
    }
    config
}

fn configure(process: &mut NativeProcess, config: Value) {
    assert_eq!(
        process.rpc("configure", "configure", config)["result"]["status"],
        "configured"
    );
}

fn handshake_params(key: &Ed25519SigningKey, capabilities: &[&str]) -> Value {
    json!({
        "protocol_version": "2.0",
        "zone": "z:work",
        "host_public_key": key.verifying_key().to_bytes(),
        "nonce": vec![11_u8; 32],
        "capabilities_requested": capabilities
    })
}

fn handshake(
    process: &mut NativeProcess,
    key: &Ed25519SigningKey,
    capabilities: &[&str],
) -> InstanceId {
    let response = process.rpc("handshake", "handshake", handshake_params(key, capabilities));
    assert_eq!(response["result"]["connector_id"], "fcp.aws-bedrock");
    assert_eq!(response["result"]["protocol_version"], "2.0");
    serde_json::from_value(response["result"]["instance_id"].clone()).unwrap()
}

fn grant(
    key: &Ed25519SigningKey,
    instance: &InstanceId,
    operation: &str,
    token_id: &[u8],
    constraints: &CapabilityConstraints,
) -> CapabilityToken {
    let capability = match operation {
        "aws_bedrock.converse"
        | "aws_bedrock.converse_stream"
        | "aws_bedrock.invoke_model"
        | "aws_bedrock.invoke_model_stream" => "aws_bedrock.chat",
        "aws_bedrock.models.list" | "aws_bedrock.health" => "aws_bedrock.models.read",
        _ => panic!("unknown fixture operation"),
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).unwrap();
    let now = Utc::now();
    CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(capability)
            .operations(&[operation])
            .zone_id("z:work")
            .principal("user:native-bedrock")
            .issuer("node:native-bedrock")
            .target_instance(instance.as_str())
            .token_id(token_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(key)
            .unwrap(),
    )
}

fn request(operation: &str, input: Value, token: CapabilityToken) -> Value {
    json!({
        "type": "invoke",
        "id": "provider-invocation",
        "connector_id": "fcp.aws-bedrock",
        "zone_id": "z:work",
        "operation": operation,
        "input": input,
        "capability_token": token
    })
}

fn converse_input() -> Value {
    json!({
        "model_id": MODEL,
        "messages": [{"role": "user", "content": [{"text": "Hello"}]}],
        "inference_config": {"maxTokens": 4}
    })
}

fn model_constraints(max_calls: u32) -> CapabilityConstraints {
    CapabilityConstraints {
        resource_allow: vec![MODEL_URI.into()],
        max_calls: Some(max_calls),
        max_bytes: Some(1_000_000),
        ..Default::default()
    }
}

fn assert_denied(response: &Value) {
    let error: FcpErrorResponse = serde_json::from_value(response["error"].clone())
        .expect("denials must contain complete FCP error envelopes");
    assert!(!error.retryable, "{response}");
}

fn decode_success(response: &Value) -> InvokeResponse {
    let response: InvokeResponse = serde_json::from_value(response["result"].clone())
        .expect("native invoke must contain one full response envelope");
    assert_eq!(response.r#type, "response");
    assert_eq!(response.status, InvokeStatus::Ok);
    response
}

#[test]
fn native_sigv4_identity_scope_preview_and_signed_budgets() {
    let server = LoopbackServer::success();
    let mut process = NativeProcess::start();
    configure(&mut process, native_config(Some(&server)));
    let awaiting: HealthSnapshot =
        serde_json::from_value(process.rpc("awaiting", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(!awaiting.is_ready());
    let key = Ed25519SigningKey::generate();
    let instance = handshake(
        &mut process,
        &key,
        &["aws_bedrock.chat", "aws_bedrock.models.read"],
    );
    let health: HealthSnapshot =
        serde_json::from_value(process.rpc("ready", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(health.is_ready());
    let details = health.details.unwrap();
    assert_eq!(details["configured"], true);
    assert_eq!(details["handshaken"], true);
    assert_eq!(details["instance_id"], json!(instance));
    let token = grant(&key, &instance, OP_CONVERSE, b"single-call", &model_constraints(1));
    let invocation = request(OP_CONVERSE, converse_input(), token);

    let mut preview = invocation.clone();
    preview["type"] = json!("simulate");
    for _ in 0..2 {
        let preview: SimulateResponse = serde_json::from_value(
            process.rpc("preview", "simulate", preview.clone())["result"].clone(),
        )
        .unwrap();
        assert!(preview.would_succeed);
    }
    for (field, value) in [
        ("connector_id", json!("fcp.other")),
        ("zone_id", json!("z:private")),
        ("id", json!("")),
        ("type", json!("simulate")),
        ("deadline_ms", json!(0)),
    ] {
        let mut invalid = invocation.clone();
        invalid[field] = value;
        assert_denied(&process.rpc("invalid-envelope", "invoke", invalid));
    }
    let mut wrong_resource = invocation.clone();
    wrong_resource["input"]["model_id"] = json!("amazon.titan-text-express-v1");
    assert_denied(&process.rpc("wrong-resource", "invoke", wrong_resource));
    let mut invalid_input = invocation.clone();
    invalid_input["input"]["messages"] = json!([]);
    assert_denied(&process.rpc("invalid-input", "invoke", invalid_input));
    for suffix in ["?route=other", "#fragment", "%2Fother", "/other", " space"] {
        let mut ambiguous = invocation.clone();
        ambiguous["input"]["model_id"] = json!(format!("{MODEL}{suffix}"));
        let response = process.rpc("ambiguous-model-route", "invoke", ambiguous);
        assert_denied(&response);
        assert!(response["error"]["code"].as_str().unwrap().starts_with("FCP-10"));
    }
    server.assert_no_requests();

    let response = decode_success(&process.rpc("transport-correlation", "invoke", invocation.clone()));
    assert_eq!(response.id.0, "provider-invocation");
    assert_eq!(response.result.unwrap(), converse_output());
    let captured = server.receive();
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.target, format!("/model/{MODEL}/converse"));
    assert_eq!(captured.body["messages"], converse_input()["messages"]);
    let authorization = header(&captured.headers, "authorization").unwrap();
    assert!(authorization.starts_with(&format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/")));
    assert!(authorization.contains("/us-east-1/bedrock/aws4_request"));
    assert!(authorization.contains("SignedHeaders="));
    assert!(authorization.contains("Signature="));
    assert!(header(&captured.headers, "x-amz-date").is_some());
    assert!(header(&captured.headers, "x-amz-content-sha256").is_some());
    assert!(!captured.headers.contains(SIGNING_MATERIAL));
    assert!(!captured.body.to_string().contains(SIGNING_MATERIAL));
    assert_eq!(
        process.rpc("spent", "invoke", invocation)["error"]["code"],
        "FCP-3001"
    );
    server.assert_no_requests();
    process.shutdown();
    server.finish();
}

#[test]
fn native_default_endpoint_readiness_does_not_require_probe_traffic() {
    let mut process = NativeProcess::start();
    configure(&mut process, native_config(None));
    let key = Ed25519SigningKey::generate();
    let instance = handshake(&mut process, &key, &["aws_bedrock.chat"]);
    let health: HealthSnapshot =
        serde_json::from_value(process.rpc("health", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(health.is_ready());
    assert_eq!(health.details.unwrap()["instance_id"], json!(instance));
    let check = process.rpc("self-check", "self_check", json!({}));
    assert_eq!(
        check["result"]["reason_code"],
        "self_check_unsupported_on_default_bedrock"
    );
    process.shutdown();
}

#[test]
fn native_session_rotation_and_failed_lifecycle_revoke_prior_grants() {
    let server = LoopbackServer::success();
    let mut process = NativeProcess::start();
    configure(&mut process, native_config(Some(&server)));
    let key = Ed25519SigningKey::generate();
    let first = handshake(&mut process, &key, &["aws_bedrock.chat"]);
    let stale = request(
        OP_CONVERSE,
        converse_input(),
        grant(&key, &first, OP_CONVERSE, b"old-instance", &model_constraints(1)),
    );
    let second = handshake(&mut process, &key, &["aws_bedrock.chat"]);
    assert_ne!(first, second);
    assert_denied(&process.rpc("stale-instance", "invoke", stale));

    let ungranted = handshake(&mut process, &key, &[]);
    let denied = request(
        OP_CONVERSE,
        converse_input(),
        grant(&key, &ungranted, OP_CONVERSE, b"unnegotiated", &model_constraints(1)),
    );
    assert_denied(&process.rpc("unnegotiated", "invoke", denied));

    for malformed in [false, true] {
        let instance = handshake(&mut process, &key, &["aws_bedrock.chat"]);
        let old = request(
            OP_CONVERSE,
            converse_input(),
            grant(&key, &instance, OP_CONVERSE, b"failed-handshake", &model_constraints(1)),
        );
        let mut invalid = handshake_params(&key, &["aws_bedrock.chat"]);
        if malformed {
            invalid["nonce"] = json!("not-a-nonce");
        } else {
            invalid["protocol_version"] = json!("999.0");
        }
        assert_denied(&process.rpc("bad-handshake", "handshake", invalid));
        assert_denied(&process.rpc("revoked-after-handshake", "invoke", old));
    }

    let instance = handshake(&mut process, &key, &["aws_bedrock.chat"]);
    let old = request(
        OP_CONVERSE,
        converse_input(),
        grant(&key, &instance, OP_CONVERSE, b"bad-config", &model_constraints(1)),
    );
    assert_denied(&process.rpc("bad-config", "configure", json!({"region": "../invalid"})));
    assert_denied(&process.rpc("revoked-after-config", "invoke", old));
    server.assert_no_requests();

    configure(&mut process, native_config(Some(&server)));
    let instance = handshake(&mut process, &key, &["aws_bedrock.chat"]);
    let fresh = request(
        OP_CONVERSE,
        converse_input(),
        grant(&key, &instance, OP_CONVERSE, b"fresh-config", &model_constraints(1)),
    );
    decode_success(&process.rpc("fresh-session", "invoke", fresh));
    server.receive();
    server.assert_no_requests();
    process.shutdown();
    server.finish();
}

#[test]
fn native_errors_preserve_retryability_and_retry_after() {
    let server = LoopbackServer::start(vec![
        ProviderResponse::json(
            429,
            json!({"__type": "ThrottlingException", "message": "fixture throttle"}),
        )
        .retry_after("7"),
    ]);
    let mut process = NativeProcess::start();
    configure(&mut process, native_config(Some(&server)));
    let key = Ed25519SigningKey::generate();
    let instance = handshake(&mut process, &key, &["aws_bedrock.chat"]);
    let invocation = request(
        OP_CONVERSE,
        converse_input(),
        grant(&key, &instance, OP_CONVERSE, b"rate-limited", &model_constraints(1)),
    );
    let response = process.rpc("throttled", "invoke", invocation);
    let error: FcpErrorResponse = serde_json::from_value(response["error"].clone()).unwrap();
    assert!(error.retryable);
    assert_eq!(error.retry_after_ms, Some(7_000));
    assert!(error.ai_recovery_hint.is_some_and(|hint| !hint.is_empty()));
    server.receive();
    server.assert_no_requests();
    process.shutdown();
    server.finish();
}

#[test]
fn native_deadline_retains_uncertain_budget_without_cancelling_fresh_work() {
    let server = LoopbackServer::start(vec![
        ProviderResponse::json(
            429,
            json!({"__type": "ThrottlingException", "message": "wait for provider"}),
        )
        .retry_after("60"),
        ProviderResponse::json(200, converse_output()),
    ]);
    let mut process = NativeProcess::start();
    let mut config = native_config(Some(&server));
    config["retry"]["max_retries"] = json!(1);
    config["retry"]["max_delay_ms"] = json!(60_000);
    configure(&mut process, config);
    let key = Ed25519SigningKey::generate();
    let instance = handshake(&mut process, &key, &["aws_bedrock.chat"]);
    let mut invocation = request(
        OP_CONVERSE,
        converse_input(),
        grant(&key, &instance, OP_CONVERSE, b"interrupted", &model_constraints(2)),
    );
    invocation["deadline_ms"] = json!(500);
    let started = Instant::now();
    let response = process.rpc("deadline", "invoke", invocation.clone());
    assert!(started.elapsed() < StdDuration::from_secs(3));
    assert_denied(&response);
    let message = response["error"]["message"].as_str().unwrap();
    assert!(message.contains("timeout") || message.contains("deadline"), "{response}");
    server.receive();

    // One call slot remains, so this denial specifically proves the uncertain
    // invocation did not regain its reserved byte capacity.
    invocation["id"] = json!("would-replay");
    invocation["deadline_ms"] = json!(5_000);
    assert_eq!(
        process.rpc("uncertain-budget", "invoke", invocation)["error"]["code"],
        "FCP-3001"
    );
    server.assert_no_requests();

    let fresh = request(
        OP_CONVERSE,
        converse_input(),
        grant(&key, &instance, OP_CONVERSE, b"fresh-after-timeout", &model_constraints(1)),
    );
    decode_success(&process.rpc("fresh-after-timeout", "invoke", fresh));
    server.receive();
    server.assert_no_requests();
    process.shutdown();
    server.finish();
}

#[test]
fn native_mantle_model_overrides_cannot_escape_the_grant_or_consume_it() {
    let server = LoopbackServer::start(vec![ProviderResponse::json(
        200,
        json!({
            "id": "msg-native",
            "type": "message",
            "role": "assistant",
            "model": MANTLE_MODEL,
            "content": [{"type": "text", "text": "hello"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
    )]);
    let mut process = NativeProcess::start();
    configure(
        &mut process,
        json!({
            "region": "us-east-1",
            "mantle_bearer_token": MANTLE_TOKEN,
            "mantle_base_url": server.url,
            "request_timeout_ms": 5_000,
            "retry": {"max_retries": 0}
        }),
    );
    let key = Ed25519SigningKey::generate();
    let instance = handshake(&mut process, &key, &["aws_bedrock.chat"]);
    let token = grant(
        &key,
        &instance,
        OP_INVOKE_MODEL,
        b"mantle-model-bound",
        &CapabilityConstraints {
            resource_allow: vec![MANTLE_MODEL_URI.into()],
            max_calls: Some(1),
            max_bytes: Some(1_000_000),
            ..Default::default()
        },
    );
    let invocation = request(
        OP_INVOKE_MODEL,
        json!({
            "model_id": MANTLE_MODEL,
            "model_family": "mantle_anthropic_messages",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "Hello"}]}],
            "max_tokens": 64
        }),
        token,
    );
    for field in ["body", "extra_body"] {
        let mut override_model = invocation.clone();
        override_model["input"][field] = json!({
            "model": "anthropic.claude-sonnet-4-6",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "Hello"}]}],
            "max_tokens": 64
        });
        assert_denied(&process.rpc("model-override", "invoke", override_model));
    }
    let mut override_stream = invocation.clone();
    override_stream["input"]["extra_body"] = json!({"stream": true});
    assert_denied(&process.rpc("stream-override", "invoke", override_stream));
    server.assert_no_requests();

    let response = decode_success(&process.rpc("bound-mantle-model", "invoke", invocation));
    assert_eq!(response.result.unwrap()["model"], MANTLE_MODEL);
    let captured = server.receive();
    assert_eq!(captured.target, "/anthropic/v1/messages");
    assert_eq!(header(&captured.headers, "authorization"), Some("Bearer bedrock-native-mantle-token"));
    assert!(header(&captured.headers, "x-amz-date").is_none());
    assert_eq!(captured.body["model"], MANTLE_MODEL);
    assert_eq!(captured.body["stream"], false);
    process.shutdown();
    server.finish();
}

#[test]
fn native_framing_recovers_and_shutdown_stops_buffered_requests() {
    let mut process = NativeProcess::start();
    process.send_bytes(b" \t\r\n{bad-json\n").unwrap();
    let error: FcpErrorResponse = serde_json::from_value(process.receive()["error"].clone()).unwrap();
    assert_eq!(error.code, "FCP-1001");
    assert!(!error.retryable);
    let health: HealthSnapshot =
        serde_json::from_value(process.rpc("after-invalid", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(!health.is_ready());
    process.send_bytes(
        b"{\"jsonrpc\":\"2.0\",\"id\":\"quit\",\"method\":\"shutdown\",\"params\":{\"type\":\"shutdown\",\"deadline_ms\":1000,\"drain\":false}}\n{\"jsonrpc\":\"2.0\",\"id\":\"must-not-run\",\"method\":\"health\",\"params\":{}}\n"
    ).unwrap();
    assert_eq!(process.receive()["id"], "quit");
    assert!(process.wait_for_exit().success());
    assert!(process.output.try_recv().is_err());
}

#[test]
fn native_oversized_frame_closes_transport() {
    let mut process = NativeProcess::start();
    // Match the native host transport ceiling, which is larger than the SDK default.
    let mut frame = vec![b'x'; 32 * 1024 * 1024 + 1];
    frame.push(b'\n');
    if let Err(error) = process.send_bytes(&frame) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    let error: FcpErrorResponse = serde_json::from_value(process.receive()["error"].clone()).unwrap();
    assert_eq!(error.code, "FCP-1004");
    assert!(!error.retryable);
    assert!(!process.wait_for_exit().success());
}
