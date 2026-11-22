//! Real shipped-binary acceptance over bounded JSONL and loopback Stripe HTTP.

#![allow(clippy::too_many_lines)]

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, Stdio},
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
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

const SECRET: &str = "sk_test_native_fixture";

struct CapturedRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: String,
}

struct ProviderResponse {
    status: u16,
    body: Value,
    retry_after: Option<u64>,
}

impl ProviderResponse {
    fn customer() -> Self {
        Self {
            status: 200,
            body: json!({"id": "cus_native", "object": "customer", "email": "native@example.test"}),
            retry_after: None,
        }
    }

    fn throttled() -> Self {
        Self {
            status: 429,
            body: json!({"error": {"message": "fixture throttle"}}),
            retry_after: Some(60),
        }
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
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let expires = Instant::now() + StdDuration::from_secs(20);
            let mut count = 0;
            loop {
                if stopped.try_recv().is_ok() {
                    break;
                }
                assert!(
                    Instant::now() < expires,
                    "provider fixture was not released"
                );
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(StdDuration::from_secs(3)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(StdDuration::from_secs(3)))
                            .unwrap();
                        sender.send(read_request(&mut stream)).unwrap();
                        let response = &responses[count.min(responses.len() - 1)];
                        count += 1;
                        let body = response.body.to_string();
                        let mut wire = format!(
                            "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                            response.status,
                            body.len()
                        );
                        if let Some(seconds) = response.retry_after {
                            wire.push_str(&format!("Retry-After: {seconds}\r\n"));
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
                        thread::sleep(StdDuration::from_millis(5))
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

    fn receive(&self) -> CapturedRequest {
        self.requests
            .recv_timeout(StdDuration::from_secs(5))
            .unwrap()
    }

    fn assert_no_requests(&self) {
        assert!(
            matches!(self.requests.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "unadmitted or repeated invocation reached Stripe"
        );
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
        assert!(
            read > 0,
            "provider connection closed before complete request"
        );
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 65_536, "fixture request exceeded its bound");
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let text = std::str::from_utf8(&bytes[..end]).unwrap();
            let headers: HashMap<String, String> = text
                .lines()
                .skip(1)
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    Some((name.to_ascii_lowercase(), value.trim().to_owned()))
                })
                .collect();
            let length = headers
                .get("content-length")
                .map_or(0, |value| value.parse::<usize>().unwrap());
            if bytes.len() >= end + 4 + length {
                let mut request_line = text.lines().next().unwrap().split_whitespace();
                return CapturedRequest {
                    method: request_line.next().unwrap().to_owned(),
                    target: request_line.next().unwrap().to_owned(),
                    headers,
                    body: String::from_utf8(bytes[end + 4..end + 4 + length].to_vec()).unwrap(),
                };
            }
        }
    }
}

struct NativeProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Result<Value, String>>,
    reader: Option<JoinHandle<()>>,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-stripe"))
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("shipped Stripe executable should start");
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let value = line.map_err(|error| error.to_string()).and_then(|line| {
                    serde_json::from_str(&line).map_err(|error| error.to_string())
                });
                if sender.send(value).is_err() {
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

    fn send(&mut self, bytes: &[u8]) {
        let input = self.input.as_mut().unwrap();
        input.write_all(bytes).unwrap();
        input.flush().unwrap();
    }

    fn receive(&self) -> Value {
        self.output
            .recv_timeout(StdDuration::from_secs(5))
            .expect("native response deadline")
            .expect("stdout must contain JSONL only")
    }

    fn rpc(&mut self, id: &str, method: &str, params: Value) -> Value {
        let mut bytes = serde_json::to_vec(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )
        .unwrap();
        bytes.push(b'\n');
        self.send(&bytes);
        let response = self.receive();
        assert_eq!(response["id"], id);
        response
    }

    fn wait_for_exit(&mut self) {
        let deadline = Instant::now() + StdDuration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "native process failed to exit");
            thread::sleep(StdDuration::from_millis(10));
        }
        self.input.take();
        self.reader.take().unwrap().join().unwrap();
    }

    fn shutdown(&mut self) {
        assert_eq!(
            self.rpc(
                "shutdown",
                "shutdown",
                json!({"type": "shutdown", "deadline_ms": 1000, "drain": false})
            )["result"]["status"],
            "shutdown"
        );
        self.wait_for_exit();
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

fn configure(process: &mut NativeProcess, server: Option<&LoopbackServer>) {
    let mut config =
        json!({"secret_key": SECRET, "webhook_signing_secret": "whsec_native_fixture"});
    if let Some(server) = server {
        config["api_url"] = json!(server.url);
    }
    assert_eq!(
        process.rpc("configure", "configure", config)["result"]["status"],
        "configured"
    );
}

fn handshake_params(key: &Ed25519SigningKey, capabilities: &[&str]) -> Value {
    json!({"protocol_version": "2.0", "zone": "z:private", "host_public_key": key.verifying_key().to_bytes(), "nonce": vec![11_u8; 32], "capabilities_requested": capabilities})
}

fn handshake(
    process: &mut NativeProcess,
    key: &Ed25519SigningKey,
    capabilities: &[&str],
) -> InstanceId {
    let response = process.rpc(
        "handshake",
        "handshake",
        handshake_params(key, capabilities),
    );
    assert_eq!(response["result"]["connector_id"], "fcp.stripe");
    assert_eq!(response["result"]["protocol_version"], "2.0");
    assert_eq!(response["result"]["event_caps"]["streaming"], false);
    assert_eq!(response["result"]["event_caps"]["replay"], false);
    assert!(
        response["result"]["capabilities_granted"]
            .as_array()
            .unwrap()
            .iter()
            .all(|grant| grant["capability"] != "undeclared.capability")
    );
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
        "stripe.create_customer" => "stripe.write",
        "stripe.ingest_webhook_event" => "stripe.webhook",
        _ => "stripe.read",
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).unwrap();
    let now = Utc::now();
    CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(capability)
            .operations(&[operation])
            .zone_id("z:private")
            .principal("user:native-stripe")
            .issuer("node:native-stripe")
            .target_instance(instance.as_str())
            .token_id(token_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(key)
            .unwrap(),
    )
}

fn constraints(resource: &str, max_calls: u32) -> CapabilityConstraints {
    CapabilityConstraints {
        resource_allow: vec![resource.into()],
        max_calls: Some(max_calls),
        max_bytes: Some(100_000),
        ..Default::default()
    }
}

fn request(id: &str, operation: &str, input: Value, token: CapabilityToken) -> Value {
    json!({"type": "invoke", "id": id, "connector_id": "fcp.stripe", "zone_id": "z:private", "operation": operation, "input": input, "capability_token": token})
}

fn denied(response: &Value) -> FcpErrorResponse {
    let error: FcpErrorResponse =
        serde_json::from_value(response["error"].clone()).expect("complete FCP error envelope");
    assert!(!error.retryable, "{response}");
    assert!(!error.message.contains(SECRET));
    error
}

fn success(response: &Value, id: &str) -> Value {
    let response: InvokeResponse =
        serde_json::from_value(response["result"].clone()).expect("full canonical InvokeResponse");
    assert_eq!(response.r#type, "response");
    assert_eq!(response.id.0, id);
    assert_eq!(response.status, InvokeStatus::Ok);
    assert!(response.error.is_none());
    response.result.unwrap()
}

#[test]
fn native_read_and_form_mutation_enforce_scope_preview_and_signed_budgets() {
    let server = LoopbackServer::start(vec![ProviderResponse::customer()]);
    let mut process = NativeProcess::start();
    let unconfigured: HealthSnapshot =
        serde_json::from_value(process.rpc("health", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(!unconfigured.is_ready());
    configure(&mut process, Some(&server));
    let pending: HealthSnapshot =
        serde_json::from_value(process.rpc("health", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(!pending.is_ready());
    let key = Ed25519SigningKey::generate();
    let instance = handshake(
        &mut process,
        &key,
        &["stripe.read", "stripe.write", "undeclared.capability"],
    );
    let ready: HealthSnapshot =
        serde_json::from_value(process.rpc("health", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(ready.is_ready());
    let details = ready.details.unwrap();
    assert_eq!(details["configured"], true);
    assert_eq!(details["handshaken"], true);
    assert_eq!(details["instance_id"], json!(instance));
    let token = grant(
        &key,
        &instance,
        "stripe.get_customer",
        b"native-read",
        &constraints("stripe:customer:cus_native", 1),
    );
    let read = request(
        "read-one",
        "stripe.get_customer",
        json!({"customer_id": "cus_native"}),
        token,
    );
    let mut preview = read.clone();
    preview["type"] = json!("simulate");
    let preview: SimulateResponse =
        serde_json::from_value(process.rpc("preview", "simulate", preview)["result"].clone())
            .unwrap();
    assert!(preview.would_succeed);
    for (field, value) in [
        ("type", json!("simulate")),
        ("id", json!("")),
        ("connector_id", json!("fcp.other")),
        ("zone_id", json!("z:owner")),
    ] {
        let mut wrong = read.clone();
        wrong[field] = value;
        denied(&process.rpc("wrong-scope", "invoke", wrong));
    }
    let mut missing_target = read.clone();
    missing_target
        .as_object_mut()
        .unwrap()
        .remove("connector_id");
    denied(&process.rpc("missing-target", "invoke", missing_target));
    let mut missing_token = read.clone();
    missing_token
        .as_object_mut()
        .unwrap()
        .remove("capability_token");
    denied(&process.rpc("missing-token", "invoke", missing_token));
    let attacker = Ed25519SigningKey::generate();
    let forged = request(
        "forged",
        "stripe.get_customer",
        json!({"customer_id": "cus_native"}),
        grant(
            &attacker,
            &instance,
            "stripe.get_customer",
            b"forged-token",
            &constraints("stripe:customer:cus_native", 1),
        ),
    );
    denied(&process.rpc("wrong-signature", "invoke", forged));
    let mut wrong_resource = read.clone();
    wrong_resource["input"]["customer_id"] = json!("cus_other");
    denied(&process.rpc("wrong-resource", "invoke", wrong_resource));
    for id in ["", ".", ".."] {
        let mut escaped_route = read.clone();
        escaped_route["input"]["customer_id"] = json!(id);
        let error = denied(&process.rpc("route-alias", "invoke", escaped_route));
        assert_eq!(error.code, "FCP-1003");
    }
    server.assert_no_requests();
    assert_eq!(
        success(
            &process.rpc("transport-read", "invoke", read.clone()),
            "read-one"
        )["customer"]["id"],
        "cus_native"
    );
    let observed = server.receive();
    assert_eq!(observed.method, "GET");
    assert_eq!(observed.target, "/v1/customers/cus_native");
    assert_eq!(
        observed.headers["authorization"],
        format!("Bearer {SECRET}")
    );
    denied(&process.rpc("spent", "invoke", read));
    server.assert_no_requests();

    let mut write_constraints = constraints("stripe:account:self", 1);
    write_constraints.idempotency_key = Some("native-create-key".into());
    let token = grant(
        &key,
        &instance,
        "stripe.create_customer",
        b"native-create",
        &write_constraints,
    );
    let create = request(
        "create-one",
        "stripe.create_customer",
        json!({"email": "native+tag@example.test", "name": "Native & Co", "idempotency_key": "native-create-key"}),
        token,
    );
    let mut conflict = create.clone();
    conflict["idempotency_key"] = json!("different-envelope-key");
    denied(&process.rpc("conflicting-key", "invoke", conflict));
    let mut wrong_key = create.clone();
    wrong_key["input"]["idempotency_key"] = json!("different-provider-key");
    denied(&process.rpc("wrong-key", "invoke", wrong_key));
    server.assert_no_requests();
    let result = success(
        &process.rpc("transport-create", "invoke", create.clone()),
        "create-one",
    );
    assert_eq!(result["audit"]["idempotency_key"], "native-create-key");
    let observed = server.receive();
    assert_eq!(observed.method, "POST");
    assert_eq!(observed.target, "/v1/customers");
    assert_eq!(
        observed.headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    assert_eq!(observed.headers["idempotency-key"], "native-create-key");
    assert!(observed.body.contains("email=native%2Btag@example.test"));
    assert!(observed.body.contains("name=Native%20%26%20Co"));
    denied(&process.rpc("spent-write", "invoke", create));
    server.assert_no_requests();
    process.shutdown();
    server.finish();
}

#[test]
fn native_deadline_cancels_retry_backoff_and_retains_admitted_bytes() {
    let server = LoopbackServer::start(vec![
        ProviderResponse::throttled(),
        ProviderResponse::customer(),
    ]);
    let mut process = NativeProcess::start();
    configure(&mut process, Some(&server));
    let key = Ed25519SigningKey::generate();
    let instance = handshake(&mut process, &key, &["stripe.read"]);
    let mut scope = constraints("stripe:customer:cus_native", 2);
    scope.max_bytes = Some(20_000);
    let token = grant(
        &key,
        &instance,
        "stripe.get_customer",
        b"deadline-token",
        &scope,
    );
    let mut req = request(
        "deadline-one",
        "stripe.get_customer",
        json!({"customer_id": "cus_native"}),
        token,
    );
    req["deadline_ms"] = json!(150);
    let start = Instant::now();
    let error = denied(&process.rpc("deadline", "invoke", req.clone()));
    assert!(error.message.contains("deadline exceeded"));
    assert!(error.message.contains("unknown"));
    assert!(start.elapsed() < StdDuration::from_secs(3));
    assert_eq!(server.receive().target, "/v1/customers/cus_native");
    req["deadline_ms"] = json!(2000);
    denied(&process.rpc("retained-reservation", "invoke", req));
    server.assert_no_requests();
    let fresh = grant(
        &key,
        &instance,
        "stripe.get_customer",
        b"fresh-token",
        &constraints("stripe:customer:cus_native", 1),
    );
    success(
        &process.rpc(
            "fresh",
            "invoke",
            request(
                "fresh-one",
                "stripe.get_customer",
                json!({"customer_id": "cus_native"}),
                fresh,
            ),
        ),
        "fresh-one",
    );
    server.receive();
    server.assert_no_requests();
    process.shutdown();
    server.finish();
}

#[test]
fn native_failed_lifecycle_attempts_and_fresh_sessions_revoke_old_grants() {
    let server = LoopbackServer::start(vec![ProviderResponse::customer()]);
    let mut process = NativeProcess::start();
    configure(&mut process, Some(&server));
    let key = Ed25519SigningKey::generate();
    let first = handshake(&mut process, &key, &["stripe.read"]);
    let old = request(
        "old",
        "stripe.get_customer",
        json!({"customer_id": "cus_native"}),
        grant(
            &key,
            &first,
            "stripe.get_customer",
            b"old-token",
            &constraints("stripe:customer:cus_native", 1),
        ),
    );
    let empty = handshake(&mut process, &key, &[]);
    assert_ne!(first, empty);
    denied(&process.rpc("old-instance", "invoke", old.clone()));
    let unnegotiated = request(
        "unnegotiated",
        "stripe.get_customer",
        json!({"customer_id": "cus_native"}),
        grant(
            &key,
            &empty,
            "stripe.get_customer",
            b"empty-token",
            &constraints("stripe:customer:cus_native", 1),
        ),
    );
    denied(&process.rpc("empty-grants", "invoke", unnegotiated));
    for malformed in [
        json!({"nonce": "bad"}),
        {
            let mut wrong = handshake_params(&key, &["stripe.read"]);
            wrong["protocol_version"] = json!("1.0.0");
            wrong
        },
        {
            let mut wrong = handshake_params(&key, &["stripe.read"]);
            wrong["zone"] = json!("z:work");
            wrong
        },
        {
            let mut wrong = handshake_params(&key, &["stripe.read"]);
            wrong["zone"] = json!("z:owner");
            wrong
        },
    ] {
        let current = handshake(&mut process, &key, &["stripe.read"]);
        let current_request = request(
            "current",
            "stripe.get_customer",
            json!({"customer_id": "cus_native"}),
            grant(
                &key,
                &current,
                "stripe.get_customer",
                b"current-token",
                &constraints("stripe:customer:cus_native", 1),
            ),
        );
        denied(&process.rpc("failed-handshake", "handshake", malformed));
        denied(&process.rpc("revoked-current", "invoke", current_request));
        let health: HealthSnapshot =
            serde_json::from_value(process.rpc("health", "health", json!({}))["result"].clone())
                .unwrap();
        assert!(!health.is_ready());
    }
    handshake(&mut process, &key, &["stripe.read"]);
    denied(&process.rpc("bad-config", "configure", json!({"secret_key": ""})));
    denied(&process.rpc(
        "no-old-configuration",
        "handshake",
        handshake_params(&key, &["stripe.read"]),
    ));
    denied(&process.rpc("no-old-grant", "invoke", old));
    server.assert_no_requests();
    process.shutdown();
    server.finish();
}

#[test]
fn native_default_endpoint_is_locally_ready_and_shutdown_stops_buffered_work() {
    let mut process = NativeProcess::start();
    configure(&mut process, None);
    let key = Ed25519SigningKey::generate();
    let instance = handshake(&mut process, &key, &["stripe.read"]);
    let health: HealthSnapshot =
        serde_json::from_value(process.rpc("health", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(health.is_ready());
    assert_eq!(health.details.unwrap()["instance_id"], json!(instance));
    let introspection = process.rpc("introspect", "introspect", json!({}));
    assert_eq!(
        introspection["result"]["operations"]
            .as_array()
            .unwrap()
            .len(),
        19
    );
    assert!(
        introspection["result"]["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    process.send(b"\n \t\n{bad json\n");
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");
    process.send(b"{\"jsonrpc\":\"2.0\",\"id\":\"stop\",\"method\":\"shutdown\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":\"must-not-run\",\"method\":\"health\",\"params\":{}}\n");
    assert_eq!(process.receive()["id"], "stop");
    process.wait_for_exit();
    assert!(matches!(
        process.output.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
}

#[test]
fn native_webhook_signature_scope_and_replay_checks_precede_provider_work() {
    let server = LoopbackServer::start(vec![ProviderResponse::customer()]);
    let mut process = NativeProcess::start();
    configure(&mut process, Some(&server));
    let key = Ed25519SigningKey::generate();
    let instance = handshake(&mut process, &key, &["stripe.webhook"]);
    let payload = json!({"id": "evt_native", "object": "event", "type": "invoice.paid", "created": Utc::now().timestamp(), "data": {"object": {"id": "in_native", "object": "invoice"}}}).to_string();
    let timestamp = Utc::now().timestamp();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec_native_fixture").unwrap();
    mac.update(format!("{timestamp}.{payload}").as_bytes());
    let signature = format!(
        "t={timestamp},v1={}",
        hex::encode(mac.finalize().into_bytes())
    );
    let token = grant(
        &key,
        &instance,
        "stripe.ingest_webhook_event",
        b"webhook-token",
        &constraints("stripe:invoice:in_native", 2),
    );
    let req = request(
        "webhook-one",
        "stripe.ingest_webhook_event",
        json!({"payload": payload, "stripe_signature": signature}),
        token,
    );
    let mut invalid = req.clone();
    invalid["input"]["stripe_signature"] = json!(format!("t={timestamp},v1=deadbeef"));
    denied(&process.rpc("bad-signature", "invoke", invalid));
    let mut preview = req.clone();
    preview["type"] = json!("simulate");
    let preview: SimulateResponse = serde_json::from_value(
        process.rpc("preview-webhook", "simulate", preview)["result"].clone(),
    )
    .unwrap();
    assert!(preview.would_succeed);
    let result = success(
        &process.rpc("webhook", "invoke", req.clone()),
        "webhook-one",
    );
    assert_eq!(result["event"]["id"], "evt_native");
    assert_eq!(result["delivery"]["signature_verified"], true);
    let mut replay = req;
    replay["id"] = json!("webhook-two");
    replay["input"]["delivery_id"] = json!("different-host-delivery");
    denied(&process.rpc("replay", "invoke", replay));
    server.assert_no_requests();
    process.shutdown();
    server.finish();
}
