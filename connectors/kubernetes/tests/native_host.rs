//! Exercise the shipped JSONL executable against real loopback Kubernetes HTTP.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

mod common;

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use fcp_core::{
    CapabilityConstraints, FcpErrorResponse, HealthSnapshot, InstanceId, InvokeResponse,
    InvokeStatus, SimulateResponse,
};
use fcp_crypto::ed25519::Ed25519SigningKey;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};

use common::{handshake_params, request, token};

struct Process {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
    reader: Option<JoinHandle<()>>,
}

impl Process {
    fn new() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-kubernetes"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender
                    .send(serde_json::from_str(&line.unwrap()).unwrap())
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
            reader: Some(reader),
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        writeln!(
            self.input.as_mut().unwrap(),
            "{}",
            json!({
                "jsonrpc": "2.0", "id": method, "method": method, "params": params,
            })
        )
        .unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        let response = self
            .output
            .recv_timeout(Duration::from_secs(10))
            .expect("native RPC deadline");
        assert_eq!(response["id"], method);
        response
    }

    fn configure(&mut self, url: &str, writes: bool) {
        let response = self.rpc(
            "configure",
            json!({
                "bearer_token": "kubernetes-native-fixture", "base_url": url,
                "allowed_namespaces": ["default"], "allow_write_operations": writes,
            }),
        );
        assert_eq!(response["result"]["status"], "configured", "{response}");
    }

    fn handshake(&mut self, key: &Ed25519SigningKey, capabilities: &[&str]) -> InstanceId {
        let response = self.rpc("handshake", handshake_params(key, capabilities));
        assert_eq!(
            response["result"]["connector_id"], "fcp.kubernetes",
            "{response}"
        );
        assert_eq!(response["result"]["nonce"], json!(vec![19_u8; 32]));
        assert_eq!(response["result"]["event_caps"]["streaming"], false);
        serde_json::from_value(response["result"]["instance_id"].clone()).unwrap()
    }

    fn shutdown(&mut self) {
        assert_eq!(
            self.rpc(
                "shutdown",
                json!({
                    "type": "shutdown", "deadline_ms": 1_000, "drain": false,
                })
            )["result"]["status"],
            "shutdown"
        );
        // Keep stdin open: shutdown itself must terminate the process.
        let expires = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < expires,
                "shutdown did not terminate the process"
            );
            thread::sleep(Duration::from_millis(10));
        }
        self.input.take();
        self.reader.take().unwrap().join().unwrap();
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

struct Observation {
    target: String,
    headers: String,
    body: Value,
}

struct Provider {
    url: String,
    requests: Receiver<Observation>,
    stop: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl Provider {
    fn new(body: Value, delay: Duration) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let (stop, stopped) = mpsc::channel();
        let worker = thread::spawn(move || {
            let expires = Instant::now() + Duration::from_secs(30);
            while stopped.try_recv().is_err() {
                assert!(
                    Instant::now() < expires,
                    "provider fixture was not released"
                );
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        sender.send(read_request(&mut stream)).unwrap();
                        thread::sleep(delay);
                        let bytes = body.to_string();
                        let wire = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{bytes}",
                            bytes.len()
                        );
                        if let Err(error) = stream.write_all(wire.as_bytes()) {
                            assert!(
                                matches!(
                                    error.kind(),
                                    std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::ConnectionReset
                                ),
                                "{error}"
                            );
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
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

    fn observed(&self) -> Observation {
        self.requests
            .recv_timeout(Duration::from_secs(3))
            .expect("expected provider request")
    }

    fn no_request(&self) {
        assert!(
            self.requests
                .recv_timeout(Duration::from_millis(75))
                .is_err(),
            "unexpected provider request"
        );
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Observation {
    let mut bytes = Vec::new();
    let mut buf = [0_u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0 && bytes.len() + n <= 1024 * 1024);
        bytes.extend_from_slice(&buf[..n]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    let length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
    assert!(length <= 1024 * 1024);
    while bytes.len() < header_end + length {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
    }
    Observation {
        target: headers.lines().next().unwrap().to_owned(),
        headers,
        body: if length == 0 {
            Value::Null
        } else {
            serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap()
        },
    }
}

fn scope(provider: &Provider, route: &str) -> CapabilityConstraints {
    CapabilityConstraints {
        resource_allow: vec![format!(
            "kubernetes://cluster/{}/namespaces/default/{route}",
            utf8_percent_encode(&provider.url, NON_ALPHANUMERIC)
        )],
        max_calls: Some(1),
        max_bytes: Some(1024 * 1024),
        ..Default::default()
    }
}

fn denied(response: &Value) -> FcpErrorResponse {
    let error: FcpErrorResponse =
        serde_json::from_value(response["error"].clone()).expect("complete FCP error");
    assert!(!error.retryable, "{response}");
    error
}

fn success(response: Value) -> InvokeResponse {
    let value: InvokeResponse =
        serde_json::from_value(response["result"].clone()).expect("canonical native response");
    assert_eq!(value.status, InvokeStatus::Ok, "{response}");
    assert_eq!(value.id.0, "kubernetes-fixture-invocation");
    value
}

#[test]
fn native_session_simulates_then_reads_and_spends_the_grant_once() {
    let provider = Provider::new(
        json!({"kind": "PodList", "items": [{"metadata": {"name": "worker"}}]}),
        Duration::ZERO,
    );
    let mut process = Process::new();
    let key = Ed25519SigningKey::generate();
    process.configure(&provider.url, false);
    let instance = process.handshake(&key, &["kubernetes.read", "unrelated.write"]);
    let health: HealthSnapshot =
        serde_json::from_value(process.rpc("health", json!({}))["result"].clone()).unwrap();
    assert!(matches!(health.status, fcp_core::HealthState::Ready));
    assert_eq!(health.details.unwrap()["instance_id"], json!(instance));
    assert_eq!(
        process.rpc("introspect", json!({}))["result"]["operations"]
            .as_array()
            .unwrap()
            .len(),
        31
    );
    let op = "kubernetes.list_pods";
    let req = request(
        op,
        json!({"namespace": "default"}),
        token(&key, &instance, op, b"read", &scope(&provider, "pods")),
    );
    for _ in 0..2 {
        let mut simulation = req.clone();
        simulation["type"] = json!("simulate");
        let result: SimulateResponse =
            serde_json::from_value(process.rpc("simulate", simulation)["result"].clone()).unwrap();
        assert!(result.would_succeed);
    }
    provider.no_request();
    let response = success(process.rpc("invoke", req.clone()));
    assert_eq!(
        response.result.unwrap()["pods"][0]["metadata"]["name"],
        "worker"
    );
    let observed = provider.observed();
    assert_eq!(
        observed.target,
        "GET /api/v1/namespaces/default/pods HTTP/1.1"
    );
    assert!(
        observed
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer kubernetes-native-fixture")
    );
    denied(&process.rpc("invoke", req));
    provider.no_request();
    process.shutdown();
}

#[test]
fn native_write_creates_the_scoped_configmap_with_correlated_output() {
    let provider = Provider::new(
        json!({"kind": "ConfigMap", "metadata": {"name": "settings"}, "data": {"mode": "ready"}}),
        Duration::ZERO,
    );
    let mut process = Process::new();
    let key = Ed25519SigningKey::generate();
    process.configure(&provider.url, true);
    let instance = process.handshake(&key, &["kubernetes.admin"]);
    let op = "kubernetes.configmap.create";
    let req = request(
        op,
        json!({"namespace": "default", "name": "settings", "data": {"mode": "ready"}}),
        token(
            &key,
            &instance,
            op,
            b"write",
            &scope(&provider, "configmaps/settings"),
        ),
    );
    let output = success(process.rpc("invoke", req)).result.unwrap();
    assert_eq!(output["configmap"]["data"]["mode"], "ready");
    let observed = provider.observed();
    assert_eq!(
        observed.target,
        "POST /api/v1/namespaces/default/configmaps HTTP/1.1"
    );
    assert_eq!(observed.body["metadata"]["namespace"], "default");
    assert_eq!(observed.body["metadata"]["name"], "settings");
    assert_eq!(observed.body["data"]["mode"], "ready");
    process.shutdown();
}

#[test]
fn native_rejects_wrong_target_zone_resources_and_unnegotiated_capabilities() {
    let provider = Provider::new(json!({"items": []}), Duration::ZERO);
    let mut process = Process::new();
    let key = Ed25519SigningKey::generate();
    process.configure(&provider.url, true);
    let instance = process.handshake(&key, &["kubernetes.read"]);
    let op = "kubernetes.list_pods";
    let req = request(
        op,
        json!({"namespace": "default"}),
        token(&key, &instance, op, b"scope", &scope(&provider, "pods")),
    );
    for (field, value) in [("connector_id", "fcp.stripe"), ("zone_id", "z:work")] {
        let mut wrong = req.clone();
        wrong[field] = json!(value);
        denied(&process.rpc("invoke", wrong));
    }
    let wrong_resource = request(
        op,
        json!({"namespace": "default"}),
        token(
            &key,
            &instance,
            op,
            b"resource",
            &scope(&provider, "secrets"),
        ),
    );
    denied(&process.rpc("invoke", wrong_resource));
    let op = "kubernetes.configmap.delete";
    let write = request(
        op,
        json!({"namespace": "default", "name": "settings"}),
        token(
            &key,
            &instance,
            op,
            b"not-granted",
            &scope(&provider, "configmaps/settings"),
        ),
    );
    denied(&process.rpc("invoke", write));
    provider.no_request();
    success(process.rpc("invoke", req));
    provider.observed();
    process.shutdown();
}

#[test]
fn native_rotates_instances_and_failed_lifecycle_requests_revoke_authority() {
    let provider = Provider::new(json!({"items": []}), Duration::ZERO);
    let mut process = Process::new();
    let key = Ed25519SigningKey::generate();
    process.configure(&provider.url, false);
    let first = process.handshake(&key, &["kubernetes.read"]);
    let op = "kubernetes.list_pods";
    let old = request(
        op,
        json!({"namespace": "default"}),
        token(&key, &first, op, b"old", &scope(&provider, "pods")),
    );
    let second = process.handshake(&key, &["kubernetes.read"]);
    assert_ne!(first, second);
    denied(&process.rpc("invoke", old));
    let current = request(
        op,
        json!({"namespace": "default"}),
        token(&key, &second, op, b"current", &scope(&provider, "pods")),
    );
    denied(&process.rpc("handshake", json!({"protocol_version": "2.0"})));
    denied(&process.rpc("invoke", current));
    process.handshake(&key, &["kubernetes.read"]);
    denied(&process.rpc(
        "configure",
        json!({"bearer_token": "fixture", "base_url": "http://untrusted.example"}),
    ));
    assert_eq!(
        process.rpc("health", json!({}))["result"]["details"]["configured"],
        false
    );
    provider.no_request();
    process.shutdown();
}

#[test]
fn native_preflight_rejects_malformed_routes_without_spending_the_call() {
    let provider = Provider::new(
        json!({"kind": "Pod", "metadata": {"name": "worker"}}),
        Duration::ZERO,
    );
    let mut process = Process::new();
    let key = Ed25519SigningKey::generate();
    process.configure(&provider.url, false);
    let instance = process.handshake(&key, &["kubernetes.read"]);
    let op = "kubernetes.get_pod";
    let req = request(
        op,
        json!({"namespace": "default", "name": "worker"}),
        token(
            &key,
            &instance,
            op,
            b"preflight",
            &scope(&provider, "pods/worker"),
        ),
    );
    for bad in [
        "../secrets",
        "worker?watch=true",
        " worker ",
        "worker%23secret",
        "",
    ] {
        let mut wrong = req.clone();
        wrong["input"]["name"] = json!(bad);
        denied(&process.rpc("invoke", wrong));
    }
    let mut wrong = req.clone();
    wrong["input"] = json!("not an object");
    denied(&process.rpc("invoke", wrong));
    provider.no_request();
    success(process.rpc("invoke", req));
    assert_eq!(
        provider.observed().target,
        "GET /api/v1/namespaces/default/pods/worker HTTP/1.1"
    );
    process.shutdown();
}

#[test]
fn native_deadline_interrupts_the_provider_and_retains_the_admission() {
    let provider = Provider::new(json!({"items": []}), Duration::from_millis(200));
    let mut process = Process::new();
    let key = Ed25519SigningKey::generate();
    process.configure(&provider.url, false);
    let instance = process.handshake(&key, &["kubernetes.read"]);
    let op = "kubernetes.list_pods";
    let mut req = request(
        op,
        json!({"namespace": "default"}),
        token(&key, &instance, op, b"deadline", &scope(&provider, "pods")),
    );
    req["deadline_ms"] = json!(50);
    let error = denied(&process.rpc("invoke", req.clone()));
    assert!(error.message.contains("outcome may be unknown"));
    provider.observed();
    denied(&process.rpc("invoke", req));
    provider.no_request();
    process.shutdown();
}

#[test]
fn native_rejects_invalid_provider_results_and_keeps_the_grant_spent() {
    let provider = Provider::new(json!({"items": "invalid pod list"}), Duration::ZERO);
    let mut process = Process::new();
    let key = Ed25519SigningKey::generate();
    process.configure(&provider.url, false);
    let instance = process.handshake(&key, &["kubernetes.read"]);
    let op = "kubernetes.list_pods";
    let req = request(
        op,
        json!({"namespace": "default"}),
        token(
            &key,
            &instance,
            op,
            b"invalid-output",
            &scope(&provider, "pods"),
        ),
    );
    denied(&process.rpc("invoke", req.clone()));
    provider.observed();
    denied(&process.rpc("invoke", req));
    provider.no_request();
    process.shutdown();
}
