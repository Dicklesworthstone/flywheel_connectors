//! Exercise the shipped executable and real HTTP for all three provider operations.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{
    CapabilityConstraints, CapabilityToken, HealthSnapshot, InstanceId, Introspection,
    InvokeResponse, InvokeStatus, SimulateResponse,
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::{Value, json};

struct CapturedRequest {
    headers: String,
    body: Value,
}

struct HttpResponse {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(body: Value) -> Self {
        let body = serde_json::to_vec(&body).unwrap();
        Self {
            status: 200,
            headers: format!(
                "content-type: application/json\r\ncontent-length: {}\r\n",
                body.len()
            ),
            body,
        }
    }

    fn video(bytes: &[u8]) -> Self {
        Self {
            status: 200,
            headers: format!(
                "content-type: video/mp4\r\ncontent-length: {}\r\n",
                bytes.len()
            ),
            body: bytes.into(),
        }
    }
}

struct Server {
    url: String,
    requests: Receiver<CapturedRequest>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let worker = thread::spawn(move || {
            for response in responses {
                let deadline = Instant::now() + Duration::from_secs(15);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "provider request timed out");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("provider accept: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                sender.send(read_request(&mut stream)).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 {} response\r\n{}connection: close\r\n\r\n",
                    response.status, response.headers
                )
                .unwrap();
                // Oversized-body rejection may close the connection early.
                let _ = stream.write_all(&response.body);
                let _ = stream.flush();
            }
        });
        Self {
            url,
            requests,
            worker: Some(worker),
        }
    }

    fn receive(&self) -> CapturedRequest {
        self.requests.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn assert_no_requests(&self) {
        assert!(matches!(
            self.requests.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    fn finish(mut self) {
        self.worker.take().unwrap().join().unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
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
        assert!(read > 0, "incomplete provider request");
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
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                let body = if length == 0 {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap()
                };
                return CapturedRequest { headers, body };
            }
        }
    }
}

struct NativeProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
    reader: Option<JoinHandle<()>>,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-openrouter"))
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start shipped OpenRouter executable");
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let response = serde_json::from_str(&line.unwrap()).expect("stdout must be JSONL");
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

    fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let input = self.input.as_mut().unwrap();
        input.write_all(bytes)?;
        input.flush()
    }

    fn receive(&self) -> Value {
        self.output
            .recv_timeout(Duration::from_secs(10))
            .expect("native response deadline")
    }

    fn rpc(&mut self, id: &str, method: &str, params: Value) -> Value {
        let mut bytes = serde_json::to_vec(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )
        .unwrap();
        bytes.push(b'\n');
        self.send(&bytes).unwrap();
        let response = self.receive();
        assert_eq!(response["id"], id);
        response
    }

    fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.input.take();
                self.reader.take().unwrap().join().unwrap();
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "native process failed to exit with stdin still open"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn configure(&mut self, server: &Server, key: &Ed25519SigningKey) -> InstanceId {
        let configured = self.rpc(
            "configure",
            "configure",
            json!({"api_key": "openrouter-test-key", "base_url": server.url}),
        );
        assert_eq!(configured["result"]["configured"], true);
        let handshake = self.rpc("handshake", "handshake", json!({
            "protocol_version": "2.0.0", "zone": "z:work", "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![9_u8; 32], "capabilities_requested": ["openrouter.chat", "openrouter.models", "openrouter.video", "openrouter.unknown"]
        }));
        assert_eq!(handshake["result"]["connector_id"], "fcp.openrouter");
        assert_eq!(
            handshake["result"]["capabilities_granted"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        serde_json::from_value(handshake["result"]["instance_id"].clone()).unwrap()
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

fn request(
    key: &Ed25519SigningKey,
    instance: &InstanceId,
    operation: &str,
    token_id: &[u8],
    constraints: CapabilityConstraints,
    input: Value,
) -> Value {
    let capability = match operation {
        "openrouter.models.list" => "openrouter.models",
        "openrouter.chat.completions" => "openrouter.chat",
        "openrouter.videos.generate" => "openrouter.video",
        _ => panic!("unknown operation"),
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let signed = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .operations(&[operation])
        .zone_id("z:work")
        .principal("user:native-test")
        .issuer("node:native-test")
        .target_instance(instance.as_str())
        .token_id(token_id)
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .unwrap()
        .sign(key)
        .unwrap();
    json!({"type": "invoke", "id": "operation-request", "connector_id": "fcp.openrouter", "zone_id": "z:work",
        "operation": operation, "input": input, "capability_token": CapabilityToken::from_raw(signed)})
}

fn output(response: Value) -> Value {
    let response: InvokeResponse = serde_json::from_value(response["result"].clone()).unwrap();
    assert_eq!(response.id.0, "operation-request");
    assert_eq!(response.status, InvokeStatus::Ok);
    response.result.unwrap()
}

fn one_call(resources: &[&str]) -> CapabilityConstraints {
    CapabilityConstraints {
        max_calls: Some(1),
        max_bytes: Some(1_000_000),
        resource_allow: resources.iter().map(|value| (*value).into()).collect(),
        ..Default::default()
    }
}

#[test]
fn native_catalog_chat_and_video_use_actual_authority_and_bounded_results() {
    let server = Server::start(vec![
        HttpResponse::json(json!({"data": [{"id": "openai/gpt-4.1-mini"}]})),
        HttpResponse::json(
            json!({"id": "chat-1", "model": "openai/gpt-4.1-mini", "choices": [{
            "message": {"content": "A small observatory."}, "finish_reason": "stop"}], "usage": {"total_tokens": 12}}),
        ),
        HttpResponse::json(
            json!({"id": "video-1", "status": "pending", "polling_url": "/jobs/video-1"}),
        ),
        HttpResponse::json(
            json!({"id": "video-1", "status": "completed", "generation_id": "generation-1", "usage": {"cost": 0.1}}),
        ),
        HttpResponse::video(b"mp4-bytes"),
    ]);
    let key = Ed25519SigningKey::generate();
    let mut process = NativeProcess::start();
    let initial: HealthSnapshot =
        serde_json::from_value(process.rpc("initial", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(!initial.is_ready());
    process.send(b"{not-json\n").unwrap();
    assert_eq!(process.receive()["error"]["code"], "FCP-1001");
    let instance = process.configure(&server, &key);
    let ready: HealthSnapshot =
        serde_json::from_value(process.rpc("ready", "health", json!({}))["result"].clone())
            .unwrap();
    assert!(ready.is_ready());
    assert_eq!(ready.details.unwrap()["instance_id"], json!(instance));
    let catalog: Introspection =
        serde_json::from_value(process.rpc("catalog", "introspect", json!({}))["result"].clone())
            .unwrap();
    assert_eq!(catalog.operations.len(), 3);

    let models = request(
        &key,
        &instance,
        "openrouter.models.list",
        b"models",
        one_call(&[]),
        json!({}),
    );
    for field in ["connector_id", "zone_id"] {
        let mut wrong = models.clone();
        wrong[field] = json!(if field == "connector_id" {
            "fcp.other"
        } else {
            "z:private"
        });
        assert_eq!(
            process.rpc("wrong-target", "invoke", wrong)["error"]["code"],
            "FCP-3001"
        );
    }
    let mut preview = models.clone();
    preview["type"] = json!("simulate");
    for _ in 0..2 {
        let result: SimulateResponse = serde_json::from_value(
            process.rpc("preview", "simulate", preview.clone())["result"].clone(),
        )
        .unwrap();
        assert!(result.would_succeed);
    }
    let mut bad = models.clone();
    bad["input"] = json!({"extra": 1});
    assert_eq!(
        process.rpc("schema", "invoke", bad)["error"]["code"],
        "FCP-1003"
    );
    server.assert_no_requests();
    assert_eq!(
        output(process.rpc("models", "invoke", models.clone()))["data"][0]["id"],
        "openai/gpt-4.1-mini"
    );
    assert_eq!(
        process.rpc("replay", "invoke", models)["error"]["code"],
        "FCP-3001"
    );
    let model_call = server.receive();
    assert!(model_call.headers.starts_with("GET /models "));
    assert!(
        model_call
            .headers
            .to_lowercase()
            .contains("authorization: bearer openrouter-test-key")
    );

    let chat = request(
        &key,
        &instance,
        "openrouter.chat.completions",
        b"chat",
        one_call(&[
            "openrouter:model:openai/gpt-4.1-mini",
            "openrouter:input_url:https://example.com/a%3Fb=1",
        ]),
        json!({"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "HTTPS://EXAMPLE.COM/a?b=1"}}]}]}),
    );
    let mut wrong_model = chat.clone();
    wrong_model["input"]["model"] = json!("other/model");
    assert_eq!(
        process.rpc("model-scope", "invoke", wrong_model)["error"]["code"],
        "FCP-3004"
    );
    let mut wrong_url = chat.clone();
    wrong_url["input"]["messages"][0]["content"][0]["image_url"]["url"] =
        json!("https://example.com/axb=1");
    assert_eq!(
        process.rpc("url-scope", "invoke", wrong_url)["error"]["code"],
        "FCP-3004"
    );
    server.assert_no_requests();
    let chat_output = output(process.rpc("chat", "invoke", chat));
    assert_eq!(chat_output["content"], "A small observatory.");
    assert_eq!(chat_output["raw"]["usage"]["total_tokens"], 12);
    let chat_call = server.receive();
    assert!(chat_call.headers.starts_with("POST /chat/completions "));
    assert_eq!(chat_call.body["model"], "openai/gpt-4.1-mini");
    assert_eq!(
        chat_call.body["messages"][0]["content"][0]["image_url"]["url"],
        "HTTPS://EXAMPLE.COM/a?b=1"
    );

    let video = request(
        &key,
        &instance,
        "openrouter.videos.generate",
        b"video",
        one_call(&[
            "openrouter:model:google/veo-3.1-fast",
            "openrouter:callback_url:https://example.com/done%3Fjob=1",
        ]),
        json!({"prompt": "A small observatory", "poll_interval_ms": 0, "max_poll_attempts": 2, "max_download_bytes": 100,
            "callback_url": "https://example.com/done?job=1"}),
    );
    let mut wrong_callback = video.clone();
    wrong_callback["input"]["callback_url"] = json!("https://example.com/doneXjob=1");
    assert_eq!(
        process.rpc("callback-scope", "invoke", wrong_callback)["error"]["code"],
        "FCP-3004"
    );
    let video_output = output(process.rpc("video", "invoke", video));
    assert_eq!(video_output["video"]["byte_len"], 9);
    assert_eq!(video_output["video"]["base64"], "bXA0LWJ5dGVz");
    assert_eq!(video_output["generation_id"], "generation-1");
    assert_eq!(video_output["model"], "google/veo-3.1-fast");
    let submitted = server.receive();
    assert!(submitted.headers.starts_with("POST /videos "));
    assert_eq!(
        submitted.body["callback_url"],
        "https://example.com/done?job=1"
    );
    assert!(server.receive().headers.starts_with("GET /jobs/video-1 "));
    assert!(
        server
            .receive()
            .headers
            .starts_with("GET /videos/video-1/content?index=0 ")
    );
    assert_eq!(
        process.rpc("shutdown", "shutdown", json!({}))["result"]["status"],
        "shutdown"
    );
    assert!(process.wait_for_exit().success());
    server.finish();
}

#[test]
fn chunked_video_body_is_bounded_and_failed_work_cannot_regain_a_call() {
    let server = Server::start(vec![
        HttpResponse::json(json!({"id": "video-limit", "status": "completed"})),
        HttpResponse {
            status: 200,
            headers: "content-type: video/mp4\r\ntransfer-encoding: chunked\r\n".into(),
            body: b"8\r\n12345678\r\n0\r\n\r\n".to_vec(),
        },
    ]);
    let key = Ed25519SigningKey::generate();
    let mut process = NativeProcess::start();
    let instance = process.configure(&server, &key);
    let invocation = request(
        &key,
        &instance,
        "openrouter.videos.generate",
        b"bounded-video",
        one_call(&["openrouter:model:google/veo-3.1-fast"]),
        json!({"prompt": "small clip", "max_download_bytes": 4}),
    );
    let failed = process.rpc("oversized-video", "invoke", invocation.clone());
    assert!(
        failed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("byte limit")
    );
    assert_eq!(failed["error"]["retryable"], false);
    assert_eq!(
        process.rpc("no-refund", "invoke", invocation)["error"]["code"],
        "FCP-3001"
    );
    assert!(server.receive().headers.starts_with("POST /videos "));
    assert!(
        server
            .receive()
            .headers
            .starts_with("GET /videos/video-limit/content?index=0 ")
    );
    process.rpc("shutdown", "shutdown", json!({}));
    assert!(process.wait_for_exit().success());
    server.finish();
}

#[test]
fn oversized_native_frame_is_rejected_before_any_dispatch() {
    let mut process = NativeProcess::start();
    let mut frame = vec![b' '; 16 * 1024 * 1024 + 1];
    frame.push(b'\n');
    let _ = process.send(&frame);
    assert_eq!(process.receive()["error"]["code"], "FCP-1004");
    assert!(!process.wait_for_exit().success());
}
