//! Exercise the shipped connector process, its native protocol and real HTTP client.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{CapabilityToken, HandshakeResponse, HealthSnapshot, InvokeResponse, InvokeStatus};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use serde_json::{Value, json};

struct NativeProcess {
    child: Child,
    input: ChildStdin,
    replies: Receiver<Value>,
    reader: Option<JoinHandle<()>>,
}

impl NativeProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fcp-huggingface"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env("RUST_LOG", "error")
            .env_remove("FCP_HOST_EGRESS_PROXY_URL")
            .spawn()
            .expect("start the real Hugging Face connector binary");
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, replies) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                let value =
                    serde_json::from_str(&line).expect("stdout contains only JSONL replies");
                if sender.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            replies,
            reader: Some(reader),
        }
    }

    fn request(&mut self, id: &str, method: &str, params: Value) -> Value {
        serde_json::to_writer(
            &mut self.input,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )
        .unwrap();
        self.input.write_all(b"\n").unwrap();
        self.input.flush().unwrap();
        let reply = self.reply();
        assert_eq!(
            reply["id"], id,
            "outer request identity must survive dispatch"
        );
        reply
    }

    fn reply(&self) -> Value {
        self.replies
            .recv_timeout(Duration::from_secs(20))
            .expect("native response must arrive within the test deadline")
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().expect("observe exact child process") {
                return status;
            }
            assert!(Instant::now() < deadline, "connector did not exit promptly");
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for NativeProcess {
    fn drop(&mut self) {
        // Cleanup owns only this test's exact child; never leave a failed test's
        // connector process or stdout reader behind.
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn read_provider_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut headers = String::new();
    loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        headers.push_str(&line);
        assert!(
            headers.len() < 16 * 1024,
            "HTTP request headers stay bounded"
        );
        if line == "\r\n" {
            return headers;
        }
    }
}

fn serve_one_model(listener: TcpListener) -> JoinHandle<String> {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "authorized request was never sent"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept loopback request: {error}"),
            }
        };
        let headers = read_provider_request(&mut stream);
        let body = r#"{"_id":"local-model","modelId":"gpt2","tags":[]}"#;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len(),
        )
        .unwrap();
        headers
    })
}

#[test]
fn native_stdio_requires_bound_authority_and_shutdown_exits_with_stdin_open() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let mut process = NativeProcess::start();

    // A malformed frame must not poison the next valid native request.
    process.input.write_all(b"{not-json}\n").unwrap();
    assert!(process.reply().get("error").is_some());
    let initial = process.request("initial-health", "health", json!({}));
    let initial: HealthSnapshot = serde_json::from_value(initial["result"].clone()).unwrap();
    assert!(!initial.is_ready());

    let configured = process.request(
        "configure",
        "configure",
        json!({
            "api_token": "hf_native_fixture_token",
            "inference_url": base_url,
            "hub_url": format!("{base_url}/api"),
            "request_timeout_ms": 5_000,
            "retry": {"max_retries": 0}
        }),
    );
    assert!(configured.get("error").is_none());

    let key = Ed25519SigningKey::from_bytes(&[76; 32]).unwrap();
    let handshake = process.request(
        "handshake",
        "handshake",
        json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "host_public_key": key.verifying_key().to_bytes(),
            "nonce": vec![19_u8; 32],
            "capabilities_requested": ["huggingface.models"]
        }),
    );
    let negotiated: HandshakeResponse =
        serde_json::from_value(handshake["result"].clone()).unwrap();
    assert_eq!(negotiated.status, "accepted");
    assert_eq!(negotiated.capabilities_granted.len(), 1);

    let health = process.request("health", "health", json!({}));
    let health: HealthSnapshot = serde_json::from_value(health["result"].clone()).unwrap();
    assert!(health.is_ready());
    let instance = health.details.unwrap()["instance_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let unsigned = process.request(
        "unsigned",
        "invoke",
        json!({
            "operation_id": "huggingface.models.info",
            "input": {"model_id": "gpt2"}
        }),
    );
    assert!(unsigned.get("error").is_some());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    let now = Utc::now();
    let token = CapabilityTokenBuilder::new()
        .capability_id("huggingface.models")
        .zone_id("z:work")
        .principal("user:native-fixture")
        .operations(&["huggingface.models.info"])
        .issuer("node:native-fixture")
        .target_instance(&instance)
        .validity(
            now - ChronoDuration::minutes(1),
            now + ChronoDuration::hours(1),
        )
        .sign(&key)
        .unwrap();
    let request = json!({
        "type": "invoke",
        "id": "provider-invoke",
        "connector_id": "fcp.huggingface",
        "operation": "huggingface.models.info",
        "zone_id": "z:work",
        "input": {"model_id": "gpt2"},
        "idempotency_key": "native-fixture",
        "capability_token": CapabilityToken::from_raw(token)
    });
    let mut preview = request.clone();
    preview["type"] = json!("simulate");
    let simulation = process.request("preview", "simulate", preview);
    assert_eq!(simulation["result"]["type"], "simulate_response");
    assert_eq!(simulation["result"]["would_succeed"], true);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    let provider = serve_one_model(listener);
    let result = process.request("outer-invoke", "invoke", request);
    let response: InvokeResponse = serde_json::from_value(result["result"].clone()).unwrap();
    assert_eq!(response.r#type, "response");
    assert_eq!(response.id.0, "provider-invoke");
    assert_eq!(response.status, InvokeStatus::Ok);
    assert_eq!(response.result.unwrap()["modelId"], "gpt2");
    let headers = provider.join().expect("loopback provider completed");
    assert!(headers.starts_with("GET /api/models/gpt2 HTTP/1.1\r\n"));
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("authorization: bearer hf_native_fixture_token")
    );

    let shutdown = process.request("shutdown", "shutdown", json!({"type": "shutdown"}));
    assert_eq!(shutdown["result"]["type"], "shutdown_ack");
    assert_eq!(shutdown["result"]["status"], "completed");
    // NativeProcess still owns an open stdin pipe: shutdown must not wait for EOF.
    assert!(process.wait_for_exit().success());
    assert!(
        process
            .replies
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );
}

#[test]
fn native_stdio_oversized_frame_cannot_become_a_following_request() {
    let mut process = NativeProcess::start();
    let mut oversized = vec![b' '; 1024 * 1024 + 2];
    oversized.extend_from_slice(b"\n{\"method\":\"health\",\"id\":\"unread\"}\n");
    if let Err(error) = process.input.write_all(&oversized) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    let response = process.reply();
    assert!(response.get("error").is_some());
    assert_ne!(response["id"], "unread");
    assert!(!process.wait_for_exit().success());
    assert!(
        process
            .replies
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );
}
