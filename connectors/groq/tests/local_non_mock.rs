#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::fmt::Write as FmtWrite;
use std::io::{Read, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_groq::GroqConnector;
use fcp_groq::connector::{test_handshake_request, test_invoke_request};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use serde_json::{Value, json};

const CONNECTOR: &str = "groq";
const PACKAGE: &str = "fcp-groq";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.13";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const API_KEY: &str = "groq-local-acceptance-key";
const OP_CHAT: &str = "groq.chat.completions";
const OP_CHAT_STREAM: &str = "groq.chat.completions_stream";
const OP_MODELS: &str = "groq.models.list";
const OP_LEGACY: &str = "groq.completions.legacy";
const CAP_CHAT: &str = "groq.chat";
const CAP_MODELS: &str = "groq.models.read";

#[derive(Debug)]
struct CapturedRequest {
    head: String,
    body: Option<Value>,
}

struct LoopbackServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    join: JoinHandle<()>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .expect("loopback listener should bind to an ephemeral port");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("loopback listener should expose its address")
        );
        let (request_tx, received) = mpsc::channel();

        let join = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .expect("loopback listener should accept expected request");
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
                    .expect("loopback stream should set read timeout");

                let request = read_complete_request(&mut stream);
                request_tx
                    .send(request)
                    .expect("captured request should be delivered to test");

                let mut raw_response = format!("HTTP/1.1 {}\r\n", response.status);
                write!(
                    &mut raw_response,
                    "content-type: {}\r\n",
                    response.content_type
                )
                .expect("content type should format");
                write!(
                    &mut raw_response,
                    "content-length: {}\r\n",
                    response.body.len()
                )
                .expect("content-length should format");
                raw_response.push_str("connection: close\r\n");
                for (name, value) in response.headers {
                    raw_response.push_str(name);
                    raw_response.push_str(": ");
                    raw_response.push_str(value);
                    raw_response.push_str("\r\n");
                }
                raw_response.push_str("\r\n");
                raw_response.push_str(response.body);

                stream
                    .write_all(raw_response.as_bytes())
                    .expect("loopback response should be writable");
            }
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn provider_base_url(&self) -> String {
        format!("{}/openai/v1", self.base_url)
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

struct HttpResponse {
    status: &'static str,
    content_type: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static str,
}

impl HttpResponse {
    const fn json(status: &'static str, body: &'static str) -> Self {
        Self {
            status,
            content_type: "application/json",
            headers: Vec::new(),
            body,
        }
    }

    const fn sse(body: &'static str) -> Self {
        Self {
            status: "200 OK",
            content_type: "text/event-stream",
            headers: Vec::new(),
            body,
        }
    }

    fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
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
                let body_slice = &bytes[body_start..body_start + content_length];
                let body = if body_slice.is_empty() {
                    None
                } else {
                    Some(
                        serde_json::from_slice(body_slice)
                            .expect("request body should be JSON when present"),
                    )
                };
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
        .unwrap_or(0)
}

fn assert_request(captured: &CapturedRequest, method: &str, target: &str) {
    let request_line = captured
        .head
        .lines()
        .next()
        .expect("captured request should include request line");
    assert_eq!(request_line, format!("{method} {target} HTTP/1.1"));
    assert!(
        captured
            .head
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {API_KEY}")),
        "request should carry configured Groq bearer token; head={}",
        captured.head
    );
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> fcp_prelude::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize capability constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    fcp_prelude::CapabilityToken::from_raw(cose)
}

async fn setup_connector(
    base_url: &str,
    capabilities: &[&'static str],
) -> (GroqConnector, Ed25519SigningKey) {
    let mut connector = GroqConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "base_url": base_url,
            "default_model": "llama-3.1-8b-instant",
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("Groq connector should configure against loopback");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let requested = capabilities
        .iter()
        .map(|capability| CapabilityId::from_static(capability))
        .collect::<Vec<_>>();
    connector
        .handshake(test_handshake_request(requested, verifying_key.to_bytes()))
        .await
        .expect("Groq connector should handshake");

    (connector, signing_key)
}

async fn invoke(
    connector: &GroqConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let capability_token = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(json!(test_invoke_request(
            "groq-local-proof",
            operation,
            input,
            capability_token,
        )))
        .await
}

fn print_artifact(case_name: &str, boundary: &Value) {
    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "case": case_name,
        "command": "cargo test -p fcp-groq --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": boundary,
        "auth_gate": {
            "mode": "bearer_api_key",
            "credentials_used": true,
            "secret_material_logged": false
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_chat_completions_posts_body_and_maps_output() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "200 OK",
        r#"{
            "id": "chatcmpl-groq-local",
            "object": "chat.completion",
            "created": 1,
            "model": "llama-3.1-8b-instant",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "loopback Groq response"},
                    "finish_reason": "stop"
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
        }"#,
    )]);
    let (connector, signing_key) = setup_connector(&server.provider_base_url(), &[CAP_CHAT]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "Say ok through loopback"}],
            "max_tokens": 32,
            "temperature": 0.2
        }),
    )
    .await
    .expect("chat completions should invoke through loopback");

    let captured = server.take();
    assert_request(&captured, "POST", "/openai/v1/chat/completions");
    let body = captured.body.expect("chat request should send JSON");
    assert_eq!(body["model"], "llama-3.1-8b-instant");
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "Say ok through loopback");
    assert_eq!(body["stream"], false);
    assert_eq!(body["max_tokens"], 32);
    assert_eq!(body["temperature"], 0.2);
    server.join();

    assert_eq!(result["id"], "chatcmpl-groq-local");
    assert_eq!(result["content"], "loopback Groq response");
    assert_eq!(result["finish_reason"], "stop");
    assert_eq!(result["usage"]["total_tokens"], 8);
    assert!(
        !result.to_string().contains(API_KEY),
        "mapped output must not leak API key"
    );

    print_artifact(
        "chat_completions",
        &json!({
            "method": "POST",
            "path": "/openai/v1/chat/completions",
            "request_fields": ["model", "messages", "stream", "max_tokens", "temperature"],
            "response_fields": ["id", "model", "content", "finish_reason", "usage", "raw"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_stream_preserves_parallel_tool_calls_and_usage() {
    let body = concat!(
        r#"data: {"id":"stream-local","object":"chat.completion.chunk","created":1,"model":"fixture","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":1,"id":"second-call","type":"function","function":{"name":"second","arguments":"["}},{"index":0,"id":"first-call","type":"function","function":{"name":"lookup","arguments":"{\"q\":"}}]},"finish_reason":null}]}"#,
        "\n\n",
        r#"data: {"id":"stream-local","object":"chat.completion.chunk","created":1,"model":"fixture","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"private argument\"}"}},{"index":1,"function":{"arguments":"2]"}}]},"finish_reason":"tool_calls"}]}"#,
        "\n\n",
        r#"data: {"id":"stream-local","object":"chat.completion.chunk","created":1,"model":"fixture","choices":[],"usage":{"prompt_tokens":4,"completion_tokens":7,"total_tokens":11}}"#,
        "\n\n",
        "data: [DONE]\n\n"
    );
    let server = LoopbackServer::start(vec![HttpResponse::sse(body)]);
    let (connector, signing_key) = setup_connector(&server.provider_base_url(), &[CAP_CHAT]).await;
    let result = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "private prompt"}],
            "tools": [{"type": "function", "function": {"name": "lookup"}}]
        }),
    )
    .await
    .expect("real HTTP streaming invoke should preserve tool results");

    let captured = server.take();
    assert_request(&captured, "POST", "/openai/v1/chat/completions");
    assert_eq!(captured.body.expect("request body")["stream"], true);
    server.join();
    assert_eq!(result["content"], "");
    assert_eq!(result["finish_reason"], "tool_calls");
    assert_eq!(result["chunk_count"], 3);
    assert_eq!(result["tool_call_delta_count"], 2);
    assert_eq!(result["tool_calls"][0]["id"], "first-call");
    assert_eq!(result["tool_calls"][0]["function"]["name"], "lookup");
    assert_eq!(
        result["tool_calls"][0]["function"]["arguments"],
        "{\"q\":\"private argument\"}"
    );
    assert_eq!(result["tool_calls"][1]["id"], "second-call");
    assert_eq!(result["tool_calls"][1]["function"]["arguments"], "[2]");
    assert_eq!(
        result["choices"][0]["message"]["tool_calls"],
        result["tool_calls"]
    );
    assert_eq!(result["usage"]["total_tokens"], 11);
    assert_eq!(result["chunks"][2]["has_usage"], true);
    assert!(!result["chunks"].to_string().contains("private argument"));
    assert!(!result.to_string().contains("private prompt"));
    assert!(!result.to_string().contains(API_KEY));

    print_artifact(
        "stream_tool_materialization",
        &json!({
            "method": "POST", "path": "/openai/v1/chat/completions",
            "tool_count": 2, "chunk_count": 3, "usage_preserved": true,
            "response_fields": ["choices", "tool_calls", "usage", "chunks"],
            "provider_payloads_logged": false
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_stream_refuses_truncated_completion() {
    let body = concat!(
        r#"data: {"id":"truncated","object":"chat.completion.chunk","created":1,"model":"fixture","choices":[{"index":0,"delta":{"content":"private partial completion"},"finish_reason":"stop"}]}"#,
        "\n\n"
    );
    let server = LoopbackServer::start(vec![HttpResponse::sse(body)]);
    let (connector, signing_key) = setup_connector(&server.provider_base_url(), &[CAP_CHAT]).await;
    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT_STREAM,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private prompt"}]}),
    )
    .await
    .expect_err("EOF before DONE must not publish partial completion as success");
    let captured = server.take();
    assert_request(&captured, "POST", "/openai/v1/chat/completions");
    server.join();
    let diagnostic = error.to_string();
    assert!(!diagnostic.contains("private partial completion"));
    assert!(!diagnostic.contains("private prompt"));
    assert!(!diagnostic.contains(API_KEY));
    print_artifact(
        "stream_truncation_denied",
        &json!({
            "method": "POST", "path": "/openai/v1/chat/completions",
            "missing_done_rejected": true, "partial_success": false,
            "provider_payloads_logged": false
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_models_list_uses_get_without_body() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "200 OK",
        r#"{
            "object": "list",
            "data": [
                {"id": "llama-3.1-8b-instant", "object": "model", "owned_by": "Meta"},
                {"id": "mixtral-8x7b-32768", "object": "model", "owned_by": "Mistral"}
            ]
        }"#,
    )]);
    let (connector, signing_key) =
        setup_connector(&server.provider_base_url(), &[CAP_MODELS]).await;

    let result = invoke(&connector, &signing_key, OP_MODELS, CAP_MODELS, json!({}))
        .await
        .expect("models list should invoke through loopback");

    let captured = server.take();
    assert_request(&captured, "GET", "/openai/v1/models");
    assert!(
        captured.body.is_none(),
        "models list should not send a JSON body"
    );
    server.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(result["object"], "list");
    assert_eq!(result["data"][0]["id"], "llama-3.1-8b-instant");
    assert_eq!(result["cache"], "shared_in_memory");

    print_artifact(
        "models_list",
        &json!({
            "method": "GET",
            "path": "/openai/v1/models",
            "request_fields": [],
            "response_fields": ["object", "data", "cache"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_legacy_completions_posts_prompt_and_maps_raw_output() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "200 OK",
        r#"{
            "id": "cmpl-groq-local",
            "object": "text_completion",
            "created": 1,
            "model": "llama-3.1-8b-instant",
            "choices": [
                {"index": 0, "text": " legacy loopback", "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}
        }"#,
    )]);
    let (connector, signing_key) = setup_connector(&server.provider_base_url(), &[CAP_CHAT]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_LEGACY,
        CAP_CHAT,
        json!({
            "prompt": "Complete legacy prompt",
            "max_tokens": 12,
            "temperature": 0.1
        }),
    )
    .await
    .expect("legacy completions should invoke through loopback");

    let captured = server.take();
    assert_request(&captured, "POST", "/openai/v1/completions");
    let body = captured.body.expect("legacy request should send JSON");
    assert_eq!(body["model"], "llama-3.1-8b-instant");
    assert_eq!(body["prompt"], "Complete legacy prompt");
    assert_eq!(body["max_tokens"], 12);
    assert_eq!(body["temperature"], 0.1);
    server.join();

    assert_eq!(result["raw"]["id"], "cmpl-groq-local");
    assert_eq!(result["raw"]["choices"][0]["text"], " legacy loopback");
    assert_eq!(result["raw"]["usage"]["total_tokens"], 6);

    print_artifact(
        "legacy_completions",
        &json!({
            "method": "POST",
            "path": "/openai/v1/completions",
            "request_fields": ["model", "prompt", "max_tokens", "temperature"],
            "response_fields": ["raw"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_auth_error_maps_without_leaking_secret_material() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "401 Unauthorized",
        r#"{
            "error": {
                "type": "authentication_error",
                "message": "bad Bearer groq-local-acceptance-key",
                "prompt": "private prompt"
            }
        }"#,
    )]);
    let (connector, signing_key) = setup_connector(&server.provider_base_url(), &[CAP_CHAT]).await;

    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "private prompt"}]}),
    )
    .await
    .expect_err("provider auth failure should map to FcpError::Unauthorized");

    let captured = server.take();
    assert_request(&captured, "POST", "/openai/v1/chat/completions");
    server.join();

    assert!(matches!(error, FcpError::Unauthorized { .. }));
    let display = error.to_string();
    assert!(
        !display.contains(API_KEY),
        "display must not leak bearer token"
    );
    assert!(
        !display.contains("private prompt"),
        "display must not leak prompt text"
    );

    print_artifact(
        "auth_error_redaction",
        &json!({
            "method": "POST",
            "path": "/openai/v1/chat/completions",
            "provider_status": 401,
            "mapped_error": "Unauthorized",
            "secret_material_logged": false
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_seconds() {
    let server = LoopbackServer::start(vec![
        HttpResponse::json(
            "429 Too Many Requests",
            r#"{"error":{"type":"rate_limit_error","message":"too fast"}}"#,
        )
        .with_header("retry-after", "3"),
    ]);
    let (connector, signing_key) = setup_connector(&server.provider_base_url(), &[CAP_CHAT]).await;

    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({"messages": [{"role": "user", "content": "retry later"}]}),
    )
    .await
    .expect_err("provider rate limit should map to FcpError::RateLimited");

    let captured = server.take();
    assert_request(&captured, "POST", "/openai/v1/chat/completions");
    server.join();

    match error {
        FcpError::RateLimited {
            retry_after_ms,
            violation,
        } => {
            assert_eq!(retry_after_ms, 3_000);
            assert!(violation.is_none());
        }
        other => panic!("expected rate-limited error, got {other:?}"),
    }

    print_artifact(
        "rate_limit_retry_after",
        &json!({
            "method": "POST",
            "path": "/openai/v1/chat/completions",
            "provider_status": 429,
            "retry_after_ms": 3000,
            "mapped_error": "RateLimited"
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_invocation_budget_interrupts_headers_and_stream_body_waits() {
    for (streaming, cancel) in [(false, false), (true, false), (false, true), (true, true)] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let base_url = format!("http://{}/openai/v1", listener.local_addr().unwrap());
        let (connector, key) = setup_connector(&base_url, &[CAP_CHAT]).await;
        let cx = fcp_async_core::compatibility_cx();
        let server_cx = cx.clone();
        let (finished_tx, finished_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            started.elapsed() < StdDuration::from_secs(3),
                            "invocation was not dispatched"
                        );
                        thread::sleep(StdDuration::from_millis(2));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(StdDuration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(StdDuration::from_secs(2)))
                .unwrap();
            let request = read_complete_request(&mut stream);
            if streaming {
                stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: 4096\r\nconnection: close\r\n\r\n").unwrap();
                stream.flush().unwrap();
            }
            if cancel {
                server_cx.set_cancel_requested(true);
            }
            // Keep the provider silent until the caller completes. The test
            // deadline is independent of the connector's configured five seconds.
            let _ = finished_rx.recv_timeout(StdDuration::from_secs(2));
            request
        });
        let operation = if streaming { OP_CHAT_STREAM } else { OP_CHAT };
        let token = valid_token(&key, connector.instance_id(), CAP_CHAT, operation);
        let mut request = test_invoke_request(
            "interrupted",
            operation,
            json!({"messages":[{"role":"user","content":"private prompt"}]}),
            token,
        );
        request.deadline_ms = Some(if cancel { 5_000 } else { 100 });
        let result =
            fcp_async_core::time::timeout(StdDuration::from_secs(1), connector.invoke(request))
                .await;
        cx.set_cancel_requested(false);
        let _ = finished_tx.send(());
        let captured = server.join().unwrap();
        assert_request(&captured, "POST", "/openai/v1/chat/completions");
        let error = result
            .expect("caller deadline or cancellation must wake the pending invocation")
            .expect_err("an interrupted provider request cannot publish success");
        assert!(matches!(
            error,
            FcpError::External {
                retryable: false,
                ..
            }
        ));
        assert!(error.to_string().contains(if cancel {
            "cancelled"
        } else {
            "budget exhausted"
        }));
        assert!(!error.to_string().contains("private prompt"));
        assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
        print_artifact(
            "invocation_interruption",
            &json!({
                "method":"POST", "path":"/openai/v1/chat/completions",
                "streaming":streaming, "cancelled":cancel,
                "provider_requests":1, "retryable":false, "partial_success":false,
            }),
        );
    }
}
