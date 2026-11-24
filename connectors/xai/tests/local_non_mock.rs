//! Local loopback acceptance coverage for the `xAI` connector.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityId, FcpConnector, FcpError, InstanceId};
use fcp_xai::XaiConnector;
use fcp_xai::connector::{test_handshake_request, test_invoke_request};
use futures_util::FutureExt;
use serde_json::{Value, json};

const CONNECTOR: &str = "xai";
const PACKAGE: &str = "fcp-xai";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.20";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const API_KEY: &str = "xai-local-acceptance-key";
const OP_CHAT: &str = "xai.chat.completions";
const OP_CHAT_STREAM: &str = "xai.chat.completions_stream";
const OP_RESPONSES: &str = "xai.responses.create";
const CAP_CHAT: &str = "xai.chat";
const CAP_RESPONSES: &str = "xai.responses.web_search";
const CAP_MODELS: &str = "xai.models.read";

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
                    .set_read_timeout(Some(Duration::from_secs(5)))
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
            }
        });

        Self {
            base_url,
            received,
            join,
        }
    }

    fn provider_base_url(&self) -> String {
        format!("{}/v1", self.base_url)
    }

    fn take(&self) -> CapturedRequest {
        self.received
            .recv_timeout(Duration::from_secs(5))
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
    body: &'static str,
}

/// Holds a real HTTP response open after headers and a body prefix. The test
/// releases the socket only after the invocation has returned, so an EOF or a
/// provider status cannot masquerade as deadline/cancellation enforcement.
struct IncompleteBodyServer {
    base_url: String,
    received: Receiver<CapturedRequest>,
    release: Sender<()>,
    join: JoinHandle<()>,
}

impl IncompleteBodyServer {
    fn start(streaming: bool, cancel_after_prefix: Option<fcp_async_core::Cx>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind incomplete-body server");
        listener.set_nonblocking(true).expect("bounded accept loop");
        let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
        let (request_tx, received) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        assert!(
                            started.elapsed() < Duration::from_secs(5),
                            "provider request never arrived"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let captured = read_complete_request(&mut stream);
            let (content_type, prefix) = if streaming {
                (
                    "text/event-stream",
                    concat!(
                        "data: {\"id\":\"chunk-local\",\"object\":\"chat.completion.chunk\",\"created\":1,",
                        "\"model\":\"grok-4.3\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n"
                    ),
                )
            } else {
                (
                    "application/json",
                    "{\"id\":\"unfinished\",\"model\":\"grok-4.3\",",
                )
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                prefix.len() + 1024,
            );
            stream
                .write_all(head.as_bytes())
                .expect("write successful response headers");
            stream
                .write_all(prefix.as_bytes())
                .expect("write incomplete response body");
            request_tx
                .send(captured)
                .expect("record dispatched request");
            if let Some(context) = cancel_after_prefix {
                context.set_cancel_requested(true);
            }
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        });
        Self {
            base_url,
            received,
            release,
            join,
        }
    }

    fn finish(self) -> CapturedRequest {
        let _ = self.release.send(());
        let captured = self.received.recv_timeout(Duration::from_secs(5));
        self.join
            .join()
            .expect("incomplete-body thread should finish");
        captured.expect("provider must have received the admitted request")
    }
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
        "request should carry configured xAI bearer key; head={}",
        captured.head
    );
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> fcp_prelude::CapabilityToken {
    constrained_token(
        signing_key,
        instance_id,
        capability,
        operation,
        None,
        &CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        },
    )
}

fn constrained_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
    token_id: Option<&[u8]>,
    constraints: &CapabilityConstraints,
) -> fcp_prelude::CapabilityToken {
    let now = Utc::now();
    let mut cbor = Vec::new();
    ciborium::into_writer(constraints, &mut cbor).expect("serialize capability constraints");
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate");
    if let Some(id) = token_id {
        builder = builder.token_id(id);
    }
    let cose = builder
        .sign(signing_key)
        .expect("capability token should sign");
    fcp_prelude::CapabilityToken::from_raw(cose)
}

async fn setup_connector(
    base_url: &str,
    capabilities: &[&'static str],
) -> (XaiConnector, Ed25519SigningKey) {
    let mut connector = XaiConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "base_url": base_url,
            "default_model": "grok-4.3",
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("xAI connector should configure against loopback");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let requested = capabilities
        .iter()
        .map(|capability| CapabilityId::from_static(capability))
        .collect::<Vec<_>>();
    connector
        .handshake(test_handshake_request(requested, verifying_key.to_bytes()))
        .await
        .expect("xAI connector should handshake");

    (connector, signing_key)
}

async fn invoke(
    connector: &XaiConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let capability_token = valid_token(signing_key, connector.instance_id(), capability, operation);
    connector
        .handle_invoke(
            serde_json::to_value(test_invoke_request(
                "xai-local-boundary",
                operation,
                input,
                capability_token,
            ))
            .expect("canonical invoke request"),
        )
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
        "command": "cargo test -p fcp-xai --test local_non_mock -- --nocapture",
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
            "id": "chatcmpl-xai-local",
            "object": "chat.completion",
            "created": 1,
            "model": "grok-4.3",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "loopback xAI response"},
                    "finish_reason": "stop"
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 4, "total_tokens": 9}
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
    assert_request(&captured, "POST", "/v1/chat/completions");
    let body = captured.body.expect("chat request should send JSON");
    assert_eq!(body["model"], "grok-4.3");
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "Say ok through loopback");
    assert_eq!(body["stream"], false);
    assert_eq!(body["max_tokens"], 32);
    assert_eq!(body["temperature"], 0.2);
    server.join();

    assert_eq!(result["id"], "chatcmpl-xai-local");
    assert_eq!(result["content"], "loopback xAI response");
    assert_eq!(result["finish_reason"], "stop");
    assert_eq!(result["usage"]["total_tokens"], 9);
    assert!(
        !result.to_string().contains(API_KEY),
        "mapped output must not leak API key"
    );

    print_artifact(
        "chat_completions",
        &json!({
            "method": "POST",
            "path": "/v1/chat/completions",
            "request_fields": ["model", "messages", "stream", "max_tokens", "temperature"],
            "response_fields": ["id", "model", "content", "finish_reason", "usage", "raw"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_responses_posts_web_search_and_extracts_citations() {
    let server = LoopbackServer::start(vec![HttpResponse::json(
        "200 OK",
        r#"{
            "id": "resp-xai-local",
            "object": "response",
            "created_at": 1,
            "model": "grok-4.3",
            "status": "completed",
            "output": [{
                "type": "message",
                "id": "msg-local",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": "xAI publishes Grok updates.",
                    "annotations": [{
                        "type": "url_citation",
                        "url": "https://x.ai/news/grok",
                        "title": "xAI news",
                        "start_index": 0,
                        "end_index": 3
                    }]
                }]
            }],
            "usage": {"input_tokens": 11, "output_tokens": 12, "total_tokens": 23},
            "server_side_tool_usage": {"web_search": 1}
        }"#,
    )]);
    let (connector, signing_key) =
        setup_connector(&server.provider_base_url(), &[CAP_RESPONSES]).await;

    let result = invoke(
        &connector,
        &signing_key,
        OP_RESPONSES,
        CAP_RESPONSES,
        json!({
            "input": [{"role": "user", "content": "What is xAI?"}],
            "include": ["no_inline_citations"],
            "web_search": {
                "allowed_domains": ["x.ai"],
                "enable_image_understanding": true
            }
        }),
    )
    .await
    .expect("responses should invoke through loopback");

    let captured = server.take();
    assert_request(&captured, "POST", "/v1/responses");
    let body = captured.body.expect("responses request should send JSON");
    assert_eq!(body["model"], "grok-4.3");
    assert_eq!(body["include"], json!(["no_inline_citations"]));
    assert_eq!(body["tools"][0]["type"], "web_search");
    assert_eq!(
        body["tools"][0]["filters"]["allowed_domains"],
        json!(["x.ai"])
    );
    assert_eq!(body["tools"][0]["enable_image_understanding"], true);
    server.join();

    assert_eq!(result["id"], "resp-xai-local");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["citation_count"], 1);
    assert_eq!(result["citation_hosts"], json!(["x.ai"]));
    assert_eq!(result["usage"]["total_tokens"], 23);
    assert!(
        !result.to_string().contains(API_KEY),
        "responses output must not leak API key"
    );

    print_artifact(
        "responses_web_search",
        &json!({
            "method": "POST",
            "path": "/v1/responses",
            "request_fields": ["model", "input", "include", "tools"],
            "response_fields": ["id", "status", "output_text", "citations", "usage"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_wrong_capability_fails_before_egress() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .expect("loopback listener should bind to an ephemeral port");
    listener
        .set_nonblocking(true)
        .expect("no-egress listener should be nonblocking");
    let base_url = format!(
        "http://{}/v1",
        listener
            .local_addr()
            .expect("loopback listener should expose its address")
    );
    let (connector, signing_key) = setup_connector(&base_url, &[CAP_MODELS]).await;

    let error = invoke(
        &connector,
        &signing_key,
        OP_CHAT,
        CAP_MODELS,
        json!({"messages": [{"role": "user", "content": "must not egress"}]}),
    )
    .await
    .expect_err("capability mismatch should fail before provider egress");

    assert!(
        matches!(
            error,
            FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
        ),
        "unexpected capability error: {error:?}"
    );
    let accept_result = listener.accept();
    assert!(
        matches!(accept_result, Err(ref err) if err.kind() == ErrorKind::WouldBlock),
        "capability denial should happen before any HTTP connection"
    );

    print_artifact(
        "wrong_capability_no_egress",
        &json!({
            "method": "none",
            "path": "none",
            "requested_operation": OP_CHAT,
            "provided_capability": CAP_MODELS,
            "mapped_error": "CapabilityDenied",
            "egress_observed": false
        }),
    );
}

async fn incomplete_body_is_bounded(cancel: bool) {
    for (operation, capability, endpoint, input) in [
        (
            OP_CHAT,
            CAP_CHAT,
            "/v1/chat/completions",
            json!({"messages":[{"role":"user","content":"hello"}]}),
        ),
        (
            OP_CHAT_STREAM,
            CAP_CHAT,
            "/v1/chat/completions",
            json!({"messages":[{"role":"user","content":"hello"}]}),
        ),
        (
            OP_RESPONSES,
            CAP_RESPONSES,
            "/v1/responses",
            json!({"input":"hello", "tools":[{"type":"web_search"}]}),
        ),
    ] {
        let context = fcp_async_core::Cx::for_testing();
        let server = IncompleteBodyServer::start(
            operation == OP_CHAT_STREAM,
            cancel.then(|| context.clone()),
        );
        let (connector, signing_key) = setup_connector(&server.base_url, &[capability]).await;
        let token = constrained_token(
            &signing_key,
            connector.instance_id(),
            capability,
            operation,
            Some(b"incomplete-body-once"),
            &CapabilityConstraints {
                resource_allow: vec!["*".into()],
                max_calls: Some(1),
                ..Default::default()
            },
        );
        let mut request = test_invoke_request("incomplete-body", operation, input, token);
        request.deadline_ms = Some(if cancel { 5_000 } else { 500 });
        let started = std::time::Instant::now();
        let future = connector.invoke(request.clone());
        futures_util::pin_mut!(future);
        let first_poll = if cancel {
            let guard = fcp_async_core::Cx::set_current(Some(context));
            // Capture the native caller context on the first poll, then drop
            // the thread-local guard before awaiting the pending I/O.
            let first_poll = future.as_mut().now_or_never();
            drop(guard);
            first_poll
        } else {
            None
        };
        let result = match first_poll {
            Some(result) => result,
            None => future.await,
        };
        let elapsed = started.elapsed();
        let captured = server.finish();
        assert_request(&captured, "POST", endpoint);
        if operation == OP_CHAT_STREAM {
            assert_eq!(captured.body.unwrap()["stream"], true);
        }
        let error = result.expect_err("incomplete body must be interrupted by caller budget");
        assert!(
            !error.is_retryable(),
            "interrupted admitted work must not advertise retry"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "caller limit did not bound the full response: {elapsed:?}"
        );
        assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
        assert!(
            connector.invoke(request).await.is_err(),
            "interrupted provider work refunded the grant"
        );
        assert_eq!(connector.handle_health().await.unwrap()["requests"], 1);
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_caller_deadline_bounds_chat_sse_and_responses_bodies() {
    incomplete_body_is_bounded(false).await;
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_active_cancellation_interrupts_dispatched_chat_sse_and_responses() {
    incomplete_body_is_bounded(true).await;
}
