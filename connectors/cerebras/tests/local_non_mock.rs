//! Local loopback acceptance coverage for the Cerebras connector.

#![allow(
    clippy::future_not_send,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_cerebras::{
    CerebrasConnector, DEFAULT_MODEL,
    connector::{test_handshake_request, test_invoke_request},
};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, InstanceId,
};
use serde_json::{Value, json};

const CONNECTOR: &str = "cerebras";
const PACKAGE: &str = "fcp-cerebras";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.27";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const API_KEY: &str = "local_cerebras_api_key";

const OP_CHAT: &str = "cerebras.chat.completions";
const OP_MODELS: &str = "cerebras.models.list";
const OP_HEALTH: &str = "cerebras.health";

const CAP_CHAT: &str = "cerebras.chat";
const CAP_MODELS: &str = "cerebras.models.read";
const CAP_HEALTH: &str = "cerebras.health.read";

const CHAT_RESPONSE: &str = r#"{
  "id": "chatcmpl-cerebras-local",
  "object": "chat.completion",
  "created": 1,
  "model": "llama3.1-8b",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "loopback Cerebras response"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 5,
    "completion_tokens": 4,
    "total_tokens": 9
  }
}"#;

const MODELS_RESPONSE: &str = r#"{
  "object": "list",
  "data": [
    {
      "id": "llama3.1-8b",
      "object": "model",
      "created": 1721692800,
      "owned_by": "Meta"
    }
  ]
}"#;

#[derive(Clone, Copy)]
struct HttpResponse {
    status: &'static str,
    body: &'static str,
}

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: HeaderObservations,
    body: Option<Value>,
}

#[derive(Debug)]
struct HeaderObservations {
    authorization: HeaderPresence,
    accept_json: HeaderPresence,
    content_type_json: HeaderPresence,
    user_agent: HeaderPresence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderPresence {
    Seen,
    Missing,
}

impl HeaderPresence {
    const fn from_found(found: bool) -> Self {
        if found { Self::Seen } else { Self::Missing }
    }

    fn assert_seen(self, name: &str) {
        assert_eq!(self, Self::Seen, "expected {name} header");
    }
}

struct LoopbackServer {
    base_url: String,
    handle: Option<JoinHandle<Vec<FixtureObservation>>>,
}

impl LoopbackServer {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            responses
                .iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, *response)
                })
                .collect()
        });

        Self {
            base_url: format!("http://{address}/v1"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<FixtureObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: HttpResponse) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let request = read_complete_request(&mut stream);
    let header_end = find_header_end(&request).expect("request contains complete headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let body_start = header_end + b"\r\n\r\n".len();
    let body = (body_start < request.len())
        .then(|| serde_json::from_slice(&request[body_start..]).expect("request body is JSON"));
    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let header_observations = HeaderObservations {
        authorization: HeaderPresence::from_found(header_equals(
            &headers,
            "authorization",
            &format!("Bearer {API_KEY}"),
        )),
        accept_json: HeaderPresence::from_found(header_contains(
            &headers,
            "accept",
            "application/json",
        )),
        content_type_json: HeaderPresence::from_found(header_contains(
            &headers,
            "content-type",
            "application/json",
        )),
        user_agent: HeaderPresence::from_found(header_contains(
            &headers,
            "user-agent",
            "fcp-cerebras/0.1.0",
        )),
    };

    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        response.body.len(),
        response.body
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers: header_observations,
        body,
    }
}

fn read_complete_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector closed before request completed");
        request.extend_from_slice(&buffer[..bytes_read]);
        assert!(request.len() < 64 * 1024, "request should stay bounded");

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = parse_content_length(&headers).unwrap_or(0);
            let expected_len = header_end + b"\r\n\r\n".len() + content_length;
            if request.len() >= expected_len {
                request.truncate(expected_len);
                return request;
            }
        }
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().expect("content-length is numeric"))
    })
}

fn header_equals(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn header_contains(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name)
            && value
                .to_ascii_lowercase()
                .contains(&expected_value.to_ascii_lowercase())
    })
}

async fn setup_connector(base_url: &str, capabilities: &[&'static str]) -> ConfiguredCerebras {
    let mut connector = CerebrasConnector::new();
    connector
        .handle_configure(json!({
            "api_key": API_KEY,
            "base_url": base_url,
            "request_timeout_ms": 5_000
        }))
        .await
        .expect("configure Cerebras connector");
    let signing_key = Ed25519SigningKey::generate();
    let requested = capabilities
        .iter()
        .map(|capability| CapabilityId::from_static(capability))
        .collect();
    connector
        .handshake(test_handshake_request(
            requested,
            signing_key.verifying_key().to_bytes(),
        ))
        .await
        .expect("handshake Cerebras connector");

    ConfiguredCerebras {
        connector,
        signing_key,
    }
}

struct ConfiguredCerebras {
    connector: CerebrasConnector,
    signing_key: Ed25519SigningKey,
}

async fn invoke(
    connector: &CerebrasConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    capability: &'static str,
    input: Value,
) -> fcp_core::FcpResult<Value> {
    let grant = valid_grant(signing_key, connector.instance_id(), capability, operation);
    let response = connector
        .invoke(test_invoke_request(
            "cerebras-local-non-mock",
            operation,
            input,
            grant,
        ))
        .await?;
    if let Some(error) = response.error {
        Err(error)
    } else {
        response.result.ok_or_else(|| FcpError::Internal {
            message: "Cerebras invoke response had neither result nor error".into(),
        })
    }
}

fn valid_grant(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints serialize");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:cerebras-local-non-mock")
        .operations(&[operation])
        .issuer("node:cerebras-local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability grant should sign");
    CapabilityToken::from_raw(cose)
}

fn print_artifact(case_name: &str, boundary: Value) {
    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "bead_id": BEAD_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "case": case_name,
        "command": "cargo test -p fcp-cerebras --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "raw_tcp_loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": boundary,
        "auth_gate": {
            "mode": "bearer_api_key",
            "authorization_header_verified": true,
            "secret_material_logged": false
        },
        "cleanup": "fixture_thread_joined",
        "result": "passed"
    });
    let rendered = artifact.to_string();
    assert!(!rendered.contains(API_KEY));
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_chat_completions_posts_body_and_maps_output() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: CHAT_RESPONSE,
    }]);
    let configured = setup_connector(server.base_url(), &[CAP_CHAT]).await;

    let result = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT,
        CAP_CHAT,
        json!({
            "messages": [{"role": "user", "content": "Say ok through loopback"}],
            "max_completion_tokens": 32,
            "temperature": 0.2,
            "reasoning_effort": "low",
            "clear_thinking": true
        }),
    )
    .await
    .expect("chat completions invoke should succeed");
    let observations = server.join();
    let observation = observations
        .first()
        .expect("one chat completions request observed");
    let body = observation.body.as_ref().expect("chat request sends JSON");

    assert_eq!(
        observation.request_line,
        "POST /v1/chat/completions HTTP/1.1"
    );
    observation
        .headers
        .authorization
        .assert_seen("authorization");
    observation.headers.accept_json.assert_seen("accept");
    observation
        .headers
        .content_type_json
        .assert_seen("content-type");
    observation.headers.user_agent.assert_seen("user-agent");
    assert_eq!(body["model"], DEFAULT_MODEL);
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "Say ok through loopback");
    assert_eq!(body["stream"], false);
    assert_eq!(body["max_completion_tokens"], 32);
    assert_eq!(body["temperature"], 0.2);
    assert_eq!(body["reasoning_effort"], "low");
    assert_eq!(body["clear_thinking"], true);
    assert_eq!(result["id"], "chatcmpl-cerebras-local");
    assert_eq!(result["model"], DEFAULT_MODEL);
    assert_eq!(result["content"], "loopback Cerebras response");
    assert_eq!(result["finish_reason"], "stop");
    assert_eq!(result["usage"]["total_tokens"], 9);
    assert!(!result.to_string().contains(API_KEY));

    print_artifact(
        "chat_completions",
        json!({
            "method": "POST",
            "path": "/v1/chat/completions",
            "request_fields": [
                "model",
                "messages",
                "stream",
                "max_completion_tokens",
                "temperature",
                "reasoning_effort",
                "clear_thinking"
            ],
            "response_fields": ["id", "model", "content", "finish_reason", "usage", "raw"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_models_and_health_share_loopback_boundary() {
    let server = LoopbackServer::start(vec![HttpResponse {
        status: "200 OK",
        body: MODELS_RESPONSE,
    }]);
    let configured = setup_connector(server.base_url(), &[CAP_MODELS, CAP_HEALTH]).await;

    let models_first = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_MODELS,
        CAP_MODELS,
        json!({}),
    )
    .await
    .expect("models invoke should succeed");
    let models_cached = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_MODELS,
        CAP_MODELS,
        json!({}),
    )
    .await
    .expect("models invoke should use cache");
    let health = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_HEALTH,
        CAP_HEALTH,
        json!({}),
    )
    .await
    .expect("health invoke should use cached model list");
    let observations = server.join();
    let observation = observations.first().expect("one models request observed");

    assert_eq!(observations.len(), 1, "models cache should avoid re-egress");
    assert_eq!(observation.request_line, "GET /v1/models HTTP/1.1");
    observation
        .headers
        .authorization
        .assert_seen("authorization");
    observation.headers.accept_json.assert_seen("accept");
    observation.headers.user_agent.assert_seen("user-agent");
    assert!(
        observation.body.is_none(),
        "models request should not send a request body"
    );
    assert_eq!(models_first["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(models_cached["data"][0]["id"], DEFAULT_MODEL);
    assert_eq!(health["status"], "ok");
    assert_eq!(health["model_count"], 1);
    assert!(!health.to_string().contains(API_KEY));

    print_artifact(
        "models_health_cached",
        json!({
            "method": "GET",
            "path": "/v1/models",
            "request_fields": [],
            "response_fields": ["object", "data"],
            "health_reused_cached_models": true,
            "observed_http_request_count": observations.len()
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_wrong_capability_fails_before_egress() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind no-egress listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let base_url = format!(
        "http://{}/v1",
        listener.local_addr().expect("read listener address")
    );
    let configured = setup_connector(&base_url, &[CAP_MODELS]).await;

    let error = invoke(
        &configured.connector,
        &configured.signing_key,
        OP_CHAT,
        CAP_MODELS,
        json!({"messages": [{"role": "user", "content": "must not reach loopback"}]}),
    )
    .await
    .expect_err("wrong capability should fail before egress");

    assert!(
        matches!(
            error,
            FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
        ),
        "expected capability denial, got {error:?}"
    );
    let accept_result = listener.accept();
    assert!(
        matches!(accept_result, Err(ref err) if err.kind() == ErrorKind::WouldBlock),
        "connector should not have opened a loopback connection; got {accept_result:?}"
    );

    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "bead_id": BEAD_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "fixture_mode": "no_egress_loopback_listener",
        "operation": OP_CHAT,
        "wrong_capability": CAP_MODELS,
        "egress_attempted": false,
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_stream_body_deadline_drops_socket_and_withholds_partial_output() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled SSE provider");
    listener.set_nonblocking(true).unwrap();
    let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let configured = setup_connector(&base_url, &[CAP_CHAT]).await;
    let provider = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "SSE accept deadline");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("SSE accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let request = read_complete_request(&mut stream);
        assert!(request.starts_with(b"POST /v1/chat/completions HTTP/1.1\r\n"));
        let prefix = concat!(
            "HTTP/1.1 200 OK\r\n",
            "content-type: text/event-stream\r\n",
            "content-length: 1000000\r\n",
            "connection: close\r\n\r\n",
            "data: {\"id\":\"partial\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"llama3.1-8b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"must not escape\"},\"finish_reason\":null}]}\n\n",
        );
        stream.write_all(prefix.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut byte = [0_u8; 1];
        let closed = matches!(stream.read(&mut byte), Ok(0));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
            "timed-out stream was silently retried"
        );
        closed
    });

    let operation = "cerebras.chat.completions_stream";
    let token = valid_grant(
        &configured.signing_key,
        configured.connector.instance_id(),
        CAP_CHAT,
        operation,
    );
    let mut request = test_invoke_request(
        "stream-body-deadline",
        operation,
        json!({"messages":[{"role":"user","content":"hello"}]}),
        token,
    );
    request.deadline_ms = Some(300);
    let started = std::time::Instant::now();
    let error = configured
        .connector
        .invoke(request)
        .await
        .expect_err("a partial stream cannot complete after its invocation deadline");
    assert!(matches!(
        error,
        FcpError::External {
            retryable: false,
            ..
        }
    ));
    assert!(!error.to_string().contains("must not escape"));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        provider.join().unwrap(),
        "deadline did not close provider socket"
    );
}
