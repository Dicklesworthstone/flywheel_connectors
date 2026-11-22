//! Local loopback acceptance coverage for the `OpenRouter` connector.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{CapabilityConstraints, CapabilityToken};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_openrouter::OpenRouterConnector;
use serde_json::{Value, json};

const CONNECTOR: &str = "openrouter";
const PACKAGE: &str = "fcp-openrouter";
const BEAD_ID: &str = "flywheel_connectors-bky21.3.6.10";
const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const OP_MODELS_LIST: &str = "openrouter.models.list";
const OP_CHAT_COMPLETIONS: &str = "openrouter.chat.completions";

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    headers: Vec<String>,
    body: Option<Value>,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start(status: u16, response_body: &Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let response_body = response_body.to_string();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream, status, &response_body)
        });

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> FixtureObservation {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_request(mut stream: TcpStream, status: u16, response_body: &str) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("request contains complete headers");
    let headers_text = String::from_utf8_lossy(&request[..header_end]);
    let request_line = headers_text.lines().next().unwrap_or_default().to_string();
    let headers = headers_text
        .lines()
        .skip(1)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let body_start = header_end + b"\r\n\r\n".len();
    let body = (body_start < request.len())
        .then(|| serde_json::from_slice(&request[body_start..]).expect("request body is JSON"));

    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        status,
        reason_phrase(status),
        response_body.len(),
        response_body
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        headers,
        body,
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).expect("read request headers");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = content_length(&headers).unwrap_or(0);
            let required_len = header_end + b"\r\n\r\n".len() + content_length;
            if request.len() >= required_len {
                request.truncate(required_len);
                return request;
            }
        }

        assert!(request.len() < 65_536, "request should stay bounded");
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().expect("valid content-length"))
    })
}

const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        _ => "Status",
    }
}

fn has_header(headers: &[String], name: &str, expected_value: &str) -> bool {
    headers.iter().any(|line| {
        let Some((header_name, value)) = line.split_once(':') else {
            return false;
        };
        header_name.eq_ignore_ascii_case(name) && value.trim() == expected_value
    })
}

async fn configured_connector(base_url: &str) -> (OpenRouterConnector, Ed25519SigningKey) {
    let mut connector = OpenRouterConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "openrouter-local-key",
            "base_url": base_url,
            "request_timeout_ms": 5_000,
            "app_name": "FCP OpenRouter local acceptance",
            "app_url": "https://example.com/fcp-openrouter-local"
        }))
        .await
        .expect("configure OpenRouter connector against loopback fixture");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![5_u8; 32],
            "capabilities_requested": ["openrouter.chat", "openrouter.models"]
        }))
        .await
        .expect("handshake OpenRouter connector");
    (connector, signing_key)
}

fn capability_token(
    connector: &OpenRouterConnector,
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operation: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
    let now = Utc::now();
    CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(capability)
            .operations(&[operation])
            .zone_id("z:work")
            .principal("user:local-acceptance")
            .issuer("node:local-acceptance")
            .target_instance(connector.instance_id().as_str())
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .sign(signing_key)
            .unwrap(),
    )
}

fn print_artifact(case_name: &str, boundary: &Value) {
    let artifact = json!({
        "connector": CONNECTOR,
        "package": PACKAGE,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "case": case_name,
        "command": "cargo test -p fcp-openrouter --test local_non_mock -- --nocapture",
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
async fn local_non_mock_models_list_uses_loopback_boundary() {
    let fixture = LoopbackFixture::start(
        200,
        &json!({
            "data": [
                {"id": "openai/gpt-4.1-mini", "name": "GPT 4.1 Mini"},
                {"id": "anthropic/claude-sonnet-4", "name": "Claude Sonnet 4"}
            ]
        }),
    );
    let (connector, signing_key) = configured_connector(fixture.base_url()).await;
    let token = capability_token(
        &connector,
        &signing_key,
        "openrouter.models",
        OP_MODELS_LIST,
    );

    let response = connector
        .handle_invoke(json!({
            "type": "invoke",
            "id": "local-models",
            "connector_id": "fcp.openrouter",
            "zone_id": "z:work",
            "operation": OP_MODELS_LIST,
            "capability_token": token,
            "input": {}
        }))
        .await
        .expect("models.list through loopback OpenRouter boundary");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(observation.request_line, "GET /models HTTP/1.1");
    assert!(has_header(
        &observation.headers,
        "authorization",
        "Bearer openrouter-local-key"
    ));
    assert!(has_header(
        &observation.headers,
        "x-title",
        "FCP OpenRouter local acceptance"
    ));
    assert!(has_header(
        &observation.headers,
        "http-referer",
        "https://example.com/fcp-openrouter-local"
    ));
    assert!(observation.body.is_none());
    assert_eq!(response["data"][0]["id"], "openai/gpt-4.1-mini");

    print_artifact(
        "models_list",
        &json!({
            "method": "GET",
            "path": "/models",
            "provider_headers": ["authorization", "x-title", "http-referer"],
            "response_fields": ["data"]
        }),
    );
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_chat_completions_posts_openai_compatible_body() {
    let fixture = LoopbackFixture::start(
        200,
        &json!({
            "id": "chatcmpl-local-001",
            "model": "openai/gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Local loopback response"
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 8,
                "completion_tokens": 4,
                "total_tokens": 12
            }
        }),
    );
    let (connector, signing_key) = configured_connector(fixture.base_url()).await;
    let token = capability_token(
        &connector,
        &signing_key,
        "openrouter.chat",
        OP_CHAT_COMPLETIONS,
    );

    let response = connector
        .handle_invoke(json!({
            "type": "invoke",
            "id": "local-chat",
            "connector_id": "fcp.openrouter",
            "zone_id": "z:work",
            "operation": OP_CHAT_COMPLETIONS,
            "capability_token": token,
            "input": {
                "model": "openai/gpt-4.1-mini",
                "messages": [
                    {"role": "user", "content": "Say hello through loopback"}
                ],
                "max_tokens": 16,
                "temperature": 0.2
            }
        }))
        .await
        .expect("chat.completions through loopback OpenRouter boundary");
    let observation = fixture.join();
    let body = observation.body.expect("chat request has JSON body");

    assert_eq!(observation.request_line, "POST /chat/completions HTTP/1.1");
    assert!(has_header(
        &observation.headers,
        "authorization",
        "Bearer openrouter-local-key"
    ));
    assert_eq!(body["model"], "openai/gpt-4.1-mini");
    assert_eq!(body["messages"][0]["role"], "user");
    assert_eq!(body["messages"][0]["content"], "Say hello through loopback");
    assert_eq!(body["max_tokens"], 16);
    assert_eq!(body["temperature"], 0.2);
    assert_eq!(response["id"], "chatcmpl-local-001");
    assert_eq!(response["content"], "Local loopback response");
    assert_eq!(response["finish_reason"], "stop");
    assert_eq!(response["usage"]["total_tokens"], 12);

    print_artifact(
        "chat_completions",
        &json!({
            "method": "POST",
            "path": "/chat/completions",
            "request_fields": ["model", "messages", "max_tokens", "temperature"],
            "response_fields": ["id", "model", "content", "finish_reason", "usage", "raw"]
        }),
    );
}
