//! Local loopback acceptance coverage for the FCP Hugging Face connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{CapabilityToken, FcpError};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_huggingface::connector::HuggingfaceConnector;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BATCH_BEAD_ID: &str = "flywheel_connectors-angoc.16.4";
const ACCESS_TOKEN: &str = "hf_local_acceptance_token";
const OP_TEXT_GENERATION: &str = "huggingface.inference.text_generation";
const OP_SUMMARIZATION: &str = "huggingface.inference.summarization";
const TEXT_GENERATION_PATH: &str = "/models/gpt2";
const SUMMARIZATION_PATH: &str = "/models/facebook/bart-large-cnn";
const TEXT_GENERATION_RESPONSE_BODY: &str =
    r#"[{"generated_text":"Flywheel connectors ship local proof."}]"#;
const SUMMARIZATION_RESPONSE_BODY: &str = r#"[{"summary_text":"Local Hugging Face summary."}]"#;

fn signing_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[75; 32]).expect("valid local acceptance signing key")
}

fn signed_request(connector: &HuggingfaceConnector, operation: &str, input: Value) -> Value {
    let now = Utc::now();
    let token = CapabilityTokenBuilder::new()
        .capability_id("huggingface.inference")
        .zone_id("z:work")
        .principal("user:huggingface-local")
        .operations(&[operation])
        .issuer("node:huggingface-local")
        .target_instance(connector.instance_id().as_str())
        .validity(
            now - ChronoDuration::minutes(1),
            now + ChronoDuration::hours(1),
        )
        .sign(&signing_key())
        .expect("sign bound capability");
    json!({
        "type": "invoke",
        "id": "local-acceptance",
        "connector_id": "fcp.huggingface",
        "operation": operation,
        "zone_id": "z:work",
        "input": input,
        "idempotency_key": "local-acceptance",
        "capability_token": CapabilityToken::from_raw(token)
    })
}

#[derive(Debug)]
struct FixtureObservation {
    request_line: String,
    authorization_seen: bool,
    content_type_json_seen: bool,
    body: Value,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<FixtureObservation>>,
}

impl LoopbackFixture {
    fn start(response_body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connector request");
            handle_request(stream, response_body)
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

fn handle_request(mut stream: TcpStream, response_body: &'static str) -> FixtureObservation {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let request = read_http_request(&mut stream);
    let header_end = find_header_end(&request).expect("request contains complete headers");
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = content_length(&headers).expect("request has content-length");
    let body_start = header_end + b"\r\n\r\n".len();
    let body_end = body_start + content_length;
    let body: Value = serde_json::from_slice(&request[body_start..body_end])
        .expect("connector request body is JSON");

    let request_line = headers.lines().next().unwrap_or_default().to_string();
    let authorization_seen =
        header_seen(&headers, "authorization", &format!("Bearer {ACCESS_TOKEN}"));
    let content_type_json_seen =
        header_value_contains(&headers, "content-type", "application/json");

    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
    .expect("write connector response");

    FixtureObservation {
        request_line,
        authorization_seen,
        content_type_json_seen,
        body,
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector closed before sending request");
        request.extend_from_slice(&buffer[..bytes_read]);

        if let Some(header_end) = find_header_end(&request) {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let Some(length) = content_length(&headers) else {
                continue;
            };
            let required_len = header_end + b"\r\n\r\n".len() + length;
            if request.len() >= required_len {
                request.truncate(required_len);
                return request;
            }
        }

        assert!(request.len() < 16 * 1024, "request should stay bounded");
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
            .then(|| value.trim().parse().expect("content-length is numeric"))
    })
}

fn header_seen(headers: &str, expected_name: &str, expected_value: &str) -> bool {
    headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case(expected_name) && value.trim() == expected_value
    })
}

fn header_value_contains(headers: &str, expected_name: &str, expected_value: &str) -> bool {
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

async fn setup_connector(base_url: &str) -> HuggingfaceConnector {
    let mut connector = HuggingfaceConnector::new();
    connector
        .handle_configure(json!({
            "api_token": ACCESS_TOKEN,
            "inference_url": base_url,
            "hub_url": base_url,
            "request_timeout_ms": 5_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure connector");
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "host_public_key": signing_key().verifying_key().to_bytes(),
            "nonce": vec![18_u8; 32],
            "capabilities_requested": ["huggingface.inference", "huggingface.models"]
        }))
        .await
        .expect("handshake connector");
    connector
}

#[fcp_async_core::runtime::test]
async fn loopback_text_generation_uses_production_client_request() {
    let fixture = LoopbackFixture::start(TEXT_GENERATION_RESPONSE_BODY);
    let mut connector = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(signed_request(
            &connector,
            OP_TEXT_GENERATION,
            json!({
                    "model_id": "gpt2",
                    "prompt": "Flywheel connectors",
                    "max_new_tokens": 8,
                    "return_full_text": false
            }),
        ))
        .await
        .expect("text generation through loopback fixture");
    connector
        .handle_shutdown(json!({"type": "shutdown"}))
        .await
        .expect("shutdown connector");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(
        observation.request_line,
        format!("POST {TEXT_GENERATION_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert!(observation.content_type_json_seen);
    assert_eq!(
        observation.body,
        json!({
            "inputs": "Flywheel connectors",
            "parameters": {
                "max_new_tokens": 8,
                "return_full_text": false
            }
        })
    );
    assert_eq!(
        result["result"][0]["generated_text"],
        "Flywheel connectors ship local proof."
    );

    let artifact = json!({
        "connector": "huggingface",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": "flywheel_connectors-bky21.3.6.14",
        "command": "cargo test -p fcp-huggingface --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "POST",
            "path": TEXT_GENERATION_PATH
        },
        "auth_gate": {
            "mode": "bearer",
            "credentials_used": true,
            "authorization_header_verified": observation.authorization_seen
        },
        "request_body": observation.body,
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn loopback_summarization_uses_production_client_request() {
    let fixture = LoopbackFixture::start(SUMMARIZATION_RESPONSE_BODY);
    let mut connector = setup_connector(fixture.base_url()).await;

    let result = connector
        .handle_invoke(signed_request(
            &connector,
            OP_SUMMARIZATION,
            json!({
                    "model_id": "facebook/bart-large-cnn",
                    "text": "Flywheel connectors need a concise local acceptance proof.",
                    "max_length": 32,
                    "min_length": 4,
                    "do_sample": true
            }),
        ))
        .await
        .expect("summarization through loopback fixture");
    connector
        .handle_shutdown(json!({"type": "shutdown"}))
        .await
        .expect("shutdown connector");
    let observation = fixture.join();

    assert_eq!(ACCEPTANCE_SUITE_CLASS, "local_non_mock");
    assert_eq!(
        observation.request_line,
        format!("POST {SUMMARIZATION_PATH} HTTP/1.1")
    );
    assert!(observation.authorization_seen);
    assert!(observation.content_type_json_seen);
    assert_eq!(
        observation.body,
        json!({
            "inputs": "Flywheel connectors need a concise local acceptance proof.",
            "parameters": {
                "generate_parameters": {
                    "max_length": 32,
                    "min_length": 4,
                    "do_sample": true
                }
            }
        })
    );
    assert_eq!(
        result["result"][0]["summary_text"],
        "Local Hugging Face summary."
    );

    let artifact = json!({
        "connector": "huggingface",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BATCH_BEAD_ID,
        "command": "cargo test -p fcp-huggingface --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "request_response_boundary": {
            "method": "POST",
            "path": SUMMARIZATION_PATH
        },
        "auth_gate": {
            "mode": "bearer",
            "credentials_used": true,
            "authorization_header_verified": observation.authorization_seen
        },
        "request_body": observation.body,
        "cleanup": "connector_shutdown_and_fixture_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn missing_summarization_text_fails_before_loopback_network_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let base_url = format!("http://{}", listener.local_addr().expect("local address"));
    let connector = setup_connector(&base_url).await;

    let error = connector
        .handle_invoke(signed_request(
            &connector,
            OP_SUMMARIZATION,
            json!({
                    "model_id": "facebook/bart-large-cnn"
            }),
        ))
        .await
        .expect_err("missing summarization text should fail before HTTP dispatch");
    assert!(matches!(error, FcpError::InvalidRequest { code: 1003, .. }));

    let accept_error = listener
        .accept()
        .expect_err("input validation should happen before loopback egress");
    assert_eq!(accept_error.kind(), io::ErrorKind::WouldBlock);

    let artifact = json!({
        "connector": "huggingface",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BATCH_BEAD_ID,
        "command": "cargo test -p fcp-huggingface --test local_non_mock -- --nocapture",
        "fixture_mode": "loopback_http",
        "provider_class": "local_sufficient",
        "operation": OP_SUMMARIZATION,
        "error_boundary": "missing_text_rejected_before_network_dispatch",
        "loopback_egress_attempted": false,
        "result": "passed"
    });
    println!("{artifact}");
}
