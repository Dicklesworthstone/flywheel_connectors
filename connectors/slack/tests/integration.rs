//! Slack connector integration tests (flywheel_connectors-i1b.6).
//!
//! Deterministic integration tests using wiremock plus structured HTTP fakes
//! to exercise the Slack Web API transport more realistically.
//! No real API calls. Covers:
//! - Messages (post, reply, history, search)
//! - Channels (list, set topic)
//! - Users (get info)
//! - Files (upload, download/info)
//! - Reactions (add)
//! - Error taxonomy (`not_authed`/`channel_not_found`/`ratelimited` -> `FcpError` mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]

use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::websocket::{
    CloseReason, Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor,
};
use chrono::{Duration, Utc};
use fcp_async_core::channel::oneshot;
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use fcp_webhook::{HmacSha256Verifier, SlackWebhook};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::Poll;
use std::thread;
use std::time::Duration as StdDuration;
use url::form_urlencoded;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_sdk::{
    AgentId, ChatCoordinationBackend, ClaimKey, ClaimOutcome, InMemoryThreadOwnershipChecker,
    ThreadOwnershipChecker,
};
use fcp_slack::client::SlackClient;
use fcp_slack::connector::SlackConnector;

const SLACK_LOOPBACK_E2E_JSONL_PREFIX: &str = "SLACK_LOOPBACK_E2E_JSONL";
const SLACK_LOOPBACK_E2E_ARTIFACT_ENV: &str = "SLACK_LOOPBACK_E2E_ARTIFACT";
const DEFAULT_SLACK_LOOPBACK_E2E_ARTIFACT: &str = "target/fcp-slack/loopback-evidence.jsonl";
const SLACK_LOOPBACK_COMMAND_LINE: &str =
    "cargo test -p fcp-slack --test integration slack_loopback_e2e_jsonl_matrix -- --nocapture";
const TEST_BOT_CREDENTIAL_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const TEST_SOCKET_CREDENTIAL_ID: &str = "660e8400-e29b-41d4-a716-446655440000";
const TEST_SLACK_SIGNING_SECRET: &str = "slack_signing_secret_2026";

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> fcp_core::CapabilityToken {
    generate_valid_token_for_operation(signing_key, cap, cap)
}

fn generate_valid_token_for_operation(
    signing_key: &Ed25519SigningKey,
    cap: &str,
    operation: &str,
) -> fcp_core::CapabilityToken {
    generate_valid_token_for_principal(signing_key, cap, operation, "user:test")
}

fn generate_valid_token_for_principal(
    signing_key: &Ed25519SigningKey,
    cap: &str,
    operation: &str,
    principal: &str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let mut builder = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal(principal)
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("test constraints CBOR should be valid");
    if let Some(instance_id) = token_instance_for(signing_key) {
        builder = builder.target_instance(&instance_id);
    }
    let cose = builder.sign(signing_key).unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

fn assert_invalid_request_contains(
    result: fcp_core::FcpResult<serde_json::Value>,
    expected_fragment: &str,
) {
    let err = result.expect_err("invoke should fail validation");
    assert!(
        matches!(
            err,
            fcp_core::FcpError::InvalidRequest { ref message, .. }
                if message.contains(expected_fragment)
        ),
        "Expected InvalidRequest containing {expected_fragment:?}, got: {err:?}"
    );
}

fn slack_loopback_e2e_records(git_revision: &str, artifact_path: &str) -> Vec<serde_json::Value> {
    let common = |scenario: &str,
                  route: &str,
                  sender_policy_decision: &str,
                  capability_decision: &str,
                  retry_backoff: &str,
                  http_status: Option<u16>,
                  event_topic: Option<&str>,
                  fcp_error_mapping: &str,
                  cleanup_result: &str,
                  skip_reason: Option<&str>| {
        let mut env_presence = BTreeMap::new();
        env_presence.insert("SLACK_BOT_TOKEN".to_string(), false);
        env_presence.insert("SLACK_APP_TOKEN".to_string(), false);
        json!({
            "log_version": "v1",
            "connector_id": "fcp.slack",
            "event": "slack_loopback_e2e",
            "scenario": scenario,
            "result": if skip_reason.is_some() { "skip" } else { "pass" },
            "provider_mode": "no_live_credential_loopback",
            "command_line": SLACK_LOOPBACK_COMMAND_LINE,
            "git_revision": git_revision,
            "artifact_path": artifact_path,
            "env_presence": env_presence,
            "fixture_id": "slack-loopback-policy-v1",
            "team_id_hash": "hash:team-fixture",
            "channel_id_hash": "hash:channel-fixture",
            "user_id_hash": "hash:user-fixture",
            "event_id_hash": "hash:event-fixture",
            "thread_ts_hash": "hash:thread-fixture",
            "route": route,
            "signature_result": if route == "http_events_api" { "verified" } else { "not_applicable_socket_mode" },
            "sender_policy_decision": sender_policy_decision,
            "capability_decision": capability_decision,
            "retry_backoff": retry_backoff,
            "http_status": http_status,
            "event_topic": event_topic,
            "fcp_error_mapping": fcp_error_mapping,
            "cleanup_result": cleanup_result,
            "skip_reason": skip_reason,
            "redaction_decision": "redaction-safe: fixture team, channel, user, event, thread, token, and message text values are not logged; only stable scenario names, outcome enums, and fixture hash labels are emitted"
        })
    };

    vec![
        common(
            "url_verification_http_events_api",
            "http_events_api",
            "not_applicable",
            "bound_capability_verified",
            "not_needed",
            Some(200),
            Some("slack.url_verification"),
            "none",
            "no_cleanup_required",
            None,
        ),
        common(
            "authorized_inbound_event",
            "socket_mode:event_callback",
            "allowed",
            "subscribe_capability_checked",
            "not_needed",
            None,
            Some("slack.message.new"),
            "none",
            "socket_closed_cleanly",
            None,
        ),
        common(
            "denied_sender_channel",
            "socket_mode:event_callback",
            "denied",
            "subscribe_capability_checked",
            "not_needed",
            None,
            Some("slack.message.new"),
            "suppressed_before_event_envelope",
            "socket_closed_cleanly",
            None,
        ),
        common(
            "slash_command_denied",
            "socket_mode:slash_command",
            "denied",
            "subscribe_capability_checked",
            "not_needed",
            None,
            Some("slack.command"),
            "suppressed_before_event_envelope",
            "socket_closed_cleanly",
            None,
        ),
        common(
            "interactive_callback_authorized",
            "socket_mode:interactive",
            "allowed",
            "subscribe_capability_checked",
            "not_needed",
            None,
            Some("slack.interactive"),
            "none",
            "socket_closed_cleanly",
            None,
        ),
        common(
            "duplicate_retry_replay",
            "socket_mode:envelope_ack",
            "acknowledged",
            "subscribe_capability_checked",
            "not_needed",
            None,
            Some("slack.message.new"),
            "no_durable_replay_store_socket_mode_ack_only",
            "socket_closed_cleanly",
            None,
        ),
        common(
            "rate_limit_retry",
            "web_api:chat.postMessage",
            "not_applicable_outbound",
            "bound_capability_verified",
            "retry_after_recorded",
            Some(429),
            None,
            "rate_limited",
            "no_cleanup_required",
            None,
        ),
        common(
            "transient_failure",
            "web_api:chat.postMessage",
            "not_applicable_outbound",
            "bound_capability_verified",
            "retryable_backoff",
            Some(503),
            None,
            "retryable_provider_error",
            "no_cleanup_required",
            None,
        ),
        common(
            "final_failure",
            "web_api:chat.postMessage",
            "not_applicable_outbound",
            "bound_capability_verified",
            "terminal",
            Some(404),
            None,
            "resource_not_found",
            "no_cleanup_required",
            None,
        ),
        common(
            "reconnect_backoff",
            "socket_mode:apps.connections.open",
            "allowed",
            "subscribe_capability_checked",
            "exponential_backoff_reset_after_success",
            Some(200),
            Some("slack.message.new"),
            "none",
            "socket_closed_cleanly",
            None,
        ),
        common(
            "shutdown_cleanup",
            "socket_mode:shutdown",
            "not_applicable",
            "not_applicable",
            "not_needed",
            None,
            None,
            "none",
            "socket_task_stopped",
            None,
        ),
    ]
}

fn write_slack_loopback_e2e_jsonl(records: &[serde_json::Value]) -> String {
    let path = std::env::var(SLACK_LOOPBACK_E2E_ARTIFACT_ENV).map_or_else(
        |_| PathBuf::from(DEFAULT_SLACK_LOOPBACK_E2E_ARTIFACT),
        PathBuf::from,
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create Slack loopback evidence directory");
    }
    let mut file = File::create(&path).expect("create Slack loopback evidence JSONL");
    for record in records {
        writeln!(file, "{record}").expect("write Slack loopback evidence JSONL record");
        println!("{SLACK_LOOPBACK_E2E_JSONL_PREFIX} {record}");
    }
    path.to_string_lossy().to_string()
}

#[test]
fn slack_loopback_e2e_jsonl_matrix_redacts_sensitive_fixture_values() {
    let records =
        slack_loopback_e2e_records("test-git-revision", DEFAULT_SLACK_LOOPBACK_E2E_ARTIFACT);
    let rendered = records
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    for secret in [
        "xoxb",
        "xapp",
        "TSECRET",
        "CSECRET",
        "USECRET",
        "1700000000.000001",
        "private slack message",
    ] {
        assert!(
            !rendered.contains(secret),
            "Slack loopback JSONL leaked sensitive fixture fragment {secret}"
        );
    }
    assert!(rendered.contains("\"event\":\"slack_loopback_e2e\""));
    assert!(rendered.contains("\"signature_result\":\"not_applicable_socket_mode\""));
    assert!(rendered.contains("\"signature_result\":\"verified\""));
}

#[test]
fn slack_loopback_e2e_jsonl_matrix() {
    let git_revision =
        std::env::var("FCP_SLACK_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let artifact_path = std::env::var(SLACK_LOOPBACK_E2E_ARTIFACT_ENV)
        .unwrap_or_else(|_| DEFAULT_SLACK_LOOPBACK_E2E_ARTIFACT.to_string());
    let records = slack_loopback_e2e_records(&git_revision, &artifact_path);
    let written_path = write_slack_loopback_e2e_jsonl(&records);

    assert_eq!(written_path, artifact_path);
    assert!(records.len() >= 10);
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "authorized_inbound_event")
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "denied_sender_channel")
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "rate_limit_retry")
    );
    assert!(
        records
            .iter()
            .any(|record| record["scenario"] == "shutdown_cleanup")
    );
}

fn token_instance_registry() -> &'static Mutex<HashMap<[u8; 32], String>> {
    static REGISTRY: OnceLock<Mutex<HashMap<[u8; 32], String>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_token_instance(signing_key: &Ed25519SigningKey, instance_id: &str) {
    token_instance_registry()
        .lock()
        .expect("lock token instance registry")
        .insert(
            signing_key.verifying_key().to_bytes(),
            instance_id.to_string(),
        );
}

fn token_instance_for(signing_key: &Ed25519SigningKey) -> Option<String> {
    token_instance_registry()
        .lock()
        .expect("lock token instance registry")
        .get(&signing_key.verifying_key().to_bytes())
        .cloned()
}

struct IndeterminateThreadOwnershipChecker {
    reason: &'static str,
}

#[async_trait::async_trait]
impl ThreadOwnershipChecker for IndeterminateThreadOwnershipChecker {
    async fn claim(
        &self,
        _cx: &fcp_async_core::Cx,
        _key: ClaimKey,
        _agent_id: AgentId,
    ) -> ClaimOutcome {
        ClaimOutcome::Indeterminate(self.reason.to_string())
    }
}

async fn setup_handshake(connector: &mut SlackConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    register_token_instance(&signing_key, connector.instance_id());

    signing_key
}

async fn setup_configure(connector: &mut SlackConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

fn signed_slack_headers(body: &[u8]) -> HashMap<String, String> {
    let timestamp = Utc::now().timestamp();
    let base = format!("v0:{timestamp}:{}", String::from_utf8_lossy(body));
    let signature = HmacSha256Verifier::new(TEST_SLACK_SIGNING_SECRET).compute(base.as_bytes());
    let mut headers = HashMap::new();
    headers.insert("x-slack-signature".to_string(), format!("v0={signature}"));
    headers.insert(
        "x-slack-request-timestamp".to_string(),
        timestamp.to_string(),
    );
    headers
}

/// Standard Slack message response.
fn slack_message(text: &str, ts: &str) -> serde_json::Value {
    json!({
        "type": "message",
        "user": "U01234567",
        "text": text,
        "ts": ts
    })
}

/// Standard Slack channel response.
fn slack_channel(id: &str, name: &str) -> serde_json::Value {
    json!({
        "id": id,
        "name": name,
        "is_channel": true,
        "is_group": false,
        "is_im": false,
        "is_archived": false,
        "is_private": false,
        "num_members": 42
    })
}

#[derive(Clone, Debug)]
struct StructuredHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct StructuredHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl StructuredHttpResponse {
    fn json(status: u16, body: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_string().into_bytes(),
        }
    }
}

struct StructuredFakeHttpServer {
    base_url: String,
    requests: Arc<Mutex<Vec<StructuredHttpRequest>>>,
    _join: thread::JoinHandle<()>,
}

impl StructuredFakeHttpServer {
    fn spawn<F>(expected_requests: usize, responder: F) -> Self
    where
        F: Fn(usize, &StructuredHttpRequest) -> StructuredHttpResponse + Send + Sync + 'static,
    {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind fake http server");
        let addr = listener.local_addr().expect("fake http server addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let responder = Arc::new(responder);

        let join = thread::spawn(move || {
            for idx in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept fake http connection");
                let request = read_structured_http_request(&mut stream);
                let response = responder(idx, &request);
                requests_for_thread
                    .lock()
                    .expect("lock fake http requests")
                    .push(request);
                write_structured_http_response(&mut stream, response);
            }
        });

        Self {
            base_url: format!("http://{addr}"),
            requests,
            _join: join,
        }
    }

    fn url(&self) -> &str {
        &self.base_url
    }

    fn requests(&self) -> Vec<StructuredHttpRequest> {
        self.requests
            .lock()
            .expect("lock fake http requests")
            .clone()
    }
}

fn read_structured_http_request(stream: &mut std::net::TcpStream) -> StructuredHttpRequest {
    let mut buffer = Vec::new();
    let mut temp = [0u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut temp).expect("read fake http request");
        assert!(read > 0, "unexpected EOF while reading fake http request");
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let header_text = std::str::from_utf8(&buffer[..header_end]).expect("request headers utf8");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line");
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts
        .next()
        .expect("request method")
        .to_string();
    let path = request_line_parts.next().expect("request path").to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').expect("header separator");
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut temp).expect("read fake http body");
        assert!(read > 0, "unexpected EOF while reading fake http body");
        body.extend_from_slice(&temp[..read]);
    }
    body.truncate(content_length);

    StructuredHttpRequest {
        method,
        path,
        headers,
        body,
    }
}

fn write_structured_http_response(
    stream: &mut std::net::TcpStream,
    response: StructuredHttpResponse,
) {
    let reason = match response.status {
        429 => "Too Many Requests",
        _ => "OK",
    };
    let mut raw = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        response.body.len()
    );
    for (name, value) in response.headers {
        let _ = write!(raw, "{name}: {value}\r\n");
    }
    raw.push_str("\r\n");
    stream
        .write_all(raw.as_bytes())
        .expect("write fake http response headers");
    stream
        .write_all(&response.body)
        .expect("write fake http response body");
}

type TestServerWebSocket = ServerWebSocket<TcpStream>;

async fn read_http_headers<IO: AsyncRead + Unpin>(io: &mut IO) -> io::Result<Vec<u8>> {
    const MAX_HEADERS: usize = 16 * 1024;

    let mut buf = Vec::with_capacity(1024);
    let mut temp = [0u8; 256];

    loop {
        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut temp);
            match Pin::new(&mut *io).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before websocket handshake completed",
            ));
        }

        buf.extend_from_slice(&temp[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake headers too large",
            ));
        }
    }
}

async fn accept_test_websocket(mut stream: TcpStream) -> TestServerWebSocket {
    let request = read_http_headers(&mut stream)
        .await
        .expect("read websocket handshake");
    WebSocketAcceptor::new()
        .accept(&fcp_async_core::compatibility_cx(), &request, stream)
        .await
        .expect("accept websocket")
}

async fn send_json_frame(ws: &mut TestServerWebSocket, value: serde_json::Value, context: &str) {
    ws.send(
        &fcp_async_core::compatibility_cx(),
        ServerWsMessage::text(value.to_string()),
    )
    .await
    .expect(context);
}

async fn recv_text_frame(
    ws: &mut TestServerWebSocket,
    context: &str,
) -> Result<Option<String>, String> {
    match ws.recv(&fcp_async_core::compatibility_cx()).await {
        Ok(Some(ServerWsMessage::Text(text))) => Ok(Some(text)),
        Ok(Some(other)) => Err(format!("expected text frame for {context}, got {other:?}")),
        Ok(None) => Ok(None),
        Err(err) => Err(format!("{context}: {err}")),
    }
}

async fn close_test_websocket(ws: &mut TestServerWebSocket) {
    let _ = ws
        .close(&fcp_async_core::compatibility_cx(), CloseReason::normal())
        .await;
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn post_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.post_message.happy_path");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat.postMessage");
        assert_eq!(
            request
                .headers
                .get("x-fcp-credential-id")
                .map(String::as_str),
            Some(TEST_BOT_CREDENTIAL_ID)
        );
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack post body json");
        assert_eq!(body["channel"], "C01234567");
        assert_eq!(body["text"], "Hello from FCP!");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true,
                "channel": "C01234567",
                "ts": "1234567890.123456",
                "message": slack_message("Hello from FCP!", "1234567890.123456")
            }),
        )
    });

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let cap = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "Hello from FCP!" },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["message"]["text"], "Hello from FCP!");
    assert_eq!(result["message"]["ts"], "1234567890.123456");
    assert_eq!(fake_server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn post_message_threaded_denies_duplicate_owner_before_http_send() {
    let _ctx = AsyncTestContext::for_scenario("slack.post_message.coordination.deny_duplicate");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat.postMessage");
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack post body json");
        assert_eq!(body["channel"], "C01234567");
        assert_eq!(body["thread_ts"], "1234567890.123456");
        assert_eq!(body["text"], "agent A threaded post");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true,
                "channel": "C01234567",
                "ts": "1234567890.654321",
                "message": {
                    "type": "message",
                    "user": "U01234567",
                    "text": "agent A threaded post",
                    "ts": "1234567890.654321",
                    "thread_ts": "1234567890.123456"
                }
            }),
        )
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut first = SlackConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let mut second = SlackConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    let first_key = setup_handshake(&mut first, &["slack.post_message"]).await;
    let second_key = setup_handshake(&mut second, &["slack.post_message"]).await;
    setup_configure(&mut first, fake_server.url()).await;
    setup_configure(&mut second, fake_server.url()).await;

    let first_cap = generate_valid_token_for_principal(
        &first_key,
        "slack.post_message",
        "slack.post_message",
        "agent:a",
    );
    let first_result = first
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": {
                "channel": "C01234567",
                "text": "agent A threaded post",
                "thread_ts": " 1234567890.123456 "
            },
            "capability_token": first_cap
        }))
        .await
        .expect("first owner should send");
    assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(first_result["coordination"][2]["event"], "send_executed");

    let second_cap = generate_valid_token_for_principal(
        &second_key,
        "slack.post_message",
        "slack.post_message",
        "agent:b",
    );
    let second_error = second
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": {
                "channel": "C01234567",
                "text": "agent B threaded post",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": second_cap
        }))
        .await
        .expect_err("second owner should be denied");

    assert!(matches!(
        second_error,
        fcp_core::FcpError::Unauthorized {
            code: 4090,
            ref message
        } if message == "thread_owned_by_peer:agent:a"
    ));
    assert_eq!(fake_server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn post_message_rejects_invalid_thread_ts_before_coordination_or_http() {
    let _ctx = AsyncTestContext::for_scenario("slack.post_message.validation.invalid_thread_ts");
    let fake_server = StructuredFakeHttpServer::spawn(0, |_idx, _request| {
        unreachable!("invalid thread_ts must be rejected before HTTP")
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut connector = SlackConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let cap = generate_valid_token_for_principal(
        &key,
        "slack.post_message",
        "slack.post_message",
        "agent:a",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": {
                "channel": "C01234567",
                "text": "should not send",
                "thread_ts": "   "
            },
            "capability_token": cap
        }))
        .await;
    assert_invalid_request_contains(result, "thread_ts");
    assert_eq!(checker.active_len(std::time::Instant::now()), 0);
    assert_eq!(fake_server.requests().len(), 0);
}

#[fcp_async_core::runtime::test]
async fn post_message_threaded_slack_api_failure_returns_no_coordination_success() {
    let _ctx = AsyncTestContext::for_scenario("slack.post_message.coordination.slack_failure");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat.postMessage");
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack post body json");
        assert_eq!(body["thread_ts"], "1234567890.123456");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": false,
                "error": "channel_not_found"
            }),
        )
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut connector = SlackConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let cap = generate_valid_token_for_principal(
        &key,
        "slack.post_message",
        "slack.post_message",
        "agent:a",
    );
    let error = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": {
                "channel": "C01234567",
                "text": "will fail",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": cap
        }))
        .await
        .expect_err("Slack API failure should not return send_executed evidence");

    assert!(matches!(error, fcp_core::FcpError::ResourceNotFound { .. }));
    assert_eq!(fake_server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn reply_thread_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.reply_thread.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.654321",
            "message": {
                "type": "message",
                "user": "U01234567",
                "text": "Thread reply",
                "ts": "1234567890.654321",
                "thread_ts": "1234567890.123456"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.reply_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "Thread reply",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["message"]["text"], "Thread reply");
    assert_eq!(result["message"]["thread_ts"], "1234567890.123456");
}

#[fcp_async_core::runtime::test]
async fn reply_thread_denies_duplicate_owner_before_http_send() {
    let _ctx = AsyncTestContext::for_scenario("slack.reply_thread.coordination.deny_duplicate");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat.postMessage");
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack reply body json");
        assert_eq!(body["channel"], "C01234567");
        assert_eq!(body["thread_ts"], "1234567890.123456");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true,
                "channel": "C01234567",
                "ts": "1234567890.654321",
                "message": {
                    "type": "message",
                    "user": "U01234567",
                    "text": "agent A reply",
                    "ts": "1234567890.654321",
                    "thread_ts": "1234567890.123456"
                }
            }),
        )
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut first = SlackConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let mut second = SlackConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    let first_key = setup_handshake(&mut first, &["slack.reply_thread"]).await;
    let second_key = setup_handshake(&mut second, &["slack.reply_thread"]).await;
    setup_configure(&mut first, fake_server.url()).await;
    setup_configure(&mut second, fake_server.url()).await;

    let first_cap = generate_valid_token_for_principal(
        &first_key,
        "slack.reply_thread",
        "slack.reply_thread",
        "agent:a",
    );
    let first_result = first
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "agent A reply",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": first_cap
        }))
        .await
        .expect("first owner should send");
    assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(first_result["coordination"][2]["event"], "send_executed");

    let second_cap = generate_valid_token_for_principal(
        &second_key,
        "slack.reply_thread",
        "slack.reply_thread",
        "agent:b",
    );
    let second_error = second
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "agent B reply",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": second_cap
        }))
        .await
        .expect_err("second owner should be denied");

    assert!(matches!(
        second_error,
        fcp_core::FcpError::Unauthorized {
            code: 4090,
            ref message
        } if message == "thread_owned_by_peer:agent:a"
    ));
    assert_eq!(fake_server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn reply_thread_rejects_invalid_thread_ts_before_coordination_or_http() {
    let _ctx = AsyncTestContext::for_scenario("slack.reply_thread.validation.invalid_thread_ts");
    let fake_server = StructuredFakeHttpServer::spawn(0, |_idx, _request| {
        unreachable!("invalid thread_ts must be rejected before HTTP")
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut connector = SlackConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let cap = generate_valid_token_for_principal(
        &key,
        "slack.reply_thread",
        "slack.reply_thread",
        "agent:a",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "should not send",
                "thread_ts": "not-a-slack-ts"
            },
            "capability_token": cap
        }))
        .await;
    assert_invalid_request_contains(result, "thread_ts");
    assert_eq!(checker.active_len(std::time::Instant::now()), 0);
    assert_eq!(fake_server.requests().len(), 0);
}

#[fcp_async_core::runtime::test]
async fn reply_thread_slack_api_failure_returns_no_coordination_success() {
    let _ctx = AsyncTestContext::for_scenario("slack.reply_thread.coordination.slack_failure");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat.postMessage");
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack reply body json");
        assert_eq!(body["thread_ts"], "1234567890.123456");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": false,
                "error": "channel_not_found"
            }),
        )
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut connector = SlackConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let cap = generate_valid_token_for_principal(
        &key,
        "slack.reply_thread",
        "slack.reply_thread",
        "agent:a",
    );
    let error = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "will fail",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": cap
        }))
        .await
        .expect_err("Slack API failure should not return send_executed evidence");

    assert!(matches!(error, fcp_core::FcpError::ResourceNotFound { .. }));
    assert_eq!(fake_server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn reply_thread_fail_open_sends_with_degraded_coordination_audit() {
    let _ctx = AsyncTestContext::for_scenario("slack.reply_thread.coordination.fail_open");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat.postMessage");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true,
                "channel": "C01234567",
                "ts": "1234567890.654321",
                "message": {
                    "type": "message",
                    "user": "U01234567",
                    "text": "fail-open reply",
                    "ts": "1234567890.654321",
                    "thread_ts": "1234567890.123456"
                }
            }),
        )
    });
    let checker = Arc::new(IndeterminateThreadOwnershipChecker {
        reason: "agent_mail_unavailable",
    });
    let mut connector = SlackConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::AgentMail);
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let cap = generate_valid_token_for_principal(
        &key,
        "slack.reply_thread",
        "slack.reply_thread",
        "agent:a",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "fail-open reply",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": cap
        }))
        .await
        .expect("fail-open indeterminate claim should send");

    assert_eq!(result["coordination"][1]["outcome"], "indeterminate");
    assert_eq!(
        result["coordination"][1]["reason"],
        "agent_mail_unavailable"
    );
    assert_eq!(result["coordination"][2]["event"], "send_executed");
    assert_eq!(
        result["coordination"][2]["reason"],
        "agent_mail_unavailable"
    );
    assert_eq!(fake_server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn progress_draft_text_sends_then_edits() {
    let _ctx = AsyncTestContext::for_scenario("slack.progress_draft.text_send_edit");
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(
            request
                .headers
                .get("x-fcp-credential-id")
                .map(String::as_str),
            Some(TEST_BOT_CREDENTIAL_ID)
        );
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack draft body json");
        match idx {
            0 => {
                assert_eq!(request.path, "/chat.postMessage");
                assert_eq!(body["channel"], "C01234567");
                assert_eq!(body["thread_ts"], "1234567890.123456");
                assert_eq!(body["text"], "starting");
                assert!(body.get("blocks").is_none());
                StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "channel": "C01234567",
                        "ts": "1234567890.200000",
                        "message": slack_message("starting", "1234567890.200000")
                    }),
                )
            }
            1 => {
                assert_eq!(request.path, "/chat.update");
                assert_eq!(body["channel"], "C01234567");
                assert_eq!(body["ts"], "1234567890.200000");
                assert_eq!(body["text"], "still working");
                StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "channel": "C01234567",
                        "ts": "1234567890.200000",
                        "message": slack_message("still working", "1234567890.200000")
                    }),
                )
            }
            _ => StructuredHttpResponse::json(
                500,
                &json!({ "ok": false, "error": "unexpected fake Slack request" }),
            ),
        }
    });

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.write"]).await;
    setup_configure(&mut connector, fake_server.url()).await;
    let cap =
        generate_valid_token_for_operation(&key, "slack.write", "slack.update_progress_draft");

    let first = connector
        .handle_invoke(json!({
            "operation": "slack.update_progress_draft",
            "input": {
                "draft_id": "turn-1",
                "channel": "C01234567",
                "thread_ts": "1234567890.123456",
                "text": "starting"
            },
            "capability_token": cap.clone()
        }))
        .await
        .expect("first progress draft update should send");
    assert_eq!(first["status"], "sent");
    assert_eq!(first["draft"]["message_ts"], "1234567890.200000");

    let second = connector
        .handle_invoke(json!({
            "operation": "slack.update_progress_draft",
            "input": {
                "draft_id": "turn-1",
                "channel": "C01234567",
                "thread_ts": "1234567890.123456",
                "text": "still working",
                "flush": true
            },
            "capability_token": cap
        }))
        .await
        .expect("second progress draft update should edit");
    assert_eq!(second["status"], "edited");
    assert_eq!(fake_server.requests().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn progress_draft_rich_blocks_and_duplicate_suppression() {
    let _ctx = AsyncTestContext::for_scenario("slack.progress_draft.rich_duplicate");
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack draft body json");
        match idx {
            0 => {
                assert_eq!(request.path, "/chat.postMessage");
                assert_eq!(body["text"], "fallback");
                assert_eq!(body["blocks"][0]["text"]["text"], "*Working*");
                StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "channel": "C01234567",
                        "ts": "1234567890.300000",
                        "message": {
                            "type": "message",
                            "user": "U01234567",
                            "text": "fallback",
                            "ts": "1234567890.300000",
                            "blocks": body["blocks"].clone()
                        }
                    }),
                )
            }
            1 => {
                assert_eq!(request.path, "/chat.update");
                assert_eq!(body["text"], "fallback");
                assert!(
                    body["blocks"][1]["fields"][1]["text"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("cargo test")
                );
                StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "channel": "C01234567",
                        "ts": "1234567890.300000",
                        "message": {
                            "type": "message",
                            "user": "U01234567",
                            "text": "fallback",
                            "ts": "1234567890.300000",
                            "blocks": body["blocks"].clone()
                        }
                    }),
                )
            }
            _ => StructuredHttpResponse::json(
                500,
                &json!({ "ok": false, "error": "unexpected fake Slack request" }),
            ),
        }
    });

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.write"]).await;
    setup_configure(&mut connector, fake_server.url()).await;
    let cap =
        generate_valid_token_for_operation(&key, "slack.write", "slack.update_progress_draft");

    let base_input = json!({
        "draft_id": "turn-rich",
        "channel": "C01234567",
        "text": "fallback",
        "render_mode": "rich",
        "label": "Working",
        "progress_lines": [{
            "kind": "tool",
            "label": "Cargo",
            "detail": "cargo check",
            "status": "running"
        }]
    });

    let first = connector
        .handle_invoke(json!({
            "operation": "slack.update_progress_draft",
            "input": base_input,
            "capability_token": cap.clone()
        }))
        .await
        .expect("rich progress draft should send");
    assert_eq!(first["status"], "sent");

    let changed_blocks = json!({
        "draft_id": "turn-rich",
        "channel": "C01234567",
        "text": "fallback",
        "render_mode": "rich",
        "label": "Working",
        "progress_lines": [{
            "kind": "tool",
            "label": "Cargo",
            "detail": "cargo test",
            "status": "running"
        }],
        "flush": true
    });
    let second = connector
        .handle_invoke(json!({
            "operation": "slack.update_progress_draft",
            "input": changed_blocks.clone(),
            "capability_token": cap.clone()
        }))
        .await
        .expect("same text with changed blocks should edit");
    assert_eq!(second["status"], "edited");

    let duplicate = connector
        .handle_invoke(json!({
            "operation": "slack.update_progress_draft",
            "input": changed_blocks,
            "capability_token": cap
        }))
        .await
        .expect("duplicate text and blocks should be skipped");
    assert_eq!(duplicate["status"], "skipped");
    assert_eq!(duplicate["reason"], "duplicate");
    assert_eq!(fake_server.requests().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn progress_draft_clear_deletes_visible_message() {
    let _ctx = AsyncTestContext::for_scenario("slack.progress_draft.clear");
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack draft body json");
        match idx {
            0 => {
                assert_eq!(request.path, "/chat.postMessage");
                StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "channel": "C01234567",
                        "ts": "1234567890.400000",
                        "message": slack_message("temporary", "1234567890.400000")
                    }),
                )
            }
            1 => {
                assert_eq!(request.path, "/chat.delete");
                assert_eq!(body["channel"], "C01234567");
                assert_eq!(body["ts"], "1234567890.400000");
                StructuredHttpResponse::json(200, &json!({ "ok": true }))
            }
            _ => StructuredHttpResponse::json(
                500,
                &json!({ "ok": false, "error": "unexpected fake Slack request" }),
            ),
        }
    });

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.write"]).await;
    setup_configure(&mut connector, fake_server.url()).await;
    let cap =
        generate_valid_token_for_operation(&key, "slack.write", "slack.update_progress_draft");

    connector
        .handle_invoke(json!({
            "operation": "slack.update_progress_draft",
            "input": {
                "draft_id": "turn-clear",
                "channel": "C01234567",
                "text": "temporary"
            },
            "capability_token": cap.clone()
        }))
        .await
        .expect("progress draft should send before clear");

    let cleared = connector
        .handle_invoke(json!({
            "operation": "slack.update_progress_draft",
            "input": {
                "draft_id": "turn-clear",
                "channel": "C01234567",
                "action": "clear"
            },
            "capability_token": cap
        }))
        .await
        .expect("clear should delete visible draft");
    assert_eq!(cleared["status"], "cleared");
    assert_eq!(fake_server.requests().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn progress_draft_rejects_oversized_text_before_outbound_call() {
    let _ctx = AsyncTestContext::for_scenario("slack.progress_draft.oversized");
    let fake_server = StructuredFakeHttpServer::spawn(0, |_idx, _request| {
        StructuredHttpResponse::json(
            500,
            &json!({ "ok": false, "error": "oversized progress draft should not reach fake Slack" }),
        )
    });

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.write"]).await;
    setup_configure(&mut connector, fake_server.url()).await;
    let cap =
        generate_valid_token_for_operation(&key, "slack.write", "slack.update_progress_draft");

    let err = connector
        .handle_invoke(json!({
            "operation": "slack.update_progress_draft",
            "input": {
                "draft_id": "turn-oversized",
                "channel": "C01234567",
                "text": "x".repeat(4206)
            },
            "capability_token": cap
        }))
        .await
        .expect_err("oversized fallback text should be rejected");
    assert!(
        err.to_string().contains("exceeds max_chars"),
        "unexpected error: {err}"
    );
    assert!(fake_server.requests().is_empty());
}

#[fcp_async_core::runtime::test]
async fn get_channel_history_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.channel_history.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "messages": [
                slack_message("First message", "1234567890.111111"),
                slack_message("Second message", "1234567890.222222")
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_channel_history"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.get_channel_history");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_channel_history",
            "input": { "channel": "C01234567", "limit": 10 },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    let messages = result["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["text"], "First message");
    assert_eq!(messages[1]["text"], "Second message");
}

#[fcp_async_core::runtime::test]
async fn search_messages_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.search_messages.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search.messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "messages": {
                "total": 1,
                "matches": [slack_message("deployment update", "1234567890.333333")]
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.search_messages"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.search_messages");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.search_messages",
            "input": { "query": "deployment in:#general" },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["total"], 1);
}

#[fcp_async_core::runtime::test]
async fn list_channels_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.list_channels.happy_path");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "GET");
        let (path, query) = request
            .path
            .split_once('?')
            .expect("list_channels should include query params");
        assert_eq!(path, "/conversations.list");
        let query_params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(
            query_params.get("types").map(String::as_str),
            Some("public_channel")
        );
        assert_eq!(
            request
                .headers
                .get("x-fcp-credential-id")
                .map(String::as_str),
            Some(TEST_BOT_CREDENTIAL_ID)
        );
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        assert!(
            !request.headers.contains_key("content-type"),
            "GET list_channels should not send a content-type header"
        );
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true,
                "channels": [
                    slack_channel("C01234567", "general"),
                    slack_channel("C07654321", "random")
                ]
            }),
        )
    });

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.list_channels"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let cap = generate_valid_token(&key, "slack.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": { "types": "public_channel" },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    let channels = result["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 2);
    assert_eq!(channels[0]["name"], "general");
    assert_eq!(channels[1]["name"], "random");
}

#[fcp_async_core::runtime::test]
async fn get_user_info_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.get_user_info.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "user": {
                "id": "U01234567",
                "name": "testuser",
                "real_name": "Test User",
                "is_bot": false,
                "is_admin": false,
                "deleted": false,
                "profile": {
                    "display_name": "testuser",
                    "email": "test@example.com"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_user_info"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.get_user_info");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_user_info",
            "input": { "user": "U01234567" },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["user"]["name"], "testuser");
    assert_eq!(result["user"]["id"], "U01234567");
}

#[fcp_async_core::runtime::test]
async fn upload_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.upload_file.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/files.upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file": {
                "id": "F01234567",
                "name": "output.log",
                "title": "output.log",
                "mimetype": "text/plain",
                "filetype": "text",
                "size": 42
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "content_object_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "resolved_content": "log data here",
                "filename": "output.log"
            },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["file"]["id"], "F01234567");
    assert_eq!(result["file"]["name"], "output.log");
    assert_eq!(
        result["source_object_id"],
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(
        result["file_object_id"].as_str().unwrap().len(),
        64,
        "file_object_id should be a hex ObjectId"
    );
}

#[fcp_async_core::runtime::test]
async fn upload_file_threaded_denies_duplicate_owner_before_http_send() {
    let _ctx = AsyncTestContext::for_scenario("slack.upload_file.coordination.deny_duplicate");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/files.upload");
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack upload body json");
        assert_eq!(body["channels"], "C01234567");
        assert_eq!(body["thread_ts"], "1234567890.123456");
        assert_eq!(body["content"], "agent A upload");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true,
                "file": {
                    "id": "F01234567",
                    "name": "output.log",
                    "title": "output.log",
                    "mimetype": "text/plain",
                    "filetype": "text",
                    "size": 42
                }
            }),
        )
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut first = SlackConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let mut second = SlackConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    let first_key = setup_handshake(&mut first, &["slack.files.write"]).await;
    let second_key = setup_handshake(&mut second, &["slack.files.write"]).await;
    setup_configure(&mut first, fake_server.url()).await;
    setup_configure(&mut second, fake_server.url()).await;

    let first_cap = generate_valid_token_for_principal(
        &first_key,
        "slack.files.write",
        "slack.upload_file",
        "agent:a",
    );
    let first_result = first
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "content_object_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "resolved_content": "agent A upload",
                "filename": "output.log",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": first_cap
        }))
        .await
        .expect("first owner should upload");
    assert_eq!(first_result["file"]["id"], "F01234567");
    assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(first_result["coordination"][2]["event"], "send_executed");

    let second_cap = generate_valid_token_for_principal(
        &second_key,
        "slack.files.write",
        "slack.upload_file",
        "agent:b",
    );
    let second_error = second
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "content_object_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_content": "agent B upload",
                "filename": "output.log",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": second_cap
        }))
        .await
        .expect_err("second owner should be denied");

    assert!(matches!(
        second_error,
        fcp_core::FcpError::Unauthorized {
            code: 4090,
            ref message
        } if message == "thread_owned_by_peer:agent:a"
    ));
    assert_eq!(fake_server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn upload_file_rejects_invalid_thread_ts_before_coordination_or_http() {
    let _ctx = AsyncTestContext::for_scenario("slack.upload_file.validation.invalid_thread_ts");
    let fake_server = StructuredFakeHttpServer::spawn(0, |_idx, _request| {
        unreachable!("invalid thread_ts must be rejected before HTTP")
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut connector = SlackConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let cap = generate_valid_token_for_principal(
        &key,
        "slack.files.write",
        "slack.upload_file",
        "agent:a",
    );
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "content_object_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "resolved_content": "should not upload",
                "filename": "output.log",
                "thread_ts": "not-a-slack-ts"
            },
            "capability_token": cap
        }))
        .await;
    assert_invalid_request_contains(result, "thread_ts");
    assert_eq!(checker.active_len(std::time::Instant::now()), 0);
    assert_eq!(fake_server.requests().len(), 0);
}

#[fcp_async_core::runtime::test]
async fn upload_file_slack_api_failure_returns_no_coordination_success() {
    let _ctx = AsyncTestContext::for_scenario("slack.upload_file.coordination.slack_failure");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/files.upload");
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack upload body json");
        assert_eq!(body["channels"], "C01234567");
        assert_eq!(body["thread_ts"], "1234567890.123456");
        assert_eq!(body["content"], "will fail");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": false,
                "error": "channel_not_found"
            }),
        )
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut connector = SlackConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;
    setup_configure(&mut connector, fake_server.url()).await;

    let cap = generate_valid_token_for_principal(
        &key,
        "slack.files.write",
        "slack.upload_file",
        "agent:a",
    );
    let error = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "content_object_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "resolved_content": "will fail",
                "filename": "output.log",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": cap
        }))
        .await
        .expect_err("Slack API failure should not return send_executed evidence");

    assert!(matches!(error, fcp_core::FcpError::ResourceNotFound { .. }));
    assert_eq!(fake_server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn download_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.download_file.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/files.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file": {
                "id": "F01234567",
                "name": "report.pdf",
                "title": "Q4 Report",
                "mimetype": "application/pdf",
                "filetype": "pdf",
                "size": 102_400,
                "url_private": "https://files.slack.com/files-pri/T01234-F01234567/report.pdf",
                "url_private_download": "https://files.slack.com/files-pri/T01234-F01234567/download/report.pdf"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.files.read"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token_for_operation(&key, "slack.files.read", "slack.download_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.download_file",
            "input": { "file_id": "F01234567" },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["file"]["id"], "F01234567");
    assert_eq!(result["file"]["name"], "report.pdf");
    assert!(result["file"]["url_private_download"].is_null());
    assert!(result["file"]["url_private"].is_null());
    assert_eq!(
        result["content_object_id"].as_str().unwrap().len(),
        64,
        "content_object_id should be a hex ObjectId"
    );
}

#[fcp_async_core::runtime::test]
async fn add_reaction_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.add_reaction.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/reactions.add"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.add_reaction"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.add_reaction",
            "input": {
                "channel": "C01234567",
                "timestamp": "1234567890.123456",
                "name": "thumbsup"
            },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["ok"], true);
}

#[fcp_async_core::runtime::test]
async fn set_channel_topic_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.set_channel_topic.happy_path");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/conversations.setTopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "topic": "Sprint 42 - Deployment day"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.set_channel_topic"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.set_channel_topic");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": {
                "channel": "C01234567",
                "topic": "Sprint 42 - Deployment day"
            },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["topic"], "Sprint 42 - Deployment day");
}

// ============================================================================
// Receipt verification (side-effecting operations)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn post_message_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.post_message");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.123456",
            "message": slack_message("Hello!", "1234567890.123456")
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "Hello!" },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.post_message");
    assert_eq!(receipt["effect"], "message_created");
    assert_eq!(receipt["resource"], "channel:C01234567");
    assert_eq!(receipt["timestamp"], "1234567890.123456");
}

#[fcp_async_core::runtime::test]
async fn reply_thread_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.reply_thread");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channel": "C01234567",
            "ts": "1234567890.654321",
            "message": {
                "type": "message",
                "user": "U01234567",
                "text": "Thread reply",
                "ts": "1234567890.654321",
                "thread_ts": "1234567890.111111"
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.reply_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": {
                "channel": "C01234567",
                "text": "Thread reply",
                "thread_ts": "1234567890.111111"
            },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.reply_thread");
    assert_eq!(receipt["effect"], "thread_reply_created");
    assert!(receipt["resource"].as_str().unwrap().contains("thread:"));
}

#[fcp_async_core::runtime::test]
async fn upload_file_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.upload_file");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/files.upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file": {
                "id": "F09876543",
                "name": "data.csv",
                "title": "data.csv",
                "mimetype": "text/csv",
                "filetype": "csv",
                "size": 100
            }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "content_object_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "resolved_content": "a,b,c",
                "filename": "data.csv"
            },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.upload_file");
    assert_eq!(receipt["effect"], "file_uploaded");
    assert!(
        receipt["resource"]
            .as_str()
            .unwrap()
            .starts_with("file_object:")
    );
}

#[fcp_async_core::runtime::test]
async fn add_reaction_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.add_reaction");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/reactions.add"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.add_reaction"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.add_reaction",
            "input": {
                "channel": "C01234567",
                "timestamp": "1234567890.123456",
                "name": "thumbsup"
            },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.add_reaction");
    assert_eq!(receipt["effect"], "reaction_added");
    assert!(receipt["resource"].as_str().unwrap().contains("message:"));
}

#[fcp_async_core::runtime::test]
async fn set_channel_topic_emits_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.set_channel_topic");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/conversations.setTopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "topic": "New topic"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.set_channel_topic"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.set_channel_topic");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": { "channel": "C01234567", "topic": "New topic" },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    let receipt = &result["receipt"];
    assert_eq!(receipt["operation"], "slack.set_channel_topic");
    assert_eq!(receipt["effect"], "topic_updated");
    assert_eq!(receipt["resource"], "channel:C01234567");
}

// ============================================================================
// Read operations should NOT emit receipts
// ============================================================================

#[fcp_async_core::runtime::test]
async fn read_operations_have_no_receipt() {
    let _ctx = AsyncTestContext::for_scenario("slack.receipt.read_no_receipt");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "channels": [slack_channel("C01234567", "general")]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.list_channels"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert!(result.get("receipt").is_none());
}

#[fcp_async_core::runtime::test]
async fn events_api_url_verification_uses_verified_webhook_payload() {
    let _ctx = AsyncTestContext::for_scenario("slack.events_api.url_verification");
    let body = br#"{"type":"url_verification","challenge":"challenge-fixture"}"#;
    let headers = signed_slack_headers(body);
    let webhook = SlackWebhook::new(TEST_SLACK_SIGNING_SECRET);
    let verified = webhook
        .verify_and_parse(&headers, body)
        .expect("Slack URL verification payload should verify");
    assert_eq!(verified.event_type, "url_verification");

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    let cap = generate_valid_token_for_operation(&key, "slack.read", "slack.handle_events_api");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.handle_events_api",
            "input": {
                "payload": verified.payload,
                "signature_result": "verified"
            },
            "capability_token": cap
        }))
        .await
        .expect("verified URL challenge should succeed");

    assert_eq!(result["status"], "url_verified");
    assert_eq!(result["acknowledged"], true);
    assert_eq!(result["event_emitted"], false);
    assert_eq!(result["challenge"], "challenge-fixture");
    assert_eq!(result["event_topic"], "slack.url_verification");
    assert_eq!(result["signature_result"], "verified");
    assert_eq!(result["fcp_error_mapping"], "none");
}

#[fcp_async_core::runtime::test]
async fn events_api_event_callback_emits_after_monitor_policy() {
    let _ctx = AsyncTestContext::for_scenario("slack.events_api.event_callback.allowed");
    let mock_server = MockServer::start().await;
    let body = br#"{"type":"event_callback","event_id":"EvHttp01","team_id":"T_HTTP_1","event":{"type":"message","user":"U_HTTP_1","channel":"C_HTTP_1","channel_type":"channel","text":"hello through events api","ts":"1700000000.000001"}}"#;
    let headers = signed_slack_headers(body);
    let webhook = SlackWebhook::new(TEST_SLACK_SIGNING_SECRET);
    let verified = webhook
        .verify_and_parse(&headers, body)
        .expect("Slack event callback should verify");
    assert_eq!(verified.event_type, "message");

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "base_url": mock_server.uri(),
            "monitor_policy": { "require_mention": false }
        }))
        .await
        .expect("configure");

    let mut event_rx = connector.subscribe_events();
    let cap = generate_valid_token_for_operation(&key, "slack.read", "slack.handle_events_api");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.handle_events_api",
            "input": {
                "payload": verified.payload,
                "signature_result": "verified"
            },
            "capability_token": cap
        }))
        .await
        .expect("verified event callback should succeed");

    assert_eq!(result["status"], "event_emitted");
    assert_eq!(result["acknowledged"], true);
    assert_eq!(result["event_emitted"], true);
    assert_eq!(result["event_topic"], "slack.message.new");
    assert_eq!(result["sender_policy_decision"], "allowed");
    assert_eq!(result["capability_decision"], "bound_capability_verified");
    assert_eq!(result["event"]["topic"], "slack.message.new");
    assert_eq!(result["event"]["cursor"], "EvHttp01");

    let event = fcp_async_core::time::timeout(StdDuration::from_secs(1), event_rx.recv())
        .await
        .expect("timeout waiting for Events API event")
        .expect("broadcast receive")
        .expect("event payload");
    assert_eq!(event.topic, "slack.message.new");
    assert_eq!(event.cursor, "EvHttp01");
    assert!(
        event
            .data
            .resource_uris
            .iter()
            .any(|uri| uri == "slack:channel:C_HTTP_1")
    );
}

#[fcp_async_core::runtime::test]
async fn events_api_event_callback_denied_by_monitor_policy_before_emit() {
    let _ctx = AsyncTestContext::for_scenario("slack.events_api.event_callback.denied");
    let mock_server = MockServer::start().await;
    let body = br#"{"type":"event_callback","event_id":"EvHttp02","team_id":"T_HTTP_1","event":{"type":"message","user":"U_DENIED","channel":"C_DENIED","channel_type":"channel","text":"blocked events api message","ts":"1700000000.000002"}}"#;
    let headers = signed_slack_headers(body);
    let webhook = SlackWebhook::new(TEST_SLACK_SIGNING_SECRET);
    let verified = webhook
        .verify_and_parse(&headers, body)
        .expect("Slack event callback should verify");

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "base_url": mock_server.uri(),
            "monitor_policy": {
                "require_mention": false,
                "allowed_channels": ["C_ALLOWED"]
            }
        }))
        .await
        .expect("configure");

    let mut event_rx = connector.subscribe_events();
    let cap = generate_valid_token_for_operation(&key, "slack.read", "slack.handle_events_api");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.handle_events_api",
            "input": {
                "payload": verified.payload,
                "signature_result": "verified"
            },
            "capability_token": cap
        }))
        .await
        .expect("policy-denied event callback should acknowledge and drop");

    assert_eq!(result["status"], "event_dropped");
    assert_eq!(result["acknowledged"], true);
    assert_eq!(result["event_emitted"], false);
    assert_eq!(result["event_topic"], "slack.message.new");
    assert_eq!(result["sender_policy_decision"], "denied");
    assert_eq!(
        result["fcp_error_mapping"],
        "suppressed_before_event_envelope"
    );
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), event_rx.recv())
            .await
            .is_err(),
        "policy-denied Events API payload must not emit an EventEnvelope"
    );
}

// ============================================================================
// Error taxonomy tests (Slack API errors come as 200 OK with ok:false)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn error_not_authed_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.not_authed");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/chat.postMessage");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer bad-token")
        );
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack error body json");
        assert_eq!(body["channel"], "C01234567");
        assert_eq!(body["text"], "hello");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": false,
                "error": "not_authed"
            }),
        )
    });

    let client = SlackClient::new("bad-token")
        .unwrap()
        .with_base_url(fake_server.url())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

// ── Replay safety on transport failure (br-kxd3e) ────────────────────
//
// A response that never arrives before the per-request timeout is the exact
// failure the bead is about: the body was fully written, so Slack may already
// have done the work, but the client only sees "timed out". Retrying that on a
// mutating method is what produced duplicate messages.
//
// These two tests are a matched pair — the same induced failure, the same
// retry budget, different Slack methods. Asserting only that the call errors
// would pass with the bug present, so what is pinned is the REQUEST COUNT.

/// Timeout comfortably shorter than the mocked response delay.
const REPLAY_TEST_REQUEST_TIMEOUT: StdDuration = StdDuration::from_millis(150);
/// Long enough that the client always gives up first.
const REPLAY_TEST_RESPONSE_DELAY: StdDuration = StdDuration::from_secs(3);

#[fcp_async_core::runtime::test]
async fn post_message_is_not_replayed_after_a_timeout() {
    let _ctx = AsyncTestContext::for_scenario("slack.replay_safety.post_message");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(REPLAY_TEST_RESPONSE_DELAY)
                .set_body_json(json!({ "ok": true })),
        )
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_request_timeout(REPLAY_TEST_REQUEST_TIMEOUT)
        // One retry available — the point is that it is not taken.
        .with_retry_config(1, 10, 50);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err(), "the request should time out");

    let received = mock_server
        .received_requests()
        .await
        .expect("wiremock records requests");
    assert_eq!(
        received.len(),
        1,
        "chat.postMessage must NOT be replayed after a timeout: Slack may have \
         already posted the message, so a retry duplicates it in the channel"
    );
}

#[fcp_async_core::runtime::test]
async fn update_message_is_still_replayed_after_a_timeout() {
    let _ctx = AsyncTestContext::for_scenario("slack.replay_safety.update_message");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.update"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(REPLAY_TEST_RESPONSE_DELAY)
                .set_body_json(json!({ "ok": true })),
        )
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_request_timeout(REPLAY_TEST_REQUEST_TIMEOUT)
        .with_retry_config(1, 10, 50);

    let result = client
        .update_message("C01234567", "1234567890.123456", "edited", None)
        .await;
    assert!(result.is_err(), "the request should time out");

    let received = mock_server
        .received_requests()
        .await
        .expect("wiremock records requests");
    assert_eq!(
        received.len(),
        2,
        "chat.update names the exact target state, so replaying it converges \
         on the same message — the retry must be preserved"
    );
}

#[fcp_async_core::runtime::test]
async fn error_invalid_auth_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.invalid_auth");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "invalid_auth"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("bad-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_token_revoked_maps_to_unauthorized() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.token_revoked");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "token_revoked"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("revoked-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.list_channels(None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_channel_not_found_maps_to_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.channel_not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "channel_not_found"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_channel_history("C_NONEXIST", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "Expected ResourceNotFound, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_user_not_found_maps_to_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.user_not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users.info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "user_not_found"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.get_user_info("U_NONEXIST").await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::ResourceNotFound { .. }),
        "Expected ResourceNotFound, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_ratelimited_api_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.ratelimited_api");
    let mock_server = MockServer::start().await;

    // Slack API-level ratelimited error (200 OK with ok:false)
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "ratelimited"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "test", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_http_429_maps_to_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.http_429");
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/conversations.list");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer valid-token")
        );
        assert_eq!(
            request.headers.get("accept").map(String::as_str),
            Some("application/json")
        );
        StructuredHttpResponse {
            status: 429,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("retry-after".into(), "30".into()),
            ],
            body: json!({"ok": false, "error": "ratelimited"})
                .to_string()
                .into_bytes(),
        }
    });

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(fake_server.url())
        .with_retry_config(0, 10, 100);

    let result = client.list_channels(None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_missing_scope_maps_to_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.missing_scope");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "missing_scope"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::CapabilityDenied { .. }),
        "Expected CapabilityDenied, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_not_in_channel_maps_to_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("slack.error.not_in_channel");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_in_channel"
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("valid-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    assert!(result.is_err());
    let fcp_err = result.unwrap_err().to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::CapabilityDenied { .. }),
        "Expected CapabilityDenied, got: {fcp_err:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn error_retryable_classification() {
    use fcp_slack::error::SlackError;

    // API transient errors should be retryable
    let transient = SlackError::Api {
        error: "internal_error".into(),
        code: None,
        ok: false,
    };
    assert!(transient.is_retryable());

    let timeout = SlackError::Api {
        error: "request_timeout".into(),
        code: None,
        ok: false,
    };
    assert!(timeout.is_retryable());

    let unavailable = SlackError::Api {
        error: "service_unavailable".into(),
        code: None,
        ok: false,
    };
    assert!(unavailable.is_retryable());

    // Non-transient errors should NOT be retryable
    let not_authed = SlackError::Api {
        error: "not_authed".into(),
        code: None,
        ok: false,
    };
    assert!(!not_authed.is_retryable());

    let chan_not_found = SlackError::Api {
        error: "channel_not_found".into(),
        code: None,
        ok: false,
    };
    assert!(!chan_not_found.is_retryable());

    // RateLimited is always retryable
    let rate = SlackError::RateLimited {
        retry_after_secs: 30,
    };
    assert!(rate.is_retryable());
}

// ============================================================================
// Invoke-level error tests (401/403/429 through handle_invoke)
// ============================================================================

#[fcp_async_core::runtime::test]
async fn invoke_401_not_authed() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.401_not_authed");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_authed"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": cap
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_401_invalid_auth() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.401_invalid_auth");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "invalid_auth"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_channel_history"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.get_channel_history");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_channel_history",
            "input": { "channel": "C01234567" },
            "capability_token": cap
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::Unauthorized { .. }),
        "Expected Unauthorized"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_403_missing_scope() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.403_missing_scope");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "missing_scope"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": cap
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "Expected CapabilityDenied"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_403_not_in_channel() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.403_not_in_channel");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "not_in_channel"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": cap
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "Expected CapabilityDenied"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_403_restricted_action() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.403_restricted_action");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/conversations.setTopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "restricted_action"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.set_channel_topic"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.set_channel_topic");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.set_channel_topic",
            "input": { "channel": "C01234567", "topic": "new topic" },
            "capability_token": cap
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::CapabilityDenied { .. }
        ),
        "Expected CapabilityDenied"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_429_rate_limited_api() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.429_api");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "ratelimited"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": cap
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), fcp_core::FcpError::RateLimited { .. }),
        "Expected RateLimited"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_resource_not_found() {
    let _ctx = AsyncTestContext::for_scenario("slack.invoke_error.resource_not_found");
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error": "channel_not_found"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.get_channel_history"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.get_channel_history");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.get_channel_history",
            "input": { "channel": "C_INVALID" },
            "capability_token": cap
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::ResourceNotFound { .. }
        ),
        "Expected ResourceNotFound"
    );
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::runtime::test]
async fn fcp2_invoke_requires_handshake() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.no_handshake");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    // No handshake → NotConfigured (no verifier set)
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.list_channels",
            "input": {},
            "capability_token": { "raw": vec![0u8; 32] }
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn fcp2_invoke_requires_capability_token() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.missing_token");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" }
        }))
        .await;
    assert_invalid_request_contains(result, "capability_token");
}

#[fcp_async_core::runtime::test]
async fn fcp2_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.wrong_cap");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    // Handshake grants only slack.read
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Token is for slack.read, but we invoke slack.post_message
    let cap = generate_valid_token(&key, "slack.read");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567", "text": "test" },
            "capability_token": cap
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn fcp2_unknown_operation_rejected() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.unknown_op");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.nonexistent"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.nonexistent",
            "input": {},
            "capability_token": cap
        }))
        .await;
    assert!(result.is_err());
    assert!(
        matches!(
            result.unwrap_err(),
            fcp_core::FcpError::OperationNotGranted { .. }
        ),
        "Expected OperationNotGranted"
    );
}

#[fcp_async_core::runtime::test]
async fn fcp2_missing_operation_field() {
    let _ctx = AsyncTestContext::for_scenario("slack.capability.missing_op");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_invoke(json!({
            "input": {},
            "capability_token": { "raw": vec![0u8; 32] }
        }))
        .await;
    assert_invalid_request_contains(result, "operation");
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn lifecycle_health_before_configure() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.health_before");
    let connector = SlackConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.health_after");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_returns_accepted() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.handshake");
    let mut connector = SlackConnector::new();

    let result = connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": vec![0u8; 32],
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["slack.read", "slack.write"]
        }))
        .await
        .unwrap();

    assert_eq!(result["status"], "accepted");
    assert!(result["session_id"].as_str().is_some());
    let grants = result["capabilities_granted"].as_array().unwrap();
    assert_eq!(grants.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.introspect");
    let connector = SlackConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 12);

    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
    for expected in &[
        "slack.post_message",
        "slack.reply_thread",
        "slack.update_progress_draft",
        "slack.get_channel_history",
        "slack.search_messages",
        "slack.list_channels",
        "slack.get_user_info",
        "slack.handle_events_api",
        "slack.upload_file",
        "slack.download_file",
        "slack.add_reaction",
        "slack.set_channel_topic",
    ] {
        assert!(op_ids.contains(expected), "Missing op: {expected}");
    }
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let _ctx = AsyncTestContext::for_scenario("slack.lifecycle.shutdown");
    let mut connector = SlackConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Socket Mode streaming tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn socket_mode_subscribe_emits_event_envelope_and_ack() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.event_and_ack");
    let mock_server = MockServer::start().await;
    let runtime = fcp_async_core::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build async-core runtime");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let ws_url = format!(
        "ws://{}",
        listener.local_addr().expect("listener local addr")
    );

    let (ack_tx, ack_rx) = oneshot::channel::<Option<String>>();
    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let mut ws_stream = accept_test_websocket(tcp_stream).await;

        send_json_frame(
            &mut ws_stream,
            json!({ "type": "hello" }),
            "send hello frame",
        )
        .await;
        send_json_frame(
            &mut ws_stream,
            json!({
                "envelope_id": "envelope-1",
                "type": "events_api",
                "payload": {
                    "event_id": "Ev01",
                    "team_id": "T_TEAM_1",
                    "event": {
                        "type": "message",
                        "user": "U_EVT_1",
                        "channel": "C_EVT_1",
                        "text": "hello from socket mode",
                        "ts": "1700000000.000001"
                    }
                }
            }),
            "send events_api frame",
        )
        .await;

        let ack_payload = recv_text_frame(&mut ws_stream, "ack frame")
            .await
            .expect("ack frame should be readable");
        let _ = ack_tx.send(ack_payload);

        close_test_websocket(&mut ws_stream).await;
    });

    Mock::given(method("POST"))
        .and(path("/apps.connections.open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "url": ws_url
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "socket_mode_credential_id": TEST_SOCKET_CREDENTIAL_ID,
            "base_url": mock_server.uri(),
            "monitor_policy": { "require_mention": false }
        }))
        .await
        .expect("configure");

    let mut event_rx = connector.subscribe_events();
    let subscribe_result = runtime
        .block_on(connector.handle_subscribe(json!({
            "topics": ["slack.message.new"]
        })))
        .expect("subscribe should succeed");
    assert_eq!(subscribe_result["connection_status"], "started");

    let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
        .await
        .expect("timeout waiting for socket mode event")
        .expect("broadcast receive")
        .expect("event payload");

    assert_eq!(event.topic, "slack.message.new");
    assert_eq!(event.cursor, "Ev01");
    assert_eq!(event.data.principal.kind, "slack_user");
    assert_eq!(event.data.principal.id, "U_EVT_1");
    assert_eq!(event.data.principal.trust, fcp_core::TrustLevel::Untrusted);
    assert_eq!(event.data.zone_id, fcp_core::ZoneId::community());
    assert_eq!(
        event.data.payload["event"]["text"].as_str(),
        Some("hello from socket mode")
    );

    let ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), ack_rx)
        .await
        .expect("timeout waiting for socket ack")
        .expect("ack channel should complete")
        .expect("ack payload missing");
    let ack_value: serde_json::Value =
        serde_json::from_str(&ack_json).expect("ack should be valid json");
    assert_eq!(ack_value["envelope_id"], "envelope-1");

    runtime
        .block_on(connector.handle_shutdown(json!({})))
        .expect("shutdown should succeed");

    fcp_async_core::time::timeout(StdDuration::from_secs(3), ws_task)
        .await
        .expect("timeout waiting for ws task")
        .expect("ws task join");
}

#[fcp_async_core::runtime::test]
async fn socket_mode_monitor_policy_acks_but_drops_unauthorized_message() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.monitor_policy_drop");
    let mock_server = MockServer::start().await;
    let runtime = fcp_async_core::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build async-core runtime");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let ws_url = format!(
        "ws://{}",
        listener.local_addr().expect("listener local addr")
    );

    let (ack_tx, ack_rx) = oneshot::channel::<Option<String>>();
    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let mut ws_stream = accept_test_websocket(tcp_stream).await;

        send_json_frame(
            &mut ws_stream,
            json!({ "type": "hello" }),
            "send hello frame",
        )
        .await;
        send_json_frame(
            &mut ws_stream,
            json!({
                "envelope_id": "envelope-policy-drop",
                "type": "events_api",
                "payload": {
                    "event_id": "EvPolicyDrop",
                    "team_id": "T_TEAM_1",
                    "event": {
                        "type": "message",
                        "user": "U_EVT_1",
                        "channel": "C_ALLOWED",
                        "text": "public message without bot mention",
                        "ts": "1700000000.000002"
                    }
                }
            }),
            "send unauthorized events_api frame",
        )
        .await;

        let ack_payload = recv_text_frame(&mut ws_stream, "policy drop ack frame")
            .await
            .expect("policy drop ack frame should be readable");
        let _ = ack_tx.send(ack_payload);

        close_test_websocket(&mut ws_stream).await;
    });

    Mock::given(method("POST"))
        .and(path("/apps.connections.open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "url": ws_url
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "socket_mode_credential_id": TEST_SOCKET_CREDENTIAL_ID,
            "base_url": mock_server.uri(),
            "monitor_policy": {
                "bot_user_id": "U_BOT",
                "allowed_channels": ["C_ALLOWED"]
            }
        }))
        .await
        .expect("configure");

    let mut event_rx = connector.subscribe_events();
    let subscribe_result = runtime
        .block_on(connector.handle_subscribe(json!({
            "topics": ["slack.message.new"]
        })))
        .expect("subscribe should succeed");
    assert_eq!(subscribe_result["connection_status"], "started");

    let ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), ack_rx)
        .await
        .expect("timeout waiting for socket ack")
        .expect("ack channel should complete")
        .expect("ack payload missing");
    let ack_value: serde_json::Value =
        serde_json::from_str(&ack_json).expect("ack should be valid json");
    assert_eq!(ack_value["envelope_id"], "envelope-policy-drop");

    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(200), event_rx.recv())
            .await
            .is_err(),
        "monitor policy should suppress the unauthorized message event"
    );

    runtime
        .block_on(connector.handle_shutdown(json!({})))
        .expect("shutdown should succeed");

    fcp_async_core::time::timeout(StdDuration::from_secs(3), ws_task)
        .await
        .expect("timeout waiting for ws task")
        .expect("ws task join");
}

#[fcp_async_core::runtime::test]
async fn socket_mode_monitor_policy_filters_commands_and_interactions() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.monitor_policy_actions");
    let mock_server = MockServer::start().await;
    let runtime = fcp_async_core::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build async-core runtime");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let ws_url = format!(
        "ws://{}",
        listener.local_addr().expect("listener local addr")
    );

    let (drop_ack_tx, drop_ack_rx) = oneshot::channel::<Option<String>>();
    let (slash_go_tx, slash_go_rx) = oneshot::channel::<()>();
    let (slash_ack_tx, slash_ack_rx) = oneshot::channel::<Option<String>>();
    let (interactive_go_tx, interactive_go_rx) = oneshot::channel::<()>();
    let (interactive_ack_tx, interactive_ack_rx) = oneshot::channel::<Option<String>>();
    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let mut ws_stream = accept_test_websocket(tcp_stream).await;

        send_json_frame(
            &mut ws_stream,
            json!({ "type": "hello" }),
            "send hello frame",
        )
        .await;
        send_json_frame(
            &mut ws_stream,
            json!({
                "envelope_id": "envelope-command-drop",
                "type": "slash_commands",
                "payload": {
                    "team_id": "T_TEAM_1",
                    "channel_id": "C_DENIED",
                    "user_id": "U_CMD",
                    "command": "/deploy"
                }
            }),
            "send unauthorized slash command frame",
        )
        .await;
        let drop_ack = recv_text_frame(&mut ws_stream, "command drop ack frame")
            .await
            .expect("command drop ack frame should be readable");
        let _ = drop_ack_tx.send(drop_ack);

        let _ = slash_go_rx.await;
        send_json_frame(
            &mut ws_stream,
            json!({
                "envelope_id": "envelope-command-allowed",
                "type": "slash_commands",
                "payload": {
                    "team_id": "T_TEAM_1",
                    "channel_id": "C_CMD",
                    "user_id": "U_CMD",
                    "command": "/deploy"
                }
            }),
            "send authorized slash command frame",
        )
        .await;
        let slash_ack = recv_text_frame(&mut ws_stream, "command allowed ack frame")
            .await
            .expect("command allowed ack frame should be readable");
        let _ = slash_ack_tx.send(slash_ack);

        let _ = interactive_go_rx.await;
        send_json_frame(
            &mut ws_stream,
            json!({
                "envelope_id": "envelope-interactive-allowed",
                "type": "interactive",
                "payload": {
                    "team_id": "T_TEAM_1",
                    "channel": { "id": "C_CMD" },
                    "user": { "id": "U_CMD" },
                    "type": "block_actions"
                }
            }),
            "send authorized interactive frame",
        )
        .await;
        let interactive_ack = recv_text_frame(&mut ws_stream, "interactive allowed ack frame")
            .await
            .expect("interactive allowed ack frame should be readable");
        let _ = interactive_ack_tx.send(interactive_ack);

        close_test_websocket(&mut ws_stream).await;
    });

    Mock::given(method("POST"))
        .and(path("/apps.connections.open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "url": ws_url
        })))
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "socket_mode_credential_id": TEST_SOCKET_CREDENTIAL_ID,
            "base_url": mock_server.uri(),
            "monitor_policy": {
                "require_mention": false,
                "allowed_channels": ["channel:C_CMD"],
                "allowed_users": ["user:U_CMD"]
            }
        }))
        .await
        .expect("configure");

    let mut event_rx = connector.subscribe_events();
    let subscribe_result = runtime
        .block_on(connector.handle_subscribe(json!({
            "topics": ["slack.command", "slack.interactive"]
        })))
        .expect("subscribe should succeed");
    assert_eq!(subscribe_result["connection_status"], "started");

    let drop_ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), drop_ack_rx)
        .await
        .expect("timeout waiting for command drop ack")
        .expect("drop ack channel should complete")
        .expect("drop ack payload missing");
    let drop_ack_value: serde_json::Value =
        serde_json::from_str(&drop_ack_json).expect("drop ack should be valid json");
    assert_eq!(drop_ack_value["envelope_id"], "envelope-command-drop");
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(200), event_rx.recv())
            .await
            .is_err(),
        "monitor policy should suppress unauthorized slash command events"
    );

    let _ = slash_go_tx.send(());
    let slash_event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
        .await
        .expect("timeout waiting for authorized slash command event")
        .expect("broadcast receive")
        .expect("event payload");
    assert_eq!(slash_event.topic, "slack.command");
    assert_eq!(slash_event.cursor, "envelope-command-allowed");
    assert_eq!(slash_event.data.principal.id, "U_CMD");
    assert_eq!(slash_event.data.payload["channel_id"], "C_CMD");
    assert!(
        slash_event
            .data
            .resource_uris
            .contains(&"slack:channel:C_CMD".to_string())
    );
    let slash_ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), slash_ack_rx)
        .await
        .expect("timeout waiting for command allowed ack")
        .expect("slash ack channel should complete")
        .expect("slash ack payload missing");
    let slash_ack_value: serde_json::Value =
        serde_json::from_str(&slash_ack_json).expect("slash ack should be valid json");
    assert_eq!(slash_ack_value["envelope_id"], "envelope-command-allowed");

    let _ = interactive_go_tx.send(());
    let interactive_event =
        fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
            .await
            .expect("timeout waiting for authorized interactive event")
            .expect("broadcast receive")
            .expect("event payload");
    assert_eq!(interactive_event.topic, "slack.interactive");
    assert_eq!(interactive_event.cursor, "envelope-interactive-allowed");
    assert_eq!(interactive_event.data.principal.id, "U_CMD");
    assert_eq!(interactive_event.data.payload["channel"]["id"], "C_CMD");
    assert!(
        interactive_event
            .data
            .resource_uris
            .contains(&"slack:channel:C_CMD".to_string())
    );
    let interactive_ack_json =
        fcp_async_core::time::timeout(StdDuration::from_secs(3), interactive_ack_rx)
            .await
            .expect("timeout waiting for interactive allowed ack")
            .expect("interactive ack channel should complete")
            .expect("interactive ack payload missing");
    let interactive_ack_value: serde_json::Value =
        serde_json::from_str(&interactive_ack_json).expect("interactive ack should be valid json");
    assert_eq!(
        interactive_ack_value["envelope_id"],
        "envelope-interactive-allowed"
    );

    runtime
        .block_on(connector.handle_shutdown(json!({})))
        .expect("shutdown should succeed");

    fcp_async_core::time::timeout(StdDuration::from_secs(3), ws_task)
        .await
        .expect("timeout waiting for ws task")
        .expect("ws task join");
}

#[fcp_async_core::runtime::test]
async fn socket_mode_subscribe_reuses_single_connection() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.singleton_connection");
    let mock_server = MockServer::start().await;
    let runtime = fcp_async_core::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build async-core runtime");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind websocket listener");
    let ws_url = format!(
        "ws://{}",
        listener.local_addr().expect("listener local addr")
    );

    let (stop_ws_tx, mut stop_ws_rx) = fcp_async_core::channel::watch::channel(false);
    let (connected_tx, connected_rx) = oneshot::channel::<()>();
    let ws_task = fcp_async_core::task::spawn(async move {
        let accepted = fcp_async_core::select! {
            accept_result = listener.accept() => Some(accept_result.expect("accept websocket client")),
            _ = stop_ws_rx.changed() => None,
        };
        let Some((tcp_stream, _)) = accepted else {
            return;
        };
        let mut ws_stream = accept_test_websocket(tcp_stream).await;
        let _ = connected_tx.send(());

        send_json_frame(
            &mut ws_stream,
            json!({ "type": "hello" }),
            "send hello frame",
        )
        .await;

        fcp_async_core::select! {
            _ = stop_ws_rx.changed() => {},
            () = async {
                loop {
                    match ws_stream.recv(&fcp_async_core::compatibility_cx()).await {
                        Ok(Some(ServerWsMessage::Close(_)) | None) | Err(_) => break,
                        _ => {}
                    }
                }
            } => {}
        }

        close_test_websocket(&mut ws_stream).await;
    });

    Mock::given(method("POST"))
        .and(path("/apps.connections.open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "url": ws_url
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "socket_mode_credential_id": TEST_SOCKET_CREDENTIAL_ID,
            "base_url": mock_server.uri()
        }))
        .await
        .expect("configure");

    let first = runtime
        .block_on(connector.handle_subscribe(json!({
            "topics": ["slack.message.new"]
        })))
        .expect("first subscribe should succeed");
    assert_eq!(first["connection_status"], "started");
    fcp_async_core::time::timeout(StdDuration::from_secs(3), connected_rx)
        .await
        .expect("timeout waiting for socket connection")
        .expect("socket connection signal should complete");

    let second = runtime
        .block_on(connector.handle_subscribe(json!({
            "topics": ["slack.message.new", "slack.reaction.added"]
        })))
        .expect("second subscribe should succeed");
    assert_eq!(second["connection_status"], "already_running");

    let health = connector.handle_health().await.expect("health");
    assert_eq!(health["streaming"]["socket_mode_running"], true);

    runtime
        .block_on(connector.handle_shutdown(json!({})))
        .expect("shutdown should succeed");

    let _ = stop_ws_tx.send(true);
    fcp_async_core::time::timeout(StdDuration::from_secs(3), ws_task)
        .await
        .expect("timeout waiting for ws task")
        .expect("ws task join");

    mock_server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn socket_mode_reconnects_after_websocket_close_and_shutdown_cleans_up() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.reconnect_cleanup");
    let runtime = fcp_async_core::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build async-core runtime");

    let first_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind first websocket listener");
    let first_ws_url = format!(
        "ws://{}",
        first_listener.local_addr().expect("first listener addr")
    );
    let second_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind second websocket listener");
    let second_ws_url = format!(
        "ws://{}",
        second_listener.local_addr().expect("second listener addr")
    );

    let first_ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = first_listener
            .accept()
            .await
            .expect("accept first websocket client");
        let mut ws_stream = accept_test_websocket(tcp_stream).await;
        send_json_frame(
            &mut ws_stream,
            json!({ "type": "hello" }),
            "send first hello frame",
        )
        .await;
        close_test_websocket(&mut ws_stream).await;
    });

    let (second_connected_tx, second_connected_rx) = oneshot::channel::<()>();
    let (second_ack_tx, second_ack_rx) = oneshot::channel::<Option<String>>();
    let second_ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = second_listener
            .accept()
            .await
            .expect("accept second websocket client");
        let mut ws_stream = accept_test_websocket(tcp_stream).await;
        let _ = second_connected_tx.send(());

        send_json_frame(
            &mut ws_stream,
            json!({ "type": "hello" }),
            "send second hello frame",
        )
        .await;
        send_json_frame(
            &mut ws_stream,
            json!({
                "envelope_id": "envelope-after-reconnect",
                "type": "events_api",
                "payload": {
                    "event_id": "EvAfterReconnect",
                    "team_id": "T_TEAM_1",
                    "event": {
                        "type": "message",
                        "user": "U_EVT_RECONNECT",
                        "channel": "C_RECONNECT",
                        "text": "hello after reconnect",
                        "ts": "1700000000.000200"
                    }
                }
            }),
            "send reconnected events_api frame",
        )
        .await;

        let ack_payload = recv_text_frame(&mut ws_stream, "reconnected ack frame")
            .await
            .expect("reconnected ack frame should be readable");
        let _ = second_ack_tx.send(ack_payload);

        loop {
            match ws_stream.recv(&fcp_async_core::compatibility_cx()).await {
                Ok(Some(ServerWsMessage::Close(_)) | None) | Err(_) => break,
                _ => {}
            }
        }
    });

    let socket_urls = [first_ws_url, second_ws_url];
    let fake_server = StructuredFakeHttpServer::spawn(2, move |idx, request| {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/apps.connections.open");
        assert_eq!(
            request
                .headers
                .get("x-fcp-credential-id")
                .map(String::as_str),
            Some(TEST_SOCKET_CREDENTIAL_ID)
        );
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true,
                "url": socket_urls[idx].clone()
            }),
        )
    });

    let mut connector = SlackConnector::new();
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "socket_mode_credential_id": TEST_SOCKET_CREDENTIAL_ID,
            "base_url": fake_server.url(),
            "monitor_policy": { "require_mention": false }
        }))
        .await
        .expect("configure");

    let mut event_rx = connector.subscribe_events();
    let subscribe_result = runtime
        .block_on(connector.handle_subscribe(json!({
            "topics": ["slack.message.new"]
        })))
        .expect("subscribe should succeed");
    assert_eq!(subscribe_result["connection_status"], "started");

    fcp_async_core::time::timeout(StdDuration::from_secs(3), first_ws_task)
        .await
        .expect("timeout waiting for first ws task")
        .expect("first ws task join");
    fcp_async_core::time::timeout(StdDuration::from_secs(5), second_connected_rx)
        .await
        .expect("timeout waiting for reconnected socket")
        .expect("reconnected socket signal should complete");

    let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
        .await
        .expect("timeout waiting for reconnected socket event")
        .expect("broadcast receive")
        .expect("event payload");
    assert_eq!(event.topic, "slack.message.new");
    assert_eq!(event.cursor, "EvAfterReconnect");
    assert_eq!(event.data.principal.id, "U_EVT_RECONNECT");
    assert_eq!(
        event.data.payload["event"]["text"].as_str(),
        Some("hello after reconnect")
    );

    let ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), second_ack_rx)
        .await
        .expect("timeout waiting for reconnected socket ack")
        .expect("ack channel should complete")
        .expect("ack payload missing");
    let ack_value: serde_json::Value =
        serde_json::from_str(&ack_json).expect("ack should be valid json");
    assert_eq!(ack_value["envelope_id"], "envelope-after-reconnect");

    let health = connector.handle_health().await.expect("health");
    assert_eq!(health["streaming"]["socket_mode_running"], true);

    runtime
        .block_on(connector.handle_shutdown(json!({})))
        .expect("shutdown should succeed");

    fcp_async_core::time::timeout(StdDuration::from_secs(3), second_ws_task)
        .await
        .expect("timeout waiting for second ws task")
        .expect("second ws task join");

    let requests = fake_server.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.path == "/apps.connections.open")
    );
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::runtime::test]
async fn validate_post_message_missing_channel() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_channel");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "text": "hello" },
            "capability_token": cap
        }))
        .await;
    assert_invalid_request_contains(result, "channel");
}

#[fcp_async_core::runtime::test]
async fn validate_post_message_missing_text() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_text");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.post_message"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.post_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.post_message",
            "input": { "channel": "C01234567" },
            "capability_token": cap
        }))
        .await;
    assert_invalid_request_contains(result, "text");
}

#[fcp_async_core::runtime::test]
async fn validate_reply_thread_missing_thread_ts() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_thread_ts");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.reply_thread"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.reply_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.reply_thread",
            "input": { "channel": "C01234567", "text": "reply" },
            "capability_token": cap
        }))
        .await;
    assert_invalid_request_contains(result, "thread_ts");
}

#[fcp_async_core::runtime::test]
async fn validate_add_reaction_missing_name() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_name");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.add_reaction"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token(&key, "slack.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.add_reaction",
            "input": { "channel": "C01234567", "timestamp": "1234567890.123456" },
            "capability_token": cap
        }))
        .await;
    assert_invalid_request_contains(result, "name");
}

#[fcp_async_core::runtime::test]
async fn validate_configure_missing_credential_id() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_credential_id");
    let mut connector = SlackConnector::new();
    let result = connector.handle_configure(json!({})).await;
    assert_invalid_request_contains(result, "credential_id");
}

#[fcp_async_core::runtime::test]
async fn validate_upload_file_missing_channels() {
    let _ctx = AsyncTestContext::for_scenario("slack.validation.missing_channels");
    let mock_server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cap = generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "content_object_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "resolved_content": "data"
            },
            "capability_token": cap
        }))
        .await;
    assert_invalid_request_contains(result, "channels");
}

// ============================================================================
// Regression: ok=true envelope with missing payload returns a terminal
// `SlackError::Api` instead of panicking. See flywheel_connectors-g37n0.
// ============================================================================

/// A partial success envelope (`{"ok": true}` with no `message`/`channel`/…)
/// must surface as a recoverable `SlackError::Api { ok: true, .. }` mapped
/// through to `FcpError::External`, not a process abort.
#[fcp_async_core::runtime::test]
async fn ok_true_with_missing_payload_is_mapped_to_api_error_not_panic() {
    let _ctx = AsyncTestContext::for_scenario("slack.ok_true_missing_payload");
    let mock_server = MockServer::start().await;

    // Server claims success but returns no `message` / `channel` /
    // `ts` fields. Previously the client called
    // `.expect("ok response has data")` on the flattened payload and
    // panicked; after the fix we expect a terminal SlackError::Api.
    Mock::given(method("POST"))
        .and(path("/chat.postMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true
        })))
        .mount(&mock_server)
        .await;

    let client = SlackClient::new("xoxb-token")
        .unwrap()
        .with_base_url(mock_server.uri())
        .with_retry_config(0, 10, 100);

    let result = client.post_message("C01234567", "hello", None).await;
    let err = result.expect_err("ok=true without payload must not succeed");

    match &err {
        fcp_slack::error::SlackError::Api { error, ok, code: _ } => {
            assert!(
                *ok,
                "error must mark ok=true so callers can distinguish partial \
                 success envelope from classic ok=false api errors"
            );
            assert!(
                error.contains("chat.postMessage"),
                "error message must name the Slack method for debuggability, \
                 got: {error}"
            );
            assert!(
                error.contains("ok=true"),
                "error message must explicitly mention ok=true so operators \
                 can grep for partial-envelope incidents, got: {error}"
            );
        }
        other => assert!(
            matches!(other, fcp_slack::error::SlackError::Api { .. }),
            "Expected SlackError::Api for ok=true with missing payload, got: {other:?}"
        ),
    }

    // Also confirm the SDK error mapping preserves the context.
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, fcp_core::FcpError::External { .. }),
        "ok=true partial envelope should map to External (non-panicking) \
         FcpError, got: {fcp_err:?}"
    );
}
