//! Slack connector integration tests (flywheel_connectors-i1b.6).
//!
//! Deterministic integration tests using wiremock plus structured HTTP fakes
//! to exercise the Slack Web API transport more realistically.
//! No real API calls. Covers:
//! - Messages (post, reply, history, search)
//! - Channels (list, set topic)
//! - Users (get info)
//! - Files (bounded binary download/upload and UTF-8 text upload)
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
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{Duration, Utc};
use fcp_async_core::channel::oneshot;
use fcp_async_core::net::{TcpListener, TcpStream};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use fcp_webhook::{HmacSha256Verifier, SlackWebhook};
use serde_json::json;
use sha2::{Digest, Sha256};
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

use fcp_sdk::prelude::{JsonlEventStream, JsonlWriter};
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

fn bundled_slack_manifest() -> &'static fcp_manifest::ConnectorManifest {
    static MANIFEST: OnceLock<fcp_manifest::ConnectorManifest> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        fcp_manifest::ConnectorManifest::parse_str(include_str!("../manifest.toml"))
            .expect("bundled Slack manifest must validate")
    })
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    operation: &str,
) -> fcp_core::CapabilityToken {
    let declaration = bundled_slack_manifest()
        .provides
        .operations
        .get(operation)
        .expect("positive token fixtures must name a manifest operation");
    generate_valid_token_for_operation(signing_key, declaration.capability.as_str(), operation)
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
            "protocol_version": "2.0.0",
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

const NATIVE_TEST_STREAM_ID: &str = "slack-integration-stream";

struct NativeTestWriter {
    pending: Vec<u8>,
    frames: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl Write for NativeTestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let frame = serde_json::from_slice(&self.pending).map_err(io::Error::other)?;
        self.frames.lock().expect("capture frame lock").push(frame);
        self.pending.clear();
        Ok(())
    }
}

struct NativeTestTransport {
    stream: JsonlEventStream,
    frames: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl NativeTestTransport {
    fn attach(connector: &mut SlackConnector) -> Self {
        let frames = Arc::new(Mutex::new(Vec::new()));
        let stream = JsonlEventStream::new(JsonlWriter::new(NativeTestWriter {
            pending: Vec::new(),
            frames: Arc::clone(&frames),
        }));
        connector
            .attach_event_stream(stream.clone())
            .expect("attach transport before handshake");
        Self { stream, frames }
    }

    async fn next_event(&self, index: usize) -> fcp_core::EventEnvelope {
        fcp_async_core::time::timeout(StdDuration::from_secs(3), async {
            loop {
                let frame = self
                    .frames
                    .lock()
                    .expect("capture frame lock")
                    .get(index)
                    .cloned();
                if let Some(frame) = frame {
                    assert_eq!(frame["jsonrpc"], "2.0");
                    assert_eq!(frame["method"], "event");
                    assert!(frame.get("id").is_none());
                    assert_eq!(frame["params"]["stream_id"], NATIVE_TEST_STREAM_ID);
                    let event: fcp_core::EventEnvelope =
                        serde_json::from_value(frame["params"]["event"].clone())
                            .expect("canonical native event envelope");
                    assert!(event.requires_ack);
                    assert_eq!(
                        event.data.connector_id,
                        fcp_core::ConnectorId::from_static("fcp.slack"),
                    );
                    assert_eq!(event.data.zone_id, fcp_core::ZoneId::work());
                    return event;
                }
                fcp_async_core::time::sleep(StdDuration::from_millis(5)).await;
            }
        })
        .await
        .expect("native event should reach the production JSONL writer")
    }

    fn acknowledge(&self, event: &fcp_core::EventEnvelope) {
        self.stream
            .acknowledge(json!({
                "stream_id": NATIVE_TEST_STREAM_ID,
                "ack": fcp_core::EventAck::new(&event.topic, vec![event.seq])
                    .with_cursors(vec![event.cursor.clone()]),
            }))
            .expect("acknowledge the exact delivered event");
    }

    fn is_empty(&self) -> bool {
        self.frames.lock().expect("capture frame lock").is_empty()
    }
}

fn native_subscribe_request(key: &Ed25519SigningKey, topic: &str) -> serde_json::Value {
    json!({
        "type": "subscribe",
        "id": "native-subscribe-test",
        "stream_id": NATIVE_TEST_STREAM_ID,
        "topics": [topic],
        "window_size": 1,
        "capability_token": generate_valid_token_for_operation(key, "slack.read", "slack.subscribe"),
    })
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

fn external_upload_reservation(
    request: &StructuredHttpRequest,
    file_id: &str,
) -> StructuredHttpResponse {
    StructuredHttpResponse::json(
        200,
        &json!({
            "ok": true,
            "file_id": file_id,
            "upload_url": format!("http://{}/upload/v1/fixture", request.headers["host"]),
        }),
    )
}

async fn mount_external_upload(server: &MockServer, file: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/files.getUploadURLExternal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "file_id": file["id"],
            "upload_url": format!("{}/upload/v1/fixture", server.uri()),
        })))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/upload/v1/fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/files.completeUploadExternal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "files": [file],
        })))
        .expect(1)
        .mount(server)
        .await;
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut first, fake_server.url()).await;
    setup_configure(&mut second, fake_server.url()).await;
    let first_key = setup_handshake(&mut first, &["slack.write"]).await;
    let second_key = setup_handshake(&mut second, &["slack.write"]).await;

    let first_cap = generate_valid_token_for_principal(
        &first_key,
        "slack.write",
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
        "slack.write",
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

    let cap =
        generate_valid_token_for_principal(&key, "slack.write", "slack.post_message", "agent:a");
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

    let cap =
        generate_valid_token_for_principal(&key, "slack.write", "slack.post_message", "agent:a");
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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut first, fake_server.url()).await;
    setup_configure(&mut second, fake_server.url()).await;
    let first_key = setup_handshake(&mut first, &["slack.write"]).await;
    let second_key = setup_handshake(&mut second, &["slack.write"]).await;

    let first_cap = generate_valid_token_for_principal(
        &first_key,
        "slack.write",
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
        "slack.write",
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

    let cap =
        generate_valid_token_for_principal(&key, "slack.write", "slack.reply_thread", "agent:a");
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

    let cap =
        generate_valid_token_for_principal(&key, "slack.write", "slack.reply_thread", "agent:a");
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

    let cap =
        generate_valid_token_for_principal(&key, "slack.write", "slack.reply_thread", "agent:a");
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;
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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.read"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.read"]).await;

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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.read"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.read"]).await;

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

    mount_external_upload(
        &mock_server,
        json!({
                    "id": "F01234567",
                    "name": "output.log",
                    "title": "output.log",
                    "mimetype": "text/plain",
                    "filetype": "text",
                    "size": 42
        }),
    )
    .await;

    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;

    let cap = generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
                "resolved_content": "log data here",
                "filename": "output.log"
            },
            "capability_token": cap
        }))
        .await
        .expect("invoke should succeed");

    assert_eq!(result["file"]["id"], "F01234567");
    assert_eq!(result["file"]["name"], "output.log");
    assert_eq!(result["content_length"], 13);
    assert_eq!(
        result["content_sha256"],
        hex::encode(Sha256::digest(b"log data here"))
    );
    assert!(result.get("source_object_id").is_none());
    assert!(result.get("file_object_id").is_none());
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    let reservation: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(reservation, json!({"filename": "output.log", "length": 13}));
    assert_eq!(requests[1].body, b"log data here");
    assert!(!requests[1].headers.contains_key("authorization"));
    assert!(!requests[1].headers.contains_key("x-fcp-credential-id"));
    let completion: serde_json::Value = serde_json::from_slice(&requests[2].body).unwrap();
    assert_eq!(
        completion,
        json!({
            "files": [{"id": "F01234567", "title": "output.log"}],
            "channel_id": "C01234567",
        })
    );
}

#[fcp_async_core::runtime::test]
async fn upload_file_threaded_denies_duplicate_owner_before_http_send() {
    let _ctx = AsyncTestContext::for_scenario("slack.upload_file.coordination.deny_duplicate");
    let fake_server = StructuredFakeHttpServer::spawn(3, |idx, request| {
        assert_eq!(request.method, "POST");
        if idx == 0 {
            assert_eq!(request.path, "/files.getUploadURLExternal");
            return external_upload_reservation(request, "F01234567");
        }
        if idx == 1 {
            assert_eq!(request.path, "/upload/v1/fixture");
            assert_eq!(request.body, b"agent A upload");
            assert!(!request.headers.contains_key("authorization"));
            return StructuredHttpResponse::json(200, &json!({}));
        }
        assert_eq!(request.path, "/files.completeUploadExternal");
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack upload body json");
        assert_eq!(body["channel_id"], "C01234567");
        assert_eq!(body["thread_ts"], "1234567890.123456");
        assert_eq!(body["files"][0]["id"], "F01234567");
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true,
                "files": [{
                    "id": "F01234567",
                    "name": "output.log",
                    "title": "output.log",
                    "mimetype": "text/plain",
                    "filetype": "text",
                    "size": 42
                }]
            }),
        )
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut first = SlackConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let mut second = SlackConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    setup_configure(&mut first, fake_server.url()).await;
    setup_configure(&mut second, fake_server.url()).await;
    let first_key = setup_handshake(&mut first, &["slack.files.write"]).await;
    let second_key = setup_handshake(&mut second, &["slack.files.write"]).await;

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
    assert_eq!(fake_server.requests().len(), 3);
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;

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
    let fake_server = StructuredFakeHttpServer::spawn(3, |idx, request| {
        assert_eq!(request.method, "POST");
        if idx == 0 {
            assert_eq!(request.path, "/files.getUploadURLExternal");
            return external_upload_reservation(request, "F01234567");
        }
        if idx == 1 {
            assert_eq!(request.path, "/upload/v1/fixture");
            assert_eq!(request.body, b"will fail");
            return StructuredHttpResponse::json(200, &json!({}));
        }
        assert_eq!(request.path, "/files.completeUploadExternal");
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("slack upload body json");
        assert_eq!(body["channel_id"], "C01234567");
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
    setup_configure(&mut connector, fake_server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;

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
                "resolved_content": "will fail",
                "filename": "output.log",
                "thread_ts": "1234567890.123456"
            },
            "capability_token": cap
        }))
        .await
        .expect_err("Slack API failure should not return send_executed evidence");

    assert!(matches!(error, fcp_core::FcpError::ResourceNotFound { .. }));
    assert_eq!(fake_server.requests().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn external_upload_sends_utf8_bytes_without_token_or_credential_reference() {
    use fcp_slack::client::SlackAuth;
    for auth in [
        SlackAuth::Token("xoxb-upload-secret".into()),
        SlackAuth::CredentialId(fcp_core::CredentialId::new()),
    ] {
        let server = StructuredFakeHttpServer::spawn(3, |idx, request| match idx {
            0 => {
                assert_eq!(request.path, "/files.getUploadURLExternal");
                assert!(
                    request.headers.contains_key("authorization")
                        || request.headers.contains_key("x-fcp-credential-id")
                );
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["length"], "hello 🌍\n".len());
                assert_eq!(body["filename"], "upload.txt");
                external_upload_reservation(request, "FUPLOAD1")
            }
            1 => {
                assert_eq!(request.path, "/upload/v1/fixture");
                assert_eq!(request.body, "hello 🌍\n".as_bytes());
                assert_eq!(request.headers["content-type"], "application/octet-stream");
                assert!(!request.headers.contains_key("authorization"));
                assert!(!request.headers.contains_key("x-fcp-credential-id"));
                StructuredHttpResponse::json(200, &json!({}))
            }
            _ => {
                assert_eq!(request.path, "/files.completeUploadExternal");
                assert!(
                    request.headers.contains_key("authorization")
                        || request.headers.contains_key("x-fcp-credential-id")
                );
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["channels"], "C0123,G4567");
                assert!(body.get("channel_id").is_none());
                assert_eq!(body["files"][0]["id"], "FUPLOAD1");
                StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true, "files": [{"id": "FUPLOAD1", "title": "upload.txt"}],
                    }),
                )
            }
        });
        let client = SlackClient::new_with_auth(auth)
            .unwrap()
            .with_base_url(server.url());
        let file = client
            .upload_file(" C0123, G4567 ", "hello 🌍\n".as_bytes(), None, None)
            .await
            .unwrap();
        assert_eq!(file.id, "FUPLOAD1");
        assert_eq!(server.requests().len(), 3);
    }
}

#[fcp_async_core::runtime::test]
async fn external_upload_single_user_uses_the_user_capable_channels_field() {
    let server = MockServer::start().await;
    mount_external_upload(&server, json!({"id": "FUPLOAD1"})).await;
    let client = SlackClient::new("token")
        .unwrap()
        .with_base_url(server.uri());
    let file = client
        .upload_file("U0123", b"hello", None, None)
        .await
        .unwrap();
    assert_eq!(file.id, "FUPLOAD1");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    let completion: serde_json::Value = serde_json::from_slice(&requests[2].body).unwrap();
    assert_eq!(completion["channels"], "U0123");
    assert!(completion.get("channel_id").is_none());
}

#[fcp_async_core::runtime::test]
async fn upload_response_limit_does_not_reduce_channel_history_capacity() {
    let message_size = 1024 * 1024 + 1;
    let server = StructuredFakeHttpServer::spawn(1, move |_idx, request| {
        assert!(request.path.starts_with("/conversations.history?"));
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true,
                "messages": [{"ts": "123.456", "text": "x".repeat(message_size)}],
                "has_more": false,
            }),
        )
    });
    let client = SlackClient::new("token")
        .unwrap()
        .with_base_url(server.url());
    let messages = client.get_channel_history("C0123", Some(1)).await.unwrap();
    assert_eq!(messages[0].text.len(), message_size);
}

#[fcp_async_core::runtime::test]
async fn external_upload_rejects_untrusted_reservation_before_sending_content() {
    let server = StructuredFakeHttpServer::spawn(1, |_idx, _request| {
        StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true, "file_id": "FUPLOAD1",
                "upload_url": "http://169.254.169.254/upload/v1/secret-capability",
            }),
        )
    });
    let client = SlackClient::new("token")
        .unwrap()
        .with_base_url(server.url());
    let error = client
        .upload_file("C0123", b"private content", None, None)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("169.254"));
    assert!(!error.to_string().contains("secret-capability"));
    assert_eq!(server.requests().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn external_upload_refuses_redirects_and_failed_transfers_without_finalizing() {
    for status in [302, 500] {
        let server = StructuredFakeHttpServer::spawn(2, move |idx, request| {
            if idx == 0 {
                return external_upload_reservation(request, "FUPLOAD1");
            }
            assert_eq!(request.path, "/upload/v1/fixture");
            StructuredHttpResponse {
                status,
                headers: vec![(
                    "location".into(),
                    format!("http://{}/must-not-follow", request.headers["host"]),
                )],
                body: b"secret provider response".to_vec(),
            }
        });
        let client = SlackClient::new("token")
            .unwrap()
            .with_base_url(server.url());
        let error = client
            .upload_file("C0123", b"content", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, fcp_slack::error::SlackError::Http { status_code: Some(code), .. } if code == status)
        );
        assert!(!error.to_string().contains("secret provider response"));
        assert_eq!(server.requests().len(), 2);
    }
}

#[fcp_async_core::runtime::test]
async fn external_upload_uncertain_completion_is_not_retried_or_reported_as_success() {
    let completions = [
        StructuredHttpResponse::json(500, &json!({"ok": false, "error": "internal_error"})),
        StructuredHttpResponse::json(200, &json!({"ok": false, "error": "internal_error"})),
        StructuredHttpResponse::json(200, &json!({"ok": true})),
        StructuredHttpResponse::json(200, &json!({"ok": true, "files": []})),
        StructuredHttpResponse::json(200, &json!({"ok": true, "files": [{"id": "FWRONG"}]})),
        StructuredHttpResponse {
            status: 200,
            headers: vec![],
            body: b"not json".to_vec(),
        },
    ];
    for completion in completions {
        let server = StructuredFakeHttpServer::spawn(3, move |idx, request| match idx {
            0 => external_upload_reservation(request, "FUPLOAD1"),
            1 => StructuredHttpResponse::json(200, &json!({})),
            _ => completion.clone(),
        });
        let client = SlackClient::new("token")
            .unwrap()
            .with_base_url(server.url())
            .with_retry_config(3, 1, 1);
        let error = client
            .upload_file("C0123", b"content", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, fcp_slack::error::SlackError::UploadOutcomeUnknown { file_id, .. } if file_id == "FUPLOAD1")
        );
        assert!(matches!(
            error.to_fcp_error(),
            fcp_core::FcpError::External {
                retryable: false,
                ..
            }
        ));
        assert!(!error.is_retryable());
        assert_eq!(server.requests().len(), 3);
    }
}

#[fcp_async_core::runtime::test]
async fn external_upload_rate_limit_retries_only_completion_with_the_same_file_id() {
    let server = StructuredFakeHttpServer::spawn(4, |idx, request| match idx {
        0 => external_upload_reservation(request, "FUPLOAD1"),
        1 => StructuredHttpResponse::json(200, &json!({})),
        2 => StructuredHttpResponse {
            status: 429,
            headers: vec![("retry-after".into(), "0".into())],
            body: vec![],
        },
        _ => StructuredHttpResponse::json(
            200,
            &json!({
                "ok": true, "files": [{"id": "FUPLOAD1"}],
            }),
        ),
    });
    let client = SlackClient::new("token")
        .unwrap()
        .with_base_url(server.url())
        .with_retry_config(3, 1, 1);
    let file = client
        .upload_file("C0123", b"content", None, None)
        .await
        .unwrap();
    assert_eq!(file.id, "FUPLOAD1");
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[2].path, "/files.completeUploadExternal");
    assert_eq!(requests[3].path, requests[2].path);
    assert_eq!(requests[3].body, requests[2].body);
}

#[fcp_async_core::runtime::test]
async fn download_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("slack.download_file.happy_path");
    let content: &[u8] = b"%PDF-1.7\n\xff\0";
    let server = StructuredFakeHttpServer::spawn(2, move |idx, request| {
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.headers["x-fcp-credential-id"],
            TEST_BOT_CREDENTIAL_ID
        );
        assert!(!request.headers.contains_key("authorization"));
        if idx == 0 {
            assert_eq!(request.path, "/files.info?file=F01234567");
            return StructuredHttpResponse::json(
                200,
                &json!({
                    "ok": true,
                    "file": {
                        "id": "F01234567", "name": "report.pdf", "title": "Q4 Report",
                        "mimetype": "application/pdf", "filetype": "pdf", "size": content.len(),
                        "url_private": format!("http://{}/files-pri/TTEST-F01234567/report.pdf", request.headers["host"]),
                        "url_private_download": format!("http://{}/files-pri/TTEST-F01234567/download/report.pdf", request.headers["host"]),
                    }
                }),
            );
        }
        assert_eq!(
            request.path,
            "/files-pri/TTEST-F01234567/download/report.pdf"
        );
        assert_eq!(request.headers["accept"], "*/*");
        StructuredHttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/pdf".into())],
            body: content.to_vec(),
        }
    });

    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.files.read"]).await;

    let cap = generate_valid_token_for_operation(&key, "slack.files.read", "slack.download_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.download_file",
            "input": { "file_id": "F01234567" },
            "capability_token": cap
        }))
        .await
        .expect("download must fetch the actual file bytes");

    assert_eq!(result["file"]["id"], "F01234567");
    assert_eq!(result["file"]["name"], "report.pdf");
    assert!(result["file"]["url_private_download"].is_null());
    assert!(result["file"]["url_private"].is_null());
    assert_eq!(result["content_base64"], BASE64_STANDARD.encode(content));
    assert_eq!(result["content_length"], content.len());
    assert_eq!(
        result["content_sha256"],
        hex::encode(Sha256::digest(content))
    );
    assert!(result.get("content_object_id").is_none());
    assert_eq!(server.requests().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn binary_file_manifest_matches_runtime_contract() {
    let manifest = fcp_manifest::ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("bundled Slack manifest must have a valid canonical interface hash");
    let introspection = SlackConnector::new().handle_introspect().await.unwrap();
    let operations = introspection["operations"].as_array().unwrap();
    for operation_id in ["slack.upload_file", "slack.download_file"] {
        let operation = &manifest.provides.operations[operation_id];
        let runtime = operations
            .iter()
            .find(|entry| entry["id"] == operation_id)
            .unwrap();
        assert_eq!(
            operation.input_schema["required"],
            runtime["input_schema"]["required"]
        );
        assert_eq!(
            operation.output_schema["required"],
            runtime["output_schema"]["required"]
        );
        assert_eq!(
            operation.output_schema["properties"]["content_length"]["maximum"],
            16 * 1024 * 1024
        );
        assert_eq!(
            operation.output_schema["properties"]["content_sha256"]["pattern"],
            "^[0-9a-f]{64}$"
        );
        let network = operation.network_constraints.as_ref().unwrap();
        assert_eq!(network.max_redirects, 0);
        assert!(
            network
                .host_allow
                .iter()
                .any(|host| host == "files.slack.com")
        );
    }
    let upload = &manifest.provides.operations["slack.upload_file"];
    assert_eq!(upload.input_schema["required"], json!(["channels"]));
    assert_eq!(
        upload.input_schema["oneOf"],
        json!([
            {"required": ["content_base64"]}, {"required": ["resolved_content"]},
        ])
    );
    assert!(
        upload.input_schema["properties"]
            .get("content_object_id")
            .is_none()
    );
    let download = &manifest.provides.operations["slack.download_file"];
    assert_eq!(download.input_schema["required"], json!(["file_id"]));
    assert_eq!(
        download.output_schema["required"],
        json!(["file", "content_base64", "content_length", "content_sha256",])
    );
    assert_eq!(
        download
            .network_constraints
            .as_ref()
            .unwrap()
            .max_response_bytes,
        16 * 1024 * 1024
    );
}

#[fcp_async_core::runtime::test]
async fn binary_download_upload_roundtrip_preserves_bytes_and_scopes_credentials() {
    let content: &[u8] = b"\0\xff\x80Slack\r\n\0\x01";
    let server = StructuredFakeHttpServer::spawn(5, move |idx, request| {
        if idx == 3 {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/upload/v1/fixture");
            assert_eq!(request.body, content);
            assert_eq!(request.headers["content-type"], "application/octet-stream");
            assert!(!request.headers.contains_key("authorization"));
            assert!(!request.headers.contains_key("x-fcp-credential-id"));
            return StructuredHttpResponse::json(200, &json!({}));
        }
        assert_eq!(
            request.headers["x-fcp-credential-id"],
            TEST_BOT_CREDENTIAL_ID
        );
        assert!(!request.headers.contains_key("authorization"));
        match idx {
            0 => {
                assert_eq!(request.method, "GET");
                assert_eq!(request.path, "/files.info?file=FBINARY1");
                StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "file": {
                            "id": "FBINARY1", "name": "source.bin", "size": content.len(),
                            "url_private_download": format!("http://{}/files-pri/TTEST-FBINARY1/download/source.bin", request.headers["host"]),
                        }
                    }),
                )
            }
            1 => {
                assert_eq!(request.method, "GET");
                assert_eq!(
                    request.path,
                    "/files-pri/TTEST-FBINARY1/download/source.bin"
                );
                assert_eq!(request.headers["accept"], "*/*");
                StructuredHttpResponse {
                    status: 200,
                    headers: vec![("content-type".into(), "application/octet-stream".into())],
                    body: content.to_vec(),
                }
            }
            2 => {
                assert_eq!(request.path, "/files.getUploadURLExternal");
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(
                    body,
                    json!({"filename": "copy.bin", "length": content.len()})
                );
                external_upload_reservation(request, "FCOPY1")
            }
            4 => {
                assert_eq!(request.path, "/files.completeUploadExternal");
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(
                    body,
                    json!({
                        "files": [{"id": "FCOPY1", "title": "copy.bin"}],
                        "channel_id": "C01234567",
                    })
                );
                StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true, "files": [{"id": "FCOPY1", "name": "copy.bin", "size": content.len()}],
                    }),
                )
            }
            _ => unreachable!("unexpected transfer stage"),
        }
    });
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, server.url()).await;
    let key = setup_handshake(&mut connector, &["slack.files.read", "slack.files.write"]).await;
    let download = connector.handle_invoke(json!({
        "operation": "slack.download_file",
        "input": { "file_id": "FBINARY1" },
        "capability_token": generate_valid_token_for_operation(&key, "slack.files.read", "slack.download_file"),
    })).await.expect("binary download");
    assert_eq!(download["content_base64"], BASE64_STANDARD.encode(content));
    assert_eq!(download["content_length"], content.len());
    assert_eq!(
        download["content_sha256"],
        hex::encode(Sha256::digest(content))
    );
    let upload = connector.handle_invoke(json!({
        "operation": "slack.upload_file",
        "input": {
            "channels": "C01234567",
            "content_base64": download["content_base64"],
            "filename": "copy.bin",
        },
        "capability_token": generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file"),
    })).await.expect("binary upload using the downloaded inline content");
    assert_eq!(upload["file"]["id"], "FCOPY1");
    assert_eq!(upload["content_length"], download["content_length"]);
    assert_eq!(upload["content_sha256"], download["content_sha256"]);
    assert_eq!(upload["receipt"]["resource"], "slack:file:FCOPY1");
    assert!(upload.get("source_object_id").is_none());
    assert!(upload.get("file_object_id").is_none());
    assert_eq!(server.requests().len(), 5);
}

#[fcp_async_core::runtime::test]
async fn private_download_authenticates_both_token_and_credential_reference_modes() {
    use fcp_slack::client::SlackAuth;

    for auth in [
        SlackAuth::Token("xoxb-download-secret".into()),
        SlackAuth::CredentialId(fcp_core::CredentialId::new()),
    ] {
        let (header, expected) = match &auth {
            SlackAuth::Token(token) => ("authorization", format!("Bearer {token}")),
            SlackAuth::CredentialId(id) => ("x-fcp-credential-id", id.to_string()),
        };
        let server = StructuredFakeHttpServer::spawn(2, move |idx, request| {
            assert_eq!(request.headers[header], expected);
            assert_eq!(request.method, "GET");
            assert_eq!(
                request.headers.contains_key("authorization"),
                header == "authorization"
            );
            assert_eq!(
                request.headers.contains_key("x-fcp-credential-id"),
                header == "x-fcp-credential-id"
            );
            if idx == 0 {
                return StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "file": {
                            "id": "FAUTH1", "size": 3,
                            "url_private": format!("http://{}/files-pri/TTEST-FAUTH1/file.bin", request.headers["host"]),
                        }
                    }),
                );
            }
            assert_eq!(request.path, "/files-pri/TTEST-FAUTH1/file.bin");
            assert_eq!(request.headers["accept"], "*/*");
            StructuredHttpResponse {
                status: 200,
                headers: vec![],
                body: vec![0, 128, 255],
            }
        });
        let client = SlackClient::new_with_auth(auth)
            .unwrap()
            .with_base_url(server.url());
        let (file, bytes) = client.download_file("FAUTH1").await.unwrap();
        assert_eq!(file.id, "FAUTH1");
        assert_eq!(bytes, [0, 128, 255]);
        assert_eq!(server.requests().len(), 2);
    }
}

#[fcp_async_core::runtime::test]
async fn download_file_rejects_untrusted_origin_without_sending_credentials() {
    let untrusted = MockServer::start().await;
    for url in [
        format!(
            "{}/files-pri/TTEST-FSAFE1/secret-capability",
            untrusted.uri()
        ),
        "https://files.slack.com.evil.invalid/files-pri/secret-capability".into(),
        "http://169.254.169.254/files-pri/secret-capability".into(),
    ] {
        let server = StructuredFakeHttpServer::spawn(1, move |_idx, _request| {
            StructuredHttpResponse::json(
                200,
                &json!({
                    "ok": true,
                    "file": {"id": "FSAFE1", "size": 3, "url_private_download": url},
                }),
            )
        });
        let client = SlackClient::new("xoxb-private-secret")
            .unwrap()
            .with_base_url(server.url())
            .with_request_timeout(StdDuration::from_secs(2));
        let error = client.download_file("FSAFE1").await.unwrap_err();
        let message = error.to_string();
        assert!(!message.contains("secret-capability"));
        assert!(!message.contains("xoxb-private-secret"));
        assert!(!message.contains("169.254"));
        assert_eq!(server.requests().len(), 1);
    }
    assert!(untrusted.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn download_file_rejects_unusable_metadata_before_fetching_content() {
    for patch in [
        json!({"id": "FDIFFERENT"}),
        json!({"is_external": true}),
        json!({"mode": "external"}),
        json!({"filetype": "remote"}),
        json!({"size": 16 * 1024 * 1024 + 1}),
        json!({"size": null}),
        json!({"url_private_download": null}),
    ] {
        let server = StructuredFakeHttpServer::spawn(1, move |_idx, request| {
            let mut file = json!({
                "id": "FSAFE1", "size": 3,
                "url_private_download": format!("http://{}/files-pri/TTEST-FSAFE1/file.bin", request.headers["host"]),
            });
            for (key, value) in patch.as_object().unwrap() {
                file[key] = value.clone();
            }
            StructuredHttpResponse::json(200, &json!({"ok": true, "file": file}))
        });
        let client = SlackClient::new("token")
            .unwrap()
            .with_base_url(server.url());
        assert!(client.download_file("FSAFE1").await.is_err());
        assert_eq!(server.requests().len(), 1);
    }
}

#[fcp_async_core::runtime::test]
async fn download_file_refuses_redirects_and_failed_transfers_without_retrying() {
    let redirect_target = MockServer::start().await;
    for status in [302, 401, 403, 429, 500] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files.info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "file": {
                    "id": "FSAFE1", "size": 3,
                    "url_private_download": format!("{}/files-pri/TTEST-FSAFE1/secret-capability", server.uri()),
                }
            })))
            .mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/files-pri/TTEST-FSAFE1/secret-capability"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header(
                        "location",
                        format!("{}/must-not-follow", redirect_target.uri()),
                    )
                    .insert_header("retry-after", "0")
                    .set_body_string("private provider failure body"),
            )
            .mount(&server)
            .await;
        let client = SlackClient::new("xoxb-private-secret")
            .unwrap()
            .with_base_url(server.uri())
            .with_retry_config(3, 1, 1);
        let error = client.download_file("FSAFE1").await.unwrap_err();
        assert!(!error.to_string().contains("private provider failure body"));
        assert!(!error.to_string().contains("secret-capability"));
        assert!(!error.to_string().contains("xoxb-private-secret"));
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "download failures must not be retried implicitly"
        );
    }
    assert!(
        redirect_target
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[fcp_async_core::runtime::test]
async fn download_file_rejects_actual_size_that_disagrees_with_metadata() {
    for metadata_size in [0, 2, 4] {
        let server = StructuredFakeHttpServer::spawn(2, move |idx, request| {
            if idx == 0 {
                return StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "file": {
                            "id": "FSIZE1", "size": metadata_size,
                            "url_private_download": format!("http://{}/files-pri/TTEST-FSIZE1/file.bin", request.headers["host"]),
                        }
                    }),
                );
            }
            StructuredHttpResponse {
                status: 200,
                headers: vec![],
                body: vec![0, 128, 255],
            }
        });
        let client = SlackClient::new("token")
            .unwrap()
            .with_base_url(server.url());
        assert!(client.download_file("FSIZE1").await.is_err());
        assert_eq!(server.requests().len(), 2);
    }
}

#[fcp_async_core::runtime::test]
async fn download_file_bounds_chunked_content_and_rejects_truncated_http_bodies() {
    for scenario in ["chunked", "oversized_chunked", "truncated"] {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let accept = || {
                let deadline = std::time::Instant::now() + StdDuration::from_secs(5);
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream
                                .set_read_timeout(Some(StdDuration::from_secs(5)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(StdDuration::from_secs(5)))
                                .unwrap();
                            return stream;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "download fixture connection timed out"
                            );
                            thread::sleep(StdDuration::from_millis(5));
                        }
                        Err(error) => panic!("download fixture accept failed: {error}"),
                    }
                }
            };
            let mut metadata_stream = accept();
            let request = read_structured_http_request(&mut metadata_stream);
            assert_eq!(request.path, "/files.info?file=FBOUNDED1");
            let metadata_size = match scenario {
                "chunked" => 3,
                "oversized_chunked" => 16 * 1024 * 1024,
                _ => 4,
            };
            write_structured_http_response(
                &mut metadata_stream,
                StructuredHttpResponse::json(
                    200,
                    &json!({
                        "ok": true,
                        "file": {
                            "id": "FBOUNDED1", "size": metadata_size,
                            "url_private_download": format!("http://{address}/files-pri/TTEST-FBOUNDED1/file.bin"),
                        }
                    }),
                ),
            );
            drop(metadata_stream);
            let mut content_stream = accept();
            let request = read_structured_http_request(&mut content_stream);
            assert_eq!(request.path, "/files-pri/TTEST-FBOUNDED1/file.bin");
            if scenario == "truncated" {
                content_stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabc",
                    )
                    .unwrap();
                return;
            }
            content_stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let oversized = scenario == "oversized_chunked";
            let chunk = if oversized {
                vec![0xAB; 1024 * 1024]
            } else {
                vec![0, 128, 255]
            };
            let chunk_header = format!("{:X}\r\n", chunk.len());
            for _ in 0..if oversized { 17 } else { 1 } {
                // A bounded reader may close the connection immediately after
                // crossing its limit; that cancellation is expected here.
                if content_stream.write_all(chunk_header.as_bytes()).is_err()
                    || content_stream.write_all(&chunk).is_err()
                    || content_stream.write_all(b"\r\n").is_err()
                {
                    return;
                }
            }
            let _ = content_stream.write_all(b"0\r\n\r\n");
        });
        let client = SlackClient::new("token")
            .unwrap()
            .with_base_url(format!("http://{address}"))
            .with_request_timeout(StdDuration::from_secs(5));
        let result = client.download_file("FBOUNDED1").await;
        if scenario == "chunked" {
            assert_eq!(result.unwrap().1, [0, 128, 255]);
        } else {
            assert!(
                result.is_err(),
                "{scenario} must not produce partial content"
            );
        }
        worker.join().expect("bounded download fixture completed");
    }
}

#[fcp_async_core::runtime::test]
async fn binary_upload_rejects_invalid_content_before_network() {
    let server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;
    for content in [
        json!({}),
        json!({"content_base64": "AA==", "resolved_content": "text"}),
        json!({"content_base64": "AA"}),
        json!({"content_base64": "AB=="}),
        json!({"content_base64": "_w=="}),
        json!({"content_base64": "AA==\n"}),
        json!({"content_base64": 42}),
    ] {
        let mut input = content;
        input["channels"] = json!("C01234567");
        input["thread_ts"] = json!("123.456");
        let error = connector.handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": input,
            "capability_token": generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file"),
        })).await.unwrap_err();
        assert!(
            matches!(error, fcp_core::FcpError::InvalidRequest { .. }),
            "unexpected validation error: {error:?}"
        );
    }
    let oversized = BASE64_STANDARD.encode(vec![0; 16 * 1024 * 1024 + 1]);
    let error = connector.handle_invoke(json!({
        "operation": "slack.upload_file",
        "input": {"channels": "C01234567", "content_base64": oversized},
        "capability_token": generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file"),
    })).await.unwrap_err();
    assert!(matches!(error, fcp_core::FcpError::InvalidRequest { .. }));
    assert!(server.received_requests().await.unwrap().is_empty());
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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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

    mount_external_upload(
        &mock_server,
        json!({
                    "id": "F09876543",
                    "name": "data.csv",
                    "title": "data.csv",
                    "mimetype": "text/csv",
                    "filetype": "csv",
                    "size": 100
        }),
    )
    .await;

    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;

    let cap = generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
                "channels": "C01234567",
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
    assert_eq!(receipt["resource"], "slack:file:F09876543");
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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.read"]).await;

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
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "base_url": mock_server.uri(),
            "receive_mode": "events_api",
            "monitor_policy": { "require_mention": false }
        }))
        .await
        .expect("configure");

    let native = NativeTestTransport::attach(&mut connector);
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_subscribe(native_subscribe_request(&key, "slack.message.new"))
        .await
        .expect("subscribe to authorized native Events API delivery");
    let cap = generate_valid_token_for_operation(&key, "slack.read", "slack.handle_events_api");
    let mut invocation = Box::pin(connector.handle_invoke(json!({
        "operation": "slack.handle_events_api",
        "input": {
            "payload": verified.payload,
            "signature_result": "verified"
        },
        "capability_token": cap
    })));
    let event = fcp_async_core::select! {
        result = &mut invocation => panic!("callback completed before downstream ACK: {result:?}"),
        event = native.next_event(0) => event,
    };
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), &mut invocation)
            .await
            .is_err(),
        "event emission alone cannot acknowledge the provider callback",
    );
    native.acknowledge(&event);
    let result = invocation
        .await
        .expect("verified callback succeeds after native ACK");

    assert_eq!(result["status"], "event_emitted");
    assert_eq!(result["acknowledged"], true);
    assert_eq!(result["event_emitted"], true);
    assert_eq!(result["event_topic"], "slack.message.new");
    assert_eq!(result["sender_policy_decision"], "allowed");
    assert_eq!(result["capability_decision"], "bound_capability_verified");
    assert_eq!(result["event"]["topic"], "slack.message.new");
    assert_eq!(result["event"]["cursor"], "EvHttp01");
    assert_eq!(result["event"], serde_json::to_value(&event).unwrap());

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

    let key = setup_handshake(&mut connector, &["slack.read"]).await;
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

fn events_api_native_fixture(key: &Ed25519SigningKey, event_id: &str) -> serde_json::Value {
    json!({
        "operation": "slack.handle_events_api",
        "input": {
            "signature_result": "verified",
            "payload": {
                "type": "event_callback",
                "event_id": event_id,
                "team_id": "T_NATIVE",
                "event": {
                    "type": "message", "user": "U_NATIVE", "channel": "C_NATIVE",
                    "text": "native delivery fixture", "ts": "1700000000.000999",
                },
            },
        },
        "capability_token": generate_valid_token_for_operation(
            key, "slack.read", "slack.handle_events_api",
        ),
    })
}

#[fcp_async_core::runtime::test]
async fn events_api_broadcast_observer_cannot_acknowledge_an_undelivered_callback() {
    let mut connector = SlackConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "receive_mode": "events_api",
            "monitor_policy": { "require_mention": false },
        }))
        .await
        .unwrap();
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    let mut observer = connector.subscribe_events();
    let result = connector
        .handle_invoke(events_api_native_fixture(&key, "EvNoConsumer"))
        .await;
    assert!(matches!(
        result,
        Err(fcp_core::FcpError::ConnectorUnavailable { .. })
    ));
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(50), observer.recv())
            .await
            .is_err(),
        "a diagnostic observer is not an authorized durable consumer",
    );
}

#[fcp_async_core::runtime::test]
async fn events_api_closed_stream_preserves_provider_identity_for_retry() {
    let mut connector = SlackConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "receive_mode": "events_api",
            "monitor_policy": { "require_mention": false },
        }))
        .await
        .unwrap();
    let native = NativeTestTransport::attach(&mut connector);
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    connector
        .handle_subscribe(native_subscribe_request(&key, "slack.events"))
        .await
        .unwrap();

    let mut first = Box::pin(connector.handle_invoke(events_api_native_fixture(&key, "EvRetry")));
    let first_event = fcp_async_core::select! {
        result = &mut first => panic!("callback completed without native ACK: {result:?}"),
        event = native.next_event(0) => event,
    };
    native.stream.close();
    assert!(matches!(
        first.await,
        Err(fcp_core::FcpError::ConnectorUnavailable { .. })
    ));
    assert!(
        native
            .stream
            .acknowledge(json!({
                "stream_id": NATIVE_TEST_STREAM_ID,
                "ack": fcp_core::EventAck::new(&first_event.topic, vec![first_event.seq])
                    .with_cursors(vec![first_event.cursor.clone()]),
            }))
            .is_err(),
        "closed session cannot accept a late ACK"
    );

    connector
        .handle_subscribe(native_subscribe_request(&key, "slack.events"))
        .await
        .expect("resume the same authorized stream");
    let mut retry = Box::pin(connector.handle_invoke(events_api_native_fixture(&key, "EvRetry")));
    let replayed = fcp_async_core::select! {
        result = &mut retry => panic!("retry completed without native ACK: {result:?}"),
        event = native.next_event(1) => event,
    };
    assert_eq!(replayed.cursor, first_event.cursor);
    assert_eq!(replayed.data.payload, first_event.data.payload);
    assert_eq!(
        replayed.data.principal.kind,
        first_event.data.principal.kind
    );
    assert_eq!(replayed.data.principal.id, first_event.data.principal.id);
    assert_eq!(
        replayed.data.principal.trust,
        first_event.data.principal.trust
    );
    assert_eq!(
        replayed.data.principal.display,
        first_event.data.principal.display
    );
    assert_eq!(replayed.data.resource_uris, first_event.data.resource_uris);
    assert_ne!(replayed.seq, first_event.seq);
    native.acknowledge(&replayed);
    let result = retry.await.expect("retry succeeds only after exact ACK");
    assert_eq!(result["acknowledged"], true);
}

#[fcp_async_core::runtime::test]
async fn events_api_pending_delivery_stops_at_signed_subscription_expiry() {
    let mut connector = SlackConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "receive_mode": "events_api",
            "monitor_policy": { "require_mention": false },
        }))
        .await
        .unwrap();
    let native = NativeTestTransport::attach(&mut connector);
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    let constraints = CapabilityConstraints {
        resource_allow: vec!["slack:events:slack.events".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).unwrap();
    let now = Utc::now();
    let token = fcp_core::CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id("slack.read")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["slack.subscribe"])
            .issuer("node:test")
            .target_instance(connector.instance_id())
            .validity(now, now + Duration::seconds(2))
            .try_constraints_cbor(&cbor)
            .unwrap()
            .sign(&key)
            .unwrap(),
    );
    let mut request = native_subscribe_request(&key, "slack.events");
    request["capability_token"] = serde_json::to_value(token).unwrap();
    connector.handle_subscribe(request).await.unwrap();
    let mut invocation =
        Box::pin(connector.handle_invoke(events_api_native_fixture(&key, "EvExpiry")));
    let event = fcp_async_core::select! {
        result = &mut invocation => panic!("callback completed before event delivery: {result:?}"),
        event = native.next_event(0) => event,
    };
    let result = fcp_async_core::time::timeout(StdDuration::from_secs(4), &mut invocation)
        .await
        .expect("expired authority must stop a pending delivery without another request");
    assert!(matches!(result, Err(fcp_core::FcpError::TokenExpired)));
    assert!(!native.stream.is_open());
    assert!(
        native
            .stream
            .acknowledge(json!({
                "stream_id": NATIVE_TEST_STREAM_ID,
                "ack": fcp_core::EventAck::new(&event.topic, vec![event.seq])
                    .with_cursors(vec![event.cursor]),
            }))
            .is_err()
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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.read"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.read"]).await;

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
async fn every_manifest_operation_accepts_its_declared_capability_in_simulation() {
    let manifest = bundled_slack_manifest();
    let fixtures = [
        (
            "slack.post_message",
            json!({"channel": "C01234567", "text": "hello"}),
        ),
        (
            "slack.reply_thread",
            json!({"channel": "C01234567", "thread_ts": "123.456", "text": "reply"}),
        ),
        (
            "slack.update_progress_draft",
            json!({"channel": "C01234567", "draft_id": "manifest-parity", "text": "working"}),
        ),
        ("slack.get_channel_history", json!({"channel": "C01234567"})),
        ("slack.search_messages", json!({"query": "status"})),
        ("slack.list_channels", json!({})),
        ("slack.get_user_info", json!({"user": "U01234567"})),
        (
            "slack.upload_file",
            json!({"channels": "C01234567", "content_base64": "AA==", "filename": "byte.bin"}),
        ),
        ("slack.download_file", json!({"file_id": "F01234567"})),
        (
            "slack.add_reaction",
            json!({"channel": "C01234567", "timestamp": "123.456", "name": "thumbsup"}),
        ),
        (
            "slack.set_channel_topic",
            json!({"channel": "C01234567", "topic": "status"}),
        ),
        (
            "slack.handle_events_api",
            json!({"payload": {"type": "url_verification", "challenge": "manifest-parity"}, "signature_result": "verified"}),
        ),
    ];
    assert_eq!(fixtures.len(), 12);
    assert_eq!(fixtures.len(), manifest.provides.operations.len());
    let server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let mut capabilities = manifest
        .provides
        .operations
        .values()
        .map(|operation| operation.capability.as_str())
        .collect::<Vec<_>>();
    capabilities.sort_unstable();
    capabilities.dedup();
    let key = setup_handshake(&mut connector, &capabilities).await;
    let introspection = connector.handle_introspect().await.unwrap();
    let runtime_operations = introspection["operations"].as_array().unwrap();
    assert_eq!(runtime_operations.len(), fixtures.len());

    for (operation_id, input) in fixtures {
        let declaration = manifest
            .provides
            .operations
            .get(operation_id)
            .expect("fixture must exercise a declared operation");
        let runtime = runtime_operations
            .iter()
            .find(|operation| operation["id"] == operation_id)
            .expect("every manifest operation must be introspected");
        assert_eq!(
            runtime["capability"],
            declaration.capability.as_str(),
            "{operation_id}"
        );
        // Take authority from the actual bundled manifest, independently of the
        // connector's runtime mapping; preserve the exact operation restriction.
        let token =
            generate_valid_token_for_operation(&key, declaration.capability.as_str(), operation_id);
        let request = fcp_core::SimulateRequest::new(
            fcp_core::ConnectorId::from_static("fcp.slack"),
            fcp_core::OperationId::from_static(operation_id),
            fcp_core::ZoneId::work(),
            input,
            token,
        );
        let response: fcp_core::SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(serde_json::to_value(request).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            response.would_succeed,
            "{operation_id} rejected manifest authority: {response:?}"
        );
        assert!(response.missing_capabilities.is_empty(), "{operation_id}");
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "simulation must not contact Slack"
    );
}

#[fcp_async_core::runtime::test]
async fn grouped_capabilities_preserve_operation_and_resource_boundaries_before_http() {
    let server = MockServer::start().await;
    let mut connector = SlackConnector::new();
    setup_configure(&mut connector, &server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.read", "slack.write"]).await;
    let input = json!({"channel": "C01234567", "text": "must not be sent"});

    for (case, capability, granted_operation, resource, denial_code) in [
        (
            "correct family, wrong operation",
            "slack.write",
            "slack.reply_thread",
            "slack:channel:C01234567",
            "FCP-3003",
        ),
        (
            "read cannot authorize write",
            "slack.read",
            "slack.post_message",
            "slack:channel:C01234567",
            "FCP-3001",
        ),
        (
            "operation name is not a capability",
            "slack.post_message",
            "slack.post_message",
            "slack:channel:C01234567",
            "FCP-3001",
        ),
        (
            "correct family and operation, wrong resource",
            "slack.write",
            "slack.post_message",
            "slack:channel:COTHER",
            "FCP-3004",
        ),
    ] {
        let constraints = CapabilityConstraints {
            resource_allow: vec![resource.into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        let now = Utc::now();
        let token = fcp_core::CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id(capability)
                .zone_id("z:work")
                .principal("user:test")
                .operations(&[granted_operation])
                .issuer("node:test")
                .target_instance(connector.instance_id())
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&cbor)
                .unwrap()
                .sign(&key)
                .unwrap(),
        );
        let request = fcp_core::SimulateRequest::new(
            fcp_core::ConnectorId::from_static("fcp.slack"),
            fcp_core::OperationId::from_static("slack.post_message"),
            fcp_core::ZoneId::work(),
            input.clone(),
            token.clone(),
        );
        let simulation: fcp_core::SimulateResponse = serde_json::from_value(
            connector
                .handle_simulate(serde_json::to_value(request).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!simulation.would_succeed, "{case}");
        assert_eq!(
            simulation.denial_code.as_deref(),
            Some(denial_code),
            "{case}"
        );
        let error = connector
            .handle_invoke(json!({
                "operation": "slack.post_message", "input": input,
                "capability_token": token,
            }))
            .await
            .expect_err(case);
        assert_eq!(error.error_code(), denial_code, "{case}");
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "{case} reached Slack"
        );
    }
}

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let _key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    // Handshake grants only slack.read
    let key = setup_handshake(&mut connector, &["slack.read"]).await;

    // Token is for slack.read, but we invoke slack.post_message
    let cap = generate_valid_token_for_operation(&key, "slack.read", "slack.read");
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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.nonexistent"]).await;

    let cap = generate_valid_token_for_operation(&key, "slack.nonexistent", "slack.nonexistent");
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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let _key = setup_handshake(&mut connector, &["slack.read"]).await;

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
            "protocol_version": "2.0.0",
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

    let (ack_tx, mut ack_rx) = oneshot::channel::<Option<String>>();
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
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "socket_mode_credential_id": TEST_SOCKET_CREDENTIAL_ID,
            "base_url": mock_server.uri(),
            "monitor_policy": { "require_mention": false }
        }))
        .await
        .expect("configure");

    let native = NativeTestTransport::attach(&mut connector);
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    let subscribe_result = runtime
        .block_on(connector.handle_subscribe(native_subscribe_request(&key, "slack.message.new")))
        .expect("subscribe should succeed");
    assert_eq!(
        subscribe_result["result"]["confirmed_topics"],
        json!(["slack.message.new"])
    );

    let event = native.next_event(0).await;

    assert_eq!(event.topic, "slack.message.new");
    assert_eq!(event.cursor, "Ev01");
    assert_eq!(event.data.principal.kind, "slack_user");
    assert_eq!(event.data.principal.id, "U_EVT_1");
    assert_eq!(event.data.principal.trust, fcp_core::TrustLevel::Untrusted);
    assert_eq!(event.data.zone_id, fcp_core::ZoneId::work());
    assert_eq!(
        event.data.payload["event"]["text"].as_str(),
        Some("hello from socket mode")
    );

    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), &mut ack_rx)
            .await
            .is_err(),
        "reading native stdout must not acknowledge Slack",
    );
    assert!(
        native
            .stream
            .acknowledge(json!({
                "stream_id": NATIVE_TEST_STREAM_ID,
                "ack": fcp_core::EventAck::new(&event.topic, vec![event.seq])
                    .with_cursors(vec!["different-provider-event".into()]),
            }))
            .is_err()
    );
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), &mut ack_rx)
            .await
            .is_err(),
        "a mismatched native ACK must not release provider credit",
    );
    native.acknowledge(&event);

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
async fn socket_mode_closed_native_stream_does_not_acknowledge_provider() {
    let _ctx = AsyncTestContext::for_scenario("slack.socket_mode.closed_native_stream");
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
    let (frame_tx, mut frame_rx) = oneshot::channel::<Result<Option<String>, String>>();
    let ws_task = fcp_async_core::task::spawn(async move {
        let (tcp_stream, _) = listener.accept().await.expect("accept websocket client");
        let mut ws_stream = accept_test_websocket(tcp_stream).await;
        send_json_frame(
            &mut ws_stream,
            json!({
                "envelope_id": "envelope-uncommitted",
                "type": "events_api",
                "payload": {
                    "event_id": "EvUncommitted",
                    "team_id": "T_TEAM_1",
                    "event": {
                        "type": "message",
                        "user": "U_EVT_1",
                        "channel": "C_EVT_1",
                        "text": "preserve this unacknowledged event",
                        "ts": "1700000000.000010"
                    }
                }
            }),
            "send event before downstream closure",
        )
        .await;
        let result = recv_text_frame(&mut ws_stream, "uncommitted provider frame").await;
        let _ = frame_tx.send(result);
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
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "socket_mode_credential_id": TEST_SOCKET_CREDENTIAL_ID,
            "base_url": mock_server.uri(),
            "monitor_policy": { "require_mention": false }
        }))
        .await
        .expect("configure");
    let native = NativeTestTransport::attach(&mut connector);
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    let mut observer = connector.subscribe_events();
    runtime
        .block_on(connector.handle_subscribe(native_subscribe_request(&key, "slack.events")))
        .expect("subscribe should succeed");

    let event = native.next_event(0).await;
    assert_eq!(event.cursor, "EvUncommitted");
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), &mut frame_rx)
            .await
            .is_err(),
        "provider acknowledgement must remain pending before consumer commit",
    );
    native.stream.close();
    let provider_frame = fcp_async_core::time::timeout(StdDuration::from_secs(3), frame_rx)
        .await
        .expect("socket should close after failed native delivery")
        .expect("server should report the final provider frame");
    assert!(
        !matches!(provider_frame, Ok(Some(_))),
        "closed native delivery must not acknowledge the provider: {provider_frame:?}",
    );
    assert!(
        native
            .stream
            .acknowledge(json!({
                "stream_id": NATIVE_TEST_STREAM_ID,
                "ack": fcp_core::EventAck::new(&event.topic, vec![event.seq])
                    .with_cursors(vec![event.cursor.clone()]),
            }))
            .is_err()
    );
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(50), observer.recv())
            .await
            .is_err(),
        "a diagnostic observer must not receive an uncommitted event",
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

    let native = NativeTestTransport::attach(&mut connector);
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    let subscribe_result = runtime
        .block_on(connector.handle_subscribe(native_subscribe_request(&key, "slack.message.new")))
        .expect("subscribe should succeed");
    assert_eq!(
        subscribe_result["result"]["confirmed_topics"],
        json!(["slack.message.new"])
    );

    let ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), ack_rx)
        .await
        .expect("timeout waiting for socket ack")
        .expect("ack channel should complete")
        .expect("ack payload missing");
    let ack_value: serde_json::Value =
        serde_json::from_str(&ack_json).expect("ack should be valid json");
    assert_eq!(ack_value["envelope_id"], "envelope-policy-drop");

    assert!(
        native.is_empty(),
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

    let native = NativeTestTransport::attach(&mut connector);
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    let subscribe_result = runtime
        .block_on(connector.handle_subscribe(native_subscribe_request(&key, "slack.events")))
        .expect("subscribe should succeed");
    assert_eq!(
        subscribe_result["result"]["confirmed_topics"],
        json!(["slack.events"])
    );

    let drop_ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), drop_ack_rx)
        .await
        .expect("timeout waiting for command drop ack")
        .expect("drop ack channel should complete")
        .expect("drop ack payload missing");
    let drop_ack_value: serde_json::Value =
        serde_json::from_str(&drop_ack_json).expect("drop ack should be valid json");
    assert_eq!(drop_ack_value["envelope_id"], "envelope-command-drop");
    assert!(
        native.is_empty(),
        "monitor policy should suppress unauthorized slash command events"
    );

    let _ = slash_go_tx.send(());
    let slash_event = native.next_event(0).await;
    assert_eq!(slash_event.topic, "slack.events");
    assert_eq!(slash_event.data.payload["source_topic"], "slack.command");
    assert_eq!(slash_event.cursor, "envelope-command-allowed");
    assert_eq!(slash_event.data.principal.id, "U_CMD");
    assert_eq!(slash_event.data.payload["event"]["channel_id"], "C_CMD");
    assert!(
        slash_event
            .data
            .resource_uris
            .contains(&"slack:channel:C_CMD".to_string())
    );
    native.acknowledge(&slash_event);
    let slash_ack_json = fcp_async_core::time::timeout(StdDuration::from_secs(3), slash_ack_rx)
        .await
        .expect("timeout waiting for command allowed ack")
        .expect("slash ack channel should complete")
        .expect("slash ack payload missing");
    let slash_ack_value: serde_json::Value =
        serde_json::from_str(&slash_ack_json).expect("slash ack should be valid json");
    assert_eq!(slash_ack_value["envelope_id"], "envelope-command-allowed");

    let _ = interactive_go_tx.send(());
    let interactive_event = native.next_event(1).await;
    assert_eq!(interactive_event.topic, "slack.events");
    assert_eq!(
        interactive_event.data.payload["source_topic"],
        "slack.interactive"
    );
    assert_eq!(interactive_event.cursor, "envelope-interactive-allowed");
    assert_eq!(interactive_event.data.principal.id, "U_CMD");
    assert_eq!(
        interactive_event.data.payload["event"]["channel"]["id"],
        "C_CMD"
    );
    assert!(
        interactive_event
            .data
            .resource_uris
            .contains(&"slack:channel:C_CMD".to_string())
    );
    native.acknowledge(&interactive_event);
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
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "socket_mode_credential_id": TEST_SOCKET_CREDENTIAL_ID,
            "base_url": mock_server.uri()
        }))
        .await
        .expect("configure");

    let _native = NativeTestTransport::attach(&mut connector);
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    let first = runtime
        .block_on(connector.handle_subscribe(native_subscribe_request(&key, "slack.events")))
        .expect("first subscribe should succeed");
    assert_eq!(first["result"]["confirmed_topics"], json!(["slack.events"]));
    fcp_async_core::time::timeout(StdDuration::from_secs(3), connected_rx)
        .await
        .expect("timeout waiting for socket connection")
        .expect("socket connection signal should complete");

    let second = runtime
        .block_on(connector.handle_subscribe(native_subscribe_request(&key, "slack.events")))
        .expect("second subscribe should succeed");
    assert_eq!(
        second["result"]["confirmed_topics"],
        json!(["slack.events"])
    );

    let replacement = runtime
        .block_on(connector.handle_subscribe(native_subscribe_request(&key, "slack.message.new")));
    assert!(
        replacement.is_err(),
        "a different topic cannot replace the live stream"
    );

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
    connector
        .handle_configure(json!({
            "credential_id": TEST_BOT_CREDENTIAL_ID,
            "socket_mode_credential_id": TEST_SOCKET_CREDENTIAL_ID,
            "base_url": fake_server.url(),
            "monitor_policy": { "require_mention": false }
        }))
        .await
        .expect("configure");

    let native = NativeTestTransport::attach(&mut connector);
    let key = setup_handshake(&mut connector, &["slack.read"]).await;
    let subscribe_result = runtime
        .block_on(connector.handle_subscribe(native_subscribe_request(&key, "slack.message.new")))
        .expect("subscribe should succeed");
    assert_eq!(
        subscribe_result["result"]["confirmed_topics"],
        json!(["slack.message.new"])
    );

    fcp_async_core::time::timeout(StdDuration::from_secs(3), first_ws_task)
        .await
        .expect("timeout waiting for first ws task")
        .expect("first ws task join");
    fcp_async_core::time::timeout(StdDuration::from_secs(5), second_connected_rx)
        .await
        .expect("timeout waiting for reconnected socket")
        .expect("reconnected socket signal should complete");

    let event = native.next_event(0).await;
    assert_eq!(event.topic, "slack.message.new");
    assert_eq!(event.cursor, "EvAfterReconnect");
    assert_eq!(event.data.principal.id, "U_EVT_RECONNECT");
    assert_eq!(
        event.data.payload["event"]["text"].as_str(),
        Some("hello after reconnect")
    );
    native.acknowledge(&event);

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.write"]).await;

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
    setup_configure(&mut connector, &mock_server.uri()).await;
    let key = setup_handshake(&mut connector, &["slack.files.write"]).await;

    let cap = generate_valid_token_for_operation(&key, "slack.files.write", "slack.upload_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "slack.upload_file",
            "input": {
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
