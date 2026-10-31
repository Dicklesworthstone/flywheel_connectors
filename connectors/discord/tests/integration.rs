//! Discord connector integration tests (flywheel_connectors-bngd).
//!
//! Deterministic integration tests using wiremock plus structured HTTP fakes
//! to exercise the Discord REST API transport more realistically.
//! No real Discord calls. Covers:
//! - Lifecycle: configure → handshake → invoke
//! - REST operation happy paths (send, edit, delete, get, react, threads)
//! - Error taxonomy (401/403/429/5xx → FCP error mapping)
//! - Capability gating (deny without token, allow with valid token)
//! - Input validation (content length, required fields)
//! - Introspection completeness

#![recursion_limit = "256"]
#![allow(clippy::too_many_lines)]

use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::websocket::{Message as ServerWsMessage, ServerWebSocket, WebSocketAcceptor};
use chrono::{Duration, Utc};
use fcp_async_core::net::TcpListener;
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{CapabilityConstraints, InstanceId};
use fcp_sdk::prelude::{JsonlEventStream, JsonlWriter};
use fcp_sdk::{
    AgentId, ChatCoordinationBackend, ClaimKey, ClaimOutcome, InMemoryThreadOwnershipChecker,
    ThreadOwnershipChecker,
};
use fcp_testkit::LogCapture;
use serde_json::json;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::future::poll_fn;
use std::io::{Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::thread;
use std::time::Duration as StdDuration;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

use fcp_discord::{DiscordConnector, limits as discord_limits};

// ============================================================================
// Constants
// ============================================================================

const INTENT_GUILDS: u64 = 1 << 0;
const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
const INTENT_DIRECT_MESSAGES: u64 = 1 << 12;
const INTENT_MESSAGE_CONTENT: u64 = 1 << 15;

const ALL_REQUIRED_INTENTS: u64 =
    INTENT_GUILDS | INTENT_GUILD_MESSAGES | INTENT_DIRECT_MESSAGES | INTENT_MESSAGE_CONTENT;

// ============================================================================
// Helpers
// ============================================================================

struct BoundTestSigningKey {
    signing_key: Ed25519SigningKey,
    instance_id: InstanceId,
}

fn generate_valid_token(signing_key: &BoundTestSigningKey, op: &str) -> fcp_core::CapabilityToken {
    generate_valid_token_for_principal(signing_key, op, "user:test")
}

fn generate_valid_token_for_principal(
    signing_key: &BoundTestSigningKey,
    op: &str,
    principal: &str,
) -> fcp_core::CapabilityToken {
    let cap = match op {
        "discord.send_message" | "discord.trigger_typing" => "discord.send",
        "discord.edit_message" => "discord.edit",
        "discord.delete_message" => "discord.delete",
        "discord.add_reaction" => "discord.react",
        "discord.create_thread" => "discord.threads",
        _ => "discord.read",
    };
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal(principal)
        .operations(&[op])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .target_instance(signing_key.instance_id.as_ref())
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should be valid")
        .sign(&signing_key.signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
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

fn unique_zone_dir(label: &str) -> String {
    std::env::temp_dir()
        .join("fcp-discord-tests")
        .join(format!("{label}-{}", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned()
}

const NATIVE_STREAM_ID: &str = "discord-integration-stream";

struct NativeCaptureWriter {
    pending: Vec<u8>,
    frames: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl Write for NativeCaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let frame = serde_json::from_slice(&self.pending).map_err(std::io::Error::other)?;
        self.frames.lock().expect("native capture lock").push(frame);
        self.pending.clear();
        Ok(())
    }
}

struct NativeCapture {
    stream: JsonlEventStream,
    frames: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl NativeCapture {
    fn attach(connector: &mut DiscordConnector) -> Self {
        let frames = Arc::new(Mutex::new(Vec::new()));
        let stream = JsonlEventStream::new(JsonlWriter::new(NativeCaptureWriter {
            pending: Vec::new(),
            frames: Arc::clone(&frames),
        }));
        connector
            .attach_event_stream(stream.clone())
            .expect("attach native event writer before handshake");
        Self { stream, frames }
    }

    async fn next_event(&self, index: usize) -> fcp_core::EventEnvelope {
        fcp_async_core::time::timeout(StdDuration::from_secs(5), async {
            loop {
                let frame = self
                    .frames
                    .lock()
                    .expect("native capture lock")
                    .get(index)
                    .cloned();
                if let Some(frame) = frame {
                    assert_eq!(frame["jsonrpc"], "2.0");
                    assert_eq!(frame["method"], "event");
                    assert!(frame.get("id").is_none());
                    assert_eq!(frame["params"]["stream_id"], NATIVE_STREAM_ID);
                    let event: fcp_core::EventEnvelope =
                        serde_json::from_value(frame["params"]["event"].clone())
                            .expect("canonical native event envelope");
                    assert!(event.requires_ack);
                    assert!(!event.cursor.is_empty());
                    assert_eq!(event.data.connector_id.as_str(), "fcp.discord");
                    assert_eq!(event.data.zone_id, fcp_core::ZoneId::work());
                    return event;
                }
                fcp_async_core::time::sleep(StdDuration::from_millis(5)).await;
            }
        })
        .await
        .expect("native event must reach the JSONL transport")
    }

    fn acknowledge(&self, event: &fcp_core::EventEnvelope) {
        self.stream
            .acknowledge(json!({
                "stream_id": NATIVE_STREAM_ID,
                "ack": fcp_core::EventAck::new(&event.topic, vec![event.seq])
                    .with_cursors(vec![event.cursor.clone()]),
            }))
            .expect("acknowledge the exact native event identity");
    }

    fn len(&self) -> usize {
        self.frames.lock().expect("native capture lock").len()
    }
}

fn native_subscription_request(
    signing_key: &BoundTestSigningKey,
    topic: &str,
) -> serde_json::Value {
    native_subscription_request_with_lifetime(signing_key, topic, Duration::hours(1))
}

fn native_subscription_request_with_lifetime(
    signing_key: &BoundTestSigningKey,
    topic: &str,
    lifetime: Duration,
) -> serde_json::Value {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec![format!("discord:events:{topic}")],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize subscription constraints");
    let token = CapabilityTokenBuilder::new()
        .capability_id("discord.read")
        .zone_id("z:work")
        .principal("user:native-consumer")
        .operations(&["discord.subscribe"])
        .issuer("node:test")
        .validity(now, now + lifetime)
        .target_instance(signing_key.instance_id.as_ref())
        .try_constraints_cbor(&cbor)
        .expect("subscription constraints")
        .sign(&signing_key.signing_key)
        .expect("sign subscription");
    json!({
        "type": "subscribe",
        "id": "discord-native-subscribe",
        "stream_id": NATIVE_STREAM_ID,
        "topics": [topic],
        "window_size": 1,
        "capability_token": fcp_core::CapabilityToken::from_raw(token),
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
        401 => "Unauthorized",
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

type TestGatewayWebSocket = ServerWebSocket<fcp_async_core::net::TcpStream>;

async fn read_gateway_websocket_headers<IO: AsyncRead + Unpin>(
    io: &mut IO,
) -> std::io::Result<Vec<u8>> {
    const MAX_HEADERS: usize = 16 * 1024;

    let mut buffer = Vec::with_capacity(1024);
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF before Discord gateway WebSocket handshake completed",
            ));
        }

        buffer.extend_from_slice(&temp[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(buffer);
        }
        if buffer.len() > MAX_HEADERS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Discord gateway WebSocket handshake headers too large",
            ));
        }
    }
}

async fn accept_test_gateway_websocket(
    mut stream: fcp_async_core::net::TcpStream,
) -> TestGatewayWebSocket {
    let request = read_gateway_websocket_headers(&mut stream)
        .await
        .expect("read gateway websocket handshake");
    assert!(
        request.starts_with(b"GET /?v=10&encoding=json HTTP/1.1\r\n"),
        "Gateway URLs must use the canonical root path and explicit protocol parameters"
    );
    WebSocketAcceptor::new()
        .accept(&fcp_async_core::compatibility_cx(), &request, stream)
        .await
        .expect("accept gateway websocket")
}

async fn recv_gateway_payload(ws: &mut TestGatewayWebSocket, context: &str) -> serde_json::Value {
    let message = fcp_async_core::time::timeout(
        StdDuration::from_secs(5),
        ws.recv(&fcp_async_core::compatibility_cx()),
    )
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for {context}"))
    .expect(context)
    .unwrap_or_else(|| panic!("{context} missing"));
    match message {
        ServerWsMessage::Text(text) => serde_json::from_str(&text).expect("gateway payload json"),
        other => panic!("expected text gateway payload for {context}, got {other:?}"),
    }
}

async fn send_gateway_json(
    ws: &mut TestGatewayWebSocket,
    payload: &serde_json::Value,
    context: &str,
) {
    ws.send(
        &fcp_async_core::compatibility_cx(),
        ServerWsMessage::Text(serde_json::to_string(payload).expect("gateway payload serializes")),
    )
    .await
    .expect(context);
}

async fn wait_for_gateway_disconnect(ws: &mut TestGatewayWebSocket) {
    // This fixture waits through the consumer assertions before shutdown.
    // Individual shutdown calls have their own tighter five-second deadline.
    fcp_async_core::time::timeout(StdDuration::from_secs(15), async {
        loop {
            match ws.recv(&fcp_async_core::compatibility_cx()).await {
                Ok(None | Some(ServerWsMessage::Close(_))) | Err(_) => break,
                Ok(Some(ServerWsMessage::Text(text))) => {
                    let payload: serde_json::Value = serde_json::from_str(&text).unwrap();
                    assert_eq!(
                        payload["op"], 1,
                        "only heartbeat frames may precede shutdown"
                    );
                    send_gateway_json(ws, &json!({"op": 11, "d": null}), "heartbeat ACK").await;
                }
                other => panic!("unexpected Gateway frame during shutdown: {other:?}"),
            }
        }
    })
    .await
    .expect("connector shutdown must close the provider WebSocket promptly");
}

fn gateway_hello(interval_ms: u64) -> serde_json::Value {
    json!({
        "op": 10,
        "d": { "heartbeat_interval": interval_ms },
        "s": null,
        "t": null,
    })
}

fn gateway_dispatch(
    event_name: &str,
    sequence: u64,
    data: &serde_json::Value,
) -> serde_json::Value {
    json!({
        "op": 0,
        "d": data,
        "s": sequence,
        "t": event_name,
    })
}

async fn mock_current_user_ok(mock_server: &MockServer, token: &str) {
    mock_current_user_ok_with_id(mock_server, token, "123456789").await;
}

async fn mock_current_user_ok_with_id(mock_server: &MockServer, token: &str, user_id: &str) {
    Mock::given(method("GET"))
        .and(path("/users/@me"))
        .and(header("Authorization", format!("Bot {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": user_id,
            "username": "TestBot",
            "discriminator": "0",
            "bot": true
        })))
        .mount(mock_server)
        .await;
}

async fn setup_configure(connector: &mut DiscordConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": base_url,
            // Keep Gateway attempts isolated from the REST fixture when a
            // test explicitly opens a native event subscription.
            "gateway_url": "ws://127.0.0.1:1/",
            "intents": ALL_REQUIRED_INTENTS
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_handshake(connector: &mut DiscordConnector, caps: &[&str]) -> BoundTestSigningKey {
    let zone_dir = unique_zone_dir("integration-handshake");
    setup_handshake_in_zone_dir(connector, caps, &zone_dir).await
}

async fn setup_handshake_in_zone_dir(
    connector: &mut DiscordConnector,
    caps: &[&str],
    zone_dir: &str,
) -> BoundTestSigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "zone_dir": zone_dir,
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("handshake should succeed");

    BoundTestSigningKey {
        signing_key,
        instance_id: connector.instance_id().clone(),
    }
}

fn native_source(event: &fcp_core::EventEnvelope) -> (&str, &serde_json::Value) {
    assert_eq!(event.topic, "discord.events");
    (
        event.data.payload["source_topic"]
            .as_str()
            .expect("aggregate source topic"),
        &event.data.payload["event"],
    )
}

fn gateway_checkpoint(zone_dir: &str) -> Option<serde_json::Value> {
    let path = std::path::Path::new(zone_dir).join("discord_gateway_state.json");
    match std::fs::read(path) {
        Ok(bytes) => Some(serde_json::from_slice(&bytes).expect("atomic gateway checkpoint JSON")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot read gateway checkpoint: {error}"),
    }
}

async fn wait_for_gateway_checkpoint(zone_dir: &str, sequence: u64) -> serde_json::Value {
    fcp_async_core::time::timeout(StdDuration::from_secs(5), async {
        loop {
            if let Some(checkpoint) = gateway_checkpoint(zone_dir)
                && checkpoint["sequence"].as_u64() == Some(sequence)
            {
                return checkpoint;
            }
            fcp_async_core::time::sleep(StdDuration::from_millis(5)).await;
        }
    })
    .await
    .expect("consumer acknowledgement must durably commit its provider sequence")
}

async fn wait_for_native_gateway_failure(
    connector: &DiscordConnector,
    capture: &NativeCapture,
) -> fcp_core::HealthSnapshot {
    fcp_async_core::time::timeout(StdDuration::from_secs(5), async {
        loop {
            let health: fcp_core::HealthSnapshot = serde_json::from_value(
                connector
                    .handle_native_health()
                    .await
                    .expect("native health"),
            )
            .expect("canonical health snapshot");
            if !capture.stream.is_open()
                && health.details.as_ref().is_some_and(|details| {
                    details["gateway_failure"]
                        .as_str()
                        .is_some_and(|reason| !reason.is_empty())
                })
            {
                assert!(matches!(
                    &health.status,
                    fcp_core::HealthState::Degraded { .. }
                ));
                return health;
            }
            fcp_async_core::time::sleep(StdDuration::from_millis(5)).await;
        }
    })
    .await
    .expect("invalid provider URLs must close the stream and expose a terminal recovery failure")
}

/// Full lifecycle: configure + mock user + handshake.
async fn setup_full(
    connector: &mut DiscordConnector,
    mock_server: &MockServer,
    caps: &[&str],
) -> BoundTestSigningKey {
    mock_current_user_ok(mock_server, "test_token").await;
    setup_configure(connector, &mock_server.uri()).await;
    setup_handshake(connector, caps).await
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_handshake_health() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();

    mock_current_user_ok(&mock_server, "test_token").await;

    let config_result = connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": mock_server.uri(),
            "intents": ALL_REQUIRED_INTENTS
        }))
        .await
        .expect("configure should succeed");

    assert_eq!(config_result["status"], "configured");
    assert_eq!(config_result["provisioning"]["token_ok"], true);

    let health = connector
        .handle_health()
        .await
        .expect("health should succeed");
    // Health reports "ready" when configured
    assert_eq!(health["status"], "ready");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect_operations() {
    let connector = DiscordConnector::new();

    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let operations = introspection["operations"].as_array().unwrap();
    // 6 original + 3 new = 9 operations
    assert_eq!(
        operations.len(),
        9,
        "expected 9 operations, got {}: {:?}",
        operations.len(),
        operations
            .iter()
            .map(|o| o["id"].as_str().unwrap_or("?"))
            .collect::<Vec<_>>()
    );

    let op_ids: Vec<&str> = operations
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();

    assert!(op_ids.contains(&"discord.send_message"));
    assert!(op_ids.contains(&"discord.edit_message"));
    assert!(op_ids.contains(&"discord.delete_message"));
    assert!(op_ids.contains(&"discord.get_channel"));
    assert!(op_ids.contains(&"discord.get_guild"));
    assert!(op_ids.contains(&"discord.trigger_typing"));
    assert!(op_ids.contains(&"discord.add_reaction"));
    assert!(op_ids.contains(&"discord.list_channels"));
    assert!(op_ids.contains(&"discord.create_thread"));

    // Verify events
    let events = introspection["events"].as_array().unwrap();
    assert!(!events.is_empty());
}

// ============================================================================
// Send Message Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn send_message_happy_path() {
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| match idx {
        0 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/users/@me");
            assert_eq!(
                request.headers.get("authorization").map(String::as_str),
                Some("Bot test_token")
            );
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "123456789",
                    "username": "TestBot",
                    "discriminator": "0",
                    "bot": true
                }),
            )
        }
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            assert_eq!(
                request.headers.get("authorization").map(String::as_str),
                Some("Bot test_token")
            );
            assert_eq!(
                request.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord send body json");
            assert_eq!(body["content"], "Hello Discord!");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "100000000000000001",
                    "channel_id": "111",
                    "content": "Hello Discord!",
                    "timestamp": "2026-03-02T12:00:00.000000+00:00",
                    "author": {"id": "123456789", "username": "TestBot", "discriminator": "0"}
                }),
            )
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    setup_configure(&mut connector, fake_server.url()).await;
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "Hello Discord!"
            },
            "capability_token": token
        }))
        .await
        .expect("send_message should succeed");

    assert_eq!(result["id"], "100000000000000001");
    assert_eq!(result["channel_id"], "111");
    assert_eq!(result["content"], "Hello Discord!");
    assert_eq!(result["delivery"]["status"], "delivered");
    assert_eq!(result["delivery"]["kind"], "final");
    assert_eq!(result["delivery"]["visibility"], "visible");
    assert_eq!(result["delivery"]["final"], true);
    assert_eq!(result["delivery"]["visible"], true);
    assert_eq!(result["delivery"]["message_id"], "100000000000000001");
    assert_eq!(result["delivery"]["reply_to"], serde_json::Value::Null);
    assert_eq!(result["delivery"]["content_present"], true);
    assert_eq!(result["delivery"]["requested_embed_count"], 0);
    assert_eq!(fake_server.requests().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn send_message_reply_denies_duplicate_owner_before_http_send() {
    let fake_server = StructuredFakeHttpServer::spawn(3, |idx, request| match idx {
        0 | 1 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/users/@me");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "123456789",
                    "username": "TestBot",
                    "discriminator": "0",
                    "bot": true
                }),
            )
        }
        2 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord reply body json");
            assert_eq!(body["content"], "agent A reply");
            assert_eq!(body["message_reference"]["message_id"], "222");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "100000000000000031",
                    "channel_id": "111",
                    "content": "agent A reply",
                    "timestamp": "2026-03-02T12:00:00.000000+00:00",
                    "author": {"id": "123456789", "username": "TestBot", "discriminator": "0"}
                }),
            )
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let checker = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut first = DiscordConnector::new()
        .with_thread_ownership_checker(checker.clone(), ChatCoordinationBackend::InMemory);
    let mut second = DiscordConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    setup_configure(&mut first, fake_server.url()).await;
    setup_configure(&mut second, fake_server.url()).await;
    let first_key = setup_handshake(&mut first, &["discord.send"]).await;
    let second_key = setup_handshake(&mut second, &["discord.send"]).await;

    let first_cap =
        generate_valid_token_for_principal(&first_key, "discord.send_message", "agent:a");
    let first_result = first
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "agent A reply",
                "reply_to": "222"
            },
            "capability_token": first_cap
        }))
        .await
        .expect("first owner should send");
    assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(first_result["coordination"][2]["event"], "send_executed");

    let second_cap =
        generate_valid_token_for_principal(&second_key, "discord.send_message", "agent:b");
    let second_error = second
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "agent B reply",
                "reply_to": "222"
            },
            "capability_token": second_cap
        }))
        .await
        .expect_err("second owner should be denied before Discord REST");

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
async fn send_message_fail_open_sends_with_degraded_coordination_audit() {
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| match idx {
        0 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/users/@me");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "123456789",
                    "username": "TestBot",
                    "discriminator": "0",
                    "bot": true
                }),
            )
        }
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "100000000000000032",
                    "channel_id": "111",
                    "content": "fail-open reply",
                    "timestamp": "2026-03-02T12:00:00.000000+00:00",
                    "author": {"id": "123456789", "username": "TestBot", "discriminator": "0"}
                }),
            )
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let checker = Arc::new(IndeterminateThreadOwnershipChecker {
        reason: "agent_mail_unavailable",
    });
    let mut connector = DiscordConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::AgentMail);
    setup_configure(&mut connector, fake_server.url()).await;
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token_for_principal(&signing_key, "discord.send_message", "agent:a");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "fail-open reply",
                "reply_to": "222"
            },
            "capability_token": token
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
    assert_eq!(fake_server.requests().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn send_message_delivery_accounting_logs_without_body_or_token() {
    let capture = LogCapture::new();
    let _guard = capture.install_json_with_filter("info");
    let secret_content = "TopSecretDeliveryBody";

    let fake_server = StructuredFakeHttpServer::spawn(2, move |idx, request| match idx {
        0 => StructuredHttpResponse::json(
            200,
            &json!({
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0",
                "bot": true
            }),
        ),
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord final send body json");
            assert_eq!(body["content"], secret_content);
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "100000000000000021",
                    "channel_id": "111",
                    "content": secret_content,
                    "timestamp": "2026-03-02T12:00:00.000000+00:00",
                    "author": {"id": "123456789", "username": "TestBot", "discriminator": "0"}
                }),
            )
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    setup_configure(&mut connector, fake_server.url()).await;
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": secret_content,
                "delivery": {
                    "kind": "final",
                    "visibility": "visible",
                    "label": "final-answer"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("final send should succeed");

    assert_eq!(result["delivery"]["status"], "delivered");
    assert_eq!(result["delivery"]["label"], "final-answer");
    assert_eq!(result["delivery"]["final"], true);
    assert_eq!(result["delivery"]["visible"], true);

    let logs = capture.jsonl();
    assert!(
        logs.contains("Discord message delivery accounted"),
        "delivery accounting log missing; logs={logs}"
    );
    assert!(
        !logs.contains(secret_content),
        "message body must not be written to delivery logs: {logs}"
    );
    assert!(
        !logs.contains("test_token"),
        "bot token must not be written to delivery logs: {logs}"
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_hidden_progress_suppresses_rest_send() {
    let fake_server = StructuredFakeHttpServer::spawn(1, |idx, request| match idx {
        0 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/users/@me");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "123456789",
                    "username": "TestBot",
                    "discriminator": "0",
                    "bot": true
                }),
            )
        }
        _ => panic!("hidden progress should not issue request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    setup_configure(&mut connector, fake_server.url()).await;
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "working on it",
                "delivery": {
                    "kind": "progress",
                    "visibility": "hidden",
                    "label": "background-progress"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("hidden non-final progress should be accounted without REST");

    assert_eq!(result["id"], serde_json::Value::Null);
    assert_eq!(result["channel_id"], "111");
    assert_eq!(result["delivery"]["status"], "suppressed");
    assert_eq!(result["delivery"]["reason"], "hidden_non_final_update");
    assert_eq!(result["delivery"]["kind"], "progress");
    assert_eq!(result["delivery"]["visibility"], "hidden");
    assert_eq!(result["delivery"]["final"], false);
    assert_eq!(result["delivery"]["visible"], false);
    assert_eq!(result["delivery"]["label"], "background-progress");
    assert_eq!(
        fake_server.requests().len(),
        1,
        "hidden progress must not call Discord REST"
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_rejects_hidden_final_reply_before_rest() {
    let fake_server = StructuredFakeHttpServer::spawn(1, |idx, request| match idx {
        0 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/users/@me");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "123456789",
                    "username": "TestBot",
                    "discriminator": "0",
                    "bot": true
                }),
            )
        }
        _ => panic!("hidden final rejection should not issue request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    setup_configure(&mut connector, fake_server.url()).await;
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let err = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "final answer",
                "delivery": {
                    "kind": "final",
                    "visibility": "hidden"
                }
            },
            "capability_token": token
        }))
        .await
        .expect_err("hidden final replies must be rejected");

    match err {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("hidden") && message.contains("final"),
                "unexpected error: {message}"
            );
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
    assert_eq!(
        fake_server.requests().len(),
        1,
        "invalid final delivery must fail before Discord REST"
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_embeds_only_final_delivery_preserves_rich_payload() {
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| match idx {
        0 => StructuredHttpResponse::json(
            200,
            &json!({
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0",
                "bot": true
            }),
        ),
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord embed send body json");
            assert!(
                body.get("content").is_none(),
                "embeds-only rich payload must not gain synthetic content: {body}"
            );
            assert_eq!(body["embeds"][0]["title"], "Incident summary");
            assert_eq!(body["embeds"][0]["description"], "All systems recovered");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "100000000000000022",
                    "channel_id": "111",
                    "content": "",
                    "timestamp": "2026-03-02T12:00:00.000000+00:00",
                    "author": {"id": "123456789", "username": "TestBot", "discriminator": "0"},
                    "embeds": [{
                        "title": "Incident summary",
                        "description": "All systems recovered"
                    }]
                }),
            )
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    setup_configure(&mut connector, fake_server.url()).await;
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": [{
                    "title": "Incident summary",
                    "description": "All systems recovered"
                }],
                "delivery": {
                    "kind": "final",
                    "label": "rich-final"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("embeds-only final delivery should succeed");

    assert_eq!(result["content"], "");
    assert_eq!(result["embeds"][0]["title"], "Incident summary");
    assert_eq!(result["delivery"]["status"], "delivered");
    assert_eq!(result["delivery"]["label"], "rich-final");
    assert_eq!(result["delivery"]["content_present"], false);
    assert_eq!(result["delivery"]["requested_embed_count"], 1);
    assert_eq!(result["delivery"]["delivered_embed_count"], 1);
}

#[fcp_async_core::runtime::test]
async fn send_message_final_delivery_5xx_is_observable_failure() {
    let capture = LogCapture::new();
    let _guard = capture.install_json_with_filter("warn");
    let final_content = "Final answer that must not be logged";

    let fake_server = StructuredFakeHttpServer::spawn(2, move |idx, request| match idx {
        0 => StructuredHttpResponse::json(
            200,
            &json!({
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0",
                "bot": true
            }),
        ),
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord failed send body json");
            assert_eq!(body["content"], final_content);
            StructuredHttpResponse::json(
                500,
                &json!({
                    "message": "Discord upstream unavailable",
                    "code": 500
                }),
            )
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": fake_server.url(),
            "gateway_url": "ws://127.0.0.1:1/",
            "intents": ALL_REQUIRED_INTENTS,
            "retry": {
                "max_attempts": 0,
                "initial_delay_ms": 10,
                "max_delay_ms": 100,
                "jitter": 0.0
            }
        }))
        .await
        .expect("configure should succeed");
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let err = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": final_content,
                "delivery": {
                    "kind": "final",
                    "visibility": "visible"
                }
            },
            "capability_token": token
        }))
        .await
        .expect_err("final delivery 5xx must be observable failure");

    match err {
        fcp_core::FcpError::External {
            service,
            status_code,
            retryable,
            ..
        } => {
            assert_eq!(service, "discord");
            assert_eq!(status_code, Some(500));
            assert!(retryable, "Discord 5xx should remain retryable");
        }
        other => panic!("expected External 500, got {other:?}"),
    }

    let logs = capture.jsonl();
    assert!(
        logs.contains("Discord visible/final message delivery failed"),
        "final failure log missing; logs={logs}"
    );
    assert!(
        !logs.contains(final_content),
        "failed final body must not be written to delivery logs: {logs}"
    );
    assert!(
        !logs.contains("test_token"),
        "bot token must not be written to delivery logs: {logs}"
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_content_too_long() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let long_content = "a".repeat(discord_limits::MESSAGE_CONTENT_MAX_CHARS + 1);

    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": long_content
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject oversized content");
}

#[fcp_async_core::runtime::test]
async fn send_message_rate_limit_preserves_retry_after() {
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| match idx {
        0 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/users/@me");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "123456789",
                    "username": "TestBot",
                    "discriminator": "0",
                    "bot": true
                }),
            )
        }
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            StructuredHttpResponse {
                status: 429,
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("retry-after".into(), "7".into()),
                ],
                body: json!({
                    "message": "Too Many Requests",
                    "retry_after": 7.0
                })
                .to_string()
                .into_bytes(),
            }
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": fake_server.url(),
            "gateway_url": "ws://127.0.0.1:1/",
            "intents": ALL_REQUIRED_INTENTS,
            "retry": {
                "max_attempts": 0,
                "initial_delay_ms": 10,
                "max_delay_ms": 100,
                "jitter": 0.0
            }
        }))
        .await
        .expect("configure should succeed");
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let err = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "Hello Discord!"
            },
            "capability_token": token
        }))
        .await
        .expect_err("429 response must surface as an error");

    match err {
        fcp_core::FcpError::RateLimited { retry_after_ms, .. } => {
            assert_eq!(retry_after_ms, 7_000);
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn send_message_final_delivery_429_retries_and_accounts_success() {
    let fake_server = StructuredFakeHttpServer::spawn(3, |idx, request| match idx {
        0 => StructuredHttpResponse::json(
            200,
            &json!({
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0",
                "bot": true
            }),
        ),
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            StructuredHttpResponse {
                status: 429,
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("retry-after".into(), "0".into()),
                ],
                body: json!({
                    "message": "Too Many Requests",
                    "retry_after": 0.0
                })
                .to_string()
                .into_bytes(),
            }
        }
        2 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord retry send body json");
            assert_eq!(body["content"], "Retried final answer");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "100000000000000023",
                    "channel_id": "111",
                    "content": "Retried final answer",
                    "timestamp": "2026-03-02T12:00:00.000000+00:00",
                    "author": {"id": "123456789", "username": "TestBot", "discriminator": "0"}
                }),
            )
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": fake_server.url(),
            "gateway_url": "ws://127.0.0.1:1/",
            "intents": ALL_REQUIRED_INTENTS,
            "retry": {
                "max_attempts": 1,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter": 0.0
            }
        }))
        .await
        .expect("configure should succeed");
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "Retried final answer",
                "delivery": {
                    "kind": "final",
                    "visibility": "visible"
                }
            },
            "capability_token": token
        }))
        .await
        .expect("final delivery should retry 429 once and succeed");

    assert_eq!(result["id"], "100000000000000023");
    assert_eq!(result["delivery"]["status"], "delivered");
    assert_eq!(result["delivery"]["final"], true);
    assert_eq!(
        fake_server.requests().len(),
        3,
        "configure plus two POST attempts should be observed"
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_rate_limit_uses_body_retry_after_without_header() {
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| match idx {
        0 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/users/@me");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "123456789",
                    "username": "TestBot",
                    "discriminator": "0",
                    "bot": true
                }),
            )
        }
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            StructuredHttpResponse {
                status: 429,
                headers: vec![("content-type".into(), "application/json".into())],
                body: json!({
                    "message": "Too Many Requests",
                    "retry_after": 1.5
                })
                .to_string()
                .into_bytes(),
            }
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": fake_server.url(),
            "gateway_url": "ws://127.0.0.1:1/",
            "intents": ALL_REQUIRED_INTENTS,
            "retry": {
                "max_attempts": 0,
                "initial_delay_ms": 10,
                "max_delay_ms": 100,
                "jitter": 0.0
            }
        }))
        .await
        .expect("configure should succeed");
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let err = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "Hello Discord!"
            },
            "capability_token": token
        }))
        .await
        .expect_err("body-only 429 response must surface as an error");

    match err {
        fcp_core::FcpError::RateLimited { retry_after_ms, .. } => {
            assert_eq!(retry_after_ms, 1_500);
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn send_message_missing_content_and_embeds() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject empty message");
}

/// Regression (flywheel_connectors-cmkuk): a malformed `embeds` payload
/// (wrong JSON shape — string instead of array, or wrong field types)
/// must surface as `FcpError::InvalidRequest` that explicitly names the
/// `embeds` field, not be silently discarded. Prior to the fix, the
/// connector parsed with `serde_json::from_value(...).ok()` and treated
/// the decode error as `None`, which on `send_message` fell through to
/// the generic "content or embeds required" branch and on `edit_message`
/// proceeded as if no embeds had been supplied at all.
#[fcp_async_core::runtime::test]
async fn send_message_malformed_embeds_returns_typed_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "Hello",
                // Wrong shape: string where an array-of-objects is expected.
                "embeds": "not-an-array"
            },
            "capability_token": token
        }))
        .await;

    let err = result.expect_err("malformed embeds must be rejected, not silently dropped");
    match err {
        fcp_core::FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1003, "expected InvalidRequest code 1003");
            assert!(
                message.contains("embeds"),
                "error must name the `embeds` field for agent debuggability, \
                 got: {message}"
            );
            assert!(
                message.contains("malformed"),
                "error must explicitly mark the payload as malformed so it \
                 cannot be mistaken for the `content or embeds required` \
                 fallback branch, got: {message}"
            );
        }
        other => panic!("Expected InvalidRequest for malformed embeds, got: {other:?}"),
    }
}

/// Regression (flywheel_connectors-cmkuk): `edit_message` must also reject
/// malformed embeds with a typed error. This is the more dangerous
/// branch — previously a bad embeds payload bypassed validation
/// entirely and the edit proceeded as though no embeds had been
/// supplied, so agents could unknowingly clobber valid embed state.
#[fcp_async_core::runtime::test]
async fn edit_message_malformed_embeds_returns_typed_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.edit"]).await;

    let token = generate_valid_token(&signing_key, "discord.edit_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.edit_message",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                // Array-of-primitives instead of array-of-objects:
                // structurally valid JSON, but not a Vec<Embed>.
                "embeds": [1, 2, 3]
            },
            "capability_token": token
        }))
        .await;

    let err = result.expect_err("malformed embeds must be rejected, not silently dropped");
    match err {
        fcp_core::FcpError::InvalidRequest { code, message } => {
            assert_eq!(code, 1003, "expected InvalidRequest code 1003");
            assert!(
                message.contains("embeds") && message.contains("malformed"),
                "error must explicitly flag malformed embeds, got: {message}"
            );
        }
        other => panic!("Expected InvalidRequest for malformed embeds, got: {other:?}"),
    }
}

// ============================================================================
// Edit Message Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn edit_message_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.edit"]).await;

    Mock::given(method("PATCH"))
        .and(path("/channels/111/messages/100000000000000001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000001",
            "channel_id": "111",
            "content": "Edited content",
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.edit_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.edit_message",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "content": "Edited content"
            },
            "capability_token": token
        }))
        .await
        .expect("edit should succeed");

    assert_eq!(result["id"], "100000000000000001");
    assert_eq!(result["content"], "Edited content");
}

// ============================================================================
// Delete Message Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn delete_message_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.delete"]).await;

    Mock::given(method("DELETE"))
        .and(path("/channels/111/messages/100000000000000001"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.delete_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.delete_message",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001"
            },
            "capability_token": token
        }))
        .await
        .expect("delete should succeed");

    assert_eq!(result["deleted"], true);
}

// ============================================================================
// Get Channel Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn get_channel_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "111",
            "type": 0,
            "name": "general",
            "guild_id": "999"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await
        .expect("get_channel should succeed");

    assert_eq!(result["id"], "111");
    assert_eq!(result["name"], "general");
}

// ============================================================================
// Get Guild Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn get_guild_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/999"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "999",
            "name": "Test Server",
            "icon": null,
            "owner_id": "300000000000000001"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_guild");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_guild",
            "input": { "guild_id": "999" },
            "capability_token": token
        }))
        .await
        .expect("get_guild should succeed");

    assert_eq!(result["id"], "999");
    assert_eq!(result["name"], "Test Server");
}

// ============================================================================
// Trigger Typing Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn trigger_typing_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    // Note: Discord returns 204 No Content, but the API client uses post<T>()
    // which deserializes the body. Mock returns 200 with JSON to match the client's expectations.
    Mock::given(method("POST"))
        .and(path("/channels/111/typing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.trigger_typing");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.trigger_typing",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await
        .expect("trigger_typing should succeed");

    assert_eq!(result["triggered"], true);
}

// ============================================================================
// Add Reaction Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn add_reaction_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.react"]).await;

    // Use percent-encoded emoji path. The connector encodes emoji bytes.
    // 👍 = U+1F44D = F0 9F 91 8D in UTF-8
    Mock::given(method("PUT"))
        .and(path(
            "/channels/111/messages/100000000000000001/reactions/%F0%9F%91%8D/@me",
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.add_reaction",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "emoji": "👍"
            },
            "capability_token": token
        }))
        .await
        .expect("add_reaction should succeed");

    assert_eq!(result["added"], true);
}

#[fcp_async_core::runtime::test]
async fn add_reaction_missing_emoji() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.react"]).await;

    let token = generate_valid_token(&signing_key, "discord.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.add_reaction",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject missing emoji");
}

// ============================================================================
// List Channels Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn list_channels_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/999/channels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "111", "type": 0, "name": "general"},
            {"id": "222", "type": 0, "name": "random"},
            {"id": "333", "type": 2, "name": "voice-chat"}
        ])))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.list_channels",
            "input": { "guild_id": "999" },
            "capability_token": token
        }))
        .await
        .expect("list_channels should succeed");

    let channels = result["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 3);
    assert_eq!(channels[0]["name"], "general");
}

// ============================================================================
// Create Thread Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn create_thread_happy_path() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages/100000000000000001/threads"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000101",
            "type": 11,
            "name": "Discussion",
            "guild_id": "999"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": "Discussion"
            },
            "capability_token": token
        }))
        .await
        .expect("create_thread should succeed");

    assert_eq!(result["id"], "100000000000000101");
    assert_eq!(result["name"], "Discussion");
}

#[fcp_async_core::runtime::test]
async fn create_thread_name_too_long() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let long_name = "a".repeat(discord_limits::THREAD_NAME_MAX_CHARS + 1);
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": long_name
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "should reject thread name > {} chars",
        discord_limits::THREAD_NAME_MAX_CHARS
    );
}

#[fcp_async_core::runtime::test]
async fn create_thread_empty_name() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": ""
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "should reject empty thread name");
}

// ============================================================================
// Capability Gating Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn invoke_without_capability_token_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    mock_current_user_ok(&mock_server, "test_token").await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Handshake grants capabilities but we don't pass a token in invoke
    let _signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": { "channel_id": "111", "content": "test" }
        }))
        .await;

    assert!(
        result.is_err(),
        "invoke without capability_token should fail"
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_with_wrong_capability_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    // Token is for discord.read, but we're trying to send a message (discord.send)
    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": { "channel_id": "111", "content": "test" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "wrong capability should be denied");
}

// ============================================================================
// Error Taxonomy Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn api_401_maps_to_unauthorized() {
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| match idx {
        0 => {
            assert_eq!(request.path, "/users/@me");
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "123456789",
                    "username": "TestBot",
                    "discriminator": "0",
                    "bot": true
                }),
            )
        }
        1 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/channels/111");
            assert_eq!(
                request.headers.get("authorization").map(String::as_str),
                Some("Bot test_token")
            );
            StructuredHttpResponse::json(401, &json!({"message": "401: Unauthorized", "code": 0}))
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    setup_configure(&mut connector, fake_server.url()).await;
    let signing_key = setup_handshake(&mut connector, &["discord.read"]).await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "401 should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_429_maps_to_rate_limited() {
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| match idx {
        0 => StructuredHttpResponse::json(
            200,
            &json!({
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0",
                "bot": true
            }),
        ),
        1 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/channels/111");
            assert_eq!(
                request.headers.get("authorization").map(String::as_str),
                Some("Bot test_token")
            );
            StructuredHttpResponse {
                status: 429,
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("retry-after".into(), "1".into()),
                ],
                body: json!({"message": "You are being rate limited.", "retry_after": 1.0})
                    .to_string()
                    .into_bytes(),
            }
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    setup_configure(&mut connector, fake_server.url()).await;
    let signing_key = setup_handshake(&mut connector, &["discord.read"]).await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");

    // Use a connector with 0 retries to avoid test slowness
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "429 should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_500_maps_to_external_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"message": "Internal Server Error", "code": 0})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "500 should map to error");
}

// ============================================================================
// Self-Check & Health Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn self_check_passes_when_configured() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    mock_current_user_ok(&mock_server, "test_token").await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Re-mount for self-check (it calls /users/@me again)
    mock_current_user_ok(&mock_server, "test_token").await;

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["details"]["token_ok"], true);
    assert_eq!(result["details"]["intents_ok"], true);
}

// ============================================================================
// Shutdown Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn shutdown_returns_status() {
    let mut connector = DiscordConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");

    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Error Handling Depth Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn api_403_forbidden_maps_to_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Missing Access", "code": 50001})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "403 should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_404_get_channel_maps_to_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Unknown Channel", "code": 10003})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "nonexistent" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "404 on get_channel should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_404_get_guild_maps_to_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/nonexistent"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Unknown Guild", "code": 10004})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_guild");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_guild",
            "input": { "guild_id": "nonexistent" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "404 on get_guild should map to error");
}

#[fcp_async_core::runtime::test]
async fn api_404_edit_message_maps_to_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.edit"]).await;

    Mock::given(method("PATCH"))
        .and(path("/channels/111/messages/gone"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Unknown Message", "code": 10008})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.edit_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.edit_message",
            "input": {
                "channel_id": "111",
                "message_id": "gone",
                "content": "updated"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "404 on edit_message should map to error");
}

#[fcp_async_core::runtime::test]
async fn non_json_error_response_handled() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/channels/111"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_channel");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "non-JSON 502 should still map to error");
}

// ============================================================================
// Input Validation Boundary Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn send_message_exactly_2000_chars_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let content_2000 = "a".repeat(discord_limits::MESSAGE_CONTENT_MAX_CHARS);

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_boundary",
            "channel_id": "111",
            "content": content_2000,
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": content_2000
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "exactly {} chars should be accepted",
        discord_limits::MESSAGE_CONTENT_MAX_CHARS
    );
    assert_eq!(result.unwrap()["id"], "msg_boundary");
}

#[fcp_async_core::runtime::test]
async fn send_message_2001_chars_rejected() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let content_2001 = "a".repeat(discord_limits::MESSAGE_CONTENT_MAX_CHARS + 1);
    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": content_2001
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "{} chars should be rejected",
        discord_limits::MESSAGE_CONTENT_MAX_CHARS + 1
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_exactly_10_embeds_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let embeds: Vec<serde_json::Value> = (0..discord_limits::EMBEDS_MAX_COUNT)
        .map(|i| json!({"title": format!("Embed {i}"), "description": "Short"}))
        .collect();

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_10embeds",
            "channel_id": "111",
            "content": "",
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": embeds
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "exactly {} embeds should be accepted",
        discord_limits::EMBEDS_MAX_COUNT
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_11_embeds_rejected() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let embeds: Vec<serde_json::Value> = (0..=discord_limits::EMBEDS_MAX_COUNT)
        .map(|i| json!({"title": format!("Embed {i}"), "description": "Short"}))
        .collect();

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": embeds
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "{} embeds should be rejected",
        discord_limits::EMBEDS_MAX_COUNT + 1
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_embed_near_4096_description_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let desc = "x".repeat(discord_limits::EMBED_DESCRIPTION_MAX_CHARS);

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_longdesc",
            "channel_id": "111",
            "content": "",
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": [{"description": desc}]
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "embed with {}-char description should be accepted",
        discord_limits::EMBED_DESCRIPTION_MAX_CHARS
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_embed_over_4096_description_rejected() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let desc = "x".repeat(discord_limits::EMBED_DESCRIPTION_MAX_CHARS + 1);
    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": [{"description": desc}]
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "embed with {}-char description should be rejected",
        discord_limits::EMBED_DESCRIPTION_MAX_CHARS + 1
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_total_embed_chars_at_6000_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let desc_at_boundary = "y".repeat(discord_limits::EMBED_TOTAL_MAX_CHARS / 3);
    let embeds: Vec<serde_json::Value> = (0..3)
        .map(|_| json!({"description": desc_at_boundary}))
        .collect();

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "msg_6000",
            "channel_id": "111",
            "content": "",
            "timestamp": "2026-03-02T12:00:00.000000+00:00"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": embeds
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "total embed chars exactly {} should be accepted",
        discord_limits::EMBED_TOTAL_MAX_CHARS
    );
}

#[fcp_async_core::runtime::test]
async fn send_message_total_embed_chars_over_6000_rejected() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let desc_over_boundary = "y".repeat((discord_limits::EMBED_TOTAL_MAX_CHARS / 3) + 1);
    let embeds: Vec<serde_json::Value> = (0..3)
        .map(|_| json!({"description": desc_over_boundary}))
        .collect();

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "embeds": embeds
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "total embed chars over {} should be rejected",
        discord_limits::EMBED_TOTAL_MAX_CHARS
    );
}

#[fcp_async_core::runtime::test]
async fn create_thread_name_exactly_100_chars_accepted() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    let name_100 = "t".repeat(discord_limits::THREAD_NAME_MAX_CHARS);

    Mock::given(method("POST"))
        .and(path("/channels/111/messages/100000000000000001/threads"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000102",
            "type": 11,
            "name": name_100,
            "guild_id": "999"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": name_100
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "thread name of exactly {} chars should be accepted",
        discord_limits::THREAD_NAME_MAX_CHARS
    );
    assert_eq!(result.unwrap()["id"], "100000000000000102");
}

#[fcp_async_core::runtime::test]
async fn add_reaction_custom_emoji_format() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.react"]).await;

    // Custom emoji "pepe:123456" → colon is encoded as %3A
    Mock::given(method("PUT"))
        .and(path(
            "/channels/111/messages/100000000000000001/reactions/pepe%3A123456/@me",
        ))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.add_reaction",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "emoji": "pepe:123456"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_ok(), "custom emoji name:id should be accepted");
    assert_eq!(result.unwrap()["added"], true);
}

// ============================================================================
// Lifecycle Edge-Case Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn health_check_when_not_configured() {
    let connector = DiscordConnector::new();
    let health = connector
        .handle_health()
        .await
        .expect("health should succeed even when not configured");

    assert_eq!(health["status"], "not_configured");
    assert!(health["uptime_ms"].as_u64().is_some());
}

#[fcp_async_core::runtime::test]
async fn self_check_when_not_configured() {
    let connector = DiscordConnector::new();
    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed even when not configured");

    assert_eq!(result["status"], "degraded");
}

#[fcp_async_core::runtime::test]
async fn configure_with_empty_bot_credential_fails() {
    let mut connector = DiscordConnector::new();
    let result = connector
        .handle_configure(json!({
            "bot_credential": "",
            "intents": ALL_REQUIRED_INTENTS
        }))
        .await;

    assert!(result.is_err(), "empty bot_credential should fail");
}

#[fcp_async_core::runtime::test]
async fn configure_with_missing_intents_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    mock_current_user_ok(&mock_server, "test_token").await;

    // Pass intents=0 meaning no required intents are set
    let result = connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": mock_server.uri(),
            "intents": 0
        }))
        .await;

    assert!(result.is_err(), "missing required intents should fail");
}

#[fcp_async_core::runtime::test]
async fn invoke_before_handshake_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    mock_current_user_ok(&mock_server, "test_token").await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Configured but no handshake → no verifier → should fail
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_channel",
            "input": { "channel_id": "111" },
            "capability_token": {
                "raw": vec![0u8; 32]
            }
        }))
        .await;

    assert!(result.is_err(), "invoke before handshake should fail");
}

#[fcp_async_core::runtime::test]
async fn shutdown_clears_state_reinvoke_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let _signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    // Shutdown
    let shutdown_result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(shutdown_result["status"], "shutdown");

    // Try to invoke after shutdown — should still have api_client but verifier
    // is intact; however the gateway tasks are torn down. The key test is that
    // shutdown returned cleanly. A second shutdown should also be idempotent.
    let shutdown_again = connector
        .handle_shutdown(json!({}))
        .await
        .expect("second shutdown should also succeed");
    assert_eq!(shutdown_again["status"], "shutdown");
}

// ============================================================================
// Operation Edge-Case Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn edit_message_with_embeds_only_no_content() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.edit"]).await;

    Mock::given(method("PATCH"))
        .and(path("/channels/111/messages/100000000000000001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000001",
            "channel_id": "111",
            "content": "",
            "timestamp": "2026-03-02T12:00:00.000000+00:00",
            "embeds": [{"title": "Updated embed"}]
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.edit_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.edit_message",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "embeds": [{"title": "Updated embed", "description": "New description"}]
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "edit with embeds only (no content) should succeed"
    );
    assert_eq!(result.unwrap()["id"], "100000000000000001");
}

#[fcp_async_core::runtime::test]
async fn send_message_with_reply_to() {
    let fake_server = StructuredFakeHttpServer::spawn(2, |idx, request| match idx {
        0 => StructuredHttpResponse::json(
            200,
            &json!({
                "id": "123456789",
                "username": "TestBot",
                "discriminator": "0",
                "bot": true
            }),
        ),
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/111/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord reply send body json");
            assert_eq!(body["content"], "This is a reply");
            assert_eq!(
                body["message_reference"]["message_id"],
                "100000000000000003"
            );
            assert_eq!(
                body["message_reference"]["fail_if_not_exists"], false,
                "reply sends should keep final content deliverable when the target disappeared"
            );
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "100000000000000011",
                    "channel_id": "111",
                    "content": "This is a reply",
                    "timestamp": "2026-03-02T12:00:00.000000+00:00"
                }),
            )
        }
        _ => panic!("unexpected request index {idx}"),
    });
    let mut connector = DiscordConnector::new();
    setup_configure(&mut connector, fake_server.url()).await;
    let signing_key = setup_handshake(&mut connector, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "This is a reply",
                "reply_to": "100000000000000003"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_ok(), "send_message with reply_to should succeed");
    let result = result.unwrap();
    assert_eq!(result["id"], "100000000000000011");
    assert_eq!(result["delivery"]["reply_to"], "100000000000000003");
    assert_eq!(result["delivery"]["reply_to_fail_if_not_exists"], false);
}

#[fcp_async_core::runtime::test]
async fn delete_message_returns_deleted_true() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.delete"]).await;

    Mock::given(method("DELETE"))
        .and(path("/channels/222/messages/100000000000000002"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.delete_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.delete_message",
            "input": {
                "channel_id": "222",
                "message_id": "100000000000000002"
            },
            "capability_token": token
        }))
        .await
        .expect("delete should succeed");

    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn list_channels_empty_guild() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/200000000000000001/channels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.list_channels");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.list_channels",
            "input": { "guild_id": "200000000000000001" },
            "capability_token": token
        }))
        .await
        .expect("list_channels on empty guild should succeed");

    let channels = result["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 0, "empty guild should return empty array");
}

#[fcp_async_core::runtime::test]
async fn get_guild_with_detailed_fields() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/200000000000000002"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "200000000000000002",
            "name": "Detailed Server",
            "icon": "abc123icon",
            "owner_id": "300000000000000002"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_guild");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_guild",
            "input": { "guild_id": "200000000000000002" },
            "capability_token": token
        }))
        .await
        .expect("get_guild with detailed fields should succeed");

    assert_eq!(result["id"], "200000000000000002");
    assert_eq!(result["name"], "Detailed Server");
    assert_eq!(result["icon"], "abc123icon");
    assert_eq!(result["owner_id"], "300000000000000002");
}

#[fcp_async_core::runtime::test]
async fn unknown_operation_fails() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    let token = generate_valid_token(&signing_key, "discord.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "unknown operation should fail");
}

#[fcp_async_core::runtime::test]
async fn send_message_with_embeds_and_content() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000012",
            "channel_id": "111",
            "content": "Check this out",
            "timestamp": "2026-03-02T12:00:00.000000+00:00",
            "embeds": [{"title": "Info"}]
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "Check this out",
                "embeds": [{"title": "Info", "description": "Details here"}]
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "send with both content and embeds should succeed"
    );
    assert_eq!(result.unwrap()["id"], "100000000000000012");
}

// ============================================================================
// Introspection Depth Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn introspect_operations_have_schemas() {
    let connector = DiscordConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let operations = introspection["operations"].as_array().unwrap();
    for op in operations {
        let op_id = op["id"].as_str().unwrap();
        assert!(
            op["input_schema"].is_object(),
            "operation {op_id} should have input_schema"
        );
        assert!(
            op["output_schema"].is_object(),
            "operation {op_id} should have output_schema"
        );
        assert!(
            op["summary"].is_string(),
            "operation {op_id} should have summary"
        );
        assert!(
            op["capability"].is_string(),
            "operation {op_id} should have capability"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn introspect_event_caps() {
    let connector = DiscordConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    // Verify event capabilities
    let event_caps = &introspection["event_caps"];
    assert_eq!(event_caps["streaming"], true);
    assert_eq!(event_caps["replay"], false);
}

#[fcp_async_core::runtime::test]
async fn introspect_operation_risk_levels() {
    let connector = DiscordConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let operations = introspection["operations"].as_array().unwrap();
    let op_map: std::collections::HashMap<&str, &serde_json::Value> = operations
        .iter()
        .map(|o| (o["id"].as_str().unwrap(), o))
        .collect();

    // delete_message should be high risk
    assert_eq!(
        op_map["discord.delete_message"]["risk_level"], "high",
        "delete_message should be high risk"
    );

    // get_channel and get_guild should be low risk
    assert_eq!(
        op_map["discord.get_channel"]["risk_level"], "low",
        "get_channel should be low risk"
    );
    assert_eq!(
        op_map["discord.get_guild"]["risk_level"], "low",
        "get_guild should be low risk"
    );
}

// ============================================================================
// Additional Error Taxonomy Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn api_403_on_send_message() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Missing Permissions", "code": 50013})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "111",
                "content": "test"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "403 on send_message should fail");
}

#[fcp_async_core::runtime::test]
async fn api_404_on_delete_message() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.delete"]).await;

    Mock::given(method("DELETE"))
        .and(path("/channels/111/messages/100000000000000004"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Unknown Message", "code": 10008})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.delete_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.delete_message",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000004"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "404 on delete_message should fail");
}

#[fcp_async_core::runtime::test]
async fn api_403_on_add_reaction() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.react"]).await;

    // Any PUT to reactions path returns 403
    Mock::given(method("PUT"))
        .and(path(
            "/channels/111/messages/100000000000000001/reactions/%F0%9F%91%8D/@me",
        ))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Reaction blocked", "code": 90001})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.add_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.add_reaction",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "emoji": "\u{1F44D}"
            },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "403 on add_reaction should fail");
}

#[fcp_async_core::runtime::test]
async fn api_503_maps_to_retryable_error() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    Mock::given(method("GET"))
        .and(path("/guilds/999"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_json(json!({"message": "Service Unavailable", "code": 0})),
        )
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.get_guild");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.get_guild",
            "input": { "guild_id": "999" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err(), "503 should map to error");
}

// ============================================================================
// Subscribe Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn subscribe_confirms_topics() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let capture = NativeCapture::attach(&mut connector);
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    let result: fcp_core::SubscribeResponse = serde_json::from_value(
        connector
            .handle_subscribe(native_subscription_request(&signing_key, "discord.message"))
            .await
            .expect("signed exact-topic subscribe should succeed"),
    )
    .expect("canonical subscription response");

    assert_eq!(result.result.confirmed_topics, vec!["discord.message"]);
    assert!(!result.result.replay_supported);
    assert!(capture.stream.is_open());
    connector.handle_shutdown(json!({})).await.unwrap();
    assert!(!capture.stream.is_open());
}

#[fcp_async_core::runtime::test]
async fn native_subscribe_rejects_invalid_or_insufficient_authority_before_gateway_start() {
    let mock_server = MockServer::start().await;
    mock_current_user_ok(&mock_server, "test_token").await;
    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_url = format!("ws://{}", gateway_listener.local_addr().unwrap());
    let mut connector = DiscordConnector::new();
    let capture = NativeCapture::attach(&mut connector);
    connector
        .handle_configure(json!({
            "bot_credential": "test_token", "api_url": mock_server.uri(),
            "gateway_url": gateway_url, "intents": ALL_REQUIRED_INTENTS,
            "gateway_identify_window_ms": 5,
        }))
        .await
        .unwrap();
    let signing_key = setup_handshake(&mut connector, &["discord.read"]).await;
    let valid = native_subscription_request(&signing_key, "discord.events");
    let mut missing_token = valid.clone();
    missing_token
        .as_object_mut()
        .unwrap()
        .remove("capability_token");
    let mut wrong_operation = valid.clone();
    wrong_operation["capability_token"] =
        serde_json::to_value(generate_valid_token(&signing_key, "discord.get_message")).unwrap();
    let mut wrong_capability = valid.clone();
    wrong_capability["capability_token"] =
        serde_json::to_value(generate_valid_token(&signing_key, "discord.send_message")).unwrap();
    let mut narrow_grant = native_subscription_request(&signing_key, "discord.message");
    narrow_grant["topics"] = json!(["discord.events"]);
    let expired = native_subscription_request_with_lifetime(
        &signing_key,
        "discord.events",
        Duration::seconds(-60),
    );
    let mut invalid_requests = vec![
        missing_token,
        wrong_operation,
        wrong_capability,
        narrow_grant,
        expired,
    ];
    for topics in [
        json!([]),
        json!(["discord.*"]),
        json!(["discord.unknown"]),
        json!(["discord.message", "discord.ready"]),
    ] {
        let mut request = valid.clone();
        request["topics"] = topics;
        invalid_requests.push(request);
    }
    for request in invalid_requests {
        assert!(connector.handle_subscribe(request).await.is_err());
        assert!(!capture.stream.is_open());
        assert_eq!(capture.len(), 0);
    }
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), gateway_listener.accept(),)
            .await
            .is_err(),
        "neither handshake nor rejected subscriptions may open the Gateway",
    );
    assert_eq!(mock_server.received_requests().await.unwrap().len(), 1);
    connector.handle_shutdown(json!({})).await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn native_gateway_restart_replays_unacknowledged_dispatch_and_keeps_heartbeats_current() {
    const PRIVATE_SESSION: &str = "session-private-replay-fixture";
    let mock_server = MockServer::start().await;
    mock_current_user_ok_with_id(&mock_server, "test_token", "999").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // A trailing slash must not become a double-slash handshake path, including
    // when the same endpoint is later restored from the READY checkpoint.
    let gateway_url = format!("ws://{}/", listener.local_addr().unwrap());
    let server_gateway_url = gateway_url.clone();
    let (heartbeat_tx, heartbeat_rx) = fcp_async_core::channel::oneshot::channel();
    let gateway_task = fcp_async_core::task::spawn(async move {
        let message = json!({
            "id": "700", "guild_id": "100", "channel_id": "200",
            "content": "replay this message", "author": {"id": "300", "username": "alice"}
        });
        let (socket, _) = listener.accept().await.unwrap();
        let mut first_ws = accept_test_gateway_websocket(socket).await;
        send_gateway_json(&mut first_ws, &gateway_hello(10_000), "first Hello").await;
        assert_eq!(
            recv_gateway_payload(&mut first_ws, "first Identify").await["op"],
            2
        );
        send_gateway_json(
            &mut first_ws,
            &gateway_dispatch(
                "READY",
                1,
                &json!({
                    "v": 10, "user": {"id": "999", "username": "TestBot"},
                    "session_id": PRIVATE_SESSION, "resume_gateway_url": server_gateway_url,
                }),
            ),
            "first READY",
        )
        .await;
        send_gateway_json(
            &mut first_ws,
            &gateway_dispatch("MESSAGE_CREATE", 2, &message),
            "unacknowledged dispatch",
        )
        .await;
        send_gateway_json(
            &mut first_ws,
            &json!({"op": 1, "d": null}),
            "request heartbeat",
        )
        .await;
        let heartbeat =
            recv_gateway_payload(&mut first_ws, "heartbeat while native ACK is pending").await;
        assert_eq!(heartbeat["op"], 1);
        assert_eq!(
            heartbeat["d"], 2,
            "heartbeat must track received frames, not consumer commits"
        );
        send_gateway_json(
            &mut first_ws,
            &json!({"op": 11, "d": null}),
            "heartbeat ACK",
        )
        .await;
        heartbeat_tx.send(()).unwrap();
        wait_for_gateway_disconnect(&mut first_ws).await;

        let (socket, _) = listener.accept().await.unwrap();
        let mut resumed_ws = accept_test_gateway_websocket(socket).await;
        send_gateway_json(&mut resumed_ws, &gateway_hello(10_000), "second Hello").await;
        let resume = recv_gateway_payload(&mut resumed_ws, "restart Resume").await;
        assert_eq!(resume["op"], 6);
        assert_eq!(resume["d"]["session_id"], PRIVATE_SESSION);
        assert_eq!(
            resume["d"]["seq"], 1,
            "resume must not skip the unacknowledged dispatch"
        );
        send_gateway_json(
            &mut resumed_ws,
            &gateway_dispatch("MESSAGE_CREATE", 2, &message),
            "provider replay",
        )
        .await;
        wait_for_gateway_disconnect(&mut resumed_ws).await;
    });

    let zone_dir = unique_zone_dir("native-replay");
    let config = json!({
        "bot_credential": "test_token", "api_url": mock_server.uri(),
        "gateway_url": gateway_url, "intents": ALL_REQUIRED_INTENTS,
        "gateway_identify_window_ms": 5,
        "inbound_policy": {
            "require_mention_in_guilds": false,
            "allowed_guilds": ["100"], "allowed_channels": ["200"], "allowed_users": ["300"],
        },
    });
    let mut first = DiscordConnector::new();
    let first_capture = NativeCapture::attach(&mut first);
    first.handle_configure(config.clone()).await.unwrap();
    let first_key = setup_handshake_in_zone_dir(&mut first, &["discord.read"], &zone_dir).await;
    first
        .handle_subscribe(native_subscription_request(&first_key, "discord.events"))
        .await
        .unwrap();
    let ready = first_capture.next_event(0).await;
    assert_eq!(native_source(&ready).0, "discord.ready");
    assert!(
        !serde_json::to_string(&ready)
            .unwrap()
            .contains(PRIVATE_SESSION)
    );
    assert!(
        !serde_json::to_string(&ready)
            .unwrap()
            .contains("resume_gateway_url")
    );
    assert!(
        gateway_checkpoint(&zone_dir)
            .is_none_or(|checkpoint| { checkpoint["sequence"].as_u64().unwrap_or(0) < 1 }),
        "READY must not be committed before its native ACK"
    );
    first_capture.acknowledge(&ready);
    wait_for_gateway_checkpoint(&zone_dir, 1).await;

    let pending = first_capture.next_event(1).await;
    assert_eq!(native_source(&pending).0, "discord.message");
    assert_eq!(native_source(&pending).1["id"], "700");
    assert!(!pending.cursor.contains(PRIVATE_SESSION));
    fcp_async_core::time::timeout(StdDuration::from_secs(5), heartbeat_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gateway_checkpoint(&zone_dir).unwrap()["sequence"], 1);
    for ack in [
        fcp_core::EventAck::new(&pending.topic, vec![pending.seq + 1])
            .with_cursors(vec![pending.cursor.clone()]),
        fcp_core::EventAck::new(&pending.topic, vec![pending.seq])
            .with_cursors(vec!["wrong-cursor".into()]),
    ] {
        assert!(
            first_capture
                .stream
                .acknowledge(json!({
                    "stream_id": NATIVE_STREAM_ID, "ack": ack,
                }))
                .is_err()
        );
        assert_eq!(gateway_checkpoint(&zone_dir).unwrap()["sequence"], 1);
    }
    fcp_async_core::time::timeout(StdDuration::from_secs(5), first.handle_shutdown(json!({})))
        .await
        .expect("pending native ACK must not block shutdown")
        .unwrap();
    assert!(!first_capture.stream.is_open());
    assert_eq!(gateway_checkpoint(&zone_dir).unwrap()["sequence"], 1);

    let mut restarted = DiscordConnector::new();
    let restarted_capture = NativeCapture::attach(&mut restarted);
    restarted.handle_configure(config).await.unwrap();
    let restarted_key =
        setup_handshake_in_zone_dir(&mut restarted, &["discord.read"], &zone_dir).await;
    restarted
        .handle_subscribe(native_subscription_request(
            &restarted_key,
            "discord.events",
        ))
        .await
        .unwrap();
    let replay = restarted_capture.next_event(0).await;
    assert_eq!(replay.cursor, pending.cursor);
    assert_eq!(replay.data.payload, pending.data.payload);
    assert_eq!(
        serde_json::to_value(&replay.data.principal).unwrap(),
        serde_json::to_value(&pending.data.principal).unwrap()
    );
    assert_eq!(replay.data.resource_uris, pending.data.resource_uris);
    assert_eq!(replay.data.thread_info, pending.data.thread_info);
    assert_eq!(replay.stream_key, pending.stream_key);
    assert_eq!(replay.ordering, pending.ordering);
    assert_ne!(replay.data.instance_id, pending.data.instance_id);
    assert_eq!(gateway_checkpoint(&zone_dir).unwrap()["sequence"], 1);
    restarted_capture.acknowledge(&replay);
    wait_for_gateway_checkpoint(&zone_dir, 2).await;
    fcp_async_core::time::timeout(
        StdDuration::from_secs(5),
        restarted.handle_shutdown(json!({})),
    )
    .await
    .expect("acknowledged stream must shut down promptly")
    .unwrap();
    assert_eq!(gateway_checkpoint(&zone_dir).unwrap()["sequence"], 2);
    fcp_async_core::time::timeout(StdDuration::from_secs(5), gateway_task)
        .await
        .expect("both provider connections must finish")
        .unwrap();
    assert_eq!(mock_server.received_requests().await.unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn native_gateway_discovery_cannot_authorize_an_unconfigured_loopback_origin() {
    let mock_server = MockServer::start().await;
    mock_current_user_ok(&mock_server, "test_token").await;
    let unapproved_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unapproved_url = format!("ws://{}", unapproved_listener.local_addr().unwrap());
    Mock::given(method("GET"))
        .and(path("/gateway/bot"))
        .and(header("Authorization", "Bot test_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "url": unapproved_url,
        })))
        .mount(&mock_server)
        .await;

    let mut connector = DiscordConnector::new();
    let capture = NativeCapture::attach(&mut connector);
    connector
        .handle_configure(json!({
            "bot_credential": "test_token", "api_url": mock_server.uri(),
            "intents": ALL_REQUIRED_INTENTS, "gateway_identify_window_ms": 5,
        }))
        .await
        .unwrap();
    let zone_dir = unique_zone_dir("unapproved-gateway-discovery");
    let key = setup_handshake_in_zone_dir(&mut connector, &["discord.read"], &zone_dir).await;
    connector
        .handle_subscribe(native_subscription_request(&key, "discord.events"))
        .await
        .unwrap();

    let health = wait_for_native_gateway_failure(&connector, &capture).await;
    let health_json = serde_json::to_string(&health).unwrap();
    assert!(!health_json.contains(&unapproved_url));
    assert!(!health_json.contains("test_token"));
    assert_eq!(capture.len(), 0);
    assert!(gateway_checkpoint(&zone_dir).is_none());
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), unapproved_listener.accept(),)
            .await
            .is_err(),
        "a loopback REST fixture must not authorize a discovered Gateway connection",
    );
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        2,
        "discovery rejection must not retry or fall back"
    );
    assert_eq!(requests[0].url.path(), "/users/@me");
    assert_eq!(requests[1].url.path(), "/gateway/bot");
    fcp_async_core::time::timeout(
        StdDuration::from_secs(5),
        connector.handle_shutdown(json!({})),
    )
    .await
    .unwrap()
    .unwrap();
}

#[fcp_async_core::runtime::test]
async fn native_gateway_rejects_foreign_ready_resume_url_without_publishing_it() {
    const PRIVATE_SESSION: &str = "rejected-resume-private-session";
    let mock_server = MockServer::start().await;
    mock_current_user_ok_with_id(&mock_server, "test_token", "999").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_url = format!("ws://{}", listener.local_addr().unwrap());
    let unapproved_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unapproved_url = format!("ws://{}", unapproved_listener.local_addr().unwrap());
    let injected_resume_url = unapproved_url.clone();
    let gateway_task = fcp_async_core::task::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = accept_test_gateway_websocket(socket).await;
        send_gateway_json(&mut ws, &gateway_hello(10_000), "Hello").await;
        assert_eq!(recv_gateway_payload(&mut ws, "Identify").await["op"], 2);
        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "READY",
                1,
                &json!({
                    "v": 10, "user": {"id": "999", "username": "TestBot"},
                    "session_id": PRIVATE_SESSION, "resume_gateway_url": injected_resume_url,
                }),
            ),
            "READY with unapproved resume origin",
        )
        .await;
        wait_for_gateway_disconnect(&mut ws).await;
    });

    let mut connector = DiscordConnector::new();
    let capture = NativeCapture::attach(&mut connector);
    connector
        .handle_configure(json!({
            "bot_credential": "test_token", "api_url": mock_server.uri(),
            "gateway_url": gateway_url, "intents": ALL_REQUIRED_INTENTS,
            "gateway_identify_window_ms": 5,
        }))
        .await
        .unwrap();
    let zone_dir = unique_zone_dir("unapproved-ready-resume");
    let key = setup_handshake_in_zone_dir(&mut connector, &["discord.read"], &zone_dir).await;
    connector
        .handle_subscribe(native_subscription_request(&key, "discord.events"))
        .await
        .unwrap();

    let health = wait_for_native_gateway_failure(&connector, &capture).await;
    let health_json = serde_json::to_string(&health).unwrap();
    assert!(!health_json.contains(&unapproved_url));
    assert!(!health_json.contains(PRIVATE_SESSION));
    assert_eq!(
        capture.len(),
        0,
        "an unusable READY must not reach the consumer"
    );
    let checkpoint = gateway_checkpoint(&zone_dir).expect("durable recovery marker");
    assert_eq!(checkpoint["version"], 2);
    assert_eq!(checkpoint["resume_invalidated"], true);
    assert!(checkpoint["sequence"].is_null());
    assert!(checkpoint["session_id"].is_null());
    assert!(checkpoint["resume_url"].is_null());
    let checkpoint_json = serde_json::to_string(&checkpoint).unwrap();
    assert!(!checkpoint_json.contains(&unapproved_url));
    assert!(!checkpoint_json.contains(PRIVATE_SESSION));
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), unapproved_listener.accept(),)
            .await
            .is_err(),
        "READY must not redirect a RESUME token to another loopback service",
    );
    fcp_async_core::time::timeout(
        StdDuration::from_secs(5),
        connector.handle_shutdown(json!({})),
    )
    .await
    .unwrap()
    .unwrap();
    fcp_async_core::time::timeout(StdDuration::from_secs(5), gateway_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mock_server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn native_gateway_rejects_poisoned_checkpoint_url_before_connecting() {
    const PRIVATE_SESSION: &str = "persisted-safe-session";
    let mock_server = MockServer::start().await;
    mock_current_user_ok_with_id(&mock_server, "test_token", "999").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_url = format!("ws://{}", listener.local_addr().unwrap());
    let server_gateway_url = gateway_url.clone();
    let gateway_task = fcp_async_core::task::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = accept_test_gateway_websocket(socket).await;
        send_gateway_json(&mut ws, &gateway_hello(10_000), "Hello").await;
        assert_eq!(recv_gateway_payload(&mut ws, "Identify").await["op"], 2);
        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "READY",
                1,
                &json!({
                    "v": 10, "user": {"id": "999", "username": "TestBot"},
                    "session_id": PRIVATE_SESSION, "resume_gateway_url": server_gateway_url,
                }),
            ),
            "valid READY",
        )
        .await;
        wait_for_gateway_disconnect(&mut ws).await;
    });
    let zone_dir = unique_zone_dir("poisoned-resume-checkpoint");
    let config = json!({
        "bot_credential": "test_token", "api_url": mock_server.uri(),
        "gateway_url": gateway_url, "intents": ALL_REQUIRED_INTENTS,
        "gateway_identify_window_ms": 5,
    });
    let mut first = DiscordConnector::new();
    let first_capture = NativeCapture::attach(&mut first);
    first.handle_configure(config.clone()).await.unwrap();
    let first_key = setup_handshake_in_zone_dir(&mut first, &["discord.read"], &zone_dir).await;
    first
        .handle_subscribe(native_subscription_request(&first_key, "discord.events"))
        .await
        .unwrap();
    let ready = first_capture.next_event(0).await;
    first_capture.acknowledge(&ready);
    wait_for_gateway_checkpoint(&zone_dir, 1).await;
    fcp_async_core::time::timeout(StdDuration::from_secs(5), first.handle_shutdown(json!({})))
        .await
        .unwrap()
        .unwrap();
    fcp_async_core::time::timeout(StdDuration::from_secs(5), gateway_task)
        .await
        .unwrap()
        .unwrap();

    let unapproved_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unapproved_url = format!("ws://{}", unapproved_listener.local_addr().unwrap());
    let checkpoint_path = std::path::Path::new(&zone_dir).join("discord_gateway_state.json");
    let mut checkpoint = gateway_checkpoint(&zone_dir).unwrap();
    checkpoint["resume_url"] = json!(unapproved_url);
    let poisoned_bytes = serde_json::to_vec(&checkpoint).unwrap();
    std::fs::write(&checkpoint_path, &poisoned_bytes).expect("install poisoned fixture URL");

    let mut restarted = DiscordConnector::new();
    let restarted_capture = NativeCapture::attach(&mut restarted);
    restarted.handle_configure(config).await.unwrap();
    let restarted_key =
        setup_handshake_in_zone_dir(&mut restarted, &["discord.read"], &zone_dir).await;
    restarted
        .handle_subscribe(native_subscription_request(
            &restarted_key,
            "discord.events",
        ))
        .await
        .unwrap();
    let health = wait_for_native_gateway_failure(&restarted, &restarted_capture).await;
    let health_json = serde_json::to_string(&health).unwrap();
    assert!(!health_json.contains(&unapproved_url));
    assert!(!health_json.contains(PRIVATE_SESSION));
    assert_eq!(restarted_capture.len(), 0);
    assert_eq!(std::fs::read(&checkpoint_path).unwrap(), poisoned_bytes);
    assert_eq!(gateway_checkpoint(&zone_dir).unwrap()["sequence"], 1);
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), unapproved_listener.accept(),)
            .await
            .is_err(),
        "restoring a checkpoint must not bypass endpoint validation or expose a RESUME token",
    );
    fcp_async_core::time::timeout(
        StdDuration::from_secs(5),
        restarted.handle_shutdown(json!({})),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(std::fs::read(&checkpoint_path).unwrap(), poisoned_bytes);
    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() == "/users/@me")
    );
}

#[fcp_async_core::runtime::test]
async fn native_gateway_expired_authority_cannot_commit_a_pending_dispatch() {
    let mock_server = MockServer::start().await;
    mock_current_user_ok_with_id(&mock_server, "test_token", "999").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_url = format!("ws://{}", listener.local_addr().unwrap());
    let server_gateway_url = gateway_url.clone();
    let gateway_task = fcp_async_core::task::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = accept_test_gateway_websocket(socket).await;
        send_gateway_json(&mut ws, &gateway_hello(10_000), "Hello").await;
        assert_eq!(recv_gateway_payload(&mut ws, "Identify").await["op"], 2);
        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "READY",
                1,
                &json!({
                    "v": 10, "user": {"id": "999", "username": "TestBot"},
                    "session_id": "expiry-session", "resume_gateway_url": server_gateway_url,
                }),
            ),
            "READY",
        )
        .await;
        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "MESSAGE_CREATE",
                2,
                &json!({
                    "id": "701", "channel_id": "200", "content": "must remain replayable",
                    "author": {"id": "300", "username": "alice"},
                }),
            ),
            "pending dispatch",
        )
        .await;
        wait_for_gateway_disconnect(&mut ws).await;
    });
    let mut connector = DiscordConnector::new();
    let capture = NativeCapture::attach(&mut connector);
    connector
        .handle_configure(json!({
            "bot_credential": "test_token", "api_url": mock_server.uri(),
            "gateway_url": gateway_url, "intents": ALL_REQUIRED_INTENTS,
            "gateway_identify_window_ms": 5,
            "inbound_policy": {"allow_dms": true},
        }))
        .await
        .unwrap();
    let zone_dir = unique_zone_dir("native-expired-authority");
    let key = setup_handshake_in_zone_dir(&mut connector, &["discord.read"], &zone_dir).await;
    let mut observer = connector.subscribe_events();
    connector
        .handle_subscribe(native_subscription_request_with_lifetime(
            &key,
            "discord.events",
            Duration::seconds(3),
        ))
        .await
        .unwrap();
    let ready = capture.next_event(0).await;
    capture.acknowledge(&ready);
    wait_for_gateway_checkpoint(&zone_dir, 1).await;
    fcp_async_core::time::timeout(StdDuration::from_secs(3), observer.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let pending = capture.next_event(1).await;
    assert_eq!(native_source(&pending).1["id"], "701");
    fcp_async_core::time::timeout(StdDuration::from_secs(5), async {
        while capture.stream.is_open() {
            fcp_async_core::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .expect("token expiry must interrupt a pending native ACK wait");
    assert!(
        capture
            .stream
            .acknowledge(json!({
                "stream_id": NATIVE_STREAM_ID,
                "ack": fcp_core::EventAck::new(&pending.topic, vec![pending.seq])
                    .with_cursors(vec![pending.cursor.clone()]),
            }))
            .is_err(),
        "an exact but expired ACK must never release provider credit"
    );
    assert_eq!(gateway_checkpoint(&zone_dir).unwrap()["sequence"], 1);
    assert!(
        fcp_async_core::time::timeout(StdDuration::from_millis(100), observer.recv())
            .await
            .is_err()
    );
    fcp_async_core::time::timeout(
        StdDuration::from_secs(5),
        connector.handle_shutdown(json!({})),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(gateway_checkpoint(&zone_dir).unwrap()["sequence"], 1);
    fcp_async_core::time::timeout(StdDuration::from_secs(5), gateway_task)
        .await
        .unwrap()
        .unwrap();
}

#[fcp_async_core::runtime::test]
async fn gateway_inbound_policy_loopback_drops_unauthorized_and_emits_authorized() {
    let mock_server = MockServer::start().await;
    mock_current_user_ok_with_id(&mock_server, "test_token", "999").await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway listener");
    let addr = listener.local_addr().expect("gateway listener addr");
    let gateway_url = format!("ws://{addr}");
    let server_gateway_url = gateway_url.clone();

    let gateway_task = fcp_async_core::task::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept gateway client");
        let mut ws = accept_test_gateway_websocket(socket).await;

        send_gateway_json(&mut ws, &gateway_hello(1_000), "send gateway hello").await;

        let identify = recv_gateway_payload(&mut ws, "client identify").await;
        assert_eq!(identify["op"], 2, "connector must identify before events");

        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "READY",
                1,
                &json!({
                    "v": 10,
                    "user": { "id": "999", "username": "TestBot" },
                    "session_id": "sess-policy",
                    "resume_gateway_url": server_gateway_url,
                }),
            ),
            "send ready",
        )
        .await;

        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "MESSAGE_CREATE",
                2,
                &json!({
                    "id": "message-denied",
                    "guild_id": "100",
                    "channel_id": "200",
                    "content": "not addressed to the bot",
                    "author": { "id": "300", "username": "alice" }
                }),
            ),
            "send unauthorized message",
        )
        .await;

        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "MESSAGE_CREATE",
                3,
                &json!({
                    "id": "message-allowed",
                    "guild_id": "100",
                    "channel_id": "200",
                    "content": "please handle this <@999>",
                    "author": { "id": "300", "username": "alice" }
                }),
            ),
            "send authorized message",
        )
        .await;

        wait_for_gateway_disconnect(&mut ws).await;
    });

    let mut connector = DiscordConnector::new();
    let capture = NativeCapture::attach(&mut connector);
    connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": mock_server.uri(),
            "gateway_url": gateway_url,
            "intents": ALL_REQUIRED_INTENTS,
            // br-x13q4: the IDENTIFY limiter is process-global, so without this
            // the second gateway test in the binary waits out the real 5 s
            // window and blows its own 3 s timeout. `cfg(test)` does not reach
            // integration tests, so the window has to be set here explicitly.
            "gateway_identify_window_ms": 5,
            "inbound_policy": {
                "require_mention_in_guilds": true,
                "allowed_guilds": ["100"],
                "allowed_channels": ["200"],
                "allowed_users": ["300"]
            }
        }))
        .await
        .expect("configure should succeed");

    let mut event_rx = connector.subscribe_events();
    let signing_key = setup_handshake(&mut connector, &["discord.read"]).await;
    connector
        .handle_subscribe(native_subscription_request(&signing_key, "discord.events"))
        .await
        .expect("subscribe should succeed");

    let mut saw_ready = false;
    let mut saw_authorized = false;
    for index in 0..2 {
        let event = capture.next_event(index).await;
        let (source_topic, payload) = native_source(&event);

        assert_ne!(
            payload["id"], "message-denied",
            "unauthorized Discord gateway event leaked through inbound policy"
        );

        match source_topic {
            "discord.ready" => {
                saw_ready = true;
                assert_eq!(event.seq, 1);
                assert!(payload.get("session_id").is_none());
            }
            "discord.message" => {
                saw_authorized = true;
                assert_eq!(event.seq, 2);
                assert_eq!(payload["id"], "message-allowed");
                assert_eq!(event.data.principal.id, "300");
            }
            other => panic!("unexpected Discord gateway event topic {other}"),
        }
        capture.acknowledge(&event);
        fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
            .await
            .expect("post-ACK diagnostic event")
            .expect("diagnostic observer")
            .expect("committed event");
    }

    assert!(saw_ready, "READY event should still be emitted");
    assert!(
        saw_authorized,
        "authorized Discord message should be emitted"
    );

    let extra = fcp_async_core::time::timeout(StdDuration::from_millis(200), event_rx.recv()).await;
    assert!(
        extra.is_err(),
        "only READY and the authorized message should be emitted"
    );
    assert_eq!(capture.len(), 2);

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    gateway_task.await.expect("gateway task should finish");
}

#[fcp_async_core::runtime::test]
async fn gateway_inbound_delivery_loopback_retains_until_visible_send_success() {
    let capture = LogCapture::new();
    let _guard = capture.install_json_with_filter("info");
    let failure_content = "secret_failure_body";
    let final_content = "secret_final_body";
    let mismatch_content = "secret_mismatch_body";
    let after_clear_content = "secret_after_clear_body";

    let fake_server = StructuredFakeHttpServer::spawn(5, move |idx, request| match idx {
        0 => {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/users/@me");
            assert_eq!(
                request.headers.get("authorization").map(String::as_str),
                Some("Bot test_token")
            );
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "999",
                    "username": "TestBot",
                    "discriminator": "0",
                    "bot": true
                }),
            )
        }
        1 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/999/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord mismatch body json");
            assert_eq!(body["content"], mismatch_content);
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "outbound-mismatch",
                    "channel_id": "999",
                    "content": mismatch_content,
                    "timestamp": "2026-03-02T12:00:00.000000+00:00",
                    "author": {"id": "999", "username": "TestBot", "discriminator": "0"}
                }),
            )
        }
        2 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/200/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord failed final body json");
            assert_eq!(body["content"], failure_content);
            StructuredHttpResponse::json(
                500,
                &json!({
                    "message": "Discord upstream unavailable",
                    "code": 500
                }),
            )
        }
        3 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/200/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord success final body json");
            assert_eq!(body["content"], final_content);
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "outbound-success",
                    "channel_id": "200",
                    "content": final_content,
                    "timestamp": "2026-03-02T12:00:00.000000+00:00",
                    "author": {"id": "999", "username": "TestBot", "discriminator": "0"}
                }),
            )
        }
        4 => {
            assert_eq!(request.method, "POST");
            assert_eq!(request.path, "/channels/200/messages");
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("discord after-clear body json");
            assert_eq!(body["content"], after_clear_content);
            StructuredHttpResponse::json(
                200,
                &json!({
                    "id": "outbound-after-clear",
                    "channel_id": "200",
                    "content": after_clear_content,
                    "timestamp": "2026-03-02T12:00:00.000000+00:00",
                    "author": {"id": "999", "username": "TestBot", "discriminator": "0"}
                }),
            )
        }
        _ => panic!("unexpected request index {idx}"),
    });

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway listener");
    let addr = listener.local_addr().expect("gateway listener addr");
    let gateway_url = format!("ws://{addr}");
    let server_gateway_url = gateway_url.clone();

    let gateway_task = fcp_async_core::task::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept gateway client");
        let mut ws = accept_test_gateway_websocket(socket).await;

        send_gateway_json(&mut ws, &gateway_hello(1_000), "send gateway hello").await;

        let identify = recv_gateway_payload(&mut ws, "client identify").await;
        assert_eq!(identify["op"], 2, "connector must identify before events");

        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "READY",
                1,
                &json!({
                    "v": 10,
                    "user": { "id": "999", "username": "TestBot" },
                    "session_id": "sess-delivery",
                    "resume_gateway_url": server_gateway_url,
                }),
            ),
            "send ready",
        )
        .await;

        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "MESSAGE_CREATE",
                2,
                &json!({
                    "id": "message-allowed",
                    "guild_id": "100",
                    "channel_id": "200",
                    "content": "please handle this <@999>",
                    "author": { "id": "300", "username": "alice" }
                }),
            ),
            "send guild message",
        )
        .await;

        send_gateway_json(
            &mut ws,
            &gateway_dispatch(
                "MESSAGE_CREATE",
                3,
                &json!({
                    "id": "message-dm",
                    "channel_id": "201",
                    "content": "dm work item",
                    "author": { "id": "301", "username": "bob" }
                }),
            ),
            "send dm message",
        )
        .await;

        wait_for_gateway_disconnect(&mut ws).await;
    });

    let mut connector = DiscordConnector::new();
    let native_capture = NativeCapture::attach(&mut connector);
    connector
        .handle_configure(json!({
            "bot_credential": "test_token",
            "api_url": fake_server.url(),
            "gateway_url": gateway_url,
            "intents": ALL_REQUIRED_INTENTS,
            // br-x13q4: see the sibling gateway test — the IDENTIFY limiter is
            // process-global and `cfg(test)` does not reach integration tests.
            "gateway_identify_window_ms": 5,
            "retry": {
                "max_attempts": 0,
                "initial_delay_ms": 10,
                "max_delay_ms": 100,
                "jitter": 0.0
            },
            "inbound_policy": {
                "require_mention_in_guilds": true,
                "allow_dms": true,
                "allowed_channels": ["200", "201"],
                "allowed_users": ["300", "301"]
            }
        }))
        .await
        .expect("configure should succeed");

    let mut event_rx = connector.subscribe_events();
    let signing_key = setup_handshake(&mut connector, &["discord.read", "discord.send"]).await;
    connector
        .handle_subscribe(native_subscription_request(&signing_key, "discord.events"))
        .await
        .expect("subscribe should succeed");

    let mut saw_ready = false;
    let mut guild_session_key = None;
    let mut dm_session_key = None;
    for index in 0..3 {
        let event = native_capture.next_event(index).await;
        let (source_topic, payload) = native_source(&event);

        match source_topic {
            "discord.ready" => {
                saw_ready = true;
                assert_eq!(event.seq, 1);
            }
            "discord.message" if payload["id"] == "message-allowed" => {
                assert_eq!(event.seq, 2);
                assert_eq!(event.data.principal.id, "300");
                assert_eq!(payload["fcp_delivery"]["event_kind"], "room_event");
                assert_eq!(payload["fcp_delivery"]["channel_id"], "200");
                assert_eq!(payload["fcp_delivery"]["guild_id"], "100");
                assert_eq!(payload["fcp_delivery"]["message_id"], "message-allowed");
                assert_eq!(
                    payload["fcp_delivery"]["retention"],
                    "pending_until_outbound_delivery"
                );
                guild_session_key = Some(
                    payload["fcp_delivery"]["session_key"]
                        .as_str()
                        .expect("guild fcp_delivery session key")
                        .to_owned(),
                );
            }
            "discord.message" if payload["id"] == "message-dm" => {
                assert_eq!(event.seq, 3);
                assert_eq!(event.data.principal.id, "301");
                assert_eq!(payload["fcp_delivery"]["event_kind"], "direct_message");
                assert_eq!(payload["fcp_delivery"]["channel_id"], "201");
                assert_eq!(payload["fcp_delivery"]["guild_id"], serde_json::Value::Null);
                assert_eq!(payload["fcp_delivery"]["message_id"], "message-dm");
                assert_eq!(
                    payload["fcp_delivery"]["retention"],
                    "pending_until_outbound_delivery"
                );
                dm_session_key = Some(
                    payload["fcp_delivery"]["session_key"]
                        .as_str()
                        .expect("dm fcp_delivery session key")
                        .to_owned(),
                );
            }
            other => panic!(
                "unexpected Discord gateway event topic/payload {other}: {:?}",
                event.data.payload
            ),
        }
        native_capture.acknowledge(&event);
        // The observer is a post-commit barrier only; provider credit comes
        // exclusively from the exact native acknowledgement above.
        fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
            .await
            .expect("post-ACK diagnostic event")
            .expect("diagnostic observer")
            .expect("committed event");
    }

    assert!(saw_ready, "READY event should be emitted");
    let guild_session_key = guild_session_key.expect("guild message should include fcp_delivery");
    let dm_session_key = dm_session_key.expect("DM message should include fcp_delivery");
    assert_ne!(
        guild_session_key, dm_session_key,
        "inbound delivery session keys must distinguish gateway events"
    );

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let hidden = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "200",
                "content": "hidden progress body",
                "delivery": {
                    "kind": "progress",
                    "visibility": "hidden",
                    "inbound_event": {
                        "session_key": guild_session_key.clone()
                    }
                }
            },
            "capability_token": token
        }))
        .await
        .expect("hidden progress should be accounted without REST");
    assert_eq!(hidden["delivery"]["status"], "suppressed");
    assert_eq!(hidden["delivery"]["reason"], "hidden_non_final_update");
    assert_eq!(hidden["delivery"]["inbound_event"]["status"], "pending");
    assert_eq!(
        hidden["delivery"]["inbound_event"]["reason"],
        "discord_send_suppressed"
    );
    assert_eq!(
        fake_server.requests().len(),
        1,
        "hidden progress must not call Discord REST"
    );

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let mismatch = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "999",
                "content": mismatch_content,
                "delivery": {
                    "kind": "final",
                    "visibility": "visible",
                    "inbound_event": {
                        "session_key": guild_session_key.clone()
                    }
                }
            },
            "capability_token": token
        }))
        .await
        .expect("visible send to wrong channel should keep inbound event pending");
    assert_eq!(
        mismatch["delivery"]["inbound_event"]["status"],
        "target_mismatch"
    );
    assert_eq!(
        mismatch["delivery"]["inbound_event"]["expected_channel_id"],
        "200"
    );
    assert_eq!(
        mismatch["delivery"]["inbound_event"]["actual_channel_id"],
        "999"
    );

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let failed = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "200",
                "content": failure_content,
                "delivery": {
                    "kind": "final",
                    "visibility": "visible",
                    "inbound_event": {
                        "session_key": guild_session_key.clone()
                    }
                }
            },
            "capability_token": token
        }))
        .await
        .expect_err("visible final 5xx must be observable and retain inbound event");
    assert!(
        matches!(
            failed,
            fcp_core::FcpError::External {
                service,
                status_code: Some(500),
                ..
            } if service == "discord"
        ),
        "expected Discord External 500"
    );

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let delivered = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "200",
                "content": final_content,
                "delivery": {
                    "kind": "final",
                    "visibility": "visible",
                    "inbound_event": {
                        "session_key": guild_session_key.clone()
                    }
                }
            },
            "capability_token": token
        }))
        .await
        .expect("matching visible final send should mark inbound event delivered");
    assert_eq!(delivered["id"], "outbound-success");
    assert_eq!(
        delivered["delivery"]["inbound_event"]["status"],
        "marked_delivered"
    );
    assert_eq!(
        delivered["delivery"]["inbound_event"]["source_message_id"],
        "message-allowed"
    );
    assert_eq!(
        delivered["delivery"]["inbound_event"]["delivered_message_id"],
        "outbound-success"
    );

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let after_clear = connector
        .handle_invoke(json!({
            "operation": "discord.send_message",
            "input": {
                "channel_id": "200",
                "content": after_clear_content,
                "delivery": {
                    "kind": "final",
                    "visibility": "visible",
                    "inbound_event": {
                        "session_key": guild_session_key
                    }
                }
            },
            "capability_token": token
        }))
        .await
        .expect("send after delivered state is cleared should still send");
    assert_eq!(after_clear["id"], "outbound-after-clear");
    assert_eq!(
        after_clear["delivery"]["inbound_event"]["status"],
        "not_found"
    );
    assert_eq!(
        after_clear["delivery"]["inbound_event"]["reason"],
        "inbound_event_not_pending"
    );

    assert_eq!(
        fake_server.requests().len(),
        5,
        "configure plus four visible REST sends should be observed"
    );

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    gateway_task.await.expect("gateway task should finish");

    let logs = capture.jsonl();
    assert!(
        logs.contains("Discord visible/final message delivery failed"),
        "failure delivery log missing; logs={logs}"
    );
    assert!(
        logs.contains("Discord message delivery accounted"),
        "success delivery log missing; logs={logs}"
    );
    for secret in [
        failure_content,
        final_content,
        mismatch_content,
        after_clear_content,
        "hidden progress body",
        "test_token",
    ] {
        assert!(
            !logs.contains(secret),
            "sensitive delivery value must not be written to logs: {secret}; logs={logs}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn subscribe_empty_topics() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let capture = NativeCapture::attach(&mut connector);
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.read"]).await;

    let mut request = native_subscription_request(&signing_key, "discord.events");
    request["topics"] = json!([]);
    let error = connector
        .handle_subscribe(request)
        .await
        .expect_err("an empty topic set must not open an unscoped Gateway stream");

    assert!(matches!(error, fcp_core::FcpError::InvalidRequest { .. }));
    assert!(!capture.stream.is_open());
    connector.handle_shutdown(json!({})).await.unwrap();
}

// ============================================================================
// Simulate Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn simulate_returns_allowed() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.send"]).await;

    let token = generate_valid_token(&signing_key, "discord.send_message");
    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": "sim-001",
            "connector_id": "discord",
            "operation": "discord.send_message",
            "zone_id": "z:work",
            "input": {
                "channel_id": "111",
                "content": "test"
            },
            "capability_token": token
        }))
        .await
        .expect("simulate should succeed");

    assert_eq!(result["would_succeed"], true);
}

// ============================================================================
// Create Thread Additional Tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn create_thread_with_auto_archive_duration() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    Mock::given(method("POST"))
        .and(path("/channels/111/messages/100000000000000001/threads"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "100000000000000103",
            "type": 11,
            "name": "Archivable Thread",
            "guild_id": "999"
        })))
        .mount(&mock_server)
        .await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "message_id": "100000000000000001",
                "name": "Archivable Thread",
                "auto_archive_duration": 1440
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_ok(),
        "create_thread with auto_archive_duration should succeed"
    );
    assert_eq!(result.unwrap()["name"], "Archivable Thread");
}

#[fcp_async_core::runtime::test]
async fn create_thread_missing_message_id() {
    let mock_server = MockServer::start().await;
    let mut connector = DiscordConnector::new();
    let signing_key = setup_full(&mut connector, &mock_server, &["discord.threads"]).await;

    let token = generate_valid_token(&signing_key, "discord.create_thread");
    let result = connector
        .handle_invoke(json!({
            "operation": "discord.create_thread",
            "input": {
                "channel_id": "111",
                "name": "No Message Thread"
            },
            "capability_token": token
        }))
        .await;

    assert!(
        result.is_err(),
        "create_thread without message_id should fail"
    );
}
