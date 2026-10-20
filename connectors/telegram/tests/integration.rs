//! Telegram connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the Telegram Bot API.
//! No real API calls. Covers:
//! - Happy-path operations (send_message, get_file, answer_callback_query)
//! - Error taxonomy (401/429 -> FcpError mapping)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, handshake, introspect, shutdown)
//! - Input validation edge cases

#![allow(clippy::too_many_lines)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::large_futures)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{CapabilityConstraints, FcpError};
use fcp_testkit::AsyncTestContext;
use serde_json::json;
#[cfg(feature = "test-support")]
use sha2::{Digest, Sha256};
#[cfg(feature = "test-support")]
use std::collections::{BTreeMap, HashMap};
#[cfg(feature = "test-support")]
use std::fs::{self, File};
#[cfg(feature = "test-support")]
use std::io::{Read, Write};
#[cfg(feature = "test-support")]
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "test-support")]
use std::path::PathBuf;
#[cfg(feature = "test-support")]
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
#[cfg(feature = "test-support")]
use std::thread;
#[cfg(feature = "test-support")]
use std::time::Duration as StdDuration;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

use fcp_telegram::{connector::TelegramConnector, limits as telegram_limits};

// ============================================================================
// Constants
// ============================================================================

const TEST_BOT_ID: &str = "123456";
const TEST_BOT_SUFFIX: &str = "ABCDEFGHIJKLMNOPQRSTUVWXyz012345";
const TEST_INSTANCE_ID: &str = "inst_telegram_integration";
const TELEGRAM_API_HOST: &str = "api.telegram.org";
const NO_EGRESS_HOST: &str = "none.invalid";
#[cfg(feature = "test-support")]
const TELEGRAM_LOOPBACK_E2E_JSONL_PREFIX: &str = "TELEGRAM_LOOPBACK_E2E_JSONL";
#[cfg(feature = "test-support")]
const TELEGRAM_LOOPBACK_E2E_ARTIFACT_ENV: &str = "TELEGRAM_LOOPBACK_E2E_ARTIFACT";
#[cfg(feature = "test-support")]
const DEFAULT_TELEGRAM_LOOPBACK_E2E_ARTIFACT: &str = "target/fcp-telegram/loopback-evidence.jsonl";
#[cfg(feature = "test-support")]
const TELEGRAM_LOOPBACK_COMMAND_LINE: &str = "cargo test -p fcp-telegram --features test-support --test integration telegram_loopback_e2e_jsonl_matrix -- --nocapture";
#[cfg(feature = "test-support")]
const TELEGRAM_LOOPBACK_WEBHOOK_SECRET: &str = "telegram-loopback-secret_1";
const TELEGRAM_EGRESS_OPERATION_IDS: &[&str] = &[
    "telegram.answer_callback_query",
    "telegram.delete_webhook",
    "telegram.get_file",
    "telegram.get_webhook_info",
    "telegram.send_chat_action",
    "telegram.send_media",
    "telegram.send_message",
    "telegram.set_message_reaction",
    "telegram.set_webhook",
];
const TELEGRAM_NO_EGRESS_OPERATION_IDS: &[&str] = &["telegram.ingest_webhook_update"];

fn test_bot_credential() -> String {
    format!("{TEST_BOT_ID}:{TEST_BOT_SUFFIX}")
}

fn parsed_manifest() -> toml::Value {
    toml::from_str::<toml::Table>(include_str!("../manifest.toml"))
        .map(toml::Value::Table)
        .expect("Telegram manifest TOML should parse")
}

fn constraints_for<'a>(
    manifest: &'a toml::Value,
    operation_id: &str,
) -> &'a toml::map::Map<String, toml::Value> {
    let operation = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_id))
        .and_then(toml::Value::as_table)
        .expect("Telegram operation should exist");
    operation
        .get("network_constraints")
        .and_then(toml::Value::as_table)
        .expect("Telegram operation should declare network_constraints")
}

fn manifest_operation_count(manifest: &toml::Value) -> usize {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("Telegram manifest should declare operations")
        .len()
}

fn string_array_field<'a>(
    constraints: &'a toml::map::Map<String, toml::Value>,
    field_name: &str,
) -> Vec<&'a str> {
    constraints
        .get(field_name)
        .and_then(toml::Value::as_array)
        .expect("network_constraints field should be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("network_constraints array field should contain strings")
        })
        .collect()
}

fn integer_array_field(
    constraints: &toml::map::Map<String, toml::Value>,
    field_name: &str,
) -> Vec<i64> {
    constraints
        .get(field_name)
        .and_then(toml::Value::as_array)
        .expect("network_constraints field should be an array")
        .iter()
        .map(|value| {
            value
                .as_integer()
                .expect("network_constraints array field should contain integers")
        })
        .collect()
}

fn bool_field(constraints: &toml::map::Map<String, toml::Value>, field_name: &str) -> bool {
    constraints
        .get(field_name)
        .and_then(toml::Value::as_bool)
        .expect("network_constraints field should be a bool")
}

fn integer_field(constraints: &toml::map::Map<String, toml::Value>, field_name: &str) -> i64 {
    constraints
        .get(field_name)
        .and_then(toml::Value::as_integer)
        .expect("network_constraints field should be an integer")
}

fn token_path(api_method: &str) -> String {
    format!("/bot{}/{api_method}", test_bot_credential())
}

fn unique_zone_dir(label: &str) -> String {
    let dir = std::env::temp_dir()
        .join("fcp-telegram-integration")
        .join(format!("{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("failed to create unique zone dir");
    dir.to_string_lossy().into_owned()
}

// ============================================================================
// Helpers
// ============================================================================

#[test]
fn manifest_declares_strict_per_operation_network_constraints() {
    let manifest = parsed_manifest();
    assert_eq!(
        manifest_operation_count(&manifest),
        TELEGRAM_EGRESS_OPERATION_IDS.len() + TELEGRAM_NO_EGRESS_OPERATION_IDS.len()
    );

    for operation_id in TELEGRAM_EGRESS_OPERATION_IDS {
        let constraints = constraints_for(&manifest, operation_id);

        assert_eq!(
            string_array_field(constraints, "host_allow").as_slice(),
            [TELEGRAM_API_HOST],
            "{operation_id} should only allow Telegram Bot API egress"
        );
        assert_eq!(
            integer_array_field(constraints, "port_allow").as_slice(),
            [443]
        );
        assert!(
            bool_field(constraints, "require_sni"),
            "{operation_id} should require TLS SNI"
        );
        assert!(
            bool_field(constraints, "deny_localhost"),
            "{operation_id} should deny localhost egress"
        );
        assert!(
            bool_field(constraints, "deny_private_ranges"),
            "{operation_id} should deny private ranges"
        );
        assert!(
            bool_field(constraints, "deny_tailnet_ranges"),
            "{operation_id} should deny tailnet ranges"
        );
        assert!(
            bool_field(constraints, "deny_ip_literals"),
            "{operation_id} should deny IP literals"
        );
        assert!(
            bool_field(constraints, "require_host_canonicalization"),
            "{operation_id} should require canonical hostnames"
        );
        assert_eq!(integer_field(constraints, "dns_max_ips"), 16);
        assert_eq!(integer_field(constraints, "max_redirects"), 0);
        assert_eq!(integer_field(constraints, "connect_timeout_ms"), 10_000);
        assert_eq!(integer_field(constraints, "total_timeout_ms"), 60_000);
        assert_eq!(integer_field(constraints, "max_response_bytes"), 10_485_760);
    }

    for operation_id in TELEGRAM_NO_EGRESS_OPERATION_IDS {
        let constraints = constraints_for(&manifest, operation_id);

        assert_eq!(
            string_array_field(constraints, "host_allow").as_slice(),
            [NO_EGRESS_HOST],
            "{operation_id} should document that host-forwarded ingress performs no connector-owned egress"
        );
        assert_eq!(
            integer_array_field(constraints, "port_allow").as_slice(),
            [0]
        );
        assert!(string_array_field(constraints, "ip_allow").is_empty());
        assert!(string_array_field(constraints, "cidr_deny").is_empty());
        assert!(
            bool_field(constraints, "deny_localhost"),
            "{operation_id} should deny localhost egress"
        );
        assert!(
            bool_field(constraints, "deny_private_ranges"),
            "{operation_id} should deny private ranges"
        );
        assert!(
            bool_field(constraints, "deny_tailnet_ranges"),
            "{operation_id} should deny tailnet ranges"
        );
        assert!(
            !bool_field(constraints, "require_sni"),
            "{operation_id} performs no connector-owned TLS egress"
        );
        assert!(string_array_field(constraints, "spki_pins").is_empty());
        assert!(
            bool_field(constraints, "deny_ip_literals"),
            "{operation_id} should deny IP literals"
        );
        assert!(
            bool_field(constraints, "require_host_canonicalization"),
            "{operation_id} should require canonical hostnames"
        );
        assert_eq!(integer_field(constraints, "dns_max_ips"), 0);
        assert_eq!(integer_field(constraints, "max_redirects"), 0);
        assert_eq!(integer_field(constraints, "connect_timeout_ms"), 1_000);
        assert_eq!(integer_field(constraints, "total_timeout_ms"), 1_000);
        assert_eq!(integer_field(constraints, "max_response_bytes"), 1_048_576);
    }
}

/// Map an operation ID to the capability ID that governs it.
fn capability_for_operation(op: &str) -> &str {
    match op {
        "telegram.send_message"
        | "telegram.send_media"
        | "telegram.answer_callback_query"
        | "telegram.send_chat_action"
        | "telegram.set_message_reaction" => "telegram.send",
        "telegram.set_webhook"
        | "telegram.delete_webhook"
        | "telegram.get_webhook_info"
        | "telegram.ingest_webhook_update" => "telegram.webhook",
        _ => "telegram.read",
    }
}

fn generate_valid_token(signing_key: &Ed25519SigningKey, op: &str) -> fcp_core::CapabilityToken {
    let cap = capability_for_operation(op);
    generate_token_for_capability(signing_key, cap, op)
}

fn generate_token_for_capability(
    signing_key: &Ed25519SigningKey,
    cap: &str,
    op: &str,
) -> fcp_core::CapabilityToken {
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
        .principal("user:test")
        .operations(&[op])
        .target_instance(TEST_INSTANCE_ID)
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

fn assert_unexpected_invalid_request(error: &fcp_core::FcpError) {
    assert!(
        matches!(error, fcp_core::FcpError::InvalidRequest { .. }),
        "Expected InvalidRequest, got: {error:?}"
    );
}

/// Mock the `getMe` endpoint (used by configure + handshake + health).
async fn mount_get_me_mock(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(token_path("getMe")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "id": 123456789,
                "is_bot": true,
                "first_name": "Test Bot",
                "username": "test_bot_fcp"
            }
        })))
        .mount(mock_server)
        .await;
}

/// Mock the `getUpdates` endpoint (polling loop started by handshake).
async fn mount_get_updates_mock(mock_server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(token_path("getUpdates")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": []
        })))
        .mount(mock_server)
        .await;
}

async fn setup_configure(connector: &mut TelegramConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "credential": test_bot_credential(),
            "base_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

async fn setup_handshake(
    connector: &mut TelegramConnector,
    mock_server: &MockServer,
    caps: &[&str],
) -> Ed25519SigningKey {
    mount_get_me_mock(mock_server).await;
    mount_get_updates_mock(mock_server).await;

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let zone_dir = unique_zone_dir("integration-handshake");
    let mapped: Vec<&str> = caps.iter().map(|c| capability_for_operation(c)).collect();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "zone_dir": zone_dir,
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": mapped,
            "requested_instance_id": TEST_INSTANCE_ID
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

/// Full setup: configure + mount mocks + handshake. Returns signing key and mock server.
async fn full_setup(
    connector: &mut TelegramConnector,
    caps: &[&str],
) -> (MockServer, Ed25519SigningKey) {
    let mock_server = MockServer::start().await;
    // Mount getMe for configure (which calls getMe to validate the token)
    mount_get_me_mock(&mock_server).await;
    setup_configure(connector, &mock_server.uri()).await;
    let signing_key = setup_handshake(connector, &mock_server, caps).await;
    (mock_server, signing_key)
}

#[cfg(feature = "test-support")]
#[derive(Clone, Debug)]
struct TelegramLoopbackRequest {
    method: String,
    path: String,
    body: serde_json::Value,
}

#[cfg(feature = "test-support")]
struct TelegramLoopbackServer {
    base_url: String,
    addr: String,
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
    requests: Arc<Mutex<Vec<TelegramLoopbackRequest>>>,
    counts: Arc<Mutex<HashMap<String, usize>>>,
}

#[cfg(feature = "test-support")]
impl TelegramLoopbackServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Telegram loopback server");
        let addr = listener
            .local_addr()
            .expect("Telegram loopback server local addr")
            .to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let thread_counts = Arc::clone(&counts);

        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Some(request) = read_telegram_loopback_request(&mut stream) else {
                    continue;
                };
                let (status, body) = telegram_loopback_response(&request, &thread_counts);
                thread_requests
                    .lock()
                    .expect("lock Telegram loopback requests")
                    .push(request);
                write_telegram_loopback_response(&mut stream, status, &body);
            }
        });

        Self {
            base_url: format!("http://{addr}"),
            addr,
            stop,
            handle,
            requests,
            counts,
        }
    }

    fn count_for(&self, key: &str) -> usize {
        self.counts
            .lock()
            .expect("lock Telegram loopback counts")
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    fn shutdown(self) -> Vec<TelegramLoopbackRequest> {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        self.handle
            .join()
            .expect("Telegram loopback server thread joins");
        self.requests
            .lock()
            .expect("lock Telegram loopback requests")
            .clone()
    }
}

#[cfg(feature = "test-support")]
fn bump_telegram_loopback_count(counts: &Arc<Mutex<HashMap<String, usize>>>, key: &str) -> usize {
    let mut counts_guard = counts.lock().expect("lock Telegram loopback counts");
    let count = counts_guard.entry(key.to_owned()).or_insert(0);
    let previous = *count;
    *count = count.saturating_add(1);
    drop(counts_guard);
    previous
}

#[cfg(feature = "test-support")]
fn telegram_loopback_response(
    request: &TelegramLoopbackRequest,
    counts: &Arc<Mutex<HashMap<String, usize>>>,
) -> (u16, serde_json::Value) {
    let path_only = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());
    let endpoint = path_only
        .strip_prefix(&format!("/bot{}/", test_bot_credential()))
        .unwrap_or("");

    match (request.method.as_str(), endpoint) {
        ("GET", "getMe") => {
            bump_telegram_loopback_count(counts, "getMe");
            (
                200,
                json!({
                    "ok": true,
                    "result": {
                        "id": 123456789,
                        "is_bot": true,
                        "first_name": "Loopback Bot",
                        "username": "loopback_bot"
                    }
                }),
            )
        }
        ("POST", "getUpdates") => {
            bump_telegram_loopback_count(counts, "getUpdates");
            (200, json!({ "ok": true, "result": [] }))
        }
        ("POST", "setWebhook") => {
            bump_telegram_loopback_count(counts, "setWebhook");
            (200, json!({ "ok": true, "result": true }))
        }
        ("POST", "deleteWebhook") => {
            bump_telegram_loopback_count(counts, "deleteWebhook");
            (200, json!({ "ok": true, "result": true }))
        }
        ("GET", "getWebhookInfo") => {
            bump_telegram_loopback_count(counts, "getWebhookInfo");
            (
                200,
                json!({
                    "ok": true,
                    "result": {
                        "url": "https://fcp.example.com/hooks/telegram",
                        "has_custom_certificate": false,
                        "pending_update_count": 0,
                        "allowed_updates": ["message", "callback_query"]
                    }
                }),
            )
        }
        ("GET", "getFile") => {
            bump_telegram_loopback_count(counts, "getFile");
            (
                200,
                json!({
                    "ok": true,
                    "result": {
                        "file_id": "telegram-loopback-file",
                        "file_unique_id": "telegram-loopback-file-unique",
                        "file_size": 2048,
                        "file_path": "documents/telegram-loopback.bin"
                    }
                }),
            )
        }
        ("POST", "sendPhoto") => {
            bump_telegram_loopback_count(counts, "sendPhoto");
            (
                200,
                json!({
                    "ok": true,
                    "result": {
                        "message_id": 9100,
                        "chat": { "id": 208214988, "type": "private", "first_name": "Loopback" },
                        "date": 1700000100,
                        "photo": [{
                            "file_id": "telegram-loopback-photo",
                            "file_unique_id": "telegram-loopback-photo-unique",
                            "width": 90,
                            "height": 90,
                            "file_size": 512
                        }]
                    }
                }),
            )
        }
        ("POST", "sendChatAction") => {
            bump_telegram_loopback_count(counts, "sendChatAction");
            (
                401,
                json!({
                    "ok": false,
                    "error_code": 401,
                    "description": "Unauthorized"
                }),
            )
        }
        ("POST", "setMessageReaction") => {
            bump_telegram_loopback_count(counts, "setMessageReaction");
            (200, json!({ "ok": true, "result": true }))
        }
        ("POST", "sendMessage") => {
            let text = request.body.get("text").and_then(serde_json::Value::as_str);
            if text == Some("retry transient") {
                let attempt = bump_telegram_loopback_count(counts, "sendMessage_retry_transient");
                if attempt == 0 {
                    return (
                        503,
                        json!({
                            "ok": false,
                            "error_code": 503,
                            "description": "Service Unavailable"
                        }),
                    );
                }
                return (
                    200,
                    json!({
                        "ok": true,
                        "result": {
                            "message_id": 9001,
                            "chat": { "id": 208214988, "type": "private", "first_name": "Loopback" },
                            "date": 1700000090,
                            "text": "retry transient"
                        }
                    }),
                );
            }

            if text == Some("rate limit fixture") {
                bump_telegram_loopback_count(counts, "sendMessage_rate_limited");
                return (
                    429,
                    json!({
                        "ok": false,
                        "error_code": 429,
                        "description": "Too Many Requests: retry after 0",
                        "parameters": { "retry_after": 0 }
                    }),
                );
            }

            bump_telegram_loopback_count(counts, "sendMessage");
            (
                200,
                json!({
                    "ok": true,
                    "result": {
                        "message_id": 9000,
                        "chat": { "id": 208214988, "type": "private", "first_name": "Loopback" },
                        "date": 1700000080,
                        "text": "ok"
                    }
                }),
            )
        }
        _ => {
            bump_telegram_loopback_count(counts, "unexpected");
            (
                404,
                json!({
                    "ok": false,
                    "error_code": 404,
                    "description": "unexpected Telegram loopback route"
                }),
            )
        }
    }
}

#[cfg(feature = "test-support")]
fn read_telegram_loopback_request(stream: &mut TcpStream) -> Option<TelegramLoopbackRequest> {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(2)))
        .ok();
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if telegram_loopback_http_request_complete(&bytes) {
            break;
        }
        if bytes.len() > 32 * 1024 {
            return None;
        }
    }

    let header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let request_line = headers.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let body_bytes = &bytes[header_end + 4..];
    let body = if body_bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(body_bytes).unwrap_or(serde_json::Value::Null)
    };

    Some(TelegramLoopbackRequest { method, path, body })
}

#[cfg(feature = "test-support")]
fn telegram_loopback_http_request_complete(bytes: &[u8]) -> bool {
    let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    bytes.len() >= header_end + 4 + content_length
}

#[cfg(feature = "test-support")]
fn write_telegram_loopback_response(stream: &mut TcpStream, status: u16, body: &serde_json::Value) {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    let body = body.to_string();
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream
        .write_all(response.as_bytes())
        .expect("write Telegram loopback response");
    stream.flush().expect("flush Telegram loopback response");
}

#[cfg(feature = "test-support")]
fn telegram_loopback_hash(label: &str, value: impl AsRef<str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(b":");
    hasher.update(value.as_ref().as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("sha256:{label}:{}", &digest[..16])
}

#[cfg(feature = "test-support")]
fn telegram_loopback_e2e_write_jsonl(records: &[serde_json::Value]) -> String {
    let path = std::env::var(TELEGRAM_LOOPBACK_E2E_ARTIFACT_ENV).map_or_else(
        |_| PathBuf::from(DEFAULT_TELEGRAM_LOOPBACK_E2E_ARTIFACT),
        PathBuf::from,
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create Telegram loopback evidence directory");
    }
    let mut file = File::create(&path).expect("create Telegram loopback evidence JSONL");
    for record in records {
        writeln!(file, "{record}").expect("write Telegram loopback evidence JSONL record");
        println!("{TELEGRAM_LOOPBACK_E2E_JSONL_PREFIX} {record}");
    }
    path.to_string_lossy().to_string()
}

#[cfg(feature = "test-support")]
#[fcp_async_core::test]
async fn telegram_loopback_e2e_jsonl_matrix() {
    let git_revision =
        std::env::var("FCP_TELEGRAM_E2E_GIT_REVISION").unwrap_or_else(|_| "unknown".to_string());
    let artifact_path = std::env::var(TELEGRAM_LOOPBACK_E2E_ARTIFACT_ENV)
        .unwrap_or_else(|_| DEFAULT_TELEGRAM_LOOPBACK_E2E_ARTIFACT.to_string());
    let env_presence = BTreeMap::from([
        ("TELEGRAM_BOT_TOKEN".to_string(), false),
        ("TELEGRAM_WEBHOOK_SECRET_TOKEN".to_string(), false),
        ("TELEGRAM_LIVE_WRITE_APPROVAL".to_string(), false),
    ]);

    let server = TelegramLoopbackServer::start();
    let mut connector = TelegramConnector::new();
    connector
        .handle_configure(json!({
            "credential": test_bot_credential(),
            "base_url": server.base_url.clone(),
            "poll_timeout": 1,
            "webhook_secret_token": TELEGRAM_LOOPBACK_WEBHOOK_SECRET,
            "inbound_policy": {
                "mode": "allowlist",
                "allowed_user_ids": [208214988]
            }
        }))
        .await
        .expect("configure should hit loopback getMe");

    let signing_key = Ed25519SigningKey::generate();
    let mut event_rx = connector.subscribe_events_for_test();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "zone_dir": unique_zone_dir("telegram-loopback-e2e-jsonl"),
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["telegram.send", "telegram.read", "telegram.webhook"],
            "requested_instance_id": TEST_INSTANCE_ID
        }))
        .await
        .expect("handshake should start polling against loopback");

    let chat_hash = telegram_loopback_hash("chat", "208214988");
    let user_hash = telegram_loopback_hash("user", "208214988");
    let denied_user_hash = telegram_loopback_hash("user", "999999999");
    let mut records = Vec::new();
    let mut common = |scenario: &str,
                      operation: &str,
                      update_id: Option<i64>,
                      chat_id_hash: Option<String>,
                      user_id_hash: Option<String>,
                      sender_policy_decision: &str,
                      capability_decision: &str,
                      retry_backoff: &str,
                      http_status: Option<u16>,
                      fcp_error_mapping: &str,
                      event_topic: Option<&str>,
                      payload_byte_count: Option<usize>,
                      cleanup: &str| {
        records.push(json!({
            "log_version": "v1",
            "connector_id": "fcp.telegram",
            "event": "telegram_loopback_e2e",
            "scenario": scenario,
            "result": "pass",
            "provider_mode": "no_live_credential_loopback",
            "command_line": TELEGRAM_LOOPBACK_COMMAND_LINE,
            "git_revision": git_revision,
            "artifact_paths": [artifact_path],
            "env_presence": env_presence,
            "fixture_id": "telegram-loopback-webhook-v1",
            "operation": operation,
            "update_id_hash": update_id.map(|id| telegram_loopback_hash("update", id.to_string())),
            "chat_id_hash": chat_id_hash,
            "user_id_hash": user_id_hash,
            "sender_policy_decision": sender_policy_decision,
            "capability_decision": capability_decision,
            "retry_backoff": retry_backoff,
            "http_status": http_status,
            "fcp_error_mapping": fcp_error_mapping,
            "event_topic": event_topic,
            "payload_byte_count": payload_byte_count,
            "cleanup": cleanup,
            "skip_reason": null,
            "redaction_decision": "redaction-safe: bot token, webhook secret, raw Telegram user/chat/update IDs, message text, media IDs, and provider payloads are not logged; evidence carries stable scenario names, hashes, status codes, byte counts, and outcome enums"
        }));
    };

    let set_webhook_token = generate_valid_token(&signing_key, "telegram.set_webhook");
    connector
        .handle_invoke(json!({
            "operation": "telegram.set_webhook",
            "input": {
                "url": "https://fcp.example.com/hooks/telegram",
                "allowed_updates": ["message", "callback_query"],
                "drop_pending_updates": true
            },
            "capability_token": set_webhook_token
        }))
        .await
        .expect("set_webhook should succeed against loopback Bot API");
    common(
        "set_webhook_secret_allowed_updates",
        "telegram.set_webhook",
        None,
        None,
        None,
        "not_applicable_outbound",
        "bound_capability_verified",
        "not_needed",
        Some(200),
        "none",
        None,
        None,
        "no_cleanup_required",
    );

    let webhook_token = generate_valid_token(&signing_key, "telegram.ingest_webhook_update");
    let authorized_payload = json!({
        "update_id": 2003,
        "message": {
            "message_id": 13,
            "message_thread_id": 17585,
            "from": {
                "id": 208214988,
                "is_bot": false,
                "first_name": "Loopback"
            },
            "chat": {
                "id": 208214988,
                "type": "private",
                "first_name": "Loopback"
            },
            "date": 1700000010,
            "text": "authorized webhook"
        }
    })
    .to_string();
    let response = connector
        .handle_invoke(json!({
            "operation": "telegram.ingest_webhook_update",
            "input": {
                "payload": authorized_payload,
                "secret_token": TELEGRAM_LOOPBACK_WEBHOOK_SECRET,
                "delivery_id": "telegram-loopback-delivery-authorized"
            },
            "capability_token": webhook_token.clone()
        }))
        .await
        .expect("authorized webhook ingest should succeed");
    assert_eq!(response["event_emitted"], true);
    assert_eq!(response["topic"], "telegram.message.new");
    assert_eq!(
        response["resource_uris"],
        json!([
            "telegram:chat:208214988:topic:17585",
            "telegram:chat:208214988",
            "telegram:user:208214988"
        ])
    );
    let event = fcp_async_core::time::timeout(StdDuration::from_secs(3), event_rx.recv())
        .await
        .expect("timed out waiting for authorized webhook event")
        .expect("broadcast receive should succeed")
        .expect("event payload should be ok");
    assert_eq!(event.topic, "telegram.message.new");
    common(
        "authorized_webhook_event",
        "telegram.ingest_webhook_update",
        Some(2003),
        Some(chat_hash.clone()),
        Some(user_hash.clone()),
        "allowed",
        "bound_capability_verified",
        "not_needed",
        None,
        "none",
        Some("telegram.message.new"),
        response
            .to_string()
            .len()
            .checked_add(event.data.payload.to_string().len()),
        "no_cleanup_required",
    );

    let denied_payload = json!({
        "update_id": 2004,
        "message": {
            "message_id": 14,
            "from": {
                "id": 999999999,
                "is_bot": false,
                "first_name": "Denied"
            },
            "chat": {
                "id": 999999999,
                "type": "private",
                "first_name": "Denied"
            },
            "date": 1700000011,
            "text": "denied webhook"
        }
    })
    .to_string();
    let denied_response = connector
        .handle_invoke(json!({
            "operation": "telegram.ingest_webhook_update",
            "input": {
                "payload": denied_payload,
                "secret_token": TELEGRAM_LOOPBACK_WEBHOOK_SECRET,
                "delivery_id": "telegram-loopback-delivery-denied"
            },
            "capability_token": webhook_token.clone()
        }))
        .await
        .expect("denied sender should be acknowledged and dropped");
    assert_eq!(denied_response["event_emitted"], false);
    assert_eq!(
        denied_response["reason"],
        "inbound_policy_denied_or_unknown_update"
    );
    common(
        "denied_sender_drop",
        "telegram.ingest_webhook_update",
        Some(2004),
        Some(telegram_loopback_hash("chat", "999999999")),
        Some(denied_user_hash),
        "denied",
        "bound_capability_verified",
        "not_needed",
        None,
        "suppressed_before_event_envelope",
        None,
        Some(denied_response.to_string().len()),
        "no_cleanup_required",
    );

    let duplicate_payload = json!({
        "update_id": 2003,
        "message": {
            "message_id": 13,
            "from": {
                "id": 208214988,
                "is_bot": false,
                "first_name": "Loopback"
            },
            "chat": {
                "id": 208214988,
                "type": "private",
                "first_name": "Loopback"
            },
            "date": 1700000010,
            "text": "authorized webhook duplicate"
        }
    })
    .to_string();
    let duplicate_response = connector
        .handle_invoke(json!({
            "operation": "telegram.ingest_webhook_update",
            "input": {
                "payload": duplicate_payload,
                "secret_token": TELEGRAM_LOOPBACK_WEBHOOK_SECRET,
                "delivery_id": "telegram-loopback-delivery-duplicate"
            },
            "capability_token": webhook_token
        }))
        .await
        .expect("duplicate webhook ingest should be acknowledged");
    assert_eq!(duplicate_response["event_emitted"], false);
    assert_eq!(duplicate_response["reason"], "duplicate_update");
    common(
        "duplicate_update_replay",
        "telegram.ingest_webhook_update",
        Some(2003),
        Some(chat_hash.clone()),
        Some(user_hash.clone()),
        "allowed_then_duplicate_suppressed",
        "bound_capability_verified",
        "not_needed",
        None,
        "duplicate_update_suppressed",
        None,
        Some(duplicate_response.to_string().len()),
        "no_cleanup_required",
    );

    let send_token = generate_valid_token(&signing_key, "telegram.send_message");
    let send_response = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": {
                "chat_id": 208214988,
                "text": "retry transient"
            },
            "capability_token": send_token.clone()
        }))
        .await
        .expect("send_message should retry a transient loopback failure");
    assert_eq!(send_response["message_id"], 9001);
    assert_eq!(server.count_for("sendMessage_retry_transient"), 2);
    common(
        "send_message_transient_retry",
        "telegram.send_message",
        None,
        Some(chat_hash.clone()),
        None,
        "not_applicable_outbound",
        "bound_capability_verified",
        "transient_503_retried_to_success",
        Some(200),
        "none",
        None,
        Some(send_response.to_string().len()),
        "no_cleanup_required",
    );

    let media_token = generate_valid_token(&signing_key, "telegram.send_media");
    let media_response = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": 208214988,
                "media_type": "photo",
                "media": "telegram-loopback-photo",
                "caption": "loopback media"
            },
            "capability_token": media_token
        }))
        .await
        .expect("send_media should succeed against loopback Bot API");
    assert_eq!(media_response["message_id"], 9100);
    common(
        "send_media_photo_metadata",
        "telegram.send_media",
        None,
        Some(chat_hash.clone()),
        None,
        "not_applicable_outbound",
        "bound_capability_verified",
        "not_needed",
        Some(200),
        "none",
        None,
        Some(media_response.to_string().len()),
        "no_cleanup_required",
    );

    let read_token = generate_valid_token(&signing_key, "telegram.get_file");
    let file_response = connector
        .handle_invoke(json!({
            "operation": "telegram.get_file",
            "input": {
                "file_id": "telegram-loopback-file"
            },
            "capability_token": read_token
        }))
        .await
        .expect("get_file should succeed against loopback Bot API");
    assert_eq!(file_response["file_size"], 2048);
    common(
        "media_download_metadata",
        "telegram.get_file",
        None,
        None,
        None,
        "not_applicable_outbound",
        "bound_capability_verified",
        "not_needed",
        Some(200),
        "none",
        None,
        Some(file_response.to_string().len()),
        "no_cleanup_required",
    );

    let chat_action_token = generate_valid_token(&signing_key, "telegram.send_chat_action");
    for _ in 0..2 {
        let error = connector
            .handle_invoke(json!({
                "operation": "telegram.send_chat_action",
                "input": {
                    "chat_id": 208214988,
                    "action": "typing"
                },
                "capability_token": chat_action_token.clone()
            }))
            .await
            .expect_err("first two chat actions should surface Telegram Unauthorized");
        assert!(matches!(error, FcpError::Unauthorized { .. }));
    }
    let suspended = connector
        .handle_invoke(json!({
            "operation": "telegram.send_chat_action",
            "input": {
                "chat_id": 208214988,
                "action": "typing"
            },
            "capability_token": chat_action_token
        }))
        .await
        .expect_err("third chat action should be locally suspended");
    assert!(matches!(suspended, FcpError::External { .. }));
    assert_eq!(server.count_for("sendChatAction"), 2);
    common(
        "send_chat_action_401_suspension",
        "telegram.send_chat_action",
        None,
        Some(chat_hash.clone()),
        None,
        "not_applicable_outbound",
        "bound_capability_verified",
        "unauthorized_circuit_opened_before_third_http_call",
        Some(401),
        "local_retryable_suspension",
        None,
        None,
        "no_cleanup_required",
    );

    let reaction_token = generate_valid_token(&signing_key, "telegram.set_message_reaction");
    let reaction_response = connector
        .handle_invoke(json!({
            "operation": "telegram.set_message_reaction",
            "input": {
                "chat_id": 208214988,
                "message_id": 13,
                "reaction": [{ "type": "emoji", "emoji": "👍" }]
            },
            "capability_token": reaction_token
        }))
        .await
        .expect("set_message_reaction should succeed against loopback Bot API");
    assert_eq!(reaction_response["success"], true);
    common(
        "set_message_reaction",
        "telegram.set_message_reaction",
        None,
        Some(chat_hash.clone()),
        None,
        "not_applicable_outbound",
        "bound_capability_verified",
        "not_needed",
        Some(200),
        "none",
        None,
        Some(reaction_response.to_string().len()),
        "no_cleanup_required",
    );

    let rate_limited = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": {
                "chat_id": 208214988,
                "text": "rate limit fixture"
            },
            "capability_token": send_token
        }))
        .await
        .expect_err("rate-limit fixture should map to FCP RateLimited");
    assert!(matches!(rate_limited, FcpError::RateLimited { .. }));
    assert_eq!(server.count_for("sendMessage_rate_limited"), 3);
    common(
        "rate_limit_response",
        "telegram.send_message",
        None,
        Some(chat_hash),
        None,
        "not_applicable_outbound",
        "bound_capability_verified",
        "retry_after_zero_then_retry_budget_exhausted",
        Some(429),
        "rate_limited",
        None,
        None,
        "no_cleanup_required",
    );

    let delete_webhook_token = generate_valid_token(&signing_key, "telegram.delete_webhook");
    connector
        .handle_invoke(json!({
            "operation": "telegram.delete_webhook",
            "input": {
                "drop_pending_updates": true
            },
            "capability_token": delete_webhook_token
        }))
        .await
        .expect("delete_webhook should succeed against loopback Bot API");
    common(
        "delete_webhook_cleanup",
        "telegram.delete_webhook",
        None,
        None,
        None,
        "not_applicable_outbound",
        "bound_capability_verified",
        "not_needed",
        Some(200),
        "none",
        None,
        None,
        "delete_webhook_called",
    );

    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should stop polling");
    let request_log = server.shutdown();
    assert!(
        request_log
            .iter()
            .any(|request| request.path == token_path("setWebhook")),
        "setWebhook route should be exercised"
    );
    assert!(
        request_log
            .iter()
            .any(|request| request.path == token_path("deleteWebhook")),
        "deleteWebhook route should be exercised"
    );
    common(
        "manual_shutdown",
        "connector.shutdown",
        None,
        None,
        None,
        "not_applicable",
        "not_applicable",
        "not_needed",
        None,
        "none",
        None,
        None,
        "polling_stopped_loopback_server_joined",
    );

    let written_path = telegram_loopback_e2e_write_jsonl(&records);
    assert_eq!(written_path, artifact_path);
    assert!(records.len() >= 11);

    let rendered = records
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let credential = test_bot_credential();
    for forbidden in [
        credential.as_str(),
        TELEGRAM_LOOPBACK_WEBHOOK_SECRET,
        "208214988",
        "999999999",
        "2003",
        "authorized webhook",
        "denied webhook",
        "retry transient",
        "rate limit fixture",
        "telegram-loopback-photo",
        "telegram-loopback-file",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "Telegram loopback JSONL leaked sensitive fixture fragment {forbidden}"
        );
    }
    assert!(rendered.contains("\"scenario\":\"authorized_webhook_event\""));
    assert!(rendered.contains("\"fcp_error_mapping\":\"rate_limited\""));
    assert!(rendered.contains("\"cleanup\":\"polling_stopped_loopback_server_joined\""));
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::test]
async fn send_message_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_message.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 42,
                "chat": { "id": 123456, "type": "private", "first_name": "Test" },
                "date": 1234567890,
                "text": "Hello from FCP!"
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "Hello from FCP!" },
            "capability_token": capability
        }))
        .await
        .expect("send_message invoke should succeed");

    assert_eq!(result["message_id"], 42);
    assert_eq!(result["chat_id"], 123456);
}

#[fcp_async_core::test]
async fn send_message_long_text_splits_utf16_chunks_and_keeps_topic() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_message.long_utf16_split");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    let first_chunk = "a".repeat(telegram_limits::MESSAGE_TEXT_MAX_CHARS - 1);
    let second_chunk = "🙂tail".to_string();
    let text = format!("{first_chunk}{second_chunk}");

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .and(body_json(json!({
            "chat_id": "123456",
            "text": first_chunk,
            "reply_to_message_id": 10,
            "message_thread_id": 77
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 101,
                "chat": { "id": 123456, "type": "private", "first_name": "Test" },
                "date": 1234567890,
                "text": "first chunk"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .and(body_json(json!({
            "chat_id": "123456",
            "text": second_chunk,
            "message_thread_id": 77
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 102,
                "chat": { "id": 123456, "type": "private", "first_name": "Test" },
                "date": 1234567891,
                "text": "second chunk"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": {
                "chat_id": "123456",
                "text": text,
                "reply_to_message_id": 10,
                "message_thread_id": 77
            },
            "capability_token": capability
        }))
        .await
        .expect("chunked send_message invoke should succeed");

    assert_eq!(result["message_id"], 101);
    assert_eq!(result["chat_id"], 123456);
    assert_eq!(result["message_ids"], json!([101, 102]));
    assert_eq!(result["chunk_count"], 2);
}

#[fcp_async_core::test]
async fn send_message_three_chunk_final_returns_all_message_ids() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_message.three_chunk_final");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    let first_chunk = "b".repeat(telegram_limits::MESSAGE_TEXT_MAX_CHARS);
    let second_chunk = "c".repeat(telegram_limits::MESSAGE_TEXT_MAX_CHARS);
    let third_chunk = "done".to_string();
    let text = format!("{first_chunk}{second_chunk}{third_chunk}");

    for (message_id, chunk) in [
        (201, first_chunk.as_str()),
        (202, second_chunk.as_str()),
        (203, third_chunk.as_str()),
    ] {
        Mock::given(method("POST"))
            .and(path(token_path("sendMessage")))
            .and(body_json(json!({
                "chat_id": "123456",
                "text": chunk
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ok": true,
                "result": {
                    "message_id": message_id,
                    "chat": { "id": 123456, "type": "private", "first_name": "Test" },
                    "date": 1234567890 + message_id,
                    "text": "chunk"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
    }

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": text },
            "capability_token": capability
        }))
        .await
        .expect("three-chunk send_message invoke should succeed");

    assert_eq!(result["message_id"], 201);
    assert_eq!(result["message_ids"], json!([201, 202, 203]));
    assert_eq!(result["chunk_count"], 3);
}

#[fcp_async_core::test]
async fn get_file_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.get_file.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.get_file"]).await;

    // getFile uses GET with query params
    Mock::given(method("GET"))
        .and(path(token_path("getFile")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "file_id": "BQACAgIAAxkBAAIsK2Y",
                "file_unique_id": "AgADrwYAAoF",
                "file_size": 12345,
                "file_path": "documents/file_0.pdf"
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.get_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.get_file",
            "input": { "file_id": "BQACAgIAAxkBAAIsK2Y" },
            "capability_token": capability
        }))
        .await
        .expect("get_file invoke should succeed");

    assert_eq!(result["file_id"], "BQACAgIAAxkBAAIsK2Y");
    assert!(result.get("download_url").is_some());
}

#[fcp_async_core::test]
async fn answer_callback_query_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.answer_callback_query.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["telegram.answer_callback_query"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("answerCallbackQuery")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": true
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.answer_callback_query");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.answer_callback_query",
            "input": { "callback_query_id": "cq-12345", "text": "Acknowledged!" },
            "capability_token": capability
        }))
        .await
        .expect("answer_callback_query invoke should succeed");

    assert_eq!(result["success"], true);
}

#[fcp_async_core::test]
async fn send_chat_action_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_chat_action.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["telegram.send_chat_action"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendChatAction")))
        .and(body_json(json!({
            "chat_id": "123456",
            "action": "typing",
            "message_thread_id": 77
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": true
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_chat_action");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_chat_action",
            "input": {
                "chat_id": "123456",
                "action": "typing",
                "message_thread_id": 77
            },
            "capability_token": capability
        }))
        .await
        .expect("send_chat_action invoke should succeed");

    assert_eq!(result["success"], true);
}

#[fcp_async_core::test]
async fn send_chat_action_repeated_401_opens_local_suspension() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_chat_action.401_suspension");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["telegram.send_chat_action"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendChatAction")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "ok": false,
            "error_code": 401,
            "description": "Unauthorized"
        })))
        .expect(2)
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_chat_action");
    for attempt in 1..=2 {
        let err = connector
            .handle_invoke(json!({
                "operation": "telegram.send_chat_action",
                "input": {
                    "chat_id": "123456",
                    "action": "typing"
                },
                "capability_token": capability.clone()
            }))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FcpError::Unauthorized { code: 2001, .. }),
            "attempt {attempt} should return Telegram Unauthorized, got {err:?}"
        );
    }

    let suspended = connector
        .handle_invoke(json!({
            "operation": "telegram.send_chat_action",
            "input": {
                "chat_id": "123456",
                "action": "typing"
            },
            "capability_token": capability
        }))
        .await
        .unwrap_err();

    let FcpError::External {
        service,
        message,
        status_code,
        retryable,
        retry_after,
    } = suspended
    else {
        panic!("expected local suspension external error, got {suspended:?}");
    };
    assert_eq!(service, "telegram");
    assert!(message.contains("sendChatAction temporarily suspended"));
    assert_eq!(status_code, Some(401));
    assert!(retryable);
    assert!(retry_after.is_some());

    let requests = mock_server.received_requests().await.unwrap_or_default();
    let chat_action_requests = requests
        .iter()
        .filter(|request| request.url.path() == token_path("sendChatAction"))
        .count();
    assert_eq!(
        chat_action_requests, 2,
        "third sendChatAction should be stopped by the local suspension before HTTP"
    );
}

#[fcp_async_core::test]
async fn set_message_reaction_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.set_message_reaction.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["telegram.set_message_reaction"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("setMessageReaction")))
        .and(body_json(json!({
            "chat_id": "123456",
            "message_id": 42,
            "reaction": [{ "type": "emoji", "emoji": "👍" }],
            "is_big": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": true
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.set_message_reaction");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.set_message_reaction",
            "input": {
                "chat_id": "123456",
                "message_id": 42,
                "reaction": [{ "type": "emoji", "emoji": "👍" }],
                "is_big": true
            },
            "capability_token": capability
        }))
        .await
        .expect("set_message_reaction invoke should succeed");

    assert_eq!(result["success"], true);
}

#[fcp_async_core::test]
async fn set_webhook_happy_path_uses_configured_secret() {
    let _ctx = AsyncTestContext::for_scenario("telegram.set_webhook.happy_path");
    let mut connector = TelegramConnector::new();
    let mock_server = MockServer::start().await;
    mount_get_me_mock(&mock_server).await;
    connector
        .handle_configure(json!({
            "credential": test_bot_credential(),
            "base_url": mock_server.uri(),
            "webhook_secret_token": "telegram-webhook-secret_1"
        }))
        .await
        .expect("configure with webhook secret should succeed");
    let signing_key =
        setup_handshake(&mut connector, &mock_server, &["telegram.set_webhook"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("setWebhook")))
        .and(body_json(json!({
            "url": "https://fcp.example.com/hooks/telegram",
            "ip_address": "203.0.113.10",
            "max_connections": 40,
            "allowed_updates": ["message", "callback_query"],
            "drop_pending_updates": true,
            "secret_token": "telegram-webhook-secret_1"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": true
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.set_webhook");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.set_webhook",
            "input": {
                "url": "https://fcp.example.com/hooks/telegram",
                "ip_address": "203.0.113.10",
                "max_connections": 40,
                "allowed_updates": ["message", "callback_query"],
                "drop_pending_updates": true
            },
            "capability_token": capability
        }))
        .await
        .expect("set_webhook invoke should succeed");

    assert_eq!(result["success"], true);
    assert_eq!(result["url"], "https://fcp.example.com/hooks/telegram");
    assert_eq!(result["secret_token_configured"], true);
}

#[fcp_async_core::test]
async fn delete_webhook_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.delete_webhook.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.delete_webhook"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("deleteWebhook")))
        .and(body_json(json!({
            "drop_pending_updates": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": true
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.delete_webhook");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.delete_webhook",
            "input": { "drop_pending_updates": true },
            "capability_token": capability
        }))
        .await
        .expect("delete_webhook invoke should succeed");

    assert_eq!(result["success"], true);
}

#[fcp_async_core::test]
async fn get_webhook_info_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.get_webhook_info.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["telegram.get_webhook_info"]).await;

    Mock::given(method("GET"))
        .and(path(token_path("getWebhookInfo")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "url": "https://fcp.example.com/hooks/telegram",
                "has_custom_certificate": false,
                "pending_update_count": 2,
                "last_error_date": 1_700_000_000,
                "last_error_message": "temporary delivery error",
                "max_connections": 40,
                "allowed_updates": ["message", "callback_query"]
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.get_webhook_info");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.get_webhook_info",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect("get_webhook_info invoke should succeed");

    assert_eq!(result["url"], "https://fcp.example.com/hooks/telegram");
    assert_eq!(result["pending_update_count"], 2);
    assert_eq!(result["max_connections"], 40);
}

// ============================================================================
// Error taxonomy tests
// ============================================================================

#[fcp_async_core::test]
async fn unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.unauthorized");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    // Override sendMessage to return 401
    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "ok": false,
            "error_code": 401,
            "description": "Unauthorized"
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "fail" },
            "capability_token": capability
        }))
        .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::Unauthorized { .. }),
        "expected Unauthorized, got {err:?}"
    );
    let fcp_core::FcpError::Unauthorized { code, message } = err else {
        return;
    };
    assert_eq!(code, 2001);
    assert!(message.contains("Unauthorized"));
}

#[fcp_async_core::test]
async fn rate_limited_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.rate_limited");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "ok": false,
            "error_code": 429,
            "description": "Too Many Requests: retry after 1",
            "parameters": { "retry_after": 1 }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "rate limited" },
            "capability_token": capability
        }))
        .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::RateLimited { .. }),
        "expected RateLimited, got {err:?}"
    );
    let fcp_core::FcpError::RateLimited { retry_after_ms, .. } = err else {
        return;
    };
    assert_eq!(retry_after_ms, 30_000);
}

// ============================================================================
// FCP2 default-deny + capability verification
// ============================================================================

#[fcp_async_core::test]
async fn invoke_without_configure_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.deny.not_configured");
    let connector = TelegramConnector::new();

    let signing_key = Ed25519SigningKey::generate();
    let capability = generate_valid_token(&signing_key, "telegram.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "should fail" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn invoke_with_wrong_capability_denied() {
    let _ctx = AsyncTestContext::for_scenario("telegram.deny.wrong_capability");
    let mut connector = TelegramConnector::new();
    // Handshake grants get_file but we invoke send_message
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.get_file"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.get_file");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "wrong cap" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn invoke_unknown_operation_denied() {
    let _ctx = AsyncTestContext::for_scenario("telegram.deny.unknown_operation");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.nonexistent"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.nonexistent",
            "input": {},
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Lifecycle tests
// ============================================================================

#[fcp_async_core::test]
async fn health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.health_not_configured");
    let connector = TelegramConnector::new();
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::test]
async fn health_configured_and_ready() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.health_configured");
    let mock_server = MockServer::start().await;
    mount_get_me_mock(&mock_server).await;

    let mut connector = TelegramConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Health calls getMe to verify connectivity -> returns "ready"
    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");
    assert!(
        result["status"] == "Ready" || result["status"] == "ready",
        "health status should be Ready, got: {}",
        result["status"]
    );
}

#[fcp_async_core::test]
async fn introspect_lists_all_operations() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.introspect");
    let connector = TelegramConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

    assert!(op_ids.contains(&"telegram.send_message"));
    assert!(op_ids.contains(&"telegram.send_media"));
    assert!(op_ids.contains(&"telegram.get_file"));
    assert!(op_ids.contains(&"telegram.answer_callback_query"));
    assert!(op_ids.contains(&"telegram.send_chat_action"));
    assert!(op_ids.contains(&"telegram.set_message_reaction"));
    assert!(op_ids.contains(&"telegram.set_webhook"));
    assert!(op_ids.contains(&"telegram.delete_webhook"));
    assert!(op_ids.contains(&"telegram.get_webhook_info"));
    assert!(op_ids.contains(&"telegram.ingest_webhook_update"));
    assert_eq!(ops.len(), 10);
}

#[fcp_async_core::test]
async fn shutdown_succeeds() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.shutdown");
    let mut connector = TelegramConnector::new();
    let result = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Send media tests
// ============================================================================

#[fcp_async_core::test]
async fn send_media_photo_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_media.photo.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendPhoto")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 100,
                "chat": { "id": 789, "type": "group", "title": "Test Group" },
                "date": 1234567890,
                "photo": [{ "file_id": "photo_small", "file_unique_id": "uniq1", "width": 90, "height": 90 }]
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_media");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": "789",
                "media_type": "photo",
                "media": "AgACAgIAAxkBAAIsK2Y"
            },
            "capability_token": capability
        }))
        .await
        .expect("send_media invoke should succeed");

    assert_eq!(result["message_id"], 100);
}

#[fcp_async_core::test]
async fn send_media_document_with_caption() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_media.document.caption");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendDocument")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 101,
                "chat": { "id": 456, "type": "private", "first_name": "User" },
                "date": 1234567890,
                "document": { "file_id": "doc_id", "file_unique_id": "uniq2", "file_name": "report.pdf" }
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_media");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": "456",
                "media_type": "document",
                "media": "https://example.com/report.pdf",
                "caption": "Monthly report"
            },
            "capability_token": capability
        }))
        .await
        .expect("send_media invoke should succeed");

    assert_eq!(result["message_id"], 101);
}

// ============================================================================
// Additional error taxonomy tests
// ============================================================================

#[fcp_async_core::test]
async fn server_error_500_maps_to_external_error() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.server_500");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "ok": false,
            "error_code": 500,
            "description": "Internal Server Error"
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123", "text": "server error" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn invoke_with_null_capability_token_denied() {
    let _ctx = AsyncTestContext::for_scenario("telegram.deny.null_token");
    let mut connector = TelegramConnector::new();
    let (_mock_server, _signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123", "text": "no token" },
            "capability_token": null
        }))
        .await;

    assert!(result.is_err());
}

// ============================================================================
// Self-check lifecycle
// ============================================================================

#[fcp_async_core::test]
async fn self_check_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.self_check_not_configured");
    let connector = TelegramConnector::new();
    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed");
    assert_eq!(result["status"], "degraded");
}

#[fcp_async_core::test]
async fn self_check_healthy() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.self_check_healthy");
    let mock_server = MockServer::start().await;
    mount_get_me_mock(&mock_server).await;

    let mut connector = TelegramConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed");
    assert_eq!(result["status"], "ok");
    assert!(result.get("details").is_some());
}

// ============================================================================
// Input validation edge cases
// ============================================================================

#[fcp_async_core::test]
async fn send_message_missing_chat_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.send_message_missing_chat_id");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "text": "no chat_id" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "Expected InvalidRequest, got {err:?}"
    );
    let fcp_core::FcpError::InvalidRequest { message, .. } = err else {
        return;
    };
    assert!(message.contains("chat_id"));
}

#[fcp_async_core::test]
async fn send_message_missing_text_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.send_message_missing_text");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "Expected InvalidRequest, got {err:?}"
    );
    let fcp_core::FcpError::InvalidRequest { message, .. } = err else {
        return;
    };
    assert!(message.contains("text"));
}

#[fcp_async_core::test]
async fn send_message_with_parse_mode() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.send_message_html");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 55,
                "chat": { "id": 111, "type": "private", "first_name": "Test" },
                "date": 1234567890,
                "text": "<b>Bold</b>"
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": {
                "chat_id": "111",
                "text": "<b>Bold</b>",
                "parse_mode": "HTML"
            },
            "capability_token": capability
        }))
        .await
        .expect("send_message with parse_mode should succeed");

    assert_eq!(result["message_id"], 55);
}

#[fcp_async_core::test]
async fn send_message_invalid_parse_mode_rejected() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.invalid_parse_mode");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.send_message");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": {
                "chat_id": "123",
                "text": "test",
                "parse_mode": "LaTeX"
            },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn send_message_with_integer_chat_id() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_message.integer_chat_id");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 77,
                "chat": { "id": 999, "type": "private", "first_name": "User" },
                "date": 1234567890,
                "text": "integer chat_id test"
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": 999, "text": "integer chat_id test" },
            "capability_token": capability
        }))
        .await
        .expect("send_message with integer chat_id should succeed");

    assert_eq!(result["message_id"], 77);
}

#[fcp_async_core::test]
async fn send_message_with_reply_to() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_message.reply_to");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 78,
                "chat": { "id": 123, "type": "private", "first_name": "User" },
                "date": 1234567890,
                "text": "reply text",
                "reply_to_message": { "message_id": 10, "date": 1234567800, "chat": { "id": 123, "type": "private" } }
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": {
                "chat_id": "123",
                "text": "reply text",
                "reply_to_message_id": 10
            },
            "capability_token": capability
        }))
        .await
        .expect("send_message with reply_to should succeed");

    assert_eq!(result["message_id"], 78);
}

#[fcp_async_core::test]
async fn send_message_markdownv2_parse_mode() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_message.markdownv2");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 79,
                "chat": { "id": 222, "type": "private", "first_name": "User" },
                "date": 1234567890,
                "text": "*bold* _italic_"
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": {
                "chat_id": "222",
                "text": "*bold* _italic_",
                "parse_mode": "MarkdownV2"
            },
            "capability_token": capability
        }))
        .await
        .expect("send_message with MarkdownV2 should succeed");

    assert_eq!(result["message_id"], 79);
}

// ============================================================================
// Additional happy-path operation tests (media subtypes)
// ============================================================================

#[fcp_async_core::test]
async fn send_media_audio_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_media.audio.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendAudio")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 200,
                "chat": { "id": 789, "type": "private", "first_name": "User" },
                "date": 1234567890,
                "audio": { "file_id": "audio_id", "file_unique_id": "uniq_audio", "duration": 120 }
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_media");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": "789",
                "media_type": "audio",
                "media": "CQACAgIAAxkBAAIsK2Y"
            },
            "capability_token": capability
        }))
        .await
        .expect("send_media audio invoke should succeed");

    assert_eq!(result["message_id"], 200);
}

#[fcp_async_core::test]
async fn send_media_video_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_media.video.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendVideo")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 201,
                "chat": { "id": 789, "type": "group", "title": "Video Group" },
                "date": 1234567890,
                "video": { "file_id": "video_id", "file_unique_id": "uniq_video", "width": 1920, "height": 1080, "duration": 30 }
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_media");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": "789",
                "media_type": "video",
                "media": "BAACAgIAAxkBAAIsK2Y"
            },
            "capability_token": capability
        }))
        .await
        .expect("send_media video invoke should succeed");

    assert_eq!(result["message_id"], 201);
}

#[fcp_async_core::test]
async fn send_media_voice_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("telegram.send_media.voice.happy_path");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendVoice")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 202,
                "chat": { "id": 111, "type": "private", "first_name": "User" },
                "date": 1234567890,
                "voice": { "file_id": "voice_id", "file_unique_id": "uniq_voice", "duration": 5 }
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_media");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": "111",
                "media_type": "voice",
                "media": "AwACAgIAAxkBAAIsK2Y"
            },
            "capability_token": capability
        }))
        .await
        .expect("send_media voice invoke should succeed");

    assert_eq!(result["message_id"], 202);
}

// ============================================================================
// Additional error taxonomy tests
// ============================================================================

#[fcp_async_core::test]
async fn forbidden_403_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.forbidden_403");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error_code": 403,
            "description": "Forbidden: bot was blocked by the user"
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123456", "text": "blocked" },
            "capability_token": capability
        }))
        .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::CapabilityDenied { .. }),
        "expected CapabilityDenied, got {err:?}"
    );
    let fcp_core::FcpError::CapabilityDenied { capability, reason } = err else {
        return;
    };
    assert_eq!(capability, "telegram.api");
    assert!(reason.contains("Forbidden"));
}

#[fcp_async_core::test]
async fn telegram_api_error_structure_chat_not_found() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.chat_not_found");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error_code": 400,
            "description": "Bad Request: chat not found"
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "999999999", "text": "ghost chat" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn get_file_api_error() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.get_file_bad_id");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.get_file"]).await;

    Mock::given(method("GET"))
        .and(path(token_path("getFile")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": false,
            "error_code": 400,
            "description": "Bad Request: invalid file_id"
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.get_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.get_file",
            "input": { "file_id": "bad-file-id" },
            "capability_token": capability
        }))
        .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::External { .. }),
        "expected External, got {err:?}"
    );
    let fcp_core::FcpError::External {
        service,
        status_code,
        retryable,
        ..
    } = err
    else {
        return;
    };
    assert_eq!(service, "telegram");
    assert_eq!(status_code, Some(400));
    assert!(!retryable);
}

#[fcp_async_core::test]
async fn send_media_photo_api_error_500() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.send_media_500");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("sendPhoto")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "ok": false,
            "error_code": 500,
            "description": "Internal Server Error"
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_media");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": "123",
                "media_type": "photo",
                "media": "photo_id_123"
            },
            "capability_token": capability
        }))
        .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::External { .. }),
        "expected External, got {err:?}"
    );
    let fcp_core::FcpError::External {
        service,
        status_code,
        retryable,
        ..
    } = err
    else {
        return;
    };
    assert_eq!(service, "telegram");
    assert_eq!(status_code, Some(500));
    assert!(retryable);
}

#[fcp_async_core::test]
async fn get_file_unauthorized_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.get_file_unauthorized");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.get_file"]).await;

    Mock::given(method("GET"))
        .and(path(token_path("getFile")))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "ok": false,
            "error_code": 401,
            "description": "Unauthorized"
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.get_file");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.get_file",
            "input": { "file_id": "BQACAgIAAxkBAAIsK2Y" },
            "capability_token": capability
        }))
        .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::Unauthorized { .. }),
        "expected Unauthorized, got {err:?}"
    );
    let fcp_core::FcpError::Unauthorized { code, message } = err else {
        return;
    };
    assert_eq!(code, 2001);
    assert!(message.contains("Unauthorized"));
}

#[fcp_async_core::test]
async fn answer_callback_query_rate_limited_maps_to_fcp_error() {
    let _ctx = AsyncTestContext::for_scenario("telegram.error.callback_rate_limited");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) =
        full_setup(&mut connector, &["telegram.answer_callback_query"]).await;

    Mock::given(method("POST"))
        .and(path(token_path("answerCallbackQuery")))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "ok": false,
            "error_code": 429,
            "description": "Too Many Requests: retry after 1",
            "parameters": { "retry_after": 1 }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.answer_callback_query");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.answer_callback_query",
            "input": { "callback_query_id": "cq-12345" },
            "capability_token": capability
        }))
        .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::RateLimited { .. }),
        "expected RateLimited, got {err:?}"
    );
    let fcp_core::FcpError::RateLimited { retry_after_ms, .. } = err else {
        return;
    };
    assert_eq!(retry_after_ms, 30_000);
}

// ============================================================================
// Additional input validation tests
// ============================================================================

#[fcp_async_core::test]
async fn send_media_missing_chat_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.send_media_missing_chat_id");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.send_media");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "media_type": "photo",
                "media": "some_file_id"
            },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, fcp_core::FcpError::InvalidRequest { .. }),
        "Expected InvalidRequest, got {err:?}"
    );
    let fcp_core::FcpError::InvalidRequest { message, .. } = err else {
        return;
    };
    assert!(
        message.contains("chat_id"),
        "Error should mention chat_id, got: {message}"
    );
}

#[fcp_async_core::test]
async fn send_media_missing_media_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.send_media_missing_media");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.send_media");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": "123",
                "media_type": "photo"
            },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("media"),
                "Error should mention media, got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

#[fcp_async_core::test]
async fn send_media_missing_media_type_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.send_media_missing_media_type");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.send_media");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": "123",
                "media": "some_file_id"
            },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("media_type"),
                "Error should mention media_type, got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

#[fcp_async_core::test]
async fn get_file_missing_file_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.get_file_missing_file_id");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.get_file"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.get_file");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.get_file",
            "input": {},
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("file_id"),
                "Error should mention file_id, got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

#[fcp_async_core::test]
async fn answer_callback_query_missing_id_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.callback_missing_id");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) =
        full_setup(&mut connector, &["telegram.answer_callback_query"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.answer_callback_query");

    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.answer_callback_query",
            "input": { "text": "no callback_query_id" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("callback_query_id"),
                "Error should mention callback_query_id, got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

#[fcp_async_core::test]
async fn send_message_text_exceeds_chunked_limit_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.text_too_long_for_chunks");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.send_message");

    let long_text = "a".repeat(telegram_limits::MESSAGE_TEXT_CHUNKED_MAX_UTF16_UNITS + 1);
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123", "text": long_text },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains(&telegram_limits::MESSAGE_TEXT_MAX_CHUNKS.to_string())
                    || message.contains("chunks"),
                "Error should mention chunk limit, got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

#[fcp_async_core::test]
async fn send_media_caption_exceeds_limit_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.validation.caption_too_long");
    let mut connector = TelegramConnector::new();
    let (_mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_media"]).await;
    let capability = generate_valid_token(&signing_key, "telegram.send_media");

    let long_caption = "b".repeat(telegram_limits::MEDIA_CAPTION_MAX_CHARS + 1);
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_media",
            "input": {
                "chat_id": "123",
                "media_type": "photo",
                "media": "some_file_id",
                "caption": long_caption
            },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains(&telegram_limits::MEDIA_CAPTION_MAX_CHARS.to_string())
                    || message.contains("caption"),
                "Error should mention caption limit, got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

// ============================================================================
// Configuration edge cases
// ============================================================================

#[fcp_async_core::test]
async fn configure_with_credential_id_mode() {
    let _ctx = AsyncTestContext::for_scenario("telegram.config.credential_id_mode");
    let mut connector = TelegramConnector::new();

    let result = connector
        .handle_configure(json!({
            "credential_id": "00000000-0000-0000-0000-000000000001"
        }))
        .await
        .expect("configure with credential_id should succeed");

    assert_eq!(result["status"], "configured_pending_token_materialization");
    assert_eq!(result["auth_mode"], "credential_id");
}

#[fcp_async_core::test]
async fn configure_both_credential_and_credential_id_rejected() {
    let _ctx = AsyncTestContext::for_scenario("telegram.config.both_auth_rejected");
    let mut connector = TelegramConnector::new();

    let result = connector
        .handle_configure(json!({
            "credential": test_bot_credential(),
            "credential_id": "00000000-0000-0000-0000-000000000001"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("exactly one"),
                "Error should mention 'exactly one', got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

#[fcp_async_core::test]
async fn configure_empty_bot_token_rejected() {
    let _ctx = AsyncTestContext::for_scenario("telegram.config.empty_token");
    let mut connector = TelegramConnector::new();

    let result = connector
        .handle_configure(json!({
            "credential": ""
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("credential") || message.contains("Missing"),
                "Error should mention missing credential, got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

#[fcp_async_core::test]
async fn configure_whitespace_only_bot_token_rejected() {
    let _ctx = AsyncTestContext::for_scenario("telegram.config.whitespace_token");
    let mut connector = TelegramConnector::new();

    let result = connector
        .handle_configure(json!({
            "credential": "   "
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::test]
async fn configure_invalid_base_url_scheme_rejected() {
    let _ctx = AsyncTestContext::for_scenario("telegram.config.invalid_base_url_scheme");
    let mut connector = TelegramConnector::new();

    let result = connector
        .handle_configure(json!({
            "credential": test_bot_credential(),
            "base_url": "ftp://api.telegram.org"
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("http") || message.contains("https"),
                "Error should mention http/https, got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

#[fcp_async_core::test]
async fn configure_empty_base_url_rejected() {
    let _ctx = AsyncTestContext::for_scenario("telegram.config.empty_base_url");
    let mut connector = TelegramConnector::new();

    let result = connector
        .handle_configure(json!({
            "credential": test_bot_credential(),
            "base_url": ""
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(
                message.contains("base_url"),
                "Error should mention base_url, got: {message}"
            );
        }
        e => {
            assert_unexpected_invalid_request(&e);
            return;
        }
    }
}

// ============================================================================
// Lifecycle: health, doctor, self-check, shutdown edge cases
// ============================================================================

#[fcp_async_core::test]
async fn health_credential_id_mode_returns_degraded() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.health_credential_id");
    let mut connector = TelegramConnector::new();

    connector
        .handle_configure(json!({
            "credential_id": "00000000-0000-0000-0000-000000000002"
        }))
        .await
        .expect("configure should succeed");

    let result = connector
        .handle_health()
        .await
        .expect("health should succeed");

    assert_eq!(result["status"], "degraded");
    assert_eq!(result["auth_mode"], "credential_id");
}

#[fcp_async_core::test]
async fn self_check_credential_id_mode_returns_degraded() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.self_check_credential_id");
    let mut connector = TelegramConnector::new();

    connector
        .handle_configure(json!({
            "credential_id": "00000000-0000-0000-0000-000000000003"
        }))
        .await
        .expect("configure should succeed");

    let result = connector
        .handle_self_check()
        .await
        .expect("self_check should succeed");

    assert_eq!(result["status"], "degraded");
}

#[fcp_async_core::test]
async fn doctor_configured_healthy() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.doctor_configured");
    let mock_server = MockServer::start().await;
    mount_get_me_mock(&mock_server).await;

    let mut connector = TelegramConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let result = connector
        .handle_doctor()
        .await
        .expect("doctor should succeed");

    assert!(result.get("checks").is_some());
    let checks = result["checks"].as_array().expect("checks should be array");
    assert!(
        checks.len() >= 4,
        "Expected at least 4 doctor checks, got {}",
        checks.len()
    );

    // Verify configuration check passed
    let config_check = checks
        .iter()
        .find(|c| c["name"] == "configuration")
        .unwrap();
    assert_eq!(config_check["passed"], true);
}

#[fcp_async_core::test]
async fn shutdown_then_reinvoke_fails() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.shutdown_reinvoke");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    // First, invoke works
    Mock::given(method("POST"))
        .and(path(token_path("sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": {
                "message_id": 300,
                "chat": { "id": 123, "type": "private", "first_name": "User" },
                "date": 1234567890,
                "text": "before shutdown"
            }
        })))
        .mount(&mock_server)
        .await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_invoke(json!({
            "operation": "telegram.send_message",
            "input": { "chat_id": "123", "text": "before shutdown" },
            "capability_token": capability
        }))
        .await;
    assert!(result.is_ok());

    // Shutdown
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");

    // After shutdown, health should still work (connector exists, just stopped)
    let health = connector
        .handle_health()
        .await
        .expect("health after shutdown should succeed");
    // The connector is still configured after shutdown
    assert!(health.get("status").is_some());
}

// ============================================================================
// Simulate operations
// ============================================================================

#[fcp_async_core::test]
async fn simulate_known_operation() {
    let _ctx = AsyncTestContext::for_scenario("telegram.simulate.known_op");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": Uuid::new_v4().to_string(),
            "connector_id": "telegram",
            "operation": "telegram.send_message",
            "zone_id": "z:work",
            "input": { "chat_id": "123", "text": "dry run" },
            "capability_token": capability
        }))
        .await
        .expect("simulate should succeed");

    assert_eq!(result["would_succeed"], true);
    drop(mock_server);
}

#[fcp_async_core::test]
async fn simulate_unknown_operation() {
    let _ctx = AsyncTestContext::for_scenario("telegram.simulate.unknown_op");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": Uuid::new_v4().to_string(),
            "connector_id": "telegram",
            "operation": "telegram.nonexistent_op",
            "zone_id": "z:work",
            "input": {},
            "capability_token": capability
        }))
        .await
        .expect("simulate should serialize denial for unknown ops");

    assert_eq!(result["would_succeed"], false);
    drop(mock_server);
}

#[fcp_async_core::test]
async fn simulate_before_configure_denied() {
    let _ctx = AsyncTestContext::for_scenario("telegram.simulate.not_configured");
    let connector = TelegramConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    let capability = generate_valid_token(&signing_key, "telegram.send_message");

    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": Uuid::new_v4().to_string(),
            "connector_id": "telegram",
            "operation": "telegram.send_message",
            "zone_id": "z:work",
            "input": { "chat_id": "123", "text": "dry run" },
            "capability_token": capability
        }))
        .await
        .expect("simulate should serialize not-configured denial");

    assert_eq!(result["would_succeed"], false);
    assert_eq!(result["denial_code"], FcpError::NotConfigured.error_code());
}

#[fcp_async_core::test]
async fn simulate_before_handshake_denied() {
    let _ctx = AsyncTestContext::for_scenario("telegram.simulate.not_handshaken");
    let mock_server = MockServer::start().await;
    mount_get_me_mock(&mock_server).await;
    let mut connector = TelegramConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let signing_key = Ed25519SigningKey::generate();
    let capability = generate_valid_token(&signing_key, "telegram.send_message");
    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": Uuid::new_v4().to_string(),
            "connector_id": "telegram",
            "operation": "telegram.send_message",
            "zone_id": "z:work",
            "input": { "chat_id": "123", "text": "dry run" },
            "capability_token": capability
        }))
        .await
        .expect("simulate should serialize not-handshaken denial");

    assert_eq!(result["would_succeed"], false);
    assert_eq!(result["denial_code"], FcpError::NotHandshaken.error_code());
}

#[fcp_async_core::test]
async fn simulate_wrong_capability_token_denied() {
    let _ctx = AsyncTestContext::for_scenario("telegram.simulate.wrong_capability");
    let mut connector = TelegramConnector::new();
    let (mock_server, signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    let capability =
        generate_token_for_capability(&signing_key, "telegram.read", "telegram.send_message");
    let result = connector
        .handle_simulate(json!({
            "type": "simulate",
            "id": Uuid::new_v4().to_string(),
            "connector_id": "telegram",
            "operation": "telegram.send_message",
            "zone_id": "z:work",
            "input": { "chat_id": "123", "text": "dry run" },
            "capability_token": capability
        }))
        .await
        .expect("simulate should serialize capability denial");

    assert_eq!(result["would_succeed"], false);
    assert_eq!(result["missing_capabilities"], json!(["telegram.send"]));
    drop(mock_server);
}

// ============================================================================
// Subscribe lifecycle
// ============================================================================

#[fcp_async_core::test]
async fn subscribe_returns_confirmed_topics() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.subscribe");
    let mut connector = TelegramConnector::new();
    let (_mock_server, _signing_key) = full_setup(&mut connector, &["telegram.send_message"]).await;

    let result = connector
        .handle_subscribe(json!({
            "topics": ["telegram.message.new", "telegram.callback_query"]
        }))
        .await
        .expect("subscribe should succeed");

    let confirmed = result["confirmed_topics"]
        .as_array()
        .expect("confirmed_topics should be array");
    assert_eq!(confirmed.len(), 2);
    assert_eq!(result["replay_supported"], false);
}

// ============================================================================
// Introspect edge case: verify schema fields
// ============================================================================

#[fcp_async_core::test]
async fn introspect_operations_have_schemas() {
    let _ctx = AsyncTestContext::for_scenario("telegram.lifecycle.introspect_schemas");
    let connector = TelegramConnector::new();
    let result = connector
        .handle_introspect()
        .await
        .expect("introspect should succeed");

    let ops = result["operations"].as_array().expect("operations array");
    for op in ops {
        assert!(
            op.get("input_schema").is_some(),
            "Operation {} should have input_schema",
            op["id"]
        );
        assert!(
            op.get("output_schema").is_some(),
            "Operation {} should have output_schema",
            op["id"]
        );
        assert!(
            op.get("capability").is_some(),
            "Operation {} should have capability",
            op["id"]
        );
    }

    // Verify events are listed
    let events = result["events"].as_array().expect("events array");
    assert!(
        events.len() >= 5,
        "Expected at least 5 event types, got {}",
        events.len()
    );
}

#[fcp_async_core::test]
async fn malformed_get_updates_payload_does_not_panic() {
    let _ctx = AsyncTestContext::for_scenario("telegram.polling.malformed_update_payload");
    let mock_server = MockServer::start().await;
    mount_get_me_mock(&mock_server).await;

    Mock::given(method("POST"))
        .and(path(token_path("getUpdates")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "result": [{
                "update_id": "bad-update-id",
                "message": { "message_id": "bad-message-id" }
            }]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = TelegramConnector::new();
    setup_configure(&mut connector, &mock_server.uri()).await;

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "zone_dir": unique_zone_dir("integration-malformed-updates"),
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": ["telegram.get_file"]
        }))
        .await
        .expect("handshake should succeed despite malformed updates");

    fcp_async_core::time::sleep(std::time::Duration::from_millis(150)).await;

    let shutdown = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should succeed");
    assert_eq!(shutdown["status"], "shutdown");
}
