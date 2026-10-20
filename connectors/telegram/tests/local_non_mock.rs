//! Local loopback acceptance coverage for the Telegram connector.

#![allow(clippy::too_many_lines)]

use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration as StdDuration,
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::CapabilityConstraints;
use fcp_telegram::connector::TelegramConnector;
use serde_json::{Value, json};
use uuid::Uuid;

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "telegram";
const FIXTURE_ID: &str = "telegram-loopback-local-acceptance";
const TEST_BOT_ID: &str = "123456";
const TEST_BOT_SUFFIX: &str = "ABCDEFGHIJKLMNOPQRSTUVWXyz012345";
const CHAT_ID: i64 = 208_214_988;

fn test_bot_credential() -> String {
    format!("{TEST_BOT_ID}:{TEST_BOT_SUFFIX}")
}

fn unique_zone_dir(label: &str) -> String {
    let dir = std::env::temp_dir()
        .join("fcp-telegram-local-non-mock")
        .join(format!("{label}-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).expect("create Telegram local acceptance zone dir");
    dir.to_string_lossy().into_owned()
}

#[derive(Clone, Debug)]
struct ObservedTelegramRequest {
    method: String,
    path: String,
    body: Value,
}

impl ObservedTelegramRequest {
    fn endpoint(&self) -> String {
        self.path
            .split('?')
            .next()
            .unwrap_or(self.path.as_str())
            .strip_prefix(&format!("/bot{}/", test_bot_credential()))
            .unwrap_or("")
            .to_string()
    }
}

struct LoopbackTelegramFixture {
    base_url: String,
    addr: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<ObservedTelegramRequest>>>,
    counts: Arc<Mutex<HashMap<String, usize>>>,
    join: JoinHandle<()>,
}

impl LoopbackTelegramFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Telegram loopback listener");
        let addr = listener
            .local_addr()
            .expect("read Telegram loopback listener address")
            .to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let thread_counts = Arc::clone(&counts);

        let join = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Some(request) = read_http_request(&mut stream) else {
                    continue;
                };
                let response = response_for_request(&request, &thread_counts);
                thread_requests
                    .lock()
                    .expect("record Telegram loopback request")
                    .push(request);
                write_http_response(&mut stream, &response);
            }
        });

        Self {
            base_url: format!("http://{addr}"),
            addr,
            stop,
            requests,
            counts,
            join,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn count_for(&self, key: &str) -> usize {
        self.counts
            .lock()
            .expect("read Telegram loopback counts")
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    fn shutdown(self) -> Vec<ObservedTelegramRequest> {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
        self.join
            .join()
            .expect("Telegram loopback server thread should join");
        self.requests
            .lock()
            .expect("read Telegram loopback requests")
            .clone()
    }
}

struct HttpFixtureResponse {
    status: u16,
    body: Value,
}

fn bump_count(counts: &Arc<Mutex<HashMap<String, usize>>>, key: &str) -> usize {
    let mut counts = counts.lock().expect("update Telegram loopback count");
    bump_count_in_map(&mut counts, key)
}

fn bump_count_in_map(counts: &mut HashMap<String, usize>, key: &str) -> usize {
    let count = counts.entry(key.to_string()).or_insert(0);
    let previous = *count;
    *count = count.saturating_add(1);
    previous
}

fn response_for_request(
    request: &ObservedTelegramRequest,
    counts: &Arc<Mutex<HashMap<String, usize>>>,
) -> HttpFixtureResponse {
    match (request.method.as_str(), request.endpoint().as_str()) {
        ("GET", "getMe") => {
            bump_count(counts, "getMe");
            HttpFixtureResponse {
                status: 200,
                body: json!({
                    "ok": true,
                    "result": {
                        "id": 123_456_789,
                        "is_bot": true,
                        "first_name": "Loopback Bot",
                        "username": "loopback_bot"
                    }
                }),
            }
        }
        ("POST", "getUpdates") => {
            bump_count(counts, "getUpdates");
            HttpFixtureResponse {
                status: 200,
                body: json!({ "ok": true, "result": [] }),
            }
        }
        ("POST", "sendMessage") => {
            bump_count(counts, "sendMessage");
            HttpFixtureResponse {
                status: 200,
                body: json!({
                    "ok": true,
                    "result": {
                        "message_id": 7001,
                        "chat": { "id": CHAT_ID, "type": "private", "first_name": "Loopback" },
                        "date": 1_700_000_080,
                        "text": "Local acceptance message"
                    }
                }),
            }
        }
        ("POST", "sendPhoto") => {
            bump_count(counts, "sendPhoto");
            HttpFixtureResponse {
                status: 200,
                body: json!({
                    "ok": true,
                    "result": {
                        "message_id": 7002,
                        "chat": { "id": CHAT_ID, "type": "private", "first_name": "Loopback" },
                        "date": 1_700_000_090,
                        "photo": [{
                            "file_id": "local-photo-id",
                            "file_unique_id": "local-photo-unique",
                            "width": 90,
                            "height": 90,
                            "file_size": 512
                        }]
                    }
                }),
            }
        }
        ("GET", "getFile") => {
            bump_count(counts, "getFile");
            HttpFixtureResponse {
                status: 200,
                body: json!({
                    "ok": true,
                    "result": {
                        "file_id": "local-file-id",
                        "file_unique_id": "local-file-unique",
                        "file_size": 4096,
                        "file_path": "documents/local-file.bin"
                    }
                }),
            }
        }
        _ => {
            bump_count(counts, "unexpected");
            HttpFixtureResponse {
                status: 404,
                body: json!({
                    "ok": false,
                    "error_code": 404,
                    "description": "unexpected Telegram local acceptance route"
                }),
            }
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> Option<ObservedTelegramRequest> {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(2)))
        .ok();
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 1024];
    loop {
        let read = stream.read(&mut temp).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&temp[..read]);
        if http_request_complete(&buffer) {
            break;
        }
        if buffer.len() > 32 * 1024 {
            return None;
        }
    }

    let header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n")?;
    let header_text = String::from_utf8_lossy(&buffer[..header_end]);
    let request_line = header_text.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let body_bytes = &buffer[header_end + 4..];
    let body = if body_bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(body_bytes).unwrap_or(Value::Null)
    };

    Some(ObservedTelegramRequest { method, path, body })
}

fn http_request_complete(buffer: &[u8]) -> bool {
    let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let header_text = String::from_utf8_lossy(&buffer[..header_end]);
    let content_length = header_text
        .lines()
        .find_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    buffer.len() >= header_end + 4 + content_length
}

fn write_http_response(stream: &mut TcpStream, response: &HttpFixtureResponse) {
    let reason = match response.status {
        200 => "OK",
        404 => "Not Found",
        _ => "Unknown",
    };
    let body = response.body.to_string();
    write!(
        stream,
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        reason,
        body.len(),
        body
    )
    .expect("write Telegram loopback response");
    stream.flush().expect("flush Telegram loopback response");
}

fn capability_for_operation(operation: &str) -> &'static str {
    match operation {
        "telegram.send_message" | "telegram.send_media" => "telegram.send",
        _ => "telegram.read",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &TelegramConnector,
    operation: &str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(&[operation])
        .issuer("node:local-non-mock")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign local acceptance token");
    fcp_core::CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut TelegramConnector) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    Box::pin(connector.handle_handshake(json!({
        "protocol_version": "1.0.0",
        "zone": "z:work",
        "zone_dir": unique_zone_dir("loopback-acceptance"),
        "host_public_key": verifying_key.to_bytes(),
        "nonce": vec![0_u8; 32],
        "capabilities_requested": ["telegram.send", "telegram.read"]
    })))
    .await
    .expect("handshake should succeed");

    signing_key
}

#[test]
fn loopback_acceptance_exercises_send_media_and_file_paths() {
    thread::Builder::new()
        .name("telegram-local-non-mock".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            fcp_async_core::runtime::block_on_sync(
                run_loopback_acceptance_exercises_send_media_and_file_paths(),
            )
            .expect("telegram local_non_mock runtime");
        })
        .expect("spawn telegram local_non_mock thread")
        .join()
        .expect("telegram local_non_mock thread should succeed");
}

async fn run_loopback_acceptance_exercises_send_media_and_file_paths() {
    let fixture = LoopbackTelegramFixture::start();
    let mut connector = TelegramConnector::new();

    Box::pin(connector.handle_configure(json!({
        "credential": test_bot_credential(),
        "base_url": fixture.base_url(),
        "poll_timeout": 1
    })))
    .await
    .expect("configure connector against loopback Telegram fixture");
    let signing_key = Box::pin(setup_handshake(&mut connector)).await;

    let send_message_token =
        generate_valid_token(&signing_key, &connector, "telegram.send_message");
    let send_message = Box::pin(connector.handle_invoke(json!({
        "operation": "telegram.send_message",
        "input": {
            "chat_id": CHAT_ID,
            "text": "Local acceptance message"
        },
        "capability_token": send_message_token
    })))
    .await
    .expect("send message through loopback fixture");
    let send_media_token = generate_valid_token(&signing_key, &connector, "telegram.send_media");
    let send_media = Box::pin(connector.handle_invoke(json!({
        "operation": "telegram.send_media",
        "input": {
            "chat_id": CHAT_ID,
            "media_type": "photo",
            "media": "local-photo-id",
            "caption": "local acceptance media"
        },
        "capability_token": send_media_token
    })))
    .await
    .expect("send media through loopback fixture");
    let file_token = generate_valid_token(&signing_key, &connector, "telegram.get_file");
    let file = Box::pin(connector.handle_invoke(json!({
        "operation": "telegram.get_file",
        "input": {
            "file_id": "local-file-id"
        },
        "capability_token": file_token
    })))
    .await
    .expect("get file through loopback fixture");

    Box::pin(connector.handle_shutdown(json!({})))
        .await
        .expect("shutdown should stop Telegram polling");

    assert_eq!(send_message["message_id"], 7001);
    assert_eq!(send_message["chat_id"], CHAT_ID);
    assert_eq!(send_media["message_id"], 7002);
    assert_eq!(send_media["chat_id"], CHAT_ID);
    assert_eq!(file["file_id"], "local-file-id");
    assert_eq!(file["file_size"], 4096);
    assert!(
        file["download_url"].as_str().is_some_and(|url| {
            url.starts_with(fixture.base_url()) && url.contains("/file/bot")
        })
    );

    assert!(fixture.count_for("getMe") >= 2);
    assert_eq!(fixture.count_for("sendMessage"), 1);
    assert_eq!(fixture.count_for("sendPhoto"), 1);
    assert_eq!(fixture.count_for("getFile"), 1);
    assert_eq!(fixture.count_for("unexpected"), 0);

    let observations = fixture.shutdown();
    let endpoints = observations
        .iter()
        .map(ObservedTelegramRequest::endpoint)
        .filter(|endpoint| !endpoint.is_empty())
        .collect::<Vec<_>>();
    assert!(endpoints.iter().any(|endpoint| endpoint == "getMe"));
    assert!(endpoints.iter().any(|endpoint| endpoint == "sendMessage"));
    assert!(endpoints.iter().any(|endpoint| endpoint == "sendPhoto"));
    assert!(endpoints.iter().any(|endpoint| endpoint == "getFile"));
    assert!(observations.iter().any(|request| {
        request.endpoint() == "sendMessage"
            && request.body.get("text").and_then(Value::as_str) == Some("Local acceptance message")
    }));
    assert!(observations.iter().any(|request| {
        // Telegram's sendPhoto API names the media field `photo`
        // (SendMediaRequest serializes media_field: "photo").
        request.endpoint() == "sendPhoto"
            && request.body.get("photo").and_then(Value::as_str) == Some("local-photo-id")
    }));

    let artifact = json!({
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "fixture_mode": "loopback_http",
        "operations": [
            "telegram.send_message",
            "telegram.send_media",
            "telegram.get_file"
        ],
        "requests_observed": observations.len(),
        "endpoints_observed": endpoints,
        "bot_token_redacted": true,
        "message_text_redacted": true,
        "media_identifier_redacted": true,
        "cleanup": "connector_shutdown_and_loopback_fixture_stopped",
        "result": "passed"
    });
    println!("{artifact}");
}
