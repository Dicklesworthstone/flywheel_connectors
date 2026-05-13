//! Local loopback acceptance coverage for the FCP WhatsApp connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration as StdDuration,
};

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, HandshakeRequest,
    InstanceId, InvokeRequest, OperationId, RequestId, ZoneId,
};
use fcp_whatsapp::WhatsAppConnector;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

const PHONE_NUMBER_ID: &str = "123456789";
const ACCESS_TOKEN: &str = "test_access_token_xyz";
const APP_SECRET: &str = "test_app_secret_12345";
const VERIFY_TOKEN: &str = "test_verify_token_xyz";
const RECIPIENT_WA_ID: &str = "15559876543";
const MESSAGE_ID: &str = "wamid.LOCAL_NON_MOCK_ACCEPTANCE";

const OP_SEND_TEXT: &str = "whatsapp.send_text";
const OP_GET_PROFILE: &str = "whatsapp.get_profile";
const OP_WEBHOOK_RECEIVE: &str = "whatsapp.webhook_receive";

const CAP_SEND: &str = "whatsapp.send";
const CAP_READ: &str = "whatsapp.read";
const CAP_WEBHOOK: &str = "whatsapp.webhook";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    authorization_seen: bool,
    body: String,
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let handle = thread::spawn(move || handle_requests(listener, expected_requests));

        Self {
            base_url: format!("http://{address}"),
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(mut self) -> Vec<RequestObservation> {
        self.handle
            .take()
            .expect("fixture thread present")
            .join()
            .expect("fixture thread completed")
    }
}

fn handle_requests(listener: TcpListener, expected_requests: usize) -> Vec<RequestObservation> {
    let mut observations = Vec::with_capacity(expected_requests);
    for _ in 0..expected_requests {
        let (mut stream, _) = listener.accept().expect("accept connector request");
        stream
            .set_read_timeout(Some(StdDuration::from_secs(5)))
            .expect("set read timeout");
        let request = read_http_request(&mut stream);
        let observation = observe_request(&request);
        let response_body = response_for_request(&observation.request_line);
        write_response(&mut stream, &response_body);
        observations.push(observation);
    }
    observations
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut header_end = None;

    while header_end.is_none() {
        let read = stream.read(&mut buffer).expect("read request headers");
        assert!(read > 0, "connection closed before request headers");
        bytes.extend_from_slice(&buffer[..read]);
        header_end = find_header_end(&bytes);
    }

    let header_end = header_end.expect("header terminator was found");
    let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
    let content_length = parse_content_length(&headers);
    while bytes.len() < header_end + 4 + content_length {
        let read = stream.read(&mut buffer).expect("read request body");
        assert!(read > 0, "connection closed before request body");
        bytes.extend_from_slice(&buffer[..read]);
    }

    String::from_utf8_lossy(&bytes).to_string()
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn observe_request(request: &str) -> RequestObservation {
    let request_line = request.lines().next().unwrap_or_default().to_owned();
    let authorization_seen = request
        .lines()
        .any(|line| line.eq_ignore_ascii_case(&format!("authorization: Bearer {ACCESS_TOKEN}")));
    let body = request
        .split_once("\r\n\r\n")
        .map_or_else(String::new, |(_, body)| body.to_owned());
    RequestObservation {
        request_line,
        authorization_seen,
        body,
    }
}

fn response_for_request(request_line: &str) -> String {
    let profile_path = format!(
        "/{PHONE_NUMBER_ID}/whatsapp_business_profile?fields=about%2Caddress%2Cdescription%2Cvertical"
    );
    if request_line == format!("POST /{PHONE_NUMBER_ID}/messages HTTP/1.1") {
        return json!({
            "messaging_product": "whatsapp",
            "contacts": [{ "input": RECIPIENT_WA_ID, "wa_id": RECIPIENT_WA_ID }],
            "messages": [{ "id": MESSAGE_ID }],
        })
        .to_string();
    }

    if request_line == format!("GET {profile_path} HTTP/1.1")
        || request_line
            == format!(
                "GET /{PHONE_NUMBER_ID}/whatsapp_business_profile?fields=about,address,description,vertical HTTP/1.1"
            )
    {
        return json!({
            "data": [{
                "about": "Local acceptance fixture profile",
                "address": "1 Connector Way",
                "description": "Dedicated WhatsApp Business Cloud API acceptance profile",
                "vertical": "PROF_SERVICES",
            }]
        })
        .to_string();
    }

    json!({
        "error": {
            "message": format!("unexpected request: {request_line}"),
            "type": "AcceptanceFixtureError",
            "code": 404
        }
    })
    .to_string()
}

fn write_response(stream: &mut TcpStream, body: &str) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .expect("write response");
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:local-non-mock")
        .operations(operations)
        .issuer("node:local-non-mock")
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should be valid")
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(cose)
}

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".to_owned(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7_u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static(CAP_SEND),
            CapabilityId::from_static(CAP_READ),
            CapabilityId::from_static(CAP_WEBHOOK),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

async fn setup_connector(base_url: &str) -> (WhatsAppConnector, Ed25519SigningKey) {
    let mut connector = WhatsAppConnector::new();
    connector
        .configure(json!({
            "base_url": base_url,
            "phone_number_id": PHONE_NUMBER_ID,
            "access_token": ACCESS_TOKEN,
            "app_secret": APP_SECRET,
            "webhook_verify_token": VERIFY_TOKEN,
            "retry": {
                "max_retries": 0,
            },
        }))
        .await
        .expect("configure connector");
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake connector");
    (connector, signing_key)
}

fn invoke_request(
    connector: &WhatsAppConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_owned(),
        id: RequestId::new(format!("req_{operation}")),
        connector_id: connector.id().clone(),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token,
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

async fn invoke(
    connector: &WhatsAppConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(invoke_request(
            connector,
            operation,
            input,
            capability_token,
        ))
        .await?;
    Ok(response
        .result
        .expect("successful invoke should return result"))
}

fn sample_text_notification() -> Value {
    json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
            "changes": [{
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": {
                        "display_phone_number": "15551234567",
                        "phone_number_id": PHONE_NUMBER_ID,
                    },
                    "messages": [{
                        "from": RECIPIENT_WA_ID,
                        "id": "wamid.LOCAL_ACCEPTANCE_WEBHOOK",
                        "timestamp": "1677000000",
                        "type": "text",
                        "text": {
                            "body": "Hello from WhatsApp",
                            "preview_url": false
                        },
                    }],
                },
                "field": "messages",
            }],
        }],
    })
}

fn sign_payload(body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(APP_SECRET.as_bytes()).expect("hmac key");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[fcp_async_core::runtime::test]
async fn loopback_cloud_api_and_webhook_acceptance_jsonl() {
    let fixture = LoopbackFixture::start(2);
    let (connector, signing_key) = setup_connector(fixture.base_url()).await;

    let send_result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": RECIPIENT_WA_ID,
            "text": "local acceptance hello",
            "preview_url": false,
        }),
        capability_token(
            &signing_key,
            CAP_SEND,
            &[OP_SEND_TEXT],
            connector.instance_id(),
        ),
    )
    .await
    .expect("send text through connector");

    let profile_result = invoke(
        &connector,
        OP_GET_PROFILE,
        json!({}),
        capability_token(
            &signing_key,
            CAP_READ,
            &[OP_GET_PROFILE],
            connector.instance_id(),
        ),
    )
    .await
    .expect("get profile through connector");

    let body = sample_text_notification().to_string();
    let webhook_result = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": {
                "x-hub-signature-256": sign_payload(body.as_bytes()),
            },
            "body": body,
        }),
        capability_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_WEBHOOK_RECEIVE],
            connector.instance_id(),
        ),
    )
    .await
    .expect("receive signed webhook through connector");

    let observations = fixture.join();
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].request_line,
        format!("POST /{PHONE_NUMBER_ID}/messages HTTP/1.1")
    );
    assert!(observations[0].authorization_seen);
    assert!(observations[0].body.contains("\"type\":\"text\""));
    assert!(observations[0].body.contains("local acceptance hello"));
    assert!(observations[1].request_line.starts_with(&format!(
        "GET /{PHONE_NUMBER_ID}/whatsapp_business_profile?"
    )));
    assert!(observations[1].authorization_seen);

    assert_eq!(send_result["message_id"], MESSAGE_ID);
    assert_eq!(send_result["wa_id"], RECIPIENT_WA_ID);
    assert_eq!(
        profile_result["description"],
        "Dedicated WhatsApp Business Cloud API acceptance profile"
    );
    assert_eq!(webhook_result["event_count"], 1);
    assert_eq!(
        webhook_result["connector_scope"],
        "whatsapp_business_cloud_api"
    );
    assert_eq!(webhook_result["personal_bridge_supported"], false);

    let artifact = json!({
        "connector": "whatsapp",
        "suite_class": "local_non_mock",
        "acceptance_suite_class": "local_non_mock",
        "fixture_mode": "loopback_http",
        "operations": [OP_SEND_TEXT, OP_GET_PROFILE, OP_WEBHOOK_RECEIVE],
        "network_boundary": "local_loopback_cloud_api_shape",
        "auth_header_observed": observations.iter().all(|request| request.authorization_seen),
        "request_lines": observations
            .iter()
            .map(|request| request.request_line.as_str())
            .collect::<Vec<_>>(),
        "message_id": send_result["message_id"],
        "profile_vertical": profile_result["vertical"],
        "webhook_event_count": webhook_result["event_count"],
        "personal_bridge_supported": webhook_result["personal_bridge_supported"],
        "provider_resource_ids_logged": false,
        "secret_values_logged": false,
        "cleanup_strategy": "fixture_thread_joined",
        "result": "passed",
    });
    println!("WHATSAPP_LOCAL_NON_MOCK_JSONL {artifact}");
}
