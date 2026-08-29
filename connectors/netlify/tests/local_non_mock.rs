//! Local loopback acceptance coverage for the Netlify connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_netlify::connector::NetlifyConnector;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector, FcpError,
    HandshakeRequest, InvokeRequest, InvokeStatus, OperationId, RequestId, ZoneId,
};
use serde::Serialize;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-bky21.4.6.2";
const CONNECTOR_ID: &str = "fcp.netlify";
const REDACTION_SENTINEL: &str = "NETLIFY_REDACTION_VALUE_SHOULD_NOT_APPEAR_IN_EVIDENCE";
const CAP_SITES_READ: &str = "netlify.sites.read";
const CAP_SITES_WRITE: &str = "netlify.sites.write";
const OP_HEALTH: &str = "netlify.health";
const OP_SITES_LIST: &str = "netlify.sites.list";
const OP_SITES_CREATE: &str = "netlify.sites.create";
const OP_SITES_DELETE: &str = "netlify.sites.delete";

fn api_auth_value() -> String {
    ["local", "netlify", "access"].join("-")
}

fn bearer_auth_header() -> String {
    format!("Bearer {}", api_auth_value())
}

const USER_RESPONSE_BODY: &str = r#"{
  "id": "user-local",
  "email": "operator@example.invalid",
  "full_name": "FCP Operator"
}"#;

const SITES_RESPONSE_BODY: &str = r#"[
  {
    "id": "site-local",
    "name": "fcp-local-site",
    "url": "https://fcp-local-site.netlify.app",
    "ssl_url": "https://fcp-local-site.netlify.app",
    "state": "current"
  }
]"#;

const CREATED_SITE_RESPONSE_BODY: &str = r#"{
  "id": "site-created",
  "name": "fcp-created-site",
  "url": "https://fcp-created-site.netlify.app",
  "ssl_url": "https://fcp-created-site.netlify.app",
  "custom_domain": "created.example.invalid",
  "state": "current"
}"#;

const DELETE_RESPONSE_BODY: &str = r#"{"deleted":true,"site_id":"site-created"}"#;
const RATE_LIMIT_BODY: &str = r#"{"message":"provider body should stay out of evidence"}"#;
const UNAUTHORIZED_BODY: &str = r#"{"message":"invalid token"}"#;
const JSON_HEADERS: &[(&str, &str)] = &[("content-type", "application/json")];
const RATE_LIMIT_HEADERS: &[(&str, &str)] =
    &[("content-type", "application/json"), ("retry-after", "5")];

#[derive(Debug, Clone, Copy)]
struct ResponseSpec {
    status: u16,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
}

impl ResponseSpec {
    const fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            headers: JSON_HEADERS,
            body,
        }
    }

    const fn json_with_headers(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
        body: &'static str,
    ) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
struct RequestObservation {
    request_line: String,
    headers: Vec<String>,
    body: String,
    response_status: u16,
    response_body_bytes: usize,
    retry_after_ms: Option<u64>,
}

impl RequestObservation {
    fn method(&self) -> &str {
        self.request_line.split_whitespace().next().unwrap_or("")
    }

    fn target(&self) -> &str {
        self.request_line.split_whitespace().nth(1).unwrap_or("")
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

struct LoopbackFixture {
    base_url: String,
    handle: Option<JoinHandle<Vec<RequestObservation>>>,
}

impl LoopbackFixture {
    fn start(responses: Vec<ResponseSpec>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Netlify listener");
        let address = listener.local_addr().expect("read loopback address");
        let handle = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept connector request");
                    handle_request(stream, response)
                })
                .collect()
        });

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
            .expect("loopback handle present")
            .join()
            .expect("loopback thread completed")
    }
}

fn handle_request(mut stream: TcpStream, response: ResponseSpec) -> RequestObservation {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set request read timeout");
    let raw = read_http_request(&mut stream);
    let (head, body) = split_request(&raw);
    let request = String::from_utf8_lossy(head);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let headers = lines.map(str::to_string).collect::<Vec<_>>();

    write_response(&mut stream, response);

    RequestObservation {
        request_line,
        headers,
        body: String::from_utf8_lossy(body).to_string(),
        response_status: response.status,
        response_body_bytes: response.body.len(),
        retry_after_ms: response.headers.iter().find_map(|(name, value)| {
            name.eq_ignore_ascii_case("retry-after")
                .then(|| value.parse::<u64>().expect("retry-after seconds") * 1_000)
        }),
    }
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2048];
    loop {
        let bytes_read = stream.read(&mut buffer).expect("read connector request");
        assert!(bytes_read > 0, "connector request should not close early");
        request.extend_from_slice(&buffer[..bytes_read]);
        if let Some(header_end) = find_header_end(&request) {
            let expected_body_len = content_length(&request[..header_end]);
            let body_bytes = request.len().saturating_sub(header_end + 4);
            if body_bytes >= expected_body_len {
                return request;
            }
        }
        assert!(request.len() < 16 * 1024, "request should stay bounded");
    }
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn split_request(request: &[u8]) -> (&[u8], &[u8]) {
    let header_end = find_header_end(request).expect("request contains header terminator");
    (&request[..header_end], &request[header_end + 4..])
}

fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

fn write_response(stream: &mut TcpStream, response: ResponseSpec) {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nconnection: close\r\ncontent-length: {}\r\n",
        response.status,
        status_reason(response.status),
        response.body.len()
    )
    .expect("write response status");
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n").expect("write response header");
    }
    write!(stream, "\r\n{}", response.body).expect("write response body");
}

const fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        401 => "Unauthorized",
        429 => "Too Many Requests",
        _ => "Status",
    }
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_health_list_create_and_delete_use_loopback_boundary() {
    let fixture = LoopbackFixture::start(vec![
        ResponseSpec::json(200, USER_RESPONSE_BODY),
        ResponseSpec::json(200, SITES_RESPONSE_BODY),
        ResponseSpec::json(201, CREATED_SITE_RESPONSE_BODY),
        ResponseSpec::json(200, DELETE_RESPONSE_BODY),
    ]);
    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(fixture.base_url(), &signing_key).await;

    let health = invoke(&connector, &signing_key, OP_HEALTH, json!({}))
        .await
        .expect("health should succeed");
    let sites = invoke(&connector, &signing_key, OP_SITES_LIST, json!({}))
        .await
        .expect("sites.list should succeed");
    let created = invoke(
        &connector,
        &signing_key,
        OP_SITES_CREATE,
        json!({
            "name": "fcp-created-site",
            "custom_domain": "created.example.invalid",
            "secret_marker": REDACTION_SENTINEL
        }),
    )
    .await
    .expect("sites.create should succeed");
    let deleted = invoke(
        &connector,
        &signing_key,
        OP_SITES_DELETE,
        json!({"site_id": "site-created"}),
    )
    .await
    .expect("sites.delete should succeed");
    let observations = fixture.join();

    assert_eq!(observations.len(), 4);
    assert_eq!(observations[0].request_line, "GET /api/v1/user HTTP/1.1");
    assert_eq!(observations[1].request_line, "GET /api/v1/sites HTTP/1.1");
    assert_eq!(observations[2].request_line, "POST /api/v1/sites HTTP/1.1");
    assert_eq!(
        observations[3].request_line,
        "DELETE /api/v1/sites/site-created HTTP/1.1"
    );
    let expected_auth = bearer_auth_header();
    for observation in &observations {
        assert_eq!(
            observation.header_value("authorization"),
            Some(expected_auth.as_str())
        );
    }

    let create_body: Value =
        serde_json::from_str(&observations[2].body).expect("create body is JSON");
    assert_eq!(create_body["name"], "fcp-created-site");
    assert_eq!(create_body["custom_domain"], "created.example.invalid");
    assert!(create_body.get("secret_marker").is_none());

    assert_eq!(health["email"], "operator@example.invalid");
    assert_eq!(sites[0]["id"], "site-local");
    assert_eq!(created["id"], "site-created");
    assert_eq!(deleted["deleted"], true);

    let logs = vec![
        evidence_log(OP_HEALTH, Some(&observations[0]), "passed"),
        evidence_log(OP_SITES_LIST, Some(&observations[1]), "passed"),
        evidence_log(OP_SITES_CREATE, Some(&observations[2]), "passed"),
        evidence_log(OP_SITES_DELETE, Some(&observations[3]), "passed"),
    ];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_auth_denial_maps_unauthorized_without_secret_logging() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json(401, UNAUTHORIZED_BODY)]);
    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(fixture.base_url(), &signing_key).await;

    let err = invoke(&connector, &signing_key, OP_HEALTH, json!({}))
        .await
        .expect_err("401 should map to FCP unauthorized");
    let observations = fixture.join();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].request_line, "GET /api/v1/user HTTP/1.1");

    assert!(matches!(err, FcpError::Unauthorized { code: 2001, .. }));

    let logs = vec![evidence_log(
        OP_HEALTH,
        Some(&observations[0]),
        "unauthorized",
    )];
    assert_redacted(&logs);
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rate_limit_maps_retry_after_without_secret_logging() {
    let fixture = LoopbackFixture::start(vec![ResponseSpec::json_with_headers(
        429,
        RATE_LIMIT_HEADERS,
        RATE_LIMIT_BODY,
    )]);
    let signing_key = Ed25519SigningKey::generate();
    let connector = configured_connector(fixture.base_url(), &signing_key).await;

    let err = invoke(&connector, &signing_key, OP_HEALTH, json!({}))
        .await
        .expect_err("rate-limited health should map to FCP error");
    let observations = fixture.join();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].request_line, "GET /api/v1/user HTTP/1.1");

    assert!(matches!(
        err,
        FcpError::RateLimited {
            retry_after_ms: 5_000,
            ..
        }
    ));

    let logs = vec![evidence_log(
        OP_HEALTH,
        Some(&observations[0]),
        "rate_limited",
    )];
    assert_redacted(&logs);
}

#[test]
fn evidence_schema_carries_connector_identity() {
    let log = evidence_log(OP_SITES_LIST, None, "passed");
    let value = serde_json::to_value(log).expect("evidence JSON");
    assert_eq!(value["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(value["bead_id"], BEAD_ID);
    assert_eq!(value["connector_id"], CONNECTOR_ID);
    assert_eq!(
        ConnectorId::from_static(CONNECTOR_ID).as_str(),
        CONNECTOR_ID
    );
    assert_eq!(
        OperationId::from_static(OP_SITES_LIST).as_str(),
        OP_SITES_LIST
    );
    assert_eq!(RequestId::new("netlify-local").to_string(), "netlify-local");
    assert_eq!(ZoneId::work().as_str(), "z:work");
    assert_eq!(NetlifyConnector::new().introspect().operations.len(), 13);
}

async fn configured_connector(base_url: &str, signing_key: &Ed25519SigningKey) -> NetlifyConnector {
    let mut connector = NetlifyConnector::new();
    connector
        .configure(json!({
            "access_token": api_auth_value(),
            "base_url": base_url,
            "request_timeout_ms": 5_000,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
        }))
        .await
        .expect("configure Netlify connector");
    connector
        .handshake(HandshakeRequest {
            protocol_version: "2.0.0".to_string(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: signing_key.verifying_key().to_bytes(),
            nonce: [23_u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_SITES_READ),
                CapabilityId::from_static(CAP_SITES_WRITE),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        })
        .await
        .expect("handshake Netlify connector");
    connector
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    assert!(
        matches!(
            operation,
            OP_HEALTH | OP_SITES_LIST | OP_SITES_CREATE | OP_SITES_DELETE
        ),
        "unsupported operation {operation}"
    );
    match operation {
        OP_SITES_CREATE | OP_SITES_DELETE => CAP_SITES_WRITE,
        _ => CAP_SITES_READ,
    }
}

fn capability_for(
    connector: &NetlifyConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let now = Utc::now();
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("user:netlify-local")
        .operations(&[operation])
        .issuer("node:local-acceptance")
        .validity(now, now + ChronoDuration::hours(1))
        .target_instance(connector.instance_id().as_str())
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("sign capability token");
    CapabilityToken::from_raw(cose)
}

async fn invoke(
    connector: &NetlifyConnector,
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    input: Value,
) -> Result<Value, FcpError> {
    let response = connector
        .invoke(InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new(format!("netlify-local-{operation}")),
            connector_id: ConnectorId::from_static(CONNECTOR_ID),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: capability_for(connector, signing_key, operation),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        })
        .await?;
    assert_eq!(response.status, InvokeStatus::Ok);
    Ok(response.result.expect("successful response has result"))
}

#[derive(Debug, Serialize)]
struct EvidenceLog {
    suite_class: &'static str,
    bead_id: &'static str,
    connector_id: &'static str,
    operation: &'static str,
    capability: &'static str,
    zone: &'static str,
    route: &'static str,
    method: String,
    outcome: &'static str,
    response_status: Option<u16>,
    response_body_bytes: Option<usize>,
    retry_after_ms: Option<u64>,
    redaction: &'static str,
}

fn evidence_log(
    operation: &'static str,
    request: Option<&RequestObservation>,
    outcome: &'static str,
) -> EvidenceLog {
    EvidenceLog {
        suite_class: ACCEPTANCE_SUITE_CLASS,
        bead_id: BEAD_ID,
        connector_id: CONNECTOR_ID,
        operation,
        capability: capability_for_operation(operation),
        zone: "z:work",
        route: request.map_or("in_process_no_egress", route_label),
        method: request.map_or_else(
            || "IN_PROCESS".to_string(),
            |request| request.method().to_string(),
        ),
        outcome,
        response_status: request.map(|request| request.response_status),
        response_body_bytes: request.map(|request| request.response_body_bytes),
        retry_after_ms: request.and_then(|request| request.retry_after_ms),
        redaction: "bearer_token_site_ids_domains_email_and_provider_body_not_logged",
    }
}

fn route_label(request: &RequestObservation) -> &'static str {
    match (request.method(), request.target()) {
        ("GET", "/api/v1/user") => "health",
        ("GET", "/api/v1/sites") => "sites.list",
        ("POST", "/api/v1/sites") => "sites.create",
        ("DELETE", "/api/v1/sites/site-created") => "sites.delete",
        _ => "unrecognized",
    }
}

fn assert_redacted(logs: &[EvidenceLog]) {
    let serialized = serde_json::to_string(logs).expect("serialize evidence logs");
    let api_auth_value = api_auth_value();
    for forbidden in [
        api_auth_value.as_str(),
        REDACTION_SENTINEL,
        "provider body",
        "operator@example.invalid",
        "created.example.invalid",
        "fcp-created-site",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "evidence logs should not contain sensitive sentinel `{forbidden}`"
        );
    }
    for entry in logs {
        eprintln!(
            "{}",
            serde_json::to_string(entry).expect("emit JSONL evidence")
        );
    }
}
