//! Integration tests for the Stripe connector.
//!
//! Covers the connector testing requirements (a81.6):
//! - Error taxonomy mapping (`StripeError` -> `FcpError`)
//! - Redaction (secret key not leaked in error messages)
//! - Idempotency-key behavior for side effects
//! - Operation dispatch through connector
//! - Capability verification
//!
//! All tests are deterministic -- no real API calls.

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

use fcp_stripe::{client::StripeClient, connector::StripeConnector, error::StripeError};

// ============================================================================
// Helpers
// ============================================================================

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &str,
) -> CapabilityToken {
    let cap = match op {
        "stripe.create_customer" | "stripe.update_customer" | "stripe.delete_customer" => {
            "stripe.write"
        }
        "stripe.create_payment_intent"
        | "stripe.confirm_payment_intent"
        | "stripe.capture_payment_intent"
        | "stripe.cancel_payment_intent"
        | "stripe.create_refund"
        | "stripe.create_subscription"
        | "stripe.cancel_subscription" => "stripe.payment",
        "stripe.ingest_webhook_event" => "stripe.webhook",
        _ => "stripe.read",
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
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut StripeConnector, caps: &[&str]) -> Ed25519SigningKey {
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

    signing_key
}

async fn setup_configure(connector: &mut StripeConnector, api_url: &str) {
    connector
        .handle_configure(json!({
            "secret_key": "sk_test_integration_key",
            "api_url": api_url
        }))
        .await
        .expect("configure should succeed");
}

fn build_webhook_signature(secret: &str, payload: &str, timestamp: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac init");
    mac.update(format!("{timestamp}.{payload}").as_bytes());
    let digest = mac.finalize().into_bytes();
    format!("t={timestamp},v1={}", hex::encode(digest))
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
    fn json(status: u16, body: impl Into<serde_json::Value>) -> Self {
        let body = body.into();
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_string().into_bytes(),
        }
    }

    const fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
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
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
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

// ============================================================================
// Error taxonomy mapping tests
// ============================================================================

/// 401 Unauthorized maps to `StripeError::Unauthorized` -> `FcpError::Unauthorized`.
#[fcp_async_core::runtime::test]
async fn error_401_maps_to_unauthorized() {
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/balance");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer bad-key")
        );
        StructuredHttpResponse::empty(401)
    });

    let client = StripeClient::new("bad-key")
        .unwrap()
        .with_api_url(&format!("{}/v1", fake_server.url()))
        .with_retry_config(0);

    let err = client.get_balance().await.unwrap_err();
    assert!(matches!(err, StripeError::Unauthorized));

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { code: 2001, .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 403 Forbidden also maps to Unauthorized.
#[fcp_async_core::runtime::test]
async fn error_403_maps_to_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("bad-key")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_balance().await.unwrap_err();
    assert!(matches!(err, StripeError::Unauthorized));
}

/// 404 Not Found maps to `StripeError::NotFound` -> `FcpError::ResourceNotFound`.
#[fcp_async_core::runtime::test]
async fn error_404_maps_to_not_found() {
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/customers/cus_missing");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer sk_test")
        );
        StructuredHttpResponse::json(
            404,
            json!({
                "error": { "type": "invalid_request_error", "message": "No such customer" }
            }),
        )
    });

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", fake_server.url()))
        .with_retry_config(0);

    let err = client.get_customer("cus_missing").await.unwrap_err();
    assert!(!err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::ResourceNotFound { .. }),
        "expected ResourceNotFound, got: {fcp_err:?}"
    );
}

/// 429 Rate Limited maps to `FcpError::RateLimited`.
#[fcp_async_core::runtime::test]
async fn error_429_rate_limited() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_balance().await.unwrap_err();
    assert!(err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::RateLimited { .. }),
        "expected RateLimited, got: {fcp_err:?}"
    );
}

/// 500 Server Error is retryable.
#[fcp_async_core::runtime::test]
async fn error_500_server_is_retryable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_balance().await.unwrap_err();
    assert!(err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(
            fcp_err,
            FcpError::External {
                retryable: true,
                ..
            }
        ),
        "expected External retryable, got: {fcp_err:?}"
    );
}

/// Every Stripe POST carries an `Idempotency-Key` even when the caller
/// supplied none, and presents the SAME key on every retry attempt.
///
/// `StripeClient::execute` retries on 5xx and on transport timeouts, both of
/// which can be reported after Stripe already accepted the request. Without a
/// stable key, one `create_customer` invoke could create up to `max_retries + 1`
/// customers — and the equivalent path creates duplicate charges and refunds.
/// A per-attempt key would be worse than none: it looks like protection while
/// providing exactly zero. See br-kxd3e.
#[fcp_async_core::runtime::test]
async fn post_without_caller_key_sends_one_stable_idempotency_key_across_retries() {
    struct RecordIdempotencyKey(Arc<Mutex<Vec<Option<String>>>>);

    impl wiremock::Match for RecordIdempotencyKey {
        fn matches(&self, request: &wiremock::Request) -> bool {
            self.0.lock().unwrap().push(
                request
                    .headers
                    .get("idempotency-key")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
            );
            true
        }
    }

    let observed = Arc::new(Mutex::new(Vec::new()));
    let mock_server = MockServer::start().await;

    // A 500 means Stripe RECEIVED the request — the dangerous case.
    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .and(RecordIdempotencyKey(Arc::clone(&observed)))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .and(RecordIdempotencyKey(Arc::clone(&observed)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "cus_1",
            "object": "customer",
            "email": "a@example.com"
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(1);

    client.create_customer("a@example.com", None).await.unwrap();

    let observed = observed.lock().unwrap().clone();
    assert_eq!(
        observed.len(),
        2,
        "expected the 500 to be retried exactly once, saw {observed:?}"
    );
    let first = observed[0]
        .as_deref()
        .expect("attempt 1 must carry a generated Idempotency-Key");
    assert!(
        first.starts_with("fcp2:retry:"),
        "generated key should be self-identifying, got {first}"
    );
    assert_eq!(
        observed[1].as_deref(),
        Some(first),
        "the retry must present the SAME key or Stripe cannot deduplicate it"
    );
}

/// Resource not found via error enum maps correctly.
#[test]
fn error_not_found_maps_correctly() {
    let err = StripeError::NotFound {
        resource: "customer:cus_123".into(),
    };
    assert!(!err.is_retryable());

    let fcp_err = err.to_fcp_error();
    assert!(matches!(fcp_err, FcpError::ResourceNotFound { .. }));
}

/// 400 Bad Request is NOT retryable.
#[test]
fn error_400_not_retryable() {
    let err = StripeError::Api {
        message: "Bad Request".into(),
        status_code: Some(400),
        error_type: Some("invalid_request_error".into()),
    };
    assert!(!err.is_retryable());
}

/// Stripe API error with `error_type` is preserved.
#[fcp_async_core::runtime::test]
async fn stripe_api_error_parsed_from_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "type": "invalid_request_error",
                "message": "Invalid email address",
                "code": "parameter_invalid"
            }
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client
        .create_customer("not-an-email", None)
        .await
        .unwrap_err();
    assert!(matches!(
        &err,
        StripeError::Api { message, .. } if message.contains("Invalid email")
    ));
}

// ============================================================================
// Redaction tests
// ============================================================================

/// Secret key should not appear in error messages.
#[fcp_async_core::runtime::test]
async fn redaction_secret_key_not_in_error_message() {
    let mock_server = MockServer::start().await;
    let redaction_probe = "sk_live_SuperSecretKeyThatShouldNotLeak12345";

    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new(redaction_probe)
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()))
        .with_retry_config(0);

    let err = client.get_balance().await.unwrap_err();
    let err_string = format!("{err:?}");
    assert!(
        !err_string.contains(redaction_probe),
        "Secret key should not appear in error debug output"
    );

    let fcp_err = err.to_fcp_error();
    let fcp_err_string = format!("{fcp_err:?}");
    assert!(
        !fcp_err_string.contains(redaction_probe),
        "Secret key should not appear in FCP error debug output"
    );
}

/// Secret key is sent as Bearer auth header.
#[fcp_async_core::runtime::test]
async fn secret_key_sent_as_bearer_auth() {
    let fake_server = StructuredFakeHttpServer::spawn(1, |_idx, request| {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/balance");
        assert!(
            !request.headers.contains_key("content-type"),
            "GET balance should not send a content-type header"
        );
        assert!(
            request.body.is_empty(),
            "GET balance should not send a body"
        );
        StructuredHttpResponse::json(
            200,
            json!({
                "object": "balance",
                "available": [{ "amount": 100, "currency": "usd" }],
                "pending": [{ "amount": 0, "currency": "usd" }]
            }),
        )
    });

    let client = StripeClient::new("sk_test_auth_check")
        .unwrap()
        .with_api_url(&format!("{}/v1", fake_server.url()))
        .with_retry_config(0);

    let balance = client.get_balance().await.unwrap();
    assert_eq!(balance.available[0].amount, 100);

    let requests = fake_server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers.get("authorization").map(String::as_str),
        Some("Bearer sk_test_auth_check")
    );
}

// ============================================================================
// Client operation tests
// ============================================================================

/// `get_customer` returns a parsed customer.
#[fcp_async_core::runtime::test]
async fn get_customer_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/customers/cus_42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "cus_42",
            "object": "customer",
            "email": "test@example.com",
            "name": "Test User"
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let customer = client.get_customer("cus_42").await.unwrap();
    assert_eq!(customer.id, "cus_42");
    assert_eq!(customer.email.as_deref(), Some("test@example.com"));
}

/// `update_customer` applies mutable fields and returns customer data.
#[fcp_async_core::runtime::test]
async fn update_customer_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/customers/cus_42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "cus_42",
            "object": "customer",
            "email": "updated@example.com",
            "name": "Updated Name"
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let customer = client
        .update_customer(
            "cus_42",
            Some("updated@example.com"),
            Some("Updated Name"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(customer.id, "cus_42");
    assert_eq!(customer.email.as_deref(), Some("updated@example.com"));
}

/// `delete_customer` returns Stripe deletion payload.
#[fcp_async_core::runtime::test]
async fn delete_customer_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/customers/cus_42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "cus_42",
            "object": "customer",
            "deleted": true
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let deleted = client.delete_customer("cus_42", None).await.unwrap();
    assert_eq!(deleted.id, "cus_42");
    assert!(deleted.deleted);
}

/// `create_payment_intent` returns the created intent.
#[fcp_async_core::runtime::test]
async fn create_payment_intent_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/payment_intents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "pi_new",
            "object": "payment_intent",
            "amount": 5000,
            "currency": "usd",
            "status": "requires_payment_method"
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let pi = client
        .create_payment_intent(5000, "usd", Some("cus_42"))
        .await
        .unwrap();
    assert_eq!(pi.id, "pi_new");
    assert_eq!(pi.amount, 5000);
    assert_eq!(pi.currency, "usd");
}

/// `create_refund` returns the refund.
#[fcp_async_core::runtime::test]
async fn create_refund_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/refunds"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_123",
            "object": "refund",
            "amount": 1000,
            "currency": "usd",
            "status": "succeeded",
            "payment_intent": "pi_42"
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let refund = client.create_refund("pi_42", Some(1000)).await.unwrap();
    assert_eq!(refund.id, "re_123");
    assert_eq!(refund.amount, 1000);
    assert_eq!(refund.status, "succeeded");
}

/// `create_subscription` returns the subscription.
#[fcp_async_core::runtime::test]
async fn create_subscription_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/subscriptions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "sub_123",
            "object": "subscription",
            "status": "active",
            "customer": "cus_42"
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let sub = client
        .create_subscription("cus_42", "price_123")
        .await
        .unwrap();
    assert_eq!(sub.id, "sub_123");
    assert_eq!(sub.status, "active");
}

/// `get_subscription` returns the subscription by id.
#[fcp_async_core::runtime::test]
async fn get_subscription_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/subscriptions/sub_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "sub_123",
            "object": "subscription",
            "status": "active",
            "customer": "cus_42"
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let sub = client.get_subscription("sub_123").await.unwrap();
    assert_eq!(sub.id, "sub_123");
    assert_eq!(sub.status, "active");
}

/// `list_subscriptions` returns a list response.
#[fcp_async_core::runtime::test]
async fn list_subscriptions_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/subscriptions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                { "id": "sub_1", "object": "subscription", "status": "active" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client
        .list_subscriptions(Some("cus_42"), Some("active"), Some(10))
        .await
        .unwrap();
    assert_eq!(result.data.len(), 1);
    assert!(!result.has_more);
}

/// `cancel_subscription` returns the cancelled subscription.
#[fcp_async_core::runtime::test]
async fn cancel_subscription_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/subscriptions/sub_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "sub_123",
            "object": "subscription",
            "status": "canceled",
            "customer": "cus_42"
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let sub = client.cancel_subscription("sub_123").await.unwrap();
    assert_eq!(sub.status, "canceled");
}

/// `list_invoices` returns a list response.
#[fcp_async_core::runtime::test]
async fn list_invoices_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/invoices"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                { "id": "in_1", "object": "invoice", "amount_due": 2000, "currency": "usd" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let result = client.list_invoices(None, Some(10)).await.unwrap();
    assert_eq!(result.data.len(), 1);
    assert!(!result.has_more);
}

/// `get_invoice` returns invoice details.
#[fcp_async_core::runtime::test]
async fn get_invoice_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/invoices/in_1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "in_1",
            "object": "invoice",
            "amount_due": 2000,
            "currency": "usd",
            "status": "open"
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let invoice = client.get_invoice("in_1").await.unwrap();
    assert_eq!(invoice.id, "in_1");
    assert_eq!(invoice.amount_due, Some(2000));
}

/// `get_balance` returns account balance.
#[fcp_async_core::runtime::test]
async fn get_balance_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "balance",
            "available": [{ "amount": 50000, "currency": "usd" }],
            "pending": [{ "amount": 10000, "currency": "usd" }]
        })))
        .mount(&mock_server)
        .await;

    let client = StripeClient::new("sk_test")
        .unwrap()
        .with_api_url(&format!("{}/v1", mock_server.uri()));

    let balance = client.get_balance().await.unwrap();
    assert_eq!(balance.available[0].amount, 50000);
    assert_eq!(balance.pending[0].amount, 10000);
}

// ============================================================================
// Connector-level invoke tests
// ============================================================================

/// Invoke `stripe.get_balance` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_balance_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "balance",
            "available": [{ "amount": 99999, "currency": "usd" }],
            "pending": []
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.get_balance"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "stripe.get_balance");

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.get_balance",
            "input": {},
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["balance"]["available"][0]["amount"], 99999);
}

/// Invoke `stripe.create_customer` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_create_customer_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "cus_new",
            "object": "customer",
            "email": "new@example.com"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.create_customer"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.create_customer",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.create_customer",
            "input": { "email": "new@example.com" },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["customer"]["id"], "cus_new");
}

/// `stripe.create_customer` derives idempotency key from invoke metadata.
#[fcp_async_core::runtime::test]
async fn invoke_create_customer_derives_idempotency_key_from_operation_id() {
    let mock_server = MockServer::start().await;
    let expected_key = "fcp2:stripe.create_customer:op-cc-1";

    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .and(header("Idempotency-Key", expected_key))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "cus_new",
            "object": "customer",
            "email": "new@example.com"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.create_customer"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.create_customer",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.create_customer",
            "operation_id": "op-cc-1",
            "input": { "email": "new@example.com" },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["customer"]["id"], "cus_new");
    assert_eq!(result["audit"]["idempotency_key"], expected_key);
}

/// Invoke `stripe.update_customer` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_update_customer_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/customers/cus_42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "cus_42",
            "object": "customer",
            "email": "updated@example.com"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.update_customer"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.update_customer",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.update_customer",
            "operation_id": "op-update-1",
            "input": { "customer_id": "cus_42", "email": "updated@example.com" },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["customer"]["id"], "cus_42");
    assert_eq!(
        result["audit"]["idempotency_key"],
        "fcp2:stripe.update_customer:op-update-1"
    );
}

/// Invoke `stripe.delete_customer` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_delete_customer_through_connector() {
    let mock_server = MockServer::start().await;
    let expected_key = "fcp2:stripe.delete_customer:op-delete-1";

    Mock::given(method("DELETE"))
        .and(path("/v1/customers/cus_42"))
        .and(header("Idempotency-Key", expected_key))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "cus_42",
            "object": "customer",
            "deleted": true
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.delete_customer"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.delete_customer",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.delete_customer",
            "operation_id": "op-delete-1",
            "input": { "customer_id": "cus_42" },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["deleted"]["id"], "cus_42");
    assert_eq!(result["audit"]["idempotency_key"], expected_key);
}

/// Invoke `stripe.get_subscription` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_subscription_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/subscriptions/sub_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "sub_123",
            "object": "subscription",
            "status": "active",
            "customer": "cus_42"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.get_subscription"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.get_subscription",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.get_subscription",
            "input": { "subscription_id": "sub_123" },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["subscription"]["id"], "sub_123");
}

/// Invoke `stripe.list_subscriptions` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_list_subscriptions_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/subscriptions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "object": "list",
            "data": [
                { "id": "sub_1", "object": "subscription", "status": "active" }
            ],
            "has_more": false
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.list_subscriptions"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.list_subscriptions",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.list_subscriptions",
            "input": { "customer": "cus_42", "status": "active", "limit": 10 },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["data"].as_array().unwrap().len(), 1);
    assert_eq!(result["has_more"], false);
}

/// Invoke `stripe.get_invoice` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_get_invoice_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/invoices/in_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "in_123",
            "object": "invoice",
            "amount_due": 1500,
            "currency": "usd",
            "status": "open"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.get_invoice"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "stripe.get_invoice");

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.get_invoice",
            "input": { "invoice_id": "in_123" },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["invoice"]["id"], "in_123");
}

/// Invoke `stripe.create_refund` through the connector.
#[fcp_async_core::runtime::test]
async fn invoke_create_refund_through_connector() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/refunds"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_456",
            "object": "refund",
            "amount": 500,
            "currency": "usd",
            "status": "succeeded",
            "payment_intent": "pi_789"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.create_refund"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.create_refund",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.create_refund",
            "input": { "payment_intent": "pi_789", "amount": 500 },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["refund"]["id"], "re_456");
    assert_eq!(result["refund"]["amount"], 500);
}

/// Side-effect subscription creation derives idempotency key and emits audit payload.
#[fcp_async_core::runtime::test]
async fn invoke_create_subscription_derives_idempotency_key_from_operation_id() {
    let mock_server = MockServer::start().await;
    let expected_key = "fcp2:stripe.create_subscription:op-sub-create-1";

    Mock::given(method("POST"))
        .and(path("/v1/subscriptions"))
        .and(header("Idempotency-Key", expected_key))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "sub_derived",
            "object": "subscription",
            "status": "active",
            "customer": "cus_42"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.create_subscription"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.create_subscription",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.create_subscription",
            "operation_id": "op-sub-create-1",
            "input": { "customer": "cus_42", "price": "price_abc123" },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["subscription"]["id"], "sub_derived");
    assert_eq!(result["audit"]["idempotency_key"], expected_key);
}

/// Side-effect subscription cancellation derives idempotency key and emits audit payload.
#[fcp_async_core::runtime::test]
async fn invoke_cancel_subscription_derives_idempotency_key_from_operation_id() {
    let mock_server = MockServer::start().await;
    let expected_key = "fcp2:stripe.cancel_subscription:op-sub-cancel-1";

    Mock::given(method("DELETE"))
        .and(path("/v1/subscriptions/sub_derived"))
        .and(header("Idempotency-Key", expected_key))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "sub_derived",
            "object": "subscription",
            "status": "canceled",
            "customer": "cus_42"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.cancel_subscription"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.cancel_subscription",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.cancel_subscription",
            "operation_id": "op-sub-cancel-1",
            "input": { "subscription_id": "sub_derived" },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["subscription"]["id"], "sub_derived");
    assert_eq!(result["audit"]["idempotency_key"], expected_key);
}

/// Side-effect operations derive an idempotency key from invoke `operation_id`.
#[fcp_async_core::runtime::test]
async fn invoke_create_refund_derives_idempotency_key_from_operation_id() {
    let mock_server = MockServer::start().await;
    let expected_key = "fcp2:stripe.create_refund:op-789";

    Mock::given(method("POST"))
        .and(path("/v1/refunds"))
        .and(header("Idempotency-Key", expected_key))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "re_derived",
            "object": "refund",
            "amount": 250,
            "currency": "usd",
            "status": "succeeded",
            "payment_intent": "pi_derived"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.create_refund"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.create_refund",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.create_refund",
            "operation_id": "op-789",
            "input": { "payment_intent": "pi_derived", "amount": 250 },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["refund"]["id"], "re_derived");
    assert_eq!(result["audit"]["idempotency_key"], expected_key);
}

/// Wrong capability token is rejected.
#[fcp_async_core::runtime::test]
async fn wrong_capability_rejected() {
    let mock_server = MockServer::start().await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.get_balance"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "stripe.get_balance");

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.get_customer",
            "input": { "customer_id": "cus_123" },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err(), "should reject mismatched capability");
}

/// Missing required field returns `InvalidRequest`.
#[fcp_async_core::runtime::test]
async fn missing_required_field_returns_invalid_request() {
    let mock_server = MockServer::start().await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.create_payment_intent"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.create_payment_intent",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.create_payment_intent",
            "input": { "amount": 2000 },
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), FcpError::InvalidRequest { .. }),
        "expected InvalidRequest for missing currency"
    );
}

/// Unknown operation is rejected.
#[fcp_async_core::runtime::test]
async fn unknown_operation_rejected() {
    let mock_server = MockServer::start().await;

    let mut connector = StripeConnector::new();
    setup_configure(&mut connector, &format!("{}/v1", mock_server.uri())).await;
    let signing_key = setup_handshake(&mut connector, &["stripe.nonexistent"]).await;
    let capability =
        generate_valid_token(&signing_key, connector.instance_id(), "stripe.nonexistent");

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.nonexistent",
            "input": {},
            "capability_token": capability
        }))
        .await;

    assert!(result.is_err());
}

/// Ingesting a webhook validates signature and returns normalized event metadata.
#[fcp_async_core::runtime::test]
async fn invoke_ingest_webhook_event_success() {
    let mut connector = StripeConnector::new();
    connector
        .handle_configure(json!({
            "secret_key": "sk_test_integration_key",
            "api_url": "http://127.0.0.1:9/v1",
            "webhook_signing_secret": "whsec_integration"
        }))
        .await
        .expect("configure should succeed");

    let signing_key = setup_handshake(&mut connector, &["stripe.ingest_webhook_event"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.ingest_webhook_event",
    );

    let signature_timestamp = Utc::now().timestamp();
    let payload = r#"{"id":"evt_integration","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
    let signature = build_webhook_signature("whsec_integration", payload, signature_timestamp);

    let result = connector
        .handle_invoke(json!({
            "operation": "stripe.ingest_webhook_event",
            "input": {
                "payload": payload,
                "stripe_signature": signature
            },
            "capability_token": capability
        }))
        .await
        .unwrap();

    assert_eq!(result["event"]["id"], "evt_integration");
    assert_eq!(result["event"]["type"], "invoice.paid");
    assert_eq!(result["delivery"]["signature_verified"], true);
    assert_eq!(result["delivery"]["replay_protected"], true);
}

/// Duplicate delivery IDs are rejected to prevent replay.
#[fcp_async_core::runtime::test]
async fn invoke_ingest_webhook_event_replay_rejected() {
    let mut connector = StripeConnector::new();
    connector
        .handle_configure(json!({
            "secret_key": "sk_test_integration_key",
            "api_url": "http://127.0.0.1:9/v1",
            "webhook_signing_secret": "whsec_replay"
        }))
        .await
        .expect("configure should succeed");

    let signing_key = setup_handshake(&mut connector, &["stripe.ingest_webhook_event"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.ingest_webhook_event",
    );

    let signature_timestamp = Utc::now().timestamp();
    let payload = r#"{"id":"evt_replay_test","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
    let signature = build_webhook_signature("whsec_replay", payload, signature_timestamp);
    let invoke = json!({
        "operation": "stripe.ingest_webhook_event",
        "input": {
            "payload": payload,
            "stripe_signature": signature
        },
        "capability_token": capability
    });

    connector.handle_invoke(invoke.clone()).await.unwrap();
    let err = connector.handle_invoke(invoke).await.unwrap_err();

    assert!(
        matches!(err, FcpError::Conflict { .. }),
        "expected Conflict on replay, got {err:?}"
    );
}

/// Signature validation failures must not leak the configured webhook secret.
#[fcp_async_core::runtime::test]
async fn invoke_ingest_webhook_event_invalid_signature_is_redacted() {
    let mut connector = StripeConnector::new();
    let webhook_material = "whsec_should_not_leak";
    connector
        .handle_configure(json!({
            "secret_key": "sk_test_integration_key",
            "api_url": "http://127.0.0.1:9/v1",
            "webhook_signing_secret": webhook_material
        }))
        .await
        .expect("configure should succeed");

    let signing_key = setup_handshake(&mut connector, &["stripe.ingest_webhook_event"]).await;
    let capability = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "stripe.ingest_webhook_event",
    );

    let payload = r#"{"id":"evt_invalid_sig","object":"event","type":"invoice.paid","created":1700000000,"data":{"object":{"id":"in_123","object":"invoice"}}}"#;
    let err = connector
        .handle_invoke(json!({
            "operation": "stripe.ingest_webhook_event",
            "input": {
                "payload": payload,
                "stripe_signature": "t=1700000000,v1=badbadbad",
                "received_at": 1_700_000_000
            },
            "capability_token": capability
        }))
        .await
        .unwrap_err();

    let rendered = format!("{err:?}");
    assert!(
        !rendered.contains(webhook_material),
        "webhook secret leaked in error"
    );
    assert!(matches!(err, FcpError::Unauthorized { .. }));
}
