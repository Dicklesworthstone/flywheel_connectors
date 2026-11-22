//! Local loopback acceptance coverage for the Stripe connector.

#![allow(clippy::too_many_lines)]

#[macro_use]
#[path = "support/mod.rs"]
mod test_support;

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{CapabilityConstraints, CapabilityToken};
use fcp_stripe::connector::StripeConnector;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "fcp.stripe";
const FIXTURE_ID: &str = "stripe-loopback-local-acceptance";
const CUSTOMER_ID: &str = "cus_local_acceptance";
const PAYMENT_INTENT_ID: &str = "pi_local_acceptance";
const REFUND_ID: &str = "re_local_acceptance";

#[derive(Clone, Debug)]
struct ObservedStripeRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl ObservedStripeRequest {
    fn authorization_seen(&self) -> bool {
        self.headers
            .get("authorization")
            .is_some_and(|value| value.starts_with("Bearer "))
    }

    fn idempotency_key(&self) -> Option<&str> {
        self.headers.get("idempotency-key").map(String::as_str)
    }

    fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type").map(String::as_str)
    }

    /// Decode the `application/x-www-form-urlencoded` request body Stripe's
    /// REST API requires (the API does not parse JSON bodies).
    fn body_form(&self) -> HashMap<String, String> {
        let body = std::str::from_utf8(&self.body).expect("request body should be UTF-8");
        body.split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').expect("form pair should contain '='");
                (
                    percent_encoding::percent_decode_str(key)
                        .decode_utf8()
                        .expect("form key should be UTF-8")
                        .into_owned(),
                    percent_encoding::percent_decode_str(value)
                        .decode_utf8()
                        .expect("form value should be UTF-8")
                        .into_owned(),
                )
            })
            .collect()
    }
}

struct LoopbackStripeFixture {
    base_url: String,
    observations: Arc<Mutex<Vec<ObservedStripeRequest>>>,
    _join: JoinHandle<()>,
}

impl LoopbackStripeFixture {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind Stripe loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let observations = Arc::new(Mutex::new(Vec::new()));
        let observations_for_thread = Arc::clone(&observations);

        let join = thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept Stripe loopback request");
                let request = read_http_request(&mut stream);
                let response = response_for_request(&request);
                observations_for_thread
                    .lock()
                    .expect("record Stripe loopback request")
                    .push(request);
                write_http_response(&mut stream, &response);
            }
        });

        Self {
            base_url: format!("http://{address}/v1"),
            observations,
            _join: join,
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn observations(&self) -> Vec<ObservedStripeRequest> {
        self.observations
            .lock()
            .expect("read Stripe loopback observations")
            .clone()
    }
}

#[derive(Debug)]
struct HttpFixtureResponse {
    status: u16,
    body: Value,
}

fn read_http_request(stream: &mut TcpStream) -> ObservedStripeRequest {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut temp).expect("read Stripe HTTP request");
        assert!(read > 0, "unexpected EOF while reading Stripe request");
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let header_text = std::str::from_utf8(&buffer[..header_end]).expect("headers are UTF-8");
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().expect("request line present");
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts
        .next()
        .expect("method present")
        .to_string();
    let path = request_line_parts.next().expect("path present").to_string();

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
        let read = stream.read(&mut temp).expect("read Stripe request body");
        assert!(read > 0, "unexpected EOF while reading Stripe body");
        body.extend_from_slice(&temp[..read]);
    }
    body.truncate(content_length);

    ObservedStripeRequest {
        method,
        path,
        headers,
        body,
    }
}

fn response_for_request(request: &ObservedStripeRequest) -> HttpFixtureResponse {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/balance") => HttpFixtureResponse {
            status: 200,
            body: json!({
                "object": "balance",
                "available": [{ "amount": 4242, "currency": "usd" }],
                "pending": [{ "amount": 111, "currency": "usd" }],
                "livemode": false
            }),
        },
        ("POST", "/v1/customers") => HttpFixtureResponse {
            status: 200,
            body: json!({
                "id": CUSTOMER_ID,
                "object": "customer",
                "email": "local-non-mock@example.invalid",
                "name": "Local Acceptance",
                "livemode": false
            }),
        },
        ("POST", "/v1/refunds") => HttpFixtureResponse {
            status: 200,
            body: json!({
                "id": REFUND_ID,
                "object": "refund",
                "amount": 321,
                "currency": "usd",
                "status": "succeeded",
                "payment_intent": PAYMENT_INTENT_ID
            }),
        },
        _ => HttpFixtureResponse {
            status: 500,
            body: json!({
                "error": {
                    "type": "invalid_request_error",
                    "message": "unexpected local acceptance request"
                }
            }),
        },
    }
}

fn write_http_response(stream: &mut TcpStream, response: &HttpFixtureResponse) {
    let reason = match response.status {
        500 => "Internal Server Error",
        _ => "OK",
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
    .expect("write Stripe loopback response");
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &str,
) -> CapabilityToken {
    let capability = match op {
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
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:private")
        .principal("user:local-non-mock")
        .operations(&[op])
        .issuer("node:local-non-mock")
        .target_instance(instance_id)
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign local acceptance token");
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut StripeConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:private",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": test_support::capabilities(caps)
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

#[fcp_async_core::runtime::test]
async fn loopback_acceptance_exercises_read_write_and_payment_paths() {
    let fixture = LoopbackStripeFixture::start(3);
    let mut connector = StripeConnector::new();

    connector
        .handle_configure(json!({
            "secret_key": "sk_test_local_acceptance_fixture",
            "api_url": fixture.base_url()
        }))
        .await
        .expect("configure connector against loopback Stripe fixture");
    let signing_key = setup_handshake(
        &mut connector,
        &[
            "stripe.get_balance",
            "stripe.create_customer",
            "stripe.create_refund",
        ],
    )
    .await;

    let balance = connector
        .handle_invoke(invoke_request!({
            "operation": "stripe.get_balance",
            "input": {},
            "capability_token": generate_valid_token(&signing_key, connector.instance_id(), "stripe.get_balance")
        }))
        .await
        .expect("read balance through loopback fixture");
    let customer = connector
        .handle_invoke(invoke_request!({
            "operation": "stripe.create_customer",
            "operation_id": "op-local-customer",
            "input": {
                "email": "local-non-mock@example.invalid",
                "name": "Local Acceptance"
            },
            "capability_token": generate_valid_token(&signing_key, connector.instance_id(), "stripe.create_customer")
        }))
        .await
        .expect("create customer through loopback fixture");
    let refund = connector
        .handle_invoke(invoke_request!({
            "operation": "stripe.create_refund",
            "operation_id": "op-local-refund",
            "input": {
                "payment_intent": PAYMENT_INTENT_ID,
                "amount": 321
            },
            "capability_token": generate_valid_token(&signing_key, connector.instance_id(), "stripe.create_refund")
        }))
        .await
        .expect("create refund through loopback fixture");

    let observations = fixture.observations();
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].method, "GET");
    assert_eq!(observations[0].path, "/v1/balance");
    assert_eq!(observations[1].method, "POST");
    assert_eq!(observations[1].path, "/v1/customers");
    assert_eq!(observations[2].method, "POST");
    assert_eq!(observations[2].path, "/v1/refunds");
    assert!(
        observations
            .iter()
            .all(ObservedStripeRequest::authorization_seen)
    );

    // Stripe's REST API only accepts form-encoded request bodies.
    for write in &observations[1..] {
        assert!(
            write
                .content_type()
                .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded")),
            "write request should be form-encoded, got {:?}",
            write.content_type()
        );
    }

    let customer_body = observations[1].body_form();
    assert_eq!(customer_body["email"], "local-non-mock@example.invalid");
    assert_eq!(customer_body["name"], "Local Acceptance");
    assert_eq!(
        observations[1].idempotency_key(),
        Some("fcp2:stripe.create_customer:op-local-customer")
    );

    let refund_body = observations[2].body_form();
    assert_eq!(refund_body["payment_intent"], PAYMENT_INTENT_ID);
    assert_eq!(refund_body["amount"], "321");
    assert_eq!(
        observations[2].idempotency_key(),
        Some("fcp2:stripe.create_refund:op-local-refund")
    );

    assert_eq!(balance["balance"]["available"][0]["amount"], 4242);
    assert_eq!(customer["customer"]["id"], CUSTOMER_ID);
    assert_eq!(
        customer["audit"]["idempotency_key"],
        "fcp2:stripe.create_customer:op-local-customer"
    );
    assert_eq!(refund["refund"]["id"], REFUND_ID);
    assert_eq!(
        refund["audit"]["idempotency_key"],
        "fcp2:stripe.create_refund:op-local-refund"
    );

    let artifact = json!({
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "fixture_mode": "loopback_http",
        "operations": [
            "stripe.get_balance",
            "stripe.create_customer",
            "stripe.create_refund"
        ],
        "requests_observed": observations.len(),
        "paths": observations.iter().map(|request| request.path.clone()).collect::<Vec<_>>(),
        "authorization_header_seen": observations
            .iter()
            .all(ObservedStripeRequest::authorization_seen),
        "idempotency_keys_observed": [
            observations[1].idempotency_key(),
            observations[2].idempotency_key()
        ],
        "cleanup": "loopback_fixture_completed_expected_requests",
        "result": "passed"
    });
    println!("{artifact}");
}
