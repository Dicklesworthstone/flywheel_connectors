//! Local no-mock acceptance coverage for the PayPal connector surface.
//!
//! The connector's production configuration intentionally rejects localhost
//! base URLs. These tests therefore cover both sides of that boundary: the
//! connector rejects local provider configuration, while the PayPal REST client
//! is exercised against a raw TCP loopback server with no live credentials.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unwrap_used
)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration as StdDuration, Instant},
};

use fcp_paypal::{
    client::PayPalClient,
    connector::PayPalConnector,
    error::PayPalError,
    types::{
        Amount, CreateBillingInfo, CreateInvoice, CreateInvoiceDetail, CreateInvoiceItem,
        CreateOrder, CreatePurchaseUnit, CreateRecipient, RefundRequest,
    },
};
use fcp_prelude::FcpConnector;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig, migration::HttpRetryConfig};
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-angoc.16.5";
const CONNECTOR_ID: &str = "fcp.paypal";
const CLIENT_ID: &str = "paypal-local-client-id";
const CLIENT_SECRET: &str = "paypal-local-client-secret";
const ACCESS_TOKEN: &str = "paypal-local-access-token";
const ORDER_ID: &str = "ORDER-LOCAL-1";
const CAPTURE_ID: &str = "CAPTURE-LOCAL-1";
const REFUND_ID: &str = "REFUND-LOCAL-1";
const INVOICE_ID: &str = "INV-LOCAL-1";
const BUYER_EMAIL: &str = "buyer-local@example.invalid";
const REFUND_NOTE: &str = "refund note that must stay out of evidence";

struct HttpResponse {
    status: &'static str,
    body: String,
}

#[derive(Debug)]
struct RecordedRequest {
    request_line: String,
    headers: String,
    body_raw: String,
    body_json: Option<Value>,
}

struct LoopbackPayPal {
    base_url: String,
    join: JoinHandle<Vec<RecordedRequest>>,
}

impl LoopbackPayPal {
    fn start(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind PayPal loopback server");
        let base_url = format!(
            "http://{}",
            listener.local_addr().expect("read PayPal loopback address")
        );

        let join = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (stream, _) = listener.accept().expect("accept PayPal client request");
                    handle_request(stream, response)
                })
                .collect()
        });

        Self { base_url, join }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn join(self) -> Vec<RecordedRequest> {
        self.join.join().expect("PayPal loopback server joined")
    }
}

fn handle_request(mut stream: TcpStream, response: HttpResponse) -> RecordedRequest {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .expect("set PayPal loopback read timeout");

    let request = read_complete_request(&mut stream);
    let body_bytes = response.body.as_bytes();
    write!(
        stream,
        "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response.status,
        body_bytes.len(),
        response.body
    )
    .expect("write PayPal loopback response");
    request
}

fn read_complete_request(stream: &mut TcpStream) -> RecordedRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let mut header_end = None;
    let mut expected_len = None;

    loop {
        let read = stream
            .read(&mut buffer)
            .expect("read PayPal loopback request");
        assert_ne!(read, 0, "connection closed before PayPal request completed");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(
            bytes.len() <= 64 * 1024,
            "PayPal request should stay bounded"
        );

        if header_end.is_none()
            && let Some(end) = find_header_end(&bytes)
        {
            let headers =
                String::from_utf8(bytes[..end].to_vec()).expect("PayPal headers should be UTF-8");
            let content_length = content_length(&headers);
            header_end = Some(end);
            expected_len = Some(end + b"\r\n\r\n".len() + content_length);
        }

        if let (Some(end), Some(total_len)) = (header_end, expected_len)
            && bytes.len() >= total_len
        {
            let headers =
                String::from_utf8(bytes[..end].to_vec()).expect("PayPal headers should be UTF-8");
            let request_line = headers
                .lines()
                .next()
                .expect("request line should be present")
                .to_owned();
            let body_start = end + b"\r\n\r\n".len();
            let body_slice = &bytes[body_start..total_len];
            let body_raw =
                String::from_utf8(body_slice.to_vec()).expect("PayPal body should be UTF-8");
            let body_json = if body_raw.trim().starts_with('{') {
                Some(serde_json::from_str(&body_raw).expect("PayPal body should be JSON"))
            } else {
                None
            };
            return RecordedRequest {
                request_line,
                headers,
                body_raw,
                body_json,
            };
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content-length"))
        })
        .unwrap_or(0)
}

fn header_value<'a>(headers: &'a str, expected_name: &str) -> Option<&'a str> {
    headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(expected_name)
            .then(|| value.trim())
    })
}

fn assert_header_eq(headers: &str, name: &str, expected: &str) {
    assert_eq!(
        header_value(headers, name),
        Some(expected),
        "missing or unexpected header {name}"
    );
}

fn stable_hash(kind: &str, raw: &str) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in kind.bytes().chain(*b":").chain(raw.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{kind}:{hash:016x}")
}

fn no_retry_config() -> HttpRetryConfig {
    HttpRetryConfig {
        max_retries: 0,
        initial_delay_ms: 1,
        max_delay_ms: 1,
        jitter_enabled: false,
    }
}

fn test_runtime() -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(StdDuration::from_secs(5)),
    )
}

fn local_client(base_url: &str) -> PayPalClient {
    PayPalClient::new(
        base_url,
        CLIENT_ID.to_owned(),
        CLIENT_SECRET.to_owned(),
        5_000,
        no_retry_config(),
    )
    .expect("raw loopback PayPal client should build")
}

fn amount(currency_code: &str, value: &str) -> Value {
    json!({
        "currency_code": currency_code,
        "value": value
    })
}

fn order_body(order_id: &str, status: &str) -> String {
    json!({
        "id": order_id,
        "status": status,
        "intent": "CAPTURE",
        "purchase_units": [{
            "reference_id": "default",
            "amount": amount("USD", "42.00")
        }]
    })
    .to_string()
}

fn capture_body(capture_id: &str) -> String {
    json!({
        "id": capture_id,
        "status": "COMPLETED",
        "amount": amount("USD", "42.00")
    })
    .to_string()
}

fn refund_body(refund_id: &str) -> String {
    json!({
        "id": refund_id,
        "status": "COMPLETED",
        "amount": amount("USD", "12.50")
    })
    .to_string()
}

fn invoice_body(invoice_id: &str) -> String {
    json!({
        "id": invoice_id,
        "status": "DRAFT",
        "detail": {
            "invoice_number": "INV-LOCAL",
            "currency_code": "USD"
        },
        "primary_recipients": [{
            "billing_info": {
                "email_address": BUYER_EMAIL
            }
        }],
        "items": [{
            "name": "Service",
            "quantity": "1",
            "unit_amount": amount("USD", "100.00")
        }]
    })
    .to_string()
}

fn test_command_line() -> String {
    std::env::var("FCP_TEST_COMMAND_LINE").unwrap_or_else(|_| {
        "cargo test -p fcp-paypal --test local_non_mock -- --nocapture".to_owned()
    })
}

fn git_revision() -> String {
    std::env::var("FCP_TEST_GIT_REVISION").unwrap_or_else(|_| "unknown".to_owned())
}

fn assert_redacted(serialized: &str) {
    for forbidden in [
        CLIENT_ID,
        CLIENT_SECRET,
        ACCESS_TOKEN,
        ORDER_ID,
        CAPTURE_ID,
        REFUND_ID,
        INVOICE_ID,
        BUYER_EMAIL,
        REFUND_NOTE,
        "/Users/",
        "/private/",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "sensitive PayPal fixture leaked in local evidence: {forbidden}"
        );
    }
}

fn emit_redacted_evidence(started: Instant, request_count: usize, cleanup_result: &str) {
    let event = json!({
        "schema_version": "1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "command_line": test_command_line(),
        "git_revision": git_revision(),
        "connector_id": CONNECTOR_ID,
        "fixture_id": "paypal-raw-http-loopback",
        "zone": "z:work",
        "operations": [
            "paypal.orders.create",
            "paypal.orders.get",
            "paypal.orders.capture",
            "paypal.payments.list",
            "paypal.payments.get",
            "paypal.payments.refund",
            "paypal.invoices.create",
            "paypal.invoices.list",
            "paypal.invoices.send",
            "paypal.health"
        ],
        "order_hash": stable_hash("order", ORDER_ID),
        "capture_hash": stable_hash("capture", CAPTURE_ID),
        "invoice_hash": stable_hash("invoice", INVOICE_ID),
        "auth_mode": "oauth2_client_credentials",
        "provider_boundary": "raw_tcp_loopback_paypal_rest",
        "http_request_count": request_count,
        "latency_ms": started.elapsed().as_millis(),
        "cleanup_result": cleanup_result,
        "skip_reason": null,
    });
    let serialized = event.to_string();
    assert_redacted(&serialized);
    eprintln!("{serialized}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_paypal_rest_boundary_and_redaction() {
    let started = Instant::now();

    let mut connector = PayPalConnector::new();
    let rejected_local_config = connector
        .configure(json!({
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "base_url": "http://127.0.0.1:9",
            "sandbox": true,
            "request_timeout_ms": 500
        }))
        .await
        .expect_err("connector config must reject local non-TLS provider URLs");
    assert!(
        format!("{rejected_local_config:?}").contains("base_url must use https"),
        "connector should fail closed before any local provider socket is reachable"
    );

    let token_body = json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "orders invoices payments"
    })
    .to_string();
    let order_created = order_body(ORDER_ID, "CREATED");
    let order_fetched = order_body(ORDER_ID, "APPROVED");
    let order_captured = order_body(ORDER_ID, "COMPLETED");
    let transaction_list = json!({
        "transaction_details": [{
            "transaction_info": {
                "transaction_id": "TXN-LOCAL-1",
                "transaction_status": "S",
                "transaction_amount": amount("USD", "42.00"),
                "transaction_updated_date": "2026-05-01T12:00:00Z"
            }
        }],
        "total_items": 1,
        "total_pages": 1
    })
    .to_string();
    let capture = capture_body(CAPTURE_ID);
    let refund = refund_body(REFUND_ID);
    let invoice = invoice_body(INVOICE_ID);
    let invoice_list = json!({
        "items": [serde_json::from_str::<Value>(&invoice).expect("invoice body JSON")],
        "total_items": 1,
        "total_pages": 1
    })
    .to_string();
    let health_error = json!({
        "name": "INVALID_REQUEST",
        "message": "limit is not supported on this endpoint"
    })
    .to_string();

    let loopback = LoopbackPayPal::start(vec![
        HttpResponse {
            status: "200 OK",
            body: token_body,
        },
        HttpResponse {
            status: "201 Created",
            body: order_created,
        },
        HttpResponse {
            status: "200 OK",
            body: order_fetched,
        },
        HttpResponse {
            status: "201 Created",
            body: order_captured,
        },
        HttpResponse {
            status: "200 OK",
            body: transaction_list,
        },
        HttpResponse {
            status: "200 OK",
            body: capture,
        },
        HttpResponse {
            status: "201 Created",
            body: refund,
        },
        HttpResponse {
            status: "201 Created",
            body: invoice,
        },
        HttpResponse {
            status: "200 OK",
            body: invoice_list,
        },
        HttpResponse {
            status: "204 No Content",
            body: String::new(),
        },
        HttpResponse {
            status: "400 Bad Request",
            body: health_error,
        },
    ]);

    let runtime = test_runtime();
    let client = local_client(loopback.base_url());

    let traversal = client
        .get_order(&runtime, "../admin")
        .await
        .expect_err("path traversal must fail before OAuth or provider traffic");
    assert!(matches!(traversal, PayPalError::InvalidInput(_)));

    let created = client
        .create_order(
            &runtime,
            &CreateOrder {
                intent: "CAPTURE".into(),
                purchase_units: vec![CreatePurchaseUnit {
                    amount: Amount {
                        currency_code: "USD".into(),
                        value: "42.00".into(),
                    },
                    description: Some("FCP local order".into()),
                    reference_id: Some("local-reference".into()),
                }],
            },
            Some("order-local-idempotency-key"),
        )
        .await
        .expect("order create should decode");
    assert_eq!(created.id, ORDER_ID);

    let fetched = client
        .get_order(&runtime, ORDER_ID)
        .await
        .expect("order get should decode");
    assert_eq!(fetched.status, "APPROVED");

    let captured = client
        .capture_order(&runtime, ORDER_ID, Some("capture-local-idempotency-key"))
        .await
        .expect("order capture should decode");
    assert_eq!(captured.status, "COMPLETED");

    let transactions = client
        .list_payments(&runtime, "2026-05-01T00:00:00Z", "2026-05-02T00:00:00Z")
        .await
        .expect("transaction search should decode");
    assert_eq!(
        transactions.transaction_details[0]
            .transaction_info
            .as_ref()
            .and_then(|info| info.transaction_id.as_deref()),
        Some("TXN-LOCAL-1")
    );

    let fetched_capture = client
        .get_capture(&runtime, CAPTURE_ID)
        .await
        .expect("capture get should decode");
    assert_eq!(fetched_capture.status, "COMPLETED");

    let refunded = client
        .refund_capture(
            &runtime,
            CAPTURE_ID,
            &RefundRequest {
                amount: Some(Amount {
                    currency_code: "USD".into(),
                    value: "12.50".into(),
                }),
                note_to_payer: Some(REFUND_NOTE.into()),
            },
            Some("refund-local-idempotency-key"),
        )
        .await
        .expect("refund should decode");
    assert_eq!(refunded.id, REFUND_ID);

    let created_invoice = client
        .create_invoice(
            &runtime,
            &CreateInvoice {
                detail: CreateInvoiceDetail {
                    currency_code: "USD".into(),
                    invoice_number: Some("INV-LOCAL".into()),
                    memo: Some("FCP local invoice".into()),
                },
                primary_recipients: vec![CreateRecipient {
                    billing_info: CreateBillingInfo {
                        email_address: BUYER_EMAIL.into(),
                    },
                }],
                items: vec![CreateInvoiceItem {
                    name: "Service".into(),
                    quantity: "1".into(),
                    unit_amount: Amount {
                        currency_code: "USD".into(),
                        value: "100.00".into(),
                    },
                }],
            },
            Some("invoice-local-idempotency-key"),
        )
        .await
        .expect("invoice create should decode");
    assert_eq!(created_invoice.id, INVOICE_ID);

    let invoices = client
        .list_invoices(&runtime)
        .await
        .expect("invoice list should decode");
    assert_eq!(invoices.items[0].id, INVOICE_ID);

    let sent = client
        .send_invoice(&runtime, INVOICE_ID, Some("send-local-idempotency-key"))
        .await
        .expect("invoice send should decode 204 contract shape");
    assert!(sent.sent);

    assert!(
        client
            .health_check(&runtime)
            .await
            .expect("400 health response still proves auth and reachability")
    );

    let requests = loopback.join();
    assert_eq!(requests.len(), 11);

    assert_eq!(requests[0].request_line, "POST /v1/oauth2/token HTTP/1.1");
    assert!(
        header_value(&requests[0].headers, "authorization")
            .is_some_and(|value| value.starts_with("Basic "))
    );
    assert_eq!(requests[0].body_raw, "grant_type=client_credentials");

    assert_eq!(
        requests[1].request_line,
        "POST /v2/checkout/orders HTTP/1.1"
    );
    assert_header_eq(
        &requests[1].headers,
        "authorization",
        "Bearer paypal-local-access-token",
    );
    assert_header_eq(
        &requests[1].headers,
        "paypal-request-id",
        "order-local-idempotency-key",
    );
    assert_eq!(requests[1].body_json.as_ref().unwrap()["intent"], "CAPTURE");

    assert_eq!(
        requests[2].request_line,
        "GET /v2/checkout/orders/ORDER-LOCAL-1 HTTP/1.1"
    );
    assert_header_eq(
        &requests[2].headers,
        "authorization",
        "Bearer paypal-local-access-token",
    );

    assert_eq!(
        requests[3].request_line,
        "POST /v2/checkout/orders/ORDER-LOCAL-1/capture HTTP/1.1"
    );
    assert_header_eq(
        &requests[3].headers,
        "paypal-request-id",
        "capture-local-idempotency-key",
    );

    assert!(
        requests[4]
            .request_line
            .starts_with("GET /v1/reporting/transactions?")
    );
    assert!(requests[4].request_line.contains("fields=all"));
    assert!(
        requests[4]
            .request_line
            .contains("start_date=2026-05-01T00")
    );
    assert!(requests[4].request_line.contains("end_date=2026-05-02T00"));

    assert_eq!(
        requests[5].request_line,
        "GET /v2/payments/captures/CAPTURE-LOCAL-1 HTTP/1.1"
    );

    assert_eq!(
        requests[6].request_line,
        "POST /v2/payments/captures/CAPTURE-LOCAL-1/refund HTTP/1.1"
    );
    assert_header_eq(
        &requests[6].headers,
        "paypal-request-id",
        "refund-local-idempotency-key",
    );
    assert_eq!(
        requests[6].body_json.as_ref().unwrap()["amount"],
        amount("USD", "12.50")
    );

    assert_eq!(
        requests[7].request_line,
        "POST /v2/invoicing/invoices HTTP/1.1"
    );
    assert_header_eq(
        &requests[7].headers,
        "paypal-request-id",
        "invoice-local-idempotency-key",
    );
    assert_eq!(
        requests[7].body_json.as_ref().unwrap()["detail"]["currency_code"],
        "USD"
    );

    assert_eq!(
        requests[8].request_line,
        "GET /v2/invoicing/invoices?page=1&page_size=20 HTTP/1.1"
    );

    assert_eq!(
        requests[9].request_line,
        "POST /v2/invoicing/invoices/INV-LOCAL-1/send HTTP/1.1"
    );
    assert_header_eq(
        &requests[9].headers,
        "paypal-request-id",
        "send-local-idempotency-key",
    );

    assert_eq!(
        requests[10].request_line,
        "GET /v2/checkout/orders?limit=1 HTTP/1.1"
    );

    emit_redacted_evidence(started, requests.len(), "loopback_closed");
}
