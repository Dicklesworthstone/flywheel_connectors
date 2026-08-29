//! Connector-local no-mock `PayPal` integration proof.
//!
//! These tests exercise the real `PayPal` client against a local HTTP server.
//! No live `PayPal` service is called.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::sync::Once;
use std::time::Duration;

use fcp_paypal::client::PayPalClient;
use fcp_paypal::connector::{PayPalConfig, PayPalConnector};
use fcp_paypal::error::PayPalError;
use fcp_paypal::types::{
    Amount, CreateBillingInfo, CreateInvoice, CreateInvoiceDetail, CreateInvoiceItem, CreateOrder,
    CreatePurchaseUnit, CreateRecipient, PayPalAuth, RefundRequest, TokenResponse,
};
use fcp_prelude::{
    ApprovalMode, FcpConnector, FcpError, IdempotencyClass, RequestId, RiskLevel, SafetyTier,
    SubscribeRequest,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CLIENT_ID: &str = "client";
const CLIENT_SECRET: &str = "secret";
const TEST_TOKEN: &str = "paypal-access-token-for-tests";
const BASIC_AUTH: &str = "Basic Y2xpZW50OnNlY3JldA==";
const BEARER_AUTH: &str = "Bearer paypal-access-token-for-tests";

static LOG_INIT: Once = Once::new();

fn init_logging() {
    LOG_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| {
                        tracing_subscriber::EnvFilter::new(
                            "info,asupersync=warn,fcp_sdk=warn,hyper=warn,hyper_util=warn,reqwest=warn,wiremock=warn",
                        )
                    }),
            )
            .json()
            .with_test_writer()
            .try_init();
    });
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
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_millis(500)),
    )
}

fn paypal_client(server: &MockServer) -> PayPalClient {
    PayPalClient::new(
        &server.uri(),
        CLIENT_ID.into(),
        CLIENT_SECRET.into(),
        500,
        no_retry_config(),
    )
    .expect("wiremock URI should build a PayPal client")
}

async fn mount_oauth_token(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/oauth2/token"))
        .and(header("authorization", BASIC_AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": TEST_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "https://uri.paypal.com/services/invoicing"
        })))
        .mount(server)
        .await;
}

fn amount(currency_code: &str, value: &str) -> serde_json::Value {
    json!({
        "currency_code": currency_code,
        "value": value
    })
}

fn order(order_id: &str, status: &str) -> serde_json::Value {
    json!({
        "id": order_id,
        "status": status,
        "intent": "CAPTURE",
        "purchase_units": [{
            "reference_id": "default",
            "description": "FCP order",
            "amount": amount("USD", "42.00")
        }],
        "links": [{
            "href": format!("https://api-m.sandbox.paypal.com/v2/checkout/orders/{order_id}"),
            "rel": "self",
            "method": "GET"
        }]
    })
}

fn capture(capture_id: &str, status: &str) -> serde_json::Value {
    json!({
        "id": capture_id,
        "status": status,
        "amount": amount("USD", "42.00")
    })
}

fn refund(refund_id: &str) -> serde_json::Value {
    json!({
        "id": refund_id,
        "status": "COMPLETED",
        "amount": amount("USD", "12.50")
    })
}

fn invoice(invoice_id: &str, status: &str) -> serde_json::Value {
    json!({
        "id": invoice_id,
        "status": status,
        "detail": {
            "invoice_number": "INV-001",
            "currency_code": "USD"
        },
        "primary_recipients": [{
            "billing_info": {
                "email_address": "buyer@example.com"
            }
        }],
        "items": [{
            "name": "Service",
            "quantity": "1",
            "unit_amount": amount("USD", "100.00")
        }]
    })
}

#[fcp_async_core::runtime::test]
async fn orders_payments_refunds_invoices_and_health_use_paypal_contracts() {
    init_logging();
    tracing::info!(
        scenario = "paypal_success_contracts",
        "starting PayPal success-path integration proof",
    );

    let server = MockServer::start().await;
    mount_oauth_token(&server).await;

    Mock::given(method("POST"))
        .and(path("/v2/checkout/orders"))
        .and(header("authorization", BEARER_AUTH))
        .and(header("paypal-request-id", "order-idem-key"))
        .and(body_json(json!({
            "intent": "CAPTURE",
            "purchase_units": [{
                "amount": amount("USD", "42.00"),
                "description": "FCP order",
                "reference_id": "ref-1"
            }]
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(order("ORDER-1", "CREATED")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/checkout/orders/ORDER-1"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(order("ORDER-1", "APPROVED")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v2/checkout/orders/ORDER-1/capture"))
        .and(header("authorization", BEARER_AUTH))
        .and(header("paypal-request-id", "capture-idem-key"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(201).set_body_json(order("ORDER-1", "COMPLETED")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/reporting/transactions"))
        .and(query_param("start_date", "2026-05-01T00:00:00Z"))
        .and(query_param("end_date", "2026-05-02T00:00:00Z"))
        .and(query_param("fields", "all"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "transaction_details": [{
                "transaction_info": {
                    "transaction_id": "TXN-1",
                    "transaction_status": "S",
                    "transaction_amount": amount("USD", "42.00"),
                    "transaction_updated_date": "2026-05-01T12:00:00Z"
                }
            }],
            "total_items": 1,
            "total_pages": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/payments/captures/CAPTURE-1"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(capture("CAPTURE-1", "COMPLETED")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v2/payments/captures/CAPTURE-1/refund"))
        .and(header("authorization", BEARER_AUTH))
        .and(header("paypal-request-id", "refund-idem-key"))
        .and(body_json(json!({
            "amount": amount("USD", "12.50"),
            "note_to_payer": "partial refund"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(refund("REFUND-1")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v2/invoicing/invoices"))
        .and(header("authorization", BEARER_AUTH))
        .and(header("paypal-request-id", "invoice-idem-key"))
        .and(body_json(json!({
            "detail": {
                "currency_code": "USD",
                "invoice_number": "INV-001",
                "memo": "FCP invoice"
            },
            "primary_recipients": [{
                "billing_info": {
                    "email_address": "buyer@example.com"
                }
            }],
            "items": [{
                "name": "Service",
                "quantity": "1",
                "unit_amount": amount("USD", "100.00")
            }]
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(invoice("INV-1", "DRAFT")))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/invoicing/invoices"))
        .and(query_param("page", "1"))
        .and(query_param("page_size", "20"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [invoice("INV-1", "DRAFT")],
            "total_items": 1,
            "total_pages": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v2/invoicing/invoices/INV-1/send"))
        .and(header("authorization", BEARER_AUTH))
        .and(header("paypal-request-id", "send-idem-key"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/checkout/orders"))
        .and(query_param("limit", "1"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "name": "INVALID_REQUEST",
            "message": "limit is not supported on this endpoint"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let runtime = test_runtime();
    let client = paypal_client(&server);

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
                    description: Some("FCP order".into()),
                    reference_id: Some("ref-1".into()),
                }],
            },
            Some("order-idem-key"),
        )
        .await
        .expect("order create should decode");
    assert_eq!(created.id, "ORDER-1");

    let fetched = client
        .get_order(&runtime, "ORDER-1")
        .await
        .expect("order get should decode");
    assert_eq!(fetched.status, "APPROVED");

    let captured = client
        .capture_order(&runtime, "ORDER-1", Some("capture-idem-key"))
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
        Some("TXN-1"),
    );

    let fetched_capture = client
        .get_capture(&runtime, "CAPTURE-1")
        .await
        .expect("capture get should decode");
    assert_eq!(fetched_capture.status, "COMPLETED");

    let refund = client
        .refund_capture(
            &runtime,
            "CAPTURE-1",
            &RefundRequest {
                amount: Some(Amount {
                    currency_code: "USD".into(),
                    value: "12.50".into(),
                }),
                note_to_payer: Some("partial refund".into()),
            },
            Some("refund-idem-key"),
        )
        .await
        .expect("refund should decode");
    assert_eq!(refund.id, "REFUND-1");

    let invoice = client
        .create_invoice(
            &runtime,
            &CreateInvoice {
                detail: CreateInvoiceDetail {
                    currency_code: "USD".into(),
                    invoice_number: Some("INV-001".into()),
                    memo: Some("FCP invoice".into()),
                },
                primary_recipients: vec![CreateRecipient {
                    billing_info: CreateBillingInfo {
                        email_address: "buyer@example.com".into(),
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
            Some("invoice-idem-key"),
        )
        .await
        .expect("invoice create should decode");
    assert_eq!(invoice.status, "DRAFT");

    let invoices = client
        .list_invoices(&runtime)
        .await
        .expect("invoice list should decode");
    assert_eq!(invoices.items[0].id, "INV-1");

    let sent = client
        .send_invoice(&runtime, "INV-1", Some("send-idem-key"))
        .await
        .expect("invoice send should return contract shape");
    assert!(sent.sent);

    assert!(
        client
            .health_check(&runtime)
            .await
            .expect("400 health probe shape still proves reachability")
    );
}

#[fcp_async_core::runtime::test]
async fn auth_rate_limit_not_found_malformed_json_and_invalid_input_are_typed() {
    init_logging();
    tracing::info!(
        scenario = "paypal_error_taxonomy",
        "starting PayPal error-taxonomy proof",
    );

    let token_failure_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth2/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client"
        })))
        .expect(1)
        .mount(&token_failure_server)
        .await;

    let runtime = test_runtime();
    let token_failure_client = paypal_client(&token_failure_server);
    let token_error = token_failure_client
        .get_order(&runtime, "ORDER-UNAUTH")
        .await
        .expect_err("OAuth token 401 should fail before resource request");
    assert!(matches!(token_error, PayPalError::OAuth(_)));
    assert!(!token_error.is_retryable());
    assert!(matches!(
        token_error.to_fcp_error(),
        FcpError::Unauthorized { code: 2002, .. }
    ));

    let server = MockServer::start().await;
    mount_oauth_token(&server).await;

    Mock::given(method("GET"))
        .and(path("/v2/payments/captures/unauthorized"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "name": "AUTHENTICATION_FAILURE"
        })))
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/payments/captures/rate_limited"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "7")
                .set_body_json(json!({ "name": "RATE_LIMIT_REACHED" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/checkout/orders/missing"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "name": "RESOURCE_NOT_FOUND"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/checkout/orders/bad_json"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&server)
        .await;

    let client = paypal_client(&server);

    let unauthorized = client
        .get_capture(&runtime, "unauthorized")
        .await
        .expect_err("API 401 should be typed unauthorized after one token refresh");
    assert!(matches!(unauthorized, PayPalError::Unauthorized(_)));
    assert!(!unauthorized.is_retryable());

    let rate_limited = client
        .get_capture(&runtime, "rate_limited")
        .await
        .expect_err("429 should map to rate limit with Retry-After");
    assert!(matches!(
        rate_limited,
        PayPalError::RateLimited {
            retry_after_ms: 7_000
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::from_secs(7)));
    assert!(matches!(
        rate_limited.to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 7_000,
            ..
        }
    ));

    let missing = client
        .get_order(&runtime, "missing")
        .await
        .expect_err("404 should map to not found");
    assert!(matches!(missing, PayPalError::NotFound(_)));
    assert!(!missing.is_retryable());

    let malformed = client
        .get_order(&runtime, "bad_json")
        .await
        .expect_err("malformed JSON should be a typed decode failure");
    assert!(matches!(malformed, PayPalError::Http(ref source) if source.is_decode()));
    assert!(!malformed.is_retryable());

    let traversal = client
        .get_order(&runtime, "../admin")
        .await
        .expect_err("path traversal should be rejected before outbound call");
    assert!(matches!(traversal, PayPalError::InvalidInput(_)));
}

#[fcp_async_core::runtime::test]
async fn reqwest_timeout_bounds_slow_paypal_responses() {
    init_logging();
    tracing::info!(scenario = "paypal_timeout", "starting PayPal timeout proof",);

    let server = MockServer::start().await;
    mount_oauth_token(&server).await;

    Mock::given(method("GET"))
        .and(path("/v2/checkout/orders/slow"))
        .and(header("authorization", BEARER_AUTH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(order("slow", "APPROVED")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let runtime = test_runtime();
    let client = PayPalClient::new(
        &server.uri(),
        CLIENT_ID.into(),
        CLIENT_SECRET.into(),
        50,
        no_retry_config(),
    )
    .expect("wiremock URI should build a PayPal client");

    let error = client
        .get_order(&runtime, "slow")
        .await
        .expect_err("slow response should hit reqwest timeout");

    assert!(matches!(error, PayPalError::Http(ref source) if source.is_timeout()));
    assert!(error.is_retryable());
}

#[test]
fn manifest_and_operation_catalog_preserve_risk_approval_and_event_metadata() {
    init_logging();

    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("forbidden = [\"system.exec\", \"network.listen\""));
    assert!(manifest.contains("webhook ingest"));

    let introspection = PayPalConnector::new().introspect();
    assert!(introspection.events.is_empty());
    assert!(
        !introspection
            .event_caps
            .as_ref()
            .expect("event caps")
            .streaming
    );

    for operation in &introspection.operations {
        assert!(
            manifest.contains(&format!(
                "[provides.operations.\"{}\"]",
                operation.id.as_str()
            )),
            "manifest should declare {}",
            operation.id
        );
    }

    let operation = |id: &str| {
        introspection
            .operations
            .iter()
            .find(|entry| entry.id.as_str() == id)
            .expect("operation catalog should contain requested PayPal operation")
    };

    let order_create = operation("paypal.orders.create");
    assert_eq!(order_create.risk_level, RiskLevel::High);
    assert_eq!(order_create.safety_tier, SafetyTier::Risky);
    assert_eq!(order_create.idempotency, IdempotencyClass::BestEffort);
    assert_eq!(
        order_create.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let payment_get = operation("paypal.payments.get");
    assert_eq!(payment_get.risk_level, RiskLevel::Low);
    assert_eq!(payment_get.safety_tier, SafetyTier::Safe);
    assert_eq!(payment_get.idempotency, IdempotencyClass::Strict);
    assert_eq!(payment_get.requires_approval, Some(ApprovalMode::None));

    let refund = operation("paypal.payments.refund");
    assert_eq!(refund.risk_level, RiskLevel::High);
    assert_eq!(refund.safety_tier, SafetyTier::Risky);
    assert_eq!(refund.idempotency, IdempotencyClass::BestEffort);
    assert_eq!(refund.requires_approval, Some(ApprovalMode::Interactive));

    let invoice_send = operation("paypal.invoices.send");
    assert_eq!(invoice_send.risk_level, RiskLevel::High);
    assert_eq!(invoice_send.safety_tier, SafetyTier::Risky);
    assert_eq!(invoice_send.idempotency, IdempotencyClass::BestEffort);
    assert_eq!(
        invoice_send.requires_approval,
        Some(ApprovalMode::Interactive)
    );
}

#[fcp_async_core::runtime::test]
async fn webhook_ingress_is_explicitly_rejected_for_request_response_slice() {
    init_logging();

    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("forbidden = [\"system.exec\", \"network.listen\""));
    assert!(manifest.contains("webhook ingest"));

    let connector = PayPalConnector::new();
    let introspection = connector.introspect();
    let operation_ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(operation_ids.len(), 10);
    for rejected in [
        "paypal.ingest_webhook_event",
        "paypal.webhook.ingest",
        "paypal.webhooks.ingest",
        "paypal.subscription.events",
    ] {
        assert!(
            !operation_ids.contains(&rejected),
            "{rejected} must stay absent until PayPal webhook verification is implemented"
        );
    }

    assert!(introspection.events.is_empty());
    let event_caps = introspection.event_caps.as_ref().expect("event caps");
    assert!(!event_caps.streaming);
    assert!(!event_caps.replay);
    assert_eq!(event_caps.min_buffer_events, 0);
    assert!(!event_caps.requires_ack);

    let subscribe_error = connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("paypal-webhook-rejection-proof"),
            topics: vec!["paypal.webhook".into()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        })
        .await
        .expect_err("PayPal webhooks must not silently subscribe");
    assert!(matches!(subscribe_error, FcpError::StreamingNotSupported));

    let health = connector.health().await;
    let details = health.details.as_ref().expect("health details");
    assert_eq!(
        details["contract"]["service_inventory"]["webhooks"]["supported"],
        false
    );
    let webhook_notes = details["contract"]["service_inventory"]["webhooks"]["notes"]
        .as_array()
        .expect("webhook notes");
    assert!(webhook_notes.iter().any(|note| {
        note.as_str()
            .is_some_and(|text| text.contains("no inbound webhook verification"))
    }));
    println!(
        "paypal_webhook_rejection_evidence={}",
        serde_json::to_string_pretty(&serde_json::json!({
            "operations": operation_ids,
            "event_caps": event_caps,
            "webhook_contract": details["contract"]["service_inventory"]["webhooks"],
        }))
        .unwrap()
    );
}

#[test]
fn debug_output_redacts_paypal_credentials_and_tokens() {
    init_logging();

    let auth = PayPalAuth {
        client_id: "client-visible-secret".into(),
        client_secret: "merchant-secret".into(),
    };
    let debug_auth = format!("{auth:?}");
    assert!(debug_auth.contains("[REDACTED]"));
    assert!(!debug_auth.contains("client-visible-secret"));
    assert!(!debug_auth.contains("merchant-secret"));

    let opaque_bearer_value = ["live", "access", "marker"].join("-");
    let oauth_response = TokenResponse {
        access_token: opaque_bearer_value.clone(),
        token_type: "Bearer".into(),
        expires_in: Some(3600),
        scope: Some("orders invoices".into()),
    };
    let debug_response = format!("{oauth_response:?}");
    assert!(debug_response.contains("[REDACTED]"));
    assert!(!debug_response.contains(&opaque_bearer_value));

    let config = PayPalConfig {
        client_id: "merchant-client-id".into(),
        client_secret: "merchant-client-secret".into(),
        base_url: "https://api-m.sandbox.paypal.com".into(),
        sandbox: true,
        retry: no_retry_config(),
        request_timeout_ms: 500,
    };
    let debug_config = format!("{config:?}");
    assert!(debug_config.contains("[REDACTED]"));
    assert!(!debug_config.contains("merchant-client-id"));
    assert!(!debug_config.contains("merchant-client-secret"));

    let client = PayPalClient::new(
        "https://api-m.sandbox.paypal.com",
        "client-id-for-debug".into(),
        "client-secret-for-debug".into(),
        500,
        no_retry_config(),
    )
    .expect("redaction proof client should build");
    let debug_client = format!("{client:?}");
    assert!(debug_client.contains("[REDACTED]"));
    assert!(!debug_client.contains("client-id-for-debug"));
    assert!(!debug_client.contains("client-secret-for-debug"));
}
