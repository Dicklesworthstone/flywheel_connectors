//! Stripe retry-scope contracts: provider retries must not authorize a new
//! payment invocation with a different automatically generated key.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use fcp_stripe::client::StripeClient;
use fcp_stripe::error::StripeError;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn client(server: &MockServer, retries: u32) -> StripeClient {
    StripeClient::new("sk_test_scope_secret")
        .unwrap()
        .with_api_url(&format!("{}/v1", server.uri()))
        .with_retry_config(retries)
}

fn assert_unknown(error: &StripeError) {
    assert!(matches!(error, StripeError::MutationOutcomeUnknown));
    assert!(!ConnectorErrorMapping::is_retryable(error));
    assert!(ConnectorErrorMapping::retry_after(error).is_none());
    assert!(matches!(
        ConnectorErrorMapping::to_fcp_error(error),
        FcpError::External {
            status_code: None,
            retryable: false,
            retry_after: None,
            ref message,
            ..
        } if message.contains("reconcile") && !message.contains("sk_test_scope_secret")
    ));
}

async fn assert_same_key(server: &MockServer, expected: Option<&str>) {
    let requests = server.received_requests().await.unwrap();
    assert!(requests.len() >= 2, "the retry path must actually execute");
    let first = requests[0].headers.get("idempotency-key").unwrap();
    for request in &requests {
        assert_eq!(request.headers.get("idempotency-key"), Some(first));
        assert_eq!(request.body, requests[0].body);
    }
    if let Some(expected) = expected {
        assert_eq!(first.to_str().unwrap(), expected);
    } else {
        assert!(first.to_str().unwrap().starts_with("fcp2:retry:"));
    }
}

#[fcp_async_core::runtime::test]
async fn generated_key_retries_locally_but_not_across_invocations() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/payment_intents"))
        .respond_with(ResponseTemplate::new(500).set_body_string("private provider details"))
        .expect(2)
        .mount(&server)
        .await;
    let error = client(&server, 1)
        .create_payment_intent(2000, "usd", None)
        .await
        .unwrap_err();
    assert_unknown(&error);
    assert!(!error.to_string().contains("private provider details"));
    assert_same_key(&server, None).await;
}

#[fcp_async_core::runtime::test]
async fn caller_supplied_key_preserves_cross_invocation_recovery() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/payment_intents"))
        .respond_with(ResponseTemplate::new(503))
        .expect(2)
        .mount(&server)
        .await;
    let error = client(&server, 1)
        .create_payment_intent_with_idempotency(2000, "usd", None, Some("order-stable-1"))
        .await
        .unwrap_err();
    assert!(error.is_retryable());
    assert!(!matches!(error, StripeError::MutationOutcomeUnknown));
    assert_same_key(&server, Some("order-stable-1")).await;
}

#[fcp_async_core::runtime::test]
async fn read_only_failures_remain_retryable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(503))
        .expect(2)
        .mount(&server)
        .await;
    let error = client(&server, 1).get_balance().await.unwrap_err();
    assert!(error.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn rate_limit_before_execution_does_not_claim_unknown_mutation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 0)
        .create_customer("test@example.com", None)
        .await
        .unwrap_err();
    assert!(matches!(error, StripeError::RateLimited { retry_after_ms: 1000 }));
    assert!(error.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn a_later_rate_limit_does_not_erase_an_ambiguous_payment() {
    let server = MockServer::start().await;
    let attempts = AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/v1/payment_intents"))
        .respond_with(move |_: &Request| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(429).insert_header("Retry-After", "1")
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let error = client(&server, 1)
        .create_payment_intent(2000, "usd", None)
        .await
        .unwrap_err();
    assert_unknown(&error);
    assert_same_key(&server, None).await;
}

#[fcp_async_core::runtime::test]
async fn same_key_success_resolves_an_earlier_ambiguous_attempt() {
    let server = MockServer::start().await;
    let attempts = AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/v1/payment_intents"))
        .respond_with(move |_: &Request| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "id": "pi_original", "object": "payment_intent", "amount": 2000,
                    "currency": "usd", "status": "succeeded"
                }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let payment = client(&server, 1)
        .create_payment_intent(2000, "usd", None)
        .await
        .unwrap();
    assert_eq!(payment.id, "pi_original");
    assert_same_key(&server, None).await;
}

#[fcp_async_core::runtime::test]
async fn unreadable_success_is_an_unknown_mutation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{broken-json"))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 1)
        .create_customer("test@example.com", None)
        .await
        .unwrap_err();
    assert_unknown(&error);
}

#[fcp_async_core::runtime::test]
async fn same_key_conflict_does_not_authorize_a_fresh_invocation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .respond_with(ResponseTemplate::new(409))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 0)
        .create_customer("test@example.com", None)
        .await
        .unwrap_err();
    assert_unknown(&error);
}

#[fcp_async_core::runtime::test]
async fn shutdown_during_a_sent_request_preserves_unknown_outcome() {
    let server = MockServer::start().await;
    let client = Arc::new(client(&server, 1));
    let shutdown = Arc::clone(&client);
    Mock::given(method("POST"))
        .and(path("/v1/customers"))
        .respond_with(move |_: &Request| {
            // The server has received the request. Cancel before returning its
            // response, rather than relying on timing to guess when send ran.
            shutdown.shutdown();
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(10))
                .set_body_json(json!({ "id": "cus_original", "object": "customer" }))
        })
        .expect(1)
        .mount(&server)
        .await;
    let error = client
        .create_customer("test@example.com", None)
        .await
        .unwrap_err();
    assert_unknown(&error);
}

#[fcp_async_core::runtime::test]
async fn shutdown_before_send_does_not_claim_a_request_was_sent() {
    let server = MockServer::start().await;
    let client = client(&server, 1);
    client.shutdown();
    let error = client
        .create_customer("test@example.com", None)
        .await
        .unwrap_err();
    assert!(!matches!(error, StripeError::MutationOutcomeUnknown));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn refund_with_a_generated_key_has_the_same_host_boundary_protection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/refunds"))
        .respond_with(ResponseTemplate::new(500))
        .expect(2)
        .mount(&server)
        .await;
    let error = client(&server, 1)
        .create_refund_with_idempotency("pi_original", Some(500), None)
        .await
        .unwrap_err();
    assert_unknown(&error);
    assert_same_key(&server, None).await;
}

#[fcp_async_core::runtime::test]
async fn invalid_keys_never_reach_the_provider_or_become_retryable() {
    let server = MockServer::start().await;
    let client = client(&server, 2);
    for key in [
        String::new(),
        " ".to_owned(),
        "x".repeat(256),
        "private-key\r\nInjected: yes".to_owned(),
        "private-key\t".to_owned(),
        "private-key\0".to_owned(),
        "private-keyé".to_owned(),
        " private-key".to_owned(),
    ] {
        let error = client
            .create_payment_intent_with_idempotency(2000, "usd", None, Some(&key))
            .await
            .unwrap_err();
        assert!(matches!(error, StripeError::InvalidIdempotencyKey));
        assert!(!error.is_retryable());
        assert!(!error.to_string().contains("private-key"));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn maximum_length_caller_key_is_preserved() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/payment_intents"))
        .respond_with(ResponseTemplate::new(500))
        .expect(2)
        .mount(&server)
        .await;
    let key = "k".repeat(255);
    let error = client(&server, 1)
        .create_payment_intent_with_idempotency(2000, "usd", None, Some(&key))
        .await
        .unwrap_err();
    assert!(error.is_retryable());
    assert_same_key(&server, Some(&key)).await;
}

#[fcp_async_core::runtime::test]
async fn post_redirect_cannot_replay_body_or_key_at_another_origin() {
    let server = MockServer::start().await;
    let destination = MockServer::start().await;
    let location = format!("{}/stolen?credential=private-key", destination.uri());
    Mock::given(method("POST"))
        .and(path("/v1/payment_intents"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", location.as_str()))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 2)
        .create_payment_intent_with_idempotency(2000, "usd", None, Some("order-stable-1"))
        .await
        .unwrap_err();
    assert!(matches!(error, StripeError::UnexpectedRedirect { status_code: 307 }));
    assert!(!error.is_retryable());
    assert!(!error.to_string().contains("private-key"));
    assert!(destination.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn get_redirect_is_not_followed_or_marked_retryable() {
    let server = MockServer::start().await;
    let destination = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", destination.uri()))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 2).get_balance().await.unwrap_err();
    assert!(matches!(error, StripeError::UnexpectedRedirect { status_code: 302 }));
    assert!(!error.is_retryable());
    assert!(destination.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn provider_retry_refusal_stops_even_read_only_server_error_retries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/balance"))
        .respond_with(ResponseTemplate::new(500).insert_header("Stripe-Should-Retry", "false"))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 2).get_balance().await.unwrap_err();
    assert!(matches!(error, StripeError::RetryForbidden { status_code: 500 }));
    assert!(!error.is_retryable());
    assert!(matches!(error.to_fcp_error(), FcpError::External { retryable: false, .. }));
}

#[fcp_async_core::runtime::test]
async fn provider_retry_refusal_overrides_rate_limit_and_caller_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/payment_intents"))
        .respond_with(ResponseTemplate::new(429).insert_header("Stripe-Should-Retry", "false"))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 2)
        .create_payment_intent_with_idempotency(2000, "usd", None, Some("order-stable-1"))
        .await
        .unwrap_err();
    assert!(matches!(error, StripeError::RetryForbidden { status_code: 429 }));
    assert!(!error.is_retryable());
    assert!(error.retry_after().is_none());
}

#[fcp_async_core::runtime::test]
async fn request_build_failure_is_not_retryable_or_reported_as_sent() {
    let client = StripeClient::new("sk_test_scope_secret")
        .unwrap()
        .with_api_url("not a URL")
        .with_retry_config(2);
    let error = client.create_customer("test@example.com", None).await.unwrap_err();
    assert!(matches!(error, StripeError::RequestBuildFailed));
    assert!(!error.is_retryable());
    assert!(matches!(error.to_fcp_error(), FcpError::InvalidRequest { code: 1005, .. }));
}
