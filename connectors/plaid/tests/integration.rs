#![allow(clippy::doc_markdown)]
//! Integration tests for the FCP Plaid connector (flywheel_connectors-38h.5).
//!
//! All tests are deterministic (mock-only, no real API calls).
//!
//! Coverage areas:
//! - Request/response parsing (link token, token exchange, accounts, transactions sync, balance)
//! - Error taxonomy mapping (`PlaidError` -> `FcpError`)
//! - Redaction (no `client_id`, secret, or access tokens in error messages)
//! - Cursor advancement logic (`transactions_sync` pagination)
//! - Connector dispatch (full invoke pipeline with capability tokens)

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_plaid::{client::PlaidClient, connector::PlaidConnector, error::PlaidError};
use fcp_prelude::{CapabilityConstraints, CapabilityToken, FcpError};
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

// ============================================================================
// Helpers
// ============================================================================

fn capability_for_operation(op: &str) -> &str {
    match op {
        "plaid.link_token_create" | "plaid.token_exchange" => "plaid.link",
        "plaid.transactions_get" | "plaid.transactions_sync" => "plaid.transactions.read",
        "plaid.auth_get" => "plaid.auth.read",
        "plaid.identity_get" => "plaid.identity.read",
        "plaid.investments_holdings_get" => "plaid.investments.read",
        "plaid.liabilities_get" => "plaid.liabilities.read",
        _ => "plaid.accounts.read",
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &str,
) -> CapabilityToken {
    let cap = capability_for_operation(op);
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
        .unwrap()
        .sign(signing_key)
        .unwrap();
    CapabilityToken::from_raw(cose)
}

async fn setup_handshake(connector: &mut PlaidConnector, ops: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let caps: Vec<&str> = ops.iter().map(|op| capability_for_operation(op)).collect();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": caps,
        }))
        .await
        .expect("handshake");
    signing_key
}

async fn setup_configure(connector: &mut PlaidConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "client_id": "test_client_id",
            "secret": "test_secret",
            "base_url": base_url,
            "environment": "sandbox",
        }))
        .await
        .expect("configure");
}

fn build_client(client_id: &str, secret: &str, base_url: &str) -> PlaidClient {
    PlaidClient::new(client_id, secret, base_url).expect("plaid client")
}

// ============================================================================
// 1. Request/response parsing
// ============================================================================

/// Parse `link_token_create` response correctly.
#[fcp_async_core::test]
async fn parse_link_token_create_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/link/token/create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "link_token": "link-sandbox-abc123",
            "expiration": "2026-03-02T23:59:59Z",
            "request_id": "req-lt-1"
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let result = client
        .link_token_create(
            "TestApp",
            &["transactions".to_string()],
            &["US".to_string()],
            "en",
            None,
        )
        .await
        .unwrap();
    assert_eq!(result.link_token, "link-sandbox-abc123");
    assert_eq!(result.expiration, "2026-03-02T23:59:59Z");
}

/// Parse `token_exchange` response correctly.
#[fcp_async_core::test]
async fn parse_token_exchange_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/item/public_token/exchange"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-sandbox-abc123",
            "item_id": "item-abc",
            "request_id": "req-te-1"
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let result = client.token_exchange("public-sandbox-xyz").await.unwrap();
    assert_eq!(result.access_token, "access-sandbox-abc123");
    assert_eq!(result.item_id, "item-abc");
}

/// Parse `accounts_get` response with account details.
#[fcp_async_core::test]
async fn parse_accounts_get_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-1",
                "balances": {
                    "available": 1000.0,
                    "current": 1100.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "1234",
                "name": "Plaid Savings",
                "official_name": "Plaid Gold Savings",
                "subtype": "savings",
                "type": "depository"
            }],
            "item": {
                "item_id": "item-1",
                "institution_id": "ins_109508",
                "available_products": ["balance", "auth"],
                "billed_products": ["transactions"]
            }
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let (accounts, item) = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].account_id, "acc-1");
    assert_eq!(accounts[0].name, "Plaid Savings");
    assert_eq!(accounts[0].balances.available, Some(1000.0));
    assert_eq!(
        accounts[0].balances.iso_currency_code.as_deref(),
        Some("USD")
    );
    assert_eq!(item.item_id, "item-1");
    assert_eq!(item.institution_id.as_deref(), Some("ins_109508"));
}

/// Parse `transactions_sync` response with cursor and transactions.
#[fcp_async_core::test]
async fn parse_transactions_sync_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "added": [{
                "transaction_id": "tx-1",
                "account_id": "acc-1",
                "amount": 42.50,
                "iso_currency_code": "USD",
                "date": "2026-02-28",
                "name": "Grocery Store",
                "merchant_name": "Whole Foods",
                "pending": false,
                "category": ["Food and Drink", "Groceries"],
                "category_id": "19047000"
            }],
            "modified": [],
            "removed": [{ "transaction_id": "tx-old" }],
            "next_cursor": "cursor-page2",
            "has_more": true
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let result = client
        .transactions_sync("access-sandbox-xxx", Some("cursor-page1"), Some(100))
        .await
        .unwrap();
    assert_eq!(result.added.len(), 1);
    assert_eq!(result.added[0].transaction_id, "tx-1");
    assert_eq!(
        result.added[0].merchant_name.as_deref(),
        Some("Whole Foods")
    );
    assert!(result.modified.is_empty());
    assert_eq!(result.removed.len(), 1);
    assert_eq!(result.removed[0].transaction_id, "tx-old");
    assert_eq!(result.next_cursor, "cursor-page2");
    assert!(result.has_more);
}

/// Parse `accounts_balance_get` response.
#[fcp_async_core::test]
async fn parse_accounts_balance_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/balance/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-1",
                "balances": {
                    "available": 500.0,
                    "current": 510.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "5678",
                "name": "Checking",
                "official_name": null,
                "subtype": "checking",
                "type": "depository"
            }]
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let accounts = client
        .accounts_balance_get("access-sandbox-xxx", None)
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].balances.available, Some(500.0));
    assert_eq!(accounts[0].balances.current, Some(510.0));
}

// ============================================================================
// 2. Error taxonomy mapping
// ============================================================================

/// 401 Unauthorized -> `FcpError::Unauthorized`.
#[fcp_async_core::test]
async fn error_401_maps_to_unauthorized() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error_type": "INVALID_INPUT",
            "error_code": "INVALID_API_KEYS",
            "error_message": "invalid client_id or secret provided"
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("bad_id", "bad_secret", &mock.base_url()).with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 403 Forbidden -> `FcpError::Unauthorized`.
#[fcp_async_core::test]
async fn error_403_maps_to_unauthorized() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error_type": "INVALID_REQUEST",
            "error_code": "ACCESS_NOT_GRANTED",
            "error_message": "access not granted for this product"
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url()).with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Unauthorized { .. }),
        "expected Unauthorized, got: {fcp_err:?}"
    );
}

/// 429 Too Many Requests -> `FcpError::RateLimited`.
#[fcp_async_core::test]
async fn error_429_maps_to_rate_limited() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(429))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url()).with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::RateLimited { .. }),
        "expected RateLimited, got: {fcp_err:?}"
    );
}

/// 500 Server Error -> `FcpError::External` (retryable).
#[fcp_async_core::test]
async fn error_500_maps_to_external_retryable() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url()).with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    assert!(err.is_retryable());
    let fcp_err = err.to_fcp_error();
    match fcp_err {
        FcpError::External {
            service, retryable, ..
        } => {
            assert_eq!(service, "plaid");
            assert!(retryable);
        }
        other => panic!("expected External, got: {other:?}"),
    }
}

/// `InvalidConfig` -> `FcpError::Internal`.
#[test]
fn error_invalid_config_maps_to_internal() {
    let err = PlaidError::InvalidConfig("missing credentials".into());
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Internal { .. }),
        "expected Internal, got: {fcp_err:?}"
    );
}

// ============================================================================
// 3. Redaction -- no client_id, secret, or access tokens in errors
// ============================================================================

/// `client_id` must not appear in error messages produced by the connector.
#[fcp_async_core::test]
async fn client_id_not_in_error_messages() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Server Error"))
        .mount(mock.inner())
        .await;

    let client =
        build_client("SENSITIVE_CLIENT_ID", "test_secret", &mock.base_url()).with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        !msg.contains("SENSITIVE_CLIENT_ID"),
        "client_id leaked in error: {msg}"
    );
}

/// `secret` must not appear in error messages produced by the connector.
#[fcp_async_core::test]
async fn secret_not_in_error_messages() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Server Error"))
        .mount(mock.inner())
        .await;

    let client =
        build_client("test_id", "SUPERSECRET_VALUE_9876", &mock.base_url()).with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-xxx", None)
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        !msg.contains("SUPERSECRET_VALUE_9876"),
        "secret leaked in error: {msg}"
    );
}

/// Access token must not appear in connector invoke error messages.
#[fcp_async_core::test]
async fn access_token_not_in_invoke_errors() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error_type": "INVALID_REQUEST",
            "error_code": "INVALID_ACCESS_TOKEN",
            "error_message": "the access token is invalid"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.accounts_get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "plaid.accounts_get");

    let err = connector
        .handle_invoke(json!({
            "operation": "plaid.accounts_get",
            "input": { "access_token": "access-sandbox-REDACTME-xyz" },
            "capability_token": token
        }))
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        !msg.contains("access-sandbox-REDACTME-xyz"),
        "access_token leaked in invoke error: {msg}"
    );
}

// ============================================================================
// 4. Cursor advancement logic
// ============================================================================

/// Cursor advances from initial (empty) to `next_cursor`.
#[fcp_async_core::test]
async fn transactions_sync_cursor_advances() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "added": [{
                "transaction_id": "tx-new-1",
                "account_id": "acc-1",
                "amount": 15.00,
                "iso_currency_code": "USD",
                "date": "2026-03-01",
                "name": "Coffee",
                "merchant_name": null,
                "pending": false,
                "category": ["Food and Drink"],
                "category_id": "13000000"
            }],
            "modified": [],
            "removed": [],
            "next_cursor": "cursor-after-initial-sync",
            "has_more": false
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    // Initial sync with no cursor
    let result = client
        .transactions_sync("access-sandbox-xxx", None, Some(100))
        .await
        .unwrap();
    assert!(!result.next_cursor.is_empty(), "next_cursor should be set");
    assert_eq!(result.next_cursor, "cursor-after-initial-sync");
    assert!(!result.has_more);
}

/// Pagination: `has_more=true` signals more pages to fetch.
#[fcp_async_core::test]
async fn transactions_sync_has_more_pagination() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "added": [{
                "transaction_id": "tx-page2-1",
                "account_id": "acc-1",
                "amount": 99.99,
                "iso_currency_code": "USD",
                "date": "2026-03-01",
                "name": "Electronics Store",
                "merchant_name": "Best Buy",
                "pending": false,
                "category": ["Shops"],
                "category_id": "19000000"
            }],
            "modified": [{
                "transaction_id": "tx-modified-1",
                "account_id": "acc-1",
                "amount": 50.00,
                "iso_currency_code": "USD",
                "date": "2026-02-28",
                "name": "Updated Merchant",
                "merchant_name": "Updated",
                "pending": false,
                "category": ["Shops"],
                "category_id": "19000000"
            }],
            "removed": [{ "transaction_id": "tx-deleted-1" }],
            "next_cursor": "cursor-page3",
            "has_more": true
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let result = client
        .transactions_sync("access-sandbox-xxx", Some("cursor-page2"), Some(50))
        .await
        .unwrap();
    assert_eq!(result.added.len(), 1);
    assert_eq!(result.modified.len(), 1);
    assert_eq!(result.removed.len(), 1);
    assert!(result.has_more, "has_more should be true for mid-sync page");
    assert_eq!(result.next_cursor, "cursor-page3");
}

// ============================================================================
// 5. Connector dispatch (full invoke pipeline with capability tokens)
// ============================================================================

/// Dispatch `accounts_get` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_accounts_get_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-dispatch-1",
                "balances": {
                    "available": 250.0,
                    "current": 250.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "0001",
                "name": "Dispatch Checking",
                "official_name": null,
                "subtype": "checking",
                "type": "depository"
            }],
            "item": {
                "item_id": "item-dispatch",
                "institution_id": "ins_1"
            }
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.accounts_get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "plaid.accounts_get");

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.accounts_get",
            "input": { "access_token": "access-sandbox-dispatch" },
            "capability_token": token
        }))
        .await
        .expect("invoke accounts_get should succeed");
    let accounts = result["accounts"].as_array().expect("accounts array");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["account_id"], "acc-dispatch-1");
}

/// Dispatch `transactions_sync` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_transactions_sync_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "added": [{
                "transaction_id": "tx-dispatch-1",
                "account_id": "acc-1",
                "amount": 12.34,
                "iso_currency_code": "USD",
                "date": "2026-03-01",
                "name": "Test Merchant",
                "merchant_name": "TestCo",
                "pending": false,
                "category": ["Food and Drink"],
                "category_id": "13000000"
            }],
            "modified": [],
            "removed": [],
            "next_cursor": "cursor-dispatch-2",
            "has_more": false
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.transactions_sync"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.transactions_sync",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.transactions_sync",
            "input": {
                "access_token": "access-sandbox-dispatch",
                "cursor": "",
                "count": 100
            },
            "capability_token": token
        }))
        .await
        .expect("invoke transactions_sync should succeed");
    assert_eq!(result["next_cursor"], "cursor-dispatch-2");
    assert_eq!(result["has_more"], false);
    let added = result["added"].as_array().expect("added array");
    assert_eq!(added.len(), 1);
    assert_eq!(added[0]["transaction_id"], "tx-dispatch-1");
}

/// Dispatch `link_token_create` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_link_token_create_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/link/token/create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "link_token": "link-sandbox-dispatch-abc",
            "expiration": "2026-03-03T00:00:00Z",
            "request_id": "req-dispatch-1"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.link_token_create"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.link_token_create",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.link_token_create",
            "input": {
                "client_name": "TestApp",
                "products": ["transactions"],
                "country_codes": ["US"],
                "language": "en"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke link_token_create should succeed");
    assert_eq!(result["link_token"], "link-sandbox-dispatch-abc");
}

// ============================================================================
// 6. Client-level tests for untested operations
// ============================================================================

/// Parse `auth_get` response with ACH routing numbers.
#[fcp_async_core::test]
async fn parse_auth_get_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-auth-1",
                "balances": {
                    "available": 800.0,
                    "current": 850.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "4321",
                "name": "ACH Checking",
                "official_name": "Premium Checking",
                "subtype": "checking",
                "type": "depository"
            }],
            "numbers": {
                "ach": [{
                    "account_id": "acc-auth-1",
                    "account": "9900009606",
                    "routing": "011401533",
                    "wire_routing": "021000021"
                }],
                "eft": [],
                "international": [],
                "bacs": []
            }
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let (accounts, numbers) = client.auth_get("access-sandbox-xxx").await.unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].account_id, "acc-auth-1");
    assert_eq!(accounts[0].name, "ACH Checking");
    let ach = numbers.ach.expect("ach numbers present");
    assert_eq!(ach.len(), 1);
    assert_eq!(ach[0]["routing"], "011401533");
}

/// Parse `auth_get` response with empty routing numbers.
#[fcp_async_core::test]
async fn parse_auth_get_empty_numbers() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [],
            "numbers": {
                "ach": [],
                "eft": [],
                "international": [],
                "bacs": []
            }
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let (accounts, numbers) = client.auth_get("access-sandbox-xxx").await.unwrap();
    assert!(accounts.is_empty());
    assert!(numbers.ach.unwrap().is_empty());
    assert!(numbers.eft.unwrap().is_empty());
}

/// Parse `identity_get` response with PII.
#[fcp_async_core::test]
async fn parse_identity_get_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-id-1",
                "owners": [{
                    "names": ["Jane Doe"],
                    "emails": [{ "data": "jane@example.com", "primary": true, "type": "primary" }],
                    "phone_numbers": [{ "data": "+15551234567", "primary": true, "type": "mobile" }],
                    "addresses": [{
                        "data": {
                            "street": "123 Main St",
                            "city": "New York",
                            "region": "NY",
                            "postal_code": "10001",
                            "country": "US"
                        },
                        "primary": true
                    }]
                }]
            }]
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let accounts = client.identity_get("access-sandbox-xxx").await.unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["account_id"], "acc-id-1");
    let owners = accounts[0]["owners"].as_array().unwrap();
    assert_eq!(owners[0]["names"][0], "Jane Doe");
}

/// Parse `identity_get` with empty accounts.
#[fcp_async_core::test]
async fn parse_identity_get_empty_accounts() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": []
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let accounts = client.identity_get("access-sandbox-xxx").await.unwrap();
    assert!(accounts.is_empty());
}

/// Parse `investments_holdings_get` response with holdings and securities.
#[fcp_async_core::test]
async fn parse_investments_holdings_get_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/investments/holdings/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-inv-1",
                "balances": {
                    "available": null,
                    "current": 25000.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "7890",
                "name": "Brokerage",
                "official_name": "Vanguard Brokerage",
                "subtype": "brokerage",
                "type": "investment"
            }],
            "holdings": [{
                "account_id": "acc-inv-1",
                "security_id": "sec-1",
                "quantity": 50.0,
                "institution_price": 175.25,
                "institution_value": 8762.50,
                "cost_basis": 7500.0,
                "iso_currency_code": "USD"
            }],
            "securities": [{
                "security_id": "sec-1",
                "name": "Apple Inc",
                "ticker_symbol": "AAPL",
                "type": "equity",
                "close_price": 175.50,
                "iso_currency_code": "USD",
                "isin": "US0378331005",
                "cusip": "037833100"
            }]
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let result = client
        .investments_holdings_get("access-sandbox-xxx")
        .await
        .unwrap();
    let holdings = result["holdings"].as_array().unwrap();
    assert_eq!(holdings.len(), 1);
    assert_eq!(holdings[0]["quantity"], 50.0);
    let securities = result["securities"].as_array().unwrap();
    assert_eq!(securities.len(), 1);
    assert_eq!(securities[0]["ticker_symbol"], "AAPL");
}

/// Parse `investments_holdings_get` with empty portfolio.
#[fcp_async_core::test]
async fn parse_investments_holdings_get_empty() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/investments/holdings/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [],
            "holdings": [],
            "securities": []
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let result = client
        .investments_holdings_get("access-sandbox-xxx")
        .await
        .unwrap();
    assert!(result["holdings"].as_array().unwrap().is_empty());
    assert!(result["securities"].as_array().unwrap().is_empty());
}

/// Parse `liabilities_get` response with credit cards, student loans, and mortgages.
#[fcp_async_core::test]
async fn parse_liabilities_get_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/liabilities/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-liab-1",
                "balances": {
                    "available": null,
                    "current": 5200.0,
                    "limit": 10000.0,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "3456",
                "name": "Visa Platinum",
                "official_name": null,
                "subtype": "credit card",
                "type": "credit"
            }],
            "liabilities": {
                "credit": [{
                    "account_id": "acc-liab-1",
                    "is_overdue": false,
                    "last_payment_amount": 500.0,
                    "last_statement_balance": 5200.0,
                    "minimum_payment_amount": 150.0,
                    "next_payment_due_date": "2026-04-01"
                }],
                "mortgage": null,
                "student": [{
                    "account_id": "acc-liab-2",
                    "disbursement_dates": ["2020-09-01"],
                    "interest_rate_percentage": 4.5,
                    "loan_name": "Federal Stafford Loan",
                    "origination_principal_amount": 25000.0,
                    "outstanding_interest_amount": 1200.0
                }]
            }
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let (accounts, liabilities) = client.liabilities_get("access-sandbox-xxx").await.unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].balances.limit, Some(10000.0));
    let credit = liabilities.credit.unwrap();
    assert_eq!(credit.len(), 1);
    assert_eq!(credit[0]["minimum_payment_amount"], 150.0);
    let student = liabilities.student.unwrap();
    assert_eq!(student.len(), 1);
    assert_eq!(student[0]["interest_rate_percentage"], 4.5);
    assert!(liabilities.mortgage.is_none());
}

/// Parse `liabilities_get` with empty liabilities.
#[fcp_async_core::test]
async fn parse_liabilities_get_empty() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/liabilities/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [],
            "liabilities": {
                "credit": [],
                "mortgage": [],
                "student": []
            }
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let (accounts, liabilities) = client.liabilities_get("access-sandbox-xxx").await.unwrap();
    assert!(accounts.is_empty());
    assert!(liabilities.credit.unwrap().is_empty());
    assert!(liabilities.student.unwrap().is_empty());
}

/// Parse `transactions_get` response (legacy endpoint).
#[fcp_async_core::test]
async fn parse_transactions_get_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-txn-1",
                "balances": {
                    "available": 1000.0,
                    "current": 1100.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "6789",
                "name": "Checking",
                "official_name": null,
                "subtype": "checking",
                "type": "depository"
            }],
            "transactions": [{
                "transaction_id": "txn-legacy-1",
                "account_id": "acc-txn-1",
                "amount": 29.95,
                "iso_currency_code": "USD",
                "date": "2026-02-15",
                "name": "AMAZON.COM",
                "merchant_name": "Amazon",
                "pending": false,
                "category": ["Shops", "Online Marketplaces"],
                "category_id": "19046000"
            }],
            "total_transactions": 1
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let result = client
        .transactions_get("access-sandbox-xxx", "2026-02-01", "2026-02-28", None)
        .await
        .unwrap();
    let txns = result["transactions"].as_array().unwrap();
    assert_eq!(txns.len(), 1);
    assert_eq!(txns[0]["transaction_id"], "txn-legacy-1");
    assert_eq!(result["total_transactions"], 1);
}

/// Parse `transactions_get` with pagination options.
#[fcp_async_core::test]
async fn parse_transactions_get_with_options() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [],
            "transactions": [],
            "total_transactions": 0
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let options = json!({ "count": 50, "offset": 100 });
    let result = client
        .transactions_get(
            "access-sandbox-xxx",
            "2026-01-01",
            "2026-01-31",
            Some(&options),
        )
        .await
        .unwrap();
    assert_eq!(result["total_transactions"], 0);
    assert!(result["transactions"].as_array().unwrap().is_empty());
}

// ============================================================================
// 7. Dispatch tests for untested operations
// ============================================================================

/// Dispatch `auth_get` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_auth_get_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-auth-dispatch",
                "balances": {
                    "available": 500.0,
                    "current": 500.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "1111",
                "name": "Auth Checking",
                "official_name": null,
                "subtype": "checking",
                "type": "depository"
            }],
            "numbers": {
                "ach": [{ "account_id": "acc-auth-dispatch", "account": "1234567890", "routing": "021000089", "wire_routing": null }],
                "eft": [],
                "international": [],
                "bacs": []
            }
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.auth_get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "plaid.auth_get");

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.auth_get",
            "input": { "access_token": "access-sandbox-dispatch" },
            "capability_token": token
        }))
        .await
        .expect("invoke auth_get should succeed");
    let accounts = result["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    let numbers = &result["numbers"];
    assert_eq!(numbers["ach"].as_array().unwrap().len(), 1);
}

/// Dispatch `identity_get` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_identity_get_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-id-dispatch",
                "owners": [{
                    "names": ["John Smith"],
                    "emails": [{ "data": "john@test.com", "primary": true, "type": "primary" }],
                    "phone_numbers": [],
                    "addresses": []
                }]
            }]
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.identity_get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "plaid.identity_get");

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.identity_get",
            "input": { "access_token": "access-sandbox-dispatch" },
            "capability_token": token
        }))
        .await
        .expect("invoke identity_get should succeed");
    let accounts = result["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["owners"][0]["names"][0], "John Smith");
}

/// Dispatch `investments_holdings_get` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_investments_holdings_get_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/investments/holdings/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-inv-dispatch",
                "balances": {
                    "available": null,
                    "current": 50000.0,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "5555",
                "name": "Investment Account",
                "official_name": null,
                "subtype": "brokerage",
                "type": "investment"
            }],
            "holdings": [{
                "account_id": "acc-inv-dispatch",
                "security_id": "sec-dispatch",
                "quantity": 100.0,
                "institution_price": 250.0,
                "institution_value": 25000.0,
                "cost_basis": 20000.0,
                "iso_currency_code": "USD"
            }],
            "securities": [{
                "security_id": "sec-dispatch",
                "name": "Microsoft Corp",
                "ticker_symbol": "MSFT",
                "type": "equity",
                "close_price": 250.0,
                "iso_currency_code": "USD",
                "isin": null,
                "cusip": null
            }]
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.investments_holdings_get"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.investments_holdings_get",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.investments_holdings_get",
            "input": { "access_token": "access-sandbox-dispatch" },
            "capability_token": token
        }))
        .await
        .expect("invoke investments_holdings_get should succeed");
    let holdings = result["holdings"].as_array().unwrap();
    assert_eq!(holdings.len(), 1);
    assert_eq!(holdings[0]["quantity"], 100.0);
}

/// Dispatch `liabilities_get` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_liabilities_get_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/liabilities/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-liab-dispatch",
                "balances": {
                    "available": null,
                    "current": 3000.0,
                    "limit": 5000.0,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "8888",
                "name": "Credit Card",
                "official_name": null,
                "subtype": "credit card",
                "type": "credit"
            }],
            "liabilities": {
                "credit": [{ "account_id": "acc-liab-dispatch", "is_overdue": false }],
                "mortgage": null,
                "student": null
            }
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.liabilities_get"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.liabilities_get",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.liabilities_get",
            "input": { "access_token": "access-sandbox-dispatch" },
            "capability_token": token
        }))
        .await
        .expect("invoke liabilities_get should succeed");
    let accounts = result["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    let credit = result["liabilities"]["credit"].as_array().unwrap();
    assert_eq!(credit.len(), 1);
}

/// Dispatch `transactions_get` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_transactions_get_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [],
            "transactions": [{
                "transaction_id": "txn-dispatch-legacy-1",
                "account_id": "acc-1",
                "amount": 55.00,
                "iso_currency_code": "USD",
                "date": "2026-02-20",
                "name": "Gas Station",
                "merchant_name": "Shell",
                "pending": false,
                "category": ["Travel", "Gas Stations"],
                "category_id": "22009000"
            }],
            "total_transactions": 1
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.transactions_get"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.transactions_get",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.transactions_get",
            "input": {
                "access_token": "access-sandbox-dispatch",
                "start_date": "2026-02-01",
                "end_date": "2026-02-28"
            },
            "capability_token": token
        }))
        .await
        .expect("invoke transactions_get should succeed");
    let txns = result["transactions"].as_array().unwrap();
    assert_eq!(txns.len(), 1);
    assert_eq!(txns[0]["transaction_id"], "txn-dispatch-legacy-1");
    assert_eq!(result["total_transactions"], 1);
}

/// Dispatch `accounts_balance_get` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_accounts_balance_get_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/balance/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [{
                "account_id": "acc-bal-dispatch",
                "balances": {
                    "available": 1234.56,
                    "current": 1300.00,
                    "limit": null,
                    "iso_currency_code": "USD",
                    "unofficial_currency_code": null
                },
                "mask": "9999",
                "name": "Balance Checking",
                "official_name": null,
                "subtype": "checking",
                "type": "depository"
            }]
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.accounts_balance_get"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.accounts_balance_get",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.accounts_balance_get",
            "input": { "access_token": "access-sandbox-dispatch" },
            "capability_token": token
        }))
        .await
        .expect("invoke accounts_balance_get should succeed");
    let accounts = result["accounts"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["balances"]["available"], 1234.56);
}

/// Dispatch `token_exchange` through the full invoke pipeline.
#[fcp_async_core::test]
async fn dispatch_token_exchange_through_invoke() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/item/public_token/exchange"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-sandbox-dispatch-token",
            "item_id": "item-dispatch-token",
            "request_id": "req-te-dispatch"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.token_exchange"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.token_exchange",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.token_exchange",
            "input": { "public_token": "public-sandbox-dispatch" },
            "capability_token": token
        }))
        .await
        .expect("invoke token_exchange should succeed");
    assert_eq!(result["access_token"], "access-sandbox-dispatch-token");
    assert_eq!(result["item_id"], "item-dispatch-token");
}

// ============================================================================
// 8. Error/edge case tests for untested operations
// ============================================================================

/// Error 401 on auth_get maps to Unauthorized.
#[fcp_async_core::test]
async fn error_401_on_auth_get() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/auth/get"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error_type": "INVALID_INPUT",
            "error_code": "INVALID_API_KEYS",
            "error_message": "invalid credentials"
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("bad_id", "bad_secret", &mock.base_url()).with_retry_config(0);

    let err = client.auth_get("access-sandbox-xxx").await.unwrap_err();
    assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
}

/// Error 401 on identity_get maps to Unauthorized.
#[fcp_async_core::test]
async fn error_401_on_identity_get() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/identity/get"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error_type": "INVALID_INPUT",
            "error_code": "INVALID_API_KEYS",
            "error_message": "bad keys"
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("bad_id", "bad_secret", &mock.base_url()).with_retry_config(0);

    let err = client.identity_get("access-sandbox-xxx").await.unwrap_err();
    assert!(matches!(err.to_fcp_error(), FcpError::Unauthorized { .. }));
}

/// Error 400 on investments_holdings_get maps to External.
#[fcp_async_core::test]
async fn error_400_on_investments_holdings_get() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/investments/holdings/get"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error_type": "INVALID_REQUEST",
            "error_code": "PRODUCTS_NOT_SUPPORTED",
            "error_message": "investments product not enabled for this item"
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url()).with_retry_config(0);

    let err = client
        .investments_holdings_get("access-sandbox-xxx")
        .await
        .unwrap_err();
    let fcp_err = err.to_fcp_error();
    match fcp_err {
        FcpError::External {
            service, retryable, ..
        } => {
            assert_eq!(service, "plaid");
            assert!(!retryable);
        }
        other => panic!("expected External, got: {other:?}"),
    }
}

/// Error 500 on liabilities_get is retryable.
#[fcp_async_core::test]
async fn error_500_on_liabilities_get() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/liabilities/get"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url()).with_retry_config(0);

    let err = client
        .liabilities_get("access-sandbox-xxx")
        .await
        .unwrap_err();
    assert!(err.is_retryable());
}

/// Error 429 on transactions_get maps to RateLimited.
#[fcp_async_core::test]
async fn error_429_on_transactions_get() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/get"))
        .respond_with(ResponseTemplate::new(429))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url()).with_retry_config(0);

    let err = client
        .transactions_get("access-sandbox-xxx", "2026-01-01", "2026-01-31", None)
        .await
        .unwrap_err();
    assert!(matches!(err.to_fcp_error(), FcpError::RateLimited { .. }));
}

// ============================================================================
// 9. Configuration edge cases
// ============================================================================

/// Missing client_id in configure yields InvalidRequest.
#[fcp_async_core::test]
async fn configure_missing_client_id() {
    let mut connector = PlaidConnector::new();
    let result = connector
        .handle_configure(json!({
            "secret": "test_secret",
            "environment": "sandbox"
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("client_id"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing both secret and credential_id in configure yields error.
#[fcp_async_core::test]
async fn configure_missing_auth() {
    let mut connector = PlaidConnector::new();
    let result = connector
        .handle_configure(json!({
            "client_id": "test_id",
            "environment": "sandbox"
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("secret") || message.contains("credential_id"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Empty client_id rejected.
#[fcp_async_core::test]
async fn configure_empty_client_id() {
    let mut connector = PlaidConnector::new();
    let result = connector
        .handle_configure(json!({
            "client_id": "  ",
            "secret": "test_secret",
            "environment": "sandbox"
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("client_id"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Empty secret with no credential_id rejected.
#[fcp_async_core::test]
async fn configure_empty_secret_no_credential() {
    let mut connector = PlaidConnector::new();
    let result = connector
        .handle_configure(json!({
            "client_id": "test_id",
            "secret": "",
            "environment": "sandbox"
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("secret") || message.contains("credential_id"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Invalid environment string rejected.
#[fcp_async_core::test]
async fn configure_invalid_environment() {
    let mut connector = PlaidConnector::new();
    let result = connector
        .handle_configure(json!({
            "client_id": "test_id",
            "secret": "test_secret",
            "environment": "staging"
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("sandbox, development, production"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Both secret and credential_id provided yields error.
#[fcp_async_core::test]
async fn configure_both_auth_modes_rejected() {
    let mut connector = PlaidConnector::new();
    let result = connector
        .handle_configure(json!({
            "client_id": "test_id",
            "secret": "test_secret",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "environment": "sandbox"
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("exactly one"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// credential_id auth mode configures but client is None.
#[fcp_async_core::test]
async fn configure_credential_id_mode() {
    let mut connector = PlaidConnector::new();
    let result = connector
        .handle_configure(json!({
            "client_id": "test_id",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "environment": "sandbox"
        }))
        .await
        .unwrap();
    assert_eq!(
        result["status"],
        "configured_pending_secret_materialization"
    );
    assert_eq!(result["details"]["auth_mode"], "credential_id");
}

/// Development environment accepted.
#[fcp_async_core::test]
async fn configure_development_environment() {
    let mut connector = PlaidConnector::new();
    let result = connector
        .handle_configure(json!({
            "client_id": "test_id",
            "secret": "test_secret",
            "environment": "development"
        }))
        .await
        .unwrap();
    assert_eq!(result["status"], "configured");
    assert_eq!(result["details"]["environment"], "development");
}

/// Production environment accepted.
#[fcp_async_core::test]
async fn configure_production_environment() {
    let mut connector = PlaidConnector::new();
    let result = connector
        .handle_configure(json!({
            "client_id": "test_id",
            "secret": "test_secret",
            "environment": "production"
        }))
        .await
        .unwrap();
    assert_eq!(result["status"], "configured");
    assert_eq!(result["details"]["environment"], "production");
}

// ============================================================================
// 10. Missing required fields per operation
// ============================================================================

/// Missing access_token on auth_get yields InvalidRequest.
#[fcp_async_core::test]
async fn invoke_auth_get_missing_access_token() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.auth_get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "plaid.auth_get");

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.auth_get",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("access_token"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing access_token on identity_get yields InvalidRequest.
#[fcp_async_core::test]
async fn invoke_identity_get_missing_access_token() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.identity_get"]).await;
    let token = generate_valid_token(&signing_key, connector.instance_id(), "plaid.identity_get");

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.identity_get",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("access_token"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing access_token on investments_holdings_get yields InvalidRequest.
#[fcp_async_core::test]
async fn invoke_investments_holdings_get_missing_access_token() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.investments_holdings_get"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.investments_holdings_get",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.investments_holdings_get",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("access_token"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing access_token on liabilities_get yields InvalidRequest.
#[fcp_async_core::test]
async fn invoke_liabilities_get_missing_access_token() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.liabilities_get"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.liabilities_get",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.liabilities_get",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("access_token"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing start_date on transactions_get yields InvalidRequest.
#[fcp_async_core::test]
async fn invoke_transactions_get_missing_start_date() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.transactions_get"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.transactions_get",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.transactions_get",
            "input": { "access_token": "access-sandbox-xxx", "end_date": "2026-02-28" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("start_date"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing end_date on transactions_get yields InvalidRequest.
#[fcp_async_core::test]
async fn invoke_transactions_get_missing_end_date() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.transactions_get"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.transactions_get",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.transactions_get",
            "input": { "access_token": "access-sandbox-xxx", "start_date": "2026-02-01" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("end_date"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing client_name on link_token_create yields InvalidRequest.
#[fcp_async_core::test]
async fn invoke_link_token_create_missing_client_name() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.link_token_create"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.link_token_create",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.link_token_create",
            "input": {
                "products": ["transactions"],
                "country_codes": ["US"],
                "language": "en"
            },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("client_name"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

/// Missing public_token on token_exchange yields InvalidRequest.
#[fcp_async_core::test]
async fn invoke_token_exchange_missing_public_token() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.token_exchange"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.token_exchange",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.token_exchange",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("public_token"));
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

// ============================================================================
// 11. Health check, doctor, introspect, simulate, shutdown
// ============================================================================

/// Health check before configuration returns not_configured.
#[fcp_async_core::test]
async fn health_check_not_configured() {
    let connector = PlaidConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

/// Health check after configuration returns healthy.
#[fcp_async_core::test]
async fn health_check_after_configure() {
    let mut connector = PlaidConnector::new();
    connector
        .handle_configure(json!({
            "client_id": "test_id",
            "secret": "test_secret",
            "base_url": "http://localhost:9999",
            "environment": "sandbox"
        }))
        .await
        .unwrap();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

/// Health check with credential_id mode returns degraded.
#[fcp_async_core::test]
async fn health_check_credential_id_degraded() {
    let mut connector = PlaidConnector::new();
    connector
        .handle_configure(json!({
            "client_id": "test_id",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "environment": "sandbox"
        }))
        .await
        .unwrap();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "degraded_pending_secret_materialization");
}

/// Doctor before configuration reports unhealthy.
#[fcp_async_core::test]
async fn doctor_not_configured_is_unhealthy() {
    let connector = PlaidConnector::new();
    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "unhealthy");
    let checks = result["checks"].as_array().unwrap();
    let config_check = checks
        .iter()
        .find(|c| c["name"] == "configuration")
        .unwrap();
    assert_eq!(config_check["passed"], false);
    assert_eq!(config_check["critical"], true);
}

/// Doctor with valid secret mode and passing credentials is healthy.
#[fcp_async_core::test]
async fn doctor_secret_mode_healthy() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/link/token/create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "link_token": "link-sandbox-doctor",
            "expiration": "2026-03-03T00:00:00Z"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    connector
        .handle_configure(json!({
            "client_id": "test_id",
            "secret": "test_secret",
            "base_url": mock.base_url(),
            "environment": "sandbox"
        }))
        .await
        .unwrap();

    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "healthy");
    let checks = result["checks"].as_array().unwrap();
    let cred_check = checks
        .iter()
        .find(|c| c["name"] == "credentials_valid")
        .unwrap();
    assert_eq!(cred_check["passed"], true);
}

/// Doctor with failing credentials reports unhealthy.
#[fcp_async_core::test]
async fn doctor_secret_mode_invalid_creds() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/link/token/create"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error_type": "INVALID_INPUT",
            "error_code": "INVALID_API_KEYS",
            "error_message": "bad creds"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnector::new();
    connector
        .handle_configure(json!({
            "client_id": "bad_id",
            "secret": "bad_secret",
            "base_url": mock.base_url(),
            "environment": "sandbox"
        }))
        .await
        .unwrap();

    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "unhealthy");
}

/// Introspect returns exactly 10 operations.
#[fcp_async_core::test]
async fn introspect_returns_all_10_operations() {
    let connector = PlaidConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 10);

    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
    let expected = [
        "plaid.link_token_create",
        "plaid.token_exchange",
        "plaid.accounts_get",
        "plaid.accounts_balance_get",
        "plaid.transactions_get",
        "plaid.transactions_sync",
        "plaid.auth_get",
        "plaid.identity_get",
        "plaid.investments_holdings_get",
        "plaid.liabilities_get",
    ];
    for expected_op in &expected {
        assert!(
            op_ids.contains(expected_op),
            "missing operation: {expected_op}"
        );
    }
}

/// Introspect operations have required schema fields.
#[fcp_async_core::test]
async fn introspect_operations_have_schemas() {
    let connector = PlaidConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().unwrap();
    for op in ops {
        assert!(
            op.get("input_schema").is_some(),
            "missing input_schema for {}",
            op["id"]
        );
        assert!(
            op.get("output_schema").is_some(),
            "missing output_schema for {}",
            op["id"]
        );
        assert!(
            op.get("summary").is_some(),
            "missing summary for {}",
            op["id"]
        );
    }
}

/// Shutdown returns status shutdown.
#[fcp_async_core::test]
async fn shutdown_returns_status() {
    let connector = PlaidConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

/// Unknown operation yields OperationNotGranted.
#[fcp_async_core::test]
async fn invoke_unknown_operation() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;
    let signing_key = setup_handshake(&mut connector, &["plaid.nonexistent_op"]).await;
    let token = generate_valid_token(
        &signing_key,
        connector.instance_id(),
        "plaid.nonexistent_op",
    );

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.nonexistent_op",
            "input": {},
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        FcpError::OperationNotGranted { .. }
    ));
}

/// Invoke without handshake returns NotConfigured.
#[fcp_async_core::test]
async fn invoke_without_handshake() {
    let mock = MockApiServer::start().await;
    let mut connector = PlaidConnector::new();
    setup_configure(&mut connector, &mock.base_url()).await;

    let signing_key = Ed25519SigningKey::generate();
    let token = generate_valid_token(&signing_key, connector.instance_id(), "plaid.accounts_get");

    let result = connector
        .handle_invoke(json!({
            "operation": "plaid.accounts_get",
            "input": { "access_token": "access-sandbox-xxx" },
            "capability_token": token
        }))
        .await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
}

/// Reconfiguration: connector can be reconfigured with new credentials.
#[fcp_async_core::test]
async fn reconfigure_connector() {
    let mut connector = PlaidConnector::new();

    // First configure
    connector
        .handle_configure(json!({
            "client_id": "first_id",
            "secret": "first_secret",
            "base_url": "http://localhost:9999",
            "environment": "sandbox"
        }))
        .await
        .unwrap();

    let health1 = connector.handle_health().await.unwrap();
    assert_eq!(health1["status"], "healthy");

    // Reconfigure with new credentials
    connector
        .handle_configure(json!({
            "client_id": "second_id",
            "secret": "second_secret",
            "base_url": "http://localhost:8888",
            "environment": "sandbox"
        }))
        .await
        .unwrap();

    let health2 = connector.handle_health().await.unwrap();
    assert_eq!(health2["status"], "healthy");
}

// ============================================================================
// 12. Multiple accounts and edge cases
// ============================================================================

/// Accounts get with multiple accounts.
#[fcp_async_core::test]
async fn parse_accounts_get_multiple_accounts() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [
                {
                    "account_id": "acc-checking",
                    "balances": { "available": 500.0, "current": 500.0, "limit": null, "iso_currency_code": "USD", "unofficial_currency_code": null },
                    "mask": "0001",
                    "name": "Checking",
                    "official_name": null,
                    "subtype": "checking",
                    "type": "depository"
                },
                {
                    "account_id": "acc-savings",
                    "balances": { "available": 10000.0, "current": 10000.0, "limit": null, "iso_currency_code": "USD", "unofficial_currency_code": null },
                    "mask": "0002",
                    "name": "Savings",
                    "official_name": "High-Yield Savings",
                    "subtype": "savings",
                    "type": "depository"
                },
                {
                    "account_id": "acc-credit",
                    "balances": { "available": 7000.0, "current": 3000.0, "limit": 10000.0, "iso_currency_code": "USD", "unofficial_currency_code": null },
                    "mask": "0003",
                    "name": "Visa",
                    "official_name": null,
                    "subtype": "credit card",
                    "type": "credit"
                }
            ],
            "item": {
                "item_id": "item-multi",
                "institution_id": "ins_1"
            }
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let (accounts, _item) = client
        .accounts_get("access-sandbox-multi", None)
        .await
        .unwrap();
    assert_eq!(accounts.len(), 3);
    assert_eq!(accounts[2].balances.limit, Some(10000.0));
}

/// Transactions sync with empty lists.
#[fcp_async_core::test]
async fn transactions_sync_empty_response() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/sync"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "added": [],
            "modified": [],
            "removed": [],
            "next_cursor": "cursor-empty",
            "has_more": false
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let result = client
        .transactions_sync("access-sandbox-xxx", Some("cursor-prev"), Some(100))
        .await
        .unwrap();
    assert!(result.added.is_empty());
    assert!(result.modified.is_empty());
    assert!(result.removed.is_empty());
    assert!(!result.has_more);
    assert_eq!(result.next_cursor, "cursor-empty");
}

/// Link token create with custom user object.
#[fcp_async_core::test]
async fn link_token_create_with_custom_user() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/link/token/create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "link_token": "link-sandbox-custom-user",
            "expiration": "2026-03-05T00:00:00Z",
            "request_id": "req-cu-1"
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url());

    let user = json!({
        "client_user_id": "custom-user-123",
        "legal_name": "Jane Test"
    });

    let result = client
        .link_token_create(
            "TestApp",
            &["transactions".to_string(), "auth".to_string()],
            &["US".to_string(), "CA".to_string()],
            "en",
            Some(&user),
        )
        .await
        .unwrap();
    assert_eq!(result.link_token, "link-sandbox-custom-user");
}

/// Error 400 maps to External non-retryable with Plaid error details.
#[fcp_async_core::test]
async fn error_400_with_plaid_error_body() {
    let mock = MockApiServer::start().await;
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error_type": "INVALID_REQUEST",
            "error_code": "INVALID_ACCESS_TOKEN",
            "error_message": "the access token provided is invalid",
            "display_message": null,
            "request_id": "req-err-1"
        })))
        .mount(mock.inner())
        .await;

    let client = build_client("test_id", "test_secret", &mock.base_url()).with_retry_config(0);

    let err = client
        .accounts_get("access-sandbox-bad", None)
        .await
        .unwrap_err();
    let fcp_err = err.to_fcp_error();
    match fcp_err {
        FcpError::External {
            service,
            retryable,
            status_code,
            message,
            ..
        } => {
            assert_eq!(service, "plaid");
            assert!(!retryable);
            assert_eq!(status_code, Some(400));
            assert!(message.contains("invalid"));
        }
        other => panic!("expected External, got: {other:?}"),
    }
}

/// Serialization error maps to FcpError::Internal.
#[test]
fn serialization_error_maps_to_internal() {
    let json_err = serde_json::from_str::<serde_json::Value>("not-json").unwrap_err();
    let err = PlaidError::Serialization(json_err);
    let fcp_err = err.to_fcp_error();
    assert!(
        matches!(fcp_err, FcpError::Internal { .. }),
        "expected Internal, got: {fcp_err:?}"
    );
}
