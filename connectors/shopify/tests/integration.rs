//! Connector-local no-mock Shopify integration proof.
//!
//! These tests exercise the real Shopify client against a local HTTP server.
//! No live Shopify service is called.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::sync::Once;
use std::time::Duration;

use fcp_prelude::{
    ApprovalMode, FcpConnector, FcpError, IdempotencyClass, RequestId, RiskLevel, SafetyTier,
    SubscribeRequest,
};
use fcp_sdk::ConnectorErrorMapping;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use fcp_shopify::client::ShopifyClient;
use fcp_shopify::connector::ShopifyConnector;
use fcp_shopify::error::ShopifyError;
use fcp_shopify::types::{
    CreateLineItem, CreateOrder, CreateProduct, CreateVariant, ShopifyAuth, UpdateProduct,
};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ACCESS_MARKER: &str = "fcp-shopify-admin-marker";
const API_PREFIX: &str = "/admin/api/2026-01";

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

fn shopify_client(server: &MockServer, request_timeout_ms: u64) -> ShopifyClient {
    ShopifyClient::new(
        "proof.myshopify.com",
        ShopifyAuth::AccessToken {
            access_token: ACCESS_MARKER.into(),
        },
        "2026-01",
        request_timeout_ms,
        no_retry_config(),
    )
    .expect("client should initialize")
    .with_base_url(&format!("{}{}", server.uri(), API_PREFIX))
}

fn product(product_id: u64, title: &str) -> serde_json::Value {
    json!({
        "id": product_id,
        "title": title,
        "vendor": "FCP",
        "product_type": "proof",
        "status": "active",
        "tags": "fcp,proof",
        "variants": [{
            "id": product_id * 10,
            "title": "Default",
            "price": "12.00",
            "sku": format!("SKU-{product_id}"),
            "inventory_quantity": 5
        }]
    })
}

fn order(order_id: u64, name: &str) -> serde_json::Value {
    json!({
        "id": order_id,
        "name": name,
        "email": "buyer@example.com",
        "total_price": "24.00",
        "currency": "USD",
        "financial_status": "paid",
        "fulfillment_status": null,
        "line_items": [{
            "id": order_id * 10,
            "title": "Proof item",
            "quantity": 2,
            "price": "12.00",
            "variant_id": 901
        }]
    })
}

fn customer(customer_id: u64, first_name: &str) -> serde_json::Value {
    json!({
        "id": customer_id,
        "first_name": first_name,
        "last_name": "Buyer",
        "email": "buyer@example.com",
        "orders_count": 3,
        "total_spent": "72.00",
        "state": "enabled"
    })
}

fn inventory_level(location_id: u64, available: i64) -> serde_json::Value {
    json!({
        "inventory_item_id": 7001,
        "location_id": location_id,
        "available": available,
        "updated_at": "2026-05-01T12:00:00-04:00"
    })
}

fn shop() -> serde_json::Value {
    json!({
        "id": 42,
        "name": "FCP Proof Shop",
        "email": "owner@example.com",
        "domain": "proof.myshopify.com",
        "plan_name": "partner_test"
    })
}

#[fcp_async_core::runtime::test]
async fn product_order_customer_inventory_and_health_use_shopify_contracts() {
    init_logging();
    tracing::info!(
        scenario = "shopify_success_contracts",
        "starting Shopify success-path integration proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/products.json")))
        .and(query_param("limit", "50"))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header(
                    "link",
                    "<https://proof.myshopify.com/admin/api/2026-01/products.json?page_info=next>; rel=\"next\"",
                )
                .set_body_json(json!({
                    "products": [product(101, "Proof product")]
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/products.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .and(header("x-shopify-idempotency-key", "create-product-idem"))
        .and(body_json(json!({
            "product": {
                "title": "New product",
                "vendor": "FCP",
                "status": "draft",
                "variants": [{
                    "title": "Default",
                    "price": "12.00",
                    "sku": "SKU-NEW"
                }]
            }
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "product": product(202, "New product")
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(format!("{API_PREFIX}/products/101.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .and(header("x-shopify-idempotency-key", "update-product-idem"))
        .and(body_json(json!({
            "product": {
                "title": "Updated product",
                "status": "active"
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "product": product(101, "Updated product")
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/orders.json")))
        .and(query_param("status", "any"))
        .and(query_param("limit", "50"))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "orders": [order(301, "#1001")]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("{API_PREFIX}/orders.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .and(header("x-shopify-idempotency-key", "create-order-idem"))
        .and(body_json(json!({
            "order": {
                "line_items": [{
                    "variant_id": 901,
                    "quantity": 2
                }],
                "email": "buyer@example.com",
                "financial_status": "paid"
            }
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "order": order(302, "#1002")
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/customers.json")))
        .and(query_param("limit", "50"))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "customers": [customer(401, "Ada")]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/inventory_levels.json")))
        .and(query_param("location_ids", "501"))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "inventory_levels": [inventory_level(501, 9)]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/shop.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "shop": shop()
        })))
        .expect(1)
        .mount(&server)
        .await;

    let runtime = test_runtime();
    let client = shopify_client(&server, 500);

    let products = client
        .list_products(&runtime)
        .await
        .expect("product first-page list should succeed");
    assert_eq!(products.len(), 1);
    assert_eq!(products[0].id, 101);
    assert_eq!(products[0].title, "Proof product");

    let created_product = client
        .create_product(
            &runtime,
            &CreateProduct {
                title: "New product".into(),
                body_html: None,
                vendor: Some("FCP".into()),
                product_type: None,
                status: Some("draft".into()),
                tags: None,
                variants: vec![CreateVariant {
                    title: Some("Default".into()),
                    price: Some("12.00".into()),
                    sku: Some("SKU-NEW".into()),
                }],
            },
            Some("create-product-idem"),
        )
        .await
        .expect("product creation should succeed");
    assert_eq!(created_product.id, 202);

    let updated_product = client
        .update_product(
            &runtime,
            101,
            &UpdateProduct {
                title: Some("Updated product".into()),
                body_html: None,
                vendor: None,
                product_type: None,
                status: Some("active".into()),
                tags: None,
            },
            Some("update-product-idem"),
        )
        .await
        .expect("product update should succeed");
    assert_eq!(updated_product.title, "Updated product");

    let orders = client
        .list_orders(&runtime)
        .await
        .expect("order first-page list should succeed");
    assert_eq!(orders[0].id, 301);

    let created_order = client
        .create_order(
            &runtime,
            &CreateOrder {
                line_items: vec![CreateLineItem {
                    variant_id: 901,
                    quantity: 2,
                }],
                email: Some("buyer@example.com".into()),
                financial_status: Some("paid".into()),
            },
            Some("create-order-idem"),
        )
        .await
        .expect("order creation should succeed");
    assert_eq!(created_order.name.as_deref(), Some("#1002"));

    let customers = client
        .list_customers(&runtime)
        .await
        .expect("customer first-page list should succeed");
    assert_eq!(customers[0].first_name.as_deref(), Some("Ada"));

    let levels = client
        .list_inventory_levels(&runtime, 501)
        .await
        .expect("inventory lookup should succeed");
    assert_eq!(levels[0].available, Some(9));

    let health = client
        .health_check(&runtime)
        .await
        .expect("shop health probe should succeed");
    assert_eq!(health.domain.as_deref(), Some("proof.myshopify.com"));
}

#[fcp_async_core::runtime::test]
async fn auth_rate_limit_decode_and_missing_resource_errors_are_typed() {
    init_logging();
    tracing::info!(
        scenario = "shopify_error_contracts",
        "starting Shopify error-path integration proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/products/401.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/products/429.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(
            ResponseTemplate::new(429)
                .append_header("retry-after", "7")
                .set_body_string("rate limited"),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/products/404.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(ResponseTemplate::new(404).set_body_string("missing"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/products/422.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!({
            "errors": "title is required"
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/products/200.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(ResponseTemplate::new(200).set_body_string("{this is not json"))
        .expect(1)
        .mount(&server)
        .await;

    let runtime = test_runtime();
    let client = shopify_client(&server, 500);

    let unauthorized = client
        .get_product(&runtime, 401)
        .await
        .expect_err("401 should map to unauthorized");
    assert!(matches!(unauthorized, ShopifyError::Unauthorized(_)));
    assert!(!unauthorized.is_retryable());

    let rate_limited = client
        .get_product(&runtime, 429)
        .await
        .expect_err("429 should map to rate limit");
    assert!(matches!(
        rate_limited,
        ShopifyError::RateLimited {
            retry_after_ms: 7_000,
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::from_secs(7)));

    let missing = client
        .get_product(&runtime, 404)
        .await
        .expect_err("404 should map to not found");
    assert!(matches!(missing, ShopifyError::NotFound(_)));

    let bad_request = client
        .get_product(&runtime, 422)
        .await
        .expect_err("422 should map to an API error");
    assert!(matches!(bad_request, ShopifyError::Api { code: 422, .. }));
    assert!(!bad_request.is_retryable());

    let malformed = client
        .get_product(&runtime, 200)
        .await
        .expect_err("malformed JSON should be a typed decode failure");
    assert!(matches!(malformed, ShopifyError::Http(ref source) if source.is_decode()));
    assert!(!malformed.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn reqwest_timeout_bounds_slow_shopify_responses() {
    init_logging();
    tracing::info!(
        scenario = "shopify_timeout",
        "starting Shopify request-timeout proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("{API_PREFIX}/products/123.json")))
        .and(header("x-shopify-access-token", ACCESS_MARKER))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(150))
                .set_body_json(json!({
                    "product": product(123, "Slow product")
                })),
        )
        .expect(1)
        .mount(&server)
        .await;

    let runtime = test_runtime();
    let client = shopify_client(&server, 25);
    let error = client
        .get_product(&runtime, 123)
        .await
        .expect_err("slow response should respect client timeout");

    assert!(matches!(error, ShopifyError::Http(ref source) if source.is_timeout()));
    assert!(error.is_retryable());
}

#[test]
fn manifest_and_operation_catalog_preserve_metadata_contract() {
    init_logging();

    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("List the first page of products"));
    assert!(manifest.contains("network.listen"));

    let introspection = ShopifyConnector::new().introspect();
    assert!(introspection.events.is_empty());
    assert!(
        !introspection
            .event_caps
            .as_ref()
            .expect("event caps should be explicit")
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
            .expect("operation catalog should contain requested Shopify operation")
    };

    let products_list = operation("shopify.products.list");
    assert_eq!(products_list.risk_level, RiskLevel::Low);
    assert_eq!(products_list.safety_tier, SafetyTier::Safe);
    assert_eq!(products_list.idempotency, IdempotencyClass::Strict);
    assert_eq!(products_list.requires_approval, Some(ApprovalMode::None));

    let product_create = operation("shopify.products.create");
    assert_eq!(product_create.risk_level, RiskLevel::Medium);
    assert_eq!(product_create.safety_tier, SafetyTier::Risky);
    assert_eq!(product_create.idempotency, IdempotencyClass::None);
    assert_eq!(
        product_create.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let product_delete = operation("shopify.products.delete");
    assert_eq!(product_delete.risk_level, RiskLevel::High);
    assert_eq!(product_delete.safety_tier, SafetyTier::Dangerous);
    assert_eq!(
        product_delete.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let order_create = operation("shopify.orders.create");
    assert_eq!(order_create.risk_level, RiskLevel::High);
    assert_eq!(order_create.safety_tier, SafetyTier::Risky);
    assert_eq!(
        order_create.requires_approval,
        Some(ApprovalMode::Interactive)
    );

    let health = operation("shopify.health");
    assert_eq!(health.safety_tier, SafetyTier::Safe);
    assert_eq!(health.requires_approval, Some(ApprovalMode::None));
}

#[fcp_async_core::runtime::test]
async fn webhook_ingress_is_explicitly_rejected_for_rest_admin_slice() {
    init_logging();

    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("\"network.listen\""));

    let connector = ShopifyConnector::new();
    let introspection = connector.introspect();
    let operation_ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(operation_ids.len(), 12);
    for rejected in [
        "shopify.ingest_webhook_event",
        "shopify.webhook.ingest",
        "shopify.webhooks.ingest",
        "shopify.webhook_subscriptions.create",
    ] {
        assert!(
            !operation_ids.contains(&rejected),
            "{rejected} must stay absent until Shopify webhook verification is implemented"
        );
    }

    assert!(introspection.events.is_empty());
    let event_caps = introspection
        .event_caps
        .as_ref()
        .expect("event caps should be explicit");
    assert!(!event_caps.streaming);
    assert!(!event_caps.replay);
    assert_eq!(event_caps.min_buffer_events, 0);
    assert!(!event_caps.requires_ack);

    let subscribe_error = connector
        .subscribe(SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("shopify-webhook-rejection-proof"),
            topics: vec!["shopify.webhook".into()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        })
        .await
        .expect_err("Shopify webhooks must not silently subscribe");
    assert!(matches!(subscribe_error, FcpError::StreamingNotSupported));

    let health = connector.health().await;
    let details = health.details.as_ref().expect("health details");
    let non_goals = details["contract"]["non_goals"]
        .as_array()
        .expect("non-goals");
    assert!(non_goals.iter().any(|entry| {
        entry
            .as_str()
            .is_some_and(|text| text.contains("Webhook or streaming ingestion"))
    }));
    println!(
        "shopify_webhook_rejection_evidence={}",
        serde_json::to_string_pretty(&serde_json::json!({
            "operations": operation_ids,
            "event_caps": event_caps,
            "non_goals": non_goals,
        }))
        .unwrap()
    );
}

#[test]
fn redaction_and_fcp_error_mapping_preserve_security_contract() {
    init_logging();

    let sensitive_marker = ["shopify", "-", "admin", "-", "credential", "-", "marker"].concat();
    let auth = ShopifyAuth::AccessToken {
        access_token: sensitive_marker.clone(),
    };
    let auth_debug = format!("{auth:?}");
    assert!(auth_debug.contains("[REDACTED]"));
    assert!(!auth_debug.contains(&sensitive_marker));

    let client = ShopifyClient::new(
        "proof.myshopify.com",
        auth,
        "2026-01",
        500,
        no_retry_config(),
    )
    .expect("client should initialize");
    let client_debug = format!("{client:?}");
    assert!(client_debug.contains("[REDACTED]"));
    assert!(!client_debug.contains(&sensitive_marker));

    let external = ShopifyError::Api {
        code: 503,
        message: "temporarily unavailable".into(),
    }
    .to_fcp_error();
    assert!(matches!(
        external,
        FcpError::External {
            ref service,
            status_code: Some(503),
            retryable: true,
            ..
        } if service == "shopify"
    ));

    let rate_limited = ShopifyError::RateLimited {
        retry_after_ms: 4_000,
    }
    .to_fcp_error();
    assert!(matches!(
        rate_limited,
        FcpError::RateLimited {
            retry_after_ms: 4_000,
            violation: None,
        }
    ));

    let cancelled = <ShopifyError as ConnectorErrorMapping>::from_async_error(
        fcp_async_core::AsyncError::Cancelled,
    )
    .to_fcp_error();
    assert!(matches!(
        cancelled,
        FcpError::Internal { ref message } if message.contains("cancelled")
    ));
}
