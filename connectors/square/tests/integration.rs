//! Integration tests for the FCP Square connector.

#![allow(
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unused_async
)]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    ApprovalMode, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, FcpConnector,
    FcpError, HandshakeRequest, IdempotencyClass, InvokeRequest, InvokeStatus, OperationId,
    RequestId, RiskLevel, SafetyTier, SubscribeRequest, ZoneId,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig, migration::HttpRetryConfig};
use fcp_square::SquareConnector;
use fcp_square::client::SquareClient;
use fcp_square::types::{CreateOrderRequest, OrderInput};
use fcp_testkit::readiness_helpers::{
    assert_doctor_response_valid, assert_self_check_not_ready, assert_self_check_ready,
};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OP_PAYMENTS_LIST: &str = "square.payments.list";
const OP_PAYMENTS_CREATE: &str = "square.payments.create";
const OP_CATALOG_LIST: &str = "square.catalog.list";
const VERIFICATION_SCRIPT_PATH: &str = "scripts/e2e/square_connector_verification.sh";
const ARTIFACT_ROOT_HINT: &str = "artifacts/e2e/square_connector/<timestamp>";

fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [23u8; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("square.payments.read"),
            CapabilityId::from_static("square.payments.write"),
            CapabilityId::from_static("square.catalog.read"),
            CapabilityId::from_static("square.locations.read"),
        ],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    op: &'static str,
) -> CapabilityToken {
    let capability = [
        (OP_PAYMENTS_LIST, "square.payments.read"),
        (OP_PAYMENTS_CREATE, "square.payments.write"),
        (OP_CATALOG_LIST, "square.catalog.read"),
    ]
    .into_iter()
    .find_map(|(known_op, capability)| (known_op == op).then_some(capability))
    .expect("unsupported Square integration operation");
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token signing should succeed");
    CapabilityToken::from_raw(raw)
}

fn invoke_req(
    op: &'static str,
    input: serde_json::Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("square-integration-1"),
        connector_id: ConnectorId::from_static("fcp.square"),
        operation: OperationId::from_static(op),
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
        approval_tokens: vec![],
    }
}

async fn setup_connector(
    server: &MockServer,
    access_token: &str,
) -> (SquareConnector, Ed25519SigningKey) {
    let mut connector = SquareConnector::new();
    let signing_key = Ed25519SigningKey::generate();
    connector
        .configure(json!({
            "base_url": format!("{}/v2", server.uri()),
            "access_token": access_token,
            "retry": {
                "max_retries": 0,
                "initial_delay_ms": 1,
                "max_delay_ms": 1,
                "jitter_enabled": false
            }
        }))
        .await
        .unwrap();
    connector
        .handshake(handshake_req(signing_key.verifying_key().to_bytes()))
        .await
        .unwrap();
    (connector, signing_key)
}

#[fcp_async_core::runtime::test]
async fn health_unconfigured_includes_guidance() {
    let connector = SquareConnector::new();
    let health = connector.health().await;
    assert!(!health.is_ready());
    let details = health.details.as_ref().expect("health details");
    assert!(details["operator_guidance"]["prerequisites"].is_array());
    assert!(details["operator_guidance"]["redaction_rules"].is_array());
    assert_eq!(details["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert_eq!(details["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    println!(
        "square_health_evidence={}",
        serde_json::to_string_pretty(&health).unwrap()
    );
}

#[test]
fn doctor_unconfigured_reports_operator_guidance() {
    let connector = SquareConnector::new();
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], false);
    assert_eq!(doctor["verification_script"], VERIFICATION_SCRIPT_PATH);
    assert!(doctor["operator_guidance"]["common_remediation"].is_array());
    assert_eq!(
        doctor["operator_guidance"]["artifact_root_hint"],
        ARTIFACT_ROOT_HINT
    );
    println!(
        "square_doctor_guidance_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_ready_with_mock_square_api_and_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/locations"))
        .and(header("authorization", "Bearer sq-ready"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "locations": [{
                "id": "LOC-1",
                "name": "Sandbox Main",
                "status": "ACTIVE",
                "country": "US",
                "currency": "USD",
                "business_name": "Square Sandbox"
            }]
        })))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server, "sq-ready").await;
    let doctor = serde_json::to_value(connector.doctor()).unwrap();
    assert_doctor_response_valid(&doctor);
    assert_eq!(doctor["ready"], true);
    assert_eq!(doctor["provisioning"]["auth_mode"], "bearer_token");
    println!(
        "square_doctor_evidence={}",
        serde_json::to_string_pretty(&doctor).unwrap()
    );

    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_ready(&value);
    assert_eq!(
        value["details"]["verification_script"],
        VERIFICATION_SCRIPT_PATH
    );
    assert_eq!(value["details"]["artifact_root_hint"], ARTIFACT_ROOT_HINT);
    assert_eq!(
        value["details"]["provisioning"]["auth_mode"],
        "bearer_token"
    );
    assert_eq!(value["details"]["live_probe"]["location_count"], 1);
    assert_eq!(value["details"]["live_probe"]["location_ids"][0], "LOC-1");
    println!(
        "square_self_check_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn self_check_retryable_square_failure_reports_degraded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/locations"))
        .and(header("authorization", "Bearer sq-retry"))
        .respond_with(ResponseTemplate::new(503).set_body_string("square unavailable"))
        .mount(&server)
        .await;

    let (connector, _signing_key) = setup_connector(&server, "sq-retry").await;
    let report = connector.self_check().await.unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_self_check_not_ready(&value);
    assert_eq!(value["status"], "degraded");
    assert_eq!(value["reason_code"], "self_check_retryable");
}

#[fcp_async_core::runtime::test]
async fn invoke_payments_list_preserves_pagination_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/payments"))
        .and(query_param("cursor", "cursor-1"))
        .and(query_param("location_id", "LOC-1"))
        .and(header("authorization", "Bearer sq-list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "payments": [{
                "id": "pay_123",
                "status": "COMPLETED",
                "amount_money": {
                    "amount": 4200,
                    "currency": "USD"
                },
                "location_id": "LOC-1"
            }],
            "cursor": "cursor-2"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server, "sq-list").await;
    let response = connector
        .invoke(invoke_req(
            OP_PAYMENTS_LIST,
            json!({
                "cursor": "cursor-1",
                "location_id": "LOC-1"
            }),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_PAYMENTS_LIST,
            ),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("payments list result");
    assert_eq!(result["cursor"], "cursor-2");
    assert_eq!(result["payments"][0]["id"], "pay_123");
    println!(
        "square_payments_pagination_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_catalog_list_preserves_filter_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/catalog/list"))
        .and(query_param("cursor", "cat-1"))
        .and(query_param("types", "ITEM,IMAGE"))
        .and(header("authorization", "Bearer sq-catalog"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "objects": [{
                "id": "item_123",
                "type": "ITEM",
                "version": 12
            }],
            "cursor": "cat-2"
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server, "sq-catalog").await;
    let response = connector
        .invoke(invoke_req(
            OP_CATALOG_LIST,
            json!({
                "cursor": "cat-1",
                "types": "ITEM,IMAGE"
            }),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_CATALOG_LIST,
            ),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("catalog list result");
    assert_eq!(result["cursor"], "cat-2");
    assert_eq!(result["objects"][0]["type"], "ITEM");
    println!(
        "square_catalog_filter_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn invoke_payment_create_preserves_mutation_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/payments"))
        .and(header("authorization", "Bearer sq-create"))
        .and(body_json(json!({
            "source_id": "cnon:card-nonce-ok",
            "idempotency_key": "payment-1",
            "amount_money": {
                "amount": 4200,
                "currency": "USD"
            },
            "location_id": "LOC-1",
            "customer_id": "CUST-1",
            "note": "sandbox invoice 42"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "payment": {
                "id": "pay_created",
                "status": "COMPLETED",
                "amount_money": {
                    "amount": 4200,
                    "currency": "USD"
                },
                "location_id": "LOC-1",
                "receipt_url": "https://squareup.com/receipt/pay_created"
            }
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server, "sq-create").await;
    let response = connector
        .invoke(invoke_req(
            OP_PAYMENTS_CREATE,
            json!({
                "source_id": "cnon:card-nonce-ok",
                "idempotency_key": "payment-1",
                "amount_money": {
                    "amount": 4200,
                    "currency": "USD"
                },
                "location_id": "LOC-1",
                "customer_id": "CUST-1",
                "note": "sandbox invoice 42"
            }),
            generate_valid_token(
                &signing_key,
                connector.instance_id().as_str(),
                OP_PAYMENTS_CREATE,
            ),
        ))
        .await
        .unwrap();

    assert_eq!(response.status, InvokeStatus::Ok);
    let result = response.result.expect("payment create result");
    assert_eq!(result["payment"]["id"], "pay_created");
    assert_eq!(
        result["payment"]["receipt_url"],
        "https://squareup.com/receipt/pay_created"
    );
    println!(
        "square_payment_create_evidence={}",
        serde_json::to_string_pretty(&result).unwrap()
    );
}

#[test]
fn introspection_emits_v3_compliance_evidence() {
    let connector = SquareConnector::new();
    let introspection = connector.introspect();
    let value = serde_json::to_value(&introspection).unwrap();
    let operations = value["operations"].as_array().expect("operations array");

    assert_eq!(operations.len(), 12);
    assert!(operations.iter().all(|operation| {
        operation["ai_hints"]["when_to_use"]
            .as_str()
            .is_some_and(|when_to_use| !when_to_use.is_empty())
    }));

    let payment_create = operations
        .iter()
        .find(|operation| operation["id"] == OP_PAYMENTS_CREATE)
        .expect("payments create operation");
    assert_eq!(
        payment_create["safety_tier"],
        serde_json::to_value(SafetyTier::Risky).unwrap()
    );
    assert_eq!(
        payment_create["requires_approval"],
        serde_json::to_value(ApprovalMode::Interactive).unwrap()
    );
    assert_eq!(
        payment_create["risk_level"],
        serde_json::to_value(RiskLevel::High).unwrap()
    );

    let health = operations
        .iter()
        .find(|operation| operation["id"] == "square.health")
        .expect("health operation");
    assert_eq!(
        health["idempotency"],
        serde_json::to_value(IdempotencyClass::Strict).unwrap()
    );

    println!(
        "square_introspection_evidence={}",
        serde_json::to_string_pretty(&value).unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn webhook_ingress_is_explicitly_rejected_for_square_rest_slice() {
    let manifest = include_str!("../manifest.toml");
    assert!(manifest.contains("\"network.listen\""));
    assert!(manifest.contains("webhook ingestion"));

    let connector = SquareConnector::new();
    let introspection = connector.introspect();
    let operation_ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(operation_ids.len(), 12);
    for rejected in [
        "square.ingest_webhook_event",
        "square.webhook.ingest",
        "square.webhooks.ingest",
        "square.subscription.events",
    ] {
        assert!(
            !operation_ids.contains(&rejected),
            "{rejected} must stay absent until Square webhook verification is implemented"
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
            id: RequestId::new("square-webhook-rejection-proof"),
            topics: vec!["square.webhook".into()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        })
        .await
        .expect_err("Square webhooks must not silently subscribe");
    assert!(matches!(subscribe_error, FcpError::StreamingNotSupported));

    let health = connector.health().await;
    let details = health.details.as_ref().expect("health details");
    let non_goals = details["contract"]["non_goals"]
        .as_array()
        .expect("non-goals");
    assert!(
        non_goals
            .iter()
            .any(|entry| entry.as_str() == Some("webhook_ingest"))
    );
    println!(
        "square_webhook_rejection_evidence={}",
        serde_json::to_string_pretty(&serde_json::json!({
            "operations": operation_ids,
            "event_caps": event_caps,
            "non_goals": non_goals,
        }))
        .unwrap()
    );
}

// ─────────────────────────────────────────────────────────────────────
// Retry replay-safety (br-kxd3e)
// ─────────────────────────────────────────────────────────────────────

fn retry_client(base_url: &str, max_retries: u32) -> (ConnectorRuntime, SquareClient) {
    let runtime = ConnectorRuntime::new(ConnectorRuntimeConfig::default());
    let client = SquareClient::new(
        base_url,
        "sq-test-token",
        HttpRetryConfig {
            max_retries,
            initial_delay_ms: 1,
            max_delay_ms: 5,
            jitter_enabled: false,
        },
    )
    .expect("square client");
    (runtime, client)
}

fn order_request(idempotency_key: Option<&str>) -> CreateOrderRequest {
    CreateOrderRequest {
        order: OrderInput {
            location_id: "L1".into(),
            line_items: Vec::new(),
        },
        idempotency_key: idempotency_key.map(str::to_string),
    }
}

/// A 5xx on `POST /orders` is NOT retried when the body carries no
/// `idempotency_key`.
///
/// A 5xx means Square received the request; without a key it has nothing to
/// deduplicate on, so a replay creates a second order. `expect(1)` is the
/// assertion — the mock panics on drop if a second request arrives.
#[fcp_async_core::runtime::test]
async fn create_order_without_idempotency_key_is_not_retried_on_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/orders"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&mock_server)
        .await;

    let (runtime, client) = retry_client(&mock_server.uri(), 3);
    client
        .create_order(&runtime, &order_request(None))
        .await
        .expect_err("a 503 must surface rather than silently create a second order");
}

/// The SAME 5xx IS retried once the body carries an `idempotency_key` — Square
/// can then deduplicate, so the replay is safe. This is what keeps the fix from
/// being a blanket loss of resilience.
#[fcp_async_core::runtime::test]
async fn create_order_with_idempotency_key_is_retried_on_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/orders"))
        .respond_with(ResponseTemplate::new(503))
        .expect(2)
        .mount(&mock_server)
        .await;

    let (runtime, client) = retry_client(&mock_server.uri(), 1);
    client
        .create_order(&runtime, &order_request(Some("caller-key-1")))
        .await
        .expect_err("still fails after exhausting retries");
}

/// `POST /orders/search` is a query, and must keep retrying despite having no
/// idempotency key — a read path must not lose resilience to this fix.
#[fcp_async_core::runtime::test]
async fn order_search_is_still_retried_on_5xx() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/orders/search"))
        .respond_with(ResponseTemplate::new(503))
        .expect(2)
        .mount(&mock_server)
        .await;

    let (runtime, client) = retry_client(&mock_server.uri(), 1);
    client
        .list_orders(&runtime, &["L1".to_string()], None)
        .await
        .expect_err("still fails after exhausting retries");
}
