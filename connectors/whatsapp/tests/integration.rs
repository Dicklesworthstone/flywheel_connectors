//! WhatsApp connector integration tests (flywheel_connectors-j05nu.1.5).
//!
//! Deterministic integration tests using wiremock to exercise the real
//! `FcpConnector` surface against mock WhatsApp Business API responses.
//! No real API calls. Covers lifecycle and self-check behavior, outbound sends
//! and profile fetches, webhook verification and replay filtering, and FCP2
//! capability verification.

#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpConnector, FcpError, HandshakeRequest,
    HealthState, InstanceId, InvokeRequest, OperationId, RequestId, SelfCheckStatus,
    ShutdownRequest, ZoneId,
};
use fcp_sdk::{
    ChatCoordinationBackend, InMemoryThreadOwnershipChecker, ThreadOwnershipChecker,
    migration::HttpRetryConfig,
};
use fcp_testkit::AsyncTestContext;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

use fcp_whatsapp::{
    client::WhatsAppClient,
    connector::{WhatsAppConnector, operations_info},
};

const PHONE_NUMBER_ID: &str = "123456789";
const ACCESS_TOKEN: &str = "test_access_token_xyz";
const APP_SECRET: &str = "test_app_secret_12345";
const VERIFY_TOKEN: &str = "test_verify_token_xyz";

const OP_SEND_TEXT: &str = "whatsapp.send_text";
const OP_SEND_TEMPLATE: &str = "whatsapp.send_template";
const OP_GET_PROFILE: &str = "whatsapp.get_profile";
const OP_WEBHOOK_VERIFY: &str = "whatsapp.webhook_verify";
const OP_WEBHOOK_RECEIVE: &str = "whatsapp.webhook_receive";

const CAP_SEND: &str = "whatsapp.send";
const CAP_READ: &str = "whatsapp.read";
const CAP_WEBHOOK: &str = "whatsapp.webhook";
const EXPECTED_MANIFEST_SCHEMA_OPS: [(&str, &str); 5] = [
    ("send_text", OP_SEND_TEXT),
    ("send_template", OP_SEND_TEMPLATE),
    ("get_profile", OP_GET_PROFILE),
    ("webhook_verify", OP_WEBHOOK_VERIFY),
    ("webhook_receive", OP_WEBHOOK_RECEIVE),
];
const WHATSAPP_API_EGRESS_OPERATION_KEYS: [&str; 3] = ["send_text", "send_template", "get_profile"];
const NO_CONNECTOR_EGRESS_OPERATION_KEYS: [&str; 2] = ["webhook_verify", "webhook_receive"];

type HmacSha256 = Hmac<Sha256>;

fn whatsapp_manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml")).expect("WhatsApp manifest TOML should parse")
}

fn manifest_operations(manifest: &toml::Value) -> &toml::Table {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("manifest should contain provides.operations")
}

fn operation_schema(manifest: &toml::Value, operation_key: &str, schema_key: &str) -> Value {
    let schema = manifest_operations(manifest)
        .get(operation_key)
        .and_then(|operation| operation.get(schema_key))
        .expect("operation should define requested schema");

    serde_json::to_value(schema).expect("manifest schema should convert to JSON")
}

fn operation_network_constraints<'a>(
    manifest: &'a toml::Value,
    operation_key: &str,
) -> &'a toml::Table {
    manifest_operations(manifest)
        .get(operation_key)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .expect("operation should define network_constraints")
}

fn string_array_field<'a>(table: &'a toml::Table, key: &str) -> Vec<&'a str> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("network_constraints.{key} should be an array"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("network_constraints.{key} entries should be strings"))
        })
        .collect()
}

fn integer_array_field(table: &toml::Table, key: &str) -> Vec<i64> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("network_constraints.{key} should be an array"))
        .iter()
        .map(|value| {
            value
                .as_integer()
                .unwrap_or_else(|| panic!("network_constraints.{key} entries should be integers"))
        })
        .collect()
}

fn bool_field(table: &toml::Table, key: &str) -> bool {
    table
        .get(key)
        .and_then(toml::Value::as_bool)
        .unwrap_or_else(|| panic!("network_constraints.{key} should be a bool"))
}

fn integer_field(table: &toml::Table, key: &str) -> i64 {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .unwrap_or_else(|| panic!("network_constraints.{key} should be an integer"))
}

fn assert_schema_accepts(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "schema should accept payload {payload:#}: {errors:#?}"
    );
}

fn assert_schema_rejects(schema: &Value, payload: &Value) {
    let validator = jsonschema::validator_for(schema).expect("schema should compile");
    let errors = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        !errors.is_empty(),
        "schema should reject payload {payload:#}"
    );
}

fn assert_manifest_schema_catalog_matches_runtime(manifest: &toml::Value) {
    let operations = operations_info();
    assert_eq!(
        operations.len(),
        EXPECTED_MANIFEST_SCHEMA_OPS.len(),
        "runtime operation catalog should stay aligned with manifest schema coverage"
    );

    for (manifest_key, operation_id) in EXPECTED_MANIFEST_SCHEMA_OPS {
        let operation = operations
            .iter()
            .find(|entry| entry.id.as_str() == operation_id)
            .expect("runtime catalog should include manifest operation");
        let input_schema = operation_schema(manifest, manifest_key, "input_schema");
        let output_schema = operation_schema(manifest, manifest_key, "output_schema");

        assert_eq!(
            input_schema, operation.input_schema,
            "{operation_id} manifest input_schema should match runtime OperationInfo"
        );
        assert_eq!(
            output_schema, operation.output_schema,
            "{operation_id} manifest output_schema should match runtime OperationInfo"
        );
        assert!(
            jsonschema::validator_for(&input_schema).is_ok(),
            "{operation_id} manifest input_schema should compile"
        );
        assert!(
            jsonschema::validator_for(&output_schema).is_ok(),
            "{operation_id} manifest output_schema should compile"
        );
    }
}

fn assert_input_schema_examples(manifest: &toml::Value) {
    let send_text = operation_schema(manifest, "send_text", "input_schema");
    assert_schema_accepts(
        &send_text,
        &json!({ "to": "15559876543", "text": "hello", "preview_url": false }),
    );
    assert_schema_rejects(&send_text, &json!({ "to": "15559876543" }));
    assert_schema_rejects(
        &send_text,
        &json!({ "to": "15559876543", "text": "hello", "unexpected": true }),
    );

    let send_template = operation_schema(manifest, "send_template", "input_schema");
    assert_schema_accepts(
        &send_template,
        &json!({
            "to": "15559876543",
            "template_name": "shipping_update",
            "language_code": "en_US",
            "components": [{ "type": "body", "parameters": [] }]
        }),
    );
    assert_schema_rejects(
        &send_template,
        &json!({ "template_name": "shipping_update" }),
    );
    assert_schema_rejects(
        &send_template,
        &json!({ "to": "15559876543", "template_name": "shipping_update", "extra": "blocked" }),
    );

    let get_profile = operation_schema(manifest, "get_profile", "input_schema");
    assert_schema_accepts(&get_profile, &json!({}));
    assert_schema_rejects(&get_profile, &json!({ "phone_number_id": PHONE_NUMBER_ID }));

    let webhook_verify = operation_schema(manifest, "webhook_verify", "input_schema");
    assert_schema_accepts(
        &webhook_verify,
        &json!({
            "hub_mode": "subscribe",
            "hub_verify_token": VERIFY_TOKEN,
            "hub_challenge": "challenge-1"
        }),
    );
    assert_schema_rejects(
        &webhook_verify,
        &json!({ "hub_mode": "subscribe", "hub_verify_token": VERIFY_TOKEN }),
    );

    let webhook_receive = operation_schema(manifest, "webhook_receive", "input_schema");
    assert_schema_accepts(
        &webhook_receive,
        &json!({
            "headers": { "X-Hub-Signature-256": "sha256=abc" },
            "body": sample_text_notification().to_string()
        }),
    );
    assert_schema_rejects(
        &webhook_receive,
        &json!({
            "headers": { "X-Hub-Signature-256": ["sha256=abc"] },
            "body": sample_text_notification().to_string()
        }),
    );
    assert_schema_rejects(
        &webhook_receive,
        &json!({
            "headers": { "X-Hub-Signature-256": "sha256=abc" },
            "body": sample_text_notification()
        }),
    );
}

fn assert_output_schema_examples(manifest: &toml::Value) {
    let send_output =
        json!({ "message_id": "wamid.1", "wa_id": "15559876543", "coordination": [] });

    let send_text = operation_schema(manifest, "send_text", "output_schema");
    assert_schema_accepts(&send_text, &send_output);
    assert_schema_rejects(&send_text, &json!({ "message_id": "wamid.1" }));
    assert_schema_rejects(
        &send_text,
        &json!({ "message_id": "wamid.1", "wa_id": "15559876543" }),
    );

    let send_template = operation_schema(manifest, "send_template", "output_schema");
    assert_schema_accepts(&send_template, &send_output);
    assert_schema_rejects(
        &send_template,
        &json!({ "message_id": "wamid.1", "wa_id": 42 }),
    );

    let get_profile = operation_schema(manifest, "get_profile", "output_schema");
    assert_schema_accepts(
        &get_profile,
        &json!({
            "about": "Business updates",
            "description": "Customer care",
            "address": "1 Market St",
            "vertical": "PROF_SERVICES"
        }),
    );
    assert_schema_accepts(&get_profile, &json!({}));
    assert_schema_rejects(&get_profile, &json!({ "about": "Business", "extra": true }));

    let webhook_verify = operation_schema(manifest, "webhook_verify", "output_schema");
    assert_schema_accepts(&webhook_verify, &json!({ "challenge": "challenge-1" }));
    assert_schema_rejects(&webhook_verify, &json!({ "challenge": 1 }));

    let webhook_receive = operation_schema(manifest, "webhook_receive", "output_schema");
    assert_schema_accepts(
        &webhook_receive,
        &json!({
            "events": [{
                "id": "wamid.1",
                "event_type": "message",
                "event_kind": "message",
                "agent_turn_eligible": true,
                "payload": {},
                "policy": {}
            }],
            "event_count": 1,
            "dropped_event_count": 0,
            "replay_dropped_count": 0,
            "policy_decisions": [],
            "connector_scope": "whatsapp_business_cloud_api",
            "personal_bridge_supported": false
        }),
    );
    assert_schema_rejects(
        &webhook_receive,
        &json!({
            "events": [],
            "event_count": 0,
            "dropped_event_count": 0,
            "replay_dropped_count": 0,
            "policy_decisions": [],
            "connector_scope": "personal_bridge",
            "personal_bridge_supported": false
        }),
    );
}

fn assert_whatsapp_api_network_constraints(network: &toml::Table) {
    assert_eq!(
        string_array_field(network, "host_allow"),
        ["graph.facebook.com"]
    );
    assert_eq!(integer_array_field(network, "port_allow"), [443]);
    assert!(string_array_field(network, "ip_allow").is_empty());
    assert!(string_array_field(network, "cidr_deny").is_empty());
    assert!(bool_field(network, "require_tls"));
    assert!(bool_field(network, "require_sni"));
    assert!(bool_field(network, "deny_localhost"));
    assert!(bool_field(network, "deny_private_ranges"));
    assert!(bool_field(network, "deny_tailnet_ranges"));
    assert!(string_array_field(network, "spki_pins").is_empty());
    assert!(bool_field(network, "deny_ip_literals"));
    assert!(bool_field(network, "require_host_canonicalization"));
    assert_eq!(integer_field(network, "dns_max_ips"), 16);
    assert_eq!(integer_field(network, "max_redirects"), 0);
    assert_eq!(integer_field(network, "connect_timeout_ms"), 10_000);
    assert_eq!(integer_field(network, "total_timeout_ms"), 30_000);
    assert_eq!(integer_field(network, "max_response_bytes"), 1_048_576);
}

fn assert_no_connector_egress_network_constraints(network: &toml::Table) {
    assert_eq!(string_array_field(network, "host_allow"), ["none.invalid"]);
    assert_eq!(integer_array_field(network, "port_allow"), [0]);
    assert!(string_array_field(network, "ip_allow").is_empty());
    assert!(string_array_field(network, "cidr_deny").is_empty());
    assert!(bool_field(network, "deny_localhost"));
    assert!(bool_field(network, "deny_private_ranges"));
    assert!(bool_field(network, "deny_tailnet_ranges"));
    assert!(!bool_field(network, "require_sni"));
    assert!(string_array_field(network, "spki_pins").is_empty());
    assert!(bool_field(network, "deny_ip_literals"));
    assert!(bool_field(network, "require_host_canonicalization"));
    assert_eq!(integer_field(network, "dns_max_ips"), 0);
    assert_eq!(integer_field(network, "max_redirects"), 0);
    assert_eq!(integer_field(network, "connect_timeout_ms"), 1_000);
    assert_eq!(integer_field(network, "total_timeout_ms"), 30_000);
    assert_eq!(integer_field(network, "max_response_bytes"), 1_048_576);
}

#[test]
fn manifest_operation_schemas_compile_and_validate_core_payloads() {
    let manifest = whatsapp_manifest();
    assert_manifest_schema_catalog_matches_runtime(&manifest);
    assert_input_schema_examples(&manifest);
    assert_output_schema_examples(&manifest);
}

#[test]
fn manifest_declares_strict_per_operation_network_constraints() {
    let manifest = whatsapp_manifest();
    let operations = manifest_operations(&manifest);
    assert_eq!(
        operations.len(),
        EXPECTED_MANIFEST_SCHEMA_OPS.len(),
        "manifest operation count should stay aligned with network-constraint coverage"
    );

    for operation_key in WHATSAPP_API_EGRESS_OPERATION_KEYS {
        assert_whatsapp_api_network_constraints(operation_network_constraints(
            &manifest,
            operation_key,
        ));
    }
    for operation_key in NO_CONNECTOR_EGRESS_OPERATION_KEYS {
        assert_no_connector_egress_network_constraints(operation_network_constraints(
            &manifest,
            operation_key,
        ));
    }
}

fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints cbor should be valid")
        .sign(signing_key)
        .expect("token should sign");
    CapabilityToken::from_raw(cose)
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| CapabilityId::new(*cap).expect("capability id"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

async fn setup_handshake(
    connector: &mut WhatsAppConnector,
    capabilities: &[&str],
) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            capabilities,
        ))
        .await
        .expect("handshake should succeed");
    signing_key
}

async fn configure_connector_with_sender_policy(
    connector: &mut WhatsAppConnector,
    base_url: &str,
    webhook_enabled: bool,
    allowed_senders: &[&str],
) {
    let mut config = json!({
        "base_url": base_url,
        "phone_number_id": PHONE_NUMBER_ID,
        "access_token": ACCESS_TOKEN,
        "retry": {
            "max_retries": 0,
        },
    });
    if webhook_enabled {
        config["app_secret"] = json!(APP_SECRET);
        config["webhook_verify_token"] = json!(VERIFY_TOKEN);
    }
    if !allowed_senders.is_empty() {
        config["webhook_allowed_senders"] = json!(allowed_senders);
    }
    connector
        .configure(config)
        .await
        .expect("configure should succeed");
}

async fn configure_connector(
    connector: &mut WhatsAppConnector,
    base_url: &str,
    webhook_enabled: bool,
) {
    configure_connector_with_sender_policy(connector, base_url, webhook_enabled, &[]).await;
}

async fn setup_connector(
    base_url: &str,
    capabilities: &[&str],
    webhook_enabled: bool,
) -> (WhatsAppConnector, Ed25519SigningKey) {
    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, base_url, webhook_enabled).await;
    let signing_key = setup_handshake(&mut connector, capabilities).await;
    (connector, signing_key)
}

async fn setup_connector_with_sender_policy(
    base_url: &str,
    capabilities: &[&str],
    allowed_senders: &[&str],
) -> (WhatsAppConnector, Ed25519SigningKey) {
    let mut connector = WhatsAppConnector::new();
    configure_connector_with_sender_policy(&mut connector, base_url, true, allowed_senders).await;
    let signing_key = setup_handshake(&mut connector, capabilities).await;
    (connector, signing_key)
}

fn invoke_request(
    connector: &WhatsAppConnector,
    operation: &'static str,
    input: Value,
    capability_token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".into(),
        id: RequestId::new("req_1"),
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

fn send_message_response(message_id: &str, wa_id: &str) -> Value {
    json!({
        "messaging_product": "whatsapp",
        "contacts": [{ "input": wa_id, "wa_id": wa_id }],
        "messages": [{ "id": message_id }],
    })
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
                        "from": "15559876543",
                        "id": "wamid.HBgLMTU1NTk4NzY1NDMVAgASGBQzQUY5MTcxMkFCRTY1RTM5REI0MAA=",
                        "timestamp": "1677000000",
                        "type": "text",
                        "text": { "body": "Hello from WhatsApp!", "preview_url": false },
                    }],
                },
                "field": "messages",
            }],
        }],
    })
}

fn sample_status_notification() -> Value {
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
                    "statuses": [{
                        "id": "wamid.STATUS123",
                        "status": "delivered",
                        "timestamp": "1677000100",
                        "recipient_id": "15559876543",
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
async fn lifecycle_health_unconfigured() {
    let connector = WhatsAppConnector::new();
    let health = connector.health().await;
    assert!(matches!(health.status, HealthState::Degraded { .. }));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_accepts_requested_capabilities() {
    let mut connector = WhatsAppConnector::new();
    let signing_key = Ed25519SigningKey::generate();

    let response = connector
        .handshake(handshake_request(
            signing_key.verifying_key().to_bytes(),
            &[CAP_SEND, CAP_READ, CAP_WEBHOOK],
        ))
        .await
        .expect("handshake should succeed");

    assert_eq!(response.status, "accepted");
    assert_eq!(response.capabilities_granted.len(), 3);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor_passes_after_configure() {
    let server = MockServer::start().await;
    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let report = connector.doctor();
    assert!(report.passed);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_health_after_configure_is_ready() {
    let server = MockServer::start().await;
    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let health = connector.health().await;
    assert!(matches!(health.status, HealthState::Ready));
}

#[fcp_async_core::runtime::test]
async fn self_check_before_configure_is_degraded() {
    let connector = WhatsAppConnector::new();
    let report = connector.self_check().await.expect("self-check should run");
    assert_eq!(report.status, SelfCheckStatus::Degraded);
    assert_eq!(report.reason_code.as_deref(), Some("not_configured"));
}

#[fcp_async_core::runtime::test]
async fn self_check_reports_ok_when_api_is_reachable() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.self_check.ok");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{PHONE_NUMBER_ID}")))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;

    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let report = connector.self_check().await.expect("self-check should run");
    assert_eq!(report.status, SelfCheckStatus::Ok);
}

#[fcp_async_core::runtime::test]
async fn self_check_unauthorized_is_failed() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.self_check.unauthorized");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{PHONE_NUMBER_ID}")))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let report = connector.self_check().await.expect("self-check should run");
    assert_eq!(report.status, SelfCheckStatus::Failed);
    assert_eq!(report.reason_code.as_deref(), Some("self_check_failed"));
}

#[fcp_async_core::runtime::test]
async fn self_check_rate_limited_is_degraded() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.self_check.rate_limited");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{PHONE_NUMBER_ID}")))
        .respond_with(ResponseTemplate::new(429).append_header("retry-after", "2"))
        .mount(&server)
        .await;

    let mut connector = WhatsAppConnector::new();
    configure_connector(&mut connector, &server.uri(), false).await;

    let report = connector.self_check().await.expect("self-check should run");
    assert_eq!(report.status, SelfCheckStatus::Degraded);
    assert_eq!(report.reason_code.as_deref(), Some("self_check_retryable"));
}

#[fcp_async_core::runtime::test]
async fn client_secretless_health_check_omits_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{PHONE_NUMBER_ID}")))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;

    let client = WhatsAppClient::new(
        &server.uri(),
        PHONE_NUMBER_ID,
        "",
        HttpRetryConfig::default(),
    )
    .expect("test client should initialize");
    assert!(client.health_check().await.is_ok());

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers.get("authorization").is_none());
}

#[fcp_async_core::runtime::test]
async fn client_health_check_with_token_sends_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{PHONE_NUMBER_ID}")))
        .and(header("authorization", "Bearer real_token"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;

    let client = WhatsAppClient::new(
        &server.uri(),
        PHONE_NUMBER_ID,
        "real_token",
        HttpRetryConfig::default(),
    )
    .expect("test client should initialize");
    assert!(client.health_check().await.is_ok());
}

#[fcp_async_core::runtime::test]
async fn send_text_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.send_text.happy_path");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .and(body_json(json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": "15551234567",
            "type": "text",
            "text": {
                "body": "Hello from FCP!",
                "preview_url": true,
            },
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(send_message_response("wamid.MSG1", "15551234567")),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_SEND,
        &[OP_SEND_TEXT],
        connector.instance_id(),
    );
    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
            "preview_url": true,
        }),
        token,
    )
    .await
    .expect("send_text should succeed");

    assert_eq!(result["message_id"], "wamid.MSG1");
    assert_eq!(result["wa_id"], "15551234567");
    assert_eq!(result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(result["coordination"][1]["outcome"], "granted");
    assert_eq!(result["coordination"][2]["event"], "send_executed");
    let coordination_text =
        serde_json::to_string(&result["coordination"]).expect("serialize coordination");
    assert!(
        !coordination_text.contains("15551234567"),
        "coordination audit must not leak raw WhatsApp recipients"
    );
    assert!(
        !coordination_text.contains("Hello from FCP!"),
        "coordination audit must not leak WhatsApp message bodies"
    );
}

#[fcp_async_core::runtime::test]
async fn send_text_claims_conversation_and_denies_duplicate_before_http() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.send_text.chat_coordination");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(send_message_response("wamid.CLAIM1", "15551234567")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let checker: Arc<dyn ThreadOwnershipChecker> = Arc::new(InMemoryThreadOwnershipChecker::new());
    let mut first = WhatsAppConnector::new()
        .with_thread_ownership_checker(Arc::clone(&checker), ChatCoordinationBackend::InMemory);
    let mut second = WhatsAppConnector::new()
        .with_thread_ownership_checker(checker, ChatCoordinationBackend::InMemory);
    configure_connector(&mut first, &server.uri(), false).await;
    configure_connector(&mut second, &server.uri(), false).await;
    let first_key = setup_handshake(&mut first, &[CAP_SEND]).await;
    let second_key = setup_handshake(&mut second, &[CAP_SEND]).await;
    let first_id = first.instance_id().clone();
    let second_id = second.instance_id().clone();

    let first_result = invoke(
        &first,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "secret WhatsApp body",
        }),
        generate_valid_token(&first_key, CAP_SEND, &[OP_SEND_TEXT], &first_id),
    )
    .await
    .expect("first send should claim and reach provider");
    assert_eq!(first_result["message_id"], "wamid.CLAIM1");
    assert_eq!(first_result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(first_result["coordination"][1]["outcome"], "granted");
    assert_eq!(first_result["coordination"][2]["event"], "send_executed");
    let coordination_text =
        serde_json::to_string(&first_result["coordination"]).expect("serialize coordination");
    assert!(
        !coordination_text.contains("15551234567"),
        "coordination audit must not leak raw WhatsApp recipients"
    );
    assert!(
        !coordination_text.contains("secret WhatsApp body"),
        "coordination audit must not leak WhatsApp message bodies"
    );

    let duplicate = invoke(
        &second,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "secret WhatsApp body",
        }),
        generate_valid_token(&second_key, CAP_SEND, &[OP_SEND_TEXT], &second_id),
    )
    .await
    .expect_err("duplicate active owner should be denied before provider HTTP");
    assert!(matches!(
        duplicate,
        FcpError::Unauthorized { code: 4090, ref message }
            if message.starts_with("thread_owned_by_peer:") && message.contains(first_id.as_str())
    ));
}

#[fcp_async_core::runtime::test]
async fn send_text_unauthorized_maps_to_fcp_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_SEND,
        &[OP_SEND_TEXT],
        connector.instance_id(),
    );
    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::Unauthorized { .. })));
}

#[fcp_async_core::runtime::test]
async fn send_text_rate_limited_maps_to_fcp_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .respond_with(ResponseTemplate::new(429).append_header("retry-after", "5"))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_SEND,
        &[OP_SEND_TEXT],
        connector.instance_id(),
    );
    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(
        result,
        Err(FcpError::RateLimited {
            retry_after_ms: 5000,
            ..
        })
    ));
}

#[fcp_async_core::runtime::test]
async fn send_text_invalid_preview_url_is_rejected() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_SEND,
        &[OP_SEND_TEXT],
        connector.instance_id(),
    );
    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
            "preview_url": "yes",
        }),
        token,
    )
    .await;

    assert!(matches!(
        result,
        Err(FcpError::InvalidRequest { ref message, .. })
            if message.contains("preview_url")
    ));
}

#[fcp_async_core::runtime::test]
async fn send_template_happy_path() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.send_template.happy_path");
    let server = MockServer::start().await;
    let components = json!([{
        "type": "body",
        "parameters": [{
            "type": "text",
            "text": "Ada",
        }],
    }]);

    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .and(body_json(json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": "15551234567",
            "type": "template",
            "template": {
                "name": "welcome_message",
                "language": { "code": "en_US" },
                "components": components.clone(),
            },
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(send_message_response("wamid.TEMPLATE1", "15551234567")),
        )
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_SEND,
        &[OP_SEND_TEMPLATE],
        connector.instance_id(),
    );
    let result = invoke(
        &connector,
        OP_SEND_TEMPLATE,
        json!({
            "to": "15551234567",
            "template_name": "welcome_message",
            "language_code": "en_US",
            "components": components,
        }),
        token,
    )
    .await
    .expect("send_template should succeed");

    assert_eq!(result["message_id"], "wamid.TEMPLATE1");
    assert_eq!(result["coordination"][0]["event"], "claim_attempt");
    assert_eq!(result["coordination"][1]["outcome"], "granted");
    assert_eq!(result["coordination"][2]["event"], "send_executed");
}

#[fcp_async_core::runtime::test]
async fn send_template_invalid_components_is_rejected() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_SEND,
        &[OP_SEND_TEMPLATE],
        connector.instance_id(),
    );
    let result = invoke(
        &connector,
        OP_SEND_TEMPLATE,
        json!({
            "to": "15551234567",
            "template_name": "welcome_message",
            "components": { "type": "body" },
        }),
        token,
    )
    .await;

    assert!(matches!(
        result,
        Err(FcpError::InvalidRequest { ref message, .. })
            if message.contains("components")
    ));
}

#[fcp_async_core::runtime::test]
async fn get_profile_happy_path_returns_flat_profile() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.get_profile.happy_path");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/{PHONE_NUMBER_ID}/whatsapp_business_profile"
        )))
        .and(query_param("fields", "about,address,description,vertical"))
        .and(header("authorization", format!("Bearer {ACCESS_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{
                "about": "Hello there",
                "address": "1 Main Street",
                "description": "Test business profile",
                "vertical": "SERVICES",
            }],
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_READ], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_READ,
        &[OP_GET_PROFILE],
        connector.instance_id(),
    );
    let result = invoke(&connector, OP_GET_PROFILE, json!({}), token)
        .await
        .expect("get_profile should succeed");

    assert_eq!(result["about"], "Hello there");
    assert_eq!(result["address"], "1 Main Street");
    assert_eq!(result["description"], "Test business profile");
    assert_eq!(result["vertical"], "SERVICES");
    assert!(result.get("data").is_none());
}

#[fcp_async_core::runtime::test]
async fn get_profile_rate_limited_maps_to_fcp_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/{PHONE_NUMBER_ID}/whatsapp_business_profile"
        )))
        .respond_with(ResponseTemplate::new(429).append_header("retry-after", "3"))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_READ], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_READ,
        &[OP_GET_PROFILE],
        connector.instance_id(),
    );
    let result = invoke(&connector, OP_GET_PROFILE, json!({}), token).await;

    assert!(matches!(
        result,
        Err(FcpError::RateLimited {
            retry_after_ms: 3000,
            ..
        })
    ));
}

#[fcp_async_core::runtime::test]
async fn get_profile_empty_response_returns_empty_object() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/{PHONE_NUMBER_ID}/whatsapp_business_profile"
        )))
        .and(query_param("fields", "about,address,description,vertical"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
        })))
        .mount(&server)
        .await;

    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_READ], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_READ,
        &[OP_GET_PROFILE],
        connector.instance_id(),
    );
    let result = invoke(&connector, OP_GET_PROFILE, json!({}), token)
        .await
        .expect("get_profile should succeed");

    assert_eq!(result, json!({}));
}

#[fcp_async_core::runtime::test]
async fn invoke_not_configured_is_rejected() {
    let mut connector = WhatsAppConnector::new();
    let signing_key = setup_handshake(&mut connector, &[CAP_SEND]).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_SEND,
        &[OP_SEND_TEXT],
        connector.instance_id(),
    );

    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::NotConfigured)));
}

#[fcp_async_core::runtime::test]
async fn webhook_verify_via_invoke() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.webhook_verify.happy_path");
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_WEBHOOK,
        &[OP_WEBHOOK_VERIFY],
        connector.instance_id(),
    );

    let result = invoke(
        &connector,
        OP_WEBHOOK_VERIFY,
        json!({
            "hub_mode": "subscribe",
            "hub_verify_token": VERIFY_TOKEN,
            "hub_challenge": "challenge_123",
        }),
        token,
    )
    .await
    .expect("webhook verify should succeed");

    assert_eq!(result["challenge"], "challenge_123");
}

#[fcp_async_core::runtime::test]
async fn webhook_verify_wrong_token_is_unauthorized() {
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_WEBHOOK,
        &[OP_WEBHOOK_VERIFY],
        connector.instance_id(),
    );

    let result = invoke(
        &connector,
        OP_WEBHOOK_VERIFY,
        json!({
            "hub_mode": "subscribe",
            "hub_verify_token": "wrong",
            "hub_challenge": "challenge_123",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::Unauthorized { .. })));
}

#[fcp_async_core::runtime::test]
async fn webhook_receive_via_invoke_parses_events() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.webhook_receive.happy_path");
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_WEBHOOK,
        &[OP_WEBHOOK_RECEIVE],
        connector.instance_id(),
    );

    let body = serde_json::to_vec(&sample_text_notification()).expect("body json");
    let result = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body).expect("utf8 body"),
        }),
        token,
    )
    .await
    .expect("webhook receive should succeed");

    assert_eq!(result["event_count"], 1);
    assert_eq!(result["dropped_event_count"], 0);
    assert_eq!(result["connector_scope"], "whatsapp_business_cloud_api");
    assert_eq!(result["personal_bridge_supported"], false);
    assert_eq!(result["events"][0]["event_type"], "message.text");
    assert_eq!(result["events"][0]["event_kind"], "message");
    assert_eq!(result["events"][0]["agent_turn_eligible"], true);
    assert_eq!(
        result["events"][0]["id"],
        "wamid.HBgLMTU1NTk4NzY1NDMVAgASGBQzQUY5MTcxMkFCRTY1RTM5REI0MAA="
    );
    assert_eq!(
        result["policy_decisions"][0]["reason"],
        "sender_policy_allow_all"
    );
}

#[fcp_async_core::runtime::test]
async fn webhook_receive_filters_replayed_events() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.webhook_receive.replay_filter");
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let body = serde_json::to_vec(&sample_status_notification()).expect("body json");

    let first = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body.clone()).expect("utf8 body"),
        }),
        generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_WEBHOOK_RECEIVE],
            connector.instance_id(),
        ),
    )
    .await
    .expect("first webhook receive should succeed");

    let second = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body).expect("utf8 body"),
        }),
        generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_WEBHOOK_RECEIVE],
            connector.instance_id(),
        ),
    )
    .await
    .expect("second webhook receive should succeed");

    assert_eq!(first["event_count"], 1);
    assert_eq!(second["event_count"], 0);
    assert_eq!(second["replay_dropped_count"], 1);
    assert_eq!(second["policy_decisions"][0]["reason"], "replay_detected");
}

#[fcp_async_core::runtime::test]
async fn webhook_receive_records_sender_policy_for_authorized_message() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.webhook_receive.sender_policy.allowed");
    let (connector, signing_key) =
        setup_connector_with_sender_policy("http://127.0.0.1:1", &[CAP_WEBHOOK], &["+15559876543"])
            .await;
    let token = generate_valid_token(
        &signing_key,
        CAP_WEBHOOK,
        &[OP_WEBHOOK_RECEIVE],
        connector.instance_id(),
    );

    let body = serde_json::to_vec(&sample_text_notification()).expect("body json");
    let result = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body).expect("utf8 body"),
        }),
        token,
    )
    .await
    .expect("webhook receive should succeed");

    assert_eq!(result["event_count"], 1);
    assert_eq!(result["dropped_event_count"], 0);
    assert_eq!(result["replay_dropped_count"], 0);
    assert_eq!(result["connector_scope"], "whatsapp_business_cloud_api");
    assert_eq!(result["personal_bridge_supported"], false);
    assert_eq!(result["events"][0]["event_kind"], "message");
    assert_eq!(result["events"][0]["agent_turn_eligible"], true);
    assert_eq!(result["events"][0]["policy"]["decision"], "accepted");
    assert_eq!(result["events"][0]["policy"]["reason"], "sender_allowed");
    assert_eq!(result["policy_decisions"][0]["decision"], "accepted");
    assert_eq!(result["policy_decisions"][0]["reason"], "sender_allowed");

    let sender_redacted = result["policy_decisions"][0]["sender_redacted"]
        .as_str()
        .expect("redacted sender");
    assert_ne!(sender_redacted, "15559876543");
    assert!(!sender_redacted.contains("9876543"));
}

#[fcp_async_core::runtime::test]
async fn webhook_receive_drops_signed_unauthorized_sender_and_preserves_replay_claim() {
    let _ctx =
        AsyncTestContext::for_scenario("whatsapp.webhook_receive.sender_policy.unauthorized");
    let (connector, signing_key) =
        setup_connector_with_sender_policy("http://127.0.0.1:1", &[CAP_WEBHOOK], &["+111"]).await;
    let body = serde_json::to_vec(&sample_text_notification()).expect("body json");

    let first = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body.clone()).expect("utf8 body"),
        }),
        generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_WEBHOOK_RECEIVE],
            connector.instance_id(),
        ),
    )
    .await
    .expect("signed unauthorized sender should be handled by policy");

    let second = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body).expect("utf8 body"),
        }),
        generate_valid_token(
            &signing_key,
            CAP_WEBHOOK,
            &[OP_WEBHOOK_RECEIVE],
            connector.instance_id(),
        ),
    )
    .await
    .expect("replayed unauthorized sender should be handled by replay policy");

    assert_eq!(first["event_count"], 0);
    assert_eq!(first["dropped_event_count"], 1);
    assert_eq!(first["replay_dropped_count"], 0);
    assert_eq!(first["policy_decisions"][0]["decision"], "dropped");
    assert_eq!(first["policy_decisions"][0]["reason"], "sender_not_allowed");
    assert_eq!(first["policy_decisions"][0]["event_kind"], "message");

    let sender_redacted = first["policy_decisions"][0]["sender_redacted"]
        .as_str()
        .expect("redacted sender");
    assert_ne!(sender_redacted, "15559876543");

    assert_eq!(second["event_count"], 0);
    assert_eq!(second["dropped_event_count"], 1);
    assert_eq!(second["replay_dropped_count"], 1);
    assert_eq!(second["policy_decisions"][0]["reason"], "replay_detected");
}

#[fcp_async_core::runtime::test]
async fn webhook_receive_keeps_status_updates_audit_only_under_sender_policy() {
    let _ctx = AsyncTestContext::for_scenario("whatsapp.webhook_receive.status_audit_policy");
    let (connector, signing_key) =
        setup_connector_with_sender_policy("http://127.0.0.1:1", &[CAP_WEBHOOK], &["+111"]).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_WEBHOOK,
        &[OP_WEBHOOK_RECEIVE],
        connector.instance_id(),
    );

    let body = serde_json::to_vec(&sample_status_notification()).expect("body json");
    let result = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": sign_payload(&body) },
            "body": String::from_utf8(body).expect("utf8 body"),
        }),
        token,
    )
    .await
    .expect("signed status update should be accepted as audit event");

    assert_eq!(result["event_count"], 1);
    assert_eq!(result["dropped_event_count"], 0);
    assert_eq!(result["events"][0]["event_kind"], "status");
    assert_eq!(result["events"][0]["agent_turn_eligible"], false);
    assert_eq!(result["events"][0]["policy"]["decision"], "accepted");
    assert_eq!(
        result["events"][0]["policy"]["reason"],
        "status_update_audit_only"
    );
    assert_eq!(
        result["policy_decisions"][0]["reason"],
        "status_update_audit_only"
    );
}

#[fcp_async_core::runtime::test]
async fn webhook_receive_invalid_signature_is_rejected() {
    let (connector, signing_key) =
        setup_connector("http://127.0.0.1:1", &[CAP_WEBHOOK], true).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_WEBHOOK,
        &[OP_WEBHOOK_RECEIVE],
        connector.instance_id(),
    );
    let body = serde_json::to_vec(&sample_text_notification()).expect("body json");

    let result = invoke(
        &connector,
        OP_WEBHOOK_RECEIVE,
        json!({
            "headers": { "x-hub-signature-256": "sha256=deadbeef" },
            "body": String::from_utf8(body).expect("utf8 body"),
        }),
        token,
    )
    .await;

    assert!(matches!(
        result,
        Err(FcpError::Unauthorized { code: 2002, ref message })
            if message.contains("Webhook signature verification failed")
    ));
}

#[fcp_async_core::runtime::test]
async fn capability_mismatch_rejects_send_text() {
    let server = MockServer::start().await;
    let (connector, signing_key) =
        setup_connector(&server.uri(), &[CAP_SEND, CAP_READ], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_READ,
        &[OP_SEND_TEXT],
        connector.instance_id(),
    );

    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspection_exposes_expected_operations() {
    let connector = WhatsAppConnector::new();
    let introspection = connector.introspect();
    let operation_ids: Vec<&str> = introspection
        .operations
        .iter()
        .map(|op| op.id.as_str())
        .collect();

    assert_eq!(operation_ids.len(), 5);
    assert!(operation_ids.contains(&OP_SEND_TEXT));
    assert!(operation_ids.contains(&OP_SEND_TEMPLATE));
    assert!(operation_ids.contains(&OP_GET_PROFILE));
    assert!(operation_ids.contains(&OP_WEBHOOK_VERIFY));
    assert!(operation_ids.contains(&OP_WEBHOOK_RECEIVE));
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown_succeeds() {
    let mut connector = WhatsAppConnector::new();
    connector
        .shutdown(ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 10_000,
            drain: false,
            reason: None,
        })
        .await
        .expect("shutdown should succeed");
}

#[fcp_async_core::runtime::test]
async fn operation_mismatch_rejects_send_text() {
    let server = MockServer::start().await;
    let (connector, signing_key) = setup_connector(&server.uri(), &[CAP_SEND], false).await;
    let token = generate_valid_token(
        &signing_key,
        CAP_SEND,
        &[OP_GET_PROFILE],
        connector.instance_id(),
    );

    let result = invoke(
        &connector,
        OP_SEND_TEXT,
        json!({
            "to": "15551234567",
            "text": "Hello from FCP!",
        }),
        token,
    )
    .await;

    assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
}

// ── Replay safety on retry (br-kxd3e) ────────────────────────────────
//
// The WhatsApp Cloud API has no idempotency key, so a 5xx retry delivers the
// message a second time to a real person's phone. The assertion is the REQUEST
// COUNT — "it still errors" would pass with the bug present.

fn replay_test_client(server: &MockServer) -> WhatsAppClient {
    WhatsAppClient::new(
        &server.uri(),
        PHONE_NUMBER_ID,
        ACCESS_TOKEN,
        HttpRetryConfig {
            max_retries: 3,
            initial_delay_ms: 1,
            max_delay_ms: 5,
            jitter_enabled: false,
        },
    )
    .expect("test client should initialize")
}

fn replay_test_runtime() -> fcp_sdk::ConnectorRuntime {
    fcp_sdk::ConnectorRuntime::new(fcp_sdk::ConnectorRuntimeConfig::default())
}

/// A Meta-shaped 5xx. Using the real error envelope matters: the client parses
/// it into `WhatsAppError::Api`, which is a DIFFERENT branch from a bodyless
/// 5xx, and it is the branch production actually takes.
fn meta_server_error() -> ResponseTemplate {
    ResponseTemplate::new(503).set_body_json(json!({
        "error": {
            "message": "(#131026) Message undeliverable",
            "type": "OAuthException",
            "code": 131_026,
            "fbtrace_id": "Az8n"
        }
    }))
}

#[fcp_async_core::runtime::test]
async fn send_text_message_is_not_retried_after_a_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .respond_with(meta_server_error())
        .mount(&server)
        .await;

    let result = replay_test_client(&server)
        .send_text_message(&replay_test_runtime(), "15551234567", "hello", false)
        .await;
    assert!(result.is_err());

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(
        requests.len(),
        1,
        "a 503 means Meta received the send — retrying delivers the message a \
         SECOND time, and WhatsApp offers no idempotency key to prevent it"
    );
}

#[fcp_async_core::runtime::test]
async fn send_text_message_still_retries_a_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/{PHONE_NUMBER_ID}/messages")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messaging_product": "whatsapp",
            "contacts": [{ "input": "15551234567", "wa_id": "15551234567" }],
            "messages": [{ "id": "wamid.1" }]
        })))
        .mount(&server)
        .await;

    replay_test_client(&server)
        .send_text_message(&replay_test_runtime(), "15551234567", "hello", false)
        .await
        .expect("a rate-limited send was refused without delivering anything");

    let requests = server.received_requests().await.unwrap_or_default();
    assert_eq!(
        requests.len(),
        2,
        "429 means the message was NOT sent, so backoff must be preserved"
    );
}
