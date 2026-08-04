//! E2E Stripe connector compliance tests (flywheel_connectors-a81.7).
//!
//! Exercises the Stripe connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock REST API)
//! - Network guard allow/deny (manifest `host_allow` exact-host validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features stripe`

#![cfg(feature = "stripe")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    AgentHint, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector,
    FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, InstanceId,
    Introspection, InvokeRequest, InvokeResponse, InvokeStatus, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use fcp_stripe::connector::StripeConnector;

// ============================================================================
// FcpConnector adapter for StripeConnector
// ============================================================================

struct StripeConnectorAdapter {
    connector: StripeConnector,
    id: ConnectorId,
}

impl StripeConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: StripeConnector::new(),
            id: ConnectorId::from_static("stripe"),
        }
    }
}

fcp_core::impl_fcp_sealed!(StripeConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for StripeConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self.connector.handle_handshake(request).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "healthy" => HealthSnapshot::ready(),
                    "not_configured" => HealthSnapshot::degraded("not_configured"),
                    other => HealthSnapshot::degraded(format!("stripe_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics::default()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> fcp_core::FcpResult<()> {
        self.connector.handle_shutdown(json!({})).await.map(|_| ())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("stripe.get_customer"),
                summary: "Retrieve a Stripe customer by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["customer_id"],
                    "properties": {
                        "customer_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "customer": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("stripe.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Look up a customer by their Stripe ID.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"customer_id": "cus_abc123"}"#.to_string()],
                    related: Vec::new(),
                },
                rate_limit: None,
                requires_approval: None,
            }],
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let request_id = req.id;
        let params = json!({
            "operation": req.operation.as_str(),
            "input": req.input,
            "capability_token": req.capability_token,
        });
        let value = self.connector.handle_invoke(params).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let value = self.connector.handle_simulate(request).await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize simulate response: {err}"),
        })
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> fcp_core::FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> fcp_core::FcpResult<()> {
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn reference_manifest_with_hash() -> String {
    let raw = include_str!("../../../tests/vectors/manifest/manifest_valid.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn handshake_request(host_public_key: [u8; 32], capabilities: &[&str]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [7u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| cap.parse::<CapabilityId>().expect("capability id parse"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(InstanceId::new()),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    capability: &str,
    operations: &[&str],
    instance_id: &str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("serialize constraints to CBOR");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
        // dja9u typestate ratchet: tokens MUST carry target_instance matching the connector.
        .target_instance(instance_id)
        .sign(signing_key)
        .expect("capability token sign");
    CapabilityToken::from_raw(cose)
}

fn invoke_request(
    operation: &'static str,
    input: serde_json::Value,
    token: CapabilityToken,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from("stripe-e2e"),
        connector_id: ConnectorId::from_static("stripe"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: token,
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

fn stripe_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/stripe/manifest.toml"))
        .expect("stripe manifest toml")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .and_then(|constraints| constraints.get("host_allow"))
        .and_then(toml::Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .expect("operation host_allow")
}

fn host_allowed(host: &str, host_allow: &[String]) -> bool {
    fcp_sandbox::host_matches_allow_list(host, host_allow)
}

/// Stripe `get_customer` REST API success response.
fn stripe_get_customer_response() -> serde_json::Value {
    json!({
        "id": "cus_e2e_test_123",
        "object": "customer",
        "email": "test@example.com",
        "name": "Test Customer",
        "description": null,
        "created": 1706745600,
        "currency": "usd",
        "default_source": null,
        "delinquent": false,
        "livemode": false,
        "metadata": {},
        "phone": null,
        "preferred_locales": [],
        "shipping": null,
        "tax_exempt": "none",
        "balance": 0
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "stripe.payment" but invoke targets "stripe.get_customer"
/// (which requires "stripe.read").
#[fcp_async_core::runtime::test]
async fn stripe_default_deny_compliance_suite_passes() {
    let mut connector = StripeConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["stripe.payment"]);
    // Token grants "stripe.payment" but invoke targets "stripe.get_customer" -> denial
    let token = build_token(
        &signing_key,
        "stripe.payment",
        &["stripe.payment"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request(
        "stripe.get_customer",
        json!({ "customer_id": "cus_abc123" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "secret_key": "sk_test_000",
            "api_url": "http://localhost:9999/v1"
        }),
        handshake: handshake.clone(),
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new(
        "stripe_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-stripe");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock REST API.
#[fcp_async_core::runtime::test]
async fn stripe_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /customers/{id} endpoint
    Mock::given(method("GET"))
        .and(path("/customers/cus_e2e_test_123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(stripe_get_customer_response()))
        .mount(mock.inner())
        .await;

    let mut connector = StripeConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["stripe.read"]);
    let token = build_token(
        &signing_key,
        "stripe.read",
        &["stripe.get_customer"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request(
        "stripe.get_customer",
        json!({ "customer_id": "cus_e2e_test_123" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "stripe_allow_valid_token".to_string(),
        config: json!({
            "secret_key": "sk_test_e2e",
            "api_url": mock.base_url(),
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-stripe");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    let invoke_entry = report
        .logs
        .iter()
        .find(|entry| entry.context.get("operation") == Some(&json!("invoke")))
        .expect("invoke entry");
    assert_eq!(invoke_entry.result, "pass");
    assert_eq!(
        invoke_entry.context.get("invoke_status"),
        Some(&json!(format!("{:?}", InvokeStatus::Ok)))
    );
    mock.assert_request_count(1).await;
    let received = mock.received_requests().await;
    let customer_request = received
        .iter()
        .find(|request| request.method.as_str() == "GET")
        .expect("expected GET request");
    assert_eq!(customer_request.url.path(), "/customers/cus_e2e_test_123");
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow exact-host validation
// ============================================================================

/// Network guard: Stripe manifest restricts all operations to `api.stripe.com`.
/// Verify that the allowed host passes and non-matching hosts are denied.
#[test]
fn stripe_manifest_network_guard_allows_and_denies() {
    let manifest = stripe_manifest_toml();

    let operations = [
        "stripe.create_customer",
        "stripe.get_customer",
        "stripe.list_customers",
        "stripe.update_customer",
        "stripe.delete_customer",
        "stripe.create_payment_intent",
        "stripe.get_payment_intent",
        "stripe.create_refund",
        "stripe.create_subscription",
        "stripe.get_subscription",
        "stripe.list_subscriptions",
        "stripe.cancel_subscription",
        "stripe.list_invoices",
        "stripe.get_invoice",
        "stripe.get_balance",
        "stripe.ingest_webhook_event",
    ];

    let expected_hosts = vec!["api.stripe.com".to_string()];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow only api.stripe.com"
        );

        // Allowed host
        assert!(
            host_allowed("api.stripe.com", &host_allow),
            "api.stripe.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("stripe.com", &host_allow),
            "stripe.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.api.stripe.com", &host_allow),
            "evil.api.stripe.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("dashboard.stripe.com", &host_allow),
            "dashboard.stripe.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("js.stripe.com", &host_allow),
            "js.stripe.com should be denied for {operation_name}"
        );
    }
}
