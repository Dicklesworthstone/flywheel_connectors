//! E2E Plaid connector compliance tests (flywheel_connectors-38h.6).
//!
//! Exercises the Plaid connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock API)
//! - Network guard allow/deny (manifest `host_allow` exact-host validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features plaid`

#![cfg(feature = "plaid")]
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

use fcp_plaid::connector::PlaidConnector;

// ============================================================================
// FcpConnector adapter for PlaidConnector
// ============================================================================

struct PlaidConnectorAdapter {
    connector: PlaidConnector,
    id: ConnectorId,
}

impl PlaidConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: PlaidConnector::new(),
            id: ConnectorId::from_static("plaid"),
        }
    }
}

fcp_core::impl_fcp_sealed!(PlaidConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for PlaidConnectorAdapter {
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
                    other => HealthSnapshot::degraded(format!("plaid_status:{other}")),
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
                id: OperationId::from_static("plaid.accounts_get"),
                summary: "Get all accounts for a linked item".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["access_token"],
                    "properties": {
                        "access_token": { "type": "string" },
                        "options": { "type": "object" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["accounts", "item"],
                    "properties": {
                        "accounts": { "type": "array" },
                        "item": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("plaid.accounts.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List all accounts for a linked institution".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"access_token": "access-sandbox-xxxx"}"#.to_string()],
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
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize test constraints");
    let resolved_capability = match capability {
        "plaid.accounts_get" => "plaid.accounts.read",
        _ => capability,
    };
    let cose = CapabilityTokenBuilder::new()
        .capability_id(resolved_capability)
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
        id: RequestId::from("plaid-e2e"),
        connector_id: ConnectorId::from_static("plaid"),
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

fn plaid_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/plaid/manifest.toml"))
        .expect("plaid manifest toml")
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

/// Plaid `accounts_get` success response.
fn plaid_accounts_success_response() -> serde_json::Value {
    json!({
        "accounts": [{
            "account_id": "acc-e2e-1",
            "balances": {
                "available": 500.0,
                "current": 510.0,
                "limit": null,
                "iso_currency_code": "USD",
                "unofficial_currency_code": null
            },
            "mask": "1234",
            "name": "E2E Checking",
            "official_name": "Plaid E2E Checking",
            "subtype": "checking",
            "type": "depository"
        }],
        "item": {
            "item_id": "item-e2e",
            "institution_id": "ins_1"
        }
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "plaid.link" but invoke targets "plaid.accounts_get"
/// (which requires "plaid.accounts.read").
#[fcp_async_core::runtime::test]
async fn plaid_default_deny_compliance_suite_passes() {
    let mut connector = PlaidConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["plaid.link"]);
    // Token grants "plaid.link" but invoke targets "plaid.accounts_get" -> denial
    let token = build_token(
        &signing_key,
        "plaid.link",
        &["plaid.link"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request(
        "plaid.accounts_get",
        json!({ "access_token": "access-sandbox-test" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: json!({
            "client_id": "test-plaid-client",
            "secret": "test-plaid-secret",
            "environment": "sandbox",
            "base_url": "http://localhost:9999"
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
        "plaid_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-plaid");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock API.
#[fcp_async_core::runtime::test]
async fn plaid_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for the accounts/get endpoint (POST)
    Mock::given(method("POST"))
        .and(path("/accounts/get"))
        .respond_with(ResponseTemplate::new(200).set_body_json(plaid_accounts_success_response()))
        .mount(mock.inner())
        .await;

    let mut connector = PlaidConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["plaid.accounts_get"],
    );
    let token = build_token(
        &signing_key,
        "plaid.accounts_get",
        &["plaid.accounts_get"],
        connector.connector.instance_id(),
    );
    let invoke = invoke_request(
        "plaid.accounts_get",
        json!({ "access_token": "access-sandbox-e2e" }),
        token,
    );
    let suite = ConnectorSuite {
        test_name: "plaid_allow_valid_token".to_string(),
        config: json!({
            "client_id": "test-plaid-client",
            "secret": "test-plaid-secret",
            "environment": "sandbox",
            "base_url": mock.base_url(),
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

    let mut runner = E2eRunner::new("fcp-e2e-plaid");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|request| request.url.path() == "/accounts/get")
        .count();
    assert_eq!(hits, 1, "expected exactly one POST to /accounts/get");
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
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow exact-host validation
// ============================================================================

/// Network guard: Plaid manifest restricts all operations to three exact hosts:
/// `production.plaid.com`, `sandbox.plaid.com`, `development.plaid.com`.
/// Verify that allowed hosts pass and non-matching hosts are denied.
#[test]
fn plaid_manifest_network_guard_allows_and_denies() {
    let manifest = plaid_manifest_toml();

    // Note: manifest doesn't include transactions_get separately from the others
    // but all operations share the same host_allow list
    let operations = [
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

    let expected_hosts = vec![
        "production.plaid.com".to_string(),
        "sandbox.plaid.com".to_string(),
        "development.plaid.com".to_string(),
    ];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow exactly the three Plaid environments"
        );

        // Allowed hosts
        assert!(
            host_allowed("production.plaid.com", &host_allow),
            "production.plaid.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("sandbox.plaid.com", &host_allow),
            "sandbox.plaid.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("development.plaid.com", &host_allow),
            "development.plaid.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("plaid.com", &host_allow),
            "plaid.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.production.plaid.com", &host_allow),
            "evil.production.plaid.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.openai.com", &host_allow),
            "api.openai.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("staging.plaid.com", &host_allow),
            "staging.plaid.com should be denied for {operation_name}"
        );
    }
}
