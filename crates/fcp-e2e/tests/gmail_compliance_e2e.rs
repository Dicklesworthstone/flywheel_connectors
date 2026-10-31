//! E2E Gmail connector compliance tests (flywheel_connectors-ofw.6).
//!
//! Exercises the Gmail connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock API)
//! - Network guard allow/deny (manifest `host_allow` validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features gmail`

#![cfg(feature = "gmail")]
#![recursion_limit = "256"]
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

use fcp_gmail::connector::GmailConnector;

// ============================================================================
// FcpConnector adapter for GmailConnector
// ============================================================================

struct GmailConnectorAdapter {
    connector: GmailConnector,
    id: ConnectorId,
}

impl GmailConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: GmailConnector::new(),
            id: ConnectorId::from_static("fcp.gmail"),
        }
    }
}

fcp_core::impl_fcp_sealed!(GmailConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GmailConnectorAdapter {
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
            Ok(payload) => serde_json::from_value(payload).unwrap_or_else(|error| {
                HealthSnapshot::error(format!("invalid Gmail health: {error}"))
            }),
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
                id: OperationId::from_static("gmail.get_message"),
                summary: "Get a single email message by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["message_id"],
                    "properties": {
                        "message_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("gmail.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Retrieve full details of a specific email message.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"message_id": "18d1234abc567890"}"#.to_string()],
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
        let request_id = req.id.clone();
        let params = serde_json::to_value(req).map_err(|error| FcpError::Internal {
            message: format!("Failed to encode invocation: {error}"),
        })?;
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
        zone: ZoneId::private(),
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
    instance_id: &str,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize test constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:private")
        .principal("user:test")
        .operations(operations)
        // dja9u typestate ratchet: the Gmail connector verifies with
        // verify_bound, which requires an INSTANCE_ID claim; bind to the
        // connector instance (instance-binding pattern, commit 16171621d).
        .target_instance(instance_id)
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("valid constraints")
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
        id: RequestId::from("gmail-e2e"),
        connector_id: ConnectorId::from_static("fcp.gmail"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::private(),
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

fn gmail_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/gmail/manifest.toml"))
        .expect("gmail manifest toml")
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

/// Gmail `get_message` success response.
fn gmail_get_message_success_response() -> serde_json::Value {
    json!({
        "id": "18d1234abc567890",
        "threadId": "18d1234abc567890",
        "labelIds": ["INBOX", "UNREAD"],
        "snippet": "Hello, this is a test email from the E2E suite.",
        "historyId": "12345",
        "internalDate": "1709308800000",
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                { "name": "From", "value": "sender@example.com" },
                { "name": "To", "value": "recipient@example.com" },
                { "name": "Subject", "value": "E2E Test" },
                { "name": "Date", "value": "Sat, 01 Mar 2026 12:00:00 +0000" }
            ],
            "body": {
                "size": 42,
                "data": "SGVsbG8sIHRoaXMgaXMgYSB0ZXN0IGVtYWlsLg=="
            }
        },
        "sizeEstimate": 1024
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants `gmail.send` but invoke targets `gmail.get_message`
/// (which requires `gmail.read`).
#[fcp_async_core::runtime::test]
async fn gmail_default_deny_compliance_suite_passes() {
    let mut connector = GmailConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["gmail.send"]);
    // Token grants `gmail.send` but invoke targets `gmail.get_message` → denial
    let token = build_token(
        &signing_key,
        connector.connector.instance_id().as_str(),
        "gmail.send",
        &["gmail.send_message"],
    );
    let invoke = invoke_request(
        "gmail.get_message",
        json!({ "message_id": "18d1234abc567890" }),
        token,
    );

    let dynamic = DynamicSuite {
        // Secretless ratchet (e99o6): the Gmail connector rejects raw `token`
        // config; use the sanctioned credential_id reference shape.
        config: json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
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
        "gmail_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-gmail");
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
async fn gmail_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for the messages/{id} endpoint (GET)
    Mock::given(method("GET"))
        .and(path("/users/me/messages/18d1234abc567890"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(gmail_get_message_success_response()),
        )
        .mount(mock.inner())
        .await;

    let mut connector = GmailConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["gmail.read"]);
    let mut invoke = invoke_request(
        "gmail.get_message",
        json!({ "message_id": "18d1234abc567890" }),
        CapabilityToken::test_token(),
    );
    let suite = ConnectorSuite {
        test_name: "gmail_allow_valid_token".to_string(),
        // Secretless ratchet (e99o6): credential_id reference shape.
        config: json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": mock.base_url(),
        }),
        handshake,
        invoke: None,
        invoke_expectations: InvokeExpectations {
            expect_error: false,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: None,
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-gmail");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    assert!(connector.health().await.is_ready());
    invoke.capability_token = build_token(
        &signing_key,
        connector.connector.instance_id().as_str(),
        "gmail.read",
        &["gmail.get_message"],
    );
    let response = connector
        .invoke(invoke)
        .await
        .expect("authorized invocation");
    assert_eq!(response.status, InvokeStatus::Ok);
    assert_eq!(
        response.result.unwrap()["message"]["id"],
        "18d1234abc567890"
    );
    let received = mock.received_requests().await;
    let hits = received
        .iter()
        .filter(|request| request.url.path() == "/users/me/messages/18d1234abc567890")
        .count();
    assert_eq!(
        hits, 1,
        "expected exactly one GET to /users/me/messages/18d1234abc567890"
    );
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow validation
// ============================================================================

/// Network guard: Gmail manifest restricts all operations to
/// `gmail.googleapis.com` and `www.googleapis.com`.
/// Verify that allowed hosts pass and non-matching hosts are denied.
///
/// This test scans every operation declared in `connectors/gmail/manifest.toml`
/// (rather than a hardcoded list) so that newly-added operations are
/// automatically covered. See also
/// `gmail_manifest_matches_connector_dispatch_surface` below, which enforces
/// that the manifest set matches the connector's introspect surface — without
/// that second test, adding a new dispatch branch in `connector.rs` without
/// a matching `[provides.operations]` block would silently pass this scan.
#[test]
fn gmail_manifest_network_guard_allows_and_denies() {
    let manifest = gmail_manifest_toml();
    let operations_table = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("provides.operations table");

    assert_eq!(
        operations_table.len(),
        11,
        "Gmail manifest should declare 11 operations (matching the connector's \
         dispatch surface in connectors/gmail/src/connector.rs, which now \
         includes gmail.trash_message); see \
         gmail_manifest_matches_connector_dispatch_surface for the drift check"
    );

    let expected_hosts = vec![
        "gmail.googleapis.com".to_string(),
        "www.googleapis.com".to_string(),
    ];

    for operation_name in operations_table.keys() {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow gmail.googleapis.com and www.googleapis.com"
        );

        // Allowed hosts
        assert!(
            host_allowed("gmail.googleapis.com", &host_allow),
            "gmail.googleapis.com should be allowed for {operation_name}"
        );
        assert!(
            host_allowed("www.googleapis.com", &host_allow),
            "www.googleapis.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("googleapis.com", &host_allow),
            "googleapis.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.gmail.googleapis.com", &host_allow),
            "evil.gmail.googleapis.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("mail.google.com", &host_allow),
            "mail.google.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("accounts.google.com", &host_allow),
            "accounts.google.com should be denied for {operation_name}"
        );
    }
}

/// Drift guard: the Gmail manifest's declared operation set must match the
/// connector's introspect surface (which is the authoritative source for
/// what `handle_invoke` will actually dispatch).
///
/// This catches the class of bug reported in flywheel_connectors-aoqb2,
/// where the manifest declared 8 operations but the connector dispatched
/// 10 — a mismatch that let the compliance suite pass while the shipped
/// contract was stale. Any future divergence (either direction) will
/// fail this test with a clear message identifying the drifted ids.
#[fcp_async_core::runtime::test]
async fn gmail_manifest_matches_connector_dispatch_surface() {
    use std::collections::BTreeSet;

    let manifest = gmail_manifest_toml();
    let manifest_ops: BTreeSet<String> = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("provides.operations table")
        .keys()
        .cloned()
        .collect();

    let connector = fcp_gmail::connector::GmailConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("handle_introspect should succeed on unconfigured connector");
    let connector_ops: BTreeSet<String> = introspection["operations"]
        .as_array()
        .expect("introspection.operations array")
        .iter()
        .map(|op| {
            op["id"]
                .as_str()
                .expect("operation.id is a string")
                .to_string()
        })
        .collect();

    let missing_from_manifest: Vec<&String> = connector_ops.difference(&manifest_ops).collect();
    let missing_from_connector: Vec<&String> = manifest_ops.difference(&connector_ops).collect();

    assert!(
        missing_from_manifest.is_empty() && missing_from_connector.is_empty(),
        "gmail manifest/connector drift detected:\n  \
         connector dispatches but manifest omits: {missing_from_manifest:?}\n  \
         manifest declares but connector omits: {missing_from_connector:?}"
    );
}
