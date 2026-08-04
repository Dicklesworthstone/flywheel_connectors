//! E2E Google Calendar connector compliance tests.
//!
//! Exercises the Google Calendar connector through the shared E2E harness:
//! - Default deny behavior for capability mismatch
//! - Allow path with valid capability token
//! - Network guard allow/deny checks via manifest constraints
//!
//! All tests are deterministic with mock servers only.
//! Run: `cargo test --package fcp-e2e --features google_calendar`

#![cfg(feature = "google_calendar")]
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
    matchers::{method, path_regex},
};

use fcp_google_calendar::connector::GoogleCalendarConnector;

// ============================================================================
// FcpConnector adapter for GoogleCalendarConnector
// ============================================================================

struct GoogleCalendarConnectorAdapter {
    connector: GoogleCalendarConnector,
    id: ConnectorId,
}

impl GoogleCalendarConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: GoogleCalendarConnector::new(),
            id: ConnectorId::from_static("google-calendar"),
        }
    }
}

fcp_core::impl_fcp_sealed!(GoogleCalendarConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GoogleCalendarConnectorAdapter {
    fn id(&self) -> &ConnectorId {
        &self.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> fcp_core::FcpResult<()> {
        self.connector.handle_configure(config).await.map(|_| ())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> fcp_core::FcpResult<HandshakeResponse> {
        let request = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
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
                    other => HealthSnapshot::degraded(format!("gcal_status:{other}")),
                }
            }
            Err(err) => HealthSnapshot::error(err.to_string()),
        }
    }

    async fn self_check(&self) -> fcp_core::FcpResult<fcp_core::SelfCheckReport> {
        let value = self.connector.handle_self_check().await?;
        serde_json::from_value(value).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize Google Calendar self_check: {err}"),
        })
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
                id: OperationId::from_static("gcal.get_event"),
                summary: "Get a calendar event by ID".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["calendar_id", "event_id"],
                    "properties": {
                        "calendar_id": { "type": "string" },
                        "event_id": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "event": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("gcal.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Get details about a specific calendar event.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![
                        r#"{"calendar_id": "primary", "event_id": "abc123"}"#.to_string(),
                    ],
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
        let request = serde_json::to_value(&req).map_err(|err| FcpError::Internal {
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

fn gcal_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/google-calendar/manifest.toml");
    let unchecked = ConnectorManifest::parse_str_unchecked(raw).expect("unchecked manifest parse");
    let computed = unchecked
        .compute_interface_hash()
        .expect("compute interface hash");
    raw.replace(
        &unchecked.manifest.interface_hash.to_string(),
        &computed.to_string(),
    )
}

fn gcal_manifest_toml() -> toml::Value {
    toml::from_str(include_str!(
        "../../../connectors/google-calendar/manifest.toml"
    ))
    .expect("google-calendar manifest TOML")
}

fn gcal_config(base_url: &str) -> serde_json::Value {
    json!({
        "token": "ya29_test_e2e",
        "base_url": base_url,
    })
}

fn handshake_request(
    host_public_key: [u8; 32],
    capabilities: &[&str],
    instance_id: InstanceId,
) -> HandshakeRequest {
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
        // The connector honors requested_instance_id and verifies with
        // verify_bound; pin it to the test instance so the token's INSTANCE_ID
        // claim matches (instance-binding pattern, commit 16171621d).
        requested_instance_id: Some(instance_id),
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
    let resolved_capability = match capability {
        "gcal.get_event" => "gcal.read",
        _ => capability,
    };
    let cose = CapabilityTokenBuilder::new()
        .capability_id(resolved_capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        // dja9u typestate ratchet: connector verifies with verify_bound, which
        // requires an INSTANCE_ID claim; bind to the test instance
        // (instance-binding pattern, commit 16171621d).
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
        id: RequestId::from("gcal-e2e"),
        connector_id: ConnectorId::from_static("google-calendar"),
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

fn operation_network_constraints<'a>(
    manifest: &'a toml::Value,
    operation_name: &str,
) -> &'a toml::value::Table {
    manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .and_then(|operations| operations.get(operation_name))
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .expect("operation network_constraints")
}

fn operation_host_allow_list(manifest: &toml::Value, operation_name: &str) -> Vec<String> {
    operation_network_constraints(manifest, operation_name)
        .get("host_allow")
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

/// Google Calendar get_event API success response.
fn gcal_get_event_response() -> serde_json::Value {
    json!({
        "kind": "calendar#event",
        "etag": "\"abc123\"",
        "id": "event_e2e_123",
        "status": "confirmed",
        "htmlLink": "https://www.google.com/calendar/event?eid=abc",
        "created": "2026-02-28T10:00:00.000Z",
        "updated": "2026-02-28T14:00:00.000Z",
        "summary": "E2E Test Meeting",
        "description": "A test calendar event",
        "creator": {
            "email": "test@example.com",
            "self": true
        },
        "organizer": {
            "email": "test@example.com",
            "self": true
        },
        "start": {
            "dateTime": "2026-03-01T10:00:00-05:00",
            "timeZone": "America/New_York"
        },
        "end": {
            "dateTime": "2026-03-01T11:00:00-05:00",
            "timeZone": "America/New_York"
        },
        "iCalUID": "event_e2e_123@google.com",
        "sequence": 0,
        "attendees": [{
            "email": "attendee@example.com",
            "responseStatus": "accepted"
        }],
        "reminders": {
            "useDefault": true
        }
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "gcal.write" but invoke targets "gcal.get_event"
/// (which requires "gcal.read").
#[fcp_async_core::runtime::test]
async fn gcal_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;

    let mut connector = GoogleCalendarConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["gcal.write"],
        instance_id.clone(),
    );
    // Token grants "gcal.write" but invoke targets "gcal.get_event" -> denial
    let token = build_token(
        &signing_key,
        instance_id.as_str(),
        "gcal.write",
        &["gcal.write"],
    );
    let invoke = invoke_request(
        "gcal.get_event",
        json!({ "calendar_id": "primary", "event_id": "event_e2e_123" }),
        token,
    );

    let dynamic = DynamicSuite {
        config: gcal_config(&mock.base_url()),
        handshake,
        invoke: Some(invoke),
        expect_invoke_error: true,
        simulate: None,
        expect_simulate_would_succeed: None,
        require_simulate_denial_details: false,
        require_capability_denial: true,
        require_decision_receipt: false,
    };
    let suite = ComplianceSuite::new("gcal_default_deny", gcal_manifest_with_hash(), dynamic);

    let mut runner = E2eRunner::new("fcp-e2e-gcal");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(
        report.passed,
        "default deny compliance should pass: {report:#?}"
    );
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock REST API.
#[fcp_async_core::runtime::test]
async fn gcal_happy_path_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GET /calendars/{calId}/events/{eventId}
    Mock::given(method("GET"))
        .and(path_regex(r"^/calendars/.+/events/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(gcal_get_event_response()))
        .mount(mock.inner())
        .await;

    let mut connector = GoogleCalendarConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["gcal.read"],
        instance_id.clone(),
    );
    let token = build_token(
        &signing_key,
        instance_id.as_str(),
        "gcal.read",
        &["gcal.get_event"],
    );
    let invoke = invoke_request(
        "gcal.get_event",
        json!({ "calendar_id": "primary", "event_id": "event_e2e_123" }),
        token,
    );

    let suite = ConnectorSuite {
        test_name: "gcal_happy_path".to_string(),
        config: gcal_config(&mock.base_url()),
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

    let mut runner = E2eRunner::new("fcp-e2e-gcal-happy");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "happy path should pass: {report:#?}");
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
    let received = mock.received_requests().await;
    assert_eq!(
        received.len(),
        1,
        "expected exactly one Google Calendar API request"
    );
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow exact-host validation
// ============================================================================

/// Network guard: Google Calendar manifest restricts all operations to
/// `www.googleapis.com`. Verify that the allowed host passes and
/// non-matching hosts are denied.
#[test]
fn gcal_manifest_network_guard_allows_and_denies() {
    let manifest = gcal_manifest_toml();
    let operations = manifest
        .get("provides")
        .and_then(toml::Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table");

    assert_eq!(
        operations.len(),
        11,
        "Google Calendar manifest should declare 11 operations"
    );

    let expected_hosts = vec!["www.googleapis.com".to_string()];

    for operation_name in operations.keys() {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow only www.googleapis.com"
        );

        // Allowed host
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
            !host_allowed("evil.www.googleapis.com", &host_allow),
            "evil.www.googleapis.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("calendar.google.com", &host_allow),
            "calendar.google.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("127.0.0.1", &host_allow),
            "127.0.0.1 should be denied for {operation_name}"
        );

        let constraints = operation_network_constraints(&manifest, operation_name);
        assert_eq!(
            constraints
                .get("deny_localhost")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must deny localhost"
        );
        assert_eq!(
            constraints
                .get("deny_private_ranges")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must deny private ranges"
        );
        assert_eq!(
            constraints
                .get("require_sni")
                .and_then(toml::Value::as_bool),
            Some(true),
            "operation {operation_name} must require SNI"
        );
    }
}
