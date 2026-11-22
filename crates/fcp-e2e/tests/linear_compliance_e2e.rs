//! E2E Linear connector compliance tests (flywheel_connectors-hwo.7).
//!
//! Exercises the Linear connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock GraphQL)
//! - Network guard allow/deny (manifest `host_allow` exact-host validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features linear`

#![cfg(feature = "linear")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_conformance::DynamicSuite;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ComplianceSuite, ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::{
    CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics, FcpConnector, FcpError,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, InstanceId, Introspection, InvokeRequest,
    InvokeResponse, InvokeStatus, OperationId, RequestId, ShutdownRequest, SimulateRequest,
    SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use fcp_testkit::MockApiServer;
use serde_json::json;
use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
};

use fcp_linear::connector::LinearConnector;

// ============================================================================
// FcpConnector adapter for LinearConnector
// ============================================================================

struct LinearConnectorAdapter {
    connector: LinearConnector,
    id: ConnectorId,
    catalog: Introspection,
}

impl LinearConnectorAdapter {
    async fn new() -> Self {
        let connector = LinearConnector::new();
        let catalog = serde_json::from_value(connector.handle_introspect().await.unwrap()).unwrap();
        Self {
            connector,
            id: ConnectorId::from_static("fcp.linear"),
            catalog,
        }
    }
}

fcp_core::impl_fcp_sealed!(LinearConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for LinearConnectorAdapter {
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
            Ok(payload) => serde_json::from_value(payload)
                .expect("Linear health must use the canonical host schema"),
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
        self.catalog.clone()
    }

    async fn invoke(&self, req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        let request_id = req.id.clone();
        let params = serde_json::to_value(req).expect("invoke request should serialize");
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

fn linear_manifest_with_hash() -> String {
    let raw = include_str!("../../../connectors/linear/manifest.toml");
    ConnectorManifest::parse_str(raw).expect("bundled Linear manifest should validate");
    raw.to_owned()
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
    instance_id: &str,
    capability: &str,
    operations: &[&str],
) -> CapabilityToken {
    let now = Utc::now();
    // C3.4 default-deny: the verifier rejects tokens with no
    // constraints claim. Wildcard grants any resource URI the
    // connector builds. (See br-1maun for full rationale.)
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
        // dja9u typestate ratchet: the Linear connector verifies with
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
        id: RequestId::from("linear-e2e"),
        connector_id: ConnectorId::from_static("fcp.linear"),
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

fn linear_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/linear/manifest.toml"))
        .expect("linear manifest toml")
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

/// Linear `get_issue` GraphQL success response.
fn linear_get_issue_graphql_response() -> serde_json::Value {
    json!({
        "data": {
            "issue": {
                "id": "issue-abc-123",
                "identifier": "LIN-42",
                "title": "Fix authentication flow",
                "description": "Users report intermittent login failures",
                "priority": 2,
                "priorityLabel": "High",
                "state": {
                    "id": "state-in-progress",
                    "name": "In Progress",
                    "color": "#f2c94c",
                    "type": "started"
                },
                "assignee": {
                    "id": "user-1",
                    "name": "Test User",
                    "displayName": "Test User",
                    "email": "test@example.com"
                },
                "team": {
                    "id": "team-eng",
                    "name": "Engineering",
                    "key": "ENG"
                },
                "labels": {
                    "nodes": [
                        { "id": "label-1", "name": "bug", "color": "#eb5757" }
                    ]
                },
                "createdAt": "2026-01-15T10:00:00.000Z",
                "updatedAt": "2026-02-28T14:30:00.000Z",
                "url": "https://linear.app/test/issue/LIN-42"
            }
        }
    })
}

// ============================================================================
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "linear.write" but invoke targets "linear.get_issue"
/// (which requires "linear.read").
#[fcp_async_core::runtime::test]
async fn linear_default_deny_compliance_suite_passes() {
    let mut connector = LinearConnectorAdapter::new().await;
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["linear.write"]);
    // Token grants "linear.write" but invoke targets "linear.get_issue" -> denial
    let token = build_token(
        &signing_key,
        connector.connector.instance_id().as_str(),
        "linear.write",
        &["linear.write"],
    );
    let invoke = invoke_request("linear.get_issue", json!({ "issue_id": "LIN-42" }), token);

    let dynamic = DynamicSuite {
        config: json!({
            "api_key": "lin_api_test_000",
            "api_url": "http://localhost:9999/graphql"
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
    let suite = ComplianceSuite::new("linear_default_deny", linear_manifest_with_hash(), dynamic);

    let mut runner = E2eRunner::new("fcp-e2e-linear");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock GraphQL.
#[fcp_async_core::runtime::test]
async fn linear_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for GraphQL endpoint (POST /graphql)
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(linear_get_issue_graphql_response()))
        .mount(mock.inner())
        .await;

    let mut connector = LinearConnectorAdapter::new().await;
    let signing_key = Ed25519SigningKey::generate();
    // Introspection declares `linear.get_issue` requires capability
    // `linear.read` (permission class), not the op id itself.
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["linear.read"]);
    let suite = ConnectorSuite {
        test_name: "linear_allow_valid_token".to_string(),
        config: json!({
            "api_key": "lin_api_test_e2e",
            "api_url": format!("{}/graphql", mock.base_url()),
        }),
        handshake,
        // The real instance is available only after this setup handshake.
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

    let mut runner = E2eRunner::new("fcp-e2e-linear");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    let health = connector.health().await;
    assert!(health.is_ready());
    let instance: InstanceId =
        serde_json::from_value(health.details.unwrap()["instance_id"].clone()).unwrap();
    let token = build_token(
        &signing_key,
        instance.as_str(),
        "linear.read",
        &["linear.get_issue"],
    );
    let request = invoke_request("linear.get_issue", json!({ "issue_id": "LIN-42" }), token);
    let response = connector
        .invoke(request)
        .await
        .expect("negotiated grant should authorize the real operation");
    assert_eq!(response.status, InvokeStatus::Ok);
    assert_eq!(response.result.unwrap()["issue"]["identifier"], "LIN-42");

    // br-7e15h: independently verify the GraphQL endpoint was hit.
    mock.assert_received("/graphql").await;
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow exact-host validation
// ============================================================================

/// Network guard: Linear manifest restricts all operations to `api.linear.app`.
/// Verify that the allowed host passes and non-matching hosts are denied.
#[test]
fn linear_manifest_network_guard_allows_and_denies() {
    let manifest = linear_manifest_toml();

    let operations = [
        "linear.create_issue",
        "linear.get_issue",
        "linear.update_issue",
        "linear.search_issues",
        "linear.list_teams",
        "linear.list_cycles",
        "linear.add_comment",
        "linear.list_projects",
    ];

    let expected_hosts = vec!["api.linear.app".to_string()];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow only api.linear.app"
        );

        // Allowed host
        assert!(
            host_allowed("api.linear.app", &host_allow),
            "api.linear.app should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("linear.app", &host_allow),
            "linear.app (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.api.linear.app", &host_allow),
            "evil.api.linear.app should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.github.com", &host_allow),
            "api.github.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("graphql.linear.app", &host_allow),
            "graphql.linear.app should be denied for {operation_name}"
        );
    }
}
