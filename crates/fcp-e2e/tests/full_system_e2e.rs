//! Full-system E2E test suite for the FCP connector lifecycle.
//!
//! Exercises the GitHub connector through configure, handshake, introspection,
//! invoke (with wiremock), capability rejection, error mapping, and evidence
//! bundle assembly.  All tests are deterministic -- no real API calls.
//!
//! Run: `cargo test --package fcp-e2e --features e2e-full,github --test full_system_e2e`

#![cfg(feature = "e2e-full")]
#![allow(clippy::too_many_lines)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::evidence::{
    EvidenceBundle, EvidenceItem, EvidenceLayer, ScenarioEnvironment, ScenarioOutcome,
    StepAssertion, StepKind, VERIFICATION_BUNDLE_SCHEMA_VERSION,
};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_github::connector::GitHubConnector;
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

// ============================================================================
// FcpConnector adapter (mirrors github_compliance_e2e.rs)
// ============================================================================

struct GitHubAdapter {
    connector: GitHubConnector,
    id: ConnectorId,
}

impl GitHubAdapter {
    fn new() -> Self {
        Self {
            connector: GitHubConnector::new(),
            id: ConnectorId::from_static("fcp.github"),
        }
    }
}

fcp_core::impl_fcp_sealed!(GitHubAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GitHubAdapter {
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
                .unwrap_or_else(|err| HealthSnapshot::error(err.to_string())),
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
                id: OperationId::from_static("github.get_repo"),
                summary: "Get repository metadata".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["owner", "repo"],
                    "properties": {
                        "owner": { "type": "string" },
                        "repo": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "required": ["repository"],
                    "properties": {
                        "repository": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static("github.read"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Retrieve metadata about a repository.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"owner": "octocat", "repo": "hello-world"}"#.to_string()],
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
        let params = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize invoke request: {err}"),
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
    let constraints = fcp_core::CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).expect("serialize test constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability)
        .zone_id("z:work")
        .principal("user:test")
        .operations(operations)
        // dja9u typestate ratchet: the GitHub connector verifies with
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
        id: RequestId::from("full-system-e2e"),
        connector_id: ConnectorId::from_static("fcp.github"),
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

fn github_get_repo_response() -> serde_json::Value {
    json!({
        "id": 1296269,
        "node_id": "MDEwOlJlcG9zaXRvcnkxMjk2MjY5",
        "name": "Hello-World",
        "full_name": "octocat/Hello-World",
        "owner": {
            "login": "octocat",
            "id": 1,
            "type": "User"
        },
        "private": false,
        "html_url": "https://github.com/octocat/Hello-World",
        "description": "This your first repo!",
        "fork": false,
        "default_branch": "main",
        "visibility": "public",
        "created_at": "2011-01-26T19:01:12Z",
        "updated_at": "2024-01-01T00:00:00Z",
        "pushed_at": "2024-01-01T00:00:00Z",
        "stargazers_count": 80,
        "watchers_count": 80,
        "forks_count": 9,
        "open_issues_count": 0,
        "language": "Rust"
    })
}

// ============================================================================
// Test 1: Configure + handshake lifecycle
// ============================================================================

/// Configure the connector and perform a handshake, verifying success.
#[fcp_async_core::runtime::test]
async fn e2e_connector_configure_and_handshake() {
    let mock = MockApiServer::start().await;
    let mut connector = GitHubAdapter::new();

    // Configure with mock base URL
    let config_result = connector
        .configure(json!({
            // Secretless ratchet (e99o6): GitHub rejects raw `token`; use the
            // sanctioned credential_id reference shape.
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": mock.base_url(),
        }))
        .await;
    assert!(
        config_result.is_ok(),
        "configure should succeed: {config_result:?}"
    );

    // Handshake
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["github.read"]);
    let handshake_result = connector.handshake(handshake).await;
    assert!(
        handshake_result.is_ok(),
        "handshake should succeed: {handshake_result:?}"
    );

    // Health after configure+handshake should be ready
    let health = connector.health().await;
    assert!(
        health.is_ready(),
        "health should be ready after configure+handshake, got: {health:?}"
    );
}

// ============================================================================
// Test 2: Introspect operations
// ============================================================================

/// Verify that introspection returns the expected set of operations with
/// correct metadata (id, capability, risk level, safety tier, schemas).
#[fcp_async_core::runtime::test]
async fn e2e_connector_introspect_operations() {
    let mock = MockApiServer::start().await;
    let mut connector = GitHubAdapter::new();

    connector
        .configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": mock.base_url(),
        }))
        .await
        .expect("configure");

    let introspection = connector.introspect();

    // Must have at least one operation
    assert!(
        !introspection.operations.is_empty(),
        "introspection should expose at least one operation"
    );

    // Verify the get_repo operation
    let get_repo = introspection
        .operations
        .iter()
        .find(|op| op.id.as_str() == "github.get_repo")
        .expect("github.get_repo operation should be present");

    assert_eq!(get_repo.capability.as_str(), "github.read");
    assert_eq!(get_repo.risk_level, RiskLevel::Low);
    assert_eq!(get_repo.safety_tier, SafetyTier::Safe);
    assert_eq!(get_repo.idempotency, IdempotencyClass::Strict);

    // Input schema must require owner and repo
    let required = get_repo.input_schema["required"]
        .as_array()
        .expect("input schema requires array");
    let required_fields: Vec<&str> = required
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        required_fields.contains(&"owner"),
        "input schema should require 'owner'"
    );
    assert!(
        required_fields.contains(&"repo"),
        "input schema should require 'repo'"
    );

    // Output schema must declare a repository field
    assert!(
        get_repo.output_schema["properties"]["repository"].is_object(),
        "output schema should have a repository property"
    );

    // AI hints must be non-empty
    assert!(
        !get_repo.ai_hints.when_to_use.is_empty(),
        "when_to_use hint should not be empty"
    );
}

// ============================================================================
// Test 3: Invoke with wiremock
// ============================================================================

/// Invoke get_repo against a wiremock-backed API and verify the response shape.
#[fcp_async_core::runtime::test]
async fn e2e_connector_invoke_with_mock() {
    let mock = MockApiServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(github_get_repo_response()))
        .mount(mock.inner())
        .await;

    let mut connector = GitHubAdapter::new();
    let signing_key = Ed25519SigningKey::generate();

    connector
        .configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": mock.base_url(),
        }))
        .await
        .expect("configure");

    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["github.read"]);
    connector.handshake(handshake).await.expect("handshake");

    let token = build_token(
        &signing_key,
        connector.connector.instance_id().as_str(),
        "github.read",
        &["github.get_repo"],
    );
    let invoke = invoke_request(
        "github.get_repo",
        json!({ "owner": "octocat", "repo": "hello-world" }),
        token,
    );

    let response = connector
        .invoke(invoke)
        .await
        .expect("invoke should succeed");
    assert_eq!(
        response.status,
        InvokeStatus::Ok,
        "invoke status should be Ok"
    );

    // The response result should contain the repo information
    let result = response
        .result
        .as_ref()
        .expect("result should be present on Ok response");
    let result_str = serde_json::to_string(result).unwrap_or_default();
    assert!(
        result_str.contains("Hello-World") || result_str.contains("hello-world"),
        "response result should reference the repository, got: {result_str}"
    );

    // Verify through the E2E runner harness as well
    let signing_key2 = Ed25519SigningKey::generate();
    let mut connector2 = GitHubAdapter::new();
    let handshake2 = handshake_request(signing_key2.verifying_key().to_bytes(), &["github.read"]);

    let suite = ConnectorSuite {
        test_name: "full_e2e_invoke_mock".to_string(),
        config: json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": mock.base_url(),
        }),
        handshake: handshake2,
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

    let mut runner = E2eRunner::new("fcp-e2e-full-system");
    let report = runner
        .run_connector_suite(&mut connector2, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "report should contain log entries");
    assert!(connector2.health().await.is_ready());

    // Sign after the runner establishes the new session and its instance.
    let token2 = build_token(
        &signing_key2,
        connector2.connector.instance_id().as_str(),
        "github.read",
        &["github.get_repo"],
    );
    let response2 = connector2
        .invoke(invoke_request(
            "github.get_repo",
            json!({ "owner": "octocat", "repo": "hello-world" }),
            token2,
        ))
        .await
        .expect("invoke after lifecycle suite");
    assert_eq!(response2.status, InvokeStatus::Ok);
    assert_eq!(
        response2.result.expect("repository output")["repository"]["full_name"],
        "octocat/Hello-World"
    );
    mock.assert_request_count(2).await;
}

// ============================================================================
// Test 4: Capability verification (invalid token rejected)
// ============================================================================

/// An invoke with a capability token that does not match the required capability
/// should be rejected by the connector or produce an error.
#[fcp_async_core::runtime::test]
async fn e2e_capability_verification() {
    let mock = MockApiServer::start().await;
    let mut connector = GitHubAdapter::new();
    let signing_key = Ed25519SigningKey::generate();

    connector
        .configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": mock.base_url(),
        }))
        .await
        .expect("configure");

    // Handshake with github.write capability (NOT github.read/github.get_repo)
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["github.write"]);
    connector.handshake(handshake).await.expect("handshake");

    // The token is valid for the current instance; the missing read grant causes denial.
    let token = build_token(
        &signing_key,
        connector.connector.instance_id().as_str(),
        "github.write",
        &["github.get_repo"],
    );
    let err = connector
        .invoke(invoke_request(
            "github.get_repo",
            json!({ "owner": "octocat", "repo": "hello-world" }),
            token,
        ))
        .await
        .expect_err("unnegotiated read capability should be denied");
    assert!(matches!(
        &err,
        FcpError::CapabilityDenied { capability, .. } if capability == "github.read"
    ));
    assert_eq!(err.error_code(), "FCP-3001");

    // Run through the E2E runner expecting an error
    let mut connector2 = GitHubAdapter::new();
    let signing_key2 = Ed25519SigningKey::generate();
    let handshake2 = handshake_request(signing_key2.verifying_key().to_bytes(), &["github.write"]);
    let token2 = build_token(
        &signing_key2,
        connector2.connector.instance_id().as_str(),
        "github.write",
        &["github.get_repo"],
    );
    let invoke2 = invoke_request(
        "github.get_repo",
        json!({ "owner": "octocat", "repo": "hello-world" }),
        token2,
    );

    let suite = ConnectorSuite {
        test_name: "full_e2e_capability_rejection".to_string(),
        config: json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": mock.base_url(),
        }),
        handshake: handshake2,
        invoke: Some(invoke2),
        invoke_expectations: InvokeExpectations {
            expect_error: true,
            expect_decision_receipt: false,
            expect_audit_event: false,
            expect_receipt: false,
            expected_reason_code: Some("FCP-3001".to_string()),
            rate_limit_pool: None,
        },
    };

    let mut runner = E2eRunner::new("fcp-e2e-full-system");
    let report = runner
        .run_connector_suite(&mut connector2, suite)
        .await
        .expect("suite should run");

    // The suite should pass because we expected an error and got one
    assert!(
        report.passed,
        "suite expecting error on capability mismatch should pass"
    );
    let execute_entry = report
        .logs
        .iter()
        .find(|entry| entry.phase == "execute")
        .expect("execute log entry");
    assert_eq!(
        execute_entry.context.get("reason_code"),
        Some(&json!("FCP-3001"))
    );
    mock.assert_request_count(0).await;
}

// ============================================================================
// Test 5: Error mapping -- structured FcpError from API error
// ============================================================================

/// Verify that a GitHub API 404 maps to a structured FcpError with the correct
/// variant and fields.
#[fcp_async_core::runtime::test]
async fn e2e_error_mapping_structured() {
    let mock = MockApiServer::start().await;

    // Mount 404 response for the repo endpoint
    Mock::given(method("GET"))
        .and(path("/repos/octocat/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "Not Found",
            "documentation_url": "https://docs.github.com/rest/repos/repos#get-a-repository"
        })))
        .mount(mock.inner())
        .await;

    let mut connector = GitHubAdapter::new();
    let signing_key = Ed25519SigningKey::generate();

    connector
        .configure(json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": mock.base_url(),
        }))
        .await
        .expect("configure");

    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["github.read"]);
    connector.handshake(handshake).await.expect("handshake");

    let token = build_token(
        &signing_key,
        connector.connector.instance_id().as_str(),
        "github.read",
        &["github.get_repo"],
    );
    let invoke = invoke_request(
        "github.get_repo",
        json!({ "owner": "octocat", "repo": "nonexistent" }),
        token,
    );

    let result = connector.invoke(invoke).await;
    assert!(result.is_err(), "invoke for nonexistent repo should fail");

    let err = result.unwrap_err();

    // The error should be one of the structured FcpError variants -- not a
    // generic internal error.  The GitHub connector maps 404 to either
    // ResourceNotFound or External depending on the path, both are acceptable.
    let is_structured = matches!(
        err,
        FcpError::ResourceNotFound { .. }
            | FcpError::External {
                status_code: Some(404),
                ..
            }
    );
    assert!(
        is_structured,
        "404 should map to ResourceNotFound or External(404), got: {err:?}"
    );

    // Verify error Display produces meaningful output
    let display = err.to_string();
    assert!(
        !display.is_empty(),
        "error Display should produce non-empty output"
    );
    mock.assert_request_count(1).await;
}

// ============================================================================
// Test 6: Evidence bundle assembly
// ============================================================================

/// Build a scenario script, run assertions, assemble an evidence bundle, and
/// verify it contains the required structural fields (schema version, scenario
/// id, artifact paths, steps, outcome, redacted fields, commands).
#[test]
fn e2e_evidence_bundle_assembly() {
    use fcp_e2e::evidence::{
        add_step, bundle_evidence, canonical_e2e_artifact_paths, finalize_scenario, new_scenario,
    };

    // ── Step 1: Build scenario script ──────────────────────────────────
    let mut script = new_scenario("full_system_evidence_test", ScenarioEnvironment::Local);
    script.meta.description =
        "Verify evidence bundle assembly from a multi-step scenario".to_string();
    script.meta.tags = vec!["e2e-full".to_string(), "github".to_string()];
    script.meta.author = "full_system_e2e".to_string();
    script.meta.created_at = Utc::now().to_rfc3339();

    // ── Step 2: Setup step ──────────────────────────────────────────────
    {
        let step = add_step(&mut script, StepKind::Setup, "Configure connector");
        step.correlation_id = "corr-setup-001".to_string();
        step.timestamp = Utc::now().to_rfc3339();
        step.duration_ms = Some(5);
        step.assertions.push(StepAssertion {
            description: "configure succeeds".to_string(),
            passed: true,
            expected: "Ok".to_string(),
            actual: "Ok".to_string(),
        });
        step.evidence.push(EvidenceItem::Log {
            lines: vec!["[INFO] connector configured with mock base_url".to_string()],
        });
    }

    // ── Step 3: Action step ─────────────────────────────────────────────
    {
        let step = add_step(&mut script, StepKind::Action, "Invoke github.get_repo");
        step.correlation_id = "corr-action-001".to_string();
        step.timestamp = Utc::now().to_rfc3339();
        step.duration_ms = Some(12);
        step.assertions.push(StepAssertion {
            description: "invoke returns Ok status".to_string(),
            passed: true,
            expected: "InvokeStatus::Ok".to_string(),
            actual: "InvokeStatus::Ok".to_string(),
        });
        step.evidence.push(EvidenceItem::Metric {
            name: "invoke_latency_ms".to_string(),
            value: 12.0,
            unit: "ms".to_string(),
        });
    }

    // ── Step 4: Assert step ─────────────────────────────────────────────
    {
        let step = add_step(&mut script, StepKind::Assert, "Response shape validation");
        step.correlation_id = "corr-assert-001".to_string();
        step.timestamp = Utc::now().to_rfc3339();
        step.duration_ms = Some(1);
        step.assertions.push(StepAssertion {
            description: "response contains repo name".to_string(),
            passed: true,
            expected: "Hello-World".to_string(),
            actual: "Hello-World".to_string(),
        });
        step.evidence.push(EvidenceItem::HealthSnapshot {
            component: "github-connector".to_string(),
            state: "healthy".to_string(),
        });
    }

    // ── Step 5: Teardown step ───────────────────────────────────────────
    {
        let step = add_step(&mut script, StepKind::Teardown, "Shutdown connector");
        step.correlation_id = "corr-teardown-001".to_string();
        step.timestamp = Utc::now().to_rfc3339();
        step.duration_ms = Some(2);
        step.assertions.push(StepAssertion {
            description: "shutdown completes".to_string(),
            passed: true,
            expected: "Ok".to_string(),
            actual: "Ok".to_string(),
        });
    }

    // ── Step 6: Finalize outcome ────────────────────────────────────────
    finalize_scenario(&mut script);
    assert_eq!(
        script.outcome,
        ScenarioOutcome::Pass,
        "all assertions passed so outcome should be Pass"
    );

    // ── Step 7: Bundle evidence ─────────────────────────────────────────
    let bundle = bundle_evidence(script, &["token", "api_key"]);

    // ── Verify bundle structure ─────────────────────────────────────────
    assert_eq!(
        bundle.schema_version, VERIFICATION_BUNDLE_SCHEMA_VERSION,
        "schema_version should match the constant"
    );
    assert_eq!(bundle.scenario_id, "full_system_evidence_test");
    assert_eq!(bundle.layer, EvidenceLayer::E2e);
    assert_eq!(bundle.retention_days, 90);

    // Artifact paths should contain the canonical set
    let canonical = canonical_e2e_artifact_paths();
    assert_eq!(
        bundle.artifact_paths, canonical,
        "artifact_paths should match canonical e2e artifact paths"
    );

    // Verify logs.jsonl equivalent path is present
    assert!(
        bundle.artifact_paths.contains_key("logs_jsonl"),
        "artifact_paths must include logs_jsonl"
    );
    // Verify summary.txt path
    assert!(
        bundle.artifact_paths.contains_key("summary_txt"),
        "artifact_paths must include summary_txt"
    );
    // Verify environment.json path
    assert!(
        bundle.artifact_paths.contains_key("environment_json"),
        "artifact_paths must include environment_json"
    );

    // Verify steps are preserved
    assert_eq!(bundle.script.steps.len(), 4, "bundle should have 4 steps");

    // Step kinds in order
    let kinds: Vec<StepKind> = bundle.script.steps.iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        vec![
            StepKind::Setup,
            StepKind::Action,
            StepKind::Assert,
            StepKind::Teardown,
        ]
    );

    // Total assertion count
    let total_assertions: usize = bundle.script.steps.iter().map(|s| s.assertions.len()).sum();
    assert_eq!(total_assertions, 4, "bundle should have 4 assertions total");

    // All assertions passed
    let all_passed = bundle
        .script
        .steps
        .iter()
        .flat_map(|s| &s.assertions)
        .all(|a| a.passed);
    assert!(all_passed, "all assertions in bundle should have passed");

    // Evidence items present
    let total_evidence: usize = bundle.script.steps.iter().map(|s| s.evidence.len()).sum();
    assert_eq!(
        total_evidence, 3,
        "bundle should have 3 evidence items (log, metric, health snapshot)"
    );

    // Redacted fields recorded
    assert_eq!(bundle.redacted_fields.len(), 2);
    assert!(bundle.redacted_fields.contains(&"token".to_string()));
    assert!(bundle.redacted_fields.contains(&"api_key".to_string()));

    // Commands validation field is populated
    assert!(
        !bundle.commands.validate.is_empty(),
        "commands.validate should not be empty"
    );

    // Bundle serializes to valid JSON
    let json = serde_json::to_string_pretty(&bundle).expect("bundle should serialize to JSON");
    assert!(json.contains("full_system_evidence_test"));
    assert!(json.contains("fcp-verification-bundle/v1"));
    assert!(json.contains("logs_jsonl"));

    // Round-trip: deserialize back and compare key fields
    let roundtrip: EvidenceBundle =
        serde_json::from_str(&json).expect("bundle should deserialize from JSON");
    assert_eq!(roundtrip.schema_version, bundle.schema_version);
    assert_eq!(roundtrip.scenario_id, bundle.scenario_id);
    assert_eq!(roundtrip.layer, bundle.layer);
    assert_eq!(roundtrip.script.steps.len(), bundle.script.steps.len());
    assert_eq!(roundtrip.redacted_fields, bundle.redacted_fields);
}
