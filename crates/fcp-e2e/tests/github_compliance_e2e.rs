//! E2E GitHub connector compliance tests (flywheel_connectors-s73.7).
//!
//! Exercises the GitHub connector through the E2E compliance harness:
//! - Default deny (missing capability -> error + decision receipt)
//! - Allow with valid token (happy path invoke via mock API)
//! - Network guard allow/deny (manifest `host_allow` exact-host validation)
//!
//! All tests are deterministic -- no real API calls.
//! Run: `cargo test --package fcp-e2e --features github`

#![cfg(feature = "github")]
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

use fcp_github::connector::GitHubConnector;

// ============================================================================
// FcpConnector adapter for GitHubConnector
// ============================================================================

struct GitHubConnectorAdapter {
    connector: GitHubConnector,
    id: ConnectorId,
}

impl GitHubConnectorAdapter {
    fn new() -> Self {
        Self {
            connector: GitHubConnector::new(),
            id: ConnectorId::from_static("fcp.github"),
        }
    }
}

fcp_core::impl_fcp_sealed!(GitHubConnectorAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GitHubConnectorAdapter {
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
    instance_id: &str,
    capability: &str,
    operations: &[&str],
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
        // dja9u typestate ratchet: the GitHub connector verifies with
        // `verify_bound`, which requires an INSTANCE_ID claim; bind to the
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
        id: RequestId::from("github-e2e"),
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

fn github_manifest_toml() -> toml::Value {
    toml::from_str(include_str!("../../../connectors/github/manifest.toml"))
        .expect("github manifest toml")
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

/// GitHub `get_repo` success response.
fn github_get_repo_success_response() -> serde_json::Value {
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
// Test 1: Default deny -- compliance suite
// ============================================================================

/// Default deny: invoke without matching capability triggers error.
/// Token grants "github.write" but invoke targets "github.get_repo"
/// (which requires "github.read").
#[fcp_async_core::runtime::test]
async fn github_default_deny_compliance_suite_passes() {
    let mock = MockApiServer::start().await;
    let mut connector = GitHubConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["github.write"]);
    // Token grants "github.write" but invoke targets "github.get_repo" → denial
    let token = build_token(
        &signing_key,
        connector.connector.instance_id().as_str(),
        "github.write",
        &["github.get_repo"],
    );
    let invoke = invoke_request(
        "github.get_repo",
        json!({ "owner": "octocat", "repo": "hello-world" }),
        token,
    );

    let dynamic = DynamicSuite {
        // Secretless ratchet (e99o6): the GitHub connector rejects raw
        // `token` config; use the sanctioned credential_id reference shape.
        config: json!({
            "credential_id": "550e8400-e29b-41d4-a716-446655440000",
            "base_url": mock.base_url()
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
        "github_default_deny",
        reference_manifest_with_hash(),
        dynamic,
    );

    let mut runner = E2eRunner::new("fcp-e2e-github");
    let report = runner
        .run_compliance_suite(&mut connector, suite)
        .await
        .expect("compliance suite run");

    assert!(report.passed, "default deny compliance should pass");

    // Bind the denial token to the negotiated instance so stale authority cannot explain it.
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
    mock.assert_request_count(0).await;
}

// ============================================================================
// Test 2: Allow with valid token -- connector suite
// ============================================================================

/// Allow: invoke with valid capability token succeeds against mock API.
#[fcp_async_core::runtime::test]
async fn github_allow_valid_token_connector_suite_passes() {
    let mock = MockApiServer::start().await;

    // Mount mock for the repos/{owner}/{repo} endpoint (GET)
    Mock::given(method("GET"))
        .and(path("/repos/octocat/hello-world"))
        .respond_with(ResponseTemplate::new(200).set_body_json(github_get_repo_success_response()))
        .mount(mock.inner())
        .await;

    let mut connector = GitHubConnectorAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes(), &["github.read"]);
    let suite = ConnectorSuite {
        test_name: "github_allow_valid_token".to_string(),
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

    let mut runner = E2eRunner::new("fcp-e2e-github");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    assert!(report.passed, "allow suite should pass");
    assert!(connector.health().await.is_ready());

    // Configure and handshake rotate the instance; mint only after the lifecycle suite.
    let token = build_token(
        &signing_key,
        connector.connector.instance_id().as_str(),
        "github.read",
        &["github.get_repo"],
    );
    let response = connector
        .invoke(invoke_request(
            "github.get_repo",
            json!({ "owner": "octocat", "repo": "hello-world" }),
            token,
        ))
        .await
        .expect("invoke with current-instance authority");
    assert_eq!(response.status, InvokeStatus::Ok);
    assert_eq!(
        response.result.expect("repository output")["repository"]["full_name"],
        "octocat/Hello-World"
    );
    mock.assert_request_count(1).await;
    let received = mock.received_requests().await;
    let repo_request = received
        .iter()
        .find(|request| request.method.as_str() == "GET")
        .expect("expected GET request");
    assert_eq!(repo_request.url.path(), "/repos/octocat/hello-world");
}

// ============================================================================
// Test 3: Network guard -- manifest host_allow exact-host validation
// ============================================================================

/// Network guard: GitHub manifest restricts all operations to `api.github.com`.
/// Verify that the allowed host passes and non-matching hosts are denied.
#[test]
fn github_manifest_network_guard_allows_and_denies() {
    let manifest = github_manifest_toml();

    let operations = [
        "github.create_issue",
        "github.get_issue",
        "github.search_issues",
        "github.create_pull_request",
        "github.get_pull_request",
        "github.merge_pull_request",
        "github.get_repo",
        "github.search_repos",
        "github.list_workflows",
        "github.trigger_workflow",
        "github.get_file_content",
        "github.search_code",
    ];

    let expected_hosts = vec!["api.github.com".to_string()];

    for operation_name in operations {
        let host_allow = operation_host_allow_list(&manifest, operation_name);
        assert_eq!(
            host_allow, expected_hosts,
            "operation {operation_name} should allow only api.github.com"
        );

        // Allowed host
        assert!(
            host_allowed("api.github.com", &host_allow),
            "api.github.com should be allowed for {operation_name}"
        );

        // Denied hosts
        assert!(
            !host_allowed("github.com", &host_allow),
            "github.com (bare domain) should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("example.com", &host_allow),
            "example.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("evil.api.github.com", &host_allow),
            "evil.api.github.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("api.gitlab.com", &host_allow),
            "api.gitlab.com should be denied for {operation_name}"
        );
        assert!(
            !host_allowed("raw.githubusercontent.com", &host_allow),
            "raw.githubusercontent.com should be denied for {operation_name}"
        );
    }
}
