use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_github::connector::GitHubConnector;
use fcp_prelude::{
    AgentHint, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo, RequestId, RiskLevel,
    SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse, SubscribeRequest,
    SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const CONNECTOR_ID: &str = "fcp.github";
const OP_GET_REPO: &str = "github.get_repo";
const CAP_READ: &str = "github.read";
const TEST_CREDENTIAL_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const OWNER: &str = "octocat";
const REPO: &str = "hello-world";

struct GitHubAdapter {
    connector: GitHubConnector,
    id: ConnectorId,
    // Only authorized provider fixtures opt into host issuance after lifecycle setup.
    // Keeping this absent preserves intentionally invalid tokens in denial tests.
    host_token_issuer: Option<Ed25519SigningKey>,
}

impl GitHubAdapter {
    fn new() -> Self {
        Self {
            connector: GitHubConnector::new(),
            id: ConnectorId::from_static(CONNECTOR_ID),
            host_token_issuer: None,
        }
    }

    fn with_host_token_issuer(signing_key: Ed25519SigningKey) -> Self {
        Self {
            host_token_issuer: Some(signing_key),
            ..Self::new()
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
        let value = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize handshake request: {err}"),
        })?;
        let response = self.connector.handle_handshake(value).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
            message: format!("failed to deserialize handshake response: {err}"),
        })
    }

    async fn health(&self) -> HealthSnapshot {
        match self.connector.handle_health().await {
            Ok(payload) => {
                serde_json::from_value::<HealthSnapshot>(payload).unwrap_or_else(|err| {
                    HealthSnapshot::error(format!("invalid GitHub health snapshot: {err}"))
                })
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
                id: OperationId::from_static(OP_GET_REPO),
                summary: "Get GitHub repository metadata".to_string(),
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
                    "properties": {
                        "repository": { "type": "object" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "Retrieve metadata for a GitHub repository.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"owner":"octocat","repo":"hello-world"}"#.to_string()],
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

    async fn invoke(&self, mut req: InvokeRequest) -> fcp_core::FcpResult<InvokeResponse> {
        if let Some(signing_key) = &self.host_token_issuer {
            // The runner constructs requests before configure/handshake. Model the real host:
            // learn the current instance from canonical health, then issue a scoped token.
            let health: HealthSnapshot =
                serde_json::from_value(self.connector.handle_health().await?).map_err(|err| {
                    FcpError::Internal {
                        message: format!("invalid GitHub health snapshot: {err}"),
                    }
                })?;
            if !health.is_ready() {
                return Err(FcpError::NotHandshaken);
            }
            let details = health.details.ok_or_else(|| FcpError::Internal {
                message: "GitHub health omitted instance details".to_string(),
            })?;
            let instance_id = details
                .get("instance_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| FcpError::Internal {
                    message: "GitHub health omitted instance_id".to_string(),
                })?;
            req.capability_token = build_token(signing_key, instance_id);
        }
        let request_id = req.id.clone();
        let request = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize invoke request: {err}"),
        })?;
        let value = self.connector.handle_invoke(request).await?;
        Ok(InvokeResponse::ok(request_id, value))
    }

    async fn simulate(&self, req: SimulateRequest) -> fcp_core::FcpResult<SimulateResponse> {
        let value = serde_json::to_value(req).map_err(|err| FcpError::Internal {
            message: format!("failed to serialize simulate request: {err}"),
        })?;
        let response = self.connector.handle_simulate(value).await?;
        serde_json::from_value(response).map_err(|err| FcpError::Internal {
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

fn handshake_request(host_public_key: [u8; 32]) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [43u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn build_token(signing_key: &Ed25519SigningKey, instance_id: &str) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec![format!("github://{OWNER}/{REPO}")],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_READ)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_GET_REPO])
        .issuer("node:test")
        .token_id(b"github-connector-suite")
        .validity(now, now + Duration::hours(1))
        .target_instance(instance_id)
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

fn get_repo_invoke(id: &'static str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::new(id),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(OP_GET_REPO),
        zone_id: ZoneId::work(),
        input: json!({
            "owner": OWNER,
            "repo": REPO
        }),
        // The opted-in test host issues this token after observing the handshaken instance.
        capability_token: CapabilityToken::from_raw(Vec::new()),
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

#[fcp_async_core::runtime::test]
async fn adapter_without_host_issuer_preserves_invalid_tokens() {
    let server = MockServer::start().await;
    let signing_key = Ed25519SigningKey::generate();
    let mut connector = GitHubAdapter::new();
    connector
        .configure(json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": server.uri(),
        }))
        .await
        .expect("configure connector");
    connector
        .handshake(handshake_request(signing_key.verifying_key().to_bytes()))
        .await
        .expect("handshake connector");

    let mut invoke = get_repo_invoke("github-invalid-token");
    invoke.capability_token = CapabilityToken::from_raw(vec![0xff]);
    connector
        .invoke(invoke)
        .await
        .expect_err("the adapter must not replace an intentionally invalid token");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "an invalid token must not reach the provider"
    );
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_gets_repo() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/repos/{OWNER}/{REPO}")))
        .and(header("X-FCP-Credential-ID", TEST_CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 1_296_269,
            "name": REPO,
            "full_name": format!("{OWNER}/{REPO}"),
            "owner": {
                "login": OWNER,
                "id": 1,
                "avatar_url": "",
                "type": "User"
            },
            "description": "Test repo",
            "private": false,
            "fork": false,
            "html_url": format!("https://github.com/{OWNER}/{REPO}"),
            "default_branch": "main",
            "language": "Rust",
            "stargazers_count": 42,
            "forks_count": 10,
            "open_issues_count": 5,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-06-01T00:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let mut connector = GitHubAdapter::with_host_token_issuer(signing_key);
    let invoke = get_repo_invoke("github-connector-suite");

    let suite = ConnectorSuite {
        test_name: "github_get_repo_happy_path".to_string(),
        config: json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": server.uri(),
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut runner = E2eRunner::new("fcp-github");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    for entry in &report.logs {
        println!(
            "{}",
            serde_json::to_string(entry).expect("serialize report log")
        );
    }

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}

#[fcp_async_core::runtime::test]
async fn connector_suite_error_path_reports_not_found_repo() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/repos/{OWNER}/{REPO}")))
        .and(header("X-FCP-Credential-ID", TEST_CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "Not Found",
            "documentation_url": "https://docs.github.com/rest/repos/repos#get-a-repository"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let handshake = handshake_request(signing_key.verifying_key().to_bytes());
    let mut connector = GitHubAdapter::with_host_token_issuer(signing_key);
    let invoke = get_repo_invoke("github-connector-suite-not-found");

    let suite = ConnectorSuite {
        test_name: "github_get_repo_not_found".to_string(),
        config: json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": server.uri(),
        }),
        handshake,
        invoke: Some(invoke),
        invoke_expectations: InvokeExpectations {
            expect_error: true,
            expected_reason_code: Some("FCP-6001".to_string()),
            ..InvokeExpectations::default()
        },
    };

    let mut runner = E2eRunner::new("fcp-github");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    for entry in &report.logs {
        println!(
            "{}",
            serde_json::to_string(entry).expect("serialize report log")
        );
    }

    assert!(report.passed, "connector suite should pass");
    let execute = report
        .logs
        .iter()
        .map(|entry| serde_json::to_value(entry).expect("serialize report log"))
        .find(|entry| {
            matches!(
                entry.get("phase").and_then(serde_json::Value::as_str),
                Some("execute")
            )
        })
        .expect("execute log entry");
    assert_eq!(
        execute["context"]["expected_error"],
        json!(true),
        "suite must assert the expected error path"
    );
    assert_eq!(
        execute["context"]["reason_code"],
        json!("FCP-6001"),
        "GitHub 404 should map to the FCP not-found code"
    );
    assert_eq!(
        execute["context"]["retryable"],
        json!(false),
        "not-found responses should be reported as terminal"
    );
}
