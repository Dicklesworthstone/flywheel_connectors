use std::sync::Once;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_google_drive::connector::DriveConnector;
use fcp_prelude::{
    AgentHint, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::json;
use tracing::info;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

static TEST_LOGGER: Once = Once::new();

fn init_json_test_logging() {
    TEST_LOGGER.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .json()
            .try_init();
    });
}

struct GoogleDriveAdapter {
    connector: DriveConnector,
    id: ConnectorId,
}

impl GoogleDriveAdapter {
    fn new() -> Self {
        Self {
            connector: DriveConnector::new(),
            id: ConnectorId::from_static("fcp.google_drive"),
        }
    }
}

fcp_core::impl_fcp_sealed!(GoogleDriveAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GoogleDriveAdapter {
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
            Ok(payload) => serde_json::from_value(payload).unwrap_or_else(|err| {
                HealthSnapshot::error(format!("invalid Drive health: {err}"))
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
            operations: vec![
                OperationInfo {
                    id: OperationId::from_static("drive.list_files"),
                    summary: "List files and folders in Google Drive".to_string(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "files": { "type": "array" }
                        }
                    }),
                    capability: CapabilityId::from_static("drive.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "List Drive files via the connector.".to_string(),
                        common_mistakes: Vec::new(),
                        examples: vec![r#"{"query":"name contains 'report'"}"#.to_string()],
                        related: Vec::new(),
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
                OperationInfo {
                    id: OperationId::from_static("drive.get_file"),
                    summary: "Get Google Drive file metadata".to_string(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "required": ["file_id"],
                        "properties": {
                            "file_id": { "type": "string" }
                        }
                    }),
                    output_schema: json!({
                        "type": "object",
                        "properties": {
                            "file": { "type": "object" }
                        }
                    }),
                    capability: CapabilityId::from_static("drive.read"),
                    risk_level: RiskLevel::Low,
                    safety_tier: SafetyTier::Safe,
                    idempotency: IdempotencyClass::Strict,
                    ai_hints: AgentHint {
                        when_to_use: "Retrieve metadata for one Drive file.".to_string(),
                        common_mistakes: Vec::new(),
                        examples: vec![r#"{"file_id":"file_123"}"#.to_string()],
                        related: Vec::new(),
                    },
                    rate_limit: None,
                    requires_approval: None,
                },
            ],
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

fn handshake_request(
    host_public_key: [u8; 32],
    capabilities: &[&str],
    instance_id: &InstanceId,
) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [11u8; 32],
        capabilities_requested: capabilities
            .iter()
            .map(|cap| cap.parse::<CapabilityId>().expect("capability id"))
            .collect(),
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn build_token(
    signing_key: &Ed25519SigningKey,
    operation: &'static str,
    instance_id: &InstanceId,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let cose = CapabilityTokenBuilder::new()
        .capability_id("drive.read")
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(cose)
}

fn drive_invoke(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    id: &'static str,
    operation: &'static str,
    input: serde_json::Value,
) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::from(id),
        connector_id: ConnectorId::from_static("fcp.google_drive"),
        operation: OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input,
        capability_token: build_token(signing_key, operation, instance_id),
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
async fn connector_suite_happy_path_lists_files() {
    init_json_test_logging();
    info!(
        test = "google_drive_connector_suite_happy_path",
        phase = "setup"
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files"))
        .and(header("authorization", "Bearer ya29_test_drive"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "drive#fileList",
            "files": [
                {
                    "id": "file_123",
                    "name": "Quarterly Report",
                    "mimeType": "application/pdf"
                }
            ],
            "nextPageToken": null
        })))
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["drive.read"],
        &instance_id,
    );
    let suite = ConnectorSuite {
        test_name: "google_drive_happy_path".to_string(),
        config: json!({
            "access_token": "ya29_test_drive",
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake,
        invoke: None,
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut runner = E2eRunner::new("fcp-google-drive");
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

    info!(
        test = "google_drive_connector_suite_happy_path",
        phase = "verify",
        passed = report.passed,
        log_entries = report.logs.len()
    );
    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
    let actual_instance: InstanceId = connector.connector.instance_id().parse().unwrap();
    assert_ne!(actual_instance, instance_id);
    let response = connector
        .invoke(drive_invoke(
            &signing_key,
            &actual_instance,
            "drive-happy-path",
            "drive.list_files",
            json!({ "query": "name contains 'Report'" }),
        ))
        .await
        .expect("invoke with the negotiated instance");
    assert_eq!(response.result.unwrap()["files"][0]["id"], "file_123");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn connector_suite_error_path_reports_not_found_file() {
    init_json_test_logging();
    info!(
        test = "google_drive_connector_suite_not_found",
        phase = "setup"
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drive/v3/files/file_missing"))
        .and(header("authorization", "Bearer ya29_test_drive"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": 404,
                "message": "File not found: file_missing",
                "status": "NOT_FOUND",
                "errors": [
                    {
                        "domain": "global",
                        "reason": "notFound",
                        "message": "File not found: file_missing"
                    }
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut connector = GoogleDriveAdapter::new();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let handshake = handshake_request(
        signing_key.verifying_key().to_bytes(),
        &["drive.read"],
        &instance_id,
    );
    let suite = ConnectorSuite {
        test_name: "google_drive_get_file_not_found".to_string(),
        config: json!({
            "access_token": "ya29_test_drive",
            "base_url": format!("{}/drive/v3", server.uri()),
        }),
        handshake,
        invoke: None,
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut runner = E2eRunner::new("fcp-google-drive");
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

    info!(
        test = "google_drive_connector_suite_not_found",
        phase = "verify",
        passed = report.passed,
        log_entries = report.logs.len()
    );
    assert!(report.passed, "connector suite should pass");
    let actual_instance: InstanceId = connector.connector.instance_id().parse().unwrap();
    let error = connector
        .invoke(drive_invoke(
            &signing_key,
            &actual_instance,
            "drive-not-found",
            "drive.get_file",
            json!({ "file_id": "file_missing" }),
        ))
        .await
        .expect_err("provider returns the requested missing file");
    assert_eq!(
        error.error_code(),
        "FCP-6001",
        "Drive 404 should map to the FCP not-found code"
    );
    assert!(
        !error.is_retryable(),
        "not-found responses should be reported as terminal"
    );
}
