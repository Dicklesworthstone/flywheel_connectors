#![recursion_limit = "256"]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_gmail::connector::GmailConnector;
use fcp_google_discovery::auth::FCP_CREDENTIAL_ID_HEADER;
use fcp_prelude::{
    AgentHint, CapabilityConstraints, CapabilityId, CapabilityToken, ConnectorId, ConnectorMetrics,
    FcpConnector, FcpError, HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass,
    InstanceId, Introspection, InvokeRequest, InvokeResponse, OperationId, OperationInfo,
    RequestId, RiskLevel, SafetyTier, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, ZoneId,
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const CONNECTOR_ID: &str = "fcp.gmail";
const OP_LIST_MESSAGES: &str = "gmail.list_messages";
const CAP_READ: &str = "gmail.read";
const TEST_CREDENTIAL_ID: &str = "00000000-0000-0000-0000-000000000001";

struct GmailAdapter {
    connector: GmailConnector,
    id: ConnectorId,
}

impl GmailAdapter {
    fn new() -> Self {
        Self {
            connector: GmailConnector::new(),
            id: ConnectorId::from_static(CONNECTOR_ID),
        }
    }
}

fcp_core::impl_fcp_sealed!(GmailAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GmailAdapter {
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
                id: OperationId::from_static(OP_LIST_MESSAGES),
                summary: "List Gmail messages".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" },
                        "max_results": { "type": "integer" },
                        "page_token": { "type": "string" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "messages": { "type": "array" },
                        "next_page_token": { "type": "string" },
                        "result_size_estimate": { "type": "integer" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List or search Gmail message references.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"query":"is:unread","max_results":2}"#.to_string()],
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

fn handshake_request(host_public_key: [u8; 32], instance_id: &InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::private(),
        zone_dir: None,
        host_public_key,
        nonce: [37u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id.clone()),
    }
}

fn build_token(signing_key: &Ed25519SigningKey, instance_id: &InstanceId) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["gmail:messages".to_string()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_READ)
        .zone_id("z:private")
        .principal("user:test")
        .operations(&[OP_LIST_MESSAGES])
        .issuer("node:test")
        .token_id(b"gmail-connector-suite")
        .target_instance(instance_id.as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_lists_messages() {
    let server = MockServer::start().await;
    let mut connector = GmailAdapter::new();
    let instance_id = connector.connector.instance_id().clone();

    Mock::given(method("GET"))
        .and(path("/users/me/messages"))
        .and(header(FCP_CREDENTIAL_ID_HEADER, TEST_CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "messages": [
                { "id": "msg_001", "threadId": "thread_001" },
                { "id": "msg_002", "threadId": "thread_002" }
            ],
            "nextPageToken": "next-page",
            "resultSizeEstimate": 2
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let mut invoke = InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::new("gmail-connector-suite"),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(OP_LIST_MESSAGES),
        zone_id: ZoneId::private(),
        input: json!({
            "query": "is:unread",
            "max_results": 2
        }),
        capability_token: CapabilityToken::test_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    };

    let suite = ConnectorSuite {
        test_name: "gmail_list_messages_happy_path".to_string(),
        config: json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": server.uri(),
        }),
        handshake: handshake_request(signing_key.verifying_key().to_bytes(), &instance_id),
        invoke: None,
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut runner = E2eRunner::new("fcp-gmail");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    // Native authority is issued only after the connector reports its actual
    // negotiated instance; the adapter must never rewrite caller tokens.
    assert_ne!(connector.connector.instance_id(), &instance_id);
    assert!(connector.health().await.is_ready());
    invoke.capability_token = build_token(&signing_key, connector.connector.instance_id());
    let response = connector.invoke(invoke).await.expect("authorized invoke");
    assert_eq!(
        response.result.unwrap()["messages"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    for entry in &report.logs {
        println!(
            "{}",
            serde_json::to_string(entry).expect("serialize report log")
        );
    }

    assert!(report.passed, "connector suite should pass");
    assert!(!report.logs.is_empty(), "structured logs should be present");
}
