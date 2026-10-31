use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_e2e::{ConnectorSuite, E2eRunner, InvokeExpectations};
use fcp_google_calendar::connector::GoogleCalendarConnector;
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

const CONNECTOR_ID: &str = "fcp.google-calendar";
const OP_LIST_EVENTS: &str = "gcal.list_events";
const CAP_READ: &str = "gcal.read";
const CALENDAR_ID: &str = "primary";

struct GoogleCalendarAdapter {
    connector: GoogleCalendarConnector,
    id: ConnectorId,
}

impl GoogleCalendarAdapter {
    fn new() -> Self {
        Self {
            connector: GoogleCalendarConnector::new(),
            id: ConnectorId::from_static(CONNECTOR_ID),
        }
    }
}

fcp_core::impl_fcp_sealed!(GoogleCalendarAdapter);

#[fcp_core::async_trait]
impl FcpConnector for GoogleCalendarAdapter {
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
            Ok(payload) => serde_json::from_value(payload)
                .unwrap_or_else(|error| HealthSnapshot::error(format!("invalid health: {error}"))),
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
                id: OperationId::from_static(OP_LIST_EVENTS),
                summary: "List Google Calendar events".to_string(),
                description: None,
                input_schema: json!({
                    "type": "object",
                    "required": ["calendar_id"],
                    "properties": {
                        "calendar_id": { "type": "string" },
                        "time_min": { "type": "string" },
                        "time_max": { "type": "string" },
                        "max_results": { "type": "integer" }
                    }
                }),
                output_schema: json!({
                    "type": "object",
                    "properties": {
                        "events": { "type": "array" },
                        "summary": { "type": "string" }
                    }
                }),
                capability: CapabilityId::from_static(CAP_READ),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint {
                    when_to_use: "List events from a Google Calendar.".to_string(),
                    common_mistakes: Vec::new(),
                    examples: vec![r#"{"calendar_id":"primary","max_results":2}"#.to_string()],
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
            message: format!("failed to serialize invoke: {error}"),
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

fn handshake_request(host_public_key: [u8; 32], instance_id: InstanceId) -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: None,
        host_public_key,
        nonce: [31u8; 32],
        capabilities_requested: vec![CapabilityId::from_static(CAP_READ)],
        host: None,
        transport_caps: None,
        requested_instance_id: Some(instance_id),
    }
}

fn build_token(signing_key: &Ed25519SigningKey, instance_id: &str) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".to_string()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");

    let raw = CapabilityTokenBuilder::new()
        .capability_id(CAP_READ)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[OP_LIST_EVENTS])
        .issuer("node:test")
        .target_instance(instance_id)
        .token_id(b"google-calendar-connector-suite")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("valid constraints cbor")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(raw)
}

#[fcp_async_core::runtime::test]
async fn connector_suite_happy_path_lists_events() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/calendar/v3/calendars/{CALENDAR_ID}/events")))
        .and(header("authorization", "Bearer ya29_test_calendar"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "summary": "Main Calendar",
            "items": [
                {
                    "id": "evt_001",
                    "status": "confirmed",
                    "summary": "Planning Review",
                    "start": { "dateTime": "2026-05-01T10:00:00Z" },
                    "end": { "dateTime": "2026-05-01T10:30:00Z" }
                },
                {
                    "id": "evt_002",
                    "status": "confirmed",
                    "summary": "Implementation Sync",
                    "start": { "dateTime": "2026-05-01T11:00:00Z" },
                    "end": { "dateTime": "2026-05-01T11:30:00Z" }
                }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let suite = ConnectorSuite {
        test_name: "google_calendar_list_events_happy_path".to_string(),
        config: json!({
            "token": "ya29_test_calendar",
            "base_url": format!("{}/calendar/v3", server.uri()),
        }),
        handshake: handshake_request(signing_key.verifying_key().to_bytes(), instance_id),
        invoke: None,
        invoke_expectations: InvokeExpectations::default(),
    };

    let mut connector = GoogleCalendarAdapter::new();
    let mut runner = E2eRunner::new("fcp-google-calendar");
    let report = runner
        .run_connector_suite(&mut connector, suite)
        .await
        .expect("connector suite run");

    // The host signs to the instance returned by the completed handshake.
    let invoke = InvokeRequest {
        r#type: "invoke".to_string(),
        id: RequestId::new("google-calendar-connector-suite"),
        connector_id: ConnectorId::from_static(CONNECTOR_ID),
        operation: OperationId::from_static(OP_LIST_EVENTS),
        zone_id: ZoneId::work(),
        input: json!({
            "calendar_id": CALENDAR_ID,
            "max_results": 2
        }),
        capability_token: build_token(&signing_key, connector.connector.instance_id()),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    };

    let response = connector
        .invoke(invoke)
        .await
        .expect("authorized native invoke");
    assert_eq!(
        response.result.unwrap()["events"].as_array().unwrap().len(),
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
