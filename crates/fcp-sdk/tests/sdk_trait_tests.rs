//! SDK Trait Tests
//!
//! Tests for `FcpConnector` trait defaults, archetype traits,
//! and helper functionality provided by the SDK.
//!
//! These tests verify:
//! - `FcpConnector` trait default implementations
//! - Archetype trait implementations (Streaming, Bidirectional, Polling, Webhook)
//! - `BaseConnector` helper methods
//! - Introspection generation

use async_trait::async_trait;
use fcp_sdk::prelude::*;
use fcp_sdk::{
    EventInfo, OperationId, RateLimitDeclarations, ReplayBufferInfo, SelfCheckReport,
    SelfCheckStatus, SessionId, SubscribeResult,
};
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// Test Connector Implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal connector implementing only required methods.
#[derive(Debug)]
struct MinimalConnector {
    base: BaseConnector,
}

impl MinimalConnector {
    fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("test:minimal:v1")),
        }
    }
}

fn test_capability_token() -> CapabilityToken {
    CapabilityToken::test_token()
}

fn test_handshake_request() -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "1.0.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: Some("/tmp/test-zone".to_string()),
        host_public_key: [0u8; 32],
        nonce: [1u8; 32],
        capabilities_requested: vec![],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn test_shutdown_request() -> ShutdownRequest {
    ShutdownRequest {
        r#type: "shutdown".to_string(),
        deadline_ms: 5000,
        drain: false,
        reason: None,
    }
}

fcp_core::impl_fcp_sealed!(MinimalConnector);

#[async_trait]
impl FcpConnector for MinimalConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: vec![],
            session_id: SessionId::new(),
            manifest_hash: "sha256:test".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot::ready()
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.record_request(true);
        Ok(InvokeResponse::ok(req.id, json!({"status": "ok"})))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(SubscribeResponse {
            r#type: "response".to_string(),
            id: req.id,
            result: SubscribeResult {
                confirmed_topics: req.topics,
                cursors: std::collections::HashMap::new(),
                replay_supported: false,
                buffer: None,
            },
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

impl ConnectorApp for MinimalConnector {
    fn describe(&self) -> ConnectorAppDescriptor {
        ConnectorAppDescriptor::new(self.id().clone())
            .with_execution_form(ConnectorRuntimeFormat::Native)
            .with_archetype(ConnectorArchetype::Operational)
            .with_state_model(ConnectorStateModel::Stateless)
            .supports_usage_snapshots()
            .supports_preflight_cost_estimates()
            .publishes_operation_receipts()
            .with_diagnostic_reason_code("self_check_unsupported")
            .with_fixture_scenario("minimal.happy_path")
            .with_local_repro_command(
                "cargo test -p fcp-sdk sdk_trait_tests::test_connector_app_contract -- --nocapture",
            )
    }

    fn contract_introspection(&self) -> Introspection {
        Introspection {
            operations: vec![OperationInfo {
                id: OperationId::from_static("test.op"),
                summary: "Test operation".to_string(),
                description: Some(
                    "Published through the execution-form-neutral app contract".into(),
                ),
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
                capability: CapabilityId::from_static("test.op.invoke"),
                risk_level: RiskLevel::Low,
                safety_tier: SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: AgentHint::default(),
                rate_limit: None,
                requires_approval: Some(ApprovalMode::None),
            }],
            events: vec![EventInfo {
                topic: "test.events".to_string(),
                schema: json!({"type": "object"}),
                requires_ack: false,
            }],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    fn capability_catalog_for(&self, introspection: &Introspection) -> ConnectorCapabilityCatalog {
        ConnectorCapabilityCatalog::from_introspection_and_rate_limits(introspection, None)
            .with_policy_assumption("requires a zone-scoped capability token")
    }
}

#[test]
fn sdk_reexports_match_owner_crates() {
    assert_eq!(
        std::any::TypeId::of::<fcp_sdk::CapabilityToken>(),
        std::any::TypeId::of::<fcp_policy::CapabilityToken>()
    );
    assert_eq!(
        std::any::TypeId::of::<fcp_sdk::ZoneId>(),
        std::any::TypeId::of::<fcp_policy::ZoneId>()
    );
    assert_eq!(
        std::any::TypeId::of::<fcp_sdk::ObjectId>(),
        std::any::TypeId::of::<fcp_evidence::ObjectId>()
    );
    assert_eq!(
        std::any::TypeId::of::<fcp_sdk::RateLimitConfig>(),
        std::any::TypeId::of::<fcp_kernel::RateLimitConfig>()
    );
}

/// Streaming connector for testing streaming-specific functionality.
#[derive(Debug)]
struct StreamingConnector {
    base: BaseConnector,
    #[allow(dead_code)]
    stream_manager: EventStreamManager,
}

impl StreamingConnector {
    fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("test:streaming:v1")),
            stream_manager: EventStreamManager::new(EventCaps {
                streaming: true,
                replay: true,
                min_buffer_events: 100,
                requires_ack: true,
            }),
        }
    }
}
fcp_core::impl_fcp_sealed!(StreamingConnector);

#[async_trait]
impl FcpConnector for StreamingConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        self.base.set_handshaken(true);
        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: vec![],
            session_id: SessionId::new(),
            manifest_hash: "sha256:test".to_string(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: true,
                min_buffer_events: 100,
                requires_ack: true,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        HealthSnapshot::ready()
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: vec![],
            events: vec![
                EventInfo {
                    topic: "events.update".to_string(),
                    schema: json!({}),
                    requires_ack: true,
                },
                EventInfo {
                    topic: "events.created".to_string(),
                    schema: json!({}),
                    requires_ack: true,
                },
            ],
            resource_types: vec![],
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: true,
                replay: true,
                min_buffer_events: 100,
                requires_ack: true,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        Ok(InvokeResponse::ok(req.id, json!({})))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Ok(SubscribeResponse {
            r#type: "response".to_string(),
            id: req.id,
            result: SubscribeResult {
                confirmed_topics: req.topics,
                cursors: std::collections::HashMap::new(),
                replay_supported: true,
                buffer: Some(ReplayBufferInfo {
                    min_events: 100,
                    overflow: "drop_oldest".to_string(),
                }),
            },
        })
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BaseConnector Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_base_connector_new() {
    let base = BaseConnector::new(ConnectorId::from_static("test:new:v1"));

    assert_eq!(base.id.as_str(), "test:new:v1");
}

#[test]
fn test_base_connector_ready_state_progression() {
    let base = BaseConnector::new(ConnectorId::from_static("test:ready:v1"));

    // Initially not ready
    assert!(base.check_ready().is_err());

    // After configure, still not ready
    base.set_configured(true);
    assert!(base.check_ready().is_err());

    // After handshake, now ready
    base.set_handshaken(true);
    assert!(base.check_ready().is_ok());
}

#[test]
fn test_base_connector_metrics_initial() {
    let base = BaseConnector::new(ConnectorId::from_static("test:metrics:v1"));

    let metrics = base.metrics();

    assert_eq!(metrics.requests_total, 0);
    assert_eq!(metrics.requests_success, 0);
    assert_eq!(metrics.requests_error, 0);
    assert_eq!(metrics.events_emitted, 0);
}

#[test]
fn test_base_connector_record_request_success() {
    let base = BaseConnector::new(ConnectorId::from_static("test:record:v1"));

    base.record_request(true);
    base.record_request(true);

    let metrics = base.metrics();
    assert_eq!(metrics.requests_total, 2);
    assert_eq!(metrics.requests_success, 2);
    assert_eq!(metrics.requests_error, 0);
}

#[test]
fn test_base_connector_record_request_error() {
    let base = BaseConnector::new(ConnectorId::from_static("test:record:v1"));

    base.record_request(false);

    let metrics = base.metrics();
    assert_eq!(metrics.requests_total, 1);
    assert_eq!(metrics.requests_success, 0);
    assert_eq!(metrics.requests_error, 1);
}

#[test]
fn test_base_connector_record_event() {
    let base = BaseConnector::new(ConnectorId::from_static("test:event:v1"));

    base.record_event();
    base.record_event();
    base.record_event();

    let metrics = base.metrics();
    assert_eq!(metrics.events_emitted, 3);
}

#[test]
fn test_base_connector_mixed_recording() {
    let base = BaseConnector::new(ConnectorId::from_static("test:mixed:v1"));

    base.record_request(true);
    base.record_request(false);
    base.record_request(true);
    base.record_event();
    base.record_event();

    let metrics = base.metrics();
    assert_eq!(metrics.requests_total, 3);
    assert_eq!(metrics.requests_success, 2);
    assert_eq!(metrics.requests_error, 1);
    assert_eq!(metrics.events_emitted, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// FcpConnector Trait Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_minimal_connector_lifecycle() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let mut connector = MinimalConnector::new();

        // Check ID
        assert_eq!(connector.id().as_str(), "test:minimal:v1");

        // Configure
        let config_result = connector.configure(json!({})).await;
        assert!(config_result.is_ok());

        // Handshake
        let hs_result = connector.handshake(test_handshake_request()).await;
        assert!(hs_result.is_ok());
        let response = hs_result.unwrap();
        assert_eq!(response.status, "accepted");

        // Health check
        let health = connector.health().await;
        assert!(health.is_ready());

        // Self-check (default)
        let self_check = connector.self_check().await.expect("self-check");
        assert_eq!(self_check.status, SelfCheckStatus::Unsupported);
        assert_eq!(
            self_check.reason_code.as_deref(),
            Some("self_check_unsupported")
        );

        // Shutdown
        let shutdown_result = connector.shutdown(test_shutdown_request()).await;
        assert!(shutdown_result.is_ok());
    });
}

#[test]
fn test_self_check_report_from_error() {
    let err = FcpError::NotConfigured;
    let report = SelfCheckReport::from_error(&err);
    assert_eq!(report.status, SelfCheckStatus::Failed);
    assert_eq!(report.reason_code.as_deref(), Some("FCP-5002"));
}

#[test]
fn test_connector_invoke() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MinimalConnector::new();

        let req = InvokeRequest {
            r#type: "invoke".to_string(),
            id: RequestId::new("req-1"),
            connector_id: ConnectorId::from_static("test:minimal:v1"),
            operation: OperationId::from_static("test.op"),
            zone_id: ZoneId::work(),
            input: json!({"key": "value"}),
            capability_token: test_capability_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        };

        let result = connector.invoke(req).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status, InvokeStatus::Ok);
    });
}

#[test]
fn test_connector_simulate() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MinimalConnector::new();

        let req = SimulateRequest {
            r#type: "simulate".to_string(),
            id: RequestId::new("sim-1"),
            connector_id: ConnectorId::from_static("test:minimal:v1"),
            operation: OperationId::from_static("test.op"),
            zone_id: ZoneId::work(),
            input: json!({}),
            capability_token: test_capability_token(),
            estimate_cost: false,
            check_availability: false,
            context: None,
            correlation_id: None,
        };

        let result = connector.simulate(req).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.would_succeed);
    });
}

#[test]
fn test_connector_introspect() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MinimalConnector::new();

        let introspection = connector.introspect();

        assert!(introspection.operations.is_empty());
        assert!(introspection.events.is_empty());
    });
}

#[test]
fn test_connector_app_contract() {
    let connector = MinimalConnector::new();

    let contract = connector.app_contract();

    assert_eq!(contract.description.connector_id, connector.id().clone());
    assert_eq!(
        contract.description.execution_forms,
        vec![ConnectorRuntimeFormat::Native]
    );
    assert_eq!(
        contract.description.archetypes,
        vec![ConnectorArchetype::Operational]
    );
    assert!(contract.description.budget.supports_usage_snapshots);
    assert!(contract.description.evidence.operation_receipts);
    assert_eq!(contract.introspection.operations.len(), 1);
    assert_eq!(contract.introspection.events.len(), 1);
    assert_eq!(
        contract.introspection.operations[0].id,
        OperationId::from_static("test.op")
    );
    assert!(
        contract
            .description
            .diagnostics
            .testkit_entry_points
            .contains(&"fcp_testkit::ConnectorTestHarness".to_string())
    );
    assert!(
        contract
            .description
            .diagnostics
            .testkit_entry_points
            .contains(&"fcp_testkit::evidence_helpers::EvidenceCollector".to_string())
    );
    assert!(
        contract
            .description
            .diagnostics
            .testkit_entry_points
            .contains(&"fcp_testkit::session_script::SessionScript".to_string())
    );
    assert_eq!(contract.capabilities.operations.len(), 1);
    assert_eq!(
        contract.capabilities.required_capabilities,
        vec![CapabilityId::from_static("test.op.invoke")]
    );
}

#[test]
fn test_connector_capability_catalog_deduplicates_capabilities() {
    let introspection = Introspection {
        operations: vec![
            fcp_core::OperationInfo {
                id: OperationId::from_static("alpha.read"),
                summary: "alpha".to_string(),
                description: None,
                input_schema: json!({}),
                output_schema: json!({}),
                capability: CapabilityId::from_static("alpha.read"),
                risk_level: fcp_core::RiskLevel::Low,
                safety_tier: fcp_core::SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: fcp_core::AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
            fcp_core::OperationInfo {
                id: OperationId::from_static("alpha.list"),
                summary: "alpha list".to_string(),
                description: None,
                input_schema: json!({}),
                output_schema: json!({}),
                capability: CapabilityId::from_static("alpha.read"),
                risk_level: fcp_core::RiskLevel::Low,
                safety_tier: fcp_core::SafetyTier::Safe,
                idempotency: IdempotencyClass::Strict,
                ai_hints: fcp_core::AgentHint::default(),
                rate_limit: None,
                requires_approval: None,
            },
        ],
        events: vec![],
        resource_types: vec![],
        auth_caps: None,
        event_caps: None,
    };

    let catalog =
        ConnectorCapabilityCatalog::from_introspection_and_rate_limits(&introspection, None)
            .with_policy_assumption("operator must pre-issue alpha.read");

    assert_eq!(catalog.operations.len(), 2);
    assert_eq!(
        catalog.required_capabilities,
        vec![CapabilityId::from_static("alpha.read")]
    );
    assert_eq!(
        catalog.policy_assumptions,
        vec!["operator must pre-issue alpha.read".to_string()]
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming Connector Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_streaming_connector_handshake_includes_event_caps() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let mut connector = StreamingConnector::new();

        let result = connector.handshake(test_handshake_request()).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.event_caps.is_some());

        let caps = response.event_caps.unwrap();
        assert!(caps.streaming);
        assert!(caps.replay);
        assert!(caps.requires_ack);
        assert_eq!(caps.min_buffer_events, 100);
    });
}

#[test]
fn test_streaming_connector_introspect_includes_events() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = StreamingConnector::new();

        let introspection = connector.introspect();

        assert!(!introspection.events.is_empty());
        // Check that events contain expected topics
        let topics: Vec<&str> = introspection
            .events
            .iter()
            .map(|e| e.topic.as_str())
            .collect();
        assert!(topics.contains(&"events.update"));
        assert!(topics.contains(&"events.created"));
    });
}

#[test]
fn test_streaming_connector_subscribe() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = StreamingConnector::new();

        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("sub-1"),
            topics: vec!["events.update".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let result = connector.subscribe(req).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.result.replay_supported);
        assert!(response.result.buffer.is_some());
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// HealthSnapshot Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_health_snapshot_ready() {
    let health = HealthSnapshot::ready();

    assert!(health.is_ready());
    assert!(health.is_healthy());
}

#[test]
fn test_health_snapshot_error() {
    let health = HealthSnapshot::error("Database connection failed");

    assert!(!health.is_ready());
    assert!(!health.is_healthy());
}

#[test]
fn test_health_snapshot_degraded() {
    let health = HealthSnapshot::degraded("Slow response times");

    assert!(!health.is_ready()); // Degraded is NOT "ready" (only Ready state is ready)
    assert!(health.is_healthy()); // But IS healthy (degraded still serves traffic)
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorId Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_connector_id_from_static() {
    let id = ConnectorId::from_static("test:connector:v1");
    assert_eq!(id.as_str(), "test:connector:v1");
}

#[test]
fn test_connector_id_display() {
    let id = ConnectorId::from_static("test:display:v1");
    assert_eq!(format!("{id}"), "test:display:v1");
}

#[test]
fn test_connector_id_debug() {
    let id = ConnectorId::from_static("test:debug:v1");
    let debug = format!("{id:?}");
    assert!(debug.contains("test:debug:v1"));
}

#[test]
fn test_connector_id_equality() {
    let id1 = ConnectorId::from_static("test:eq:v1");
    let id2 = ConnectorId::from_static("test:eq:v1");
    let id3 = ConnectorId::from_static("test:different:v1");

    assert_eq!(id1, id2);
    assert_ne!(id1, id3);
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneId Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_zone_id_work() {
    let zone = ZoneId::work();
    assert_eq!(zone.as_str(), "z:work");
}

#[test]
fn test_zone_id_private() {
    let zone = ZoneId::private();
    assert_eq!(zone.as_str(), "z:private");
}

#[test]
fn test_zone_id_owner() {
    let zone = ZoneId::owner();
    assert_eq!(zone.as_str(), "z:owner");
}

#[test]
fn test_zone_id_community() {
    let zone = ZoneId::community();
    assert_eq!(zone.as_str(), "z:community");
}

#[test]
fn test_zone_id_equality() {
    let z1 = ZoneId::work();
    let z2 = ZoneId::work();
    let z3 = ZoneId::private();

    assert_eq!(z1, z2);
    assert_ne!(z1, z3);
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionId Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_session_id_new() {
    let s1 = SessionId::new();
    let s2 = SessionId::new();

    // Each new session ID should be unique
    assert_ne!(s1, s2);
}

#[test]
fn test_session_id_debug() {
    let session = SessionId::new();
    let debug = format!("{session:?}");
    // SessionId should have a debug representation
    assert_ne!(debug, "");
}

// ─────────────────────────────────────────────────────────────────────────────
// RequestId Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_request_id_new() {
    let req_id = RequestId::new("test-request-123");
    assert_eq!(req_id.0, "test-request-123");
}

#[test]
fn test_request_id_display() {
    let req_id = RequestId::new("display-test");
    assert_eq!(format!("{req_id}"), "display-test");
}

// ─────────────────────────────────────────────────────────────────────────────
// InstanceId Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_instance_id_new() {
    let i1 = InstanceId::new();
    let i2 = InstanceId::new();

    // Each instance ID should be unique
    assert_ne!(i1, i2);
}

// ─────────────────────────────────────────────────────────────────────────────
// InvokeResponse Builder Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_invoke_response_ok_builder() {
    let response = InvokeResponse::ok(RequestId::new("req-1"), json!({"data": "value"}));

    assert_eq!(response.status, InvokeStatus::Ok);
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

#[test]
fn test_invoke_response_error_builder() {
    let response = InvokeResponse::error(
        RequestId::new("req-1"),
        FcpError::Internal {
            message: "Test error".to_string(),
        },
    );

    assert_eq!(response.status, InvokeStatus::Error);
    assert!(response.result.is_none());
    assert!(response.error.is_some());
}

// ─────────────────────────────────────────────────────────────────────────────
// SimulateResponse Builder Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_simulate_response_allowed_builder() {
    let response = SimulateResponse::allowed(RequestId::new("sim-1"));

    assert!(response.would_succeed);
    assert!(response.failure_reason.is_none());
    assert!(response.denial_code.is_none());
}

#[test]
fn test_simulate_response_denied_builder() {
    let response = SimulateResponse::denied(RequestId::new("sim-1"), "Not authorized", "FCP-3001");

    assert!(!response.would_succeed);
    assert_eq!(response.failure_reason, Some("Not authorized".to_string()));
    assert_eq!(response.denial_code, Some("FCP-3001".to_string()));
}

#[test]
fn test_simulate_response_with_cost_estimate() {
    let response = SimulateResponse::allowed(RequestId::new("sim-1"))
        .with_cost_estimate(CostEstimate::with_credits(50));

    assert!(response.would_succeed);
    assert!(response.estimated_cost.is_some());
    assert_eq!(
        response.estimated_cost.as_ref().unwrap().api_credits,
        Some(50)
    );
}

#[test]
fn test_simulate_response_with_availability() {
    let response = SimulateResponse::allowed(RequestId::new("sim-1"))
        .with_availability(ResourceAvailability::available());

    assert!(response.would_succeed);
    assert!(response.availability.is_some());
    assert!(response.availability.as_ref().unwrap().available);
}

#[test]
fn test_simulate_response_with_missing_capabilities() {
    let response = SimulateResponse::denied(RequestId::new("sim-1"), "Missing caps", "FCP-3001")
        .with_missing_capabilities(vec!["cap.a".to_string(), "cap.b".to_string()]);

    assert!(!response.would_succeed);
    assert_eq!(response.missing_capabilities.len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Principal Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_principal_creation() {
    let principal = Principal {
        kind: "user".to_string(),
        id: "user-123".to_string(),
        trust: TrustLevel::Paired,
        display: Some("Test User".to_string()),
    };

    assert_eq!(principal.kind, "user");
    assert_eq!(principal.id, "user-123");
    assert!(matches!(principal.trust, TrustLevel::Paired));
    assert_eq!(principal.display, Some("Test User".to_string()));
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustLevel Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_trust_level_variants() {
    let anonymous = TrustLevel::Anonymous;
    let untrusted = TrustLevel::Untrusted;
    let paired = TrustLevel::Paired;
    let admin = TrustLevel::Admin;

    // Just verify they're different
    assert!(!matches!(anonymous, TrustLevel::Admin));
    assert!(!matches!(untrusted, TrustLevel::Admin));
    assert!(matches!(paired, TrustLevel::Paired));
    assert!(matches!(admin, TrustLevel::Admin));
}

// ─────────────────────────────────────────────────────────────────────────────
// EventCaps Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_event_caps_creation() {
    let caps = EventCaps {
        streaming: true,
        replay: true,
        min_buffer_events: 50,
        requires_ack: false,
    };

    assert!(caps.streaming);
    assert!(caps.replay);
    assert_eq!(caps.min_buffer_events, 50);
    assert!(!caps.requires_ack);
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorMetrics Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_connector_metrics_structure() {
    let base = BaseConnector::new(ConnectorId::from_static("test:metrics:v1"));

    base.record_request(true);
    base.record_request(false);
    base.record_event();

    let metrics = base.metrics();

    assert_eq!(metrics.requests_total, 2);
    assert_eq!(metrics.requests_success, 1);
    assert_eq!(metrics.requests_error, 1);
    assert_eq!(metrics.events_emitted, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// RateLimitDeclarations Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_rate_limits_default_is_unknown() {
    let connector = MinimalConnector::new();
    assert!(
        connector.rate_limits().is_none(),
        "default FcpConnector::rate_limits() must preserve unknown/undeclared state"
    );
}

#[test]
fn test_rate_limit_declarations_default_is_empty() {
    let decls = RateLimitDeclarations::default();
    assert!(decls.is_empty());
}
