//! SDK Standard Methods Tests
//!
//! Validates the connector SDK standard-method surface is correct and ergonomic.
//! This includes: invoke, simulate, subscribe, introspect, and lifecycle methods.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use fcp_sdk::prelude::*;
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// Test Fixtures: Mock Connector Implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Mock connector for testing SDK standard methods.
#[derive(Debug)]
struct MockConnector {
    base: BaseConnector,
    invoke_count: Arc<AtomicU64>,
    simulate_count: Arc<AtomicU64>,
    subscribe_count: Arc<AtomicU64>,
    should_fail: bool,
}

impl MockConnector {
    fn new(id: &'static str) -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static(id)),
            invoke_count: Arc::new(AtomicU64::new(0)),
            simulate_count: Arc::new(AtomicU64::new(0)),
            subscribe_count: Arc::new(AtomicU64::new(0)),
            should_fail: false,
        }
    }

    const fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }

    fn invoke_count(&self) -> u64 {
        self.invoke_count.load(Ordering::SeqCst)
    }

    fn simulate_count(&self) -> u64 {
        self.simulate_count.load(Ordering::SeqCst)
    }

    fn subscribe_count(&self) -> u64 {
        self.subscribe_count.load(Ordering::SeqCst)
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

fn test_invoke_request(connector_id: &'static str, operation: &'static str) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: fcp_sdk::RequestId::new("test-req-1"),
        connector_id: ConnectorId::from_static(connector_id),
        operation: fcp_sdk::OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input: json!({"test": "data"}),
        capability_token: test_capability_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    }
}

fn test_simulate_request(connector_id: &'static str, operation: &'static str) -> SimulateRequest {
    SimulateRequest {
        r#type: "simulate".to_string(),
        id: fcp_sdk::RequestId::new("test-sim-1"),
        connector_id: ConnectorId::from_static(connector_id),
        operation: fcp_sdk::OperationId::from_static(operation),
        zone_id: ZoneId::work(),
        input: json!({"test": "data"}),
        capability_token: test_capability_token(),
        estimate_cost: false,
        check_availability: false,
        context: None,
        correlation_id: None,
    }
}

fn test_subscribe_request() -> SubscribeRequest {
    SubscribeRequest {
        r#type: "subscribe".to_string(),
        id: fcp_sdk::RequestId::new("test-sub-1"),
        topics: vec!["events.test".to_string()],
        since: None,
        max_events_per_sec: None,
        batch_ms: None,
        window_size: None,
        capability_token: None,
    }
}

fcp_core::impl_fcp_sealed!(MockConnector);

#[async_trait]
impl FcpConnector for MockConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, _config: serde_json::Value) -> FcpResult<()> {
        if self.should_fail {
            return Err(FcpError::Internal {
                message: "Configuration failed".to_string(),
            });
        }
        self.base.set_configured(true);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if self.should_fail {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: "Handshake denied".to_string(),
            });
        }
        self.base.set_handshaken(true);
        Ok(HandshakeResponse {
            status: "accepted".to_string(),
            capabilities_granted: vec![],
            session_id: fcp_sdk::SessionId::new(),
            manifest_hash: "sha256:test".to_string(),
            nonce: req.nonce,
            event_caps: None,
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        if self.should_fail {
            HealthSnapshot::error("Test failure")
        } else {
            HealthSnapshot::ready()
        }
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
        self.invoke_count.fetch_add(1, Ordering::SeqCst);
        self.base.record_request(!self.should_fail);

        if self.should_fail {
            return Err(FcpError::Internal {
                message: "Invoke failed".to_string(),
            });
        }

        Ok(InvokeResponse::ok(req.id, json!({"status": "ok"})))
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        self.simulate_count.fetch_add(1, Ordering::SeqCst);

        if self.should_fail {
            return Ok(SimulateResponse::denied(
                req.id,
                "Operation not permitted",
                "FCP-3001",
            ));
        }

        let mut response = SimulateResponse::allowed(req.id);

        if req.estimate_cost {
            response = response.with_cost_estimate(CostEstimate::with_credits(10));
        }

        if req.check_availability {
            response = response.with_availability(
                ResourceAvailability::available().with_rate_limit(100, Some(60000)),
            );
        }

        Ok(response)
    }

    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        self.subscribe_count.fetch_add(1, Ordering::SeqCst);

        if self.should_fail {
            return Err(FcpError::StreamingNotSupported);
        }

        Ok(SubscribeResponse {
            r#type: "response".to_string(),
            id: req.id,
            result: fcp_sdk::SubscribeResult {
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

// ─────────────────────────────────────────────────────────────────────────────
// Standard Method Signature Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_invoke_method_signature_correct() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:mock:v1");
        let req = test_invoke_request("test:mock:v1", "test.operation");

        let result = connector.invoke(req).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, InvokeStatus::Ok);
        assert!(response.result.is_some());
        assert_eq!(connector.invoke_count(), 1);
    });
}

#[test]
fn test_simulate_method_signature_correct() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:mock:v1");
        let req = test_simulate_request("test:mock:v1", "test.operation");

        let result = connector.simulate(req).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.would_succeed);
        assert_eq!(connector.simulate_count(), 1);
    });
}

#[test]
fn test_subscribe_method_signature_correct() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:mock:v1");
        let req = test_subscribe_request();

        let result = connector.subscribe(req).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_ne!(
            response.result.confirmed_topics,
            [] as [std::string::String; 0]
        );
        assert_eq!(connector.subscribe_count(), 1);
    });
}

#[test]
fn test_introspect_returns_correct_schema() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:mock:v1");

        let introspection = connector.introspect();

        // Introspection has operations, events, resource_types, auth_caps, event_caps
        assert!(introspection.operations.is_empty());
        assert!(introspection.events.is_empty());
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_connector_lifecycle_configure_then_handshake() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let mut connector = MockConnector::new("test:lifecycle:v1");

        // Initially not ready
        assert!(connector.base.check_ready().is_err());

        // Configure
        let config_result = connector.configure(json!({})).await;
        assert!(config_result.is_ok());

        // Still not ready (need handshake)
        assert!(connector.base.check_ready().is_err());

        // Handshake
        let hs_result = connector.handshake(test_handshake_request()).await;
        assert!(hs_result.is_ok());

        // Now ready
        assert!(connector.base.check_ready().is_ok());
    });
}

#[test]
fn test_connector_health_check() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:health:v1");

        let health = connector.health().await;

        assert!(health.is_ready());
    });
}

#[test]
fn test_connector_health_check_unhealthy() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:health:v1").with_failure();

        let health = connector.health().await;

        assert!(!health.is_healthy());
    });
}

#[test]
fn test_connector_metrics_tracking() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:metrics:v1");

        // Initial metrics should be zero
        let initial_metrics = connector.metrics();
        assert_eq!(initial_metrics.requests_total, 0);
        assert_eq!(initial_metrics.requests_success, 0);

        // Invoke some requests
        let req = test_invoke_request("test:metrics:v1", "test.op");
        let _ = connector.invoke(req.clone()).await;
        let _ = connector.invoke(req).await;

        // Check metrics updated
        let metrics = connector.metrics();
        assert_eq!(metrics.requests_total, 2);
        assert_eq!(metrics.requests_success, 2);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Handling Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_invoke_error_handling() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:error:v1").with_failure();
        let req = test_invoke_request("test:error:v1", "test.operation");

        let result = connector.invoke(req).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::Internal { .. }));
    });
}

#[test]
fn test_configure_error_handling() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let mut connector = MockConnector::new("test:error:v1").with_failure();

        let result = connector.configure(json!({})).await;

        assert!(result.is_err());
    });
}

#[test]
fn test_handshake_error_handling() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let mut connector = MockConnector::new("test:error:v1").with_failure();

        let result = connector.handshake(test_handshake_request()).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::Unauthorized { .. }));
    });
}

#[test]
fn test_subscribe_error_handling() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:error:v1").with_failure();
        let req = test_subscribe_request();

        let result = connector.subscribe(req).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FcpError::StreamingNotSupported));
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulate with CostEstimate Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_simulate_with_cost_estimate() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:cost:v1");
        let mut req = test_simulate_request("test:cost:v1", "test.operation");
        req.estimate_cost = true;

        let result = connector.simulate(req).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.would_succeed);
        assert!(response.estimated_cost.is_some());
        let cost = response.estimated_cost.unwrap();
        assert_eq!(cost.api_credits, Some(10));
    });
}

#[test]
fn test_simulate_with_availability_check() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:avail:v1");
        let mut req = test_simulate_request("test:avail:v1", "test.operation");
        req.check_availability = true;

        let result = connector.simulate(req).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.would_succeed);
        assert!(response.availability.is_some());
        let avail = response.availability.unwrap();
        assert!(avail.available);
        assert_eq!(avail.rate_limit_remaining, Some(100));
    });
}

#[test]
fn test_simulate_denied_returns_reason() {
    let _ = fcp_async_core::runtime::block_on_sync(async {
        let connector = MockConnector::new("test:denied:v1").with_failure();
        let req = test_simulate_request("test:denied:v1", "test.operation");

        let result = connector.simulate(req).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.would_succeed);
        assert!(response.failure_reason.is_some());
        assert!(response.denial_code.is_some());
        assert_eq!(response.denial_code.unwrap(), "FCP-3001");
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// BaseConnector Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_base_connector_id() {
    let base = BaseConnector::new(ConnectorId::from_static("test:base:v1"));

    assert_eq!(base.id.as_str(), "test:base:v1");
}

#[test]
fn test_base_connector_check_ready_states() {
    let base = BaseConnector::new(ConnectorId::from_static("test:ready:v1"));

    // Initially not ready
    assert!(base.check_ready().is_err());

    // Set configured
    base.set_configured(true);
    assert!(base.check_ready().is_err()); // Still needs handshake

    // Set handshaken
    base.set_handshaken(true);
    assert!(base.check_ready().is_ok());
}

#[test]
fn test_base_connector_metrics_recording() {
    let base = BaseConnector::new(ConnectorId::from_static("test:metrics:v1"));

    // Record some requests
    base.record_request(true);
    base.record_request(true);
    base.record_request(false);

    let metrics = base.metrics();
    assert_eq!(metrics.requests_total, 3);
    assert_eq!(metrics.requests_success, 2);
    assert_eq!(metrics.requests_error, 1);
}

#[test]
fn test_base_connector_event_recording() {
    let base = BaseConnector::new(ConnectorId::from_static("test:events:v1"));

    base.record_event();
    base.record_event();

    let metrics = base.metrics();
    assert_eq!(metrics.events_emitted, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Request/Response Type Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_invoke_request_builder() {
    let req = InvokeRequest {
        r#type: "invoke".to_string(),
        id: fcp_sdk::RequestId::new("req-123"),
        connector_id: ConnectorId::from_static("test:builder:v1"),
        operation: fcp_sdk::OperationId::from_static("test.op"),
        zone_id: ZoneId::work(),
        input: json!({"key": "value"}),
        capability_token: test_capability_token(),
        holder_proof: None,
        context: None,
        idempotency_key: Some("idem-key-1".to_string()),
        lease_seq: None,
        deadline_ms: Some(5000),
        correlation_id: None,
        provenance: None,
        approval_tokens: vec![],
    };

    assert_eq!(req.r#type, "invoke");
    assert_eq!(req.id.0, "req-123");
    assert_eq!(req.connector_id.as_str(), "test:builder:v1");
    assert_eq!(req.idempotency_key, Some("idem-key-1".to_string()));
    assert_eq!(req.deadline_ms, Some(5000));
}

#[test]
fn test_invoke_response_ok() {
    let response = InvokeResponse::ok(
        fcp_sdk::RequestId::new("req-123"),
        json!({"result": "success"}),
    );

    assert_eq!(response.status, InvokeStatus::Ok);
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

#[test]
fn test_invoke_response_error() {
    let response = InvokeResponse::error(
        fcp_sdk::RequestId::new("req-123"),
        FcpError::Internal {
            message: "test error".to_string(),
        },
    );

    assert_eq!(response.status, InvokeStatus::Error);
    assert!(response.result.is_none());
    assert!(response.error.is_some());
}

#[test]
fn test_simulate_response_allowed() {
    let response = SimulateResponse::allowed(fcp_sdk::RequestId::new("sim-123"));

    assert!(response.would_succeed);
    assert!(response.failure_reason.is_none());
    assert!(response.denial_code.is_none());
    assert_eq!(
        response.missing_capabilities,
        [] as [std::string::String; 0]
    );
}

#[test]
fn test_simulate_response_denied() {
    let response = SimulateResponse::denied(
        fcp_sdk::RequestId::new("sim-123"),
        "Missing capability",
        "FCP-3001",
    );

    assert!(!response.would_succeed);
    assert_eq!(
        response.failure_reason,
        Some("Missing capability".to_string())
    );
    assert_eq!(response.denial_code, Some("FCP-3001".to_string()));
}

#[test]
fn test_simulate_response_with_missing_capabilities() {
    let response = SimulateResponse::denied(
        fcp_sdk::RequestId::new("sim-123"),
        "Missing capabilities",
        "FCP-3001",
    )
    .with_missing_capabilities(vec!["email.send".to_string(), "email.read".to_string()]);

    assert!(!response.would_succeed);
    assert_eq!(response.missing_capabilities.len(), 2);
    assert!(
        response
            .missing_capabilities
            .contains(&"email.send".to_string())
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// CostEstimate Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cost_estimate_with_credits() {
    let cost = CostEstimate::with_credits(100);

    assert_eq!(cost.api_credits, Some(100));
    assert!(cost.estimated_duration_ms.is_none());
    assert!(cost.estimated_bytes.is_none());
    assert!(cost.currency.is_none());
}

#[test]
fn test_cost_estimate_with_duration() {
    let cost = CostEstimate::with_duration_ms(500);

    assert!(cost.api_credits.is_none());
    assert_eq!(cost.estimated_duration_ms, Some(500));
}

#[test]
fn test_cost_estimate_with_bytes() {
    let cost = CostEstimate::with_bytes(1024);

    assert!(cost.api_credits.is_none());
    assert_eq!(cost.estimated_bytes, Some(1024));
}

#[test]
fn test_cost_estimate_builder_chain() {
    let cost = CostEstimate::with_credits(100)
        .and_duration_ms(500)
        .and_bytes(2048);

    assert_eq!(cost.api_credits, Some(100));
    assert_eq!(cost.estimated_duration_ms, Some(500));
    assert_eq!(cost.estimated_bytes, Some(2048));
}

#[test]
fn test_currency_cost() {
    let currency = CurrencyCost::new(1000, "USD");

    assert_eq!(currency.amount_cents, 1000);
    assert_eq!(currency.currency_code, "USD");
}

#[test]
fn test_currency_cost_usd_cents() {
    let currency = CurrencyCost::usd_cents(500);

    assert_eq!(currency.amount_cents, 500);
    assert_eq!(currency.currency_code, "USD");
}
