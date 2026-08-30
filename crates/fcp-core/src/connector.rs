//! Connector trait and base types.
//!
//! Based on FCP Specification Section 4 (System Architecture).

use std::fmt;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use futures_util::Stream;
use serde::{Deserialize, Serialize};

use crate::{
    CapabilityToken, ConnectorId, ConstraintsEnforced, EventAck, EventEnvelope, EventNack,
    FcpResult, HandshakeRequest, HandshakeResponse, HealthSnapshot, InstanceId, Introspection,
    InvokeRequest, InvokeResponse, RateLimitDeclarations, SelfCheckReport, ShutdownRequest,
    SimulateRequest, SimulateResponse, SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};

// ─────────────────────────────────────────────────────────────────────────────
// Sealed Trait Pattern (MOR/C3.6)
// ─────────────────────────────────────────────────────────────────────────────

/// Sealed module prevents external crates from implementing FCP connector traits.
///
/// All types that implement [`FcpConnector`] must also implement [`Sealed`](sealed::Sealed).
/// Use the `impl_fcp_sealed!` macro to satisfy this requirement.
#[doc(hidden)]
pub mod sealed {
    /// Marker trait that seals the FCP connector trait hierarchy.
    ///
    /// This trait cannot be implemented outside the FCP crate ecosystem.
    /// Use `impl_fcp_sealed!` to implement it for your connector type.
    pub trait Sealed {}
}

/// Implement the sealed marker trait for one or more connector types.
///
/// This is required for any type that implements [`FcpConnector`].
///
/// # Example
///
/// ```ignore
/// use fcp_core::impl_fcp_sealed;
///
/// struct MyConnector { /* ... */ }
/// impl_fcp_sealed!(MyConnector);
/// ```
#[macro_export]
macro_rules! impl_fcp_sealed {
    ($($ty:ty),+ $(,)?) => {
        $(impl $crate::sealed::Sealed for $ty {})+
    };
}

/// Type alias for event streams.
pub type EventStream = Pin<Box<dyn Stream<Item = FcpResult<EventEnvelope>> + Send>>;

/// Core connector trait - all FCP connectors must implement this.
///
/// This trait is **sealed** — external crates must use `impl_fcp_sealed!`
/// to satisfy the `Sealed` supertrait before implementing `FcpConnector`.
#[async_trait]
pub trait FcpConnector: sealed::Sealed + Send + Sync {
    /// Get the connector's unique identifier.
    fn id(&self) -> &ConnectorId;

    /// Configure the connector with the given settings.
    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()>;

    /// Perform the FCP handshake.
    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse>;

    /// Get the current health status.
    async fn health(&self) -> HealthSnapshot;

    /// Run a connector self-check (read-only, bounded).
    ///
    /// **Contract:**
    /// - MUST NOT perform side effects (read-only checks only).
    /// - MUST be bounded by timeouts in the caller/host.
    /// - SHOULD return stable `reason_code` values for degraded/failed states.
    ///
    /// Default implementation reports `unsupported`.
    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        Ok(SelfCheckReport::unsupported())
    }

    /// Get connector metrics.
    fn metrics(&self) -> ConnectorMetrics;

    /// Gracefully shutdown the connector.
    async fn shutdown(&mut self, req: ShutdownRequest) -> FcpResult<()>;

    /// Get introspection data describing capabilities.
    fn introspect(&self) -> Introspection;

    /// Declare connector rate limits for planning and observability.
    ///
    /// Default: the connector did not declare rate limits through this surface.
    fn rate_limits(&self) -> Option<RateLimitDeclarations> {
        None
    }

    /// Invoke an operation.
    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse>;

    /// Simulate an operation (preflight check).
    ///
    /// Per FCP Specification Section 9.4:
    /// Allows callers to check if an operation would succeed (capability check,
    /// resource availability, cost estimation) without executing it.
    ///
    /// **Hard Requirements:**
    /// - **No side effects:** simulate MUST NOT perform external writes or mutate external state.
    /// - **Policy-aware:** simulate must reflect capability/policy gating as closely as invoke.
    /// - **Deterministic & bounded:** checks must be bounded (timeouts, size limits).
    ///
    /// Connectors MUST override simulate for each operation they support.
    /// The default implementation denies all operations (default-deny principle).
    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        // Default-deny: connectors that have not explicitly validated an operation
        // must not silently claim it would succeed.
        Ok(SimulateResponse::denied(
            req.id,
            "Operation not simulated: connector has not implemented simulate() for this operation",
            "FCP-3010",
        ))
    }

    /// Subscribe to event topics.
    async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse>;

    /// Unsubscribe from event topics.
    async fn unsubscribe(&self, req: UnsubscribeRequest) -> FcpResult<()>;

    /// Acknowledge delivery of events (when `requires_ack=true`).
    ///
    /// Connectors that track delivery state should override this to
    /// update their replay buffers and pending-ack sets.
    async fn ack(&self, _ack: EventAck) -> FcpResult<()> {
        Ok(())
    }

    /// Negative acknowledgment (request redelivery).
    ///
    /// Connectors that support redelivery should override this.
    async fn nack(&self, _nack: EventNack) -> FcpResult<()> {
        Ok(())
    }
}

/// Connector metrics for monitoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectorMetrics {
    /// Total requests received
    pub requests_total: u64,
    /// Successful requests
    pub requests_success: u64,
    /// Failed requests
    pub requests_error: u64,
    /// Active connections/sessions
    pub connections_active: u64,
    /// Events emitted
    pub events_emitted: u64,
    /// Current request latency (p50) in milliseconds
    pub latency_p50_ms: u64,
    /// Current request latency (p99) in milliseconds
    pub latency_p99_ms: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
}

impl fmt::Display for ConnectorMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "requests_total={} requests_success={} requests_error={} connections_active={} events_emitted={} latency_p50_ms={} latency_p99_ms={} bytes_sent={} bytes_received={}",
            self.requests_total,
            self.requests_success,
            self.requests_error,
            self.connections_active,
            self.events_emitted,
            self.latency_p50_ms,
            self.latency_p99_ms,
            self.bytes_sent,
            self.bytes_received
        )
    }
}

/// Runtime lifecycle state for a connector instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorLifecycleState {
    /// Connector binary and metadata are loaded but not yet active.
    Loaded,
    /// Connector has completed activation and is ready to run.
    Activated,
    /// Connector is actively running.
    Running,
    /// Connector is suspended and may be resumed.
    Suspended,
    /// Connector has terminated and cannot resume.
    Terminated,
}

/// Canonical connector interaction route.
///
/// This is the closed vocabulary used to classify the primary interaction
/// pattern a connector exposes to hosts, CLIs, and conformance fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorRoute {
    /// Request/response APIs such as REST, GraphQL, or gRPC.
    RequestResponse,
    /// Continuous server-to-agent streams such as SSE, WebSocket, or logs.
    Streaming,
    /// Full-duplex real-time communication.
    Bidirectional,
    /// Periodic fetch or cursor/offset-based synchronization.
    Polling,
    /// Inbound callbacks from external services.
    Webhook,
    /// Queue or pub/sub integrations.
    Queue,
    /// File/blob storage operations.
    File,
    /// Database query and mutation operations.
    Database,
    /// CLI/process wrapper connectors.
    Cli,
    /// Browser automation or scraping connectors.
    Browser,
}

impl ConnectorRoute {
    /// Return the canonical wire/display tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestResponse => "request-response",
            Self::Streaming => "streaming",
            Self::Bidirectional => "bidirectional",
            Self::Polling => "polling",
            Self::Webhook => "webhook",
            Self::Queue => "queue",
            Self::File => "file",
            Self::Database => "database",
            Self::Cli => "cli",
            Self::Browser => "browser",
        }
    }
}

impl fmt::Display for ConnectorRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ConnectorLifecycleState {
    /// Return the canonical wire/display string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Activated => "activated",
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Terminated => "terminated",
        }
    }
}

impl fmt::Display for ConnectorLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ConnectorLifecycleState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "loaded" => Ok(Self::Loaded),
            "activated" => Ok(Self::Activated),
            "running" => Ok(Self::Running),
            "suspended" => Ok(Self::Suspended),
            "terminated" => Ok(Self::Terminated),
            _ => Err(format!(
                "invalid connector lifecycle state `{value}`: expected one of loaded, activated, running, suspended, terminated"
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Archetype Traits
// ─────────────────────────────────────────────────────────────────────────────

/// Request-response archetype (e.g., REST API, GraphQL).
#[async_trait]
pub trait RequestResponse: FcpConnector {
    /// Send a request and wait for a response.
    async fn request(&self, req: InvokeRequest) -> FcpResult<InvokeResponse>;
}

/// Streaming archetype (e.g., WebSocket, SSE).
#[async_trait]
pub trait Streaming: FcpConnector {
    /// Subscribe to a stream.
    async fn stream_subscribe(&self, topic: &str) -> FcpResult<EventStream>;

    /// Get event stream.
    fn events(&self) -> EventStream;
}

/// Bidirectional archetype (e.g., WebSocket chat).
#[async_trait]
pub trait Bidirectional: Streaming {
    /// Send a message to the stream.
    async fn send(&self, message: serde_json::Value) -> FcpResult<()>;
}

/// Polling archetype (e.g., IMAP, RSS).
#[async_trait]
pub trait Polling: FcpConnector {
    /// Start polling a target.
    ///
    /// Requires a `CapabilityToken<ConstraintsEnforced>` (cryptographic
    /// verification, instance binding, and request-level capability
    /// constraints all passed). The connector runtime — the enforcement point
    /// — is expected to call [`CapabilityVerifier::verify_bound`](crate::capability::CapabilityVerifier::verify_bound) or promote an
    /// [`UnboundVerified`](crate::capability::UnboundVerified) token via [`CapabilityToken::promote_with_instance`],
    /// then [`CapabilityToken::promote_with_constraints`] before calling these
    /// methods.
    async fn start_polling(
        &self,
        target: &str,
        interval: Option<std::time::Duration>,
        token: &CapabilityToken<ConstraintsEnforced>,
    ) -> FcpResult<()>;

    /// Stop polling a target.
    async fn stop_polling(
        &self,
        target: &str,
        token: &CapabilityToken<ConstraintsEnforced>,
    ) -> FcpResult<()>;

    /// Trigger immediate poll.
    async fn poll_now(
        &self,
        target: &str,
        token: &CapabilityToken<ConstraintsEnforced>,
    ) -> FcpResult<usize>;

    /// Get event stream.
    fn events(&self) -> EventStream;
}

/// Webhook archetype (e.g., GitHub, Stripe).
#[async_trait]
pub trait Webhook: FcpConnector {
    /// Register a webhook handler.
    ///
    /// Requires a `CapabilityToken<ConstraintsEnforced>` — the connector
    /// runtime must verify/promote the token and evaluate request-level
    /// capability constraints before calling this method.
    async fn register_handler(
        &self,
        source: &str,
        token: &CapabilityToken<ConstraintsEnforced>,
    ) -> FcpResult<()>;

    /// Get the webhook URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector cannot produce a webhook URL for `source`.
    fn webhook_url(&self, source: &str) -> FcpResult<String>;

    /// Get event stream.
    fn events(&self) -> EventStream;
}

// ─────────────────────────────────────────────────────────────────────────────
// Base Connector Implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Base connector state that can be reused by implementations.
#[derive(Debug)]
pub struct BaseConnector {
    /// Connector ID
    pub id: ConnectorId,
    /// Instance ID (unique per run)
    pub instance_id: InstanceId,
    /// Whether configured
    pub configured: AtomicBool,
    /// Whether handshake completed
    pub handshaken: AtomicBool,
    /// Metrics (internal atomic storage)
    metrics: AtomicConnectorMetrics,
}

#[derive(Debug, Default)]
struct AtomicConnectorMetrics {
    requests_total: AtomicU64,
    requests_success: AtomicU64,
    requests_error: AtomicU64,
    connections_active: AtomicU64,
    events_emitted: AtomicU64,
    latency_p50_ms: AtomicU64,
    latency_p99_ms: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

impl sealed::Sealed for BaseConnector {}

impl BaseConnector {
    /// Create a new base connector.
    #[must_use]
    pub fn new(id: impl Into<ConnectorId>) -> Self {
        Self {
            id: id.into(),
            instance_id: InstanceId::new(),
            configured: AtomicBool::new(false),
            handshaken: AtomicBool::new(false),
            metrics: AtomicConnectorMetrics::default(),
        }
    }

    /// Check if the connector is ready.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `FcpError::NotConfigured` if `configure` has not completed.
    /// - `FcpError::NotHandshaken` if `handshake` has not completed.
    pub fn check_ready(&self) -> FcpResult<()> {
        if !self.configured.load(Ordering::Acquire) {
            return Err(crate::FcpError::NotConfigured);
        }
        if !self.handshaken.load(Ordering::Acquire) {
            return Err(crate::FcpError::NotHandshaken);
        }
        Ok(())
    }

    /// Set configured state.
    pub fn set_configured(&self, configured: bool) {
        self.configured.store(configured, Ordering::Release);
    }

    /// Set handshaken state.
    pub fn set_handshaken(&self, handshaken: bool) {
        self.handshaken.store(handshaken, Ordering::Release);
    }

    /// Increment request count.
    pub fn record_request(&self, success: bool) {
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        if success {
            self.metrics
                .requests_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics.requests_error.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment event count.
    pub fn record_event(&self) {
        self.metrics.events_emitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of current metrics.
    pub fn metrics(&self) -> ConnectorMetrics {
        ConnectorMetrics {
            requests_total: self.metrics.requests_total.load(Ordering::Relaxed),
            requests_success: self.metrics.requests_success.load(Ordering::Relaxed),
            requests_error: self.metrics.requests_error.load(Ordering::Relaxed),
            connections_active: self.metrics.connections_active.load(Ordering::Relaxed),
            events_emitted: self.metrics.events_emitted.load(Ordering::Relaxed),
            latency_p50_ms: self.metrics.latency_p50_ms.load(Ordering::Relaxed),
            latency_p99_ms: self.metrics.latency_p99_ms.load(Ordering::Relaxed),
            bytes_sent: self.metrics.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.metrics.bytes_received.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────────
    // ConnectorMetrics tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_default() {
        let metrics = ConnectorMetrics::default();

        assert_eq!(metrics.requests_total, 0);
        assert_eq!(metrics.requests_success, 0);
        assert_eq!(metrics.requests_error, 0);
        assert_eq!(metrics.connections_active, 0);
        assert_eq!(metrics.events_emitted, 0);
        assert_eq!(metrics.latency_p50_ms, 0);
        assert_eq!(metrics.latency_p99_ms, 0);
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
    }

    #[test]
    fn connector_metrics_clone() {
        let metrics = ConnectorMetrics {
            requests_total: 100,
            requests_success: 95,
            ..Default::default()
        };

        // Clone and verify both copies have correct values
        let cloned = metrics.clone();
        assert_eq!(metrics.requests_total, 100);
        assert_eq!(cloned.requests_total, 100);
        assert_eq!(cloned.requests_success, 95);
    }

    #[test]
    fn connector_metrics_debug() {
        let metrics = ConnectorMetrics::default();
        let debug = format!("{metrics:?}");

        assert!(debug.contains("ConnectorMetrics"));
        assert!(debug.contains("requests_total"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // BaseConnector tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn base_connector_new() {
        let id = ConnectorId::from_static("my:connector:v1");
        let base = BaseConnector::new(id);

        assert_eq!(base.id.as_str(), "my:connector:v1");
        assert!(!base.configured.load(std::sync::atomic::Ordering::Relaxed));
        assert!(!base.handshaken.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(base.metrics().requests_total, 0);
    }

    #[test]
    fn base_connector_new_with_connector_id() {
        let id = ConnectorId::new("test", "streaming", "v1").unwrap();
        let base = BaseConnector::new(id);

        assert_eq!(base.id.as_str(), "test:streaming:v1");
    }

    fn test_connector_id() -> ConnectorId {
        ConnectorId::from_static("test:base:v1")
    }

    #[test]
    fn base_connector_check_ready_not_configured() {
        let base = BaseConnector::new(test_connector_id());

        let result = base.check_ready();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::FcpError::NotConfigured
        ));
    }

    #[test]
    fn base_connector_check_ready_not_handshaken() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);

        let result = base.check_ready();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::FcpError::NotHandshaken
        ));
    }

    #[test]
    fn base_connector_check_ready_success() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_handshaken(true);

        let result = base.check_ready();

        assert!(result.is_ok());
    }

    #[test]
    fn base_connector_record_request_success() {
        let base = BaseConnector::new(test_connector_id());

        base.record_request(true);

        assert_eq!(base.metrics().requests_total, 1);
        assert_eq!(base.metrics().requests_success, 1);
        assert_eq!(base.metrics().requests_error, 0);
    }

    #[test]
    fn base_connector_record_request_failure() {
        let base = BaseConnector::new(test_connector_id());

        base.record_request(false);

        assert_eq!(base.metrics().requests_total, 1);
        assert_eq!(base.metrics().requests_success, 0);
        assert_eq!(base.metrics().requests_error, 1);
    }

    #[test]
    fn base_connector_record_request_multiple() {
        let base = BaseConnector::new(test_connector_id());

        base.record_request(true);
        base.record_request(true);
        base.record_request(false);
        base.record_request(true);
        base.record_request(false);

        assert_eq!(base.metrics().requests_total, 5);
        assert_eq!(base.metrics().requests_success, 3);
        assert_eq!(base.metrics().requests_error, 2);
    }

    #[test]
    fn base_connector_record_event() {
        let base = BaseConnector::new(test_connector_id());

        base.record_event();
        base.record_event();
        base.record_event();

        assert_eq!(base.metrics().events_emitted, 3);
    }

    #[test]
    fn base_connector_debug() {
        let base = BaseConnector::new(ConnectorId::from_static("debug:test:v1"));
        let debug = format!("{base:?}");

        assert!(debug.contains("BaseConnector"));
        assert!(debug.contains("debug:test:v1"));
        assert!(debug.contains("configured"));
        assert!(debug.contains("handshaken"));
    }

    #[test]
    fn base_connector_lifecycle() {
        // Test typical connector lifecycle
        let base = BaseConnector::new(ConnectorId::from_static("lifecycle:connector:v1"));

        // Initially not ready
        assert!(base.check_ready().is_err());

        // After configuration
        base.set_configured(true);
        assert!(base.check_ready().is_err());

        // After handshake
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Record some activity
        base.record_request(true);
        base.record_request(true);
        base.record_request(false);
        base.record_event();
        base.record_event();

        assert_eq!(base.metrics().requests_total, 3);
        assert_eq!(base.metrics().requests_success, 2);
        assert_eq!(base.metrics().requests_error, 1);
        assert_eq!(base.metrics().events_emitted, 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional ConnectorMetrics tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_serde_roundtrip() {
        let metrics = ConnectorMetrics {
            requests_total: 1000,
            requests_success: 950,
            requests_error: 50,
            connections_active: 12,
            events_emitted: 500,
            latency_p50_ms: 45,
            latency_p99_ms: 250,
            bytes_sent: 1_000_000,
            bytes_received: 2_000_000,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.requests_total, 1000);
        assert_eq!(decoded.requests_success, 950);
        assert_eq!(decoded.requests_error, 50);
        assert_eq!(decoded.connections_active, 12);
        assert_eq!(decoded.events_emitted, 500);
        assert_eq!(decoded.latency_p50_ms, 45);
        assert_eq!(decoded.latency_p99_ms, 250);
        assert_eq!(decoded.bytes_sent, 1_000_000);
        assert_eq!(decoded.bytes_received, 2_000_000);
    }

    #[test]
    fn connector_metrics_partial_init() {
        let metrics = ConnectorMetrics {
            requests_total: 42,
            latency_p99_ms: 100,
            ..Default::default()
        };
        assert_eq!(metrics.requests_total, 42);
        assert_eq!(metrics.latency_p99_ms, 100);
        assert_eq!(metrics.requests_success, 0);
        assert_eq!(metrics.bytes_sent, 0);
    }

    #[test]
    fn connector_metrics_json_fields() {
        let metrics = ConnectorMetrics::default();
        let value = serde_json::to_value(&metrics).unwrap();
        for field in [
            "requests_total",
            "requests_success",
            "requests_error",
            "connections_active",
            "events_emitted",
            "latency_p50_ms",
            "latency_p99_ms",
            "bytes_sent",
            "bytes_received",
        ] {
            assert!(value.get(field).is_some(), "missing field: {field}");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional BaseConnector tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn base_connector_instance_id_unique() {
        let a = BaseConnector::new(test_connector_id());
        let b = BaseConnector::new(test_connector_id());
        // Instance IDs should be unique for each BaseConnector
        assert_ne!(
            a.instance_id.as_str(),
            b.instance_id.as_str(),
            "instance IDs should be unique"
        );
    }

    #[test]
    fn base_connector_metrics_initially_zero() {
        let base = BaseConnector::new(test_connector_id());
        let m = base.metrics();
        assert_eq!(m.requests_total, 0);
        assert_eq!(m.requests_success, 0);
        assert_eq!(m.requests_error, 0);
        assert_eq!(m.connections_active, 0);
        assert_eq!(m.events_emitted, 0);
        assert_eq!(m.latency_p50_ms, 0);
        assert_eq!(m.latency_p99_ms, 0);
        assert_eq!(m.bytes_sent, 0);
        assert_eq!(m.bytes_received, 0);
    }

    #[test]
    fn base_connector_set_configured_toggle() {
        let base = BaseConnector::new(test_connector_id());
        assert!(!base.configured.load(Ordering::Relaxed));

        base.set_configured(true);
        assert!(base.configured.load(Ordering::Relaxed));

        base.set_configured(false);
        assert!(!base.configured.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_set_handshaken_toggle() {
        let base = BaseConnector::new(test_connector_id());
        assert!(!base.handshaken.load(Ordering::Relaxed));

        base.set_handshaken(true);
        assert!(base.handshaken.load(Ordering::Relaxed));

        base.set_handshaken(false);
        assert!(!base.handshaken.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_metrics_snapshot_independent() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);

        let snapshot1 = base.metrics();
        base.record_request(true);
        let snapshot2 = base.metrics();

        // Snapshot values are independent
        assert_eq!(snapshot1.requests_total, 1);
        assert_eq!(snapshot2.requests_total, 2);
    }

    #[test]
    fn base_connector_check_ready_reconfigure() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Deconfigure -> no longer ready
        base.set_configured(false);
        assert!(base.check_ready().is_err());

        // Reconfigure -> ready again
        base.set_configured(true);
        assert!(base.check_ready().is_ok());
    }

    #[test]
    fn base_connector_mixed_success_failure() {
        let base = BaseConnector::new(test_connector_id());
        for i in 0..100 {
            base.record_request(i % 3 != 0);
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, 100);
        // i=0,3,6,...,99 => failures = 34 (0..100 step 3)
        assert_eq!(m.requests_error, 34);
        assert_eq!(m.requests_success, 66);
    }

    #[test]
    fn base_connector_many_events() {
        let base = BaseConnector::new(test_connector_id());
        for _ in 0..1000 {
            base.record_event();
        }
        assert_eq!(base.metrics().events_emitted, 1000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorMetrics – boundary values
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_max_values() {
        let metrics = ConnectorMetrics {
            requests_total: u64::MAX,
            requests_success: u64::MAX,
            requests_error: u64::MAX,
            connections_active: u64::MAX,
            events_emitted: u64::MAX,
            latency_p50_ms: u64::MAX,
            latency_p99_ms: u64::MAX,
            bytes_sent: u64::MAX,
            bytes_received: u64::MAX,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.requests_total, u64::MAX);
        assert_eq!(decoded.bytes_received, u64::MAX);
    }

    #[test]
    fn connector_metrics_deserialize_from_literal() {
        let raw = r#"{
            "requests_total": 42,
            "requests_success": 40,
            "requests_error": 2,
            "connections_active": 5,
            "events_emitted": 100,
            "latency_p50_ms": 10,
            "latency_p99_ms": 200,
            "bytes_sent": 9999,
            "bytes_received": 8888
        }"#;
        let m: ConnectorMetrics = serde_json::from_str(raw).unwrap();
        assert_eq!(m.requests_total, 42);
        assert_eq!(m.connections_active, 5);
        assert_eq!(m.latency_p50_ms, 10);
        assert_eq!(m.bytes_sent, 9999);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BaseConnector – edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn base_connector_from_string_id() {
        let base = BaseConnector::new(ConnectorId::from_static("fcp.slack:streaming:1"));
        assert_eq!(base.id.as_str(), "fcp.slack:streaming:1");
    }

    #[test]
    fn base_connector_check_ready_sequence_matters() {
        let base = BaseConnector::new(test_connector_id());
        // Only handshaken, not configured → still not ready
        base.set_handshaken(true);
        let err = base.check_ready().unwrap_err();
        assert!(matches!(err, crate::FcpError::NotConfigured));
    }

    #[test]
    fn base_connector_record_only_failures() {
        let base = BaseConnector::new(test_connector_id());
        for _ in 0..50 {
            base.record_request(false);
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, 50);
        assert_eq!(m.requests_success, 0);
        assert_eq!(m.requests_error, 50);
    }

    #[test]
    fn base_connector_record_only_successes() {
        let base = BaseConnector::new(test_connector_id());
        for _ in 0..50 {
            base.record_request(true);
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, 50);
        assert_eq!(m.requests_success, 50);
        assert_eq!(m.requests_error, 0);
    }

    #[test]
    fn base_connector_events_independent_of_requests() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        base.record_event();
        base.record_event();
        let m = base.metrics();
        assert_eq!(m.requests_total, 1);
        assert_eq!(m.events_emitted, 2);
    }

    #[test]
    fn base_connector_multiple_metrics_snapshots_diverge() {
        let base = BaseConnector::new(test_connector_id());
        let snap1 = base.metrics();
        base.record_request(true);
        base.record_request(true);
        base.record_request(true);
        let snap2 = base.metrics();
        base.record_event();
        let snap3 = base.metrics();
        assert_eq!(snap1.requests_total, 0);
        assert_eq!(snap2.requests_total, 3);
        assert_eq!(snap3.requests_total, 3);
        assert_eq!(snap3.events_emitted, 1);
        assert_eq!(snap2.events_emitted, 0);
    }

    #[test]
    fn connector_id_equality_in_base_connector() {
        let a = BaseConnector::new(ConnectorId::from_static("fcp.a:rr:1"));
        let b = BaseConnector::new(ConnectorId::from_static("fcp.a:rr:1"));
        assert_eq!(a.id, b.id);
        // But instance IDs differ
        assert_ne!(a.instance_id.as_str(), b.instance_id.as_str());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New tests – deeper coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_clone_is_independent() {
        let original = ConnectorMetrics {
            requests_total: 10,
            requests_success: 8,
            requests_error: 2,
            connections_active: 3,
            events_emitted: 50,
            latency_p50_ms: 15,
            latency_p99_ms: 120,
            bytes_sent: 4096,
            bytes_received: 8192,
        };
        let mut cloned = original.clone();
        cloned.requests_total = 999;
        cloned.bytes_sent = 0;
        // Original unaffected by mutation of clone
        assert_eq!(original.requests_total, 10);
        assert_eq!(original.bytes_sent, 4096);
        assert_eq!(cloned.requests_total, 999);
        assert_eq!(cloned.bytes_sent, 0);
    }

    #[test]
    fn connector_metrics_all_fields_populated() {
        let metrics = ConnectorMetrics {
            requests_total: 1,
            requests_success: 2,
            requests_error: 3,
            connections_active: 4,
            events_emitted: 5,
            latency_p50_ms: 6,
            latency_p99_ms: 7,
            bytes_sent: 8,
            bytes_received: 9,
        };
        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.requests_success, 2);
        assert_eq!(metrics.requests_error, 3);
        assert_eq!(metrics.connections_active, 4);
        assert_eq!(metrics.events_emitted, 5);
        assert_eq!(metrics.latency_p50_ms, 6);
        assert_eq!(metrics.latency_p99_ms, 7);
        assert_eq!(metrics.bytes_sent, 8);
        assert_eq!(metrics.bytes_received, 9);
    }

    #[test]
    fn connector_metrics_serde_extra_fields_ignored() {
        // serde default: unknown fields are ignored during deserialization
        let raw = r#"{
            "requests_total": 5,
            "requests_success": 4,
            "requests_error": 1,
            "connections_active": 0,
            "events_emitted": 0,
            "latency_p50_ms": 0,
            "latency_p99_ms": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "extra_field": 42
        }"#;
        let m: ConnectorMetrics = serde_json::from_str(raw).unwrap();
        assert_eq!(m.requests_total, 5);
        assert_eq!(m.requests_success, 4);
        assert_eq!(m.requests_error, 1);
    }

    #[test]
    fn connector_metrics_serde_missing_field_fails() {
        // All fields are required (no #[serde(default)])
        let raw = r#"{"requests_total": 5}"#;
        let result = serde_json::from_str::<ConnectorMetrics>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn connector_metrics_debug_contains_all_fields() {
        let metrics = ConnectorMetrics {
            requests_total: 11,
            requests_success: 22,
            requests_error: 33,
            connections_active: 44,
            events_emitted: 55,
            latency_p50_ms: 66,
            latency_p99_ms: 77,
            bytes_sent: 88,
            bytes_received: 99,
        };
        let dbg = format!("{metrics:?}");
        assert!(dbg.contains("requests_success"));
        assert!(dbg.contains("requests_error"));
        assert!(dbg.contains("connections_active"));
        assert!(dbg.contains("events_emitted"));
        assert!(dbg.contains("latency_p50_ms"));
        assert!(dbg.contains("latency_p99_ms"));
        assert!(dbg.contains("bytes_sent"));
        assert!(dbg.contains("bytes_received"));
    }

    #[test]
    fn connector_metrics_serde_roundtrip_zeros() {
        let metrics = ConnectorMetrics::default();
        let json = serde_json::to_string(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.requests_total, 0);
        assert_eq!(decoded.latency_p99_ms, 0);
        assert_eq!(decoded.bytes_received, 0);
    }

    #[test]
    fn connector_metrics_json_value_types() {
        let metrics = ConnectorMetrics {
            requests_total: 7,
            ..Default::default()
        };
        let value = serde_json::to_value(&metrics).unwrap();
        // All fields should serialize as numbers
        assert!(value["requests_total"].is_number());
        assert!(value["latency_p50_ms"].is_number());
        assert!(value["bytes_sent"].is_number());
        assert_eq!(value["requests_total"].as_u64(), Some(7));
    }

    #[test]
    fn base_connector_check_ready_error_display() {
        let base = BaseConnector::new(test_connector_id());
        let err = base.check_ready().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not configured") || msg.contains("NotConfigured"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn base_connector_check_ready_not_handshaken_error_display() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        let err = base.check_ready().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not handshaken") || msg.contains("NotHandshaken"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn base_connector_dehandshake_reverts_ready() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Remove handshake
        base.set_handshaken(false);
        let err = base.check_ready().unwrap_err();
        assert!(matches!(err, crate::FcpError::NotHandshaken));
    }

    #[test]
    fn base_connector_repeated_set_configured_idempotent() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_configured(true);
        base.set_configured(true);
        assert!(base.configured.load(Ordering::Relaxed));

        base.set_configured(false);
        base.set_configured(false);
        assert!(!base.configured.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_repeated_set_handshaken_idempotent() {
        let base = BaseConnector::new(test_connector_id());
        base.set_handshaken(true);
        base.set_handshaken(true);
        assert!(base.handshaken.load(Ordering::Relaxed));

        base.set_handshaken(false);
        base.set_handshaken(false);
        assert!(!base.handshaken.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_metrics_unaffected_by_state_changes() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        base.record_event();

        // Changing configured/handshaken should not reset metrics
        base.set_configured(true);
        base.set_handshaken(true);
        base.set_configured(false);
        base.set_handshaken(false);

        let m = base.metrics();
        assert_eq!(m.requests_total, 1);
        assert_eq!(m.requests_success, 1);
        assert_eq!(m.events_emitted, 1);
    }

    #[test]
    fn base_connector_instance_id_format() {
        let base = BaseConnector::new(test_connector_id());
        let iid = base.instance_id.as_str();
        // InstanceId should be non-empty
        assert!(!iid.is_empty(), "instance ID should not be empty");
    }

    #[test]
    fn base_connector_debug_includes_metrics() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        let dbg = format!("{base:?}");
        assert!(dbg.contains("instance_id"));
        assert!(dbg.contains("metrics"));
    }

    #[test]
    fn base_connector_interleaved_requests_and_events() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        base.record_event();
        base.record_request(false);
        base.record_event();
        base.record_event();
        base.record_request(true);

        let m = base.metrics();
        assert_eq!(m.requests_total, 3);
        assert_eq!(m.requests_success, 2);
        assert_eq!(m.requests_error, 1);
        assert_eq!(m.events_emitted, 3);
    }

    #[test]
    fn base_connector_high_volume_requests() {
        let base = BaseConnector::new(test_connector_id());
        let count: u64 = 10_000;
        for _ in 0..count {
            base.record_request(true);
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, count);
        assert_eq!(m.requests_success, count);
        assert_eq!(m.requests_error, 0);
    }

    #[test]
    fn base_connector_high_volume_events() {
        let base = BaseConnector::new(test_connector_id());
        let count: u64 = 10_000;
        for _ in 0..count {
            base.record_event();
        }
        assert_eq!(base.metrics().events_emitted, count);
    }

    #[test]
    fn base_connector_zero_requests_zero_events() {
        let base = BaseConnector::new(test_connector_id());
        let m = base.metrics();
        assert_eq!(m.requests_total, 0);
        assert_eq!(m.events_emitted, 0);
        assert_eq!(m.connections_active, 0);
    }

    #[test]
    fn base_connector_check_ready_returns_unit() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_handshaken(true);
        let result: FcpResult<()> = base.check_ready();
        assert_eq!(result.unwrap(), ());
    }

    #[test]
    fn base_connector_different_ids_different_connectors() {
        let a = BaseConnector::new(ConnectorId::from_static("alpha:rr:v1"));
        let b = BaseConnector::new(ConnectorId::from_static("beta:streaming:v2"));
        assert_ne!(a.id.as_str(), b.id.as_str());
        assert_ne!(a.instance_id.as_str(), b.instance_id.as_str());
    }

    #[test]
    fn base_connector_new_does_not_start_ready() {
        let base = BaseConnector::new(ConnectorId::from_static("fresh:connector:v1"));
        assert!(base.check_ready().is_err());
        assert!(!base.configured.load(Ordering::Relaxed));
        assert!(!base.handshaken.load(Ordering::Relaxed));
    }

    #[test]
    fn connector_metrics_serde_via_value() {
        let metrics = ConnectorMetrics {
            requests_total: 500,
            requests_success: 490,
            requests_error: 10,
            connections_active: 7,
            events_emitted: 200,
            latency_p50_ms: 25,
            latency_p99_ms: 180,
            bytes_sent: 65_536,
            bytes_received: 131_072,
        };
        let json = serde_json::to_value(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.requests_total, 500);
        assert_eq!(decoded.requests_success, 490);
        assert_eq!(decoded.requests_error, 10);
        assert_eq!(decoded.connections_active, 7);
        assert_eq!(decoded.events_emitted, 200);
        assert_eq!(decoded.latency_p50_ms, 25);
        assert_eq!(decoded.latency_p99_ms, 180);
        assert_eq!(decoded.bytes_sent, 65_536);
        assert_eq!(decoded.bytes_received, 131_072);
    }

    #[test]
    fn base_connector_metrics_snapshot_after_no_activity() {
        let base = BaseConnector::new(test_connector_id());
        // Taking multiple snapshots without activity should all be zero
        let s1 = base.metrics();
        let s2 = base.metrics();
        let s3 = base.metrics();
        assert_eq!(s1.requests_total, 0);
        assert_eq!(s2.requests_total, 0);
        assert_eq!(s3.requests_total, 0);
    }

    #[test]
    fn base_connector_check_ready_configured_false_handshaken_false() {
        let base = BaseConnector::new(test_connector_id());
        // Both false: should get NotConfigured (checked first)
        let err = base.check_ready().unwrap_err();
        assert!(matches!(err, crate::FcpError::NotConfigured));
    }

    #[test]
    fn base_connector_full_state_cycle() {
        let base = BaseConnector::new(test_connector_id());

        // Phase 1: unconfigured
        assert!(base.check_ready().is_err());

        // Phase 2: configure
        base.set_configured(true);
        assert!(base.check_ready().is_err());

        // Phase 3: handshake -> ready
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Phase 4: do work
        base.record_request(true);
        base.record_request(false);
        base.record_event();

        // Phase 5: deconfigure (simulating shutdown)
        base.set_configured(false);
        base.set_handshaken(false);
        assert!(base.check_ready().is_err());

        // Phase 6: metrics survive state changes
        let m = base.metrics();
        assert_eq!(m.requests_total, 2);
        assert_eq!(m.events_emitted, 1);

        // Phase 7: reconfigure
        base.set_configured(true);
        base.set_handshaken(true);
        assert!(base.check_ready().is_ok());

        // Phase 8: more work accumulates
        base.record_request(true);
        let m = base.metrics();
        assert_eq!(m.requests_total, 3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorMetrics – serde edge cases & structural tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_metrics_serde_negative_number_fails() {
        let raw = r#"{
            "requests_total": -1,
            "requests_success": 0,
            "requests_error": 0,
            "connections_active": 0,
            "events_emitted": 0,
            "latency_p50_ms": 0,
            "latency_p99_ms": 0,
            "bytes_sent": 0,
            "bytes_received": 0
        }"#;
        let result = serde_json::from_str::<ConnectorMetrics>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn connector_metrics_serde_float_value_fails() {
        let raw = r#"{
            "requests_total": 1.5,
            "requests_success": 0,
            "requests_error": 0,
            "connections_active": 0,
            "events_emitted": 0,
            "latency_p50_ms": 0,
            "latency_p99_ms": 0,
            "bytes_sent": 0,
            "bytes_received": 0
        }"#;
        let result = serde_json::from_str::<ConnectorMetrics>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn connector_metrics_serde_null_field_fails() {
        let raw = r#"{
            "requests_total": null,
            "requests_success": 0,
            "requests_error": 0,
            "connections_active": 0,
            "events_emitted": 0,
            "latency_p50_ms": 0,
            "latency_p99_ms": 0,
            "bytes_sent": 0,
            "bytes_received": 0
        }"#;
        let result = serde_json::from_str::<ConnectorMetrics>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn connector_metrics_serde_string_field_fails() {
        let raw = r#"{
            "requests_total": "five",
            "requests_success": 0,
            "requests_error": 0,
            "connections_active": 0,
            "events_emitted": 0,
            "latency_p50_ms": 0,
            "latency_p99_ms": 0,
            "bytes_sent": 0,
            "bytes_received": 0
        }"#;
        let result = serde_json::from_str::<ConnectorMetrics>(raw);
        assert!(result.is_err());
    }

    #[test]
    fn connector_metrics_serde_empty_json_object_fails() {
        let result = serde_json::from_str::<ConnectorMetrics>("{}");
        assert!(result.is_err());
    }

    #[test]
    fn connector_metrics_serde_json_array_fails() {
        let result = serde_json::from_str::<ConnectorMetrics>("[1,2,3]");
        assert!(result.is_err());
    }

    #[test]
    fn connector_metrics_serde_json_null_fails() {
        let result = serde_json::from_str::<ConnectorMetrics>("null");
        assert!(result.is_err());
    }

    #[test]
    fn connector_metrics_serde_large_values() {
        let metrics = ConnectorMetrics {
            requests_total: 999_999_999_999,
            requests_success: 888_888_888_888,
            requests_error: 111_111_111_111,
            connections_active: 100_000,
            events_emitted: 777_777_777,
            latency_p50_ms: 500,
            latency_p99_ms: 5000,
            bytes_sent: 1_000_000_000_000,
            bytes_received: 2_000_000_000_000,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.requests_total, 999_999_999_999);
        assert_eq!(decoded.bytes_received, 2_000_000_000_000);
    }

    #[test]
    fn connector_metrics_serde_pretty_roundtrip() {
        let metrics = ConnectorMetrics {
            requests_total: 50,
            requests_success: 48,
            requests_error: 2,
            connections_active: 1,
            events_emitted: 10,
            latency_p50_ms: 20,
            latency_p99_ms: 300,
            bytes_sent: 2048,
            bytes_received: 4096,
        };
        let pretty = serde_json::to_string_pretty(&metrics).unwrap();
        assert!(pretty.contains('\n'));
        let decoded: ConnectorMetrics = serde_json::from_str(&pretty).unwrap();
        assert_eq!(decoded.requests_total, 50);
        assert_eq!(decoded.latency_p99_ms, 300);
    }

    #[test]
    fn connector_metrics_serde_value_roundtrip() {
        let metrics = ConnectorMetrics {
            requests_total: 7,
            requests_success: 6,
            requests_error: 1,
            connections_active: 2,
            events_emitted: 3,
            latency_p50_ms: 4,
            latency_p99_ms: 5,
            bytes_sent: 100,
            bytes_received: 200,
        };
        let value = serde_json::to_value(&metrics).unwrap();
        let decoded: ConnectorMetrics = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.requests_total, 7);
        assert_eq!(decoded.requests_error, 1);
        assert_eq!(decoded.bytes_sent, 100);
    }

    #[test]
    fn connector_metrics_json_field_count() {
        let metrics = ConnectorMetrics::default();
        let value = serde_json::to_value(&metrics).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(
            obj.len(),
            9,
            "ConnectorMetrics should have exactly 9 fields"
        );
    }

    #[test]
    fn connector_metrics_default_eq() {
        let a = ConnectorMetrics::default();
        let b = ConnectorMetrics::default();
        // While ConnectorMetrics doesn't derive PartialEq, we can compare field by field
        assert_eq!(a.requests_total, b.requests_total);
        assert_eq!(a.requests_success, b.requests_success);
        assert_eq!(a.requests_error, b.requests_error);
        assert_eq!(a.connections_active, b.connections_active);
        assert_eq!(a.events_emitted, b.events_emitted);
        assert_eq!(a.latency_p50_ms, b.latency_p50_ms);
        assert_eq!(a.latency_p99_ms, b.latency_p99_ms);
        assert_eq!(a.bytes_sent, b.bytes_sent);
        assert_eq!(a.bytes_received, b.bytes_received);
    }

    #[test]
    fn connector_metrics_debug_values_appear() {
        let metrics = ConnectorMetrics {
            requests_total: 42,
            requests_success: 41,
            requests_error: 1,
            connections_active: 5,
            events_emitted: 99,
            latency_p50_ms: 15,
            latency_p99_ms: 250,
            bytes_sent: 1234,
            bytes_received: 5678,
        };
        let dbg = format!("{metrics:?}");
        assert!(dbg.contains("42"));
        assert!(dbg.contains("41"));
        assert!(dbg.contains("1234"));
        assert!(dbg.contains("5678"));
    }

    #[test]
    fn connector_metrics_clone_all_fields_preserved() {
        let metrics = ConnectorMetrics {
            requests_total: 1,
            requests_success: 2,
            requests_error: 3,
            connections_active: 4,
            events_emitted: 5,
            latency_p50_ms: 6,
            latency_p99_ms: 7,
            bytes_sent: 8,
            bytes_received: 9,
        };
        let cloned = metrics.clone();
        assert_eq!(cloned.requests_total, metrics.requests_total);
        assert_eq!(cloned.requests_success, metrics.requests_success);
        assert_eq!(cloned.requests_error, metrics.requests_error);
        assert_eq!(cloned.connections_active, metrics.connections_active);
        assert_eq!(cloned.events_emitted, metrics.events_emitted);
        assert_eq!(cloned.latency_p50_ms, metrics.latency_p50_ms);
        assert_eq!(cloned.latency_p99_ms, metrics.latency_p99_ms);
        assert_eq!(cloned.bytes_sent, metrics.bytes_sent);
        assert_eq!(cloned.bytes_received, metrics.bytes_received);
    }

    #[test]
    fn connector_metrics_struct_size_nonzero() {
        assert!(std::mem::size_of::<ConnectorMetrics>() > 0);
    }

    #[test]
    fn connector_metrics_struct_alignment() {
        // u64 fields should give 8-byte alignment
        assert_eq!(std::mem::align_of::<ConnectorMetrics>(), 8);
    }

    #[test]
    fn connector_metrics_size_is_nine_u64s() {
        // 9 u64 fields = 72 bytes
        assert_eq!(
            std::mem::size_of::<ConnectorMetrics>(),
            9 * std::mem::size_of::<u64>()
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BaseConnector – additional edge cases & patterns
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn base_connector_instance_id_starts_with_inst() {
        let base = BaseConnector::new(test_connector_id());
        assert!(
            base.instance_id.as_str().starts_with("inst_"),
            "instance ID should start with inst_ prefix"
        );
    }

    #[test]
    fn base_connector_instance_id_length() {
        let base = BaseConnector::new(test_connector_id());
        let iid = base.instance_id.as_str();
        // "inst_" (5) + UUID (36 chars with hyphens) = 41
        assert_eq!(iid.len(), 41, "instance ID length: {iid}");
    }

    #[test]
    fn base_connector_three_unique_instance_ids() {
        let a = BaseConnector::new(test_connector_id());
        let b = BaseConnector::new(test_connector_id());
        let c = BaseConnector::new(test_connector_id());
        let ids = [
            a.instance_id.as_str(),
            b.instance_id.as_str(),
            c.instance_id.as_str(),
        ];
        // All three must be distinct
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
        assert_ne!(ids[0], ids[2]);
    }

    #[test]
    fn base_connector_connector_id_display() {
        let base = BaseConnector::new(ConnectorId::from_static("disp:streaming:v2"));
        assert_eq!(base.id.to_string(), "disp:streaming:v2");
    }

    #[test]
    fn base_connector_connector_id_as_ref() {
        let base = BaseConnector::new(ConnectorId::from_static("ref:rr:v1"));
        let s: &str = base.id.as_ref();
        assert_eq!(s, "ref:rr:v1");
    }

    #[test]
    fn base_connector_connector_id_clone() {
        let base = BaseConnector::new(ConnectorId::from_static("clone:test:v1"));
        let cloned_id = base.id.clone();
        assert_eq!(base.id, cloned_id);
    }

    #[test]
    fn base_connector_record_request_alternating() {
        let base = BaseConnector::new(test_connector_id());
        for i in 0..20 {
            base.record_request(i % 2 == 0);
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, 20);
        assert_eq!(m.requests_success, 10);
        assert_eq!(m.requests_error, 10);
    }

    #[test]
    fn base_connector_metrics_latency_starts_zero() {
        let base = BaseConnector::new(test_connector_id());
        let m = base.metrics();
        assert_eq!(m.latency_p50_ms, 0);
        assert_eq!(m.latency_p99_ms, 0);
    }

    #[test]
    fn base_connector_metrics_bytes_start_zero() {
        let base = BaseConnector::new(test_connector_id());
        let m = base.metrics();
        assert_eq!(m.bytes_sent, 0);
        assert_eq!(m.bytes_received, 0);
    }

    #[test]
    fn base_connector_set_configured_from_false_to_false() {
        let base = BaseConnector::new(test_connector_id());
        // Already false, setting false should be idempotent
        base.set_configured(false);
        assert!(!base.configured.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_set_handshaken_from_false_to_false() {
        let base = BaseConnector::new(test_connector_id());
        base.set_handshaken(false);
        assert!(!base.handshaken.load(Ordering::Relaxed));
    }

    #[test]
    fn base_connector_check_ready_returns_ok_unit() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        base.set_handshaken(true);
        base.check_ready().unwrap();
        // check_ready returns () on success, confirming no error
    }

    #[test]
    fn base_connector_record_single_event_only() {
        let base = BaseConnector::new(test_connector_id());
        base.record_event();
        let m = base.metrics();
        assert_eq!(m.events_emitted, 1);
        assert_eq!(m.requests_total, 0);
    }

    #[test]
    fn base_connector_record_single_request_only() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        let m = base.metrics();
        assert_eq!(m.requests_total, 1);
        assert_eq!(m.events_emitted, 0);
    }

    #[test]
    fn base_connector_rapid_state_toggle() {
        let base = BaseConnector::new(test_connector_id());
        for _ in 0..100 {
            base.set_configured(true);
            base.set_handshaken(true);
            assert!(base.check_ready().is_ok());
            base.set_configured(false);
            assert!(base.check_ready().is_err());
            base.set_configured(true);
        }
        assert!(base.check_ready().is_ok());
    }

    #[test]
    fn base_connector_metrics_after_large_event_burst() {
        let base = BaseConnector::new(test_connector_id());
        let count = 50_000_u64;
        for _ in 0..count {
            base.record_event();
        }
        assert_eq!(base.metrics().events_emitted, count);
        assert_eq!(base.metrics().requests_total, 0);
    }

    #[test]
    fn base_connector_metrics_mixed_large_volume() {
        let base = BaseConnector::new(test_connector_id());
        let n = 1_000_u64;
        for _ in 0..n {
            base.record_request(true);
            base.record_request(false);
            base.record_event();
        }
        let m = base.metrics();
        assert_eq!(m.requests_total, 2 * n);
        assert_eq!(m.requests_success, n);
        assert_eq!(m.requests_error, n);
        assert_eq!(m.events_emitted, n);
    }

    #[test]
    fn base_connector_debug_after_activity() {
        let base = BaseConnector::new(ConnectorId::from_static("debug:active:v1"));
        base.set_configured(true);
        base.record_request(true);
        base.record_event();
        let dbg = format!("{base:?}");
        assert!(dbg.contains("debug:active:v1"));
        assert!(dbg.contains("configured"));
    }

    #[test]
    fn base_connector_check_ready_error_type_not_configured() {
        let base = BaseConnector::new(test_connector_id());
        let err = base.check_ready().unwrap_err();
        // The error should be exactly NotConfigured when neither configured nor handshaken
        assert!(
            matches!(err, crate::FcpError::NotConfigured),
            "Expected NotConfigured, got {err:?}"
        );
    }

    #[test]
    fn base_connector_check_ready_error_type_not_handshaken() {
        let base = BaseConnector::new(test_connector_id());
        base.set_configured(true);
        let err = base.check_ready().unwrap_err();
        assert!(
            matches!(err, crate::FcpError::NotHandshaken),
            "Expected NotHandshaken, got {err:?}"
        );
    }

    #[test]
    fn base_connector_new_with_different_archetypes() {
        let rr = BaseConnector::new(ConnectorId::new("test", "rr", "v1").unwrap());
        let stream = BaseConnector::new(ConnectorId::new("test", "streaming", "v1").unwrap());
        let poll = BaseConnector::new(ConnectorId::new("test", "polling", "v1").unwrap());
        let wh = BaseConnector::new(ConnectorId::new("test", "webhook", "v1").unwrap());
        assert_eq!(rr.id.as_str(), "test:rr:v1");
        assert_eq!(stream.id.as_str(), "test:streaming:v1");
        assert_eq!(poll.id.as_str(), "test:polling:v1");
        assert_eq!(wh.id.as_str(), "test:webhook:v1");
    }

    #[test]
    fn base_connector_check_ready_priority_configured_before_handshaken() {
        let base = BaseConnector::new(test_connector_id());
        // Both false -> NotConfigured is checked first
        base.set_handshaken(true);
        base.set_configured(false);
        let err = base.check_ready().unwrap_err();
        assert!(matches!(err, crate::FcpError::NotConfigured));
    }

    #[test]
    fn base_connector_metrics_snapshot_is_copy_semantics() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        let snap = base.metrics();
        // Modifying base doesn't affect the snapshot (it's an owned struct)
        base.record_request(true);
        assert_eq!(snap.requests_total, 1);
        assert_eq!(base.metrics().requests_total, 2);
    }

    #[test]
    fn base_connector_id_into_string() {
        let id = ConnectorId::from_static("conv:rr:v1");
        let s: String = id.into();
        assert_eq!(s, "conv:rr:v1");
    }

    #[test]
    fn connector_id_from_str_valid() {
        let id: ConnectorId = "valid:connector:v1".parse().unwrap();
        assert_eq!(id.as_str(), "valid:connector:v1");
    }

    #[test]
    fn connector_id_equality() {
        let a = ConnectorId::from_static("same:id:v1");
        let b = ConnectorId::from_static("same:id:v1");
        assert_eq!(a, b);
    }

    #[test]
    fn connector_id_inequality() {
        let a = ConnectorId::from_static("one:id:v1");
        let b = ConnectorId::from_static("two:id:v1");
        assert_ne!(a, b);
    }

    #[test]
    fn connector_id_hash_used_in_map() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let id = ConnectorId::from_static("map:test:v1");
        map.insert(id.clone(), 42);
        assert_eq!(map.get(&id), Some(&42));
    }

    #[test]
    fn connector_id_serde_roundtrip() {
        let id = ConnectorId::from_static("serde:test:v1");
        let json = serde_json::to_string(&id).unwrap();
        let decoded: ConnectorId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn connector_id_serde_is_string() {
        let id = ConnectorId::from_static("serde:shape:v1");
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        assert!(!json.contains('{'));
    }

    #[test]
    fn connector_id_display_matches_as_str() {
        let id = ConnectorId::from_static("display:match:v1");
        assert_eq!(id.to_string(), id.as_str());
    }

    #[test]
    fn instance_id_default_starts_with_inst() {
        let id = InstanceId::default();
        assert!(id.as_str().starts_with("inst_"));
    }

    #[test]
    fn instance_id_two_defaults_differ() {
        let a = InstanceId::default();
        let b = InstanceId::default();
        assert_ne!(a, b);
    }

    #[test]
    fn atomic_connector_metrics_default_all_zero() {
        // AtomicConnectorMetrics is private, but we test through BaseConnector
        let base = BaseConnector::new(test_connector_id());
        let m = base.metrics();
        let total = m.requests_total
            + m.requests_success
            + m.requests_error
            + m.connections_active
            + m.events_emitted
            + m.latency_p50_ms
            + m.latency_p99_ms
            + m.bytes_sent
            + m.bytes_received;
        assert_eq!(total, 0, "all metric fields should sum to zero initially");
    }

    #[test]
    fn base_connector_metrics_snapshot_fields_consistent() {
        let base = BaseConnector::new(test_connector_id());
        base.record_request(true);
        base.record_request(false);
        let m = base.metrics();
        // Invariant: total = success + error
        assert_eq!(m.requests_total, m.requests_success + m.requests_error);
    }

    #[test]
    fn base_connector_metrics_invariant_over_many_requests() {
        let base = BaseConnector::new(test_connector_id());
        for i in 0..500 {
            base.record_request(i % 7 != 0);
        }
        let m = base.metrics();
        assert_eq!(
            m.requests_total,
            m.requests_success + m.requests_error,
            "total must equal success + error"
        );
        assert_eq!(m.requests_total, 500);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Default simulate() — default-deny enforcement (MOR/C3.5)
    // ─────────────────────────────────────────────────────────────────────────

    /// Minimal connector that does NOT override `simulate()`, relying on
    /// the trait default to prove that it denies all operations.
    struct DefaultSimulateConnector {
        base: BaseConnector,
    }

    impl sealed::Sealed for DefaultSimulateConnector {}

    impl DefaultSimulateConnector {
        fn new() -> Self {
            Self {
                base: BaseConnector::new(ConnectorId::from_static("test:default-sim:v1")),
            }
        }
    }

    #[async_trait]
    impl FcpConnector for DefaultSimulateConnector {
        fn id(&self) -> &ConnectorId {
            &self.base.id
        }
        async fn configure(&mut self, _: serde_json::Value) -> FcpResult<()> {
            Ok(())
        }
        async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
            Ok(HandshakeResponse {
                status: "accepted".into(),
                capabilities_granted: vec![],
                session_id: crate::SessionId::new(),
                manifest_hash: "sha256:test".into(),
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
        async fn shutdown(&mut self, _: ShutdownRequest) -> FcpResult<()> {
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
            Ok(InvokeResponse::ok(req.id, serde_json::json!({})))
        }
        // NOTE: simulate() is intentionally NOT overridden here.
        async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
            Ok(SubscribeResponse {
                r#type: "response".into(),
                id: req.id,
                result: crate::SubscribeResult {
                    confirmed_topics: vec![],
                    cursors: std::collections::HashMap::new(),
                    replay_supported: false,
                    buffer: None,
                },
            })
        }
        async fn unsubscribe(&self, _: UnsubscribeRequest) -> FcpResult<()> {
            Ok(())
        }
    }

    /// Connector that explicitly overrides `simulate()` to allow its
    /// known operation, proving the override pattern works.
    struct OverrideSimulateConnector {
        base: BaseConnector,
    }

    impl sealed::Sealed for OverrideSimulateConnector {}

    impl OverrideSimulateConnector {
        fn new() -> Self {
            Self {
                base: BaseConnector::new(ConnectorId::from_static("test:override-sim:v1")),
            }
        }
    }

    #[async_trait]
    impl FcpConnector for OverrideSimulateConnector {
        fn id(&self) -> &ConnectorId {
            &self.base.id
        }
        async fn configure(&mut self, _: serde_json::Value) -> FcpResult<()> {
            Ok(())
        }
        async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
            Ok(HandshakeResponse {
                status: "accepted".into(),
                capabilities_granted: vec![],
                session_id: crate::SessionId::new(),
                manifest_hash: "sha256:test".into(),
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
        async fn shutdown(&mut self, _: ShutdownRequest) -> FcpResult<()> {
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
            Ok(InvokeResponse::ok(req.id, serde_json::json!({})))
        }
        async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
            if req.operation.as_str() == "test.allowed_op" {
                Ok(SimulateResponse::allowed(req.id))
            } else {
                Ok(SimulateResponse::denied(
                    req.id,
                    "Unknown operation",
                    "FCP-3010",
                ))
            }
        }
        async fn subscribe(&self, req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
            Ok(SubscribeResponse {
                r#type: "response".into(),
                id: req.id,
                result: crate::SubscribeResult {
                    confirmed_topics: vec![],
                    cursors: std::collections::HashMap::new(),
                    replay_supported: false,
                    buffer: None,
                },
            })
        }
        async fn unsubscribe(&self, _: UnsubscribeRequest) -> FcpResult<()> {
            Ok(())
        }
    }

    fn make_simulate_request(operation: &'static str) -> SimulateRequest {
        SimulateRequest {
            r#type: "simulate".into(),
            id: crate::RequestId::new("sim-test"),
            connector_id: ConnectorId::from_static("test:default-sim:v1"),
            operation: crate::OperationId::from_static(operation),
            zone_id: crate::ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: crate::CapabilityToken::test_token(),
            estimate_cost: false,
            check_availability: false,
            context: None,
            correlation_id: None,
        }
    }

    #[test]
    fn default_simulate_returns_denied() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let connector = DefaultSimulateConnector::new();
            let req = make_simulate_request("any.operation");

            let result = connector.simulate(req).await;

            assert!(result.is_ok());
            let response = result.unwrap();
            assert!(
                !response.would_succeed,
                "Default simulate() must deny — default-deny principle"
            );
        });
    }

    #[test]
    fn default_simulate_denied_includes_reason_code() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let connector = DefaultSimulateConnector::new();
            let req = make_simulate_request("unknown.op");

            let response = connector.simulate(req).await.unwrap();

            assert!(response.failure_reason.is_some());
            assert!(
                response
                    .failure_reason
                    .as_deref()
                    .unwrap()
                    .contains("not simulated"),
                "Reason should explain the operation was not simulated"
            );
            assert_eq!(
                response.denial_code.as_deref(),
                Some("FCP-3010"),
                "Denial code should be FCP-3010"
            );
        });
    }

    #[test]
    fn override_simulate_returns_allowed_for_known_op() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let connector = OverrideSimulateConnector::new();
            let req = make_simulate_request("test.allowed_op");

            let response = connector.simulate(req).await.unwrap();

            assert!(
                response.would_succeed,
                "Explicit simulate() override must allow known operations"
            );
            assert!(response.failure_reason.is_none());
        });
    }

    #[test]
    fn override_simulate_denies_unknown_op() {
        let _ = fcp_async_core::runtime::block_on_sync(async {
            let connector = OverrideSimulateConnector::new();
            let req = make_simulate_request("unknown.operation");

            let response = connector.simulate(req).await.unwrap();

            assert!(
                !response.would_succeed,
                "Override should still deny operations it doesn't handle"
            );
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sealed Trait Pattern (MOR/C3.6)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn sealed_trait_exists_on_fcp_connector() {
        // Verify that FcpConnector requires Sealed as supertrait.
        // If this compiles, the Sealed supertrait is properly wired.
        fn assert_sealed<T: sealed::Sealed + FcpConnector>(_: &T) {}
        let connector = DefaultSimulateConnector::new();
        assert_sealed(&connector);
    }

    #[test]
    fn base_connector_implements_sealed() {
        fn assert_sealed<T: sealed::Sealed>(_: &T) {}
        let base = BaseConnector::new(test_connector_id());
        assert_sealed(&base);
    }

    #[test]
    fn impl_fcp_sealed_macro_works() {
        struct MacroTestConnector;
        impl_fcp_sealed!(MacroTestConnector);

        fn assert_sealed<T: sealed::Sealed>(_: &T) {}
        assert_sealed(&MacroTestConnector);
    }

    #[test]
    fn impl_fcp_sealed_macro_multiple_types() {
        struct ConnA;
        struct ConnB;
        struct ConnC;
        impl_fcp_sealed!(ConnA, ConnB, ConnC);

        fn assert_sealed<T: sealed::Sealed>(_: &T) {}
        assert_sealed(&ConnA);
        assert_sealed(&ConnB);
        assert_sealed(&ConnC);
    }

    #[test]
    fn sealed_trait_is_doc_hidden() {
        // The sealed module is #[doc(hidden)] — this test verifies
        // the module is accessible (for workspace use) but signals
        // it should not be relied upon by external crates.
        let _: &dyn sealed::Sealed = &BaseConnector::new(test_connector_id());
    }

    #[test]
    fn archetype_traits_inherit_sealed_via_fcp_connector() {
        // Archetype traits require FcpConnector which requires Sealed.
        // These function signatures prove the bound hierarchy at compile time.
        fn _assert_rr<T: RequestResponse + sealed::Sealed>() {}
        fn _assert_streaming<T: Streaming + sealed::Sealed>() {}
        fn _assert_polling<T: Polling + sealed::Sealed>() {}
        fn _assert_webhook<T: Webhook + sealed::Sealed>() {}
        fn _assert_bidi<T: Bidirectional + sealed::Sealed>() {}

        // The functions above compile only if Sealed is transitively required.
        // No instantiation needed — this is purely a type-level check.
    }
}
