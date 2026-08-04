//! Discovery API for agents to find and introspect connectors.
//!
//! Based on bead `bd-2h7e`: [FCP2] Host Discovery Endpoint.
//!
//! Provides endpoints:
//! - `discover` - List all connectors with summary
//! - `introspect` - Get tool descriptors for one connector
//! - `preflight` - Check authz without execution
//! - `health` - Host + connector health

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use fcp_async_core::sync::{Mutex, RwLock};
use fcp_kernel::{
    AgentHint, ApprovalMode, ConnectorHealth, ConnectorId, IdempotencyClass, Introspection,
    OperationInfo, RateLimitDeclarations, RequestId, SelfCheckReport, UsageBudgetSnapshot,
};
use fcp_prelude::{ApprovalToken, CapabilityId, CapabilityToken, RiskLevel, SafetyTier, ZoneId};
use serde::{Deserialize, Serialize};

use crate::{HostError, HostResult};

// ─────────────────────────────────────────────────────────────────────────────
// Discovery Types
// ─────────────────────────────────────────────────────────────────────────────

/// Filter for discovery requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryFilter {
    /// Filter by category (e.g., "messaging", "storage").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// Filter by maximum safety tier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_risk: Option<SafetyTier>,

    /// Filter by health status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthFilter>,
}

/// Health filter options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthFilter {
    /// Only healthy connectors.
    Healthy,
    /// Only degraded connectors.
    Degraded,
    /// Only available (healthy or degraded).
    Available,
    /// All connectors including unavailable.
    All,
}

impl DiscoveryFilter {
    /// Check if a connector summary matches this filter.
    #[must_use]
    pub fn matches(&self, connector: &ConnectorSummary) -> bool {
        // Category filter
        if let Some(ref cat) = self.category
            && !connector.categories.iter().any(|c| c == cat)
        {
            return false;
        }

        // Risk/safety tier filter
        if let Some(max_risk) = self.max_risk
            && !connector.max_safety_tier.is_at_most(max_risk)
        {
            return false;
        }

        // Health filter
        if let Some(health_filter) = self.health {
            match health_filter {
                HealthFilter::Healthy => {
                    if !connector.health.is_healthy() {
                        return false;
                    }
                }
                HealthFilter::Degraded => {
                    if !matches!(connector.health, ConnectorHealth::Degraded { .. }) {
                        return false;
                    }
                }
                HealthFilter::Available => {
                    if !connector.health.is_available() {
                        return false;
                    }
                }
                HealthFilter::All => {} // No filter
            }
        }

        true
    }
}

/// Agent-visible cache metadata for discovery and introspection responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheMetadata {
    /// Strong `ETag` for content comparison.
    pub etag: String,

    /// Last modification timestamp for the cached content.
    pub last_modified: DateTime<Utc>,

    /// Seconds before the client should revalidate.
    pub max_age_seconds: u32,

    /// Optional stale-while-revalidate budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_while_revalidate_seconds: Option<u32>,
}

impl CacheMetadata {
    fn strong<T: Serialize>(
        payload: &T,
        last_modified: DateTime<Utc>,
        max_age_seconds: u32,
        stale_while_revalidate_seconds: Option<u32>,
    ) -> Self {
        // Stream JSON directly into the BLAKE3 hasher to avoid allocating
        // a temporary Vec<u8> of the entire serialized payload. BLAKE3's
        // Hasher implements std::io::Write, so serde_json can write to it.
        let mut hasher = blake3::Hasher::new();
        serde_json::to_writer(&mut hasher, payload)
            .expect("cache metadata payload should serialize");
        let etag = format!("\"{}\"", hasher.finalize().to_hex());
        Self {
            etag,
            last_modified,
            max_age_seconds,
            stale_while_revalidate_seconds,
        }
    }
}

/// Conditional cache validators supplied by the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheValidator {
    /// Strong `ETag` from a prior response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_none_match: Option<String>,

    /// Previously observed modification timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_modified_since: Option<DateTime<Utc>>,
}

impl CacheValidator {
    fn is_not_modified(&self, cache: &CacheMetadata) -> bool {
        if let Some(ref etag) = self.if_none_match {
            return etag == &cache.etag;
        }

        self.if_modified_since
            .is_some_and(|timestamp| cache.last_modified <= timestamp)
    }
}

/// Lightweight response metadata for cache validation results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseMeta {
    /// Application-level status code for the payload.
    pub status: u16,

    /// Optional human-readable status message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ResponseMeta {
    fn not_modified() -> Self {
        // Use a String literal directly instead of .to_string() on &str.
        // The allocation is unavoidable (message is Option<String>), but
        // this form is idiomatic and clear about intent.
        Self {
            status: 304,
            message: Some(String::from("Not Modified")),
        }
    }
}

/// Summary information about a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorSummary {
    /// Connector identifier.
    pub id: ConnectorId,

    /// Human-readable name.
    pub name: String,

    /// Brief description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Semantic version.
    pub version: semver::Version,

    /// Categories this connector belongs to.
    #[serde(default)]
    pub categories: Vec<String>,

    /// Number of tools/operations available.
    pub tool_count: u32,

    /// Maximum safety tier across all operations.
    pub max_safety_tier: SafetyTier,

    /// Whether the connector is enabled.
    pub enabled: bool,

    /// Current health status.
    pub health: ConnectorHealth,

    /// Last health check timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_health_check: Option<DateTime<Utc>>,
}

/// Response from the discovery endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    /// List of connectors matching the filter.
    pub connectors: Vec<ConnectorSummary>,

    /// Registry version (for caching/ETag).
    pub registry_version: u64,

    /// Whether the host supports streaming events.
    ///
    /// `None` means discovery does not yet have authoritative host-capability
    /// evidence for this surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_streaming: Option<bool>,

    /// Whether the host supports batch invoke.
    ///
    /// `None` means discovery does not yet have authoritative host-capability
    /// evidence for this surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_batching: Option<bool>,

    /// Server timestamp.
    pub timestamp: DateTime<Utc>,

    /// Optional cache metadata for agent-side validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheMetadata>,

    /// Optional response status metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ResponseMeta>,
}

impl DiscoveryResponse {
    /// Create a new discovery response.
    #[must_use]
    pub fn new(connectors: Vec<ConnectorSummary>, registry_version: u64) -> Self {
        Self {
            connectors,
            registry_version,
            supports_streaming: None,
            supports_batching: None,
            timestamp: Utc::now(),
            cache: None,
            meta: None,
        }
    }

    #[cfg(test)]
    #[must_use]
    const fn with_host_capabilities(
        mut self,
        supports_streaming: Option<bool>,
        supports_batching: Option<bool>,
    ) -> Self {
        self.supports_streaming = supports_streaming;
        self.supports_batching = supports_batching;
        self
    }

    #[must_use]
    fn with_cache_metadata(mut self, cache: CacheMetadata) -> Self {
        self.cache = Some(cache);
        self
    }

    #[must_use]
    fn with_response_meta(mut self, meta: ResponseMeta) -> Self {
        self.meta = Some(meta);
        self
    }

    #[must_use]
    fn not_modified(
        connectors: Vec<ConnectorSummary>,
        registry_version: u64,
        cache: CacheMetadata,
    ) -> Self {
        Self::new(connectors, registry_version)
            .with_cache_metadata(cache)
            .with_response_meta(ResponseMeta::not_modified())
    }
}

/// Discovery response plus cache metadata for callers that emit observability.
#[derive(Debug, Clone)]
pub struct DiscoveryQueryResult {
    /// Serialized discovery payload returned to clients.
    pub response: DiscoveryResponse,
    /// Whether connector summaries came from the in-memory cache.
    pub cache_hit: bool,
}

/// Response from the connector inventory/status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorInventoryResponse {
    /// Connector summary.
    pub connector: ConnectorSummary,

    /// Registry version backing the response.
    pub registry_version: u64,

    /// Optional cache metadata for agent-side validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheMetadata>,

    /// Optional response status metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ResponseMeta>,
}

impl ConnectorInventoryResponse {
    #[must_use]
    fn not_modified(
        connector: ConnectorSummary,
        registry_version: u64,
        cache: CacheMetadata,
    ) -> Self {
        Self {
            connector,
            registry_version,
            cache: Some(cache),
            meta: Some(ResponseMeta::not_modified()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Introspection Types
// ─────────────────────────────────────────────────────────────────────────────

/// Connector archetype classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorArchetype {
    /// Runtime does not have authoritative archetype metadata.
    Unknown,
    /// Request-response (REST, GraphQL).
    RequestResponse,
    /// Streaming (WebSocket, SSE).
    Streaming,
    /// Bidirectional (WebSocket chat).
    Bidirectional,
    /// Polling (IMAP, RSS).
    Polling,
    /// Webhook (GitHub, Stripe).
    Webhook,
}

/// Response from the introspect endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Connector summary.
    pub connector: ConnectorSummary,

    /// Tool descriptors (operations).
    pub tools: Vec<ToolDescriptor>,

    /// Rate limit declarations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limits: Option<RateLimitDeclarations>,

    /// Connector archetype.
    pub archetype: ConnectorArchetype,

    /// Full introspection data.
    pub introspection: Introspection,

    /// Optional cache metadata for agent-side validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheMetadata>,

    /// Optional response status metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ResponseMeta>,
}

impl IntrospectionResponse {
    #[must_use]
    fn not_modified(
        connector: ConnectorSummary,
        tools: Vec<ToolDescriptor>,
        rate_limits: Option<RateLimitDeclarations>,
        archetype: ConnectorArchetype,
        introspection: Introspection,
        cache: CacheMetadata,
    ) -> Self {
        Self {
            connector,
            tools,
            rate_limits,
            archetype,
            introspection,
            cache: Some(cache),
            meta: Some(ResponseMeta::not_modified()),
        }
    }
}

/// Response from a connector self-check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheckResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,

    /// Self-check report from the connector.
    pub report: SelfCheckReport,

    /// Timestamp when the self-check was executed.
    pub checked_at: DateTime<Utc>,
}

/// MCP-compatible tool descriptor.
///
/// Per SEP-1382 and MCP 2025 spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// Tool name (operation ID).
    pub name: String,

    /// Human-readable description.
    pub description: String,

    /// JSON Schema for input parameters.
    pub input_schema: serde_json::Value,

    /// JSON Schema for output.
    pub output_schema: serde_json::Value,

    /// Required capability.
    pub capability: CapabilityId,

    /// Risk level (for agent UX).
    pub risk_level: RiskLevel,

    /// Safety tier.
    pub safety_tier: SafetyTier,

    /// Idempotency class.
    pub idempotency: IdempotencyClass,

    /// Approval mode required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalMode>,

    /// Whether this tool requires confirmation.
    pub requires_confirmation: bool,

    /// Whether this tool is idempotent.
    pub idempotent: bool,

    /// Whether this tool supports simulate.
    ///
    /// `None` means the host cannot yet prove live simulate support for this
    /// operation from authoritative evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supports_simulate: Option<bool>,

    /// Latency hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_hint: Option<LatencyHint>,

    /// Rate limit names that apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rate_limits: Vec<String>,

    /// Example invocations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<ToolExample>,

    /// AI agent hints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_hints: Option<AgentHint>,
}

impl From<&OperationInfo> for ToolDescriptor {
    fn from(op: &OperationInfo) -> Self {
        Self {
            name: op.id.to_string(),
            description: op.description.clone().unwrap_or_else(|| op.summary.clone()),
            input_schema: op.input_schema.clone(),
            output_schema: op.output_schema.clone(),
            capability: op.capability.clone(),
            risk_level: op.risk_level,
            safety_tier: op.safety_tier,
            idempotency: op.idempotency,
            approval_mode: op.requires_approval,
            requires_confirmation: matches!(
                op.requires_approval,
                Some(
                    ApprovalMode::Policy | ApprovalMode::Interactive | ApprovalMode::ElevationToken
                )
            ),
            idempotent: matches!(
                op.idempotency,
                IdempotencyClass::Strict | IdempotencyClass::BestEffort
            ),
            // OperationInfo alone does not prove live simulate support.
            supports_simulate: None,
            latency_hint: None,
            rate_limits: op
                .rate_limit
                .as_ref()
                .and_then(|rl| rl.pool_name.clone())
                .map_or_else(Vec::new, |pool_name| vec![pool_name]),
            examples: op
                .ai_hints
                .examples
                .iter()
                .filter_map(|example| {
                    serde_json::from_str(example).ok().map(|input| ToolExample {
                        description: None,
                        input,
                        output: None,
                    })
                })
                .collect(),
            ai_hints: if op.ai_hints.when_to_use.is_empty()
                && op.ai_hints.common_mistakes.is_empty()
                && op.ai_hints.examples.is_empty()
                && op.ai_hints.related.is_empty()
            {
                None
            } else {
                Some(op.ai_hints.clone())
            },
        }
    }
}

impl ToolDescriptor {
    pub(crate) fn from_operation(
        op: &OperationInfo,
        declarations: Option<&RateLimitDeclarations>,
    ) -> Self {
        let mut tool = Self::from(op);
        if let Some(decls) = declarations
            && let Some(pools) = decls.tool_pool_map.get(op.id.as_str())
        {
            tool.rate_limits.clone_from(pools);
        }
        tool
    }
}

/// Latency hint for tool execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyHint {
    /// Fast (< 100ms).
    Fast,
    /// Medium (100ms - 1s).
    Medium,
    /// Slow (1s - 10s).
    Slow,
    /// Very slow (> 10s).
    VerySlow,
}

/// Example tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExample {
    /// Description of what this example demonstrates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Example input.
    pub input: serde_json::Value,

    /// Example output (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Preflight Types
// ─────────────────────────────────────────────────────────────────────────────

/// Request for preflight authorization check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightRequest {
    /// Target connector.
    pub connector_id: ConnectorId,

    /// Operation to check.
    pub operation: String,

    /// Proposed input parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,

    /// Principal making the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,

    /// Zone the operation would execute in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<ZoneId>,
}

/// External preflight request sent to `fcp-host`.
///
/// Extends the internal budget-only [`PreflightRequest`] with the real
/// authorization material needed for truthful preflight checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPreflightRequest {
    /// Planned request id. Reused by the subsequent invoke so exact-scope
    /// approval tokens can bind preflight and execution to the same request.
    pub request_id: RequestId,

    /// Target connector.
    pub connector_id: ConnectorId,

    /// Operation to check.
    pub operation: String,

    /// Proposed input parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,

    /// Principal making the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,

    /// Zone the operation would execute in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<ZoneId>,

    /// Capability token authorizing the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,

    /// Approval tokens authorizing elevated or explicitly approved execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_tokens: Vec<ApprovalToken>,
}

impl HostPreflightRequest {
    #[must_use]
    pub fn budget_request(&self) -> PreflightRequest {
        PreflightRequest {
            connector_id: self.connector_id.clone(),
            operation: self.operation.clone(),
            params: self.params.clone(),
            principal: self.principal.clone(),
            zone_id: self.zone_id.clone(),
        }
    }
}

/// Response from preflight check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResponse {
    /// Whether the operation would be allowed.
    pub allowed: bool,

    /// Reason if not allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Required capabilities that are missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_capabilities: Vec<String>,

    /// Rate limit status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<PreflightRateLimit>,

    /// Estimated cost (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost: Option<EstimatedCost>,

    /// Usage budget snapshot (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_status: Option<UsageBudgetSnapshot>,
}

impl PreflightResponse {
    /// Create an allowed response.
    #[must_use]
    pub const fn allowed() -> Self {
        Self {
            allowed: true,
            reason: None,
            missing_capabilities: Vec::new(),
            rate_limit: None,
            estimated_cost: None,
            budget_status: None,
        }
    }

    /// Create a denied response.
    #[must_use]
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
            missing_capabilities: vec![],
            rate_limit: None,
            estimated_cost: None,
            budget_status: None,
        }
    }
}

/// Rate limit info for preflight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightRateLimit {
    /// Whether currently rate limited.
    pub limited: bool,

    /// Requests remaining.
    pub remaining: u32,

    /// Window reset timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_at: Option<DateTime<Utc>>,
}

/// Estimated cost for an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimatedCost {
    /// Estimated API calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_calls: Option<u32>,

    /// Estimated tokens (for LLM connectors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u32>,

    /// Estimated monetary cost (USD cents).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_cents: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Types
// ─────────────────────────────────────────────────────────────────────────────

/// Host-level health response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostHealthResponse {
    /// Overall host health.
    pub status: HostHealthStatus,

    /// Per-connector health.
    pub connectors: HashMap<ConnectorId, ConnectorHealth>,

    /// Host uptime in seconds.
    pub uptime_seconds: u64,

    /// Number of active connections.
    pub active_connections: u32,

    /// Timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Host health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostHealthStatus {
    /// All systems operational.
    Healthy,
    /// Some connectors degraded.
    Degraded,
    /// Major issues.
    Unhealthy,
}

/// Status of the mesh network connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshStatus {
    /// Mesh is fully connected and reachable.
    Connected,
    /// Mesh is reachable but experiencing issues (e.g. peer partitions).
    Degraded,
    /// Mesh is not reachable.
    Unreachable,
    /// Mesh is not configured (standalone mode).
    NotConfigured,
}

impl MeshStatus {
    /// Whether the mesh is considered operational (connected or degraded).
    #[must_use]
    pub const fn is_operational(&self) -> bool {
        matches!(self, Self::Connected | Self::Degraded)
    }
}

/// Status of the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEngineStatus {
    /// Policy engine is loaded and operational.
    Active,
    /// Policy engine is loaded but some rules failed to parse.
    PartiallyLoaded,
    /// Policy engine is not initialized.
    NotInitialized,
    /// Policy engine encountered a fatal error.
    Error,
}

impl PolicyEngineStatus {
    /// Whether the policy engine can make decisions.
    #[must_use]
    pub const fn can_decide(&self) -> bool {
        matches!(self, Self::Active | Self::PartiallyLoaded)
    }
}

/// Extended diagnostics beyond basic health — mesh, policy, resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDiagnostics {
    /// Basic health information.
    pub health: HostHealthResponse,
    /// Mesh connectivity status.
    pub mesh_status: MeshStatus,
    /// Policy engine status.
    pub policy_engine: PolicyEngineStatus,
    /// Number of connectors in each lifecycle state.
    pub connector_counts: ConnectorStateCounts,
    /// Whether configuration changes are pending reload.
    pub pending_config_reload: bool,
}

/// Counts of connectors by state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorStateCounts {
    /// Running connectors.
    pub running: u32,
    /// Starting connectors.
    pub starting: u32,
    /// Stopped connectors.
    pub stopped: u32,
    /// Failed connectors.
    pub failed: u32,
    /// Disabled connectors.
    pub disabled: u32,
}

impl ConnectorStateCounts {
    /// Total number of connectors.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.running + self.starting + self.stopped + self.failed + self.disabled
    }

    /// Whether all connectors are healthy (running or disabled).
    #[must_use]
    pub const fn all_healthy(&self) -> bool {
        self.failed == 0 && self.stopped == 0 && self.starting == 0
    }
}

impl HostDiagnostics {
    /// Compute an aggregate health status from all diagnostic signals.
    #[must_use]
    pub fn aggregate_status(&self) -> HostHealthStatus {
        if self.health.status == HostHealthStatus::Unhealthy {
            return HostHealthStatus::Unhealthy;
        }
        if !self.policy_engine.can_decide() {
            return HostHealthStatus::Unhealthy;
        }
        if self.mesh_status == MeshStatus::Unreachable {
            return HostHealthStatus::Degraded;
        }
        if self.connector_counts.failed > 0 {
            return HostHealthStatus::Degraded;
        }
        if self.mesh_status == MeshStatus::Degraded {
            return HostHealthStatus::Degraded;
        }
        self.health.status
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SafetyTier Extensions
// ─────────────────────────────────────────────────────────────────────────────

/// Extension trait for `SafetyTier` comparisons.
pub trait SafetyTierExt {
    /// Check if this tier is at most the given level.
    fn is_at_most(&self, other: SafetyTier) -> bool;

    /// Get the numeric level (lower = safer).
    fn level(&self) -> u8;
}

impl SafetyTierExt for SafetyTier {
    fn is_at_most(&self, other: SafetyTier) -> bool {
        self.level() <= other.level()
    }

    fn level(&self) -> u8 {
        match self {
            Self::Safe => 0,
            Self::Risky => 1,
            Self::Dangerous => 2,
            Self::Critical => 3,
            Self::Forbidden => 4,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Registry Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for connector registry backends.
#[async_trait::async_trait]
pub trait ConnectorRegistry: Send + Sync {
    /// List all connector summaries.
    async fn list(&self) -> Vec<ConnectorSummary>;

    /// Get a specific connector summary by ID.
    async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary>;

    /// Get full introspection for a connector.
    async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection>;

    /// Get the archetype for a connector.
    async fn get_archetype(&self, id: &ConnectorId) -> Option<ConnectorArchetype>;

    /// Get rate limit declarations for a connector.
    async fn get_rate_limits(&self, id: &ConnectorId) -> Option<RateLimitDeclarations>;

    /// Run a connector self-check.
    async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport>;

    /// Get the current registry version.
    fn version(&self) -> u64;
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy Engine Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for policy evaluation.
#[async_trait::async_trait]
pub trait PolicyEngine: Send + Sync {
    /// Evaluate a preflight request.
    async fn evaluate_preflight(&self, request: &PreflightRequest) -> PreflightResponse;
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery Endpoint
// ─────────────────────────────────────────────────────────────────────────────

/// Discovery endpoint implementation.
pub struct DiscoveryEndpoint<R, P> {
    registry: Arc<R>,
    policy_engine: Arc<P>,
    cache: DiscoveryCache,
}

impl<R, P> DiscoveryEndpoint<R, P>
where
    R: ConnectorRegistry,
    P: PolicyEngine,
{
    /// Create a new discovery endpoint.
    pub fn new(registry: Arc<R>, policy_engine: Arc<P>) -> Self {
        Self {
            registry,
            policy_engine,
            cache: DiscoveryCache::new(Duration::from_secs(30)),
        }
    }

    /// Create with custom cache TTL.
    pub fn with_cache_ttl(registry: Arc<R>, policy_engine: Arc<P>, ttl: Duration) -> Self {
        Self {
            registry,
            policy_engine,
            cache: DiscoveryCache::new(ttl),
        }
    }

    /// List all connectors (filtered).
    pub async fn discover(&self, filter: Option<DiscoveryFilter>) -> DiscoveryResponse {
        self.discover_with_metadata(filter).await.response
    }

    /// List all connectors (filtered) plus cache metadata for callers that
    /// need to emit cache-aware logs or metrics.
    pub async fn discover_with_metadata(
        &self,
        filter: Option<DiscoveryFilter>,
    ) -> DiscoveryQueryResult {
        self.discover_query(filter, None).await
    }

    /// List all connectors (filtered) with optional conditional cache validation.
    pub async fn discover_query(
        &self,
        filter: Option<DiscoveryFilter>,
        validator: Option<CacheValidator>,
    ) -> DiscoveryQueryResult {
        let cache_result = self.cache.get_or_refresh(&*self.registry).await;
        let filtered = match filter {
            Some(f) => cache_result
                .connectors
                .into_iter()
                .filter(|c| f.matches(c))
                .collect(),
            None => cache_result.connectors,
        };

        let cache = self.discovery_cache_metadata(
            &filtered,
            cache_result.registry_version,
            cache_result.last_modified,
        );

        let response = if validator
            .as_ref()
            .is_some_and(|validator| validator.is_not_modified(&cache))
        {
            DiscoveryResponse::not_modified(filtered, cache_result.registry_version, cache)
        } else {
            DiscoveryResponse::new(filtered, cache_result.registry_version)
                .with_cache_metadata(cache)
        };

        DiscoveryQueryResult {
            response,
            cache_hit: cache_result.cache_hit,
        }
    }

    /// Fetch a single connector inventory/status record.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectorNotFound`] if the connector is missing
    /// from the registry cache.
    pub async fn connector(
        &self,
        connector_id: &ConnectorId,
    ) -> HostResult<ConnectorInventoryResponse> {
        self.connector_with_cache(connector_id, None).await
    }

    /// Fetch a single connector inventory/status record with optional
    /// conditional cache validation.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectorNotFound`] if the connector is missing
    /// from the registry cache.
    pub async fn connector_with_cache(
        &self,
        connector_id: &ConnectorId,
        validator: Option<CacheValidator>,
    ) -> HostResult<ConnectorInventoryResponse> {
        let cache_result = self.cache.get_or_refresh(&*self.registry).await;
        let connector = cache_result
            .connectors
            .iter()
            .find(|summary| &summary.id == connector_id)
            .cloned()
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
        let cache = self.connector_cache_metadata(
            &connector,
            cache_result.registry_version,
            cache_result.last_modified,
        );

        if validator
            .as_ref()
            .is_some_and(|validator| validator.is_not_modified(&cache))
        {
            return Ok(ConnectorInventoryResponse::not_modified(
                connector,
                cache_result.registry_version,
                cache,
            ));
        }

        Ok(ConnectorInventoryResponse {
            connector,
            registry_version: cache_result.registry_version,
            cache: Some(cache),
            meta: None,
        })
    }

    /// Introspect a single connector.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectorNotFound`] if the connector or its
    /// introspection data is missing from the registry.
    pub async fn introspect(
        &self,
        connector_id: &ConnectorId,
    ) -> HostResult<IntrospectionResponse> {
        self.introspect_with_cache(connector_id, None).await
    }

    /// Introspect a single connector with optional conditional cache validation.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectorNotFound`] if the connector or its
    /// introspection data is missing from the registry.
    pub async fn introspect_with_cache(
        &self,
        connector_id: &ConnectorId,
        validator: Option<CacheValidator>,
    ) -> HostResult<IntrospectionResponse> {
        let cache_result = self.cache.get_or_refresh(&*self.registry).await;
        let summary = cache_result
            .connectors
            .iter()
            .find(|summary| &summary.id == connector_id)
            .cloned()
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;

        let introspection = self
            .registry
            .get_introspection(connector_id)
            .await
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;

        let archetype = self
            .registry
            .get_archetype(connector_id)
            .await
            .unwrap_or(ConnectorArchetype::Unknown);

        let rate_limits = self.registry.get_rate_limits(connector_id).await;

        // Convert operations to tool descriptors
        let tools: Vec<ToolDescriptor> = introspection
            .operations
            .iter()
            .map(|op| ToolDescriptor::from_operation(op, rate_limits.as_ref()))
            .collect();
        let cache = self.introspection_cache_metadata(
            &summary,
            &introspection,
            archetype,
            rate_limits.as_ref(),
            &tools,
            cache_result.last_modified,
        );

        if validator
            .as_ref()
            .is_some_and(|validator| validator.is_not_modified(&cache))
        {
            return Ok(IntrospectionResponse::not_modified(
                summary,
                tools,
                rate_limits,
                archetype,
                introspection,
                cache,
            ));
        }

        Ok(IntrospectionResponse {
            connector: summary,
            tools,
            rate_limits,
            archetype,
            introspection,
            cache: Some(cache),
            meta: None,
        })
    }

    /// Run a connector self-check (read-only).
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectorNotFound`] if the connector is missing.
    pub async fn self_check(&self, connector_id: &ConnectorId) -> HostResult<SelfCheckResponse> {
        let report = self
            .registry
            .self_check(connector_id)
            .await
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;

        Ok(SelfCheckResponse {
            connector_id: connector_id.clone(),
            report,
            checked_at: Utc::now(),
        })
    }

    /// Preflight authorization check.
    pub async fn preflight(&self, request: PreflightRequest) -> PreflightResponse {
        self.policy_engine.evaluate_preflight(&request).await
    }

    /// Invalidate the discovery cache.
    pub async fn invalidate_cache(&self) {
        self.cache.invalidate().await;
    }

    fn discovery_cache_metadata(
        &self,
        connectors: &[ConnectorSummary],
        registry_version: u64,
        last_modified: DateTime<Utc>,
    ) -> CacheMetadata {
        let mut sorted = connectors.to_vec();
        sorted.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        self.cache
            .cache_metadata(&(registry_version, sorted), last_modified)
    }

    fn introspection_cache_metadata(
        &self,
        connector: &ConnectorSummary,
        introspection: &Introspection,
        archetype: ConnectorArchetype,
        rate_limits: Option<&RateLimitDeclarations>,
        tools: &[ToolDescriptor],
        last_modified: DateTime<Utc>,
    ) -> CacheMetadata {
        self.cache.cache_metadata(
            &(connector, introspection, archetype, rate_limits, tools),
            last_modified,
        )
    }

    fn connector_cache_metadata(
        &self,
        connector: &ConnectorSummary,
        registry_version: u64,
        last_modified: DateTime<Utc>,
    ) -> CacheMetadata {
        self.cache
            .cache_metadata(&(registry_version, connector), last_modified)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery Cache
// ─────────────────────────────────────────────────────────────────────────────

/// Cache for discovery responses.
pub struct DiscoveryCache {
    /// Cached connector summaries.
    cache: RwLock<Option<CachedDiscovery>>,
    /// Serializes cache refreshes so concurrent misses collapse to one load.
    refresh_lock: Mutex<()>,
    /// Time-to-live.
    ttl: Duration,
}

struct CachedDiscovery {
    connectors: Vec<ConnectorSummary>,
    registry_version: u64,
    cached_at: Instant,
    last_modified: DateTime<Utc>,
}

struct DiscoveryCacheResult {
    connectors: Vec<ConnectorSummary>,
    registry_version: u64,
    cache_hit: bool,
    last_modified: DateTime<Utc>,
}

impl DiscoveryCache {
    /// Create a new cache with the given TTL.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            ttl,
        }
    }

    fn cache_metadata<T: Serialize>(
        &self,
        payload: &T,
        last_modified: DateTime<Utc>,
    ) -> CacheMetadata {
        let ttl_seconds =
            u32::try_from(self.ttl.as_secs().min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
        CacheMetadata::strong(payload, last_modified, ttl_seconds, Some(ttl_seconds))
    }

    async fn cached_result(&self, registry_version: u64) -> Option<DiscoveryCacheResult> {
        let read = self.cache.read().await;
        let cached = read.as_ref()?;
        if cached.registry_version != registry_version || cached.cached_at.elapsed() >= self.ttl {
            return None;
        }

        Some(DiscoveryCacheResult {
            connectors: cached.connectors.clone(),
            registry_version: cached.registry_version,
            cache_hit: true,
            last_modified: cached.last_modified,
        })
    }

    /// Get cached connectors or refresh from registry.
    async fn get_or_refresh<R: ConnectorRegistry>(&self, registry: &R) -> DiscoveryCacheResult {
        if let Some(cached) = self.cached_result(registry.version()).await {
            return cached;
        }

        // The refresh lock provides single-flight refresh to avoid a thundering
        // herd of concurrent registry loads. Two cases must skip it:
        //  - `ttl == 0` disables caching, so the fast-path check above always
        //    misses; holding one mutex across `registry.list().await` would then
        //    serialize *every* concurrent discovery call through a single lock.
        //  - a poisoned lock (a prior loader panicked while holding it) must not
        //    brick discovery forever — degrade to an unsynchronized refresh.
        let _refresh_guard = if self.ttl.is_zero() {
            None
        } else {
            self.refresh_lock.lock_poison_tolerant().await
        };
        let registry_version = registry.version();
        if let Some(cached) = self.cached_result(registry_version).await {
            return cached;
        }

        // Cache miss or expired - refresh
        let connectors = registry.list().await;
        let refreshed_version = registry.version();

        let mut write = self.cache.write().await;
        let last_modified = if write
            .as_ref()
            .is_some_and(|cached| cached.registry_version == refreshed_version)
        {
            write
                .as_ref()
                .map_or_else(Utc::now, |cached| cached.last_modified)
        } else {
            Utc::now()
        };
        *write = Some(CachedDiscovery {
            connectors: connectors.clone(),
            registry_version: refreshed_version,
            cached_at: Instant::now(),
            last_modified,
        });

        DiscoveryCacheResult {
            connectors,
            registry_version: refreshed_version,
            cache_hit: false,
            last_modified,
        }
    }

    /// Invalidate the cache.
    pub async fn invalidate(&self) {
        let mut write = self.cache.write().await;
        *write = None;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_async_core::{task, time};
    use fcp_kernel::SelfCheckStatus;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    // Test SafetyTier extension
    #[test]
    fn safety_tier_level_ordering() {
        assert!(SafetyTier::Safe.level() < SafetyTier::Risky.level());
        assert!(SafetyTier::Risky.level() < SafetyTier::Dangerous.level());
        assert!(SafetyTier::Dangerous.level() < SafetyTier::Critical.level());
        assert!(SafetyTier::Critical.level() < SafetyTier::Forbidden.level());
    }

    #[test]
    fn safety_tier_is_at_most() {
        assert!(SafetyTier::Safe.is_at_most(SafetyTier::Safe));
        assert!(SafetyTier::Safe.is_at_most(SafetyTier::Risky));
        assert!(SafetyTier::Risky.is_at_most(SafetyTier::Dangerous));
        assert!(!SafetyTier::Dangerous.is_at_most(SafetyTier::Safe));
        assert!(!SafetyTier::Forbidden.is_at_most(SafetyTier::Critical));
    }

    // Test DiscoveryFilter
    fn make_summary(
        name: &str,
        archetype: &str,
        version: &str,
        categories: Vec<&str>,
        safety: SafetyTier,
        health: ConnectorHealth,
    ) -> ConnectorSummary {
        let id = ConnectorId::new(name, archetype, version).expect("valid connector id");
        ConnectorSummary {
            id,
            name: name.to_string(),
            description: None,
            version: semver::Version::new(1, 0, 0),
            categories: categories.into_iter().map(String::from).collect(),
            tool_count: 5,
            max_safety_tier: safety,
            enabled: true,
            health,
            last_health_check: Some(Utc::now()),
        }
    }

    #[test]
    fn filter_matches_no_filter() {
        let filter = DiscoveryFilter::default();
        let summary = make_summary(
            "test",
            "conn",
            "v1",
            vec!["messaging"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );

        assert!(filter.matches(&summary));
    }

    #[test]
    fn filter_matches_category() {
        let filter = DiscoveryFilter {
            category: Some("messaging".to_string()),
            ..Default::default()
        };

        let messaging = make_summary(
            "test",
            "msg",
            "v1",
            vec!["messaging"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let storage = make_summary(
            "test",
            "store",
            "v1",
            vec!["storage"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );

        assert!(filter.matches(&messaging));
        assert!(!filter.matches(&storage));
    }

    #[test]
    fn filter_matches_risk() {
        let filter = DiscoveryFilter {
            max_risk: Some(SafetyTier::Risky),
            ..Default::default()
        };

        let safe = make_summary(
            "test",
            "safe",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let risky = make_summary(
            "test",
            "risky",
            "v1",
            vec![],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );
        let dangerous = make_summary(
            "test",
            "danger",
            "v1",
            vec![],
            SafetyTier::Dangerous,
            ConnectorHealth::healthy(),
        );

        assert!(filter.matches(&safe));
        assert!(filter.matches(&risky));
        assert!(!filter.matches(&dangerous));
    }

    #[test]
    fn filter_matches_health() {
        let healthy_filter = DiscoveryFilter {
            health: Some(HealthFilter::Healthy),
            ..Default::default()
        };

        let available_filter = DiscoveryFilter {
            health: Some(HealthFilter::Available),
            ..Default::default()
        };

        let healthy = make_summary(
            "test",
            "h",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let degraded = make_summary(
            "test",
            "d",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::degraded("slow"),
        );
        let unavailable = make_summary(
            "test",
            "u",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::unavailable("down"),
        );

        assert!(healthy_filter.matches(&healthy));
        assert!(!healthy_filter.matches(&degraded));
        assert!(!healthy_filter.matches(&unavailable));

        assert!(available_filter.matches(&healthy));
        assert!(available_filter.matches(&degraded));
        assert!(!available_filter.matches(&unavailable));
    }

    // Test PreflightResponse
    #[test]
    fn preflight_response_allowed() {
        let resp = PreflightResponse::allowed();
        assert!(resp.allowed);
        assert!(resp.reason.is_none());
    }

    #[test]
    fn preflight_response_denied() {
        let resp = PreflightResponse::denied("insufficient permissions");
        assert!(!resp.allowed);
        assert_eq!(resp.reason.as_deref(), Some("insufficient permissions"));
    }

    // Test DiscoveryResponse
    #[test]
    fn discovery_response_new() {
        let connectors = vec![make_summary(
            "test",
            "a",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        )];
        let resp = DiscoveryResponse::new(connectors, 42);

        assert_eq!(resp.connectors.len(), 1);
        assert_eq!(resp.registry_version, 42);
        assert_eq!(resp.supports_streaming, None);
        assert_eq!(resp.supports_batching, None);
    }

    // Test serialization roundtrips
    #[test]
    fn discovery_filter_serialization() {
        let filter = DiscoveryFilter {
            category: Some("messaging".to_string()),
            max_risk: Some(SafetyTier::Risky),
            health: Some(HealthFilter::Available),
        };

        let json = serde_json::to_string(&filter).unwrap();
        let parsed: DiscoveryFilter = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.category, filter.category);
        assert_eq!(parsed.max_risk, filter.max_risk);
        assert_eq!(parsed.health, filter.health);
    }

    #[test]
    fn connector_summary_serialization() {
        let summary = make_summary(
            "test",
            "serial",
            "v1",
            vec!["category1", "category2"],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: ConnectorSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, summary.id);
        assert_eq!(parsed.name, summary.name);
        assert_eq!(parsed.categories, summary.categories);
        assert_eq!(parsed.max_safety_tier, summary.max_safety_tier);
    }

    #[test]
    fn tool_descriptor_serialization() {
        let tool = ToolDescriptor {
            name: "send_message".to_string(),
            description: "Send a message to a channel".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
            capability: CapabilityId::new("cap.send_message").expect("capability"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            approval_mode: Some(ApprovalMode::Interactive),
            requires_confirmation: true,
            idempotent: false,
            supports_simulate: Some(true),
            latency_hint: Some(LatencyHint::Fast),
            rate_limits: vec!["discord_api".to_string()],
            examples: vec![],
            ai_hints: Some(AgentHint {
                when_to_use: "Use for sending chat messages".to_string(),
                common_mistakes: vec!["Missing channel_id".to_string()],
                examples: vec![r#"{"channel_id":"123","content":"hi"}"#.to_string()],
                related: vec![CapabilityId::new("discord.delete_message").expect("capability")],
            }),
        };

        let json = serde_json::to_string(&tool).unwrap();
        let parsed: ToolDescriptor = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, tool.name);
        assert_eq!(parsed.safety_tier, tool.safety_tier);
        assert_eq!(parsed.latency_hint, tool.latency_hint);
        assert_eq!(parsed.supports_simulate, Some(true));
    }

    #[test]
    fn tool_descriptor_serialization_omits_unknown_simulate_support() {
        let tool = ToolDescriptor::from(&make_operation("send_message", Some("Send a message")));
        let json = serde_json::to_value(&tool).unwrap();
        let object = json.as_object().unwrap();
        assert!(!object.contains_key("supports_simulate"));
    }

    #[test]
    fn health_filter_serialization() {
        for filter in [
            HealthFilter::Healthy,
            HealthFilter::Degraded,
            HealthFilter::Available,
            HealthFilter::All,
        ] {
            let json = serde_json::to_string(&filter).unwrap();
            let parsed: HealthFilter = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, filter);
        }
    }

    #[test]
    fn connector_archetype_serialization() {
        for archetype in [
            ConnectorArchetype::Unknown,
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Webhook,
        ] {
            let json = serde_json::to_string(&archetype).unwrap();
            let parsed: ConnectorArchetype = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, archetype);
        }
    }

    #[test]
    fn latency_hint_serialization() {
        for hint in [
            LatencyHint::Fast,
            LatencyHint::Medium,
            LatencyHint::Slow,
            LatencyHint::VerySlow,
        ] {
            let json = serde_json::to_string(&hint).unwrap();
            let parsed: LatencyHint = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, hint);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Discovery cache + endpoint behavior
    // ─────────────────────────────────────────────────────────────────────────

    struct CountingRegistry {
        connectors: Vec<ConnectorSummary>,
        list_calls: Arc<AtomicUsize>,
    }

    impl CountingRegistry {
        fn new(connectors: Vec<ConnectorSummary>, list_calls: Arc<AtomicUsize>) -> Self {
            Self {
                connectors,
                list_calls,
            }
        }

        fn find(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.connectors.iter().find(|c| &c.id == id).cloned()
        }
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for CountingRegistry {
        async fn list(&self) -> Vec<ConnectorSummary> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            self.connectors.clone()
        }

        async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.find(id)
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            self.find(id).map(|_| Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            })
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            None
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            self.find(id).map(|_| SelfCheckReport::ok())
        }

        fn version(&self) -> u64 {
            1
        }
    }

    struct SlowCountingRegistry {
        connectors: Vec<ConnectorSummary>,
        list_calls: Arc<AtomicUsize>,
        list_delay: Duration,
    }

    impl SlowCountingRegistry {
        fn new(
            connectors: Vec<ConnectorSummary>,
            list_calls: Arc<AtomicUsize>,
            list_delay: Duration,
        ) -> Self {
            Self {
                connectors,
                list_calls,
                list_delay,
            }
        }

        fn find(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.connectors.iter().find(|c| &c.id == id).cloned()
        }
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for SlowCountingRegistry {
        async fn list(&self) -> Vec<ConnectorSummary> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            time::sleep(self.list_delay).await;
            self.connectors.clone()
        }

        async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.find(id)
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            self.find(id).map(|_| Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            })
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            None
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            self.find(id).map(|_| SelfCheckReport::ok())
        }

        fn version(&self) -> u64 {
            1
        }
    }

    /// Registry whose first `list()` panics while the refresh lock is held —
    /// simulating a loader panic that poisons the single-flight lock — then
    /// succeeds on every subsequent call.
    struct PanicOnceRegistry {
        connectors: Vec<ConnectorSummary>,
        list_calls: Arc<AtomicUsize>,
    }

    impl PanicOnceRegistry {
        fn new(connectors: Vec<ConnectorSummary>, list_calls: Arc<AtomicUsize>) -> Self {
            Self {
                connectors,
                list_calls,
            }
        }

        fn find(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.connectors.iter().find(|c| &c.id == id).cloned()
        }
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for PanicOnceRegistry {
        async fn list(&self) -> Vec<ConnectorSummary> {
            let prior = self.list_calls.fetch_add(1, Ordering::SeqCst);
            assert!(
                prior > 0,
                "PanicOnceRegistry: simulated loader panic on first list()"
            );
            self.connectors.clone()
        }

        async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.find(id)
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            self.find(id).map(|_| Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            })
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            None
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            self.find(id).map(|_| SelfCheckReport::ok())
        }

        fn version(&self) -> u64 {
            1
        }
    }

    /// Registry that records the peak number of `list()` calls executing
    /// concurrently, so a test can prove refreshes are (or are not) serialized.
    struct ConcurrencyProbeRegistry {
        connectors: Vec<ConnectorSummary>,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        delay: Duration,
    }

    impl ConcurrencyProbeRegistry {
        fn new(
            connectors: Vec<ConnectorSummary>,
            active: Arc<AtomicUsize>,
            peak: Arc<AtomicUsize>,
            delay: Duration,
        ) -> Self {
            Self {
                connectors,
                active,
                peak,
                delay,
            }
        }

        fn find(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.connectors.iter().find(|c| &c.id == id).cloned()
        }
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for ConcurrencyProbeRegistry {
        async fn list(&self) -> Vec<ConnectorSummary> {
            let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            time::sleep(self.delay).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            self.connectors.clone()
        }

        async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.find(id)
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            self.find(id).map(|_| Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            })
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            None
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            self.find(id).map(|_| SelfCheckReport::ok())
        }

        fn version(&self) -> u64 {
            1
        }
    }

    struct MutableRegistry {
        connectors: RwLock<Vec<ConnectorSummary>>,
        list_calls: Arc<AtomicUsize>,
        version: AtomicU64,
    }

    impl MutableRegistry {
        fn new(
            connectors: Vec<ConnectorSummary>,
            version: u64,
            list_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                connectors: RwLock::new(connectors),
                list_calls,
                version: AtomicU64::new(version),
            }
        }

        async fn replace(&self, connectors: Vec<ConnectorSummary>, version: u64) {
            *self.connectors.write().await = connectors;
            self.version.store(version, Ordering::SeqCst);
        }

        async fn find(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.connectors
                .read()
                .await
                .iter()
                .find(|connector| &connector.id == id)
                .cloned()
        }
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for MutableRegistry {
        async fn list(&self) -> Vec<ConnectorSummary> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            self.connectors.read().await.clone()
        }

        async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.find(id).await
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            self.find(id).await.map(|_| Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            })
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            None
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            self.find(id).await.map(|_| SelfCheckReport::ok())
        }

        fn version(&self) -> u64 {
            self.version.load(Ordering::SeqCst)
        }
    }

    struct VolatileGetRegistry {
        summary: ConnectorSummary,
        list_calls: Arc<AtomicUsize>,
        get_calls: Arc<AtomicUsize>,
    }

    impl VolatileGetRegistry {
        fn new(
            summary: ConnectorSummary,
            list_calls: Arc<AtomicUsize>,
            get_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                summary,
                list_calls,
                get_calls,
            }
        }
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for VolatileGetRegistry {
        async fn list(&self) -> Vec<ConnectorSummary> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            vec![self.summary.clone()]
        }

        async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            if &self.summary.id != id {
                return None;
            }

            let mut summary = self.summary.clone();
            let offset_millis = i64::try_from(self.get_calls.fetch_add(1, Ordering::SeqCst))
                .unwrap_or(i64::MAX.saturating_sub(1));
            summary.last_health_check = summary.last_health_check.map(|timestamp| {
                timestamp + chrono::Duration::milliseconds(offset_millis.saturating_add(1))
            });
            Some(summary)
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            (&self.summary.id == id).then_some(Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            })
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            None
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            (&self.summary.id == id).then_some(SelfCheckReport::ok())
        }

        fn version(&self) -> u64 {
            1
        }
    }

    struct AllowPolicy;

    #[async_trait::async_trait]
    impl PolicyEngine for AllowPolicy {
        async fn evaluate_preflight(&self, _request: &PreflightRequest) -> PreflightResponse {
            PreflightResponse::allowed()
        }
    }

    struct DenyPolicy;

    #[async_trait::async_trait]
    impl PolicyEngine for DenyPolicy {
        async fn evaluate_preflight(&self, _request: &PreflightRequest) -> PreflightResponse {
            PreflightResponse::denied("policy denied")
        }
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_cache_reuses_within_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "cache",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let cache = DiscoveryCache::new(Duration::from_secs(60));

        let first = cache.get_or_refresh(&registry).await;
        let second = cache.get_or_refresh(&registry).await;

        assert!(!first.cache_hit);
        assert!(second.cache_hit);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_cache_collapses_concurrent_cold_misses() {
        const CALLERS: usize = 128;

        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "stampede",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = Arc::new(SlowCountingRegistry::new(
            vec![summary.clone()],
            Arc::clone(&calls),
            Duration::from_millis(25),
        ));
        #[allow(clippy::duration_suboptimal_units)]
        let cache = Arc::new(DiscoveryCache::new(Duration::from_secs(60)));

        let mut handles = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let cache = Arc::clone(&cache);
            let registry = Arc::clone(&registry);
            handles.push(task::spawn(async move {
                cache.get_or_refresh(Arc::as_ref(&registry)).await
            }));
        }

        let mut misses = 0_usize;
        let mut hits = 0_usize;
        for handle in handles {
            let result = handle.await.expect("cache caller task should complete");
            if result.cache_hit {
                hits += 1;
            } else {
                misses += 1;
            }
            assert_eq!(result.connectors.len(), 1);
            assert_eq!(
                result.connectors.first().map(|connector| &connector.id),
                Some(&summary.id)
            );
        }

        assert_eq!(misses, 1);
        assert_eq!(hits, CALLERS - 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let evidence = serde_json::json!({
            "event": "fcp.host.metadata_cache",
            "case": "discovery_cache_collapses_concurrent_cold_misses",
            "callers": CALLERS,
            "hits": hits,
            "misses": misses,
            "registry_list_calls": calls.load(Ordering::SeqCst),
            "collapsed_waiters": hits,
        });
        let evidence_jsonl = format!("{}\n", serde_json::to_string(&evidence).unwrap());
        let parsed: serde_json::Value = serde_json::from_str(evidence_jsonl.trim_end()).unwrap();
        let caller_count = u64::try_from(CALLERS).expect("caller count should fit in u64");
        let collapsed_count =
            u64::try_from(CALLERS - 1).expect("collapsed caller count should fit in u64");
        assert_eq!(parsed["event"], "fcp.host.metadata_cache");
        assert_eq!(parsed["callers"].as_u64(), Some(caller_count));
        assert_eq!(parsed["hits"].as_u64(), Some(collapsed_count));
        assert_eq!(parsed["misses"].as_u64(), Some(1));
        assert_eq!(parsed["registry_list_calls"].as_u64(), Some(1));
        print!("{evidence_jsonl}");
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_cache_refreshes_when_expired() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "expired",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        let cache = DiscoveryCache::new(Duration::from_millis(0));

        let first = cache.get_or_refresh(&registry).await;
        let second = cache.get_or_refresh(&registry).await;

        assert!(!first.cache_hit);
        assert!(!second.cache_hit);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_ttl_zero_does_not_serialize_concurrent_refreshes() {
        // With caching disabled (ttl == 0) the fast-path check always misses, so
        // holding the single-flight refresh lock across `registry.list().await`
        // would serialize *every* concurrent discovery call. The ttl == 0 bypass
        // must let concurrent refreshes run in parallel.
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "ttl-zero",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = Arc::new(ConcurrencyProbeRegistry::new(
            vec![summary.clone()],
            Arc::clone(&active),
            Arc::clone(&peak),
            Duration::from_millis(25),
        ));
        let cache = Arc::new(DiscoveryCache::new(Duration::from_millis(0)));

        let mut handles = Vec::with_capacity(2);
        for _ in 0..2 {
            let cache = Arc::clone(&cache);
            let registry = Arc::clone(&registry);
            handles.push(task::spawn(async move {
                cache.get_or_refresh(Arc::as_ref(&registry)).await
            }));
        }
        for handle in handles {
            let result = handle.await.expect("refresh task should complete");
            assert!(!result.cache_hit);
            assert_eq!(result.connectors.len(), 1);
        }

        assert_eq!(
            peak.load(Ordering::SeqCst),
            2,
            "ttl == 0 must not serialize concurrent refreshes through the single-flight lock"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_recovers_after_loader_panic_poisons_refresh_lock() {
        // A loader panic while the refresh lock is held poisons that lock. The
        // cache must degrade to an unsynchronized refresh rather than propagating
        // the poison panic on every subsequent call (permanent discovery outage).
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "poison",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = Arc::new(PanicOnceRegistry::new(
            vec![summary.clone()],
            Arc::clone(&calls),
        ));
        #[allow(clippy::duration_suboptimal_units)]
        let cache = Arc::new(DiscoveryCache::new(Duration::from_secs(60)));

        // First refresh panics inside the loader (while holding the refresh lock),
        // poisoning it. `task::spawn` catches the unwind and reports it as an err.
        let first = {
            let cache = Arc::clone(&cache);
            let registry = Arc::clone(&registry);
            task::spawn(async move { cache.get_or_refresh(Arc::as_ref(&registry)).await }).await
        };
        assert!(
            first.is_err(),
            "first refresh should panic inside the loader and poison the refresh lock"
        );

        // The refresh lock is now poisoned; discovery must still recover.
        let recovered = cache.get_or_refresh(Arc::as_ref(&registry)).await;
        assert!(!recovered.cache_hit);
        assert_eq!(recovered.connectors.len(), 1);
        assert_eq!(
            recovered.connectors.first().map(|connector| &connector.id),
            Some(&summary.id)
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "loader is called once (panics) then once more (succeeds)"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_cache_refreshes_when_registry_version_changes() {
        let calls = Arc::new(AtomicUsize::new(0));
        let primary = make_summary(
            "versioned",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let secondary = make_summary(
            "versioned-extra",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );
        let registry = MutableRegistry::new(vec![primary.clone()], 1, Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let cache = DiscoveryCache::new(Duration::from_secs(60));

        let first = cache.get_or_refresh(&registry).await;
        assert_eq!(first.connectors.len(), 1);
        assert_eq!(first.registry_version, 1);
        assert!(!first.cache_hit);

        registry.replace(vec![primary, secondary.clone()], 2).await;

        let second = cache.get_or_refresh(&registry).await;
        assert_eq!(second.connectors.len(), 2);
        assert_eq!(second.registry_version, 2);
        assert!(!second.cache_hit);
        assert!(
            second
                .connectors
                .iter()
                .any(|connector| connector.id == secondary.id)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_invalidate_cache_forces_refresh() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "invalidate",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let endpoint = DiscoveryEndpoint::with_cache_ttl(
            Arc::new(registry),
            Arc::new(AllowPolicy),
            Duration::from_secs(60),
        );

        let _ = endpoint.discover(None).await;
        let _ = endpoint.discover(None).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        endpoint.invalidate_cache().await;
        let _ = endpoint.discover(None).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_reports_cache_hit_metadata() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "cache-meta",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let endpoint = DiscoveryEndpoint::with_cache_ttl(
            Arc::new(registry),
            Arc::new(AllowPolicy),
            Duration::from_secs(60),
        );

        let first = endpoint.discover_with_metadata(None).await;
        let second = endpoint
            .discover_with_metadata(Some(DiscoveryFilter {
                category: Some("test".to_string()),
                ..Default::default()
            }))
            .await;

        assert!(!first.cache_hit);
        assert!(second.cache_hit);
        assert_eq!(first.response.registry_version, 1);
        assert_eq!(second.response.registry_version, 1);
        assert_eq!(second.response.connectors.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cache_validator_prefers_etag_when_present() {
        let now = Utc::now();
        let cache = CacheMetadata {
            etag: "\"etag-1\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: Some(30),
        };

        let validator = CacheValidator {
            if_none_match: Some("\"etag-2\"".to_string()),
            if_modified_since: Some(now + chrono::Duration::seconds(1)),
        };

        assert!(!validator.is_not_modified(&cache));
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_returns_cache_metadata() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "cache-response",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::with_cache_ttl(
            Arc::new(registry),
            Arc::new(AllowPolicy),
            Duration::from_secs(45),
        );

        let response = endpoint.discover(None).await;
        let cache = response
            .cache
            .expect("discovery response should include cache metadata");

        assert!(cache.etag.starts_with('"'));
        assert!(cache.etag.ends_with('"'));
        assert_eq!(cache.max_age_seconds, 45);
        assert_eq!(cache.stale_while_revalidate_seconds, Some(45));
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_query_returns_not_modified_for_matching_etag() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "cache-304",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::with_cache_ttl(
            Arc::new(registry),
            Arc::new(AllowPolicy),
            Duration::from_secs(30),
        );

        let first = endpoint.discover_query(None, None).await;
        let etag = first
            .response
            .cache
            .as_ref()
            .expect("cache metadata should be present")
            .etag
            .clone();

        let second = endpoint
            .discover_query(
                None,
                Some(CacheValidator {
                    if_none_match: Some(etag),
                    if_modified_since: None,
                }),
            )
            .await;

        assert_eq!(second.response.connectors.len(), 1);
        assert_eq!(second.response.connectors[0].id, summary.id);
        assert_eq!(
            second.response.meta.as_ref().map(|meta| meta.status),
            Some(304)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_query_returns_not_modified_for_if_modified_since() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "cache-time",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::with_cache_ttl(
            Arc::new(registry),
            Arc::new(AllowPolicy),
            Duration::from_secs(30),
        );

        let first = endpoint.discover_query(None, None).await;
        let last_modified = first
            .response
            .cache
            .as_ref()
            .expect("cache metadata should be present")
            .last_modified;

        let second = endpoint
            .discover_query(
                None,
                Some(CacheValidator {
                    if_none_match: None,
                    if_modified_since: Some(last_modified + chrono::Duration::seconds(1)),
                }),
            )
            .await;

        assert_eq!(
            second.response.meta.as_ref().map(|meta| meta.status),
            Some(304)
        );
        assert_eq!(second.response.connectors.len(), 1);
        assert_eq!(second.response.connectors[0].id, summary.id);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_query_returns_fresh_response_for_stale_etag() {
        let calls = Arc::new(AtomicUsize::new(0));
        let primary = make_summary(
            "cache-stale",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let secondary = make_summary(
            "cache-stale-extra",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );
        let registry = Arc::new(MutableRegistry::new(
            vec![primary.clone()],
            1,
            Arc::clone(&calls),
        ));
        let endpoint = DiscoveryEndpoint::with_cache_ttl(
            Arc::clone(&registry),
            Arc::new(AllowPolicy),
            Duration::from_secs(30),
        );

        let first = endpoint.discover_query(None, None).await;
        let etag = first
            .response
            .cache
            .as_ref()
            .expect("cache metadata should be present")
            .etag
            .clone();

        registry.replace(vec![primary, secondary], 2).await;

        let second = endpoint
            .discover_query(
                None,
                Some(CacheValidator {
                    if_none_match: Some(etag),
                    if_modified_since: None,
                }),
            )
            .await;

        assert_eq!(second.response.connectors.len(), 2);
        assert!(second.response.meta.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_with_cache_returns_not_modified_for_matching_etag() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "cache-introspect",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let first = endpoint
            .introspect_with_cache(&summary.id, None)
            .await
            .expect("introspection should succeed");
        let etag = first
            .cache
            .as_ref()
            .expect("cache metadata should be present")
            .etag
            .clone();

        let second = endpoint
            .introspect_with_cache(
                &summary.id,
                Some(CacheValidator {
                    if_none_match: Some(etag),
                    if_modified_since: None,
                }),
            )
            .await
            .expect("conditional introspection should succeed");

        assert_eq!(second.tools.len(), first.tools.len());
        assert_eq!(
            second.introspection.operations.len(),
            first.introspection.operations.len()
        );
        assert_eq!(second.rate_limits.is_some(), first.rate_limits.is_some());
        assert_eq!(second.meta.as_ref().map(|meta| meta.status), Some(304));
    }

    #[fcp_async_core::runtime::test]
    async fn introspection_with_cache_ignores_volatile_get_summary_fields() {
        let list_calls = Arc::new(AtomicUsize::new(0));
        let get_calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "cache-introspect-volatile",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = VolatileGetRegistry::new(
            summary.clone(),
            Arc::clone(&list_calls),
            Arc::clone(&get_calls),
        );
        let endpoint = DiscoveryEndpoint::with_cache_ttl(
            Arc::new(registry),
            Arc::new(AllowPolicy),
            Duration::from_secs(30),
        );

        let first = endpoint
            .introspect_with_cache(&summary.id, None)
            .await
            .expect("introspection should succeed");
        let etag = first
            .cache
            .as_ref()
            .expect("cache metadata should be present")
            .etag
            .clone();

        let second = endpoint
            .introspect_with_cache(
                &summary.id,
                Some(CacheValidator {
                    if_none_match: Some(etag),
                    if_modified_since: None,
                }),
            )
            .await
            .expect("conditional introspection should succeed");

        assert_eq!(second.meta.as_ref().map(|meta| meta.status), Some(304));
        assert_eq!(list_calls.load(Ordering::SeqCst), 1);
        assert_eq!(get_calls.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_introspect_missing_connector() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));
        let id = ConnectorId::new("missing", "test", "v1").unwrap();

        let err = endpoint.introspect(&id).await.unwrap_err();
        assert!(matches!(err, HostError::ConnectorNotFound(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_marks_missing_archetype_unknown() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "default-arch",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let response = endpoint.introspect(&summary.id).await.unwrap();
        assert_eq!(response.archetype, ConnectorArchetype::Unknown);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_self_check_missing_connector() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));
        let id = ConnectorId::new("missing", "test", "v1").unwrap();

        let err = endpoint.self_check(&id).await.unwrap_err();
        assert!(matches!(err, HostError::ConnectorNotFound(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_self_check_ok() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "self-check",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let response = endpoint.self_check(&summary.id).await.unwrap();
        assert_eq!(response.connector_id, summary.id);
        assert_eq!(response.report.status, SelfCheckStatus::Ok);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_preflight_passthrough() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(DenyPolicy));

        let request = PreflightRequest {
            connector_id: ConnectorId::new("test", "pf", "v1").unwrap(),
            operation: "read".into(),
            params: None,
            principal: None,
            zone_id: None,
        };

        let response = endpoint.preflight(request).await;
        assert!(!response.allowed);
        assert_eq!(response.reason.as_deref(), Some("policy denied"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Combined filter tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn filter_matches_combined_category_and_risk() {
        let filter = DiscoveryFilter {
            category: Some("messaging".to_string()),
            max_risk: Some(SafetyTier::Risky),
            health: None,
        };

        // Matches both category and risk
        let safe_msg = make_summary(
            "test",
            "sm",
            "v1",
            vec!["messaging"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(filter.matches(&safe_msg));

        // Right category, too risky
        let dangerous_msg = make_summary(
            "test",
            "dm",
            "v1",
            vec!["messaging"],
            SafetyTier::Dangerous,
            ConnectorHealth::healthy(),
        );
        assert!(!filter.matches(&dangerous_msg));

        // Wrong category, right risk
        let safe_storage = make_summary(
            "test",
            "ss",
            "v1",
            vec!["storage"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(!filter.matches(&safe_storage));
    }

    #[test]
    fn filter_matches_all_three_dimensions() {
        let filter = DiscoveryFilter {
            category: Some("ai".to_string()),
            max_risk: Some(SafetyTier::Risky),
            health: Some(HealthFilter::Available),
        };

        // Matches all
        let good = make_summary(
            "test",
            "g",
            "v1",
            vec!["ai"],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );
        assert!(filter.matches(&good));

        // Matches category + risk, but unavailable
        let down = make_summary(
            "test",
            "dn",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::unavailable("down"),
        );
        assert!(!filter.matches(&down));

        // Degraded counts as available
        let degraded = make_summary(
            "test",
            "dg",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::degraded("slow"),
        );
        assert!(filter.matches(&degraded));
    }

    #[test]
    fn filter_health_degraded_only_matches_degraded() {
        let filter = DiscoveryFilter {
            health: Some(HealthFilter::Degraded),
            ..Default::default()
        };

        let healthy = make_summary(
            "test",
            "hh",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let degraded = make_summary(
            "test",
            "dd",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::degraded("slow"),
        );

        assert!(!filter.matches(&healthy));
        assert!(filter.matches(&degraded));
    }

    #[test]
    fn filter_health_all_matches_everything() {
        let filter = DiscoveryFilter {
            health: Some(HealthFilter::All),
            ..Default::default()
        };

        let healthy = make_summary(
            "test",
            "ah",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let degraded = make_summary(
            "test",
            "ad",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::degraded("slow"),
        );
        let unavailable = make_summary(
            "test",
            "au",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::unavailable("down"),
        );

        assert!(filter.matches(&healthy));
        assert!(filter.matches(&degraded));
        assert!(filter.matches(&unavailable));
    }

    #[test]
    fn filter_category_with_multi_category_connector() {
        let filter = DiscoveryFilter {
            category: Some("ai".to_string()),
            ..Default::default()
        };

        let multi = make_summary(
            "test",
            "mc",
            "v1",
            vec!["messaging", "ai", "knowledge"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(filter.matches(&multi));

        let no_match = make_summary(
            "test",
            "nm",
            "v1",
            vec!["messaging", "storage"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(!filter.matches(&no_match));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PreflightResponse populated fields
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn preflight_response_with_missing_capabilities() {
        let mut resp = PreflightResponse::denied("missing caps");
        resp.missing_capabilities = vec!["cap.read".to_string(), "cap.write".to_string()];

        assert!(!resp.allowed);
        assert_eq!(resp.missing_capabilities.len(), 2);
        assert!(resp.missing_capabilities.contains(&"cap.read".to_string()));
    }

    #[test]
    fn preflight_response_with_rate_limit() {
        let mut resp = PreflightResponse::denied("rate limited");
        resp.rate_limit = Some(PreflightRateLimit {
            limited: true,
            remaining: 0,
            reset_at: Some(Utc::now()),
        });

        assert!(resp.rate_limit.as_ref().unwrap().limited);
        assert_eq!(resp.rate_limit.as_ref().unwrap().remaining, 0);
        assert!(resp.rate_limit.as_ref().unwrap().reset_at.is_some());
    }

    #[test]
    fn preflight_response_with_estimated_cost() {
        let mut resp = PreflightResponse::allowed();
        resp.estimated_cost = Some(EstimatedCost {
            api_calls: Some(3),
            tokens: Some(1500),
            cost_cents: Some(2),
        });

        let cost = resp.estimated_cost.as_ref().unwrap();
        assert_eq!(cost.api_calls, Some(3));
        assert_eq!(cost.tokens, Some(1500));
        assert_eq!(cost.cost_cents, Some(2));
    }

    #[test]
    fn preflight_response_serialization_roundtrip() {
        use fcp_kernel::{BudgetEnforcement, BudgetStatus, UsageBudgetUsage, UsageMetricKind};
        use fcp_prelude::ZoneId;

        let mut resp = PreflightResponse::denied("rate limited");
        resp.missing_capabilities = vec!["cap.send".to_string()];
        resp.rate_limit = Some(PreflightRateLimit {
            limited: true,
            remaining: 5,
            reset_at: None,
        });
        resp.estimated_cost = Some(EstimatedCost {
            api_calls: Some(1),
            tokens: None,
            cost_cents: Some(10),
        });
        resp.budget_status = Some(UsageBudgetSnapshot {
            zone_id: ZoneId::work(),
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetUsage {
                metric: UsageMetricKind::Tokens,
                used: 1500,
                limit: 2000,
                remaining: 500,
                window_started_at: 1_700_000_000,
                window_resets_at: 1_700_000_060,
                status: BudgetStatus::Ok,
            }],
            updated_at: 1_700_000_020,
        });

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: PreflightResponse = serde_json::from_str(&json).unwrap();

        assert!(!parsed.allowed);
        assert_eq!(parsed.missing_capabilities, vec!["cap.send"]);
        assert!(parsed.rate_limit.as_ref().unwrap().limited);
        assert_eq!(parsed.rate_limit.as_ref().unwrap().remaining, 5);
        assert_eq!(parsed.estimated_cost.as_ref().unwrap().api_calls, Some(1));
        assert!(parsed.estimated_cost.as_ref().unwrap().tokens.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EstimatedCost + HostHealth serialization
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn estimated_cost_partial_fields() {
        let cost = EstimatedCost {
            api_calls: None,
            tokens: Some(500),
            cost_cents: None,
        };

        let json = serde_json::to_string(&cost).unwrap();
        let parsed: EstimatedCost = serde_json::from_str(&json).unwrap();
        assert!(parsed.api_calls.is_none());
        assert_eq!(parsed.tokens, Some(500));
        assert!(parsed.cost_cents.is_none());
    }

    #[test]
    fn host_health_response_serialization() {
        let response = HostHealthResponse {
            status: HostHealthStatus::Degraded,
            connectors: HashMap::new(),
            uptime_seconds: 3600,
            active_connections: 5,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: HostHealthResponse = serde_json::from_str(&json).unwrap();

        assert!(matches!(parsed.status, HostHealthStatus::Degraded));
        assert_eq!(parsed.uptime_seconds, 3600);
        assert_eq!(parsed.active_connections, 5);
    }

    #[test]
    fn host_health_status_serialization() {
        for status in [
            HostHealthStatus::Healthy,
            HostHealthStatus::Degraded,
            HostHealthStatus::Unhealthy,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: HostHealthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(
                std::mem::discriminant(&parsed),
                std::mem::discriminant(&status)
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Endpoint: discover with strict filter returns empty
    // ─────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_discover_all_filtered_out() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "test",
            "only",
            "v1",
            vec!["storage"],
            SafetyTier::Dangerous,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        // Filter that excludes everything: wrong category + too strict risk
        let filter = DiscoveryFilter {
            category: Some("messaging".to_string()),
            max_risk: Some(SafetyTier::Safe),
            health: None,
        };

        let response = endpoint.discover(Some(filter)).await;
        assert!(response.connectors.is_empty());
        assert_eq!(response.registry_version, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_discover_no_filter_returns_all() {
        let calls = Arc::new(AtomicUsize::new(0));
        let s1 = make_summary(
            "a",
            "first",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let s2 = make_summary(
            "b",
            "second",
            "v1",
            vec!["storage"],
            SafetyTier::Dangerous,
            ConnectorHealth::degraded("slow"),
        );
        let registry = CountingRegistry::new(vec![s1, s2], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let response = endpoint.discover(None).await;
        assert_eq!(response.connectors.len(), 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ToolDescriptor::from(OperationInfo) conversion tests
    // ─────────────────────────────────────────────────────────────────────────

    fn make_operation(id: &str, description: Option<&str>) -> OperationInfo {
        use fcp_kernel::OperationId;
        use fcp_prelude::RateLimit;
        OperationInfo {
            id: OperationId::new(id).expect("valid operation id"),
            summary: format!("{id} summary"),
            description: description.map(String::from),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "string"}),
            capability: CapabilityId::new(format!("cap.{id}")).expect("valid cap id"),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "Always".to_string(),
                common_mistakes: vec!["Mistake A".into()],
                examples: vec![r#"{"key":"val"}"#.into()],
                related: vec![CapabilityId::new("cap.other").unwrap()],
            },
            rate_limit: Some(RateLimit {
                max: 100,
                per_ms: 60_000,
                burst: None,
                scope: Some("per_user".into()),
                pool_name: Some("api_pool".into()),
            }),
            requires_approval: Some(ApprovalMode::Interactive),
        }
    }

    #[test]
    fn tool_descriptor_from_operation_info_with_description() {
        let op = make_operation("send_msg", Some("Send a message"));
        let tool = ToolDescriptor::from(&op);

        assert_eq!(tool.name, "send_msg");
        assert_eq!(tool.description, "Send a message");
        assert_eq!(tool.risk_level, RiskLevel::Medium);
        assert_eq!(tool.safety_tier, SafetyTier::Risky);
        assert_eq!(tool.idempotency, IdempotencyClass::Strict);
        assert!(tool.requires_confirmation);
        assert!(tool.idempotent); // Strict => idempotent
        assert_eq!(tool.supports_simulate, None);
        assert!(tool.ai_hints.is_some());
    }

    #[test]
    fn tool_descriptor_from_operation_info_no_description_uses_summary() {
        let op = make_operation("list_items", None);
        let tool = ToolDescriptor::from(&op);

        assert_eq!(tool.description, "list_items summary");
    }

    #[test]
    fn tool_descriptor_from_operation_idempotent_best_effort() {
        let mut op = make_operation("update", None);
        op.idempotency = IdempotencyClass::BestEffort;
        let tool = ToolDescriptor::from(&op);
        assert!(tool.idempotent);
    }

    #[test]
    fn tool_descriptor_from_operation_not_idempotent_none() {
        let mut op = make_operation("create", None);
        op.idempotency = IdempotencyClass::None;
        op.requires_approval = None;
        let tool = ToolDescriptor::from(&op);
        assert!(!tool.idempotent);
        assert!(!tool.requires_confirmation);
        assert!(tool.approval_mode.is_none());
    }

    #[test]
    fn tool_descriptor_from_operation_rate_limit_pool_name_preferred() {
        let op = make_operation("op1", None);
        let tool = ToolDescriptor::from(&op);
        assert_eq!(tool.rate_limits, vec!["api_pool"]);
    }

    #[test]
    fn tool_descriptor_from_operation_rate_limit_without_pool_name_has_no_named_pools() {
        use fcp_prelude::RateLimit;
        let mut op = make_operation("op2", None);
        op.rate_limit = Some(RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: Some("per_connector".into()),
            pool_name: None,
        });
        let tool = ToolDescriptor::from(&op);
        assert!(tool.rate_limits.is_empty());
    }

    #[test]
    fn tool_descriptor_from_operation_no_rate_limit() {
        let mut op = make_operation("op3", None);
        op.rate_limit = None;
        let tool = ToolDescriptor::from(&op);
        assert!(tool.rate_limits.is_empty());
    }

    #[test]
    fn tool_descriptor_from_operation_empty_ai_hints() {
        let mut op = make_operation("op4", None);
        op.ai_hints = AgentHint::default();
        let tool = ToolDescriptor::from(&op);
        assert!(tool.ai_hints.is_none());
    }

    #[test]
    fn tool_descriptor_from_operation_examples_parsed() {
        let op = make_operation("op6", None);
        let tool = ToolDescriptor::from(&op);
        assert_eq!(tool.examples.len(), 1);
        assert_eq!(tool.examples[0].input, serde_json::json!({"key": "val"}));
        assert!(tool.examples[0].description.is_none());
        assert!(tool.examples[0].output.is_none());
    }

    #[test]
    fn tool_descriptor_from_operation_invalid_example_json() {
        let mut op = make_operation("op7", None);
        op.ai_hints.examples = vec!["not valid json".into()];
        let tool = ToolDescriptor::from(&op);
        assert!(tool.examples.is_empty());
    }

    #[test]
    fn tool_descriptor_from_operation_skips_only_invalid_examples() {
        let mut op = make_operation("op8", None);
        op.ai_hints.examples = vec![r#"{"key":"val"}"#.into(), "not valid json".into()];
        let tool = ToolDescriptor::from(&op);

        assert_eq!(tool.examples.len(), 1);
        assert_eq!(tool.examples[0].input, serde_json::json!({"key": "val"}));
    }

    #[test]
    fn tool_descriptor_from_operation_approval_mode_none_does_not_require_confirmation() {
        let mut op = make_operation("op9", None);
        op.requires_approval = Some(ApprovalMode::None);
        let tool = ToolDescriptor::from(&op);

        assert_eq!(tool.approval_mode, Some(ApprovalMode::None));
        assert!(!tool.requires_confirmation);
    }

    #[test]
    fn tool_descriptor_from_operation_with_declarations_overrides_rate_limits() {
        use fcp_kernel::RateLimitDeclarations;
        let op = make_operation("send_msg", None);
        let mut decls = RateLimitDeclarations {
            limits: vec![],
            tool_pool_map: HashMap::new(),
        };
        decls
            .tool_pool_map
            .insert("send_msg".into(), vec!["pool_a".into(), "pool_b".into()]);

        let tool = ToolDescriptor::from_operation(&op, Some(&decls));
        assert_eq!(tool.rate_limits, vec!["pool_a", "pool_b"]);
    }

    #[test]
    fn tool_descriptor_from_operation_with_declarations_no_match() {
        use fcp_kernel::RateLimitDeclarations;
        let op = make_operation("send_msg", None);
        let decls = RateLimitDeclarations {
            limits: vec![],
            tool_pool_map: HashMap::new(),
        };

        let tool = ToolDescriptor::from_operation(&op, Some(&decls));
        // Falls through to the From impl's rate_limits
        assert_eq!(tool.rate_limits, vec!["api_pool"]);
    }

    #[test]
    fn tool_descriptor_from_operation_with_no_declarations() {
        let op = make_operation("send_msg", None);
        let tool = ToolDescriptor::from_operation(&op, None);
        assert_eq!(tool.rate_limits, vec!["api_pool"]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SafetyTier level exact values
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn safety_tier_level_exact_values() {
        assert_eq!(SafetyTier::Safe.level(), 0);
        assert_eq!(SafetyTier::Risky.level(), 1);
        assert_eq!(SafetyTier::Dangerous.level(), 2);
        assert_eq!(SafetyTier::Critical.level(), 3);
        assert_eq!(SafetyTier::Forbidden.level(), 4);
    }

    #[test]
    fn safety_tier_forbidden_not_at_most_critical() {
        assert!(!SafetyTier::Forbidden.is_at_most(SafetyTier::Critical));
        assert!(SafetyTier::Forbidden.is_at_most(SafetyTier::Forbidden));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional serde roundtrip tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn preflight_request_serialization_roundtrip() {
        let req = PreflightRequest {
            connector_id: ConnectorId::new("test", "conn", "v1").unwrap(),
            operation: "send".into(),
            params: Some(serde_json::json!({"channel": "123"})),
            principal: Some("user:alice".into()),
            zone_id: Some(ZoneId::work()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: PreflightRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation, "send");
        assert_eq!(parsed.principal.as_deref(), Some("user:alice"));
        assert!(parsed.params.is_some());
    }

    #[test]
    fn preflight_request_minimal_fields() {
        let req = PreflightRequest {
            connector_id: ConnectorId::new("test", "conn", "v1").unwrap(),
            operation: "read".into(),
            params: None,
            principal: None,
            zone_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: PreflightRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.params.is_none());
        assert!(parsed.principal.is_none());
        assert!(parsed.zone_id.is_none());
    }

    #[test]
    fn self_check_response_serialization_roundtrip() {
        let resp = SelfCheckResponse {
            connector_id: ConnectorId::new("test", "conn", "v1").unwrap(),
            report: SelfCheckReport::ok(),
            checked_at: Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: SelfCheckResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, resp.connector_id);
        assert_eq!(parsed.report.status, SelfCheckStatus::Ok);
    }

    #[test]
    fn discovery_response_serialization_roundtrip() {
        let connectors = vec![make_summary(
            "test",
            "rtrip",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        )];
        let resp = DiscoveryResponse::new(connectors, 99);
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DiscoveryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.registry_version, 99);
        assert_eq!(parsed.supports_streaming, None);
        assert_eq!(parsed.supports_batching, None);
        assert_eq!(parsed.connectors.len(), 1);
    }

    #[test]
    fn tool_example_serialization_roundtrip() {
        let example = ToolExample {
            description: Some("Send hello".into()),
            input: serde_json::json!({"msg": "hello"}),
            output: Some(serde_json::json!({"ok": true})),
        };
        let json = serde_json::to_string(&example).unwrap();
        let parsed: ToolExample = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.description.as_deref(), Some("Send hello"));
        assert_eq!(parsed.input["msg"], "hello");
        assert!(parsed.output.is_some());
    }

    #[test]
    fn tool_example_minimal() {
        let example = ToolExample {
            description: None,
            input: serde_json::json!({}),
            output: None,
        };
        let json = serde_json::to_string(&example).unwrap();
        let parsed: ToolExample = serde_json::from_str(&json).unwrap();
        assert!(parsed.description.is_none());
        assert!(parsed.output.is_none());
    }

    #[test]
    fn estimated_cost_all_none() {
        let cost = EstimatedCost {
            api_calls: None,
            tokens: None,
            cost_cents: None,
        };
        let json = serde_json::to_string(&cost).unwrap();
        let parsed: EstimatedCost = serde_json::from_str(&json).unwrap();
        assert!(parsed.api_calls.is_none());
        assert!(parsed.tokens.is_none());
        assert!(parsed.cost_cents.is_none());
    }

    #[test]
    fn preflight_rate_limit_no_reset_at() {
        let rl = PreflightRateLimit {
            limited: false,
            remaining: 42,
            reset_at: None,
        };
        let json = serde_json::to_string(&rl).unwrap();
        let parsed: PreflightRateLimit = serde_json::from_str(&json).unwrap();
        assert!(!parsed.limited);
        assert_eq!(parsed.remaining, 42);
        assert!(parsed.reset_at.is_none());
    }

    #[test]
    fn introspection_response_serialization_roundtrip() {
        let summary = make_summary(
            "test",
            "intro",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let resp = IntrospectionResponse {
            connector: summary,
            tools: vec![],
            rate_limits: None,
            archetype: ConnectorArchetype::Streaming,
            introspection: Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            },
            cache: None,
            meta: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: IntrospectionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.archetype, ConnectorArchetype::Streaming);
        assert!(parsed.tools.is_empty());
        assert!(parsed.rate_limits.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Host health with populated connectors map
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_health_response_with_connectors() {
        let mut connectors = HashMap::new();
        let id1 = ConnectorId::new("svc", "a", "v1").unwrap();
        let id2 = ConnectorId::new("svc", "b", "v1").unwrap();
        connectors.insert(id1, ConnectorHealth::healthy());
        connectors.insert(id2, ConnectorHealth::unavailable("timeout"));

        let resp = HostHealthResponse {
            status: HostHealthStatus::Degraded,
            connectors,
            uptime_seconds: 7200,
            active_connections: 10,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let parsed: HostHealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connectors.len(), 2);
        assert_eq!(parsed.uptime_seconds, 7200);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DiscoveryFilter edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn filter_matches_empty_categories_vec() {
        let filter = DiscoveryFilter {
            category: Some("ai".into()),
            ..Default::default()
        };
        let summary = make_summary(
            "test",
            "empty",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        // Connector with no categories should not match any category filter
        assert!(!filter.matches(&summary));
    }

    #[test]
    fn filter_default_matches_everything() {
        let filter = DiscoveryFilter::default();
        assert!(filter.category.is_none());
        assert!(filter.max_risk.is_none());
        assert!(filter.health.is_none());

        let unavailable = make_summary(
            "test",
            "unav",
            "v1",
            vec![],
            SafetyTier::Forbidden,
            ConnectorHealth::unavailable("gone"),
        );
        assert!(filter.matches(&unavailable));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorSummary optional fields
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_summary_with_optional_fields() {
        let id = ConnectorId::new("test", "full", "v1").unwrap();
        let summary = ConnectorSummary {
            id,
            name: "Full Summary".into(),
            description: Some("A described connector".into()),
            version: semver::Version::new(2, 3, 4),
            categories: vec!["messaging".into(), "ai".into()],
            tool_count: 15,
            max_safety_tier: SafetyTier::Critical,
            enabled: false,
            health: ConnectorHealth::degraded("partial"),
            last_health_check: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: ConnectorSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.description.as_deref(), Some("A described connector"));
        assert_eq!(parsed.version.to_string(), "2.3.4");
        assert_eq!(parsed.tool_count, 15);
        assert!(!parsed.enabled);
        assert!(parsed.last_health_check.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Debug trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn discovery_filter_debug() {
        let filter = DiscoveryFilter {
            category: Some("test".into()),
            max_risk: Some(SafetyTier::Dangerous),
            health: Some(HealthFilter::Healthy),
        };
        let debug = format!("{filter:?}");
        assert!(debug.contains("DiscoveryFilter"));
        assert!(debug.contains("Dangerous"));
    }

    #[test]
    fn preflight_request_debug() {
        let req = PreflightRequest {
            connector_id: ConnectorId::new("test", "dbg", "v1").unwrap(),
            operation: "invoke".into(),
            params: None,
            principal: None,
            zone_id: None,
        };
        let debug = format!("{req:?}");
        assert!(debug.contains("PreflightRequest"));
        assert!(debug.contains("invoke"));
    }

    #[test]
    fn preflight_response_debug() {
        let resp = PreflightResponse::allowed();
        let debug = format!("{resp:?}");
        assert!(debug.contains("PreflightResponse"));
        assert!(debug.contains("true"));
    }

    #[test]
    fn estimated_cost_debug() {
        let cost = EstimatedCost {
            api_calls: Some(5),
            tokens: None,
            cost_cents: Some(100),
        };
        let debug = format!("{cost:?}");
        assert!(debug.contains("EstimatedCost"));
        assert!(debug.contains("100"));
    }

    #[test]
    fn preflight_rate_limit_debug() {
        let rl = PreflightRateLimit {
            limited: true,
            remaining: 0,
            reset_at: None,
        };
        let debug = format!("{rl:?}");
        assert!(debug.contains("PreflightRateLimit"));
    }

    #[test]
    fn self_check_response_debug() {
        let resp = SelfCheckResponse {
            connector_id: ConnectorId::new("test", "dbg", "v1").unwrap(),
            report: SelfCheckReport::ok(),
            checked_at: Utc::now(),
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("SelfCheckResponse"));
    }

    #[test]
    fn host_health_response_debug() {
        let resp = HostHealthResponse {
            status: HostHealthStatus::Healthy,
            connectors: HashMap::new(),
            uptime_seconds: 0,
            active_connections: 0,
            timestamp: Utc::now(),
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("HostHealthResponse"));
        assert!(debug.contains("Healthy"));
    }

    #[test]
    fn connector_archetype_debug() {
        let debug = format!("{:?}", ConnectorArchetype::Bidirectional);
        assert!(debug.contains("Bidirectional"));
    }

    #[test]
    fn latency_hint_debug() {
        for hint in [
            LatencyHint::Fast,
            LatencyHint::Medium,
            LatencyHint::Slow,
            LatencyHint::VerySlow,
        ] {
            let debug = format!("{hint:?}");
            assert!(!debug.is_empty());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DiscoveryEndpoint introspect success with operations
    // ─────────────────────────────────────────────────────────────────────────

    struct RegistryWithOps {
        connectors: Vec<ConnectorSummary>,
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for RegistryWithOps {
        async fn list(&self) -> Vec<ConnectorSummary> {
            self.connectors.clone()
        }

        async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.connectors.iter().find(|c| &c.id == id).cloned()
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            self.connectors.iter().find(|c| &c.id == id).map(|_| {
                let op = make_operation("test_op", Some("A test operation"));
                Introspection {
                    operations: vec![op],
                    events: vec![],
                    resource_types: vec![],
                    auth_caps: None,
                    event_caps: None,
                }
            })
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            Some(ConnectorArchetype::Streaming)
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            Some(RateLimitDeclarations {
                limits: vec![],
                tool_pool_map: {
                    let mut m = HashMap::new();
                    m.insert("test_op".into(), vec!["global_pool".into()]);
                    m
                },
            })
        }

        async fn self_check(&self, _id: &ConnectorId) -> Option<SelfCheckReport> {
            None
        }

        fn version(&self) -> u64 {
            42
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_with_operations_and_rate_limits() {
        let summary = make_summary(
            "rich",
            "test",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = RegistryWithOps {
            connectors: vec![summary.clone()],
        };
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let resp = endpoint.introspect(&summary.id).await.unwrap();
        assert_eq!(resp.archetype, ConnectorArchetype::Streaming);
        assert_eq!(resp.tools.len(), 1);
        assert_eq!(resp.tools[0].name, "test_op");
        assert_eq!(resp.tools[0].description, "A test operation");
        // Rate limits overridden by declarations
        assert_eq!(resp.tools[0].rate_limits, vec!["global_pool"]);
        assert!(resp.rate_limits.is_some());
        assert_eq!(resp.introspection.operations.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_with_custom_cache_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "ttl",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::with_cache_ttl(
            Arc::new(registry),
            Arc::new(AllowPolicy),
            Duration::from_millis(0),
        );

        let _ = endpoint.discover(None).await;
        let _ = endpoint.discover(None).await;
        // Zero TTL means every call refreshes
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_preflight_allow_policy() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let request = PreflightRequest {
            connector_id: ConnectorId::new("test", "pf", "v1").unwrap(),
            operation: "read".into(),
            params: None,
            principal: None,
            zone_id: None,
        };

        let response = endpoint.preflight(request).await;
        assert!(response.allowed);
        assert!(response.reason.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DiscoveryCache direct tests
    // ─────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn discovery_cache_invalidate_clears() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "inv",
            "test",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let cache = DiscoveryCache::new(Duration::from_secs(300));

        let _ = cache.get_or_refresh(&registry).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        cache.invalidate().await;

        let _ = cache.get_or_refresh(&registry).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_cache_returns_correct_data() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "data",
            "test",
            "v1",
            vec!["storage"],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let cache = DiscoveryCache::new(Duration::from_secs(60));

        let result = cache.get_or_refresh(&registry).await;
        assert_eq!(result.connectors.len(), 1);
        assert_eq!(result.connectors[0].id, summary.id);
        assert_eq!(result.connectors[0].max_safety_tier, SafetyTier::Risky);
        assert_eq!(result.registry_version, 1);
        assert!(!result.cache_hit);
    }

    #[fcp_async_core::runtime::test]
    async fn discovery_cache_empty_registry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let cache = DiscoveryCache::new(Duration::from_secs(60));

        let result = cache.get_or_refresh(&registry).await;
        assert!(result.connectors.is_empty());
        assert_eq!(result.registry_version, 1);
        assert!(!result.cache_hit);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SafetyTier reflexivity and transitivity
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn safety_tier_is_at_most_reflexive() {
        for tier in [
            SafetyTier::Safe,
            SafetyTier::Risky,
            SafetyTier::Dangerous,
            SafetyTier::Critical,
            SafetyTier::Forbidden,
        ] {
            assert!(tier.is_at_most(tier), "{tier:?} should be at most itself");
        }
    }

    #[test]
    fn safety_tier_level_consistent_with_is_at_most() {
        let tiers = [
            SafetyTier::Safe,
            SafetyTier::Risky,
            SafetyTier::Dangerous,
            SafetyTier::Critical,
            SafetyTier::Forbidden,
        ];
        for (i, a) in tiers.iter().enumerate() {
            for (j, b) in tiers.iter().enumerate() {
                assert_eq!(
                    a.is_at_most(*b),
                    i <= j,
                    "{a:?}.is_at_most({b:?}) should be {}",
                    i <= j,
                );
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorArchetype serde roundtrip (all variants)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_archetype_serde_roundtrip_all() {
        let archetypes = [
            ConnectorArchetype::Unknown,
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Webhook,
        ];
        for arch in archetypes {
            let json = serde_json::to_string(&arch).unwrap();
            let parsed: ConnectorArchetype = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, arch);
        }
    }

    #[test]
    fn connector_archetype_snake_case_names() {
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Unknown).unwrap(),
            "\"unknown\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::RequestResponse).unwrap(),
            "\"request_response\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorArchetype::Webhook).unwrap(),
            "\"webhook\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LatencyHint serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn latency_hint_serde_roundtrip_all() {
        let hints = [
            LatencyHint::Fast,
            LatencyHint::Medium,
            LatencyHint::Slow,
            LatencyHint::VerySlow,
        ];
        for hint in hints {
            let json = serde_json::to_string(&hint).unwrap();
            let parsed: LatencyHint = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, hint);
        }
    }

    #[test]
    fn latency_hint_snake_case() {
        assert_eq!(
            serde_json::to_string(&LatencyHint::VerySlow).unwrap(),
            "\"very_slow\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HostHealthStatus serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_health_status_serde_roundtrip_all() {
        let statuses = [
            HostHealthStatus::Healthy,
            HostHealthStatus::Degraded,
            HostHealthStatus::Unhealthy,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: HostHealthStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn host_health_status_lowercase_names() {
        assert_eq!(
            serde_json::to_string(&HostHealthStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&HostHealthStatus::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&HostHealthStatus::Unhealthy).unwrap(),
            "\"unhealthy\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HostHealthResponse edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_health_response_zero_uptime() {
        let resp = HostHealthResponse {
            status: HostHealthStatus::Healthy,
            connectors: HashMap::new(),
            uptime_seconds: 0,
            active_connections: 0,
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: HostHealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.uptime_seconds, 0);
        assert!(parsed.connectors.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DiscoveryResponse constructor
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn discovery_response_new_empty_connectors() {
        let resp = DiscoveryResponse::new(vec![], 1);
        assert!(resp.connectors.is_empty());
        assert_eq!(resp.registry_version, 1);
        assert_eq!(resp.supports_streaming, None);
        assert_eq!(resp.supports_batching, None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EstimatedCost edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn estimated_cost_all_fields_present() {
        let cost = EstimatedCost {
            api_calls: Some(10),
            tokens: Some(5000),
            cost_cents: Some(250),
        };
        let json = serde_json::to_string(&cost).unwrap();
        let parsed: EstimatedCost = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.api_calls, Some(10));
        assert_eq!(parsed.tokens, Some(5000));
        assert_eq!(parsed.cost_cents, Some(250));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PreflightRateLimit serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn preflight_rate_limit_limited_with_reset() {
        let rl = PreflightRateLimit {
            limited: true,
            remaining: 0,
            reset_at: Some(Utc::now()),
        };
        let json = serde_json::to_string(&rl).unwrap();
        let parsed: PreflightRateLimit = serde_json::from_str(&json).unwrap();
        assert!(parsed.limited);
        assert_eq!(parsed.remaining, 0);
        assert!(parsed.reset_at.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PreflightResponse factory methods
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn preflight_response_denied_has_reason() {
        let resp = PreflightResponse::denied("rate limited");
        assert!(!resp.allowed);
        assert_eq!(resp.reason.as_deref(), Some("rate limited"));
    }

    #[test]
    fn preflight_response_allowed_no_reason() {
        let resp = PreflightResponse::allowed();
        assert!(resp.allowed);
        assert!(resp.reason.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DiscoveryFilter combined category+risk+health
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn filter_all_dimensions_match() {
        let filter = DiscoveryFilter {
            category: Some("ai".into()),
            max_risk: Some(SafetyTier::Risky),
            health: Some(HealthFilter::Available),
        };
        let summary = make_summary(
            "test",
            "good",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(filter.matches(&summary));
    }

    #[test]
    fn filter_all_dimensions_category_mismatch() {
        let filter = DiscoveryFilter {
            category: Some("messaging".into()),
            max_risk: Some(SafetyTier::Dangerous),
            health: Some(HealthFilter::Available),
        };
        let summary = make_summary(
            "test",
            "cat",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(!filter.matches(&summary));
    }

    #[test]
    fn filter_all_dimensions_risk_exceeded() {
        let filter = DiscoveryFilter {
            category: Some("ai".into()),
            max_risk: Some(SafetyTier::Safe),
            health: Some(HealthFilter::Available),
        };
        let summary = make_summary(
            "test",
            "risky",
            "v1",
            vec!["ai"],
            SafetyTier::Dangerous,
            ConnectorHealth::healthy(),
        );
        assert!(!filter.matches(&summary));
    }

    #[test]
    fn filter_all_dimensions_health_mismatch() {
        let filter = DiscoveryFilter {
            category: Some("ai".into()),
            max_risk: Some(SafetyTier::Dangerous),
            health: Some(HealthFilter::Healthy),
        };
        let summary = make_summary(
            "test",
            "unhealthy",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::unavailable("down"),
        );
        assert!(!filter.matches(&summary));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorHealth convenience constructors
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_health_healthy_status() {
        let h = ConnectorHealth::healthy();
        assert!(h.is_healthy());
        assert!(h.is_available());
    }

    #[test]
    fn connector_health_degraded_has_reason() {
        let h = ConnectorHealth::degraded("slow response");
        assert!(!h.is_healthy());
        assert!(h.is_available());
        assert!(matches!(h, ConnectorHealth::Degraded { .. }));
    }

    #[test]
    fn connector_health_unavailable_has_reason() {
        let h = ConnectorHealth::unavailable("timeout");
        assert!(!h.is_healthy());
        assert!(!h.is_available());
        assert!(matches!(h, ConnectorHealth::Unavailable { .. }));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Introspect with missing introspection data
    // ─────────────────────────────────────────────────────────────────────────

    struct RegistryNoIntrospection {
        connectors: Vec<ConnectorSummary>,
    }

    #[async_trait::async_trait]
    impl ConnectorRegistry for RegistryNoIntrospection {
        async fn list(&self) -> Vec<ConnectorSummary> {
            self.connectors.clone()
        }

        async fn get(&self, id: &ConnectorId) -> Option<ConnectorSummary> {
            self.connectors.iter().find(|c| &c.id == id).cloned()
        }

        async fn get_introspection(&self, _id: &ConnectorId) -> Option<Introspection> {
            None
        }

        async fn get_archetype(&self, _id: &ConnectorId) -> Option<ConnectorArchetype> {
            None
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, _id: &ConnectorId) -> Option<SelfCheckReport> {
            None
        }

        fn version(&self) -> u64 {
            1
        }
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_missing_introspection_returns_error() {
        let summary = make_summary(
            "test",
            "nointro",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = RegistryNoIntrospection {
            connectors: vec![summary.clone()],
        };
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let result = endpoint.introspect(&summary.id).await;
        // Should return error when introspection is not available
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_missing_connector_returns_error() {
        let registry = RegistryNoIntrospection { connectors: vec![] };
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));
        let missing_id = ConnectorId::new("test", "missing", "v1").unwrap();
        let result = endpoint.introspect(&missing_id).await;
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DenyPolicy preflight
    // ─────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn discovery_endpoint_preflight_deny_policy() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(DenyPolicy));

        let request = PreflightRequest {
            connector_id: ConnectorId::new("test", "denied", "v1").unwrap(),
            operation: "write".into(),
            params: None,
            principal: None,
            zone_id: None,
        };

        let response = endpoint.preflight(request).await;
        assert!(!response.allowed);
        assert!(response.reason.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DiscoveryCache invalidate idempotent
    // ─────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn discovery_cache_invalidate_idempotent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "idem",
            "test",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        #[allow(clippy::duration_suboptimal_units)]
        let cache = DiscoveryCache::new(Duration::from_secs(300));

        let _ = cache.get_or_refresh(&registry).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Multiple invalidations are safe
        cache.invalidate().await;
        cache.invalidate().await;
        cache.invalidate().await;

        let _ = cache.get_or_refresh(&registry).await;
        // Only one refresh after multiple invalidations
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CacheMetadata + CacheValidator sync tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cache_metadata_eq() {
        let now = Utc::now();
        let a = CacheMetadata {
            etag: "\"abc\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: Some(15),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn cache_metadata_debug() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"test-etag\"".to_string(),
            last_modified: now,
            max_age_seconds: 60,
            stale_while_revalidate_seconds: None,
        };
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("CacheMetadata"));
        assert!(dbg.contains("test-etag"));
    }

    #[test]
    fn cache_metadata_no_stale_while_revalidate() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"e\"".to_string(),
            last_modified: now,
            max_age_seconds: 0,
            stale_while_revalidate_seconds: None,
        };
        assert!(meta.stale_while_revalidate_seconds.is_none());
    }

    #[test]
    fn cache_validator_default() {
        let v = CacheValidator::default();
        assert!(v.if_none_match.is_none());
        assert!(v.if_modified_since.is_none());
    }

    #[test]
    fn cache_validator_eq() {
        let a = CacheValidator {
            if_none_match: Some("\"xyz\"".to_string()),
            if_modified_since: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn cache_validator_debug() {
        let v = CacheValidator {
            if_none_match: Some("\"e1\"".to_string()),
            if_modified_since: None,
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("CacheValidator"));
    }

    #[test]
    fn cache_validator_matching_etag_is_not_modified() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"same\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let v = CacheValidator {
            if_none_match: Some("\"same\"".to_string()),
            if_modified_since: None,
        };
        assert!(v.is_not_modified(&meta));
    }

    #[test]
    fn cache_validator_mismatched_etag_is_modified() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"aaa\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let v = CacheValidator {
            if_none_match: Some("\"bbb\"".to_string()),
            if_modified_since: None,
        };
        assert!(!v.is_not_modified(&meta));
    }

    #[test]
    fn cache_validator_if_modified_since_future_is_not_modified() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"x\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let v = CacheValidator {
            if_none_match: None,
            if_modified_since: Some(now + chrono::Duration::seconds(60)),
        };
        assert!(v.is_not_modified(&meta));
    }

    #[test]
    fn cache_validator_if_modified_since_past_is_modified() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"x\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let v = CacheValidator {
            if_none_match: None,
            if_modified_since: Some(now - chrono::Duration::seconds(60)),
        };
        assert!(!v.is_not_modified(&meta));
    }

    #[test]
    fn cache_validator_empty_is_always_modified() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"any\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let v = CacheValidator::default();
        assert!(!v.is_not_modified(&meta));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ResponseMeta tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn response_meta_not_modified() {
        let meta = ResponseMeta::not_modified();
        assert_eq!(meta.status, 304);
        assert_eq!(meta.message.as_deref(), Some("Not Modified"));
    }

    #[test]
    fn response_meta_debug() {
        let meta = ResponseMeta {
            status: 200,
            message: Some("OK".into()),
        };
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("ResponseMeta"));
        assert!(dbg.contains("200"));
    }

    #[test]
    fn response_meta_eq() {
        let a = ResponseMeta {
            status: 200,
            message: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn response_meta_serialization_roundtrip() {
        let meta = ResponseMeta {
            status: 404,
            message: Some("Not Found".into()),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ResponseMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.message.as_deref(), Some("Not Found"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DiscoveryResponse additional tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn discovery_response_new_defaults() {
        let resp = DiscoveryResponse::new(vec![], 0);
        assert!(resp.connectors.is_empty());
        assert_eq!(resp.registry_version, 0);
        assert_eq!(resp.supports_streaming, None);
        assert_eq!(resp.supports_batching, None);
        assert!(resp.cache.is_none());
        assert!(resp.meta.is_none());
    }

    #[test]
    fn discovery_response_with_host_capabilities_preserves_known_values() {
        let resp =
            DiscoveryResponse::new(vec![], 5).with_host_capabilities(Some(true), Some(false));
        assert_eq!(resp.supports_streaming, Some(true));
        assert_eq!(resp.supports_batching, Some(false));
    }

    #[test]
    fn discovery_response_serialization_omits_unknown_host_capabilities() {
        let resp = DiscoveryResponse::new(vec![], 5);
        let json = serde_json::to_value(&resp).unwrap();
        let object = json.as_object().unwrap();
        assert!(!object.contains_key("supports_streaming"));
        assert!(!object.contains_key("supports_batching"));
    }

    #[test]
    fn discovery_response_not_modified_has_304_meta() {
        let connectors = vec![make_summary(
            "test",
            "cache",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        )];
        let now = Utc::now();
        let cache = CacheMetadata {
            etag: "\"etag\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let resp = DiscoveryResponse::not_modified(connectors, 5, cache);
        assert_eq!(resp.connectors.len(), 1);
        assert_eq!(resp.registry_version, 5);
        assert!(resp.cache.is_some());
        assert_eq!(resp.meta.as_ref().unwrap().status, 304);
    }

    #[test]
    fn discovery_response_debug() {
        let resp = DiscoveryResponse::new(vec![], 99);
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("DiscoveryResponse"));
    }

    #[test]
    fn discovery_query_result_debug() {
        let resp = DiscoveryResponse::new(vec![], 1);
        let result = DiscoveryQueryResult {
            response: resp,
            cache_hit: true,
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("DiscoveryQueryResult"));
        assert!(dbg.contains("true"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DiscoveryFilter serde edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn discovery_filter_default_serialization_omits_none() {
        let filter = DiscoveryFilter::default();
        let json = serde_json::to_string(&filter).unwrap();
        // skip_serializing_if means None fields are omitted
        assert!(!json.contains("category"));
        assert!(!json.contains("max_risk"));
        assert!(!json.contains("health"));
    }

    #[test]
    fn discovery_filter_clone() {
        let filter = DiscoveryFilter {
            category: Some("ai".into()),
            max_risk: Some(SafetyTier::Risky),
            health: Some(HealthFilter::Healthy),
        };
        let cloned = filter.clone();
        assert_eq!(filter.category, cloned.category);
        assert_eq!(filter.max_risk, cloned.max_risk);
        assert_eq!(filter.health, cloned.health);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorSummary edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_summary_empty_categories() {
        let summary = make_summary(
            "test",
            "empty",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        assert!(summary.categories.is_empty());
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: ConnectorSummary = serde_json::from_str(&json).unwrap();
        assert!(parsed.categories.is_empty());
    }

    #[test]
    fn connector_summary_debug() {
        let summary = make_summary(
            "test",
            "dbg",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("ConnectorSummary"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PreflightRequest + PreflightResponse edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn preflight_response_allowed_has_empty_capabilities() {
        let resp = PreflightResponse::allowed();
        assert!(resp.missing_capabilities.is_empty());
        assert!(resp.rate_limit.is_none());
        assert!(resp.estimated_cost.is_none());
        assert!(resp.budget_status.is_none());
    }

    #[test]
    fn preflight_response_denied_has_empty_capabilities() {
        let resp = PreflightResponse::denied("nope");
        assert!(resp.missing_capabilities.is_empty());
    }

    #[test]
    fn preflight_response_clone() {
        let resp = PreflightResponse::denied("cloned");
        let cloned = resp.clone();
        assert_eq!(resp.allowed, cloned.allowed);
        assert_eq!(resp.reason, cloned.reason);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IntrospectionResponse edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn introspection_response_not_modified_has_304() {
        let summary = make_summary(
            "test",
            "nm",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let operation = make_operation("nm_op", Some("not modified op"));
        let tools = vec![ToolDescriptor::from(&operation)];
        let introspection = Introspection {
            operations: vec![operation],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };
        let rate_limits = Some(RateLimitDeclarations {
            limits: vec![],
            tool_pool_map: HashMap::new(),
        });
        let now = Utc::now();
        let cache = CacheMetadata {
            etag: "\"e\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let resp = IntrospectionResponse::not_modified(
            summary,
            tools,
            rate_limits,
            ConnectorArchetype::RequestResponse,
            introspection,
            cache,
        );
        assert_eq!(resp.tools.len(), 1);
        assert_eq!(resp.meta.as_ref().unwrap().status, 304);
        assert!(resp.cache.is_some());
        assert_eq!(resp.archetype, ConnectorArchetype::RequestResponse);
        assert_eq!(resp.introspection.operations.len(), 1);
        assert!(resp.rate_limits.is_some());
    }

    #[test]
    fn introspection_response_debug() {
        let summary = make_summary(
            "test",
            "dbgi",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let resp = IntrospectionResponse {
            connector: summary,
            tools: vec![],
            rate_limits: None,
            archetype: ConnectorArchetype::Webhook,
            introspection: Introspection {
                operations: vec![],
                events: vec![],
                resource_types: vec![],
                auth_caps: None,
                event_caps: None,
            },
            cache: None,
            meta: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("IntrospectionResponse"));
        assert!(dbg.contains("Webhook"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SelfCheckResponse edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn self_check_response_clone() {
        let resp = SelfCheckResponse {
            connector_id: ConnectorId::new("test", "sc", "v1").unwrap(),
            report: SelfCheckReport::ok(),
            checked_at: Utc::now(),
        };
        let cloned = resp.clone();
        assert_eq!(resp.connector_id, cloned.connector_id);
        assert_eq!(resp.report.status, cloned.report.status);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HostHealthResponse edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_health_response_empty_connectors() {
        let resp = HostHealthResponse {
            status: HostHealthStatus::Healthy,
            connectors: HashMap::new(),
            uptime_seconds: 0,
            active_connections: 0,
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: HostHealthResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.connectors.is_empty());
        assert_eq!(parsed.uptime_seconds, 0);
    }

    #[test]
    fn host_health_status_clone() {
        let a = HostHealthStatus::Unhealthy;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn host_health_response_clone() {
        let resp = HostHealthResponse {
            status: HostHealthStatus::Degraded,
            connectors: HashMap::new(),
            uptime_seconds: 100,
            active_connections: 3,
            timestamp: Utc::now(),
        };
        let cloned = resp.clone();
        assert_eq!(
            std::mem::discriminant(&resp.status),
            std::mem::discriminant(&cloned.status)
        );
        assert_eq!(resp.uptime_seconds, cloned.uptime_seconds);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ToolDescriptor edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tool_descriptor_clone() {
        let tool = ToolDescriptor {
            name: "clone_test".to_string(),
            description: "desc".to_string(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            capability: CapabilityId::new("cap.clone").expect("capability"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            approval_mode: None,
            requires_confirmation: false,
            idempotent: true,
            supports_simulate: Some(false),
            latency_hint: None,
            rate_limits: vec![],
            examples: vec![],
            ai_hints: None,
        };
        let cloned = tool.clone();
        assert_eq!(tool.name, cloned.name);
        assert_eq!(tool.description, cloned.description);
        assert_eq!(tool.risk_level, cloned.risk_level);
    }

    #[test]
    fn tool_descriptor_debug() {
        let tool = ToolDescriptor {
            name: "debug_tool".to_string(),
            description: "for debug".to_string(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            capability: CapabilityId::new("cap.dbg").expect("capability"),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::None,
            approval_mode: Some(ApprovalMode::Interactive),
            requires_confirmation: true,
            idempotent: false,
            supports_simulate: Some(true),
            latency_hint: Some(LatencyHint::VerySlow),
            rate_limits: vec!["pool1".into()],
            examples: vec![],
            ai_hints: None,
        };
        let dbg = format!("{tool:?}");
        assert!(dbg.contains("ToolDescriptor"));
        assert!(dbg.contains("debug_tool"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ToolExample edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tool_example_clone() {
        let ex = ToolExample {
            description: Some("clone".into()),
            input: serde_json::json!({"x": 1}),
            output: Some(serde_json::json!({"y": 2})),
        };
        let cloned = ex.clone();
        assert_eq!(ex.description, cloned.description);
        assert_eq!(ex.input, cloned.input);
        assert_eq!(ex.output, cloned.output);
    }

    #[test]
    fn tool_example_debug() {
        let ex = ToolExample {
            description: None,
            input: serde_json::json!({}),
            output: None,
        };
        let dbg = format!("{ex:?}");
        assert!(dbg.contains("ToolExample"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EstimatedCost + PreflightRateLimit clone
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn estimated_cost_clone() {
        let cost = EstimatedCost {
            api_calls: Some(10),
            tokens: Some(500),
            cost_cents: Some(25),
        };
        let cloned = cost.clone();
        assert_eq!(cost.api_calls, cloned.api_calls);
        assert_eq!(cost.tokens, cloned.tokens);
        assert_eq!(cost.cost_cents, cloned.cost_cents);
    }

    #[test]
    fn preflight_rate_limit_clone() {
        let rl = PreflightRateLimit {
            limited: true,
            remaining: 5,
            reset_at: Some(Utc::now()),
        };
        let cloned = rl.clone();
        assert_eq!(rl.limited, cloned.limited);
        assert_eq!(rl.remaining, cloned.remaining);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorArchetype copy semantics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_archetype_copy() {
        let a = ConnectorArchetype::Polling;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LatencyHint copy semantics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn latency_hint_copy() {
        let a = LatencyHint::Slow;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HealthFilter copy semantics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_filter_copy() {
        let a = HealthFilter::Degraded;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn health_filter_debug() {
        let dbg = format!("{:?}", HealthFilter::All);
        assert!(dbg.contains("All"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CacheMetadata serialization
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cache_metadata_serialization_roundtrip() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"etag-abc\"".to_string(),
            last_modified: now,
            max_age_seconds: 120,
            stale_while_revalidate_seconds: Some(30),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: CacheMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.etag, "\"etag-abc\"");
        assert_eq!(parsed.max_age_seconds, 120);
        assert_eq!(parsed.stale_while_revalidate_seconds, Some(30));
    }

    #[test]
    fn cache_validator_serialization_roundtrip() {
        let v = CacheValidator {
            if_none_match: Some("\"etag-xyz\"".to_string()),
            if_modified_since: Some(Utc::now()),
        };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: CacheValidator = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.if_none_match.as_deref(), Some("\"etag-xyz\""));
        assert!(parsed.if_modified_since.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MeshStatus
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn mesh_status_connected_is_operational() {
        assert!(MeshStatus::Connected.is_operational());
    }

    #[test]
    fn mesh_status_degraded_is_operational() {
        assert!(MeshStatus::Degraded.is_operational());
    }

    #[test]
    fn mesh_status_unreachable_not_operational() {
        assert!(!MeshStatus::Unreachable.is_operational());
    }

    #[test]
    fn mesh_status_not_configured_not_operational() {
        assert!(!MeshStatus::NotConfigured.is_operational());
    }

    #[test]
    fn mesh_status_json_roundtrip() {
        for status in [
            MeshStatus::Connected,
            MeshStatus::Degraded,
            MeshStatus::Unreachable,
            MeshStatus::NotConfigured,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: MeshStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn mesh_status_snake_case_serialization() {
        assert_eq!(
            serde_json::to_string(&MeshStatus::Connected).unwrap(),
            "\"connected\""
        );
        assert_eq!(
            serde_json::to_string(&MeshStatus::NotConfigured).unwrap(),
            "\"not_configured\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PolicyEngineStatus
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn policy_engine_active_can_decide() {
        assert!(PolicyEngineStatus::Active.can_decide());
    }

    #[test]
    fn policy_engine_partially_loaded_can_decide() {
        assert!(PolicyEngineStatus::PartiallyLoaded.can_decide());
    }

    #[test]
    fn policy_engine_not_initialized_cannot_decide() {
        assert!(!PolicyEngineStatus::NotInitialized.can_decide());
    }

    #[test]
    fn policy_engine_error_cannot_decide() {
        assert!(!PolicyEngineStatus::Error.can_decide());
    }

    #[test]
    fn policy_engine_json_roundtrip() {
        for status in [
            PolicyEngineStatus::Active,
            PolicyEngineStatus::PartiallyLoaded,
            PolicyEngineStatus::NotInitialized,
            PolicyEngineStatus::Error,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: PolicyEngineStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ConnectorStateCounts
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_counts_default_is_zero() {
        let counts = ConnectorStateCounts::default();
        assert_eq!(counts.total(), 0);
        assert!(counts.all_healthy());
    }

    #[test]
    fn connector_state_counts_total() {
        let counts = ConnectorStateCounts {
            running: 3,
            starting: 1,
            stopped: 2,
            failed: 1,
            disabled: 4,
        };
        assert_eq!(counts.total(), 11);
    }

    #[test]
    fn connector_state_counts_all_running_is_healthy() {
        let counts = ConnectorStateCounts {
            running: 5,
            disabled: 2,
            ..Default::default()
        };
        assert!(counts.all_healthy());
    }

    #[test]
    fn connector_state_counts_with_failed_not_healthy() {
        let counts = ConnectorStateCounts {
            running: 5,
            failed: 1,
            ..Default::default()
        };
        assert!(!counts.all_healthy());
    }

    #[test]
    fn connector_state_counts_with_stopped_not_healthy() {
        let counts = ConnectorStateCounts {
            running: 5,
            stopped: 1,
            ..Default::default()
        };
        assert!(!counts.all_healthy());
    }

    #[test]
    fn connector_state_counts_json_roundtrip() {
        let counts = ConnectorStateCounts {
            running: 3,
            starting: 1,
            stopped: 0,
            failed: 2,
            disabled: 1,
        };
        let json = serde_json::to_string(&counts).unwrap();
        let parsed: ConnectorStateCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, counts);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HostDiagnostics aggregate_status
    // ─────────────────────────────────────────────────────────────────────────

    fn make_diagnostics(
        health_status: HostHealthStatus,
        mesh: MeshStatus,
        policy: PolicyEngineStatus,
        failed_connectors: u32,
    ) -> HostDiagnostics {
        HostDiagnostics {
            health: HostHealthResponse {
                status: health_status,
                connectors: HashMap::new(),
                uptime_seconds: 3600,
                active_connections: 0,
                timestamp: Utc::now(),
            },
            mesh_status: mesh,
            policy_engine: policy,
            connector_counts: ConnectorStateCounts {
                running: 5,
                failed: failed_connectors,
                ..Default::default()
            },
            pending_config_reload: false,
        }
    }

    #[test]
    fn diagnostics_all_healthy() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Connected,
            PolicyEngineStatus::Active,
            0,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Healthy);
    }

    #[test]
    fn diagnostics_unhealthy_host_stays_unhealthy() {
        let diag = make_diagnostics(
            HostHealthStatus::Unhealthy,
            MeshStatus::Connected,
            PolicyEngineStatus::Active,
            0,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Unhealthy);
    }

    #[test]
    fn diagnostics_policy_error_makes_unhealthy() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Connected,
            PolicyEngineStatus::Error,
            0,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Unhealthy);
    }

    #[test]
    fn diagnostics_policy_not_initialized_makes_unhealthy() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Connected,
            PolicyEngineStatus::NotInitialized,
            0,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Unhealthy);
    }

    #[test]
    fn diagnostics_mesh_unreachable_degrades() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Unreachable,
            PolicyEngineStatus::Active,
            0,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Degraded);
    }

    #[test]
    fn diagnostics_mesh_degraded_degrades() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Degraded,
            PolicyEngineStatus::Active,
            0,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Degraded);
    }

    #[test]
    fn diagnostics_failed_connectors_degrades() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Connected,
            PolicyEngineStatus::Active,
            2,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Degraded);
    }

    #[test]
    fn diagnostics_not_configured_mesh_healthy_if_all_else_ok() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::NotConfigured,
            PolicyEngineStatus::Active,
            0,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Healthy);
    }

    #[test]
    fn diagnostics_partially_loaded_policy_healthy() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Connected,
            PolicyEngineStatus::PartiallyLoaded,
            0,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Healthy);
    }

    #[test]
    fn diagnostics_json_roundtrip() {
        let diag = make_diagnostics(
            HostHealthStatus::Degraded,
            MeshStatus::Degraded,
            PolicyEngineStatus::Active,
            1,
        );
        let json = serde_json::to_string(&diag).unwrap();
        let parsed: HostDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mesh_status, MeshStatus::Degraded);
        assert_eq!(parsed.policy_engine, PolicyEngineStatus::Active);
        assert_eq!(parsed.connector_counts.failed, 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: HostPreflightRequest::budget_request tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_preflight_request_budget_request_copies_all_fields() {
        let req = HostPreflightRequest {
            request_id: RequestId::random(),
            connector_id: ConnectorId::new("test", "budget", "v1").unwrap(),
            operation: "write".into(),
            params: Some(serde_json::json!({"key": "value"})),
            principal: Some("user:bob".into()),
            zone_id: Some(ZoneId::work()),
            capability_token: None,
            approval_tokens: vec![],
        };
        let budget = req.budget_request();
        assert_eq!(budget.connector_id, req.connector_id);
        assert_eq!(budget.operation, "write");
        assert_eq!(budget.params, req.params);
        assert_eq!(budget.principal.as_deref(), Some("user:bob"));
        assert!(budget.zone_id.is_some());
    }

    #[test]
    fn host_preflight_request_budget_request_with_none_fields() {
        let req = HostPreflightRequest {
            request_id: RequestId::random(),
            connector_id: ConnectorId::new("test", "minimal", "v1").unwrap(),
            operation: "read".into(),
            params: None,
            principal: None,
            zone_id: None,
            capability_token: None,
            approval_tokens: vec![],
        };
        let budget = req.budget_request();
        assert!(budget.params.is_none());
        assert!(budget.principal.is_none());
        assert!(budget.zone_id.is_none());
    }

    #[test]
    fn host_preflight_request_serialization_roundtrip() {
        let req = HostPreflightRequest {
            request_id: RequestId::random(),
            connector_id: ConnectorId::new("test", "serde", "v1").unwrap(),
            operation: "delete".into(),
            params: Some(serde_json::json!({"id": 42})),
            principal: Some("agent:alpha".into()),
            zone_id: None,
            capability_token: None,
            approval_tokens: vec![],
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostPreflightRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation, "delete");
        assert_eq!(parsed.principal.as_deref(), Some("agent:alpha"));
    }

    #[test]
    fn host_preflight_request_debug() {
        let req = HostPreflightRequest {
            request_id: RequestId::random(),
            connector_id: ConnectorId::new("test", "dbg", "v1").unwrap(),
            operation: "invoke".into(),
            params: None,
            principal: None,
            zone_id: None,
            capability_token: None,
            approval_tokens: vec![],
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("HostPreflightRequest"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CacheMetadata::strong determinism
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cache_metadata_strong_produces_deterministic_etag() {
        let now = Utc::now();
        let payload = serde_json::json!({"foo": "bar"});
        let a = CacheMetadata::strong(&payload, now, 60, Some(30));
        let b = CacheMetadata::strong(&payload, now, 60, Some(30));
        assert_eq!(a.etag, b.etag);
        assert!(a.etag.starts_with('"'));
        assert!(a.etag.ends_with('"'));
    }

    #[test]
    fn cache_metadata_strong_different_payload_different_etag() {
        let now = Utc::now();
        let a = CacheMetadata::strong(&serde_json::json!({"a": 1}), now, 60, None);
        let b = CacheMetadata::strong(&serde_json::json!({"b": 2}), now, 60, None);
        assert_ne!(a.etag, b.etag);
    }

    #[test]
    fn cache_metadata_strong_stores_max_age_and_stale() {
        let now = Utc::now();
        let meta = CacheMetadata::strong(&"payload", now, 120, Some(45));
        assert_eq!(meta.max_age_seconds, 120);
        assert_eq!(meta.stale_while_revalidate_seconds, Some(45));
        assert_eq!(meta.last_modified, now);
    }

    #[test]
    fn cache_metadata_strong_no_stale() {
        let now = Utc::now();
        let meta = CacheMetadata::strong(&"payload", now, 30, None);
        assert!(meta.stale_while_revalidate_seconds.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CacheValidator boundary: equal timestamp
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cache_validator_if_modified_since_equal_is_not_modified() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"x\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let v = CacheValidator {
            if_none_match: None,
            if_modified_since: Some(now),
        };
        // Equal timestamp means cache.last_modified <= timestamp, so not modified
        assert!(v.is_not_modified(&meta));
    }

    #[test]
    fn cache_validator_etag_takes_priority_over_if_modified_since() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"match\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        // etag matches, even if if_modified_since is in the past
        let v = CacheValidator {
            if_none_match: Some("\"match\"".to_string()),
            if_modified_since: Some(now - chrono::Duration::seconds(3600)),
        };
        assert!(v.is_not_modified(&meta));
    }

    #[test]
    fn cache_validator_etag_mismatch_ignores_if_modified_since() {
        let now = Utc::now();
        let meta = CacheMetadata {
            etag: "\"a\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        // etag mismatch returns early as modified, even if timestamp says not modified
        let v = CacheValidator {
            if_none_match: Some("\"b\"".to_string()),
            if_modified_since: Some(now + chrono::Duration::seconds(3600)),
        };
        assert!(!v.is_not_modified(&meta));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: DiscoveryEndpoint::connector() tests
    // ─────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn connector_endpoint_returns_summary() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "conn",
            "test",
            "v1",
            vec!["messaging"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let resp = endpoint.connector(&summary.id).await.unwrap();
        assert_eq!(resp.connector.id, summary.id);
        assert_eq!(resp.registry_version, 1);
        assert!(resp.cache.is_some());
        assert!(resp.meta.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn connector_endpoint_missing_returns_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));
        let missing = ConnectorId::new("missing", "conn", "v1").unwrap();

        let err = endpoint.connector(&missing).await.unwrap_err();
        assert!(matches!(err, HostError::ConnectorNotFound(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn connector_with_cache_returns_not_modified_for_matching_etag() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "conn-cache",
            "test",
            "v1",
            vec!["storage"],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let first = endpoint.connector(&summary.id).await.unwrap();
        let etag = first.cache.as_ref().unwrap().etag.clone();

        let second = endpoint
            .connector_with_cache(
                &summary.id,
                Some(CacheValidator {
                    if_none_match: Some(etag),
                    if_modified_since: None,
                }),
            )
            .await
            .unwrap();

        assert_eq!(second.meta.as_ref().map(|m| m.status), Some(304));
    }

    #[fcp_async_core::runtime::test]
    async fn connector_with_cache_returns_fresh_for_stale_etag() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "conn-stale",
            "test",
            "v1",
            vec!["ai"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let resp = endpoint
            .connector_with_cache(
                &summary.id,
                Some(CacheValidator {
                    if_none_match: Some("\"old-etag\"".to_string()),
                    if_modified_since: None,
                }),
            )
            .await
            .unwrap();

        assert!(resp.meta.is_none()); // Fresh response, no 304
        assert!(resp.cache.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn connector_with_cache_missing_connector_returns_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = CountingRegistry::new(vec![], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));
        let missing = ConnectorId::new("gone", "conn", "v1").unwrap();

        let err = endpoint
            .connector_with_cache(
                &missing,
                Some(CacheValidator {
                    if_none_match: Some("\"any\"".to_string()),
                    if_modified_since: None,
                }),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, HostError::ConnectorNotFound(_)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ConnectorInventoryResponse tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_inventory_response_not_modified_has_304() {
        let summary = make_summary(
            "inv",
            "nm",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let now = Utc::now();
        let cache = CacheMetadata {
            etag: "\"e\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let resp = ConnectorInventoryResponse::not_modified(summary, 7, cache);
        assert_eq!(resp.registry_version, 7);
        assert!(resp.cache.is_some());
        assert_eq!(resp.meta.as_ref().unwrap().status, 304);
        assert_eq!(
            resp.meta.as_ref().unwrap().message.as_deref(),
            Some("Not Modified")
        );
    }

    #[test]
    fn connector_inventory_response_serialization_roundtrip() {
        let summary = make_summary(
            "inv",
            "serde",
            "v1",
            vec!["storage"],
            SafetyTier::Risky,
            ConnectorHealth::degraded("slow"),
        );
        let resp = ConnectorInventoryResponse {
            connector: summary,
            registry_version: 42,
            cache: None,
            meta: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ConnectorInventoryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.registry_version, 42);
        assert!(parsed.cache.is_none());
        assert!(parsed.meta.is_none());
    }

    #[test]
    fn connector_inventory_response_debug() {
        let summary = make_summary(
            "inv",
            "dbg",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let resp = ConnectorInventoryResponse {
            connector: summary,
            registry_version: 1,
            cache: None,
            meta: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("ConnectorInventoryResponse"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ToolDescriptor::from edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tool_descriptor_from_operation_rate_limit_no_pool_no_scope() {
        use fcp_prelude::RateLimit;
        let mut op = make_operation("op_empty_rl", None);
        op.rate_limit = Some(RateLimit {
            max: 50,
            per_ms: 5000,
            burst: Some(10),
            scope: None,
            pool_name: None,
        });
        let tool = ToolDescriptor::from(&op);
        // Neither pool_name nor scope => empty rate_limits
        assert!(tool.rate_limits.is_empty());
    }

    #[test]
    fn tool_descriptor_from_operation_multiple_examples() {
        let mut op = make_operation("multi_ex", None);
        op.ai_hints.examples = vec![
            r#"{"a":1}"#.into(),
            r#"{"b":2}"#.into(),
            r#"{"c":3}"#.into(),
        ];
        let tool = ToolDescriptor::from(&op);
        assert_eq!(tool.examples.len(), 3);
        assert_eq!(tool.examples[0].input, serde_json::json!({"a": 1}));
        assert_eq!(tool.examples[1].input, serde_json::json!({"b": 2}));
        assert_eq!(tool.examples[2].input, serde_json::json!({"c": 3}));
    }

    #[test]
    fn tool_descriptor_from_operation_ai_hints_only_when_to_use() {
        let mut op = make_operation("hints_partial", None);
        op.ai_hints = AgentHint {
            when_to_use: "Use when X".to_string(),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![],
        };
        let tool = ToolDescriptor::from(&op);
        // Has when_to_use so ai_hints should be Some
        assert!(tool.ai_hints.is_some());
        assert_eq!(tool.ai_hints.as_ref().unwrap().when_to_use, "Use when X");
    }

    #[test]
    fn tool_descriptor_from_operation_ai_hints_only_common_mistakes() {
        let mut op = make_operation("hints_mistakes", None);
        op.ai_hints = AgentHint {
            when_to_use: String::new(),
            common_mistakes: vec!["mistake".into()],
            examples: vec![],
            related: vec![],
        };
        let tool = ToolDescriptor::from(&op);
        assert!(tool.ai_hints.is_some());
    }

    #[test]
    fn tool_descriptor_from_operation_ai_hints_only_related() {
        let mut op = make_operation("hints_related", None);
        op.ai_hints = AgentHint {
            when_to_use: String::new(),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![CapabilityId::new("cap.other").unwrap()],
        };
        let tool = ToolDescriptor::from(&op);
        assert!(tool.ai_hints.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ConnectorStateCounts edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_state_counts_with_starting_not_healthy() {
        let counts = ConnectorStateCounts {
            running: 5,
            starting: 1,
            ..Default::default()
        };
        assert!(!counts.all_healthy());
    }

    #[test]
    fn connector_state_counts_only_disabled_is_healthy() {
        let counts = ConnectorStateCounts {
            disabled: 10,
            ..Default::default()
        };
        assert!(counts.all_healthy());
        assert_eq!(counts.total(), 10);
    }

    #[test]
    fn connector_state_counts_eq() {
        let a = ConnectorStateCounts {
            running: 1,
            starting: 2,
            stopped: 3,
            failed: 4,
            disabled: 5,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn connector_state_counts_debug() {
        let counts = ConnectorStateCounts {
            running: 3,
            ..Default::default()
        };
        let dbg = format!("{counts:?}");
        assert!(dbg.contains("ConnectorStateCounts"));
        assert!(dbg.contains('3'));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: HostDiagnostics aggregate_status priority tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn diagnostics_unhealthy_overrides_policy_error() {
        // Even if policy is Error, Unhealthy host status takes precedence
        let diag = make_diagnostics(
            HostHealthStatus::Unhealthy,
            MeshStatus::Connected,
            PolicyEngineStatus::Error,
            0,
        );
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Unhealthy);
    }

    #[test]
    fn diagnostics_degraded_host_with_failed_connectors_stays_degraded() {
        let diag = make_diagnostics(
            HostHealthStatus::Degraded,
            MeshStatus::Connected,
            PolicyEngineStatus::Active,
            3,
        );
        // health.status is Degraded, policy can decide, mesh connected,
        // failed > 0 => Degraded
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Degraded);
    }

    #[test]
    fn diagnostics_mesh_unreachable_with_failed_connectors() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Unreachable,
            PolicyEngineStatus::Active,
            5,
        );
        // Mesh unreachable checked before failed connectors
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Degraded);
    }

    #[test]
    fn diagnostics_pending_config_reload_does_not_affect_status() {
        let mut diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Connected,
            PolicyEngineStatus::Active,
            0,
        );
        diag.pending_config_reload = true;
        assert_eq!(diag.aggregate_status(), HostHealthStatus::Healthy);
    }

    #[test]
    fn diagnostics_debug() {
        let diag = make_diagnostics(
            HostHealthStatus::Healthy,
            MeshStatus::Connected,
            PolicyEngineStatus::Active,
            0,
        );
        let dbg = format!("{diag:?}");
        assert!(dbg.contains("HostDiagnostics"));
    }

    #[test]
    fn diagnostics_clone() {
        let diag = make_diagnostics(
            HostHealthStatus::Degraded,
            MeshStatus::Degraded,
            PolicyEngineStatus::PartiallyLoaded,
            1,
        );
        let cloned = diag.clone();
        assert_eq!(diag.aggregate_status(), cloned.aggregate_status());
        assert_eq!(diag.mesh_status, cloned.mesh_status);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: DiscoveryFilter serialization edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn discovery_filter_partial_fields_serialization() {
        let filter = DiscoveryFilter {
            category: None,
            max_risk: Some(SafetyTier::Dangerous),
            health: None,
        };
        let json = serde_json::to_string(&filter).unwrap();
        assert!(!json.contains("category"));
        assert!(json.contains("max_risk"));
        assert!(!json.contains("health"));
        let parsed: DiscoveryFilter = serde_json::from_str(&json).unwrap();
        assert!(parsed.category.is_none());
        assert_eq!(parsed.max_risk, Some(SafetyTier::Dangerous));
    }

    #[test]
    fn discovery_filter_only_health_field() {
        let filter = DiscoveryFilter {
            category: None,
            max_risk: None,
            health: Some(HealthFilter::Degraded),
        };
        let json = serde_json::to_string(&filter).unwrap();
        assert!(!json.contains("category"));
        assert!(!json.contains("max_risk"));
        assert!(json.contains("health"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: MeshStatus and PolicyEngineStatus extra coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn mesh_status_debug() {
        for status in [
            MeshStatus::Connected,
            MeshStatus::Degraded,
            MeshStatus::Unreachable,
            MeshStatus::NotConfigured,
        ] {
            let dbg = format!("{status:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn mesh_status_copy() {
        let a = MeshStatus::Connected;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn policy_engine_status_debug() {
        for status in [
            PolicyEngineStatus::Active,
            PolicyEngineStatus::PartiallyLoaded,
            PolicyEngineStatus::NotInitialized,
            PolicyEngineStatus::Error,
        ] {
            let dbg = format!("{status:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn policy_engine_status_copy() {
        let a = PolicyEngineStatus::Active;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn policy_engine_status_snake_case_serialization() {
        assert_eq!(
            serde_json::to_string(&PolicyEngineStatus::PartiallyLoaded).unwrap(),
            "\"partially_loaded\""
        );
        assert_eq!(
            serde_json::to_string(&PolicyEngineStatus::NotInitialized).unwrap(),
            "\"not_initialized\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ResponseMeta edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn response_meta_no_message() {
        let meta = ResponseMeta {
            status: 200,
            message: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("message"));
        let parsed: ResponseMeta = serde_json::from_str(&json).unwrap();
        assert!(parsed.message.is_none());
    }

    #[test]
    fn response_meta_clone_preserves_fields() {
        let meta = ResponseMeta {
            status: 500,
            message: Some("Internal Error".into()),
        };
        let cloned = meta.clone();
        assert_eq!(meta.status, cloned.status);
        assert_eq!(meta.message, cloned.message);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: DiscoveryResponse builder chain
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn discovery_response_with_cache_metadata_chain() {
        let now = Utc::now();
        let cache = CacheMetadata {
            etag: "\"chain\"".to_string(),
            last_modified: now,
            max_age_seconds: 60,
            stale_while_revalidate_seconds: Some(10),
        };
        let resp = DiscoveryResponse::new(vec![], 5).with_cache_metadata(cache);
        assert!(resp.cache.is_some());
        assert_eq!(resp.cache.as_ref().unwrap().etag, "\"chain\"");
        assert!(resp.meta.is_none());
    }

    #[test]
    fn discovery_response_with_response_meta_chain() {
        let meta = ResponseMeta {
            status: 200,
            message: Some("OK".into()),
        };
        let resp = DiscoveryResponse::new(vec![], 1).with_response_meta(meta);
        assert!(resp.meta.is_some());
        assert_eq!(resp.meta.as_ref().unwrap().status, 200);
    }

    #[test]
    fn discovery_response_chained_cache_and_meta() {
        let now = Utc::now();
        let cache = CacheMetadata {
            etag: "\"both\"".to_string(),
            last_modified: now,
            max_age_seconds: 30,
            stale_while_revalidate_seconds: None,
        };
        let meta = ResponseMeta {
            status: 304,
            message: Some("Not Modified".into()),
        };
        let resp = DiscoveryResponse::new(vec![], 1)
            .with_cache_metadata(cache)
            .with_response_meta(meta);
        assert!(resp.cache.is_some());
        assert!(resp.meta.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: IntrospectionResponse::not_modified preserves archetype
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn introspection_response_not_modified_preserves_all_archetypes() {
        let summary = make_summary(
            "test",
            "arch",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let operation = make_operation("arch_op", Some("arch op"));
        let tools = vec![ToolDescriptor::from(&operation)];
        let introspection = Introspection {
            operations: vec![operation],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };
        let rate_limits = Some(RateLimitDeclarations {
            limits: vec![],
            tool_pool_map: HashMap::new(),
        });
        let now = Utc::now();
        for archetype in [
            ConnectorArchetype::Unknown,
            ConnectorArchetype::RequestResponse,
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Webhook,
        ] {
            let cache = CacheMetadata {
                etag: "\"e\"".to_string(),
                last_modified: now,
                max_age_seconds: 30,
                stale_while_revalidate_seconds: None,
            };
            let resp = IntrospectionResponse::not_modified(
                summary.clone(),
                tools.clone(),
                rate_limits.clone(),
                archetype,
                introspection.clone(),
                cache,
            );
            assert_eq!(resp.archetype, archetype);
            assert_eq!(resp.tools.len(), 1);
            assert_eq!(resp.introspection.operations.len(), 1);
            assert!(resp.rate_limits.is_some());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: DiscoveryEndpoint::introspect_with_cache if_modified_since
    // ─────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn introspect_with_cache_returns_not_modified_for_future_timestamp() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "introspect-ts",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        // Populate cache
        let first = endpoint.introspect(&summary.id).await.unwrap();

        let far_future = Utc::now() + chrono::Duration::seconds(86400);
        let resp = endpoint
            .introspect_with_cache(
                &summary.id,
                Some(CacheValidator {
                    if_none_match: None,
                    if_modified_since: Some(far_future),
                }),
            )
            .await
            .unwrap();

        assert_eq!(resp.meta.as_ref().map(|m| m.status), Some(304));
        assert_eq!(resp.tools.len(), first.tools.len());
        assert_eq!(
            resp.introspection.operations.len(),
            first.introspection.operations.len()
        );
        assert_eq!(resp.rate_limits.is_some(), first.rate_limits.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn introspect_with_cache_returns_fresh_for_past_timestamp() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "introspect-past",
            "test",
            "v1",
            vec!["test"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary.clone()], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        let far_past = Utc::now() - chrono::Duration::seconds(86400);
        let resp = endpoint
            .introspect_with_cache(
                &summary.id,
                Some(CacheValidator {
                    if_none_match: None,
                    if_modified_since: Some(far_past),
                }),
            )
            .await
            .unwrap();

        assert!(resp.meta.is_none()); // Fresh, no 304
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: DiscoveryQuery with filter + validator combined
    // ─────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn discover_query_with_filter_and_validator_not_modified() {
        let calls = Arc::new(AtomicUsize::new(0));
        let s1 = make_summary(
            "a",
            "msg",
            "v1",
            vec!["messaging"],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let s2 = make_summary(
            "b",
            "stor",
            "v1",
            vec!["storage"],
            SafetyTier::Risky,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![s1, s2], Arc::clone(&calls));
        let endpoint = DiscoveryEndpoint::new(Arc::new(registry), Arc::new(AllowPolicy));

        // Get etag for filtered (messaging only) result
        let filter = DiscoveryFilter {
            category: Some("messaging".to_string()),
            ..Default::default()
        };
        let first = endpoint.discover_query(Some(filter.clone()), None).await;
        assert_eq!(first.response.connectors.len(), 1);
        let etag = first.response.cache.as_ref().unwrap().etag.clone();

        // Same filter + matching etag => 304
        let second = endpoint
            .discover_query(
                Some(filter),
                Some(CacheValidator {
                    if_none_match: Some(etag),
                    if_modified_since: None,
                }),
            )
            .await;
        assert_eq!(second.response.meta.as_ref().map(|m| m.status), Some(304));
        assert_eq!(second.response.connectors.len(), 1);
        assert_eq!(
            second.response.connectors[0].id,
            first.response.connectors[0].id
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: DiscoveryCache with very large TTL
    // ─────────────────────────────────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn discovery_cache_large_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let summary = make_summary(
            "large-ttl",
            "test",
            "v1",
            vec![],
            SafetyTier::Safe,
            ConnectorHealth::healthy(),
        );
        let registry = CountingRegistry::new(vec![summary], Arc::clone(&calls));
        let cache = DiscoveryCache::new(Duration::from_secs(u64::from(u32::MAX)));

        let first = cache.get_or_refresh(&registry).await;
        let second = cache.get_or_refresh(&registry).await;
        assert!(!first.cache_hit);
        assert!(second.cache_hit);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: HostPreflightRequest with approval tokens
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_preflight_request_clone() {
        let req = HostPreflightRequest {
            request_id: RequestId::random(),
            connector_id: ConnectorId::new("test", "clone", "v1").unwrap(),
            operation: "op".into(),
            params: None,
            principal: None,
            zone_id: None,
            capability_token: None,
            approval_tokens: vec![],
        };
        let cloned = req.clone();
        assert_eq!(req.connector_id, cloned.connector_id);
        assert_eq!(req.operation, cloned.operation);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: HealthFilter serialization names
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn health_filter_lowercase_names() {
        assert_eq!(
            serde_json::to_string(&HealthFilter::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&HealthFilter::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&HealthFilter::Available).unwrap(),
            "\"available\""
        );
        assert_eq!(
            serde_json::to_string(&HealthFilter::All).unwrap(),
            "\"all\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: SelfCheckResponse serde
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn self_check_response_fields_preserved() {
        let now = Utc::now();
        let resp = SelfCheckResponse {
            connector_id: ConnectorId::new("test", "fields", "v1").unwrap(),
            report: SelfCheckReport::ok(),
            checked_at: now,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: SelfCheckResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.checked_at, now);
        assert_eq!(parsed.report.status, SelfCheckStatus::Ok);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: DiscoveryCache::cache_metadata TTL mapping
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn discovery_cache_metadata_ttl_seconds_from_duration() {
        let cache = DiscoveryCache::new(Duration::from_mins(2));
        let now = Utc::now();
        let meta = cache.cache_metadata(&"test-payload", now);
        assert_eq!(meta.max_age_seconds, 120);
        assert_eq!(meta.stale_while_revalidate_seconds, Some(120));
        assert_eq!(meta.last_modified, now);
    }

    #[test]
    fn discovery_cache_metadata_zero_ttl() {
        let cache = DiscoveryCache::new(Duration::from_millis(0));
        let now = Utc::now();
        let meta = cache.cache_metadata(&"payload", now);
        assert_eq!(meta.max_age_seconds, 0);
        assert_eq!(meta.stale_while_revalidate_seconds, Some(0));
    }
}
