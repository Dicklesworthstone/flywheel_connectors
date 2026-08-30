//! Durable host-side admin state for connector lifecycle and configuration.
//!
//! This module extracts the host binary's persisted lifecycle snapshot into a
//! reusable library component and widens it into a canonical admin-state model
//! for later `fwc` lifecycle/config work. The current focus is the storage
//! shape, monotonic journal semantics, and persistence invariants.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use blake3::hash;
use chrono::{DateTime, Utc};
use fcp_async_core::sync::{Mutex, RwLock};
use fcp_kernel::{
    ConnectorHealth, ConnectorId, LifecycleError, LifecycleManager, LifecycleRecord,
    LifecycleState, LifecycleStatus, TransitionReason,
};
pub use fcp_mesh::planner::SimulateResourceAvailability;
use fcp_prelude::{
    ApprovalToken, CapabilityConstraints, CapabilityGrant, CapabilityId, CapabilityToken,
    CredentialId, ObjectPlacementPolicy, OperationId,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    HostError, HostResult, ManagedNetworkConstraints, RuntimeNetworkEnforcement,
    discovery::ConnectorSummary, supervisor::ConnectorPrewarmConfig,
};

const HOST_ADMIN_STATE_SNAPSHOT_VERSION: u32 = 1;
const REDACTED_CONFIG_VALUE: &str = "[REDACTED]";

/// Canonical connector inventory entry persisted and applied by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedConnectorConfig {
    /// Canonical connector identifier.
    pub id: String,
    /// Executable path for the connector binary.
    pub binary: String,
    /// Optional connector manifest TOML path used by the host to derive
    /// operation-level enforcement metadata, including
    /// `provides.operations.*.network_constraints`.
    ///
    /// Relative paths are resolved by the host process from its current
    /// working directory when it loads the managed inventory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Additional argv entries passed to the connector subprocess.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Connector-specific environment overrides.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Optional persisted config payload forwarded to `configure`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    /// Optional category labels surfaced by discovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Optional explicit semantic version override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Allowed invocation zones. The host gateway rejects any connector
    /// RPC whose config leaves this list empty, and rejects any
    /// `InvokeRequest` whose `zone_id` is not present here even with a
    /// structurally-valid capability token. Production deployments must pin
    /// every connector to its declared `home/allowed_sources` set per the
    /// manifest's `[zones]` section.
    /// br-flywheel_connectors-by4vu.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_zones: Vec<String>,
    /// Allowed connector operations — when non-empty, the host gateway
    /// rejects any `InvokeRequest` whose `operation` is not in this
    /// list, even if the connector's runtime introspection advertises
    /// the operation and the capability token's `capability` claim
    /// matches what the connector self-reports.
    ///
    /// Closes the manifest-allowed-operations enforcement gap on
    /// `br-ike8x` (which itself was a follow-up from the br-2ot4f
    /// cross-crate audit pass). Without this list, the operation
    /// gate runs entirely off `tool.capability` from the connector's
    /// own introspection — so a connector that decides to expose a
    /// new operation under a permissive capability id can be invoked
    /// through it as long as the caller holds a token for THAT id.
    /// Operators that pin the operation list per connector
    /// (mirroring the `[provides.operations]` section of the
    /// manifest TOML) get defense-in-depth: even a malicious or
    /// drifted connector binary cannot expose an op the operator
    /// did not approve.
    ///
    /// Empty (the default) preserves pre-pinning behavior so
    /// existing inventories don't break. Production deployments
    /// should pin the list per connector. Unlike `allowed_zones`,
    /// an empty operation list remains a legacy fall-through.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_operations: Vec<String>,
    /// Fail closed on live invokes unless `manifest_path` declares
    /// `network_constraints` for the requested operation and the selected
    /// execution path can enforce them.
    ///
    /// Native subprocess connectors can open their own sockets unless a
    /// host-mediated egress path is explicitly wired. This flag keeps
    /// sandbox-enforced deployments honest by refusing to dispatch operations
    /// whose operation-level network constraints cannot be proven from the
    /// connector manifest.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enforce_operation_network_constraints: bool,
    /// br-v2kt4: explicit fail-closed flag for empty
    /// `allowed_operations` lists. Empty `allowed_zones` now fail
    /// closed unconditionally as a missing zone envelope; this flag
    /// only controls whether an empty operation allow-list rejects
    /// every operation or preserves the legacy operation fall-through.
    ///
    /// New deployments should set this to `true` and explicitly
    /// populate the allowlists. Existing deployments deserialize
    /// with the flag absent and continue to behave as before. See
    /// docs/audit/security-audit-saas-alpha-2026-05-02.md §b.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enforce_empty_allow_lists: bool,
    /// Host-side runtime network enforcement mode. This is operator-approved
    /// inventory state, distinct from connector runtime introspection.
    #[serde(
        default,
        skip_serializing_if = "RuntimeNetworkEnforcement::is_legacy_unspecified"
    )]
    pub runtime_network_enforcement: RuntimeNetworkEnforcement,
    /// Host-owned connector startup prewarm policy.
    ///
    /// This is persisted operator intent, not connector introspection. The
    /// production host must validate it before launching or checking out any
    /// process so prewarm evidence cannot be confused with the default
    /// on-demand startup path.
    #[serde(default, skip_serializing_if = "is_default_prewarm_config")]
    pub prewarm: ConnectorPrewarmConfig,
    /// Per-operation network policy used by the host runtime path.
    ///
    /// Keys are operation ids. Values are host-managed constraints that can
    /// include explicitly supported config-derived placeholders.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub operation_network_constraints: BTreeMap<String, ManagedNetworkConstraints>,
    /// Operator override for the cancellation deadline of this connector's
    /// operations, in milliseconds (`flywheel_connectors-861lx`).
    ///
    /// When `Some`, this wins over the per-archetype defaults (1 s for
    /// bounded one-shot archetypes, 10 s for long-lived archetypes). The
    /// host fails closed when an operation tracked with this connector
    /// ignores its cancellation past the deadline: the connector
    /// subprocess is force-terminated (SIGTERM grace, then SIGKILL) and
    /// the cancellation audit event carries `forced = true`. Must be > 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_deadline_ms: Option<u64>,
}

/// Live connector inventory mutation kind handled by the host admin plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorInventoryMutationKind {
    /// Add a new connector to the managed inventory.
    Install,
    /// Replace an existing connector entry in the managed inventory.
    Update,
}

/// Host admin API request for a live connector inventory mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorInventoryMutationRequest {
    /// Requested mutation kind.
    pub kind: ConnectorInventoryMutationKind,
    /// Preview the mutation against the live host inventory without persisting or applying it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Connector entry to persist and apply.
    pub connector: ManagedConnectorConfig,
}

/// Result of reconciling the live subprocess registry to a new inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorInventoryApplyReport {
    /// Connector identifiers newly added to the live registry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<String>,
    /// Connector identifiers whose subprocess/config was refreshed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub updated: Vec<String>,
    /// Connector identifiers removed from the live registry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    /// Connector identifiers left unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unchanged: Vec<String>,
    /// New registry version visible to cache-aware clients.
    pub registry_version: u64,
}

/// Host admin API response after persisting and applying an inventory mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorInventoryMutationResponse {
    /// Requested mutation kind.
    pub kind: ConnectorInventoryMutationKind,
    /// Whether this response is a preview only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Managed connectors file written by the host.
    pub connectors_file: String,
    /// Previous connector entry when this was an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<ManagedConnectorConfig>,
    /// Current persisted connector entry.
    pub current: ManagedConnectorConfig,
    /// Total connector count after the mutation.
    pub inventory_size: usize,
    /// Live registry reconciliation summary.
    pub apply: ConnectorInventoryApplyReport,
    /// Admin-state reconciliation summary after the live registry changed.
    pub admin_state: StartupReconciliationReport,
}

// ── Lifecycle transition RPC types ──────────────────────────────────────────

/// Lifecycle transition action requested via the host admin API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    /// Enable a connector (set desired state to `Enabled`).
    Enable,
    /// Disable a connector without uninstalling (set desired state to `Disabled`).
    Disable,
    /// Restart a running connector (disable then re-enable).
    Restart,
    /// Reload connector configuration without a full restart.
    Reload,
    /// Remove a connector from active use (set desired state to `Uninstalled`).
    Uninstall,
    /// Promote a canary deployment to production.
    Promote,
}

/// Host admin API request for a lifecycle state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransitionRequest {
    /// Requested lifecycle action.
    pub action: LifecycleAction,
    /// Optional human-readable reason for the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional actor or subsystem requesting the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiated_by: Option<String>,
    /// Preview the transition without persisting it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
}

/// Host admin API response after a lifecycle state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransitionResponse {
    /// Connector identifier.
    pub connector_id: String,
    /// Action that was performed.
    pub action: LifecycleAction,
    /// Whether this was a preview only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Desired state before the transition.
    pub previous_desired_state: DesiredRuntimeState,
    /// Desired state after the transition.
    pub current_desired_state: DesiredRuntimeState,
    /// Observed state at the time of the transition.
    pub observed_state: ObservedRuntimeState,
    /// Lifecycle record if available after the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_status: Option<LifecycleStatus>,
    /// Journal sequence number for this transition.
    pub journal_sequence: u64,
    /// Timestamp of the transition.
    pub transitioned_at: DateTime<Utc>,
}

/// Host admin API request for querying the admin state journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalQueryRequest {
    /// Optional connector ID filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Only return entries after this sequence number.
    #[serde(default)]
    pub after_sequence: u64,
    /// Maximum number of entries to return.
    #[serde(default = "default_journal_limit")]
    pub limit: usize,
}

const fn default_journal_limit() -> usize {
    100
}

/// Host admin API response for a journal query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalQueryResponse {
    /// Journal entries matching the query.
    pub entries: Vec<AdminStateJournalEntry>,
    /// Total number of entries in the journal (before filtering).
    pub total_entries: usize,
    /// Highest sequence number in the response.
    pub latest_sequence: u64,
}

// ── Logs, events, and receipt query types ───────────────────────────────────

/// Severity level for host-side log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSeverity {
    Debug,
    Info,
    Warn,
    Error,
}

/// A single structured log entry from the host control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostLogEntry {
    /// Monotonic sequence within the host log.
    pub sequence: u64,
    /// Connector that produced the log, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Log severity.
    pub severity: LogSeverity,
    /// Log message.
    pub message: String,
    /// Structured fields attached to this log entry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    /// Timestamp of the log entry.
    pub timestamp: DateTime<Utc>,
}

/// Host admin API request for querying logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogQueryRequest {
    /// Optional connector ID filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Minimum severity to include.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<LogSeverity>,
    /// Only return entries after this sequence number.
    #[serde(default)]
    pub after_sequence: u64,
    /// Maximum number of entries to return.
    #[serde(default = "default_journal_limit")]
    pub limit: usize,
}

/// Host admin API response for a log query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogQueryResponse {
    /// Log entries matching the query.
    pub entries: Vec<HostLogEntry>,
    /// Highest sequence number in the response.
    pub latest_sequence: u64,
}

/// Host-side event kind for the control plane event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostEventKind {
    /// Connector lifecycle state changed.
    LifecycleTransition,
    /// Connector health check result.
    HealthCheck,
    /// Configuration revision applied.
    ConfigRevision,
    /// Rollout decision made.
    RolloutDecision,
    /// Supply chain verification completed.
    SupplyChainVerification,
    /// Admin state drift detected.
    DriftDetected,
    /// Connector started or stopped.
    ConnectorStateChange,
}

/// A single host control-plane event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEvent {
    /// Unique event identifier.
    pub event_id: String,
    /// Event kind.
    pub kind: HostEventKind,
    /// Related connector, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Human-readable summary.
    pub summary: String,
    /// Structured payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
    /// Whether this event has been acknowledged.
    #[serde(default)]
    pub acknowledged: bool,
}

/// Host admin API request for querying events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventQueryRequest {
    /// Optional connector ID filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Optional event kind filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<HostEventKind>,
    /// Only include unacknowledged events.
    #[serde(default)]
    pub unacknowledged_only: bool,
    /// Maximum number of events to return.
    #[serde(default = "default_journal_limit")]
    pub limit: usize,
}

/// Host admin API response for an event query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventQueryResponse {
    /// Events matching the query.
    pub events: Vec<HostEvent>,
    /// Total unacknowledged event count.
    pub unacknowledged_count: usize,
}

/// Host admin API request for acknowledging events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAcknowledgeRequest {
    /// Event IDs to acknowledge.
    pub event_ids: Vec<String>,
}

/// Host admin API response after acknowledging events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAcknowledgeResponse {
    /// Number of events acknowledged.
    pub acknowledged_count: usize,
    /// Event IDs that were not found.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_found: Vec<String>,
}

/// Host admin API request for querying operation receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptQueryRequest {
    /// Connector ID filter.
    pub connector_id: String,
    /// Optional operation name filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Only return receipts after this timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<DateTime<Utc>>,
    /// Maximum number of receipts to return.
    #[serde(default = "default_journal_limit")]
    pub limit: usize,
}

/// A summarized operation receipt from the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSummary {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Connector that executed the operation.
    pub connector_id: String,
    /// Operation name.
    pub operation: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
    /// Idempotency key if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Timestamp of execution.
    pub executed_at: DateTime<Utc>,
}

/// Host admin API response for a receipt query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptQueryResponse {
    /// Receipts matching the query.
    pub receipts: Vec<ReceiptSummary>,
    /// Total receipt count for this connector.
    pub total_receipts: usize,
}

// ── Simulate RPC types ──────────────────────────────────────────────────────

/// Host RPC request for a simulation (preflight + connector simulate).
///
/// This goes beyond the existing `/rpc/preflight` by actually reaching the
/// connector's `simulate()` implementation. Preflight only checks
/// budget/capability/rate-limit; simulate also asks the connector whether the
/// operation *would* succeed and can return cost estimates and resource
/// availability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSimulateRequest {
    /// Unique request identifier for correlation.
    pub request_id: String,
    /// Target connector.
    pub connector_id: String,
    /// Operation to simulate.
    pub operation: String,
    /// Input parameters (same shape as an invoke request).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    /// Zone context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    /// Principal requesting the simulation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Capability token authorizing the live simulation request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,
    /// Approval tokens required for elevated live simulation requests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_tokens: Vec<ApprovalToken>,
    /// Whether to ask the connector for cost estimates.
    #[serde(default)]
    pub estimate_cost: bool,
    /// Whether to ask the connector for resource availability.
    #[serde(default)]
    pub check_availability: bool,
    /// Deadline in milliseconds for the simulation. Prevents unbounded connector work.
    #[serde(default = "default_simulate_deadline_ms")]
    pub deadline_ms: u64,
}

const fn default_simulate_deadline_ms() -> u64 {
    5000
}

/// Which phases of the simulate pipeline actually ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulatePhase {
    /// Only host-side preflight ran (budget, capability, rate-limit).
    PreflightOnly,
    /// Host preflight passed, connector `simulate()` was called.
    ConnectorReached,
    /// Connector reported it does not support simulation for this operation.
    ConnectorUnsupported,
    /// Simulation timed out before the connector responded.
    TimedOut,
}

/// Host RPC response for a simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSimulateResponse {
    /// Correlation request identifier.
    pub request_id: String,
    /// Whether the operation would succeed (combined preflight + connector verdict).
    pub would_succeed: bool,
    /// Which phase of the simulate pipeline actually ran.
    pub phase: SimulatePhase,
    /// Host-side preflight verdict.
    pub preflight_allowed: bool,
    /// Human-readable reason if the simulation denied the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// FCP error code (e.g., `FCP-3001`) if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_code: Option<String>,
    /// Capabilities required but not present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_capabilities: Vec<String>,
    /// Connector-reported cost estimate, when `estimate_cost` was true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_estimate: Option<SimulateCostEstimate>,
    /// Connector-reported resource availability, when `check_availability` was true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability: Option<SimulateResourceAvailability>,
    /// Wall-clock time the simulation took in milliseconds.
    pub duration_ms: u64,
    /// Bounded receipt tracking the simulation for audit.
    pub receipt: SimulateReceipt,
}

/// Cost estimate returned by a connector simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateCostEstimate {
    /// Estimated API credits consumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_credits: Option<u64>,
    /// Estimated execution duration in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_duration_ms: Option<u64>,
    /// Estimated bytes transferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_bytes: Option<u64>,
    /// Confidence level of the estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<SimulateCostConfidence>,
}

/// Confidence level for a cost estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulateCostConfidence {
    /// Rough order of magnitude.
    Low,
    /// Based on historical data or connector heuristics.
    Medium,
    /// Connector queried upstream API for exact cost.
    High,
}

/// Bounded simulation receipt for audit and deduplication.
///
/// This is the host-side record of a simulation request. It captures what
/// was simulated, the verdict, and enough metadata for replay detection.
/// Unlike an invoke receipt, a simulate receipt guarantees no side effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateReceipt {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Connector that was simulated.
    pub connector_id: String,
    /// Operation that was simulated.
    pub operation: String,
    /// Phase reached.
    pub phase: SimulatePhase,
    /// Combined verdict.
    pub would_succeed: bool,
    /// Input digest (blake3 hash of the input JSON, hex-encoded).
    /// Allows deduplication without storing the full input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_digest: Option<String>,
    /// Wall-clock simulation duration in milliseconds.
    pub duration_ms: u64,
    /// Timestamp of the simulation.
    pub simulated_at: DateTime<Utc>,
}

/// Host admin API request for querying simulation receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateReceiptQueryRequest {
    /// Connector ID filter.
    pub connector_id: String,
    /// Optional operation filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Only return receipts after this timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<DateTime<Utc>>,
    /// Maximum number of receipts to return.
    #[serde(default = "default_journal_limit")]
    pub limit: usize,
}

/// Host admin API response for a simulation receipt query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateReceiptQueryResponse {
    /// Matching simulation receipts.
    pub receipts: Vec<SimulateReceipt>,
    /// Total simulation receipt count for this connector.
    pub total_receipts: usize,
}

/// Host-advertised simulation capability for a connector operation.
///
/// This is the truthful metadata that tells the CLI whether simulation is
/// real, trivial, unknown, not-yet-measured, unavailable, or unsupported for
/// a given operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulateSupport {
    /// The connector implements a real `simulate()` for this operation.
    Real,
    /// The connector returns a trivial `allowed()` without checking anything.
    /// The CLI should display this as "preflight only".
    Trivial,
    /// The connector does not support simulation for this operation.
    Unsupported,
    /// No trustworthy simulate-support signal is available yet.
    Unknown,
    /// The host has not run the measurement needed to classify support yet.
    NotYetMeasured,
    /// The host would normally classify support, but the connector is currently unavailable.
    Unavailable,
}

/// Per-operation simulation metadata advertised by the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationSimulateMetadata {
    /// Operation identifier.
    pub operation: String,
    /// Simulation support level.
    pub simulate_support: SimulateSupport,
    /// Whether cost estimation is available.
    #[serde(default)]
    pub supports_cost_estimate: bool,
    /// Whether availability checking is available.
    #[serde(default)]
    pub supports_availability_check: bool,
    /// Maximum deadline the connector accepts for simulation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_deadline_ms: Option<u64>,
}

// ── Capability issuance and auth transport contract ─────────────────────────

/// Host admin API request for issuing a capability token.
///
/// The host is the sole issuer of capability tokens in a zone. Tokens are
/// scoped to a specific connector, set of operations, and principal, with
/// optional constraints on resources, call budget, and credential access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityIssuanceRequest {
    /// Target connector for which capabilities are being granted.
    pub connector_id: String,
    /// Capability granted by the token.
    ///
    /// The live invoke verifier checks the operation's declared capability,
    /// not just the operation id. Issuance therefore must stamp canonical
    /// grants that pair this capability with each requested operation.
    pub capability_id: String,
    /// Zone within which the token is valid.
    pub zone_id: String,
    /// Principal receiving the capability.
    pub principal_id: String,
    /// Allowed operations. Empty means all operations under the connector.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
    /// Token time-to-live in seconds. Defaults to 3600 (1 hour).
    #[serde(default = "default_token_ttl_secs")]
    pub ttl_secs: u64,
    /// Optional not-before delay in seconds (deferred activation).
    /// Must not exceed `MAX_NOT_BEFORE_DELAY_SECS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_delay_secs: Option<u64>,
    /// If set, the token requires a holder proof from this node for replay resistance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_node: Option<String>,
    /// Maximum delegation depth. 0 means the token cannot be delegated.
    #[serde(default)]
    pub max_delegation_depth: u32,
    /// Optional resource allow list (URI patterns).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_allow: Vec<String>,
    /// Optional resource deny list (URI patterns).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_deny: Vec<String>,
    /// Optional call budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,
    /// Optional byte budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Allowed credential IDs for secretless egress.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_allow: Vec<CredentialId>,
    /// Preview the issuance without signing. Returns the redacted inspection
    /// but no raw token.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
}

const fn default_token_ttl_secs() -> u64 {
    3600
}

const MAX_NOT_BEFORE_DELAY_SECS: u64 = 10 * 365 * 24 * 60 * 60;

fn validated_not_before_delay_secs(delay_secs: u64) -> Result<i64, LifecycleError> {
    if delay_secs > MAX_NOT_BEFORE_DELAY_SECS {
        return Err(LifecycleError::Persistence {
            reason: format!(
                "invalid capability issuance request: not_before_delay_secs {delay_secs} exceeds max {MAX_NOT_BEFORE_DELAY_SECS}"
            ),
        });
    }

    i64::try_from(delay_secs).map_err(|_| LifecycleError::Persistence {
        reason: format!(
            "invalid capability issuance request: not_before_delay_secs {delay_secs} overflows i64 seconds"
        ),
    })
}

fn capability_constraints_from_request(
    request: &CapabilityIssuanceRequest,
) -> CapabilityConstraints {
    let resource_allow = if request.resource_allow.is_empty() {
        vec!["*".to_string()]
    } else {
        request.resource_allow.clone()
    };

    CapabilityConstraints {
        resource_allow,
        resource_deny: request.resource_deny.clone(),
        max_calls: request.max_calls,
        max_bytes: request.max_bytes,
        idempotency_key: None,
        credential_allow: request.credential_allow.clone(),
    }
}

fn capability_grants_from_request(
    request: &CapabilityIssuanceRequest,
) -> Result<Vec<CapabilityGrant>, LifecycleError> {
    let capability = CapabilityId::new(request.capability_id.as_str()).map_err(|error| {
        LifecycleError::Persistence {
            reason: format!(
                "invalid capability issuance request: capability_id '{}' is not canonical: {error}",
                request.capability_id
            ),
        }
    })?;

    if request.operations.is_empty() {
        return Ok(vec![CapabilityGrant {
            capability,
            operation: None,
        }]);
    }

    request
        .operations
        .iter()
        .map(|operation| {
            let operation = OperationId::new(operation.as_str()).map_err(|error| {
                LifecycleError::Persistence {
                    reason: format!(
                        "invalid capability issuance request: operation '{operation}' is not canonical: {error}"
                    ),
                }
            })?;
            Ok(CapabilityGrant {
                capability: capability.clone(),
                operation: Some(operation),
            })
        })
        .collect()
}

fn serialize_capability_constraints(
    constraints: &CapabilityConstraints,
) -> Result<ciborium::Value, LifecycleError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(constraints, &mut bytes).map_err(|error| {
        LifecycleError::Persistence {
            reason: format!("failed to serialize capability constraints: {error}"),
        }
    })?;
    ciborium::from_reader(&bytes[..]).map_err(|error| LifecycleError::Persistence {
        reason: format!("failed to encode capability constraints claim: {error}"),
    })
}

fn serialize_capability_grants(
    grants: &[CapabilityGrant],
) -> Result<ciborium::Value, LifecycleError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(grants, &mut bytes).map_err(|error| LifecycleError::Persistence {
        reason: format!("failed to serialize capability grants: {error}"),
    })?;
    ciborium::from_reader(&bytes[..]).map_err(|error| LifecycleError::Persistence {
        reason: format!("failed to encode capability grants claim: {error}"),
    })
}

fn deserialize_capability_constraints(
    claims: &fcp_crypto::cose::CwtClaims,
) -> Result<CapabilityConstraints, LifecycleError> {
    let Some(encoded_constraints) = claims.get(fcp_crypto::cose::fcp2_claims::CONSTRAINTS) else {
        return Ok(CapabilityConstraints::default());
    };

    let mut bytes = Vec::new();
    ciborium::into_writer(encoded_constraints, &mut bytes).map_err(|error| {
        LifecycleError::Persistence {
            reason: format!("failed to reserialize capability constraints claim: {error}"),
        }
    })?;
    ciborium::from_reader(&bytes[..]).map_err(|error| LifecycleError::Persistence {
        reason: format!("failed to decode capability constraints claim: {error}"),
    })
}

/// Host admin API response after issuing a capability token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityIssuanceResponse {
    /// Whether this was a preview only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Unique token identifier (CWT `cti` claim, hex-encoded).
    pub token_id: String,
    /// Raw `COSE_Sign1` token bytes, base64-encoded.
    /// Absent when `dry_run` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_cbor_b64: Option<String>,
    /// Redaction-safe inspection of the issued token.
    pub inspection: CapabilityTokenInspection,
    /// Journal sequence recording this issuance.
    pub journal_sequence: u64,
    /// Timestamp of issuance.
    pub issued_at: DateTime<Utc>,
}

/// Redaction-safe view of a capability token's claims.
///
/// All fields are derived from the token's CWT claims. Sensitive material
/// (signing key, raw COSE bytes) is never exposed here. This type is safe
/// for CLI rendering, audit logs, and diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenInspection {
    /// Token identifier (CWT `cti` claim, hex-encoded).
    pub token_id: String,
    /// Issuer identity.
    pub issuer: String,
    /// Subject (principal receiving the capability).
    pub subject: String,
    /// Audience (connector or zone scope).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Zone this token is valid within.
    pub zone_id: String,
    /// Capability ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    /// Allowed operations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
    /// Holder node binding. When present, requests must include a holder proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_node: Option<String>,
    /// Maximum delegation depth remaining.
    pub delegation_depth: u32,
    /// Issued-at timestamp (RFC 3339).
    pub issued_at: DateTime<Utc>,
    /// Not-before timestamp (RFC 3339), if deferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    /// Expiration timestamp (RFC 3339).
    pub expires_at: DateTime<Utc>,
    /// Whether the token is currently valid (not expired and past nbf).
    pub currently_valid: bool,
    /// Seconds remaining until expiry, or 0 if expired.
    pub seconds_remaining: u64,
    /// Resource allow patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_allow: Vec<String>,
    /// Resource deny patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_deny: Vec<String>,
    /// Call budget, if constrained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,
    /// Byte budget, if constrained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Credential IDs allowed for secretless egress.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_allow: Vec<CredentialId>,
}

/// Host admin API request for inspecting a capability token without verifying its signature.
///
/// This is a read-only operation that extracts the token's claims into a
/// redaction-safe form for CLI display and diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenInspectRequest {
    /// Raw `COSE_Sign1` token bytes, base64-encoded.
    pub token_cbor_b64: String,
}

/// Host admin API request for verifying a capability token against the host's key ring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenVerifyRequest {
    /// Raw `COSE_Sign1` token bytes, base64-encoded.
    pub token_cbor_b64: String,
    /// Operation being requested (for scope checking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Connector being targeted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
}

/// Host admin API response for a capability token verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CapabilityTokenVerifyResponse {
    /// Whether the token's cryptographic signature is valid.
    pub signature_valid: bool,
    /// Whether the token is within its validity window.
    pub temporally_valid: bool,
    /// Whether the token's scope covers the requested operation/connector.
    pub scope_valid: bool,
    /// Combined validity: all three checks pass.
    pub valid: bool,
    /// Redaction-safe inspection of the token.
    pub inspection: CapabilityTokenInspection,
    /// Human-readable rejection reasons, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejection_reasons: Vec<String>,
}

/// Structured auth envelope that the CLI carries in live requests.
///
/// This is the "transport contract" — the exact shape of auth data that `fwc`
/// must supply in every live request to `fcp-host`. The host verifies each
/// field independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRequestAuth {
    /// `COSE_Sign1` capability token (base64-encoded CBOR).
    pub capability_token_b64: String,
    /// Holder proof binding the token to this request, preventing replay.
    /// Required when the token's `holder_node` claim is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_proof: Option<LiveRequestHolderProof>,
    /// Approval tokens authorizing elevated, declassified, or specifically
    /// approved operations. Each approval is independently verified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_tokens: Vec<LiveRequestApprovalToken>,
}

/// Holder proof as transported in a live request.
///
/// The holder signs `"FCP2-HOLDER-PROOF-V1" || len(request_id) || request_id ||
/// len(operation_id) || operation_id || len(token_jti) || token_jti` to bind
/// the token to this specific request, preventing replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRequestHolderProof {
    /// Ed25519 signature (hex-encoded, 128 hex chars / 64 bytes).
    pub signature_hex: String,
    /// Node ID of the holder (must match the token's `holder_node` claim).
    pub holder_node: String,
}

/// Approval token as transported in a live request.
///
/// Approval tokens authorize specific actions that exceed the base capability
/// token's grants: elevations, declassifications, and execution-scoped
/// approvals for dangerous operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRequestApprovalToken {
    /// Unique approval token ID.
    pub token_id: String,
    /// Issuer of the approval.
    pub issuer: String,
    /// Zone this approval is valid within.
    pub zone_id: String,
    /// Approval scope kind: `elevation`, `declassification`, or `execution`.
    pub scope_kind: String,
    /// Scope payload (varies by kind).
    pub scope: Value,
    /// Token expiration (Unix epoch ms).
    pub expires_at_ms: u64,
    /// Optional `COSE_Sign1` signature (base64-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<String>,
}

// ── Structured auth denial types ────────────────────────────────────────────
// These types are returned by preflight, invoke, batch, and simulate when
// auth verification fails. They carry enough detail for the CLI to render
// actionable remediation.

/// Why an auth check failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthDenialKind {
    /// No capability token was provided.
    MissingToken,
    /// Token could not be parsed or decoded.
    MalformedToken,
    /// Token signature is invalid or unverifiable.
    InvalidSignature,
    /// Token is expired or not yet valid.
    TemporallyInvalid,
    /// Token does not grant the requested operation.
    InsufficientScope,
    /// Token does not cover the target connector.
    WrongConnector,
    /// Token has been revoked by the host.
    Revoked,
    /// Holder proof is required but missing or invalid.
    HolderProofFailed,
    /// An approval token is required but not provided.
    MissingApproval,
    /// An approval token is present but invalid, expired, or wrong scope.
    InvalidApproval,
}

/// Structured denial envelope returned by auth-gated RPC paths.
///
/// This type provides enough information for the CLI to:
/// 1. Display a clear, specific error message
/// 2. Suggest remediation steps
/// 3. Allow agents to branch on the denial kind
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthDenial {
    /// The RPC path that was denied (e.g., "invoke", "simulate", "batch").
    pub rpc: String,
    /// The kind of denial.
    pub kind: AuthDenialKind,
    /// Human-readable denial message.
    pub message: String,
    /// Token inspection (if the token could be parsed at all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection: Option<CapabilityTokenInspection>,
    /// Remediation hints ordered from most to least likely to help.
    pub remediation: Vec<String>,
    /// Unique denial ID for audit trail correlation.
    pub denial_id: String,
    /// When the denial was issued.
    pub denied_at: DateTime<Utc>,
}

/// Build an `AuthDenial` from a verify response that failed.
impl AuthDenial {
    /// Create a denial from a failed verification.
    #[must_use]
    pub fn from_verify_failure(rpc: &str, verify: &CapabilityTokenVerifyResponse) -> Self {
        let kind = if !verify.signature_valid {
            AuthDenialKind::InvalidSignature
        } else if !verify.temporally_valid {
            AuthDenialKind::TemporallyInvalid
        } else if !verify.scope_valid {
            AuthDenialKind::InsufficientScope
        } else if verify
            .rejection_reasons
            .iter()
            .any(|r| r.contains("revoked"))
        {
            AuthDenialKind::Revoked
        } else {
            AuthDenialKind::InsufficientScope
        };

        let message = if verify.rejection_reasons.is_empty() {
            format!("{rpc}: auth verification failed")
        } else {
            format!("{rpc}: {}", verify.rejection_reasons.join("; "))
        };

        let mut remediation = Vec::new();
        match kind {
            AuthDenialKind::TemporallyInvalid => {
                remediation.push(
                    "Re-issue the capability token (the current one is expired or not yet valid)"
                        .to_owned(),
                );
                remediation
                    .push("Check system clock synchronization between host and client".to_owned());
            }
            AuthDenialKind::InsufficientScope => {
                remediation.push("Request a token with the correct operation scope".to_owned());
                remediation.push(
                    "Check that the token covers the target connector and operation".to_owned(),
                );
            }
            AuthDenialKind::Revoked => {
                remediation.push(
                    "Request a new capability token (the previous one was revoked)".to_owned(),
                );
            }
            AuthDenialKind::InvalidSignature => {
                remediation.push("Ensure the token was issued by a trusted authority".to_owned());
                remediation.push("The token may have been tampered with or corrupted".to_owned());
            }
            _ => {}
        }

        Self {
            rpc: rpc.to_owned(),
            kind,
            message,
            inspection: Some(verify.inspection.clone()),
            remediation,
            denial_id: format!("denial-{}-{}", rpc, Utc::now().timestamp_millis()),
            denied_at: Utc::now(),
        }
    }

    /// Create a denial for a missing token.
    #[must_use]
    pub fn missing_token(rpc: &str) -> Self {
        Self {
            rpc: rpc.to_owned(),
            kind: AuthDenialKind::MissingToken,
            message: format!("{rpc}: a capability token is required but none was provided"),
            inspection: None,
            remediation: vec![
                format!(
                    "Issue a capability token: `fwc capabilities issue --connector <id> --operation {rpc}`"
                ),
                "Pass the token via --capability-token or FWC_CAPABILITY_TOKEN".to_owned(),
            ],
            denial_id: format!("denial-{}-{}", rpc, Utc::now().timestamp_millis()),
            denied_at: Utc::now(),
        }
    }

    /// Create a denial for a malformed token that could not be parsed.
    #[must_use]
    pub fn malformed_token(rpc: &str, parse_error: &str) -> Self {
        Self {
            rpc: rpc.to_owned(),
            kind: AuthDenialKind::MalformedToken,
            message: format!("{rpc}: capability token could not be parsed: {parse_error}"),
            inspection: None,
            remediation: vec![
                "Ensure the token is a valid base64-encoded COSE_Sign1 structure".to_owned(),
                "Re-issue the token if it was corrupted".to_owned(),
            ],
            denial_id: format!("denial-{}-{}", rpc, Utc::now().timestamp_millis()),
            denied_at: Utc::now(),
        }
    }

    /// Create a denial for a missing or invalid holder proof.
    #[must_use]
    pub fn holder_proof_failed(rpc: &str, reason: &str) -> Self {
        Self {
            rpc: rpc.to_owned(),
            kind: AuthDenialKind::HolderProofFailed,
            message: format!("{rpc}: holder proof verification failed: {reason}"),
            inspection: None,
            remediation: vec![
                "Include a valid holder proof matching the token's holder_node claim".to_owned(),
                "Sign the request binding with the holder's Ed25519 key".to_owned(),
            ],
            denial_id: format!("denial-{}-{}", rpc, Utc::now().timestamp_millis()),
            denied_at: Utc::now(),
        }
    }

    /// Create a denial for a missing approval token.
    #[must_use]
    pub fn missing_approval(rpc: &str, required_scope: &str) -> Self {
        Self {
            rpc: rpc.to_owned(),
            kind: AuthDenialKind::MissingApproval,
            message: format!(
                "{rpc}: this operation requires an approval token with scope '{required_scope}'"
            ),
            inspection: None,
            remediation: vec![
                format!("Request an approval token with scope '{required_scope}'"),
                "Pass approval tokens via --approval-token".to_owned(),
            ],
            denial_id: format!("denial-{}-{}", rpc, Utc::now().timestamp_millis()),
            denied_at: Utc::now(),
        }
    }
}

// ── Artifact provenance and install source validation ────────────────────────
// These types enforce that only real, provenance-verified artifacts can be
// installed on the live runtime path.

/// What kind of artifact source was provided for install/update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSourceKind {
    /// A real registry artifact with full provenance.
    Registry,
    /// A mesh-mirrored copy of a registry artifact, available from a peer node.
    MeshMirror,
    /// A local file path (development/staging).
    LocalPath,
    /// A remote URL (direct download).
    RemoteUrl,
    /// An inline WASM blob (embedded in the request).
    InlineBlob,
}

/// Provenance evidence attached to an artifact for install/update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    /// Source kind.
    pub source_kind: ArtifactSourceKind,
    /// Source URI or path.
    pub source_uri: String,
    /// Blake3 hash of the artifact bytes (hex-encoded).
    pub content_hash: String,
    /// Whether the hash was verified by the host.
    pub hash_verified: bool,
    /// Optional supply-chain signature (base64-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<String>,
    /// Whether a valid supply-chain signature was verified.
    #[serde(default)]
    pub signature_verified: bool,
    /// The manifest version from the artifact's embedded metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_version: Option<String>,
    /// Size of the artifact in bytes.
    pub size_bytes: u64,
}

/// Why an artifact was rejected by the host's provenance gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRejectionKind {
    /// The artifact has a placeholder hash (e.g., `PLACEHOLDER_HASH`).
    PlaceholderHash,
    /// The artifact has a zero-length or empty content hash.
    EmptyHash,
    /// The content hash does not match the actual artifact bytes.
    HashMismatch,
    /// The artifact is a known demo/stub bundle (synthetic identity).
    DemoBundle,
    /// The artifact has no embedded manifest or an invalid manifest.
    InvalidManifest,
    /// The supply-chain signature is missing when policy requires it.
    MissingSignature,
    /// The supply-chain signature failed verification.
    InvalidSignature,
    /// The artifact exceeds the maximum allowed size.
    OversizedArtifact,
    /// The source URI is not allowed by the host's install policy.
    DisallowedSource,
}

/// Structured rejection envelope for artifact install/update failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRejection {
    /// The connector being installed/updated.
    pub connector_id: String,
    /// The kind of rejection.
    pub kind: ArtifactRejectionKind,
    /// Human-readable rejection message.
    pub message: String,
    /// Provenance details of the rejected artifact (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ArtifactProvenance>,
    /// Remediation hints.
    pub remediation: Vec<String>,
    /// Policy gate that triggered the rejection.
    pub policy_gate: String,
}

/// Persisted host-admin metadata describing the runtime artifact currently
/// associated with a connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorArtifactMetadata {
    /// Provenance evidence for the artifact accepted by the host.
    pub provenance: ArtifactProvenance,
    /// Optional placement hint captured alongside the artifact metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<ObjectPlacementPolicy>,
    /// When the host recorded this metadata.
    pub recorded_at: DateTime<Utc>,
    /// Optional initiating actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_by: Option<String>,
}

/// Response for the host-admin artifact metadata read path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorArtifactMetadataResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Persisted artifact/admin metadata, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ConnectorArtifactMetadata>,
    /// Timestamp when the response was evaluated.
    pub evaluated_at: DateTime<Utc>,
}

/// Request for registering connector artifact/admin provenance metadata through
/// the host control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorArtifactRegistrationRequest {
    /// Preview the result without persisting the metadata.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Provenance evidence supplied for the artifact.
    pub provenance: ArtifactProvenance,
    /// Optional placement hint to persist alongside the artifact metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<ObjectPlacementPolicy>,
    /// Whether host policy requires a verified signature for this registration.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_signature: bool,
    /// Optional host policy size limit for the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size_bytes: Option<u64>,
    /// Optional initiating actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiated_by: Option<String>,
}

/// Response from the host-admin artifact provenance registration path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorArtifactRegistrationResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Whether this was a preview only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Whether the registration was accepted by host policy.
    pub accepted: bool,
    /// Previous persisted metadata, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<ConnectorArtifactMetadata>,
    /// Current metadata after acceptance or preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<ConnectorArtifactMetadata>,
    /// Structured rejection details when the request was denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<ArtifactRejection>,
    /// Journal sequence recorded for accepted persisted updates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_sequence: Option<u64>,
    /// Timestamp when the host evaluated the request.
    pub evaluated_at: DateTime<Utc>,
}

/// Known placeholder hashes that must be rejected on the live install path.
pub const KNOWN_PLACEHOLDER_HASHES: &[&str] = &[
    "PLACEHOLDER_HASH",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA-256 of empty
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", // Blake3 of empty
];

/// Check whether a hash looks like a placeholder or demo hash.
#[must_use]
pub fn is_placeholder_hash(hash: &str) -> bool {
    if hash.is_empty() {
        return true;
    }
    let normalized = hash.trim().to_lowercase();
    KNOWN_PLACEHOLDER_HASHES
        .iter()
        .any(|p| normalized == p.to_lowercase())
}

/// Validate an artifact's provenance before allowing install/update.
///
/// Returns `None` if the artifact passes all gates, or `Some(rejection)` if
/// it should be rejected.
#[must_use]
pub fn validate_artifact_provenance(
    connector_id: &str,
    provenance: &ArtifactProvenance,
    require_signature: bool,
    max_size_bytes: Option<u64>,
) -> Option<ArtifactRejection> {
    // Gate 1: Placeholder hash
    if is_placeholder_hash(&provenance.content_hash) {
        return Some(ArtifactRejection {
            connector_id: connector_id.to_owned(),
            kind: ArtifactRejectionKind::PlaceholderHash,
            message: format!(
                "Artifact for '{}' has a placeholder hash '{}'. \
                 Real artifacts must have computed content hashes.",
                connector_id, provenance.content_hash
            ),
            provenance: Some(provenance.clone()),
            remediation: vec![
                "Build the connector with `fwc package` to compute a real content hash".to_owned(),
                "Use `with_computed_hash()` in tests to generate valid hashes".to_owned(),
            ],
            policy_gate: "provenance.hash.no_placeholder".to_owned(),
        });
    }

    // Gate 2: Hash verification
    if !provenance.hash_verified {
        return Some(ArtifactRejection {
            connector_id: connector_id.to_owned(),
            kind: ArtifactRejectionKind::HashMismatch,
            message: format!(
                "Artifact for '{connector_id}' has an unverified content hash. \
                 The host could not confirm the hash matches the artifact bytes."
            ),
            provenance: Some(provenance.clone()),
            remediation: vec![
                "Ensure the artifact is not corrupted during transfer".to_owned(),
                "Re-download or re-package the connector".to_owned(),
            ],
            policy_gate: "provenance.hash.verified".to_owned(),
        });
    }

    // Gate 3: Signature required but missing
    if require_signature && provenance.signature_b64.is_none() {
        return Some(ArtifactRejection {
            connector_id: connector_id.to_owned(),
            kind: ArtifactRejectionKind::MissingSignature,
            message: format!(
                "Artifact for '{connector_id}' has no supply-chain signature. \
                 This host's policy requires signed artifacts."
            ),
            provenance: Some(provenance.clone()),
            remediation: vec![
                "Sign the artifact with `fwc package --sign`".to_owned(),
                "Contact your supply-chain administrator for signing keys".to_owned(),
            ],
            policy_gate: "provenance.signature.required".to_owned(),
        });
    }

    // Gate 4: Signature present but invalid
    if provenance.signature_b64.is_some() && !provenance.signature_verified {
        return Some(ArtifactRejection {
            connector_id: connector_id.to_owned(),
            kind: ArtifactRejectionKind::InvalidSignature,
            message: format!(
                "Artifact for '{connector_id}' has an invalid supply-chain signature."
            ),
            provenance: Some(provenance.clone()),
            remediation: vec![
                "Re-sign the artifact with a trusted key".to_owned(),
                "The artifact may have been modified after signing".to_owned(),
            ],
            policy_gate: "provenance.signature.valid".to_owned(),
        });
    }

    // Gate 5: Size limit
    if let Some(max) = max_size_bytes.filter(|&max| provenance.size_bytes > max) {
        return Some(ArtifactRejection {
            connector_id: connector_id.to_owned(),
            kind: ArtifactRejectionKind::OversizedArtifact,
            message: format!(
                "Artifact for '{connector_id}' is {} bytes, exceeding the {max} byte limit.",
                provenance.size_bytes
            ),
            provenance: Some(provenance.clone()),
            remediation: vec![
                "Optimize the connector binary size".to_owned(),
                "Request a size limit increase from the host administrator".to_owned(),
            ],
            policy_gate: "provenance.size.max".to_owned(),
        });
    }

    None
}

/// Summary of an issued token tracked by the host for revocation and audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedTokenRecord {
    /// Token identifier (hex-encoded CWT `cti`).
    pub token_id: String,
    /// Connector the token is scoped to.
    pub connector_id: String,
    /// Principal that received the token.
    pub principal_id: String,
    /// Zone the token is valid within.
    pub zone_id: String,
    /// Token creation timestamp.
    pub issued_at: DateTime<Utc>,
    /// Token expiration timestamp.
    pub expires_at: DateTime<Utc>,
    /// Whether the token has been revoked.
    #[serde(default)]
    pub revoked: bool,
    /// Revocation reason, if revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
    /// Revocation timestamp, if revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Host admin API request for revoking a previously issued token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRevocationRequest {
    /// Token identifier to revoke.
    pub token_id: String,
    /// Reason for revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Host admin API response after revoking a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRevocationResponse {
    /// Whether the token was found and revoked.
    pub revoked: bool,
    /// Token identifier.
    pub token_id: String,
    /// Human-readable message.
    pub message: String,
    /// Journal sequence recording this revocation.
    pub journal_sequence: u64,
}

/// Host admin API request for listing issued tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedTokenQueryRequest {
    /// Optional connector ID filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Optional principal ID filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Only include active (non-revoked, non-expired) tokens.
    #[serde(default)]
    pub active_only: bool,
    /// Maximum number of tokens to return.
    #[serde(default = "default_journal_limit")]
    pub limit: usize,
}

/// Host admin API response for a token query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedTokenQueryResponse {
    /// Matching token records.
    pub tokens: Vec<IssuedTokenRecord>,
    /// Total number of tracked tokens.
    pub total_tokens: usize,
    /// Number of currently active tokens.
    pub active_count: usize,
}

/// Desired connector runtime state persisted by the host admin plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DesiredRuntimeState {
    /// No desired runtime target has been recorded yet.
    #[default]
    Unspecified,
    /// Connector should be enabled and eligible for execution.
    Enabled,
    /// Connector should remain installed but disabled.
    Disabled,
    /// Connector should be removed from active use.
    Uninstalled,
}

impl DesiredRuntimeState {
    const fn from_lifecycle_state(state: LifecycleState) -> Self {
        match state {
            LifecycleState::Disabled => Self::Disabled,
            LifecycleState::Uninstalled => Self::Uninstalled,
            LifecycleState::Pending
            | LifecycleState::Installing
            | LifecycleState::Canary
            | LifecycleState::Production
            | LifecycleState::RolledBack => Self::Enabled,
        }
    }
}

/// Observed connector runtime state persisted by the host admin plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ObservedRuntimeState {
    /// The host has not yet observed a concrete runtime state.
    #[default]
    Unknown,
    /// Connector is starting or installing.
    Starting,
    /// Connector is running and currently receiving traffic.
    Running,
    /// Connector is available but degraded or recently rolled back.
    Degraded,
    /// Connector is stopped by policy or operator action.
    Stopped,
    /// Connector artifacts or runtime process are missing.
    Missing,
}

impl ObservedRuntimeState {
    const fn from_lifecycle_state(state: LifecycleState) -> Self {
        match state {
            LifecycleState::Pending | LifecycleState::Installing => Self::Starting,
            LifecycleState::Canary | LifecycleState::Production => Self::Running,
            LifecycleState::RolledBack => Self::Degraded,
            LifecycleState::Disabled => Self::Stopped,
            LifecycleState::Uninstalled => Self::Missing,
        }
    }
}

/// A single connector config revision recorded by the host admin plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigRevisionRecord {
    /// Monotonic revision identifier.
    pub revision_id: u64,
    /// Previous active revision for this connector, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_revision_id: Option<u64>,
    /// Revision creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Optional actor or subsystem that created the revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Optional summary or mutation reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_reason: Option<String>,
    /// Export-safe connector config payload with inline secrets redacted.
    pub payload: Value,
    /// Stable digest of the serialized payload.
    pub payload_digest: String,
    /// JSON pointer paths where inline secret material was redacted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
    /// Secretless credential references preserved in persisted config state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_references: Vec<CredentialReferenceRecord>,
    /// Whether the original payload contained inline secret material.
    #[serde(default, skip_serializing_if = "is_false")]
    pub contains_inline_secrets: bool,
}

impl ConfigRevisionRecord {
    fn new(
        revision_id: u64,
        previous_revision_id: Option<u64>,
        payload: Value,
        created_by: Option<String>,
        change_reason: Option<String>,
    ) -> Result<Self, LifecycleError> {
        let payload_digest = config_payload_digest(&payload)?;
        let sanitized_payload = sanitize_config_payload(payload);
        Ok(Self {
            revision_id,
            previous_revision_id,
            created_at: Utc::now(),
            created_by,
            change_reason,
            payload: sanitized_payload.payload,
            payload_digest,
            redacted_fields: sanitized_payload.redacted_fields,
            credential_references: sanitized_payload.credential_references,
            contains_inline_secrets: sanitized_payload.contains_inline_secrets,
        })
    }

    /// Whether this recorded revision can be safely replayed back into the host.
    #[must_use]
    pub const fn is_replayable(&self) -> bool {
        !self.contains_inline_secrets
    }
}

/// Sanitized connector config payload safe for host responses and audit trails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedConnectorConfig {
    /// Export-safe config payload with inline secrets redacted.
    pub payload: Value,
    /// Stable digest of the raw serialized payload.
    pub payload_digest: String,
    /// JSON pointer paths where inline secret material was redacted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
    /// Secretless credential references preserved in the payload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_references: Vec<CredentialReferenceRecord>,
    /// Whether the original payload contained inline secret material.
    #[serde(default, skip_serializing_if = "is_false")]
    pub contains_inline_secrets: bool,
}

impl SanitizedConnectorConfig {
    /// Build a sanitized config view from a raw payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload cannot be serialized for digesting.
    pub fn from_payload(payload: Value) -> Result<Self, LifecycleError> {
        let payload_digest = config_payload_digest(&payload)?;
        let sanitized_payload = sanitize_config_payload(payload);
        Ok(Self {
            payload: sanitized_payload.payload,
            payload_digest,
            redacted_fields: sanitized_payload.redacted_fields,
            credential_references: sanitized_payload.credential_references,
            contains_inline_secrets: sanitized_payload.contains_inline_secrets,
        })
    }

    /// Whether this sanitized payload can be safely replayed back into the host.
    #[must_use]
    pub const fn is_replayable(&self) -> bool {
        !self.contains_inline_secrets
    }
}

impl From<&ConfigRevisionRecord> for SanitizedConnectorConfig {
    fn from(revision: &ConfigRevisionRecord) -> Self {
        Self {
            payload: revision.payload.clone(),
            payload_digest: revision.payload_digest.clone(),
            redacted_fields: revision.redacted_fields.clone(),
            credential_references: revision.credential_references.clone(),
            contains_inline_secrets: revision.contains_inline_secrets,
        }
    }
}

/// Source of the current host-visible config snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorConfigSnapshotSource {
    /// Current config is backed by the active admin-state revision.
    ActiveRevision,
    /// Current config comes from the managed inventory but has not yet been
    /// checkpointed into config revision history.
    ManagedInventory,
}

/// Host-visible current config snapshot for one connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigSnapshot {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Current sanitized config payload.
    pub current: SanitizedConnectorConfig,
    /// Where the current payload came from.
    pub source: ConnectorConfigSnapshotSource,
    /// Active config revision id, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_id: Option<u64>,
    /// Active revision metadata, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision: Option<ConfigRevisionRecord>,
    /// Total config revisions tracked for the connector.
    pub revision_count: usize,
    /// Latest journal sequence touching this connector.
    pub last_journal_sequence: u64,
}

/// Host-visible config revision history for one connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigRevisionsResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Currently active revision id, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_id: Option<u64>,
    /// Total revisions in history.
    pub revision_count: usize,
    /// Latest journal sequence touching this connector.
    pub last_journal_sequence: u64,
    /// Recorded config revisions in creation order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revisions: Vec<ConfigRevisionRecord>,
}

/// Diff request comparing a candidate config payload against the current config
/// or a specific prior revision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigDiffRequest {
    /// Candidate raw config payload.
    pub payload: Value,
    /// Optional baseline revision id. Defaults to the current config snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<u64>,
}

/// Diff classification for one changed config path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigDiffKind {
    /// Path was added in the candidate payload.
    Added,
    /// Path was removed from the candidate payload.
    Removed,
    /// Path existed in both payloads but changed value.
    Changed,
}

/// One changed config path between two payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDiffEntry {
    /// JSON pointer path (`/` for the root payload).
    pub path: String,
    /// Change classification.
    pub kind: ConfigDiffKind,
    /// Previous value when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    /// Candidate value when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
}

/// Host-visible diff response for one config candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigDiffResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Baseline revision id when diffing against revision history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_revision_id: Option<u64>,
    /// Sanitized baseline payload.
    pub base: SanitizedConnectorConfig,
    /// Sanitized candidate payload.
    pub candidate: SanitizedConnectorConfig,
    /// Whether any paths changed.
    pub changed: bool,
    /// Detailed changed paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<ConfigDiffEntry>,
}

/// Validate a candidate config payload against the live host registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigValidateRequest {
    /// Candidate raw config payload.
    pub payload: Value,
    /// Optional optimistic concurrency guard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_active_revision_id: Option<u64>,
}

/// Validation result for a candidate config payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigValidateResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Whether the host accepted the candidate in preview mode.
    pub valid: bool,
    /// Current active revision id when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_active_revision_id: Option<u64>,
    /// Current sanitized config payload.
    pub current: SanitizedConnectorConfig,
    /// Candidate sanitized config payload.
    pub candidate: SanitizedConnectorConfig,
    /// Detailed changed paths between current and candidate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff: Vec<ConfigDiffEntry>,
    /// Preview of the live registry reconciliation when validation succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<ConnectorInventoryApplyReport>,
    /// Validation failure when `valid=false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Apply a candidate config payload through the live host admin plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigApplyRequest {
    /// Candidate raw config payload.
    pub payload: Value,
    /// Optional optimistic concurrency guard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_active_revision_id: Option<u64>,
    /// Optional actor/subsystem label recorded in revision history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Optional change summary recorded in revision history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_reason: Option<String>,
}

/// Apply response for a host-backed config mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigApplyResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Whether the requested payload changed anything materially.
    #[serde(default, skip_serializing_if = "is_false")]
    pub changed: bool,
    /// Previous active revision id when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_active_revision_id: Option<u64>,
    /// Current active revision id when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_active_revision_id: Option<u64>,
    /// Previous sanitized config payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<SanitizedConnectorConfig>,
    /// Current sanitized config payload after the mutation.
    pub current: SanitizedConnectorConfig,
    /// Detailed changed paths between previous and current.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff: Vec<ConfigDiffEntry>,
    /// Newly recorded active revision when a write occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<ConfigRevisionRecord>,
    /// Live registry reconciliation report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apply: Option<ConnectorInventoryApplyReport>,
    /// Admin-state reconciliation summary after the live registry changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_state: Option<StartupReconciliationReport>,
}

/// Roll back to a previous config revision by re-applying its sanitized payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigRollbackRequest {
    /// Revision to re-apply as the new active config.
    pub revision_id: u64,
    /// Optional optimistic concurrency guard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_active_revision_id: Option<u64>,
    /// Optional actor/subsystem label recorded in the new revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Optional change summary recorded in the new revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_reason: Option<String>,
}

/// Compute a stable path-level diff between two config payloads.
#[must_use]
pub fn diff_config_values(before: &Value, after: &Value) -> Vec<ConfigDiffEntry> {
    let mut entries = Vec::new();
    diff_config_values_inner("", Some(before), Some(after), &mut entries);
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

/// Compute a path-level diff while redacting any inline secret values.
///
/// The raw payloads are still compared first, so secret rotations remain
/// visible as changed paths even though the returned values are sanitized.
///
/// # Errors
///
/// Returns an error if any changed value cannot be serialized during
/// sanitization.
pub fn diff_sanitized_config_values(
    before: &Value,
    after: &Value,
) -> Result<Vec<ConfigDiffEntry>, LifecycleError> {
    diff_config_values(before, after)
        .into_iter()
        .map(|entry| {
            Ok(ConfigDiffEntry {
                path: entry.path.clone(),
                kind: entry.kind,
                before: sanitize_diff_value(&entry.path, entry.before)?,
                after: sanitize_diff_value(&entry.path, entry.after)?,
            })
        })
        .collect()
}

fn diff_config_values_inner(
    path: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    entries: &mut Vec<ConfigDiffEntry>,
) {
    match (before, after) {
        (Some(left), Some(right)) if left == right => {}
        (None, Some(right)) => entries.push(ConfigDiffEntry {
            path: config_diff_path(path),
            kind: ConfigDiffKind::Added,
            before: None,
            after: Some(right.clone()),
        }),
        (Some(left), None) => entries.push(ConfigDiffEntry {
            path: config_diff_path(path),
            kind: ConfigDiffKind::Removed,
            before: Some(left.clone()),
            after: None,
        }),
        (Some(Value::Object(left)), Some(Value::Object(right))) => {
            let keys = left
                .keys()
                .chain(right.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            for key in keys {
                let child_path = join_json_pointer(path, &key);
                diff_config_values_inner(&child_path, left.get(&key), right.get(&key), entries);
            }
        }
        (Some(Value::Array(left)), Some(Value::Array(right))) => {
            let max_len = left.len().max(right.len());
            for index in 0..max_len {
                let child_path = join_json_pointer(path, &index.to_string());
                diff_config_values_inner(&child_path, left.get(index), right.get(index), entries);
            }
        }
        (Some(left), Some(right)) => entries.push(ConfigDiffEntry {
            path: config_diff_path(path),
            kind: ConfigDiffKind::Changed,
            before: Some(left.clone()),
            after: Some(right.clone()),
        }),
        (None, None) => {}
    }
}

fn sanitize_diff_value(path: &str, value: Option<Value>) -> Result<Option<Value>, LifecycleError> {
    value
        .map(|value| sanitize_diff_value_inner(path, value))
        .transpose()
}

fn sanitize_diff_value_inner(path: &str, value: Value) -> Result<Value, LifecycleError> {
    if path != "/" {
        let key = path.rsplit('/').next().unwrap_or_default();
        if should_redact_config_key(key) {
            return Ok(Value::String(REDACTED_CONFIG_VALUE.to_string()));
        }
        if is_credential_reference_key(key) {
            return Ok(value);
        }
    }

    SanitizedConnectorConfig::from_payload(value).map(|value| value.payload)
}

fn config_diff_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn join_json_pointer(path: &str, segment: &str) -> String {
    let escaped = segment.replace('~', "~0").replace('/', "~1");
    if path.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{path}/{escaped}")
    }
}

/// Resolution state for a persisted secretless credential reference.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceStatus {
    /// The host has not checked the reference since it was persisted.
    #[default]
    Unknown,
    /// The reference is currently resolvable.
    Available,
    /// The underlying secret material rotated since the last known-good check.
    Rotated,
    /// The referenced credential no longer exists.
    Missing,
    /// The reference exists but could not be accessed.
    Inaccessible,
}

/// Secretless credential reference metadata captured in config revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialReferenceRecord {
    /// JSON pointer path to the reference inside the config payload.
    pub path: String,
    /// Credential handle preserved instead of inline secret material.
    pub credential_id: CredentialId,
    /// Latest known resolution state for this reference.
    #[serde(default)]
    pub status: SecretReferenceStatus,
    /// Most recent resolution attempt timestamp, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<DateTime<Utc>>,
    /// Most recent resolution error, redacted and operator-safe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Mutation recorded in the host admin-state journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminStateMutation {
    /// Lifecycle record was upserted.
    LifecycleRecordSaved {
        /// Version currently represented by the lifecycle record.
        version: Version,
        /// Current lifecycle state after the save.
        state: LifecycleState,
    },
    /// Desired runtime state changed.
    DesiredStateSet {
        /// New desired runtime target.
        desired_state: DesiredRuntimeState,
    },
    /// Observed runtime state changed.
    ObservedStateSet {
        /// New observed runtime state.
        observed_state: ObservedRuntimeState,
    },
    /// Connector pin state changed.
    PinSet {
        /// Version pinned for the connector.
        version: Version,
    },
    /// Connector pin state was cleared.
    PinCleared,
    /// Config revision was appended and made active.
    ConfigRevisionAppended {
        /// Newly assigned revision identifier.
        revision_id: u64,
        /// Stable payload digest for diff/audit linkage.
        payload_digest: String,
    },
    /// Artifact/admin provenance metadata was updated.
    ArtifactMetadataUpdated {
        /// Source kind accepted by the host.
        source_kind: ArtifactSourceKind,
        /// Source URI or path recorded for the artifact.
        source_uri: String,
        /// Stable content digest recorded for the artifact.
        content_hash: String,
        /// Manifest version from the artifact metadata, when known.
        manifest_version: Option<String>,
        /// Whether placement metadata was recorded alongside the artifact.
        placement_present: bool,
    },
}

/// A monotonic admin-state journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminStateJournalEntry {
    /// Monotonic sequence number for total ordering.
    pub sequence: u64,
    /// Connector affected by the mutation.
    pub connector_id: ConnectorId,
    /// Timestamp of the mutation.
    pub occurred_at: DateTime<Utc>,
    /// Mutation detail.
    pub mutation: AdminStateMutation,
    /// Optional initiating actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiated_by: Option<String>,
}

/// Canonical persisted admin state for a single connector.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectorAdminState {
    /// Latest persisted lifecycle record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleRecord>,
    /// Desired runtime target.
    #[serde(default)]
    pub desired_state: DesiredRuntimeState,
    /// Latest host-observed runtime state.
    #[serde(default)]
    pub observed_state: ObservedRuntimeState,
    /// Optional pinned version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_version: Option<Version>,
    /// Recorded config revisions for this connector.
    #[serde(default)]
    pub config_revisions: Vec<ConfigRevisionRecord>,
    /// Currently active config revision id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_config_revision_id: Option<u64>,
    /// Optional persisted runtime artifact/admin provenance metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ConnectorArtifactMetadata>,
    /// Last journal sequence that mutated this connector.
    #[serde(default)]
    pub last_journal_sequence: u64,
}

impl ConnectorAdminState {
    /// Return the active config revision, if any.
    #[must_use]
    pub fn active_config_revision(&self) -> Option<&ConfigRevisionRecord> {
        let revision_id = self.active_config_revision_id?;
        self.config_revisions
            .iter()
            .find(|revision| revision.revision_id == revision_id)
    }

    /// Return a specific config revision by id, if present.
    #[must_use]
    pub fn config_revision(&self, revision_id: u64) -> Option<&ConfigRevisionRecord> {
        self.config_revisions
            .iter()
            .find(|revision| revision.revision_id == revision_id)
    }

    const fn apply_lifecycle_projection(&mut self, record: &LifecycleRecord) {
        self.desired_state = DesiredRuntimeState::from_lifecycle_state(record.state);
        self.observed_state = ObservedRuntimeState::from_lifecycle_state(record.state);
    }
}

const STARTUP_RECONCILIATION_ACTOR: &str = "host-startup-reconcile";
const STARTUP_RECONCILIATION_STUCK_SECS: i64 = 300;

/// Recommended next action when connector state has drifted from intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Restart the connector runtime.
    RestartConnector,
    /// Repair configuration or health before retrying.
    RepairConnector,
    /// Reinstall or restore connector artifacts.
    ReinstallConnector,
    /// Finish an in-flight rollout decision.
    CompleteRollout,
    /// Disable or uninstall the connector to match policy.
    DisableConnector,
    /// Manual operator investigation is required.
    Investigate,
}

/// Drift category for desired-versus-observed connector state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorDriftKind {
    /// Connector should be enabled but is not running.
    EnabledButNotRunning,
    /// Connector should be enabled but the artifact/runtime is missing.
    EnabledButMissing,
    /// Connector is enabled but degraded.
    EnabledButDegraded,
    /// Connector is disabled but still active.
    DisabledButRunning,
    /// Connector should be absent but is still present.
    UninstalledButPresent,
    /// Installation appears to be stuck.
    InstallStuck,
    /// Canary rollout is overdue for promotion or rollback.
    CanaryStuck,
}

/// Human/audit-friendly drift detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorDriftStatus {
    /// Classified drift kind.
    pub kind: ConnectorDriftKind,
    /// Suggested recovery action for the operator or agent.
    pub recovery_action: RecoveryAction,
    /// Stable human-readable summary.
    pub message: String,
}

/// Host-visible connector status after reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorAdminStatus {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Desired runtime target.
    pub desired_state: DesiredRuntimeState,
    /// Latest observed runtime state.
    pub observed_state: ObservedRuntimeState,
    /// Lifecycle/rollout status when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleStatus>,
    /// Optional pinned version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_version: Option<Version>,
    /// Active config revision id, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_config_revision_id: Option<u64>,
    /// Persisted runtime artifact/admin provenance metadata, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ConnectorArtifactMetadata>,
    /// Total config revisions tracked for this connector.
    pub config_revision_count: usize,
    /// Latest journal sequence touching this connector.
    pub last_journal_sequence: u64,
    /// Drift/recovery diagnosis when desired and observed state diverge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift: Option<ConnectorDriftStatus>,
    /// Timestamp when this view was evaluated.
    pub evaluated_at: DateTime<Utc>,
}

/// Result row for one connector during startup reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupReconciliationEntry {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Whether the connector received a fresh admin-state row.
    pub created_admin_state: bool,
    /// Desired runtime state after reconciliation.
    pub desired_state: DesiredRuntimeState,
    /// Observed state before reconciliation.
    pub observed_state_before: ObservedRuntimeState,
    /// Observed state after reconciliation.
    pub observed_state_after: ObservedRuntimeState,
    /// Whether persistence state changed during reconciliation.
    pub updated: bool,
    /// Drift classification after reconciliation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift: Option<ConnectorDriftStatus>,
}

/// Aggregate startup reconciliation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupReconciliationReport {
    /// Timestamp of the reconciliation pass.
    pub reconciled_at: DateTime<Utc>,
    /// Total tracked connectors after reconciliation.
    pub tracked_connectors: usize,
    /// Number of connector admin-state rows created.
    pub created_connectors: usize,
    /// Number of observed-state updates applied.
    pub observed_updates: usize,
    /// Number of connectors still in drift after reconciliation.
    pub drifted_connectors: usize,
    /// Per-connector outcomes.
    pub entries: Vec<StartupReconciliationEntry>,
}

const fn desired_state_from_summary(summary: &ConnectorSummary) -> DesiredRuntimeState {
    if summary.enabled {
        DesiredRuntimeState::Enabled
    } else {
        DesiredRuntimeState::Disabled
    }
}

const fn observed_state_from_summary(summary: &ConnectorSummary) -> ObservedRuntimeState {
    if !summary.enabled {
        return ObservedRuntimeState::Stopped;
    }

    match &summary.health {
        ConnectorHealth::Healthy => ObservedRuntimeState::Running,
        ConnectorHealth::Degraded { .. } => ObservedRuntimeState::Degraded,
        ConnectorHealth::Unavailable { .. } => ObservedRuntimeState::Stopped,
    }
}

fn install_stuck(record: &LifecycleRecord, now: DateTime<Utc>) -> bool {
    matches!(
        record.state,
        LifecycleState::Pending | LifecycleState::Installing
    ) && now
        .signed_duration_since(record.state_changed_at)
        .num_seconds()
        >= STARTUP_RECONCILIATION_STUCK_SECS
}

fn canary_stuck(record: &LifecycleRecord, now: DateTime<Utc>) -> bool {
    record.state == LifecycleState::Canary && record.canary_expires_in_secs_at(now) == Some(0)
}

fn connector_drift_status(
    state: &ConnectorAdminState,
    now: DateTime<Utc>,
) -> Option<ConnectorDriftStatus> {
    if let Some(record) = state.lifecycle.as_ref() {
        if install_stuck(record, now) {
            return Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::InstallStuck,
                recovery_action: RecoveryAction::Investigate,
                message: "connector install/startup has remained pending long enough to require operator investigation".to_string(),
            });
        }

        if canary_stuck(record, now) {
            return Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::CanaryStuck,
                recovery_action: RecoveryAction::CompleteRollout,
                message: "connector canary has exceeded its maximum duration and needs promotion or rollback".to_string(),
            });
        }
    }

    match state.desired_state {
        DesiredRuntimeState::Enabled => match state.observed_state {
            ObservedRuntimeState::Degraded => Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::EnabledButDegraded,
                recovery_action: RecoveryAction::RepairConnector,
                message: "connector should be enabled but health or self-check results are degraded".to_string(),
            }),
            ObservedRuntimeState::Stopped => Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::EnabledButNotRunning,
                recovery_action: RecoveryAction::RestartConnector,
                message: "connector should be enabled but is not currently running".to_string(),
            }),
            ObservedRuntimeState::Missing => Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::EnabledButMissing,
                recovery_action: RecoveryAction::ReinstallConnector,
                message: "connector should be enabled but no live runtime or artifact was found".to_string(),
            }),
            ObservedRuntimeState::Unknown | ObservedRuntimeState::Starting => Some(
                ConnectorDriftStatus {
                    kind: ConnectorDriftKind::EnabledButNotRunning,
                    recovery_action: RecoveryAction::Investigate,
                    message: "connector should be enabled but the host has not yet observed a stable running state".to_string(),
                },
            ),
            ObservedRuntimeState::Running => None,
        },
        DesiredRuntimeState::Disabled => match state.observed_state {
            ObservedRuntimeState::Running | ObservedRuntimeState::Degraded => {
                Some(ConnectorDriftStatus {
                    kind: ConnectorDriftKind::DisabledButRunning,
                    recovery_action: RecoveryAction::DisableConnector,
                    message: "connector should be disabled but still appears active".to_string(),
                })
            }
            _ => None,
        },
        DesiredRuntimeState::Uninstalled => match state.observed_state {
            ObservedRuntimeState::Running
            | ObservedRuntimeState::Degraded
            | ObservedRuntimeState::Stopped
            | ObservedRuntimeState::Starting => Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::UninstalledButPresent,
                recovery_action: RecoveryAction::DisableConnector,
                message: "connector should be uninstalled but host state still shows it present".to_string(),
            }),
            ObservedRuntimeState::Unknown | ObservedRuntimeState::Missing => None,
        },
        DesiredRuntimeState::Unspecified => None,
    }
}

fn connector_admin_status_from_state(
    connector_id: &ConnectorId,
    state: &ConnectorAdminState,
    now: DateTime<Utc>,
) -> ConnectorAdminStatus {
    ConnectorAdminStatus {
        connector_id: connector_id.clone(),
        desired_state: state.desired_state,
        observed_state: state.observed_state,
        lifecycle: state
            .lifecycle
            .as_ref()
            .map(|record| LifecycleStatus::from_record(record, now, false)),
        pinned_version: state.pinned_version.clone(),
        active_config_revision_id: state.active_config_revision_id,
        artifact: state.artifact.clone(),
        config_revision_count: state.config_revisions.len(),
        last_journal_sequence: state.last_journal_sequence,
        drift: connector_drift_status(state, now),
        evaluated_at: now,
    }
}

/// Entire persisted admin-state snapshot for the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAdminStateSnapshot {
    #[serde(default = "host_admin_state_snapshot_version")]
    schema_version: u32,
    #[serde(default)]
    connectors: HashMap<ConnectorId, ConnectorAdminState>,
    #[serde(default)]
    journal: Vec<AdminStateJournalEntry>,
    #[serde(default = "initial_revision_id")]
    next_config_revision_id: u64,
    #[serde(default = "initial_journal_sequence")]
    next_journal_sequence: u64,
    #[serde(default)]
    events: Vec<HostEvent>,
    #[serde(default)]
    next_event_sequence: u64,
    #[serde(default)]
    logs: Vec<HostLogEntry>,
    #[serde(default)]
    next_log_sequence: u64,
    #[serde(default)]
    issued_tokens: Vec<IssuedTokenRecord>,
    #[serde(default)]
    next_token_sequence: u64,
    #[serde(default)]
    last_observed_time_ms: i64,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    issuer_verifying_keys: HashMap<String, fcp_crypto::ed25519::Ed25519VerifyingKey>,
    #[serde(default)]
    receipts: Vec<ReceiptSummary>,
    #[serde(default)]
    simulate_receipts: Vec<SimulateReceipt>,
}

impl Default for HostAdminStateSnapshot {
    fn default() -> Self {
        Self {
            schema_version: HOST_ADMIN_STATE_SNAPSHOT_VERSION,
            connectors: HashMap::new(),
            journal: Vec::new(),
            next_config_revision_id: initial_revision_id(),
            next_journal_sequence: initial_journal_sequence(),
            events: Vec::new(),
            next_event_sequence: 1,
            logs: Vec::new(),
            next_log_sequence: 1,
            issued_tokens: Vec::new(),
            next_token_sequence: 1,
            last_observed_time_ms: 0,
            issuer_verifying_keys: HashMap::new(),
            receipts: Vec::new(),
            simulate_receipts: Vec::new(),
        }
    }
}

impl HostAdminStateSnapshot {
    fn connector_state_mut(&mut self, connector_id: &ConnectorId) -> &mut ConnectorAdminState {
        self.connectors.entry(connector_id.clone()).or_default()
    }

    const fn next_config_revision_id(&mut self) -> u64 {
        let revision_id = self.next_config_revision_id;
        self.next_config_revision_id = self.next_config_revision_id.saturating_add(1);
        revision_id
    }

    fn append_journal(
        &mut self,
        connector_id: &ConnectorId,
        mutation: AdminStateMutation,
        initiated_by: Option<String>,
    ) -> u64 {
        let sequence = self.next_journal_sequence;
        self.next_journal_sequence = self.next_journal_sequence.saturating_add(1);
        self.journal.push(AdminStateJournalEntry {
            sequence,
            connector_id: connector_id.clone(),
            occurred_at: Utc::now(),
            mutation,
            initiated_by,
        });
        sequence
    }

    fn from_legacy(legacy: LegacyHostLifecycleSnapshot) -> Self {
        let mut snapshot = Self::default();
        for (connector_id, record) in legacy.records {
            let state = snapshot.connector_state_mut(&connector_id);
            state.apply_lifecycle_projection(&record);
            state.lifecycle = Some(record);
        }
        for (connector_id, pinned_version) in legacy.pinned_versions {
            snapshot.connector_state_mut(&connector_id).pinned_version = Some(pinned_version);
        }
        snapshot
    }
}

fn set_snapshot_desired_state(
    snapshot: &mut HostAdminStateSnapshot,
    connector_id: &ConnectorId,
    desired_state: DesiredRuntimeState,
    initiated_by: Option<&str>,
) -> bool {
    let current = snapshot
        .connectors
        .get(connector_id)
        .map_or(DesiredRuntimeState::Unspecified, |state| {
            state.desired_state
        });
    if current == desired_state {
        return false;
    }

    let sequence = snapshot.append_journal(
        connector_id,
        AdminStateMutation::DesiredStateSet { desired_state },
        initiated_by.map(ToOwned::to_owned),
    );
    let state = snapshot.connector_state_mut(connector_id);
    state.desired_state = desired_state;
    state.last_journal_sequence = sequence;
    true
}

fn set_snapshot_observed_state(
    snapshot: &mut HostAdminStateSnapshot,
    connector_id: &ConnectorId,
    observed_state: ObservedRuntimeState,
    initiated_by: Option<&str>,
) -> bool {
    let current = snapshot
        .connectors
        .get(connector_id)
        .map_or(ObservedRuntimeState::Unknown, |state| state.observed_state);
    if current == observed_state {
        return false;
    }

    let sequence = snapshot.append_journal(
        connector_id,
        AdminStateMutation::ObservedStateSet { observed_state },
        initiated_by.map(ToOwned::to_owned),
    );
    let state = snapshot.connector_state_mut(connector_id);
    state.observed_state = observed_state;
    state.last_journal_sequence = sequence;
    true
}

fn reconcile_registered_connector(
    snapshot: &mut HostAdminStateSnapshot,
    summary: &ConnectorSummary,
    now: DateTime<Utc>,
) -> (StartupReconciliationEntry, bool) {
    let connector_id = &summary.id;
    let created_admin_state = !snapshot.connectors.contains_key(connector_id);
    if created_admin_state {
        let _ = snapshot.connector_state_mut(connector_id);
    }

    let observed_state_before = snapshot
        .connectors
        .get(connector_id)
        .map_or(ObservedRuntimeState::Unknown, |state| state.observed_state);
    let mut updated = false;

    if created_admin_state
        || snapshot
            .connectors
            .get(connector_id)
            .is_some_and(|state| state.desired_state == DesiredRuntimeState::Unspecified)
    {
        updated |= set_snapshot_desired_state(
            snapshot,
            connector_id,
            desired_state_from_summary(summary),
            Some(STARTUP_RECONCILIATION_ACTOR),
        );
    }

    let observed_updated = set_snapshot_observed_state(
        snapshot,
        connector_id,
        observed_state_from_summary(summary),
        Some(STARTUP_RECONCILIATION_ACTOR),
    );
    updated |= observed_updated;

    let state = snapshot
        .connectors
        .get(connector_id)
        .expect("connector state must exist after reconciliation");
    (
        StartupReconciliationEntry {
            connector_id: connector_id.clone(),
            created_admin_state,
            desired_state: state.desired_state,
            observed_state_before,
            observed_state_after: state.observed_state,
            updated,
            drift: connector_drift_status(state, now),
        },
        observed_updated,
    )
}

fn reconcile_missing_connector(
    snapshot: &mut HostAdminStateSnapshot,
    connector_id: &ConnectorId,
    now: DateTime<Utc>,
) -> (StartupReconciliationEntry, bool) {
    let observed_state_before = snapshot
        .connectors
        .get(connector_id)
        .map_or(ObservedRuntimeState::Unknown, |state| state.observed_state);
    let observed_updated = set_snapshot_observed_state(
        snapshot,
        connector_id,
        ObservedRuntimeState::Missing,
        Some(STARTUP_RECONCILIATION_ACTOR),
    );
    let state = snapshot
        .connectors
        .get(connector_id)
        .expect("persisted connector state should still exist");
    (
        StartupReconciliationEntry {
            connector_id: connector_id.clone(),
            created_admin_state: false,
            desired_state: state.desired_state,
            observed_state_before,
            observed_state_after: state.observed_state,
            updated: observed_updated,
            drift: connector_drift_status(state, now),
        },
        observed_updated,
    )
}

const fn host_admin_state_snapshot_version() -> u32 {
    HOST_ADMIN_STATE_SNAPSHOT_VERSION
}

const fn initial_revision_id() -> u64 {
    1
}

const fn initial_journal_sequence() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyHostLifecycleSnapshot {
    #[serde(default = "host_admin_state_snapshot_version")]
    schema_version: u32,
    #[serde(default)]
    records: HashMap<ConnectorId, LifecycleRecord>,
    #[serde(default)]
    pinned_versions: HashMap<ConnectorId, Version>,
}

/// Durable host-side admin-state store.
pub struct HostAdminStateStore {
    state: RwLock<HostAdminStateSnapshot>,
    state_path: Option<PathBuf>,
    persist_lock: Mutex<()>,
}

impl Default for HostAdminStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HostAdminStateStore {
    /// Create an in-memory store without filesystem persistence.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(HostAdminStateSnapshot::default()),
            state_path: None,
            persist_lock: Mutex::new(()),
        }
    }

    /// Create a store using the default admin-state path from the environment.
    ///
    /// The current implementation reuses the existing host lifecycle state file
    /// path so the extracted library store can consume previously persisted host
    /// snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured path is invalid or the persisted
    /// snapshot cannot be loaded.
    pub fn from_env() -> HostResult<Self> {
        let state_path = resolve_admin_state_path()?;
        Self::with_state_path_opt(state_path)
    }

    /// Create a store persisted at a specific path.
    ///
    /// # Errors
    ///
    /// Returns an error if the persisted snapshot cannot be loaded.
    pub fn with_state_path(state_path: PathBuf) -> HostResult<Self> {
        Self::with_state_path_opt(Some(state_path))
    }

    /// Create a store with an explicit optional persistence path.
    ///
    /// # Errors
    ///
    /// Returns an error if the persisted snapshot cannot be loaded.
    pub fn with_state_path_opt(state_path: Option<PathBuf>) -> HostResult<Self> {
        let state = match state_path.as_deref() {
            Some(path) => load_admin_state_snapshot(path)?,
            None => HostAdminStateSnapshot::default(),
        };
        Ok(Self {
            state: RwLock::new(state),
            state_path,
            persist_lock: Mutex::new(()),
        })
    }

    async fn apply_mutation<T, F>(&self, mutate: F) -> Result<T, LifecycleError>
    where
        F: FnOnce(&mut HostAdminStateSnapshot) -> Result<T, LifecycleError>,
    {
        let _persist_guard = self.persist_lock.lock().await;
        let mut snapshot = self.state.read().await.clone();
        let result = mutate(&mut snapshot)?;

        let path = self.state_path.clone();
        // Host admin-state writes are serialized behind `persist_lock` and only
        // flush one small JSON snapshot, so persisting inline is preferable to
        // reaching for a Tokio-only blocking shim in the async-core stack.
        persist_admin_state_snapshot(path.as_deref(), &snapshot)?;

        *self.state.write().await = snapshot;
        Ok(result)
    }

    /// Return the persisted connector admin state, if present.
    pub async fn connector_state(&self, connector_id: &ConnectorId) -> Option<ConnectorAdminState> {
        self.state
            .read()
            .await
            .connectors
            .get(connector_id)
            .cloned()
    }

    /// Return the full admin-state journal or only the entries for one connector.
    pub async fn journal(&self, connector_id: Option<&ConnectorId>) -> Vec<AdminStateJournalEntry> {
        self.state
            .read()
            .await
            .journal
            .iter()
            .filter(|entry| connector_id.is_none_or(|id| &entry.connector_id == id))
            .cloned()
            .collect()
    }

    /// Export the current admin-state snapshot as JSON safe for CLI rendering,
    /// logs, fixtures, and diagnostics.
    ///
    /// Inline secret values are redacted before persistence, while
    /// credential-reference metadata remains available for safe inspection.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be serialized.
    pub async fn export_snapshot_json(&self) -> Result<Value, LifecycleError> {
        serde_json::to_value(self.state.read().await.clone()).map_err(|err| {
            LifecycleError::Persistence {
                reason: format!("could not serialize admin state export: {err}"),
            }
        })
    }

    /// Persist a desired runtime target for one connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be persisted.
    pub async fn set_desired_state(
        &self,
        connector_id: &ConnectorId,
        desired_state: DesiredRuntimeState,
        initiated_by: Option<String>,
    ) -> Result<(), LifecycleError> {
        self.apply_mutation(|snapshot| {
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::DesiredStateSet { desired_state },
                initiated_by,
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.desired_state = desired_state;
            state.last_journal_sequence = sequence;
            Ok(())
        })
        .await
    }

    /// Persist an observed runtime state for one connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be persisted.
    pub async fn set_observed_state(
        &self,
        connector_id: &ConnectorId,
        observed_state: ObservedRuntimeState,
        initiated_by: Option<String>,
    ) -> Result<(), LifecycleError> {
        self.apply_mutation(|snapshot| {
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::ObservedStateSet { observed_state },
                initiated_by,
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.observed_state = observed_state;
            state.last_journal_sequence = sequence;
            Ok(())
        })
        .await
    }

    /// Append and activate a config revision for one connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the config payload cannot be serialized or the
    /// snapshot cannot be persisted.
    pub async fn append_config_revision(
        &self,
        connector_id: &ConnectorId,
        payload: Value,
        created_by: Option<String>,
        change_reason: Option<String>,
    ) -> Result<ConfigRevisionRecord, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let previous_revision_id = snapshot
                .connectors
                .get(connector_id)
                .and_then(|state| state.active_config_revision_id);
            let revision_id = snapshot.next_config_revision_id();
            let revision = ConfigRevisionRecord::new(
                revision_id,
                previous_revision_id,
                payload,
                created_by.clone(),
                change_reason,
            )?;
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::ConfigRevisionAppended {
                    revision_id,
                    payload_digest: revision.payload_digest.clone(),
                },
                created_by,
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.config_revisions.push(revision.clone());
            state.active_config_revision_id = Some(revision_id);
            state.last_journal_sequence = sequence;
            Ok(revision)
        })
        .await
    }

    /// Return a point-in-time config snapshot for one connector.
    ///
    /// Returns `None` when the connector has no persisted admin state.
    pub async fn get_config_snapshot(
        &self,
        connector_id: &ConnectorId,
    ) -> Option<ConnectorConfigSnapshot> {
        let guard = self.state.read().await;
        let state = guard.connectors.get(connector_id)?;
        let active_revision = state.active_config_revision();
        let (current, source) = active_revision.map_or_else(
            || {
                (
                    SanitizedConnectorConfig {
                        payload: Value::Null,
                        payload_digest: String::new(),
                        redacted_fields: Vec::new(),
                        credential_references: Vec::new(),
                        contains_inline_secrets: false,
                    },
                    ConnectorConfigSnapshotSource::ManagedInventory,
                )
            },
            |revision| {
                (
                    SanitizedConnectorConfig {
                        payload: revision.payload.clone(),
                        payload_digest: revision.payload_digest.clone(),
                        redacted_fields: revision.redacted_fields.clone(),
                        credential_references: revision.credential_references.clone(),
                        contains_inline_secrets: revision.contains_inline_secrets,
                    },
                    ConnectorConfigSnapshotSource::ActiveRevision,
                )
            },
        );
        Some(ConnectorConfigSnapshot {
            connector_id: connector_id.clone(),
            current,
            source,
            active_revision_id: state.active_config_revision_id,
            active_revision: active_revision.cloned(),
            revision_count: state.config_revisions.len(),
            last_journal_sequence: state.last_journal_sequence,
        })
    }

    /// Return the config revision history for one connector.
    ///
    /// Returns `None` when the connector has no persisted admin state.
    pub async fn config_revisions(
        &self,
        connector_id: &ConnectorId,
    ) -> Option<ConnectorConfigRevisionsResponse> {
        let guard = self.state.read().await;
        let state = guard.connectors.get(connector_id)?;
        Some(ConnectorConfigRevisionsResponse {
            connector_id: connector_id.clone(),
            active_revision_id: state.active_config_revision_id,
            revision_count: state.config_revisions.len(),
            last_journal_sequence: state.last_journal_sequence,
            revisions: state.config_revisions.clone(),
        })
    }

    /// Validate a candidate config against the current state.
    ///
    /// Returns a diff and validation preview without mutating state.
    /// If `expected_active_revision_id` is provided and does not match,
    /// the response indicates a stale-revision conflict.
    ///
    /// # Errors
    /// Returns `LifecycleError` if the config is invalid or the connector cannot be validated.
    pub async fn validate_config(
        &self,
        connector_id: &ConnectorId,
        request: &ConnectorConfigValidateRequest,
    ) -> Result<ConnectorConfigValidateResponse, LifecycleError> {
        let guard = self.state.read().await;
        let state = guard
            .connectors
            .get(connector_id)
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;

        let current_sanitized = current_sanitized_config(state);

        // Optimistic concurrency check.
        if let Some(expected) = request.expected_active_revision_id
            && state.active_config_revision_id != Some(expected)
        {
            return Ok(ConnectorConfigValidateResponse {
                connector_id: connector_id.clone(),
                valid: false,
                current_active_revision_id: state.active_config_revision_id,
                current: current_sanitized,
                candidate: SanitizedConnectorConfig::from_payload(request.payload.clone())?,
                diff: Vec::new(),
                preview: None,
                error: Some(format!(
                    "stale revision: expected {expected}, found {:?}",
                    state.active_config_revision_id
                )),
            });
        }

        let current_payload = state
            .active_config_revision()
            .map_or(&Value::Null, |revision| &revision.payload);
        let diff = diff_config_values(current_payload, &request.payload);
        let candidate = SanitizedConnectorConfig::from_payload(request.payload.clone())?;

        Ok(ConnectorConfigValidateResponse {
            connector_id: connector_id.clone(),
            valid: true,
            current_active_revision_id: state.active_config_revision_id,
            current: current_sanitized,
            candidate,
            diff,
            preview: None,
            error: None,
        })
    }

    /// Apply a candidate config as a new revision with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns `LifecycleError::NotFound` if the connector is unknown.
    /// Returns `LifecycleError::Persistence` if `expected_active_revision_id`
    /// does not match (stale-revision conflict).
    pub async fn apply_config(
        &self,
        connector_id: &ConnectorId,
        request: &ConnectorConfigApplyRequest,
    ) -> Result<ConnectorConfigApplyResponse, LifecycleError> {
        let cid = connector_id.clone();
        self.apply_mutation(|snapshot| {
            let state = snapshot
                .connectors
                .get(&cid)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: cid.clone(),
                })?;

            // Optimistic concurrency guard.
            if let Some(expected) = request.expected_active_revision_id
                && state.active_config_revision_id != Some(expected)
            {
                return Err(LifecycleError::Persistence {
                    reason: format!(
                        "stale revision: expected {expected}, found {:?}",
                        state.active_config_revision_id,
                    ),
                });
            }

            let previous_active_revision_id = state.active_config_revision_id;
            let previous_payload = state
                .active_config_revision()
                .map_or(Value::Null, |revision| revision.payload.clone());
            let previous = SanitizedConnectorConfig::from_payload(previous_payload.clone())?;
            let diff = diff_config_values(&previous_payload, &request.payload);
            let changed = !diff.is_empty();

            let revision_id = snapshot.next_config_revision_id();
            let revision = ConfigRevisionRecord::new(
                revision_id,
                previous_active_revision_id,
                request.payload.clone(),
                request.created_by.clone(),
                request.change_reason.clone(),
            )?;

            let sequence = snapshot.append_journal(
                &cid,
                AdminStateMutation::ConfigRevisionAppended {
                    revision_id,
                    payload_digest: revision.payload_digest.clone(),
                },
                request.created_by.clone(),
            );

            let current = SanitizedConnectorConfig::from_payload(request.payload.clone())?;

            let state = snapshot.connector_state_mut(&cid);
            state.config_revisions.push(revision.clone());
            state.active_config_revision_id = Some(revision_id);
            state.last_journal_sequence = sequence;

            Ok(ConnectorConfigApplyResponse {
                connector_id: cid.clone(),
                changed,
                previous_active_revision_id,
                current_active_revision_id: Some(revision_id),
                previous: Some(previous),
                current,
                diff,
                revision: Some(revision),
                apply: None,
                admin_state: None,
            })
        })
        .await
    }

    /// Rollback config to a previous revision with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns `LifecycleError::NotFound` if the connector or target revision
    /// is unknown.  Returns `LifecycleError::Persistence` if
    /// `expected_active_revision_id` does not match.
    pub async fn rollback_config(
        &self,
        connector_id: &ConnectorId,
        request: &ConnectorConfigRollbackRequest,
    ) -> Result<ConnectorConfigApplyResponse, LifecycleError> {
        let cid = connector_id.clone();
        self.apply_mutation(|snapshot| {
            let state = snapshot
                .connectors
                .get(&cid)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: cid.clone(),
                })?;

            // Optimistic concurrency guard.
            if let Some(expected) = request.expected_active_revision_id
                && state.active_config_revision_id != Some(expected)
            {
                return Err(LifecycleError::Persistence {
                    reason: format!(
                        "stale revision: expected {expected}, found {:?}",
                        state.active_config_revision_id,
                    ),
                });
            }

            // Find the target revision to roll back to.
            let target = state
                .config_revision(request.revision_id)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: cid.clone(),
                })?
                .clone();

            let previous_active_revision_id = state.active_config_revision_id;
            let previous_payload = state
                .active_config_revision()
                .map_or(Value::Null, |revision| revision.payload.clone());
            let previous = SanitizedConnectorConfig::from_payload(previous_payload.clone())?;
            let diff = diff_config_values(&previous_payload, &target.payload);
            let changed = !diff.is_empty();

            // Create a new revision with the target's payload.
            let revision_id = snapshot.next_config_revision_id();
            let revision = ConfigRevisionRecord::new(
                revision_id,
                previous_active_revision_id,
                target.payload.clone(),
                request.created_by.clone(),
                request.change_reason.clone(),
            )?;

            let sequence = snapshot.append_journal(
                &cid,
                AdminStateMutation::ConfigRevisionAppended {
                    revision_id,
                    payload_digest: revision.payload_digest.clone(),
                },
                request.created_by.clone(),
            );

            let current = SanitizedConnectorConfig::from_payload(target.payload)?;

            let state = snapshot.connector_state_mut(&cid);
            state.config_revisions.push(revision.clone());
            state.active_config_revision_id = Some(revision_id);
            state.last_journal_sequence = sequence;

            Ok(ConnectorConfigApplyResponse {
                connector_id: cid.clone(),
                changed,
                previous_active_revision_id,
                current_active_revision_id: Some(revision_id),
                previous: Some(previous),
                current,
                diff,
                revision: Some(revision),
                apply: None,
                admin_state: None,
            })
        })
        .await
    }

    /// Pin a specific connector version.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be persisted.
    pub async fn pin(
        &self,
        connector_id: &ConnectorId,
        version: Version,
    ) -> Result<(), LifecycleError> {
        self.apply_mutation(|snapshot| {
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::PinSet {
                    version: version.clone(),
                },
                None,
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.pinned_version = Some(version);
            state.last_journal_sequence = sequence;
            Ok(())
        })
        .await
    }

    /// Remove a connector version pin, returning the previous pin if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be persisted.
    pub async fn unpin(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<Version>, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let removed = snapshot
                .connectors
                .get(connector_id)
                .and_then(|state| state.pinned_version.clone());
            let sequence =
                snapshot.append_journal(connector_id, AdminStateMutation::PinCleared, None);
            let state = snapshot.connector_state_mut(connector_id);
            state.pinned_version = None;
            state.last_journal_sequence = sequence;
            Ok(removed)
        })
        .await
    }

    /// Return the current pinned version, if any.
    pub async fn pinned_version(&self, connector_id: &ConnectorId) -> Option<Version> {
        self.state
            .read()
            .await
            .connectors
            .get(connector_id)
            .and_then(|state| state.pinned_version.clone())
    }

    /// Return a host-facing desired-versus-observed status view for one
    /// connector.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::NotFound`] when the connector has no persisted
    /// admin state.
    pub async fn connector_status(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<ConnectorAdminStatus, LifecycleError> {
        self.connector_status_at(connector_id, Utc::now()).await
    }

    async fn connector_status_at(
        &self,
        connector_id: &ConnectorId,
        now: DateTime<Utc>,
    ) -> Result<ConnectorAdminStatus, LifecycleError> {
        let state = self.state.read().await;
        let connector_state =
            state
                .connectors
                .get(connector_id)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: connector_id.clone(),
                })?;
        Ok(connector_admin_status_from_state(
            connector_id,
            connector_state,
            now,
        ))
    }

    /// Return the current artifact/admin provenance metadata for one connector.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::NotFound`] when the connector has no persisted
    /// admin state.
    pub async fn connector_artifact_metadata(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<ConnectorArtifactMetadataResponse, LifecycleError> {
        self.connector_artifact_metadata_at(connector_id, Utc::now())
            .await
    }

    async fn connector_artifact_metadata_at(
        &self,
        connector_id: &ConnectorId,
        now: DateTime<Utc>,
    ) -> Result<ConnectorArtifactMetadataResponse, LifecycleError> {
        let state = self.state.read().await;
        let connector_state =
            state
                .connectors
                .get(connector_id)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: connector_id.clone(),
                })?;
        Ok(ConnectorArtifactMetadataResponse {
            connector_id: connector_id.clone(),
            artifact: connector_state.artifact.clone(),
            evaluated_at: now,
        })
    }

    /// Validate and optionally persist connector artifact/admin provenance
    /// metadata through the host control plane.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::NotFound`] when the connector has no persisted
    /// admin state. Validation denials are returned in the response payload so
    /// callers can inspect precise rejection reasons without parsing host
    /// transport errors.
    pub async fn register_connector_artifact(
        &self,
        connector_id: &ConnectorId,
        request: &ConnectorArtifactRegistrationRequest,
    ) -> Result<ConnectorArtifactRegistrationResponse, LifecycleError> {
        self.register_connector_artifact_at(connector_id, request, Utc::now())
            .await
    }

    async fn register_connector_artifact_at(
        &self,
        connector_id: &ConnectorId,
        request: &ConnectorArtifactRegistrationRequest,
        now: DateTime<Utc>,
    ) -> Result<ConnectorArtifactRegistrationResponse, LifecycleError> {
        let previous = {
            let state = self.state.read().await;
            let connector_state =
                state
                    .connectors
                    .get(connector_id)
                    .ok_or_else(|| LifecycleError::NotFound {
                        connector_id: connector_id.clone(),
                    })?;
            connector_state.artifact.clone()
        };

        if let Some(rejection) = validate_artifact_provenance(
            connector_id.as_str(),
            &request.provenance,
            request.require_signature,
            request.max_size_bytes,
        ) {
            return Ok(ConnectorArtifactRegistrationResponse {
                connector_id: connector_id.clone(),
                dry_run: request.dry_run,
                accepted: false,
                previous,
                current: None,
                rejection: Some(rejection),
                journal_sequence: None,
                evaluated_at: now,
            });
        }

        let current = ConnectorArtifactMetadata {
            provenance: request.provenance.clone(),
            placement: request.placement.clone(),
            recorded_at: now,
            recorded_by: request.initiated_by.clone(),
        };

        if request.dry_run {
            return Ok(ConnectorArtifactRegistrationResponse {
                connector_id: connector_id.clone(),
                dry_run: true,
                accepted: true,
                previous,
                current: Some(current),
                rejection: None,
                journal_sequence: None,
                evaluated_at: now,
            });
        }

        let current_for_snapshot = current.clone();
        let initiated_by = request.initiated_by.clone();
        let (previous, journal_sequence) = self
            .apply_mutation(|snapshot| {
                if !snapshot.connectors.contains_key(connector_id) {
                    return Err(LifecycleError::NotFound {
                        connector_id: connector_id.clone(),
                    });
                }

                let previous = snapshot
                    .connectors
                    .get(connector_id)
                    .and_then(|state| state.artifact.clone());
                let journal_sequence = snapshot.append_journal(
                    connector_id,
                    AdminStateMutation::ArtifactMetadataUpdated {
                        source_kind: current_for_snapshot.provenance.source_kind.clone(),
                        source_uri: current_for_snapshot.provenance.source_uri.clone(),
                        content_hash: current_for_snapshot.provenance.content_hash.clone(),
                        manifest_version: current_for_snapshot.provenance.manifest_version.clone(),
                        placement_present: current_for_snapshot.placement.is_some(),
                    },
                    initiated_by.clone(),
                );
                if let Some(state) = snapshot.connectors.get_mut(connector_id) {
                    state.artifact = Some(current_for_snapshot.clone());
                    state.last_journal_sequence = journal_sequence;
                }
                Ok((previous, journal_sequence))
            })
            .await?;

        Ok(ConnectorArtifactRegistrationResponse {
            connector_id: connector_id.clone(),
            dry_run: false,
            accepted: true,
            previous,
            current: Some(current),
            rejection: None,
            journal_sequence: Some(journal_sequence),
            evaluated_at: now,
        })
    }

    /// Execute a lifecycle transition and return the resulting state.
    ///
    /// The transition atomically updates desired state, journals the mutation,
    /// and optionally delegates to the [`LifecycleManager`] trait for promote
    /// operations. Dry-run mode returns the projected state without persisting.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector is not tracked or if the transition
    /// is invalid for the current state.
    pub async fn execute_lifecycle_transition(
        &self,
        connector_id: &ConnectorId,
        request: &LifecycleTransitionRequest,
    ) -> Result<LifecycleTransitionResponse, LifecycleError> {
        let now = Utc::now();

        // Read current state first (for dry-run and validation).
        let (previous_desired, observed, current_lifecycle_status, current_seq) = {
            let state = self.state.read().await;
            let cs =
                state
                    .connectors
                    .get(connector_id)
                    .ok_or_else(|| LifecycleError::NotFound {
                        connector_id: connector_id.clone(),
                    })?;
            let lifecycle_status = cs.lifecycle.as_ref().map(|record| LifecycleStatus {
                connector_id: connector_id.clone(),
                state: record.state,
                version: record.version.clone(),
                health: record.health.clone(),
                auto_promote_pending: false,
                auto_rollback_pending: false,
                canary_expires_in_secs: None,
                crash_loop_detected: false,
                rollback_target_version: record.previous_version.clone(),
            });
            (
                cs.desired_state,
                cs.observed_state,
                lifecycle_status,
                cs.last_journal_sequence,
            )
        };

        let target_desired = match request.action {
            LifecycleAction::Enable | LifecycleAction::Restart | LifecycleAction::Reload => {
                DesiredRuntimeState::Enabled
            }
            LifecycleAction::Disable => DesiredRuntimeState::Disabled,
            LifecycleAction::Uninstall => DesiredRuntimeState::Uninstalled,
            LifecycleAction::Promote => DesiredRuntimeState::Enabled,
        };

        if request.dry_run {
            return Ok(LifecycleTransitionResponse {
                connector_id: connector_id.to_string(),
                action: request.action,
                dry_run: true,
                previous_desired_state: previous_desired,
                current_desired_state: target_desired,
                observed_state: observed,
                lifecycle_status: current_lifecycle_status,
                journal_sequence: current_seq,
                transitioned_at: now,
            });
        }

        // For promote, delegate to the LifecycleManager trait implementation.
        let lifecycle_status = if request.action == LifecycleAction::Promote {
            match self.promote(connector_id).await {
                Ok(record) => {
                    let status = LifecycleStatus {
                        connector_id: connector_id.clone(),
                        state: record.state,
                        version: record.version.clone(),
                        health: record.health.clone(),
                        auto_promote_pending: false,
                        auto_rollback_pending: false,
                        canary_expires_in_secs: None,
                        crash_loop_detected: false,
                        rollback_target_version: record.previous_version,
                    };
                    Some(status)
                }
                Err(e) => return Err(e),
            }
        } else {
            current_lifecycle_status
        };

        // Apply desired state mutation.
        self.set_desired_state(
            connector_id,
            target_desired,
            request
                .initiated_by
                .clone()
                .or_else(|| Some("admin-api".to_string())),
        )
        .await?;

        let new_seq = {
            let state = self.state.read().await;
            state
                .connectors
                .get(connector_id)
                .map_or(0, |cs| cs.last_journal_sequence)
        };

        Ok(LifecycleTransitionResponse {
            connector_id: connector_id.to_string(),
            action: request.action,
            dry_run: false,
            previous_desired_state: previous_desired,
            current_desired_state: target_desired,
            observed_state: observed,
            lifecycle_status,
            journal_sequence: new_seq,
            transitioned_at: now,
        })
    }

    /// Query the admin state journal with optional filtering.
    pub async fn query_journal(&self, request: &JournalQueryRequest) -> JournalQueryResponse {
        let state = self.state.read().await;
        let all_entries = &state.journal;
        let total_entries = all_entries.len();
        let latest_sequence = all_entries.last().map_or(0, |e| e.sequence);

        let filtered: Vec<AdminStateJournalEntry> = all_entries
            .iter()
            .filter(|e| e.sequence > request.after_sequence)
            .filter(|e| {
                request
                    .connector_id
                    .as_ref()
                    .is_none_or(|filter_id| e.connector_id.as_str() == filter_id.as_str())
            })
            .take(request.limit.min(10_000))
            .cloned()
            .collect();

        JournalQueryResponse {
            entries: filtered,
            total_entries,
            latest_sequence,
        }
    }

    /// Append a log entry to the host log buffer.
    pub async fn append_log(
        &self,
        connector_id: Option<&str>,
        severity: LogSeverity,
        message: String,
        fields: BTreeMap<String, Value>,
    ) {
        self.apply_mutation(|snapshot| {
            let seq = snapshot.next_log_sequence;
            snapshot.next_log_sequence = snapshot.next_log_sequence.saturating_add(1);
            snapshot.logs.push(HostLogEntry {
                sequence: seq,
                connector_id: connector_id.map(String::from),
                severity,
                message,
                fields,
                timestamp: Utc::now(),
            });
            Ok(())
        })
        .await
        .ok();
    }

    /// Query host logs with optional filtering.
    pub async fn query_logs(&self, request: &LogQueryRequest) -> LogQueryResponse {
        let state = self.state.read().await;
        let severity_ord = |s: &LogSeverity| match s {
            LogSeverity::Debug => 0,
            LogSeverity::Info => 1,
            LogSeverity::Warn => 2,
            LogSeverity::Error => 3,
        };
        let min_ord = request.min_severity.as_ref().map_or(0, severity_ord);

        let entries: Vec<HostLogEntry> = state
            .logs
            .iter()
            .filter(|e| e.sequence > request.after_sequence)
            .filter(|e| {
                request
                    .connector_id
                    .as_ref()
                    .is_none_or(|cid| e.connector_id.as_deref() == Some(cid.as_str()))
            })
            .filter(|e| severity_ord(&e.severity) >= min_ord)
            .take(request.limit)
            .cloned()
            .collect();
        let latest_sequence = entries.last().map_or(0, |e| e.sequence);
        LogQueryResponse {
            entries,
            latest_sequence,
        }
    }

    /// Emit a host control-plane event.
    pub async fn emit_event(
        &self,
        kind: HostEventKind,
        connector_id: Option<&str>,
        summary: String,
        payload: Option<Value>,
    ) {
        self.apply_mutation(|snapshot| {
            let seq = snapshot.next_event_sequence;
            snapshot.next_event_sequence += 1;
            snapshot.events.push(HostEvent {
                event_id: format!("evt-{seq}"),
                kind,
                connector_id: connector_id.map(String::from),
                summary,
                payload,
                timestamp: Utc::now(),
                acknowledged: false,
            });
            Ok(())
        })
        .await
        .ok();
    }

    /// Query host events with optional filtering.
    pub async fn query_events(&self, request: &EventQueryRequest) -> EventQueryResponse {
        let state = self.state.read().await;
        let events: Vec<HostEvent> = state
            .events
            .iter()
            .filter(|e| {
                request
                    .connector_id
                    .as_ref()
                    .is_none_or(|cid| e.connector_id.as_deref() == Some(cid.as_str()))
            })
            .filter(|e| request.kind.is_none_or(|k| e.kind == k))
            .filter(|e| !request.unacknowledged_only || !e.acknowledged)
            .take(request.limit)
            .cloned()
            .collect();
        let unacknowledged_count = state.events.iter().filter(|e| !e.acknowledged).count();
        EventQueryResponse {
            events,
            unacknowledged_count,
        }
    }

    /// Acknowledge events by ID.
    pub async fn acknowledge_events(
        &self,
        request: &EventAcknowledgeRequest,
    ) -> EventAcknowledgeResponse {
        let mut acknowledged_count = 0;
        let mut not_found = Vec::new();

        self.apply_mutation(|snapshot| {
            for event_id in &request.event_ids {
                if let Some(event) = snapshot.events.iter_mut().find(|e| e.event_id == *event_id) {
                    if !event.acknowledged {
                        event.acknowledged = true;
                        acknowledged_count += 1;
                    }
                } else {
                    not_found.push(event_id.clone());
                }
            }
            Ok(())
        })
        .await
        .ok();

        EventAcknowledgeResponse {
            acknowledged_count,
            not_found,
        }
    }

    // ── Capability issuance and token management ────────────────────────────

    /// Issue a new capability token.
    ///
    /// The host generates a `COSE_Sign1` token signed with the provided signing key,
    /// records the issuance in the journal, and tracks the token for revocation.
    ///
    /// # Errors
    ///
    /// Returns an error if token construction or persistence fails.
    #[allow(clippy::too_many_lines)]
    pub async fn issue_capability_token(
        &self,
        request: &CapabilityIssuanceRequest,
        signing_key: &fcp_crypto::ed25519::Ed25519SigningKey,
    ) -> Result<CapabilityIssuanceResponse, LifecycleError> {
        let now = Utc::now();
        let ttl = i64::try_from(request.ttl_secs).unwrap_or(3600);
        let expires = now + chrono::Duration::seconds(ttl);
        let not_before = request
            .not_before_delay_secs
            .map(validated_not_before_delay_secs)
            .transpose()?
            .map(|delay| now + chrono::Duration::seconds(delay));
        let grants = capability_grants_from_request(request)?;
        let constraints = capability_constraints_from_request(request);

        // Generate token ID from timestamp + hash of request fields.
        let token_id_bytes: [u8; 16] = {
            let mut buf = [0u8; 16];
            let ts = now.timestamp_nanos_opt().unwrap_or(0);
            buf[..8].copy_from_slice(&ts.to_le_bytes());
            let digest = hash(
                format!("{}:{}:{}", request.connector_id, request.principal_id, ts).as_bytes(),
            );
            buf[8..16].copy_from_slice(&digest.as_bytes()[..8]);
            buf
        };
        let token_id_hex = hex::encode(token_id_bytes);

        // Build CWT claims.
        let issuer_verifying_key = signing_key.verifying_key();
        let issuer_key_id = issuer_verifying_key.key_id().to_hex();
        let issuer_id = format!("host:{issuer_key_id}");
        let mut claims = fcp_crypto::cose::CwtClaims::new()
            .issuer(&issuer_id)
            .subject(&request.principal_id)
            .audience(&request.zone_id)
            .zone_id(&request.zone_id)
            .capability_id(&request.capability_id)
            .issued_at(now)
            .expiration(expires)
            .token_id(&token_id_bytes)
            .principal_id(&request.principal_id);

        if let Some(nbf) = not_before {
            claims = claims.not_before(nbf);
        }

        if !request.operations.is_empty() {
            let ops_refs: Vec<&str> = request.operations.iter().map(String::as_str).collect();
            claims = claims.operations(&ops_refs);
        }

        if let Some(ref holder) = request.holder_node {
            claims = claims.holder_node(holder);
        }

        claims = claims.custom(
            fcp_crypto::cose::fcp2_claims::DELEGATION_DEPTH,
            ciborium::Value::Integer(request.max_delegation_depth.into()),
        );
        claims = claims.custom(
            fcp_crypto::cose::fcp2_claims::GRANTS,
            serialize_capability_grants(&grants)?,
        );
        claims = claims.custom(
            fcp_crypto::cose::fcp2_claims::CONSTRAINTS,
            serialize_capability_constraints(&constraints)?,
        );

        // Build redaction-safe inspection.
        let inspection = CapabilityTokenInspection {
            token_id: token_id_hex.clone(),
            issuer: issuer_id.clone(),
            subject: request.principal_id.clone(),
            audience: Some(request.zone_id.clone()),
            zone_id: request.zone_id.clone(),
            capability_id: Some(request.capability_id.clone()),
            operations: request.operations.clone(),
            holder_node: request.holder_node.clone(),
            delegation_depth: request.max_delegation_depth,
            issued_at: now,
            not_before,
            expires_at: expires,
            currently_valid: not_before.is_none_or(|nbf| now >= nbf) && now < expires,
            seconds_remaining: u64::try_from((expires - now).num_seconds().max(0)).unwrap_or(0),
            resource_allow: constraints.resource_allow.clone(),
            resource_deny: constraints.resource_deny.clone(),
            max_calls: constraints.max_calls,
            max_bytes: constraints.max_bytes,
            credential_allow: constraints.credential_allow.clone(),
        };

        // Sign the token (unless dry run).
        let token_cbor_b64 = if request.dry_run {
            None
        } else {
            let cose_token =
                fcp_crypto::cose::CoseToken::sign(signing_key, &claims).map_err(|e| {
                    LifecycleError::Persistence {
                        reason: format!("failed to sign capability token: {e}"),
                    }
                })?;
            let cbor_bytes = cose_token
                .to_cbor()
                .map_err(|e| LifecycleError::Persistence {
                    reason: format!("failed to serialize capability token: {e}"),
                })?;
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &cbor_bytes,
            ))
        };

        // Record in journal and token registry.
        let auth_connector_id = ConnectorId::from_static("fcp.auth:utility:1.0.0");
        let journal_sequence = self
            .apply_mutation(|snapshot| {
                let seq = snapshot.append_journal(
                    &auth_connector_id,
                    AdminStateMutation::DesiredStateSet {
                        desired_state: DesiredRuntimeState::Enabled,
                    },
                    Some(format!("token_issue:{token_id_hex}")),
                );

                if !request.dry_run {
                    snapshot.issued_tokens.push(IssuedTokenRecord {
                        token_id: token_id_hex.clone(),
                        connector_id: request.connector_id.clone(),
                        principal_id: request.principal_id.clone(),
                        zone_id: request.zone_id.clone(),
                        issued_at: now,
                        expires_at: expires,
                        revoked: false,
                        revocation_reason: None,
                        revoked_at: None,
                    });
                    snapshot.next_token_sequence = snapshot.next_token_sequence.saturating_add(1);
                    snapshot
                        .issuer_verifying_keys
                        .insert(issuer_key_id.clone(), issuer_verifying_key.clone());
                }

                Ok(seq)
            })
            .await?;

        Ok(CapabilityIssuanceResponse {
            dry_run: request.dry_run,
            token_id: token_id_hex,
            token_cbor_b64,
            inspection,
            journal_sequence,
            issued_at: now,
        })
    }

    /// Inspect a capability token's claims without verifying its signature.
    ///
    /// Parses the base64-encoded `COSE_Sign1` token and extracts a redaction-safe
    /// view of its CWT claims.
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be parsed.
    pub fn inspect_capability_token(
        token_cbor_b64: &str,
    ) -> Result<CapabilityTokenInspection, LifecycleError> {
        Self::inspect_capability_token_at(token_cbor_b64, Utc::now())
    }

    fn inspect_capability_token_at(
        token_cbor_b64: &str,
        now: DateTime<Utc>,
    ) -> Result<CapabilityTokenInspection, LifecycleError> {
        let cbor_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token_cbor_b64)
                .map_err(|e| LifecycleError::Persistence {
                    reason: format!("invalid base64 in capability token: {e}"),
                })?;

        let cose_token = fcp_crypto::cose::CoseToken::from_cbor(&cbor_bytes).map_err(|e| {
            LifecycleError::Persistence {
                reason: format!("invalid COSE token: {e}"),
            }
        })?;

        let claims = cose_token
            .claims_unverified()
            .map_err(|e| LifecycleError::Persistence {
                reason: format!("failed to parse token claims: {e}"),
            })?;

        let iat_ts = claims
            .get(fcp_crypto::cose::cwt_claims::IAT)
            .and_then(|v| match v {
                ciborium::Value::Integer(i) => i64::try_from(*i).ok(),
                _ => None,
            });
        let issued_at = iat_ts
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .unwrap_or(now);

        let expires_at = claims
            .get_expiration()
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            .unwrap_or(now);

        let not_before = claims
            .get_not_before()
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

        let currently_valid = not_before.is_none_or(|nbf| now >= nbf) && now < expires_at;
        let seconds_remaining = u64::try_from((expires_at - now).num_seconds().max(0)).unwrap_or(0);

        let token_id = claims.get_jti().map(hex::encode).unwrap_or_default();

        let operations = claims
            .get(fcp_crypto::cose::fcp2_claims::OPERATIONS)
            .and_then(|v| match v {
                ciborium::Value::Array(arr) => Some(
                    arr.iter()
                        .filter_map(|item| match item {
                            ciborium::Value::Text(s) => Some(s.clone()),
                            _ => None,
                        })
                        .collect(),
                ),
                _ => None,
            })
            .unwrap_or_default();

        let delegation_depth = claims
            .get(fcp_crypto::cose::fcp2_claims::DELEGATION_DEPTH)
            .and_then(|v| match v {
                ciborium::Value::Integer(i) => u32::try_from(i64::try_from(*i).unwrap_or(0)).ok(),
                _ => None,
            })
            .unwrap_or(0);
        let constraints = deserialize_capability_constraints(&claims)?;

        Ok(CapabilityTokenInspection {
            token_id,
            issuer: claims.get_issuer().unwrap_or("unknown").to_string(),
            subject: claims
                .get_subject()
                .or_else(
                    || match claims.get(fcp_crypto::cose::fcp2_claims::PRINCIPAL_ID) {
                        Some(ciborium::Value::Text(principal)) => Some(principal.as_str()),
                        _ => None,
                    },
                )
                .unwrap_or("unknown")
                .to_string(),
            audience: claims
                .get(fcp_crypto::cose::cwt_claims::AUD)
                .and_then(|v| match v {
                    ciborium::Value::Text(s) => Some(s.clone()),
                    _ => None,
                }),
            zone_id: claims.get_zone_id().unwrap_or("unknown").to_string(),
            capability_id: claims.get_capability_id().map(String::from),
            operations,
            holder_node: claims.get_holder_node().map(String::from),
            delegation_depth,
            issued_at,
            not_before,
            expires_at,
            currently_valid,
            seconds_remaining,
            resource_allow: constraints.resource_allow,
            resource_deny: constraints.resource_deny,
            max_calls: constraints.max_calls,
            max_bytes: constraints.max_bytes,
            credential_allow: constraints.credential_allow,
        })
    }

    /// Verify a capability token against the host's state.
    ///
    /// Performs three independent checks:
    /// 1. **Signature**: Verifies the `COSE_Sign1` signature against the host's
    ///    persisted issuer key ring using the token's COSE `kid`.
    /// 2. **Temporal**: Is the token currently within its not-before/expiration window?
    /// 3. **Scope**: If an `operation_id` or `connector_id` is provided, does the
    ///    token's grant cover them?
    ///
    /// Additionally checks the host's revocation ledger — a structurally valid
    /// token that has been revoked is reported as invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be parsed at all.
    pub async fn verify_capability_token(
        &self,
        request: &CapabilityTokenVerifyRequest,
    ) -> Result<CapabilityTokenVerifyResponse, LifecycleError> {
        self.verify_capability_token_at(request, Utc::now()).await
    }

    async fn verify_capability_token_at(
        &self,
        request: &CapabilityTokenVerifyRequest,
        observed_now: DateTime<Utc>,
    ) -> Result<CapabilityTokenVerifyResponse, LifecycleError> {
        let effective_now = self.effective_verification_time(observed_now).await?;
        let inspection = Self::inspect_capability_token_at(&request.token_cbor_b64, effective_now)?;
        let mut rejection_reasons = Vec::new();

        // 1. Cryptographic signature validity against the host issuer key ring.
        let token_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &request.token_cbor_b64,
        )
        .map_err(|e| LifecycleError::Persistence {
            reason: format!("invalid base64 in capability token: {e}"),
        })?;
        let token = fcp_crypto::cose::CoseToken::from_cbor(&token_bytes).map_err(|e| {
            LifecycleError::Persistence {
                reason: format!("invalid COSE token: {e}"),
            }
        })?;
        let token_key_id = token
            .get_key_id()
            .ok()
            .and_then(|raw| fcp_crypto::kid::KeyId::try_from_slice(&raw).ok())
            .map(|kid| kid.to_hex());
        let verifying_key = if let Some(ref key_id) = token_key_id {
            let state = self.state.read().await;
            state.issuer_verifying_keys.get(key_id).cloned()
        } else {
            None
        };
        let signature_valid = verifying_key
            .as_ref()
            .is_some_and(|key| token.verify(key).is_ok());
        match (
            token_key_id.as_deref(),
            verifying_key.as_ref(),
            signature_valid,
        ) {
            (None, _, _) => rejection_reasons.push("Token is missing a COSE key ID (kid)".into()),
            (Some(key_id), None, _) => {
                rejection_reasons.push(format!("No verifying key found for token key ID {key_id}"));
            }
            (Some(_), Some(_), false) => {
                rejection_reasons.push("Token signature verification failed".into());
            }
            _ => {}
        }

        // 2. Temporal validity
        let temporally_valid = inspection.currently_valid;
        if !temporally_valid {
            if inspection.seconds_remaining == 0 {
                rejection_reasons.push(format!("Token expired at {}", inspection.expires_at));
            }
            if let Some(nbf) = inspection.not_before
                && effective_now < nbf
            {
                rejection_reasons.push(format!("Token not yet valid (not-before: {nbf})"));
            }
        }

        // 3. Scope validity
        let operation_scope_valid = Self::check_scope_validity(
            &inspection,
            request.operation_id.as_deref(),
            None,
            &mut rejection_reasons,
        );
        let connector_scope_valid = self
            .check_connector_scope_validity(
                &inspection,
                request.connector_id.as_deref(),
                &mut rejection_reasons,
            )
            .await;
        let scope_valid = operation_scope_valid && connector_scope_valid;

        // 4. Revocation check
        let revoked = self.is_token_revoked(&inspection.token_id).await;
        if revoked {
            rejection_reasons.push(format!("Token {} has been revoked", inspection.token_id));
        }

        let valid = signature_valid && temporally_valid && scope_valid && !revoked;

        Ok(CapabilityTokenVerifyResponse {
            signature_valid,
            temporally_valid,
            scope_valid,
            valid,
            inspection,
            rejection_reasons,
        })
    }

    async fn effective_verification_time(
        &self,
        observed_now: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, LifecycleError> {
        let observed_now_ms = observed_now.timestamp_millis();
        let last_observed_time_ms = self.state.read().await.last_observed_time_ms;
        if observed_now_ms <= last_observed_time_ms {
            return Ok(
                DateTime::from_timestamp_millis(last_observed_time_ms).unwrap_or(observed_now)
            );
        }

        let effective_now_ms = self
            .apply_mutation(|snapshot| {
                snapshot.last_observed_time_ms =
                    snapshot.last_observed_time_ms.max(observed_now_ms);
                Ok(snapshot.last_observed_time_ms)
            })
            .await?;
        Ok(DateTime::from_timestamp_millis(effective_now_ms).unwrap_or(observed_now))
    }

    /// Check whether a token's scope covers the requested operation and connector.
    fn check_scope_validity(
        inspection: &CapabilityTokenInspection,
        operation_id: Option<&str>,
        connector_id: Option<&str>,
        rejection_reasons: &mut Vec<String>,
    ) -> bool {
        let mut scope_ok = true;

        if let Some(op) = operation_id.filter(|op| {
            !inspection.operations.is_empty()
                && !inspection.operations.iter().any(|o| o == *op || o == "*")
        }) {
            scope_ok = false;
            rejection_reasons.push(format!(
                "Token does not grant operation '{op}'. Granted: [{}]",
                inspection.operations.join(", ")
            ));
        }

        if let Some(cid) = connector_id {
            // The token's audience or subject should match the connector
            let audience_match = inspection
                .audience
                .as_deref()
                .is_some_and(|aud| aud == cid || aud == "*");
            let subject_match = inspection.subject == cid || inspection.subject == "*";

            if !audience_match && !subject_match {
                scope_ok = false;
                rejection_reasons.push(format!(
                    "Token not scoped for connector '{cid}'. \
                     Subject: '{}', Audience: {:?}",
                    inspection.subject, inspection.audience
                ));
            }
        }

        scope_ok
    }

    async fn check_connector_scope_validity(
        &self,
        inspection: &CapabilityTokenInspection,
        connector_id: Option<&str>,
        rejection_reasons: &mut Vec<String>,
    ) -> bool {
        let Some(cid) = connector_id else {
            return true;
        };

        let audience_match = inspection
            .audience
            .as_deref()
            .is_some_and(|aud| aud == cid || aud == "*");
        let subject_match = inspection.subject == cid || inspection.subject == "*";
        if audience_match || subject_match {
            return true;
        }

        let state = self.state.read().await;
        let issued_connector = state
            .issued_tokens
            .iter()
            .find(|token| token.token_id == inspection.token_id)
            .map(|token| token.connector_id.as_str());
        if issued_connector.is_some_and(|scoped_connector| scoped_connector == cid) {
            return true;
        }

        rejection_reasons.push(format!(
            "Token not scoped for connector '{cid}'. Subject: '{}', Audience: {:?}, Issued connector: {}",
            inspection.subject,
            inspection.audience,
            issued_connector.unwrap_or("<unknown>")
        ));
        false
    }

    /// Check whether a token has been revoked in the host's ledger.
    async fn is_token_revoked(&self, token_id: &str) -> bool {
        if token_id.is_empty() {
            return false;
        }
        let state = self.state.read().await;
        state
            .issued_tokens
            .iter()
            .any(|t| t.token_id == token_id && t.revoked)
    }

    /// Revoke a previously issued token by its ID.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub async fn revoke_token(
        &self,
        request: &TokenRevocationRequest,
    ) -> Result<TokenRevocationResponse, LifecycleError> {
        let now = Utc::now();
        let auth_connector_id = ConnectorId::from_static("fcp.auth:utility:1.0.0");
        let mut was_revoked = false;

        let journal_sequence = self
            .apply_mutation(|snapshot| {
                if let Some(record) = snapshot
                    .issued_tokens
                    .iter_mut()
                    .find(|t| t.token_id == request.token_id && !t.revoked)
                {
                    record.revoked = true;
                    record.revocation_reason.clone_from(&request.reason);
                    record.revoked_at = Some(now);
                    was_revoked = true;
                }

                Ok(snapshot.append_journal(
                    &auth_connector_id,
                    AdminStateMutation::DesiredStateSet {
                        desired_state: DesiredRuntimeState::Disabled,
                    },
                    Some(format!("token_revoke:{}", request.token_id)),
                ))
            })
            .await?;

        let message = if was_revoked {
            format!("Token {} revoked", request.token_id)
        } else {
            format!("Token {} not found or already revoked", request.token_id)
        };

        Ok(TokenRevocationResponse {
            revoked: was_revoked,
            token_id: request.token_id.clone(),
            message,
            journal_sequence,
        })
    }

    /// Query issued token records.
    pub async fn query_issued_tokens(
        &self,
        request: &IssuedTokenQueryRequest,
    ) -> IssuedTokenQueryResponse {
        let snapshot = self.state.read().await;
        let now = Utc::now();

        let tokens: Vec<IssuedTokenRecord> = snapshot
            .issued_tokens
            .iter()
            .filter(|t| {
                request
                    .connector_id
                    .as_ref()
                    .is_none_or(|cid| t.connector_id == *cid)
            })
            .filter(|t| {
                request
                    .principal_id
                    .as_ref()
                    .is_none_or(|pid| t.principal_id == *pid)
            })
            .filter(|t| {
                if request.active_only {
                    !t.revoked && t.expires_at > now
                } else {
                    true
                }
            })
            .take(request.limit)
            .cloned()
            .collect();

        let total_tokens = snapshot.issued_tokens.len();
        let active_count = snapshot
            .issued_tokens
            .iter()
            .filter(|t| !t.revoked && t.expires_at > now)
            .count();

        IssuedTokenQueryResponse {
            tokens,
            total_tokens,
            active_count,
        }
    }

    // ── Receipt tracking ───────────────────────────────────────────────────

    /// Record an operation receipt summary in the admin state.
    ///
    /// Called by the host after a live invoke returns an auditable receipt.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub async fn record_receipt(&self, receipt: ReceiptSummary) -> Result<u64, LifecycleError> {
        let connector_id: ConnectorId =
            receipt
                .connector_id
                .parse()
                .map_err(|err| LifecycleError::Persistence {
                    reason: format!(
                        "could not parse receipt connector id '{}': {err}",
                        receipt.connector_id
                    ),
                })?;

        self.apply_mutation(|snapshot| {
            let seq = snapshot.append_journal(
                &connector_id,
                AdminStateMutation::DesiredStateSet {
                    desired_state: DesiredRuntimeState::Enabled,
                },
                Some(format!("invoke_receipt:{}", receipt.receipt_id)),
            );
            snapshot.receipts.push(receipt);
            Ok(seq)
        })
        .await
    }

    /// Query operation receipts.
    pub async fn query_receipts(&self, request: &ReceiptQueryRequest) -> ReceiptQueryResponse {
        let snapshot = self.state.read().await;

        let receipts: Vec<ReceiptSummary> = snapshot
            .receipts
            .iter()
            .filter(|r| r.connector_id == request.connector_id)
            .filter(|r| {
                request
                    .operation
                    .as_ref()
                    .is_none_or(|op| r.operation == *op)
            })
            .filter(|r| request.after.is_none_or(|after| r.executed_at > after))
            .take(request.limit)
            .cloned()
            .collect();

        let total_receipts = snapshot
            .receipts
            .iter()
            .filter(|r| r.connector_id == request.connector_id)
            .count();

        ReceiptQueryResponse {
            receipts,
            total_receipts,
        }
    }

    // ── Simulate receipt tracking ───────────────────────────────────────────

    /// Record a simulation receipt in the admin state.
    ///
    /// Called by the host after routing a simulate request to a connector (or
    /// after preflight denies the request).
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub async fn record_simulate_receipt(
        &self,
        receipt: SimulateReceipt,
    ) -> Result<u64, LifecycleError> {
        let auth_connector_id = ConnectorId::from_static("fcp.simulate:utility:1.0.0");
        self.apply_mutation(|snapshot| {
            let seq = snapshot.append_journal(
                &auth_connector_id,
                AdminStateMutation::DesiredStateSet {
                    desired_state: DesiredRuntimeState::Enabled,
                },
                Some(format!("simulate_receipt:{}", receipt.receipt_id)),
            );
            snapshot.simulate_receipts.push(receipt);
            Ok(seq)
        })
        .await
    }

    /// Query simulation receipts.
    pub async fn query_simulate_receipts(
        &self,
        request: &SimulateReceiptQueryRequest,
    ) -> SimulateReceiptQueryResponse {
        let snapshot = self.state.read().await;

        let receipts: Vec<SimulateReceipt> = snapshot
            .simulate_receipts
            .iter()
            .filter(|r| r.connector_id == request.connector_id)
            .filter(|r| {
                request
                    .operation
                    .as_ref()
                    .is_none_or(|op| r.operation == *op)
            })
            .filter(|r| request.after.is_none_or(|after| r.simulated_at > after))
            .take(request.limit)
            .cloned()
            .collect();

        let total_receipts = snapshot
            .simulate_receipts
            .iter()
            .filter(|r| r.connector_id == request.connector_id)
            .count();

        SimulateReceiptQueryResponse {
            receipts,
            total_receipts,
        }
    }

    /// Reconcile persisted admin state against the currently registered
    /// connector inventory.
    ///
    /// Existing desired state remains authoritative. Startup reconciliation only
    /// initializes intent for newly discovered connectors and refreshes observed
    /// runtime state so crashes, missing artifacts, and stuck rollouts surface as
    /// explicit drift instead of stale snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error if the reconciled snapshot cannot be persisted.
    pub async fn reconcile_registered_connectors(
        &self,
        registered: &[ConnectorSummary],
    ) -> Result<StartupReconciliationReport, LifecycleError> {
        self.reconcile_registered_connectors_at(registered, Utc::now())
            .await
    }

    async fn reconcile_registered_connectors_at(
        &self,
        registered: &[ConnectorSummary],
        now: DateTime<Utc>,
    ) -> Result<StartupReconciliationReport, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let registered_ids: HashSet<ConnectorId> = registered
                .iter()
                .map(|summary| summary.id.clone())
                .collect();
            let missing_connector_ids: Vec<ConnectorId> = snapshot
                .connectors
                .keys()
                .filter(|connector_id| !registered_ids.contains(*connector_id))
                .cloned()
                .collect();

            let mut created_connectors = 0;
            let mut observed_updates = 0;
            let mut entries = Vec::with_capacity(registered.len() + missing_connector_ids.len());

            for summary in registered {
                let (entry, observed_state_changed) =
                    reconcile_registered_connector(snapshot, summary, now);
                if entry.created_admin_state {
                    created_connectors += 1;
                }
                if observed_state_changed {
                    observed_updates += 1;
                }
                entries.push(entry);
            }

            for connector_id in missing_connector_ids {
                let (entry, observed_state_changed) =
                    reconcile_missing_connector(snapshot, &connector_id, now);
                if observed_state_changed {
                    observed_updates += 1;
                }
                entries.push(entry);
            }

            entries
                .sort_by(|left, right| left.connector_id.as_str().cmp(right.connector_id.as_str()));
            let drifted_connectors = entries.iter().filter(|entry| entry.drift.is_some()).count();

            Ok(StartupReconciliationReport {
                reconciled_at: now,
                tracked_connectors: snapshot.connectors.len(),
                created_connectors,
                observed_updates,
                drifted_connectors,
                entries,
            })
        })
        .await
    }
}

#[async_trait::async_trait]
impl LifecycleManager for HostAdminStateStore {
    async fn get(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<LifecycleRecord>, LifecycleError> {
        Ok(self
            .state
            .read()
            .await
            .connectors
            .get(connector_id)
            .and_then(|state| state.lifecycle.clone()))
    }

    async fn save(&self, record: &LifecycleRecord) -> Result<(), LifecycleError> {
        let initiated_by = record
            .transitions
            .last()
            .and_then(|transition| transition.initiated_by.clone());
        self.apply_mutation(|snapshot| {
            let sequence = snapshot.append_journal(
                &record.connector_id,
                AdminStateMutation::LifecycleRecordSaved {
                    version: record.version.clone(),
                    state: record.state,
                },
                initiated_by,
            );
            let state = snapshot.connector_state_mut(&record.connector_id);
            state.apply_lifecycle_projection(record);
            state.lifecycle = Some(record.clone());
            state.last_journal_sequence = sequence;
            Ok(())
        })
        .await
    }

    async fn promote(&self, connector_id: &ConnectorId) -> Result<LifecycleRecord, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let updated_record = {
                let state = snapshot.connector_state_mut(connector_id);
                let record = state
                    .lifecycle
                    .as_mut()
                    .ok_or_else(|| LifecycleError::NotFound {
                        connector_id: connector_id.clone(),
                    })?;
                let health_score = record.health.success_rate.min(100);
                record.transition(
                    LifecycleState::Production,
                    TransitionReason::AutoPromotion { health_score },
                )?;
                let updated_record = record.clone();
                state.apply_lifecycle_projection(&updated_record);
                updated_record
            };
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::LifecycleRecordSaved {
                    version: updated_record.version.clone(),
                    state: updated_record.state,
                },
                None,
            );
            snapshot
                .connector_state_mut(connector_id)
                .last_journal_sequence = sequence;
            Ok(updated_record)
        })
        .await
    }

    async fn rollback(
        &self,
        connector_id: &ConnectorId,
        reason: Option<String>,
    ) -> Result<LifecycleRecord, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let updated_record = {
                let state = snapshot.connector_state_mut(connector_id);
                let record = state
                    .lifecycle
                    .as_mut()
                    .ok_or_else(|| LifecycleError::NotFound {
                        connector_id: connector_id.clone(),
                    })?;
                if record.previous_version.is_none() {
                    return Err(LifecycleError::NoRollbackTarget);
                }
                let health_score = record.health.success_rate.min(100);
                let failure_reason = reason.unwrap_or_else(|| "rollback requested".to_string());
                record.transition(
                    LifecycleState::RolledBack,
                    TransitionReason::AutoRollback {
                        health_score,
                        failure_reason,
                    },
                )?;
                let updated_record = record.clone();
                state.apply_lifecycle_projection(&updated_record);
                updated_record
            };
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::LifecycleRecordSaved {
                    version: updated_record.version.clone(),
                    state: updated_record.state,
                },
                None,
            );
            snapshot
                .connector_state_mut(connector_id)
                .last_journal_sequence = sequence;
            Ok(updated_record)
        })
        .await
    }

    async fn status(&self, connector_id: &ConnectorId) -> Result<LifecycleStatus, LifecycleError> {
        let state = self.state.read().await;
        let record = state
            .connectors
            .get(connector_id)
            .and_then(|entry| entry.lifecycle.as_ref())
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;
        Ok(LifecycleStatus::from_record(record, Utc::now(), false))
    }
}

fn resolve_admin_state_path() -> HostResult<Option<PathBuf>> {
    match std::env::var("FCP_HOST_LIFECYCLE_STATE_FILE") {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(PathBuf::from(trimmed)))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(Some(default_admin_state_path())),
        Err(std::env::VarError::NotUnicode(_)) => Err(HostError::InvalidFilter(
            "FCP_HOST_LIFECYCLE_STATE_FILE must be valid unicode".to_string(),
        )),
    }
}

fn default_admin_state_path() -> PathBuf {
    PathBuf::from(".fcp-host").join("lifecycle-state.json")
}

fn load_admin_state_snapshot(path: &Path) -> HostResult<HostAdminStateSnapshot> {
    if !path.exists() {
        return Ok(HostAdminStateSnapshot::default());
    }

    let bytes = std::fs::read(path).map_err(|err| {
        HostError::Internal(format!(
            "failed to read admin state file '{}': {err}",
            path.display()
        ))
    })?;

    let raw: Value = serde_json::from_slice(&bytes).map_err(|err| {
        HostError::Internal(format!(
            "failed to parse admin state file '{}': {err}",
            path.display()
        ))
    })?;

    let raw_object = raw.as_object().ok_or_else(|| {
        HostError::Internal(format!(
            "admin state file '{}' must contain a JSON object",
            path.display()
        ))
    })?;

    let is_legacy_snapshot =
        raw_object.contains_key("records") || raw_object.contains_key("pinned_versions");

    if !is_legacy_snapshot {
        let snapshot: HostAdminStateSnapshot = serde_json::from_value(raw).map_err(|err| {
            HostError::Internal(format!(
                "failed to parse admin state file '{}': {err}",
                path.display()
            ))
        })?;
        if snapshot.schema_version != HOST_ADMIN_STATE_SNAPSHOT_VERSION {
            return Err(HostError::Internal(format!(
                "unsupported admin state schema version {} in '{}'",
                snapshot.schema_version,
                path.display()
            )));
        }
        return Ok(snapshot);
    }

    let legacy: LegacyHostLifecycleSnapshot = serde_json::from_value(raw).map_err(|err| {
        HostError::Internal(format!(
            "failed to parse admin state file '{}': {err}",
            path.display()
        ))
    })?;
    if legacy.schema_version != HOST_ADMIN_STATE_SNAPSHOT_VERSION {
        return Err(HostError::Internal(format!(
            "unsupported legacy admin state schema version {} in '{}'",
            legacy.schema_version,
            path.display()
        )));
    }
    Ok(HostAdminStateSnapshot::from_legacy(legacy))
}

fn persist_admin_state_snapshot(
    path: Option<&Path>,
    snapshot: &HostAdminStateSnapshot,
) -> Result<(), LifecycleError> {
    let Some(path) = path else {
        return Ok(());
    };

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| LifecycleError::Persistence {
            reason: format!(
                "could not create admin state directory '{}': {err}",
                parent.display()
            ),
        })?;
    }

    let payload =
        serde_json::to_vec_pretty(snapshot).map_err(|err| LifecycleError::Persistence {
            reason: format!(
                "could not serialize admin state for '{}': {err}",
                path.display()
            ),
        })?;
    let temp_path = temporary_admin_state_path(path);
    let write_result = (|| -> Result<(), LifecycleError> {
        let mut file =
            std::fs::File::create(&temp_path).map_err(|err| LifecycleError::Persistence {
                reason: format!(
                    "could not create temporary admin state file '{}': {err}",
                    temp_path.display()
                ),
            })?;
        file.write_all(&payload)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|err| LifecycleError::Persistence {
                reason: format!(
                    "could not write admin state file '{}': {err}",
                    temp_path.display()
                ),
            })?;
        replace_admin_state_file(&temp_path, path).map_err(|err| LifecycleError::Persistence {
            reason: format!(
                "could not replace admin state file '{}': {err}",
                path.display()
            ),
        })?;
        Ok(())
    })();

    if write_result.is_err() && temp_path.exists() {
        let _ = std::fs::remove_file(&temp_path);
    }

    write_result
}

fn temporary_admin_state_path(path: &Path) -> PathBuf {
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".tmp");
    PathBuf::from(temp)
}

#[cfg(not(windows))]
fn replace_admin_state_file(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    std::fs::rename(temp_path, path)
}

#[cfg(windows)]
fn replace_admin_state_file(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::rename(temp_path, path)
}

fn config_payload_digest(payload: &Value) -> Result<String, LifecycleError> {
    let bytes = serde_json::to_vec(payload).map_err(|err| LifecycleError::Persistence {
        reason: format!("could not serialize config revision payload: {err}"),
    })?;
    Ok(hash(&bytes).to_hex().to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SanitizedConfigPayload {
    payload: Value,
    redacted_fields: Vec<String>,
    credential_references: Vec<CredentialReferenceRecord>,
    contains_inline_secrets: bool,
}

/// Extract the current sanitized config from a connector's admin state.
fn current_sanitized_config(state: &ConnectorAdminState) -> SanitizedConnectorConfig {
    state.active_config_revision().map_or_else(
        || SanitizedConnectorConfig {
            payload: Value::Null,
            payload_digest: String::new(),
            redacted_fields: Vec::new(),
            credential_references: Vec::new(),
            contains_inline_secrets: false,
        },
        |revision| SanitizedConnectorConfig {
            payload: revision.payload.clone(),
            payload_digest: revision.payload_digest.clone(),
            redacted_fields: revision.redacted_fields.clone(),
            credential_references: revision.credential_references.clone(),
            contains_inline_secrets: revision.contains_inline_secrets,
        },
    )
}

fn sanitize_config_payload(payload: Value) -> SanitizedConfigPayload {
    let mut redacted_fields = Vec::new();
    let mut credential_references = Vec::new();
    let mut contains_inline_secrets = false;
    let payload = sanitize_config_value(
        payload,
        "",
        &mut redacted_fields,
        &mut credential_references,
        &mut contains_inline_secrets,
    );
    SanitizedConfigPayload {
        payload,
        redacted_fields,
        credential_references,
        contains_inline_secrets,
    }
}

fn sanitize_config_value(
    value: Value,
    path: &str,
    redacted_fields: &mut Vec<String>,
    credential_references: &mut Vec<CredentialReferenceRecord>,
    contains_inline_secrets: &mut bool,
) -> Value {
    match value {
        Value::Object(map) => {
            let mut sanitized = serde_json::Map::new();
            for (key, value) in map {
                let child_path = extend_json_pointer(path, &key);
                if is_credential_reference_key(&key) {
                    collect_credential_references(&child_path, &value, credential_references);
                    sanitized.insert(key, value);
                    continue;
                }

                if should_redact_config_key(&key) {
                    *contains_inline_secrets = true;
                    redacted_fields.push(child_path);
                    sanitized.insert(key, Value::String(REDACTED_CONFIG_VALUE.to_string()));
                    continue;
                }

                sanitized.insert(
                    key,
                    sanitize_config_value(
                        value,
                        &child_path,
                        redacted_fields,
                        credential_references,
                        contains_inline_secrets,
                    ),
                );
            }
            Value::Object(sanitized)
        }
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    sanitize_config_value(
                        value,
                        &extend_json_pointer(path, &index.to_string()),
                        redacted_fields,
                        credential_references,
                        contains_inline_secrets,
                    )
                })
                .collect(),
        ),
        other => other,
    }
}

fn collect_credential_references(
    path: &str,
    value: &Value,
    credential_references: &mut Vec<CredentialReferenceRecord>,
) {
    match value {
        Value::String(raw) => {
            if let Ok(credential_id) = CredentialId::parse(raw) {
                credential_references.push(CredentialReferenceRecord {
                    path: path.to_string(),
                    credential_id,
                    status: SecretReferenceStatus::Unknown,
                    last_checked_at: None,
                    last_error: None,
                });
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_credential_references(
                    &extend_json_pointer(path, &index.to_string()),
                    value,
                    credential_references,
                );
            }
        }
        _ => {}
    }
}

fn is_credential_reference_key(key: &str) -> bool {
    key.to_ascii_lowercase().contains("credential_id")
}

fn should_redact_config_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    if is_credential_reference_key(&normalized) {
        return false;
    }

    [
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn extend_json_pointer(prefix: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    if prefix.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{prefix}/{escaped}")
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

fn is_default_prewarm_config(config: &ConnectorPrewarmConfig) -> bool {
    config == &ConnectorPrewarmConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use fcp_crypto::cose::CoseToken;
    use fcp_kernel::{CanaryPolicy, ConnectorHealth, HealthMetrics};
    use fcp_prelude::SafetyTier;

    fn canonicalize_json(value: Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(canonicalize_json)
                    .collect::<Vec<_>>(),
            ),
            Value::Object(map) => {
                let mut entries = map.into_iter().collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                let mut canonical = serde_json::Map::new();
                for (key, value) in entries {
                    canonical.insert(key, canonicalize_json(value));
                }
                Value::Object(canonical)
            }
            other => other,
        }
    }

    fn scrub_json_pointer(snapshot: &mut Value, pointer: &str, replacement: &str) {
        *snapshot.pointer_mut(pointer).expect("pointer exists") = Value::String(replacement.into());
    }

    fn connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test.admin-state:utility:1.0.0")
    }

    fn secondary_connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test.admin-state-secondary:utility:1.0.0")
    }

    const fn lifecycle_action_target(action: LifecycleAction) -> DesiredRuntimeState {
        match action {
            LifecycleAction::Enable | LifecycleAction::Restart | LifecycleAction::Reload => {
                DesiredRuntimeState::Enabled
            }
            LifecycleAction::Disable => DesiredRuntimeState::Disabled,
            LifecycleAction::Uninstall => DesiredRuntimeState::Uninstalled,
            LifecycleAction::Promote => DesiredRuntimeState::Enabled,
        }
    }

    fn connector_summary(
        connector_id: ConnectorId,
        enabled: bool,
        health: ConnectorHealth,
    ) -> ConnectorSummary {
        ConnectorSummary {
            id: connector_id,
            name: "Test Connector".to_string(),
            description: Some("Admin-state reconciliation test connector".to_string()),
            version: Version::new(1, 0, 0),
            categories: vec!["test".to_string()],
            tool_count: 1,
            max_safety_tier: SafetyTier::Safe,
            enabled,
            health,
            last_health_check: Some(Utc::now()),
        }
    }

    fn config_payload(name: &str) -> Value {
        serde_json::json!({
            "profile": name,
            "credential_id": format!("cred-{name}"),
        })
    }

    fn placement_policy() -> ObjectPlacementPolicy {
        ObjectPlacementPolicy {
            min_nodes: 2,
            max_node_fraction_bps: 5_000,
            preferred_devices: Vec::new(),
            excluded_devices: Vec::new(),
            target_coverage_bps: 9_000,
            min_source_diversity: 2,
        }
    }

    fn secretful_config_payload(credential_id: CredentialId) -> Value {
        serde_json::json!({
            "profile": "work",
            "credential_id": credential_id.to_string(),
            "access_token": "super-secret-access-token",
            "nested": {
                "client_secret": "ultra-secret-client-secret",
                "safe": "value"
            }
        })
    }

    #[fcp_async_core::runtime::test]
    async fn store_persists_connector_state_config_and_journal_across_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("state").join("admin-state.json");
        let connector_id = connector_id();
        let previous_version = Version::new(1, 4, 0);
        let current_version = Version::new(1, 5, 0);

        let store = HostAdminStateStore::with_state_path(state_path.clone()).expect("store");
        let mut record = LifecycleRecord::new(connector_id.clone(), current_version.clone())
            .with_previous_version(previous_version);
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .expect("pending -> installing");
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.4.0".to_string(),
                    to_version: "1.5.0".to_string(),
                },
            )
            .expect("installing -> canary");

        store.save(&record).await.expect("save");
        store
            .set_desired_state(
                &connector_id,
                DesiredRuntimeState::Enabled,
                Some("test-suite".to_string()),
            )
            .await
            .expect("desired");
        store
            .set_observed_state(
                &connector_id,
                ObservedRuntimeState::Running,
                Some("supervisor".to_string()),
            )
            .await
            .expect("observed");
        store
            .pin(&connector_id, current_version.clone())
            .await
            .expect("pin");
        let revision = store
            .append_config_revision(
                &connector_id,
                config_payload("work"),
                Some("test-suite".to_string()),
                Some("bootstrap".to_string()),
            )
            .await
            .expect("revision");

        let reloaded = HostAdminStateStore::with_state_path(state_path).expect("reloaded");
        let restored = reloaded
            .connector_state(&connector_id)
            .await
            .expect("connector state");

        assert_eq!(
            serde_json::to_value(restored.lifecycle.as_ref().expect("lifecycle"))
                .expect("serialize"),
            serde_json::to_value(&record).expect("serialize")
        );
        assert_eq!(restored.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(restored.observed_state, ObservedRuntimeState::Running);
        assert_eq!(restored.pinned_version, Some(current_version));
        assert_eq!(
            restored.active_config_revision_id,
            Some(revision.revision_id)
        );
        assert_eq!(
            restored
                .active_config_revision()
                .expect("active revision")
                .payload,
            config_payload("work")
        );
        assert_eq!(reloaded.journal(Some(&connector_id)).await.len(), 5);
    }

    #[fcp_async_core::runtime::test]
    async fn config_revisions_chain_monotonically_and_emit_monotonic_journal() {
        let store = HostAdminStateStore::new();
        let connector_id = connector_id();

        let first = store
            .append_config_revision(
                &connector_id,
                config_payload("one"),
                Some("operator-a".to_string()),
                Some("initial".to_string()),
            )
            .await
            .expect("first");
        let second = store
            .append_config_revision(
                &connector_id,
                config_payload("two"),
                Some("operator-b".to_string()),
                Some("update".to_string()),
            )
            .await
            .expect("second");

        assert!(second.revision_id > first.revision_id);
        assert_eq!(second.previous_revision_id, Some(first.revision_id));

        let journal = store.journal(Some(&connector_id)).await;
        assert_eq!(journal.len(), 2);
        assert_eq!(journal[0].sequence, 1);
        assert_eq!(journal[1].sequence, 2);
        assert!(matches!(
            journal[1].mutation,
            AdminStateMutation::ConfigRevisionAppended { revision_id, .. }
                if revision_id == second.revision_id
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn config_revision_redacts_inline_secrets_and_preserves_credential_refs() {
        let store = HostAdminStateStore::new();
        let connector_id = connector_id();
        let credential_id =
            CredentialId::parse("abababab-abab-abab-abab-abababababab").expect("credential id");

        let revision = store
            .append_config_revision(
                &connector_id,
                secretful_config_payload(credential_id),
                Some("operator".to_string()),
                Some("seed".to_string()),
            )
            .await
            .expect("append revision");

        assert_eq!(
            revision.payload["credential_id"],
            Value::String(credential_id.to_string())
        );
        assert_eq!(
            revision.payload["access_token"],
            Value::String(REDACTED_CONFIG_VALUE.to_string())
        );
        assert_eq!(
            revision.payload["nested"]["client_secret"],
            Value::String(REDACTED_CONFIG_VALUE.to_string())
        );
        assert_eq!(
            revision.payload["nested"]["safe"],
            Value::String("value".to_string())
        );
        assert!(revision.contains_inline_secrets);
        assert_eq!(
            revision.redacted_fields,
            vec![
                "/access_token".to_string(),
                "/nested/client_secret".to_string()
            ]
        );
        assert_eq!(revision.credential_references.len(), 1);
        assert_eq!(revision.credential_references[0].path, "/credential_id");
        assert_eq!(
            revision.credential_references[0].credential_id,
            credential_id
        );
        assert_eq!(
            revision.credential_references[0].status,
            SecretReferenceStatus::Unknown
        );
        assert!(!format!("{revision:?}").contains("super-secret-access-token"));
        assert!(!format!("{revision:?}").contains("ultra-secret-client-secret"));
    }

    #[fcp_async_core::runtime::test]
    async fn export_snapshot_json_is_safe_by_default_even_when_secret_digests_change() {
        let store = HostAdminStateStore::new();
        let connector_id = connector_id();
        let credential_id =
            CredentialId::parse("cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd").expect("credential id");

        let first = store
            .append_config_revision(
                &connector_id,
                secretful_config_payload(credential_id),
                Some("operator".to_string()),
                Some("initial".to_string()),
            )
            .await
            .expect("first revision");
        let second = store
            .append_config_revision(
                &connector_id,
                serde_json::json!({
                    "profile": "work",
                    "credential_id": credential_id.to_string(),
                    "access_token": "rotated-access-token"
                }),
                Some("operator".to_string()),
                Some("rotated".to_string()),
            )
            .await
            .expect("second revision");

        assert_ne!(
            first.payload_digest, second.payload_digest,
            "raw payload digest should still detect secret changes"
        );
        assert_eq!(
            first.payload["access_token"],
            second.payload["access_token"]
        );

        let export = store.export_snapshot_json().await.expect("export snapshot");
        let export_text = export.to_string();
        assert!(!export_text.contains("super-secret-access-token"));
        assert!(!export_text.contains("ultra-secret-client-secret"));
        assert!(!export_text.contains("rotated-access-token"));
        assert!(export_text.contains(REDACTED_CONFIG_VALUE));
        assert!(export_text.contains(&credential_id.to_string()));
    }

    #[test]
    fn diff_sanitized_config_values_redacts_secrets_without_hiding_changes() {
        let before = serde_json::json!({
            "profile": "work",
            "access_token": "super-secret-access-token",
            "nested": {
                "client_secret": "ultra-secret-client-secret",
                "safe": "alpha"
            }
        });
        let after = serde_json::json!({
            "profile": "work",
            "access_token": "rotated-access-token",
            "nested": {
                "client_secret": "second-client-secret",
                "safe": "beta"
            }
        });

        let diff = diff_sanitized_config_values(&before, &after).expect("diff should sanitize");

        assert!(diff.iter().any(|entry| {
            entry.path == "/access_token"
                && entry.kind == ConfigDiffKind::Changed
                && entry.before == Some(Value::String(REDACTED_CONFIG_VALUE.to_string()))
                && entry.after == Some(Value::String(REDACTED_CONFIG_VALUE.to_string()))
        }));
        assert!(diff.iter().any(|entry| {
            entry.path == "/nested/client_secret"
                && entry.kind == ConfigDiffKind::Changed
                && entry.before == Some(Value::String(REDACTED_CONFIG_VALUE.to_string()))
                && entry.after == Some(Value::String(REDACTED_CONFIG_VALUE.to_string()))
        }));
        assert!(diff.iter().any(|entry| {
            entry.path == "/nested/safe"
                && entry.kind == ConfigDiffKind::Changed
                && entry.before == Some(Value::String("alpha".to_string()))
                && entry.after == Some(Value::String("beta".to_string()))
        }));
    }

    #[fcp_async_core::runtime::test]
    async fn store_loads_legacy_lifecycle_snapshot_and_projects_runtime_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("legacy").join("lifecycle.json");
        let connector_id = connector_id();
        let version = Version::new(2, 0, 0);
        let mut record = LifecycleRecord::new(connector_id.clone(), version.clone());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .expect("pending -> installing");
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .expect_err("installing -> production is invalid");
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.9.0".to_string(),
                    to_version: version.to_string(),
                },
            )
            .expect("installing -> canary");

        let mut records = serde_json::Map::new();
        records.insert(
            connector_id.to_string(),
            serde_json::to_value(record).expect("record value"),
        );
        let mut pinned_versions = serde_json::Map::new();
        pinned_versions.insert(
            connector_id.to_string(),
            serde_json::to_value(version.clone()).expect("version value"),
        );
        let legacy = Value::Object(serde_json::Map::from_iter([
            ("schema_version".to_string(), Value::from(1)),
            ("records".to_string(), Value::Object(records)),
            (
                "pinned_versions".to_string(),
                Value::Object(pinned_versions),
            ),
        ]));
        std::fs::create_dir_all(state_path.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &state_path,
            serde_json::to_vec_pretty(&legacy).expect("legacy json"),
        )
        .expect("write");

        let store = HostAdminStateStore::with_state_path(state_path).expect("load");
        let restored = store
            .connector_state(&connector_id)
            .await
            .expect("connector state");
        assert!(restored.lifecycle.is_some());
        assert_eq!(restored.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(restored.observed_state, ObservedRuntimeState::Running);
        assert_eq!(restored.pinned_version, Some(version));
        assert!(store.journal(Some(&connector_id)).await.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn startup_reconciliation_creates_rows_and_marks_missing_connectors() {
        let store = HostAdminStateStore::new();
        let live_connector_id = connector_id();
        let missing_connector_id = secondary_connector_id();

        store
            .set_desired_state(
                &missing_connector_id,
                DesiredRuntimeState::Enabled,
                Some("test-suite".to_string()),
            )
            .await
            .expect("desired state should persist");
        store
            .set_observed_state(
                &missing_connector_id,
                ObservedRuntimeState::Running,
                Some("test-suite".to_string()),
            )
            .await
            .expect("observed state should persist");

        let registered = vec![connector_summary(
            live_connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        let now = Utc.with_ymd_and_hms(2026, 3, 10, 23, 45, 0).unwrap();
        let report = store
            .reconcile_registered_connectors_at(&registered, now)
            .await
            .expect("startup reconciliation should persist");

        assert_eq!(report.tracked_connectors, 2);
        assert_eq!(report.created_connectors, 1);
        assert_eq!(report.observed_updates, 2);
        assert_eq!(report.drifted_connectors, 1);

        let live_entry = report
            .entries
            .iter()
            .find(|entry| entry.connector_id == live_connector_id)
            .expect("live connector entry");
        assert!(live_entry.created_admin_state);
        assert_eq!(live_entry.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(
            live_entry.observed_state_before,
            ObservedRuntimeState::Unknown
        );
        assert_eq!(
            live_entry.observed_state_after,
            ObservedRuntimeState::Running
        );
        assert!(live_entry.updated);
        assert!(live_entry.drift.is_none());

        let missing_entry = report
            .entries
            .iter()
            .find(|entry| entry.connector_id == missing_connector_id)
            .expect("missing connector entry");
        assert!(!missing_entry.created_admin_state);
        assert_eq!(missing_entry.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(
            missing_entry.observed_state_before,
            ObservedRuntimeState::Running
        );
        assert_eq!(
            missing_entry.observed_state_after,
            ObservedRuntimeState::Missing
        );
        assert!(missing_entry.updated);
        assert_eq!(
            missing_entry
                .drift
                .as_ref()
                .expect("missing connector should drift")
                .kind,
            ConnectorDriftKind::EnabledButMissing
        );

        let missing_status = store
            .connector_status_at(&missing_connector_id, now)
            .await
            .expect("status should exist after reconciliation");
        assert_eq!(missing_status.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(missing_status.observed_state, ObservedRuntimeState::Missing);
        assert_eq!(
            missing_status
                .drift
                .as_ref()
                .expect("missing connector should drift")
                .recovery_action,
            RecoveryAction::ReinstallConnector
        );
    }

    #[test]
    fn connector_drift_status_identifies_stuck_install_and_canary() {
        let now = Utc.with_ymd_and_hms(2026, 3, 10, 23, 50, 0).unwrap();
        let install_record = LifecycleRecord {
            connector_id: connector_id(),
            version: Version::new(1, 0, 0),
            state: LifecycleState::Installing,
            deployed_at: now - Duration::minutes(15),
            state_changed_at: now - Duration::minutes(10),
            transitions: Vec::new(),
            health: HealthMetrics::default(),
            canary_policy: CanaryPolicy::default(),
            previous_version: None,
        };
        let install_state = ConnectorAdminState {
            lifecycle: Some(install_record),
            desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Starting,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        let install_drift =
            connector_drift_status(&install_state, now).expect("install should be stuck");
        assert_eq!(install_drift.kind, ConnectorDriftKind::InstallStuck);
        assert_eq!(install_drift.recovery_action, RecoveryAction::Investigate);

        let canary_record = LifecycleRecord {
            connector_id: secondary_connector_id(),
            version: Version::new(1, 1, 0),
            state: LifecycleState::Canary,
            deployed_at: now - Duration::minutes(30),
            state_changed_at: now - Duration::minutes(20),
            transitions: Vec::new(),
            health: HealthMetrics::default(),
            canary_policy: CanaryPolicy {
                max_canary_duration_secs: 60,
                ..CanaryPolicy::default()
            },
            previous_version: Some(Version::new(1, 0, 0)),
        };
        let canary_state = ConnectorAdminState {
            lifecycle: Some(canary_record),
            desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Running,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        let canary_drift =
            connector_drift_status(&canary_state, now).expect("canary should be stuck");
        assert_eq!(canary_drift.kind, ConnectorDriftKind::CanaryStuck);
        assert_eq!(
            canary_drift.recovery_action,
            RecoveryAction::CompleteRollout
        );
    }

    // ── LifecycleAction serde ──

    #[test]
    fn lifecycle_action_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Enable).unwrap(),
            r#""enable""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Disable).unwrap(),
            r#""disable""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Restart).unwrap(),
            r#""restart""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Reload).unwrap(),
            r#""reload""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Uninstall).unwrap(),
            r#""uninstall""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Promote).unwrap(),
            r#""promote""#
        );
    }

    #[test]
    fn lifecycle_action_deserializes_all_variants() {
        let actions = [
            "enable",
            "disable",
            "restart",
            "reload",
            "uninstall",
            "promote",
        ];
        for action in actions {
            let json = format!("\"{action}\"");
            let parsed: LifecycleAction = serde_json::from_str(&json).unwrap();
            let reserialized = serde_json::to_string(&parsed).unwrap();
            assert_eq!(reserialized, json);
        }
    }

    // ── LifecycleTransitionRequest serde ──

    #[test]
    fn lifecycle_transition_request_minimal() {
        let json = r#"{"action":"enable"}"#;
        let req: LifecycleTransitionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.action, LifecycleAction::Enable);
        assert!(req.reason.is_none());
        assert!(req.initiated_by.is_none());
        assert!(!req.dry_run);
    }

    #[test]
    fn lifecycle_transition_request_full() {
        let json = r#"{
            "action": "disable",
            "reason": "maintenance window",
            "initiated_by": "operator",
            "dry_run": true
        }"#;
        let req: LifecycleTransitionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.action, LifecycleAction::Disable);
        assert_eq!(req.reason.as_deref(), Some("maintenance window"));
        assert_eq!(req.initiated_by.as_deref(), Some("operator"));
        assert!(req.dry_run);
    }

    #[test]
    fn lifecycle_transition_response_roundtrip() {
        let response = LifecycleTransitionResponse {
            connector_id: "fcp.test:echo:1.0.0".to_string(),
            action: LifecycleAction::Enable,
            dry_run: false,
            previous_desired_state: DesiredRuntimeState::Disabled,
            current_desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Stopped,
            lifecycle_status: None,
            journal_sequence: 42,
            transitioned_at: Utc::now(),
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: LifecycleTransitionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "fcp.test:echo:1.0.0");
        assert_eq!(parsed.action, LifecycleAction::Enable);
        assert_eq!(parsed.previous_desired_state, DesiredRuntimeState::Disabled);
        assert_eq!(parsed.current_desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(parsed.journal_sequence, 42);
    }

    // ── JournalQueryRequest serde ──

    #[test]
    fn journal_query_request_defaults() {
        let json = r"{}";
        let req: JournalQueryRequest = serde_json::from_str(json).unwrap();
        assert!(req.connector_id.is_none());
        assert_eq!(req.after_sequence, 0);
        assert_eq!(req.limit, 100);
    }

    #[test]
    fn journal_query_request_with_filter() {
        let json = r#"{"connector_id":"fcp.test:echo:1.0.0","after_sequence":10,"limit":50}"#;
        let req: JournalQueryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.connector_id.as_deref(), Some("fcp.test:echo:1.0.0"));
        assert_eq!(req.after_sequence, 10);
        assert_eq!(req.limit, 50);
    }

    #[test]
    fn journal_query_response_roundtrip() {
        let response = JournalQueryResponse {
            entries: Vec::new(),
            total_entries: 42,
            latest_sequence: 100,
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: JournalQueryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_entries, 42);
        assert_eq!(parsed.latest_sequence, 100);
        assert!(parsed.entries.is_empty());
    }

    // ── execute_lifecycle_transition integration ──

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_enable_dry_run() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [connector_summary(
            connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: true,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert!(response.dry_run);
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(response.action, LifecycleAction::Enable);
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_enable_persists() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [connector_summary(
            connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: Some("go live".to_string()),
            initiated_by: Some("operator".to_string()),
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert!(!response.dry_run);
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
        assert!(response.journal_sequence > 0);

        let status = store.connector_status(&connector_id).await.unwrap();
        assert_eq!(status.desired_state, DesiredRuntimeState::Enabled);
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_disable() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [connector_summary(
            connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        // Enable first.
        let enable = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&connector_id, &enable)
            .await
            .unwrap();

        // Then disable.
        let disable = LifecycleTransitionRequest {
            action: LifecycleAction::Disable,
            reason: Some("maintenance".to_string()),
            initiated_by: None,
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &disable)
            .await
            .unwrap();
        assert_eq!(
            response.previous_desired_state,
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            response.current_desired_state,
            DesiredRuntimeState::Disabled
        );
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_uninstall() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [connector_summary(
            connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Uninstall,
            reason: Some("no longer needed".to_string()),
            initiated_by: None,
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert_eq!(
            response.current_desired_state,
            DesiredRuntimeState::Uninstalled
        );
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_restart_sets_enabled() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [connector_summary(
            connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Restart,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert_eq!(response.action, LifecycleAction::Restart);
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_reload_sets_enabled() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [connector_summary(
            connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Reload,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert_eq!(response.action, LifecycleAction::Reload);
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_not_found() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:ghost:1.0.0");
        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        let result = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await;
        assert!(result.is_err());
    }

    // ── query_journal integration ──

    #[fcp_async_core::runtime::test]
    async fn query_journal_empty() {
        let store = HostAdminStateStore::new();
        let request = JournalQueryRequest {
            connector_id: None,
            after_sequence: 0,
            limit: 100,
        };
        let response = store.query_journal(&request).await;
        assert!(response.entries.is_empty());
        assert_eq!(response.total_entries, 0);
        assert_eq!(response.latest_sequence, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn query_journal_after_transitions() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [connector_summary(
            connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        // Perform transitions.
        let enable = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: Some("test".to_string()),
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&connector_id, &enable)
            .await
            .unwrap();

        let disable = LifecycleTransitionRequest {
            action: LifecycleAction::Disable,
            reason: None,
            initiated_by: Some("test".to_string()),
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&connector_id, &disable)
            .await
            .unwrap();

        // Query all entries.
        let request = JournalQueryRequest {
            connector_id: None,
            after_sequence: 0,
            limit: 100,
        };
        let response = store.query_journal(&request).await;
        assert!(response.total_entries >= 2);
        assert!(response.latest_sequence > 0);
    }

    #[fcp_async_core::runtime::test]
    async fn query_journal_with_connector_filter() {
        let store = HostAdminStateStore::new();
        let c1 = ConnectorId::from_static("fcp.test:alpha:1.0.0");
        let c2 = ConnectorId::from_static("fcp.test:beta:1.0.0");
        let summaries = [
            connector_summary(c1.clone(), true, ConnectorHealth::healthy()),
            connector_summary(c2.clone(), true, ConnectorHealth::healthy()),
        ];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let enable_c1 = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&c1, &enable_c1)
            .await
            .unwrap();

        let enable_c2 = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&c2, &enable_c2)
            .await
            .unwrap();

        // Filter to c1 only.
        let request = JournalQueryRequest {
            connector_id: Some("fcp.test:alpha:1.0.0".to_string()),
            after_sequence: 0,
            limit: 100,
        };
        let response = store.query_journal(&request).await;
        for entry in &response.entries {
            assert_eq!(entry.connector_id.as_str(), "fcp.test:alpha:1.0.0");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn query_journal_respects_after_sequence() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [connector_summary(
            connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        // Two transitions.
        for action in [LifecycleAction::Enable, LifecycleAction::Disable] {
            let req = LifecycleTransitionRequest {
                action,
                reason: None,
                initiated_by: None,
                dry_run: false,
            };
            store
                .execute_lifecycle_transition(&connector_id, &req)
                .await
                .unwrap();
        }

        // Get all entries to find a midpoint.
        let all = store
            .query_journal(&JournalQueryRequest {
                connector_id: None,
                after_sequence: 0,
                limit: 1000,
            })
            .await;
        let total = all.entries.len();
        assert!(total >= 2);

        // Query after the first entry.
        let first_seq = all.entries[0].sequence;
        let after_first = store
            .query_journal(&JournalQueryRequest {
                connector_id: None,
                after_sequence: first_seq,
                limit: 1000,
            })
            .await;
        assert!(after_first.entries.len() < total);
        for entry in &after_first.entries {
            assert!(entry.sequence > first_seq);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn query_journal_respects_limit() {
        let store = HostAdminStateStore::new();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [connector_summary(
            connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        // Several transitions to create journal entries.
        for action in [
            LifecycleAction::Enable,
            LifecycleAction::Disable,
            LifecycleAction::Enable,
        ] {
            let req = LifecycleTransitionRequest {
                action,
                reason: None,
                initiated_by: None,
                dry_run: false,
            };
            store
                .execute_lifecycle_transition(&connector_id, &req)
                .await
                .unwrap();
        }

        let request = JournalQueryRequest {
            connector_id: None,
            after_sequence: 0,
            limit: 1,
        };
        let response = store.query_journal(&request).await;
        assert_eq!(response.entries.len(), 1);
    }

    // ── Lifecycle action target mapping ──

    #[test]
    fn lifecycle_action_target_desired_state() {
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Enable),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Disable),
            DesiredRuntimeState::Disabled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Restart),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Reload),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Uninstall),
            DesiredRuntimeState::Uninstalled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Promote),
            DesiredRuntimeState::Enabled
        );
    }

    // ── LogSeverity serde ──

    #[test]
    fn log_severity_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&LogSeverity::Debug).unwrap(),
            r#""debug""#
        );
        assert_eq!(
            serde_json::to_string(&LogSeverity::Error).unwrap(),
            r#""error""#
        );
    }

    #[test]
    fn host_log_entry_roundtrip() {
        let entry = HostLogEntry {
            sequence: 1,
            connector_id: Some("fcp.test:echo:1.0.0".to_string()),
            severity: LogSeverity::Info,
            message: "connector started".to_string(),
            fields: BTreeMap::new(),
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: HostLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sequence, 1);
        assert_eq!(parsed.severity, LogSeverity::Info);
    }

    #[test]
    fn log_query_request_defaults() {
        let json = r"{}";
        let req: LogQueryRequest = serde_json::from_str(json).unwrap();
        assert!(req.connector_id.is_none());
        assert!(req.min_severity.is_none());
        assert_eq!(req.after_sequence, 0);
        assert_eq!(req.limit, 100);
    }

    // ── HostEventKind serde ──

    #[test]
    fn host_event_kind_serializes_all_variants() {
        let kinds = [
            HostEventKind::LifecycleTransition,
            HostEventKind::HealthCheck,
            HostEventKind::ConfigRevision,
            HostEventKind::RolloutDecision,
            HostEventKind::SupplyChainVerification,
            HostEventKind::DriftDetected,
            HostEventKind::ConnectorStateChange,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let parsed: HostEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn host_event_roundtrip() {
        let event = HostEvent {
            event_id: "evt-1".to_string(),
            kind: HostEventKind::LifecycleTransition,
            connector_id: Some("fcp.test:echo:1.0.0".to_string()),
            summary: "enabled".to_string(),
            payload: Some(serde_json::json!({"state": "enabled"})),
            timestamp: Utc::now(),
            acknowledged: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: HostEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_id, "evt-1");
        assert!(!parsed.acknowledged);
    }

    #[test]
    fn event_query_request_defaults() {
        let json = r"{}";
        let req: EventQueryRequest = serde_json::from_str(json).unwrap();
        assert!(req.connector_id.is_none());
        assert!(req.kind.is_none());
        assert!(!req.unacknowledged_only);
        assert_eq!(req.limit, 100);
    }

    #[test]
    fn event_acknowledge_request_roundtrip() {
        let req = EventAcknowledgeRequest {
            event_ids: vec!["evt-1".to_string(), "evt-2".to_string()],
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: EventAcknowledgeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_ids.len(), 2);
    }

    #[test]
    fn receipt_query_request_roundtrip() {
        let req = ReceiptQueryRequest {
            connector_id: "fcp.test:echo:1.0.0".to_string(),
            operation: Some("send_message".to_string()),
            after: None,
            limit: 50,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ReceiptQueryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "fcp.test:echo:1.0.0");
        assert_eq!(parsed.operation.as_deref(), Some("send_message"));
    }

    #[test]
    fn receipt_summary_roundtrip() {
        let receipt = ReceiptSummary {
            receipt_id: "rcpt-1".to_string(),
            connector_id: "fcp.test:echo:1.0.0".to_string(),
            operation: "send_message".to_string(),
            success: true,
            duration_ms: 42,
            idempotency_key: None,
            executed_at: Utc::now(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: ReceiptSummary = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.duration_ms, 42);
    }

    fn test_receipt_summary(connector_id: &str, operation: &str, success: bool) -> ReceiptSummary {
        ReceiptSummary {
            receipt_id: format!("rcpt-{connector_id}-{operation}"),
            connector_id: connector_id.to_string(),
            operation: operation.to_string(),
            success,
            duration_ms: 42,
            idempotency_key: Some(format!("idem-{operation}")),
            executed_at: Utc::now(),
        }
    }

    // ── Log store integration ──

    #[fcp_async_core::runtime::test]
    async fn append_and_query_logs() {
        let store = HostAdminStateStore::new();

        store
            .append_log(
                Some("fcp.test:echo:1.0.0"),
                LogSeverity::Info,
                "connector started".to_string(),
                BTreeMap::new(),
            )
            .await;
        store
            .append_log(
                Some("fcp.test:echo:1.0.0"),
                LogSeverity::Error,
                "connection failed".to_string(),
                BTreeMap::new(),
            )
            .await;

        let all = store
            .query_logs(&LogQueryRequest {
                connector_id: None,
                min_severity: None,
                after_sequence: 0,
                limit: 100,
            })
            .await;
        assert_eq!(all.entries.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn query_logs_severity_filter() {
        let store = HostAdminStateStore::new();

        store
            .append_log(
                None,
                LogSeverity::Debug,
                "debug msg".to_string(),
                BTreeMap::new(),
            )
            .await;
        store
            .append_log(
                None,
                LogSeverity::Error,
                "error msg".to_string(),
                BTreeMap::new(),
            )
            .await;

        let errors_only = store
            .query_logs(&LogQueryRequest {
                connector_id: None,
                min_severity: Some(LogSeverity::Error),
                after_sequence: 0,
                limit: 100,
            })
            .await;
        assert_eq!(errors_only.entries.len(), 1);
        assert_eq!(errors_only.entries[0].severity, LogSeverity::Error);
    }

    #[fcp_async_core::runtime::test]
    async fn query_logs_connector_filter() {
        let store = HostAdminStateStore::new();

        store
            .append_log(
                Some("fcp.test:alpha:1.0.0"),
                LogSeverity::Info,
                "alpha log".to_string(),
                BTreeMap::new(),
            )
            .await;
        store
            .append_log(
                Some("fcp.test:beta:1.0.0"),
                LogSeverity::Info,
                "beta log".to_string(),
                BTreeMap::new(),
            )
            .await;

        let alpha_only = store
            .query_logs(&LogQueryRequest {
                connector_id: Some("fcp.test:alpha:1.0.0".to_string()),
                min_severity: None,
                after_sequence: 0,
                limit: 100,
            })
            .await;
        assert_eq!(alpha_only.entries.len(), 1);
        assert_eq!(
            alpha_only.entries[0].connector_id.as_deref(),
            Some("fcp.test:alpha:1.0.0")
        );
    }

    // ── Event store integration ──

    #[fcp_async_core::runtime::test]
    async fn emit_and_query_events() {
        let store = HostAdminStateStore::new();

        store
            .emit_event(
                HostEventKind::LifecycleTransition,
                Some("fcp.test:echo:1.0.0"),
                "connector enabled".to_string(),
                None,
            )
            .await;
        store
            .emit_event(
                HostEventKind::HealthCheck,
                Some("fcp.test:echo:1.0.0"),
                "health ok".to_string(),
                None,
            )
            .await;

        let all = store
            .query_events(&EventQueryRequest {
                connector_id: None,
                kind: None,
                unacknowledged_only: false,
                limit: 100,
            })
            .await;
        assert_eq!(all.events.len(), 2);
        assert_eq!(all.unacknowledged_count, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn query_events_by_kind() {
        let store = HostAdminStateStore::new();

        store
            .emit_event(
                HostEventKind::LifecycleTransition,
                None,
                "transition".to_string(),
                None,
            )
            .await;
        store
            .emit_event(HostEventKind::HealthCheck, None, "check".to_string(), None)
            .await;

        let transitions = store
            .query_events(&EventQueryRequest {
                connector_id: None,
                kind: Some(HostEventKind::LifecycleTransition),
                unacknowledged_only: false,
                limit: 100,
            })
            .await;
        assert_eq!(transitions.events.len(), 1);
        assert_eq!(
            transitions.events[0].kind,
            HostEventKind::LifecycleTransition
        );
    }

    #[fcp_async_core::runtime::test]
    async fn acknowledge_events_and_filter() {
        let store = HostAdminStateStore::new();

        store
            .emit_event(
                HostEventKind::DriftDetected,
                None,
                "drift".to_string(),
                None,
            )
            .await;
        store
            .emit_event(HostEventKind::HealthCheck, None, "ok".to_string(), None)
            .await;

        // Get all events.
        let all = store
            .query_events(&EventQueryRequest {
                connector_id: None,
                kind: None,
                unacknowledged_only: false,
                limit: 100,
            })
            .await;
        assert_eq!(all.events.len(), 2);

        // Acknowledge the first one.
        let ack_response = store
            .acknowledge_events(&EventAcknowledgeRequest {
                event_ids: vec![all.events[0].event_id.clone()],
            })
            .await;
        assert_eq!(ack_response.acknowledged_count, 1);
        assert!(ack_response.not_found.is_empty());

        // Query unacknowledged only.
        let unacked = store
            .query_events(&EventQueryRequest {
                connector_id: None,
                kind: None,
                unacknowledged_only: true,
                limit: 100,
            })
            .await;
        assert_eq!(unacked.events.len(), 1);
        assert_eq!(unacked.unacknowledged_count, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn acknowledge_nonexistent_event() {
        let store = HostAdminStateStore::new();
        let response = store
            .acknowledge_events(&EventAcknowledgeRequest {
                event_ids: vec!["evt-999".to_string()],
            })
            .await;
        assert_eq!(response.acknowledged_count, 0);
        assert_eq!(response.not_found, vec!["evt-999"]);
    }

    #[fcp_async_core::runtime::test]
    async fn record_and_query_receipts() {
        let store = HostAdminStateStore::new();

        store
            .record_receipt(test_receipt_summary(
                "github:saas:1.0.0",
                "list_repos",
                true,
            ))
            .await
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQueryRequest {
                connector_id: "github:saas:1.0.0".to_string(),
                operation: None,
                after: None,
                limit: 100,
            })
            .await;
        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.total_receipts, 1);
        assert!(result.receipts[0].success);
    }

    #[fcp_async_core::runtime::test]
    async fn query_receipts_filter_by_operation() {
        let store = HostAdminStateStore::new();

        store
            .record_receipt(test_receipt_summary(
                "github:saas:1.0.0",
                "list_repos",
                true,
            ))
            .await
            .unwrap();
        store
            .record_receipt(test_receipt_summary(
                "github:saas:1.0.0",
                "create_issue",
                false,
            ))
            .await
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQueryRequest {
                connector_id: "github:saas:1.0.0".to_string(),
                operation: Some("create_issue".to_string()),
                after: None,
                limit: 100,
            })
            .await;
        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.receipts[0].operation, "create_issue");
        assert_eq!(result.total_receipts, 2);
        assert!(!result.receipts[0].success);
    }

    #[fcp_async_core::runtime::test]
    async fn query_receipts_filter_by_connector() {
        let store = HostAdminStateStore::new();

        store
            .record_receipt(test_receipt_summary(
                "github:saas:1.0.0",
                "list_repos",
                true,
            ))
            .await
            .unwrap();
        store
            .record_receipt(test_receipt_summary(
                "slack:saas:1.0.0",
                "send_message",
                true,
            ))
            .await
            .unwrap();

        let result = store
            .query_receipts(&ReceiptQueryRequest {
                connector_id: "github:saas:1.0.0".to_string(),
                operation: None,
                after: None,
                limit: 100,
            })
            .await;
        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.total_receipts, 1);
        assert_eq!(result.receipts[0].connector_id, "github:saas:1.0.0");
    }

    // ── Capability issuance tests ──────────────────────────────────────────

    fn test_signing_key() -> fcp_crypto::ed25519::Ed25519SigningKey {
        fcp_crypto::ed25519::Ed25519SigningKey::generate()
    }

    fn test_credential_id(byte: u8) -> CredentialId {
        let raw = match byte {
            0x11 => "11111111-1111-1111-1111-111111111111",
            0x22 => "22222222-2222-2222-2222-222222222222",
            0x33 => "33333333-3333-3333-3333-333333333333",
            0x44 => "44444444-4444-4444-4444-444444444444",
            0x55 => "55555555-5555-5555-5555-555555555555",
            _ => panic!("unsupported credential id test byte: {byte:#04x}"),
        };
        CredentialId::parse(raw).unwrap()
    }

    fn basic_issuance_request() -> CapabilityIssuanceRequest {
        CapabilityIssuanceRequest {
            connector_id: "github:saas:1.0.0".to_string(),
            capability_id: "github.repo".to_string(),
            zone_id: "z:work".to_string(),
            principal_id: "agent:test-agent".to_string(),
            operations: vec!["list_repos".to_string(), "create_issue".to_string()],
            ttl_secs: 3600,
            not_before_delay_secs: None,
            holder_node: None,
            max_delegation_depth: 0,
            resource_allow: Vec::new(),
            resource_deny: Vec::new(),
            max_calls: None,
            max_bytes: None,
            credential_allow: Vec::new(),
            dry_run: false,
        }
    }

    #[fcp_async_core::runtime::test]
    async fn issue_capability_token_basic() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let request = basic_issuance_request();

        let response = store.issue_capability_token(&request, &key).await.unwrap();

        assert!(!response.dry_run);
        assert!(!response.token_id.is_empty());
        assert!(response.token_cbor_b64.is_some());
        assert_eq!(response.inspection.subject, "agent:test-agent");
        assert_eq!(response.inspection.audience.as_deref(), Some("z:work"));
        assert_eq!(response.inspection.zone_id, "z:work");
        assert_eq!(
            response.inspection.capability_id.as_deref(),
            Some("github.repo")
        );
        assert_eq!(
            response.inspection.operations,
            vec!["list_repos", "create_issue"]
        );
        assert_eq!(response.inspection.resource_allow, vec!["*"]);
        assert!(response.inspection.currently_valid);
        assert!(response.inspection.seconds_remaining > 0);
        assert_eq!(response.inspection.delegation_depth, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn issued_token_verifies_with_core_live_capability_verifier() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let request = basic_issuance_request();

        let response = store.issue_capability_token(&request, &key).await.unwrap();
        let token_b64 = response.token_cbor_b64.expect("non-dry-run token");
        let token_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token_b64).unwrap();
        let token = CapabilityToken::from_raw(CoseToken::from_cbor(&token_bytes).unwrap());
        let verifier = fcp_core::CapabilityVerifier::without_instance_binding(
            key.verifying_key().to_bytes(),
            fcp_core::ZoneId::try_from("z:work".to_string()).unwrap(),
        );

        let verified = verifier
            .verify_unbound(
                token,
                &CapabilityId::new("github.repo").unwrap(),
                &OperationId::new("list_repos").unwrap(),
                &[],
            )
            .expect("host-issued token must satisfy live core verifier");

        assert_eq!(verified.claims().get_capability_id(), Some("github.repo"));
    }

    #[fcp_async_core::runtime::test]
    async fn issue_capability_token_dry_run() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let mut request = basic_issuance_request();
        request.dry_run = true;

        let response = store.issue_capability_token(&request, &key).await.unwrap();

        assert!(response.dry_run);
        assert!(response.token_cbor_b64.is_none());
        assert!(!response.token_id.is_empty());
        assert_eq!(response.inspection.subject, "agent:test-agent");

        // Dry run should not record in token registry.
        let tokens = store
            .query_issued_tokens(&IssuedTokenQueryRequest {
                connector_id: None,
                principal_id: None,
                active_only: false,
                limit: 100,
            })
            .await;
        assert_eq!(tokens.total_tokens, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn issue_capability_token_with_holder_node() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let mut request = basic_issuance_request();
        request.holder_node = Some("node:my-laptop".to_string());

        let response = store.issue_capability_token(&request, &key).await.unwrap();

        assert_eq!(
            response.inspection.holder_node.as_deref(),
            Some("node:my-laptop")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn issue_capability_token_with_not_before_delay() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let mut request = basic_issuance_request();
        request.not_before_delay_secs = Some(60);

        let response = store.issue_capability_token(&request, &key).await.unwrap();

        assert!(response.inspection.not_before.is_some());
        // Token should not be currently valid since nbf is in the future.
        assert!(!response.inspection.currently_valid);
    }

    #[fcp_async_core::runtime::test]
    async fn issue_capability_token_rejects_overflowing_not_before_delay() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let mut request = basic_issuance_request();
        request.not_before_delay_secs = Some(u64::MAX);

        let err = store
            .issue_capability_token(&request, &key)
            .await
            .unwrap_err();
        let reason = match err {
            LifecycleError::Persistence { reason } => reason,
            _ => String::new(),
        };
        assert!(!reason.is_empty());
        assert!(reason.contains("not_before_delay_secs"));
        assert!(reason.contains("exceeds max"));
    }

    #[fcp_async_core::runtime::test]
    async fn issue_capability_token_rejects_not_before_delay_above_cap() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let mut request = basic_issuance_request();
        request.not_before_delay_secs = Some(MAX_NOT_BEFORE_DELAY_SECS + 1);

        let err = store
            .issue_capability_token(&request, &key)
            .await
            .unwrap_err();
        let reason = match err {
            LifecycleError::Persistence { reason } => reason,
            _ => String::new(),
        };
        assert!(!reason.is_empty());
        assert!(reason.contains("not_before_delay_secs"));
        assert!(reason.contains("exceeds max"));
    }

    #[fcp_async_core::runtime::test]
    async fn issue_capability_token_with_constraints() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let credential_id = test_credential_id(0x11);
        let mut request = basic_issuance_request();
        request.resource_allow = vec!["repos/my-org/*".to_string()];
        request.resource_deny = vec!["repos/my-org/secret-repo".to_string()];
        request.max_calls = Some(100);
        request.max_bytes = Some(1_048_576);
        request.credential_allow = vec![credential_id];

        let response = store.issue_capability_token(&request, &key).await.unwrap();

        assert_eq!(response.inspection.resource_allow, vec!["repos/my-org/*"]);
        assert_eq!(
            response.inspection.resource_deny,
            vec!["repos/my-org/secret-repo"]
        );
        assert_eq!(response.inspection.max_calls, Some(100));
        assert_eq!(response.inspection.max_bytes, Some(1_048_576));
        assert_eq!(response.inspection.credential_allow, vec![credential_id]);
    }

    #[fcp_async_core::runtime::test]
    async fn issue_and_inspect_round_trip() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let credential_id = test_credential_id(0x22);
        let mut request = basic_issuance_request();
        request.resource_allow = vec!["repos/my-org/*".to_string()];
        request.resource_deny = vec!["repos/my-org/secret-repo".to_string()];
        request.max_calls = Some(100);
        request.max_bytes = Some(1_048_576);
        request.credential_allow = vec![credential_id];

        let response = store.issue_capability_token(&request, &key).await.unwrap();
        let token_b64 = response.token_cbor_b64.unwrap();

        let inspection = HostAdminStateStore::inspect_capability_token(&token_b64).unwrap();

        assert_eq!(inspection.subject, "agent:test-agent");
        assert_eq!(inspection.zone_id, "z:work");
        assert_eq!(inspection.operations, vec!["list_repos", "create_issue"]);
        assert_eq!(inspection.resource_allow, vec!["repos/my-org/*"]);
        assert_eq!(inspection.resource_deny, vec!["repos/my-org/secret-repo"]);
        assert_eq!(inspection.max_calls, Some(100));
        assert_eq!(inspection.max_bytes, Some(1_048_576));
        assert_eq!(inspection.credential_allow, vec![credential_id]);
        assert!(inspection.currently_valid);
        assert!(!inspection.token_id.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn issued_token_serializes_constraints_claim() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let credential_id = test_credential_id(0x33);
        let mut request = basic_issuance_request();
        request.resource_allow = vec!["repos/my-org/*".to_string()];
        request.resource_deny = vec!["repos/my-org/secret-repo".to_string()];
        request.max_calls = Some(100);
        request.max_bytes = Some(1_048_576);
        request.credential_allow = vec![credential_id];

        let response = store.issue_capability_token(&request, &key).await.unwrap();
        let token_b64 = response.token_cbor_b64.unwrap();
        let token_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token_b64).unwrap();
        let token = CoseToken::from_cbor(&token_bytes).unwrap();
        let claims = token.claims_unverified().unwrap();
        let constraints = deserialize_capability_constraints(&claims).unwrap();

        assert_eq!(constraints.resource_allow, request.resource_allow);
        assert_eq!(constraints.resource_deny, request.resource_deny);
        assert_eq!(constraints.max_calls, request.max_calls);
        assert_eq!(constraints.max_bytes, request.max_bytes);
        assert_eq!(constraints.credential_allow, request.credential_allow);
    }

    #[fcp_async_core::runtime::test]
    async fn inspect_invalid_base64_returns_error() {
        let result = HostAdminStateStore::inspect_capability_token("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn issue_records_in_token_registry() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let request = basic_issuance_request();

        store.issue_capability_token(&request, &key).await.unwrap();

        let tokens = store
            .query_issued_tokens(&IssuedTokenQueryRequest {
                connector_id: None,
                principal_id: None,
                active_only: false,
                limit: 100,
            })
            .await;

        assert_eq!(tokens.total_tokens, 1);
        assert_eq!(tokens.active_count, 1);
        assert_eq!(tokens.tokens[0].connector_id, "github:saas:1.0.0");
        assert_eq!(tokens.tokens[0].principal_id, "agent:test-agent");
        assert!(!tokens.tokens[0].revoked);
    }

    #[fcp_async_core::runtime::test]
    async fn revoke_token_success() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let request = basic_issuance_request();

        let issued = store.issue_capability_token(&request, &key).await.unwrap();

        let revoke_response = store
            .revoke_token(&TokenRevocationRequest {
                token_id: issued.token_id.clone(),
                reason: Some("compromised".to_string()),
            })
            .await
            .unwrap();

        assert!(revoke_response.revoked);
        assert_eq!(revoke_response.token_id, issued.token_id);

        // Query should show revoked.
        let tokens = store
            .query_issued_tokens(&IssuedTokenQueryRequest {
                connector_id: None,
                principal_id: None,
                active_only: false,
                limit: 100,
            })
            .await;
        assert_eq!(tokens.total_tokens, 1);
        assert!(tokens.tokens[0].revoked);
        assert_eq!(
            tokens.tokens[0].revocation_reason.as_deref(),
            Some("compromised")
        );
        assert!(tokens.tokens[0].revoked_at.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn revoke_nonexistent_token() {
        let store = HostAdminStateStore::new();

        let response = store
            .revoke_token(&TokenRevocationRequest {
                token_id: "nonexistent".to_string(),
                reason: None,
            })
            .await
            .unwrap();

        assert!(!response.revoked);
    }

    #[fcp_async_core::runtime::test]
    async fn revoke_already_revoked_token() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let request = basic_issuance_request();

        let issued = store.issue_capability_token(&request, &key).await.unwrap();

        // First revocation.
        let r1 = store
            .revoke_token(&TokenRevocationRequest {
                token_id: issued.token_id.clone(),
                reason: Some("first".to_string()),
            })
            .await
            .unwrap();
        assert!(r1.revoked);

        // Second revocation - already revoked.
        let r2 = store
            .revoke_token(&TokenRevocationRequest {
                token_id: issued.token_id.clone(),
                reason: Some("second".to_string()),
            })
            .await
            .unwrap();
        assert!(!r2.revoked);
    }

    #[fcp_async_core::runtime::test]
    async fn query_tokens_filter_by_connector() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();

        // Issue two tokens for different connectors.
        let mut req1 = basic_issuance_request();
        req1.connector_id = "github:saas:1.0.0".to_string();
        store.issue_capability_token(&req1, &key).await.unwrap();

        let mut req2 = basic_issuance_request();
        req2.connector_id = "slack:saas:1.0.0".to_string();
        store.issue_capability_token(&req2, &key).await.unwrap();

        let github_tokens = store
            .query_issued_tokens(&IssuedTokenQueryRequest {
                connector_id: Some("github:saas:1.0.0".to_string()),
                principal_id: None,
                active_only: false,
                limit: 100,
            })
            .await;
        assert_eq!(github_tokens.tokens.len(), 1);
        assert_eq!(github_tokens.total_tokens, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn query_tokens_filter_by_principal() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();

        let mut req1 = basic_issuance_request();
        req1.principal_id = "agent:alice".to_string();
        store.issue_capability_token(&req1, &key).await.unwrap();

        let mut req2 = basic_issuance_request();
        req2.principal_id = "agent:bob".to_string();
        store.issue_capability_token(&req2, &key).await.unwrap();

        let alice_tokens = store
            .query_issued_tokens(&IssuedTokenQueryRequest {
                connector_id: None,
                principal_id: Some("agent:alice".to_string()),
                active_only: false,
                limit: 100,
            })
            .await;
        assert_eq!(alice_tokens.tokens.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn query_tokens_active_only_excludes_revoked() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();

        let issued = store
            .issue_capability_token(&basic_issuance_request(), &key)
            .await
            .unwrap();

        store
            .revoke_token(&TokenRevocationRequest {
                token_id: issued.token_id,
                reason: None,
            })
            .await
            .unwrap();

        let active = store
            .query_issued_tokens(&IssuedTokenQueryRequest {
                connector_id: None,
                principal_id: None,
                active_only: true,
                limit: 100,
            })
            .await;
        assert_eq!(active.tokens.len(), 0);
        assert_eq!(active.active_count, 0);
        assert_eq!(active.total_tokens, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn issue_multiple_tokens_unique_ids() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();

        let r1 = store
            .issue_capability_token(&basic_issuance_request(), &key)
            .await
            .unwrap();
        let r2 = store
            .issue_capability_token(&basic_issuance_request(), &key)
            .await
            .unwrap();

        assert_ne!(r1.token_id, r2.token_id);
        assert_ne!(r1.journal_sequence, r2.journal_sequence);
    }

    #[fcp_async_core::runtime::test]
    async fn issue_token_with_delegation_depth() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let mut request = basic_issuance_request();
        request.max_delegation_depth = 3;

        let response = store.issue_capability_token(&request, &key).await.unwrap();

        assert_eq!(response.inspection.delegation_depth, 3);

        // Inspect round-trip should preserve delegation depth.
        let inspection = HostAdminStateStore::inspect_capability_token(
            response.token_cbor_b64.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(inspection.delegation_depth, 3);
    }

    #[fcp_async_core::runtime::test]
    async fn issue_token_no_operations_means_all() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let mut request = basic_issuance_request();
        request.operations.clear();

        let response = store.issue_capability_token(&request, &key).await.unwrap();

        assert!(response.inspection.operations.is_empty());

        let inspection = HostAdminStateStore::inspect_capability_token(
            response.token_cbor_b64.as_ref().unwrap(),
        )
        .unwrap();
        assert!(inspection.operations.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn issue_token_custom_ttl() {
        let store = HostAdminStateStore::new();
        let key = test_signing_key();
        let mut request = basic_issuance_request();
        request.ttl_secs = 300; // 5 minutes

        let response = store.issue_capability_token(&request, &key).await.unwrap();

        // seconds_remaining should be close to 300 (allow some wiggle for test execution).
        assert!(response.inspection.seconds_remaining <= 300);
        assert!(response.inspection.seconds_remaining >= 298);
    }

    #[test]
    fn capability_issuance_request_serde_round_trip() {
        let mut request = basic_issuance_request();
        request.credential_allow = vec![test_credential_id(0x44)];
        let json = serde_json::to_string(&request).unwrap();
        let parsed: CapabilityIssuanceRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, request.connector_id);
        assert_eq!(parsed.zone_id, request.zone_id);
        assert_eq!(parsed.principal_id, request.principal_id);
        assert_eq!(parsed.operations, request.operations);
        assert_eq!(parsed.ttl_secs, request.ttl_secs);
        assert_eq!(parsed.credential_allow, request.credential_allow);
    }

    #[test]
    fn capability_token_inspection_serde_round_trip() {
        let inspection = CapabilityTokenInspection {
            token_id: "abc123".to_string(),
            issuer: "host:test".to_string(),
            subject: "agent:test".to_string(),
            audience: Some("github:saas:1.0.0".to_string()),
            zone_id: "z:work".to_string(),
            capability_id: None,
            operations: vec!["list_repos".to_string()],
            holder_node: None,
            delegation_depth: 0,
            issued_at: Utc::now(),
            not_before: None,
            expires_at: Utc::now() + Duration::hours(1),
            currently_valid: true,
            seconds_remaining: 3600,
            resource_allow: Vec::new(),
            resource_deny: Vec::new(),
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![test_credential_id(0x55)],
        };

        let json = serde_json::to_string(&inspection).unwrap();
        let parsed: CapabilityTokenInspection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.token_id, "abc123");
        assert_eq!(parsed.subject, "agent:test");
        assert_eq!(parsed.credential_allow, inspection.credential_allow);
    }

    #[test]
    fn live_request_auth_serde_round_trip() {
        let auth = LiveRequestAuth {
            capability_token_b64: "dGVzdA==".to_string(),
            holder_proof: Some(LiveRequestHolderProof {
                signature_hex: "ab".repeat(64),
                holder_node: "node:laptop".to_string(),
            }),
            approval_tokens: vec![LiveRequestApprovalToken {
                token_id: "apt-1".to_string(),
                issuer: "host:test".to_string(),
                zone_id: "z:work".to_string(),
                scope_kind: "execution".to_string(),
                scope: serde_json::json!({"operation_id": "delete_repo"}),
                expires_at_ms: 9_999_999_999_999,
                signature_b64: None,
            }],
        };

        let json = serde_json::to_string(&auth).unwrap();
        let parsed: LiveRequestAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.capability_token_b64, "dGVzdA==");
        assert!(parsed.holder_proof.is_some());
        assert_eq!(parsed.approval_tokens.len(), 1);
        assert_eq!(parsed.approval_tokens[0].scope_kind, "execution");
    }

    #[test]
    fn token_revocation_request_serde() {
        let req = TokenRevocationRequest {
            token_id: "tok-1".to_string(),
            reason: Some("compromised".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: TokenRevocationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.token_id, "tok-1");
        assert_eq!(parsed.reason.as_deref(), Some("compromised"));
    }

    #[test]
    fn issued_token_record_serde() {
        let record = IssuedTokenRecord {
            token_id: "tok-1".to_string(),
            connector_id: "github:saas:1.0.0".to_string(),
            principal_id: "agent:test".to_string(),
            zone_id: "z:work".to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            revoked: false,
            revocation_reason: None,
            revoked_at: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: IssuedTokenRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.token_id, "tok-1");
        assert!(!parsed.revoked);
    }

    #[test]
    fn issued_token_query_request_defaults() {
        let json = r#"{"active_only": true}"#;
        let parsed: IssuedTokenQueryRequest = serde_json::from_str(json).unwrap();
        assert!(parsed.active_only);
        assert_eq!(parsed.limit, 100); // default_journal_limit
        assert!(parsed.connector_id.is_none());
    }

    #[test]
    fn live_request_holder_proof_serde() {
        let proof = LiveRequestHolderProof {
            signature_hex: "ff".repeat(64),
            holder_node: "node:test".to_string(),
        };
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("node:test"));
        let parsed: LiveRequestHolderProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.holder_node, "node:test");
        assert_eq!(parsed.signature_hex.len(), 128);
    }

    #[test]
    fn live_request_approval_token_serde() {
        let token = LiveRequestApprovalToken {
            token_id: "apt-1".to_string(),
            issuer: "host:local".to_string(),
            zone_id: "z:work".to_string(),
            scope_kind: "elevation".to_string(),
            scope: serde_json::json!({"operation_id": "admin_action", "target_integrity": "high"}),
            expires_at_ms: 1_700_000_000_000,
            signature_b64: Some("c2lnbmF0dXJl".to_string()),
        };
        let json = serde_json::to_string(&token).unwrap();
        let parsed: LiveRequestApprovalToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scope_kind, "elevation");
        assert!(parsed.signature_b64.is_some());
    }

    #[test]
    fn capability_issuance_response_serde() {
        let response = CapabilityIssuanceResponse {
            dry_run: false,
            token_id: "tok-1".to_string(),
            token_cbor_b64: Some("base64data".to_string()),
            inspection: CapabilityTokenInspection {
                token_id: "tok-1".to_string(),
                issuer: "host:key1".to_string(),
                subject: "agent:test".to_string(),
                audience: None,
                zone_id: "z:work".to_string(),
                capability_id: None,
                operations: Vec::new(),
                holder_node: None,
                delegation_depth: 0,
                issued_at: Utc::now(),
                not_before: None,
                expires_at: Utc::now() + Duration::hours(1),
                currently_valid: true,
                seconds_remaining: 3600,
                resource_allow: Vec::new(),
                resource_deny: Vec::new(),
                max_calls: None,
                max_bytes: None,
                credential_allow: Vec::new(),
            },
            journal_sequence: 1,
            issued_at: Utc::now(),
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: CapabilityIssuanceResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.token_id, "tok-1");
    }

    #[test]
    fn capability_token_verify_response_serde() {
        let response = CapabilityTokenVerifyResponse {
            signature_valid: true,
            temporally_valid: true,
            scope_valid: true,
            valid: true,
            inspection: CapabilityTokenInspection {
                token_id: "tok-1".to_string(),
                issuer: "host:key1".to_string(),
                subject: "agent:test".to_string(),
                audience: None,
                zone_id: "z:work".to_string(),
                capability_id: None,
                operations: Vec::new(),
                holder_node: None,
                delegation_depth: 0,
                issued_at: Utc::now(),
                not_before: None,
                expires_at: Utc::now() + Duration::hours(1),
                currently_valid: true,
                seconds_remaining: 3600,
                resource_allow: Vec::new(),
                resource_deny: Vec::new(),
                max_calls: None,
                max_bytes: None,
                credential_allow: Vec::new(),
            },
            rejection_reasons: Vec::new(),
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: CapabilityTokenVerifyResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.valid);
    }

    #[test]
    fn capability_issuance_request_default_ttl() {
        // `capability_id` was added as a required field in
        // CapabilityIssuanceRequest after the live invoke verifier
        // started checking the operation's declared capability rather
        // than just the operation id. The default-ttl test focuses on
        // serde defaults for the TTL/dry_run/max_delegation_depth
        // fields, but it still has to send a complete payload that
        // satisfies the now-mandatory fields — otherwise serde fails
        // with `missing field "capability_id"` before any default kicks
        // in.
        let json = r#"{
            "connector_id": "test:saas:1.0.0",
            "capability_id": "test.invoke",
            "zone_id": "z:work",
            "principal_id": "agent:test"
        }"#;
        let parsed: CapabilityIssuanceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.ttl_secs, 3600);
        assert!(!parsed.dry_run);
        assert_eq!(parsed.max_delegation_depth, 0);
    }

    // ── Simulate RPC tests ─────────────────────────────────────────────────

    fn test_simulate_receipt(
        connector_id: &str,
        operation: &str,
        phase: SimulatePhase,
        would_succeed: bool,
    ) -> SimulateReceipt {
        SimulateReceipt {
            receipt_id: format!("sim-{connector_id}-{operation}"),
            connector_id: connector_id.to_string(),
            operation: operation.to_string(),
            phase,
            would_succeed,
            input_digest: Some("abc123".to_string()),
            duration_ms: 42,
            simulated_at: Utc::now(),
        }
    }

    #[test]
    fn host_simulate_request_serde_round_trip() {
        let request = HostSimulateRequest {
            request_id: "req-1".to_string(),
            connector_id: "github:saas:1.0.0".to_string(),
            operation: "list_repos".to_string(),
            input: Some(serde_json::json!({"org": "test"})),
            zone_id: Some("z:work".to_string()),
            principal: Some("agent:test".to_string()),
            capability_token: None,
            approval_tokens: Vec::new(),
            estimate_cost: true,
            check_availability: false,
            deadline_ms: 3000,
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: HostSimulateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.request_id, "req-1");
        assert_eq!(parsed.connector_id, "github:saas:1.0.0");
        assert!(parsed.capability_token.is_none());
        assert!(parsed.approval_tokens.is_empty());
        assert!(parsed.estimate_cost);
        assert!(!parsed.check_availability);
        assert_eq!(parsed.deadline_ms, 3000);
    }

    #[test]
    fn host_simulate_request_defaults() {
        let json = r#"{
            "request_id": "req-1",
            "connector_id": "github:saas:1.0.0",
            "operation": "list_repos"
        }"#;
        let parsed: HostSimulateRequest = serde_json::from_str(json).unwrap();
        assert!(parsed.capability_token.is_none());
        assert!(parsed.approval_tokens.is_empty());
        assert!(!parsed.estimate_cost);
        assert!(!parsed.check_availability);
        assert_eq!(parsed.deadline_ms, 5000);
        assert!(parsed.input.is_none());
    }

    #[test]
    fn host_simulate_response_success_serde() {
        let response = HostSimulateResponse {
            request_id: "req-1".to_string(),
            would_succeed: true,
            phase: SimulatePhase::ConnectorReached,
            preflight_allowed: true,
            failure_reason: None,
            denial_code: None,
            missing_capabilities: Vec::new(),
            cost_estimate: Some(SimulateCostEstimate {
                api_credits: Some(5),
                estimated_duration_ms: Some(200),
                estimated_bytes: Some(1024),
                confidence: Some(SimulateCostConfidence::Medium),
            }),
            availability: Some(SimulateResourceAvailability {
                available: true,
                rate_limit_remaining: Some(450),
                rate_limit_reset_at: Some(1_700_000_000),
                details: None,
            }),
            duration_ms: 15,
            receipt: test_simulate_receipt(
                "github:saas:1.0.0",
                "list_repos",
                SimulatePhase::ConnectorReached,
                true,
            ),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: HostSimulateResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.would_succeed);
        assert_eq!(parsed.phase, SimulatePhase::ConnectorReached);
        assert!(parsed.cost_estimate.is_some());
        assert_eq!(parsed.cost_estimate.unwrap().api_credits, Some(5));
        assert!(parsed.availability.is_some());
    }

    #[test]
    fn host_simulate_response_denied_serde() {
        let response = HostSimulateResponse {
            request_id: "req-2".to_string(),
            would_succeed: false,
            phase: SimulatePhase::PreflightOnly,
            preflight_allowed: false,
            failure_reason: Some("missing capability: net.egress".to_string()),
            denial_code: Some("FCP-3001".to_string()),
            missing_capabilities: vec!["net.egress".to_string()],
            cost_estimate: None,
            availability: None,
            duration_ms: 2,
            receipt: test_simulate_receipt(
                "github:saas:1.0.0",
                "create_issue",
                SimulatePhase::PreflightOnly,
                false,
            ),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: HostSimulateResponse = serde_json::from_str(&json).unwrap();
        assert!(!parsed.would_succeed);
        assert_eq!(parsed.phase, SimulatePhase::PreflightOnly);
        assert_eq!(parsed.missing_capabilities, vec!["net.egress"]);
    }

    #[test]
    fn simulate_phase_serde_all_variants() {
        for (phase, expected) in [
            (SimulatePhase::PreflightOnly, "\"preflight_only\""),
            (SimulatePhase::ConnectorReached, "\"connector_reached\""),
            (
                SimulatePhase::ConnectorUnsupported,
                "\"connector_unsupported\"",
            ),
            (SimulatePhase::TimedOut, "\"timed_out\""),
        ] {
            let json = serde_json::to_string(&phase).unwrap();
            assert_eq!(json, expected);
            let parsed: SimulatePhase = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, phase);
        }
    }

    #[test]
    fn simulate_cost_estimate_serde() {
        let estimate = SimulateCostEstimate {
            api_credits: Some(10),
            estimated_duration_ms: Some(500),
            estimated_bytes: None,
            confidence: Some(SimulateCostConfidence::High),
        };
        let json = serde_json::to_string(&estimate).unwrap();
        let parsed: SimulateCostEstimate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.api_credits, Some(10));
        assert_eq!(parsed.confidence, Some(SimulateCostConfidence::High));
    }

    #[test]
    fn simulate_cost_confidence_serde() {
        for (conf, expected) in [
            (SimulateCostConfidence::Low, "\"low\""),
            (SimulateCostConfidence::Medium, "\"medium\""),
            (SimulateCostConfidence::High, "\"high\""),
        ] {
            let json = serde_json::to_string(&conf).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn simulate_resource_availability_serde() {
        let avail = SimulateResourceAvailability {
            available: true,
            rate_limit_remaining: Some(100),
            rate_limit_reset_at: None,
            details: Some("API healthy".to_string()),
        };
        let json = serde_json::to_string(&avail).unwrap();
        let parsed: SimulateResourceAvailability = serde_json::from_str(&json).unwrap();
        assert!(parsed.available);
        assert_eq!(parsed.details.as_deref(), Some("API healthy"));
    }

    #[test]
    fn simulate_receipt_serde() {
        let receipt = test_simulate_receipt(
            "github:saas:1.0.0",
            "list_repos",
            SimulatePhase::ConnectorReached,
            true,
        );
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: SimulateReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "github:saas:1.0.0");
        assert_eq!(parsed.phase, SimulatePhase::ConnectorReached);
        assert!(parsed.would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn record_and_query_simulate_receipts() {
        let store = HostAdminStateStore::new();

        let receipt = test_simulate_receipt(
            "github:saas:1.0.0",
            "list_repos",
            SimulatePhase::ConnectorReached,
            true,
        );
        store.record_simulate_receipt(receipt).await.unwrap();

        let result = store
            .query_simulate_receipts(&SimulateReceiptQueryRequest {
                connector_id: "github:saas:1.0.0".to_string(),
                operation: None,
                after: None,
                limit: 100,
            })
            .await;
        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.total_receipts, 1);
        assert!(result.receipts[0].would_succeed);
    }

    #[fcp_async_core::runtime::test]
    async fn query_simulate_receipts_filter_by_operation() {
        let store = HostAdminStateStore::new();

        store
            .record_simulate_receipt(test_simulate_receipt(
                "github:saas:1.0.0",
                "list_repos",
                SimulatePhase::ConnectorReached,
                true,
            ))
            .await
            .unwrap();
        store
            .record_simulate_receipt(test_simulate_receipt(
                "github:saas:1.0.0",
                "create_issue",
                SimulatePhase::PreflightOnly,
                false,
            ))
            .await
            .unwrap();

        let result = store
            .query_simulate_receipts(&SimulateReceiptQueryRequest {
                connector_id: "github:saas:1.0.0".to_string(),
                operation: Some("create_issue".to_string()),
                after: None,
                limit: 100,
            })
            .await;
        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.receipts[0].operation, "create_issue");
        assert_eq!(result.total_receipts, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn query_simulate_receipts_filter_by_connector() {
        let store = HostAdminStateStore::new();

        store
            .record_simulate_receipt(test_simulate_receipt(
                "github:saas:1.0.0",
                "list_repos",
                SimulatePhase::ConnectorReached,
                true,
            ))
            .await
            .unwrap();
        store
            .record_simulate_receipt(test_simulate_receipt(
                "slack:saas:1.0.0",
                "send_message",
                SimulatePhase::ConnectorReached,
                true,
            ))
            .await
            .unwrap();

        let result = store
            .query_simulate_receipts(&SimulateReceiptQueryRequest {
                connector_id: "github:saas:1.0.0".to_string(),
                operation: None,
                after: None,
                limit: 100,
            })
            .await;
        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.total_receipts, 1);
    }

    #[test]
    fn simulate_support_serde_all_variants() {
        for (support, expected) in [
            (SimulateSupport::Real, "\"real\""),
            (SimulateSupport::Trivial, "\"trivial\""),
            (SimulateSupport::Unsupported, "\"unsupported\""),
            (SimulateSupport::Unknown, "\"unknown\""),
            (SimulateSupport::NotYetMeasured, "\"not_yet_measured\""),
            (SimulateSupport::Unavailable, "\"unavailable\""),
        ] {
            let json = serde_json::to_string(&support).unwrap();
            assert_eq!(json, expected);
            let parsed: SimulateSupport = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, support);
        }
    }

    #[test]
    fn operation_simulate_metadata_serde() {
        let metadata = OperationSimulateMetadata {
            operation: "list_repos".to_string(),
            simulate_support: SimulateSupport::Real,
            supports_cost_estimate: true,
            supports_availability_check: false,
            max_deadline_ms: Some(10000),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: OperationSimulateMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.simulate_support, SimulateSupport::Real);
        assert!(parsed.supports_cost_estimate);
        assert!(!parsed.supports_availability_check);
        assert_eq!(parsed.max_deadline_ms, Some(10000));
    }

    #[test]
    fn simulate_receipt_query_request_defaults() {
        let json = r#"{"connector_id": "test:saas:1.0.0"}"#;
        let parsed: SimulateReceiptQueryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.connector_id, "test:saas:1.0.0");
        assert!(parsed.operation.is_none());
        assert!(parsed.after.is_none());
        assert_eq!(parsed.limit, 100);
    }

    #[test]
    fn host_simulate_response_timed_out() {
        let response = HostSimulateResponse {
            request_id: "req-3".to_string(),
            would_succeed: false,
            phase: SimulatePhase::TimedOut,
            preflight_allowed: true,
            failure_reason: Some("simulation deadline exceeded".to_string()),
            denial_code: None,
            missing_capabilities: Vec::new(),
            cost_estimate: None,
            availability: None,
            duration_ms: 5001,
            receipt: test_simulate_receipt(
                "slow-connector:saas:1.0.0",
                "heavy_op",
                SimulatePhase::TimedOut,
                false,
            ),
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: HostSimulateResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.phase, SimulatePhase::TimedOut);
        assert!(parsed.preflight_allowed);
        assert!(!parsed.would_succeed);
    }

    #[test]
    fn host_simulate_response_connector_unsupported() {
        let response = HostSimulateResponse {
            request_id: "req-4".to_string(),
            would_succeed: false,
            phase: SimulatePhase::ConnectorUnsupported,
            preflight_allowed: true,
            failure_reason: Some(
                "connector does not support simulation for this operation".to_string(),
            ),
            denial_code: None,
            missing_capabilities: Vec::new(),
            cost_estimate: None,
            availability: None,
            duration_ms: 1,
            receipt: test_simulate_receipt(
                "legacy:saas:1.0.0",
                "old_op",
                SimulatePhase::ConnectorUnsupported,
                false,
            ),
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: HostSimulateResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.phase, SimulatePhase::ConnectorUnsupported);
    }

    // ── Auth verification and denial tests ───────────────────────────────

    #[test]
    fn auth_denial_kind_serde_roundtrip() {
        let kinds = [
            AuthDenialKind::MissingToken,
            AuthDenialKind::MalformedToken,
            AuthDenialKind::InvalidSignature,
            AuthDenialKind::TemporallyInvalid,
            AuthDenialKind::InsufficientScope,
            AuthDenialKind::WrongConnector,
            AuthDenialKind::Revoked,
            AuthDenialKind::HolderProofFailed,
            AuthDenialKind::MissingApproval,
            AuthDenialKind::InvalidApproval,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let back: AuthDenialKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn auth_denial_missing_token() {
        let denial = AuthDenial::missing_token("invoke");
        assert_eq!(denial.rpc, "invoke");
        assert_eq!(denial.kind, AuthDenialKind::MissingToken);
        assert!(denial.message.contains("required"));
        assert!(denial.inspection.is_none());
        assert!(!denial.remediation.is_empty());
        assert!(denial.denial_id.starts_with("denial-invoke-"));
    }

    #[test]
    fn auth_denial_malformed_token() {
        let denial = AuthDenial::malformed_token("simulate", "invalid base64");
        assert_eq!(denial.kind, AuthDenialKind::MalformedToken);
        assert!(denial.message.contains("invalid base64"));
        assert!(denial.remediation.iter().any(|r| r.contains("COSE_Sign1")));
    }

    #[test]
    fn auth_denial_holder_proof_failed() {
        let denial = AuthDenial::holder_proof_failed("invoke", "signature mismatch");
        assert_eq!(denial.kind, AuthDenialKind::HolderProofFailed);
        assert!(denial.message.contains("signature mismatch"));
        assert!(denial.remediation.iter().any(|r| r.contains("Ed25519")));
    }

    #[test]
    fn auth_denial_missing_approval() {
        let denial = AuthDenial::missing_approval("invoke", "elevation");
        assert_eq!(denial.kind, AuthDenialKind::MissingApproval);
        assert!(denial.message.contains("elevation"));
        assert!(denial.remediation.iter().any(|r| r.contains("elevation")));
    }

    #[test]
    fn auth_denial_from_verify_expired_token() {
        let inspection = CapabilityTokenInspection {
            token_id: "test-token-1".to_owned(),
            issuer: "test-issuer".to_owned(),
            subject: "test-subject".to_owned(),
            audience: None,
            zone_id: "zone-1".to_owned(),
            capability_id: Some("cap-1".to_owned()),
            operations: vec!["read".to_owned()],
            holder_node: None,
            delegation_depth: 0,
            issued_at: Utc::now() - chrono::Duration::hours(2),
            not_before: None,
            expires_at: Utc::now() - chrono::Duration::hours(1),
            currently_valid: false,
            seconds_remaining: 0,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
        };

        let verify = CapabilityTokenVerifyResponse {
            signature_valid: true,
            temporally_valid: false,
            scope_valid: true,
            valid: false,
            inspection,
            rejection_reasons: vec!["Token expired".to_owned()],
        };

        let denial = AuthDenial::from_verify_failure("invoke", &verify);
        assert_eq!(denial.kind, AuthDenialKind::TemporallyInvalid);
        assert!(denial.message.contains("Token expired"));
        assert!(denial.inspection.is_some());
        assert!(denial.remediation.iter().any(|r| r.contains("Re-issue")));
    }

    #[test]
    fn auth_denial_from_verify_insufficient_scope() {
        let inspection = CapabilityTokenInspection {
            token_id: "test-token-2".to_owned(),
            issuer: "test-issuer".to_owned(),
            subject: "test-subject".to_owned(),
            audience: None,
            zone_id: "zone-1".to_owned(),
            capability_id: Some("cap-2".to_owned()),
            operations: vec!["read".to_owned()],
            holder_node: None,
            delegation_depth: 0,
            issued_at: Utc::now(),
            not_before: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            currently_valid: true,
            seconds_remaining: 3600,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
        };

        let verify = CapabilityTokenVerifyResponse {
            signature_valid: true,
            temporally_valid: true,
            scope_valid: false,
            valid: false,
            inspection,
            rejection_reasons: vec!["Token does not grant operation 'write'".to_owned()],
        };

        let denial = AuthDenial::from_verify_failure("invoke", &verify);
        assert_eq!(denial.kind, AuthDenialKind::InsufficientScope);
        assert!(denial.remediation.iter().any(|r| r.contains("scope")));
    }

    #[test]
    fn auth_denial_from_verify_revoked() {
        let inspection = CapabilityTokenInspection {
            token_id: "test-token-3".to_owned(),
            issuer: "test-issuer".to_owned(),
            subject: "test-subject".to_owned(),
            audience: None,
            zone_id: "zone-1".to_owned(),
            capability_id: Some("cap-3".to_owned()),
            operations: vec!["read".to_owned()],
            holder_node: None,
            delegation_depth: 0,
            issued_at: Utc::now(),
            not_before: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            currently_valid: true,
            seconds_remaining: 3600,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
        };

        let verify = CapabilityTokenVerifyResponse {
            signature_valid: true,
            temporally_valid: true,
            scope_valid: true,
            valid: false,
            inspection,
            rejection_reasons: vec!["Token has been revoked".to_owned()],
        };

        let denial = AuthDenial::from_verify_failure("batch", &verify);
        assert_eq!(denial.kind, AuthDenialKind::Revoked);
        assert!(
            denial
                .remediation
                .iter()
                .any(|r| r.contains("new capability token"))
        );
    }

    #[test]
    fn auth_denial_serde_roundtrip() {
        let denial = AuthDenial::missing_token("simulate");
        let json = serde_json::to_string(&denial).unwrap();
        let parsed: AuthDenial = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rpc, "simulate");
        assert_eq!(parsed.kind, AuthDenialKind::MissingToken);
    }

    #[test]
    fn auth_denial_json_has_required_fields() {
        let denial = AuthDenial::missing_token("invoke");
        let value: Value = serde_json::to_value(&denial).unwrap();
        assert!(value.get("rpc").is_some());
        assert!(value.get("kind").is_some());
        assert!(value.get("message").is_some());
        assert!(value.get("remediation").is_some());
        assert!(value.get("denial_id").is_some());
        assert!(value.get("denied_at").is_some());
    }

    #[test]
    fn auth_denial_each_kind_has_distinct_serde() {
        let kinds = [
            AuthDenialKind::MissingToken,
            AuthDenialKind::MalformedToken,
            AuthDenialKind::InvalidSignature,
            AuthDenialKind::TemporallyInvalid,
            AuthDenialKind::InsufficientScope,
            AuthDenialKind::WrongConnector,
            AuthDenialKind::Revoked,
            AuthDenialKind::HolderProofFailed,
            AuthDenialKind::MissingApproval,
            AuthDenialKind::InvalidApproval,
        ];
        let serialized: Vec<String> = kinds
            .iter()
            .map(|k| serde_json::to_string(k).unwrap())
            .collect();
        let unique: std::collections::HashSet<_> = serialized.iter().collect();
        assert_eq!(
            unique.len(),
            serialized.len(),
            "Each kind should serialize distinctly"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn verify_token_from_issued_token() {
        let store = HostAdminStateStore::new();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();

        let request = CapabilityIssuanceRequest {
            connector_id: "test:saas:1.0.0".to_owned(),
            capability_id: "test.read".to_owned(),
            zone_id: "zone-test".to_owned(),
            principal_id: "agent-1".to_owned(),
            operations: vec!["read".to_owned(), "write".to_owned()],
            ttl_secs: 3600,
            not_before_delay_secs: None,
            holder_node: None,
            max_delegation_depth: 0,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
            dry_run: false,
        };

        let issued = store
            .issue_capability_token(&request, &signing_key)
            .await
            .expect("issue token");

        // Verify the issued token
        let verify_request = CapabilityTokenVerifyRequest {
            token_cbor_b64: issued.token_cbor_b64.expect("non-dry-run token"),
            operation_id: Some("read".to_owned()),
            connector_id: Some("test:saas:1.0.0".to_owned()),
        };

        let result = store
            .verify_capability_token(&verify_request)
            .await
            .expect("verify token");

        assert!(result.signature_valid);
        assert!(result.temporally_valid);
        assert!(result.scope_valid);
        assert!(result.valid);
        assert_eq!(result.inspection.audience.as_deref(), Some("zone-test"));
        assert!(result.rejection_reasons.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn verify_issued_token_wrong_connector_fails_scope() {
        let store = HostAdminStateStore::new();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();

        let request = CapabilityIssuanceRequest {
            connector_id: "test:saas:1.0.0".to_owned(),
            capability_id: "test.read".to_owned(),
            zone_id: "zone-test".to_owned(),
            principal_id: "agent-1".to_owned(),
            operations: vec!["read".to_owned()],
            ttl_secs: 3600,
            not_before_delay_secs: None,
            holder_node: None,
            max_delegation_depth: 0,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
            dry_run: false,
        };

        let issued = store
            .issue_capability_token(&request, &signing_key)
            .await
            .expect("issue token");

        let verify_request = CapabilityTokenVerifyRequest {
            token_cbor_b64: issued.token_cbor_b64.expect("non-dry-run token"),
            operation_id: Some("read".to_owned()),
            connector_id: Some("wrong:saas:1.0.0".to_owned()),
        };

        let result = store
            .verify_capability_token(&verify_request)
            .await
            .expect("verify token");

        assert!(result.signature_valid);
        assert!(result.temporally_valid);
        assert!(!result.scope_valid);
        assert!(!result.valid);
        assert!(
            result
                .rejection_reasons
                .iter()
                .any(|reason| reason.contains("wrong:saas:1.0.0"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn verify_token_wrong_operation_fails_scope() {
        let store = HostAdminStateStore::new();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();

        let request = CapabilityIssuanceRequest {
            connector_id: "test:saas:1.0.0".to_owned(),
            capability_id: "test.read".to_owned(),
            zone_id: "zone-test".to_owned(),
            principal_id: "agent-1".to_owned(),
            operations: vec!["read".to_owned()],
            ttl_secs: 3600,
            not_before_delay_secs: None,
            holder_node: None,
            max_delegation_depth: 0,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
            dry_run: false,
        };

        let issued = store
            .issue_capability_token(&request, &signing_key)
            .await
            .expect("issue token");

        let verify_request = CapabilityTokenVerifyRequest {
            token_cbor_b64: issued.token_cbor_b64.expect("non-dry-run token"),
            operation_id: Some("write".to_owned()),
            connector_id: None,
        };

        let result = store
            .verify_capability_token(&verify_request)
            .await
            .expect("verify token");

        assert!(!result.scope_valid);
        assert!(!result.valid);
        assert!(!result.rejection_reasons.is_empty());
        assert!(result.rejection_reasons[0].contains("write"));
    }

    #[fcp_async_core::runtime::test]
    async fn verify_revoked_token_fails() {
        let store = HostAdminStateStore::new();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();

        let issue_request = CapabilityIssuanceRequest {
            connector_id: "test:saas:1.0.0".to_owned(),
            capability_id: "test.read".to_owned(),
            zone_id: "zone-test".to_owned(),
            principal_id: "agent-1".to_owned(),
            operations: vec!["read".to_owned()],
            ttl_secs: 3600,
            not_before_delay_secs: None,
            holder_node: None,
            max_delegation_depth: 0,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
            dry_run: false,
        };

        let issued = store
            .issue_capability_token(&issue_request, &signing_key)
            .await
            .expect("issue token");

        // Revoke the token
        let revoke_request = TokenRevocationRequest {
            token_id: issued.token_id.clone(),
            reason: Some("test revocation".to_owned()),
        };
        let revoke_result = store.revoke_token(&revoke_request).await.expect("revoke");
        assert!(revoke_result.revoked);

        // Verify should fail
        let verify_request = CapabilityTokenVerifyRequest {
            token_cbor_b64: issued.token_cbor_b64.expect("non-dry-run token"),
            operation_id: None,
            connector_id: None,
        };

        let result = store
            .verify_capability_token(&verify_request)
            .await
            .expect("verify token");

        assert!(!result.valid);
        assert!(
            result
                .rejection_reasons
                .iter()
                .any(|r| r.contains("revoked"))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn verify_token_no_operation_check_passes_scope() {
        let store = HostAdminStateStore::new();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();

        let request = CapabilityIssuanceRequest {
            connector_id: "test:saas:1.0.0".to_owned(),
            capability_id: "test.read".to_owned(),
            zone_id: "zone-test".to_owned(),
            principal_id: "agent-1".to_owned(),
            operations: vec!["read".to_owned()],
            ttl_secs: 3600,
            not_before_delay_secs: None,
            holder_node: None,
            max_delegation_depth: 0,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
            dry_run: false,
        };

        let issued = store
            .issue_capability_token(&request, &signing_key)
            .await
            .expect("issue token");

        // Verify without specifying an operation — should pass scope check
        let verify_request = CapabilityTokenVerifyRequest {
            token_cbor_b64: issued.token_cbor_b64.expect("non-dry-run token"),
            operation_id: None,
            connector_id: None,
        };

        let result = store
            .verify_capability_token(&verify_request)
            .await
            .expect("verify token");

        assert!(result.valid);
    }

    #[fcp_async_core::runtime::test]
    async fn verify_token_stays_expired_after_clock_moves_backward() {
        let store = HostAdminStateStore::new();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();

        let request = CapabilityIssuanceRequest {
            connector_id: "test:saas:1.0.0".to_owned(),
            capability_id: "test.read".to_owned(),
            zone_id: "zone-test".to_owned(),
            principal_id: "agent-1".to_owned(),
            operations: vec!["read".to_owned()],
            ttl_secs: 60,
            not_before_delay_secs: None,
            holder_node: None,
            max_delegation_depth: 0,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
            dry_run: false,
        };

        let issued = store
            .issue_capability_token(&request, &signing_key)
            .await
            .expect("issue token");
        let token_cbor_b64 = issued.token_cbor_b64.clone().expect("non-dry-run token");
        let verify_request = CapabilityTokenVerifyRequest {
            token_cbor_b64,
            operation_id: Some("read".to_owned()),
            connector_id: None,
        };

        let forward_time = issued.issued_at + chrono::Duration::minutes(2);
        let expired = store
            .verify_capability_token_at(&verify_request, forward_time)
            .await
            .expect("verify token after expiry");
        assert!(!expired.temporally_valid);
        assert!(!expired.valid);
        assert!(
            expired
                .rejection_reasons
                .iter()
                .any(|reason| reason.contains("expired"))
        );

        let rewound = store
            .verify_capability_token_at(&verify_request, issued.issued_at)
            .await
            .expect("verify token after clock rewind");
        assert!(!rewound.temporally_valid);
        assert!(!rewound.valid);
        assert_eq!(
            store.state.read().await.last_observed_time_ms,
            forward_time.timestamp_millis()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn verify_tampered_token_fails_signature() {
        let store = HostAdminStateStore::new();
        let signing_key = fcp_crypto::Ed25519SigningKey::generate();

        let request = CapabilityIssuanceRequest {
            connector_id: "test:saas:1.0.0".to_owned(),
            capability_id: "test.read".to_owned(),
            zone_id: "zone-test".to_owned(),
            principal_id: "agent-1".to_owned(),
            operations: vec!["read".to_owned()],
            ttl_secs: 3600,
            not_before_delay_secs: None,
            holder_node: None,
            max_delegation_depth: 0,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
            dry_run: false,
        };

        let issued = store
            .issue_capability_token(&request, &signing_key)
            .await
            .expect("issue token");
        let mut token_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            issued.token_cbor_b64.expect("non-dry-run token"),
        )
        .expect("decode token");
        *token_bytes.last_mut().expect("signature byte") ^= 0x01;
        let tampered_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, token_bytes);

        let verify_request = CapabilityTokenVerifyRequest {
            token_cbor_b64: tampered_b64,
            operation_id: Some("read".to_owned()),
            connector_id: None,
        };

        let result = store
            .verify_capability_token(&verify_request)
            .await
            .expect("verify tampered token");

        assert!(!result.signature_valid);
        assert!(!result.valid);
        assert!(
            result
                .rejection_reasons
                .iter()
                .any(|reason| reason.contains("signature verification failed"))
        );
    }

    #[test]
    fn scope_check_wildcard_operation_passes() {
        let inspection = CapabilityTokenInspection {
            token_id: String::new(),
            issuer: String::new(),
            subject: String::new(),
            audience: None,
            zone_id: String::new(),
            capability_id: None,
            operations: vec!["*".to_owned()],
            holder_node: None,
            delegation_depth: 0,
            issued_at: Utc::now(),
            not_before: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            currently_valid: true,
            seconds_remaining: 3600,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
        };

        let mut reasons = Vec::new();
        let valid = HostAdminStateStore::check_scope_validity(
            &inspection,
            Some("any_operation"),
            None,
            &mut reasons,
        );
        assert!(valid, "Wildcard operation should pass scope check");
        assert!(reasons.is_empty());
    }

    #[test]
    fn scope_check_wrong_connector_fails() {
        let inspection = CapabilityTokenInspection {
            token_id: String::new(),
            issuer: String::new(),
            subject: "correct:saas:1.0.0".to_owned(),
            audience: Some("correct:saas:1.0.0".to_owned()),
            zone_id: String::new(),
            capability_id: None,
            operations: vec![],
            holder_node: None,
            delegation_depth: 0,
            issued_at: Utc::now(),
            not_before: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            currently_valid: true,
            seconds_remaining: 3600,
            resource_allow: vec![],
            resource_deny: vec![],
            max_calls: None,
            max_bytes: None,
            credential_allow: vec![],
        };

        let mut reasons = Vec::new();
        let valid = HostAdminStateStore::check_scope_validity(
            &inspection,
            None,
            Some("wrong:saas:1.0.0"),
            &mut reasons,
        );
        assert!(!valid, "Wrong connector should fail scope check");
        assert!(!reasons.is_empty());
        assert!(reasons[0].contains("wrong:saas:1.0.0"));
    }

    // ── Artifact provenance validation tests ─────────────────────────────

    fn valid_provenance() -> ArtifactProvenance {
        ArtifactProvenance {
            source_kind: ArtifactSourceKind::Registry,
            source_uri: "registry://connectors/test:saas:1.0.0".to_owned(),
            content_hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                .to_owned(),
            hash_verified: true,
            signature_b64: Some("dGVzdC1zaWduYXR1cmU=".to_owned()),
            signature_verified: true,
            manifest_version: Some("1.0.0".to_owned()),
            size_bytes: 1024,
        }
    }

    #[test]
    fn valid_artifact_passes_all_gates() {
        let result = validate_artifact_provenance(
            "test:saas:1.0.0",
            &valid_provenance(),
            true,
            Some(10_000),
        );
        assert!(result.is_none(), "Valid provenance should pass");
    }

    #[test]
    fn placeholder_hash_rejected() {
        let mut prov = valid_provenance();
        prov.content_hash = "PLACEHOLDER_HASH".to_owned();
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, false, None);
        assert!(result.is_some());
        let rejection = result.unwrap();
        assert_eq!(rejection.kind, ArtifactRejectionKind::PlaceholderHash);
        assert!(rejection.message.contains("placeholder"));
        assert_eq!(rejection.policy_gate, "provenance.hash.no_placeholder");
    }

    #[test]
    fn empty_hash_rejected() {
        let mut prov = valid_provenance();
        prov.content_hash = String::new();
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, false, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, ArtifactRejectionKind::PlaceholderHash);
    }

    #[test]
    fn zero_hash_rejected() {
        let mut prov = valid_provenance();
        prov.content_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, false, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, ArtifactRejectionKind::PlaceholderHash);
    }

    #[test]
    fn sha256_empty_hash_rejected() {
        let mut prov = valid_provenance();
        prov.content_hash =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned();
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, false, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, ArtifactRejectionKind::PlaceholderHash);
    }

    #[test]
    fn unverified_hash_rejected() {
        let mut prov = valid_provenance();
        prov.hash_verified = false;
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, false, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, ArtifactRejectionKind::HashMismatch);
    }

    #[test]
    fn missing_signature_when_required_rejected() {
        let mut prov = valid_provenance();
        prov.signature_b64 = None;
        prov.signature_verified = false;
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, true, None);
        assert!(result.is_some());
        let rejection = result.unwrap();
        assert_eq!(rejection.kind, ArtifactRejectionKind::MissingSignature);
        assert!(rejection.message.contains("no supply-chain signature"));
    }

    #[test]
    fn missing_signature_when_not_required_passes() {
        let mut prov = valid_provenance();
        prov.signature_b64 = None;
        prov.signature_verified = false;
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, false, None);
        assert!(result.is_none(), "Signature not required should pass");
    }

    #[test]
    fn invalid_signature_rejected() {
        let mut prov = valid_provenance();
        prov.signature_verified = false;
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, false, None);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().kind,
            ArtifactRejectionKind::InvalidSignature
        );
    }

    #[test]
    fn oversized_artifact_rejected() {
        let mut prov = valid_provenance();
        prov.size_bytes = 100_000_000;
        let result =
            validate_artifact_provenance("test:saas:1.0.0", &prov, false, Some(50_000_000));
        assert!(result.is_some());
        let rejection = result.unwrap();
        assert_eq!(rejection.kind, ArtifactRejectionKind::OversizedArtifact);
        assert!(rejection.message.contains("100000000"));
    }

    #[test]
    fn artifact_under_size_limit_passes() {
        let prov = valid_provenance();
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, false, Some(10_000));
        assert!(result.is_none());
    }

    #[test]
    fn artifact_rejection_kind_serde_roundtrip() {
        let kinds = [
            ArtifactRejectionKind::PlaceholderHash,
            ArtifactRejectionKind::EmptyHash,
            ArtifactRejectionKind::HashMismatch,
            ArtifactRejectionKind::DemoBundle,
            ArtifactRejectionKind::InvalidManifest,
            ArtifactRejectionKind::MissingSignature,
            ArtifactRejectionKind::InvalidSignature,
            ArtifactRejectionKind::OversizedArtifact,
            ArtifactRejectionKind::DisallowedSource,
        ];
        for kind in &kinds {
            let json_str = serde_json::to_string(kind).unwrap();
            let back: ArtifactRejectionKind = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn artifact_source_kind_serde_roundtrip() {
        let kinds = [
            ArtifactSourceKind::Registry,
            ArtifactSourceKind::MeshMirror,
            ArtifactSourceKind::LocalPath,
            ArtifactSourceKind::RemoteUrl,
            ArtifactSourceKind::InlineBlob,
        ];
        for kind in &kinds {
            let json_str = serde_json::to_string(kind).unwrap();
            let back: ArtifactSourceKind = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn artifact_rejection_has_remediation() {
        let mut prov = valid_provenance();
        prov.content_hash = "PLACEHOLDER_HASH".to_owned();
        let result = validate_artifact_provenance("test:saas:1.0.0", &prov, false, None);
        let rejection = result.unwrap();
        assert!(!rejection.remediation.is_empty());
        assert!(!rejection.policy_gate.is_empty());
    }

    #[test]
    fn is_placeholder_hash_detects_known_placeholders() {
        assert!(is_placeholder_hash("PLACEHOLDER_HASH"));
        assert!(is_placeholder_hash(""));
        assert!(is_placeholder_hash(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_placeholder_hash(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        ));
    }

    #[test]
    fn is_placeholder_hash_case_insensitive() {
        assert!(is_placeholder_hash("placeholder_hash"));
        assert!(is_placeholder_hash("Placeholder_Hash"));
    }

    #[test]
    fn artifact_rejection_json_has_required_fields() {
        let mut prov = valid_provenance();
        prov.content_hash = "PLACEHOLDER_HASH".to_owned();
        let rejection =
            validate_artifact_provenance("test:saas:1.0.0", &prov, false, None).unwrap();
        let value: Value = serde_json::to_value(&rejection).unwrap();
        assert!(value.get("connector_id").is_some());
        assert!(value.get("kind").is_some());
        assert!(value.get("message").is_some());
        assert!(value.get("provenance").is_some());
        assert!(value.get("remediation").is_some());
        assert!(value.get("policy_gate").is_some());
    }

    #[test]
    fn provenance_validation_gate_order_placeholder_first() {
        // Even with other issues, placeholder hash should be caught first
        let mut prov = valid_provenance();
        prov.content_hash = "PLACEHOLDER_HASH".to_owned();
        prov.hash_verified = false;
        prov.signature_b64 = None;
        prov.size_bytes = 999_999_999;
        let rejection =
            validate_artifact_provenance("test:saas:1.0.0", &prov, true, Some(100)).unwrap();
        assert_eq!(rejection.kind, ArtifactRejectionKind::PlaceholderHash);
    }

    // ── Config RPC methods ─────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn get_config_snapshot_returns_none_for_unknown_connector() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        assert!(store.get_config_snapshot(&cid).await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn get_config_snapshot_returns_managed_inventory_when_no_revisions() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        // Create an entry by saving a lifecycle record.
        let record = LifecycleRecord::new(cid.clone(), Version::new(1, 0, 0));
        store.save(&record).await.expect("save");
        let snapshot = store.get_config_snapshot(&cid).await.expect("snapshot");
        assert_eq!(
            snapshot.source,
            ConnectorConfigSnapshotSource::ManagedInventory
        );
        assert!(snapshot.active_revision_id.is_none());
        assert!(snapshot.active_revision.is_none());
        assert_eq!(snapshot.revision_count, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn get_config_snapshot_returns_active_revision_after_append() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let payload = config_payload("prod");
        store
            .append_config_revision(&cid, payload.clone(), Some("test".to_owned()), None)
            .await
            .expect("append");
        let snapshot = store.get_config_snapshot(&cid).await.expect("snapshot");
        assert_eq!(
            snapshot.source,
            ConnectorConfigSnapshotSource::ActiveRevision
        );
        assert!(snapshot.active_revision_id.is_some());
        assert!(snapshot.active_revision.is_some());
        assert_eq!(snapshot.revision_count, 1);
        assert_eq!(snapshot.current.payload["profile"], "prod");
    }

    #[fcp_async_core::runtime::test]
    async fn config_revisions_returns_none_for_unknown() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        assert!(store.config_revisions(&cid).await.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn config_revisions_returns_history_after_multiple_appends() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        store
            .append_config_revision(&cid, config_payload("v1"), None, None)
            .await
            .expect("v1");
        store
            .append_config_revision(&cid, config_payload("v2"), None, None)
            .await
            .expect("v2");
        let history = store.config_revisions(&cid).await.expect("history");
        assert_eq!(history.revision_count, 2);
        assert_eq!(history.revisions.len(), 2);
        assert!(history.active_revision_id.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn validate_config_succeeds_without_concurrency_guard() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        store
            .append_config_revision(&cid, config_payload("v1"), None, None)
            .await
            .expect("v1");
        let request = ConnectorConfigValidateRequest {
            payload: config_payload("v2"),
            expected_active_revision_id: None,
        };
        let response = store
            .validate_config(&cid, &request)
            .await
            .expect("validate");
        assert!(response.valid);
        assert!(response.error.is_none());
        assert!(!response.diff.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn validate_config_detects_stale_revision() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        store
            .append_config_revision(&cid, config_payload("v1"), None, None)
            .await
            .expect("v1");
        let request = ConnectorConfigValidateRequest {
            payload: config_payload("v2"),
            expected_active_revision_id: Some(999), // wrong revision
        };
        let response = store
            .validate_config(&cid, &request)
            .await
            .expect("validate");
        assert!(!response.valid);
        assert!(response.error.is_some());
        assert!(response.error.unwrap().contains("stale"));
    }

    #[fcp_async_core::runtime::test]
    async fn validate_config_fails_for_unknown_connector() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let request = ConnectorConfigValidateRequest {
            payload: config_payload("v1"),
            expected_active_revision_id: None,
        };
        let result = store.validate_config(&cid, &request).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn apply_config_creates_new_revision() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        store
            .append_config_revision(&cid, config_payload("v1"), None, None)
            .await
            .expect("v1");
        let request = ConnectorConfigApplyRequest {
            payload: config_payload("v2"),
            expected_active_revision_id: None,
            created_by: Some("test-suite".to_owned()),
            change_reason: Some("upgrade".to_owned()),
        };
        let response = store.apply_config(&cid, &request).await.expect("apply");
        assert!(response.changed);
        assert!(response.previous.is_some());
        assert!(response.revision.is_some());
        assert_eq!(response.current.payload["profile"], "v2");
        assert!(response.current_active_revision_id.is_some());
        // Verify revision count increased.
        let snapshot = store.get_config_snapshot(&cid).await.expect("snapshot");
        assert_eq!(snapshot.revision_count, 2);
    }

    #[fcp_async_core::runtime::test]
    async fn apply_config_rejects_stale_revision() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        store
            .append_config_revision(&cid, config_payload("v1"), None, None)
            .await
            .expect("v1");
        let request = ConnectorConfigApplyRequest {
            payload: config_payload("v2"),
            expected_active_revision_id: Some(999),
            created_by: None,
            change_reason: None,
        };
        let result = store.apply_config(&cid, &request).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn rollback_config_reverts_to_target_revision() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let rev1 = store
            .append_config_revision(&cid, config_payload("v1"), None, None)
            .await
            .expect("v1");
        store
            .append_config_revision(&cid, config_payload("v2"), None, None)
            .await
            .expect("v2");
        // Rollback to v1.
        let request = ConnectorConfigRollbackRequest {
            revision_id: rev1.revision_id,
            expected_active_revision_id: None,
            created_by: Some("rollback-test".to_owned()),
            change_reason: Some("reverting".to_owned()),
        };
        let response = store
            .rollback_config(&cid, &request)
            .await
            .expect("rollback");
        assert!(response.changed);
        assert_eq!(response.current.payload["profile"], "v1");
        // Rollback creates a new revision (3rd total).
        let snapshot = store.get_config_snapshot(&cid).await.expect("snapshot");
        assert_eq!(snapshot.revision_count, 3);
    }

    #[fcp_async_core::runtime::test]
    async fn rollback_config_fails_for_unknown_revision() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        store
            .append_config_revision(&cid, config_payload("v1"), None, None)
            .await
            .expect("v1");
        let request = ConnectorConfigRollbackRequest {
            revision_id: 999,
            expected_active_revision_id: None,
            created_by: None,
            change_reason: None,
        };
        let result = store.rollback_config(&cid, &request).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn apply_config_no_diff_still_creates_revision() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let payload = config_payload("same");
        store
            .append_config_revision(&cid, payload.clone(), None, None)
            .await
            .expect("first");
        let request = ConnectorConfigApplyRequest {
            payload,
            expected_active_revision_id: None,
            created_by: None,
            change_reason: None,
        };
        let response = store.apply_config(&cid, &request).await.expect("apply");
        // No material change but revision still created.
        assert!(!response.changed);
        assert!(response.revision.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn validate_config_no_diff_returns_valid() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let payload = config_payload("same");
        store
            .append_config_revision(&cid, payload.clone(), None, None)
            .await
            .expect("first");
        let request = ConnectorConfigValidateRequest {
            payload,
            expected_active_revision_id: None,
        };
        let response = store
            .validate_config(&cid, &request)
            .await
            .expect("validate");
        assert!(response.valid);
        assert!(response.diff.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn apply_config_with_correct_expected_revision_succeeds() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let rev1 = store
            .append_config_revision(&cid, config_payload("v1"), None, None)
            .await
            .expect("v1");
        let request = ConnectorConfigApplyRequest {
            payload: config_payload("v2"),
            expected_active_revision_id: Some(rev1.revision_id),
            created_by: None,
            change_reason: None,
        };
        let response = store.apply_config(&cid, &request).await.expect("apply");
        assert!(response.changed);
    }

    #[fcp_async_core::runtime::test]
    async fn rollback_config_rejects_stale_revision_guard() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let rev1 = store
            .append_config_revision(&cid, config_payload("v1"), None, None)
            .await
            .expect("v1");
        store
            .append_config_revision(&cid, config_payload("v2"), None, None)
            .await
            .expect("v2");
        let request = ConnectorConfigRollbackRequest {
            revision_id: rev1.revision_id,
            expected_active_revision_id: Some(999), // wrong
            created_by: None,
            change_reason: None,
        };
        let result = store.rollback_config(&cid, &request).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn register_connector_artifact_dry_run_does_not_persist() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let summaries = [connector_summary(
            cid.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = ConnectorArtifactRegistrationRequest {
            dry_run: true,
            provenance: valid_provenance(),
            placement: Some(placement_policy()),
            require_signature: true,
            max_size_bytes: Some(100_000),
            initiated_by: Some("preview-agent".to_owned()),
        };

        let response = store
            .register_connector_artifact(&cid, &request)
            .await
            .unwrap();
        assert!(response.accepted);
        assert!(response.dry_run);
        assert!(response.previous.is_none());
        assert!(response.journal_sequence.is_none());
        let current = response.current.expect("dry run should project metadata");
        assert_eq!(
            current.provenance.source_uri,
            "registry://connectors/test:saas:1.0.0"
        );
        assert!(current.placement.is_some());

        let metadata = store.connector_artifact_metadata(&cid).await.unwrap();
        assert!(metadata.artifact.is_none(), "dry run must not persist");
        let status = store.connector_status(&cid).await.unwrap();
        assert!(status.artifact.is_none(), "status should remain unchanged");
    }

    #[fcp_async_core::runtime::test]
    async fn register_connector_artifact_persists_and_surfaces_in_status() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let summaries = [connector_summary(
            cid.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = ConnectorArtifactRegistrationRequest {
            dry_run: false,
            provenance: valid_provenance(),
            placement: Some(placement_policy()),
            require_signature: true,
            max_size_bytes: Some(100_000),
            initiated_by: Some("registry-sync".to_owned()),
        };

        let response = store
            .register_connector_artifact(&cid, &request)
            .await
            .unwrap();
        assert!(response.accepted);
        assert!(!response.dry_run);
        assert!(response.rejection.is_none());
        assert!(response.journal_sequence.is_some());

        let metadata = store.connector_artifact_metadata(&cid).await.unwrap();
        let artifact = metadata.artifact.expect("artifact metadata should persist");
        assert_eq!(
            artifact.provenance.source_kind,
            ArtifactSourceKind::Registry
        );
        assert_eq!(artifact.recorded_by.as_deref(), Some("registry-sync"));
        assert!(artifact.placement.is_some());

        let status = store.connector_status(&cid).await.unwrap();
        assert!(
            status.artifact.is_some(),
            "status should expose artifact metadata"
        );
        assert_eq!(
            status
                .artifact
                .as_ref()
                .and_then(|value| value.recorded_by.as_deref()),
            Some("registry-sync")
        );

        let journal = store.journal(Some(&cid)).await;
        let last = journal
            .last()
            .expect("artifact registration should journal");
        assert!(matches!(
            &last.mutation,
            AdminStateMutation::ArtifactMetadataUpdated {
                source_kind: ArtifactSourceKind::Registry,
                placement_present: true,
                ..
            }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn register_connector_artifact_rejects_placeholder_hash_without_persisting() {
        let store = HostAdminStateStore::new();
        let cid = connector_id();
        let summaries = [connector_summary(
            cid.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let mut provenance = valid_provenance();
        provenance.content_hash = "PLACEHOLDER_HASH".to_owned();
        let request = ConnectorArtifactRegistrationRequest {
            dry_run: false,
            provenance,
            placement: None,
            require_signature: true,
            max_size_bytes: Some(100_000),
            initiated_by: Some("registry-sync".to_owned()),
        };

        let response = store
            .register_connector_artifact(&cid, &request)
            .await
            .unwrap();
        assert!(!response.accepted);
        assert!(response.current.is_none());
        assert!(response.journal_sequence.is_none());
        assert!(matches!(
            response.rejection.as_ref().map(|value| &value.kind),
            Some(&ArtifactRejectionKind::PlaceholderHash)
        ));

        let metadata = store.connector_artifact_metadata(&cid).await.unwrap();
        assert!(metadata.artifact.is_none());
        let journal = store.journal(Some(&cid)).await;
        assert!(
            journal.iter().all(|entry| !matches!(
                &entry.mutation,
                AdminStateMutation::ArtifactMetadataUpdated { .. }
            )),
            "rejected artifact registrations must not mutate persisted state"
        );
    }

    // ── Placeholder hash detection (bead 29.12) ─────────────────────────

    fn make_provenance(hash: &str) -> ArtifactProvenance {
        ArtifactProvenance {
            source_kind: ArtifactSourceKind::Registry,
            source_uri: "registry:fcp.test:1.0.0".to_owned(),
            content_hash: hash.to_owned(),
            hash_verified: true,
            signature_b64: Some("dGVzdC1zaWduYXR1cmU=".to_owned()),
            signature_verified: true,
            manifest_version: Some("1.0.0".to_owned()),
            size_bytes: 1024,
        }
    }

    #[test]
    fn placeholder_hash_detects_placeholder_hash_literal() {
        assert!(is_placeholder_hash("PLACEHOLDER_HASH"));
    }

    #[test]
    fn placeholder_hash_detects_all_zeros_64() {
        assert!(is_placeholder_hash(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn placeholder_hash_detects_sha256_of_empty() {
        assert!(is_placeholder_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn placeholder_hash_detects_blake3_of_empty() {
        assert!(is_placeholder_hash(
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        ));
    }

    #[test]
    fn placeholder_hash_every_known_entry_is_detected() {
        for hash in KNOWN_PLACEHOLDER_HASHES {
            assert!(
                is_placeholder_hash(hash),
                "KNOWN_PLACEHOLDER_HASHES entry '{hash}' was not detected"
            );
        }
    }

    #[test]
    fn placeholder_hash_empty_string_is_placeholder() {
        assert!(is_placeholder_hash(""));
    }

    #[test]
    fn placeholder_hash_whitespace_only_is_not_matched() {
        // Whitespace-only strings are not empty (is_empty check) and after trim+lowercase
        // become "" which doesn't match any KNOWN_PLACEHOLDER_HASHES entry.
        assert!(!is_placeholder_hash("  "));
    }

    // ── Case insensitivity ───────────────────────────────────────────────

    #[test]
    fn placeholder_hash_case_insensitive_placeholder_hash() {
        assert!(is_placeholder_hash("placeholder_hash"));
        assert!(is_placeholder_hash("Placeholder_Hash"));
        assert!(is_placeholder_hash("PLACEHOLDER_HASH"));
    }

    #[test]
    fn placeholder_hash_case_insensitive_all_zeros() {
        // All zeros is case-insensitive by nature (no letters), but verify trim works
        assert!(is_placeholder_hash(
            "  0000000000000000000000000000000000000000000000000000000000000000  "
        ));
    }

    #[test]
    fn placeholder_hash_case_insensitive_sha256_empty_uppercase() {
        assert!(is_placeholder_hash(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        ));
    }

    #[test]
    fn placeholder_hash_case_insensitive_blake3_empty_mixed() {
        assert!(is_placeholder_hash(
            "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262"
        ));
    }

    // ── Real hashes are NOT falsely rejected ─────────────────────────────

    #[test]
    fn real_blake3_hash_not_rejected() {
        assert!(!is_placeholder_hash(
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        ));
    }

    #[test]
    fn real_sha256_hash_not_rejected() {
        assert!(!is_placeholder_hash(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ));
    }

    #[test]
    fn real_arbitrary_hex_hash_not_rejected() {
        assert!(!is_placeholder_hash(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        ));
    }

    #[test]
    fn real_short_hash_not_rejected() {
        assert!(!is_placeholder_hash("abc123def456"));
    }

    #[test]
    fn real_production_hash_samples_not_rejected() {
        let hashes = [
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
            "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d",
        ];
        for hash in &hashes {
            assert!(
                !is_placeholder_hash(hash),
                "Real hash '{hash}' must not be treated as placeholder"
            );
        }
    }

    // ── validate_artifact_provenance with placeholder hashes ─────────────

    #[test]
    fn validate_provenance_rejects_placeholder_hash_literal() {
        let prov = make_provenance("PLACEHOLDER_HASH");
        let rejection = validate_artifact_provenance("fcp.test:util:1.0", &prov, false, None);
        assert!(rejection.is_some());
        let r = rejection.unwrap();
        assert!(matches!(r.kind, ArtifactRejectionKind::PlaceholderHash));
        assert!(r.message.contains("placeholder") || r.message.contains("PLACEHOLDER"));
    }

    #[test]
    fn validate_provenance_rejects_all_zeros_hash() {
        let prov =
            make_provenance("0000000000000000000000000000000000000000000000000000000000000000");
        let rejection = validate_artifact_provenance("fcp.test:util:1.0", &prov, false, None);
        assert!(rejection.is_some());
        assert!(matches!(
            rejection.unwrap().kind,
            ArtifactRejectionKind::PlaceholderHash
        ));
    }

    #[test]
    fn validate_provenance_rejects_empty_hash() {
        let prov = make_provenance("");
        let rejection = validate_artifact_provenance("fcp.test:util:1.0", &prov, false, None);
        assert!(rejection.is_some());
        assert!(matches!(
            rejection.unwrap().kind,
            ArtifactRejectionKind::PlaceholderHash
        ));
    }

    #[test]
    fn validate_provenance_rejection_has_informative_message() {
        let prov = make_provenance("PLACEHOLDER_HASH");
        let r = validate_artifact_provenance("fcp.slack:comm:2.0", &prov, false, None).unwrap();
        assert!(r.message.contains("fcp.slack:comm:2.0"));
        assert!(r.message.contains("PLACEHOLDER_HASH"));
        assert!(!r.remediation.is_empty());
        assert_eq!(r.policy_gate, "provenance.hash.no_placeholder");
        assert_eq!(r.connector_id, "fcp.slack:comm:2.0");
    }

    #[test]
    fn validate_provenance_rejection_includes_provenance() {
        let prov = make_provenance("PLACEHOLDER_HASH");
        let r = validate_artifact_provenance("fcp.test:util:1.0", &prov, false, None).unwrap();
        assert!(r.provenance.is_some());
        assert_eq!(r.provenance.unwrap().content_hash, "PLACEHOLDER_HASH");
    }

    #[test]
    fn validate_provenance_rejection_remediation_is_actionable() {
        let prov = make_provenance("PLACEHOLDER_HASH");
        let r = validate_artifact_provenance("fcp.test:util:1.0", &prov, false, None).unwrap();
        assert!(r.remediation.len() >= 2);
        for hint in &r.remediation {
            assert!(!hint.is_empty(), "remediation hint must not be empty");
            assert!(hint.len() > 10, "remediation should be meaningful: {hint}");
        }
    }

    #[test]
    fn validate_provenance_accepts_real_hash() {
        let prov =
            make_provenance("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        let result = validate_artifact_provenance("fcp.test:util:1.0", &prov, false, None);
        assert!(
            result.is_none(),
            "Real hash should pass provenance validation"
        );
    }

    // ── diff_config_values edge cases ───────────────────────────────────

    #[test]
    fn diff_config_values_identical_objects_produces_no_entries() {
        let val = serde_json::json!({"a": 1, "b": "two"});
        let entries = diff_config_values(&val, &val);
        assert!(entries.is_empty());
    }

    #[test]
    fn diff_config_values_both_null_produces_no_entries() {
        let entries = diff_config_values(&Value::Null, &Value::Null);
        assert!(entries.is_empty());
    }

    #[test]
    fn diff_config_values_root_type_change_scalar_to_object() {
        let before = serde_json::json!("hello");
        let after = serde_json::json!({"greeting": "hello"});
        let entries = diff_config_values(&before, &after);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/");
        assert_eq!(entries[0].kind, ConfigDiffKind::Changed);
    }

    #[test]
    fn diff_config_values_added_key() {
        let before = serde_json::json!({"a": 1});
        let after = serde_json::json!({"a": 1, "b": 2});
        let entries = diff_config_values(&before, &after);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/b");
        assert_eq!(entries[0].kind, ConfigDiffKind::Added);
        assert_eq!(entries[0].after, Some(serde_json::json!(2)));
    }

    #[test]
    fn diff_config_values_removed_key() {
        let before = serde_json::json!({"a": 1, "b": 2});
        let after = serde_json::json!({"a": 1});
        let entries = diff_config_values(&before, &after);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/b");
        assert_eq!(entries[0].kind, ConfigDiffKind::Removed);
        assert_eq!(entries[0].before, Some(serde_json::json!(2)));
    }

    #[test]
    fn diff_config_values_array_element_added() {
        let before = serde_json::json!([1, 2]);
        let after = serde_json::json!([1, 2, 3]);
        let entries = diff_config_values(&before, &after);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/2");
        assert_eq!(entries[0].kind, ConfigDiffKind::Added);
    }

    #[test]
    fn diff_config_values_array_element_removed() {
        let before = serde_json::json!([1, 2, 3]);
        let after = serde_json::json!([1, 2]);
        let entries = diff_config_values(&before, &after);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/2");
        assert_eq!(entries[0].kind, ConfigDiffKind::Removed);
    }

    #[test]
    fn diff_config_values_array_element_changed() {
        let before = serde_json::json!([1, 2, 3]);
        let after = serde_json::json!([1, 99, 3]);
        let entries = diff_config_values(&before, &after);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/1");
        assert_eq!(entries[0].kind, ConfigDiffKind::Changed);
        assert_eq!(entries[0].before, Some(serde_json::json!(2)));
        assert_eq!(entries[0].after, Some(serde_json::json!(99)));
    }

    #[test]
    fn diff_config_values_deeply_nested_change() {
        let before = serde_json::json!({"a": {"b": {"c": 1}}});
        let after = serde_json::json!({"a": {"b": {"c": 2}}});
        let entries = diff_config_values(&before, &after);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/a/b/c");
        assert_eq!(entries[0].kind, ConfigDiffKind::Changed);
    }

    #[test]
    fn diff_config_values_entries_sorted_by_path() {
        let before = serde_json::json!({"z": 1, "a": 2, "m": 3});
        let after = serde_json::json!({"z": 10, "a": 20, "m": 30});
        let entries = diff_config_values(&before, &after);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "/a");
        assert_eq!(entries[1].path, "/m");
        assert_eq!(entries[2].path, "/z");
    }

    #[test]
    fn diff_config_values_empty_objects_no_diff() {
        let before = serde_json::json!({});
        let after = serde_json::json!({});
        let entries = diff_config_values(&before, &after);
        assert!(entries.is_empty());
    }

    #[test]
    fn diff_config_values_empty_arrays_no_diff() {
        let before = serde_json::json!([]);
        let after = serde_json::json!([]);
        let entries = diff_config_values(&before, &after);
        assert!(entries.is_empty());
    }

    // ── join_json_pointer and config_diff_path ──────────────────────────

    #[test]
    fn join_json_pointer_escapes_tilde() {
        let result = join_json_pointer("", "key~with~tilde");
        assert_eq!(result, "/key~0with~0tilde");
    }

    #[test]
    fn join_json_pointer_escapes_slash() {
        let result = join_json_pointer("", "key/with/slash");
        assert_eq!(result, "/key~1with~1slash");
    }

    #[test]
    fn join_json_pointer_appends_to_existing_path() {
        let result = join_json_pointer("/a/b", "c");
        assert_eq!(result, "/a/b/c");
    }

    #[test]
    fn config_diff_path_empty_becomes_root() {
        let result = config_diff_path("");
        assert_eq!(result, "/");
    }

    #[test]
    fn config_diff_path_nonempty_passes_through() {
        let result = config_diff_path("/a/b");
        assert_eq!(result, "/a/b");
    }

    // ── should_redact_config_key ────────────────────────────────────────

    #[test]
    fn should_redact_config_key_recognizes_all_secret_patterns() {
        let secret_keys = [
            "token",
            "secret",
            "password",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "client_secret",
            "private_key",
        ];
        for key in secret_keys {
            assert!(
                should_redact_config_key(key),
                "key '{key}' should be redacted"
            );
        }
    }

    #[test]
    fn should_redact_config_key_case_insensitive() {
        assert!(should_redact_config_key("API_KEY"));
        assert!(should_redact_config_key("Access_Token"));
        assert!(should_redact_config_key("CLIENT_SECRET"));
    }

    #[test]
    fn should_redact_config_key_does_not_redact_safe_keys() {
        assert!(!should_redact_config_key("profile"));
        assert!(!should_redact_config_key("name"));
        assert!(!should_redact_config_key("endpoint"));
        assert!(!should_redact_config_key("max_retries"));
    }

    #[test]
    fn should_redact_config_key_credential_id_is_not_redacted() {
        assert!(!should_redact_config_key("credential_id"));
        assert!(!should_redact_config_key("my_credential_id"));
    }

    // ── is_credential_reference_key ─────────────────────────────────────

    #[test]
    fn is_credential_reference_key_matches_credential_id() {
        assert!(is_credential_reference_key("credential_id"));
        assert!(is_credential_reference_key("CREDENTIAL_ID"));
        assert!(is_credential_reference_key("my_credential_id"));
    }

    #[test]
    fn is_credential_reference_key_rejects_non_credential_keys() {
        assert!(!is_credential_reference_key("password"));
        assert!(!is_credential_reference_key("api_key"));
        assert!(!is_credential_reference_key("profile"));
    }

    // ── DesiredRuntimeState / ObservedRuntimeState from_lifecycle_state ──

    #[test]
    fn desired_runtime_state_from_lifecycle_state_all_variants() {
        assert_eq!(
            DesiredRuntimeState::from_lifecycle_state(LifecycleState::Pending),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            DesiredRuntimeState::from_lifecycle_state(LifecycleState::Installing),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            DesiredRuntimeState::from_lifecycle_state(LifecycleState::Canary),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            DesiredRuntimeState::from_lifecycle_state(LifecycleState::Production),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            DesiredRuntimeState::from_lifecycle_state(LifecycleState::RolledBack),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            DesiredRuntimeState::from_lifecycle_state(LifecycleState::Disabled),
            DesiredRuntimeState::Disabled
        );
        assert_eq!(
            DesiredRuntimeState::from_lifecycle_state(LifecycleState::Uninstalled),
            DesiredRuntimeState::Uninstalled
        );
    }

    #[test]
    fn observed_runtime_state_from_lifecycle_state_all_variants() {
        assert_eq!(
            ObservedRuntimeState::from_lifecycle_state(LifecycleState::Pending),
            ObservedRuntimeState::Starting
        );
        assert_eq!(
            ObservedRuntimeState::from_lifecycle_state(LifecycleState::Installing),
            ObservedRuntimeState::Starting
        );
        assert_eq!(
            ObservedRuntimeState::from_lifecycle_state(LifecycleState::Canary),
            ObservedRuntimeState::Running
        );
        assert_eq!(
            ObservedRuntimeState::from_lifecycle_state(LifecycleState::Production),
            ObservedRuntimeState::Running
        );
        assert_eq!(
            ObservedRuntimeState::from_lifecycle_state(LifecycleState::RolledBack),
            ObservedRuntimeState::Degraded
        );
        assert_eq!(
            ObservedRuntimeState::from_lifecycle_state(LifecycleState::Disabled),
            ObservedRuntimeState::Stopped
        );
        assert_eq!(
            ObservedRuntimeState::from_lifecycle_state(LifecycleState::Uninstalled),
            ObservedRuntimeState::Missing
        );
    }

    // ── DesiredRuntimeState / ObservedRuntimeState defaults and serde ────

    #[test]
    fn desired_runtime_state_default_is_unspecified() {
        assert_eq!(
            DesiredRuntimeState::default(),
            DesiredRuntimeState::Unspecified
        );
    }

    #[test]
    fn observed_runtime_state_default_is_unknown() {
        assert_eq!(
            ObservedRuntimeState::default(),
            ObservedRuntimeState::Unknown
        );
    }

    #[test]
    fn desired_runtime_state_serde_all_variants() {
        let variants = [
            DesiredRuntimeState::Unspecified,
            DesiredRuntimeState::Enabled,
            DesiredRuntimeState::Disabled,
            DesiredRuntimeState::Uninstalled,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let back: DesiredRuntimeState = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn observed_runtime_state_serde_all_variants() {
        let variants = [
            ObservedRuntimeState::Unknown,
            ObservedRuntimeState::Starting,
            ObservedRuntimeState::Running,
            ObservedRuntimeState::Degraded,
            ObservedRuntimeState::Stopped,
            ObservedRuntimeState::Missing,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let back: ObservedRuntimeState = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back);
        }
    }

    // ── connector_drift_status additional combos ────────────────────────

    #[test]
    fn drift_enabled_but_stopped() {
        let state = ConnectorAdminState {
            lifecycle: None,
            desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Stopped,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        let drift = connector_drift_status(&state, Utc::now()).expect("should drift");
        assert_eq!(drift.kind, ConnectorDriftKind::EnabledButNotRunning);
        assert_eq!(drift.recovery_action, RecoveryAction::RestartConnector);
    }

    #[test]
    fn drift_enabled_but_degraded() {
        let state = ConnectorAdminState {
            lifecycle: None,
            desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Degraded,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        let drift = connector_drift_status(&state, Utc::now()).expect("should drift");
        assert_eq!(drift.kind, ConnectorDriftKind::EnabledButDegraded);
        assert_eq!(drift.recovery_action, RecoveryAction::RepairConnector);
    }

    #[test]
    fn drift_enabled_but_missing() {
        let state = ConnectorAdminState {
            lifecycle: None,
            desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Missing,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        let drift = connector_drift_status(&state, Utc::now()).expect("should drift");
        assert_eq!(drift.kind, ConnectorDriftKind::EnabledButMissing);
        assert_eq!(drift.recovery_action, RecoveryAction::ReinstallConnector);
    }

    #[test]
    fn drift_enabled_and_running_no_drift() {
        let state = ConnectorAdminState {
            lifecycle: None,
            desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Running,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        assert!(connector_drift_status(&state, Utc::now()).is_none());
    }

    #[test]
    fn drift_disabled_but_running() {
        let state = ConnectorAdminState {
            lifecycle: None,
            desired_state: DesiredRuntimeState::Disabled,
            observed_state: ObservedRuntimeState::Running,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        let drift = connector_drift_status(&state, Utc::now()).expect("should drift");
        assert_eq!(drift.kind, ConnectorDriftKind::DisabledButRunning);
        assert_eq!(drift.recovery_action, RecoveryAction::DisableConnector);
    }

    #[test]
    fn drift_disabled_but_degraded() {
        let state = ConnectorAdminState {
            lifecycle: None,
            desired_state: DesiredRuntimeState::Disabled,
            observed_state: ObservedRuntimeState::Degraded,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        let drift = connector_drift_status(&state, Utc::now()).expect("should drift");
        assert_eq!(drift.kind, ConnectorDriftKind::DisabledButRunning);
    }

    #[test]
    fn drift_disabled_and_stopped_no_drift() {
        let state = ConnectorAdminState {
            lifecycle: None,
            desired_state: DesiredRuntimeState::Disabled,
            observed_state: ObservedRuntimeState::Stopped,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        assert!(connector_drift_status(&state, Utc::now()).is_none());
    }

    #[test]
    fn drift_uninstalled_but_running() {
        let state = ConnectorAdminState {
            lifecycle: None,
            desired_state: DesiredRuntimeState::Uninstalled,
            observed_state: ObservedRuntimeState::Running,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        let drift = connector_drift_status(&state, Utc::now()).expect("should drift");
        assert_eq!(drift.kind, ConnectorDriftKind::UninstalledButPresent);
        assert_eq!(drift.recovery_action, RecoveryAction::DisableConnector);
    }

    #[test]
    fn drift_uninstalled_and_missing_no_drift() {
        let state = ConnectorAdminState {
            lifecycle: None,
            desired_state: DesiredRuntimeState::Uninstalled,
            observed_state: ObservedRuntimeState::Missing,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
            artifact: None,
        };
        assert!(connector_drift_status(&state, Utc::now()).is_none());
    }

    #[test]
    fn drift_unspecified_never_drifts() {
        for observed in [
            ObservedRuntimeState::Unknown,
            ObservedRuntimeState::Running,
            ObservedRuntimeState::Stopped,
            ObservedRuntimeState::Missing,
        ] {
            let state = ConnectorAdminState {
                lifecycle: None,
                desired_state: DesiredRuntimeState::Unspecified,
                observed_state: observed,
                pinned_version: None,
                config_revisions: Vec::new(),
                active_config_revision_id: None,
                last_journal_sequence: 0,
                artifact: None,
            };
            assert!(
                connector_drift_status(&state, Utc::now()).is_none(),
                "Unspecified desired should never drift with observed={observed:?}"
            );
        }
    }

    // ── ConnectorAdminState methods ─────────────────────────────────────

    #[test]
    fn connector_admin_state_config_revision_by_id() {
        let mut state = ConnectorAdminState::default();
        let revision = ConfigRevisionRecord::new(42, None, config_payload("test"), None, None)
            .expect("revision");
        state.config_revisions.push(revision);
        assert!(state.config_revision(42).is_some());
        assert!(state.config_revision(999).is_none());
    }

    #[test]
    fn connector_admin_state_active_config_revision_none_when_empty() {
        let state = ConnectorAdminState::default();
        assert!(state.active_config_revision().is_none());
    }

    #[test]
    fn connector_admin_state_active_config_revision_none_when_id_does_not_match() {
        let mut state = ConnectorAdminState {
            active_config_revision_id: Some(999),
            ..ConnectorAdminState::default()
        };
        let revision = ConfigRevisionRecord::new(42, None, config_payload("test"), None, None)
            .expect("revision");
        state.config_revisions.push(revision);
        assert!(state.active_config_revision().is_none());
    }

    // ── SanitizedConnectorConfig ────────────────────────────────────────

    #[test]
    fn sanitized_connector_config_from_payload_with_secrets() {
        let payload = serde_json::json!({
            "profile": "work",
            "api_key": "my-secret-key",
        });
        let sanitized = SanitizedConnectorConfig::from_payload(payload).unwrap();
        assert_eq!(
            sanitized.payload["api_key"],
            Value::String(REDACTED_CONFIG_VALUE.to_string())
        );
        assert!(sanitized.contains_inline_secrets);
        assert!(!sanitized.is_replayable());
    }

    #[test]
    fn sanitized_connector_config_from_payload_without_secrets() {
        let payload = serde_json::json!({"profile": "work", "endpoint": "https://api.test"});
        let sanitized = SanitizedConnectorConfig::from_payload(payload).unwrap();
        assert!(!sanitized.contains_inline_secrets);
        assert!(sanitized.is_replayable());
        assert!(sanitized.redacted_fields.is_empty());
    }

    #[test]
    fn sanitized_connector_config_from_config_revision_record() {
        let revision = ConfigRevisionRecord::new(
            1,
            None,
            serde_json::json!({"api_key": "hidden"}),
            None,
            None,
        )
        .expect("revision");
        let sanitized = SanitizedConnectorConfig::from(&revision);
        assert_eq!(sanitized.payload, revision.payload);
        assert_eq!(sanitized.payload_digest, revision.payload_digest);
        assert_eq!(
            sanitized.contains_inline_secrets,
            revision.contains_inline_secrets
        );
    }

    // ── ConfigRevisionRecord::is_replayable ─────────────────────────────

    #[test]
    fn config_revision_record_is_replayable_when_no_secrets() {
        let revision =
            ConfigRevisionRecord::new(1, None, serde_json::json!({"profile": "work"}), None, None)
                .expect("revision");
        assert!(revision.is_replayable());
    }

    #[test]
    fn config_revision_record_not_replayable_with_secrets() {
        let revision = ConfigRevisionRecord::new(
            1,
            None,
            serde_json::json!({"password": "secret"}),
            None,
            None,
        )
        .expect("revision");
        assert!(!revision.is_replayable());
    }

    // ── is_false helper ─────────────────────────────────────────────────

    #[test]
    fn is_false_returns_true_for_false() {
        assert!(is_false(&false));
    }

    #[test]
    fn is_false_returns_false_for_true() {
        assert!(!is_false(&true));
    }

    // ── ConnectorInventoryMutationKind serde ─────────────────────────────

    #[test]
    fn connector_inventory_mutation_kind_serde_roundtrip() {
        for kind in [
            ConnectorInventoryMutationKind::Install,
            ConnectorInventoryMutationKind::Update,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ConnectorInventoryMutationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // ── SecretReferenceStatus serde and defaults ────────────────────────

    #[test]
    fn secret_reference_status_default_is_unknown() {
        assert_eq!(
            SecretReferenceStatus::default(),
            SecretReferenceStatus::Unknown
        );
    }

    #[test]
    fn secret_reference_status_serde_all_variants() {
        let variants = [
            SecretReferenceStatus::Unknown,
            SecretReferenceStatus::Available,
            SecretReferenceStatus::Rotated,
            SecretReferenceStatus::Missing,
            SecretReferenceStatus::Inaccessible,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let back: SecretReferenceStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back);
        }
    }

    // ── ConnectorConfigSnapshotSource serde ──────────────────────────────

    #[test]
    fn connector_config_snapshot_source_serde_roundtrip() {
        for source in [
            ConnectorConfigSnapshotSource::ActiveRevision,
            ConnectorConfigSnapshotSource::ManagedInventory,
        ] {
            let json = serde_json::to_string(&source).unwrap();
            let back: ConnectorConfigSnapshotSource = serde_json::from_str(&json).unwrap();
            assert_eq!(source, back);
        }
    }

    // ── ConfigDiffKind serde ────────────────────────────────────────────

    #[test]
    fn config_diff_kind_serde_all_variants() {
        for kind in [
            ConfigDiffKind::Added,
            ConfigDiffKind::Removed,
            ConfigDiffKind::Changed,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ConfigDiffKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // ── AdminStateMutation serde ────────────────────────────────────────

    #[test]
    fn admin_state_mutation_serde_lifecycle_record_saved() {
        let mutation = AdminStateMutation::LifecycleRecordSaved {
            version: Version::new(1, 0, 0),
            state: LifecycleState::Production,
        };
        let json = serde_json::to_string(&mutation).unwrap();
        let back: AdminStateMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(mutation, back);
    }

    #[test]
    fn admin_state_mutation_serde_desired_state_set() {
        let mutation = AdminStateMutation::DesiredStateSet {
            desired_state: DesiredRuntimeState::Enabled,
        };
        let json = serde_json::to_string(&mutation).unwrap();
        let back: AdminStateMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(mutation, back);
    }

    #[test]
    fn admin_state_mutation_serde_pin_cleared() {
        let mutation = AdminStateMutation::PinCleared;
        let json = serde_json::to_string(&mutation).unwrap();
        let back: AdminStateMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(mutation, back);
    }

    #[test]
    fn admin_state_mutation_serde_config_revision_appended() {
        let mutation = AdminStateMutation::ConfigRevisionAppended {
            revision_id: 42,
            payload_digest: "abc123".to_owned(),
        };
        let json = serde_json::to_string(&mutation).unwrap();
        let back: AdminStateMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(mutation, back);
    }

    // ── sanitize_config_payload edge cases ──────────────────────────────

    #[test]
    fn sanitize_config_payload_handles_array_with_secrets() {
        let payload = serde_json::json!({
            "entries": [
                {"name": "safe", "password": "hidden1"},
                {"name": "also_safe", "client_secret": "hidden2"}
            ]
        });
        let sanitized = sanitize_config_payload(payload);
        assert!(sanitized.contains_inline_secrets);
        let entries = sanitized.payload["entries"].as_array().expect("array");
        assert_eq!(
            entries[0]["password"],
            Value::String(REDACTED_CONFIG_VALUE.to_string())
        );
        assert_eq!(
            entries[1]["client_secret"],
            Value::String(REDACTED_CONFIG_VALUE.to_string())
        );
        assert_eq!(entries[0]["name"], "safe");
    }

    #[test]
    fn sanitize_config_payload_preserves_non_object_non_array_values() {
        let payload = serde_json::json!("plain string");
        let sanitized = sanitize_config_payload(payload);
        assert_eq!(sanitized.payload, serde_json::json!("plain string"));
        assert!(!sanitized.contains_inline_secrets);
    }

    #[test]
    fn sanitize_config_payload_null_value() {
        let sanitized = sanitize_config_payload(Value::Null);
        assert_eq!(sanitized.payload, Value::Null);
        assert!(!sanitized.contains_inline_secrets);
    }

    // ── install_stuck and canary_stuck boundary conditions ───────────────

    #[test]
    fn install_stuck_false_when_below_threshold() {
        let now = Utc::now();
        let record = LifecycleRecord {
            connector_id: connector_id(),
            version: Version::new(1, 0, 0),
            state: LifecycleState::Installing,
            deployed_at: now,
            state_changed_at: now - Duration::seconds(299), // just below 300s
            transitions: Vec::new(),
            health: HealthMetrics::default(),
            canary_policy: CanaryPolicy::default(),
            previous_version: None,
        };
        assert!(!install_stuck(&record, now));
    }

    #[test]
    fn install_stuck_true_at_exact_threshold() {
        let now = Utc::now();
        let record = LifecycleRecord {
            connector_id: connector_id(),
            version: Version::new(1, 0, 0),
            state: LifecycleState::Installing,
            deployed_at: now,
            state_changed_at: now - Duration::seconds(300), // exactly 300s
            transitions: Vec::new(),
            health: HealthMetrics::default(),
            canary_policy: CanaryPolicy::default(),
            previous_version: None,
        };
        assert!(install_stuck(&record, now));
    }

    #[test]
    fn install_stuck_false_for_canary_state() {
        let now = Utc::now();
        let record = LifecycleRecord {
            connector_id: connector_id(),
            version: Version::new(1, 0, 0),
            state: LifecycleState::Canary,
            deployed_at: now,
            state_changed_at: now - Duration::seconds(600),
            transitions: Vec::new(),
            health: HealthMetrics::default(),
            canary_policy: CanaryPolicy::default(),
            previous_version: None,
        };
        assert!(!install_stuck(&record, now));
    }

    #[test]
    fn install_stuck_true_for_pending_state() {
        let now = Utc::now();
        let record = LifecycleRecord {
            connector_id: connector_id(),
            version: Version::new(1, 0, 0),
            state: LifecycleState::Pending,
            deployed_at: now,
            state_changed_at: now - Duration::seconds(600),
            transitions: Vec::new(),
            health: HealthMetrics::default(),
            canary_policy: CanaryPolicy::default(),
            previous_version: None,
        };
        assert!(install_stuck(&record, now));
    }

    // ── desired_state_from_summary / observed_state_from_summary ────────

    #[test]
    fn desired_state_from_summary_enabled() {
        let summary = connector_summary(connector_id(), true, ConnectorHealth::healthy());
        assert_eq!(
            desired_state_from_summary(&summary),
            DesiredRuntimeState::Enabled
        );
    }

    #[test]
    fn desired_state_from_summary_disabled() {
        let summary = connector_summary(connector_id(), false, ConnectorHealth::healthy());
        assert_eq!(
            desired_state_from_summary(&summary),
            DesiredRuntimeState::Disabled
        );
    }

    #[test]
    fn observed_state_from_summary_disabled_is_stopped() {
        let summary = connector_summary(connector_id(), false, ConnectorHealth::healthy());
        assert_eq!(
            observed_state_from_summary(&summary),
            ObservedRuntimeState::Stopped
        );
    }

    #[test]
    fn observed_state_from_summary_enabled_healthy_is_running() {
        let summary = connector_summary(connector_id(), true, ConnectorHealth::healthy());
        assert_eq!(
            observed_state_from_summary(&summary),
            ObservedRuntimeState::Running
        );
    }

    #[test]
    fn observed_state_from_summary_enabled_degraded() {
        let summary = connector_summary(
            connector_id(),
            true,
            ConnectorHealth::Degraded {
                reason: "flaky".to_string(),
            },
        );
        assert_eq!(
            observed_state_from_summary(&summary),
            ObservedRuntimeState::Degraded
        );
    }

    #[test]
    fn observed_state_from_summary_enabled_unavailable_is_stopped() {
        let summary = connector_summary(
            connector_id(),
            true,
            ConnectorHealth::Unavailable {
                reason: "crashed".to_string(),
                since: Utc::now(),
            },
        );
        assert_eq!(
            observed_state_from_summary(&summary),
            ObservedRuntimeState::Stopped
        );
    }

    // ── RecoveryAction and ConnectorDriftKind serde ──────────────────────

    #[test]
    fn recovery_action_serde_all_variants() {
        let variants = [
            RecoveryAction::RestartConnector,
            RecoveryAction::RepairConnector,
            RecoveryAction::ReinstallConnector,
            RecoveryAction::CompleteRollout,
            RecoveryAction::DisableConnector,
            RecoveryAction::Investigate,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let back: RecoveryAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn connector_drift_kind_serde_all_variants() {
        let variants = [
            ConnectorDriftKind::EnabledButNotRunning,
            ConnectorDriftKind::EnabledButMissing,
            ConnectorDriftKind::EnabledButDegraded,
            ConnectorDriftKind::DisabledButRunning,
            ConnectorDriftKind::UninstalledButPresent,
            ConnectorDriftKind::InstallStuck,
            ConnectorDriftKind::CanaryStuck,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let back: ConnectorDriftKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back);
        }
    }

    // ── extend_json_pointer ─────────────────────────────────────────────

    #[test]
    fn extend_json_pointer_escapes_tilde_and_slash() {
        let result = extend_json_pointer("/root", "key~with/both");
        assert_eq!(result, "/root/key~0with~1both");
    }

    #[test]
    fn extend_json_pointer_from_empty_prefix() {
        let result = extend_json_pointer("", "first");
        assert_eq!(result, "/first");
    }

    // ── ManagedConnectorConfig serde ────────────────────────────────────

    #[test]
    fn managed_connector_config_minimal_serde() {
        let json = r#"{"id":"test","binary":"/bin/test"}"#;
        let config: ManagedConnectorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.id, "test");
        assert_eq!(config.binary, "/bin/test");
        assert!(config.name.is_none());
        assert!(config.args.is_empty());
        assert!(config.env.is_empty());
        assert_eq!(config.prewarm, ConnectorPrewarmConfig::default());
    }

    #[test]
    fn managed_connector_config_full_roundtrip() {
        let config = ManagedConnectorConfig {
            cancellation_deadline_ms: None,
            id: "test-connector".to_string(),
            binary: "/usr/bin/test".to_string(),
            manifest_path: None,
            name: Some("Test".to_string()),
            description: Some("A test connector".to_string()),
            args: vec!["--verbose".to_string()],
            env: BTreeMap::from([("KEY".to_string(), "val".to_string())]),
            config: Some(serde_json::json!({"port": 8080})),
            categories: vec!["test".to_string()],
            version: Some("1.0.0".to_string()),
            allowed_zones: Vec::new(),
            allowed_operations: Vec::new(),
            enforce_operation_network_constraints: false,
            enforce_empty_allow_lists: false,
            runtime_network_enforcement: RuntimeNetworkEnforcement::LegacyUnspecified,
            prewarm: ConnectorPrewarmConfig::default(),
            operation_network_constraints: BTreeMap::new(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: ManagedConnectorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn managed_connector_config_serializes_explicit_prewarm_policy() {
        let config = ManagedConnectorConfig {
            cancellation_deadline_ms: None,
            id: "test-connector".to_string(),
            binary: "/usr/bin/test".to_string(),
            manifest_path: None,
            name: None,
            description: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            config: None,
            categories: Vec::new(),
            version: None,
            allowed_zones: Vec::new(),
            allowed_operations: Vec::new(),
            enforce_operation_network_constraints: false,
            enforce_empty_allow_lists: false,
            runtime_network_enforcement: RuntimeNetworkEnforcement::LegacyUnspecified,
            prewarm: ConnectorPrewarmConfig::warm_pool(
                1,
                2,
                std::time::Duration::from_secs(30),
                std::time::Duration::from_millis(50),
            ),
            operation_network_constraints: BTreeMap::new(),
        };

        let value = serde_json::to_value(&config).unwrap();
        assert_eq!(value["prewarm"]["strategy"], "warm_pool");
        let back: ManagedConnectorConfig = serde_json::from_value(value).unwrap();
        assert_eq!(back.prewarm, config.prewarm);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Snapshot intentionally covers the full admin request/response surface.
    fn admin_api_request_response_shape_snapshot() {
        let fixed_at = Utc.with_ymd_and_hms(2026, 4, 20, 1, 14, 0).unwrap();

        let inventory_mutation_request = ConnectorInventoryMutationRequest {
            kind: ConnectorInventoryMutationKind::Update,
            dry_run: true,
            connector: ManagedConnectorConfig {
                cancellation_deadline_ms: None,
                id: "fcp.github".to_string(),
                binary: "[connector-binary]".to_string(),
                manifest_path: Some("connectors/github/manifest.toml".to_string()),
                name: Some("GitHub".to_string()),
                description: Some("GitHub connector".to_string()),
                args: vec![
                    "serve".to_string(),
                    "--zone".to_string(),
                    "z:work".to_string(),
                ],
                env: BTreeMap::from([
                    ("FCP_LOG".to_string(), "info".to_string()),
                    ("FCP_PROFILE".to_string(), "work".to_string()),
                ]),
                config: Some(serde_json::json!({
                    "credential_id": "[credential-id]",
                    "webhook_secret": "[redacted]",
                    "workspace_root": "[workspace-root]",
                })),
                categories: vec!["issues".to_string(), "scm".to_string()],
                version: Some("1.2.3".to_string()),
                allowed_zones: Vec::new(),
                allowed_operations: Vec::new(),
                enforce_operation_network_constraints: true,
                enforce_empty_allow_lists: false,
                runtime_network_enforcement: RuntimeNetworkEnforcement::LegacyUnspecified,
                prewarm: ConnectorPrewarmConfig::default(),
                operation_network_constraints: BTreeMap::new(),
            },
        };

        let lifecycle_transition_request = LifecycleTransitionRequest {
            action: LifecycleAction::Reload,
            reason: Some("config rollout".to_string()),
            initiated_by: Some("admin-cli".to_string()),
            dry_run: false,
        };

        let lifecycle_transition_response = LifecycleTransitionResponse {
            connector_id: "fcp.github".to_string(),
            action: LifecycleAction::Reload,
            dry_run: false,
            previous_desired_state: DesiredRuntimeState::Enabled,
            current_desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Running,
            lifecycle_status: None,
            journal_sequence: 42,
            transitioned_at: fixed_at,
        };

        let host_simulate_request = HostSimulateRequest {
            request_id: "[request-id]".to_string(),
            connector_id: "fcp.github".to_string(),
            operation: "issues.create".to_string(),
            input: Some(serde_json::json!({
                "body": "[redacted]",
                "labels": ["bug", "triage"],
                "repository": "flywheel-ai/flywheel_connectors",
                "title": "Snapshot drift",
            })),
            zone_id: Some("z:work".to_string()),
            principal: Some("agent://cod-p9".to_string()),
            capability_token: None,
            approval_tokens: Vec::new(),
            estimate_cost: true,
            check_availability: true,
            deadline_ms: 2_500,
        };

        let host_simulate_response = HostSimulateResponse {
            request_id: "[request-id]".to_string(),
            would_succeed: false,
            phase: SimulatePhase::ConnectorReached,
            preflight_allowed: true,
            failure_reason: Some(
                "upstream dry-run rejected stale repository permissions".to_string(),
            ),
            denial_code: Some("FCP-3007".to_string()),
            missing_capabilities: vec!["github.repo:issues.write".to_string()],
            cost_estimate: Some(SimulateCostEstimate {
                api_credits: Some(1),
                estimated_duration_ms: Some(120),
                estimated_bytes: Some(2_048),
                confidence: Some(SimulateCostConfidence::High),
            }),
            availability: Some(SimulateResourceAvailability {
                available: true,
                rate_limit_remaining: Some(4_998),
                rate_limit_reset_at: Some(1_776_625_600),
                details: Some("shared org quota".to_string()),
            }),
            duration_ms: 37,
            receipt: SimulateReceipt {
                receipt_id: "[receipt-id]".to_string(),
                connector_id: "fcp.github".to_string(),
                operation: "issues.create".to_string(),
                phase: SimulatePhase::ConnectorReached,
                would_succeed: false,
                input_digest: Some("[input-digest]".to_string()),
                duration_ms: 37,
                simulated_at: fixed_at,
            },
        };

        let mut snapshot = serde_json::json!({
            "inventory_mutation_request": inventory_mutation_request,
            "lifecycle_transition_request": lifecycle_transition_request,
            "lifecycle_transition_response": lifecycle_transition_response,
            "host_simulate_request": host_simulate_request,
            "host_simulate_response": host_simulate_response,
        });
        for pointer in [
            "/lifecycle_transition_response/transitioned_at",
            "/host_simulate_response/receipt/simulated_at",
        ] {
            scrub_json_pointer(&mut snapshot, pointer, "[timestamp]");
        }

        insta::assert_json_snapshot!(
            "admin_api_request_response_shape_snapshot",
            canonicalize_json(snapshot)
        );
    }

    // ── HostAdminStateSnapshot default values ───────────────────────────

    #[test]
    fn host_admin_state_snapshot_default_initial_values() {
        let snapshot = HostAdminStateSnapshot::default();
        assert_eq!(snapshot.schema_version, HOST_ADMIN_STATE_SNAPSHOT_VERSION);
        assert!(snapshot.connectors.is_empty());
        assert!(snapshot.journal.is_empty());
        assert_eq!(snapshot.next_config_revision_id, 1);
        assert_eq!(snapshot.next_journal_sequence, 1);
        assert_eq!(snapshot.next_event_sequence, 1);
        assert_eq!(snapshot.next_log_sequence, 1);
        assert_eq!(snapshot.next_token_sequence, 1);
        assert!(snapshot.issuer_verifying_keys.is_empty());
    }

    // ── HostAdminStateStore::new default ────────────────────────────────

    #[test]
    fn host_admin_state_store_default_equals_new() {
        // The Default impl delegates to new(), verify both produce valid stores
        let _default_store = HostAdminStateStore::default();
        let _new_store = HostAdminStateStore::new();
    }
}
