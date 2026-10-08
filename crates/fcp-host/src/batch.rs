//! Batch invoke: multi-tool execution with dependency ordering.
//!
//! Allows agents to invoke multiple tools in a single request with:
//! - Dependency-aware topological ordering
//! - Bounded parallelism for independent operations
//! - Stop-on-first-error or continue-on-failure semantics
//! - Zone constraint validation (fail-fast, default deny)
//! - Per-operation timing and audit trail
//!
//! Based on bead `flywheel_connectors-2b2l`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use fcp_policy::ZoneId;
use serde::{Deserialize, Serialize};

use crate::{HostError, HostResult};

// ─────────────────────────────────────────────────────────────────────────────
// Request Types
// ─────────────────────────────────────────────────────────────────────────────

/// A batch invoke request containing multiple operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInvokeRequest {
    /// Operations to execute.
    pub operations: Vec<BatchOperation>,
    /// Execution options.
    pub options: BatchOptions,
}

/// A single operation within a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOperation {
    /// Unique identifier for this operation within the batch.
    pub id: String,
    /// Tool identifier (e.g., ``fcp.discord.send_message``).
    pub tool: String,
    /// Input payload for the tool.
    pub input: serde_json::Value,
    /// IDs of operations that must complete before this one.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Optional zone override for this operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<ZoneId>,
    /// Optional scheduler hints used by adaptive batch planning.
    #[serde(default, skip_serializing_if = "BatchScheduleHint::is_default")]
    pub scheduler: BatchScheduleHint,
}

/// Options controlling batch execution behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOptions {
    /// Maximum number of operations to run concurrently.
    #[serde(default = "default_max_parallelism")]
    pub max_parallelism: u32,
    /// Whether to abort remaining operations on first failure.
    #[serde(default)]
    pub stop_on_first_error: bool,
    /// Overall timeout for the entire batch.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Adaptive scheduling options. Defaults to deterministic FIFO tier order.
    #[serde(default, skip_serializing_if = "BatchSchedulerOptions::is_default")]
    pub scheduler: BatchSchedulerOptions,
}

const fn default_max_parallelism() -> u32 {
    8
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            max_parallelism: default_max_parallelism(),
            stop_on_first_error: false,
            timeout_ms: default_timeout_ms(),
            scheduler: BatchSchedulerOptions::default(),
        }
    }
}

/// Relative urgency hint for a batch operation.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchOperationPriority {
    /// Drop or background work.
    Low,
    /// Ordinary user-visible work.
    #[default]
    Normal,
    /// Latency-sensitive work.
    High,
    /// Control-plane work that gates the rest of the batch.
    Critical,
}

impl BatchOperationPriority {
    const fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Normal => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }
}

/// Per-operation scheduler hints for adaptive batch planning.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchScheduleHint {
    /// Relative operation priority. Higher priority runs earlier within a dependency tier.
    #[serde(default)]
    pub priority: BatchOperationPriority,
    /// Estimated service time in milliseconds for SRPT-style ordering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_duration_ms: Option<u64>,
    /// Fairness bucket used to prevent one zone/tenant from monopolizing a tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fairness_key: Option<String>,
}

impl BatchScheduleHint {
    const fn is_default(&self) -> bool {
        self.priority.rank() == BatchOperationPriority::Normal.rank()
            && self.estimated_duration_ms.is_none()
            && self.fairness_key.is_none()
    }
}

/// Batch scheduling strategy.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchSchedulerMode {
    /// Preserve deterministic topological FIFO ordering.
    #[default]
    Fifo,
    /// Reorder independent operations by priority, estimated duration, and fairness.
    Adaptive,
}

/// Scheduler options for dependency-tier batch planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSchedulerOptions {
    /// Scheduling mode. Defaults to FIFO for stable existing behavior.
    #[serde(default)]
    pub mode: BatchSchedulerMode,
    /// Maximum consecutive operations from the same fairness bucket in a tier.
    #[serde(default = "default_max_consecutive_per_fairness_key")]
    pub max_consecutive_per_fairness_key: usize,
}

const fn default_max_consecutive_per_fairness_key() -> usize {
    2
}

impl Default for BatchSchedulerOptions {
    fn default() -> Self {
        Self {
            mode: BatchSchedulerMode::Fifo,
            max_consecutive_per_fairness_key: default_max_consecutive_per_fairness_key(),
        }
    }
}

impl BatchSchedulerOptions {
    const fn is_default(&self) -> bool {
        matches!(self.mode, BatchSchedulerMode::Fifo)
            && self.max_consecutive_per_fairness_key == default_max_consecutive_per_fairness_key()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Response Types
// ─────────────────────────────────────────────────────────────────────────────

/// Overall batch status.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    /// All operations succeeded.
    Success,
    /// Some operations succeeded, some failed.
    PartialSuccess,
    /// All operations failed.
    AllFailed,
    /// Batch was aborted (e.g., `stop_on_first_error` triggered).
    Aborted,
}

/// Status of an individual operation result.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationResultStatus {
    /// Operation completed successfully.
    Success,
    /// Operation failed.
    Error,
    /// Operation was skipped (dependency failed or batch aborted).
    Skipped,
}

/// Result of a single operation within a batch.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    /// Operation ID.
    pub id: String,
    /// Result status.
    pub status: OperationResultStatus,
    /// Output payload (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// Error info (present on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BatchOperationError>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// Error details for a failed operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOperationError {
    /// Error code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Retry-after hint in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Response from a batch invoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInvokeResponse {
    /// Overall status.
    pub status: BatchStatus,
    /// Number of operations that completed successfully.
    pub completed: usize,
    /// Number of operations that failed.
    pub failed: usize,
    /// Number of operations that were skipped.
    pub skipped: usize,
    /// Per-operation results in submission order.
    pub results: Vec<OperationResult>,
    /// Total batch duration in milliseconds.
    pub total_duration_ms: u64,
    /// Optional adaptive scheduler replay report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_report: Option<BatchScheduleReport>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution Plan
// ─────────────────────────────────────────────────────────────────────────────

/// A tier of operations that can execute in parallel.
#[derive(Debug, Clone)]
pub struct ExecutionTier {
    /// Operation IDs in this tier (all independent of each other).
    pub operation_ids: Vec<String>,
}

/// An execution plan produced by topological sort.
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    /// Tiers of operations, executed sequentially; within each tier, parallel.
    pub tiers: Vec<ExecutionTier>,
    /// Total number of operations.
    pub total_operations: usize,
}

impl ExecutionPlan {
    /// Number of tiers (sequential depth).
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.tiers.len()
    }

    /// Maximum width (largest tier).
    #[must_use]
    pub fn max_width(&self) -> usize {
        self.tiers
            .iter()
            .map(|t| t.operation_ids.len())
            .max()
            .unwrap_or(0)
    }
}

/// Reason an operation moved, stayed, or fell back during scheduling.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchScheduleAction {
    /// FIFO mode was requested, so no adaptive reorder was applied.
    FifoFallback,
    /// The operation stayed in the same position after adaptive scheduling.
    Kept,
    /// The operation moved earlier because of a higher priority hint.
    PriorityPromote,
    /// The operation moved earlier because of a shorter estimated duration.
    ShortJobPromote,
    /// The operation moved to satisfy the fairness cap.
    FairnessInterleave,
}

/// Replayable counterfactual for one scheduling decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchScheduleCounterfactual {
    /// Operation position in deterministic FIFO tier order.
    pub fifo_position: usize,
    /// Operation position after scheduler application.
    pub scheduled_position: usize,
    /// Estimated wait before this operation under FIFO ordering.
    pub fifo_wait_before_ms: u64,
    /// Estimated wait before this operation under scheduled ordering.
    pub scheduled_wait_before_ms: u64,
    /// Scheduled wait minus FIFO wait. Negative means the operation moved earlier.
    pub wait_delta_ms: i64,
}

/// One scheduler decision emitted for offline replay and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchScheduleDecision {
    /// Dependency tier index.
    pub tier_index: usize,
    /// Operation id.
    pub operation_id: String,
    /// Scheduler action.
    pub action: BatchScheduleAction,
    /// Priority considered by the scheduler.
    pub priority: BatchOperationPriority,
    /// Estimated operation duration considered by the scheduler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_duration_ms: Option<u64>,
    /// Fairness bucket considered by the scheduler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fairness_key: Option<String>,
    /// Counterfactual FIFO-vs-scheduled wait estimate.
    pub counterfactual: BatchScheduleCounterfactual,
}

/// Replayable report for adaptive batch scheduler decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchScheduleReport {
    /// Scheduler mode used to build the plan.
    pub mode: BatchSchedulerMode,
    /// Total operation count.
    pub total_operations: usize,
    /// Original topological tiers before adaptive reordering.
    pub original_tiers: Vec<Vec<String>>,
    /// Final tiers after scheduler application.
    pub scheduled_tiers: Vec<Vec<String>>,
    /// Whether the scheduler intentionally preserved FIFO order.
    pub fallback: bool,
    /// Human-readable fallback reason when `fallback` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// Compact FIFO-vs-scheduled queue-wait replay summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queueing_summary: Option<BatchScheduleQueueingSummary>,
    /// Dependency-tier morsels derived from `max_parallelism`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub morselization: Option<BatchMorselizationReport>,
    /// Per-operation decisions.
    pub decisions: Vec<BatchScheduleDecision>,
}

/// Replayable report for max-parallelism bounded execution morsels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchMorselizationReport {
    /// Maximum operations allowed in one execution morsel.
    pub max_operations_per_morsel: usize,
    /// Number of morsels produced across all dependency tiers.
    pub total_morsels: usize,
    /// Number of dependency tiers that required splitting.
    pub split_tiers: usize,
    /// Largest operation count in any morsel.
    pub largest_morsel_operations: usize,
    /// Whether no tier needed splitting at the requested bound.
    pub fallback: bool,
    /// Human-readable fallback reason when no tier needed splitting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// Ordered morsels. Flattening these operation ids reproduces the scheduled tiers.
    pub morsels: Vec<BatchMorsel>,
}

/// A bounded chunk of one dependency tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct BatchMorsel {
    /// Dependency tier index.
    pub tier_index: usize,
    /// Zero-based morsel index within the tier.
    pub morsel_index: usize,
    /// Operation ids included in this morsel.
    pub operation_ids: Vec<String>,
    /// Number of operations in this morsel.
    pub operation_count: usize,
    /// Sum of operation duration estimates for replay and capacity planning.
    pub estimated_duration_ms: u64,
    /// Fairness buckets represented in this morsel.
    pub fairness_keys: Vec<String>,
}

/// Nearest-rank queue-wait percentiles in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct BatchScheduleWaitPercentiles {
    /// 50th percentile wait.
    pub p50_ms: u64,
    /// 95th percentile wait.
    pub p95_ms: u64,
    /// 99th percentile wait.
    pub p99_ms: u64,
    /// 99.9th percentile wait.
    pub p999_ms: u64,
    /// Maximum observed wait.
    pub max_ms: u64,
    /// Integer mean wait.
    pub mean_ms: u64,
}

impl BatchScheduleWaitPercentiles {
    /// Compute nearest-rank percentiles from millisecond wait samples.
    #[must_use]
    pub fn from_millis<I>(samples: I) -> Option<Self>
    where
        I: IntoIterator<Item = u64>,
    {
        let mut sorted: Vec<u64> = samples.into_iter().collect();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_unstable();
        let sum = sorted
            .iter()
            .fold(0_u128, |acc, value| acc.saturating_add(u128::from(*value)));
        let sample_count = u64::try_from(sorted.len()).unwrap_or(u64::MAX);
        let mean = sum / u128::from(sample_count.max(1));
        let mean_ms = u64::try_from(mean).unwrap_or(u64::MAX);

        Some(Self {
            p50_ms: nearest_rank_millis(&sorted, 500),
            p95_ms: nearest_rank_millis(&sorted, 950),
            p99_ms: nearest_rank_millis(&sorted, 990),
            p999_ms: nearest_rank_millis(&sorted, 999),
            max_ms: sorted[sorted.len() - 1],
            mean_ms,
        })
    }
}

/// Compact replay summary for FIFO-vs-scheduled queue waits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchScheduleQueueingSummary {
    /// Number of decisions included in the queue-wait replay.
    pub sample_count: usize,
    /// FIFO queue-wait percentiles.
    pub fifo_wait: BatchScheduleWaitPercentiles,
    /// Scheduled queue-wait percentiles.
    pub scheduled_wait: BatchScheduleWaitPercentiles,
    /// FIFO p99 minus scheduled p99. Positive means adaptive scheduling improved p99.
    pub p99_wait_improvement_ms: i64,
    /// FIFO p99.9 minus scheduled p99.9. Positive means adaptive scheduling improved p99.9.
    pub p999_wait_improvement_ms: i64,
    /// Largest per-operation wait increase versus FIFO.
    pub max_wait_increase_ms: i64,
    /// Number of operations moved earlier by priority or short-job ordering.
    pub promoted_operations: usize,
    /// Number of operations moved later than FIFO.
    pub delayed_operations: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Zone Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Maps tool names to their bound zones for validation.
#[derive(Debug, Clone, Default)]
pub struct ZoneRegistry {
    tool_zones: HashMap<String, ZoneId>,
}

impl ZoneRegistry {
    /// Create a new zone registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool's zone binding.
    pub fn register(&mut self, tool: &str, zone: ZoneId) {
        self.tool_zones.insert(tool.to_string(), zone);
    }

    /// Look up the zone for a tool.
    #[must_use]
    pub fn get_zone(&self, tool: &str) -> Option<&ZoneId> {
        self.tool_zones.get(tool)
    }
}

/// Validates zone constraints for batch operations.
#[derive(Debug)]
pub struct BatchZoneValidator {
    agent_zone: ZoneId,
    registry: ZoneRegistry,
}

impl BatchZoneValidator {
    /// Create a new zone validator.
    #[must_use]
    pub const fn new(agent_zone: ZoneId, registry: ZoneRegistry) -> Self {
        Self {
            agent_zone,
            registry,
        }
    }

    fn effective_zone<'a>(&'a self, operation: &'a BatchOperation) -> Option<&'a ZoneId> {
        operation
            .zone
            .as_ref()
            .or_else(|| self.registry.get_zone(&operation.tool))
    }

    /// Validate all operations are zone-accessible.
    ///
    /// Both the registered tool binding and an explicit operation zone must be
    /// accessible. An operation zone selects a target; it cannot authorize an
    /// unregistered tool or conceal a more privileged registered binding.
    ///
    /// Returns the IDs of operations that violate zone constraints.
    ///
    /// # Errors
    /// Returns [`HostError::PreflightFailed`] when a tool has no registered
    /// binding or either zone is inaccessible to the current agent.
    pub fn validate(&self, operations: &[BatchOperation]) -> HostResult<()> {
        let mut violations = Vec::new();
        let mut unknown_tools = Vec::new();
        for op in operations {
            let Some(bound_zone) = self.registry.get_zone(&op.tool) else {
                unknown_tools.push(op.id.clone());
                continue;
            };
            let target_zone = op.zone.as_ref().unwrap_or(bound_zone);
            if !zone_accessible(&self.agent_zone, bound_zone)
                || !zone_accessible(&self.agent_zone, target_zone)
            {
                violations.push(op.id.clone());
            }
        }
        if !unknown_tools.is_empty() {
            Err(HostError::PreflightFailed(format!(
                "missing zone mapping for operations: {}",
                unknown_tools.join(", ")
            )))
        } else if !violations.is_empty() {
            Err(HostError::PreflightFailed(format!(
                "zone boundary violations for operations: {}",
                violations.join(", ")
            )))
        } else {
            Ok(())
        }
    }

    /// Group operations by their target zone.
    #[must_use]
    pub fn group_by_zone(&self, operations: &[BatchOperation]) -> BTreeMap<String, Vec<String>> {
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for op in operations {
            let zone_str = self.effective_zone(op).map_or_else(
                || "<unresolved>".to_string(),
                |zone| zone.as_str().to_string(),
            );
            groups.entry(zone_str).or_default().push(op.id.clone());
        }
        groups
    }
}

/// Check whether an agent zone can access a connector zone.
///
/// Zone hierarchy: `z:owner` > `z:private` > `z:work` > `z:project:*` > `z:community` > `z:public`.
/// A higher-privilege zone can access lower-privilege zones but not vice versa.
fn zone_accessible(agent_zone: &ZoneId, connector_zone: &ZoneId) -> bool {
    let agent = agent_zone.as_str();
    let connector = connector_zone.as_str();

    // Same zone is always accessible.
    if agent == connector {
        return true;
    }

    let hierarchy = ["z:owner", "z:private", "z:work", "z:community", "z:public"];

    let agent_level = hierarchy.iter().position(|&z| z == agent);
    let connector_level = hierarchy.iter().position(|&z| z == connector);

    match (agent_level, connector_level) {
        (Some(a), Some(c)) => a <= c, // Lower index = higher privilege
        _ => {
            // Project zones: accessible if agent is work or higher, or same project.
            if connector.starts_with("z:project:") {
                agent == "z:owner" || agent == "z:private" || agent == "z:work"
            } else if agent.starts_with("z:project:") {
                connector == "z:community" || connector == "z:public"
            } else {
                false
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch Executor
// ─────────────────────────────────────────────────────────────────────────────

/// Batch executor that plans and executes operations.
#[derive(Debug)]
pub struct BatchExecutor {
    zone_validator: Option<BatchZoneValidator>,
}

impl BatchExecutor {
    /// Create a new batch executor without zone validation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            zone_validator: None,
        }
    }

    /// Create a new batch executor with zone validation.
    #[must_use]
    pub const fn with_zone_validator(validator: BatchZoneValidator) -> Self {
        Self {
            zone_validator: Some(validator),
        }
    }

    /// Validate a batch request before execution.
    ///
    /// # Errors
    /// Returns an error when the batch is empty, contains duplicate or
    /// unknown dependencies, contains a dependency cycle, requests zero
    /// parallelism, or fails zone validation.
    pub fn validate(&self, request: &BatchInvokeRequest) -> HostResult<()> {
        // Check for empty batch.
        if request.operations.is_empty() {
            return Err(HostError::InvalidFilter("batch has no operations".into()));
        }

        // Check for duplicate IDs.
        let mut seen = HashSet::new();
        for op in &request.operations {
            if !seen.insert(&op.id) {
                return Err(HostError::InvalidFilter(format!(
                    "duplicate operation id: {}",
                    op.id
                )));
            }
        }

        // Check max_parallelism > 0.
        if request.options.max_parallelism == 0 {
            return Err(HostError::InvalidFilter(
                "max_parallelism must be > 0".into(),
            ));
        }

        if matches!(request.options.scheduler.mode, BatchSchedulerMode::Adaptive)
            && request.options.scheduler.max_consecutive_per_fairness_key == 0
        {
            return Err(HostError::InvalidFilter(
                "adaptive scheduler fairness cap must be > 0".into(),
            ));
        }

        // Check that all depends_on references exist.
        let all_ids: HashSet<&str> = request.operations.iter().map(|o| o.id.as_str()).collect();
        for op in &request.operations {
            for dep in &op.depends_on {
                if !all_ids.contains(dep.as_str()) {
                    return Err(HostError::InvalidFilter(format!(
                        "operation '{}' depends on unknown operation '{dep}'",
                        op.id
                    )));
                }
            }
            // Check self-dependency.
            if op.depends_on.contains(&op.id) {
                return Err(HostError::InvalidFilter(format!(
                    "operation '{}' depends on itself",
                    op.id
                )));
            }
        }

        // Check for cycles.
        if has_cycle(&request.operations) {
            return Err(HostError::InvalidFilter(
                "dependency cycle detected in batch operations".into(),
            ));
        }

        // Zone validation.
        if let Some(ref validator) = self.zone_validator {
            validator.validate(&request.operations)?;
        }

        Ok(())
    }

    /// Build an execution plan via topological sort.
    ///
    /// Operations are grouped into tiers: within each tier, operations are
    /// independent and can run in parallel. Tiers must execute sequentially.
    ///
    /// # Errors
    /// Returns any validation error produced by [`Self::validate`] or a cycle
    /// detection error if the dependency graph cannot be tiered.
    pub fn plan(&self, request: &BatchInvokeRequest) -> HostResult<ExecutionPlan> {
        self.validate(request)?;
        let tiers = topological_tiers(&request.operations)?;
        let tiers = schedule_tiers(&request.operations, tiers, &request.options.scheduler);
        Ok(ExecutionPlan {
            total_operations: request.operations.len(),
            tiers,
        })
    }

    /// Build an execution plan and a replayable scheduler decision report.
    ///
    /// # Errors
    /// Returns any validation error produced by [`Self::validate`] or a cycle
    /// detection error if the dependency graph cannot be tiered.
    pub fn plan_with_schedule_report(
        &self,
        request: &BatchInvokeRequest,
    ) -> HostResult<(ExecutionPlan, BatchScheduleReport)> {
        self.validate(request)?;
        let tiers = topological_tiers(&request.operations)?;
        let (tiers, report) =
            schedule_tiers_with_report(&request.operations, tiers, &request.options);
        Ok((
            ExecutionPlan {
                total_operations: request.operations.len(),
                tiers,
            },
            report,
        ))
    }

    /// Execute a batch synchronously using a provided handler function.
    ///
    /// The `handler` is called for each operation and returns either an output
    /// value or an error. Operations are executed in topological tier order.
    /// Within each tier, operations are executed sequentially (async parallel
    /// execution is handled at a higher layer).
    ///
    /// # Errors
    /// Returns any validation or planning error produced before execution
    /// begins. Individual operation failures are captured in the response.
    pub fn execute_sync<F>(
        &self,
        request: &BatchInvokeRequest,
        handler: F,
    ) -> HostResult<BatchInvokeResponse>
    where
        F: Fn(&BatchOperation) -> Result<serde_json::Value, BatchOperationError>,
    {
        let (plan, schedule_report) = self.plan_with_schedule_report(request)?;
        let schedule_report =
            matches!(request.options.scheduler.mode, BatchSchedulerMode::Adaptive)
                .then_some(schedule_report);
        let start = Instant::now();
        let timeout = Duration::from_millis(request.options.timeout_ms);
        let op_map: HashMap<&str, &BatchOperation> = request
            .operations
            .iter()
            .map(|o| (o.id.as_str(), o))
            .collect();
        let mut results_map: HashMap<String, OperationResult> =
            HashMap::with_capacity(request.operations.len());
        let mut aborted = false;

        for tier in &plan.tiers {
            if aborted {
                record_skipped_operations(&mut results_map, &tier.operation_ids, None);
                continue;
            }

            if start.elapsed() >= timeout {
                aborted = true;
                let timeout_error = batch_timeout_error();
                record_skipped_operations(
                    &mut results_map,
                    &tier.operation_ids,
                    Some(&timeout_error),
                );
                continue;
            }

            execute_tier(
                tier,
                &op_map,
                &mut results_map,
                request.options.stop_on_first_error,
                &handler,
                &mut aborted,
            );
        }

        Ok(build_response(
            request,
            results_map,
            aborted,
            start,
            schedule_report,
        ))
    }
}

impl Default for BatchExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Graph Algorithms
// ─────────────────────────────────────────────────────────────────────────────

/// Detect cycles in the operation dependency graph using iterative DFS.
fn has_cycle(operations: &[BatchOperation]) -> bool {
    let id_set: HashSet<&str> = operations.iter().map(|o| o.id.as_str()).collect();
    let deps: HashMap<&str, Vec<&str>> = operations
        .iter()
        .map(|o| {
            (
                o.id.as_str(),
                o.depends_on
                    .iter()
                    .filter_map(|d| {
                        if id_set.contains(d.as_str()) {
                            Some(d.as_str())
                        } else {
                            None
                        }
                    })
                    .collect(),
            )
        })
        .collect();

    // States: 0=unvisited, 1=in-progress, 2=done
    let mut state: HashMap<&str, u8> = deps.keys().map(|&k| (k, 0)).collect();

    for &start in deps.keys() {
        if state[start] == 2 {
            continue;
        }
        // Iterative DFS with explicit stack of (node, iterator_position).
        let mut stack: Vec<(&str, usize)> = vec![(start, 0)];
        state.insert(start, 1);

        while let Some((node, idx)) = stack.last_mut() {
            let neighbors = &deps[*node];
            if *idx < neighbors.len() {
                let next = neighbors[*idx];
                *idx += 1;
                match state[next] {
                    1 => return true, // Back edge → cycle.
                    0 => {
                        state.insert(next, 1);
                        stack.push((next, 0));
                    }
                    _ => {} // Already done.
                }
            } else {
                state.insert(*node, 2);
                stack.pop();
            }
        }
    }

    false
}

/// Compute topological tiers via Kahn's algorithm.
///
/// Returns tiers where each tier contains operations whose dependencies are
/// all satisfied by prior tiers.
fn topological_tiers(operations: &[BatchOperation]) -> HostResult<Vec<ExecutionTier>> {
    let id_set: HashSet<&str> = operations.iter().map(|o| o.id.as_str()).collect();

    // Build adjacency and in-degree. Pre-allocate for the known operation count
    // to avoid rehashing as the maps grow.
    let mut in_degree: HashMap<&str, usize> = HashMap::with_capacity(operations.len());
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::with_capacity(operations.len());

    for op in operations {
        let mut degree = 0;
        let op_id = op.id.as_str();

        for dep in &op.depends_on {
            if id_set.contains(dep.as_str()) {
                degree += 1;
                dependents.entry(dep.as_str()).or_default().push(op_id);
            }
        }

        *in_degree.entry(op_id).or_default() += degree;
    }

    let mut tiers = Vec::new();
    let mut queue: Vec<&str> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(&id, _)| id)
        .collect();
    queue.sort_unstable();

    let mut processed = 0usize;

    while !queue.is_empty() {
        let tier_ids: Vec<String> = queue.iter().copied().map(String::from).collect();
        queue.clear();
        processed += tier_ids.len();

        let mut next_ready: Vec<&str> = Vec::new();
        for id in &tier_ids {
            if let Some(deps) = dependents.get(id.as_str()) {
                for &dep_id in deps {
                    if let Some(deg) = in_degree.get_mut(dep_id) {
                        *deg -= 1;
                        if *deg == 0 {
                            next_ready.push(dep_id);
                        }
                    }
                }
            }
        }

        tiers.push(ExecutionTier {
            operation_ids: tier_ids,
        });

        next_ready.sort_unstable();
        queue = next_ready;
    }

    if processed != operations.len() {
        return Err(HostError::InvalidFilter(
            "dependency cycle detected in batch operations".into(),
        ));
    }

    Ok(tiers)
}

const UNKNOWN_ESTIMATED_DURATION_MS: u64 = 1_000_000;

struct BatchSchedulerMetadata<'a> {
    operations: HashMap<&'a str, &'a BatchOperation>,
}

impl<'a> BatchSchedulerMetadata<'a> {
    fn new(operations: &'a [BatchOperation]) -> Self {
        Self {
            operations: operations
                .iter()
                .map(|operation| (operation.id.as_str(), operation))
                .collect(),
        }
    }

    fn operation(&self, operation_id: &str) -> &'a BatchOperation {
        self.operations
            .get(operation_id)
            .copied()
            .expect("planned batch operation must exist")
    }

    fn hint(&self, operation_id: &str) -> &'a BatchScheduleHint {
        &self.operation(operation_id).scheduler
    }

    fn fairness_key(&self, operation_id: &str) -> Option<String> {
        let operation = self.operation(operation_id);
        operation
            .scheduler
            .fairness_key
            .clone()
            .or_else(|| operation.zone.as_ref().map(|zone| zone.as_str().to_owned()))
    }

    fn estimated_duration_ms(&self, operation_id: &str) -> u64 {
        self.hint(operation_id)
            .estimated_duration_ms
            .unwrap_or(UNKNOWN_ESTIMATED_DURATION_MS)
    }
}

fn schedule_tiers(
    operations: &[BatchOperation],
    tiers: Vec<ExecutionTier>,
    options: &BatchSchedulerOptions,
) -> Vec<ExecutionTier> {
    if !matches!(options.mode, BatchSchedulerMode::Adaptive) {
        return tiers;
    }

    let metadata = BatchSchedulerMetadata::new(operations);
    tiers
        .into_iter()
        .map(|tier| ExecutionTier {
            operation_ids: adaptive_order_tier(&tier.operation_ids, &metadata, options),
        })
        .collect()
}

fn schedule_tiers_with_report(
    operations: &[BatchOperation],
    tiers: Vec<ExecutionTier>,
    options: &BatchOptions,
) -> (Vec<ExecutionTier>, BatchScheduleReport) {
    let scheduler = &options.scheduler;
    let original_tiers: Vec<Vec<String>> = tiers
        .iter()
        .map(|tier| tier.operation_ids.clone())
        .collect();
    let scheduled_tiers = schedule_tiers(operations, tiers, scheduler);
    let scheduled_tier_ids: Vec<Vec<String>> = scheduled_tiers
        .iter()
        .map(|tier| tier.operation_ids.clone())
        .collect();
    let fallback = matches!(scheduler.mode, BatchSchedulerMode::Fifo);
    let decisions = schedule_decisions(
        operations,
        &original_tiers,
        &scheduled_tier_ids,
        scheduler.mode,
    );
    let morselization = morselization_report(
        operations,
        &scheduled_tier_ids,
        usize::try_from(options.max_parallelism)
            .unwrap_or(usize::MAX)
            .max(1),
    );

    (
        scheduled_tiers,
        BatchScheduleReport {
            mode: scheduler.mode,
            total_operations: operations.len(),
            original_tiers,
            scheduled_tiers: scheduled_tier_ids,
            fallback,
            fallback_reason: fallback.then(|| "scheduler mode is fifo".to_owned()),
            queueing_summary: queueing_summary_from_decisions(&decisions),
            morselization: Some(morselization),
            decisions,
        },
    )
}

fn adaptive_order_tier(
    operation_ids: &[String],
    metadata: &BatchSchedulerMetadata<'_>,
    options: &BatchSchedulerOptions,
) -> Vec<String> {
    let mut pending = operation_ids.to_vec();
    pending.sort_by(|left, right| compare_schedule_key(left, right, metadata));
    apply_fairness_cap(
        pending,
        metadata,
        options.max_consecutive_per_fairness_key.max(1),
    )
}

fn compare_schedule_key(
    left: &str,
    right: &str,
    metadata: &BatchSchedulerMetadata<'_>,
) -> std::cmp::Ordering {
    let left_hint = metadata.hint(left);
    let right_hint = metadata.hint(right);
    right_hint
        .priority
        .rank()
        .cmp(&left_hint.priority.rank())
        .then_with(|| {
            metadata
                .estimated_duration_ms(left)
                .cmp(&metadata.estimated_duration_ms(right))
        })
        .then_with(|| left.cmp(right))
}

fn apply_fairness_cap(
    mut pending: Vec<String>,
    metadata: &BatchSchedulerMetadata<'_>,
    fairness_cap: usize,
) -> Vec<String> {
    let mut scheduled = Vec::with_capacity(pending.len());
    let mut last_key: Option<String> = None;
    let mut streak = 0usize;

    while !pending.is_empty() {
        let choice = fairness_choice_index(
            &pending,
            metadata,
            last_key.as_deref(),
            streak,
            fairness_cap,
        );
        let operation_id = pending.remove(choice);
        let key = metadata.fairness_key(&operation_id);
        if last_key.as_deref() == key.as_deref() {
            streak += 1;
        } else {
            last_key = key;
            streak = 1;
        }
        scheduled.push(operation_id);
    }

    scheduled
}

fn fairness_choice_index(
    pending: &[String],
    metadata: &BatchSchedulerMetadata<'_>,
    last_key: Option<&str>,
    streak: usize,
    fairness_cap: usize,
) -> usize {
    if streak < fairness_cap {
        return 0;
    }

    let Some(last_key) = last_key else {
        return 0;
    };

    pending
        .iter()
        .position(|operation_id| metadata.fairness_key(operation_id).as_deref() != Some(last_key))
        .unwrap_or(0)
}

fn schedule_decisions(
    operations: &[BatchOperation],
    original_tiers: &[Vec<String>],
    scheduled_tiers: &[Vec<String>],
    mode: BatchSchedulerMode,
) -> Vec<BatchScheduleDecision> {
    let metadata = BatchSchedulerMetadata::new(operations);
    let mut decisions = Vec::with_capacity(operations.len());

    for (tier_index, (original, scheduled)) in
        original_tiers.iter().zip(scheduled_tiers).enumerate()
    {
        let original_positions = positions_by_operation(original);
        let scheduled_positions = positions_by_operation(scheduled);
        let fifo_waits = wait_before_by_operation(original, &metadata);
        let scheduled_waits = wait_before_by_operation(scheduled, &metadata);

        for operation_id in scheduled {
            let fifo_position = original_positions[operation_id.as_str()];
            let scheduled_position = scheduled_positions[operation_id.as_str()];
            let hint = metadata.hint(operation_id);
            let fifo_wait = fifo_waits[operation_id.as_str()];
            let scheduled_wait = scheduled_waits[operation_id.as_str()];
            decisions.push(BatchScheduleDecision {
                tier_index,
                operation_id: operation_id.clone(),
                action: schedule_action(mode, fifo_position, scheduled_position, hint),
                priority: hint.priority,
                estimated_duration_ms: hint.estimated_duration_ms,
                fairness_key: metadata.fairness_key(operation_id),
                counterfactual: BatchScheduleCounterfactual {
                    fifo_position,
                    scheduled_position,
                    fifo_wait_before_ms: fifo_wait,
                    scheduled_wait_before_ms: scheduled_wait,
                    wait_delta_ms: wait_delta_ms(scheduled_wait, fifo_wait),
                },
            });
        }
    }

    decisions
}

fn positions_by_operation(operation_ids: &[String]) -> HashMap<&str, usize> {
    operation_ids
        .iter()
        .enumerate()
        .map(|(index, operation_id)| (operation_id.as_str(), index))
        .collect()
}

fn wait_before_by_operation<'a>(
    operation_ids: &'a [String],
    metadata: &BatchSchedulerMetadata<'_>,
) -> HashMap<&'a str, u64> {
    let mut waits = HashMap::with_capacity(operation_ids.len());
    let mut elapsed = 0u64;
    for operation_id in operation_ids {
        waits.insert(operation_id.as_str(), elapsed);
        elapsed = elapsed.saturating_add(metadata.estimated_duration_ms(operation_id));
    }
    waits
}

fn nearest_rank_millis(sorted: &[u64], per_mille: usize) -> u64 {
    let len = sorted.len();
    let rank = len.saturating_mul(per_mille).saturating_add(999) / 1_000;
    let index = rank.saturating_sub(1).min(len - 1);
    sorted[index]
}

fn queueing_summary_from_decisions(
    decisions: &[BatchScheduleDecision],
) -> Option<BatchScheduleQueueingSummary> {
    let fifo_wait = BatchScheduleWaitPercentiles::from_millis(
        decisions
            .iter()
            .map(|decision| decision.counterfactual.fifo_wait_before_ms),
    )?;
    let scheduled_wait = BatchScheduleWaitPercentiles::from_millis(
        decisions
            .iter()
            .map(|decision| decision.counterfactual.scheduled_wait_before_ms),
    )?;
    let max_wait_increase_ms = decisions
        .iter()
        .map(|decision| decision.counterfactual.wait_delta_ms.max(0))
        .max()
        .unwrap_or(0);
    let promoted_operations = decisions
        .iter()
        .filter(|decision| {
            matches!(
                decision.action,
                BatchScheduleAction::PriorityPromote | BatchScheduleAction::ShortJobPromote
            )
        })
        .count();
    let delayed_operations = decisions
        .iter()
        .filter(|decision| decision.counterfactual.wait_delta_ms > 0)
        .count();

    Some(BatchScheduleQueueingSummary {
        sample_count: decisions.len(),
        fifo_wait,
        scheduled_wait,
        p99_wait_improvement_ms: signed_millis_delta(fifo_wait.p99_ms, scheduled_wait.p99_ms),
        p999_wait_improvement_ms: signed_millis_delta(fifo_wait.p999_ms, scheduled_wait.p999_ms),
        max_wait_increase_ms,
        promoted_operations,
        delayed_operations,
    })
}

fn morselization_report(
    operations: &[BatchOperation],
    scheduled_tiers: &[Vec<String>],
    max_operations_per_morsel: usize,
) -> BatchMorselizationReport {
    let max_operations_per_morsel = max_operations_per_morsel.max(1);
    let metadata = BatchSchedulerMetadata::new(operations);
    let mut morsels = Vec::new();
    let mut split_tiers = 0usize;
    let mut largest_morsel_operations = 0usize;

    for (tier_index, tier) in scheduled_tiers.iter().enumerate() {
        if tier.len() > max_operations_per_morsel {
            split_tiers += 1;
        }

        for (morsel_index, chunk) in tier.chunks(max_operations_per_morsel).enumerate() {
            largest_morsel_operations = largest_morsel_operations.max(chunk.len());
            let estimated_duration_ms = chunk.iter().fold(0_u64, |total, operation_id| {
                total.saturating_add(metadata.estimated_duration_ms(operation_id))
            });
            let mut fairness_keys: Vec<String> = chunk
                .iter()
                .filter_map(|operation_id| metadata.fairness_key(operation_id))
                .collect();
            fairness_keys.sort();
            fairness_keys.dedup();

            morsels.push(BatchMorsel {
                tier_index,
                morsel_index,
                operation_ids: chunk.to_vec(),
                operation_count: chunk.len(),
                estimated_duration_ms,
                fairness_keys,
            });
        }
    }

    let fallback = split_tiers == 0;
    BatchMorselizationReport {
        max_operations_per_morsel,
        total_morsels: morsels.len(),
        split_tiers,
        largest_morsel_operations,
        fallback,
        fallback_reason: fallback
            .then(|| "all scheduled tiers fit within max_parallelism".to_owned()),
        morsels,
    }
}

const fn schedule_action(
    mode: BatchSchedulerMode,
    fifo_position: usize,
    scheduled_position: usize,
    hint: &BatchScheduleHint,
) -> BatchScheduleAction {
    if matches!(mode, BatchSchedulerMode::Fifo) {
        return BatchScheduleAction::FifoFallback;
    }

    if fifo_position == scheduled_position {
        return BatchScheduleAction::Kept;
    }

    if scheduled_position < fifo_position {
        if hint.priority.rank() > BatchOperationPriority::Normal.rank() {
            BatchScheduleAction::PriorityPromote
        } else {
            BatchScheduleAction::ShortJobPromote
        }
    } else {
        BatchScheduleAction::FairnessInterleave
    }
}

fn wait_delta_ms(scheduled_wait: u64, fifo_wait: u64) -> i64 {
    signed_millis_delta(scheduled_wait, fifo_wait)
}

fn signed_millis_delta(left: u64, right: u64) -> i64 {
    let delta = i128::from(left) - i128::from(right);
    let clamped = delta.clamp(i128::from(i64::MIN), i128::from(i64::MAX));
    i64::try_from(clamped).unwrap_or_else(|_| unreachable!("clamped wait delta must fit in i64"))
}

fn batch_timeout_error() -> BatchOperationError {
    BatchOperationError {
        code: "BATCH_TIMEOUT".into(),
        message: "batch timeout exceeded".into(),
        retry_after_ms: None,
    }
}

fn dependency_failed_error() -> BatchOperationError {
    BatchOperationError {
        code: "DEP_FAILED".into(),
        message: "dependency failed".into(),
        retry_after_ms: None,
    }
}

const fn skipped_result(id: String, error: Option<BatchOperationError>) -> OperationResult {
    OperationResult {
        id,
        status: OperationResultStatus::Skipped,
        output: None,
        error,
        duration_ms: 0,
    }
}

fn executed_result(
    id: &str,
    result: Result<serde_json::Value, BatchOperationError>,
    started_at: Instant,
) -> OperationResult {
    match result {
        Ok(output) => OperationResult {
            id: id.to_string(),
            status: OperationResultStatus::Success,
            output: Some(output),
            error: None,
            duration_ms: elapsed_millis(started_at),
        },
        Err(error) => OperationResult {
            id: id.to_string(),
            status: OperationResultStatus::Error,
            output: None,
            error: Some(error),
            duration_ms: elapsed_millis(started_at),
        },
    }
}

fn elapsed_millis(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn dependency_failed(
    operation: &BatchOperation,
    results_map: &HashMap<String, OperationResult>,
) -> bool {
    operation.depends_on.iter().any(|dependency_id| {
        results_map
            .get(dependency_id.as_str())
            .is_some_and(|result| result.status != OperationResultStatus::Success)
    })
}

fn record_skipped_operations(
    results_map: &mut HashMap<String, OperationResult>,
    operation_ids: &[String],
    error: Option<&BatchOperationError>,
) {
    for operation_id in operation_ids {
        results_map.insert(
            operation_id.clone(),
            skipped_result(operation_id.clone(), error.cloned()),
        );
    }
}

fn execute_tier<F>(
    tier: &ExecutionTier,
    operation_map: &HashMap<&str, &BatchOperation>,
    results_map: &mut HashMap<String, OperationResult>,
    stop_on_first_error: bool,
    handler: &F,
    aborted: &mut bool,
) where
    F: Fn(&BatchOperation) -> Result<serde_json::Value, BatchOperationError>,
{
    for operation_id in &tier.operation_ids {
        if *aborted {
            results_map.insert(
                operation_id.clone(),
                skipped_result(operation_id.clone(), None),
            );
            continue;
        }

        let operation = operation_map[operation_id.as_str()];
        if dependency_failed(operation, results_map) {
            results_map.insert(
                operation_id.clone(),
                skipped_result(operation_id.clone(), Some(dependency_failed_error())),
            );
            continue;
        }

        let started_at = Instant::now();
        let result = executed_result(operation_id, handler(operation), started_at);
        if stop_on_first_error && result.status == OperationResultStatus::Error {
            *aborted = true;
        }
        results_map.insert(operation_id.clone(), result);
    }
}

fn build_response(
    request: &BatchInvokeRequest,
    mut results_map: HashMap<String, OperationResult>,
    aborted: bool,
    started_at: Instant,
    schedule_report: Option<BatchScheduleReport>,
) -> BatchInvokeResponse {
    let results: Vec<OperationResult> = request
        .operations
        .iter()
        .map(|operation| {
            results_map
                .remove(operation.id.as_str())
                .unwrap_or_else(|| skipped_result(operation.id.clone(), None))
        })
        .collect();

    let completed = results
        .iter()
        .filter(|result| result.status == OperationResultStatus::Success)
        .count();
    let failed = results
        .iter()
        .filter(|result| result.status == OperationResultStatus::Error)
        .count();
    let skipped = results
        .iter()
        .filter(|result| result.status == OperationResultStatus::Skipped)
        .count();

    BatchInvokeResponse {
        status: batch_status(aborted, completed, failed),
        completed,
        failed,
        skipped,
        results,
        total_duration_ms: elapsed_millis(started_at),
        schedule_report,
    }
}

const fn batch_status(aborted: bool, completed: usize, failed: usize) -> BatchStatus {
    if aborted && failed > 0 {
        BatchStatus::Aborted
    } else if failed == 0 {
        BatchStatus::Success
    } else if completed == 0 {
        BatchStatus::AllFailed
    } else {
        BatchStatus::PartialSuccess
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::redundant_clone,
        reason = "clone-focused tests intentionally exercise Clone impls"
    )]

    use super::*;

    // ── Helpers ──

    fn op(id: &str, tool: &str, deps: &[&str]) -> BatchOperation {
        BatchOperation {
            id: id.into(),
            tool: tool.into(),
            input: serde_json::json!({}),
            depends_on: deps.iter().map(|&s| s.into()).collect(),
            zone: None,
            scheduler: BatchScheduleHint::default(),
        }
    }

    fn scheduled_op(
        id: &str,
        priority: BatchOperationPriority,
        estimated_duration_ms: u64,
        fairness_key: Option<&str>,
        deps: &[&str],
    ) -> BatchOperation {
        let mut operation = op(id, "tool", deps);
        operation.scheduler = BatchScheduleHint {
            priority,
            estimated_duration_ms: Some(estimated_duration_ms),
            fairness_key: fairness_key.map(String::from),
        };
        operation
    }

    fn simple_request(ops: Vec<BatchOperation>) -> BatchInvokeRequest {
        BatchInvokeRequest {
            operations: ops,
            options: BatchOptions::default(),
        }
    }

    fn adaptive_request(ops: Vec<BatchOperation>) -> BatchInvokeRequest {
        BatchInvokeRequest {
            operations: ops,
            options: BatchOptions {
                scheduler: BatchSchedulerOptions {
                    mode: BatchSchedulerMode::Adaptive,
                    max_consecutive_per_fairness_key: 2,
                },
                ..Default::default()
            },
        }
    }

    fn skewed_swarm_scheduler_ops() -> Vec<BatchOperation> {
        let mut operations = Vec::with_capacity(1_000);
        for index in 0..10 {
            operations.push(scheduled_op(
                &format!("long_{index:02}"),
                BatchOperationPriority::Normal,
                10_000,
                Some("tenant-long"),
                &[],
            ));
        }
        for index in 0..990 {
            operations.push(scheduled_op(
                &format!("short_{index:03}"),
                BatchOperationPriority::Normal,
                1,
                Some(&format!("tenant-short-{}", index % 64)),
                &[],
            ));
        }
        operations
    }

    fn ok_output(_op: &BatchOperation) -> serde_json::Value {
        serde_json::json!({"ok": true})
    }

    fn failing_handler(_op: &BatchOperation) -> Result<serde_json::Value, BatchOperationError> {
        Err(BatchOperationError {
            code: "TEST_ERROR".into(),
            message: "test failure".into(),
            retry_after_ms: None,
        })
    }

    fn selective_handler(op: &BatchOperation) -> Result<serde_json::Value, BatchOperationError> {
        if op.id.starts_with("fail") {
            Err(BatchOperationError {
                code: "FAIL".into(),
                message: format!("{} failed", op.id),
                retry_after_ms: None,
            })
        } else {
            Ok(serde_json::json!({"id": op.id}))
        }
    }

    // ── Validation Tests ──

    #[test]
    fn validate_empty_batch_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("no operations"));
    }

    #[test]
    fn validate_duplicate_ids_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool1", &[]), op("a", "tool2", &[])]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("duplicate operation id"));
    }

    #[test]
    fn validate_unknown_dependency_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool1", &["nonexistent"])]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("unknown operation"));
    }

    #[test]
    fn validate_self_dependency_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool1", &["a"])]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("depends on itself"));
    }

    #[test]
    fn validate_cycle_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool1", &["b"]), op("b", "tool1", &["a"])]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn validate_three_node_cycle_rejected() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &["c"]),
            op("b", "tool1", &["a"]),
            op("c", "tool1", &["b"]),
        ]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn validate_zero_parallelism_rejected() {
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![op("a", "tool1", &[])],
            options: BatchOptions {
                max_parallelism: 0,
                ..Default::default()
            },
        };
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("max_parallelism"));
    }

    #[test]
    fn validate_batch_scheduler_rejects_zero_fairness_cap() {
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![op("a", "tool1", &[])],
            options: BatchOptions {
                scheduler: BatchSchedulerOptions {
                    mode: BatchSchedulerMode::Adaptive,
                    max_consecutive_per_fairness_key: 0,
                },
                ..Default::default()
            },
        };
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("fairness cap"));
    }

    #[test]
    fn validate_valid_request_passes() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &["a"]),
            op("c", "tool3", &["a"]),
            op("d", "tool4", &["b", "c"]),
        ]);
        assert!(executor.validate(&req).is_ok());
    }

    #[test]
    fn validate_single_operation_passes() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("only", "tool", &[])]);
        assert!(executor.validate(&req).is_ok());
    }

    #[test]
    fn validate_no_dependencies_passes() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &[]),
            op("c", "tool3", &[]),
        ]);
        assert!(executor.validate(&req).is_ok());
    }

    // ── Execution Plan Tests ──

    #[test]
    fn plan_single_op_one_tier() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool", &[])]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.tiers.len(), 1);
        assert_eq!(plan.tiers[0].operation_ids, vec!["a"]);
        assert_eq!(plan.total_operations, 1);
    }

    #[test]
    fn plan_independent_ops_single_tier() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &[]),
            op("c", "tool3", &[]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.tiers.len(), 1);
        assert_eq!(plan.tiers[0].operation_ids.len(), 3);
    }

    #[test]
    fn plan_linear_chain_three_tiers() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &["a"]),
            op("c", "tool3", &["b"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 3);
        assert_eq!(plan.max_width(), 1);
        assert_eq!(plan.tiers[0].operation_ids, vec!["a"]);
        assert_eq!(plan.tiers[1].operation_ids, vec!["b"]);
        assert_eq!(plan.tiers[2].operation_ids, vec!["c"]);
    }

    #[test]
    fn plan_diamond_shape() {
        // a -> b, a -> c, b -> d, c -> d
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "tool1", &[]),
            op("b", "tool2", &["a"]),
            op("c", "tool3", &["a"]),
            op("d", "tool4", &["b", "c"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 3);
        assert_eq!(plan.tiers[0].operation_ids, vec!["a"]);
        assert_eq!(plan.tiers[1].operation_ids.len(), 2);
        assert!(plan.tiers[1].operation_ids.contains(&"b".to_string()));
        assert!(plan.tiers[1].operation_ids.contains(&"c".to_string()));
        assert_eq!(plan.tiers[2].operation_ids, vec!["d"]);
    }

    #[test]
    fn plan_wide_then_narrow() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "t", &[]),
            op("b", "t", &[]),
            op("c", "t", &[]),
            op("d", "t", &[]),
            op("e", "t", &["a", "b", "c", "d"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 2);
        assert_eq!(plan.max_width(), 4);
        assert_eq!(plan.tiers[1].operation_ids, vec!["e"]);
    }

    #[test]
    fn plan_deterministic_ordering() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("z", "t", &[]),
            op("a", "t", &[]),
            op("m", "t", &[]),
        ]);
        let plan1 = executor.plan(&req).unwrap();
        let plan2 = executor.plan(&req).unwrap();
        assert_eq!(
            plan1.tiers[0].operation_ids, plan2.tiers[0].operation_ids,
            "plan should be deterministic"
        );
        // Sorted alphabetically.
        assert_eq!(plan1.tiers[0].operation_ids, vec!["a", "m", "z"]);
    }

    #[test]
    fn batch_scheduler_fifo_report_preserves_default_order() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            scheduled_op("z", BatchOperationPriority::Critical, 1, None, &[]),
            scheduled_op("a", BatchOperationPriority::Low, 1, None, &[]),
            scheduled_op("m", BatchOperationPriority::High, 1, None, &[]),
        ]);
        let (plan, report) = executor.plan_with_schedule_report(&req).unwrap();

        assert_eq!(plan.tiers[0].operation_ids, vec!["a", "m", "z"]);
        assert!(report.fallback);
        assert_eq!(
            report.fallback_reason.as_deref(),
            Some("scheduler mode is fifo")
        );
        assert!(
            report
                .decisions
                .iter()
                .all(|decision| decision.action == BatchScheduleAction::FifoFallback)
        );
        let morselization = report
            .morselization
            .expect("schedule report should include max-parallelism morsels");
        assert!(morselization.fallback);
        assert_eq!(
            morselization.fallback_reason.as_deref(),
            Some("all scheduled tiers fit within max_parallelism")
        );
        assert_eq!(morselization.total_morsels, 1);
    }

    #[test]
    fn batch_scheduler_adaptive_prioritizes_critical_and_short_jobs() {
        let executor = BatchExecutor::new();
        let req = adaptive_request(vec![
            scheduled_op("a_long", BatchOperationPriority::Normal, 10_000, None, &[]),
            scheduled_op("z_short", BatchOperationPriority::Normal, 10, None, &[]),
            scheduled_op(
                "c_critical",
                BatchOperationPriority::Critical,
                25,
                None,
                &[],
            ),
        ]);
        let (plan, report) = executor.plan_with_schedule_report(&req).unwrap();

        assert_eq!(
            plan.tiers[0].operation_ids,
            vec!["c_critical", "z_short", "a_long"]
        );
        let critical = report
            .decisions
            .iter()
            .find(|decision| decision.operation_id == "c_critical")
            .unwrap();
        assert_eq!(critical.action, BatchScheduleAction::PriorityPromote);
        assert!(critical.counterfactual.wait_delta_ms < 0);

        let short = report
            .decisions
            .iter()
            .find(|decision| decision.operation_id == "z_short")
            .unwrap();
        assert_eq!(short.action, BatchScheduleAction::ShortJobPromote);
        assert_eq!(short.counterfactual.scheduled_wait_before_ms, 25);
    }

    #[test]
    fn batch_scheduler_replay_summary_proves_tail_queueing_gain_without_starvation() {
        let executor = BatchExecutor::new();
        let req = adaptive_request(skewed_swarm_scheduler_ops());
        let (plan, report) = executor.plan_with_schedule_report(&req).unwrap();
        let summary = report
            .queueing_summary
            .as_ref()
            .expect("adaptive report should include queueing summary");

        assert_eq!(summary.sample_count, 1_000);
        assert_eq!(summary.promoted_operations, 990);
        assert_eq!(summary.delayed_operations, 10);
        assert!(
            summary.p99_wait_improvement_ms > 90_000,
            "expected p99 queueing gain from short-job promotion; got {summary:?}"
        );
        assert!(
            summary.p999_wait_improvement_ms > 10_000,
            "expected p99.9 queueing gain from short-job promotion; got {summary:?}"
        );
        assert!(
            summary.max_wait_increase_ms <= 990,
            "long jobs may wait behind the short burst but must not starve; got {summary:?}"
        );
        assert_eq!(summary.scheduled_wait.p99_ms, 989);
        assert_eq!(summary.fifo_wait.p99_ms, 100_979);
        assert_eq!(
            plan.tiers[0]
                .operation_ids
                .first()
                .expect("scheduled tier has operations"),
            "short_000"
        );
    }

    #[test]
    fn batch_scheduler_adaptive_interleaves_fairness_buckets() {
        let executor = BatchExecutor::new();
        let req = adaptive_request(vec![
            scheduled_op(
                "a1",
                BatchOperationPriority::Normal,
                10,
                Some("tenant-a"),
                &[],
            ),
            scheduled_op(
                "a2",
                BatchOperationPriority::Normal,
                10,
                Some("tenant-a"),
                &[],
            ),
            scheduled_op(
                "a3",
                BatchOperationPriority::Normal,
                10,
                Some("tenant-a"),
                &[],
            ),
            scheduled_op(
                "b1",
                BatchOperationPriority::Normal,
                10,
                Some("tenant-b"),
                &[],
            ),
        ]);
        let (plan, report) = executor.plan_with_schedule_report(&req).unwrap();

        assert_eq!(plan.tiers[0].operation_ids, vec!["a1", "a2", "b1", "a3"]);
        let b1 = report
            .decisions
            .iter()
            .find(|decision| decision.operation_id == "b1")
            .unwrap();
        assert_eq!(b1.action, BatchScheduleAction::ShortJobPromote);
        let a3 = report
            .decisions
            .iter()
            .find(|decision| decision.operation_id == "a3")
            .unwrap();
        assert_eq!(a3.action, BatchScheduleAction::FairnessInterleave);
    }

    #[test]
    fn batch_scheduler_adaptive_respects_dependency_tiers() {
        let executor = BatchExecutor::new();
        let req = adaptive_request(vec![
            scheduled_op("root", BatchOperationPriority::Low, 1000, None, &[]),
            scheduled_op(
                "dependent_critical",
                BatchOperationPriority::Critical,
                1,
                None,
                &["root"],
            ),
            scheduled_op("sibling", BatchOperationPriority::High, 1, None, &[]),
        ]);
        let (plan, report) = executor.plan_with_schedule_report(&req).unwrap();

        assert_eq!(plan.tiers[0].operation_ids, vec!["sibling", "root"]);
        assert_eq!(plan.tiers[1].operation_ids, vec!["dependent_critical"]);
        assert_eq!(
            report.scheduled_tiers,
            vec![
                vec!["sibling".to_string(), "root".to_string()],
                vec!["dependent_critical".to_string()]
            ]
        );
    }

    #[test]
    fn batch_scheduler_morselization_report_splits_tiers_without_reordering() {
        let executor = BatchExecutor::new();
        let mut req = adaptive_request(
            (0..10)
                .map(|index| {
                    scheduled_op(
                        &format!("op_{index:02}"),
                        BatchOperationPriority::Normal,
                        u64::try_from(index + 1).unwrap(),
                        Some(if index % 2 == 0 {
                            "tenant-even"
                        } else {
                            "tenant-odd"
                        }),
                        &[],
                    )
                })
                .collect(),
        );
        req.options.max_parallelism = 3;

        let (plan, report) = executor.plan_with_schedule_report(&req).unwrap();
        let morselization = report
            .morselization
            .expect("schedule report should include max-parallelism morsels");
        let flattened: Vec<String> = morselization
            .morsels
            .iter()
            .flat_map(|morsel| morsel.operation_ids.iter().cloned())
            .collect();

        assert!(!morselization.fallback);
        assert_eq!(morselization.max_operations_per_morsel, 3);
        assert_eq!(morselization.total_morsels, 4);
        assert_eq!(morselization.split_tiers, 1);
        assert_eq!(morselization.largest_morsel_operations, 3);
        assert_eq!(flattened, plan.tiers[0].operation_ids);
        assert!(
            morselization
                .morsels
                .iter()
                .all(|morsel| morsel.operation_count <= 3)
        );
        assert!(
            morselization
                .morsels
                .iter()
                .all(|morsel| morsel.estimated_duration_ms > 0)
        );
    }

    #[test]
    fn batch_scheduler_morselization_report_respects_dependency_tiers() {
        let executor = BatchExecutor::new();
        let mut req = adaptive_request(vec![
            scheduled_op("root_a", BatchOperationPriority::Normal, 1, None, &[]),
            scheduled_op("root_b", BatchOperationPriority::Normal, 1, None, &[]),
            scheduled_op(
                "dependent",
                BatchOperationPriority::Critical,
                1,
                None,
                &["root_a"],
            ),
        ]);
        req.options.max_parallelism = 1;

        let (plan, report) = executor.plan_with_schedule_report(&req).unwrap();
        let morselization = report
            .morselization
            .expect("schedule report should include max-parallelism morsels");

        assert_eq!(plan.tiers.len(), 2);
        assert_eq!(morselization.total_morsels, 3);
        assert_eq!(morselization.morsels[0].tier_index, 0);
        assert_eq!(morselization.morsels[1].tier_index, 0);
        assert_eq!(morselization.morsels[2].tier_index, 1);
        assert_eq!(
            morselization.morsels[2].operation_ids,
            vec!["dependent".to_string()]
        );
    }

    #[test]
    fn execute_sync_adaptive_response_includes_replay_summary() {
        let executor = BatchExecutor::new();
        let req = adaptive_request(vec![
            scheduled_op("long", BatchOperationPriority::Normal, 1_000, None, &[]),
            scheduled_op("short", BatchOperationPriority::Normal, 1, None, &[]),
        ]);

        let response = executor
            .execute_sync(&req, |operation| {
                Ok(serde_json::json!({ "id": operation.id }))
            })
            .unwrap();
        let report = response
            .schedule_report
            .expect("adaptive execute_sync response should carry replay report");
        let summary = report
            .queueing_summary
            .expect("adaptive replay report should carry queueing summary");

        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.promoted_operations, 1);
        assert_eq!(summary.delayed_operations, 1);
        assert_eq!(summary.max_wait_increase_ms, 1);

        let morselization = report
            .morselization
            .expect("adaptive replay report should carry max-parallelism morsels");
        assert!(morselization.fallback);
        assert_eq!(morselization.total_morsels, 1);
        assert_eq!(
            morselization.morsels[0].operation_ids,
            vec!["short", "long"]
        );
    }

    // ── Execution Tests ──

    #[test]
    fn execute_all_succeed() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool1", &[]), op("b", "tool2", &[])]);
        let resp = executor.execute_sync(&req, |op| Ok(ok_output(op))).unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.completed, 2);
        assert_eq!(resp.failed, 0);
        assert_eq!(resp.skipped, 0);
        assert_eq!(resp.results.len(), 2);
    }

    #[test]
    fn execute_all_fail() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool1", &[]), op("b", "tool2", &[])]);
        let resp = executor.execute_sync(&req, failing_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::AllFailed);
        assert_eq!(resp.completed, 0);
        assert_eq!(resp.failed, 2);
    }

    #[test]
    fn execute_partial_failure() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("ok1", "tool", &[]),
            op("fail1", "tool", &[]),
            op("ok2", "tool", &[]),
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::PartialSuccess);
        assert_eq!(resp.completed, 2);
        assert_eq!(resp.failed, 1);
    }

    #[test]
    fn execute_stop_on_first_error() {
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![
                op("a", "tool", &[]),
                op("fail1", "tool", &["a"]),
                op("c", "tool", &["fail1"]),
            ],
            options: BatchOptions {
                stop_on_first_error: true,
                ..Default::default()
            },
        };
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::Aborted);
        assert_eq!(resp.completed, 1); // "a" succeeded
        assert_eq!(resp.failed, 1); // "fail1" failed
        assert_eq!(resp.skipped, 1); // "c" skipped
    }

    #[test]
    fn execute_dependency_failure_skips_dependents() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("fail1", "tool", &[]),
            op("b", "tool", &["fail1"]),
            op("c", "tool", &["b"]),
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        // fail1 fails, b skipped (dep failed), c skipped (dep failed)
        assert_eq!(resp.failed, 1);
        assert_eq!(resp.skipped, 2);
    }

    #[test]
    fn execute_independent_ops_not_skipped_on_failure() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("fail1", "tool", &[]),
            op("ok1", "tool", &[]), // Independent of fail1
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.completed, 1);
        assert_eq!(resp.failed, 1);
        assert_eq!(resp.skipped, 0);
    }

    #[test]
    fn execute_results_in_submission_order() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("z", "tool", &[]),
            op("a", "tool", &[]),
            op("m", "tool", &[]),
        ]);
        let resp = executor.execute_sync(&req, |op| Ok(ok_output(op))).unwrap();
        let ids: Vec<&str> = resp.results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["z", "a", "m"],
            "results should be in submission order"
        );
    }

    #[test]
    fn execute_diamond_dependency_order() {
        let executor = BatchExecutor::new();
        let call_order = std::sync::Mutex::new(Vec::new());
        let req = simple_request(vec![
            op("a", "tool", &[]),
            op("b", "tool", &["a"]),
            op("c", "tool", &["a"]),
            op("d", "tool", &["b", "c"]),
        ]);
        let resp = executor
            .execute_sync(&req, |op| {
                call_order.lock().unwrap().push(op.id.clone());
                Ok(serde_json::json!({"id": op.id}))
            })
            .unwrap();

        let order = call_order.lock().unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        // "a" must come before "b" and "c"; "d" must come last.
        let a_pos = order.iter().position(|s| s == "a").unwrap();
        let b_pos = order.iter().position(|s| s == "b").unwrap();
        let c_pos = order.iter().position(|s| s == "c").unwrap();
        let d_pos = order.iter().position(|s| s == "d").unwrap();
        drop(order);
        assert!(a_pos < b_pos);
        assert!(a_pos < c_pos);
        assert!(b_pos < d_pos);
        assert!(c_pos < d_pos);
    }

    #[test]
    fn execute_handler_output_is_captured() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool", &[])]);
        let resp = executor
            .execute_sync(&req, |op| {
                Ok(serde_json::json!({"tool": op.tool, "processed": true}))
            })
            .unwrap();
        let output = resp.results[0].output.as_ref().unwrap();
        assert_eq!(output["tool"], "tool");
        assert_eq!(output["processed"], true);
    }

    #[test]
    fn execute_error_details_are_captured() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool", &[])]);
        let resp = executor
            .execute_sync(&req, |_| {
                Err(BatchOperationError {
                    code: "RATE_LIMIT".into(),
                    message: "too many requests".into(),
                    retry_after_ms: Some(5000),
                })
            })
            .unwrap();
        let err = resp.results[0].error.as_ref().unwrap();
        assert_eq!(err.code, "RATE_LIMIT");
        assert_eq!(err.retry_after_ms, Some(5000));
    }

    #[test]
    fn execute_duration_is_tracked() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool", &[])]);
        let resp = executor.execute_sync(&req, |op| Ok(ok_output(op))).unwrap();
        // Duration should be set (may be 0ms for fast ops, but field exists).
        assert!(resp.total_duration_ms < 1000);
        assert!(resp.results[0].duration_ms < 1000);
    }

    // ── Zone Validation Tests ──

    #[test]
    fn zone_same_zone_accessible() {
        assert!(zone_accessible(&ZoneId::work(), &ZoneId::work()));
    }

    #[test]
    fn zone_owner_accesses_everything() {
        assert!(zone_accessible(&ZoneId::owner(), &ZoneId::public()));
        assert!(zone_accessible(&ZoneId::owner(), &ZoneId::work()));
        assert!(zone_accessible(&ZoneId::owner(), &ZoneId::private()));
    }

    #[test]
    fn zone_public_cannot_access_private() {
        assert!(!zone_accessible(&ZoneId::public(), &ZoneId::private()));
    }

    #[test]
    fn zone_work_cannot_access_private() {
        assert!(!zone_accessible(&ZoneId::work(), &ZoneId::private()));
    }

    #[test]
    fn zone_work_accesses_community() {
        assert!(zone_accessible(&ZoneId::work(), &ZoneId::community()));
    }

    #[test]
    fn zone_work_accesses_public() {
        assert!(zone_accessible(&ZoneId::work(), &ZoneId::public()));
    }

    #[test]
    fn zone_project_accesses_community() {
        assert!(zone_accessible(
            &"z:project:myapp".parse::<ZoneId>().unwrap(),
            &ZoneId::community()
        ));
    }

    #[test]
    fn zone_project_accesses_public() {
        assert!(zone_accessible(
            &"z:project:myapp".parse::<ZoneId>().unwrap(),
            &ZoneId::public()
        ));
    }

    #[test]
    fn zone_work_accesses_project() {
        assert!(zone_accessible(
            &ZoneId::work(),
            &"z:project:myapp".parse::<ZoneId>().unwrap()
        ));
    }

    #[test]
    fn zone_community_cannot_access_project() {
        assert!(!zone_accessible(
            &ZoneId::community(),
            &"z:project:myapp".parse::<ZoneId>().unwrap()
        ));
    }

    #[test]
    fn zone_validator_rejects_violation() {
        let mut reg = ZoneRegistry::new();
        reg.register("secret.tool", ZoneId::owner());
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        let ops = vec![op("a", "secret.tool", &[])];
        let err = validator.validate(&ops).unwrap_err();
        assert!(err.to_string().contains("zone boundary violations"));
        assert!(err.to_string().contains('a'));
    }

    #[test]
    fn zone_validator_allows_accessible() {
        let mut reg = ZoneRegistry::new();
        reg.register("pub.tool", ZoneId::public());
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        let ops = vec![op("a", "pub.tool", &[])];
        assert!(validator.validate(&ops).is_ok());
    }

    #[test]
    fn zone_validator_unknown_tool_rejects_missing_mapping() {
        let reg = ZoneRegistry::new();
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        let ops = vec![op("a", "unknown.tool", &[])];
        let err = validator.validate(&ops).unwrap_err();
        assert!(err.to_string().contains("missing zone mapping"));
        assert!(err.to_string().contains('a'));
    }

    #[test]
    fn zone_validator_operation_zone_override_takes_precedence() {
        let mut reg = ZoneRegistry::new();
        reg.register("pub.tool", ZoneId::public());
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        let mut operation = op("a", "pub.tool", &[]);
        operation.zone = Some(ZoneId::owner());
        let err = validator.validate(&[operation]).unwrap_err();
        assert!(err.to_string().contains('a'));
    }

    #[test]
    fn zone_validator_multiple_violations() {
        let mut reg = ZoneRegistry::new();
        reg.register("secret1", ZoneId::owner());
        reg.register("secret2", ZoneId::private());
        let validator = BatchZoneValidator::new(ZoneId::public(), reg);
        let ops = vec![op("a", "secret1", &[]), op("b", "secret2", &[])];
        let err = validator.validate(&ops).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains('a'));
        assert!(msg.contains('b'));
    }

    #[test]
    fn zone_group_by_zone() {
        let mut reg = ZoneRegistry::new();
        reg.register("pub.tool", ZoneId::public());
        reg.register("work.tool", ZoneId::work());
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        let ops = vec![
            op("a", "pub.tool", &[]),
            op("b", "work.tool", &[]),
            op("c", "unknown.tool", &[]),
        ];
        let groups = validator.group_by_zone(&ops);
        assert_eq!(groups.len(), 3);
        assert!(groups.contains_key("<unresolved>"));
        assert!(groups.contains_key("z:public"));
        assert!(groups.contains_key("z:work"));
        assert_eq!(groups["z:work"], vec!["b"]);
        assert_eq!(groups["<unresolved>"], vec!["c"]);
    }

    #[test]
    fn zone_group_by_zone_uses_operation_override() {
        let mut reg = ZoneRegistry::new();
        reg.register("pub.tool", ZoneId::public());
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        let mut operation = op("a", "pub.tool", &[]);
        operation.zone = Some(ZoneId::private());
        let groups = validator.group_by_zone(&[operation]);
        assert_eq!(groups.len(), 1);
        assert!(groups.contains_key("z:private"));
    }

    #[test]
    fn executor_with_zone_validator_rejects_violations() {
        let mut reg = ZoneRegistry::new();
        reg.register("secret", ZoneId::owner());
        let validator = BatchZoneValidator::new(ZoneId::public(), reg);
        let executor = BatchExecutor::with_zone_validator(validator);
        let req = simple_request(vec![op("a", "secret", &[])]);
        let err = executor.validate(&req).unwrap_err();
        assert!(err.to_string().contains("zone boundary"));
    }

    // ── Serialization Tests ──

    #[test]
    fn batch_request_json_roundtrip() {
        let req = simple_request(vec![
            op("a", "fcp.discord.send", &[]),
            op("b", "fcp.github.create", &["a"]),
        ]);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: BatchInvokeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operations.len(), 2);
        assert_eq!(parsed.operations[1].depends_on, vec!["a"]);
    }

    #[test]
    fn batch_response_json_roundtrip() {
        let resp = BatchInvokeResponse {
            status: BatchStatus::PartialSuccess,
            completed: 2,
            failed: 1,
            skipped: 0,
            results: vec![
                OperationResult {
                    id: "a".into(),
                    status: OperationResultStatus::Success,
                    output: Some(serde_json::json!({"ok": true})),
                    error: None,
                    duration_ms: 42,
                },
                OperationResult {
                    id: "b".into(),
                    status: OperationResultStatus::Error,
                    output: None,
                    error: Some(BatchOperationError {
                        code: "ERR".into(),
                        message: "fail".into(),
                        retry_after_ms: Some(1000),
                    }),
                    duration_ms: 10,
                },
            ],
            total_duration_ms: 52,
            schedule_report: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BatchInvokeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, BatchStatus::PartialSuccess);
        assert_eq!(parsed.results.len(), 2);
    }

    #[test]
    fn batch_status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&BatchStatus::PartialSuccess).unwrap(),
            "\"partial_success\""
        );
        assert_eq!(
            serde_json::to_string(&BatchStatus::AllFailed).unwrap(),
            "\"all_failed\""
        );
    }

    #[test]
    fn operation_result_status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&OperationResultStatus::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&OperationResultStatus::Skipped).unwrap(),
            "\"skipped\""
        );
    }

    #[test]
    fn batch_options_defaults() {
        let opts = BatchOptions::default();
        assert_eq!(opts.max_parallelism, 8);
        assert!(!opts.stop_on_first_error);
        assert_eq!(opts.timeout_ms, 30_000);
        assert_eq!(opts.scheduler.mode, BatchSchedulerMode::Fifo);
    }

    #[test]
    fn batch_options_deserialize_with_defaults() {
        let json = r#"{"max_parallelism": 4}"#;
        let opts: BatchOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.max_parallelism, 4);
        assert!(!opts.stop_on_first_error);
        assert_eq!(opts.timeout_ms, 30_000);
        assert_eq!(opts.scheduler.mode, BatchSchedulerMode::Fifo);
    }

    // ── Edge Cases ──

    #[test]
    fn large_batch_no_deps() {
        let executor = BatchExecutor::new();
        let ops: Vec<BatchOperation> = (0..100)
            .map(|i| op(&format!("op{i}"), "tool", &[]))
            .collect();
        let req = simple_request(ops);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 1);
        assert_eq!(plan.max_width(), 100);
    }

    #[test]
    fn large_linear_chain() {
        let executor = BatchExecutor::new();
        let mut ops = vec![op("op0", "tool", &[])];
        for i in 1..50 {
            ops.push(op(&format!("op{i}"), "tool", &[&format!("op{}", i - 1)]));
        }
        let req = simple_request(ops);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 50);
        assert_eq!(plan.max_width(), 1);
    }

    #[test]
    fn operation_with_empty_tool() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "", &[])]);
        // Empty tool name is valid at this layer — tool resolution happens later.
        assert!(executor.validate(&req).is_ok());
    }

    #[test]
    fn operation_with_complex_input() {
        let executor = BatchExecutor::new();
        let mut op = op("a", "tool", &[]);
        op.input = serde_json::json!({
            "nested": {"array": [1, 2, 3], "null": null},
            "bool": true
        });
        let req = simple_request(vec![op]);
        let resp = executor
            .execute_sync(&req, |o| Ok(o.input.clone()))
            .unwrap();
        let output = resp.results[0].output.as_ref().unwrap();
        assert_eq!(output["nested"]["array"][1], 2);
    }

    #[test]
    fn executor_default_trait() {
        let executor = BatchExecutor::default();
        let req = simple_request(vec![op("a", "tool", &[])]);
        assert!(executor.validate(&req).is_ok());
    }

    // ── Cycle Detection Tests ──

    #[test]
    fn no_cycle_in_dag() {
        assert!(!has_cycle(&[
            op("a", "t", &[]),
            op("b", "t", &["a"]),
            op("c", "t", &["a"]),
            op("d", "t", &["b", "c"]),
        ]));
    }

    #[test]
    fn cycle_two_nodes() {
        assert!(has_cycle(&[op("a", "t", &["b"]), op("b", "t", &["a"]),]));
    }

    #[test]
    fn cycle_three_nodes() {
        assert!(has_cycle(&[
            op("a", "t", &["c"]),
            op("b", "t", &["a"]),
            op("c", "t", &["b"]),
        ]));
    }

    #[test]
    fn no_cycle_empty() {
        assert!(!has_cycle(&[]));
    }

    #[test]
    fn no_cycle_single_node() {
        assert!(!has_cycle(&[op("a", "t", &[])]));
    }

    // ── Zone Registry Tests ──

    #[test]
    fn zone_registry_register_and_get() {
        let mut reg = ZoneRegistry::new();
        reg.register("tool1", ZoneId::work());
        assert_eq!(reg.get_zone("tool1").unwrap().as_str(), "z:work");
        assert!(reg.get_zone("unknown").is_none());
    }

    #[test]
    fn zone_registry_overwrite() {
        let mut reg = ZoneRegistry::new();
        reg.register("tool1", ZoneId::work());
        reg.register("tool1", ZoneId::public());
        assert_eq!(reg.get_zone("tool1").unwrap().as_str(), "z:public");
    }

    // ── Execution Plan Properties ──

    #[test]
    fn execution_plan_depth_and_width() {
        let plan = ExecutionPlan {
            tiers: vec![
                ExecutionTier {
                    operation_ids: vec!["a".into(), "b".into()],
                },
                ExecutionTier {
                    operation_ids: vec!["c".into()],
                },
                ExecutionTier {
                    operation_ids: vec!["d".into(), "e".into(), "f".into()],
                },
            ],
            total_operations: 6,
        };
        assert_eq!(plan.depth(), 3);
        assert_eq!(plan.max_width(), 3);
    }

    #[test]
    fn execution_plan_empty() {
        let plan = ExecutionPlan {
            tiers: vec![],
            total_operations: 0,
        };
        assert_eq!(plan.depth(), 0);
        assert_eq!(plan.max_width(), 0);
    }

    // ── Stop-on-first-error with parallel tier ──

    #[test]
    fn stop_on_error_in_parallel_tier() {
        let executor = BatchExecutor::new();
        // Three independent ops, one fails.
        let req = BatchInvokeRequest {
            operations: vec![
                op("ok1", "tool", &[]),
                op("fail1", "tool", &[]),
                op("ok2", "tool", &[]),
            ],
            options: BatchOptions {
                stop_on_first_error: true,
                ..Default::default()
            },
        };
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        // Because all are in the same tier, at least some execute before abort.
        assert_eq!(resp.status, BatchStatus::Aborted);
        assert!(resp.failed >= 1);
    }

    // ── Response status edge cases ──

    #[test]
    fn all_skipped_counts_as_all_failed() {
        let executor = BatchExecutor::new();
        // fail1 fails, b depends on fail1 → skipped.
        let req = simple_request(vec![op("fail1", "tool", &[]), op("b", "tool", &["fail1"])]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        // 1 failed, 1 skipped, 0 completed → AllFailed.
        assert_eq!(resp.completed, 0);
    }

    // ── BatchOperation extended tests ──

    #[test]
    fn batch_operation_with_zone_field_set() {
        let mut operation = op("a", "fcp.discord.send", &[]);
        operation.zone = Some(ZoneId::work());
        assert_eq!(operation.zone.as_ref().map(ZoneId::as_str), Some("z:work"));
        assert_eq!(operation.id, "a");
    }

    #[test]
    fn batch_operation_json_serialization_with_depends_on() {
        let operation = op("b", "fcp.github.create", &["a", "c"]);
        let json = serde_json::to_value(&operation).unwrap();
        assert_eq!(json["id"], "b");
        assert_eq!(json["tool"], "fcp.github.create");
        assert_eq!(json["depends_on"], serde_json::json!(["a", "c"]));
    }

    #[test]
    fn batch_operation_zone_omitted_when_none_in_json() {
        let operation = op("a", "tool", &[]);
        let json = serde_json::to_string(&operation).unwrap();
        assert!(!json.contains("zone"), "zone should be skipped when None");
    }

    #[test]
    fn batch_operation_empty_id_passes_serialization() {
        let operation = op("", "tool", &[]);
        let json = serde_json::to_string(&operation).unwrap();
        let parsed: BatchOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "");
    }

    // ── BatchOptions extended tests ──

    #[test]
    fn batch_options_custom_timeout() {
        let opts = BatchOptions {
            max_parallelism: 4,
            stop_on_first_error: true,
            timeout_ms: 5000,
            ..Default::default()
        };
        assert_eq!(opts.max_parallelism, 4);
        assert!(opts.stop_on_first_error);
        assert_eq!(opts.timeout_ms, 5000);
    }

    #[test]
    fn batch_options_max_parallelism_one() {
        let opts = BatchOptions {
            max_parallelism: 1,
            ..Default::default()
        };
        assert_eq!(opts.max_parallelism, 1);
    }

    #[test]
    fn batch_options_all_fields_set() {
        let opts = BatchOptions {
            max_parallelism: 16,
            stop_on_first_error: true,
            timeout_ms: 120_000,
            ..Default::default()
        };
        assert_eq!(opts.max_parallelism, 16);
        assert!(opts.stop_on_first_error);
        assert_eq!(opts.timeout_ms, 120_000);
    }

    #[test]
    fn batch_options_json_roundtrip() {
        let opts = BatchOptions {
            max_parallelism: 4,
            stop_on_first_error: true,
            timeout_ms: 5000,
            ..Default::default()
        };
        let json = serde_json::to_string(&opts).unwrap();
        let parsed: BatchOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_parallelism, 4);
        assert!(parsed.stop_on_first_error);
        assert_eq!(parsed.timeout_ms, 5000);
    }

    // ── BatchOperationError extended tests ──

    #[test]
    fn batch_operation_error_without_retry_after() {
        let err = BatchOperationError {
            code: "NOT_FOUND".into(),
            message: "resource not found".into(),
            retry_after_ms: None,
        };
        assert_eq!(err.code, "NOT_FOUND");
        assert!(err.retry_after_ms.is_none());
    }

    #[test]
    fn batch_operation_error_with_retry_after() {
        let err = BatchOperationError {
            code: "RATE_LIMIT".into(),
            message: "slow down".into(),
            retry_after_ms: Some(3000),
        };
        assert_eq!(err.retry_after_ms, Some(3000));
    }

    #[test]
    fn batch_operation_error_json_roundtrip() {
        let err = BatchOperationError {
            code: "INTERNAL".into(),
            message: "something broke".into(),
            retry_after_ms: Some(10_000),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: BatchOperationError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "INTERNAL");
        assert_eq!(parsed.message, "something broke");
        assert_eq!(parsed.retry_after_ms, Some(10_000));
    }

    #[test]
    fn batch_operation_error_retry_after_omitted_when_none() {
        let err = BatchOperationError {
            code: "ERR".into(),
            message: "msg".into(),
            retry_after_ms: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(
            !json.contains("retry_after_ms"),
            "retry_after_ms should be skipped when None"
        );
    }

    // ── OperationResult extended tests ──

    #[test]
    fn operation_result_success_with_output() {
        let result = OperationResult {
            id: "op1".into(),
            status: OperationResultStatus::Success,
            output: Some(serde_json::json!({"key": "value"})),
            error: None,
            duration_ms: 15,
        };
        assert_eq!(result.status, OperationResultStatus::Success);
        assert!(result.output.is_some());
        assert!(result.error.is_none());
        assert_eq!(result.output.unwrap()["key"], "value");
    }

    #[test]
    fn operation_result_error_with_details() {
        let result = OperationResult {
            id: "op2".into(),
            status: OperationResultStatus::Error,
            output: None,
            error: Some(BatchOperationError {
                code: "TIMEOUT".into(),
                message: "request timed out".into(),
                retry_after_ms: Some(2000),
            }),
            duration_ms: 30_000,
        };
        assert_eq!(result.status, OperationResultStatus::Error);
        assert!(result.output.is_none());
        let err = result.error.unwrap();
        assert_eq!(err.code, "TIMEOUT");
        assert_eq!(err.retry_after_ms, Some(2000));
    }

    #[test]
    fn operation_result_skipped_with_error() {
        let result = OperationResult {
            id: "op3".into(),
            status: OperationResultStatus::Skipped,
            output: None,
            error: Some(BatchOperationError {
                code: "DEP_FAILED".into(),
                message: "dependency failed".into(),
                retry_after_ms: None,
            }),
            duration_ms: 0,
        };
        assert_eq!(result.status, OperationResultStatus::Skipped);
        assert_eq!(result.error.as_ref().unwrap().code, "DEP_FAILED");
    }

    #[test]
    fn operation_result_json_roundtrip_success() {
        let result = OperationResult {
            id: "r1".into(),
            status: OperationResultStatus::Success,
            output: Some(serde_json::json!({"key": "value"})),
            error: None,
            duration_ms: 42,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: OperationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "r1");
        assert_eq!(parsed.status, OperationResultStatus::Success);
        assert_eq!(parsed.duration_ms, 42);
        assert_eq!(parsed.output.unwrap()["key"], "value");
    }

    // ── ExecutionPlan extended tests ──

    #[test]
    fn execution_plan_single_wide_tier() {
        let plan = ExecutionPlan {
            tiers: vec![ExecutionTier {
                operation_ids: vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
            }],
            total_operations: 5,
        };
        assert_eq!(plan.depth(), 1);
        assert_eq!(plan.max_width(), 5);
    }

    #[test]
    fn execution_plan_single_narrow_tier() {
        let plan = ExecutionPlan {
            tiers: vec![ExecutionTier {
                operation_ids: vec!["only".into()],
            }],
            total_operations: 1,
        };
        assert_eq!(plan.depth(), 1);
        assert_eq!(plan.max_width(), 1);
    }

    #[test]
    fn execution_plan_many_tiers_varying_widths() {
        let plan = ExecutionPlan {
            tiers: vec![
                ExecutionTier {
                    operation_ids: vec!["a".into()],
                },
                ExecutionTier {
                    operation_ids: vec!["b".into(), "c".into(), "d".into(), "e".into()],
                },
                ExecutionTier {
                    operation_ids: vec!["f".into(), "g".into()],
                },
                ExecutionTier {
                    operation_ids: vec!["h".into()],
                },
            ],
            total_operations: 8,
        };
        assert_eq!(plan.depth(), 4);
        assert_eq!(plan.max_width(), 4);
    }

    // ── Topological sorting: complex DAGs ──

    #[test]
    fn topo_complex_dag_ten_nodes() {
        // Build a 10-node DAG:
        //   r1, r2 (roots) → a, b → c, d → e → f → g → sink
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("r1", "t", &[]),
            op("r2", "t", &[]),
            op("a", "t", &["r1"]),
            op("b", "t", &["r2"]),
            op("c", "t", &["a", "b"]),
            op("d", "t", &["a"]),
            op("e", "t", &["c", "d"]),
            op("f", "t", &["e"]),
            op("g", "t", &["f"]),
            op("sink", "t", &["g"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.total_operations, 10);
        // Verify ordering: r1/r2 first, sink last
        let first_tier: &[String] = &plan.tiers[0].operation_ids;
        assert!(first_tier.contains(&"r1".to_string()));
        assert!(first_tier.contains(&"r2".to_string()));
        let last_tier = &plan.tiers.last().unwrap().operation_ids;
        assert!(last_tier.contains(&"sink".to_string()));
    }

    #[test]
    fn topo_multiple_roots() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("r1", "t", &[]),
            op("r2", "t", &[]),
            op("r3", "t", &[]),
            op("r4", "t", &[]),
            op("join", "t", &["r1", "r2", "r3", "r4"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 2);
        assert_eq!(plan.tiers[0].operation_ids.len(), 4);
        assert_eq!(plan.tiers[1].operation_ids, vec!["join"]);
    }

    #[test]
    fn topo_deep_chain_twenty_nodes() {
        let executor = BatchExecutor::new();
        let mut ops = vec![op("n0", "t", &[])];
        for i in 1..20 {
            ops.push(op(&format!("n{i}"), "t", &[&format!("n{}", i - 1)]));
        }
        let req = simple_request(ops);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 20);
        assert_eq!(plan.max_width(), 1);
        assert_eq!(plan.tiers[0].operation_ids[0], "n0");
        assert_eq!(plan.tiers[19].operation_ids[0], "n19");
    }

    #[test]
    fn topo_forest_disconnected_components() {
        // Three independent chains form a forest
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a1", "t", &[]),
            op("a2", "t", &["a1"]),
            op("b1", "t", &[]),
            op("b2", "t", &["b1"]),
            op("c1", "t", &[]),
            op("c2", "t", &["c1"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 2);
        assert_eq!(plan.tiers[0].operation_ids.len(), 3);
        assert_eq!(plan.tiers[1].operation_ids.len(), 3);
    }

    #[test]
    fn topo_wide_middle_tier() {
        // root → a,b,c,d,e → sink
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("root", "t", &[]),
            op("a", "t", &["root"]),
            op("b", "t", &["root"]),
            op("c", "t", &["root"]),
            op("d", "t", &["root"]),
            op("e", "t", &["root"]),
            op("sink", "t", &["a", "b", "c", "d", "e"]),
        ]);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 3);
        assert_eq!(plan.max_width(), 5);
        assert_eq!(plan.tiers[1].operation_ids, vec!["a", "b", "c", "d", "e"]);
    }

    // ── Cycle detection extended ──

    #[test]
    fn cycle_self_loop_detected() {
        // Self-loop should be caught by validate before has_cycle
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("x", "t", &["x"])]);
        assert!(executor.validate(&req).is_err());
    }

    #[test]
    fn cycle_long_chain_five_nodes() {
        // a→b→c→d→e→a
        assert!(has_cycle(&[
            op("a", "t", &["e"]),
            op("b", "t", &["a"]),
            op("c", "t", &["b"]),
            op("d", "t", &["c"]),
            op("e", "t", &["d"]),
        ]));
    }

    #[test]
    fn cycle_long_chain_seven_nodes() {
        assert!(has_cycle(&[
            op("n0", "t", &["n6"]),
            op("n1", "t", &["n0"]),
            op("n2", "t", &["n1"]),
            op("n3", "t", &["n2"]),
            op("n4", "t", &["n3"]),
            op("n5", "t", &["n4"]),
            op("n6", "t", &["n5"]),
        ]));
    }

    #[test]
    fn cycle_diamond_with_back_edge() {
        // Diamond a→b,c→d, plus back-edge d→a
        assert!(has_cycle(&[
            op("a", "t", &["d"]),
            op("b", "t", &["a"]),
            op("c", "t", &["a"]),
            op("d", "t", &["b", "c"]),
        ]));
    }

    #[test]
    fn no_cycle_complex_dag_with_shared_deps() {
        // Multiple convergence points but no back-edges
        assert!(!has_cycle(&[
            op("a", "t", &[]),
            op("b", "t", &[]),
            op("c", "t", &["a", "b"]),
            op("d", "t", &["a"]),
            op("e", "t", &["c", "d"]),
            op("f", "t", &["d", "b"]),
            op("g", "t", &["e", "f"]),
        ]));
    }

    // ── Topological sorting: edge cases ──

    #[test]
    fn topological_tiers_single_node() {
        let tiers = topological_tiers(&[op("a", "t", &[])]).unwrap();
        assert_eq!(tiers.len(), 1);
        assert_eq!(tiers[0].operation_ids, vec!["a"]);
    }

    #[test]
    fn topological_tiers_sorted_within_tier() {
        let tiers =
            topological_tiers(&[op("z", "t", &[]), op("a", "t", &[]), op("m", "t", &[])]).unwrap();
        assert_eq!(tiers[0].operation_ids, vec!["a", "m", "z"]);
    }

    #[test]
    fn topological_tiers_cycle_returns_error() {
        let result = topological_tiers(&[op("a", "t", &["b"]), op("b", "t", &["a"])]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    // ── Execution extended tests ──

    #[test]
    fn execute_single_op_failure() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "tool", &[])]);
        let resp = executor.execute_sync(&req, failing_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::AllFailed);
        assert_eq!(resp.completed, 0);
        assert_eq!(resp.failed, 1);
        assert_eq!(resp.skipped, 0);
    }

    #[test]
    fn execute_all_ops_same_tool() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "fcp.slack.send", &[]),
            op("b", "fcp.slack.send", &[]),
            op("c", "fcp.slack.send", &[]),
            op("d", "fcp.slack.send", &[]),
        ]);
        let resp = executor
            .execute_sync(&req, |o| Ok(serde_json::json!({"sent_by": o.id})))
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.completed, 4);
        for result in &resp.results {
            let output = result.output.as_ref().unwrap();
            assert_eq!(output["sent_by"], result.id);
        }
    }

    #[test]
    fn execute_handler_returns_different_outputs_per_op() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("fetch", "fcp.http.get", &[]),
            op("transform", "fcp.transform", &["fetch"]),
            op("store", "fcp.db.insert", &["transform"]),
        ]);
        let counter = std::sync::Mutex::new(0u32);
        let resp = executor
            .execute_sync(&req, |o| {
                let mut c = counter.lock().unwrap();
                *c += 1;
                let step = *c;
                drop(c);
                Ok(serde_json::json!({
                    "operation": o.id,
                    "step": step,
                    "tool": o.tool
                }))
            })
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.results[0].output.as_ref().unwrap()["step"], 1);
        assert_eq!(resp.results[1].output.as_ref().unwrap()["step"], 2);
        assert_eq!(resp.results[2].output.as_ref().unwrap()["step"], 3);
    }

    #[test]
    fn execute_results_preserve_order_with_complex_deps() {
        // Submission order: e, d, c, b, a — but execution order is a, b/c, d, e
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("e", "t", &["d"]),
            op("d", "t", &["b", "c"]),
            op("c", "t", &["a"]),
            op("b", "t", &["a"]),
            op("a", "t", &[]),
        ]);
        let resp = executor
            .execute_sync(&req, |o| Ok(serde_json::json!({"id": o.id})))
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.results.len(), 5);
        let ids: Vec<&str> = resp.results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["e", "d", "c", "b", "a"]);
    }

    #[test]
    fn execute_large_batch_fifty_independent_ops() {
        let executor = BatchExecutor::new();
        let ops: Vec<BatchOperation> = (0..50)
            .map(|i| op(&format!("op{i:03}"), "tool", &[]))
            .collect();
        let req = simple_request(ops);
        let resp = executor
            .execute_sync(&req, |o| Ok(serde_json::json!({"id": o.id})))
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.completed, 50);
        assert_eq!(resp.failed, 0);
        assert_eq!(resp.results.len(), 50);
    }

    // ── Stop-on-first-error extended ──

    #[test]
    fn stop_on_first_error_first_tier_failure_skips_second() {
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![
                op("fail1", "t", &[]),
                op("ok1", "t", &["fail1"]),
                op("ok2", "t", &["ok1"]),
            ],
            options: BatchOptions {
                stop_on_first_error: true,
                ..Default::default()
            },
        };
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::Aborted);
        assert_eq!(resp.failed, 1);
        // ok1 and ok2 should be skipped (ok1 dep failed, ok2 in later aborted tier)
        assert_eq!(resp.skipped, 2);
    }

    #[test]
    fn stop_on_error_failure_in_middle_of_tier() {
        // Tier 0: a_ok (sorts first), fail1 (sorts second), z_ok (sorts third)
        // Tier 1: dep (depends on a_ok)
        // a_ok succeeds, then fail1 triggers abort; z_ok and dep should be skipped
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![
                op("a_ok", "t", &[]),
                op("fail1", "t", &[]),
                op("z_ok", "t", &[]),
                op("z_dep", "t", &["a_ok"]),
            ],
            options: BatchOptions {
                stop_on_first_error: true,
                ..Default::default()
            },
        };
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::Aborted);
        // a_ok runs first (sorts before fail1) and succeeds
        let a_ok = resp.results.iter().find(|r| r.id == "a_ok").unwrap();
        assert_eq!(a_ok.status, OperationResultStatus::Success);
        // fail1 runs second and triggers abort
        let fail1 = resp.results.iter().find(|r| r.id == "fail1").unwrap();
        assert_eq!(fail1.status, OperationResultStatus::Error);
        // z_ok should be skipped (same tier, aborted after fail1)
        let z_ok = resp.results.iter().find(|r| r.id == "z_ok").unwrap();
        assert_eq!(z_ok.status, OperationResultStatus::Skipped);
        // z_dep should be skipped (tier 1, aborted)
        let z_dep = resp.results.iter().find(|r| r.id == "z_dep").unwrap();
        assert_eq!(z_dep.status, OperationResultStatus::Skipped);
    }

    #[test]
    fn stop_on_error_multiple_failures_in_same_tier() {
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![
                op("fail1", "t", &[]),
                op("fail2", "t", &[]),
                op("ok1", "t", &[]),
                op("next", "t", &["ok1"]),
            ],
            options: BatchOptions {
                stop_on_first_error: true,
                ..Default::default()
            },
        };
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.status, BatchStatus::Aborted);
        // At least 1 failure; once first failure triggers abort, remaining ops
        // in the tier may be skipped depending on execution order within the tier.
        assert!(resp.failed >= 1);
        // next should be skipped (in tier 2, aborted)
        let next = resp.results.iter().find(|r| r.id == "next").unwrap();
        assert_eq!(next.status, OperationResultStatus::Skipped);
    }

    // ── Dependency failure propagation ──

    #[test]
    fn dep_failure_chain_a_fails_b_c_skipped() {
        // a → b → c, a fails
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("fail_a", "t", &[]),
            op("b", "t", &["fail_a"]),
            op("c", "t", &["b"]),
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.failed, 1);
        assert_eq!(resp.skipped, 2);
        let b_result = resp.results.iter().find(|r| r.id == "b").unwrap();
        assert_eq!(b_result.status, OperationResultStatus::Skipped);
        assert_eq!(b_result.error.as_ref().unwrap().code, "DEP_FAILED");
        let c_result = resp.results.iter().find(|r| r.id == "c").unwrap();
        assert_eq!(c_result.status, OperationResultStatus::Skipped);
    }

    #[test]
    fn dep_failure_diamond_a_fails_all_skipped() {
        // a(fail) → b, c → d
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("fail_a", "t", &[]),
            op("b", "t", &["fail_a"]),
            op("c", "t", &["fail_a"]),
            op("d", "t", &["b", "c"]),
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.failed, 1); // only fail_a
        assert_eq!(resp.skipped, 3); // b, c, d all skipped
        for id in &["b", "c", "d"] {
            let r = resp.results.iter().find(|r| r.id == *id).unwrap();
            assert_eq!(r.status, OperationResultStatus::Skipped);
        }
    }

    #[test]
    fn dep_failure_partial_diamond_one_branch_succeeds() {
        // root_ok(success), root_fail(fail) → mid depends on both → sink depends on mid
        // mid is skipped because one dep failed
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("ok_root", "t", &[]),
            op("fail_root", "t", &[]),
            op("mid", "t", &["ok_root", "fail_root"]),
            op("sink", "t", &["mid"]),
        ]);
        let resp = executor.execute_sync(&req, selective_handler).unwrap();
        assert_eq!(resp.completed, 1); // ok_root
        assert_eq!(resp.failed, 1); // fail_root
        assert_eq!(resp.skipped, 2); // mid, sink
    }

    // ── Edge cases extended ──

    #[test]
    fn execute_with_max_parallelism_one_sequential() {
        let executor = BatchExecutor::new();
        let call_order = std::sync::Mutex::new(Vec::new());
        let req = BatchInvokeRequest {
            operations: vec![op("a", "t", &[]), op("b", "t", &[]), op("c", "t", &[])],
            options: BatchOptions {
                max_parallelism: 1,
                ..Default::default()
            },
        };
        let resp = executor
            .execute_sync(&req, |o| {
                call_order.lock().unwrap().push(o.id.clone());
                Ok(serde_json::json!({"ok": true}))
            })
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.completed, 3);
        // All three are independent, so they should all be in one tier
        // (max_parallelism doesn't affect tier planning, only async dispatch)
        let order = call_order.lock().unwrap();
        let len = order.len();
        drop(order);
        assert_eq!(len, 3);
    }

    #[test]
    fn very_long_dependency_chain_hundred_ops() {
        let executor = BatchExecutor::new();
        let mut ops = vec![op("n000", "t", &[])];
        for i in 1..100 {
            ops.push(op(&format!("n{i:03}"), "t", &[&format!("n{:03}", i - 1)]));
        }
        let req = simple_request(ops);
        let plan = executor.plan(&req).unwrap();
        assert_eq!(plan.depth(), 100);
        assert_eq!(plan.max_width(), 1);
        assert_eq!(plan.total_operations, 100);
        // Execute and verify all succeed
        let resp = executor
            .execute_sync(&req, |o| Ok(serde_json::json!({"id": o.id})))
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.completed, 100);
    }

    #[test]
    fn operations_with_complex_json_inputs() {
        let executor = BatchExecutor::new();
        let mut op1 = op("a", "tool", &[]);
        op1.input = serde_json::json!({
            "deeply": {
                "nested": {
                    "structure": {
                        "array": [1, "two", null, true, {"inner": "obj"}],
                        "key": "value"
                    }
                }
            },
            "tags": ["alpha", "beta", "gamma"],
            "count": 42,
            "active": false,
            "metadata": null
        });
        let mut op2 = op("b", "tool", &["a"]);
        op2.input = serde_json::json!([
            {"id": 1, "items": [10, 20, 30]},
            {"id": 2, "items": []},
            {"id": 3, "items": [40]}
        ]);
        let req = simple_request(vec![op1, op2]);
        let resp = executor
            .execute_sync(&req, |o| Ok(o.input.clone()))
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        let output_a = resp.results[0].output.as_ref().unwrap();
        assert_eq!(
            output_a["deeply"]["nested"]["structure"]["array"][4]["inner"],
            "obj"
        );
        let output_b = resp.results[1].output.as_ref().unwrap();
        assert_eq!(output_b[0]["items"][2], 30);
        assert_eq!(output_b[1]["items"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn batch_invoke_response_json_roundtrip_full() {
        let resp = BatchInvokeResponse {
            status: BatchStatus::Aborted,
            completed: 3,
            failed: 2,
            skipped: 5,
            results: vec![OperationResult {
                id: "x".into(),
                status: OperationResultStatus::Skipped,
                output: None,
                error: Some(BatchOperationError {
                    code: "BATCH_TIMEOUT".into(),
                    message: "batch timeout exceeded".into(),
                    retry_after_ms: None,
                }),
                duration_ms: 0,
            }],
            total_duration_ms: 30_000,
            schedule_report: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BatchInvokeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, BatchStatus::Aborted);
        assert_eq!(parsed.completed, 3);
        assert_eq!(parsed.failed, 2);
        assert_eq!(parsed.skipped, 5);
        assert_eq!(
            parsed.results[0].error.as_ref().unwrap().code,
            "BATCH_TIMEOUT"
        );
    }

    #[test]
    fn zone_registry_many_tools() {
        let mut reg = ZoneRegistry::new();
        for i in 0..50 {
            reg.register(&format!("tool.{i}"), ZoneId::public());
        }
        assert_eq!(reg.get_zone("tool.0").unwrap().as_str(), "z:public");
        assert_eq!(reg.get_zone("tool.49").unwrap().as_str(), "z:public");
        assert!(reg.get_zone("tool.50").is_none());
    }

    #[test]
    fn execute_handler_receives_correct_tool_name() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![
            op("a", "fcp.discord.send_message", &[]),
            op("b", "fcp.github.create_issue", &["a"]),
        ]);
        let tools_seen = std::sync::Mutex::new(Vec::new());
        let resp = executor
            .execute_sync(&req, |o| {
                tools_seen.lock().unwrap().push(o.tool.clone());
                Ok(serde_json::json!({}))
            })
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        let seen = tools_seen.lock().unwrap();
        let first = seen[0].clone();
        let second = seen[1].clone();
        drop(seen);
        assert_eq!(first, "fcp.discord.send_message");
        assert_eq!(second, "fcp.github.create_issue");
    }

    #[test]
    fn skipped_result_helper_without_error() {
        let result = skipped_result("test_id".to_string(), None);
        assert_eq!(result.id, "test_id");
        assert_eq!(result.status, OperationResultStatus::Skipped);
        assert!(result.output.is_none());
        assert!(result.error.is_none());
        assert_eq!(result.duration_ms, 0);
    }

    #[test]
    fn skipped_result_helper_with_error() {
        let err = dependency_failed_error();
        let result = skipped_result("dep_skip".to_string(), Some(err));
        assert_eq!(result.status, OperationResultStatus::Skipped);
        assert_eq!(result.error.as_ref().unwrap().code, "DEP_FAILED");
    }

    #[test]
    fn skipped_result_helper_with_dep_error() {
        let err = dependency_failed_error();
        let result = skipped_result("chained".to_string(), Some(err));
        assert_eq!(result.status, OperationResultStatus::Skipped);
        assert_eq!(result.error.as_ref().unwrap().code, "DEP_FAILED");
        assert_eq!(result.error.as_ref().unwrap().message, "dependency failed");
    }

    // ── New tests: batch_status edge cases ──

    #[test]
    fn batch_status_aborted_no_failures_is_success() {
        // aborted=true but failed=0 should produce Success (no failed ops)
        let status = batch_status(true, 5, 0);
        assert_eq!(status, BatchStatus::Success);
    }

    #[test]
    fn batch_status_not_aborted_all_failed() {
        let status = batch_status(false, 0, 3);
        assert_eq!(status, BatchStatus::AllFailed);
    }

    #[test]
    fn batch_status_not_aborted_partial() {
        let status = batch_status(false, 2, 1);
        assert_eq!(status, BatchStatus::PartialSuccess);
    }

    #[test]
    fn batch_status_not_aborted_all_succeeded() {
        let status = batch_status(false, 5, 0);
        assert_eq!(status, BatchStatus::Success);
    }

    #[test]
    fn batch_status_aborted_with_failures() {
        let status = batch_status(true, 0, 3);
        assert_eq!(status, BatchStatus::Aborted);
    }

    #[test]
    fn batch_status_aborted_mixed_completed_and_failed() {
        let status = batch_status(true, 2, 1);
        assert_eq!(status, BatchStatus::Aborted);
    }

    #[test]
    fn batch_status_zero_completed_zero_failed() {
        // No completed, no failed (e.g., all skipped) => Success because failed==0
        let status = batch_status(false, 0, 0);
        assert_eq!(status, BatchStatus::Success);
    }

    // ── New tests: batch_timeout_error helper ──

    #[test]
    fn batch_timeout_error_fields() {
        let err = batch_timeout_error();
        assert_eq!(err.code, "BATCH_TIMEOUT");
        assert_eq!(err.message, "batch timeout exceeded");
        assert!(err.retry_after_ms.is_none());
    }

    // ── New tests: dependency_failed_error helper ──

    #[test]
    fn dependency_failed_error_fields() {
        let err = dependency_failed_error();
        assert_eq!(err.code, "DEP_FAILED");
        assert_eq!(err.message, "dependency failed");
        assert!(err.retry_after_ms.is_none());
    }

    // ── New tests: serde deserialization from JSON strings ──

    #[test]
    fn batch_status_deserialize_all_variants() {
        let success: BatchStatus = serde_json::from_str("\"success\"").unwrap();
        assert_eq!(success, BatchStatus::Success);
        let partial: BatchStatus = serde_json::from_str("\"partial_success\"").unwrap();
        assert_eq!(partial, BatchStatus::PartialSuccess);
        let all_failed: BatchStatus = serde_json::from_str("\"all_failed\"").unwrap();
        assert_eq!(all_failed, BatchStatus::AllFailed);
        let aborted: BatchStatus = serde_json::from_str("\"aborted\"").unwrap();
        assert_eq!(aborted, BatchStatus::Aborted);
    }

    #[test]
    fn operation_result_status_deserialize_all_variants() {
        let success: OperationResultStatus = serde_json::from_str("\"success\"").unwrap();
        assert_eq!(success, OperationResultStatus::Success);
        let error: OperationResultStatus = serde_json::from_str("\"error\"").unwrap();
        assert_eq!(error, OperationResultStatus::Error);
        let skipped: OperationResultStatus = serde_json::from_str("\"skipped\"").unwrap();
        assert_eq!(skipped, OperationResultStatus::Skipped);
    }

    #[test]
    fn batch_status_invalid_variant_rejected() {
        let result = serde_json::from_str::<BatchStatus>("\"unknown_status\"");
        assert!(result.is_err());
    }

    #[test]
    fn operation_result_status_invalid_variant_rejected() {
        let result = serde_json::from_str::<OperationResultStatus>("\"pending\"");
        assert!(result.is_err());
    }

    // ── New tests: BatchOptions serde edge cases ──

    #[test]
    fn batch_options_deserialize_empty_object_uses_all_defaults() {
        let opts: BatchOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(opts.max_parallelism, 8);
        assert!(!opts.stop_on_first_error);
        assert_eq!(opts.timeout_ms, 30_000);
    }

    #[test]
    fn batch_options_deserialize_only_stop_on_first_error() {
        let json = r#"{"stop_on_first_error": true}"#;
        let opts: BatchOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.max_parallelism, 8);
        assert!(opts.stop_on_first_error);
        assert_eq!(opts.timeout_ms, 30_000);
    }

    #[test]
    fn batch_options_deserialize_only_timeout() {
        let json = r#"{"timeout_ms": 60000}"#;
        let opts: BatchOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.max_parallelism, 8);
        assert!(!opts.stop_on_first_error);
        assert_eq!(opts.timeout_ms, 60_000);
    }

    #[test]
    fn batch_options_large_parallelism_value() {
        let opts = BatchOptions {
            max_parallelism: u32::MAX,
            ..Default::default()
        };
        let json = serde_json::to_string(&opts).unwrap();
        let parsed: BatchOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_parallelism, u32::MAX);
    }

    // ── New tests: BatchOperation serde edge cases ──

    #[test]
    fn batch_operation_deserialize_without_depends_on_defaults_empty() {
        let json = r#"{"id":"x","tool":"t","input":{}}"#;
        let op: BatchOperation = serde_json::from_str(json).unwrap();
        assert!(op.depends_on.is_empty());
        assert!(op.zone.is_none());
    }

    #[test]
    fn batch_operation_with_zone_serializes_zone() {
        let mut operation = op("a", "tool", &[]);
        operation.zone = Some(ZoneId::private());
        let json = serde_json::to_string(&operation).unwrap();
        assert!(json.contains("\"zone\":\"z:private\""));
    }

    #[test]
    fn batch_operation_clone_preserves_all_fields() {
        let mut original = op("a", "fcp.tool", &["b", "c"]);
        original.zone = Some(ZoneId::work());
        original.input = serde_json::json!({"key": "val"});
        let cloned = original.clone();
        assert_eq!(cloned.id, original.id);
        assert_eq!(cloned.tool, original.tool);
        assert_eq!(cloned.depends_on, original.depends_on);
        assert_eq!(cloned.zone, original.zone);
        assert_eq!(cloned.input, original.input);
    }

    #[test]
    fn batch_operation_invalid_zone_rejected_on_deserialize() {
        let json = r#"{"id":"x","tool":"t","input":{},"zone":"zone-work"}"#;
        let err = serde_json::from_str::<BatchOperation>(json).unwrap_err();
        assert!(err.to_string().contains("zone id"));
    }

    // ── New tests: zone_accessible exhaustive pairs ──

    #[test]
    fn zone_public_to_public_accessible() {
        assert!(zone_accessible(&ZoneId::public(), &ZoneId::public()));
    }

    #[test]
    fn zone_community_to_community_accessible() {
        assert!(zone_accessible(&ZoneId::community(), &ZoneId::community()));
    }

    #[test]
    fn zone_owner_to_owner_accessible() {
        assert!(zone_accessible(&ZoneId::owner(), &ZoneId::owner()));
    }

    #[test]
    fn zone_private_to_private_accessible() {
        assert!(zone_accessible(&ZoneId::private(), &ZoneId::private()));
    }

    #[test]
    fn zone_community_accesses_public() {
        assert!(zone_accessible(&ZoneId::community(), &ZoneId::public()));
    }

    #[test]
    fn zone_public_cannot_access_owner() {
        assert!(!zone_accessible(&ZoneId::public(), &ZoneId::owner()));
    }

    #[test]
    fn zone_public_cannot_access_work() {
        assert!(!zone_accessible(&ZoneId::public(), &ZoneId::work()));
    }

    #[test]
    fn zone_community_cannot_access_private() {
        assert!(!zone_accessible(&ZoneId::community(), &ZoneId::private()));
    }

    #[test]
    fn zone_community_cannot_access_owner() {
        assert!(!zone_accessible(&ZoneId::community(), &ZoneId::owner()));
    }

    #[test]
    fn zone_owner_accesses_community() {
        assert!(zone_accessible(&ZoneId::owner(), &ZoneId::community()));
    }

    #[test]
    fn zone_project_same_project_accessible() {
        let proj = "z:project:alpha".parse::<ZoneId>().unwrap();
        assert!(zone_accessible(&proj, &proj));
    }

    #[test]
    fn zone_public_cannot_access_project() {
        let proj = "z:project:test".parse::<ZoneId>().unwrap();
        assert!(!zone_accessible(&ZoneId::public(), &proj));
    }

    // ── New tests: ZoneRegistry edge cases ──

    #[test]
    fn zone_registry_default_is_empty() {
        let reg = ZoneRegistry::default();
        assert!(reg.get_zone("anything").is_none());
    }

    #[test]
    fn zone_registry_empty_tool_name() {
        let mut reg = ZoneRegistry::new();
        reg.register("", ZoneId::public());
        assert_eq!(reg.get_zone("").unwrap().as_str(), "z:public");
    }

    #[test]
    fn zone_registry_clone() {
        let mut reg = ZoneRegistry::new();
        reg.register("t", ZoneId::work());
        let cloned = reg.clone();
        assert_eq!(cloned.get_zone("t").unwrap().as_str(), "z:work");
    }

    // ── New tests: group_by_zone edge cases ──

    #[test]
    fn zone_group_by_zone_empty_operations() {
        let reg = ZoneRegistry::new();
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        let groups = validator.group_by_zone(&[]);
        assert!(groups.is_empty());
    }

    #[test]
    fn zone_group_by_zone_all_unknown_tools_stay_unresolved() {
        let reg = ZoneRegistry::new();
        let validator = BatchZoneValidator::new(ZoneId::private(), reg);
        let ops = vec![op("a", "x", &[]), op("b", "y", &[])];
        let groups = validator.group_by_zone(&ops);
        assert_eq!(groups.len(), 1);
        assert!(groups.contains_key("<unresolved>"));
        assert_eq!(groups["<unresolved>"].len(), 2);
    }

    #[test]
    fn zone_group_by_zone_single_tool_single_group() {
        let mut reg = ZoneRegistry::new();
        reg.register("tool", ZoneId::community());
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        let ops = vec![op("a", "tool", &[])];
        let groups = validator.group_by_zone(&ops);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups["z:community"], vec!["a"]);
    }

    // ── New tests: validator on empty ops ──

    #[test]
    fn zone_validator_empty_operations_passes() {
        let reg = ZoneRegistry::new();
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        assert!(validator.validate(&[]).is_ok());
    }

    // ── New tests: has_cycle edge cases ──

    #[test]
    fn no_cycle_two_independent_nodes() {
        assert!(!has_cycle(&[op("a", "t", &[]), op("b", "t", &[])]));
    }

    #[test]
    fn no_cycle_single_dependency() {
        assert!(!has_cycle(&[op("a", "t", &[]), op("b", "t", &["a"])]));
    }

    #[test]
    fn cycle_in_subgraph_with_independent_node() {
        // a (independent), b→c→b (cycle)
        assert!(has_cycle(&[
            op("a", "t", &[]),
            op("b", "t", &["c"]),
            op("c", "t", &["b"]),
        ]));
    }

    #[test]
    fn no_cycle_wide_fan_out() {
        let mut ops = vec![op("root", "t", &[])];
        for i in 0..10 {
            ops.push(op(&format!("child{i}"), "t", &["root"]));
        }
        assert!(!has_cycle(&ops));
    }

    #[test]
    fn no_cycle_wide_fan_in() {
        let mut ops: Vec<BatchOperation> =
            (0..10).map(|i| op(&format!("src{i}"), "t", &[])).collect();
        let deps: Vec<String> = (0..10).map(|i| format!("src{i}")).collect();
        let dep_refs: Vec<&str> = deps.iter().map(String::as_str).collect();
        ops.push(op("sink", "t", &dep_refs));
        assert!(!has_cycle(&ops));
    }

    // ── New tests: ExecutionPlan and ExecutionTier ──

    #[test]
    fn execution_tier_clone() {
        let tier = ExecutionTier {
            operation_ids: vec!["a".into(), "b".into()],
        };
        let cloned = tier.clone();
        assert_eq!(cloned.operation_ids, tier.operation_ids);
    }

    #[test]
    fn execution_plan_clone() {
        let plan = ExecutionPlan {
            tiers: vec![ExecutionTier {
                operation_ids: vec!["x".into()],
            }],
            total_operations: 1,
        };
        let cloned = plan.clone();
        assert_eq!(cloned.depth(), plan.depth());
        assert_eq!(cloned.total_operations, plan.total_operations);
    }

    #[test]
    fn execution_plan_max_width_single_element_tiers() {
        let plan = ExecutionPlan {
            tiers: vec![
                ExecutionTier {
                    operation_ids: vec!["a".into()],
                },
                ExecutionTier {
                    operation_ids: vec!["b".into()],
                },
                ExecutionTier {
                    operation_ids: vec!["c".into()],
                },
            ],
            total_operations: 3,
        };
        assert_eq!(plan.max_width(), 1);
        assert_eq!(plan.depth(), 3);
    }

    // ── New tests: BatchExecutor default ──

    #[test]
    fn executor_new_is_same_as_default() {
        let e1 = BatchExecutor::new();
        let e2 = BatchExecutor::default();
        // Both have no zone validator
        assert!(e1.zone_validator.is_none());
        assert!(e2.zone_validator.is_none());
    }

    // ── New tests: validate edge cases ──

    #[test]
    fn validate_duplicate_deps_in_single_op_passes() {
        let executor = BatchExecutor::new();
        // An op can list the same dependency twice — no validation against that
        let req = simple_request(vec![op("a", "t", &[]), op("b", "t", &["a", "a"])]);
        assert!(executor.validate(&req).is_ok());
    }

    #[test]
    fn validate_many_ops_no_deps_passes() {
        let executor = BatchExecutor::new();
        let ops: Vec<BatchOperation> = (0..200)
            .map(|i| op(&format!("op{i:04}"), "t", &[]))
            .collect();
        let req = simple_request(ops);
        assert!(executor.validate(&req).is_ok());
    }

    #[test]
    fn validate_max_u32_parallelism_passes() {
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![op("a", "t", &[])],
            options: BatchOptions {
                max_parallelism: u32::MAX,
                ..Default::default()
            },
        };
        assert!(executor.validate(&req).is_ok());
    }

    #[test]
    fn validate_zero_timeout_passes() {
        // Zero timeout is valid at the validation layer; execution handles it
        let executor = BatchExecutor::new();
        let req = BatchInvokeRequest {
            operations: vec![op("a", "t", &[])],
            options: BatchOptions {
                timeout_ms: 0,
                ..Default::default()
            },
        };
        assert!(executor.validate(&req).is_ok());
    }

    // ── New tests: BatchInvokeRequest serde ──

    #[test]
    fn batch_invoke_request_deserialize_minimal_json() {
        let json = r#"{
            "operations": [{"id":"a","tool":"t","input":{}}],
            "options": {}
        }"#;
        let req: BatchInvokeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.operations.len(), 1);
        assert_eq!(req.options.max_parallelism, 8);
    }

    #[test]
    fn batch_invoke_request_clone() {
        let req = simple_request(vec![op("a", "t", &[]), op("b", "t", &["a"])]);
        let cloned = req.clone();
        assert_eq!(req.operations.len(), cloned.operations.len());
        assert_eq!(cloned.operations.len(), 2);
        assert_eq!(cloned.operations[1].depends_on, vec!["a"]);
    }

    // ── New tests: BatchInvokeResponse serde ──

    #[test]
    fn batch_invoke_response_empty_results() {
        let resp = BatchInvokeResponse {
            status: BatchStatus::Success,
            completed: 0,
            failed: 0,
            skipped: 0,
            results: vec![],
            total_duration_ms: 0,
            schedule_report: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BatchInvokeResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.results.is_empty());
        assert_eq!(parsed.total_duration_ms, 0);
    }

    #[test]
    fn batch_invoke_response_clone() {
        let resp = BatchInvokeResponse {
            status: BatchStatus::AllFailed,
            completed: 0,
            failed: 3,
            skipped: 0,
            results: vec![OperationResult {
                id: "x".into(),
                status: OperationResultStatus::Error,
                output: None,
                error: None,
                duration_ms: 5,
            }],
            total_duration_ms: 0,
            schedule_report: None,
        };
        let cloned = resp.clone();
        assert_eq!(resp.status, cloned.status);
        assert_eq!(cloned.status, BatchStatus::AllFailed);
        assert_eq!(cloned.failed, 3);
        assert_eq!(cloned.results[0].id, "x");
    }

    // ── New tests: OperationResult serde skip_serializing_if ──

    #[test]
    fn operation_result_output_omitted_when_none() {
        let result = OperationResult {
            id: "a".into(),
            status: OperationResultStatus::Error,
            output: None,
            error: None,
            duration_ms: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("output"));
    }

    #[test]
    fn operation_result_error_omitted_when_none() {
        let result = OperationResult {
            id: "a".into(),
            status: OperationResultStatus::Success,
            output: Some(serde_json::json!(42)),
            error: None,
            duration_ms: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("error"));
    }

    #[test]
    fn operation_result_clone() {
        let result = OperationResult {
            id: "z".into(),
            status: OperationResultStatus::Success,
            output: Some(serde_json::json!({"nested": [1, 2]})),
            error: None,
            duration_ms: 99,
        };
        let cloned = result.clone();
        assert_eq!(result.id, cloned.id);
        assert_eq!(cloned.id, "z");
        assert_eq!(cloned.duration_ms, 99);
        assert_eq!(cloned.output, result.output);
    }

    // ── New tests: BatchOperationError serde + clone ──

    #[test]
    fn batch_operation_error_clone() {
        let err = BatchOperationError {
            code: "X".into(),
            message: "msg".into(),
            retry_after_ms: Some(100),
        };
        let cloned = err.clone();
        assert_eq!(err.code, cloned.code);
        assert_eq!(cloned.code, "X");
        assert_eq!(cloned.retry_after_ms, Some(100));
    }

    #[test]
    fn batch_operation_error_deserialize_without_retry() {
        let json = r#"{"code":"ERR","message":"oops"}"#;
        let err: BatchOperationError = serde_json::from_str(json).unwrap();
        assert_eq!(err.code, "ERR");
        assert!(err.retry_after_ms.is_none());
    }

    // ── New tests: execute with zone validator ──

    #[test]
    fn execute_with_zone_validator_succeeds_on_allowed_zones() {
        let mut reg = ZoneRegistry::new();
        reg.register("pub.tool", ZoneId::public());
        let validator = BatchZoneValidator::new(ZoneId::work(), reg);
        let executor = BatchExecutor::with_zone_validator(validator);
        let req = simple_request(vec![op("a", "pub.tool", &[])]);
        let resp = executor
            .execute_sync(&req, |_| Ok(serde_json::json!({"ok": true})))
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.completed, 1);
    }

    #[test]
    fn execute_with_zone_validator_fails_on_violation() {
        let mut reg = ZoneRegistry::new();
        reg.register("secret", ZoneId::owner());
        let validator = BatchZoneValidator::new(ZoneId::public(), reg);
        let executor = BatchExecutor::with_zone_validator(validator);
        let req = simple_request(vec![op("a", "secret", &[])]);
        let err = executor
            .execute_sync(&req, |_| Ok(serde_json::json!({})))
            .unwrap_err();
        assert!(err.to_string().contains("zone boundary"));
    }

    // ── New tests: executed_result helper ──

    #[test]
    fn executed_result_success_captures_output() {
        let started = Instant::now();
        let result = executed_result("op1", Ok(serde_json::json!({"ok": true})), started);
        assert_eq!(result.id, "op1");
        assert_eq!(result.status, OperationResultStatus::Success);
        assert!(result.output.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn executed_result_error_captures_error() {
        let started = Instant::now();
        let err = BatchOperationError {
            code: "FAIL".into(),
            message: "nope".into(),
            retry_after_ms: Some(500),
        };
        let result = executed_result("op2", Err(err), started);
        assert_eq!(result.id, "op2");
        assert_eq!(result.status, OperationResultStatus::Error);
        assert!(result.output.is_none());
        assert_eq!(result.error.as_ref().unwrap().code, "FAIL");
        assert_eq!(result.error.as_ref().unwrap().retry_after_ms, Some(500));
    }

    // ── New tests: dependency_failed helper ──

    #[test]
    fn dependency_failed_returns_false_when_all_deps_succeeded() {
        let operation = op("b", "t", &["a"]);
        let mut results_map = HashMap::new();
        results_map.insert(
            "a".to_string(),
            OperationResult {
                id: "a".into(),
                status: OperationResultStatus::Success,
                output: None,
                error: None,
                duration_ms: 0,
            },
        );
        assert!(!dependency_failed(&operation, &results_map));
    }

    #[test]
    fn dependency_failed_returns_true_when_dep_errored() {
        let operation = op("b", "t", &["a"]);
        let mut results_map = HashMap::new();
        results_map.insert(
            "a".to_string(),
            OperationResult {
                id: "a".into(),
                status: OperationResultStatus::Error,
                output: None,
                error: None,
                duration_ms: 0,
            },
        );
        assert!(dependency_failed(&operation, &results_map));
    }

    #[test]
    fn dependency_failed_returns_true_when_dep_skipped() {
        let operation = op("c", "t", &["b"]);
        let mut results_map = HashMap::new();
        results_map.insert(
            "b".to_string(),
            OperationResult {
                id: "b".into(),
                status: OperationResultStatus::Skipped,
                output: None,
                error: None,
                duration_ms: 0,
            },
        );
        assert!(dependency_failed(&operation, &results_map));
    }

    #[test]
    fn dependency_failed_returns_false_when_dep_not_in_map() {
        let operation = op("b", "t", &["a"]);
        let results_map = HashMap::new();
        // Dependency not yet processed => not considered failed
        assert!(!dependency_failed(&operation, &results_map));
    }

    #[test]
    fn dependency_failed_returns_false_when_no_deps() {
        let operation = op("a", "t", &[]);
        let results_map = HashMap::new();
        assert!(!dependency_failed(&operation, &results_map));
    }

    #[test]
    fn dependency_failed_mixed_deps_one_failed() {
        let operation = op("d", "t", &["a", "b", "c"]);
        let mut results_map = HashMap::new();
        results_map.insert(
            "a".to_string(),
            OperationResult {
                id: "a".into(),
                status: OperationResultStatus::Success,
                output: None,
                error: None,
                duration_ms: 0,
            },
        );
        results_map.insert(
            "b".to_string(),
            OperationResult {
                id: "b".into(),
                status: OperationResultStatus::Error,
                output: None,
                error: None,
                duration_ms: 0,
            },
        );
        results_map.insert(
            "c".to_string(),
            OperationResult {
                id: "c".into(),
                status: OperationResultStatus::Success,
                output: None,
                error: None,
                duration_ms: 0,
            },
        );
        assert!(dependency_failed(&operation, &results_map));
    }

    // ── New tests: record_skipped_operations ──

    #[test]
    fn record_skipped_operations_empty_list_is_noop() {
        let mut results_map = HashMap::new();
        record_skipped_operations(&mut results_map, &[], None);
        assert!(results_map.is_empty());
    }

    #[test]
    fn record_skipped_operations_multiple_with_error() {
        let mut results_map = HashMap::new();
        let ids = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        let err = batch_timeout_error();
        record_skipped_operations(&mut results_map, &ids, Some(&err));
        assert_eq!(results_map.len(), 3);
        for id in &ids {
            let r = &results_map[id];
            assert_eq!(r.status, OperationResultStatus::Skipped);
            assert_eq!(r.error.as_ref().unwrap().code, "BATCH_TIMEOUT");
        }
    }

    #[test]
    fn record_skipped_operations_multiple_without_error() {
        let mut results_map = HashMap::new();
        let ids = vec!["a".to_string(), "b".to_string()];
        record_skipped_operations(&mut results_map, &ids, None);
        for id in &ids {
            let r = &results_map[id];
            assert_eq!(r.status, OperationResultStatus::Skipped);
            assert!(r.error.is_none());
        }
    }

    // ── New tests: BatchStatus Copy + Eq ──

    #[test]
    fn batch_status_copy_and_eq() {
        let s1 = BatchStatus::Success;
        let s2 = s1; // Copy
        assert_eq!(s1, s2);
        assert_ne!(s1, BatchStatus::Aborted);
    }

    #[test]
    fn operation_result_status_copy_and_eq() {
        let s1 = OperationResultStatus::Skipped;
        let s2 = s1; // Copy
        assert_eq!(s1, s2);
        assert_ne!(s1, OperationResultStatus::Success);
    }

    // ── New tests: BatchStatus serialize all variants ──

    #[test]
    fn batch_status_serialize_success() {
        assert_eq!(
            serde_json::to_string(&BatchStatus::Success).unwrap(),
            "\"success\""
        );
    }

    #[test]
    fn batch_status_serialize_aborted() {
        assert_eq!(
            serde_json::to_string(&BatchStatus::Aborted).unwrap(),
            "\"aborted\""
        );
    }

    #[test]
    fn operation_result_status_serialize_error() {
        assert_eq!(
            serde_json::to_string(&OperationResultStatus::Error).unwrap(),
            "\"error\""
        );
    }

    // ── New tests: execution with various handler behaviors ──

    #[test]
    fn execute_handler_can_use_input_payload() {
        let executor = BatchExecutor::new();
        let mut custom_op = op("a", "t", &[]);
        custom_op.input = serde_json::json!({"multiply": 7});
        let req = simple_request(vec![custom_op]);
        let resp = executor
            .execute_sync(&req, |o| {
                let factor = o.input["multiply"].as_u64().unwrap_or(1);
                Ok(serde_json::json!({"result": factor * 6}))
            })
            .unwrap();
        assert_eq!(resp.results[0].output.as_ref().unwrap()["result"], 42);
    }

    #[test]
    fn execute_handler_returning_null_output() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "t", &[])]);
        let resp = executor
            .execute_sync(&req, |_| Ok(serde_json::Value::Null))
            .unwrap();
        assert_eq!(resp.status, BatchStatus::Success);
        assert_eq!(resp.results[0].output, Some(serde_json::Value::Null));
    }

    #[test]
    fn execute_handler_returning_string_output() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "t", &[])]);
        let resp = executor
            .execute_sync(&req, |_| Ok(serde_json::json!("just a string")))
            .unwrap();
        assert_eq!(
            resp.results[0].output.as_ref().unwrap(),
            &serde_json::json!("just a string")
        );
    }

    #[test]
    fn execute_handler_returning_array_output() {
        let executor = BatchExecutor::new();
        let req = simple_request(vec![op("a", "t", &[])]);
        let resp = executor
            .execute_sync(&req, |_| Ok(serde_json::json!([1, 2, 3])))
            .unwrap();
        let arr = resp.results[0].output.as_ref().unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    // ── New tests: const fn helpers ──

    #[test]
    fn default_max_parallelism_value() {
        assert_eq!(default_max_parallelism(), 8);
    }

    #[test]
    fn default_timeout_ms_value() {
        assert_eq!(default_timeout_ms(), 30_000);
    }
}
