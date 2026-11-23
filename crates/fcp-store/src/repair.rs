//! Repair controller for maintaining object coverage (NORMATIVE).
//!
//! Implements bounded, convergent repair from `FCP_Specification_V3.md` §11.5
//! (Offline and Repair Behavior) and Appendix Z (Coverage and Repair Playbook).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use fcp_async_core::sync::{OwnedSemaphorePermit, Semaphore};
use fcp_prelude::{ObjectId, ObjectPlacementPolicy, ZoneId};
use fcp_telemetry::metrics;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::coverage::{CoverageEvaluation, CoverageHealth};
use crate::symbol_store::SymbolStore;

/// Repair request for an object.
#[derive(Debug, Clone)]
pub struct RepairRequest {
    /// Object to repair.
    pub object_id: ObjectId,
    /// Zone the object belongs to.
    pub zone_id: ZoneId,
    /// Current coverage evaluation.
    pub coverage: CoverageEvaluation,
    /// Target placement policy.
    pub policy: ObjectPlacementPolicy,
    /// Priority (higher = more urgent).
    pub priority: u32,
}

/// Repair result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairResult {
    /// Object that was repaired.
    pub object_id: ObjectId,
    /// Whether repair was successful.
    pub success: bool,
    /// New coverage after repair.
    pub new_coverage_bps: u32,
    /// Symbols added during repair.
    pub symbols_added: u32,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Current power state of the host running the repair controller.
///
/// Threaded in from the runtime/mesh layer (typically from
/// `DeviceProfile.battery_percent` in `fcp-mesh::device`). The
/// controller reads this on every `next_repair()` call and defers
/// non-critical repairs when the host is on battery and drops below
/// `RepairControllerConfig::battery_defer_threshold_percent`.
///
/// Introduced by bead flywheel_connectors-qyv8n. The enum is
/// deliberately narrow — just AC vs. Battery(percent) — because the
/// controller does not need the full `DeviceProfile` surface, only
/// the signal that gates deferral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PowerState {
    /// Running on wall power (or power state is unknown / not reported).
    /// The controller behaves as before — no deferral.
    #[default]
    Ac,
    /// Running on battery. `percent` is 0..=100.
    Battery {
        /// Battery level as an integer percentage, 0..=100.
        percent: u8,
    },
}

impl PowerState {
    /// Returns true when the state is `Battery { percent: p }` with
    /// `p < threshold`. `AC` always returns false; an explicit
    /// `Battery { percent: 100 }` returns false unless threshold > 100.
    #[must_use]
    pub const fn is_low_battery(self, threshold_percent: u8) -> bool {
        match self {
            Self::Ac => false,
            Self::Battery { percent } => percent < threshold_percent,
        }
    }
}

/// Repair controller configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairControllerConfig {
    /// Maximum concurrent repair operations.
    pub max_concurrent_repairs: usize,
    /// Maximum repairs per minute (rate limit).
    pub max_repairs_per_minute: u32,
    /// Interval between repair loop iterations.
    pub repair_interval: Duration,
    /// Minimum coverage deficit (bps) to trigger repair.
    pub min_deficit_bps: u32,
    /// Maximum symbols to request per repair.
    pub max_symbols_per_repair: u32,
    /// Battery-level threshold (%) below which non-critical repairs
    /// are deferred when the controller is informed the host is on
    /// battery (via [`RepairController::set_power_state`]). Defaults
    /// to 20 — the same threshold `fcp_mesh::device::DeviceProfile::
    /// is_low_battery` uses. Repairs already in-flight are NOT
    /// interrupted; only newly-dequeued repairs are gated.
    ///
    /// Set to 0 to never defer on battery (battery and AC behave
    /// identically). Set to 101 to defer on ANY battery state,
    /// regardless of percent.
    pub battery_defer_threshold_percent: u8,
}

impl Default for RepairControllerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_repairs: 10,
            max_repairs_per_minute: 100,
            repair_interval: Duration::from_secs(60),
            min_deficit_bps: 500, // 5% deficit triggers repair
            max_symbols_per_repair: 100,
            battery_defer_threshold_percent: 20,
        }
    }
}

/// Repair statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepairStats {
    /// Total repairs attempted.
    pub repairs_attempted: u64,
    /// Successful repairs.
    pub repairs_succeeded: u64,
    /// Failed repairs.
    pub repairs_failed: u64,
    /// Total symbols added.
    pub symbols_added: u64,
    /// Current repair queue depth.
    pub queue_depth: usize,
    /// Repairs blocked by rate limit.
    pub rate_limited: u64,
    /// Repairs deferred because the host is on battery below the
    /// configured threshold (bead flywheel_connectors-qyv8n).
    #[serde(default)]
    pub power_deferred: u64,
}

/// Stable reason code for why a repair action was planned or deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairReasonCode {
    /// Coverage or availability is below the policy SLO target.
    #[serde(rename = "repair.policy_slo_deficit")]
    PolicySloDeficit,
    /// Coverage is reconstructable but violates source-diversity policy.
    #[serde(rename = "repair.diversity_deficit")]
    DiversityDeficit,
    /// Object is hot and should be pre-staged beyond the base policy floor.
    #[serde(rename = "repair.hot_object_pre_stage")]
    HotObjectPreStage,
    /// Repair was deferred because the current cycle budget was exhausted.
    #[serde(rename = "repair.deferred_cycle_budget")]
    DeferredCycleBudget,
    /// Repair was deferred because the planner is power constrained.
    #[serde(rename = "repair.deferred_power_budget")]
    DeferredPowerBudget,
}

impl RepairReasonCode {
    /// Return the stable wire-format string for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicySloDeficit => "repair.policy_slo_deficit",
            Self::DiversityDeficit => "repair.diversity_deficit",
            Self::HotObjectPreStage => "repair.hot_object_pre_stage",
            Self::DeferredCycleBudget => "repair.deferred_cycle_budget",
            Self::DeferredPowerBudget => "repair.deferred_power_budget",
        }
    }
}

impl fmt::Display for RepairReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-cycle repair planning budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairCycleBudget {
    /// Maximum actions that may be planned in a cycle.
    pub max_repairs: usize,
    /// Maximum estimated bytes that may be spent in a cycle.
    pub max_bytes: u64,
    /// Maximum estimated decode CPU budget in milliseconds.
    pub max_decode_ms: u32,
}

impl Default for RepairCycleBudget {
    fn default() -> Self {
        Self {
            max_repairs: usize::MAX,
            max_bytes: u64::MAX,
            max_decode_ms: u32::MAX,
        }
    }
}

/// Budget usage consumed by the selected repair actions in a cycle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairCycleUsage {
    /// Number of selected repair actions.
    pub repairs: usize,
    /// Estimated bytes consumed by selected actions.
    pub bytes: u64,
    /// Estimated decode milliseconds consumed by selected actions.
    pub decode_ms: u32,
}

impl RepairCycleUsage {
    const fn can_fit(&self, budget: &RepairCycleBudget, action: &RepairPlanAction) -> bool {
        self.repairs < budget.max_repairs
            && self.bytes.saturating_add(action.estimated_bytes) <= budget.max_bytes
            && self.decode_ms.saturating_add(action.estimated_decode_ms) <= budget.max_decode_ms
    }

    const fn record(&mut self, action: &RepairPlanAction) {
        self.repairs += 1;
        self.bytes = self.bytes.saturating_add(action.estimated_bytes);
        self.decode_ms = self.decode_ms.saturating_add(action.estimated_decode_ms);
    }
}

/// Summary of the strictest policy targets encountered in a planning cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPolicyTargets {
    /// Maximum target coverage requirement across tracked objects.
    pub target_coverage_bps: u32,
    /// Maximum minimum source-diversity requirement across tracked objects.
    pub min_source_diversity: u8,
    /// Strictest source concentration ceiling across tracked objects.
    pub max_node_fraction_bps: u16,
}

impl Default for RepairPolicyTargets {
    fn default() -> Self {
        Self {
            target_coverage_bps: 0,
            min_source_diversity: 0,
            max_node_fraction_bps: 10_000,
        }
    }
}

/// Deterministic zone-level SLO summary derived during a planning cycle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairSloMetrics {
    /// Median coverage across tracked objects using nearest-rank percentiles.
    pub coverage_p50_bps: u32,
    /// 90th percentile coverage across tracked objects using nearest-rank percentiles.
    pub coverage_p90_bps: u32,
    /// 99th percentile coverage across tracked objects using nearest-rank percentiles.
    pub coverage_p99_bps: u32,
    /// Ratio of hot objects that are currently reconstructable.
    pub hot_object_access_bps: u32,
}

impl RepairSloMetrics {
    fn from_coverages(
        coverage_samples: &mut [u32],
        hot_object_count: usize,
        hot_object_available_count: usize,
    ) -> Self {
        // Skip sort if samples are already in order (common when list_zone
        // returns objects in deterministic order and coverage is monotonic).
        let is_sorted = coverage_samples.windows(2).all(|w| w[0] <= w[1]);
        if !is_sorted {
            coverage_samples.sort_unstable();
        }

        Self {
            coverage_p50_bps: percentile_bps(coverage_samples, 50),
            coverage_p90_bps: percentile_bps(coverage_samples, 90),
            coverage_p99_bps: percentile_bps(coverage_samples, 99),
            hot_object_access_bps: basis_points_ratio(hot_object_available_count, hot_object_count),
        }
    }
}

fn percentile_bps(sorted_samples: &[u32], percentile: usize) -> u32 {
    if sorted_samples.is_empty() {
        return 0;
    }

    // Use u64 arithmetic to avoid overflow when len * percentile exceeds usize::MAX.
    let numerator = (sorted_samples.len() as u64).saturating_mul(percentile as u64);
    let rank = (numerator.div_ceil(100) as usize)
        .saturating_sub(1)
        .min(sorted_samples.len().saturating_sub(1));
    sorted_samples[rank]
}

fn basis_points_ratio(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return 0;
    }

    let numerator = u64::try_from(numerator).unwrap_or(u64::MAX);
    let denominator = u64::try_from(denominator).unwrap_or(u64::MAX);
    let ratio = numerator.saturating_mul(10_000) / denominator.max(1);
    u32::try_from(ratio).unwrap_or(u32::MAX)
}

/// Additional knobs that influence a single deterministic repair planning cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPlanningOptions {
    /// Monotonic cycle identifier for logs and comparisons.
    pub cycle_id: u64,
    /// Hard budget limits for the cycle.
    pub budget: RepairCycleBudget,
    /// Objects that should be pre-staged more aggressively than the base policy.
    #[serde(default)]
    pub hot_objects: Vec<ObjectId>,
    /// Coverage target for hot-object pre-staging.
    pub hot_object_min_coverage_bps: u32,
    /// Whether the planner should defer non-critical work due to power constraints.
    pub power_saver: bool,
    /// Whether the device is on mains power and can spend extra repair budget.
    pub mains_power: bool,
    /// Whether the current network is metered and should avoid non-critical repairs.
    pub metered_network: bool,
    /// Estimated repair bandwidth available to the planner, in kilobits per second.
    pub bandwidth_estimate_kbps: u32,
    /// Extra cost multiplier, in basis points, for DERP-only or otherwise expensive links.
    pub derp_penalty_bps: u32,
}

impl Default for RepairPlanningOptions {
    fn default() -> Self {
        Self {
            cycle_id: 0,
            budget: RepairCycleBudget::default(),
            hot_objects: Vec::new(),
            hot_object_min_coverage_bps: 10_000,
            power_saver: false,
            mains_power: false,
            metered_network: false,
            bandwidth_estimate_kbps: 0,
            derp_penalty_bps: 0,
        }
    }
}

/// A single explainable repair action selected by the planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPlanAction {
    /// Object to repair.
    pub object_id: ObjectId,
    /// Stable reason code explaining why this action was chosen.
    pub reason_code: RepairReasonCode,
    /// Deterministic priority used for ordering.
    pub priority: u32,
    /// Estimated number of symbols to fetch or pre-stage.
    pub estimated_symbols: u32,
    /// Estimated bytes consumed by the action.
    pub estimated_bytes: u64,
    /// Estimated decode CPU budget consumed by the action.
    pub estimated_decode_ms: u32,
}

/// Deterministic plan output for a single zone repair cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPlan {
    /// Zone that was planned.
    pub zone_id: ZoneId,
    /// Cycle identifier that produced this plan.
    pub cycle_id: u64,
    /// Summary of the strictest policy targets seen in the cycle.
    pub policy_targets: RepairPolicyTargets,
    /// Number of objects evaluated in the zone.
    pub object_count_tracked: usize,
    /// Number of objects that were below target or selected for pre-staging.
    pub object_count_below_target: usize,
    /// Zone-level SLO summary derived from the tracked objects in this cycle.
    pub slo_metrics: RepairSloMetrics,
    /// Planner budget limits for the cycle.
    pub budget: RepairCycleBudget,
    /// Budget actually consumed by `actions`.
    pub budget_used: RepairCycleUsage,
    /// Selected repair actions.
    pub actions: Vec<RepairPlanAction>,
    /// Deferred actions that were explainably skipped.
    pub deferred: Vec<RepairPlanAction>,
}

/// Queue mutation applied during zone evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairQueueAction {
    /// A new repair request was queued.
    Queue,
    /// An existing queued request was refreshed with newer state.
    Refresh,
    /// A stale queued request was removed.
    Remove,
    /// No queue mutation was required.
    Skip,
}

/// Stable reason code for a zone-evaluation decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairEvaluationReasonCode {
    /// Coverage or availability is below the policy SLO target.
    #[serde(rename = "repair.policy_slo_deficit")]
    PolicySloDeficit,
    /// Coverage is reconstructable but violates source-diversity policy.
    #[serde(rename = "repair.diversity_deficit")]
    DiversityDeficit,
    /// The object currently satisfies its repair policy.
    #[serde(rename = "repair.healthy")]
    Healthy,
    /// The object exists in the zone but no longer has a placement policy.
    #[serde(rename = "repair.missing_policy")]
    MissingPolicy,
    /// The object metadata exists but no current symbol distribution is available.
    #[serde(rename = "repair.missing_distribution")]
    MissingDistribution,
}

impl RepairEvaluationReasonCode {
    /// Return the stable wire-format string for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicySloDeficit => "repair.policy_slo_deficit",
            Self::DiversityDeficit => "repair.diversity_deficit",
            Self::Healthy => "repair.healthy",
            Self::MissingPolicy => "repair.missing_policy",
            Self::MissingDistribution => "repair.missing_distribution",
        }
    }
}

impl fmt::Display for RepairEvaluationReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Deterministic per-object decision emitted by zone evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairEvaluationDecision {
    /// Object evaluated during the zone pass.
    pub object_id: ObjectId,
    /// Queue mutation applied for this object.
    pub action: RepairQueueAction,
    /// Stable reason explaining the decision.
    pub reason_code: RepairEvaluationReasonCode,
    /// Observed coverage in basis points when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_bps: Option<u32>,
    /// Distinct source nodes observed when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distinct_nodes: Option<usize>,
    /// Computed queue priority when the object requires repair.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
}

/// Explainable report for one zone evaluation pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairEvaluationReport {
    /// Zone that was evaluated.
    pub zone_id: ZoneId,
    /// Queue depth before pruning and per-object updates.
    pub queue_depth_before: usize,
    /// Queue depth after the evaluation completes.
    pub queue_depth_after: usize,
    /// Count of stale queued requests dropped because the object no longer exists.
    pub pruned_stale_requests: usize,
    /// Per-object decisions in deterministic object-id order.
    pub decisions: Vec<RepairEvaluationDecision>,
}

#[derive(Debug)]
struct ZonePlanInputs {
    policy_targets: RepairPolicyTargets,
    object_count_tracked: usize,
    object_count_below_target: usize,
    coverage_samples: Vec<u32>,
    hot_object_count: usize,
    hot_object_available_count: usize,
    candidates: Vec<RepairPlanAction>,
}

/// Rate limiter state.
struct RateLimiterState {
    tokens: u32,
    last_refill: std::time::Instant,
}

/// Rate limiter for repairs.
struct RateLimiter {
    state: RwLock<RateLimiterState>,
    max_tokens: u32,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            state: RwLock::new(RateLimiterState {
                tokens: max_per_minute,
                last_refill: std::time::Instant::now(),
            }),
            max_tokens: max_per_minute,
        }
    }

    fn try_acquire(&self) -> bool {
        if self.max_tokens == 0 {
            return false;
        }

        let mut state = self.state.write();
        self.refill_locked(&mut state);

        if state.tokens > 0 {
            state.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn available(&self) -> u32 {
        if self.max_tokens == 0 {
            return 0;
        }

        let mut state = self.state.write();
        self.refill_locked(&mut state);
        state.tokens
    }

    fn refill_locked(&self, state: &mut RateLimiterState) {
        let now = std::time::Instant::now();
        let elapsed = now.saturating_duration_since(state.last_refill);

        let nanos_per_token = 60_000_000_000u64 / u64::from(self.max_tokens).max(1);
        if nanos_per_token == 0 {
            state.tokens = self.max_tokens;
            state.last_refill = now;
            return;
        }

        let elapsed_nanos = elapsed.as_nanos();
        let new_tokens_u128 = elapsed_nanos / u128::from(nanos_per_token);

        if new_tokens_u128 > 0 {
            let new_tokens = u32::try_from(new_tokens_u128).unwrap_or(u32::MAX);
            let updated = state.tokens.saturating_add(new_tokens);

            if updated >= self.max_tokens {
                state.tokens = self.max_tokens;
                let remainder_nanos = elapsed_nanos % u128::from(nanos_per_token);
                let rem_secs = u64::try_from(remainder_nanos / 1_000_000_000).unwrap_or(0);
                let rem_nanos = (remainder_nanos % 1_000_000_000) as u32;
                state.last_refill = now
                    .checked_sub(Duration::new(rem_secs, rem_nanos))
                    .unwrap_or(now);
            } else {
                state.tokens = updated;
                // Advance time by the amount of tokens added to preserve phase
                let advance_nanos = new_tokens_u128.saturating_mul(u128::from(nanos_per_token));
                let adv_secs = u64::try_from(advance_nanos / 1_000_000_000).unwrap_or(u64::MAX);
                let adv_nanos = (advance_nanos % 1_000_000_000) as u32;
                if adv_secs < u64::MAX {
                    if let Some(advanced) = state
                        .last_refill
                        .checked_add(Duration::new(adv_secs, adv_nanos))
                    {
                        state.last_refill = advanced;
                    } else {
                        state.last_refill = now;
                    }
                } else {
                    state.last_refill = now;
                }
            }
        }
    }
}

/// Aging boost applied to a deferred repair's priority per evaluation
/// cycle it remained in the queue without being drained.
///
/// Under heavy churn (new high-priority repairs continuously arriving),
/// a pure priority-first scheduler starves lower-priority items
/// indefinitely. Aging gives each deferred item a monotonic priority
/// boost on every `evaluate_zone*` pass that upserts it again, so a
/// P=500 item that has sat through 10 evaluation cycles effectively
/// competes at P=1500 against fresh P=1000 arrivals. Saturates at
/// [`MAX_DEFERRAL_COUNT`] to keep arithmetic bounded.
const AGING_BOOST_PER_DEFERRAL: u32 = 100;

/// Cap on the deferral counter so the aging arithmetic stays bounded
/// and the sort key doesn't keep growing forever. Once an item has
/// been deferred this many cycles, further aging is a no-op — it's
/// already at top-of-queue and additional aging doesn't change
/// ordering relative to other saturated items.
const MAX_DEFERRAL_COUNT: u32 = 1_000_000;

/// Internal queue entry: a `RepairRequest` plus the bookkeeping the
/// controller needs to prevent cross-cycle starvation.
#[derive(Debug, Clone)]
struct QueuedRepair {
    request: RepairRequest,
    /// Number of `evaluate_zone*` cycles this entry has been refreshed
    /// without being drained. Incremented by [`RepairController::upsert_repair`]
    /// when an existing entry is refreshed. Reset to zero only on
    /// removal (`next_repair`, `remove_queued_repair`, `prune_zone_repairs`,
    /// `clear_queue`).
    deferral_count: u32,
}

impl QueuedRepair {
    /// Effective priority for sorting: base priority plus the aging
    /// boost proportional to how long this item has been waiting.
    /// Saturating arithmetic so a pathological `deferral_count` can't
    /// wrap back to a low value.
    fn effective_priority(&self) -> u32 {
        let boost = self
            .deferral_count
            .min(MAX_DEFERRAL_COUNT)
            .saturating_mul(AGING_BOOST_PER_DEFERRAL);
        self.request.priority.saturating_add(boost)
    }
}

/// Ordering key for queued repairs.
///
/// `BTreeMap::pop_last` returns the largest key, so higher effective
/// priority sorts larger. For equal priority, the lower object id sorts
/// larger to preserve the previous sorted-Vec tie-break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepairQueueKey {
    effective_priority: u32,
    object_id: ObjectId,
}

impl RepairQueueKey {
    fn for_entry(entry: &QueuedRepair) -> Self {
        Self {
            effective_priority: entry.effective_priority(),
            object_id: entry.request.object_id,
        }
    }
}

impl Ord for RepairQueueKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.effective_priority
            .cmp(&other.effective_priority)
            .then_with(|| other.object_id.cmp(&self.object_id))
    }
}

impl PartialOrd for RepairQueueKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Default)]
struct RepairQueue {
    entries: BTreeMap<RepairQueueKey, QueuedRepair>,
    object_keys: HashMap<ObjectId, RepairQueueKey>,
}

impl RepairQueue {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn insert_entry(&mut self, entry: QueuedRepair) {
        let key = RepairQueueKey::for_entry(&entry);
        self.object_keys.insert(entry.request.object_id, key);
        self.entries.insert(key, entry);
    }

    fn upsert(&mut self, request: RepairRequest) -> RepairQueueAction {
        if let Some(existing_key) = self.object_keys.remove(&request.object_id)
            && let Some(mut existing) = self.entries.remove(&existing_key)
        {
            // Refresh: preserve and advance the deferral counter so an
            // item that evaluate_zone keeps noticing but that
            // next_repair keeps deferring climbs the queue over time.
            // Starvation-prevention: under heavy churn where fresh
            // high-priority items continuously arrive, this is the
            // only thing keeping a low-priority-but-persistently-queued
            // item from waiting forever.
            existing.request = request;
            existing.deferral_count = existing
                .deferral_count
                .saturating_add(1)
                .min(MAX_DEFERRAL_COUNT);
            self.insert_entry(existing);
            RepairQueueAction::Refresh
        } else {
            self.insert_entry(QueuedRepair {
                request,
                deferral_count: 0,
            });
            RepairQueueAction::Queue
        }
    }

    fn pop_next(&mut self) -> Option<RepairRequest> {
        let (_, entry) = self.entries.pop_last()?;
        self.object_keys.remove(&entry.request.object_id);
        Some(entry.request)
    }

    fn remove_object(&mut self, object_id: &ObjectId) -> bool {
        let Some(key) = self.object_keys.remove(object_id) else {
            return false;
        };
        self.entries.remove(&key).is_some()
    }

    fn prune_zone_repairs(
        &mut self,
        zone_id: &ZoneId,
        tracked_objects: &BTreeSet<ObjectId>,
    ) -> usize {
        let stale: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                (entry.request.zone_id == *zone_id
                    && !tracked_objects.contains(&entry.request.object_id))
                .then_some((*key, entry.request.object_id))
            })
            .collect();

        for (key, object_id) in &stale {
            self.entries.remove(key);
            self.object_keys.remove(object_id);
        }

        stale.len()
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.object_keys.clear();
    }
}

/// Repair controller for maintaining coverage across the mesh.
///
/// Implements bounded, rate-limited repair with convergent behavior.
pub struct RepairController {
    config: RepairControllerConfig,
    semaphore: Arc<Semaphore>,
    rate_limiter: RateLimiter,
    stats: RwLock<RepairStats>,
    queue: RwLock<RepairQueue>,
    /// Latest observed host power state. Defaults to
    /// [`PowerState::Ac`] — i.e. legacy behaviour (no deferral) until
    /// a caller explicitly reports battery state via
    /// [`RepairController::set_power_state`]. Wrapped in `RwLock` so
    /// the runtime layer can update it without taking the repair
    /// queue lock.
    power_state: RwLock<PowerState>,
}

impl RepairController {
    fn sync_queue_depth(&self, queue_depth: usize) {
        self.stats.write().queue_depth = queue_depth;
    }

    fn remove_queued_repair(&self, object_id: &ObjectId) -> bool {
        let mut queue = self.queue.write();
        let removed = queue.remove_object(object_id);
        if removed {
            self.sync_queue_depth(queue.len());
        }
        removed
    }

    fn prune_zone_repairs(&self, zone_id: &ZoneId, tracked_objects: &BTreeSet<ObjectId>) -> usize {
        let mut queue = self.queue.write();
        let removed = queue.prune_zone_repairs(zone_id, tracked_objects);
        if removed > 0 {
            self.sync_queue_depth(queue.len());
        }
        removed
    }

    /// Create a new repair controller.
    #[must_use]
    pub fn new(config: RepairControllerConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_repairs));
        let rate_limiter = RateLimiter::new(config.max_repairs_per_minute);

        Self {
            config,
            semaphore,
            rate_limiter,
            stats: RwLock::new(RepairStats::default()),
            queue: RwLock::new(RepairQueue::default()),
            power_state: RwLock::new(PowerState::default()),
        }
    }

    /// Report the host's current power state to the controller.
    ///
    /// Used by the runtime/mesh layer to plumb
    /// `fcp_mesh::device::DeviceProfile.battery_percent` into the
    /// repair path. Calling this does NOT cancel in-flight repairs;
    /// it only gates subsequent `next_repair()` dequeues. Callers may
    /// invoke it as often as their power subsystem emits events; the
    /// cost is one `RwLock::write` and one enum copy.
    ///
    /// Introduced by bead flywheel_connectors-qyv8n.
    pub fn set_power_state(&self, state: PowerState) {
        *self.power_state.write() = state;
    }

    /// Returns the latest reported power state. Defaults to
    /// [`PowerState::Ac`] if `set_power_state` was never called.
    #[must_use]
    pub fn power_state(&self) -> PowerState {
        *self.power_state.read()
    }

    fn upsert_repair(&self, request: RepairRequest) -> RepairQueueAction {
        let mut queue = self.queue.write();
        let action = queue.upsert(request);
        self.sync_queue_depth(queue.len());
        action
    }

    /// Queue or refresh a repair request with the latest observed state.
    pub fn queue_repair(&self, request: RepairRequest) {
        let _ = self.upsert_repair(request);
    }

    /// Get the next repair request if rate limit allows.
    ///
    /// Power-aware (bead flywheel_connectors-qyv8n): if the host was
    /// reported on battery below
    /// [`RepairControllerConfig::battery_defer_threshold_percent`] via
    /// [`Self::set_power_state`], the dequeue is skipped, the
    /// `power_deferred` stat is incremented, and a `tracing::info!`
    /// event is emitted naming the battery percent + threshold so
    /// operators can see the deferral in logs. In-flight repairs are
    /// unaffected; only newly-dequeued repairs are gated.
    pub fn next_repair(&self) -> Option<RepairRequest> {
        // Acquire write lock first, then check emptiness before consuming a
        // rate-limit token. This avoids a TOCTOU race where the queue is drained
        // between the emptiness check and token acquisition, wasting the token.
        let mut queue = self.queue.write();
        if queue.is_empty() {
            return None;
        }

        // Power-state gate: if the host is on battery below the
        // configured threshold, defer the dequeue. Checked BEFORE the
        // rate-limit token so a deferred cycle does not consume one
        // of the minute's tokens. Logged at info so operators can
        // correlate repair starvation with power transitions.
        let state = *self.power_state.read();
        if state.is_low_battery(self.config.battery_defer_threshold_percent) {
            let pending = queue.len();
            drop(queue);
            self.stats.write().power_deferred += 1;
            let percent = match state {
                PowerState::Battery { percent } => percent,
                PowerState::Ac => 100,
            };
            tracing::info!(
                component = "fcp_store.repair",
                event = RepairReasonCode::DeferredPowerBudget.as_str(),
                battery_percent = percent,
                threshold_percent = self.config.battery_defer_threshold_percent,
                pending_repairs = pending,
                "deferring repair dequeue while host is on battery below threshold"
            );
            return None;
        }

        if !self.rate_limiter.try_acquire() {
            self.stats.write().rate_limited += 1;
            return None;
        }

        let request = queue.pop_next();
        self.stats.write().queue_depth = queue.len();
        request
    }

    /// Try to acquire a repair permit.
    ///
    /// Returns `None` if max concurrent repairs reached.
    pub fn try_acquire_permit(&self) -> Option<RepairPermit> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .ok()
            .map(|permit| RepairPermit { _permit: permit })
    }

    /// Record a repair result.
    pub fn record_result(&self, result: &RepairResult) {
        let mut stats = self.stats.write();
        stats.repairs_attempted += 1;

        if result.success {
            stats.repairs_succeeded += 1;
            stats.symbols_added += u64::from(result.symbols_added);
        } else {
            stats.repairs_failed += 1;
        }
    }

    /// Get current repair statistics.
    #[must_use]
    pub fn stats(&self) -> RepairStats {
        self.stats.read().clone()
    }

    /// Get repair controller configuration.
    #[must_use]
    pub const fn config(&self) -> &RepairControllerConfig {
        &self.config
    }

    const fn placement_node_deficit(
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
    ) -> u8 {
        // Both placement floors constrain the distinct nodes counted by coverage.
        // Satisfying source diversity alone must not suppress replica repair.
        let required = if policy.min_nodes > policy.min_source_diversity {
            policy.min_nodes
        } else {
            policy.min_source_diversity
        };
        coverage.diversity_deficit(required)
    }

    const fn evaluate_reason_code(
        &self,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
    ) -> Option<RepairEvaluationReasonCode> {
        if !coverage.is_available {
            return Some(RepairEvaluationReasonCode::PolicySloDeficit);
        }

        if Self::placement_node_deficit(coverage, policy) > 0
            || coverage.concentration_deficit_bps(policy.max_node_fraction_bps) > 0
        {
            return Some(RepairEvaluationReasonCode::DiversityDeficit);
        }

        let deficit = coverage.coverage_deficit_bps(policy.target_coverage_bps);
        if deficit > 0 && deficit >= self.config.min_deficit_bps {
            return Some(RepairEvaluationReasonCode::PolicySloDeficit);
        }

        None
    }

    /// Check if an object needs repair based on coverage.
    #[must_use]
    pub const fn needs_repair(
        &self,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
    ) -> bool {
        self.evaluate_reason_code(coverage, policy).is_some()
    }

    /// Calculate repair priority for an object.
    #[must_use]
    pub const fn calculate_priority(
        &self,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
    ) -> u32 {
        let health = coverage.health(policy);
        let diversity_deficit = Self::placement_node_deficit(coverage, policy);
        let concentration_deficit =
            coverage.concentration_deficit_bps(policy.max_node_fraction_bps);

        match health {
            CoverageHealth::Unavailable => {
                // Highest priority, but differentiate by coverage deficit
                // Objects with less coverage get higher priority
                let deficit = coverage.coverage_deficit_bps(policy.target_coverage_bps);
                1000 + deficit / 100 // 1000-1100+ range (higher deficit = higher priority)
            }
            CoverageHealth::Degraded => {
                // Priority based on deficit
                let deficit = coverage.coverage_deficit_bps(policy.target_coverage_bps);
                if diversity_deficit > 0 || concentration_deficit > 0 {
                    #[allow(clippy::cast_possible_truncation)] // u8 -> u32 is always safe
                    {
                        200 + (diversity_deficit as u32) * 10
                            + (concentration_deficit as u32) / 100
                            + deficit / 100
                    }
                } else {
                    100 + deficit / 100 // 100-199 range
                }
            }
            CoverageHealth::Healthy => 0,
        }
    }

    const fn plan_reason_code(
        &self,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
        is_hot_object: bool,
        options: &RepairPlanningOptions,
    ) -> Option<RepairReasonCode> {
        if !coverage.is_available {
            return Some(RepairReasonCode::PolicySloDeficit);
        }

        if Self::placement_node_deficit(coverage, policy) > 0 {
            return Some(RepairReasonCode::DiversityDeficit);
        }
        if coverage.concentration_deficit_bps(policy.max_node_fraction_bps) > 0 {
            return Some(RepairReasonCode::DiversityDeficit);
        }

        let deficit = coverage.coverage_deficit_bps(policy.target_coverage_bps);
        if deficit > 0 && deficit >= self.config.min_deficit_bps {
            return Some(RepairReasonCode::PolicySloDeficit);
        }

        if is_hot_object && coverage.coverage_bps < options.hot_object_min_coverage_bps {
            return Some(RepairReasonCode::HotObjectPreStage);
        }

        None
    }

    const fn calculate_plan_priority(
        &self,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
        reason_code: RepairReasonCode,
        options: &RepairPlanningOptions,
    ) -> u32 {
        match reason_code {
            RepairReasonCode::HotObjectPreStage => {
                400 + coverage.coverage_deficit_bps(options.hot_object_min_coverage_bps) / 100
            }
            RepairReasonCode::PolicySloDeficit | RepairReasonCode::DiversityDeficit => {
                self.calculate_priority(coverage, policy)
            }
            RepairReasonCode::DeferredCycleBudget | RepairReasonCode::DeferredPowerBudget => 0,
        }
    }

    fn estimate_plan_action(
        &self,
        object_id: ObjectId,
        coverage: &CoverageEvaluation,
        policy: &ObjectPlacementPolicy,
        object_meta: &crate::symbol_store::ObjectSymbolMeta,
        reason_code: RepairReasonCode,
        options: &RepairPlanningOptions,
    ) -> RepairPlanAction {
        let coverage_symbols = coverage.symbols_needed(policy.target_coverage_bps);
        let diversity_symbols = u32::from(Self::placement_node_deficit(coverage, policy));
        let concentration_symbols =
            coverage.concentration_repair_symbols_needed(policy.max_node_fraction_bps);
        let hot_symbols = if matches!(reason_code, RepairReasonCode::HotObjectPreStage) {
            coverage
                .symbols_needed(options.hot_object_min_coverage_bps)
                .max(1)
        } else {
            0
        };
        let max_symbols_per_repair = self.config.max_symbols_per_repair.max(1);
        let estimated_symbols = coverage_symbols
            .max(diversity_symbols)
            .max(concentration_symbols)
            .max(hot_symbols)
            .max(1)
            .min(max_symbols_per_repair);
        let base_bytes = u64::from(estimated_symbols) * u64::from(object_meta.oti.symbol_size);
        let derp_multiplier = u64::from(10_000u32.saturating_add(options.derp_penalty_bps));
        let estimated_bytes = base_bytes.saturating_mul(derp_multiplier) / 10_000;
        let estimated_decode_ms = estimated_symbols
            .saturating_mul(2)
            .saturating_add(object_meta.source_symbols / 8)
            .max(1);

        RepairPlanAction {
            object_id,
            reason_code,
            priority: self.calculate_plan_priority(coverage, policy, reason_code, options),
            estimated_symbols,
            estimated_bytes,
            estimated_decode_ms,
        }
    }

    fn effective_budget(
        &self,
        policy_targets: RepairPolicyTargets,
        slo_metrics: RepairSloMetrics,
        candidates: &[RepairPlanAction],
        options: &RepairPlanningOptions,
    ) -> RepairCycleBudget {
        const AGGRESSIVE_REPAIR_BANDWIDTH_KBPS: u32 = 50_000;

        let mut budget = options.budget;
        let has_policy_slo_deficit = candidates
            .iter()
            .any(|action| action.reason_code == RepairReasonCode::PolicySloDeficit);
        let severe_zone_deficit = policy_targets.target_coverage_bps > 0
            && policy_targets
                .target_coverage_bps
                .saturating_sub(slo_metrics.coverage_p50_bps)
                >= self.config.min_deficit_bps;

        if has_policy_slo_deficit
            && severe_zone_deficit
            && options.mains_power
            && !options.power_saver
            && !options.metered_network
            && options.bandwidth_estimate_kbps >= AGGRESSIVE_REPAIR_BANDWIDTH_KBPS
        {
            budget.max_repairs = budget.max_repairs.saturating_mul(2);
            budget.max_bytes = budget.max_bytes.saturating_mul(2);
            budget.max_decode_ms = budget.max_decode_ms.saturating_mul(2);
        }

        budget
    }

    async fn collect_zone_plan_inputs(
        &self,
        zone_id: &ZoneId,
        symbol_store: &dyn SymbolStore,
        policies: &HashMap<ObjectId, ObjectPlacementPolicy>,
        options: &RepairPlanningOptions,
    ) -> ZonePlanInputs {
        let mut object_ids = symbol_store.list_zone(zone_id).await;
        object_ids.sort();

        let mut policy_targets = RepairPolicyTargets::default();
        let mut object_count_tracked = 0usize;
        let mut object_count_below_target = 0usize;
        let mut coverage_samples = Vec::new();
        let mut hot_object_count = 0usize;
        let mut hot_object_available_count = 0usize;
        let mut candidates = Vec::new();

        // Build HashSet once for O(1) hot-object checks instead of
        // O(hot_objects.len()) linear scan per object in the loop below.
        let hot_set: std::collections::HashSet<&ObjectId> = options.hot_objects.iter().collect();

        for object_id in object_ids {
            let Some(policy) = policies.get(&object_id).cloned() else {
                continue;
            };
            let Some(dist) = symbol_store.get_distribution(&object_id).await else {
                continue;
            };
            let Ok(object_meta) = symbol_store.get_object_meta(&object_id).await else {
                continue;
            };

            object_count_tracked += 1;
            policy_targets.target_coverage_bps = policy_targets
                .target_coverage_bps
                .max(policy.target_coverage_bps);
            policy_targets.min_source_diversity = policy_targets
                .min_source_diversity
                .max(policy.min_source_diversity);
            policy_targets.max_node_fraction_bps = policy_targets
                .max_node_fraction_bps
                .min(policy.max_node_fraction_bps);

            let coverage = CoverageEvaluation::from_distribution(object_id, &dist);
            coverage_samples.push(coverage.coverage_bps);
            let is_hot_object = hot_set.contains(&object_id);
            if is_hot_object {
                hot_object_count += 1;
                if coverage.is_available {
                    hot_object_available_count += 1;
                }
            }
            let Some(reason_code) =
                self.plan_reason_code(&coverage, &policy, is_hot_object, options)
            else {
                continue;
            };

            object_count_below_target += 1;
            candidates.push(self.estimate_plan_action(
                object_id,
                &coverage,
                &policy,
                &object_meta,
                reason_code,
                options,
            ));
        }

        ZonePlanInputs {
            policy_targets,
            object_count_tracked,
            object_count_below_target,
            coverage_samples,
            hot_object_count,
            hot_object_available_count,
            candidates,
        }
    }

    fn select_plan_actions(
        options: &RepairPlanningOptions,
        plan: &mut RepairPlan,
        candidates: Vec<RepairPlanAction>,
    ) {
        for action in candidates {
            let is_noncritical_policy_deficit =
                matches!(action.reason_code, RepairReasonCode::PolicySloDeficit)
                    && action.priority < 1000;
            let is_noncritical_hot_prestage =
                action.reason_code == RepairReasonCode::HotObjectPreStage;
            let should_defer_for_power = (options.power_saver || options.metered_network)
                && (is_noncritical_policy_deficit || is_noncritical_hot_prestage);

            if should_defer_for_power {
                let mut deferred = action;
                deferred.reason_code = RepairReasonCode::DeferredPowerBudget;
                plan.deferred.push(deferred);
                continue;
            }

            if plan.budget_used.can_fit(&plan.budget, &action) {
                plan.budget_used.record(&action);
                plan.actions.push(action);
            } else {
                let mut deferred = action;
                deferred.reason_code = if options.power_saver || options.metered_network {
                    RepairReasonCode::DeferredPowerBudget
                } else {
                    RepairReasonCode::DeferredCycleBudget
                };
                plan.deferred.push(deferred);
            }
        }
    }

    /// Build a deterministic, explainable repair plan for one zone evaluation cycle.
    pub async fn plan_zone(
        &self,
        zone_id: &ZoneId,
        symbol_store: &dyn SymbolStore,
        policies: &HashMap<ObjectId, ObjectPlacementPolicy>,
        options: &RepairPlanningOptions,
    ) -> RepairPlan {
        let ZonePlanInputs {
            policy_targets,
            object_count_tracked,
            object_count_below_target,
            mut coverage_samples,
            hot_object_count,
            hot_object_available_count,
            mut candidates,
        } = self
            .collect_zone_plan_inputs(zone_id, symbol_store, policies, options)
            .await;
        let slo_metrics = RepairSloMetrics::from_coverages(
            &mut coverage_samples,
            hot_object_count,
            hot_object_available_count,
        );
        let effective_budget =
            self.effective_budget(policy_targets, slo_metrics, &candidates, options);

        candidates.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.estimated_bytes.cmp(&right.estimated_bytes))
                .then_with(|| left.estimated_decode_ms.cmp(&right.estimated_decode_ms))
                .then_with(|| left.object_id.cmp(&right.object_id))
        });

        let mut plan = RepairPlan {
            zone_id: zone_id.clone(),
            cycle_id: options.cycle_id,
            policy_targets,
            object_count_tracked,
            object_count_below_target,
            slo_metrics,
            budget: effective_budget,
            budget_used: RepairCycleUsage::default(),
            actions: Vec::new(),
            deferred: Vec::new(),
        };

        Self::select_plan_actions(options, &mut plan, candidates);
        plan
    }

    /// Evaluate all objects in a zone and queue repairs as needed.
    pub async fn evaluate_zone(
        &self,
        zone_id: &ZoneId,
        symbol_store: &dyn SymbolStore,
        policies: &HashMap<ObjectId, ObjectPlacementPolicy>,
    ) {
        let _ = self
            .evaluate_zone_with_report(zone_id, symbol_store, policies)
            .await;
    }

    /// Evaluate all objects in a zone and return an explainable queue transcript.
    #[allow(clippy::too_many_lines)]
    pub async fn evaluate_zone_with_report(
        &self,
        zone_id: &ZoneId,
        symbol_store: &dyn SymbolStore,
        policies: &HashMap<ObjectId, ObjectPlacementPolicy>,
    ) -> RepairEvaluationReport {
        let mut object_ids = symbol_store.list_zone(zone_id).await;
        object_ids.sort();
        let tracked_objects = object_ids.iter().copied().collect::<BTreeSet<_>>();
        let queue_depth_before = self.queue_depth();
        let pruned_stale_requests = self.prune_zone_repairs(zone_id, &tracked_objects);
        let mut decisions = Vec::with_capacity(object_ids.len());

        for object_id in object_ids {
            let policy = if let Some(p) = policies.get(&object_id) {
                p.clone()
            } else {
                let action = if self.remove_queued_repair(&object_id) {
                    RepairQueueAction::Remove
                } else {
                    RepairQueueAction::Skip
                };
                decisions.push(RepairEvaluationDecision {
                    object_id,
                    action,
                    reason_code: RepairEvaluationReasonCode::MissingPolicy,
                    coverage_bps: None,
                    distinct_nodes: None,
                    priority: None,
                });
                continue;
            };

            let Some(dist) = symbol_store.get_distribution(&object_id).await else {
                let action = if self.remove_queued_repair(&object_id) {
                    RepairQueueAction::Remove
                } else {
                    RepairQueueAction::Skip
                };
                decisions.push(RepairEvaluationDecision {
                    object_id,
                    action,
                    reason_code: RepairEvaluationReasonCode::MissingDistribution,
                    coverage_bps: None,
                    distinct_nodes: None,
                    priority: None,
                });
                continue;
            };

            let coverage = CoverageEvaluation::from_distribution(object_id, &dist);
            let diversity_bps = coverage.diversity_bps(policy.min_source_diversity);

            metrics::record_symbol_coverage(
                zone_id.as_ref(),
                coverage.distinct_nodes,
                coverage.coverage_bps,
                coverage.max_node_fraction_bps,
                diversity_bps,
            );
            if coverage.is_available
                && policy.min_source_diversity > 0
                && coverage.distinct_nodes < policy.min_source_diversity as usize
            {
                metrics::record_diversity_violation(
                    zone_id.as_ref(),
                    policy.min_source_diversity,
                    coverage.distinct_nodes,
                );
            }
            if coverage.is_available
                && coverage.concentration_deficit_bps(policy.max_node_fraction_bps) > 0
            {
                metrics::record_concentration_violation(
                    zone_id.as_ref(),
                    policy.max_node_fraction_bps,
                    coverage.max_node_fraction_bps,
                );
            }

            if let Some(reason_code) = self.evaluate_reason_code(&coverage, &policy) {
                let priority = self.calculate_priority(&coverage, &policy);
                let action = self.upsert_repair(RepairRequest {
                    object_id,
                    zone_id: zone_id.clone(),
                    coverage: coverage.clone(),
                    policy,
                    priority,
                });
                decisions.push(RepairEvaluationDecision {
                    object_id,
                    action,
                    reason_code,
                    coverage_bps: Some(coverage.coverage_bps),
                    distinct_nodes: Some(coverage.distinct_nodes),
                    priority: Some(priority),
                });
            } else {
                let action = if self.remove_queued_repair(&object_id) {
                    RepairQueueAction::Remove
                } else {
                    RepairQueueAction::Skip
                };
                decisions.push(RepairEvaluationDecision {
                    object_id,
                    action,
                    reason_code: RepairEvaluationReasonCode::Healthy,
                    coverage_bps: Some(coverage.coverage_bps),
                    distinct_nodes: Some(coverage.distinct_nodes),
                    priority: None,
                });
            }
        }

        RepairEvaluationReport {
            zone_id: zone_id.clone(),
            queue_depth_before,
            queue_depth_after: self.queue_depth(),
            pruned_stale_requests,
            decisions,
        }
    }

    /// Get available rate limit tokens.
    #[must_use]
    pub fn available_rate_tokens(&self) -> u32 {
        self.rate_limiter.available()
    }

    /// Get queue depth.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue.read().len()
    }

    /// Clear the repair queue.
    pub fn clear_queue(&self) {
        self.queue.write().clear();
        self.stats.write().queue_depth = 0;
    }
}

/// RAII permit for concurrent repair operations.
pub struct RepairPermit {
    _permit: OwnedSemaphorePermit,
}

/// Targeted repair request for specific symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetedRepairRequest {
    /// Object to repair.
    pub object_id: ObjectId,
    /// Specific ESIs to request.
    pub esis: Vec<u32>,
    /// Preferred source nodes (for source diversity).
    pub preferred_sources: Vec<u64>,
    /// Nodes to exclude (already have symbols from).
    pub excluded_sources: Vec<u64>,
}

impl TargetedRepairRequest {
    /// Create a new targeted repair request.
    #[must_use]
    pub const fn new(object_id: ObjectId) -> Self {
        Self {
            object_id,
            esis: Vec::new(),
            preferred_sources: Vec::new(),
            excluded_sources: Vec::new(),
        }
    }

    /// Add ESIs to request.
    #[must_use]
    pub fn with_esis(mut self, esis: Vec<u32>) -> Self {
        self.esis = normalize_u32_ids(esis);
        self
    }

    /// Set preferred sources.
    #[must_use]
    pub fn with_preferred_sources(mut self, sources: Vec<u64>) -> Self {
        let excluded: std::collections::HashSet<_> =
            self.excluded_sources.iter().copied().collect();
        self.preferred_sources = normalize_u64_ids(sources)
            .into_iter()
            .filter(|source| !excluded.contains(source))
            .collect();
        self
    }

    /// Set excluded sources.
    #[must_use]
    pub fn with_excluded_sources(mut self, sources: Vec<u64>) -> Self {
        self.excluded_sources = normalize_u64_ids(sources);
        let excluded: std::collections::HashSet<_> =
            self.excluded_sources.iter().copied().collect();
        self.preferred_sources
            .retain(|source| !excluded.contains(source));
        self
    }
}

fn normalize_u32_ids(mut ids: Vec<u32>) -> Vec<u32> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn normalize_u64_ids(mut ids: Vec<u64>) -> Vec<u64> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;

    use bytes::Bytes;
    use chrono::Utc;
    use jsonschema::Validator;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use serde_json::json;
    use uuid::Uuid;

    use crate::symbol_store::{ObjectTransmissionInfo, StoredSymbol, SymbolMeta};
    use crate::{MemorySymbolStore, MemorySymbolStoreConfig, ObjectSymbolMeta, SymbolDistribution};

    const E2E_LOG_V1_SCHEMA: &str =
        include_str!("../../fcp-conformance/src/schemas/E2E_Log_v1.schema.json");

    fn validate_e2e_log_entry(value: &serde_json::Value) -> Result<(), String> {
        let schema: serde_json::Value =
            serde_json::from_str(E2E_LOG_V1_SCHEMA).map_err(|err| err.to_string())?;
        let validator =
            Validator::new(&schema).map_err(|err| format!("schema compile failed: {err}"))?;
        validator.validate(value).map_err(|err| err.to_string())
    }

    fn assert_valid_e2e_log_entry(value: &serde_json::Value) {
        validate_e2e_log_entry(value).expect("expected log entry to match the E2E schema");
    }

    #[derive(Default)]
    struct StoreLogData {
        object_id: Option<ObjectId>,
        symbol_count: Option<u32>,
        coverage_bps: Option<u32>,
        nodes_holding: Option<Vec<String>>,
        details: Option<serde_json::Value>,
    }

    fn nodes_from_distribution(dist: &SymbolDistribution) -> Vec<String> {
        let mut nodes: Vec<String> = dist.nodes.keys().map(|id| format!("node-{id}")).collect();
        nodes.sort();
        nodes
    }

    fn run_store_test<F, Fut>(test_name: &str, phase: &str, operation: &str, assertions: u32, f: F)
    where
        F: FnOnce() -> Fut + panic::UnwindSafe,
        Fut: std::future::Future<Output = StoreLogData>,
    {
        let start = Instant::now();
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            fcp_async_core::runtime::block_on_sync(f()).expect("runtime")
        }));
        let duration_us = start.elapsed().as_micros();

        let (passed, failed, outcome, data) = match &result {
            Ok(data) => (assertions, 0, "pass", Some(data)),
            Err(_) => (0, assertions, "fail", None),
        };

        let log = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "info",
            "test_name": test_name,
            "module": "fcp-store",
            "phase": phase,
            "operation": operation,
            "correlation_id": Uuid::new_v4().to_string(),
            "result": outcome,
            "duration_us": duration_us,
            "object_id": data.and_then(|d| d.object_id).map(|id| id.to_string()),
            "symbol_count": data.and_then(|d| d.symbol_count),
            "coverage_bps": data.and_then(|d| d.coverage_bps),
            "nodes_holding": data.and_then(|d| d.nodes_holding.clone()),
            "details": data.and_then(|d| d.details.clone()),
            "assertions": {
                "passed": passed,
                "failed": failed
            }
        });
        println!("{log}");

        if let Err(payload) = result {
            panic::resume_unwind(payload);
        }
    }

    fn log_repair_action(
        object_id: &ObjectId,
        source_node: u64,
        target_node: u64,
        coverage_before: u32,
        coverage_after: u32,
        reason_code: &str,
    ) {
        let log = json!({
            "repair_action": "replicate",
            "object_id": object_id.to_string(),
            "source_node": format!("node-{source_node}"),
            "target_node": format!("node-{target_node}"),
            "coverage_before_bps": coverage_before,
            "coverage_after_bps": coverage_after,
            "reason_code": reason_code,
        });
        println!("{log}");
    }

    fn test_coverage(total: u32, source: u32) -> CoverageEvaluation {
        CoverageEvaluation {
            object_id: ObjectId::from_bytes([1; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: total
                .saturating_mul(10_000)
                .checked_div(source)
                .unwrap_or(0),
            is_available: total >= source,
            total_symbols: total,
            source_symbols: source,
        }
    }

    fn test_policy() -> ObjectPlacementPolicy {
        ObjectPlacementPolicy {
            min_nodes: 1,
            max_node_fraction_bps: 10000,
            preferred_devices: vec![],
            excluded_devices: vec![],
            target_coverage_bps: 10000, // 100%
            min_source_diversity: 0,
        }
    }

    fn test_zone_id() -> ZoneId {
        "z:planner".parse().unwrap()
    }

    fn planner_options(cycle_id: u64) -> RepairPlanningOptions {
        RepairPlanningOptions {
            cycle_id,
            ..Default::default()
        }
    }

    async fn seed_planner_object(
        store: &MemorySymbolStore,
        object_id: ObjectId,
        source_symbols: u32,
        total_symbols: u32,
        symbol_size: u16,
        source_nodes: &[u64],
    ) {
        let zone_id = test_zone_id();
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo {
                transfer_length: u64::from(source_symbols) * u64::from(symbol_size),
                symbol_size,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
                payload_hash: None,
            },
            source_symbols,
            first_symbol_at: 1_000_000,
        };
        store.put_object_meta(meta).await.unwrap();

        for esi in 0..total_symbols {
            let source_node = source_nodes[(esi as usize) % source_nodes.len()];
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(source_node),
                    stored_at: 1_000_000 + u64::from(esi),
                },
                data: Bytes::from(vec![0_u8; usize::from(symbol_size)]),
            };
            store.put_symbol(symbol).await.unwrap();
        }
    }

    #[test]
    fn needs_repair_unavailable() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(5, 10); // 50% coverage, unavailable
        let policy = test_policy();

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_degraded() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 500, // 5%
            ..Default::default()
        });

        // 90% coverage = 10% deficit = 1000 bps deficit
        let coverage = test_coverage(9, 10);
        let policy = test_policy();

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_diversity_deficit() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10); // fully available
        let mut policy = test_policy();
        policy.min_source_diversity = 2;

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn minimum_node_policy_triggers_repair_at_full_coverage() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10);
        let mut policy = test_policy();
        policy.min_nodes = 3;

        assert!(coverage.is_available);
        assert!(!coverage.meets_policy(&policy));
        assert!(controller.needs_repair(&coverage, &policy));
        assert_eq!(controller.calculate_priority(&coverage, &policy), 220);

        // Source diversity may impose a stricter floor than placement.
        policy.min_source_diversity = 4;
        assert_eq!(controller.calculate_priority(&coverage, &policy), 230);
        policy.min_nodes = 5;
        assert_eq!(controller.calculate_priority(&coverage, &policy), 240);
    }

    #[test]
    fn zero_repair_threshold_requires_a_positive_deficit() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 0,
            ..Default::default()
        });
        let mut policy = test_policy();

        for total in [10, 15] {
            let coverage = test_coverage(total, 10);
            assert!(!controller.needs_repair(&coverage, &policy));
            assert_eq!(
                controller.plan_reason_code(&coverage, &policy, false, &planner_options(1)),
                None
            );
        }

        // A zero threshold still requests repair for the smallest actual deficit.
        policy.target_coverage_bps = 10_001;
        let coverage = test_coverage(10, 10);
        assert!(controller.needs_repair(&coverage, &policy));
        assert_eq!(
            controller.plan_reason_code(&coverage, &policy, false, &planner_options(1)),
            Some(RepairReasonCode::PolicySloDeficit)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn minimum_node_repair_plan_and_queue_converge() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let zone_id = test_zone_id();
        let object_id = ObjectId::from_bytes([0xA6; 32]);
        seed_planner_object(&store, object_id, 4, 4, 64, &[1]).await;

        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 0,
            ..Default::default()
        });
        let mut policy = test_policy();
        policy.min_nodes = 3;
        let policies = HashMap::from([(object_id, policy)]);
        let options = planner_options(1);

        let plan = controller
            .plan_zone(&zone_id, &store, &policies, &options)
            .await;
        assert_eq!(plan.object_count_below_target, 1);
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].reason_code, RepairReasonCode::DiversityDeficit);
        assert_eq!(plan.actions[0].estimated_symbols, 2);
        assert_eq!(plan.actions[0].estimated_bytes, 128);
        assert_eq!(plan.actions[0].priority, 220);

        let report = controller
            .evaluate_zone_with_report(&zone_id, &store, &policies)
            .await;
        assert_eq!(report.queue_depth_after, 1);
        assert_eq!(report.decisions[0].action, RepairQueueAction::Queue);
        assert_eq!(
            report.decisions[0].reason_code,
            RepairEvaluationReasonCode::DiversityDeficit
        );
        assert_eq!(report.decisions[0].priority, Some(220));

        // New repair slots from two additional nodes satisfy the placement floor.
        for (esi, source_node) in [(4, 2), (5, 3)] {
            store
                .put_symbol(StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi,
                        zone_id: zone_id.clone(),
                        source_node: Some(source_node),
                        stored_at: 1_000_000 + u64::from(esi),
                    },
                    data: Bytes::from(vec![0_u8; 64]),
                })
                .await
                .unwrap();
        }

        let repaired = controller
            .evaluate_zone_with_report(&zone_id, &store, &policies)
            .await;
        assert_eq!(repaired.queue_depth_before, 1);
        assert_eq!(repaired.queue_depth_after, 0);
        assert_eq!(repaired.decisions[0].action, RepairQueueAction::Remove);
        assert_eq!(
            repaired.decisions[0].reason_code,
            RepairEvaluationReasonCode::Healthy
        );
        let repaired_plan = controller
            .plan_zone(&zone_id, &store, &policies, &options)
            .await;
        assert_eq!(repaired_plan.object_count_below_target, 0);
        assert!(repaired_plan.actions.is_empty());
        assert!(repaired_plan.deferred.is_empty());
        assert_eq!(repaired_plan.budget_used, RepairCycleUsage::default());
    }

    #[test]
    fn repair_queued_for_diversity_deficit() {
        run_store_test(
            "repair_queued_for_diversity_deficit",
            "verify",
            "repair",
            4,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });

                let zone_id: ZoneId = "z:test".parse().unwrap();
                let object_id = ObjectId::from_bytes([9; 32]);
                let oti = ObjectTransmissionInfo {
                    transfer_length: 256,
                    symbol_size: 64,
                    source_blocks: 1,
                    sub_blocks: 1,
                    alignment: 8,
                    payload_hash: None,
                };
                let meta = ObjectSymbolMeta {
                    object_id,
                    zone_id: zone_id.clone(),
                    oti,
                    source_symbols: 4,
                    first_symbol_at: 1_000_000,
                };
                store.put_object_meta(meta).await.unwrap();

                for esi in 0..4 {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id,
                            esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(1),
                            stored_at: 1_000_000 + u64::from(esi),
                        },
                        data: Bytes::from(vec![0_u8; 64]),
                    };
                    store.put_symbol(symbol).await.unwrap();
                }

                let policy = ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10_000,
                    min_source_diversity: 2,
                };
                let mut policies = HashMap::new();
                policies.insert(object_id, policy.clone());

                let controller = RepairController::new(RepairControllerConfig::default());
                controller.evaluate_zone(&zone_id, &store, &policies).await;

                assert_eq!(controller.queue_depth(), 1);
                let request = controller.next_repair().expect("repair queued");
                assert_eq!(request.object_id, object_id);
                assert_eq!(request.coverage.distinct_nodes, 1);
                assert!(!request.coverage.meets_diversity_for_reconstruction(&policy));

                let entry = json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "test_name": "repair_queued_for_diversity_deficit",
                    "module": "fcp-store",
                    "phase": "verify",
                    "correlation_id": Uuid::new_v4().to_string(),
                    "result": "pass",
                    "duration_ms": 0,
                    "assertions": { "passed": 4, "failed": 0 },
                    "details": {
                        "object_id": object_id.to_string(),
                        "source_count": request.coverage.distinct_nodes,
                        "diversity_bps": request.coverage.diversity_bps(policy.min_source_diversity),
                        "repair_queued": true
                    }
                });
                assert_valid_e2e_log_entry(&entry);

                let dist = store.get_distribution(&object_id).await.unwrap();

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(request.coverage.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({
                        "source_count": request.coverage.distinct_nodes,
                        "diversity_bps": request.coverage.diversity_bps(policy.min_source_diversity)
                    })),
                }
            },
        );
    }

    #[test]
    fn no_repair_healthy() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10); // 100% coverage
        let policy = test_policy();

        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn priority_calculation() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let policy = test_policy();

        // Unavailable = highest priority (1000 + deficit-based increment)
        // 5/10 symbols = 50% coverage = 5000 bps, target = 10000 bps, deficit = 5000 bps
        // priority = 1000 + 5000/100 = 1050
        let unavailable = test_coverage(5, 10);
        let priority = controller.calculate_priority(&unavailable, &policy);
        assert!(priority >= 1000, "unavailable should have priority >= 1000");
        assert_eq!(priority, 1050, "5/10 symbols should have priority 1050");

        // Degraded = medium priority
        let degraded = CoverageEvaluation {
            object_id: ObjectId::from_bytes([2; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10_000,
            coverage_bps: 9_000,
            is_available: true,
            total_symbols: 10,
            source_symbols: 10,
        };
        let priority = controller.calculate_priority(&degraded, &policy);
        assert!((100..200).contains(&priority));

        let mut diversity_policy = test_policy();
        diversity_policy.min_source_diversity = 3;
        let diversity_priority = controller.calculate_priority(&degraded, &diversity_policy);
        assert!(
            diversity_priority >= 200,
            "diversity deficits should elevate priority"
        );

        // Healthy = no priority
        let healthy = test_coverage(10, 10);
        assert_eq!(controller.calculate_priority(&healthy, &policy), 0);
    }

    #[test]
    fn queue_and_dequeue() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let request1 = RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        let request2 = RepairRequest {
            object_id: ObjectId::from_bytes([2; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(3, 10),
            policy: test_policy(),
            priority: 1000, // Higher priority
        };

        controller.queue_repair(request1);
        controller.queue_repair(request2);

        assert_eq!(controller.queue_depth(), 2);

        // Should get highest priority first
        let next = controller.next_repair().unwrap();
        assert_eq!(next.priority, 1000);

        let next = controller.next_repair().unwrap();
        assert_eq!(next.priority, 100);
    }

    #[test]
    fn queue_tie_breaks_by_object_id() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let higher_object_id = RepairRequest {
            object_id: ObjectId::from_bytes([2; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        let lower_object_id = RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        // Insert in reverse object-id order to prove deterministic tie-breaking.
        controller.queue_repair(higher_object_id);
        controller.queue_repair(lower_object_id);

        let first = controller.next_repair().expect("first item");
        let second = controller.next_repair().expect("second item");
        assert_eq!(first.object_id, ObjectId::from_bytes([1; 32]));
        assert_eq!(second.object_id, ObjectId::from_bytes([2; 32]));
    }

    #[test]
    fn duplicate_queue_ignored() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let request = RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };

        controller.queue_repair(request.clone());
        controller.queue_repair(request); // Duplicate

        assert_eq!(controller.queue_depth(), 1);
    }

    #[test]
    fn record_results() {
        let controller = RepairController::new(RepairControllerConfig::default());

        let success = RepairResult {
            object_id: ObjectId::from_bytes([1; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        };

        let failure = RepairResult {
            object_id: ObjectId::from_bytes([2; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("timeout".into()),
        };

        controller.record_result(&success);
        controller.record_result(&failure);

        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 2);
        assert_eq!(stats.repairs_succeeded, 1);
        assert_eq!(stats.repairs_failed, 1);
        assert_eq!(stats.symbols_added, 5);
    }

    #[test]
    fn rate_limiting() {
        let config = RepairControllerConfig {
            max_repairs_per_minute: 2,
            ..Default::default()
        };
        let controller = RepairController::new(config);

        // Queue 5 repairs
        for i in 0..5 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }

        // Should only get 2 due to rate limit
        assert!(controller.next_repair().is_some());
        assert!(controller.next_repair().is_some());
        assert!(controller.next_repair().is_none()); // Rate limited

        let stats = controller.stats();
        assert!(stats.rate_limited > 0);
    }

    #[test]
    fn concurrent_permits() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 2,
            ..Default::default()
        };
        let controller = RepairController::new(config);

        let permit1 = controller.try_acquire_permit();
        assert!(permit1.is_some());

        let permit2 = controller.try_acquire_permit();
        assert!(permit2.is_some());

        // Third should fail
        let permit3 = controller.try_acquire_permit();
        assert!(permit3.is_none());

        // Drop one permit
        drop(permit1);

        // Now should succeed
        let permit4 = controller.try_acquire_permit();
        assert!(permit4.is_some());
    }

    #[test]
    fn targeted_repair_request() {
        let request = TargetedRepairRequest::new(ObjectId::from_bytes([1; 32]))
            .with_esis(vec![0, 1, 2])
            .with_preferred_sources(vec![100, 200])
            .with_excluded_sources(vec![300]);

        assert_eq!(request.esis.len(), 3);
        assert_eq!(request.preferred_sources.len(), 2);
        assert_eq!(request.excluded_sources.len(), 1);
    }

    #[test]
    fn targeted_repair_request_normalizes_and_resolves_conflicts() {
        let request = TargetedRepairRequest::new(ObjectId::from_bytes([2; 32]))
            .with_preferred_sources(vec![300, 200, 200, 100])
            .with_esis(vec![9, 2, 2, 7, 9, 1])
            .with_excluded_sources(vec![300, 400, 300]);

        assert_eq!(request.esis, vec![1, 2, 7, 9]);
        assert_eq!(request.preferred_sources, vec![100, 200]);
        assert_eq!(request.excluded_sources, vec![300, 400]);
    }

    #[test]
    fn clear_queue() {
        let controller = RepairController::new(RepairControllerConfig::default());

        for i in 0..5 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }

        assert_eq!(controller.queue_depth(), 5);

        controller.clear_queue();
        assert_eq!(controller.queue_depth(), 0);
    }

    // --- New edge case tests ---

    #[test]
    fn config_default_values() {
        let config = RepairControllerConfig::default();
        assert_eq!(config.max_concurrent_repairs, 10);
        assert_eq!(config.max_repairs_per_minute, 100);
        assert_eq!(config.repair_interval, Duration::from_secs(60));
        assert_eq!(config.min_deficit_bps, 500);
        assert_eq!(config.max_symbols_per_repair, 100);
    }

    #[test]
    fn repair_stats_default() {
        let stats = RepairStats::default();
        assert_eq!(stats.repairs_attempted, 0);
        assert_eq!(stats.repairs_succeeded, 0);
        assert_eq!(stats.repairs_failed, 0);
        assert_eq!(stats.symbols_added, 0);
        assert_eq!(stats.queue_depth, 0);
        assert_eq!(stats.rate_limited, 0);
    }

    #[test]
    fn repair_result_serde_roundtrip() {
        let result = RepairResult {
            object_id: ObjectId::from_bytes([1; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.success);
        assert_eq!(deserialized.new_coverage_bps, 10000);
        assert_eq!(deserialized.symbols_added, 5);
        assert!(deserialized.error.is_none());
    }

    #[test]
    fn repair_result_serde_with_error() {
        let result = RepairResult {
            object_id: ObjectId::from_bytes([2; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("timeout".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(!deserialized.success);
        assert_eq!(deserialized.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn repair_stats_serde_roundtrip() {
        let stats = RepairStats {
            repairs_attempted: 10,
            repairs_succeeded: 8,
            repairs_failed: 2,
            symbols_added: 40,
            queue_depth: 3,
            rate_limited: 1,
            power_deferred: 0,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: RepairStats = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.repairs_attempted, 10);
        assert_eq!(deserialized.repairs_succeeded, 8);
        assert_eq!(deserialized.symbols_added, 40);
    }

    #[test]
    fn next_repair_empty_queue() {
        let controller = RepairController::new(RepairControllerConfig::default());
        assert!(controller.next_repair().is_none());
        // No rate_limited bump on empty queue
        assert_eq!(controller.stats().rate_limited, 0);
    }

    #[test]
    fn needs_repair_small_deficit_below_threshold() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 500,
            ..Default::default()
        });

        // 96% coverage = 4% deficit = 400 bps (below 500 threshold)
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 9600;
        coverage.is_available = true;
        let policy = test_policy();

        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn config_accessor() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 5,
            max_repairs_per_minute: 50,
            ..Default::default()
        };
        let controller = RepairController::new(config);
        assert_eq!(controller.config().max_concurrent_repairs, 5);
        assert_eq!(controller.config().max_repairs_per_minute, 50);
    }

    #[test]
    fn available_rate_tokens_initially_full() {
        let config = RepairControllerConfig {
            max_repairs_per_minute: 100,
            ..Default::default()
        };
        let controller = RepairController::new(config);
        assert_eq!(controller.available_rate_tokens(), 100);
    }

    #[test]
    fn targeted_repair_request_default() {
        let id = ObjectId::from_bytes([1; 32]);
        let request = TargetedRepairRequest::new(id);
        assert_eq!(request.object_id, id);
        assert!(request.esis.is_empty());
        assert!(request.preferred_sources.is_empty());
        assert!(request.excluded_sources.is_empty());
    }

    #[test]
    fn targeted_repair_request_serde_roundtrip() {
        let request = TargetedRepairRequest::new(ObjectId::from_bytes([1; 32]))
            .with_esis(vec![0, 1, 2])
            .with_preferred_sources(vec![100])
            .with_excluded_sources(vec![200, 300]);

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: TargetedRepairRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.esis, vec![0, 1, 2]);
        assert_eq!(deserialized.preferred_sources, vec![100]);
        assert_eq!(deserialized.excluded_sources, vec![200, 300]);
    }

    #[test]
    fn clear_queue_resets_stats_depth() {
        let controller = RepairController::new(RepairControllerConfig::default());

        controller.queue_repair(RepairRequest {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        });

        assert_eq!(controller.stats().queue_depth, 1);
        controller.clear_queue();
        assert_eq!(controller.stats().queue_depth, 0);
    }

    #[test]
    fn repair_controller_config_serde_roundtrip() {
        let config = RepairControllerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RepairControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.max_concurrent_repairs,
            config.max_concurrent_repairs
        );
        assert_eq!(deserialized.min_deficit_bps, config.min_deficit_bps);
    }

    #[test]
    fn calculate_priority_healthy_is_zero() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let healthy = test_coverage(10, 10);
        let policy = test_policy();
        assert_eq!(controller.calculate_priority(&healthy, &policy), 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn repair_loop_improves_coverage() {
        run_store_test(
            "repair_loop_improves_coverage",
            "verify",
            "repair",
            3,
            || async {
                let zone_id: ZoneId = "z:store-sim".parse().unwrap();
                let object_id = ObjectId::from_bytes([7; 32]);
                let source_symbols: u32 = 10;
                let symbol_size: u16 = 64;
                let mut rng = StdRng::seed_from_u64(0x5EED);

                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });

                let meta = ObjectSymbolMeta {
                    object_id,
                    zone_id: zone_id.clone(),
                    oti: ObjectTransmissionInfo {
                        transfer_length: u64::from(source_symbols) * u64::from(symbol_size),
                        symbol_size,
                        source_blocks: 1,
                        sub_blocks: 1,
                        alignment: 8,
                        payload_hash: None,
                    },
                    source_symbols,
                    first_symbol_at: 1_000_000,
                };

                store.put_object_meta(meta).await.unwrap();

                let mut next_esi = 0_u32;
                for _ in 0..5 {
                    let node = if rng.gen_bool(0.5) { 1 } else { 3 };
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id,
                            esi: next_esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(node),
                            stored_at: 1_000_000 + u64::from(next_esi),
                        },
                        data: Bytes::from(vec![0_u8; symbol_size as usize]),
                    };
                    store.put_symbol(symbol).await.unwrap();
                    next_esi += 1;
                }

                let policy = ObjectPlacementPolicy {
                    min_nodes: 2,
                    max_node_fraction_bps: 7000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10000,
                    min_source_diversity: 0,
                };

                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 16,
                    ..Default::default()
                });

                let mut policies = HashMap::new();
                policies.insert(object_id, policy.clone());

                controller.evaluate_zone(&zone_id, &store, &policies).await;

                let before_dist = store.get_distribution(&object_id).await.unwrap();
                let before_eval = CoverageEvaluation::from_distribution(object_id, &before_dist);

                assert!(controller.queue_depth() > 0);

                if let Some(request) = controller.next_repair() {
                    let _permit = controller.try_acquire_permit().expect("permit");
                    let needed = request
                        .coverage
                        .symbols_needed(request.policy.target_coverage_bps);
                    let to_add = needed.min(controller.config().max_symbols_per_repair);

                    for _ in 0..to_add {
                        let node = if rng.gen_bool(0.5) { 1 } else { 3 };
                        let symbol = StoredSymbol {
                            meta: SymbolMeta {
                                object_id,
                                esi: next_esi,
                                zone_id: zone_id.clone(),
                                source_node: Some(node),
                                stored_at: 1_000_500 + u64::from(next_esi),
                            },
                            data: Bytes::from(vec![1_u8; symbol_size as usize]),
                        };
                        store.put_symbol(symbol).await.unwrap();
                        next_esi += 1;
                    }

                    let after_dist = store.get_distribution(&object_id).await.unwrap();
                    let after_eval = CoverageEvaluation::from_distribution(object_id, &after_dist);

                    log_repair_action(
                        &object_id,
                        1,
                        3,
                        request.coverage.coverage_bps,
                        after_eval.coverage_bps,
                        "BELOW_THRESHOLD",
                    );

                    controller.record_result(&RepairResult {
                        object_id,
                        success: true,
                        new_coverage_bps: after_eval.coverage_bps,
                        symbols_added: to_add,
                        error: None,
                    });
                }

                let after_dist = store.get_distribution(&object_id).await.unwrap();
                let after_eval = CoverageEvaluation::from_distribution(object_id, &after_dist);

                assert!(after_eval.coverage_bps >= policy.target_coverage_bps);

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(after_dist.total_symbols),
                    coverage_bps: Some(after_eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&after_dist)),
                    details: Some(json!({
                        "coverage_before_bps": before_eval.coverage_bps,
                        "coverage_after_bps": after_eval.coverage_bps,
                    })),
                }
            },
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn repair_respects_budget_and_idempotent() {
        run_store_test(
            "repair_respects_budget_and_idempotent",
            "verify",
            "repair",
            4,
            || async {
                let zone_id: ZoneId = "z:store-sim".parse().unwrap();
                let object_id = ObjectId::from_bytes([9; 32]);
                let source_symbols: u32 = 10;
                let symbol_size: u16 = 64;

                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 2,
                });

                let meta = ObjectSymbolMeta {
                    object_id,
                    zone_id: zone_id.clone(),
                    oti: ObjectTransmissionInfo {
                        transfer_length: u64::from(source_symbols) * u64::from(symbol_size),
                        symbol_size,
                        source_blocks: 1,
                        sub_blocks: 1,
                        alignment: 8,
                        payload_hash: None,
                    },
                    source_symbols,
                    first_symbol_at: 2_000_000,
                };

                store.put_object_meta(meta).await.unwrap();

                let mut next_esi = 0_u32;
                for node in [2_u64, 3_u64, 2_u64, 3_u64, 2_u64, 3_u64] {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id,
                            esi: next_esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(node),
                            stored_at: 2_000_000 + u64::from(next_esi),
                        },
                        data: Bytes::from(vec![2_u8; symbol_size as usize]),
                    };
                    store.put_symbol(symbol).await.unwrap();
                    next_esi += 1;
                }

                let policy = ObjectPlacementPolicy {
                    min_nodes: 2,
                    max_node_fraction_bps: 8000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10000,
                    min_source_diversity: 0,
                };

                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 2,
                    ..Default::default()
                });

                let mut policies = HashMap::new();
                policies.insert(object_id, policy.clone());

                controller.evaluate_zone(&zone_id, &store, &policies).await;
                let before_dist = store.get_distribution(&object_id).await.unwrap();
                let before_eval = CoverageEvaluation::from_distribution(object_id, &before_dist);

                let mut total_added = 0_u32;
                for _ in 0..2 {
                    if let Some(request) = controller.next_repair() {
                        let _permit = controller.try_acquire_permit().expect("permit");
                        let needed = request
                            .coverage
                            .symbols_needed(request.policy.target_coverage_bps);
                        let to_add = needed.min(controller.config().max_symbols_per_repair);
                        total_added += to_add;

                        for _ in 0..to_add {
                            let symbol = StoredSymbol {
                                meta: SymbolMeta {
                                    object_id,
                                    esi: next_esi,
                                    zone_id: zone_id.clone(),
                                    source_node: Some(4),
                                    stored_at: 2_000_500 + u64::from(next_esi),
                                },
                                data: Bytes::from(vec![3_u8; symbol_size as usize]),
                            };
                            store.put_symbol(symbol).await.unwrap();
                            next_esi += 1;
                        }

                        let after_dist = store.get_distribution(&object_id).await.unwrap();
                        let after_eval =
                            CoverageEvaluation::from_distribution(object_id, &after_dist);

                        log_repair_action(
                            &object_id,
                            2,
                            4,
                            request.coverage.coverage_bps,
                            after_eval.coverage_bps,
                            "BELOW_THRESHOLD",
                        );

                        controller.record_result(&RepairResult {
                            object_id,
                            success: true,
                            new_coverage_bps: after_eval.coverage_bps,
                            symbols_added: to_add,
                            error: None,
                        });
                    }

                    controller.evaluate_zone(&zone_id, &store, &policies).await;
                }

                let after_dist = store.get_distribution(&object_id).await.unwrap();
                let after_eval = CoverageEvaluation::from_distribution(object_id, &after_dist);

                assert!(total_added <= 4);
                assert!(after_eval.coverage_bps >= policy.target_coverage_bps);

                controller.evaluate_zone(&zone_id, &store, &policies).await;
                assert_eq!(controller.queue_depth(), 0);

                StoreLogData {
                    object_id: Some(object_id),
                    symbol_count: Some(after_dist.total_symbols),
                    coverage_bps: Some(after_eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&after_dist)),
                    details: Some(json!({
                        "coverage_before_bps": before_eval.coverage_bps,
                        "coverage_after_bps": after_eval.coverage_bps,
                        "symbols_added": total_added,
                    })),
                }
            },
        );
    }

    #[test]
    fn repair_prioritizes_unavailable_objects() {
        run_store_test(
            "repair_prioritizes_unavailable_objects",
            "verify",
            "repair",
            2,
            || async {
                let zone_id: ZoneId = "z:store-sim".parse().unwrap();
                let object_a = ObjectId::from_bytes([0xAA; 32]);
                let object_b = ObjectId::from_bytes([0xBB; 32]);
                let source_symbols: u32 = 10;
                let symbol_size: u16 = 32;

                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 3,
                });

                for object_id in [object_a, object_b] {
                    let meta = ObjectSymbolMeta {
                        object_id,
                        zone_id: zone_id.clone(),
                        oti: ObjectTransmissionInfo {
                            transfer_length: u64::from(source_symbols) * u64::from(symbol_size),
                            symbol_size,
                            source_blocks: 1,
                            sub_blocks: 1,
                            alignment: 8,
                            payload_hash: None,
                        },
                        source_symbols,
                        first_symbol_at: 3_000_000,
                    };
                    store.put_object_meta(meta).await.unwrap();
                }

                let mut next_esi = 0_u32;
                for _ in 0..4 {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id: object_a,
                            esi: next_esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(1),
                            stored_at: 3_000_000 + u64::from(next_esi),
                        },
                        data: Bytes::from(vec![4_u8; symbol_size as usize]),
                    };
                    store.put_symbol(symbol).await.unwrap();
                    next_esi += 1;
                }

                for _ in 0..9 {
                    let symbol = StoredSymbol {
                        meta: SymbolMeta {
                            object_id: object_b,
                            esi: next_esi,
                            zone_id: zone_id.clone(),
                            source_node: Some(2),
                            stored_at: 3_000_500 + u64::from(next_esi),
                        },
                        data: Bytes::from(vec![5_u8; symbol_size as usize]),
                    };
                    store.put_symbol(symbol).await.unwrap();
                    next_esi += 1;
                }

                let policy = ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10000,
                    min_source_diversity: 0,
                };

                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 4,
                    ..Default::default()
                });

                let mut policies = HashMap::new();
                policies.insert(object_a, policy.clone());
                policies.insert(object_b, policy.clone());

                controller.evaluate_zone(&zone_id, &store, &policies).await;

                let first = controller.next_repair().expect("first repair");
                let second = controller.next_repair().expect("second repair");

                assert_eq!(first.object_id, object_a);
                assert_eq!(second.object_id, object_b);

                let dist = store.get_distribution(&object_a).await.unwrap();
                let eval = CoverageEvaluation::from_distribution(object_a, &dist);

                StoreLogData {
                    object_id: Some(object_a),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({
                        "first_repair_object": first.object_id.to_string(),
                        "second_repair_object": second.object_id.to_string(),
                    })),
                }
            },
        );
    }

    // ================================================================
    // Unit tests for types and controller logic (bead 3p99)
    // ================================================================

    // ---- RepairControllerConfig ----

    #[test]
    fn config_default_all_fields() {
        let c = RepairControllerConfig::default();
        assert_eq!(c.max_concurrent_repairs, 10);
        assert_eq!(c.max_repairs_per_minute, 100);
        assert_eq!(c.repair_interval, Duration::from_secs(60));
        assert_eq!(c.min_deficit_bps, 500);
        assert_eq!(c.max_symbols_per_repair, 100);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = RepairControllerConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: RepairControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_concurrent_repairs, 10);
        assert_eq!(back.max_repairs_per_minute, 100);
        assert_eq!(back.max_symbols_per_repair, 100);
    }

    #[test]
    fn config_debug_clone() {
        let c = RepairControllerConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("RepairControllerConfig"));
        let cloned = c.clone();
        assert_eq!(cloned.max_concurrent_repairs, c.max_concurrent_repairs);
    }

    // ---- RepairStats ----

    #[test]
    fn stats_default_all_zero() {
        let s = RepairStats::default();
        assert_eq!(s.repairs_attempted, 0);
        assert_eq!(s.repairs_succeeded, 0);
        assert_eq!(s.repairs_failed, 0);
        assert_eq!(s.symbols_added, 0);
        assert_eq!(s.queue_depth, 0);
        assert_eq!(s.rate_limited, 0);
    }

    #[test]
    fn stats_serde_roundtrip() {
        let s = RepairStats {
            repairs_attempted: 10,
            repairs_succeeded: 8,
            repairs_failed: 2,
            symbols_added: 500,
            queue_depth: 3,
            rate_limited: 1,
            power_deferred: 0,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: RepairStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.repairs_attempted, 10);
        assert_eq!(back.repairs_succeeded, 8);
        assert_eq!(back.symbols_added, 500);
    }

    #[test]
    fn stats_debug_clone() {
        let s = RepairStats::default();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("RepairStats"));
        assert_eq!(s.repairs_attempted, 0);
    }

    // ---- RepairResult ----

    #[test]
    fn repair_result_json_roundtrip() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([1; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(back.success);
        assert_eq!(back.symbols_added, 5);
        assert!(back.error.is_none());
    }

    #[test]
    fn repair_result_with_error() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([2; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("timeout".into()),
        };
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn repair_result_debug_clone() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([3; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 1,
            error: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("RepairResult"));
        assert_eq!(r.symbols_added, 1);
    }

    // ---- TargetedRepairRequest ----

    #[test]
    fn targeted_repair_request_new() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([4; 32]));
        assert!(r.esis.is_empty());
        assert!(r.preferred_sources.is_empty());
        assert!(r.excluded_sources.is_empty());
    }

    #[test]
    fn targeted_repair_request_builder() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([5; 32]))
            .with_esis(vec![1, 2, 3])
            .with_preferred_sources(vec![10, 20])
            .with_excluded_sources(vec![30]);
        assert_eq!(r.esis, vec![1, 2, 3]);
        assert_eq!(r.preferred_sources, vec![10, 20]);
        assert_eq!(r.excluded_sources, vec![30]);
    }

    #[test]
    fn targeted_repair_request_json_roundtrip() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([6; 32])).with_esis(vec![10, 20]);
        let json = serde_json::to_string(&r).unwrap();
        let back: TargetedRepairRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.esis, vec![10, 20]);
    }

    #[test]
    fn targeted_repair_request_debug_clone() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([7; 32])).with_esis(vec![42]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TargetedRepairRequest"));
        assert_eq!(r.esis, vec![42]);
    }

    // ---- RateLimiter ----

    #[test]
    fn rate_limiter_starts_full() {
        let rl = RateLimiter::new(10);
        assert_eq!(rl.available(), 10);
    }

    #[test]
    fn rate_limiter_depletes() {
        let rl = RateLimiter::new(3);
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        // 4th should fail (no time for refill)
        assert!(!rl.try_acquire());
    }

    #[test]
    fn rate_limiter_zero_max() {
        let rl = RateLimiter::new(0);
        assert_eq!(rl.available(), 0);
        assert!(!rl.try_acquire());
    }

    // ---- RepairController: queue + dedup + ordering ----

    #[test]
    fn queue_repair_dedup() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let object_id = ObjectId::from_bytes([10; 32]);
        let coverage = test_coverage(5, 10);
        let policy = test_policy();

        let req = RepairRequest {
            object_id,
            zone_id: "z:test".parse().unwrap(),
            coverage,
            policy,
            priority: 100,
        };
        controller.queue_repair(req.clone());
        controller.queue_repair(req); // duplicate
        assert_eq!(controller.queue_depth(), 1);
    }

    #[test]
    fn queue_repair_priority_ordering() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let policy = test_policy();

        let low = RepairRequest {
            object_id: ObjectId::from_bytes([0xAA; 32]),
            zone_id: zone_id.clone(),
            coverage: test_coverage(9, 10),
            policy: policy.clone(),
            priority: 10,
        };
        let high = RepairRequest {
            object_id: ObjectId::from_bytes([0xBB; 32]),
            zone_id,
            coverage: test_coverage(5, 10),
            policy,
            priority: 100,
        };

        controller.queue_repair(low);
        controller.queue_repair(high);
        assert_eq!(controller.queue_depth(), 2);

        let first = controller.next_repair().unwrap();
        assert_eq!(first.priority, 100); // higher priority first
    }

    #[test]
    fn clear_queue_resets_depth() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let req = RepairRequest {
            object_id: ObjectId::from_bytes([11; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 50,
        };
        controller.queue_repair(req);
        assert_eq!(controller.queue_depth(), 1);
        controller.clear_queue();
        assert_eq!(controller.queue_depth(), 0);
    }

    #[test]
    fn next_repair_returns_none_on_empty() {
        let controller = RepairController::new(RepairControllerConfig::default());
        assert!(controller.next_repair().is_none());
    }

    // ---- record_result ----

    #[test]
    fn record_result_success() {
        let controller = RepairController::new(RepairControllerConfig::default());
        controller.record_result(&RepairResult {
            object_id: ObjectId::from_bytes([12; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        });
        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 1);
        assert_eq!(stats.repairs_succeeded, 1);
        assert_eq!(stats.repairs_failed, 0);
        assert_eq!(stats.symbols_added, 5);
    }

    #[test]
    fn record_result_failure() {
        let controller = RepairController::new(RepairControllerConfig::default());
        controller.record_result(&RepairResult {
            object_id: ObjectId::from_bytes([13; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("timeout".into()),
        });
        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 1);
        assert_eq!(stats.repairs_succeeded, 0);
        assert_eq!(stats.repairs_failed, 1);
        assert_eq!(stats.symbols_added, 0);
    }

    // ---- needs_repair / calculate_priority ----

    #[test]
    fn needs_repair_healthy() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10); // 100% coverage
        let policy = test_policy();
        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn calculate_priority_unavailable() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(5, 10); // 50% = unavailable
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        assert!(priority >= 1000); // unavailable range
    }

    #[test]
    fn calculate_priority_degraded() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Construct degraded: is_available=true but coverage below target
        let coverage = CoverageEvaluation {
            object_id: ObjectId::from_bytes([1; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: 9000, // 90%, below target 100%
            is_available: true,
            total_symbols: 9,
            source_symbols: 10,
        };
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        assert!(priority >= 100);
        assert!(priority < 1000);
    }

    #[test]
    fn calculate_priority_healthy() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = test_coverage(10, 10); // 100%
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        assert_eq!(priority, 0);
    }

    // ---- config/stats accessors ----

    #[test]
    fn controller_config_accessor() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 5,
            ..Default::default()
        };
        let controller = RepairController::new(config);
        assert_eq!(controller.config().max_concurrent_repairs, 5);
    }

    #[test]
    fn controller_stats_initial() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 0);
        assert_eq!(stats.queue_depth, 0);
    }

    #[test]
    fn controller_available_rate_tokens() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 50,
            ..Default::default()
        });
        assert_eq!(controller.available_rate_tokens(), 50);
    }

    // ---- RepairPermit ----

    #[test]
    fn try_acquire_permit_succeeds() {
        let controller = RepairController::new(RepairControllerConfig {
            max_concurrent_repairs: 2,
            ..Default::default()
        });
        let p1 = controller.try_acquire_permit();
        assert!(p1.is_some());
        let p2 = controller.try_acquire_permit();
        assert!(p2.is_some());
        // 3rd should fail (max_concurrent_repairs = 2)
        let p3 = controller.try_acquire_permit();
        assert!(p3.is_none());
        // Drop one permit
        drop(p1);
        let p4 = controller.try_acquire_permit();
        assert!(p4.is_some());
    }

    // ---- RepairRequest ----

    #[test]
    fn repair_request_debug_clone() {
        let req = RepairRequest {
            object_id: ObjectId::from_bytes([14; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 42,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("RepairRequest"));
        assert_eq!(req.priority, 42);
    }

    // ================================================================
    // Additional edge-case and coverage tests
    // ================================================================

    // ---- RepairControllerConfig additional ----

    #[test]
    fn config_custom_values_preserved() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 3,
            max_repairs_per_minute: 25,
            repair_interval: Duration::from_millis(500),
            min_deficit_bps: 1000,
            max_symbols_per_repair: 50,
            battery_defer_threshold_percent: 20,
        };
        assert_eq!(config.max_concurrent_repairs, 3);
        assert_eq!(config.max_repairs_per_minute, 25);
        assert_eq!(config.repair_interval, Duration::from_millis(500));
        assert_eq!(config.min_deficit_bps, 1000);
        assert_eq!(config.max_symbols_per_repair, 50);
    }

    #[test]
    fn config_serde_custom_roundtrip() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 1,
            max_repairs_per_minute: 1,
            repair_interval: Duration::from_secs(1),
            min_deficit_bps: 1,
            max_symbols_per_repair: 1,
            battery_defer_threshold_percent: 20,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: RepairControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_concurrent_repairs, 1);
        assert_eq!(back.max_repairs_per_minute, 1);
        assert_eq!(back.min_deficit_bps, 1);
        assert_eq!(back.max_symbols_per_repair, 1);
    }

    #[test]
    fn config_serde_json_contains_fields() {
        let config = RepairControllerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("max_concurrent_repairs"));
        assert!(json.contains("max_repairs_per_minute"));
        assert!(json.contains("min_deficit_bps"));
        assert!(json.contains("max_symbols_per_repair"));
        assert!(json.contains("repair_interval"));
    }

    #[test]
    fn config_clone_independence() {
        let original = RepairControllerConfig {
            max_concurrent_repairs: 7,
            ..Default::default()
        };
        let mut cloned = original.clone();
        cloned.max_concurrent_repairs = 99;
        assert_eq!(original.max_concurrent_repairs, 7);
        assert_eq!(cloned.max_concurrent_repairs, 99);
    }

    // ---- RepairStats additional ----

    #[test]
    fn stats_clone_independence() {
        let original = RepairStats {
            repairs_attempted: 5,
            repairs_succeeded: 3,
            repairs_failed: 2,
            symbols_added: 100,
            queue_depth: 1,
            rate_limited: 0,
            power_deferred: 0,
        };
        let mut cloned = original.clone();
        cloned.repairs_attempted = 999;
        assert_eq!(original.repairs_attempted, 5);
        assert_eq!(cloned.repairs_attempted, 999);
    }

    #[test]
    fn stats_serde_all_fields_preserved() {
        let s = RepairStats {
            repairs_attempted: 42,
            repairs_succeeded: 30,
            repairs_failed: 12,
            symbols_added: 300,
            queue_depth: 7,
            rate_limited: 5,
            power_deferred: 0,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: RepairStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.repairs_attempted, 42);
        assert_eq!(back.repairs_succeeded, 30);
        assert_eq!(back.repairs_failed, 12);
        assert_eq!(back.symbols_added, 300);
        assert_eq!(back.queue_depth, 7);
        assert_eq!(back.rate_limited, 5);
    }

    #[test]
    fn stats_json_contains_fields() {
        let s = RepairStats::default();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("repairs_attempted"));
        assert!(json.contains("repairs_succeeded"));
        assert!(json.contains("repairs_failed"));
        assert!(json.contains("symbols_added"));
        assert!(json.contains("queue_depth"));
        assert!(json.contains("rate_limited"));
    }

    // ---- RepairResult additional ----

    #[test]
    fn repair_result_clone_independence() {
        let original = RepairResult {
            object_id: ObjectId::from_bytes([20; 32]),
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 10,
            error: None,
        };
        let cloned = original.clone();
        assert_eq!(cloned.object_id, original.object_id);
        assert_eq!(cloned.success, original.success);
        assert_eq!(cloned.new_coverage_bps, original.new_coverage_bps);
        assert_eq!(cloned.symbols_added, original.symbols_added);
        assert_eq!(cloned.error, original.error);
    }

    #[test]
    fn repair_result_serde_failure_roundtrip() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([21; 32]),
            success: false,
            new_coverage_bps: 0,
            symbols_added: 0,
            error: Some("network error: connection refused".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(!back.success);
        assert_eq!(back.new_coverage_bps, 0);
        assert_eq!(back.symbols_added, 0);
        assert_eq!(
            back.error.as_deref(),
            Some("network error: connection refused")
        );
    }

    #[test]
    fn repair_result_json_contains_fields() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([22; 32]),
            success: true,
            new_coverage_bps: 9500,
            symbols_added: 3,
            error: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("object_id"));
        assert!(json.contains("success"));
        assert!(json.contains("new_coverage_bps"));
        assert!(json.contains("symbols_added"));
        assert!(json.contains("error"));
    }

    #[test]
    fn repair_result_partial_coverage() {
        let r = RepairResult {
            object_id: ObjectId::from_bytes([23; 32]),
            success: true,
            new_coverage_bps: 7500,
            symbols_added: 2,
            error: None,
        };
        assert!(r.success);
        assert!(r.new_coverage_bps < 10000);
        assert!(r.new_coverage_bps > 0);
        assert_eq!(r.symbols_added, 2);
    }

    // ---- TargetedRepairRequest additional ----

    #[test]
    fn targeted_request_clone_independence() {
        let original =
            TargetedRepairRequest::new(ObjectId::from_bytes([30; 32])).with_esis(vec![1, 2]);
        let mut cloned = original.clone();
        cloned.esis.push(3);
        assert_eq!(original.esis.len(), 2);
        assert_eq!(cloned.esis.len(), 3);
    }

    #[test]
    fn targeted_request_empty_builder_chain() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([31; 32]))
            .with_esis(vec![])
            .with_preferred_sources(vec![])
            .with_excluded_sources(vec![]);
        assert!(r.esis.is_empty());
        assert!(r.preferred_sources.is_empty());
        assert!(r.excluded_sources.is_empty());
    }

    #[test]
    fn targeted_request_large_esi_list() {
        let esis: Vec<u32> = (0..1000).collect();
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([32; 32])).with_esis(esis);
        assert_eq!(r.esis.len(), 1000);
        assert_eq!(r.esis[999], 999);
    }

    #[test]
    fn targeted_request_serde_with_all_fields() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([33; 32]))
            .with_esis(vec![0, 1, 2, 3])
            .with_preferred_sources(vec![100, 200, 300])
            .with_excluded_sources(vec![400, 500]);
        let json = serde_json::to_string(&r).unwrap();
        let back: TargetedRepairRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.object_id, ObjectId::from_bytes([33; 32]));
        assert_eq!(back.esis, vec![0, 1, 2, 3]);
        assert_eq!(back.preferred_sources, vec![100, 200, 300]);
        assert_eq!(back.excluded_sources, vec![400, 500]);
    }

    #[test]
    fn targeted_request_debug_contains_fields() {
        let r = TargetedRepairRequest::new(ObjectId::from_bytes([34; 32]))
            .with_esis(vec![10])
            .with_preferred_sources(vec![1]);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TargetedRepairRequest"));
        assert!(dbg.contains("esis"));
        assert!(dbg.contains("preferred_sources"));
        assert!(dbg.contains("excluded_sources"));
    }

    // ---- RateLimiter additional ----

    #[test]
    fn rate_limiter_single_token() {
        let rl = RateLimiter::new(1);
        assert_eq!(rl.available(), 1);
        assert!(rl.try_acquire());
        assert!(!rl.try_acquire());
        assert_eq!(rl.available(), 0);
    }

    #[test]
    fn rate_limiter_large_capacity() {
        let rl = RateLimiter::new(10_000);
        assert_eq!(rl.available(), 10_000);
        for _ in 0..100 {
            assert!(rl.try_acquire());
        }
        assert_eq!(rl.available(), 9_900);
    }

    #[test]
    fn rate_limiter_available_after_partial_drain() {
        let rl = RateLimiter::new(5);
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert_eq!(rl.available(), 3);
    }

    // ---- RepairController queue edge cases ----

    #[test]
    fn queue_depth_tracks_insertions() {
        let controller = RepairController::new(RepairControllerConfig::default());
        assert_eq!(controller.queue_depth(), 0);

        for i in 0..5_u8 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: u32::from(i) * 10,
            });
            assert_eq!(controller.queue_depth(), (i as usize) + 1);
        }
    }

    #[test]
    fn queue_depth_tracks_removals() {
        let controller = RepairController::new(RepairControllerConfig::default());
        for i in 0..3_u8 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }
        assert_eq!(controller.queue_depth(), 3);
        let _ = controller.next_repair();
        assert_eq!(controller.queue_depth(), 2);
        let _ = controller.next_repair();
        assert_eq!(controller.queue_depth(), 1);
        let _ = controller.next_repair();
        assert_eq!(controller.queue_depth(), 0);
    }

    #[test]
    fn stats_reflects_multiple_operations() {
        let controller = RepairController::new(RepairControllerConfig::default());

        for i in 0..5_u8 {
            controller.record_result(&RepairResult {
                object_id: ObjectId::from_bytes([i; 32]),
                success: true,
                new_coverage_bps: 10000,
                symbols_added: 3,
                error: None,
            });
        }
        for i in 5..8_u8 {
            controller.record_result(&RepairResult {
                object_id: ObjectId::from_bytes([i; 32]),
                success: false,
                new_coverage_bps: 5000,
                symbols_added: 0,
                error: Some("failed".into()),
            });
        }

        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 8);
        assert_eq!(stats.repairs_succeeded, 5);
        assert_eq!(stats.repairs_failed, 3);
        assert_eq!(stats.symbols_added, 15); // 5 * 3
    }

    #[test]
    fn stats_queue_depth_syncs_with_queue() {
        let controller = RepairController::new(RepairControllerConfig::default());
        controller.queue_repair(RepairRequest {
            object_id: ObjectId::from_bytes([40; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        });
        assert_eq!(controller.stats().queue_depth, 1);

        controller.queue_repair(RepairRequest {
            object_id: ObjectId::from_bytes([41; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 200,
        });
        assert_eq!(controller.stats().queue_depth, 2);

        let _ = controller.next_repair();
        assert_eq!(controller.stats().queue_depth, 1);
    }

    // ---- needs_repair edge cases ----

    #[test]
    fn needs_repair_deficit_exactly_at_threshold() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 500,
            ..Default::default()
        });

        // Exactly 500 bps deficit (5%)
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 9500;
        coverage.is_available = true;
        let policy = test_policy();

        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_deficit_one_below_threshold() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 500,
            ..Default::default()
        });

        // 499 bps deficit (just below threshold)
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 9501;
        coverage.is_available = true;
        let policy = test_policy();

        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_unavailable_always_true() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Zero coverage, unavailable
        let mut coverage = test_coverage(0, 10);
        coverage.is_available = false;
        coverage.coverage_bps = 0;
        let policy = test_policy();
        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_diversity_but_full_coverage() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Full coverage (10/10 = 10000 bps), but only 1 node when min_source_diversity = 3
        let coverage = test_coverage(10, 10);
        let mut policy = test_policy();
        policy.min_source_diversity = 3;
        // distinct_nodes = 1, min_source_diversity = 3 => diversity_deficit = 2
        assert!(controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn needs_repair_concentration_but_full_coverage() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = CoverageEvaluation {
            object_id: ObjectId::from_bytes([52; 32]),
            distinct_nodes: 2,
            max_node_fraction_bps: 7500,
            coverage_bps: 10_000,
            is_available: true,
            total_symbols: 4,
            source_symbols: 4,
        };
        let mut policy = test_policy();
        policy.max_node_fraction_bps = 5_000;
        assert!(controller.needs_repair(&coverage, &policy));
    }

    // ---- calculate_priority edge cases ----

    #[test]
    fn calculate_priority_unavailable_full_deficit() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Zero coverage: deficit = 10000 bps
        let mut coverage = test_coverage(0, 10);
        coverage.is_available = false;
        coverage.coverage_bps = 0;
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        // 1000 + 10000/100 = 1100
        assert_eq!(priority, 1100);
    }

    #[test]
    fn calculate_priority_degraded_diversity_deficit() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Available but degraded: 90% coverage, 1 node, min_diversity = 3
        let coverage = CoverageEvaluation {
            object_id: ObjectId::from_bytes([50; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: 9000, // 10% deficit = 1000 bps
            is_available: true,
            total_symbols: 9,
            source_symbols: 10,
        };
        let mut policy = test_policy();
        policy.min_source_diversity = 3;
        let priority = controller.calculate_priority(&coverage, &policy);
        // diversity_deficit = 3 - 1 = 2
        // 200 + 2*10 + 1000/100 = 200 + 20 + 10 = 230
        assert_eq!(priority, 230);
    }

    #[test]
    fn calculate_priority_degraded_concentration_deficit() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let coverage = CoverageEvaluation {
            object_id: ObjectId::from_bytes([53; 32]),
            distinct_nodes: 2,
            max_node_fraction_bps: 7500,
            coverage_bps: 10_000,
            is_available: true,
            total_symbols: 4,
            source_symbols: 4,
        };
        let mut policy = test_policy();
        policy.max_node_fraction_bps = 5_000;
        let priority = controller.calculate_priority(&coverage, &policy);
        assert_eq!(priority, 225);
    }

    #[test]
    fn calculate_priority_degraded_no_diversity() {
        let controller = RepairController::new(RepairControllerConfig::default());
        // Available but 80% coverage = 2000 bps deficit, no diversity requirement
        let coverage = CoverageEvaluation {
            object_id: ObjectId::from_bytes([51; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: 8000,
            is_available: true,
            total_symbols: 8,
            source_symbols: 10,
        };
        let policy = test_policy();
        let priority = controller.calculate_priority(&coverage, &policy);
        // 100 + 2000/100 = 120
        assert_eq!(priority, 120);
    }

    #[test]
    fn calculate_priority_ordering_is_correct() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let policy = test_policy();

        // Healthy
        let healthy = test_coverage(10, 10);
        let p_healthy = controller.calculate_priority(&healthy, &policy);

        // Degraded (80% coverage)
        let degraded = CoverageEvaluation {
            object_id: ObjectId::from_bytes([52; 32]),
            distinct_nodes: 1,
            max_node_fraction_bps: 10000,
            coverage_bps: 8000,
            is_available: true,
            total_symbols: 8,
            source_symbols: 10,
        };
        let p_degraded = controller.calculate_priority(&degraded, &policy);

        // Unavailable (50% coverage)
        let unavailable = test_coverage(5, 10);
        let p_unavailable = controller.calculate_priority(&unavailable, &policy);

        assert_eq!(p_healthy, 0);
        assert!(p_degraded > p_healthy);
        assert!(p_unavailable > p_degraded);
    }

    // ---- Queue multi-object ordering ----

    #[test]
    fn queue_three_priorities_dequeue_order() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let policy = test_policy();

        let priorities = [50_u32, 200, 100];
        for (i, &p) in priorities.iter().enumerate() {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i as u8; 32]),
                zone_id: zone_id.clone(),
                coverage: test_coverage(5, 10),
                policy: policy.clone(),
                priority: p,
            });
        }

        let first = controller.next_repair().unwrap();
        assert_eq!(first.priority, 200);
        let second = controller.next_repair().unwrap();
        assert_eq!(second.priority, 100);
        let third = controller.next_repair().unwrap();
        assert_eq!(third.priority, 50);
    }

    #[test]
    fn queue_dedup_refreshes_existing_request() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let id = ObjectId::from_bytes([60; 32]);

        let req1 = RepairRequest {
            object_id: id,
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        };
        let req2 = RepairRequest {
            object_id: id,
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 999, // different priority, but same object_id
        };

        controller.queue_repair(req1);
        controller.queue_repair(req2);

        let dequeued = controller.next_repair().unwrap();
        assert_eq!(dequeued.priority, 999);
        assert!(controller.next_repair().is_none());
    }

    // ---- Controller rate limiting edge cases ----

    #[test]
    fn rate_limit_does_not_apply_to_empty_queue() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 0, // zero rate limit
            ..Default::default()
        });
        // Empty queue returns None without bumping rate_limited
        assert!(controller.next_repair().is_none());
        assert_eq!(controller.stats().rate_limited, 0);
    }

    #[test]
    fn rate_limited_bumps_stats() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 1,
            ..Default::default()
        });

        for i in 0..3_u8 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: 100,
            });
        }

        // First succeeds
        assert!(controller.next_repair().is_some());
        // Second fails due to rate limit
        assert!(controller.next_repair().is_none());
        assert!(controller.stats().rate_limited >= 1);
    }

    // ---- Permit edge cases ----

    #[test]
    fn permit_single_concurrent() {
        let controller = RepairController::new(RepairControllerConfig {
            max_concurrent_repairs: 1,
            ..Default::default()
        });
        let p1 = controller.try_acquire_permit();
        assert!(p1.is_some());
        assert!(controller.try_acquire_permit().is_none());
        drop(p1);
        assert!(controller.try_acquire_permit().is_some());
    }

    #[test]
    fn permit_reclaim_after_drop() {
        let controller = RepairController::new(RepairControllerConfig {
            max_concurrent_repairs: 3,
            ..Default::default()
        });
        let p1 = controller.try_acquire_permit().unwrap();
        let p2 = controller.try_acquire_permit().unwrap();
        let p3 = controller.try_acquire_permit().unwrap();
        assert!(controller.try_acquire_permit().is_none());

        // Drop one and verify one slot opens
        drop(p1);
        let p4 = controller.try_acquire_permit();
        assert!(p4.is_some());

        // Still at capacity
        assert!(controller.try_acquire_permit().is_none());

        // Drop two more to free two slots
        drop(p2);
        drop(p3);
        assert!(controller.try_acquire_permit().is_some());
    }

    // ---- Clear queue after partial drain ----

    #[test]
    fn clear_queue_after_partial_drain() {
        let controller = RepairController::new(RepairControllerConfig::default());
        for i in 0..5_u8 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: "z:test".parse().unwrap(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: u32::from(i) * 10,
            });
        }
        // Drain 2
        let _ = controller.next_repair();
        let _ = controller.next_repair();
        assert_eq!(controller.queue_depth(), 3);
        // Clear remaining
        controller.clear_queue();
        assert_eq!(controller.queue_depth(), 0);
        assert!(controller.next_repair().is_none());
    }

    // ---- RepairRequest fields ----

    #[test]
    fn repair_request_zone_id_preserved() {
        let zone_id: ZoneId = "z:production".parse().unwrap();
        let req = RepairRequest {
            object_id: ObjectId::from_bytes([70; 32]),
            zone_id: zone_id.clone(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 500,
        };
        assert_eq!(req.zone_id, zone_id);
        assert_eq!(req.priority, 500);
    }

    #[test]
    fn repair_request_coverage_accessible() {
        let req = RepairRequest {
            object_id: ObjectId::from_bytes([71; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(7, 10),
            policy: test_policy(),
            priority: 100,
        };
        assert_eq!(req.coverage.total_symbols, 7);
        assert_eq!(req.coverage.source_symbols, 10);
    }

    // ---- Controller with various configs ----

    #[test]
    fn controller_zero_rate_limit_blocks_all() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 0,
            ..Default::default()
        });
        controller.queue_repair(RepairRequest {
            object_id: ObjectId::from_bytes([80; 32]),
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        });
        // Queue has item, but rate limiter blocks
        assert_eq!(controller.queue_depth(), 1);
        assert!(controller.next_repair().is_none());
        assert!(controller.stats().rate_limited >= 1);
    }

    #[test]
    fn controller_high_deficit_threshold_skips_minor() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 5000, // 50% deficit required
            ..Default::default()
        });
        // 80% coverage = 2000 bps deficit, below 5000 threshold
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 8000;
        coverage.is_available = true;
        let policy = test_policy();
        assert!(!controller.needs_repair(&coverage, &policy));
    }

    #[test]
    fn controller_low_deficit_threshold_triggers_easily() {
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 100, // 1% deficit is enough
            ..Default::default()
        });
        // 98% coverage = 200 bps deficit, above 100 threshold
        let mut coverage = test_coverage(10, 10);
        coverage.coverage_bps = 9800;
        coverage.is_available = true;
        let policy = test_policy();
        assert!(controller.needs_repair(&coverage, &policy));
    }

    // ---- Integration: queue + dequeue + record ----

    #[test]
    fn full_lifecycle_queue_dequeue_record() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let id = ObjectId::from_bytes([90; 32]);

        controller.queue_repair(RepairRequest {
            object_id: id,
            zone_id: "z:test".parse().unwrap(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 500,
        });
        assert_eq!(controller.queue_depth(), 1);

        let req = controller.next_repair().unwrap();
        assert_eq!(req.object_id, id);
        assert_eq!(controller.queue_depth(), 0);

        let _permit = controller.try_acquire_permit().unwrap();

        controller.record_result(&RepairResult {
            object_id: id,
            success: true,
            new_coverage_bps: 10000,
            symbols_added: 5,
            error: None,
        });

        let stats = controller.stats();
        assert_eq!(stats.repairs_attempted, 1);
        assert_eq!(stats.repairs_succeeded, 1);
        assert_eq!(stats.symbols_added, 5);
    }

    #[test]
    fn planner_reason_codes_cover_policy_diversity_and_hot_paths() {
        run_store_test(
            "planner_reason_codes_cover_policy_diversity_and_hot_paths",
            "verify",
            "repair_plan",
            6,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });
                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 8,
                    ..Default::default()
                });
                let zone_id = test_zone_id();

                let slo_object = ObjectId::from_bytes([0x11; 32]);
                let diversity_object = ObjectId::from_bytes([0x22; 32]);
                let hot_object = ObjectId::from_bytes([0x33; 32]);

                seed_planner_object(&store, slo_object, 10, 5, 64, &[1]).await;
                seed_planner_object(&store, diversity_object, 4, 4, 64, &[1]).await;
                seed_planner_object(&store, hot_object, 10, 10, 64, &[1, 2, 3]).await;

                let mut policies = HashMap::new();
                policies.insert(slo_object, test_policy());
                let mut diversity_policy = test_policy();
                diversity_policy.min_source_diversity = 2;
                policies.insert(diversity_object, diversity_policy);
                let mut hot_policy = test_policy();
                hot_policy.target_coverage_bps = 9_000;
                policies.insert(hot_object, hot_policy);

                let mut options = planner_options(7);
                options.hot_objects = vec![hot_object];
                options.hot_object_min_coverage_bps = 15_000;

                let plan = controller
                    .plan_zone(&zone_id, &store, &policies, &options)
                    .await;
                assert_eq!(plan.object_count_tracked, 3);
                assert_eq!(plan.object_count_below_target, 3);
                assert_eq!(plan.actions.len(), 3);
                assert_eq!(
                    plan.actions[0].reason_code,
                    RepairReasonCode::PolicySloDeficit
                );
                assert_eq!(
                    plan.actions[1].reason_code,
                    RepairReasonCode::HotObjectPreStage
                );
                assert_eq!(
                    plan.actions[2].reason_code,
                    RepairReasonCode::DiversityDeficit
                );

                StoreLogData {
                    symbol_count: Some(plan.object_count_tracked as u32),
                    details: Some(json!({
                        "cycle_id": plan.cycle_id,
                        "reason_codes": plan.actions.iter().map(|action| action.reason_code.as_str()).collect::<Vec<_>>(),
                        "budget_used": {
                            "repairs": plan.budget_used.repairs,
                            "bytes": plan.budget_used.bytes,
                            "decode_ms": plan.budget_used.decode_ms
                        }
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn planner_is_deterministic_and_tie_breaks_by_cost_then_object_id() {
        run_store_test(
            "planner_is_deterministic_and_tie_breaks_by_cost_then_object_id",
            "verify",
            "repair_plan",
            5,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });
                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 4,
                    ..Default::default()
                });
                let zone_id = test_zone_id();

                let cheap_object = ObjectId::from_bytes([0x41; 32]);
                let expensive_object = ObjectId::from_bytes([0x42; 32]);

                seed_planner_object(&store, expensive_object, 4, 3, 256, &[1]).await;
                seed_planner_object(&store, cheap_object, 4, 3, 64, &[1]).await;

                let mut policies = HashMap::new();
                policies.insert(expensive_object, test_policy());
                policies.insert(cheap_object, test_policy());

                let mut options = planner_options(8);
                options.derp_penalty_bps = 5_000;
                let first_plan = controller
                    .plan_zone(&zone_id, &store, &policies, &options)
                    .await;
                let second_plan = controller
                    .plan_zone(&zone_id, &store, &policies, &options)
                    .await;

                assert_eq!(first_plan, second_plan);
                assert_eq!(first_plan.actions.len(), 2);
                assert_eq!(first_plan.actions[0].object_id, cheap_object);
                assert!(
                    first_plan.actions[0].estimated_bytes < first_plan.actions[1].estimated_bytes
                );

                StoreLogData {
                    symbol_count: Some(u32::try_from(first_plan.actions.len()).unwrap_or(u32::MAX)),
                    details: Some(json!({
                        "ordered_objects": first_plan.actions.iter().map(|action| action.object_id.to_string()).collect::<Vec<_>>(),
                        "estimated_bytes": first_plan.actions.iter().map(|action| action.estimated_bytes).collect::<Vec<_>>()
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn planner_enforces_budgets_and_defers_noncritical_work_when_power_limited() {
        run_store_test(
            "planner_enforces_budgets_and_defers_noncritical_work_when_power_limited",
            "verify",
            "repair_plan",
            6,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });
                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 8,
                    ..Default::default()
                });
                let zone_id = test_zone_id();

                let unavailable_object = ObjectId::from_bytes([0x51; 32]);
                let degraded_object = ObjectId::from_bytes([0x52; 32]);

                seed_planner_object(&store, unavailable_object, 8, 3, 64, &[1]).await;
                seed_planner_object(&store, degraded_object, 10, 9, 64, &[1, 2]).await;

                let mut policies = HashMap::new();
                policies.insert(unavailable_object, test_policy());
                policies.insert(degraded_object, test_policy());

                let mut options = planner_options(9);
                options.power_saver = true;
                options.budget = RepairCycleBudget {
                    max_repairs: 1,
                    max_bytes: 1_024,
                    max_decode_ms: 32,
                };

                let plan = controller
                    .plan_zone(&zone_id, &store, &policies, &options)
                    .await;
                assert_eq!(plan.actions.len(), 1);
                assert_eq!(plan.actions[0].object_id, unavailable_object);
                assert_eq!(
                    plan.actions[0].reason_code,
                    RepairReasonCode::PolicySloDeficit
                );
                assert_eq!(plan.deferred.len(), 1);
                assert_eq!(plan.deferred[0].object_id, degraded_object);
                assert_eq!(
                    plan.deferred[0].reason_code,
                    RepairReasonCode::DeferredPowerBudget
                );

                StoreLogData {
                    symbol_count: Some(
                        u32::try_from(plan.actions.len() + plan.deferred.len()).unwrap_or(u32::MAX),
                    ),
                    details: Some(json!({
                        "selected": plan.actions.iter().map(|action| action.object_id.to_string()).collect::<Vec<_>>(),
                        "deferred": plan.deferred.iter().map(|action| action.object_id.to_string()).collect::<Vec<_>>(),
                        "budget": {
                            "max_repairs": plan.budget.max_repairs,
                            "max_bytes": plan.budget.max_bytes,
                            "max_decode_ms": plan.budget.max_decode_ms
                        },
                        "budget_used": {
                            "repairs": plan.budget_used.repairs,
                            "bytes": plan.budget_used.bytes,
                            "decode_ms": plan.budget_used.decode_ms
                        }
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn planner_expands_budget_when_on_mains_with_high_bandwidth() {
        run_store_test(
            "planner_expands_budget_when_on_mains_with_high_bandwidth",
            "verify",
            "repair_plan",
            7,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });
                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 8,
                    ..Default::default()
                });
                let zone_id = test_zone_id();

                let first_object = ObjectId::from_bytes([0x53; 32]);
                let second_object = ObjectId::from_bytes([0x54; 32]);
                let third_object = ObjectId::from_bytes([0x55; 32]);

                seed_planner_object(&store, first_object, 8, 3, 128, &[1]).await;
                seed_planner_object(&store, second_object, 8, 3, 128, &[1]).await;
                seed_planner_object(&store, third_object, 8, 3, 128, &[1]).await;

                let policies = HashMap::from([
                    (first_object, test_policy()),
                    (second_object, test_policy()),
                    (third_object, test_policy()),
                ]);

                let mut baseline = planner_options(12);
                baseline.budget = RepairCycleBudget {
                    max_repairs: 1,
                    max_bytes: 2_048,
                    max_decode_ms: 64,
                };
                let baseline_plan = controller
                    .plan_zone(&zone_id, &store, &policies, &baseline)
                    .await;

                let mut aggressive = baseline.clone();
                aggressive.cycle_id = 13;
                aggressive.mains_power = true;
                aggressive.bandwidth_estimate_kbps = 100_000;
                let aggressive_plan = controller
                    .plan_zone(&zone_id, &store, &policies, &aggressive)
                    .await;

                assert_eq!(baseline_plan.actions.len(), 1);
                assert_eq!(baseline_plan.budget.max_repairs, 1);
                assert_eq!(aggressive_plan.budget.max_repairs, 2);
                assert_eq!(aggressive_plan.budget.max_bytes, 4_096);
                assert_eq!(aggressive_plan.budget.max_decode_ms, 128);
                assert!(
                    aggressive_plan.actions.len() > baseline_plan.actions.len(),
                    "mains+bandwidth should allow a more aggressive cycle budget",
                );
                assert!(
                    aggressive_plan.object_count_below_target >= aggressive_plan.actions.len(),
                    "aggressive planning should still stay bounded by the tracked deficit set",
                );

                StoreLogData {
                    symbol_count: Some(aggressive_plan.object_count_tracked as u32),
                    details: Some(json!({
                        "baseline_budget": {
                            "max_repairs": baseline_plan.budget.max_repairs,
                            "max_bytes": baseline_plan.budget.max_bytes,
                            "max_decode_ms": baseline_plan.budget.max_decode_ms
                        },
                        "aggressive_budget": {
                            "max_repairs": aggressive_plan.budget.max_repairs,
                            "max_bytes": aggressive_plan.budget.max_bytes,
                            "max_decode_ms": aggressive_plan.budget.max_decode_ms
                        },
                        "baseline_actions": baseline_plan.actions.len(),
                        "aggressive_actions": aggressive_plan.actions.len()
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn planner_defers_hot_object_prestage_on_metered_network() {
        run_store_test(
            "planner_defers_hot_object_prestage_on_metered_network",
            "verify",
            "repair_plan",
            6,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });
                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 8,
                    ..Default::default()
                });
                let zone_id = test_zone_id();

                let unavailable_object = ObjectId::from_bytes([0x56; 32]);
                let hot_object = ObjectId::from_bytes([0x57; 32]);

                seed_planner_object(&store, unavailable_object, 8, 3, 64, &[1]).await;
                seed_planner_object(&store, hot_object, 10, 10, 64, &[1, 2, 3]).await;

                let mut hot_policy = test_policy();
                hot_policy.target_coverage_bps = 9_000;
                let policies = HashMap::from([
                    (unavailable_object, test_policy()),
                    (hot_object, hot_policy),
                ]);

                let mut options = planner_options(14);
                options.hot_objects = vec![hot_object];
                options.hot_object_min_coverage_bps = 15_000;
                options.metered_network = true;

                let plan = controller
                    .plan_zone(&zone_id, &store, &policies, &options)
                    .await;

                assert_eq!(plan.actions.len(), 1);
                assert_eq!(plan.actions[0].object_id, unavailable_object);
                assert_eq!(
                    plan.actions[0].reason_code,
                    RepairReasonCode::PolicySloDeficit
                );
                assert_eq!(plan.deferred.len(), 1);
                assert_eq!(plan.deferred[0].object_id, hot_object);
                assert_eq!(
                    plan.deferred[0].reason_code,
                    RepairReasonCode::DeferredPowerBudget
                );

                StoreLogData {
                    symbol_count: Some(plan.object_count_tracked as u32),
                    details: Some(json!({
                        "selected": plan.actions.iter().map(|action| action.object_id.to_string()).collect::<Vec<_>>(),
                        "deferred": plan.deferred.iter().map(|action| action.object_id.to_string()).collect::<Vec<_>>(),
                        "deferred_reason_codes": plan.deferred.iter().map(|action| action.reason_code.as_str()).collect::<Vec<_>>()
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn planner_cost_estimates_are_monotonic_and_capped() {
        let object_id = ObjectId::from_bytes([0x60; 32]);
        let object_meta = ObjectSymbolMeta {
            object_id,
            zone_id: test_zone_id(),
            oti: ObjectTransmissionInfo {
                transfer_length: 64 * 16,
                symbol_size: 64,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
                payload_hash: None,
            },
            source_symbols: 16,
            first_symbol_at: 1_000_000,
        };
        let controller = RepairController::new(RepairControllerConfig {
            min_deficit_bps: 100,
            max_symbols_per_repair: 6,
            ..Default::default()
        });
        let policy = test_policy();
        let baseline_options = planner_options(10);
        let penalized_options = RepairPlanningOptions {
            derp_penalty_bps: 5_000,
            ..baseline_options.clone()
        };

        let mildly_degraded = CoverageEvaluation {
            distinct_nodes: 2,
            max_node_fraction_bps: 5_000,
            ..test_coverage(12, 16)
        };
        let badly_degraded = CoverageEvaluation {
            distinct_nodes: 1,
            ..test_coverage(4, 16)
        };

        let mild_action = controller.estimate_plan_action(
            object_id,
            &mildly_degraded,
            &policy,
            &object_meta,
            RepairReasonCode::PolicySloDeficit,
            &baseline_options,
        );
        let severe_action = controller.estimate_plan_action(
            object_id,
            &badly_degraded,
            &policy,
            &object_meta,
            RepairReasonCode::PolicySloDeficit,
            &baseline_options,
        );
        let penalized_action = controller.estimate_plan_action(
            object_id,
            &mildly_degraded,
            &policy,
            &object_meta,
            RepairReasonCode::PolicySloDeficit,
            &penalized_options,
        );

        assert_eq!(mild_action.estimated_symbols, 4);
        assert_eq!(severe_action.estimated_symbols, 6);
        assert!(
            severe_action.estimated_symbols <= controller.config.max_symbols_per_repair,
            "estimated symbols must stay capped per repair",
        );
        assert!(severe_action.estimated_symbols > mild_action.estimated_symbols);
        assert!(severe_action.estimated_bytes > mild_action.estimated_bytes);
        assert!(severe_action.estimated_decode_ms > mild_action.estimated_decode_ms);
        assert!(penalized_action.estimated_bytes > mild_action.estimated_bytes);
        assert_eq!(
            penalized_action.estimated_decode_ms, mild_action.estimated_decode_ms,
            "DERP penalty should inflate transport cost but not decode cost",
        );
    }

    #[test]
    fn planner_detects_concentration_only_violation() {
        run_store_test(
            "planner_detects_concentration_only_violation",
            "verify",
            "repair_plan",
            4,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });
                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 8,
                    ..Default::default()
                });
                let zone_id = test_zone_id();
                let object_id = ObjectId::from_bytes([0x61; 32]);

                seed_planner_object(&store, object_id, 4, 4, 64, &[1, 1, 1, 2]).await;

                let mut policy = test_policy();
                policy.max_node_fraction_bps = 5_000;
                let policies = HashMap::from([(object_id, policy)]);
                let plan = controller
                    .plan_zone(&zone_id, &store, &policies, &planner_options(10))
                    .await;

                assert_eq!(plan.actions.len(), 1);
                assert_eq!(plan.actions[0].object_id, object_id);
                assert_eq!(
                    plan.actions[0].reason_code,
                    RepairReasonCode::DiversityDeficit
                );
                assert_eq!(plan.actions[0].estimated_symbols, 2);
                assert_eq!(plan.policy_targets.max_node_fraction_bps, 5_000);

                StoreLogData {
                    symbol_count: Some(plan.object_count_tracked as u32),
                    details: Some(json!({
                        "cycle_id": plan.cycle_id,
                        "reason_codes": plan.actions.iter().map(|a| a.reason_code.as_str()).collect::<Vec<_>>(),
                        "max_node_fraction_bps": plan.policy_targets.max_node_fraction_bps,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn planner_reports_zone_slo_percentiles_and_hot_access_ratio() {
        run_store_test(
            "planner_reports_zone_slo_percentiles_and_hot_access_ratio",
            "verify",
            "repair_plan",
            7,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });
                let controller = RepairController::new(RepairControllerConfig {
                    min_deficit_bps: 100,
                    max_symbols_per_repair: 8,
                    ..Default::default()
                });
                let zone_id = test_zone_id();

                let unavailable_hot = ObjectId::from_bytes([0x71; 32]);
                let healthy_hot = ObjectId::from_bytes([0x72; 32]);
                let degraded_cold = ObjectId::from_bytes([0x73; 32]);
                let healthy_cold = ObjectId::from_bytes([0x74; 32]);

                seed_planner_object(&store, unavailable_hot, 4, 3, 64, &[1]).await;
                seed_planner_object(&store, healthy_hot, 4, 4, 64, &[1, 2]).await;
                seed_planner_object(&store, degraded_cold, 4, 2, 64, &[1]).await;
                seed_planner_object(&store, healthy_cold, 4, 4, 64, &[1, 2, 3]).await;

                let policies = HashMap::from([
                    (unavailable_hot, test_policy()),
                    (healthy_hot, test_policy()),
                    (degraded_cold, test_policy()),
                    (healthy_cold, test_policy()),
                ]);

                let mut options = planner_options(11);
                options.hot_objects = vec![unavailable_hot, healthy_hot];

                let plan = controller
                    .plan_zone(&zone_id, &store, &policies, &options)
                    .await;

                assert_eq!(plan.object_count_tracked, 4);
                assert_eq!(plan.slo_metrics.coverage_p50_bps, 7_500);
                assert_eq!(plan.slo_metrics.coverage_p90_bps, 10_000);
                assert_eq!(plan.slo_metrics.coverage_p99_bps, 10_000);
                assert_eq!(plan.slo_metrics.hot_object_access_bps, 5_000);

                StoreLogData {
                    symbol_count: Some(plan.object_count_tracked as u32),
                    details: Some(json!({
                        "cycle_id": plan.cycle_id,
                        "coverage_percentiles_bps": {
                            "p50": plan.slo_metrics.coverage_p50_bps,
                            "p90": plan.slo_metrics.coverage_p90_bps,
                            "p99": plan.slo_metrics.coverage_p99_bps
                        },
                        "hot_object_access_bps": plan.slo_metrics.hot_object_access_bps,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // --- RepairControllerConfig tests ---

    #[test]
    fn repair_config_default() {
        let config = RepairControllerConfig::default();
        assert_eq!(config.max_concurrent_repairs, 10);
        assert_eq!(config.max_repairs_per_minute, 100);
        assert_eq!(config.repair_interval, Duration::from_secs(60));
        assert_eq!(config.min_deficit_bps, 500);
        assert_eq!(config.max_symbols_per_repair, 100);
    }

    #[test]
    fn repair_config_serde_roundtrip() {
        let config = RepairControllerConfig {
            max_concurrent_repairs: 5,
            max_repairs_per_minute: 50,
            repair_interval: Duration::from_secs(30),
            min_deficit_bps: 1000,
            max_symbols_per_repair: 200,
            battery_defer_threshold_percent: 20,
        };
        let json = serde_json::to_string(&config).unwrap();
        let rt: RepairControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.max_concurrent_repairs, 5);
        assert_eq!(rt.max_repairs_per_minute, 50);
        assert_eq!(rt.min_deficit_bps, 1000);
    }

    #[test]
    fn repair_config_debug() {
        let config = RepairControllerConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("RepairControllerConfig"));
    }

    #[test]
    fn repair_config_clone() {
        let config = RepairControllerConfig::default();
        let cloned = config.clone();
        assert_eq!(config.max_concurrent_repairs, cloned.max_concurrent_repairs);
        assert_eq!(config.min_deficit_bps, cloned.min_deficit_bps);
    }

    // --- RepairStats tests ---

    #[test]
    fn repair_stats_default_all_zero() {
        let stats = RepairStats::default();
        assert_eq!(stats.repairs_attempted, 0);
        assert_eq!(stats.repairs_succeeded, 0);
        assert_eq!(stats.repairs_failed, 0);
        assert_eq!(stats.symbols_added, 0);
        assert_eq!(stats.queue_depth, 0);
        assert_eq!(stats.rate_limited, 0);
    }

    #[test]
    fn repair_stats_serde_json_roundtrip() {
        let stats = RepairStats {
            repairs_attempted: 10,
            repairs_succeeded: 8,
            repairs_failed: 2,
            symbols_added: 100,
            queue_depth: 5,
            rate_limited: 1,
            power_deferred: 0,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let rt: RepairStats = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.repairs_attempted, 10);
        assert_eq!(rt.repairs_succeeded, 8);
        assert_eq!(rt.repairs_failed, 2);
        assert_eq!(rt.symbols_added, 100);
    }

    #[test]
    fn repair_stats_debug() {
        let stats = RepairStats::default();
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("RepairStats"));
    }

    #[test]
    fn repair_stats_clone() {
        let stats = RepairStats {
            repairs_attempted: 5,
            repairs_succeeded: 3,
            repairs_failed: 2,
            symbols_added: 50,
            queue_depth: 1,
            rate_limited: 0,
            power_deferred: 0,
        };
        let cloned = stats.clone();
        assert_eq!(stats.repairs_attempted, cloned.repairs_attempted);
    }

    // --- RepairReasonCode tests ---

    #[test]
    fn repair_reason_code_as_str_all() {
        assert_eq!(
            RepairReasonCode::PolicySloDeficit.as_str(),
            "repair.policy_slo_deficit"
        );
        assert_eq!(
            RepairReasonCode::DiversityDeficit.as_str(),
            "repair.diversity_deficit"
        );
        assert_eq!(
            RepairReasonCode::HotObjectPreStage.as_str(),
            "repair.hot_object_pre_stage"
        );
        assert_eq!(
            RepairReasonCode::DeferredCycleBudget.as_str(),
            "repair.deferred_cycle_budget"
        );
        assert_eq!(
            RepairReasonCode::DeferredPowerBudget.as_str(),
            "repair.deferred_power_budget"
        );
    }

    #[test]
    fn repair_reason_code_display() {
        let code = RepairReasonCode::PolicySloDeficit;
        assert_eq!(code.to_string(), "repair.policy_slo_deficit");
    }

    #[test]
    fn repair_reason_code_serde_roundtrip() {
        for code in [
            RepairReasonCode::PolicySloDeficit,
            RepairReasonCode::DiversityDeficit,
            RepairReasonCode::HotObjectPreStage,
            RepairReasonCode::DeferredCycleBudget,
            RepairReasonCode::DeferredPowerBudget,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let rt: RepairReasonCode = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, code);
        }
    }

    #[test]
    fn repair_reason_code_debug() {
        let code = RepairReasonCode::DiversityDeficit;
        let dbg = format!("{code:?}");
        assert!(dbg.contains("DiversityDeficit"));
    }

    #[test]
    fn repair_reason_code_clone_eq() {
        let a = RepairReasonCode::HotObjectPreStage;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn repair_evaluation_reason_code_serde_roundtrip() {
        for code in [
            RepairEvaluationReasonCode::PolicySloDeficit,
            RepairEvaluationReasonCode::DiversityDeficit,
            RepairEvaluationReasonCode::Healthy,
            RepairEvaluationReasonCode::MissingPolicy,
            RepairEvaluationReasonCode::MissingDistribution,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let rt: RepairEvaluationReasonCode = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, code);
            assert_eq!(rt.as_str(), code.as_str());
        }
    }

    #[test]
    fn repair_evaluation_report_serde_roundtrip() {
        let report = RepairEvaluationReport {
            zone_id: test_zone_id(),
            queue_depth_before: 1,
            queue_depth_after: 0,
            pruned_stale_requests: 1,
            decisions: vec![
                RepairEvaluationDecision {
                    object_id: ObjectId::from_bytes([0xA1; 32]),
                    action: RepairQueueAction::Refresh,
                    reason_code: RepairEvaluationReasonCode::PolicySloDeficit,
                    coverage_bps: Some(7_500),
                    distinct_nodes: Some(2),
                    priority: Some(125),
                },
                RepairEvaluationDecision {
                    object_id: ObjectId::from_bytes([0xA2; 32]),
                    action: RepairQueueAction::Skip,
                    reason_code: RepairEvaluationReasonCode::Healthy,
                    coverage_bps: Some(10_000),
                    distinct_nodes: Some(3),
                    priority: None,
                },
            ],
        };

        let json = serde_json::to_string(&report).unwrap();
        let rt: RepairEvaluationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, report);
    }

    // --- RepairCycleBudget tests ---

    #[test]
    fn repair_cycle_budget_default() {
        let budget = RepairCycleBudget::default();
        assert_eq!(budget.max_repairs, usize::MAX);
        assert_eq!(budget.max_bytes, u64::MAX);
        assert_eq!(budget.max_decode_ms, u32::MAX);
    }

    #[test]
    fn repair_cycle_budget_serde_roundtrip() {
        let budget = RepairCycleBudget {
            max_repairs: 50,
            max_bytes: 1_000_000,
            max_decode_ms: 5000,
        };
        let json = serde_json::to_string(&budget).unwrap();
        let rt: RepairCycleBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.max_repairs, 50);
        assert_eq!(rt.max_bytes, 1_000_000);
        assert_eq!(rt.max_decode_ms, 5000);
    }

    #[test]
    fn repair_cycle_budget_debug() {
        let budget = RepairCycleBudget::default();
        let dbg = format!("{budget:?}");
        assert!(dbg.contains("RepairCycleBudget"));
    }

    // --- RepairCycleUsage tests ---

    #[test]
    fn repair_cycle_usage_default() {
        let usage = RepairCycleUsage::default();
        assert_eq!(usage.repairs, 0);
        assert_eq!(usage.bytes, 0);
        assert_eq!(usage.decode_ms, 0);
    }

    #[test]
    fn repair_cycle_usage_serde_roundtrip() {
        let usage = RepairCycleUsage {
            repairs: 3,
            bytes: 5000,
            decode_ms: 100,
        };
        let json = serde_json::to_string(&usage).unwrap();
        let rt: RepairCycleUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.repairs, 3);
        assert_eq!(rt.bytes, 5000);
        assert_eq!(rt.decode_ms, 100);
    }

    #[test]
    fn repair_cycle_usage_debug() {
        let usage = RepairCycleUsage::default();
        let dbg = format!("{usage:?}");
        assert!(dbg.contains("RepairCycleUsage"));
    }

    // --- RepairPolicyTargets tests ---

    #[test]
    fn repair_policy_targets_default() {
        let targets = RepairPolicyTargets::default();
        assert_eq!(targets.target_coverage_bps, 0);
        assert_eq!(targets.min_source_diversity, 0);
        assert_eq!(targets.max_node_fraction_bps, 10_000);
    }

    #[test]
    fn repair_policy_targets_serde_roundtrip() {
        let targets = RepairPolicyTargets {
            target_coverage_bps: 9000,
            min_source_diversity: 3,
            max_node_fraction_bps: 5000,
        };
        let json = serde_json::to_string(&targets).unwrap();
        let rt: RepairPolicyTargets = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.target_coverage_bps, 9000);
        assert_eq!(rt.min_source_diversity, 3);
        assert_eq!(rt.max_node_fraction_bps, 5000);
    }

    #[test]
    fn repair_slo_metrics_default() {
        let metrics = RepairSloMetrics::default();
        assert_eq!(metrics.coverage_p50_bps, 0);
        assert_eq!(metrics.coverage_p90_bps, 0);
        assert_eq!(metrics.coverage_p99_bps, 0);
        assert_eq!(metrics.hot_object_access_bps, 0);
    }

    #[test]
    fn repair_slo_metrics_serde_roundtrip() {
        let metrics = RepairSloMetrics {
            coverage_p50_bps: 7500,
            coverage_p90_bps: 10_000,
            coverage_p99_bps: 12_000,
            hot_object_access_bps: 5000,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let rt: RepairSloMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, metrics);
    }

    // --- RepairPlanningOptions tests ---

    #[test]
    fn repair_planning_options_default() {
        let opts = RepairPlanningOptions::default();
        assert_eq!(opts.cycle_id, 0);
        assert!(opts.hot_objects.is_empty());
        assert_eq!(opts.hot_object_min_coverage_bps, 10_000);
        assert!(!opts.power_saver);
        assert_eq!(opts.derp_penalty_bps, 0);
    }

    #[test]
    fn repair_planning_options_serde_roundtrip() {
        let opts = RepairPlanningOptions {
            cycle_id: 42,
            budget: RepairCycleBudget {
                max_repairs: 10,
                max_bytes: 50_000,
                max_decode_ms: 200,
            },
            hot_objects: vec![ObjectId::from_bytes([1; 32])],
            hot_object_min_coverage_bps: 8000,
            power_saver: true,
            mains_power: true,
            metered_network: true,
            bandwidth_estimate_kbps: 25_000,
            derp_penalty_bps: 500,
        };
        let json = serde_json::to_string(&opts).unwrap();
        let rt: RepairPlanningOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.cycle_id, 42);
        assert!(rt.power_saver);
        assert_eq!(rt.derp_penalty_bps, 500);
        assert_eq!(rt.hot_objects.len(), 1);
    }

    // --- RepairPlanAction tests ---

    #[test]
    fn repair_plan_action_serde_roundtrip() {
        let action = RepairPlanAction {
            object_id: ObjectId::from_bytes([7; 32]),
            reason_code: RepairReasonCode::PolicySloDeficit,
            priority: 500,
            estimated_symbols: 10,
            estimated_bytes: 6400,
            estimated_decode_ms: 25,
        };
        let json = serde_json::to_string(&action).unwrap();
        let rt: RepairPlanAction = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, action);
    }

    #[test]
    fn repair_plan_action_debug() {
        let action = RepairPlanAction {
            object_id: ObjectId::from_bytes([7; 32]),
            reason_code: RepairReasonCode::DiversityDeficit,
            priority: 200,
            estimated_symbols: 5,
            estimated_bytes: 3200,
            estimated_decode_ms: 12,
        };
        let dbg = format!("{action:?}");
        assert!(dbg.contains("RepairPlanAction"));
        assert!(dbg.contains("DiversityDeficit"));
    }

    // --- RepairResult tests ---

    #[test]
    fn repair_result_serde_success_roundtrip() {
        let result = RepairResult {
            object_id: ObjectId::from_bytes([10; 32]),
            success: true,
            new_coverage_bps: 10_000,
            symbols_added: 5,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let rt: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(rt.success);
        assert_eq!(rt.new_coverage_bps, 10_000);
        assert_eq!(rt.symbols_added, 5);
        assert!(rt.error.is_none());
    }

    #[test]
    fn repair_result_with_error_message() {
        let result = RepairResult {
            object_id: ObjectId::from_bytes([10; 32]),
            success: false,
            new_coverage_bps: 5000,
            symbols_added: 0,
            error: Some("decode failure".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let rt: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(!rt.success);
        assert_eq!(rt.error.as_deref(), Some("decode failure"));
    }

    #[test]
    fn repair_result_debug() {
        let result = RepairResult {
            object_id: ObjectId::from_bytes([10; 32]),
            success: true,
            new_coverage_bps: 10_000,
            symbols_added: 3,
            error: None,
        };
        let dbg = format!("{result:?}");
        assert!(dbg.contains("RepairResult"));
    }

    // --- TargetedRepairRequest tests ---

    #[test]
    fn targeted_repair_request_new_empty() {
        let id = ObjectId::from_bytes([1; 32]);
        let req = TargetedRepairRequest::new(id);
        assert_eq!(req.object_id, id);
        assert!(req.esis.is_empty());
        assert!(req.preferred_sources.is_empty());
        assert!(req.excluded_sources.is_empty());
    }

    #[test]
    fn targeted_repair_request_builder_chain() {
        let id = ObjectId::from_bytes([2; 32]);
        let req = TargetedRepairRequest::new(id)
            .with_esis(vec![0, 1, 2])
            .with_preferred_sources(vec![10, 20])
            .with_excluded_sources(vec![30]);

        assert_eq!(req.esis, vec![0, 1, 2]);
        assert_eq!(req.preferred_sources, vec![10, 20]);
        assert_eq!(req.excluded_sources, vec![30]);
    }

    #[test]
    fn targeted_repair_request_serde_json_roundtrip() {
        let req = TargetedRepairRequest::new(ObjectId::from_bytes([3; 32]))
            .with_esis(vec![5, 10, 15])
            .with_preferred_sources(vec![100])
            .with_excluded_sources(vec![200, 300]);

        let json = serde_json::to_string(&req).unwrap();
        let rt: TargetedRepairRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.esis, vec![5, 10, 15]);
        assert_eq!(rt.preferred_sources, vec![100]);
        assert_eq!(rt.excluded_sources, vec![200, 300]);
    }

    #[test]
    fn targeted_repair_request_debug() {
        let req = TargetedRepairRequest::new(ObjectId::from_bytes([4; 32]));
        let dbg = format!("{req:?}");
        assert!(dbg.contains("TargetedRepairRequest"));
    }

    #[test]
    fn targeted_repair_request_clone() {
        let req = TargetedRepairRequest::new(ObjectId::from_bytes([5; 32])).with_esis(vec![1, 2]);
        let cloned = req.clone();
        assert_eq!(req.object_id, cloned.object_id);
        assert_eq!(req.esis, cloned.esis);
    }

    // --- RepairPlan serde ---

    #[test]
    fn repair_plan_serde_roundtrip() {
        let plan = RepairPlan {
            zone_id: test_zone_id(),
            cycle_id: 7,
            policy_targets: RepairPolicyTargets::default(),
            object_count_tracked: 10,
            object_count_below_target: 3,
            slo_metrics: RepairSloMetrics::default(),
            budget: RepairCycleBudget::default(),
            budget_used: RepairCycleUsage::default(),
            actions: vec![],
            deferred: vec![],
        };
        let json = serde_json::to_string(&plan).unwrap();
        let rt: RepairPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.cycle_id, 7);
        assert_eq!(rt.object_count_tracked, 10);
        assert_eq!(rt.object_count_below_target, 3);
    }

    // --- RepairReasonCode additional tests ---

    #[test]
    fn repair_reason_code_as_str_all_variants() {
        assert_eq!(
            RepairReasonCode::PolicySloDeficit.as_str(),
            "repair.policy_slo_deficit"
        );
        assert_eq!(
            RepairReasonCode::DiversityDeficit.as_str(),
            "repair.diversity_deficit"
        );
        assert_eq!(
            RepairReasonCode::HotObjectPreStage.as_str(),
            "repair.hot_object_pre_stage"
        );
        assert_eq!(
            RepairReasonCode::DeferredCycleBudget.as_str(),
            "repair.deferred_cycle_budget"
        );
        assert_eq!(
            RepairReasonCode::DeferredPowerBudget.as_str(),
            "repair.deferred_power_budget"
        );
    }

    #[test]
    fn repair_reason_code_display_matches_as_str() {
        for code in [
            RepairReasonCode::PolicySloDeficit,
            RepairReasonCode::DiversityDeficit,
            RepairReasonCode::HotObjectPreStage,
            RepairReasonCode::DeferredCycleBudget,
            RepairReasonCode::DeferredPowerBudget,
        ] {
            assert_eq!(code.to_string(), code.as_str());
        }
    }

    #[test]
    fn repair_reason_code_copy_eq() {
        let a = RepairReasonCode::PolicySloDeficit;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, RepairReasonCode::DiversityDeficit);
    }

    // --- RepairCycleBudget tests ---

    #[test]
    fn repair_cycle_budget_default_is_unlimited() {
        let budget = RepairCycleBudget::default();
        assert_eq!(budget.max_repairs, usize::MAX);
        assert_eq!(budget.max_bytes, u64::MAX);
        assert_eq!(budget.max_decode_ms, u32::MAX);
    }

    #[test]
    fn repair_cycle_budget_serde_json_rt() {
        let budget = RepairCycleBudget {
            max_repairs: 42,
            max_bytes: 1024,
            max_decode_ms: 500,
        };
        let json = serde_json::to_string(&budget).unwrap();
        let rt: RepairCycleBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.max_repairs, 42);
        assert_eq!(rt.max_bytes, 1024);
        assert_eq!(rt.max_decode_ms, 500);
    }

    #[test]
    fn repair_cycle_budget_copy_eq() {
        let a = RepairCycleBudget {
            max_repairs: 10,
            max_bytes: 100,
            max_decode_ms: 50,
        };
        let b = a;
        assert_eq!(a, b);
    }

    // --- RepairCycleUsage tests ---

    #[test]
    fn repair_cycle_usage_default_all_zero() {
        let usage = RepairCycleUsage::default();
        assert_eq!(usage.repairs, 0);
        assert_eq!(usage.bytes, 0);
        assert_eq!(usage.decode_ms, 0);
    }

    #[test]
    fn repair_cycle_usage_serde_json_rt() {
        let usage = RepairCycleUsage {
            repairs: 5,
            bytes: 2048,
            decode_ms: 100,
        };
        let json = serde_json::to_string(&usage).unwrap();
        let rt: RepairCycleUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.repairs, 5);
        assert_eq!(rt.bytes, 2048);
        assert_eq!(rt.decode_ms, 100);
    }

    // --- RepairPolicyTargets tests ---

    #[test]
    fn repair_policy_targets_default_values() {
        let targets = RepairPolicyTargets::default();
        assert_eq!(targets.target_coverage_bps, 0);
        assert_eq!(targets.min_source_diversity, 0);
        assert_eq!(targets.max_node_fraction_bps, 10_000);
    }

    #[test]
    fn repair_policy_targets_serde_json_rt() {
        let targets = RepairPolicyTargets {
            target_coverage_bps: 15_000,
            min_source_diversity: 3,
            max_node_fraction_bps: 5000,
        };
        let json = serde_json::to_string(&targets).unwrap();
        let rt: RepairPolicyTargets = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.target_coverage_bps, 15_000);
        assert_eq!(rt.min_source_diversity, 3);
        assert_eq!(rt.max_node_fraction_bps, 5000);
    }

    // --- RepairPlanningOptions tests ---

    #[test]
    fn repair_planning_options_default_values() {
        let opts = RepairPlanningOptions::default();
        assert_eq!(opts.cycle_id, 0);
        assert!(opts.hot_objects.is_empty());
        assert!(!opts.power_saver);
        assert!(!opts.mains_power);
        assert!(!opts.metered_network);
        assert_eq!(opts.bandwidth_estimate_kbps, 0);
        assert_eq!(opts.derp_penalty_bps, 0);
    }

    #[test]
    fn repair_planning_options_serde_json_rt() {
        let opts = RepairPlanningOptions {
            cycle_id: 42,
            budget: RepairCycleBudget::default(),
            hot_objects: vec![ObjectId::from_bytes([1; 32])],
            hot_object_min_coverage_bps: 20_000,
            power_saver: true,
            mains_power: true,
            metered_network: true,
            bandwidth_estimate_kbps: 25_000,
            derp_penalty_bps: 500,
        };
        let json = serde_json::to_string(&opts).unwrap();
        let rt: RepairPlanningOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.cycle_id, 42);
        assert!(rt.power_saver);
        assert!(rt.mains_power);
        assert!(rt.metered_network);
        assert_eq!(rt.bandwidth_estimate_kbps, 25_000);
        assert_eq!(rt.derp_penalty_bps, 500);
        assert_eq!(rt.hot_objects.len(), 1);
    }

    // --- RepairStats tests ---

    #[test]
    fn repair_stats_default_fields_zero() {
        let stats = RepairStats::default();
        assert_eq!(stats.repairs_attempted, 0);
        assert_eq!(stats.repairs_succeeded, 0);
        assert_eq!(stats.repairs_failed, 0);
        assert_eq!(stats.symbols_added, 0);
        assert_eq!(stats.queue_depth, 0);
        assert_eq!(stats.rate_limited, 0);
    }

    #[test]
    fn repair_stats_serde_json_all_fields_rt() {
        let stats = RepairStats {
            repairs_attempted: 100,
            repairs_succeeded: 80,
            repairs_failed: 20,
            symbols_added: 500,
            queue_depth: 5,
            rate_limited: 3,
            power_deferred: 0,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let rt: RepairStats = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.repairs_attempted, 100);
        assert_eq!(rt.repairs_succeeded, 80);
        assert_eq!(rt.rate_limited, 3);
    }

    // --- RepairResult tests ---

    #[test]
    fn repair_result_success_serde() {
        let result = RepairResult {
            object_id: ObjectId::from_bytes([1; 32]),
            success: true,
            new_coverage_bps: 12_000,
            symbols_added: 5,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let rt: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(rt.success);
        assert_eq!(rt.new_coverage_bps, 12_000);
        assert!(rt.error.is_none());
    }

    #[test]
    fn repair_result_failure_serde() {
        let result = RepairResult {
            object_id: ObjectId::from_bytes([2; 32]),
            success: false,
            new_coverage_bps: 3000,
            symbols_added: 0,
            error: Some("decode failed".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let rt: RepairResult = serde_json::from_str(&json).unwrap();
        assert!(!rt.success);
        assert_eq!(rt.error.as_deref(), Some("decode failed"));
    }

    // --- Acceptance: evaluate_zone queues repairs for deficit objects ---

    #[fcp_async_core::runtime::test]
    async fn evaluate_zone_queues_repairs_for_objects_below_coverage() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let zone = test_zone_id();
        let oid = ObjectId::from_bytes([10; 32]);
        // 5 of 10 source symbols → 50% coverage, unavailable
        seed_planner_object(&store, oid, 10, 5, 64, &[1]).await;

        let mut policies = HashMap::new();
        policies.insert(oid, test_policy());

        let controller = RepairController::new(RepairControllerConfig::default());
        controller.evaluate_zone(&zone, &store, &policies).await;

        let stats = controller.stats();
        assert_eq!(
            stats.queue_depth, 1,
            "one object below target should be queued"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn evaluate_zone_skips_healthy_objects() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let zone = test_zone_id();
        let oid = ObjectId::from_bytes([11; 32]);
        // 10 of 10 source symbols → 100% coverage, available
        seed_planner_object(&store, oid, 10, 10, 64, &[1]).await;

        let mut policies = HashMap::new();
        policies.insert(oid, test_policy());

        let controller = RepairController::new(RepairControllerConfig::default());
        controller.evaluate_zone(&zone, &store, &policies).await;

        let stats = controller.stats();
        assert_eq!(stats.queue_depth, 0, "healthy objects should not be queued");
    }

    #[fcp_async_core::runtime::test]
    async fn evaluate_zone_refresh_preserves_global_priority_order() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let current_zone = test_zone_id();
        let other_zone: ZoneId = "z:other".parse().unwrap();
        let current_object = ObjectId::from_bytes([12; 32]);
        let other_object = ObjectId::from_bytes([13; 32]);

        // 5 of 10 source symbols -> refreshed request should become unavailable/high priority.
        seed_planner_object(&store, current_object, 10, 5, 64, &[1]).await;

        let mut policies = HashMap::new();
        policies.insert(current_object, test_policy());

        let controller = RepairController::new(RepairControllerConfig::default());
        controller.queue_repair(RepairRequest {
            object_id: other_object,
            zone_id: other_zone.clone(),
            coverage: test_coverage(9, 10),
            policy: test_policy(),
            priority: 10,
        });
        controller.queue_repair(RepairRequest {
            object_id: current_object,
            zone_id: current_zone.clone(),
            coverage: test_coverage(9, 10),
            policy: test_policy(),
            priority: 10,
        });

        let report = controller
            .evaluate_zone_with_report(&current_zone, &store, &policies)
            .await;
        assert_eq!(report.queue_depth_before, 2);
        assert_eq!(report.queue_depth_after, 2);
        assert_eq!(report.pruned_stale_requests, 0);
        assert_eq!(report.decisions.len(), 1);
        assert_eq!(report.decisions[0].action, RepairQueueAction::Refresh);

        let first = controller.next_repair().expect("refreshed request first");
        assert_eq!(first.object_id, current_object);
        assert!(first.priority > 10);

        let second = controller.next_repair().expect("other-zone request second");
        assert_eq!(second.object_id, other_object);
        assert_eq!(second.zone_id, other_zone);
    }

    #[fcp_async_core::runtime::test]
    async fn evaluate_zone_queues_multiple_deficit_objects_by_priority() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let zone = test_zone_id();
        let oid_a = ObjectId::from_bytes([20; 32]);
        let oid_b = ObjectId::from_bytes([21; 32]);
        // oid_a: 3/10 = 30% coverage (worse deficit)
        seed_planner_object(&store, oid_a, 10, 3, 64, &[1]).await;
        // oid_b: 7/10 = 70% coverage (still below 100%)
        seed_planner_object(&store, oid_b, 10, 7, 64, &[1]).await;

        let mut policies = HashMap::new();
        policies.insert(oid_a, test_policy());
        policies.insert(oid_b, test_policy());

        let controller = RepairController::new(RepairControllerConfig::default());
        controller.evaluate_zone(&zone, &store, &policies).await;

        let stats = controller.stats();
        assert_eq!(
            stats.queue_depth, 2,
            "both deficit objects should be queued"
        );

        // Higher priority item (worse coverage) should be dequeued first
        let first = controller.next_repair().unwrap();
        let second = controller.next_repair().unwrap();
        assert!(
            first.priority >= second.priority,
            "worse deficit object should have higher or equal priority"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn evaluate_zone_with_report_exposes_queue_refresh_and_policy_removal() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let zone = test_zone_id();
        let oid = ObjectId::from_bytes([24; 32]);
        seed_planner_object(&store, oid, 10, 7, 64, &[1]).await;

        let mut policies = HashMap::new();
        policies.insert(oid, test_policy());

        let controller = RepairController::new(RepairControllerConfig::default());

        let first = controller
            .evaluate_zone_with_report(&zone, &store, &policies)
            .await;
        let first_decision = first
            .decisions
            .iter()
            .find(|decision| decision.object_id == oid)
            .expect("deficit object should be reported");
        assert_eq!(first.queue_depth_before, 0);
        assert_eq!(first.queue_depth_after, 1);
        assert_eq!(first.pruned_stale_requests, 0);
        assert_eq!(first_decision.action, RepairQueueAction::Queue);
        assert_eq!(
            first_decision.reason_code,
            RepairEvaluationReasonCode::PolicySloDeficit
        );
        assert_eq!(first_decision.coverage_bps, Some(7000));
        assert_eq!(first_decision.distinct_nodes, Some(1));
        assert_eq!(first_decision.priority, Some(1030));

        let second = controller
            .evaluate_zone_with_report(&zone, &store, &policies)
            .await;
        let second_decision = second
            .decisions
            .iter()
            .find(|decision| decision.object_id == oid)
            .expect("refreshed object should be reported");
        assert_eq!(second.queue_depth_before, 1);
        assert_eq!(second.queue_depth_after, 1);
        assert_eq!(second_decision.action, RepairQueueAction::Refresh);
        assert_eq!(
            second_decision.reason_code,
            RepairEvaluationReasonCode::PolicySloDeficit
        );
        assert_eq!(second_decision.priority, Some(1030));

        let third = controller
            .evaluate_zone_with_report(&zone, &store, &HashMap::new())
            .await;
        let third_decision = third
            .decisions
            .iter()
            .find(|decision| decision.object_id == oid)
            .expect("policy removal should be reported");
        assert_eq!(third.queue_depth_before, 1);
        assert_eq!(third.queue_depth_after, 0);
        assert_eq!(third_decision.action, RepairQueueAction::Remove);
        assert_eq!(
            third_decision.reason_code,
            RepairEvaluationReasonCode::MissingPolicy
        );
        assert_eq!(third_decision.coverage_bps, None);
        assert_eq!(third_decision.priority, None);
    }

    #[fcp_async_core::runtime::test]
    async fn evaluate_zone_with_report_prunes_missing_object_requests() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let zone = test_zone_id();
        let oid = ObjectId::from_bytes([0x93; 32]);
        seed_planner_object(&store, oid, 10, 5, 64, &[1]).await;

        let policies = HashMap::from([(oid, test_policy())]);
        let controller = RepairController::new(RepairControllerConfig::default());
        let initial = controller
            .evaluate_zone_with_report(&zone, &store, &policies)
            .await;
        assert_eq!(initial.queue_depth_after, 1);

        store.delete_object(&oid).await.unwrap();

        let removed = controller
            .evaluate_zone_with_report(&zone, &store, &policies)
            .await;
        assert_eq!(removed.queue_depth_before, 1);
        assert_eq!(removed.queue_depth_after, 0);
        assert_eq!(removed.pruned_stale_requests, 1);
        assert!(removed.decisions.is_empty());
        assert_eq!(controller.queue_depth(), 0);
    }

    // --- Acceptance: plan_zone produces actionable plans ---

    #[fcp_async_core::runtime::test]
    async fn plan_zone_produces_actions_for_deficit_objects() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let zone = test_zone_id();
        let oid = ObjectId::from_bytes([30; 32]);
        seed_planner_object(&store, oid, 10, 5, 64, &[1]).await;

        let mut policies = HashMap::new();
        policies.insert(oid, test_policy());

        let controller = RepairController::new(RepairControllerConfig::default());
        let plan = controller
            .plan_zone(&zone, &store, &policies, &planner_options(1))
            .await;

        assert_eq!(plan.zone_id, zone);
        assert_eq!(plan.object_count_tracked, 1);
        assert!(
            plan.object_count_below_target > 0,
            "below-target count must be positive"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn plan_zone_empty_when_all_objects_healthy() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let zone = test_zone_id();
        let oid = ObjectId::from_bytes([31; 32]);
        seed_planner_object(&store, oid, 10, 10, 64, &[1]).await;

        let mut policies = HashMap::new();
        policies.insert(oid, test_policy());

        let controller = RepairController::new(RepairControllerConfig::default());
        let plan = controller
            .plan_zone(&zone, &store, &policies, &planner_options(1))
            .await;

        assert_eq!(plan.object_count_below_target, 0);
        assert!(
            plan.actions.is_empty(),
            "no actions needed for healthy objects"
        );
    }

    // --- Acceptance: repair loop convergence ---

    #[test]
    fn repair_queue_drains_as_results_recorded() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 1000,
            ..Default::default()
        });

        // Queue 5 repair requests
        for i in 0u8..5 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([i; 32]),
                zone_id: test_zone_id(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: u32::from(i),
            });
        }
        assert_eq!(controller.stats().queue_depth, 5);

        // Process all and record success
        let mut processed = 0;
        while let Some(req) = controller.next_repair() {
            controller.record_result(&RepairResult {
                object_id: req.object_id,
                success: true,
                new_coverage_bps: 10_000,
                symbols_added: 5,
                error: None,
            });
            processed += 1;
        }

        assert_eq!(processed, 5, "all queued items should be processed");
        assert_eq!(
            controller.stats().queue_depth,
            0,
            "queue should drain to zero"
        );
        assert_eq!(controller.stats().repairs_succeeded, 5);
        assert_eq!(controller.stats().symbols_added, 25);
    }

    #[test]
    fn repair_queue_tracks_failures_separately() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 1000,
            ..Default::default()
        });

        controller.queue_repair(RepairRequest {
            object_id: ObjectId::from_bytes([40; 32]),
            zone_id: test_zone_id(),
            coverage: test_coverage(2, 10),
            policy: test_policy(),
            priority: 100,
        });

        let req = controller.next_repair().unwrap();
        controller.record_result(&RepairResult {
            object_id: req.object_id,
            success: false,
            new_coverage_bps: 2000,
            symbols_added: 0,
            error: Some("decode failed".into()),
        });

        let stats = controller.stats();
        assert_eq!(stats.repairs_failed, 1);
        assert_eq!(stats.repairs_succeeded, 0);
        assert_eq!(stats.symbols_added, 0);
    }

    // --- Acceptance: concurrent permit limits ---

    #[test]
    fn concurrent_permits_respect_limit() {
        let controller = RepairController::new(RepairControllerConfig {
            max_concurrent_repairs: 2,
            ..Default::default()
        });

        let p1 = controller.try_acquire_permit();
        let p2 = controller.try_acquire_permit();
        let p3 = controller.try_acquire_permit();

        assert!(p1.is_some(), "first permit should succeed");
        assert!(p2.is_some(), "second permit should succeed");
        assert!(p3.is_none(), "third permit should be blocked at limit 2");

        // Drop first permit, third should now succeed
        drop(p1);
        let p4 = controller.try_acquire_permit();
        assert!(p4.is_some(), "permit should be available after drop");
    }

    // --- Acceptance: rate limiter ---

    #[test]
    fn rate_limiter_blocks_excessive_repairs() {
        let controller = RepairController::new(RepairControllerConfig {
            max_repairs_per_minute: 2,
            ..Default::default()
        });

        for i in 0u8..5 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([50 + i; 32]),
                zone_id: test_zone_id(),
                coverage: test_coverage(3, 10),
                policy: test_policy(),
                priority: u32::from(i),
            });
        }

        // Should get exactly 2 before rate limit kicks in
        let r1 = controller.next_repair();
        let r2 = controller.next_repair();
        let r3 = controller.next_repair();

        assert!(r1.is_some(), "first repair should pass rate limit");
        assert!(r2.is_some(), "second repair should pass rate limit");
        assert!(r3.is_none(), "third repair should be rate limited");
        assert!(
            controller.stats().rate_limited > 0,
            "rate limit counter should increment"
        );
    }

    // --- Acceptance: deduplication in queue ---

    #[test]
    fn duplicate_queue_entries_are_rejected() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let oid = ObjectId::from_bytes([60; 32]);

        controller.queue_repair(RepairRequest {
            object_id: oid,
            zone_id: test_zone_id(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 10,
        });
        controller.queue_repair(RepairRequest {
            object_id: oid,
            zone_id: test_zone_id(),
            coverage: test_coverage(3, 10),
            policy: test_policy(),
            priority: 20,
        });

        assert_eq!(
            controller.stats().queue_depth,
            1,
            "duplicate object should not be queued twice"
        );
    }

    // --- Acceptance: clear_queue resets state ---

    #[test]
    fn clear_queue_empties_and_resets_depth() {
        let controller = RepairController::new(RepairControllerConfig::default());

        for i in 0u8..3 {
            controller.queue_repair(RepairRequest {
                object_id: ObjectId::from_bytes([70 + i; 32]),
                zone_id: test_zone_id(),
                coverage: test_coverage(5, 10),
                policy: test_policy(),
                priority: u32::from(i),
            });
        }
        assert_eq!(controller.stats().queue_depth, 3);

        controller.clear_queue();
        assert_eq!(controller.stats().queue_depth, 0);
        assert!(controller.next_repair().is_none());
    }

    // --- Acceptance: diversity deficit triggers repair ---

    #[fcp_async_core::runtime::test]
    async fn evaluate_zone_detects_diversity_deficit() {
        let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
        let zone = test_zone_id();
        let oid = ObjectId::from_bytes([80; 32]);
        // All 10 symbols on one node — coverage is 100% but diversity is 1 (policy needs 3)
        seed_planner_object(&store, oid, 10, 10, 64, &[1]).await;

        let mut policies = HashMap::new();
        let mut policy = test_policy();
        policy.min_source_diversity = 3;
        policies.insert(oid, policy);

        let controller = RepairController::new(RepairControllerConfig::default());
        controller.evaluate_zone(&zone, &store, &policies).await;

        // The object is available (100% coverage) but fails source-diversity policy
        // (1 node vs 3 required), so needs_repair returns true and queues it.
        let stats = controller.stats();
        assert_eq!(
            stats.queue_depth, 1,
            "diversity-deficit object should be queued for repair"
        );
    }

    // ── Starvation-prevention: aging under heavy churn ──

    /// Regression: under heavy churn a high-priority item stream starves
    /// low-priority repairs indefinitely. Aging must lift a persistently-
    /// deferred low-priority item above fresh high-priority arrivals
    /// after enough cycles. Without aging, the low-priority item sits
    /// at the back of the queue forever.
    #[test]
    fn aging_lifts_persistently_deferred_low_priority_above_fresh_high_priority() {
        use crate::coverage::CoverageEvaluation;

        let controller = RepairController::new(RepairControllerConfig::default());
        let zone = test_zone_id();
        let low = ObjectId::from_bytes([1; 32]);
        let fresh_high = ObjectId::from_bytes([2; 32]);

        // Construct a CoverageEvaluation suitable for RepairRequest; the
        // exact coverage values don't affect queue ordering — only
        // `priority` and aging do.
        let coverage = CoverageEvaluation::from_distribution(
            low,
            &crate::coverage::SymbolDistribution::new(1),
        );

        let policy = test_policy();

        // Seed: one low-priority request for `low`. This becomes the
        // "persistently queued but never drained" item.
        controller.queue_repair(RepairRequest {
            object_id: low,
            zone_id: zone.clone(),
            coverage: coverage.clone(),
            policy: policy.clone(),
            priority: 500,
        });

        // Simulate many evaluate cycles — each cycle re-upserts the
        // same low-priority item (evaluate_zone keeps noticing it's
        // still below target). Each refresh bumps its deferral_count.
        // After enough cycles the aging boost should exceed the
        // fresh high-priority arrivals' delta (1000 - 500 = 500, so
        // 500 / AGING_BOOST_PER_DEFERRAL = 5 cycles of deferral).
        for _ in 0..10 {
            controller.queue_repair(RepairRequest {
                object_id: low,
                zone_id: zone.clone(),
                coverage: coverage.clone(),
                policy: policy.clone(),
                priority: 500,
            });
        }

        // Now a fresh high-priority arrival appears (first upsert, so
        // deferral_count=0, no aging boost).
        controller.queue_repair(RepairRequest {
            object_id: fresh_high,
            zone_id: zone,
            coverage,
            policy,
            priority: 1000,
        });

        // Aging expectation: after 10 refreshes the low-priority item
        // has effective priority 500 + 10*100 = 1500, beating the
        // fresh high's 1000. next_repair must dequeue `low` first.
        let first = controller
            .next_repair()
            .expect("queue is non-empty")
            .object_id;
        assert_eq!(
            first, low,
            "aging must lift a persistently-deferred low-priority item \
             above fresh high-priority arrivals — without this, heavy churn \
             starves low-priority repairs forever",
        );
    }

    /// A fresh arrival at a higher priority than a never-deferred
    /// sibling must STILL win — aging is a tie-breaker over time,
    /// not a global priority inversion. This guards against the fix
    /// going too far and making the queue FIFO-ish regardless of
    /// priority.
    #[test]
    fn aging_does_not_invert_priority_on_fresh_inputs() {
        use crate::coverage::CoverageEvaluation;

        let controller = RepairController::new(RepairControllerConfig::default());
        let zone = test_zone_id();
        let low = ObjectId::from_bytes([1; 32]);
        let high = ObjectId::from_bytes([2; 32]);

        let coverage = CoverageEvaluation::from_distribution(
            low,
            &crate::coverage::SymbolDistribution::new(1),
        );
        let policy = test_policy();

        // Both are fresh upserts (deferral_count=0 for both). Priority
        // alone must decide the order.
        controller.queue_repair(RepairRequest {
            object_id: low,
            zone_id: zone.clone(),
            coverage: coverage.clone(),
            policy: policy.clone(),
            priority: 500,
        });
        controller.queue_repair(RepairRequest {
            object_id: high,
            zone_id: zone,
            coverage,
            policy,
            priority: 1000,
        });

        let first = controller
            .next_repair()
            .expect("queue is non-empty")
            .object_id;
        assert_eq!(
            first, high,
            "fresh high-priority arrival must win against fresh low-priority \
             sibling — priority still dominates when no aging has accumulated",
        );
    }

    // ── Power-aware deferral (bead flywheel_connectors-qyv8n) ───────────
    //
    // The repair controller MUST defer non-critical repair dequeues when
    // the runtime has reported that the host is on battery below
    // `RepairControllerConfig::battery_defer_threshold_percent`. The
    // default threshold is 20%, matching `fcp_mesh::device::DeviceProfile::
    // is_low_battery`. In-flight repairs are NOT interrupted — only
    // newly-dequeued repairs are gated.
    //
    // These two tests pin both sides of the gate:
    //   (a) AC power (or battery ≥ threshold) → dequeue proceeds as normal
    //   (b) Battery below threshold → dequeue returns None, the
    //       `power_deferred` stat increments, and the queue is NOT
    //       drained (next AC transition resumes the backlog).

    fn queue_one_repair(controller: &RepairController) -> ObjectId {
        let object_id = ObjectId::from_bytes([0xA5; 32]);
        controller.queue_repair(RepairRequest {
            object_id,
            zone_id: test_zone_id(),
            coverage: test_coverage(5, 10),
            policy: test_policy(),
            priority: 100,
        });
        object_id
    }

    #[test]
    fn next_repair_dequeues_normally_on_ac_power() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let queued = queue_one_repair(&controller);

        // Default power state is AC — no deferral.
        assert_eq!(controller.power_state(), PowerState::Ac);

        let request = controller
            .next_repair()
            .expect("AC power must not defer the dequeue");
        assert_eq!(request.object_id, queued);
        let stats = controller.stats();
        assert_eq!(
            stats.power_deferred, 0,
            "AC dequeue must not bump power_deferred"
        );
    }

    #[test]
    fn next_repair_accepts_battery_at_or_above_threshold() {
        // battery_defer_threshold_percent defaults to 20. Battery at
        // exactly 20% must NOT defer — the threshold is strict-less-than.
        let controller = RepairController::new(RepairControllerConfig::default());
        let queued = queue_one_repair(&controller);
        controller.set_power_state(PowerState::Battery { percent: 20 });

        let request = controller
            .next_repair()
            .expect("battery at threshold must not defer");
        assert_eq!(request.object_id, queued);
        assert_eq!(controller.stats().power_deferred, 0);
    }

    #[test]
    fn next_repair_defers_on_low_battery_and_keeps_queue_intact() {
        let controller = RepairController::new(RepairControllerConfig::default());
        let queued = queue_one_repair(&controller);

        // Report a critically low battery — 5% is well below the 20%
        // default threshold.
        controller.set_power_state(PowerState::Battery { percent: 5 });

        let result = controller.next_repair();
        assert!(
            result.is_none(),
            "low-battery dequeue must return None (got {result:?})"
        );

        // Power-deferred stat must bump by exactly 1.
        assert_eq!(
            controller.stats().power_deferred,
            1,
            "low-battery deferral must increment the power_deferred stat"
        );
        // And the rate-limit stat must NOT bump — the battery gate
        // runs BEFORE the rate-limit token is consumed so a deferred
        // cycle does not burn rate-limit budget.
        assert_eq!(
            controller.stats().rate_limited,
            0,
            "battery deferral must not consume a rate-limit token"
        );

        // Queue must NOT have been drained. Transition back to AC
        // and verify the same request is still dequeue-able.
        controller.set_power_state(PowerState::Ac);
        let request = controller
            .next_repair()
            .expect("after AC transition, deferred repair must be dequeued");
        assert_eq!(
            request.object_id, queued,
            "AC-resumed dequeue must surface the previously-deferred repair"
        );
    }

    #[test]
    fn power_state_helpers_behave_as_expected() {
        assert!(!PowerState::Ac.is_low_battery(20));
        assert!(PowerState::Battery { percent: 5 }.is_low_battery(20));
        assert!(!PowerState::Battery { percent: 20 }.is_low_battery(20));
        assert!(!PowerState::Battery { percent: 95 }.is_low_battery(20));
        // Threshold 0 → NEVER defer, even on battery.
        assert!(!PowerState::Battery { percent: 1 }.is_low_battery(0));
        // Threshold 101 → ALWAYS defer on any battery state.
        assert!(PowerState::Battery { percent: 100 }.is_low_battery(101));
    }
}
