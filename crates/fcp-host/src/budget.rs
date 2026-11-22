//! Usage budget tracking and enforcement helpers.
//!
//! Tracks per-zone usage against configured budget policies and surfaces
//! snapshots suitable for CLI/operator reporting.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use fcp_async_core::sync::RwLock;
use fcp_kernel::{
    BudgetEnforcement, BudgetStatus, FcpError, LifecycleError, UsageBudgetPolicy,
    UsageBudgetSnapshot, UsageBudgetUsage, UsageMetric, UsageMetricKind,
};
use fcp_policy::ZoneId;
use serde::{Deserialize, Serialize};

use crate::{
    HostAdminStateStore, HostError, HostResult, InvocationTicket, PolicyEngine, PreflightRequest,
    PreflightResponse,
};

const MAX_TRACKED_BUDGET_ZONES: usize = 4096;

/// Header carrying host backpressure reason for connector clients.
pub const FCP_BACKPRESSURE_REASON_HEADER: &str = "X-FCP-Backpressure-Reason";
/// Header carrying the host-computed retry floor in whole seconds.
pub const FCP_BACKPRESSURE_RETRY_AFTER_HEADER: &str = "X-FCP-Backpressure-Retry-After";
/// Canonical host backpressure reason for exhausted zone budgets.
pub const FCP_BACKPRESSURE_BUDGET_EXHAUSTED: &str = "budget-exhausted";

/// Request payload for reporting current budget state.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BudgetReportRequest {
    /// Optional zone filter. When omitted, report every configured zone.
    #[serde(default)]
    pub zone_id: Option<String>,
}

/// Response payload for budget reporting.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BudgetReportResponse {
    /// Stable schema version for the report shape.
    pub schema_version: String,
    /// Timestamp when the report was generated.
    pub generated_at: DateTime<Utc>,
    /// Current snapshots for each matching zone.
    pub zones: Vec<UsageBudgetSnapshot>,
}

impl BudgetReportResponse {
    /// Schema version for budget report payloads.
    pub const SCHEMA_VERSION: &'static str = "1.0.0";
}

/// Action to take when a budget is evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAction {
    /// Within budgets.
    Allow,
    /// Exceeded budget but warn-only.
    Warn,
    /// Exceeded budget and deny operations.
    Deny,
}

/// Result of evaluating usage against budgets.
#[derive(Debug, Clone)]
pub struct BudgetEvaluation {
    /// Action to take for the operation.
    pub action: BudgetAction,
    /// Snapshot of budget usage after applying metrics.
    pub snapshot: UsageBudgetSnapshot,
}

/// Connector-visible signal emitted when the host refuses work due to budget exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetBackpressureSignal {
    /// Canonical reason value for [`FCP_BACKPRESSURE_REASON_HEADER`].
    pub reason: &'static str,
    /// Retry floor for [`FCP_BACKPRESSURE_RETRY_AFTER_HEADER`].
    pub retry_after_seconds: u64,
}

/// Return the tightest remaining budget from a zone snapshot.
#[must_use]
pub fn budget_remaining_floor(snapshot: &UsageBudgetSnapshot) -> Option<u64> {
    snapshot.budgets.iter().map(|budget| budget.remaining).min()
}

/// Whether a zone snapshot should prevent new work from being routed there.
#[must_use]
pub fn budget_snapshot_blocks_routing(snapshot: &UsageBudgetSnapshot) -> bool {
    snapshot.enforcement == BudgetEnforcement::Deny
        && snapshot
            .budgets
            .iter()
            .any(|budget| budget.status == BudgetStatus::Exceeded || budget.remaining == 0)
}

impl BudgetEvaluation {
    /// Convert a denial into an FCP error.
    #[must_use]
    pub fn to_error(&self) -> Option<FcpError> {
        if self.action != BudgetAction::Deny {
            return None;
        }

        let exceeded = self
            .snapshot
            .budgets
            .iter()
            .find(|b| b.status == BudgetStatus::Exceeded)?;
        let window_seconds = exceeded
            .window_resets_at
            .saturating_sub(exceeded.window_started_at);

        Some(FcpError::BudgetExceeded {
            metric: exceeded.metric,
            used: exceeded.used,
            limit: exceeded.limit,
            window_seconds,
        })
    }

    /// Return connector-facing backpressure metadata for denied budget exhaustion.
    #[must_use]
    pub fn backpressure_signal(&self) -> Option<BudgetBackpressureSignal> {
        if self.action != BudgetAction::Deny {
            return None;
        }

        let retry_after_seconds = self
            .snapshot
            .budgets
            .iter()
            .filter(|b| b.status == BudgetStatus::Exceeded)
            .map(|b| b.window_resets_at.saturating_sub(self.snapshot.updated_at))
            .max()?;

        Some(BudgetBackpressureSignal {
            reason: FCP_BACKPRESSURE_BUDGET_EXHAUSTED,
            retry_after_seconds,
        })
    }
}

/// Tracks usage per zone and enforces budget policies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetTracker {
    zones: HashMap<ZoneId, ZoneBudgetState>,
    #[serde(default)]
    observed_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneBudgetState {
    metrics: HashMap<UsageMetricKind, MetricWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricWindow {
    window_seconds: u64,
    window_started_at: u64,
    used: u64,
}

impl BudgetTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record usage metrics for a zone and evaluate budgets.
    #[must_use]
    pub fn record_usage(
        &mut self,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
        metrics: &[UsageMetric],
    ) -> BudgetEvaluation {
        self.record_usage_at(zone_id, policy, metrics, now_secs())
    }

    pub(crate) fn record_usage_at(
        &mut self,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
        metrics: &[UsageMetric],
        now: u64,
    ) -> BudgetEvaluation {
        let now = now.max(self.observed_at_unix_secs);
        self.observed_at_unix_secs = now;
        let usage_by_kind = aggregate_metrics(metrics);
        let state = self.zones.entry(zone_id.clone()).or_default();

        let mut entries = Vec::new();
        let mut exceeded = false;

        for budget in &policy.budgets {
            let used_delta = usage_by_kind.get(&budget.metric).copied().unwrap_or(0);
            let window = state
                .metrics
                .entry(budget.metric)
                .or_insert_with(|| MetricWindow::new(budget.window_seconds, now));
            window.roll_if_needed(now, budget.window_seconds);
            window.used = window.used.saturating_add(used_delta);

            let status = if window.used > budget.limit {
                exceeded = true;
                BudgetStatus::Exceeded
            } else {
                BudgetStatus::Ok
            };

            let remaining = budget.limit.saturating_sub(window.used);
            entries.push(UsageBudgetUsage {
                metric: budget.metric,
                used: window.used,
                limit: budget.limit,
                remaining,
                window_started_at: window.window_started_at,
                window_resets_at: window
                    .window_started_at
                    .saturating_add(window.window_seconds),
                status,
            });
        }

        let snapshot = UsageBudgetSnapshot {
            zone_id: zone_id.clone(),
            enforcement: policy.enforcement,
            budgets: entries,
            updated_at: now,
        };

        let action = match (exceeded, policy.enforcement) {
            (true, BudgetEnforcement::Deny) => {
                let exceeded_budgets: Vec<_> = snapshot
                    .budgets
                    .iter()
                    .filter(|b| b.status == BudgetStatus::Exceeded)
                    .collect();
                tracing::warn!(
                    zone_id = %zone_id,
                    action = "deny",
                    exceeded_count = exceeded_budgets.len(),
                    "budget exceeded"
                );
                for exceeded in exceeded_budgets {
                    tracing::debug!(
                        zone_id = %zone_id,
                        metric = ?exceeded.metric,
                        used = exceeded.used,
                        limit = exceeded.limit,
                        remaining = exceeded.remaining,
                        "budget limit exceeded"
                    );
                }
                BudgetAction::Deny
            }
            (true, BudgetEnforcement::Warn) => {
                let exceeded_budgets: Vec<_> = snapshot
                    .budgets
                    .iter()
                    .filter(|b| b.status == BudgetStatus::Exceeded)
                    .collect();
                tracing::warn!(
                    zone_id = %zone_id,
                    action = "warn",
                    exceeded_count = exceeded_budgets.len(),
                    "budget warning threshold exceeded"
                );
                for exceeded in exceeded_budgets {
                    tracing::debug!(
                        zone_id = %zone_id,
                        metric = ?exceeded.metric,
                        used = exceeded.used,
                        limit = exceeded.limit,
                        remaining = exceeded.remaining,
                        "budget limit exceeded"
                    );
                }
                BudgetAction::Warn
            }
            (false, _) => BudgetAction::Allow,
        };

        BudgetEvaluation { action, snapshot }
    }

    /// Get a snapshot of current usage for a zone without recording new usage.
    #[must_use]
    pub fn snapshot(
        &mut self,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
    ) -> UsageBudgetSnapshot {
        self.snapshot_at(zone_id, policy, now_secs())
    }

    pub(crate) fn snapshot_at(
        &mut self,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
        now: u64,
    ) -> UsageBudgetSnapshot {
        let now = now.max(self.observed_at_unix_secs);
        self.observed_at_unix_secs = now;
        let state = self.zones.entry(zone_id.clone()).or_default();

        let mut entries = Vec::new();
        for budget in &policy.budgets {
            let window = state
                .metrics
                .entry(budget.metric)
                .or_insert_with(|| MetricWindow::new(budget.window_seconds, now));
            window.roll_if_needed(now, budget.window_seconds);

            let status = if window.used > budget.limit {
                BudgetStatus::Exceeded
            } else {
                BudgetStatus::Ok
            };

            let remaining = budget.limit.saturating_sub(window.used);
            entries.push(UsageBudgetUsage {
                metric: budget.metric,
                used: window.used,
                limit: budget.limit,
                remaining,
                window_started_at: window.window_started_at,
                window_resets_at: window
                    .window_started_at
                    .saturating_add(window.window_seconds),
                status,
            });
        }

        UsageBudgetSnapshot {
            zone_id: zone_id.clone(),
            enforcement: policy.enforcement,
            budgets: entries,
            updated_at: now,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.zones.is_empty() && self.observed_at_unix_secs == 0
    }

    pub(crate) fn validate_persisted(&self) -> HostResult<()> {
        if self.zones.len() > MAX_TRACKED_BUDGET_ZONES
            || self.observed_at_unix_secs > i64::MAX as u64
            || self.zones.values().any(|zone| {
                zone.metrics.values().any(|window| {
                    window.window_seconds == 0
                        || window.window_started_at > self.observed_at_unix_secs
                })
            })
        {
            return Err(HostError::Internal(
                "persisted zone budget windows are inconsistent".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn check_capacity(&self, zone_id: &ZoneId) -> Result<(), LifecycleError> {
        if !self.zones.contains_key(zone_id) && self.zones.len() >= MAX_TRACKED_BUDGET_ZONES {
            return Err(invalid_budget("zone budget ledger capacity exhausted"));
        }
        Ok(())
    }

    /// Spend the next host invocation before dispatch, under the store's transaction.
    /// Other metrics remain observed post-outcome usage rather than estimates.
    pub(crate) fn reserve_request(
        &mut self,
        zone_id: &ZoneId,
        policy: &UsageBudgetPolicy,
        now: u64,
    ) -> Result<bool, LifecycleError> {
        validate_usage_budget_policy(policy)?;
        self.check_capacity(zone_id)?;
        let snapshot = self.snapshot_at(zone_id, policy, now);
        if policy.enforcement == BudgetEnforcement::Deny
            && snapshot.budgets.iter().any(|entry| {
                entry.status == BudgetStatus::Exceeded
                    || (entry.metric == UsageMetricKind::Requests && entry.used >= entry.limit)
            })
        {
            return Err(invalid_budget(
                "zone usage budget exhausted before invocation admission",
            ));
        }
        let reserved = policy
            .budgets
            .iter()
            .any(|entry| entry.metric == UsageMetricKind::Requests);
        if reserved {
            self.record_usage_at(zone_id, policy, &[UsageMetric::requests(1)], now);
        }
        Ok(reserved)
    }
}

pub(crate) fn validate_usage_budget_policy(
    policy: &UsageBudgetPolicy,
) -> Result<(), LifecycleError> {
    let mut metrics = std::collections::HashSet::new();
    if policy
        .budgets
        .iter()
        .any(|budget| budget.window_seconds == 0 || !metrics.insert(budget.metric))
    {
        return Err(invalid_budget(
            "zone budgets require positive windows and unique metrics",
        ));
    }
    Ok(())
}

fn invalid_budget(reason: &str) -> LifecycleError {
    LifecycleError::InvalidPolicy {
        reason: reason.to_owned(),
    }
}

/// Policy engine backed by the host's transactional usage ledger.
///
/// Live hosts share their lifecycle store with this engine so admission,
/// reports, and outcome accounting observe the same persisted windows.
pub struct BudgetPolicyEngine {
    store: Arc<HostAdminStateStore>,
    policies: RwLock<HashMap<ZoneId, UsageBudgetPolicy>>,
}

impl std::fmt::Debug for BudgetPolicyEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BudgetPolicyEngine")
            .finish_non_exhaustive()
    }
}

impl BudgetPolicyEngine {
    /// Validate an operator-supplied policy before publishing host configuration.
    ///
    /// # Errors
    /// Rejects zero-length windows and repeated metric limits.
    pub fn validate_policy(policy: &UsageBudgetPolicy) -> HostResult<()> {
        validate_usage_budget_policy(policy)
            .map_err(|error| HostError::InvalidFilter(error.to_string()))
    }

    /// Create an ephemeral budget engine with no policies configured.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an ephemeral budget engine with predefined policies.
    #[must_use]
    pub fn with_policies(policies: HashMap<ZoneId, UsageBudgetPolicy>) -> Self {
        Self::with_state_store(policies, Arc::new(HostAdminStateStore::new()))
    }

    /// Use the same store that commits invocation admission and finalization.
    ///
    /// Filesystem-backed stores retain usage across host restarts. An explicit
    /// memory store retains it only for that store's lifetime.
    #[must_use]
    pub fn with_state_store(
        policies: HashMap<ZoneId, UsageBudgetPolicy>,
        store: Arc<HostAdminStateStore>,
    ) -> Self {
        Self {
            store,
            policies: RwLock::new(policies),
        }
    }

    /// The shared ledger and invocation store used by this engine.
    #[must_use]
    pub fn state_store(&self) -> &Arc<HostAdminStateStore> {
        &self.store
    }

    /// Insert or update the budget policy for a zone.
    ///
    /// Invalid policies are refused when evaluated or charged; no budget
    /// window is reset merely by changing its limit or enforcement mode.
    pub async fn upsert_policy(&self, zone_id: ZoneId, policy: UsageBudgetPolicy) {
        let mut write = self.policies.write().await;
        write.insert(zone_id, policy);
    }

    /// Remove the budget policy for a zone without forgetting retained usage.
    pub async fn remove_policy(&self, zone_id: &ZoneId) -> Option<UsageBudgetPolicy> {
        let mut write = self.policies.write().await;
        write.remove(zone_id)
    }

    /// Clone the current trusted policy for atomic invocation admission.
    pub async fn policy_for_zone(&self, zone_id: &ZoneId) -> Option<UsageBudgetPolicy> {
        self.policies.read().await.get(zone_id).cloned()
    }

    /// Record observed usage outside an invocation's once-only settlement.
    ///
    /// # Errors
    ///
    /// Refuses invalid policies, full ledgers, or unavailable persistence.
    pub async fn record_usage(
        &self,
        zone_id: &ZoneId,
        metrics: &[UsageMetric],
    ) -> HostResult<Option<BudgetEvaluation>> {
        let Some(policy) = self.policy_for_zone(zone_id).await else {
            return Ok(None);
        };
        self.store
            .record_zone_budget_usage(zone_id, &policy, metrics)
            .await
            .map(Some)
    }

    /// Settle one retained invocation's observed metrics exactly once.
    ///
    /// An admission-reserved request is not billed again. Missing provider
    /// metrics stay missing; this method does not estimate tokens or price.
    ///
    /// # Errors
    ///
    /// Refuses unknown tickets, mismatched zones, conflicting settlements,
    /// invalid policies, or unavailable persistence.
    pub async fn record_invocation_usage(
        &self,
        ticket: &InvocationTicket,
        zone_id: &ZoneId,
        metrics: &[UsageMetric],
    ) -> HostResult<Option<BudgetEvaluation>> {
        let Some(policy) = self.policy_for_zone(zone_id).await else {
            return Ok(None);
        };
        self.store
            .settle_invocation_budget(ticket, zone_id, &policy, metrics)
            .await
            .map(Some)
    }

    /// Fetch current usage without consuming a request or changing storage.
    ///
    /// # Errors
    ///
    /// Refuses invalid policies or unavailable persistence.
    pub async fn snapshot(&self, zone_id: &ZoneId) -> HostResult<Option<UsageBudgetSnapshot>> {
        let Some(policy) = self.policy_for_zone(zone_id).await else {
            return Ok(None);
        };
        self.store
            .snapshot_zone_budget(zone_id, &policy)
            .await
            .map(Some)
    }

    /// Report current snapshots for all configured zones or a single zone.
    ///
    /// # Errors
    ///
    /// Refuses invalid policies or unavailable persistence rather than
    /// presenting an empty or reset report.
    pub async fn report(&self, zone_filter: Option<&ZoneId>) -> HostResult<BudgetReportResponse> {
        let policies = {
            let read = self.policies.read().await;
            let mut entries = read
                .iter()
                .filter(|(zone_id, _)| zone_filter.is_none_or(|requested| *zone_id == requested))
                .map(|(zone_id, policy)| (zone_id.clone(), policy.clone()))
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
            entries
        };
        let zones = self.store.report_zone_budgets(&policies).await?;
        Ok(BudgetReportResponse {
            schema_version: BudgetReportResponse::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            zones,
        })
    }
}

impl Default for BudgetPolicyEngine {
    fn default() -> Self {
        Self::with_policies(HashMap::new())
    }
}

#[async_trait::async_trait]
impl PolicyEngine for BudgetPolicyEngine {
    async fn evaluate_preflight(&self, request: &PreflightRequest) -> PreflightResponse {
        let mut response = PreflightResponse::allowed();
        let Some(zone_id) = request.zone_id.as_ref() else {
            return response;
        };
        let snapshot = match self.snapshot(zone_id).await {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return response,
            Err(_) => {
                response.allowed = false;
                response.reason = Some("usage budget accounting unavailable".to_owned());
                return response;
            }
        };
        let blocks_next = snapshot.enforcement == BudgetEnforcement::Deny
            && snapshot.budgets.iter().any(|entry| {
                entry.status == BudgetStatus::Exceeded
                    || (entry.metric == UsageMetricKind::Requests && entry.remaining == 0)
            });
        response.budget_status = Some(snapshot);
        if blocks_next {
            response.allowed = false;
            response.reason = Some("usage budget exceeded".to_string());
        }
        response
    }
}

impl MetricWindow {
    const fn new(window_seconds: u64, now: u64) -> Self {
        Self {
            window_seconds,
            window_started_at: now,
            used: 0,
        }
    }

    const fn roll_if_needed(&mut self, now: u64, configured_window: u64) {
        if self.window_seconds != configured_window || configured_window == 0 {
            self.window_seconds = configured_window;
            self.window_started_at = now;
            self.used = 0;
            return;
        }

        let elapsed = now.saturating_sub(self.window_started_at);
        if elapsed >= self.window_seconds {
            // Align the new window start time to prevent drift
            let windows_passed = elapsed / self.window_seconds;
            self.window_started_at = self
                .window_started_at
                .saturating_add(windows_passed.saturating_mul(self.window_seconds));
            self.used = 0;
        }
    }
}

fn aggregate_metrics(metrics: &[UsageMetric]) -> HashMap<UsageMetricKind, u64> {
    let mut totals: HashMap<UsageMetricKind, u64> = HashMap::with_capacity(metrics.len());
    for metric in metrics {
        let entry = totals.entry(metric.kind).or_insert(0);
        *entry = entry.saturating_add(metric.amount);
    }
    totals
}

fn now_secs() -> u64 {
    let ts = Utc::now().timestamp();
    u64::try_from(ts).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_kernel::{
        BudgetEnforcement, ConnectorId, UsageBudgetLimit, UsageBudgetPolicy, UsageMetricKind,
    };
    use fcp_policy::ZoneId;

    static LOG_CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn budget_tracker_warns_on_exceeded() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        assert_eq!(eval.action, BudgetAction::Warn);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    #[test]
    fn budget_tracker_denies_on_exceeded() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 1,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(2)]);
        assert_eq!(eval.action, BudgetAction::Deny);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_denies_on_exceeded_preflight() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        let eval = engine
            .record_usage(&zone, &[UsageMetric::tokens(150)])
            .await
            .expect("budget storage")
            .expect("budget policy");
        assert_eq!(eval.action, BudgetAction::Deny);

        let request = PreflightRequest {
            connector_id: ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: Some(zone.clone()),
        };

        let response = engine.evaluate_preflight(&request).await;
        assert!(!response.allowed);
        assert_eq!(response.reason.as_deref(), Some("usage budget exceeded"));
        let snapshot = response.budget_status.expect("budget status");
        assert_eq!(snapshot.zone_id, zone);
        assert_eq!(snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    #[test]
    fn budget_snapshot_blocks_routing_when_deny_budget_is_exhausted() {
        let snapshot = UsageBudgetSnapshot {
            zone_id: ZoneId::work(),
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetUsage {
                metric: UsageMetricKind::Requests,
                used: 10,
                limit: 10,
                remaining: 0,
                window_started_at: 100,
                window_resets_at: 200,
                status: BudgetStatus::Ok,
            }],
            updated_at: 150,
        };

        assert!(budget_snapshot_blocks_routing(&snapshot));
        assert_eq!(budget_remaining_floor(&snapshot), Some(0));
    }

    #[test]
    fn budget_snapshot_warn_exhaustion_does_not_block_routing() {
        let snapshot = UsageBudgetSnapshot {
            zone_id: ZoneId::work(),
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetUsage {
                metric: UsageMetricKind::Requests,
                used: 11,
                limit: 10,
                remaining: 0,
                window_started_at: 100,
                window_resets_at: 200,
                status: BudgetStatus::Exceeded,
            }],
            updated_at: 150,
        };

        assert!(!budget_snapshot_blocks_routing(&snapshot));
        assert_eq!(budget_remaining_floor(&snapshot), Some(0));
    }

    #[test]
    fn budget_tracker_allows_when_within_budget() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Ok);
        assert_eq!(eval.snapshot.budgets[0].used, 50);
        assert_eq!(eval.snapshot.budgets[0].remaining, 50);
    }

    #[test]
    fn budget_tracker_allows_with_no_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Ok);
        assert_eq!(eval.snapshot.budgets[0].used, 0);
        assert_eq!(eval.snapshot.budgets[0].remaining, 100);
    }

    #[test]
    fn budget_evaluation_to_error_returns_budget_exceeded() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 10,
                window_seconds: 3600,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(15)]);
        assert_eq!(eval.action, BudgetAction::Deny);

        let error = eval.to_error().expect("expected FcpError::BudgetExceeded");
        if let FcpError::BudgetExceeded {
            metric,
            used,
            limit,
            window_seconds,
        } = error
        {
            assert_eq!(metric, UsageMetricKind::Requests);
            assert_eq!(used, 15);
            assert_eq!(limit, 10);
            assert_eq!(window_seconds, 3600);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    #[test]
    fn budget_evaluation_to_error_returns_none_for_allow() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert!(eval.to_error().is_none());
    }

    #[test]
    fn budget_evaluation_to_error_returns_none_for_warn() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        assert_eq!(eval.action, BudgetAction::Warn);
        assert!(eval.to_error().is_none());
    }

    #[test]
    fn budget_tracker_accumulates_usage_within_window() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();

        let eval1 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(30)]);
        assert_eq!(eval1.action, BudgetAction::Allow);
        assert_eq!(eval1.snapshot.budgets[0].used, 30);

        let eval2 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(40)]);
        assert_eq!(eval2.action, BudgetAction::Allow);
        assert_eq!(eval2.snapshot.budgets[0].used, 70);

        let eval3 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval3.action, BudgetAction::Deny);
        assert_eq!(eval3.snapshot.budgets[0].used, 120);
        assert_eq!(eval3.snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    #[test]
    fn budget_tracker_tracks_zones_independently() {
        let zone_work = ZoneId::work();
        let zone_private = ZoneId::private();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();

        let eval_work = tracker.record_usage(&zone_work, &policy, &[UsageMetric::tokens(80)]);
        assert_eq!(eval_work.action, BudgetAction::Allow);
        assert_eq!(eval_work.snapshot.budgets[0].used, 80);
        assert_eq!(eval_work.snapshot.zone_id, zone_work);

        let eval_private = tracker.record_usage(&zone_private, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval_private.action, BudgetAction::Allow);
        assert_eq!(eval_private.snapshot.budgets[0].used, 50);
        assert_eq!(eval_private.snapshot.zone_id, zone_private);

        let eval_work2 = tracker.record_usage(&zone_work, &policy, &[UsageMetric::tokens(30)]);
        assert_eq!(eval_work2.action, BudgetAction::Deny);
        assert_eq!(eval_work2.snapshot.budgets[0].used, 110);

        let eval_private2 =
            tracker.record_usage(&zone_private, &policy, &[UsageMetric::tokens(30)]);
        assert_eq!(eval_private2.action, BudgetAction::Allow);
        assert_eq!(eval_private2.snapshot.budgets[0].used, 80);
    }

    #[test]
    fn budget_snapshot_reflects_current_state() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(45)]);

        let snapshot = tracker.snapshot(&zone, &policy);
        assert_eq!(snapshot.zone_id, zone);
        assert_eq!(snapshot.budgets[0].used, 45);
        assert_eq!(snapshot.budgets[0].limit, 100);
        assert_eq!(snapshot.budgets[0].remaining, 55);
        assert_eq!(snapshot.budgets[0].status, BudgetStatus::Ok);

        let snapshot2 = tracker.snapshot(&zone, &policy);
        assert_eq!(snapshot2.budgets[0].used, 45);
    }

    #[test]
    fn budget_tracker_aggregates_multiple_metrics() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 10,
                    window_seconds: 60,
                },
            ],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[
                UsageMetric::tokens(30),
                UsageMetric::requests(5),
                UsageMetric::tokens(20),
            ],
        );

        assert_eq!(eval.action, BudgetAction::Allow);
        let tokens_entry = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Tokens)
            .expect("tokens entry");
        assert_eq!(tokens_entry.used, 50);
        let requests_entry = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Requests)
            .expect("requests entry");
        assert_eq!(requests_entry.used, 5);
    }

    #[test]
    fn budget_snapshot_includes_zone_id() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);

        assert_eq!(eval.snapshot.zone_id, zone);
        assert_eq!(eval.snapshot.enforcement, BudgetEnforcement::Warn);
    }

    #[test]
    fn budget_deny_emits_structured_log_with_zone_id() {
        use fcp_testkit::LogCapture;

        let _log_capture_guard = LOG_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("warn");
        tracing::callsite::rebuild_interest_cache();

        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        assert_eq!(eval.action, BudgetAction::Deny);

        let logs = capture.jsonl();
        assert!(
            logs.contains("budget exceeded"),
            "expected 'budget exceeded' in logs, got: {logs}"
        );
        assert!(
            logs.contains("zone_id"),
            "expected 'zone_id' in logs, got: {logs}"
        );
        assert!(
            logs.contains("deny"),
            "expected 'deny' action in logs, got: {logs}"
        );
    }

    #[test]
    fn budget_warn_emits_structured_log_with_zone_id() {
        use fcp_testkit::LogCapture;

        let _log_capture_guard = LOG_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let capture = LogCapture::new();
        let _guard = capture.install_json_with_filter("warn");
        tracing::callsite::rebuild_interest_cache();

        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        assert_eq!(eval.action, BudgetAction::Warn);

        let logs = capture.jsonl();
        assert!(
            logs.contains("budget warning threshold exceeded"),
            "expected 'budget warning threshold exceeded' in logs, got: {logs}"
        );
        assert!(
            logs.contains("zone_id"),
            "expected 'zone_id' in logs, got: {logs}"
        );
        assert!(
            logs.contains("warn"),
            "expected 'warn' action in logs, got: {logs}"
        );
    }

    // ── BudgetAction tests ──

    #[test]
    fn budget_action_eq_and_copy() {
        let a = BudgetAction::Allow;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(BudgetAction::Allow, BudgetAction::Deny);
        assert_ne!(BudgetAction::Warn, BudgetAction::Deny);
    }

    // ── BudgetTracker default/new ──

    #[test]
    fn budget_tracker_new_is_empty() {
        let tracker = BudgetTracker::new();
        assert!(tracker.zones.is_empty());
    }

    #[test]
    fn budget_tracker_default_is_new() {
        let tracker = BudgetTracker::default();
        assert!(tracker.zones.is_empty());
    }

    // ── aggregate_metrics tests ──

    #[test]
    fn aggregate_metrics_empty() {
        let result = aggregate_metrics(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn aggregate_metrics_deduplicates() {
        let metrics = vec![
            UsageMetric::tokens(10),
            UsageMetric::tokens(20),
            UsageMetric::requests(5),
        ];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), 30);
        assert_eq!(*result.get(&UsageMetricKind::Requests).unwrap(), 5);
    }

    // ── BudgetEvaluation to_error edge cases ──

    #[test]
    fn budget_evaluation_to_error_deny_with_empty_budgets() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![],
                updated_at: 0,
            },
        };
        // No exceeded entry to find, returns None even though action is Deny
        assert!(eval.to_error().is_none());
    }

    #[test]
    fn budget_backpressure_signal_uses_max_reset_window() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Tokens,
                        used: 20,
                        limit: 10,
                        remaining: 0,
                        window_started_at: 90,
                        window_resets_at: 150,
                        status: BudgetStatus::Exceeded,
                    },
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Requests,
                        used: 50,
                        limit: 10,
                        remaining: 0,
                        window_started_at: 90,
                        window_resets_at: 190,
                        status: BudgetStatus::Exceeded,
                    },
                ],
                updated_at: 100,
            },
        };

        let signal = eval
            .backpressure_signal()
            .expect("denied budget exhaustion should signal backpressure");
        assert_eq!(signal.reason, FCP_BACKPRESSURE_BUDGET_EXHAUSTED);
        assert_eq!(signal.retry_after_seconds, 90);
    }

    #[test]
    fn budget_backpressure_signal_none_for_warn_only() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Warn,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Tokens,
                    used: 20,
                    limit: 10,
                    remaining: 0,
                    window_started_at: 90,
                    window_resets_at: 150,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 100,
            },
        };

        assert!(eval.backpressure_signal().is_none());
    }

    // ── BudgetPolicyEngine async tests ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_snapshot_without_policy_returns_none() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        assert!(engine.snapshot(&zone).await.unwrap().is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_record_usage_without_policy_returns_none() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        assert!(
            engine
                .record_usage(&zone, &[UsageMetric::tokens(10)])
                .await
                .unwrap()
                .is_none()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_remove_policy() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        engine.upsert_policy(zone.clone(), policy).await;
        assert!(engine.snapshot(&zone).await.unwrap().is_some());

        let removed = engine.remove_policy(&zone).await;
        assert!(removed.is_some());
        assert!(engine.snapshot(&zone).await.unwrap().is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_upsert_replaces() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();

        let policy1 = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        engine.upsert_policy(zone.clone(), policy1).await;

        let snap1 = engine.snapshot(&zone).await.unwrap().unwrap();
        assert_eq!(snap1.enforcement, BudgetEnforcement::Warn);

        let policy2 = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 200,
                window_seconds: 120,
            }],
        };
        engine.upsert_policy(zone.clone(), policy2).await;

        let snap2 = engine.snapshot(&zone).await.unwrap().unwrap();
        assert_eq!(snap2.enforcement, BudgetEnforcement::Deny);
        assert_eq!(snap2.budgets[0].limit, 200);
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_preflight_allows_within_budget() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        // Record some usage within budget
        let eval = engine
            .record_usage(&zone, &[UsageMetric::tokens(50)])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(eval.action, BudgetAction::Allow);

        let request = PreflightRequest {
            connector_id: ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: Some(zone),
        };

        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
        assert!(response.reason.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_preflight_no_zone_always_allows() {
        let engine = BudgetPolicyEngine::new();

        let request = PreflightRequest {
            connector_id: ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: None,
        };

        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_warn_enforcement_allows_preflight() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        // Exceed the budget
        engine
            .record_usage(&zone, &[UsageMetric::tokens(200)])
            .await
            .unwrap();

        let request = PreflightRequest {
            connector_id: ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: Some(zone),
        };

        // Warn enforcement does not deny
        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
    }

    // ── Budget snapshot with no prior usage ──

    #[test]
    fn budget_snapshot_fresh_zone_shows_zero_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 500,
                window_seconds: 3600,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let snap = tracker.snapshot(&zone, &policy);
        assert_eq!(snap.budgets[0].used, 0);
        assert_eq!(snap.budgets[0].remaining, 500);
        assert_eq!(snap.budgets[0].status, BudgetStatus::Ok);
    }

    // ── Multiple budget limits ──

    #[test]
    fn budget_tracker_partial_exceed_still_denies() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 1000,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 5,
                    window_seconds: 60,
                },
            ],
        };

        let mut tracker = BudgetTracker::new();
        // Exceed requests but not tokens
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[UsageMetric::tokens(100), UsageMetric::requests(10)],
        );
        assert_eq!(eval.action, BudgetAction::Deny);

        let tokens = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Tokens)
            .unwrap();
        assert_eq!(tokens.status, BudgetStatus::Ok);

        let requests = eval
            .snapshot
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Requests)
            .unwrap();
        assert_eq!(requests.status, BudgetStatus::Exceeded);
    }

    // ── Empty policy budgets ──

    #[test]
    fn budget_tracker_empty_budgets_always_allows() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(1_000_000)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert!(eval.snapshot.budgets.is_empty());
    }

    // ── MetricWindow roll_if_needed edge cases ──

    #[test]
    fn metric_window_roll_resets_when_window_size_changes() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 42;
        // configured_window differs from window_seconds → full reset
        window.roll_if_needed(1005, 120);
        assert_eq!(window.window_seconds, 120);
        assert_eq!(window.window_started_at, 1005);
        assert_eq!(window.used, 0);
    }

    #[test]
    fn metric_window_roll_resets_when_configured_window_zero() {
        let mut window = MetricWindow::new(0, 1000);
        window.used = 99;
        // configured_window == 0 → always reset
        window.roll_if_needed(1050, 0);
        assert_eq!(window.window_started_at, 1050);
        assert_eq!(window.used, 0);
    }

    #[test]
    fn metric_window_roll_no_roll_within_window() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 10;
        // 30s elapsed < 60s window → no roll
        window.roll_if_needed(1030, 60);
        assert_eq!(window.used, 10);
        assert_eq!(window.window_started_at, 1000);
    }

    #[test]
    fn metric_window_roll_exactly_at_boundary() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 50;
        // elapsed == window_seconds → rolls
        window.roll_if_needed(1060, 60);
        assert_eq!(window.used, 0);
        assert_eq!(window.window_started_at, 1060);
    }

    #[test]
    fn metric_window_roll_multiple_windows_passed() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 77;
        // 180s elapsed = 3 windows → should align start to 1000 + 3*60 = 1180
        window.roll_if_needed(1180, 60);
        assert_eq!(window.used, 0);
        assert_eq!(window.window_started_at, 1180);
    }

    #[test]
    fn metric_window_roll_partial_extra_window() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 33;
        // 150s = 2 full windows + 30s partial
        // windows_passed = 150/60 = 2, new start = 1000 + 2*60 = 1120
        window.roll_if_needed(1150, 60);
        assert_eq!(window.used, 0);
        assert_eq!(window.window_started_at, 1120);
    }

    #[test]
    fn metric_window_roll_now_before_start_saturates() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 5;
        // now < window_started_at → saturating_sub gives 0, no roll
        window.roll_if_needed(500, 60);
        assert_eq!(window.used, 5);
        assert_eq!(window.window_started_at, 1000);
    }

    // ── aggregate_metrics edge cases ──

    #[test]
    fn aggregate_metrics_saturates_on_overflow() {
        let metrics = vec![UsageMetric::tokens(u64::MAX), UsageMetric::tokens(1)];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), u64::MAX);
    }

    #[test]
    fn aggregate_metrics_single_entry() {
        let metrics = vec![UsageMetric::requests(42)];
        let result = aggregate_metrics(&metrics);
        assert_eq!(result.len(), 1);
        assert_eq!(*result.get(&UsageMetricKind::Requests).unwrap(), 42);
    }

    // ── Budget limit = 0 ──

    #[test]
    fn budget_tracker_zero_limit_exceeds_on_any_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 0,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(1)]);
        assert_eq!(eval.action, BudgetAction::Deny);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Exceeded);
        assert_eq!(eval.snapshot.budgets[0].remaining, 0);
    }

    #[test]
    fn budget_tracker_zero_limit_allows_zero_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 0,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 0);
    }

    // ── Budget evaluation to_error with multiple exceeded entries picks first ──

    #[test]
    fn budget_evaluation_to_error_skips_ok_finds_first_exceeded() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Tokens,
                        used: 50,
                        limit: 100,
                        remaining: 50,
                        window_started_at: 0,
                        window_resets_at: 60,
                        status: BudgetStatus::Ok,
                    },
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Requests,
                        used: 20,
                        limit: 10,
                        remaining: 0,
                        window_started_at: 0,
                        window_resets_at: 60,
                        status: BudgetStatus::Exceeded,
                    },
                ],
                updated_at: 30,
            },
        };
        let error = eval.to_error().expect("should produce error");
        if let FcpError::BudgetExceeded {
            metric,
            used,
            limit,
            ..
        } = error
        {
            assert_eq!(metric, UsageMetricKind::Requests);
            assert_eq!(used, 20);
            assert_eq!(limit, 10);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    // ── BudgetPolicyEngine::with_policies ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_with_policies_constructor() {
        let zone = ZoneId::work();
        let mut policies = HashMap::new();
        policies.insert(
            zone.clone(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 500,
                    window_seconds: 3600,
                }],
            },
        );

        let engine = BudgetPolicyEngine::with_policies(policies);
        let snap = engine.snapshot(&zone).await.unwrap().unwrap();
        assert_eq!(snap.budgets[0].limit, 500);
        assert_eq!(snap.budgets[0].used, 0);
        assert_eq!(snap.enforcement, BudgetEnforcement::Deny);
    }

    // ── BudgetPolicyEngine remove_policy idempotency ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_remove_policy_idempotent() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();

        // Remove from empty → None
        assert!(engine.remove_policy(&zone).await.is_none());

        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![],
                },
            )
            .await;

        // First removal → Some
        assert!(engine.remove_policy(&zone).await.is_some());
        // Second removal → None
        assert!(engine.remove_policy(&zone).await.is_none());
    }

    // ── BudgetPolicyEngine record_usage with empty metrics ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_record_usage_empty_metrics() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        let eval = engine.record_usage(&zone, &[]).await.unwrap().unwrap();
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 0);
    }

    // ── BudgetAction Debug ──

    #[test]
    fn budget_action_debug() {
        assert_eq!(format!("{:?}", BudgetAction::Allow), "Allow");
        assert_eq!(format!("{:?}", BudgetAction::Warn), "Warn");
        assert_eq!(format!("{:?}", BudgetAction::Deny), "Deny");
    }

    // ── BudgetEvaluation clone ──

    #[test]
    fn budget_evaluation_clone() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Allow,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![],
                updated_at: 123,
            },
        };
        let cloned = eval.clone();
        assert_eq!(cloned.action, eval.action);
        assert_eq!(cloned.snapshot.zone_id, eval.snapshot.zone_id);
        assert_eq!(cloned.snapshot.updated_at, eval.snapshot.updated_at);
    }

    // ── Snapshot window timing ──

    #[test]
    fn budget_snapshot_window_resets_at_correct() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 3600,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(10)]);
        let entry = &eval.snapshot.budgets[0];
        // resets_at should be started_at + window_seconds
        assert_eq!(entry.window_resets_at, entry.window_started_at + 3600);
    }

    // ── Multiple record_usage calls with different metric types ──

    #[test]
    fn budget_tracker_untracked_metric_ignored() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        // Record requests but policy only tracks tokens
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(1000)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 0);
    }

    // ── Budget enforcement field in snapshot ──

    #[test]
    fn budget_snapshot_enforcement_preserved() {
        let zone = ZoneId::work();
        for enforcement in [BudgetEnforcement::Deny, BudgetEnforcement::Warn] {
            let policy = UsageBudgetPolicy {
                enforcement,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 60,
                }],
            };

            let mut tracker = BudgetTracker::new();
            let snap = tracker.snapshot(&zone, &policy);
            assert_eq!(snap.enforcement, enforcement);
        }
    }

    // ── BudgetAction debug for all variants ──

    #[test]
    fn budget_action_all_variants_debug() {
        let actions = [BudgetAction::Allow, BudgetAction::Warn, BudgetAction::Deny];
        for action in &actions {
            let dbg = format!("{action:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── BudgetEvaluation debug ──

    #[test]
    fn budget_evaluation_debug() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Allow,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![],
                updated_at: 0,
            },
        };
        let dbg = format!("{eval:?}");
        assert!(dbg.contains("BudgetEvaluation"));
        assert!(dbg.contains("Allow"));
    }

    // ── BudgetTracker debug ──

    #[test]
    fn budget_tracker_debug() {
        let tracker = BudgetTracker::new();
        let dbg = format!("{tracker:?}");
        assert!(dbg.contains("BudgetTracker"));
    }

    // ── BudgetPolicyEngine debug ──

    #[test]
    fn budget_policy_engine_debug() {
        let engine = BudgetPolicyEngine::new();
        let dbg = format!("{engine:?}");
        assert!(dbg.contains("BudgetPolicyEngine"));
    }

    // ── BudgetPolicyEngine default ──

    #[test]
    fn budget_policy_engine_default() {
        let engine = BudgetPolicyEngine::default();
        let dbg = format!("{engine:?}");
        assert!(dbg.contains("BudgetPolicyEngine"));
    }

    // ── MetricWindow constructor ──

    #[test]
    fn metric_window_new_fields() {
        let w = MetricWindow::new(300, 5000);
        assert_eq!(w.window_seconds, 300);
        assert_eq!(w.window_started_at, 5000);
        assert_eq!(w.used, 0);
    }

    // ── MetricWindow clone ──

    #[test]
    fn metric_window_clone() {
        let original = MetricWindow::new(60, 1000);
        let cloned = original.clone();
        assert_eq!(original.window_seconds, cloned.window_seconds);
        assert_eq!(original.window_started_at, cloned.window_started_at);
        assert_eq!(original.used, cloned.used);
    }

    // ── aggregate_metrics with many entries ──

    #[test]
    fn aggregate_metrics_many_same_kind() {
        let metrics: Vec<UsageMetric> = (0..100).map(|_| UsageMetric::tokens(1)).collect();
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), 100);
    }

    // ── Budget tracker snapshot does not modify state ──

    #[test]
    fn budget_tracker_snapshot_idempotent() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        let snap1 = tracker.snapshot(&zone, &policy);
        let snap2 = tracker.snapshot(&zone, &policy);
        assert_eq!(snap1.budgets[0].used, snap2.budgets[0].used);
        assert_eq!(snap1.budgets[0].remaining, snap2.budgets[0].remaining);
    }

    // ── Budget evaluation to_error with non-exceeded budgets ──

    #[test]
    fn budget_evaluation_deny_no_exceeded_returns_none() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Tokens,
                    used: 50,
                    limit: 100,
                    remaining: 50,
                    window_started_at: 0,
                    window_resets_at: 60,
                    status: BudgetStatus::Ok,
                }],
                updated_at: 0,
            },
        };
        // Even though action is Deny, no budget has Exceeded status
        assert!(eval.to_error().is_none());
    }

    // ── Budget saturating add ──

    #[test]
    fn budget_tracker_saturating_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: u64::MAX,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(u64::MAX - 10)]);
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(20)]);
        // Should saturate at u64::MAX
        assert_eq!(eval.snapshot.budgets[0].used, u64::MAX);
    }

    // ── now_secs ──

    #[test]
    fn now_secs_is_positive() {
        let ts = now_secs();
        // Should be well past epoch year 2000 = 946684800
        assert!(ts > 946_684_800);
    }

    // ── BudgetAction clone and copy semantics ──

    #[test]
    fn budget_action_clone_all_variants() {
        for action in [BudgetAction::Allow, BudgetAction::Warn, BudgetAction::Deny] {
            let cloned = action;
            assert_eq!(action, cloned);
        }
    }

    #[test]
    fn budget_action_ne_all_pairs() {
        assert_ne!(BudgetAction::Allow, BudgetAction::Warn);
        assert_ne!(BudgetAction::Allow, BudgetAction::Deny);
        assert_ne!(BudgetAction::Warn, BudgetAction::Deny);
    }

    // ── BudgetAction Eq reflexivity ──

    #[test]
    fn budget_action_eq_reflexive() {
        let a = BudgetAction::Allow;
        let w = BudgetAction::Warn;
        let d = BudgetAction::Deny;
        assert_eq!(a, a);
        assert_eq!(w, w);
        assert_eq!(d, d);
    }

    // ── BudgetEvaluation to_error window_seconds calculation ──

    #[test]
    fn budget_evaluation_to_error_window_seconds_from_timestamps() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Bytes,
                    used: 2000,
                    limit: 1000,
                    remaining: 0,
                    window_started_at: 1000,
                    window_resets_at: 4600,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 2000,
            },
        };
        let error = eval.to_error().expect("should produce error");
        if let FcpError::BudgetExceeded {
            metric,
            used,
            limit,
            window_seconds,
        } = error
        {
            assert_eq!(metric, UsageMetricKind::Bytes);
            assert_eq!(used, 2000);
            assert_eq!(limit, 1000);
            // window_seconds = resets_at - started_at = 4600 - 1000 = 3600
            assert_eq!(window_seconds, 3600);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    #[test]
    fn budget_evaluation_to_error_saturating_sub_on_window_times() {
        // When resets_at < started_at (shouldn't happen, but test saturating behavior)
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Tokens,
                    used: 200,
                    limit: 100,
                    remaining: 0,
                    window_started_at: 5000,
                    window_resets_at: 3000,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 5000,
            },
        };
        let error = eval.to_error().expect("should produce error");
        if let FcpError::BudgetExceeded { window_seconds, .. } = error {
            assert_eq!(window_seconds, 0);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    // ── aggregate_metrics with u64::MAX single entry ──

    #[test]
    fn aggregate_metrics_single_max() {
        let metrics = vec![UsageMetric::bytes(u64::MAX)];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Bytes).unwrap(), u64::MAX);
    }

    // ── Budget tracker: warn enforcement still accumulates ──

    #[test]
    fn budget_tracker_warn_continues_accumulating_after_exceed() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        let eval2 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval2.action, BudgetAction::Warn);
        assert_eq!(eval2.snapshot.budgets[0].used, 200);
    }

    // ── Budget tracker: deny enforcement still accumulates ──

    #[test]
    fn budget_tracker_deny_continues_accumulating_after_exceed() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(150)]);
        let eval2 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        assert_eq!(eval2.action, BudgetAction::Deny);
        assert_eq!(eval2.snapshot.budgets[0].used, 200);
    }

    // ── BudgetPolicyEngine: remove nonexistent returns None ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_remove_nonexistent_zone() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::owner();
        assert!(engine.remove_policy(&zone).await.is_none());
    }

    // ── Additional coverage: edge cases and missing paths ──

    #[test]
    fn budget_tracker_snapshot_unknown_zone_shows_zero() {
        let zone = ZoneId::owner();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 50,
                window_seconds: 120,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let snap = tracker.snapshot(&zone, &policy);
        assert_eq!(snap.budgets[0].used, 0);
        assert_eq!(snap.budgets[0].remaining, 50);
        assert_eq!(snap.zone_id, zone);
    }

    #[test]
    fn budget_tracker_record_empty_policy_budgets_with_metrics() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![],
        };
        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[UsageMetric::tokens(100), UsageMetric::requests(10)],
        );
        assert_eq!(eval.action, BudgetAction::Allow);
        assert!(eval.snapshot.budgets.is_empty());
    }

    #[test]
    fn metric_window_debug() {
        let w = MetricWindow::new(60, 1000);
        let dbg = format!("{w:?}");
        assert!(dbg.contains("MetricWindow"));
        assert!(dbg.contains("60"));
        assert!(dbg.contains("1000"));
    }

    #[test]
    fn budget_evaluation_to_error_returns_none_on_allow_action() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Allow,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Tokens,
                    used: 200,
                    limit: 100,
                    remaining: 0,
                    window_started_at: 0,
                    window_resets_at: 60,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 0,
            },
        };
        // Action is Allow, so to_error returns None regardless of budget status
        assert!(eval.to_error().is_none());
    }

    #[test]
    fn budget_tracker_api_credits_metric() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::ApiCredits,
                limit: 1000,
                window_seconds: 3600,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::api_credits(500)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 500);
        assert_eq!(eval.snapshot.budgets[0].remaining, 500);

        let eval2 = tracker.record_usage(&zone, &policy, &[UsageMetric::api_credits(600)]);
        assert_eq!(eval2.action, BudgetAction::Deny);
        assert_eq!(eval2.snapshot.budgets[0].used, 1100);
    }

    #[test]
    fn budget_tracker_bytes_metric() {
        let zone = ZoneId::private();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Bytes,
                limit: 1_048_576,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::bytes(1_048_576 + 1)]);
        assert_eq!(eval.action, BudgetAction::Warn);
        assert_eq!(eval.snapshot.budgets[0].remaining, 0);
    }

    #[test]
    fn aggregate_metrics_two_different_kinds() {
        let metrics = vec![UsageMetric::api_credits(7), UsageMetric::bytes(99)];
        let result = aggregate_metrics(&metrics);
        assert_eq!(result.len(), 2);
        assert_eq!(*result.get(&UsageMetricKind::ApiCredits).unwrap(), 7);
        assert_eq!(*result.get(&UsageMetricKind::Bytes).unwrap(), 99);
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_report_all_zones_is_sorted() {
        let engine = BudgetPolicyEngine::new();
        engine
            .upsert_policy(
                ZoneId::work(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Requests,
                        limit: 10,
                        window_seconds: 60,
                    }],
                },
            )
            .await;
        engine
            .upsert_policy(
                ZoneId::private(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;

        let report = engine.report(None).await.unwrap();
        assert_eq!(report.schema_version, BudgetReportResponse::SCHEMA_VERSION);
        assert_eq!(report.zones.len(), 2);
        assert_eq!(report.zones[0].zone_id, ZoneId::private());
        assert_eq!(report.zones[1].zone_id, ZoneId::work());
    }

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_report_zone_filter_limits_output() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::ApiCredits,
                        limit: 1_000,
                        window_seconds: 3_600,
                    }],
                },
            )
            .await;
        engine
            .record_usage(&zone, &[UsageMetric::api_credits(250)])
            .await
            .expect("usage should be recorded");

        let report = engine.report(Some(&zone)).await.unwrap();
        assert_eq!(report.zones.len(), 1);
        assert_eq!(report.zones[0].zone_id, zone);
        assert_eq!(report.zones[0].budgets[0].used, 250);
    }

    // ══════════════════════════════════════════════════════════════════
    // NEW TESTS — expanded coverage for budget.rs
    // ══════════════════════════════════════════════════════════════════

    // ── BudgetReportRequest serde + Default ──

    #[test]
    fn budget_report_request_default_has_no_zone() {
        let req = BudgetReportRequest::default();
        assert!(req.zone_id.is_none());
    }

    #[test]
    fn budget_report_request_clone() {
        let req = BudgetReportRequest {
            zone_id: Some("zone-alpha".to_string()),
        };
        let cloned = req.clone();
        assert_eq!(req.zone_id.as_deref(), Some("zone-alpha"));
        assert_eq!(cloned.zone_id.as_deref(), Some("zone-alpha"));
    }

    #[test]
    fn budget_report_request_debug() {
        let req = BudgetReportRequest::default();
        let dbg = format!("{req:?}");
        assert!(dbg.contains("BudgetReportRequest"));
    }

    #[test]
    fn budget_report_request_serde_roundtrip_with_zone() {
        let req = BudgetReportRequest {
            zone_id: Some("production".to_string()),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let parsed: BudgetReportRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.zone_id.as_deref(), Some("production"));
    }

    #[test]
    fn budget_report_request_serde_roundtrip_without_zone() {
        let req = BudgetReportRequest { zone_id: None };
        let json = serde_json::to_string(&req).expect("serialize");
        let parsed: BudgetReportRequest = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.zone_id.is_none());
    }

    #[test]
    fn budget_report_request_deserialize_empty_object() {
        let parsed: BudgetReportRequest = serde_json::from_str("{}").expect("deserialize empty");
        assert!(parsed.zone_id.is_none());
    }

    // ── BudgetReportResponse serde + fields ──

    #[test]
    fn budget_report_response_schema_version_constant() {
        assert_eq!(BudgetReportResponse::SCHEMA_VERSION, "1.0.0");
    }

    #[test]
    fn budget_report_response_debug() {
        let resp = BudgetReportResponse {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![],
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("BudgetReportResponse"));
    }

    #[test]
    fn budget_report_response_clone() {
        let resp = BudgetReportResponse {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![],
        };
        let cloned = resp.clone();
        assert_eq!(resp.schema_version, cloned.schema_version);
        assert!(resp.zones.is_empty());
        assert!(cloned.zones.is_empty());
    }

    #[test]
    fn budget_report_response_serde_roundtrip() {
        let resp = BudgetReportResponse {
            schema_version: "1.0.0".to_string(),
            generated_at: Utc::now(),
            zones: vec![],
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let parsed: BudgetReportResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.schema_version, "1.0.0");
        assert!(parsed.zones.is_empty());
    }

    // ── BudgetTracker: exact-at-limit boundary ──

    #[test]
    fn budget_tracker_exact_at_limit_is_ok() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(100)]);
        // used == limit is NOT exceeded (only used > limit triggers exceeded)
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Ok);
        assert_eq!(eval.snapshot.budgets[0].remaining, 0);
    }

    #[test]
    fn budget_tracker_one_over_limit_is_exceeded() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(101)]);
        assert_eq!(eval.action, BudgetAction::Deny);
        assert_eq!(eval.snapshot.budgets[0].status, BudgetStatus::Exceeded);
    }

    // ── DurationMs metric kind ──

    #[test]
    fn budget_tracker_duration_ms_metric() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::DurationMs,
                limit: 5000,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::duration_ms(3000)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 3000);
        assert_eq!(eval.snapshot.budgets[0].remaining, 2000);

        let eval2 = tracker.record_usage(&zone, &policy, &[UsageMetric::duration_ms(2500)]);
        assert_eq!(eval2.action, BudgetAction::Deny);
        assert_eq!(eval2.snapshot.budgets[0].used, 5500);
    }

    // ── All five metric kinds in a single policy ──

    #[test]
    fn budget_tracker_all_five_metric_kinds() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 1000,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 50,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Bytes,
                    limit: 1_000_000,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::DurationMs,
                    limit: 10_000,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::ApiCredits,
                    limit: 100,
                    window_seconds: 60,
                },
            ],
        };
        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[
                UsageMetric::tokens(500),
                UsageMetric::requests(10),
                UsageMetric::bytes(500_000),
                UsageMetric::duration_ms(5000),
                UsageMetric::api_credits(50),
            ],
        );
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets.len(), 5);
        for entry in &eval.snapshot.budgets {
            assert_eq!(entry.status, BudgetStatus::Ok);
        }
    }

    // ── Multiple zones with different policies ──

    #[test]
    fn budget_tracker_different_policies_per_zone() {
        let zone_a = ZoneId::work();
        let zone_b = ZoneId::private();
        let policy_strict = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 10,
                window_seconds: 60,
            }],
        };
        let policy_lenient = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 10_000,
                window_seconds: 60,
            }],
        };

        let mut tracker = BudgetTracker::new();
        let eval_a = tracker.record_usage(&zone_a, &policy_strict, &[UsageMetric::tokens(50)]);
        assert_eq!(eval_a.action, BudgetAction::Deny);

        let eval_b = tracker.record_usage(&zone_b, &policy_lenient, &[UsageMetric::tokens(50)]);
        assert_eq!(eval_b.action, BudgetAction::Allow);
    }

    // ── Snapshot after exceeded state still shows exceeded ──

    #[test]
    fn budget_tracker_snapshot_after_exceeded_shows_exceeded() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let _ = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(200)]);
        let snap = tracker.snapshot(&zone, &policy);
        assert_eq!(snap.budgets[0].status, BudgetStatus::Exceeded);
        assert_eq!(snap.budgets[0].used, 200);
        assert_eq!(snap.budgets[0].remaining, 0);
    }

    // ── aggregate_metrics: all five kinds at once ──

    #[test]
    fn aggregate_metrics_all_five_kinds() {
        let metrics = vec![
            UsageMetric::tokens(10),
            UsageMetric::requests(20),
            UsageMetric::bytes(30),
            UsageMetric::duration_ms(40),
            UsageMetric::api_credits(50),
        ];
        let result = aggregate_metrics(&metrics);
        assert_eq!(result.len(), 5);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), 10);
        assert_eq!(*result.get(&UsageMetricKind::Requests).unwrap(), 20);
        assert_eq!(*result.get(&UsageMetricKind::Bytes).unwrap(), 30);
        assert_eq!(*result.get(&UsageMetricKind::DurationMs).unwrap(), 40);
        assert_eq!(*result.get(&UsageMetricKind::ApiCredits).unwrap(), 50);
    }

    #[test]
    fn aggregate_metrics_zero_amounts() {
        let metrics = vec![UsageMetric::tokens(0), UsageMetric::tokens(0)];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), 0);
    }

    #[test]
    fn aggregate_metrics_multiple_saturate_separately() {
        let metrics = vec![
            UsageMetric::tokens(u64::MAX),
            UsageMetric::tokens(100),
            UsageMetric::requests(u64::MAX),
            UsageMetric::requests(1),
        ];
        let result = aggregate_metrics(&metrics);
        assert_eq!(*result.get(&UsageMetricKind::Tokens).unwrap(), u64::MAX);
        assert_eq!(*result.get(&UsageMetricKind::Requests).unwrap(), u64::MAX);
    }

    // ── MetricWindow edge cases ──

    #[test]
    fn metric_window_roll_u64_max_window_seconds() {
        let mut window = MetricWindow::new(u64::MAX, 0);
        window.used = 42;
        // elapsed = 100 < u64::MAX, no roll
        window.roll_if_needed(100, u64::MAX);
        assert_eq!(window.used, 42);
        assert_eq!(window.window_started_at, 0);
    }

    #[test]
    fn metric_window_roll_window_seconds_one() {
        let mut window = MetricWindow::new(1, 1000);
        window.used = 10;
        // elapsed = 1 >= window_seconds(1) → rolls
        window.roll_if_needed(1001, 1);
        assert_eq!(window.used, 0);
        assert_eq!(window.window_started_at, 1001);
    }

    #[test]
    fn metric_window_roll_many_short_windows() {
        let mut window = MetricWindow::new(1, 0);
        window.used = 5;
        // 100 windows passed
        window.roll_if_needed(100, 1);
        assert_eq!(window.used, 0);
        assert_eq!(window.window_started_at, 100);
    }

    #[test]
    fn metric_window_roll_no_change_same_timestamp() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 15;
        // now == window_started_at → elapsed = 0 < 60, no roll
        window.roll_if_needed(1000, 60);
        assert_eq!(window.used, 15);
        assert_eq!(window.window_started_at, 1000);
    }

    #[test]
    fn metric_window_roll_from_nonzero_window_to_zero_resets() {
        let mut window = MetricWindow::new(60, 1000);
        window.used = 25;
        // configured_window = 0 → always resets
        window.roll_if_needed(1010, 0);
        assert_eq!(window.used, 0);
        assert_eq!(window.window_started_at, 1010);
        assert_eq!(window.window_seconds, 0);
    }

    // ── BudgetTracker: limit == u64::MAX ──

    #[test]
    fn budget_tracker_max_limit_allows_large_usage() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: u64::MAX,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(u64::MAX - 1)]);
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, u64::MAX - 1);
        assert_eq!(eval.snapshot.budgets[0].remaining, 1);
    }

    // ── BudgetTracker: multiple record calls accumulating to exact limit ──

    #[test]
    fn budget_tracker_accumulate_to_exact_limit() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 5,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        for _ in 0..5 {
            let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(1)]);
            assert_eq!(eval.action, BudgetAction::Allow);
        }
        // 6th request exceeds
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::requests(1)]);
        assert_eq!(eval.action, BudgetAction::Deny);
        assert_eq!(eval.snapshot.budgets[0].used, 6);
    }

    // ── BudgetEvaluation to_error: multiple exceeded entries returns first ──

    #[test]
    fn budget_evaluation_to_error_multiple_exceeded_returns_first() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Tokens,
                        used: 200,
                        limit: 100,
                        remaining: 0,
                        window_started_at: 0,
                        window_resets_at: 60,
                        status: BudgetStatus::Exceeded,
                    },
                    UsageBudgetUsage {
                        metric: UsageMetricKind::Requests,
                        used: 20,
                        limit: 10,
                        remaining: 0,
                        window_started_at: 0,
                        window_resets_at: 60,
                        status: BudgetStatus::Exceeded,
                    },
                ],
                updated_at: 0,
            },
        };
        let error = eval.to_error().expect("should produce error");
        // Should find the first exceeded entry (Tokens)
        if let FcpError::BudgetExceeded { metric, .. } = error {
            assert_eq!(metric, UsageMetricKind::Tokens);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    // ── BudgetEvaluation to_error: Warn action with exceeded entries ──

    #[test]
    fn budget_evaluation_to_error_warn_with_exceeded_returns_none() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Warn,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Tokens,
                    used: 200,
                    limit: 100,
                    remaining: 0,
                    window_started_at: 0,
                    window_resets_at: 60,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 0,
            },
        };
        // Warn action never produces an error
        assert!(eval.to_error().is_none());
    }

    // ── BudgetEvaluation to_error: window_seconds = 0 ──

    #[test]
    fn budget_evaluation_to_error_zero_window() {
        let eval = BudgetEvaluation {
            action: BudgetAction::Deny,
            snapshot: UsageBudgetSnapshot {
                zone_id: ZoneId::work(),
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetUsage {
                    metric: UsageMetricKind::Tokens,
                    used: 10,
                    limit: 5,
                    remaining: 0,
                    window_started_at: 100,
                    window_resets_at: 100,
                    status: BudgetStatus::Exceeded,
                }],
                updated_at: 100,
            },
        };
        let error = eval.to_error().expect("should produce error");
        if let FcpError::BudgetExceeded { window_seconds, .. } = error {
            assert_eq!(window_seconds, 0);
        } else {
            unreachable!("expected BudgetExceeded");
        }
    }

    // ── BudgetTracker: snapshot does not change zones map size ──

    #[test]
    fn budget_tracker_snapshot_creates_zone_entry() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        assert!(tracker.zones.is_empty());
        let _ = tracker.snapshot(&zone, &policy);
        // snapshot creates the zone entry via or_default()
        assert_eq!(tracker.zones.len(), 1);
    }

    // ── BudgetTracker: snapshot multiple budgets ──

    #[test]
    fn budget_tracker_snapshot_multiple_budgets() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Bytes,
                    limit: 1024,
                    window_seconds: 120,
                },
            ],
        };
        let mut tracker = BudgetTracker::new();
        let snap = tracker.snapshot(&zone, &policy);
        assert_eq!(snap.budgets.len(), 2);
        assert_eq!(snap.budgets[0].metric, UsageMetricKind::Tokens);
        assert_eq!(snap.budgets[1].metric, UsageMetricKind::Bytes);
        assert_eq!(snap.budgets[0].limit, 100);
        assert_eq!(snap.budgets[1].limit, 1024);
    }

    // ── BudgetPolicyEngine async: report with no policies ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_report_empty_has_no_zones() {
        let engine = BudgetPolicyEngine::new();
        let report = engine.report(None).await.unwrap();
        assert!(report.zones.is_empty());
        assert_eq!(report.schema_version, BudgetReportResponse::SCHEMA_VERSION);
    }

    // ── BudgetPolicyEngine async: report filter on nonexistent zone ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_report_filter_nonexistent_zone() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;
        let nonexistent = ZoneId::owner();
        let report = engine.report(Some(&nonexistent)).await.unwrap();
        assert!(report.zones.is_empty());
    }

    // ── BudgetPolicyEngine async: preflight with zone but no policy ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_preflight_zone_without_policy_allows() {
        let engine = BudgetPolicyEngine::new();
        let request = PreflightRequest {
            connector_id: ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: Some(ZoneId::work()),
        };
        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
        assert!(response.reason.is_none());
        assert!(response.budget_status.is_none());
    }

    // ── BudgetPolicyEngine async: with_policies multiple zones ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_with_policies_multiple_zones() {
        let mut policies = HashMap::new();
        policies.insert(
            ZoneId::work(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Deny,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 100,
                    window_seconds: 60,
                }],
            },
        );
        policies.insert(
            ZoneId::private(),
            UsageBudgetPolicy {
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 50,
                    window_seconds: 3600,
                }],
            },
        );
        let engine = BudgetPolicyEngine::with_policies(policies);
        let snap_work = engine.snapshot(&ZoneId::work()).await.unwrap().unwrap();
        assert_eq!(snap_work.enforcement, BudgetEnforcement::Deny);
        let snap_priv = engine.snapshot(&ZoneId::private()).await.unwrap().unwrap();
        assert_eq!(snap_priv.enforcement, BudgetEnforcement::Warn);
    }

    // ── BudgetPolicyEngine async: record_usage then snapshot consistency ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_record_then_snapshot() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 1000,
                        window_seconds: 60,
                    }],
                },
            )
            .await;
        engine
            .record_usage(&zone, &[UsageMetric::tokens(250)])
            .await
            .unwrap();
        let snap = engine.snapshot(&zone).await.unwrap().unwrap();
        assert_eq!(snap.budgets[0].used, 250);
        assert_eq!(snap.budgets[0].remaining, 750);
    }

    // ── BudgetPolicyEngine async: report includes usage from recording ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_report_reflects_recorded_usage() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 500,
                        window_seconds: 3600,
                    }],
                },
            )
            .await;
        engine
            .record_usage(&zone, &[UsageMetric::tokens(123)])
            .await
            .unwrap();
        let report = engine.report(None).await.unwrap();
        assert_eq!(report.zones.len(), 1);
        assert_eq!(report.zones[0].budgets[0].used, 123);
    }

    // ── BudgetPolicyEngine async: upsert preserves existing tracked usage ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_upsert_preserves_tracker_state() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        engine.upsert_policy(zone.clone(), policy.clone()).await;
        engine
            .record_usage(&zone, &[UsageMetric::tokens(75)])
            .await
            .unwrap();

        // Upsert with a new limit, tracker state for this zone still has accumulated usage
        let new_policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 200,
                window_seconds: 60,
            }],
        };
        engine.upsert_policy(zone.clone(), new_policy).await;
        let snap = engine.snapshot(&zone).await.unwrap().unwrap();
        // Usage is still tracked in the BudgetTracker
        assert_eq!(snap.budgets[0].used, 75);
        assert_eq!(snap.budgets[0].limit, 200);
        assert_eq!(snap.budgets[0].remaining, 125);
    }

    // ── BudgetPolicyEngine async: preflight with budget_status populated ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_preflight_populates_budget_status() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;
        engine
            .record_usage(&zone, &[UsageMetric::tokens(30)])
            .await
            .unwrap();

        let request = PreflightRequest {
            connector_id: ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: Some(zone.clone()),
        };
        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
        let status = response
            .budget_status
            .expect("budget_status should be populated");
        assert_eq!(status.zone_id, zone);
        assert_eq!(status.budgets[0].used, 30);
    }

    // ── now_secs returns reasonable value ──

    #[test]
    fn now_secs_returns_reasonable_timestamp() {
        let ts = now_secs();
        // Should be past 2020-01-01 = 1577836800
        assert!(ts > 1_577_836_800);
        // Should be before 2100-01-01 = 4102444800
        assert!(ts < 4_102_444_800);
    }

    // ── BudgetTracker: record_usage with mixed relevant/irrelevant metrics ──

    #[test]
    fn budget_tracker_mixed_relevant_irrelevant_metrics() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        // Send tokens + requests + bytes, but only tokens is tracked in policy
        let eval = tracker.record_usage(
            &zone,
            &policy,
            &[
                UsageMetric::tokens(50),
                UsageMetric::requests(999),
                UsageMetric::bytes(999_999),
            ],
        );
        assert_eq!(eval.action, BudgetAction::Allow);
        assert_eq!(eval.snapshot.budgets[0].used, 50);
        // Only 1 budget entry for tokens
        assert_eq!(eval.snapshot.budgets.len(), 1);
    }

    // ── BudgetTracker: snapshot updated_at is reasonable ──

    #[test]
    fn budget_tracker_snapshot_updated_at_is_recent() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let snap = tracker.snapshot(&zone, &policy);
        // updated_at should be a recent timestamp
        assert!(snap.updated_at > 1_577_836_800);
    }

    // ── BudgetTracker: record_usage updated_at is reasonable ──

    #[test]
    fn budget_tracker_record_usage_updated_at_is_recent() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        let eval = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(10)]);
        assert!(eval.snapshot.updated_at > 1_577_836_800);
    }

    // ── BudgetPolicyEngine async: generated_at is recent ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_report_generated_at_is_recent() {
        let engine = BudgetPolicyEngine::new();
        let before = Utc::now();
        let report = engine.report(None).await.unwrap();
        let after = Utc::now();
        assert!(report.generated_at >= before);
        assert!(report.generated_at <= after);
    }

    // ── BudgetPolicyEngine async: warn enforcement + exceeded still allows preflight ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_preflight_exceeded_warn_has_budget_status() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Warn,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;
        engine
            .record_usage(&zone, &[UsageMetric::tokens(200)])
            .await
            .unwrap();

        let request = PreflightRequest {
            connector_id: ConnectorId::new("budget", "test", "v1").expect("connector id"),
            operation: "invoke".to_string(),
            params: None,
            principal: None,
            zone_id: Some(zone),
        };
        let response = engine.evaluate_preflight(&request).await;
        assert!(response.allowed);
        let status = response.budget_status.expect("should have budget_status");
        assert_eq!(status.budgets[0].status, BudgetStatus::Exceeded);
    }

    // ── BudgetTracker: snapshot with zero window_seconds ──

    #[test]
    fn budget_tracker_zero_window_seconds_always_resets() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 0,
            }],
        };
        let mut tracker = BudgetTracker::new();
        // Record some usage
        let eval1 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(50)]);
        // With window_seconds = 0, roll_if_needed resets on every call
        // Second call resets the window
        let eval2 = tracker.record_usage(&zone, &policy, &[UsageMetric::tokens(30)]);
        // Usage is reset each time due to zero window
        assert_eq!(eval2.snapshot.budgets[0].used, 30);
        assert_eq!(eval2.action, BudgetAction::Allow);
        // But first call accumulated
        assert_eq!(eval1.snapshot.budgets[0].used, 50);
    }

    // ── BudgetPolicyEngine async: remove policy then record_usage returns None ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_record_after_remove_returns_none() {
        let engine = BudgetPolicyEngine::new();
        let zone = ZoneId::work();
        engine
            .upsert_policy(
                zone.clone(),
                UsageBudgetPolicy {
                    enforcement: BudgetEnforcement::Deny,
                    budgets: vec![UsageBudgetLimit {
                        metric: UsageMetricKind::Tokens,
                        limit: 100,
                        window_seconds: 60,
                    }],
                },
            )
            .await;
        engine
            .record_usage(&zone, &[UsageMetric::tokens(50)])
            .await
            .unwrap();
        engine.remove_policy(&zone).await;
        assert!(
            engine
                .record_usage(&zone, &[UsageMetric::tokens(10)])
                .await
                .unwrap()
                .is_none()
        );
    }

    // ── BudgetPolicyEngine async: report with three zones sorted ──

    #[fcp_async_core::runtime::test]
    async fn budget_policy_engine_report_three_zones_sorted() {
        let engine = BudgetPolicyEngine::new();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Warn,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Tokens,
                limit: 100,
                window_seconds: 60,
            }],
        };
        // Insert in non-alphabetical order
        engine.upsert_policy(ZoneId::work(), policy.clone()).await;
        engine.upsert_policy(ZoneId::owner(), policy.clone()).await;
        engine.upsert_policy(ZoneId::private(), policy).await;

        let report = engine.report(None).await.unwrap();
        assert_eq!(report.zones.len(), 3);
        // Zones should be sorted alphabetically
        let zone_ids: Vec<&str> = report.zones.iter().map(|z| z.zone_id.as_str()).collect();
        let mut sorted = zone_ids.clone();
        sorted.sort_unstable();
        assert_eq!(zone_ids, sorted);
    }

    #[test]
    fn request_reservations_use_persisted_high_water_across_rollover_and_clock_rollback() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 1,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        assert!(tracker.reserve_request(&zone, &policy, 1_000).unwrap());
        assert!(tracker.reserve_request(&zone, &policy, 1_059).is_err());
        assert!(tracker.reserve_request(&zone, &policy, 1_060).unwrap());
        let encoded = serde_json::to_vec(&tracker).unwrap();
        let mut restarted: BudgetTracker = serde_json::from_slice(&encoded).unwrap();
        restarted.validate_persisted().unwrap();
        assert!(restarted.reserve_request(&zone, &policy, 1_000).is_err());
        let current = restarted.snapshot_at(&zone, &policy, 1_001);
        assert_eq!(current.updated_at, 1_060);
        assert_eq!(current.budgets[0].window_started_at, 1_060);
        assert_eq!(current.budgets[0].used, 1);
        assert!(restarted.reserve_request(&zone, &policy, 1_120).unwrap());
        assert!(restarted.reserve_request(&zone, &policy, 1_119).is_err());
    }

    #[test]
    fn request_capacity_is_projected_without_reserving_unknown_provider_cost() {
        let zone = ZoneId::work();
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![
                UsageBudgetLimit {
                    metric: UsageMetricKind::Requests,
                    limit: 1,
                    window_seconds: 60,
                },
                UsageBudgetLimit {
                    metric: UsageMetricKind::Tokens,
                    limit: 10,
                    window_seconds: 60,
                },
            ],
        };
        let mut tracker = BudgetTracker::new();
        tracker.record_usage_at(&zone, &policy, &[UsageMetric::tokens(10)], 100);
        tracker.reserve_request(&zone, &policy, 100).unwrap();
        let snapshot = tracker.snapshot_at(&zone, &policy, 100);
        assert_eq!(snapshot.budgets[0].used, 1);
        assert_eq!(snapshot.budgets[1].used, 10);
        assert!(tracker.reserve_request(&zone, &policy, 100).is_err());
        let mut zero = policy.clone();
        zero.budgets[0].limit = 0;
        assert!(
            BudgetTracker::new()
                .reserve_request(&zone, &zero, 100)
                .is_err()
        );
        let mut over = BudgetTracker::new();
        over.record_usage_at(&zone, &policy, &[UsageMetric::tokens(11)], 100);
        assert!(over.reserve_request(&zone, &policy, 100).is_err());
    }

    #[test]
    fn zone_capacity_never_evicts_spent_request_allowance() {
        let policy = UsageBudgetPolicy {
            enforcement: BudgetEnforcement::Deny,
            budgets: vec![UsageBudgetLimit {
                metric: UsageMetricKind::Requests,
                limit: 1,
                window_seconds: 60,
            }],
        };
        let mut tracker = BudgetTracker::new();
        for index in 0..MAX_TRACKED_BUDGET_ZONES {
            let zone: ZoneId = format!("z:budget-{index}").parse().unwrap();
            tracker.reserve_request(&zone, &policy, 100).unwrap();
        }
        assert!(
            tracker
                .reserve_request(&ZoneId::work(), &policy, 100)
                .unwrap_err()
                .to_string()
                .contains("capacity exhausted")
        );
        let existing: ZoneId = "z:budget-0".parse().unwrap();
        assert!(tracker.reserve_request(&existing, &policy, 100).is_err());
        tracker.reserve_request(&existing, &policy, 160).unwrap();
        assert_eq!(tracker.zones.len(), MAX_TRACKED_BUDGET_ZONES);
    }
}
