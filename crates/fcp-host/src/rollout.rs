//! Host-side rollout control for staged connector deployments.
//!
//! This module bridges the generic lifecycle primitives in `fcp-kernel` with
//! host-observed health signals:
//! - registry self-check results
//! - connector availability/degradation status
//! - success/error-rate samples from live traffic
//! - process uptime and crash-loop detection
//!
//! The controller persists lifecycle state through the provided
//! [`fcp_kernel::LifecycleManager`] and emits deterministic evidence bundles for
//! each scheduling/evaluation decision.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use fcp_kernel::{
    CanaryPolicy, ConnectorHealth, ConnectorId, CrashLoopDetector, LifecycleError,
    LifecycleManager, LifecycleRecord, LifecycleState, SelfCheckReport, SelfCheckStatus,
    TransitionReason,
};
pub use fcp_kernel::{
    RolloutAuditEvent, RolloutDecision, RolloutEvidence, RolloutObservation, RolloutOutcome,
};
use fcp_prelude::RolloutPolicy;

use crate::{ConnectorRegistry, HostError, HostResult};

/// Configuration for rollout-controller health gating.
#[derive(Debug, Clone)]
pub struct RolloutControllerConfig {
    /// Minimum supervisor-observed uptime before auto-promotion is allowed.
    pub min_uptime_secs_for_promotion: u64,
    /// Whether connectors that do not implement self-check may still auto-promote.
    pub allow_unsupported_self_check_promotion: bool,
    /// Crash-loop threshold used by the host-side detector.
    pub crash_loop_threshold: usize,
    /// Crash-loop evaluation window in seconds.
    pub crash_loop_window_secs: i64,
}

impl Default for RolloutControllerConfig {
    fn default() -> Self {
        Self {
            min_uptime_secs_for_promotion: 60,
            allow_unsupported_self_check_promotion: true,
            crash_loop_threshold: 3,
            crash_loop_window_secs: 300,
        }
    }
}

/// Host-side controller that evaluates canary promotion/rollback decisions.
pub struct RolloutController<R, M> {
    registry: Arc<R>,
    lifecycle: Arc<M>,
    config: RolloutControllerConfig,
    state: Mutex<HashMap<ConnectorId, ConnectorRuntimeState>>,
}

impl<R, M> RolloutController<R, M>
where
    R: ConnectorRegistry,
    M: LifecycleManager,
{
    /// Create a new rollout controller with default configuration.
    #[must_use]
    pub fn new(registry: Arc<R>, lifecycle: Arc<M>) -> Self {
        Self::with_config(registry, lifecycle, RolloutControllerConfig::default())
    }

    /// Create a new rollout controller with explicit configuration.
    #[must_use]
    pub fn with_config(
        registry: Arc<R>,
        lifecycle: Arc<M>,
        config: RolloutControllerConfig,
    ) -> Self {
        Self {
            registry,
            lifecycle,
            config,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Start or re-enter a connector rollout in canary mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector is missing, the policy is invalid, or
    /// lifecycle persistence fails.
    #[allow(clippy::too_many_lines)]
    pub async fn schedule_canary(
        &self,
        connector_id: &ConnectorId,
        version: semver::Version,
        previous_version: Option<semver::Version>,
        policy: &RolloutPolicy,
        observed_at: DateTime<Utc>,
    ) -> HostResult<RolloutOutcome> {
        policy
            .validate()
            .map_err(|error| HostError::Internal(format!("invalid rollout policy: {error}")))?;
        if previous_version
            .as_ref()
            .is_some_and(|previous| previous == &version)
        {
            return Err(HostError::InvalidFilter(format!(
                "rollout previous_version `{version}` must differ from target version `{version}`"
            )));
        }

        let _summary = self
            .registry
            .get(connector_id)
            .await
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;

        let mut record = self
            .get_record(connector_id)
            .await?
            .unwrap_or_else(|| LifecycleRecord::new(connector_id.clone(), version.clone()));

        let state_before = record.state;
        let previous_recorded_version = record.version.clone();
        if previous_version.is_some() {
            record.previous_version = previous_version;
        } else if previous_recorded_version != version {
            record.previous_version = Some(previous_recorded_version.clone());
        }
        record.version = version.clone();
        record.canary_policy = to_canary_policy(policy);
        record.reset_health();

        transition_to_canary(
            &mut record,
            connector_id,
            &version,
            previous_recorded_version,
            observed_at,
        )?;

        self.lifecycle
            .save(&record)
            .await
            .map_err(map_lifecycle_error)?;
        self.reset_runtime_state(connector_id);

        let evidence = build_evidence(&BuildEvidenceInput {
            record: &record,
            state_before,
            decision: RolloutDecision::Scheduled,
            reason_code: "canary_scheduled",
            message: "connector scheduled in canary",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::unsupported(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 0,
            policy,
            observed_at,
        });
        let audit_event = build_audit_event(
            connector_id,
            state_before,
            record.state,
            RolloutDecision::Scheduled,
            &evidence,
        );

        tracing::info!(
            connector_id = %connector_id,
            decision = %RolloutDecision::Scheduled.as_str(),
            state_before = %state_before,
            state_after = %record.state,
            evidence_digest = %audit_event.evidence_digest,
            "rollout decision"
        );

        Ok(RolloutOutcome {
            record,
            decision: RolloutDecision::Scheduled,
            audit_event,
            evidence,
        })
    }

    /// Evaluate a single rollout observation and persist any transition.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector is unknown, the rollout policy is
    /// invalid, or the lifecycle manager rejects the transition/persistence.
    /// Rollback decisions are refused until verified runtime restoration is
    /// available; a lifecycle transition alone cannot restore an executable.
    #[allow(clippy::too_many_lines)]
    pub async fn evaluate(
        &self,
        connector_id: &ConnectorId,
        observation: RolloutObservation,
    ) -> HostResult<RolloutOutcome> {
        observation
            .policy
            .validate()
            .map_err(|error| HostError::Internal(format!("invalid rollout policy: {error}")))?;

        let summary = self
            .registry
            .get(connector_id)
            .await
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
        let self_check = self
            .registry
            .self_check(connector_id)
            .await
            .unwrap_or_else(SelfCheckReport::unsupported);

        let mut record = self
            .get_record(connector_id)
            .await?
            .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
        record.canary_policy = to_canary_policy(&observation.policy);
        record.update_health(observation.invocation_succeeded, observation.latency_ms);

        let runtime_state = self.update_runtime_state(connector_id, &observation);
        let state_before = record.state;
        let decision_plan = evaluate_decision(
            &record,
            &summary.health,
            &self_check,
            runtime_state.failure_streak,
            runtime_state.crash_loop_detected,
            &observation,
            &self.config,
        );

        let decision = match decision_plan.decision {
            RolloutDecision::Promote => {
                record
                    .transition(
                        LifecycleState::Production,
                        TransitionReason::AutoPromotion {
                            health_score: health_score_percent(record.health.success_rate),
                        },
                    )
                    .map_err(map_lifecycle_error)?;
                RolloutDecision::Promote
            }
            RolloutDecision::Rollback => {
                let target = record
                    .previous_version
                    .as_ref()
                    .ok_or_else(|| map_lifecycle_error(LifecycleError::NoRollbackTarget))?;
                // Registry discovery and lifecycle persistence cannot restore a
                // previous executable or its admitted inventory. Preserve the
                // deployed record instead of reporting a completed rollback.
                return Err(HostError::Unavailable(format!(
                    "connector '{connector_id}' requires rollback to v{target} ({}: {}), but verified executable and inventory restoration is unavailable; restore a verified prior deployment through managed inventory before rescheduling. Lifecycle state and version pins were not changed",
                    decision_plan.reason_code, decision_plan.message
                )));
            }
            RolloutDecision::Hold => RolloutDecision::Hold,
            RolloutDecision::Scheduled => RolloutDecision::Scheduled,
        };

        self.lifecycle
            .save(&record)
            .await
            .map_err(map_lifecycle_error)?;

        let evidence = build_evidence(&BuildEvidenceInput {
            record: &record,
            state_before,
            decision,
            reason_code: decision_plan.reason_code,
            message: &decision_plan.message,
            pinned: observation.pinned,
            crash_loop_detected: runtime_state.crash_loop_detected,
            failure_streak: runtime_state.failure_streak,
            self_check: &self_check,
            connector_health: &summary.health,
            uptime_secs: observation.uptime_secs,
            policy: &observation.policy,
            observed_at: observation.observed_at,
        });
        let audit_event = build_audit_event(
            connector_id,
            state_before,
            record.state,
            decision,
            &evidence,
        );

        tracing::info!(
            connector_id = %connector_id,
            decision = %decision.as_str(),
            state_before = %state_before,
            state_after = %record.state,
            success_rate_bps = evidence.success_rate_bps,
            error_rate_bps = evidence.error_rate_bps,
            failure_streak = evidence.failure_streak,
            crash_loop_detected = evidence.crash_loop_detected,
            evidence_digest = %audit_event.evidence_digest,
            "rollout decision"
        );

        Ok(RolloutOutcome {
            record,
            decision,
            audit_event,
            evidence,
        })
    }

    async fn get_record(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<LifecycleRecord>, HostError> {
        self.lifecycle
            .get(connector_id)
            .await
            .map_err(map_lifecycle_error)
    }

    #[allow(clippy::significant_drop_tightening)]
    fn update_runtime_state(
        &self,
        connector_id: &ConnectorId,
        observation: &RolloutObservation,
    ) -> RuntimeSnapshot {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            let entry =
                state
                    .entry(connector_id.clone())
                    .or_insert_with(|| ConnectorRuntimeState {
                        failure_streak: 0,
                        crash_detector: CrashLoopDetector::new(
                            self.config.crash_loop_threshold,
                            self.config.crash_loop_window_secs,
                        ),
                    });

            if observation.invocation_succeeded {
                entry.failure_streak = 0;
                entry.crash_detector.record_success();
            } else {
                entry.failure_streak = entry.failure_streak.saturating_add(1);
                if observation.crashed {
                    entry.crash_detector.record_crash(observation.observed_at);
                }
            }

            RuntimeSnapshot {
                failure_streak: entry.failure_streak,
                crash_loop_detected: observation.crashed
                    && entry.crash_detector.is_crash_loop(observation.observed_at),
            }
        }
    }

    fn reset_runtime_state(&self, connector_id: &ConnectorId) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(connector_id);
    }
}

#[derive(Debug, Clone)]
struct ConnectorRuntimeState {
    failure_streak: u32,
    crash_detector: CrashLoopDetector,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeSnapshot {
    failure_streak: u32,
    crash_loop_detected: bool,
}

#[derive(Debug, Clone)]
struct DecisionPlan {
    decision: RolloutDecision,
    reason_code: &'static str,
    message: String,
}

fn transition_to_canary(
    record: &mut LifecycleRecord,
    connector_id: &ConnectorId,
    version: &semver::Version,
    previous_recorded_version: semver::Version,
    observed_at: DateTime<Utc>,
) -> HostResult<()> {
    match record.state {
        LifecycleState::Pending => {
            record
                .transition(
                    LifecycleState::Installing,
                    TransitionReason::InstallComplete,
                )
                .map_err(map_lifecycle_error)?;
            record
                .transition(LifecycleState::Canary, canary_reason(None, version))
                .map_err(map_lifecycle_error)?;
        }
        LifecycleState::Installing => {
            record
                .transition(LifecycleState::Canary, canary_reason(None, version))
                .map_err(map_lifecycle_error)?;
        }
        LifecycleState::Production | LifecycleState::RolledBack | LifecycleState::Disabled => {
            let reason =
                (previous_recorded_version != *version).then_some(previous_recorded_version);
            record
                .transition(
                    LifecycleState::Canary,
                    canary_reason(reason.as_ref(), version),
                )
                .map_err(map_lifecycle_error)?;
        }
        LifecycleState::Canary => {
            record.state_changed_at = observed_at;
            if let Some(last_transition) = record.transitions.last_mut() {
                last_transition.timestamp = observed_at;
            }
        }
        LifecycleState::Uninstalled => {
            return Err(HostError::Unavailable(format!(
                "cannot schedule canary for uninstalled connector {connector_id}"
            )));
        }
    }
    record.state_changed_at = observed_at;
    if let Some(last_transition) = record.transitions.last_mut() {
        last_transition.timestamp = observed_at;
    }
    Ok(())
}

fn evaluate_decision(
    record: &LifecycleRecord,
    connector_health: &ConnectorHealth,
    self_check: &SelfCheckReport,
    failure_streak: u32,
    crash_loop_detected: bool,
    observation: &RolloutObservation,
    config: &RolloutControllerConfig,
) -> DecisionPlan {
    if record.state != LifecycleState::Canary {
        return DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "state_not_canary",
            message: format!("connector is in {} state", record.state),
        };
    }

    if let Some(plan) = check_rollback_conditions(
        record,
        connector_health,
        self_check,
        failure_streak,
        crash_loop_detected,
        observation,
    ) {
        return plan;
    }

    if let Some(plan) =
        check_hold_conditions(record, connector_health, self_check, observation, config)
    {
        return plan;
    }

    let error_rate_bps = error_rate_bps(record);
    let success_rate_bps = success_rate_bps(record);
    if success_rate_bps >= observation.policy.success_thresholds.min_success_rate_bps
        && error_rate_bps <= observation.policy.success_thresholds.max_error_rate_bps
    {
        return DecisionPlan {
            decision: RolloutDecision::Promote,
            reason_code: "promotion_thresholds_met",
            message: "canary met promotion success thresholds".to_string(),
        };
    }

    DecisionPlan {
        decision: RolloutDecision::Hold,
        reason_code: "promotion_thresholds_not_met",
        message: format!(
            "success rate {success_rate_bps}bps / error rate {error_rate_bps}bps did not satisfy promotion thresholds"
        ),
    }
}

fn check_rollback_conditions(
    record: &LifecycleRecord,
    connector_health: &ConnectorHealth,
    self_check: &SelfCheckReport,
    failure_streak: u32,
    crash_loop_detected: bool,
    observation: &RolloutObservation,
) -> Option<DecisionPlan> {
    if matches!(self_check.status, SelfCheckStatus::Failed) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "self_check_failed",
            message: explain_self_check(self_check),
        });
    }

    if matches!(connector_health, ConnectorHealth::Unavailable { .. }) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "connector_unavailable",
            message: connector_health_reason(connector_health)
                .unwrap_or_else(|| "connector became unavailable".to_string()),
        });
    }

    if crash_loop_detected {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "crash_loop_detected",
            message: "connector entered a crash loop during canary".to_string(),
        });
    }

    let error_rate_bps = error_rate_bps(record);
    let rules = &observation.policy.rollback_rules;
    if rules.auto_rollback
        && record.health.samples >= u64::from(rules.min_samples)
        && failure_streak >= rules.max_consecutive_failures
    {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "consecutive_failures_exceeded",
            message: format!(
                "failure streak {failure_streak} exceeded rollout limit {}",
                rules.max_consecutive_failures
            ),
        });
    }

    if rules.auto_rollback
        && record.health.samples >= u64::from(rules.min_samples)
        && error_rate_bps > rules.max_error_rate_bps
    {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "error_rate_exceeded",
            message: format!(
                "error rate {error_rate_bps}bps exceeded rollout limit {}bps",
                rules.max_error_rate_bps
            ),
        });
    }

    if record.canary_expires_in_secs_at(observation.observed_at) == Some(0) && rules.auto_rollback {
        return Some(DecisionPlan {
            decision: RolloutDecision::Rollback,
            reason_code: "canary_expired",
            message: "canary window expired before promotion thresholds were met".to_string(),
        });
    }

    None
}

fn check_hold_conditions(
    record: &LifecycleRecord,
    connector_health: &ConnectorHealth,
    self_check: &SelfCheckReport,
    observation: &RolloutObservation,
    config: &RolloutControllerConfig,
) -> Option<DecisionPlan> {
    if observation.pinned {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "pinned",
            message: "connector is pinned, auto-promotion is disabled".to_string(),
        });
    }

    if matches!(self_check.status, SelfCheckStatus::Degraded) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "self_check_degraded",
            message: explain_self_check(self_check),
        });
    }

    if matches!(connector_health, ConnectorHealth::Degraded { .. }) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "connector_degraded",
            message: connector_health_reason(connector_health)
                .unwrap_or_else(|| "connector is degraded".to_string()),
        });
    }

    if matches!(self_check.status, SelfCheckStatus::Unsupported)
        && !config.allow_unsupported_self_check_promotion
    {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "self_check_required",
            message: "self-check support is required before promotion".to_string(),
        });
    }

    if observation.uptime_secs < config.min_uptime_secs_for_promotion {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "uptime_too_low",
            message: format!(
                "uptime {}s is below promotion floor {}s",
                observation.uptime_secs, config.min_uptime_secs_for_promotion
            ),
        });
    }

    let canary_elapsed = canary_elapsed_secs(record, observation.observed_at).unwrap_or(0);
    if canary_elapsed < u64::from(observation.policy.min_canary_duration_secs) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "canary_duration_not_met",
            message: format!(
                "canary has only run for {canary_elapsed}s (minimum {}s)",
                observation.policy.min_canary_duration_secs
            ),
        });
    }

    if record.health.samples < u64::from(observation.policy.success_thresholds.min_samples) {
        return Some(DecisionPlan {
            decision: RolloutDecision::Hold,
            reason_code: "insufficient_samples",
            message: format!(
                "only {} samples collected (need at least {})",
                record.health.samples, observation.policy.success_thresholds.min_samples
            ),
        });
    }

    None
}

struct BuildEvidenceInput<'a> {
    record: &'a LifecycleRecord,
    state_before: LifecycleState,
    decision: RolloutDecision,
    reason_code: &'a str,
    message: &'a str,
    pinned: bool,
    crash_loop_detected: bool,
    failure_streak: u32,
    self_check: &'a SelfCheckReport,
    connector_health: &'a ConnectorHealth,
    uptime_secs: u64,
    policy: &'a RolloutPolicy,
    observed_at: DateTime<Utc>,
}

fn build_evidence(input: &BuildEvidenceInput<'_>) -> RolloutEvidence {
    let (connector_health_status, connector_health_reason) =
        connector_health_fields(input.connector_health);

    RolloutEvidence {
        connector_id: input.record.connector_id.clone(),
        state_before: input.state_before,
        state_after: input.record.state,
        decision: input.decision,
        reason_code: input.reason_code.to_string(),
        message: input.message.to_string(),
        pinned: input.pinned,
        crash_loop_detected: input.crash_loop_detected,
        failure_streak: input.failure_streak,
        self_check_status: input.self_check.status,
        self_check_reason_code: input.self_check.reason_code.clone(),
        connector_health_status,
        connector_health_reason,
        samples: input.record.health.samples,
        success_rate_bps: success_rate_bps(input.record),
        error_rate_bps: error_rate_bps(input.record),
        avg_latency_ms: input.record.health.avg_latency_ms(),
        max_latency_ms: input.record.health.max_latency_ms,
        uptime_secs: input.uptime_secs,
        canary_elapsed_secs: canary_elapsed_secs(input.record, input.observed_at),
        canary_expires_in_secs: input.record.canary_expires_in_secs_at(input.observed_at),
        promotion_threshold_bps: input.policy.success_thresholds.min_success_rate_bps,
        promotion_max_error_bps: input.policy.success_thresholds.max_error_rate_bps,
        promotion_min_samples: input.policy.success_thresholds.min_samples,
        rollback_max_error_bps: input.policy.rollback_rules.max_error_rate_bps,
        rollback_max_consecutive_failures: input.policy.rollback_rules.max_consecutive_failures,
        rollback_min_samples: input.policy.rollback_rules.min_samples,
        auto_rollback: input.policy.rollback_rules.auto_rollback,
        observed_at: input.observed_at,
    }
}

fn build_audit_event(
    connector_id: &ConnectorId,
    state_before: LifecycleState,
    state_after: LifecycleState,
    decision: RolloutDecision,
    evidence: &RolloutEvidence,
) -> RolloutAuditEvent {
    RolloutAuditEvent {
        connector_id: connector_id.clone(),
        state_before,
        state_after,
        decision,
        reason_code: evidence.reason_code.clone(),
        message: evidence.message.clone(),
        observed_at: evidence.observed_at,
        evidence_digest: evidence.digest(),
    }
}

fn canary_reason(
    previous_version: Option<&semver::Version>,
    version: &semver::Version,
) -> TransitionReason {
    previous_version.map_or(TransitionReason::InstallComplete, |prev| {
        TransitionReason::NewVersion {
            from_version: prev.to_string(),
            to_version: version.to_string(),
        }
    })
}

fn to_canary_policy(policy: &RolloutPolicy) -> CanaryPolicy {
    CanaryPolicy {
        promotion_threshold: percent_from_bps_ceil(policy.success_thresholds.min_success_rate_bps),
        rollback_threshold: 100u8.saturating_sub(percent_from_bps_ceil(
            policy.rollback_rules.max_error_rate_bps,
        )),
        min_samples: u64::from(policy.success_thresholds.min_samples),
        min_canary_duration_secs: policy.min_canary_duration_secs,
        max_canary_duration_secs: policy
            .min_canary_duration_secs
            .max(policy.success_thresholds.window_secs)
            .max(policy.rollback_rules.window_secs),
        canary_traffic_percent: policy.canary_percent,
    }
}

fn percent_from_bps_ceil(bps: u16) -> u8 {
    let percent = bps.min(10_000).div_ceil(100);
    u8::try_from(percent).unwrap_or(100)
}

fn success_rate_bps(record: &LifecycleRecord) -> u16 {
    if record.health.samples == 0 {
        return 10_000;
    }
    let numerator = u128::from(record.health.successes).saturating_mul(10_000);
    let rate = numerator / u128::from(record.health.samples);
    u16::try_from(rate.min(10_000)).unwrap_or(10_000)
}

fn error_rate_bps(record: &LifecycleRecord) -> u16 {
    if record.health.samples == 0 {
        return 0;
    }
    let numerator = u128::from(record.health.failures).saturating_mul(10_000);
    let rate = numerator / u128::from(record.health.samples);
    u16::try_from(rate.min(10_000)).unwrap_or(10_000)
}

fn health_score_percent(percent: u8) -> u8 {
    percent.min(100)
}

fn canary_elapsed_secs(record: &LifecycleRecord, now: DateTime<Utc>) -> Option<u64> {
    if record.state != LifecycleState::Canary {
        return None;
    }

    let start = record
        .transitions
        .iter()
        .rev()
        .find(|transition| transition.to == LifecycleState::Canary)
        .map_or(record.deployed_at, |transition| transition.timestamp);
    let elapsed = now.signed_duration_since(start).num_seconds().max(0);
    u64::try_from(elapsed).ok()
}

fn connector_health_fields(health: &ConnectorHealth) -> (String, Option<String>) {
    match health {
        ConnectorHealth::Healthy => ("healthy".to_string(), None),
        ConnectorHealth::Degraded { reason } => ("degraded".to_string(), Some(reason.clone())),
        ConnectorHealth::Unavailable { reason, .. } => {
            ("unavailable".to_string(), Some(reason.clone()))
        }
    }
}

fn connector_health_reason(health: &ConnectorHealth) -> Option<String> {
    connector_health_fields(health).1
}

fn explain_self_check(self_check: &SelfCheckReport) -> String {
    self_check
        .message
        .clone()
        .or_else(|| self_check.reason_code.clone())
        .unwrap_or_else(|| {
            format!(
                "self-check returned {}",
                self_check_status_label(self_check)
            )
        })
}

const fn self_check_status_label(self_check: &SelfCheckReport) -> &'static str {
    match self_check.status {
        SelfCheckStatus::Ok => "ok",
        SelfCheckStatus::Degraded => "degraded",
        SelfCheckStatus::Failed => "failed",
        SelfCheckStatus::Unsupported => "unsupported",
    }
}

fn map_lifecycle_error(error: LifecycleError) -> HostError {
    match error {
        LifecycleError::NotFound { connector_id } => {
            HostError::ConnectorNotFound(connector_id.to_string())
        }
        other => HostError::Internal(format!("lifecycle error: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use fcp_async_core::sync::RwLock;
    use fcp_kernel::{
        AgentHint, ApprovalMode, ConnectorId, IdempotencyClass, Introspection, LifecycleStatus,
        OperationId, OperationInfo, RateLimitDeclarations,
    };
    use fcp_prelude::{CapabilityId, RiskLevel, SafetyTier};

    fn connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test.rollout:utility:1.0.0")
    }

    fn rollout_policy() -> RolloutPolicy {
        RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(120)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(2000, 3, 3, 300, true))
            .build()
    }

    fn operation(id: &str) -> OperationInfo {
        OperationInfo {
            id: OperationId::new(id).expect("valid operation id"),
            summary: id.to_string(),
            description: Some(format!("{id} operation")),
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: serde_json::json!({"type":"object"}),
            capability: CapabilityId::new(format!("cap.{id}")).expect("valid cap"),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: id.to_string(),
                common_mistakes: vec![],
                examples: vec![],
                related: vec![],
            },
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        }
    }

    fn connector_summary(health: ConnectorHealth) -> crate::ConnectorSummary {
        crate::ConnectorSummary {
            id: connector_id(),
            name: "rollout-test".to_string(),
            description: Some("rollout test connector".to_string()),
            version: semver::Version::new(1, 0, 0),
            categories: vec!["test".to_string()],
            tool_count: 1,
            max_safety_tier: SafetyTier::Safe,
            enabled: true,
            health,
            last_health_check: Some(Utc::now()),
        }
    }

    fn introspection() -> Introspection {
        Introspection {
            operations: vec![operation("echo")],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        }
    }

    struct TestRegistry {
        summary: crate::ConnectorSummary,
        self_check: SelfCheckReport,
    }

    #[async_trait]
    impl ConnectorRegistry for TestRegistry {
        async fn list(&self) -> Vec<crate::ConnectorSummary> {
            vec![self.summary.clone()]
        }

        async fn get(&self, id: &ConnectorId) -> Option<crate::ConnectorSummary> {
            (&self.summary.id == id).then(|| self.summary.clone())
        }

        async fn get_introspection(&self, id: &ConnectorId) -> Option<Introspection> {
            (&self.summary.id == id).then(introspection)
        }

        async fn get_archetype(&self, id: &ConnectorId) -> Option<crate::ConnectorArchetype> {
            (&self.summary.id == id).then_some(crate::ConnectorArchetype::RequestResponse)
        }

        async fn get_rate_limits(&self, _id: &ConnectorId) -> Option<RateLimitDeclarations> {
            None
        }

        async fn self_check(&self, id: &ConnectorId) -> Option<SelfCheckReport> {
            (&self.summary.id == id).then(|| self.self_check.clone())
        }

        fn version(&self) -> u64 {
            1
        }
    }

    struct InMemoryLifecycleManager {
        records: RwLock<HashMap<ConnectorId, LifecycleRecord>>,
    }

    impl InMemoryLifecycleManager {
        fn new() -> Self {
            Self {
                records: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl LifecycleManager for InMemoryLifecycleManager {
        async fn get(
            &self,
            connector_id: &ConnectorId,
        ) -> Result<Option<LifecycleRecord>, LifecycleError> {
            Ok(self.records.read().await.get(connector_id).cloned())
        }

        async fn save(&self, record: &LifecycleRecord) -> Result<(), LifecycleError> {
            self.records
                .write()
                .await
                .insert(record.connector_id.clone(), record.clone());
            Ok(())
        }

        async fn promote(
            &self,
            connector_id: &ConnectorId,
        ) -> Result<LifecycleRecord, LifecycleError> {
            let mut records = self.records.write().await;
            let record = records
                .get_mut(connector_id)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: connector_id.clone(),
                })?;
            record.transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )?;
            Ok(record.clone())
        }

        async fn rollback(
            &self,
            connector_id: &ConnectorId,
            reason: Option<String>,
        ) -> Result<LifecycleRecord, LifecycleError> {
            let mut records = self.records.write().await;
            let record = records
                .get_mut(connector_id)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: connector_id.clone(),
                })?;
            record.transition(
                LifecycleState::RolledBack,
                TransitionReason::ManualRollback { reason },
            )?;
            Ok(record.clone())
        }

        async fn status(
            &self,
            connector_id: &ConnectorId,
        ) -> Result<LifecycleStatus, LifecycleError> {
            let records = self.records.read().await;
            let record = records
                .get(connector_id)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: connector_id.clone(),
                })?;
            Ok(LifecycleStatus::from_record(record, Utc::now(), false))
        }
    }

    async fn scheduled_record(
        registry: Arc<TestRegistry>,
        lifecycle: Arc<InMemoryLifecycleManager>,
        observed_at: DateTime<Utc>,
    ) -> RolloutController<TestRegistry, InMemoryLifecycleManager> {
        let controller = RolloutController::with_config(
            registry,
            lifecycle.clone(),
            RolloutControllerConfig {
                min_uptime_secs_for_promotion: 30,
                ..RolloutControllerConfig::default()
            },
        );

        controller
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 1, 0),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                observed_at,
            )
            .await
            .expect("canary should schedule");
        controller
    }

    #[fcp_async_core::runtime::test]
    async fn schedule_canary_transitions_to_canary() {
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = RolloutController::new(registry, lifecycle.clone());
        let observed_at = Utc::now();

        let outcome = controller
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 1, 0),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                observed_at,
            )
            .await
            .expect("schedule should succeed");

        assert_eq!(outcome.decision, RolloutDecision::Scheduled);
        assert_eq!(outcome.record.state, LifecycleState::Canary);
        assert_eq!(
            outcome.record.previous_version,
            Some(semver::Version::new(1, 0, 0))
        );
        assert_eq!(outcome.audit_event.reason_code, "canary_scheduled");
    }

    #[fcp_async_core::runtime::test]
    async fn healthy_canary_promotes_to_production() {
        let observed_at = Utc::now() - chrono::Duration::seconds(180);
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = scheduled_record(registry, lifecycle, observed_at).await;

        for _ in 0..4 {
            let _ = controller
                .evaluate(
                    &connector_id(),
                    RolloutObservation::new(true, rollout_policy())
                        .with_latency_ms(25)
                        .with_uptime_secs(180)
                        .observed_at(Utc::now()),
                )
                .await
                .expect("evaluation should succeed");
        }

        let outcome = controller
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy())
                    .with_latency_ms(30)
                    .with_uptime_secs(181)
                    .observed_at(Utc::now()),
            )
            .await
            .expect("final evaluation should succeed");

        assert_eq!(outcome.decision, RolloutDecision::Promote);
        assert_eq!(outcome.record.state, LifecycleState::Production);
        assert_eq!(outcome.audit_event.reason_code, "promotion_thresholds_met");
    }

    #[fcp_async_core::runtime::test]
    async fn pinned_canary_never_auto_promotes() {
        let observed_at = Utc::now() - chrono::Duration::seconds(180);
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = scheduled_record(registry, lifecycle, observed_at).await;

        for _ in 0..6 {
            let outcome = controller
                .evaluate(
                    &connector_id(),
                    RolloutObservation::new(true, rollout_policy())
                        .with_latency_ms(15)
                        .with_uptime_secs(200)
                        .pinned(true)
                        .observed_at(Utc::now()),
                )
                .await
                .expect("evaluation should succeed");
            assert_eq!(outcome.decision, RolloutDecision::Hold);
            assert_eq!(outcome.audit_event.reason_code, "pinned");
            assert_eq!(outcome.record.state, LifecycleState::Canary);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn failed_self_check_refuses_unavailable_runtime_rollback_without_mutation() {
        let observed_at = Utc::now() - chrono::Duration::seconds(180);
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::failed("self_check_failed", "database unavailable"),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = scheduled_record(registry, lifecycle.clone(), observed_at).await;
        let before = lifecycle
            .get(&connector_id())
            .await
            .expect("read lifecycle")
            .expect("scheduled record");

        let error = controller
            .evaluate(
                &connector_id(),
                RolloutObservation::new(false, rollout_policy())
                    .with_latency_ms(250)
                    .with_uptime_secs(180)
                    .observed_at(Utc::now()),
            )
            .await
            .expect_err("metadata cannot restore a runtime");

        assert!(matches!(
            error,
            HostError::Unavailable(message)
                if message.contains("self_check_failed")
                    && message.contains("v1.0.0")
                    && message.contains("verified executable and inventory restoration")
        ));
        let after = lifecycle
            .get(&connector_id())
            .await
            .expect("read preserved lifecycle")
            .expect("scheduled record remains");
        assert_eq!(after.state, LifecycleState::Canary);
        assert_eq!(
            serde_json::to_value(after).expect("serialize preserved record"),
            serde_json::to_value(before).expect("serialize original record")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn failure_streak_refuses_unavailable_runtime_rollback_without_mutation() {
        let observed_at = Utc::now() - chrono::Duration::seconds(180);
        let registry = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lifecycle = Arc::new(InMemoryLifecycleManager::new());
        let controller = scheduled_record(registry, lifecycle.clone(), observed_at).await;

        for _ in 0..2 {
            let outcome = controller
                .evaluate(
                    &connector_id(),
                    RolloutObservation::new(false, rollout_policy())
                        .with_latency_ms(500)
                        .with_uptime_secs(180)
                        .observed_at(Utc::now()),
                )
                .await
                .expect("observations below the rollback threshold should succeed");
            assert_eq!(outcome.decision, RolloutDecision::Hold);
        }
        let before = lifecycle
            .get(&connector_id())
            .await
            .expect("read lifecycle")
            .expect("scheduled record");
        let error = controller
            .evaluate(
                &connector_id(),
                RolloutObservation::new(false, rollout_policy())
                    .with_latency_ms(500)
                    .with_uptime_secs(180)
                    .observed_at(Utc::now()),
            )
            .await
            .expect_err("the rollback threshold cannot complete a runtime restore");
        assert!(matches!(
            error,
            HostError::Unavailable(message)
                if message.contains("consecutive_failures_exceeded")
                    && message.contains("managed inventory")
        ));
        let after = lifecycle
            .get(&connector_id())
            .await
            .expect("read preserved lifecycle")
            .expect("scheduled record remains");
        assert_eq!(after.state, LifecycleState::Canary);
        assert_eq!(
            serde_json::to_value(after).expect("serialize preserved record"),
            serde_json::to_value(before).expect("serialize original record")
        );
    }

    #[test]
    fn evidence_digest_is_deterministic() {
        let mut record = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .expect("pending -> installing");
        record
            .transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .expect("installing -> canary");

        let evidence_a = build_evidence(&BuildEvidenceInput {
            record: &record,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "insufficient_samples",
            message: "need more samples",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 90,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let evidence_b = evidence_a.clone();

        assert_eq!(evidence_a.digest(), evidence_b.digest());
    }

    #[test]
    fn default_config_values() {
        let c = RolloutControllerConfig::default();
        assert_eq!(c.min_uptime_secs_for_promotion, 60);
        assert!(c.allow_unsupported_self_check_promotion);
        assert_eq!(c.crash_loop_threshold, 3);
        assert_eq!(c.crash_loop_window_secs, 300);
    }

    #[test]
    fn config_clone_eq() {
        let c = RolloutControllerConfig {
            min_uptime_secs_for_promotion: 120,
            allow_unsupported_self_check_promotion: false,
            crash_loop_threshold: 5,
            crash_loop_window_secs: 600,
        };
        let d = c.clone();
        assert_eq!(
            c.min_uptime_secs_for_promotion,
            d.min_uptime_secs_for_promotion
        );
        assert_eq!(c.crash_loop_threshold, d.crash_loop_threshold);
    }

    #[test]
    fn observation_defaults() {
        let o = RolloutObservation::new(true, rollout_policy());
        assert!(o.invocation_succeeded);
        assert!(o.latency_ms.is_none());
        assert_eq!(o.uptime_secs, 0);
        assert!(!o.pinned);
        assert!(!o.crashed);
    }

    #[test]
    fn observation_builder() {
        let now = Utc::now();
        let o = RolloutObservation::new(false, rollout_policy())
            .with_latency_ms(42)
            .with_uptime_secs(100)
            .pinned(true)
            .crashed(true)
            .observed_at(now);
        assert_eq!(o.latency_ms, Some(42));
        assert_eq!(o.uptime_secs, 100);
        assert!(o.pinned);
        assert!(o.crashed);
        assert_eq!(o.observed_at, now);
    }

    #[test]
    fn decision_as_str_all() {
        assert_eq!(RolloutDecision::Scheduled.as_str(), "scheduled");
        assert_eq!(RolloutDecision::Hold.as_str(), "hold");
        assert_eq!(RolloutDecision::Promote.as_str(), "promote");
        assert_eq!(RolloutDecision::Rollback.as_str(), "rollback");
    }

    #[test]
    fn decision_serde() {
        for d in [
            RolloutDecision::Scheduled,
            RolloutDecision::Hold,
            RolloutDecision::Promote,
            RolloutDecision::Rollback,
        ] {
            let j = serde_json::to_string(&d).unwrap();
            assert_eq!(d, serde_json::from_str::<RolloutDecision>(&j).unwrap());
        }
    }

    #[test]
    fn bps_ceil_rounding() {
        assert_eq!(percent_from_bps_ceil(0), 0);
        assert_eq!(percent_from_bps_ceil(100), 1);
        assert_eq!(percent_from_bps_ceil(150), 2);
        assert_eq!(percent_from_bps_ceil(9500), 95);
        assert_eq!(percent_from_bps_ceil(10_000), 100);
        assert_eq!(percent_from_bps_ceil(10_001), 100);
    }

    #[test]
    fn rate_bps_zero_samples() {
        let r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        assert_eq!(success_rate_bps(&r), 10_000);
        assert_eq!(error_rate_bps(&r), 0);
    }

    #[test]
    fn rate_bps_with_data() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        for _ in 0..9 {
            r.update_health(true, Some(10));
        }
        r.update_health(false, Some(500));
        assert_eq!(success_rate_bps(&r), 9000);
        assert_eq!(error_rate_bps(&r), 1000);
    }

    #[test]
    fn health_score_clamp() {
        assert_eq!(health_score_percent(0), 0);
        assert_eq!(health_score_percent(100), 100);
        assert_eq!(health_score_percent(255), 100);
    }

    #[test]
    fn health_fields_variants() {
        let (s, r) = connector_health_fields(&ConnectorHealth::healthy());
        assert_eq!(s, "healthy");
        assert!(r.is_none());
        let (s, r) = connector_health_fields(&ConnectorHealth::Degraded {
            reason: "slow".into(),
        });
        assert_eq!(s, "degraded");
        assert_eq!(r.as_deref(), Some("slow"));
        let (s, r) = connector_health_fields(&ConnectorHealth::Unavailable {
            reason: "down".into(),
            since: Utc::now(),
        });
        assert_eq!(s, "unavailable");
        assert_eq!(r.as_deref(), Some("down"));
    }

    #[test]
    fn health_reason_none_healthy() {
        assert!(connector_health_reason(&ConnectorHealth::healthy()).is_none());
    }

    #[test]
    fn status_labels() {
        assert_eq!(self_check_status_label(&SelfCheckReport::ok()), "ok");
        assert_eq!(
            self_check_status_label(&SelfCheckReport::unsupported()),
            "unsupported"
        );
        assert_eq!(
            self_check_status_label(&SelfCheckReport::failed("c", "m")),
            "failed"
        );
    }

    #[test]
    fn explain_uses_message_then_code_then_label() {
        let r1 = SelfCheckReport::failed("code", "message");
        assert_eq!(explain_self_check(&r1), "message");
        let mut r2 = SelfCheckReport::failed("code", "m");
        r2.message = None;
        assert_eq!(explain_self_check(&r2), "code");
        let mut r3 = SelfCheckReport::failed("c", "m");
        r3.message = None;
        r3.reason_code = None;
        assert!(explain_self_check(&r3).contains("failed"));
    }

    #[test]
    fn lifecycle_error_mapping() {
        assert!(matches!(
            map_lifecycle_error(LifecycleError::NotFound {
                connector_id: connector_id()
            }),
            HostError::ConnectorNotFound(_)
        ));
        assert!(matches!(
            map_lifecycle_error(LifecycleError::NoRollbackTarget),
            HostError::Internal(_)
        ));
    }

    #[test]
    fn canary_reason_variants() {
        assert!(matches!(
            canary_reason(
                Some(&semver::Version::new(1, 0, 0)),
                &semver::Version::new(2, 0, 0)
            ),
            TransitionReason::NewVersion { .. }
        ));
        assert!(matches!(
            canary_reason(None, &semver::Version::new(2, 0, 0)),
            TransitionReason::InstallComplete
        ));
    }

    #[test]
    fn canary_policy_from_rollout() {
        let cp = to_canary_policy(&rollout_policy());
        assert_eq!(cp.canary_traffic_percent, 5);
        assert_eq!(cp.min_canary_duration_secs, 120);
        assert_eq!(cp.min_samples, 5);
    }

    #[test]
    fn evidence_roundtrip() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        r.transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "t",
            message: "t",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let j = serde_json::to_string(&e).unwrap();
        let d: RolloutEvidence = serde_json::from_str(&j).unwrap();
        assert_eq!(e.reason_code, d.reason_code);
    }

    #[test]
    fn evidence_digest_differs() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        r.transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        let now = Utc::now();
        let a = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "a",
            message: "a",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: now,
        });
        let b = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "b",
            message: "b",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: now,
        });
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn audit_event_digest_and_roundtrip() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        r.transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "t",
            message: "t",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let evt = build_audit_event(
            &connector_id(),
            LifecycleState::Canary,
            LifecycleState::Canary,
            RolloutDecision::Hold,
            &e,
        );
        assert!(evt.evidence_digest.starts_with("blake3-256:"));
        let j = serde_json::to_string(&evt).unwrap();
        let d: RolloutAuditEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(evt.reason_code, d.reason_code);
    }

    fn make_canary_record() -> LifecycleRecord {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.previous_version = Some(semver::Version::new(0, 9, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        r.transition(LifecycleState::Canary, TransitionReason::InstallComplete)
            .unwrap();
        r
    }

    #[test]
    fn eval_not_canary_holds() {
        let r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "state_not_canary");
    }

    #[test]
    fn eval_self_check_failed() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::failed("db", "database down"),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "self_check_failed");
    }

    #[test]
    fn eval_unavailable() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::Unavailable {
                reason: "x".into(),
                since: Utc::now(),
            },
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "connector_unavailable");
    }

    #[test]
    fn eval_crash_loop() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            true,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "crash_loop_detected");
    }

    #[test]
    fn eval_error_rate() {
        let mut r = make_canary_record();
        for _ in 0..5 {
            r.update_health(false, Some(100));
        }
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(false, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "error_rate_exceeded");
    }

    #[test]
    fn eval_pinned() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .pinned(true),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "pinned");
    }

    #[test]
    fn eval_degraded_self_check() {
        let r = make_canary_record();
        let mut sc = SelfCheckReport::ok();
        sc.status = SelfCheckStatus::Degraded;
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &sc,
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "self_check_degraded");
    }

    #[test]
    fn eval_degraded_connector() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::Degraded {
                reason: "mem".into(),
            },
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "connector_degraded");
    }

    #[test]
    fn eval_self_check_required() {
        let r = make_canary_record();
        let cfg = RolloutControllerConfig {
            allow_unsupported_self_check_promotion: false,
            ..RolloutControllerConfig::default()
        };
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::unsupported(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &cfg,
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "self_check_required");
    }

    #[test]
    fn eval_uptime_low() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(5),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "uptime_too_low");
    }

    #[test]
    fn canary_elapsed_non_canary_none() {
        let r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        assert!(canary_elapsed_secs(&r, Utc::now()).is_none());
    }

    #[test]
    fn canary_elapsed_positive() {
        let r = make_canary_record();
        assert!(canary_elapsed_secs(&r, Utc::now()).is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_schedule_from_production() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg.clone(), lm.clone());
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 0, 0),
            None,
            &rollout_policy(),
            Utc::now() - chrono::Duration::seconds(300),
        )
        .await
        .unwrap();
        lm.promote(&connector_id()).await.unwrap();
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 1, 0),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Scheduled);
        assert_eq!(o.record.state, LifecycleState::Canary);
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_unknown_connector_errs() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg, lm);
        let unk = ConnectorId::from_static("fcp.unknown:utility:1.0.0");
        assert!(
            ctrl.schedule_canary(
                &unk,
                semver::Version::new(1, 0, 0),
                None,
                &rollout_policy(),
                Utc::now()
            )
            .await
            .is_err()
        );
        assert!(
            ctrl.evaluate(&unk, RolloutObservation::new(true, rollout_policy()))
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_degraded_holds() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::Degraded {
                reason: "lat".into(),
            }),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm, t).await;
        let o = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy())
                    .with_uptime_secs(200)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Hold);
        assert_eq!(o.audit_event.reason_code, "connector_degraded");
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_unavailable_runtime_refuses_rollback_without_mutation() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::Unavailable {
                reason: "killed".into(),
                since: Utc::now(),
            }),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm.clone(), t).await;
        let before = lm
            .get(&connector_id())
            .await
            .expect("read lifecycle")
            .expect("scheduled record");
        let error = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(false, rollout_policy())
                    .with_uptime_secs(200)
                    .observed_at(Utc::now()),
            )
            .await
            .expect_err("an unavailable runtime cannot prove restoration");
        assert!(matches!(
            error,
            HostError::Unavailable(message)
                if message.contains("connector_unavailable")
                    && message.contains("verified executable and inventory restoration")
        ));
        let after = lm
            .get(&connector_id())
            .await
            .expect("read preserved lifecycle")
            .expect("scheduled record remains");
        assert_eq!(after.state, LifecycleState::Canary);
        assert_eq!(
            serde_json::to_value(after).expect("serialize preserved record"),
            serde_json::to_value(before).expect("serialize original record")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_uptime_low_holds() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm, t).await;
        let o = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy())
                    .with_uptime_secs(5)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Hold);
        assert_eq!(o.audit_event.reason_code, "uptime_too_low");
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_custom_config() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let cfg = RolloutControllerConfig {
            min_uptime_secs_for_promotion: 300,
            allow_unsupported_self_check_promotion: false,
            crash_loop_threshold: 5,
            crash_loop_window_secs: 600,
        };
        let ctrl = RolloutController::with_config(reg, lm, cfg);
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 0, 0),
                None,
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Scheduled);
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_reschedule_resets_health() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg.clone(), lm.clone());
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 0, 0),
            None,
            &rollout_policy(),
            Utc::now() - chrono::Duration::seconds(300),
        )
        .await
        .unwrap();
        let _ = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(false, rollout_policy())
                    .with_uptime_secs(50)
                    .observed_at(Utc::now()),
            )
            .await;
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 1, 0),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.record.health.samples, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_version_tracking() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg, lm);
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(2, 0, 0),
                Some(semver::Version::new(1, 5, 0)),
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.record.version, semver::Version::new(2, 0, 0));
        assert_eq!(
            o.record.previous_version,
            Some(semver::Version::new(1, 5, 0))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_schedule_from_rolled_back() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg.clone(), lm.clone());
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 0, 0),
            None,
            &rollout_policy(),
            Utc::now() - chrono::Duration::seconds(300),
        )
        .await
        .unwrap();
        lm.rollback(&connector_id(), Some("bad".into()))
            .await
            .unwrap();
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 0, 1),
                Some(semver::Version::new(1, 0, 0)),
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Scheduled);
        assert_eq!(o.record.state, LifecycleState::Canary);
    }

    #[test]
    fn evidence_fields_reflect_inputs() {
        let mut r = make_canary_record();
        for _ in 0..8 {
            r.update_health(true, Some(25));
        }
        for _ in 0..2 {
            r.update_health(false, Some(500));
        }
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "t",
            message: "t",
            pinned: true,
            crash_loop_detected: true,
            failure_streak: 7,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::Degraded {
                reason: "slow".into(),
            },
            uptime_secs: 42,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert!(e.pinned);
        assert!(e.crash_loop_detected);
        assert_eq!(e.failure_streak, 7);
        assert_eq!(e.uptime_secs, 42);
        assert_eq!(e.connector_health_status, "degraded");
        assert_eq!(e.success_rate_bps, 8000);
        assert_eq!(e.error_rate_bps, 2000);
        assert_eq!(e.samples, 10);
    }

    // ── RolloutDecision serde roundtrip for each variant ──────────────

    #[test]
    fn decision_serde_scheduled_json_value() {
        let j = serde_json::to_value(RolloutDecision::Scheduled).unwrap();
        assert_eq!(j, serde_json::json!("scheduled"));
    }

    #[test]
    fn decision_serde_hold_json_value() {
        let j = serde_json::to_value(RolloutDecision::Hold).unwrap();
        assert_eq!(j, serde_json::json!("hold"));
    }

    #[test]
    fn decision_serde_promote_json_value() {
        let j = serde_json::to_value(RolloutDecision::Promote).unwrap();
        assert_eq!(j, serde_json::json!("promote"));
    }

    #[test]
    fn decision_serde_rollback_json_value() {
        let j = serde_json::to_value(RolloutDecision::Rollback).unwrap();
        assert_eq!(j, serde_json::json!("rollback"));
    }

    #[test]
    fn decision_invalid_serde_string_rejected() {
        let result = serde_json::from_value::<RolloutDecision>(serde_json::json!("unknown"));
        assert!(result.is_err());
    }

    // ── RolloutDecision Clone / Copy / Debug / Eq ─────────────────────

    #[test]
    fn decision_clone_and_copy() {
        let d = RolloutDecision::Promote;
        let cloned = d;
        assert_eq!(d, cloned);
    }

    #[test]
    fn decision_debug_format() {
        let s = format!("{:?}", RolloutDecision::Rollback);
        assert!(s.contains("Rollback"));
    }

    #[test]
    fn decision_ne_different_variants() {
        assert_ne!(RolloutDecision::Hold, RolloutDecision::Promote);
        assert_ne!(RolloutDecision::Scheduled, RolloutDecision::Rollback);
    }

    // ── RolloutControllerConfig edge cases ────────────────────────────

    #[test]
    fn config_zero_uptime_threshold() {
        let c = RolloutControllerConfig {
            min_uptime_secs_for_promotion: 0,
            allow_unsupported_self_check_promotion: true,
            crash_loop_threshold: 1,
            crash_loop_window_secs: 1,
        };
        assert_eq!(c.min_uptime_secs_for_promotion, 0);
    }

    #[test]
    fn config_large_values() {
        let c = RolloutControllerConfig {
            min_uptime_secs_for_promotion: u64::MAX,
            allow_unsupported_self_check_promotion: false,
            crash_loop_threshold: usize::MAX,
            crash_loop_window_secs: i64::MAX,
        };
        assert_eq!(c.min_uptime_secs_for_promotion, u64::MAX);
        assert_eq!(c.crash_loop_threshold, usize::MAX);
    }

    #[test]
    fn config_debug_format() {
        let c = RolloutControllerConfig::default();
        let s = format!("{c:?}");
        assert!(s.contains("RolloutControllerConfig"));
        assert!(s.contains("60"));
    }

    // ── RolloutObservation builder edge cases ─────────────────────────

    #[test]
    fn observation_failed_invocation_defaults() {
        let o = RolloutObservation::new(false, rollout_policy());
        assert!(!o.invocation_succeeded);
        assert!(o.latency_ms.is_none());
        assert_eq!(o.uptime_secs, 0);
        assert!(!o.pinned);
        assert!(!o.crashed);
    }

    #[test]
    fn observation_zero_latency() {
        let o = RolloutObservation::new(true, rollout_policy()).with_latency_ms(0);
        assert_eq!(o.latency_ms, Some(0));
    }

    #[test]
    fn observation_max_latency() {
        let o = RolloutObservation::new(true, rollout_policy()).with_latency_ms(u32::MAX);
        assert_eq!(o.latency_ms, Some(u32::MAX));
    }

    #[test]
    fn observation_max_uptime() {
        let o = RolloutObservation::new(true, rollout_policy()).with_uptime_secs(u64::MAX);
        assert_eq!(o.uptime_secs, u64::MAX);
    }

    #[test]
    fn observation_clone_preserves_fields() {
        let now = Utc::now();
        let original = RolloutObservation::new(true, rollout_policy())
            .with_latency_ms(99)
            .with_uptime_secs(500)
            .pinned(true)
            .crashed(true)
            .observed_at(now);
        let cloned = original.clone();
        assert_eq!(original.latency_ms, cloned.latency_ms);
        assert_eq!(original.uptime_secs, cloned.uptime_secs);
        assert_eq!(original.pinned, cloned.pinned);
        assert_eq!(original.crashed, cloned.crashed);
        assert_eq!(original.observed_at, cloned.observed_at);
    }

    #[test]
    fn observation_debug_format() {
        let o = RolloutObservation::new(true, rollout_policy());
        let s = format!("{o:?}");
        assert!(s.contains("RolloutObservation"));
    }

    // ── percent_from_bps_ceil edge cases ──────────────────────────────

    #[test]
    fn bps_ceil_single_bps() {
        assert_eq!(percent_from_bps_ceil(1), 1);
    }

    #[test]
    fn bps_ceil_99_bps() {
        assert_eq!(percent_from_bps_ceil(99), 1);
    }

    #[test]
    fn bps_ceil_101_bps() {
        assert_eq!(percent_from_bps_ceil(101), 2);
    }

    #[test]
    fn bps_ceil_exact_boundaries() {
        for i in 0u16..=100 {
            let bps = i * 100;
            assert_eq!(percent_from_bps_ceil(bps), u8::try_from(i).unwrap());
        }
    }

    #[test]
    fn bps_ceil_u16_max_clamps_to_100() {
        assert_eq!(percent_from_bps_ceil(u16::MAX), 100);
    }

    // ── success_rate_bps / error_rate_bps detailed tests ──────────────

    #[test]
    fn rate_bps_all_successes() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        for _ in 0..100 {
            r.update_health(true, Some(10));
        }
        assert_eq!(success_rate_bps(&r), 10_000);
        assert_eq!(error_rate_bps(&r), 0);
    }

    #[test]
    fn rate_bps_all_failures() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        for _ in 0..100 {
            r.update_health(false, Some(10));
        }
        assert_eq!(success_rate_bps(&r), 0);
        assert_eq!(error_rate_bps(&r), 10_000);
    }

    #[test]
    fn rate_bps_single_success() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.update_health(true, Some(10));
        assert_eq!(success_rate_bps(&r), 10_000);
        assert_eq!(error_rate_bps(&r), 0);
    }

    #[test]
    fn rate_bps_single_failure() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.update_health(false, Some(10));
        assert_eq!(success_rate_bps(&r), 0);
        assert_eq!(error_rate_bps(&r), 10_000);
    }

    #[test]
    fn rate_bps_half_and_half() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        for _ in 0..50 {
            r.update_health(true, Some(10));
        }
        for _ in 0..50 {
            r.update_health(false, Some(10));
        }
        assert_eq!(success_rate_bps(&r), 5000);
        assert_eq!(error_rate_bps(&r), 5000);
    }

    // ── health_score_percent edge cases ───────────────────────────────

    #[test]
    fn health_score_mid_range() {
        assert_eq!(health_score_percent(50), 50);
    }

    #[test]
    fn health_score_one() {
        assert_eq!(health_score_percent(1), 1);
    }

    #[test]
    fn health_score_99() {
        assert_eq!(health_score_percent(99), 99);
    }

    #[test]
    fn health_score_101_clamps() {
        assert_eq!(health_score_percent(101), 100);
    }

    // ── connector_health_fields edge cases ────────────────────────────

    #[test]
    fn health_fields_degraded_empty_reason() {
        let (s, r) = connector_health_fields(&ConnectorHealth::Degraded {
            reason: String::new(),
        });
        assert_eq!(s, "degraded");
        assert_eq!(r.as_deref(), Some(""));
    }

    #[test]
    fn health_fields_unavailable_empty_reason() {
        let (s, r) = connector_health_fields(&ConnectorHealth::Unavailable {
            reason: String::new(),
            since: Utc::now(),
        });
        assert_eq!(s, "unavailable");
        assert_eq!(r.as_deref(), Some(""));
    }

    #[test]
    fn health_reason_degraded_returns_some() {
        let r = connector_health_reason(&ConnectorHealth::Degraded {
            reason: "latency".into(),
        });
        assert_eq!(r.as_deref(), Some("latency"));
    }

    #[test]
    fn health_reason_unavailable_returns_some() {
        let r = connector_health_reason(&ConnectorHealth::Unavailable {
            reason: "crash".into(),
            since: Utc::now(),
        });
        assert_eq!(r.as_deref(), Some("crash"));
    }

    // ── self_check_status_label all variants ──────────────────────────

    #[test]
    fn self_check_label_degraded() {
        let mut report = SelfCheckReport::ok();
        report.status = SelfCheckStatus::Degraded;
        assert_eq!(self_check_status_label(&report), "degraded");
    }

    // ── explain_self_check with details ───────────────────────────────

    #[test]
    fn explain_self_check_unsupported_fallback() {
        let mut r = SelfCheckReport::unsupported();
        r.message = None;
        r.reason_code = None;
        let msg = explain_self_check(&r);
        assert!(msg.contains("unsupported"));
    }

    #[test]
    fn explain_self_check_ok_no_message_no_code() {
        let r = SelfCheckReport::ok();
        let msg = explain_self_check(&r);
        assert!(msg.contains("ok"));
    }

    // ── map_lifecycle_error additional variants ───────────────────────

    #[test]
    fn lifecycle_error_invalid_transition() {
        let err = map_lifecycle_error(LifecycleError::InvalidTransition {
            from: LifecycleState::Pending,
            to: LifecycleState::Production,
        });
        assert!(matches!(err, HostError::Internal(_)));
    }

    #[test]
    fn lifecycle_error_invalid_policy() {
        let err = map_lifecycle_error(LifecycleError::InvalidPolicy {
            reason: "bad policy".to_string(),
        });
        assert!(matches!(err, HostError::Internal(_)));
        if let HostError::Internal(msg) = err {
            assert!(msg.contains("bad policy"));
        }
    }

    // ── canary_reason detailed checks ─────────────────────────────────

    #[test]
    fn canary_reason_new_version_contains_versions() {
        let reason = canary_reason(
            Some(&semver::Version::new(1, 0, 0)),
            &semver::Version::new(2, 0, 0),
        );
        if let TransitionReason::NewVersion {
            from_version,
            to_version,
        } = reason
        {
            assert_eq!(from_version, "1.0.0");
            assert_eq!(to_version, "2.0.0");
        } else {
            panic!("expected NewVersion variant");
        }
    }

    #[test]
    fn canary_reason_same_versions() {
        let reason = canary_reason(
            Some(&semver::Version::new(1, 0, 0)),
            &semver::Version::new(1, 0, 0),
        );
        if let TransitionReason::NewVersion {
            from_version,
            to_version,
        } = reason
        {
            assert_eq!(from_version, to_version);
        } else {
            panic!("expected NewVersion variant");
        }
    }

    // ── to_canary_policy detailed checks ──────────────────────────────

    #[test]
    fn canary_policy_max_duration_uses_largest_window() {
        let policy = RolloutPolicy::builder()
            .canary_percent(10)
            .min_canary_duration_secs(60)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 5, 600))
            .rollback_rules(fcp_core::RollbackRules::new(2000, 3, 3, 900, true))
            .build();
        let cp = to_canary_policy(&policy);
        // max_canary_duration_secs = max(60, 600, 900) = 900
        assert_eq!(cp.max_canary_duration_secs, 900);
    }

    #[test]
    fn canary_policy_promotion_threshold_ceil() {
        let policy = RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(60)
            .success_thresholds(fcp_core::SuccessThresholds::new(9550, 500, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(2000, 3, 3, 300, true))
            .build();
        let cp = to_canary_policy(&policy);
        // 9550 bps / 100 = 95.5 -> ceil = 96
        assert_eq!(cp.promotion_threshold, 96);
    }

    #[test]
    fn canary_policy_zero_canary_percent() {
        let policy = RolloutPolicy::builder()
            .canary_percent(0)
            .min_canary_duration_secs(60)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(2000, 3, 3, 300, true))
            .build();
        let cp = to_canary_policy(&policy);
        assert_eq!(cp.canary_traffic_percent, 0);
    }

    // ── canary_elapsed_secs edge cases ────────────────────────────────

    #[test]
    fn canary_elapsed_immediately_after_transition() {
        let r = make_canary_record();
        let elapsed = canary_elapsed_secs(&r, r.state_changed_at);
        assert_eq!(elapsed, Some(0));
    }

    #[test]
    fn canary_elapsed_in_past_returns_zero() {
        let r = make_canary_record();
        let past = r.state_changed_at - chrono::Duration::seconds(100);
        let elapsed = canary_elapsed_secs(&r, past);
        assert_eq!(elapsed, Some(0));
    }

    // ── RolloutEvidence serde roundtrip detailed ──────────────────────

    #[test]
    fn evidence_all_fields_roundtrip() {
        let now = Utc::now();
        let mut r = make_canary_record();
        for _ in 0..5 {
            r.update_health(true, Some(20));
        }
        for _ in 0..5 {
            r.update_health(false, Some(200));
        }
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Rollback,
            reason_code: "error_rate_exceeded",
            message: "error rate too high",
            pinned: true,
            crash_loop_detected: true,
            failure_streak: 5,
            self_check: &SelfCheckReport::failed("db", "database down"),
            connector_health: &ConnectorHealth::Unavailable {
                reason: "gone".into(),
                since: now,
            },
            uptime_secs: 999,
            policy: &rollout_policy(),
            observed_at: now,
        });
        let json_str = serde_json::to_string_pretty(&e).unwrap();
        let deserialized: RolloutEvidence = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.decision, RolloutDecision::Rollback);
        assert_eq!(deserialized.reason_code, "error_rate_exceeded");
        assert_eq!(deserialized.message, "error rate too high");
        assert!(deserialized.pinned);
        assert!(deserialized.crash_loop_detected);
        assert_eq!(deserialized.failure_streak, 5);
        assert_eq!(deserialized.self_check_status, SelfCheckStatus::Failed);
        assert_eq!(deserialized.self_check_reason_code.as_deref(), Some("db"));
        assert_eq!(deserialized.connector_health_status, "unavailable");
        assert_eq!(
            deserialized.connector_health_reason.as_deref(),
            Some("gone")
        );
        assert_eq!(deserialized.uptime_secs, 999);
        assert_eq!(deserialized.samples, 10);
        assert_eq!(deserialized.success_rate_bps, 5000);
        assert_eq!(deserialized.error_rate_bps, 5000);
    }

    #[test]
    fn evidence_digest_starts_with_blake3_prefix() {
        let r = make_canary_record();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let digest = e.digest();
        assert!(digest.starts_with("blake3-256:"));
        // blake3-256 hex digest is 64 chars after prefix
        let hex_part = digest.strip_prefix("blake3-256:").unwrap();
        assert_eq!(hex_part.len(), 64);
    }

    #[test]
    fn evidence_clone_preserves_digest() {
        let r = make_canary_record();
        let original = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let cloned = original.clone();
        assert_eq!(original.digest(), cloned.digest());
        assert_eq!(original.reason_code, cloned.reason_code);
    }

    // ── RolloutAuditEvent serde roundtrip ─────────────────────────────

    #[test]
    fn audit_event_full_roundtrip() {
        let now = Utc::now();
        let evt = RolloutAuditEvent {
            connector_id: connector_id(),
            state_before: LifecycleState::Canary,
            state_after: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "canary_scheduled".to_string(),
            message: "test".to_string(),
            observed_at: now,
            evidence_digest: "blake3-256:test".to_string(),
        };
        let j = serde_json::to_value(&evt).unwrap();
        let d: RolloutAuditEvent = serde_json::from_value(j).unwrap();
        assert_eq!(evt.connector_id, d.connector_id);
        assert_eq!(evt.state_before, d.state_before);
        assert_eq!(evt.state_after, d.state_after);
        assert_eq!(evt.decision, d.decision);
        assert_eq!(evt.reason_code, d.reason_code);
        assert_eq!(evt.message, d.message);
        assert_eq!(evt.evidence_digest, d.evidence_digest);
    }

    #[test]
    fn audit_event_debug_format() {
        let evt = RolloutAuditEvent {
            connector_id: connector_id(),
            state_before: LifecycleState::Canary,
            state_after: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "canary_scheduled".to_string(),
            message: "test".to_string(),
            observed_at: Utc::now(),
            evidence_digest: "blake3-256:test".to_string(),
        };
        let s = format!("{evt:?}");
        assert!(s.contains("RolloutAuditEvent"));
        assert!(s.contains("canary_scheduled"));
    }

    #[test]
    fn audit_event_clone_eq() {
        let evt = RolloutAuditEvent {
            connector_id: connector_id(),
            state_before: LifecycleState::Canary,
            state_after: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "canary_scheduled".to_string(),
            message: "test".to_string(),
            observed_at: Utc::now(),
            evidence_digest: "blake3-256:test".to_string(),
        };
        let cloned = evt.clone();
        assert_eq!(evt, cloned);
    }

    // ── RolloutOutcome serde roundtrip ────────────────────────────────

    #[test]
    fn outcome_serde_roundtrip() {
        let r = make_canary_record();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "t",
            message: "t",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let ae = build_audit_event(
            &connector_id(),
            LifecycleState::Canary,
            LifecycleState::Canary,
            RolloutDecision::Hold,
            &e,
        );
        let outcome = RolloutOutcome {
            record: r,
            decision: RolloutDecision::Hold,
            audit_event: ae,
            evidence: e,
        };
        let j = serde_json::to_string(&outcome).unwrap();
        let d: RolloutOutcome = serde_json::from_str(&j).unwrap();
        assert_eq!(d.decision, RolloutDecision::Hold);
    }

    #[test]
    fn outcome_debug_format() {
        let r = make_canary_record();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "t",
            message: "t",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let ae = build_audit_event(
            &connector_id(),
            LifecycleState::Canary,
            LifecycleState::Canary,
            RolloutDecision::Hold,
            &e,
        );
        let outcome = RolloutOutcome {
            record: r,
            decision: RolloutDecision::Hold,
            audit_event: ae,
            evidence: e,
        };
        let s = format!("{outcome:?}");
        assert!(s.contains("RolloutOutcome"));
    }

    // ── evaluate_decision: insufficient samples hold ──────────────────

    #[test]
    fn eval_insufficient_samples_holds() {
        let r = make_canary_record();
        // No samples recorded at all — below min_samples threshold
        let canary_start = r.state_changed_at;
        let later = canary_start + chrono::Duration::seconds(200);
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .observed_at(later),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "insufficient_samples");
    }

    // ── evaluate_decision: canary_duration_not_met ────────────────────

    #[test]
    fn eval_canary_duration_not_met_holds() {
        let mut r = make_canary_record();
        for _ in 0..10 {
            r.update_health(true, Some(10));
        }
        // Observation time is very close to canary start
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .observed_at(r.state_changed_at + chrono::Duration::seconds(5)),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "canary_duration_not_met");
    }

    // ── evaluate_decision: promotion when all thresholds met ──────────

    #[test]
    fn eval_promotion_thresholds_met() {
        let mut r = make_canary_record();
        for _ in 0..10 {
            r.update_health(true, Some(10));
        }
        let later = r.state_changed_at + chrono::Duration::seconds(300);
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .observed_at(later),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Promote);
        assert_eq!(p.reason_code, "promotion_thresholds_met");
    }

    // ── evaluate_decision: thresholds not met (mixed results) ─────────

    #[test]
    fn eval_promotion_thresholds_not_met_mixed_results() {
        let mut r = make_canary_record();
        // 7 success, 3 failure = 70% success < 95% threshold
        for _ in 0..7 {
            r.update_health(true, Some(10));
        }
        for _ in 0..3 {
            r.update_health(false, Some(10));
        }
        let later = r.state_changed_at + chrono::Duration::seconds(300);
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .observed_at(later),
            &RolloutControllerConfig::default(),
        );
        // Not enough for promotion, but error rate 3000bps > 2000bps rollback threshold
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "error_rate_exceeded");
    }

    // ── evaluate_decision: consecutive failures below threshold ────────

    #[test]
    fn eval_consecutive_failures_below_threshold_holds() {
        let mut r = make_canary_record();
        for _ in 0..5 {
            r.update_health(true, Some(10));
        }
        // failure_streak = 2, threshold is 3
        let later = r.state_changed_at + chrono::Duration::seconds(300);
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            2,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .observed_at(later),
            &RolloutControllerConfig::default(),
        );
        // 100% success rate, should promote
        assert_eq!(p.decision, RolloutDecision::Promote);
    }

    // ── evaluate_decision: auto_rollback disabled ─────────────────────

    #[test]
    fn eval_no_auto_rollback_despite_failures() {
        let mut r = make_canary_record();
        for _ in 0..5 {
            r.update_health(false, Some(100));
        }
        let policy = RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(120)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 3, 300))
            .rollback_rules(fcp_core::RollbackRules::new(2000, 3, 3, 300, false))
            .build();
        let later = r.state_changed_at + chrono::Duration::seconds(300);
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            5,
            false,
            &RolloutObservation::new(false, policy)
                .with_uptime_secs(200)
                .observed_at(later),
            &RolloutControllerConfig::default(),
        );
        // auto_rollback is false, so no rollback from error rate or consecutive failures
        // But promotion thresholds not met either (0% success rate)
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "promotion_thresholds_not_met");
    }

    // ── evaluate_decision priority: rollback > hold > promote ─────────

    #[test]
    fn eval_rollback_priority_over_hold_pinned() {
        let r = make_canary_record();
        // Self-check failed triggers rollback even if pinned
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::failed("x", "y"),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .pinned(true),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "self_check_failed");
    }

    #[test]
    fn eval_crash_loop_priority_over_degraded() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::Degraded {
                reason: "slow".into(),
            },
            &SelfCheckReport::ok(),
            0,
            true,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "crash_loop_detected");
    }

    // ── transition_to_canary for each starting state ──────────────────

    #[test]
    fn transition_from_pending_to_canary() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        let now = Utc::now();
        transition_to_canary(
            &mut r,
            &connector_id(),
            &semver::Version::new(1, 0, 0),
            semver::Version::new(1, 0, 0),
            now,
        )
        .unwrap();
        assert_eq!(r.state, LifecycleState::Canary);
    }

    #[test]
    fn transition_from_installing_to_canary() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        let now = Utc::now();
        transition_to_canary(
            &mut r,
            &connector_id(),
            &semver::Version::new(1, 0, 0),
            semver::Version::new(1, 0, 0),
            now,
        )
        .unwrap();
        assert_eq!(r.state, LifecycleState::Canary);
    }

    #[test]
    fn transition_from_canary_stays_canary() {
        let mut r = make_canary_record();
        let now = Utc::now();
        transition_to_canary(
            &mut r,
            &connector_id(),
            &semver::Version::new(1, 0, 0),
            semver::Version::new(1, 0, 0),
            now,
        )
        .unwrap();
        assert_eq!(r.state, LifecycleState::Canary);
        assert_eq!(r.state_changed_at, now);
    }

    #[test]
    fn transition_from_production_to_canary() {
        let mut r = make_canary_record();
        r.transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 99 },
        )
        .unwrap();
        let now = Utc::now();
        transition_to_canary(
            &mut r,
            &connector_id(),
            &semver::Version::new(2, 0, 0),
            semver::Version::new(1, 0, 0),
            now,
        )
        .unwrap();
        assert_eq!(r.state, LifecycleState::Canary);
    }

    #[test]
    fn transition_from_rolled_back_to_canary() {
        let mut r = make_canary_record();
        r.transition(
            LifecycleState::RolledBack,
            TransitionReason::ManualRollback { reason: None },
        )
        .unwrap();
        let now = Utc::now();
        transition_to_canary(
            &mut r,
            &connector_id(),
            &semver::Version::new(2, 0, 0),
            semver::Version::new(1, 0, 0),
            now,
        )
        .unwrap();
        assert_eq!(r.state, LifecycleState::Canary);
    }

    #[test]
    fn transition_from_uninstalled_errors() {
        let mut r = make_canary_record();
        r.transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 99 },
        )
        .unwrap();
        r.transition(
            LifecycleState::Uninstalled,
            TransitionReason::Disabled {
                reason: "cleanup".into(),
            },
        )
        .unwrap();
        let now = Utc::now();
        let result = transition_to_canary(
            &mut r,
            &connector_id(),
            &semver::Version::new(2, 0, 0),
            semver::Version::new(1, 0, 0),
            now,
        );
        assert!(result.is_err());
    }

    // ── build_evidence with various self_check statuses ───────────────

    #[test]
    fn evidence_with_degraded_self_check() {
        let r = make_canary_record();
        let sc = SelfCheckReport::degraded("slow_db", "database is slow");
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "self_check_degraded",
            message: "degraded",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &sc,
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert_eq!(e.self_check_status, SelfCheckStatus::Degraded);
        assert_eq!(e.self_check_reason_code.as_deref(), Some("slow_db"));
    }

    #[test]
    fn evidence_with_unsupported_self_check() {
        let r = make_canary_record();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::unsupported(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert_eq!(e.self_check_status, SelfCheckStatus::Unsupported);
        assert!(e.self_check_reason_code.is_some());
    }

    // ── build_audit_event fields ──────────────────────────────────────

    #[test]
    fn audit_event_captures_state_transitions() {
        let r = make_canary_record();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Pending,
            decision: RolloutDecision::Scheduled,
            reason_code: "canary_scheduled",
            message: "scheduled",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 0,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        let ae = build_audit_event(
            &connector_id(),
            LifecycleState::Pending,
            LifecycleState::Canary,
            RolloutDecision::Scheduled,
            &e,
        );
        assert_eq!(ae.state_before, LifecycleState::Pending);
        assert_eq!(ae.state_after, LifecycleState::Canary);
        assert_eq!(ae.decision, RolloutDecision::Scheduled);
        assert_eq!(ae.reason_code, "canary_scheduled");
        assert!(!ae.evidence_digest.is_empty());
    }

    // ── Evidence policy thresholds ────────────────────────────────────

    #[test]
    fn evidence_captures_policy_thresholds() {
        let r = make_canary_record();
        let policy = rollout_policy();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &policy,
            observed_at: Utc::now(),
        });
        assert_eq!(e.promotion_threshold_bps, 9500);
        assert_eq!(e.promotion_max_error_bps, 500);
        assert_eq!(e.promotion_min_samples, 5);
        assert_eq!(e.rollback_max_error_bps, 2000);
        assert_eq!(e.rollback_max_consecutive_failures, 3);
        assert_eq!(e.rollback_min_samples, 3);
        assert!(e.auto_rollback);
    }

    // ── Canary expiry in evidence ─────────────────────────────────────

    #[test]
    fn evidence_canary_elapsed_and_expires() {
        let r = make_canary_record();
        let later = r.state_changed_at + chrono::Duration::seconds(60);
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: later,
        });
        assert_eq!(e.canary_elapsed_secs, Some(60));
        assert!(e.canary_expires_in_secs.is_some());
    }

    // ── Evidence for non-canary state ─────────────────────────────────

    #[test]
    fn evidence_non_canary_no_elapsed() {
        let r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Pending,
            decision: RolloutDecision::Hold,
            reason_code: "state_not_canary",
            message: "not canary",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 0,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert!(e.canary_elapsed_secs.is_none());
        assert!(e.canary_expires_in_secs.is_none());
    }

    // ── Multiple lifecycle states in evaluate_decision ─────────────────

    #[test]
    fn eval_pending_state_holds() {
        let r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "state_not_canary");
    }

    #[test]
    fn eval_production_state_holds() {
        let mut r = make_canary_record();
        r.transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 99 },
        )
        .unwrap();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "state_not_canary");
    }

    #[test]
    fn eval_rolled_back_state_holds() {
        let mut r = make_canary_record();
        r.transition(
            LifecycleState::RolledBack,
            TransitionReason::ManualRollback { reason: None },
        )
        .unwrap();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "state_not_canary");
    }

    // ── NEW: canary_expired rollback path ───────────────────────────────

    #[test]
    fn eval_canary_expired_triggers_rollback() {
        let mut r = make_canary_record();
        for _ in 0..5 {
            r.update_health(true, Some(10));
        }
        // Set canary_policy so max_canary_duration_secs is the computed max
        let policy = rollout_policy();
        r.canary_policy = to_canary_policy(&policy);
        // Move time far past max canary duration
        let far_future = r.state_changed_at
            + chrono::Duration::seconds(i64::from(r.canary_policy.max_canary_duration_secs) + 1);
        // Use a policy where success thresholds are very high so promotion doesn't fire
        let strict_policy = RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(10)
            .success_thresholds(fcp_core::SuccessThresholds::new(10_000, 0, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(10_000, 100, 3, 300, true))
            .build();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, strict_policy)
                .with_uptime_secs(200)
                .observed_at(far_future),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "canary_expired");
    }

    #[test]
    fn eval_canary_expired_no_rollback_when_auto_rollback_off() {
        let mut r = make_canary_record();
        for _ in 0..5 {
            r.update_health(true, Some(10));
        }
        let policy = rollout_policy();
        r.canary_policy = to_canary_policy(&policy);
        let far_future = r.state_changed_at
            + chrono::Duration::seconds(i64::from(r.canary_policy.max_canary_duration_secs) + 1);
        let no_auto_policy = RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(10)
            .success_thresholds(fcp_core::SuccessThresholds::new(10_000, 0, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(10_000, 100, 3, 300, false))
            .build();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, no_auto_policy)
                .with_uptime_secs(200)
                .observed_at(far_future),
            &RolloutControllerConfig::default(),
        );
        // auto_rollback is false so canary expiry doesn't rollback
        assert_ne!(p.reason_code, "canary_expired");
    }

    // ── NEW: transition_to_canary from Disabled ─────────────────────────

    #[test]
    fn transition_from_disabled_to_canary() {
        let mut r = make_canary_record();
        r.transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 99 },
        )
        .unwrap();
        r.transition(
            LifecycleState::Disabled,
            TransitionReason::Disabled {
                reason: "maintenance".into(),
            },
        )
        .unwrap();
        let now = Utc::now();
        transition_to_canary(
            &mut r,
            &connector_id(),
            &semver::Version::new(2, 0, 0),
            semver::Version::new(1, 0, 0),
            now,
        )
        .unwrap();
        assert_eq!(r.state, LifecycleState::Canary);
        assert_eq!(r.state_changed_at, now);
    }

    // ── NEW: transition_to_canary version inference ─────────────────────

    #[test]
    fn transition_from_production_same_version_no_new_version_reason() {
        let mut r = make_canary_record();
        r.transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 99 },
        )
        .unwrap();
        let now = Utc::now();
        // Same version -> no previous_version in reason
        transition_to_canary(
            &mut r,
            &connector_id(),
            &semver::Version::new(1, 0, 0),
            semver::Version::new(1, 0, 0),
            now,
        )
        .unwrap();
        assert_eq!(r.state, LifecycleState::Canary);
    }

    #[test]
    fn transition_from_production_new_version_has_new_version_reason() {
        let mut r = make_canary_record();
        r.transition(
            LifecycleState::Production,
            TransitionReason::AutoPromotion { health_score: 99 },
        )
        .unwrap();
        let now = Utc::now();
        transition_to_canary(
            &mut r,
            &connector_id(),
            &semver::Version::new(2, 0, 0),
            semver::Version::new(1, 0, 0),
            now,
        )
        .unwrap();
        assert_eq!(r.state, LifecycleState::Canary);
        // Should have 4+ transitions now: pending->installing, installing->canary, canary->production, production->canary
        let last = r.transitions.last().unwrap();
        assert_eq!(last.to, LifecycleState::Canary);
    }

    // ── NEW: rate BPS edge cases ────────────────────────────────────────

    #[test]
    fn rate_bps_one_of_three() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.update_health(true, Some(10));
        r.update_health(false, Some(10));
        r.update_health(false, Some(10));
        // 1/3 = 3333 bps success, 2/3 = 6666 bps error
        assert_eq!(success_rate_bps(&r), 3333);
        assert_eq!(error_rate_bps(&r), 6666);
    }

    #[test]
    fn rate_bps_two_of_three() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.update_health(true, Some(10));
        r.update_health(true, Some(10));
        r.update_health(false, Some(10));
        assert_eq!(success_rate_bps(&r), 6666);
        assert_eq!(error_rate_bps(&r), 3333);
    }

    #[test]
    fn rate_bps_large_sample_count() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        for _ in 0..10_000 {
            r.update_health(true, Some(1));
        }
        for _ in 0..50 {
            r.update_health(false, Some(1));
        }
        // 10000/10050 ~= 9950 bps, 50/10050 ~= 49 bps
        let sr = success_rate_bps(&r);
        let er = error_rate_bps(&r);
        assert!(sr > 9900 && sr <= 10_000, "sr={sr}");
        assert!(er < 100, "er={er}");
    }

    // ── NEW: to_canary_policy rollback threshold computation ────────────

    #[test]
    fn canary_policy_rollback_threshold_computation() {
        let policy = RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(120)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(2000, 3, 3, 300, true))
            .build();
        let cp = to_canary_policy(&policy);
        // rollback_threshold = 100 - ceil(2000/100) = 100 - 20 = 80
        assert_eq!(cp.rollback_threshold, 80);
    }

    #[test]
    fn canary_policy_rollback_threshold_with_non_round_bps() {
        let policy = RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(60)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(1550, 3, 3, 300, true))
            .build();
        let cp = to_canary_policy(&policy);
        // 1550 bps -> ceil = 16% -> rollback_threshold = 100 - 16 = 84
        assert_eq!(cp.rollback_threshold, 84);
    }

    #[test]
    fn canary_policy_rollback_threshold_zero_error_rate() {
        let policy = RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(60)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(0, 3, 3, 300, true))
            .build();
        let cp = to_canary_policy(&policy);
        // 0 bps -> ceil = 0% -> rollback_threshold = 100 - 0 = 100
        assert_eq!(cp.rollback_threshold, 100);
    }

    #[test]
    fn canary_policy_rollback_threshold_max_error_rate() {
        let policy = RolloutPolicy::builder()
            .canary_percent(5)
            .min_canary_duration_secs(60)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(10_000, 3, 3, 300, true))
            .build();
        let cp = to_canary_policy(&policy);
        // 10000 bps -> ceil = 100% -> rollback_threshold = 100 - 100 = 0
        assert_eq!(cp.rollback_threshold, 0);
    }

    // ── NEW: canary_policy max_canary_duration_secs with min > window ───

    #[test]
    fn canary_policy_max_duration_uses_min_canary_when_largest() {
        let policy = RolloutPolicy::builder()
            .canary_percent(10)
            .min_canary_duration_secs(1000)
            .success_thresholds(fcp_core::SuccessThresholds::new(9500, 500, 5, 300))
            .rollback_rules(fcp_core::RollbackRules::new(2000, 3, 3, 200, true))
            .build();
        let cp = to_canary_policy(&policy);
        // max = max(1000, 300, 200) = 1000
        assert_eq!(cp.max_canary_duration_secs, 1000);
    }

    // ── NEW: evidence latency fields ────────────────────────────────────

    #[test]
    fn evidence_avg_latency_none_when_no_latency_data() {
        let r = make_canary_record();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert!(e.avg_latency_ms.is_none());
        assert_eq!(e.max_latency_ms, 0);
    }

    #[test]
    fn evidence_latency_fields_with_data() {
        let mut r = make_canary_record();
        r.update_health(true, Some(100));
        r.update_health(true, Some(300));
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert!(e.avg_latency_ms.is_some());
        assert!(e.max_latency_ms >= 300);
    }

    // ── NEW: evidence observed_at field ─────────────────────────────────

    #[test]
    fn evidence_observed_at_matches_input() {
        let r = make_canary_record();
        let fixed_time = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: fixed_time,
        });
        assert_eq!(e.observed_at, fixed_time);
    }

    // ── NEW: audit event observed_at from evidence ──────────────────────

    #[test]
    fn audit_event_observed_at_from_evidence() {
        let r = make_canary_record();
        let fixed_time = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: fixed_time,
        });
        let ae = build_audit_event(
            &connector_id(),
            LifecycleState::Canary,
            LifecycleState::Canary,
            RolloutDecision::Hold,
            &e,
        );
        assert_eq!(ae.observed_at, fixed_time);
    }

    // ── NEW: evidence connector_id matches record ───────────────────────

    #[test]
    fn evidence_connector_id_matches_record() {
        let r = make_canary_record();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert_eq!(e.connector_id, connector_id());
    }

    // ── NEW: evidence state_after reflects record ───────────────────────

    #[test]
    fn evidence_state_after_reflects_record_state() {
        let r = make_canary_record();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Pending,
            decision: RolloutDecision::Scheduled,
            reason_code: "canary_scheduled",
            message: "scheduled",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &SelfCheckReport::ok(),
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 0,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert_eq!(e.state_before, LifecycleState::Pending);
        assert_eq!(e.state_after, LifecycleState::Canary);
    }

    // ── NEW: rollback conditions with min_samples not met ───────────────

    #[test]
    fn eval_consecutive_failures_not_triggered_below_min_samples() {
        let r = make_canary_record();
        // No samples recorded, but failure_streak is high
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            100,
            false,
            &RolloutObservation::new(false, rollout_policy())
                .with_uptime_secs(200)
                .observed_at(r.state_changed_at + chrono::Duration::seconds(300)),
            &RolloutControllerConfig::default(),
        );
        // min_samples=3 in rollback_rules, but record has 0 samples
        // So consecutive_failures_exceeded won't fire, falls through to insufficient_samples hold
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "insufficient_samples");
    }

    #[test]
    fn eval_error_rate_not_triggered_below_min_samples() {
        let mut r = make_canary_record();
        // Only 2 samples (below rollback min_samples=3)
        r.update_health(false, Some(10));
        r.update_health(false, Some(10));
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(false, rollout_policy())
                .with_uptime_secs(200)
                .observed_at(r.state_changed_at + chrono::Duration::seconds(300)),
            &RolloutControllerConfig::default(),
        );
        // 2 < min_samples=3 for rollback, but also < min_samples=5 for promotion
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "insufficient_samples");
    }

    // ── NEW: rollback priority over hold conditions ─────────────────────

    #[test]
    fn eval_unavailable_priority_over_pinned() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::Unavailable {
                reason: "process died".into(),
                since: Utc::now(),
            },
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .pinned(true),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "connector_unavailable");
    }

    #[test]
    fn eval_self_check_failed_priority_over_crash_loop() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::failed("db_gone", "database is gone"),
            0,
            true,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        // self_check_failed is checked before crash_loop
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "self_check_failed");
    }

    #[test]
    fn eval_self_check_failed_priority_over_unavailable() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::Unavailable {
                reason: "dead".into(),
                since: Utc::now(),
            },
            &SelfCheckReport::failed("x", "y"),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Rollback);
        assert_eq!(p.reason_code, "self_check_failed");
    }

    // ── NEW: hold priority chain ────────────────────────────────────────

    #[test]
    fn eval_pinned_priority_over_degraded_self_check() {
        let r = make_canary_record();
        let mut sc = SelfCheckReport::ok();
        sc.status = SelfCheckStatus::Degraded;
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &sc,
            0,
            false,
            &RolloutObservation::new(true, rollout_policy())
                .with_uptime_secs(200)
                .pinned(true),
            &RolloutControllerConfig::default(),
        );
        // pinned is checked before degraded self_check
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "pinned");
    }

    #[test]
    fn eval_degraded_self_check_priority_over_degraded_connector() {
        let r = make_canary_record();
        let mut sc = SelfCheckReport::ok();
        sc.status = SelfCheckStatus::Degraded;
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::Degraded {
                reason: "slow".into(),
            },
            &sc,
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "self_check_degraded");
    }

    // ── NEW: map_lifecycle_error additional variants ─────────────────────

    #[test]
    fn lifecycle_error_persistence_maps_to_internal() {
        let err = map_lifecycle_error(LifecycleError::Persistence {
            reason: "disk full".to_string(),
        });
        assert!(matches!(err, HostError::Internal(_)));
        if let HostError::Internal(msg) = err {
            assert!(msg.contains("disk full"));
        }
    }

    #[test]
    fn lifecycle_error_no_rollback_target_maps_to_internal() {
        let err = map_lifecycle_error(LifecycleError::NoRollbackTarget);
        assert!(matches!(err, HostError::Internal(_)));
    }

    // ── NEW: percent_from_bps_ceil additional edge cases ─────────────────

    #[test]
    fn bps_ceil_50_bps() {
        assert_eq!(percent_from_bps_ceil(50), 1);
    }

    #[test]
    fn bps_ceil_200_bps() {
        assert_eq!(percent_from_bps_ceil(200), 2);
    }

    #[test]
    fn bps_ceil_9999_bps() {
        assert_eq!(percent_from_bps_ceil(9999), 100);
    }

    #[test]
    fn bps_ceil_9901_bps() {
        assert_eq!(percent_from_bps_ceil(9901), 100);
    }

    // ── NEW: self_check explain with ok status ──────────────────────────

    #[test]
    fn explain_self_check_with_message_set() {
        let mut r = SelfCheckReport::ok();
        r.message = Some("all good".into());
        assert_eq!(explain_self_check(&r), "all good");
    }

    #[test]
    fn explain_self_check_degraded_with_message() {
        let r = SelfCheckReport::degraded("slow", "running slowly");
        assert_eq!(explain_self_check(&r), "running slowly");
    }

    #[test]
    fn explain_self_check_degraded_no_message_uses_code() {
        let mut r = SelfCheckReport::degraded("slow", "running slowly");
        r.message = None;
        assert_eq!(explain_self_check(&r), "slow");
    }

    // ── NEW: canary_elapsed_secs with transition timestamp ──────────────

    #[test]
    fn canary_elapsed_uses_latest_canary_transition() {
        let mut r = make_canary_record();
        // Backdate the canary transition to a known time
        let base = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        if let Some(last) = r.transitions.last_mut() {
            last.timestamp = base;
        }
        let check_at = base + chrono::Duration::seconds(42);
        let elapsed = canary_elapsed_secs(&r, check_at);
        assert_eq!(elapsed, Some(42));
    }

    #[test]
    fn canary_elapsed_large_duration() {
        let mut r = make_canary_record();
        let base = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        if let Some(last) = r.transitions.last_mut() {
            last.timestamp = base;
        }
        let check_at = base + chrono::Duration::seconds(86_400);
        let elapsed = canary_elapsed_secs(&r, check_at);
        assert_eq!(elapsed, Some(86_400));
    }

    // ── NEW: controller async tests ─────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn ctrl_schedule_without_previous_version_infers_from_record() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg.clone(), lm.clone());
        // First schedule with version 1.0.0
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 0, 0),
            None,
            &rollout_policy(),
            Utc::now() - chrono::Duration::seconds(300),
        )
        .await
        .unwrap();
        // Second schedule with version 2.0.0, no explicit previous_version
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(2, 0, 0),
                None,
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(o.record.version, semver::Version::new(2, 0, 0));
        assert_eq!(
            o.record.previous_version,
            Some(semver::Version::new(1, 0, 0))
        );
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_schedule_same_version_no_previous() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg.clone(), lm.clone());
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 0, 0),
            None,
            &rollout_policy(),
            Utc::now() - chrono::Duration::seconds(300),
        )
        .await
        .unwrap();
        // Re-schedule same version, no previous_version
        let o = ctrl
            .schedule_canary(
                &connector_id(),
                semver::Version::new(1, 0, 0),
                None,
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .unwrap();
        // Same version -> previous_version should not be set (version == recorded)
        assert!(o.record.previous_version.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_schedule_rejects_matching_previous_version() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg, lm);
        let version = semver::Version::new(1, 0, 0);

        let err = ctrl
            .schedule_canary(
                &connector_id(),
                version.clone(),
                Some(version.clone()),
                &rollout_policy(),
                Utc::now(),
            )
            .await
            .expect_err("matching previous_version should be rejected");

        assert!(matches!(
            err,
            HostError::InvalidFilter(message)
                if message.contains("must differ from target version")
                    && message.contains(&version.to_string())
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_evaluate_resets_failure_streak_on_success() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        // Isolate the streak gate: aggregate error rate must not request a
        // rollback before this test can observe the reset after a success.
        let mut policy = rollout_policy();
        policy.rollback_rules.max_error_rate_bps = 10_000;
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm, t).await;
        // Send 2 failures
        for _ in 0..2 {
            let _ = ctrl
                .evaluate(
                    &connector_id(),
                    RolloutObservation::new(false, policy.clone())
                        .with_uptime_secs(180)
                        .observed_at(Utc::now()),
                )
                .await
                .unwrap();
        }
        // Send 1 success to reset streak
        let _ = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, policy.clone())
                    .with_uptime_secs(180)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        // Send one more failure; the successful sample restarted the streak.
        let o = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(false, policy)
                    .with_uptime_secs(180)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(o.evidence.failure_streak, 1);
        assert_eq!(o.decision, RolloutDecision::Hold);
        assert_eq!(o.record.state, LifecycleState::Canary);
        assert_ne!(o.audit_event.reason_code, "consecutive_failures_exceeded");
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_evaluate_no_record_errors() {
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::new(reg, lm);
        // Evaluate without scheduling first — should fail with ConnectorNotFound
        let result = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy()),
            )
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_rollback_without_previous_version_errors() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::failed("x", "y"),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        // Schedule without a previous_version (first deploy, same version)
        let ctrl = RolloutController::with_config(
            reg,
            lm.clone(),
            RolloutControllerConfig {
                min_uptime_secs_for_promotion: 30,
                ..RolloutControllerConfig::default()
            },
        );
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 0, 0),
            None,
            &rollout_policy(),
            t,
        )
        .await
        .unwrap();
        // Force remove previous_version from the saved record
        {
            let mut records = lm.records.write().await;
            if let Some(rec) = records.get_mut(&connector_id()) {
                rec.previous_version = None;
            }
        }
        // Evaluate with self-check failed -> rollback path, but no rollback target
        let result = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(false, rollout_policy())
                    .with_uptime_secs(200)
                    .observed_at(Utc::now()),
            )
            .await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_self_check_unsupported_promotes_when_allowed() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::unsupported(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm, t).await;
        // With allow_unsupported_self_check_promotion=true (default),
        // unsupported self-check should not block promotion
        for _ in 0..4 {
            let _ = ctrl
                .evaluate(
                    &connector_id(),
                    RolloutObservation::new(true, rollout_policy())
                        .with_latency_ms(10)
                        .with_uptime_secs(200)
                        .observed_at(Utc::now()),
                )
                .await
                .unwrap();
        }
        let o = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy())
                    .with_latency_ms(10)
                    .with_uptime_secs(200)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(o.decision, RolloutDecision::Promote);
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_self_check_unsupported_holds_when_not_allowed() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::unsupported(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = RolloutController::with_config(
            reg,
            lm.clone(),
            RolloutControllerConfig {
                min_uptime_secs_for_promotion: 30,
                allow_unsupported_self_check_promotion: false,
                ..RolloutControllerConfig::default()
            },
        );
        ctrl.schedule_canary(
            &connector_id(),
            semver::Version::new(1, 1, 0),
            Some(semver::Version::new(1, 0, 0)),
            &rollout_policy(),
            t,
        )
        .await
        .unwrap();
        for _ in 0..6 {
            let o = ctrl
                .evaluate(
                    &connector_id(),
                    RolloutObservation::new(true, rollout_policy())
                        .with_latency_ms(10)
                        .with_uptime_secs(200)
                        .observed_at(Utc::now()),
                )
                .await
                .unwrap();
            assert_eq!(o.decision, RolloutDecision::Hold);
            assert_eq!(o.audit_event.reason_code, "self_check_required");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_evidence_has_correct_self_check_status() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::degraded("slow_db", "database is slow"),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm, t).await;
        let o = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy())
                    .with_uptime_secs(200)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(o.evidence.self_check_status, SelfCheckStatus::Degraded);
        assert_eq!(
            o.evidence.self_check_reason_code.as_deref(),
            Some("slow_db")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn ctrl_outcome_evidence_digest_matches_audit() {
        let t = Utc::now() - chrono::Duration::seconds(180);
        let reg = Arc::new(TestRegistry {
            summary: connector_summary(ConnectorHealth::healthy()),
            self_check: SelfCheckReport::ok(),
        });
        let lm = Arc::new(InMemoryLifecycleManager::new());
        let ctrl = scheduled_record(reg, lm, t).await;
        let o = ctrl
            .evaluate(
                &connector_id(),
                RolloutObservation::new(true, rollout_policy())
                    .with_uptime_secs(200)
                    .observed_at(Utc::now()),
            )
            .await
            .unwrap();
        assert_eq!(o.audit_event.evidence_digest, o.evidence.digest());
    }

    // ── NEW: observation not crashed not pinned explicit ─────────────────

    #[test]
    fn observation_pinned_false_then_true() {
        let o = RolloutObservation::new(true, rollout_policy())
            .pinned(false)
            .pinned(true);
        assert!(o.pinned);
    }

    #[test]
    fn observation_crashed_false_then_true() {
        let o = RolloutObservation::new(true, rollout_policy())
            .crashed(false)
            .crashed(true);
        assert!(o.crashed);
    }

    // ── NEW: decision equality exhaustive ────────────────────────────────

    #[test]
    fn decision_eq_reflexive() {
        for d in [
            RolloutDecision::Scheduled,
            RolloutDecision::Hold,
            RolloutDecision::Promote,
            RolloutDecision::Rollback,
        ] {
            assert_eq!(d, d);
        }
    }

    // ── NEW: evidence with failed self_check_status ─────────────────────

    #[test]
    fn evidence_with_failed_self_check() {
        let r = make_canary_record();
        let sc = SelfCheckReport::failed("conn_fail", "connection refused");
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Rollback,
            reason_code: "self_check_failed",
            message: "connection refused",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &sc,
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert_eq!(e.self_check_status, SelfCheckStatus::Failed);
        assert_eq!(e.self_check_reason_code.as_deref(), Some("conn_fail"));
        assert_eq!(e.decision, RolloutDecision::Rollback);
    }

    // ── NEW: evidence with ok self_check has reason_code ─────────────────

    #[test]
    fn evidence_with_ok_self_check_reason() {
        let r = make_canary_record();
        let sc = SelfCheckReport::ok();
        let e = build_evidence(&BuildEvidenceInput {
            record: &r,
            state_before: LifecycleState::Canary,
            decision: RolloutDecision::Hold,
            reason_code: "test",
            message: "test",
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check: &sc,
            connector_health: &ConnectorHealth::healthy(),
            uptime_secs: 60,
            policy: &rollout_policy(),
            observed_at: Utc::now(),
        });
        assert_eq!(e.self_check_status, SelfCheckStatus::Ok);
    }

    // ── NEW: eval with installing state ──────────────────────────────────

    #[test]
    fn eval_installing_state_holds() {
        let mut r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        r.transition(
            LifecycleState::Installing,
            TransitionReason::InstallComplete,
        )
        .unwrap();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.decision, RolloutDecision::Hold);
        assert_eq!(p.reason_code, "state_not_canary");
    }

    // ── NEW: eval rollback message content ──────────────────────────────

    #[test]
    fn eval_crash_loop_message_content() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            true,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert!(p.message.contains("crash loop"));
    }

    #[test]
    fn eval_unavailable_message_uses_reason() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::Unavailable {
                reason: "OOM killed".into(),
                since: Utc::now(),
            },
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert!(p.message.contains("OOM killed"));
    }

    #[test]
    fn eval_consecutive_failures_message_includes_streak() {
        let mut r = make_canary_record();
        for _ in 0..5 {
            r.update_health(true, Some(10));
        }
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            10,
            false,
            &RolloutObservation::new(false, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert_eq!(p.reason_code, "consecutive_failures_exceeded");
        assert!(p.message.contains("10"));
    }

    #[test]
    fn eval_uptime_message_includes_values() {
        let r = make_canary_record();
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(5),
            &RolloutControllerConfig::default(),
        );
        assert!(p.message.contains("5s"));
        assert!(p.message.contains("60s"));
    }

    #[test]
    fn eval_state_not_canary_message_includes_state() {
        let r = LifecycleRecord::new(connector_id(), semver::Version::new(1, 0, 0));
        let p = evaluate_decision(
            &r,
            &ConnectorHealth::healthy(),
            &SelfCheckReport::ok(),
            0,
            false,
            &RolloutObservation::new(true, rollout_policy()).with_uptime_secs(200),
            &RolloutControllerConfig::default(),
        );
        assert!(p.message.contains("pending"));
    }
}
