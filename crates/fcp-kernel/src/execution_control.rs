//! Canonical execution-control types shared across host and operator surfaces.

use blake3::hash;
use chrono::{DateTime, Utc};
use fcp_core::{
    CapabilityToken, ConnectorId, LifecycleRecord, LifecycleState, RolloutPolicy, SelfCheckStatus,
};
use serde::{Deserialize, Serialize};

/// Why an operation was cancelled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CancelReason {
    /// User explicitly requested cancellation.
    UserRequested,
    /// Agent detected an issue and is aborting.
    AgentAbort {
        /// Reason for the abort.
        reason: String,
    },
    /// Approaching timeout, requesting graceful shutdown.
    TimeoutApproaching {
        /// Milliseconds remaining before hard timeout.
        remaining_ms: u64,
    },
    /// Resource limit approaching.
    ResourceLimit {
        /// Which resource is constrained.
        resource: String,
        /// Current usage.
        current: u64,
        /// Limit threshold.
        limit: u64,
    },
    /// Superseded by another operation.
    Superseded {
        /// ID of the superseding operation.
        by_operation_id: String,
    },
    /// Session or connection is closing.
    SessionClosing,
}

impl CancelReason {
    /// Human-readable label for this reason category.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::UserRequested => "user_requested",
            Self::AgentAbort { .. } => "agent_abort",
            Self::TimeoutApproaching { .. } => "timeout_approaching",
            Self::ResourceLimit { .. } => "resource_limit",
            Self::Superseded { .. } => "superseded",
            Self::SessionClosing => "session_closing",
        }
    }
}

/// How cleanup should be handled after cancellation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CleanupBehavior {
    /// Best-effort cleanup; may leave partial state.
    #[default]
    BestEffort,
    /// Must fully clean up before returning (bounded by timeout).
    Full {
        /// Maximum time to spend on cleanup.
        timeout_ms: u64,
    },
    /// No cleanup; abandon immediately and return.
    Abandon,
    /// Checkpoint state for potential resume later.
    Checkpoint,
}

/// Unit of measurement for progress values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressUnit {
    /// Byte count.
    Bytes,
    /// Item count.
    Items,
    /// HTTP request count.
    Requests,
    /// Database row count.
    Rows,
    /// Custom unit with a label.
    Custom(String),
}

impl ProgressUnit {
    /// Human-readable label for this unit.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Bytes => "bytes",
            Self::Items => "items",
            Self::Requests => "requests",
            Self::Rows => "rows",
            Self::Custom(label) => label,
        }
    }
}

/// A snapshot of progress for an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressUpdate {
    /// Current phase name (e.g. "uploading", "verifying").
    pub phase: String,
    /// Current progress value.
    pub current: u64,
    /// Total expected value (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// Unit of measurement.
    pub unit: ProgressUnit,
    /// Computed percentage (0.0–100.0), if total is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage: Option<f64>,
    /// Rate per second (in the same unit), if calculable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<u64>,
    /// Estimated time remaining in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_ms: Option<u64>,
    /// Human-readable status message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ProgressUpdate {
    /// Compute percentage from current/total if total is known and non-zero.
    #[must_use]
    pub fn computed_percentage(&self) -> Option<f64> {
        self.total.and_then(|total| {
            if total == 0 {
                None
            } else {
                #[allow(clippy::cast_precision_loss)]
                Some(self.current as f64 / total as f64 * 100.0)
            }
        })
    }

    /// Whether progress is indeterminate (total unknown).
    #[must_use]
    pub const fn is_indeterminate(&self) -> bool {
        self.total.is_none()
    }

    /// Whether the operation has reached completion.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.total.is_some_and(|total| self.current >= total)
    }
}

/// Current state of a cancellation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationOutcome {
    /// Operation was successfully cancelled.
    Cancelled,
    /// Operation had already completed before cancellation arrived.
    TooLate,
    /// Cancellation is in progress (cleanup running).
    Pending,
    /// Cancellation failed (operation could not be stopped).
    Failed,
}

/// A request to cancel an in-flight operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationRequest {
    /// ID of the operation to cancel.
    pub operation_id: String,
    /// Why the operation is being cancelled.
    pub reason: CancelReason,
    /// How cleanup should be handled.
    #[serde(default)]
    pub cleanup: CleanupBehavior,
    /// Whether to return partial results if available.
    #[serde(default)]
    pub return_partial: bool,
    /// Verified capability token for owner-scoped self-cancel.
    ///
    /// Admin/operator cancel paths may omit this and rely on their
    /// out-of-band admin authentication instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,
}

/// Result of a cancellation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationResponse {
    /// ID of the cancelled operation.
    pub operation_id: String,
    /// Outcome of the cancellation attempt.
    pub outcome: CancellationOutcome,
    /// Partial results if available and requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_result: Option<PartialResult>,
    /// Checkpoint info if checkpoint cleanup was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointInfo>,
    /// Cleanup summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_result: Option<CleanupResult>,
    /// Duration of the cancellation process in milliseconds.
    pub duration_ms: u64,
}

/// Partial results from a cancelled operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialResult {
    /// Number of items completed before cancellation.
    pub completed_items: u64,
    /// Total items expected (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items: Option<u64>,
    /// The partial output data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Checkpoint information for resumable operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointInfo {
    /// Checkpoint ID for resume.
    pub id: String,
    /// Whether this checkpoint can be used to resume.
    pub resumable: bool,
    /// When the checkpoint expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Opaque state for the connector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<serde_json::Value>,
}

/// Summary of cleanup after cancellation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupResult {
    /// Whether cleanup completed successfully.
    pub success: bool,
    /// Resources that were cleaned up.
    pub cleaned: Vec<String>,
    /// Resources that could not be cleaned up.
    pub failed: Vec<String>,
    /// Duration of cleanup in milliseconds.
    pub duration_ms: u64,
}

/// Audit event for a cancellation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancellationAuditEvent {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Operation that was cancelled.
    pub operation_id: String,
    /// Reason for cancellation.
    pub reason: CancelReason,
    /// Outcome of the cancellation.
    pub outcome: CancellationOutcome,
    /// Duration of the cancellation process.
    pub duration_ms: u64,
    /// Whether partial results were returned.
    pub had_partial_result: bool,
    /// Whether a checkpoint was created.
    pub had_checkpoint: bool,
    /// Whether the supervisor force-terminated the operation's connector
    /// subprocess because the cancellation deadline expired without the
    /// operation completing (`flywheel_connectors-861lx`). Always `false`
    /// for graceful cancellations.
    #[serde(default)]
    pub forced: bool,
}

/// A transition between phases of a multi-step operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTransition {
    /// Phase being exited.
    pub from_phase: String,
    /// Phase being entered.
    pub to_phase: String,
    /// Remaining phases after the current one.
    pub phases_remaining: Vec<String>,
    /// When the transition occurred.
    pub timestamp: DateTime<Utc>,
}

/// A progress notification emitted by an execution surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressNotification {
    /// Operation this notification belongs to.
    pub operation_id: String,
    /// Correlating request ID.
    pub request_id: u64,
    /// The notification payload.
    pub payload: ProgressPayload,
    /// When this notification was created.
    pub timestamp: DateTime<Utc>,
}

/// Payload of a progress notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProgressPayload {
    /// A progress update with metrics.
    Update(ProgressUpdate),
    /// A phase transition.
    Phase(PhaseTransition),
}

/// Options for progress streaming on an invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressOptions {
    /// Whether to stream progress updates.
    #[serde(default)]
    pub stream_progress: bool,
    /// Minimum interval between progress updates in milliseconds.
    #[serde(default = "default_progress_interval_ms")]
    pub progress_interval_ms: u64,
}

const fn default_progress_interval_ms() -> u64 {
    500
}

impl Default for ProgressOptions {
    fn default() -> Self {
        Self {
            stream_progress: false,
            progress_interval_ms: default_progress_interval_ms(),
        }
    }
}

/// Aggregated progress across multiple operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedProgress {
    /// Total operations being tracked.
    pub total_operations: usize,
    /// Operations that have completed.
    pub completed_operations: usize,
    /// Operations currently in progress.
    pub in_progress_operations: usize,
    /// Overall percentage (average of individual percentages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overall_percentage: Option<f64>,
}

/// Supervisor observation used to evaluate a rollout step.
#[derive(Debug, Clone)]
pub struct RolloutObservation {
    /// Whether the most recent invocation or health sample succeeded.
    pub invocation_succeeded: bool,
    /// Optional end-to-end latency for the sample.
    pub latency_ms: Option<u32>,
    /// Supervisor-observed connector uptime.
    pub uptime_secs: u64,
    /// Whether the deployment is pinned and therefore must not auto-promote.
    pub pinned: bool,
    /// Whether the supervisor observed a hard crash for this connector.
    pub crashed: bool,
    /// Rollout policy to evaluate against.
    pub policy: RolloutPolicy,
    /// Timestamp associated with the observation.
    pub observed_at: DateTime<Utc>,
}

impl RolloutObservation {
    /// Create a new observation using the current wall-clock time.
    #[must_use]
    pub fn new(invocation_succeeded: bool, policy: RolloutPolicy) -> Self {
        Self {
            invocation_succeeded,
            latency_ms: None,
            uptime_secs: 0,
            pinned: false,
            crashed: false,
            policy,
            observed_at: Utc::now(),
        }
    }

    /// Set the observed latency in milliseconds.
    #[must_use]
    pub const fn with_latency_ms(mut self, latency_ms: u32) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    /// Set the observed uptime in seconds.
    #[must_use]
    pub const fn with_uptime_secs(mut self, uptime_secs: u64) -> Self {
        self.uptime_secs = uptime_secs;
        self
    }

    /// Mark the deployment as pinned.
    #[must_use]
    pub const fn pinned(mut self, pinned: bool) -> Self {
        self.pinned = pinned;
        self
    }

    /// Mark the observation as a crash signal.
    #[must_use]
    pub const fn crashed(mut self, crashed: bool) -> Self {
        self.crashed = crashed;
        self
    }

    /// Override the observation timestamp.
    #[must_use]
    pub const fn observed_at(mut self, observed_at: DateTime<Utc>) -> Self {
        self.observed_at = observed_at;
        self
    }
}

/// High-level rollout decision taken by the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutDecision {
    /// A connector was scheduled or re-entered into canary.
    Scheduled,
    /// No state transition occurred.
    Hold,
    /// Canary was promoted to production.
    Promote,
    /// Canary was rolled back.
    Rollback,
}

impl RolloutDecision {
    /// Stable string representation used in logs and reasoning surfaces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Hold => "hold",
            Self::Promote => "promote",
            Self::Rollback => "rollback",
        }
    }
}

/// Deterministic audit record for a rollout decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutAuditEvent {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// State before evaluation.
    pub state_before: LifecycleState,
    /// State after evaluation.
    pub state_after: LifecycleState,
    /// Controller decision.
    pub decision: RolloutDecision,
    /// Stable reason code for the decision.
    pub reason_code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Timestamp at which the decision was made.
    pub observed_at: DateTime<Utc>,
    /// Content digest of the evidence bundle.
    pub evidence_digest: String,
}

/// Evidence bundle used for audit and tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutEvidence {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// State before evaluation.
    pub state_before: LifecycleState,
    /// State after evaluation.
    pub state_after: LifecycleState,
    /// Current controller decision.
    pub decision: RolloutDecision,
    /// Stable reason code.
    pub reason_code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Whether the deployment is pinned.
    pub pinned: bool,
    /// Whether a crash loop was detected.
    pub crash_loop_detected: bool,
    /// Current consecutive failure streak tracked by the host.
    pub failure_streak: u32,
    /// Latest self-check status.
    pub self_check_status: SelfCheckStatus,
    /// Stable self-check reason code, when present.
    pub self_check_reason_code: Option<String>,
    /// Current external connector-health status.
    pub connector_health_status: String,
    /// Optional external connector-health reason.
    pub connector_health_reason: Option<String>,
    /// Samples recorded in lifecycle health.
    pub samples: u64,
    /// Success rate in basis points.
    pub success_rate_bps: u16,
    /// Error rate in basis points.
    pub error_rate_bps: u16,
    /// Average latency in milliseconds.
    pub avg_latency_ms: Option<u32>,
    /// Maximum observed latency in milliseconds.
    pub max_latency_ms: u32,
    /// Supervisor-observed uptime in seconds.
    pub uptime_secs: u64,
    /// Elapsed canary duration in seconds, if in canary.
    pub canary_elapsed_secs: Option<u64>,
    /// Remaining canary duration before expiry, if in canary.
    pub canary_expires_in_secs: Option<u32>,
    /// Promotion success-rate threshold in basis points.
    pub promotion_threshold_bps: u16,
    /// Promotion max-error threshold in basis points.
    pub promotion_max_error_bps: u16,
    /// Promotion minimum samples.
    pub promotion_min_samples: u32,
    /// Rollback max-error threshold in basis points.
    pub rollback_max_error_bps: u16,
    /// Rollback failure-streak threshold.
    pub rollback_max_consecutive_failures: u32,
    /// Rollback minimum samples.
    pub rollback_min_samples: u32,
    /// Whether the rollout policy allows automatic rollback.
    pub auto_rollback: bool,
    /// Evaluation timestamp.
    pub observed_at: DateTime<Utc>,
}

impl RolloutEvidence {
    /// Compute a stable digest for the evidence bundle.
    ///
    /// # Panics
    ///
    /// Panics if evidence serialization fails (should never occur with
    /// well-formed evidence).
    #[must_use]
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self)
            .expect("rollout evidence serialization should be deterministic");
        format!("blake3-256:{}", hash(&bytes).to_hex())
    }
}

/// Result of a rollout scheduling or evaluation step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutOutcome {
    /// Updated lifecycle record after persistence.
    pub record: LifecycleRecord,
    /// High-level controller decision.
    pub decision: RolloutDecision,
    /// Audit event describing the decision.
    pub audit_event: RolloutAuditEvent,
    /// Evidence bundle backing the audit event.
    pub evidence: RolloutEvidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_reason_labels_are_stable() {
        assert_eq!(CancelReason::UserRequested.label(), "user_requested");
        assert_eq!(
            CancelReason::TimeoutApproaching { remaining_ms: 10 }.label(),
            "timeout_approaching"
        );
    }

    #[test]
    fn cleanup_behavior_defaults_to_best_effort() {
        assert!(matches!(
            CleanupBehavior::default(),
            CleanupBehavior::BestEffort
        ));
    }

    #[test]
    fn progress_unit_labels_match_wire_names() {
        assert_eq!(ProgressUnit::Bytes.label(), "bytes");
        assert_eq!(ProgressUnit::Custom("chunks".into()).label(), "chunks");
    }

    #[test]
    fn progress_update_percentage_uses_total_when_available() {
        let update = ProgressUpdate {
            phase: "verify".into(),
            current: 25,
            total: Some(100),
            unit: ProgressUnit::Items,
            percentage: None,
            rate: None,
            eta_ms: None,
            message: None,
        };

        assert_eq!(update.computed_percentage(), Some(25.0));
        assert!(!update.is_indeterminate());
        assert!(!update.is_complete());
    }

    #[test]
    fn cancellation_outcome_serde_is_stable() {
        let json = serde_json::to_string(&CancellationOutcome::Pending).unwrap();
        assert_eq!(json, "\"pending\"");
        let parsed: CancellationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CancellationOutcome::Pending);
    }

    #[test]
    fn progress_options_default_interval_is_stable() {
        let options = ProgressOptions::default();
        assert!(!options.stream_progress);
        assert_eq!(options.progress_interval_ms, 500);
    }

    #[test]
    fn cancellation_request_defaults_cleanup_and_partial_flags() {
        let parsed: CancellationRequest =
            serde_json::from_str(r#"{"operation_id":"op-1","reason":{"type":"user_requested"}}"#)
                .unwrap();

        assert!(matches!(parsed.cleanup, CleanupBehavior::BestEffort));
        assert!(!parsed.return_partial);
    }

    #[test]
    fn rollout_decision_string_labels_are_stable() {
        assert_eq!(RolloutDecision::Scheduled.as_str(), "scheduled");
        assert_eq!(RolloutDecision::Hold.as_str(), "hold");
        assert_eq!(RolloutDecision::Promote.as_str(), "promote");
        assert_eq!(RolloutDecision::Rollback.as_str(), "rollback");
    }

    #[test]
    fn rollout_evidence_digest_is_deterministic() {
        let evidence = RolloutEvidence {
            connector_id: ConnectorId::from_static("fcp.test.rollout"),
            state_before: LifecycleState::Canary,
            state_after: LifecycleState::Production,
            decision: RolloutDecision::Promote,
            reason_code: "promotion_threshold_met".into(),
            message: "ready to promote".into(),
            pinned: false,
            crash_loop_detected: false,
            failure_streak: 0,
            self_check_status: SelfCheckStatus::Ok,
            self_check_reason_code: None,
            connector_health_status: "healthy".into(),
            connector_health_reason: None,
            samples: 10,
            success_rate_bps: 10_000,
            error_rate_bps: 0,
            avg_latency_ms: Some(12),
            max_latency_ms: 20,
            uptime_secs: 120,
            canary_elapsed_secs: Some(60),
            canary_expires_in_secs: Some(300),
            promotion_threshold_bps: 9_500,
            promotion_max_error_bps: 200,
            promotion_min_samples: 5,
            rollback_max_error_bps: 1_000,
            rollback_max_consecutive_failures: 3,
            rollback_min_samples: 3,
            auto_rollback: true,
            observed_at: Utc::now(),
        };

        let digest = evidence.digest();
        assert_eq!(digest, evidence.digest());
    }
}
