//! Operation cancellation: graceful abort with cleanup and audit.
//!
//! Provides types and logic for cancelling in-flight operations with:
//! - Reason codes explaining why cancellation was requested
//! - Cleanup behavior control (best-effort, full, abandon, checkpoint)
//! - Partial result capture from cancelled operations
//! - Checkpoint/resume support for resumable operations
//! - Audit trail for all cancellation decisions
//!
//! Based on bead `flywheel_connectors-2653`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fcp_async_core::process::Child;

use chrono::{DateTime, Utc};
pub use fcp_kernel::{
    CancelReason, CancellationAuditEvent, CancellationOutcome, CancellationRequest,
    CancellationResponse, CheckpointInfo, CleanupBehavior, CleanupResult, PartialResult,
};

use crate::{HostError, HostResult};

use crate::ConnectorArchetype;

// ─────────────────────────────────────────────────────────────────────────────
// Cancellation Deadlines (flywheel_connectors-861lx)
// ─────────────────────────────────────────────────────────────────────────────

/// Default cancellation deadline for bounded one-shot archetypes
/// (`request_response`, `webhook`).
pub const DEFAULT_CANCELLATION_DEADLINE_ONE_SHOT: Duration = Duration::from_secs(1);

/// Default cancellation deadline for long-lived archetypes.
///
/// Applies to `streaming`, `bidirectional`, `polling`, and `unknown`.
/// Long-lived connectors need a longer graceful window; `unknown` is
/// deliberately conservative so a connector with missing runtime
/// archetype metadata is never force-terminated prematurely.
pub const DEFAULT_CANCELLATION_DEADLINE_LONG_LIVED: Duration = Duration::from_secs(10);

/// Archetype-defaulted cancellation deadline (`flywheel_connectors-861lx`).
#[must_use]
pub const fn default_cancellation_deadline(archetype: ConnectorArchetype) -> Duration {
    match archetype {
        ConnectorArchetype::RequestResponse | ConnectorArchetype::Webhook => {
            DEFAULT_CANCELLATION_DEADLINE_ONE_SHOT
        }
        ConnectorArchetype::Streaming
        | ConnectorArchetype::Bidirectional
        | ConnectorArchetype::Polling
        | ConnectorArchetype::Unknown => DEFAULT_CANCELLATION_DEADLINE_LONG_LIVED,
    }
}

/// Deadline policy recorded when a subprocess-backed operation is tracked.
///
/// Production invokes are backed by a connector subprocess that can be
/// force-terminated when the operation ignores a cancellation request past
/// its deadline. Registrations without a backing subprocess
/// ([`CancellationController::track_with_owner`]) never expire.
#[derive(Debug, Clone)]
pub struct CancellationScope {
    /// Connector whose subprocess backs the operation. The reaper
    /// force-terminates this connector's subprocess on deadline expiry.
    pub connector_id: String,
    /// Archetype from which the deadline default is derived.
    pub archetype: ConnectorArchetype,
    /// Operator override
    /// (`ManagedConnectorConfig::cancellation_deadline_ms`). Wins over the
    /// archetype default when present.
    pub deadline_override: Option<Duration>,
}

impl CancellationScope {
    /// Build a scope with the archetype-default deadline.
    #[must_use]
    pub fn new(connector_id: impl Into<String>, archetype: ConnectorArchetype) -> Self {
        Self {
            connector_id: connector_id.into(),
            archetype,
            deadline_override: None,
        }
    }

    /// Attach an operator deadline override in milliseconds.
    #[must_use]
    pub fn with_deadline_override_ms(mut self, override_ms: Option<u64>) -> Self {
        self.deadline_override = override_ms.map(Duration::from_millis);
        self
    }

    /// Effective deadline: operator override, else archetype default.
    #[must_use]
    pub const fn effective_deadline(&self) -> Duration {
        match self.deadline_override {
            Some(deadline) => deadline,
            None => default_cancellation_deadline(self.archetype),
        }
    }
}

/// An operation whose cancellation deadline expired without completion.
#[derive(Debug, Clone)]
pub struct ExpiredCancellation {
    /// Operation that ignored its cancellation past the deadline.
    pub operation_id: String,
    /// Connector whose subprocess should be force-terminated.
    pub connector_id: String,
    /// The effective deadline that expired.
    pub deadline: Duration,
}

/// Force-terminates a connector subprocess (SIGTERM grace, then SIGKILL).
///
/// Enforcement primitive behind the cancellation-deadline reaper
/// (`flywheel_connectors-861lx`). The child is intentionally not waited
/// on (the asupersync process layer's `Child::wait` is synchronous); the
/// spawning runner's `kill_on_drop` setting reaps the process when its
/// handle is dropped.
pub async fn force_terminate_child(child: &mut Child, grace: Duration) {
    #[cfg(unix)]
    {
        // Best-effort graceful stop; SIGKILL below is the backstop.
        let _ = child.signal(libc::SIGTERM);
    }
    fcp_async_core::time::sleep(grace).await;
    let _ = child.start_kill();
}

// ─────────────────────────────────────────────────────────────────────────────
// Operation Tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks the state of an in-flight operation.
#[derive(Debug, Clone)]
struct TrackedOperation {
    /// Whether the operation has been completed.
    completed: bool,
    /// Whether a cancellation has been requested.
    cancel_requested: bool,
    /// Principal that initiated this operation (from the invoke-time
    /// `X-Principal` header). `None` means the caller intentionally
    /// opted into unowned tracking, so any caller may cancel. When
    /// `Some`, `cancel` MUST be called with a matching
    /// `asserted_principal`, otherwise the call is rejected — this
    /// closes br-jdaro, where knowing the client-chosen operation ID
    /// was sufficient to cancel any in-flight operation.
    owner: Option<String>,
    /// Subprocess-backed deadline policy. `None` for bookkeeping-only
    /// registrations ([`CancellationController::track_with_owner`]),
    /// which never expire and are never force-terminated.
    scope: Option<CancellationScope>,
    /// Monotonic instant cancellation was requested (deadline anchor).
    cancel_requested_at: Option<Instant>,
    /// Original cancellation reason, replayed into the forced audit event.
    cancel_reason: Option<CancelReason>,
    /// Set once the reaper dispatched a force-terminate for this
    /// operation, keeping reaped sweeps idempotent.
    forced_cancel_sent: bool,
}

/// Controller that manages operation tracking and cancellation.
///
/// # Panics
///
/// Methods that access the internal mutex will panic if the mutex is
/// poisoned (only possible if a thread panicked while holding the lock).
pub struct CancellationController {
    operations: Mutex<HashMap<String, TrackedOperation>>,
    audit_log: Mutex<Vec<CancellationAuditEvent>>,
}

impl std::fmt::Debug for CancellationController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancellationController")
            .field("operations", &format_args!("<Mutex>"))
            .field("audit_log", &format_args!("<Mutex>"))
            .finish()
    }
}

impl CancellationController {
    /// Create a new cancellation controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            operations: Mutex::new(HashMap::new()),
            audit_log: Mutex::new(Vec::new()),
        }
    }

    /// Register an operation for tracking with an explicit owner.
    ///
    /// `owner` is the principal that initiated the operation (e.g. the
    /// `X-Principal` HTTP header forwarded by `invoke_handler`). When
    /// set, [`Self::cancel`] will reject calls whose asserted principal
    /// does not match — closes br-jdaro (cross-principal cancel via
    /// guessed operation ID).
    ///
    /// Callers that intentionally allow unauthenticated cancellation
    /// must pass `None` explicitly. New authenticated routes MUST use
    /// this method with a real owner.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn track_with_owner(&self, operation_id: &str, owner: Option<&str>) {
        let mut ops = self.operations.lock().expect("operations lock");
        ops.insert(
            operation_id.to_string(),
            TrackedOperation {
                completed: false,
                cancel_requested: false,
                owner: owner.map(str::to_string),
                scope: None,
                cancel_requested_at: None,
                cancel_reason: None,
                forced_cancel_sent: false,
            },
        );
    }

    /// Register a subprocess-backed operation with a cancellation deadline
    /// (`flywheel_connectors-861lx`).
    ///
    /// Production invokes MUST use this method: when the operation ignores
    /// a cancellation request past `scope`'s effective deadline, the reaper
    /// reports it via [`Self::reap_expired`] so the host can force-terminate
    /// `scope.connector_id`'s subprocess and audit `forced = true`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn track_operation(
        &self,
        operation_id: &str,
        owner: Option<&str>,
        scope: CancellationScope,
    ) {
        let mut ops = self.operations.lock().expect("operations lock");
        ops.insert(
            operation_id.to_string(),
            TrackedOperation {
                completed: false,
                cancel_requested: false,
                owner: owner.map(str::to_string),
                scope: Some(scope),
                cancel_requested_at: None,
                cancel_reason: None,
                forced_cancel_sent: false,
            },
        );
    }

    /// Mark an operation as completed.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn complete(&self, operation_id: &str) {
        let mut ops = self.operations.lock().expect("operations lock");
        if let Some(op) = ops.get_mut(operation_id) {
            op.completed = true;
        }
    }

    /// Check if cancellation has been requested for an operation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn is_cancel_requested(&self, operation_id: &str) -> bool {
        self.operations
            .lock()
            .expect("operations lock")
            .get(operation_id)
            .is_some_and(|op| op.cancel_requested)
    }

    /// Request cancellation of an operation.
    ///
    /// Uses `now` for timestamp determinism. `asserted_principal` is
    /// the caller's principal (e.g. from the `X-Principal` header). If
    /// the tracked operation has an owner (recorded via
    /// [`Self::track_with_owner`]), the asserted principal MUST match;
    /// mismatched calls are rejected with [`HostError::PreflightFailed`],
    /// which the HTTP handler maps to 403 Forbidden. This closes
    /// br-jdaro (cross-principal cancel via guessed operation ID).
    ///
    /// Operations explicitly tracked without an owner remain
    /// cancellable by any caller.
    ///
    /// # Errors
    ///
    /// - [`HostError::ConnectorNotFound`] if the operation is not tracked.
    /// - [`HostError::PreflightFailed`] if the operation has an owner
    ///   and `asserted_principal` does not match.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn cancel(
        &self,
        request: &CancellationRequest,
        asserted_principal: Option<&str>,
        now: DateTime<Utc>,
    ) -> HostResult<CancellationResponse> {
        let start = Instant::now();

        let outcome = {
            let mut ops = self.operations.lock().expect("operations lock");
            match ops.get_mut(&request.operation_id) {
                None => {
                    return Err(HostError::ConnectorNotFound(format!(
                        "operation not found: {}",
                        request.operation_id
                    )));
                }
                Some(op) => {
                    // br-jdaro: reject mismatched principal BEFORE any
                    // state mutation. If no owner was recorded at track
                    // time, fall through to the legacy permissive path.
                    if let Some(owner) = op.owner.as_deref() {
                        match asserted_principal {
                            Some(p) if p == owner => {}
                            _ => {
                                return Err(HostError::PreflightFailed(format!(
                                    "cancellation principal mismatch for operation {}",
                                    request.operation_id
                                )));
                            }
                        }
                    }

                    if op.completed {
                        CancellationOutcome::TooLate
                    } else if op.cancel_requested {
                        CancellationOutcome::Pending
                    } else {
                        op.cancel_requested = true;
                        op.cancel_requested_at = Some(Instant::now());
                        op.cancel_reason = Some(request.reason.clone());
                        CancellationOutcome::Cancelled
                    }
                }
            }
        };

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        // Build checkpoint if requested and cancellation succeeded.
        let checkpoint = if matches!(request.cleanup, CleanupBehavior::Checkpoint)
            && outcome == CancellationOutcome::Cancelled
        {
            Some(CheckpointInfo {
                id: format!("ckpt_{}", request.operation_id),
                resumable: true,
                expires_at: Some(now + chrono::Duration::hours(24)),
                state: None,
            })
        } else {
            None
        };

        // Build cleanup result.
        let cleanup_result = match outcome {
            CancellationOutcome::Cancelled | CancellationOutcome::Pending => Some(CleanupResult {
                success: true,
                cleaned: vec!["operation_state".into()],
                failed: vec![],
                duration_ms,
            }),
            _ => None,
        };

        // Record audit event.
        let audit_event = CancellationAuditEvent {
            timestamp: now,
            operation_id: request.operation_id.clone(),
            reason: request.reason.clone(),
            outcome,
            duration_ms,
            had_partial_result: false, // Set by caller when partial data exists
            had_checkpoint: checkpoint.is_some(),
            forced: false,
        };
        self.audit_log.lock().expect("audit lock").push(audit_event);

        Ok(CancellationResponse {
            operation_id: request.operation_id.clone(),
            outcome,
            partial_result: None, // Set by caller when partial data is available
            checkpoint,
            cleanup_result,
            duration_ms,
        })
    }

    /// Sweep for operations whose cancellation deadline expired without
    /// completion (`flywheel_connectors-861lx`).
    ///
    /// Returns each expired operation exactly once (the reaper marks it as
    /// dispatched), so repeated sweeps never double force-terminate.
    /// Completed operations and bookkeeping-only registrations (no scope)
    /// never expire. The tracking entry is deliberately kept: the in-flight
    /// invoke completes (or errors) on its own when the subprocess dies, and
    /// no Strict-idempotency intent is released by a forced cancel.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn reap_expired(&self, now: Instant) -> Vec<ExpiredCancellation> {
        let mut ops = self.operations.lock().expect("operations lock");
        let mut expired = Vec::new();
        for (operation_id, op) in ops.iter_mut() {
            if !op.cancel_requested || op.completed || op.forced_cancel_sent {
                continue;
            }
            let Some(requested_at) = op.cancel_requested_at else {
                continue;
            };
            let Some(scope) = op.scope.as_ref() else {
                continue;
            };
            let deadline = scope.effective_deadline();
            if now.saturating_duration_since(requested_at) >= deadline {
                op.forced_cancel_sent = true;
                expired.push(ExpiredCancellation {
                    operation_id: operation_id.clone(),
                    connector_id: scope.connector_id.clone(),
                    deadline,
                });
            }
        }
        expired
    }

    /// Record the audit event for a force-terminated operation.
    ///
    /// Called by the host reaper after force-terminating the connector
    /// subprocess for [`ExpiredCancellation`] entries returned by
    /// [`Self::reap_expired`]. Emits `CancellationAuditEvent` with
    /// `outcome = Cancelled` and `forced = true`, replaying the original
    /// cancellation reason. The tracking entry stays until the regular
    /// invoke path calls [`Self::complete`].
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn record_forced_cancellation(&self, operation_id: &str, now: DateTime<Utc>) {
        let (reason, duration_ms) = {
            let mut ops = self.operations.lock().expect("operations lock");
            let Some(op) = ops.get_mut(operation_id) else {
                return;
            };
            op.forced_cancel_sent = true;
            let duration_ms = op
                .cancel_requested_at
                .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX))
                .unwrap_or_default();
            (
                op.cancel_reason
                    .clone()
                    .unwrap_or(CancelReason::UserRequested),
                duration_ms,
            )
        };
        self.audit_log
            .lock()
            .expect("audit lock")
            .push(CancellationAuditEvent {
                timestamp: now,
                operation_id: operation_id.to_string(),
                reason,
                outcome: CancellationOutcome::Cancelled,
                duration_ms,
                had_partial_result: false,
                had_checkpoint: false,
                forced: true,
            });
    }

    /// Re-arm a failed force-terminate so the next reaper sweep retries
    /// it (`flywheel_connectors-861lx`). Completed operations are never
    /// re-armed: once the invoke path reports completion the deadline is
    /// moot.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn rearm_force_terminate(&self, operation_id: &str) {
        let mut ops = self.operations.lock().expect("operations lock");
        if let Some(op) = ops.get_mut(operation_id) {
            if !op.completed {
                op.forced_cancel_sent = false;
            }
        }
    }

    /// Remove a completed or cancelled operation from tracking.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn remove(&self, operation_id: &str) {
        self.operations
            .lock()
            .expect("operations lock")
            .remove(operation_id);
    }

    /// Number of currently tracked operations.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.operations.lock().expect("operations lock").len()
    }

    /// Get audit events, newest first.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn audit_events(&self) -> Vec<CancellationAuditEvent> {
        let mut result = {
            let guard = self.audit_log.lock().expect("audit lock");
            guard.clone()
        };
        result.reverse();
        result
    }

    /// Clear all audit events.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn clear_audit_log(&self) {
        self.audit_log.lock().expect("audit lock").clear();
    }
}

impl Default for CancellationController {
    fn default() -> Self {
        Self::new()
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
    use chrono::TimeZone;
    use fcp_kernel::OperationId;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap()
    }

    fn cancel_request(op_id: &str, reason: CancelReason) -> CancellationRequest {
        CancellationRequest {
            operation_id: op_id.into(),
            reason,
            cleanup: CleanupBehavior::default(),
            return_partial: false,
            capability_token: None,
        }
    }

    // ── CancelReason tests ──

    #[test]
    fn cancel_reason_user_requested_label() {
        assert_eq!(CancelReason::UserRequested.label(), "user_requested");
    }

    #[test]
    fn cancel_reason_agent_abort_label() {
        let r = CancelReason::AgentAbort {
            reason: "bad state".into(),
        };
        assert_eq!(r.label(), "agent_abort");
    }

    #[test]
    fn cancel_reason_timeout_label() {
        let r = CancelReason::TimeoutApproaching { remaining_ms: 500 };
        assert_eq!(r.label(), "timeout_approaching");
    }

    #[test]
    fn cancel_reason_resource_limit_label() {
        let r = CancelReason::ResourceLimit {
            resource: "memory".into(),
            current: 900,
            limit: 1000,
        };
        assert_eq!(r.label(), "resource_limit");
    }

    #[test]
    fn cancel_reason_superseded_label() {
        let r = CancelReason::Superseded {
            by_operation_id: "op_new".into(),
        };
        assert_eq!(r.label(), "superseded");
    }

    #[test]
    fn cancel_reason_session_closing_label() {
        assert_eq!(CancelReason::SessionClosing.label(), "session_closing");
    }

    #[test]
    fn cancel_reason_json_roundtrip() {
        let r = CancelReason::AgentAbort {
            reason: "detected error".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.label(), "agent_abort");
    }

    #[test]
    fn cancel_reason_resource_limit_json_roundtrip() {
        let r = CancelReason::ResourceLimit {
            resource: "tokens".into(),
            current: 950,
            limit: 1000,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("tokens"));
        assert!(json.contains("950"));
    }

    // ── CleanupBehavior tests ──

    #[test]
    fn cleanup_default_is_best_effort() {
        assert!(matches!(
            CleanupBehavior::default(),
            CleanupBehavior::BestEffort
        ));
    }

    #[test]
    fn cleanup_full_has_timeout() {
        let c = CleanupBehavior::Full { timeout_ms: 5000 };
        if let CleanupBehavior::Full { timeout_ms } = c {
            assert_eq!(timeout_ms, 5000);
        } else {
            panic!("expected Full variant");
        }
    }

    #[test]
    fn cleanup_json_roundtrip() {
        let c = CleanupBehavior::Checkpoint;
        let json = serde_json::to_string(&c).unwrap();
        let parsed: CleanupBehavior = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, CleanupBehavior::Checkpoint));
    }

    #[test]
    fn cleanup_abandon_json_roundtrip() {
        let c = CleanupBehavior::Abandon;
        let json = serde_json::to_string(&c).unwrap();
        let parsed: CleanupBehavior = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, CleanupBehavior::Abandon));
    }

    // ── CancellationOutcome tests ──

    #[test]
    fn outcome_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&CancellationOutcome::TooLate).unwrap(),
            "\"too_late\""
        );
        assert_eq!(
            serde_json::to_string(&CancellationOutcome::Cancelled).unwrap(),
            "\"cancelled\""
        );
    }

    #[test]
    fn outcome_equality() {
        assert_eq!(
            CancellationOutcome::Cancelled,
            CancellationOutcome::Cancelled
        );
        assert_ne!(CancellationOutcome::Cancelled, CancellationOutcome::TooLate);
    }

    // ── CancellationController tests ──

    #[test]
    fn track_and_count() {
        let ctrl = CancellationController::new();
        assert_eq!(ctrl.tracked_count(), 0);
        ctrl.track_with_owner("op1", None);
        assert_eq!(ctrl.tracked_count(), 1);
        ctrl.track_with_owner("op2", None);
        assert_eq!(ctrl.tracked_count(), 2);
    }

    #[test]
    fn cancel_unknown_operation_errors() {
        let ctrl = CancellationController::new();
        let req = cancel_request("nonexistent", CancelReason::UserRequested);
        let err = ctrl.cancel(&req, None, fixed_now()).unwrap_err();
        assert!(err.to_string().contains("operation not found"));
    }

    /// Regression for br-jdaro: an operation tracked with an owner MUST
    /// NOT be cancellable by a different principal. Before this fix the
    /// cancel route on `/rpc/cancel` accepted any caller-supplied
    /// `operation_id` and cancelled it — cross-principal `DoS` via guessed ID.
    #[test]
    fn cancel_rejects_mismatched_principal_when_owner_recorded() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", Some("agent:alice"));
        let req = cancel_request("op1", CancelReason::UserRequested);

        // Wrong principal: must be rejected with PreflightFailed (→ 403).
        let err = ctrl
            .cancel(&req, Some("agent:mallory"), fixed_now())
            .unwrap_err();
        assert!(
            matches!(err, HostError::PreflightFailed(_)),
            "expected PreflightFailed for mismatched principal, got {err:?}"
        );

        // No principal at all: also rejected (can't prove ownership).
        let err = ctrl.cancel(&req, None, fixed_now()).unwrap_err();
        assert!(matches!(err, HostError::PreflightFailed(_)));

        // State must be untouched after rejected attempts — the real
        // owner's cancel must still be able to run.
        let resp = ctrl.cancel(&req, Some("agent:alice"), fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
    }

    /// br-jdaro companion: an operation tracked WITHOUT an owner stays
    /// cancellable by any principal — preserves legacy behavior for
    /// unauthenticated routes and existing integration tests.
    #[test]
    fn cancel_allows_any_principal_when_no_owner_recorded() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_legacy", None);
        let req = cancel_request("op_legacy", CancelReason::UserRequested);

        let resp = ctrl
            .cancel(&req, Some("agent:anyone"), fixed_now())
            .unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
    }

    #[test]
    fn cancel_active_operation_succeeds() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        assert_eq!(resp.operation_id, "op1");
    }

    #[test]
    fn cancel_completed_operation_returns_too_late() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.complete("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::TooLate);
    }

    #[test]
    fn cancel_already_cancelled_returns_pending() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = cancel_request("op1", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        // Second cancellation attempt.
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
    }

    #[test]
    fn is_cancel_requested_false_initially() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        assert!(!ctrl.is_cancel_requested("op1"));
    }

    #[test]
    fn is_cancel_requested_true_after_cancel() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = cancel_request("op1", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert!(ctrl.is_cancel_requested("op1"));
    }

    #[test]
    fn is_cancel_requested_unknown_returns_false() {
        let ctrl = CancellationController::new();
        assert!(!ctrl.is_cancel_requested("nonexistent"));
    }

    #[test]
    fn remove_decreases_count() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.track_with_owner("op2", None);
        assert_eq!(ctrl.tracked_count(), 2);
        ctrl.remove("op1");
        assert_eq!(ctrl.tracked_count(), 1);
    }

    #[test]
    fn remove_unknown_is_noop() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.remove("nonexistent");
        assert_eq!(ctrl.tracked_count(), 1);
    }

    // ── Checkpoint tests ──

    #[test]
    fn checkpoint_created_on_checkpoint_cleanup() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = CancellationRequest {
            operation_id: "op1".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
            capability_token: None,
        };
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        let ckpt = resp.checkpoint.unwrap();
        assert!(ckpt.resumable);
        assert!(ckpt.id.contains("op1"));
        assert!(ckpt.expires_at.is_some());
    }

    #[test]
    fn no_checkpoint_on_best_effort() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert!(resp.checkpoint.is_none());
    }

    #[test]
    fn no_checkpoint_on_too_late() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.complete("op1");
        let req = CancellationRequest {
            operation_id: "op1".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
            capability_token: None,
        };
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::TooLate);
        assert!(resp.checkpoint.is_none());
    }

    // ── Cleanup result tests ──

    #[test]
    fn cleanup_result_present_on_cancel() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        let cleanup = resp.cleanup_result.unwrap();
        assert!(cleanup.success);
        assert!(!cleanup.cleaned.is_empty());
        assert!(cleanup.failed.is_empty());
    }

    #[test]
    fn no_cleanup_result_on_too_late() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.complete("op1");
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert!(resp.cleanup_result.is_none());
    }

    // ── Audit log tests ──

    #[test]
    fn audit_event_recorded_on_cancel() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = cancel_request("op1", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_id, "op1");
        assert_eq!(events[0].outcome, CancellationOutcome::Cancelled);
        assert_eq!(events[0].reason.label(), "user_requested");
    }

    #[test]
    fn audit_event_recorded_on_too_late() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.complete("op1");
        let req = cancel_request("op1", CancelReason::SessionClosing);
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, CancellationOutcome::TooLate);
    }

    #[test]
    fn audit_multiple_events() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.track_with_owner("op2", None);
        ctrl.cancel(
            &cancel_request("op1", CancelReason::UserRequested),
            None,
            fixed_now(),
        )
        .unwrap();
        ctrl.cancel(
            &cancel_request("op2", CancelReason::SessionClosing),
            None,
            fixed_now(),
        )
        .unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 2);
        // Newest first.
        assert_eq!(events[0].operation_id, "op2");
        assert_eq!(events[1].operation_id, "op1");
    }

    #[test]
    fn clear_audit_log() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.cancel(
            &cancel_request("op1", CancelReason::UserRequested),
            None,
            fixed_now(),
        )
        .unwrap();
        assert_eq!(ctrl.audit_events().len(), 1);
        ctrl.clear_audit_log();
        assert!(ctrl.audit_events().is_empty());
    }

    #[test]
    fn audit_checkpoint_flag_set() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = CancellationRequest {
            operation_id: "op1".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
            capability_token: None,
        };
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert!(events[0].had_checkpoint);
    }

    #[test]
    fn audit_no_checkpoint_flag() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.cancel(
            &cancel_request("op1", CancelReason::UserRequested),
            None,
            fixed_now(),
        )
        .unwrap();
        let events = ctrl.audit_events();
        assert!(!events[0].had_checkpoint);
    }

    // ── Serialization tests ──

    #[test]
    fn cancellation_request_json_roundtrip() {
        let req = CancellationRequest {
            operation_id: "op_abc".into(),
            reason: CancelReason::TimeoutApproaching { remaining_ms: 1000 },
            cleanup: CleanupBehavior::Full { timeout_ms: 5000 },
            return_partial: true,
            capability_token: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation_id, "op_abc");
        assert!(parsed.return_partial);
    }

    #[test]
    fn cancellation_response_json_roundtrip() {
        let resp = CancellationResponse {
            operation_id: "op_abc".into(),
            outcome: CancellationOutcome::Cancelled,
            partial_result: Some(PartialResult {
                completed_items: 42,
                total_items: Some(100),
                data: Some(serde_json::json!({"items": [1, 2, 3]})),
            }),
            checkpoint: None,
            cleanup_result: Some(CleanupResult {
                success: true,
                cleaned: vec!["temp_files".into()],
                failed: vec![],
                duration_ms: 10,
            }),
            duration_ms: 15,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CancellationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.outcome, CancellationOutcome::Cancelled);
        assert_eq!(parsed.partial_result.unwrap().completed_items, 42);
    }

    #[test]
    fn checkpoint_info_json_roundtrip() {
        let ckpt = CheckpointInfo {
            id: "ckpt_123".into(),
            resumable: true,
            expires_at: Some(fixed_now()),
            state: Some(serde_json::json!({"cursor": "page_5"})),
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.resumable);
        assert_eq!(parsed.id, "ckpt_123");
    }

    // ── Default trait tests ──

    #[test]
    fn controller_default() {
        let ctrl = CancellationController::default();
        assert_eq!(ctrl.tracked_count(), 0);
    }

    #[test]
    fn controller_debug() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let dbg = format!("{ctrl:?}");
        assert!(dbg.contains("CancellationController"));
        assert!(dbg.contains("operations"));
    }

    // ── PartialResult tests ──

    #[test]
    fn partial_result_with_data() {
        let pr = PartialResult {
            completed_items: 50,
            total_items: Some(200),
            data: Some(serde_json::json!({"batch": "partial"})),
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.completed_items, 50);
        assert_eq!(parsed.total_items, Some(200));
    }

    #[test]
    fn partial_result_minimal() {
        let pr = PartialResult {
            completed_items: 0,
            total_items: None,
            data: None,
        };
        let json = serde_json::to_string(&pr).unwrap();
        assert!(!json.contains("total_items"));
        assert!(!json.contains("data"));
    }

    // ── Edge cases ──

    #[test]
    fn complete_unknown_operation_is_noop() {
        let ctrl = CancellationController::new();
        ctrl.complete("nonexistent"); // Should not panic.
        assert_eq!(ctrl.tracked_count(), 0);
    }

    #[test]
    fn track_same_id_overwrites() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        ctrl.track_with_owner("op1", None);
        assert_eq!(ctrl.tracked_count(), 1);
    }

    #[test]
    fn cancel_with_all_reason_variants() {
        let ctrl = CancellationController::new();
        let reasons = vec![
            CancelReason::UserRequested,
            CancelReason::AgentAbort {
                reason: "err".into(),
            },
            CancelReason::TimeoutApproaching { remaining_ms: 100 },
            CancelReason::ResourceLimit {
                resource: "mem".into(),
                current: 90,
                limit: 100,
            },
            CancelReason::Superseded {
                by_operation_id: "op_new".into(),
            },
            CancelReason::SessionClosing,
        ];
        for (i, reason) in reasons.into_iter().enumerate() {
            let id = format!("op{i}");
            ctrl.track_with_owner(&id, None);
            let req = cancel_request(&id, reason);
            let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
            assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        }
        assert_eq!(ctrl.audit_events().len(), 6);
    }

    // Note: OperationId from fcp_kernel is not used directly in the controller
    // to keep the API string-based and flexible. Callers convert as needed.
    #[test]
    fn operation_id_interop() {
        let op_id = OperationId::from_static("test.cancel.op");
        let ctrl = CancellationController::new();
        ctrl.track_with_owner(op_id.as_str(), None);
        assert_eq!(ctrl.tracked_count(), 1);
        let req = cancel_request(op_id.as_str(), CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
    }

    // ── CancelReason serialization (extended) ──

    #[test]
    fn cancel_reason_user_requested_deserialize_from_json() {
        let json = r#"{"type":"user_requested"}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        assert_eq!(r.label(), "user_requested");
    }

    #[test]
    fn cancel_reason_agent_abort_deserialize_from_json() {
        let json = r#"{"type":"agent_abort","reason":"something went wrong"}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        assert_eq!(r.label(), "agent_abort");
        if let CancelReason::AgentAbort { reason } = r {
            assert_eq!(reason, "something went wrong");
        } else {
            panic!("expected AgentAbort");
        }
    }

    #[test]
    fn cancel_reason_timeout_approaching_deserialize_from_json() {
        let json = r#"{"type":"timeout_approaching","remaining_ms":250}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        if let CancelReason::TimeoutApproaching { remaining_ms } = r {
            assert_eq!(remaining_ms, 250);
        } else {
            panic!("expected TimeoutApproaching");
        }
    }

    #[test]
    fn cancel_reason_resource_limit_deserialize_from_json() {
        let json = r#"{"type":"resource_limit","resource":"cpu","current":95,"limit":100}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        if let CancelReason::ResourceLimit {
            resource,
            current,
            limit,
        } = r
        {
            assert_eq!(resource, "cpu");
            assert_eq!(current, 95);
            assert_eq!(limit, 100);
        } else {
            panic!("expected ResourceLimit");
        }
    }

    #[test]
    fn cancel_reason_superseded_deserialize_from_json() {
        let json = r#"{"type":"superseded","by_operation_id":"op_replacement"}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        if let CancelReason::Superseded { by_operation_id } = r {
            assert_eq!(by_operation_id, "op_replacement");
        } else {
            panic!("expected Superseded");
        }
    }

    #[test]
    fn cancel_reason_session_closing_deserialize_from_json() {
        let json = r#"{"type":"session_closing"}"#;
        let r: CancelReason = serde_json::from_str(json).unwrap();
        assert_eq!(r.label(), "session_closing");
    }

    #[test]
    fn cancel_reason_unknown_variant_rejected() {
        let json = r#"{"type":"cosmic_ray"}"#;
        let result = serde_json::from_str::<CancelReason>(json);
        assert!(result.is_err());
    }

    #[test]
    fn cancel_reason_superseded_json_roundtrip() {
        let r = CancelReason::Superseded {
            by_operation_id: "op_v2".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::Superseded { by_operation_id } = parsed {
            assert_eq!(by_operation_id, "op_v2");
        } else {
            panic!("expected Superseded");
        }
    }

    // ── CleanupBehavior::Full (extended) ──

    #[test]
    fn cleanup_full_zero_timeout() {
        let c = CleanupBehavior::Full { timeout_ms: 0 };
        if let CleanupBehavior::Full { timeout_ms } = c {
            assert_eq!(timeout_ms, 0);
        } else {
            panic!("expected Full");
        }
    }

    #[test]
    fn cleanup_full_json_roundtrip_with_timeout() {
        let c = CleanupBehavior::Full { timeout_ms: 30000 };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("30000"));
        let parsed: CleanupBehavior = serde_json::from_str(&json).unwrap();
        if let CleanupBehavior::Full { timeout_ms } = parsed {
            assert_eq!(timeout_ms, 30000);
        } else {
            panic!("expected Full");
        }
    }

    // ── CancellationOutcome (extended) ──

    #[test]
    fn outcome_pending_json_roundtrip() {
        let o = CancellationOutcome::Pending;
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(json, "\"pending\"");
        let parsed: CancellationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CancellationOutcome::Pending);
    }

    #[test]
    fn outcome_failed_json_roundtrip() {
        let o = CancellationOutcome::Failed;
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(json, "\"failed\"");
        let parsed: CancellationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, CancellationOutcome::Failed);
    }

    #[test]
    fn outcome_all_variants_not_equal() {
        let variants = [
            CancellationOutcome::Cancelled,
            CancellationOutcome::TooLate,
            CancellationOutcome::Pending,
            CancellationOutcome::Failed,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    // ── CancellationRequest (extended) ──

    #[test]
    fn request_with_return_partial_true() {
        let req = CancellationRequest {
            operation_id: "op_partial".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::default(),
            return_partial: true,
            capability_token: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("true"));
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert!(parsed.return_partial);
    }

    #[test]
    fn request_with_full_cleanup() {
        let req = CancellationRequest {
            operation_id: "op_full".into(),
            reason: CancelReason::SessionClosing,
            cleanup: CleanupBehavior::Full { timeout_ms: 10000 },
            return_partial: false,
            capability_token: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation_id, "op_full");
        assert!(matches!(
            parsed.cleanup,
            CleanupBehavior::Full { timeout_ms: 10000 }
        ));
    }

    #[test]
    fn request_with_abandon_cleanup() {
        let req = CancellationRequest {
            operation_id: "op_abandon".into(),
            reason: CancelReason::AgentAbort {
                reason: "fatal".into(),
            },
            cleanup: CleanupBehavior::Abandon,
            return_partial: false,
            capability_token: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.cleanup, CleanupBehavior::Abandon));
    }

    #[test]
    fn request_with_checkpoint_cleanup() {
        let req = CancellationRequest {
            operation_id: "op_ckpt".into(),
            reason: CancelReason::TimeoutApproaching { remaining_ms: 500 },
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: true,
            capability_token: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: CancellationRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.cleanup, CleanupBehavior::Checkpoint));
        assert!(parsed.return_partial);
    }

    #[test]
    fn request_cleanup_defaults_when_missing() {
        let json = r#"{"operation_id":"op_x","reason":{"type":"user_requested"}}"#;
        let parsed: CancellationRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(parsed.cleanup, CleanupBehavior::BestEffort));
        assert!(!parsed.return_partial);
    }

    // ── CancellationResponse (extended) ──

    #[test]
    fn response_none_fields_omitted_in_json() {
        let resp = CancellationResponse {
            operation_id: "op_sparse".into(),
            outcome: CancellationOutcome::TooLate,
            partial_result: None,
            checkpoint: None,
            cleanup_result: None,
            duration_ms: 5,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("partial_result"));
        assert!(!json.contains("checkpoint"));
        assert!(!json.contains("cleanup_result"));
    }

    #[test]
    fn response_all_fields_populated() {
        let resp = CancellationResponse {
            operation_id: "op_full_resp".into(),
            outcome: CancellationOutcome::Cancelled,
            partial_result: Some(PartialResult {
                completed_items: 10,
                total_items: Some(50),
                data: Some(serde_json::json!([1, 2, 3])),
            }),
            checkpoint: Some(CheckpointInfo {
                id: "ckpt_99".into(),
                resumable: true,
                expires_at: Some(fixed_now()),
                state: Some(serde_json::json!({"page": 5})),
            }),
            cleanup_result: Some(CleanupResult {
                success: true,
                cleaned: vec!["cache".into(), "temp".into()],
                failed: vec![],
                duration_ms: 3,
            }),
            duration_ms: 12,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CancellationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation_id, "op_full_resp");
        assert!(parsed.partial_result.is_some());
        assert!(parsed.checkpoint.is_some());
        assert!(parsed.cleanup_result.is_some());
        assert_eq!(parsed.duration_ms, 12);
    }

    // ── PartialResult (extended) ──

    #[test]
    fn partial_result_large_values() {
        let pr = PartialResult {
            completed_items: u64::MAX,
            total_items: Some(u64::MAX),
            data: None,
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.completed_items, u64::MAX);
        assert_eq!(parsed.total_items, Some(u64::MAX));
    }

    #[test]
    fn partial_result_completed_exceeds_total() {
        let pr = PartialResult {
            completed_items: 200,
            total_items: Some(100),
            data: None,
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.completed_items, 200);
        assert_eq!(parsed.total_items, Some(100));
    }

    #[test]
    fn partial_result_with_complex_data() {
        let pr = PartialResult {
            completed_items: 3,
            total_items: None,
            data: Some(serde_json::json!({
                "rows": [
                    {"id": 1, "name": "alpha"},
                    {"id": 2, "name": "beta"},
                    {"id": 3, "name": "gamma"}
                ],
                "metadata": {"source": "test"}
            })),
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.completed_items, 3);
        let data = parsed.data.unwrap();
        assert!(data["rows"].is_array());
        assert_eq!(data["rows"].as_array().unwrap().len(), 3);
    }

    // ── CheckpointInfo (extended) ──

    #[test]
    fn checkpoint_without_state() {
        let ckpt = CheckpointInfo {
            id: "ckpt_no_state".into(),
            resumable: true,
            expires_at: Some(fixed_now()),
            state: None,
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        // "state" as a key should not appear, but "ckpt_no_state" contains
        // the substring "state" in the id — check for the key specifically.
        assert!(!json.contains("\"state\""));
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.state.is_none());
    }

    #[test]
    fn checkpoint_without_expires_at() {
        let ckpt = CheckpointInfo {
            id: "ckpt_no_expiry".into(),
            resumable: true,
            expires_at: None,
            state: Some(serde_json::json!({"cursor": 42})),
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        assert!(!json.contains("expires_at"));
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.expires_at.is_none());
        assert!(parsed.state.is_some());
    }

    #[test]
    fn checkpoint_non_resumable() {
        let ckpt = CheckpointInfo {
            id: "ckpt_final".into(),
            resumable: false,
            expires_at: None,
            state: None,
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        assert!(!parsed.resumable);
        assert!(parsed.expires_at.is_none());
        assert!(parsed.state.is_none());
    }

    // ── CleanupResult (extended) ──

    #[test]
    fn cleanup_result_with_failed_items() {
        let cr = CleanupResult {
            success: false,
            cleaned: vec!["cache".into()],
            failed: vec!["lock_file".into(), "temp_dir".into()],
            duration_ms: 500,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert!(!parsed.success);
        assert_eq!(parsed.cleaned.len(), 1);
        assert_eq!(parsed.failed.len(), 2);
        assert_eq!(parsed.failed[0], "lock_file");
        assert_eq!(parsed.failed[1], "temp_dir");
    }

    #[test]
    fn cleanup_result_empty_cleaned_list() {
        let cr = CleanupResult {
            success: false,
            cleaned: vec![],
            failed: vec!["everything".into()],
            duration_ms: 100,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.cleaned.is_empty());
        assert_eq!(parsed.failed.len(), 1);
    }

    #[test]
    fn cleanup_result_zero_duration() {
        let cr = CleanupResult {
            success: true,
            cleaned: vec!["state".into()],
            failed: vec![],
            duration_ms: 0,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.duration_ms, 0);
    }

    #[test]
    fn cleanup_result_both_cleaned_and_failed() {
        let cr = CleanupResult {
            success: false,
            cleaned: vec!["a".into(), "b".into(), "c".into()],
            failed: vec!["d".into(), "e".into()],
            duration_ms: 250,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cleaned.len(), 3);
        assert_eq!(parsed.failed.len(), 2);
        assert!(!parsed.success);
    }

    // ── CancellationAuditEvent (extended) ──

    #[test]
    fn audit_event_json_roundtrip_all_fields() {
        let event = CancellationAuditEvent {
            timestamp: fixed_now(),
            operation_id: "op_audited".into(),
            reason: CancelReason::ResourceLimit {
                resource: "disk".into(),
                current: 980,
                limit: 1000,
            },
            outcome: CancellationOutcome::Cancelled,
            duration_ms: 42,
            had_partial_result: true,
            had_checkpoint: true,
            forced: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CancellationAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.operation_id, "op_audited");
        assert_eq!(parsed.outcome, CancellationOutcome::Cancelled);
        assert_eq!(parsed.duration_ms, 42);
        assert!(parsed.had_partial_result);
        assert!(parsed.had_checkpoint);
        assert!(!parsed.forced);
        assert_eq!(parsed.reason.label(), "resource_limit");
    }

    #[test]
    fn audit_event_clone() {
        let event = CancellationAuditEvent {
            timestamp: fixed_now(),
            operation_id: "op_clone".into(),
            reason: CancelReason::SessionClosing,
            outcome: CancellationOutcome::Pending,
            duration_ms: 7,
            had_partial_result: false,
            had_checkpoint: false,
            forced: false,
        };
        let cloned = event.clone();
        assert_eq!(event.operation_id, "op_clone");
        assert_eq!(cloned.outcome, CancellationOutcome::Pending);
        assert_eq!(cloned.duration_ms, 7);
    }

    // ── CancellationController (extended) ──

    #[test]
    fn controller_track_many_cancel_some() {
        let ctrl = CancellationController::new();
        for i in 0..20 {
            ctrl.track_with_owner(&format!("op_{i}"), None);
        }
        assert_eq!(ctrl.tracked_count(), 20);

        // Cancel only even-numbered operations.
        for i in (0..20).step_by(2) {
            let req = cancel_request(&format!("op_{i}"), CancelReason::UserRequested);
            let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
            assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        }
        // Odd operations should not be cancel-requested.
        for i in (1..20).step_by(2) {
            assert!(!ctrl.is_cancel_requested(&format!("op_{i}")));
        }
        // Even operations should be cancel-requested.
        for i in (0..20).step_by(2) {
            assert!(ctrl.is_cancel_requested(&format!("op_{i}")));
        }
        assert_eq!(ctrl.audit_events().len(), 10);
    }

    #[test]
    fn controller_cancel_with_full_cleanup() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_full_cleanup", None);
        let req = CancellationRequest {
            operation_id: "op_full_cleanup".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Full { timeout_ms: 3000 },
            return_partial: false,
            capability_token: None,
        };
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        // No checkpoint because cleanup is Full, not Checkpoint.
        assert!(resp.checkpoint.is_none());
        // Cleanup result should be present because outcome is Cancelled.
        assert!(resp.cleanup_result.is_some());
    }

    #[test]
    fn controller_cancel_with_abandon() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_abandon", None);
        let req = CancellationRequest {
            operation_id: "op_abandon".into(),
            reason: CancelReason::AgentAbort {
                reason: "critical".into(),
            },
            cleanup: CleanupBehavior::Abandon,
            return_partial: false,
            capability_token: None,
        };
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        // No checkpoint on Abandon.
        assert!(resp.checkpoint.is_none());
        assert!(resp.cleanup_result.is_some());
    }

    #[test]
    fn controller_retrack_after_remove() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_reuse", None);
        let req = cancel_request("op_reuse", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert!(ctrl.is_cancel_requested("op_reuse"));

        ctrl.remove("op_reuse");
        assert_eq!(ctrl.tracked_count(), 0);
        assert!(!ctrl.is_cancel_requested("op_reuse"));

        // Re-track the same ID; it should be fresh.
        ctrl.track_with_owner("op_reuse", None);
        assert_eq!(ctrl.tracked_count(), 1);
        assert!(!ctrl.is_cancel_requested("op_reuse"));

        // Cancelling again should succeed (not Pending).
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
    }

    #[test]
    fn controller_audit_ordering_many_ops() {
        let ctrl = CancellationController::new();
        let ids: Vec<String> = (0..10).map(|i| format!("seq_{i}")).collect();
        for id in &ids {
            ctrl.track_with_owner(id, None);
        }
        for id in &ids {
            let req = cancel_request(id, CancelReason::SessionClosing);
            ctrl.cancel(&req, None, fixed_now()).unwrap();
        }
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 10);
        // Newest first: last cancelled should be first in audit.
        assert_eq!(events[0].operation_id, "seq_9");
        assert_eq!(events[9].operation_id, "seq_0");
    }

    #[test]
    fn controller_clear_audit_then_add_more() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_a", None);
        ctrl.cancel(
            &cancel_request("op_a", CancelReason::UserRequested),
            None,
            fixed_now(),
        )
        .unwrap();
        assert_eq!(ctrl.audit_events().len(), 1);

        ctrl.clear_audit_log();
        assert!(ctrl.audit_events().is_empty());

        ctrl.track_with_owner("op_b", None);
        ctrl.cancel(
            &cancel_request("op_b", CancelReason::SessionClosing),
            None,
            fixed_now(),
        )
        .unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation_id, "op_b");
    }

    #[test]
    fn controller_track_cancel_remove_retrack_lifecycle() {
        let ctrl = CancellationController::new();

        // Phase 1: Track and cancel.
        ctrl.track_with_owner("lifecycle_op", None);
        assert_eq!(ctrl.tracked_count(), 1);
        let req = cancel_request("lifecycle_op", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        assert!(ctrl.is_cancel_requested("lifecycle_op"));

        // Phase 2: Remove.
        ctrl.remove("lifecycle_op");
        assert_eq!(ctrl.tracked_count(), 0);
        // Cancel after remove should error.
        let err = ctrl.cancel(&req, None, fixed_now()).unwrap_err();
        assert!(err.to_string().contains("operation not found"));

        // Phase 3: Re-track.
        ctrl.track_with_owner("lifecycle_op", None);
        assert!(!ctrl.is_cancel_requested("lifecycle_op"));

        // Phase 4: Complete then try cancel.
        ctrl.complete("lifecycle_op");
        let resp2 = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp2.outcome, CancellationOutcome::TooLate);

        // Audit should have 3 entries total (cancel, error is not audited, cancel again).
        // The error path returns Err before recording audit, so only 2 successful cancel calls recorded.
        assert_eq!(ctrl.audit_events().len(), 2);
    }

    // ── Edge cases ──

    #[test]
    fn empty_string_operation_id() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("", None);
        assert_eq!(ctrl.tracked_count(), 1);
        let req = cancel_request("", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        assert_eq!(resp.operation_id, "");
        ctrl.remove("");
        assert_eq!(ctrl.tracked_count(), 0);
    }

    #[test]
    fn very_long_operation_id() {
        let long_id = "x".repeat(10000);
        let ctrl = CancellationController::new();
        ctrl.track_with_owner(&long_id, None);
        let req = cancel_request(&long_id, CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        assert_eq!(resp.operation_id, long_id);
    }

    #[test]
    fn many_cancellations_of_same_op_after_retracks() {
        let ctrl = CancellationController::new();
        for _ in 0..50 {
            ctrl.track_with_owner("repeated", None);
            let req = cancel_request("repeated", CancelReason::UserRequested);
            let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
            assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
            ctrl.remove("repeated");
        }
        assert_eq!(ctrl.tracked_count(), 0);
        assert_eq!(ctrl.audit_events().len(), 50);
    }

    #[test]
    fn cancel_with_superseded_preserves_by_operation_id_in_audit() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("old_op", None);
        let req = cancel_request(
            "old_op",
            CancelReason::Superseded {
                by_operation_id: "new_op_v2".into(),
            },
        );
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events.len(), 1);
        if let CancelReason::Superseded { by_operation_id } = &events[0].reason {
            assert_eq!(by_operation_id, "new_op_v2");
        } else {
            panic!("expected Superseded reason in audit");
        }
    }

    #[test]
    fn cancel_pending_has_cleanup_result() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_pending", None);
        let req = cancel_request("op_pending", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap(); // First: Cancelled
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap(); // Second: Pending
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
        // Pending also gets a cleanup result per the controller logic.
        assert!(resp.cleanup_result.is_some());
    }

    #[test]
    fn checkpoint_id_format_includes_operation_id() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("my_special_op", None);
        let req = CancellationRequest {
            operation_id: "my_special_op".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
            capability_token: None,
        };
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        let ckpt = resp.checkpoint.unwrap();
        assert_eq!(ckpt.id, "ckpt_my_special_op");
    }

    #[test]
    fn checkpoint_expires_24h_from_now() {
        let now = fixed_now();
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_expiry", None);
        let req = CancellationRequest {
            operation_id: "op_expiry".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
            capability_token: None,
        };
        let resp = ctrl.cancel(&req, None, now).unwrap();
        let ckpt = resp.checkpoint.unwrap();
        let expected_expiry = now + chrono::Duration::hours(24);
        assert_eq!(ckpt.expires_at, Some(expected_expiry));
    }

    #[test]
    fn audit_event_not_recorded_on_error() {
        let ctrl = CancellationController::new();
        // No tracking — cancel should error.
        let req = cancel_request("ghost_op", CancelReason::UserRequested);
        let result = ctrl.cancel(&req, None, fixed_now());
        assert!(result.is_err());
        // No audit event should be recorded for errors.
        assert!(ctrl.audit_events().is_empty());
    }

    #[test]
    fn controller_remove_cancelled_does_not_affect_audit() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_logged", None);
        ctrl.cancel(
            &cancel_request("op_logged", CancelReason::UserRequested),
            None,
            fixed_now(),
        )
        .unwrap();
        assert_eq!(ctrl.audit_events().len(), 1);

        // Removing the operation does not clear its audit entry.
        ctrl.remove("op_logged");
        assert_eq!(ctrl.audit_events().len(), 1);
        assert_eq!(ctrl.audit_events()[0].operation_id, "op_logged");
    }

    #[test]
    fn controller_complete_does_not_record_audit() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_complete_only", None);
        ctrl.complete("op_complete_only");
        // Completing without cancelling should produce no audit events.
        assert!(ctrl.audit_events().is_empty());
    }

    #[test]
    fn response_partial_result_is_none_from_controller() {
        // The controller always sets partial_result to None.
        // Callers are responsible for attaching partial results.
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_no_partial", None);
        let req = CancellationRequest {
            operation_id: "op_no_partial".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::default(),
            return_partial: true, // Even with return_partial=true
            capability_token: None,
        };
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert!(resp.partial_result.is_none());
    }

    #[test]
    fn audit_had_partial_result_always_false_from_controller() {
        // The controller always sets had_partial_result to false.
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_audit_partial", None);
        let req = CancellationRequest {
            operation_id: "op_audit_partial".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::default(),
            return_partial: true,
            capability_token: None,
        };
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        let events = ctrl.audit_events();
        assert!(!events[0].had_partial_result);
    }

    #[test]
    fn controller_track_overwrites_cancelled_state() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_overwrite", None);
        let req = cancel_request("op_overwrite", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert!(ctrl.is_cancel_requested("op_overwrite"));

        // Re-tracking should reset the state (overwrite).
        ctrl.track_with_owner("op_overwrite", None);
        assert!(!ctrl.is_cancel_requested("op_overwrite"));
        assert_eq!(ctrl.tracked_count(), 1);
    }

    #[test]
    fn controller_track_overwrites_completed_state() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_reset", None);
        ctrl.complete("op_reset");
        // Cancel returns TooLate.
        let req = cancel_request("op_reset", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::TooLate);

        // Re-track resets; cancel should now succeed.
        ctrl.track_with_owner("op_reset", None);
        let resp2 = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp2.outcome, CancellationOutcome::Cancelled);
    }

    #[test]
    fn cancel_reason_agent_abort_empty_reason() {
        let r = CancelReason::AgentAbort {
            reason: String::new(),
        };
        assert_eq!(r.label(), "agent_abort");
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::AgentAbort { reason } = parsed {
            assert!(reason.is_empty());
        } else {
            panic!("expected AgentAbort");
        }
    }

    #[test]
    fn multiple_ops_different_reasons_in_audit() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_user", None);
        ctrl.track_with_owner("op_timeout", None);
        ctrl.track_with_owner("op_resource", None);

        ctrl.cancel(
            &cancel_request("op_user", CancelReason::UserRequested),
            None,
            fixed_now(),
        )
        .unwrap();
        ctrl.cancel(
            &cancel_request(
                "op_timeout",
                CancelReason::TimeoutApproaching { remaining_ms: 100 },
            ),
            None,
            fixed_now(),
        )
        .unwrap();
        ctrl.cancel(
            &cancel_request(
                "op_resource",
                CancelReason::ResourceLimit {
                    resource: "mem".into(),
                    current: 95,
                    limit: 100,
                },
            ),
            None,
            fixed_now(),
        )
        .unwrap();

        let events = ctrl.audit_events();
        assert_eq!(events.len(), 3);
        // Newest first.
        assert_eq!(events[0].reason.label(), "resource_limit");
        assert_eq!(events[1].reason.label(), "timeout_approaching");
        assert_eq!(events[2].reason.label(), "user_requested");
    }

    #[test]
    fn cancel_error_message_includes_operation_id() {
        let ctrl = CancellationController::new();
        let req = cancel_request("missing_op_xyz", CancelReason::UserRequested);
        let err = ctrl.cancel(&req, None, fixed_now()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("missing_op_xyz"));
    }

    #[test]
    fn cleanup_result_on_pending_contains_operation_state() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_pending_cleanup", None);
        let req = cancel_request("op_pending_cleanup", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap(); // Cancelled
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap(); // Pending
        let cleanup = resp.cleanup_result.unwrap();
        assert!(cleanup.cleaned.contains(&"operation_state".to_string()));
    }

    #[test]
    fn no_checkpoint_on_pending_even_with_checkpoint_cleanup() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_ckpt_pending", None);
        let req = CancellationRequest {
            operation_id: "op_ckpt_pending".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
            capability_token: None,
        };
        // First cancel: Cancelled, should have checkpoint.
        let resp1 = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp1.outcome, CancellationOutcome::Cancelled);
        assert!(resp1.checkpoint.is_some());

        // Second cancel: Pending, cancel_requested is already true.
        // Outcome is Pending, and checkpoint is only created when outcome == Cancelled.
        let resp2 = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp2.outcome, CancellationOutcome::Pending);
        assert!(resp2.checkpoint.is_none());
    }

    #[test]
    fn audit_timestamp_matches_provided_now() {
        let now = Utc.with_ymd_and_hms(2025, 1, 15, 8, 30, 0).unwrap();
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_ts", None);
        ctrl.cancel(
            &cancel_request("op_ts", CancelReason::UserRequested),
            None,
            now,
        )
        .unwrap();
        let events = ctrl.audit_events();
        assert_eq!(events[0].timestamp, now);
    }

    // ── NEW: CancelReason clone fidelity ──

    #[test]
    fn cancel_reason_clone_user_requested() {
        let original = CancelReason::UserRequested;
        let cloned = original.clone();
        assert_eq!(original.label(), cloned.label());
    }

    #[test]
    fn cancel_reason_clone_agent_abort_preserves_reason() {
        let original = CancelReason::AgentAbort {
            reason: "out of memory".into(),
        };
        let cloned = original.clone();
        if let (
            CancelReason::AgentAbort {
                reason: original_reason,
            },
            CancelReason::AgentAbort { reason },
        ) = (&original, cloned)
        {
            assert_eq!(reason, *original_reason);
        } else {
            panic!("expected AgentAbort after clone");
        }
    }

    #[test]
    fn cancel_reason_clone_timeout_preserves_remaining_ms() {
        let original = CancelReason::TimeoutApproaching {
            remaining_ms: 12345,
        };
        let cloned = original.clone();
        if let (
            CancelReason::TimeoutApproaching {
                remaining_ms: original_remaining_ms,
            },
            CancelReason::TimeoutApproaching { remaining_ms },
        ) = (&original, cloned)
        {
            assert_eq!(remaining_ms, *original_remaining_ms);
        } else {
            panic!("expected TimeoutApproaching after clone");
        }
    }

    #[test]
    fn cancel_reason_clone_resource_limit_preserves_fields() {
        let original = CancelReason::ResourceLimit {
            resource: "gpu_vram".into(),
            current: 7500,
            limit: 8000,
        };
        let cloned = original.clone();
        if let (
            CancelReason::ResourceLimit {
                resource: original_resource,
                current: original_current,
                limit: original_limit,
            },
            CancelReason::ResourceLimit {
                resource,
                current,
                limit,
            },
        ) = (&original, cloned)
        {
            assert_eq!(resource, *original_resource);
            assert_eq!(current, *original_current);
            assert_eq!(limit, *original_limit);
        } else {
            panic!("expected ResourceLimit after clone");
        }
    }

    #[test]
    fn cancel_reason_clone_superseded_preserves_id() {
        let original = CancelReason::Superseded {
            by_operation_id: "op_replacement_v3".into(),
        };
        let cloned = original.clone();
        if let (
            CancelReason::Superseded {
                by_operation_id: original_id,
            },
            CancelReason::Superseded { by_operation_id },
        ) = (&original, cloned)
        {
            assert_eq!(by_operation_id, *original_id);
        } else {
            panic!("expected Superseded after clone");
        }
    }

    #[test]
    fn cancel_reason_clone_session_closing() {
        let original = CancelReason::SessionClosing;
        let cloned = original.clone();
        assert_eq!(original.label(), cloned.label());
        assert_eq!(cloned.label(), "session_closing");
    }

    // ── NEW: CancelReason debug formatting ──

    #[test]
    fn cancel_reason_debug_user_requested() {
        let r = CancelReason::UserRequested;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("UserRequested"));
    }

    #[test]
    fn cancel_reason_debug_agent_abort_includes_reason() {
        let r = CancelReason::AgentAbort {
            reason: "disk full".into(),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("AgentAbort"));
        assert!(dbg.contains("disk full"));
    }

    #[test]
    fn cancel_reason_debug_timeout_includes_ms() {
        let r = CancelReason::TimeoutApproaching { remaining_ms: 999 };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("TimeoutApproaching"));
        assert!(dbg.contains("999"));
    }

    #[test]
    fn cancel_reason_debug_resource_limit_includes_fields() {
        let r = CancelReason::ResourceLimit {
            resource: "threads".into(),
            current: 50,
            limit: 64,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ResourceLimit"));
        assert!(dbg.contains("threads"));
        assert!(dbg.contains("50"));
        assert!(dbg.contains("64"));
    }

    // ── NEW: CancelReason boundary values ──

    #[test]
    fn cancel_reason_timeout_zero_remaining() {
        let r = CancelReason::TimeoutApproaching { remaining_ms: 0 };
        assert_eq!(r.label(), "timeout_approaching");
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::TimeoutApproaching { remaining_ms } = parsed {
            assert_eq!(remaining_ms, 0);
        } else {
            panic!("expected TimeoutApproaching");
        }
    }

    #[test]
    fn cancel_reason_timeout_max_remaining() {
        let r = CancelReason::TimeoutApproaching {
            remaining_ms: u64::MAX,
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::TimeoutApproaching { remaining_ms } = parsed {
            assert_eq!(remaining_ms, u64::MAX);
        } else {
            panic!("expected TimeoutApproaching");
        }
    }

    #[test]
    fn cancel_reason_resource_limit_current_equals_limit() {
        let r = CancelReason::ResourceLimit {
            resource: "connections".into(),
            current: 100,
            limit: 100,
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::ResourceLimit { current, limit, .. } = parsed {
            assert_eq!(current, limit);
        } else {
            panic!("expected ResourceLimit");
        }
    }

    #[test]
    fn cancel_reason_resource_limit_current_exceeds_limit() {
        let r = CancelReason::ResourceLimit {
            resource: "memory_mb".into(),
            current: 2048,
            limit: 1024,
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::ResourceLimit { current, limit, .. } = parsed {
            assert!(current > limit);
        } else {
            panic!("expected ResourceLimit");
        }
    }

    #[test]
    fn cancel_reason_resource_limit_zero_values() {
        let r = CancelReason::ResourceLimit {
            resource: "quota".into(),
            current: 0,
            limit: 0,
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::ResourceLimit { current, limit, .. } = parsed {
            assert_eq!(current, 0);
            assert_eq!(limit, 0);
        } else {
            panic!("expected ResourceLimit");
        }
    }

    // ── NEW: CancelReason serde edge cases ──

    #[test]
    fn cancel_reason_agent_abort_unicode_reason() {
        let r = CancelReason::AgentAbort {
            reason: "\u{1F4A5} explosion detected \u{2603}".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::AgentAbort { reason } = parsed {
            assert!(reason.contains("explosion"));
        } else {
            panic!("expected AgentAbort");
        }
    }

    #[test]
    fn cancel_reason_superseded_unicode_id() {
        let r = CancelReason::Superseded {
            by_operation_id: "\u{00E9}t\u{00E9}".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CancelReason = serde_json::from_str(&json).unwrap();
        if let CancelReason::Superseded { by_operation_id } = parsed {
            assert_eq!(by_operation_id, "\u{00E9}t\u{00E9}");
        } else {
            panic!("expected Superseded");
        }
    }

    #[test]
    fn cancel_reason_missing_required_field_rejected() {
        // AgentAbort requires `reason` field
        let json = r#"{"type":"agent_abort"}"#;
        let result = serde_json::from_str::<CancelReason>(json);
        assert!(result.is_err());
    }

    #[test]
    fn cancel_reason_resource_limit_missing_field_rejected() {
        let json = r#"{"type":"resource_limit","resource":"cpu","current":50}"#;
        let result = serde_json::from_str::<CancelReason>(json);
        assert!(result.is_err());
    }

    // ── NEW: CleanupBehavior clone and debug ──

    #[test]
    fn cleanup_best_effort_debug() {
        let c = CleanupBehavior::BestEffort;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("BestEffort"));
    }

    #[test]
    fn cleanup_full_debug_includes_timeout() {
        let c = CleanupBehavior::Full { timeout_ms: 7777 };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Full"));
        assert!(dbg.contains("7777"));
    }

    #[test]
    fn cleanup_abandon_debug() {
        let c = CleanupBehavior::Abandon;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Abandon"));
    }

    #[test]
    fn cleanup_checkpoint_debug() {
        let c = CleanupBehavior::Checkpoint;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Checkpoint"));
    }

    #[test]
    fn cleanup_clone_full_preserves_timeout() {
        let c = CleanupBehavior::Full { timeout_ms: 9999 };
        let cloned = c.clone();
        if let (
            CleanupBehavior::Full {
                timeout_ms: original_timeout_ms,
            },
            CleanupBehavior::Full { timeout_ms },
        ) = (&c, cloned)
        {
            assert_eq!(timeout_ms, *original_timeout_ms);
        } else {
            panic!("expected Full after clone");
        }
    }

    #[test]
    fn cleanup_full_max_timeout() {
        let c = CleanupBehavior::Full {
            timeout_ms: u64::MAX,
        };
        let json = serde_json::to_string(&c).unwrap();
        let parsed: CleanupBehavior = serde_json::from_str(&json).unwrap();
        if let CleanupBehavior::Full { timeout_ms } = parsed {
            assert_eq!(timeout_ms, u64::MAX);
        } else {
            panic!("expected Full");
        }
    }

    #[test]
    fn cleanup_best_effort_json_roundtrip() {
        let c = CleanupBehavior::BestEffort;
        let json = serde_json::to_string(&c).unwrap();
        let parsed: CleanupBehavior = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, CleanupBehavior::BestEffort));
    }

    // ── NEW: CancellationOutcome copy semantics ──

    #[test]
    fn outcome_copy_semantics() {
        let a = CancellationOutcome::Cancelled;
        let b = a; // Copy
        assert_eq!(a, b); // `a` still usable after copy
    }

    #[test]
    fn outcome_clone_equals_copy() {
        let a = CancellationOutcome::Failed;
        let b = a;
        let c = a;
        assert_eq!(b, c);
    }

    #[test]
    fn outcome_debug_all_variants() {
        let dbg_cancelled = format!("{:?}", CancellationOutcome::Cancelled);
        let dbg_too_late = format!("{:?}", CancellationOutcome::TooLate);
        let dbg_pending = format!("{:?}", CancellationOutcome::Pending);
        let dbg_failed = format!("{:?}", CancellationOutcome::Failed);
        assert!(dbg_cancelled.contains("Cancelled"));
        assert!(dbg_too_late.contains("TooLate"));
        assert!(dbg_pending.contains("Pending"));
        assert!(dbg_failed.contains("Failed"));
    }

    #[test]
    fn outcome_deserialize_cancelled() {
        let parsed: CancellationOutcome = serde_json::from_str("\"cancelled\"").unwrap();
        assert_eq!(parsed, CancellationOutcome::Cancelled);
    }

    #[test]
    fn outcome_deserialize_too_late() {
        let parsed: CancellationOutcome = serde_json::from_str("\"too_late\"").unwrap();
        assert_eq!(parsed, CancellationOutcome::TooLate);
    }

    #[test]
    fn outcome_deserialize_invalid_rejected() {
        let result = serde_json::from_str::<CancellationOutcome>("\"exploded\"");
        assert!(result.is_err());
    }

    // ── NEW: PartialResult edge cases ──

    #[test]
    fn partial_result_clone_preserves_all_fields() {
        let pr = PartialResult {
            completed_items: 77,
            total_items: Some(200),
            data: Some(serde_json::json!({"key": "val"})),
        };
        let cloned = pr.clone();
        assert_eq!(pr.completed_items, cloned.completed_items);
        assert_eq!(pr.total_items, cloned.total_items);
        assert_eq!(pr.data, cloned.data);
    }

    #[test]
    fn partial_result_debug_formatting() {
        let pr = PartialResult {
            completed_items: 5,
            total_items: None,
            data: None,
        };
        let dbg = format!("{pr:?}");
        assert!(dbg.contains("PartialResult"));
        assert!(dbg.contains('5'));
    }

    #[test]
    fn partial_result_zero_completed_items() {
        let pr = PartialResult {
            completed_items: 0,
            total_items: Some(1000),
            data: None,
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.completed_items, 0);
        assert_eq!(parsed.total_items, Some(1000));
    }

    #[test]
    fn partial_result_total_items_zero() {
        let pr = PartialResult {
            completed_items: 0,
            total_items: Some(0),
            data: None,
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_items, Some(0));
    }

    #[test]
    fn partial_result_with_null_json_data() {
        // `Some(Value::Null)` serializes as `"data": null`, which serde
        // deserializes back to `None` for `Option` fields. Verify this
        // round-trip behavior.
        let pr = PartialResult {
            completed_items: 1,
            total_items: None,
            data: Some(serde_json::Value::Null),
        };
        let json = serde_json::to_string(&pr).unwrap();
        assert!(json.contains("null"));
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        // serde coerces `null` → None for Option fields
        assert!(parsed.data.is_none());
    }

    #[test]
    fn partial_result_with_nested_array_data() {
        let pr = PartialResult {
            completed_items: 2,
            total_items: None,
            data: Some(serde_json::json!([[1, 2], [3, 4]])),
        };
        let json = serde_json::to_string(&pr).unwrap();
        let parsed: PartialResult = serde_json::from_str(&json).unwrap();
        let arr = parsed.data.unwrap();
        assert!(arr.is_array());
        assert_eq!(arr.as_array().unwrap().len(), 2);
    }

    // ── NEW: CheckpointInfo edge cases ──

    #[test]
    fn checkpoint_info_clone_preserves_all_fields() {
        let ckpt = CheckpointInfo {
            id: "ckpt_clone_test".into(),
            resumable: false,
            expires_at: Some(fixed_now()),
            state: Some(serde_json::json!({"page": 99})),
        };
        let cloned = ckpt.clone();
        assert_eq!(ckpt.id, cloned.id);
        assert_eq!(ckpt.resumable, cloned.resumable);
        assert_eq!(ckpt.expires_at, cloned.expires_at);
        assert_eq!(ckpt.state, cloned.state);
    }

    #[test]
    fn checkpoint_info_debug_formatting() {
        let ckpt = CheckpointInfo {
            id: "ckpt_dbg".into(),
            resumable: true,
            expires_at: None,
            state: None,
        };
        let dbg = format!("{ckpt:?}");
        assert!(dbg.contains("CheckpointInfo"));
        assert!(dbg.contains("ckpt_dbg"));
    }

    #[test]
    fn checkpoint_info_empty_id() {
        let ckpt = CheckpointInfo {
            id: String::new(),
            resumable: true,
            expires_at: None,
            state: None,
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        assert!(parsed.id.is_empty());
    }

    #[test]
    fn checkpoint_info_complex_state() {
        let ckpt = CheckpointInfo {
            id: "ckpt_complex".into(),
            resumable: true,
            expires_at: None,
            state: Some(serde_json::json!({
                "cursor": "abc123",
                "page": 42,
                "filters": ["active", "pending"],
                "nested": {"depth": 3}
            })),
        };
        let json = serde_json::to_string(&ckpt).unwrap();
        let parsed: CheckpointInfo = serde_json::from_str(&json).unwrap();
        let state = parsed.state.unwrap();
        assert_eq!(state["cursor"], "abc123");
        assert_eq!(state["page"], 42);
        assert!(state["filters"].is_array());
    }

    // ── NEW: CleanupResult edge cases ──

    #[test]
    fn cleanup_result_clone_preserves_all_fields() {
        let cr = CleanupResult {
            success: false,
            cleaned: vec!["a".into(), "b".into()],
            failed: vec!["c".into()],
            duration_ms: 42,
        };
        let cloned = cr.clone();
        assert_eq!(cr.success, cloned.success);
        assert_eq!(cr.cleaned, cloned.cleaned);
        assert_eq!(cr.failed, cloned.failed);
        assert_eq!(cr.duration_ms, cloned.duration_ms);
    }

    #[test]
    fn cleanup_result_debug_formatting() {
        let cr = CleanupResult {
            success: true,
            cleaned: vec!["temp".into()],
            failed: vec![],
            duration_ms: 1,
        };
        let dbg = format!("{cr:?}");
        assert!(dbg.contains("CleanupResult"));
        assert!(dbg.contains("temp"));
    }

    #[test]
    fn cleanup_result_large_duration() {
        let cr = CleanupResult {
            success: true,
            cleaned: vec![],
            failed: vec![],
            duration_ms: u64::MAX,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.duration_ms, u64::MAX);
    }

    #[test]
    fn cleanup_result_many_items() {
        let cleaned: Vec<String> = (0..100).map(|i| format!("resource_{i}")).collect();
        let failed: Vec<String> = (0..50).map(|i| format!("stuck_{i}")).collect();
        let cr = CleanupResult {
            success: false,
            cleaned: cleaned.clone(),
            failed: failed.clone(),
            duration_ms: 5000,
        };
        let json = serde_json::to_string(&cr).unwrap();
        let parsed: CleanupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cleaned, cleaned);
        assert_eq!(parsed.failed, failed);
    }

    // ── NEW: CancellationAuditEvent edge cases ──

    #[test]
    fn audit_event_debug_formatting() {
        let event = CancellationAuditEvent {
            timestamp: fixed_now(),
            operation_id: "op_dbg".into(),
            reason: CancelReason::UserRequested,
            outcome: CancellationOutcome::Cancelled,
            duration_ms: 0,
            had_partial_result: false,
            had_checkpoint: false,
            forced: false,
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("CancellationAuditEvent"));
        assert!(dbg.contains("op_dbg"));
    }

    #[test]
    fn audit_event_with_failed_outcome_roundtrip() {
        let event = CancellationAuditEvent {
            timestamp: fixed_now(),
            operation_id: "op_failed".into(),
            reason: CancelReason::SessionClosing,
            outcome: CancellationOutcome::Failed,
            duration_ms: 999,
            had_partial_result: true,
            had_checkpoint: false,
            forced: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CancellationAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.outcome, CancellationOutcome::Failed);
        assert!(parsed.had_partial_result);
        assert!(!parsed.had_checkpoint);
    }

    #[test]
    fn audit_event_zero_duration() {
        let event = CancellationAuditEvent {
            timestamp: fixed_now(),
            operation_id: "op_instant".into(),
            reason: CancelReason::UserRequested,
            outcome: CancellationOutcome::Cancelled,
            duration_ms: 0,
            had_partial_result: false,
            had_checkpoint: false,
            forced: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CancellationAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.duration_ms, 0);
    }

    #[test]
    fn audit_event_max_duration() {
        let event = CancellationAuditEvent {
            timestamp: fixed_now(),
            operation_id: "op_eternal".into(),
            reason: CancelReason::UserRequested,
            outcome: CancellationOutcome::Pending,
            duration_ms: u64::MAX,
            had_partial_result: false,
            had_checkpoint: false,
            forced: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CancellationAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.duration_ms, u64::MAX);
    }

    // ── NEW: CancellationRequest serde edge cases ──

    #[test]
    fn request_deserialize_missing_cleanup_defaults() {
        let json = r#"{
            "operation_id": "op_minimal",
            "reason": {"type": "session_closing"}
        }"#;
        let parsed: CancellationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.operation_id, "op_minimal");
        assert!(matches!(parsed.cleanup, CleanupBehavior::BestEffort));
        assert!(!parsed.return_partial);
    }

    #[test]
    fn request_deserialize_missing_operation_id_rejected() {
        let json = r#"{"reason": {"type": "user_requested"}}"#;
        let result = serde_json::from_str::<CancellationRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn request_deserialize_missing_reason_rejected() {
        let json = r#"{"operation_id": "op_no_reason"}"#;
        let result = serde_json::from_str::<CancellationRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn request_debug_formatting() {
        let req = cancel_request("op_dbg_req", CancelReason::UserRequested);
        let dbg = format!("{req:?}");
        assert!(dbg.contains("CancellationRequest"));
        assert!(dbg.contains("op_dbg_req"));
    }

    #[test]
    fn request_clone_preserves_all_fields() {
        let req = CancellationRequest {
            operation_id: "op_clone_req".into(),
            reason: CancelReason::TimeoutApproaching { remaining_ms: 500 },
            cleanup: CleanupBehavior::Full { timeout_ms: 3000 },
            return_partial: true,
            capability_token: None,
        };
        let cloned = req.clone();
        assert_eq!(req.operation_id, cloned.operation_id);
        assert_eq!(req.return_partial, cloned.return_partial);
        assert!(matches!(
            cloned.cleanup,
            CleanupBehavior::Full { timeout_ms: 3000 }
        ));
    }

    // ── NEW: CancellationResponse edge cases ──

    #[test]
    fn response_debug_formatting() {
        let resp = CancellationResponse {
            operation_id: "op_dbg_resp".into(),
            outcome: CancellationOutcome::TooLate,
            partial_result: None,
            checkpoint: None,
            cleanup_result: None,
            duration_ms: 7,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("CancellationResponse"));
        assert!(dbg.contains("op_dbg_resp"));
    }

    #[test]
    fn response_clone_preserves_all_fields() {
        let resp = CancellationResponse {
            operation_id: "op_clone_resp".into(),
            outcome: CancellationOutcome::Cancelled,
            partial_result: Some(PartialResult {
                completed_items: 5,
                total_items: Some(10),
                data: None,
            }),
            checkpoint: Some(CheckpointInfo {
                id: "ckpt_clone".into(),
                resumable: true,
                expires_at: None,
                state: None,
            }),
            cleanup_result: Some(CleanupResult {
                success: true,
                cleaned: vec!["state".into()],
                failed: vec![],
                duration_ms: 1,
            }),
            duration_ms: 3,
        };
        let cloned = resp.clone();
        assert_eq!(resp.operation_id, cloned.operation_id);
        assert_eq!(resp.outcome, cloned.outcome);
        assert_eq!(resp.duration_ms, cloned.duration_ms);
        assert!(cloned.partial_result.is_some());
        assert!(cloned.checkpoint.is_some());
        assert!(cloned.cleanup_result.is_some());
    }

    #[test]
    fn response_zero_duration() {
        let resp = CancellationResponse {
            operation_id: "op_instant_resp".into(),
            outcome: CancellationOutcome::TooLate,
            partial_result: None,
            checkpoint: None,
            cleanup_result: None,
            duration_ms: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: CancellationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.duration_ms, 0);
    }

    // ── NEW: Controller advanced scenarios ──

    #[test]
    fn controller_interleaved_track_complete_cancel() {
        let ctrl = CancellationController::new();
        // Track three ops
        ctrl.track_with_owner("a", None);
        ctrl.track_with_owner("b", None);
        ctrl.track_with_owner("c", None);

        // Complete b, cancel a, then try to cancel b (too late)
        ctrl.complete("b");
        let resp_a = ctrl
            .cancel(
                &cancel_request("a", CancelReason::UserRequested),
                None,
                fixed_now(),
            )
            .unwrap();
        assert_eq!(resp_a.outcome, CancellationOutcome::Cancelled);

        let resp_b = ctrl
            .cancel(
                &cancel_request("b", CancelReason::UserRequested),
                None,
                fixed_now(),
            )
            .unwrap();
        assert_eq!(resp_b.outcome, CancellationOutcome::TooLate);

        // c is still active
        assert!(!ctrl.is_cancel_requested("c"));

        let events = ctrl.audit_events();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn controller_unicode_operation_ids() {
        let ctrl = CancellationController::new();
        let ids = [
            "\u{4F60}\u{597D}",
            "\u{00E9}t\u{00E9}",
            "\u{1F680}rocket",
            "\u{00DF}tra\u{00DF}e",
        ];
        for id in &ids {
            ctrl.track_with_owner(id, None);
        }
        assert_eq!(ctrl.tracked_count(), 4);
        for id in &ids {
            let req = cancel_request(id, CancelReason::SessionClosing);
            let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
            assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
            assert_eq!(resp.operation_id, *id);
        }
        assert_eq!(ctrl.audit_events().len(), 4);
    }

    #[test]
    fn controller_remove_then_cancel_errors() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_remove_cancel", None);
        ctrl.remove("op_remove_cancel");
        let req = cancel_request("op_remove_cancel", CancelReason::UserRequested);
        let err = ctrl.cancel(&req, None, fixed_now()).unwrap_err();
        assert!(err.to_string().contains("operation not found"));
    }

    #[test]
    fn controller_complete_then_retrack_then_cancel() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_reborn", None);
        ctrl.complete("op_reborn");

        // Retrack the same ID — should be fresh
        ctrl.track_with_owner("op_reborn", None);
        let req = cancel_request("op_reborn", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
    }

    #[test]
    fn controller_cancel_then_complete_then_retrack() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_flow", None);
        // Cancel
        let req = cancel_request("op_flow", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert!(ctrl.is_cancel_requested("op_flow"));

        // Complete after cancel
        ctrl.complete("op_flow");

        // Retrack resets
        ctrl.track_with_owner("op_flow", None);
        assert!(!ctrl.is_cancel_requested("op_flow"));
    }

    #[test]
    fn controller_audit_events_empty_initially() {
        let ctrl = CancellationController::new();
        assert!(ctrl.audit_events().is_empty());
    }

    #[test]
    fn controller_audit_events_returns_clone() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_audit_clone", None);
        ctrl.cancel(
            &cancel_request("op_audit_clone", CancelReason::UserRequested),
            None,
            fixed_now(),
        )
        .unwrap();
        let events1 = ctrl.audit_events();
        let events2 = ctrl.audit_events();
        // Both return independent clones
        assert_eq!(events1.len(), events2.len());
        assert_eq!(events1[0].operation_id, events2[0].operation_id);
    }

    #[test]
    fn controller_checkpoint_not_created_on_failed_outcome() {
        // The controller never produces Failed outcome directly, but verify
        // that TooLate (which is produced) never gets a checkpoint
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_ckpt_fail", None);
        ctrl.complete("op_ckpt_fail");
        let req = CancellationRequest {
            operation_id: "op_ckpt_fail".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: true,
            capability_token: None,
        };
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::TooLate);
        assert!(resp.checkpoint.is_none());
        assert!(resp.cleanup_result.is_none());
    }

    #[test]
    fn controller_cancel_with_different_timestamps() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_t1", None);
        ctrl.track_with_owner("op_t2", None);
        let t1 = Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();
        let t2 = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();

        ctrl.cancel(
            &cancel_request("op_t1", CancelReason::UserRequested),
            None,
            t1,
        )
        .unwrap();
        ctrl.cancel(
            &cancel_request("op_t2", CancelReason::SessionClosing),
            None,
            t2,
        )
        .unwrap();

        let events = ctrl.audit_events();
        // Newest first
        assert_eq!(events[0].timestamp, t2);
        assert_eq!(events[1].timestamp, t1);
    }

    #[test]
    fn controller_cleanup_result_cleaned_contains_operation_state() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_verify_cleanup", None);
        let req = cancel_request("op_verify_cleanup", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        let cleanup = resp.cleanup_result.unwrap();
        assert_eq!(cleanup.cleaned, vec!["operation_state"]);
        assert!(cleanup.failed.is_empty());
        assert!(cleanup.success);
    }
    // ── flywheel_connectors-861lx: cancellation deadlines ──

    #[test]
    fn default_cancellation_deadline_per_archetype() {
        assert_eq!(
            default_cancellation_deadline(ConnectorArchetype::RequestResponse),
            DEFAULT_CANCELLATION_DEADLINE_ONE_SHOT
        );
        assert_eq!(
            default_cancellation_deadline(ConnectorArchetype::Webhook),
            DEFAULT_CANCELLATION_DEADLINE_ONE_SHOT
        );
        for long_lived in [
            ConnectorArchetype::Streaming,
            ConnectorArchetype::Bidirectional,
            ConnectorArchetype::Polling,
            ConnectorArchetype::Unknown,
        ] {
            assert_eq!(
                default_cancellation_deadline(long_lived),
                DEFAULT_CANCELLATION_DEADLINE_LONG_LIVED
            );
        }
    }

    #[test]
    fn scope_override_wins_over_archetype_default() {
        let overridden = CancellationScope::new("c:rr:1.0", ConnectorArchetype::RequestResponse)
            .with_deadline_override_ms(Some(250));
        assert_eq!(overridden.effective_deadline(), Duration::from_millis(250));

        let defaulted = CancellationScope::new("c:rr:1.0", ConnectorArchetype::RequestResponse);
        assert_eq!(
            defaulted.effective_deadline(),
            DEFAULT_CANCELLATION_DEADLINE_ONE_SHOT
        );
    }

    #[test]
    fn deadline_expiry_reaps_only_overdue_uncompleted_ops() {
        let ctrl = CancellationController::new();
        ctrl.track_operation(
            "op_overdue",
            Some("user:alice"),
            CancellationScope::new("c:slow:1.0", ConnectorArchetype::RequestResponse)
                .with_deadline_override_ms(Some(100)),
        );
        ctrl.track_operation(
            "op_completed",
            Some("user:alice"),
            CancellationScope::new("c:fast:1.0", ConnectorArchetype::RequestResponse)
                .with_deadline_override_ms(Some(100)),
        );
        ctrl.track_operation(
            "op_not_cancelled",
            Some("user:alice"),
            CancellationScope::new("c:idle:1.0", ConnectorArchetype::RequestResponse)
                .with_deadline_override_ms(Some(100)),
        );
        let start = Instant::now();
        for id in ["op_overdue", "op_completed"] {
            let req = cancel_request(id, CancelReason::UserRequested);
            ctrl.cancel(&req, Some("user:alice"), fixed_now()).unwrap();
        }
        ctrl.complete("op_completed");

        // Before the deadline: nothing expires.
        assert!(
            ctrl.reap_expired(start + Duration::from_millis(50))
                .is_empty()
        );

        // At/after the deadline: only the overdue uncompleted op expires.
        let expired = ctrl.reap_expired(start + Duration::from_millis(150));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].operation_id, "op_overdue");
        assert_eq!(expired[0].connector_id, "c:slow:1.0");
        assert_eq!(expired[0].deadline, Duration::from_millis(100));

        // Idempotence: the second sweep returns nothing.
        assert!(
            ctrl.reap_expired(start + Duration::from_millis(999))
                .is_empty()
        );

        // The tracking entry is kept (invoke completion owns removal); a
        // forced cancel releases no Strict-idempotency intent.
        assert!(ctrl.is_cancel_requested("op_overdue"));
        assert_eq!(ctrl.tracked_count(), 3);
    }

    #[test]
    fn forced_cancellation_records_forced_audit_event() {
        let ctrl = CancellationController::new();
        ctrl.track_operation(
            "op_forced",
            Some("user:alice"),
            CancellationScope::new("c:stuck:1.0", ConnectorArchetype::Streaming)
                .with_deadline_override_ms(Some(50)),
        );
        let req = cancel_request(
            "op_forced",
            CancelReason::AgentAbort {
                reason: "stuck".into(),
            },
        );
        ctrl.cancel(&req, Some("user:alice"), fixed_now()).unwrap();
        let expired = ctrl.reap_expired(Instant::now() + Duration::from_millis(100));
        assert_eq!(expired.len(), 1);
        ctrl.record_forced_cancellation("op_forced", fixed_now());

        let events = ctrl.audit_events();
        assert_eq!(events.len(), 2); // graceful request + forced record
        let forced = &events[0]; // newest first
        assert!(forced.forced);
        assert_eq!(forced.outcome, CancellationOutcome::Cancelled);
        assert!(matches!(forced.reason, CancelReason::AgentAbort { .. }));

        // Bookkeeping-only registrations never expire, even far past any
        // conceivable deadline.
        let plain = CancellationController::new();
        plain.track_with_owner("op_plain", None);
        let req = cancel_request("op_plain", CancelReason::UserRequested);
        plain.cancel(&req, None, fixed_now()).unwrap();
        assert!(
            plain
                .reap_expired(Instant::now() + Duration::from_secs(3600))
                .is_empty()
        );
    }

    // ── flywheel_connectors-861lx: real force-terminate sequence ──

    /// The SIGTERM lands immediately on a responsive process; the elapsed
    /// time is dominated by the grace window.
    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn force_terminate_child_kills_responsive_process() {
        let mut child = fcp_async_core::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sleep process");
        let start = Instant::now();
        force_terminate_child(&mut child, Duration::from_millis(100)).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(2_500),
            "force-terminate must complete promptly, took {elapsed:?}"
        );
        fcp_async_core::time::sleep(Duration::from_millis(150)).await;
        let status = child
            .try_wait()
            .expect("try_wait must succeed after kill")
            .expect("responsive process must have exited after SIGTERM");
        assert!(
            !status.success(),
            "SIGTERM-terminated process must not report success"
        );
    }

    /// A process that ignores SIGTERM must still die: the SIGKILL
    /// backstop escalates after the grace window.
    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn force_terminate_child_sigkill_backstop_beats_term_trap() {
        let mut child = fcp_async_core::process::Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; sleep 30")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn term-trapping process");
        force_terminate_child(&mut child, Duration::from_millis(100)).await;
        fcp_async_core::time::sleep(Duration::from_millis(150)).await;
        let status = child
            .try_wait()
            .expect("try_wait must succeed after kill")
            .expect("SIGKILL backstop must terminate a SIGTERM-immune process");
        assert!(
            !status.success(),
            "SIGKILL-terminated process must not report success"
        );
    }
}
