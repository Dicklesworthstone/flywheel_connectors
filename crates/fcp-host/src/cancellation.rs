//! Operation cancellation: graceful abort with cleanup and audit.
//!
//! Provides types and logic for cancelling in-flight operations with:
//! - Reason codes explaining why cancellation was requested
//! - Cleanup behavior control (best-effort, full, abandon, checkpoint)
//! - Runtime-reported partial results, cleanup and checkpoint evidence
//! - Bounded in-memory history of cancellation decisions
//!
//! Recent completed registrations are retained for late cancellation diagnostics.
//! Active operations, unsettled runtimes and owned, unacknowledged termination
//! attempts are never evicted to make room for history. Durable invocation
//! records remain the authority for historical outcomes after this cache evicts
//! a completed registration. Audit history is also bounded; its discarded-event
//! counter makes truncation and explicit clears observable.
//!
//! Based on bead `flywheel_connectors-2653`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use fcp_async_core::process::Child;

use chrono::{DateTime, Utc};
pub use fcp_kernel::{
    CancelReason, CancellationAuditEvent, CancellationOutcome, CancellationRequest,
    CancellationResponse, CheckpointInfo, CleanupBehavior, CleanupResult, PartialResult,
};

use crate::{HostError, HostResult};

use crate::ConnectorArchetype;

mod terminator;
pub use terminator::CancellationTerminator;

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

/// Signed origin and invocation generation that admitted a relayed operation.
/// This binding is retained after completion so an old relay cannot cancel a
/// newer invocation that reuses the same client operation ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCancellationBinding {
    /// Authenticated mesh node that originally forwarded the invocation.
    pub origin_node: String,
    /// Invocation attempt allocated by that origin before forwarding.
    pub origin_attempt_id: u64,
}

/// Deadline policy recorded when a subprocess-backed operation is tracked.
/// Registrations without a backing subprocess
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
    /// Optional concrete-runtime terminator. Unsupported runtimes must not
    /// be falsely reported as force-terminated.
    pub terminator: Option<CancellationTerminator>,
    /// Signed mesh origin and invocation generation, when this is a relay.
    pub relay: Option<RelayCancellationBinding>,
}

impl CancellationScope {
    /// Build a scope with the archetype-default deadline.
    #[must_use]
    pub fn new(connector_id: impl Into<String>, archetype: ConnectorArchetype) -> Self {
        Self {
            connector_id: connector_id.into(),
            archetype,
            deadline_override: None,
            terminator: None,
            relay: None,
        }
    }

    /// Attach a concrete runtime termination path to this operation.
    #[must_use]
    pub fn with_terminator(mut self, terminator: CancellationTerminator) -> Self {
        self.terminator = Some(terminator);
        self
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
///
/// Retain this handle through the termination attempt, then report its result
/// with the registration-aware controller methods. Clones share attempt
/// ownership. If every handle disappears without a recorded result, a later
/// sweep can retry a supported runtime without resetting its original deadline.
#[derive(Debug, Clone)]
pub struct ExpiredCancellation {
    /// Operation that ignored its cancellation past the deadline.
    pub operation_id: String,
    /// Connector identifier for audit labeling ONLY, not target lookup.
    pub connector_id: String,
    /// The effective deadline that expired.
    pub deadline: Duration,
    /// Captured runtime from the operation, not the current registry entry.
    pub terminator: Option<CancellationTerminator>,
    registration: Arc<()>,
    // The operation map holds only a Weak reference. Task cancellation, unwind,
    // or dropping an unpolled attempt therefore cannot strand a dispatch latch.
    attempt: Arc<()>,
}

/// Identity of one registration, independent of a reusable client operation ID.
#[derive(Debug, Clone)]
pub struct CancellationRegistration {
    operation_id: String,
    identity: Arc<()>,
}

/// Evidence supplied by the runtime that owns a cancelled invocation.
///
/// This is an internal completion report, never an HTTP cancellation request.
/// Producers must report only work they actually performed and checkpoints they
/// actually persisted. Missing evidence stays absent: stopping a process does
/// not prove provider rollback, successful cleanup, or resumability.
///
/// The controller retains this report against the exact registration and only
/// exposes it after all owned runtime work has settled.
#[derive(Debug, Clone, Default)]
pub struct CancellationEvidence {
    /// Actual partial output, returned only when the caller requests it.
    pub partial_result: Option<PartialResult>,
    /// A real persisted checkpoint, with the producer's ID and expiry.
    pub checkpoint: Option<CheckpointInfo>,
    /// Observed cleanup results, including any failures.
    pub cleanup_result: Option<CleanupResult>,
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
#[allow(clippy::struct_excessive_bools)]
struct TrackedOperation {
    /// Distinguishes successive registrations using the same client ID.
    registration: Arc<()>,
    /// Whether the operation has been completed.
    completed: bool,
    /// The request waiter ended, but its owned runtime may still be retiring.
    /// Such registrations keep their ID and termination target until settlement.
    completion_pending: bool,
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
    /// Kept separately from scope so completed tombstones still reject stale
    /// mesh cancellations after the runtime termination handle is disarmed.
    relay: Option<RelayCancellationBinding>,
    /// Subprocess-backed deadline policy. `None` for bookkeeping-only
    /// registrations ([`CancellationController::track_with_owner`]),
    /// which never expire and are never force-terminated.
    scope: Option<CancellationScope>,
    /// Monotonic instant cancellation was requested (deadline anchor).
    cancel_requested_at: Option<Instant>,
    /// Original cancellation reason, replayed into the forced audit event.
    cancel_reason: Option<CancelReason>,
    /// A runtime-owned cancellation result, hidden until settlement.
    cancellation_evidence: Option<CancellationEvidence>,
    /// Frozen elapsed cancellation time after the registration settles.
    cancellation_duration_ms: Option<u64>,
    /// A definitive non-cancellation result, recorded before runtime settlement.
    returned_normally: bool,
    /// Whether an attempt was dispatched. Unsupported targets retain this
    /// latch; supported targets may retry after all attempt owners disappear.
    forced_cancel_sent: bool,
    /// Identity and liveness of the current termination attempt, not its runtime.
    force_attempt: Weak<()>,
    /// Acknowledged termination is terminal even if its audit history is cleared.
    forced_cancel_recorded: bool,
}

impl TrackedOperation {
    fn owns_expiration(&self, expired: &ExpiredCancellation) -> bool {
        Arc::ptr_eq(&self.registration, &expired.registration)
            && Weak::ptr_eq(&self.force_attempt, &Arc::downgrade(&expired.attempt))
    }
}

fn disarm_scope(scope: Option<CancellationScope>) {
    if let Some(terminator) = scope.and_then(|scope| scope.terminator) {
        let _ = terminator.disarm();
    }
}

/// Maximum number of recent completed registrations retained as history.
///
/// Live and settling operations are not history and remain owned independently.
const MAX_COMPLETED_OPERATION_HISTORY: usize = 1024;
/// Maximum number of cancellation audit events retained in memory.
const MAX_CANCELLATION_AUDIT_HISTORY: usize = 1024;

#[derive(Default)]
struct OperationTracker {
    entries: HashMap<String, TrackedOperation>,
    completed: VecDeque<CancellationRegistration>,
}

impl OperationTracker {
    /// Remove only completed registrations, and only the exact generation that
    /// entered the history queue. A pending force-result owner pins its record
    /// until acknowledgement or loss of the last attempt handle. This history
    /// limit never authorizes dropping live runtime custody.
    fn prune_completed(&mut self) {
        // Visit each queued generation at most once. If every remaining record
        // is pinned by outstanding work, stop rather than evicting one or spinning.
        let candidates = self.completed.len();
        for _ in 0..candidates {
            if self.completed.len() <= MAX_COMPLETED_OPERATION_HISTORY {
                break;
            }
            let Some(registration) = self.completed.pop_front() else {
                break;
            };
            let Some(operation) = self.entries.get(&registration.operation_id) else {
                continue;
            };
            if !Arc::ptr_eq(&operation.registration, &registration.identity) {
                continue;
            }
            if !operation.completed
                || operation.completion_pending
                || operation.scope.is_some()
                || (!operation.forced_cancel_recorded
                    && operation.force_attempt.strong_count() != 0)
            {
                self.completed.push_back(registration);
                continue;
            }
            self.entries.remove(&registration.operation_id);
        }
    }
}

#[derive(Default)]
struct CancellationAuditLog {
    events: VecDeque<CancellationAuditEvent>,
    discarded: u64,
}

impl CancellationAuditLog {
    fn push(&mut self, event: CancellationAuditEvent) {
        if self.events.len() == MAX_CANCELLATION_AUDIT_HISTORY {
            self.events.pop_front();
            self.discarded = self.discarded.saturating_add(1);
        }
        self.events.push_back(event);
    }

    fn clear(&mut self) {
        self.discarded = self
            .discarded
            .saturating_add(u64::try_from(self.events.len()).unwrap_or(u64::MAX));
        self.events.clear();
    }
}

/// Controller that manages operation tracking and cancellation.
///
/// Completed-operation and audit history are bounded to 1,024 entries each.
/// Outstanding force-result owners can temporarily pin completed registrations
/// beyond that history limit; acknowledgement and the regular reaper release
/// those pins. Active and settling registrations are never evicted.
///
/// # Panics
///
/// Methods that access the internal mutex will panic if the mutex is
/// poisoned (only possible if a thread panicked while holding the lock).
pub struct CancellationController {
    operations: Mutex<OperationTracker>,
    audit_log: Mutex<CancellationAuditLog>,
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
            operations: Mutex::new(OperationTracker::default()),
            audit_log: Mutex::new(CancellationAuditLog::default()),
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
        let previous = {
            let mut ops = self.operations.lock().expect("operations lock");
            ops.prune_completed();
            if ops.entries.contains_key(operation_id) {
                ops.completed
                    .retain(|registration| registration.operation_id != operation_id);
            }
            ops.entries.insert(
                operation_id.to_string(),
                TrackedOperation {
                    registration: Arc::new(()),
                    completed: false,
                    completion_pending: false,
                    cancel_requested: false,
                    owner: owner.map(str::to_string),
                    relay: None,
                    scope: None,
                    cancel_requested_at: None,
                    cancel_reason: None,
                    cancellation_evidence: None,
                    cancellation_duration_ms: None,
                    returned_normally: false,
                    forced_cancel_sent: false,
                    force_attempt: Weak::new(),
                    forced_cancel_recorded: false,
                },
            )
        };
        disarm_scope(previous.and_then(|operation| operation.scope));
    }

    /// Register a subprocess-backed operation with a cancellation deadline
    /// (`flywheel_connectors-861lx`).
    ///
    /// Production invokes MUST use this method: when the operation ignores
    /// a cancellation request past `scope`'s effective deadline, the reaper
    /// reports it via [`Self::reap_expired`] so the host can force-terminate
    /// `scope.connector_id`'s subprocess and audit `forced = true`.
    ///
    /// An active registration reserves its operation ID until completion.
    /// Reusing that ID must not replace its owner or revoke its cancellation
    /// target while the original invocation can still execute.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::PreflightFailed`] if the operation ID is active.
    /// Completed operation IDs may be registered for a new invocation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn track_operation(
        &self,
        operation_id: &str,
        owner: Option<&str>,
        scope: CancellationScope,
    ) -> HostResult<CancellationRegistration> {
        if scope.relay.as_ref().is_some_and(|relay| {
            relay.origin_node.trim().is_empty() || relay.origin_attempt_id == 0
        }) {
            return Err(HostError::PreflightFailed(
                "relayed invocation requires a nonempty origin and nonzero attempt ID".to_owned(),
            ));
        }
        let registration = CancellationRegistration {
            operation_id: operation_id.to_string(),
            identity: Arc::new(()),
        };
        let previous = {
            let mut ops = self.operations.lock().expect("operations lock");
            ops.prune_completed();
            if ops
                .entries
                .get(operation_id)
                .is_some_and(|operation| !operation.completed)
            {
                return Err(HostError::PreflightFailed(format!(
                    "operation ID is already active: {operation_id}"
                )));
            }
            if ops.entries.contains_key(operation_id) {
                ops.completed
                    .retain(|completed| completed.operation_id != operation_id);
            }
            ops.entries.insert(
                operation_id.to_string(),
                TrackedOperation {
                    registration: Arc::clone(&registration.identity),
                    completed: false,
                    completion_pending: false,
                    cancel_requested: false,
                    owner: owner.map(str::to_string),
                    relay: scope.relay.clone(),
                    scope: Some(scope),
                    cancel_requested_at: None,
                    cancel_reason: None,
                    cancellation_evidence: None,
                    cancellation_duration_ms: None,
                    returned_normally: false,
                    forced_cancel_sent: false,
                    force_attempt: Weak::new(),
                    forced_cancel_recorded: false,
                },
            )
        };
        disarm_scope(previous.and_then(|operation| operation.scope));
        Ok(registration)
    }

    /// Mark an operation as completed.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn complete(&self, operation_id: &str) {
        self.complete_matching(operation_id, None);
    }

    /// Complete only the invocation that owns this registration. An older
    /// request must not complete a new request reusing its client ID.
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    pub fn complete_registration(&self, registration: &CancellationRegistration) {
        self.complete_matching(&registration.operation_id, Some(&registration.identity));
    }

    /// Record a definitive non-cancellation result before publishing runtime
    /// settlement. This prevents a force-termination acknowledgement racing
    /// waiter teardown from relabeling a result that already completed normally.
    ///
    /// The producer must call this before its completion probe can report true.
    /// Recording a result does not release runtime custody or complete the
    /// registration. Stale, completed, or contradictory reports are rejected.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn record_returned_registration(&self, registration: &CancellationRegistration) -> bool {
        let mut ops = self.operations.lock().expect("operations lock");
        let Some(op) = ops.entries.get_mut(&registration.operation_id) else {
            return false;
        };
        if !Arc::ptr_eq(&registration.identity, &op.registration)
            || op.completed
            || op.cancellation_evidence.is_some()
            || op.forced_cancel_recorded
        {
            return false;
        }
        op.returned_normally = true;
        true
    }

    /// Report that this runtime took its cancellation path, retaining its real
    /// result until owned work and finalizers have settled.
    ///
    /// Merely observing a controller cancellation request is not sufficient:
    /// the producer must have stopped or abandoned the invocation itself. A
    /// successful response racing a cancellation request uses ordinary
    /// completion instead, so it is never relabeled as cancelled.
    ///
    /// Returns false for stale, already completed, or duplicate reports, and
    /// when no cancellation was requested for this registration. The first
    /// accepted report cannot be replaced by a later callback. A true return
    /// acknowledges the report, not settlement: callers continue seeing
    /// `Pending` while the captured runtime remains live.
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned or a runtime completion probe
    /// panics, as with [`Self::complete_registration_when_settled`].
    #[must_use]
    pub fn complete_cancelled_registration_when_settled(
        &self,
        registration: &CancellationRegistration,
        evidence: CancellationEvidence,
    ) -> bool {
        {
            let mut ops = self.operations.lock().expect("operations lock");
            let Some(op) = ops.entries.get_mut(&registration.operation_id) else {
                return false;
            };
            if !Arc::ptr_eq(&registration.identity, &op.registration)
                || !op.cancel_requested
                || op.completed
                || op.returned_normally
                || op.cancellation_evidence.is_some()
            {
                return false;
            }
            op.cancellation_evidence = Some(evidence);
        }
        self.complete_registration_when_settled(registration);
        true
    }

    /// Release an ended request only after its owned runtime confirms settlement.
    /// A dropped HTTP waiter can leave an active native command behind. Keep the
    /// registration and captured runtime until the host reaper observes exit.
    ///
    /// The runtime callback is always invoked outside the operation map lock.
    /// Callers must signal their own cancellation/retirement before using this
    /// method; this method neither guesses a shared process nor invents an audit.
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    pub fn complete_registration_when_settled(&self, registration: &CancellationRegistration) {
        let terminator = {
            let mut ops = self.operations.lock().expect("operations lock");
            let Some(op) = ops.entries.get_mut(&registration.operation_id) else {
                return;
            };
            if op.completed || !Arc::ptr_eq(&registration.identity, &op.registration) {
                return;
            }
            op.completion_pending = true;
            op.scope.as_ref().and_then(|scope| scope.terminator.clone())
        };
        if terminator
            .as_ref()
            .is_none_or(CancellationTerminator::is_finished)
        {
            self.complete_registration(registration);
        }
    }

    fn complete_settled_registrations(&self) {
        let pending: Vec<_> = {
            let ops = self.operations.lock().expect("operations lock");
            ops.entries
                .iter()
                .filter(|(_, op)| op.completion_pending && !op.completed)
                .map(|(operation_id, op)| {
                    (
                        CancellationRegistration {
                            operation_id: operation_id.clone(),
                            identity: Arc::clone(&op.registration),
                        },
                        op.scope.as_ref().and_then(|scope| scope.terminator.clone()),
                    )
                })
                .collect()
        };
        for (registration, terminator) in pending {
            if terminator
                .as_ref()
                .is_none_or(CancellationTerminator::is_finished)
            {
                self.complete_registration(&registration);
            }
        }
        // A completed record may have been pinned by a force-result handle
        // which disappeared without an acknowledgement between reaper sweeps.
        self.operations
            .lock()
            .expect("operations lock")
            .prune_completed();
    }

    fn complete_matching(&self, operation_id: &str, identity: Option<&Arc<()>>) {
        let scope = {
            let mut ops = self.operations.lock().expect("operations lock");
            let Some(op) = ops.entries.get_mut(operation_id) else {
                return;
            };
            if op.completed
                || identity.is_some_and(|identity| !Arc::ptr_eq(identity, &op.registration))
            {
                return;
            }
            op.completed = true;
            op.completion_pending = false;
            op.cancellation_duration_ms = op
                .cancel_requested_at
                .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX));
            let completed = CancellationRegistration {
                operation_id: operation_id.to_owned(),
                identity: Arc::clone(&op.registration),
            };
            let scope = op.scope.take();
            ops.completed.push_back(completed);
            ops.prune_completed();
            scope
        };
        // Completed tombstones retain ownership/audit metadata, not processes.
        // Revoke callbacks outside the controller lock to avoid drop lock chains.
        disarm_scope(scope);
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
            .entries
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
    /// Operations explicitly tracked without an owner remain cancellable by
    /// any caller. Accepting a request returns `Pending`; `Cancelled` requires
    /// observed runtime cancellation and settlement. Cleanup and checkpoint
    /// fields contain only evidence supplied by that registration's runtime.
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
        self.cancel_matching(request, asserted_principal, None, now)
    }

    /// Cancel only the invocation admitted by this authenticated mesh origin.
    /// The verified principal, retained origin, and origin attempt must all
    /// match under the same lock that performs the cancellation transition.
    /// Completed matching invocations return `TooLate`; a reused operation ID
    /// never transfers cancellation authority to the new invocation.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::ConnectorNotFound`] when the operation is absent,
    /// or [`HostError::PreflightFailed`] for missing or mismatched authority.
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    pub fn cancel_relay(
        &self,
        request: &CancellationRequest,
        verified_principal: &str,
        relay: &RelayCancellationBinding,
        now: DateTime<Utc>,
    ) -> HostResult<CancellationResponse> {
        if verified_principal.trim().is_empty()
            || relay.origin_node.trim().is_empty()
            || relay.origin_attempt_id == 0
        {
            return Err(HostError::PreflightFailed(
                "mesh cancellation requires a verified principal, origin, and attempt ID"
                    .to_owned(),
            ));
        }
        self.cancel_matching(request, Some(verified_principal), Some(relay), now)
    }

    fn cancel_matching(
        &self,
        request: &CancellationRequest,
        asserted_principal: Option<&str>,
        relay: Option<&RelayCancellationBinding>,
        now: DateTime<Utc>,
    ) -> HostResult<CancellationResponse> {
        let start = Instant::now();

        let (outcome, evidence, cancellation_duration_ms) = {
            let mut ops = self.operations.lock().expect("operations lock");
            match ops.entries.get_mut(&request.operation_id) {
                None => {
                    return Err(HostError::ConnectorNotFound(format!(
                        "operation not found: {}",
                        request.operation_id
                    )));
                }
                Some(op) => {
                    if let Some(relay) = relay
                        && (op.owner.is_none() || op.relay.as_ref() != Some(relay))
                    {
                        return Err(HostError::PreflightFailed(format!(
                            "mesh cancellation origin or invocation generation mismatch for operation {}",
                            request.operation_id
                        )));
                    }
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

                    let outcome = if op.completed
                        && op.cancel_requested
                        && !op.returned_normally
                        && (op.cancellation_evidence.is_some() || op.forced_cancel_recorded)
                    {
                        CancellationOutcome::Cancelled
                    } else if op.completed {
                        CancellationOutcome::TooLate
                    } else {
                        if !op.cancel_requested {
                            op.cancel_requested = true;
                            op.cancel_requested_at = Some(Instant::now());
                            op.cancel_reason = Some(request.reason.clone());
                        }
                        CancellationOutcome::Pending
                    };
                    let evidence = if outcome == CancellationOutcome::Cancelled {
                        op.cancellation_evidence.clone().unwrap_or_default()
                    } else {
                        CancellationEvidence::default()
                    };
                    let duration_ms = op.cancellation_duration_ms.or_else(|| {
                        op.cancel_requested_at
                            .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX))
                    });
                    (outcome, evidence, duration_ms)
                }
            }
        };

        let duration_ms = cancellation_duration_ms
            .unwrap_or_else(|| u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX));
        let partial_result = if request.return_partial {
            evidence.partial_result
        } else {
            None
        };
        let checkpoint = if matches!(request.cleanup, CleanupBehavior::Checkpoint) {
            evidence.checkpoint
        } else {
            None
        };

        let audit_event = CancellationAuditEvent {
            timestamp: now,
            operation_id: request.operation_id.clone(),
            reason: request.reason.clone(),
            outcome,
            duration_ms,
            had_partial_result: partial_result.is_some(),
            had_checkpoint: checkpoint.is_some(),
            forced: false,
        };
        self.audit_log.lock().expect("audit lock").push(audit_event);

        Ok(CancellationResponse {
            operation_id: request.operation_id.clone(),
            outcome,
            partial_result,
            checkpoint,
            cleanup_result: evidence.cleanup_result,
            duration_ms,
        })
    }

    /// Sweep for operations whose cancellation deadline expired without
    /// completion (`flywheel_connectors-861lx`).
    ///
    /// At most one live attempt is returned for each operation. Retaining any
    /// clone of its expiration suppresses duplicate dispatch; losing all clones
    /// without acknowledgement makes a supported runtime eligible on the next
    /// sweep. Explicit rearming invalidates that attempt before retrying. The
    /// original cancellation instant and operator deadline never reset.
    ///
    /// Unsupported targets are reported once, not retried in a busy loop.
    /// Completed, acknowledged, and bookkeeping-only registrations never expire.
    /// Neither losing an attempt nor acknowledging its result releases the
    /// operation ID or any Strict-idempotency intent. Physical termination must
    /// still be observed by the caller before it records a forced cancellation.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn reap_expired(&self, now: Instant) -> Vec<ExpiredCancellation> {
        // Sweep orphaned waiter completions even without an explicit /cancel.
        // Settled queued work must not acquire a forced-child-exit audit merely
        // because its cancellation deadline also elapsed before this sweep.
        self.complete_settled_registrations();
        let mut ops = self.operations.lock().expect("operations lock");
        let mut expired = Vec::new();
        for (operation_id, op) in &mut ops.entries {
            if !op.cancel_requested
                || op.completed
                || op.forced_cancel_recorded
                || op.returned_normally
            {
                continue;
            }
            let Some(requested_at) = op.cancel_requested_at else {
                continue;
            };
            let Some(scope) = op.scope.as_ref() else {
                continue;
            };
            if op.forced_cancel_sent
                && (scope.terminator.is_none() || op.force_attempt.strong_count() != 0)
            {
                continue;
            }
            let deadline = scope.effective_deadline();
            if now.saturating_duration_since(requested_at) >= deadline {
                let attempt = Arc::new(());
                op.force_attempt = Arc::downgrade(&attempt);
                op.forced_cancel_sent = true;
                expired.push(ExpiredCancellation {
                    operation_id: operation_id.clone(),
                    connector_id: scope.connector_id.clone(),
                    deadline,
                    terminator: scope.terminator.clone(),
                    registration: Arc::clone(&op.registration),
                    attempt,
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
    /// invoke path calls [`Self::complete`]. Repeated acknowledgement is inert.
    /// Production reapers must use [`Self::record_forced_expiration`] to fence
    /// both reused operation IDs and successive attempts.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn record_forced_cancellation(&self, operation_id: &str, now: DateTime<Utc>) {
        self.record_forced_matching(operation_id, None, now);
    }

    /// Record a forced cancellation only for the current registration AND
    /// termination attempt. Returns false for stale or duplicate results.
    /// A valid result may arrive after the original waiter completed, provided
    /// its operation ID has not been reused in the meantime.
    ///
    /// # Panics
    ///
    /// Panics if an internal mutex is poisoned.
    #[must_use]
    pub fn record_forced_expiration(
        &self,
        expired: &ExpiredCancellation,
        now: DateTime<Utc>,
    ) -> bool {
        self.record_forced_matching(&expired.operation_id, Some(expired), now)
    }

    fn record_forced_matching(
        &self,
        operation_id: &str,
        expiration: Option<&ExpiredCancellation>,
        now: DateTime<Utc>,
    ) -> bool {
        let (reason, duration_ms) = {
            let mut ops = self.operations.lock().expect("operations lock");
            let Some(op) = ops.entries.get_mut(operation_id) else {
                return false;
            };
            if op.forced_cancel_recorded
                || op.returned_normally
                || expiration.is_some_and(|expired| !op.owns_expiration(expired))
            {
                return false;
            }
            op.forced_cancel_sent = true;
            op.forced_cancel_recorded = true;
            let duration_ms = op
                .cancel_requested_at
                .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX))
                .unwrap_or_default();
            let result = (
                op.cancel_reason
                    .clone()
                    .unwrap_or(CancelReason::UserRequested),
                duration_ms,
            );
            ops.prune_completed();
            result
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
        true
    }

    /// Re-arm a failed force-terminate so the next reaper sweep retries
    /// it (`flywheel_connectors-861lx`). Completed operations and acknowledged
    /// termination results are never re-armed. Production reapers must use
    /// [`Self::rearm_expiration`] to avoid rearming a newer attempt.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn rearm_force_terminate(&self, operation_id: &str) {
        self.rearm_matching(operation_id, None);
    }

    /// Retry only the current attempt for the registration whose termination
    /// failed. Late failures cannot displace a newer in-flight attempt.
    ///
    /// # Panics
    ///
    /// Panics if the operations mutex is poisoned.
    pub fn rearm_expiration(&self, expired: &ExpiredCancellation) {
        self.rearm_matching(&expired.operation_id, Some(expired));
    }

    fn rearm_matching(&self, operation_id: &str, expiration: Option<&ExpiredCancellation>) {
        let mut ops = self.operations.lock().expect("operations lock");
        if let Some(op) = ops.entries.get_mut(operation_id) {
            if expiration.is_some_and(|expired| !op.owns_expiration(expired)) {
                return;
            }
            if !op.completed && !op.forced_cancel_recorded {
                op.forced_cancel_sent = false;
                // Invalidate even before the next sweep publishes a new attempt.
                op.force_attempt = Weak::new();
            }
        }
    }

    /// Remove a completed or cancelled operation from tracking.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn remove(&self, operation_id: &str) {
        let removed = {
            let mut ops = self.operations.lock().expect("operations lock");
            let removed = ops.entries.remove(operation_id);
            ops.completed
                .retain(|registration| registration.operation_id != operation_id);
            ops.prune_completed();
            removed
        };
        disarm_scope(removed.and_then(|operation| operation.scope));
    }

    /// Number of currently tracked operations.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.operations
            .lock()
            .expect("operations lock")
            .entries
            .len()
    }

    /// Get at most 1,024 retained in-memory audit events, newest first.
    ///
    /// This is a recent-history view, not a complete durable audit trail.
    /// See [`Self::discarded_audit_event_count`] for prior history loss.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn audit_events(&self) -> Vec<CancellationAuditEvent> {
        self.audit_log
            .lock()
            .expect("audit lock")
            .events
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    /// Number of in-memory audit events discarded over this controller's life.
    ///
    /// Includes capacity eviction and explicit clears, saturates at `u64::MAX`,
    /// and never resets when history is cleared. This count and [`Self::audit_events`]
    /// are separate observations when cancellation is concurrent.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn discarded_audit_event_count(&self) -> u64 {
        self.audit_log.lock().expect("audit lock").discarded
    }

    /// Clear retained audit events without resetting the discarded-event count.
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

    fn retain_completed_history(
        controller: &CancellationController,
        operation_id: &str,
    ) -> CancellationRegistration {
        let registration = controller
            .track_operation(
                operation_id,
                Some("history-owner"),
                CancellationScope::new("history", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
        controller.complete_registration(&registration);
        registration
    }

    #[test]
    fn completed_history_is_bounded_and_duplicate_completion_does_not_age_it() {
        let controller = CancellationController::new();
        for index in 0..MAX_COMPLETED_OPERATION_HISTORY * 3 {
            let registration = retain_completed_history(&controller, &format!("done-{index}"));
            controller.complete_registration(&registration);
            assert!(controller.tracked_count() <= MAX_COMPLETED_OPERATION_HISTORY);
        }
        assert_eq!(controller.tracked_count(), MAX_COMPLETED_OPERATION_HISTORY);
        assert_eq!(
            controller.operations.lock().unwrap().completed.len(),
            MAX_COMPLETED_OPERATION_HISTORY,
        );
        assert!(matches!(
            controller.cancel(
                &cancel_request("done-0", CancelReason::UserRequested),
                Some("history-owner"),
                fixed_now(),
            ),
            Err(HostError::ConnectorNotFound(_)),
        ));
        let newest = format!("done-{}", MAX_COMPLETED_OPERATION_HISTORY * 3 - 1);
        assert_eq!(
            controller
                .cancel(
                    &cancel_request(&newest, CancelReason::UserRequested),
                    Some("history-owner"),
                    fixed_now(),
                )
                .unwrap()
                .outcome,
            CancellationOutcome::TooLate,
        );
    }

    #[test]
    fn repeated_id_reuse_and_removal_do_not_accumulate_completion_queue_entries() {
        let controller = CancellationController::new();
        for index in 0..MAX_COMPLETED_OPERATION_HISTORY * 2 {
            let registration = retain_completed_history(&controller, "same-id");
            controller.complete_registration(&registration);
            controller.complete("same-id");
            let tracker = controller.operations.lock().unwrap();
            assert_eq!(tracker.entries.len(), 1);
            assert_eq!(tracker.completed.len(), 1);
            drop(tracker);
            if index % 2 == 0 {
                controller.remove("same-id");
                let tracker = controller.operations.lock().unwrap();
                assert!(tracker.entries.is_empty());
                assert!(tracker.completed.is_empty());
            }
        }
    }

    #[test]
    fn history_pressure_preserves_live_and_unsettled_runtime_ownership() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let controller = CancellationController::new();
        let active = controller
            .track_operation(
                "live",
                Some("live-owner"),
                CancellationScope::new("live", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&finished);
        let settling = controller
            .track_operation(
                "settling",
                Some("settling-owner"),
                CancellationScope::new("native", ConnectorArchetype::RequestResponse)
                    .with_terminator(CancellationTerminator::new(
                        || panic!("retention must not terminate a live runtime"),
                        move || observed.load(Ordering::SeqCst),
                    )),
            )
            .unwrap();
        controller.complete_registration_when_settled(&settling);
        for index in 0..MAX_COMPLETED_OPERATION_HISTORY * 2 {
            retain_completed_history(&controller, &format!("history-{index}"));
        }
        assert_eq!(
            controller.tracked_count(),
            MAX_COMPLETED_OPERATION_HISTORY + 2
        );
        for operation_id in ["live", "settling"] {
            assert!(
                controller
                    .track_operation(
                        operation_id,
                        Some("replacement"),
                        CancellationScope::new("other", ConnectorArchetype::RequestResponse),
                    )
                    .is_err()
            );
        }
        assert!(controller.reap_expired(Instant::now()).is_empty());
        {
            let tracker = controller.operations.lock().unwrap();
            assert!(!tracker.entries["live"].completed);
            assert!(!tracker.entries["settling"].completed);
            assert!(tracker.entries["settling"].completion_pending);
            assert!(tracker.entries["settling"].scope.is_some());
        }
        finished.store(true, Ordering::SeqCst);
        assert!(controller.reap_expired(Instant::now()).is_empty());
        assert_eq!(
            controller.tracked_count(),
            MAX_COMPLETED_OPERATION_HISTORY + 1
        );
        controller.complete_registration(&active);
        assert_eq!(controller.tracked_count(), MAX_COMPLETED_OPERATION_HISTORY);
        assert!(controller.audit_events().is_empty());
    }

    #[test]
    fn eviction_and_id_reuse_preserve_registration_owner_and_relay_fences() {
        let controller = CancellationController::new();
        let old_binding = RelayCancellationBinding {
            origin_node: "entry".to_owned(),
            origin_attempt_id: 7,
        };
        let scope_for = |relay: RelayCancellationBinding| {
            let mut scope = CancellationScope::new("native", ConnectorArchetype::RequestResponse);
            scope.relay = Some(relay);
            scope
        };
        let old = controller
            .track_operation(
                "reused-history",
                Some("old-owner"),
                scope_for(old_binding.clone()),
            )
            .unwrap();
        controller.complete_registration(&old);
        for index in 0..MAX_COMPLETED_OPERATION_HISTORY {
            retain_completed_history(&controller, &format!("replacement-history-{index}"));
        }
        assert!(
            !controller
                .operations
                .lock()
                .unwrap()
                .entries
                .contains_key("reused-history")
        );
        let new_binding = RelayCancellationBinding {
            origin_attempt_id: 8,
            ..old_binding.clone()
        };
        let replacement = controller
            .track_operation(
                "reused-history",
                Some("new-owner"),
                scope_for(new_binding.clone()),
            )
            .unwrap();
        controller.complete_registration(&old);
        controller.complete_registration_when_settled(&old);
        let request = cancel_request("reused-history", CancelReason::UserRequested);
        for (owner, binding) in [("old-owner", &old_binding), ("new-owner", &old_binding)] {
            assert!(matches!(
                controller.cancel_relay(&request, owner, binding, fixed_now()),
                Err(HostError::PreflightFailed(_)),
            ));
        }
        assert!(!controller.is_cancel_requested("reused-history"));
        assert_eq!(
            controller
                .cancel_relay(&request, "new-owner", &new_binding, fixed_now())
                .unwrap()
                .outcome,
            CancellationOutcome::Pending,
        );
        assert_eq!(controller.audit_events().len(), 1);
        controller.complete_registration(&replacement);
    }

    #[test]
    fn owned_force_result_survives_completion_history_pressure() {
        let controller = CancellationController::new();
        let registration = cancellable_attempt(&controller, "pinned-result");
        let expired = controller
            .reap_expired(Instant::now() + Duration::from_secs(1))
            .pop()
            .unwrap();
        controller.complete_registration(&registration);
        for index in 0..MAX_COMPLETED_OPERATION_HISTORY * 2 {
            retain_completed_history(&controller, &format!("pinned-history-{index}"));
        }
        assert!(controller.record_forced_expiration(&expired, fixed_now()));
        assert_eq!(
            controller
                .audit_events()
                .iter()
                .filter(|event| event.forced)
                .count(),
            1,
        );
        for index in 0..MAX_COMPLETED_OPERATION_HISTORY {
            retain_completed_history(&controller, &format!("released-history-{index}"));
        }
        let replacement = controller
            .track_operation(
                "pinned-result",
                Some("replacement-owner"),
                CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
        assert!(!controller.record_forced_expiration(&expired, fixed_now()));
        controller.rearm_expiration(&expired);
        controller.complete_registration(&registration);
        assert!(!controller.is_cancel_requested("pinned-result"));
        assert!(!controller.operations.lock().unwrap().entries["pinned-result"].completed);
        controller.complete_registration(&replacement);
    }

    #[test]
    fn reaper_reclaims_history_after_outstanding_force_result_handles_disappear() {
        let controller = CancellationController::new();
        let registrations: Vec<_> = (0..=MAX_COMPLETED_OPERATION_HISTORY)
            .map(|index| cancellable_attempt(&controller, &format!("pending-result-{index}")))
            .collect();
        let expired = controller.reap_expired(Instant::now() + Duration::from_secs(1));
        assert_eq!(expired.len(), MAX_COMPLETED_OPERATION_HISTORY + 1);
        for registration in &registrations {
            controller.complete_registration(registration);
        }
        // Every extra entry is pinned by real outstanding attempt ownership.
        assert_eq!(
            controller.tracked_count(),
            MAX_COMPLETED_OPERATION_HISTORY + 1
        );
        drop(expired);
        assert!(controller.reap_expired(Instant::now()).is_empty());
        assert_eq!(controller.tracked_count(), MAX_COMPLETED_OPERATION_HISTORY);
        assert!(controller.audit_events().iter().all(|event| !event.forced));
    }

    #[test]
    fn concurrent_completion_keeps_history_bounded_without_evicting_active_work() {
        let controller = CancellationController::new();
        controller
            .track_operation(
                "still-live",
                Some("owner"),
                CancellationScope::new("live", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let controller = &controller;
                scope.spawn(move || {
                    for index in 0..MAX_COMPLETED_OPERATION_HISTORY / 4 {
                        retain_completed_history(controller, &format!("worker-{worker}-{index}"));
                    }
                });
            }
        });
        assert_eq!(
            controller.tracked_count(),
            MAX_COMPLETED_OPERATION_HISTORY + 1
        );
        let tracker = controller.operations.lock().unwrap();
        assert_eq!(tracker.completed.len(), MAX_COMPLETED_OPERATION_HISTORY);
        assert!(!tracker.entries["still-live"].completed);
    }

    #[test]
    fn audit_history_retains_newest_events_and_reports_eviction_and_clear_loss() {
        let controller = CancellationController::new();
        controller.track_with_owner("audit-retention", None);
        let request = cancel_request("audit-retention", CancelReason::UserRequested);
        let total = MAX_CANCELLATION_AUDIT_HISTORY + 7;
        for index in 0..total {
            controller
                .cancel(
                    &request,
                    None,
                    fixed_now() + chrono::Duration::milliseconds(i64::try_from(index).unwrap()),
                )
                .unwrap();
        }
        let events = controller.audit_events();
        assert_eq!(events.len(), MAX_CANCELLATION_AUDIT_HISTORY);
        assert_eq!(controller.discarded_audit_event_count(), 7);
        assert_eq!(
            events[0].timestamp,
            fixed_now() + chrono::Duration::milliseconds(i64::try_from(total - 1).unwrap()),
        );
        assert_eq!(
            events.last().unwrap().timestamp,
            fixed_now() + chrono::Duration::milliseconds(7),
        );
        controller.record_forced_cancellation("audit-retention", fixed_now());
        assert!(controller.audit_events()[0].forced);
        assert_eq!(
            controller.audit_events().len(),
            MAX_CANCELLATION_AUDIT_HISTORY
        );
        assert_eq!(controller.discarded_audit_event_count(), 8);
        // Repeated acknowledgement must not consume history capacity again.
        controller.record_forced_cancellation("audit-retention", fixed_now());
        assert_eq!(controller.discarded_audit_event_count(), 8);

        controller.clear_audit_log();
        assert!(controller.audit_events().is_empty());
        assert_eq!(
            controller.discarded_audit_event_count(),
            u64::try_from(total + 1).unwrap(),
        );
        controller.clear_audit_log();
        controller.cancel(&request, None, fixed_now()).unwrap();
        assert_eq!(controller.audit_events().len(), 1);
        assert_eq!(
            controller.discarded_audit_event_count(),
            u64::try_from(total + 1).unwrap(),
        );
    }

    #[test]
    fn abandoned_waiter_keeps_registration_until_runtime_settles_without_cancel() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let controller = Arc::new(CancellationController::new());
        let finished = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&finished);
        let probe_controller = Arc::downgrade(&controller);
        let registration = controller
            .track_operation(
                "abandoned",
                Some("owner"),
                CancellationScope::new("native", ConnectorArchetype::RequestResponse)
                    .with_terminator(CancellationTerminator::new(
                        || {},
                        move || {
                            // A completion probe may re-enter controller reads.
                            // Calling it under the operations lock would deadlock.
                            let controller = probe_controller.upgrade().unwrap();
                            assert!(!controller.is_cancel_requested("abandoned"));
                            observed.load(Ordering::SeqCst)
                        },
                    )),
            )
            .unwrap();

        controller.complete_registration_when_settled(&registration);
        assert!(
            controller
                .track_operation(
                    "abandoned",
                    Some("other"),
                    CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
                )
                .is_err()
        );
        assert!(controller.reap_expired(Instant::now()).is_empty());
        finished.store(true, Ordering::SeqCst);
        assert!(controller.reap_expired(Instant::now()).is_empty());
        controller
            .track_operation(
                "abandoned",
                Some("other"),
                CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
    }

    #[test]
    fn settled_pending_completion_precedes_forced_expiration_sweep() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let controller = CancellationController::new();
        let finished = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&finished);
        let registration = controller
            .track_operation(
                "queued-only",
                None,
                CancellationScope::new("native", ConnectorArchetype::RequestResponse)
                    .with_deadline_override_ms(Some(1))
                    .with_terminator(CancellationTerminator::new(
                        || panic!("settled queued work must not be force-terminated"),
                        move || observed.load(Ordering::SeqCst),
                    )),
            )
            .unwrap();
        controller
            .cancel(
                &CancellationRequest {
                    operation_id: "queued-only".into(),
                    reason: CancelReason::UserRequested,
                    cleanup: CleanupBehavior::default(),
                    return_partial: false,
                    capability_token: None,
                },
                None,
                chrono::Utc::now(),
            )
            .unwrap();
        controller.complete_registration_when_settled(&registration);
        finished.store(true, Ordering::SeqCst);

        assert!(
            controller
                .reap_expired(Instant::now() + Duration::from_secs(1))
                .is_empty()
        );
        assert!(controller.audit_events().iter().all(|event| !event.forced));
        controller
            .track_operation(
                "queued-only",
                None,
                CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
    }

    #[test]
    fn stale_deferred_completion_cannot_release_a_reused_operation_id() {
        let controller = CancellationController::new();
        let old = controller
            .track_operation(
                "reused-pending",
                Some("old-owner"),
                CancellationScope::new("old", ConnectorArchetype::RequestResponse)
                    .with_terminator(CancellationTerminator::new(|| {}, || false)),
            )
            .unwrap();
        controller.complete_registration_when_settled(&old);
        controller.complete_registration(&old);
        let replacement = controller
            .track_operation(
                "reused-pending",
                Some("new-owner"),
                CancellationScope::new("new", ConnectorArchetype::RequestResponse)
                    .with_terminator(CancellationTerminator::new(|| {}, || false)),
            )
            .unwrap();

        controller.complete_registration_when_settled(&old);
        assert!(controller.reap_expired(Instant::now()).is_empty());
        assert!(
            controller
                .track_operation(
                    "reused-pending",
                    None,
                    CancellationScope::new("third", ConnectorArchetype::RequestResponse),
                )
                .is_err()
        );
        controller.complete_registration(&replacement);
    }

    #[test]
    fn expired_cancel_retains_the_original_runtime_not_its_replacement() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let old_exited = Arc::new(AtomicBool::new(false));
        let new_exited = Arc::new(AtomicBool::new(false));
        let old_abort = Arc::clone(&old_exited);
        let old_finished = Arc::clone(&old_exited);
        let scope = CancellationScope::new("same-id", ConnectorArchetype::RequestResponse)
            .with_deadline_override_ms(Some(1))
            .with_terminator(CancellationTerminator::new(
                move || old_abort.store(true, Ordering::SeqCst),
                move || old_finished.load(Ordering::SeqCst),
            ));
        let controller = CancellationController::new();
        controller
            .track_operation("old-operation", None, scope)
            .unwrap();
        controller
            .cancel(
                &CancellationRequest {
                    operation_id: "old-operation".into(),
                    reason: CancelReason::UserRequested,
                    cleanup: CleanupBehavior::default(),
                    return_partial: false,
                    capability_token: None,
                },
                None,
                chrono::Utc::now(),
            )
            .unwrap();
        // Simulates replacing the registry entry with another incarnation
        // carrying the SAME connector ID. The captured hook must stay old.
        let replacement = Arc::clone(&new_exited);
        let _new_terminator = CancellationTerminator::new(
            move || replacement.store(true, Ordering::SeqCst),
            || false,
        );
        let expired = controller.reap_expired(Instant::now() + Duration::from_secs(1));
        assert_eq!(expired.len(), 1);
        let target = expired[0].terminator.as_ref().unwrap();
        assert!(target.abort());
        assert!(target.is_finished());
        assert!(old_exited.load(Ordering::SeqCst));
        assert!(!new_exited.load(Ordering::SeqCst));
    }

    #[test]
    fn completion_releases_runtime_and_revokes_an_extracted_expiration() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let runtime = Arc::new(AtomicBool::new(false));
        let weak_runtime = Arc::downgrade(&runtime);
        let finished = Arc::clone(&runtime);
        let controller = CancellationController::new();
        let registration = controller
            .track_operation(
                "completed",
                Some("owner"),
                CancellationScope::new("connector", ConnectorArchetype::RequestResponse)
                    .with_deadline_override_ms(Some(1))
                    .with_terminator(CancellationTerminator::new(
                        move || runtime.store(true, Ordering::SeqCst),
                        move || finished.load(Ordering::SeqCst),
                    )),
            )
            .unwrap();
        controller
            .cancel(
                &cancel_request("completed", CancelReason::UserRequested),
                Some("owner"),
                fixed_now(),
            )
            .unwrap();
        let expired = controller.reap_expired(Instant::now() + Duration::from_secs(1));
        assert_eq!(expired.len(), 1);
        controller.complete_registration(&registration);
        assert!(weak_runtime.upgrade().is_none());
        assert!(!expired[0].terminator.as_ref().unwrap().abort());
        assert_eq!(
            controller
                .cancel(
                    &cancel_request("completed", CancelReason::UserRequested),
                    Some("owner"),
                    fixed_now(),
                )
                .unwrap()
                .outcome,
            CancellationOutcome::TooLate,
        );
    }

    #[test]
    fn reused_operation_id_rejects_old_completion_audit_and_rearm() {
        let controller = CancellationController::new();
        let scope = || {
            CancellationScope::new("connector", ConnectorArchetype::RequestResponse)
                .with_deadline_override_ms(Some(1))
                .with_terminator(CancellationTerminator::new(|| {}, || true))
        };
        let old_registration = controller.track_operation("reused", None, scope()).unwrap();
        controller
            .cancel(
                &cancel_request("reused", CancelReason::UserRequested),
                None,
                fixed_now(),
            )
            .unwrap();
        let old_expired = controller.reap_expired(Instant::now() + Duration::from_secs(1));
        assert_eq!(old_expired.len(), 1);

        controller.complete_registration(&old_registration);
        let replacement = controller.track_operation("reused", None, scope()).unwrap();
        assert!(!old_expired[0].terminator.as_ref().unwrap().abort());
        controller.complete_registration(&old_registration);
        assert_eq!(
            controller
                .cancel(
                    &cancel_request("reused", CancelReason::UserRequested),
                    None,
                    fixed_now()
                )
                .unwrap()
                .outcome,
            CancellationOutcome::Pending,
        );
        let new_expired = controller.reap_expired(Instant::now() + Duration::from_secs(1));
        assert_eq!(new_expired.len(), 1);
        controller.clear_audit_log();
        assert!(!controller.record_forced_expiration(&old_expired[0], fixed_now()));
        assert!(controller.audit_events().is_empty());
        controller.rearm_expiration(&old_expired[0]);
        assert!(
            controller
                .reap_expired(Instant::now() + Duration::from_secs(2))
                .is_empty()
        );
        assert!(new_expired[0].terminator.as_ref().unwrap().abort());
        controller.complete_registration(&replacement);
        assert!(controller.record_forced_expiration(&new_expired[0], fixed_now()));
        assert!(controller.audit_events()[0].forced);
    }

    #[test]
    fn active_operation_id_cannot_replace_its_owner_or_termination_target() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let controller = CancellationController::new();
        let original_aborted = Arc::new(AtomicBool::new(false));
        let abort = Arc::clone(&original_aborted);
        let original = controller
            .track_operation(
                "shared-id",
                Some("original-owner"),
                CancellationScope::new("original", ConnectorArchetype::RequestResponse)
                    .with_deadline_override_ms(Some(1))
                    .with_terminator(CancellationTerminator::new(
                        move || abort.store(true, Ordering::SeqCst),
                        || true,
                    )),
            )
            .unwrap();
        let replacement_runtime = Arc::new(());
        let replacement_weak = Arc::downgrade(&replacement_runtime);
        let error = controller
            .track_operation(
                "shared-id",
                Some("replacement-owner"),
                CancellationScope::new("replacement", ConnectorArchetype::RequestResponse)
                    .with_terminator(CancellationTerminator::new(
                        move || {
                            let _ = &replacement_runtime;
                        },
                        || false,
                    )),
            )
            .unwrap_err();
        assert!(matches!(error, HostError::PreflightFailed(_)));
        assert!(replacement_weak.upgrade().is_none());
        assert_eq!(controller.tracked_count(), 1);
        assert!(
            controller
                .cancel(
                    &cancel_request("shared-id", CancelReason::UserRequested),
                    Some("replacement-owner"),
                    fixed_now(),
                )
                .is_err()
        );
        controller
            .cancel(
                &cancel_request("shared-id", CancelReason::UserRequested),
                Some("original-owner"),
                fixed_now(),
            )
            .unwrap();
        let expired = controller.reap_expired(Instant::now() + Duration::from_secs(1));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].connector_id, "original");
        assert!(expired[0].terminator.as_ref().unwrap().abort());
        assert!(original_aborted.load(Ordering::SeqCst));

        controller.complete_registration(&original);
        let replacement = controller
            .track_operation(
                "shared-id",
                Some("replacement-owner"),
                CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
            )
            .expect("completed IDs remain reusable");
        controller.complete_registration(&original);
        assert_eq!(
            controller
                .cancel(
                    &cancel_request("shared-id", CancelReason::UserRequested),
                    Some("replacement-owner"),
                    fixed_now(),
                )
                .unwrap()
                .outcome,
            CancellationOutcome::Pending,
        );
        controller.complete_registration(&replacement);
    }

    #[test]
    fn concurrent_registration_admits_exactly_one_active_owner() {
        let controller = Arc::new(CancellationController::new());
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let contenders = ["owner-a", "owner-b"].map(|owner| {
            let controller = Arc::clone(&controller);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                controller.track_operation(
                    "contended-id",
                    Some(owner),
                    CancellationScope::new(owner, ConnectorArchetype::RequestResponse),
                )
            })
        });
        barrier.wait();
        let results = contenders.map(|contender| contender.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert_eq!(controller.tracked_count(), 1);
    }

    #[test]
    fn removing_tracking_revokes_already_extracted_termination_handles() {
        let controller = CancellationController::new();
        controller
            .track_operation(
                "removed",
                None,
                CancellationScope::new("connector", ConnectorArchetype::RequestResponse)
                    .with_deadline_override_ms(Some(1))
                    .with_terminator(CancellationTerminator::new(
                        || panic!("removed operation must not abort a runtime"),
                        || false,
                    )),
            )
            .unwrap();
        controller
            .cancel(
                &cancel_request("removed", CancelReason::UserRequested),
                None,
                fixed_now(),
            )
            .unwrap();
        let expired = controller.reap_expired(Instant::now() + Duration::from_secs(1));
        assert_eq!(expired.len(), 1);
        controller.remove("removed");
        assert!(!expired[0].terminator.as_ref().unwrap().abort());
    }

    #[test]
    fn relay_cancellation_fences_owner_origin_and_reused_operation_ids() {
        let controller = CancellationController::new();
        let binding = RelayCancellationBinding {
            origin_node: "entry-a".to_owned(),
            origin_attempt_id: 41,
        };
        let scope_for = |relay: RelayCancellationBinding| {
            let mut scope =
                CancellationScope::new("connector", ConnectorArchetype::RequestResponse);
            scope.relay = Some(relay);
            scope
        };
        let registration = controller
            .track_operation("relayed", Some("owner"), scope_for(binding.clone()))
            .unwrap();
        let request = cancel_request("relayed", CancelReason::UserRequested);
        let other_origin = RelayCancellationBinding {
            origin_node: "entry-b".to_owned(),
            ..binding.clone()
        };
        let next = RelayCancellationBinding {
            origin_attempt_id: 42,
            ..binding.clone()
        };

        for (principal, relay) in [
            ("other", &binding),
            ("owner", &other_origin),
            ("owner", &next),
        ] {
            assert!(matches!(
                controller.cancel_relay(&request, principal, relay, fixed_now()),
                Err(HostError::PreflightFailed(_))
            ));
            assert!(!controller.is_cancel_requested("relayed"));
            assert!(controller.audit_events().is_empty());
        }
        assert_eq!(
            controller
                .cancel_relay(&request, "owner", &binding, fixed_now())
                .unwrap()
                .outcome,
            CancellationOutcome::Pending
        );
        assert_eq!(
            controller
                .cancel_relay(&request, "owner", &binding, fixed_now())
                .unwrap()
                .outcome,
            CancellationOutcome::Pending
        );
        controller.complete_registration(&registration);
        assert_eq!(
            controller
                .cancel_relay(&request, "owner", &binding, fixed_now())
                .unwrap()
                .outcome,
            CancellationOutcome::TooLate
        );
        assert!(matches!(
            controller.cancel_relay(&request, "owner", &other_origin, fixed_now()),
            Err(HostError::PreflightFailed(_))
        ));

        controller
            .track_operation("relayed", Some("owner"), scope_for(next.clone()))
            .unwrap();
        assert!(matches!(
            controller.cancel_relay(&request, "owner", &binding, fixed_now()),
            Err(HostError::PreflightFailed(_))
        ));
        assert!(!controller.is_cancel_requested("relayed"));
        assert_eq!(
            controller
                .cancel_relay(&request, "owner", &next, fixed_now())
                .unwrap()
                .outcome,
            CancellationOutcome::Pending
        );
    }

    #[test]
    fn relay_cancellation_rejects_missing_authority_without_changing_local_cancel() {
        let controller = CancellationController::new();
        for (origin, attempt) in [("", 1), ("   ", 1), ("entry", 0)] {
            let mut scope =
                CancellationScope::new("connector", ConnectorArchetype::RequestResponse);
            scope.relay = Some(RelayCancellationBinding {
                origin_node: origin.to_owned(),
                origin_attempt_id: attempt,
            });
            assert!(matches!(
                controller.track_operation("invalid", Some("owner"), scope),
                Err(HostError::PreflightFailed(_))
            ));
        }
        assert_eq!(controller.tracked_count(), 0);

        let binding = RelayCancellationBinding {
            origin_node: "entry".to_owned(),
            origin_attempt_id: 1,
        };
        let mut scope = CancellationScope::new("connector", ConnectorArchetype::RequestResponse);
        scope.relay = Some(binding.clone());
        controller.track_operation("unowned", None, scope).unwrap();
        controller.track_with_owner("local", Some("owner"));

        for operation_id in ["unowned", "local"] {
            let request = cancel_request(operation_id, CancelReason::UserRequested);
            assert!(matches!(
                controller.cancel_relay(&request, "owner", &binding, fixed_now()),
                Err(HostError::PreflightFailed(_))
            ));
            assert!(!controller.is_cancel_requested(operation_id));
        }
        assert!(controller.audit_events().is_empty());
        for (operation_id, principal) in [("unowned", None), ("local", Some("owner"))] {
            assert_eq!(
                controller
                    .cancel(
                        &cancel_request(operation_id, CancelReason::UserRequested),
                        principal,
                        fixed_now(),
                    )
                    .unwrap()
                    .outcome,
                CancellationOutcome::Pending
            );
        }
    }

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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
    }

    #[test]
    fn cancel_active_operation_is_pending_until_runtime_completion() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
    fn repeated_cancel_request_remains_pending_without_runtime_completion() {
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

    fn cancellation_evidence_fixture() -> CancellationEvidence {
        CancellationEvidence {
            partial_result: Some(PartialResult {
                completed_items: 3,
                total_items: Some(9),
                data: Some(serde_json::json!({"rows": [1, 2, 3]})),
            }),
            checkpoint: Some(CheckpointInfo {
                id: "persisted-object-d14c".into(),
                resumable: true,
                expires_at: Some(fixed_now() + chrono::Duration::minutes(17)),
                state: Some(serde_json::json!({"cursor": "after-three"})),
            }),
            cleanup_result: Some(CleanupResult {
                success: false,
                cleaned: vec!["temporary_file".into()],
                failed: vec!["provider_rollback".into()],
                duration_ms: 51,
            }),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn runtime_evidence_stays_hidden_until_settlement_and_replays_without_invention() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let ctrl = CancellationController::new();
        let finished = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&finished);
        let registration = ctrl
            .track_operation(
                "evidence",
                Some("owner"),
                CancellationScope::new("runtime", ConnectorArchetype::RequestResponse)
                    .with_terminator(CancellationTerminator::new(
                        || panic!("settlement must not force a cooperative runtime"),
                        move || observed.load(Ordering::SeqCst),
                    )),
            )
            .unwrap();
        let mut request = CancellationRequest {
            operation_id: "evidence".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: true,
            capability_token: None,
        };
        let accepted = ctrl.cancel(&request, Some("owner"), fixed_now()).unwrap();
        assert_eq!(accepted.outcome, CancellationOutcome::Pending);
        assert!(accepted.partial_result.is_none());
        assert!(accepted.checkpoint.is_none());
        assert!(accepted.cleanup_result.is_none());
        let anchor = Instant::now() - Duration::from_secs(2);
        ctrl.operations
            .lock()
            .unwrap()
            .entries
            .get_mut("evidence")
            .unwrap()
            .cancel_requested_at = Some(anchor);

        let expected = cancellation_evidence_fixture();
        assert!(
            ctrl.complete_cancelled_registration_when_settled(&registration, expected.clone(),)
        );
        // A duplicate callback cannot erase the first report or free live work.
        assert!(!ctrl.complete_cancelled_registration_when_settled(
            &registration,
            CancellationEvidence::default(),
        ));
        assert!(!ctrl.record_returned_registration(&registration));
        let pending = ctrl.cancel(&request, Some("owner"), fixed_now()).unwrap();
        assert_eq!(pending.outcome, CancellationOutcome::Pending);
        assert!(pending.partial_result.is_none());
        assert!(pending.checkpoint.is_none());
        assert!(pending.cleanup_result.is_none());
        assert!(pending.duration_ms >= 2_000);
        assert_eq!(
            ctrl.operations.lock().unwrap().entries["evidence"].cancel_requested_at,
            Some(anchor)
        );
        assert!(
            ctrl.track_operation(
                "evidence",
                Some("replacement"),
                CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
            )
            .is_err()
        );
        assert!(ctrl.audit_events().iter().all(|event| {
            event.outcome == CancellationOutcome::Pending
                && !event.had_partial_result
                && !event.had_checkpoint
        }));

        finished.store(true, Ordering::SeqCst);
        assert!(ctrl.reap_expired(Instant::now()).is_empty());
        let settled = ctrl.cancel(&request, Some("owner"), fixed_now()).unwrap();
        assert_eq!(settled.outcome, CancellationOutcome::Cancelled);
        assert_eq!(
            serde_json::to_value(&settled.partial_result).unwrap(),
            serde_json::to_value(&expected.partial_result).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&settled.checkpoint).unwrap(),
            serde_json::to_value(&expected.checkpoint).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&settled.cleanup_result).unwrap(),
            serde_json::to_value(&expected.cleanup_result).unwrap()
        );
        let repeated = ctrl.cancel(&request, Some("owner"), fixed_now()).unwrap();
        assert_eq!(
            serde_json::to_value(&settled).unwrap(),
            serde_json::to_value(&repeated).unwrap()
        );
        assert!(ctrl.audit_events()[0].had_partial_result);
        assert!(ctrl.audit_events()[0].had_checkpoint);

        request.return_partial = false;
        request.cleanup = CleanupBehavior::BestEffort;
        let limited = ctrl.cancel(&request, Some("owner"), fixed_now()).unwrap();
        assert_eq!(limited.outcome, CancellationOutcome::Cancelled);
        assert!(limited.partial_result.is_none());
        assert!(limited.checkpoint.is_none());
        assert!(limited.cleanup_result.is_some());
        assert!(!ctrl.audit_events()[0].had_partial_result);
        assert!(!ctrl.audit_events()[0].had_checkpoint);
    }

    #[test]
    fn cancellation_evidence_cannot_create_authority_or_relabel_completed_success() {
        let ctrl = CancellationController::new();
        let scope = || CancellationScope::new("runtime", ConnectorArchetype::RequestResponse);
        let old = ctrl
            .track_operation("reused-evidence", Some("old-owner"), scope())
            .unwrap();
        assert!(
            !ctrl.complete_cancelled_registration_when_settled(
                &old,
                CancellationEvidence::default(),
            )
        );
        assert!(!ctrl.is_cancel_requested("reused-evidence"));
        let request = cancel_request("reused-evidence", CancelReason::UserRequested);
        ctrl.cancel(&request, Some("old-owner"), fixed_now())
            .unwrap();
        ctrl.complete_registration(&old);
        assert!(
            !ctrl.complete_cancelled_registration_when_settled(
                &old,
                CancellationEvidence::default(),
            )
        );
        assert_eq!(
            ctrl.cancel(&request, Some("old-owner"), fixed_now())
                .unwrap()
                .outcome,
            CancellationOutcome::TooLate
        );

        let current = ctrl
            .track_operation("reused-evidence", Some("new-owner"), scope())
            .unwrap();
        ctrl.cancel(&request, Some("new-owner"), fixed_now())
            .unwrap();
        assert!(!ctrl.record_returned_registration(&old));
        assert!(
            !ctrl.complete_cancelled_registration_when_settled(
                &old,
                cancellation_evidence_fixture(),
            )
        );
        assert!(ctrl.complete_cancelled_registration_when_settled(
            &current,
            CancellationEvidence::default(),
        ));
        let response = ctrl
            .cancel(&request, Some("new-owner"), fixed_now())
            .unwrap();
        assert_eq!(response.outcome, CancellationOutcome::Cancelled);
        assert!(response.checkpoint.is_none());
        assert!(response.cleanup_result.is_none());
    }

    #[test]
    fn force_acknowledgement_requires_settlement_and_does_not_claim_cleanup() {
        let ctrl = CancellationController::new();
        let registration = ctrl
            .track_operation(
                "force-evidence",
                None,
                CancellationScope::new("runtime", ConnectorArchetype::RequestResponse)
                    .with_deadline_override_ms(Some(0))
                    .with_terminator(CancellationTerminator::new(|| {}, || true)),
            )
            .unwrap();
        let request = CancellationRequest {
            operation_id: "force-evidence".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: true,
            capability_token: None,
        };
        ctrl.cancel(&request, None, fixed_now()).unwrap();
        let expired = ctrl.reap_expired(Instant::now());
        assert_eq!(expired.len(), 1);
        let terminator = expired[0].terminator.as_ref().unwrap();
        assert!(terminator.abort());
        assert!(terminator.is_finished());
        assert!(ctrl.record_forced_expiration(&expired[0], fixed_now()));
        assert_eq!(
            ctrl.cancel(&request, None, fixed_now()).unwrap().outcome,
            CancellationOutcome::Pending
        );
        ctrl.complete_registration(&registration);
        for _ in 0..2 {
            let response = ctrl.cancel(&request, None, fixed_now()).unwrap();
            assert_eq!(response.outcome, CancellationOutcome::Cancelled);
            assert!(response.partial_result.is_none());
            assert!(response.checkpoint.is_none());
            assert!(response.cleanup_result.is_none());
        }
    }

    #[test]
    fn returned_result_fences_force_acknowledgement_before_and_after_completion() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let ctrl = CancellationController::new();
        let finished = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&finished);
        let registration = ctrl
            .track_operation(
                "returned",
                None,
                CancellationScope::new("runtime", ConnectorArchetype::RequestResponse)
                    .with_deadline_override_ms(Some(0))
                    .with_terminator(CancellationTerminator::new(
                        || {},
                        move || observed.load(Ordering::SeqCst),
                    )),
            )
            .unwrap();
        let request = cancel_request("returned", CancelReason::UserRequested);
        ctrl.cancel(&request, None, fixed_now()).unwrap();
        let expired = ctrl.reap_expired(Instant::now());
        let terminator = expired[0].terminator.as_ref().unwrap();
        // The result was already selected; abort wins before waiter teardown.
        assert!(terminator.abort());
        assert!(!terminator.is_finished());
        assert!(ctrl.record_returned_registration(&registration));
        assert!(!ctrl.complete_cancelled_registration_when_settled(
            &registration,
            cancellation_evidence_fixture(),
        ));
        finished.store(true, Ordering::SeqCst);
        assert!(terminator.is_finished());
        // Exercise the exact window before the controller is marked complete.
        assert!(!ctrl.record_forced_expiration(&expired[0], fixed_now()));
        ctrl.complete_registration_when_settled(&registration);
        assert!(!ctrl.record_forced_expiration(&expired[0], fixed_now()));
        assert_eq!(
            ctrl.cancel(&request, None, fixed_now()).unwrap().outcome,
            CancellationOutcome::TooLate
        );
        assert!(ctrl.audit_events().iter().all(|event| !event.forced));
        assert!(ctrl.reap_expired(Instant::now()).is_empty());
    }

    #[test]
    fn checkpoint_request_cannot_invent_resumable_state() {
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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
        assert!(resp.checkpoint.is_none());
        assert!(resp.cleanup_result.is_none());
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
    fn accepted_cancel_cannot_claim_cleanup_was_performed() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op1", None);
        let req = cancel_request("op1", CancelReason::UserRequested);
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert!(resp.cleanup_result.is_none());
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
        assert_eq!(events[0].outcome, CancellationOutcome::Pending);
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
    fn audit_does_not_claim_checkpoint_for_an_unfulfilled_request() {
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
        assert!(!events[0].had_checkpoint);
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
            assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
            assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
        // No checkpoint because cleanup is Full, not Checkpoint.
        assert!(resp.checkpoint.is_none());
        // Requesting full cleanup is not evidence that any cleanup happened.
        assert!(resp.cleanup_result.is_none());
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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
        // No checkpoint on Abandon.
        assert!(resp.checkpoint.is_none());
        assert!(resp.cleanup_result.is_none());
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

        // The fresh invocation accepts its own cancellation request.
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
        assert_eq!(resp.operation_id, long_id);
    }

    #[test]
    fn many_cancellations_of_same_op_after_retracks() {
        let ctrl = CancellationController::new();
        for _ in 0..50 {
            ctrl.track_with_owner("repeated", None);
            let req = cancel_request("repeated", CancelReason::UserRequested);
            let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
            assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
    fn repeated_pending_cancellation_has_no_cleanup_evidence() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_pending", None);
        let req = cancel_request("op_pending", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap(); // First: Pending
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap(); // Second: Pending
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
        assert!(resp.cleanup_result.is_none());
    }

    #[test]
    fn checkpoint_id_is_supplied_by_the_runtime() {
        let ctrl = CancellationController::new();
        let registration = ctrl
            .track_operation(
                "my_special_op",
                None,
                CancellationScope::new("connector", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
        let req = CancellationRequest {
            operation_id: "my_special_op".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
            capability_token: None,
        };
        assert!(
            ctrl.cancel(&req, None, fixed_now())
                .unwrap()
                .checkpoint
                .is_none()
        );
        assert!(ctrl.complete_cancelled_registration_when_settled(
            &registration,
            cancellation_evidence_fixture(),
        ));
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        let ckpt = resp.checkpoint.unwrap();
        assert_eq!(ckpt.id, "persisted-object-d14c");
        assert_eq!(
            ckpt.state,
            Some(serde_json::json!({"cursor": "after-three"}))
        );
    }

    #[test]
    fn checkpoint_expiry_is_supplied_by_the_runtime() {
        let now = fixed_now();
        let ctrl = CancellationController::new();
        let registration = ctrl
            .track_operation(
                "op_expiry",
                None,
                CancellationScope::new("connector", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
        let req = CancellationRequest {
            operation_id: "op_expiry".into(),
            reason: CancelReason::UserRequested,
            cleanup: CleanupBehavior::Checkpoint,
            return_partial: false,
            capability_token: None,
        };
        ctrl.cancel(&req, None, now).unwrap();
        assert!(ctrl.complete_cancelled_registration_when_settled(
            &registration,
            cancellation_evidence_fixture(),
        ));
        let resp = ctrl.cancel(&req, None, now).unwrap();
        let ckpt = resp.checkpoint.unwrap();
        assert_eq!(ckpt.expires_at, Some(now + chrono::Duration::minutes(17)));
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
        // A request cannot create partial output that the runtime never supplied.
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
    fn audit_had_partial_result_is_false_without_runtime_evidence() {
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
        assert_eq!(resp2.outcome, CancellationOutcome::Pending);
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
    fn pending_cleanup_does_not_claim_operation_state_was_removed() {
        let ctrl = CancellationController::new();
        ctrl.track_with_owner("op_pending_cleanup", None);
        let req = cancel_request("op_pending_cleanup", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap(); // Pending
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap(); // Pending
        assert!(resp.cleanup_result.is_none());
        assert_eq!(ctrl.tracked_count(), 1);
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
        // Both calls only request cancellation; neither persists a checkpoint.
        let resp1 = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp1.outcome, CancellationOutcome::Pending);
        assert!(resp1.checkpoint.is_none());
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
        assert_eq!(parsed.completed_items, 0);
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
        assert_eq!(resp_a.outcome, CancellationOutcome::Pending);

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
            assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
        assert_eq!(resp.outcome, CancellationOutcome::Pending);
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
    fn controller_preserves_real_cleanup_failure_instead_of_claiming_success() {
        let ctrl = CancellationController::new();
        let registration = ctrl
            .track_operation(
                "op_verify_cleanup",
                None,
                CancellationScope::new("connector", ConnectorArchetype::RequestResponse),
            )
            .unwrap();
        let req = cancel_request("op_verify_cleanup", CancelReason::UserRequested);
        ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert!(ctrl.complete_cancelled_registration_when_settled(
            &registration,
            cancellation_evidence_fixture(),
        ));
        let resp = ctrl.cancel(&req, None, fixed_now()).unwrap();
        assert_eq!(resp.outcome, CancellationOutcome::Cancelled);
        let cleanup = resp.cleanup_result.unwrap();
        assert_eq!(cleanup.cleaned, vec!["temporary_file"]);
        assert_eq!(cleanup.failed, vec!["provider_rollback"]);
        assert_eq!(cleanup.duration_ms, 51);
        assert!(!cleanup.success);
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
        )
        .unwrap();
        ctrl.track_operation(
            "op_completed",
            Some("user:alice"),
            CancellationScope::new("c:fast:1.0", ConnectorArchetype::RequestResponse)
                .with_deadline_override_ms(Some(100)),
        )
        .unwrap();
        ctrl.track_operation(
            "op_not_cancelled",
            Some("user:alice"),
            CancellationScope::new("c:idle:1.0", ConnectorArchetype::RequestResponse)
                .with_deadline_override_ms(Some(100)),
        )
        .unwrap();
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
        )
        .unwrap();
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

    // ── Lost termination attempts: recover ownership, never invent exit ──

    fn cancellable_attempt(
        controller: &CancellationController,
        operation_id: &str,
    ) -> CancellationRegistration {
        let registration = controller
            .track_operation(
                operation_id,
                None,
                CancellationScope::new(operation_id, ConnectorArchetype::RequestResponse)
                    .with_deadline_override_ms(Some(500))
                    .with_terminator(CancellationTerminator::new(|| {}, || false)),
            )
            .unwrap();
        controller
            .cancel(
                &cancel_request(operation_id, CancelReason::UserRequested),
                None,
                fixed_now(),
            )
            .unwrap();
        registration
    }

    #[test]
    fn lost_attempt_retries_only_after_last_clone_without_resetting_deadline() {
        let controller = CancellationController::new();
        let registration = cancellable_attempt(&controller, "lost");
        let requested_at = controller.operations.lock().unwrap().entries["lost"]
            .cancel_requested_at
            .unwrap();
        let at_deadline = requested_at + Duration::from_millis(500);
        assert!(
            controller
                .reap_expired(at_deadline - Duration::from_nanos(1))
                .is_empty()
        );
        let original = controller.reap_expired(at_deadline).pop().unwrap();
        let retained = original.clone();
        let old_attempt = Arc::downgrade(&original.attempt);
        drop(original);
        assert!(controller.reap_expired(at_deadline).is_empty());
        drop(retained);
        let retry = controller.reap_expired(at_deadline).pop().unwrap();
        assert!(!Weak::ptr_eq(&old_attempt, &Arc::downgrade(&retry.attempt)));
        assert!(Arc::ptr_eq(&registration.identity, &retry.registration));
        assert_eq!(retry.deadline, Duration::from_millis(500));
        assert_eq!(
            controller.operations.lock().unwrap().entries["lost"].cancel_requested_at,
            Some(requested_at)
        );
        assert!(controller.audit_events().iter().all(|event| !event.forced));
        assert!(
            controller
                .track_operation(
                    "lost",
                    None,
                    CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
                )
                .is_err(),
            "losing a reaper is not completion of the invocation"
        );
    }

    #[test]
    fn dropping_unpolled_or_pending_attempt_futures_recovers_dispatch() {
        use std::future::Future;
        use std::task::{Context, Waker};

        let controller = CancellationController::new();
        cancellable_attempt(&controller, "dropped-future");
        let now = Instant::now() + Duration::from_secs(1);
        for poll_first in [false, true] {
            let expired = controller.reap_expired(now).pop().unwrap();
            let mut work = Box::pin(async move {
                std::future::pending::<()>().await;
                drop(expired);
            });
            if poll_first {
                let mut context = Context::from_waker(Waker::noop());
                assert!(work.as_mut().poll(&mut context).is_pending());
            }
            assert!(controller.reap_expired(now).is_empty());
            drop(work);
        }
        assert_eq!(controller.reap_expired(now).len(), 1);
        assert!(controller.audit_events().iter().all(|event| !event.forced));
    }

    #[test]
    fn unwinding_attempt_recovers_without_explicit_rearm() {
        let controller = CancellationController::new();
        cancellable_attempt(&controller, "unwound");
        let now = Instant::now() + Duration::from_secs(1);
        let expired = controller.reap_expired(now).pop().unwrap();
        let failed = std::thread::spawn(move || {
            let _owned_attempt = expired;
            panic!("termination worker failed before reporting its result");
        });
        assert!(failed.join().is_err());
        assert_eq!(controller.reap_expired(now).len(), 1);
        assert!(controller.audit_events().iter().all(|event| !event.forced));
    }

    #[test]
    fn stale_attempt_results_cannot_acknowledge_or_rearm_a_newer_attempt() {
        let controller = CancellationController::new();
        cancellable_attempt(&controller, "retry-fenced");
        let now = Instant::now() + Duration::from_secs(1);
        let old = controller.reap_expired(now).pop().unwrap();
        controller.rearm_expiration(&old);
        assert!(!controller.record_forced_expiration(&old, fixed_now()));
        let current = controller.reap_expired(now).pop().unwrap();
        assert!(Arc::ptr_eq(&old.registration, &current.registration));
        assert!(!Arc::ptr_eq(&old.attempt, &current.attempt));
        controller.rearm_expiration(&old);
        assert!(controller.reap_expired(now).is_empty());
        assert!(!controller.record_forced_expiration(&old, fixed_now()));
        assert!(controller.record_forced_expiration(&current, fixed_now()));
        assert_eq!(
            controller
                .audit_events()
                .iter()
                .filter(|event| event.forced)
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_acknowledgements_emit_one_forced_audit_and_cannot_be_rearmed() {
        let controller = Arc::new(CancellationController::new());
        cancellable_attempt(&controller, "ack-once");
        let now = Instant::now() + Duration::from_secs(1);
        let expired = controller.reap_expired(now).pop().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let workers = [(), ()].map(|()| {
            let controller = Arc::clone(&controller);
            let barrier = Arc::clone(&barrier);
            let expired = expired.clone();
            std::thread::spawn(move || {
                barrier.wait();
                controller.record_forced_expiration(&expired, fixed_now())
            })
        });
        barrier.wait();
        let results = workers.map(|worker| worker.join().unwrap());
        assert_eq!(results.into_iter().filter(|recorded| *recorded).count(), 1);
        assert_eq!(
            controller
                .audit_events()
                .iter()
                .filter(|event| event.forced)
                .count(),
            1
        );
        controller.rearm_expiration(&expired);
        controller.rearm_force_terminate("ack-once");
        controller.record_forced_cancellation("ack-once", fixed_now());
        assert_eq!(
            controller
                .audit_events()
                .iter()
                .filter(|event| event.forced)
                .count(),
            1
        );
        controller.clear_audit_log();
        assert!(!controller.record_forced_expiration(&expired, fixed_now()));
        drop(expired);
        assert!(controller.reap_expired(now).is_empty());
        assert!(controller.audit_events().is_empty());
        assert!(
            controller
                .track_operation(
                    "ack-once",
                    None,
                    CancellationScope::new("replacement", ConnectorArchetype::RequestResponse),
                )
                .is_err(),
            "acknowledging termination must not release the operation ID"
        );
    }

    #[test]
    fn lost_attempts_recover_independently_while_another_attempt_remains_owned() {
        let controller = CancellationController::new();
        for id in ["kept", "lost-a", "lost-b"] {
            cancellable_attempt(&controller, id);
        }
        let now = Instant::now() + Duration::from_secs(1);
        let mut expired = controller.reap_expired(now);
        assert_eq!(expired.len(), 3);
        let retained_index = expired
            .iter()
            .position(|entry| entry.operation_id == "kept")
            .unwrap();
        let retained = expired.swap_remove(retained_index);
        drop(expired);
        let retries = controller.reap_expired(now);
        let ids: std::collections::BTreeSet<_> = retries
            .iter()
            .map(|entry| entry.operation_id.as_str())
            .collect();
        assert_eq!(ids, std::collections::BTreeSet::from(["lost-a", "lost-b"]));
        assert!(controller.reap_expired(now).is_empty());
        drop(retained);
        let recovered = controller.reap_expired(now);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].operation_id, "kept");
        assert!(controller.audit_events().iter().all(|event| !event.forced));
    }

    #[test]
    fn lost_attempt_does_not_resurrect_completed_removed_or_replaced_registrations() {
        let controller = CancellationController::new();
        let completed = cancellable_attempt(&controller, "completed-attempt");
        cancellable_attempt(&controller, "removed-attempt");
        let now = Instant::now() + Duration::from_secs(1);
        let old = controller.reap_expired(now);
        controller.complete_registration(&completed);
        controller.remove("removed-attempt");
        drop(old);
        assert!(controller.reap_expired(now).is_empty());

        let replacement = cancellable_attempt(&controller, "completed-attempt");
        let current = controller.reap_expired(now).pop().unwrap();
        assert!(Arc::ptr_eq(&current.registration, &replacement.identity));
        assert!(!Arc::ptr_eq(&current.registration, &completed.identity));
        controller.complete_registration(&completed);
        assert!(controller.reap_expired(now).is_empty());
        drop(current);
        let retry = controller.reap_expired(now).pop().unwrap();
        assert!(Arc::ptr_eq(&retry.registration, &replacement.identity));
    }

    #[test]
    fn unsupported_target_is_not_automatically_redispatched_after_handle_loss() {
        let controller = CancellationController::new();
        controller
            .track_operation(
                "unsupported",
                None,
                CancellationScope::new("unsupported", ConnectorArchetype::RequestResponse)
                    .with_deadline_override_ms(Some(1)),
            )
            .unwrap();
        controller
            .cancel(
                &cancel_request("unsupported", CancelReason::UserRequested),
                None,
                fixed_now(),
            )
            .unwrap();
        let now = Instant::now() + Duration::from_secs(1);
        let expired = controller.reap_expired(now);
        assert_eq!(expired.len(), 1);
        assert!(expired[0].terminator.is_none());
        drop(expired);
        assert!(
            controller
                .reap_expired(now + Duration::from_secs(60))
                .is_empty()
        );
        assert!(controller.audit_events().iter().all(|event| !event.forced));
        controller.rearm_force_terminate("unsupported");
        assert_eq!(
            controller.reap_expired(now).len(),
            1,
            "explicit legacy retry remains available"
        );
    }
}
