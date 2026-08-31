//! Cancellation-deadline bounded propagation conformance
//! (`flywheel_connectors-861lx`).
//!
//! NORMATIVE properties proven here (in-process, deterministic — the
//! same pattern as `host_invoke_loop_conformance.rs`):
//!
//! 1. **Unresponsive operations are force-terminated within deadline +
//!    epsilon.** An operation tracked with a
//!    [`fcp_host::CancellationScope`] that ignores its cancellation past
//!    the effective deadline MUST be reported by the reaper sweep
//!    exactly once, and the recorded audit event MUST carry
//!    `outcome = Cancelled` with `forced = true`.
//! 2. **Responsive operations are never force-terminated.** An
//!    operation that completes before its deadline MUST never appear in
//!    a reaper sweep, and MUST never produce a `forced` audit event.
//!
//! 10 s long-lived), operator override precedence, wire-compatible
//! `forced` serde default, the Strict-idempotency invariant that a
//! forced cancel does NOT release the tracked operation, and re-arm on
//! failed force-terminate.

use std::time::{Duration, Instant};

use chrono::Utc;
use fcp_host::{
    CancelReason, CancellationController, CancellationOutcome, CancellationRequest,
    CancellationScope, CleanupBehavior, ConnectorArchetype,
};

fn request(operation_id: &str, reason: CancelReason) -> CancellationRequest {
    CancellationRequest {
        operation_id: operation_id.to_string(),
        reason,
        cleanup: CleanupBehavior::default(),
        return_partial: false,
        capability_token: None,
    }
}

#[test]
fn unresponsive_operation_is_reaped_within_deadline_plus_epsilon() {
    let ctrl = CancellationController::new();
    ctrl.track_operation(
        "op-unresponsive",
        Some("user:alice"),
        CancellationScope::new("c:slow:1.0", ConnectorArchetype::RequestResponse)
            .with_deadline_override_ms(Some(100)),
    );

    let start = Instant::now();
    let cancel = request("op-unresponsive", CancelReason::UserRequested);
    let response = ctrl
        .cancel(&cancel, Some("user:alice"), Utc::now())
        .unwrap();
    assert_eq!(response.outcome, CancellationOutcome::Cancelled);

    // Before deadline + epsilon: nothing may be reaped.
    let early = ctrl.reap_expired(start + Duration::from_millis(50));
    assert!(
        early.is_empty(),
        "reaper MUST NOT fire before the deadline expires"
    );

    // At deadline + epsilon: exactly the unresponsive operation.
    let expired = ctrl.reap_expired(start + Duration::from_millis(150));
    assert_eq!(
        expired.len(),
        1,
        "deadline expiry MUST report the operation"
    );
    assert_eq!(expired[0].operation_id, "op-unresponsive");
    assert_eq!(expired[0].connector_id, "c:slow:1.0");
    assert_eq!(expired[0].deadline, Duration::from_millis(100));

    // The host reaper force-terminates and then records the audit event;
    // the event MUST carry forced = true with the Cancelled outcome.
    ctrl.record_forced_cancellation("op-unresponsive", Utc::now());
    let events = ctrl.audit_events();
    let forced = events
        .iter()
        .find(|event| event.forced)
        .expect("forced cancellation MUST be audited with forced = true");
    assert_eq!(forced.operation_id, "op-unresponsive");
    assert_eq!(forced.outcome, CancellationOutcome::Cancelled);
}

#[test]
fn responsive_operation_is_never_force_terminated() {
    let ctrl = CancellationController::new();
    ctrl.track_operation(
        "op-responsive",
        Some("user:alice"),
        CancellationScope::new("c:fast:1.0", ConnectorArchetype::Streaming)
            .with_deadline_override_ms(Some(100)),
    );
    let start = Instant::now();
    let cancel = request(
        "op-responsive",
        CancelReason::AgentAbort {
            reason: "operator stopped the run".into(),
        },
    );
    ctrl.cancel(&cancel, Some("user:alice"), Utc::now())
        .unwrap();

    // The connector acknowledges by finishing before the deadline.
    ctrl.complete("op-responsive");

    // Sweep far past the deadline: a completed operation MUST never be
    // reaped, and no forced audit event may exist.
    assert!(
        ctrl.reap_expired(start + Duration::from_secs(3600))
            .is_empty()
    );
    assert!(
        ctrl.audit_events().iter().all(|event| !event.forced),
        "responsive operations MUST NOT be force-terminated"
    );
}

#[test]
fn archetype_defaults_bound_the_effective_deadline() {
    let one_shot = |archetype| CancellationScope::new("c:x:1.0", archetype).effective_deadline();
    assert_eq!(
        one_shot(ConnectorArchetype::RequestResponse),
        Duration::from_secs(1),
        "request-response archetype MUST default to the 1 s bound"
    );
    assert_eq!(
        one_shot(ConnectorArchetype::Webhook),
        Duration::from_secs(1),
        "webhook archetype MUST default to the 1 s bound"
    );
    for archetype in [
        ConnectorArchetype::Streaming,
        ConnectorArchetype::Bidirectional,
        ConnectorArchetype::Polling,
        ConnectorArchetype::Unknown,
    ] {
        assert_eq!(
            one_shot(archetype),
            Duration::from_secs(10),
            "{archetype:?} MUST default to the 10 s long-lived bound"
        );
    }
}

#[test]
fn operator_override_wins_over_archetype_default() {
    let scope = CancellationScope::new("c:stream:1.0", ConnectorArchetype::Streaming)
        .with_deadline_override_ms(Some(250));
    assert_eq!(
        scope.effective_deadline(),
        Duration::from_millis(250),
        "a configured cancellation_deadline_ms MUST win over the archetype default"
    );
}

#[test]
fn forced_field_is_wire_compatible_via_serde_default() {
    // An audit event serialized by an older build (no `forced` key) MUST
    // deserialize with forced = false.
    let legacy_json = r#"{
        "timestamp": "2026-08-29T12:00:00Z",
        "operation_id": "op-legacy",
        "reason": {"type": "user_requested"},
        "outcome": "cancelled",
        "duration_ms": 5,
        "had_partial_result": false,
        "had_checkpoint": false
    }"#;
    let parsed: fcp_host::CancellationAuditEvent = serde_json::from_str(legacy_json)
        .expect("legacy audit JSON without `forced` MUST deserialize");
    assert!(!parsed.forced, "missing `forced` MUST default to false");
}

#[test]
fn forced_cancellation_does_not_release_the_tracked_operation() {
    // Strict-idempotency invariant: a forced cancel is bookkeeping plus
    // subprocess termination. The tracking entry stays until the regular
    // invoke path completes, and no intent is released here.
    let ctrl = CancellationController::new();
    ctrl.track_operation(
        "op-intent",
        Some("user:alice"),
        CancellationScope::new("c:stuck:1.0", ConnectorArchetype::Polling)
            .with_deadline_override_ms(Some(50)),
    );
    let cancel = request(
        "op-intent",
        CancelReason::TimeoutApproaching { remaining_ms: 0 },
    );
    ctrl.cancel(&cancel, Some("user:alice"), Utc::now())
        .unwrap();
    let expired = ctrl.reap_expired(Instant::now() + Duration::from_secs(1));
    assert_eq!(expired.len(), 1, "sweep must dispatch the force-terminate");
    ctrl.record_forced_cancellation("op-intent", Utc::now());

    assert_eq!(
        ctrl.tracked_count(),
        1,
        "forced cancel MUST NOT release the operation"
    );
    assert!(ctrl.is_cancel_requested("op-intent"));
}

#[test]
fn failed_force_terminate_is_rearmed_and_retried() {
    let ctrl = CancellationController::new();
    ctrl.track_operation(
        "op-retry",
        Some("user:alice"),
        CancellationScope::new("c:gone:1.0", ConnectorArchetype::RequestResponse)
            .with_deadline_override_ms(Some(50)),
    );
    let cancel = request("op-retry", CancelReason::UserRequested);
    ctrl.cancel(&cancel, Some("user:alice"), Utc::now())
        .unwrap();

    let start = Instant::now();
    assert_eq!(
        ctrl.reap_expired(start + Duration::from_millis(100)).len(),
        1,
        "first sweep MUST report the expired operation"
    );

    // Kill failed: the reaper re-arms and the next sweep retries.
    ctrl.rearm_force_terminate("op-retry");
    assert_eq!(
        ctrl.reap_expired(start + Duration::from_millis(150)).len(),
        1,
        "re-armed operations MUST be retried by the next sweep"
    );

    // After completion a re-arm is a no-op and the sweep stays empty.
    ctrl.complete("op-retry");
    ctrl.rearm_force_terminate("op-retry");
    assert!(
        ctrl.reap_expired(start + Duration::from_millis(200))
            .is_empty()
    );
}

#[test]
fn bookkeeping_only_registrations_never_expire() {
    // track_with_owner (no scope) registers operations without a backing
    // subprocess; there is nothing to force-terminate, so the reaper MUST
    // ignore them forever.
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-plain", None);
    let cancel = request("op-plain", CancelReason::UserRequested);
    ctrl.cancel(&cancel, None, Utc::now()).unwrap();
    assert!(
        ctrl.reap_expired(Instant::now() + Duration::from_secs(86_400))
            .is_empty()
    );
}
