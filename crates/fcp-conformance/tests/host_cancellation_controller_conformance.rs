//! `CancellationController` track/cancel/complete + br-jdaro
//! principal-mismatch defense conformance.
//!
//! `fcp_host::CancellationController` is the per-operation
//! cancellation tracker that the host gateway exposes to the admin
//! API and to in-process callers. Two NORMATIVE properties drive
//! its design:
//!
//! 1. **State machine (br-2653).** `track` registers an operation,
//!    `complete` marks it finished, `cancel` requests cancellation.
//!    The outcome MUST be:
//!    - `Pending` while an accepted cancellation awaits runtime settlement,
//!      including repeated requests,
//!    - `Cancelled` only after runtime-owned cancellation evidence settles,
//!    - `TooLate` after ordinary completion without cancellation evidence.
//! 2. **Principal-mismatch defense (br-jdaro).** When `track` was
//!    called with `Some(owner)`, `cancel` MUST reject any caller
//!    whose `asserted_principal` does not match the recorded owner —
//!    BEFORE any state mutation. Without this, a caller who guesses a
//!    client-chosen `operation_id` could cancel anyone's operations.
//!
//! Plus: cancel of an unknown operation returns
//! `HostError::ConnectorNotFound`; an audit event is recorded for
//! every cancel attempt; `track` with `None` owner is the legacy
//! permissive path that does NOT enforce principal matching.

use chrono::Utc;
use fcp_host::{
    CancelReason, CancellationController, CancellationOutcome, CancellationRequest, CleanupBehavior,
};

fn user_request(operation_id: &str) -> CancellationRequest {
    CancellationRequest {
        operation_id: operation_id.to_string(),
        reason: CancelReason::UserRequested,
        cleanup: CleanupBehavior::BestEffort,
        return_partial: false,
        capability_token: None,
    }
}

#[test]
fn cancel_of_tracked_operation_returns_pending_outcome() {
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-1", Some("user:alice"));

    let response = ctrl
        .cancel(&user_request("op-1"), Some("user:alice"), Utc::now())
        .expect("cancel must succeed for owner");
    assert_eq!(
        response.outcome,
        CancellationOutcome::Pending,
        "accepting cancellation MUST NOT claim runtime completion"
    );

    assert!(
        ctrl.is_cancel_requested("op-1"),
        "after a successful cancel, is_cancel_requested MUST return true"
    );
}

#[test]
fn second_cancel_returns_pending_outcome() {
    // Duplicate requests preserve Pending until the runtime confirms settlement.
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-2", Some("user:alice"));

    let _ = ctrl
        .cancel(&user_request("op-2"), Some("user:alice"), Utc::now())
        .expect("first cancel");
    let r2 = ctrl
        .cancel(&user_request("op-2"), Some("user:alice"), Utc::now())
        .expect("second cancel still returns Ok");
    assert_eq!(
        r2.outcome,
        CancellationOutcome::Pending,
        "double-cancel MUST return Pending (idempotent — the request was already accepted)"
    );
}

#[test]
fn cancel_after_complete_returns_too_late() {
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-3", Some("user:alice"));
    ctrl.complete("op-3");

    let response = ctrl
        .cancel(&user_request("op-3"), Some("user:alice"), Utc::now())
        .expect("cancel of completed operation still returns Ok with TooLate");
    assert_eq!(
        response.outcome,
        CancellationOutcome::TooLate,
        "cancel after complete MUST return TooLate"
    );
}

#[test]
fn cancel_of_unknown_operation_returns_error() {
    let ctrl = CancellationController::new();
    let result = ctrl.cancel(&user_request("op-unknown"), None, Utc::now());
    assert!(
        result.is_err(),
        "cancel of an operation never tracked MUST return an error rather than synthesizing state"
    );
}

#[test]
fn br_jdaro_principal_mismatch_rejects_before_state_mutation() {
    // Critical security property: an attacker who guesses the
    // operation_id but does not know the owner MUST be rejected,
    // and the underlying tracked operation MUST remain in its
    // pre-attempt state (NOT marked cancel_requested).
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-jdaro", Some("user:alice"));

    let result = ctrl.cancel(&user_request("op-jdaro"), Some("user:eve"), Utc::now());
    assert!(
        result.is_err(),
        "cancel by mismatched principal MUST be rejected; got Ok({result:?})"
    );

    // The tracked operation must NOT have been mutated — alice can
    // still cancel her own op normally.
    assert!(
        !ctrl.is_cancel_requested("op-jdaro"),
        "br-jdaro: rejected cancel attempt MUST NOT mutate operation state"
    );

    // Alice can still cancel.
    let r = ctrl
        .cancel(&user_request("op-jdaro"), Some("user:alice"), Utc::now())
        .expect("legitimate owner cancel must succeed after rejected attempt");
    assert_eq!(
        r.outcome,
        CancellationOutcome::Pending,
        "legitimate cancellation must still be accepted after an impostor is rejected"
    );
}

#[test]
fn br_jdaro_principal_mismatch_with_none_asserted_is_rejected() {
    // A caller who fails to assert any principal MUST also be
    // rejected when an owner is recorded.
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-anon", Some("user:alice"));

    let result = ctrl.cancel(&user_request("op-anon"), None, Utc::now());
    assert!(
        result.is_err(),
        "cancel with None asserted_principal MUST be rejected when an owner was recorded"
    );
    assert!(!ctrl.is_cancel_requested("op-anon"));
}

#[test]
fn legacy_none_owner_is_permissive_for_any_caller() {
    // The legacy permissive path: track_with_owner(_, None) means
    // "any caller may cancel". This is the back-compat behaviour
    // for routes that intentionally allow unauthenticated cancel.
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-legacy", None);

    // Any asserted principal works — including None.
    let r = ctrl
        .cancel(&user_request("op-legacy"), Some("user:anyone"), Utc::now())
        .expect("None-owner accepts any caller");
    assert_eq!(r.outcome, CancellationOutcome::Pending);
}

#[test]
fn audit_log_records_every_successful_cancel() {
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-audit", Some("user:alice"));
    let _ = ctrl
        .cancel(&user_request("op-audit"), Some("user:alice"), Utc::now())
        .expect("cancel");

    let events = ctrl.audit_events();
    assert!(
        events
            .iter()
            .any(|e| e.operation_id == "op-audit"
                && matches!(e.outcome, CancellationOutcome::Pending)),
        "audit log MUST contain a Pending entry for op-audit; got {events:?}"
    );
}

#[test]
fn audit_log_records_too_late_cancel_attempts() {
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-late", Some("user:alice"));
    ctrl.complete("op-late");
    let _ = ctrl
        .cancel(&user_request("op-late"), Some("user:alice"), Utc::now())
        .expect("cancel of completed");

    let events = ctrl.audit_events();
    assert!(
        events
            .iter()
            .any(|e| e.operation_id == "op-late"
                && matches!(e.outcome, CancellationOutcome::TooLate)),
        "audit log MUST capture TooLate cancellation attempts for forensics"
    );
}

#[test]
fn remove_after_complete_drops_tracking_entry() {
    // remove() must clear tracking; subsequent cancel of the same
    // operation_id must return ConnectorNotFound (not stale state).
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-remove", Some("user:alice"));
    ctrl.complete("op-remove");
    assert_eq!(ctrl.tracked_count(), 1);

    ctrl.remove("op-remove");
    assert_eq!(
        ctrl.tracked_count(),
        0,
        "remove() MUST drop the tracking entry"
    );

    let result = ctrl.cancel(&user_request("op-remove"), Some("user:alice"), Utc::now());
    assert!(
        result.is_err(),
        "after remove(), cancel MUST treat the operation as unknown"
    );
}

#[test]
fn is_cancel_requested_returns_false_for_untracked_operation() {
    let ctrl = CancellationController::new();
    assert!(
        !ctrl.is_cancel_requested("nonexistent"),
        "is_cancel_requested on an untracked operation MUST return false (not panic)"
    );
}

#[test]
fn track_then_complete_then_is_cancel_requested_remains_false() {
    let ctrl = CancellationController::new();
    ctrl.track_with_owner("op-clean", Some("user:alice"));
    ctrl.complete("op-clean");
    assert!(
        !ctrl.is_cancel_requested("op-clean"),
        "completing an operation MUST NOT set the cancel_requested flag"
    );
}
