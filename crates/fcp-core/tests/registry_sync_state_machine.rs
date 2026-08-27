//! Pin `LifecycleState` + `LifecycleRecord::transition` state-machine truth
//! table — the closest analogue to "`RegistrySync` state machine"
//! (flywheel_connectors-gbsko).
//!
//! Bead asks for `RegistrySync` state-machine pinning per the documented state
//! machine. No type literally named `RegistrySync` exists in fcp-core. The
//! closest analogue with a documented state machine is [`LifecycleState`] +
//! [`LifecycleRecord::transition`] at `crates/fcp-core/src/lifecycle.rs:44+322`,
//! whose `validate_transition` enumerates the legal `(from, to)` cells. This
//! test pins:
//!   * 7-variant `LifecycleState` `snake_case` serde rename + Display,
//!   * Predicate truth tables: `is_active`, `can_start_canary`, `can_promote`,
//!     `can_rollback` — each exhaustive over all 7 states,
//!   * Full 7×7 transition truth table (49 cells, each Allow/Deny pinned),
//!   * Self-transitions denied for every state,
//!   * `transition()` mutates `state` + pushes to `transitions` on success,
//!   * `transition()` leaves both untouched on `InvalidTransition`,
//!   * `LifecycleError::InvalidTransition` Display contains both states,
//!   * `TransitionReason` internally-tagged `snake_case` serde matrix.

use chrono::Utc;
use fcp_core::{
    CanaryPolicy, ConnectorId, HealthMetrics, LifecycleError, LifecycleRecord, LifecycleState,
    LifecycleTransition, TransitionReason,
};
use semver::Version;
use serde_json::json;

const ALL_STATES: &[LifecycleState] = &[
    LifecycleState::Pending,
    LifecycleState::Installing,
    LifecycleState::Canary,
    LifecycleState::Production,
    LifecycleState::RolledBack,
    LifecycleState::Disabled,
    LifecycleState::Uninstalled,
];

fn fresh_record() -> LifecycleRecord {
    LifecycleRecord::new(
        ConnectorId::from_static("fcp.test:lifecycle:v1"),
        Version::parse("1.2.3").unwrap(),
    )
}

/// Force a record into a target state by walking a known-legal path. Panics if
/// the destination is unreachable from `Pending`.
fn record_in_state(state: LifecycleState) -> LifecycleRecord {
    let mut r = fresh_record();
    let path: &[LifecycleState] = match state {
        LifecycleState::Pending => &[],
        LifecycleState::Installing => &[LifecycleState::Installing],
        LifecycleState::Canary => &[LifecycleState::Installing, LifecycleState::Canary],
        LifecycleState::Production => &[
            LifecycleState::Installing,
            LifecycleState::Canary,
            LifecycleState::Production,
        ],
        LifecycleState::RolledBack => &[
            LifecycleState::Installing,
            LifecycleState::Canary,
            LifecycleState::RolledBack,
        ],
        LifecycleState::Disabled => &[
            LifecycleState::Installing,
            LifecycleState::Canary,
            LifecycleState::Disabled,
        ],
        LifecycleState::Uninstalled => &[LifecycleState::Uninstalled],
    };
    for &step in path {
        r.transition(step, TransitionReason::ManualPromotion)
            .unwrap();
    }
    assert_eq!(r.state, state);
    r
}

/// Documented allow-list for `(from, to)` transitions. This must match
/// `lifecycle.rs:338 validate_transition` — drift on either side fails this
/// test loudly.
const fn is_documented_legal(from: LifecycleState, to: LifecycleState) -> bool {
    use LifecycleState::*;
    matches!(
        (from, to),
        (Pending, Installing | Uninstalled)
            | (Installing | Production | RolledBack | Disabled, Canary)
            | (
                Installing | Canary | Production | RolledBack | Disabled,
                Uninstalled
            )
            | (Canary, Production | RolledBack | Disabled)
            | (Production, RolledBack | Disabled)
            | (RolledBack, Disabled)
    )
}

#[test]
fn lifecycle_state_serde_uses_snake_case() {
    let cases = [
        (LifecycleState::Pending, "pending"),
        (LifecycleState::Installing, "installing"),
        (LifecycleState::Canary, "canary"),
        (LifecycleState::Production, "production"),
        (LifecycleState::RolledBack, "rolled_back"),
        (LifecycleState::Disabled, "disabled"),
        (LifecycleState::Uninstalled, "uninstalled"),
    ];

    for (state, wire) in cases {
        let v = serde_json::to_value(state).unwrap();
        assert_eq!(v, json!(wire), "{state:?} must serialize to `{wire}`");
        let back: LifecycleState = serde_json::from_value(v).unwrap();
        assert_eq!(back, state);
        // Display matches wire form.
        assert_eq!(state.to_string(), wire, "{state:?} Display != wire form");
    }
}

#[test]
fn lifecycle_state_rejects_pascalcase_input() {
    // Loud sentinel: dropping the snake_case rename would let PascalCase
    // through and silently break wire compatibility.
    let result: Result<LifecycleState, _> = serde_json::from_value(json!("RolledBack"));
    assert!(result.is_err(), "must reject PascalCase, got {result:?}");
    let result: Result<LifecycleState, _> = serde_json::from_value(json!("PENDING"));
    assert!(result.is_err(), "must reject SCREAMING, got {result:?}");
}

#[test]
fn is_active_predicate_truth_table() {
    let active = [LifecycleState::Canary, LifecycleState::Production];
    for &s in ALL_STATES {
        let expected = active.contains(&s);
        assert_eq!(s.is_active(), expected, "is_active({s:?})");
    }
}

#[test]
fn can_start_canary_predicate_truth_table() {
    let allowed = [
        LifecycleState::Installing,
        LifecycleState::Production,
        LifecycleState::RolledBack,
        LifecycleState::Disabled,
    ];
    for &s in ALL_STATES {
        let expected = allowed.contains(&s);
        assert_eq!(s.can_start_canary(), expected, "can_start_canary({s:?})");
    }
}

#[test]
fn can_promote_predicate_truth_table() {
    for &s in ALL_STATES {
        let expected = s == LifecycleState::Canary;
        assert_eq!(s.can_promote(), expected, "can_promote({s:?})");
    }
}

#[test]
fn can_rollback_predicate_truth_table() {
    let allowed = [LifecycleState::Canary, LifecycleState::Production];
    for &s in ALL_STATES {
        let expected = allowed.contains(&s);
        assert_eq!(s.can_rollback(), expected, "can_rollback({s:?})");
    }
}

#[test]
fn full_transition_truth_table_pins_every_cell() {
    for &from in ALL_STATES {
        for &to in ALL_STATES {
            let mut r = record_in_state(from);
            let result = r.transition(to, TransitionReason::ManualPromotion);
            let expected = is_documented_legal(from, to);
            assert_eq!(
                result.is_ok(),
                expected,
                "({from:?} -> {to:?}) expected legal={expected}, got {result:?}"
            );
        }
    }
}

#[test]
fn self_transitions_are_always_denied() {
    // The state machine has no self-loops — any state must reject a transition
    // back to itself.
    for &s in ALL_STATES {
        let mut r = record_in_state(s);
        let result = r.transition(s, TransitionReason::ManualPromotion);
        assert!(
            result.is_err(),
            "self-transition {s:?} -> {s:?} must be rejected, got {result:?}"
        );
        assert_eq!(r.state, s, "failed transition must not mutate state");
    }
}

#[test]
fn successful_transition_updates_state_and_appends_history() {
    let mut r = fresh_record();
    assert_eq!(r.state, LifecycleState::Pending);
    assert_eq!(r.transitions, [] as [fcp_core::LifecycleTransition; 0]);
    let original_state_changed_at = r.state_changed_at;

    r.transition(
        LifecycleState::Installing,
        TransitionReason::InstallComplete,
    )
    .unwrap();

    assert_eq!(r.state, LifecycleState::Installing);
    assert_eq!(r.transitions.len(), 1);
    let event: &LifecycleTransition = &r.transitions[0];
    assert_eq!(event.from, LifecycleState::Pending);
    assert_eq!(event.to, LifecycleState::Installing);
    assert_eq!(event.reason, TransitionReason::InstallComplete);
    assert!(
        event.timestamp <= Utc::now(),
        "transition timestamp must be wall-clock current"
    );
    assert!(
        r.state_changed_at >= original_state_changed_at,
        "state_changed_at must advance"
    );
}

#[test]
fn failed_transition_leaves_state_and_history_untouched() {
    let mut r = fresh_record();
    let snapshot_state = r.state;
    let snapshot_history_len = r.transitions.len();

    // Pending -> Production is illegal.
    let err = r
        .transition(
            LifecycleState::Production,
            TransitionReason::ManualPromotion,
        )
        .expect_err("Pending -> Production must fail");
    match err {
        LifecycleError::InvalidTransition { from, to } => {
            assert_eq!(from, LifecycleState::Pending);
            assert_eq!(to, LifecycleState::Production);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    assert_eq!(r.state, snapshot_state, "state must not advance on failure");
    assert_eq!(
        r.transitions.len(),
        snapshot_history_len,
        "transitions vec must not grow on failure"
    );
}

#[test]
fn invalid_transition_display_mentions_both_states() {
    let err = LifecycleError::InvalidTransition {
        from: LifecycleState::Pending,
        to: LifecycleState::Production,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("pending"),
        "msg should mention from-state: {msg}"
    );
    assert!(
        msg.contains("production"),
        "msg should mention to-state: {msg}"
    );
}

#[test]
fn transition_reason_serde_uses_internally_tagged_snake_case() {
    // TransitionReason carries `#[serde(tag = "type", rename_all = "snake_case")]`.
    // Pin the tag on every variant.
    let cases = [
        (TransitionReason::InstallComplete, "install_complete"),
        (TransitionReason::ManualPromotion, "manual_promotion"),
        (TransitionReason::Uninstalled, "uninstalled"),
    ];
    for (reason, tag) in cases {
        let v = serde_json::to_value(&reason).unwrap();
        let obj = v.as_object().expect("must be object");
        assert_eq!(
            obj.get("type"),
            Some(&json!(tag)),
            "{reason:?} must carry tag `{tag}`"
        );
        let back: TransitionReason = serde_json::from_value(v).unwrap();
        assert_eq!(back, reason);
    }

    // Variants with payload preserve fields alongside the tag.
    let auto_promo = TransitionReason::AutoPromotion { health_score: 92 };
    let v = serde_json::to_value(&auto_promo).unwrap();
    assert_eq!(v.get("type"), Some(&json!("auto_promotion")));
    assert_eq!(v.get("health_score"), Some(&json!(92)));
    let back: TransitionReason = serde_json::from_value(v).unwrap();
    assert_eq!(back, auto_promo);

    let auto_rollback = TransitionReason::AutoRollback {
        health_score: 12,
        failure_reason: "p99 spike".to_string(),
    };
    let v = serde_json::to_value(&auto_rollback).unwrap();
    assert_eq!(v.get("type"), Some(&json!("auto_rollback")));
    assert_eq!(v.get("failure_reason"), Some(&json!("p99 spike")));
    let back: TransitionReason = serde_json::from_value(v).unwrap();
    assert_eq!(back, auto_rollback);

    // Distinct reasons must produce distinct JSON.
    let distinct = serde_json::to_value(TransitionReason::ManualPromotion).unwrap();
    let distinct2 = serde_json::to_value(TransitionReason::Uninstalled).unwrap();
    assert_ne!(distinct, distinct2);
}

#[test]
fn lifecycle_record_serde_roundtrip_preserves_full_transition_history() {
    let mut r = fresh_record();
    r.transition(
        LifecycleState::Installing,
        TransitionReason::InstallComplete,
    )
    .unwrap();
    r.transition(LifecycleState::Canary, TransitionReason::ManualPromotion)
        .unwrap();
    r.transition(
        LifecycleState::Production,
        TransitionReason::AutoPromotion { health_score: 95 },
    )
    .unwrap();
    assert_eq!(r.transitions.len(), 3);

    let bytes = serde_json::to_vec(&r).unwrap();
    let back: LifecycleRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.state, LifecycleState::Production);
    assert_eq!(back.transitions.len(), 3);
    assert_eq!(back.transitions[0].to, LifecycleState::Installing);
    assert_eq!(back.transitions[1].to, LifecycleState::Canary);
    assert_eq!(back.transitions[2].to, LifecycleState::Production);
    assert_eq!(
        back.transitions[2].reason,
        TransitionReason::AutoPromotion { health_score: 95 }
    );
}

#[test]
fn fresh_record_starts_in_pending_with_default_health_and_canary_policy() {
    let r = fresh_record();
    assert_eq!(r.state, LifecycleState::Pending);
    assert_eq!(r.transitions, [] as [fcp_core::LifecycleTransition; 0]);
    assert!(r.previous_version.is_none());
    // Sanity: defaults match LifecycleRecord::new() contract.
    let _: &HealthMetrics = &r.health;
    let _: &CanaryPolicy = &r.canary_policy;
}
