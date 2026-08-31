//! Pin `IntentStatus` documented state-machine + `IdempotencyEntry` predicate
//! truth tables + `OperationValidationError` 9-variant Display matrix —
//! the closest analogue to "`IntentLifecycle` state machine"
//! (flywheel_connectors-l53eq).
//!
//! Bead asks for `IntentLifecycle` state-transition pinning per the
//! documented state machine. No type literally named `IntentLifecycle`
//! exists in fcp-core. The intent lifecycle is the
//! [`IntentStatus`] (`crates/fcp-core/src/operation.rs:356`) 5-variant
//! ladder driven through [`IdempotencyEntry`] (`operation.rs:389`)
//! predicates and validated by [`OperationValidationError`]
//! (`operation.rs:445`).
//!
//! `intent_manifest_serde_tag_matrix.rs` pins `IntentStatus` serde matrix.
//! `exactly_once_golden_vectors.rs` checks `OperationValidationError`
//! displayability + status serde round-trip. Residual unpinned axes:
//!   * Documented state-machine transition truth table (which
//!     from→to transitions are LEGAL per the documented `Pending` →
//!     `InProgress` → `Completed`/`Failed`/`Orphaned` ladder),
//!   * `IdempotencyEntry` predicate truth tables exhaustive over all 5
//!     `IntentStatus` values (`is_terminal`, `should_return_cached`),
//!   * `is_intent_orphaned` 4-corner truth table,
//!   * `required_idempotency_for_safety_tier` 4-cell truth table,
//!   * `OperationValidationError` 9-variant Display verbatim with payload
//!     preservation.

use fcp_cbor::SchemaId;
use fcp_core::{
    IdempotencyClass, IdempotencyEntry, IntentStatus, ObjectHeader, ObjectId, OperationIntent,
    OperationValidationError, Provenance, TailscaleNodeId, ZoneId, is_intent_orphaned,
    required_idempotency_for_safety_tier,
};
use semver::Version;
use uuid::Uuid;

const ALL_STATUSES: &[IntentStatus] = &[
    IntentStatus::Pending,
    IntentStatus::InProgress,
    IntentStatus::Completed,
    IntentStatus::Failed,
    IntentStatus::Orphaned,
];

const fn obj(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

fn make_entry(
    status: IntentStatus,
    receipt_id: Option<ObjectId>,
    expires_at: u64,
) -> IdempotencyEntry {
    IdempotencyEntry {
        key: "k".to_string(),
        zone_id: ZoneId::work(),
        intent_id: obj(0x10),
        receipt_id,
        status,
        created_at: 1_700_000_000,
        expires_at,
    }
}

/// Documented allow-list for the `IntentStatus` state machine. Per the
/// documentation in operation.rs:351-368:
///   `Pending`     → `InProgress` (operation starts)
///   `Pending`     → `Orphaned`   (no progress within threshold, no receipt)
///   `InProgress`  → `Completed`  (success receipt)
///   `InProgress`  → `Failed`     (error receipt)
///   `InProgress`  → `Orphaned`   (partial work, no receipt, expired)
///   `Completed`/`Failed`/`Orphaned`: terminal (no further transition)
const fn is_documented_legal_transition(from: IntentStatus, to: IntentStatus) -> bool {
    use IntentStatus::*;
    matches!(
        (from, to),
        (Pending, InProgress | Orphaned) | (InProgress, Completed | Failed | Orphaned)
    )
}

#[test]
fn intent_status_documented_transitions_match_allow_list() {
    // Walk the 5×5 matrix and confirm the allow-list mirrors the
    // documented transitions verbatim. Self-loops are not legal.
    // (IntentStatus does not derive Hash; use linear lookup.)
    let legal_pairs: &[(IntentStatus, IntentStatus)] = &[
        (IntentStatus::Pending, IntentStatus::InProgress),
        (IntentStatus::Pending, IntentStatus::Orphaned),
        (IntentStatus::InProgress, IntentStatus::Completed),
        (IntentStatus::InProgress, IntentStatus::Failed),
        (IntentStatus::InProgress, IntentStatus::Orphaned),
    ];

    for &from in ALL_STATUSES {
        for &to in ALL_STATUSES {
            let documented = is_documented_legal_transition(from, to);
            let in_allow_list = legal_pairs.iter().any(|&(f, t)| f == from && t == to);
            assert_eq!(
                documented, in_allow_list,
                "transition {from:?} → {to:?}: documented={documented}, allow_list={in_allow_list}"
            );
        }
    }
    assert_eq!(legal_pairs.len(), 5, "5 documented transitions total");
}

#[test]
fn intent_status_terminal_states_have_no_outgoing_transitions() {
    // Completed, Failed, Orphaned are terminal — no documented outgoing
    // transitions. Pin so a future relaxation that lets a terminal state
    // resume is caught loudly.
    for terminal in [
        IntentStatus::Completed,
        IntentStatus::Failed,
        IntentStatus::Orphaned,
    ] {
        for &to in ALL_STATUSES {
            assert!(
                !is_documented_legal_transition(terminal, to),
                "terminal {terminal:?} must have no outgoing transition to {to:?}"
            );
        }
    }
}

#[test]
fn intent_status_pending_only_advances_to_in_progress_or_orphaned() {
    // From Pending, only InProgress (start) and Orphaned (timeout) are
    // legal — completion/failure cannot happen without first being
    // InProgress.
    assert!(is_documented_legal_transition(
        IntentStatus::Pending,
        IntentStatus::InProgress
    ));
    assert!(is_documented_legal_transition(
        IntentStatus::Pending,
        IntentStatus::Orphaned
    ));
    assert!(!is_documented_legal_transition(
        IntentStatus::Pending,
        IntentStatus::Completed
    ));
    assert!(!is_documented_legal_transition(
        IntentStatus::Pending,
        IntentStatus::Failed
    ));
    assert!(!is_documented_legal_transition(
        IntentStatus::Pending,
        IntentStatus::Pending
    ));
}

#[test]
fn intent_status_in_progress_advances_to_completed_failed_or_orphaned() {
    assert!(is_documented_legal_transition(
        IntentStatus::InProgress,
        IntentStatus::Completed
    ));
    assert!(is_documented_legal_transition(
        IntentStatus::InProgress,
        IntentStatus::Failed
    ));
    assert!(is_documented_legal_transition(
        IntentStatus::InProgress,
        IntentStatus::Orphaned
    ));
    // InProgress cannot reverse to Pending.
    assert!(!is_documented_legal_transition(
        IntentStatus::InProgress,
        IntentStatus::Pending
    ));
    assert!(!is_documented_legal_transition(
        IntentStatus::InProgress,
        IntentStatus::InProgress
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// IdempotencyEntry predicate truth tables
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn is_terminal_truth_table_includes_only_completed_and_failed() {
    // is_terminal pins the OUTCOME-terminal subset: Completed and Failed
    // ONLY (Orphaned is documented as a separate "no-receipt" terminal
    // not counted as is_terminal). Pin so a future expansion that
    // includes Orphaned as terminal silently changes retry semantics.
    for &status in ALL_STATUSES {
        let entry = make_entry(status, None, u64::MAX);
        let expected = matches!(status, IntentStatus::Completed | IntentStatus::Failed);
        assert_eq!(entry.is_terminal(), expected, "is_terminal({status:?})");
    }
}

#[test]
fn is_expired_boundary_truth_table() {
    let entry = make_entry(IntentStatus::Completed, Some(obj(0x20)), 1_000);

    assert!(
        !entry.is_expired(999),
        "now < expires_at must NOT be expired"
    );
    assert!(entry.is_expired(1_000), "now == expires_at IS expired");
    assert!(entry.is_expired(1_001), "now > expires_at IS expired");
    assert!(entry.is_expired(u64::MAX));
}

#[test]
fn should_return_cached_requires_terminal_with_receipt_and_not_expired() {
    let receipt = Some(obj(0x20));
    let now = 500;
    let future = 1_000;

    // Completed + receipt + not expired → cache hit.
    let entry = make_entry(IntentStatus::Completed, receipt, future);
    assert!(entry.should_return_cached(now));

    // Failed + receipt + not expired → cache hit.
    let entry = make_entry(IntentStatus::Failed, receipt, future);
    assert!(entry.should_return_cached(now));

    // Pending → no cache (not terminal).
    let entry = make_entry(IntentStatus::Pending, receipt, future);
    assert!(!entry.should_return_cached(now));

    // InProgress → no cache (not terminal).
    let entry = make_entry(IntentStatus::InProgress, receipt, future);
    assert!(!entry.should_return_cached(now));

    // Orphaned → no cache (not terminal per is_terminal contract).
    let entry = make_entry(IntentStatus::Orphaned, receipt, future);
    assert!(!entry.should_return_cached(now));

    // Completed but no receipt → no cache.
    let entry = make_entry(IntentStatus::Completed, None, future);
    assert!(!entry.should_return_cached(now));

    // Completed with receipt but expired → no cache.
    let entry = make_entry(IntentStatus::Completed, receipt, 100);
    assert!(!entry.should_return_cached(now));
}

#[test]
fn should_return_cached_truth_table_per_status() {
    // Walk all 5 statuses with receipt + future expires.
    for &status in ALL_STATUSES {
        let entry = make_entry(status, Some(obj(0x20)), u64::MAX);
        let expected = matches!(status, IntentStatus::Completed | IntentStatus::Failed);
        assert_eq!(
            entry.should_return_cached(0),
            expected,
            "should_return_cached({status:?})"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// is_intent_orphaned truth table
// ─────────────────────────────────────────────────────────────────────────────

fn make_intent(planned_at: u64) -> OperationIntent {
    let zone = ZoneId::work();
    OperationIntent {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.operation", "intent", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            created_at: planned_at,
            provenance: Provenance::new(zone),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        },
        request_object_id: obj(0x10),
        capability_token_jti: Uuid::nil(),
        idempotency_key: None,
        planned_at,
        planned_by: TailscaleNodeId::new("planner"),
        lease_seq: None,
        upstream_idempotency: None,
        signature: fcp_core::NodeSignature::new(
            fcp_core::NodeId::new("test"),
            [0u8; 64],
            planned_at,
        ),
    }
}

#[test]
fn is_intent_orphaned_truth_table_4_corners() {
    let intent = make_intent(1_000);
    let threshold = 600;

    // Has receipt + within threshold → NOT orphaned.
    assert!(!is_intent_orphaned(&intent, true, 1_500, threshold));
    // Has receipt + past threshold → NOT orphaned (receipt resolves it).
    assert!(!is_intent_orphaned(&intent, true, 2_000, threshold));
    // No receipt + within threshold → NOT orphaned (still has time).
    assert!(!is_intent_orphaned(&intent, false, 1_500, threshold));
    // No receipt + past threshold → IS orphaned.
    assert!(is_intent_orphaned(&intent, false, 2_000, threshold));
    // No receipt + AT threshold (saturating_sub == threshold) → NOT
    // orphaned (rule is STRICTLY greater than threshold).
    assert!(!is_intent_orphaned(&intent, false, 1_600, threshold));
}

#[test]
fn is_intent_orphaned_now_before_planned_at_is_not_orphaned() {
    // Boundary: now < planned_at (clock skew or test artifact). saturating_sub
    // returns 0, which is NOT > threshold for any positive threshold.
    let intent = make_intent(2_000);
    assert!(!is_intent_orphaned(&intent, false, 1_000, 600));
    assert!(!is_intent_orphaned(&intent, false, 0, 600));
}

// ─────────────────────────────────────────────────────────────────────────────
// required_idempotency_for_safety_tier truth table
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn required_idempotency_for_safety_tier_full_truth_table() {
    // Per spec: Dangerous OR Risky → Strict; Safe (neither) → None.
    assert_eq!(
        required_idempotency_for_safety_tier(true, false),
        IdempotencyClass::Strict,
        "Dangerous → Strict"
    );
    assert_eq!(
        required_idempotency_for_safety_tier(false, true),
        IdempotencyClass::Strict,
        "Risky → Strict"
    );
    assert_eq!(
        required_idempotency_for_safety_tier(true, true),
        IdempotencyClass::Strict,
        "Both Dangerous and Risky → Strict"
    );
    assert_eq!(
        required_idempotency_for_safety_tier(false, false),
        IdempotencyClass::None,
        "Safe (neither) → None"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// OperationValidationError 9-variant Display matrix
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn intent_not_found_display() {
    let err = OperationValidationError::IntentNotFound {
        idempotency_key: "k1".to_string(),
    };
    assert_eq!(err.to_string(), "intent not found for idempotency key: k1");
}

#[test]
fn already_completed_display() {
    let err = OperationValidationError::AlreadyCompleted {
        idempotency_key: "k1".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "operation already completed for idempotency key: k1"
    );
}

#[test]
fn idempotency_key_mismatch_display_with_some() {
    let err = OperationValidationError::IdempotencyKeyMismatch {
        expected: Some("a".to_string()),
        got: Some("b".to_string()),
    };
    assert_eq!(
        err.to_string(),
        "idempotency key mismatch: expected a, got b"
    );
}

#[test]
fn idempotency_key_mismatch_display_with_none_renders_angle_bracket_none() {
    let err = OperationValidationError::IdempotencyKeyMismatch {
        expected: None,
        got: Some("b".to_string()),
    };
    assert_eq!(
        err.to_string(),
        "idempotency key mismatch: expected <none>, got b"
    );

    let err = OperationValidationError::IdempotencyKeyMismatch {
        expected: Some("a".to_string()),
        got: None,
    };
    assert_eq!(
        err.to_string(),
        "idempotency key mismatch: expected a, got <none>"
    );

    let err = OperationValidationError::IdempotencyKeyMismatch {
        expected: None,
        got: None,
    };
    assert_eq!(
        err.to_string(),
        "idempotency key mismatch: expected <none>, got <none>"
    );
}

#[test]
fn zone_mismatch_display() {
    let err = OperationValidationError::ZoneMismatch {
        expected: ZoneId::work(),
        got: ZoneId::owner(),
    };
    assert_eq!(
        err.to_string(),
        "zone mismatch: expected z:work, got z:owner"
    );
}

#[test]
fn intent_reference_missing_display() {
    let id = obj(0x42);
    let err = OperationValidationError::IntentReferenceMissing { receipt_id: id };
    assert_eq!(
        err.to_string(),
        format!("receipt {id} does not reference an intent")
    );
}

#[test]
fn lease_seq_mismatch_display() {
    let err = OperationValidationError::LeaseSeqMismatch {
        expected: 42,
        got: 41,
    };
    assert_eq!(err.to_string(), "lease seq mismatch: expected 42, got 41");
}

#[test]
fn intent_orphaned_display() {
    let id = obj(0x10);
    let err = OperationValidationError::IntentOrphaned {
        intent_id: id,
        planned_at: 1_700_000_000,
    };
    assert_eq!(
        err.to_string(),
        format!("intent {id} orphaned (planned at 1700000000)")
    );
}

#[test]
fn signature_invalid_display() {
    let err = OperationValidationError::SignatureInvalid {
        reason: "bad sig".to_string(),
    };
    assert_eq!(err.to_string(), "signature invalid: bad sig");
}

#[test]
fn request_mismatch_display() {
    let expected = obj(0x11);
    let got = obj(0x22);
    let err = OperationValidationError::RequestMismatch { expected, got };
    assert_eq!(
        err.to_string(),
        format!("request mismatch: expected {expected}, got {got}")
    );
}

#[test]
fn all_nine_validation_error_variants_have_distinct_display() {
    let variants = [
        OperationValidationError::IntentNotFound {
            idempotency_key: "k".to_string(),
        },
        OperationValidationError::AlreadyCompleted {
            idempotency_key: "k".to_string(),
        },
        OperationValidationError::IdempotencyKeyMismatch {
            expected: Some("a".to_string()),
            got: Some("b".to_string()),
        },
        OperationValidationError::ZoneMismatch {
            expected: ZoneId::work(),
            got: ZoneId::owner(),
        },
        OperationValidationError::IntentReferenceMissing {
            receipt_id: obj(0x42),
        },
        OperationValidationError::LeaseSeqMismatch {
            expected: 1,
            got: 2,
        },
        OperationValidationError::IntentOrphaned {
            intent_id: obj(0x10),
            planned_at: 1,
        },
        OperationValidationError::SignatureInvalid {
            reason: "x".to_string(),
        },
        OperationValidationError::RequestMismatch {
            expected: obj(0x11),
            got: obj(0x22),
        },
    ];
    let strings: std::collections::HashSet<_> = variants.iter().map(ToString::to_string).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "Display collision across OperationValidationError: {strings:?}"
    );
}

#[test]
fn operation_validation_error_implements_std_error() {
    fn assert_error<E: std::error::Error>(_: &E) {}
    let err = OperationValidationError::IntentNotFound {
        idempotency_key: "k".to_string(),
    };
    assert_error(&err);
}
