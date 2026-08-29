//! E2E tests for the FCP2 Taint/Approval flow (provenance system).
//!
//! Exercises the provenance model end-to-end:
//! - Taint blocking for dangerous/risky/safe operations
//! - `ApprovalToken` elevation and declassification
//! - `SanitizerReceipt` taint reduction
//! - Provenance merge semantics (integrity=MIN, confidentiality=MAX, taint=OR)
//! - Information flow / zone crossing rules
//! - Full logged flows with `E2eLogger` structured logging
//!
//! All tests are synchronous and deterministic (no network, no async).

#![allow(clippy::too_many_lines)]

use fcp_e2e::{AssertionsSummary, E2eLogEntry, E2eLogger};
use fcp_prelude::{
    ApprovalScope, ApprovalToken, ConfidentialityLevel, DeclassificationScope, ElevationScope,
    ExecutionScope, FlowCheckResult, InputConstraint, IntegrityLevel, ObjectId, ProvenanceRecord,
    ProvenanceViolation, SafetyTier, SanitizerReceipt, TaintDecision, TaintFlag, TaintFlags,
    ZoneId,
};
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn oid(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn make_approval_token(
    token_id: &str,
    scope: ApprovalScope,
    zone: ZoneId,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> ApprovalToken {
    ApprovalToken::approved(
        token_id.to_string(),
        issued_at_ms,
        expires_at_ms,
        "test-issuer".to_string(),
        scope,
        zone,
        None,
    )
}

fn make_sanitizer_receipt(
    receipt_id: &str,
    authorized: &[TaintFlag],
    cleared: &[TaintFlag],
    covered: &[ObjectId],
) -> SanitizerReceipt {
    SanitizerReceipt {
        receipt_id: receipt_id.to_string(),
        timestamp_ms: 1000,
        sanitizer_id: "test-sanitizer".to_string(),
        sanitizer_zone: ZoneId::work(),
        authorized_flags: authorized.to_vec(),
        covered_inputs: covered.to_vec(),
        cleared_flags: cleared.to_vec(),
        signature: None,
    }
}

fn log_entry(
    test_name: &str,
    phase: &str,
    result: &str,
    passed: u32,
    failed: u32,
    context: serde_json::Value,
) -> E2eLogEntry {
    E2eLogEntry::new(
        "info",
        test_name,
        "fcp-e2e",
        phase,
        "taint-approval-e2e",
        result,
        0,
        AssertionsSummary::new(passed, failed),
        context,
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// A. Taint Blocking Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn taint_public_input_blocks_dangerous_operation() {
    let record = ProvenanceRecord::public_input();
    let result = record.can_drive_operation(SafetyTier::Dangerous);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::PublicInputForDangerousOperation => {}
        other => panic!("expected PublicInputForDangerousOperation, got {other:?}"),
    }
}

#[test]
fn taint_malicious_blocks_risky() {
    let mut record = ProvenanceRecord::new(ZoneId::work());
    record.taint_flags.insert(TaintFlag::PotentiallyMalicious);
    let result = record.can_drive_operation(SafetyTier::Risky);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::MaliciousInputDetected => {}
        other => panic!("expected MaliciousInputDetected, got {other:?}"),
    }
}

#[test]
fn taint_malicious_blocks_dangerous() {
    let mut record = ProvenanceRecord::new(ZoneId::work());
    record.taint_flags.insert(TaintFlag::PotentiallyMalicious);
    let result = record.can_drive_operation(SafetyTier::Dangerous);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::MaliciousInputDetected => {}
        other => panic!("expected MaliciousInputDetected, got {other:?}"),
    }
}

#[test]
fn taint_cross_zone_unapproved_blocks_dangerous() {
    let mut record = ProvenanceRecord::new(ZoneId::work());
    record.taint_flags.insert(TaintFlag::CrossZoneUnapproved);
    let result = record.can_drive_operation(SafetyTier::Dangerous);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::CrossZoneUnapprovedForDangerousOperation => {}
        other => panic!("expected CrossZoneUnapprovedForDangerousOperation, got {other:?}"),
    }
}

#[test]
fn taint_safe_operations_always_allowed() {
    // Even fully tainted input can drive Safe operations
    let mut record = ProvenanceRecord::public_input();
    record.taint_flags.insert(TaintFlag::PotentiallyMalicious);
    record.taint_flags.insert(TaintFlag::CrossZoneUnapproved);
    record.taint_flags.insert(TaintFlag::WebhookInjected);
    record.taint_flags.insert(TaintFlag::AiGenerated);
    assert!(record.can_drive_operation(SafetyTier::Safe).is_ok());
}

#[test]
fn taint_risky_with_work_integrity_allows() {
    // Risky ops OK if integrity >= Work even with critical taint (except PotentiallyMalicious)
    let mut record = ProvenanceRecord::new(ZoneId::work());
    record.taint_flags.insert(TaintFlag::PublicInput);
    record.taint_flags.insert(TaintFlag::CrossZoneUnapproved);
    // Work zone gives integrity=Work, which satisfies the requirement
    assert!(record.can_drive_operation(SafetyTier::Risky).is_ok());
}

#[test]
fn taint_risky_with_untrusted_integrity_and_critical_flag_blocks() {
    let record = ProvenanceRecord::public_input();
    // PublicInput is critical, and integrity is Untrusted
    let result = record.can_drive_operation(SafetyTier::Risky);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::TaintedInputForRiskyOperation { taint_flags } => {
            assert!(taint_flags.contains(&TaintFlag::PublicInput));
        }
        other => panic!("expected TaintedInputForRiskyOperation, got {other:?}"),
    }
}

#[test]
fn taint_dangerous_insufficient_integrity() {
    // Work zone record with no taint flags but lowered integrity
    let record = ProvenanceRecord::new(ZoneId::public());
    // Public zone has Untrusted integrity — no taint flags but low integrity
    let result = record.can_drive_operation(SafetyTier::Dangerous);
    // It should hit PublicInput or InsufficientIntegrity
    // Actually public_input flag not set here — just low integrity
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::InsufficientIntegrity { required, actual } => {
            assert_eq!(required, IntegrityLevel::Work);
            assert_eq!(actual, IntegrityLevel::Untrusted);
        }
        other => panic!("expected InsufficientIntegrity, got {other:?}"),
    }
}

#[test]
fn taint_non_critical_flags_allow_risky() {
    // Non-critical taint flags should not block Risky operations
    let mut record = ProvenanceRecord::new(ZoneId::work());
    record.taint_flags.insert(TaintFlag::UserGenerated);
    record.taint_flags.insert(TaintFlag::AiGenerated);
    record.taint_flags.insert(TaintFlag::UnverifiedLink);
    assert!(record.can_drive_operation(SafetyTier::Risky).is_ok());
}

#[test]
fn clean_work_record_drives_dangerous() {
    let record = ProvenanceRecord::new(ZoneId::work());
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_ok());
}

// ═════════════════════════════════════════════════════════════════════════════
// B. Approval Token / Elevation Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn elevation_approval_raises_integrity() {
    let mut record = ProvenanceRecord::public_input();
    // Initially blocks Dangerous
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_err());

    // Elevate integrity from Untrusted to Work
    let result = record.apply_elevation(IntegrityLevel::Work, oid("elevation-token-1"), 1000);
    assert!(result.is_ok());
    assert_eq!(record.integrity_label, IntegrityLevel::Work);

    // Still blocked because PublicInput taint is present
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_err());

    // Remove PublicInput taint
    record.apply_taint_reduction(
        &[TaintFlag::PublicInput],
        oid("sanitizer-receipt-1"),
        vec![],
        1001,
    );
    assert!(!record.taint_flags.contains(TaintFlag::PublicInput));

    // Now should succeed
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_ok());
}

#[test]
fn elevation_requires_higher_level() {
    let mut record = ProvenanceRecord::new(ZoneId::work());
    assert_eq!(record.integrity_label, IntegrityLevel::Work);

    // Attempt to elevate to same level
    let result = record.apply_elevation(IntegrityLevel::Work, oid("token-same"), 1000);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::InvalidElevation { current, requested } => {
            assert_eq!(current, IntegrityLevel::Work);
            assert_eq!(requested, IntegrityLevel::Work);
        }
        other => panic!("expected InvalidElevation, got {other:?}"),
    }

    // Attempt to elevate to lower level
    let result = record.apply_elevation(IntegrityLevel::Community, oid("token-lower"), 1001);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::InvalidElevation { current, requested } => {
            assert_eq!(current, IntegrityLevel::Work);
            assert_eq!(requested, IntegrityLevel::Community);
        }
        other => panic!("expected InvalidElevation, got {other:?}"),
    }
}

#[test]
fn approval_token_validity_window() {
    let token = make_approval_token(
        "tok-1",
        ApprovalScope::Elevation(ElevationScope {
            operation_id: "test.op".to_string(),
            original_provenance_id: oid("prov-1"),
            target_integrity: IntegrityLevel::Work,
        }),
        ZoneId::work(),
        1000, // issued
        2000, // expires
    );

    // Within window
    assert!(token.is_valid(1500));

    // Expired
    assert!(token.is_expired(2000));
    assert!(token.is_expired(3000));
    assert!(!token.is_valid(2000));

    // Not yet valid
    assert!(token.is_not_yet_valid(999));
    assert!(!token.is_valid(999));

    // Edge: exactly at issued_at_ms
    assert!(token.is_valid(1000));
}

#[test]
fn approval_token_not_yet_valid() {
    let token = make_approval_token(
        "tok-future",
        ApprovalScope::Elevation(ElevationScope {
            operation_id: "test.op".to_string(),
            original_provenance_id: oid("prov-future"),
            target_integrity: IntegrityLevel::Private,
        }),
        ZoneId::work(),
        5000,
        10000,
    );

    assert!(token.is_not_yet_valid(4999));
    assert!(!token.is_not_yet_valid(5000));
    assert!(!token.is_not_yet_valid(7500));
}

#[test]
fn elevation_scope_binds_to_operation() {
    let scope = ElevationScope {
        operation_id: "data.delete".to_string(),
        original_provenance_id: oid("prov-x"),
        target_integrity: IntegrityLevel::Private,
    };
    let token = make_approval_token(
        "tok-elev-op",
        ApprovalScope::Elevation(scope),
        ZoneId::work(),
        0,
        u64::MAX,
    );

    match &token.scope {
        ApprovalScope::Elevation(elev) => {
            assert_eq!(elev.operation_id, "data.delete");
            assert_eq!(elev.target_integrity, IntegrityLevel::Private);
        }
        other => panic!("expected Elevation scope, got {other:?}"),
    }
}

#[test]
fn execution_scope_constraints_checked() {
    let scope = ExecutionScope {
        connector_id: "my-connector".to_string(),
        method_pattern: "data.*".to_string(),
        request_object_id: Some(oid("req-123")),
        input_hash: None,
        input_constraints: vec![
            InputConstraint {
                pointer: "/action".to_string(),
                expected: json!("delete"),
            },
            InputConstraint {
                pointer: "/target/id".to_string(),
                expected: json!(42),
            },
        ],
    };
    let token = make_approval_token(
        "tok-exec",
        ApprovalScope::Execution(scope),
        ZoneId::work(),
        0,
        u64::MAX,
    );

    match &token.scope {
        ApprovalScope::Execution(exec) => {
            assert_eq!(exec.connector_id, "my-connector");
            assert_eq!(exec.method_pattern, "data.*");
            assert_eq!(exec.input_constraints.len(), 2);
            assert_eq!(exec.input_constraints[0].pointer, "/action");
            assert_eq!(exec.input_constraints[0].expected, json!("delete"));
            assert_eq!(exec.input_constraints[1].pointer, "/target/id");
            assert_eq!(exec.input_constraints[1].expected, json!(42));
            assert_eq!(exec.request_object_id, Some(oid("req-123")));
        }
        other => panic!("expected Execution scope, got {other:?}"),
    }
}

#[test]
fn elevation_records_label_adjustment() {
    let mut record = ProvenanceRecord::new(ZoneId::public());
    assert!(record.label_adjustments.is_empty());

    let _ = record.apply_elevation(IntegrityLevel::Work, oid("elev-tok"), 42);

    assert_eq!(record.label_adjustments.len(), 1);
    let adj = &record.label_adjustments[0];
    assert_eq!(adj.timestamp_ms, 42);
    assert_eq!(adj.prev_integrity, Some(IntegrityLevel::Untrusted));
    assert_eq!(adj.new_integrity, Some(IntegrityLevel::Work));
    assert!(adj.prev_confidentiality.is_none());
    assert!(adj.new_confidentiality.is_none());
}

// ═════════════════════════════════════════════════════════════════════════════
// C. Taint Reduction / Sanitizer Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn sanitizer_receipt_clears_public_input() {
    let mut record = ProvenanceRecord::public_input();
    assert!(record.taint_flags.contains(TaintFlag::PublicInput));

    record.apply_taint_reduction(
        &[TaintFlag::PublicInput],
        oid("receipt-1"),
        vec![oid("input-a")],
        1000,
    );

    assert!(!record.taint_flags.contains(TaintFlag::PublicInput));
    assert!(record.taint_flags.is_empty());
    assert_eq!(record.taint_reductions.len(), 1);
    assert_eq!(
        record.taint_reductions[0].cleared_flags,
        vec![TaintFlag::PublicInput]
    );
    assert_eq!(
        record.taint_reductions[0].covered_inputs,
        vec![oid("input-a")]
    );
}

#[test]
fn sanitizer_receipt_partial_clear() {
    let mut record = ProvenanceRecord::public_input();
    record.taint_flags.insert(TaintFlag::WebhookInjected);
    record.taint_flags.insert(TaintFlag::AiGenerated);

    // Only clear PublicInput
    record.apply_taint_reduction(
        &[TaintFlag::PublicInput],
        oid("receipt-partial"),
        vec![],
        1000,
    );

    assert!(!record.taint_flags.contains(TaintFlag::PublicInput));
    assert!(record.taint_flags.contains(TaintFlag::WebhookInjected));
    assert!(record.taint_flags.contains(TaintFlag::AiGenerated));
    assert_eq!(record.taint_flags.len(), 2);
}

#[test]
fn sanitizer_receipt_covers_inputs() {
    let receipt = make_sanitizer_receipt(
        "rcpt-cover",
        &[TaintFlag::PublicInput],
        &[TaintFlag::PublicInput],
        &[oid("in-1"), oid("in-2"), oid("in-3")],
    );

    assert!(receipt.covers_input(&oid("in-1")));
    assert!(receipt.covers_input(&oid("in-2")));
    assert!(receipt.covers_input(&oid("in-3")));
    assert!(!receipt.covers_input(&oid("in-4")));
}

#[test]
fn sanitizer_no_op_if_flag_not_present() {
    let mut record = ProvenanceRecord::new(ZoneId::work());
    assert!(record.taint_flags.is_empty());

    record.apply_taint_reduction(
        &[TaintFlag::PublicInput, TaintFlag::PotentiallyMalicious],
        oid("receipt-noop"),
        vec![],
        1000,
    );

    // No reduction entry since nothing was actually cleared
    assert!(record.taint_reductions.is_empty());
    assert!(record.taint_flags.is_empty());
}

#[test]
fn taint_reduction_then_dangerous_allowed() {
    let mut record = ProvenanceRecord::public_input();

    // Initially blocked
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_err());

    // Elevate integrity
    let _ = record.apply_elevation(IntegrityLevel::Work, oid("elev-tok-2"), 1000);

    // Still blocked (PublicInput taint)
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_err());

    // Sanitize
    record.apply_taint_reduction(
        &[TaintFlag::PublicInput],
        oid("receipt-clear"),
        vec![],
        1001,
    );

    // Now allowed
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_ok());
}

#[test]
fn sanitizer_receipt_validity_check() {
    let valid_receipt = make_sanitizer_receipt(
        "valid",
        &[TaintFlag::PublicInput, TaintFlag::WebhookInjected],
        &[TaintFlag::PublicInput], // subset of authorized
        &[],
    );
    assert!(valid_receipt.is_valid());

    let invalid_receipt = SanitizerReceipt {
        receipt_id: "invalid".to_string(),
        timestamp_ms: 1000,
        sanitizer_id: "bad-sanitizer".to_string(),
        sanitizer_zone: ZoneId::work(),
        authorized_flags: vec![TaintFlag::PublicInput],
        covered_inputs: vec![],
        // Cleared a flag not in authorized_flags
        cleared_flags: vec![TaintFlag::PublicInput, TaintFlag::PotentiallyMalicious],
        signature: None,
    };
    assert!(!invalid_receipt.is_valid());
}

#[test]
fn sanitizer_can_clear_flag_check() {
    let receipt = make_sanitizer_receipt(
        "rcpt-auth",
        &[TaintFlag::PublicInput, TaintFlag::AiGenerated],
        &[],
        &[],
    );

    assert!(receipt.can_clear(TaintFlag::PublicInput));
    assert!(receipt.can_clear(TaintFlag::AiGenerated));
    assert!(!receipt.can_clear(TaintFlag::PotentiallyMalicious));
    assert!(!receipt.can_clear(TaintFlag::CrossZoneUnapproved));
}

// ═════════════════════════════════════════════════════════════════════════════
// D. Provenance Merge Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn merge_integrity_is_min() {
    let r_work = ProvenanceRecord::new(ZoneId::work());
    let r_private = ProvenanceRecord::new(ZoneId::private());

    let merged = ProvenanceRecord::merge(&[&r_work, &r_private], ZoneId::work());
    // MIN(Work=2, Private=3) = Work
    assert_eq!(merged.integrity_label, IntegrityLevel::Work);
}

#[test]
fn merge_confidentiality_is_max() {
    let r_public = ProvenanceRecord::new(ZoneId::public());
    let r_private = ProvenanceRecord::new(ZoneId::private());

    let merged = ProvenanceRecord::merge(&[&r_public, &r_private], ZoneId::work());
    // MAX(Public=0, Private=3) = Private
    assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Private);
}

#[test]
fn merge_taint_is_union() {
    let mut r1 = ProvenanceRecord::new(ZoneId::work());
    r1.taint_flags.insert(TaintFlag::UserGenerated);
    r1.taint_flags.insert(TaintFlag::AiGenerated);

    let mut r2 = ProvenanceRecord::new(ZoneId::work());
    r2.taint_flags.insert(TaintFlag::WebhookInjected);
    r2.taint_flags.insert(TaintFlag::AiGenerated); // overlap

    let merged = ProvenanceRecord::merge(&[&r1, &r2], ZoneId::work());
    assert!(merged.taint_flags.contains(TaintFlag::UserGenerated));
    assert!(merged.taint_flags.contains(TaintFlag::AiGenerated));
    assert!(merged.taint_flags.contains(TaintFlag::WebhookInjected));
    assert_eq!(merged.taint_flags.len(), 3);
}

#[test]
fn merge_empty_records_returns_clean() {
    let merged = ProvenanceRecord::merge(&[], ZoneId::work());
    assert_eq!(merged.integrity_label, IntegrityLevel::Work);
    assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Work);
    assert!(merged.taint_flags.is_empty());
    assert!(merged.label_adjustments.is_empty());
    assert!(merged.taint_reductions.is_empty());
    assert!(merged.zone_crossings.is_empty());
    assert!(merged.input_sources.is_empty());
}

#[test]
fn merge_three_records_integrity_min_of_all() {
    let r_owner = ProvenanceRecord::new(ZoneId::owner());
    let r_work = ProvenanceRecord::new(ZoneId::work());
    let r_pub = ProvenanceRecord::new(ZoneId::public());

    let merged = ProvenanceRecord::merge(&[&r_owner, &r_work, &r_pub], ZoneId::work());
    // MIN(Owner=4, Work=2, Untrusted=0) = Untrusted
    assert_eq!(merged.integrity_label, IntegrityLevel::Untrusted);
    // MAX(Owner=4, Work=2, Public=0) = Owner
    assert_eq!(merged.confidentiality_label, ConfidentialityLevel::Owner);
}

#[test]
fn merge_preserves_input_sources() {
    let mut r1 = ProvenanceRecord::new(ZoneId::work());
    r1.input_sources.push(oid("src-a"));
    r1.input_sources.push(oid("src-b"));

    let mut r2 = ProvenanceRecord::new(ZoneId::work());
    r2.input_sources.push(oid("src-c"));

    let merged = ProvenanceRecord::merge(&[&r1, &r2], ZoneId::work());
    assert_eq!(merged.input_sources.len(), 3);
    assert!(merged.input_sources.contains(&oid("src-a")));
    assert!(merged.input_sources.contains(&oid("src-b")));
    assert!(merged.input_sources.contains(&oid("src-c")));
}

#[test]
fn merge_uses_first_record_origin() {
    let r1 = ProvenanceRecord::new(ZoneId::private());
    let r2 = ProvenanceRecord::new(ZoneId::work());

    let merged = ProvenanceRecord::merge(&[&r1, &r2], ZoneId::public());
    assert_eq!(merged.origin_zone, ZoneId::private());
    assert_eq!(merged.current_zone, ZoneId::public());
}

// ═════════════════════════════════════════════════════════════════════════════
// E. Information Flow / Zone Crossing Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn flow_integrity_down_allowed() {
    // Owner → Private: integrity flows DOWN freely (Owner>Private), confidentiality also OK
    // (Owner conf = Owner, Private conf = Private, target >= current? Private < Owner → NO)
    // Actually for a pure integrity-down test, use same-confidentiality zones.
    // Work → Community: integrity Work>Community (OK), conf Work>Community (needs declassification)
    // To test pure integrity-down: use a record with Public confidentiality, high integrity
    let mut record = ProvenanceRecord::new(ZoneId::work());
    // Lower confidentiality to Public so it doesn't need declassification
    record.confidentiality_label = ConfidentialityLevel::Public;
    assert_eq!(
        record.can_flow_to(&ZoneId::public()),
        FlowCheckResult::Allowed
    );
}

#[test]
fn flow_integrity_up_requires_elevation() {
    // Public → Work: integrity needs to go UP, requires elevation
    let record = ProvenanceRecord::new(ZoneId::public());
    assert_eq!(
        record.can_flow_to(&ZoneId::work()),
        FlowCheckResult::RequiresElevation
    );
}

#[test]
fn flow_confidentiality_up_allowed() {
    // Public → Private: confidentiality flows UP freely
    let record = ProvenanceRecord::new(ZoneId::public());
    // For public→private: integrity check: target_integrity(Private=3) <= current(Untrusted=0) → NO
    // confidentiality check: target_conf(Private=3) >= current_conf(Public=0) → YES
    // So it requires elevation (for integrity), not declassification
    assert_eq!(
        record.can_flow_to(&ZoneId::private()),
        FlowCheckResult::RequiresElevation
    );
}

#[test]
fn flow_same_zone_allowed() {
    let record = ProvenanceRecord::new(ZoneId::work());
    assert_eq!(
        record.can_flow_to(&ZoneId::work()),
        FlowCheckResult::Allowed
    );
}

#[test]
fn flow_confidentiality_down_requires_declassification() {
    // Private → Public: confidentiality needs to go DOWN, requires declassification
    let record = ProvenanceRecord::new(ZoneId::private());
    // integrity check: target_integrity(Untrusted=0) <= current(Private=3) → YES
    // confidentiality check: target_conf(Public=0) >= current_conf(Private=3) → NO
    assert_eq!(
        record.can_flow_to(&ZoneId::public()),
        FlowCheckResult::RequiresDeclassification
    );
}

#[test]
fn flow_requires_both_elevation_and_declassification() {
    // Construct a scenario: low integrity, high confidentiality
    // Try to flow to high integrity, low confidentiality
    let mut record = ProvenanceRecord::new(ZoneId::public());
    // Manually raise confidentiality to Private (simulating previous zone crossing)
    record.confidentiality_label = ConfidentialityLevel::Private;
    // integrity=Untrusted, confidentiality=Private

    // Flow to work zone: requires integrity UP (elevation) AND confidentiality DOWN (declassification)
    // target_integrity(Work=2) <= Untrusted(0)? NO → needs elevation
    // target_conf(Work=2) >= Private(3)? NO → needs declassification
    assert_eq!(
        record.can_flow_to(&ZoneId::work()),
        FlowCheckResult::RequiresBoth
    );
}

#[test]
fn zone_crossing_unapproved_adds_taint() {
    let mut record = ProvenanceRecord::new(ZoneId::work());
    assert!(!record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));

    record.record_zone_crossing(
        ZoneId::public(),
        false, // unapproved
        None,
        1000,
    );

    assert!(record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
    assert_eq!(record.current_zone, ZoneId::public());
    assert_eq!(record.zone_crossings.len(), 1);
    assert!(!record.zone_crossings[0].approved);
}

#[test]
fn zone_crossing_approved_no_taint() {
    let mut record = ProvenanceRecord::new(ZoneId::work());

    record.record_zone_crossing(
        ZoneId::public(),
        true, // approved
        Some(oid("approval-tok")),
        1000,
    );

    assert!(!record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
    assert_eq!(record.current_zone, ZoneId::public());
    assert_eq!(record.zone_crossings.len(), 1);
    assert!(record.zone_crossings[0].approved);
    assert_eq!(
        record.zone_crossings[0].approval_token_id,
        Some(oid("approval-tok"))
    );
}

#[test]
fn declassification_lowers_confidentiality() {
    let mut record = ProvenanceRecord::new(ZoneId::private());
    assert_eq!(record.confidentiality_label, ConfidentialityLevel::Private);

    let result =
        record.apply_declassification(ConfidentialityLevel::Work, oid("declass-tok"), 2000);
    assert!(result.is_ok());
    assert_eq!(record.confidentiality_label, ConfidentialityLevel::Work);
    assert_eq!(record.label_adjustments.len(), 1);
    assert_eq!(
        record.label_adjustments[0].prev_confidentiality,
        Some(ConfidentialityLevel::Private)
    );
    assert_eq!(
        record.label_adjustments[0].new_confidentiality,
        Some(ConfidentialityLevel::Work)
    );
}

#[test]
fn declassification_requires_lower_level() {
    let mut record = ProvenanceRecord::new(ZoneId::work());
    assert_eq!(record.confidentiality_label, ConfidentialityLevel::Work);

    // Attempt to "declassify" to same level
    let result =
        record.apply_declassification(ConfidentialityLevel::Work, oid("declass-same"), 1000);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::InvalidDeclassification { current, requested } => {
            assert_eq!(current, ConfidentialityLevel::Work);
            assert_eq!(requested, ConfidentialityLevel::Work);
        }
        other => panic!("expected InvalidDeclassification, got {other:?}"),
    }

    // Attempt to "declassify" upward
    let result =
        record.apply_declassification(ConfidentialityLevel::Private, oid("declass-up"), 1001);
    assert!(result.is_err());
    match result.unwrap_err() {
        ProvenanceViolation::InvalidDeclassification { current, requested } => {
            assert_eq!(current, ConfidentialityLevel::Work);
            assert_eq!(requested, ConfidentialityLevel::Private);
        }
        other => panic!("expected InvalidDeclassification, got {other:?}"),
    }
}

#[test]
fn multiple_zone_crossings_tracked() {
    let mut record = ProvenanceRecord::new(ZoneId::owner());

    record.record_zone_crossing(ZoneId::private(), true, Some(oid("t1")), 100);
    record.record_zone_crossing(ZoneId::work(), true, Some(oid("t2")), 200);
    record.record_zone_crossing(ZoneId::public(), false, None, 300);

    assert_eq!(record.zone_crossings.len(), 3);
    assert_eq!(record.current_zone, ZoneId::public());
    // Last crossing was unapproved
    assert!(record.taint_flags.contains(TaintFlag::CrossZoneUnapproved));
}

// ═════════════════════════════════════════════════════════════════════════════
// F. E2E Flow Tests (with structured logging)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn taint_approval_full_flow_logged() {
    let mut logger = E2eLogger::new();

    // Phase 1: Setup — create tainted input
    let mut record = ProvenanceRecord::public_input();
    logger.push(log_entry(
        "taint_approval_full_flow",
        "setup",
        "pass",
        1,
        0,
        json!({
            "step": "create_tainted_input",
            "origin_zone": "public",
            "integrity": "untrusted",
            "has_public_input_taint": true,
        }),
    ));

    // Phase 2: Execute — attempt Dangerous operation (should fail)
    let deny_result = record.can_drive_operation(SafetyTier::Dangerous);
    assert!(deny_result.is_err());
    logger.push(log_entry(
        "taint_approval_full_flow",
        "execute",
        "pass",
        1,
        0,
        json!({
            "step": "deny_dangerous_with_taint",
            "operation_tier": "dangerous",
            "denied": true,
            "violation": "PublicInputForDangerousOperation",
        }),
    ));

    // Phase 3: Execute — elevate integrity
    let elev = record.apply_elevation(IntegrityLevel::Work, oid("full-flow-elev"), 5000);
    assert!(elev.is_ok());
    logger.push(log_entry(
        "taint_approval_full_flow",
        "execute",
        "pass",
        1,
        0,
        json!({
            "step": "elevate_integrity",
            "from": "untrusted",
            "to": "work",
        }),
    ));

    // Phase 4: Execute — sanitize taint
    record.apply_taint_reduction(
        &[TaintFlag::PublicInput],
        oid("full-flow-sanitize"),
        vec![oid("input-data")],
        5001,
    );
    logger.push(log_entry(
        "taint_approval_full_flow",
        "execute",
        "pass",
        1,
        0,
        json!({
            "step": "sanitize_taint",
            "cleared_flags": ["PUBLIC_INPUT"],
        }),
    ));

    // Phase 5: Verify — Dangerous operation now allowed
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_ok());
    logger.push(log_entry(
        "taint_approval_full_flow",
        "verify",
        "pass",
        1,
        0,
        json!({
            "step": "allow_dangerous_after_approval",
            "allowed": true,
        }),
    ));

    // Validate all log entries
    let entries = logger.entries();
    assert_eq!(entries.len(), 5);
    for entry in entries {
        assert!(
            entry.validate().is_ok(),
            "log entry failed validation: {entry:?}"
        );
    }
}

#[test]
fn sanitizer_flow_logged() {
    let mut logger = E2eLogger::new();

    // Setup: multi-tainted record
    let mut record = ProvenanceRecord::new(ZoneId::work());
    record.taint_flags.insert(TaintFlag::WebhookInjected);
    record.taint_flags.insert(TaintFlag::UserGenerated);
    logger.push(log_entry(
        "sanitizer_flow",
        "setup",
        "pass",
        1,
        0,
        json!({
            "step": "create_multi_tainted",
            "taint_count": 2,
        }),
    ));

    // Execute: sanitize WebhookInjected only
    record.apply_taint_reduction(
        &[TaintFlag::WebhookInjected],
        oid("san-receipt-1"),
        vec![oid("webhook-payload")],
        100,
    );
    assert!(!record.taint_flags.contains(TaintFlag::WebhookInjected));
    assert!(record.taint_flags.contains(TaintFlag::UserGenerated));
    logger.push(log_entry(
        "sanitizer_flow",
        "execute",
        "pass",
        2,
        0,
        json!({
            "step": "partial_sanitize",
            "cleared": ["WEBHOOK_INJECTED"],
            "remaining": ["USER_GENERATED"],
        }),
    ));

    // Execute: sanitize remaining
    record.apply_taint_reduction(
        &[TaintFlag::UserGenerated],
        oid("san-receipt-2"),
        vec![],
        200,
    );
    assert!(record.taint_flags.is_empty());
    logger.push(log_entry(
        "sanitizer_flow",
        "execute",
        "pass",
        1,
        0,
        json!({
            "step": "full_sanitize",
            "taint_count": 0,
        }),
    ));

    // Verify: Dangerous operation allowed (work zone, no taint)
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_ok());
    logger.push(log_entry(
        "sanitizer_flow",
        "verify",
        "pass",
        1,
        0,
        json!({
            "step": "dangerous_allowed_after_sanitize",
            "allowed": true,
        }),
    ));

    let entries = logger.entries();
    assert_eq!(entries.len(), 4);
    for entry in entries {
        assert!(entry.validate().is_ok());
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// G. Additional Edge Case Tests
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn taint_flags_from_flag() {
    let flags = TaintFlags::from_flag(TaintFlag::AiGenerated);
    assert!(flags.contains(TaintFlag::AiGenerated));
    assert_eq!(flags.len(), 1);
    assert!(!flags.is_empty());
}

#[test]
fn taint_flags_merge_two_sets() {
    let mut a = TaintFlags::new();
    a.insert(TaintFlag::PublicInput);
    a.insert(TaintFlag::AiGenerated);

    let mut b = TaintFlags::new();
    b.insert(TaintFlag::WebhookInjected);
    b.insert(TaintFlag::AiGenerated);

    let merged = a.merge(&b);
    assert_eq!(merged.len(), 3);
    assert!(merged.contains(TaintFlag::PublicInput));
    assert!(merged.contains(TaintFlag::AiGenerated));
    assert!(merged.contains(TaintFlag::WebhookInjected));
}

#[test]
fn taint_flags_is_critical_classification() {
    assert!(TaintFlag::PublicInput.is_critical());
    assert!(TaintFlag::PotentiallyMalicious.is_critical());
    assert!(TaintFlag::CrossZoneUnapproved.is_critical());

    assert!(!TaintFlag::UnverifiedLink.is_critical());
    assert!(!TaintFlag::UntrustedTransform.is_critical());
    assert!(!TaintFlag::WebhookInjected.is_critical());
    assert!(!TaintFlag::UserGenerated.is_critical());
    assert!(!TaintFlag::AiGenerated.is_critical());
}

#[test]
fn taint_flags_has_critical_check() {
    let mut flags = TaintFlags::new();
    assert!(!flags.has_critical());

    flags.insert(TaintFlag::AiGenerated);
    assert!(!flags.has_critical());

    flags.insert(TaintFlag::PublicInput);
    assert!(flags.has_critical());
}

#[test]
fn taint_flags_from_iter() {
    let flags: TaintFlags = vec![
        TaintFlag::PublicInput,
        TaintFlag::AiGenerated,
        TaintFlag::PublicInput, // duplicate
    ]
    .into_iter()
    .collect();
    assert_eq!(flags.len(), 2); // set semantics
}

#[test]
fn integrity_level_from_zone_mapping() {
    assert_eq!(
        IntegrityLevel::from_zone(&ZoneId::owner()),
        IntegrityLevel::Owner
    );
    assert_eq!(
        IntegrityLevel::from_zone(&ZoneId::private()),
        IntegrityLevel::Private
    );
    assert_eq!(
        IntegrityLevel::from_zone(&ZoneId::work()),
        IntegrityLevel::Work
    );
    assert_eq!(
        IntegrityLevel::from_zone(&ZoneId::public()),
        IntegrityLevel::Untrusted
    );
}

#[test]
fn confidentiality_level_from_zone_mapping() {
    assert_eq!(
        ConfidentialityLevel::from_zone(&ZoneId::owner()),
        ConfidentialityLevel::Owner
    );
    assert_eq!(
        ConfidentialityLevel::from_zone(&ZoneId::private()),
        ConfidentialityLevel::Private
    );
    assert_eq!(
        ConfidentialityLevel::from_zone(&ZoneId::work()),
        ConfidentialityLevel::Work
    );
    assert_eq!(
        ConfidentialityLevel::from_zone(&ZoneId::public()),
        ConfidentialityLevel::Public
    );
}

#[test]
fn integrity_level_ordering_full() {
    assert!(IntegrityLevel::Untrusted < IntegrityLevel::Community);
    assert!(IntegrityLevel::Community < IntegrityLevel::Work);
    assert!(IntegrityLevel::Work < IntegrityLevel::Private);
    assert!(IntegrityLevel::Private < IntegrityLevel::Owner);
    assert_eq!(IntegrityLevel::Untrusted.as_u8(), 0);
    assert_eq!(IntegrityLevel::Owner.as_u8(), 4);
}

#[test]
fn confidentiality_level_ordering_full() {
    assert!(ConfidentialityLevel::Public < ConfidentialityLevel::Community);
    assert!(ConfidentialityLevel::Community < ConfidentialityLevel::Work);
    assert!(ConfidentialityLevel::Work < ConfidentialityLevel::Private);
    assert!(ConfidentialityLevel::Private < ConfidentialityLevel::Owner);
    assert_eq!(ConfidentialityLevel::Public.as_u8(), 0);
    assert_eq!(ConfidentialityLevel::Owner.as_u8(), 4);
}

#[test]
fn taint_decision_serde_roundtrip() {
    let decision = TaintDecision {
        allowed: false,
        reason_code: "public_input_dangerous".to_string(),
        safety_tier: SafetyTier::Dangerous,
        contributing_flags: vec![TaintFlag::PublicInput],
        approval_token_id: Some(oid("tok-1")),
        sanitizer_receipt_id: None,
    };

    let json_str = serde_json::to_string(&decision).expect("serialize");
    let restored: TaintDecision = serde_json::from_str(&json_str).expect("deserialize");
    assert!(!restored.allowed);
    assert_eq!(restored.reason_code, "public_input_dangerous");
    assert_eq!(restored.contributing_flags, vec![TaintFlag::PublicInput]);
    assert!(restored.approval_token_id.is_some());
    assert!(restored.sanitizer_receipt_id.is_none());
}

#[test]
fn approval_token_serde_roundtrip() {
    let token = make_approval_token(
        "tok-serde",
        ApprovalScope::Elevation(ElevationScope {
            operation_id: "test.op".to_string(),
            original_provenance_id: oid("prov-serde"),
            target_integrity: IntegrityLevel::Private,
        }),
        ZoneId::work(),
        100,
        200,
    );

    let json_str = serde_json::to_string(&token).expect("serialize");
    let restored: ApprovalToken = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(restored.token_id, "tok-serde");
    assert_eq!(restored.issued_at_ms, 100);
    assert_eq!(restored.expires_at_ms, 200);
    assert_eq!(restored.issuer, "test-issuer");
    assert!(restored.is_valid(150));
}

#[test]
fn sanitizer_receipt_serde_roundtrip() {
    let receipt = make_sanitizer_receipt(
        "rcpt-serde",
        &[TaintFlag::PublicInput, TaintFlag::AiGenerated],
        &[TaintFlag::PublicInput],
        &[oid("in-1")],
    );

    let json_str = serde_json::to_string(&receipt).expect("serialize");
    let restored: SanitizerReceipt = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(restored.receipt_id, "rcpt-serde");
    assert!(restored.is_valid());
    assert!(restored.covers_input(&oid("in-1")));
    assert!(restored.can_clear(TaintFlag::PublicInput));
}

#[test]
fn provenance_record_serde_roundtrip() {
    let mut record = ProvenanceRecord::public_input();
    record.taint_flags.insert(TaintFlag::AiGenerated);
    record.input_sources.push(oid("src-1"));
    let _ = record.apply_elevation(IntegrityLevel::Work, oid("e-tok"), 100);
    record.apply_taint_reduction(
        &[TaintFlag::PublicInput],
        oid("san-r"),
        vec![oid("src-1")],
        200,
    );

    let json_str = serde_json::to_string(&record).expect("serialize");
    let restored: ProvenanceRecord = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(restored.integrity_label, IntegrityLevel::Work);
    assert!(!restored.taint_flags.contains(TaintFlag::PublicInput));
    assert!(restored.taint_flags.contains(TaintFlag::AiGenerated));
    assert_eq!(restored.label_adjustments.len(), 1);
    assert_eq!(restored.taint_reductions.len(), 1);
}

#[test]
fn declassification_scope_fields() {
    let scope = DeclassificationScope {
        from_zone: ZoneId::private(),
        to_zone: ZoneId::work(),
        object_ids: vec![oid("obj-1"), oid("obj-2")],
        target_confidentiality: ConfidentialityLevel::Work,
    };
    let token = make_approval_token(
        "tok-declass",
        ApprovalScope::Declassification(scope),
        ZoneId::private(),
        0,
        u64::MAX,
    );

    match &token.scope {
        ApprovalScope::Declassification(declass) => {
            assert_eq!(declass.from_zone, ZoneId::private());
            assert_eq!(declass.to_zone, ZoneId::work());
            assert_eq!(declass.object_ids.len(), 2);
            assert_eq!(declass.target_confidentiality, ConfidentialityLevel::Work);
        }
        other => panic!("expected Declassification scope, got {other:?}"),
    }
}

#[test]
fn full_cycle_taint_elevate_sanitize_cross_declassify() {
    // Complex multi-step flow:
    // 1. Start with public input (tainted, low integrity, low confidentiality)
    // 2. Elevate integrity to Work
    // 3. Sanitize PublicInput taint
    // 4. Cross zone to Private (approved)
    // 5. Declassify from Private confidentiality to Work
    let mut record = ProvenanceRecord::public_input();

    // Step 1: verify initial state
    assert_eq!(record.integrity_label, IntegrityLevel::Untrusted);
    assert_eq!(record.confidentiality_label, ConfidentialityLevel::Public);
    assert!(record.taint_flags.contains(TaintFlag::PublicInput));
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_err());

    // Step 2: elevate
    assert!(
        record
            .apply_elevation(IntegrityLevel::Work, oid("cycle-elev"), 100)
            .is_ok()
    );
    assert_eq!(record.integrity_label, IntegrityLevel::Work);

    // Step 3: sanitize
    record.apply_taint_reduction(&[TaintFlag::PublicInput], oid("cycle-san"), vec![], 200);
    assert!(!record.taint_flags.contains(TaintFlag::PublicInput));
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_ok());

    // Step 4: cross to private zone (approved)
    record.record_zone_crossing(ZoneId::private(), true, Some(oid("cross-tok")), 300);
    assert_eq!(record.current_zone, ZoneId::private());
    // Confidentiality does NOT auto-change from crossing; only taint and current_zone change
    assert_eq!(record.confidentiality_label, ConfidentialityLevel::Public);

    // Step 5: manually set confidentiality high (simulating data handling in private zone)
    record.confidentiality_label = ConfidentialityLevel::Private;

    // Now declassify so it can flow back to work
    assert!(
        record
            .apply_declassification(ConfidentialityLevel::Work, oid("cycle-declass"), 400)
            .is_ok()
    );
    assert_eq!(record.confidentiality_label, ConfidentialityLevel::Work);
    assert_eq!(
        record.can_flow_to(&ZoneId::work()),
        FlowCheckResult::Allowed
    );
}

#[test]
fn taint_flag_display() {
    assert_eq!(format!("{}", TaintFlag::PublicInput), "PUBLIC_INPUT");
    assert_eq!(
        format!("{}", TaintFlag::PotentiallyMalicious),
        "POTENTIALLY_MALICIOUS"
    );
    assert_eq!(
        format!("{}", TaintFlag::CrossZoneUnapproved),
        "CROSS_ZONE_UNAPPROVED"
    );
    assert_eq!(format!("{}", TaintFlag::AiGenerated), "AI_GENERATED");
    assert_eq!(
        format!("{}", TaintFlag::WebhookInjected),
        "WEBHOOK_INJECTED"
    );
    assert_eq!(format!("{}", TaintFlag::UserGenerated), "USER_GENERATED");
    assert_eq!(format!("{}", TaintFlag::UnverifiedLink), "UNVERIFIED_LINK");
    assert_eq!(
        format!("{}", TaintFlag::UntrustedTransform),
        "UNTRUSTED_TRANSFORM"
    );
}

#[test]
fn integrity_level_display() {
    assert_eq!(format!("{}", IntegrityLevel::Untrusted), "untrusted");
    assert_eq!(format!("{}", IntegrityLevel::Community), "community");
    assert_eq!(format!("{}", IntegrityLevel::Work), "work");
    assert_eq!(format!("{}", IntegrityLevel::Private), "private");
    assert_eq!(format!("{}", IntegrityLevel::Owner), "owner");
}

#[test]
fn confidentiality_level_display() {
    assert_eq!(format!("{}", ConfidentialityLevel::Public), "public");
    assert_eq!(format!("{}", ConfidentialityLevel::Community), "community");
    assert_eq!(format!("{}", ConfidentialityLevel::Work), "work");
    assert_eq!(format!("{}", ConfidentialityLevel::Private), "private");
    assert_eq!(format!("{}", ConfidentialityLevel::Owner), "owner");
}

#[test]
fn provenance_violation_display() {
    let v1 = ProvenanceViolation::PublicInputForDangerousOperation;
    assert!(format!("{v1}").contains("public input"));

    let v2 = ProvenanceViolation::MaliciousInputDetected;
    assert!(format!("{v2}").contains("malicious"));

    let v3 = ProvenanceViolation::InvalidElevation {
        current: IntegrityLevel::Work,
        requested: IntegrityLevel::Community,
    };
    assert!(format!("{v3}").contains("elevation"));

    let v4 = ProvenanceViolation::InvalidDeclassification {
        current: ConfidentialityLevel::Work,
        requested: ConfidentialityLevel::Private,
    };
    assert!(format!("{v4}").contains("declassification"));

    let v5 = ProvenanceViolation::InsufficientIntegrity {
        required: IntegrityLevel::Work,
        actual: IntegrityLevel::Untrusted,
    };
    assert!(format!("{v5}").contains("integrity"));
}

#[test]
fn elevation_chain_incremental() {
    // Elevate step by step: Untrusted -> Community -> Work -> Private -> Owner
    let mut record = ProvenanceRecord::new(ZoneId::public());
    assert_eq!(record.integrity_label, IntegrityLevel::Untrusted);

    assert!(
        record
            .apply_elevation(IntegrityLevel::Community, oid("e1"), 10)
            .is_ok()
    );
    assert!(
        record
            .apply_elevation(IntegrityLevel::Work, oid("e2"), 20)
            .is_ok()
    );
    assert!(
        record
            .apply_elevation(IntegrityLevel::Private, oid("e3"), 30)
            .is_ok()
    );
    assert!(
        record
            .apply_elevation(IntegrityLevel::Owner, oid("e4"), 40)
            .is_ok()
    );

    assert_eq!(record.integrity_label, IntegrityLevel::Owner);
    assert_eq!(record.label_adjustments.len(), 4);
}

#[test]
fn declassification_chain_incremental() {
    // Declassify step by step: Owner -> Private -> Work -> Community -> Public
    let mut record = ProvenanceRecord::new(ZoneId::owner());
    assert_eq!(record.confidentiality_label, ConfidentialityLevel::Owner);

    assert!(
        record
            .apply_declassification(ConfidentialityLevel::Private, oid("d1"), 10)
            .is_ok()
    );
    assert!(
        record
            .apply_declassification(ConfidentialityLevel::Work, oid("d2"), 20)
            .is_ok()
    );
    assert!(
        record
            .apply_declassification(ConfidentialityLevel::Community, oid("d3"), 30)
            .is_ok()
    );
    assert!(
        record
            .apply_declassification(ConfidentialityLevel::Public, oid("d4"), 40)
            .is_ok()
    );

    assert_eq!(record.confidentiality_label, ConfidentialityLevel::Public);
    assert_eq!(record.label_adjustments.len(), 4);
}

#[test]
fn community_zone_integrity_level() {
    let record = ProvenanceRecord::new(ZoneId::community());
    assert_eq!(record.integrity_label, IntegrityLevel::Community);
    assert_eq!(
        record.confidentiality_label,
        ConfidentialityLevel::Community
    );
}

#[test]
fn taint_reduction_records_timestamp_and_receipt() {
    let mut record = ProvenanceRecord::public_input();
    record.taint_flags.insert(TaintFlag::AiGenerated);

    record.apply_taint_reduction(
        &[TaintFlag::PublicInput, TaintFlag::AiGenerated],
        oid("ts-receipt"),
        vec![oid("covered-a"), oid("covered-b")],
        9999,
    );

    assert_eq!(record.taint_reductions.len(), 1);
    let reduction = &record.taint_reductions[0];
    assert_eq!(reduction.timestamp_ms, 9999);
    assert_eq!(reduction.sanitizer_receipt_id, oid("ts-receipt"));
    assert_eq!(reduction.covered_inputs.len(), 2);
    assert_eq!(reduction.cleared_flags.len(), 2);
    assert!(reduction.cleared_flags.contains(&TaintFlag::PublicInput));
    assert!(reduction.cleared_flags.contains(&TaintFlag::AiGenerated));
}

#[test]
fn forbidden_tier_blocks_like_dangerous() {
    // Forbidden operations should also reject tainted input
    let record = ProvenanceRecord::public_input();
    let result = record.can_drive_operation(SafetyTier::Forbidden);
    assert!(result.is_err());
}

#[test]
fn critical_tier_blocks_like_dangerous() {
    // Critical operations also reject tainted input
    let record = ProvenanceRecord::public_input();
    let result = record.can_drive_operation(SafetyTier::Critical);
    assert!(result.is_err());
}

#[test]
fn owner_zone_record_drives_all_tiers() {
    let record = ProvenanceRecord::new(ZoneId::owner());
    assert!(record.can_drive_operation(SafetyTier::Safe).is_ok());
    assert!(record.can_drive_operation(SafetyTier::Risky).is_ok());
    assert!(record.can_drive_operation(SafetyTier::Dangerous).is_ok());
    assert!(record.can_drive_operation(SafetyTier::Critical).is_ok());
    // Forbidden operations are NEVER allowed, regardless of provenance
    assert!(record.can_drive_operation(SafetyTier::Forbidden).is_err());
}
