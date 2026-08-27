use fcp_core::{
    ApprovalScope, ApprovalToken, ConfidentialityLevel, DeclassificationError,
    DeclassificationScope, ObjectId, ProvenanceRecord, ZoneId, declassify,
};

fn object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn approved_declassification_token(
    object_id: ObjectId,
    signature: Option<Vec<u8>>,
) -> ApprovalToken {
    ApprovalToken::approved(
        "approval-declassify-1",
        1_000,
        2_000,
        "node:authority",
        ApprovalScope::Declassification(DeclassificationScope {
            from_zone: ZoneId::private(),
            to_zone: ZoneId::work(),
            object_ids: vec![object_id],
            target_confidentiality: ConfidentialityLevel::Work,
        }),
        ZoneId::private(),
        signature,
    )
}

#[test]
fn test_declassify_approved_compiles() {
    let object_id = object_id("secret-object");
    let approval = approved_declassification_token(object_id, Some(vec![0xA5; 64]));
    let mut provenance = ProvenanceRecord::new(ZoneId::private());

    let event = declassify(
        &approval,
        &mut provenance,
        object_id,
        ConfidentialityLevel::Work,
        1_500,
    )
    .expect("approved declassification should succeed");

    assert!(event.accepted);
    assert_eq!(event.reason_code, "Accepted");
    assert_eq!(event.src_label, ConfidentialityLevel::Private);
    assert_eq!(event.dst_label, ConfidentialityLevel::Work);
    assert_eq!(provenance.confidentiality_label, ConfidentialityLevel::Work);
    assert_eq!(provenance.label_adjustments.len(), 1);
}

#[test]
fn test_invalid_approver_emits_audit_with_reject_marker() {
    let object_id = object_id("secret-object");
    let approval = approved_declassification_token(object_id, None);
    let mut provenance = ProvenanceRecord::new(ZoneId::private());

    let error = declassify(
        &approval,
        &mut provenance,
        object_id,
        ConfidentialityLevel::Work,
        1_500,
    )
    .expect_err("unsigned approval must be rejected");

    assert!(matches!(
        error,
        DeclassificationError::InvalidApprover { .. }
    ));
    let event = error.event();
    assert!(!event.accepted);
    assert_eq!(event.reason_code, "InvalidApprover");
    assert_eq!(event.src_label, ConfidentialityLevel::Private);
    assert_eq!(event.dst_label, ConfidentialityLevel::Work);
    assert_eq!(
        provenance.confidentiality_label,
        ConfidentialityLevel::Private
    );
    assert_eq!(
        provenance.label_adjustments,
        [] as [fcp_core::LabelAdjustment; 0]
    );
}

#[test]
fn trybuild_runs() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/typestate_compile_fail/pending_to_declassify.rs");
    t.compile_fail("tests/typestate_compile_fail/pending_to_delegate.rs");
}
