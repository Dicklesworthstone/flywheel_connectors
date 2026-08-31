//! br-crr6l — Cross-zone enforcement conformance against the real
//! `fcp_core::policy::PolicyEngine::evaluate_invoke` path.
//!
//! This is the replacement for the shadow `fcp_conformance::interop::
//! cross_zone` module retired in bead flywheel_connectors-1vcqs. The
//! shadow model defined local `CrossZoneRequest` / `ApprovalToken` /
//! `ReasonCode` types and its own `evaluate_cross_zone_access` impl,
//! so the conformance lane passed even when real enforcement
//! regressed. Every test here binds to the crate-public FCP types
//! (`PolicyEngine`, `PolicyDecisionInput`, `ApprovalToken`,
//! `ProvenanceRecord`, `DecisionReasonCode`) so divergence between
//! spec and runtime is caught.
//!
//! Each test name is tagged with the expected `DecisionReasonCode`
//! from the cross-zone surface.
//!
//! Scope: the following `DecisionReasonCode` variants exist in the
//! policy surface but are NOT emitted from `evaluate_invoke` for the
//! cross-zone flow — they are filter-outputs applied inside
//! `apply_declassification` / `apply_elevation` that silently drop
//! the token and fall through to the generic "missing approval"
//! code:
//!
//!   `DecisionReasonCode::ApprovalExpired`
//!   `DecisionReasonCode::ApprovalZoneMismatch`
//!
//! An expired or zone-mismatched token is not exposed with a distinct
//! code from `evaluate_invoke` itself — it surfaces as
//! `ApprovalMissingDeclassification` after being filtered out. The
//! tests below pin that exact fall-through so a future change that
//! wants to surface the distinct codes can't silently flip the
//! observable reason without updating these regressions.

use fcp_cbor::SchemaId;
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityId, ConfidentialityLevel, ConnectorId, Decision,
    DecisionReasonCode, DecisionReceiptPolicy, DeclassificationScope, ElevationScope,
    IntegrityLevel, ObjectHeader, ObjectId, OperationId, PolicyDecisionInput, PolicyEngine,
    PrincipalId, Provenance, ProvenanceRecord, SafetyTier, SanitizerReceipt, TransportMode, ZoneId,
    ZonePolicyObject, ZoneTransportPolicy,
};

const NOW_MS: u64 = 1_700_000_000_000;
const TOKEN_TTL_MS: u64 = 60_000;

fn test_header(zone_id: ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.core", "CrossZoneTest", semver::Version::new(1, 0, 0)),
        zone_id: zone_id.clone(),
        created_at: NOW_MS,
        provenance: Provenance::new(zone_id),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

fn minimal_zone_policy(zone: ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: test_header(zone.clone()),
        zone_id: zone,
        principal_allow: Vec::new(),
        principal_deny: Vec::new(),
        connector_allow: Vec::new(),
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        },
        decision_receipts: DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn engine_for(zone: ZoneId) -> PolicyEngine {
    PolicyEngine {
        zone_policy: minimal_zone_policy(zone),
    }
}

/// Build an invocation input rooted in `source_zone` heading to
/// `target_zone`. `approval_tokens` lives outside the input so its
/// reference lifetime tracks the caller's scope.
fn cross_zone_input(
    source_zone: ZoneId,
    target_zone: ZoneId,
    approval_tokens: &[ApprovalToken],
) -> PolicyDecisionInput<'_> {
    static EMPTY_RECEIPTS: &[SanitizerReceipt] = &[];
    static EMPTY_OBJECTS: &[ObjectId] = &[];
    PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"crr6l-req"),
        zone_id: target_zone,
        principal: PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("test:cross-zone:1.0.0"),
        operation_id: OperationId::from_static("op.cross_zone"),
        capability_id: CapabilityId::new("cap.cross_zone").expect("capability"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(source_zone),
        approval_tokens,
        sanitizer_receipts: EMPTY_RECEIPTS,
        request_input: None,
        request_input_hash: None,
        related_object_ids: EMPTY_OBJECTS,
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: NOW_MS,
        posture_attestation: None,
    }
}

fn declassification_token(
    from_zone: ZoneId,
    to_zone: ZoneId,
    object_ids: Vec<ObjectId>,
    target_confidentiality: ConfidentialityLevel,
    token_zone: ZoneId,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> ApprovalToken {
    ApprovalToken::approved(
        "decl-test",
        issued_at_ms,
        expires_at_ms,
        "issuer:cross-zone",
        ApprovalScope::Declassification(DeclassificationScope {
            from_zone,
            to_zone,
            object_ids,
            target_confidentiality,
        }),
        token_zone,
        None,
    )
}

// ──────────────────────────────────────────────────────────────────
// MSH-CROSSZONE-ALLOW: same-zone safe invoke is allowed outright
// ──────────────────────────────────────────────────────────────────

#[test]
fn cross_zone_allow_same_zone_no_flow_restriction() {
    let engine = engine_for(ZoneId::work());
    let input = cross_zone_input(ZoneId::work(), ZoneId::work(), &[]);
    let decision = engine.evaluate_invoke(&input);
    assert!(matches!(decision.decision, Decision::Allow));
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
}

// ──────────────────────────────────────────────────────────────────
// DecisionReasonCode::ApprovalMissingDeclassification variants
// ──────────────────────────────────────────────────────────────────

#[test]
fn cross_zone_work_to_community_without_declassification_token_is_denied() {
    // z:work -> z:community = confidentiality Work(2) -> Community(1)
    // flows DOWN, requires declassification. No token supplied =>
    // ApprovalMissingDeclassification.
    let engine = engine_for(ZoneId::community());
    let input = cross_zone_input(ZoneId::work(), ZoneId::community(), &[]);
    let decision = engine.evaluate_invoke(&input);
    assert!(matches!(decision.decision, Decision::Deny));
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingDeclassification
    );
}

#[test]
fn cross_zone_elevation_scoped_token_does_not_satisfy_declassification_requirement() {
    // Present an Elevation-scoped token when the flow requires
    // Declassification. The scope filter in apply_declassification
    // drops the token and the fall-through is MissingDeclassification.
    let elevation = ApprovalToken::approved(
        "elev-wrongscope",
        NOW_MS.saturating_sub(1_000),
        NOW_MS.saturating_add(TOKEN_TTL_MS),
        "issuer",
        ApprovalScope::Elevation(ElevationScope {
            operation_id: "op.cross_zone".into(),
            original_provenance_id: ObjectId::from_unscoped_bytes(b"crr6l-req"),
            target_integrity: IntegrityLevel::Work,
        }),
        ZoneId::community(),
        None,
    );
    let approvals = vec![elevation];
    let engine = engine_for(ZoneId::community());
    let input = cross_zone_input(ZoneId::work(), ZoneId::community(), &approvals);
    let decision = engine.evaluate_invoke(&input);
    assert!(matches!(decision.decision, Decision::Deny));
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingDeclassification
    );
}

#[test]
fn cross_zone_expired_declassification_token_is_filtered_and_denied() {
    // Token IS correctly scoped but expired. apply_declassification
    // filters it via token.is_valid(now_ms); the observable reason
    // code is the fall-through ApprovalMissingDeclassification. Pinning
    // this behavior so a future refactor that splits expired tokens
    // into a distinct ApprovalExpired code must update this test.
    let req_id = ObjectId::from_unscoped_bytes(b"crr6l-req");
    let token = declassification_token(
        ZoneId::work(),
        ZoneId::community(),
        vec![req_id],
        ConfidentialityLevel::Community,
        ZoneId::community(),
        NOW_MS.saturating_sub(10_000),
        NOW_MS.saturating_sub(1_000), // expired before `NOW_MS`
    );
    let approvals = vec![token];
    let engine = engine_for(ZoneId::community());
    let input = cross_zone_input(ZoneId::work(), ZoneId::community(), &approvals);
    let decision = engine.evaluate_invoke(&input);
    assert!(matches!(decision.decision, Decision::Deny));
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingDeclassification
    );
}

#[test]
fn cross_zone_wrong_token_zone_is_filtered_and_denied() {
    // Token correctly scoped but carries `zone_id = z:private` while
    // the request targets z:community. apply_declassification
    // filters the token via zone equality; fall-through is
    // ApprovalMissingDeclassification.
    let req_id = ObjectId::from_unscoped_bytes(b"crr6l-req");
    let token = declassification_token(
        ZoneId::work(),
        ZoneId::community(),
        vec![req_id],
        ConfidentialityLevel::Community,
        ZoneId::private(), // NOT the target zone
        NOW_MS.saturating_sub(1_000),
        NOW_MS.saturating_add(TOKEN_TTL_MS),
    );
    let approvals = vec![token];
    let engine = engine_for(ZoneId::community());
    let input = cross_zone_input(ZoneId::work(), ZoneId::community(), &approvals);
    let decision = engine.evaluate_invoke(&input);
    assert!(matches!(decision.decision, Decision::Deny));
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingDeclassification
    );
}

// ──────────────────────────────────────────────────────────────────
// DecisionReasonCode::Allow with a matching declassification token
// ──────────────────────────────────────────────────────────────────

#[test]
fn cross_zone_valid_matching_declassification_token_is_allowed() {
    // Correct from_zone + to_zone + target_confidentiality + object_id
    // + token zone_id + within validity window. apply_declassification
    // attaches the token's object id to evidence and allows the flow.
    let req_id = ObjectId::from_unscoped_bytes(b"crr6l-req");
    let token = declassification_token(
        ZoneId::work(),
        ZoneId::community(),
        vec![req_id],
        ConfidentialityLevel::Community,
        ZoneId::community(),
        NOW_MS.saturating_sub(1_000),
        NOW_MS.saturating_add(TOKEN_TTL_MS),
    );
    let approvals = vec![token];
    let engine = engine_for(ZoneId::community());
    let input = cross_zone_input(ZoneId::work(), ZoneId::community(), &approvals);
    let decision = engine.evaluate_invoke(&input);
    assert!(
        matches!(decision.decision, Decision::Allow),
        "matching declassification token must allow the cross-zone flow, got {decision:?}"
    );
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
    assert!(
        !decision.evidence.is_empty(),
        "allow path must record the token as evidence"
    );
}

// ──────────────────────────────────────────────────────────────────
// DecisionReasonCode::ApprovalMissingElevation
// ──────────────────────────────────────────────────────────────────

#[test]
fn cross_zone_community_to_work_without_elevation_token_is_denied() {
    // z:community -> z:work = integrity Community(1) -> Work(2)
    // flows UP, requires Elevation. No token supplied =>
    // ApprovalMissingElevation.
    let engine = engine_for(ZoneId::work());
    let input = cross_zone_input(ZoneId::community(), ZoneId::work(), &[]);
    let decision = engine.evaluate_invoke(&input);
    assert!(matches!(decision.decision, Decision::Deny));
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingElevation
    );
}

#[test]
fn cross_zone_declassification_scoped_token_does_not_satisfy_elevation_requirement() {
    // Present a Declassification token when the flow requires
    // Elevation. The wrong-scope token is filtered out of
    // apply_elevation; fall-through is ApprovalMissingElevation.
    let req_id = ObjectId::from_unscoped_bytes(b"crr6l-req");
    let decl = declassification_token(
        ZoneId::community(),
        ZoneId::work(),
        vec![req_id],
        ConfidentialityLevel::Work,
        ZoneId::work(),
        NOW_MS.saturating_sub(1_000),
        NOW_MS.saturating_add(TOKEN_TTL_MS),
    );
    let approvals = vec![decl];
    let engine = engine_for(ZoneId::work());
    let input = cross_zone_input(ZoneId::community(), ZoneId::work(), &approvals);
    let decision = engine.evaluate_invoke(&input);
    assert!(matches!(decision.decision, Decision::Deny));
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingElevation
    );
}
