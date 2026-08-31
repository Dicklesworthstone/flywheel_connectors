//! flywheel_connectors-angoc.2.4 - zone-binding mutation fuzz coverage.
//!
//! This lane proves that a request whose effective dispatch zone is mutated
//! away from its original provenance zone is not silently accepted by the real
//! policy path. It intentionally binds to `PolicyEngine::evaluate_invoke`
//! instead of a test-local policy model.

use fcp_cbor::SchemaId;
use fcp_prelude::{
    CapabilityId, ConnectorId, Decision, DecisionReasonCode, DecisionReceiptPolicy, ObjectHeader,
    ObjectId, OperationId, PolicyDecisionInput, PolicyEngine, PrincipalId, Provenance,
    ProvenanceRecord, SafetyTier, SanitizerReceipt, TransportMode, ZoneId, ZonePolicyObject,
    ZoneTransportPolicy,
};
use proptest::prelude::*;

const NOW_MS: u64 = 1_700_000_000_000;
const STANDARD_ZONE_COUNT: usize = 5;

fn standard_zone(index: usize) -> ZoneId {
    match index % STANDARD_ZONE_COUNT {
        0 => ZoneId::owner(),
        1 => ZoneId::private(),
        2 => ZoneId::work(),
        3 => ZoneId::community(),
        _ => ZoneId::public(),
    }
}

fn test_header(zone_id: ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new(
            "fcp.core",
            "ZoneMutationFuzz",
            semver::Version::new(1, 0, 0),
        ),
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

fn policy_input(source_zone: ZoneId, dispatch_zone: ZoneId) -> PolicyDecisionInput<'static> {
    static EMPTY_RECEIPTS: &[SanitizerReceipt] = &[];
    static EMPTY_OBJECTS: &[ObjectId] = &[];

    PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"angoc-zone-mutation-req"),
        zone_id: dispatch_zone,
        principal: PrincipalId::new("user:zone-mutation").expect("principal"),
        connector_id: ConnectorId::from_static("test:zone-mutation:1.0.0"),
        operation_id: OperationId::from_static("op.zone_mutation"),
        capability_id: CapabilityId::new("cap.zone_mutation").expect("capability"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(source_zone),
        approval_tokens: &[],
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

fn assert_zone_mutation_result(source_zone: &ZoneId, dispatch_zone: &ZoneId) {
    let same_zone = source_zone == dispatch_zone;
    let engine = engine_for(dispatch_zone.clone());
    let input = policy_input(source_zone.clone(), dispatch_zone.clone());
    let decision = engine.evaluate_invoke(&input);

    if same_zone {
        assert!(
            matches!(decision.decision, Decision::Allow),
            "same-zone request {source_zone:?} -> {dispatch_zone:?} must be preserved"
        );
        assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
    } else {
        assert!(
            matches!(decision.decision, Decision::Deny),
            "mutated-zone request {source_zone:?} -> {dispatch_zone:?} must be rejected"
        );
        assert!(
            matches!(
                decision.reason_code,
                DecisionReasonCode::ApprovalMissingElevation
                    | DecisionReasonCode::ApprovalMissingDeclassification
            ),
            "mutated-zone rejection {source_zone:?} -> {dispatch_zone:?} used unstable reason {:?}",
            decision.reason_code
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn generated_standard_zone_mutations_are_preserved_or_rejected(
        source_index in 0usize..STANDARD_ZONE_COUNT,
        dispatch_index in 0usize..STANDARD_ZONE_COUNT,
    ) {
        assert_zone_mutation_result(&standard_zone(source_index), &standard_zone(dispatch_index));
    }
}

#[test]
fn same_zone_work_request_is_preserved() {
    assert_zone_mutation_result(&ZoneId::work(), &ZoneId::work());
}

#[test]
fn owner_to_public_mutation_requires_declassification() {
    let engine = engine_for(ZoneId::public());
    let input = policy_input(ZoneId::owner(), ZoneId::public());
    let decision = engine.evaluate_invoke(&input);

    assert!(matches!(decision.decision, Decision::Deny));
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingDeclassification
    );
}

#[test]
fn public_to_owner_mutation_requires_elevation() {
    let engine = engine_for(ZoneId::owner());
    let input = policy_input(ZoneId::public(), ZoneId::owner());
    let decision = engine.evaluate_invoke(&input);

    assert!(matches!(decision.decision, Decision::Deny));
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingElevation
    );
}
