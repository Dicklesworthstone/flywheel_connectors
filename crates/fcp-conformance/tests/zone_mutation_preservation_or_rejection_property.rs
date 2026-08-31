//! flywheel_connectors-angoc.2.4 - exhaustive zone-mutation proof artifact.
//!
//! The proof artifact records the standard-zone matrix and pins the invariant
//! that requests are either preserved in their original zone or rejected with a
//! stable approval-missing reason when the effective dispatch zone is mutated.

use fcp_cbor::SchemaId;
use fcp_prelude::{
    CapabilityId, ConnectorId, Decision, DecisionReasonCode, DecisionReceiptPolicy, ObjectHeader,
    ObjectId, OperationId, PolicyDecisionInput, PolicyEngine, PrincipalId, Provenance,
    ProvenanceRecord, SafetyTier, SanitizerReceipt, TransportMode, ZoneId, ZonePolicyObject,
    ZoneTransportPolicy,
};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::PathBuf};

const NOW_MS: u64 = 1_700_000_000_000;
const STANDARD_ZONE_COUNT: usize = 5;
const SCHEMA_VERSION: &str = "fcp.zone_mutation_proof.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ZoneMutationPropertyProof {
    schema_version: String,
    property: String,
    total_pairs: usize,
    preserved_pairs: usize,
    rejected_pairs: usize,
    accepted_denial_reason_codes: Vec<String>,
    standard_zones: Vec<String>,
}

fn standard_zone(index: usize) -> ZoneId {
    match index % STANDARD_ZONE_COUNT {
        0 => ZoneId::owner(),
        1 => ZoneId::private(),
        2 => ZoneId::work(),
        3 => ZoneId::community(),
        _ => ZoneId::public(),
    }
}

fn standard_zone_names() -> Vec<String> {
    (0..STANDARD_ZONE_COUNT)
        .map(|index| standard_zone(index).as_str().to_owned())
        .collect()
}

fn test_header(zone_id: ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new(
            "fcp.core",
            "ZoneMutationProperty",
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
        request_object_id: ObjectId::from_unscoped_bytes(b"angoc-zone-property-req"),
        zone_id: dispatch_zone,
        principal: PrincipalId::new("user:zone-property").expect("principal"),
        connector_id: ConnectorId::from_static("test:zone-property:1.0.0"),
        operation_id: OperationId::from_static("op.zone_property"),
        capability_id: CapabilityId::new("cap.zone_property").expect("capability"),
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

fn decision_for(source_zone: &ZoneId, dispatch_zone: &ZoneId) -> fcp_prelude::PolicyDecision {
    let engine = engine_for(dispatch_zone.clone());
    let input = policy_input(source_zone.clone(), dispatch_zone.clone());
    engine.evaluate_invoke(&input)
}

fn reason_code_wire_name(reason_code: DecisionReasonCode) -> String {
    serde_json::to_value(reason_code)
        .expect("decision reason code serializes")
        .as_str()
        .expect("decision reason code serializes as string")
        .to_owned()
}

fn assert_preserved_or_rejected(source_zone: &ZoneId, dispatch_zone: &ZoneId) {
    let same_zone = source_zone == dispatch_zone;
    let decision = decision_for(source_zone, dispatch_zone);

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

fn build_exhaustive_proof() -> ZoneMutationPropertyProof {
    let mut preserved_pairs = 0usize;
    let mut rejected_pairs = 0usize;
    let mut denial_reasons = BTreeSet::new();

    for source_index in 0..STANDARD_ZONE_COUNT {
        for dispatch_index in 0..STANDARD_ZONE_COUNT {
            let source_zone = standard_zone(source_index);
            let dispatch_zone = standard_zone(dispatch_index);
            let same_zone = source_zone == dispatch_zone;
            let decision = decision_for(&source_zone, &dispatch_zone);

            if same_zone {
                assert!(
                    matches!(decision.decision, Decision::Allow),
                    "same-zone request {source_zone:?} -> {dispatch_zone:?} must be preserved"
                );
                assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
                preserved_pairs += 1;
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
                denial_reasons.insert(reason_code_wire_name(decision.reason_code));
                rejected_pairs += 1;
            }
        }
    }

    ZoneMutationPropertyProof {
        schema_version: SCHEMA_VERSION.to_owned(),
        property: "standard-zone requests preserve original zone or reject mutation".to_owned(),
        total_pairs: STANDARD_ZONE_COUNT * STANDARD_ZONE_COUNT,
        preserved_pairs,
        rejected_pairs,
        accepted_denial_reason_codes: denial_reasons.into_iter().collect(),
        standard_zones: standard_zone_names(),
    }
}

fn proof_output_path() -> PathBuf {
    let root = std::env::var_os("FCP_ZONE_MUTATION_PROOF_DIR").map_or_else(
        || std::env::temp_dir().join("fcp-zone-mutation-proofs"),
        PathBuf::from,
    );
    root.join(format!(
        "zone-mutation-property-proof-{}.json",
        std::process::id()
    ))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn generated_standard_zone_pairs_are_preserved_or_rejected(
        source_index in 0usize..STANDARD_ZONE_COUNT,
        dispatch_index in 0usize..STANDARD_ZONE_COUNT,
    ) {
        assert_preserved_or_rejected(&standard_zone(source_index), &standard_zone(dispatch_index));
    }
}

#[test]
fn exhaustive_standard_zone_matrix_writes_replayable_proof_artifact() {
    let proof = build_exhaustive_proof();

    assert_eq!(proof.schema_version, SCHEMA_VERSION);
    assert_eq!(proof.total_pairs, 25);
    assert_eq!(proof.preserved_pairs, 5);
    assert_eq!(proof.rejected_pairs, 20);
    assert_eq!(
        proof.accepted_denial_reason_codes,
        vec![
            "approval.missing_declassification".to_owned(),
            "approval.missing_elevation".to_owned(),
        ]
    );
    assert_eq!(
        proof.standard_zones,
        vec![
            "z:owner".to_owned(),
            "z:private".to_owned(),
            "z:work".to_owned(),
            "z:community".to_owned(),
            "z:public".to_owned(),
        ]
    );

    let output_path = proof_output_path();
    let output_dir = output_path
        .parent()
        .expect("proof output path must have parent directory");
    fs::create_dir_all(output_dir).expect("create proof artifact directory");

    let json = serde_json::to_string_pretty(&proof).expect("serialize proof artifact");
    fs::write(&output_path, json).expect("write proof artifact");
    let loaded: ZoneMutationPropertyProof =
        serde_json::from_slice(&fs::read(&output_path).expect("read proof artifact"))
            .expect("proof artifact should replay as JSON");

    assert_eq!(loaded, proof);
}
