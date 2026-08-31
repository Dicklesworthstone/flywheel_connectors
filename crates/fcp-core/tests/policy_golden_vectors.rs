//! Policy engine golden decision vectors + property tests.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use fcp_cbor::SchemaId;
use fcp_core::{
    ApprovalScope, ApprovalToken, ConfidentialityLevel, ConnectorId, DecisionReasonCode,
    DeclassificationScope, NodeId, NodeSignature, ObjectHeader, ObjectId, OperationId,
    PolicyDecisionInput, PolicyEngine, PolicyPattern, PostureAttestation, PostureAttributeKey,
    PostureAttributeValue, PostureRequirements, Provenance, ProvenanceRecord, RoleGraph,
    RoleGraphError, RoleObject, SafetyTier, SanitizerReceipt, TaintFlag, TransportMode, ZoneId,
    ZonePolicyObject, ZoneTransportPolicy,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct DecisionVector {
    name: String,
    decision: String,
    reason_code: String,
    evidence: Vec<String>,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("policy")
}

fn write_vector(name: &str, vector: &DecisionVector) {
    let dir = vectors_dir();
    fs::create_dir_all(&dir).expect("create vectors dir");
    let path = dir.join(name);

    let mut bytes = Vec::new();
    ciborium::into_writer(vector, &mut bytes).expect("CBOR encode");
    fs::write(&path, &bytes).expect("write vector");

    let decoded: DecisionVector = ciborium::from_reader(bytes.as_slice()).expect("decode");
    assert_eq!(&decoded, vector);
}

fn test_header(kind: &str, zone: ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.core", kind, Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(zone),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

fn test_signature() -> NodeSignature {
    NodeSignature::new(NodeId::new("node-1"), [0u8; 64], 1_700_000_000)
}

fn base_policy(zone: ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: test_header("ZonePolicyObject", zone.clone()),
        zone_id: zone,
        principal_allow: vec![PolicyPattern {
            pattern: "user:*".to_string(),
        }],
        principal_deny: Vec::new(),
        connector_allow: vec![PolicyPattern {
            pattern: "connector:*".to_string(),
        }],
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: vec![],
        transport_policy: ZoneTransportPolicy::default(),
        decision_receipts: fcp_core::DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn make_allow_vector(name: &str, decision: &fcp_core::PolicyDecision) {
    let vector = DecisionVector {
        name: name.to_string(),
        decision: match decision.decision {
            fcp_core::Decision::Allow => "allow".to_string(),
            fcp_core::Decision::Deny => "deny".to_string(),
        },
        reason_code: decision.reason_code.as_str().to_string(),
        evidence: decision.evidence.iter().map(ToString::to_string).collect(),
    };

    write_vector(&format!("{name}.cbor"), &vector);
}

#[test]
fn decision_vector_allow_basic() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let capability = fcp_core::CapabilityId::from_static("cap.read");

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-1"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: capability,
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);

    let receipt = decision.to_receipt(
        test_header("DecisionReceipt", ZoneId::work()),
        input.request_object_id,
        test_signature(),
    );
    assert!(receipt.is_allow());

    make_allow_vector("decision_allow_basic", &decision);
}

#[test]
fn decision_vector_denies_checkpoint_stale() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-2"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: false,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::CheckpointStaleFrontier
    );

    make_allow_vector("decision_deny_checkpoint_stale", &decision);
}

#[test]
fn decision_vector_denies_transport_derp() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.transport_policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: false,
        allow_funnel: false,
    };
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-3"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Derp,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::TransportDerpForbidden
    );

    make_allow_vector("decision_deny_derp", &decision);
}

#[test]
fn decision_vector_denies_principal_deny() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.principal_deny = vec![PolicyPattern {
        pattern: "user:blocked".to_string(),
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-3b"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:blocked").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyPrincipalDenied
    );

    make_allow_vector("decision_deny_principal", &decision);
}

#[test]
fn decision_vector_denies_capability_not_allowed() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.capability_allow = vec![PolicyPattern {
        pattern: "cap.read".to_string(),
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-3c"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.write"),
        capability_id: fcp_core::CapabilityId::from_static("cap.write"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyCapabilityNotAllowed
    );

    make_allow_vector("decision_deny_capability_not_allowed", &decision);
}

#[test]
fn decision_vector_denies_capability_ceiling() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.capability_ceiling = vec![fcp_core::CapabilityId::from_static("cap.read")];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-3d"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.write"),
        capability_id: fcp_core::CapabilityId::from_static("cap.write"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::CapabilityInsufficient
    );

    make_allow_vector("decision_deny_capability_ceiling", &decision);
}

#[test]
fn decision_vector_denies_connector_deny() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.connector_deny = vec![PolicyPattern {
        pattern: "connector:test".to_string(),
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-3e"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyConnectorDenied
    );

    make_allow_vector("decision_deny_connector", &decision);
}

#[test]
fn decision_vector_denies_capability_deny() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.capability_deny = vec![PolicyPattern {
        pattern: "cap.write".to_string(),
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-3f"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.write"),
        capability_id: fcp_core::CapabilityId::from_static("cap.write"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyCapabilityDenied
    );

    make_allow_vector("decision_deny_capability", &decision);
}

#[test]
fn decision_vector_denies_missing_execution_approval() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-3g"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.run"),
        capability_id: fcp_core::CapabilityId::from_static("cap.exec"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: true,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingExecution
    );

    make_allow_vector("decision_deny_missing_execution", &decision);
}

#[test]
fn decision_vector_denies_public_input_dangerous() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-4"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.write"),
        capability_id: fcp_core::CapabilityId::from_static("cap.write"),
        safety_tier: SafetyTier::Dangerous,
        provenance: ProvenanceRecord::public_input(),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::TaintPublicInputDangerous
    );

    make_allow_vector("decision_deny_public_dangerous", &decision);
}

#[test]
fn decision_vector_allows_after_sanitize_unverified_link() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let mut provenance = ProvenanceRecord::new(zone.clone());
    provenance.taint_flags.insert(TaintFlag::UnverifiedLink);
    provenance.input_sources = vec![ObjectId::from_unscoped_bytes(b"input-1")];

    let receipt = SanitizerReceipt {
        receipt_id: "receipt-1".to_string(),
        timestamp_ms: 1_700_000_000_000,
        sanitizer_id: "sanitizer:test".to_string(),
        sanitizer_zone: zone.clone(),
        authorized_flags: vec![TaintFlag::UnverifiedLink],
        covered_inputs: vec![ObjectId::from_unscoped_bytes(b"input-1")],
        cleared_flags: vec![TaintFlag::UnverifiedLink],
        signature: None,
    };

    let receipts = vec![receipt];

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-5"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.risky"),
        capability_id: fcp_core::CapabilityId::from_static("cap.risky"),
        safety_tier: SafetyTier::Risky,
        provenance,
        approval_tokens: &[],
        sanitizer_receipts: receipts.as_slice(),
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);

    make_allow_vector("decision_allow_after_sanitize", &decision);
}

/// Deny-after-sanitize: the sanitizer receipt is valid and cleared the
/// flag it was authorized to clear, but RESIDUAL taint remains and the
/// operation is Dangerous, so downstream checks still reject.
///
/// Concretely: provenance carries BOTH `UnverifiedLink` and `PublicInput`;
/// the sanitizer is authorized for `UnverifiedLink` only. After apply,
/// `UnverifiedLink` is gone and evidence is accumulated — but the
/// `PublicInput + Dangerous` check downstream denies, producing
/// `TaintPublicInputDangerous`. This locks down the spec guarantee that
/// sanitization does NOT grant carte blanche — each flag is cleared
/// independently, and residual taint is still enforceable.
///
/// Spec source: FCP V3 §7 (Provenance and Taint), MUST clause that a
/// sanitizer receipt clears only the flags it authorizes.
#[test]
fn decision_vector_denies_after_sanitize_residual_taint() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let mut provenance = ProvenanceRecord::new(zone.clone());
    provenance.taint_flags.insert(TaintFlag::UnverifiedLink);
    provenance.taint_flags.insert(TaintFlag::PublicInput);
    provenance.input_sources = vec![ObjectId::from_unscoped_bytes(b"input-1")];

    // Sanitizer authorized only for UnverifiedLink; cannot touch PublicInput.
    let receipt = SanitizerReceipt {
        receipt_id: "receipt-partial".to_string(),
        timestamp_ms: 1_700_000_000_000,
        sanitizer_id: "sanitizer:link-only".to_string(),
        sanitizer_zone: zone.clone(),
        authorized_flags: vec![TaintFlag::UnverifiedLink],
        covered_inputs: vec![ObjectId::from_unscoped_bytes(b"input-1")],
        cleared_flags: vec![TaintFlag::UnverifiedLink],
        signature: None,
    };

    let receipts = vec![receipt];

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-deny-after-sanitize"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.dangerous"),
        capability_id: fcp_core::CapabilityId::from_static("cap.dangerous"),
        safety_tier: SafetyTier::Dangerous,
        provenance,
        approval_tokens: &[],
        sanitizer_receipts: receipts.as_slice(),
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::TaintPublicInputDangerous,
        "sanitize cleared UnverifiedLink, but residual PublicInput + Dangerous MUST deny"
    );
    // Evidence set is non-empty: the valid sanitizer receipt was consulted
    // and referenced, even though the operation ultimately denies.
    assert!(
        !decision.evidence.is_empty(),
        "sanitizer receipt should appear in evidence even when the final verdict denies"
    );

    make_allow_vector("decision_deny_after_sanitize", &decision);
}

#[test]
fn decision_vector_requires_declassification() {
    let zone = ZoneId::public();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let request_id = ObjectId::from_unscoped_bytes(b"req-6");

    let input = PolicyDecisionInput {
        request_object_id: request_id,
        zone_id: zone.clone(),
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::private()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[request_id],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingDeclassification
    );

    make_allow_vector("decision_deny_missing_declassification", &decision);

    let approval = ApprovalToken {
        token_id: "declass-1".to_string(),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_100_000,
        issuer: "node:authority".to_string(),
        scope: ApprovalScope::Declassification(DeclassificationScope {
            from_zone: ZoneId::private(),
            to_zone: zone,
            object_ids: vec![request_id],
            target_confidentiality: ConfidentialityLevel::Public,
        }),
        zone_id: ZoneId::public(),
        signature: None,
        _state: std::marker::PhantomData,
    };

    let approvals = vec![approval];
    let input_with_token = PolicyDecisionInput {
        approval_tokens: approvals.as_slice(),
        ..input
    };

    let decision = engine.evaluate_invoke(&input_with_token);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);

    make_allow_vector("decision_allow_with_declassification", &decision);
}

#[test]
fn decision_vector_execution_scope_binding() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let request_id = ObjectId::from_unscoped_bytes(b"req-7");
    let input_hash = [9u8; 32];

    let input_json = json!({"arg": "value"});

    let mismatch_token = ApprovalToken {
        token_id: "exec-mismatch".to_string(),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_100_000,
        issuer: "node:authority".to_string(),
        scope: ApprovalScope::Execution(fcp_core::ExecutionScope {
            connector_id: "connector:test".to_string(),
            method_pattern: "op.*".to_string(),
            request_object_id: Some(ObjectId::from_unscoped_bytes(b"other")),
            input_hash: Some(input_hash),
            input_constraints: vec![fcp_core::InputConstraint {
                pointer: "/arg".to_string(),
                expected: json!("value"),
            }],
        }),
        zone_id: zone.clone(),
        signature: None,
        _state: std::marker::PhantomData,
    };

    let approvals = vec![mismatch_token];

    let input = PolicyDecisionInput {
        request_object_id: request_id,
        zone_id: zone.clone(),
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.run"),
        capability_id: fcp_core::CapabilityId::from_static("cap.exec"),
        safety_tier: SafetyTier::Risky,
        provenance: ProvenanceRecord::new(zone.clone()),
        approval_tokens: approvals.as_slice(),
        sanitizer_receipts: &[],
        request_input: Some(&input_json),
        request_input_hash: Some(input_hash),
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: true,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalExecutionScopeMismatch
    );

    make_allow_vector("decision_deny_execution_mismatch", &decision);

    let matching_token = ApprovalToken {
        token_id: "exec-match".to_string(),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_100_000,
        issuer: "node:authority".to_string(),
        scope: ApprovalScope::Execution(fcp_core::ExecutionScope {
            connector_id: "connector:test".to_string(),
            method_pattern: "op.*".to_string(),
            request_object_id: Some(request_id),
            input_hash: Some(input_hash),
            input_constraints: vec![fcp_core::InputConstraint {
                pointer: "/arg".to_string(),
                expected: json!("value"),
            }],
        }),
        zone_id: zone,
        signature: None,
        _state: std::marker::PhantomData,
    };

    let approvals = vec![matching_token];
    let input_match = PolicyDecisionInput {
        approval_tokens: approvals.as_slice(),
        ..input
    };

    let decision = engine.evaluate_invoke(&input_match);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);

    make_allow_vector("decision_allow_execution_match", &decision);
}

#[test]
fn role_graph_cycle_detection() {
    let role_alpha_id = ObjectId::from_unscoped_bytes(b"role-a");
    let role_beta_id = ObjectId::from_unscoped_bytes(b"role-b");

    let role_a = RoleObject {
        name: "role-a".to_string(),
        caps: vec![],
        includes: vec![role_beta_id],
    };

    let role_b = RoleObject {
        name: "role-b".to_string(),
        caps: vec![],
        includes: vec![role_alpha_id],
    };

    let roles = HashMap::from([(role_alpha_id, role_a), (role_beta_id, role_b)]);
    let graph = RoleGraph::new(roles);

    let err = graph
        .validate_acyclic()
        .expect_err("cycle should be detected");
    match err {
        RoleGraphError::RoleCycle { .. } => {}
        other @ RoleGraphError::UnknownRole { .. } => {
            panic!("unexpected error: {other:?}");
        }
    }
}

#[test]
fn role_graph_resolves_caps() {
    let role_alpha_id = ObjectId::from_unscoped_bytes(b"role-a");
    let role_beta_id = ObjectId::from_unscoped_bytes(b"role-b");

    let role_a = RoleObject {
        name: "role-a".to_string(),
        caps: vec![fcp_core::CapabilityGrant {
            capability: fcp_core::CapabilityId::from_static("cap.a"),
            operation: None,
        }],
        includes: vec![role_beta_id],
    };

    let role_b = RoleObject {
        name: "role-b".to_string(),
        caps: vec![fcp_core::CapabilityGrant {
            capability: fcp_core::CapabilityId::from_static("cap.b"),
            operation: None,
        }],
        includes: vec![],
    };

    let roles = HashMap::from([(role_alpha_id, role_a), (role_beta_id, role_b)]);
    let graph = RoleGraph::new(roles);
    graph.validate_acyclic().expect("acyclic");

    let caps = graph.resolve_caps(&[role_alpha_id]).expect("resolve caps");
    let cap_ids: Vec<String> = caps
        .iter()
        .map(|c| c.capability.as_str().to_string())
        .collect();

    assert!(cap_ids.contains(&"cap.a".to_string()));
    assert!(cap_ids.contains(&"cap.b".to_string()));
}

#[test]
fn role_graph_property_dag_no_cycle() {
    let mut roles = HashMap::new();

    let base_id = ObjectId::from_unscoped_bytes(b"role-base");
    roles.insert(
        base_id,
        RoleObject {
            name: "base".to_string(),
            caps: vec![],
            includes: vec![],
        },
    );

    for idx in 0..5u8 {
        let role_id = ObjectId::from_unscoped_bytes(&[idx]);
        roles.insert(
            role_id,
            RoleObject {
                name: format!("role-{idx}"),
                caps: vec![],
                includes: vec![base_id],
            },
        );
    }

    let graph = RoleGraph::new(roles);
    graph.validate_acyclic().expect("DAG should be valid");
}

// ─────────────────────────────────────────────────────────────────────────────
// Revocation Staleness Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_vector_denies_revocation_stale() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-revoke-stale"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: false, // <-- stale revocation state
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::RevocationStaleFrontier
    );

    make_allow_vector("decision_deny_revocation_stale", &decision);
}

// ─────────────────────────────────────────────────────────────────────────────
// Transport Mode Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_vector_denies_transport_funnel() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.transport_policy = ZoneTransportPolicy {
        allow_lan: true,
        allow_derp: true,
        allow_funnel: false, // <-- funnel forbidden
    };
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-funnel"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Funnel, // <-- using funnel
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::TransportFunnelForbidden
    );

    make_allow_vector("decision_deny_funnel", &decision);
}

#[test]
fn decision_vector_denies_transport_lan() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.transport_policy = ZoneTransportPolicy {
        allow_lan: false, // <-- LAN forbidden
        allow_derp: true,
        allow_funnel: false,
    };
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-lan"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan, // <-- using LAN
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::TransportLanForbidden
    );

    make_allow_vector("decision_deny_lan", &decision);
}

#[test]
fn decision_vector_allows_transport_derp() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.transport_policy = ZoneTransportPolicy {
        allow_lan: false,
        allow_derp: true, // <-- DERP allowed
        allow_funnel: false,
    };
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-derp-ok"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Derp, // <-- DERP is allowed
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);

    make_allow_vector("decision_allow_derp", &decision);
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Deny/Allow List Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_vector_denies_connector_on_deny_list() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.connector_deny = vec![PolicyPattern {
        pattern: "connector:blocked*".to_string(),
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-conn-deny"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:blocked-one"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyConnectorDenied
    );

    make_allow_vector("decision_deny_connector_blocklist", &decision);
}

#[test]
fn decision_vector_denies_connector_not_allowed() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.connector_allow = vec![PolicyPattern {
        pattern: "connector:allowed*".to_string(),
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-conn-not-allowed"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:unauthorized"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyConnectorNotAllowed
    );

    make_allow_vector("decision_deny_connector_not_allowed", &decision);
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability Deny List Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_vector_denies_capability_on_deny_list() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.capability_deny = vec![PolicyPattern {
        pattern: "cap.dangerous*".to_string(),
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-cap-deny"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.danger"),
        capability_id: fcp_core::CapabilityId::from_static("cap.dangerous.delete"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyCapabilityDenied
    );

    make_allow_vector("decision_deny_capability_blocklist", &decision);
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern Matching Edge Case Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pattern_matching_exact() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.principal_allow = vec![PolicyPattern {
        pattern: "user:alice".to_string(), // exact match
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    // Exact match should allow
    let input_alice = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-exact-alice"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input_alice);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);

    // Different user should be denied
    let input_bob = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-exact-bob"),
        principal: fcp_core::PrincipalId::new("user:bob").expect("principal"),
        ..input_alice.clone()
    };

    let decision = engine.evaluate_invoke(&input_bob);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyPrincipalNotAllowed
    );
}

#[test]
fn pattern_matching_wildcard_suffix() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.principal_allow = vec![PolicyPattern {
        pattern: "user:admin*".to_string(), // suffix wildcard
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    // admin-alice should match
    let input_admin = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-wild-admin"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:admin-alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input_admin);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);

    // user:guest should not match
    let input_guest = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-wild-guest"),
        principal: fcp_core::PrincipalId::new("user:guest").expect("principal"),
        ..input_admin.clone()
    };

    let decision = engine.evaluate_invoke(&input_guest);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyPrincipalNotAllowed
    );
}

#[test]
fn pattern_matching_wildcard_prefix() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.principal_allow = vec![PolicyPattern {
        pattern: "*:alice".to_string(), // prefix wildcard
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input_user_alice = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-prefix-user"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input_user_alice);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);

    // service:alice should also match
    let input_service_alice = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-prefix-svc"),
        principal: fcp_core::PrincipalId::new("service:alice").expect("principal"),
        ..input_user_alice.clone()
    };

    let decision = engine.evaluate_invoke(&input_service_alice);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
}

#[test]
fn pattern_matching_multiple_patterns() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.principal_allow = vec![
        PolicyPattern {
            pattern: "user:alice".to_string(),
        },
        PolicyPattern {
            pattern: "user:bob".to_string(),
        },
        PolicyPattern {
            pattern: "service:*".to_string(),
        },
    ];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    // All three patterns should match their respective principals
    for (name, principal_str) in [
        ("alice", "user:alice"),
        ("bob", "user:bob"),
        ("service", "service:backend"),
    ] {
        let input = PolicyDecisionInput {
            request_object_id: ObjectId::from_unscoped_bytes(name.as_bytes()),
            zone_id: zone.clone(),
            principal: fcp_core::PrincipalId::new(principal_str).expect("principal"),
            connector_id: ConnectorId::from_static("connector:test"),
            operation_id: OperationId::from_static("op.read"),
            capability_id: fcp_core::CapabilityId::from_static("cap.read"),
            safety_tier: SafetyTier::Safe,
            provenance: ProvenanceRecord::new(ZoneId::work()),
            approval_tokens: &[],
            sanitizer_receipts: &[],
            request_input: None,
            request_input_hash: None,
            related_object_ids: &[],
            transport: TransportMode::Lan,
            checkpoint_fresh: true,
            revocation_fresh: true,
            execution_approval_required: false,
            now_ms: 1_700_000_000_000,
            posture_attestation: None,
        };

        let decision = engine.evaluate_invoke(&input);
        assert_eq!(
            decision.reason_code,
            DecisionReasonCode::Allow,
            "Principal {principal_str} should be allowed"
        );
    }
}

#[test]
fn pattern_deny_takes_precedence() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.principal_allow = vec![PolicyPattern {
        pattern: "user:*".to_string(),
    }];
    policy.principal_deny = vec![PolicyPattern {
        pattern: "user:blocked".to_string(),
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    // user:blocked matches allow but also deny, should be denied
    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-deny-precedence"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:blocked").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyPrincipalDenied
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sanitizer Receipt Validation Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sanitizer_receipt_invalid() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let mut provenance = ProvenanceRecord::new(zone.clone());
    provenance.taint_flags.insert(TaintFlag::UnverifiedLink);
    provenance.input_sources = vec![ObjectId::from_unscoped_bytes(b"input-1")];

    // Receipt that doesn't cover the required input
    let invalid_receipt = SanitizerReceipt {
        receipt_id: "receipt-invalid".to_string(),
        timestamp_ms: 1_700_000_000_000,
        sanitizer_id: "sanitizer:test".to_string(),
        sanitizer_zone: zone.clone(),
        authorized_flags: vec![TaintFlag::UnverifiedLink],
        covered_inputs: vec![ObjectId::from_unscoped_bytes(b"different-input")], // wrong input
        cleared_flags: vec![TaintFlag::UnverifiedLink],
        signature: None,
    };

    let receipts = vec![invalid_receipt];

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-invalid-receipt"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.risky"),
        capability_id: fcp_core::CapabilityId::from_static("cap.risky"),
        safety_tier: SafetyTier::Risky,
        provenance,
        approval_tokens: &[],
        sanitizer_receipts: receipts.as_slice(),
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    // Should be denied because sanitizer receipt doesn't cover the required inputs
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::SanitizerCoverageInsufficient
    );

    make_allow_vector("decision_deny_sanitizer_coverage", &decision);
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision Reason Code Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_reason_code_string_roundtrip() {
    // All variants from DecisionReasonCode
    let codes = [
        DecisionReasonCode::Allow,
        DecisionReasonCode::CapabilityInsufficient,
        DecisionReasonCode::CheckpointStaleFrontier,
        DecisionReasonCode::RevocationStaleFrontier,
        DecisionReasonCode::TaintPublicInputDangerous,
        DecisionReasonCode::TaintMaliciousInput,
        DecisionReasonCode::TaintRiskyRequiresElevation,
        DecisionReasonCode::IntegrityInsufficient,
        DecisionReasonCode::ZonePolicyPrincipalDenied,
        DecisionReasonCode::ZonePolicyConnectorDenied,
        DecisionReasonCode::ZonePolicyCapabilityDenied,
        DecisionReasonCode::ZonePolicyPrincipalNotAllowed,
        DecisionReasonCode::ZonePolicyConnectorNotAllowed,
        DecisionReasonCode::ZonePolicyCapabilityNotAllowed,
        DecisionReasonCode::ApprovalMissingElevation,
        DecisionReasonCode::ApprovalMissingDeclassification,
        DecisionReasonCode::ApprovalMissingExecution,
        DecisionReasonCode::ApprovalElevationScopeMismatch,
        DecisionReasonCode::ApprovalExecutionScopeMismatch,
        DecisionReasonCode::ApprovalTokenInvalid,
        DecisionReasonCode::TransportDerpForbidden,
        DecisionReasonCode::TransportFunnelForbidden,
        DecisionReasonCode::TransportLanForbidden,
        DecisionReasonCode::SanitizerReceiptInvalid,
        DecisionReasonCode::SanitizerCoverageInsufficient,
    ];

    for code in codes {
        let s = code.as_str();
        assert!(
            !s.is_empty(),
            "DecisionReasonCode::{code:?} should have non-empty string"
        );
        // Verify strings use dot-separated format (e.g., "capability.insufficient")
        assert!(
            s.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c == '.'),
            "DecisionReasonCode string should be valid format: {s}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution Approval Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_vector_denies_execution_approval_missing() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-exec-missing"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.run"),
        capability_id: fcp_core::CapabilityId::from_static("cap.exec"),
        safety_tier: SafetyTier::Risky,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[], // <-- no approval tokens
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: true, // <-- requires approval
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingExecution
    );

    make_allow_vector("decision_deny_execution_missing", &decision);
}

// ─────────────────────────────────────────────────────────────────────────────
// Role Graph Error Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn role_graph_unknown_role_error() {
    let role_id = ObjectId::from_unscoped_bytes(b"role-exists");
    let unknown_id = ObjectId::from_unscoped_bytes(b"role-unknown");

    let role = RoleObject {
        name: "existing".to_string(),
        caps: vec![fcp_core::CapabilityGrant {
            capability: fcp_core::CapabilityId::from_static("cap.test"),
            operation: None,
        }],
        includes: vec![unknown_id], // <-- references unknown role
    };

    let roles = HashMap::from([(role_id, role)]);
    let graph = RoleGraph::new(roles);

    // Validation should detect unknown role reference
    let err = graph
        .validate_acyclic()
        .expect_err("unknown role should be detected");
    match err {
        RoleGraphError::UnknownRole { role_id: id } => {
            assert_eq!(id, unknown_id);
        }
        other @ RoleGraphError::RoleCycle { .. } => {
            panic!("unexpected error: {other:?}");
        }
    }
}

#[test]
fn role_graph_resolve_unknown_role_returns_error() {
    let role_id = ObjectId::from_unscoped_bytes(b"role-known");
    let unknown_id = ObjectId::from_unscoped_bytes(b"role-missing");

    let role = RoleObject {
        name: "known".to_string(),
        caps: vec![],
        includes: vec![],
    };

    let roles = HashMap::from([(role_id, role)]);
    let graph = RoleGraph::new(roles);

    // Try to resolve capabilities for unknown role
    let err = graph
        .resolve_caps(&[unknown_id])
        .expect_err("unknown role should error");
    match err {
        RoleGraphError::UnknownRole { role_id: id } => {
            assert_eq!(id, unknown_id);
        }
        other @ RoleGraphError::RoleCycle { .. } => {
            panic!("unexpected error: {other:?}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability Ceiling Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_vector_capability_ceiling_allows_within() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    // Ceiling allows read and write
    policy.capability_ceiling = vec![
        fcp_core::CapabilityId::from_static("cap.read"),
        fcp_core::CapabilityId::from_static("cap.write"),
    ];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-ceiling-ok"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"), // within ceiling
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
}

#[test]
fn decision_vector_empty_ceiling_allows_all() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.capability_ceiling = vec![]; // empty means no ceiling
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-no-ceiling"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.admin"),
        capability_id: fcp_core::CapabilityId::from_static("cap.admin.superpower"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
}

// ─────────────────────────────────────────────────────────────────────────────
// Approval Token Expiry Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_vector_denies_expired_approval_token() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let request_id = ObjectId::from_unscoped_bytes(b"req-expired");

    let expired_token = ApprovalToken {
        token_id: "exec-expired".to_string(),
        issued_at_ms: 1_699_999_000_000,
        expires_at_ms: 1_699_999_500_000, // <-- expired before now_ms
        issuer: "node:authority".to_string(),
        scope: ApprovalScope::Execution(fcp_core::ExecutionScope {
            connector_id: "connector:test".to_string(),
            method_pattern: "op.*".to_string(),
            request_object_id: Some(request_id),
            input_hash: None,
            input_constraints: vec![],
        }),
        zone_id: zone.clone(),
        signature: None,
        _state: std::marker::PhantomData,
    };

    let approvals = vec![expired_token];

    let input = PolicyDecisionInput {
        request_object_id: request_id,
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.run"),
        capability_id: fcp_core::CapabilityId::from_static("cap.exec"),
        safety_tier: SafetyTier::Risky,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: approvals.as_slice(),
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: true,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    // Token is expired, so execution approval is still missing
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ApprovalMissingExecution
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Principal Not Allowed Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decision_vector_denies_principal_not_allowed() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.principal_allow = vec![PolicyPattern {
        pattern: "user:allowed*".to_string(),
    }];
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-principal-na"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:stranger").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::ZonePolicyPrincipalNotAllowed
    );

    make_allow_vector("decision_deny_principal_not_allowed", &decision);
}

// ─────────────────────────────────────────────────────────────────────────────
// Posture Attestation Tests
// ─────────────────────────────────────────────────────────────────────────────

fn create_valid_attestation(node_id: &str) -> PostureAttestation {
    // Use fixed timestamps consistent with now_ms: 1_700_000_000_000 (Nov 14, 2023 22:13:20 UTC)
    // issued_at: 1 hour before now_ms, expires_at: 23 hours after now_ms
    let issued_at =
        chrono::DateTime::from_timestamp_millis(1_699_996_400_000).expect("valid timestamp");
    let expires_at =
        chrono::DateTime::from_timestamp_millis(1_700_082_800_000).expect("valid timestamp");

    let mut attributes = HashMap::new();
    attributes.insert(
        PostureAttributeKey::OsType,
        PostureAttributeValue::String("macos".to_string()),
    );
    attributes.insert(
        PostureAttributeKey::OsVersion,
        PostureAttributeValue::String("14.2.1".to_string()),
    );
    attributes.insert(
        PostureAttributeKey::DiskEncryption,
        PostureAttributeValue::Bool(true),
    );
    attributes.insert(
        PostureAttributeKey::FirewallEnabled,
        PostureAttributeValue::Bool(true),
    );

    PostureAttestation {
        schema: PostureAttestation::SCHEMA.to_string(),
        attestation_id: "att-12345".to_string(),
        node_id: NodeId::new(node_id),
        attributes,
        issued_at,
        expires_at,
        verifier_id: "trusted-verifier".to_string(),
        signature: "signature".to_string(),
        verifier_kid: "kid-1".to_string(),
    }
}

#[test]
fn decision_vector_denies_posture_attestation_missing() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.requires_posture = Some(
        PostureRequirements::builder()
            .require_disk_encryption(true)
            .build(),
    );
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-posture-missing"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::PostureAttestationMissing
    );
}

#[test]
fn decision_vector_denies_posture_attestation_expired() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.requires_posture = Some(
        PostureRequirements::builder()
            .require_disk_encryption(true)
            .build(),
    );
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    // Create an expired attestation (expires_at before now_ms: 1_700_000_000_000)
    let mut attestation = create_valid_attestation("node-1");
    attestation.expires_at =
        chrono::DateTime::from_timestamp_millis(1_699_990_000_000).expect("valid timestamp");

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-posture-expired"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: Some(&attestation),
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::PostureAttestationExpired
    );
}

#[test]
fn decision_vector_denies_posture_requirement_not_met() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    // Require OS version 15.0, but attestation has 14.2.1
    policy.requires_posture = Some(
        PostureRequirements::builder()
            .require_os_min_version("15.0")
            .build(),
    );
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let attestation = create_valid_attestation("node-1");

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-posture-unmet"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: Some(&attestation),
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::PostureRequirementNotMet
    );
}

#[test]
fn decision_vector_allows_with_valid_posture() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.requires_posture = Some(
        PostureRequirements::builder()
            .require_disk_encryption(true)
            .require_os_min_version("14.0")
            .build(),
    );
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let attestation = create_valid_attestation("node-1");

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-posture-valid"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: Some(&attestation),
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
}

#[test]
fn decision_vector_allows_without_posture_requirement() {
    // When no posture requirements are set, attestation is optional
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-no-posture-req"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: None,
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(decision.reason_code, DecisionReasonCode::Allow);
}

#[test]
fn decision_vector_denies_posture_verifier_not_allowed() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.requires_posture = Some(
        PostureRequirements::builder()
            .require_disk_encryption(true)
            .allow_verifier("specific-verifier")
            .build(),
    );
    let engine = PolicyEngine {
        zone_policy: policy,
    };

    // Attestation from a different verifier
    let attestation = create_valid_attestation("node-1");

    let input = PolicyDecisionInput {
        request_object_id: ObjectId::from_unscoped_bytes(b"req-posture-verifier"),
        zone_id: zone,
        principal: fcp_core::PrincipalId::new("user:alice").expect("principal"),
        connector_id: ConnectorId::from_static("connector:test"),
        operation_id: OperationId::from_static("op.read"),
        capability_id: fcp_core::CapabilityId::from_static("cap.read"),
        safety_tier: SafetyTier::Safe,
        provenance: ProvenanceRecord::new(ZoneId::work()),
        approval_tokens: &[],
        sanitizer_receipts: &[],
        request_input: None,
        request_input_hash: None,
        related_object_ids: &[],
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        now_ms: 1_700_000_000_000,
        posture_attestation: Some(&attestation),
    };

    let decision = engine.evaluate_invoke(&input);
    assert_eq!(
        decision.reason_code,
        DecisionReasonCode::PostureVerifierNotAllowed
    );
}
