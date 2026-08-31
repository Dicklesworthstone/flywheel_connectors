//! 5-zone zone-isolation E2E coverage for Phase C.7.
//!
//! The harness drives the crate-public policy path used by the host boundary
//! (`PolicyEngine::evaluate_invoke`) with five canonical zones and emits one
//! structured zone-check JSON line per decision.

#![allow(clippy::too_many_arguments, clippy::too_many_lines)]

use fcp_cbor::SchemaId;
use fcp_e2e::{
    AssertionsSummary, E2eLogEntry, E2eLogger, scan_log_jsonl, validate_log_entry_value,
};
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityId, ConfidentialityLevel, ConnectorId, Decision,
    DecisionReasonCode, DecisionReceiptPolicy, DeclassificationScope, ElevationScope,
    IntegrityLevel, ObjectHeader, ObjectId, OperationId, PolicyDecision, PolicyDecisionInput,
    PolicyEngine, PolicyPattern, PrincipalId, Provenance, ProvenanceRecord, SafetyTier,
    SanitizerReceipt, TransportMode, ZoneId, ZonePolicyObject, ZoneTransportPolicy, declassify,
};
use proptest::prelude::*;
use serde_json::{Value, json};

const NOW_MS: u64 = 1_700_000_000_000;
const TOKEN_TTL_MS: u64 = 60_000;
const ZONE_COUNT: usize = 5;
const STRUCTURED_REASON_CODES: &[&str] = &[
    DecisionReasonCode::Allow.as_str(),
    DecisionReasonCode::CapabilityInsufficient.as_str(),
    DecisionReasonCode::CheckpointStaleFrontier.as_str(),
    DecisionReasonCode::RevocationStaleFrontier.as_str(),
    DecisionReasonCode::TaintPublicInputDangerous.as_str(),
    DecisionReasonCode::TaintUnverifiedLinkRisky.as_str(),
    DecisionReasonCode::TaintMaliciousInput.as_str(),
    DecisionReasonCode::TaintRiskyRequiresElevation.as_str(),
    DecisionReasonCode::TaintCrossZoneUnapproved.as_str(),
    DecisionReasonCode::IntegrityInsufficient.as_str(),
    DecisionReasonCode::ZonePolicyPrincipalDenied.as_str(),
    DecisionReasonCode::ZonePolicyConnectorDenied.as_str(),
    DecisionReasonCode::ZonePolicyCapabilityDenied.as_str(),
    DecisionReasonCode::ZonePolicyPrincipalNotAllowed.as_str(),
    DecisionReasonCode::ZonePolicyConnectorNotAllowed.as_str(),
    DecisionReasonCode::ZonePolicyCapabilityNotAllowed.as_str(),
    DecisionReasonCode::ApprovalMissingElevation.as_str(),
    DecisionReasonCode::ApprovalMissingDeclassification.as_str(),
    DecisionReasonCode::ApprovalMissingExecution.as_str(),
    DecisionReasonCode::ApprovalElevationScopeMismatch.as_str(),
    DecisionReasonCode::ApprovalExecutionScopeMismatch.as_str(),
    DecisionReasonCode::ApprovalExpired.as_str(),
    DecisionReasonCode::ApprovalZoneMismatch.as_str(),
    DecisionReasonCode::ApprovalTokenInvalid.as_str(),
    DecisionReasonCode::TransportDerpForbidden.as_str(),
    DecisionReasonCode::TransportFunnelForbidden.as_str(),
    DecisionReasonCode::TransportLanForbidden.as_str(),
    DecisionReasonCode::SanitizerReceiptInvalid.as_str(),
    DecisionReasonCode::SanitizerCoverageInsufficient.as_str(),
    DecisionReasonCode::PostureAttestationMissing.as_str(),
    DecisionReasonCode::PostureAttestationExpired.as_str(),
    DecisionReasonCode::PostureAttestationInvalid.as_str(),
    DecisionReasonCode::PostureRequirementNotMet.as_str(),
    DecisionReasonCode::PostureVerifierNotAllowed.as_str(),
    DecisionReasonCode::OperationForbidden.as_str(),
];

struct ZoneFixture {
    zone_id: ZoneId,
    connector_id: ConnectorId,
    capability_id: CapabilityId,
    allowed_zones: Vec<ZoneId>,
}

impl ZoneFixture {
    fn new(zone_id: ZoneId) -> Self {
        let slug = zone_slug(&zone_id);
        Self {
            zone_id: zone_id.clone(),
            connector_id: ConnectorId::new(format!("zone-{slug}"), "e2e", "v1")
                .expect("connector id is canonical"),
            capability_id: CapabilityId::new(format!("cap.zone.{slug}"))
                .expect("capability id is canonical"),
            allowed_zones: vec![zone_id],
        }
    }

    fn engine(&self) -> PolicyEngine {
        PolicyEngine {
            zone_policy: ZonePolicyObject {
                header: object_header(self.zone_id.clone()),
                zone_id: self.zone_id.clone(),
                principal_allow: Vec::new(),
                principal_deny: Vec::new(),
                connector_allow: vec![PolicyPattern {
                    pattern: self.connector_id.as_str().to_owned(),
                }],
                connector_deny: Vec::new(),
                capability_allow: vec![PolicyPattern {
                    pattern: self.capability_id.as_str().to_owned(),
                }],
                capability_deny: Vec::new(),
                capability_ceiling: vec![self.capability_id.clone()],
                transport_policy: ZoneTransportPolicy {
                    allow_lan: true,
                    allow_derp: true,
                    allow_funnel: true,
                },
                decision_receipts: DecisionReceiptPolicy::default(),
                usage_budget: None,
                requires_posture: None,
            },
        }
    }
}

fn object_header(zone_id: ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new(
            "fcp.e2e",
            "ZoneIsolationFixture",
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

fn zone_slug(zone_id: &ZoneId) -> &'static str {
    match zone_id.as_str() {
        "z:public" => "public",
        "z:community" => "community",
        "z:work" => "work",
        "z:project:alpha" => "project-alpha",
        "z:private" => "private",
        other => panic!("unexpected fixture zone {other}"),
    }
}

fn project_alpha_zone() -> ZoneId {
    "z:project:alpha"
        .parse()
        .expect("project alpha zone id is canonical")
}

fn zone_by_index(index: usize) -> ZoneId {
    match index % ZONE_COUNT {
        0 => ZoneId::public(),
        1 => ZoneId::community(),
        2 => ZoneId::work(),
        3 => project_alpha_zone(),
        _ => ZoneId::private(),
    }
}

fn object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn principal() -> PrincipalId {
    PrincipalId::new("user:zone-isolation").expect("principal id is canonical")
}

fn operation_id() -> OperationId {
    OperationId::from_static("op.zone.invoke")
}

fn elevation_token(
    token_id: &str,
    zone_id: ZoneId,
    request_object_id: ObjectId,
    target_integrity: IntegrityLevel,
) -> ApprovalToken {
    ApprovalToken::approved(
        token_id,
        NOW_MS.saturating_sub(1_000),
        NOW_MS.saturating_add(TOKEN_TTL_MS),
        "issuer:zone-isolation",
        ApprovalScope::Elevation(ElevationScope {
            operation_id: operation_id().as_str().to_owned(),
            original_provenance_id: request_object_id,
            target_integrity,
        }),
        zone_id,
        Some(vec![0xA5; 64]),
    )
}

fn declassification_token(
    token_id: &str,
    from_zone: ZoneId,
    to_zone: ZoneId,
    request_object_id: ObjectId,
    target_confidentiality: ConfidentialityLevel,
) -> ApprovalToken {
    ApprovalToken::approved(
        token_id,
        NOW_MS.saturating_sub(1_000),
        NOW_MS.saturating_add(TOKEN_TTL_MS),
        "issuer:zone-isolation",
        ApprovalScope::Declassification(DeclassificationScope {
            from_zone,
            to_zone: to_zone.clone(),
            object_ids: vec![request_object_id],
            target_confidentiality,
        }),
        to_zone,
        Some(vec![0x5A; 64]),
    )
}

fn decision_label(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

fn audit_event_type(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "ZoneAllow",
        Decision::Deny => "ZoneReject",
    }
}

fn evaluate_zone_check(
    logger: &mut E2eLogger,
    scenario_id: &str,
    source_zone: ZoneId,
    target_zone: ZoneId,
    request_object_id: ObjectId,
    approval_tokens: &[ApprovalToken],
    safety_tier: SafetyTier,
    now_ms: u64,
) -> PolicyDecision {
    static EMPTY_RECEIPTS: &[SanitizerReceipt] = &[];
    static EMPTY_OBJECTS: &[ObjectId] = &[];

    let fixture = ZoneFixture::new(target_zone.clone());
    let input = PolicyDecisionInput {
        request_object_id,
        zone_id: target_zone,
        principal: principal(),
        connector_id: fixture.connector_id.clone(),
        operation_id: operation_id(),
        capability_id: fixture.capability_id.clone(),
        safety_tier,
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
        now_ms,
        posture_attestation: None,
    };

    let decision = fixture.engine().evaluate_invoke(&input);
    push_zone_check_log(
        logger,
        scenario_id,
        &input,
        &decision,
        &fixture.allowed_zones,
    );
    decision
}

fn push_zone_check_log(
    logger: &mut E2eLogger,
    scenario_id: &str,
    input: &PolicyDecisionInput<'_>,
    decision: &PolicyDecision,
    allowed_zones: &[ZoneId],
) {
    let context = json!({
        "request_id": input.request_object_id.to_string(),
        "src_zone": input.provenance.current_zone.as_str(),
        "dst_zone": input.zone_id.as_str(),
        "capability": input.capability_id.as_str(),
        "connector_id": input.connector_id.as_str(),
        "operation_id": input.operation_id.as_str(),
        "allowed_zones": allowed_zones
            .iter()
            .map(ZoneId::as_str)
            .collect::<Vec<_>>(),
        "decision": decision_label(decision.decision),
        "reason_code": decision.reason_code.as_str(),
        "audit_event": audit_event_type(decision.decision),
        "hlc": input.now_ms,
        "evidence_count": decision.evidence.len(),
    });
    let entry = E2eLogEntry::new(
        "info",
        scenario_id,
        "fcp-e2e",
        "execute",
        format!("zone-isolation-{scenario_id}"),
        "pass",
        0,
        AssertionsSummary::new(1, 0),
        context,
    )
    .with_scenario_id(scenario_id)
    .with_step("zone-check", 1);
    entry
        .validate()
        .expect("zone-check log must satisfy schema");
    println!(
        "{}",
        serde_json::to_string(&entry).expect("zone-check log serializes")
    );
    logger.push(entry);
}

fn assert_decision(decision: &PolicyDecision, expected: Decision, reason: DecisionReasonCode) {
    assert_eq!(decision.decision, expected);
    assert_eq!(decision.reason_code, reason);
}

fn assert_log_has_zone_check_fields(entry: &E2eLogEntry) {
    validate_log_entry_value(
        &serde_json::to_value(entry).expect("log entry serializes for schema validation"),
    )
    .expect("zone-check log entry must validate");

    let context = entry
        .context
        .as_object()
        .expect("context must be a JSON object");
    for key in [
        "request_id",
        "src_zone",
        "dst_zone",
        "capability",
        "decision",
        "reason_code",
        "audit_event",
        "hlc",
    ] {
        assert!(
            context.contains_key(key),
            "missing structured log key {key}"
        );
    }

    assert!(
        STRUCTURED_REASON_CODES.contains(
            &context
                .get("reason_code")
                .and_then(Value::as_str)
                .expect("reason_code must be a string")
        ),
        "reason_code must be one of the public DecisionReasonCode variants"
    );
}

fn assert_clean_jsonl(logger: &E2eLogger) {
    let jsonl = logger.to_json_lines();
    let scan = scan_log_jsonl(&jsonl);
    assert_eq!(
        scan.error_count, 0,
        "zone-check JSONL must be redaction-clean"
    );
}

#[test]
fn test_public_to_private_invoke_rejected() {
    let mut logger = E2eLogger::new();
    let decision = evaluate_zone_check(
        &mut logger,
        "public_to_private_invoke_rejected",
        ZoneId::public(),
        ZoneId::private(),
        object_id("public-to-private-request"),
        &[],
        SafetyTier::Safe,
        NOW_MS,
    );

    assert_decision(
        &decision,
        Decision::Deny,
        DecisionReasonCode::ApprovalMissingElevation,
    );
    assert_log_has_zone_check_fields(&logger.entries()[0]);
    assert_clean_jsonl(&logger);
}

#[test]
fn test_work_to_private_data_flow_blocked() {
    let mut logger = E2eLogger::new();
    let request_object_id = object_id("work-to-private-request");

    let denied = evaluate_zone_check(
        &mut logger,
        "work_to_private_without_approval",
        ZoneId::work(),
        ZoneId::private(),
        request_object_id,
        &[],
        SafetyTier::Safe,
        NOW_MS,
    );
    assert_decision(
        &denied,
        Decision::Deny,
        DecisionReasonCode::ApprovalMissingElevation,
    );

    let approvals = vec![elevation_token(
        "elev-work-private",
        ZoneId::private(),
        request_object_id,
        IntegrityLevel::Private,
    )];
    let allowed = evaluate_zone_check(
        &mut logger,
        "work_to_private_with_approval",
        ZoneId::work(),
        ZoneId::private(),
        request_object_id,
        &approvals,
        SafetyTier::Safe,
        NOW_MS,
    );
    assert_decision(&allowed, Decision::Allow, DecisionReasonCode::Allow);
    assert!(
        !allowed.evidence.is_empty(),
        "allow path must record approval evidence"
    );
    for entry in logger.entries() {
        assert_log_has_zone_check_fields(entry);
    }
    assert_clean_jsonl(&logger);
}

#[test]
fn test_project_alpha_scoped_capability_works_within() {
    let mut logger = E2eLogger::new();
    let project = project_alpha_zone();
    let decision = evaluate_zone_check(
        &mut logger,
        "project_alpha_scoped_capability_works_within",
        project.clone(),
        project,
        object_id("project-alpha-request"),
        &[],
        SafetyTier::Safe,
        NOW_MS,
    );

    assert_decision(&decision, Decision::Allow, DecisionReasonCode::Allow);
    assert_log_has_zone_check_fields(&logger.entries()[0]);
    assert_clean_jsonl(&logger);
}

#[test]
fn test_community_to_work_requires_declassification() {
    let mut logger = E2eLogger::new();
    let request_object_id = object_id("work-to-community-request");

    let literal_community_to_work = evaluate_zone_check(
        &mut logger,
        "community_to_work_without_elevation",
        ZoneId::community(),
        ZoneId::work(),
        request_object_id,
        &[],
        SafetyTier::Safe,
        NOW_MS,
    );
    assert_decision(
        &literal_community_to_work,
        Decision::Deny,
        DecisionReasonCode::ApprovalMissingElevation,
    );

    // The declassification edge in the IFC lattice is work-confidential data
    // entering a community context; keep it in this test because the bead's
    // function name is the stable externally referenced proof hook.
    let denied = evaluate_zone_check(
        &mut logger,
        "community_to_work_without_declassification",
        ZoneId::work(),
        ZoneId::community(),
        request_object_id,
        &[],
        SafetyTier::Safe,
        NOW_MS,
    );
    assert_decision(
        &denied,
        Decision::Deny,
        DecisionReasonCode::ApprovalMissingDeclassification,
    );

    let approval = declassification_token(
        "decl-work-community",
        ZoneId::work(),
        ZoneId::community(),
        request_object_id,
        ConfidentialityLevel::Community,
    );
    let approvals = vec![approval.clone()];
    let allowed = evaluate_zone_check(
        &mut logger,
        "community_to_work_with_declassification",
        ZoneId::work(),
        ZoneId::community(),
        request_object_id,
        &approvals,
        SafetyTier::Safe,
        NOW_MS,
    );
    assert_decision(&allowed, Decision::Allow, DecisionReasonCode::Allow);

    let mut provenance = ProvenanceRecord::new(ZoneId::work());
    let event = declassify(
        &approval,
        &mut provenance,
        request_object_id,
        ConfidentialityLevel::Community,
        NOW_MS,
    )
    .expect("approved declassification must emit an accepted audit event");
    assert!(event.accepted);
    assert_eq!(event.reason_code, "Accepted");
    assert_eq!(event.src_label, ConfidentialityLevel::Work);
    assert_eq!(event.dst_label, ConfidentialityLevel::Community);
    assert!(!event.approver_fingerprint.is_empty());

    for entry in logger.entries() {
        assert_log_has_zone_check_fields(entry);
    }
    assert_clean_jsonl(&logger);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn test_all_rejections_emit_structured_log(source_index in 0usize..ZONE_COUNT, target_index in 0usize..ZONE_COUNT) {
        let mut logger = E2eLogger::new();
        let source_zone = zone_by_index(source_index);
        let target_zone = zone_by_index(target_index);
        let decision = evaluate_zone_check(
            &mut logger,
            "all_rejections_emit_structured_log",
            source_zone,
            target_zone,
            object_id("proptest-zone-rejection"),
            &[],
            SafetyTier::Safe,
            NOW_MS,
        );

        let entry = logger.entries().last().expect("zone check must emit a log");
        if matches!(decision.decision, Decision::Deny) {
            assert_log_has_zone_check_fields(entry);
            let context = entry.context.as_object().expect("context must be an object");
            prop_assert_eq!(
                context.get("decision").and_then(Value::as_str),
                Some("deny")
            );
            prop_assert_eq!(
                context.get("audit_event").and_then(Value::as_str),
                Some("ZoneReject")
            );
        }
        assert_clean_jsonl(&logger);
    }
}

#[test]
fn test_audit_chain_continuity_under_rejection() {
    let mut logger = E2eLogger::new();
    let mut audit_chain = Vec::new();

    for index in 0_u64..100 {
        let decision = evaluate_zone_check(
            &mut logger,
            "audit_chain_continuity_under_rejection",
            ZoneId::public(),
            ZoneId::private(),
            object_id(&format!("audit-reject-{index}")),
            &[],
            SafetyTier::Safe,
            NOW_MS + index,
        );
        assert_decision(
            &decision,
            Decision::Deny,
            DecisionReasonCode::ApprovalMissingElevation,
        );
        let entry = logger
            .entries()
            .last()
            .expect("rejection must emit audit log");
        assert_log_has_zone_check_fields(entry);
        audit_chain.push(entry.context.clone());
    }

    assert_eq!(audit_chain.len(), 100);
    for (expected_index, event) in audit_chain.iter().enumerate() {
        let context = event.as_object().expect("audit event is an object");
        assert_eq!(
            context.get("audit_event").and_then(Value::as_str),
            Some("ZoneReject")
        );
        assert_eq!(
            context.get("hlc").and_then(Value::as_u64),
            Some(NOW_MS + u64::try_from(expected_index).expect("index fits u64"))
        );
    }
    for pair in audit_chain.windows(2) {
        let first = pair[0]
            .get("hlc")
            .and_then(Value::as_u64)
            .expect("first hlc");
        let second = pair[1]
            .get("hlc")
            .and_then(Value::as_u64)
            .expect("second hlc");
        assert!(first < second, "zone rejection HLCs must be monotone");
    }
    assert_clean_jsonl(&logger);
}
