//! Policy simulation unit tests with structured JSONL logging.

use chrono::Utc;
use fcp_conformance::schemas::validate_e2e_log_jsonl;
use fcp_prelude::{
    ApprovalScope, ApprovalToken, CapabilityId, DecisionReasonCode, InvokeRequest, OperationId,
    PolicySimulationInput, ProvenanceRecord, SafetyTier, TransportMode, ZoneId, ZonePolicyObject,
    ZoneTransportPolicy, simulate_policy_decision,
};
use fcp_testkit::LogCapture;
use serde_json::json;
use uuid::Uuid;

const NOW_MS: u64 = 1_700_000_000_000;

#[test]
fn simulation_missing_capability_denies_with_reason() {
    let zone = ZoneId::work();
    let mut policy = base_policy(zone.clone());
    policy.capability_ceiling = vec![CapabilityId::from_static("cap.allowed")];

    let invoke = base_invoke(zone);
    let mut input = base_simulation_input(policy, invoke);
    input.principal = Some("user:alice".to_string());
    input.capability_id = Some("cap.denied".to_string());

    let receipt = simulate_policy_decision(&input).expect("simulate policy decision");
    assert!(receipt.is_deny());
    assert_eq!(
        receipt.reason_code,
        DecisionReasonCode::CapabilityInsufficient.as_str()
    );

    emit_and_validate_log(
        "policy_sim_missing_capability",
        "pass",
        &receipt.reason_code,
    );
}

#[test]
fn simulation_stale_revocation_denies() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());

    let invoke = base_invoke(zone);
    let mut input = base_simulation_input(policy, invoke);
    input.principal = Some("user:alice".to_string());
    input.revocation_fresh = false;

    let receipt = simulate_policy_decision(&input).expect("simulate policy decision");
    assert!(receipt.is_deny());
    assert_eq!(
        receipt.reason_code,
        DecisionReasonCode::RevocationStaleFrontier.as_str()
    );

    emit_and_validate_log("policy_sim_revocation_stale", "pass", &receipt.reason_code);
}

#[test]
fn simulation_execution_approval_allows() {
    let zone = ZoneId::work();
    let policy = base_policy(zone.clone());

    let mut invoke = base_invoke(zone);
    invoke.approval_tokens.push(execution_approval(&invoke));

    let mut input = base_simulation_input(policy, invoke);
    input.principal = Some("user:alice".to_string());
    input.execution_approval_required = true;

    let receipt = simulate_policy_decision(&input).expect("simulate policy decision");
    assert!(receipt.is_allow());
    assert_eq!(receipt.reason_code, DecisionReasonCode::Allow.as_str());

    emit_and_validate_log(
        "policy_sim_execution_approval",
        "pass",
        &receipt.reason_code,
    );
}

fn base_policy(zone: ZoneId) -> ZonePolicyObject {
    ZonePolicyObject {
        header: test_header("ZonePolicyObject", zone.clone()),
        zone_id: zone,
        principal_allow: vec![fcp_core::PolicyPattern {
            pattern: "user:*".to_string(),
        }],
        principal_deny: Vec::new(),
        connector_allow: vec![fcp_core::PolicyPattern {
            pattern: "connector:*".to_string(),
        }],
        connector_deny: Vec::new(),
        capability_allow: Vec::new(),
        capability_deny: Vec::new(),
        capability_ceiling: Vec::new(),
        transport_policy: ZoneTransportPolicy::default(),
        decision_receipts: fcp_core::DecisionReceiptPolicy::default(),
        usage_budget: None,
        requires_posture: None,
    }
}

fn base_invoke(zone: ZoneId) -> InvokeRequest {
    InvokeRequest {
        r#type: "invoke".to_string(),
        id: fcp_core::RequestId::new("req-test"),
        connector_id: fcp_core::ConnectorId::from_static("connector:test"),
        operation: OperationId::from_static("op.read"),
        zone_id: zone,
        input: json!({"value": 1}),
        capability_token: fcp_core::CapabilityToken::test_token(),
        holder_proof: None,
        context: None,
        idempotency_key: None,
        lease_seq: None,
        deadline_ms: None,
        correlation_id: None,
        provenance: None,
        approval_tokens: Vec::new(),
    }
}

fn base_simulation_input(
    zone_policy: ZonePolicyObject,
    invoke_request: InvokeRequest,
) -> PolicySimulationInput {
    PolicySimulationInput {
        zone_policy,
        invoke_request,
        transport: TransportMode::Lan,
        checkpoint_fresh: true,
        revocation_fresh: true,
        execution_approval_required: false,
        sanitizer_receipts: Vec::new(),
        related_object_ids: Vec::new(),
        request_object_id: None,
        request_input_hash: None,
        safety_tier: SafetyTier::Safe,
        principal: None,
        capability_id: None,
        provenance_record: Some(ProvenanceRecord::new(ZoneId::work())),
        now_ms: Some(NOW_MS),
        posture_attestation: None,
    }
}

fn execution_approval(invoke: &InvokeRequest) -> ApprovalToken {
    ApprovalToken {
        token_id: "token-1".to_string(),
        issued_at_ms: NOW_MS - 1000,
        expires_at_ms: NOW_MS + 1000,
        issuer: "owner".to_string(),
        scope: ApprovalScope::Execution(fcp_core::ExecutionScope {
            connector_id: invoke.connector_id.as_str().to_string(),
            method_pattern: invoke.operation.as_str().to_string(),
            request_object_id: None,
            input_hash: None,
            input_constraints: Vec::new(),
        }),
        zone_id: invoke.zone_id.clone(),
        signature: None,
        _state: std::marker::PhantomData,
    }
}

fn test_header(kind: &str, zone: ZoneId) -> fcp_core::ObjectHeader {
    fcp_core::ObjectHeader {
        encryption_kind: fcp_core::ObjectEncryptionKind::default(),
        schema: fcp_cbor::SchemaId::new("fcp.core", kind, semver::Version::new(1, 0, 0)),
        zone_id: zone.clone(),
        created_at: NOW_MS / 1000,
        provenance: fcp_core::Provenance::new(zone),
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

fn emit_and_validate_log(test_name: &str, result: &str, reason_code: &str) {
    let capture = LogCapture::new();
    let correlation_id = Uuid::new_v4().to_string();
    let entry = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "test_name": test_name,
        "module": "fcp-testkit",
        "phase": "assert",
        "correlation_id": correlation_id,
        "result": result,
        "duration_ms": 1,
        "assertions": {"passed": 1, "failed": 0},
        "context": {"reason_code": reason_code}
    });
    capture.push_line(&serde_json::to_string(&entry).expect("serialize log entry"));

    let payload = capture.jsonl();
    validate_e2e_log_jsonl(&payload).expect("validate jsonl log schema");
}
