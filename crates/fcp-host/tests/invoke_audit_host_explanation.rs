//! Keep audit explanations aligned with the production host emitter, not only
//! hand-written examples of the wire format. No provider or host server needed.

use fcp_audit::explain::{CausalReasonKind, ReplayBundle, explain_bundle, parse_replay_bundle};
use fcp_audit::explain::host::{HostRequestOutcome, explain_host_request};
use fcp_host::{InvokeAuditChain, InvokeAuditContext, InvokePhase};

fn context(request_id: &str) -> InvokeAuditContext {
    InvokeAuditContext {
        zone_id: "z:work".to_owned(),
        actor: "agent:audit-test".to_owned(),
        connector_id: "github".to_owned(),
        operation: "issues.create".to_owned(),
        operation_id: request_id.to_owned(),
        correlation_id: Some("shared-client-correlation".to_owned()),
        occurred_at: 1_700_000_000,
    }
}

#[test]
fn production_interleaved_requests_are_explained_by_server_id() {
    let chain = InvokeAuditChain::new();
    let first = context("server-request-a");
    let second = context("server-request-b");
    let entries = vec![
        chain.append(&first, InvokePhase::PreflightAllow).unwrap(),
        chain.append(&second, InvokePhase::PreflightAllow).unwrap(),
        chain.append(&second, InvokePhase::DispatchResult {
            receipt_id: None,
            success: false,
            duration_ms: 9,
        }).unwrap(),
        chain.append(&first, InvokePhase::DispatchResult {
            receipt_id: Some("receipt-a".to_owned()),
            success: true,
            duration_ms: 17,
        }).unwrap(),
    ];
    assert!(fcp_audit::verify_chain(&entries, None, Some("z:work")).is_clean());
    let jsonl = entries.iter().map(|entry| serde_json::to_string(entry).unwrap())
        .collect::<Vec<_>>().join("\n");
    let bundle = parse_replay_bundle(&jsonl).unwrap();
    let result = explain_bundle(&bundle).unwrap();
    let summary = result.host_request.as_ref().unwrap();
    assert_eq!(summary.request_id, "server-request-a");
    assert_eq!(summary.outcome, HostRequestOutcome::ReportedSuccess);
    assert_eq!(summary.observed_phase_count, 2);
    assert_eq!(summary.duration_ms, Some(17));
    assert_eq!(summary.reported_receipt_id.as_deref(), Some("receipt-a"));
    assert_eq!(result.operation_id, "issues.create");
    assert_eq!(summary.last_seq - summary.first_seq, 3);
    assert!(result.reasons.iter().all(|reason| reason.kind == CausalReasonKind::HostLifecycle));
    let other = explain_host_request(&bundle, "z:work", "server-request-b").unwrap();
    assert_eq!(other.host_request.unwrap().outcome, HostRequestOutcome::ReportedFailure);
}

#[test]
fn production_denial_is_not_rendered_as_an_invocation() {
    let chain = InvokeAuditChain::new();
    let denied = chain.append(&context("denied-request"), InvokePhase::PreflightDeny {
        reason: "capability missing: private-provider-error".to_owned(),
    }).unwrap();
    let bundle = ReplayBundle { audit_entries: vec![denied], ..ReplayBundle::default() };
    let result = explain_bundle(&bundle).unwrap();
    assert_eq!(result.host_request.as_ref().unwrap().outcome, HostRequestOutcome::Denied);
    assert!(!result.render_human().contains("invoked operation"));
    assert!(!result.render_human().contains("private-provider-error"));
}

#[test]
fn production_dispatch_error_without_admission_keeps_execution_uncertain() {
    let chain = InvokeAuditChain::new();
    let mut ctx = context("failed-request");
    ctx.correlation_id = None;
    let failed = chain.append(&ctx, InvokePhase::DispatchError {
        error: "registry lookup failed".to_owned(),
        duration_ms: 0,
    }).unwrap();
    let bundle = ReplayBundle { audit_entries: vec![failed], ..ReplayBundle::default() };
    let result = explain_bundle(&bundle).unwrap();
    let summary = result.host_request.as_ref().unwrap();
    assert_eq!(summary.outcome, HostRequestOutcome::DispatchError);
    assert!(!summary.admission_observed);
    assert_eq!(summary.duration_ms, Some(0));
    assert!(result.correlation_id.is_none());
    assert!(result.render_human().contains("retry safety are unknown"));
}

#[test]
fn production_mesh_response_remains_entry_host_custody_not_connector_success() {
    let chain = InvokeAuditChain::new();
    let ctx = context("relayed-request");
    let attempt = chain.append(&ctx, InvokePhase::MeshForwardAttempt {
        target_node: "peer-a".to_owned(),
        decision: "mesh_selected".to_owned(),
    }).unwrap();
    let response = chain.append(&ctx, InvokePhase::MeshForwarded {
        target_node: "peer-a".to_owned(),
        decision: "mesh_selected".to_owned(),
        executor_status: Some(200),
        failed_attempts: Vec::new(),
        duration_ms: 29,
    }).unwrap();
    let entries = vec![attempt, response];
    assert!(fcp_audit::verify_chain(&entries, None, Some("z:work")).is_clean());
    let json = serde_json::to_string(&entries).unwrap();
    let explanation = explain_bundle(&parse_replay_bundle(&json).unwrap()).unwrap();
    let summary = explanation.host_request.as_ref().unwrap();
    assert_eq!(summary.outcome, HostRequestOutcome::RelayResponse);
    assert!(!summary.admission_observed);
    assert_eq!(summary.reported_success, None);
    assert_eq!(summary.duration_ms, Some(29));
    let relay = summary.relay.as_ref().unwrap();
    assert_eq!(relay.observed_targets, ["peer-a"]);
    assert_eq!(relay.reported_executor_status, Some(200));
    assert!(explanation.render_human().contains("not a connector success receipt"));
}

#[test]
fn production_mesh_absent_response_is_unconfirmed_not_safe_to_retry() {
    let chain = InvokeAuditChain::new();
    let failed = chain.append(&context("unconfirmed-request"), InvokePhase::MeshForwarded {
        target_node: "peer-a".to_owned(),
        decision: "mesh_delivery_failed".to_owned(),
        executor_status: None,
        failed_attempts: vec!["peer-a".to_owned()],
        duration_ms: 40,
    }).unwrap();
    let bundle = ReplayBundle { audit_entries: vec![failed], ..ReplayBundle::default() };
    let result = explain_bundle(&bundle).unwrap();
    let summary = result.host_request.as_ref().unwrap();
    assert_eq!(summary.outcome, HostRequestOutcome::RelayUnconfirmed);
    assert_eq!(summary.reported_success, None);
    assert_eq!(summary.relay.as_ref().unwrap().reported_failed_attempt_count, Some(1));
    assert!(result.render_human().contains("retry safety remain unknown"));
    assert!(result.render_human().contains("routing history is incomplete"));
}
