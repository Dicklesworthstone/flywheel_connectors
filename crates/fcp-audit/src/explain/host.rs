//! Explanations of the host's real `invoke.*` audit vocabulary.
//!
//! Host `operation_id` is a server-assigned request ID; `metadata.operation`
//! is the connector method. Client correlations may be absent or reused.
//! This module interprets captured phases from ONE host chain. It does not
//! fetch live state, authenticate a capture, infer capability predicates, or
//! establish that an external side effect committed.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{CausalExplanation, CausalReason, CausalReasonKind, ExplainError, ReplayBundle};
use crate::AuditEntry;

/// Outcome reported by captured host phases, not current execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostRequestOutcome {
    /// Preflight passed, but the capture contains no terminal phase.
    Admitted,
    /// Preflight denied the request before connector dispatch.
    Denied,
    /// The host recorded a successful dispatch response.
    ReportedSuccess,
    /// The host recorded an unsuccessful dispatch response.
    ReportedFailure,
    /// Dispatch failed before or during execution; side effects are unknown.
    DispatchError,
    /// A dispatch response was captured without its preceding admission.
    Incomplete,
    /// The entry host recorded a relay attempt, without a terminal response.
    RelayPending,
    /// The entry host received a peer response, not proof of connector success.
    RelayResponse,
    /// The relay ended without a peer response; delivery and effects are unknown.
    RelayUnconfirmed,
}

impl HostRequestOutcome {
    /// Stable spelling for JSON and human output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Denied => "denied",
            Self::ReportedSuccess => "reported_success",
            Self::ReportedFailure => "reported_failure",
            Self::DispatchError => "dispatch_error",
            Self::Incomplete => "incomplete",
            Self::RelayPending => "relay_pending",
            Self::RelayResponse => "relay_response",
            Self::RelayUnconfirmed => "relay_unconfirmed",
        }
    }
}

/// Request-scoped facts observed in one captured host chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRequestSummary {
    /// Server-assigned ID, independent of the connector method and correlation.
    pub request_id: String,
    /// Captured outcome; never a claim about current state or authorization.
    pub outcome: HostRequestOutcome,
    /// Whether `invoke.allow` was captured for this request.
    pub admission_observed: bool,
    /// Whether a terminal denial, response, or error was captured.
    pub terminal_observed: bool,
    /// Number of distinct captured phases after identical-entry deduplication.
    pub observed_phase_count: usize,
    /// First observed sequence in the zone's host chain.
    pub first_seq: u64,
    /// Last observed sequence; intervening entries can belong to other requests.
    pub last_seq: u64,
    /// Timestamp of the last observed phase, not a reconstructed completion time.
    pub last_observed_at: u64,
    /// Reported dispatch success flag, only when a result phase was captured.
    pub reported_success: Option<bool>,
    /// Reported host duration, not a difference of clamped audit timestamps.
    pub duration_ms: Option<u64>,
    /// Connector-supplied receipt reference; the receipt itself is not verified.
    pub reported_receipt_id: Option<String>,
    /// Entry-host routing evidence, never borrowed as executor authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<HostRelaySummary>,
}

/// Routing custody reported by the entry host for one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRelaySummary {
    /// Targets in captured attempt order; may omit attempts outside the capture.
    pub observed_targets: Vec<String>,
    /// Peer named by the terminal relay record, if one was captured.
    pub reported_terminal_target: Option<String>,
    /// Peer HTTP-equivalent response status; a 2xx is not connector success.
    pub reported_executor_status: Option<u16>,
    /// Count of failures reported by the terminal record, not a verified history.
    pub reported_failed_attempt_count: Option<usize>,
}

/// Explain a host request by its zone and server-assigned request ID.
///
/// The newest captured phase selects the request. All captured phases for
/// that exact zone/request are checked, even when their scope disagrees.
/// The caller must not concatenate chains from different hosts without an
/// independently established common source identity.
///
/// # Errors
///
/// Returns [`ExplainError::NoInvocation`] for an absent request and
/// [`ExplainError::InvalidHostLifecycle`] for incomplete identities, conflicting
/// captures, malformed phase payloads, or contradictory lifecycle ordering.
pub fn explain_host_request(
    bundle: &ReplayBundle,
    zone_id: &str,
    request_id: &str,
) -> Result<CausalExplanation, ExplainError> {
    let selected = bundle
        .audit_entries
        .iter()
        .filter(|entry| {
            is_host_event(entry)
                && entry.zone_id == zone_id
                && entry.operation_id.as_deref() == Some(request_id)
        })
        .max_by_key(|entry| (entry.seq, entry.occurred_at, entry.id.as_str()))
        .ok_or(ExplainError::NoInvocation)?;
    explain_request_at_entry(bundle, selected)
}

pub(super) fn is_host_event(entry: &AuditEntry) -> bool {
    // Unknown host phases must fail explicitly, not reveal an older success.
    entry.event_type.starts_with("invoke.")
}

pub(super) fn explain_request_at_entry(
    bundle: &ReplayBundle,
    selected: &AuditEntry,
) -> Result<CausalExplanation, ExplainError> {
    validate_identity(selected)?;
    let request_id = selected.operation_id.as_deref().ok_or(invalid("missing request ID"))?;
    let operation = required_string(selected, "operation")?;
    let entries = request_entries(bundle, selected, operation)?;
    let first = entries.first().ok_or(ExplainError::NoInvocation)?;
    let mut summary = HostRequestSummary {
        request_id: request_id.to_owned(),
        outcome: HostRequestOutcome::Incomplete,
        admission_observed: false,
        terminal_observed: false,
        observed_phase_count: entries.len(),
        first_seq: first.seq,
        last_seq: first.seq,
        last_observed_at: first.occurred_at,
        reported_success: None,
        duration_ms: None,
        reported_receipt_id: None,
        relay: None,
    };
    let mut reasons = Vec::with_capacity(entries.len());
    let mut warnings = vec![
        "captured host phases are not authenticated by this explanation; verify chain integrity and signatures separately".to_owned(),
        "phase evidence does not establish current authorization, complete capture, or committed external side effects".to_owned(),
    ];
    for entry in entries {
        if summary.terminal_observed {
            return Err(invalid("a request has phases after a terminal outcome"));
        }
        summary.last_seq = entry.seq;
        summary.last_observed_at = entry.occurred_at;
        let statement = observe_phase(entry, &mut summary, &mut warnings)?;
        reasons.push(CausalReason {
            kind: CausalReasonKind::HostLifecycle,
            statement: statement.to_owned(),
            evidence: vec![format!("audit_entry:{}", entry.id)],
        });
    }
    if !summary.terminal_observed {
        warnings.push("no terminal phase was captured; the request may still be running or the capture may be incomplete".to_owned());
    }
    // Native phases do not carry capability predicate traces. Never fabricate
    // a grant, verified receipt, or revocation verdict from coarse phase flags.
    warnings.push("capability predicates and revocation status are not established by host lifecycle events".to_owned());
    Ok(CausalExplanation {
        connector_id: selected.connector_id.clone().ok_or(invalid("missing connector ID"))?,
        operation_id: operation.to_owned(),
        occurred_at: selected.occurred_at,
        actor: selected.actor.clone(),
        zone_id: selected.zone_id.clone(),
        correlation_id: (!selected.correlation_id.is_empty()).then(|| selected.correlation_id.clone()),
        invocation_audit_entry_id: selected.id.clone(),
        reasons,
        warnings,
        host_request: Some(summary),
    })
}

fn observe_phase(
    entry: &AuditEntry,
    summary: &mut HostRequestSummary,
    warnings: &mut Vec<String>,
) -> Result<&'static str, ExplainError> {
    Ok(match entry.event_type.as_str() {
        "invoke.allow" => {
            if summary.admission_observed || summary.relay.is_some() {
                return Err(invalid("preflight admission follows admission or relay"));
            }
            summary.admission_observed = true;
            summary.outcome = HostRequestOutcome::Admitted;
            "host recorded preflight admission; this alone does not establish dispatch or completion"
        }
        "invoke.deny" => {
            if summary.admission_observed || summary.relay.is_some() {
                return Err(invalid("a preflight denial follows admission or relay"));
            }
            summary.outcome = HostRequestOutcome::Denied;
            summary.terminal_observed = true;
            "host recorded preflight denial before connector dispatch"
        }
        "invoke.result" => {
            if summary.relay.is_some() {
                return Err(invalid("local dispatch result cannot complete an entry-host relay"));
            }
            let success = entry.metadata.get("success").and_then(Value::as_bool)
                .ok_or(invalid("dispatch result requires a boolean success flag"))?;
            summary.duration_ms = Some(required_duration(entry)?);
            summary.reported_receipt_id = optional_string(entry, "receipt_id")?.map(str::to_owned);
            summary.reported_success = Some(success);
            summary.terminal_observed = true;
            summary.outcome = if !summary.admission_observed {
                warnings.push("dispatch result has no captured admission; the authorization path is unknown".to_owned());
                HostRequestOutcome::Incomplete
            } else if success {
                HostRequestOutcome::ReportedSuccess
            } else {
                HostRequestOutcome::ReportedFailure
            };
            "host recorded a dispatch response; its receipt reference is not receipt verification"
        }
        "invoke.error" => {
            summary.duration_ms = Some(required_duration(entry)?);
            summary.terminal_observed = true;
            summary.outcome = HostRequestOutcome::DispatchError;
            warnings.push("a dispatch error may occur before or during execution; external side effects and retry safety are unknown".to_owned());
            "host recorded a dispatch error, not a successful connector response"
        }
        "invoke.mesh_forward_attempt" => observe_relay_attempt(entry, summary)?,
        "invoke.mesh_forwarded" => observe_relay_response(entry, summary, warnings)?,
        _ => return Err(invalid("unsupported host request phase")),
    })
}

fn relay_summary(summary: &mut HostRequestSummary) -> &mut HostRelaySummary {
    summary.relay.get_or_insert_with(|| HostRelaySummary {
        observed_targets: Vec::new(),
        reported_terminal_target: None,
        reported_executor_status: None,
        reported_failed_attempt_count: None,
    })
}

fn observe_relay_attempt(
    entry: &AuditEntry,
    summary: &mut HostRequestSummary,
) -> Result<&'static str, ExplainError> {
    let target = required_string(entry, "target_node")?;
    required_string(entry, "decision")?;
    relay_summary(summary).observed_targets.push(target.to_owned());
    summary.outcome = HostRequestOutcome::RelayPending;
    Ok("entry host recorded a relay attempt; this is not delivery or executor-admission evidence")
}

fn observe_relay_response(
    entry: &AuditEntry,
    summary: &mut HostRequestSummary,
    warnings: &mut Vec<String>,
) -> Result<&'static str, ExplainError> {
    let target = required_string(entry, "target_node")?;
    required_string(entry, "decision")?;
    let status = match entry.metadata.get("executor_status") {
        Some(Value::Null) => None,
        Some(value) => Some(value.as_u64().filter(|status| (100..=599).contains(status))
            .and_then(|status| u16::try_from(status).ok())
            .ok_or(invalid("relay executor_status must be null or a valid HTTP status"))?),
        None => return Err(invalid("relay record is missing executor_status")),
    };
    let failures = entry.metadata.get("failed_attempts").and_then(Value::as_array)
        .ok_or(invalid("relay record requires a failed_attempts array"))?;
    if failures.iter().any(|value| value.as_str().is_none_or(|value| value.trim().is_empty())) {
        return Err(invalid("relay failed_attempts must contain nonempty strings"));
    }
    summary.duration_ms = Some(required_duration(entry)?);
    let relay = relay_summary(summary);
    match relay.observed_targets.last() {
        None => warnings.push("relay response has no captured attempt; routing history is incomplete".to_owned()),
        Some(previous) if previous != target => warnings.push("terminal peer differs from the last captured attempt; intervening routing history is missing".to_owned()),
        Some(_) => {}
    }
    relay.reported_terminal_target = Some(target.to_owned());
    relay.reported_executor_status = status;
    relay.reported_failed_attempt_count = Some(failures.len());
    summary.terminal_observed = true;
    summary.outcome = if status.is_some() {
        HostRequestOutcome::RelayResponse
    } else {
        HostRequestOutcome::RelayUnconfirmed
    };
    warnings.push("entry-host relay evidence does not establish executor authorization or connector completion; inspect the executor's independently verified chain".to_owned());
    if status.is_none() {
        warnings.push("no peer response was recorded; delivery, side effects and retry safety remain unknown".to_owned());
    }
    Ok("entry host recorded a relay outcome; a peer HTTP response is not a connector success receipt")
}

fn request_entries<'a>(
    bundle: &'a ReplayBundle,
    selected: &AuditEntry,
    operation: &str,
) -> Result<Vec<&'a AuditEntry>, ExplainError> {
    let mut by_seq = BTreeMap::new();
    let mut by_id = BTreeMap::new();
    for entry in &bundle.audit_entries {
        if !is_host_event(entry) || entry.zone_id != selected.zone_id
            || entry.operation_id != selected.operation_id
        {
            continue;
        }
        validate_identity(entry)?;
        if entry.actor != selected.actor || entry.connector_id != selected.connector_id
            || entry.correlation_id != selected.correlation_id
            || required_string(entry, "operation")? != operation
        {
            return Err(invalid("server request ID has conflicting scope"));
        }
        if let Some(previous) = by_id.insert(entry.id.as_str(), entry)
            && previous != entry
        {
            return Err(invalid("conflicting captures share an audit entry ID"));
        }
        if let Some(previous) = by_seq.insert(entry.seq, entry)
            && previous != entry
        {
            return Err(invalid("distinct request phases share a chain sequence"));
        }
    }
    // Catch an ID reused by a differently scoped or non-host entry too.
    for entry in &bundle.audit_entries {
        if let Some(previous) = by_id.get(entry.id.as_str())
            && *previous != entry
        {
            return Err(invalid("conflicting captures share an audit entry ID"));
        }
    }
    let entries: Vec<_> = by_seq.into_values().collect();
    if entries.windows(2).any(|pair| pair[1].occurred_at < pair[0].occurred_at) {
        return Err(invalid("request timestamps regress in chain order"));
    }
    Ok(entries)
}

fn validate_identity(entry: &AuditEntry) -> Result<(), ExplainError> {
    if entry.id.trim().is_empty() || entry.actor.trim().is_empty() || entry.zone_id.trim().is_empty()
        || entry.connector_id.as_deref().is_none_or(|value| value.trim().is_empty())
        || entry.operation_id.as_deref().is_none_or(|value| value.trim().is_empty())
    {
        return Err(invalid("host phase requires complete request identity"));
    }
    Ok(())
}

fn required_string<'a>(entry: &'a AuditEntry, key: &str) -> Result<&'a str, ExplainError> {
    optional_string(entry, key)?.ok_or(invalid("host phase is missing a required string field"))
}

fn optional_string<'a>(entry: &'a AuditEntry, key: &str) -> Result<Option<&'a str>, ExplainError> {
    entry.metadata.get(key).map(|value| {
        value.as_str().filter(|value| !value.trim().is_empty())
            .ok_or(invalid("host phase has an invalid string field"))
    }).transpose()
}

fn required_duration(entry: &AuditEntry) -> Result<u64, ExplainError> {
    entry.metadata.get("duration_ms").and_then(Value::as_u64)
        .ok_or(invalid("terminal host phase requires an unsigned duration_ms"))
}

const fn invalid(reason: &'static str) -> ExplainError {
    ExplainError::InvalidHostLifecycle(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{explain_bundle, explain_invocation, parse_replay_bundle};
    use crate::{Severity, audit_entry_hlc_from_occurred_at};
    use serde_json::json;

    fn phase(seq: u64, event_type: &str) -> AuditEntry {
        AuditEntry {
            id: format!("phase-{seq}"),
            event_type: event_type.to_owned(),
            severity: Severity::Info,
            actor: "user:alice".to_owned(),
            zone_id: "z:work".to_owned(),
            seq,
            occurred_at: 100 + seq,
            hlc: audit_entry_hlc_from_occurred_at(100 + seq, "user:alice"),
            prev: None,
            correlation_id: String::new(),
            trace_context: None,
            connector_id: Some("github".to_owned()),
            operation_id: Some("request-a".to_owned()),
            metadata: BTreeMap::from([
                ("operation".to_owned(), json!("issues.create")),
                ("success".to_owned(), json!(true)),
                ("duration_ms".to_owned(), json!(17)),
            ]),
            issuer_kid: None,
            signature: None,
        }
    }

    fn bundle(entries: Vec<AuditEntry>) -> ReplayBundle {
        ReplayBundle { audit_entries: entries, ..ReplayBundle::default() }
    }

    #[test]
    fn production_vocabulary_reaches_default_explainer() {
        let evidence = bundle(vec![phase(0, "invoke.allow"), phase(2, "invoke.result")]);
        let result = explain_bundle(&evidence).unwrap();
        let summary = result.host_request.as_ref().unwrap();
        assert_eq!(summary.outcome, HostRequestOutcome::ReportedSuccess);
        assert_eq!(summary.request_id, "request-a");
        assert_eq!(result.operation_id, "issues.create");
        assert_eq!(summary.duration_ms, Some(17));
        assert!(result.correlation_id.is_none());
        assert!(!result.render_human().contains("invoked operation request-a"));
        assert!(result.reasons.iter().all(|reason| reason.kind == CausalReasonKind::HostLifecycle));
    }

    #[test]
    fn admission_and_denial_do_not_claim_completed_dispatch() {
        for (event, outcome) in [("invoke.allow", HostRequestOutcome::Admitted), ("invoke.deny", HostRequestOutcome::Denied)] {
            let result = explain_bundle(&bundle(vec![phase(0, event)])).unwrap();
            assert_eq!(result.host_request.as_ref().unwrap().outcome, outcome);
            assert!(!result.render_human().contains("invoked operation"));
            assert_eq!(result.host_request.as_ref().unwrap().terminal_observed, event == "invoke.deny");
        }
    }

    #[test]
    fn missing_admission_is_not_invented_from_a_result() {
        let result = explain_bundle(&bundle(vec![phase(2, "invoke.result")])).unwrap();
        let summary = result.host_request.unwrap();
        assert_eq!(summary.outcome, HostRequestOutcome::Incomplete);
        assert!(!summary.admission_observed);
        assert_eq!(summary.reported_success, Some(true));
    }

    #[test]
    fn failure_and_error_have_distinct_retry_semantics() {
        let mut failed = phase(2, "invoke.result");
        failed.metadata.insert("success".to_owned(), json!(false));
        let result = explain_bundle(&bundle(vec![phase(0, "invoke.allow"), failed])).unwrap();
        assert_eq!(result.host_request.unwrap().outcome, HostRequestOutcome::ReportedFailure);
        let error = explain_bundle(&bundle(vec![phase(1, "invoke.error")])).unwrap();
        assert_eq!(error.host_request.as_ref().unwrap().outcome, HostRequestOutcome::DispatchError);
        assert!(error.render_human().contains("retry safety are unknown"));
    }

    #[test]
    fn malformed_payloads_fail_without_falling_back_to_admission() {
        for (key, value) in [("success", json!("true")), ("duration_ms", json!(-1)), ("receipt_id", Value::Null), ("operation", json!(false))] {
            let mut result = phase(2, "invoke.result");
            result.metadata.insert(key.to_owned(), value);
            assert!(explain_bundle(&bundle(vec![phase(0, "invoke.allow"), result])).is_err());
        }
    }

    #[test]
    fn contradictory_and_reused_lifecycles_fail() {
        for events in [["invoke.allow", "invoke.deny"], ["invoke.deny", "invoke.result"], ["invoke.result", "invoke.result"], ["invoke.allow", "invoke.allow"], ["invoke.error", "invoke.allow"]] {
            assert!(explain_bundle(&bundle(vec![phase(0, events[0]), phase(1, events[1])])).is_err());
        }
    }

    #[test]
    fn repeated_client_correlations_do_not_merge_server_requests() {
        let first = phase(0, "invoke.deny");
        let mut second = phase(2, "invoke.allow");
        second.operation_id = Some("request-b".to_owned());
        let result = explain_bundle(&bundle(vec![first, second])).unwrap();
        assert_eq!(result.host_request.as_ref().unwrap().request_id, "request-b");
        assert_eq!(result.host_request.unwrap().observed_phase_count, 1);
    }

    #[test]
    fn conflicting_scope_is_not_silently_filtered_out() {
        for key in ["actor", "connector", "correlation", "operation"] {
            let mut result = phase(2, "invoke.result");
            match key {
                "actor" => result.actor = "user:bob".to_owned(),
                "connector" => result.connector_id = Some("slack".to_owned()),
                "correlation" => result.correlation_id = "other".to_owned(),
                _ => { result.metadata.insert("operation".to_owned(), json!("issues.delete")); }
            }
            assert!(explain_bundle(&bundle(vec![phase(0, "invoke.allow"), result])).is_err());
        }
    }

    #[test]
    fn duplicates_and_reordering_do_not_change_the_summary() {
        let admitted = phase(0, "invoke.allow");
        let finished = phase(3, "invoke.result");
        let expected = explain_bundle(&bundle(vec![admitted.clone(), finished.clone()])).unwrap();
        assert_eq!(explain_bundle(&bundle(vec![finished.clone(), admitted.clone(), finished, admitted])).unwrap(), expected);
    }

    #[test]
    fn conflicting_ids_sequences_and_chronology_are_rejected() {
        for field in ["id", "seq", "time"] {
            let admitted = phase(0, "invoke.allow");
            let mut result = phase(2, "invoke.result");
            match field {
                "id" => result.id = admitted.id.clone(),
                "seq" => result.seq = admitted.seq,
                _ => result.occurred_at = admitted.occurred_at - 1,
            }
            assert!(explain_bundle(&bundle(vec![admitted, result])).is_err());
        }
    }

    #[test]
    fn explicit_selection_uses_zone_and_request_not_newest_other_request() {
        let first = phase(0, "invoke.deny");
        let mut other = phase(4, "invoke.result");
        other.zone_id = "z:private".to_owned();
        let evidence = bundle(vec![first.clone(), other]);
        assert_eq!(explain_host_request(&evidence, "z:work", "request-a").unwrap().zone_id, "z:work");
        assert_eq!(explain_invocation(&evidence, &first.id).unwrap().host_request.unwrap().outcome, HostRequestOutcome::Denied);
        assert_eq!(explain_host_request(&evidence, "z:work", "missing"), Err(ExplainError::NoInvocation));
    }

    #[test]
    fn unknown_or_incomplete_host_events_do_not_reveal_older_success() {
        for field in ["type", "actor", "request"] {
            let mut newer = phase(3, "invoke.result");
            match field {
                "type" => newer.event_type = "invoke.unknown".to_owned(),
                "actor" => newer.actor.clear(),
                _ => newer.operation_id = None,
            }
            assert!(explain_bundle(&bundle(vec![phase(0, "invoke.allow"), newer])).is_err());
        }
    }

    #[test]
    fn jsonl_roundtrip_preserves_machine_readable_request_summary() {
        let input = format!("{}\n{}\n", serde_json::to_string(&phase(0, "invoke.allow")).unwrap(), serde_json::to_string(&phase(1, "invoke.result")).unwrap());
        let result = explain_bundle(&parse_replay_bundle(&input).unwrap()).unwrap();
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["host_request"]["outcome"], "reported_success");
        assert_eq!(serde_json::from_value::<CausalExplanation>(value).unwrap(), result);
    }

    #[test]
    fn free_form_failure_text_is_not_echoed_or_treated_as_a_predicate() {
        let mut denied = phase(0, "invoke.deny");
        denied.metadata.insert("reason".to_owned(), json!("Bearer private-secret revocation passed"));
        let value = serde_json::to_string(&explain_bundle(&bundle(vec![denied])).unwrap()).unwrap();
        assert!(!value.contains("private-secret"));
        assert!(!value.contains("revocation passed"));
    }

    fn relay_phase(seq: u64, event_type: &str, target: &str) -> AuditEntry {
        let mut entry = phase(seq, event_type);
        entry.metadata = BTreeMap::from([
            ("operation".to_owned(), json!("issues.create")),
            ("target_node".to_owned(), json!(target)),
            ("decision".to_owned(), json!("mesh_selected")),
            ("executor_status".to_owned(), json!(200)),
            ("failed_attempts".to_owned(), json!([])),
            ("duration_ms".to_owned(), json!(29)),
        ]);
        entry
    }

    #[test]
    fn relay_attempt_is_neither_admission_nor_delivery() {
        let capture = bundle(vec![relay_phase(0, "invoke.mesh_forward_attempt", "peer-a")]);
        let result = explain_bundle(&capture).unwrap();
        let summary = result.host_request.as_ref().unwrap();
        assert_eq!(summary.outcome, HostRequestOutcome::RelayPending);
        assert!(!summary.admission_observed);
        assert!(!summary.terminal_observed);
        assert_eq!(summary.reported_success, None);
        assert_eq!(summary.relay.as_ref().unwrap().observed_targets, ["peer-a"]);
        assert!(!result.render_human().contains("invoked operation"));
    }

    #[test]
    fn peer_response_status_never_becomes_connector_success() {
        for status in [200, 202, 403, 500] {
            let mut response = relay_phase(2, "invoke.mesh_forwarded", "peer-a");
            response.metadata.insert("executor_status".to_owned(), json!(status));
            let capture = bundle(vec![
                relay_phase(0, "invoke.mesh_forward_attempt", "peer-a"),
                response,
            ]);
            let result = explain_bundle(&capture).unwrap();
            let summary = result.host_request.as_ref().unwrap();
            assert_eq!(summary.outcome, HostRequestOutcome::RelayResponse);
            assert!(!summary.admission_observed);
            assert!(summary.terminal_observed);
            assert_eq!(summary.reported_success, None);
            assert_eq!(summary.reported_receipt_id, None);
            assert_eq!(summary.duration_ms, Some(29));
            assert_eq!(summary.relay.as_ref().unwrap().reported_executor_status, Some(status));
            assert!(result.render_human().contains("not a connector success receipt"));
        }
    }

    #[test]
    fn relay_without_peer_response_keeps_delivery_and_retries_uncertain() {
        let mut response = relay_phase(2, "invoke.mesh_forwarded", "peer-a");
        response.metadata.insert("executor_status".to_owned(), Value::Null);
        response.metadata.insert("failed_attempts".to_owned(), json!(["private-relay-error"]));
        let result = explain_bundle(&bundle(vec![response])).unwrap();
        let summary = result.host_request.as_ref().unwrap();
        assert_eq!(summary.outcome, HostRequestOutcome::RelayUnconfirmed);
        assert_eq!(summary.relay.as_ref().unwrap().reported_failed_attempt_count, Some(1));
        assert!(result.render_human().contains("retry safety remain unknown"));
        assert!(!serde_json::to_string(&result).unwrap().contains("private-relay-error"));
    }

    #[test]
    fn missing_relay_attempts_are_reported_not_fabricated() {
        for captured_attempt in [None, Some("peer-a")] {
            let mut entries = Vec::new();
            if let Some(target) = captured_attempt {
                entries.push(relay_phase(0, "invoke.mesh_forward_attempt", target));
            }
            entries.push(relay_phase(2, "invoke.mesh_forwarded", "peer-b"));
            let result = explain_bundle(&bundle(entries)).unwrap();
            let relay = result.host_request.as_ref().unwrap().relay.as_ref().unwrap();
            assert_eq!(relay.observed_targets.len(), if captured_attempt.is_some() { 1 } else { 0 });
            assert_eq!(relay.reported_terminal_target.as_deref(), Some("peer-b"));
            assert!(result.warnings.iter().any(|warning| {
                warning.contains("routing history is incomplete")
                    || warning.contains("routing history is missing")
            }));
        }
    }

    #[test]
    fn malformed_relay_metadata_never_falls_back_to_pending() {
        let invalid_fields = [
            ("target_node", json!("")),
            ("decision", Value::Null),
            ("executor_status", json!("200")),
            ("executor_status", json!(99)),
            ("executor_status", json!(600)),
            ("executor_status", json!(200.5)),
            ("failed_attempts", Value::Null),
            ("failed_attempts", json!([false])),
            ("failed_attempts", json!([""])),
            ("duration_ms", json!(-1)),
        ];
        for (field, value) in invalid_fields {
            let mut response = relay_phase(2, "invoke.mesh_forwarded", "peer-a");
            response.metadata.insert(field.to_owned(), value);
            assert!(explain_bundle(&bundle(vec![
                relay_phase(0, "invoke.mesh_forward_attempt", "peer-a"),
                response,
            ])).is_err(), "{field}");
        }
        let mut response = relay_phase(2, "invoke.mesh_forwarded", "peer-a");
        response.metadata.remove("executor_status");
        assert!(explain_bundle(&bundle(vec![response])).is_err());
    }

    #[test]
    fn relay_and_local_completion_cannot_be_spliced_into_success() {
        for phase_name in ["invoke.allow", "invoke.deny", "invoke.result"] {
            assert!(explain_bundle(&bundle(vec![
                relay_phase(0, "invoke.mesh_forward_attempt", "peer-a"),
                phase(2, phase_name),
            ])).is_err());
        }
        assert!(explain_bundle(&bundle(vec![
            relay_phase(0, "invoke.mesh_forwarded", "peer-a"),
            relay_phase(2, "invoke.mesh_forward_attempt", "peer-b"),
        ])).is_err());
        let result = explain_bundle(&bundle(vec![
            relay_phase(0, "invoke.mesh_forward_attempt", "peer-a"),
            phase(2, "invoke.error"),
        ])).unwrap();
        assert_eq!(result.host_request.unwrap().outcome, HostRequestOutcome::DispatchError);
    }

    #[test]
    fn relay_attempt_order_is_stable_across_duplicate_captures() {
        let first = relay_phase(0, "invoke.mesh_forward_attempt", "peer-a");
        let second = relay_phase(2, "invoke.mesh_forward_attempt", "peer-b");
        let response = relay_phase(4, "invoke.mesh_forwarded", "peer-b");
        let expected = explain_bundle(&bundle(vec![first.clone(), second.clone(), response.clone()])).unwrap();
        let shuffled = bundle(vec![response, second.clone(), first.clone(), second, first]);
        assert_eq!(explain_bundle(&shuffled).unwrap(), expected);
        let relay = expected.host_request.unwrap().relay.unwrap();
        assert_eq!(relay.observed_targets, ["peer-a", "peer-b"]);
    }

    #[test]
    fn relay_summary_roundtrips_without_changing_local_admission_evidence() {
        let result = explain_bundle(&bundle(vec![
            phase(0, "invoke.allow"),
            relay_phase(1, "invoke.mesh_forward_attempt", "peer-a"),
            relay_phase(2, "invoke.mesh_forwarded", "peer-a"),
        ])).unwrap();
        let summary = result.host_request.as_ref().unwrap();
        assert!(summary.admission_observed);
        assert_eq!(summary.outcome, HostRequestOutcome::RelayResponse);
        assert_eq!(summary.reported_success, None);
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["host_request"]["relay"]["reported_executor_status"], 200);
        assert_eq!(serde_json::from_value::<CausalExplanation>(value).unwrap(), result);
    }
}
