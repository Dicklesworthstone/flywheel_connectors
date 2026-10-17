//! Causal explanations for replayed audit bundles.
//!
//! The types in this module intentionally operate on replay artifacts rather
//! than live host state. A caller supplies the audit-event chain, capability
//! token evidence, and decision receipts captured with an operation. The
//! explainer then derives a deterministic human-readable "why did this happen"
//! narrative from those artifacts. Association is not authentication: callers
//! must verify chain integrity and signatures independently before trusting it.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Write as _;
use thiserror::Error;

use crate::{AuditEntry, Decision, DecisionReceipt, event_types};

pub mod host;

/// Replay evidence consumed by [`explain_bundle`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundle {
    /// Audit entries captured for the replayed operation.
    #[serde(
        default,
        alias = "audit_events",
        alias = "audit_event_chain",
        alias = "events",
        alias = "entries"
    )]
    pub audit_entries: Vec<AuditEntry>,
    /// Capability tokens captured with the replay bundle.
    #[serde(default, alias = "tokens")]
    pub capability_tokens: Vec<Value>,
    /// Decision receipts captured with the replay bundle.
    #[serde(default, alias = "decision_receipts")]
    pub receipts: Vec<DecisionReceipt>,
}

/// Machine-readable causal explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalExplanation {
    /// Connector that was invoked.
    pub connector_id: String,
    /// Operation that was invoked.
    pub operation_id: String,
    /// Unix timestamp seconds from the invocation audit entry.
    pub occurred_at: u64,
    /// Actor recorded by the invocation audit entry.
    pub actor: String,
    /// Zone recorded by the invocation audit entry.
    pub zone_id: String,
    /// Correlation ID used to join bundle artifacts.
    pub correlation_id: Option<String>,
    /// Invocation audit entry ID.
    pub invocation_audit_entry_id: String,
    /// Ordered causal reasons.
    pub reasons: Vec<CausalReason>,
    /// Non-fatal evidence gaps observed while explaining.
    pub warnings: Vec<String>,
    /// Captured host request lifecycle, distinct from a capability invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_request: Option<host::HostRequestSummary>,
}

impl CausalExplanation {
    /// Render the explanation as a human-readable narrative.
    #[must_use]
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        if let Some(request) = &self.host_request {
            let _ = writeln!(
                out,
                "Captured host request {}: connector {}, operation {}, outcome {}. Associated evidence:",
                request.request_id,
                self.connector_id,
                self.operation_id,
                request.outcome.as_str()
            );
        } else {
            let _ = writeln!(
                out,
                "Captured audit: Connector {} invoked operation {} at time {}. Associated evidence:",
                self.connector_id, self.operation_id, self.occurred_at
            );
        }
        for (idx, reason) in self.reasons.iter().enumerate() {
            let marker = reason_marker(idx);
            let _ = writeln!(out, "({marker}) {}", reason.statement);
        }
        if !self.warnings.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "Evidence caveats:");
            for warning in &self.warnings {
                let _ = writeln!(out, "- {warning}");
            }
        }
        out.trim_end().to_string()
    }
}

/// One causal premise in a narrative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalReason {
    /// Reason category.
    pub kind: CausalReasonKind,
    /// Human-readable reason statement.
    pub statement: String,
    /// Evidence IDs backing the reason.
    pub evidence: Vec<String>,
}

/// Stable reason categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalReasonKind {
    /// Capability-token grant evidence.
    CapabilityGrant,
    /// Audit entry that confirms admission or invocation.
    AuditAdmission,
    /// Decision receipt evidence.
    DecisionReceipt,
    /// Revocation-cascade evidence.
    RevocationCascade,
    /// A host request phase; not a capability grant or authenticated proof.
    HostLifecycle,
}

/// Errors returned by replay-bundle explanation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExplainError {
    /// Bundle contained no usable evidence.
    #[error("replay bundle does not contain audit entries, capability tokens, or receipts")]
    EmptyBundle,
    /// No invocation-like audit entry could be selected.
    #[error("replay bundle does not contain an invocation audit entry")]
    NoInvocation,
    /// Different entries claim the same selected invocation ID.
    #[error("replay bundle contains conflicting entries for the selected invocation")]
    ConflictingInvocation,
    /// The captured host request has malformed or contradictory phase evidence.
    #[error("invalid captured host lifecycle: {0}")]
    InvalidHostLifecycle(&'static str),
    /// JSON parsing failed.
    #[error("failed to parse replay bundle: {0}")]
    Parse(String),
}

/// Parse a replay bundle from JSON or JSONL.
///
/// JSON object inputs may use `audit_entries`, `audit_events`,
/// `audit_event_chain`, `events`, or `entries` for the audit chain. JSON array
/// and JSONL inputs are interpreted as audit-entry chains.
///
/// # Errors
///
/// Returns [`ExplainError::Parse`] when the input cannot be parsed as a replay
/// bundle, audit entry, JSON array, or JSONL audit-entry chain.
pub fn parse_replay_bundle(input: &str) -> Result<ReplayBundle, ExplainError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(ReplayBundle::default());
    }

    // Preserve pretty-printed single documents. Multiple JSONL objects also
    // start with `{`, so a failed whole-document parse must reach the strict
    // per-line parser below instead of rejecting every ordinary JSONL chain.
    if trimmed.starts_with('{')
        && let Ok(value) = serde_json::from_str::<Value>(trimmed)
    {
        if looks_like_bundle_object(&value) {
            return serde_json::from_str(trimmed).map_err(|err| parse_error(&err));
        }
        let entry = serde_json::from_str(trimmed).map_err(|err| parse_error(&err))?;
        return Ok(ReplayBundle {
            audit_entries: vec![entry],
            capability_tokens: Vec::new(),
            receipts: Vec::new(),
        });
    }

    Ok(ReplayBundle {
        audit_entries: parse_audit_entries(input)?,
        capability_tokens: Vec::new(),
        receipts: Vec::new(),
    })
}

/// Parse audit entries from a JSON array or JSONL text.
///
/// # Errors
///
/// Returns [`ExplainError::Parse`] when any JSON array element or JSONL line is
/// not a valid [`AuditEntry`].
pub fn parse_audit_entries(input: &str) -> Result<Vec<AuditEntry>, ExplainError> {
    parse_json_array_or_jsonl(input, "audit entry")
}

/// Parse decision receipts from a JSON array or JSONL text.
///
/// # Errors
///
/// Returns [`ExplainError::Parse`] when any JSON array element or JSONL line is
/// not a valid [`DecisionReceipt`].
pub fn parse_decision_receipts(input: &str) -> Result<Vec<DecisionReceipt>, ExplainError> {
    parse_json_array_or_jsonl(input, "decision receipt")
}

/// Parse capability-token evidence from a JSON array, JSON object, or JSONL text.
///
/// # Errors
///
/// Returns [`ExplainError::Parse`] when the input cannot be parsed as a JSON
/// array, JSON object, or JSONL sequence of token values.
pub fn parse_capability_tokens(input: &str) -> Result<Vec<Value>, ExplainError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed).map_err(|err| parse_error(&err));
    }

    if trimmed.starts_with('{')
        && let Ok(value) = serde_json::from_str::<Value>(trimmed)
    {
        if let Some(tokens) = value
            .get("capability_tokens")
            .or_else(|| value.get("tokens"))
            .and_then(Value::as_array)
        {
            return Ok(tokens.clone());
        }
        return Ok(vec![value]);
    }

    input
        .lines()
        .enumerate()
        .filter_map(non_empty_line)
        .map(|(idx, line)| {
            serde_json::from_str(line)
                .map_err(|err| ExplainError::Parse(format!("line {}: {err}", idx + 1)))
        })
        .collect()
}

/// Explain the newest capability invocation or host request phase in a capture.
///
/// Evidence must bind to the selected request, not merely share a connector.
/// Missing revocation evidence is reported as unknown, never as proof that an
/// issuer was intact. This function does not authenticate captured artifacts.
/// Use [`explain_invocation`] to select an older invocation explicitly.
/// Host phases are grouped by the server request ID, not client correlation.
/// A preflight denial, admission, or relay is never called a completed invoke.
///
/// # Errors
///
/// Returns [`ExplainError::EmptyBundle`] when no replay evidence is present and
/// [`ExplainError::NoInvocation`] when no complete capability invocation is
/// present, [`ExplainError::ConflictingInvocation`] for conflicting IDs, or
/// [`ExplainError::InvalidHostLifecycle`] for unusable host phase evidence.
pub fn explain_bundle(bundle: &ReplayBundle) -> Result<CausalExplanation, ExplainError> {
    if bundle.audit_entries.is_empty()
        && bundle.capability_tokens.is_empty()
        && bundle.receipts.is_empty()
    {
        return Err(ExplainError::EmptyBundle);
    }

    let invocation = select_invocation(&bundle.audit_entries).ok_or(ExplainError::NoInvocation)?;
    explain_selected(bundle, invocation)
}

/// Explain one capability invocation or host request by an audit-entry ID.
///
/// Unlike [`explain_bundle`], this never silently selects another invocation
/// when the requested ID is absent. IDs naming non-invocation events are also
/// rejected. Duplicate identical captures are harmless; conflicting captures
/// of the selected ID are rejected before evidence is associated.
/// For a host phase, the ID selects its request and all captured phases of that
/// request are summarized; the caller's filtered capture defines the horizon.
///
/// # Errors
///
/// Returns [`ExplainError::NoInvocation`] if the ID has no complete invocation,
/// [`ExplainError::ConflictingInvocation`] if its captured entries disagree,
/// or [`ExplainError::InvalidHostLifecycle`] for contradictory host phases.
pub fn explain_invocation(
    bundle: &ReplayBundle,
    invocation_id: &str,
) -> Result<CausalExplanation, ExplainError> {
    let invocation = bundle
        .audit_entries
        .iter()
        .find(|entry| {
            entry.id == invocation_id && (is_invocation(entry) || host::is_host_event(entry))
        })
        .ok_or(ExplainError::NoInvocation)?;
    explain_selected(bundle, invocation)
}

fn explain_selected(
    bundle: &ReplayBundle,
    invocation: &AuditEntry,
) -> Result<CausalExplanation, ExplainError> {
    if bundle
        .audit_entries
        .iter()
        .any(|entry| entry.id == invocation.id && entry != invocation)
    {
        return Err(ExplainError::ConflictingInvocation);
    }
    if host::is_host_event(invocation) {
        return host::explain_request_at_entry(bundle, invocation);
    }
    let connector_id = invocation
        .connector_id
        .clone()
        .unwrap_or_else(|| "unknown-connector".to_string());
    let operation_id = invocation
        .operation_id
        .clone()
        .unwrap_or_else(|| "unknown-operation".to_string());
    let correlation_id = non_empty(invocation.correlation_id.as_str()).map(ToOwned::to_owned);

    let capability_token = select_capability_token(bundle, invocation);
    let admission_entry = select_admission_entry(&bundle.audit_entries, invocation);
    let receipt = select_receipt(bundle, invocation);
    let mut reasons = Vec::new();
    let mut warnings = vec![
        "captured artifacts are not authenticated by this explanation; verify chain integrity and signatures separately"
            .to_string(),
    ];
    let denied = receipt.is_some_and(|receipt| receipt.decision == Decision::Deny);
    if denied {
        warnings.push(
            "a request-bound denial contradicts the recorded invocation; positive authorization evidence is not presented as its justification"
                .to_string(),
        );
    }

    if let Some(token) = capability_token.filter(|_| !denied) {
        reasons.push(capability_reason(token, invocation));
    } else if !denied {
        warnings.push(format!(
            "no capability token matched connector {connector_id} operation {operation_id}"
        ));
    }

    if let Some(entry) = admission_entry.filter(|_| !denied) {
        reasons.push(admission_reason(entry, invocation));
    } else if !denied {
        warnings.push(format!(
            "no admission audit event matched invocation {}",
            invocation.id
        ));
    }

    if let Some(decision_receipt) = receipt {
        reasons.push(receipt_reason(decision_receipt));
    } else {
        warnings.push(format!(
            "no decision receipt matched invocation {}",
            invocation.id
        ));
    }

    if let Some(reason) = revocation_reason(bundle, invocation) {
        reasons.push(reason);
    } else {
        warnings.push(
            "no request-bound revocation evidence was captured; revocation status is unknown"
                .to_string(),
        );
    }

    Ok(CausalExplanation {
        connector_id,
        operation_id,
        occurred_at: invocation.occurred_at,
        actor: invocation.actor.clone(),
        zone_id: invocation.zone_id.clone(),
        correlation_id,
        invocation_audit_entry_id: invocation.id.clone(),
        reasons,
        warnings,
        host_request: None,
    })
}

fn parse_json_array_or_jsonl<T>(input: &str, label: &str) -> Result<Vec<T>, ExplainError>
where
    T: for<'de> Deserialize<'de>,
{
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed).map_err(|err| parse_error(&err));
    }

    if trimmed.starts_with('{') && serde_json::from_str::<serde::de::IgnoredAny>(trimmed).is_ok() {
        // A valid document with invalid fields remains an error, not a reason
        // to downgrade to a different input shape or accept a partial prefix.
        // Deserialize the original text so duplicate fields remain errors.
        return serde_json::from_str(trimmed)
            .map(|single| vec![single])
            .map_err(|err| parse_error(&err));
    }

    input
        .lines()
        .enumerate()
        .filter_map(non_empty_line)
        .map(|(idx, line)| {
            serde_json::from_str(line)
                .map_err(|err| ExplainError::Parse(format!("{label} line {}: {err}", idx + 1)))
        })
        .collect()
}

fn non_empty_line((idx, line): (usize, &str)) -> Option<(usize, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some((idx, trimmed))
    }
}

fn parse_error(error: &serde_json::Error) -> ExplainError {
    ExplainError::Parse(error.to_string())
}

fn looks_like_bundle_object(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        [
            "audit_entries",
            "audit_events",
            "audit_event_chain",
            "events",
            "entries",
            "capability_tokens",
            "tokens",
            "receipts",
            "decision_receipts",
        ]
        .iter()
        .any(|key| object.contains_key(*key))
    })
}

fn select_invocation(entries: &[AuditEntry]) -> Option<&AuditEntry> {
    entries
        .iter()
        .filter(|entry| is_invocation(entry) || host::is_host_event(entry))
        .max_by_key(|entry| (entry.occurred_at, entry.seq, entry.id.as_str()))
}

fn is_invocation(entry: &AuditEntry) -> bool {
    entry.event_type == event_types::CAPABILITY_INVOKE
        && !entry.id.is_empty()
        && !entry.actor.is_empty()
        && !entry.zone_id.is_empty()
        && entry.connector_id.as_deref().and_then(non_empty).is_some()
        && entry.operation_id.as_deref().and_then(non_empty).is_some()
}

fn select_capability_token<'a>(
    bundle: &'a ReplayBundle,
    invocation: &AuditEntry,
) -> Option<&'a Value> {
    let mut matching = bundle
        .capability_tokens
        .iter()
        .filter(|token| token_matches_invocation(token, invocation))
        .filter(|token| {
            token_field(token, &["audit_entry_id", "invocation_audit_entry_id"])
                == Ok(Some(invocation.id.as_str()))
                || has_unique_request_context(&bundle.audit_entries, invocation)
        });
    let first = matching.next()?;
    // Do not choose an arbitrary grant when two different captures both claim
    // this request. Reordering a bundle must not change its justification.
    matching.all(|token| token == first).then_some(first)
}

fn select_admission_entry<'a>(
    entries: &'a [AuditEntry],
    invocation: &'a AuditEntry,
) -> Option<&'a AuditEntry> {
    if !has_unique_request_context(entries, invocation) {
        return None;
    }
    entries
        .iter()
        .filter(|entry| {
            entry_matches_invocation(entry, invocation)
                && entry.id != invocation.id
                && entry.seq < invocation.seq
                && entry.occurred_at <= invocation.occurred_at
                && entry.event_type == "capability.admission"
        })
        .max_by_key(|entry| (entry.seq, entry.occurred_at, entry.id.as_str()))
        .filter(|entry| admission_allows(entry))
}

fn select_receipt<'a>(
    bundle: &'a ReplayBundle,
    invocation: &AuditEntry,
) -> Option<&'a DecisionReceipt> {
    bundle
        .receipts
        .iter()
        .filter(|receipt| receipt_matches_invocation(receipt, invocation))
        .filter(|receipt| {
            receipt.audit_entry_id.is_some()
                || has_unique_request_context(&bundle.audit_entries, invocation)
        })
        .max_by_key(|receipt| {
            // A denial must not disappear behind an earlier (or reordered)
            // allow. Surface the contradiction instead of narrating success.
            (
                receipt.decision == Decision::Deny,
                receipt.decided_at,
                receipt.id.as_str(),
            )
        })
}

fn token_matches_invocation(token: &Value, invocation: &AuditEntry) -> bool {
    if token_field(token, &["connector_id", "connector"]) != Ok(invocation.connector_id.as_deref())
        || token_field(token, &["operation_id", "operation", "op"])
            != Ok(invocation.operation_id.as_deref())
        || token_field(token, &["zone_id", "zone"]) != Ok(Some(invocation.zone_id.as_str()))
        || token_field(token, &["actor", "principal", "sub"]) != Ok(Some(invocation.actor.as_str()))
        || !matches!(token_field(token, &["id", "token_id", "jti"]), Ok(Some(_)))
    {
        return false;
    }
    let Ok(reference) = token_field(token, &["audit_entry_id", "invocation_audit_entry_id"]) else {
        return false;
    };
    let Ok(correlation) = token_field(token, &["correlation_id", "correlation"]) else {
        return false;
    };
    if reference.is_some_and(|id| id != invocation.id)
        || correlation.is_some_and(|id| id != invocation.correlation_id)
    {
        return false;
    }
    reference.is_some()
        || (non_empty(&invocation.correlation_id).is_some()
            && correlation == Some(invocation.correlation_id.as_str()))
}

fn entry_matches_invocation(entry: &AuditEntry, invocation: &AuditEntry) -> bool {
    entry.zone_id == invocation.zone_id
        && entry.actor == invocation.actor
        && entry.connector_id == invocation.connector_id
        && entry.operation_id == invocation.operation_id
        && !invocation.correlation_id.is_empty()
        && entry.correlation_id == invocation.correlation_id
}

fn receipt_matches_invocation(receipt: &DecisionReceipt, invocation: &AuditEntry) -> bool {
    if receipt.zone_id != invocation.zone_id
        || receipt.decided_at > invocation.occurred_at
        || receipt
            .connector_id
            .as_ref()
            .is_some_and(|id| Some(id) != invocation.connector_id.as_ref())
        || receipt
            .operation_id
            .as_ref()
            .is_some_and(|id| Some(id) != invocation.operation_id.as_ref())
        || receipt
            .correlation_id
            .as_ref()
            .is_some_and(|id| id != &invocation.correlation_id)
    {
        return false;
    }
    // An explicit reference is authoritative for association, never a hint
    // that may fall back to correlation after naming a different invocation.
    match receipt.audit_entry_id.as_deref() {
        Some(id) => id == invocation.id,
        None => {
            !invocation.correlation_id.is_empty()
                && receipt.correlation_id.as_deref() == Some(invocation.correlation_id.as_str())
                && receipt.connector_id == invocation.connector_id
                && receipt.operation_id == invocation.operation_id
        }
    }
}

fn has_unique_request_context(entries: &[AuditEntry], invocation: &AuditEntry) -> bool {
    !invocation.correlation_id.is_empty()
        && !entries.iter().any(|entry| {
            is_invocation(entry)
                && entry.id != invocation.id
                && entry.zone_id == invocation.zone_id
                && entry.correlation_id == invocation.correlation_id
                && entry.connector_id == invocation.connector_id
                && entry.operation_id == invocation.operation_id
        })
}

fn admission_allows(entry: &AuditEntry) -> bool {
    let mut saw_allow = false;
    for key in ["decision", "admission", "admitted"] {
        if let Some(value) = entry.metadata.get(key) {
            let allowed = if key == "admitted" {
                value.as_bool() == Some(true)
                    || value
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
            } else {
                value
                    .as_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case("allow"))
            };
            if !allowed {
                return false;
            }
            saw_allow = true;
        }
    }
    saw_allow
}

fn capability_reason(token: &Value, invocation: &AuditEntry) -> CausalReason {
    let token_id = value_string(token, &["id", "token_id", "jti"])
        .unwrap_or_else(|| "captured-token".to_string());
    let capability = value_string(token, &["capability_id", "capability", "cap"])
        .unwrap_or_else(|| "the required capability".to_string());
    // The audit entry's signer is not necessarily the capability's issuer.
    let issuer = value_string(token, &["issuer_kid", "issuer", "iss"]);
    let mut statement = format!(
        "captured capability token {token_id} declares {capability} for connector {} operation {}",
        invocation
            .connector_id
            .as_deref()
            .unwrap_or("unknown-connector"),
        invocation
            .operation_id
            .as_deref()
            .unwrap_or("unknown-operation")
    );
    if let Some(issuer) = issuer {
        let _ = write!(statement, " under issuer {issuer}");
    }
    CausalReason {
        kind: CausalReasonKind::CapabilityGrant,
        statement,
        evidence: vec![format!("capability_token:{token_id}")],
    }
}

fn admission_reason(entry: &AuditEntry, _invocation: &AuditEntry) -> CausalReason {
    // The `entry.id == invocation.id` shortcut existed to soften the
    // misleading message produced when select_admission_entry's
    // pre-vs4nt fallback handed the invocation back as its own
    // admission. With the fallback removed (br-vs4nt completion),
    // `entry` is always a real admission audit and we always render
    // the literal "confirmed admission" statement.
    CausalReason {
        kind: CausalReasonKind::AuditAdmission,
        statement: format!(
            "audit event {} (seq {}) confirmed admission before connector dispatch",
            entry.id, entry.seq
        ),
        evidence: vec![format!("audit_entry:{}", entry.id)],
    }
}

fn receipt_reason(receipt: &DecisionReceipt) -> CausalReason {
    let explanation = receipt
        .explanation
        .as_deref()
        .or_else(|| non_empty(receipt.reason_code.as_str()))
        .unwrap_or("allow");
    let confidence = receipt
        .confidence
        .as_ref()
        .map_or_else(String::new, |score| {
            format!(
                " with confidence {} (n={}, nonconforming={})",
                score.display_value(),
                score.sample_count,
                score.nonconforming_count
            )
        });
    CausalReason {
        kind: CausalReasonKind::DecisionReceipt,
        statement: format!(
            "decision receipt {} returned {}{confidence} with reason {explanation}",
            receipt.id, receipt.decision
        ),
        evidence: vec![format!("receipt:{}", receipt.id)],
    }
}

fn revocation_reason(bundle: &ReplayBundle, invocation: &AuditEntry) -> Option<CausalReason> {
    let relevant_revocations: Vec<&AuditEntry> = bundle
        .audit_entries
        .iter()
        .filter(|entry| entry.event_type == event_types::REVOCATION_ISSUED)
        .filter(|entry| {
            entry_matches_invocation(entry, invocation)
                && entry.occurred_at <= invocation.occurred_at
                && entry.seq <= invocation.seq
                && has_unique_request_context(&bundle.audit_entries, invocation)
        })
        .collect();
    let revocation_receipts: Vec<&DecisionReceipt> = bundle
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.decision == Decision::Deny
                && receipt.reason_code.split('.').any(|part| {
                    part.eq_ignore_ascii_case("revocation") || part.eq_ignore_ascii_case("revoked")
                })
                && receipt_matches_invocation(receipt, invocation)
                && (receipt.audit_entry_id.is_some()
                    || has_unique_request_context(&bundle.audit_entries, invocation))
        })
        .collect();

    if !relevant_revocations.is_empty() || !revocation_receipts.is_empty() {
        let mut evidence: Vec<String> = relevant_revocations
            .iter()
            .map(|entry| format!("audit_entry:{}", entry.id))
            .collect();
        evidence.extend(
            revocation_receipts
                .iter()
                .map(|receipt| format!("receipt:{}", receipt.id)),
        );
        evidence.sort();
        evidence.dedup();
        return Some(CausalReason {
            kind: CausalReasonKind::RevocationCascade,
            statement: "captured revocation-related evidence is associated with this invocation"
                .to_string(),
            evidence,
        });
    }

    None
}

fn token_field<'a>(value: &'a Value, keys: &[&str]) -> Result<Option<&'a str>, ()> {
    token_field_at_depth(value, keys, 0)
}

fn token_field_at_depth<'a>(
    value: &'a Value,
    keys: &[&str],
    depth: usize,
) -> Result<Option<&'a str>, ()> {
    // Public entry-backed callers can construct Values without the JSON
    // decoder's recursion limit. Bound traversal of envelope aliases too.
    if depth > 16 {
        return Err(());
    }
    let object = value.as_object().ok_or(())?;
    let mut selected = None;
    for key in keys {
        if let Some(value) = object.get(*key) {
            let field = value.as_str().and_then(non_empty).ok_or(())?;
            if selected.is_some_and(|existing| existing != field) {
                return Err(());
            }
            selected = Some(field);
        }
    }
    for wrapper in [
        "claims",
        "payload",
        "token",
        "capability_token",
        "capability",
    ] {
        if let Some(nested) = object.get(wrapper).filter(|value| value.is_object())
            && let Some(field) = token_field_at_depth(nested, keys, depth + 1)?
        {
            if selected.is_some_and(|existing| existing != field) {
                return Err(());
            }
            selected = Some(field);
        }
    }
    Ok(selected)
}

const fn non_empty(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}

fn value_string(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    for key in keys {
        if let Some(found) = object.get(*key).and_then(scalar_to_string) {
            return Some(found);
        }
    }
    for nested in [
        "claims",
        "payload",
        "token",
        "capability_token",
        "capability",
    ] {
        if let Some(found) = object
            .get(nested)
            .and_then(|nested_value| value_string(nested_value, keys))
        {
            return Some(found);
        }
    }
    None
}

fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn reason_marker(idx: usize) -> char {
    u8::try_from(idx)
        .ok()
        .and_then(|offset| b'a'.checked_add(offset))
        .filter(u8::is_ascii_lowercase)
        .map_or('?', char::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;
    use std::collections::BTreeMap;

    fn audit_entry(
        seq: u64,
        event_type: &str,
        connector_id: Option<&str>,
        operation_id: Option<&str>,
        correlation_id: &str,
        metadata: BTreeMap<String, Value>,
    ) -> AuditEntry {
        let mut entry = AuditEntry {
            id: String::new(),
            event_type: event_type.to_string(),
            severity: Severity::Info,
            actor: "user:alice".to_string(),
            zone_id: "z:work".to_string(),
            seq,
            occurred_at: 1_700_000_000 + seq,
            hlc: crate::audit_entry_hlc_from_occurred_at(1_700_000_000 + seq, "user:alice"),
            prev: None,
            correlation_id: correlation_id.to_string(),
            trace_context: None,
            connector_id: connector_id.map(ToOwned::to_owned),
            operation_id: operation_id.map(ToOwned::to_owned),
            metadata,
            issuer_kid: None,
            signature: None,
        };
        entry.id = entry.computed_id().expect("entry id computes");
        entry
    }

    fn allow_receipt(entry: &AuditEntry) -> DecisionReceipt {
        DecisionReceipt {
            id: "receipt-allow-1".to_string(),
            request_id: "request-1".to_string(),
            decision: Decision::Allow,
            reason_code: "policy.admitted".to_string(),
            evidence: vec![entry.id.clone()],
            audit_entry_id: Some(entry.id.clone()),
            explanation: Some("policy bundle admitted the operation".to_string()),
            decided_at: entry.occurred_at,
            zone_id: entry.zone_id.clone(),
            correlation_id: Some(entry.correlation_id.clone()),
            trace_context: None,
            connector_id: entry.connector_id.clone(),
            operation_id: entry.operation_id.clone(),
            confidence: None,
            issuer_kid: None,
            signature: None,
        }
    }

    #[test]
    fn explain_bundle_builds_causal_inference_narrative() {
        let mut admission_metadata = BTreeMap::new();
        admission_metadata.insert("decision".to_string(), Value::String("allow".to_string()));
        let admission = audit_entry(
            0,
            "capability.admission",
            Some("fcp.slack"),
            Some("chat.postMessage"),
            "corr-1",
            admission_metadata,
        );
        let invocation = audit_entry(
            1,
            event_types::CAPABILITY_INVOKE,
            Some("fcp.slack"),
            Some("chat.postMessage"),
            "corr-1",
            BTreeMap::new(),
        );
        let token = serde_json::json!({
            "id": "tok-1",
            "capability_id": "slack.messages.write",
            "connector_id": "fcp.slack",
            "operation_id": "chat.postMessage",
            "zone_id": "z:work",
            "actor": "user:alice",
            "correlation_id": "corr-1",
            "issuer_kid": "kid-owner"
        });
        let bundle = ReplayBundle {
            audit_entries: vec![admission, invocation.clone()],
            capability_tokens: vec![token],
            receipts: vec![allow_receipt(&invocation)],
        };

        let explanation = explain_bundle(&bundle).expect("bundle explains");
        let human = explanation.render_human();

        assert!(human.contains("Connector fcp.slack invoked operation chat.postMessage"));
        assert!(human.contains("capability token tok-1 declares slack.messages.write"));
        assert!(human.contains("confirmed admission"));
        assert!(human.contains("decision receipt receipt-allow-1 returned allow"));
        assert!(human.contains("revocation status is unknown"));
        assert!(human.contains("not authenticated"));
    }

    #[test]
    fn explain_bundle_does_not_borrow_unmatched_positive_evidence() {
        let invocation = audit_entry(
            0,
            event_types::CAPABILITY_INVOKE,
            Some("fcp.github"),
            Some("issues.create"),
            "corr-github",
            BTreeMap::new(),
        );
        let slack_invocation = audit_entry(
            1,
            event_types::CAPABILITY_INVOKE,
            Some("fcp.slack"),
            Some("chat.postMessage"),
            "corr-slack",
            BTreeMap::new(),
        );
        let slack_token = serde_json::json!({
            "id": "tok-slack",
            "capability_id": "slack.messages.write",
            "connector_id": "fcp.slack",
            "operation_id": "chat.postMessage",
            "issuer_kid": "kid-owner"
        });
        let mut slack_receipt = allow_receipt(&slack_invocation);
        slack_receipt.id = "receipt-slack-allow".to_string();
        let bundle = ReplayBundle {
            audit_entries: vec![invocation.clone()],
            capability_tokens: vec![slack_token],
            receipts: vec![slack_receipt],
        };

        let explanation = explain_bundle(&bundle).expect("bundle explains");
        let human = explanation.render_human();

        assert!(
            human.contains(
                "no capability token matched connector fcp.github operation issues.create"
            )
        );
        assert!(!human.contains("tok-slack"));
        assert!(!human.contains("slack.messages.write"));
        assert!(!human.contains("receipt-slack-allow"));
        assert!(!human.contains("returned allow"));

        // br-vs4nt completion: the same anti-pattern existed for
        // admission entries — `select_admission_entry` used to fall
        // back to `Some(invocation)` so the invocation entry rendered
        // as its own admission proof. Pin that we now surface the
        // missing-admission warning AND do not emit a false admission
        // claim. Without this pin the bundle would render an
        // AuditAdmission reason pointing at the invocation itself.
        assert!(
            human.contains(&format!(
                "no admission audit event matched invocation {}",
                invocation.id
            )),
            "br-vs4nt admission seam: missing-admission warning must surface, got: {human}"
        );
        assert!(
            !human.contains("recorded the admitted invocation"),
            "br-vs4nt admission seam: must not borrow invocation as admission, got: {human}"
        );
        assert!(
            !human.contains("confirmed admission before connector dispatch"),
            "br-vs4nt admission seam: must not synthesize admission claim from invocation, got: {human}"
        );
        assert!(
            !explanation
                .reasons
                .iter()
                .any(|reason| matches!(reason.kind, CausalReasonKind::AuditAdmission)),
            "br-vs4nt admission seam: bundle without admission audit must not produce an \
             AuditAdmission reason, got reasons: {:?}",
            explanation.reasons,
        );
    }

    #[test]
    fn explain_parse_replay_bundle_accepts_entry_jsonl() {
        let invocation = audit_entry(
            0,
            event_types::CAPABILITY_INVOKE,
            Some("fcp.github"),
            Some("issues.create"),
            "corr-jsonl",
            BTreeMap::new(),
        );
        let jsonl = serde_json::to_string(&invocation).expect("entry serializes");

        let bundle = parse_replay_bundle(&jsonl).expect("jsonl parses");

        assert_eq!(bundle.audit_entries, vec![invocation]);
        assert_eq!(bundle.capability_tokens, [] as [serde_json::Value; 0]);
        assert_eq!(bundle.receipts, [] as [DecisionReceipt; 0]);
    }

    #[test]
    fn parses_multiple_audit_records_with_blank_lines_and_crlf() {
        let entries: Vec<_> = (0..2)
            .map(|seq| {
                audit_entry(
                    seq,
                    event_types::CAPABILITY_INVOKE,
                    Some("fcp.github"),
                    Some("issues.create"),
                    "corr-jsonl",
                    BTreeMap::new(),
                )
            })
            .collect();
        let input = format!(
            "\r\n{}\r\n \r\n{}\r\n",
            serde_json::to_string(&entries[0]).unwrap(),
            serde_json::to_string(&entries[1]).unwrap(),
        );
        assert_eq!(parse_audit_entries(&input).unwrap(), entries);
        assert_eq!(parse_replay_bundle(&input).unwrap().audit_entries, entries);
    }

    #[test]
    fn parses_multiple_receipts_and_token_records() {
        let entry = audit_entry(
            0,
            event_types::CAPABILITY_INVOKE,
            None,
            None,
            "corr-jsonl",
            BTreeMap::new(),
        );
        let first = allow_receipt(&entry);
        let mut second = first.clone();
        second.id = "receipt-allow-2".to_owned();
        let input = format!(
            "{}\n{}\n",
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap(),
        );
        assert_eq!(
            parse_decision_receipts(&input).unwrap(),
            vec![first, second]
        );
        assert_eq!(
            parse_capability_tokens("{\"id\":\"a\"}\n\n{\"id\":\"b\"}\n").unwrap(),
            vec![
                serde_json::json!({"id": "a"}),
                serde_json::json!({"id": "b"})
            ]
        );
    }

    #[test]
    fn preserves_pretty_documents_arrays_and_bundle_aliases() {
        let entry = audit_entry(
            0,
            event_types::CAPABILITY_INVOKE,
            None,
            None,
            "corr-json",
            BTreeMap::new(),
        );
        for value in [
            serde_json::to_value(&entry).unwrap(),
            serde_json::json!([entry]),
            serde_json::json!({"audit_events": [entry]}),
        ] {
            let input = serde_json::to_string_pretty(&value).unwrap();
            assert_eq!(
                parse_replay_bundle(&input).unwrap().audit_entries,
                vec![entry.clone()]
            );
        }
        assert_eq!(
            parse_capability_tokens("{\n  \"tokens\": [{\"id\": \"a\"}]\n}").unwrap(),
            vec![serde_json::json!({"id": "a"})]
        );
    }

    #[test]
    fn rejects_invalid_suffixes_and_duplicate_typed_fields() {
        let entry = audit_entry(
            0,
            event_types::CAPABILITY_INVOKE,
            None,
            None,
            "corr-jsonl",
            BTreeMap::new(),
        );
        let valid = serde_json::to_string(&entry).unwrap();
        for suffix in ["{", "{}", "null", "[]", "garbage"] {
            let input = format!("{valid}\n{suffix}");
            assert!(parse_replay_bundle(&input).is_err());
            assert!(parse_audit_entries(&input).is_err());
        }
        let duplicate = format!("{{\"seq\":1,{}", &valid[1..]);
        assert!(parse_audit_entries(&duplicate).is_err());
        assert!(parse_replay_bundle(&duplicate).is_err());
        assert!(parse_replay_bundle("{\"audit_entries\":[],\"events\":[]}").is_err());
        assert!(parse_capability_tokens("{\"id\":\"a\"}\n{").is_err());
    }

    fn invocation() -> AuditEntry {
        audit_entry(
            10,
            event_types::CAPABILITY_INVOKE,
            Some("fcp.github"),
            Some("issues.create"),
            "request-a",
            BTreeMap::new(),
        )
    }

    fn bound_token(entry: &AuditEntry) -> Value {
        serde_json::json!({
            "id": "token-a",
            "capability_id": "github.issues.write",
            "connector_id": entry.connector_id,
            "operation_id": entry.operation_id,
            "zone_id": entry.zone_id,
            "actor": entry.actor,
            "correlation_id": entry.correlation_id,
        })
    }

    fn admission() -> AuditEntry {
        audit_entry(
            9,
            "capability.admission",
            Some("fcp.github"),
            Some("issues.create"),
            "request-a",
            BTreeMap::from([("decision".to_string(), serde_json::json!("allow"))]),
        )
    }

    fn has_reason(explanation: &CausalExplanation, kind: CausalReasonKind) -> bool {
        explanation.reasons.iter().any(|reason| reason.kind == kind)
    }

    #[test]
    fn explicit_selection_never_substitutes_a_newer_invocation() {
        let older = invocation();
        let mut newer = older.clone();
        newer.id = "newer-invocation".to_string();
        newer.occurred_at += 1;
        newer.correlation_id = "request-b".to_string();
        let bundle = ReplayBundle {
            audit_entries: vec![older.clone(), newer.clone()],
            ..ReplayBundle::default()
        };
        assert_eq!(
            explain_bundle(&bundle).unwrap().invocation_audit_entry_id,
            newer.id
        );
        assert_eq!(
            explain_invocation(&bundle, &older.id)
                .unwrap()
                .invocation_audit_entry_id,
            older.id
        );
        assert_eq!(
            explain_invocation(&bundle, "missing"),
            Err(ExplainError::NoInvocation)
        );
    }

    #[test]
    fn non_invocation_events_and_incomplete_scope_are_not_invocations() {
        let valid = invocation();
        for field in [
            "event_type",
            "id",
            "actor",
            "zone_id",
            "connector_id",
            "operation_id",
        ] {
            let mut entry = valid.clone();
            match field {
                "event_type" => entry.event_type = event_types::SECRET_ACCESS.to_string(),
                "id" => entry.id.clear(),
                "actor" => entry.actor.clear(),
                "zone_id" => entry.zone_id.clear(),
                "connector_id" => entry.connector_id = None,
                _ => entry.operation_id = Some(String::new()),
            }
            let bundle = ReplayBundle {
                audit_entries: vec![entry],
                ..ReplayBundle::default()
            };
            assert_eq!(
                explain_bundle(&bundle),
                Err(ExplainError::NoInvocation),
                "{field}"
            );
        }
    }

    #[test]
    fn selected_id_conflicts_fail_but_identical_duplicates_are_safe() {
        let entry = invocation();
        let mut bundle = ReplayBundle {
            audit_entries: vec![entry.clone(), entry.clone()],
            ..ReplayBundle::default()
        };
        assert!(explain_invocation(&bundle, &entry.id).is_ok());
        bundle.audit_entries[1].actor = "user:mallory".to_string();
        assert_eq!(
            explain_bundle(&bundle),
            Err(ExplainError::ConflictingInvocation)
        );
        assert_eq!(
            explain_invocation(&bundle, &entry.id),
            Err(ExplainError::ConflictingInvocation)
        );
    }

    #[test]
    fn token_scope_must_be_present_and_match_exactly() {
        let entry = invocation();
        let token = bound_token(&entry);
        assert!(token_matches_invocation(&token, &entry));
        assert!(!token_matches_invocation(&serde_json::json!({}), &entry));
        for field in [
            "id",
            "connector_id",
            "operation_id",
            "zone_id",
            "actor",
            "correlation_id",
        ] {
            let mut missing = token.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                !token_matches_invocation(&missing, &entry),
                "missing {field}"
            );
            for value in [Value::Null, serde_json::json!(17), serde_json::json!("")] {
                let mut malformed = token.clone();
                malformed[field] = value;
                assert!(
                    !token_matches_invocation(&malformed, &entry),
                    "malformed {field}"
                );
            }
        }
        for field in [
            "connector_id",
            "operation_id",
            "zone_id",
            "actor",
            "correlation_id",
        ] {
            let mut other = token.clone();
            other[field] = serde_json::json!("another-request");
            assert!(
                !token_matches_invocation(&other, &entry),
                "mismatched {field}"
            );
        }
    }

    #[test]
    fn token_aliases_cannot_hide_conflicting_nested_scope() {
        let entry = invocation();
        let token = bound_token(&entry);
        assert!(token_matches_invocation(
            &serde_json::json!({"claims": token}),
            &entry
        ));
        for nested in [
            serde_json::json!({"zone": "z:private"}),
            serde_json::json!({"sub": "user:mallory"}),
            serde_json::json!({"op": false}),
            serde_json::json!({"correlation": "request-b"}),
            serde_json::json!({"jti": "other-token"}),
        ] {
            let mut conflicting = token.clone();
            conflicting["claims"] = nested;
            assert!(!token_matches_invocation(&conflicting, &entry));
        }
        let mut nested = token;
        for _ in 0..18 {
            nested = serde_json::json!({"claims": nested});
        }
        assert!(!token_matches_invocation(&nested, &entry));
    }

    #[test]
    fn explicit_token_reference_works_without_correlation_but_never_overrides_conflicts() {
        let mut entry = invocation();
        entry.correlation_id.clear();
        let mut token = bound_token(&entry);
        token.as_object_mut().unwrap().remove("correlation_id");
        token["audit_entry_id"] = serde_json::json!(entry.id);
        assert!(token_matches_invocation(&token, &entry));
        token["invocation_audit_entry_id"] = serde_json::json!("foreign-id");
        assert!(!token_matches_invocation(&token, &entry));
    }

    #[test]
    fn ambiguous_token_captures_are_not_selected_by_input_order() {
        let entry = invocation();
        let first = bound_token(&entry);
        let mut second = first.clone();
        second["id"] = serde_json::json!("token-b");
        let mut bundle = ReplayBundle {
            audit_entries: vec![entry.clone()],
            capability_tokens: vec![first, second],
            ..ReplayBundle::default()
        };
        assert!(select_capability_token(&bundle, &entry).is_none());
        bundle.capability_tokens.reverse();
        assert!(select_capability_token(&bundle, &entry).is_none());
    }

    #[test]
    fn admission_requires_explicit_allow_without_conflicting_flags() {
        let mut entry = admission();
        assert!(admission_allows(&entry));
        entry
            .metadata
            .insert("admitted".to_string(), serde_json::json!(false));
        assert!(!admission_allows(&entry));
        entry.metadata.clear();
        assert!(!admission_allows(&entry));
        entry
            .metadata
            .insert("admitted".to_string(), serde_json::json!(true));
        assert!(admission_allows(&entry));
    }

    #[test]
    fn admission_must_precede_dispatch_and_match_the_principal_and_zone() {
        let target = invocation();
        let valid = admission();
        assert!(select_admission_entry(&[valid.clone(), target.clone()], &target).is_some());
        for field in ["actor", "zone", "correlation", "time", "sequence", "type"] {
            let mut other = valid.clone();
            match field {
                "actor" => other.actor = "user:mallory".to_string(),
                "zone" => other.zone_id = "z:private".to_string(),
                "correlation" => other.correlation_id.clear(),
                "time" => other.occurred_at = target.occurred_at + 1,
                "sequence" => other.seq = target.seq,
                _ => other.event_type = "capability.admission.denied".to_string(),
            }
            assert!(
                select_admission_entry(&[other, target.clone()], &target).is_none(),
                "{field}"
            );
        }
        let mut self_admitted = target.clone();
        self_admitted.metadata = valid.metadata;
        assert!(select_admission_entry(&[self_admitted.clone()], &self_admitted).is_none());
    }

    #[test]
    fn a_later_denied_admission_does_not_reveal_an_earlier_allow() {
        let target = invocation();
        let mut allowed = admission();
        allowed.seq = 8;
        let mut denied = admission();
        denied.id = "denied-admission".to_string();
        denied
            .metadata
            .insert("decision".to_string(), serde_json::json!("deny"));
        assert!(select_admission_entry(&[allowed, denied, target.clone()], &target).is_none());
    }

    #[test]
    fn receipt_reference_cannot_fall_back_or_override_conflicting_scope() {
        let target = invocation();
        let receipt = allow_receipt(&target);
        assert!(receipt_matches_invocation(&receipt, &target));
        for field in [
            "reference",
            "zone",
            "connector",
            "operation",
            "correlation",
            "time",
        ] {
            let mut other = receipt.clone();
            match field {
                "reference" => other.audit_entry_id = Some("foreign-id".to_string()),
                "zone" => other.zone_id = "z:private".to_string(),
                "connector" => other.connector_id = Some("fcp.slack".to_string()),
                "operation" => other.operation_id = Some("issues.delete".to_string()),
                "correlation" => other.correlation_id = Some("request-b".to_string()),
                _ => other.decided_at = target.occurred_at + 1,
            }
            assert!(!receipt_matches_invocation(&other, &target), "{field}");
        }
    }

    #[test]
    fn receipt_without_a_reference_requires_complete_correlation_scope() {
        let target = invocation();
        let mut receipt = allow_receipt(&target);
        receipt.audit_entry_id = None;
        assert!(receipt_matches_invocation(&receipt, &target));
        receipt.connector_id = None;
        assert!(!receipt_matches_invocation(&receipt, &target));
        receipt.audit_entry_id = Some(target.id.clone());
        receipt.operation_id = None;
        receipt.correlation_id = None;
        assert!(receipt_matches_invocation(&receipt, &target));
    }

    #[test]
    fn denial_receipts_are_not_hidden_behind_allow_receipts() {
        let target = invocation();
        let mut denied = allow_receipt(&target);
        denied.id = "denial".to_string();
        denied.decision = Decision::Deny;
        denied.reason_code = "capability.revoked".to_string();
        denied.explanation = None;
        let mut bundle = ReplayBundle {
            audit_entries: vec![admission(), target.clone()],
            capability_tokens: vec![bound_token(&target)],
            receipts: vec![allow_receipt(&target), denied],
        };
        let first = explain_bundle(&bundle).unwrap();
        assert!(!has_reason(&first, CausalReasonKind::CapabilityGrant));
        assert!(!has_reason(&first, CausalReasonKind::AuditAdmission));
        assert!(first.render_human().contains("returned deny"));
        assert!(first.render_human().contains("contradicts"));
        assert!(has_reason(&first, CausalReasonKind::RevocationCascade));
        bundle.receipts.reverse();
        assert_eq!(explain_bundle(&bundle).unwrap(), first);
    }

    #[test]
    fn unrelated_revocations_do_not_contaminate_an_invocation() {
        let target = invocation();
        let mut revocation = admission();
        revocation.event_type = event_types::REVOCATION_ISSUED.to_string();
        revocation.zone_id = "z:private".to_string();
        let mut receipt = allow_receipt(&target);
        receipt.audit_entry_id = Some("other-invocation".to_string());
        receipt.decision = Decision::Deny;
        receipt.reason_code = "capability.revoked".to_string();
        let bundle = ReplayBundle {
            audit_entries: vec![revocation, target],
            receipts: vec![receipt],
            ..ReplayBundle::default()
        };
        let explanation = explain_bundle(&bundle).unwrap();
        assert!(!has_reason(
            &explanation,
            CausalReasonKind::RevocationCascade
        ));
        assert!(
            explanation
                .render_human()
                .contains("revocation status is unknown")
        );
        assert!(!explanation.render_human().contains("remained intact"));
    }

    #[test]
    fn revocation_witnesses_are_scoped_sorted_and_deduplicated() {
        let target = invocation();
        let mut revocation = admission();
        revocation.event_type = event_types::REVOCATION_ISSUED.to_string();
        let mut bundle = ReplayBundle {
            audit_entries: vec![revocation.clone(), target.clone(), revocation],
            ..ReplayBundle::default()
        };
        let explanation = explain_bundle(&bundle).unwrap();
        let reason = explanation
            .reasons
            .iter()
            .find(|reason| reason.kind == CausalReasonKind::RevocationCascade)
            .unwrap();
        assert_eq!(reason.evidence.len(), 1);
        bundle.audit_entries.reverse();
        assert_eq!(explain_bundle(&bundle).unwrap(), explanation);
        bundle.audit_entries[0].occurred_at = target.occurred_at + 1;
        bundle.audit_entries[2].seq = target.seq + 1;
        assert!(revocation_reason(&bundle, &target).is_none());
    }

    #[test]
    fn reused_correlation_requires_an_explicit_invocation_reference() {
        let target = invocation();
        let mut previous = target.clone();
        previous.id = "previous-invocation".to_string();
        previous.seq = 8;
        let mut bundle = ReplayBundle {
            audit_entries: vec![previous, admission(), target.clone()],
            capability_tokens: vec![bound_token(&target)],
            receipts: vec![allow_receipt(&target)],
        };
        let explanation = explain_invocation(&bundle, &target.id).unwrap();
        assert!(!has_reason(&explanation, CausalReasonKind::CapabilityGrant));
        assert!(!has_reason(&explanation, CausalReasonKind::AuditAdmission));
        assert!(has_reason(&explanation, CausalReasonKind::DecisionReceipt));
        bundle.capability_tokens[0]["audit_entry_id"] = serde_json::json!(target.id);
        assert!(select_capability_token(&bundle, &target).is_some());
        bundle.receipts[0].audit_entry_id = None;
        assert!(select_receipt(&bundle, &target).is_none());
    }
}
