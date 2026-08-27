//! Causal explanations for replayed audit bundles.
//!
//! The types in this module intentionally operate on replay artifacts rather
//! than live host state. A caller supplies the audit-event chain, capability
//! token evidence, and decision receipts captured with an operation. The
//! explainer then derives a deterministic human-readable "why did this happen"
//! narrative from those artifacts.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Write as _;
use thiserror::Error;

use crate::{AuditEntry, Decision, DecisionReceipt, event_types};

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
}

impl CausalExplanation {
    /// Render the explanation as a human-readable narrative.
    #[must_use]
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Connector {} invoked operation {} at time {} because:",
            self.connector_id, self.operation_id, self.occurred_at
        );
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

    if trimmed.starts_with('{') {
        let value: Value = serde_json::from_str(trimmed).map_err(|err| parse_error(&err))?;
        if looks_like_bundle_object(&value) {
            return serde_json::from_value(value).map_err(|err| parse_error(&err));
        }
        let entry = serde_json::from_value(value).map_err(|err| parse_error(&err))?;
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

    if trimmed.starts_with('{') {
        let value: Value = serde_json::from_str(trimmed).map_err(|err| parse_error(&err))?;
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

/// Build a deterministic causal explanation from replay evidence.
///
/// # Errors
///
/// Returns [`ExplainError::EmptyBundle`] when no replay evidence is present and
/// [`ExplainError::NoInvocation`] when no invocation-like audit entry can be
/// selected from the bundle.
pub fn explain_bundle(bundle: &ReplayBundle) -> Result<CausalExplanation, ExplainError> {
    if bundle.audit_entries.is_empty()
        && bundle.capability_tokens.is_empty()
        && bundle.receipts.is_empty()
    {
        return Err(ExplainError::EmptyBundle);
    }

    let invocation = select_invocation(&bundle.audit_entries).ok_or(ExplainError::NoInvocation)?;
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
    let receipt = select_receipt(&bundle.receipts, invocation);
    let mut reasons = Vec::new();
    let mut warnings = Vec::new();

    if let Some(token) = capability_token {
        reasons.push(capability_reason(token, invocation));
    } else {
        warnings.push(format!(
            "no capability token matched connector {connector_id} operation {operation_id}"
        ));
    }

    if let Some(entry) = admission_entry {
        reasons.push(admission_reason(entry, invocation));
    } else {
        warnings.push(format!(
            "no admission audit event matched invocation {}",
            invocation.id
        ));
    }

    if let Some(decision_receipt) = receipt {
        reasons.push(receipt_reason(decision_receipt));
    } else {
        warnings.push(format!(
            "no allow decision receipt matched invocation {}",
            invocation.id
        ));
    }

    reasons.push(revocation_reason(bundle, invocation, capability_token));

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

    if trimmed.starts_with('{') {
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
    entries.iter().max_by_key(|entry| {
        (
            invocation_score(entry),
            entry.occurred_at,
            entry.seq,
            entry.id.as_str(),
        )
    })
}

fn invocation_score(entry: &AuditEntry) -> u8 {
    let mut score = 0;
    if entry.event_type == event_types::CAPABILITY_INVOKE {
        score += 8;
    }
    if entry.connector_id.is_some() {
        score += 2;
    }
    if entry.operation_id.is_some() {
        score += 2;
    }
    if metadata_value_contains(&entry.metadata, "decision", "allow")
        || metadata_value_contains(&entry.metadata, "admission", "allow")
        || metadata_value_contains(&entry.metadata, "admitted", "true")
    {
        score += 1;
    }
    score
}

fn select_capability_token<'a>(
    bundle: &'a ReplayBundle,
    invocation: &AuditEntry,
) -> Option<&'a Value> {
    bundle
        .capability_tokens
        .iter()
        .find(|token| token_matches_invocation(token, invocation))
}

fn select_admission_entry<'a>(
    entries: &'a [AuditEntry],
    invocation: &'a AuditEntry,
) -> Option<&'a AuditEntry> {
    // br-vs4nt completion: do NOT fall back to the invocation entry
    // itself when no actual admission audit was recorded. Pre-fix the
    // `.or(Some(invocation))` made `admission_entry` always Some, which
    // suppressed the "no admission audit event matched" warning AND
    // injected a misleading `AuditAdmission` reason claiming the
    // invocation entry "recorded the admitted invocation". A bundle
    // with NO real admission audit thus rendered as if admission had
    // been confirmed before dispatch — exactly the cross-evidence
    // borrowing pattern vs4nt closed for capability_token + receipt,
    // missed for admission_entry.
    entries.iter().find(|entry| {
        entry_matches_invocation(entry, invocation)
            && (entry.event_type.contains("admission")
                || metadata_value_contains(&entry.metadata, "decision", "allow")
                || metadata_value_contains(&entry.metadata, "admission", "allow")
                || metadata_value_contains(&entry.metadata, "admitted", "true"))
    })
}

fn select_receipt<'a>(
    receipts: &'a [DecisionReceipt],
    invocation: &AuditEntry,
) -> Option<&'a DecisionReceipt> {
    receipts.iter().find(|receipt| {
        receipt_matches_invocation(receipt, invocation) && receipt.decision.is_allow()
    })
}

fn token_matches_invocation(token: &Value, invocation: &AuditEntry) -> bool {
    field_matches(
        token,
        &["connector_id", "connector"],
        invocation.connector_id.as_deref(),
    ) && field_matches(
        token,
        &["operation_id", "operation", "op"],
        invocation.operation_id.as_deref(),
    ) && field_matches(
        token,
        &["correlation_id", "correlation"],
        non_empty(invocation.correlation_id.as_str()),
    )
}

fn entry_matches_invocation(entry: &AuditEntry, invocation: &AuditEntry) -> bool {
    optional_str_matches(
        entry.connector_id.as_deref(),
        invocation.connector_id.as_deref(),
    ) && optional_str_matches(
        entry.operation_id.as_deref(),
        invocation.operation_id.as_deref(),
    ) && optional_str_matches(
        non_empty(entry.correlation_id.as_str()),
        non_empty(invocation.correlation_id.as_str()),
    )
}

fn receipt_matches_invocation(receipt: &DecisionReceipt, invocation: &AuditEntry) -> bool {
    receipt.audit_entry_id.as_deref() == Some(invocation.id.as_str())
        || (optional_str_matches(
            receipt.connector_id.as_deref(),
            invocation.connector_id.as_deref(),
        ) && optional_str_matches(
            receipt.operation_id.as_deref(),
            invocation.operation_id.as_deref(),
        ) && optional_str_matches(
            receipt.correlation_id.as_deref(),
            non_empty(invocation.correlation_id.as_str()),
        ))
}

fn capability_reason(token: &Value, invocation: &AuditEntry) -> CausalReason {
    let token_id = value_string(token, &["id", "token_id", "jti"])
        .unwrap_or_else(|| "captured-token".to_string());
    let capability = value_string(token, &["capability_id", "capability", "cap"])
        .unwrap_or_else(|| "the required capability".to_string());
    let issuer = value_string(token, &["issuer_kid", "issuer", "iss"])
        .or_else(|| invocation.issuer_kid.as_ref().map(ToString::to_string));
    let mut statement = format!(
        "capability token {token_id} granted {capability} for connector {} operation {}",
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

fn revocation_reason(
    bundle: &ReplayBundle,
    invocation: &AuditEntry,
    token: Option<&Value>,
) -> CausalReason {
    let relevant_revocations: Vec<&AuditEntry> = bundle
        .audit_entries
        .iter()
        .filter(|entry| entry.event_type.contains("revocation"))
        .filter(|entry| {
            optional_str_matches(
                non_empty(entry.correlation_id.as_str()),
                non_empty(invocation.correlation_id.as_str()),
            ) || optional_str_matches(
                entry.connector_id.as_deref(),
                invocation.connector_id.as_deref(),
            )
        })
        .collect();
    let revocation_receipts: Vec<&DecisionReceipt> = bundle
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.decision == Decision::Deny && receipt.reason_code.contains("revocation")
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
        return CausalReason {
            kind: CausalReasonKind::RevocationCascade,
            statement: "revocation cascade triggered for this replay bundle".to_string(),
            evidence,
        };
    }

    let issuer = token
        .and_then(|value| value_string(value, &["issuer_kid", "issuer", "iss"]))
        .or_else(|| invocation.issuer_kid.as_ref().map(ToString::to_string))
        .unwrap_or_else(|| "the captured issuer chain".to_string());
    CausalReason {
        kind: CausalReasonKind::RevocationCascade,
        statement: format!(
            "revocation cascade did not trigger because {issuer} remained intact in the replay evidence"
        ),
        evidence: vec![format!("audit_entry:{}", invocation.id)],
    }
}

fn field_matches(value: &Value, keys: &[&str], expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    value_string(value, keys).is_none_or(|actual| actual == expected)
}

fn optional_str_matches(actual: Option<&str>, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| actual.is_none_or(|actual| actual == expected))
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

fn metadata_value_contains(
    metadata: &std::collections::BTreeMap<String, Value>,
    key: &str,
    expected: &str,
) -> bool {
    metadata
        .get(key)
        .and_then(scalar_to_string)
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
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
        assert!(human.contains("capability token tok-1 granted slack.messages.write"));
        assert!(human.contains("confirmed admission"));
        assert!(human.contains("decision receipt receipt-allow-1 returned allow"));
        assert!(human.contains("revocation cascade did not trigger"));
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
}
