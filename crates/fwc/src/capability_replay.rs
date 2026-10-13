//! Reusable implementation for `fwc capability replay`.

use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fcp_audit::AuditEntry;
pub use fcp_audit::replay::AUDIT_CHAIN_ENV;
use fcp_audit::replay::{
    DEFAULT_REPLAY_WINDOW_SECS, PredicateTrace, ReplayError,
    reconstruct_predicate_trace_from_entries, reconstruct_predicate_trace_from_path,
    validate_replay_window,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Requested capability replay output shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplayOutput {
    /// Embed the canonical JSON trace in the normal fwc payload.
    Json,
    /// Include one predicate-step JSON object per line.
    Jsonl,
    /// Include a concise operator-readable narrative.
    Human,
}

impl ReplayOutput {
    /// Return the command-line spelling for this output mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Human => "human",
        }
    }
}

/// Errors raised by the fwc capability replay adapter.
#[derive(Debug)]
pub enum CapabilityReplayError {
    /// The `--since` duration could not be parsed.
    InvalidSince(String),
    /// Predicate replay failed.
    Replay(ReplayError),
    /// The rendered JSONL payload could not be serialized.
    Serialize(String),
}

impl CapabilityReplayError {
    /// Stable machine-readable error type for fwc output.
    #[must_use]
    pub const fn error_type(&self) -> &'static str {
        match self {
            Self::InvalidSince(_) => "invalid-since-duration",
            Self::Replay(ReplayError::AuditChainUnavailable(_)) => "audit-chain-unavailable",
            Self::Serialize(_) | Self::Replay(ReplayError::AuditChainCorrupted(_)) => {
                "audit-chain-corrupted"
            }
            Self::Replay(ReplayError::WideWindowRequiresConfirm { .. }) => {
                "wide-window-requires-confirm"
            }
            Self::Replay(ReplayError::TokenNotFoundInAuditChain { .. }) => {
                "TokenNotFoundInAuditChain"
            }
        }
    }

    /// Whether retrying after operator action can reasonably succeed.
    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::InvalidSince(_) | Self::Serialize(_) => false,
            Self::Replay(
                ReplayError::WideWindowRequiresConfirm { .. }
                | ReplayError::TokenNotFoundInAuditChain { .. }
                | ReplayError::AuditChainUnavailable(_)
                | ReplayError::AuditChainCorrupted(_),
            ) => true,
        }
    }

    /// Redaction-safe token hash associated with the error, if available.
    #[must_use]
    pub fn token_hash(&self) -> Option<&str> {
        match self {
            Self::Replay(ReplayError::TokenNotFoundInAuditChain { token_hash }) => {
                Some(token_hash.as_str())
            }
            _ => None,
        }
    }
}

impl fmt::Display for CapabilityReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSince(message) => write!(formatter, "{message}"),
            Self::Replay(error) => write!(formatter, "{error}"),
            Self::Serialize(message) => {
                write!(formatter, "failed to render replay output: {message}")
            }
        }
    }
}

impl std::error::Error for CapabilityReplayError {}

impl From<ReplayError> for CapabilityReplayError {
    fn from(value: ReplayError) -> Self {
        Self::Replay(value)
    }
}

/// Build a complete fwc payload for a capability replay request.
///
/// # Errors
///
/// Returns [`CapabilityReplayError`] when the duration, audit-chain input, or
/// predicate trace reconstruction fails.
pub fn build_replay_payload(
    token: &str,
    since: &str,
    confirm: bool,
    audit_chain: Option<&Path>,
    output: ReplayOutput,
    now_unix: u64,
) -> Result<Value, CapabilityReplayError> {
    let since_seconds = parse_since_seconds(since)?;
    // Do not open a file or block on stdin before the caller confirms a wide scan.
    validate_replay_window(since_seconds, confirm)?;
    let path = audit_chain
        .map(PathBuf::from)
        .or_else(|| std::env::var_os(AUDIT_CHAIN_ENV).map(PathBuf::from))
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| {
            ReplayError::AuditChainUnavailable(format!(
                "no artifact configured; use --audit-chain or set {AUDIT_CHAIN_ENV}"
            ))
        })?;
    let trace = reconstruct_predicate_trace_from_path(
        token,
        Duration::from_secs(since_seconds),
        confirm,
        now_unix,
        &path,
    )?;
    payload_from_trace(&trace, output)
}

/// Build a complete fwc payload from already-loaded audit entries.
///
/// # Errors
///
/// Returns [`CapabilityReplayError`] when reconstruction or rendering fails.
pub fn build_replay_payload_from_entries(
    token: &str,
    since_seconds: u64,
    confirm: bool,
    entries: &[AuditEntry],
    output: ReplayOutput,
    now_unix: u64,
) -> Result<Value, CapabilityReplayError> {
    let trace = reconstruct_predicate_trace_from_entries(
        token,
        Duration::from_secs(since_seconds),
        confirm,
        now_unix,
        entries,
    )?;
    payload_from_trace(&trace, output)
}

/// Parse an fwc duration such as `30s`, `5m`, `2h`, or `7d`.
///
/// # Errors
///
/// Returns [`CapabilityReplayError::InvalidSince`] when the string is empty,
/// has an unsupported suffix, has a non-integer amount, or overflows `u64`.
pub fn parse_since_seconds(raw: &str) -> Result<u64, CapabilityReplayError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CapabilityReplayError::InvalidSince(
            "empty duration".to_owned(),
        ));
    }

    let (number, multiplier) = match trimmed.as_bytes().last() {
        Some(b's') => (&trimmed[..trimmed.len() - 1], 1_u64),
        Some(b'm') => (&trimmed[..trimmed.len() - 1], 60),
        Some(b'h') => (&trimmed[..trimmed.len() - 1], 3_600),
        Some(b'd') => (&trimmed[..trimmed.len() - 1], 86_400),
        Some(byte) if byte.is_ascii_digit() => (trimmed, 1),
        Some(_) => {
            return Err(CapabilityReplayError::InvalidSince(format!(
                "unknown duration suffix in `{trimmed}`; use s, m, h, or d"
            )));
        }
        None => unreachable!("empty duration returned earlier"),
    };

    let value = number.parse::<u64>().map_err(|_| {
        CapabilityReplayError::InvalidSince(format!("invalid number in duration `{number}`"))
    })?;
    value.checked_mul(multiplier).ok_or_else(|| {
        CapabilityReplayError::InvalidSince(format!("duration `{trimmed}` overflows seconds"))
    })
}

/// Return the current Unix timestamp in seconds.
#[must_use]
pub fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn payload_from_trace(
    trace: &PredicateTrace,
    output: ReplayOutput,
) -> Result<Value, CapabilityReplayError> {
    let mut payload = serde_json::to_value(trace)
        .map_err(|error| CapabilityReplayError::Serialize(error.to_string()))?;
    let Some(object) = payload.as_object_mut() else {
        return Err(CapabilityReplayError::Serialize(
            "trace did not serialize to an object".to_owned(),
        ));
    };

    object.insert("status".to_owned(), json!("ok"));
    object.insert("command".to_owned(), json!("capability"));
    object.insert("subcommand".to_owned(), json!("replay"));
    object.insert("output".to_owned(), json!(output.as_str()));
    object.insert(
        "source".to_owned(),
        json!({
            "kind": "audit-chain-artifact",
            "default_window_seconds": DEFAULT_REPLAY_WINDOW_SECS,
        }),
    );

    match output {
        ReplayOutput::Json => {}
        ReplayOutput::Jsonl => {
            object.insert("jsonl".to_owned(), json!(render_jsonl(trace)?));
        }
        ReplayOutput::Human => {
            object.insert("human".to_owned(), json!(render_human(trace)));
        }
    }

    Ok(payload)
}

fn render_jsonl(trace: &PredicateTrace) -> Result<String, CapabilityReplayError> {
    trace
        .trace
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| lines.join("\n"))
        .map_err(|error| CapabilityReplayError::Serialize(error.to_string()))
}

fn render_human(trace: &PredicateTrace) -> String {
    let mut output = format!(
        "capability replay: {} ({} steps, {}us)\n",
        serde_json::to_string(&trace.final_verdict).unwrap_or_else(|_| "\"unknown\"".to_owned()),
        trace.total_steps,
        trace.total_latency_us
    );
    writeln!(
        &mut output,
        "audit chain: {}..{}",
        trace.audit_chain_range.start_seq, trace.audit_chain_range.end_seq
    )
    .expect("writing to String cannot fail");
    for step in &trace.trace {
        writeln!(
            &mut output,
            "{} -> {} witness={:?} evaluator={}",
            step.rule_name, step.output, step.witness_chain_indices, step.evaluator_version
        )
        .expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use fcp_audit::{AuditEntry, AuditEntryBuilder, event_types};

    use crate::capability_replay::{
        CapabilityReplayError, ReplayOutput, build_replay_payload,
        build_replay_payload_from_entries, parse_since_seconds,
    };

    const NOW: u64 = 1_700_000_100;
    const TOKEN: &str = "cap-token-secret";

    #[test]
    fn wide_window_is_rejected_before_reading_stdin() {
        let error = build_replay_payload(
            TOKEN,
            "8d",
            false,
            Some(std::path::Path::new("-")),
            ReplayOutput::Json,
            NOW,
        )
        .expect_err("confirmation precedes potentially blocking stdin");
        assert_eq!(error.error_type(), "wide-window-requires-confirm");
    }

    #[test]
    fn explicitly_empty_source_is_unavailable_not_token_absence() {
        let error = build_replay_payload(
            TOKEN,
            "7d",
            false,
            Some(std::path::Path::new("")),
            ReplayOutput::Json,
            NOW,
        )
        .expect_err("an absent source cannot prove token absence");
        assert_eq!(error.error_type(), "audit-chain-unavailable");
        assert!(error.recoverable());
        assert!(error.token_hash().is_none());
    }

    #[test]
    fn invalid_duration_precedes_source_resolution() {
        let error = build_replay_payload(
            TOKEN,
            "not-a-duration",
            false,
            Some(std::path::Path::new("-")),
            ReplayOutput::Json,
            NOW,
        )
        .expect_err("invalid duration");
        assert_eq!(error.error_type(), "invalid-since-duration");
    }

    fn entry(seq: u64, metadata: Vec<(&str, Value)>) -> AuditEntry {
        metadata
            .into_iter()
            .fold(
                AuditEntryBuilder::new()
                    .id(format!("entry-{seq}"))
                    .event_type(event_types::CAPABILITY_INVOKE)
                    .actor("user:alice")
                    .zone_id("z:work")
                    .seq(seq)
                    .occurred_at(NOW - 10 + seq),
                |builder, (key, value)| builder.meta(key, value),
            )
            .build()
            .expect("audit entry builds")
    }

    #[test]
    fn parse_since_supports_documented_units() {
        assert_eq!(parse_since_seconds("30s").expect("seconds"), 30);
        assert_eq!(parse_since_seconds("5m").expect("minutes"), 300);
        assert_eq!(parse_since_seconds("2h").expect("hours"), 7_200);
        assert_eq!(parse_since_seconds("7d").expect("days"), 604_800);
        assert_eq!(parse_since_seconds("42").expect("bare seconds"), 42);
    }

    #[test]
    fn payload_includes_rendered_human_output() {
        let entries = vec![entry(
            1,
            vec![
                ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
                ("rule_name", json!("zone_match")),
                ("inputs_json", json!({"src_zone": "z:work"})),
                ("output", json!(true)),
                ("latency_us", json!(25)),
            ],
        )];

        let payload = build_replay_payload_from_entries(
            TOKEN,
            604_800,
            false,
            &entries,
            ReplayOutput::Human,
            NOW,
        )
        .expect("payload builds");

        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["command"], "capability");
        assert_eq!(payload["subcommand"], "replay");
        assert!(
            payload["human"]
                .as_str()
                .expect("human output")
                .contains("zone_match")
        );
    }

    #[test]
    fn wide_window_error_type_is_stable() {
        let error =
            build_replay_payload_from_entries(TOKEN, 604_801, false, &[], ReplayOutput::Json, NOW)
                .expect_err("wide window requires confirm");

        assert!(matches!(
            error,
            CapabilityReplayError::Replay(
                fcp_audit::replay::ReplayError::WideWindowRequiresConfirm { .. }
            )
        ));
        assert_eq!(error.error_type(), "wide-window-requires-confirm");
    }

    #[test]
    fn all_output_modes_redact_labels_and_nested_secret_keys() {
        let evidence = entry(1, vec![
            ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
            ("rule_name", json!(format!("zone_match:{TOKEN}"))),
            ("evaluator_version", json!(format!("v1:{TOKEN}"))),
            ("inputs_json", json!({"nested": {(TOKEN): "value"}})),
            ("output", json!(true)),
        ]);
        for output in [ReplayOutput::Json, ReplayOutput::Jsonl, ReplayOutput::Human] {
            let payload = build_replay_payload_from_entries(
                TOKEN, 60, false, std::slice::from_ref(&evidence), output, NOW,
            ).expect("redacted payload");
            assert!(!payload.to_string().contains(TOKEN));
            assert_eq!(payload["status"], "ok");
            if output == ReplayOutput::Jsonl {
                let line = payload["jsonl"].as_str().expect("JSONL string");
                let step: Value = serde_json::from_str(line).expect("valid JSONL step");
                assert_eq!(step["output"], true);
            }
        }
    }

    #[test]
    fn contradictory_evidence_is_reported_as_corruption_not_success() {
        let evidence = entry(1, vec![
            ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
            ("rule_name", json!("revocation_check")),
            ("output", json!(false)),
            ("final_verdict", json!("accepted")),
        ]);
        let error = build_replay_payload_from_entries(
            TOKEN, 60, false, &[evidence], ReplayOutput::Json, NOW,
        ).expect_err("cannot render contradictory evidence as success");
        assert_eq!(error.error_type(), "audit-chain-corrupted");
        assert!(!error.to_string().contains(TOKEN));
    }
}
