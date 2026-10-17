//! Predicate-trace reconstruction for capability-token audit replay.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::AuditEntry;
use crate::explain::parse_replay_bundle;

/// Default replay lookback window: seven days.
pub const DEFAULT_REPLAY_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

/// Explicitly configured default artifact, shared with `fwc capability replay`.
pub const AUDIT_CHAIN_ENV: &str = "FWC_AUDIT_CHAIN";

/// Maximum artifact size in bytes, including whitespace (16 MiB).
///
/// Confirmation expands the lookback window, never the input-size limit.
pub const MAX_REPLAY_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

const TOKEN_HASH_PREFIX: &str = "blake3:";
const DEFAULT_EVALUATOR_VERSION: &str = "0.0.0";
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "secret",
    "token",
    "password",
    "credential",
    "private_key",
    "api_key",
    "service_account",
    "authorization",
    "cookie",
];

/// Reconstructed predicate trace for one capability token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateTrace {
    /// Redaction-safe BLAKE3 hash of the input token.
    pub token_hash: String,
    /// Final capability-decision verdict inferred from predicate steps.
    pub final_verdict: FinalVerdict,
    /// Number of predicate steps in `trace`.
    pub total_steps: usize,
    /// Reconstructed latency in microseconds.
    pub total_latency_us: u64,
    /// Audit-chain sequence span used as witness evidence.
    pub audit_chain_range: AuditChainRange,
    /// Ordered predicate-evaluation steps.
    pub trace: Vec<PredicateStep>,
}

/// Inclusive audit-chain sequence range used by a replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainRange {
    /// First audit-chain sequence number consulted.
    pub start_seq: u64,
    /// Last audit-chain sequence number consulted.
    pub end_seq: u64,
}

/// One predicate-evaluation step reconstructed from audit-chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateStep {
    /// Stable predicate or rule identifier.
    pub rule_name: String,
    /// Redacted predicate inputs.
    pub inputs_json: Value,
    /// Boolean predicate result.
    pub output: bool,
    /// Audit-chain sequence numbers that witness this step.
    pub witness_chain_indices: Vec<u64>,
    /// Evaluator version captured by the audit source.
    pub evaluator_version: String,
}

/// Final decision represented by a capability predicate trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalVerdict {
    /// Every predicate step accepted the token.
    Accepted,
    /// A non-revocation predicate rejected the token.
    RejectedPredicate,
    /// The token was rejected because revocation evidence was present.
    RejectedRevocation,
    /// The token was rejected because it had expired.
    RejectedExpired,
}

/// Errors that can occur while reconstructing a predicate trace.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReplayError {
    /// Requested window exceeds the default cap and the caller did not confirm.
    #[error(
        "replay window {since_secs}s exceeds default cap {max_secs}s; pass --confirm to continue"
    )]
    WideWindowRequiresConfirm {
        /// Requested lookback window in seconds.
        since_secs: u64,
        /// Default unconfirmed lookback cap in seconds.
        max_secs: u64,
    },
    /// No matching audit entries were found.
    #[error("capability token {token_hash} has no audit-chain entries in the requested window")]
    TokenNotFoundInAuditChain {
        /// Redaction-safe BLAKE3 hash of the requested token.
        token_hash: String,
    },
    /// The audit chain could not be read.
    #[error("audit chain unavailable: {0}")]
    AuditChainUnavailable(String),
    /// Matching entries were present but unusable as predicate evidence.
    #[error("audit chain corrupted: {0}")]
    AuditChainCorrupted(String),
}

/// Return the redaction-safe capability-token hash used by replay outputs.
#[must_use]
pub fn token_hash(token: &str) -> String {
    format!(
        "{TOKEN_HASH_PREFIX}{}",
        blake3::hash(token.as_bytes()).to_hex()
    )
}

/// Reconstruct a predicate trace from the artifact configured by [`AUDIT_CHAIN_ENV`].
///
/// No configuration is an unavailable source, not evidence that a token was
/// absent from an audit chain. A configured `-` explicitly selects standard
/// input. Use [`reconstruct_predicate_trace_from_path`] or
/// [`reconstruct_predicate_trace_from_reader`] to supply a source without
/// consulting the environment. Artifact replay does not authenticate its source
/// or claim to walk a live, signature-verified host audit chain.
///
/// # Errors
///
/// Returns [`ReplayError::WideWindowRequiresConfirm`] when `since` exceeds the
/// seven-day cap without confirmation, [`ReplayError::AuditChainUnavailable`]
/// for absent or unreadable sources, or the artifact/reconstruction errors
/// documented by [`reconstruct_predicate_trace_from_reader`].
pub fn reconstruct_predicate_trace(
    token: &str,
    since: Duration,
    confirm: bool,
) -> Result<PredicateTrace, ReplayError> {
    validate_replay_window(since.as_secs(), confirm)?;
    let path = std::env::var_os(AUDIT_CHAIN_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            ReplayError::AuditChainUnavailable(format!(
                "no artifact configured; set {AUDIT_CHAIN_ENV} or supply an explicit source"
            ))
        })?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    reconstruct_predicate_trace_from_path(token, since, confirm, now_unix, &path)
}

/// Reconstruct a trace from an explicit artifact path, or `-` for standard input.
///
/// The confirmation gate runs before opening the source. Read sizes are bounded
/// by [`MAX_REPLAY_ARTIFACT_BYTES`]; this is not an I/O timeout or source attestation.
///
/// # Errors
///
/// Returns [`ReplayError::AuditChainUnavailable`] if the file cannot be opened,
/// or any error from [`reconstruct_predicate_trace_from_reader`].
pub fn reconstruct_predicate_trace_from_path(
    token: &str,
    since: Duration,
    confirm: bool,
    now_unix: u64,
    path: &Path,
) -> Result<PredicateTrace, ReplayError> {
    validate_replay_window(since.as_secs(), confirm)?;
    if path.as_os_str() == "-" {
        return reconstruct_predicate_trace_from_reader(
            token,
            since,
            confirm,
            now_unix,
            std::io::stdin().lock(),
        );
    }
    let file = std::fs::File::open(path).map_err(|error| {
        ReplayError::AuditChainUnavailable(format!(
            "cannot open audit-chain artifact: {:?}",
            error.kind()
        ))
    })?;
    reconstruct_predicate_trace_from_reader(token, since, confirm, now_unix, file)
}

/// Reconstruct a trace from a bounded UTF-8 JSON, JSONL, or replay-bundle reader.
///
/// Reads at most [`MAX_REPLAY_ARTIFACT_BYTES`] plus one byte to detect overflow.
/// No partial prefix is replayed after an I/O, size, encoding, or parsing error.
/// The caller owns the source's trust and I/O deadline policy.
///
/// # Errors
///
/// Returns [`ReplayError::WideWindowRequiresConfirm`] before reading when needed,
/// [`ReplayError::AuditChainUnavailable`] on I/O failure, or
/// [`ReplayError::AuditChainCorrupted`] for oversized or malformed input.
/// A successfully read empty chain returns [`ReplayError::TokenNotFoundInAuditChain`].
pub fn reconstruct_predicate_trace_from_reader(
    token: &str,
    since: Duration,
    confirm: bool,
    now_unix: u64,
    reader: impl Read,
) -> Result<PredicateTrace, ReplayError> {
    validate_replay_window(since.as_secs(), confirm)?;
    let mut reader = reader.take(MAX_REPLAY_ARTIFACT_BYTES + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|error| {
        ReplayError::AuditChainUnavailable(format!(
            "cannot read audit-chain artifact: {:?}",
            error.kind()
        ))
    })?;
    if reader.limit() == 0 {
        return Err(ReplayError::AuditChainCorrupted(format!(
            "audit-chain artifact exceeds {MAX_REPLAY_ARTIFACT_BYTES} bytes"
        )));
    }
    let input = String::from_utf8(bytes).map_err(|_| {
        ReplayError::AuditChainCorrupted("audit-chain artifact is not UTF-8".to_owned())
    })?;
    // Parser diagnostics can quote attacker-controlled fields containing secrets.
    let bundle = parse_replay_bundle(&input).map_err(|_| {
        ReplayError::AuditChainCorrupted("invalid JSON/JSONL audit-chain artifact".to_owned())
    })?;
    reconstruct_predicate_trace_from_entries(token, since, confirm, now_unix, &bundle.audit_entries)
}

/// Reconstruct a predicate trace from captured audit entries.
///
/// # Errors
///
/// Returns [`ReplayError::WideWindowRequiresConfirm`] when `since` exceeds the
/// seven-day cap without confirmation, [`ReplayError::TokenNotFoundInAuditChain`]
/// when the window has no matching entries, or
/// [`ReplayError::AuditChainCorrupted`] when matching entries lack usable
/// predicate-step evidence.
/// Only exact, typed token-identity metadata selects evidence. A declared hash
/// takes precedence over raw identifiers; free-form inputs never establish
/// token identity. Conflicting decisions require a narrower artifact rather
/// than combining separate evaluations into a fabricated single decision.
/// Zone and correlation boundaries must also agree, including missing versus
/// present correlation IDs. Uncorrelated artifacts remain caller-scoped.
pub fn reconstruct_predicate_trace_from_entries(
    token: &str,
    since: Duration,
    confirm: bool,
    now_unix: u64,
    entries: &[AuditEntry],
) -> Result<PredicateTrace, ReplayError> {
    let since_secs = since.as_secs();
    validate_replay_window(since_secs, confirm)?;

    let token_hash = token_hash(token);
    let cutoff = now_unix.saturating_sub(since_secs);
    let mut selected = Vec::new();
    for entry in entries {
        if entry.occurred_at >= cutoff
            && entry.occurred_at <= now_unix
            && entry_mentions_token(entry, token, &token_hash)?
        {
            selected.push(entry);
        }
    }

    selected.sort_by_key(|entry| (entry.seq, entry.occurred_at, entry.id.as_str()));

    if selected.is_empty() {
        return Err(ReplayError::TokenNotFoundInAuditChain { token_hash });
    }

    if let Some(first) = selected.first()
        && selected.iter().any(|entry| {
            entry.zone_id != first.zone_id || entry.correlation_id != first.correlation_id
        })
    {
        return Err(ReplayError::AuditChainCorrupted(
            "matching entries cross zone or correlation boundaries; supply a single-evaluation artifact"
                .to_owned(),
        ));
    }

    let mut trace = Vec::new();
    let mut explicit_latency_us = 0_u64;
    let mut saw_explicit_latency = false;
    let mut explicit_verdict = None;

    for entry in &selected {
        if let Some(latency_us) = metadata_u64(&entry.metadata, &["latency_us", "duration_us"]) {
            explicit_latency_us = explicit_latency_us.saturating_add(latency_us);
            saw_explicit_latency = true;
        }
        if let Some(verdict) = metadata_verdict(&entry.metadata)? {
            if explicit_verdict.is_some_and(|previous| previous != verdict) {
                return Err(ReplayError::AuditChainCorrupted(
                    "matching entries contain conflicting decisions; supply a single-decision artifact"
                        .to_owned(),
                ));
            }
            explicit_verdict = Some(verdict);
        }
        trace.extend(predicate_steps_from_entry(entry, token)?);
    }

    if trace.is_empty() {
        return Err(ReplayError::AuditChainCorrupted(
            "matched token entries contained no predicate trace steps".to_owned(),
        ));
    }

    let audit_chain_range = chain_range(&trace).ok_or_else(|| {
        ReplayError::AuditChainCorrupted(
            "predicate trace did not include witness chain indices".to_owned(),
        )
    })?;
    let total_latency_us = if saw_explicit_latency {
        explicit_latency_us
    } else {
        reconstructed_latency_us(&selected)
    };
    let final_verdict = explicit_verdict.unwrap_or_else(|| infer_final_verdict(&trace));
    if final_verdict == FinalVerdict::Accepted && trace.iter().any(|step| !step.output) {
        return Err(ReplayError::AuditChainCorrupted(
            "accepted verdict contradicts failed predicate evidence".to_owned(),
        ));
    }

    // Infer from the original rule labels before redacting them. Redaction must
    // not change expiry/revocation classification when a token ID overlaps a
    // rule label, nor expose the token through labels in JSON or human output.
    for step in &mut trace {
        step.rule_name = redact_label(&step.rule_name, token);
        step.evaluator_version = redact_label(&step.evaluator_version, token);
    }

    Ok(PredicateTrace {
        token_hash,
        final_verdict,
        total_steps: trace.len(),
        total_latency_us,
        audit_chain_range,
        trace,
    })
}

/// Validate the replay lookback before resolving or reading an artifact.
///
/// # Errors
///
/// Returns [`ReplayError::WideWindowRequiresConfirm`] for an unconfirmed window
/// longer than [`DEFAULT_REPLAY_WINDOW_SECS`].
pub const fn validate_replay_window(since_secs: u64, confirm: bool) -> Result<(), ReplayError> {
    if since_secs > DEFAULT_REPLAY_WINDOW_SECS && !confirm {
        return Err(ReplayError::WideWindowRequiresConfirm {
            since_secs,
            max_secs: DEFAULT_REPLAY_WINDOW_SECS,
        });
    }
    Ok(())
}

fn entry_mentions_token(
    entry: &AuditEntry,
    raw_token: &str,
    token_hash: &str,
) -> Result<bool, ReplayError> {
    if raw_token.is_empty() {
        return Ok(false);
    }
    let mut hashes = entry
        .metadata
        .iter()
        .filter(|(key, _)| is_token_hash_key(key))
        .peekable();
    if hashes.peek().is_some() {
        // Never let an unrelated raw ID or free-form mention override an
        // explicit digest. All supplied digest aliases must agree exactly.
        return consistent_identity(hashes.map(|(_, value)| value), token_hash);
    }
    let identities = entry
        .metadata
        .iter()
        .filter(|(key, _)| is_token_identity_key(key));
    consistent_identity(identities.map(|(_, value)| value), raw_token)
}

fn consistent_identity<'a>(
    values: impl Iterator<Item = &'a Value>,
    expected: &str,
) -> Result<bool, ReplayError> {
    let mut matching = false;
    let mut mismatching = false;
    for value in values {
        if value.as_str() == Some(expected) {
            matching = true;
        } else {
            mismatching = true;
        }
    }
    if matching && mismatching {
        // Excluding an ambiguous entry could silently erase a rejected step
        // while retaining other, accepting evidence for the same token.
        return Err(ReplayError::AuditChainCorrupted(
            "matching entry contains conflicting token identity aliases".to_owned(),
        ));
    }
    Ok(matching)
}

fn is_token_hash_key(key: &str) -> bool {
    matches!(
        key,
        "token_hash" | "capability_token_hash" | "capability_hash" | "capability_token_digest"
    )
}

fn is_token_identity_key(key: &str) -> bool {
    matches!(key, "token_id" | "capability_token_id" | "jti")
}

fn predicate_steps_from_entry(
    entry: &AuditEntry,
    raw_token: &str,
) -> Result<Vec<PredicateStep>, ReplayError> {
    if let Some(trace) = consistent_alias(
        entry.metadata.get("predicate_trace"),
        entry.metadata.get("trace"),
    )? {
        let trace = trace
            .as_array()
            .filter(|steps| !steps.is_empty())
            .ok_or_else(|| {
                ReplayError::AuditChainCorrupted(
                    "predicate trace must be a non-empty JSON array".to_owned(),
                )
            })?;
        return trace
            .iter()
            .map(|value| predicate_step_from_value(value, entry.seq, raw_token))
            .collect();
    }

    Ok(direct_predicate_step(entry, raw_token)?
        .into_iter()
        .collect())
}

fn predicate_step_from_value(
    value: &Value,
    fallback_seq: u64,
    raw_token: &str,
) -> Result<PredicateStep, ReplayError> {
    let Some(object) = value.as_object() else {
        return Err(ReplayError::AuditChainCorrupted(
            "predicate_trace entries must be JSON objects".to_owned(),
        ));
    };
    let rule_name = object_string(object, &["rule_name", "predicate", "name"])
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            ReplayError::AuditChainCorrupted(
                "predicate_trace entry is missing rule_name".to_owned(),
            )
        })?;
    let output = object_bool(object, &["output", "result", "allowed"]).ok_or_else(|| {
        ReplayError::AuditChainCorrupted(
            "predicate_trace entry has missing, invalid, or conflicting boolean output".to_owned(),
        )
    })?;
    let inputs_json = object
        .get("inputs_json")
        .or_else(|| object.get("inputs"))
        .or_else(|| object.get("input"))
        .map_or_else(|| json!({}), |value| redact_inputs(value, raw_token));
    let witness_chain_indices = object_witness_indices(object, fallback_seq)?;
    let evaluator_version = object_string(object, &["evaluator_version", "version"])
        .unwrap_or_else(|| DEFAULT_EVALUATOR_VERSION.to_owned());

    Ok(PredicateStep {
        rule_name,
        inputs_json,
        output,
        witness_chain_indices,
        evaluator_version,
    })
}

fn direct_predicate_step(
    entry: &AuditEntry,
    raw_token: &str,
) -> Result<Option<PredicateStep>, ReplayError> {
    if ![
        "rule_name",
        "predicate",
        "name",
        "output",
        "result",
        "allowed",
    ]
    .iter()
    .any(|key| entry.metadata.contains_key(*key))
    {
        return Ok(None);
    }
    let rule_name = metadata_string(&entry.metadata, &["rule_name", "predicate", "name"])
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            ReplayError::AuditChainCorrupted(
                "predicate entry has missing or invalid rule_name".to_owned(),
            )
        })?;
    let output =
        metadata_bool(&entry.metadata, &["output", "result", "allowed"]).ok_or_else(|| {
            ReplayError::AuditChainCorrupted(
                "predicate entry has missing, invalid, or conflicting boolean output".to_owned(),
            )
        })?;
    let inputs_json = entry
        .metadata
        .get("inputs_json")
        .or_else(|| entry.metadata.get("inputs"))
        .or_else(|| entry.metadata.get("input"))
        .map_or_else(|| json!({}), |value| redact_inputs(value, raw_token));
    let witness_chain_indices = metadata_witness_indices(&entry.metadata, entry.seq)?;
    let evaluator_version = metadata_string(&entry.metadata, &["evaluator_version", "version"])
        .unwrap_or_else(|| DEFAULT_EVALUATOR_VERSION.to_owned());

    Ok(Some(PredicateStep {
        rule_name,
        inputs_json,
        output,
        witness_chain_indices,
        evaluator_version,
    }))
}

fn redact_label(value: &str, raw_token: &str) -> String {
    if raw_token.is_empty() {
        value.to_owned()
    } else {
        value.replace(raw_token, "<redacted>")
    }
}

fn redact_inputs(value: &Value, raw_token: &str) -> Value {
    redact_value(value, raw_token, None)
}

fn redact_value(value: &Value, raw_token: &str, key: Option<&str>) -> Value {
    if key.is_some_and(is_sensitive_key) {
        return redaction_marker(redacted_len(value));
    }

    match value {
        Value::String(value) if !raw_token.is_empty() && value.contains(raw_token) => {
            redaction_marker(value.len())
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| redact_value(value, raw_token, None))
                .collect(),
        ),
        // Redact the enclosing object rather than renaming secret-bearing keys:
        // renamed keys could collide and silently discard unrelated evidence.
        Value::Object(object)
            if !raw_token.is_empty() && object.keys().any(|key| key.contains(raw_token)) =>
        {
            redaction_marker(redacted_len(value))
        }
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), redact_value(value, raw_token, Some(key))))
                .collect(),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

fn redaction_marker(len: usize) -> Value {
    json!({ "<redacted>": { "len": len } })
}

fn redacted_len(value: &Value) -> usize {
    value
        .as_str()
        .map_or_else(|| value.to_string().len(), str::len)
}

fn metadata_string(metadata: &MapLike, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| metadata.get(*key))
        .and_then(scalar_string)
        .map(str::to_owned)
}

fn metadata_bool(metadata: &MapLike, keys: &[&str]) -> Option<bool> {
    consistent_bool(keys.iter().filter_map(|key| metadata.get(*key)))
}

fn metadata_u64(metadata: &MapLike, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| metadata.get(*key).and_then(Value::as_u64))
}

fn metadata_verdict(metadata: &MapLike) -> Result<Option<FinalVerdict>, ReplayError> {
    let mut result = None;
    for value in ["final_verdict", "verdict"]
        .iter()
        .filter_map(|key| metadata.get(*key))
    {
        let verdict = value
            .as_str()
            .and_then(parse_final_verdict)
            .ok_or_else(|| {
                ReplayError::AuditChainCorrupted("invalid explicit verdict".to_owned())
            })?;
        if result.is_some_and(|previous| previous != verdict) {
            return Err(ReplayError::AuditChainCorrupted(
                "conflicting explicit verdict aliases".to_owned(),
            ));
        }
        result = Some(verdict);
    }
    Ok(result)
}

type MapLike = std::collections::BTreeMap<String, Value>;

fn object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(scalar_string)
        .map(str::to_owned)
}

fn object_bool(object: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    consistent_bool(keys.iter().filter_map(|key| object.get(*key)))
}

fn consistent_bool<'a>(values: impl Iterator<Item = &'a Value>) -> Option<bool> {
    let mut result = None;
    for value in values {
        let output = scalar_bool(value)?;
        if result.is_some_and(|previous| previous != output) {
            return None;
        }
        result = Some(output);
    }
    result
}

fn scalar_string(value: &Value) -> Option<&str> {
    value.as_str()
}

fn scalar_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) if value.eq_ignore_ascii_case("true") => Some(true),
        Value::String(value) if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn object_witness_indices(
    object: &Map<String, Value>,
    fallback_seq: u64,
) -> Result<Vec<u64>, ReplayError> {
    consistent_alias(
        object.get("witness_chain_indices"),
        object.get("witness_seq"),
    )?
    .map_or_else(|| Ok(vec![fallback_seq]), witness_indices)
}

fn metadata_witness_indices(
    metadata: &MapLike,
    fallback_seq: u64,
) -> Result<Vec<u64>, ReplayError> {
    consistent_alias(
        metadata.get("witness_chain_indices"),
        metadata.get("witness_seq"),
    )?
    .map_or_else(|| Ok(vec![fallback_seq]), witness_indices)
}

fn consistent_alias<'a>(
    primary: Option<&'a Value>,
    alias: Option<&'a Value>,
) -> Result<Option<&'a Value>, ReplayError> {
    if let (Some(primary), Some(alias)) = (primary, alias)
        && primary != alias
    {
        return Err(ReplayError::AuditChainCorrupted(
            "conflicting evidence aliases".to_owned(),
        ));
    }
    Ok(primary.or(alias))
}

fn witness_indices(value: &Value) -> Result<Vec<u64>, ReplayError> {
    let indices = match value {
        Value::Number(number) => number.as_u64().map(|value| vec![value]),
        Value::Array(values) => values.iter().map(Value::as_u64).collect::<Option<Vec<_>>>(),
        _ => None,
    };
    indices
        .filter(|indices| !indices.is_empty())
        .ok_or_else(|| {
            ReplayError::AuditChainCorrupted(
            "witness indices must be an unsigned integer or a non-empty array of unsigned integers"
                .to_owned(),
        )
        })
}

fn chain_range(trace: &[PredicateStep]) -> Option<AuditChainRange> {
    let mut iter = trace
        .iter()
        .flat_map(|step| step.witness_chain_indices.iter().copied());
    let first = iter.next()?;
    let (start_seq, end_seq) = iter.fold((first, first), |(min, max), seq| {
        (min.min(seq), max.max(seq))
    });
    Some(AuditChainRange { start_seq, end_seq })
}

const fn reconstructed_latency_us(selected: &[&AuditEntry]) -> u64 {
    let Some(first) = selected.first() else {
        return 0;
    };
    let Some(last) = selected.last() else {
        return 0;
    };
    last.occurred_at
        .saturating_sub(first.occurred_at)
        .saturating_mul(1_000_000)
}

fn infer_final_verdict(trace: &[PredicateStep]) -> FinalVerdict {
    let Some(rejection) = trace.iter().rev().find(|step| !step.output) else {
        return FinalVerdict::Accepted;
    };

    let rule = rejection.rule_name.to_ascii_lowercase();
    if rule.contains("revocation") || rule.contains("revoked") {
        FinalVerdict::RejectedRevocation
    } else if rule.contains("expiry") || rule.contains("expired") || rule.contains("expiration") {
        FinalVerdict::RejectedExpired
    } else {
        FinalVerdict::RejectedPredicate
    }
}

fn parse_final_verdict(value: &str) -> Option<FinalVerdict> {
    match value {
        "accepted" => Some(FinalVerdict::Accepted),
        "rejected_predicate" => Some(FinalVerdict::RejectedPredicate),
        "rejected_revocation" => Some(FinalVerdict::RejectedRevocation),
        "rejected_expired" => Some(FinalVerdict::RejectedExpired),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read as _};

    use serde_json::{Value, json};

    use crate::{AuditEntry, AuditEntryBuilder, event_types};

    use super::{
        DEFAULT_REPLAY_WINDOW_SECS, FinalVerdict, MAX_REPLAY_ARTIFACT_BYTES, ReplayError,
        reconstruct_predicate_trace_from_entries, reconstruct_predicate_trace_from_reader,
        token_hash,
    };

    const NOW: u64 = 1_700_000_100;
    const TOKEN: &str = "cap-token-secret";

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

    fn replay(entries: &[AuditEntry]) -> Result<super::PredicateTrace, ReplayError> {
        reconstruct_predicate_trace_from_entries(
            TOKEN,
            std::time::Duration::from_secs(DEFAULT_REPLAY_WINDOW_SECS),
            false,
            NOW,
            entries,
        )
    }

    fn read_artifact(input: impl io::Read) -> Result<super::PredicateTrace, ReplayError> {
        reconstruct_predicate_trace_from_reader(
            TOKEN,
            std::time::Duration::from_secs(DEFAULT_REPLAY_WINDOW_SECS),
            false,
            NOW,
            input,
        )
    }

    fn accepted_entry(seq: u64) -> AuditEntry {
        entry(
            seq,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("rule_name", json!("zone_match")),
                ("output", json!(true)),
            ],
        )
    }

    #[test]
    fn reader_replays_json_arrays_single_entries_and_bundle_aliases() {
        let entries = vec![accepted_entry(1), accepted_entry(2)];
        let expected = replay(&entries).expect("entry-backed replay");
        let array = serde_json::to_string(&entries).expect("serialize entries");
        assert_eq!(
            read_artifact(array.as_bytes()).expect("array replay"),
            expected
        );

        for key in [
            "audit_entries",
            "audit_events",
            "audit_event_chain",
            "events",
            "entries",
        ] {
            let bundle =
                serde_json::to_string_pretty(&json!({ (key): entries })).expect("serialize bundle");
            assert_eq!(
                read_artifact(bundle.as_bytes()).expect("bundle replay"),
                expected
            );
        }

        let single = serde_json::to_string_pretty(&entries[0]).expect("serialize entry");
        assert_eq!(
            read_artifact(single.as_bytes()).expect("single entry replay"),
            replay(&entries[..1]).expect("single entry-backed replay")
        );
    }

    #[test]
    fn reader_replays_jsonl_with_blank_lines_and_crlf() {
        let entries = vec![accepted_entry(1), accepted_entry(2)];
        let first = serde_json::to_string(&entries[0]).expect("first entry");
        let second = serde_json::to_string(&entries[1]).expect("second entry");
        let input = format!("\r\n{first}\r\n  \r\n{second}\r\n");
        assert_eq!(
            read_artifact(input.as_bytes()).expect("JSONL replay"),
            replay(&entries).expect("entry-backed replay")
        );
    }

    #[test]
    fn shared_parser_accepts_token_jsonl_and_pretty_printed_wrappers() {
        use crate::explain::parse_capability_tokens;

        let tokens = vec![json!({"jti": "first"}), json!({"jti": "second"})];
        let jsonl = format!("{}\n{}\n", tokens[0], tokens[1]);
        assert_eq!(
            parse_capability_tokens(&jsonl).expect("token JSONL"),
            tokens
        );
        let wrapper =
            serde_json::to_string_pretty(&json!({"tokens": tokens})).expect("token wrapper");
        assert_eq!(
            parse_capability_tokens(&wrapper).expect("token wrapper"),
            tokens
        );
        assert!(parse_capability_tokens(&format!("{jsonl}{{")).is_err());
    }

    #[test]
    fn reader_never_replays_a_valid_prefix_of_malformed_jsonl() {
        let valid = serde_json::to_string(&accepted_entry(1)).expect("entry");
        for invalid in ["{", "null", "{\"audit_entries\":[]}"] {
            let input = format!("{valid}\n{invalid}\n");
            assert!(matches!(
                read_artifact(input.as_bytes()),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
        }
    }

    #[test]
    fn reader_distinguishes_empty_evidence_from_unreadable_evidence() {
        assert!(matches!(
            read_artifact(&b"[]"[..]),
            Err(ReplayError::TokenNotFoundInAuditChain { .. })
        ));
        assert!(matches!(
            read_artifact(&b"\xff"[..]),
            Err(ReplayError::AuditChainCorrupted(_))
        ));
    }

    struct FailedRead;

    impl io::Read for FailedRead {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other(TOKEN))
        }
    }

    #[test]
    fn reader_does_not_replay_a_prefix_after_io_failure_or_leak_io_details() {
        let valid = serde_json::to_vec(&vec![accepted_entry(1)]).expect("entries");
        let error = read_artifact(Cursor::new(valid).chain(FailedRead))
            .expect_err("I/O failure cannot yield a partial replay");
        assert!(matches!(error, ReplayError::AuditChainUnavailable(_)));
        assert!(!error.to_string().contains(TOKEN));
    }

    struct MustNotRead;

    impl io::Read for MustNotRead {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            panic!("confirmation must precede I/O")
        }
    }

    #[test]
    fn reader_enforces_confirmation_before_any_io() {
        let result = reconstruct_predicate_trace_from_reader(
            TOKEN,
            std::time::Duration::from_secs(DEFAULT_REPLAY_WINDOW_SECS + 1),
            false,
            NOW,
            MustNotRead,
        );
        assert!(matches!(
            result,
            Err(ReplayError::WideWindowRequiresConfirm { .. })
        ));
    }

    #[test]
    fn reader_accepts_exact_limit_but_confirmation_never_bypasses_size_cap() {
        let exact = Cursor::new(b"[]").chain(io::repeat(b' ').take(MAX_REPLAY_ARTIFACT_BYTES - 2));
        assert!(matches!(
            read_artifact(exact),
            Err(ReplayError::TokenNotFoundInAuditChain { .. })
        ));
        for confirm in [false, true] {
            let result = reconstruct_predicate_trace_from_reader(
                TOKEN,
                std::time::Duration::from_secs(DEFAULT_REPLAY_WINDOW_SECS),
                confirm,
                NOW,
                io::repeat(b' ').take(MAX_REPLAY_ARTIFACT_BYTES + 1),
            );
            assert!(matches!(result, Err(ReplayError::AuditChainCorrupted(_))));
        }
    }

    #[test]
    fn parser_error_does_not_echo_secret_bearing_artifact_fields() {
        let input = format!(r#"{{"audit_entries":"{TOKEN}"}}"#);
        let error = read_artifact(input.as_bytes()).expect_err("invalid bundle");
        assert!(matches!(error, ReplayError::AuditChainCorrupted(_)));
        assert!(!error.to_string().contains(TOKEN));
    }

    #[test]
    fn exact_typed_identity_aliases_select_evidence() {
        for key in [
            "token_hash",
            "capability_token_hash",
            "capability_hash",
            "capability_token_digest",
        ] {
            let evidence = entry(
                1,
                vec![
                    (key, json!(token_hash(TOKEN))),
                    ("rule_name", json!("zone_match")),
                    ("output", json!(true)),
                ],
            );
            assert_eq!(replay(&[evidence]).expect("hash alias").total_steps, 1);
        }
        for key in ["token_id", "capability_token_id", "jti"] {
            let evidence = entry(
                1,
                vec![
                    (key, json!(TOKEN)),
                    ("rule_name", json!("zone_match")),
                    ("output", json!(true)),
                ],
            );
            assert_eq!(replay(&[evidence]).expect("identity alias").total_steps, 1);
        }
    }

    #[test]
    fn free_form_mentions_and_substring_collisions_never_select_evidence() {
        for metadata in [
            vec![("token_id", json!(format!("prefix-{TOKEN}-suffix")))],
            vec![("token_hash", json!(format!("{}-suffix", token_hash(TOKEN))))],
            vec![("message", json!(TOKEN))],
            vec![("inputs_json", json!({"token_hash": token_hash(TOKEN)}))],
            vec![("trace", json!([{ "inputs": [TOKEN, token_hash(TOKEN)] }]))],
        ] {
            let mut evidence = entry(1, metadata);
            evidence
                .metadata
                .insert("rule_name".into(), json!("revocation_check"));
            evidence.metadata.insert("output".into(), json!(false));
            let result = replay(&[evidence]);
            assert!(matches!(
                result,
                Err(ReplayError::TokenNotFoundInAuditChain { .. })
            ));
        }
    }

    #[test]
    fn unrelated_entry_cannot_poison_matching_tokens_verdict() {
        let unrelated = entry(
            2,
            vec![
                ("token_hash", json!(token_hash("other-token"))),
                ("inputs_json", json!({"message": TOKEN})),
                ("rule_name", json!("revocation_check")),
                ("output", json!(false)),
                ("final_verdict", json!("rejected_revocation")),
            ],
        );
        let trace = replay(&[accepted_entry(1), unrelated]).expect("isolated token");
        assert_eq!(trace.final_verdict, FinalVerdict::Accepted);
        assert_eq!(trace.total_steps, 1);
        assert_eq!(trace.audit_chain_range.end_seq, 1);
    }

    #[test]
    fn explicit_digest_cannot_be_overridden_by_raw_id_or_conflicting_alias() {
        for digest in [json!(token_hash("other-token")), json!(null), json!(17)] {
            let evidence = entry(
                1,
                vec![
                    ("token_hash", digest),
                    ("token_id", json!(TOKEN)),
                    ("rule_name", json!("zone_match")),
                    ("output", json!(true)),
                ],
            );
            assert!(matches!(
                replay(&[evidence]),
                Err(ReplayError::TokenNotFoundInAuditChain { .. })
            ));
        }
        let mut evidence = accepted_entry(1);
        evidence.metadata.insert(
            "capability_token_digest".into(),
            json!(token_hash("other-token")),
        );
        assert!(matches!(
            replay(&[evidence]),
            Err(ReplayError::AuditChainCorrupted(_))
        ));
    }

    #[test]
    fn conflicting_identity_aliases_cannot_hide_rejected_evidence() {
        let mut rejected = accepted_entry(2);
        rejected.metadata.insert("output".into(), json!(false));
        rejected
            .metadata
            .insert("capability_hash".into(), json!(null));
        assert!(matches!(
            replay(&[accepted_entry(1), rejected]),
            Err(ReplayError::AuditChainCorrupted(_))
        ));
        let ambiguous_id = entry(
            2,
            vec![
                ("token_id", json!(TOKEN)),
                ("jti", json!("other-token")),
                ("rule_name", json!("revocation_check")),
                ("output", json!(false)),
            ],
        );
        assert!(matches!(
            replay(&[accepted_entry(1), ambiguous_id]),
            Err(ReplayError::AuditChainCorrupted(_))
        ));
    }

    #[test]
    fn empty_token_does_not_match_empty_identity_or_its_hash() {
        for identity in [
            vec![("token_id", json!(""))],
            vec![("token_hash", json!(token_hash("")))],
        ] {
            let result = reconstruct_predicate_trace_from_entries(
                "",
                std::time::Duration::from_secs(60),
                false,
                NOW,
                &[entry(1, identity)],
            );
            assert!(matches!(
                result,
                Err(ReplayError::TokenNotFoundInAuditChain { .. })
            ));
        }
    }

    #[test]
    fn replay_window_includes_boundaries_but_not_future_or_stale_entries() {
        let mut before = accepted_entry(1);
        before.occurred_at = NOW - 61;
        let mut start = accepted_entry(2);
        start.occurred_at = NOW - 60;
        let mut end = accepted_entry(3);
        end.occurred_at = NOW;
        let mut future = accepted_entry(4);
        future.occurred_at = NOW + 1;
        future.metadata.insert("output".into(), json!(false));
        let result = reconstruct_predicate_trace_from_entries(
            TOKEN,
            std::time::Duration::from_secs(60),
            false,
            NOW,
            &[future, end, before, start],
        )
        .expect("bounded time window");
        assert_eq!(result.total_steps, 2);
        assert_eq!(result.final_verdict, FinalVerdict::Accepted);
        assert_eq!(result.audit_chain_range.start_seq, 2);
        assert_eq!(result.audit_chain_range.end_seq, 3);
    }

    #[test]
    fn accepted_verdict_cannot_override_rejected_predicate() {
        let evidence = entry(
            1,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("rule_name", json!("revocation_check")),
                ("output", json!(false)),
                ("final_verdict", json!("accepted")),
            ],
        );
        assert!(matches!(
            replay(&[evidence]),
            Err(ReplayError::AuditChainCorrupted(_))
        ));
    }

    #[test]
    fn invalid_or_conflicting_explicit_verdicts_are_not_ignored() {
        for verdict in [json!("acceptedd"), json!(true), json!(null)] {
            let mut evidence = accepted_entry(1);
            evidence.metadata.insert("final_verdict".into(), verdict);
            assert!(matches!(
                replay(&[evidence]),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
        }
        let mut evidence = accepted_entry(1);
        evidence
            .metadata
            .insert("final_verdict".into(), json!("accepted"));
        evidence
            .metadata
            .insert("verdict".into(), json!("rejected_expired"));
        assert!(matches!(
            replay(&[evidence]),
            Err(ReplayError::AuditChainCorrupted(_))
        ));
    }

    #[test]
    fn conflicting_decisions_require_a_narrower_artifact() {
        let mut first = accepted_entry(1);
        first
            .metadata
            .insert("final_verdict".into(), json!("accepted"));
        let second = entry(
            2,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("final_verdict", json!("rejected_expired")),
            ],
        );
        assert!(matches!(
            replay(&[first, second]),
            Err(ReplayError::AuditChainCorrupted(_))
        ));
    }

    #[test]
    fn explicit_rejection_is_retained_when_predicate_capture_is_partial() {
        let mut evidence = accepted_entry(1);
        evidence
            .metadata
            .insert("final_verdict".into(), json!("rejected_expired"));
        assert_eq!(
            replay(&[evidence])
                .expect("explicit rejection")
                .final_verdict,
            FinalVerdict::RejectedExpired
        );
    }

    #[test]
    fn malformed_trace_cannot_fall_back_to_an_accepting_direct_step() {
        for malformed in [
            json!(null),
            json!({}),
            json!(true),
            json!([]),
            json!([null]),
        ] {
            let mut evidence = accepted_entry(1);
            evidence
                .metadata
                .insert("predicate_trace".into(), malformed);
            assert!(matches!(
                replay(&[evidence]),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
        }
    }

    #[test]
    fn malformed_direct_steps_cannot_disappear_from_an_accepting_trace() {
        for malformed in [
            vec![("rule_name", json!("revocation_check"))],
            vec![("output", json!(false))],
            vec![("rule_name", json!("")), ("output", json!(true))],
            vec![
                ("rule_name", json!("revocation_check")),
                ("output", json!("not-a-bool")),
            ],
        ] {
            let mut evidence = entry(2, malformed);
            evidence
                .metadata
                .insert("token_hash".into(), json!(token_hash(TOKEN)));
            assert!(matches!(
                replay(&[accepted_entry(1), evidence]),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
        }
    }

    #[test]
    fn boolean_aliases_must_all_be_valid_and_consistent() {
        for conflicting in [json!(false), json!(null), json!("garbage")] {
            let mut direct = accepted_entry(1);
            direct.metadata.insert("result".into(), conflicting.clone());
            assert!(matches!(
                replay(&[direct]),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
            let nested = entry(
                1,
                vec![
                    ("token_hash", json!(token_hash(TOKEN))),
                    (
                        "predicate_trace",
                        json!([{"rule_name": "zone_match", "output": true, "allowed": conflicting}]),
                    ),
                ],
            );
            assert!(matches!(
                replay(&[nested]),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
        }
        let mut consistent = accepted_entry(1);
        consistent.metadata.insert("result".into(), json!("TRUE"));
        assert_eq!(
            replay(&[consistent])
                .expect("consistent aliases")
                .final_verdict,
            FinalVerdict::Accepted
        );
    }

    #[test]
    fn witness_arrays_never_silently_drop_invalid_elements_or_use_fallback() {
        for invalid in [
            json!([]),
            json!([1, "secret"]),
            json!([-1]),
            json!(1.5),
            json!(null),
        ] {
            let mut direct = accepted_entry(1);
            direct
                .metadata
                .insert("witness_chain_indices".into(), invalid.clone());
            assert!(matches!(
                replay(&[direct]),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
            let nested = entry(
                1,
                vec![
                    ("token_hash", json!(token_hash(TOKEN))),
                    (
                        "predicate_trace",
                        json!([{"rule_name": "zone_match", "output": true, "witness_seq": invalid}]),
                    ),
                ],
            );
            assert!(matches!(
                replay(&[nested]),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
        }
    }

    #[test]
    fn absent_and_valid_witnesses_keep_their_documented_shapes() {
        for (value, expected) in [(json!(9), vec![9]), (json!([2, 9]), vec![2, 9])] {
            let mut evidence = accepted_entry(1);
            evidence.metadata.insert("witness_seq".into(), value);
            assert_eq!(
                replay(&[evidence]).expect("explicit witnesses").trace[0].witness_chain_indices,
                expected
            );
        }
        assert_eq!(
            replay(&[accepted_entry(1)])
                .expect("fallback witness")
                .trace[0]
                .witness_chain_indices,
            vec![1]
        );
    }

    #[test]
    fn redacts_labels_object_keys_and_authorization_cookie_fields() {
        let evidence = entry(
            1,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("rule_name", json!(format!("revocation_check:{TOKEN}"))),
                ("evaluator_version", json!(format!("v1:{TOKEN}"))),
                (
                    "inputs_json",
                    json!({
                        "headers": {"Authorization": "Bearer private-credential", "Cookie": "sid=session-secret"},
                        "nested": {(TOKEN): "value"},
                        "safe": "visible"
                    }),
                ),
                ("output", json!(false)),
            ],
        );
        let trace = replay(&[evidence]).expect("redacted replay");
        assert_eq!(trace.final_verdict, FinalVerdict::RejectedRevocation);
        let serialized = serde_json::to_string(&trace).expect("trace JSON");
        for secret in [TOKEN, "private-credential", "session-secret"] {
            assert!(!serialized.contains(secret));
        }
        assert!(serialized.contains("visible"));
    }

    #[test]
    fn redaction_does_not_change_inferred_verdict_when_token_overlaps_rule() {
        let evidence = entry(
            1,
            vec![
                ("token_id", json!("revocation")),
                ("rule_name", json!("revocation_check")),
                ("output", json!(false)),
            ],
        );
        let trace = reconstruct_predicate_trace_from_entries(
            "revocation",
            std::time::Duration::from_secs(60),
            false,
            NOW,
            &[evidence],
        )
        .expect("inference precedes redaction");
        assert_eq!(trace.final_verdict, FinalVerdict::RejectedRevocation);
        assert_eq!(trace.trace[0].rule_name, "<redacted>_check");
    }

    #[test]
    fn malformed_predicate_diagnostic_does_not_echo_secret_rule_name() {
        let evidence = entry(
            1,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("predicate_trace", json!([{"rule_name": TOKEN}])),
            ],
        );
        let error = replay(&[evidence]).expect_err("missing output");
        assert!(matches!(error, ReplayError::AuditChainCorrupted(_)));
        assert!(!error.to_string().contains(TOKEN));
    }

    #[test]
    fn reconstructs_accepted_trace() {
        let hash = token_hash(TOKEN);
        let entries = vec![
            entry(
                1,
                vec![
                    ("token_hash", json!(hash)),
                    ("rule_name", json!("zone_match")),
                    (
                        "inputs_json",
                        json!({"src_zone": "z:work", "dst_zone": "z:work"}),
                    ),
                    ("output", json!(true)),
                    ("latency_us", json!(100)),
                    ("evaluator_version", json!("1.2.0")),
                ],
            ),
            entry(
                2,
                vec![
                    ("token_id", json!(TOKEN)),
                    ("rule_name", json!("capability_token_signature_verify")),
                    ("inputs_json", json!({"alg": "ed25519"})),
                    ("output", json!(true)),
                    ("latency_us", json!(145)),
                    ("evaluator_version", json!("1.2.0")),
                ],
            ),
        ];

        let trace = replay(&entries).expect("trace reconstructs");

        assert_eq!(trace.token_hash, token_hash(TOKEN));
        assert_eq!(trace.final_verdict, FinalVerdict::Accepted);
        assert_eq!(trace.total_steps, 2);
        assert_eq!(trace.total_latency_us, 245);
        assert_eq!(trace.audit_chain_range.start_seq, 1);
        assert_eq!(trace.audit_chain_range.end_seq, 2);
    }

    #[test]
    fn refuses_to_merge_zones_or_distinct_request_correlations() {
        let first = accepted_entry(1);
        let mut second = accepted_entry(2);
        second.zone_id = "z:private".to_owned();
        assert!(matches!(
            replay(&[first.clone(), second]),
            Err(ReplayError::AuditChainCorrupted(_))
        ));
        for (left, right) in [
            ("request-a", "request-b"),
            ("", "request-b"),
            ("request-a", ""),
        ] {
            let mut first = first.clone();
            let mut second = accepted_entry(2);
            first.correlation_id = left.to_owned();
            second.correlation_id = right.to_owned();
            assert!(matches!(
                replay(&[first, second]),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
        }
        let mut first = first;
        let mut second = accepted_entry(2);
        first.correlation_id = "request-a".to_owned();
        second.correlation_id = "request-a".to_owned();
        assert_eq!(replay(&[second, first]).unwrap().total_steps, 2);
    }

    #[test]
    fn conflicting_trace_and_witness_aliases_cannot_hide_evidence() {
        let mut captured = accepted_entry(1);
        captured.metadata.insert(
            "predicate_trace".to_owned(),
            json!([{"rule_name": "zone", "output": true}]),
        );
        captured.metadata.insert(
            "trace".to_owned(),
            json!([{"rule_name": "zone", "output": false}]),
        );
        assert!(matches!(
            replay(&[captured]),
            Err(ReplayError::AuditChainCorrupted(_))
        ));

        for nested in [false, true] {
            let captured = if nested {
                entry(
                    1,
                    vec![
                        ("token_hash", json!(token_hash(TOKEN))),
                        (
                            "predicate_trace",
                            json!([{
                                "rule_name": "zone", "output": true,
                                "witness_chain_indices": [1], "witness_seq": [2]
                            }]),
                        ),
                    ],
                )
            } else {
                let mut captured = accepted_entry(1);
                captured
                    .metadata
                    .insert("witness_chain_indices".to_owned(), json!([1]));
                captured
                    .metadata
                    .insert("witness_seq".to_owned(), json!([2]));
                captured
            };
            assert!(matches!(
                replay(&[captured]),
                Err(ReplayError::AuditChainCorrupted(_))
            ));
        }
    }

    #[test]
    fn infers_revocation_and_expiry_rejections() {
        let revoked = vec![entry(
            1,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("rule_name", json!("revocation_check")),
                ("output", json!(false)),
            ],
        )];
        let expired = vec![entry(
            2,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("rule_name", json!("expiry_check")),
                ("output", json!(false)),
            ],
        )];

        assert_eq!(
            replay(&revoked).expect("revoked trace").final_verdict,
            FinalVerdict::RejectedRevocation
        );
        assert_eq!(
            replay(&expired).expect("expired trace").final_verdict,
            FinalVerdict::RejectedExpired
        );
    }

    #[test]
    fn unknown_token_returns_not_found() {
        let entries = vec![entry(
            1,
            vec![
                ("token_hash", json!(token_hash("different-token"))),
                ("rule_name", json!("zone_match")),
                ("output", json!(true)),
            ],
        )];

        let error = replay(&entries).expect_err("unknown token must fail");

        assert!(matches!(
            error,
            ReplayError::TokenNotFoundInAuditChain { .. }
        ));
    }

    #[test]
    fn wide_window_requires_confirmation() {
        let error = reconstruct_predicate_trace_from_entries(
            TOKEN,
            std::time::Duration::from_secs(DEFAULT_REPLAY_WINDOW_SECS + 1),
            false,
            NOW,
            &[],
        )
        .expect_err("wide replay must require confirm");

        assert!(matches!(
            error,
            ReplayError::WideWindowRequiresConfirm { .. }
        ));
    }

    #[test]
    fn redacts_secret_inputs_and_raw_token() {
        let entries = vec![entry(
            1,
            vec![
                ("token_hash", json!(token_hash(TOKEN))),
                ("rule_name", json!("credential_scope")),
                (
                    "inputs_json",
                    json!({
                        "service_account_key": "abcdef",
                        "request": format!("Bearer {TOKEN}"),
                        "safe": "visible"
                    }),
                ),
                ("output", json!(true)),
            ],
        )];

        let trace = replay(&entries).expect("trace reconstructs");
        let serialized = serde_json::to_string(&trace).expect("trace serializes");

        assert!(!serialized.contains(TOKEN));
        assert!(!serialized.contains("abcdef"));
        assert!(serialized.contains("visible"));
        assert!(serialized.contains("<redacted>"));
    }
}
