//! Reusable implementation for `fwc capability replay`.
//!
//! Set `FWC_AUDIT_TRUST_POLICY` to an independently provisioned JSON policy to
//! require a complete signed chain through its pinned head. Policy or evidence
//! failures never fall back to unverified replay. Without a policy, output is
//! explicitly labeled unverified. Neither mode claims to observe live state.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fcp_audit::explain::parse_replay_bundle;
pub use fcp_audit::replay::AUDIT_CHAIN_ENV;
use fcp_audit::replay::{
    DEFAULT_REPLAY_WINDOW_SECS, MAX_REPLAY_ARTIFACT_BYTES, PredicateTrace, ReplayError,
    reconstruct_predicate_trace_from_entries, reconstruct_predicate_trace_from_path,
    validate_replay_window,
};
use fcp_audit::{AuditEntry, ChainHead, verify_chain_with_required_signed_head};
use fcp_crypto::{Ed25519VerifyingKey, KeyId, ed25519::PUBLIC_KEY_SIZE};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Path to the operator-provisioned replay trust policy, separate from evidence.
pub const AUDIT_TRUST_POLICY_ENV: &str = "FWC_AUDIT_TRUST_POLICY";
const MAX_TRUST_POLICY_BYTES: u64 = 256 * 1024;
const MAX_TRUSTED_REPLAY_KEYS: usize = 64;

/// Independent trust anchors for one zone's captured audit chain.
///
/// The expected head pins the exact terminal entry, not merely a lower bound:
/// dropping a signed suffix cannot make an older prefix appear complete. Keys
/// must come from the operator's trust store, never from the captured bundle.
/// Signatures authenticate captured statements, not the truth of an external
/// service's response or the completeness of later, unobserved history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayTrustPolicy {
    /// Exact zone whose complete chain is expected.
    pub zone_id: String,
    /// Independently pinned, signed terminal head.
    pub expected_head: ChainHead,
    /// Trusted Ed25519 public keys as 64 hexadecimal characters each.
    /// Key IDs are derived locally; aliases cannot inflate the trusted set.
    pub public_keys_hex: Vec<String>,
    /// Minimum number of distinct trusted signatures required on the head.
    pub minimum_head_signers: usize,
}

impl ReplayTrustPolicy {
    fn trusted_keys(&self) -> Result<HashMap<KeyId, Ed25519VerifyingKey>, CapabilityReplayError> {
        if self.zone_id.is_empty()
            || self.expected_head.zone_id != self.zone_id
            || self.expected_head.head_entry.is_empty()
            || self.expected_head.epoch_id.is_empty()
            || !self.expected_head.coverage.is_finite()
            || !(0.0..=1.0).contains(&self.expected_head.coverage)
            || self.public_keys_hex.is_empty()
            || self.public_keys_hex.len() > MAX_TRUSTED_REPLAY_KEYS
            || self.minimum_head_signers == 0
            || self.minimum_head_signers > self.public_keys_hex.len()
            || self.expected_head.signatures.len() > MAX_TRUSTED_REPLAY_KEYS
        {
            return Err(CapabilityReplayError::InvalidTrustPolicy(
                "invalid zone, head, trusted key count, or signer threshold",
            ));
        }
        let mut keys = HashMap::with_capacity(self.public_keys_hex.len());
        for encoded in &self.public_keys_hex {
            let invalid_key = || CapabilityReplayError::InvalidTrustPolicy("invalid public key");
            if encoded.len() != PUBLIC_KEY_SIZE * 2 {
                return Err(invalid_key());
            }
            let bytes: [u8; PUBLIC_KEY_SIZE] = hex::decode(encoded)
                .map_err(|_| invalid_key())?
                .try_into()
                .map_err(|_| invalid_key())?;
            let key = Ed25519VerifyingKey::from_bytes(&bytes).map_err(|_| invalid_key())?;
            if keys.insert(key.key_id(), key).is_some() {
                return Err(CapabilityReplayError::InvalidTrustPolicy(
                    "duplicate trusted public key",
                ));
            }
        }
        Ok(keys)
    }
}

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
    /// The independently configured trust policy is missing or invalid.
    InvalidTrustPolicy(&'static str),
    /// Evidence could not be authenticated through the pinned head.
    UnverifiedChain(&'static str),
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
            Self::InvalidTrustPolicy(_) => "invalid-audit-trust-policy",
            Self::UnverifiedChain(_) => "audit-chain-unverified",
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
            Self::InvalidTrustPolicy(_) | Self::UnverifiedChain(_) => true,
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
            Self::InvalidTrustPolicy(message) => {
                write!(formatter, "invalid audit trust policy: {message}")
            }
            Self::UnverifiedChain(message) => write!(formatter, "audit chain unverified: {message}"),
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
    let policy_path = std::env::var_os(AUDIT_TRUST_POLICY_ENV).map(PathBuf::from);
    build_replay_payload_from_paths(
        token,
        since_seconds,
        confirm,
        &path,
        output,
        now_unix,
        policy_path.as_deref(),
    )
}

/// Replay explicit evidence and optional independent trust-policy paths.
///
/// This entrypoint does not consult environment variables. A configured policy
/// is mandatory: missing, empty, invalid, or failed verification never retries
/// the evidence as unverified. Only the evidence path may be `-` for stdin.
///
/// # Errors
///
/// Returns confirmation, policy, I/O, verification, or reconstruction errors.
pub fn build_replay_payload_from_paths(
    token: &str,
    since_seconds: u64,
    confirm: bool,
    path: &Path,
    output: ReplayOutput,
    now_unix: u64,
    policy_path: Option<&Path>,
) -> Result<Value, CapabilityReplayError> {
    validate_replay_window(since_seconds, confirm)?;
    if let Some(policy_path) = policy_path {
        if policy_path.as_os_str().is_empty() || policy_path.as_os_str() == "-" {
            return Err(CapabilityReplayError::InvalidTrustPolicy(
                "policy must be an independent file, not empty or stdin",
            ));
        }
        let policy_file = std::fs::File::open(policy_path)
            .map_err(|_| CapabilityReplayError::InvalidTrustPolicy("cannot open policy file"))?;
        let policy = read_replay_trust_policy(policy_file)?;
        if path.as_os_str() == "-" {
            return build_authenticated_replay_payload_from_reader(
                token,
                since_seconds,
                confirm,
                std::io::stdin().lock(),
                output,
                now_unix,
                &policy,
            );
        }
        let file = std::fs::File::open(path).map_err(|_| {
            ReplayError::AuditChainUnavailable("cannot open audit-chain artifact".to_string())
        })?;
        return build_authenticated_replay_payload_from_reader(
            token, since_seconds, confirm, file, output, now_unix, &policy,
        );
    }
    let trace = reconstruct_predicate_trace_from_path(
        token,
        Duration::from_secs(since_seconds),
        confirm,
        now_unix,
        path,
    )?;
    payload_from_trace(&trace, output, None)
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
    payload_from_trace(&trace, output, None)
}

/// Decode a bounded, independently provisioned trust-policy document.
///
/// # Errors
///
/// Rejects unreadable, oversized, malformed, ambiguous, or invalid policies.
/// Diagnostic text never echoes the document or public-key input.
pub fn read_replay_trust_policy(
    reader: impl Read,
) -> Result<ReplayTrustPolicy, CapabilityReplayError> {
    let input = read_bounded_artifact(reader, MAX_TRUST_POLICY_BYTES).map_err(|_| {
        CapabilityReplayError::InvalidTrustPolicy("cannot read bounded policy document")
    })?;
    let policy: ReplayTrustPolicy = serde_json::from_str(&input)
        .map_err(|_| CapabilityReplayError::InvalidTrustPolicy("invalid policy JSON"))?;
    policy.trusted_keys()?;
    Ok(policy)
}

/// Authenticate a bounded artifact before constructing its predicate trace.
///
/// The confirmation and trust-policy gates run before reading the artifact.
/// The whole captured chain is verified, including entries outside the replay
/// window; filtering first could hide a forged, missing, or reordered suffix.
/// The reader's I/O deadline remains the caller's responsibility.
///
/// # Errors
///
/// Returns policy, I/O, parsing, authentication, integrity, or replay errors.
pub fn build_authenticated_replay_payload_from_reader(
    token: &str,
    since_seconds: u64,
    confirm: bool,
    reader: impl Read,
    output: ReplayOutput,
    now_unix: u64,
    policy: &ReplayTrustPolicy,
) -> Result<Value, CapabilityReplayError> {
    validate_replay_window(since_seconds, confirm)?;
    policy.trusted_keys()?;
    let input = read_bounded_artifact(reader, MAX_REPLAY_ARTIFACT_BYTES)?;
    let bundle = parse_replay_bundle(&input).map_err(|_| {
        ReplayError::AuditChainCorrupted("invalid JSON/JSONL audit-chain artifact".to_string())
    })?;
    build_authenticated_replay_payload_from_entries(
        token,
        since_seconds,
        confirm,
        &bundle.audit_entries,
        output,
        now_unix,
        policy,
    )
}

/// Authenticate a complete captured chain through an independently pinned head.
///
/// All entry signatures, the head's distinct signers, canonical object IDs,
/// genesis, sequence continuity, hash links, zone, and exact tip must verify.
/// Even warning-level integrity issues refuse authenticated output. This does
/// not verify a live host, grant current authority, or authenticate unrelated
/// token/receipt objects bundled alongside the audit entries.
///
/// # Errors
///
/// Returns an error on any trust, chain, witness, or reconstruction failure.
pub fn build_authenticated_replay_payload_from_entries(
    token: &str,
    since_seconds: u64,
    confirm: bool,
    entries: &[AuditEntry],
    output: ReplayOutput,
    now_unix: u64,
    policy: &ReplayTrustPolicy,
) -> Result<Value, CapabilityReplayError> {
    validate_replay_window(since_seconds, confirm)?;
    let keys = policy.trusted_keys()?;
    if policy.expected_head.signatures.len() < policy.minimum_head_signers {
        return Err(CapabilityReplayError::UnverifiedChain(
            "head signer threshold not met",
        ));
    }
    let report = verify_chain_with_required_signed_head(
        entries,
        Some(&policy.expected_head),
        Some(&policy.zone_id),
        |kid| keys.get(kid).cloned(),
    )
    .map_err(|_| CapabilityReplayError::UnverifiedChain("entry or head authentication failed"))?;
    if !report.is_clean() || !report.status.is_ok() {
        return Err(CapabilityReplayError::UnverifiedChain(
            "audit chain integrity check failed",
        ));
    }
    if entries.iter().any(|entry| entry.occurred_at > now_unix) {
        return Err(CapabilityReplayError::UnverifiedChain(
            "audit chain contains future evidence",
        ));
    }
    let trace = reconstruct_predicate_trace_from_entries(
        token,
        Duration::from_secs(since_seconds),
        confirm,
        now_unix,
        entries,
    )?;
    // Verified chains start at zero and contain every sequence exactly once.
    // A signed trace must not cite a nonexistent witness outside that chain.
    for sequence in trace.trace.iter().flat_map(|step| &step.witness_chain_indices) {
        if usize::try_from(*sequence)
            .ok()
            .and_then(|index| entries.get(index))
            .is_none_or(|entry| entry.seq != *sequence)
        {
            return Err(CapabilityReplayError::UnverifiedChain(
                "predicate witness is absent from the verified chain",
            ));
        }
    }
    payload_from_trace(&trace, output, Some(policy))
}

fn read_bounded_artifact(reader: impl Read, limit: u64) -> Result<String, CapabilityReplayError> {
    let mut reader = reader.take(limit + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|_| {
        ReplayError::AuditChainUnavailable("cannot read audit artifact".to_string())
    })?;
    if reader.limit() == 0 {
        return Err(ReplayError::AuditChainCorrupted(
            "audit artifact exceeds size limit".to_string(),
        )
        .into());
    }
    String::from_utf8(bytes).map_err(|_| {
        ReplayError::AuditChainCorrupted("audit artifact is not UTF-8".to_string()).into()
    })
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
    verified: Option<&ReplayTrustPolicy>,
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
            "live": false,
            "default_window_seconds": DEFAULT_REPLAY_WINDOW_SECS,
            "chain_integrity_verified": verified.is_some(),
            "entry_signatures_verified": verified.is_some(),
            "head_signatures_verified": verified.is_some(),
            "trusted_head": verified.map(|policy| json!({
                "entry": policy.expected_head.head_entry,
                "sequence": policy.expected_head.head_seq,
                "minimum_signers": policy.minimum_head_signers,
            })),
        }),
    );

    match output {
        ReplayOutput::Json => {}
        ReplayOutput::Jsonl => {
            object.insert("jsonl".to_owned(), json!(render_jsonl(trace)?));
        }
        ReplayOutput::Human => {
            let evidence = if verified.is_some() {
                "signed chain verified through pinned head; not live state"
            } else {
                "unverified captured artifact"
            };
            object.insert(
                "human".to_owned(),
                json!(format!("evidence: {evidence}\n{}", render_human(trace))),
            );
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
    use std::io::{self, Read};
    use std::path::Path;

    use serde_json::{Value, json};

    use fcp_audit::{AuditEntry, AuditEntryBuilder, ChainHead, HeadSignature, event_types};
    use fcp_crypto::Ed25519SigningKey;

    use crate::capability_replay::{
        CapabilityReplayError, ReplayOutput, ReplayTrustPolicy,
        build_authenticated_replay_payload_from_entries,
        build_authenticated_replay_payload_from_reader, build_replay_payload,
        build_replay_payload_from_entries, build_replay_payload_from_paths,
        parse_since_seconds, read_bounded_artifact, read_replay_trust_policy,
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

    fn sign_entries(entries: &mut [AuditEntry], key: &Ed25519SigningKey) {
        let mut previous = None;
        for entry in entries {
            entry.prev = previous;
            entry.id = entry.computed_id().expect("canonical fixture ID");
            entry.sign(key).expect("sign fixture entry");
            previous = Some(entry.id.clone());
        }
    }

    fn pin_head(entries: &[AuditEntry], signers: &[&Ed25519SigningKey]) -> ReplayTrustPolicy {
        let tip = entries.last().expect("nonempty fixture");
        let mut head = ChainHead {
            zone_id: "z:work".to_string(),
            head_entry: tip.id.clone(),
            head_seq: tip.seq,
            coverage: 1.0,
            epoch_id: "test-epoch".to_string(),
            signature_count: u32::try_from(signers.len()).unwrap(),
            signatures: Vec::new(),
        };
        let transcript = head.signing_bytes();
        head.signatures = signers
            .iter()
            .map(|key| HeadSignature {
                issuer_kid: key.key_id().to_hex(),
                signature: key.sign(&transcript).to_bytes().to_vec(),
            })
            .collect();
        ReplayTrustPolicy {
            zone_id: "z:work".to_string(),
            expected_head: head,
            public_keys_hex: signers
                .iter()
                .map(|key| hex::encode(key.verifying_key().to_bytes()))
                .collect(),
            minimum_head_signers: signers.len(),
        }
    }

    fn signed_fixture() -> (Vec<AuditEntry>, ReplayTrustPolicy, Ed25519SigningKey) {
        let key = Ed25519SigningKey::from_bytes(&[7_u8; 32]).unwrap();
        let mut entries: Vec<_> = (0..2)
            .map(|seq| {
                entry(seq, vec![
                    ("token_hash", json!(fcp_audit::replay::token_hash(TOKEN))),
                    ("rule_name", json!(format!("predicate-{seq}"))),
                    ("output", json!(true)),
                    ("inputs_json", json!({"request": format!("Bearer {TOKEN}")})),
                ])
            })
            .collect();
        sign_entries(&mut entries, &key);
        let policy = pin_head(&entries, &[&key]);
        (entries, policy, key)
    }

    fn authenticated(
        entries: &[AuditEntry],
        policy: &ReplayTrustPolicy,
    ) -> Result<Value, CapabilityReplayError> {
        build_authenticated_replay_payload_from_entries(
            TOKEN, 60, false, entries, ReplayOutput::Json, NOW, policy,
        )
    }

    fn assert_unverified(result: Result<Value, CapabilityReplayError>) {
        let error = result.expect_err("must not downgrade failed authentication");
        assert_eq!(error.error_type(), "audit-chain-unverified");
        assert!(!error.to_string().contains(TOKEN));
    }

    #[test]
    fn authenticated_chain_labels_all_output_modes_without_claiming_live_state() {
        let (entries, policy, _) = signed_fixture();
        for mode in [ReplayOutput::Json, ReplayOutput::Jsonl, ReplayOutput::Human] {
            let payload = build_authenticated_replay_payload_from_entries(
                TOKEN, 60, false, &entries, mode, NOW, &policy,
            ).unwrap();
            assert_eq!(payload["status"], "ok");
            assert_eq!(payload["total_steps"], 2);
            assert_eq!(payload["source"]["live"], false);
            assert_eq!(payload["source"]["chain_integrity_verified"], true);
            assert_eq!(payload["source"]["entry_signatures_verified"], true);
            assert_eq!(payload["source"]["head_signatures_verified"], true);
            assert_eq!(payload["source"]["trusted_head"]["entry"], policy.expected_head.head_entry);
            assert!(!payload.to_string().contains(TOKEN));
            if mode == ReplayOutput::Human {
                assert!(payload["human"].as_str().unwrap().contains("not live state"));
            }
        }
    }

    #[test]
    fn raw_replay_never_labels_signed_looking_input_as_verified() {
        let (entries, _, _) = signed_fixture();
        let payload = build_replay_payload_from_entries(
            TOKEN, 60, false, &entries, ReplayOutput::Human, NOW,
        ).unwrap();
        assert_eq!(payload["source"]["chain_integrity_verified"], false);
        assert_eq!(payload["source"]["entry_signatures_verified"], false);
        assert_eq!(payload["source"]["head_signatures_verified"], false);
        assert!(payload["source"]["trusted_head"].is_null());
        assert!(payload["human"].as_str().unwrap().contains("unverified captured artifact"));
    }

    #[test]
    fn unsigned_unknown_and_tampered_entries_never_fall_back_to_raw_replay() {
        let (entries, policy, _) = signed_fixture();
        for missing_kid in [false, true] {
            let mut unsigned = entries.clone();
            if missing_kid {
                unsigned[0].issuer_kid = None;
            } else {
                unsigned[0].signature = None;
            }
            assert_unverified(authenticated(&unsigned, &policy));
        }
        let other = Ed25519SigningKey::from_bytes(&[9_u8; 32]).unwrap();
        let mut unknown = policy.clone();
        unknown.public_keys_hex = vec![hex::encode(other.verifying_key().to_bytes())];
        assert_unverified(authenticated(&entries, &unknown));
        let mut tampered = entries;
        tampered[1].metadata.insert("output".to_string(), json!(false));
        assert_unverified(authenticated(&tampered, &policy));
    }

    #[test]
    fn authentication_precedes_window_filtering() {
        let (mut entries, policy, _) = signed_fixture();
        let now = entries[1].occurred_at;
        let payload = build_authenticated_replay_payload_from_entries(
            TOKEN, 0, false, &entries, ReplayOutput::Json, now, &policy,
        ).unwrap();
        assert_eq!(payload["total_steps"], 1);
        entries[0].actor = format!("forged-{TOKEN}");
        assert_unverified(build_authenticated_replay_payload_from_entries(
            TOKEN, 0, false, &entries, ReplayOutput::Json, now, &policy,
        ));
    }

    #[test]
    fn pinned_head_rejects_prefix_suffix_reordering_and_empty_chain() {
        let (entries, policy, _) = signed_fixture();
        assert_unverified(authenticated(&entries[..1], &policy));
        assert_unverified(authenticated(&entries[1..], &policy));
        assert_unverified(authenticated(&[], &policy));
        let mut reordered = entries;
        reordered.reverse();
        assert_unverified(authenticated(&reordered, &policy));
    }

    #[test]
    fn invalid_head_signatures_and_counts_are_rejected() {
        let (entries, policy, _) = signed_fixture();
        let mut forged = policy.clone();
        forged.expected_head.signatures[0].signature[0] ^= 1;
        assert_unverified(authenticated(&entries, &forged));
        let mut unsigned = policy.clone();
        unsigned.expected_head.signatures.clear();
        assert_unverified(authenticated(&entries, &unsigned));
        let mut inconsistent = policy;
        inconsistent.expected_head.signature_count = 2;
        assert_unverified(authenticated(&entries, &inconsistent));
    }

    #[test]
    fn head_threshold_requires_distinct_trusted_signers() {
        let (entries, _, first) = signed_fixture();
        let second = Ed25519SigningKey::from_bytes(&[9_u8; 32]).unwrap();
        let policy = pin_head(&entries, &[&first, &second]);
        assert!(authenticated(&entries, &policy).is_ok());

        let mut below_threshold = pin_head(&entries, &[&first]);
        below_threshold.public_keys_hex = policy.public_keys_hex.clone();
        below_threshold.minimum_head_signers = 2;
        assert_unverified(authenticated(&entries, &below_threshold));

        let mut duplicate_signer = pin_head(&entries, &[&first, &first]);
        duplicate_signer.public_keys_hex = policy.public_keys_hex;
        assert_unverified(authenticated(&entries, &duplicate_signer));
    }

    #[test]
    fn warning_level_zone_mismatch_is_not_authenticated_success() {
        let (mut entries, _, key) = signed_fixture();
        entries[1].zone_id = "z:private".to_string();
        sign_entries(&mut entries, &key);
        let policy = pin_head(&entries, &[&key]);
        let keys = policy.trusted_keys().unwrap();
        let report = fcp_audit::verify_chain_with_required_signed_head(
            &entries, Some(&policy.expected_head), Some(&policy.zone_id),
            |kid| keys.get(kid).cloned(),
        ).unwrap();
        assert_eq!(report.status, fcp_audit::VerifyStatus::Warn);
        assert_unverified(authenticated(&entries, &policy));
    }

    #[test]
    fn signed_future_and_regressing_timestamps_are_rejected() {
        let (entries, _, key) = signed_fixture();
        for timestamp in [NOW + 1, entries[0].occurred_at - 1] {
            let mut changed = entries.clone();
            changed[1].occurred_at = timestamp;
            sign_entries(&mut changed, &key);
            let policy = pin_head(&changed, &[&key]);
            assert_unverified(authenticated(&changed, &policy));
        }
    }

    #[test]
    fn signed_predicate_cannot_cite_a_nonexistent_chain_witness() {
        let (mut entries, _, key) = signed_fixture();
        entries[1].metadata.insert("witness_seq".to_string(), json!(999));
        sign_entries(&mut entries, &key);
        let policy = pin_head(&entries, &[&key]);
        assert_unverified(authenticated(&entries, &policy));
    }

    #[test]
    fn invalid_trust_parameters_and_duplicate_keys_fail_closed() {
        let (_, policy, _) = signed_fixture();
        for case in 0..9 {
            let mut invalid = policy.clone();
            match case {
                0 => invalid.minimum_head_signers = 0,
                1 => invalid.minimum_head_signers = 2,
                2 => invalid.zone_id = "z:private".to_string(),
                3 => invalid.expected_head.coverage = f64::NAN,
                4 => invalid.expected_head.coverage = 1.5,
                5 => invalid.public_keys_hex.clear(),
                6 => invalid.public_keys_hex[0] = "0".repeat(64),
                7 => invalid.public_keys_hex[0] = TOKEN.to_string(),
                _ => invalid.public_keys_hex.push(invalid.public_keys_hex[0].to_uppercase()),
            }
            let error = invalid.trusted_keys().unwrap_err();
            assert_eq!(error.error_type(), "invalid-audit-trust-policy", "case {case}");
            assert!(!error.to_string().contains(TOKEN));
        }
    }

    #[test]
    fn policy_reader_accepts_valid_policy_and_rejects_unknown_or_duplicate_fields() {
        let (_, policy, _) = signed_fixture();
        let text = serde_json::to_string(&policy).unwrap();
        let parsed = read_replay_trust_policy(text.as_bytes()).unwrap();
        assert_eq!(parsed.expected_head, policy.expected_head);
        assert_eq!(parsed.public_keys_hex, policy.public_keys_hex);
        for text in [
            format!("{{\"minimum_head_signers\":0,{}", &text[1..]),
            format!("{{\"unexpected\":\"{TOKEN}\",{}", &text[1..]),
            format!("{{\"public_keys_hex\":\"{TOKEN}\"}}"),
        ] {
            let error = read_replay_trust_policy(text.as_bytes()).unwrap_err();
            assert_eq!(error.error_type(), "invalid-audit-trust-policy");
            assert!(!error.to_string().contains(TOKEN));
        }
    }

    struct MustNotRead;

    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("admission gates must run before reading evidence")
        }
    }

    #[test]
    fn window_and_policy_gates_precede_evidence_io() {
        let (_, mut policy, _) = signed_fixture();
        let error = build_authenticated_replay_payload_from_reader(
            TOKEN, 604_801, false, MustNotRead, ReplayOutput::Json, NOW, &policy,
        ).unwrap_err();
        assert_eq!(error.error_type(), "wide-window-requires-confirm");
        policy.minimum_head_signers = 0;
        let error = build_authenticated_replay_payload_from_reader(
            TOKEN, 60, false, MustNotRead, ReplayOutput::Json, NOW, &policy,
        ).unwrap_err();
        assert_eq!(error.error_type(), "invalid-audit-trust-policy");
    }

    #[test]
    fn explicitly_invalid_policy_paths_do_not_downgrade_or_read_stdin() {
        for policy_path in ["", "-"] {
            let error = build_replay_payload_from_paths(
                TOKEN, 60, false, Path::new("-"), ReplayOutput::Json, NOW,
                Some(Path::new(policy_path)),
            ).unwrap_err();
            assert_eq!(error.error_type(), "invalid-audit-trust-policy");
        }
        let error = build_replay_payload_from_paths(
            TOKEN, 604_801, false, Path::new("-"), ReplayOutput::Json, NOW,
            Some(Path::new("")),
        ).unwrap_err();
        assert_eq!(error.error_type(), "wide-window-requires-confirm");
    }

    #[test]
    fn signed_jsonl_array_and_bundle_readers_share_the_authenticated_path() {
        let (entries, policy, _) = signed_fixture();
        let jsonl = entries.iter().map(|entry| serde_json::to_string(entry).unwrap())
            .collect::<Vec<_>>().join("\n");
        for text in [
            jsonl,
            serde_json::to_string_pretty(&entries).unwrap(),
            json!({"audit_entries": entries}).to_string(),
        ] {
            let payload = build_authenticated_replay_payload_from_reader(
                TOKEN, 60, false, text.as_bytes(), ReplayOutput::Json, NOW, &policy,
            ).unwrap();
            assert_eq!(payload["total_steps"], 2);
            assert_eq!(payload["source"]["entry_signatures_verified"], true);
        }
    }

    struct FailedRead;

    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other(TOKEN))
        }
    }

    #[test]
    fn bounded_reader_rejects_overflow_encoding_and_io_errors_after_prefix() {
        assert_eq!(read_bounded_artifact("1234".as_bytes(), 4).unwrap(), "1234");
        let error = read_bounded_artifact("12345".as_bytes(), 4).unwrap_err();
        assert_eq!(error.error_type(), "audit-chain-corrupted");
        let error = read_bounded_artifact(&[0xff_u8][..], 4).unwrap_err();
        assert_eq!(error.error_type(), "audit-chain-corrupted");
        let error = read_bounded_artifact("{}".as_bytes().chain(FailedRead), 4).unwrap_err();
        assert_eq!(error.error_type(), "audit-chain-unavailable");
        assert!(!error.to_string().contains(TOKEN));
        let (_, policy, _) = signed_fixture();
        let text = serde_json::to_string(&policy).unwrap();
        let error = read_replay_trust_policy(text.as_bytes().chain(FailedRead)).unwrap_err();
        assert_eq!(error.error_type(), "invalid-audit-trust-policy");
        assert!(!error.to_string().contains(TOKEN));
    }

    #[test]
    fn malformed_or_unreadable_suffix_is_not_replayed_as_a_valid_prefix() {
        let (entries, policy, _) = signed_fixture();
        let valid = serde_json::to_string(&entries).unwrap();
        let malformed = format!("{valid}\n{{\"{TOKEN}\":");
        let error = build_authenticated_replay_payload_from_reader(
            TOKEN, 60, false, malformed.as_bytes(), ReplayOutput::Json, NOW, &policy,
        ).unwrap_err();
        assert_eq!(error.error_type(), "audit-chain-corrupted");
        assert!(!error.to_string().contains(TOKEN));
        let error = build_authenticated_replay_payload_from_reader(
            TOKEN, 60, false, valid.as_bytes().chain(FailedRead), ReplayOutput::Json, NOW, &policy,
        ).unwrap_err();
        assert_eq!(error.error_type(), "audit-chain-unavailable");
    }
}
