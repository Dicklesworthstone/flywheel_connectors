//! FCP2 audit chain and receipt primitives.
//!
//! This crate provides protocol-level types for audit chains, decision receipts,
//! event filtering, and chain verification. These are the building blocks used
//! by higher-level crates (`fcp-core`, `fcp-cli`) to implement audit functionality.
//!
//! # Authenticity vs integrity
//!
//! `AuditEntry::computed_id` (a domain-separated BLAKE3 hash of the canonical
//! payload) and `verify_chain` together guarantee **integrity against edits**:
//! once a chain is published, no entry can be silently mutated without breaking
//! the hash linkage. They do NOT, on their own, guarantee **authenticity
//! against forgery**: anyone who can append to the store can produce an entry
//! claiming any `actor`, and `verify_chain` will accept the chain as well-formed.
//!
//! For authenticity, populate the optional `issuer_kid` and `signature` fields
//! on [`AuditEntry`] (see [`AuditEntry::sign`]) and verify with
//! [`verify_chain_with_signers`]. The unsigned [`verify_chain`] remains
//! available for callers that intentionally separate authenticity from chain
//! integrity (e.g., when signatures live in a wrapping envelope).

#![forbid(unsafe_code)]

use fcp_crypto::{
    Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, KeyId,
    ed25519::SIGNATURE_SIZE as ED25519_SIGNATURE_SIZE,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use thiserror::Error;

pub mod cep;
pub mod compaction;
pub mod conformal;
pub mod explain;
pub mod hlc;
pub mod otlp_export;
pub mod replay;

pub use cep::{
    AnomalyAlertError, CEP_ANOMALY_ALERT_SCHEMA_VERSION, EventPattern, EventPatternError,
    EventPredicate, PatternMatch,
};
pub use compaction::{
    ReservoirCompaction, ReservoirCompactionError, ReservoirCompactionReport, ReservoirCompactor,
    compact_entries,
};
pub use conformal::{ConformalScore, ConformalScoreEstimator};
pub use hlc::{HybridLogicalClock, HybridLogicalTimestamp};

const AUDIT_ENTRY_ID_DOMAIN: &[u8] = b"FCP2-AUDIT-ENTRY-V1";
const CAPABILITY_CONSTRAINT_DESCRIPTOR_HASH_DOMAIN: &[u8] =
    b"FCP2-CAPABILITY-CONSTRAINT-DESCRIPTOR-V1";
const DECISION_RECEIPT_ID_DOMAIN: &[u8] = b"FCP2-DECISION-RECEIPT-V1";
const DECISION_RECEIPT_SIG_DOMAIN: &[u8] = b"FCP2-DECISION-RECEIPT-SIG-V1";

/// Default grace window (seconds) for entries whose `occurred_at` is ahead of
/// the verifier's wall clock.
///
/// Entries timestamped more than this far in the future are treated as clock
/// skew beyond tolerance or deliberate poisoning of freshness/SLA signals, and
/// are flagged as critical by [`verify_chain_with_clock`]. 300 seconds (5
/// minutes) matches the skew tolerance used by Kerberos and most IAM systems.
pub const MAX_FUTURE_TIMESTAMP_SKEW_SECS: u64 = 300;
const AUDIT_ENTRY_SIG_DOMAIN: &[u8] = b"FCP2-AUDIT-ENTRY-SIG-V1";
const CHAIN_HEAD_SIG_DOMAIN: &[u8] = b"FCP2-AUDIT-CHAIN-HEAD-SIG-V1";

/// Convert an audit entry's wall-clock timestamp into the default HLC stamp.
///
/// Callers that already maintain a causal HLC should set the explicit `hlc`
/// field instead. This helper exists for builder paths and fixtures that only
/// have the legacy Unix-seconds timestamp available.
#[must_use]
pub fn audit_entry_hlc_from_occurred_at(
    occurred_at: u64,
    node_id: impl Into<String>,
) -> HybridLogicalTimestamp {
    HybridLogicalTimestamp::from_physical(occurred_at.saturating_mul(1_000), node_id)
}

fn default_audit_entry_hlc() -> HybridLogicalTimestamp {
    audit_entry_hlc_from_occurred_at(0, "legacy-audit-entry")
}

// ============================================================================
// Event type constants
// ============================================================================

/// Required audit event types (NORMATIVE).
pub mod event_types {
    /// Secret was accessed by an actor.
    pub const SECRET_ACCESS: &str = "secret.access";
    /// Capability was invoked.
    pub const CAPABILITY_INVOKE: &str = "capability.invoke";
    /// Capability constraints denied a request before connector dispatch.
    pub const CAPABILITY_CONSTRAINT_DENIED: &str = "capability.constraint_denied";
    /// Privilege elevation was granted.
    pub const ELEVATION_GRANTED: &str = "elevation.granted";
    /// Declassification was granted.
    pub const DECLASSIFICATION_GRANTED: &str = "declassification.granted";
    /// Object transitioned between zones.
    pub const ZONE_TRANSITION: &str = "zone.transition";
    /// Revocation was issued.
    pub const REVOCATION_ISSUED: &str = "revocation.issued";
    /// Security violation detected.
    pub const SECURITY_VIOLATION: &str = "security.violation";
    /// Audit chain fork detected (critical).
    pub const AUDIT_FORK_DETECTED: &str = "audit.fork_detected";
    /// CEP pattern matched an anomaly over audit-chain entries.
    pub const CEP_ANOMALY_ALERT: &str = "audit.cep_anomaly_alert";
}

// ============================================================================
// Severity
// ============================================================================

/// Severity level for audit events.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational event, no action required.
    #[default]
    Info,
    /// Warning event, may require attention.
    Warning,
    /// Error event, requires investigation.
    Error,
    /// Critical event, requires immediate action.
    Critical,
}

impl Severity {
    /// Returns the severity for a given event type string.
    #[must_use]
    pub fn for_event_type(event_type: &str) -> Self {
        match event_type {
            event_types::SECRET_ACCESS
            | event_types::CAPABILITY_CONSTRAINT_DENIED
            | event_types::ELEVATION_GRANTED
            | event_types::DECLASSIFICATION_GRANTED => Self::Warning,
            event_types::REVOCATION_ISSUED
            | event_types::SECURITY_VIOLATION
            | event_types::CEP_ANOMALY_ALERT => Self::Error,
            event_types::AUDIT_FORK_DETECTED => Self::Critical,
            _ => Self::Info,
        }
    }

    /// Returns true if this severity is at least as severe as `other`.
    #[must_use]
    pub const fn is_at_least(&self, other: Self) -> bool {
        *self as u8 >= other as u8
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ============================================================================
// TraceContext
// ============================================================================

/// W3C Trace Context compatible distributed trace context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    /// 16-byte trace ID encoded as hex string.
    pub trace_id: String,
    /// 8-byte span ID encoded as hex string.
    pub span_id: String,
    /// Trace flags (W3C trace-flags).
    #[serde(default)]
    pub flags: u8,
}

impl TraceContext {
    /// Create a new trace context.
    #[must_use]
    pub fn new(trace_id: impl Into<String>, span_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
            flags: 0,
        }
    }

    /// Create a trace context with flags.
    #[must_use]
    pub const fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Returns true if the sampled flag is set.
    #[must_use]
    pub const fn is_sampled(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

impl fmt::Display for TraceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "00-{}-{}-{:02x}",
            self.trace_id, self.span_id, self.flags
        )
    }
}

// ============================================================================
// AuditEntry
// ============================================================================

/// Structured payload for a capability-constraint denial audit event.
///
/// The audit entry records a hash of the request descriptor instead of the raw
/// request payload. `observed_value` is the narrow value that failed the
/// constraint check, such as a resource URI or usage counter summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityConstraintDenied {
    /// Machine-readable constraint kind that denied the request.
    pub constraint_kind: String,
    /// Narrow observed value that failed the constraint check.
    pub observed_value: String,
    /// Domain-separated BLAKE3 hash of the redacted request descriptor.
    pub request_descriptor_hash: String,
    /// Node that made the denial decision.
    pub denying_node: String,
    /// Event timestamp in Unix seconds.
    pub timestamp: u64,
}

impl CapabilityConstraintDenied {
    /// Create a new capability-constraint denial payload.
    #[must_use]
    pub fn new(
        constraint_kind: impl Into<String>,
        observed_value: impl Into<String>,
        request_descriptor_hash: impl Into<String>,
        denying_node: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        Self {
            constraint_kind: constraint_kind.into(),
            observed_value: observed_value.into(),
            request_descriptor_hash: request_descriptor_hash.into(),
            denying_node: denying_node.into(),
            timestamp,
        }
    }

    #[must_use]
    fn into_metadata(self) -> std::collections::BTreeMap<String, serde_json::Value> {
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert("constraint_kind".to_string(), self.constraint_kind.into());
        metadata.insert("observed_value".to_string(), self.observed_value.into());
        metadata.insert(
            "request_descriptor_hash".to_string(),
            self.request_descriptor_hash.into(),
        );
        metadata.insert("denying_node".to_string(), self.denying_node.into());
        metadata.insert("timestamp".to_string(), self.timestamp.into());
        metadata
    }
}

/// Hash a redacted request descriptor for capability-constraint audit events.
///
/// The descriptor should contain routing and constraint-relevant fields only,
/// never the raw request payload. The returned hash is domain-separated from
/// audit-entry IDs and receipt IDs.
///
/// # Errors
///
/// Returns [`AuditError::SerializationError`] when canonical CBOR encoding of
/// the descriptor fails.
pub fn capability_constraint_request_descriptor_hash<T>(
    descriptor: &T,
) -> Result<String, AuditError>
where
    T: Serialize,
{
    let canonical = fcp_cbor::to_canonical_cbor(descriptor).map_err(|err| {
        AuditError::SerializationError(format!(
            "failed to canonicalize capability-constraint request descriptor: {err}"
        ))
    })?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_CONSTRAINT_DESCRIPTOR_HASH_DOMAIN);
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize().as_bytes()))
}

/// A single entry in the audit chain.
///
/// Represents an append-only, hash-linked audit event. Each entry links to its
/// predecessor via `prev` and carries a monotonic `seq` for O(1) freshness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this entry.
    pub id: String,
    /// Event type (e.g., "secret.access", "capability.invoke").
    pub event_type: String,
    /// Severity level.
    pub severity: Severity,
    /// Actor who triggered the event.
    pub actor: String,
    /// Zone where event occurred.
    pub zone_id: String,
    /// Monotonic chain sequence number.
    pub seq: u64,
    /// When event occurred (Unix timestamp seconds).
    pub occurred_at: u64,
    /// Hybrid logical timestamp for cross-zone causal ordering.
    #[serde(default = "default_audit_entry_hlc")]
    pub hlc: HybridLogicalTimestamp,
    /// Previous entry ID in chain (hash link).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// Correlation ID for request tracing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub correlation_id: String,
    /// Optional trace context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,
    /// Connector ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Operation ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Additional metadata as key-value pairs.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub metadata: std::collections::BTreeMap<String, serde_json::Value>,
    /// Key ID of the issuer that signed this entry, if any.
    ///
    /// Required when `signature` is `Some`. Lookup at verification time
    /// resolves this to an [`Ed25519VerifyingKey`] via the caller-supplied
    /// resolver passed to [`verify_chain_with_signers`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_kid: Option<KeyId>,
    /// Ed25519 signature over the entry's canonical signing transcript
    /// (see [`AuditEntry::signing_bytes`]).
    ///
    /// `None` for entries written by callers that do not sign (the legacy
    /// shape; integrity is still enforced by hash linkage but authenticity
    /// is not). When present, [`verify_chain_with_signers`] verifies this
    /// against the resolved verifying key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Ed25519Signature>,
}

#[derive(Serialize)]
struct AuditEntryIdMaterial<'a> {
    event_type: &'a str,
    severity: Severity,
    actor: &'a str,
    zone_id: &'a str,
    seq: u64,
    occurred_at: u64,
    hlc: &'a HybridLogicalTimestamp,
    prev: Option<&'a str>,
    correlation_id: &'a str,
    trace_context: Option<&'a TraceContext>,
    connector_id: Option<&'a str>,
    operation_id: Option<&'a str>,
    metadata: &'a std::collections::BTreeMap<String, serde_json::Value>,
}

/// Borrowed field set used to compute an [`AuditEntry`] canonical id without
/// first materializing an owned entry.
///
/// This is useful on hot append paths that may need to speculatively compute
/// an id and then discard it if an optimistic chain-head compare fails. The
/// canonical payload is byte-identical to [`AuditEntry::computed_id`].
#[derive(Debug, Clone, Copy)]
pub struct AuditEntryIdFields<'a> {
    /// Audit event type.
    pub event_type: &'a str,
    /// Event severity.
    pub severity: Severity,
    /// Actor who triggered the event.
    pub actor: &'a str,
    /// Zone where the event occurred.
    pub zone_id: &'a str,
    /// Monotonic chain sequence number.
    pub seq: u64,
    /// Event timestamp in Unix seconds.
    pub occurred_at: u64,
    /// Hybrid logical timestamp bound into the canonical entry id.
    pub hlc: &'a HybridLogicalTimestamp,
    /// Previous entry ID in the chain, if any.
    pub prev: Option<&'a str>,
    /// Correlation ID for request tracing.
    pub correlation_id: &'a str,
    /// Optional distributed trace context.
    pub trace_context: Option<&'a TraceContext>,
    /// Connector ID, if applicable.
    pub connector_id: Option<&'a str>,
    /// Operation ID, if applicable.
    pub operation_id: Option<&'a str>,
    /// Additional metadata as key-value pairs.
    pub metadata: &'a std::collections::BTreeMap<String, serde_json::Value>,
}

/// Compute the canonical id for an audit-entry payload from borrowed fields.
///
/// # Errors
///
/// Returns [`AuditError::SerializationError`] when canonical CBOR encoding of
/// the entry payload fails.
pub fn compute_audit_entry_id(fields: AuditEntryIdFields<'_>) -> Result<String, AuditError> {
    let material = AuditEntryIdMaterial {
        event_type: fields.event_type,
        severity: fields.severity,
        actor: fields.actor,
        zone_id: fields.zone_id,
        seq: fields.seq,
        occurred_at: fields.occurred_at,
        hlc: fields.hlc,
        prev: fields.prev,
        correlation_id: fields.correlation_id,
        trace_context: fields.trace_context,
        connector_id: fields.connector_id,
        operation_id: fields.operation_id,
        metadata: fields.metadata,
    };

    let canonical = fcp_cbor::to_canonical_cbor(&material).map_err(|err| {
        AuditError::SerializationError(format!("failed to canonicalize audit entry: {err}"))
    })?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(AUDIT_ENTRY_ID_DOMAIN);
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize().as_bytes()))
}

impl AuditEntry {
    /// Check if this is a genesis entry (seq 0, no prev).
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.seq == 0 && self.prev.is_none()
    }

    /// Check if this entry follows another entry in the chain.
    #[must_use]
    pub fn follows(&self, other: &Self) -> bool {
        other
            .seq
            .checked_add(1)
            .is_some_and(|next_seq| self.seq == next_seq)
            && self.prev.as_deref() == Some(other.id.as_str())
    }

    /// Get the severity for this entry's event type.
    #[must_use]
    pub fn computed_severity(&self) -> Severity {
        Severity::for_event_type(&self.event_type)
    }

    /// Recompute the canonical entry ID from the entry payload itself.
    ///
    /// The `id` field is excluded from the canonical bytes so verification does
    /// not trust producer-supplied identifiers.
    ///
    /// # Errors
    /// Returns [`AuditError::SerializationError`] when canonical CBOR encoding
    /// of the entry payload fails.
    pub fn computed_id(&self) -> Result<String, AuditError> {
        compute_audit_entry_id(AuditEntryIdFields {
            event_type: &self.event_type,
            severity: self.severity,
            actor: &self.actor,
            zone_id: &self.zone_id,
            seq: self.seq,
            occurred_at: self.occurred_at,
            hlc: &self.hlc,
            prev: self.prev.as_deref(),
            correlation_id: &self.correlation_id,
            trace_context: self.trace_context.as_ref(),
            connector_id: self.connector_id.as_deref(),
            operation_id: self.operation_id.as_deref(),
            metadata: &self.metadata,
        })
    }

    /// Canonical bytes that an issuer signs to bind their identity to
    /// this entry.
    ///
    /// Format: `AUDIT_ENTRY_SIG_DOMAIN || u32(id_len, LE) || id ||
    ///          u32(kid_len, LE) || kid_bytes`
    ///
    /// The signature commits to the recomputed `id` (a hash of the
    /// canonical payload) rather than the producer-supplied `id` field,
    /// so it transitively binds every other field that participates in
    /// `computed_id`. The `issuer_kid` is included in the transcript so
    /// a signature cannot be replayed under a different claimed issuer.
    /// The `signature` field itself is excluded.
    ///
    /// # Errors
    /// Returns [`AuditError::SerializationError`] if `computed_id` fails
    /// to canonicalize the payload.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuditError> {
        let id = self.computed_id()?;
        Ok(self.signing_bytes_from_id(&id))
    }

    /// Build signing bytes from a **pre-computed** canonical id,
    /// skipping the redundant `computed_id()` canonicalization.
    ///
    /// Used by batch verification paths (e.g.
    /// [`verify_chain_with_signers`]) that already hold the canonical
    /// id for each entry; prevents paying the canonical-CBOR +
    /// BLAKE3 cost twice per entry per call (br-atd32). The caller is
    /// responsible for having computed `id` via
    /// [`AuditEntry::computed_id`] — passing an arbitrary string
    /// produces a valid but meaningless signing transcript.
    #[must_use]
    pub fn signing_bytes_from_id(&self, id: &str) -> Vec<u8> {
        let id_bytes = id.as_bytes();
        let kid_slice: &[u8] = self
            .issuer_kid
            .as_ref()
            .map_or(&[][..], |kid| kid.as_slice());

        let mut bytes = Vec::with_capacity(
            AUDIT_ENTRY_SIG_DOMAIN.len() + 4 + id_bytes.len() + 4 + kid_slice.len(),
        );
        bytes.extend_from_slice(AUDIT_ENTRY_SIG_DOMAIN);
        bytes.extend_from_slice(
            &u32::try_from(id_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(id_bytes);
        bytes.extend_from_slice(
            &u32::try_from(kid_slice.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(kid_slice);
        bytes
    }

    /// Sign this entry with the supplied Ed25519 signing key, populating
    /// `issuer_kid` and `signature` in place. Overwrites any prior
    /// signature. After signing, callers should treat the entry as
    /// immutable; mutating any field covered by `computed_id`
    /// invalidates the signature.
    ///
    /// # Errors
    /// Returns [`AuditError::SerializationError`] if the canonical
    /// signing transcript cannot be built.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) -> Result<(), AuditError> {
        // Set the kid first so it participates in the signed transcript.
        self.issuer_kid = Some(signing_key.key_id());
        let transcript = self.signing_bytes()?;
        self.signature = Some(signing_key.sign(&transcript));
        Ok(())
    }

    /// Verify the entry's signature against the supplied verifying key.
    ///
    /// Requires both `issuer_kid` and `signature` to be present and the
    /// `verifying_key.key_id()` to match `issuer_kid`. Returns
    /// [`AuditError::SignerMissing`] when either field is absent and
    /// [`AuditError::SignatureInvalid`] when the signer/key do not match
    /// or the signature does not verify against the canonical transcript.
    ///
    /// # Errors
    /// See above for the typed error variants.
    pub fn verify_signature(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), AuditError> {
        let id = self.computed_id()?;
        self.verify_signature_with_id(verifying_key, &id)
    }

    /// Verify the entry's signature using a **pre-computed** canonical
    /// id for the signing transcript, avoiding the redundant
    /// canonicalize+hash work that [`verify_signature`] performs.
    ///
    /// Used by batch verification (see [`verify_chain_with_signers`])
    /// that already holds the canonical id for each entry; paired with
    /// [`signing_bytes_from_id`] this halves the per-entry
    /// serialization cost of a signed-chain check (br-atd32).
    ///
    /// # Errors
    /// Same as [`verify_signature`]: [`AuditError::SignerMissing`] when
    /// `issuer_kid` or `signature` is absent;
    /// [`AuditError::SignatureInvalid`] when the signer/key do not
    /// match or the signature does not verify against the canonical
    /// transcript.
    ///
    /// [`signing_bytes_from_id`]: Self::signing_bytes_from_id
    pub fn verify_signature_with_id(
        &self,
        verifying_key: &Ed25519VerifyingKey,
        id: &str,
    ) -> Result<(), AuditError> {
        let kid = self
            .issuer_kid
            .as_ref()
            .ok_or(AuditError::SignerMissing { seq: self.seq })?;
        let signature = self
            .signature
            .as_ref()
            .ok_or(AuditError::SignerMissing { seq: self.seq })?;

        if verifying_key.key_id().as_slice() != kid.as_slice() {
            return Err(AuditError::SignatureInvalid { seq: self.seq });
        }

        let transcript = self.signing_bytes_from_id(id);
        verifying_key
            .verify(&transcript, signature)
            .map_err(|_| AuditError::SignatureInvalid { seq: self.seq })
    }
}

impl fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[seq={}] {} by {} in {} at {}",
            self.seq, self.event_type, self.actor, self.zone_id, self.occurred_at
        )
    }
}

// ============================================================================
// AuditEntryBuilder
// ============================================================================

/// Builder for constructing `AuditEntry` instances.
#[derive(Debug, Clone, Default)]
pub struct AuditEntryBuilder {
    id: Option<String>,
    event_type: Option<String>,
    severity: Option<Severity>,
    actor: Option<String>,
    zone_id: Option<String>,
    seq: Option<u64>,
    occurred_at: Option<u64>,
    hlc: Option<HybridLogicalTimestamp>,
    prev: Option<String>,
    correlation_id: Option<String>,
    trace_context: Option<TraceContext>,
    connector_id: Option<String>,
    operation_id: Option<String>,
    metadata: std::collections::BTreeMap<String, serde_json::Value>,
}

impl AuditEntryBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the entry ID.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the event type.
    #[must_use]
    pub fn event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = Some(event_type.into());
        self
    }

    /// Set the severity.
    #[must_use]
    pub const fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Set the actor.
    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Set the zone ID.
    #[must_use]
    pub fn zone_id(mut self, zone_id: impl Into<String>) -> Self {
        self.zone_id = Some(zone_id.into());
        self
    }

    /// Set the sequence number.
    #[must_use]
    pub const fn seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Set the occurred-at timestamp.
    #[must_use]
    pub const fn occurred_at(mut self, ts: u64) -> Self {
        self.occurred_at = Some(ts);
        self
    }

    /// Set the hybrid logical timestamp.
    #[must_use]
    pub fn hlc(mut self, hlc: HybridLogicalTimestamp) -> Self {
        self.hlc = Some(hlc);
        self
    }

    /// Set the previous entry ID.
    #[must_use]
    pub fn prev(mut self, prev: impl Into<String>) -> Self {
        self.prev = Some(prev.into());
        self
    }

    /// Set the correlation ID.
    #[must_use]
    pub fn correlation_id(mut self, cid: impl Into<String>) -> Self {
        self.correlation_id = Some(cid.into());
        self
    }

    /// Set the trace context.
    #[must_use]
    pub fn trace_context(mut self, tc: TraceContext) -> Self {
        self.trace_context = Some(tc);
        self
    }

    /// Set the connector ID.
    #[must_use]
    pub fn connector_id(mut self, cid: impl Into<String>) -> Self {
        self.connector_id = Some(cid.into());
        self
    }

    /// Set the operation ID.
    #[must_use]
    pub fn operation_id(mut self, oid: impl Into<String>) -> Self {
        self.operation_id = Some(oid.into());
        self
    }

    /// Add a metadata key-value pair.
    #[must_use]
    pub fn meta(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Mark this entry as a capability-constraint denial audit event.
    ///
    /// This populates the normative event type, warning severity, and redacted
    /// structured metadata. Callers still supply the chain-specific fields
    /// (`id`, `seq`, and optional `prev`) through the normal builder methods.
    #[must_use]
    pub fn capability_constraint_denied(mut self, denial: CapabilityConstraintDenied) -> Self {
        self.event_type = Some(event_types::CAPABILITY_CONSTRAINT_DENIED.to_string());
        self.severity = Some(Severity::Warning);
        self.metadata.extend(denial.into_metadata());
        self
    }

    /// Build the `AuditEntry`.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::BuilderMissingField` if required fields are not set.
    pub fn build(self) -> Result<AuditEntry, AuditError> {
        let id = self
            .id
            .ok_or_else(|| AuditError::BuilderMissingField("id".to_string()))?;
        let event_type = self
            .event_type
            .ok_or_else(|| AuditError::BuilderMissingField("event_type".to_string()))?;
        let actor = self
            .actor
            .ok_or_else(|| AuditError::BuilderMissingField("actor".to_string()))?;
        let zone_id = self
            .zone_id
            .ok_or_else(|| AuditError::BuilderMissingField("zone_id".to_string()))?;
        let seq = self
            .seq
            .ok_or_else(|| AuditError::BuilderMissingField("seq".to_string()))?;
        let occurred_at = self
            .occurred_at
            .ok_or_else(|| AuditError::BuilderMissingField("occurred_at".to_string()))?;

        let severity = self
            .severity
            .unwrap_or_else(|| Severity::for_event_type(&event_type));
        let hlc = self
            .hlc
            .unwrap_or_else(|| audit_entry_hlc_from_occurred_at(occurred_at, actor.clone()));

        Ok(AuditEntry {
            id,
            event_type,
            severity,
            actor,
            zone_id,
            seq,
            occurred_at,
            hlc,
            prev: self.prev,
            correlation_id: self.correlation_id.unwrap_or_default(),
            trace_context: self.trace_context,
            connector_id: self.connector_id,
            operation_id: self.operation_id,
            metadata: self.metadata,
            issuer_kid: None,
            signature: None,
        })
    }

    /// Build an [`AuditEntry`] whose id is derived from its canonical payload.
    ///
    /// The entry is first materialized with a placeholder id, then its
    /// canonical id is computed and written back into the public `id` field.
    /// This avoids the common two-build pattern where callers construct a
    /// provisional entry only to hash it, then clone the same builder again to
    /// construct the final entry with the computed id.
    ///
    /// # Errors
    ///
    /// Returns `AuditError::BuilderMissingField` when required fields are
    /// absent, or `AuditError::SerializationError` if canonical CBOR
    /// encoding of the entry payload fails.
    pub fn build_with_computed_id(self) -> Result<AuditEntry, AuditError> {
        let mut entry = self.id("__provisional__").build()?;
        entry.id = entry.computed_id()?;
        Ok(entry)
    }
}

// ============================================================================
// ChainHead
// ============================================================================

/// A quorum signature attached to a [`ChainHead`].
///
/// Carries an opaque signature byte string plus the issuer's key identifier.
/// `fcp-audit` itself does not verify the signature (doing so would require a
/// crypto dependency); callers are expected to use the issuer key registry of
/// their choice (typically an Ed25519 verifying key looked up by `issuer_kid`).
///
/// The signatures are carried on `ChainHead` so consumers can make quorum
/// decisions based on the ACTUAL signatures present, not on a producer-asserted
/// count. See [`ChainHead::has_quorum`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadSignature {
    /// Issuer key identifier (e.g., a `KeyId` in string form).
    pub issuer_kid: String,
    /// Opaque signature bytes (typically Ed25519, 64 bytes), hex-encoded on the wire.
    #[serde(with = "head_signature_bytes")]
    pub signature: Vec<u8>,
}

mod head_signature_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Checkpoint of the audit chain head.
///
/// Enables fast sync without full chain traversal.
///
/// # Quorum semantics
///
/// A head's quorum status is determined by the [`signatures`](Self::signatures)
/// list, NOT by the [`signature_count`](Self::signature_count) field in
/// isolation. The count is retained for wire-format and snapshot
/// backwards-compatibility but is cross-checked against the signatures list:
/// any divergence is surfaced by [`verify_chain`] as an
/// `audit.head_signature_count_inconsistent` issue, and
/// [`ChainHead::has_quorum`] returns `false` when the two disagree.
///
/// Callers that need to authenticate a head MUST verify the
/// [`HeadSignature`] entries against a trusted issuer key registry — this
/// crate does not perform that verification itself (to remain crypto-free).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainHead {
    /// Zone this head covers.
    pub zone_id: String,
    /// Head entry ID (tip of the chain).
    pub head_entry: String,
    /// Sequence number of the head entry.
    pub head_seq: u64,
    /// Coverage fraction (0.0-1.0) of expected nodes contributing.
    pub coverage: f64,
    /// Epoch identifier.
    pub epoch_id: String,
    /// Number of quorum signatures. MUST equal `signatures.len()`; divergence
    /// is flagged by [`verify_chain`] as a critical issue.
    pub signature_count: u32,
    /// Quorum signatures from issuers attesting to this head.
    ///
    /// Empty for legacy/unsigned heads. Wire format omits the field when
    /// empty so pre-existing serialized heads remain decodable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<HeadSignature>,
}

impl ChainHead {
    /// Returns true if coverage meets the given threshold.
    #[must_use]
    pub const fn meets_coverage(&self, threshold: f64) -> bool {
        self.coverage >= threshold
    }

    /// Returns true iff this head carries at least one signature, the declared
    /// [`signature_count`](Self::signature_count) matches the actual number of
    /// signatures present, AND every signature carries a distinct
    /// `issuer_kid`.
    ///
    /// This method intentionally does NOT verify signatures cryptographically
    /// (that requires an issuer-key registry outside this crate's scope), but
    /// it refuses to treat a producer-asserted numeric count as quorum when no
    /// signatures are attached, when the count disagrees with the list, or when
    /// the same signer appears more than once (which would let one key inflate
    /// its way to any threshold). Cryptographic distinctness is enforced by
    /// [`Self::verify_signatures`].
    #[must_use]
    pub fn has_quorum(&self) -> bool {
        if self.signatures.is_empty()
            || !usize::try_from(self.signature_count).is_ok_and(|n| n == self.signatures.len())
        {
            return false;
        }
        let mut seen: HashSet<&str> = HashSet::with_capacity(self.signatures.len());
        self.signatures
            .iter()
            .all(|sig| seen.insert(sig.issuer_kid.as_str()))
    }

    /// Returns true iff the declared [`signature_count`](Self::signature_count)
    /// matches `signatures.len()`. Used to catch producers that lie about the
    /// count vs the attached signatures.
    #[must_use]
    pub fn signature_count_consistent(&self) -> bool {
        usize::try_from(self.signature_count).is_ok_and(|n| n == self.signatures.len())
    }

    /// Canonical bytes that a quorum issuer signs to bind their identity
    /// to this chain head (br-ax97w).
    ///
    /// Format:
    ///   `CHAIN_HEAD_SIG_DOMAIN
    ///    || u32(zone_id_len, LE)   || zone_id
    ///    || u32(head_entry_len, LE) || head_entry
    ///    || u64(head_seq, LE)
    ///    || u64(coverage_bits, LE)  // exact f64 to_bits representation
    ///    || u32(epoch_id_len, LE)   || epoch_id
    ///    || u32(signature_count, LE)`
    ///
    /// Intentionally EXCLUDES [`Self::signatures`] to break the
    /// recursion (a signature cannot commit to itself). The transcript
    /// DOES commit to `signature_count` so a producer cannot silently
    /// add or drop a signature entry after the quorum signs.
    /// `coverage` is bound as its exact IEEE-754 bit pattern so out-of-range
    /// or non-finite values cannot be retargeted to a different semantic
    /// value (for example `1.5 -> 1.0`) without invalidating signatures.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let zone_bytes = self.zone_id.as_bytes();
        let head_entry_bytes = self.head_entry.as_bytes();
        let epoch_bytes = self.epoch_id.as_bytes();
        let coverage_bits = self.coverage.to_bits();

        let mut bytes = Vec::with_capacity(
            CHAIN_HEAD_SIG_DOMAIN.len()
                + 4
                + zone_bytes.len()
                + 4
                + head_entry_bytes.len()
                + 8
                + 8
                + 4
                + epoch_bytes.len()
                + 4,
        );
        bytes.extend_from_slice(CHAIN_HEAD_SIG_DOMAIN);
        bytes.extend_from_slice(
            &u32::try_from(zone_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(zone_bytes);
        bytes.extend_from_slice(
            &u32::try_from(head_entry_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(head_entry_bytes);
        bytes.extend_from_slice(&self.head_seq.to_le_bytes());
        bytes.extend_from_slice(&coverage_bits.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(epoch_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(epoch_bytes);
        bytes.extend_from_slice(&self.signature_count.to_le_bytes());
        bytes
    }

    /// Verify every [`HeadSignature`] in [`Self::signatures`] against
    /// the caller-supplied issuer key registry (br-ax97w).
    ///
    /// The head's `head_seq` is used as the `seq` on any returned
    /// [`AuditError`] so callers can correlate the rejection with the
    /// chain tip. Verification is ALL-OR-NOTHING: the first signature
    /// that fails to resolve (`UnknownIssuer`) or fails to verify
    /// (`SignatureInvalid`) aborts with a typed error.
    ///
    /// # Errors
    ///
    /// - [`AuditError::EmptySignedHead`] — the head carries no
    ///   signatures, or a signature entry carries empty bytes.
    /// - [`AuditError::UnknownIssuer`] — a signature references an
    ///   `issuer_kid` that `key_lookup` does not resolve.
    /// - [`AuditError::SignatureInvalid`] — a non-empty signature has
    ///   wrong-length bytes, the kid does not match the verifying key,
    ///   or the Ed25519 verify fails against [`Self::signing_bytes`].
    pub fn verify_signatures(
        &self,
        key_lookup: &impl Fn(&KeyId) -> Option<Ed25519VerifyingKey>,
    ) -> Result<(), AuditError> {
        if self.signatures.is_empty() {
            return Err(AuditError::EmptySignedHead { seq: self.head_seq });
        }
        let transcript = self.signing_bytes();
        // Track resolved signer keys so a single key cannot satisfy an
        // N-signer quorum by attaching the same signature N times — quorum is
        // N *distinct* signers, not N signatures.
        let mut seen_signers: HashSet<Vec<u8>> = HashSet::with_capacity(self.signatures.len());
        for sig in &self.signatures {
            let kid = KeyId::from_hex(&sig.issuer_kid)
                .map_err(|_| AuditError::UnknownIssuer { seq: self.head_seq })?;
            let verifying_key =
                key_lookup(&kid).ok_or(AuditError::UnknownIssuer { seq: self.head_seq })?;
            if verifying_key.key_id().as_slice() != kid.as_slice() {
                return Err(AuditError::SignatureInvalid { seq: self.head_seq });
            }
            if !seen_signers.insert(kid.as_slice().to_vec()) {
                return Err(AuditError::DuplicateSigner { seq: self.head_seq });
            }
            if sig.signature.is_empty() {
                return Err(AuditError::EmptySignedHead { seq: self.head_seq });
            }
            if sig.signature.len() < ED25519_SIGNATURE_SIZE {
                return Err(AuditError::SignatureInvalid { seq: self.head_seq });
            }
            let signature = Ed25519Signature::try_from_slice(&sig.signature)
                .map_err(|_| AuditError::SignatureInvalid { seq: self.head_seq })?;
            verifying_key
                .verify(&transcript, &signature)
                .map_err(|_| AuditError::SignatureInvalid { seq: self.head_seq })?;
        }
        Ok(())
    }
}

impl fmt::Display for ChainHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChainHead(zone={}, seq={}, coverage={:.1}%)",
            self.zone_id,
            self.head_seq,
            self.coverage * 100.0
        )
    }
}

// ============================================================================
// Decision + DecisionReceipt
// ============================================================================

/// Decision outcome for capability/access evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Access/capability was allowed.
    Allow,
    /// Access/capability was denied.
    Deny,
}

impl Decision {
    /// Returns true if this is an Allow decision.
    #[must_use]
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns true if this is a Deny decision.
    #[must_use]
    pub const fn is_deny(self) -> bool {
        matches!(self, Self::Deny)
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

/// Decision receipt for explainable allow/deny.
///
/// Content-addressed "why allowed/denied" record with stable reason codes
/// and evidence references. This powers `fcp explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Unique receipt ID.
    pub id: String,
    /// The request that was evaluated.
    pub request_id: String,
    /// The decision outcome.
    pub decision: Decision,
    /// Stable reason code for programmatic handling.
    pub reason_code: String,
    /// Evidence references that support this decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Canonical audit entry that recorded the decision, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_entry_id: Option<String>,
    /// Optional human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    /// When the decision was made (Unix timestamp seconds).
    pub decided_at: u64,
    /// Zone context.
    pub zone_id: String,
    /// Correlation ID tying the receipt to the evaluated request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Trace context for distributed request attribution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_context: Option<TraceContext>,
    /// Connector that produced or was evaluated by this decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Connector operation associated with the decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Calibrated confidence derived from recent receipt history for this
    /// connector operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConformalScore>,
    /// Ed25519 key ID of the receipt's signer, when the emitting host
    /// has a configured audit signing key. Present iff [`Self::signature`]
    /// is present. Bead `flywheel_connectors-17l4c`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_kid: Option<KeyId>,
    /// Ed25519 signature over the canonical transcript produced by
    /// [`Self::signing_bytes`]. Present iff the emitting host signed
    /// the receipt. Absence means the receipt was emitted by a legacy
    /// path that predates signing; verifiers MUST distinguish
    /// "unsigned receipt" from "signature invalid" so an operator
    /// upgrading a fleet can observe the two cohorts separately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Ed25519Signature>,
}

#[derive(Serialize)]
struct DecisionReceiptIdMaterial<'a> {
    // Everything except `id`, `issuer_kid`, `signature`: the former is
    // producer-supplied and must not be trusted; the latter two are
    // what the signature binds so they cannot appear inside the bound
    // transcript.
    request_id: &'a str,
    decision: Decision,
    reason_code: &'a str,
    evidence: &'a [String],
    audit_entry_id: Option<&'a str>,
    explanation: Option<&'a str>,
    decided_at: u64,
    zone_id: &'a str,
    correlation_id: Option<&'a str>,
    trace_context: Option<&'a TraceContext>,
    connector_id: Option<&'a str>,
    operation_id: Option<&'a str>,
    confidence: Option<&'a ConformalScore>,
}

impl DecisionReceipt {
    /// Returns true if this receipt is an allow decision.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }

    /// Returns true if this receipt is a deny decision.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        self.decision.is_deny()
    }

    /// Returns true if this receipt has an explanation.
    #[must_use]
    pub const fn has_explanation(&self) -> bool {
        self.explanation.is_some()
    }

    /// Returns the number of evidence references.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    /// Recompute the canonical receipt ID from the payload itself.
    ///
    /// Domain-separated BLAKE3 over the canonical CBOR of every field
    /// except `id`, `issuer_kid`, and `signature`. Mirrors
    /// [`AuditEntry::computed_id`] — `id` is excluded because
    /// producer-supplied identifiers must not be trusted; the other
    /// two are what the signature binds, so they cannot appear inside
    /// the bound transcript.
    ///
    /// # Errors
    /// Returns [`AuditError::SerializationError`] when canonical CBOR
    /// encoding of the payload fails.
    pub fn computed_id(&self) -> Result<String, AuditError> {
        let material = DecisionReceiptIdMaterial {
            request_id: &self.request_id,
            decision: self.decision,
            reason_code: &self.reason_code,
            evidence: &self.evidence,
            audit_entry_id: self.audit_entry_id.as_deref(),
            explanation: self.explanation.as_deref(),
            decided_at: self.decided_at,
            zone_id: &self.zone_id,
            correlation_id: self.correlation_id.as_deref(),
            trace_context: self.trace_context.as_ref(),
            connector_id: self.connector_id.as_deref(),
            operation_id: self.operation_id.as_deref(),
            confidence: self.confidence.as_ref(),
        };

        let canonical = fcp_cbor::to_canonical_cbor(&material).map_err(|err| {
            AuditError::SerializationError(format!(
                "failed to canonicalize decision receipt {}: {err}",
                self.id
            ))
        })?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(DECISION_RECEIPT_ID_DOMAIN);
        hasher.update(&canonical);
        Ok(hex::encode(hasher.finalize().as_bytes()))
    }

    /// Canonical bytes that an issuer signs to bind their identity to
    /// this receipt.
    ///
    /// Format: `DECISION_RECEIPT_SIG_DOMAIN || u32(id_len, LE) || id ||
    ///          u32(kid_len, LE) || kid_bytes`
    ///
    /// The signature commits to the recomputed `id` (a hash of the
    /// canonical payload) rather than the producer-supplied `id`
    /// field, so it transitively binds every other field that
    /// participates in [`Self::computed_id`]. The `issuer_kid` is
    /// included in the transcript so a signature cannot be replayed
    /// under a different claimed issuer. The `signature` field itself
    /// is excluded.
    ///
    /// # Errors
    /// Returns [`AuditError::SerializationError`] if [`Self::computed_id`]
    /// fails to canonicalize the payload.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuditError> {
        let id = self.computed_id()?;
        let id_bytes = id.as_bytes();
        let kid_slice: &[u8] = self
            .issuer_kid
            .as_ref()
            .map_or(&[][..], |kid| kid.as_slice());

        let mut bytes = Vec::with_capacity(
            DECISION_RECEIPT_SIG_DOMAIN.len() + 4 + id_bytes.len() + 4 + kid_slice.len(),
        );
        bytes.extend_from_slice(DECISION_RECEIPT_SIG_DOMAIN);
        bytes.extend_from_slice(
            &u32::try_from(id_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(id_bytes);
        bytes.extend_from_slice(
            &u32::try_from(kid_slice.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(kid_slice);
        Ok(bytes)
    }

    /// Sign this receipt with the supplied Ed25519 signing key,
    /// populating [`Self::issuer_kid`] and [`Self::signature`] in
    /// place. Overwrites any prior signature. After signing, callers
    /// should treat the receipt as immutable; mutating any field
    /// covered by [`Self::computed_id`] invalidates the signature.
    ///
    /// # Errors
    /// Returns [`AuditError::SerializationError`] if the canonical
    /// signing transcript cannot be built.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) -> Result<(), AuditError> {
        // Set the kid first so it participates in the signed transcript.
        self.issuer_kid = Some(signing_key.key_id());
        let transcript = self.signing_bytes()?;
        self.signature = Some(signing_key.sign(&transcript));
        Ok(())
    }

    /// Verify the receipt's signature against the supplied verifying
    /// key. Mirrors [`AuditEntry::verify_signature`].
    ///
    /// Requires both [`Self::issuer_kid`] and [`Self::signature`] to
    /// be present and the `verifying_key.key_id()` to match
    /// `issuer_kid`. Returns [`AuditError::SignerMissing`] when either
    /// field is absent (so callers can distinguish unsigned-receipt
    /// from invalid-signature cohorts during a rollout) and
    /// [`AuditError::SignatureInvalid`] when the signer/key do not
    /// match or the signature does not verify against the canonical
    /// transcript.
    ///
    /// # Errors
    /// See above for the typed error variants.
    pub fn verify_signature(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), AuditError> {
        let kid = self
            .issuer_kid
            .as_ref()
            .ok_or(AuditError::SignerMissing { seq: 0 })?;
        let signature = self
            .signature
            .as_ref()
            .ok_or(AuditError::SignerMissing { seq: 0 })?;

        if verifying_key.key_id().as_slice() != kid.as_slice() {
            return Err(AuditError::SignatureInvalid { seq: 0 });
        }

        let transcript = self.signing_bytes()?;
        verifying_key
            .verify(&transcript, signature)
            .map_err(|_| AuditError::SignatureInvalid { seq: 0 })
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecisionReceipt({}: {} for {} reason={})",
            self.id, self.decision, self.request_id, self.reason_code
        )
    }
}

// ============================================================================
// AuditFilter
// ============================================================================

/// Filter options for querying audit entries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by connector ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Filter by operation ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// Filter by correlation ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Filter by trace ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Filter by event type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Filter by actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Filter by minimum severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
    /// Filter by zone ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
}

impl AuditFilter {
    /// Check if this filter matches the given entry.
    #[must_use]
    pub fn matches(&self, entry: &AuditEntry) -> bool {
        if let Some(ref cid) = self.connector_id {
            if entry.connector_id.as_ref() != Some(cid) {
                return false;
            }
        }
        if let Some(ref oid) = self.operation_id {
            if entry.operation_id.as_ref() != Some(oid) {
                return false;
            }
        }
        if let Some(ref corr) = self.correlation_id {
            if entry.correlation_id != *corr {
                return false;
            }
        }
        if let Some(ref tid) = self.trace_id {
            match &entry.trace_context {
                Some(tc) if tc.trace_id == *tid => {}
                _ => return false,
            }
        }
        if let Some(ref et) = self.event_type {
            if entry.event_type != *et {
                return false;
            }
        }
        if let Some(ref actor) = self.actor {
            if entry.actor != *actor {
                return false;
            }
        }
        if let Some(min_sev) = self.min_severity {
            if !entry.severity.is_at_least(min_sev) {
                return false;
            }
        }
        if let Some(ref zone) = self.zone_id {
            if entry.zone_id != *zone {
                return false;
            }
        }
        true
    }

    /// Check if any filter field is set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.connector_id.is_none()
            && self.operation_id.is_none()
            && self.correlation_id.is_none()
            && self.trace_id.is_none()
            && self.event_type.is_none()
            && self.actor.is_none()
            && self.min_severity.is_none()
            && self.zone_id.is_none()
    }

    /// Count the number of active filter fields.
    #[must_use]
    pub const fn active_count(&self) -> usize {
        let mut count = 0;
        if self.connector_id.is_some() {
            count += 1;
        }
        if self.operation_id.is_some() {
            count += 1;
        }
        if self.correlation_id.is_some() {
            count += 1;
        }
        if self.trace_id.is_some() {
            count += 1;
        }
        if self.event_type.is_some() {
            count += 1;
        }
        if self.actor.is_some() {
            count += 1;
        }
        if self.min_severity.is_some() {
            count += 1;
        }
        if self.zone_id.is_some() {
            count += 1;
        }
        count
    }
}

impl fmt::Display for AuditFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "AuditFilter(none)");
        }
        write!(f, "AuditFilter({} active)", self.active_count())
    }
}

// ============================================================================
// VerifyStatus + VerifyIssue + VerifyReport
// ============================================================================

/// Status of audit chain verification.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerifyStatus {
    /// Chain is valid.
    #[default]
    Ok,
    /// Chain has warnings but is usable.
    Warn,
    /// Chain has critical issues.
    Fail,
}

impl VerifyStatus {
    /// Returns true if the status indicates success.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns true if the status indicates failure.
    #[must_use]
    pub const fn is_fail(self) -> bool {
        matches!(self, Self::Fail)
    }
}

impl fmt::Display for VerifyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Warn => write!(f, "warn"),
            Self::Fail => write!(f, "fail"),
        }
    }
}

/// An issue found during chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyIssue {
    /// Issue code (e.g., `audit.seq_gap`).
    pub code: String,
    /// Human-readable description.
    pub message: String,
    /// Sequence number where issue was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// Entry ID where issue was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
}

impl VerifyIssue {
    /// Create a new verify issue.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            seq: None,
            entry_id: None,
        }
    }

    /// Set the sequence number context.
    #[must_use]
    pub const fn with_seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Set the entry ID context.
    #[must_use]
    pub fn with_entry_id(mut self, entry_id: impl Into<String>) -> Self {
        self.entry_id = Some(entry_id.into());
        self
    }

    /// Returns true if this is a critical issue that causes verification failure.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        matches!(
            self.code.as_str(),
            "audit.fork_detected"
                | "audit.object_id_mismatch"
                | "audit.object_id_unverifiable"
                | "audit.chain.empty"
                | "audit.prev_mismatch"
                | "audit.seq_gap"
                | "audit.genesis_invalid"
                | "audit.head_mismatch"
                | "audit.head_seq_mismatch"
                | "audit.head_signature_count_inconsistent"
                | "audit.timestamp_future"
        )
    }
}

impl fmt::Display for VerifyIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Report from audit chain verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Overall status.
    pub status: VerifyStatus,
    /// Zone ID (if scoped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    /// Number of entries in the chain.
    pub chain_len: usize,
    /// Head sequence (if head was provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<u64>,
    /// Head entry ID (if head was provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_entry: Option<String>,
    /// Issues found.
    #[serde(default)]
    pub issues: Vec<VerifyIssue>,
}

impl VerifyReport {
    /// Create an empty OK report.
    #[must_use]
    pub const fn ok(chain_len: usize) -> Self {
        Self {
            status: VerifyStatus::Ok,
            zone_id: None,
            chain_len,
            head_seq: None,
            head_entry: None,
            issues: Vec::new(),
        }
    }

    /// Returns true if no issues were found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.issues.is_empty()
    }

    /// Returns the number of critical issues.
    #[must_use]
    pub fn critical_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_critical()).count()
    }
}

impl fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VerifyReport(status={}, chain_len={}, issues={})",
            self.status,
            self.chain_len,
            self.issues.len()
        )
    }
}

// ============================================================================
// Chain verification
// ============================================================================

/// Verify an audit chain for **integrity** (hash linkage, monotonic
/// sequence, head agreement) — NOT for **authenticity**.
///
/// Checks:
/// - Genesis entry has seq 0 and no prev
/// - Sequence numbers are monotonically increasing without gaps
/// - Each entry's `prev` points to the preceding entry's `id`
/// - Each entry's `id` matches the canonical payload hash
/// - If a head is provided, it matches the chain tip
///
/// **Authenticity gap (NORMATIVE):** This function does NOT verify
/// `issuer_kid` or `signature` on entries. A chain composed entirely of
/// forged entries (any actor / any zone) signed by no one will pass
/// `verify_chain` cleanly as long as the hash linkage is internally
/// consistent. To enforce authenticity, use
/// [`verify_chain_with_signers`] and supply a key resolver.
///
/// # Arguments
///
/// * `entries` - Sorted audit entries (by seq, ascending)
/// * `head` - Optional chain head to verify against
/// * `zone_id` - Optional zone ID to scope verification
///
/// # Returns
///
/// A `VerifyReport` describing the chain's integrity.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn verify_chain(
    entries: &[AuditEntry],
    head: Option<&ChainHead>,
    zone_id: Option<&str>,
) -> VerifyReport {
    let precomputed: Vec<Result<String, AuditError>> =
        entries.iter().map(AuditEntry::computed_id).collect();
    verify_chain_with_precomputed_ids(entries, head, zone_id, &precomputed)
}

/// Internal core of [`verify_chain`] that accepts precomputed canonical ids.
///
/// Exposed for batch callers (see [`verify_chain_with_signers`]) that need to
/// share canonical-id work across signature verification AND chain-integrity
/// verification (br-atd32).
///
/// The slice length MUST equal `entries.len()`; each element is either
/// `Ok(canonical_id)` or `Err(err)` for the corresponding entry.
/// `Err` positions surface an `audit.object_id_unverifiable` issue in
/// the returned report, matching the behavior of the unified
/// [`verify_chain`] path.
#[must_use]
#[allow(clippy::too_many_lines)] // Single report builder keeps all chain-integrity issues in one pass.
pub fn verify_chain_with_precomputed_ids(
    entries: &[AuditEntry],
    head: Option<&ChainHead>,
    zone_id: Option<&str>,
    precomputed_ids: &[Result<String, AuditError>],
) -> VerifyReport {
    debug_assert_eq!(
        entries.len(),
        precomputed_ids.len(),
        "precomputed_ids length must match entries length"
    );

    let mut issues = Vec::new();

    if entries.is_empty() {
        let mut report = VerifyReport::ok(0);
        report.zone_id = zone_id.map(ToString::to_string);
        if head.is_some() {
            issues.push(VerifyIssue::new(
                "audit.chain.empty",
                "head provided but chain is empty",
            ));
            report.issues = issues;
            report.status = VerifyStatus::Fail;
        }
        return report;
    }

    let mut canonical_ids: Vec<Option<String>> = Vec::with_capacity(entries.len());
    for (entry, precomputed) in entries.iter().zip(precomputed_ids.iter()) {
        match precomputed {
            Ok(canonical_id) => {
                if entry.id != *canonical_id {
                    issues.push(
                        VerifyIssue::new(
                            "audit.object_id_mismatch",
                            format!(
                                "entry id does not match canonical payload hash; expected {canonical_id}"
                            ),
                        )
                        .with_seq(entry.seq)
                        .with_entry_id(&entry.id),
                    );
                }
                canonical_ids.push(Some(canonical_id.clone()));
            }
            Err(err) => {
                issues.push(
                    VerifyIssue::new(
                        "audit.object_id_unverifiable",
                        format!("entry id could not be recomputed: {err}"),
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
                canonical_ids.push(None);
            }
        }
    }

    let effective_zone = zone_id.or_else(|| entries.first().map(|entry| entry.zone_id.as_str()));

    // Check chain zone consistency. Even without an explicit filter, a chain is
    // zone-bound, so the first entry's zone is the authoritative baseline for
    // the rest of the entries and the optional head.
    if let Some(zone) = effective_zone {
        for entry in entries {
            if entry.zone_id != zone {
                issues.push(
                    VerifyIssue::new(
                        "audit.zone_mismatch",
                        format!(
                            "entry zone {} does not match expected zone {}",
                            entry.zone_id, zone
                        ),
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
            }
        }
    }

    // Check duplicate seqs
    let mut seen_seq: std::collections::HashMap<u64, &str> = std::collections::HashMap::new();
    for (entry, canonical_id) in entries.iter().zip(&canonical_ids) {
        let effective_id = canonical_id.as_deref().unwrap_or(entry.id.as_str());
        if let Some(prev_id) = seen_seq.insert(entry.seq, effective_id) {
            if prev_id != effective_id {
                issues.push(
                    VerifyIssue::new(
                        "audit.fork_detected",
                        "multiple entries share the same seq with different ids",
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
            }
        }
    }

    // Check genesis and chain linking
    let mut iter = entries.iter().zip(canonical_ids.iter()).enumerate();
    if let Some((_, (first, _))) = iter.next() {
        if first.seq != 0 || first.prev.is_some() {
            issues.push(
                VerifyIssue::new(
                    "audit.genesis_invalid",
                    "genesis entry must have seq 0 and no prev",
                )
                .with_seq(first.seq)
                .with_entry_id(&first.id),
            );
        }

        let mut prev = first;
        let mut prev_canonical_id = canonical_ids[0].as_deref().unwrap_or(prev.id.as_str());
        for (_, (entry, canonical_id)) in iter {
            // Use checked_add so seq == u64::MAX is correctly treated as a
            // terminal state, consistent with AuditEntry::follows().
            // saturating_add would silently accept a stalled chain.
            let Some(expected_seq) = prev.seq.checked_add(1) else {
                issues.push(
                    VerifyIssue::new(
                        "audit.seq_overflow",
                        format!(
                            "sequence number overflow: previous seq {} cannot be incremented",
                            prev.seq
                        ),
                    )
                    .with_seq(prev.seq)
                    .with_entry_id(&prev.id),
                );
                // Cannot validate further entries after overflow.
                break;
            };
            if entry.seq != expected_seq {
                issues.push(
                    VerifyIssue::new(
                        "audit.seq_gap",
                        format!("expected seq {expected_seq}, found {}", entry.seq),
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
            }

            if entry.prev.as_deref() != Some(prev_canonical_id) {
                issues.push(
                    VerifyIssue::new(
                        "audit.prev_mismatch",
                        "prev pointer does not match previous entry id",
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
            }

            // Timestamps should be non-decreasing along the chain.
            // A backwards timestamp indicates clock skew or tampering.
            if entry.occurred_at < prev.occurred_at {
                issues.push(
                    VerifyIssue::new(
                        "audit.timestamp_regression",
                        format!(
                            "timestamp {} is earlier than previous entry timestamp {}",
                            entry.occurred_at, prev.occurred_at
                        ),
                    )
                    .with_seq(entry.seq)
                    .with_entry_id(&entry.id),
                );
            }

            prev = entry;
            prev_canonical_id = canonical_id.as_deref().unwrap_or(prev.id.as_str());
        }
    }

    // Verify head
    if let Some(head) = head {
        if let Some(last) = entries.last() {
            let last_canonical_id = canonical_ids[entries.len() - 1]
                .as_deref()
                .unwrap_or(last.id.as_str());
            if head.head_entry != last_canonical_id {
                issues.push(
                    VerifyIssue::new(
                        "audit.head_mismatch",
                        "chain head does not reference chain tip",
                    )
                    .with_seq(last.seq)
                    .with_entry_id(&last.id),
                );
            }
            if head.head_seq != last.seq {
                issues.push(
                    VerifyIssue::new(
                        "audit.head_seq_mismatch",
                        "head seq does not match chain tip seq",
                    )
                    .with_seq(last.seq)
                    .with_entry_id(&last.id),
                );
            }
        }

        if let Some(zone) = effective_zone {
            if head.zone_id != zone {
                issues.push(VerifyIssue::new(
                    "audit.head_zone_mismatch",
                    format!("head zone {} does not match {}", head.zone_id, zone),
                ));
            }
        }

        // Cross-check that the producer's asserted `signature_count` matches
        // the actual number of signatures attached. Without this, a producer
        // could claim quorum (signature_count=N) while attaching zero
        // signatures, and downstream `has_quorum` checks elsewhere in the
        // codebase would trust the bare count. See
        // `ChainHead::has_quorum` for the read-side enforcement.
        if !head.signature_count_consistent() {
            issues.push(VerifyIssue::new(
                "audit.head_signature_count_inconsistent",
                format!(
                    "head declares signature_count={} but {} signatures are attached",
                    head.signature_count,
                    head.signatures.len()
                ),
            ));
        }
    }

    let is_fail = issues.iter().any(VerifyIssue::is_critical);

    let status = if issues.is_empty() {
        VerifyStatus::Ok
    } else if is_fail {
        VerifyStatus::Fail
    } else {
        VerifyStatus::Warn
    };

    VerifyReport {
        status,
        zone_id: zone_id.map(ToString::to_string),
        chain_len: entries.len(),
        head_seq: head.map(|h| h.head_seq),
        head_entry: head.map(|h| h.head_entry.clone()),
        issues,
    }
}

/// Verify an audit chain for **both integrity and authenticity**.
///
/// Runs [`verify_chain`] for integrity, then requires every entry to
/// carry `issuer_kid` + `signature` and verify against the key returned
/// by `key_lookup(&issuer_kid)`. Closes the authenticity gap that the
/// unsigned [`verify_chain`] intentionally leaves open:
///
///   - Unsigned entries are rejected with
///     [`AuditError::SignerMissing`]
///   - Entries whose `issuer_kid` is unknown to the resolver are
///     rejected with [`AuditError::UnknownIssuer`]
///   - Entries whose signature does not verify against the canonical
///     signing transcript (see [`AuditEntry::signing_bytes`]) are
///     rejected with [`AuditError::SignatureInvalid`]
///
/// On success, returns the same [`VerifyReport`] as [`verify_chain`];
/// on any signer-related failure, returns an `Err` with the first
/// offending entry's seq. Integrity issues surfaced by [`verify_chain`]
/// are reported via the returned `VerifyReport` as usual; this wrapper
/// only fails fast on authenticity.
///
/// # Arguments
///
/// * `entries` - Sorted audit entries (by seq, ascending)
/// * `head` - Optional chain head to verify against
/// * `zone_id` - Optional zone ID to scope verification
/// * `key_lookup` - Resolver from `issuer_kid` to verifying key. Return
///   `None` to reject the entry as having an unknown issuer.
///
/// # Errors
///
/// Returns `AuditError::SignerMissing`, `AuditError::EmptySignedHead`,
/// `AuditError::UnknownIssuer`, or `AuditError::SignatureInvalid` on the
/// first offending entry/head.
pub fn verify_chain_with_signers(
    entries: &[AuditEntry],
    head: Option<&ChainHead>,
    zone_id: Option<&str>,
    key_lookup: impl Fn(&KeyId) -> Option<Ed25519VerifyingKey>,
) -> Result<VerifyReport, AuditError> {
    // br-atd32: canonicalize each entry exactly once and share the
    // result between signature verification and chain-integrity
    // verification. Previously this path paid ~2 full canonical-CBOR
    // + BLAKE3 passes per entry (one inside verify_signature ->
    // signing_bytes -> computed_id, one inside verify_chain).
    let precomputed_ids: Vec<Result<String, AuditError>> =
        entries.iter().map(AuditEntry::computed_id).collect();

    for (entry, id_result) in entries.iter().zip(precomputed_ids.iter()) {
        let kid = entry
            .issuer_kid
            .as_ref()
            .ok_or(AuditError::SignerMissing { seq: entry.seq })?;
        if entry.signature.is_none() {
            return Err(AuditError::SignerMissing { seq: entry.seq });
        }
        let verifying_key = key_lookup(kid).ok_or(AuditError::UnknownIssuer { seq: entry.seq })?;
        // If computed_id failed for this entry, propagate the
        // serialization error with the original semantics (the old
        // verify_signature path bubbled it through ?). Clone is cheap:
        // AuditError derives Clone (see definition).
        let id = match id_result {
            Ok(id) => id.as_str(),
            Err(err) => return Err(err.clone()),
        };
        entry.verify_signature_with_id(&verifying_key, id)?;
    }

    // br-ax97w: authenticate the ChainHead quorum too. verify_chain only
    // checks head-entry linkage + signature_count consistency; an
    // attacker who tampers with a serialized head can swap the quorum
    // signatures for arbitrary bytes while preserving the linkage
    // fields, and the old verify_chain_with_signers would still return
    // Ok. Here we cryptographically verify EVERY head signature against
    // the issuer key registry, over the `ChainHead::signing_bytes()`
    // transcript (which commits to zone_id, head_entry, head_seq,
    // coverage, epoch_id, and signature_count).
    if let Some(head) = head {
        head.verify_signatures(&key_lookup)?;
    }

    Ok(verify_chain_with_precomputed_ids(
        entries,
        head,
        zone_id,
        &precomputed_ids,
    ))
}

/// Verify a signed audit chain and require a non-empty, authenticated head.
///
/// This is the strict production/operator-health entrypoint for contexts where
/// a clean [`VerifyReport`] must mean both the entries and the chain head were
/// present, signed, and authenticated. It rejects empty chains before integrity
/// verification and rejects a missing or empty signed head with
/// [`AuditError::EmptySignedHead`].
///
/// # Errors
///
/// Returns [`AuditError::VerificationFailed`] for an empty entry chain,
/// [`AuditError::EmptySignedHead`] for a missing/empty signed head, or the
/// signer-authentication errors returned by [`verify_chain_with_signers`].
pub fn verify_chain_with_required_signed_head(
    entries: &[AuditEntry],
    head: Option<&ChainHead>,
    zone_id: Option<&str>,
    key_lookup: impl Fn(&KeyId) -> Option<Ed25519VerifyingKey>,
) -> Result<VerifyReport, AuditError> {
    if entries.is_empty() {
        return Err(AuditError::VerificationFailed(
            "signed-head verification requires a non-empty audit chain".to_string(),
        ));
    }

    let head = head.ok_or(AuditError::EmptySignedHead { seq: 0 })?;
    verify_chain_with_signers(entries, Some(head), zone_id, key_lookup)
}

/// Verify an audit chain AND reject entries timestamped implausibly far in
/// the future relative to `now_unix_secs` (a grace of
/// [`MAX_FUTURE_TIMESTAMP_SKEW_SECS`] is allowed for clock skew).
///
/// This closes the gap where [`verify_chain`] detects backward timestamp
/// regressions but accepts arbitrarily-future `occurred_at` values. A
/// single forged future-dated entry is otherwise sufficient to poison
/// freshness SLAs permanently, since subsequent entries only need to be
/// non-decreasing from that point.
///
/// Callers that have no wall-clock reference (offline audit replays)
/// should keep using [`verify_chain`].
#[must_use]
pub fn verify_chain_with_clock(
    entries: &[AuditEntry],
    head: Option<&ChainHead>,
    zone_id: Option<&str>,
    now_unix_secs: u64,
) -> VerifyReport {
    let mut report = verify_chain(entries, head, zone_id);
    let ceiling = now_unix_secs.saturating_add(MAX_FUTURE_TIMESTAMP_SKEW_SECS);

    for entry in entries {
        if entry.occurred_at > ceiling {
            report.issues.push(
                VerifyIssue::new(
                    "audit.timestamp_future",
                    format!(
                        "entry timestamp {} exceeds now+skew ceiling {} by {} seconds",
                        entry.occurred_at,
                        ceiling,
                        entry.occurred_at.saturating_sub(ceiling),
                    ),
                )
                .with_seq(entry.seq)
                .with_entry_id(&entry.id),
            );
        }
    }

    // Re-classify status if we added critical future-timestamp issues.
    let is_fail = report.issues.iter().any(VerifyIssue::is_critical);
    report.status = if report.issues.is_empty() {
        VerifyStatus::Ok
    } else if is_fail {
        VerifyStatus::Fail
    } else {
        VerifyStatus::Warn
    };

    report
}

// ============================================================================
// AuditError
// ============================================================================

/// Errors that can occur in audit operations.
#[derive(Debug, Clone, Error)]
pub enum AuditError {
    /// A required field was missing from the builder.
    #[error("builder missing required field: {0}")]
    BuilderMissingField(String),

    /// Chain verification failed.
    #[error("chain verification failed: {0}")]
    VerificationFailed(String),

    /// Zone was not found.
    #[error("zone '{0}' not found or not accessible")]
    ZoneNotFound(String),

    /// Audit chain is unavailable.
    #[error("audit chain for zone '{0}' is unavailable")]
    ChainUnavailable(String),

    /// Sequence number overflow.
    #[error("sequence number overflow at seq {0}")]
    SeqOverflow(u64),

    /// Invalid entry: describes what's wrong.
    #[error("invalid entry: {0}")]
    InvalidEntry(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Fork detected in the chain.
    #[error("fork detected at seq {0}")]
    ForkDetected(u64),

    /// Entry has no `issuer_kid` or `signature` but signature
    /// verification was requested.
    #[error("entry at seq {seq} is missing issuer_kid or signature")]
    SignerMissing {
        /// Sequence number of the entry that lacked signer binding.
        seq: u64,
    },

    /// Signature verification failed (kid mismatch or signature did not
    /// validate against the canonical signing transcript).
    #[error("signature verification failed at seq {seq}")]
    SignatureInvalid {
        /// Sequence number of the entry whose signature failed.
        seq: u64,
    },

    /// A strict signed-head verifier received no signed head bytes, or
    /// a [`HeadSignature`] carried an empty signature byte string.
    #[error("signed audit chain head at seq {seq} is empty")]
    EmptySignedHead {
        /// Sequence number of the chain head that lacked signature bytes.
        seq: u64,
    },

    /// `verify_chain_with_signers` could not resolve the entry's
    /// `issuer_kid` to a known verifying key.
    #[error("unknown issuer_kid at seq {seq}")]
    UnknownIssuer {
        /// Sequence number of the entry whose issuer key was unknown.
        seq: u64,
    },

    /// A quorum-signed head carried two or more signatures from the same
    /// issuer key. Quorum requires N *distinct* signers; without a
    /// distinctness check a single compromised key could inflate its
    /// signature to satisfy any threshold.
    #[error("duplicate quorum signer at seq {seq}")]
    DuplicateSigner {
        /// Sequence number of the head that carried a repeated signer.
        seq: u64,
    },

    /// Optimistic-CAS retry budget exhausted under same-zone
    /// contention (br-1a73y).
    ///
    /// The per-zone audit-chain writer bounds CAS retries against
    /// pathological storms. Hitting that bound means the per-zone
    /// `Mutex` is overloaded — too many concurrent writers racing on
    /// the same zone. The bail itself is correct (no panic, no chain
    /// corruption), but the operator's correct response is to look at
    /// concurrent-writer counts and consider scaling the per-zone
    /// `Mutex` into a per-shard layout — NOT to investigate
    /// serialisation or canonicalisation bugs (which is what the
    /// previous `SerializationError` taxonomy implied).
    #[error(
        "audit chain CAS retry budget exhausted: zone `{zone_id}` after {attempts} \
         attempts under same-zone contention — scale per-zone writer or shard"
    )]
    ContentionExhausted {
        /// Zone whose audit chain saturated the CAS retry budget.
        zone_id: String,
        /// Number of CAS attempts before the budget tripped.
        attempts: usize,
    },
}

impl AuditError {
    /// Returns the FCP error code for this error variant.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::BuilderMissingField(_) => "FCP-4000",
            Self::VerificationFailed(_) => "FCP-5010",
            Self::ZoneNotFound(_) => "FCP-4001",
            Self::ChainUnavailable(_) => "FCP-5011",
            Self::SeqOverflow(_) => "FCP-5012",
            Self::InvalidEntry(_) => "FCP-4002",
            Self::SerializationError(_) => "FCP-5013",
            Self::ForkDetected(_) => "FCP-5014",
            Self::SignerMissing { .. } => "FCP-5015",
            Self::SignatureInvalid { .. } => "FCP-5016",
            Self::UnknownIssuer { .. } => "FCP-5017",
            Self::EmptySignedHead { .. } => "FCP-5018",
            Self::ContentionExhausted { .. } => "FCP-5019",
            Self::DuplicateSigner { .. } => "FCP-5020",
        }
    }
}

// ============================================================================
// FreshnessLevel
// ============================================================================

/// Freshness level for audit chain status reporting.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum FreshnessLevel {
    /// Chain is up to date.
    Fresh,
    /// Chain is slightly behind.
    Stale,
    /// Chain is significantly behind.
    Degraded,
    /// Chain data is missing or unavailable.
    #[default]
    Missing,
}

impl FreshnessLevel {
    /// Returns true if the chain is considered healthy.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

impl fmt::Display for FreshnessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh => write!(f, "fresh"),
            Self::Stale => write!(f, "stale"),
            Self::Degraded => write!(f, "degraded"),
            Self::Missing => write!(f, "missing"),
        }
    }
}

// ============================================================================
// AuditStatus
// ============================================================================

/// Status of the audit subsystem for a zone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditStatus {
    /// Freshness of the audit chain.
    pub freshness: FreshnessLevel,
    /// Current head sequence number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<u64>,
    /// Coverage fraction (0.0-1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<f64>,
    /// Optional reason/explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuditStatus {
    /// Create a fresh status.
    #[must_use]
    pub const fn fresh(head_seq: u64, coverage: f64) -> Self {
        Self {
            freshness: FreshnessLevel::Fresh,
            head_seq: Some(head_seq),
            coverage: Some(coverage),
            reason: None,
        }
    }

    /// Create a missing status.
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            freshness: FreshnessLevel::Missing,
            head_seq: None,
            coverage: None,
            reason: None,
        }
    }

    /// Add a reason to this status.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

impl Default for AuditStatus {
    fn default() -> Self {
        Self::missing()
    }
}

impl fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuditStatus({})", self.freshness)?;
        if let Some(seq) = self.head_seq {
            write!(f, " seq={seq}")?;
        }
        if let Some(cov) = self.coverage {
            write!(f, " coverage={:.1}%", cov * 100.0)?;
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn raw_genesis_entry() -> AuditEntry {
        AuditEntry {
            id: "entry-0".to_string(),
            event_type: event_types::CAPABILITY_INVOKE.to_string(),
            severity: Severity::Info,
            actor: "user:alice".to_string(),
            zone_id: "z:work".to_string(),
            seq: 0,
            occurred_at: 1_700_000_000,
            hlc: audit_entry_hlc_from_occurred_at(1_700_000_000, "user:alice"),
            prev: None,
            correlation_id: "corr-0".to_string(),
            trace_context: None,
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            metadata: BTreeMap::new(),
            issuer_kid: None,
            signature: None,
        }
    }

    fn raw_chain_entry(seq: u64, prev_id: &str) -> AuditEntry {
        AuditEntry {
            id: format!("entry-{seq}"),
            event_type: event_types::SECRET_ACCESS.to_string(),
            severity: Severity::Warning,
            actor: "user:bob".to_string(),
            zone_id: "z:work".to_string(),
            seq,
            occurred_at: 1_700_000_000 + seq * 60,
            hlc: audit_entry_hlc_from_occurred_at(1_700_000_000 + seq * 60, "user:bob"),
            prev: Some(prev_id.to_string()),
            correlation_id: format!("corr-{seq}"),
            trace_context: None,
            connector_id: None,
            operation_id: None,
            metadata: BTreeMap::new(),
            issuer_kid: None,
            signature: None,
        }
    }

    fn with_computed_id(mut entry: AuditEntry) -> AuditEntry {
        entry.id = entry.computed_id().unwrap();
        entry
    }

    fn canonical_test_entry(seq: u64) -> AuditEntry {
        if seq == 0 {
            with_computed_id(raw_genesis_entry())
        } else {
            let prev = canonical_test_entry(seq - 1);
            with_computed_id(raw_chain_entry(seq, &prev.id))
        }
    }

    fn canonicalize_prev_reference(prev_id: &str) -> String {
        prev_id
            .strip_prefix("entry-")
            .and_then(|value| value.parse::<u64>().ok())
            .map_or_else(|| prev_id.to_string(), |seq| canonical_test_entry(seq).id)
    }

    fn canonicalize_head_reference(entry_id: &str) -> String {
        canonicalize_prev_reference(entry_id)
    }

    fn genesis_entry() -> AuditEntry {
        canonical_test_entry(0)
    }

    fn chain_entry(seq: u64, prev_id: &str) -> AuditEntry {
        with_computed_id(raw_chain_entry(seq, &canonicalize_prev_reference(prev_id)))
    }

    fn sample_signatures(n: u8) -> Vec<HeadSignature> {
        (0..n)
            .map(|i| HeadSignature {
                issuer_kid: format!("kid-{i}"),
                signature: vec![i; 64],
            })
            .collect()
    }

    fn sample_head(entry_id: &str, seq: u64) -> ChainHead {
        ChainHead {
            zone_id: "z:work".to_string(),
            head_entry: canonicalize_head_reference(entry_id),
            head_seq: seq,
            coverage: 0.85,
            epoch_id: "epoch-1".to_string(),
            signature_count: 3,
            signatures: sample_signatures(3),
        }
    }

    fn canonical_chain_in_zone(len: usize, zone_id: &str) -> Vec<AuditEntry> {
        assert!(len > 0, "test chains must contain at least one entry");

        let mut entries = Vec::with_capacity(len);
        let mut prev_id = None;

        for seq in 0..len {
            let mut entry = if seq == 0 {
                raw_genesis_entry()
            } else {
                raw_chain_entry(seq as u64, prev_id.as_deref().unwrap_or("missing-prev"))
            };
            entry.zone_id = zone_id.to_string();
            entry.prev = prev_id.clone();
            entry.id = entry.computed_id().unwrap();

            prev_id = Some(entry.id.clone());
            entries.push(entry);
        }

        entries
    }

    fn chain_head_for(entries: &[AuditEntry], zone_id: &str) -> ChainHead {
        let last = entries.last().expect("test chains must not be empty");
        ChainHead {
            zone_id: zone_id.to_string(),
            head_entry: last.id.clone(),
            head_seq: last.seq,
            coverage: 0.85,
            epoch_id: "epoch-1".to_string(),
            signature_count: 3,
            signatures: sample_signatures(3),
        }
    }

    fn normalized_verify_report(mut report: VerifyReport) -> VerifyReport {
        report.zone_id = None;
        report.head_entry = None;
        report
    }

    fn sample_receipt() -> DecisionReceipt {
        DecisionReceipt {
            id: "receipt-1".to_string(),
            request_id: "req-1".to_string(),
            decision: Decision::Allow,
            reason_code: "policy.match".to_string(),
            evidence: vec!["evidence-1".to_string(), "evidence-2".to_string()],
            audit_entry_id: None,
            explanation: Some("Policy matched capability grant".to_string()),
            decided_at: 1_700_000_000,
            zone_id: "z:work".to_string(),
            correlation_id: None,
            trace_context: None,
            connector_id: None,
            operation_id: None,
            confidence: None,
            issuer_kid: None,
            signature: None,
        }
    }

    // ── event_types constants ────────────────────────────────────────────

    #[test]
    fn event_type_constants_are_valid() {
        assert_eq!(event_types::SECRET_ACCESS, "secret.access");
        assert_eq!(event_types::CAPABILITY_INVOKE, "capability.invoke");
        assert_eq!(
            event_types::CAPABILITY_CONSTRAINT_DENIED,
            "capability.constraint_denied"
        );
        assert_eq!(event_types::ELEVATION_GRANTED, "elevation.granted");
        assert_eq!(
            event_types::DECLASSIFICATION_GRANTED,
            "declassification.granted"
        );
        assert_eq!(event_types::ZONE_TRANSITION, "zone.transition");
        assert_eq!(event_types::REVOCATION_ISSUED, "revocation.issued");
        assert_eq!(event_types::SECURITY_VIOLATION, "security.violation");
        assert_eq!(event_types::AUDIT_FORK_DETECTED, "audit.fork_detected");
        assert_eq!(event_types::CEP_ANOMALY_ALERT, "audit.cep_anomaly_alert");
    }

    #[test]
    fn event_type_constants_contain_dot() {
        let types = [
            event_types::SECRET_ACCESS,
            event_types::CAPABILITY_INVOKE,
            event_types::CAPABILITY_CONSTRAINT_DENIED,
            event_types::ELEVATION_GRANTED,
            event_types::DECLASSIFICATION_GRANTED,
            event_types::ZONE_TRANSITION,
            event_types::REVOCATION_ISSUED,
            event_types::SECURITY_VIOLATION,
            event_types::AUDIT_FORK_DETECTED,
            event_types::CEP_ANOMALY_ALERT,
        ];
        for t in types {
            assert!(t.contains('.'), "event type {t} should contain a dot");
        }
    }

    // ── Severity ─────────────────────────────────────────────────────────

    #[test]
    fn severity_default_is_info() {
        assert_eq!(Severity::default(), Severity::Info);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn severity_is_at_least() {
        assert!(Severity::Critical.is_at_least(Severity::Info));
        assert!(Severity::Warning.is_at_least(Severity::Warning));
        assert!(!Severity::Info.is_at_least(Severity::Warning));
    }

    #[test]
    fn severity_for_event_type_mapping() {
        assert_eq!(
            Severity::for_event_type(event_types::CAPABILITY_INVOKE),
            Severity::Info
        );
        assert_eq!(
            Severity::for_event_type(event_types::CAPABILITY_CONSTRAINT_DENIED),
            Severity::Warning
        );
        assert_eq!(
            Severity::for_event_type(event_types::ZONE_TRANSITION),
            Severity::Info
        );
        assert_eq!(
            Severity::for_event_type(event_types::SECRET_ACCESS),
            Severity::Warning
        );
        assert_eq!(
            Severity::for_event_type(event_types::ELEVATION_GRANTED),
            Severity::Warning
        );
        assert_eq!(
            Severity::for_event_type(event_types::DECLASSIFICATION_GRANTED),
            Severity::Warning
        );
        assert_eq!(
            Severity::for_event_type(event_types::REVOCATION_ISSUED),
            Severity::Error
        );
        assert_eq!(
            Severity::for_event_type(event_types::SECURITY_VIOLATION),
            Severity::Error
        );
        assert_eq!(
            Severity::for_event_type(event_types::AUDIT_FORK_DETECTED),
            Severity::Critical
        );
        assert_eq!(
            Severity::for_event_type(event_types::CEP_ANOMALY_ALERT),
            Severity::Error
        );
    }

    #[test]
    fn severity_for_unknown_event_type() {
        assert_eq!(Severity::for_event_type("custom.event"), Severity::Info);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Error.to_string(), "error");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn severity_serde_roundtrip() {
        for sev in [
            Severity::Info,
            Severity::Warning,
            Severity::Error,
            Severity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let parsed: Severity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, parsed);
        }
    }

    #[test]
    fn severity_serde_values() {
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(
            serde_json::to_string(&Severity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn severity_debug() {
        let debug = format!("{:?}", Severity::Critical);
        assert_eq!(debug, "Critical");
    }

    #[test]
    fn severity_clone() {
        let sev = Severity::Warning;
        let copied = sev;
        assert_eq!(sev, copied);
    }

    #[test]
    fn severity_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Severity::Info);
        set.insert(Severity::Warning);
        set.insert(Severity::Info); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn severity_copy() {
        let sev = Severity::Error;
        let copied = sev;
        assert_eq!(sev, copied); // both still usable, Copy trait
    }

    // ── TraceContext ─────────────────────────────────────────────────────

    #[test]
    fn trace_context_new() {
        let tc = TraceContext::new("trace-id-123", "span-id-456");
        assert_eq!(tc.trace_id, "trace-id-123");
        assert_eq!(tc.span_id, "span-id-456");
        assert_eq!(tc.flags, 0);
    }

    #[test]
    fn trace_context_with_flags() {
        let tc = TraceContext::new("tid", "sid").with_flags(0x01);
        assert_eq!(tc.flags, 0x01);
        assert!(tc.is_sampled());
    }

    #[test]
    fn trace_context_not_sampled() {
        let tc = TraceContext::new("tid", "sid");
        assert!(!tc.is_sampled());
    }

    #[test]
    fn trace_context_sampled_flag() {
        let tc = TraceContext::new("tid", "sid").with_flags(0x03);
        assert!(tc.is_sampled()); // bit 0 is set
    }

    #[test]
    fn trace_context_display() {
        let tc = TraceContext::new("aabb", "ccdd").with_flags(1);
        assert_eq!(tc.to_string(), "00-aabb-ccdd-01");
    }

    #[test]
    fn trace_context_display_zero_flags() {
        let tc = TraceContext::new("aabb", "ccdd");
        assert_eq!(tc.to_string(), "00-aabb-ccdd-00");
    }

    #[test]
    fn trace_context_serde_roundtrip() {
        let tc = TraceContext::new("trace123", "span456").with_flags(1);
        let json = serde_json::to_string(&tc).unwrap();
        let parsed: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, parsed);
    }

    #[test]
    fn trace_context_serde_default_flags() {
        // flags has #[serde(default)] so should deserialize to 0 if missing
        let json = r#"{"trace_id":"t","span_id":"s"}"#;
        let tc: TraceContext = serde_json::from_str(json).unwrap();
        assert_eq!(tc.flags, 0);
    }

    #[test]
    fn trace_context_clone() {
        let tc = TraceContext::new("tid", "sid").with_flags(5);
        let cloned = tc.clone();
        assert_eq!(tc, cloned);
    }

    #[test]
    fn trace_context_debug() {
        let tc = TraceContext::new("tid", "sid");
        let debug = format!("{tc:?}");
        assert!(debug.contains("TraceContext"));
        assert!(debug.contains("tid"));
    }

    #[test]
    fn trace_context_eq() {
        let a = TraceContext::new("tid", "sid");
        let b = TraceContext::new("tid", "sid");
        let c = TraceContext::new("other", "sid");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn trace_context_empty_ids() {
        let tc = TraceContext::new("", "");
        assert_eq!(tc.trace_id, "");
        assert_eq!(tc.span_id, "");
        assert_eq!(tc.to_string(), "00---00");
    }

    #[test]
    fn trace_context_unicode_ids() {
        let tc = TraceContext::new("trace-\u{1F600}", "span-\u{1F680}");
        assert!(tc.trace_id.contains('\u{1F600}'));
        let json = serde_json::to_string(&tc).unwrap();
        let parsed: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, parsed);
    }

    // ── AuditEntry ───────────────────────────────────────────────────────

    #[test]
    fn audit_entry_is_genesis() {
        let entry = genesis_entry();
        assert!(entry.is_genesis());
    }

    #[test]
    fn audit_entry_not_genesis_with_prev() {
        let mut entry = genesis_entry();
        entry.prev = Some("prev-id".to_string());
        assert!(!entry.is_genesis());
    }

    #[test]
    fn audit_entry_not_genesis_nonzero_seq() {
        let mut entry = genesis_entry();
        entry.seq = 1;
        assert!(!entry.is_genesis());
    }

    #[test]
    fn audit_entry_follows() {
        let first = genesis_entry();
        let second = chain_entry(1, "entry-0");
        assert!(second.follows(&first));
    }

    #[test]
    fn audit_entry_follows_wrong_prev() {
        let first = genesis_entry();
        let second = chain_entry(1, "wrong-id");
        assert!(!second.follows(&first));
    }

    #[test]
    fn audit_entry_follows_wrong_seq() {
        let first = genesis_entry();
        let mut second = chain_entry(2, "entry-0"); // gap
        second.prev = Some(first.id.clone());
        assert!(!second.follows(&first));
    }

    #[test]
    fn audit_entry_follows_seq_overflow() {
        let mut first = genesis_entry();
        first.seq = u64::MAX;
        let second = chain_entry(0, "entry-0");
        assert!(!second.follows(&first)); // would overflow
    }

    #[test]
    fn audit_entry_computed_severity() {
        let entry = genesis_entry();
        assert_eq!(entry.computed_severity(), Severity::Info);

        let mut entry2 = genesis_entry();
        entry2.event_type = event_types::SECURITY_VIOLATION.to_string();
        assert_eq!(entry2.computed_severity(), Severity::Error);
    }

    #[test]
    fn audit_entry_display() {
        let entry = genesis_entry();
        let display = entry.to_string();
        assert!(display.contains("seq=0"));
        assert!(display.contains("capability.invoke"));
        assert!(display.contains("user:alice"));
        assert!(display.contains("z:work"));
    }

    #[test]
    fn audit_entry_serde_roundtrip() {
        let entry = genesis_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn audit_entry_serde_skips_none_fields() {
        let entry = genesis_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"prev\""));
        assert!(!json.contains("\"trace_context\""));
    }

    #[test]
    fn audit_entry_serde_skips_empty_metadata() {
        let entry = genesis_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"metadata\""));
    }

    #[test]
    fn audit_entry_serde_skips_empty_correlation_id() {
        let mut entry = genesis_entry();
        entry.correlation_id = String::new();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"correlation_id\""));
    }

    #[test]
    fn audit_entry_serde_with_metadata() {
        let mut entry = genesis_entry();
        entry
            .metadata
            .insert("key".to_string(), serde_json::json!("value"));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"metadata\""));
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.metadata.get("key"),
            Some(&serde_json::json!("value"))
        );
    }

    #[test]
    fn audit_entry_clone() {
        let entry = genesis_entry();
        let cloned = entry.clone();
        assert_eq!(entry.id, cloned.id);
        assert_eq!(entry.seq, cloned.seq);
    }

    #[test]
    fn audit_entry_debug() {
        let entry = genesis_entry();
        let debug = format!("{entry:?}");
        assert!(debug.contains("AuditEntry"));
        assert!(debug.contains(&entry.id));
    }

    #[test]
    fn audit_entry_eq() {
        let a = genesis_entry();
        let b = genesis_entry();
        assert_eq!(a, b);

        let mut c = genesis_entry();
        c.id = "different".to_string();
        assert_ne!(a, c);
    }

    #[test]
    fn audit_entry_computed_id_is_deterministic() {
        let entry = genesis_entry();
        let computed_a = entry.computed_id().unwrap();
        let computed_b = entry.computed_id().unwrap();
        assert_eq!(computed_a, computed_b);
        assert_eq!(computed_a, entry.id);
    }

    #[test]
    fn audit_entry_hlc_participates_in_canonical_id() {
        let mut entry = genesis_entry();
        let baseline = entry.computed_id().unwrap();
        entry.hlc = HybridLogicalTimestamp::new(
            entry.hlc.physical_ms,
            entry.hlc.logical.saturating_add(1),
            entry.hlc.node_id.clone(),
        );
        assert_ne!(
            baseline,
            entry.computed_id().unwrap(),
            "HLC must be part of the audit-entry canonical payload"
        );
    }

    #[test]
    fn audit_entry_with_trace_context() {
        let mut entry = genesis_entry();
        entry.trace_context = Some(TraceContext::new("trace-abc", "span-def"));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("trace_context"));
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert!(parsed.trace_context.is_some());
        assert_eq!(parsed.trace_context.as_ref().unwrap().trace_id, "trace-abc");
    }

    #[test]
    fn audit_entry_unicode_actor() {
        let mut entry = genesis_entry();
        entry.actor = "user:\u{1F600}\u{1F680}".to_string();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.actor, "user:\u{1F600}\u{1F680}");
    }

    #[test]
    fn audit_entry_large_seq() {
        let mut entry = genesis_entry();
        entry.seq = u64::MAX;
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.seq, u64::MAX);
    }

    #[test]
    fn audit_entry_empty_strings() {
        let entry = AuditEntry {
            id: String::new(),
            event_type: String::new(),
            severity: Severity::Info,
            actor: String::new(),
            zone_id: String::new(),
            seq: 0,
            occurred_at: 0,
            hlc: audit_entry_hlc_from_occurred_at(0, ""),
            prev: None,
            correlation_id: String::new(),
            trace_context: None,
            connector_id: None,
            operation_id: None,
            metadata: BTreeMap::new(),
            issuer_kid: None,
            signature: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    // ── Signer binding (regression for la0l1) ─────────────────────────────

    fn signed_test_entry(seq: u64, prev_id: Option<&str>) -> AuditEntry {
        AuditEntry {
            id: "placeholder".to_string(),
            event_type: event_types::CAPABILITY_INVOKE.to_string(),
            severity: Severity::Info,
            actor: "agent:alice".to_string(),
            zone_id: "z:work".to_string(),
            seq,
            occurred_at: 1_700_000_000 + seq * 60,
            hlc: audit_entry_hlc_from_occurred_at(1_700_000_000 + seq * 60, "agent:alice"),
            prev: prev_id.map(ToString::to_string),
            correlation_id: format!("corr-{seq}"),
            trace_context: None,
            connector_id: None,
            operation_id: None,
            metadata: BTreeMap::new(),
            issuer_kid: None,
            signature: None,
        }
    }

    #[test]
    fn sign_and_verify_signature_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let mut entry = signed_test_entry(0, None);
        entry.id = entry.computed_id().unwrap();
        entry.sign(&signing_key).expect("sign succeeds");

        assert!(entry.issuer_kid.is_some(), "issuer_kid populated");
        assert!(entry.signature.is_some(), "signature populated");
        assert_eq!(
            entry.issuer_kid.as_ref().unwrap().as_slice(),
            signing_key.key_id().as_slice(),
            "kid matches signing key"
        );

        entry
            .verify_signature(&verifying_key)
            .expect("self-issued signature must verify");
    }

    #[test]
    fn verify_signature_rejects_wrong_key() {
        let signing_key = Ed25519SigningKey::generate();
        let other_key = Ed25519SigningKey::generate();

        let mut entry = signed_test_entry(0, None);
        entry.id = entry.computed_id().unwrap();
        entry.sign(&signing_key).expect("sign succeeds");

        match entry.verify_signature(&other_key.verifying_key()) {
            Err(AuditError::SignatureInvalid { seq: 0 }) => {}
            other => panic!("expected SignatureInvalid for kid mismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_signature_rejects_tampered_actor() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let mut entry = signed_test_entry(0, None);
        entry.id = entry.computed_id().unwrap();
        entry.sign(&signing_key).expect("sign succeeds");

        // After signing, mutate the actor — `id` is no longer canonical
        // so `computed_id` (and thus `signing_bytes`) recomputes a
        // different transcript; the signature must fail verification.
        entry.actor = "agent:eve".to_string();
        match entry.verify_signature(&verifying_key) {
            Err(AuditError::SignatureInvalid { seq: 0 }) => {}
            other => panic!("expected SignatureInvalid after mutation, got {other:?}"),
        }
    }

    #[test]
    fn verify_signature_rejects_missing_fields() {
        let entry = signed_test_entry(0, None);
        let key = Ed25519SigningKey::generate().verifying_key();
        match entry.verify_signature(&key) {
            Err(AuditError::SignerMissing { seq: 0 }) => {}
            other => panic!("expected SignerMissing for unsigned entry, got {other:?}"),
        }
    }

    /// Regression for br-atd32: the new `signing_bytes_from_id` +
    /// `verify_signature_with_id` fast path must be byte-identical to
    /// the legacy `signing_bytes` + `verify_signature` path for a
    /// well-formed signed entry. This pins the perf refactor against
    /// accidental transcript drift.
    #[test]
    fn signing_bytes_from_id_matches_signing_bytes_for_signed_entry() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let mut entry = signed_test_entry(0, None);
        entry.id = entry.computed_id().unwrap();
        entry.sign(&signing_key).expect("sign succeeds");

        let canonical_id = entry.computed_id().expect("computed_id");
        let legacy_bytes = entry.signing_bytes().expect("signing_bytes");
        let fast_bytes = entry.signing_bytes_from_id(&canonical_id);
        assert_eq!(
            legacy_bytes, fast_bytes,
            "signing_bytes_from_id must produce byte-identical transcript to signing_bytes"
        );

        // Both verify paths must accept the legitimate signature.
        entry
            .verify_signature(&verifying_key)
            .expect("legacy verify ok");
        entry
            .verify_signature_with_id(&verifying_key, &canonical_id)
            .expect("fast-path verify ok");

        // And both must reject a wrong key (guard against accidental
        // skip-verify regressions in the fast path).
        let other_key = Ed25519SigningKey::generate().verifying_key();
        assert!(matches!(
            entry.verify_signature(&other_key),
            Err(AuditError::SignatureInvalid { .. })
        ));
        assert!(matches!(
            entry.verify_signature_with_id(&other_key, &canonical_id),
            Err(AuditError::SignatureInvalid { .. })
        ));
    }

    /// Regression for br-atd32: `verify_chain_with_precomputed_ids`
    /// must return the same `VerifyReport` as `verify_chain` for the
    /// same input. This pins the refactor so the precomputed-id public
    /// helper cannot silently diverge from the canonical path.
    #[test]
    fn verify_chain_with_precomputed_ids_matches_verify_chain() {
        let signing_key = Ed25519SigningKey::generate();

        let mut entries = Vec::new();
        let mut prev_id: Option<String> = None;
        for seq in 0..4 {
            let mut entry = signed_test_entry(seq, prev_id.as_deref());
            entry.id = entry.computed_id().unwrap();
            entry.sign(&signing_key).expect("sign succeeds");
            prev_id = Some(entry.id.clone());
            entries.push(entry);
        }

        let legacy = verify_chain(&entries, None, Some("z:work"));
        let precomputed: Vec<Result<String, AuditError>> =
            entries.iter().map(AuditEntry::computed_id).collect();
        let fast = verify_chain_with_precomputed_ids(&entries, None, Some("z:work"), &precomputed);

        assert_eq!(legacy.status, fast.status);
        assert_eq!(legacy.chain_len, fast.chain_len);
        assert_eq!(legacy.issues.len(), fast.issues.len());
        assert_eq!(legacy.zone_id, fast.zone_id);
    }

    #[test]
    fn verify_chain_with_signers_accepts_fully_signed_chain() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let kid = signing_key.key_id();

        // Build a 3-entry chain, sign each. Compute id BEFORE signing
        // so `signing_bytes` covers a stable id.
        let mut entries = Vec::new();
        let mut prev_id: Option<String> = None;
        for seq in 0..3 {
            let mut entry = signed_test_entry(seq, prev_id.as_deref());
            entry.id = entry.computed_id().unwrap();
            entry.sign(&signing_key).expect("sign succeeds");
            prev_id = Some(entry.id.clone());
            entries.push(entry);
        }

        let resolver = |looking: &KeyId| -> Option<Ed25519VerifyingKey> {
            if looking.as_slice() == kid.as_slice() {
                Some(verifying_key.clone())
            } else {
                None
            }
        };
        let report = verify_chain_with_signers(&entries, None, Some("z:work"), resolver)
            .expect("signed chain must verify");
        assert_eq!(report.chain_len, 3);
    }

    #[test]
    fn verify_chain_with_signers_rejects_unsigned_entry() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        // Build a chain where seq 0 is signed but seq 1 is NOT — exactly
        // the forgery scenario the bead describes.
        let mut e0 = signed_test_entry(0, None);
        e0.id = e0.computed_id().unwrap();
        e0.sign(&signing_key).expect("sign genesis");

        let mut e1 = signed_test_entry(1, Some(&e0.id));
        e1.id = e1.computed_id().unwrap();
        // intentionally do NOT sign e1

        let entries = vec![e0, e1];
        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        match verify_chain_with_signers(&entries, None, Some("z:work"), resolver) {
            Err(AuditError::SignerMissing { seq: 1 }) => {}
            other => panic!("expected SignerMissing at seq 1, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_with_signers_rejects_unknown_issuer() {
        let signing_key = Ed25519SigningKey::generate();

        let mut entry = signed_test_entry(0, None);
        entry.id = entry.computed_id().unwrap();
        entry.sign(&signing_key).expect("sign");

        let entries = vec![entry];
        let resolver = |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { None };
        match verify_chain_with_signers(&entries, None, Some("z:work"), resolver) {
            Err(AuditError::UnknownIssuer { seq: 0 }) => {}
            other => panic!("expected UnknownIssuer, got {other:?}"),
        }
    }

    // ── br-ax97w: ChainHead quorum signatures are verified too ────

    fn signed_chain_and_head(signing_key: &Ed25519SigningKey) -> (Vec<AuditEntry>, ChainHead) {
        let mut entries = Vec::new();
        let mut prev_id: Option<String> = None;
        for seq in 0..2 {
            let mut entry = signed_test_entry(seq, prev_id.as_deref());
            entry.id = entry.computed_id().unwrap();
            entry.sign(signing_key).expect("sign");
            prev_id = Some(entry.id.clone());
            entries.push(entry);
        }
        let tip = entries.last().unwrap().clone();
        let head = ChainHead {
            zone_id: tip.zone_id.clone(),
            head_entry: tip.id.clone(),
            head_seq: tip.seq,
            coverage: 1.0,
            epoch_id: "epoch-ax97w".to_string(),
            signature_count: 1,
            signatures: Vec::new(),
        };
        (entries, head)
    }

    fn sign_head(head: &mut ChainHead, signing_key: &Ed25519SigningKey) {
        let transcript = head.signing_bytes();
        let signature = signing_key.sign(&transcript);
        head.signatures = vec![HeadSignature {
            issuer_kid: signing_key.key_id().to_hex(),
            signature: signature.to_bytes().to_vec(),
        }];
        head.signature_count = 1;
    }

    #[test]
    fn verify_chain_with_signers_accepts_signed_head() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let (entries, mut head) = signed_chain_and_head(&signing_key);
        sign_head(&mut head, &signing_key);

        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        let report = verify_chain_with_signers(&entries, Some(&head), Some("z:work"), resolver)
            .expect("properly-signed head must verify");
        assert_eq!(report.chain_len, entries.len());
    }

    #[test]
    fn verify_chain_with_signers_rejects_head_with_no_signatures() {
        // The bead scenario: an attacker-tampered head with
        // signature_count claimed but signatures list emptied out.
        // Old behavior: verify_chain_with_signers returned Ok(report).
        // New behavior (eah6j): EmptySignedHead at head_seq.
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let (entries, head) = signed_chain_and_head(&signing_key);
        // head.signatures intentionally left empty even though
        // signature_count = 1. This is the canonical tamper payload.
        assert_eq!(head.signatures, [] as [HeadSignature; 0]);
        assert_eq!(head.signature_count, 1);

        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        let result = verify_chain_with_signers(&entries, Some(&head), Some("z:work"), resolver);
        assert!(
            matches!(result, Err(AuditError::EmptySignedHead { .. })),
            "expected EmptySignedHead for unsigned head, got {result:?}"
        );
    }

    #[test]
    fn verify_chain_with_signers_rejects_head_with_empty_signature_bytes() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let (entries, mut head) = signed_chain_and_head(&signing_key);
        head.signatures = vec![HeadSignature {
            issuer_kid: signing_key.key_id().to_hex(),
            signature: Vec::new(),
        }];
        head.signature_count = 1;

        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        let result = verify_chain_with_signers(&entries, Some(&head), Some("z:work"), resolver);
        assert!(
            matches!(result, Err(AuditError::EmptySignedHead { .. })),
            "expected EmptySignedHead for empty head signature, got {result:?}"
        );
    }

    #[test]
    fn verify_signatures_rejects_duplicate_signer_inflating_quorum() {
        // A single key must not satisfy an N-signer quorum by attaching the
        // same valid signature N times: `verify_signatures` must reject the
        // repeated signer, and `has_quorum` must not treat duplicate kids as a
        // quorum.
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let (_entries, mut head) = signed_chain_and_head(&signing_key);

        // Set signature_count BEFORE computing the transcript: signing_bytes()
        // commits to signature_count, so the signature must be over the count
        // the verifier will recompute, otherwise SignatureInvalid fires first
        // and masks the distinctness check under test.
        head.signature_count = 3;

        // One key signs the transcript; the same (kid, signature) is attached
        // three times to fake a 3-signer quorum.
        let transcript = head.signing_bytes();
        let signature = signing_key.sign(&transcript);
        let entry = HeadSignature {
            issuer_kid: signing_key.key_id().to_hex(),
            signature: signature.to_bytes().to_vec(),
        };
        head.signatures = vec![entry.clone(), entry.clone(), entry];

        // Every individual signature is cryptographically valid, so the only
        // thing standing between this and a forged quorum is the distinctness
        // check.
        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        let result = head.verify_signatures(&resolver);
        assert!(
            matches!(result, Err(AuditError::DuplicateSigner { .. })),
            "duplicate signer must be rejected, got {result:?}"
        );

        // Structural check (no crypto) must also refuse duplicate issuer_kids.
        assert!(
            !head.has_quorum(),
            "has_quorum must not count repeated signers as a quorum"
        );

        // A genuinely distinct set of signers still verifies and has quorum.
        let key_b = Ed25519SigningKey::generate();
        let key_c = Ed25519SigningKey::generate();
        head.signatures = vec![
            HeadSignature {
                issuer_kid: signing_key.key_id().to_hex(),
                signature: signing_key.sign(&transcript).to_bytes().to_vec(),
            },
            HeadSignature {
                issuer_kid: key_b.key_id().to_hex(),
                signature: key_b.sign(&transcript).to_bytes().to_vec(),
            },
            HeadSignature {
                issuer_kid: key_c.key_id().to_hex(),
                signature: key_c.sign(&transcript).to_bytes().to_vec(),
            },
        ];
        head.signature_count = 3;
        let multi = std::collections::HashMap::from([
            (signing_key.key_id().to_hex(), verifying_key.clone()),
            (key_b.key_id().to_hex(), key_b.verifying_key()),
            (key_c.key_id().to_hex(), key_c.verifying_key()),
        ]);
        let multi_resolver =
            |kid: &KeyId| -> Option<Ed25519VerifyingKey> { multi.get(&kid.to_hex()).cloned() };
        head.verify_signatures(&multi_resolver)
            .expect("three distinct signers must verify");
        assert!(head.has_quorum(), "three distinct signers form a quorum");
    }

    #[test]
    fn verify_chain_with_signers_rejects_head_signature_below_length_floor() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let (entries, mut head) = signed_chain_and_head(&signing_key);
        head.signatures = vec![HeadSignature {
            issuer_kid: signing_key.key_id().to_hex(),
            signature: vec![0xAA; ED25519_SIGNATURE_SIZE - 1],
        }];
        head.signature_count = 1;

        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        let result = verify_chain_with_signers(&entries, Some(&head), Some("z:work"), resolver);
        assert!(
            matches!(result, Err(AuditError::SignatureInvalid { .. })),
            "expected SignatureInvalid for short head signature, got {result:?}"
        );
    }

    #[test]
    fn verify_chain_with_required_signed_head_rejects_missing_head() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let (entries, _head) = signed_chain_and_head(&signing_key);

        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        let result =
            verify_chain_with_required_signed_head(&entries, None, Some("z:work"), resolver);
        assert!(
            matches!(result, Err(AuditError::EmptySignedHead { .. })),
            "expected EmptySignedHead for missing signed head, got {result:?}"
        );
    }

    #[test]
    fn verify_chain_with_required_signed_head_rejects_empty_chain() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let (_entries, mut head) = signed_chain_and_head(&signing_key);
        sign_head(&mut head, &signing_key);

        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        let result =
            verify_chain_with_required_signed_head(&[], Some(&head), Some("z:work"), resolver);
        assert!(
            matches!(result, Err(AuditError::VerificationFailed(ref message)) if message.contains("non-empty audit chain")),
            "expected VerificationFailed for empty signed chain, got {result:?}"
        );
    }

    #[test]
    fn verify_chain_with_signers_rejects_head_with_forged_signature_bytes() {
        // Attacker keeps signature_count consistent and a signature
        // entry present, but fills the bytes with garbage. Must fail
        // closed at the Ed25519 verify step.
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let (entries, mut head) = signed_chain_and_head(&signing_key);
        head.signatures = vec![HeadSignature {
            issuer_kid: signing_key.key_id().to_hex(),
            signature: vec![0xAA; 64],
        }];
        head.signature_count = 1;

        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        match verify_chain_with_signers(&entries, Some(&head), Some("z:work"), resolver) {
            Err(AuditError::SignatureInvalid { .. }) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_with_signers_rejects_head_coverage_tamper_from_out_of_range_to_in_range() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let (entries, mut head) = signed_chain_and_head(&signing_key);
        head.coverage = 1.5;
        sign_head(&mut head, &signing_key);

        let mut tampered = head.clone();
        tampered.coverage = 1.0;

        let resolver =
            |_kid: &KeyId| -> Option<Ed25519VerifyingKey> { Some(verifying_key.clone()) };
        match verify_chain_with_signers(&entries, Some(&tampered), Some("z:work"), resolver) {
            Err(AuditError::SignatureInvalid { .. }) => {}
            other => panic!("expected SignatureInvalid after coverage retargeting, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_with_signers_rejects_head_signed_by_unknown_issuer() {
        // head signed by a rotating-out issuer whose kid is not in
        // the resolver map. Must surface UnknownIssuer.
        let trusted = Ed25519SigningKey::generate();
        let rotated_out = Ed25519SigningKey::generate();
        let trusted_vk = trusted.verifying_key();
        let trusted_kid = trusted.key_id();
        let (entries, mut head) = signed_chain_and_head(&trusted);
        sign_head(&mut head, &rotated_out);

        let resolver = |looking: &KeyId| -> Option<Ed25519VerifyingKey> {
            if looking.as_slice() == trusted_kid.as_slice() {
                Some(trusted_vk.clone())
            } else {
                None
            }
        };
        match verify_chain_with_signers(&entries, Some(&head), Some("z:work"), resolver) {
            Err(AuditError::UnknownIssuer { .. }) => {}
            other => panic!("expected UnknownIssuer, got {other:?}"),
        }
    }

    #[test]
    fn chain_head_signing_bytes_changes_on_any_covered_field_tamper() {
        let (_, head) = signed_chain_and_head(&Ed25519SigningKey::generate());
        let baseline = head.signing_bytes();
        let mut tampered_zone = head.clone();
        tampered_zone.zone_id = "z:attacker".into();
        assert_ne!(tampered_zone.signing_bytes(), baseline);
        let mut tampered_seq = head.clone();
        tampered_seq.head_seq = tampered_seq.head_seq.wrapping_add(1);
        assert_ne!(tampered_seq.signing_bytes(), baseline);
        let mut tampered_coverage = head.clone();
        tampered_coverage.coverage = 0.5;
        assert_ne!(tampered_coverage.signing_bytes(), baseline);
        let mut tampered_count = head.clone();
        tampered_count.signature_count = tampered_count.signature_count.wrapping_add(1);
        assert_ne!(tampered_count.signing_bytes(), baseline);
        let mut tampered_epoch = head.clone();
        tampered_epoch.epoch_id = "epoch-drift".into();
        assert_ne!(tampered_epoch.signing_bytes(), baseline);
        let mut tampered_entry = head;
        tampered_entry.head_entry = "forged-tip".into();
        assert_ne!(tampered_entry.signing_bytes(), baseline);
    }

    #[test]
    fn chain_head_signing_bytes_distinguish_out_of_range_coverage_from_clamped_in_range_value() {
        let (_, mut head) = signed_chain_and_head(&Ed25519SigningKey::generate());
        head.coverage = 1.5;
        let out_of_range = head.signing_bytes();
        head.coverage = 1.0;
        let in_range = head.signing_bytes();
        assert_ne!(out_of_range, in_range);
    }

    // ── AuditEntryBuilder ────────────────────────────────────────────────

    #[test]
    fn builder_basic() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::CAPABILITY_INVOKE)
            .actor("user:alice")
            .zone_id("z:work")
            .seq(0)
            .occurred_at(1_700_000_000)
            .build()
            .unwrap();

        assert_eq!(entry.id, "e-1");
        assert_eq!(entry.event_type, event_types::CAPABILITY_INVOKE);
        assert!(entry.is_genesis());
        // Severity auto-computed
        assert_eq!(entry.severity, Severity::Info);
        assert_eq!(
            entry.hlc,
            audit_entry_hlc_from_occurred_at(1_700_000_000, "user:alice")
        );
    }

    #[test]
    fn builder_build_with_computed_id_sets_canonical_id() -> Result<(), AuditError> {
        let entry = AuditEntryBuilder::new()
            .event_type(event_types::CAPABILITY_INVOKE)
            .actor("user:alice")
            .zone_id("z:work")
            .seq(0)
            .occurred_at(1_700_000_000)
            .build_with_computed_id()?;

        let recomputed = entry.computed_id()?;
        assert_eq!(entry.id, recomputed);
        assert_ne!(entry.id, "__provisional__");
        Ok(())
    }

    #[test]
    fn borrowed_audit_entry_id_fields_match_entry_computed_id() -> Result<(), AuditError> {
        let trace_context = TraceContext::new("trace-id", "span-id").with_flags(1);
        let entry = AuditEntryBuilder::new()
            .event_type(event_types::CAPABILITY_INVOKE)
            .severity(Severity::Warning)
            .actor("user:alice")
            .zone_id("z:work")
            .seq(7)
            .occurred_at(1_700_000_007)
            .prev("prev-entry")
            .correlation_id("corr-7")
            .trace_context(trace_context)
            .connector_id("github")
            .operation_id("list_repos")
            .meta("operation", serde_json::json!("list_repos"))
            .meta("success", serde_json::json!(true))
            .build_with_computed_id()?;

        let borrowed = compute_audit_entry_id(AuditEntryIdFields {
            event_type: &entry.event_type,
            severity: entry.severity,
            actor: &entry.actor,
            zone_id: &entry.zone_id,
            seq: entry.seq,
            occurred_at: entry.occurred_at,
            hlc: &entry.hlc,
            prev: entry.prev.as_deref(),
            correlation_id: &entry.correlation_id,
            trace_context: entry.trace_context.as_ref(),
            connector_id: entry.connector_id.as_deref(),
            operation_id: entry.operation_id.as_deref(),
            metadata: &entry.metadata,
        })?;

        assert_eq!(borrowed, entry.computed_id()?);
        assert_eq!(borrowed, entry.id);
        Ok(())
    }

    #[test]
    fn builder_with_all_fields() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::SECRET_ACCESS)
            .severity(Severity::Critical)
            .actor("user:bob")
            .zone_id("z:prod")
            .seq(5)
            .occurred_at(1_700_000_300)
            .prev("e-0")
            .correlation_id("corr-5")
            .trace_context(TraceContext::new("tid", "sid"))
            .connector_id("fcp.slack:base:v1")
            .operation_id("send")
            .meta("key1", serde_json::json!(42))
            .build()
            .unwrap();

        assert_eq!(entry.severity, Severity::Critical); // explicit override
        assert_eq!(entry.prev, Some("e-0".to_string()));
        assert!(entry.trace_context.is_some());
        assert_eq!(entry.connector_id, Some("fcp.slack:base:v1".to_string()));
        assert_eq!(entry.operation_id, Some("send".to_string()));
        assert_eq!(entry.metadata.get("key1"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn builder_missing_id() {
        let result = AuditEntryBuilder::new()
            .event_type("test")
            .actor("alice")
            .zone_id("z:w")
            .seq(0)
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("id"));
    }

    #[test]
    fn builder_missing_event_type() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .actor("alice")
            .zone_id("z:w")
            .seq(0)
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("event_type"));
    }

    #[test]
    fn builder_missing_actor() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .zone_id("z:w")
            .seq(0)
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("actor"));
    }

    #[test]
    fn builder_missing_zone_id() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("alice")
            .seq(0)
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("zone_id"));
    }

    #[test]
    fn builder_missing_seq() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("alice")
            .zone_id("z:w")
            .occurred_at(0)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("seq"));
    }

    #[test]
    fn builder_missing_occurred_at() {
        let result = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("alice")
            .zone_id("z:w")
            .seq(0)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("occurred_at"));
    }

    #[test]
    fn builder_auto_severity() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::AUDIT_FORK_DETECTED)
            .actor("system")
            .zone_id("z:w")
            .seq(0)
            .occurred_at(0)
            .build()
            .unwrap();
        assert_eq!(entry.severity, Severity::Critical);
    }

    #[test]
    fn builder_default() {
        let builder = AuditEntryBuilder::default();
        let debug = format!("{builder:?}");
        assert!(debug.contains("AuditEntryBuilder"));
    }

    #[test]
    fn builder_clone() {
        let builder = AuditEntryBuilder::new().id("e-1").event_type("test");
        let cloned = builder.clone();
        let debug_orig = format!("{builder:?}");
        let debug_clone = format!("{cloned:?}");
        assert_eq!(debug_orig, debug_clone);
    }

    // ── ChainHead ────────────────────────────────────────────────────────

    #[test]
    fn chain_head_meets_coverage() {
        let head = sample_head("entry-5", 5);
        assert!(head.meets_coverage(0.80));
        assert!(head.meets_coverage(0.85));
        assert!(!head.meets_coverage(0.90));
    }

    #[test]
    fn chain_head_has_quorum() {
        let head = sample_head("entry-5", 5);
        assert!(head.has_quorum());
        assert!(head.signature_count_consistent());

        // Count cleared but signatures still present → inconsistent → no quorum.
        let mut no_quorum = sample_head("entry-5", 5);
        no_quorum.signature_count = 0;
        assert!(!no_quorum.has_quorum());
        assert!(!no_quorum.signature_count_consistent());

        // Signatures cleared but count still 3 → inconsistent → no quorum.
        let mut no_sigs = sample_head("entry-5", 5);
        no_sigs.signatures.clear();
        assert!(!no_sigs.has_quorum());
        assert!(!no_sigs.signature_count_consistent());

        // The original bug: numeric count > 0 with no signatures attached
        // MUST NOT be treated as quorum. Before this fix,
        // `has_quorum() == true` would be returned on a producer-asserted
        // bare count.
        let forged = ChainHead {
            zone_id: "z:work".to_string(),
            head_entry: "forged".to_string(),
            head_seq: 5,
            coverage: 1.0,
            epoch_id: "epoch-forged".to_string(),
            signature_count: 7,
            signatures: vec![],
        };
        assert!(
            !forged.has_quorum(),
            "quorum cannot be asserted from a bare count"
        );

        // Legacy wire: omitted signatures default to empty; regardless of
        // count, has_quorum returns false on decoded legacy heads.
        let legacy_json = r#"{"zone_id":"z:work","head_entry":"e","head_seq":0,"coverage":1.0,"epoch_id":"ep","signature_count":3}"#;
        let legacy: ChainHead = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(legacy.signatures, [] as [HeadSignature; 0]);
        assert!(!legacy.has_quorum());
        assert!(!legacy.signature_count_consistent());
    }

    #[test]
    fn chain_head_display() {
        let head = sample_head("entry-5", 5);
        let display = head.to_string();
        assert!(display.contains("z:work"));
        assert!(display.contains("seq=5"));
        assert!(display.contains("85.0%"));
    }

    #[test]
    fn chain_head_serde_roundtrip() {
        let head = sample_head("entry-5", 5);
        let json = serde_json::to_string(&head).unwrap();
        let parsed: ChainHead = serde_json::from_str(&json).unwrap();
        assert_eq!(head, parsed);
    }

    #[test]
    fn chain_head_clone() {
        let head = sample_head("entry-5", 5);
        let cloned = head.clone();
        assert_eq!(head.head_seq, cloned.head_seq);
        assert_eq!(head.zone_id, cloned.zone_id);
    }

    #[test]
    fn chain_head_debug() {
        let head = sample_head("entry-5", 5);
        let debug = format!("{head:?}");
        assert!(debug.contains("ChainHead"));
    }

    #[test]
    fn chain_head_zero_coverage() {
        let mut head = sample_head("entry-5", 5);
        head.coverage = 0.0;
        assert!(!head.meets_coverage(0.1));
        assert!(head.meets_coverage(0.0));
    }

    #[test]
    fn chain_head_full_coverage() {
        let mut head = sample_head("entry-5", 5);
        head.coverage = 1.0;
        assert!(head.meets_coverage(1.0));
    }

    // ── Decision ─────────────────────────────────────────────────────────

    #[test]
    fn decision_is_allow() {
        assert!(Decision::Allow.is_allow());
        assert!(!Decision::Allow.is_deny());
    }

    #[test]
    fn decision_is_deny() {
        assert!(Decision::Deny.is_deny());
        assert!(!Decision::Deny.is_allow());
    }

    #[test]
    fn decision_display() {
        assert_eq!(Decision::Allow.to_string(), "allow");
        assert_eq!(Decision::Deny.to_string(), "deny");
    }

    #[test]
    fn decision_serde_roundtrip() {
        for d in [Decision::Allow, Decision::Deny] {
            let json = serde_json::to_string(&d).unwrap();
            let parsed: Decision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, parsed);
        }
    }

    #[test]
    fn decision_serde_values() {
        assert_eq!(
            serde_json::to_string(&Decision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(serde_json::to_string(&Decision::Deny).unwrap(), "\"deny\"");
    }

    #[test]
    fn decision_clone() {
        let d = Decision::Allow;
        let copied = d;
        assert_eq!(d, copied);
    }

    #[test]
    fn decision_copy() {
        let d = Decision::Deny;
        let copied = d;
        assert_eq!(d, copied);
    }

    #[test]
    fn decision_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Decision::Allow);
        set.insert(Decision::Deny);
        set.insert(Decision::Allow);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn decision_debug() {
        assert_eq!(format!("{:?}", Decision::Allow), "Allow");
        assert_eq!(format!("{:?}", Decision::Deny), "Deny");
    }

    // ── DecisionReceipt ──────────────────────────────────────────────────

    #[test]
    fn receipt_is_allow() {
        let receipt = sample_receipt();
        assert!(receipt.is_allow());
        assert!(!receipt.is_deny());
    }

    #[test]
    fn receipt_is_deny() {
        let mut receipt = sample_receipt();
        receipt.decision = Decision::Deny;
        assert!(receipt.is_deny());
        assert!(!receipt.is_allow());
    }

    #[test]
    fn receipt_has_explanation() {
        let receipt = sample_receipt();
        assert!(receipt.has_explanation());

        let mut no_exp = sample_receipt();
        no_exp.explanation = None;
        assert!(!no_exp.has_explanation());
    }

    #[test]
    fn receipt_evidence_count() {
        let receipt = sample_receipt();
        assert_eq!(receipt.evidence_count(), 2);

        let mut no_ev = sample_receipt();
        no_ev.evidence.clear();
        assert_eq!(no_ev.evidence_count(), 0);
    }

    #[test]
    fn receipt_display() {
        let receipt = sample_receipt();
        let display = receipt.to_string();
        assert!(display.contains("receipt-1"));
        assert!(display.contains("allow"));
        assert!(display.contains("req-1"));
        assert!(display.contains("policy.match"));
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn receipt_serde_skips_none_explanation() {
        let mut receipt = sample_receipt();
        receipt.explanation = None;
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("explanation"));
    }

    #[test]
    fn receipt_serde_skips_empty_evidence() {
        let mut receipt = sample_receipt();
        receipt.evidence.clear();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("evidence"));
    }

    #[test]
    fn receipt_clone() {
        let receipt = sample_receipt();
        let cloned = receipt.clone();
        assert_eq!(receipt.id, cloned.id);
        assert_eq!(receipt.decision, cloned.decision);
    }

    #[test]
    fn receipt_debug() {
        let receipt = sample_receipt();
        let debug = format!("{receipt:?}");
        assert!(debug.contains("DecisionReceipt"));
    }

    // ── AuditFilter ──────────────────────────────────────────────────────

    #[test]
    fn filter_default_is_empty() {
        let filter = AuditFilter::default();
        assert!(filter.is_empty());
        assert_eq!(filter.active_count(), 0);
    }

    #[test]
    fn filter_matches_all_when_empty() {
        let filter = AuditFilter::default();
        let entry = genesis_entry();
        assert!(filter.matches(&entry));
    }

    #[test]
    fn filter_connector_id() {
        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            ..Default::default()
        };
        let entry = genesis_entry();
        assert!(filter.matches(&entry));

        let filter_wrong = AuditFilter {
            connector_id: Some("fcp.slack:base:v1".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&entry));
    }

    #[test]
    fn filter_connector_id_none_entry() {
        let filter = AuditFilter {
            connector_id: Some("any".to_string()),
            ..Default::default()
        };
        let mut entry = genesis_entry();
        entry.connector_id = None;
        assert!(!filter.matches(&entry));
    }

    #[test]
    fn filter_operation_id() {
        let filter = AuditFilter {
            operation_id: Some("send_message".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            operation_id: Some("other_op".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_correlation_id() {
        let filter = AuditFilter {
            correlation_id: Some("corr-0".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            correlation_id: Some("corr-999".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_trace_id() {
        let filter = AuditFilter {
            trace_id: Some("trace-abc".to_string()),
            ..Default::default()
        };
        // No trace context on genesis => no match
        assert!(!filter.matches(&genesis_entry()));

        let mut entry = genesis_entry();
        entry.trace_context = Some(TraceContext::new("trace-abc", "span-def"));
        assert!(filter.matches(&entry));
    }

    #[test]
    fn filter_event_type() {
        let filter = AuditFilter {
            event_type: Some(event_types::CAPABILITY_INVOKE.to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            event_type: Some(event_types::SECRET_ACCESS.to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_actor() {
        let filter = AuditFilter {
            actor: Some("user:alice".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            actor: Some("user:bob".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_min_severity() {
        let filter = AuditFilter {
            min_severity: Some(Severity::Warning),
            ..Default::default()
        };
        // Genesis entry is Info severity
        assert!(!filter.matches(&genesis_entry()));

        let mut entry = genesis_entry();
        entry.severity = Severity::Error;
        assert!(filter.matches(&entry));
    }

    #[test]
    fn filter_zone_id() {
        let filter = AuditFilter {
            zone_id: Some("z:work".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));

        let filter_wrong = AuditFilter {
            zone_id: Some("z:prod".to_string()),
            ..Default::default()
        };
        assert!(!filter_wrong.matches(&genesis_entry()));
    }

    #[test]
    fn filter_multiple_fields() {
        let filter = AuditFilter {
            actor: Some("user:alice".to_string()),
            event_type: Some(event_types::CAPABILITY_INVOKE.to_string()),
            zone_id: Some("z:work".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&genesis_entry()));
        assert_eq!(filter.active_count(), 3);
        assert!(!filter.is_empty());
    }

    #[test]
    fn filter_active_count_all() {
        let filter = AuditFilter {
            connector_id: Some("c".to_string()),
            operation_id: Some("o".to_string()),
            correlation_id: Some("corr".to_string()),
            trace_id: Some("t".to_string()),
            event_type: Some("e".to_string()),
            actor: Some("a".to_string()),
            min_severity: Some(Severity::Info),
            zone_id: Some("z".to_string()),
        };
        assert_eq!(filter.active_count(), 8);
    }

    #[test]
    fn filter_display_empty() {
        let filter = AuditFilter::default();
        assert_eq!(filter.to_string(), "AuditFilter(none)");
    }

    #[test]
    fn filter_display_active() {
        let filter = AuditFilter {
            actor: Some("alice".to_string()),
            ..Default::default()
        };
        assert_eq!(filter.to_string(), "AuditFilter(1 active)");
    }

    #[test]
    fn filter_serde_roundtrip() {
        let filter = AuditFilter {
            connector_id: Some("c".to_string()),
            actor: Some("a".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&filter).unwrap();
        let parsed: AuditFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(filter, parsed);
    }

    #[test]
    fn filter_serde_skips_none() {
        let filter = AuditFilter::default();
        let json = serde_json::to_string(&filter).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn filter_clone() {
        let filter = AuditFilter {
            actor: Some("alice".to_string()),
            ..Default::default()
        };
        let cloned = filter.clone();
        assert_eq!(filter, cloned);
    }

    #[test]
    fn filter_debug() {
        let filter = AuditFilter::default();
        let debug = format!("{filter:?}");
        assert!(debug.contains("AuditFilter"));
    }

    // ── VerifyStatus ─────────────────────────────────────────────────────

    #[test]
    fn verify_status_is_ok() {
        assert!(VerifyStatus::Ok.is_ok());
        assert!(!VerifyStatus::Warn.is_ok());
        assert!(!VerifyStatus::Fail.is_ok());
    }

    #[test]
    fn verify_status_is_fail() {
        assert!(VerifyStatus::Fail.is_fail());
        assert!(!VerifyStatus::Ok.is_fail());
        assert!(!VerifyStatus::Warn.is_fail());
    }

    #[test]
    fn verify_status_default() {
        assert_eq!(VerifyStatus::default(), VerifyStatus::Ok);
    }

    #[test]
    fn verify_status_display() {
        assert_eq!(VerifyStatus::Ok.to_string(), "ok");
        assert_eq!(VerifyStatus::Warn.to_string(), "warn");
        assert_eq!(VerifyStatus::Fail.to_string(), "fail");
    }

    #[test]
    fn verify_status_serde_roundtrip() {
        for s in [VerifyStatus::Ok, VerifyStatus::Warn, VerifyStatus::Fail] {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: VerifyStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, parsed);
        }
    }

    #[test]
    fn verify_status_serde_values() {
        assert_eq!(serde_json::to_string(&VerifyStatus::Ok).unwrap(), "\"ok\"");
        assert_eq!(
            serde_json::to_string(&VerifyStatus::Warn).unwrap(),
            "\"warn\""
        );
        assert_eq!(
            serde_json::to_string(&VerifyStatus::Fail).unwrap(),
            "\"fail\""
        );
    }

    #[test]
    fn verify_status_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VerifyStatus::Ok);
        set.insert(VerifyStatus::Warn);
        set.insert(VerifyStatus::Ok);
        assert_eq!(set.len(), 2);
    }

    // ── VerifyIssue ──────────────────────────────────────────────────────

    #[test]
    fn verify_issue_new() {
        let issue = VerifyIssue::new("audit.test", "test message");
        assert_eq!(issue.code, "audit.test");
        assert_eq!(issue.message, "test message");
        assert!(issue.seq.is_none());
        assert!(issue.entry_id.is_none());
    }

    #[test]
    fn verify_issue_with_seq() {
        let issue = VerifyIssue::new("audit.test", "msg").with_seq(42);
        assert_eq!(issue.seq, Some(42));
    }

    #[test]
    fn verify_issue_with_entry_id() {
        let issue = VerifyIssue::new("audit.test", "msg").with_entry_id("entry-5");
        assert_eq!(issue.entry_id, Some("entry-5".to_string()));
    }

    #[test]
    fn verify_issue_chained_builders() {
        let issue = VerifyIssue::new("audit.test", "msg")
            .with_seq(10)
            .with_entry_id("e-10");
        assert_eq!(issue.seq, Some(10));
        assert_eq!(issue.entry_id, Some("e-10".to_string()));
    }

    #[test]
    fn verify_issue_is_critical_true() {
        let critical_codes = [
            "audit.fork_detected",
            "audit.object_id_mismatch",
            "audit.object_id_unverifiable",
            "audit.chain.empty",
            "audit.prev_mismatch",
            "audit.seq_gap",
            "audit.genesis_invalid",
            "audit.head_mismatch",
            "audit.head_seq_mismatch",
        ];
        for code in critical_codes {
            let issue = VerifyIssue::new(code, "msg");
            assert!(issue.is_critical(), "{code} should be critical");
        }
    }

    #[test]
    fn verify_issue_is_critical_false() {
        let non_critical = ["audit.zone_mismatch", "custom.issue"];
        for code in non_critical {
            let issue = VerifyIssue::new(code, "msg");
            assert!(!issue.is_critical(), "{code} should not be critical");
        }
    }

    #[test]
    fn verify_issue_display() {
        let issue = VerifyIssue::new("audit.test", "something went wrong");
        assert_eq!(issue.to_string(), "audit.test: something went wrong");
    }

    #[test]
    fn verify_issue_serde_roundtrip() {
        let issue = VerifyIssue::new("audit.test", "msg")
            .with_seq(5)
            .with_entry_id("e-5");
        let json = serde_json::to_string(&issue).unwrap();
        let parsed: VerifyIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(issue, parsed);
    }

    #[test]
    fn verify_issue_serde_skips_none() {
        let issue = VerifyIssue::new("audit.test", "msg");
        let json = serde_json::to_string(&issue).unwrap();
        assert!(!json.contains("seq"));
        assert!(!json.contains("entry_id"));
    }

    #[test]
    fn verify_issue_clone() {
        let issue = VerifyIssue::new("code", "msg").with_seq(1);
        let cloned = issue.clone();
        assert_eq!(issue, cloned);
    }

    // ── VerifyReport ─────────────────────────────────────────────────────

    #[test]
    fn verify_report_ok() {
        let report = VerifyReport::ok(10);
        assert!(report.is_clean());
        assert_eq!(report.chain_len, 10);
        assert_eq!(report.status, VerifyStatus::Ok);
        assert_eq!(report.critical_count(), 0);
    }

    #[test]
    fn verify_report_critical_count() {
        let mut report = VerifyReport::ok(5);
        report.issues.push(VerifyIssue::new("audit.seq_gap", "gap"));
        report
            .issues
            .push(VerifyIssue::new("audit.zone_mismatch", "zone"));
        report
            .issues
            .push(VerifyIssue::new("audit.fork_detected", "fork"));
        assert_eq!(report.critical_count(), 2);
    }

    #[test]
    fn verify_report_display() {
        let report = VerifyReport::ok(5);
        let display = report.to_string();
        assert!(display.contains("ok"));
        assert!(display.contains("chain_len=5"));
        assert!(display.contains("issues=0"));
    }

    #[test]
    fn verify_report_serde_roundtrip() {
        let mut report = VerifyReport::ok(3);
        report.zone_id = Some("z:work".to_string());
        report.head_seq = Some(2);
        report.head_entry = Some("entry-2".to_string());
        let json = serde_json::to_string(&report).unwrap();
        let parsed: VerifyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
    }

    #[test]
    fn verify_report_serde_skips_none() {
        let report = VerifyReport::ok(0);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("zone_id"));
        assert!(!json.contains("head_seq"));
        assert!(!json.contains("head_entry"));
    }

    #[test]
    fn verify_report_clone() {
        let report = VerifyReport::ok(5);
        let cloned = report.clone();
        assert_eq!(report, cloned);
    }

    // ── verify_chain function ────────────────────────────────────────────

    #[test]
    fn verify_chain_empty() {
        let report = verify_chain(&[], None, None);
        assert!(report.status.is_ok());
        assert_eq!(report.chain_len, 0);
        assert!(report.is_clean());
    }

    #[test]
    fn verify_chain_empty_with_head() {
        let head = sample_head("entry-0", 0);
        let report = verify_chain(&[], Some(&head), None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(!report.is_clean());
        assert_eq!(report.critical_count(), 1);
        assert_eq!(report.issues[0].code, "audit.chain.empty");
    }

    #[test]
    fn verify_chain_valid_single() {
        let entries = [genesis_entry()];
        let report = verify_chain(&entries, None, None);
        assert!(report.status.is_ok());
        assert_eq!(report.chain_len, 1);
    }

    #[test]
    fn verify_chain_valid_three_entries() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let e2 = chain_entry(2, "entry-1");
        let entries = [e0, e1, e2];
        let report = verify_chain(&entries, None, None);
        assert!(report.status.is_ok());
        assert_eq!(report.chain_len, 3);
    }

    #[test]
    fn verify_chain_flags_head_signature_count_inconsistent() {
        // Producer claims signature_count=7 but attached zero signatures.
        // verify_chain MUST flag this as critical so downstream trust
        // decisions can't proceed on the bare numeric claim.
        let entries = canonical_chain_in_zone(2, "z:work");
        let last = entries.last().unwrap();
        let forged_head = ChainHead {
            zone_id: "z:work".to_string(),
            head_entry: last.id.clone(),
            head_seq: last.seq,
            coverage: 1.0,
            epoch_id: "epoch-forged".to_string(),
            signature_count: 7,
            signatures: vec![],
        };
        let report = verify_chain(&entries, Some(&forged_head), None);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_signature_count_inconsistent"),
            "expected head_signature_count_inconsistent, got {:?}",
            report.issues
        );
        assert!(
            report.status.is_fail(),
            "inconsistent count must be a critical failure"
        );
    }

    #[test]
    fn verify_chain_accepts_consistent_signed_head() {
        // Count matches signatures attached → no inconsistency issue.
        let entries = canonical_chain_in_zone(2, "z:work");
        let head = chain_head_for(&entries, "z:work");
        assert_eq!(
            usize::try_from(head.signature_count).unwrap(),
            head.signatures.len()
        );
        let report = verify_chain(&entries, Some(&head), None);
        assert!(
            !report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_signature_count_inconsistent"),
            "consistent head must not emit inconsistent-count issue"
        );
    }

    #[test]
    fn verify_chain_with_clock_flags_far_future_entry() {
        // Entry stamped 1 hour ahead of now+skew ceiling → critical issue.
        let now: u64 = 1_700_000_000;
        let future_ts = now + MAX_FUTURE_TIMESTAMP_SKEW_SECS + 3600;

        let mut entries = canonical_chain_in_zone(2, "z:work");
        entries[1].occurred_at = future_ts;
        // Recompute id because occurred_at is inside the hash.
        entries[1].id = entries[1].computed_id().unwrap();

        let report = verify_chain_with_clock(&entries, None, None, now);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.timestamp_future"),
            "expected audit.timestamp_future, got {:?}",
            report.issues
        );
        assert!(report.status.is_fail(), "far-future entry must be critical");
    }

    #[test]
    fn verify_chain_with_clock_accepts_within_skew() {
        // Entry stamped exactly at now+skew ceiling → NOT flagged.
        let now: u64 = 1_700_000_000;
        let within_skew = now + MAX_FUTURE_TIMESTAMP_SKEW_SECS;

        let mut entries = canonical_chain_in_zone(2, "z:work");
        entries[1].occurred_at = within_skew;
        entries[1].id = entries[1].computed_id().unwrap();

        let report = verify_chain_with_clock(&entries, None, None, now);
        assert!(
            !report
                .issues
                .iter()
                .any(|i| i.code == "audit.timestamp_future"),
            "entry at ceiling must not be flagged, got {:?}",
            report.issues
        );
    }

    #[test]
    fn verify_chain_with_clock_flags_u64_max_timestamp() {
        // Maximum adversarial case: u64::MAX timestamp. saturating_add
        // on the ceiling means we don't panic, and the entry is flagged.
        let now: u64 = 1_700_000_000;
        let mut entries = canonical_chain_in_zone(2, "z:work");
        entries[1].occurred_at = u64::MAX;
        entries[1].id = entries[1].computed_id().unwrap();

        let report = verify_chain_with_clock(&entries, None, None, now);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.timestamp_future"),
            "u64::MAX timestamp must be flagged"
        );
        assert!(report.status.is_fail());
    }

    #[test]
    fn verify_chain_with_clock_matches_verify_chain_when_clean() {
        // No future entries → the two APIs agree on outcome.
        let entries = canonical_chain_in_zone(3, "z:work");
        let now: u64 = 1_900_000_000;
        let plain = verify_chain(&entries, None, None);
        let clocked = verify_chain_with_clock(&entries, None, None, now);
        assert_eq!(plain.status, clocked.status);
        assert_eq!(plain.issues.len(), clocked.issues.len());
    }

    proptest! {
        #[test]
        fn verify_chain_mr_idempotent_on_repeated_verification(
            len in 1usize..=6,
            include_head in any::<bool>(),
            scoped_verification in any::<bool>(),
            mismatch_filter in any::<bool>(),
            mismatch_head_zone in any::<bool>(),
            forge_last_id in any::<bool>(),
        ) {
            let mut entries = canonical_chain_in_zone(len, "z:work");
            if forge_last_id {
                let last = entries
                    .last_mut()
                    .expect("generated chains must contain a tail entry");
                last.id = format!("forged-{}", last.id);
            }

            let head = include_head.then(|| {
                chain_head_for(
                    &entries,
                    if mismatch_head_zone {
                        "z:shadow"
                    } else {
                        "z:work"
                    },
                )
            });
            let zone_filter = scoped_verification.then_some(if mismatch_filter {
                "z:other"
            } else {
                "z:work"
            });

            let report_once = verify_chain(&entries, head.as_ref(), zone_filter);
            let report_twice = verify_chain(&entries, head.as_ref(), zone_filter);

            prop_assert_eq!(report_once, report_twice);
        }

        #[test]
        fn verify_chain_mr_head_zone_invariance(
            len in 1usize..=6,
            scoped_verification in any::<bool>(),
            zones in prop::sample::select(vec![
                ("z:work", "z:staging"),
                ("z:prod", "z:prod-canary"),
                ("z:community", "z:community-shadow"),
            ]),
        ) {
            let (base_zone, transformed_zone) = zones;

            let base_entries = canonical_chain_in_zone(len, base_zone);
            let base_head = chain_head_for(&base_entries, base_zone);
            let base_filter = scoped_verification.then_some(base_zone);
            let base_report = verify_chain(&base_entries, Some(&base_head), base_filter);

            let transformed_entries = canonical_chain_in_zone(len, transformed_zone);
            let transformed_head = chain_head_for(&transformed_entries, transformed_zone);
            let transformed_filter = scoped_verification.then_some(transformed_zone);
            let transformed_report = verify_chain(
                &transformed_entries,
                Some(&transformed_head),
                transformed_filter,
            );

            prop_assert!(base_report.is_clean());
            prop_assert!(transformed_report.is_clean());
            prop_assert_eq!(
                normalized_verify_report(base_report.clone()),
                normalized_verify_report(transformed_report.clone()),
            );
            prop_assert_eq!(base_report.zone_id.as_deref(), base_filter);
            prop_assert_eq!(transformed_report.zone_id.as_deref(), transformed_filter);
        }
    }

    #[test]
    fn verify_chain_seq_overflow_stops_validation() {
        let mut e0 = genesis_entry();
        e0.seq = u64::MAX;
        let e1 = chain_entry(7, "entry-0");

        let report = verify_chain(&[e0, e1], None, None);

        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "audit.seq_overflow"),
            "expected audit.seq_overflow issue, got {:?}",
            report.issues
        );
        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.code == "audit.seq_gap"),
            "overflow should terminate chain validation before seq-gap checks"
        );
    }

    #[test]
    fn verify_chain_invalid_genesis_nonzero_seq() {
        let mut entry = genesis_entry();
        entry.seq = 1;
        let report = verify_chain(&[entry], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.genesis_invalid")
        );
    }

    #[test]
    fn verify_chain_invalid_genesis_with_prev() {
        let mut entry = genesis_entry();
        entry.prev = Some("some-prev".to_string());
        let report = verify_chain(&[entry], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
    }

    #[test]
    fn verify_chain_seq_gap() {
        let e0 = genesis_entry();
        let e2 = chain_entry(2, "entry-0"); // seq gap: 0 -> 2
        let report = verify_chain(&[e0, e2], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(report.issues.iter().any(|i| i.code == "audit.seq_gap"));
    }

    #[test]
    fn verify_chain_prev_mismatch() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "wrong-prev");
        let report = verify_chain(&[e0, e1], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.prev_mismatch")
        );
    }

    #[test]
    fn verify_chain_zone_mismatch() {
        let mut entry = genesis_entry();
        entry.zone_id = "z:other".to_string();
        let report = verify_chain(&[entry], None, Some("z:work"));
        assert!(!report.is_clean());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.zone_mismatch")
        );
    }

    #[test]
    fn verify_chain_duplicate_seq_fork() {
        let e0 = genesis_entry();
        let mut e0_fork = genesis_entry();
        e0_fork.actor = "user:eve".to_string();
        let report = verify_chain(&[e0, e0_fork], None, None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.fork_detected")
        );
    }

    #[test]
    fn verify_chain_head_match() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let head = sample_head("entry-1", 1);
        let report = verify_chain(&[e0, e1], Some(&head), None);
        assert!(report.status.is_ok());
    }

    #[test]
    fn verify_chain_head_mismatch_entry() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let head = sample_head("wrong-entry", 1);
        let report = verify_chain(&[e0, e1], Some(&head), None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_mismatch")
        );
    }

    #[test]
    fn verify_chain_head_mismatch_seq() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let head = sample_head("entry-1", 99);
        let report = verify_chain(&[e0, e1], Some(&head), None);
        assert_eq!(report.status, VerifyStatus::Fail);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_seq_mismatch")
        );
    }

    #[test]
    fn verify_chain_head_zone_mismatch() {
        let e0 = genesis_entry();
        let mut head = sample_head("entry-0", 0);
        head.zone_id = "z:other".to_string();
        let report = verify_chain(&[e0], Some(&head), Some("z:work"));
        assert!(!report.is_clean());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_zone_mismatch")
        );
    }

    #[test]
    fn verify_chain_head_zone_mismatch_without_filter() {
        let e0 = genesis_entry();
        let mut head = sample_head("entry-0", 0);
        head.zone_id = "z:other".to_string();
        let report = verify_chain(&[e0], Some(&head), None);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_zone_mismatch")
        );
    }

    #[test]
    fn verify_chain_without_filter_rejects_mixed_zone_entries() {
        let e0 = genesis_entry();
        let mut e1 = chain_entry(1, "entry-0");
        e1.zone_id = "z:other".to_string();
        e1.id = e1.computed_id().unwrap();

        let head = ChainHead {
            zone_id: e0.zone_id.clone(),
            head_entry: e1.id.clone(),
            head_seq: e1.seq,
            coverage: 1.0,
            epoch_id: "epoch-mixed-zone".to_string(),
            signature_count: 1,
            signatures: sample_signatures(1),
        };

        let report = verify_chain(&[e0, e1], Some(&head), None);
        assert_eq!(report.status, VerifyStatus::Warn);
        assert!(!report.is_clean());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "audit.zone_mismatch"),
            "mixed-zone chain should emit zone mismatch without an explicit filter"
        );
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.code != "audit.head_zone_mismatch"),
            "head matching the baseline zone should not add a separate head mismatch"
        );
    }

    #[test]
    fn verify_chain_with_zone_filter_ok() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let report = verify_chain(&[e0, e1], None, Some("z:work"));
        assert!(report.status.is_ok());
        assert_eq!(report.zone_id, Some("z:work".to_string()));
    }

    // ── AuditError ───────────────────────────────────────────────────────

    #[test]
    fn audit_error_display_builder_missing() {
        let err = AuditError::BuilderMissingField("id".to_string());
        assert_eq!(err.to_string(), "builder missing required field: id");
    }

    #[test]
    fn audit_error_display_verification_failed() {
        let err = AuditError::VerificationFailed("chain broken".to_string());
        assert!(err.to_string().contains("chain broken"));
    }

    #[test]
    fn audit_error_display_zone_not_found() {
        let err = AuditError::ZoneNotFound("z:test".to_string());
        assert!(err.to_string().contains("z:test"));
    }

    #[test]
    fn audit_error_display_chain_unavailable() {
        let err = AuditError::ChainUnavailable("z:prod".to_string());
        assert!(err.to_string().contains("z:prod"));
    }

    #[test]
    fn audit_error_display_seq_overflow() {
        let err = AuditError::SeqOverflow(u64::MAX);
        assert!(err.to_string().contains("overflow"));
    }

    #[test]
    fn audit_error_display_invalid_entry() {
        let err = AuditError::InvalidEntry("bad data".to_string());
        assert!(err.to_string().contains("bad data"));
    }

    #[test]
    fn audit_error_display_serialization() {
        let err = AuditError::SerializationError("parse fail".to_string());
        assert!(err.to_string().contains("parse fail"));
    }

    #[test]
    fn audit_error_display_fork() {
        let err = AuditError::ForkDetected(42);
        assert!(err.to_string().contains("42"));
    }

    #[test]
    fn audit_error_codes() {
        assert_eq!(
            AuditError::BuilderMissingField(String::new()).error_code(),
            "FCP-4000"
        );
        assert_eq!(
            AuditError::VerificationFailed(String::new()).error_code(),
            "FCP-5010"
        );
        assert_eq!(
            AuditError::ZoneNotFound(String::new()).error_code(),
            "FCP-4001"
        );
        assert_eq!(
            AuditError::ChainUnavailable(String::new()).error_code(),
            "FCP-5011"
        );
        assert_eq!(AuditError::SeqOverflow(0).error_code(), "FCP-5012");
        assert_eq!(
            AuditError::InvalidEntry(String::new()).error_code(),
            "FCP-4002"
        );
        assert_eq!(
            AuditError::SerializationError(String::new()).error_code(),
            "FCP-5013"
        );
        assert_eq!(AuditError::ForkDetected(0).error_code(), "FCP-5014");
    }

    #[test]
    fn audit_error_debug() {
        let err = AuditError::ForkDetected(10);
        let debug = format!("{err:?}");
        assert!(debug.contains("ForkDetected"));
        assert!(debug.contains("10"));
    }

    #[test]
    fn audit_error_clone() {
        let err = AuditError::ZoneNotFound("z:test".to_string());
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn audit_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(AuditError::ForkDetected(1));
        assert!(err.to_string().contains("fork"));
    }

    // ── FreshnessLevel ───────────────────────────────────────────────────

    #[test]
    fn freshness_default_is_missing() {
        assert_eq!(FreshnessLevel::default(), FreshnessLevel::Missing);
    }

    #[test]
    fn freshness_is_healthy() {
        assert!(FreshnessLevel::Fresh.is_healthy());
        assert!(!FreshnessLevel::Stale.is_healthy());
        assert!(!FreshnessLevel::Degraded.is_healthy());
        assert!(!FreshnessLevel::Missing.is_healthy());
    }

    #[test]
    fn freshness_ordering() {
        assert!(FreshnessLevel::Fresh < FreshnessLevel::Stale);
        assert!(FreshnessLevel::Stale < FreshnessLevel::Degraded);
        assert!(FreshnessLevel::Degraded < FreshnessLevel::Missing);
    }

    #[test]
    fn freshness_display() {
        assert_eq!(FreshnessLevel::Fresh.to_string(), "fresh");
        assert_eq!(FreshnessLevel::Stale.to_string(), "stale");
        assert_eq!(FreshnessLevel::Degraded.to_string(), "degraded");
        assert_eq!(FreshnessLevel::Missing.to_string(), "missing");
    }

    #[test]
    fn freshness_serde_roundtrip() {
        for lvl in [
            FreshnessLevel::Fresh,
            FreshnessLevel::Stale,
            FreshnessLevel::Degraded,
            FreshnessLevel::Missing,
        ] {
            let json = serde_json::to_string(&lvl).unwrap();
            let parsed: FreshnessLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(lvl, parsed);
        }
    }

    #[test]
    fn freshness_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessLevel::Fresh);
        set.insert(FreshnessLevel::Missing);
        set.insert(FreshnessLevel::Fresh);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn freshness_clone() {
        let lvl = FreshnessLevel::Degraded;
        let copied = lvl;
        assert_eq!(lvl, copied);
    }

    #[test]
    fn freshness_copy() {
        let lvl = FreshnessLevel::Stale;
        let copied = lvl;
        assert_eq!(lvl, copied);
    }

    // ── AuditStatus ──────────────────────────────────────────────────────

    #[test]
    fn audit_status_fresh() {
        let status = AuditStatus::fresh(100, 0.95);
        assert_eq!(status.freshness, FreshnessLevel::Fresh);
        assert_eq!(status.head_seq, Some(100));
        assert_eq!(status.coverage, Some(0.95));
        assert!(status.reason.is_none());
    }

    #[test]
    fn audit_status_missing() {
        let status = AuditStatus::missing();
        assert_eq!(status.freshness, FreshnessLevel::Missing);
        assert!(status.head_seq.is_none());
        assert!(status.coverage.is_none());
    }

    #[test]
    fn audit_status_default_is_missing() {
        let status = AuditStatus::default();
        assert_eq!(status.freshness, FreshnessLevel::Missing);
    }

    #[test]
    fn audit_status_with_reason() {
        let status = AuditStatus::fresh(50, 0.5).with_reason("partial coverage");
        assert_eq!(status.reason, Some("partial coverage".to_string()));
    }

    #[test]
    fn audit_status_display_fresh() {
        let status = AuditStatus::fresh(100, 0.95);
        let display = status.to_string();
        assert!(display.contains("fresh"));
        assert!(display.contains("seq=100"));
        assert!(display.contains("95.0%"));
    }

    #[test]
    fn audit_status_display_missing() {
        let status = AuditStatus::missing();
        let display = status.to_string();
        assert!(display.contains("missing"));
        assert!(!display.contains("seq="));
    }

    #[test]
    fn audit_status_serde_roundtrip() {
        let status = AuditStatus::fresh(200, 0.75).with_reason("test");
        let json = serde_json::to_string(&status).unwrap();
        let parsed: AuditStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
    }

    #[test]
    fn audit_status_serde_skips_none() {
        let status = AuditStatus::missing();
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("head_seq"));
        assert!(!json.contains("coverage"));
        assert!(!json.contains("reason"));
    }

    #[test]
    fn audit_status_clone() {
        let status = AuditStatus::fresh(10, 0.5);
        let cloned = status.clone();
        assert_eq!(status.freshness, cloned.freshness);
        assert_eq!(status.head_seq, cloned.head_seq);
    }

    #[test]
    fn audit_status_debug() {
        let status = AuditStatus::fresh(10, 0.5);
        let debug = format!("{status:?}");
        assert!(debug.contains("AuditStatus"));
    }

    // ── NEW: Severity edge cases ────────────────────────────────────────

    #[test]
    fn severity_is_at_least_same_variant() {
        assert!(Severity::Info.is_at_least(Severity::Info));
        assert!(Severity::Warning.is_at_least(Severity::Warning));
        assert!(Severity::Error.is_at_least(Severity::Error));
        assert!(Severity::Critical.is_at_least(Severity::Critical));
    }

    #[test]
    fn severity_is_at_least_lower_to_higher() {
        assert!(!Severity::Info.is_at_least(Severity::Critical));
        assert!(!Severity::Warning.is_at_least(Severity::Error));
        assert!(!Severity::Warning.is_at_least(Severity::Critical));
        assert!(!Severity::Error.is_at_least(Severity::Critical));
    }

    #[test]
    fn severity_for_event_type_empty_string() {
        assert_eq!(Severity::for_event_type(""), Severity::Info);
    }

    #[test]
    fn severity_serde_rejects_invalid_value() {
        let result: Result<Severity, _> = serde_json::from_str("\"panic\"");
        assert!(result.is_err());
    }

    #[test]
    fn severity_serde_rejects_number() {
        let result: Result<Severity, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    fn severity_partial_ord_consistent_with_eq() {
        let a = Severity::Warning;
        let b = Severity::Warning;
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Equal));
    }

    // ── NEW: TraceContext edge cases ────────────────────────────────────

    #[test]
    fn trace_context_flags_high_bits() {
        let tc = TraceContext::new("t", "s").with_flags(0xFE);
        assert!(!tc.is_sampled()); // bit 0 is not set
        assert_eq!(tc.flags, 0xFE);
    }

    #[test]
    fn trace_context_flags_all_bits_set() {
        let tc = TraceContext::new("t", "s").with_flags(0xFF);
        assert!(tc.is_sampled());
    }

    #[test]
    fn trace_context_display_high_flags() {
        let tc = TraceContext::new("aa", "bb").with_flags(0xFF);
        assert_eq!(tc.to_string(), "00-aa-bb-ff");
    }

    #[test]
    fn trace_context_serde_with_explicit_flags() {
        let json = r#"{"trace_id":"t","span_id":"s","flags":255}"#;
        let tc: TraceContext = serde_json::from_str(json).unwrap();
        assert_eq!(tc.flags, 255);
    }

    #[test]
    fn trace_context_long_ids() {
        let long_id = "a".repeat(1000);
        let tc = TraceContext::new(long_id.as_str(), "s");
        assert_eq!(tc.trace_id.len(), 1000);
        let json = serde_json::to_string(&tc).unwrap();
        let parsed: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, parsed);
    }

    // ── NEW: AuditEntry deeper tests ───────────────────────────────────

    #[test]
    fn audit_entry_follows_self_is_false() {
        let entry = genesis_entry();
        assert!(!entry.follows(&entry));
    }

    #[test]
    fn audit_entry_computed_severity_all_event_types() {
        let types_and_severities = [
            (event_types::SECRET_ACCESS, Severity::Warning),
            (event_types::CAPABILITY_INVOKE, Severity::Info),
            (event_types::ELEVATION_GRANTED, Severity::Warning),
            (event_types::DECLASSIFICATION_GRANTED, Severity::Warning),
            (event_types::ZONE_TRANSITION, Severity::Info),
            (event_types::REVOCATION_ISSUED, Severity::Error),
            (event_types::SECURITY_VIOLATION, Severity::Error),
            (event_types::AUDIT_FORK_DETECTED, Severity::Critical),
            (event_types::CEP_ANOMALY_ALERT, Severity::Error),
        ];
        for (event_type, expected) in types_and_severities {
            let mut entry = genesis_entry();
            entry.event_type = event_type.to_string();
            assert_eq!(
                entry.computed_severity(),
                expected,
                "wrong severity for {event_type}"
            );
        }
    }

    #[test]
    fn audit_entry_serde_with_all_optional_fields() {
        let mut entry = genesis_entry();
        entry.prev = Some("prev-id".to_string());
        entry.trace_context = Some(TraceContext::new("t", "s").with_flags(1));
        entry.connector_id = Some("conn-1".to_string());
        entry.operation_id = Some("op-1".to_string());
        entry.correlation_id = "corr-abc".to_string();
        entry
            .metadata
            .insert("k1".to_string(), serde_json::json!(true));
        entry
            .metadata
            .insert("k2".to_string(), serde_json::json!([1, 2, 3]));

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn audit_entry_serde_from_minimal_json() {
        let json = r#"{
            "id": "e1",
            "event_type": "test",
            "severity": "info",
            "actor": "a",
            "zone_id": "z",
            "seq": 0,
            "occurred_at": 100
        }"#;
        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.id, "e1");
        assert!(entry.prev.is_none());
        assert!(entry.trace_context.is_none());
        assert!(entry.connector_id.is_none());
        assert!(entry.operation_id.is_none());
        assert!(entry.metadata.is_empty());
        assert_eq!(entry.correlation_id, "");
    }

    #[test]
    fn audit_entry_metadata_complex_values() {
        let mut entry = genesis_entry();
        entry.metadata.insert(
            "nested".to_string(),
            serde_json::json!({"a": {"b": [1, 2]}}),
        );
        entry
            .metadata
            .insert("null_val".to_string(), serde_json::Value::Null);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.metadata, parsed.metadata);
    }

    #[test]
    fn audit_entry_display_includes_occurred_at() {
        let entry = genesis_entry();
        let display = entry.to_string();
        assert!(display.contains("1700000000"));
    }

    // ── NEW: Builder edge cases ────────────────────────────────────────

    #[test]
    fn builder_multiple_metadata_entries() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("a")
            .zone_id("z")
            .seq(0)
            .occurred_at(0)
            .meta("key1", serde_json::json!("val1"))
            .meta("key2", serde_json::json!(42))
            .meta("key3", serde_json::json!(null))
            .build()
            .unwrap();
        assert_eq!(entry.metadata.len(), 3);
        assert_eq!(entry.metadata.get("key1"), Some(&serde_json::json!("val1")));
        assert_eq!(entry.metadata.get("key2"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn builder_overwrite_metadata_key() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("a")
            .zone_id("z")
            .seq(0)
            .occurred_at(0)
            .meta("key", serde_json::json!("first"))
            .meta("key", serde_json::json!("second"))
            .build()
            .unwrap();
        assert_eq!(entry.metadata.len(), 1);
        assert_eq!(
            entry.metadata.get("key"),
            Some(&serde_json::json!("second"))
        );
    }

    #[test]
    fn builder_empty_build_fails() {
        let result = AuditEntryBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_severity_auto_for_secret_access() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::SECRET_ACCESS)
            .actor("a")
            .zone_id("z")
            .seq(0)
            .occurred_at(0)
            .build()
            .unwrap();
        assert_eq!(entry.severity, Severity::Warning);
    }

    #[test]
    fn builder_severity_auto_for_revocation() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::REVOCATION_ISSUED)
            .actor("a")
            .zone_id("z")
            .seq(0)
            .occurred_at(0)
            .build()
            .unwrap();
        assert_eq!(entry.severity, Severity::Error);
    }

    #[test]
    fn builder_correlation_id_defaults_to_empty() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("a")
            .zone_id("z")
            .seq(0)
            .occurred_at(0)
            .build()
            .unwrap();
        assert_eq!(entry.correlation_id, "");
    }

    #[test]
    fn builder_prev_defaults_to_none() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type("test")
            .actor("a")
            .zone_id("z")
            .seq(0)
            .occurred_at(0)
            .build()
            .unwrap();
        assert!(entry.prev.is_none());
    }

    // ── NEW: ChainHead edge cases ──────────────────────────────────────

    #[test]
    fn chain_head_meets_coverage_exact_boundary() {
        let mut head = sample_head("e", 0);
        head.coverage = 0.50;
        assert!(head.meets_coverage(0.50));
        assert!(!head.meets_coverage(0.51));
    }

    #[test]
    fn chain_head_serde_preserves_all_fields() {
        let head = ChainHead {
            zone_id: "z:test".to_string(),
            head_entry: "entry-99".to_string(),
            head_seq: 99,
            coverage: 0.123_456_789,
            epoch_id: "epoch-42".to_string(),
            signature_count: 7,
            signatures: sample_signatures(7),
        };
        let json = serde_json::to_string(&head).unwrap();
        let parsed: ChainHead = serde_json::from_str(&json).unwrap();
        assert_eq!(head.zone_id, parsed.zone_id);
        assert_eq!(head.head_entry, parsed.head_entry);
        assert_eq!(head.head_seq, parsed.head_seq);
        assert_eq!(head.epoch_id, parsed.epoch_id);
        assert_eq!(head.signature_count, parsed.signature_count);
    }

    #[test]
    fn chain_head_display_zero_coverage() {
        let mut head = sample_head("e", 0);
        head.coverage = 0.0;
        let display = head.to_string();
        assert!(display.contains("0.0%"));
    }

    #[test]
    fn chain_head_display_full_coverage() {
        let mut head = sample_head("e", 0);
        head.coverage = 1.0;
        let display = head.to_string();
        assert!(display.contains("100.0%"));
    }

    #[test]
    fn chain_head_large_seq() {
        let head = sample_head("e", u64::MAX);
        assert_eq!(head.head_seq, u64::MAX);
        let json = serde_json::to_string(&head).unwrap();
        let parsed: ChainHead = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.head_seq, u64::MAX);
    }

    // ── NEW: Decision edge cases ───────────────────────────────────────

    #[test]
    fn decision_serde_rejects_unknown_variant() {
        let result: Result<Decision, _> = serde_json::from_str("\"maybe\"");
        assert!(result.is_err());
    }

    #[test]
    fn decision_serde_rejects_null() {
        let result: Result<Decision, _> = serde_json::from_str("null");
        assert!(result.is_err());
    }

    // ── NEW: DecisionReceipt deeper tests ──────────────────────────────

    #[test]
    fn receipt_deny_display() {
        let mut receipt = sample_receipt();
        receipt.decision = Decision::Deny;
        let display = receipt.to_string();
        assert!(display.contains("deny"));
    }

    #[test]
    fn receipt_no_evidence_no_explanation() {
        let receipt = DecisionReceipt {
            id: "r-1".to_string(),
            request_id: "req-1".to_string(),
            decision: Decision::Deny,
            reason_code: "policy.denied".to_string(),
            evidence: vec![],
            audit_entry_id: None,
            explanation: None,
            decided_at: 0,
            zone_id: "z:test".to_string(),
            correlation_id: None,
            trace_context: None,
            connector_id: None,
            operation_id: None,
            confidence: None,
            issuer_kid: None,
            signature: None,
        };
        assert_eq!(receipt.evidence_count(), 0);
        assert!(!receipt.has_explanation());

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("evidence"));
        assert!(!json.contains("explanation"));
        let parsed: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn receipt_with_provenance_fields_roundtrips() {
        let receipt = DecisionReceipt {
            id: "r-2".to_string(),
            request_id: "req-2".to_string(),
            decision: Decision::Allow,
            reason_code: "policy.allowed".to_string(),
            evidence: vec!["audit:e-1".to_string()],
            audit_entry_id: Some("e-1".to_string()),
            explanation: Some("Matched exact connector policy".to_string()),
            decided_at: 42,
            zone_id: "z:prod".to_string(),
            correlation_id: Some("corr-2".to_string()),
            trace_context: Some(TraceContext::new("trace-2", "span-2").with_flags(0x01)),
            connector_id: Some("stripe".to_string()),
            operation_id: Some("charges.create".to_string()),
            confidence: Some(ConformalScore::from_value(0.875, 32, 3, 90, None)),
            issuer_kid: None,
            signature: None,
        };

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"audit_entry_id\":\"e-1\""));
        assert!(json.contains("\"correlation_id\":\"corr-2\""));
        assert!(json.contains("\"connector_id\":\"stripe\""));
        assert!(json.contains("\"operation_id\":\"charges.create\""));
        assert!(json.contains("\"confidence\""));

        let parsed: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.confidence.as_ref().unwrap().display_value(), "0.875");
        assert_eq!(parsed, receipt);
    }

    #[test]
    fn receipt_many_evidence_refs() {
        let mut receipt = sample_receipt();
        receipt.evidence = (0..100).map(|i| format!("ev-{i}")).collect();
        assert_eq!(receipt.evidence_count(), 100);
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.evidence_count(), 100);
    }

    #[test]
    fn receipt_serde_from_full_json() {
        let json = r#"{
            "id": "r-2",
            "request_id": "req-2",
            "decision": "deny",
            "reason_code": "no_cap",
            "evidence": ["e1"],
            "explanation": "Not authorized",
            "decided_at": 999,
            "zone_id": "z:prod"
        }"#;
        let receipt: DecisionReceipt = serde_json::from_str(json).unwrap();
        assert!(receipt.is_deny());
        assert!(receipt.has_explanation());
        assert_eq!(receipt.evidence_count(), 1);
        assert_eq!(receipt.decided_at, 999);
    }

    // ── NEW: AuditFilter deeper tests ──────────────────────────────────

    #[test]
    fn filter_matches_trace_id_wrong_trace() {
        let filter = AuditFilter {
            trace_id: Some("trace-xyz".to_string()),
            ..Default::default()
        };
        let mut entry = genesis_entry();
        entry.trace_context = Some(TraceContext::new("trace-abc", "span-1"));
        assert!(!filter.matches(&entry));
    }

    #[test]
    fn filter_min_severity_info_matches_all() {
        let filter = AuditFilter {
            min_severity: Some(Severity::Info),
            ..Default::default()
        };
        let entry = genesis_entry(); // Info severity
        assert!(filter.matches(&entry));
    }

    #[test]
    fn filter_min_severity_critical_only() {
        let filter = AuditFilter {
            min_severity: Some(Severity::Critical),
            ..Default::default()
        };
        let mut entry_warn = genesis_entry();
        entry_warn.severity = Severity::Warning;
        assert!(!filter.matches(&entry_warn));

        let mut entry_err = genesis_entry();
        entry_err.severity = Severity::Error;
        assert!(!filter.matches(&entry_err));

        let mut entry_crit = genesis_entry();
        entry_crit.severity = Severity::Critical;
        assert!(filter.matches(&entry_crit));
    }

    #[test]
    fn filter_combined_all_fields_match() {
        let mut entry = genesis_entry();
        entry.trace_context = Some(TraceContext::new("tid-1", "sid-1"));
        entry.severity = Severity::Warning;

        let filter = AuditFilter {
            connector_id: Some("fcp.telegram:base:v1".to_string()),
            operation_id: Some("send_message".to_string()),
            correlation_id: Some("corr-0".to_string()),
            trace_id: Some("tid-1".to_string()),
            event_type: Some(event_types::CAPABILITY_INVOKE.to_string()),
            actor: Some("user:alice".to_string()),
            min_severity: Some(Severity::Warning),
            zone_id: Some("z:work".to_string()),
        };
        assert!(filter.matches(&entry));
    }

    #[test]
    fn filter_combined_one_field_fails() {
        let filter = AuditFilter {
            actor: Some("user:alice".to_string()),
            zone_id: Some("z:wrong".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&genesis_entry()));
    }

    #[test]
    fn filter_operation_id_none_entry() {
        let filter = AuditFilter {
            operation_id: Some("any".to_string()),
            ..Default::default()
        };
        let mut entry = genesis_entry();
        entry.operation_id = None;
        assert!(!filter.matches(&entry));
    }

    #[test]
    fn filter_serde_all_fields_roundtrip() {
        let filter = AuditFilter {
            connector_id: Some("c".to_string()),
            operation_id: Some("o".to_string()),
            correlation_id: Some("corr".to_string()),
            trace_id: Some("t".to_string()),
            event_type: Some("e".to_string()),
            actor: Some("a".to_string()),
            min_severity: Some(Severity::Error),
            zone_id: Some("z".to_string()),
        };
        let json = serde_json::to_string(&filter).unwrap();
        let parsed: AuditFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(filter, parsed);
    }

    #[test]
    fn filter_display_many_active() {
        let filter = AuditFilter {
            actor: Some("a".to_string()),
            zone_id: Some("z".to_string()),
            event_type: Some("e".to_string()),
            ..Default::default()
        };
        assert_eq!(filter.to_string(), "AuditFilter(3 active)");
    }

    // ── NEW: VerifyIssue edge cases ────────────────────────────────────

    #[test]
    fn verify_issue_serde_minimal() {
        let json = r#"{"code":"x","message":"y"}"#;
        let issue: VerifyIssue = serde_json::from_str(json).unwrap();
        assert_eq!(issue.code, "x");
        assert_eq!(issue.message, "y");
        assert!(issue.seq.is_none());
        assert!(issue.entry_id.is_none());
    }

    #[test]
    fn verify_issue_display_long_message() {
        let long_msg = "x".repeat(500);
        let issue = VerifyIssue::new("code", long_msg.as_str());
        let display = issue.to_string();
        assert!(display.starts_with("code: "));
        assert_eq!(display.len(), 6 + 500);
    }

    #[test]
    fn verify_issue_is_critical_empty_code() {
        let issue = VerifyIssue::new("", "msg");
        assert!(!issue.is_critical());
    }

    #[test]
    fn verify_issue_with_seq_zero() {
        let issue = VerifyIssue::new("code", "msg").with_seq(0);
        assert_eq!(issue.seq, Some(0));
    }

    #[test]
    fn verify_issue_with_entry_id_empty() {
        let issue = VerifyIssue::new("code", "msg").with_entry_id("");
        assert_eq!(issue.entry_id, Some(String::new()));
    }

    // ── NEW: VerifyReport deeper tests ─────────────────────────────────

    #[test]
    fn verify_report_is_clean_with_issues() {
        let mut report = VerifyReport::ok(5);
        assert!(report.is_clean());
        report
            .issues
            .push(VerifyIssue::new("audit.zone_mismatch", "mismatch"));
        assert!(!report.is_clean());
    }

    #[test]
    fn verify_report_critical_count_none_critical() {
        let mut report = VerifyReport::ok(5);
        report
            .issues
            .push(VerifyIssue::new("audit.zone_mismatch", "m"));
        assert_eq!(report.critical_count(), 0);
    }

    #[test]
    fn verify_report_display_with_issues() {
        let mut report = VerifyReport::ok(10);
        report.status = VerifyStatus::Fail;
        report.issues.push(VerifyIssue::new("audit.seq_gap", "gap"));
        report
            .issues
            .push(VerifyIssue::new("audit.prev_mismatch", "mismatch"));
        let display = report.to_string();
        assert!(display.contains("fail"));
        assert!(display.contains("chain_len=10"));
        assert!(display.contains("issues=2"));
    }

    #[test]
    fn verify_report_serde_with_issues() {
        let mut report = VerifyReport::ok(2);
        report.status = VerifyStatus::Warn;
        report
            .issues
            .push(VerifyIssue::new("audit.zone_mismatch", "z").with_seq(1));
        let json = serde_json::to_string(&report).unwrap();
        let parsed: VerifyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
        assert_eq!(parsed.issues.len(), 1);
    }

    #[test]
    fn verify_report_ok_zero_chain() {
        let report = VerifyReport::ok(0);
        assert_eq!(report.chain_len, 0);
        assert!(report.is_clean());
    }

    // ── NEW: verify_chain deeper scenarios ─────────────────────────────

    #[test]
    fn verify_chain_long_valid_chain() {
        let mut entries = vec![genesis_entry()];
        for i in 1u64..20 {
            entries.push(chain_entry(i, &format!("entry-{}", i - 1)));
        }
        let report = verify_chain(&entries, None, None);
        assert!(report.status.is_ok());
        assert_eq!(report.chain_len, 20);
    }

    #[test]
    fn verify_chain_long_chain_with_head() {
        let mut entries = vec![genesis_entry()];
        for i in 1u64..10 {
            entries.push(chain_entry(i, &format!("entry-{}", i - 1)));
        }
        let head = sample_head("entry-9", 9);
        let report = verify_chain(&entries, Some(&head), None);
        assert!(report.status.is_ok());
    }

    #[test]
    fn verify_chain_zone_mismatch_multiple_entries() {
        let mut e0 = genesis_entry();
        e0.zone_id = "z:other".to_string();
        let mut e1 = chain_entry(1, "entry-0");
        e1.zone_id = "z:other".to_string();
        let report = verify_chain(&[e0, e1], None, Some("z:work"));
        let zone_count = report
            .issues
            .iter()
            .filter(|i| i.code == "audit.zone_mismatch")
            .count();
        assert_eq!(zone_count, 2);
    }

    #[test]
    fn verify_chain_returns_zone_id_in_report() {
        let report = verify_chain(&[], None, Some("z:test-zone"));
        assert_eq!(report.zone_id, Some("z:test-zone".to_string()));
    }

    #[test]
    fn verify_chain_head_populates_head_fields() {
        let e0 = genesis_entry();
        let head = sample_head("entry-0", 0);
        let report = verify_chain(&[e0], Some(&head), None);
        assert_eq!(report.head_seq, Some(0));
        assert_eq!(report.head_entry, Some(head.head_entry));
    }

    #[test]
    fn verify_chain_multiple_issues_combined() {
        // Genesis has prev (invalid) AND zone mismatch
        let mut e0 = genesis_entry();
        e0.prev = Some("ghost".to_string());
        e0.zone_id = "z:wrong".to_string();
        let report = verify_chain(&[e0], None, Some("z:work"));
        assert!(report.status.is_fail());
        assert!(report.issues.len() >= 2);
    }

    #[test]
    fn verify_chain_duplicate_seq_same_id_no_fork() {
        // Same id at same seq should not trigger fork
        let e0 = genesis_entry();
        let e0_dup = genesis_entry(); // exact same entry
        let report = verify_chain(&[e0, e0_dup], None, None);
        let fork_count = report
            .issues
            .iter()
            .filter(|i| i.code == "audit.fork_detected")
            .count();
        assert_eq!(fork_count, 0);
    }

    #[test]
    fn verify_chain_seq_gap_and_prev_mismatch() {
        let e0 = genesis_entry();
        let mut e3 = chain_entry(3, "wrong-prev"); // seq gap + prev mismatch
        e3.id = "entry-3".to_string();
        let report = verify_chain(&[e0, e3], None, None);
        assert!(report.status.is_fail());
        assert!(report.issues.iter().any(|i| i.code == "audit.seq_gap"));
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.prev_mismatch")
        );
    }

    #[test]
    fn verify_chain_head_both_entry_and_seq_mismatch() {
        let e0 = genesis_entry();
        let head = sample_head("wrong-entry", 99);
        let report = verify_chain(&[e0], Some(&head), None);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_mismatch")
        );
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.head_seq_mismatch")
        );
    }

    // ── NEW: AuditError deeper tests ───────────────────────────────────

    #[test]
    fn audit_error_clone_preserves_message() {
        let err = AuditError::VerificationFailed("chain integrity compromised".to_string());
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
        assert_eq!(err.error_code(), cloned.error_code());
    }

    #[test]
    fn audit_error_debug_all_variants() {
        let variants: Vec<AuditError> = vec![
            AuditError::BuilderMissingField("f".to_string()),
            AuditError::VerificationFailed("v".to_string()),
            AuditError::ZoneNotFound("z".to_string()),
            AuditError::ChainUnavailable("c".to_string()),
            AuditError::SeqOverflow(1),
            AuditError::InvalidEntry("i".to_string()),
            AuditError::SerializationError("s".to_string()),
            AuditError::ForkDetected(2),
        ];
        for err in variants {
            let debug = format!("{err:?}");
            assert_ne!(debug, "");
        }
    }

    #[test]
    fn audit_error_display_seq_overflow_max() {
        let err = AuditError::SeqOverflow(u64::MAX);
        let display = err.to_string();
        assert!(display.contains("18446744073709551615"));
    }

    #[test]
    fn audit_error_fork_detected_zero() {
        let err = AuditError::ForkDetected(0);
        assert!(err.to_string().contains('0'));
        assert_eq!(err.error_code(), "FCP-5014");
    }

    // ── NEW: FreshnessLevel deeper tests ───────────────────────────────

    #[test]
    fn freshness_serde_values() {
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Fresh).unwrap(),
            "\"fresh\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Stale).unwrap(),
            "\"stale\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Missing).unwrap(),
            "\"missing\""
        );
    }

    #[test]
    fn freshness_serde_rejects_unknown() {
        let result: Result<FreshnessLevel, _> = serde_json::from_str("\"ancient\"");
        assert!(result.is_err());
    }

    #[test]
    fn freshness_debug_all_variants() {
        assert_eq!(format!("{:?}", FreshnessLevel::Fresh), "Fresh");
        assert_eq!(format!("{:?}", FreshnessLevel::Stale), "Stale");
        assert_eq!(format!("{:?}", FreshnessLevel::Degraded), "Degraded");
        assert_eq!(format!("{:?}", FreshnessLevel::Missing), "Missing");
    }

    // ── NEW: AuditStatus deeper tests ──────────────────────────────────

    #[test]
    fn audit_status_fresh_zero_coverage() {
        let status = AuditStatus::fresh(0, 0.0);
        assert_eq!(status.freshness, FreshnessLevel::Fresh);
        assert_eq!(status.head_seq, Some(0));
        assert_eq!(status.coverage, Some(0.0));
    }

    #[test]
    fn audit_status_with_reason_replaces_none() {
        let status = AuditStatus::missing().with_reason("no data");
        assert_eq!(status.reason, Some("no data".to_string()));
    }

    #[test]
    fn audit_status_display_with_reason_not_shown() {
        // Display does not include reason (verified by current impl)
        let status = AuditStatus::fresh(5, 0.5).with_reason("partial");
        let display = status.to_string();
        assert!(display.contains("fresh"));
        assert!(display.contains("seq=5"));
    }

    #[test]
    fn audit_status_serde_missing_roundtrip() {
        let status = AuditStatus::missing();
        let json = serde_json::to_string(&status).unwrap();
        let parsed: AuditStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
    }

    #[test]
    fn audit_status_serde_with_reason_roundtrip() {
        let status = AuditStatus::fresh(42, 0.99).with_reason("test reason");
        let json = serde_json::to_string(&status).unwrap();
        let parsed: AuditStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status.reason, parsed.reason);
        assert_eq!(status.freshness, parsed.freshness);
    }

    #[test]
    fn audit_status_eq_different_freshness() {
        let a = AuditStatus::fresh(10, 0.5);
        let b = AuditStatus::missing();
        assert_ne!(a, b);
    }

    // ── NEW: VerifyStatus edge cases ───────────────────────────────────

    #[test]
    fn verify_status_serde_rejects_invalid() {
        let result: Result<VerifyStatus, _> = serde_json::from_str("\"unknown\"");
        assert!(result.is_err());
    }

    #[test]
    fn verify_status_copy_semantics() {
        let s = VerifyStatus::Warn;
        let s2 = s;
        assert_eq!(s, s2);
    }

    #[test]
    fn verify_status_debug_all_variants() {
        assert_eq!(format!("{:?}", VerifyStatus::Ok), "Ok");
        assert_eq!(format!("{:?}", VerifyStatus::Warn), "Warn");
        assert_eq!(format!("{:?}", VerifyStatus::Fail), "Fail");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Extended test battery: cross-type integration, deeper edge cases
    // ══════════════════════════════════════════════════════════════════════

    // ── AuditError extended ───────────────────────────────────────────────

    #[test]
    fn audit_error_error_code_is_deterministic() {
        let e1 = AuditError::ForkDetected(1);
        let e2 = AuditError::ForkDetected(999);
        assert_eq!(e1.error_code(), e2.error_code());
    }

    #[test]
    fn audit_error_all_variants_are_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(AuditError::BuilderMissingField("f".into())),
            Box::new(AuditError::VerificationFailed("v".into())),
            Box::new(AuditError::ZoneNotFound("z".into())),
            Box::new(AuditError::ChainUnavailable("c".into())),
            Box::new(AuditError::SeqOverflow(42)),
            Box::new(AuditError::InvalidEntry("i".into())),
            Box::new(AuditError::SerializationError("s".into())),
            Box::new(AuditError::ForkDetected(0)),
        ];
        assert_eq!(variants.len(), 8);
        for v in &variants {
            assert_ne!(v.to_string(), "");
        }
    }

    #[test]
    fn audit_error_display_messages_are_distinct() {
        use std::collections::HashSet;
        let errors = [
            AuditError::BuilderMissingField("f".into()).to_string(),
            AuditError::VerificationFailed("v".into()).to_string(),
            AuditError::ZoneNotFound("z".into()).to_string(),
            AuditError::ChainUnavailable("c".into()).to_string(),
            AuditError::SeqOverflow(0).to_string(),
            AuditError::InvalidEntry("i".into()).to_string(),
            AuditError::SerializationError("s".into()).to_string(),
            AuditError::ForkDetected(0).to_string(),
        ];
        let unique: HashSet<_> = errors.iter().collect();
        assert_eq!(unique.len(), 8);
    }

    #[test]
    fn audit_error_codes_are_unique() {
        use std::collections::HashSet;
        let codes: Vec<&str> = vec![
            AuditError::BuilderMissingField(String::new()).error_code(),
            AuditError::VerificationFailed(String::new()).error_code(),
            AuditError::ZoneNotFound(String::new()).error_code(),
            AuditError::ChainUnavailable(String::new()).error_code(),
            AuditError::SeqOverflow(0).error_code(),
            AuditError::InvalidEntry(String::new()).error_code(),
            AuditError::SerializationError(String::new()).error_code(),
            AuditError::ForkDetected(0).error_code(),
        ];
        let unique: HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), 8);
    }

    #[test]
    fn audit_error_codes_start_with_fcp() {
        let variants: Vec<AuditError> = vec![
            AuditError::BuilderMissingField(String::new()),
            AuditError::VerificationFailed(String::new()),
            AuditError::ZoneNotFound(String::new()),
            AuditError::ChainUnavailable(String::new()),
            AuditError::SeqOverflow(0),
            AuditError::InvalidEntry(String::new()),
            AuditError::SerializationError(String::new()),
            AuditError::ForkDetected(0),
        ];
        for v in &variants {
            assert!(
                v.error_code().starts_with("FCP-"),
                "error code {} should start with FCP-",
                v.error_code()
            );
        }
    }

    #[test]
    fn audit_error_clone_preserves_message_and_code() {
        let original = AuditError::VerificationFailed("chain broken at seq 5".into());
        let cloned = original.clone();
        assert_eq!(original.to_string(), cloned.to_string());
        assert_eq!(original.error_code(), cloned.error_code());
    }

    #[test]
    fn audit_error_empty_message_variants() {
        let err = AuditError::BuilderMissingField(String::new());
        assert!(err.to_string().contains("builder missing required field"));

        let err = AuditError::ZoneNotFound(String::new());
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn audit_error_unicode_message() {
        let err = AuditError::InvalidEntry("données corrompues".into());
        assert!(err.to_string().contains("données"));
    }

    #[test]
    fn audit_error_long_message() {
        let msg = "x".repeat(2000);
        let err = AuditError::SerializationError(msg.clone());
        assert!(err.to_string().contains(&msg));
    }

    #[test]
    fn audit_error_seq_overflow_max() {
        let err = AuditError::SeqOverflow(u64::MAX);
        let s = err.to_string();
        assert!(s.contains(&u64::MAX.to_string()));
    }

    #[test]
    fn audit_error_fork_detected_at_seq_zero() {
        let err = AuditError::ForkDetected(0);
        assert!(err.to_string().contains('0'));
    }

    // ── verify_chain extended scenarios ───────────────────────────────────

    #[test]
    fn verify_chain_50_entry_valid_chain() {
        let mut entries = vec![genesis_entry()];
        for i in 1u64..50 {
            entries.push(chain_entry(i, &format!("entry-{}", i - 1)));
        }
        let report = verify_chain(&entries, None, None);
        assert!(report.status.is_ok());
        assert_eq!(report.chain_len, 50);
        assert!(report.is_clean());
    }

    #[test]
    fn verify_chain_gap_at_end() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let mut e5 = chain_entry(5, "entry-1");
        e5.id = "entry-5".to_string();
        let report = verify_chain(&[e0, e1, e5], None, None);
        assert!(report.status.is_fail());
        let gap_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "audit.seq_gap")
            .collect();
        assert_eq!(gap_issues.len(), 1);
        assert_eq!(gap_issues[0].seq, Some(5));
    }

    #[test]
    fn verify_chain_multiple_gaps() {
        let e0 = genesis_entry();
        let mut e3 = chain_entry(3, "entry-0");
        e3.id = "entry-3".to_string();
        let mut e7 = chain_entry(7, "entry-3");
        e7.id = "entry-7".to_string();
        let report = verify_chain(&[e0, e3, e7], None, None);
        let gap_count = report
            .issues
            .iter()
            .filter(|i| i.code == "audit.seq_gap")
            .count();
        assert_eq!(gap_count, 2);
    }

    #[test]
    fn verify_chain_head_double_mismatch_entry_and_seq() {
        let e0 = genesis_entry();
        let head = sample_head("wrong-entry", 999);
        let report = verify_chain(&[e0], Some(&head), None);
        assert!(report.status.is_fail());
        let has_head_mismatch = report
            .issues
            .iter()
            .any(|i| i.code == "audit.head_mismatch");
        let has_seq_mismatch = report
            .issues
            .iter()
            .any(|i| i.code == "audit.head_seq_mismatch");
        assert!(has_head_mismatch);
        assert!(has_seq_mismatch);
    }

    #[test]
    fn verify_chain_zone_filter_matching_all_entries() {
        let mut entries = vec![genesis_entry()];
        for i in 1u64..5 {
            entries.push(chain_entry(i, &format!("entry-{}", i - 1)));
        }
        let report = verify_chain(&entries, None, Some("z:work"));
        assert!(report.status.is_ok());
        assert_eq!(report.zone_id, Some("z:work".to_string()));
    }

    #[test]
    fn verify_chain_head_zone_match_ok() {
        let e0 = genesis_entry();
        let head = sample_head("entry-0", 0);
        let report = verify_chain(&[e0], Some(&head), Some("z:work"));
        let has_zone_head_issues = report
            .issues
            .iter()
            .any(|i| i.code == "audit.head_zone_mismatch");
        assert!(!has_zone_head_issues);
    }

    #[test]
    fn verify_chain_single_invalid_genesis_seq_and_prev() {
        let mut e0 = genesis_entry();
        e0.seq = 5;
        e0.prev = Some("phantom".to_string());
        let report = verify_chain(&[e0], None, None);
        assert!(report.status.is_fail());
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == "audit.genesis_invalid")
        );
    }

    #[test]
    fn verify_chain_no_zone_filter_no_zone_in_report() {
        let report = verify_chain(&[genesis_entry()], None, None);
        assert!(report.zone_id.is_none());
    }

    #[test]
    fn verify_chain_empty_with_zone() {
        let report = verify_chain(&[], None, Some("z:test"));
        assert_eq!(report.zone_id, Some("z:test".to_string()));
        assert!(report.status.is_ok());
        assert_eq!(report.chain_len, 0);
    }

    // ── AuditFilter combination logic ────────────────────────────────────

    #[test]
    fn filter_matches_subset_of_entries() {
        let entries: Vec<AuditEntry> = (0..5)
            .map(|i| {
                let mut e = genesis_entry();
                e.id = format!("entry-{i}");
                e.seq = i;
                if i % 2 == 0 {
                    e.severity = Severity::Error;
                }
                e
            })
            .collect();

        let filter = AuditFilter {
            min_severity: Some(Severity::Error),
            ..Default::default()
        };

        let matched_count = entries.iter().filter(|e| filter.matches(e)).count();
        assert_eq!(matched_count, 3); // i=0,2,4
    }

    #[test]
    fn filter_no_match_when_all_fields_wrong() {
        let filter = AuditFilter {
            connector_id: Some("wrong".into()),
            operation_id: Some("wrong".into()),
            actor: Some("wrong".into()),
            zone_id: Some("wrong".into()),
            ..Default::default()
        };
        assert!(!filter.matches(&genesis_entry()));
    }

    #[test]
    fn filter_serde_from_empty_json() {
        let filter: AuditFilter = serde_json::from_str("{}").unwrap();
        assert!(filter.is_empty());
        assert_eq!(filter.active_count(), 0);
    }

    #[test]
    fn filter_eq_same_fields() {
        let a = AuditFilter {
            actor: Some("alice".into()),
            zone_id: Some("z:work".into()),
            ..Default::default()
        };
        let b = AuditFilter {
            actor: Some("alice".into()),
            zone_id: Some("z:work".into()),
            ..Default::default()
        };
        assert_eq!(a, b);
    }

    #[test]
    fn filter_ne_different_fields() {
        let a = AuditFilter {
            actor: Some("alice".into()),
            ..Default::default()
        };
        let b = AuditFilter {
            actor: Some("bob".into()),
            ..Default::default()
        };
        assert_ne!(a, b);
    }

    // ── DecisionReceipt extended ─────────────────────────────────────────

    #[test]
    fn receipt_serde_from_minimal_json() {
        let json = r#"{
            "id": "r",
            "request_id": "req",
            "decision": "allow",
            "reason_code": "ok",
            "decided_at": 0,
            "zone_id": "z"
        }"#;
        let receipt: DecisionReceipt = serde_json::from_str(json).unwrap();
        assert!(receipt.is_allow());
        assert_eq!(receipt.evidence_count(), 0);
        assert!(!receipt.has_explanation());
    }

    #[test]
    fn receipt_unicode_reason_code() {
        let mut receipt = sample_receipt();
        receipt.reason_code = "politique.refusé".into();
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.reason_code, "politique.refusé");
    }

    #[test]
    fn receipt_eq_same_data() {
        let a = sample_receipt();
        let b = sample_receipt();
        assert_eq!(a, b);
    }

    #[test]
    fn receipt_ne_different_decision() {
        let mut a = sample_receipt();
        let mut b = sample_receipt();
        b.decision = Decision::Deny;
        a.decision = Decision::Allow;
        assert_ne!(a, b);
    }

    #[test]
    fn receipt_large_evidence_serde_roundtrip() {
        let mut receipt = sample_receipt();
        receipt.evidence = (0..500).map(|i| format!("evidence-ref-{i}")).collect();
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.evidence.len(), 500);
    }

    #[test]
    fn receipt_display_deny_variant() {
        let mut receipt = sample_receipt();
        receipt.decision = Decision::Deny;
        receipt.reason_code = "cap.revoked".into();
        let display = receipt.to_string();
        assert!(display.contains("deny"));
        assert!(display.contains("cap.revoked"));
    }

    // ── ChainHead extended ───────────────────────────────────────────────

    #[test]
    fn chain_head_has_quorum_boundary() {
        // Quorum now requires BOTH signatures attached AND count == len.
        let mut head = sample_head("e", 0);
        head.signature_count = 1;
        head.signatures = sample_signatures(1);
        assert!(head.has_quorum());

        // Clearing the count without clearing signatures → inconsistent.
        head.signature_count = 0;
        assert!(!head.has_quorum());

        // Clearing signatures with any count → no quorum.
        head.signatures.clear();
        head.signature_count = 5;
        assert!(!head.has_quorum());
    }

    #[test]
    fn chain_head_eq_same_data() {
        let a = sample_head("entry-5", 5);
        let b = sample_head("entry-5", 5);
        assert_eq!(a, b);
    }

    #[test]
    fn chain_head_ne_different_seq() {
        let a = sample_head("entry-5", 5);
        let b = sample_head("entry-5", 6);
        assert_ne!(a, b);
    }

    #[test]
    fn chain_head_ne_different_entry() {
        let a = sample_head("entry-a", 5);
        let b = sample_head("entry-b", 5);
        assert_ne!(a, b);
    }

    #[test]
    fn chain_head_display_includes_zone() {
        let mut head = sample_head("e", 0);
        head.zone_id = "z:production-us-east-1".into();
        let display = head.to_string();
        assert!(display.contains("z:production-us-east-1"));
    }

    // ── AuditEntry extended ──────────────────────────────────────────────

    #[test]
    fn audit_entry_follows_consecutive_chain() {
        let mut entries = vec![genesis_entry()];
        for i in 1u64..10 {
            entries.push(chain_entry(i, &format!("entry-{}", i - 1)));
        }
        for i in 1..entries.len() {
            assert!(
                entries[i].follows(&entries[i - 1]),
                "entry {} should follow entry {}",
                i,
                i - 1
            );
        }
    }

    #[test]
    fn audit_entry_genesis_does_not_follow_non_genesis() {
        let non_genesis = chain_entry(1, "entry-0");
        let genesis = genesis_entry();
        assert!(!genesis.follows(&non_genesis));
    }

    #[test]
    fn audit_entry_display_chain_entry() {
        let entry = chain_entry(5, "entry-4");
        let display = entry.to_string();
        assert!(display.contains("seq=5"));
        assert!(display.contains(event_types::SECRET_ACCESS));
        assert!(display.contains("user:bob"));
        assert!(display.contains("z:work"));
    }

    #[test]
    fn audit_entry_serde_preserves_btreemap_ordering() {
        let mut entry = genesis_entry();
        entry.metadata.insert("z_key".into(), serde_json::json!(1));
        entry.metadata.insert("a_key".into(), serde_json::json!(2));
        entry.metadata.insert("m_key".into(), serde_json::json!(3));

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        let keys: Vec<_> = parsed.metadata.keys().collect();
        assert_eq!(keys, vec!["a_key", "m_key", "z_key"]);
    }

    #[test]
    fn audit_entry_ne_different_event_type() {
        let mut a = genesis_entry();
        let mut b = genesis_entry();
        b.event_type = event_types::SECURITY_VIOLATION.into();
        a.event_type = event_types::CAPABILITY_INVOKE.into();
        assert_ne!(a, b);
    }

    #[test]
    fn audit_entry_ne_different_metadata() {
        let mut a = genesis_entry();
        let mut b = genesis_entry();
        a.metadata.insert("key".into(), serde_json::json!("val_a"));
        b.metadata.insert("key".into(), serde_json::json!("val_b"));
        assert_ne!(a, b);
    }

    // ── AuditEntryBuilder extended ───────────────────────────────────────

    #[test]
    fn builder_chain_of_entries() {
        let e0 = AuditEntryBuilder::new()
            .id("e-0")
            .event_type(event_types::CAPABILITY_INVOKE)
            .actor("user:alice")
            .zone_id("z:work")
            .seq(0)
            .occurred_at(1_000)
            .build()
            .unwrap();

        let e1 = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::SECRET_ACCESS)
            .actor("user:bob")
            .zone_id("z:work")
            .seq(1)
            .occurred_at(2_000)
            .prev(&e0.id)
            .correlation_id("corr-1")
            .build()
            .unwrap();

        assert!(e0.is_genesis());
        assert!(e1.follows(&e0));
    }

    #[test]
    fn builder_with_all_optional_fields_roundtrip() {
        let entry = AuditEntryBuilder::new()
            .id("e-full")
            .event_type(event_types::ELEVATION_GRANTED)
            .severity(Severity::Warning)
            .actor("admin:root")
            .zone_id("z:secure")
            .seq(42)
            .occurred_at(1_700_000_000)
            .prev("e-41")
            .correlation_id("corr-xyz")
            .trace_context(TraceContext::new("trace-full", "span-full").with_flags(0x01))
            .connector_id("fcp.slack:base:v2")
            .operation_id("list_channels")
            .meta("source", serde_json::json!("api"))
            .meta("latency_ms", serde_json::json!(150))
            .build()
            .unwrap();

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn builder_severity_explicit_override_lower() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::SECURITY_VIOLATION)
            .severity(Severity::Info) // explicitly override auto Error to Info
            .actor("a")
            .zone_id("z")
            .seq(0)
            .occurred_at(0)
            .build()
            .unwrap();
        assert_eq!(entry.severity, Severity::Info);
    }

    #[test]
    fn builder_empty_strings_for_required_fields() {
        let entry = AuditEntryBuilder::new()
            .id("")
            .event_type("")
            .actor("")
            .zone_id("")
            .seq(0)
            .occurred_at(0)
            .build()
            .unwrap();
        assert_eq!(entry.id, "");
        assert_eq!(entry.event_type, "");
    }

    #[test]
    fn builder_error_is_audit_error() {
        let err = AuditEntryBuilder::new().build().unwrap_err();
        let _: &AuditError = &err;
        assert_eq!(err.error_code(), "FCP-4000");
    }

    // ── FreshnessLevel extended ──────────────────────────────────────────

    #[test]
    fn freshness_serde_serialized_strings() {
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Fresh).unwrap(),
            "\"fresh\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Stale).unwrap(),
            "\"stale\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&FreshnessLevel::Missing).unwrap(),
            "\"missing\""
        );
    }

    #[test]
    fn freshness_serde_rejects_invalid_variant() {
        let result: Result<FreshnessLevel, _> = serde_json::from_str("\"expired\"");
        assert!(result.is_err());
    }

    #[test]
    fn freshness_serde_rejects_numeric() {
        let result: Result<FreshnessLevel, _> = serde_json::from_str("1");
        assert!(result.is_err());
    }

    #[test]
    fn freshness_ordering_all_pair_combinations() {
        let levels = [
            FreshnessLevel::Fresh,
            FreshnessLevel::Stale,
            FreshnessLevel::Degraded,
            FreshnessLevel::Missing,
        ];
        for i in 0..levels.len() {
            for j in (i + 1)..levels.len() {
                assert!(
                    levels[i] < levels[j],
                    "{:?} should be < {:?}",
                    levels[i],
                    levels[j]
                );
            }
        }
    }

    #[test]
    fn freshness_debug_format_all_variants() {
        assert_eq!(format!("{:?}", FreshnessLevel::Fresh), "Fresh");
        assert_eq!(format!("{:?}", FreshnessLevel::Stale), "Stale");
        assert_eq!(format!("{:?}", FreshnessLevel::Degraded), "Degraded");
        assert_eq!(format!("{:?}", FreshnessLevel::Missing), "Missing");
    }

    // ── AuditStatus extended ─────────────────────────────────────────────

    #[test]
    fn audit_status_fresh_with_full_coverage() {
        let status = AuditStatus::fresh(999, 1.0);
        assert_eq!(status.freshness, FreshnessLevel::Fresh);
        assert_eq!(status.coverage, Some(1.0));
    }

    #[test]
    fn audit_status_fresh_with_zero_coverage() {
        let status = AuditStatus::fresh(0, 0.0);
        assert_eq!(status.head_seq, Some(0));
        assert_eq!(status.coverage, Some(0.0));
    }

    #[test]
    fn audit_status_with_reason_chain() {
        let status = AuditStatus::missing().with_reason("no data source configured");
        assert_eq!(status.reason, Some("no data source configured".to_string()));
        assert_eq!(status.freshness, FreshnessLevel::Missing);
    }

    #[test]
    fn audit_status_display_with_reason_does_not_include_reason() {
        let status = AuditStatus::fresh(10, 0.5).with_reason("test");
        let display = status.to_string();
        // Display only shows freshness, seq, coverage — not reason
        assert!(display.contains("fresh"));
        assert!(display.contains("seq=10"));
        assert!(display.contains("50.0%"));
    }

    #[test]
    fn audit_status_eq_same_data() {
        let a = AuditStatus::fresh(50, 0.75);
        let b = AuditStatus::fresh(50, 0.75);
        assert_eq!(a, b);
    }

    #[test]
    fn audit_status_ne_different_freshness() {
        let a = AuditStatus::fresh(50, 0.75);
        let b = AuditStatus::missing();
        assert_ne!(a, b);
    }

    #[test]
    fn audit_status_serde_missing_status_roundtrip() {
        let status = AuditStatus::missing();
        let json = serde_json::to_string(&status).unwrap();
        let parsed: AuditStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
    }

    #[test]
    fn audit_status_serde_with_all_fields() {
        let status = AuditStatus {
            freshness: FreshnessLevel::Stale,
            head_seq: Some(42),
            coverage: Some(0.333),
            reason: Some("behind by 3 epochs".into()),
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: AuditStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);
    }

    #[test]
    fn audit_status_display_stale() {
        let status = AuditStatus {
            freshness: FreshnessLevel::Stale,
            head_seq: Some(5),
            coverage: None,
            reason: None,
        };
        let display = status.to_string();
        assert!(display.contains("stale"));
        assert!(display.contains("seq=5"));
        assert!(!display.contains("coverage"));
    }

    #[test]
    fn audit_status_display_degraded_no_seq() {
        let status = AuditStatus {
            freshness: FreshnessLevel::Degraded,
            head_seq: None,
            coverage: Some(0.1),
            reason: None,
        };
        let display = status.to_string();
        assert!(display.contains("degraded"));
        assert!(display.contains("10.0%"));
        assert!(!display.contains("seq="));
    }

    // ── Cross-type integration tests ─────────────────────────────────────

    #[test]
    fn build_chain_verify_and_filter() {
        let e0 = with_computed_id(
            AuditEntryBuilder::new()
                .id("chain-0")
                .event_type(event_types::CAPABILITY_INVOKE)
                .actor("user:alice")
                .zone_id("z:work")
                .seq(0)
                .occurred_at(1_000)
                .connector_id("fcp.telegram:base:v1")
                .operation_id("send_message")
                .build()
                .unwrap(),
        );

        let e1 = with_computed_id(
            AuditEntryBuilder::new()
                .id("chain-1")
                .event_type(event_types::SECRET_ACCESS)
                .actor("user:bob")
                .zone_id("z:work")
                .seq(1)
                .occurred_at(2_000)
                .prev(&e0.id)
                .correlation_id("corr-1")
                .build()
                .unwrap(),
        );

        let e2 = with_computed_id(
            AuditEntryBuilder::new()
                .id("chain-2")
                .event_type(event_types::SECURITY_VIOLATION)
                .actor("user:eve")
                .zone_id("z:work")
                .seq(2)
                .occurred_at(3_000)
                .prev(&e1.id)
                .build()
                .unwrap(),
        );

        // Verify chain is valid
        let entries = [e0.clone(), e1.clone(), e2.clone()];
        let report = verify_chain(&entries, None, Some("z:work"));
        assert!(report.status.is_ok());

        // Filter by actor
        let filter_alice = AuditFilter {
            actor: Some("user:alice".into()),
            ..Default::default()
        };
        assert!(filter_alice.matches(&e0));
        assert!(!filter_alice.matches(&e1));
        assert!(!filter_alice.matches(&e2));

        // Filter by severity
        let filter_error = AuditFilter {
            min_severity: Some(Severity::Error),
            ..Default::default()
        };
        assert!(!filter_error.matches(&e0)); // Info
        assert!(!filter_error.matches(&e1)); // Warning
        assert!(filter_error.matches(&e2)); // Error
    }

    #[derive(serde::Serialize)]
    struct TestConstraintDescriptor<'a> {
        request_id: &'a str,
        connector_id: &'a str,
        operation_id: &'a str,
        zone_id: &'a str,
        resource_uri: &'a str,
        payload_hash: &'a str,
        observed_calls: u32,
    }

    fn test_constraint_descriptor() -> TestConstraintDescriptor<'static> {
        TestConstraintDescriptor {
            request_id: "req-constraint-001",
            connector_id: "fcp.test.audit:utility:1.0.0",
            operation_id: "test.echo",
            zone_id: "z:work",
            resource_uri: "/messages/123",
            payload_hash: "payload-hash-only",
            observed_calls: 1,
        }
    }

    #[test]
    fn capability_constraint_descriptor_hash_is_deterministic()
    -> Result<(), Box<dyn std::error::Error>> {
        let descriptor = test_constraint_descriptor();
        let first = capability_constraint_request_descriptor_hash(&descriptor)?;
        let second = capability_constraint_request_descriptor_hash(&descriptor)?;

        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|ch| ch.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn capability_constraint_denied_entry_is_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let descriptor = test_constraint_descriptor();
        let request_descriptor_hash = capability_constraint_request_descriptor_hash(&descriptor)?;
        let raw_payload = "secret input body that must never appear in audit metadata";

        let entry = AuditEntryBuilder::new()
            .id("entry-constraint-denied")
            .actor("agent:auditor")
            .zone_id("z:work")
            .seq(1)
            .occurred_at(1_700_000_060)
            .correlation_id("req-constraint-001")
            .connector_id("fcp.test.audit:utility:1.0.0")
            .operation_id("test.echo")
            .capability_constraint_denied(CapabilityConstraintDenied::new(
                "scope_ceiling_exceeded",
                "calls=1,max_calls=0",
                request_descriptor_hash.clone(),
                "node:fcp-host-1",
                1_700_000_060,
            ))
            .build()?;

        assert_eq!(entry.event_type, event_types::CAPABILITY_CONSTRAINT_DENIED);
        assert_eq!(entry.severity, Severity::Warning);
        assert_eq!(
            entry.metadata.get("request_descriptor_hash"),
            Some(&serde_json::json!(request_descriptor_hash))
        );
        assert!(!entry.metadata.contains_key("payload"));
        assert!(!entry.metadata.contains_key("raw_payload"));

        let json = serde_json::to_string(&entry)?;
        assert!(!json.contains(raw_payload));
        Ok(())
    }

    #[test]
    fn capability_constraint_denied_entry_preserves_hash_link_continuity()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = with_computed_id(
            AuditEntryBuilder::new()
                .id("constraint-chain-0")
                .event_type(event_types::CAPABILITY_INVOKE)
                .actor("agent:auditor")
                .zone_id("z:work")
                .seq(0)
                .occurred_at(1_700_000_000)
                .build()?,
        );
        let request_descriptor_hash =
            capability_constraint_request_descriptor_hash(&test_constraint_descriptor())?;
        let denial = with_computed_id(
            AuditEntryBuilder::new()
                .id("constraint-chain-1")
                .actor("agent:auditor")
                .zone_id("z:work")
                .seq(1)
                .occurred_at(1_700_000_060)
                .prev(&genesis.id)
                .capability_constraint_denied(CapabilityConstraintDenied::new(
                    "scope_ceiling_exceeded",
                    "calls=1,max_calls=0",
                    request_descriptor_hash,
                    "node:fcp-host-1",
                    1_700_000_060,
                ))
                .build()?,
        );

        assert!(denial.follows(&genesis));
        let report = verify_chain(&[genesis, denial], None, Some("z:work"));
        assert!(report.status.is_ok(), "{report:?}");
        Ok(())
    }

    #[test]
    fn capability_constraint_denied_entry_cbor_is_deterministic()
    -> Result<(), Box<dyn std::error::Error>> {
        let hash = capability_constraint_request_descriptor_hash(&test_constraint_descriptor())?;
        let build_entry = || -> Result<AuditEntry, AuditError> {
            AuditEntryBuilder::new()
                .id("constraint-cbor")
                .actor("agent:auditor")
                .zone_id("z:work")
                .seq(7)
                .occurred_at(1_700_000_420)
                .capability_constraint_denied(CapabilityConstraintDenied::new(
                    "resource_uri_not_in_allowlist",
                    "/admin/keys",
                    hash.clone(),
                    "node:fcp-host-1",
                    1_700_000_420,
                ))
                .build()
        };

        let first = fcp_cbor::to_canonical_cbor(&build_entry()?)?;
        let second = fcp_cbor::to_canonical_cbor(&build_entry()?)?;
        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn decision_receipt_with_audit_entry_correlation() {
        let entry = AuditEntryBuilder::new()
            .id("e-1")
            .event_type(event_types::CAPABILITY_INVOKE)
            .actor("user:alice")
            .zone_id("z:work")
            .seq(0)
            .occurred_at(1_000)
            .correlation_id("request-abc")
            .build()
            .unwrap();

        let request_id = entry.correlation_id.clone();
        let evidence_id = entry.id.clone();
        let receipt = DecisionReceipt {
            id: "receipt-1".into(),
            request_id,
            decision: Decision::Allow,
            reason_code: "policy.match".into(),
            evidence: vec![evidence_id],
            audit_entry_id: Some(entry.id.clone()),
            explanation: Some("Matched wildcard capability grant".into()),
            decided_at: 1_001,
            zone_id: entry.zone_id,
            correlation_id: Some(entry.correlation_id.clone()),
            trace_context: entry.trace_context.clone(),
            connector_id: entry.connector_id.clone(),
            operation_id: entry.operation_id,
            confidence: None,
            issuer_kid: None,
            signature: None,
        };

        assert!(receipt.is_allow());
        assert_eq!(receipt.evidence_count(), 1);
        assert_eq!(receipt.evidence[0], "e-1");
        assert_eq!(receipt.audit_entry_id.as_deref(), Some("e-1"));
        assert_eq!(receipt.request_id, "request-abc");
    }

    #[test]
    fn verify_chain_with_head_and_filter_integration() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let e2 = chain_entry(2, "entry-1");
        let entries = [e0, e1.clone(), e2];

        let head = sample_head("entry-2", 2);
        let report = verify_chain(&entries, Some(&head), Some("z:work"));
        assert!(report.status.is_ok());
        assert_eq!(report.head_seq, Some(2));
        assert_eq!(report.head_entry, Some(head.head_entry));
        assert_eq!(report.zone_id, Some("z:work".into()));

        // e1 has Warning severity (chain_entry sets it)
        let filter = AuditFilter {
            min_severity: Some(Severity::Warning),
            ..Default::default()
        };
        assert!(filter.matches(&e1));
    }

    // ── DecisionReceipt signing / tamper-detection (br-17l4c) ────────────

    #[test]
    fn decision_receipt_sign_then_verify_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut receipt = sample_receipt();

        receipt.sign(&signing_key).expect("sign must succeed");
        assert!(
            receipt.issuer_kid.is_some(),
            "sign must populate issuer_kid"
        );
        assert!(receipt.signature.is_some(), "sign must populate signature");
        assert_eq!(
            receipt.issuer_kid.as_ref().unwrap().as_slice(),
            signing_key.key_id().as_slice(),
        );

        receipt
            .verify_signature(&verifying_key)
            .expect("self-issued signature must verify");
    }

    #[test]
    fn decision_receipt_unsigned_verify_reports_signer_missing() {
        // The empty-path rollout cohort: a receipt with no signature
        // must surface as SignerMissing, distinguishable from
        // SignatureInvalid so operators can count "legacy unsigned
        // receipts still in flight" separately from "tampered".
        let verifying_key = Ed25519SigningKey::generate().verifying_key();
        let receipt = sample_receipt();

        let err = receipt
            .verify_signature(&verifying_key)
            .expect_err("unsigned receipt must not verify");
        assert!(
            matches!(err, AuditError::SignerMissing { .. }),
            "expected SignerMissing, got {err:?}"
        );
    }

    #[test]
    fn decision_receipt_tamper_decision_field_is_detected() {
        // The canonical tamper-detection regression for bead
        // flywheel_connectors-17l4c: a receipt with a valid signature
        // whose `decision` is mutated after signing MUST fail
        // verify_signature. Pre-patch this was undetectable because
        // DecisionReceipt had no signature at all; post-patch the
        // signature transcript binds every field that participates
        // in computed_id, so any mutation breaks verification.
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut receipt = sample_receipt();

        receipt.sign(&signing_key).expect("sign must succeed");

        // Flip Allow → Deny. Signature bytes are untouched.
        receipt.decision = Decision::Deny;

        let err = receipt
            .verify_signature(&verifying_key)
            .expect_err("tampered receipt must not verify");
        assert!(
            matches!(err, AuditError::SignatureInvalid { .. }),
            "expected SignatureInvalid, got {err:?}"
        );
    }

    #[test]
    fn decision_receipt_tamper_reason_code_is_detected() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut receipt = sample_receipt();

        receipt.sign(&signing_key).expect("sign must succeed");
        // `reason_code` is the single field most likely to drift in
        // an attacker's favour (e.g. "policy.denied" → "policy.match").
        receipt.reason_code = "policy.override".to_string();

        let err = receipt
            .verify_signature(&verifying_key)
            .expect_err("reason_code mutation must break the signature");
        assert!(matches!(err, AuditError::SignatureInvalid { .. }));
    }

    #[test]
    fn decision_receipt_tamper_explanation_is_detected() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut receipt = sample_receipt();

        receipt.sign(&signing_key).expect("sign must succeed");
        receipt.explanation = Some("mutated explanation after signing".into());

        let err = receipt
            .verify_signature(&verifying_key)
            .expect_err("explanation mutation must break the signature");
        assert!(matches!(err, AuditError::SignatureInvalid { .. }));
    }

    #[test]
    fn decision_receipt_verify_rejects_key_id_mismatch() {
        // Signed with key A, verified with key B whose kid differs.
        // Must fail with SignatureInvalid before even reaching the
        // Ed25519 verify call, since the kid-binding step returns
        // first — the id field is not trusted for this check.
        let signer_a = Ed25519SigningKey::generate();
        let verifier_b = Ed25519SigningKey::generate().verifying_key();
        // Distinct keys imply distinct kids with overwhelming probability.
        assert_ne!(
            signer_a.verifying_key().key_id().as_slice(),
            verifier_b.key_id().as_slice()
        );

        let mut receipt = sample_receipt();
        receipt.sign(&signer_a).expect("sign must succeed");

        let err = receipt
            .verify_signature(&verifier_b)
            .expect_err("cross-key verification must not succeed");
        assert!(matches!(err, AuditError::SignatureInvalid { .. }));
    }

    #[test]
    fn decision_receipt_computed_id_is_deterministic() {
        // The id-recompute path is stable under repeated calls and
        // across clones — a regression that accidentally mixed in an
        // RNG / timestamp / thread-id would surface here before the
        // signature round-trip obscures it.
        let receipt = sample_receipt();
        let a = receipt.computed_id().expect("computed_id 1");
        let b = receipt.computed_id().expect("computed_id 2");
        let c = receipt.computed_id().expect("computed_id cloned");
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn verify_chain_rejects_forged_ids_even_when_links_match_forged_values() {
        let mut e0 = genesis_entry();
        e0.id = "forged-entry-0".to_string();

        let mut e1 = chain_entry(1, "entry-0");
        e1.prev = Some(e0.id.clone());
        e1.id = "forged-entry-1".to_string();

        let head = ChainHead {
            zone_id: "z:work".to_string(),
            head_entry: e1.id.clone(),
            head_seq: 1,
            coverage: 1.0,
            epoch_id: "epoch-attack".to_string(),
            signature_count: 1,
            signatures: sample_signatures(1),
        };

        let report = verify_chain(&[e0, e1], Some(&head), None);
        assert!(report.status.is_fail());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "audit.object_id_mismatch")
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "audit.prev_mismatch")
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "audit.head_mismatch")
        );
    }

    #[test]
    fn verify_report_from_chain_then_serde() {
        let e0 = genesis_entry();
        let e1 = chain_entry(1, "entry-0");
        let head = sample_head("entry-1", 1);
        let report = verify_chain(&[e0, e1], Some(&head), Some("z:work"));

        let json = serde_json::to_string(&report).unwrap();
        let parsed: VerifyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
    }

    // ── VerifyIssue with_entry_id type variations ────────────────────────

    #[test]
    fn verify_issue_with_entry_id_string_ref() {
        let id = "entry-42".to_string();
        let issue = VerifyIssue::new("code", "msg").with_entry_id(&id);
        assert_eq!(issue.entry_id, Some("entry-42".into()));
    }

    #[test]
    fn verify_issue_with_entry_id_owned_string() {
        let issue = VerifyIssue::new("code", "msg").with_entry_id("owned".to_string());
        assert_eq!(issue.entry_id, Some("owned".into()));
    }

    #[test]
    fn verify_issue_serde_all_fields() {
        let issue = VerifyIssue::new("audit.seq_gap", "expected 5, found 7")
            .with_seq(7)
            .with_entry_id("entry-7");
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("\"seq\":7"));
        assert!(json.contains("\"entry_id\":\"entry-7\""));
        let parsed: VerifyIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(issue, parsed);
    }

    #[test]
    fn verify_issue_debug_with_context() {
        let issue = VerifyIssue::new("audit.fork_detected", "fork")
            .with_seq(10)
            .with_entry_id("e-10");
        let debug = format!("{issue:?}");
        assert!(debug.contains("VerifyIssue"));
        assert!(debug.contains("fork_detected"));
        assert!(debug.contains("10"));
    }

    // ── Severity boundary behavior ───────────────────────────────────────

    #[test]
    fn severity_all_variants_to_string_roundtrip() {
        for sev in [
            Severity::Info,
            Severity::Warning,
            Severity::Error,
            Severity::Critical,
        ] {
            let s = sev.to_string();
            let json_str = format!("\"{s}\"");
            let parsed: Severity = serde_json::from_str(&json_str).unwrap();
            assert_eq!(sev, parsed);
        }
    }

    #[test]
    fn severity_for_event_type_case_sensitive() {
        // Event types are case-sensitive; "Secret.Access" != "secret.access"
        assert_eq!(Severity::for_event_type("Secret.Access"), Severity::Info);
        assert_eq!(Severity::for_event_type("secret.access"), Severity::Warning);
    }

    // ── Decision exhaustive ──────────────────────────────────────────────

    #[test]
    fn decision_allow_and_deny_are_only_variants() {
        let allow = Decision::Allow;
        let deny = Decision::Deny;
        assert!(allow.is_allow() && !allow.is_deny());
        assert!(deny.is_deny() && !deny.is_allow());
    }

    #[test]
    fn decision_eq_reflexive() {
        assert_eq!(Decision::Allow, Decision::Allow);
        assert_eq!(Decision::Deny, Decision::Deny);
    }

    #[test]
    fn decision_ne_different() {
        assert_ne!(Decision::Allow, Decision::Deny);
    }

    // ── VerifyStatus serde boundary ──────────────────────────────────────

    #[test]
    fn verify_status_serde_case_sensitive() {
        let ok: Result<VerifyStatus, _> = serde_json::from_str("\"Ok\"");
        assert!(ok.is_err()); // Should be "ok" lowercase
    }

    #[test]
    fn verify_status_serde_null_rejected() {
        let result: Result<VerifyStatus, _> = serde_json::from_str("null");
        assert!(result.is_err());
    }

    // ── TraceContext W3C format ───────────────────────────────────────────

    #[test]
    fn trace_context_w3c_format_structure() {
        let tc = TraceContext::new("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331")
            .with_flags(0x01);
        let display = tc.to_string();
        let parts: Vec<&str> = display.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "00"); // version
        assert_eq!(parts[1], "0af7651916cd43dd8448eb211c80319c"); // trace-id
        assert_eq!(parts[2], "b7ad6b7169203331"); // span-id
        assert_eq!(parts[3], "01"); // flags
    }

    // ── AuditEntry metadata type coverage ────────────────────────────────

    #[test]
    fn audit_entry_metadata_number_types() {
        let mut entry = genesis_entry();
        entry.metadata.insert("int".into(), serde_json::json!(42));
        entry
            .metadata
            .insert("float".into(), serde_json::json!(1.23));
        entry
            .metadata
            .insert("negative".into(), serde_json::json!(-100));
        entry.metadata.insert("zero".into(), serde_json::json!(0));

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.metadata.get("int"), Some(&serde_json::json!(42)));
        assert_eq!(parsed.metadata.get("float"), Some(&serde_json::json!(1.23)));
        assert_eq!(
            parsed.metadata.get("negative"),
            Some(&serde_json::json!(-100))
        );
    }

    #[test]
    fn audit_entry_metadata_boolean_and_null() {
        let mut entry = genesis_entry();
        entry
            .metadata
            .insert("flag_true".into(), serde_json::json!(true));
        entry
            .metadata
            .insert("flag_false".into(), serde_json::json!(false));
        entry
            .metadata
            .insert("nothing".into(), serde_json::Value::Null);

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.metadata.len(), 3);
    }

    #[test]
    fn audit_entry_metadata_array_value() {
        let mut entry = genesis_entry();
        entry
            .metadata
            .insert("tags".into(), serde_json::json!(["a", "b", "c"]));

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.metadata.get("tags"),
            Some(&serde_json::json!(["a", "b", "c"]))
        );
    }

    // ── VerifyReport with zone_id ────────────────────────────────────────

    #[test]
    fn verify_report_serde_with_zone_and_head() {
        let report = VerifyReport {
            status: VerifyStatus::Warn,
            zone_id: Some("z:prod".into()),
            chain_len: 100,
            head_seq: Some(99),
            head_entry: Some("entry-99".into()),
            issues: vec![VerifyIssue::new("audit.zone_mismatch", "mismatch").with_seq(50)],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: VerifyReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
        assert_eq!(parsed.issues.len(), 1);
        assert_eq!(parsed.issues[0].seq, Some(50));
    }

    #[test]
    fn verify_report_display_warn_status() {
        let report = VerifyReport {
            status: VerifyStatus::Warn,
            zone_id: None,
            chain_len: 42,
            head_seq: None,
            head_entry: None,
            issues: vec![VerifyIssue::new("warn.test", "warning")],
        };
        let display = report.to_string();
        assert!(display.contains("warn"));
        assert!(display.contains("chain_len=42"));
        assert!(display.contains("issues=1"));
    }

    // ── AuditFilter edge: empty string matches ──────────────────────────

    #[test]
    fn filter_empty_string_actor_matches_empty_actor_entry() {
        let filter = AuditFilter {
            actor: Some(String::new()),
            ..Default::default()
        };
        let mut entry = genesis_entry();
        entry.actor = String::new();
        assert!(filter.matches(&entry));
    }

    #[test]
    fn filter_empty_string_actor_does_not_match_nonempty() {
        let filter = AuditFilter {
            actor: Some(String::new()),
            ..Default::default()
        };
        assert!(!filter.matches(&genesis_entry())); // genesis has "user:alice"
    }

    // ── ChainHead coverage boundary ─────────────────────────────────────

    #[test]
    fn chain_head_meets_coverage_negative_threshold() {
        let head = sample_head("e", 0);
        // coverage is 0.85, any negative threshold should pass
        assert!(head.meets_coverage(-1.0));
    }

    #[test]
    fn chain_head_meets_coverage_above_one() {
        let mut head = sample_head("e", 0);
        head.coverage = 1.5; // unusual but technically possible
        assert!(head.meets_coverage(1.0));
        assert!(head.meets_coverage(1.5));
        assert!(!head.meets_coverage(1.6));
    }

    // ── Miscellaneous ───────────────────────────────────────────────────

    #[test]
    fn verify_chain_single_entry_with_matching_head() {
        let e0 = genesis_entry();
        let head = sample_head("entry-0", 0);
        let report = verify_chain(&[e0], Some(&head), None);
        assert!(report.status.is_ok());
    }

    #[test]
    fn verify_chain_fork_does_not_count_same_id_at_same_seq() {
        let e0 = genesis_entry();
        let e0_same = genesis_entry(); // identical
        let report = verify_chain(&[e0, e0_same], None, None);
        let forks = report
            .issues
            .iter()
            .filter(|i| i.code == "audit.fork_detected")
            .count();
        assert_eq!(forks, 0);
    }

    #[test]
    fn audit_entry_is_genesis_both_conditions_required() {
        // seq=0 but has prev -> not genesis
        let mut e = genesis_entry();
        e.prev = Some("prev".into());
        assert!(!e.is_genesis());

        // no prev but seq!=0 -> not genesis
        let mut e2 = genesis_entry();
        e2.seq = 1;
        assert!(!e2.is_genesis());
    }

    #[test]
    fn audit_error_debug_includes_variant_and_data() {
        let err = AuditError::BuilderMissingField("event_type".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("BuilderMissingField"));
        assert!(debug.contains("event_type"));
    }

    #[test]
    fn freshness_is_healthy_only_for_fresh() {
        assert!(FreshnessLevel::Fresh.is_healthy());
        for level in [
            FreshnessLevel::Stale,
            FreshnessLevel::Degraded,
            FreshnessLevel::Missing,
        ] {
            assert!(!level.is_healthy(), "{level:?} should not be healthy");
        }
    }

    #[test]
    fn verify_status_is_ok_only_for_ok() {
        assert!(VerifyStatus::Ok.is_ok());
        assert!(!VerifyStatus::Warn.is_ok());
        assert!(!VerifyStatus::Fail.is_ok());
    }

    #[test]
    fn verify_status_is_fail_only_for_fail() {
        assert!(VerifyStatus::Fail.is_fail());
        assert!(!VerifyStatus::Ok.is_fail());
        assert!(!VerifyStatus::Warn.is_fail());
    }

    #[test]
    fn audit_status_serde_from_json_fresh() {
        let json = r#"{"freshness":"fresh","head_seq":10,"coverage":0.9}"#;
        let status: AuditStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.freshness, FreshnessLevel::Fresh);
        assert_eq!(status.head_seq, Some(10));
    }

    #[test]
    fn audit_status_serde_from_json_minimal() {
        let json = r#"{"freshness":"missing"}"#;
        let status: AuditStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.freshness, FreshnessLevel::Missing);
        assert!(status.head_seq.is_none());
    }
}
