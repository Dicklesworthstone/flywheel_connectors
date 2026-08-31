//! Distributed lease coordination (NORMATIVE).
//!
//! Implements the lease semantics defined in `FCP_Specification_V3.md` §11.3 (Leases).
//!
//! # Core Concepts
//!
//! - **Lease**: Exclusive, timed ownership of a (zone, subject) pair.
//! - **Fencing Token**: `lease_seq` ensures monotonicity and fencing of stale writes.
//! - **Granularity**: Leases are per-object or per-singleton-role.
//!
//! # Invariants
//!
//! - `ConnectorState` writes (`singleton_writer` fencing)
//! - `ZoneCheckpoint` advancement (coordinator election)
//! - Exclusive resource access (e.g., specific hardware)
use fcp_cbor::SchemaId;
use fcp_crypto::{canonical_signing_bytes, canonicalize::to_deterministic_cbor};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ObjectHeader, ObjectId, SignatureSet, TailscaleNodeId, ZoneId};

/// Domain-separated schema ID for quorum signatures over durable lease authority.
pub const LEASE_QUORUM_SIGNING_SCHEMA_ID: &str = "fcp.lease.quorum-signing.v1";

/// Get current Unix timestamp in seconds.
///
/// Returns 0 if the system clock is before the Unix epoch (e.g.,
/// misconfigured containers or embedded devices), rather than panicking.
#[must_use]
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease Purpose (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Lease purpose discriminant (NORMATIVE).
///
/// Defines what a lease authorizes. Each purpose has specific semantics:
///
/// - `OperationExecution`: Prevents duplicate execution of operations with side effects.
///   Used by the exactly-once semantics system (see §15 OperationIntent/Receipt).
///
/// - `ConnectorStateWrite`: Serializes writes to `SingleWriter` connector state.
///   Only the lease holder may write to the associated state object.
///
/// - `ComputationMigration`: Coordinates computation migration between nodes.
///   Ensures safe handoffs during device changes or load balancing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeasePurpose {
    /// Prevents duplicate execution of operations with side effects.
    OperationExecution,
    /// Serializes writes to `SingleWriter` connector state.
    ConnectorStateWrite,
    /// Coordinates computation migration between nodes.
    ComputationMigration,
    /// Elects a coordinator for a zone.
    CoordinatorElection,
    /// Locks a computation for migration.
    Migration,
    /// Exclusive access to a resource.
    ResourceAccess,
}

impl std::fmt::Display for LeasePurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperationExecution => write!(f, "operation_execution"),
            Self::ConnectorStateWrite => write!(f, "connector_state_write"),
            Self::ComputationMigration => write!(f, "computation_migration"),
            Self::CoordinatorElection => write!(f, "coordinator_election"),
            Self::Migration => write!(f, "migration"),
            Self::ResourceAccess => write!(f, "resource_access"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Generic lease primitive (NORMATIVE).
///
/// A short-lived, renewable lock that says:
/// "node X owns subject S for purpose P until time T."
///
/// # Fencing Token Semantics
///
/// The `lease_seq` is critical for safety:
/// - Monotonically increases per (`zone_id`, `subject_object_id`)
/// - Higher `lease_seq` wins deterministically, regardless of wall-clock expiry
/// - Prevents "zombie lease" problems
///
/// # Coordinator Selection
///
/// The coordinator is selected via HRW/Rendezvous hashing over
/// `(zone_id, subject_object_id)`. This ensures deterministic, consistent
/// selection without a central coordinator.
///
/// # Quorum Requirements
///
/// - Safe ops: Single coordinator signature may be sufficient
/// - Risky ops: Require f+1 signatures
/// - Dangerous ops: Require n-f signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Object header (includes zone, schema, etc).
    pub header: ObjectHeader,

    /// Node holding the lease.
    pub holder: TailscaleNodeId,

    /// Lease sequence number (monotonic).
    ///
    /// - Monotonically increases per (`zone_id`, `subject_object_id`)
    /// - Higher `lease_seq` wins deterministically, regardless of wall-clock expiry
    pub lease_seq: u64,

    /// Expiration timestamp (Unix seconds).
    pub exp: u64,

    /// Subject being leased (e.g., connector state ID).
    pub subject_object_id: ObjectId,

    /// What this lease authorizes.
    pub purpose: LeasePurpose,

    /// Quorum signatures (NORMATIVE for Risky/Dangerous).
    pub quorum_signatures: SignatureSet,
}

/// Input parameters for creating a new lease.
#[derive(Debug, Clone)]
pub struct LeaseParams {
    pub schema: SchemaId,
    pub zone_id: ZoneId,
    pub holder: TailscaleNodeId,
    pub lease_seq: u64,
    pub ttl_secs: u32,
    pub subject_object_id: ObjectId,
    pub provenance: crate::Provenance,
    pub purpose: LeasePurpose,
    pub quorum_signatures: SignatureSet,
}

#[derive(Debug, Serialize)]
struct LeaseQuorumSignable<'a> {
    header: &'a ObjectHeader,
    holder: &'a TailscaleNodeId,
    lease_seq: u64,
    exp: u64,
    subject_object_id: &'a ObjectId,
    purpose: LeasePurpose,
}

/// Canonical identifier for a lease object referenced elsewhere in the mesh.
pub type LeaseId = ObjectId;

/// Display-safe opaque identifier for lease authority references.
///
/// A `LeaseToken` is not a secret. It is a stable, log-safe handle for
/// referencing lease authority in receipts, handoff records, and audit trails
/// without serializing the full lease object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LeaseToken(String);

impl LeaseToken {
    const PREFIX: &'static str = "lease:";
    const MAX_LEN: usize = 256;

    /// Create a new lease token identifier.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseTokenParseError`] if the token is not in canonical
    /// `lease:<identifier>` form.
    pub fn new(token: impl Into<String>) -> Result<Self, LeaseTokenParseError> {
        Self::try_from(token.into())
    }

    /// Return the token identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LeaseToken {
    type Error = LeaseTokenParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_lease_token(&value)?;
        Ok(Self(value))
    }
}

impl From<LeaseToken> for String {
    fn from(value: LeaseToken) -> Self {
        value.0
    }
}

impl std::str::FromStr for LeaseToken {
    type Err = LeaseTokenParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl std::fmt::Display for LeaseToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn validate_lease_token(value: &str) -> Result<(), LeaseTokenParseError> {
    if value.is_empty() {
        return Err(LeaseTokenParseError::Empty);
    }

    if value.len() > LeaseToken::MAX_LEN {
        return Err(LeaseTokenParseError::TooLong {
            len: value.len(),
            max: LeaseToken::MAX_LEN,
        });
    }

    let Some(identifier) = value.strip_prefix(LeaseToken::PREFIX) else {
        return Err(LeaseTokenParseError::MissingPrefix);
    };

    if identifier.is_empty() {
        return Err(LeaseTokenParseError::MissingIdentifier);
    }

    for (relative_index, ch) in identifier.char_indices() {
        let index = LeaseToken::PREFIX.len() + relative_index;
        let first_char = relative_index == 0;
        let valid =
            ch.is_ascii_alphanumeric() || (!first_char && matches!(ch, '-' | '_' | '.' | ':'));

        if !valid {
            return Err(LeaseTokenParseError::InvalidChar { ch, index });
        }
    }

    Ok(())
}

/// Error returned when parsing a [`LeaseToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseTokenParseError {
    /// The token was empty.
    Empty,
    /// The token did not start with the canonical `lease:` prefix.
    MissingPrefix,
    /// The token had no identifier after the canonical prefix.
    MissingIdentifier,
    /// The token exceeded the maximum supported byte length.
    TooLong {
        /// Actual token length in bytes.
        len: usize,
        /// Maximum supported token length in bytes.
        max: usize,
    },
    /// The token contained a character outside the display-safe grammar.
    InvalidChar {
        /// Invalid character.
        ch: char,
        /// Byte index of the invalid character.
        index: usize,
    },
}

impl std::fmt::Display for LeaseTokenParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("lease token must not be empty"),
            Self::MissingPrefix => f.write_str("lease token must start with 'lease:'"),
            Self::MissingIdentifier => f.write_str("lease token identifier must not be empty"),
            Self::TooLong { len, max } => {
                write!(f, "lease token too long ({len} bytes > {max} bytes)")
            }
            Self::InvalidChar { ch, index } => write!(
                f,
                "lease token contains invalid character '{ch}' at byte {index}"
            ),
        }
    }
}

impl std::error::Error for LeaseTokenParseError {}

/// Auditable transfer of exclusive execution authority between nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseHandoff {
    /// Lease being relinquished by the source holder.
    pub previous_lease_id: LeaseId,
    /// Lease that the target holder will resume under.
    pub next_lease_id: LeaseId,
    /// Node that currently holds the lease.
    pub from_holder: TailscaleNodeId,
    /// Node that is receiving the lease.
    pub to_holder: TailscaleNodeId,
    /// Zone in which the handoff is valid.
    pub zone_id: ZoneId,
    /// Subject covered by the lease.
    pub subject_object_id: ObjectId,
    /// Purpose preserved across the handoff.
    pub purpose: LeasePurpose,
    /// Fencing token held by the source lease.
    pub previous_fencing_token: u64,
    /// Fencing token that the target must resume under.
    pub next_fencing_token: u64,
    /// Unix timestamp when the handoff was authorized.
    pub transferred_at: u64,
    /// Optional checkpoint object that the target must reconstruct before resume.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_object_id: Option<ObjectId>,
}

impl Lease {
    /// Canonical schema identifier for durable lease authority objects.
    #[must_use]
    pub fn schema_id() -> SchemaId {
        SchemaId::new("fcp.lease", "lease", semver::Version::new(1, 0, 0))
    }

    /// Create a new lease.
    #[must_use]
    pub fn new(params: LeaseParams) -> Self {
        let created_at = current_timestamp();
        let exp = created_at + u64::from(params.ttl_secs);

        Self {
            header: ObjectHeader {
                encryption_kind: Default::default(),
                schema: params.schema,
                zone_id: params.zone_id,
                created_at,
                provenance: params.provenance,
                refs: vec![params.subject_object_id], // Lease implicitly refs subject
                foreign_refs: vec![],
                ttl_secs: Some(u64::from(params.ttl_secs)),
                placement: None,
            },
            holder: params.holder,
            lease_seq: params.lease_seq,
            exp,
            subject_object_id: params.subject_object_id,
            purpose: params.purpose,
            quorum_signatures: params.quorum_signatures,
        }
    }

    /// Fencing token (NORMATIVE): monotonically increases per (`zone_id`, `subject_object_id`).
    #[must_use]
    pub const fn fencing_token(&self) -> u64 {
        self.lease_seq
    }

    /// Check if expired.
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        now >= self.exp
    }

    /// Get the zone ID.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Compute canonical bytes that quorum signers must sign for this lease.
    ///
    /// The signable view intentionally excludes `quorum_signatures`; otherwise
    /// each signer would need to sign a payload that already contains its own
    /// signature. The signed fields bind the lease authority context:
    /// header/zone/provenance/refs, holder, fence, expiry, subject, and purpose.
    ///
    /// # Errors
    ///
    /// Returns a crypto serialization error if deterministic CBOR encoding fails.
    pub fn quorum_signing_bytes(&self) -> fcp_crypto::CryptoResult<Vec<u8>> {
        let signable = LeaseQuorumSignable {
            header: &self.header,
            holder: &self.holder,
            lease_seq: self.lease_seq,
            exp: self.exp,
            subject_object_id: &self.subject_object_id,
            purpose: self.purpose,
        };
        let cbor = to_deterministic_cbor(&signable)?;
        Ok(canonical_signing_bytes(
            LEASE_QUORUM_SIGNING_SCHEMA_ID,
            &cbor,
        ))
    }
}

/// Errors returned when lease handoff validation fails.
#[derive(Debug, Error)]
pub enum LeaseTransferValidationError {
    #[error("cannot transfer expired lease (expired at {expired_at}, current time {now})")]
    LeaseExpired { expired_at: u64, now: u64 },
    #[error("lease handoff reused lease id {lease_id}")]
    LeaseIdReused { lease_id: LeaseId },
    #[error("lease handoff must transfer to a different holder (holder {holder:?})")]
    SelfTransfer { holder: TailscaleNodeId },
    #[error("handoff source holder mismatch: expected {expected:?}, got {got:?}")]
    FromHolderMismatch {
        expected: TailscaleNodeId,
        got: TailscaleNodeId,
    },
    #[error("handoff subject mismatch: expected {expected}, got {got}")]
    SubjectMismatch { expected: ObjectId, got: ObjectId },
    #[error("handoff zone mismatch: expected {expected}, got {got}")]
    ZoneMismatch { expected: ZoneId, got: ZoneId },
    #[error("handoff purpose mismatch: expected {expected}, got {got}")]
    PurposeMismatch {
        expected: LeasePurpose,
        got: LeasePurpose,
    },
    #[error("handoff previous fencing token mismatch: expected {expected}, got {got}")]
    PreviousFenceMismatch { expected: u64, got: u64 },
    #[error("handoff fencing token must increase monotonically (previous {previous}, next {next})")]
    NonMonotonicFence { previous: u64, next: u64 },
}

/// Validate a lease handoff before resumption on another node.
///
/// # Errors
/// Returns a [`LeaseTransferValidationError`] if the active lease does not match the
/// handoff, if the handoff is stale, or if fencing token monotonicity is violated.
pub fn validate_lease_handoff(
    active_lease: &Lease,
    handoff: &LeaseHandoff,
    now: u64,
) -> Result<(), LeaseTransferValidationError> {
    if active_lease.is_expired(now) {
        return Err(LeaseTransferValidationError::LeaseExpired {
            expired_at: active_lease.exp,
            now,
        });
    }

    if handoff.previous_lease_id == handoff.next_lease_id {
        return Err(LeaseTransferValidationError::LeaseIdReused {
            lease_id: handoff.previous_lease_id,
        });
    }

    if handoff.from_holder == handoff.to_holder {
        return Err(LeaseTransferValidationError::SelfTransfer {
            holder: handoff.from_holder.clone(),
        });
    }

    if active_lease.holder != handoff.from_holder {
        return Err(LeaseTransferValidationError::FromHolderMismatch {
            expected: active_lease.holder.clone(),
            got: handoff.from_holder.clone(),
        });
    }

    if active_lease.subject_object_id != handoff.subject_object_id {
        return Err(LeaseTransferValidationError::SubjectMismatch {
            expected: active_lease.subject_object_id,
            got: handoff.subject_object_id,
        });
    }

    if active_lease.zone_id() != &handoff.zone_id {
        return Err(LeaseTransferValidationError::ZoneMismatch {
            expected: active_lease.zone_id().clone(),
            got: handoff.zone_id.clone(),
        });
    }

    if active_lease.purpose != handoff.purpose {
        return Err(LeaseTransferValidationError::PurposeMismatch {
            expected: active_lease.purpose,
            got: handoff.purpose,
        });
    }

    if active_lease.fencing_token() != handoff.previous_fencing_token {
        return Err(LeaseTransferValidationError::PreviousFenceMismatch {
            expected: active_lease.fencing_token(),
            got: handoff.previous_fencing_token,
        });
    }

    if handoff.next_fencing_token <= handoff.previous_fencing_token {
        return Err(LeaseTransferValidationError::NonMonotonicFence {
            previous: handoff.previous_fencing_token,
            next: handoff.next_fencing_token,
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease Request
// ─────────────────────────────────────────────────────────────────────────────

/// Request to acquire or renew a lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRequest {
    /// Subject to lease.
    pub subject_object_id: ObjectId,

    /// Zone ID.
    pub zone_id: ZoneId,

    /// Requesting node.
    pub requester: TailscaleNodeId,

    /// Requested TTL in seconds.
    pub requested_ttl: u32,

    /// If renewing, the current `lease_seq` being held.
    pub renew_seq: Option<u64>,
}

/// Response to a lease request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LeaseResponse {
    /// Lease granted.
    Granted(Box<Lease>),

    /// Lease denied (held by another or stale renew).
    Denied {
        /// Current lease holder.
        current_holder: TailscaleNodeId,
        /// When the current lease expires.
        expires_at: u64,
        /// Current `lease_seq` (for information).
        current_seq: u64,
    },

    /// Request invalid (e.g., wrong zone).
    Invalid { reason: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// HRW Coordinator Selection (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute HRW (Highest Random Weight) hash for coordinator selection.
///
/// This provides deterministic, consistent coordinator selection without
/// a central coordinator.
fn hrw_hash(zone_id: &ZoneId, subject_id: &ObjectId, node_id: &TailscaleNodeId) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP2-HRW-V1");

    let z_bytes = zone_id.as_bytes();
    hasher.update(
        &u32::try_from(z_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    hasher.update(z_bytes);

    // ObjectId is fixed length (32 bytes), but we prefix it for consistency and future-proofing
    let s_bytes = subject_id.as_bytes();
    hasher.update(
        &u32::try_from(s_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    hasher.update(s_bytes);

    let n_bytes = node_id.as_str().as_bytes();
    hasher.update(
        &u32::try_from(n_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    hasher.update(n_bytes);

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    // Take the first 8 bytes as a u64 for comparison
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Select the coordinator for a lease using HRW/Rendezvous hashing.
///
/// # Arguments
///
/// * `zone_id` - The zone context
/// * `subject_id` - The object being leased
/// * `nodes` - List of eligible nodes
///
/// # Returns
///
/// The node with the highest HRW hash, or `None` if no nodes are available.
///
/// # Determinism
///
/// This function is fully deterministic - given the same inputs, all nodes
/// will select the same coordinator. This is essential for distributed
/// coordination without explicit communication.
#[must_use]
pub fn select_coordinator(
    zone_id: &ZoneId,
    subject_id: &ObjectId,
    nodes: &[TailscaleNodeId],
) -> Option<TailscaleNodeId> {
    nodes
        .iter()
        .max_by_key(|n| hrw_hash(zone_id, subject_id, n))
        .cloned()
}

/// Get all nodes ranked by HRW score for a subject.
///
/// This is useful for determining failover order when the primary
/// coordinator is unavailable.
#[must_use]
pub fn rank_nodes_by_hrw(
    zone_id: &ZoneId,
    subject_id: &ObjectId,
    nodes: &[TailscaleNodeId],
) -> Vec<TailscaleNodeId> {
    let mut scored: Vec<_> = nodes
        .iter()
        .map(|n| (hrw_hash(zone_id, subject_id, n), n.clone()))
        .collect();
    // Sort descending by score
    scored.sort_by_key(|item| std::cmp::Reverse(item.0));
    scored.into_iter().map(|(_, n)| n).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when lease validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseValidationError {
    /// Lease has expired.
    Expired { expired_at: u64, now: u64 },

    /// Lease is for wrong subject.
    SubjectMismatch { expected: ObjectId, got: ObjectId },

    /// Lease is for wrong zone.
    ZoneMismatch { expected: ZoneId, got: ZoneId },

    /// Lease is for wrong purpose.
    PurposeMismatch {
        expected: LeasePurpose,
        got: LeasePurpose,
    },

    /// Lease has been superseded by a newer lease.
    Superseded { held_seq: u64, current_seq: u64 },

    /// Coordinator mismatch (wrong coordinator signed).
    CoordinatorMismatch {
        expected: TailscaleNodeId,
        got: TailscaleNodeId,
    },

    /// Insufficient quorum signatures.
    InsufficientQuorum { required: usize, got: usize },

    /// Quorum signature set contains multiple signatures for the same node.
    DuplicateQuorumSigner { node_id: String },
}

impl std::fmt::Display for LeaseValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired { expired_at, now } => {
                write!(f, "lease expired at {expired_at}, current time is {now}")
            }
            Self::SubjectMismatch { expected, got } => {
                write!(f, "subject mismatch: expected {expected}, got {got}")
            }
            Self::ZoneMismatch { expected, got } => {
                write!(f, "zone mismatch: expected {expected}, got {got}")
            }
            Self::PurposeMismatch { expected, got } => {
                write!(f, "purpose mismatch: expected {expected}, got {got}")
            }
            Self::Superseded {
                held_seq,
                current_seq,
            } => {
                write!(
                    f,
                    "lease superseded: held seq {held_seq}, current seq {current_seq}"
                )
            }
            Self::CoordinatorMismatch { expected, got } => {
                write!(
                    f,
                    "coordinator mismatch: expected {}, got {}",
                    expected.as_str(),
                    got.as_str()
                )
            }
            Self::InsufficientQuorum { required, got } => {
                write!(
                    f,
                    "insufficient quorum: required {required} signatures, got {got}"
                )
            }
            Self::DuplicateQuorumSigner { node_id } => {
                write!(f, "duplicate quorum signer: {node_id}")
            }
        }
    }
}

impl std::error::Error for LeaseValidationError {}

/// Validate a lease for use.
///
/// # Arguments
///
/// * `lease` - The lease to validate
/// * `expected_subject` - Expected subject object ID
/// * `expected_zone` - Expected zone ID
/// * `expected_purpose` - Expected purpose
/// * `current_known_seq` - The highest `lease_seq` known for this subject
/// * `now` - Current timestamp
/// * `required_signatures` - Minimum required quorum signatures
///
/// # Errors
///
/// Returns an error if validation fails.
pub fn validate_lease(
    lease: &Lease,
    expected_subject: &ObjectId,
    expected_zone: &ZoneId,
    expected_purpose: LeasePurpose,
    current_known_seq: u64,
    now: u64,
    required_signatures: usize,
) -> Result<(), LeaseValidationError> {
    // Check expiry
    if lease.is_expired(now) {
        return Err(LeaseValidationError::Expired {
            expired_at: lease.exp,
            now,
        });
    }

    // Check subject
    if &lease.subject_object_id != expected_subject {
        return Err(LeaseValidationError::SubjectMismatch {
            expected: *expected_subject,
            got: lease.subject_object_id,
        });
    }

    // Check zone
    if lease.zone_id() != expected_zone {
        return Err(LeaseValidationError::ZoneMismatch {
            expected: expected_zone.clone(),
            got: lease.zone_id().clone(),
        });
    }

    // Check purpose
    if lease.purpose != expected_purpose {
        return Err(LeaseValidationError::PurposeMismatch {
            expected: expected_purpose,
            got: lease.purpose,
        });
    }

    // Check if superseded (NORMATIVE: higher seq wins)
    if lease.lease_seq < current_known_seq {
        return Err(LeaseValidationError::Superseded {
            held_seq: lease.lease_seq,
            current_seq: current_known_seq,
        });
    }

    // Check quorum. A malformed serialized SignatureSet can contain duplicate
    // node IDs even though SignatureSet::add rejects them, so reject duplicates
    // before raw signature count can satisfy quorum.
    if let Some(node_id) = lease.quorum_signatures.duplicate_node_id() {
        return Err(LeaseValidationError::DuplicateQuorumSigner {
            node_id: node_id.to_owned(),
        });
    }

    let sig_count = lease.quorum_signatures.len();
    if sig_count < required_signatures {
        return Err(LeaseValidationError::InsufficientQuorum {
            required: required_signatures,
            got: sig_count,
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_object_id(name: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(name.as_bytes())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HRW Coordinator Selection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hrw_deterministic() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        // Same inputs should always produce same output
        let coord1 = select_coordinator(&zone, &subject, &nodes);
        let coord2 = select_coordinator(&zone, &subject, &nodes);
        assert_eq!(coord1, coord2);

        // Should not be None with non-empty nodes
        assert!(coord1.is_some());
    }

    #[test]
    fn test_hrw_empty_nodes() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes: Vec<TailscaleNodeId> = vec![];

        assert!(select_coordinator(&zone, &subject, &nodes).is_none());
    }

    #[test]
    fn test_hrw_single_node() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![test_node("only-node")];

        let coord = select_coordinator(&zone, &subject, &nodes);
        assert_eq!(coord, Some(test_node("only-node")));
    }

    #[test]
    fn test_hrw_different_subjects_different_coordinators() {
        let zone = test_zone();
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
            test_node("node-d"),
            test_node("node-e"),
        ];

        // Different subjects may (probabilistically) get different coordinators
        let subjects: Vec<_> = (0..20)
            .map(|i| test_object_id(&format!("subject-{i}")))
            .collect();

        let coords: Vec<_> = subjects
            .iter()
            .map(|s| select_coordinator(&zone, s, &nodes))
            .collect();

        // Not all coordinators should be the same (with high probability)
        let first = &coords[0];
        let all_same = coords.iter().all(|c| c == first);

        // This is probabilistic but should pass with overwhelming probability
        assert!(!all_same, "HRW should distribute load across nodes");
    }

    #[test]
    fn test_rank_nodes_ordering() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        let ranked = rank_nodes_by_hrw(&zone, &subject, &nodes);

        // Ranked should have same length as input
        assert_eq!(ranked.len(), nodes.len());

        // First ranked node should be the coordinator
        let coord = select_coordinator(&zone, &subject, &nodes);
        assert_eq!(Some(&ranked[0]), coord.as_ref());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Fencing Token Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_fencing_token_higher_wins() {
        let lease1 = create_test_lease(10);
        let lease2 = create_test_lease(20);

        // Higher fencing token wins
        assert!(lease2.fencing_token() > lease1.fencing_token());
    }

    #[test]
    fn test_lease_fencing_token_equal() {
        let lease1 = create_test_lease(10);
        let lease2 = create_test_lease(10);

        // Same fencing token
        assert_eq!(lease1.fencing_token(), lease2.fencing_token());
    }

    #[test]
    fn test_lease_expiry() {
        let lease = create_test_lease_with_exp(1, 2000);

        // Before expiry
        assert!(!lease.is_expired(1500));

        // At expiry
        assert!(lease.is_expired(2000));

        // After expiry
        assert!(lease.is_expired(2500));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_lease_success() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,    // current_known_seq
            1500, // now (before expiry)
            0,    // no signatures required
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_lease_expired() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            2500, // now > exp
            0,
        );

        assert!(matches!(result, Err(LeaseValidationError::Expired { .. })));
    }

    #[test]
    fn test_validate_lease_superseded() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10, // current_known_seq > lease.lease_seq
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::Superseded { .. })
        ));
    }

    #[test]
    fn test_validate_lease_purpose_mismatch() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::ConnectorStateWrite, // Wrong purpose
            5,
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::PurposeMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_lease_subject_mismatch() {
        let subject = test_object_id("subject");
        let wrong_subject = test_object_id("wrong-subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &wrong_subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::SubjectMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_lease_zone_mismatch() {
        let subject = test_object_id("subject");
        // Lease is created with test_zone() (work), but we validate against private
        let wrong_zone = ZoneId::private();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &wrong_zone,
            LeasePurpose::OperationExecution,
            5,
            1500,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::ZoneMismatch { .. })
        ));
    }

    #[test]
    fn validate_lease_handoff_accepts_monotonic_transfer() {
        let subject = test_object_id("computation");
        let mut active_lease = create_test_lease_with_subject(7, 2_000, subject);
        active_lease.purpose = LeasePurpose::ComputationMigration;

        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("lease-source"),
            next_lease_id: test_object_id("lease-target"),
            from_holder: active_lease.holder.clone(),
            to_holder: test_node("target-node"),
            zone_id: active_lease.zone_id().clone(),
            subject_object_id: subject,
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token: active_lease.fencing_token(),
            next_fencing_token: active_lease.fencing_token() + 1,
            transferred_at: 1_500,
            checkpoint_object_id: Some(test_object_id("checkpoint")),
        };

        assert!(validate_lease_handoff(&active_lease, &handoff, 1_500).is_ok());
    }

    #[test]
    fn validate_lease_handoff_rejects_stale_fencing_token() {
        let subject = test_object_id("computation");
        let mut active_lease = create_test_lease_with_subject(7, 2_000, subject);
        active_lease.purpose = LeasePurpose::ComputationMigration;

        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("lease-source"),
            next_lease_id: test_object_id("lease-target"),
            from_holder: active_lease.holder.clone(),
            to_holder: test_node("target-node"),
            zone_id: active_lease.zone_id().clone(),
            subject_object_id: subject,
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token: active_lease.fencing_token(),
            next_fencing_token: active_lease.fencing_token(),
            transferred_at: 1_500,
            checkpoint_object_id: None,
        };

        let err = validate_lease_handoff(&active_lease, &handoff, 1_500).unwrap_err();
        assert!(matches!(
            err,
            LeaseTransferValidationError::NonMonotonicFence { .. }
        ));
    }

    #[test]
    fn validate_lease_handoff_rejects_reused_lease_id() {
        let subject = test_object_id("computation");
        let mut active_lease = create_test_lease_with_subject(7, 2_000, subject);
        active_lease.purpose = LeasePurpose::ComputationMigration;

        let reused_lease_id = test_object_id("lease-source");
        let handoff = LeaseHandoff {
            previous_lease_id: reused_lease_id,
            next_lease_id: reused_lease_id,
            from_holder: active_lease.holder.clone(),
            to_holder: test_node("target-node"),
            zone_id: active_lease.zone_id().clone(),
            subject_object_id: subject,
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token: active_lease.fencing_token(),
            next_fencing_token: active_lease.fencing_token() + 1,
            transferred_at: 1_500,
            checkpoint_object_id: None,
        };

        let err = validate_lease_handoff(&active_lease, &handoff, 1_500).unwrap_err();
        assert!(matches!(
            err,
            LeaseTransferValidationError::LeaseIdReused { .. }
        ));
    }

    #[test]
    fn test_validate_lease_insufficient_quorum() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            1500,
            3, // requires 3 signatures, but lease has none
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::InsufficientQuorum {
                required: 3,
                got: 0
            })
        ));
    }

    #[test]
    fn test_validate_lease_rejects_duplicate_quorum_signer() {
        let subject = test_object_id("subject");
        let zone = test_zone();
        let mut lease = create_test_lease_with_subject(5, 2000, subject);
        lease.quorum_signatures = duplicate_signature_set("node-1");

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            1500,
            2,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::DuplicateQuorumSigner { node_id })
                if node_id == "node-1"
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseValidationError Display Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_validation_error_display() {
        let err = LeaseValidationError::Expired {
            expired_at: 1000,
            now: 2000,
        };
        assert!(err.to_string().contains("expired"));

        let err = LeaseValidationError::Superseded {
            held_seq: 5,
            current_seq: 10,
        };
        assert!(err.to_string().contains("superseded"));

        let err = LeaseValidationError::InsufficientQuorum {
            required: 3,
            got: 1,
        };
        assert!(err.to_string().contains("quorum"));

        let err = LeaseValidationError::DuplicateQuorumSigner {
            node_id: "node-1".to_owned(),
        };
        assert!(err.to_string().contains("duplicate quorum signer"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HRW Coordinator Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_hrw_node_addition_minimal_disruption() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");

        let original_nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        let coord_before = select_coordinator(&zone, &subject, &original_nodes);

        // Add a new node
        let mut nodes_with_new = original_nodes;
        nodes_with_new.push(test_node("node-d"));

        let coord_after = select_coordinator(&zone, &subject, &nodes_with_new);

        // Either coordinator is the same OR it's the new node
        // (HRW provides minimal disruption on node addition)
        assert!(
            coord_before == coord_after || coord_after == Some(test_node("node-d")),
            "HRW should provide minimal disruption on node addition"
        );
    }

    #[test]
    fn test_hrw_failover_ordering() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        let ranked = rank_nodes_by_hrw(&zone, &subject, &nodes);
        assert_eq!(ranked.len(), 3);

        // If primary (ranked[0]) fails, secondary (ranked[1]) should be next
        let remaining_nodes: Vec<_> = nodes.iter().filter(|n| *n != &ranked[0]).cloned().collect();

        let new_coord = select_coordinator(&zone, &subject, &remaining_nodes);
        assert_eq!(new_coord, Some(ranked[1].clone()));
    }

    #[test]
    fn test_hrw_stable_across_node_order() {
        let zone = test_zone();
        let subject = test_object_id("test-subject");

        let nodes1 = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        // Same nodes, different order
        let nodes2 = vec![
            test_node("node-c"),
            test_node("node-a"),
            test_node("node-b"),
        ];

        let coord1 = select_coordinator(&zone, &subject, &nodes1);
        let coord2 = select_coordinator(&zone, &subject, &nodes2);

        assert_eq!(
            coord1, coord2,
            "HRW should be stable regardless of input order"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeasePurpose Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_purpose_display() {
        assert_eq!(
            LeasePurpose::OperationExecution.to_string(),
            "operation_execution"
        );
        assert_eq!(
            LeasePurpose::ConnectorStateWrite.to_string(),
            "connector_state_write"
        );
        assert_eq!(
            LeasePurpose::ComputationMigration.to_string(),
            "computation_migration"
        );
    }

    #[test]
    fn test_lease_purpose_serde() {
        let purposes = [
            LeasePurpose::OperationExecution,
            LeasePurpose::ConnectorStateWrite,
            LeasePurpose::ComputationMigration,
            LeasePurpose::CoordinatorElection,
            LeasePurpose::Migration,
            LeasePurpose::ResourceAccess,
        ];

        for purpose in purposes {
            let json = serde_json::to_string(&purpose).unwrap();
            let deserialized: LeasePurpose = serde_json::from_str(&json).unwrap();
            assert_eq!(purpose, deserialized);
        }
    }

    #[test]
    fn test_lease_purpose_all_variants_display() {
        // Test all LeasePurpose variants have correct Display output
        assert_eq!(
            LeasePurpose::CoordinatorElection.to_string(),
            "coordinator_election"
        );
        assert_eq!(LeasePurpose::Migration.to_string(), "migration");
        assert_eq!(LeasePurpose::ResourceAccess.to_string(), "resource_access");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Serde Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_serde_roundtrip() {
        let lease = create_test_lease(42);

        let json = serde_json::to_string(&lease).unwrap();
        let deserialized: Lease = serde_json::from_str(&json).unwrap();

        assert_eq!(lease.holder, deserialized.holder);
        assert_eq!(lease.lease_seq, deserialized.lease_seq);
        assert_eq!(lease.exp, deserialized.exp);
        assert_eq!(lease.subject_object_id, deserialized.subject_object_id);
        assert_eq!(lease.purpose, deserialized.purpose);
    }

    #[test]
    fn test_lease_serde_preserves_all_fields() {
        let subject = test_object_id("specific-subject");
        let lease = create_test_lease_with_subject(100, 9999, subject);

        let json = serde_json::to_string_pretty(&lease).unwrap();

        // Verify JSON contains expected fields
        assert!(json.contains("holder"));
        assert!(json.contains("lease_seq"));
        assert!(json.contains("exp"));
        assert!(json.contains("subject_object_id"));
        assert!(json.contains("purpose"));
        assert!(json.contains("quorum_signatures"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseRequest Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_request_creation() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("subject"),
            zone_id: test_zone(),
            requester: test_node("requester"),
            requested_ttl: 300,
            renew_seq: None,
        };

        assert_eq!(request.requester.as_str(), "requester");
        assert_eq!(request.requested_ttl, 300);
        assert!(request.renew_seq.is_none());
    }

    #[test]
    fn test_lease_request_renewal() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("subject"),
            zone_id: test_zone(),
            requester: test_node("requester"),
            requested_ttl: 300,
            renew_seq: Some(42),
        };

        assert_eq!(request.renew_seq, Some(42));
    }

    #[test]
    fn test_lease_request_serde_roundtrip() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("subject"),
            zone_id: test_zone(),
            requester: test_node("requester"),
            requested_ttl: 600,
            renew_seq: Some(10),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: LeaseRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.subject_object_id, deserialized.subject_object_id);
        assert_eq!(request.zone_id, deserialized.zone_id);
        assert_eq!(request.requester, deserialized.requester);
        assert_eq!(request.requested_ttl, deserialized.requested_ttl);
        assert_eq!(request.renew_seq, deserialized.renew_seq);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseResponse Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_response_granted() {
        let lease = create_test_lease(1);
        let response = LeaseResponse::Granted(Box::new(lease.clone()));

        assert!(
            matches!(&response, LeaseResponse::Granted(l) if l.lease_seq == lease.lease_seq),
            "Expected Granted variant, got {response:?}"
        );
    }

    #[test]
    fn test_lease_response_denied() {
        let response = LeaseResponse::Denied {
            current_holder: test_node("holder"),
            expires_at: 3000,
            current_seq: 5,
        };

        assert!(
            matches!(
                &response,
                LeaseResponse::Denied { current_holder, expires_at, current_seq }
                    if current_holder.as_str() == "holder" && *expires_at == 3000 && *current_seq == 5
            ),
            "Expected Denied variant, got {response:?}"
        );
    }

    #[test]
    fn test_lease_response_invalid() {
        let response = LeaseResponse::Invalid {
            reason: "wrong zone".to_string(),
        };

        assert!(
            matches!(&response, LeaseResponse::Invalid { reason } if reason == "wrong zone"),
            "Expected Invalid variant, got {response:?}"
        );
    }

    #[test]
    fn test_lease_response_serde_granted() {
        let lease = create_test_lease(42);
        let response = LeaseResponse::Granted(Box::new(lease));

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: LeaseResponse = serde_json::from_str(&json).unwrap();

        assert!(matches!(deserialized, LeaseResponse::Granted(_)));
    }

    #[test]
    fn test_lease_response_serde_denied() {
        let response = LeaseResponse::Denied {
            current_holder: test_node("holder"),
            expires_at: 5000,
            current_seq: 10,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: LeaseResponse = serde_json::from_str(&json).unwrap();

        assert!(
            matches!(
                &deserialized,
                LeaseResponse::Denied { current_holder, expires_at, current_seq }
                    if current_holder.as_str() == "holder" && *expires_at == 5000 && *current_seq == 10
            ),
            "Expected Denied variant after deserialization, got {deserialized:?}"
        );
    }

    #[test]
    fn test_lease_response_serde_invalid() {
        let response = LeaseResponse::Invalid {
            reason: "test reason".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: LeaseResponse = serde_json::from_str(&json).unwrap();

        assert!(
            matches!(&deserialized, LeaseResponse::Invalid { reason } if reason == "test reason"),
            "Expected Invalid variant after deserialization, got {deserialized:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease Conflict Resolution Tests (Fencing Token Semantics)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fencing_token_prevents_zombie_lease() {
        // Scenario: Node A has lease seq 10, but node B acquired seq 15
        // Node A's lease should be rejected even if not expired
        let subject = test_object_id("shared-resource");
        let zone = test_zone();

        let zombie_lease = create_test_lease_with_subject(10, 5000, subject);

        // Current known seq is 15 (someone else got a newer lease)
        let result = validate_lease(
            &zombie_lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            15, // current_known_seq > zombie_lease.lease_seq
            1000,
            0,
        );

        assert!(matches!(
            result,
            Err(LeaseValidationError::Superseded {
                held_seq: 10,
                current_seq: 15
            })
        ));
    }

    #[test]
    fn test_higher_seq_wins_regardless_of_expiry() {
        // Even if old lease hasn't expired, higher seq wins
        let subject = test_object_id("resource");
        let zone = test_zone();

        // Old lease: seq 5, expires far in future
        let old_lease = create_test_lease_with_subject(5, 99999, subject);

        // New lease: seq 10
        let new_lease = create_test_lease_with_subject(10, 2000, subject);

        // Old lease should fail validation
        let old_result = validate_lease(
            &old_lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10, // current known is new lease's seq
            1000,
            0,
        );
        assert!(old_result.is_err());

        // New lease should pass
        let new_result = validate_lease(
            &new_lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10,
            1000,
            0,
        );
        assert!(new_result.is_ok());
    }

    #[test]
    fn test_lease_at_exact_seq_is_valid() {
        // Lease with seq == current_known_seq should be valid
        let subject = test_object_id("resource");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(10, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10, // exact match
            1000,
            0,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_lease_ahead_of_known_seq_is_valid() {
        // Lease with seq > current_known_seq should be valid
        // (node might have received newer lease info)
        let subject = test_object_id("resource");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(15, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            10, // lease.seq > current_known
            1000,
            0,
        );

        assert!(result.is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease::new Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_lease_new_sets_expiry_correctly() {
        use crate::Provenance;
        use fcp_cbor::SchemaId;
        use semver::Version;

        let zone = test_zone();
        let subject = test_object_id("subject");
        let ttl_secs = 300;

        let params = LeaseParams {
            schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            holder: test_node("holder"),
            lease_seq: 1,
            ttl_secs,
            subject_object_id: subject,
            provenance: Provenance::new(zone),
            purpose: LeasePurpose::OperationExecution,
            quorum_signatures: SignatureSet::default(),
        };

        let lease = Lease::new(params);

        // exp should be created_at + ttl_secs
        assert_eq!(lease.exp, lease.header.created_at + u64::from(ttl_secs));

        // subject should be in refs
        assert!(lease.header.refs.contains(&subject));

        // ttl_secs should be set in header
        assert_eq!(lease.header.ttl_secs, Some(u64::from(ttl_secs)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeasePurpose – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_purpose_copy() {
        let a = LeasePurpose::OperationExecution;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn lease_purpose_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LeasePurpose::Migration);
        set.insert(LeasePurpose::Migration);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn lease_purpose_hash_all_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LeasePurpose::OperationExecution);
        set.insert(LeasePurpose::ConnectorStateWrite);
        set.insert(LeasePurpose::ComputationMigration);
        set.insert(LeasePurpose::CoordinatorElection);
        set.insert(LeasePurpose::Migration);
        set.insert(LeasePurpose::ResourceAccess);
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn lease_purpose_inequality() {
        assert_ne!(LeasePurpose::OperationExecution, LeasePurpose::Migration);
        assert_ne!(
            LeasePurpose::ConnectorStateWrite,
            LeasePurpose::ResourceAccess
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseValidationError – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_validation_error_clone() {
        let err = LeaseValidationError::Expired {
            expired_at: 100,
            now: 200,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn lease_validation_error_equality() {
        let a = LeaseValidationError::Superseded {
            held_seq: 5,
            current_seq: 10,
        };
        let b = LeaseValidationError::Superseded {
            held_seq: 5,
            current_seq: 10,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn lease_validation_error_inequality() {
        let a = LeaseValidationError::Expired {
            expired_at: 100,
            now: 200,
        };
        let b = LeaseValidationError::Superseded {
            held_seq: 1,
            current_seq: 2,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn lease_validation_error_is_error_trait() {
        let err: &dyn std::error::Error = &LeaseValidationError::Expired {
            expired_at: 100,
            now: 200,
        };
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn lease_validation_error_display_all_variants() {
        let subject_mismatch = LeaseValidationError::SubjectMismatch {
            expected: test_object_id("a"),
            got: test_object_id("b"),
        };
        assert!(subject_mismatch.to_string().contains("subject mismatch"));

        let zone_mismatch = LeaseValidationError::ZoneMismatch {
            expected: ZoneId::work(),
            got: ZoneId::private(),
        };
        assert!(zone_mismatch.to_string().contains("zone mismatch"));

        let purpose = LeaseValidationError::PurposeMismatch {
            expected: LeasePurpose::OperationExecution,
            got: LeasePurpose::Migration,
        };
        assert!(purpose.to_string().contains("purpose mismatch"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lease – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_clone() {
        let lease = create_test_lease(42);
        let cloned = lease.clone();
        assert_eq!(cloned.lease_seq, lease.lease_seq);
        assert_eq!(cloned.holder, lease.holder);
        assert_eq!(cloned.exp, lease.exp);
        assert_eq!(cloned.purpose, lease.purpose);
    }

    #[test]
    fn lease_zone_id_accessor() {
        let lease = create_test_lease(1);
        assert_eq!(*lease.zone_id(), ZoneId::work());
    }

    #[test]
    fn lease_is_expired_boundary() {
        let lease = create_test_lease_with_exp(1, 1000);
        // Just before expiry
        assert!(!lease.is_expired(999));
        // Exactly at expiry
        assert!(lease.is_expired(1000));
    }

    #[test]
    fn lease_fencing_token_matches_seq() {
        let lease = create_test_lease(777);
        assert_eq!(lease.fencing_token(), 777);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseRequest – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_request_clone() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("s"),
            zone_id: test_zone(),
            requester: test_node("n"),
            requested_ttl: 60,
            renew_seq: Some(5),
        };
        let cloned = request.clone();
        assert_eq!(cloned.requested_ttl, request.requested_ttl);
        assert_eq!(cloned.renew_seq, request.renew_seq);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseResponse – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_response_clone() {
        let response = LeaseResponse::Denied {
            current_holder: test_node("h"),
            expires_at: 5000,
            current_seq: 10,
        };
        let cloned = Clone::clone(&response);
        assert!(matches!(
            cloned,
            LeaseResponse::Denied {
                current_seq: 10,
                ..
            }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // rank_nodes_by_hrw – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rank_nodes_empty() {
        let zone = test_zone();
        let subject = test_object_id("s");
        let ranked = rank_nodes_by_hrw(&zone, &subject, &[]);
        assert!(ranked.is_empty());
    }

    #[test]
    fn rank_nodes_single() {
        let zone = test_zone();
        let subject = test_object_id("s");
        let nodes = vec![test_node("only")];
        let ranked = rank_nodes_by_hrw(&zone, &subject, &nodes);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].as_str(), "only");
    }

    #[test]
    fn rank_nodes_deterministic() {
        let zone = test_zone();
        let subject = test_object_id("s");
        let nodes = vec![test_node("a"), test_node("b"), test_node("c")];
        let r1 = rank_nodes_by_hrw(&zone, &subject, &nodes);
        let r2 = rank_nodes_by_hrw(&zone, &subject, &nodes);
        assert_eq!(r1, r2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // current_timestamp – basic sanity
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn current_timestamp_is_reasonable() {
        let ts = current_timestamp();
        // Should be after 2020-01-01
        assert!(ts > 1_577_836_800);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LeaseParams – clone
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_params_clone() {
        use crate::Provenance;
        use fcp_cbor::SchemaId;
        use semver::Version;

        let zone = test_zone();
        let params = LeaseParams {
            schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            holder: test_node("h"),
            lease_seq: 1,
            ttl_secs: 60,
            subject_object_id: test_object_id("s"),
            provenance: Provenance::new(zone),
            purpose: LeasePurpose::ResourceAccess,
            quorum_signatures: SignatureSet::default(),
        };
        let cloned = params.clone();
        assert_eq!(cloned.lease_seq, params.lease_seq);
        assert_eq!(cloned.purpose, params.purpose);
    }

    #[test]
    fn quorum_signing_bytes_exclude_quorum_signatures() {
        let lease_a = create_test_lease(7);
        let mut lease_b = lease_a.clone();
        let mut signatures = SignatureSet::new();
        signatures.add(crate::NodeSignature::new(
            crate::NodeId::new("node-a"),
            [0xA5; 64],
            1_000,
        ));
        lease_b.quorum_signatures = signatures;

        let bytes_a = lease_a.quorum_signing_bytes().expect("signing bytes");
        let bytes_b = lease_b.quorum_signing_bytes().expect("signing bytes");

        assert_eq!(bytes_a, bytes_b);

        lease_b.lease_seq += 1;
        let bytes_c = lease_b.quorum_signing_bytes().expect("signing bytes");
        assert_ne!(bytes_a, bytes_c);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper Functions
    // ─────────────────────────────────────────────────────────────────────────

    fn create_test_lease(lease_seq: u64) -> Lease {
        create_test_lease_with_exp(lease_seq, 2000)
    }

    fn create_test_lease_with_exp(lease_seq: u64, exp: u64) -> Lease {
        create_test_lease_with_subject(lease_seq, exp, test_object_id("subject"))
    }

    fn create_test_lease_with_subject(lease_seq: u64, exp: u64, subject: ObjectId) -> Lease {
        use crate::Provenance;
        use fcp_cbor::SchemaId;
        use semver::Version;

        let zone = test_zone();
        Lease {
            header: ObjectHeader {
                encryption_kind: Default::default(),
                schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
                zone_id: zone.clone(),
                created_at: 1000,
                provenance: Provenance::new(zone),
                refs: vec![subject],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            holder: test_node("holder-node"),
            lease_seq,
            exp,
            subject_object_id: subject,
            purpose: LeasePurpose::OperationExecution,
            quorum_signatures: SignatureSet::default(),
        }
    }

    fn create_test_lease_with_purpose(
        lease_seq: u64,
        exp: u64,
        subject: ObjectId,
        purpose: LeasePurpose,
    ) -> Lease {
        let mut lease = create_test_lease_with_subject(lease_seq, exp, subject);
        lease.purpose = purpose;
        lease
    }

    fn duplicate_signature_set(node_id: &str) -> SignatureSet {
        serde_json::from_value(serde_json::json!({
            "signatures": [
                {
                    "node_id": node_id,
                    "signature": "aa".repeat(64),
                    "signed_at": 1000
                },
                {
                    "node_id": node_id,
                    "signature": "bb".repeat(64),
                    "signed_at": 2000
                }
            ]
        }))
        .expect("duplicate signature JSON should deserialize")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: LeasePurpose
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_purpose_debug_format() {
        let dbg = format!("{:?}", LeasePurpose::ComputationMigration);
        assert!(dbg.contains("ComputationMigration"));
    }

    #[test]
    fn lease_purpose_clone() {
        let p = LeasePurpose::CoordinatorElection;
        let cloned = p;
        assert_eq!(p, cloned);
    }

    #[test]
    fn lease_purpose_serde_snake_case() {
        let json = serde_json::to_string(&LeasePurpose::OperationExecution).unwrap();
        assert_eq!(json, "\"operation_execution\"");

        let json = serde_json::to_string(&LeasePurpose::ConnectorStateWrite).unwrap();
        assert_eq!(json, "\"connector_state_write\"");

        let json = serde_json::to_string(&LeasePurpose::ComputationMigration).unwrap();
        assert_eq!(json, "\"computation_migration\"");

        let json = serde_json::to_string(&LeasePurpose::CoordinatorElection).unwrap();
        assert_eq!(json, "\"coordinator_election\"");

        let json = serde_json::to_string(&LeasePurpose::Migration).unwrap();
        assert_eq!(json, "\"migration\"");

        let json = serde_json::to_string(&LeasePurpose::ResourceAccess).unwrap();
        assert_eq!(json, "\"resource_access\"");
    }

    #[test]
    fn lease_purpose_deserialize_unknown_fails() {
        let result = serde_json::from_str::<LeasePurpose>("\"unknown_purpose\"");
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: LeaseTransferValidationError Display
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_transfer_error_display_expired() {
        let err = LeaseTransferValidationError::LeaseExpired {
            expired_at: 100,
            now: 200,
        };
        let msg = err.to_string();
        assert!(msg.contains("expired"));
        assert!(msg.contains("100"));
        assert!(msg.contains("200"));
    }

    #[test]
    fn lease_transfer_error_display_reused() {
        let err = LeaseTransferValidationError::LeaseIdReused {
            lease_id: test_object_id("dup"),
        };
        let msg = err.to_string();
        assert!(msg.contains("reused"));
    }

    #[test]
    fn lease_transfer_error_display_self_transfer() {
        let err = LeaseTransferValidationError::SelfTransfer {
            holder: test_node("self-node"),
        };
        let msg = err.to_string();
        assert!(msg.contains("different holder"));
    }

    #[test]
    fn lease_transfer_error_display_from_holder_mismatch() {
        let err = LeaseTransferValidationError::FromHolderMismatch {
            expected: test_node("a"),
            got: test_node("b"),
        };
        let msg = err.to_string();
        assert!(msg.contains("source holder mismatch"));
    }

    #[test]
    fn lease_transfer_error_display_subject_mismatch() {
        let err = LeaseTransferValidationError::SubjectMismatch {
            expected: test_object_id("a"),
            got: test_object_id("b"),
        };
        let msg = err.to_string();
        assert!(msg.contains("subject mismatch"));
    }

    #[test]
    fn lease_transfer_error_display_zone_mismatch() {
        let err = LeaseTransferValidationError::ZoneMismatch {
            expected: ZoneId::work(),
            got: ZoneId::private(),
        };
        let msg = err.to_string();
        assert!(msg.contains("zone mismatch"));
    }

    #[test]
    fn lease_transfer_error_display_purpose_mismatch() {
        let err = LeaseTransferValidationError::PurposeMismatch {
            expected: LeasePurpose::OperationExecution,
            got: LeasePurpose::Migration,
        };
        let msg = err.to_string();
        assert!(msg.contains("purpose mismatch"));
    }

    #[test]
    fn lease_transfer_error_display_previous_fence_mismatch() {
        let err = LeaseTransferValidationError::PreviousFenceMismatch {
            expected: 10,
            got: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("fencing token mismatch"));
        assert!(msg.contains("10"));
    }

    #[test]
    fn lease_transfer_error_display_non_monotonic() {
        let err = LeaseTransferValidationError::NonMonotonicFence {
            previous: 7,
            next: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("monotonically"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: validate_lease_handoff
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_lease_handoff_rejects_expired_lease() {
        let subject = test_object_id("s");
        let mut active_lease = create_test_lease_with_subject(5, 100, subject);
        active_lease.purpose = LeasePurpose::ComputationMigration;

        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: active_lease.holder.clone(),
            to_holder: test_node("target"),
            zone_id: active_lease.zone_id().clone(),
            subject_object_id: subject,
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token: 5,
            next_fencing_token: 6,
            transferred_at: 200,
            checkpoint_object_id: None,
        };

        let err = validate_lease_handoff(&active_lease, &handoff, 200).unwrap_err();
        assert!(matches!(
            err,
            LeaseTransferValidationError::LeaseExpired { .. }
        ));
    }

    #[test]
    fn validate_lease_handoff_rejects_self_transfer() {
        let subject = test_object_id("s");
        let mut active_lease = create_test_lease_with_subject(5, 2000, subject);
        active_lease.purpose = LeasePurpose::ComputationMigration;

        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: active_lease.holder.clone(),
            to_holder: active_lease.holder.clone(), // same as from
            zone_id: active_lease.zone_id().clone(),
            subject_object_id: subject,
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token: 5,
            next_fencing_token: 6,
            transferred_at: 1500,
            checkpoint_object_id: None,
        };

        let err = validate_lease_handoff(&active_lease, &handoff, 1500).unwrap_err();
        assert!(matches!(
            err,
            LeaseTransferValidationError::SelfTransfer { .. }
        ));
    }

    #[test]
    fn validate_lease_handoff_rejects_holder_mismatch() {
        let subject = test_object_id("s");
        let active_lease =
            create_test_lease_with_purpose(5, 2000, subject, LeasePurpose::ComputationMigration);

        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: test_node("wrong-holder"),
            to_holder: test_node("target"),
            zone_id: active_lease.zone_id().clone(),
            subject_object_id: subject,
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token: 5,
            next_fencing_token: 6,
            transferred_at: 1500,
            checkpoint_object_id: None,
        };

        let err = validate_lease_handoff(&active_lease, &handoff, 1500).unwrap_err();
        assert!(matches!(
            err,
            LeaseTransferValidationError::FromHolderMismatch { .. }
        ));
    }

    #[test]
    fn validate_lease_handoff_rejects_subject_mismatch() {
        let subject = test_object_id("s");
        let active_lease =
            create_test_lease_with_purpose(5, 2000, subject, LeasePurpose::ComputationMigration);

        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: active_lease.holder.clone(),
            to_holder: test_node("target"),
            zone_id: active_lease.zone_id().clone(),
            subject_object_id: test_object_id("wrong-subject"),
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token: 5,
            next_fencing_token: 6,
            transferred_at: 1500,
            checkpoint_object_id: None,
        };

        let err = validate_lease_handoff(&active_lease, &handoff, 1500).unwrap_err();
        assert!(matches!(
            err,
            LeaseTransferValidationError::SubjectMismatch { .. }
        ));
    }

    #[test]
    fn validate_lease_handoff_rejects_zone_mismatch() {
        let subject = test_object_id("s");
        let active_lease =
            create_test_lease_with_purpose(5, 2000, subject, LeasePurpose::ComputationMigration);

        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: active_lease.holder.clone(),
            to_holder: test_node("target"),
            zone_id: ZoneId::private(), // wrong zone
            subject_object_id: subject,
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token: 5,
            next_fencing_token: 6,
            transferred_at: 1500,
            checkpoint_object_id: None,
        };

        let err = validate_lease_handoff(&active_lease, &handoff, 1500).unwrap_err();
        assert!(matches!(
            err,
            LeaseTransferValidationError::ZoneMismatch { .. }
        ));
    }

    #[test]
    fn validate_lease_handoff_rejects_purpose_mismatch() {
        let subject = test_object_id("s");
        let active_lease =
            create_test_lease_with_purpose(5, 2000, subject, LeasePurpose::ComputationMigration);

        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: active_lease.holder.clone(),
            to_holder: test_node("target"),
            zone_id: active_lease.zone_id().clone(),
            subject_object_id: subject,
            purpose: LeasePurpose::ResourceAccess, // wrong purpose
            previous_fencing_token: 5,
            next_fencing_token: 6,
            transferred_at: 1500,
            checkpoint_object_id: None,
        };

        let err = validate_lease_handoff(&active_lease, &handoff, 1500).unwrap_err();
        assert!(matches!(
            err,
            LeaseTransferValidationError::PurposeMismatch { .. }
        ));
    }

    #[test]
    fn validate_lease_handoff_rejects_fence_mismatch() {
        let subject = test_object_id("s");
        let active_lease =
            create_test_lease_with_purpose(5, 2000, subject, LeasePurpose::ComputationMigration);

        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: active_lease.holder.clone(),
            to_holder: test_node("target"),
            zone_id: active_lease.zone_id().clone(),
            subject_object_id: subject,
            purpose: LeasePurpose::ComputationMigration,
            previous_fencing_token: 99, // wrong token
            next_fencing_token: 100,
            transferred_at: 1500,
            checkpoint_object_id: None,
        };

        let err = validate_lease_handoff(&active_lease, &handoff, 1500).unwrap_err();
        assert!(matches!(
            err,
            LeaseTransferValidationError::PreviousFenceMismatch { .. }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: LeaseHandoff
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_handoff_serde_roundtrip() {
        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: test_node("from"),
            to_holder: test_node("to"),
            zone_id: test_zone(),
            subject_object_id: test_object_id("subj"),
            purpose: LeasePurpose::Migration,
            previous_fencing_token: 10,
            next_fencing_token: 11,
            transferred_at: 5000,
            checkpoint_object_id: Some(test_object_id("cp")),
        };

        let json = serde_json::to_string(&handoff).unwrap();
        let back: LeaseHandoff = serde_json::from_str(&json).unwrap();
        assert_eq!(handoff, back);
    }

    #[test]
    fn lease_handoff_serde_without_checkpoint() {
        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: test_node("from"),
            to_holder: test_node("to"),
            zone_id: test_zone(),
            subject_object_id: test_object_id("subj"),
            purpose: LeasePurpose::OperationExecution,
            previous_fencing_token: 1,
            next_fencing_token: 2,
            transferred_at: 1000,
            checkpoint_object_id: None,
        };

        let json = serde_json::to_string(&handoff).unwrap();
        assert!(!json.contains("checkpoint_object_id"));
        let back: LeaseHandoff = serde_json::from_str(&json).unwrap();
        assert!(back.checkpoint_object_id.is_none());
    }

    #[test]
    fn lease_handoff_clone() {
        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: test_node("from"),
            to_holder: test_node("to"),
            zone_id: test_zone(),
            subject_object_id: test_object_id("subj"),
            purpose: LeasePurpose::ResourceAccess,
            previous_fencing_token: 5,
            next_fencing_token: 6,
            transferred_at: 2000,
            checkpoint_object_id: None,
        };
        let cloned = handoff.clone();
        assert_eq!(handoff, cloned);
    }

    #[test]
    fn lease_handoff_debug_format() {
        let handoff = LeaseHandoff {
            previous_lease_id: test_object_id("prev"),
            next_lease_id: test_object_id("next"),
            from_holder: test_node("from"),
            to_holder: test_node("to"),
            zone_id: test_zone(),
            subject_object_id: test_object_id("subj"),
            purpose: LeasePurpose::Migration,
            previous_fencing_token: 1,
            next_fencing_token: 2,
            transferred_at: 1000,
            checkpoint_object_id: None,
        };
        let dbg = format!("{handoff:?}");
        assert!(dbg.contains("LeaseHandoff"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: Lease expiry edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_not_expired_at_zero_timestamp() {
        let lease = create_test_lease_with_exp(1, 2000);
        assert!(!lease.is_expired(0));
    }

    #[test]
    fn lease_expired_at_max_timestamp() {
        let lease = create_test_lease_with_exp(1, u64::MAX);
        assert!(!lease.is_expired(u64::MAX - 1));
        assert!(lease.is_expired(u64::MAX));
    }

    #[test]
    fn lease_with_zero_expiry_always_expired() {
        let lease = create_test_lease_with_exp(1, 0);
        assert!(lease.is_expired(0));
        assert!(lease.is_expired(1));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: validate_lease edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validate_lease_exact_expiry_fails() {
        let subject = test_object_id("s");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            2000, // exactly at expiry
            0,
        );
        assert!(matches!(result, Err(LeaseValidationError::Expired { .. })));
    }

    #[test]
    fn validate_lease_just_before_expiry_succeeds() {
        let subject = test_object_id("s");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(5, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            5,
            1999, // just before expiry
            0,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_lease_seq_zero_valid() {
        let subject = test_object_id("s");
        let zone = test_zone();
        let lease = create_test_lease_with_subject(0, 2000, subject);

        let result = validate_lease(
            &lease,
            &subject,
            &zone,
            LeasePurpose::OperationExecution,
            0,
            1000,
            0,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn validate_lease_all_purposes() {
        let subject = test_object_id("s");
        let zone = test_zone();
        for purpose in [
            LeasePurpose::OperationExecution,
            LeasePurpose::ConnectorStateWrite,
            LeasePurpose::ComputationMigration,
            LeasePurpose::CoordinatorElection,
            LeasePurpose::Migration,
            LeasePurpose::ResourceAccess,
        ] {
            let lease = create_test_lease_with_purpose(5, 2000, subject, purpose);
            let result = validate_lease(&lease, &subject, &zone, purpose, 5, 1000, 0);
            assert!(result.is_ok(), "purpose {purpose:?} should validate");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: HRW
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn hrw_all_nodes_appear_in_ranking() {
        let zone = test_zone();
        let subject = test_object_id("s");
        let nodes = vec![
            test_node("a"),
            test_node("b"),
            test_node("c"),
            test_node("d"),
        ];
        let ranked = rank_nodes_by_hrw(&zone, &subject, &nodes);
        for n in &nodes {
            assert!(ranked.contains(n));
        }
    }

    #[test]
    fn hrw_ranking_is_permutation() {
        let zone = test_zone();
        let subject = test_object_id("subj");
        let nodes = vec![test_node("x"), test_node("y"), test_node("z")];
        let ranked = rank_nodes_by_hrw(&zone, &subject, &nodes);
        assert_eq!(ranked.len(), nodes.len());
        // Verify each node appears exactly once
        for n in &nodes {
            assert!(ranked.contains(n), "ranked should contain {n:?}");
        }
    }

    #[test]
    fn hrw_different_zones_may_differ() {
        let subject = test_object_id("s");
        let nodes = vec![test_node("a"), test_node("b"), test_node("c")];
        let coord1 = select_coordinator(&ZoneId::work(), &subject, &nodes);
        let coord2 = select_coordinator(&ZoneId::private(), &subject, &nodes);
        // They might differ (probabilistic but likely with 2 different zones)
        // We just verify both are valid
        assert!(coord1.is_some());
        assert!(coord2.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: LeaseRequest serde edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_request_no_renew_seq_serde() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("s"),
            zone_id: test_zone(),
            requester: test_node("n"),
            requested_ttl: 120,
            renew_seq: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        let back: LeaseRequest = serde_json::from_str(&json).unwrap();
        assert!(back.renew_seq.is_none());
        assert_eq!(back.requested_ttl, 120);
    }

    #[test]
    fn lease_request_zero_ttl() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("s"),
            zone_id: test_zone(),
            requester: test_node("n"),
            requested_ttl: 0,
            renew_seq: None,
        };
        assert_eq!(request.requested_ttl, 0);
    }

    #[test]
    fn lease_request_max_ttl() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("s"),
            zone_id: test_zone(),
            requester: test_node("n"),
            requested_ttl: u32::MAX,
            renew_seq: None,
        };
        assert_eq!(request.requested_ttl, u32::MAX);
    }

    #[test]
    fn lease_request_debug_format() {
        let request = LeaseRequest {
            subject_object_id: test_object_id("s"),
            zone_id: test_zone(),
            requester: test_node("n"),
            requested_ttl: 60,
            renew_seq: None,
        };
        let dbg = format!("{request:?}");
        assert!(dbg.contains("LeaseRequest"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: LeaseResponse edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_response_invalid_empty_reason() {
        let response = LeaseResponse::Invalid {
            reason: String::new(),
        };
        assert!(matches!(&response, LeaseResponse::Invalid { reason } if reason.is_empty()));
    }

    #[test]
    fn lease_response_denied_zero_values() {
        let response = LeaseResponse::Denied {
            current_holder: test_node("h"),
            expires_at: 0,
            current_seq: 0,
        };
        let json = serde_json::to_string(&response).unwrap();
        let back: LeaseResponse = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            back,
            LeaseResponse::Denied {
                expires_at: 0,
                current_seq: 0,
                ..
            }
        ));
    }

    #[test]
    fn lease_response_debug_format() {
        let resp = LeaseResponse::Invalid {
            reason: "test".to_string(),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("Invalid"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: current_timestamp
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn current_timestamp_monotonic_within_test() {
        let t1 = current_timestamp();
        let t2 = current_timestamp();
        assert!(t2 >= t1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Expanded coverage: Lease::new
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn lease_new_zero_ttl() {
        use crate::Provenance;
        use fcp_cbor::SchemaId;
        use semver::Version;

        let zone = test_zone();
        let subject = test_object_id("s");
        let params = LeaseParams {
            schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            holder: test_node("h"),
            lease_seq: 1,
            ttl_secs: 0,
            subject_object_id: subject,
            provenance: Provenance::new(zone),
            purpose: LeasePurpose::ResourceAccess,
            quorum_signatures: SignatureSet::default(),
        };
        let lease = Lease::new(params);
        assert_eq!(lease.exp, lease.header.created_at);
    }

    #[test]
    fn lease_new_large_ttl() {
        use crate::Provenance;
        use fcp_cbor::SchemaId;
        use semver::Version;

        let zone = test_zone();
        let subject = test_object_id("s");
        let params = LeaseParams {
            schema: SchemaId::new("fcp.lease", "lease", Version::new(1, 0, 0)),
            zone_id: zone.clone(),
            holder: test_node("h"),
            lease_seq: 1,
            ttl_secs: u32::MAX,
            subject_object_id: subject,
            provenance: Provenance::new(zone),
            purpose: LeasePurpose::ConnectorStateWrite,
            quorum_signatures: SignatureSet::default(),
        };
        let lease = Lease::new(params);
        assert_eq!(lease.exp, lease.header.created_at + u64::from(u32::MAX));
    }
}
