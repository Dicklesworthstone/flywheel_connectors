//! Revocation types for FCP (NORMATIVE).
//!
//! This module implements the revocation system from `FCP_Specification_V3.md` §6.4.
//! Revocations make compromised devices/keys/tokens recoverable. Without revocation,
//! "compromised device" recovery is mostly imaginary.
//!
//! # Core Concepts
//!
//! - `RevocationObject`: Owner-signed object revoking one or more `ObjectId`s
//! - `RevocationEvent`: Chain node linking revocations with monotonic sequence
//! - `RevocationHead`: Quorum-signed checkpoint for O(1) freshness comparison
//! - `RevocationRegistry`: Exact lookup table for revocation objects
//!
//! # Freshness Policies
//!
//! | Policy | Behavior |
//! |--------|----------|
//! | Strict | Require fresh revocation frontier or abort |
//! | Warn | Allow cached if within `max_age`, record degraded |
//! | `BestEffort` | Proceed with stale cache, record degraded state |
//!
//! # Enforcement
//!
//! Revocations MUST be checked before any capability use:
//! ```text
//! if registry.is_revoked(&capability_token_id) {
//!     return Err(FcpError::CapabilityRevoked);
//! }
//! ```

use std::collections::HashMap;
use std::fmt;

use fcp_crypto::{
    CryptoResult, HybridSignable, HybridSignedObjectKind, SignedEnvelope, signing_bytes_for_payload,
};
use serde::{Deserialize, Serialize};

use crate::{ObjectHeader, ObjectId, QuorumPolicy, QuotientFilter, RiskTier, SignatureSet, ZoneId};

/// Scope of a revocation (NORMATIVE).
///
/// Determines what type of object is being revoked and how the revocation
/// should be enforced across the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationScope {
    /// Revoke capability tokens.
    /// Affected tokens MUST be rejected at all verification points.
    Capability,

    /// Revoke an issuer key.
    /// The node can no longer mint tokens; existing tokens remain valid until expiry.
    IssuerKey,

    /// Revoke a node attestation.
    /// Removes the device from the mesh entirely.
    NodeAttestation,

    /// Revoke a zone key.
    /// Forces zone key rotation; all zone members must re-enroll.
    ZoneKey,

    /// Revoke a connector binary.
    /// Supply chain response: connector MUST be stopped and replaced.
    ConnectorBinary,
}

impl RevocationScope {
    /// Get the human-readable name for this scope.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Capability => "capability",
            Self::IssuerKey => "issuer_key",
            Self::NodeAttestation => "node_attestation",
            Self::ZoneKey => "zone_key",
            Self::ConnectorBinary => "connector_binary",
        }
    }

    /// Check if this revocation scope is critical (requires immediate action).
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::NodeAttestation | Self::ZoneKey | Self::ConnectorBinary
        )
    }
}

impl fmt::Display for RevocationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Revocation object (NORMATIVE).
///
/// An owner-signed object that revokes one or more `ObjectId`s. The revocation
/// becomes effective at `effective_at` and may optionally expire.
///
/// # Signature Requirements
///
/// The `signature` field MUST be an Ed25519 signature from the zone owner.
/// Non-owner signatures are invalid and MUST be rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationObject {
    /// Object header with zone, schema, and provenance.
    pub header: ObjectHeader,

    /// `ObjectIds` being revoked.
    pub revoked: Vec<ObjectId>,

    /// Type of revocation.
    pub scope: RevocationScope,

    /// Human-readable reason for revocation.
    pub reason: String,

    /// When revocation becomes effective (UNIX timestamp).
    pub effective_at: u64,

    /// When revocation expires (None = permanent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Owner signature (Ed25519, REQUIRED).
    #[serde(with = "crate::util::hex_or_bytes")]
    pub signature: [u8; 64],
}

impl RevocationObject {
    /// Check if the revocation is currently active.
    #[must_use]
    pub fn is_active(&self, now: u64) -> bool {
        if now < self.effective_at {
            return false;
        }
        self.expires_at.is_none_or(|exp| now < exp)
    }

    /// Check if a specific object ID is revoked by this revocation.
    #[must_use]
    pub fn revokes(&self, object_id: &ObjectId) -> bool {
        self.revoked.contains(object_id)
    }

    /// Get the zone this revocation applies to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }
}

impl HybridSignable for RevocationObject {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::Revocation;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature = [0_u8; 64];
        signing_bytes_for_payload(Self::OBJECT_KIND, &unsigned)
    }
}

/// Hybrid signed revocation-object envelope.
pub type HybridSignedRevocationObject = SignedEnvelope<RevocationObject>;

/// Revocation event chain node (NORMATIVE).
///
/// Links revocation objects into a hash-chain with monotonic sequence numbers.
/// This enables O(1) freshness comparison: if your local `head_seq` is less than
/// the remote `head_seq`, you're stale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEvent {
    /// Object header.
    pub header: ObjectHeader,

    /// The revocation object this event references.
    pub revocation_object_id: ObjectId,

    /// Previous event in the chain (None for genesis).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<ObjectId>,

    /// Monotonic sequence number for O(1) freshness comparison.
    pub seq: u64,

    /// When the revocation occurred (UNIX timestamp).
    pub occurred_at: u64,

    /// Signature over the event (from the issuing node).
    #[serde(with = "crate::util::hex_or_bytes")]
    pub signature: [u8; 64],
}

impl RevocationEvent {
    /// Check if this event follows another event in the chain.
    ///
    /// # Arguments
    ///
    /// * `other` - The event that should precede this one
    /// * `other_id` - The `ObjectId` of `other` (computed from its content/header)
    ///
    /// # Returns
    ///
    /// `true` if this event's `prev` points to `other_id` and this event's
    /// sequence number is exactly one greater than `other`'s.
    #[must_use]
    pub fn follows(&self, other: &Self, other_id: &ObjectId) -> bool {
        // Use checked_add to prevent overflow when other.seq is u64::MAX
        other
            .seq
            .checked_add(1)
            .is_some_and(|next_seq| self.seq == next_seq)
            && self.prev.as_ref() == Some(other_id)
    }

    /// Get the zone this event belongs to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }
}

impl HybridSignable for RevocationEvent {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::Revocation;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature = [0_u8; 64];
        signing_bytes_for_payload(Self::OBJECT_KIND, &unsigned)
    }
}

/// Hybrid signed revocation-event envelope.
pub type HybridSignedRevocationEvent = SignedEnvelope<RevocationEvent>;

/// Epoch identifier for revocation head checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpochId(String);

impl EpochId {
    /// Create a new epoch ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the epoch ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Revocation head checkpoint (NORMATIVE).
///
/// A quorum-signed checkpoint that represents the current state of the
/// revocation chain for a zone. Nodes can compare `head_seq` values for
/// O(1) freshness determination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationHead {
    /// Object header.
    pub header: ObjectHeader,

    /// Zone this head applies to.
    pub zone_id: ZoneId,

    /// `ObjectId` of the head event.
    pub head_event: ObjectId,

    /// Sequence number of the head event (for O(1) freshness).
    pub head_seq: u64,

    /// Epoch identifier for this checkpoint.
    pub epoch_id: EpochId,

    /// Quorum signatures from zone nodes (NORMATIVE).
    pub quorum_signatures: SignatureSet,
}

impl RevocationHead {
    /// Check if this head is fresher than another.
    #[must_use]
    pub const fn is_fresher_than(&self, other: &Self) -> bool {
        self.head_seq > other.head_seq
    }

    /// Check if this head satisfies the quorum policy.
    #[must_use]
    pub fn satisfies_quorum(&self, policy: &QuorumPolicy) -> bool {
        self.quorum_signatures
            .satisfies_quorum(policy, RiskTier::CriticalWrite)
    }

    /// Get the age of this head relative to a timestamp.
    #[must_use]
    pub const fn age_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.header.created_at)
    }
}

impl HybridSignable for RevocationHead {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::Revocation;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.quorum_signatures = SignatureSet::new();
        signing_bytes_for_payload(Self::OBJECT_KIND, &unsigned)
    }
}

/// Hybrid signed revocation-head envelope.
pub type HybridSignedRevocationHead = SignedEnvelope<RevocationHead>;

/// Freshness policy for revocation checks (NORMATIVE).
///
/// Determines how strictly revocation freshness is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum FreshnessPolicy {
    /// Require fresh revocation frontier or abort.
    /// Use for high-risk operations where stale revocation data is unacceptable.
    #[default]
    Strict,

    /// Allow cached revocations if within `max_age`.
    /// Records degraded state but allows operation to proceed.
    Warn,

    /// Proceed with stale cache, record degraded state.
    /// Use only when availability trumps security.
    BestEffort,
}

impl FreshnessPolicy {
    /// Get the human-readable name for this policy.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Warn => "warn",
            Self::BestEffort => "best_effort",
        }
    }

    /// Check if this policy allows stale data.
    #[must_use]
    pub const fn allows_stale(&self) -> bool {
        !matches!(self, Self::Strict)
    }

    /// Get the default freshness policy for a risk tier.
    #[must_use]
    pub const fn for_risk_tier(tier: RiskTier) -> Self {
        match tier {
            RiskTier::CriticalWrite | RiskTier::Dangerous => Self::Strict,
            RiskTier::Risky => Self::Warn,
            RiskTier::Safe => Self::BestEffort,
        }
    }
}

impl fmt::Display for FreshnessPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Revocation Freshness Class (manifest-declared, C1.3)
// ─────────────────────────────────────────────────────────────────────────────

/// Revocation freshness class declared in connector manifests (NORMATIVE).
///
/// The connector author sets this per-operation in `manifest.toml` to declare
/// the minimum freshness guarantee the host MUST enforce. The host MUST NOT
/// allow an operator to downgrade a `Critical` operation to `BestEffort`.
///
/// Mapping to [`FreshnessPolicy`]:
/// - `Critical` → `Strict` (deny if stale)
/// - `Risky` → `Warn` (log degradation)
/// - `Safe` → `BestEffort` (proceed with stale cache)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationFreshnessClass {
    /// Security-critical operation (secret access, zone key rotation, etc.).
    /// Host MUST use `Strict` freshness. Deny if stale.
    Critical,

    /// Risk-bearing operation (writes, deletes, escalated reads).
    /// Host MUST use at least `Warn` freshness. Log degradation.
    Risky,

    /// Low-risk read-only operation.
    /// Host MAY use `BestEffort` freshness.
    Safe,
}

impl RevocationFreshnessClass {
    /// The minimum [`FreshnessPolicy`] this class requires.
    #[must_use]
    pub const fn minimum_policy(&self) -> FreshnessPolicy {
        match self {
            Self::Critical => FreshnessPolicy::Strict,
            Self::Risky => FreshnessPolicy::Warn,
            Self::Safe => FreshnessPolicy::BestEffort,
        }
    }

    /// Check whether an operator-chosen policy satisfies this class.
    ///
    /// Returns `true` if `operator_policy` is at least as strict as the
    /// class requires.
    #[must_use]
    pub const fn allows_policy(&self, operator_policy: FreshnessPolicy) -> bool {
        // Strict > Warn > BestEffort  (lower ordinal = stricter)
        // A policy satisfies a class if it is AT LEAST as strict.
        match (self, operator_policy) {
            (Self::Critical, FreshnessPolicy::Strict)
            | (Self::Risky, FreshnessPolicy::Strict | FreshnessPolicy::Warn)
            | (Self::Safe, _) => true,
            (Self::Critical | Self::Risky, _) => false,
        }
    }

    /// String representation for TOML/JSON.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Risky => "risky",
            Self::Safe => "safe",
        }
    }
}

impl fmt::Display for RevocationFreshnessClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Revocation check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCheckResult {
    /// Whether the object is revoked.
    pub is_revoked: bool,

    /// The revocation object if revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation: Option<ObjectId>,

    /// Scope of the revocation if revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<RevocationScope>,

    /// Whether the check used stale data.
    pub stale_data: bool,

    /// Age of the revocation head in seconds.
    pub head_age_secs: u64,
}

/// Revocation registry (NORMATIVE).
///
/// Provides exact revocation lookups via a hash map. The quotient cache is a
/// negative precheck only: cache positives still fall through to the exact
/// registry, so false positives cannot revoke a non-revoked object.
///
/// # Usage
///
/// ```ignore
/// let registry = RevocationRegistry::new();
///
/// // Fast path: definitely not revoked
/// if !registry.is_revoked(&object_id) {
///     // Safe to proceed
/// }
///
/// // Get full revocation details
/// if let Some(revocation) = registry.get_revocation(&object_id) {
///     // Handle revocation
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct RevocationRegistry {
    /// Signed, non-dominated revocation windows for each revoked `ObjectId`.
    revocations: HashMap<ObjectId, Vec<RevocationObject>>,

    /// Local mutation history, independent of publication of the chain head.
    /// A hash chain avoids counter wraparound and distinguishes divergent
    /// registries that happen to have applied the same number of mutations.
    revision: [u8; 32],

    /// Revocation-aware negative cache for fast definitely-absent checks.
    pub quotient_cache: QuotientFilter<ObjectId>,

    /// Latest known revocation head.
    pub head: Option<ObjectId>,

    /// Head sequence number for freshness comparison.
    pub head_seq: u64,

    /// When the registry was last updated (UNIX timestamp).
    pub last_updated: u64,
}

impl RevocationRegistry {
    /// Create a new empty revocation registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry with custom revocation-cache sizing.
    #[must_use]
    pub fn with_capacity(expected_revocations: usize) -> Self {
        Self {
            revocations: HashMap::with_capacity(expected_revocations),
            revision: [0; 32],
            quotient_cache: QuotientFilter::with_capacity(expected_revocations),
            head: None,
            head_seq: 0,
            last_updated: 0,
        }
    }

    /// Check if an object ID is revoked (MUST be called before any capability use).
    ///
    /// Exact membership check; the quotient cache only skips definite misses.
    #[must_use]
    pub fn is_revoked(&self, object_id: &ObjectId) -> bool {
        if !self.quotient_cache.may_contain(object_id) {
            return false;
        }
        self.revocations.contains_key(object_id)
    }

    /// Check if any retained revocation is active at a specific time.
    ///
    /// Independent signed windows combine by union. A later suspension must
    /// remain effective even when it does not contain an earlier suspension.
    #[must_use]
    pub fn is_revoked_at(&self, object_id: &ObjectId, at: u64) -> bool {
        self.get_revocations(object_id)
            .iter()
            .any(|revocation| revocation.is_active(at))
    }

    /// Get one retained signed revocation for an object ID.
    ///
    /// This representative is not necessarily active at the caller's time.
    /// Use [`Self::is_revoked_at`] for temporal decisions and
    /// [`Self::get_revocations`] for all retained evidence.
    #[must_use]
    pub fn get_revocation(&self, object_id: &ObjectId) -> Option<&RevocationObject> {
        self.get_revocations(object_id).first()
    }

    /// Get every retained signed revocation window for an object ID.
    ///
    /// Covered windows in the same zone and scope are redundant and may be
    /// removed. Remaining objects are preserved byte-for-byte; synthesizing a
    /// wider window would invalidate their owner signatures and could revoke
    /// an object during a gap that no owner authorized.
    #[must_use]
    pub fn get_revocations(&self, object_id: &ObjectId) -> &[RevocationObject] {
        self.revocations.get(object_id).map_or(&[], Vec::as_slice)
    }

    /// Add a revocation to the registry.
    ///
    /// Each object's windows form a non-dominated set: discard an incoming
    /// window only if an existing window in the same zone and scope covers it;
    /// otherwise retain it and remove any windows that it completely covers.
    /// Identical windows remain first-writer wins, so replays do not churn
    /// metadata. Disjoint and partially overlapping windows are all retained.
    ///
    /// This preserves every authorized revoked instant regardless of delivery
    /// order, without letting future or already-expired records suppress an
    /// active revocation. `None` for `expires_at` is an unbounded endpoint.
    /// Signature and owner authority must be verified before insertion.
    pub fn add_revocation(&mut self, revocation: &RevocationObject) {
        for object_id in &revocation.revoked {
            let windows = self.revocations.entry(*object_id).or_default();
            if windows
                .iter()
                .any(|existing| revocation_covers(existing, revocation))
            {
                continue;
            }
            windows.retain(|existing| !revocation_covers(revocation, existing));
            windows.push(revocation.clone());
            self.quotient_cache.insert(object_id);
            self.record_revocation_mutation(object_id, revocation);
        }
    }

    fn record_revocation_mutation(&mut self, object_id: &ObjectId, revocation: &RevocationObject) {
        let mut hasher = blake3::Hasher::new_derive_key("FCP/RevocationRegistry/add/v1");
        hasher.update(&self.revision);
        hasher.update(object_id.as_bytes());
        let zone = revocation.zone_id().as_bytes();
        hasher.update(&(zone.len() as u64).to_le_bytes());
        hasher.update(zone);
        hasher.update(revocation.scope.as_str().as_bytes());
        hasher.update(&revocation.effective_at.to_le_bytes());
        if let Some(expiry) = revocation.expires_at {
            hasher.update(&[1]);
            hasher.update(&expiry.to_le_bytes());
        } else {
            hasher.update(&[0]);
        }
        hasher.update(&revocation.signature);
        self.revision = *hasher.finalize().as_bytes();
    }

    /// Update the head pointer and sequence.
    pub const fn update_head(&mut self, head: ObjectId, seq: u64, updated_at: u64) {
        // Enforce sequence monotonicity (C1.3)
        if seq <= self.head_seq && self.head.is_some() {
            return;
        }
        self.head = Some(head);
        self.head_seq = seq;
        self.last_updated = updated_at;
    }

    /// Check freshness against a remote head.
    ///
    /// Returns `true` if this registry is fresh (not behind the remote).
    #[must_use]
    pub const fn is_fresh(&self, remote_seq: u64) -> bool {
        self.head_seq >= remote_seq
    }

    /// Check freshness with a policy and max age.
    ///
    /// # Arguments
    ///
    /// * `remote_seq` - Remote head sequence number
    /// * `policy` - Freshness enforcement policy
    /// * `max_age_secs` - Maximum acceptable age for cached data
    /// * `now` - Current timestamp
    ///
    /// # Returns
    ///
    /// A result indicating freshness status.
    #[must_use]
    pub const fn check_freshness(
        &self,
        remote_seq: u64,
        policy: FreshnessPolicy,
        max_age_secs: u64,
        now: u64,
    ) -> FreshnessCheckResult {
        let is_fresh = self.head_seq >= remote_seq;
        let age = now.saturating_sub(self.last_updated);
        let within_max_age = age <= max_age_secs;

        match policy {
            FreshnessPolicy::Strict => FreshnessCheckResult {
                allowed: is_fresh,
                stale: !is_fresh,
                age_secs: age,
                reason: if is_fresh {
                    None
                } else {
                    Some(FreshnessFailureReason::StaleData)
                },
            },
            FreshnessPolicy::Warn => FreshnessCheckResult {
                allowed: is_fresh || within_max_age,
                stale: !is_fresh,
                age_secs: age,
                reason: if is_fresh {
                    None
                } else if within_max_age {
                    Some(FreshnessFailureReason::StaleButWithinMaxAge)
                } else {
                    Some(FreshnessFailureReason::StaleData)
                },
            },
            FreshnessPolicy::BestEffort => FreshnessCheckResult {
                allowed: true,
                stale: !is_fresh,
                age_secs: age,
                reason: if is_fresh {
                    None
                } else {
                    Some(FreshnessFailureReason::StaleButAllowed)
                },
            },
        }
    }

    /// Get the number of revocations in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revocations.len()
    }

    /// Check if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revocations.is_empty()
    }

    /// Clear all revocations.
    pub fn clear(&mut self) {
        // Never reuse an earlier revision: clearing and rebuilding the same
        // frontier must not resurrect a seal from before the reset.
        let mut hasher = blake3::Hasher::new_derive_key("FCP/RevocationRegistry/clear/v1");
        hasher.update(&self.revision);
        self.revision = *hasher.finalize().as_bytes();
        self.revocations.clear();
        self.quotient_cache.clear();
        self.head = None;
        self.head_seq = 0;
        self.last_updated = 0;
    }

    /// Get all revocations of a specific scope.
    #[must_use]
    pub fn revocations_by_scope(&self, scope: RevocationScope) -> Vec<&RevocationObject> {
        self.revocations
            .values()
            .flatten()
            .filter(|r| r.scope == scope)
            .collect()
    }
}

fn revocation_covers(outer: &RevocationObject, inner: &RevocationObject) -> bool {
    outer.scope == inner.scope
        && outer.zone_id() == inner.zone_id()
        && outer.effective_at <= inner.effective_at
        && match (outer.expires_at, inner.expires_at) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(outer_expiry), Some(inner_expiry)) => outer_expiry >= inner_expiry,
        }
}

/// Result of a freshness check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshnessCheckResult {
    /// Whether the operation is allowed to proceed.
    pub allowed: bool,

    /// Whether the data is stale.
    pub stale: bool,

    /// Age of the cached data in seconds.
    pub age_secs: u64,

    /// Reason for failure or degraded operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<FreshnessFailureReason>,
}

/// Reasons for freshness check results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FreshnessFailureReason {
    /// Data is stale and operation was blocked.
    StaleData,
    /// Data is stale but within max age (Warn policy).
    StaleButWithinMaxAge,
    /// Data is stale but operation allowed (`BestEffort` policy).
    StaleButAllowed,
}

impl FreshnessFailureReason {
    /// Get the human-readable description.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::StaleData => "stale_data",
            Self::StaleButWithinMaxAge => "stale_but_within_max_age",
            Self::StaleButAllowed => "stale_but_allowed",
        }
    }
}

impl fmt::Display for FreshnessFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Revocation Seal (C1.1 — Check-Use Atomicity)
// ─────────────────────────────────────────────────────────────────────────────

/// The decision produced by a revocation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationDecision {
    /// The object is NOT revoked at the time of the check.
    NotRevoked,
    /// The object IS revoked at the time of the check.
    Revoked,
}

/// A sealed proof of a revocation check at a specific point in time.
///
/// The `RevocationSeal` binds a revocation check result to the registry's
/// head and local revision at check time. At operation commit time, the seal
/// MUST be re-validated: a new revocation invalidates it immediately, even
/// before the corresponding chain head has been published.
///
/// This is an optimistic concurrency control mechanism, NOT a lock. Most
/// operations will find the seal still valid. Only operations that race
/// with a revocation event will need re-checking.
///
/// # Invariant
///
/// A seal is valid only while the head, sequence, local revision, and exact
/// membership decision still match. This is a consistency proof within a
/// trusted process, not a signed authorization object for remote callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationSeal {
    /// Timestamp when the check was performed (monotonic counter or UNIX epoch).
    pub checked_at: u64,
    /// The registry `head_seq` at the time of the check.
    pub head_seq: u64,
    /// Exact chain head observed, including an uninitialized registry.
    pub registry_head: Option<ObjectId>,
    /// Local mutation revision, independent of the published chain head.
    #[serde(with = "crate::util::hex_or_bytes")]
    pub registry_revision: [u8; 32],
    /// The object ID that was checked.
    pub token_id: ObjectId,
    /// The decision: was the object revoked or not?
    pub decision: RevocationDecision,
}

/// Result of validating a seal against the current registry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SealValidation {
    /// Seal is still valid — `head_seq` has not advanced.
    Valid,
    /// Seal is stale — `head_seq` has advanced, re-check required.
    Stale {
        /// The seal's `head_seq` at check time.
        seal_seq: u64,
        /// The current registry `head_seq`.
        current_seq: u64,
    },
    /// Local revocations or the exact head changed without a sequence change,
    /// or the claimed decision no longer matches exact registry membership.
    StateChanged,
    /// Seal `token_id` does not match the expected token.
    TokenMismatch,
}

impl SealValidation {
    /// Stable variant label for registry-consistency reporting.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Stale { .. } => "stale",
            Self::StateChanged => "state_changed",
            Self::TokenMismatch => "token_mismatch",
        }
    }

    /// Whether the seal is still valid.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

impl fmt::Display for SealValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RevocationRegistry {
    /// Check revocation status and return a sealed proof.
    ///
    /// The seal captures exact membership and both published and unpublished
    /// registry changes. Like [`Self::is_revoked`], it conservatively denies
    /// every known revoked ID regardless of the window's effective time.
    #[must_use]
    pub fn check_with_seal(&self, token_id: &ObjectId, now: u64) -> RevocationSeal {
        let decision = if self.is_revoked(token_id) {
            RevocationDecision::Revoked
        } else {
            RevocationDecision::NotRevoked
        };

        RevocationSeal {
            checked_at: now,
            head_seq: self.head_seq,
            registry_head: self.head,
            registry_revision: self.revision,
            token_id: *token_id,
            decision,
        }
    }

    /// Validate a seal against the current registry state.
    ///
    /// Returns `Valid` only if the frontier, local revision and decision match.
    /// `Stale` reports a sequence change, `StateChanged` a local mutation or
    /// conflicting head/decision, and `TokenMismatch` an unrelated token.
    #[must_use]
    pub fn validate_seal(
        &self,
        seal: &RevocationSeal,
        expected_token_id: &ObjectId,
    ) -> SealValidation {
        if seal.token_id != *expected_token_id {
            return SealValidation::TokenMismatch;
        }

        if seal.head_seq != self.head_seq {
            return SealValidation::Stale {
                seal_seq: seal.head_seq,
                current_seq: self.head_seq,
            };
        }

        let revoked = self.is_revoked(expected_token_id);
        if seal.registry_head != self.head
            || seal.registry_revision != self.revision
            || (seal.decision == RevocationDecision::Revoked) != revoked
        {
            return SealValidation::StateChanged;
        }

        SealValidation::Valid
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Revocation SLA Checker (C1.4 — Zone-Wide Revocation Freshness SLA)
// ─────────────────────────────────────────────────────────────────────────────

/// The revocation freshness status of a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationSlaStatus {
    /// The zone's revocation frontier is within the SLA window.
    Fresh,
    /// The zone's revocation frontier is stale — SLA breached.
    Breached {
        /// How many seconds past the SLA the frontier is.
        overdue_secs: u64,
    },
}

impl RevocationSlaStatus {
    /// Whether the zone's revocation is fresh.
    #[must_use]
    pub const fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// Checks whether a zone's revocation frontier meets the declared SLA.
///
/// The SLA is declared in the [`ZoneCheckpoint`](crate::audit::ZoneCheckpoint)
/// via `revocation_freshness_sla_secs`. This checker compares the checkpoint's
/// `rev_seq` timestamp against the current time to determine if the zone is
/// in DEGRADED revocation state.
#[derive(Debug, Clone)]
pub struct RevocationSlaChecker {
    /// The `rev_seq` from the zone checkpoint.
    pub checkpoint_rev_seq: u64,
    /// When the checkpoint was last updated (UNIX epoch seconds).
    pub checkpoint_updated_at: u64,
    /// The SLA window in seconds.
    pub sla_secs: u64,
}

impl RevocationSlaChecker {
    /// Create a new SLA checker from checkpoint data.
    #[must_use]
    pub const fn new(checkpoint_rev_seq: u64, checkpoint_updated_at: u64, sla_secs: u64) -> Self {
        Self {
            checkpoint_rev_seq,
            checkpoint_updated_at,
            sla_secs,
        }
    }

    /// Check whether the revocation SLA is met at the given time.
    #[must_use]
    pub const fn check_sla(&self, now: u64) -> RevocationSlaStatus {
        let age = now.saturating_sub(self.checkpoint_updated_at);
        if age <= self.sla_secs {
            RevocationSlaStatus::Fresh
        } else {
            RevocationSlaStatus::Breached {
                overdue_secs: age - self.sla_secs,
            }
        }
    }

    /// Whether an operation with the given freshness class may proceed.
    ///
    /// - `Critical` operations MUST abort when SLA is breached.
    /// - `Risky` operations SHOULD warn but may proceed.
    /// - `Safe` operations may always proceed.
    #[must_use]
    pub const fn may_proceed(&self, now: u64, freshness_class: RevocationFreshnessClass) -> bool {
        match freshness_class {
            RevocationFreshnessClass::Critical => self.check_sla(now).is_fresh(),
            RevocationFreshnessClass::Risky | RevocationFreshnessClass::Safe => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provenance;
    use fcp_cbor::SchemaId;
    use semver::Version;

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.core", "RevocationObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_revocation() -> RevocationObject {
        RevocationObject {
            header: test_header(),
            revoked: vec![ObjectId::from_bytes([1u8; 32])],
            scope: RevocationScope::Capability,
            reason: "Compromised device".into(),
            effective_at: 1_700_000_000,
            expires_at: None,
            signature: [0u8; 64],
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationScope Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_scope_display() {
        assert_eq!(RevocationScope::Capability.to_string(), "capability");
        assert_eq!(RevocationScope::IssuerKey.to_string(), "issuer_key");
        assert_eq!(
            RevocationScope::NodeAttestation.to_string(),
            "node_attestation"
        );
        assert_eq!(RevocationScope::ZoneKey.to_string(), "zone_key");
        assert_eq!(
            RevocationScope::ConnectorBinary.to_string(),
            "connector_binary"
        );
    }

    #[test]
    fn revocation_scope_is_critical() {
        assert!(!RevocationScope::Capability.is_critical());
        assert!(!RevocationScope::IssuerKey.is_critical());
        assert!(RevocationScope::NodeAttestation.is_critical());
        assert!(RevocationScope::ZoneKey.is_critical());
        assert!(RevocationScope::ConnectorBinary.is_critical());
    }

    #[test]
    fn revocation_scope_serialization() {
        let scope = RevocationScope::Capability;
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("Capability"));

        let deserialized: RevocationScope = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, scope);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_object_is_active() {
        let revocation = test_revocation();

        // Before effective_at: not active
        assert!(!revocation.is_active(1_699_999_999));

        // At effective_at: active
        assert!(revocation.is_active(1_700_000_000));

        // After effective_at: active (permanent)
        assert!(revocation.is_active(2_000_000_000));
    }

    #[test]
    fn revocation_object_is_active_with_expiry() {
        let mut revocation = test_revocation();
        revocation.expires_at = Some(1_800_000_000);

        // Before effective_at: not active
        assert!(!revocation.is_active(1_699_999_999));

        // Between effective and expiry: active
        assert!(revocation.is_active(1_750_000_000));

        // After expiry: not active
        assert!(!revocation.is_active(1_800_000_001));
    }

    #[test]
    fn revocation_object_revokes() {
        let revocation = test_revocation();
        let revoked_id = ObjectId::from_bytes([1u8; 32]);
        let other_id = ObjectId::from_bytes([2u8; 32]);

        assert!(revocation.revokes(&revoked_id));
        assert!(!revocation.revokes(&other_id));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessPolicy Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_policy_display() {
        assert_eq!(FreshnessPolicy::Strict.to_string(), "strict");
        assert_eq!(FreshnessPolicy::Warn.to_string(), "warn");
        assert_eq!(FreshnessPolicy::BestEffort.to_string(), "best_effort");
    }

    #[test]
    fn freshness_policy_allows_stale() {
        assert!(!FreshnessPolicy::Strict.allows_stale());
        assert!(FreshnessPolicy::Warn.allows_stale());
        assert!(FreshnessPolicy::BestEffort.allows_stale());
    }

    #[test]
    fn freshness_policy_for_risk_tier() {
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::CriticalWrite),
            FreshnessPolicy::Strict
        );
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::Dangerous),
            FreshnessPolicy::Strict
        );
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::Risky),
            FreshnessPolicy::Warn
        );
        assert_eq!(
            FreshnessPolicy::for_risk_tier(RiskTier::Safe),
            FreshnessPolicy::BestEffort
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationRegistry Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn registry_empty() {
        let registry = RevocationRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.head.is_none());
    }

    #[test]
    fn registry_is_revoked_fast_path() {
        let registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([99u8; 32]);

        assert!(!registry.is_revoked(&id));
    }

    #[test]
    fn registry_add_and_check_revocation() {
        let mut registry = RevocationRegistry::new();
        let revocation = test_revocation();
        let revoked_id = ObjectId::from_bytes([1u8; 32]);
        let other_id = ObjectId::from_bytes([2u8; 32]);

        registry.add_revocation(&revocation);

        assert!(registry.is_revoked(&revoked_id));
        assert!(!registry.is_revoked(&other_id));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_is_revoked_at() {
        let mut registry = RevocationRegistry::new();
        let mut revocation = test_revocation();
        revocation.expires_at = Some(1_800_000_000);

        let revoked_id = ObjectId::from_bytes([1u8; 32]);
        registry.add_revocation(&revocation);

        // Before effective: not revoked
        assert!(!registry.is_revoked_at(&revoked_id, 1_699_999_999));

        // During active period: revoked
        assert!(registry.is_revoked_at(&revoked_id, 1_750_000_000));

        // After expiry: not revoked
        assert!(!registry.is_revoked_at(&revoked_id, 1_800_000_001));
    }

    #[test]
    fn registry_get_revocation() {
        let mut registry = RevocationRegistry::new();
        let revocation = test_revocation();
        let revoked_id = ObjectId::from_bytes([1u8; 32]);

        registry.add_revocation(&revocation);

        let retrieved = registry.get_revocation(&revoked_id).unwrap();
        assert_eq!(retrieved.reason, "Compromised device");
        assert_eq!(retrieved.scope, RevocationScope::Capability);
    }

    #[test]
    fn registry_update_head() {
        let mut registry = RevocationRegistry::new();
        let head = ObjectId::from_bytes([42u8; 32]);

        registry.update_head(head, 100, 1_700_000_000);

        assert_eq!(registry.head, Some(head));
        assert_eq!(registry.head_seq, 100);
        assert_eq!(registry.last_updated, 1_700_000_000);
    }

    #[test]
    fn registry_is_fresh() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;

        assert!(registry.is_fresh(50)); // Equal
        assert!(registry.is_fresh(25)); // Ahead
        assert!(!registry.is_fresh(100)); // Behind
    }

    #[test]
    fn registry_check_freshness_strict() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        let now = 1_700_000_100;

        // Fresh: allowed
        let result = registry.check_freshness(50, FreshnessPolicy::Strict, 300, now);
        assert!(result.allowed);
        assert!(!result.stale);

        // Stale: blocked
        let result = registry.check_freshness(100, FreshnessPolicy::Strict, 300, now);
        assert!(!result.allowed);
        assert!(result.stale);
    }

    #[test]
    fn registry_check_freshness_warn() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        let now = 1_700_000_100;
        let max_age = 200;

        // Stale but within max_age: allowed with warning
        let result = registry.check_freshness(100, FreshnessPolicy::Warn, max_age, now);
        assert!(result.allowed);
        assert!(result.stale);
        assert_eq!(
            result.reason,
            Some(FreshnessFailureReason::StaleButWithinMaxAge)
        );

        // Stale and beyond max_age: blocked
        let result = registry.check_freshness(100, FreshnessPolicy::Warn, 50, now);
        assert!(!result.allowed);
        assert!(result.stale);
    }

    #[test]
    fn registry_check_freshness_best_effort() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        let now = 1_700_001_000; // Very stale

        // Always allowed
        let result = registry.check_freshness(100, FreshnessPolicy::BestEffort, 0, now);
        assert!(result.allowed);
        assert!(result.stale);
        assert_eq!(result.reason, Some(FreshnessFailureReason::StaleButAllowed));
    }

    #[test]
    fn registry_clear() {
        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&test_revocation());
        registry.update_head(ObjectId::from_bytes([1u8; 32]), 10, 1_700_000_000);

        assert!(!registry.is_empty());

        registry.clear();

        assert!(registry.is_empty());
        assert!(registry.head.is_none());
        assert_eq!(registry.head_seq, 0);
    }

    #[test]
    fn registry_revocations_by_scope() {
        let mut registry = RevocationRegistry::new();

        let mut cap_revocation = test_revocation();
        cap_revocation.scope = RevocationScope::Capability;
        cap_revocation.revoked = vec![ObjectId::from_bytes([1u8; 32])];

        let mut key_revocation = test_revocation();
        key_revocation.scope = RevocationScope::IssuerKey;
        key_revocation.revoked = vec![ObjectId::from_bytes([2u8; 32])];

        registry.add_revocation(&cap_revocation);
        registry.add_revocation(&key_revocation);

        let cap_revocations = registry.revocations_by_scope(RevocationScope::Capability);
        assert_eq!(cap_revocations.len(), 1);

        let key_revocations = registry.revocations_by_scope(RevocationScope::IssuerKey);
        assert_eq!(key_revocations.len(), 1);

        let node_revocations = registry.revocations_by_scope(RevocationScope::NodeAttestation);
        assert!(node_revocations.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationEvent Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_event_follows() {
        // The ObjectId of event1 (in a real system, this would be computed from event1's content)
        let event1_id = ObjectId::from_bytes([10u8; 32]);
        let event2_id = ObjectId::from_bytes([20u8; 32]);

        let event1 = RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([1u8; 32]),
            prev: None,
            seq: 1,
            occurred_at: 1_700_000_000,
            signature: [0u8; 64],
        };

        let event2 = RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([2u8; 32]),
            prev: Some(event1_id), // Points to event1's ObjectId, NOT its revocation_object_id
            seq: 2,
            occurred_at: 1_700_000_001,
            signature: [0u8; 64],
        };

        // event2 follows event1 (event2.prev points to event1_id, and seq is correct)
        assert!(event2.follows(&event1, &event1_id));
        // event1 does not follow event2 (wrong order)
        assert!(!event1.follows(&event2, &event2_id));
        // event2 does not follow event1 with wrong ID
        let wrong_id = ObjectId::from_bytes([99u8; 32]);
        assert!(!event2.follows(&event1, &wrong_id));
    }

    #[test]
    fn revocation_event_follows_overflow_protection() {
        let event1_id = ObjectId::from_bytes([10u8; 32]);

        let event1 = RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([1u8; 32]),
            prev: None,
            seq: u64::MAX, // Maximum sequence number
            occurred_at: 1_700_000_000,
            signature: [0u8; 64],
        };

        let event2 = RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([2u8; 32]),
            prev: Some(event1_id),
            seq: 0, // Would be u64::MAX + 1 if it wrapped
            occurred_at: 1_700_000_001,
            signature: [0u8; 64],
        };

        // Should return false because u64::MAX + 1 overflows (no valid successor)
        assert!(!event2.follows(&event1, &event1_id));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationHead Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_head_is_fresher_than() {
        let head1 = RevocationHead {
            header: test_header(),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([1u8; 32]),
            head_seq: 10,
            epoch_id: EpochId::new("epoch-1"),
            quorum_signatures: SignatureSet::new(),
        };

        let head2 = RevocationHead {
            header: test_header(),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([2u8; 32]),
            head_seq: 20,
            epoch_id: EpochId::new("epoch-2"),
            quorum_signatures: SignatureSet::new(),
        };

        assert!(head2.is_fresher_than(&head1));
        assert!(!head1.is_fresher_than(&head2));
        assert!(!head1.is_fresher_than(&head1)); // Same seq
    }

    #[test]
    fn revocation_head_age() {
        let mut head = RevocationHead {
            header: test_header(),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([1u8; 32]),
            head_seq: 10,
            epoch_id: EpochId::new("epoch-1"),
            quorum_signatures: SignatureSet::new(),
        };
        head.header.created_at = 1_700_000_000;

        let now = 1_700_000_100;
        assert_eq!(head.age_secs(now), 100);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EpochId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn epoch_id_display() {
        let epoch = EpochId::new("epoch-2024-01");
        assert_eq!(epoch.to_string(), "epoch-2024-01");
        assert_eq!(epoch.as_str(), "epoch-2024-01");
    }

    #[test]
    fn epoch_id_serialization() {
        let epoch = EpochId::new("epoch-123");
        let json = serde_json::to_string(&epoch).unwrap();
        let deserialized: EpochId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.as_str(), "epoch-123");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationScope – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_scope_serde_roundtrip_all_variants() {
        let variants = [
            RevocationScope::Capability,
            RevocationScope::IssuerKey,
            RevocationScope::NodeAttestation,
            RevocationScope::ZoneKey,
            RevocationScope::ConnectorBinary,
        ];
        for scope in &variants {
            let json = serde_json::to_string(scope).unwrap();
            let decoded: RevocationScope = serde_json::from_str(&json).unwrap();
            assert_eq!(*scope, decoded, "roundtrip mismatch for {scope:?}");
        }
    }

    #[test]
    fn revocation_scope_as_str_all_variants() {
        assert_eq!(RevocationScope::Capability.as_str(), "capability");
        assert_eq!(RevocationScope::IssuerKey.as_str(), "issuer_key");
        assert_eq!(
            RevocationScope::NodeAttestation.as_str(),
            "node_attestation"
        );
        assert_eq!(RevocationScope::ZoneKey.as_str(), "zone_key");
        assert_eq!(
            RevocationScope::ConnectorBinary.as_str(),
            "connector_binary"
        );
    }

    #[test]
    fn revocation_scope_copy() {
        let a = RevocationScope::ZoneKey;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn revocation_scope_clone() {
        let a = RevocationScope::ConnectorBinary;
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn revocation_scope_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RevocationScope::Capability);
        set.insert(RevocationScope::Capability);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn revocation_scope_hash_different_variants() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RevocationScope::Capability);
        set.insert(RevocationScope::IssuerKey);
        set.insert(RevocationScope::NodeAttestation);
        set.insert(RevocationScope::ZoneKey);
        set.insert(RevocationScope::ConnectorBinary);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn revocation_scope_inequality() {
        assert_ne!(RevocationScope::Capability, RevocationScope::IssuerKey);
        assert_ne!(RevocationScope::ZoneKey, RevocationScope::ConnectorBinary);
    }

    #[test]
    fn revocation_scope_critical_vs_non_critical_partition() {
        let non_critical = [RevocationScope::Capability, RevocationScope::IssuerKey];
        let critical = [
            RevocationScope::NodeAttestation,
            RevocationScope::ZoneKey,
            RevocationScope::ConnectorBinary,
        ];
        for scope in &non_critical {
            assert!(!scope.is_critical(), "{scope:?} should not be critical");
        }
        for scope in &critical {
            assert!(scope.is_critical(), "{scope:?} should be critical");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationObject – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_object_zone_id() {
        let revocation = test_revocation();
        assert_eq!(*revocation.zone_id(), ZoneId::work());
    }

    #[test]
    fn revocation_object_revokes_multiple_ids() {
        let mut revocation = test_revocation();
        let id1 = ObjectId::from_bytes([1u8; 32]);
        let id2 = ObjectId::from_bytes([2u8; 32]);
        let id3 = ObjectId::from_bytes([3u8; 32]);
        revocation.revoked = vec![id1, id2];

        assert!(revocation.revokes(&id1));
        assert!(revocation.revokes(&id2));
        assert!(!revocation.revokes(&id3));
    }

    #[test]
    fn revocation_object_revokes_empty_list() {
        let mut revocation = test_revocation();
        revocation.revoked = vec![];
        let id = ObjectId::from_bytes([1u8; 32]);
        assert!(!revocation.revokes(&id));
    }

    #[test]
    fn revocation_object_is_active_exact_effective_at() {
        let revocation = test_revocation();
        // At exactly effective_at: should be active
        assert!(revocation.is_active(revocation.effective_at));
        // One tick before: not active
        assert!(!revocation.is_active(revocation.effective_at - 1));
    }

    #[test]
    fn revocation_object_is_active_exact_expires_at() {
        let mut revocation = test_revocation();
        revocation.expires_at = Some(1_800_000_000);
        // At exactly expires_at: NOT active (now < exp is false when now == exp)
        assert!(!revocation.is_active(1_800_000_000));
        // One tick before expiry: active
        assert!(revocation.is_active(1_799_999_999));
    }

    #[test]
    fn revocation_object_clone() {
        let revocation = test_revocation();
        let cloned = revocation.clone();
        assert_eq!(cloned.scope, revocation.scope);
        assert_eq!(cloned.reason, revocation.reason);
        assert_eq!(cloned.effective_at, revocation.effective_at);
        assert_eq!(cloned.expires_at, revocation.expires_at);
        assert_eq!(cloned.revoked.len(), revocation.revoked.len());
    }

    #[test]
    fn revocation_object_serde_roundtrip() {
        let revocation = test_revocation();
        let json = serde_json::to_string(&revocation).unwrap();
        let decoded: RevocationObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.scope, revocation.scope);
        assert_eq!(decoded.reason, revocation.reason);
        assert_eq!(decoded.effective_at, revocation.effective_at);
        assert_eq!(decoded.expires_at, revocation.expires_at);
        assert_eq!(decoded.revoked, revocation.revoked);
    }

    #[test]
    fn revocation_object_serde_with_expiry() {
        let mut revocation = test_revocation();
        revocation.expires_at = Some(1_900_000_000);
        let json = serde_json::to_string(&revocation).unwrap();
        assert!(json.contains("expires_at"));
        let decoded: RevocationObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.expires_at, Some(1_900_000_000));
    }

    #[test]
    fn revocation_object_serde_without_expiry_omits_field() {
        let revocation = test_revocation();
        assert!(revocation.expires_at.is_none());
        let json = serde_json::to_string(&revocation).unwrap();
        assert!(!json.contains("expires_at"));
    }

    #[test]
    fn revocation_object_all_scopes() {
        let scopes = [
            RevocationScope::Capability,
            RevocationScope::IssuerKey,
            RevocationScope::NodeAttestation,
            RevocationScope::ZoneKey,
            RevocationScope::ConnectorBinary,
        ];
        for scope in scopes {
            let mut rev = test_revocation();
            rev.scope = scope;
            let json = serde_json::to_string(&rev).unwrap();
            let decoded: RevocationObject = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded.scope, scope);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationEvent – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_event(seq: u64, prev: Option<ObjectId>) -> RevocationEvent {
        RevocationEvent {
            header: test_header(),
            revocation_object_id: ObjectId::from_bytes([1u8; 32]),
            prev,
            seq,
            occurred_at: 1_700_000_000 + seq,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn revocation_event_zone_id() {
        let event = test_event(1, None);
        assert_eq!(*event.zone_id(), ZoneId::work());
    }

    #[test]
    fn revocation_event_genesis_has_no_prev() {
        let genesis = test_event(0, None);
        assert!(genesis.prev.is_none());
        assert_eq!(genesis.seq, 0);
    }

    #[test]
    fn revocation_event_follows_requires_exact_seq_increment() {
        let event1_id = ObjectId::from_bytes([10u8; 32]);
        let event1 = test_event(5, None);
        // Gap: seq 5 → seq 7 (should fail, needs seq 6)
        let event_gap = RevocationEvent {
            prev: Some(event1_id),
            seq: 7,
            ..test_event(7, Some(event1_id))
        };
        assert!(!event_gap.follows(&event1, &event1_id));
    }

    #[test]
    fn revocation_event_follows_correct_seq() {
        let event1_id = ObjectId::from_bytes([10u8; 32]);
        let event1 = test_event(5, None);
        let event2 = test_event(6, Some(event1_id));
        assert!(event2.follows(&event1, &event1_id));
    }

    #[test]
    fn revocation_event_clone() {
        let event = test_event(42, None);
        let cloned = event.clone();
        assert_eq!(cloned.seq, event.seq);
        assert_eq!(cloned.occurred_at, event.occurred_at);
        assert_eq!(cloned.prev, event.prev);
        assert_eq!(cloned.revocation_object_id, event.revocation_object_id);
    }

    #[test]
    fn revocation_event_serde_roundtrip() {
        let event = test_event(10, Some(ObjectId::from_bytes([5u8; 32])));
        let json = serde_json::to_string(&event).unwrap();
        let decoded: RevocationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.seq, 10);
        assert_eq!(decoded.prev, Some(ObjectId::from_bytes([5u8; 32])));
    }

    #[test]
    fn revocation_event_serde_genesis_omits_prev() {
        let genesis = test_event(0, None);
        let json = serde_json::to_string(&genesis).unwrap();
        assert!(!json.contains("\"prev\""));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EpochId – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn epoch_id_equality() {
        let a = EpochId::new("epoch-1");
        let b = EpochId::new("epoch-1");
        assert_eq!(a, b);
    }

    #[test]
    fn epoch_id_inequality() {
        let a = EpochId::new("epoch-1");
        let b = EpochId::new("epoch-2");
        assert_ne!(a, b);
    }

    #[test]
    fn epoch_id_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(EpochId::new("epoch-1"));
        set.insert(EpochId::new("epoch-1"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn epoch_id_hash_different() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(EpochId::new("epoch-1"));
        set.insert(EpochId::new("epoch-2"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn epoch_id_clone() {
        let a = EpochId::new("epoch-1");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn epoch_id_from_string() {
        let s = String::from("epoch-owned");
        let epoch = EpochId::new(s);
        assert_eq!(epoch.as_str(), "epoch-owned");
    }

    #[test]
    fn epoch_id_empty() {
        let epoch = EpochId::new("");
        assert_eq!(epoch.as_str(), "");
        assert_eq!(epoch.to_string(), "");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationHead – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_head(seq: u64) -> RevocationHead {
        RevocationHead {
            header: test_header(),
            zone_id: ZoneId::work(),
            head_event: ObjectId::from_bytes([1u8; 32]),
            head_seq: seq,
            epoch_id: EpochId::new(format!("epoch-{seq}")),
            quorum_signatures: SignatureSet::new(),
        }
    }

    #[test]
    fn revocation_head_age_saturating() {
        let mut head = test_head(1);
        head.header.created_at = 1_700_000_000;
        // now < created_at → saturating_sub returns 0
        assert_eq!(head.age_secs(1_699_999_000), 0);
    }

    #[test]
    fn revocation_head_age_zero() {
        let mut head = test_head(1);
        head.header.created_at = 1_700_000_000;
        assert_eq!(head.age_secs(1_700_000_000), 0);
    }

    #[test]
    fn revocation_head_is_fresher_equal_seqs() {
        let h1 = test_head(10);
        let h2 = test_head(10);
        // Equal seqs: neither is fresher
        assert!(!h1.is_fresher_than(&h2));
        assert!(!h2.is_fresher_than(&h1));
    }

    #[test]
    fn revocation_head_clone() {
        let head = test_head(42);
        let cloned = head.clone();
        assert_eq!(head.head_seq, 42);
        assert_eq!(head.zone_id, ZoneId::work());
        assert_eq!(head.epoch_id.as_str(), "epoch-42");
        assert_eq!(cloned.head_seq, 42);
        assert_eq!(cloned.zone_id, ZoneId::work());
        assert_eq!(cloned.epoch_id.as_str(), "epoch-42");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessPolicy – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_policy_default_is_strict() {
        let policy = FreshnessPolicy::default();
        assert_eq!(policy, FreshnessPolicy::Strict);
    }

    #[test]
    fn freshness_policy_serde_roundtrip_all_variants() {
        let variants = [
            FreshnessPolicy::Strict,
            FreshnessPolicy::Warn,
            FreshnessPolicy::BestEffort,
        ];
        for policy in &variants {
            let json = serde_json::to_string(policy).unwrap();
            let decoded: FreshnessPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(*policy, decoded, "roundtrip mismatch for {policy:?}");
        }
    }

    #[test]
    fn freshness_policy_as_str_all_variants() {
        assert_eq!(FreshnessPolicy::Strict.as_str(), "strict");
        assert_eq!(FreshnessPolicy::Warn.as_str(), "warn");
        assert_eq!(FreshnessPolicy::BestEffort.as_str(), "best_effort");
    }

    #[test]
    fn freshness_policy_copy() {
        let a = FreshnessPolicy::Warn;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn freshness_policy_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessPolicy::Strict);
        set.insert(FreshnessPolicy::Strict);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn freshness_policy_hash_all_variants_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessPolicy::Strict);
        set.insert(FreshnessPolicy::Warn);
        set.insert(FreshnessPolicy::BestEffort);
        assert_eq!(set.len(), 3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessFailureReason – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_failure_reason_as_str_all() {
        assert_eq!(FreshnessFailureReason::StaleData.as_str(), "stale_data");
        assert_eq!(
            FreshnessFailureReason::StaleButWithinMaxAge.as_str(),
            "stale_but_within_max_age"
        );
        assert_eq!(
            FreshnessFailureReason::StaleButAllowed.as_str(),
            "stale_but_allowed"
        );
    }

    #[test]
    fn freshness_failure_reason_display_all() {
        assert_eq!(FreshnessFailureReason::StaleData.to_string(), "stale_data");
        assert_eq!(
            FreshnessFailureReason::StaleButWithinMaxAge.to_string(),
            "stale_but_within_max_age"
        );
        assert_eq!(
            FreshnessFailureReason::StaleButAllowed.to_string(),
            "stale_but_allowed"
        );
    }

    #[test]
    fn freshness_failure_reason_serde_roundtrip_all() {
        let variants = [
            FreshnessFailureReason::StaleData,
            FreshnessFailureReason::StaleButWithinMaxAge,
            FreshnessFailureReason::StaleButAllowed,
        ];
        for reason in &variants {
            let json = serde_json::to_string(reason).unwrap();
            let decoded: FreshnessFailureReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, decoded, "roundtrip mismatch for {reason:?}");
        }
    }

    #[test]
    fn freshness_failure_reason_equality() {
        assert_eq!(
            FreshnessFailureReason::StaleData,
            FreshnessFailureReason::StaleData
        );
        assert_ne!(
            FreshnessFailureReason::StaleData,
            FreshnessFailureReason::StaleButAllowed
        );
    }

    #[test]
    fn freshness_failure_reason_copy() {
        let a = FreshnessFailureReason::StaleButWithinMaxAge;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn freshness_failure_reason_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessFailureReason::StaleData);
        set.insert(FreshnessFailureReason::StaleData);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn freshness_failure_reason_hash_all_distinct() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FreshnessFailureReason::StaleData);
        set.insert(FreshnessFailureReason::StaleButWithinMaxAge);
        set.insert(FreshnessFailureReason::StaleButAllowed);
        assert_eq!(set.len(), 3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessCheckResult – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_check_result_serde_with_reason() {
        let result = FreshnessCheckResult {
            allowed: false,
            stale: true,
            age_secs: 300,
            reason: Some(FreshnessFailureReason::StaleData),
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: FreshnessCheckResult = serde_json::from_str(&json).unwrap();
        assert!(!decoded.allowed);
        assert!(decoded.stale);
        assert_eq!(decoded.age_secs, 300);
        assert_eq!(decoded.reason, Some(FreshnessFailureReason::StaleData));
    }

    #[test]
    fn freshness_check_result_serde_without_reason() {
        let result = FreshnessCheckResult {
            allowed: true,
            stale: false,
            age_secs: 0,
            reason: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("reason"));
        let decoded: FreshnessCheckResult = serde_json::from_str(&json).unwrap();
        assert!(decoded.allowed);
        assert!(!decoded.stale);
        assert!(decoded.reason.is_none());
    }

    #[test]
    fn freshness_check_result_clone() {
        let result = FreshnessCheckResult {
            allowed: true,
            stale: true,
            age_secs: 42,
            reason: Some(FreshnessFailureReason::StaleButAllowed),
        };
        let cloned = result.clone();
        assert_eq!(cloned.allowed, result.allowed);
        assert_eq!(cloned.stale, result.stale);
        assert_eq!(cloned.age_secs, result.age_secs);
        assert_eq!(cloned.reason, result.reason);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationCheckResult – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn revocation_check_result_serde_revoked() {
        let result = RevocationCheckResult {
            is_revoked: true,
            revocation: Some(ObjectId::from_bytes([1u8; 32])),
            scope: Some(RevocationScope::Capability),
            stale_data: false,
            head_age_secs: 10,
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: RevocationCheckResult = serde_json::from_str(&json).unwrap();
        assert!(decoded.is_revoked);
        assert!(decoded.revocation.is_some());
        assert_eq!(decoded.scope, Some(RevocationScope::Capability));
        assert_eq!(decoded.head_age_secs, 10);
    }

    #[test]
    fn revocation_check_result_serde_not_revoked() {
        let result = RevocationCheckResult {
            is_revoked: false,
            revocation: None,
            scope: None,
            stale_data: false,
            head_age_secs: 5,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("revocation"));
        assert!(!json.contains("scope"));
        let decoded: RevocationCheckResult = serde_json::from_str(&json).unwrap();
        assert!(!decoded.is_revoked);
        assert!(decoded.revocation.is_none());
        assert!(decoded.scope.is_none());
    }

    #[test]
    fn revocation_check_result_clone() {
        let result = RevocationCheckResult {
            is_revoked: true,
            revocation: Some(ObjectId::from_bytes([3u8; 32])),
            scope: Some(RevocationScope::ZoneKey),
            stale_data: true,
            head_age_secs: 999,
        };
        let cloned = result.clone();
        assert_eq!(cloned.is_revoked, result.is_revoked);
        assert_eq!(cloned.revocation, result.revocation);
        assert_eq!(cloned.scope, result.scope);
        assert_eq!(cloned.stale_data, result.stale_data);
        assert_eq!(cloned.head_age_secs, result.head_age_secs);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RevocationRegistry – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn registry_with_capacity() {
        let registry = RevocationRegistry::with_capacity(1000);
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.head.is_none());
        assert_eq!(registry.head_seq, 0);
        assert_eq!(registry.last_updated, 0);
    }

    #[test]
    fn registry_add_multiple_revocations() {
        let mut registry = RevocationRegistry::new();

        let mut rev1 = test_revocation();
        rev1.revoked = vec![ObjectId::from_bytes([1u8; 32])];
        rev1.scope = RevocationScope::Capability;

        let mut rev2 = test_revocation();
        rev2.revoked = vec![ObjectId::from_bytes([2u8; 32])];
        rev2.scope = RevocationScope::IssuerKey;

        let mut rev3 = test_revocation();
        rev3.revoked = vec![ObjectId::from_bytes([3u8; 32])];
        rev3.scope = RevocationScope::ZoneKey;

        registry.add_revocation(&rev1);
        registry.add_revocation(&rev2);
        registry.add_revocation(&rev3);

        assert_eq!(registry.len(), 3);
        assert!(registry.is_revoked(&ObjectId::from_bytes([1u8; 32])));
        assert!(registry.is_revoked(&ObjectId::from_bytes([2u8; 32])));
        assert!(registry.is_revoked(&ObjectId::from_bytes([3u8; 32])));
        assert!(!registry.is_revoked(&ObjectId::from_bytes([4u8; 32])));
    }

    #[test]
    fn registry_add_revocation_with_multiple_ids() {
        let mut registry = RevocationRegistry::new();
        let mut revocation = test_revocation();
        let id1 = ObjectId::from_bytes([10u8; 32]);
        let id2 = ObjectId::from_bytes([20u8; 32]);
        let id3 = ObjectId::from_bytes([30u8; 32]);
        revocation.revoked = vec![id1, id2, id3];

        registry.add_revocation(&revocation);
        // Each revoked ID gets its own entry in the map
        assert_eq!(registry.len(), 3);
        assert!(registry.is_revoked(&id1));
        assert!(registry.is_revoked(&id2));
        assert!(registry.is_revoked(&id3));
    }

    #[test]
    fn registry_later_revocation_does_not_defer_active_one() {
        // A second revocation for the same object_id with a far-future
        // effective_at MUST NOT replace an active earlier revocation;
        // otherwise is_revoked_at(now) would return false until the new
        // effective_at, suppressing an active revocation.
        let mut registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([42u8; 32]);

        let mut early = test_revocation();
        early.revoked = vec![id];
        early.effective_at = 1_700_000_000;

        let mut late = test_revocation();
        late.revoked = vec![id];
        late.effective_at = u64::MAX;
        late.reason = "deferred".into();

        registry.add_revocation(&early);
        registry.add_revocation(&late);

        // The earlier (active) revocation must win.
        let stored = registry.get_revocation(&id).expect("entry exists");
        assert_eq!(stored.effective_at, 1_700_000_000);
        assert!(registry.is_revoked_at(&id, 1_700_000_001));
    }

    #[test]
    fn registry_earlier_revocation_replaces_later_one() {
        // The opposite case: if a later-effective revocation is added first
        // and a stricter (earlier-effective) one arrives second, the earlier
        // one MUST take effect.
        let mut registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([43u8; 32]);

        let mut late = test_revocation();
        late.revoked = vec![id];
        late.effective_at = 2_000_000_000;

        let mut early = test_revocation();
        early.revoked = vec![id];
        early.effective_at = 1_700_000_000;

        registry.add_revocation(&late);
        registry.add_revocation(&early);

        let stored = registry.get_revocation(&id).expect("entry exists");
        assert_eq!(stored.effective_at, 1_700_000_000);
    }

    // The tie case (identical effective_at): the replace condition is
    // `existing.effective_at > revocation.effective_at`, so on equality the
    // first-writer wins. This test codifies that semantics so any future
    // change — e.g., moving to `>=` for content-addressed tie-break — is
    // flagged rather than silently changing observable behavior. Both
    // revocations agree on `is_revoked_at` because the effective_at matches.
    #[test]
    fn registry_equal_effective_at_is_first_writer_wins() {
        let mut registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([44u8; 32]);
        let effective_at = 1_800_000_000;

        let mut first = test_revocation();
        first.revoked = vec![id];
        first.effective_at = effective_at;
        first.reason = "first-writer".into();

        let mut second = test_revocation();
        second.revoked = vec![id];
        second.effective_at = effective_at;
        second.reason = "second-writer".into();

        registry.add_revocation(&first);
        registry.add_revocation(&second);

        let stored = registry.get_revocation(&id).expect("entry exists");
        assert_eq!(stored.effective_at, effective_at);
        assert_eq!(
            stored.reason, "first-writer",
            "on effective_at tie, the first-written revocation must be retained"
        );
        // Semantic invariant: regardless of which revocation won the
        // metadata slot, is_revoked_at stays stable because effective_at
        // is identical — divergence on ties is cosmetic, not functional.
        assert!(registry.is_revoked_at(&id, effective_at));
        assert!(registry.is_revoked_at(&id, effective_at + 1));
        assert!(!registry.is_revoked_at(&id, effective_at - 1));
    }

    // Past-expiry suppression: a new revocation whose active window has
    // already closed MUST NOT replace an active open-ended revocation
    // just because its effective_at is earlier. Before the
    // "strictly dominates" rule this replay would flip is_revoked_at(now)
    // back to false — equivalent to a revocation wipeout.
    #[test]
    fn registry_past_expiry_revocation_does_not_suppress_active_one() {
        let mut registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([46u8; 32]);

        let mut active = test_revocation();
        active.revoked = vec![id];
        active.effective_at = 1_800_000_000;
        active.expires_at = None; // permanent

        let mut past_expiry = test_revocation();
        past_expiry.revoked = vec![id];
        past_expiry.effective_at = 1_000_000_000; // earlier than active
        past_expiry.expires_at = Some(1_100_000_000); // already closed by now
        past_expiry.reason = "replay-to-suppress".into();

        registry.add_revocation(&active);
        registry.add_revocation(&past_expiry);

        // The open-ended active revocation must be retained; reading the
        // registry at a "now" past the replay's expires_at must still
        // observe the object as revoked.
        let now = 2_000_000_000;
        assert!(
            registry.is_revoked_at(&id, now),
            "past-expiry replay must not suppress the active revocation"
        );
        let stored = registry.get_revocation(&id).expect("entry exists");
        assert_eq!(stored.effective_at, 1_800_000_000);
        assert!(stored.expires_at.is_none());
    }

    // Symmetric positive case: a new revocation that strictly dominates the
    // existing one (earlier start AND later/None end) is accepted.
    #[test]
    fn registry_strictly_dominating_revocation_replaces_existing() {
        let mut registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([47u8; 32]);

        let mut bounded = test_revocation();
        bounded.revoked = vec![id];
        bounded.effective_at = 1_800_000_000;
        bounded.expires_at = Some(1_900_000_000);

        let mut dominating = test_revocation();
        dominating.revoked = vec![id];
        dominating.effective_at = 1_700_000_000; // earlier
        dominating.expires_at = None; // never expires ⇒ dominates
        dominating.reason = "upgrade-to-permanent".into();

        registry.add_revocation(&bounded);
        registry.add_revocation(&dominating);

        let stored = registry.get_revocation(&id).expect("entry exists");
        assert_eq!(stored.effective_at, 1_700_000_000);
        assert!(stored.expires_at.is_none());
        assert_eq!(stored.reason, "upgrade-to-permanent");
    }

    // Same effective_at, strictly later expires_at: an issuer upgrading a
    // bounded revocation into a permanent one (or simply extending the expiry)
    // MUST replace the existing entry. Before the poset-domination fix this
    // case was rejected because `starts_no_later` used `<` instead of `<=`,
    // so a legitimate expiry extension on a same-start window was silently
    // dropped and the revocation still expired at the earlier bound.
    #[test]
    fn registry_same_start_later_expiry_replaces_existing() {
        let mut registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([48u8; 32]);
        let shared_effective_at = 1_800_000_000;

        let mut bounded = test_revocation();
        bounded.revoked = vec![id];
        bounded.effective_at = shared_effective_at;
        bounded.expires_at = Some(1_900_000_000);
        bounded.reason = "initial-bounded".into();

        let mut extended = test_revocation();
        extended.revoked = vec![id];
        extended.effective_at = shared_effective_at; // same start
        extended.expires_at = None; // strictly wider on expiry axis
        extended.reason = "upgrade-to-permanent".into();

        registry.add_revocation(&bounded);
        registry.add_revocation(&extended);

        let stored = registry.get_revocation(&id).expect("entry exists");
        assert!(
            stored.expires_at.is_none(),
            "same-start permanent upgrade must replace bounded predecessor"
        );
        assert_eq!(stored.reason, "upgrade-to-permanent");
        // Past the original bound, the object must still be observed revoked.
        assert!(registry.is_revoked_at(&id, 2_000_000_000));
    }

    // Same effective_at, strictly later finite expires_at: analog of the
    // above but both expiries are finite. The longer finite window still
    // strictly dominates the shorter, so the replacement must occur.
    #[test]
    fn registry_same_start_longer_finite_expiry_replaces_existing() {
        let mut registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([49u8; 32]);
        let shared_effective_at = 1_800_000_000;

        let mut short = test_revocation();
        short.revoked = vec![id];
        short.effective_at = shared_effective_at;
        short.expires_at = Some(1_900_000_000);
        short.reason = "short-window".into();

        let mut long = test_revocation();
        long.revoked = vec![id];
        long.effective_at = shared_effective_at;
        long.expires_at = Some(2_000_000_000);
        long.reason = "extended-window".into();

        registry.add_revocation(&short);
        registry.add_revocation(&long);

        let stored = registry.get_revocation(&id).expect("entry exists");
        assert_eq!(stored.expires_at, Some(2_000_000_000));
        assert_eq!(stored.reason, "extended-window");
    }

    // Converse: a shorter expiry at the same effective_at MUST NOT replace a
    // longer one. This is the symmetric half of the past-expiry suppression
    // guard — it protects against an attacker narrowing an active window while
    // keeping its start intact.
    #[test]
    fn registry_same_start_shorter_expiry_does_not_replace() {
        let mut registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([50u8; 32]);
        let shared_effective_at = 1_800_000_000;

        let mut long = test_revocation();
        long.revoked = vec![id];
        long.effective_at = shared_effective_at;
        long.expires_at = None;
        long.reason = "permanent".into();

        let mut short = test_revocation();
        short.revoked = vec![id];
        short.effective_at = shared_effective_at;
        short.expires_at = Some(1_900_000_000);
        short.reason = "narrowing-attempt".into();

        registry.add_revocation(&long);
        registry.add_revocation(&short);

        let stored = registry.get_revocation(&id).expect("entry exists");
        assert!(stored.expires_at.is_none());
        assert_eq!(stored.reason, "permanent");
    }

    fn window_revocation(
        id: ObjectId,
        effective_at: u64,
        expires_at: Option<u64>,
        signature_byte: u8,
    ) -> RevocationObject {
        RevocationObject {
            revoked: vec![id],
            effective_at,
            expires_at,
            signature: [signature_byte; 64],
            ..test_revocation()
        }
    }

    #[test]
    fn registry_retains_disjoint_signed_windows_in_both_delivery_orders() {
        let id = ObjectId::from_bytes([61; 32]);
        let first = window_revocation(id, 10, Some(20), 1);
        let second = window_revocation(id, 30, Some(40), 2);

        for windows in [[&first, &second], [&second, &first]] {
            let mut registry = RevocationRegistry::new();
            for window in windows {
                registry.add_revocation(window);
            }

            assert_eq!(registry.len(), 1);
            assert_eq!(registry.get_revocations(&id).len(), 2);
            for now in [0, 9, 10, 19, 20, 29, 30, 39, 40, u64::MAX] {
                assert_eq!(
                    registry.is_revoked_at(&id, now),
                    first.is_active(now) || second.is_active(now),
                    "revocation union must preserve exact boundaries at {now}"
                );
            }

            // A fabricated encompassing [10, 40) record would revoke the gap
            // and invalidate the owner's signature. Keep both signed objects.
            for original in [&first, &second] {
                let retained = registry
                    .get_revocations(&id)
                    .iter()
                    .find(|record| record.signature == original.signature)
                    .expect("both original signatures remain available");
                assert_eq!(
                    fcp_cbor::to_canonical_cbor(retained).unwrap(),
                    fcp_cbor::to_canonical_cbor(original).unwrap()
                );
            }
        }
    }

    #[test]
    fn registry_window_union_is_independent_of_all_delivery_permutations() {
        let id = ObjectId::from_bytes([62; 32]);
        let windows = [
            window_revocation(id, 2, Some(8), 1),
            window_revocation(id, 5, Some(12), 2),
            window_revocation(id, 15, Some(20), 3),
            window_revocation(id, 17, None, 4),
        ];

        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let order = [a, b, c, d];
                        if (0..4).any(|index| order[..index].contains(&order[index])) {
                            continue;
                        }
                        let mut registry = RevocationRegistry::new();
                        for index in order {
                            registry.add_revocation(&windows[index]);
                        }
                        for now in (0..25).chain([u64::MAX]) {
                            assert_eq!(
                                registry.is_revoked_at(&id, now),
                                windows.iter().any(|window| window.is_active(now)),
                                "delivery {order:?} changed revocation at {now}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn registry_dominating_window_compacts_only_covered_evidence() {
        let id = ObjectId::from_bytes([63; 32]);
        let mut registry = RevocationRegistry::new();
        for window in [
            window_revocation(id, 10, Some(20), 1),
            window_revocation(id, 30, Some(40), 2),
            window_revocation(id, 50, None, 3),
        ] {
            registry.add_revocation(&window);
        }

        let wider = window_revocation(id, 5, Some(45), 4);
        registry.add_revocation(&wider);
        assert_eq!(registry.get_revocations(&id).len(), 2);
        assert!(registry.is_revoked_at(&id, 25));
        assert!(!registry.is_revoked_at(&id, 47));
        assert!(registry.is_revoked_at(&id, u64::MAX));
        assert!(
            registry
                .get_revocations(&id)
                .iter()
                .any(|record| record.signature == wider.signature)
        );

        let permanent = window_revocation(id, 0, None, 5);
        registry.add_revocation(&permanent);
        assert_eq!(registry.get_revocations(&id).len(), 1);
        assert_eq!(registry.get_revocation(&id).unwrap().signature, [5; 64]);
    }

    #[test]
    fn registry_preserves_evidence_for_distinct_scopes_and_zones() {
        let id = ObjectId::from_bytes([64; 32]);
        let capability = window_revocation(id, 10, None, 1);
        let mut issuer = window_revocation(id, 10, None, 2);
        issuer.scope = RevocationScope::IssuerKey;
        let mut other_zone = window_revocation(id, 10, None, 3);
        other_zone.header.zone_id = ZoneId::private();

        let mut registry = RevocationRegistry::new();
        for window in [&capability, &issuer, &other_zone] {
            registry.add_revocation(window);
        }
        assert_eq!(registry.get_revocations(&id).len(), 3);
        assert_eq!(
            registry
                .revocations_by_scope(RevocationScope::Capability)
                .len(),
            2
        );
        assert_eq!(
            registry
                .revocations_by_scope(RevocationScope::IssuerKey)
                .len(),
            1
        );
    }

    #[test]
    fn registry_duplicate_ids_and_replays_do_not_duplicate_windows_or_revisions() {
        let id = ObjectId::from_bytes([65; 32]);
        let mut record = window_revocation(id, 10, Some(20), 1);
        record.revoked.push(id);
        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&record);
        let seal = registry.check_with_seal(&id, 15);

        for _ in 0..10 {
            registry.add_revocation(&record);
            registry.add_revocation(&window_revocation(id, 12, Some(18), 2));
        }
        assert_eq!(registry.get_revocations(&id).len(), 1);
        assert_eq!(registry.validate_seal(&seal, &id), SealValidation::Valid);
    }

    // Re-adding the same revocation must be idempotent: repeated deliveries
    // from gossip or retried apply paths cannot re-order outcomes or leak
    // metadata drift. Length stays at 1 entry per revoked id.
    #[test]
    fn registry_add_revocation_is_idempotent() {
        let mut registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([45u8; 32]);

        let mut rev = test_revocation();
        rev.revoked = vec![id];
        rev.effective_at = 1_900_000_000;
        rev.reason = "duplicate-delivery".into();

        for _ in 0..5 {
            registry.add_revocation(&rev);
        }

        assert_eq!(registry.len(), 1);
        let stored = registry.get_revocation(&id).expect("entry exists");
        assert_eq!(stored.effective_at, 1_900_000_000);
        assert_eq!(stored.reason, "duplicate-delivery");
    }

    #[test]
    fn registry_len_tracking() {
        let mut registry = RevocationRegistry::new();
        assert_eq!(registry.len(), 0);

        let mut rev = test_revocation();
        rev.revoked = vec![ObjectId::from_bytes([1u8; 32])];
        registry.add_revocation(&rev);
        assert_eq!(registry.len(), 1);

        let mut rev2 = test_revocation();
        rev2.revoked = vec![ObjectId::from_bytes([2u8; 32])];
        registry.add_revocation(&rev2);
        assert_eq!(registry.len(), 2);

        registry.clear();
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn registry_is_empty_transitions() {
        let mut registry = RevocationRegistry::new();
        assert!(registry.is_empty());

        registry.add_revocation(&test_revocation());
        assert!(!registry.is_empty());

        registry.clear();
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_is_fresh_zero_seq() {
        let registry = RevocationRegistry::new();
        assert!(registry.is_fresh(0)); // 0 >= 0
        assert!(!registry.is_fresh(1)); // 0 < 1
    }

    #[test]
    fn registry_check_freshness_all_policies_when_fresh() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 100;
        registry.last_updated = 1_700_000_000;
        let now = 1_700_000_050;

        // When fresh, all policies should allow and not be stale
        for policy in [
            FreshnessPolicy::Strict,
            FreshnessPolicy::Warn,
            FreshnessPolicy::BestEffort,
        ] {
            let result = registry.check_freshness(100, policy, 300, now);
            assert!(result.allowed, "policy {policy:?} should allow when fresh");
            assert!(
                !result.stale,
                "policy {policy:?} should not be stale when fresh"
            );
            assert!(
                result.reason.is_none(),
                "policy {policy:?} should have no reason when fresh"
            );
            assert_eq!(result.age_secs, 50);
        }
    }

    #[test]
    fn registry_check_freshness_warn_fresh_data() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 100;
        registry.last_updated = 1_700_000_000;
        let now = 1_700_000_050;

        let result = registry.check_freshness(100, FreshnessPolicy::Warn, 300, now);
        assert!(result.allowed);
        assert!(!result.stale);
        assert!(result.reason.is_none());
    }

    #[test]
    fn registry_check_freshness_strict_stale_reason() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        let result = registry.check_freshness(100, FreshnessPolicy::Strict, 300, 1_700_000_100);
        assert!(!result.allowed);
        assert!(result.stale);
        assert_eq!(result.reason, Some(FreshnessFailureReason::StaleData));
    }

    #[test]
    fn registry_check_freshness_warn_stale_beyond_max_age_reason() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 50;
        registry.last_updated = 1_700_000_000;

        // now - last_updated = 500, max_age = 100 → beyond max age
        let result = registry.check_freshness(100, FreshnessPolicy::Warn, 100, 1_700_000_500);
        assert!(!result.allowed);
        assert!(result.stale);
        assert_eq!(result.reason, Some(FreshnessFailureReason::StaleData));
    }

    #[test]
    fn registry_check_freshness_best_effort_always_allowed() {
        let mut registry = RevocationRegistry::new();
        registry.head_seq = 0;
        registry.last_updated = 0;

        // Extremely stale, max_age 0, but BestEffort always allows
        let result = registry.check_freshness(u64::MAX, FreshnessPolicy::BestEffort, 0, u64::MAX);
        assert!(result.allowed);
        assert!(result.stale);
    }

    #[test]
    fn registry_revocations_by_scope_all_scopes() {
        let mut registry = RevocationRegistry::new();
        let scopes = [
            RevocationScope::Capability,
            RevocationScope::IssuerKey,
            RevocationScope::NodeAttestation,
            RevocationScope::ZoneKey,
            RevocationScope::ConnectorBinary,
        ];
        for (i, scope) in scopes.iter().enumerate() {
            let mut rev = test_revocation();
            rev.scope = *scope;
            let revoked_byte = u8::try_from(i).expect("scope index fits u8") + 10;
            rev.revoked = vec![ObjectId::from_bytes([revoked_byte; 32])];
            registry.add_revocation(&rev);
        }

        for scope in scopes {
            let found = registry.revocations_by_scope(scope);
            assert_eq!(found.len(), 1, "expected 1 revocation for scope {scope:?}");
            assert_eq!(found[0].scope, scope);
        }
    }

    #[test]
    fn registry_get_revocation_absent() {
        let registry = RevocationRegistry::new();
        let id = ObjectId::from_bytes([99u8; 32]);
        assert!(registry.get_revocation(&id).is_none());
    }

    #[test]
    fn registry_update_head_overwrites() {
        let mut registry = RevocationRegistry::new();
        let head1 = ObjectId::from_bytes([1u8; 32]);
        let head2 = ObjectId::from_bytes([2u8; 32]);

        registry.update_head(head1, 10, 100);
        assert_eq!(registry.head_seq, 10);

        registry.update_head(head2, 20, 200);
        assert_eq!(registry.head, Some(head2));
        assert_eq!(registry.head_seq, 20);
        assert_eq!(registry.last_updated, 200);
    }

    #[test]
    fn registry_update_head_rejects_rollback() {
        let mut registry = RevocationRegistry::new();
        let head1 = ObjectId::from_bytes([1u8; 32]);
        let head2 = ObjectId::from_bytes([2u8; 32]);

        registry.update_head(head1, 20, 200);
        assert_eq!(registry.head_seq, 20);

        // Attempt rollback to seq 10
        registry.update_head(head2, 10, 100);
        assert_eq!(registry.head, Some(head1));
        assert_eq!(registry.head_seq, 20);
        assert_eq!(registry.last_updated, 200);
    }

    #[test]
    fn registry_clone() {
        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&test_revocation());
        registry.update_head(ObjectId::from_bytes([42u8; 32]), 5, 999);

        let cloned = registry.clone();
        assert_eq!(cloned.len(), registry.len());
        assert_eq!(cloned.head_seq, registry.head_seq);
        assert_eq!(cloned.last_updated, registry.last_updated);
        assert_eq!(cloned.head, registry.head);
    }

    #[test]
    fn registry_default_matches_new() {
        let from_new = RevocationRegistry::new();
        let from_default = RevocationRegistry::default();
        assert!(from_new.is_empty());
        assert!(from_default.is_empty());
        assert_eq!(from_new.head_seq, from_default.head_seq);
        assert_eq!(from_new.last_updated, from_default.last_updated);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // C1.3: RevocationFreshnessClass tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_class_critical_rejects_besteffort() {
        let class = RevocationFreshnessClass::Critical;
        assert!(!class.allows_policy(FreshnessPolicy::BestEffort));
        assert!(!class.allows_policy(FreshnessPolicy::Warn));
        assert!(class.allows_policy(FreshnessPolicy::Strict));
    }

    #[test]
    fn freshness_class_risky_accepts_warn_and_strict() {
        let class = RevocationFreshnessClass::Risky;
        assert!(!class.allows_policy(FreshnessPolicy::BestEffort));
        assert!(class.allows_policy(FreshnessPolicy::Warn));
        assert!(class.allows_policy(FreshnessPolicy::Strict));
    }

    #[test]
    fn freshness_class_safe_accepts_all() {
        let class = RevocationFreshnessClass::Safe;
        assert!(class.allows_policy(FreshnessPolicy::BestEffort));
        assert!(class.allows_policy(FreshnessPolicy::Warn));
        assert!(class.allows_policy(FreshnessPolicy::Strict));
    }

    #[test]
    fn freshness_class_minimum_policy_mapping() {
        assert_eq!(
            RevocationFreshnessClass::Critical.minimum_policy(),
            FreshnessPolicy::Strict
        );
        assert_eq!(
            RevocationFreshnessClass::Risky.minimum_policy(),
            FreshnessPolicy::Warn
        );
        assert_eq!(
            RevocationFreshnessClass::Safe.minimum_policy(),
            FreshnessPolicy::BestEffort
        );
    }

    #[test]
    fn freshness_class_serde_roundtrip() {
        for class in [
            RevocationFreshnessClass::Critical,
            RevocationFreshnessClass::Risky,
            RevocationFreshnessClass::Safe,
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: RevocationFreshnessClass = serde_json::from_str(&json).unwrap();
            assert_eq!(back, class);
        }
    }

    #[test]
    fn freshness_class_display() {
        assert_eq!(RevocationFreshnessClass::Critical.as_str(), "critical");
        assert_eq!(RevocationFreshnessClass::Risky.as_str(), "risky");
        assert_eq!(RevocationFreshnessClass::Safe.as_str(), "safe");
        assert_eq!(RevocationFreshnessClass::Critical.to_string(), "critical");
    }

    // ─────────────────────────────────────────────────────────────────────
    // C1.1: RevocationSeal acceptance tests
    // ─────────────────────────────────────────────────────────────────────

    fn make_object_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    fn make_revocation_for(token_ids: &[ObjectId]) -> RevocationObject {
        RevocationObject {
            header: test_header(),
            revoked: token_ids.to_vec(),
            scope: RevocationScope::Capability,
            reason: "Test revocation".into(),
            effective_at: 1_700_000_000,
            expires_at: None,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn c1_1_fresh_seal_passes_validation() {
        let mut registry = RevocationRegistry::new();
        let token_id = make_object_id(0xAB);
        registry.update_head(make_object_id(0x01), 10, 1000);

        let seal = registry.check_with_seal(&token_id, 1001);

        assert_eq!(seal.decision, RevocationDecision::NotRevoked);
        assert_eq!(seal.head_seq, 10);
        assert_eq!(seal.token_id, token_id);

        // Validate immediately — head hasn't advanced
        let validation = registry.validate_seal(&seal, &token_id);
        assert_eq!(validation, SealValidation::Valid);
        assert!(validation.is_valid());
    }

    #[test]
    fn c1_1_stale_seal_triggers_recheck() {
        let mut registry = RevocationRegistry::new();
        let token_id = make_object_id(0xCD);
        registry.update_head(make_object_id(0x01), 10, 1000);

        // Check at head_seq=10
        let seal = registry.check_with_seal(&token_id, 1001);
        assert_eq!(seal.decision, RevocationDecision::NotRevoked);

        // Registry advances (new revocation inserted)
        registry.update_head(make_object_id(0x02), 11, 1002);

        // Seal is now stale
        let validation = registry.validate_seal(&seal, &token_id);
        assert_eq!(
            validation,
            SealValidation::Stale {
                seal_seq: 10,
                current_seq: 11
            }
        );
        assert!(!validation.is_valid());
    }

    #[test]
    fn c1_1_concurrent_revocation_detected() {
        let mut registry = RevocationRegistry::new();
        let token_id = make_object_id(0xEE);
        registry.update_head(make_object_id(0x01), 5, 500);

        // Check passes — token not revoked
        let seal = registry.check_with_seal(&token_id, 501);
        assert_eq!(seal.decision, RevocationDecision::NotRevoked);

        // Between check and commit, someone revokes the token
        let revocation = make_revocation_for(&[token_id]);
        registry.add_revocation(&revocation);
        registry.update_head(make_object_id(0x02), 6, 502);

        // Seal is stale → re-check required
        let validation = registry.validate_seal(&seal, &token_id);
        assert!(!validation.is_valid());

        // Re-check: token IS now revoked
        let new_seal = registry.check_with_seal(&token_id, 503);
        assert_eq!(new_seal.decision, RevocationDecision::Revoked);
        assert_eq!(new_seal.head_seq, 6);
    }

    #[test]
    fn c1_1_seal_wrong_token_id_rejected() {
        let mut registry = RevocationRegistry::new();
        let token_a = make_object_id(0xAA);
        let token_b = make_object_id(0xBB);
        registry.update_head(make_object_id(0x01), 1, 100);

        let seal = registry.check_with_seal(&token_a, 101);

        // Try to validate against a different token
        let validation = registry.validate_seal(&seal, &token_b);
        assert_eq!(validation, SealValidation::TokenMismatch);
        assert!(!validation.is_valid());
    }

    #[test]
    fn c1_1_seal_serialization_roundtrip() {
        let mut registry = RevocationRegistry::new();
        let token_id = make_object_id(0xDD);
        registry.update_head(make_object_id(0x01), 42, 9999);

        let seal = registry.check_with_seal(&token_id, 10000);

        let json = serde_json::to_string(&seal).unwrap();
        let roundtripped: RevocationSeal = serde_json::from_str(&json).unwrap();

        assert_eq!(seal, roundtripped);
        assert_eq!(roundtripped.head_seq, 42);
        assert_eq!(roundtripped.checked_at, 10000);
        assert_eq!(roundtripped.decision, RevocationDecision::NotRevoked);
    }

    #[test]
    fn c1_1_revoked_token_seal_carries_revoked_decision() {
        let mut registry = RevocationRegistry::new();
        let token_id = make_object_id(0xFF);
        let revocation = make_revocation_for(&[token_id]);
        registry.add_revocation(&revocation);
        registry.update_head(make_object_id(0x01), 1, 100);

        let seal = registry.check_with_seal(&token_id, 101);
        assert_eq!(seal.decision, RevocationDecision::Revoked);

        // Even a fresh seal with Revoked decision should validate as Valid
        // (the seal is fresh, the token is just revoked)
        let validation = registry.validate_seal(&seal, &token_id);
        assert!(validation.is_valid());
    }

    #[test]
    fn c1_1_insertion_invalidates_allow_seal_before_head_publication() {
        let id = make_object_id(0xE1);
        let mut registry = RevocationRegistry::new();
        registry.update_head(make_object_id(1), 7, 100);
        let seal = registry.check_with_seal(&id, 101);
        assert_eq!(seal.decision, RevocationDecision::NotRevoked);

        registry.add_revocation(&make_revocation_for(&[id]));
        assert_eq!(registry.head_seq, seal.head_seq);
        assert_eq!(
            registry.validate_seal(&seal, &id),
            SealValidation::StateChanged
        );
        assert_eq!(
            registry.check_with_seal(&id, 102).decision,
            RevocationDecision::Revoked
        );
    }

    #[test]
    fn c1_1_new_window_invalidates_seal_even_when_membership_stays_revoked() {
        let id = make_object_id(0xE2);
        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&window_revocation(id, 10, Some(20), 1));
        let seal = registry.check_with_seal(&id, 15);

        registry.add_revocation(&window_revocation(id, 30, Some(40), 2));
        assert_eq!(
            registry.validate_seal(&seal, &id),
            SealValidation::StateChanged
        );
    }

    #[test]
    fn c1_1_clear_and_rebuild_cannot_resurrect_seals_at_the_same_frontier() {
        let id = make_object_id(0xE3);
        let head = make_object_id(1);
        let record = make_revocation_for(&[id]);
        let mut registry = RevocationRegistry::new();
        registry.add_revocation(&record);
        registry.update_head(head, 7, 100);
        let seal = registry.check_with_seal(&id, 101);

        registry.clear();
        registry.add_revocation(&record);
        registry.update_head(head, 7, 100);
        assert_eq!(
            registry.validate_seal(&seal, &id),
            SealValidation::StateChanged
        );
        let current = registry.check_with_seal(&id, 102);
        assert_eq!(registry.validate_seal(&current, &id), SealValidation::Valid);
    }

    #[test]
    fn c1_1_equal_mutation_counts_do_not_alias_divergent_registries() {
        let checked_id = make_object_id(0xE4);
        let mut first = RevocationRegistry::new();
        let mut second = RevocationRegistry::new();
        first.add_revocation(&make_revocation_for(&[make_object_id(2)]));
        second.add_revocation(&make_revocation_for(&[make_object_id(3)]));
        first.update_head(make_object_id(1), 7, 100);
        second.update_head(make_object_id(1), 7, 100);

        let seal = first.check_with_seal(&checked_id, 101);
        assert_eq!(
            second.validate_seal(&seal, &checked_id),
            SealValidation::StateChanged
        );
        assert_eq!(
            first.clone().validate_seal(&seal, &checked_id),
            SealValidation::Valid
        );
    }

    #[test]
    fn c1_1_seal_binds_exact_head_and_decision() {
        let id = make_object_id(0xE5);
        let mut registry = RevocationRegistry::new();
        registry.update_head(make_object_id(1), 7, 100);
        let mut seal = registry.check_with_seal(&id, 101);
        seal.registry_head = Some(make_object_id(2));
        assert_eq!(
            registry.validate_seal(&seal, &id),
            SealValidation::StateChanged
        );

        let mut seal = registry.check_with_seal(&id, 101);
        seal.decision = RevocationDecision::Revoked;
        assert_eq!(
            registry.validate_seal(&seal, &id),
            SealValidation::StateChanged
        );

        registry.add_revocation(&make_revocation_for(&[id]));
        let mut seal = registry.check_with_seal(&id, 102);
        seal.decision = RevocationDecision::NotRevoked;
        assert_eq!(
            registry.validate_seal(&seal, &id),
            SealValidation::StateChanged
        );
    }

    // ── C1.2 — Exact membership, no false-positive revocation ──────────

    fn make_id_from_u32(i: u32) -> ObjectId {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        ObjectId::from_bytes(b)
    }

    fn make_revocation_single(id: ObjectId) -> RevocationObject {
        RevocationObject {
            header: test_header(),
            revoked: vec![id],
            scope: RevocationScope::Capability,
            reason: "Test revocation".into(),
            effective_at: 1_700_000_000,
            expires_at: None,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn c1_2_exact_membership_no_false_positives() {
        // Revocation checks use HashMap (exact), NOT probabilistic filters.
        // With 10K revocations, zero false positives must occur.
        let mut registry = RevocationRegistry::new();

        let revoked_count = 10_000u32;
        for i in 0..revoked_count {
            let id = make_id_from_u32(i);
            registry.add_revocation(&make_revocation_single(id));
        }

        // Every revoked ID must be found
        for i in 0..revoked_count {
            assert!(registry.is_revoked(&make_id_from_u32(i)));
        }

        // 10_000 non-revoked IDs must NOT be falsely revoked
        let mut false_positives = 0u32;
        for i in revoked_count..(revoked_count * 2) {
            if registry.is_revoked(&make_id_from_u32(i)) {
                false_positives += 1;
            }
        }
        assert_eq!(
            false_positives, 0,
            "exact membership must have zero false positives"
        );
    }

    #[test]
    fn c1_2_collision_prone_ids_no_false_positive() {
        // IDs that differ only in a single byte must not collide
        let mut registry = RevocationRegistry::new();

        let mut revoked_bytes = [0xFFu8; 32];
        revoked_bytes[0] = 0x01;
        let revoked_id = ObjectId::from_bytes(revoked_bytes);
        registry.add_revocation(&make_revocation_single(revoked_id));

        // Vary each byte position — none should false-positive
        for pos in 0..32 {
            let mut probe_bytes = revoked_bytes;
            probe_bytes[pos] ^= 0x01;
            let probe_id = ObjectId::from_bytes(probe_bytes);
            assert!(
                !registry.is_revoked(&probe_id),
                "false positive at byte position {pos}"
            );
        }
    }

    #[test]
    fn c1_2_seal_exact_check_with_10k_entries() {
        // check_with_seal must also be exact (no false revocations via seal path)
        let mut registry = RevocationRegistry::new();
        registry.update_head(make_object_id(0x01), 1, 100);

        for i in 0u32..1000 {
            let id = make_id_from_u32(i);
            registry.add_revocation(&make_revocation_single(id));
        }
        registry.update_head(make_object_id(0x02), 1001, 200);

        // Non-revoked IDs via seal path: all must be NotRevoked
        for i in 1000u32..2000 {
            let seal = registry.check_with_seal(&make_id_from_u32(i), 300);
            assert_eq!(
                seal.decision,
                RevocationDecision::NotRevoked,
                "false revocation via seal for id {i}"
            );
        }

        // Revoked IDs via seal path: all must be Revoked
        for i in 0u32..1000 {
            let seal = registry.check_with_seal(&make_id_from_u32(i), 300);
            assert_eq!(
                seal.decision,
                RevocationDecision::Revoked,
                "missed revocation via seal for id {i}"
            );
        }
    }

    #[test]
    fn c1_2_performance_10k_revocations() {
        // Ensure revocation lookup is fast even with 10K entries
        let mut registry = RevocationRegistry::new();

        for i in 0u32..10_000 {
            let id = make_id_from_u32(i);
            registry.add_revocation(&make_revocation_single(id));
        }

        // 100K lookups (mix of hits and misses)
        let start = std::time::Instant::now();
        for i in 0u32..100_000 {
            let _ = registry.is_revoked(&make_id_from_u32(i));
        }
        let elapsed = start.elapsed();
        // HashMap O(1) lookups: 100K should finish well under 1 second
        assert!(
            elapsed.as_millis() < 1000,
            "100K revocation lookups took {elapsed:?}, expected < 1s"
        );
    }

    // ── C1.4 — Zone-wide revocation SLA with quorum-signed frontier ────

    #[test]
    fn c1_4_sla_fresh_within_window() {
        let checker = RevocationSlaChecker::new(100, 1_700_000_000, 300);
        let status = checker.check_sla(1_700_000_200); // 200s < 300s SLA
        assert_eq!(status, RevocationSlaStatus::Fresh);
        assert!(status.is_fresh());
    }

    #[test]
    fn c1_4_sla_breached_past_window() {
        let checker = RevocationSlaChecker::new(100, 1_700_000_000, 300);
        let status = checker.check_sla(1_700_000_500); // 500s > 300s SLA
        assert_eq!(status, RevocationSlaStatus::Breached { overdue_secs: 200 });
        assert!(!status.is_fresh());
    }

    #[test]
    fn c1_4_critical_op_aborts_on_breach() {
        let checker = RevocationSlaChecker::new(100, 1_700_000_000, 300);
        // Within SLA — Critical may proceed
        assert!(checker.may_proceed(1_700_000_200, RevocationFreshnessClass::Critical));
        // SLA breached — Critical must NOT proceed
        assert!(!checker.may_proceed(1_700_000_500, RevocationFreshnessClass::Critical));
    }

    #[test]
    fn c1_4_risky_and_safe_ops_proceed_despite_breach() {
        let checker = RevocationSlaChecker::new(100, 1_700_000_000, 300);
        // Even when SLA breached, Risky and Safe may proceed
        assert!(checker.may_proceed(1_700_000_500, RevocationFreshnessClass::Risky));
        assert!(checker.may_proceed(1_700_000_500, RevocationFreshnessClass::Safe));
    }

    #[test]
    fn c1_4_sla_at_exact_boundary() {
        let checker = RevocationSlaChecker::new(100, 1_700_000_000, 300);
        // Exactly at the SLA boundary — still Fresh
        let status = checker.check_sla(1_700_000_300);
        assert_eq!(status, RevocationSlaStatus::Fresh);

        // One second past — Breached
        let status = checker.check_sla(1_700_000_301);
        assert_eq!(status, RevocationSlaStatus::Breached { overdue_secs: 1 });
    }

    #[test]
    fn c1_4_sla_serialization_roundtrip() {
        let status = RevocationSlaStatus::Breached { overdue_secs: 42 };
        let json = serde_json::to_string(&status).unwrap();
        let roundtripped: RevocationSlaStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, roundtripped);

        let fresh = RevocationSlaStatus::Fresh;
        let json = serde_json::to_string(&fresh).unwrap();
        let roundtripped: RevocationSlaStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(fresh, roundtripped);
    }
}
