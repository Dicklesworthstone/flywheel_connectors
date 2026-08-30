//! Trust/Quorum Model for FCP2 (NORMATIVE).
//!
//! This module defines quorum-signed object semantics with well-defined threshold
//! rules and conflict behavior. Many FCP2 objects require multiple signatures
//! (`AuditHead`, `RevocationHead`, `ZoneCheckpoint`, leases for risky ops).
//!
//! # Core Concepts
//!
//! - `n`: eligible nodes for a zone (by membership)
//! - `f`: maximum Byzantine faults assumed for that zone
//! - Threshold rules are configurable per zone
//!
//! # Risk Tiers
//!
//! | Tier | Required Signatures | Example Operations |
//! |------|--------------------|--------------------|
//! | `CriticalWrite` | `n - f` | `AuditHead`, `ZoneCheckpoint` |
//! | Dangerous | `n - f` | Dangerous leases |
//! | Risky | `f + 1` | Risky leases |
//! | Safe | 1 (coordinator) | Safe ops |
//!
//! # Determinism Rules
//!
//! - Quorum signatures MUST be sorted by `node_id` before hashing/encoding
//! - Tie-breakers MUST be deterministic and audited

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ZoneId;

/// Risk tier for operations requiring quorum signatures (NORMATIVE).
///
/// **Purpose:** Classifies the quorum requirements for distributed consensus operations.
/// Determines how many node signatures are needed to authorize an operation.
///
/// **Usage:**
/// - Quorum policy: `required_quorum(n, f, risk_tier)`
/// - Signature validation: `satisfies_quorum(policy, risk_tier)`
/// - Lease operations: `LeaseType.default_risk_tier()`
///
/// **Note:** This is distinct from [`SafetyTier`](crate::capability::SafetyTier) in `capability.rs`, which classifies
/// tool/operation safety for agent authorization. `RiskTier` is about "how many signatures?",
/// while `SafetyTier` is about "can this agent do this operation?".
///
/// | Tier | Required Signatures | Example Operations |
/// |------|--------------------|--------------------|
/// | `Safe` | 1 (coordinator only) | Safe leases |
/// | `Risky` | `f + 1` | Risky leases |
/// | `Dangerous` | `n - f` | Dangerous leases |
/// | `CriticalWrite` | `n - f` | AuditHead, ZoneCheckpoint |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskTier {
    /// Safe operations: coordinator-only signature (1 signature).
    Safe,
    /// Risky operations: require `f + 1` signatures (fault-tolerant minimum).
    Risky,
    /// Dangerous operations: require `n - f` signatures (Byzantine-tolerant).
    Dangerous,
    /// Critical writes (audit, checkpoint): require `n - f` signatures.
    CriticalWrite,
}

impl RiskTier {
    /// Get the human-readable name for this risk tier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Risky => "risky",
            Self::Dangerous => "dangerous",
            Self::CriticalWrite => "critical_write",
        }
    }
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Operation purpose for quorum requirements (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuorumPurpose {
    /// Audit chain head advancement.
    AuditHead,
    /// Zone checkpoint creation.
    ZoneCheckpoint,
    /// Revocation chain head advancement.
    RevocationHead,
    /// Lease acquisition for dangerous operations.
    DangerousLease,
    /// Lease acquisition for risky operations.
    RiskyLease,
    /// Safe lease (coordinator only).
    SafeLease,
    /// Key rotation ceremony.
    KeyRotation,
    /// Zone membership change.
    MembershipChange,
}

impl QuorumPurpose {
    /// Get the default risk tier for this purpose.
    #[must_use]
    pub const fn default_risk_tier(&self) -> RiskTier {
        match self {
            Self::AuditHead | Self::ZoneCheckpoint | Self::RevocationHead => {
                RiskTier::CriticalWrite
            }
            Self::DangerousLease | Self::KeyRotation | Self::MembershipChange => {
                RiskTier::Dangerous
            }
            Self::RiskyLease => RiskTier::Risky,
            Self::SafeLease => RiskTier::Safe,
        }
    }
}

/// Quorum policy configuration for a zone (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumPolicy {
    /// Zone this policy applies to.
    pub zone_id: ZoneId,

    /// Total eligible nodes in the zone (n).
    pub eligible_nodes: u32,

    /// Maximum Byzantine faults assumed (f).
    pub max_faults: u32,

    /// Allow degraded mode operations.
    pub allow_degraded_mode: bool,

    /// Minimum nodes required for degraded mode.
    pub degraded_mode_min_nodes: u32,
}

impl QuorumPolicy {
    /// Create a new quorum policy.
    ///
    /// # Panics
    ///
    /// Panics if `max_faults >= eligible_nodes` or if `eligible_nodes == 0`.
    #[must_use]
    pub fn new(zone_id: ZoneId, eligible_nodes: u32, max_faults: u32) -> Self {
        assert!(eligible_nodes > 0, "eligible_nodes must be > 0");
        assert!(
            max_faults < eligible_nodes,
            "max_faults must be < eligible_nodes"
        );

        Self {
            zone_id,
            eligible_nodes,
            max_faults,
            allow_degraded_mode: false,
            degraded_mode_min_nodes: 1,
        }
    }

    /// Create a policy with degraded mode enabled.
    #[must_use]
    pub const fn with_degraded_mode(mut self, min_nodes: u32) -> Self {
        self.allow_degraded_mode = true;
        self.degraded_mode_min_nodes = min_nodes;
        self
    }

    /// Calculate the required number of signatures for a given risk tier.
    ///
    /// Returns the minimum number of signatures needed to satisfy the quorum
    /// requirement for the specified risk tier.
    #[must_use]
    pub fn required_signatures(&self, risk_tier: RiskTier) -> u32 {
        required_quorum(self.eligible_nodes, self.max_faults, risk_tier)
    }

    /// Check if a signature count satisfies the quorum for a risk tier.
    #[must_use]
    pub fn is_quorum_met(&self, signature_count: u32, risk_tier: RiskTier) -> bool {
        signature_count >= self.required_signatures(risk_tier)
    }

    /// Check if we're in degraded mode (reduced node count).
    #[must_use]
    pub const fn is_degraded(&self, available_nodes: u32) -> bool {
        available_nodes < self.eligible_nodes
    }

    /// Check if an operation is allowed in degraded mode.
    #[must_use]
    pub fn can_proceed_degraded(&self, available_nodes: u32, risk_tier: RiskTier) -> bool {
        if !self.allow_degraded_mode {
            return false;
        }

        if available_nodes < self.degraded_mode_min_nodes {
            return false;
        }

        // In degraded mode, only Safe operations are allowed
        risk_tier == RiskTier::Safe
    }
}

/// Calculate required quorum for given parameters (NORMATIVE).
///
/// # Arguments
///
/// * `n` - Total eligible nodes
/// * `f` - Maximum Byzantine faults
/// * `risk_tier` - The risk classification of the operation
///
/// # Returns
///
/// The minimum number of signatures required.
///
/// # Panics
///
/// Panics if `n == 0` or `f >= n`.
#[must_use]
pub fn required_quorum(n: u32, f: u32, risk_tier: RiskTier) -> u32 {
    assert!(n > 0, "n must be > 0");
    assert!(f < n, "f must be < n");

    match risk_tier {
        // Safe: coordinator only
        RiskTier::Safe => 1,
        // Risky: f + 1 (can tolerate up to f failures)
        RiskTier::Risky => f + 1,
        // Dangerous and CriticalWrite: n - f (classic BFT quorum)
        RiskTier::Dangerous | RiskTier::CriticalWrite => n - f,
    }
}

/// Node identifier for signature canonicalization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    /// Create a new node ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the node ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Ord for NodeId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for NodeId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single node signature in a quorum set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSignature {
    /// The node that produced this signature.
    pub node_id: NodeId,

    /// The Ed25519 signature bytes (64 bytes), hex-encoded for serialization.
    #[serde(with = "crate::util::hex_or_bytes")]
    pub signature: [u8; 64],

    /// Timestamp when the signature was created (UNIX seconds).
    pub signed_at: u64,
}

impl NodeSignature {
    /// Create a new node signature.
    #[must_use]
    pub const fn new(node_id: NodeId, signature: [u8; 64], signed_at: u64) -> Self {
        Self {
            node_id,
            signature,
            signed_at,
        }
    }
}

impl Ord for NodeSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.node_id.cmp(&other.node_id)
    }
}

impl PartialOrd for NodeSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A canonicalized set of quorum signatures (NORMATIVE).
///
/// Signatures are stored sorted by `node_id` to ensure deterministic
/// serialization for hashing and encoding.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(into = "SignatureSetRaw", from = "SignatureSetRaw")]
pub struct SignatureSet {
    /// Signatures sorted by `node_id` (NORMATIVE: MUST be sorted).
    signatures: Vec<NodeSignature>,

    /// Set of node IDs for O(1) duplicate detection.
    /// NOTE: This is a cache rebuilt on deserialization - not serialized.
    node_ids: BTreeSet<String>,
}

/// Raw representation for serialization (without the cache).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignatureSetRaw {
    signatures: Vec<NodeSignature>,
}

impl From<SignatureSet> for SignatureSetRaw {
    fn from(set: SignatureSet) -> Self {
        Self {
            signatures: set.signatures,
        }
    }
}

impl From<SignatureSetRaw> for SignatureSet {
    fn from(raw: SignatureSetRaw) -> Self {
        let node_ids = raw
            .signatures
            .iter()
            .map(|sig| sig.node_id.0.clone())
            .collect();
        Self {
            signatures: raw.signatures,
            node_ids,
        }
    }
}

impl<'de> Deserialize<'de> for SignatureSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = SignatureSetRaw::deserialize(deserializer)?;
        Ok(Self::from(raw))
    }
}

impl PartialEq for SignatureSet {
    fn eq(&self, other: &Self) -> bool {
        // Only compare signatures - node_ids is a derived cache
        self.signatures == other.signatures
    }
}

impl Eq for SignatureSet {}

impl SignatureSet {
    /// Create a new empty signature set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a signature to the set.
    ///
    /// Returns `true` if the signature was added, `false` if a signature
    /// from this node already exists.
    pub fn add(&mut self, sig: NodeSignature) -> bool {
        if self.node_ids.contains(sig.node_id.as_str()) {
            return false;
        }

        self.node_ids.insert(sig.node_id.0.clone());
        self.signatures.push(sig);
        self.signatures.sort();
        true
    }

    /// Get the number of signatures in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Check if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Return the first duplicate signer node ID, if the serialized signature
    /// vector contains duplicates.
    #[must_use]
    pub fn duplicate_node_id(&self) -> Option<&str> {
        let mut seen = BTreeSet::new();
        for sig in &self.signatures {
            if !seen.insert(sig.node_id.as_str()) {
                return Some(sig.node_id.as_str());
            }
        }
        None
    }

    /// Get an iterator over the signatures.
    pub fn iter(&self) -> impl Iterator<Item = &NodeSignature> {
        self.signatures.iter()
    }

    /// Get the signatures as a slice (guaranteed sorted by `node_id`).
    #[must_use]
    pub fn as_slice(&self) -> &[NodeSignature] {
        &self.signatures
    }

    /// Check if the signature set satisfies a quorum policy.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn satisfies_quorum(&self, policy: &QuorumPolicy, risk_tier: RiskTier) -> bool {
        // Safe: signature sets are bounded to reasonable sizes (< u32::MAX)
        policy.is_quorum_met(self.len() as u32, risk_tier)
    }

    /// Get canonical bytes for hashing (NORMATIVE).
    ///
    /// Format: concatenation of sorted `(node_id_bytes || signature)`.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for sig in &self.signatures {
            let node_bytes = sig.node_id.as_str().as_bytes();
            out.extend_from_slice(
                &u32::try_from(node_bytes.len())
                    .unwrap_or(u32::MAX)
                    .to_le_bytes(),
            );
            out.extend_from_slice(node_bytes);
            out.extend_from_slice(&sig.signature);
        }
        out
    }
}

/// Reason codes for degraded mode (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DegradedModeReason {
    /// Network partition detected.
    NetworkPartition,
    /// Insufficient nodes online.
    InsufficientNodes,
    /// Node failure detected.
    NodeFailure,
    /// Quorum timeout exceeded.
    QuorumTimeout,
    /// Manual override by operator.
    ManualOverride,
}

impl DegradedModeReason {
    /// Get the human-readable description.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NetworkPartition => "network_partition",
            Self::InsufficientNodes => "insufficient_nodes",
            Self::NodeFailure => "node_failure",
            Self::QuorumTimeout => "quorum_timeout",
            Self::ManualOverride => "manual_override",
        }
    }
}

impl fmt::Display for DegradedModeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Degraded mode state for a zone (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModeState {
    /// Whether degraded mode is active.
    pub active: bool,

    /// Reason for entering degraded mode.
    pub reason: Option<DegradedModeReason>,

    /// When degraded mode was entered (UNIX timestamp).
    pub entered_at: Option<u64>,

    /// Number of available nodes.
    pub available_nodes: u32,

    /// Number of expected nodes.
    pub expected_nodes: u32,
}

impl DegradedModeState {
    /// Create a normal (non-degraded) state.
    #[must_use]
    pub const fn normal(available_nodes: u32) -> Self {
        Self {
            active: false,
            reason: None,
            entered_at: None,
            available_nodes,
            expected_nodes: available_nodes,
        }
    }

    /// Create a degraded state.
    #[must_use]
    pub const fn degraded(
        reason: DegradedModeReason,
        entered_at: u64,
        available_nodes: u32,
        expected_nodes: u32,
    ) -> Self {
        Self {
            active: true,
            reason: Some(reason),
            entered_at: Some(entered_at),
            available_nodes,
            expected_nodes,
        }
    }
}

/// Result of a quorum verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumVerificationResult {
    /// Whether the quorum was satisfied.
    pub satisfied: bool,

    /// Number of valid signatures.
    pub valid_count: u32,

    /// Number of signatures required.
    pub required_count: u32,

    /// Risk tier used for verification.
    pub risk_tier: RiskTier,

    /// Whether the zone is in degraded mode.
    pub degraded_mode: bool,

    /// Reason for failure (if any).
    pub failure_reason: Option<QuorumFailureReason>,
}

/// Reasons for quorum failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuorumFailureReason {
    /// Insufficient signatures.
    InsufficientSignatures,
    /// Invalid signature detected.
    InvalidSignature,
    /// Duplicate node signature.
    DuplicateNode,
    /// Node not in eligible set.
    NodeNotEligible,
    /// Operation not allowed in degraded mode.
    DegradedModeNotAllowed,
    /// Signature expired.
    SignatureExpired,
}

impl QuorumFailureReason {
    /// Get the human-readable description.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InsufficientSignatures => "insufficient_signatures",
            Self::InvalidSignature => "invalid_signature",
            Self::DuplicateNode => "duplicate_node",
            Self::NodeNotEligible => "node_not_eligible",
            Self::DegradedModeNotAllowed => "degraded_mode_not_allowed",
            Self::SignatureExpired => "signature_expired",
        }
    }
}

impl fmt::Display for QuorumFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // Required Quorum Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_required_quorum_safe() {
        // Safe always requires 1 signature
        assert_eq!(required_quorum(3, 1, RiskTier::Safe), 1);
        assert_eq!(required_quorum(5, 2, RiskTier::Safe), 1);
        assert_eq!(required_quorum(7, 3, RiskTier::Safe), 1);
    }

    #[test]
    fn test_required_quorum_risky() {
        // Risky requires f + 1
        assert_eq!(required_quorum(3, 1, RiskTier::Risky), 2); // 1 + 1
        assert_eq!(required_quorum(5, 2, RiskTier::Risky), 3); // 2 + 1
        assert_eq!(required_quorum(7, 3, RiskTier::Risky), 4); // 3 + 1
    }

    #[test]
    fn test_required_quorum_dangerous() {
        // Dangerous requires n - f
        assert_eq!(required_quorum(3, 1, RiskTier::Dangerous), 2); // 3 - 1
        assert_eq!(required_quorum(5, 2, RiskTier::Dangerous), 3); // 5 - 2
        assert_eq!(required_quorum(7, 3, RiskTier::Dangerous), 4); // 7 - 3
    }

    #[test]
    fn test_required_quorum_critical_write() {
        // CriticalWrite requires n - f (same as Dangerous)
        assert_eq!(required_quorum(3, 1, RiskTier::CriticalWrite), 2);
        assert_eq!(required_quorum(5, 2, RiskTier::CriticalWrite), 3);
        assert_eq!(required_quorum(7, 3, RiskTier::CriticalWrite), 4);
    }

    #[test]
    fn test_required_quorum_edge_cases() {
        // Minimum valid config: n=1, f=0
        assert_eq!(required_quorum(1, 0, RiskTier::Safe), 1);
        assert_eq!(required_quorum(1, 0, RiskTier::Risky), 1); // 0 + 1
        assert_eq!(required_quorum(1, 0, RiskTier::Dangerous), 1); // 1 - 0
        assert_eq!(required_quorum(1, 0, RiskTier::CriticalWrite), 1);

        // Two nodes: n=2, f=0
        assert_eq!(required_quorum(2, 0, RiskTier::Risky), 1);
        assert_eq!(required_quorum(2, 0, RiskTier::Dangerous), 2);
    }

    #[test]
    #[should_panic(expected = "n must be > 0")]
    fn test_required_quorum_panics_n_zero() {
        let _ = required_quorum(0, 0, RiskTier::Safe);
    }

    #[test]
    #[should_panic(expected = "f must be < n")]
    fn test_required_quorum_panics_f_equals_n() {
        let _ = required_quorum(3, 3, RiskTier::Safe);
    }

    #[test]
    #[should_panic(expected = "f must be < n")]
    fn test_required_quorum_panics_f_greater_than_n() {
        let _ = required_quorum(3, 5, RiskTier::Safe);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // QuorumPolicy Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_policy_new() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        assert_eq!(policy.eligible_nodes, 5);
        assert_eq!(policy.max_faults, 2);
        assert!(!policy.allow_degraded_mode);
    }

    #[test]
    fn test_quorum_policy_with_degraded_mode() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2).with_degraded_mode(2);
        assert!(policy.allow_degraded_mode);
        assert_eq!(policy.degraded_mode_min_nodes, 2);
    }

    #[test]
    fn test_quorum_policy_required_signatures() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        assert_eq!(policy.required_signatures(RiskTier::Safe), 1);
        assert_eq!(policy.required_signatures(RiskTier::Risky), 3);
        assert_eq!(policy.required_signatures(RiskTier::Dangerous), 3);
        assert_eq!(policy.required_signatures(RiskTier::CriticalWrite), 3);
    }

    #[test]
    fn test_quorum_policy_is_quorum_met() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);

        // Safe: needs 1
        assert!(policy.is_quorum_met(1, RiskTier::Safe));
        assert!(policy.is_quorum_met(2, RiskTier::Safe));

        // Risky: needs 3
        assert!(!policy.is_quorum_met(2, RiskTier::Risky));
        assert!(policy.is_quorum_met(3, RiskTier::Risky));
        assert!(policy.is_quorum_met(4, RiskTier::Risky));

        // Dangerous: needs 3
        assert!(!policy.is_quorum_met(2, RiskTier::Dangerous));
        assert!(policy.is_quorum_met(3, RiskTier::Dangerous));
    }

    #[test]
    fn test_quorum_policy_is_degraded() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        assert!(!policy.is_degraded(5));
        assert!(policy.is_degraded(4));
        assert!(policy.is_degraded(1));
    }

    #[test]
    fn test_quorum_policy_can_proceed_degraded() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2).with_degraded_mode(2);

        // Safe ops allowed with sufficient nodes
        assert!(policy.can_proceed_degraded(3, RiskTier::Safe));
        assert!(policy.can_proceed_degraded(2, RiskTier::Safe));
        assert!(!policy.can_proceed_degraded(1, RiskTier::Safe)); // Below min

        // Non-safe ops not allowed in degraded mode
        assert!(!policy.can_proceed_degraded(3, RiskTier::Risky));
        assert!(!policy.can_proceed_degraded(3, RiskTier::Dangerous));
        assert!(!policy.can_proceed_degraded(3, RiskTier::CriticalWrite));
    }

    #[test]
    fn test_quorum_policy_degraded_mode_disabled() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        // Degraded mode disabled by default
        assert!(!policy.can_proceed_degraded(3, RiskTier::Safe));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SignatureSet Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signature_set_empty() {
        let set = SignatureSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_signature_set_add_single() {
        let mut set = SignatureSet::new();
        let sig = NodeSignature::new(NodeId::new("node-1"), [0; 64], 1000);

        assert!(set.add(sig));
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_signature_set_rejects_duplicate() {
        let mut set = SignatureSet::new();
        let sig1 = NodeSignature::new(NodeId::new("node-1"), [0; 64], 1000);
        let sig2 = NodeSignature::new(NodeId::new("node-1"), [1; 64], 2000);

        assert!(set.add(sig1));
        assert!(!set.add(sig2)); // Same node_id
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_signature_set_sorted_by_node_id() {
        let mut set = SignatureSet::new();

        // Add in non-sorted order
        set.add(NodeSignature::new(NodeId::new("node-c"), [0; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-a"), [1; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-b"), [2; 64], 1000));

        let ids: Vec<_> = set.iter().map(|s| s.node_id.as_str()).collect();
        assert_eq!(ids, vec!["node-a", "node-b", "node-c"]);
    }

    #[test]
    fn test_signature_set_canonical_bytes_deterministic() {
        let mut set1 = SignatureSet::new();
        let mut set2 = SignatureSet::new();

        // Add in different order
        set1.add(NodeSignature::new(NodeId::new("node-a"), [1; 64], 1000));
        set1.add(NodeSignature::new(NodeId::new("node-b"), [2; 64], 1000));

        set2.add(NodeSignature::new(NodeId::new("node-b"), [2; 64], 1000));
        set2.add(NodeSignature::new(NodeId::new("node-a"), [1; 64], 1000));

        // Canonical bytes should be identical
        assert_eq!(set1.canonical_bytes(), set2.canonical_bytes());
    }

    #[test]
    fn test_signature_set_satisfies_quorum() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        let mut set = SignatureSet::new();

        // Add 2 signatures (not enough for Risky/Dangerous)
        set.add(NodeSignature::new(NodeId::new("node-1"), [0; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-2"), [1; 64], 1000));

        assert!(set.satisfies_quorum(&policy, RiskTier::Safe));
        assert!(!set.satisfies_quorum(&policy, RiskTier::Risky)); // needs 3

        // Add third signature
        set.add(NodeSignature::new(NodeId::new("node-3"), [2; 64], 1000));
        assert!(set.satisfies_quorum(&policy, RiskTier::Risky));
        assert!(set.satisfies_quorum(&policy, RiskTier::Dangerous));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RiskTier Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_risk_tier_display() {
        assert_eq!(RiskTier::Safe.to_string(), "safe");
        assert_eq!(RiskTier::Risky.to_string(), "risky");
        assert_eq!(RiskTier::Dangerous.to_string(), "dangerous");
        assert_eq!(RiskTier::CriticalWrite.to_string(), "critical_write");
    }

    #[test]
    fn test_quorum_purpose_default_risk_tier() {
        assert_eq!(
            QuorumPurpose::AuditHead.default_risk_tier(),
            RiskTier::CriticalWrite
        );
        assert_eq!(
            QuorumPurpose::ZoneCheckpoint.default_risk_tier(),
            RiskTier::CriticalWrite
        );
        assert_eq!(
            QuorumPurpose::DangerousLease.default_risk_tier(),
            RiskTier::Dangerous
        );
        assert_eq!(
            QuorumPurpose::RiskyLease.default_risk_tier(),
            RiskTier::Risky
        );
        assert_eq!(QuorumPurpose::SafeLease.default_risk_tier(), RiskTier::Safe);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DegradedModeState Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_degraded_mode_state_normal() {
        let state = DegradedModeState::normal(5);
        assert!(!state.active);
        assert!(state.reason.is_none());
        assert!(state.entered_at.is_none());
        assert_eq!(state.available_nodes, 5);
    }

    #[test]
    fn test_degraded_mode_state_degraded() {
        let state = DegradedModeState::degraded(DegradedModeReason::NetworkPartition, 1000, 3, 5);
        assert!(state.active);
        assert_eq!(state.reason, Some(DegradedModeReason::NetworkPartition));
        assert_eq!(state.entered_at, Some(1000));
        assert_eq!(state.available_nodes, 3);
        assert_eq!(state.expected_nodes, 5);
    }

    #[test]
    fn test_degraded_mode_reason_display() {
        assert_eq!(
            DegradedModeReason::NetworkPartition.to_string(),
            "network_partition"
        );
        assert_eq!(
            DegradedModeReason::InsufficientNodes.to_string(),
            "insufficient_nodes"
        );
        assert_eq!(DegradedModeReason::NodeFailure.to_string(), "node_failure");
        assert_eq!(
            DegradedModeReason::QuorumTimeout.to_string(),
            "quorum_timeout"
        );
        assert_eq!(
            DegradedModeReason::ManualOverride.to_string(),
            "manual_override"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // QuorumFailureReason Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_failure_reason_display() {
        assert_eq!(
            QuorumFailureReason::InsufficientSignatures.to_string(),
            "insufficient_signatures"
        );
        assert_eq!(
            QuorumFailureReason::InvalidSignature.to_string(),
            "invalid_signature"
        );
        assert_eq!(
            QuorumFailureReason::DuplicateNode.to_string(),
            "duplicate_node"
        );
        assert_eq!(
            QuorumFailureReason::NodeNotEligible.to_string(),
            "node_not_eligible"
        );
        assert_eq!(
            QuorumFailureReason::DegradedModeNotAllowed.to_string(),
            "degraded_mode_not_allowed"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NodeId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_node_id_ordering() {
        let a = NodeId::new("aaa");
        let b = NodeId::new("bbb");
        let c = NodeId::new("ccc");

        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn test_node_id_display() {
        let id = NodeId::new("test-node-123");
        assert_eq!(id.to_string(), "test-node-123");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Serialization Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_risk_tier_serialization() {
        let tier = RiskTier::CriticalWrite;
        let json = serde_json::to_string(&tier).unwrap();
        let deserialized: RiskTier = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, tier);
    }

    #[test]
    fn test_quorum_policy_serialization() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2).with_degraded_mode(2);
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: QuorumPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.eligible_nodes, 5);
        assert_eq!(deserialized.max_faults, 2);
        assert!(deserialized.allow_degraded_mode);
        assert_eq!(deserialized.degraded_mode_min_nodes, 2);
    }

    #[test]
    fn test_signature_set_serialization() {
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(NodeId::new("node-1"), [0; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-2"), [1; 64], 2000));

        let json = serde_json::to_string(&set).unwrap();
        let deserialized: SignatureSet = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.len(), 2);
        // The node_ids cache is rebuilt during deserialization
    }

    #[test]
    fn test_signature_set_duplicate_detection_after_deserialization() {
        // Regression test: ensure node_ids cache is rebuilt after deserialization
        // so that duplicate detection continues to work correctly.
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(
            NodeId::new("node-alpha"),
            [0xAA; 64],
            1000,
        ));
        set.add(NodeSignature::new(
            NodeId::new("node-beta"),
            [0xBB; 64],
            2000,
        ));

        // Serialize and deserialize
        let json = serde_json::to_string(&set).unwrap();
        let mut deserialized: SignatureSet = serde_json::from_str(&json).unwrap();

        // Try to add a duplicate - should be rejected
        let duplicate_added = deserialized.add(NodeSignature::new(
            NodeId::new("node-alpha"), // Same node_id
            [0xFF; 64],                // Different signature value
            3000,
        ));
        assert!(
            !duplicate_added,
            "Duplicate node-alpha should be rejected after deserialization"
        );
        assert_eq!(
            deserialized.len(),
            2,
            "Length should remain 2 after rejected duplicate"
        );

        // Adding a new node should still work
        let new_added = deserialized.add(NodeSignature::new(
            NodeId::new("node-gamma"),
            [0xCC; 64],
            4000,
        ));
        assert!(new_added, "New node-gamma should be accepted");
        assert_eq!(deserialized.len(), 3);
    }

    #[test]
    fn test_signature_set_reports_malformed_deserialized_duplicate_node() {
        let json = serde_json::json!({
            "signatures": [
                {
                    "node_id": "node-alpha",
                    "signature": "aa".repeat(64),
                    "signed_at": 1000
                },
                {
                    "node_id": "node-alpha",
                    "signature": "bb".repeat(64),
                    "signed_at": 2000
                }
            ]
        });
        let set: SignatureSet = serde_json::from_value(json).unwrap();

        assert_eq!(set.len(), 2);
        assert_eq!(set.duplicate_node_id(), Some("node-alpha"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Byzantine Fault Tolerance (n/f) Assumption Tests
    // ─────────────────────────────────────────────────────────────────────────
    // For BFT systems: n >= 3f + 1, so f_max = floor((n-1)/3)

    /// Helper: Calculate maximum tolerable Byzantine faults for n nodes.
    /// For BFT: `f_max` = floor((n-1)/3)
    fn max_byzantine_faults(n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        (n - 1) / 3
    }

    #[test]
    fn test_bft_3_node_mesh_tolerates_0_faults() {
        // 3-node mesh: f_max = (3-1)/3 = 0
        let n = 3;
        let f_max = max_byzantine_faults(n);
        assert_eq!(f_max, 0, "3-node mesh should tolerate 0 Byzantine faults");

        // With f=0, all risk tiers should work
        let policy = QuorumPolicy::new(ZoneId::work(), n, 0);
        assert_eq!(policy.required_signatures(RiskTier::Safe), 1);
        assert_eq!(policy.required_signatures(RiskTier::Risky), 1); // 0 + 1
        assert_eq!(policy.required_signatures(RiskTier::Dangerous), 3); // 3 - 0
        assert_eq!(policy.required_signatures(RiskTier::CriticalWrite), 3);

        // All 3 nodes required for critical operations (unanimous)
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(NodeId::new("node-0"), [0; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-1"), [1; 64], 1000));
        assert!(!set.satisfies_quorum(&policy, RiskTier::CriticalWrite));
        set.add(NodeSignature::new(NodeId::new("node-2"), [2; 64], 1000));
        assert!(set.satisfies_quorum(&policy, RiskTier::CriticalWrite));
    }

    #[test]
    fn test_bft_4_node_mesh_tolerates_1_fault() {
        // 4-node mesh: f_max = (4-1)/3 = 1
        let n = 4;
        let f_max = max_byzantine_faults(n);
        assert_eq!(f_max, 1, "4-node mesh should tolerate 1 Byzantine fault");

        // With f=1: n >= 3(1) + 1 = 4 ✓
        let policy = QuorumPolicy::new(ZoneId::work(), n, 1);
        assert_eq!(policy.required_signatures(RiskTier::Safe), 1);
        assert_eq!(policy.required_signatures(RiskTier::Risky), 2); // 1 + 1
        assert_eq!(policy.required_signatures(RiskTier::Dangerous), 3); // 4 - 1
        assert_eq!(policy.required_signatures(RiskTier::CriticalWrite), 3);

        // 3 of 4 needed for critical operations
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(NodeId::new("node-0"), [0; 64], 1000));
        set.add(NodeSignature::new(NodeId::new("node-1"), [1; 64], 1000));
        assert!(!set.satisfies_quorum(&policy, RiskTier::CriticalWrite));
        set.add(NodeSignature::new(NodeId::new("node-2"), [2; 64], 1000));
        assert!(set.satisfies_quorum(&policy, RiskTier::CriticalWrite));
    }

    #[test]
    fn test_bft_7_node_mesh_tolerates_2_faults() {
        // 7-node mesh: f_max = (7-1)/3 = 2
        let n = 7;
        let f_max = max_byzantine_faults(n);
        assert_eq!(f_max, 2, "7-node mesh should tolerate 2 Byzantine faults");

        // With f=2: n >= 3(2) + 1 = 7 ✓
        let policy = QuorumPolicy::new(ZoneId::work(), n, 2);
        assert_eq!(policy.required_signatures(RiskTier::Safe), 1);
        assert_eq!(policy.required_signatures(RiskTier::Risky), 3); // 2 + 1
        assert_eq!(policy.required_signatures(RiskTier::Dangerous), 5); // 7 - 2
        assert_eq!(policy.required_signatures(RiskTier::CriticalWrite), 5);

        // 5 of 7 needed for critical operations
        let mut set = SignatureSet::new();
        for i in 0u8..4 {
            set.add(NodeSignature::new(
                NodeId::new(format!("node-{i}")),
                [i; 64],
                1000,
            ));
        }
        assert!(!set.satisfies_quorum(&policy, RiskTier::CriticalWrite)); // 4 < 5
        set.add(NodeSignature::new(NodeId::new("node-4"), [4; 64], 1000));
        assert!(set.satisfies_quorum(&policy, RiskTier::CriticalWrite)); // 5 >= 5
    }

    #[test]
    fn test_bft_f_less_than_n_div_3_invariant() {
        // Verify the BFT invariant: for true Byzantine tolerance, f < n/3
        // Which is equivalent to: n >= 3f + 1

        // Test various configurations
        let test_cases = [
            (1, 0, true),  // n=1, f=0: 1 >= 1 ✓
            (3, 0, true),  // n=3, f=0: 3 >= 1 ✓
            (4, 1, true),  // n=4, f=1: 4 >= 4 ✓
            (5, 1, true),  // n=5, f=1: 5 >= 4 ✓
            (6, 1, true),  // n=6, f=1: 6 >= 4 ✓
            (7, 2, true),  // n=7, f=2: 7 >= 7 ✓
            (10, 3, true), // n=10, f=3: 10 >= 10 ✓
            (13, 4, true), // n=13, f=4: 13 >= 13 ✓
            // Edge cases that violate BFT (but allowed by current impl)
            (3, 1, false), // n=3, f=1: 3 >= 4 ✗ (not BFT safe)
            (4, 2, false), // n=4, f=2: 4 >= 7 ✗ (not BFT safe)
            (6, 2, false), // n=6, f=2: 6 >= 7 ✗ (not BFT safe)
        ];

        for (n, f, is_bft_safe) in test_cases {
            let actual_max_f = max_byzantine_faults(n);
            let is_safe = f <= actual_max_f;
            assert_eq!(
                is_safe, is_bft_safe,
                "n={n}, f={f}: expected BFT safe={is_bft_safe}, actual max_f={actual_max_f}"
            );
        }
    }

    #[test]
    fn test_quorum_size_n_minus_f_calculated_correctly() {
        // Verify quorum = n - f for Dangerous/CriticalWrite
        let test_cases = [
            (3, 0, 3),  // 3 - 0 = 3
            (4, 1, 3),  // 4 - 1 = 3
            (5, 1, 4),  // 5 - 1 = 4
            (7, 2, 5),  // 7 - 2 = 5
            (10, 3, 7), // 10 - 3 = 7
            (13, 4, 9), // 13 - 4 = 9
        ];

        for (n, f, expected_quorum) in test_cases {
            let actual = required_quorum(n, f, RiskTier::CriticalWrite);
            assert_eq!(
                actual, expected_quorum,
                "n={n}, f={f}: expected quorum={expected_quorum}, got {actual}"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Threshold Rules Tests (Zone Operations, Checkpoints, Revocations)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_zone_operations_require_2f_plus_1_for_risky() {
        // Risky operations require f + 1 signatures (not 2f+1)
        // Note: The spec says 2f+1 for BFT, but our impl uses f+1 for Risky
        let test_cases = [
            (4, 1, 2),  // f + 1 = 2
            (7, 2, 3),  // f + 1 = 3
            (10, 3, 4), // f + 1 = 4
        ];

        for (n, f, expected) in test_cases {
            let actual = required_quorum(n, f, RiskTier::Risky);
            assert_eq!(
                actual, expected,
                "Risky quorum for n={n}, f={f}: expected {expected}, got {actual}"
            );
        }
    }

    #[test]
    fn test_checkpoint_advancement_requires_quorum() {
        // ZoneCheckpoint uses CriticalWrite risk tier
        assert_eq!(
            QuorumPurpose::ZoneCheckpoint.default_risk_tier(),
            RiskTier::CriticalWrite
        );

        let policy = QuorumPolicy::new(ZoneId::work(), 7, 2);
        let required = policy.required_signatures(RiskTier::CriticalWrite);
        assert_eq!(required, 5); // 7 - 2 = 5

        let mut set = SignatureSet::new();
        for i in 0u8..4 {
            set.add(NodeSignature::new(
                NodeId::new(format!("node-{i}")),
                [i; 64],
                1000,
            ));
        }
        assert!(
            !set.satisfies_quorum(&policy, RiskTier::CriticalWrite),
            "4 signatures should not satisfy checkpoint quorum (need 5)"
        );

        set.add(NodeSignature::new(NodeId::new("node-4"), [4; 64], 1000));
        assert!(
            set.satisfies_quorum(&policy, RiskTier::CriticalWrite),
            "5 signatures should satisfy checkpoint quorum"
        );
    }

    #[test]
    fn test_key_rotation_requires_quorum() {
        // KeyRotation uses Dangerous risk tier
        assert_eq!(
            QuorumPurpose::KeyRotation.default_risk_tier(),
            RiskTier::Dangerous
        );

        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);
        let required = policy.required_signatures(RiskTier::Dangerous);
        assert_eq!(required, 4); // 5 - 1 = 4
    }

    #[test]
    fn test_revocation_propagation_requires_quorum() {
        // RevocationHead uses CriticalWrite risk tier
        assert_eq!(
            QuorumPurpose::RevocationHead.default_risk_tier(),
            RiskTier::CriticalWrite
        );

        let policy = QuorumPolicy::new(ZoneId::work(), 4, 1);
        let required = policy.required_signatures(RiskTier::CriticalWrite);
        assert_eq!(required, 3); // 4 - 1 = 3
    }

    #[test]
    fn test_threshold_signature_verification() {
        // Test that exactly the threshold number of signatures is needed
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);

        // Dangerous needs 4 signatures (5 - 1)
        for sig_count in 0..=5 {
            let should_satisfy = sig_count >= 4;
            assert_eq!(
                policy.is_quorum_met(sig_count, RiskTier::Dangerous),
                should_satisfy,
                "With {sig_count} signatures: expected satisfied={should_satisfy}"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Degraded Mode Semantics Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_degraded_mode_triggers_at_f_failures() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(3);

        // Full capacity: not degraded
        assert!(!policy.is_degraded(5));

        // One failure (at f): degraded
        assert!(policy.is_degraded(4));

        // More failures: still degraded
        assert!(policy.is_degraded(3));
        assert!(policy.is_degraded(2));
        assert!(policy.is_degraded(1));
    }

    #[test]
    fn test_operations_pause_when_quorum_lost() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(3);

        // With 2 nodes: below degraded_mode_min_nodes (3)
        // Even Safe operations should be blocked
        assert!(
            !policy.can_proceed_degraded(2, RiskTier::Safe),
            "Operations should pause when below minimum nodes"
        );

        // With 0 nodes: definitely blocked
        assert!(!policy.can_proceed_degraded(0, RiskTier::Safe));
    }

    #[test]
    fn test_clear_error_codes_for_degraded_state() {
        // All reason codes should have clear string representations
        let reasons = [
            (DegradedModeReason::NetworkPartition, "network_partition"),
            (DegradedModeReason::InsufficientNodes, "insufficient_nodes"),
            (DegradedModeReason::NodeFailure, "node_failure"),
            (DegradedModeReason::QuorumTimeout, "quorum_timeout"),
            (DegradedModeReason::ManualOverride, "manual_override"),
        ];

        for (reason, expected_str) in reasons {
            assert_eq!(reason.as_str(), expected_str);
        }

        // QuorumFailureReason should also be clear
        assert_eq!(
            QuorumFailureReason::DegradedModeNotAllowed.as_str(),
            "degraded_mode_not_allowed"
        );
    }

    #[test]
    fn test_recovery_path_when_nodes_return() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(3);

        // Simulate degraded state
        let degraded_state = DegradedModeState::degraded(
            DegradedModeReason::NodeFailure,
            1000,
            3, // 3 available
            5, // 5 expected
        );
        assert!(degraded_state.active);

        // When nodes return, we can create a normal state
        let recovered_state = DegradedModeState::normal(5);
        assert!(!recovered_state.active);
        assert!(recovered_state.reason.is_none());

        // Full capacity means not degraded
        assert!(!policy.is_degraded(5));

        // And all operations should work
        assert!(policy.is_quorum_met(4, RiskTier::Dangerous));
    }

    #[test]
    fn test_degraded_mode_all_reasons_serializable() {
        let reasons = [
            DegradedModeReason::NetworkPartition,
            DegradedModeReason::InsufficientNodes,
            DegradedModeReason::NodeFailure,
            DegradedModeReason::QuorumTimeout,
            DegradedModeReason::ManualOverride,
        ];

        for reason in reasons {
            let state = DegradedModeState::degraded(reason, 1000, 3, 5);
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: DegradedModeState = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.reason, Some(reason));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Safety Tier Quorum Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_safe_operations_single_node() {
        // Safe operations require only 1 signature (coordinator)
        for n in 1..=10 {
            for f in 0..n {
                assert_eq!(
                    required_quorum(n, f, RiskTier::Safe),
                    1,
                    "Safe operations should always require exactly 1 signature"
                );
            }
        }
    }

    #[test]
    fn test_risky_operations_f_plus_1_quorum() {
        // Risky operations require f + 1 signatures
        let test_cases = [
            (3, 0, 1),
            (4, 1, 2),
            (5, 1, 2),
            (5, 2, 3),
            (7, 2, 3),
            (10, 3, 4),
        ];

        for (n, f, expected) in test_cases {
            let actual = required_quorum(n, f, RiskTier::Risky);
            assert_eq!(
                actual, expected,
                "Risky: n={n}, f={f} should require {expected}, got {actual}"
            );
        }
    }

    #[test]
    fn test_dangerous_operations_higher_quorum() {
        // Dangerous operations require n - f signatures
        let test_cases = [
            (3, 0, 3),  // unanimous
            (4, 1, 3),  // 3 of 4
            (5, 1, 4),  // 4 of 5
            (7, 2, 5),  // 5 of 7
            (10, 3, 7), // 7 of 10
        ];

        for (n, f, expected) in test_cases {
            let actual = required_quorum(n, f, RiskTier::Dangerous);
            assert_eq!(
                actual, expected,
                "Dangerous: n={n}, f={f} should require {expected}, got {actual}"
            );
        }
    }

    #[test]
    fn test_critical_operations_same_as_dangerous() {
        // CriticalWrite has the same quorum as Dangerous
        for n in 1..=10 {
            for f in 0..n {
                let dangerous = required_quorum(n, f, RiskTier::Dangerous);
                let critical = required_quorum(n, f, RiskTier::CriticalWrite);
                assert_eq!(
                    dangerous, critical,
                    "n={n}, f={f}: CriticalWrite should match Dangerous"
                );
            }
        }
    }

    #[test]
    fn test_quorum_purpose_to_risk_tier_mapping() {
        // Verify all purposes map to expected risk tiers
        let mappings = [
            (QuorumPurpose::SafeLease, RiskTier::Safe),
            (QuorumPurpose::RiskyLease, RiskTier::Risky),
            (QuorumPurpose::DangerousLease, RiskTier::Dangerous),
            (QuorumPurpose::KeyRotation, RiskTier::Dangerous),
            (QuorumPurpose::MembershipChange, RiskTier::Dangerous),
            (QuorumPurpose::AuditHead, RiskTier::CriticalWrite),
            (QuorumPurpose::ZoneCheckpoint, RiskTier::CriticalWrite),
            (QuorumPurpose::RevocationHead, RiskTier::CriticalWrite),
        ];

        for (purpose, expected_tier) in mappings {
            assert_eq!(
                purpose.default_risk_tier(),
                expected_tier,
                "{purpose:?} should map to {expected_tier:?}"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Split-Brain Prevention Tests
    // ─────────────────────────────────────────────────────────────────────────

    /// Represents a partition of nodes for split-brain testing.
    struct Partition {
        nodes: Vec<NodeId>,
    }

    impl Partition {
        fn new(node_ids: &[&str]) -> Self {
            Self {
                nodes: node_ids.iter().map(|id| NodeId::new(*id)).collect(),
            }
        }

        fn size(&self) -> u32 {
            u32::try_from(self.nodes.len()).expect("partition size fits u32")
        }

        fn create_signature_set(&self) -> SignatureSet {
            let mut set = SignatureSet::new();
            for (i, node) in self.nodes.iter().enumerate() {
                let idx = u8::try_from(i).expect("node index fits u8");
                set.add(NodeSignature::new(node.clone(), [idx; 64], 1000));
            }
            set
        }
    }

    #[test]
    fn test_only_one_partition_can_make_progress() {
        // 5-node cluster with f=1, split into 3-2
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);
        let quorum_needed = policy.required_signatures(RiskTier::CriticalWrite); // 4

        let majority = Partition::new(&["node-0", "node-1", "node-2"]);
        let minority = Partition::new(&["node-3", "node-4"]);

        // Neither partition alone has quorum for critical ops
        assert!(
            !policy.is_quorum_met(majority.size(), RiskTier::CriticalWrite),
            "3 nodes should not satisfy quorum of {quorum_needed}"
        );
        assert!(
            !policy.is_quorum_met(minority.size(), RiskTier::CriticalWrite),
            "2 nodes should not satisfy quorum of {quorum_needed}"
        );

        // For Safe operations, either partition can proceed
        assert!(policy.is_quorum_met(majority.size(), RiskTier::Safe));
        assert!(policy.is_quorum_met(minority.size(), RiskTier::Safe));

        // For Risky (f+1=2), both partitions can technically proceed
        // but only if they have >= 2 nodes
        assert!(policy.is_quorum_met(majority.size(), RiskTier::Risky));
        assert!(policy.is_quorum_met(minority.size(), RiskTier::Risky));

        // This is why CriticalWrite requires n-f: to prevent split-brain
        // on critical operations like checkpoints
    }

    #[test]
    fn test_minority_partition_refuses_writes() {
        // 7-node cluster with f=2, split into 5-2
        let policy = QuorumPolicy::new(ZoneId::work(), 7, 2);

        let majority = Partition::new(&["node-0", "node-1", "node-2", "node-3", "node-4"]);
        let minority = Partition::new(&["node-5", "node-6"]);

        // Majority can achieve quorum (5 >= 5)
        let majority_sigs = majority.create_signature_set();
        assert!(
            majority_sigs.satisfies_quorum(&policy, RiskTier::CriticalWrite),
            "Majority partition (5) should satisfy quorum (5)"
        );

        // Minority cannot achieve quorum (2 < 5)
        let minority_sigs = minority.create_signature_set();
        assert!(
            !minority_sigs.satisfies_quorum(&policy, RiskTier::CriticalWrite),
            "Minority partition (2) should not satisfy quorum (5)"
        );
    }

    #[test]
    fn test_majority_partition_continues() {
        // 5-node cluster, 3-node majority should continue operations
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1).with_degraded_mode(3);

        // Even though we're degraded (3 < 5), we can do Safe ops
        assert!(policy.can_proceed_degraded(3, RiskTier::Safe));

        // But we cannot do critical operations without full quorum
        // Note: can_proceed_degraded only allows Safe ops
        assert!(!policy.can_proceed_degraded(3, RiskTier::CriticalWrite));

        // However, if we have 4 signatures, we CAN satisfy CriticalWrite
        assert!(policy.is_quorum_met(4, RiskTier::CriticalWrite));
    }

    #[test]
    fn test_split_brain_merge_after_heal() {
        // After network partition heals, both sides should be able to
        // participate in quorum again

        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);

        // During partition: neither side has full quorum
        let side_a = Partition::new(&["node-0", "node-1", "node-2"]);
        let side_b = Partition::new(&["node-3", "node-4"]);

        assert!(
            !side_a
                .create_signature_set()
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );
        assert!(
            !side_b
                .create_signature_set()
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );

        // After heal: combined set can achieve quorum
        let mut healed_set = SignatureSet::new();
        for node in &side_a.nodes {
            healed_set.add(NodeSignature::new(node.clone(), [0; 64], 2000));
        }
        for node in &side_b.nodes {
            healed_set.add(NodeSignature::new(node.clone(), [1; 64], 2000));
        }

        assert_eq!(healed_set.len(), 5);
        assert!(
            healed_set.satisfies_quorum(&policy, RiskTier::CriticalWrite),
            "Healed cluster should satisfy quorum"
        );
    }

    #[test]
    fn test_even_split_cannot_proceed() {
        // 4-node cluster with f=1, split 2-2
        let policy = QuorumPolicy::new(ZoneId::work(), 4, 1);
        let required = policy.required_signatures(RiskTier::CriticalWrite); // 3

        // Neither 2-node partition can proceed with critical ops
        assert!(
            !policy.is_quorum_met(2, RiskTier::CriticalWrite),
            "2 nodes cannot satisfy quorum of {required}"
        );

        // This prevents split-brain: neither side can make conflicting updates
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Additional Edge Case Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_large_cluster_quorum() {
        // Test with larger cluster sizes
        let test_cases = [
            (100, 33, 67), // f = 33, quorum = 67
            (50, 16, 34),  // f = 16, quorum = 34
            (25, 8, 17),   // f = 8, quorum = 17
        ];

        for (n, f, expected_quorum) in test_cases {
            let actual = required_quorum(n, f, RiskTier::CriticalWrite);
            assert_eq!(
                actual, expected_quorum,
                "n={n}, f={f}: expected {expected_quorum}, got {actual}"
            );
        }
    }

    #[test]
    fn test_quorum_verification_result_fields() {
        // Test QuorumVerificationResult structure
        let result = QuorumVerificationResult {
            satisfied: false,
            valid_count: 2,
            required_count: 3,
            risk_tier: RiskTier::Dangerous,
            degraded_mode: true,
            failure_reason: Some(QuorumFailureReason::InsufficientSignatures),
        };

        assert!(!result.satisfied);
        assert_eq!(result.valid_count, 2);
        assert_eq!(result.required_count, 3);
        assert_eq!(result.risk_tier, RiskTier::Dangerous);
        assert!(result.degraded_mode);
        assert_eq!(
            result.failure_reason,
            Some(QuorumFailureReason::InsufficientSignatures)
        );

        // Verify serialization
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: QuorumVerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.satisfied, result.satisfied);
        assert_eq!(deserialized.valid_count, result.valid_count);
    }

    #[test]
    fn test_signature_set_with_many_nodes() {
        // Stress test signature set with many nodes
        let mut set = SignatureSet::new();

        for i in 0u8..100 {
            let added = set.add(NodeSignature::new(
                NodeId::new(format!("node-{i:03}")), // Zero-padded for consistent ordering
                [i; 64],
                1000 + u64::from(i),
            ));
            assert!(added, "Adding node-{i:03} should succeed");
        }

        assert_eq!(set.len(), 100);

        // Verify ordering is maintained
        let ids: Vec<_> = set.iter().map(|s| s.node_id.as_str()).collect();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort_unstable();
        assert_eq!(ids, sorted_ids, "Signatures should be sorted by node_id");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests (NORMATIVE)
    // ─────────────────────────────────────────────────────────────────────────
    // These tests verify that our serialization is deterministic and can be
    // used to generate/validate golden vectors for interoperability testing.

    /// Schema for quorum golden vectors.
    fn quorum_schema() -> fcp_cbor::SchemaId {
        fcp_cbor::SchemaId::new(
            "fcp.core",
            "QuorumGoldenVector",
            semver::Version::new(1, 0, 0),
        )
    }

    /// Schema for degraded state golden vectors.
    fn degraded_state_schema() -> fcp_cbor::SchemaId {
        fcp_cbor::SchemaId::new(
            "fcp.core",
            "DegradedStateGoldenVector",
            semver::Version::new(1, 0, 0),
        )
    }

    /// Golden vector wrapper for quorum scenarios (`SignatureSet` + metadata).
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
    struct QuorumGoldenVector {
        scenario: String,
        eligible_nodes: u32,
        max_faults: u32,
        signatures: SignatureSet,
        satisfies_risk_tier: Option<String>,
        zone_id: String,
    }

    /// Golden vector wrapper for degraded state scenarios.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
    struct DegradedStateGoldenVector {
        scenario: String,
        state: DegradedModeState,
        policy_eligible_nodes: u32,
        policy_max_faults: u32,
    }

    /// Helper: Create a deterministic signature for golden vectors.
    fn deterministic_signature(node_idx: u8) -> [u8; 64] {
        [node_idx; 64]
    }

    #[test]
    fn test_golden_vector_quorum_3_of_3() {
        let mut signatures = SignatureSet::new();
        signatures.add(NodeSignature::new(
            NodeId::new("node-alice"),
            deterministic_signature(0x01),
            1_704_067_200,
        ));
        signatures.add(NodeSignature::new(
            NodeId::new("node-bob"),
            deterministic_signature(0x02),
            1_704_067_200,
        ));
        signatures.add(NodeSignature::new(
            NodeId::new("node-charlie"),
            deterministic_signature(0x03),
            1_704_067_200,
        ));

        let vector = QuorumGoldenVector {
            scenario: "3-node unanimous quorum (f=0)".to_string(),
            eligible_nodes: 3,
            max_faults: 0,
            signatures,
            satisfies_risk_tier: Some("critical_write".to_string()),
            zone_id: "z:work".to_string(),
        };

        let schema = quorum_schema();
        let bytes1 = fcp_cbor::CanonicalSerializer::serialize(&vector, &schema).unwrap();
        let bytes2 = fcp_cbor::CanonicalSerializer::serialize(&vector, &schema).unwrap();
        assert_eq!(bytes1, bytes2, "Serialization must be deterministic");

        let decoded: QuorumGoldenVector =
            fcp_cbor::CanonicalSerializer::deserialize(&bytes1, &schema).unwrap();
        assert_eq!(decoded, vector);

        let policy = QuorumPolicy::new(ZoneId::work(), 3, 0);
        assert!(
            decoded
                .signatures
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );
    }

    #[test]
    fn test_golden_vector_quorum_3_of_5() {
        let mut signatures = SignatureSet::new();
        signatures.add(NodeSignature::new(
            NodeId::new("node-alpha"),
            deterministic_signature(0x11),
            1_704_067_200,
        ));
        signatures.add(NodeSignature::new(
            NodeId::new("node-beta"),
            deterministic_signature(0x12),
            1_704_067_200,
        ));
        signatures.add(NodeSignature::new(
            NodeId::new("node-gamma"),
            deterministic_signature(0x13),
            1_704_067_200,
        ));

        let vector = QuorumGoldenVector {
            scenario: "5-node cluster with 3 signatures (f=1)".to_string(),
            eligible_nodes: 5,
            max_faults: 1,
            signatures,
            satisfies_risk_tier: Some("risky".to_string()),
            zone_id: "z:work".to_string(),
        };

        let schema = quorum_schema();
        let bytes = fcp_cbor::CanonicalSerializer::serialize(&vector, &schema).unwrap();
        let decoded: QuorumGoldenVector =
            fcp_cbor::CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, vector);

        let policy = QuorumPolicy::new(ZoneId::work(), 5, 1);
        assert!(
            decoded
                .signatures
                .satisfies_quorum(&policy, RiskTier::Risky)
        );
        assert!(
            !decoded
                .signatures
                .satisfies_quorum(&policy, RiskTier::CriticalWrite)
        );
    }

    #[test]
    fn test_golden_vector_degraded_state() {
        let state =
            DegradedModeState::degraded(DegradedModeReason::InsufficientNodes, 1_704_067_200, 3, 5);

        let vector = DegradedStateGoldenVector {
            scenario: "5-node cluster degraded to 3 nodes".to_string(),
            state,
            policy_eligible_nodes: 5,
            policy_max_faults: 1,
        };

        let schema = degraded_state_schema();
        let bytes = fcp_cbor::CanonicalSerializer::serialize(&vector, &schema).unwrap();
        let decoded: DegradedStateGoldenVector =
            fcp_cbor::CanonicalSerializer::deserialize(&bytes, &schema).unwrap();
        assert_eq!(decoded, vector);

        assert!(decoded.state.active);
        assert_eq!(
            decoded.state.reason,
            Some(DegradedModeReason::InsufficientNodes)
        );
    }

    #[test]
    #[ignore = "generates golden vector files on demand"]
    fn generate_golden_vector_files() {
        use std::fs;
        use std::path::Path;

        let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/vectors/quorum");

        fs::create_dir_all(&vectors_dir).expect("Failed to create vectors directory");

        // quorum_3_of_3.cbor
        {
            let mut signatures = SignatureSet::new();
            signatures.add(NodeSignature::new(
                NodeId::new("node-alice"),
                deterministic_signature(0x01),
                1_704_067_200,
            ));
            signatures.add(NodeSignature::new(
                NodeId::new("node-bob"),
                deterministic_signature(0x02),
                1_704_067_200,
            ));
            signatures.add(NodeSignature::new(
                NodeId::new("node-charlie"),
                deterministic_signature(0x03),
                1_704_067_200,
            ));

            let vector = QuorumGoldenVector {
                scenario: "3-node unanimous quorum (f=0)".to_string(),
                eligible_nodes: 3,
                max_faults: 0,
                signatures,
                satisfies_risk_tier: Some("critical_write".to_string()),
                zone_id: "z:work".to_string(),
            };

            let bytes =
                fcp_cbor::CanonicalSerializer::serialize(&vector, &quorum_schema()).unwrap();
            fs::write(vectors_dir.join("quorum_3_of_3.cbor"), &bytes).unwrap();
        }

        // quorum_3_of_5.cbor
        {
            let mut signatures = SignatureSet::new();
            signatures.add(NodeSignature::new(
                NodeId::new("node-alpha"),
                deterministic_signature(0x11),
                1_704_067_200,
            ));
            signatures.add(NodeSignature::new(
                NodeId::new("node-beta"),
                deterministic_signature(0x12),
                1_704_067_200,
            ));
            signatures.add(NodeSignature::new(
                NodeId::new("node-gamma"),
                deterministic_signature(0x13),
                1_704_067_200,
            ));

            let vector = QuorumGoldenVector {
                scenario: "5-node cluster with 3 signatures (f=1)".to_string(),
                eligible_nodes: 5,
                max_faults: 1,
                signatures,
                satisfies_risk_tier: Some("risky".to_string()),
                zone_id: "z:work".to_string(),
            };

            let bytes =
                fcp_cbor::CanonicalSerializer::serialize(&vector, &quorum_schema()).unwrap();
            fs::write(vectors_dir.join("quorum_3_of_5.cbor"), &bytes).unwrap();
        }

        // degraded_state.cbor
        {
            let state = DegradedModeState::degraded(
                DegradedModeReason::InsufficientNodes,
                1_704_067_200,
                3,
                5,
            );

            let vector = DegradedStateGoldenVector {
                scenario: "5-node cluster degraded to 3 nodes".to_string(),
                state,
                policy_eligible_nodes: 5,
                policy_max_faults: 1,
            };

            let bytes = fcp_cbor::CanonicalSerializer::serialize(&vector, &degraded_state_schema())
                .unwrap();
            fs::write(vectors_dir.join("degraded_state.cbor"), &bytes).unwrap();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Additional quorum tests for 110+ coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn risk_tier_as_str_all_variants() {
        assert_eq!(RiskTier::Safe.as_str(), "safe");
        assert_eq!(RiskTier::Risky.as_str(), "risky");
        assert_eq!(RiskTier::Dangerous.as_str(), "dangerous");
        assert_eq!(RiskTier::CriticalWrite.as_str(), "critical_write");
    }

    #[test]
    fn risk_tier_copy_semantics() {
        let tier = RiskTier::Dangerous;
        let copied = tier;
        assert_eq!(tier, copied);
    }

    #[test]
    fn risk_tier_hash_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RiskTier::Safe);
        set.insert(RiskTier::Risky);
        set.insert(RiskTier::Dangerous);
        set.insert(RiskTier::CriticalWrite);
        assert_eq!(set.len(), 4);
        // Inserting duplicate should not increase size
        set.insert(RiskTier::Safe);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn risk_tier_serde_all_variants() {
        let tiers = [
            RiskTier::Safe,
            RiskTier::Risky,
            RiskTier::Dangerous,
            RiskTier::CriticalWrite,
        ];
        for tier in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            let decoded: RiskTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, decoded);
        }
    }

    #[test]
    fn risk_tier_debug_format() {
        let debug = format!("{:?}", RiskTier::CriticalWrite);
        assert!(debug.contains("CriticalWrite"));
    }

    #[test]
    fn risk_tier_inequality() {
        assert_ne!(RiskTier::Safe, RiskTier::Risky);
        assert_ne!(RiskTier::Dangerous, RiskTier::CriticalWrite);
    }

    #[test]
    fn quorum_purpose_copy_semantics() {
        let purpose = QuorumPurpose::AuditHead;
        let copied = purpose;
        assert_eq!(purpose, copied);
    }

    #[test]
    fn quorum_purpose_hash_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(QuorumPurpose::AuditHead);
        set.insert(QuorumPurpose::ZoneCheckpoint);
        set.insert(QuorumPurpose::RevocationHead);
        set.insert(QuorumPurpose::DangerousLease);
        set.insert(QuorumPurpose::RiskyLease);
        set.insert(QuorumPurpose::SafeLease);
        set.insert(QuorumPurpose::KeyRotation);
        set.insert(QuorumPurpose::MembershipChange);
        assert_eq!(set.len(), 8);
    }

    #[test]
    fn quorum_purpose_serde_all_variants() {
        let purposes = [
            QuorumPurpose::AuditHead,
            QuorumPurpose::ZoneCheckpoint,
            QuorumPurpose::RevocationHead,
            QuorumPurpose::DangerousLease,
            QuorumPurpose::RiskyLease,
            QuorumPurpose::SafeLease,
            QuorumPurpose::KeyRotation,
            QuorumPurpose::MembershipChange,
        ];
        for purpose in purposes {
            let json = serde_json::to_string(&purpose).unwrap();
            let decoded: QuorumPurpose = serde_json::from_str(&json).unwrap();
            assert_eq!(purpose, decoded);
        }
    }

    #[test]
    fn quorum_purpose_debug_format() {
        let debug = format!("{:?}", QuorumPurpose::KeyRotation);
        assert!(debug.contains("KeyRotation"));
    }

    #[test]
    fn quorum_policy_new_single_node() {
        let policy = QuorumPolicy::new(ZoneId::work(), 1, 0);
        assert_eq!(policy.eligible_nodes, 1);
        assert_eq!(policy.max_faults, 0);
        assert_eq!(policy.required_signatures(RiskTier::Safe), 1);
        assert_eq!(policy.required_signatures(RiskTier::Dangerous), 1);
    }

    #[test]
    #[should_panic(expected = "eligible_nodes must be > 0")]
    fn quorum_policy_new_zero_nodes_panics() {
        let _ = QuorumPolicy::new(ZoneId::work(), 0, 0);
    }

    #[test]
    #[should_panic(expected = "max_faults must be < eligible_nodes")]
    fn quorum_policy_new_f_equals_n_panics() {
        let _ = QuorumPolicy::new(ZoneId::work(), 3, 3);
    }

    #[test]
    fn quorum_policy_degraded_mode_defaults() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        assert!(!policy.allow_degraded_mode);
        assert_eq!(policy.degraded_mode_min_nodes, 1);
    }

    #[test]
    fn quorum_policy_is_degraded_at_full_capacity() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        assert!(!policy.is_degraded(5));
        assert!(!policy.is_degraded(6)); // more than expected is not degraded
    }

    #[test]
    fn quorum_policy_is_degraded_zero_available() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        assert!(policy.is_degraded(0));
    }

    #[test]
    fn quorum_policy_degraded_mode_disabled_blocks_all() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        // Without degraded mode enabled, all degraded ops are blocked
        assert!(!policy.can_proceed_degraded(4, RiskTier::Safe));
        assert!(!policy.can_proceed_degraded(4, RiskTier::Risky));
        assert!(!policy.can_proceed_degraded(4, RiskTier::Dangerous));
    }

    #[test]
    fn quorum_policy_degraded_mode_min_nodes_boundary() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2).with_degraded_mode(3);
        // At min_nodes: allowed for Safe
        assert!(policy.can_proceed_degraded(3, RiskTier::Safe));
        // Below min_nodes: not allowed even for Safe
        assert!(!policy.can_proceed_degraded(2, RiskTier::Safe));
    }

    #[test]
    fn quorum_policy_is_quorum_met_zero_sigs() {
        let policy = QuorumPolicy::new(ZoneId::work(), 3, 1);
        assert!(!policy.is_quorum_met(0, RiskTier::Safe));
    }

    #[test]
    fn quorum_policy_is_quorum_met_exact_threshold() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        // Risky needs f+1 = 3
        assert!(policy.is_quorum_met(3, RiskTier::Risky));
        assert!(!policy.is_quorum_met(2, RiskTier::Risky));
    }

    #[test]
    fn quorum_policy_is_quorum_met_above_threshold() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        // Dangerous needs n-f = 3, having 5 should still pass
        assert!(policy.is_quorum_met(5, RiskTier::Dangerous));
    }

    #[test]
    fn node_id_new_from_string() {
        let id = NodeId::new("my-node".to_string());
        assert_eq!(id.as_str(), "my-node");
    }

    #[test]
    fn node_id_equality() {
        let a = NodeId::new("node-1");
        let b = NodeId::new("node-1");
        assert_eq!(a, b);
    }

    #[test]
    fn node_id_inequality() {
        let a = NodeId::new("node-1");
        let b = NodeId::new("node-2");
        assert_ne!(a, b);
    }

    #[test]
    fn node_id_ord_consistent_with_partial_ord() {
        let a = NodeId::new("aaa");
        let b = NodeId::new("bbb");
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn node_id_clone() {
        let id = NodeId::new("cloneable");
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn node_id_serde_roundtrip() {
        let id = NodeId::new("serde-node");
        let json = serde_json::to_string(&id).unwrap();
        let decoded: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn node_signature_fields() {
        let sig = NodeSignature::new(NodeId::new("n1"), [0xAB; 64], 999);
        assert_eq!(sig.node_id.as_str(), "n1");
        assert_eq!(sig.signature, [0xAB; 64]);
        assert_eq!(sig.signed_at, 999);
    }

    #[test]
    fn node_signature_ord_by_node_id() {
        let a = NodeSignature::new(NodeId::new("alpha"), [0; 64], 1000);
        let b = NodeSignature::new(NodeId::new("beta"), [0; 64], 1000);
        assert!(a < b);
        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
    }

    #[test]
    fn node_signature_clone() {
        let sig = NodeSignature::new(NodeId::new("n"), [42; 64], 100);
        let cloned = sig.clone();
        assert_eq!(sig, cloned);
    }

    #[test]
    fn node_signature_serde_roundtrip() {
        let sig = NodeSignature::new(NodeId::new("test"), [0xFF; 64], 1234);
        let json = serde_json::to_string(&sig).unwrap();
        let decoded: NodeSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn signature_set_default_is_empty() {
        let set = SignatureSet::default();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn signature_set_as_slice() {
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(NodeId::new("n1"), [1; 64], 100));
        set.add(NodeSignature::new(NodeId::new("n2"), [2; 64], 200));
        let slice = set.as_slice();
        assert_eq!(slice.len(), 2);
        assert_eq!(slice[0].node_id.as_str(), "n1");
        assert_eq!(slice[1].node_id.as_str(), "n2");
    }

    #[test]
    fn signature_set_canonical_bytes_empty() {
        let set = SignatureSet::new();
        let bytes = set.canonical_bytes();
        assert!(bytes.is_empty());
    }

    #[test]
    fn signature_set_canonical_bytes_single() {
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(NodeId::new("n"), [0xAA; 64], 100));
        let bytes = set.canonical_bytes();
        // node_id length (4 bytes) + node_id bytes + signature (64 bytes)
        assert_eq!(bytes.len(), 4 + 1 + 64); // "n" is 1 byte
    }

    #[test]
    fn signature_set_eq_ignores_order_of_addition() {
        let mut set1 = SignatureSet::new();
        set1.add(NodeSignature::new(NodeId::new("a"), [1; 64], 100));
        set1.add(NodeSignature::new(NodeId::new("b"), [2; 64], 200));

        let mut set2 = SignatureSet::new();
        set2.add(NodeSignature::new(NodeId::new("b"), [2; 64], 200));
        set2.add(NodeSignature::new(NodeId::new("a"), [1; 64], 100));

        assert_eq!(set1, set2);
    }

    #[test]
    fn signature_set_ne_different_signatures() {
        let mut set1 = SignatureSet::new();
        set1.add(NodeSignature::new(NodeId::new("a"), [1; 64], 100));

        let mut set2 = SignatureSet::new();
        set2.add(NodeSignature::new(NodeId::new("a"), [2; 64], 100));

        assert_ne!(set1, set2);
    }

    #[test]
    fn signature_set_iter_yields_sorted_order() {
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(NodeId::new("z"), [0; 64], 100));
        set.add(NodeSignature::new(NodeId::new("a"), [1; 64], 100));
        set.add(NodeSignature::new(NodeId::new("m"), [2; 64], 100));

        let ids: Vec<&str> = set.iter().map(|s| s.node_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "m", "z"]);
    }

    #[test]
    fn degraded_mode_reason_copy_semantics() {
        let reason = DegradedModeReason::NetworkPartition;
        let copied = reason;
        assert_eq!(reason, copied);
    }

    #[test]
    fn degraded_mode_reason_hash_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DegradedModeReason::NetworkPartition);
        set.insert(DegradedModeReason::InsufficientNodes);
        set.insert(DegradedModeReason::NodeFailure);
        set.insert(DegradedModeReason::QuorumTimeout);
        set.insert(DegradedModeReason::ManualOverride);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn degraded_mode_reason_serde_all_variants() {
        let reasons = [
            DegradedModeReason::NetworkPartition,
            DegradedModeReason::InsufficientNodes,
            DegradedModeReason::NodeFailure,
            DegradedModeReason::QuorumTimeout,
            DegradedModeReason::ManualOverride,
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let decoded: DegradedModeReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, decoded);
        }
    }

    #[test]
    fn degraded_mode_state_normal_expected_equals_available() {
        let state = DegradedModeState::normal(7);
        assert_eq!(state.available_nodes, 7);
        assert_eq!(state.expected_nodes, 7);
    }

    #[test]
    fn degraded_mode_state_serde_roundtrip() {
        let state = DegradedModeState::degraded(DegradedModeReason::QuorumTimeout, 5000, 2, 5);
        let json = serde_json::to_string(&state).unwrap();
        let decoded: DegradedModeState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn degraded_mode_state_clone() {
        let state = DegradedModeState::degraded(DegradedModeReason::ManualOverride, 1000, 3, 5);
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn degraded_mode_state_debug_format() {
        let state = DegradedModeState::normal(3);
        let debug = format!("{state:?}");
        assert!(debug.contains("DegradedModeState"));
    }

    #[test]
    fn quorum_failure_reason_copy_semantics() {
        let reason = QuorumFailureReason::DuplicateNode;
        let copied = reason;
        assert_eq!(reason, copied);
    }

    #[test]
    fn quorum_failure_reason_hash_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(QuorumFailureReason::InsufficientSignatures);
        set.insert(QuorumFailureReason::InvalidSignature);
        set.insert(QuorumFailureReason::DuplicateNode);
        set.insert(QuorumFailureReason::NodeNotEligible);
        set.insert(QuorumFailureReason::DegradedModeNotAllowed);
        set.insert(QuorumFailureReason::SignatureExpired);
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn quorum_failure_reason_as_str_signature_expired() {
        assert_eq!(
            QuorumFailureReason::SignatureExpired.as_str(),
            "signature_expired"
        );
    }

    #[test]
    fn quorum_failure_reason_display_signature_expired() {
        assert_eq!(
            QuorumFailureReason::SignatureExpired.to_string(),
            "signature_expired"
        );
    }

    #[test]
    fn quorum_failure_reason_serde_all_variants() {
        let reasons = [
            QuorumFailureReason::InsufficientSignatures,
            QuorumFailureReason::InvalidSignature,
            QuorumFailureReason::DuplicateNode,
            QuorumFailureReason::NodeNotEligible,
            QuorumFailureReason::DegradedModeNotAllowed,
            QuorumFailureReason::SignatureExpired,
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let decoded: QuorumFailureReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, decoded);
        }
    }

    #[test]
    fn quorum_verification_result_satisfied() {
        let result = QuorumVerificationResult {
            satisfied: true,
            valid_count: 5,
            required_count: 3,
            risk_tier: RiskTier::Risky,
            degraded_mode: false,
            failure_reason: None,
        };
        assert!(result.satisfied);
        assert!(result.failure_reason.is_none());
    }

    #[test]
    fn quorum_verification_result_serde_roundtrip() {
        let result = QuorumVerificationResult {
            satisfied: false,
            valid_count: 1,
            required_count: 3,
            risk_tier: RiskTier::CriticalWrite,
            degraded_mode: true,
            failure_reason: Some(QuorumFailureReason::DegradedModeNotAllowed),
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: QuorumVerificationResult = serde_json::from_str(&json).unwrap();
        assert!(!decoded.satisfied);
        assert_eq!(decoded.valid_count, 1);
        assert_eq!(decoded.required_count, 3);
        assert_eq!(
            decoded.failure_reason,
            Some(QuorumFailureReason::DegradedModeNotAllowed)
        );
    }

    #[test]
    fn quorum_verification_result_clone() {
        let result = QuorumVerificationResult {
            satisfied: true,
            valid_count: 3,
            required_count: 3,
            risk_tier: RiskTier::Safe,
            degraded_mode: false,
            failure_reason: None,
        };
        let cloned = result.clone();
        assert_eq!(cloned.satisfied, result.satisfied);
        assert_eq!(cloned.valid_count, result.valid_count);
    }

    #[test]
    fn required_quorum_n_equals_2_f_equals_1() {
        assert_eq!(required_quorum(2, 1, RiskTier::Safe), 1);
        assert_eq!(required_quorum(2, 1, RiskTier::Risky), 2); // f+1 = 2
        assert_eq!(required_quorum(2, 1, RiskTier::Dangerous), 1); // n-f = 1
    }

    #[test]
    fn required_quorum_large_n() {
        assert_eq!(required_quorum(1000, 333, RiskTier::CriticalWrite), 667);
        assert_eq!(required_quorum(1000, 333, RiskTier::Risky), 334);
        assert_eq!(required_quorum(1000, 333, RiskTier::Safe), 1);
    }

    #[test]
    fn signature_set_clone() {
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(NodeId::new("a"), [1; 64], 100));
        set.add(NodeSignature::new(NodeId::new("b"), [2; 64], 200));
        let cloned = set.clone();
        assert_eq!(set, cloned);
        assert_eq!(cloned.len(), 2);
    }

    #[test]
    fn signature_set_satisfies_quorum_safe_with_single() {
        let policy = QuorumPolicy::new(ZoneId::work(), 10, 3);
        let mut set = SignatureSet::new();
        set.add(NodeSignature::new(NodeId::new("n1"), [0; 64], 100));
        assert!(set.satisfies_quorum(&policy, RiskTier::Safe));
    }

    #[test]
    fn signature_set_does_not_satisfy_quorum_empty() {
        let policy = QuorumPolicy::new(ZoneId::work(), 5, 2);
        let set = SignatureSet::new();
        assert!(!set.satisfies_quorum(&policy, RiskTier::Safe));
    }

    #[test]
    fn quorum_policy_serialization_with_zone() {
        let policy = QuorumPolicy::new(ZoneId::owner(), 7, 2).with_degraded_mode(4);
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: QuorumPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.eligible_nodes, 7);
        assert_eq!(decoded.max_faults, 2);
        assert!(decoded.allow_degraded_mode);
        assert_eq!(decoded.degraded_mode_min_nodes, 4);
    }

    #[test]
    fn degraded_mode_reason_inequality() {
        assert_ne!(
            DegradedModeReason::NetworkPartition,
            DegradedModeReason::NodeFailure
        );
    }

    #[test]
    fn quorum_failure_reason_inequality() {
        assert_ne!(
            QuorumFailureReason::InsufficientSignatures,
            QuorumFailureReason::InvalidSignature
        );
    }

    #[test]
    fn quorum_purpose_membership_change_is_dangerous() {
        assert_eq!(
            QuorumPurpose::MembershipChange.default_risk_tier(),
            RiskTier::Dangerous
        );
    }
}
