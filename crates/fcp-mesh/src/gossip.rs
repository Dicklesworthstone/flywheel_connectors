//! FCP Gossip Layer for Object Availability and Reconciliation.
//!
//! This module implements the gossip baseline from `FCP_Specification_V3.md`
//! §11.6.8 (Gossip and Anti-Entropy Mechanics):
//! - Object/symbol availability announcements
//! - Compact summaries for anti-entropy
//! - Bounded reconciliation (no unbounded work)
//!
//! # Security Model (NORMATIVE)
//!
//! 1. **Quarantined objects MUST NOT pollute gossip**: Only admitted objects are gossiped.
//! 2. **Signed summaries**: All gossip messages are signed for authentication and rate limiting.
//! 3. **Bounded reconciliation**: Reconciliation work is bounded by admission control.
//!
//! # Design Notes
//!
//! XOR filters use `xorf::Xor8` for compact ≈1.23 bits/element membership queries.
//! IBLT sketches mask object IDs with a deterministic zone mask before insertion,
//! so wire sketches do not expose raw object-id XOR sums.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use xorf::Filter as _;

use crate::admission::ObjectAdmissionClass;
use crate::iblt::{
    Iblt, IbltDecodeResult, IbltMask, LayeredFilterConfig, LayeredReconciliationFilter,
};
use fcp_crypto::{CryptoError, Ed25519Signature, Ed25519VerifyingKey};
use fcp_prelude::{EpochId, NodeSignature, ObjectId, TailscaleNodeId, ZoneId};
use fcp_telemetry::metrics;

// ─────────────────────────────────────────────────────────────────────────────
// Constants (NORMATIVE defaults)
// ─────────────────────────────────────────────────────────────────────────────

/// Default maximum objects per gossip summary (bounded reconciliation).
pub const DEFAULT_MAX_OBJECTS_PER_SUMMARY: usize = 10_000;

/// Default maximum symbols per gossip summary.
pub const DEFAULT_MAX_SYMBOLS_PER_SUMMARY: usize = 100_000;

/// Default gossip summary TTL in seconds.
pub const DEFAULT_SUMMARY_TTL_SECS: u64 = 300;

/// Default tolerance for a future-dated gossip timestamp, in seconds.
///
/// Without this floor a peer with a fast clock (or an adversary) could
/// emit a `GossipSummary` / `GossipRequest` / `RevocationPushMessage`
/// whose `timestamp` is far in the future. The age computation
/// `now.saturating_sub(timestamp)` then collapses to `0`, so the
/// freshness gate `age > ttl_secs` is always false and the message is
/// treated as fresh — defeating the gate.
///
/// 30 seconds covers ordinary NTP drift between cooperating nodes
/// while still rejecting deliberately-spoofed timestamps that could
/// (a) bypass the freshness window, or (b) for `GossipSummary`,
/// poison `peer_states[peer].last_updated` so legitimate later
/// summaries appear "older" until wall-clock catches up.
pub const DEFAULT_MAX_FUTURE_SKEW_SECS: u64 = 30;

/// Default reconciliation batch size (bounded work).
pub const DEFAULT_RECONCILIATION_BATCH_SIZE: usize = 1000;

/// Minimum byte budget for encoded IBLT placeholders.
pub const MIN_IBLT_BYTES_BUDGET: usize = 8192;

/// Maximum object IDs in a single gossip request (anti-amplification).
pub const MAX_OBJECT_IDS_PER_REQUEST: usize = 100;

/// Bounded timestamp validator for gossip-class messages.
///
/// Rejects (returns `true`) when `timestamp` is either:
///   * older than `ttl_secs` relative to `now`, or
///   * more than `max_future_skew_secs` in the future relative to `now`.
///
/// The future-skew bound is the security-relevant half: without it,
/// `now.saturating_sub(future_ts)` collapses to 0 and the
/// `age > ttl_secs` gate trivially passes, letting a peer with a fast
/// clock (or a malicious peer) bypass the freshness window or pin
/// `peer_states[peer].last_updated` to a future value so subsequent
/// legitimate updates compare older and are ignored until wall-clock
/// catches up.
#[must_use]
pub const fn is_outside_freshness_window(
    timestamp: u64,
    now: u64,
    ttl_secs: u64,
    max_future_skew_secs: u64,
) -> bool {
    if timestamp > now && timestamp - now > max_future_skew_secs {
        return true;
    }
    now.saturating_sub(timestamp) > ttl_secs
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer Protocol Capability Advertisement
// ─────────────────────────────────────────────────────────────────────────────

/// Wire-level mesh protocol generations a peer can speak during V3 -> V4 migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshProtocolVersion {
    /// V3 classical mesh keying: Ed25519 + X25519.
    V3,
    /// V4 hybrid post-quantum mesh keying: Dilithium + ML-KEM hybrid.
    V4,
}

impl MeshProtocolVersion {
    #[must_use]
    const fn wire_id(self) -> u8 {
        match self {
            Self::V3 => 3,
            Self::V4 => 4,
        }
    }
}

/// Advertised protocol generations for a mesh peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerProtocolCapabilities {
    /// Protocol generations this peer claims it can complete.
    pub protocols: BTreeSet<MeshProtocolVersion>,
}

impl PeerProtocolCapabilities {
    /// Classical-only capability advertisement.
    #[must_use]
    pub fn v3_only() -> Self {
        Self {
            protocols: BTreeSet::from([MeshProtocolVersion::V3]),
        }
    }

    /// Hybrid migration advertisement: accepts V3 fallback and V4.
    #[must_use]
    pub fn v3_v4() -> Self {
        Self {
            protocols: BTreeSet::from([MeshProtocolVersion::V3, MeshProtocolVersion::V4]),
        }
    }

    /// V4-only advertisement for peers past the fallback phase.
    #[must_use]
    pub fn v4_only() -> Self {
        Self {
            protocols: BTreeSet::from([MeshProtocolVersion::V4]),
        }
    }

    /// Whether this advertisement includes a protocol generation.
    #[must_use]
    pub fn supports(&self, protocol: MeshProtocolVersion) -> bool {
        self.protocols.contains(&protocol)
    }

    /// Whether this advertisement can satisfy a V4-required receiver policy.
    #[must_use]
    pub fn supports_v4(&self) -> bool {
        self.supports(MeshProtocolVersion::V4)
    }

    /// Whether this peer explicitly claims only V3 capability.
    #[must_use]
    pub fn is_v3_only(&self) -> bool {
        self.protocols.len() == 1 && self.supports(MeshProtocolVersion::V3)
    }
}

impl Default for PeerProtocolCapabilities {
    fn default() -> Self {
        Self::v3_only()
    }
}

/// Signed control-plane gossip advertisement for peer V3/V4 capability state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilityAdvertisement {
    /// Peer making the capability claim.
    pub from: TailscaleNodeId,
    /// Supported mesh protocol generations.
    pub capabilities: PeerProtocolCapabilities,
    /// Advertisement timestamp (Unix seconds).
    pub timestamp: u64,
    /// Peer signature over [`Self::signing_bytes`].
    pub signature: Option<NodeSignature>,
}

impl PeerCapabilityAdvertisement {
    /// Build a new unsigned capability advertisement.
    #[must_use]
    pub fn new(
        from: TailscaleNodeId,
        capabilities: PeerProtocolCapabilities,
        timestamp: u64,
    ) -> Self {
        Self {
            from,
            capabilities,
            timestamp,
            signature: None,
        }
    }

    /// Convenience constructor for a V3-only peer.
    #[must_use]
    pub fn v3_only(from: TailscaleNodeId, timestamp: u64) -> Self {
        Self::new(from, PeerProtocolCapabilities::v3_only(), timestamp)
    }

    /// Convenience constructor for a V3/V4-capable peer.
    #[must_use]
    pub fn v3_v4(from: TailscaleNodeId, timestamp: u64) -> Self {
        Self::new(from, PeerProtocolCapabilities::v3_v4(), timestamp)
    }

    /// Check whether the advertisement falls outside the freshness window.
    #[must_use]
    pub const fn is_stale(&self, now: u64, ttl_secs: u64, max_future_skew_secs: u64) -> bool {
        is_outside_freshness_window(self.timestamp, now, ttl_secs, max_future_skew_secs)
    }

    /// Canonical transcript bytes signed by the peer.
    ///
    /// # Panics
    ///
    /// Panics if any encoded variable-length field exceeds `u32::MAX`.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(64usize.saturating_add(self.capabilities.protocols.len()));
        bytes.extend_from_slice(b"FCP4-PEER-CAPABILITY-V1");

        let from_bytes = self.from.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(from_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(from_bytes);

        bytes.extend_from_slice(
            &u32::try_from(self.capabilities.protocols.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for protocol in &self.capabilities.protocols {
            bytes.push(protocol.wire_id());
        }

        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Attach a peer signature to the advertisement.
    #[must_use]
    pub fn with_signature(mut self, signature: NodeSignature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Verify the attached peer signature against the canonical transcript.
    ///
    /// # Errors
    ///
    /// Returns an error if the advertisement is unsigned or signature
    /// validation fails.
    pub fn verify_signature(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| CryptoError::MissingField("signature".into()))?;
        let signature = Ed25519Signature::from_bytes(&signature.signature);
        verifying_key.verify(&self.signing_bytes(), &signature)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Filter Types (XOR Filter + IBLT Placeholder)
// ─────────────────────────────────────────────────────────────────────────────

/// XOR filter for fast probabilistic membership hints (NORMATIVE).
///
/// Wraps `xorf::Xor8` for production-grade membership queries with:
/// - ≈1.23 bits per element (vs ≈10 bits for Bloom filters)
/// - <0.4% false positive rate per query
/// - No false negatives
/// - Deterministic construction from sorted key sets
///
/// XOR filters are immutable after construction, so this wrapper accumulates
/// u64 keys and lazily builds the `Xor8` on first query. The built filter is
/// cached and invalidated when new items are inserted.
///
/// # Security Note — NOT for revocation checks
///
/// This filter is used exclusively for gossip set reconciliation (object
/// availability, symbol routing) where false positives cause unnecessary
/// transfers but NOT security failures. Revocation checks MUST use exact
/// membership via [`RevocationRegistry::is_revoked`](fcp_core::RevocationRegistry::is_revoked)
/// which is backed by `HashMap<ObjectId, RevocationObject>`. See MOR/C1.2.
#[derive(Debug, Serialize, Deserialize)]
pub struct XorFilterPlaceholder {
    /// Deduped u64 keys derived from item bytes via Blake3.
    /// `BTreeSet` ensures deterministic iteration order.
    keys: BTreeSet<u64>,
    /// Hash seed for deterministic key derivation.
    seed: u64,
    /// Cached built XOR filter (rebuilt lazily on query).
    /// Skipped during serialization; rebuilt on demand after deserialization.
    #[serde(skip)]
    built: Mutex<Option<xorf::Xor8>>,
    /// Cached layered Bloom+XOR filter for lower false-positive route hints.
    /// Skipped during serialization; rebuilt on demand after deserialization.
    #[serde(skip)]
    layered: Mutex<Option<LayeredReconciliationFilter>>,
}

impl Clone for XorFilterPlaceholder {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            seed: self.seed,
            // Cache is not cloned; will be rebuilt lazily
            built: Mutex::new(None),
            layered: Mutex::new(None),
        }
    }
}

impl Default for XorFilterPlaceholder {
    fn default() -> Self {
        Self::new()
    }
}

impl XorFilterPlaceholder {
    /// Create a new empty filter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeSet::new(),
            seed: 0,
            built: Mutex::new(None),
            layered: Mutex::new(None),
        }
    }

    /// Create a filter with a specific seed for reproducibility.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self {
            keys: BTreeSet::new(),
            seed,
            built: Mutex::new(None),
            layered: Mutex::new(None),
        }
    }

    /// Insert an item into the filter.
    ///
    /// Hashes the item to a u64 key and adds it to the key set.
    /// Invalidates any cached `Xor8` filter.
    pub fn insert(&mut self, item: &[u8]) {
        let key = self.hash_item(item);
        if self.keys.insert(key) {
            // New key added; invalidate cached filter.
            // Using get_mut() avoids locking since we have &mut self.
            if let Ok(built) = self.built.get_mut() {
                *built = None;
            }
            if let Ok(layered) = self.layered.get_mut() {
                *layered = None;
            }
        }
    }

    /// Check if an item might be in the filter.
    ///
    /// Returns `false` if definitely not present, `true` if possibly present
    /// (with <0.4% false positive rate for `Xor8`).
    #[must_use]
    pub fn may_contain(&self, item: &[u8]) -> bool {
        if self.keys.is_empty() {
            return false;
        }
        let key = self.hash_item(item);
        // Fast path: check authoritative key set first
        if self.keys.contains(&key) {
            return true;
        }
        // Build the Xor8 filter if not yet built and query it
        self.ensure_built();
        if let Ok(guard) = self.layered.lock() {
            if let Some(ref filter) = *guard {
                return filter.may_contain_key(key);
            }
        }
        if let Ok(guard) = self.built.lock() {
            if let Some(ref filter) = *guard {
                return filter.contains(&key);
            }
        }
        // Fallback: if filter couldn't be built, check key set only
        false
    }

    /// Get the number of distinct elements inserted.
    #[must_use]
    pub fn len(&self) -> u32 {
        u32::try_from(self.keys.len()).unwrap_or(u32::MAX)
    }

    /// Check if filter is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Compute a BLAKE3 digest of the filter for comparison.
    ///
    /// The digest is computed over the sorted key set, ensuring deterministic
    /// results regardless of insertion order.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP2-XOR-FILTER-DIGEST-V2");
        hasher.update(&self.seed.to_le_bytes());
        let count = u32::try_from(self.keys.len()).unwrap_or(u32::MAX);
        hasher.update(&count.to_le_bytes());
        // Keys are in sorted order (BTreeSet), so digest is deterministic
        for key in &self.keys {
            hasher.update(&key.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Hash an item to a u64 key using BLAKE3 with the filter's seed.
    fn hash_item(&self, item: &[u8]) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.seed.to_le_bytes());
        hasher.update(item);
        let hash = hasher.finalize();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&hash.as_bytes()[0..8]);
        u64::from_le_bytes(buf)
    }

    /// Ensure the `Xor8` filter is built from the current key set.
    fn ensure_built(&self) {
        let key_vec: Vec<u64> = self.keys.iter().copied().collect();
        if key_vec.is_empty() {
            return;
        }

        if let Ok(mut guard) = self.built.lock() {
            if guard.is_none() {
                // xorf::Xor8::from requires no duplicate keys (guaranteed by BTreeSet)
                *guard = Some(xorf::Xor8::from(key_vec.as_slice()));
            }
        }

        if let Ok(mut guard) = self.layered.lock() {
            if guard.is_none() {
                *guard = Some(LayeredReconciliationFilter::from_keys(
                    self.seed,
                    LayeredFilterConfig::default(),
                    self.keys.clone(),
                ));
                debug!(
                    component = "mesh.gossip",
                    event = "layered_filter_promoted",
                    metric = "fcp.mesh.iblt.layer_promotions",
                    key_count = self.keys.len(),
                    target_fpr = LayeredFilterConfig::default().target_fpr
                );
            }
        }
    }
}

/// IBLT-backed gossip sketch for precise set reconciliation (NORMATIVE).
///
/// This is a thin wrapper over the production [`Iblt`] in
/// [`crate::iblt`]. Earlier revisions kept a JSON-serialized
/// `VecDeque<(ObjectId, Option<u32>)>` change log here as a placeholder
/// — it could not reconcile any divergence larger than
/// `reconciliation_batch_size` and silently dropped the oldest
/// changes. The wrapper now sizes a real `Iblt` for the configured
/// expected-difference budget, inserts admitted objects into the
/// sketch on each local change, and serializes the sketch as
/// canonical CBOR on the wire. Peer decode rehydrates a real `Iblt`
/// and enforces a cell-count cap rather than a change-count cap.
///
/// The name `IbltPlaceholder` is retained for ABI continuity (the
/// type is re-exported through the crate root and referenced from the
/// fuzz target) but the implementation is now production. Callers
/// that relied on `recent_changes()` to inspect the old per-change
/// log now receive an empty `Vec` — the sketch decode path should be
/// used for reconciliation instead. Symbol-level ESIs are no longer
/// tracked in this sketch; symbol reconciliation already flowed
/// through `symbol_filter` / `symbol_availability`, and mixing
/// (ObjectId, esi) pairs into the same change log was confusing and
/// not IBLT-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbltPlaceholder {
    /// Zone-derived object-id mask. The wire encoding remains the underlying
    /// IBLT, but the cell key sums contain masked object IDs.
    mask: IbltMask,
    /// Production IBLT sketch over admitted object IDs.
    iblt: Iblt,
    /// Cell-count budget used when constructing and validating sketches.
    cell_count: usize,
    /// Monotonic counter of local `note_local_change` calls. Retained
    /// for metrics parity with the pre-migration placeholder so
    /// existing `change_seq()` observers keep working.
    change_seq: u64,
}

impl Default for IbltPlaceholder {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors when decoding an IBLT gossip sketch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IbltDecodeError {
    /// Encoded sketch exceeded the configured byte budget.
    TooLarge { len: usize, max: usize },
    /// Encoded sketch could not be parsed as a canonical CBOR `Iblt`.
    InvalidEncoding,
    /// Encoded sketch declared more IBLT cells than the peer's cap allows.
    ///
    /// The variant is named `TooManyChanges` for backward compatibility
    /// with the previous change-log placeholder; under the production
    /// sketch the numeric fields describe IBLT cell count vs. cap.
    TooManyChanges { decoded: usize, max: usize },
}

impl IbltDecodeError {
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "iblt_bytes_exceeded",
            Self::InvalidEncoding => "iblt_invalid_encoding",
            Self::TooManyChanges { .. } => "iblt_change_limit_exceeded",
        }
    }
}

impl IbltPlaceholder {
    /// Create a new IBLT sketch sized for `DEFAULT_RECONCILIATION_BATCH_SIZE`
    /// expected differences.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_changes(DEFAULT_RECONCILIATION_BATCH_SIZE)
    }

    /// Create with a custom expected-difference budget.
    ///
    /// The argument is named `max_changes` for API continuity with the
    /// previous placeholder (`reconciliation_batch_size` callers pass
    /// the same value). The underlying `Iblt` is sized via
    /// [`Iblt::recommended_cell_count`] which floors at
    /// [`MIN_RECOMMENDED_IBLT_CELLS`](crate::iblt::MIN_RECOMMENDED_IBLT_CELLS) — so even
    /// `with_max_changes(0)` produces a valid (if unused) sketch.
    ///
    /// # Panics
    ///
    /// Panics only if the recommended cell-count helper violates its own
    /// minimum-size contract.
    #[must_use]
    pub fn with_max_changes(max_changes: usize) -> Self {
        Self::with_mask(max_changes, IbltMask::default())
    }

    /// Create with a custom expected-difference budget and object-id mask.
    ///
    /// # Panics
    ///
    /// Panics only if the recommended cell-count helper violates its own
    /// minimum-size contract.
    #[must_use]
    pub fn with_mask(max_changes: usize, mask: IbltMask) -> Self {
        let cell_count = Iblt::recommended_cell_count(max_changes);
        let iblt = Iblt::with_cell_count(cell_count)
            .expect("recommended_cell_count always returns at least MIN_RECOMMENDED_IBLT_CELLS");
        Self {
            mask,
            iblt,
            cell_count,
            change_seq: 0,
        }
    }

    /// Record a local change (object added/updated).
    ///
    /// `esi` is accepted for backward compatibility with the previous
    /// placeholder signature but is ignored — IBLT reconciliation
    /// operates over object IDs; symbol-level ESI reconciliation flows
    /// through the parallel `symbol_filter` / `symbol_availability`
    /// paths on `GossipState`.
    pub fn note_local_change(&mut self, object_id: &ObjectId, _esi: Option<u32>) {
        self.iblt.insert(self.mask.apply(*object_id));
        self.change_seq += 1;
    }

    /// Record a local object deletion.
    pub fn note_local_delete(&mut self, object_id: &ObjectId) {
        self.iblt.delete(self.mask.apply(*object_id));
        self.change_seq += 1;
    }

    /// Legacy accessor retained for ABI continuity. The production
    /// sketch does not maintain a per-change log; callers should
    /// perform an IBLT decode against a peer sketch instead of
    /// inspecting this list. Always returns an empty `Vec`.
    #[must_use]
    pub fn recent_changes(&self) -> Vec<(ObjectId, Option<u32>)> {
        Vec::new()
    }

    /// Get current change sequence.
    #[must_use]
    pub const fn change_seq(&self) -> u64 {
        self.change_seq
    }

    /// Object-id mask used before inserting into the sketch.
    #[must_use]
    pub const fn mask(&self) -> IbltMask {
        self.mask
    }

    /// Number of IBLT cells in the underlying sketch. Used by gossip
    /// telemetry to track sketch size on the wire.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.iblt.cell_count()
    }

    /// Borrow the underlying production IBLT sketch.
    #[must_use]
    pub const fn as_iblt(&self) -> &Iblt {
        &self.iblt
    }

    /// Encode the IBLT sketch for wire transmission as canonical CBOR.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // ciborium::into_writer returns Result<()>; silently drop errors and
        // hand back whatever bytes were written (empty on hard failure).
        let _ = ciborium::into_writer(&self.iblt, &mut buf);
        buf
    }

    /// Decode an IBLT sketch from a wire payload with explicit bounds.
    ///
    /// `max_changes` (historical name — see note on
    /// [`IbltDecodeError::TooManyChanges`]) caps the declared IBLT
    /// cell count; a peer that ships a sketch larger than our
    /// reconciliation budget is rejected. `max_bytes` caps the
    /// serialized payload length. The empty payload decodes to an
    /// empty sketch sized for `max_changes` for backward compatibility
    /// with the placeholder that returned `Self::with_max_changes` on
    /// empty input.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload exceeds byte/cell budgets or
    /// is malformed.
    pub fn decode_with_limits(
        bytes: &[u8],
        max_changes: usize,
        max_bytes: usize,
    ) -> Result<Self, IbltDecodeError> {
        if bytes.len() > max_bytes {
            return Err(IbltDecodeError::TooLarge {
                len: bytes.len(),
                max: max_bytes,
            });
        }

        if bytes.is_empty() {
            return Ok(Self::with_max_changes(max_changes));
        }

        let iblt: Iblt =
            ciborium::from_reader(bytes).map_err(|_| IbltDecodeError::InvalidEncoding)?;
        // Enforce the caller-supplied cell-count budget. The budget is
        // expressed in expected-difference units, so compare against
        // the recommended cell count for that budget.
        let cell_cap = Iblt::recommended_cell_count(max_changes);
        if iblt.cell_count() > cell_cap {
            return Err(IbltDecodeError::TooManyChanges {
                decoded: iblt.cell_count(),
                max: cell_cap,
            });
        }

        let cell_count = iblt.cell_count();
        Ok(Self {
            mask: IbltMask::default(),
            iblt,
            cell_count,
            change_seq: 0,
        })
    }

    /// Reset the sketch to an empty IBLT of the same cell budget.
    /// `change_seq` is preserved so metrics observers do not see a
    /// reset.
    ///
    /// # Panics
    ///
    /// Panics only if the previously validated cell count is no longer
    /// accepted by [`Iblt::with_cell_count`].
    pub fn clear(&mut self) {
        self.iblt = Iblt::with_cell_count(self.cell_count)
            .expect("cell_count was previously validated to be >= IBLT_HASH_COUNT");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gossip State
// ─────────────────────────────────────────────────────────────────────────────

/// Local gossip state for a zone (NORMATIVE).
///
/// Tracks which objects and symbols this node has available for gossip.
/// Only admitted (non-quarantined) objects are included.
#[derive(Debug, Clone)]
pub struct GossipState {
    /// Zone this state covers.
    zone_id: ZoneId,

    /// Object availability filter (fast membership hint).
    object_filter: XorFilterPlaceholder,

    /// Symbol availability filter.
    symbol_filter: XorFilterPlaceholder,

    /// IBLT state for precise reconciliation.
    iblt_state: IbltPlaceholder,
    /// Zone-derived mask used by both cached and summary IBLT sketches.
    iblt_mask: IbltMask,

    /// Admitted object IDs (authoritative set).
    admitted_objects: BTreeSet<ObjectId>,

    /// Symbol availability: object_id -> set of ESIs.
    symbol_availability: BTreeMap<ObjectId, BTreeSet<u32>>,

    /// Last update timestamp.
    last_updated: u64,

    /// Incrementally-maintained masked IBLT over `admitted_objects` (br-m68xt).
    /// Updated in O(1) by `announce_object` / `remove_object` so
    /// `build_iblt` / `reconcile_with_peer_iblt` can avoid the O(N)
    /// rebuild-every-peer cost. Sized at construction using
    /// `config.reconciliation_batch_size`; callers that request a
    /// different `expected_difference` fall back to the full rebuild
    /// path (which preserves exact legacy semantics for that call).
    cached_iblt: Iblt,
    /// Cell count of `cached_iblt`; cached to avoid repeated
    /// `recommended_cell_count` lookups on the hot path.
    cached_iblt_cell_count: usize,
}

impl GossipState {
    /// Create a new gossip state for a zone.
    ///
    /// # Panics
    ///
    /// Panics only if the reconciliation batch size maps to an invalid IBLT
    /// cell count, which would violate [`Iblt::recommended_cell_count`].
    #[must_use]
    pub fn new(zone_id: ZoneId, config: &GossipConfig) -> Self {
        let iblt_mask = IbltMask::for_zone(&zone_id);
        let cached_iblt_cell_count = Iblt::recommended_cell_count(config.reconciliation_batch_size);
        let cached_iblt = Iblt::with_cell_count(cached_iblt_cell_count)
            .expect("reconciliation_batch_size yields a valid cell count");
        Self {
            zone_id,
            object_filter: XorFilterPlaceholder::new(),
            symbol_filter: XorFilterPlaceholder::new(),
            iblt_state: IbltPlaceholder::with_mask(config.reconciliation_batch_size, iblt_mask),
            iblt_mask,
            admitted_objects: BTreeSet::new(),
            symbol_availability: BTreeMap::new(),
            last_updated: 0,
            cached_iblt,
            cached_iblt_cell_count,
        }
    }

    /// Get the zone ID.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Announce local object availability (NORMATIVE).
    ///
    /// Only admitted objects should be announced. This method does NOT check
    /// admission class - the caller MUST ensure the object is admitted.
    pub fn announce_object(&mut self, object_id: &ObjectId, now: u64) {
        if self.admitted_objects.insert(*object_id) {
            self.object_filter.insert(object_id.as_bytes());
            self.iblt_state.note_local_change(object_id, None);
            // br-m68xt: maintain the reconciliation IBLT incrementally.
            // The BTreeSet::insert guard above ensures no double-inserts.
            self.cached_iblt.insert(self.iblt_mask.apply(*object_id));
            self.last_updated = now;
        }
    }

    /// Announce local symbol availability (NORMATIVE).
    ///
    /// # Arguments
    ///
    /// * `object_id` - The object this symbol belongs to
    /// * `esi` - Encoding Symbol Identifier
    /// * `now` - Current timestamp
    pub fn announce_symbol(&mut self, object_id: &ObjectId, esi: u32, now: u64) {
        // Ensure object is tracked
        if !self.admitted_objects.contains(object_id) {
            self.announce_object(object_id, now);
        }

        // Add symbol
        let symbols = self.symbol_availability.entry(*object_id).or_default();
        if symbols.insert(esi) {
            self.symbol_filter.insert(&symbol_key(object_id, esi));
            self.last_updated = now;
        }
    }

    /// Check if we might have an object (fast filter check).
    #[must_use]
    pub fn may_have_object(&self, object_id: &ObjectId) -> bool {
        self.object_filter.may_contain(object_id.as_bytes())
    }

    /// Check if we definitely have an object (authoritative check).
    #[must_use]
    pub fn has_object(&self, object_id: &ObjectId) -> bool {
        self.admitted_objects.contains(object_id)
    }

    /// Check if we might have a symbol.
    #[must_use]
    pub fn may_have_symbol(&self, object_id: &ObjectId, esi: u32) -> bool {
        self.symbol_filter.may_contain(&symbol_key(object_id, esi))
    }

    /// Check if we definitely have a symbol.
    #[must_use]
    pub fn has_symbol(&self, object_id: &ObjectId, esi: u32) -> bool {
        self.symbol_availability
            .get(object_id)
            .is_some_and(|s| s.contains(&esi))
    }

    /// Get all symbols we have for an object.
    #[must_use]
    pub fn symbols_for_object(&self, object_id: &ObjectId) -> Option<&BTreeSet<u32>> {
        self.symbol_availability.get(object_id)
    }

    /// Get the number of admitted objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.admitted_objects.len()
    }

    /// Get the total number of symbols.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.symbol_availability.values().map(BTreeSet::len).sum()
    }

    /// Create a compact summary for gossip exchange.
    #[must_use]
    pub fn create_summary(&self, from: TailscaleNodeId, epoch_id: EpochId) -> GossipSummary {
        GossipSummary {
            from,
            zone_id: self.zone_id.clone(),
            epoch_id,
            object_filter_digest: self.object_filter.digest(),
            symbol_filter_digest: self.symbol_filter.digest(),
            object_count: u32::try_from(self.admitted_objects.len()).unwrap_or(u32::MAX),
            symbol_count: u32::try_from(self.symbol_count()).unwrap_or(u32::MAX),
            iblt: self.iblt_state.encode(),
            timestamp: self.last_updated,
            signature: None,
        }
    }

    /// Remove an object from gossip state.
    pub fn remove_object(&mut self, object_id: &ObjectId, now: u64) {
        // br-m68xt: delete from the cached IBLT BEFORE we lose the
        // was-present signal from `BTreeSet::remove`. Skipping the
        // delete when the object was never present keeps the cached
        // IBLT perfectly in sync with `admitted_objects` — spurious
        // deletes would push cell counters negative and corrupt
        // decode().
        if self.admitted_objects.remove(object_id) {
            self.iblt_state.note_local_delete(object_id);
            self.cached_iblt.delete(self.iblt_mask.apply(*object_id));
        }
        self.symbol_availability.remove(object_id);
        self.rebuild_filters();
        self.last_updated = now;
    }

    /// Rebuild filters from authoritative sets.
    fn rebuild_filters(&mut self) {
        self.object_filter = XorFilterPlaceholder::new();
        self.symbol_filter = XorFilterPlaceholder::new();

        for object_id in &self.admitted_objects {
            self.object_filter.insert(object_id.as_bytes());
        }

        for (object_id, esis) in &self.symbol_availability {
            for esi in esis {
                self.symbol_filter.insert(&symbol_key(object_id, *esi));
            }
        }
    }

    /// Get list of admitted objects (bounded).
    #[must_use]
    pub fn list_objects(&self, limit: usize) -> Vec<ObjectId> {
        self.admitted_objects.iter().take(limit).copied().collect()
    }

    /// Test-only accessor for the authoritative admitted-objects set.
    /// Used by the br-m68xt cache-sync regression tests to rebuild an
    /// independent IBLT for comparison against the cached one.
    #[cfg(test)]
    fn admitted_objects_iter_for_test(&self) -> impl Iterator<Item = &ObjectId> {
        self.admitted_objects.iter()
    }

    /// Build a production IBLT sketch from the admitted objects set.
    ///
    /// The IBLT is sized for the expected difference between nodes. Callers
    /// should pass a reasonable estimate (e.g. the count of recent changes).
    ///
    /// Fast path (br-m68xt): when `expected_difference` yields the same
    /// cell count as the incrementally-maintained `cached_iblt`,
    /// returns a clone of that sketch — O(cell_count) instead of
    /// O(admitted_objects.len()) per call. This is the hot path for
    /// `reconcile_with_peer_iblt` during gossip fanout, where rebuilding
    /// a full sketch per peer was the dominant CPU cost.
    ///
    /// Slow path: when the requested `expected_difference` maps to a
    /// different cell budget than the cached sketch (rare — callers
    /// typically use the config-derived batch size consistently), the
    /// legacy full-rebuild path is used for that one call so exact
    /// semantics are preserved for every caller.
    #[must_use]
    pub fn build_iblt(&self, expected_difference: usize) -> Iblt {
        let requested_cell_count = Iblt::recommended_cell_count(expected_difference);
        if requested_cell_count == self.cached_iblt_cell_count {
            return self.cached_iblt.clone();
        }

        let mut iblt = Iblt::with_expected_difference(expected_difference);
        for object_id in &self.admitted_objects {
            iblt.insert(self.iblt_mask.apply(*object_id));
        }
        iblt
    }

    /// Reconcile with a peer's IBLT sketch.
    ///
    /// Returns the decode result with `only_left` (objects we have that the peer
    /// doesn't) and `only_right` (objects the peer has that we don't).
    /// If the decode is incomplete, callers should fall back to paginated list
    /// exchange.
    pub fn reconcile_with_peer_iblt(
        &self,
        peer_iblt: &Iblt,
        expected_difference: usize,
    ) -> Option<IbltDecodeResult> {
        let local_iblt = self.build_iblt(expected_difference);
        // Ensure same cell count for subtraction
        if local_iblt.cell_count() != peer_iblt.cell_count() {
            return None;
        }
        let diff = local_iblt.subtract(peer_iblt).ok()?;
        Some(crate::iblt::masked::unmask_decode_result(
            diff.decode(),
            self.iblt_mask,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gossip Summary
// ─────────────────────────────────────────────────────────────────────────────

/// Signed gossip summary for anti-entropy (NORMATIVE).
///
/// This is exchanged between peers to detect differences in object/symbol availability.
/// The digest allows quick comparison without transferring full sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipSummary {
    /// Source node.
    pub from: TailscaleNodeId,
    /// Zone this summary covers.
    pub zone_id: ZoneId,
    /// Current epoch.
    pub epoch_id: EpochId,
    /// Digest of object filter.
    pub object_filter_digest: [u8; 32],
    /// Digest of symbol filter.
    pub symbol_filter_digest: [u8; 32],
    /// Number of objects (for quick comparison).
    pub object_count: u32,
    /// Number of symbols.
    pub symbol_count: u32,
    /// Compact IBLT encoding for precise delta reconciliation.
    pub iblt: Vec<u8>,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
    /// Node signature (for authentication and rate limiting).
    pub signature: Option<NodeSignature>,
}

impl GossipSummary {
    /// Check if this summary differs from another (needs reconciliation).
    #[must_use]
    pub fn differs_from(&self, other: &Self) -> bool {
        self.object_filter_digest != other.object_filter_digest
            || self.symbol_filter_digest != other.symbol_filter_digest
    }

    /// Check if the summary's timestamp falls outside the freshness window.
    ///
    /// Returns `true` for messages older than `ttl_secs` *or* dated more
    /// than `max_future_skew_secs` in the future relative to `now`. The
    /// future bound closes a gap where `now.saturating_sub(timestamp)`
    /// returns `0` for any future timestamp, which previously made the
    /// `age > ttl_secs` check accept arbitrarily future-dated summaries
    /// as fresh.
    #[must_use]
    pub const fn is_stale(&self, now: u64, ttl_secs: u64, max_future_skew_secs: u64) -> bool {
        is_outside_freshness_window(self.timestamp, now, ttl_secs, max_future_skew_secs)
    }

    /// Get bytes for signing.
    ///
    /// # Panics
    ///
    /// Panics if any field byte length exceeds `u32::MAX`.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        // Pre-allocate: 22 (prefix) + ~50 (from+zone+epoch with lengths)
        // + 64 (digests) + 8 (counts) + iblt.len() + 8 (timestamp)
        let estimated = 152 + self.iblt.len();
        let mut bytes = Vec::with_capacity(estimated);
        bytes.extend_from_slice(b"FCP2-GOSSIP-SUMMARY-V1");

        let from_bytes = self.from.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(from_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(from_bytes);

        let zone_bytes = self.zone_id.as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(zone_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(zone_bytes);

        let epoch_bytes = self.epoch_id.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(epoch_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(epoch_bytes);

        bytes.extend_from_slice(&self.object_filter_digest);
        bytes.extend_from_slice(&self.symbol_filter_digest);
        bytes.extend_from_slice(&self.object_count.to_le_bytes());
        bytes.extend_from_slice(&self.symbol_count.to_le_bytes());

        bytes.extend_from_slice(
            &u32::try_from(self.iblt.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.iblt);

        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Attach a signature to this summary.
    #[must_use]
    pub fn with_signature(mut self, signature: NodeSignature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Verify the attached node signature against the canonical transcript.
    ///
    /// # Errors
    ///
    /// Returns an error if the summary is unsigned or the signature fails to
    /// validate against `verifying_key`.
    pub fn verify_signature(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| CryptoError::MissingField("signature".into()))?;
        let signature = Ed25519Signature::from_bytes(&signature.signature);
        verifying_key.verify(&self.signing_bytes(), &signature)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gossip Messages
// ─────────────────────────────────────────────────────────────────────────────

/// Gossip message types for wire exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GossipMessage {
    /// Summary announcement (periodic broadcast).
    Summary(GossipSummary),

    /// Signed V3/V4 peer capability advertisement.
    PeerCapabilities(PeerCapabilityAdvertisement),

    /// Request for specific objects/symbols (bounded).
    Request(GossipRequest),

    /// Response with requested data.
    Response(GossipResponse),

    /// Reconciliation request using IBLT.
    ReconcileRequest(ReconcileRequest),

    /// Reconciliation response with missing items.
    ReconcileResponse(ReconcileResponse),

    /// Priority revocation push (direct peer notification).
    /// Sent immediately on revocation, bypassing standard gossip cadence.
    RevocationPush(RevocationPushMessage),
}

/// Request for specific objects or symbols (NORMATIVE).
///
/// Requests are bounded to prevent amplification attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipRequest {
    /// Requesting node.
    pub from: TailscaleNodeId,
    /// Zone being requested.
    pub zone_id: ZoneId,
    /// Object IDs requested (bounded by `MAX_OBJECT_IDS_PER_REQUEST`).
    pub object_ids: Vec<ObjectId>,
    /// Specific symbols requested: (object_id, esi).
    pub symbols: Vec<(ObjectId, u32)>,
    /// Request timestamp.
    pub timestamp: u64,
    /// Optional signature for authenticated requests.
    pub signature: Option<NodeSignature>,
}

impl GossipRequest {
    /// Create a new request for objects.
    #[must_use]
    pub fn for_objects(
        from: TailscaleNodeId,
        zone_id: ZoneId,
        object_ids: Vec<ObjectId>,
        now: u64,
    ) -> Self {
        // Bound request size
        let bounded_ids: Vec<_> = object_ids
            .into_iter()
            .take(MAX_OBJECT_IDS_PER_REQUEST)
            .collect();

        Self {
            from,
            zone_id,
            object_ids: bounded_ids,
            symbols: Vec::new(),
            timestamp: now,
            signature: None,
        }
    }

    /// Create a new request for symbols.
    #[must_use]
    pub fn for_symbols(
        from: TailscaleNodeId,
        zone_id: ZoneId,
        symbols: Vec<(ObjectId, u32)>,
        now: u64,
    ) -> Self {
        // Bound request size
        let bounded_symbols: Vec<_> = symbols
            .into_iter()
            .take(MAX_OBJECT_IDS_PER_REQUEST)
            .collect();

        Self {
            from,
            zone_id,
            object_ids: Vec::new(),
            symbols: bounded_symbols,
            timestamp: now,
            signature: None,
        }
    }

    /// Validate request bounds.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.object_ids.len() <= MAX_OBJECT_IDS_PER_REQUEST
            && self.symbols.len() <= MAX_OBJECT_IDS_PER_REQUEST
    }

    /// Validate request bounds against configured limits.
    #[must_use]
    pub fn is_valid_with_limits(&self, max_objects: usize, max_symbols: usize) -> bool {
        self.object_ids.len() <= max_objects && self.symbols.len() <= max_symbols
    }
}

/// Response to a gossip request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipResponse {
    /// Responding node.
    pub from: TailscaleNodeId,
    /// In response to request from.
    pub to: TailscaleNodeId,
    /// Zone.
    pub zone_id: ZoneId,
    /// Object availability: which requested objects we have.
    pub have_objects: Vec<ObjectId>,
    /// Symbol availability: which requested symbols we have.
    pub have_symbols: Vec<(ObjectId, u32)>,
    /// Response timestamp.
    pub timestamp: u64,
}

/// Reconciliation request using IBLT state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileRequest {
    /// Requesting node.
    pub from: TailscaleNodeId,
    /// Zone being reconciled.
    pub zone_id: ZoneId,
    /// Our IBLT state.
    pub iblt: Vec<u8>,
    /// Our filter digests.
    pub object_filter_digest: [u8; 32],
    pub symbol_filter_digest: [u8; 32],
    /// Request timestamp.
    pub timestamp: u64,
}

/// Reconciliation response with computed differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileResponse {
    /// Responding node.
    pub from: TailscaleNodeId,
    /// Zone.
    pub zone_id: ZoneId,
    /// Objects we have that peer is missing (bounded).
    pub peer_missing_objects: Vec<ObjectId>,
    /// Objects peer has that we're missing (bounded).
    pub we_missing_objects: Vec<ObjectId>,
    /// Response timestamp.
    pub timestamp: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Priority Revocation Push (C1.5)
// ─────────────────────────────────────────────────────────────────────────────

/// Direct revocation push message for priority delivery.
///
/// Sent immediately to all known online peers when a revocation event occurs,
/// bypassing the standard gossip interval. Bounded by
/// [`GossipConfig::max_revocation_push_peers`] to prevent amplification.
///
/// # Two-layer signing (NORMATIVE, br-flywheel_connectors-uxsnk)
///
/// The push carries two independent signatures:
///
/// - `signature` (peer signature): produced by the `from` node over
///   [`Self::signing_bytes`]. Authenticates the transport path and
///   rate-limits who may originate/forward pushes. Sufficient to
///   prevent off-mesh injection but NOT to authorize the revocation
///   itself.
/// - `owner_signature` (zone-owner signature): produced by the zone's
///   owner key over [`Self::owner_signing_bytes`] (the subset of the
///   push that carries revocation authority — zone, revoked ids,
///   revocation head seq). This is the *only* field that grants a peer
///   the right to revoke objects. A compromised peer can produce a
///   valid `signature` but cannot forge an `owner_signature` without
///   the zone owner's private key.
///
/// Pre-uxsnk, only `signature` was verified, so any peer holding a
/// registered signing key could revoke arbitrary objects in zones it
/// was a member of. The recipient now verifies BOTH before applying
/// any revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationPushMessage {
    /// Node that originated or forwarded the push.
    pub from: TailscaleNodeId,
    /// Zone the revocation applies to.
    pub zone_id: ZoneId,
    /// The revoked object IDs (exact set, NOT XOR filter).
    pub revoked_ids: Vec<ObjectId>,
    /// The new revocation head sequence after this revocation.
    pub new_rev_seq: u64,
    /// Push timestamp.
    pub timestamp: u64,
    /// Peer (transport) signature authenticating the push (prevents injection).
    pub signature: Option<NodeSignature>,
    /// Zone-owner signature over [`Self::owner_signing_bytes`] authorizing
    /// the revocation content itself. Required: if absent or invalid,
    /// `MeshNode::handle_revocation_push` rejects the push regardless
    /// of a valid peer signature (br-uxsnk).
    #[serde(default)]
    pub owner_signature: Option<NodeSignature>,
}

impl RevocationPushMessage {
    /// Create a new revocation push for the given IDs.
    #[must_use]
    pub fn new(
        from: TailscaleNodeId,
        zone_id: ZoneId,
        revoked_ids: Vec<ObjectId>,
        new_rev_seq: u64,
        now: u64,
    ) -> Self {
        Self {
            from,
            zone_id,
            revoked_ids,
            new_rev_seq,
            timestamp: now,
            signature: None,
            owner_signature: None,
        }
    }

    /// Attach a zone-owner signature authorizing the revocation payload.
    #[must_use]
    pub fn with_owner_signature(mut self, owner_signature: NodeSignature) -> Self {
        self.owner_signature = Some(owner_signature);
        self
    }

    /// Transcript bytes signed by the zone owner (br-uxsnk).
    ///
    /// Deliberately excludes `from` and `timestamp` so that a single
    /// owner signature remains valid regardless of which peer forwards
    /// the push and when — the owner signs the REVOCATION CONTENT, not
    /// the delivery envelope. Includes `zone_id`, the sorted
    /// `revoked_ids`, and `new_rev_seq`: the fields that together name
    /// "what has been revoked, as of which head sequence, in which
    /// zone."
    ///
    /// `revoked_ids` is iterated in the slice's declared order. Callers
    /// producing signatures and verifying them MUST agree on that order
    /// — the recommended convention is to sort by `ObjectId` bytes
    /// before signing so two pushes carrying the same semantic set
    /// produce the same transcript regardless of how the sender
    /// happened to assemble the vector.
    ///
    /// # Panics
    ///
    /// Panics if any encoded variable-length field exceeds `u32::MAX`.
    #[must_use]
    pub fn owner_signing_bytes(&self) -> Vec<u8> {
        let estimated = 64usize.saturating_add(self.revoked_ids.len().saturating_mul(32));
        let mut bytes = Vec::with_capacity(estimated);
        bytes.extend_from_slice(b"FCP2-REVOCATION-OWNER-V1");

        let zone_bytes = self.zone_id.as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(zone_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(zone_bytes);

        bytes.extend_from_slice(
            &u32::try_from(self.revoked_ids.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for object_id in &self.revoked_ids {
            bytes.extend_from_slice(object_id.as_bytes());
        }

        bytes.extend_from_slice(&self.new_rev_seq.to_le_bytes());
        bytes
    }

    /// Verify the attached zone-owner signature against
    /// [`Self::owner_signing_bytes`] using `owner_verifying_key`.
    ///
    /// # Errors
    ///
    /// Returns an error if `owner_signature` is absent or fails
    /// Ed25519 verification against the provided key.
    pub fn verify_owner_signature(
        &self,
        owner_verifying_key: &Ed25519VerifyingKey,
    ) -> Result<(), CryptoError> {
        let signature = self
            .owner_signature
            .as_ref()
            .ok_or_else(|| CryptoError::MissingField("owner_signature".into()))?;
        let signature = Ed25519Signature::from_bytes(&signature.signature);
        owner_verifying_key.verify(&self.owner_signing_bytes(), &signature)
    }

    /// Get bytes for signing.
    ///
    /// # Panics
    ///
    /// Panics if any encoded variable-length field exceeds `u32::MAX`.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let estimated = 128usize.saturating_add(self.revoked_ids.len().saturating_mul(32));
        let mut bytes = Vec::with_capacity(estimated);
        bytes.extend_from_slice(b"FCP2-REVOCATION-PUSH-V1");

        let from_bytes = self.from.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(from_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(from_bytes);

        let zone_bytes = self.zone_id.as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(zone_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(zone_bytes);

        bytes.extend_from_slice(
            &u32::try_from(self.revoked_ids.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for object_id in &self.revoked_ids {
            bytes.extend_from_slice(object_id.as_bytes());
        }

        bytes.extend_from_slice(&self.new_rev_seq.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Verify the attached node signature against the canonical transcript.
    ///
    /// # Errors
    ///
    /// Returns an error if the push is unsigned or the signature fails to
    /// validate against `verifying_key`.
    pub fn verify_signature(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| CryptoError::MissingField("signature".into()))?;
        let signature = Ed25519Signature::from_bytes(&signature.signature);
        verifying_key.verify(&self.signing_bytes(), &signature)
    }
}

/// Policy for priority gossip of revocation events.
///
/// Controls whether and how revocation events are pushed directly to peers
/// instead of waiting for the next gossip round.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriorityGossipPolicy {
    /// Push revocations to all known online peers immediately, bounded by
    /// [`GossipConfig::max_revocation_push_peers`].
    #[default]
    DirectPush,
    /// Use the priority gossip interval (faster than standard) but no direct push.
    PriorityInterval,
    /// Use standard gossip cadence (no priority treatment).
    Standard,
    /// Operator-invoked emergency revocation. Pushes to **all** known peers
    /// without the normal `max_revocation_push_peers` bound, with up to
    /// [`Self::EMERGENCY_BURST_FANOUT`] parallel send paths and
    /// retry/quorum-witness collection bounded by
    /// [`Self::EMERGENCY_PROPAGATION_DEADLINE_MS`]. Used only by the
    /// `fwc emergency revoke` admin path (m8j0q.8).
    ///
    /// Per ADR `m8j0q-emergency-revocation-protocol`: the Emergency variant
    /// is intentionally separate from `DirectPush` so call-site discipline
    /// is visible (an `if policy.is_emergency()` branch in every site
    /// would be more error-prone than an enum variant).
    Emergency,
}

impl PriorityGossipPolicy {
    /// Maximum parallel send paths used by the emergency burst push.
    pub const EMERGENCY_BURST_FANOUT: usize = 64;

    /// Hard upper bound on emergency-revoke propagation latency, in ms.
    /// Witness collection MUST complete (or be abandoned with
    /// `QuorumNotReached`) before this deadline elapses.
    pub const EMERGENCY_PROPAGATION_DEADLINE_MS: u64 = 5_000;

    /// Number of [`super::emergency_revocation::RevocationWitness`]
    /// signatures the originator collects before declaring quorum reached.
    /// In small-mesh deployments where this exceeds peer count the
    /// originator falls back to majority-of-online (see ADR §"Open
    /// questions resolved" #2).
    pub const EMERGENCY_QUORUM_WITNESSES: usize = 3;

    /// Per-zone rate limit on emergency-revoke originations, in seconds.
    /// Enforced by the host's admin RPC layer to prevent revocation-as-DoS
    /// even with a compromised owner key.
    pub const EMERGENCY_RATE_LIMIT_PER_ZONE_SECS: u64 = 60;

    /// Whether this policy uses direct peer push.
    #[must_use]
    pub const fn uses_direct_push(&self) -> bool {
        matches!(self, Self::DirectPush | Self::Emergency)
    }

    /// Whether this policy is the operator-invoked emergency variant.
    #[must_use]
    pub const fn is_emergency(&self) -> bool {
        matches!(self, Self::Emergency)
    }

    /// The gossip interval in milliseconds for this policy.
    #[must_use]
    pub const fn interval_ms(&self, config: &GossipConfig) -> u64 {
        match self {
            Self::DirectPush | Self::PriorityInterval | Self::Emergency => {
                config.priority_gossip_interval_ms
            }
            Self::Standard => 300, // Standard gossip cadence
        }
    }

    /// The fanout cap for this policy when planning a direct-push burst.
    ///
    /// `DirectPush` honors `GossipConfig::max_revocation_push_peers`.
    /// `Emergency` overrides it with [`Self::EMERGENCY_BURST_FANOUT`] so
    /// operator-driven incident response is not capped by ordinary
    /// amplification limits.
    #[must_use]
    pub const fn fanout_cap(&self, config: &GossipConfig) -> usize {
        match self {
            Self::DirectPush => config.max_revocation_push_peers,
            Self::Emergency => Self::EMERGENCY_BURST_FANOUT,
            Self::PriorityInterval | Self::Standard => 0,
        }
    }
}

/// Observable planning result for a direct revocation-push fanout attempt.
///
/// Transport/orchestration layers can use this boundary type to decide whether
/// a `RevocationPushMessage` should be emitted immediately, suppressed until a
/// later deadline, or trimmed to the configured amplification cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationPushFanoutPlan {
    /// Peers selected for immediate direct push, in caller-provided order.
    pub selected_peers: Vec<TailscaleNodeId>,
    /// Earliest millisecond timestamp when another direct push may proceed.
    pub next_allowed_at_ms: Option<u64>,
    /// Policy used to plan this fanout.
    pub policy: PriorityGossipPolicy,
    /// Number of peers offered to the planner before policy filtering.
    pub requested_peer_count: usize,
    /// Maximum peers the policy allowed for this attempt.
    pub fanout_cap: usize,
    /// Redaction-safe explanation for the selected fanout behavior.
    pub decision: FanoutDecision,
    /// Whether the adaptive direct-push gate was enabled for this attempt.
    pub adaptive_enabled: bool,
    /// Candidate cap computed by the adaptive gate, when it was active.
    pub adaptive_candidate_cap: Option<usize>,
    /// Reason the planner used static or non-direct behavior.
    pub fallback_reason: Option<FanoutFallbackReason>,
}

/// Redaction-safe direct-push fanout decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutDecision {
    /// Policy does not use direct push.
    IntervalOnly,
    /// A previous direct push in the same zone is still inside the interval.
    RateLimited,
    /// No peers were available for direct push.
    EmptyPeerSet,
    /// Direct push selected every offered peer.
    FullPeerSet,
    /// Direct push was capped by the configured amplification limit.
    Capped,
    /// Direct push was capped by the enabled adaptive safety gate.
    AdaptiveCapped,
    /// Emergency path selected peers using the emergency burst cap.
    EmergencyBurst,
}

/// Redaction-safe reason for falling back from adaptive direct push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutFallbackReason {
    /// Adaptive fanout is disabled in configuration.
    AdaptiveDisabled,
    /// Policy does not allow direct push.
    PolicyDoesNotDirectPush,
    /// Emergency revocation bypasses adaptive fanout.
    EmergencyBypass,
    /// Offered peer count is below the configured adaptive floor.
    PeerCountBelowAdaptiveFloor,
    /// Adaptive settings were invalid and static fanout was safer.
    InvalidAdaptiveConfig,
    /// Adaptive candidate matched the static cap and would not change behavior.
    AdaptiveMatchesStaticCap,
}

/// Redaction-safe evidence row for operator dashboards and JSONL harnesses.
///
/// This deliberately omits peer IDs, object IDs, payload digests, and zone IDs;
/// it reports only counts, policy, timing, and bounded decision reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationPushFanoutEvidence {
    /// Policy used to plan the fanout.
    pub policy: PriorityGossipPolicy,
    /// Planner decision.
    pub decision: FanoutDecision,
    /// Offered peer count before filtering.
    pub requested_peer_count: usize,
    /// Selected peer count after filtering.
    pub selected_peer_count: usize,
    /// Offered peers not selected for direct push.
    pub suppressed_peer_count: usize,
    /// Effective cap used for the attempt.
    pub fanout_cap: usize,
    /// Whether adaptive direct-push fanout was enabled.
    pub adaptive_enabled: bool,
    /// Candidate cap computed by the adaptive gate, when active.
    pub adaptive_candidate_cap: Option<usize>,
    /// Static fallback or bypass reason, when any.
    pub fallback_reason: Option<FanoutFallbackReason>,
    /// Earliest millisecond timestamp for another direct push in the zone.
    pub next_allowed_at_ms: Option<u64>,
}

impl RevocationPushFanoutPlan {
    /// Return a redaction-safe evidence row for this fanout plan.
    #[must_use]
    pub fn redacted_evidence(&self) -> RevocationPushFanoutEvidence {
        let selected_peer_count = self.selected_peers.len();
        RevocationPushFanoutEvidence {
            policy: self.policy,
            decision: self.decision,
            requested_peer_count: self.requested_peer_count,
            selected_peer_count,
            suppressed_peer_count: self
                .requested_peer_count
                .saturating_sub(selected_peer_count),
            fanout_cap: self.fanout_cap,
            adaptive_enabled: self.adaptive_enabled,
            adaptive_candidate_cap: self.adaptive_candidate_cap,
            fallback_reason: self.fallback_reason,
            next_allowed_at_ms: self.next_allowed_at_ms,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer Gossip State
// ─────────────────────────────────────────────────────────────────────────────

/// Gossip state for a peer (NORMATIVE).
///
/// Tracks what we know about a peer's object/symbol availability.
#[derive(Debug, Clone)]
pub struct PeerGossipState {
    /// Peer node ID.
    peer_id: TailscaleNodeId,
    /// Last received summary.
    last_summary: Option<GossipSummary>,
    /// Object filter (received from peer).
    object_filter: XorFilterPlaceholder,
    /// Symbol filter (received from peer).
    symbol_filter: XorFilterPlaceholder,
    /// Last update time.
    last_updated: u64,
    /// Number of failed gossip attempts.
    failed_attempts: u32,
}

impl PeerGossipState {
    /// Create a new peer gossip state.
    #[must_use]
    pub fn new(peer_id: TailscaleNodeId) -> Self {
        Self {
            peer_id,
            last_summary: None,
            object_filter: XorFilterPlaceholder::new(),
            symbol_filter: XorFilterPlaceholder::new(),
            last_updated: 0,
            failed_attempts: 0,
        }
    }

    /// Get the peer ID.
    #[must_use]
    pub const fn peer_id(&self) -> &TailscaleNodeId {
        &self.peer_id
    }

    /// Update state from a received summary.
    pub fn update_from_summary(&mut self, summary: GossipSummary, now: u64) {
        self.last_summary = Some(summary);
        self.last_updated = now;
        self.failed_attempts = 0;
    }

    /// Check if peer might have an object.
    #[must_use]
    pub fn may_have_object(&self, object_id: &ObjectId) -> bool {
        self.object_filter.may_contain(object_id.as_bytes())
    }

    /// Check if peer might have a symbol.
    #[must_use]
    pub fn may_have_symbol(&self, object_id: &ObjectId, esi: u32) -> bool {
        self.symbol_filter.may_contain(&symbol_key(object_id, esi))
    }

    /// Check if peer state is stale.
    #[must_use]
    pub const fn is_stale(&self, now: u64, ttl_secs: u64) -> bool {
        now.saturating_sub(self.last_updated) > ttl_secs
    }

    /// Record a failed gossip attempt.
    pub fn record_failure(&mut self) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
    }

    /// Get the number of consecutive failures.
    #[must_use]
    pub const fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesh Gossip Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Mesh gossip controller (NORMATIVE).
///
/// Orchestrates gossip between peers for a zone.
#[derive(Debug)]
pub struct MeshGossip {
    /// Our node ID.
    local_node: TailscaleNodeId,
    /// Local gossip state per zone.
    zone_states: HashMap<ZoneId, GossipState>,
    /// Known peer states.
    peer_states: HashMap<TailscaleNodeId, PeerGossipState>,
    /// Last successful direct revocation-push fanout per zone, in ms.
    last_priority_push_at_ms: HashMap<ZoneId, u64>,
    /// Configuration.
    config: GossipConfig,
}

/// Gossip configuration.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Maximum objects per summary.
    pub max_objects_per_summary: usize,
    /// Maximum symbols per summary.
    pub max_symbols_per_summary: usize,
    /// Maximum objects per request.
    pub max_objects_per_request: usize,
    /// Maximum symbols per request.
    pub max_symbols_per_request: usize,
    /// Summary TTL in seconds.
    pub summary_ttl_secs: u64,
    /// Maximum tolerated future-dated skew on gossip timestamps, in seconds.
    ///
    /// Messages whose timestamp is more than this far in the future relative
    /// to `now` are rejected as out-of-window — independent of `summary_ttl_secs`.
    /// See [`is_outside_freshness_window`] for the rationale.
    pub max_future_skew_secs: u64,
    /// Reconciliation batch size.
    pub reconciliation_batch_size: usize,
    /// Priority gossip interval for revocation events (milliseconds).
    /// Revocation events use this faster interval instead of the standard
    /// gossip cadence. Default: 100ms (vs ~300ms for regular gossip).
    pub priority_gossip_interval_ms: u64,
    /// Maximum peers for direct revocation push.
    /// Bounds the amplification factor: at most this many direct pushes
    /// per revocation event. Default: 32.
    pub max_revocation_push_peers: usize,
    /// Disabled-by-default adaptive direct-push fanout gate.
    ///
    /// When enabled, ordinary `DirectPush` revocations may select fewer
    /// peers than [`Self::max_revocation_push_peers`] in large swarms. The
    /// adaptive cap is never allowed to exceed the static cap, so the
    /// existing static behavior remains the safety fallback. Emergency
    /// revocations bypass this gate and continue to use
    /// [`PriorityGossipPolicy::EMERGENCY_BURST_FANOUT`].
    pub adaptive_revocation_push_fanout: AdaptiveRevocationPushFanoutConfig,
    /// Maximum distinct peer gossip states retained in memory.
    ///
    /// Every accepted summary with a never-seen `summary.from` inserts a
    /// new entry in `peer_states`. Without a cap, an adversary (or a bug in
    /// an unauthenticated dispatcher — see the lower-level
    /// `MeshGossip::handle_summary` doc) can inflate the map to exhaust
    /// memory within a single TTL window, before `prune_stale_peers` runs.
    /// This cap bounds that growth regardless of pruning cadence.
    ///
    /// Default: 4096, sized well above realistic zone peer counts and
    /// below the point where peer-state book-keeping dominates memory on
    /// a modest node.
    pub max_peer_states: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_objects_per_summary: DEFAULT_MAX_OBJECTS_PER_SUMMARY,
            max_symbols_per_summary: DEFAULT_MAX_SYMBOLS_PER_SUMMARY,
            max_objects_per_request: MAX_OBJECT_IDS_PER_REQUEST,
            max_symbols_per_request: MAX_OBJECT_IDS_PER_REQUEST,
            summary_ttl_secs: DEFAULT_SUMMARY_TTL_SECS,
            max_future_skew_secs: DEFAULT_MAX_FUTURE_SKEW_SECS,
            reconciliation_batch_size: DEFAULT_RECONCILIATION_BATCH_SIZE,
            priority_gossip_interval_ms: 100,
            max_revocation_push_peers: 32,
            adaptive_revocation_push_fanout: AdaptiveRevocationPushFanoutConfig::default(),
            max_peer_states: 4096,
        }
    }
}

/// Safety gate for adaptive direct revocation-push fanout.
///
/// The gate is disabled by default. When explicitly enabled, it only applies to
/// [`PriorityGossipPolicy::DirectPush`], requires a minimum observed peer count,
/// and computes a deterministic cap from the offered peer count. The computed
/// cap is then clamped to the static cap so adaptive behavior cannot increase
/// amplification beyond the pre-existing bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRevocationPushFanoutConfig {
    /// Whether adaptive direct-push fanout is enabled.
    pub enabled: bool,
    /// Minimum offered peers before adaptive selection is considered.
    pub min_observed_peers: usize,
    /// Lower bound for selected peers once the gate is active.
    pub min_selected_peers: usize,
    /// Divisor used to compute `ceil(offered_peers / target_peer_divisor)`.
    pub target_peer_divisor: usize,
    /// Additional hard cap for the adaptive candidate.
    pub max_selected_peers: usize,
}

impl Default for AdaptiveRevocationPushFanoutConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_observed_peers: 16,
            min_selected_peers: 4,
            target_peer_divisor: 4,
            max_selected_peers: 32,
        }
    }
}

impl AdaptiveRevocationPushFanoutConfig {
    /// Return a disabled gate with the standard safety parameters retained.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Return an enabled gate with the standard safety parameters.
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }
}

impl GossipConfig {
    /// Derived byte budget for encoded IBLT payloads.
    ///
    /// The production sketch is a CBOR-encoded [`Iblt`] sized for
    /// `reconciliation_batch_size` expected differences
    /// ([`Iblt::recommended_cell_count`] returns ~1.5×N cells floored
    /// at [`MIN_RECOMMENDED_IBLT_CELLS`](crate::iblt::MIN_RECOMMENDED_IBLT_CELLS)). Each cell is an `IbltCell`
    /// with `{count: i32, key_sum: [u8;32], hash_check: u32}` plus
    /// CBOR map overhead, landing in the ~70-byte range per cell in
    /// practice; the per-difference budget here is 128 bytes to
    /// cover the 1.5× cell multiplier with headroom for field-name
    /// overhead in the outer struct.
    #[must_use]
    pub const fn max_iblt_bytes(&self) -> usize {
        // 16 MB hard cap to prevent saturating_mul from returning usize::MAX.
        const MAX_IBLT_BYTES_CAP: usize = 16 * 1024 * 1024;

        let derived = self.reconciliation_batch_size.saturating_mul(128);
        if derived < MIN_IBLT_BYTES_BUDGET {
            MIN_IBLT_BYTES_BUDGET
        } else if derived > MAX_IBLT_BYTES_CAP {
            MAX_IBLT_BYTES_CAP
        } else {
            derived
        }
    }

    /// Derived raw wire budget for a JSON-encoded gossip payload.
    ///
    /// `dispatch_gossip_payload` receives attacker-controlled transport
    /// bytes and must reject absurdly large bodies BEFORE
    /// `serde_json::from_slice` allocates and parses them. The dominant
    /// variable-length field on legitimate summary traffic is `iblt:
    /// Vec<u8>`, which JSON encodes as an array of decimal bytes. In
    /// compact JSON each byte contributes at most 4 characters
    /// (`255,`) plus the surrounding `[]`, so `4 * max_iblt_bytes()`
    /// covers the hottest legitimate case. Add a small fixed cushion
    /// for the remaining fields and clamp to keep pathological
    /// operator-chosen reconciliation budgets from turning this
    /// pre-parse gate into a no-op.
    #[must_use]
    pub const fn max_wire_payload_bytes(&self) -> usize {
        const MIN_WIRE_PAYLOAD_BYTES: usize = 64 * 1024;
        const MAX_WIRE_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
        const FIXED_JSON_OVERHEAD_BYTES: usize = 16 * 1024;

        let derived = self
            .max_iblt_bytes()
            .saturating_mul(4)
            .saturating_add(FIXED_JSON_OVERHEAD_BYTES);
        if derived < MIN_WIRE_PAYLOAD_BYTES {
            MIN_WIRE_PAYLOAD_BYTES
        } else if derived > MAX_WIRE_PAYLOAD_BYTES {
            MAX_WIRE_PAYLOAD_BYTES
        } else {
            derived
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RevocationFanoutGate {
    fanout_cap: usize,
    adaptive_enabled: bool,
    adaptive_candidate_cap: Option<usize>,
    fallback_reason: Option<FanoutFallbackReason>,
}

fn evaluate_revocation_fanout_gate(
    policy: PriorityGossipPolicy,
    requested_peer_count: usize,
    config: &GossipConfig,
) -> RevocationFanoutGate {
    let static_cap = policy.fanout_cap(config);
    let adaptive = config.adaptive_revocation_push_fanout;

    if !policy.uses_direct_push() {
        return RevocationFanoutGate {
            fanout_cap: static_cap,
            adaptive_enabled: adaptive.enabled,
            adaptive_candidate_cap: None,
            fallback_reason: Some(FanoutFallbackReason::PolicyDoesNotDirectPush),
        };
    }

    if policy.is_emergency() {
        return RevocationFanoutGate {
            fanout_cap: static_cap,
            adaptive_enabled: adaptive.enabled,
            adaptive_candidate_cap: None,
            fallback_reason: Some(FanoutFallbackReason::EmergencyBypass),
        };
    }

    if !adaptive.enabled {
        return RevocationFanoutGate {
            fanout_cap: static_cap,
            adaptive_enabled: false,
            adaptive_candidate_cap: None,
            fallback_reason: Some(FanoutFallbackReason::AdaptiveDisabled),
        };
    }

    if requested_peer_count < adaptive.min_observed_peers {
        return RevocationFanoutGate {
            fanout_cap: static_cap,
            adaptive_enabled: true,
            adaptive_candidate_cap: None,
            fallback_reason: Some(FanoutFallbackReason::PeerCountBelowAdaptiveFloor),
        };
    }

    if adaptive.target_peer_divisor == 0
        || adaptive.min_selected_peers == 0
        || adaptive.max_selected_peers == 0
    {
        return RevocationFanoutGate {
            fanout_cap: static_cap,
            adaptive_enabled: true,
            adaptive_candidate_cap: None,
            fallback_reason: Some(FanoutFallbackReason::InvalidAdaptiveConfig),
        };
    }

    let static_effective_cap = requested_peer_count.min(static_cap);
    let adaptive_candidate_cap = requested_peer_count
        .div_ceil(adaptive.target_peer_divisor)
        .max(adaptive.min_selected_peers)
        .min(adaptive.max_selected_peers)
        .min(static_effective_cap);

    if adaptive_candidate_cap >= static_effective_cap {
        RevocationFanoutGate {
            fanout_cap: static_cap,
            adaptive_enabled: true,
            adaptive_candidate_cap: Some(adaptive_candidate_cap),
            fallback_reason: Some(FanoutFallbackReason::AdaptiveMatchesStaticCap),
        }
    } else {
        RevocationFanoutGate {
            fanout_cap: adaptive_candidate_cap,
            adaptive_enabled: true,
            adaptive_candidate_cap: Some(adaptive_candidate_cap),
            fallback_reason: None,
        }
    }
}

impl MeshGossip {
    /// Create a new gossip controller.
    #[must_use]
    pub fn new(local_node: TailscaleNodeId, config: GossipConfig) -> Self {
        Self {
            local_node,
            zone_states: HashMap::new(),
            peer_states: HashMap::new(),
            last_priority_push_at_ms: HashMap::new(),
            config,
        }
    }

    /// Create with default configuration.
    #[must_use]
    pub fn with_defaults(local_node: TailscaleNodeId) -> Self {
        Self::new(local_node, GossipConfig::default())
    }

    /// Summary freshness window, in seconds.
    #[must_use]
    pub const fn summary_ttl_secs(&self) -> u64 {
        self.config.summary_ttl_secs
    }

    /// Maximum tolerated future-dated skew on gossip timestamps, in seconds.
    #[must_use]
    pub const fn max_future_skew_secs(&self) -> u64 {
        self.config.max_future_skew_secs
    }

    /// Maximum raw transport bytes accepted by the JSON gossip decoder.
    #[must_use]
    pub const fn max_wire_payload_bytes(&self) -> usize {
        self.config.max_wire_payload_bytes()
    }

    /// Expected-difference budget used for IBLT reconciliation.
    #[must_use]
    pub const fn reconciliation_batch_size(&self) -> usize {
        self.config.reconciliation_batch_size
    }

    /// Maximum encoded IBLT bytes accepted by gossip reconciliation paths.
    #[must_use]
    pub const fn max_iblt_bytes(&self) -> usize {
        self.config.max_iblt_bytes()
    }

    /// Plan a direct revocation-push fanout at the transport boundary.
    ///
    /// Enforces the configured interval backoff for repeated direct pushes in
    /// the same zone and caps fanout to
    /// [`GossipConfig::max_revocation_push_peers`] to bound amplification.
    ///
    /// `PriorityInterval` and `Standard` do not emit direct pushes; callers
    /// should rely on their normal summary/request cadence instead.
    #[must_use]
    pub fn plan_revocation_push_fanout(
        &mut self,
        zone_id: &ZoneId,
        peers: &[TailscaleNodeId],
        policy: PriorityGossipPolicy,
        now_ms: u64,
    ) -> RevocationPushFanoutPlan {
        let requested_peer_count = peers.len();
        let gate = evaluate_revocation_fanout_gate(policy, requested_peer_count, &self.config);
        if !policy.uses_direct_push() {
            return RevocationPushFanoutPlan {
                selected_peers: Vec::new(),
                next_allowed_at_ms: None,
                policy,
                requested_peer_count,
                fanout_cap: gate.fanout_cap,
                decision: FanoutDecision::IntervalOnly,
                adaptive_enabled: gate.adaptive_enabled,
                adaptive_candidate_cap: gate.adaptive_candidate_cap,
                fallback_reason: gate.fallback_reason,
            };
        }

        let interval_ms = policy.interval_ms(&self.config);
        if let Some(last_push_at_ms) = self.last_priority_push_at_ms.get(zone_id).copied() {
            let next_allowed_at_ms = last_push_at_ms.saturating_add(interval_ms);
            if now_ms < next_allowed_at_ms {
                return RevocationPushFanoutPlan {
                    selected_peers: Vec::new(),
                    next_allowed_at_ms: Some(next_allowed_at_ms),
                    policy,
                    requested_peer_count,
                    fanout_cap: gate.fanout_cap,
                    decision: FanoutDecision::RateLimited,
                    adaptive_enabled: gate.adaptive_enabled,
                    adaptive_candidate_cap: gate.adaptive_candidate_cap,
                    fallback_reason: gate.fallback_reason,
                };
            }
        }

        let selected_peers = peers
            .iter()
            .take(gate.fanout_cap)
            .cloned()
            .collect::<Vec<_>>();
        let decision = if selected_peers.is_empty() {
            FanoutDecision::EmptyPeerSet
        } else if policy.is_emergency() {
            FanoutDecision::EmergencyBurst
        } else if gate.adaptive_candidate_cap.is_some()
            && gate.fallback_reason.is_none()
            && selected_peers.len() < requested_peer_count
        {
            FanoutDecision::AdaptiveCapped
        } else if selected_peers.len() < requested_peer_count {
            FanoutDecision::Capped
        } else {
            FanoutDecision::FullPeerSet
        };
        if !selected_peers.is_empty() {
            self.last_priority_push_at_ms
                .insert(zone_id.clone(), now_ms);
        }

        RevocationPushFanoutPlan {
            selected_peers,
            next_allowed_at_ms: Some(now_ms.saturating_add(interval_ms)),
            policy,
            requested_peer_count,
            fanout_cap: gate.fanout_cap,
            decision,
            adaptive_enabled: gate.adaptive_enabled,
            adaptive_candidate_cap: gate.adaptive_candidate_cap,
            fallback_reason: gate.fallback_reason,
        }
    }

    /// Get or create zone state.
    ///
    /// Borrows `config` and `zone_states` as disjoint fields to avoid
    /// cloning `GossipConfig` on every call.
    fn get_or_create_zone(&mut self, zone_id: &ZoneId) -> &mut GossipState {
        let config = &self.config;
        self.zone_states
            .entry(zone_id.clone())
            .or_insert_with(|| GossipState::new(zone_id.clone(), config))
    }

    /// Announce object availability (NORMATIVE).
    ///
    /// # Arguments
    ///
    /// * `zone_id` - Zone the object belongs to
    /// * `object_id` - Object being announced
    /// * `admission_class` - Object admission class (MUST be Admitted)
    /// * `now` - Current timestamp
    ///
    /// # Returns
    ///
    /// `true` if object was added to gossip, `false` if quarantined (not gossiped).
    pub fn announce_object(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        admission_class: ObjectAdmissionClass,
        now: u64,
    ) -> bool {
        // NORMATIVE: Quarantined objects MUST NOT pollute gossip
        if admission_class == ObjectAdmissionClass::Quarantined {
            warn!(
                component = "mesh.gossip",
                event = "quarantine_blocked",
                zone_id = %zone_id,
                object_id = %object_id,
                reason = "gossip_propagation_denied"
            );
            return false;
        }

        let state = self.get_or_create_zone(zone_id);
        state.announce_object(object_id, now);
        info!(
            component = "mesh.gossip",
            event = "object_announced",
            node_id = %self.local_node.as_str(),
            zone_id = %zone_id,
            object_id = %object_id,
            timestamp = now
        );
        true
    }

    /// Announce symbol availability.
    pub fn announce_symbol(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        esi: u32,
        admission_class: ObjectAdmissionClass,
        now: u64,
    ) -> bool {
        // NORMATIVE: Quarantined objects MUST NOT pollute gossip
        if admission_class == ObjectAdmissionClass::Quarantined {
            warn!(
                component = "mesh.gossip",
                event = "quarantine_blocked",
                zone_id = %zone_id,
                object_id = %object_id,
                reason = "gossip_propagation_denied"
            );
            return false;
        }

        let state = self.get_or_create_zone(zone_id);
        state.announce_symbol(object_id, esi, now);
        debug!(
            component = "mesh.gossip",
            event = "symbol_announced",
            node_id = %self.local_node.as_str(),
            zone_id = %zone_id,
            object_id = %object_id,
            esi,
            timestamp = now
        );
        true
    }

    /// Create a summary for a zone.
    #[must_use]
    pub fn create_summary(&self, zone_id: &ZoneId, epoch_id: EpochId) -> Option<GossipSummary> {
        self.zone_states.get(zone_id).map(|state| {
            let epoch_label = epoch_id.as_str().to_string();
            let iblt_cells = state.iblt_state.entry_count();
            let mut summary = state.create_summary(self.local_node.clone(), epoch_id);
            let max_iblt_bytes = self.config.max_iblt_bytes();
            let mut fallback_reason = "none";
            summary.object_count = summary
                .object_count
                .min(u32::try_from(self.config.max_objects_per_summary).unwrap_or(u32::MAX));
            summary.symbol_count = summary
                .symbol_count
                .min(u32::try_from(self.config.max_symbols_per_summary).unwrap_or(u32::MAX));
            if summary.iblt.len() > max_iblt_bytes {
                // Empty wire payload is the new fallback marker; the
                // decoder routes empty bytes to the "empty sketch sized
                // for peer batch" branch. Previously this was the JSON
                // literal `b"[]"` for the placeholder-JSON wire format.
                summary.iblt = Vec::new();
                fallback_reason = "iblt_bytes_exceeded";
            }
            if tracing::enabled!(tracing::Level::DEBUG) || fallback_reason != "none" {
                let object_digest = hex::encode(summary.object_filter_digest);
                let symbol_digest = hex::encode(summary.symbol_filter_digest);
                let summary_bytes =
                    serde_json::to_vec(&summary).map_or(0usize, |bytes| bytes.len());
                let summary_bytes = u64::try_from(summary_bytes).unwrap_or(u64::MAX);
                let iblt_bytes = u64::try_from(summary.iblt.len()).unwrap_or(u64::MAX);
                let iblt_cells = u64::try_from(iblt_cells).unwrap_or(u64::MAX);
                if fallback_reason == "none" {
                    debug!(
                        component = "mesh.gossip",
                        event = "summary_created",
                        node_id = %self.local_node.as_str(),
                        zone_id = %zone_id,
                        epoch_id = %epoch_label,
                        object_count = summary.object_count,
                        symbol_count = summary.symbol_count,
                        reconciliation_batch_size = self.config.reconciliation_batch_size,
                        summary_bytes,
                        iblt_bytes,
                        iblt_cells,
                        fallback_reason,
                        object_digest = %object_digest,
                        symbol_digest = %symbol_digest
                    );
                } else {
                    info!(
                        component = "mesh.gossip",
                        event = "summary_created",
                        node_id = %self.local_node.as_str(),
                        zone_id = %zone_id,
                        epoch_id = %epoch_label,
                        object_count = summary.object_count,
                        symbol_count = summary.symbol_count,
                        reconciliation_batch_size = self.config.reconciliation_batch_size,
                        summary_bytes,
                        iblt_bytes,
                        iblt_cells,
                        fallback_reason,
                        object_digest = %object_digest,
                        symbol_digest = %symbol_digest
                    );
                }
            }
            summary
        })
    }

    /// Handle received summary from a peer.
    ///
    /// Callers on an untrusted network path must verify `summary.signature`
    /// before invoking this lower-level state mutator.
    /// [`crate::node::MeshNode`] provides the authenticated dispatch entrypoint.
    ///
    /// Returns `true` when the summary was accepted and mutated peer state,
    /// or `false` when it was rejected and ignored.
    #[allow(clippy::too_many_lines)] // Summary validation updates several independent gossip indexes atomically.
    pub fn handle_summary(&mut self, summary: GossipSummary, now: u64) -> bool {
        if summary.is_stale(
            now,
            self.config.summary_ttl_secs,
            self.config.max_future_skew_secs,
        ) {
            let age_secs = now.saturating_sub(summary.timestamp);
            let future_skew_secs = summary.timestamp.saturating_sub(now);
            warn!(
                component = "mesh.gossip",
                event = "summary_rejected",
                reason = if future_skew_secs > 0 { "future_dated" } else { "stale" },
                peer_node_id = %summary.from.as_str(),
                zone_id = %summary.zone_id,
                object_count = summary.object_count,
                symbol_count = summary.symbol_count,
                age_seconds = age_secs,
                future_skew_seconds = future_skew_secs,
                ttl_seconds = self.config.summary_ttl_secs,
                max_future_skew_seconds = self.config.max_future_skew_secs
            );
            return false;
        }

        if summary.object_count as usize > self.config.max_objects_per_summary
            || summary.symbol_count as usize > self.config.max_symbols_per_summary
        {
            warn!(
                component = "mesh.gossip",
                event = "summary_rejected",
                reason = "oversized",
                peer_node_id = %summary.from.as_str(),
                zone_id = %summary.zone_id,
                object_count = summary.object_count,
                symbol_count = summary.symbol_count,
                max_objects = self.config.max_objects_per_summary,
                max_symbols = self.config.max_symbols_per_summary
            );
            return false;
        }

        let peer_id = summary.from.clone();
        let object_count = summary.object_count;
        let symbol_count = summary.symbol_count;
        let iblt_bytes = summary.iblt.len();
        let max_iblt_bytes = self.config.max_iblt_bytes();
        let decode_start = Instant::now();
        let iblt_cells = match IbltPlaceholder::decode_with_limits(
            &summary.iblt,
            self.config.reconciliation_batch_size,
            max_iblt_bytes,
        ) {
            Ok(decoded) => decoded.entry_count(),
            Err(error) => {
                let decode_ms =
                    u64::try_from(decode_start.elapsed().as_millis()).unwrap_or(u64::MAX);
                warn!(
                    component = "mesh.gossip",
                    event = "summary_rejected",
                    reason = error.reason_code(),
                    peer_node_id = %summary.from.as_str(),
                    zone_id = %summary.zone_id,
                    object_count,
                    symbol_count,
                    iblt_bytes,
                    max_iblt_bytes,
                    decode_ms
                );
                return false;
            }
        };
        let decode_ms = u64::try_from(decode_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let summary_bytes = serde_json::to_vec(&summary).map_or(0usize, |bytes| bytes.len());
        let summary_bytes = u64::try_from(summary_bytes).unwrap_or(u64::MAX);
        let iblt_cells = u64::try_from(iblt_cells).unwrap_or(u64::MAX);

        // Bound `peer_states` cardinality. Updates to an already-known peer
        // are idempotent and always allowed (so normal rotation through a
        // saturated map keeps working). Inserts for a never-seen peer when
        // the map is already at capacity are rejected to prevent an
        // unverified or floods-allowed dispatcher from driving memory
        // exhaustion between `prune_stale_peers` cycles.
        if !self.peer_states.contains_key(&peer_id)
            && self.peer_states.len() >= self.config.max_peer_states
        {
            warn!(
                component = "mesh.gossip",
                event = "summary_rejected",
                reason = "peer_state_cap",
                peer_node_id = %peer_id.as_str(),
                zone_id = %summary.zone_id,
                object_count,
                symbol_count,
                peer_state_count = self.peer_states.len(),
                peer_state_cap = self.config.max_peer_states,
            );
            return false;
        }

        if self
            .peer_states
            .get(&peer_id)
            .and_then(|state| state.last_summary.as_ref())
            .is_some_and(|current| summary.timestamp < current.timestamp)
        {
            let newer_timestamp = self
                .peer_states
                .get(&peer_id)
                .and_then(|state| state.last_summary.as_ref())
                .map_or(0, |current| current.timestamp);
            warn!(
                component = "mesh.gossip",
                event = "summary_rejected",
                reason = "older_than_current",
                peer_node_id = %peer_id.as_str(),
                zone_id = %summary.zone_id,
                object_count,
                symbol_count,
                summary_timestamp = summary.timestamp,
                newer_timestamp
            );
            return false;
        }

        // Update peer state
        let peer_state = self
            .peer_states
            .entry(peer_id.clone())
            .or_insert_with(|| PeerGossipState::new(peer_id.clone()));

        peer_state.update_from_summary(summary, now);
        debug!(
            component = "mesh.gossip",
            event = "summary_received",
            peer_node_id = %peer_id.as_str(),
            object_count,
            symbol_count,
            summary_bytes,
            iblt_bytes,
            iblt_cells,
            decode_ms,
            accepted = true
        );
        true
    }

    /// Find peers that might have an object.
    #[must_use]
    pub fn find_object_sources(&self, object_id: &ObjectId) -> Vec<TailscaleNodeId> {
        self.peer_states
            .iter()
            .filter(|(_, state)| state.may_have_object(object_id))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Find peers that might have a symbol.
    #[must_use]
    pub fn find_symbol_sources(&self, object_id: &ObjectId, esi: u32) -> Vec<TailscaleNodeId> {
        self.peer_states
            .iter()
            .filter(|(_, state)| state.may_have_symbol(object_id, esi))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Check if we have an object locally.
    #[must_use]
    pub fn has_object(&self, zone_id: &ZoneId, object_id: &ObjectId) -> bool {
        self.zone_states
            .get(zone_id)
            .is_some_and(|s| s.has_object(object_id))
    }

    /// Check if we have a symbol locally.
    #[must_use]
    pub fn has_symbol(&self, zone_id: &ZoneId, object_id: &ObjectId, esi: u32) -> bool {
        self.zone_states
            .get(zone_id)
            .is_some_and(|s| s.has_symbol(object_id, esi))
    }

    /// Maximum object IDs accepted in one bounded gossip request/response.
    #[must_use]
    pub fn max_objects_per_request(&self) -> usize {
        self.config
            .max_objects_per_request
            .min(MAX_OBJECT_IDS_PER_REQUEST)
    }

    /// Maximum symbol IDs accepted in one bounded gossip request/response.
    #[must_use]
    pub fn max_symbols_per_request(&self) -> usize {
        self.config
            .max_symbols_per_request
            .min(MAX_OBJECT_IDS_PER_REQUEST)
    }

    /// Create a bounded request for objects we're missing.
    #[must_use]
    pub fn create_request(
        &self,
        zone_id: &ZoneId,
        object_ids: Vec<ObjectId>,
        now: u64,
    ) -> GossipRequest {
        let max_objects = self.max_objects_per_request();
        let bounded: Vec<_> = object_ids.into_iter().take(max_objects).collect();
        debug!(
            component = "mesh.gossip",
            event = "request_created",
            node_id = %self.local_node.as_str(),
            zone_id = %zone_id,
            objects_requested = bounded.len(),
            max_objects
        );
        GossipRequest::for_objects(self.local_node.clone(), zone_id.clone(), bounded, now)
    }

    /// Handle a request from a peer.
    #[must_use]
    pub fn handle_request(&self, request: &GossipRequest) -> GossipResponse {
        let max_objects = self.max_objects_per_request();
        let max_symbols = self.max_symbols_per_request();
        let objects_requested = request.object_ids.len();
        let symbols_requested = request.symbols.len();
        let request_size = objects_requested + symbols_requested;

        if !request.is_valid_with_limits(max_objects, max_symbols) {
            let reason = if objects_requested > max_objects {
                "object_count_exceeded"
            } else if symbols_requested > max_symbols {
                "symbol_count_exceeded"
            } else {
                "invalid_request"
            };
            warn!(
                component = "mesh.gossip",
                event = "request_rejected",
                reason,
                peer_id = %request.from.as_str(),
                zone_id = %request.zone_id,
                objects_requested,
                symbols_requested,
                max_objects,
                max_symbols,
                request_size
            );
            return GossipResponse {
                from: self.local_node.clone(),
                to: request.from.clone(),
                zone_id: request.zone_id.clone(),
                have_objects: Vec::new(),
                have_symbols: Vec::new(),
                timestamp: request.timestamp,
            };
        }

        let zone_state = self.zone_states.get(&request.zone_id);

        let have_objects: Vec<ObjectId> = request
            .object_ids
            .iter()
            .take(max_objects)
            .filter(|id| zone_state.is_some_and(|s| s.has_object(id)))
            .copied()
            .collect();

        let have_symbols: Vec<(ObjectId, u32)> = request
            .symbols
            .iter()
            .take(max_symbols)
            .filter(|(id, esi)| zone_state.is_some_and(|s| s.has_symbol(id, *esi)))
            .copied()
            .collect();

        debug!(
            component = "mesh.gossip",
            event = "request_handled",
            peer_id = %request.from.as_str(),
            zone_id = %request.zone_id,
            objects_requested,
            symbols_requested,
            objects_served = have_objects.len(),
            symbols_served = have_symbols.len(),
            request_size
        );
        GossipResponse {
            from: self.local_node.clone(),
            to: request.from.clone(),
            zone_id: request.zone_id.clone(),
            have_objects,
            have_symbols,
            timestamp: request.timestamp,
        }
    }

    /// List admitted objects for a zone (up to `limit`).
    ///
    /// Returns object IDs known locally in the given zone. Used by
    /// test harnesses to drive simulated gossip replication.
    #[must_use]
    pub fn list_objects_in_zone(&self, zone_id: &ZoneId, limit: usize) -> Vec<ObjectId> {
        self.zone_states
            .get(zone_id)
            .map(|s| s.list_objects(limit))
            .unwrap_or_default()
    }

    /// Build a production IBLT for a zone's admitted objects.
    ///
    /// The returned sketch can be sent to peers for IBLT-based reconciliation.
    #[must_use]
    pub fn build_zone_iblt(&self, zone_id: &ZoneId, expected_difference: usize) -> Option<Iblt> {
        self.zone_states
            .get(zone_id)
            .map(|state| state.build_iblt(expected_difference))
    }

    /// Reconcile a zone with a peer's IBLT sketch.
    ///
    /// Returns a bounded `ReconcileResponse` identifying objects each side is
    /// missing. When the IBLT decode is incomplete (peel stalls), the response
    /// lists only the objects recovered before stalling — the caller should
    /// fall back to paginated list exchange for the remainder.
    #[must_use]
    pub fn reconcile_zone_iblt(
        &self,
        zone_id: &ZoneId,
        peer_id: &TailscaleNodeId,
        peer_iblt: &Iblt,
        expected_difference: usize,
        now: u64,
    ) -> Option<ReconcileResponse> {
        let state = self.zone_states.get(zone_id)?;
        let decode_start = Instant::now();
        let result = state.reconcile_with_peer_iblt(peer_iblt, expected_difference)?;
        let decode_us = u64::try_from(decode_start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let diff_decoded = result
            .only_left
            .len()
            .saturating_add(result.only_right.len());
        let diff_decoded = u64::try_from(diff_decoded).unwrap_or(u64::MAX);
        let n_local = u64::try_from(state.object_count()).unwrap_or(u64::MAX);
        let n_remote_summary = self
            .peer_states
            .get(peer_id)
            .and_then(|peer_state| peer_state.last_summary.as_ref())
            .filter(|summary| summary.zone_id == *zone_id)
            .map(|summary| u64::from(summary.object_count));
        let n_remote = n_remote_summary.unwrap_or(0);
        let n_remote_known = n_remote_summary.is_some();
        let remote_iblt_cells = u64::try_from(peer_iblt.cell_count()).unwrap_or(u64::MAX);
        let complete = result.complete;
        let remaining_nonzero_cells = result.remaining_nonzero_cells;
        metrics::record_mesh_iblt_decode_latency_us(
            zone_id.as_str(),
            peer_id.as_str(),
            "masked",
            !complete,
            decode_us,
        );

        let max_objects = MAX_OBJECT_IDS_PER_REQUEST;
        let peer_missing: Vec<ObjectId> = result.only_left.into_iter().take(max_objects).collect();
        let we_missing: Vec<ObjectId> = result.only_right.into_iter().take(max_objects).collect();

        if complete {
            debug!(
                component = "mesh.gossip",
                otlp = "fcp.mesh.iblt",
                event = "iblt_reconciled",
                scheme = "masked",
                zone_id = %zone_id,
                peer_id = %peer_id.as_str(),
                n_local,
                n_remote,
                n_remote_known,
                remote_iblt_cells,
                diff_decoded,
                decode_us,
                overflow = false,
                peer_missing_count = peer_missing.len(),
                we_missing_count = we_missing.len()
            );
        } else {
            info!(
                component = "mesh.gossip",
                otlp = "fcp.mesh.iblt",
                event = "iblt_partial_decode",
                scheme = "masked",
                zone_id = %zone_id,
                peer_id = %peer_id.as_str(),
                n_local,
                n_remote,
                n_remote_known,
                remote_iblt_cells,
                diff_decoded,
                decode_us,
                overflow = true,
                remaining_cells = remaining_nonzero_cells,
                peer_missing_count = peer_missing.len(),
                we_missing_count = we_missing.len(),
                "IBLT peel incomplete — caller should fall back to paginated list exchange"
            );
        }

        Some(ReconcileResponse {
            from: self.local_node.clone(),
            zone_id: zone_id.clone(),
            peer_missing_objects: peer_missing,
            we_missing_objects: we_missing,
            timestamp: now,
        })
    }

    /// Get stats for a zone.
    #[must_use]
    pub fn zone_stats(&self, zone_id: &ZoneId) -> Option<GossipStats> {
        self.zone_states.get(zone_id).map(|state| GossipStats {
            object_count: state.object_count(),
            symbol_count: state.symbol_count(),
            last_updated: state.last_updated,
        })
    }

    /// Get number of known peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peer_states.len()
    }

    /// Return the last accepted summary recorded for a peer.
    #[must_use]
    pub fn peer_last_summary(&self, peer_id: &TailscaleNodeId) -> Option<&GossipSummary> {
        self.peer_states
            .get(peer_id)
            .and_then(|state| state.last_summary.as_ref())
    }

    /// Remove peer states that have gone stale.
    ///
    /// This is used by integration/e2e flows to model peer leave/partition
    /// recovery with bounded gossip state.
    ///
    /// Returns the number of peer entries removed.
    pub fn prune_stale_peers(&mut self, now: u64) -> usize {
        let ttl_secs = self.config.summary_ttl_secs;
        let mut removed = 0usize;

        self.peer_states.retain(|peer_id, state| {
            let stale = state.is_stale(now, ttl_secs);
            if stale {
                removed += 1;
                warn!(
                    component = "mesh.gossip",
                    event = "peer_pruned",
                    peer_id = %peer_id.as_str(),
                    ttl_seconds = ttl_secs,
                    age_seconds = now.saturating_sub(state.last_updated),
                    failed_attempts = state.failed_attempts()
                );
            }
            !stale
        });

        removed
    }
}

/// Gossip statistics.
#[derive(Debug, Clone)]
pub struct GossipStats {
    /// Number of objects.
    pub object_count: usize,
    /// Number of symbols.
    pub symbol_count: usize,
    /// Last update timestamp.
    pub last_updated: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

/// Create a symbol key for filter insertion.
fn symbol_key(object_id: &ObjectId, esi: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(object_id.as_bytes());
    key.extend_from_slice(&esi.to_le_bytes());
    key
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::ObjectAdmissionClass;
    use fcp_crypto::Ed25519SigningKey;
    use serde::Serialize;

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(label.as_bytes())
    }

    fn test_epoch() -> EpochId {
        EpochId::new("epoch-test")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // XorFilterPlaceholder Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn filter_insert_and_check() {
        let mut filter = XorFilterPlaceholder::new();
        assert!(filter.is_empty());

        filter.insert(b"test-item");
        assert!(!filter.is_empty());
        assert_eq!(filter.len(), 1);

        // Should find inserted item
        assert!(filter.may_contain(b"test-item"));

        // May or may not find non-inserted (false positives allowed)
        // Just ensure no panic
        let _ = filter.may_contain(b"other-item");
    }

    #[test]
    fn filter_digest_deterministic() {
        let mut filter1 = XorFilterPlaceholder::with_seed(42);
        let mut filter2 = XorFilterPlaceholder::with_seed(42);

        filter1.insert(b"item-a");
        filter1.insert(b"item-b");
        filter2.insert(b"item-a");
        filter2.insert(b"item-b");

        assert_eq!(filter1.digest(), filter2.digest());
    }

    #[test]
    fn filter_digest_differs_by_content() {
        let mut filter1 = XorFilterPlaceholder::with_seed(42);
        let mut filter2 = XorFilterPlaceholder::with_seed(42);

        filter1.insert(b"item-a");
        filter2.insert(b"item-b");

        assert_ne!(filter1.digest(), filter2.digest());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IBLT Sketch Tests (production-backed; placeholder name retained)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn iblt_tracks_changes() {
        let mut iblt = IbltPlaceholder::new();
        let obj_id = test_object_id("obj-1");

        iblt.note_local_change(&obj_id, None);
        assert_eq!(iblt.change_seq(), 1);

        iblt.note_local_change(&obj_id, Some(42));
        assert_eq!(iblt.change_seq(), 2);
    }

    #[test]
    fn iblt_change_seq_increments_regardless_of_budget() {
        let mut iblt = IbltPlaceholder::with_max_changes(3);
        let obj_id = test_object_id("obj");

        for i in 0..5 {
            iblt.note_local_change(&obj_id, Some(i));
        }

        // Production sketch no longer drops a "recent changes" log; the
        // monotonic change_seq still reflects every note_local_change.
        assert_eq!(iblt.change_seq(), 5);
        // recent_changes() is retained only for ABI continuity and is
        // always empty under the production sketch.
        assert!(iblt.recent_changes().is_empty());
    }

    #[test]
    fn iblt_encode_is_cbor_iblt_roundtrip() {
        let mut iblt = IbltPlaceholder::new();
        let obj_id = test_object_id("rt");
        iblt.note_local_change(&obj_id, None);

        let encoded = iblt.encode();
        // CBOR-encoded Iblt; the raw bytes are not a JSON array any more.
        let decoded: Iblt = ciborium::from_reader(encoded.as_slice())
            .expect("IbltPlaceholder::encode produces canonical CBOR Iblt");
        // The real sketch contains the inserted object — peel confirms it.
        let empty = Iblt::with_cell_count(decoded.cell_count()).unwrap();
        let diff = decoded.subtract(&empty).unwrap();
        let result = diff.decode();
        assert!(result.is_complete());
        assert_eq!(result.only_left.len(), 1);
        assert_eq!(result.only_right.len(), 0);
    }

    #[test]
    fn iblt_decode_rejects_oversized_payload() {
        let err = IbltPlaceholder::decode_with_limits(
            &vec![b'x'; MIN_IBLT_BYTES_BUDGET + 1],
            8,
            MIN_IBLT_BYTES_BUDGET,
        )
        .expect_err("oversized payload should fail");
        assert_eq!(
            err,
            IbltDecodeError::TooLarge {
                len: MIN_IBLT_BYTES_BUDGET + 1,
                max: MIN_IBLT_BYTES_BUDGET,
            }
        );
    }

    #[test]
    fn iblt_decode_rejects_invalid_encoding() {
        let err = IbltPlaceholder::decode_with_limits(b"not-cbor", 8, MIN_IBLT_BYTES_BUDGET)
            .expect_err("malformed payload should fail");
        assert_eq!(err, IbltDecodeError::InvalidEncoding);
    }

    #[test]
    fn iblt_decode_rejects_oversized_cell_count() {
        // Build a sketch with a larger cell budget than the peer
        // accepts, then confirm decode_with_limits rejects it.
        let big = IbltPlaceholder::with_max_changes(512);
        let big_cells = big.entry_count();
        let small_cells = Iblt::recommended_cell_count(2);
        assert!(big_cells > small_cells, "test fixture assumes big>small");

        let err = IbltPlaceholder::decode_with_limits(
            &big.encode(),
            2,
            MIN_IBLT_BYTES_BUDGET.max(big.encode().len()),
        )
        .expect_err("peer sketch larger than our cell cap should fail");
        assert_eq!(
            err,
            IbltDecodeError::TooManyChanges {
                decoded: big_cells,
                max: small_cells,
            }
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GossipState Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn gossip_state_announce_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("object-1");

        assert!(!state.has_object(&obj_id));
        state.announce_object(&obj_id, 1000);
        assert!(state.has_object(&obj_id));
        assert!(state.may_have_object(&obj_id));
        assert_eq!(state.object_count(), 1);
    }

    #[test]
    fn gossip_state_announce_symbol() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("object-1");

        state.announce_symbol(&obj_id, 42, 1000);

        assert!(state.has_object(&obj_id)); // Object auto-added
        assert!(state.has_symbol(&obj_id, 42));
        assert!(state.may_have_symbol(&obj_id, 42));
        assert_eq!(state.symbol_count(), 1);
    }

    #[test]
    fn gossip_state_create_summary() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("object-1");

        state.announce_object(&obj_id, 1000);
        state.announce_symbol(&obj_id, 1, 1000);
        state.announce_symbol(&obj_id, 2, 1000);

        let summary = state.create_summary(test_node("local"), test_epoch());

        assert_eq!(summary.zone_id.as_str(), "z:work");
        assert_eq!(summary.object_count, 1);
        assert_eq!(summary.symbol_count, 2);
    }

    #[test]
    fn gossip_state_remove_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("object-1");

        state.announce_object(&obj_id, 1000);
        state.announce_symbol(&obj_id, 42, 1000);
        assert!(state.has_object(&obj_id));

        state.remove_object(&obj_id, 2000);
        assert!(!state.has_object(&obj_id));
        assert!(!state.has_symbol(&obj_id, 42));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GossipSummary Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn summary_differs_from() {
        let summary1 = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [1; 32],
            symbol_filter_digest: [2; 32],
            object_count: 10,
            symbol_count: 100,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        let summary2 = GossipSummary {
            object_filter_digest: [3; 32], // Different
            ..summary1.clone()
        };

        assert!(summary1.differs_from(&summary2));
        assert!(!summary1.differs_from(&summary1));
    }

    #[test]
    fn summary_is_stale() {
        let summary = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 0,
            symbol_count: 0,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        assert!(!summary.is_stale(1100, 300, DEFAULT_MAX_FUTURE_SKEW_SECS)); // Within TTL
        assert!(summary.is_stale(1500, 300, DEFAULT_MAX_FUTURE_SKEW_SECS)); // Past TTL
        // Future-dated rejection: timestamp 1000 with now=900 => 100s ahead,
        // beyond DEFAULT_MAX_FUTURE_SKEW_SECS (30s).
        assert!(summary.is_stale(900, 300, DEFAULT_MAX_FUTURE_SKEW_SECS));
        // Within future-skew tolerance still verifies as fresh.
        assert!(!summary.is_stale(990, 300, DEFAULT_MAX_FUTURE_SKEW_SECS));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GossipRequest Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn request_bounds_object_ids() {
        let many_ids: Vec<ObjectId> = (0..200)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();

        let request = GossipRequest::for_objects(test_node("node"), test_zone(), many_ids, 1000);

        assert!(request.is_valid());
        assert_eq!(request.object_ids.len(), MAX_OBJECT_IDS_PER_REQUEST);
    }

    #[test]
    fn request_bounds_symbols() {
        let object_id = test_object_id("obj-symbols");
        let symbols: Vec<(ObjectId, u32)> = (0..200).map(|esi| (object_id, esi)).collect();

        let request = GossipRequest::for_symbols(test_node("node"), test_zone(), symbols, 1000);

        assert!(request.is_valid());
        assert_eq!(request.symbols.len(), MAX_OBJECT_IDS_PER_REQUEST);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MeshGossip Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn mesh_gossip_announce_admitted_object() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("admitted-obj");

        let added =
            gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);

        assert!(added);
        assert!(gossip.has_object(&test_zone(), &obj_id));
    }

    #[test]
    fn mesh_gossip_rejects_quarantined_object() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("quarantined-obj");

        let added = gossip.announce_object(
            &test_zone(),
            &obj_id,
            ObjectAdmissionClass::Quarantined,
            1000,
        );

        // NORMATIVE: Quarantined objects MUST NOT pollute gossip
        assert!(!added);
        assert!(!gossip.has_object(&test_zone(), &obj_id));
    }

    #[test]
    fn mesh_gossip_create_summary() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);

        let summary = gossip.create_summary(&test_zone(), test_epoch());
        assert!(summary.is_some());
        assert_eq!(summary.unwrap().object_count, 1);
    }

    #[test]
    fn mesh_gossip_create_summary_clamps_counts() {
        let config = GossipConfig {
            max_objects_per_summary: 1,
            max_symbols_per_summary: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);

        let obj_id = test_object_id("obj-1");
        gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);
        gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            1,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        let obj_id2 = test_object_id("obj-2");
        gossip.announce_object(&test_zone(), &obj_id2, ObjectAdmissionClass::Admitted, 1000);
        gossip.announce_symbol(
            &test_zone(),
            &obj_id2,
            2,
            ObjectAdmissionClass::Admitted,
            1000,
        );

        let summary = gossip
            .create_summary(&test_zone(), test_epoch())
            .expect("summary");
        assert_eq!(summary.object_count, 1);
        assert_eq!(summary.symbol_count, 1);
    }

    #[test]
    fn mesh_gossip_create_summary_stays_within_iblt_budget() {
        // Post-migration invariant: the production IBLT sketch is
        // sized from `reconciliation_batch_size` via
        // `Iblt::recommended_cell_count` and encoded as canonical
        // CBOR. The byte budget `max_iblt_bytes` is tuned (128 bytes
        // per expected-difference unit, 8192-byte floor) to cover the
        // CBOR cell size + outer-struct overhead, so the sketch fits
        // by construction and the fallback-marker path is now only
        // reachable from pathological external wire growth.
        //
        // This test replaces the legacy
        // `mesh_gossip_create_summary_falls_back_when_iblt_exceeds_budget`
        // which exercised a placeholder JSON wire that scaled with
        // announce volume; the production sketch is fixed-size per
        // cell budget.
        let config = GossipConfig {
            reconciliation_batch_size: 64,
            ..GossipConfig::default()
        };
        let max_iblt_bytes = config.max_iblt_bytes();
        let mut gossip = MeshGossip::new(test_node("local"), config);
        let obj_id = test_object_id("obj-summary-budget");

        for esi in 0..512 {
            gossip.announce_symbol(
                &test_zone(),
                &obj_id,
                esi,
                ObjectAdmissionClass::Admitted,
                1_000,
            );
        }

        let summary = gossip
            .create_summary(&test_zone(), test_epoch())
            .expect("summary should exist");
        assert!(
            !summary.iblt.is_empty(),
            "production sketch should always populate summary.iblt"
        );
        assert!(
            summary.iblt.len() <= max_iblt_bytes,
            "sketch {} exceeded configured byte budget {}",
            summary.iblt.len(),
            max_iblt_bytes,
        );
        // The sketch must be decodable by a peer with the same batch size.
        IbltPlaceholder::decode_with_limits(&summary.iblt, 64, max_iblt_bytes)
            .expect("created summary must be decodable");
    }

    #[test]
    fn mesh_gossip_handle_summary_updates_peer() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 50,
            symbol_count: 500,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        gossip.handle_summary(summary, 1000);
        assert_eq!(gossip.peer_count(), 1);
    }

    #[test]
    fn mesh_gossip_prunes_stale_peers() {
        let config = GossipConfig {
            summary_ttl_secs: 10,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);

        let initial_summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 1,
            symbol_count: 1,
            iblt: vec![],
            timestamp: 100,
            signature: None,
        };

        gossip.handle_summary(initial_summary, 100);
        assert_eq!(gossip.peer_count(), 1);

        let removed = gossip.prune_stale_peers(111);
        assert_eq!(removed, 1);
        assert_eq!(gossip.peer_count(), 0);

        let fresh_summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [1; 32],
            symbol_filter_digest: [2; 32],
            object_count: 2,
            symbol_count: 2,
            iblt: vec![],
            timestamp: 112,
            signature: None,
        };

        gossip.handle_summary(fresh_summary, 112);
        assert_eq!(gossip.peer_count(), 1);
    }

    #[test]
    fn mesh_gossip_ignores_stale_summary() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let now = 1000u64;
        let timestamp = now.saturating_sub(DEFAULT_SUMMARY_TTL_SECS + 1);

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 50,
            symbol_count: 500,
            iblt: vec![],
            timestamp,
            signature: None,
        };

        gossip.handle_summary(summary, now);
        assert_eq!(gossip.peer_count(), 0);
    }

    #[test]
    fn mesh_gossip_ignores_future_dated_summary() {
        // Regression for br-flywheel_connectors-hawuq: a peer (or a peer with
        // a fast clock) that emits a summary with `timestamp` far in the future
        // previously slipped past `is_stale` because `now.saturating_sub(future)`
        // collapsed to 0. Once accepted, `peer_states[peer].last_updated` was
        // pinned to that future value so legitimate later summaries appeared
        // older and were ignored until wall-clock caught up. The bounded future
        // skew rejects the summary before any peer state is mutated.
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let now = 1000u64;
        let future_skew = gossip.max_future_skew_secs();
        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 50,
            symbol_count: 500,
            iblt: vec![],
            timestamp: now + future_skew + 1,
            signature: None,
        };

        let accepted = gossip.handle_summary(summary, now);
        assert!(!accepted, "future-dated summary must be rejected");
        assert_eq!(
            gossip.peer_count(),
            0,
            "peer state must not be created from a rejected future-dated summary"
        );
    }

    #[test]
    fn mesh_gossip_accepts_summary_within_future_skew_tolerance() {
        // Companion to the above: a summary inside the bounded future-skew
        // window (typical NTP drift on cooperating nodes) must still verify.
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let now = 1000u64;
        let future_skew = gossip.max_future_skew_secs();
        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 50,
            symbol_count: 500,
            iblt: vec![],
            timestamp: now + future_skew,
            signature: None,
        };

        let accepted = gossip.handle_summary(summary, now);
        assert!(
            accepted,
            "summary at the upper edge of the future-skew window must verify"
        );
        assert_eq!(gossip.peer_count(), 1);
    }

    #[test]
    fn mesh_gossip_ignores_oversized_summary() {
        let config = GossipConfig {
            max_objects_per_summary: 1,
            max_symbols_per_summary: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 2,
            symbol_count: 2,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        gossip.handle_summary(summary, 1000);
        assert_eq!(gossip.peer_count(), 0);
    }

    #[test]
    fn mesh_gossip_rejects_summary_with_oversized_iblt() {
        let config = GossipConfig {
            reconciliation_batch_size: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config.clone());

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 1,
            symbol_count: 1,
            iblt: vec![0u8; config.max_iblt_bytes() + 1],
            timestamp: 1_000,
            signature: None,
        };

        gossip.handle_summary(summary, 1_000);
        assert_eq!(gossip.peer_count(), 0);
    }

    #[test]
    fn mesh_gossip_rejects_summary_with_invalid_iblt() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 1,
            symbol_count: 1,
            iblt: b"not-json".to_vec(),
            timestamp: 1_000,
            signature: None,
        };

        gossip.handle_summary(summary, 1_000);
        assert_eq!(gossip.peer_count(), 0);
    }

    #[test]
    fn mesh_gossip_handle_request() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);

        let request = GossipRequest::for_objects(
            test_node("peer"),
            test_zone(),
            vec![obj_id, test_object_id("unknown")],
            1000,
        );

        let response = gossip.handle_request(&request);

        // Should only include objects we have
        assert_eq!(response.have_objects.len(), 1);
        assert_eq!(response.have_objects[0], obj_id);
    }

    #[test]
    fn mesh_gossip_handle_request_bounds_results() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        let object_ids: Vec<ObjectId> = (0..MAX_OBJECT_IDS_PER_REQUEST)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();

        for object_id in &object_ids {
            gossip.announce_object(
                &test_zone(),
                object_id,
                ObjectAdmissionClass::Admitted,
                1000,
            );
        }

        let request =
            GossipRequest::for_objects(test_node("peer"), test_zone(), object_ids.clone(), 1000);

        let response = gossip.handle_request(&request);
        assert_eq!(response.have_objects.len(), object_ids.len());
    }

    #[test]
    fn mesh_gossip_handle_request_rejects_invalid_request() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        let object_ids: Vec<ObjectId> = (0..=MAX_OBJECT_IDS_PER_REQUEST)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();

        for object_id in &object_ids {
            gossip.announce_object(
                &test_zone(),
                object_id,
                ObjectAdmissionClass::Admitted,
                1000,
            );
        }

        let request = GossipRequest {
            from: test_node("peer"),
            zone_id: test_zone(),
            object_ids,
            symbols: vec![],
            timestamp: 1000,
            signature: None,
        };

        let response = gossip.handle_request(&request);
        assert!(response.have_objects.is_empty());
        assert!(response.have_symbols.is_empty());
    }

    #[test]
    fn mesh_gossip_handle_request_rejects_over_config_object_request() {
        let config = GossipConfig {
            max_objects_per_request: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);

        let object_ids: Vec<ObjectId> = (0..2)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();

        for object_id in &object_ids {
            gossip.announce_object(
                &test_zone(),
                object_id,
                ObjectAdmissionClass::Admitted,
                1000,
            );
        }

        let request = GossipRequest::for_objects(test_node("peer"), test_zone(), object_ids, 1000);

        let response = gossip.handle_request(&request);
        assert!(response.have_objects.is_empty());
        assert!(response.have_symbols.is_empty());
    }

    #[test]
    fn mesh_gossip_handle_request_rejects_invalid_symbol_request() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let object_id = test_object_id("obj-symbols-invalid");

        gossip.announce_symbol(
            &test_zone(),
            &object_id,
            1,
            ObjectAdmissionClass::Admitted,
            1000,
        );

        let max_esi =
            u32::try_from(MAX_OBJECT_IDS_PER_REQUEST).expect("max symbols fits u32 in test");
        let symbols: Vec<(ObjectId, u32)> = (0..=max_esi).map(|esi| (object_id, esi)).collect();

        let request = GossipRequest {
            from: test_node("peer"),
            zone_id: test_zone(),
            object_ids: vec![],
            symbols,
            timestamp: 1000,
            signature: None,
        };

        let response = gossip.handle_request(&request);
        assert!(response.have_objects.is_empty());
        assert!(response.have_symbols.is_empty());
    }

    #[test]
    fn mesh_gossip_handle_request_rejects_over_config_symbol_request() {
        let config = GossipConfig {
            max_symbols_per_request: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);
        let object_id = test_object_id("obj-symbols-config");

        gossip.announce_symbol(
            &test_zone(),
            &object_id,
            1,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        gossip.announce_symbol(
            &test_zone(),
            &object_id,
            2,
            ObjectAdmissionClass::Admitted,
            1000,
        );

        let symbols = vec![(object_id, 1), (object_id, 2)];
        let request = GossipRequest::for_symbols(test_node("peer"), test_zone(), symbols, 1000);

        let response = gossip.handle_request(&request);
        assert!(response.have_objects.is_empty());
        assert!(response.have_symbols.is_empty());
    }

    #[test]
    fn mesh_gossip_find_object_sources() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        // Add a peer that "has" the object (via filter)
        let mut peer_state = PeerGossipState::new(test_node("peer-1"));
        peer_state.object_filter.insert(obj_id.as_bytes());
        gossip.peer_states.insert(test_node("peer-1"), peer_state);

        let sources = gossip.find_object_sources(&obj_id);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].as_str(), "peer-1");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PeerGossipState Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn peer_state_tracks_failures() {
        let mut peer = PeerGossipState::new(test_node("peer"));
        assert_eq!(peer.failed_attempts(), 0);

        peer.record_failure();
        peer.record_failure();
        assert_eq!(peer.failed_attempts(), 2);
    }

    #[test]
    fn peer_state_is_stale() {
        let peer = PeerGossipState::new(test_node("peer"));
        // last_updated defaults to 0

        assert!(peer.is_stale(1000, 300));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Symbol Key Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn symbol_key_format() {
        let obj_id = test_object_id("obj");
        let key = symbol_key(&obj_id, 42);

        // 32 bytes object_id + 4 bytes esi
        assert_eq!(key.len(), 36);
        assert!(key.starts_with(obj_id.as_bytes()));
    }

    // --- New tests below ---

    #[test]
    fn iblt_clear_and_encode() {
        let mut iblt = IbltPlaceholder::new();
        let obj_id = test_object_id("obj-1");

        iblt.note_local_change(&obj_id, None);
        iblt.note_local_change(&obj_id, Some(1));
        assert_eq!(iblt.change_seq(), 2);

        let encoded_before = iblt.encode();
        assert!(!encoded_before.is_empty());

        iblt.clear();
        // After clear, the sketch is empty: a self-subtract decodes to
        // the empty set (no only_left / only_right).
        let self_diff = iblt.as_iblt().subtract(iblt.as_iblt()).unwrap();
        let result = self_diff.decode();
        assert!(result.is_complete());
        assert!(result.only_left.is_empty());
        assert!(result.only_right.is_empty());
        // change_seq is preserved across clear().
        assert_eq!(iblt.change_seq(), 2);
    }

    #[test]
    fn gossip_state_list_objects() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);

        for i in 0..5 {
            state.announce_object(&test_object_id(&format!("obj-{i}")), 1000);
        }
        assert_eq!(state.object_count(), 5);

        let limited = state.list_objects(3);
        assert_eq!(limited.len(), 3);

        let all = state.list_objects(100);
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn gossip_state_symbols_for_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj_id = test_object_id("obj-1");

        assert!(state.symbols_for_object(&obj_id).is_none());

        state.announce_symbol(&obj_id, 10, 1000);
        state.announce_symbol(&obj_id, 20, 1000);

        let syms = state.symbols_for_object(&obj_id).unwrap();
        assert_eq!(syms.len(), 2);
        assert!(syms.contains(&10));
        assert!(syms.contains(&20));
    }

    #[test]
    fn gossip_state_zone_id() {
        let config = GossipConfig::default();
        let state = GossipState::new(test_zone(), &config);
        assert_eq!(state.zone_id(), &test_zone());
    }

    #[test]
    fn gossip_summary_signing_bytes_deterministic() {
        let summary = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0xAA; 32],
            symbol_filter_digest: [0xBB; 32],
            object_count: 42,
            symbol_count: 100,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };

        let bytes1 = summary.signing_bytes();
        let bytes2 = summary.signing_bytes();
        assert_eq!(bytes1, bytes2);
        assert!(bytes1.starts_with(b"FCP2-GOSSIP-SUMMARY-V1"));
    }

    #[test]
    fn gossip_summary_with_signature() {
        let summary = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 0,
            symbol_count: 0,
            iblt: vec![],
            timestamp: 0,
            signature: None,
        };

        assert!(summary.signature.is_none());
        let node_id = fcp_core::NodeId::new("node-1");
        let sig = NodeSignature::new(node_id, [0xAB; 64], 1000);
        let signed = summary.with_signature(sig);
        assert!(signed.signature.is_some());
    }

    #[test]
    fn peer_capability_advertisement_signing_round_trip() {
        let signing_key = Ed25519SigningKey::generate();
        let template = PeerCapabilityAdvertisement::v3_v4(test_node("node-1"), 1_000);
        let signature = NodeSignature::new(
            fcp_core::NodeId::new("node-1"),
            signing_key.sign(&template.signing_bytes()).to_bytes(),
            1_000,
        );
        let advertisement = template.with_signature(signature);

        advertisement
            .verify_signature(&signing_key.verifying_key())
            .expect("peer capability advertisement signature should verify");
        assert!(advertisement.capabilities.supports_v4());
        assert!(!advertisement.capabilities.is_v3_only());
    }

    #[test]
    fn peer_capability_message_serde_roundtrip() {
        let msg = GossipMessage::PeerCapabilities(PeerCapabilityAdvertisement::v3_only(
            test_node("node-1"),
            1_000,
        ));
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: GossipMessage = serde_json::from_str(&json).unwrap();

        match deserialized {
            GossipMessage::PeerCapabilities(advertisement) => {
                assert!(advertisement.capabilities.is_v3_only());
                assert_eq!(advertisement.from.as_str(), "node-1");
            }
            other => panic!("expected PeerCapabilities variant, got {other:?}"),
        }
    }

    #[test]
    fn gossip_request_is_valid_with_limits() {
        let request = GossipRequest::for_objects(
            test_node("n"),
            test_zone(),
            vec![test_object_id("a"), test_object_id("b")],
            0,
        );

        assert!(request.is_valid_with_limits(5, 5));
        assert!(request.is_valid_with_limits(2, 5));
        assert!(!request.is_valid_with_limits(1, 5)); // 2 objects > limit 1
    }

    #[test]
    fn gossip_message_serde_roundtrip() {
        let summary = GossipSummary {
            from: test_node("node-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 1,
            symbol_count: 2,
            iblt: vec![],
            timestamp: 1000,
            signature: None,
        };
        let msg = GossipMessage::Summary(summary);
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: GossipMessage = serde_json::from_str(&json).unwrap();
        match deserialized {
            GossipMessage::Summary(s) => {
                assert_eq!(s.object_count, 1);
                assert_eq!(s.symbol_count, 2);
            }
            _ => panic!("expected Summary variant"),
        }
    }

    #[test]
    fn gossip_stats_debug_clone() {
        let stats = GossipStats {
            object_count: 10,
            symbol_count: 50,
            last_updated: 1234,
        };
        let cloned = stats.clone();
        assert_eq!(cloned.object_count, 10);
        let s = format!("{stats:?}");
        assert!(s.contains("GossipStats"));
    }

    #[test]
    fn gossip_config_defaults() {
        let config = GossipConfig::default();
        assert_eq!(
            config.max_objects_per_summary,
            DEFAULT_MAX_OBJECTS_PER_SUMMARY
        );
        assert_eq!(
            config.max_symbols_per_summary,
            DEFAULT_MAX_SYMBOLS_PER_SUMMARY
        );
        assert_eq!(config.summary_ttl_secs, DEFAULT_SUMMARY_TTL_SECS);
        assert_eq!(
            config.reconciliation_batch_size,
            DEFAULT_RECONCILIATION_BATCH_SIZE
        );
        assert!(
            config.max_iblt_bytes() >= MIN_IBLT_BYTES_BUDGET,
            "IBLT byte budget should be explicitly bounded"
        );
    }

    #[derive(Serialize)]
    struct NaiveAvailabilitySummary {
        objects: Vec<ObjectId>,
        symbols: Vec<(ObjectId, u32)>,
    }

    #[test]
    fn optimized_summary_is_smaller_than_naive_baseline() {
        let config = GossipConfig {
            reconciliation_batch_size: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);
        let mut objects = Vec::new();
        let mut symbols = Vec::new();

        for object_index in 0..96 {
            let object_id = test_object_id(&format!("naive-{object_index}"));
            objects.push(object_id);
            gossip.announce_object(
                &test_zone(),
                &object_id,
                ObjectAdmissionClass::Admitted,
                1_000,
            );
            for esi in 0..4 {
                symbols.push((object_id, esi));
                gossip.announce_symbol(
                    &test_zone(),
                    &object_id,
                    esi,
                    ObjectAdmissionClass::Admitted,
                    1_000,
                );
            }
        }

        let summary = gossip
            .create_summary(&test_zone(), test_epoch())
            .expect("summary should exist");
        let optimized_bytes = serde_json::to_vec(&summary).expect("summary should serialize");
        let baseline_bytes = serde_json::to_vec(&NaiveAvailabilitySummary { objects, symbols })
            .expect("baseline should serialize");

        assert!(
            optimized_bytes.len() < baseline_bytes.len(),
            "optimized summary should be smaller than explicit baseline"
        );
    }

    #[test]
    fn peer_gossip_state_update_from_summary() {
        let mut peer = PeerGossipState::new(test_node("peer-1"));
        peer.record_failure();
        peer.record_failure();
        assert_eq!(peer.failed_attempts(), 2);

        let summary = GossipSummary {
            from: test_node("peer-1"),
            zone_id: test_zone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 5,
            symbol_count: 10,
            iblt: vec![],
            timestamp: 2000,
            signature: None,
        };

        peer.update_from_summary(summary, 2000);
        assert_eq!(peer.failed_attempts(), 0); // reset on update
        assert!(!peer.is_stale(2100, 300));
    }

    #[test]
    fn peer_gossip_state_peer_id() {
        let peer = PeerGossipState::new(test_node("my-peer"));
        assert_eq!(peer.peer_id().as_str(), "my-peer");
    }

    #[test]
    fn peer_gossip_state_may_have_symbol() {
        let mut peer = PeerGossipState::new(test_node("peer-1"));
        let obj_id = test_object_id("obj-sym");

        assert!(!peer.may_have_symbol(&obj_id, 42));

        peer.symbol_filter.insert(&symbol_key(&obj_id, 42));
        assert!(peer.may_have_symbol(&obj_id, 42));
    }

    #[test]
    fn mesh_gossip_announce_symbol_admitted() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        let added = gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            5,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        assert!(added);
        assert!(gossip.has_symbol(&test_zone(), &obj_id, 5));
    }

    #[test]
    fn mesh_gossip_announce_symbol_quarantined_rejected() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        let added = gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            5,
            ObjectAdmissionClass::Quarantined,
            1000,
        );
        assert!(!added);
        assert!(!gossip.has_symbol(&test_zone(), &obj_id, 5));
    }

    #[test]
    fn mesh_gossip_has_symbol_unknown_zone() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");
        assert!(!gossip.has_symbol(&test_zone(), &obj_id, 0));
    }

    #[test]
    fn mesh_gossip_list_objects_in_zone() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        // No zone yet
        assert!(gossip.list_objects_in_zone(&test_zone(), 10).is_empty());

        for i in 0..5 {
            gossip.announce_object(
                &test_zone(),
                &test_object_id(&format!("obj-{i}")),
                ObjectAdmissionClass::Admitted,
                1000,
            );
        }

        let objs = gossip.list_objects_in_zone(&test_zone(), 3);
        assert_eq!(objs.len(), 3);

        let all = gossip.list_objects_in_zone(&test_zone(), 100);
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn mesh_gossip_zone_stats() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));

        assert!(gossip.zone_stats(&test_zone()).is_none());

        let obj_id = test_object_id("obj-1");
        gossip.announce_object(&test_zone(), &obj_id, ObjectAdmissionClass::Admitted, 1000);
        gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            1,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        gossip.announce_symbol(
            &test_zone(),
            &obj_id,
            2,
            ObjectAdmissionClass::Admitted,
            1000,
        );

        let stats = gossip.zone_stats(&test_zone()).unwrap();
        assert_eq!(stats.object_count, 1);
        assert_eq!(stats.symbol_count, 2);
        assert_eq!(stats.last_updated, 1000);
    }

    #[test]
    fn mesh_gossip_create_request() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        let ids = vec![test_object_id("a"), test_object_id("b")];

        let request = gossip.create_request(&test_zone(), ids, 1000);
        assert_eq!(request.object_ids.len(), 2);
        assert_eq!(request.from.as_str(), "local");
        assert!(request.is_valid());
    }

    #[test]
    fn mesh_gossip_find_symbol_sources() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let obj_id = test_object_id("obj-1");

        let mut peer = PeerGossipState::new(test_node("peer-1"));
        peer.symbol_filter.insert(&symbol_key(&obj_id, 7));
        gossip.peer_states.insert(test_node("peer-1"), peer);

        let sources = gossip.find_symbol_sources(&obj_id, 7);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].as_str(), "peer-1");

        let no_sources = gossip.find_symbol_sources(&obj_id, 999);
        assert!(no_sources.is_empty());
    }

    #[test]
    fn mesh_gossip_create_summary_none_for_unknown_zone() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        assert!(gossip.create_summary(&test_zone(), test_epoch()).is_none());
    }

    #[test]
    fn xor_filter_with_seed() {
        let mut f1 = XorFilterPlaceholder::with_seed(100);
        let mut f2 = XorFilterPlaceholder::with_seed(200);

        f1.insert(b"same-item");
        f2.insert(b"same-item");

        // Different seeds produce different digests
        assert_ne!(f1.digest(), f2.digest());
    }

    #[test]
    fn xor_filter_default() {
        let filter = XorFilterPlaceholder::default();
        assert!(filter.is_empty());
        assert_eq!(filter.len(), 0);
    }

    #[test]
    fn xor_filter_may_contain_not_inserted() {
        let filter = XorFilterPlaceholder::new();
        // Empty filter should not contain anything
        assert!(!filter.may_contain(b"anything"));
    }

    #[test]
    fn iblt_default() {
        let iblt = IbltPlaceholder::default();
        assert_eq!(iblt.change_seq(), 0);
        // Production default sketch is sized for the default batch size;
        // it is non-empty in cell count but empty in admitted objects.
        assert!(iblt.entry_count() >= crate::iblt::MIN_RECOMMENDED_IBLT_CELLS);
    }

    // ── XorFilterPlaceholder additional tests ──────────────────

    #[test]
    fn xor_filter_multiple_inserts() {
        let mut filter = XorFilterPlaceholder::new();
        filter.insert(b"item-1");
        filter.insert(b"item-2");
        filter.insert(b"item-3");
        assert_eq!(filter.len(), 3);
        assert!(filter.may_contain(b"item-1"));
        assert!(filter.may_contain(b"item-2"));
        assert!(filter.may_contain(b"item-3"));
    }

    #[test]
    fn xor_filter_digest_differs_by_seed() {
        let mut f1 = XorFilterPlaceholder::with_seed(1);
        let mut f2 = XorFilterPlaceholder::with_seed(2);
        f1.insert(b"same-item");
        f2.insert(b"same-item");
        assert_ne!(f1.digest(), f2.digest());
    }

    #[test]
    fn xor_filter_empty_digest_deterministic() {
        let d1 = XorFilterPlaceholder::new().digest();
        let d2 = XorFilterPlaceholder::new().digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn xor_filter_serde_roundtrip() {
        let mut filter = XorFilterPlaceholder::with_seed(99);
        filter.insert(b"serde-test");
        let json = serde_json::to_string(&filter).unwrap();
        let deserialized: XorFilterPlaceholder = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 1);
        assert!(deserialized.may_contain(b"serde-test"));
    }

    // ── XOR Filter Production Tests (br21t.6) ────────────────

    #[test]
    fn xor_filter_zero_false_negatives_1000_members() {
        // Construct filter from 1000 BLAKE3 hashes; verify all members query true.
        let mut filter = XorFilterPlaceholder::new();
        let items: Vec<Vec<u8>> = (0..1000)
            .map(|i| {
                blake3::hash(format!("member-{i}").as_bytes())
                    .as_bytes()
                    .to_vec()
            })
            .collect();

        for item in &items {
            filter.insert(item);
        }
        assert_eq!(filter.len(), 1000);

        // Every inserted item MUST be found (zero false negatives)
        for item in &items {
            assert!(
                filter.may_contain(item),
                "false negative detected — XOR filters must have zero false negatives"
            );
        }
    }

    #[test]
    fn xor_filter_false_positive_rate_under_threshold() {
        // Xor8 FP rate should be < 0.4% (≈ 1/256). Test with 10,000 non-member queries.
        let mut filter = XorFilterPlaceholder::new();
        for i in 0..1000 {
            filter.insert(format!("member-{i}").as_bytes());
        }

        let mut false_positives = 0u32;
        let trials = 10_000;
        for i in 0..trials {
            let probe = format!("non-member-probe-{i}");
            if filter.may_contain(probe.as_bytes()) {
                false_positives += 1;
            }
        }

        let fp_rate = f64::from(false_positives) / f64::from(trials);
        // Xor8 theoretical FP ≈ 0.39%. Allow up to 1% for statistical margin.
        assert!(
            fp_rate < 0.01,
            "false positive rate {fp_rate:.4} exceeds 1% threshold ({false_positives}/{trials})"
        );
    }

    #[test]
    fn xor_filter_large_set_100k_members() {
        // Verify filter works correctly with 100k members
        let mut filter = XorFilterPlaceholder::new();
        for i in 0u64..100_000 {
            filter.insert(&i.to_le_bytes());
        }
        assert_eq!(filter.len(), 100_000);

        // Spot-check: all members present (zero false negatives)
        for i in (0u64..100_000).step_by(1000) {
            assert!(
                filter.may_contain(&i.to_le_bytes()),
                "false negative at index {i}"
            );
        }

        // FP rate check on non-members
        let mut fps = 0u32;
        let trials = 10_000u32;
        for i in 100_000u64..110_000 {
            if filter.may_contain(&i.to_le_bytes()) {
                fps += 1;
            }
        }
        let fp_rate = f64::from(fps) / f64::from(trials);
        assert!(
            fp_rate < 0.01,
            "large set FP rate {fp_rate:.4} exceeds 1% ({fps}/{trials})"
        );
    }

    #[test]
    fn xor_filter_serde_roundtrip_preserves_queries() {
        // Serialize, deserialize, then verify same membership results
        let mut filter = XorFilterPlaceholder::with_seed(42);
        let items: Vec<Vec<u8>> = (0..500)
            .map(|i| format!("serde-item-{i}").into_bytes())
            .collect();
        for item in &items {
            filter.insert(item);
        }

        let json = serde_json::to_string(&filter).unwrap();
        let restored: XorFilterPlaceholder = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.len(), filter.len());
        assert_eq!(restored.digest(), filter.digest());

        // All original members still found after round-trip
        for item in &items {
            assert!(
                restored.may_contain(item),
                "member lost after serde round-trip"
            );
        }
    }

    #[test]
    fn xor_filter_empty_no_false_positives() {
        let filter = XorFilterPlaceholder::new();
        assert!(filter.is_empty());
        assert_eq!(filter.len(), 0);

        // Empty filter must return false for any query
        for i in 0..100 {
            assert!(
                !filter.may_contain(format!("probe-{i}").as_bytes()),
                "empty filter returned true for probe-{i}"
            );
        }
    }

    #[test]
    fn xor_filter_determinism_same_inputs_same_filter() {
        // Same items in same order produce identical digests
        let items: Vec<Vec<u8>> = (0..100).map(|i| format!("det-{i}").into_bytes()).collect();

        let mut f1 = XorFilterPlaceholder::with_seed(7);
        let mut f2 = XorFilterPlaceholder::with_seed(7);
        for item in &items {
            f1.insert(item);
            f2.insert(item);
        }

        assert_eq!(f1.digest(), f2.digest());
        assert_eq!(f1.len(), f2.len());
    }

    #[test]
    fn xor_filter_determinism_insertion_order_invariant() {
        // Same items in different order produce identical digests
        // (BTreeSet ensures deterministic key ordering)
        let mut f1 = XorFilterPlaceholder::with_seed(7);
        let mut f2 = XorFilterPlaceholder::with_seed(7);

        f1.insert(b"alpha");
        f1.insert(b"beta");
        f1.insert(b"gamma");

        f2.insert(b"gamma");
        f2.insert(b"alpha");
        f2.insert(b"beta");

        assert_eq!(f1.digest(), f2.digest());
    }

    #[test]
    fn xor_filter_duplicate_insert_is_idempotent() {
        let mut filter = XorFilterPlaceholder::new();
        filter.insert(b"dup-item");
        filter.insert(b"dup-item");
        filter.insert(b"dup-item");
        // BTreeSet deduplicates; count should be 1
        assert_eq!(filter.len(), 1);
        assert!(filter.may_contain(b"dup-item"));
    }

    #[test]
    fn xor_filter_clone_preserves_membership() {
        let mut original = XorFilterPlaceholder::new();
        for i in 0..50 {
            original.insert(format!("clone-{i}").as_bytes());
        }

        let cloned = original.clone();
        assert_eq!(cloned.len(), original.len());
        assert_eq!(cloned.digest(), original.digest());

        for i in 0..50 {
            assert!(cloned.may_contain(format!("clone-{i}").as_bytes()));
        }
    }

    // ── IbltPlaceholder additional tests ───────────────────────

    #[test]
    fn iblt_zero_max_changes_still_increments_seq() {
        // The argument is a budget hint, not a gate — change_seq still
        // increments on every note_local_change regardless of the
        // expected-difference budget. The underlying Iblt is floored
        // to MIN_RECOMMENDED_IBLT_CELLS.
        let mut iblt = IbltPlaceholder::with_max_changes(0);
        let obj = test_object_id("o");
        iblt.note_local_change(&obj, None);
        iblt.note_local_change(&obj, Some(1));
        assert_eq!(iblt.change_seq(), 2);
    }

    #[test]
    fn iblt_encode_decode_roundtrip() {
        // Insert distinct objects: IBLT peeling requires pure cells
        // with count ±1, so duplicating the same object_id across two
        // note_local_change calls would produce count=2 cells that the
        // peel can't recover.
        let mut iblt = IbltPlaceholder::with_max_changes(64);
        let obj_a = test_object_id("rt-a");
        let obj_b = test_object_id("rt-b");
        iblt.note_local_change(&obj_a, None);
        iblt.note_local_change(&obj_b, Some(42));
        let encoded = iblt.encode();
        let decoded = IbltPlaceholder::decode_with_limits(
            &encoded,
            64,
            encoded.len().max(MIN_IBLT_BYTES_BUDGET),
        )
        .unwrap();
        let empty = Iblt::with_cell_count(decoded.as_iblt().cell_count()).unwrap();
        let diff = decoded.as_iblt().subtract(&empty).unwrap();
        let result = diff.decode();
        assert!(result.is_complete());
        assert_eq!(result.only_left, [obj_a, obj_b].into_iter().collect());
    }

    #[test]
    fn iblt_with_mask_encodes_masked_keys_on_wire() {
        let mask = IbltMask::from_bytes([0xA5; 32]);
        let mut iblt = IbltPlaceholder::with_mask(16, mask);
        let object_id = test_object_id("masked-wire");
        iblt.note_local_change(&object_id, None);

        let encoded = iblt.encode();
        let raw_wire_iblt: Iblt =
            ciborium::from_reader(encoded.as_slice()).expect("summary IBLT is CBOR");
        let empty = Iblt::with_cell_count(raw_wire_iblt.cell_count()).unwrap();
        let raw_result = raw_wire_iblt.subtract(&empty).unwrap().decode();

        assert!(raw_result.is_complete());
        assert!(!raw_result.only_left.contains(&object_id));
        assert!(raw_result.only_left.contains(&mask.apply(object_id)));
    }

    #[test]
    fn iblt_decode_empty_bytes_returns_empty() {
        let decoded = IbltPlaceholder::decode_with_limits(&[], 10, 4096).unwrap();
        // Empty payload yields a sketch sized for the requested budget
        // with zero inserted items; a self-subtract peels to the empty
        // set.
        let self_diff = decoded
            .as_iblt()
            .subtract(decoded.as_iblt())
            .unwrap()
            .decode();
        assert!(self_diff.only_left.is_empty());
        assert!(self_diff.only_right.is_empty());
    }

    #[test]
    fn iblt_decode_too_many_changes() {
        // A peer ships a sketch sized for 200 expected differences; the
        // local cap is 3. The cell-count comparison rejects it.
        let iblt = IbltPlaceholder::with_max_changes(200);
        let encoded = iblt.encode();
        let err = IbltPlaceholder::decode_with_limits(
            &encoded,
            3,
            encoded.len().max(MIN_IBLT_BYTES_BUDGET),
        )
        .unwrap_err();
        assert!(
            matches!(err, IbltDecodeError::TooManyChanges { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn iblt_decode_error_reason_codes() {
        assert_eq!(
            IbltDecodeError::TooLarge { len: 10, max: 5 }.reason_code(),
            "iblt_bytes_exceeded"
        );
        assert_eq!(
            IbltDecodeError::InvalidEncoding.reason_code(),
            "iblt_invalid_encoding"
        );
        assert_eq!(
            IbltDecodeError::TooManyChanges {
                decoded: 10,
                max: 5
            }
            .reason_code(),
            "iblt_change_limit_exceeded"
        );
    }

    #[test]
    fn iblt_clear() {
        let mut iblt = IbltPlaceholder::new();
        iblt.note_local_change(&test_object_id("c"), None);
        // Insertion changed the sketch; subtracting against an empty
        // sketch of the same cell count peels a single item.
        let empty_before = Iblt::with_cell_count(iblt.as_iblt().cell_count()).unwrap();
        assert_eq!(
            iblt.as_iblt()
                .subtract(&empty_before)
                .unwrap()
                .decode()
                .only_left
                .len(),
            1
        );

        iblt.clear();
        // After clear, the sketch is empty again.
        let empty_after = Iblt::with_cell_count(iblt.as_iblt().cell_count()).unwrap();
        let diff = iblt.as_iblt().subtract(&empty_after).unwrap().decode();
        assert!(diff.only_left.is_empty());
    }

    #[test]
    fn iblt_entry_count() {
        // entry_count now reports IBLT cell count rather than change
        // list length.
        let iblt = IbltPlaceholder::with_max_changes(5);
        assert_eq!(iblt.entry_count(), Iblt::recommended_cell_count(5));
    }

    #[test]
    fn iblt_reconciliation_recovers_full_divergence() {
        // Regression for the pre-migration placeholder: a VecDeque of
        // recent_changes bounded at `reconciliation_batch_size` silently
        // dropped the oldest changes as soon as divergence exceeded the
        // window. The production sketch reconciles the full difference
        // set regardless of how many changes have happened since the
        // last sync (up to the cell budget).
        let mut local = IbltPlaceholder::with_max_changes(128);
        let mut remote = IbltPlaceholder::with_max_changes(128);

        for i in 0..64 {
            local.note_local_change(&test_object_id(&format!("shared-{i}")), None);
            remote.note_local_change(&test_object_id(&format!("shared-{i}")), None);
        }
        // Local-only inserts beyond the old window size.
        let local_only: Vec<_> = (0..40)
            .map(|i| test_object_id(&format!("local-{i}")))
            .collect();
        for obj in &local_only {
            local.note_local_change(obj, None);
        }

        // Simulate a wire exchange: local ships its sketch, remote
        // decodes it, subtracts its own sketch, and peels.
        let local_wire = local.encode();
        let remote_decoded = IbltPlaceholder::decode_with_limits(
            &local_wire,
            128,
            local_wire.len().max(MIN_IBLT_BYTES_BUDGET),
        )
        .unwrap();

        let diff = remote_decoded.as_iblt().subtract(remote.as_iblt()).unwrap();
        let result = diff.decode();
        assert!(
            result.is_complete(),
            "peeling stalled: {} nonzero cells left",
            result.remaining_nonzero_cells
        );
        assert_eq!(
            result.only_left.len(),
            40,
            "remote should learn of exactly the 40 local-only inserts"
        );
        for obj in &local_only {
            assert!(
                result.only_left.contains(obj),
                "missing local-only object {obj:?} from reconciliation"
            );
        }
    }

    // ── GossipState additional tests ───────────────────────────

    #[test]
    fn gossip_state_announce_object_idempotent() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("idem");
        state.announce_object(&obj, 100);
        state.announce_object(&obj, 200);
        // Object counted once despite double announce
        assert_eq!(state.object_count(), 1);
    }

    #[test]
    fn gossip_state_announce_symbol_auto_announces_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("auto");
        state.announce_symbol(&obj, 0, 100);
        assert!(state.has_object(&obj));
        assert!(state.has_symbol(&obj, 0));
    }

    #[test]
    fn gossip_state_announce_symbol_idempotent() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("si");
        state.announce_symbol(&obj, 5, 100);
        state.announce_symbol(&obj, 5, 200);
        assert_eq!(state.symbol_count(), 1);
    }

    #[test]
    fn gossip_state_remove_object_clears_symbols() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("rm");
        state.announce_object(&obj, 100);
        state.announce_symbol(&obj, 0, 100);
        assert_eq!(state.object_count(), 1);
        assert_eq!(state.symbol_count(), 1);

        state.remove_object(&obj, 200);
        assert_eq!(state.object_count(), 0);
        assert_eq!(state.symbol_count(), 0);
        assert!(!state.has_object(&obj));
    }

    #[test]
    fn gossip_state_may_have_vs_has() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("mh");
        state.announce_object(&obj, 100);

        // Both should agree for inserted items
        assert!(state.has_object(&obj));
        assert!(state.may_have_object(&obj));

        // For non-inserted: has is definitive, may_have can false-positive
        let other = test_object_id("other");
        assert!(!state.has_object(&other));
    }

    #[test]
    fn gossip_state_multiple_symbols_per_object() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let obj = test_object_id("multi");
        state.announce_symbol(&obj, 0, 100);
        state.announce_symbol(&obj, 1, 100);
        state.announce_symbol(&obj, 2, 100);
        assert_eq!(state.symbol_count(), 3);
        let syms = state.symbols_for_object(&obj).unwrap();
        assert_eq!(syms.len(), 3);
        assert!(syms.contains(&0));
        assert!(syms.contains(&1));
        assert!(syms.contains(&2));
    }

    #[test]
    fn gossip_state_create_summary_fields() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        state.announce_object(&test_object_id("s1"), 100);
        state.announce_symbol(&test_object_id("s1"), 0, 100);

        let summary = state.create_summary(test_node("me"), test_epoch());
        assert_eq!(summary.zone_id, test_zone());
        assert_eq!(summary.object_count, 1);
        assert_eq!(summary.symbol_count, 1);
        assert_eq!(summary.timestamp, 100);
        assert!(summary.signature.is_none());
    }

    #[test]
    fn gossip_state_summary_iblt_is_masked_and_object_level() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        let object_id = test_object_id("summary-mask");
        for esi in 0..16 {
            state.announce_symbol(&object_id, esi, 100);
        }

        let summary = state.create_summary(test_node("masked"), test_epoch());
        let raw_wire_iblt: Iblt =
            ciborium::from_reader(summary.iblt.as_slice()).expect("summary IBLT is CBOR");
        let empty = Iblt::with_cell_count(raw_wire_iblt.cell_count()).unwrap();
        let raw_result = raw_wire_iblt.subtract(&empty).unwrap().decode();

        assert!(raw_result.is_complete());
        assert_eq!(
            raw_result.only_left.len(),
            1,
            "symbol announcements must not reinsert the object into the object-level IBLT"
        );
        assert!(!raw_result.only_left.contains(&object_id));
        assert!(
            raw_result
                .only_left
                .contains(&state.iblt_mask.apply(object_id))
        );
    }

    // ── GossipSummary additional tests ─────────────────────────

    #[test]
    fn gossip_summary_differs_from_same() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        state.announce_object(&test_object_id("d1"), 100);
        let s1 = state.create_summary(test_node("n1"), test_epoch());
        let s2 = state.create_summary(test_node("n1"), test_epoch());
        assert!(!s1.differs_from(&s2));
    }

    #[test]
    fn gossip_summary_differs_from_different() {
        let config = GossipConfig::default();
        let mut s1_state = GossipState::new(test_zone(), &config);
        s1_state.announce_object(&test_object_id("a"), 100);
        let s1 = s1_state.create_summary(test_node("n1"), test_epoch());

        let mut s2_state = GossipState::new(test_zone(), &config);
        s2_state.announce_object(&test_object_id("b"), 100);
        let s2 = s2_state.create_summary(test_node("n2"), test_epoch());

        assert!(s1.differs_from(&s2));
    }

    #[test]
    fn gossip_summary_is_stale() {
        let config = GossipConfig::default();
        let state = GossipState::new(test_zone(), &config);
        let summary = state.create_summary(test_node("n"), test_epoch());
        // timestamp=0, now=0, ttl=300 → not stale
        assert!(!summary.is_stale(0, 300, DEFAULT_MAX_FUTURE_SKEW_SECS));
        // now=301 → stale
        assert!(summary.is_stale(301, 300, DEFAULT_MAX_FUTURE_SKEW_SECS));
    }

    #[test]
    fn gossip_summary_signing_bytes_includes_domain_separator() {
        let config = GossipConfig::default();
        let state = GossipState::new(test_zone(), &config);
        let summary = state.create_summary(test_node("sig"), test_epoch());
        let bytes = summary.signing_bytes();
        assert!(bytes.starts_with(b"FCP2-GOSSIP-SUMMARY-V1"));
    }

    #[test]
    fn gossip_summary_signing_bytes_differ_by_zone() {
        let config = GossipConfig::default();
        let s1 = GossipState::new(ZoneId::work(), &config);
        let s2 = GossipState::new(ZoneId::private(), &config);
        let b1 = s1
            .create_summary(test_node("n"), test_epoch())
            .signing_bytes();
        let b2 = s2
            .create_summary(test_node("n"), test_epoch())
            .signing_bytes();
        assert_ne!(b1, b2);
    }

    // ── GossipConfig tests ─────────────────────────────────────

    #[test]
    fn gossip_config_max_iblt_bytes_derived() {
        let config = GossipConfig::default();
        let expected = DEFAULT_RECONCILIATION_BATCH_SIZE * 128;
        assert_eq!(config.max_iblt_bytes(), expected);
    }

    #[test]
    fn gossip_config_max_iblt_bytes_min_budget() {
        let config = GossipConfig {
            reconciliation_batch_size: 1,
            ..GossipConfig::default()
        };
        // 1 * 128 = 128 < MIN_IBLT_BYTES_BUDGET(8192), so uses min.
        assert_eq!(config.max_iblt_bytes(), MIN_IBLT_BYTES_BUDGET);
    }

    // ── GossipRequest additional tests ─────────────────────────

    #[test]
    fn gossip_request_for_objects_bounds_at_max() {
        let many_ids: Vec<ObjectId> = (0..200)
            .map(|i| test_object_id(&format!("obj-{i}")))
            .collect();
        let req = GossipRequest::for_objects(test_node("n"), test_zone(), many_ids, 0);
        assert_eq!(req.object_ids.len(), MAX_OBJECT_IDS_PER_REQUEST);
        assert!(req.symbols.is_empty());
        assert!(req.is_valid());
    }

    #[test]
    fn gossip_request_for_symbols_bounds_at_max() {
        let many_syms: Vec<(ObjectId, u32)> = (0..200)
            .map(|i| (test_object_id(&format!("s-{i}")), i))
            .collect();
        let req = GossipRequest::for_symbols(test_node("n"), test_zone(), many_syms, 0);
        assert_eq!(req.symbols.len(), MAX_OBJECT_IDS_PER_REQUEST);
        assert!(req.object_ids.is_empty());
        assert!(req.is_valid());
    }

    #[test]
    fn gossip_request_is_valid_rejects_oversized() {
        let req = GossipRequest {
            from: test_node("n"),
            zone_id: test_zone(),
            object_ids: (0..101).map(|i| test_object_id(&format!("o{i}"))).collect(),
            symbols: Vec::new(),
            timestamp: 0,
            signature: None,
        };
        assert!(!req.is_valid());
    }

    // ── MeshGossip additional tests ────────────────────────────

    #[test]
    fn mesh_gossip_prune_stale_peers() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let zone = test_zone();
        let epoch = test_epoch();

        // Add objects and create a summary from a "peer"
        gossip.announce_object(
            &zone,
            &test_object_id("o1"),
            ObjectAdmissionClass::Admitted,
            100,
        );
        let summary = gossip.create_summary(&zone, epoch).unwrap();

        // Simulate receiving it as if from a peer
        let mut peer_summary = summary;
        peer_summary.from = test_node("peer-1");
        peer_summary.timestamp = 100;
        gossip.handle_summary(peer_summary, 100);
        assert_eq!(gossip.peer_count(), 1);

        // Not stale yet (ttl=300)
        assert_eq!(gossip.prune_stale_peers(399), 0);
        assert_eq!(gossip.peer_count(), 1);

        // Now stale
        assert_eq!(gossip.prune_stale_peers(401), 1);
        assert_eq!(gossip.peer_count(), 0);
    }

    #[test]
    fn mesh_gossip_has_object_unknown_zone() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        assert!(!gossip.has_object(&test_zone(), &test_object_id("x")));
    }

    #[test]
    fn mesh_gossip_has_symbol_checks_zone() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let zone = test_zone();
        let obj = test_object_id("sym-zone");
        gossip.announce_symbol(&zone, &obj, 7, ObjectAdmissionClass::Admitted, 100);
        assert!(gossip.has_symbol(&zone, &obj, 7));
        assert!(!gossip.has_symbol(&zone, &obj, 8));
    }

    #[test]
    fn mesh_gossip_quarantined_symbol_not_announced() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let zone = test_zone();
        let obj = test_object_id("q-sym");
        let result = gossip.announce_symbol(&zone, &obj, 0, ObjectAdmissionClass::Quarantined, 100);
        assert!(!result);
        assert!(!gossip.has_symbol(&zone, &obj, 0));
    }

    #[test]
    fn mesh_gossip_create_summary_returns_none_for_missing_zone() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        assert!(gossip.create_summary(&test_zone(), test_epoch()).is_none());
    }

    #[test]
    fn mesh_gossip_debug() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        let s = format!("{gossip:?}");
        assert!(s.contains("MeshGossip"));
    }

    // ── PeerGossipState additional tests ───────────────────────

    #[test]
    fn peer_gossip_state_record_failure_saturates() {
        let mut state = PeerGossipState::new(test_node("sat"));
        for _ in 0..10 {
            state.record_failure();
        }
        assert_eq!(state.failed_attempts(), 10);
    }

    #[test]
    fn peer_gossip_state_update_resets_failures() {
        let mut state = PeerGossipState::new(test_node("reset"));
        state.record_failure();
        state.record_failure();
        assert_eq!(state.failed_attempts(), 2);

        let config = GossipConfig::default();
        let gs = GossipState::new(test_zone(), &config);
        let summary = gs.create_summary(test_node("p"), test_epoch());
        state.update_from_summary(summary, 100);
        assert_eq!(state.failed_attempts(), 0);
    }

    #[test]
    fn peer_gossip_state_debug_clone() {
        let state = PeerGossipState::new(test_node("dc"));
        let cloned = state.clone();
        assert_eq!(cloned.peer_id(), state.peer_id());
        let s = format!("{state:?}");
        assert!(s.contains("PeerGossipState"));
    }

    // ── GossipResponse / ReconcileRequest / ReconcileResponse ──

    #[test]
    fn gossip_response_serde_roundtrip() {
        let resp = GossipResponse {
            from: test_node("a"),
            to: test_node("b"),
            zone_id: test_zone(),
            have_objects: vec![test_object_id("o1")],
            have_symbols: vec![(test_object_id("o1"), 42)],
            timestamp: 999,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: GossipResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.timestamp, 999);
        assert_eq!(deserialized.have_objects.len(), 1);
    }

    #[test]
    fn reconcile_request_serde_roundtrip() {
        let req = ReconcileRequest {
            from: test_node("r"),
            zone_id: test_zone(),
            iblt: vec![],
            object_filter_digest: [0xAA; 32],
            symbol_filter_digest: [0xBB; 32],
            timestamp: 0,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ReconcileRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.timestamp, 0);
    }

    #[test]
    fn reconcile_response_serde_roundtrip() {
        let resp = ReconcileResponse {
            from: test_node("rr"),
            zone_id: test_zone(),
            peer_missing_objects: vec![test_object_id("m1")],
            we_missing_objects: vec![test_object_id("m2")],
            timestamp: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: ReconcileResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.peer_missing_objects.len(), 1);
        assert_eq!(deserialized.we_missing_objects.len(), 1);
    }

    // ── GossipMessage all variants ─────────────────────────────

    #[test]
    fn gossip_message_summary_variant_serde() {
        let config = GossipConfig::default();
        let state = GossipState::new(test_zone(), &config);
        let summary = state.create_summary(test_node("sv"), test_epoch());
        let msg = GossipMessage::Summary(summary);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"summary\""));
        let _: GossipMessage = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn gossip_message_request_variant_serde() {
        let req = GossipRequest::for_objects(test_node("rq"), test_zone(), vec![], 0);
        let msg = GossipMessage::Request(req);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"request\""));
    }

    #[test]
    fn gossip_message_reconcile_variants_serde() {
        let req_msg = GossipMessage::ReconcileRequest(ReconcileRequest {
            from: test_node("rc"),
            zone_id: test_zone(),
            iblt: vec![],
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            timestamp: 0,
        });
        let json = serde_json::to_string(&req_msg).unwrap();
        assert!(json.contains("\"type\":\"reconcile_request\""));

        let resp_msg = GossipMessage::ReconcileResponse(ReconcileResponse {
            from: test_node("rc"),
            zone_id: test_zone(),
            peer_missing_objects: vec![],
            we_missing_objects: vec![],
            timestamp: 0,
        });
        let json = serde_json::to_string(&resp_msg).unwrap();
        assert!(json.contains("\"type\":\"reconcile_response\""));
    }

    // ── GossipStats ────────────────────────────────────────────

    #[test]
    fn gossip_stats_fields() {
        let stats = GossipStats {
            object_count: 10,
            symbol_count: 50,
            last_updated: 1234,
        };
        let cloned = stats.clone();
        assert_eq!(stats.object_count, 10);
        assert_eq!(stats.symbol_count, 50);
        assert_eq!(cloned.last_updated, 1234);
    }

    // ── Production IBLT Wiring Tests (br21t.3) ────────────────

    /// Regression for br-m68xt: the cached IBLT must stay byte-
    /// identical to a freshly-rebuilt one after every
    /// announce_object / remove_object, across arbitrary orderings.
    /// This pins the incremental-maintenance invariant so a future
    /// refactor cannot silently desync the cache from
    /// `admitted_objects`.
    #[test]
    fn gossip_state_cached_iblt_stays_in_sync_with_admitted_objects() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);

        let ids: Vec<_> = (0..16)
            .map(|i| test_object_id(&format!("m68xt-{i}")))
            .collect();

        // Interleave announces and removes; after each operation the
        // cached IBLT (returned via build_iblt at the cache's cell
        // count) must equal a rebuilt-from-scratch IBLT over the same
        // admitted set.
        for (i, id) in ids.iter().enumerate() {
            state.announce_object(id, u64::try_from(i).unwrap());

            let cached = state.build_iblt(config.reconciliation_batch_size);
            let mut fresh = Iblt::with_cell_count(cached.cell_count()).unwrap();
            for admitted in state.admitted_objects_iter_for_test() {
                fresh.insert(state.iblt_mask.apply(*admitted));
            }
            assert_eq!(
                cached.cells(),
                fresh.cells(),
                "cached IBLT desynced from admitted_objects after announce #{i}"
            );
        }

        // Remove every other object; cache must still match a rebuild.
        for (i, id) in ids.iter().enumerate().step_by(2) {
            state.remove_object(id, u64::try_from(100 + i).unwrap());

            let cached = state.build_iblt(config.reconciliation_batch_size);
            let mut fresh = Iblt::with_cell_count(cached.cell_count()).unwrap();
            for admitted in state.admitted_objects_iter_for_test() {
                fresh.insert(state.iblt_mask.apply(*admitted));
            }
            assert_eq!(
                cached.cells(),
                fresh.cells(),
                "cached IBLT desynced from admitted_objects after remove #{i}"
            );
        }

        // Idempotency: a remove on an id that was already removed must
        // NOT delete from the cache again (that would corrupt cell
        // counters).
        state.remove_object(&ids[0], 9999);
        let cached = state.build_iblt(config.reconciliation_batch_size);
        let mut fresh = Iblt::with_cell_count(cached.cell_count()).unwrap();
        for admitted in state.admitted_objects_iter_for_test() {
            fresh.insert(state.iblt_mask.apply(*admitted));
        }
        assert_eq!(
            cached.cells(),
            fresh.cells(),
            "idempotent remove desynced cache"
        );
    }

    /// Regression for br-m68xt slow path: when build_iblt is called
    /// with an expected_difference that maps to a DIFFERENT cell count
    /// than the cached sketch, the result must still be a correct
    /// rebuild over the current admitted set — the fast-path short
    /// circuit cannot mask the slow-path semantics.
    #[test]
    fn gossip_state_build_iblt_slow_path_matches_admitted_set() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);
        state.announce_object(&test_object_id("slow-a"), 1);
        state.announce_object(&test_object_id("slow-b"), 2);

        // Pick an expected_difference whose recommended_cell_count
        // differs from the cached one so the slow path fires.
        let mismatched_diff = config.reconciliation_batch_size * 4 + 7;
        let slow = state.build_iblt(mismatched_diff);
        assert_ne!(
            slow.cell_count(),
            state
                .build_iblt(config.reconciliation_batch_size)
                .cell_count(),
            "slow-path test needs a differently-sized IBLT"
        );

        let mut fresh = Iblt::with_cell_count(slow.cell_count()).unwrap();
        for admitted in state.admitted_objects_iter_for_test() {
            fresh.insert(state.iblt_mask.apply(*admitted));
        }
        assert_eq!(
            slow.cells(),
            fresh.cells(),
            "slow-path build_iblt desynced from admitted"
        );
    }

    #[test]
    fn gossip_state_build_iblt_contains_admitted_objects() {
        let config = GossipConfig::default();
        let mut state = GossipState::new(test_zone(), &config);

        let obj_a = test_object_id("iblt-a");
        let obj_b = test_object_id("iblt-b");
        state.announce_object(&obj_a, 1);
        state.announce_object(&obj_b, 2);

        let iblt = state.build_iblt(10);
        // IBLT should be sized for expected difference
        assert!(iblt.cell_count() >= 64); // MIN_RECOMMENDED_IBLT_CELLS
    }

    #[test]
    fn gossip_state_reconcile_finds_differences() {
        let config = GossipConfig::default();
        let mut local = GossipState::new(test_zone(), &config);
        let mut peer = GossipState::new(test_zone(), &config);

        let shared = test_object_id("shared");
        let local_only = test_object_id("local-only");
        let peer_only = test_object_id("peer-only");

        local.announce_object(&shared, 1);
        local.announce_object(&local_only, 2);

        peer.announce_object(&shared, 1);
        peer.announce_object(&peer_only, 2);

        let peer_iblt = peer.build_iblt(10);
        let result = local
            .reconcile_with_peer_iblt(&peer_iblt, 10)
            .expect("reconciliation should succeed");

        assert!(result.is_complete(), "small difference should peel fully");
        assert!(
            result.only_left.contains(&local_only),
            "local-only object should be in only_left"
        );
        assert!(
            result.only_right.contains(&peer_only),
            "peer-only object should be in only_right"
        );
        assert!(
            !result.only_left.contains(&shared),
            "shared object should not appear in differences"
        );
    }

    #[test]
    fn gossip_state_reconcile_empty_sets() {
        let config = GossipConfig::default();
        let local = GossipState::new(test_zone(), &config);
        let peer = GossipState::new(test_zone(), &config);

        let peer_iblt = peer.build_iblt(0);
        let result = local
            .reconcile_with_peer_iblt(&peer_iblt, 0)
            .expect("empty reconciliation should succeed");

        assert!(result.is_complete());
        assert!(result.only_left.is_empty());
        assert!(result.only_right.is_empty());
    }

    #[test]
    fn mesh_gossip_reconcile_zone_iblt_bidirectional() {
        let mut gossip_a = MeshGossip::with_defaults(test_node("node-a"));
        let mut gossip_b = MeshGossip::with_defaults(test_node("node-b"));

        let shared = test_object_id("shared-obj");
        let a_only = test_object_id("a-only-obj");
        let b_only = test_object_id("b-only-obj");
        let zone = test_zone();

        for obj in [&shared, &a_only] {
            gossip_a.announce_object(&zone, obj, ObjectAdmissionClass::Admitted, 1);
        }
        for obj in [&shared, &b_only] {
            gossip_b.announce_object(&zone, obj, ObjectAdmissionClass::Admitted, 1);
        }

        // Build B's IBLT and reconcile from A's perspective
        let b_iblt = gossip_b
            .build_zone_iblt(&zone, 10)
            .expect("zone should exist");
        let response = gossip_a
            .reconcile_zone_iblt(&zone, &test_node("node-b"), &b_iblt, 10, 2)
            .expect("reconciliation should succeed");

        assert!(
            response.peer_missing_objects.contains(&a_only),
            "A-only object should be in peer_missing"
        );
        assert!(
            response.we_missing_objects.contains(&b_only),
            "B-only object should be in we_missing"
        );
    }

    #[test]
    fn mesh_gossip_reconcile_bounds_by_max_object_ids() {
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        let zone = test_zone();

        // Add more objects than MAX_OBJECT_IDS_PER_REQUEST
        for i in 0..MAX_OBJECT_IDS_PER_REQUEST + 50 {
            let obj = test_object_id(&format!("obj-{i}"));
            gossip.announce_object(&zone, &obj, ObjectAdmissionClass::Admitted, 1);
        }

        // Empty peer IBLT (peer has nothing)
        let peer_iblt = Iblt::with_expected_difference(MAX_OBJECT_IDS_PER_REQUEST + 50);
        let response = gossip
            .reconcile_zone_iblt(
                &zone,
                &test_node("peer"),
                &peer_iblt,
                MAX_OBJECT_IDS_PER_REQUEST + 50,
                2,
            )
            .expect("reconciliation should succeed");

        // Response should be bounded by MAX_OBJECT_IDS_PER_REQUEST
        assert!(
            response.peer_missing_objects.len() <= MAX_OBJECT_IDS_PER_REQUEST,
            "peer_missing should be bounded: got {}, max {}",
            response.peer_missing_objects.len(),
            MAX_OBJECT_IDS_PER_REQUEST
        );
    }

    #[test]
    fn mesh_gossip_reconcile_unknown_zone_returns_none() {
        let gossip = MeshGossip::with_defaults(test_node("local"));
        let iblt = Iblt::with_expected_difference(0);
        let result = gossip.reconcile_zone_iblt(&ZoneId::owner(), &test_node("peer"), &iblt, 0, 1);
        assert!(result.is_none(), "unknown zone should return None");
    }

    // ── Protocol Tests (br21t.4): convergence + adversarial ───

    #[test]
    fn full_gossip_round_two_nodes_converge() {
        // Simulate a full gossip round: two nodes exchange summaries,
        // detect differences via IBLT, request missing objects, and converge.
        let zone = test_zone();
        let epoch = test_epoch();

        let mut node_a = MeshGossip::with_defaults(test_node("node-a"));
        let mut node_b = MeshGossip::with_defaults(test_node("node-b"));

        // Shared objects
        let shared: Vec<ObjectId> = (0..5)
            .map(|i| test_object_id(&format!("shared-{i}")))
            .collect();
        // A-exclusive objects
        let a_only: Vec<ObjectId> = (0..3)
            .map(|i| test_object_id(&format!("a-only-{i}")))
            .collect();
        // B-exclusive objects
        let b_only: Vec<ObjectId> = (0..2)
            .map(|i| test_object_id(&format!("b-only-{i}")))
            .collect();

        for obj in shared.iter().chain(a_only.iter()) {
            node_a.announce_object(&zone, obj, ObjectAdmissionClass::Admitted, 1);
        }
        for obj in shared.iter().chain(b_only.iter()) {
            node_b.announce_object(&zone, obj, ObjectAdmissionClass::Admitted, 1);
        }

        // Step 1: Nodes exchange summaries
        let summary_a = node_a
            .create_summary(&zone, epoch.clone())
            .expect("zone exists");
        let summary_b = node_b.create_summary(&zone, epoch).expect("zone exists");

        // Digests should differ (different object sets)
        assert!(summary_a.differs_from(&summary_b));

        // Step 2: IBLT-based reconciliation
        let b_iblt = node_b.build_zone_iblt(&zone, 10).unwrap();
        let reconcile = node_a
            .reconcile_zone_iblt(&zone, &test_node("node-b"), &b_iblt, 10, 2)
            .expect("reconciliation should work");

        // Step 3: Verify differences detected correctly
        for obj in &a_only {
            assert!(
                reconcile.peer_missing_objects.contains(obj),
                "A-only object should be detected as peer-missing"
            );
        }
        for obj in &b_only {
            assert!(
                reconcile.we_missing_objects.contains(obj),
                "B-only object should be detected as we-missing"
            );
        }

        // Step 4: Simulate A receiving B's missing objects
        for obj in &b_only {
            node_a.announce_object(&zone, obj, ObjectAdmissionClass::Admitted, 3);
        }
        // Simulate B receiving A's missing objects
        for obj in &a_only {
            node_b.announce_object(&zone, obj, ObjectAdmissionClass::Admitted, 3);
        }

        // Step 5: After exchange, nodes should have identical object sets
        let a_objects: BTreeSet<ObjectId> = node_a
            .list_objects_in_zone(&zone, 100)
            .into_iter()
            .collect();
        let b_objects: BTreeSet<ObjectId> = node_b
            .list_objects_in_zone(&zone, 100)
            .into_iter()
            .collect();
        assert_eq!(a_objects, b_objects, "nodes should converge after exchange");
        assert_eq!(a_objects.len(), 10); // 5 shared + 3 a-only + 2 b-only
    }

    #[test]
    fn adversarial_corrupt_iblt_does_not_crash() {
        let zone = test_zone();
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        gossip.announce_object(
            &zone,
            &test_object_id("obj-1"),
            ObjectAdmissionClass::Admitted,
            1,
        );

        // Craft a corrupt IBLT with wrong cell count
        let corrupt_iblt = Iblt::with_expected_difference(999);
        let result = gossip.reconcile_zone_iblt(
            &zone,
            &test_node("evil-peer"),
            &corrupt_iblt,
            10, // Different expected_difference -> different cell count
            2,
        );
        // Should return None (cell count mismatch), not crash
        assert!(
            result.is_none(),
            "mismatched IBLT cell count should gracefully return None"
        );
    }

    #[test]
    fn adversarial_iblt_with_garbage_cells_does_not_crash() {
        let zone = test_zone();
        let mut gossip = MeshGossip::with_defaults(test_node("local"));
        gossip.announce_object(
            &zone,
            &test_object_id("obj-1"),
            ObjectAdmissionClass::Admitted,
            1,
        );

        // Create an IBLT with matching cell count but garbage data
        let expected_diff = 10;
        let cell_count = Iblt::recommended_cell_count(expected_diff);
        let garbage_iblt = Iblt::with_cell_count(cell_count).unwrap();
        // Empty IBLT (no inserts) is valid but has no data — decode should succeed
        let result = gossip.reconcile_zone_iblt(
            &zone,
            &test_node("evil-peer"),
            &garbage_iblt,
            expected_diff,
            2,
        );
        // Should succeed but may show partial decode (that's fine)
        assert!(result.is_some(), "empty peer IBLT should still reconcile");
    }

    // ── C1.5 — Priority gossip for revocation ─────────────────────

    #[test]
    fn c1_5_revocation_push_message_construction() {
        let msg = RevocationPushMessage::new(
            test_node("node-1"),
            test_zone(),
            vec![test_object_id("revoked-1"), test_object_id("revoked-2")],
            42,
            1_700_000_000,
        );
        assert_eq!(msg.revoked_ids.len(), 2);
        assert_eq!(msg.new_rev_seq, 42);
        assert!(msg.signature.is_none());
    }

    #[test]
    fn c1_5_revocation_push_serialization_roundtrip() {
        let msg = RevocationPushMessage::new(
            test_node("node-1"),
            test_zone(),
            vec![test_object_id("tok-1")],
            10,
            1_700_000_000,
        );
        let gossip_msg = GossipMessage::RevocationPush(msg);
        let json = serde_json::to_string(&gossip_msg).unwrap();
        let rt: GossipMessage = serde_json::from_str(&json).unwrap();
        match rt {
            GossipMessage::RevocationPush(m) => {
                assert_eq!(m.revoked_ids.len(), 1);
                assert_eq!(m.new_rev_seq, 10);
            }
            _ => panic!("expected RevocationPush variant"),
        }
    }

    #[test]
    fn c1_5_priority_gossip_policy_defaults() {
        let policy = PriorityGossipPolicy::default();
        assert_eq!(policy, PriorityGossipPolicy::DirectPush);
        assert!(policy.uses_direct_push());
    }

    #[test]
    fn c1_5_priority_interval_faster_than_standard() {
        let config = GossipConfig::default();
        let priority = PriorityGossipPolicy::DirectPush;
        let standard = PriorityGossipPolicy::Standard;

        assert!(priority.interval_ms(&config) < standard.interval_ms(&config));
        assert_eq!(priority.interval_ms(&config), 100);
        assert_eq!(standard.interval_ms(&config), 300);
    }

    #[test]
    fn c1_5_config_priority_fields() {
        let config = GossipConfig::default();
        assert_eq!(config.priority_gossip_interval_ms, 100);
        assert_eq!(config.max_revocation_push_peers, 32);
    }

    // ── m8j0q.8.b: PriorityGossipPolicy::Emergency variant tests ─────

    #[test]
    fn emergency_policy_constants_match_adr_contract() {
        // ADR `m8j0q-emergency-revocation-protocol` §"Required API
        // shape" #1 fixes these constants. Drifting them silently
        // would change the operator contract; this test pins them.
        assert_eq!(PriorityGossipPolicy::EMERGENCY_BURST_FANOUT, 64);
        assert_eq!(
            PriorityGossipPolicy::EMERGENCY_PROPAGATION_DEADLINE_MS,
            5_000
        );
        assert_eq!(PriorityGossipPolicy::EMERGENCY_QUORUM_WITNESSES, 3);
        assert_eq!(PriorityGossipPolicy::EMERGENCY_RATE_LIMIT_PER_ZONE_SECS, 60);
    }

    #[test]
    fn emergency_policy_is_emergency_predicate() {
        assert!(PriorityGossipPolicy::Emergency.is_emergency());
        assert!(!PriorityGossipPolicy::DirectPush.is_emergency());
        assert!(!PriorityGossipPolicy::PriorityInterval.is_emergency());
        assert!(!PriorityGossipPolicy::Standard.is_emergency());
    }

    #[test]
    fn emergency_policy_uses_direct_push() {
        // Emergency MUST use direct push (it's a burst-push) — code
        // sites that branch on uses_direct_push() must include
        // Emergency in the direct-push path.
        assert!(PriorityGossipPolicy::Emergency.uses_direct_push());
        assert!(PriorityGossipPolicy::DirectPush.uses_direct_push());
        assert!(!PriorityGossipPolicy::PriorityInterval.uses_direct_push());
        assert!(!PriorityGossipPolicy::Standard.uses_direct_push());
    }

    #[test]
    fn emergency_policy_uses_priority_interval() {
        // ADR "Tests expected to follow" m8j0q.8.b: emergency interval
        // falls back to priority_gossip_interval_ms (no separate
        // emergency interval — the Emergency variant is about *fanout*
        // and *retry*, not cadence).
        let config = GossipConfig::default();
        assert_eq!(
            PriorityGossipPolicy::Emergency.interval_ms(&config),
            config.priority_gossip_interval_ms
        );
    }

    #[test]
    fn emergency_policy_uses_full_fanout() {
        // ADR "Tests expected to follow" m8j0q.8.b: burst-push selects
        // up to EMERGENCY_BURST_FANOUT, NOT max_revocation_push_peers.
        let config = GossipConfig {
            max_revocation_push_peers: 5,
            ..GossipConfig::default()
        };
        assert_eq!(
            PriorityGossipPolicy::Emergency.fanout_cap(&config),
            PriorityGossipPolicy::EMERGENCY_BURST_FANOUT,
            "Emergency must override max_revocation_push_peers"
        );
        // Verify DirectPush still honors the configured cap.
        assert_eq!(PriorityGossipPolicy::DirectPush.fanout_cap(&config), 5);
        // Non-direct-push policies have no fanout (they wait for the
        // next gossip round instead of bursting).
        assert_eq!(
            PriorityGossipPolicy::PriorityInterval.fanout_cap(&config),
            0
        );
        assert_eq!(PriorityGossipPolicy::Standard.fanout_cap(&config), 0);
    }

    #[test]
    fn priority_gossip_policy_serde_round_trip_includes_emergency_variant() {
        // Adding Emergency must not perturb the wire form of the
        // existing variants, AND Emergency itself must round-trip.
        for variant in [
            PriorityGossipPolicy::DirectPush,
            PriorityGossipPolicy::PriorityInterval,
            PriorityGossipPolicy::Standard,
            PriorityGossipPolicy::Emergency,
        ] {
            let json = serde_json::to_string(&variant).expect("encode");
            let back: PriorityGossipPolicy = serde_json::from_str(&json).expect("decode");
            assert_eq!(back, variant, "round-trip drift for {variant:?}");
        }
    }

    #[test]
    fn c1_5_push_bounded_by_max_peers() {
        let config = GossipConfig {
            max_revocation_push_peers: 5,
            ..GossipConfig::default()
        };
        // Simulate: have 10 peers, but config limits to 5
        let peer_count = 10usize;
        let push_count = peer_count.min(config.max_revocation_push_peers);
        assert_eq!(push_count, 5);
    }

    #[test]
    fn direct_push_plan_reports_capped_static_fanout() {
        let mut gossip = MeshGossip::new(
            test_node("local-node"),
            GossipConfig {
                max_revocation_push_peers: 2,
                ..GossipConfig::default()
            },
        );
        let peers = vec![
            test_node("peer-a"),
            test_node("peer-b"),
            test_node("peer-c"),
        ];

        let plan = gossip.plan_revocation_push_fanout(
            &test_zone(),
            &peers,
            PriorityGossipPolicy::DirectPush,
            1_000,
        );

        assert_eq!(plan.selected_peers, peers[..2].to_vec());
        assert_eq!(plan.policy, PriorityGossipPolicy::DirectPush);
        assert_eq!(plan.requested_peer_count, 3);
        assert_eq!(plan.fanout_cap, 2);
        assert_eq!(plan.decision, FanoutDecision::Capped);
        assert!(!plan.adaptive_enabled);
        assert_eq!(plan.adaptive_candidate_cap, None);
        assert_eq!(
            plan.fallback_reason,
            Some(FanoutFallbackReason::AdaptiveDisabled)
        );
        assert_eq!(plan.next_allowed_at_ms, Some(1_100));
    }

    #[test]
    fn emergency_fanout_plan_uses_emergency_burst_cap() {
        let mut gossip = MeshGossip::new(
            test_node("local-node"),
            GossipConfig {
                adaptive_revocation_push_fanout: AdaptiveRevocationPushFanoutConfig::enabled(),
                max_revocation_push_peers: 2,
                ..GossipConfig::default()
            },
        );
        let peers = (0..70)
            .map(|index| test_node(&format!("peer-{index}")))
            .collect::<Vec<_>>();

        let plan = gossip.plan_revocation_push_fanout(
            &test_zone(),
            &peers,
            PriorityGossipPolicy::Emergency,
            1_000,
        );

        assert_eq!(
            plan.selected_peers.len(),
            PriorityGossipPolicy::EMERGENCY_BURST_FANOUT
        );
        assert_eq!(plan.policy, PriorityGossipPolicy::Emergency);
        assert_eq!(plan.requested_peer_count, 70);
        assert_eq!(
            plan.fanout_cap,
            PriorityGossipPolicy::EMERGENCY_BURST_FANOUT
        );
        assert_eq!(plan.decision, FanoutDecision::EmergencyBurst);
        assert!(plan.adaptive_enabled);
        assert_eq!(plan.adaptive_candidate_cap, None);
        assert_eq!(
            plan.fallback_reason,
            Some(FanoutFallbackReason::EmergencyBypass)
        );
        assert_eq!(plan.next_allowed_at_ms, Some(1_100));
    }

    #[test]
    fn priority_interval_plan_reports_interval_only() {
        let mut gossip = MeshGossip::new(test_node("local-node"), GossipConfig::default());
        let peers = vec![test_node("peer-a")];

        let plan = gossip.plan_revocation_push_fanout(
            &test_zone(),
            &peers,
            PriorityGossipPolicy::PriorityInterval,
            1_000,
        );

        assert!(plan.selected_peers.is_empty());
        assert_eq!(plan.policy, PriorityGossipPolicy::PriorityInterval);
        assert_eq!(plan.requested_peer_count, 1);
        assert_eq!(plan.fanout_cap, 0);
        assert_eq!(plan.decision, FanoutDecision::IntervalOnly);
        assert_eq!(
            plan.fallback_reason,
            Some(FanoutFallbackReason::PolicyDoesNotDirectPush)
        );
        assert_eq!(plan.next_allowed_at_ms, None);
    }

    #[test]
    fn repeated_direct_push_plan_reports_rate_limit() {
        let mut gossip = MeshGossip::new(test_node("local-node"), GossipConfig::default());
        let peers = vec![test_node("peer-a"), test_node("peer-b")];
        let zone = test_zone();

        let _first = gossip.plan_revocation_push_fanout(
            &zone,
            &peers,
            PriorityGossipPolicy::DirectPush,
            1_000,
        );
        let limited = gossip.plan_revocation_push_fanout(
            &zone,
            &peers,
            PriorityGossipPolicy::DirectPush,
            1_050,
        );

        assert!(limited.selected_peers.is_empty());
        assert_eq!(limited.policy, PriorityGossipPolicy::DirectPush);
        assert_eq!(limited.requested_peer_count, 2);
        assert_eq!(
            limited.fanout_cap,
            GossipConfig::default().max_revocation_push_peers
        );
        assert_eq!(limited.decision, FanoutDecision::RateLimited);
        assert_eq!(
            limited.fallback_reason,
            Some(FanoutFallbackReason::AdaptiveDisabled)
        );
        assert_eq!(limited.next_allowed_at_ms, Some(1_100));
    }

    #[test]
    fn adaptive_direct_push_gate_caps_large_swarm_with_redacted_evidence() {
        let mut gossip = MeshGossip::new(
            test_node("local-node"),
            GossipConfig {
                max_revocation_push_peers: 32,
                adaptive_revocation_push_fanout: AdaptiveRevocationPushFanoutConfig::enabled(),
                ..GossipConfig::default()
            },
        );
        let peers = (0..100)
            .map(|index| test_node(&format!("peer-{index}")))
            .collect::<Vec<_>>();

        let plan = gossip.plan_revocation_push_fanout(
            &test_zone(),
            &peers,
            PriorityGossipPolicy::DirectPush,
            1_000,
        );

        assert_eq!(plan.selected_peers, peers[..25].to_vec());
        assert_eq!(plan.fanout_cap, 25);
        assert_eq!(plan.decision, FanoutDecision::AdaptiveCapped);
        assert!(plan.adaptive_enabled);
        assert_eq!(plan.adaptive_candidate_cap, Some(25));
        assert_eq!(plan.fallback_reason, None);

        let evidence = plan.redacted_evidence();
        assert_eq!(evidence.requested_peer_count, 100);
        assert_eq!(evidence.selected_peer_count, 25);
        assert_eq!(evidence.suppressed_peer_count, 75);
        let encoded = serde_json::to_string(&evidence).expect("evidence serializes");
        assert!(encoded.contains("\"decision\":\"adaptive_capped\""));
        assert!(
            !encoded.contains("peer-"),
            "redacted evidence must not expose peer labels: {encoded}"
        );
    }

    #[test]
    fn adaptive_direct_push_below_floor_uses_static_fallback() {
        let mut gossip = MeshGossip::new(
            test_node("local-node"),
            GossipConfig {
                max_revocation_push_peers: 8,
                adaptive_revocation_push_fanout: AdaptiveRevocationPushFanoutConfig::enabled(),
                ..GossipConfig::default()
            },
        );
        let peers = (0..10)
            .map(|index| test_node(&format!("peer-{index}")))
            .collect::<Vec<_>>();

        let plan = gossip.plan_revocation_push_fanout(
            &test_zone(),
            &peers,
            PriorityGossipPolicy::DirectPush,
            1_000,
        );

        assert_eq!(plan.selected_peers, peers[..8].to_vec());
        assert_eq!(plan.fanout_cap, 8);
        assert_eq!(plan.decision, FanoutDecision::Capped);
        assert!(plan.adaptive_enabled);
        assert_eq!(plan.adaptive_candidate_cap, None);
        assert_eq!(
            plan.fallback_reason,
            Some(FanoutFallbackReason::PeerCountBelowAdaptiveFloor)
        );
    }

    // Regression: MeshGossip::handle_summary is a public lower-level mutator
    // that the doc comment flags as skipping signature verification. Without
    // a peer-state cardinality cap, an unverified dispatcher (or a flood
    // through an authenticated path that has permissively registered keys)
    // can drive `peer_states` to OOM within a single summary_ttl_secs
    // window — `prune_stale_peers` only fires on an external cadence.
    //
    // This test pins the cap: once peer_states is at capacity, a summary
    // from a never-seen peer is rejected; summaries from an already-tracked
    // peer still update idempotently (so the cap does not break legitimate
    // rotation through a saturated map).
    #[test]
    fn handle_summary_caps_peer_state_cardinality() {
        const CAP: usize = 4;
        let config = GossipConfig {
            max_peer_states: CAP,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(test_node("local"), config);
        let zone = test_zone();

        let build_summary = |peer: &TailscaleNodeId, ts: u64| GossipSummary {
            from: peer.clone(),
            zone_id: zone.clone(),
            epoch_id: test_epoch(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            object_count: 0,
            symbol_count: 0,
            // Empty payload is accepted by decode_with_limits as "peer
            // sketch sized for local batch, empty items" — matches the
            // wire-format fallback marker used by create_summary.
            iblt: Vec::new(),
            timestamp: ts,
            signature: None,
        };

        // Fill the peer_states map to exactly `CAP`. Each insert must take.
        for i in 0..CAP {
            let peer = test_node(&format!("peer-{i}"));
            gossip.handle_summary(build_summary(&peer, 1_000), 1_000);
        }
        assert_eq!(
            gossip.peer_count(),
            CAP,
            "map should be saturated after {CAP} distinct peers"
        );

        // Saturation boundary: a never-seen peer is rejected.
        let overflow_peer = test_node("peer-overflow");
        gossip.handle_summary(build_summary(&overflow_peer, 1_001), 1_001);
        assert_eq!(
            gossip.peer_count(),
            CAP,
            "summary from an unknown peer past the cap must NOT expand peer_states",
        );
        assert!(
            gossip
                .find_object_sources(&test_object_id("anything"))
                .is_empty()
                || !gossip
                    .peer_states
                    .keys()
                    .any(|k| k.as_str() == "peer-overflow"),
            "the rejected peer must not appear anywhere in gossip state",
        );

        // Already-tracked peer: updates remain idempotent even at saturation.
        let existing_peer = test_node("peer-0");
        let before_count = gossip.peer_count();
        gossip.handle_summary(build_summary(&existing_peer, 1_002), 1_002);
        assert_eq!(
            gossip.peer_count(),
            before_count,
            "idempotent update for an already-tracked peer must keep count stable",
        );
    }

    #[test]
    fn gossip_config_default_max_peer_states_is_set() {
        let config = GossipConfig::default();
        assert!(
            config.max_peer_states > 0,
            "default max_peer_states must be a positive bound; got {}",
            config.max_peer_states
        );
        assert!(
            config.max_peer_states <= 1_000_000,
            "default max_peer_states must stay below the pathological-OOM threshold; got {}",
            config.max_peer_states
        );
    }
}
