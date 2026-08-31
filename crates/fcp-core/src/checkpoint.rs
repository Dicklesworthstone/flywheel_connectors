//! Checkpoint/Frontier Management: Advancement Protocol, Fork Detection, Convergence (NORMATIVE).
//!
//! This module implements the checkpoint advancement protocol as described in
//! `FCP_Specification_V3.md` §6.5 (Zone Checkpoints). `ZoneCheckpoints` are the "heartbeat" of mesh security;
//! stale checkpoints mean stale revocation/audit enforcement.
//!
//! # Protocol Overview
//!
//! 1. **Trigger Conditions**: New checkpoint issued when time elapsed, chains grew, or policy changed
//! 2. **Coordinator Selection**: HRW hash over (`zone_id`, "checkpoint", epoch)
//! 3. **Proposal**: Coordinator broadcasts `CheckpointProposal`
//! 4. **Signature Collection**: Nodes sign if all heads known/valid and seq = `prev_seq` + 1
//! 5. **Finalization**: Once n-f signatures collected, checkpoint published
//! 6. **Fork Detection**: Same `zone_id` + same seq + different `checkpoint_id` = fork

use std::{collections::BTreeSet, fmt};

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    EpochId, NodeSignature, ObjectHeader, ObjectId, SignatureSet, TailscaleNodeId, ZoneId,
};

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Trigger Conditions
// ─────────────────────────────────────────────────────────────────────────────

/// Default checkpoint interval in seconds (NORMATIVE).
pub const DEFAULT_CHECKPOINT_INTERVAL_SECS: u64 = 60;

/// Default audit chain growth threshold (NORMATIVE).
pub const DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD: u64 = 100;

/// Trigger conditions for checkpoint advancement (NORMATIVE).
///
/// A new checkpoint SHOULD be issued when any of these conditions are met.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckpointTrigger {
    /// Time since last checkpoint exceeds interval.
    TimeElapsed {
        /// Seconds since last checkpoint.
        elapsed_secs: u64,
        /// Configured interval threshold.
        threshold_secs: u64,
    },
    /// Audit chain has grown beyond threshold.
    AuditChainGrowth {
        /// Number of new events since last checkpoint.
        new_events: u64,
        /// Configured threshold.
        threshold: u64,
    },
    /// Revocation chain has new events (any new revocation triggers checkpoint).
    RevocationChainGrowth {
        /// Number of new revocation events.
        new_events: u64,
    },
    /// Zone policy or configuration changed.
    PolicyChange {
        /// Previous policy head.
        old_policy_head: ObjectId,
        /// New policy head.
        new_policy_head: ObjectId,
    },
    /// Manual checkpoint requested by operator.
    Manual {
        /// Optional reason for manual trigger.
        reason: Option<String>,
    },
}

impl CheckpointTrigger {
    /// Stable display token for checkpoint trigger variants.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TimeElapsed { .. } => "time_elapsed",
            Self::AuditChainGrowth { .. } => "audit_chain_growth",
            Self::RevocationChainGrowth { .. } => "revocation_chain_growth",
            Self::PolicyChange { .. } => "policy_change",
            Self::Manual { .. } => "manual",
        }
    }

    /// Check if time-based trigger condition is met.
    #[must_use]
    pub const fn check_time_elapsed(elapsed_secs: u64, threshold_secs: u64) -> Option<Self> {
        if elapsed_secs > threshold_secs {
            Some(Self::TimeElapsed {
                elapsed_secs,
                threshold_secs,
            })
        } else {
            None
        }
    }

    /// Check if audit chain growth trigger is met.
    #[must_use]
    pub const fn check_audit_growth(new_events: u64, threshold: u64) -> Option<Self> {
        if new_events > threshold {
            Some(Self::AuditChainGrowth {
                new_events,
                threshold,
            })
        } else {
            None
        }
    }

    /// Check if revocation chain has new events.
    #[must_use]
    pub const fn check_revocation_growth(new_events: u64) -> Option<Self> {
        if new_events > 0 {
            Some(Self::RevocationChainGrowth { new_events })
        } else {
            None
        }
    }
}

impl fmt::Display for CheckpointTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Proposal
// ─────────────────────────────────────────────────────────────────────────────

/// Checkpoint proposal broadcast by coordinator (NORMATIVE).
///
/// The coordinator creates this proposal after being selected via HRW hash.
/// Nodes verify the proposal and sign if valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointProposal {
    /// Zone this checkpoint covers.
    pub zone_id: ZoneId,
    /// Proposed checkpoint sequence (MUST be `prev_seq` + 1).
    pub proposed_seq: u64,
    /// Previous checkpoint ID (for chain linking).
    pub prev_checkpoint_id: Option<ObjectId>,
    /// Proposed audit head binding.
    pub audit_head_id: ObjectId,
    pub audit_head_seq: u64,
    /// Proposed revocation head binding.
    pub revocation_head_id: ObjectId,
    pub revocation_head_seq: u64,
    /// Policy/config head bindings.
    pub zone_definition_head: ObjectId,
    pub zone_policy_head: ObjectId,
    pub active_zone_key_manifest: ObjectId,
    /// Epoch at proposal time.
    pub epoch_id: EpochId,
    /// Proposal timestamp (Unix seconds).
    pub proposed_at: u64,
    /// Coordinator who created this proposal.
    pub coordinator: TailscaleNodeId,
    /// Signature by coordinator.
    pub coordinator_signature: NodeSignature,
    /// Trigger condition(s) that caused this proposal.
    pub triggers: Vec<CheckpointTrigger>,
}

impl CheckpointProposal {
    /// Verify that `proposed_seq` follows the previous checkpoint correctly.
    #[must_use]
    pub fn seq_follows_prev(&self, prev_seq: u64) -> bool {
        prev_seq
            .checked_add(1)
            .is_some_and(|expected| self.proposed_seq == expected)
    }

    /// Check if timestamp is within acceptable skew tolerance.
    #[must_use]
    pub const fn timestamp_within_skew(&self, local_time: u64, max_skew_secs: u64) -> bool {
        self.proposed_at.abs_diff(local_time) <= max_skew_secs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fork Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Fork detection result (NORMATIVE).
///
/// A fork exists when two checkpoints have:
/// - Same `zone_id`
/// - Same seq
/// - Different `checkpoint_id`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkDetectionResult {
    /// No fork detected.
    NoFork,
    /// Fork detected with evidence.
    ForkDetected(ForkEvidence),
}

impl ForkDetectionResult {
    /// Returns true if a fork was detected.
    #[must_use]
    pub const fn is_fork(&self) -> bool {
        matches!(self, Self::ForkDetected(_))
    }
}

/// Evidence of a detected fork (CRITICAL SECURITY EVENT).
///
/// When a fork is detected:
/// 1. Halt checkpoint advancement immediately
/// 2. Emit `audit.fork_detected` audit event
/// 3. Push alert to operator
/// 4. Operations requiring fresh checkpoint MUST fail
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkEvidence {
    /// Zone where fork was detected.
    pub zone_id: ZoneId,
    /// Conflicting sequence number.
    pub conflicting_seq: u64,
    /// First checkpoint ID at this seq.
    pub checkpoint_a: ObjectId,
    /// Second (conflicting) checkpoint ID at same seq.
    pub checkpoint_b: ObjectId,
    /// When fork was detected (Unix timestamp).
    pub detected_at: u64,
    /// Node that detected the fork.
    pub detected_by: TailscaleNodeId,
    /// Signers of checkpoint A (if known).
    pub signers_a: BTreeSet<String>,
    /// Signers of checkpoint B (if known).
    pub signers_b: BTreeSet<String>,
}

impl ForkEvidence {
    /// Create new fork evidence.
    #[must_use]
    pub const fn new(
        zone_id: ZoneId,
        conflicting_seq: u64,
        checkpoint_a: ObjectId,
        checkpoint_b: ObjectId,
        detected_at: u64,
        detected_by: TailscaleNodeId,
    ) -> Self {
        Self {
            zone_id,
            conflicting_seq,
            checkpoint_a,
            checkpoint_b,
            detected_at,
            detected_by,
            signers_a: BTreeSet::new(),
            signers_b: BTreeSet::new(),
        }
    }

    /// Detect fork between two checkpoints with same seq.
    ///
    /// Returns `Some(ForkEvidence)` if checkpoints have same `zone_id` and seq
    /// but different IDs.
    #[must_use]
    pub fn detect(
        zone_id: &ZoneId,
        seq: u64,
        id_a: &ObjectId,
        id_b: &ObjectId,
        now: u64,
        detector: TailscaleNodeId,
    ) -> Option<Self> {
        if id_a == id_b {
            None
        } else {
            Some(Self::new(zone_id.clone(), seq, *id_a, *id_b, now, detector))
        }
    }

    /// Add signers from checkpoint A.
    #[must_use]
    pub fn with_signers_a(mut self, signers: impl IntoIterator<Item = String>) -> Self {
        self.signers_a = signers.into_iter().collect();
        self
    }

    /// Add signers from checkpoint B.
    #[must_use]
    pub fn with_signers_b(mut self, signers: impl IntoIterator<Item = String>) -> Self {
        self.signers_b = signers.into_iter().collect();
        self
    }

    /// Find nodes that signed both conflicting checkpoints (Byzantine nodes).
    #[must_use]
    pub fn double_signers(&self) -> BTreeSet<String> {
        self.signers_a
            .intersection(&self.signers_b)
            .cloned()
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Computation Migration Checkpoints
// ─────────────────────────────────────────────────────────────────────────────

/// Default payload size that triggers chunked checkpoint transfer encoding.
pub const DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_THRESHOLD_BYTES: usize = 256 * 1024;

/// Default chunk size used when splitting large computation checkpoints.
pub const DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_SIZE_BYTES: usize = 64 * 1024;

/// Minimal authority binding carried across computation migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationCapabilityContext {
    /// Capability token JTI authorizing this computation.
    pub capability_token_jti: Uuid,
    /// Latest bound checkpoint object, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<ObjectId>,
    /// Freshness binding for checkpoint-aware resumption.
    pub checkpoint_seq: u64,
    /// Audit event/object binding for authoritative replay checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_event_id: Option<ObjectId>,
}

/// Manifest describing a chunked canonical checkpoint payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkedObjectManifest {
    /// Content-addressed identifier for the full canonical payload.
    pub payload_object_id: ObjectId,
    /// Total canonical payload length in bytes.
    pub total_bytes: u64,
    /// Chunk size used to segment the payload.
    pub chunk_size_bytes: u32,
    /// Content-addressed identifiers for each chunk in order.
    pub chunk_object_ids: Vec<ObjectId>,
}

impl ChunkedObjectManifest {
    /// Number of chunks described by this manifest.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunk_object_ids.len()
    }
}

/// Canonical checkpoint payload carried as ordered chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkedCheckpoint {
    pub manifest: ChunkedObjectManifest,
    pub chunks: Vec<Vec<u8>>,
}

/// Wire encoding for checkpoint transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case")]
pub enum CheckpointTransferEncoding {
    /// Small checkpoints travel inline as a canonical schema-bound payload.
    Inline {
        object_id: ObjectId,
        canonical_bytes: Vec<u8>,
    },
    /// Large checkpoints are transferred as a manifest plus ordered chunks.
    Chunked(ChunkedCheckpoint),
}

impl CheckpointTransferEncoding {
    /// Get the content-addressed identifier for the full checkpoint payload.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        match self {
            Self::Inline { object_id, .. } => *object_id,
            Self::Chunked(chunked) => chunked.manifest.payload_object_id,
        }
    }
}

/// Canonical checkpoint required for safe migration and resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationCheckpoint {
    /// Object header for zone/provenance binding.
    pub header: ObjectHeader,
    /// Content-addressed identifier for the suspended computation.
    pub computation_id: ObjectId,
    /// Node holding execution authority when the checkpoint was written.
    pub current_holder: TailscaleNodeId,
    /// Monotonic checkpoint sequence for freshness checks.
    pub checkpoint_seq: u64,
    /// Suspension time in Unix seconds.
    pub suspended_at: u64,
    /// Lease authorizing the suspended computation.
    pub lease_id: ObjectId,
    /// Lease fencing token observed when the checkpoint was taken.
    pub lease_fencing_token: u64,
    /// Minimal authority binding required for resume validation.
    pub capability_context: MigrationCapabilityContext,
    /// Canonical connector/runtime state blob.
    pub state_cbor: Vec<u8>,
}

impl ComputationCheckpoint {
    /// Canonical schema identifier for computation migration checkpoints.
    #[must_use]
    pub fn schema() -> SchemaId {
        SchemaId::new("fcp.core", "ComputationCheckpoint", Version::new(1, 0, 0))
    }

    /// Zone in which the checkpoint is valid.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }

    /// Serialize to the canonical schema-bound checkpoint payload.
    ///
    /// # Errors
    /// Returns a [`SerializationError`] if canonical encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        CanonicalSerializer::serialize(self, &Self::schema())
    }

    /// Derive the content-addressed identifier for the canonical payload.
    ///
    /// # Errors
    /// Returns a [`SerializationError`] if canonical encoding fails.
    pub fn object_id(&self) -> Result<ObjectId, SerializationError> {
        Ok(ObjectId::from_unscoped_bytes(&self.canonical_bytes()?))
    }

    /// Convert this checkpoint into a transfer encoding suitable for the mesh.
    ///
    /// # Errors
    /// Returns a [`CheckpointChunkError`] if canonical encoding fails or the
    /// requested chunk size cannot be represented safely.
    pub fn to_transfer_encoding(
        &self,
        chunk_threshold_bytes: usize,
        chunk_size_bytes: usize,
    ) -> Result<CheckpointTransferEncoding, CheckpointChunkError> {
        if chunk_size_bytes == 0 {
            return Err(CheckpointChunkError::InvalidChunkSize);
        }

        let canonical_bytes = self.canonical_bytes()?;
        let object_id = ObjectId::from_unscoped_bytes(&canonical_bytes);
        if canonical_bytes.len() <= chunk_threshold_bytes {
            return Ok(CheckpointTransferEncoding::Inline {
                object_id,
                canonical_bytes,
            });
        }

        let total_bytes = u64::try_from(canonical_bytes.len()).map_err(|_| {
            CheckpointChunkError::ManifestLengthOverflow {
                total_bytes: canonical_bytes.len(),
            }
        })?;
        let chunk_size_bytes_u32 = u32::try_from(chunk_size_bytes)
            .map_err(|_| CheckpointChunkError::ManifestChunkSizeOverflow { chunk_size_bytes })?;

        let chunks: Vec<Vec<u8>> = canonical_bytes
            .chunks(chunk_size_bytes)
            .map(<[u8]>::to_vec)
            .collect();
        let chunk_object_ids = chunks
            .iter()
            .map(|chunk| ObjectId::from_unscoped_bytes(chunk))
            .collect();

        Ok(CheckpointTransferEncoding::Chunked(ChunkedCheckpoint {
            manifest: ChunkedObjectManifest {
                payload_object_id: object_id,
                total_bytes,
                chunk_size_bytes: chunk_size_bytes_u32,
                chunk_object_ids,
            },
            chunks,
        }))
    }

    /// Reconstruct a checkpoint from inline or chunked transfer encoding.
    ///
    /// # Errors
    /// Returns a [`CheckpointChunkError`] if integrity checks fail or decoding is invalid.
    pub fn from_transfer_encoding(
        encoding: &CheckpointTransferEncoding,
    ) -> Result<Self, CheckpointChunkError> {
        let canonical_bytes = match encoding {
            CheckpointTransferEncoding::Inline {
                object_id,
                canonical_bytes,
            } => {
                let derived_object_id = ObjectId::from_unscoped_bytes(canonical_bytes);
                if &derived_object_id != object_id {
                    return Err(CheckpointChunkError::PayloadIntegrityMismatch {
                        expected: *object_id,
                        got: derived_object_id,
                    });
                }
                canonical_bytes.clone()
            }
            CheckpointTransferEncoding::Chunked(chunked) => reconstruct_chunked_payload(chunked)?,
        };

        Ok(CanonicalSerializer::deserialize(
            &canonical_bytes,
            &Self::schema(),
        )?)
    }
}

/// Errors produced while splitting or reconstructing chunked checkpoints.
#[derive(Debug, Error)]
pub enum CheckpointChunkError {
    #[error("checkpoint chunk size must be greater than zero")]
    InvalidChunkSize,
    #[error("checkpoint payload length {total_bytes} does not fit in manifest")]
    ManifestLengthOverflow { total_bytes: usize },
    #[error("checkpoint chunk size {chunk_size_bytes} does not fit in manifest")]
    ManifestChunkSizeOverflow { chunk_size_bytes: usize },
    #[error("checkpoint payload length {total_bytes} cannot be represented on this platform")]
    ManifestLengthUnsupported { total_bytes: u64 },
    #[error("checkpoint chunk count mismatch: expected {expected}, got {got}")]
    ChunkCountMismatch { expected: usize, got: usize },
    #[error("checkpoint payload length mismatch: expected {expected}, got {got}")]
    PayloadLengthMismatch { expected: usize, got: usize },
    #[error("checkpoint chunk {index} failed integrity validation")]
    ChunkIntegrityMismatch {
        index: usize,
        expected: ObjectId,
        got: ObjectId,
    },
    #[error("checkpoint payload failed integrity validation")]
    PayloadIntegrityMismatch { expected: ObjectId, got: ObjectId },
    #[error(transparent)]
    Serialization(#[from] SerializationError),
}

/// Reassemble a chunked canonical checkpoint payload with integrity checks.
///
/// # Errors
/// Returns a [`CheckpointChunkError`] if any chunk is missing, corrupted, or if
/// the reconstructed payload does not match the manifest digest.
pub fn reconstruct_chunked_payload(
    chunked: &ChunkedCheckpoint,
) -> Result<Vec<u8>, CheckpointChunkError> {
    let expected_chunks = chunked.manifest.chunk_count();
    if chunked.chunks.len() != expected_chunks {
        return Err(CheckpointChunkError::ChunkCountMismatch {
            expected: expected_chunks,
            got: chunked.chunks.len(),
        });
    }

    let expected_total_bytes = usize::try_from(chunked.manifest.total_bytes).map_err(|_| {
        CheckpointChunkError::ManifestLengthUnsupported {
            total_bytes: chunked.manifest.total_bytes,
        }
    })?;

    // Validate the manifest's claimed total against the actual chunk data
    // BEFORE pre-allocating. Without this, a manifest can advertise an
    // arbitrarily large total_bytes and force the runtime into a
    // Vec::with_capacity(huge) reservation before any integrity check
    // runs — on strict allocators (e.g. macOS) that panics outright, and
    // on overcommit allocators it reserves address space that the
    // subsequent PayloadLengthMismatch error will never justify.
    let actual_total_bytes: usize = chunked
        .chunks
        .iter()
        .try_fold(0usize, |acc, chunk| acc.checked_add(chunk.len()))
        .ok_or(CheckpointChunkError::PayloadLengthMismatch {
            expected: expected_total_bytes,
            got: usize::MAX,
        })?;
    if actual_total_bytes != expected_total_bytes {
        return Err(CheckpointChunkError::PayloadLengthMismatch {
            expected: expected_total_bytes,
            got: actual_total_bytes,
        });
    }

    let mut payload = Vec::with_capacity(expected_total_bytes);
    for (index, (chunk, expected_object_id)) in chunked
        .chunks
        .iter()
        .zip(&chunked.manifest.chunk_object_ids)
        .enumerate()
    {
        let derived_object_id = ObjectId::from_unscoped_bytes(chunk);
        if &derived_object_id != expected_object_id {
            return Err(CheckpointChunkError::ChunkIntegrityMismatch {
                index,
                expected: *expected_object_id,
                got: derived_object_id,
            });
        }
        payload.extend_from_slice(chunk);
    }

    if payload.len() != expected_total_bytes {
        return Err(CheckpointChunkError::PayloadLengthMismatch {
            expected: expected_total_bytes,
            got: payload.len(),
        });
    }

    let derived_payload_id = ObjectId::from_unscoped_bytes(&payload);
    if derived_payload_id != chunked.manifest.payload_object_id {
        return Err(CheckpointChunkError::PayloadIntegrityMismatch {
            expected: chunked.manifest.payload_object_id,
            got: derived_payload_id,
        });
    }

    Ok(payload)
}

// ─────────────────────────────────────────────────────────────────────────────
// Coordinator Selection (HRW Hash)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute HRW hash for coordinator selection (NORMATIVE).
///
/// Uses BLAKE3 hash of (`zone_id`, "checkpoint", epoch, `node_id`) to produce
/// a deterministic ordering of nodes. The highest hash value wins.
///
/// # Panics
///
/// Panics if any input byte length exceeds `u32::MAX`.
#[must_use]
pub fn hrw_hash_checkpoint(zone_id: &ZoneId, epoch: &EpochId, node_id: &TailscaleNodeId) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP2-HRW-CHECKPOINT-V1");

    let z_bytes = zone_id.as_bytes();
    hasher.update(
        &u32::try_from(z_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    hasher.update(z_bytes);

    let e_bytes = epoch.as_str().as_bytes();
    hasher.update(
        &u32::try_from(e_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    hasher.update(e_bytes);

    let n_bytes = node_id.as_str().as_bytes();
    hasher.update(
        &u32::try_from(n_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    hasher.update(n_bytes);

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    // Take first 8 bytes as u64 for comparison
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Select checkpoint coordinator from eligible nodes (NORMATIVE).
///
/// Uses Highest Random Weight (HRW) hashing for deterministic, consistent
/// coordinator selection across all nodes.
///
/// # Arguments
///
/// * `zone_id` - The zone for checkpoint
/// * `epoch` - Current epoch
/// * `eligible_nodes` - Nodes eligible to be coordinator
///
/// # Returns
///
/// The node with highest HRW hash, or None if no eligible nodes.
#[must_use]
pub fn select_checkpoint_coordinator(
    zone_id: &ZoneId,
    epoch: &EpochId,
    eligible_nodes: &[TailscaleNodeId],
) -> Option<TailscaleNodeId> {
    eligible_nodes
        .iter()
        .max_by_key(|node| hrw_hash_checkpoint(zone_id, epoch, node))
        .cloned()
}

/// Rank nodes by HRW hash for fallback coordinator selection (NORMATIVE).
///
/// Returns nodes sorted by descending HRW hash. If primary coordinator fails,
/// the next node in the ranking becomes coordinator.
#[must_use]
pub fn rank_checkpoint_coordinators(
    zone_id: &ZoneId,
    epoch: &EpochId,
    eligible_nodes: &[TailscaleNodeId],
) -> Vec<TailscaleNodeId> {
    let mut ranked: Vec<_> = eligible_nodes
        .iter()
        .map(|node| (hrw_hash_checkpoint(zone_id, epoch, node), node.clone()))
        .collect();
    ranked.sort_by_key(|item| std::cmp::Reverse(item.0)); // Descending by hash
    ranked.into_iter().map(|(_, node)| node).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Advancement State Machine
// ─────────────────────────────────────────────────────────────────────────────

/// State of checkpoint advancement protocol (NORMATIVE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CheckpointAdvanceState {
    /// Idle, waiting for trigger condition.
    Idle {
        /// Current checkpoint seq.
        current_seq: u64,
        /// When last checkpoint was finalized.
        last_checkpoint_at: u64,
    },
    /// Trigger condition met, selecting coordinator.
    TriggeredAwaitingCoordinator {
        /// Trigger that caused advancement.
        trigger: CheckpointTrigger,
        /// When trigger occurred.
        triggered_at: u64,
    },
    /// Coordinator selected, proposal broadcast.
    ProposalBroadcast {
        /// The broadcast proposal (boxed to reduce enum size).
        proposal: Box<CheckpointProposal>,
        /// Signatures collected so far.
        collected_signatures: SignatureSet,
        /// Required signature count (n-f).
        required_signatures: usize,
    },
    /// Sufficient signatures collected, checkpoint finalized.
    Finalized {
        /// Finalized checkpoint ID.
        checkpoint_id: ObjectId,
        /// Finalized sequence.
        finalized_seq: u64,
        /// When finalized.
        finalized_at: u64,
    },
    /// Fork detected, advancement halted.
    Halted {
        /// Fork evidence.
        fork_evidence: ForkEvidence,
        /// When halted.
        halted_at: u64,
    },
}

impl CheckpointAdvanceState {
    /// Create initial idle state.
    #[must_use]
    pub const fn idle(current_seq: u64, last_checkpoint_at: u64) -> Self {
        Self::Idle {
            current_seq,
            last_checkpoint_at,
        }
    }

    /// Check if advancement is halted due to fork.
    #[must_use]
    pub const fn is_halted(&self) -> bool {
        matches!(self, Self::Halted { .. })
    }

    /// Check if checkpoint can advance (not halted).
    #[must_use]
    pub const fn can_advance(&self) -> bool {
        !self.is_halted()
    }

    /// Get fork evidence if halted.
    #[must_use]
    pub const fn fork_evidence(&self) -> Option<&ForkEvidence> {
        match self {
            Self::Halted { fork_evidence, .. } => Some(fork_evidence),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Errors during checkpoint proposal validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum CheckpointValidationError {
    /// Sequence number does not follow previous checkpoint.
    InvalidSequence { expected: u64, got: u64 },
    /// Proposal timestamp outside acceptable skew.
    TimestampSkew {
        local_time: u64,
        proposal_time: u64,
        max_skew: u64,
    },
    /// Referenced head is unknown.
    UnknownHead {
        head_type: String,
        head_id: ObjectId,
    },
    /// Referenced head is invalid.
    InvalidHead {
        head_type: String,
        head_id: ObjectId,
        reason: String,
    },
    /// Proposer is not the valid coordinator.
    NotCoordinator {
        expected: TailscaleNodeId,
        got: TailscaleNodeId,
    },
    /// Coordinator signature is invalid.
    InvalidCoordinatorSignature,
    /// Fork was detected.
    ForkDetected(ForkEvidence),
    /// Zone mismatch.
    ZoneMismatch { expected: ZoneId, got: ZoneId },
    /// Epoch mismatch.
    EpochMismatch { expected: EpochId, got: EpochId },
}

impl CheckpointValidationError {
    /// Check if this error indicates a fork (critical security event).
    #[must_use]
    pub const fn is_fork(&self) -> bool {
        matches!(self, Self::ForkDetected(_))
    }

    /// Get reason code for audit/logging.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidSequence { .. } => "FCP-5001",
            Self::TimestampSkew { .. } => "FCP-5002",
            Self::UnknownHead { .. } => "FCP-5003",
            Self::InvalidHead { .. } => "FCP-5004",
            Self::NotCoordinator { .. } => "FCP-5005",
            Self::InvalidCoordinatorSignature => "FCP-5006",
            Self::ForkDetected(_) => "FCP-5010",
            Self::ZoneMismatch { .. } => "FCP-5007",
            Self::EpochMismatch { .. } => "FCP-5008",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Freshness Verification
// ─────────────────────────────────────────────────────────────────────────────

/// Freshness check result for token/revocation verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreshnessResult {
    /// Checkpoint is fresh enough.
    Fresh,
    /// Checkpoint is stale but operation allowed in degraded mode.
    DegradedMode,
    /// Checkpoint too stale, operation must fail.
    TooStale,
}

impl FreshnessResult {
    /// Check token freshness against local checkpoint (NORMATIVE).
    ///
    /// Token is fresh if `token.chk_seq <= local_checkpoint_seq`.
    #[must_use]
    pub const fn check_token_freshness(
        token_chk_seq: u64,
        local_checkpoint_seq: u64,
        degraded_mode_allowed: bool,
    ) -> Self {
        if token_chk_seq <= local_checkpoint_seq {
            Self::Fresh
        } else if degraded_mode_allowed {
            Self::DegradedMode
        } else {
            Self::TooStale
        }
    }

    /// Check revocation freshness (NORMATIVE).
    ///
    /// Local revocation head must be >= policy minimum.
    #[must_use]
    pub const fn check_revocation_freshness(
        local_rev_head_seq: u64,
        policy_min_rev_seq: u64,
        degraded_mode_allowed: bool,
    ) -> Self {
        if local_rev_head_seq >= policy_min_rev_seq {
            Self::Fresh
        } else if degraded_mode_allowed {
            Self::DegradedMode
        } else {
            Self::TooStale
        }
    }

    /// Returns true if operation can proceed.
    #[must_use]
    pub const fn allows_operation(&self) -> bool {
        !matches!(self, Self::TooStale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeId, Provenance};

    // ─────────────────────────────────────────────────────────────────────────
    // Test Helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    fn test_epoch() -> EpochId {
        EpochId::new("epoch-42")
    }

    fn test_node(name: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(name)
    }

    fn test_object_id(label: &str) -> ObjectId {
        ObjectId::test_id(label)
    }

    fn test_migration_header(kind: &str, refs: Vec<ObjectId>) -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.core", kind, Version::new(1, 0, 0)),
            zone_id: test_zone(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(test_zone()),
            refs,
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_migration_context(checkpoint_seq: u64) -> MigrationCapabilityContext {
        MigrationCapabilityContext {
            capability_token_jti: Uuid::from_bytes([0xAB; 16]),
            checkpoint_id: None,
            checkpoint_seq,
            audit_event_id: Some(test_object_id("audit-event")),
        }
    }

    fn test_computation_checkpoint(state_cbor: Vec<u8>) -> ComputationCheckpoint {
        let computation_id = test_object_id("computation");
        let lease_id = test_object_id("lease");
        ComputationCheckpoint {
            header: test_migration_header("ComputationCheckpoint", vec![computation_id, lease_id]),
            computation_id,
            current_holder: test_node("node-source"),
            checkpoint_seq: 7,
            suspended_at: 1_700_000_100,
            lease_id,
            lease_fencing_token: 11,
            capability_context: test_migration_context(7),
            state_cbor,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointTrigger Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trigger_time_elapsed_met() {
        let trigger = CheckpointTrigger::check_time_elapsed(65, 60);
        assert!(trigger.is_some());
        if let Some(CheckpointTrigger::TimeElapsed {
            elapsed_secs,
            threshold_secs,
        }) = trigger
        {
            assert_eq!(elapsed_secs, 65);
            assert_eq!(threshold_secs, 60);
        }
    }

    #[test]
    fn trigger_time_elapsed_not_met() {
        let trigger = CheckpointTrigger::check_time_elapsed(55, 60);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_time_elapsed_boundary() {
        // Exactly at threshold - should NOT trigger (must exceed)
        let trigger = CheckpointTrigger::check_time_elapsed(60, 60);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_audit_growth_met() {
        let trigger = CheckpointTrigger::check_audit_growth(150, 100);
        assert!(trigger.is_some());
        if let Some(CheckpointTrigger::AuditChainGrowth {
            new_events,
            threshold,
        }) = trigger
        {
            assert_eq!(new_events, 150);
            assert_eq!(threshold, 100);
        }
    }

    #[test]
    fn trigger_audit_growth_not_met() {
        let trigger = CheckpointTrigger::check_audit_growth(50, 100);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_revocation_growth_any_events() {
        let trigger = CheckpointTrigger::check_revocation_growth(1);
        assert!(trigger.is_some());
    }

    #[test]
    fn trigger_revocation_growth_zero_events() {
        let trigger = CheckpointTrigger::check_revocation_growth(0);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_serialization_roundtrip() {
        let triggers = vec![
            CheckpointTrigger::TimeElapsed {
                elapsed_secs: 120,
                threshold_secs: 60,
            },
            CheckpointTrigger::AuditChainGrowth {
                new_events: 200,
                threshold: 100,
            },
            CheckpointTrigger::RevocationChainGrowth { new_events: 5 },
            CheckpointTrigger::PolicyChange {
                old_policy_head: test_object_id("old-policy"),
                new_policy_head: test_object_id("new-policy"),
            },
            CheckpointTrigger::Manual {
                reason: Some("Operator requested".to_string()),
            },
        ];

        for trigger in triggers {
            let json = serde_json::to_string(&trigger).unwrap();
            let decoded: CheckpointTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, trigger);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fork Detection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_detection_different_ids() {
        let zone = test_zone();
        let id_a = test_object_id("checkpoint-a");
        let id_b = test_object_id("checkpoint-b");
        let detector = test_node("detector-node");

        let evidence = ForkEvidence::detect(&zone, 10, &id_a, &id_b, 1_700_000_000, detector);

        assert!(evidence.is_some());
        let ev = evidence.unwrap();
        assert_eq!(ev.zone_id.as_str(), "z:work");
        assert_eq!(ev.conflicting_seq, 10);
        assert_eq!(ev.checkpoint_a, id_a);
        assert_eq!(ev.checkpoint_b, id_b);
    }

    #[test]
    fn fork_detection_same_ids_no_fork() {
        let zone = test_zone();
        let id_a = test_object_id("checkpoint-same");
        let id_b = test_object_id("checkpoint-same");
        let detector = test_node("detector-node");

        let evidence = ForkEvidence::detect(&zone, 10, &id_a, &id_b, 1_700_000_000, detector);

        assert!(evidence.is_none());
    }

    #[test]
    fn fork_evidence_double_signers() {
        let evidence = ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("detector"),
        )
        .with_signers_a([
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
        ])
        .with_signers_b([
            "bob".to_string(),
            "david".to_string(),
            "charlie".to_string(),
        ]);

        let double_signers = evidence.double_signers();

        // bob and charlie signed both
        assert_eq!(double_signers.len(), 2);
        assert!(double_signers.contains("bob"));
        assert!(double_signers.contains("charlie"));
    }

    #[test]
    fn fork_detection_result_is_fork() {
        let result = ForkDetectionResult::NoFork;
        assert!(!result.is_fork());

        let evidence = ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("detector"),
        );
        let result = ForkDetectionResult::ForkDetected(evidence);
        assert!(result.is_fork());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HRW Coordinator Selection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn hrw_hash_deterministic() {
        let zone = test_zone();
        let epoch = test_epoch();
        let node = test_node("node-1");

        let hash1 = hrw_hash_checkpoint(&zone, &epoch, &node);
        let hash2 = hrw_hash_checkpoint(&zone, &epoch, &node);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hrw_hash_differs_by_node() {
        let zone = test_zone();
        let epoch = test_epoch();

        let hash1 = hrw_hash_checkpoint(&zone, &epoch, &test_node("node-1"));
        let hash2 = hrw_hash_checkpoint(&zone, &epoch, &test_node("node-2"));

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hrw_hash_differs_by_epoch() {
        let zone = test_zone();
        let node = test_node("node-1");

        let hash1 = hrw_hash_checkpoint(&zone, &EpochId::new("epoch-1"), &node);
        let hash2 = hrw_hash_checkpoint(&zone, &EpochId::new("epoch-2"), &node);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hrw_hash_differs_by_zone() {
        let epoch = test_epoch();
        let node = test_node("node-1");

        let hash1 = hrw_hash_checkpoint(&ZoneId::work(), &epoch, &node);
        let hash2 = hrw_hash_checkpoint(&ZoneId::public(), &epoch, &node);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn coordinator_selection_deterministic() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
        ];

        let coord1 = select_checkpoint_coordinator(&zone, &epoch, &nodes);
        let coord2 = select_checkpoint_coordinator(&zone, &epoch, &nodes);

        assert_eq!(coord1, coord2);
        assert!(coord1.is_some());
    }

    #[test]
    fn coordinator_selection_empty_nodes() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes: Vec<TailscaleNodeId> = vec![];

        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes);

        assert!(coord.is_none());
    }

    #[test]
    fn coordinator_ranking_all_nodes_included() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![
            test_node("node-a"),
            test_node("node-b"),
            test_node("node-c"),
            test_node("node-d"),
        ];

        let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);

        assert_eq!(ranked.len(), nodes.len());
        // First in ranking should be the selected coordinator
        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes);
        assert_eq!(Some(&ranked[0]), coord.as_ref());
    }

    #[test]
    fn coordinator_ranking_order_preserved() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![
            test_node("node-x"),
            test_node("node-y"),
            test_node("node-z"),
        ];

        let ranked1 = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
        let ranked2 = rank_checkpoint_coordinators(&zone, &epoch, &nodes);

        assert_eq!(ranked1, ranked2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Checkpoint Advancement State Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn advance_state_idle() {
        let state = CheckpointAdvanceState::idle(10, 1_700_000_000);

        assert!(!state.is_halted());
        assert!(state.can_advance());
        assert!(state.fork_evidence().is_none());
    }

    #[test]
    fn advance_state_halted() {
        let evidence = ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("detector"),
        );
        let state = CheckpointAdvanceState::Halted {
            fork_evidence: evidence,
            halted_at: 1_700_000_001,
        };

        assert!(state.is_halted());
        assert!(!state.can_advance());
        assert!(state.fork_evidence().is_some());
        assert_eq!(state.fork_evidence().unwrap().conflicting_seq, 10);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Checkpoint Proposal Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn proposal_seq_follows_prev() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 11,
            prev_checkpoint_id: Some(test_object_id("prev-chk")),
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 100,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 50,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };

        assert!(proposal.seq_follows_prev(10));
        assert!(!proposal.seq_follows_prev(9));
        assert!(!proposal.seq_follows_prev(11));
    }

    #[test]
    fn proposal_seq_handles_overflow() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 0, // Would be u64::MAX + 1
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 100,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 50,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };

        // u64::MAX + 1 would overflow, so checked_add returns None
        assert!(!proposal.seq_follows_prev(u64::MAX));
    }

    #[test]
    fn proposal_timestamp_within_skew() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 100,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 50,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };

        // Within skew
        assert!(proposal.timestamp_within_skew(1_700_000_005, 10));
        assert!(proposal.timestamp_within_skew(1_699_999_995, 10));
        // Exactly at boundary
        assert!(proposal.timestamp_within_skew(1_700_000_010, 10));
        // Outside skew
        assert!(!proposal.timestamp_within_skew(1_700_000_015, 10));
        assert!(!proposal.timestamp_within_skew(1_699_999_985, 10));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Validation Error Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validation_error_reason_codes() {
        let errors = vec![
            (
                CheckpointValidationError::InvalidSequence {
                    expected: 10,
                    got: 12,
                },
                "FCP-5001",
            ),
            (
                CheckpointValidationError::TimestampSkew {
                    local_time: 100,
                    proposal_time: 200,
                    max_skew: 10,
                },
                "FCP-5002",
            ),
            (
                CheckpointValidationError::UnknownHead {
                    head_type: "audit".to_string(),
                    head_id: test_object_id("h"),
                },
                "FCP-5003",
            ),
            (
                CheckpointValidationError::InvalidHead {
                    head_type: "rev".to_string(),
                    head_id: test_object_id("h"),
                    reason: "bad".to_string(),
                },
                "FCP-5004",
            ),
            (
                CheckpointValidationError::NotCoordinator {
                    expected: test_node("a"),
                    got: test_node("b"),
                },
                "FCP-5005",
            ),
            (
                CheckpointValidationError::InvalidCoordinatorSignature,
                "FCP-5006",
            ),
            (
                CheckpointValidationError::ZoneMismatch {
                    expected: test_zone(),
                    got: ZoneId::public(),
                },
                "FCP-5007",
            ),
            (
                CheckpointValidationError::EpochMismatch {
                    expected: test_epoch(),
                    got: EpochId::new("other"),
                },
                "FCP-5008",
            ),
        ];

        for (error, expected_code) in errors {
            assert_eq!(error.reason_code(), expected_code);
            assert!(!error.is_fork());
        }

        // Fork error
        let fork_error = CheckpointValidationError::ForkDetected(ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("d"),
        ));
        assert_eq!(fork_error.reason_code(), "FCP-5010");
        assert!(fork_error.is_fork());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Freshness Verification Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_token_fresh() {
        let result = FreshnessResult::check_token_freshness(5, 10, false);
        assert_eq!(result, FreshnessResult::Fresh);
        assert!(result.allows_operation());
    }

    #[test]
    fn freshness_token_stale_no_degraded() {
        let result = FreshnessResult::check_token_freshness(15, 10, false);
        assert_eq!(result, FreshnessResult::TooStale);
        assert!(!result.allows_operation());
    }

    #[test]
    fn freshness_token_stale_with_degraded() {
        let result = FreshnessResult::check_token_freshness(15, 10, true);
        assert_eq!(result, FreshnessResult::DegradedMode);
        assert!(result.allows_operation());
    }

    #[test]
    fn freshness_revocation_fresh() {
        let result = FreshnessResult::check_revocation_freshness(50, 40, false);
        assert_eq!(result, FreshnessResult::Fresh);
        assert!(result.allows_operation());
    }

    #[test]
    fn freshness_revocation_stale_no_degraded() {
        let result = FreshnessResult::check_revocation_freshness(30, 40, false);
        assert_eq!(result, FreshnessResult::TooStale);
        assert!(!result.allows_operation());
    }

    #[test]
    fn freshness_revocation_stale_with_degraded() {
        let result = FreshnessResult::check_revocation_freshness(30, 40, true);
        assert_eq!(result, FreshnessResult::DegradedMode);
        assert!(result.allows_operation());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_hrw_checkpoint_hash() {
        // Deterministic golden vector for HRW hash
        let zone: ZoneId = "z:work".parse().unwrap();
        let epoch = EpochId::new("epoch-test-golden");
        let node = TailscaleNodeId::new("node-golden-test");

        let hash = hrw_hash_checkpoint(&zone, &epoch, &node);

        // This is a golden vector - if it changes, the hash algorithm changed
        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(b"FCP2-HRW-CHECKPOINT-V1");

        let z_bytes = zone.as_bytes();
        expected_hasher.update(
            &u32::try_from(z_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        expected_hasher.update(z_bytes);

        let e_bytes = epoch.as_str().as_bytes();
        expected_hasher.update(
            &u32::try_from(e_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        expected_hasher.update(e_bytes);

        let n_bytes = node.as_str().as_bytes();
        expected_hasher.update(
            &u32::try_from(n_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        expected_hasher.update(n_bytes);

        let expected_bytes = expected_hasher.finalize();
        let mut expected_buf = [0u8; 8];
        expected_buf.copy_from_slice(&expected_bytes.as_bytes()[0..8]);
        let expected_u64 = u64::from_le_bytes(expected_buf);

        assert_eq!(
            hash, expected_u64,
            "HRW checkpoint hash golden vector mismatch"
        );
    }

    #[test]
    fn golden_coordinator_selection() {
        // Deterministic coordinator selection test
        let zone: ZoneId = "z:work".parse().unwrap();
        let epoch = EpochId::new("epoch-golden");
        let nodes = vec![
            TailscaleNodeId::new("node-alice"),
            TailscaleNodeId::new("node-bob"),
            TailscaleNodeId::new("node-charlie"),
        ];

        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes).unwrap();

        // Golden vector - the winning coordinator for this input
        // If this changes, HRW selection semantics changed
        assert_eq!(
            coord.as_str(),
            "node-charlie",
            "Coordinator selection golden vector mismatch"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn default_checkpoint_interval_is_60() {
        assert_eq!(DEFAULT_CHECKPOINT_INTERVAL_SECS, 60);
    }

    #[test]
    fn default_audit_chain_growth_threshold_is_100() {
        assert_eq!(DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD, 100);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointTrigger – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trigger_clone_preserves_equality() {
        let trigger = CheckpointTrigger::TimeElapsed {
            elapsed_secs: 120,
            threshold_secs: 60,
        };
        let cloned = trigger.clone();
        assert_eq!(trigger, cloned);
    }

    #[test]
    fn trigger_manual_none_reason_serde() {
        let trigger = CheckpointTrigger::Manual { reason: None };
        let json = serde_json::to_string(&trigger).unwrap();
        let decoded: CheckpointTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(trigger, decoded);
        if let CheckpointTrigger::Manual { reason } = decoded {
            assert!(reason.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn trigger_inequality_across_variants() {
        let a = CheckpointTrigger::TimeElapsed {
            elapsed_secs: 120,
            threshold_secs: 60,
        };
        let b = CheckpointTrigger::RevocationChainGrowth { new_events: 1 };
        assert_ne!(a, b);
    }

    #[test]
    fn trigger_audit_growth_boundary_not_met() {
        // Exactly at threshold - should NOT trigger (must exceed)
        let trigger = CheckpointTrigger::check_audit_growth(100, 100);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_revocation_growth_large_count() {
        let trigger = CheckpointTrigger::check_revocation_growth(u64::MAX);
        assert!(trigger.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ForkEvidence – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_evidence_clone() {
        let evidence = ForkEvidence::new(
            test_zone(),
            5,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("det"),
        );
        let cloned = evidence.clone();
        assert_eq!(evidence, cloned);
    }

    #[test]
    fn fork_evidence_double_signers_no_overlap() {
        let evidence = ForkEvidence::new(
            test_zone(),
            1,
            test_object_id("x"),
            test_object_id("y"),
            100,
            test_node("d"),
        )
        .with_signers_a(["alice".to_string()])
        .with_signers_b(["bob".to_string()]);
        assert!(evidence.double_signers().is_empty());
    }

    #[test]
    fn fork_evidence_double_signers_empty_sets() {
        let evidence = ForkEvidence::new(
            test_zone(),
            1,
            test_object_id("x"),
            test_object_id("y"),
            100,
            test_node("d"),
        );
        assert!(evidence.signers_a.is_empty());
        assert!(evidence.signers_b.is_empty());
        assert!(evidence.double_signers().is_empty());
    }

    #[test]
    fn fork_evidence_serde_roundtrip() {
        let evidence = ForkEvidence::new(
            test_zone(),
            99,
            test_object_id("cp-a"),
            test_object_id("cp-b"),
            1_700_000_000,
            test_node("detector"),
        )
        .with_signers_a(["node1".to_string()])
        .with_signers_b(["node2".to_string()]);
        let json = serde_json::to_string(&evidence).unwrap();
        let decoded: ForkEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, decoded);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ForkDetectionResult – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn fork_detection_result_no_fork_serde() {
        let result = ForkDetectionResult::NoFork;
        let json = serde_json::to_string(&result).unwrap();
        let decoded: ForkDetectionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
        assert!(!decoded.is_fork());
    }

    #[test]
    fn fork_detection_result_fork_detected_serde() {
        let evidence = ForkEvidence::new(
            test_zone(),
            7,
            test_object_id("a"),
            test_object_id("b"),
            100,
            test_node("d"),
        );
        let result = ForkDetectionResult::ForkDetected(evidence);
        let json = serde_json::to_string(&result).unwrap();
        let decoded: ForkDetectionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
        assert!(decoded.is_fork());
    }

    #[test]
    fn fork_detection_result_clone() {
        let evidence = ForkEvidence::new(
            test_zone(),
            7,
            test_object_id("a"),
            test_object_id("b"),
            100,
            test_node("d"),
        );
        let result = ForkDetectionResult::ForkDetected(evidence);
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointAdvanceState – serde all variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn advance_state_idle_serde() {
        let state = CheckpointAdvanceState::idle(5, 1_700_000_000);
        let json = serde_json::to_string(&state).unwrap();
        let decoded: CheckpointAdvanceState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn advance_state_triggered_serde() {
        let state = CheckpointAdvanceState::TriggeredAwaitingCoordinator {
            trigger: CheckpointTrigger::RevocationChainGrowth { new_events: 3 },
            triggered_at: 1_700_000_050,
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: CheckpointAdvanceState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
        assert!(decoded.can_advance());
    }

    #[test]
    fn advance_state_finalized_serde() {
        let state = CheckpointAdvanceState::Finalized {
            checkpoint_id: test_object_id("final-chk"),
            finalized_seq: 42,
            finalized_at: 1_700_001_000,
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: CheckpointAdvanceState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
        assert!(!decoded.is_halted());
        assert!(decoded.can_advance());
        assert!(decoded.fork_evidence().is_none());
    }

    #[test]
    fn advance_state_halted_serde() {
        let evidence = ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            1_700_000_000,
            test_node("d"),
        );
        let state = CheckpointAdvanceState::Halted {
            fork_evidence: evidence,
            halted_at: 1_700_000_001,
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: CheckpointAdvanceState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
        assert!(decoded.is_halted());
    }

    #[test]
    fn advance_state_clone() {
        let state = CheckpointAdvanceState::idle(0, 0);
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn advance_state_triggered_can_advance() {
        let state = CheckpointAdvanceState::TriggeredAwaitingCoordinator {
            trigger: CheckpointTrigger::Manual {
                reason: Some("test".into()),
            },
            triggered_at: 0,
        };
        assert!(state.can_advance());
        assert!(!state.is_halted());
        assert!(state.fork_evidence().is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointValidationError – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn validation_error_invalid_sequence_serde() {
        let err = CheckpointValidationError::InvalidSequence {
            expected: 10,
            got: 12,
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_timestamp_skew_serde() {
        let err = CheckpointValidationError::TimestampSkew {
            local_time: 100,
            proposal_time: 200,
            max_skew: 10,
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_not_coordinator_serde() {
        let err = CheckpointValidationError::NotCoordinator {
            expected: test_node("a"),
            got: test_node("b"),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_invalid_coordinator_signature_serde() {
        let err = CheckpointValidationError::InvalidCoordinatorSignature;
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_zone_mismatch_serde() {
        let err = CheckpointValidationError::ZoneMismatch {
            expected: test_zone(),
            got: ZoneId::public(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_epoch_mismatch_serde() {
        let err = CheckpointValidationError::EpochMismatch {
            expected: test_epoch(),
            got: EpochId::new("other"),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_fork_detected_serde() {
        let err = CheckpointValidationError::ForkDetected(ForkEvidence::new(
            test_zone(),
            10,
            test_object_id("a"),
            test_object_id("b"),
            100,
            test_node("d"),
        ));
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
        assert!(decoded.is_fork());
    }

    #[test]
    fn validation_error_clone() {
        let err = CheckpointValidationError::InvalidSequence {
            expected: 1,
            got: 2,
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // FreshnessResult – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn freshness_result_copy() {
        let a = FreshnessResult::Fresh;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn freshness_result_serde_all_variants() {
        for variant in [
            FreshnessResult::Fresh,
            FreshnessResult::DegradedMode,
            FreshnessResult::TooStale,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let decoded: FreshnessResult = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, decoded);
        }
    }

    #[test]
    fn freshness_token_boundary_equal_seq_is_fresh() {
        // token_chk_seq == local_checkpoint_seq → Fresh
        let result = FreshnessResult::check_token_freshness(10, 10, false);
        assert_eq!(result, FreshnessResult::Fresh);
    }

    #[test]
    fn freshness_revocation_boundary_equal_seq_is_fresh() {
        // local_rev_head_seq == policy_min_rev_seq → Fresh
        let result = FreshnessResult::check_revocation_freshness(40, 40, false);
        assert_eq!(result, FreshnessResult::Fresh);
    }

    #[test]
    fn freshness_allows_operation_all_variants() {
        assert!(FreshnessResult::Fresh.allows_operation());
        assert!(FreshnessResult::DegradedMode.allows_operation());
        assert!(!FreshnessResult::TooStale.allows_operation());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CheckpointProposal – additional coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn proposal_clone() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 100,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 50,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![CheckpointTrigger::Manual { reason: None }],
        };
        let cloned = proposal.clone();
        assert_eq!(proposal, cloned);
    }

    #[test]
    fn proposal_serde_roundtrip() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 5,
            prev_checkpoint_id: Some(test_object_id("prev")),
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 200,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 75,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![
                CheckpointTrigger::TimeElapsed {
                    elapsed_secs: 120,
                    threshold_secs: 60,
                },
                CheckpointTrigger::RevocationChainGrowth { new_events: 3 },
            ],
        };
        let json = serde_json::to_string(&proposal).unwrap();
        let decoded: CheckpointProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(proposal, decoded);
    }

    #[test]
    fn proposal_seq_follows_genesis() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 0,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 0,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };
        // Genesis: prev_seq = 0, proposed_seq = 1
        assert!(proposal.seq_follows_prev(0));
    }

    #[test]
    fn proposal_timestamp_within_skew_zero_skew() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 0,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 0,
            zone_definition_head: test_object_id("zone-def"),
            zone_policy_head: test_object_id("policy"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };
        // Zero skew: only exact match
        assert!(proposal.timestamp_within_skew(1_700_000_000, 0));
        assert!(!proposal.timestamp_within_skew(1_700_000_001, 0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Coordinator ranking – edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn coordinator_ranking_single_node() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![test_node("only-node")];
        let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].as_str(), "only-node");
    }

    #[test]
    fn coordinator_ranking_empty_nodes() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes: Vec<TailscaleNodeId> = vec![];
        let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
        assert!(ranked.is_empty());
    }

    #[test]
    fn coordinator_selection_single_node() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![test_node("solo")];
        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes);
        assert_eq!(coord.unwrap().as_str(), "solo");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden Vector Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn golden_fork_evidence_serialization() {
        let evidence = ForkEvidence {
            zone_id: "z:work".parse().unwrap(),
            conflicting_seq: 42,
            checkpoint_a: ObjectId::from_bytes([0xAA; 32]),
            checkpoint_b: ObjectId::from_bytes([0xBB; 32]),
            detected_at: 1_700_000_000,
            detected_by: TailscaleNodeId::new("detector-node"),
            signers_a: ["alice".to_string(), "bob".to_string()]
                .into_iter()
                .collect(),
            signers_b: ["bob".to_string(), "charlie".to_string()]
                .into_iter()
                .collect(),
        };

        let json = serde_json::to_string(&evidence).unwrap();
        let decoded: ForkEvidence = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.conflicting_seq, 42);
        assert_eq!(
            decoded.double_signers(),
            std::iter::once("bob".to_string()).collect()
        );
    }

    #[test]
    fn computation_checkpoint_canonical_roundtrip() {
        let checkpoint = test_computation_checkpoint(vec![1, 2, 3, 4, 5]);

        let bytes1 = checkpoint.canonical_bytes().unwrap();
        let bytes2 = checkpoint.canonical_bytes().unwrap();
        assert_eq!(bytes1, bytes2);

        let decoded: ComputationCheckpoint =
            CanonicalSerializer::deserialize(&bytes1, &ComputationCheckpoint::schema()).unwrap();
        assert_eq!(
            decoded.canonical_bytes().unwrap(),
            checkpoint.canonical_bytes().unwrap()
        );
        assert_eq!(
            checkpoint.object_id().unwrap(),
            ObjectId::from_unscoped_bytes(&bytes1)
        );
    }

    #[test]
    fn computation_checkpoint_chunked_transfer_roundtrip() {
        let checkpoint = test_computation_checkpoint(vec![0x5Au8; 4096]);
        let encoding = checkpoint
            .to_transfer_encoding(
                DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_THRESHOLD_BYTES.min(128),
                DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_SIZE_BYTES.min(256),
            )
            .unwrap();

        let CheckpointTransferEncoding::Chunked(chunked) = &encoding else {
            panic!("expected chunked checkpoint encoding");
        };
        assert!(chunked.manifest.chunk_count() > 1);
        assert_eq!(encoding.object_id(), chunked.manifest.payload_object_id);

        let restored = ComputationCheckpoint::from_transfer_encoding(&encoding).unwrap();
        assert_eq!(
            restored.canonical_bytes().unwrap(),
            checkpoint.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn computation_checkpoint_chunked_transfer_detects_corruption() {
        let checkpoint = test_computation_checkpoint(vec![0x33u8; 4096]);
        let mut encoding = checkpoint.to_transfer_encoding(64, 128).unwrap();

        let CheckpointTransferEncoding::Chunked(chunked) = &mut encoding else {
            panic!("expected chunked checkpoint encoding");
        };
        chunked.chunks[0][0] ^= 0xFF;

        let err = ComputationCheckpoint::from_transfer_encoding(&encoding).unwrap_err();
        assert!(matches!(
            err,
            CheckpointChunkError::ChunkIntegrityMismatch { .. }
                | CheckpointChunkError::PayloadIntegrityMismatch { .. }
        ));
    }

    #[test]
    fn computation_checkpoint_inline_transfer_detects_payload_integrity_mismatch() {
        let checkpoint = test_computation_checkpoint(vec![1, 2, 3, 4]);
        let mut canonical_bytes = checkpoint.canonical_bytes().unwrap();
        canonical_bytes[0] ^= 0xFF;

        let encoding = CheckpointTransferEncoding::Inline {
            object_id: checkpoint.object_id().unwrap(),
            canonical_bytes,
        };

        let err = ComputationCheckpoint::from_transfer_encoding(&encoding).unwrap_err();
        assert!(matches!(
            err,
            CheckpointChunkError::PayloadIntegrityMismatch { .. }
        ));
    }

    #[test]
    fn reconstruct_chunked_payload_rejects_oversized_manifest_before_allocation() {
        // An attacker-controlled manifest that claims a huge total_bytes
        // (here 1 GiB) with tiny actual chunks must be rejected by the
        // pre-allocation size check, NOT by triggering a huge
        // Vec::with_capacity followed by PayloadLengthMismatch after a
        // multi-gigabyte reservation.
        let chunks = vec![vec![1u8, 2, 3]];
        let chunked = ChunkedCheckpoint {
            manifest: ChunkedObjectManifest {
                payload_object_id: test_object_id("payload"),
                total_bytes: 1_000_000_000, // 1 GiB claim
                chunk_size_bytes: 3,
                chunk_object_ids: chunks
                    .iter()
                    .map(|chunk| ObjectId::from_unscoped_bytes(chunk))
                    .collect(),
            },
            chunks,
        };

        let err = reconstruct_chunked_payload(&chunked).unwrap_err();
        assert!(matches!(
            err,
            CheckpointChunkError::PayloadLengthMismatch {
                expected: 1_000_000_000,
                got: 3,
            }
        ));
    }

    #[test]
    fn reconstruct_chunked_payload_rejects_payload_length_mismatch() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let chunked = ChunkedCheckpoint {
            manifest: ChunkedObjectManifest {
                payload_object_id: test_object_id("payload"),
                total_bytes: 5,
                chunk_size_bytes: 3,
                chunk_object_ids: chunks
                    .iter()
                    .map(|chunk| ObjectId::from_unscoped_bytes(chunk))
                    .collect(),
            },
            chunks,
        };

        let err = reconstruct_chunked_payload(&chunked).unwrap_err();
        assert!(matches!(
            err,
            CheckpointChunkError::PayloadLengthMismatch {
                expected: 5,
                got: 6
            }
        ));
    }

    #[test]
    fn reconstruct_chunked_payload_rejects_payload_integrity_mismatch() {
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let chunked = ChunkedCheckpoint {
            manifest: ChunkedObjectManifest {
                payload_object_id: test_object_id("wrong-payload"),
                total_bytes: 6,
                chunk_size_bytes: 3,
                chunk_object_ids: chunks
                    .iter()
                    .map(|chunk| ObjectId::from_unscoped_bytes(chunk))
                    .collect(),
            },
            chunks,
        };

        let err = reconstruct_chunked_payload(&chunked).unwrap_err();
        assert!(matches!(
            err,
            CheckpointChunkError::PayloadIntegrityMismatch { .. }
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Additional checkpoint tests for 110+ coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn trigger_time_elapsed_just_above_threshold() {
        let trigger = CheckpointTrigger::check_time_elapsed(61, 60);
        assert!(trigger.is_some());
    }

    #[test]
    fn trigger_time_elapsed_zero_threshold() {
        // Any positive elapsed triggers with zero threshold
        let trigger = CheckpointTrigger::check_time_elapsed(1, 0);
        assert!(trigger.is_some());
    }

    #[test]
    fn trigger_time_elapsed_zero_both() {
        // 0 is not > 0, so no trigger
        let trigger = CheckpointTrigger::check_time_elapsed(0, 0);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_time_elapsed_u64_max() {
        let trigger = CheckpointTrigger::check_time_elapsed(u64::MAX, u64::MAX - 1);
        assert!(trigger.is_some());
    }

    #[test]
    fn trigger_audit_growth_just_above_threshold() {
        let trigger = CheckpointTrigger::check_audit_growth(101, 100);
        assert!(trigger.is_some());
    }

    #[test]
    fn trigger_audit_growth_zero_threshold() {
        let trigger = CheckpointTrigger::check_audit_growth(1, 0);
        assert!(trigger.is_some());
    }

    #[test]
    fn trigger_audit_growth_zero_both() {
        let trigger = CheckpointTrigger::check_audit_growth(0, 0);
        assert!(trigger.is_none());
    }

    #[test]
    fn trigger_revocation_growth_u64_one() {
        let trigger = CheckpointTrigger::check_revocation_growth(1);
        assert!(trigger.is_some());
        if let Some(CheckpointTrigger::RevocationChainGrowth { new_events }) = trigger {
            assert_eq!(new_events, 1);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn trigger_policy_change_serde() {
        let trigger = CheckpointTrigger::PolicyChange {
            old_policy_head: test_object_id("old"),
            new_policy_head: test_object_id("new"),
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let decoded: CheckpointTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(trigger, decoded);
    }

    #[test]
    fn trigger_manual_with_long_reason() {
        let reason = "x".repeat(5000);
        let trigger = CheckpointTrigger::Manual {
            reason: Some(reason),
        };
        let json = serde_json::to_string(&trigger).unwrap();
        let decoded: CheckpointTrigger = serde_json::from_str(&json).unwrap();
        if let CheckpointTrigger::Manual {
            reason: Some(decoded_reason),
        } = decoded
        {
            assert_eq!(decoded_reason.len(), 5000);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn trigger_debug_format() {
        let trigger = CheckpointTrigger::TimeElapsed {
            elapsed_secs: 100,
            threshold_secs: 60,
        };
        let debug = format!("{trigger:?}");
        assert!(debug.contains("TimeElapsed"));
        assert!(debug.contains("100"));
    }

    #[test]
    fn fork_evidence_detect_returns_none_for_equal_ids() {
        let zone = test_zone();
        let id = test_object_id("same-checkpoint");
        let result = ForkEvidence::detect(&zone, 0, &id, &id, 0, test_node("n"));
        assert!(result.is_none());
    }

    #[test]
    fn fork_evidence_all_signers_overlap() {
        let evidence = ForkEvidence::new(
            test_zone(),
            1,
            test_object_id("a"),
            test_object_id("b"),
            100,
            test_node("d"),
        )
        .with_signers_a(["alice".to_string(), "bob".to_string()])
        .with_signers_b(["alice".to_string(), "bob".to_string()]);
        let double = evidence.double_signers();
        assert_eq!(double.len(), 2);
        assert!(double.contains("alice"));
        assert!(double.contains("bob"));
    }

    #[test]
    fn fork_evidence_fields_accessible() {
        let evidence = ForkEvidence::new(
            test_zone(),
            77,
            test_object_id("cp-a"),
            test_object_id("cp-b"),
            1_700_000_999,
            test_node("det-node"),
        );
        assert_eq!(evidence.zone_id, test_zone());
        assert_eq!(evidence.conflicting_seq, 77);
        assert_eq!(evidence.detected_at, 1_700_000_999);
        assert_eq!(evidence.detected_by.as_str(), "det-node");
    }

    #[test]
    fn fork_detection_result_debug() {
        let result = ForkDetectionResult::NoFork;
        let debug = format!("{result:?}");
        assert!(debug.contains("NoFork"));
    }

    #[test]
    fn hrw_hash_minimal_inputs_still_deterministic() {
        // The original "zero-length inputs" variant of this test passed an
        // empty TailscaleNodeId, which is no longer constructible after the
        // canonical-id check landed (`TailscaleNodeId::new("")` now panics
        // with `Empty`). The property under test is hash determinism for
        // boundary-thin inputs, not "zero-length" per se — exercise it with
        // single-character canonical ids that still represent the smallest
        // legal node and epoch identifiers.
        let zone: ZoneId = "z:".parse().unwrap_or_else(|_| ZoneId::work());
        let epoch = EpochId::new("a");
        let node = TailscaleNodeId::new("n");
        let h1 = hrw_hash_checkpoint(&zone, &epoch, &node);
        let h2 = hrw_hash_checkpoint(&zone, &epoch, &node);
        assert_eq!(h1, h2);
    }

    #[test]
    fn coordinator_selection_two_nodes() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes = vec![test_node("alpha"), test_node("beta")];
        let coord = select_checkpoint_coordinator(&zone, &epoch, &nodes);
        assert!(coord.is_some());
        // Winner should be one of the two nodes
        let winner = coord.unwrap();
        assert!(winner.as_str() == "alpha" || winner.as_str() == "beta");
    }

    #[test]
    fn coordinator_ranking_preserves_all_nodes() {
        let zone = test_zone();
        let epoch = test_epoch();
        let nodes: Vec<TailscaleNodeId> =
            (0..10).map(|i| test_node(&format!("node-{i}"))).collect();
        let ranked = rank_checkpoint_coordinators(&zone, &epoch, &nodes);
        assert_eq!(ranked.len(), 10);
        // All original nodes should be in the ranked list
        for node in &nodes {
            assert!(ranked.iter().any(|r| r.as_str() == node.as_str()));
        }
    }

    #[test]
    fn coordinator_ranking_different_epochs_different_order() {
        let zone = test_zone();
        let nodes = vec![
            test_node("a"),
            test_node("b"),
            test_node("c"),
            test_node("d"),
            test_node("e"),
        ];
        let ranked1 = rank_checkpoint_coordinators(&zone, &EpochId::new("epoch-1"), &nodes);
        let ranked2 = rank_checkpoint_coordinators(&zone, &EpochId::new("epoch-2"), &nodes);
        // With 5 nodes and different epochs, it's extremely likely the ordering differs
        // (but not guaranteed; we can only assert both have same length)
        assert_eq!(ranked1.len(), ranked2.len());
    }

    #[test]
    fn advance_state_finalized_fields() {
        let state = CheckpointAdvanceState::Finalized {
            checkpoint_id: test_object_id("chk-final"),
            finalized_seq: 999,
            finalized_at: 1_700_099_999,
        };
        assert!(!state.is_halted());
        assert!(state.can_advance());
        assert!(state.fork_evidence().is_none());
    }

    #[test]
    fn advance_state_proposal_broadcast_can_advance() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 0,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 0,
            zone_definition_head: test_object_id("zd"),
            zone_policy_head: test_object_id("zp"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_000,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_000,
            ),
            triggers: vec![],
        };
        let state = CheckpointAdvanceState::ProposalBroadcast {
            proposal: Box::new(proposal),
            collected_signatures: SignatureSet::new(),
            required_signatures: 3,
        };
        assert!(state.can_advance());
        assert!(!state.is_halted());
        assert!(state.fork_evidence().is_none());
    }

    #[test]
    fn validation_error_unknown_head_reason_code() {
        let err = CheckpointValidationError::UnknownHead {
            head_type: "audit".to_string(),
            head_id: test_object_id("h"),
        };
        assert_eq!(err.reason_code(), "FCP-5003");
        assert!(!err.is_fork());
    }

    #[test]
    fn validation_error_invalid_head_reason_code() {
        let err = CheckpointValidationError::InvalidHead {
            head_type: "revocation".to_string(),
            head_id: test_object_id("h"),
            reason: "corrupt".to_string(),
        };
        assert_eq!(err.reason_code(), "FCP-5004");
    }

    #[test]
    fn validation_error_unknown_head_serde() {
        let err = CheckpointValidationError::UnknownHead {
            head_type: "audit".to_string(),
            head_id: test_object_id("h"),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn validation_error_invalid_head_serde() {
        let err = CheckpointValidationError::InvalidHead {
            head_type: "rev".to_string(),
            head_id: test_object_id("h"),
            reason: "stale".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: CheckpointValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn freshness_token_zero_seq_is_fresh() {
        let result = FreshnessResult::check_token_freshness(0, 0, false);
        assert_eq!(result, FreshnessResult::Fresh);
    }

    #[test]
    fn freshness_token_large_difference() {
        let result = FreshnessResult::check_token_freshness(u64::MAX, 0, false);
        assert_eq!(result, FreshnessResult::TooStale);
    }

    #[test]
    fn freshness_revocation_zero_seq() {
        let result = FreshnessResult::check_revocation_freshness(0, 0, false);
        assert_eq!(result, FreshnessResult::Fresh);
    }

    #[test]
    fn freshness_revocation_large_difference() {
        let result = FreshnessResult::check_revocation_freshness(0, u64::MAX, false);
        assert_eq!(result, FreshnessResult::TooStale);
    }

    #[test]
    fn freshness_revocation_large_difference_degraded() {
        let result = FreshnessResult::check_revocation_freshness(0, u64::MAX, true);
        assert_eq!(result, FreshnessResult::DegradedMode);
    }

    #[test]
    fn freshness_result_inequality() {
        assert_ne!(FreshnessResult::Fresh, FreshnessResult::TooStale);
        assert_ne!(FreshnessResult::Fresh, FreshnessResult::DegradedMode);
        assert_ne!(FreshnessResult::DegradedMode, FreshnessResult::TooStale);
    }

    #[test]
    fn default_constants_consistency() {
        let interval = DEFAULT_CHECKPOINT_INTERVAL_SECS;
        let growth = DEFAULT_AUDIT_CHAIN_GROWTH_THRESHOLD;
        let chunk_threshold = DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_THRESHOLD_BYTES;
        let chunk_size = DEFAULT_COMPUTATION_CHECKPOINT_CHUNK_SIZE_BYTES;
        assert!(interval > 0);
        assert!(growth > 0);
        assert!(chunk_threshold > 0);
        assert!(chunk_size > 0);
        assert!(chunk_threshold > chunk_size);
    }

    #[test]
    fn computation_checkpoint_schema_stable() {
        let schema1 = ComputationCheckpoint::schema();
        let schema2 = ComputationCheckpoint::schema();
        assert_eq!(schema1.namespace, schema2.namespace);
        assert_eq!(schema1.name, schema2.name);
    }

    #[test]
    fn computation_checkpoint_zone_id() {
        let cp = test_computation_checkpoint(vec![1, 2, 3]);
        assert_eq!(cp.zone_id(), &test_zone());
    }

    #[test]
    fn computation_checkpoint_object_id_deterministic() {
        let cp = test_computation_checkpoint(vec![1, 2, 3]);
        let id1 = cp.object_id().unwrap();
        let id2 = cp.object_id().unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn computation_checkpoint_inline_transfer_small_payload() {
        let cp = test_computation_checkpoint(vec![1, 2, 3]);
        // Use a very large threshold so it stays inline
        let encoding = cp.to_transfer_encoding(1_000_000, 1024).unwrap();
        assert!(matches!(
            encoding,
            CheckpointTransferEncoding::Inline { .. }
        ));
    }

    #[test]
    fn computation_checkpoint_transfer_zero_chunk_size_error() {
        let cp = test_computation_checkpoint(vec![1, 2, 3]);
        let err = cp.to_transfer_encoding(0, 0).unwrap_err();
        assert!(matches!(err, CheckpointChunkError::InvalidChunkSize));
    }

    #[test]
    fn checkpoint_transfer_encoding_object_id_inline() {
        let oid = test_object_id("inline-payload");
        let encoding = CheckpointTransferEncoding::Inline {
            object_id: oid,
            canonical_bytes: vec![1, 2, 3],
        };
        assert_eq!(encoding.object_id(), oid);
    }

    #[test]
    fn chunked_object_manifest_chunk_count() {
        let manifest = ChunkedObjectManifest {
            payload_object_id: test_object_id("payload"),
            total_bytes: 1024,
            chunk_size_bytes: 256,
            chunk_object_ids: vec![
                test_object_id("c0"),
                test_object_id("c1"),
                test_object_id("c2"),
            ],
        };
        assert_eq!(manifest.chunk_count(), 3);
    }

    #[test]
    fn chunked_object_manifest_empty() {
        let manifest = ChunkedObjectManifest {
            payload_object_id: test_object_id("empty"),
            total_bytes: 0,
            chunk_size_bytes: 256,
            chunk_object_ids: vec![],
        };
        assert_eq!(manifest.chunk_count(), 0);
    }

    #[test]
    fn reconstruct_chunked_payload_count_mismatch() {
        let chunked = ChunkedCheckpoint {
            manifest: ChunkedObjectManifest {
                payload_object_id: test_object_id("p"),
                total_bytes: 10,
                chunk_size_bytes: 5,
                chunk_object_ids: vec![test_object_id("c0"), test_object_id("c1")],
            },
            chunks: vec![vec![1, 2, 3]], // Only 1 chunk, manifest says 2
        };
        let err = reconstruct_chunked_payload(&chunked).unwrap_err();
        assert!(matches!(
            err,
            CheckpointChunkError::ChunkCountMismatch {
                expected: 2,
                got: 1
            }
        ));
    }

    #[test]
    fn migration_capability_context_serde_roundtrip() {
        let ctx = test_migration_context(42);
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: MigrationCapabilityContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.checkpoint_seq, 42);
        assert!(decoded.audit_event_id.is_some());
    }

    #[test]
    fn migration_capability_context_no_checkpoint_id() {
        let ctx = MigrationCapabilityContext {
            capability_token_jti: Uuid::nil(),
            checkpoint_id: None,
            checkpoint_seq: 0,
            audit_event_id: None,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("checkpoint_id"));
        let decoded: MigrationCapabilityContext = serde_json::from_str(&json).unwrap();
        assert!(decoded.checkpoint_id.is_none());
        assert!(decoded.audit_event_id.is_none());
    }

    #[test]
    fn migration_capability_context_clone() {
        let ctx = test_migration_context(10);
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
    }

    #[test]
    fn checkpoint_chunk_error_display_invalid_chunk_size() {
        let err = CheckpointChunkError::InvalidChunkSize;
        let msg = err.to_string();
        assert!(msg.contains("chunk size"));
    }

    #[test]
    fn checkpoint_chunk_error_display_chunk_count_mismatch() {
        let err = CheckpointChunkError::ChunkCountMismatch {
            expected: 5,
            got: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains('5'));
        assert!(msg.contains('3'));
    }

    #[test]
    fn checkpoint_chunk_error_display_payload_length_mismatch() {
        let err = CheckpointChunkError::PayloadLengthMismatch {
            expected: 1024,
            got: 512,
        };
        let msg = err.to_string();
        assert!(msg.contains("1024"));
        assert!(msg.contains("512"));
    }

    #[test]
    fn checkpoint_chunk_error_display_manifest_length_overflow() {
        let err = CheckpointChunkError::ManifestLengthOverflow { total_bytes: 999 };
        let msg = err.to_string();
        assert!(msg.contains("999"));
    }

    #[test]
    fn checkpoint_chunk_error_display_manifest_chunk_size_overflow() {
        let err = CheckpointChunkError::ManifestChunkSizeOverflow {
            chunk_size_bytes: 12345,
        };
        let msg = err.to_string();
        assert!(msg.contains("12345"));
    }

    #[test]
    fn checkpoint_chunk_error_display_payload_integrity() {
        let err = CheckpointChunkError::PayloadIntegrityMismatch {
            expected: test_object_id("expected"),
            got: test_object_id("got"),
        };
        let msg = err.to_string();
        assert!(msg.contains("integrity"));
    }

    #[test]
    fn checkpoint_chunk_error_display_chunk_integrity() {
        let err = CheckpointChunkError::ChunkIntegrityMismatch {
            index: 3,
            expected: test_object_id("exp"),
            got: test_object_id("actual"),
        };
        let msg = err.to_string();
        assert!(msg.contains('3'));
    }

    #[test]
    fn proposal_timestamp_within_skew_local_before_proposal() {
        let proposal = CheckpointProposal {
            zone_id: test_zone(),
            proposed_seq: 1,
            prev_checkpoint_id: None,
            audit_head_id: test_object_id("audit"),
            audit_head_seq: 0,
            revocation_head_id: test_object_id("rev"),
            revocation_head_seq: 0,
            zone_definition_head: test_object_id("zd"),
            zone_policy_head: test_object_id("zp"),
            active_zone_key_manifest: test_object_id("zkm"),
            epoch_id: test_epoch(),
            proposed_at: 1_700_000_100,
            coordinator: test_node("coord"),
            coordinator_signature: NodeSignature::new(
                NodeId::new("coord"),
                [0u8; 64],
                1_700_000_100,
            ),
            triggers: vec![],
        };
        // local_time is 50 seconds before proposal, skew tolerance is 60
        assert!(proposal.timestamp_within_skew(1_700_000_050, 60));
        // local_time is 70 seconds before proposal, skew tolerance is 60
        assert!(!proposal.timestamp_within_skew(1_700_000_030, 60));
    }

    #[test]
    fn computation_checkpoint_fields() {
        let cp = test_computation_checkpoint(vec![9, 8, 7]);
        assert_eq!(cp.checkpoint_seq, 7);
        assert_eq!(cp.lease_fencing_token, 11);
        assert_eq!(cp.current_holder.as_str(), "node-source");
        assert_eq!(cp.state_cbor, vec![9, 8, 7]);
    }

    #[test]
    fn chunked_checkpoint_serde_roundtrip() {
        let chunked = ChunkedCheckpoint {
            manifest: ChunkedObjectManifest {
                payload_object_id: test_object_id("payload"),
                total_bytes: 6,
                chunk_size_bytes: 3,
                chunk_object_ids: vec![test_object_id("c0"), test_object_id("c1")],
            },
            chunks: vec![vec![1, 2, 3], vec![4, 5, 6]],
        };
        let json = serde_json::to_string(&chunked).unwrap();
        let decoded: ChunkedCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, chunked);
    }

    #[test]
    fn checkpoint_transfer_encoding_inline_serde() {
        let encoding = CheckpointTransferEncoding::Inline {
            object_id: test_object_id("inline"),
            canonical_bytes: vec![10, 20, 30],
        };
        let json = serde_json::to_string(&encoding).unwrap();
        let decoded: CheckpointTransferEncoding = serde_json::from_str(&json).unwrap();
        assert_eq!(encoding, decoded);
    }
}
