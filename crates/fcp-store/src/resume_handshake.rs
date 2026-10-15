//! Resume-on-target handshake for process snapshot rehydration.
//!
//! The protocol is deliberately data-shaped and canonical: a source announces
//! the snapshot manifest hash, the target acknowledges freshness and capability
//! availability, the source streams the manifest bytes as `RaptorQ` symbols, and
//! the target confirms rehydration before the source lease may be released.

use std::collections::BTreeMap;

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use fcp_prelude::ObjectId;
use fcp_raptorq::{
    DecodeError, EncodeError, RaptorQConfig, RaptorQDecoder, RaptorQEncoder, RaptorQSymbolFrame,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ObjectTransmissionInfo, ProcessSnapshotError, ProcessSnapshotManifest,
    ProcessSnapshotTrustAnchors,
};

/// Default upper bound for a resume handshake.
pub const DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS: u64 = 30_000;

const RESUME_HANDSHAKE_ID_DOMAIN: &[u8] = b"FCP-STORE-RESUME-HANDSHAKE-ID-V1";

/// Errors raised while validating a resume-on-target transcript.
#[derive(Debug, Error)]
pub enum ResumeHandshakeError {
    /// Canonical CBOR encoding or decoding failed.
    #[error("canonical serialization error: {0}")]
    Serialization(#[from] SerializationError),

    /// Snapshot manifest verification failed.
    #[error("process snapshot error: {0}")]
    Snapshot(#[from] ProcessSnapshotError),

    /// `RaptorQ` encoding failed.
    #[error("raptorq encode error: {0}")]
    Encode(#[from] EncodeError),

    /// `RaptorQ` decoding failed.
    #[error("raptorq decode error: {0}")]
    Decode(#[from] DecodeError),

    /// A message belongs to a different handshake or snapshot manifest.
    #[error("resume handshake linkage mismatch: {reason}")]
    LinkageMismatch {
        /// Human-readable mismatch reason.
        reason: String,
    },

    /// Target rejected the resume because snapshot or capability checks failed.
    #[error("target rejected resume: freshness={freshness:?}, capability={capability:?}")]
    TargetRejected {
        /// Target's view of snapshot freshness.
        freshness: SnapshotFreshness,
        /// Target's view of restore capability availability.
        capability: CapabilityAvailability,
    },

    /// The handshake exceeded its configured timeout.
    #[error("resume handshake timed out after {elapsed_ms}ms (timeout {timeout_ms}ms)")]
    Timeout {
        /// Observed elapsed milliseconds.
        elapsed_ms: u64,
        /// Configured timeout.
        timeout_ms: u64,
    },

    /// A later step arrived before its prerequisite.
    #[error("resume handshake out of order: {reason}")]
    OutOfOrder {
        /// Human-readable ordering violation.
        reason: String,
    },

    /// Source lease release was observed before target rehydration succeeded.
    #[error("source lease release observed before successful target rehydration")]
    LeaseReleasedBeforeRehydration,

    /// Target did not report successful rehydration.
    #[error("target did not successfully rehydrate: {status:?}")]
    RehydrationFailed {
        /// Reported rehydration status.
        status: RehydrationStatus,
    },

    /// Replaying the same operation id produced conflicting effects.
    #[error("in-flight operation {op_id} replayed with conflicting effect hash")]
    ReplayConflict {
        /// Operation identifier with inconsistent effects.
        op_id: String,
    },

    /// A source-side in-flight operation was not replayed on the target.
    #[error("in-flight operation {op_id} was not replayed on target")]
    MissingReplayOperation {
        /// Missing operation identifier.
        op_id: String,
    },

    /// A symbol frame did not match the request's expected stream.
    #[error("snapshot symbol frame mismatch: {reason}")]
    SymbolFrameMismatch {
        /// Human-readable mismatch reason.
        reason: String,
    },

    /// The provided symbols did not reconstruct the manifest bytes.
    #[error("snapshot symbol stream did not reconstruct manifest bytes")]
    IncompleteSnapshotStream,

    /// Reconstructed bytes were not the announced manifest object.
    #[error("snapshot manifest hash mismatch: expected {expected}, actual {actual}")]
    SnapshotManifestHashMismatch {
        /// Manifest hash announced by the source.
        expected: ObjectId,
        /// Manifest hash reconstructed from the stream.
        actual: ObjectId,
    },
}

/// Target's freshness decision for the announced manifest hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotFreshness {
    /// Target has no newer snapshot and can accept this one.
    Fresh,
    /// Target has a newer or incompatible snapshot.
    Stale,
    /// Target cannot determine freshness.
    Unknown,
}

/// Target's capability availability decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAvailability {
    /// Target has the capability material required to restore.
    Available,
    /// Target does not have the required capability.
    Missing,
    /// Capability was revoked.
    Revoked,
    /// Capability exists but is expired.
    Expired,
}

/// Target-side terminal rehydration status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RehydrationStatus {
    /// Snapshot was rehydrated and the connector resumed.
    Rehydrated,
    /// Target failed before a safe switchover point.
    Failed,
    /// Target rolled back and source must retain the lease.
    RolledBack,
}

/// One post-snapshot operation that must be replayed idempotently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeReplayOp {
    /// Stable operation id from the source-side in-flight log.
    pub op_id: String,
    /// Canonical effect hash for idempotence checks.
    pub effect_hash: [u8; 32],
}

impl ResumeReplayOp {
    /// Build a replay operation from canonical effect bytes.
    #[must_use]
    pub fn from_effect(op_id: impl Into<String>, effect_bytes: &[u8]) -> Self {
        Self {
            op_id: op_id.into(),
            effect_hash: *blake3::hash(effect_bytes).as_bytes(),
        }
    }
}

/// Source-to-target resume request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeHandshakeRequest {
    /// Deterministic id for this resume attempt.
    pub handshake_id: ObjectId,
    /// Source node currently holding the execution lease.
    pub source_node: String,
    /// Candidate target node.
    pub target_node: String,
    /// Content address of the canonical snapshot manifest bytes.
    pub snapshot_manifest_hash: ObjectId,
    /// Snapshot id carried inside the manifest.
    pub snapshot_id: ObjectId,
    /// Capability-token pin copied from the manifest for target preflight.
    pub capability_token_pinned: [u8; 32],
    /// `RaptorQ` transmission info for the manifest byte stream.
    pub raptorq: ObjectTransmissionInfo,
    /// Source-side execution lease fencing token.
    pub lease_fencing_token: u64,
    /// Start timestamp in milliseconds.
    pub started_at_ms: u64,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Operations logged after snapshot capture and before switchover.
    pub in_flight_ops: Vec<ResumeReplayOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResumeHandshakeIdentity {
    source_node: String,
    target_node: String,
    snapshot_manifest_hash: ObjectId,
    snapshot_id: ObjectId,
    capability_token_pinned: [u8; 32],
    raptorq: ObjectTransmissionInfo,
    lease_fencing_token: u64,
    started_at_ms: u64,
    timeout_ms: u64,
    in_flight_ops: Vec<ResumeReplayOp>,
}

impl ResumeHandshakeRequest {
    /// Build a request from a signed snapshot manifest and stream metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError`] if the manifest id or canonical
    /// handshake id cannot be derived.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        source_node: impl Into<String>,
        target_node: impl Into<String>,
        snapshot_manifest: &ProcessSnapshotManifest,
        raptorq: ObjectTransmissionInfo,
        lease_fencing_token: u64,
        started_at_ms: u64,
        timeout_ms: u64,
        in_flight_ops: Vec<ResumeReplayOp>,
    ) -> Result<Self, ResumeHandshakeError> {
        snapshot_manifest.verify_snapshot_id()?;
        let source_node = source_node.into();
        let target_node = target_node.into();
        let snapshot_manifest_hash = snapshot_manifest.manifest_object_id()?;
        let identity = ResumeHandshakeIdentity {
            source_node: source_node.clone(),
            target_node: target_node.clone(),
            snapshot_manifest_hash,
            snapshot_id: snapshot_manifest.snapshot_id,
            capability_token_pinned: snapshot_manifest.capability_token_pinned,
            raptorq,
            lease_fencing_token,
            started_at_ms,
            timeout_ms,
            in_flight_ops: canonical_replay_ops(&in_flight_ops)?,
        };
        let handshake_id = derive_handshake_id(&identity)?;

        Ok(Self {
            handshake_id,
            source_node,
            target_node,
            snapshot_manifest_hash,
            snapshot_id: snapshot_manifest.snapshot_id,
            capability_token_pinned: snapshot_manifest.capability_token_pinned,
            raptorq,
            lease_fencing_token,
            started_at_ms,
            timeout_ms,
            in_flight_ops: identity.in_flight_ops,
        })
    }

    /// Recompute the content binding of a received or deserialized request.
    ///
    /// This is linkage validation, not authentication: the surrounding mesh
    /// transport must authenticate peers and enforce capability and lease policy.
    ///
    /// # Errors
    /// Returns an error if request fields no longer match `handshake_id`, or
    /// duplicate replay operations disagree about their effects.
    pub fn validate_identity(&self) -> Result<(), ResumeHandshakeError> {
        let computed = derive_handshake_id(&self.identity()?)?;
        if computed != self.handshake_id {
            return Err(ResumeHandshakeError::LinkageMismatch {
                reason: "request fields differ from their handshake identity".into(),
            });
        }
        Ok(())
    }

    fn identity(&self) -> Result<ResumeHandshakeIdentity, ResumeHandshakeError> {
        Ok(ResumeHandshakeIdentity {
            source_node: self.source_node.clone(),
            target_node: self.target_node.clone(),
            snapshot_manifest_hash: self.snapshot_manifest_hash,
            snapshot_id: self.snapshot_id,
            capability_token_pinned: self.capability_token_pinned,
            raptorq: self.raptorq,
            lease_fencing_token: self.lease_fencing_token,
            started_at_ms: self.started_at_ms,
            timeout_ms: self.timeout_ms,
            in_flight_ops: canonical_replay_ops(&self.in_flight_ops)?,
        })
    }

    /// Encode a manifest byte stream as handshake-bound snapshot symbols.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError::Encode`] if `RaptorQ` refuses the
    /// payload, or [`ResumeHandshakeError::SymbolFrameMismatch`] if the bytes
    /// do not match the request's announced object or OTI.
    pub fn encode_snapshot_manifest_symbols(
        &self,
        manifest_bytes: &[u8],
        config: &RaptorQConfig,
        first_sent_at_ms: u64,
    ) -> Result<Vec<ResumeSnapshotSymbol>, ResumeHandshakeError> {
        self.validate_identity()?;
        let actual_hash = ObjectId::from_unscoped_bytes(manifest_bytes);
        if actual_hash != self.snapshot_manifest_hash {
            return Err(ResumeHandshakeError::SnapshotManifestHashMismatch {
                expected: self.snapshot_manifest_hash,
                actual: actual_hash,
            });
        }

        let encoder = RaptorQEncoder::new(manifest_bytes, config)?;
        let oti = encoder.transmission_info();
        if ObjectTransmissionInfo::from_oti(oti) != self.raptorq {
            return Err(ResumeHandshakeError::SymbolFrameMismatch {
                reason: "encoder OTI does not match request".into(),
            });
        }

        Ok(encoder
            .into_encode_all()
            .into_iter()
            .enumerate()
            .map(|(ordinal, (esi, data))| ResumeSnapshotSymbol {
                handshake_id: self.handshake_id,
                snapshot_manifest_hash: self.snapshot_manifest_hash,
                frame: RaptorQSymbolFrame::new(self.snapshot_manifest_hash, oti, esi, data),
                ordinal: u32::try_from(ordinal).unwrap_or(u32::MAX),
                sent_at_ms: first_sent_at_ms.saturating_add(u64::try_from(ordinal).unwrap_or(0)),
            })
            .collect())
    }

    /// Return the configured timeout, substituting the default for zero.
    #[must_use]
    pub const fn effective_timeout_ms(&self) -> u64 {
        if self.timeout_ms == 0 {
            DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS
        } else {
            self.timeout_ms
        }
    }
}

/// Target acknowledgement of snapshot freshness and capability availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeTargetAck {
    /// Handshake being acknowledged.
    pub handshake_id: ObjectId,
    /// Snapshot manifest hash being acknowledged.
    pub snapshot_manifest_hash: ObjectId,
    /// Target freshness decision.
    pub freshness: SnapshotFreshness,
    /// Target capability decision.
    pub capability: CapabilityAvailability,
    /// Optional resource reservation id.
    pub resource_reservation_id: Option<String>,
    /// Target acknowledgement timestamp in milliseconds.
    pub acked_at_ms: u64,
    /// Target's expected stream metadata.
    pub expected_raptorq: ObjectTransmissionInfo,
}

impl ResumeTargetAck {
    /// Build an accepting target acknowledgement.
    #[must_use]
    pub fn accept(
        request: &ResumeHandshakeRequest,
        resource_reservation_id: impl Into<Option<String>>,
        acked_at_ms: u64,
    ) -> Self {
        Self {
            handshake_id: request.handshake_id,
            snapshot_manifest_hash: request.snapshot_manifest_hash,
            freshness: SnapshotFreshness::Fresh,
            capability: CapabilityAvailability::Available,
            resource_reservation_id: resource_reservation_id.into(),
            acked_at_ms,
            expected_raptorq: request.raptorq,
        }
    }

    /// Whether target preflight accepted the resume.
    #[must_use]
    pub const fn is_acceptance(&self) -> bool {
        matches!(self.freshness, SnapshotFreshness::Fresh)
            && matches!(self.capability, CapabilityAvailability::Available)
    }
}

/// One manifest byte-stream symbol within the resume handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeSnapshotSymbol {
    /// Handshake this symbol belongs to.
    pub handshake_id: ObjectId,
    /// Snapshot manifest hash being streamed.
    pub snapshot_manifest_hash: ObjectId,
    /// `RaptorQ` symbol frame.
    pub frame: RaptorQSymbolFrame,
    /// Monotonic ordinal within this handshake stream.
    pub ordinal: u32,
    /// Send timestamp in milliseconds.
    pub sent_at_ms: u64,
}

/// Target completion acknowledgement after replay and resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeTargetComplete {
    /// Handshake being completed.
    pub handshake_id: ObjectId,
    /// Snapshot manifest hash that was rehydrated.
    pub snapshot_manifest_hash: ObjectId,
    /// Target rehydration status.
    pub status: RehydrationStatus,
    /// Idempotently replayed post-snapshot operations.
    pub replayed_ops: Vec<ResumeReplayOp>,
    /// Resume completion timestamp in milliseconds.
    pub resumed_at_ms: u64,
}

impl ResumeTargetComplete {
    /// Build a successful target completion acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError::ReplayConflict`] if duplicate replay ids
    /// carry conflicting effect hashes.
    #[allow(clippy::needless_pass_by_value)]
    pub fn rehydrated(
        request: &ResumeHandshakeRequest,
        replayed_ops: Vec<ResumeReplayOp>,
        resumed_at_ms: u64,
    ) -> Result<Self, ResumeHandshakeError> {
        Ok(Self {
            handshake_id: request.handshake_id,
            snapshot_manifest_hash: request.snapshot_manifest_hash,
            status: RehydrationStatus::Rehydrated,
            replayed_ops: canonical_replay_ops(&replayed_ops)?,
            resumed_at_ms,
        })
    }
}

/// Source-side lease release after target rehydration succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeSourceLeaseRelease {
    /// Handshake being released.
    pub handshake_id: ObjectId,
    /// Snapshot manifest hash that was moved.
    pub snapshot_manifest_hash: ObjectId,
    /// Released source lease fencing token.
    pub lease_fencing_token: u64,
    /// Release timestamp in milliseconds.
    pub released_at_ms: u64,
}

impl ResumeSourceLeaseRelease {
    /// Build the source release message.
    #[must_use]
    pub const fn new(request: &ResumeHandshakeRequest, released_at_ms: u64) -> Self {
        Self {
            handshake_id: request.handshake_id,
            snapshot_manifest_hash: request.snapshot_manifest_hash,
            lease_fencing_token: request.lease_fencing_token,
            released_at_ms,
        }
    }
}

/// Canonical message envelope for the resume handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ResumeHandshakeMessage {
    /// Source starts the resume.
    Request(ResumeHandshakeRequest),
    /// Target accepts or rejects preflight.
    TargetAck(ResumeTargetAck),
    /// Source streams one snapshot manifest symbol.
    SnapshotSymbol(ResumeSnapshotSymbol),
    /// Target confirms rehydration/resume.
    TargetComplete(ResumeTargetComplete),
    /// Source releases its lease after target success.
    SourceLeaseRelease(ResumeSourceLeaseRelease),
}

impl ResumeHandshakeMessage {
    /// Canonical schema for resume handshake messages.
    #[must_use]
    pub fn schema_id() -> SchemaId {
        SchemaId::new("fcp.store", "ResumeHandshakeMessage", Version::new(1, 0, 0))
    }

    /// Encode this message as schema-prefixed canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError::Serialization`] when canonical encoding
    /// fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ResumeHandshakeError> {
        Ok(CanonicalSerializer::serialize(self, &Self::schema_id())?)
    }

    /// Decode a canonical resume handshake message.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError::Serialization`] when schema validation
    /// or canonical decoding fails.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ResumeHandshakeError> {
        Ok(CanonicalSerializer::deserialize(bytes, &Self::schema_id())?)
    }
}

/// Full successful resume transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeHandshakeTranscript {
    /// Source request.
    pub request: ResumeHandshakeRequest,
    /// Target preflight acknowledgement.
    pub ack: ResumeTargetAck,
    /// Manifest byte-stream symbols.
    pub symbols: Vec<ResumeSnapshotSymbol>,
    /// Target rehydration completion.
    pub complete: ResumeTargetComplete,
    /// Source release after completion.
    pub source_release: ResumeSourceLeaseRelease,
}

impl ResumeHandshakeTranscript {
    /// Validate ordering, timeout, target preflight, replay idempotence, and
    /// atomic source lease release.
    ///
    /// This checks transcript consistency, not peer authentication, actual
    /// process liveness, or payload reconstruction. Verify the signed manifest
    /// and its payload separately before restoring any process state.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError`] for any invalid transcript invariant.
    pub fn validate_success(&self) -> Result<(), ResumeHandshakeError> {
        self.validate_preflight()?;
        self.validate_symbols()?;
        self.validate_completion()?;
        self.validate_source_release()
    }

    /// Decode the streamed snapshot manifest bytes using `RaptorQ`.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError`] when preflight or symbol linkage fails,
    /// the stream is incomplete, or the reconstructed bytes do not match the
    /// announced manifest hash.
    pub fn decode_snapshot_manifest_bytes(
        &self,
        config: &RaptorQConfig,
    ) -> Result<Vec<u8>, ResumeHandshakeError> {
        self.validate_preflight()?;
        self.validate_symbols()?;

        let mut decoder = RaptorQDecoder::new(self.request.raptorq.to_oti(), config);
        let mut decoded_manifest = None;
        for symbol in &self.symbols {
            if let Some(bytes) = decoder.add_symbol(symbol.frame.esi, symbol.frame.data.clone())? {
                decoded_manifest = Some(bytes);
                break;
            }
        }

        let bytes = decoded_manifest.ok_or(ResumeHandshakeError::IncompleteSnapshotStream)?;
        let actual = ObjectId::from_unscoped_bytes(&bytes);
        if actual != self.request.snapshot_manifest_hash {
            return Err(ResumeHandshakeError::SnapshotManifestHashMismatch {
                expected: self.request.snapshot_manifest_hash,
                actual,
            });
        }
        Ok(bytes)
    }

    /// Decode and verify the streamed snapshot manifest before target-side
    /// state unmarshalling.
    ///
    /// # Errors
    ///
    /// Returns [`ResumeHandshakeError`] if reconstruction, signature
    /// validation, or capability-token pinning fails.
    pub fn decode_verified_snapshot_manifest(
        &self,
        config: &RaptorQConfig,
        capability_token_bytes: &[u8],
        trust_anchors: &ProcessSnapshotTrustAnchors,
    ) -> Result<ProcessSnapshotManifest, ResumeHandshakeError> {
        let bytes = self.decode_snapshot_manifest_bytes(config)?;
        let manifest = ProcessSnapshotManifest::decode_verified(
            &bytes,
            capability_token_bytes,
            trust_anchors,
        )?;
        let actual = manifest.manifest_object_id()?;
        if actual != self.request.snapshot_manifest_hash {
            return Err(ResumeHandshakeError::SnapshotManifestHashMismatch {
                expected: self.request.snapshot_manifest_hash,
                actual,
            });
        }
        if manifest.snapshot_id != self.request.snapshot_id
            || manifest.capability_token_pinned != self.request.capability_token_pinned
        {
            return Err(ResumeHandshakeError::LinkageMismatch {
                reason: "verified manifest differs from the snapshot or capability pin accepted in preflight".into(),
            });
        }
        Ok(manifest)
    }

    /// Return a source-retained rollback plan if the handshake has timed out
    /// before successful target completion.
    #[must_use]
    pub fn rollback_if_timed_out(&self, now_ms: u64) -> Option<ResumeRollbackPlan> {
        let elapsed = now_ms.saturating_sub(self.request.started_at_ms);
        if elapsed <= self.request.effective_timeout_ms() {
            return None;
        }
        // A bare status marker from another attempt, a late completion, or a
        // missing replay must not settle this timeout. Source release is not
        // required here: valid target completion precedes that separate step.
        if self
            .validate_preflight()
            .and_then(|()| self.validate_symbols())
            .and_then(|()| self.validate_completion())
            .is_ok()
        {
            return None;
        }

        Some(ResumeRollbackPlan {
            handshake_id: self.request.handshake_id,
            source_node: self.request.source_node.clone(),
            target_node: self.request.target_node.clone(),
            snapshot_manifest_hash: self.request.snapshot_manifest_hash,
            reason: ResumeRollbackReason::Timeout,
            keep_source_lease: true,
        })
    }

    fn validate_preflight(&self) -> Result<(), ResumeHandshakeError> {
        self.request.validate_identity()?;
        ensure_linkage(
            self.request.handshake_id,
            self.request.snapshot_manifest_hash,
            self.ack.handshake_id,
            self.ack.snapshot_manifest_hash,
            "target ack",
        )?;
        if self.ack.expected_raptorq != self.request.raptorq {
            return Err(ResumeHandshakeError::LinkageMismatch {
                reason: "target ack expected different raptorq metadata".into(),
            });
        }
        ensure_elapsed_within_timeout(
            self.request.started_at_ms,
            self.ack.acked_at_ms,
            self.request.effective_timeout_ms(),
        )?;
        if !self.ack.is_acceptance() {
            return Err(ResumeHandshakeError::TargetRejected {
                freshness: self.ack.freshness,
                capability: self.ack.capability,
            });
        }
        Ok(())
    }

    fn validate_symbols(&self) -> Result<(), ResumeHandshakeError> {
        if self.symbols.is_empty() {
            return Err(ResumeHandshakeError::IncompleteSnapshotStream);
        }
        let mut previous_ordinal = None;
        let mut previous_sent_at_ms = self.ack.acked_at_ms;
        for symbol in &self.symbols {
            ensure_linkage(
                self.request.handshake_id,
                self.request.snapshot_manifest_hash,
                symbol.handshake_id,
                symbol.snapshot_manifest_hash,
                "snapshot symbol",
            )?;
            if symbol.sent_at_ms < previous_sent_at_ms {
                return Err(ResumeHandshakeError::OutOfOrder {
                    reason: "snapshot symbol sent before target ack or preceding symbol".into(),
                });
            }
            ensure_elapsed_within_timeout(
                self.request.started_at_ms,
                symbol.sent_at_ms,
                self.request.effective_timeout_ms(),
            )?;
            if symbol.frame.object_id != self.request.snapshot_manifest_hash {
                return Err(ResumeHandshakeError::SymbolFrameMismatch {
                    reason: "symbol object id differs from announced manifest hash".into(),
                });
            }
            if ObjectTransmissionInfo::from_oti(symbol.frame.oti) != self.request.raptorq {
                return Err(ResumeHandshakeError::SymbolFrameMismatch {
                    reason: "symbol OTI differs from request".into(),
                });
            }
            if !symbol.frame.has_expected_symbol_size() {
                return Err(ResumeHandshakeError::SymbolFrameMismatch {
                    reason: "symbol payload length differs from OTI symbol size".into(),
                });
            }
            if let Some(previous) = previous_ordinal
                && symbol.ordinal <= previous
            {
                return Err(ResumeHandshakeError::OutOfOrder {
                    reason: "snapshot symbol ordinals must increase".into(),
                });
            }
            previous_ordinal = Some(symbol.ordinal);
            previous_sent_at_ms = symbol.sent_at_ms;
        }
        Ok(())
    }

    fn validate_completion(&self) -> Result<(), ResumeHandshakeError> {
        ensure_linkage(
            self.request.handshake_id,
            self.request.snapshot_manifest_hash,
            self.complete.handshake_id,
            self.complete.snapshot_manifest_hash,
            "target completion",
        )?;
        let last_symbol_at = self
            .symbols
            .last()
            .map_or(self.ack.acked_at_ms, |symbol| symbol.sent_at_ms);
        if self.complete.resumed_at_ms < last_symbol_at {
            return Err(ResumeHandshakeError::OutOfOrder {
                reason: "target completion before last snapshot symbol".into(),
            });
        }
        ensure_elapsed_within_timeout(
            self.request.started_at_ms,
            self.complete.resumed_at_ms,
            self.request.effective_timeout_ms(),
        )?;
        if !matches!(self.complete.status, RehydrationStatus::Rehydrated) {
            return Err(ResumeHandshakeError::RehydrationFailed {
                status: self.complete.status,
            });
        }
        validate_replay_set(&self.request.in_flight_ops, &self.complete.replayed_ops)
    }

    fn validate_source_release(&self) -> Result<(), ResumeHandshakeError> {
        ensure_linkage(
            self.request.handshake_id,
            self.request.snapshot_manifest_hash,
            self.source_release.handshake_id,
            self.source_release.snapshot_manifest_hash,
            "source release",
        )?;
        if self.source_release.lease_fencing_token != self.request.lease_fencing_token {
            return Err(ResumeHandshakeError::LinkageMismatch {
                reason: "source release fencing token differs from request".into(),
            });
        }
        if self.source_release.released_at_ms < self.complete.resumed_at_ms {
            return Err(ResumeHandshakeError::LeaseReleasedBeforeRehydration);
        }
        Ok(())
    }
}

/// Reason a target resume attempt rolls back to the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeRollbackReason {
    /// The handshake exceeded its timeout.
    Timeout,
    /// Target rejected snapshot freshness.
    StaleSnapshot,
    /// Target could not satisfy restore capability requirements.
    CapabilityUnavailable,
    /// Target failed during rehydration.
    RehydrationFailed,
}

/// Source-retained rollback plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeRollbackPlan {
    /// Handshake that rolled back.
    pub handshake_id: ObjectId,
    /// Source node that must retain execution.
    pub source_node: String,
    /// Failed target node.
    pub target_node: String,
    /// Snapshot manifest hash involved in the attempt.
    pub snapshot_manifest_hash: ObjectId,
    /// Rollback reason.
    pub reason: ResumeRollbackReason,
    /// Whether the source lease must be retained.
    pub keep_source_lease: bool,
}

fn derive_handshake_id(
    identity: &ResumeHandshakeIdentity,
) -> Result<ObjectId, ResumeHandshakeError> {
    let identity_bytes = CanonicalSerializer::serialize(identity, &handshake_identity_schema_id())?;
    let mut content = Vec::with_capacity(RESUME_HANDSHAKE_ID_DOMAIN.len() + identity_bytes.len());
    content.extend_from_slice(RESUME_HANDSHAKE_ID_DOMAIN);
    content.extend_from_slice(&identity_bytes);
    Ok(ObjectId::from_unscoped_bytes(&content))
}

fn handshake_identity_schema_id() -> SchemaId {
    SchemaId::new(
        "fcp.store",
        "ResumeHandshakeIdentity",
        Version::new(1, 0, 0),
    )
}

fn ensure_linkage(
    expected_handshake_id: ObjectId,
    expected_manifest_hash: ObjectId,
    actual_handshake_id: ObjectId,
    actual_manifest_hash: ObjectId,
    label: &str,
) -> Result<(), ResumeHandshakeError> {
    if actual_handshake_id != expected_handshake_id {
        return Err(ResumeHandshakeError::LinkageMismatch {
            reason: format!("{label} handshake id differs from request"),
        });
    }
    if actual_manifest_hash != expected_manifest_hash {
        return Err(ResumeHandshakeError::LinkageMismatch {
            reason: format!("{label} manifest hash differs from request"),
        });
    }
    Ok(())
}

fn ensure_elapsed_within_timeout(
    started_at_ms: u64,
    observed_at_ms: u64,
    timeout_ms: u64,
) -> Result<(), ResumeHandshakeError> {
    let elapsed_ms = observed_at_ms.checked_sub(started_at_ms).ok_or_else(|| {
        ResumeHandshakeError::OutOfOrder {
            reason: "handshake evidence predates the source request".into(),
        }
    })?;
    if elapsed_ms > timeout_ms {
        return Err(ResumeHandshakeError::Timeout {
            elapsed_ms,
            timeout_ms,
        });
    }
    Ok(())
}

fn canonical_replay_ops(
    ops: &[ResumeReplayOp],
) -> Result<Vec<ResumeReplayOp>, ResumeHandshakeError> {
    let map = replay_map(ops)?;
    Ok(map
        .into_iter()
        .map(|(op_id, effect_hash)| ResumeReplayOp { op_id, effect_hash })
        .collect())
}

fn replay_map(ops: &[ResumeReplayOp]) -> Result<BTreeMap<String, [u8; 32]>, ResumeHandshakeError> {
    let mut map = BTreeMap::new();
    for op in ops {
        match map.insert(op.op_id.clone(), op.effect_hash) {
            Some(existing) if existing != op.effect_hash => {
                return Err(ResumeHandshakeError::ReplayConflict {
                    op_id: op.op_id.clone(),
                });
            }
            _ => {}
        }
    }
    Ok(map)
}

fn validate_replay_set(
    expected: &[ResumeReplayOp],
    actual: &[ResumeReplayOp],
) -> Result<(), ResumeHandshakeError> {
    let expected = replay_map(expected)?;
    let actual = replay_map(actual)?;
    if actual.keys().any(|op_id| !expected.contains_key(op_id)) {
        return Err(ResumeHandshakeError::LinkageMismatch {
            reason: "target replay includes an operation absent from the source request".into(),
        });
    }
    for (op_id, expected_hash) in expected {
        match actual.get(&op_id) {
            Some(actual_hash) if *actual_hash == expected_hash => {}
            Some(_) => return Err(ResumeHandshakeError::ReplayConflict { op_id }),
            None => return Err(ResumeHandshakeError::MissingReplayOperation { op_id }),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fcp_crypto::Ed25519SigningKey;
    use fcp_raptorq::ChunkedObjectManifest;

    use super::*;
    use crate::ProcessSnapshotFormat;

    const TOKEN: &[u8] = b"resume-capability-token";

    fn signing_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[9_u8; 32]).unwrap()
    }

    fn raptorq_config() -> RaptorQConfig {
        RaptorQConfig {
            symbol_size: 96,
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        }
    }

    fn sample_manifest() -> ProcessSnapshotManifest {
        let payload = b"criu-process-state:pid=8080;heap=stable;fds=7,9";
        let (chunk_manifest, _chunks) = ChunkedObjectManifest::from_payload(payload, 13);
        ProcessSnapshotManifest::sign(
            8080,
            "source-node",
            ProcessSnapshotFormat::Criu,
            chunk_manifest,
            TOKEN,
            &signing_key(),
        )
        .unwrap()
    }

    fn sample_request_and_symbols() -> (ResumeHandshakeRequest, Vec<ResumeSnapshotSymbol>) {
        let manifest = sample_manifest();
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let config = raptorq_config();
        let encoder = RaptorQEncoder::new(&manifest_bytes, &config).unwrap();
        let request = ResumeHandshakeRequest::new(
            "source-node",
            "target-node",
            &manifest,
            ObjectTransmissionInfo::from_oti(encoder.transmission_info()),
            77,
            1_000,
            DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS,
            vec![
                ResumeReplayOp::from_effect("op-1", b"write-a"),
                ResumeReplayOp::from_effect("op-2", b"write-b"),
            ],
        )
        .unwrap();
        let symbols = request
            .encode_snapshot_manifest_symbols(&manifest_bytes, &config, 1_010)
            .unwrap();
        (request, symbols)
    }

    fn successful_transcript() -> ResumeHandshakeTranscript {
        let (request, symbols) = sample_request_and_symbols();
        let ack = ResumeTargetAck::accept(&request, Some("reservation-1".to_string()), 1_005);
        let complete =
            ResumeTargetComplete::rehydrated(&request, request.in_flight_ops.clone(), 1_050)
                .unwrap();
        let source_release = ResumeSourceLeaseRelease::new(&request, 1_051);
        ResumeHandshakeTranscript {
            request,
            ack,
            symbols,
            complete,
            source_release,
        }
    }

    #[test]
    fn handshake_canonical_message_roundtrips_byte_equivalent() {
        let transcript = successful_transcript();
        let message = ResumeHandshakeMessage::Request(transcript.request);
        let bytes = message.canonical_bytes().unwrap();
        let decoded = ResumeHandshakeMessage::from_canonical_bytes(&bytes).unwrap();

        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        assert_eq!(decoded, message);
    }

    #[test]
    fn successful_transcript_decodes_and_verifies_snapshot_manifest() {
        let transcript = successful_transcript();
        transcript.validate_success().unwrap();
        let anchors = ProcessSnapshotTrustAnchors::single(signing_key().verifying_key());

        let decoded = transcript
            .decode_verified_snapshot_manifest(&raptorq_config(), TOKEN, &anchors)
            .unwrap();

        assert_eq!(decoded.snapshot_id, transcript.request.snapshot_id);
        assert_eq!(
            decoded.manifest_object_id().unwrap(),
            transcript.request.snapshot_manifest_hash
        );
    }

    #[test]
    fn stale_or_missing_capability_ack_rejects_resume() {
        let mut transcript = successful_transcript();
        transcript.ack.freshness = SnapshotFreshness::Stale;
        transcript.ack.capability = CapabilityAvailability::Missing;

        let err = transcript.validate_success().unwrap_err();

        assert!(matches!(err, ResumeHandshakeError::TargetRejected { .. }));
    }

    #[test]
    fn source_release_before_rehydration_is_rejected() {
        let mut transcript = successful_transcript();
        transcript.source_release.released_at_ms = transcript.complete.resumed_at_ms - 1;

        let err = transcript.validate_success().unwrap_err();

        assert!(matches!(
            err,
            ResumeHandshakeError::LeaseReleasedBeforeRehydration
        ));
    }

    #[test]
    fn timeout_rolls_back_to_source_without_releasing_lease() {
        let mut transcript = successful_transcript();
        transcript.complete.status = RehydrationStatus::Failed;
        transcript.complete.resumed_at_ms =
            transcript.request.started_at_ms + transcript.request.effective_timeout_ms() + 1;

        let plan = transcript
            .rollback_if_timed_out(transcript.complete.resumed_at_ms)
            .expect("timeout should produce rollback plan");

        assert_eq!(plan.handshake_id, transcript.request.handshake_id);
        assert_eq!(plan.reason, ResumeRollbackReason::Timeout);
        assert!(plan.keep_source_lease);
    }

    #[test]
    fn replay_duplicates_with_same_effect_are_idempotent() {
        let (request, symbols) = sample_request_and_symbols();
        let mut replayed = request.in_flight_ops.clone();
        replayed.push(request.in_flight_ops[0].clone());
        let ack = ResumeTargetAck::accept(&request, None, 1_005);
        let complete = ResumeTargetComplete::rehydrated(&request, replayed, 1_050).unwrap();
        let source_release = ResumeSourceLeaseRelease::new(&request, 1_051);
        let transcript = ResumeHandshakeTranscript {
            request,
            ack,
            symbols,
            complete,
            source_release,
        };

        transcript.validate_success().unwrap();
        assert_eq!(transcript.complete.replayed_ops.len(), 2);
    }

    #[test]
    fn replay_same_operation_with_different_effect_is_rejected() {
        let (request, _symbols) = sample_request_and_symbols();
        let mut replayed = request.in_flight_ops.clone();
        replayed.push(ResumeReplayOp::from_effect("op-1", b"different-effect"));

        let err = ResumeTargetComplete::rehydrated(&request, replayed, 1_050).unwrap_err();

        assert!(matches!(err, ResumeHandshakeError::ReplayConflict { .. }));
    }

    #[test]
    fn symbol_frame_must_match_announced_manifest_hash() {
        let mut transcript = successful_transcript();
        transcript.symbols[0].frame.object_id = ObjectId::from_bytes([0x44; 32]);

        let err = transcript.validate_success().unwrap_err();

        assert!(matches!(
            err,
            ResumeHandshakeError::SymbolFrameMismatch { .. }
        ));
    }

    fn rebind_request(transcript: &mut ResumeHandshakeTranscript) {
        let id = derive_handshake_id(&transcript.request.identity().unwrap()).unwrap();
        transcript.request.handshake_id = id;
        transcript.ack.handshake_id = id;
        transcript.complete.handshake_id = id;
        transcript.source_release.handshake_id = id;
        for symbol in &mut transcript.symbols {
            symbol.handshake_id = id;
        }
    }

    #[test]
    fn deserialized_request_fields_cannot_reuse_an_accepted_identity() {
        let original = successful_transcript();
        let changes = [
            ("source_node", serde_json::json!("another-source")),
            ("target_node", serde_json::json!("another-target")),
            ("lease_fencing_token", serde_json::json!(78)),
            ("started_at_ms", serde_json::json!(999)),
            ("timeout_ms", serde_json::json!(60_000)),
            ("in_flight_ops", serde_json::json!([])),
            (
                "snapshot_id",
                serde_json::to_value(ObjectId::from_bytes([4; 32])).unwrap(),
            ),
            (
                "capability_token_pinned",
                serde_json::to_value([3_u8; 32]).unwrap(),
            ),
        ];
        for (field, replacement) in changes {
            let mut value = serde_json::to_value(&original).unwrap();
            value["request"][field] = replacement;
            let altered: ResumeHandshakeTranscript = serde_json::from_value(value).unwrap();
            assert!(
                matches!(
                    altered.validate_success(),
                    Err(ResumeHandshakeError::LinkageMismatch { .. })
                ),
                "accepted altered request field {field}"
            );
            assert!(matches!(
                altered.decode_snapshot_manifest_bytes(&raptorq_config()),
                Err(ResumeHandshakeError::LinkageMismatch { .. })
            ));
        }
    }

    #[test]
    fn encoding_refuses_a_request_with_a_stale_identity() {
        let (mut request, _) = sample_request_and_symbols();
        request.target_node = "replacement-target".into();
        assert!(matches!(
            request.encode_snapshot_manifest_symbols(
                &sample_manifest().canonical_bytes().unwrap(),
                &raptorq_config(),
                1_010,
            ),
            Err(ResumeHandshakeError::LinkageMismatch { .. })
        ));
    }

    #[test]
    fn verified_manifest_must_match_even_rehashed_preflight_snapshot_and_token_pins() {
        let anchors = ProcessSnapshotTrustAnchors::single(signing_key().verifying_key());
        for change_pin in [false, true] {
            let mut transcript = successful_transcript();
            if change_pin {
                transcript.request.capability_token_pinned[0] ^= 1;
            } else {
                transcript.request.snapshot_id = ObjectId::from_bytes([4; 32]);
            }
            rebind_request(&mut transcript);
            transcript.validate_success().unwrap();
            assert!(matches!(
                transcript.decode_verified_snapshot_manifest(&raptorq_config(), TOKEN, &anchors),
                Err(ResumeHandshakeError::LinkageMismatch { .. })
            ));
        }
    }

    #[test]
    fn request_construction_rejects_an_inconsistent_snapshot_identity() {
        let mut manifest = sample_manifest();
        manifest.snapshot_id = ObjectId::from_bytes([4; 32]);
        let (request, _) = sample_request_and_symbols();
        assert!(matches!(
            ResumeHandshakeRequest::new(
                "source-node",
                "target-node",
                &manifest,
                request.raptorq,
                77,
                1_000,
                DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS,
                Vec::new(),
            ),
            Err(ResumeHandshakeError::Snapshot(
                ProcessSnapshotError::SnapshotIdMismatch { .. }
            ))
        ));
    }

    #[test]
    fn preflight_cannot_predate_the_source_request() {
        let mut transcript = successful_transcript();
        transcript.ack.acked_at_ms = transcript.request.started_at_ms - 1;
        assert!(matches!(
            transcript.validate_success(),
            Err(ResumeHandshakeError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn symbol_timestamps_cannot_hide_a_late_predecessor() {
        let mut transcript = successful_transcript();
        assert!(transcript.symbols.len() > 1);
        transcript.symbols[0].sent_at_ms = transcript.symbols[1].sent_at_ms + 1;
        assert!(matches!(
            transcript.validate_success(),
            Err(ResumeHandshakeError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn manifest_decoding_rejects_symbols_outside_the_shared_deadline() {
        let mut transcript = successful_transcript();
        transcript.symbols.last_mut().unwrap().sent_at_ms =
            transcript.request.started_at_ms + transcript.request.effective_timeout_ms() + 1;
        assert!(matches!(
            transcript.decode_snapshot_manifest_bytes(&raptorq_config()),
            Err(ResumeHandshakeError::Timeout { .. })
        ));
    }

    #[test]
    fn a_completion_without_manifest_transfer_is_not_successful() {
        let mut transcript = successful_transcript();
        transcript.symbols.clear();
        assert!(matches!(
            transcript.validate_success(),
            Err(ResumeHandshakeError::IncompleteSnapshotStream)
        ));
    }

    #[test]
    fn replay_cannot_include_an_operation_not_requested_by_the_source() {
        let mut transcript = successful_transcript();
        transcript
            .complete
            .replayed_ops
            .push(ResumeReplayOp::from_effect("unrequested", b"effect"));
        assert!(matches!(
            transcript.validate_success(),
            Err(ResumeHandshakeError::LinkageMismatch { .. })
        ));
    }

    #[test]
    fn rehydrated_marker_with_wrong_linkage_does_not_suppress_timeout_rollback() {
        let mut transcript = successful_transcript();
        transcript.complete.handshake_id = ObjectId::from_bytes([6; 32]);
        let now = transcript.request.started_at_ms + transcript.request.effective_timeout_ms() + 1;
        assert!(
            transcript
                .rollback_if_timed_out(now)
                .unwrap()
                .keep_source_lease
        );
    }

    #[test]
    fn late_or_incomplete_rehydration_does_not_suppress_timeout_rollback() {
        for late in [false, true] {
            let mut transcript = successful_transcript();
            let now =
                transcript.request.started_at_ms + transcript.request.effective_timeout_ms() + 1;
            if late {
                transcript.complete.resumed_at_ms = now;
            } else {
                transcript.complete.replayed_ops.pop();
            }
            assert!(
                transcript
                    .rollback_if_timed_out(now)
                    .unwrap()
                    .keep_source_lease
            );
        }
    }

    #[test]
    fn valid_completion_suppresses_rollback_before_the_separate_source_release() {
        let mut transcript = successful_transcript();
        let now = transcript.request.started_at_ms + transcript.request.effective_timeout_ms() + 1;
        transcript.source_release.released_at_ms = 0;
        assert!(transcript.rollback_if_timed_out(now).is_none());
        assert!(matches!(
            transcript.validate_success(),
            Err(ResumeHandshakeError::LeaseReleasedBeforeRehydration)
        ));
    }

    #[test]
    fn canonical_replay_order_and_identical_duplicates_preserve_request_identity() {
        let mut transcript = successful_transcript();
        transcript.request.in_flight_ops.reverse();
        transcript
            .request
            .in_flight_ops
            .push(transcript.request.in_flight_ops[0].clone());
        transcript.validate_success().unwrap();
    }

    #[test]
    fn deadline_boundary_and_equal_symbol_timestamps_remain_valid() {
        let mut transcript = successful_transcript();
        for symbol in &mut transcript.symbols {
            symbol.sent_at_ms = transcript.ack.acked_at_ms;
        }
        transcript.complete.resumed_at_ms =
            transcript.request.started_at_ms + transcript.request.effective_timeout_ms();
        transcript.source_release.released_at_ms = transcript.complete.resumed_at_ms;
        transcript.validate_success().unwrap();
    }
}
