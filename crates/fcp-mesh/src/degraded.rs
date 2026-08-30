//! Degraded-mode control-plane transport over FCPS.
//!
//! When FCPC (reliable control-plane stream) is unavailable due to degraded network
//! conditions, partitions, or bootstrap scenarios, control-plane objects can be
//! transported over the symbol-native FCPS data plane with `FrameFlags::CONTROL_PLANE`.
//!
//! This module implements the spec-described mesh fallback transport:
//! - Sender wraps canonical `ControlPlaneObject` as symbols
//! - Sends as FCPS frames with `CONTROL_PLANE` flag
//! - Receiver verifies session MAC + per-symbol AEAD
//! - Reconstructs object payload (RaptorQ or raw chunking)
//! - Enforces retention: Required objects stored, Ephemeral may be discarded
//!
//! # Wire Format
//!
//! The FCPS frame with `CONTROL_PLANE` flag encodes:
//! - Standard FCPS header (114 bytes) with `CONTROL_PLANE | ENCRYPTED | RAPTORQ`
//! - Symbol records containing RaptorQ-encoded control-plane object
//! - Each symbol is encrypted with zone key (per-symbol AEAD)

use std::collections::{BTreeMap, HashMap};

use fcp_crypto::{
    AeadKey, CryptoError, Ed25519SigningKey, Ed25519VerifyingKey, MlDsa65SigningKey,
    MlDsa65VerifyingKey, PqSigningPolicy,
};
use fcp_prelude::{
    ObjectId, TailscaleNodeId, ZoneId, ZoneIdHash, ZoneKey,
    ZoneKeyAlgorithm as CoreZoneKeyAlgorithm, ZoneKeyId,
};
use fcp_protocol::{
    FCPS_VERSION, FcpsFrame, FcpsFrameHeader, FrameError, FrameFlags, HybridSignedFcpsFrame,
    SignedFcpsFrame, SymbolContext, SymbolEnvelopeError, SymbolRecord,
    ZoneKeyAlgorithm as SymbolZoneKeyAlgorithm, decrypt_symbol, encrypt_symbol,
    verify_hybrid_signed_fcps_frame,
};
use fcp_raptorq::{DecodeError, EncodeError, RaptorQConfig, RaptorQDecoder, RaptorQEncoder};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Error type for degraded-mode transport operations.
#[derive(Debug, Error)]
pub enum DegradedTransportError {
    /// Encoding failed.
    #[error("encoding failed: {0}")]
    Encode(#[from] EncodeError),

    /// Decoding failed.
    #[error("decoding failed: {0}")]
    Decode(#[from] DecodeError),

    /// Frame parsing failed.
    #[error("frame error: {0}")]
    Frame(#[from] FrameError),

    /// Object reconstruction incomplete (need more symbols).
    #[error("reconstruction incomplete: received {received}/{needed} symbols")]
    Incomplete { received: u32, needed: u32 },

    /// Schema hash mismatch after reconstruction.
    ///
    /// Part of the stable degraded-transport error contract for consumers
    /// that know the expected schema of a reconstructed payload. The decoder
    /// itself cannot raise this: the reconstructed wire payload carries the
    /// claimed schema hash but nothing to compare it against (see
    /// `DegradedModeDecoder::finish_reconstruction` for the verification
    /// deferral; bead degraded-reconstruct-objectid-verify-qtmop).
    #[error("schema hash mismatch: expected {expected:?}, got {actual:?}")]
    SchemaHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// Object ID mismatch after reconstruction.
    ///
    /// Part of the stable degraded-transport error contract for promotion
    /// boundaries that re-derive the content address. The decoder itself
    /// cannot raise this: `derive_id` needs the object's `ObjectHeader` and
    /// the zone `ObjectIdKey`, neither of which exists at the degraded
    /// transport layer (see `DegradedModeDecoder::finish_reconstruction`;
    /// bead degraded-reconstruct-objectid-verify-qtmop).
    #[error("object ID mismatch")]
    ObjectIdMismatch,

    /// Retention policy violation (Required object was dropped).
    #[error("retention violation: Required object was not stored")]
    RetentionViolation,

    /// Frame missing CONTROL_PLANE flag.
    #[error("frame missing CONTROL_PLANE flag")]
    MissingControlPlaneFlag,

    /// CONTROL_PLANE frame carried no symbols.
    #[error("control-plane frame contains no symbols")]
    EmptyControlPlaneFrame,

    /// Zone ID hash mismatch.
    #[error("zone id hash mismatch: expected {expected:?}, got {got:?}")]
    ZoneMismatch {
        expected: ZoneIdHash,
        got: ZoneIdHash,
    },

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Hybrid signing operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Symbol encryption failed before a CONTROL_PLANE frame could be emitted.
    #[error("symbol encryption failed for esi {esi}: {source}")]
    SymbolEncryptFailed {
        esi: u32,
        #[source]
        source: SymbolEnvelopeError,
    },

    /// Symbol decryption/authentication failed before decode.
    #[error("symbol decryption failed for esi {esi}: {source}")]
    SymbolDecryptFailed {
        esi: u32,
        #[source]
        source: SymbolEnvelopeError,
    },

    /// Authenticated symbol crypto context is required for degraded transport.
    #[error("authenticated symbol crypto context required for degraded transport")]
    SymbolCryptoUnavailable,

    /// Too many concurrent pending reconstructions.
    #[error(
        "too many pending reconstructions: current {current}, limit {limit}; \
         drop or call clear_pending() to free capacity"
    )]
    PendingLimitExceeded { current: usize, limit: usize },
}

/// Retention class for control-plane objects (NORMATIVE).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RetentionClass {
    /// Object MUST be stored and replayable after restart.
    #[default]
    Required,
    /// Object MAY be discarded after processing.
    Ephemeral,
}

/// Authenticated degraded-frame verification inputs.
pub struct SignedDegradedFrameAuth<'a> {
    /// Classical Ed25519 verifying key for the signed FCPS frame.
    pub verifying_key: &'a Ed25519VerifyingKey,
    /// Post-quantum ML-DSA verifying key for the signed FCPS frame.
    pub pq_verifying_key: &'a MlDsa65VerifyingKey,
    /// Required signature policy for the hybrid envelope.
    pub signing_policy: PqSigningPolicy,
    /// Zone key used for symbol decryption.
    pub zone_key: &'a ZoneKey,
    /// Zone-key algorithm used for symbol decryption.
    pub algorithm: CoreZoneKeyAlgorithm,
}

/// Control-plane object wrapped for degraded-mode transport.
#[derive(Debug, Clone)]
pub struct ControlPlaneEnvelope {
    /// Canonical CBOR-serialized control-plane object.
    pub payload: Vec<u8>,
    /// Schema hash (first 32 bytes of BLAKE3 of schema definition).
    pub schema_hash: [u8; 32],
    /// Object ID (BLAKE3-keyed hash).
    pub object_id: ObjectId,
    /// Zone this object belongs to.
    pub zone_id: ZoneId,
    /// Zone key ID for decryption.
    pub zone_key_id: ZoneKeyId,
    /// Epoch this control-plane object belongs to.
    pub epoch_id: u64,
    /// Retention class.
    pub retention: RetentionClass,
}

impl ControlPlaneEnvelope {
    /// Create a new control-plane envelope.
    #[must_use]
    pub fn new(
        payload: Vec<u8>,
        schema_hash: [u8; 32],
        object_id: ObjectId,
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        epoch_id: u64,
        retention: RetentionClass,
    ) -> Self {
        Self {
            payload,
            schema_hash,
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            retention,
        }
    }
}

/// Encoder for control-plane objects over FCPS.
///
/// Wraps a canonical control-plane object as FCPS frames with `CONTROL_PLANE` flag.
pub struct DegradedModeEncoder {
    config: RaptorQConfig,
    sender_instance_id: u64,
    next_frame_seq: u64,
}

impl DegradedModeEncoder {
    /// Create a new degraded-mode encoder.
    #[must_use]
    pub fn new(config: RaptorQConfig, sender_instance_id: u64) -> Self {
        Self {
            config,
            sender_instance_id,
            next_frame_seq: 0,
        }
    }

    /// Encode a control-plane object into FCPS frames.
    ///
    /// Returns one or more FCPS frames with `CONTROL_PLANE` flag set.
    /// The `epoch_id` argument is the authoritative transport epoch to write
    /// into the FCPS header; the envelope's stored `epoch_id` is reused only
    /// for decoded/stored envelopes on the receiving side.
    ///
    /// # Errors
    ///
    /// Returns `DegradedTransportError::Encode` if RaptorQ encoding fails.
    pub fn encode_authenticated(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        epoch_id: u64,
        zone_key: &ZoneKey,
        algorithm: CoreZoneKeyAlgorithm,
        source_id: &TailscaleNodeId,
    ) -> Result<Vec<FcpsFrame>, DegradedTransportError> {
        info!(
            object_id = %envelope.object_id,
            zone_id = %envelope.zone_id,
            retention = ?envelope.retention,
            payload_len = envelope.payload.len(),
            "degraded_mode: encoding control-plane object for FCPS transport"
        );

        // Build the wire payload: length(4 bytes) || schema_hash(32 bytes) || payload
        // Length prefix allows decoder to know exact payload size after RaptorQ padding
        let payload_len = u32::try_from(envelope.payload.len()).unwrap_or(u32::MAX);
        let mut wire_payload = Vec::with_capacity(4 + 32 + envelope.payload.len());
        wire_payload.extend_from_slice(&payload_len.to_be_bytes());
        wire_payload.extend_from_slice(&envelope.schema_hash);
        wire_payload.extend_from_slice(&envelope.payload);

        // Encode with RaptorQ
        let encoder = RaptorQEncoder::new(&wire_payload, &self.config)?;
        let symbols = encoder.encode_all();
        let k = u16::try_from(encoder.source_symbols()).unwrap_or(u16::MAX);

        // Build FCPS frames
        let flags = FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE;
        let zone_id_hash = envelope.zone_id.hash();

        // For simplicity, pack all symbols into a single frame
        // (production would batch based on MTU)
        let frame_seq = self.next_frame_seq;
        let zone_key = aead_key(zone_key);
        let algorithm = protocol_zone_key_algorithm(algorithm);
        let symbol_records: Result<Vec<_>, _> = symbols
            .into_iter()
            .map(|(esi, data)| {
                let context = symbol_context(
                    envelope.object_id.clone(),
                    esi,
                    k,
                    zone_id_hash,
                    envelope.zone_key_id,
                    epoch_id,
                    source_id.clone(),
                    self.sender_instance_id,
                    frame_seq,
                );
                let (data, auth_tag) =
                    encrypt_symbol(&zone_key, algorithm, &context, &data).map_err(|source| {
                        DegradedTransportError::SymbolEncryptFailed { esi, source }
                    })?;
                Ok::<SymbolRecord, DegradedTransportError>(SymbolRecord {
                    esi,
                    k,
                    data,
                    auth_tag,
                })
            })
            .collect();
        let symbol_records = symbol_records?;

        let symbol_size = self.config.symbol_size;
        let total_payload_len: u32 = symbol_records
            .iter()
            .map(|r| u32::try_from(r.wire_size()).unwrap_or(u32::MAX))
            .sum();

        let header = FcpsFrameHeader {
            version: FCPS_VERSION,
            flags,
            symbol_count: u32::try_from(symbol_records.len()).unwrap_or(u32::MAX),
            total_payload_len,
            object_id: envelope.object_id.clone(),
            symbol_size,
            zone_key_id: envelope.zone_key_id.clone(),
            zone_id_hash,
            epoch_id,
            sender_instance_id: self.sender_instance_id,
            frame_seq,
        };

        self.next_frame_seq += 1;

        debug!(
            object_id = %envelope.object_id,
            symbol_count = symbol_records.len(),
            frame_seq = header.frame_seq,
            "degraded_mode: created CONTROL_PLANE FCPS frame"
        );

        Ok(vec![FcpsFrame {
            header,
            symbols: symbol_records,
        }])
    }

    /// Encode a control-plane object with the test-only static zone key.
    ///
    /// # Errors
    ///
    /// Returns `DegradedTransportError` if the object cannot be encoded.
    #[cfg(test)]
    pub fn encode(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        epoch_id: u64,
    ) -> Result<Vec<FcpsFrame>, DegradedTransportError> {
        self.encode_authenticated(
            envelope,
            epoch_id,
            &ZoneKey::from_bytes([0x44; 32]),
            CoreZoneKeyAlgorithm::ChaCha20Poly1305,
            &TailscaleNodeId::new("mesh-test-sender"),
        )
    }

    /// Encode a control-plane object without authenticated degraded transport.
    ///
    /// # Errors
    ///
    /// Always returns [`DegradedTransportError::SymbolCryptoUnavailable`] in
    /// non-test builds because callers must use [`Self::encode_authenticated`].
    #[cfg(not(test))]
    pub fn encode(
        &mut self,
        _envelope: &ControlPlaneEnvelope,
        _epoch_id: u64,
    ) -> Result<Vec<FcpsFrame>, DegradedTransportError> {
        Err(DegradedTransportError::SymbolCryptoUnavailable)
    }

    /// Encode and sign a control-plane object for degraded/bootstrap mode.
    ///
    /// Use when session MACs are unavailable. The provided `epoch_id` is the
    /// transport epoch written to each signed frame header.
    ///
    /// # Errors
    ///
    /// Returns `DegradedTransportError::Encode` if encoding fails.
    #[allow(clippy::too_many_arguments)] // Degraded bootstrap frames must bind zone crypto, source, timestamp, and signer.
    pub fn encode_signed_authenticated(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        epoch_id: u64,
        zone_key: &ZoneKey,
        algorithm: CoreZoneKeyAlgorithm,
        source_id: &TailscaleNodeId,
        timestamp: u64,
        signing_key: &Ed25519SigningKey,
        pq_signing_key: &MlDsa65SigningKey,
    ) -> Result<Vec<HybridSignedFcpsFrame>, DegradedTransportError> {
        let frames =
            self.encode_authenticated(envelope, epoch_id, zone_key, algorithm, source_id)?;

        let signed: Result<Vec<_>, _> = frames
            .into_iter()
            .map(|frame| {
                SignedFcpsFrame::new_hybrid(
                    &frame,
                    source_id.clone(),
                    timestamp,
                    signing_key,
                    pq_signing_key,
                )
                .map_err(DegradedTransportError::from)
            })
            .collect();
        signed
    }

    /// Encode and sign a control-plane object with the test-only static zone key.
    ///
    /// # Errors
    ///
    /// Returns `DegradedTransportError` if encoding or signing fails.
    #[cfg(test)]
    pub fn encode_signed(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        epoch_id: u64,
        source_id: &TailscaleNodeId,
        timestamp: u64,
        signing_key: &Ed25519SigningKey,
        pq_signing_key: &MlDsa65SigningKey,
    ) -> Result<Vec<HybridSignedFcpsFrame>, DegradedTransportError> {
        self.encode_signed_authenticated(
            envelope,
            epoch_id,
            &ZoneKey::from_bytes([0x44; 32]),
            CoreZoneKeyAlgorithm::ChaCha20Poly1305,
            source_id,
            timestamp,
            signing_key,
            pq_signing_key,
        )
    }

    /// Encode a signed control-plane object without authenticated degraded transport.
    ///
    /// # Errors
    ///
    /// Always returns [`DegradedTransportError::SymbolCryptoUnavailable`] in
    /// non-test builds because callers must use
    /// [`Self::encode_signed_authenticated`].
    #[cfg(not(test))]
    pub fn encode_signed(
        &mut self,
        _envelope: &ControlPlaneEnvelope,
        _epoch_id: u64,
        _source_id: &TailscaleNodeId,
        _timestamp: u64,
        _signing_key: &Ed25519SigningKey,
        _pq_signing_key: &MlDsa65SigningKey,
    ) -> Result<Vec<HybridSignedFcpsFrame>, DegradedTransportError> {
        Err(DegradedTransportError::SymbolCryptoUnavailable)
    }
}

/// Default cap on concurrent pending control-plane reconstructions.
///
/// An adversary can send FCPS frames with unique object_id/epoch_id tuples
/// to create arbitrarily many distinct `PendingReconstructionKey` entries,
/// each of which holds a RaptorQ decoder (multi-KiB). Without a bound the
/// pending map would grow without limit. This cap is intentionally
/// generous — legitimate control-plane bursts rarely exceed a few dozen
/// concurrent in-flight reconstructions.
pub const DEFAULT_MAX_PENDING_RECONSTRUCTIONS: usize = 256;

/// Decoder for control-plane objects from FCPS frames.
///
/// Accumulates symbols from FCPS frames with `CONTROL_PLANE` flag until
/// reconstruction is possible.
pub struct DegradedModeDecoder {
    config: RaptorQConfig,
    /// In-progress reconstructions keyed by object + transport context.
    pending: HashMap<PendingReconstructionKey, PendingReconstruction>,
    /// Maximum concurrent pending reconstructions; enforced in
    /// `process_frame` to bound memory use under adversarial input.
    max_pending: usize,
}

/// Identity for an in-flight degraded-mode reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingReconstructionKey {
    object_id: ObjectId,
    zone_id_hash: ZoneIdHash,
    zone_key_id: ZoneKeyId,
    epoch_id: u64,
    symbol_size: u16,
    source_symbols_k: u16,
}

impl PendingReconstructionKey {
    #[must_use]
    fn from_frame(frame: &FcpsFrame) -> Option<Self> {
        let source_symbols_k = frame.symbols.first()?.k;
        Some(Self {
            object_id: frame.header.object_id.clone(),
            zone_id_hash: frame.header.zone_id_hash,
            zone_key_id: frame.header.zone_key_id.clone(),
            epoch_id: frame.header.epoch_id,
            symbol_size: frame.header.symbol_size,
            source_symbols_k,
        })
    }

    #[must_use]
    fn matches_object_id(&self, object_id: &ObjectId) -> bool {
        &self.object_id == object_id
    }
}

/// In-progress object reconstruction.
struct PendingReconstruction {
    decoder: RaptorQDecoder,
    zone_id: ZoneId,
    zone_key_id: ZoneKeyId,
    retention: RetentionClass,
}

impl DegradedModeDecoder {
    /// Create a new degraded-mode decoder with the default pending cap
    /// ([`DEFAULT_MAX_PENDING_RECONSTRUCTIONS`]).
    #[must_use]
    pub fn new(config: RaptorQConfig) -> Self {
        Self::with_max_pending(config, DEFAULT_MAX_PENDING_RECONSTRUCTIONS)
    }

    /// Create a new degraded-mode decoder with an explicit pending cap.
    ///
    /// `max_pending` is clamped to at least 1 so the decoder can always
    /// make progress on a single object.
    #[must_use]
    pub fn with_max_pending(config: RaptorQConfig, max_pending: usize) -> Self {
        Self {
            config,
            pending: HashMap::new(),
            max_pending: max_pending.max(1),
        }
    }

    /// Process an FCPS frame with `CONTROL_PLANE` flag.
    ///
    /// Returns `Some(envelope)` when reconstruction completes.
    ///
    /// # Errors
    ///
    /// Returns error if frame is invalid or decoding fails.
    ///
    /// # Panics
    ///
    /// This function should not panic under normal operation. Internal map state
    /// is guaranteed consistent when reconstruction completes.
    pub fn process_frame_authenticated(
        &mut self,
        frame: &FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
        zone_key: &ZoneKey,
        algorithm: CoreZoneKeyAlgorithm,
        source_id: &TailscaleNodeId,
    ) -> Result<Option<ControlPlaneEnvelope>, DegradedTransportError> {
        self.validate_control_plane_frame(frame, expected_zone_id)?;
        debug!(
            object_id = %frame.header.object_id,
            symbol_count = frame.symbols.len(),
            frame_seq = frame.header.frame_seq,
            "degraded_mode: processing CONTROL_PLANE frame"
        );

        let pending_key = PendingReconstructionKey::from_frame(frame)
            .ok_or(DegradedTransportError::EmptyControlPlaneFrame)?;
        let object_id = pending_key.object_id.clone();

        // Bound concurrent pending reconstructions. An adversary sending
        // frames with unique (object_id, epoch_id, ...) tuples could
        // otherwise grow `self.pending` without limit. We allow adding
        // symbols to an EXISTING reconstruction even when the map is full
        // (it's progress, not a new allocation); we only reject truly new
        // entries when we're already at capacity.
        if !self.pending.contains_key(&pending_key) && self.pending.len() >= self.max_pending {
            warn!(
                object_id = %frame.header.object_id,
                current = self.pending.len(),
                limit = self.max_pending,
                "degraded_mode: rejecting new pending reconstruction (limit reached)"
            );
            return Err(DegradedTransportError::PendingLimitExceeded {
                current: self.pending.len(),
                limit: self.max_pending,
            });
        }

        let completed_payload = {
            let pending = self.pending.entry(pending_key.clone()).or_insert_with(|| {
                Self::new_pending_reconstruction(frame, expected_zone_id, retention, &self.config)
            });
            Self::decode_symbols(
                &mut pending.decoder,
                frame,
                &aead_key(zone_key),
                protocol_zone_key_algorithm(algorithm),
                source_id,
            )?
        };

        completed_payload.map_or(Ok(None), |payload| {
            self.finish_reconstruction(&pending_key, &object_id, frame, &payload)
        })
    }

    /// Process a frame with the test-only static zone key.
    ///
    /// # Errors
    ///
    /// Returns `DegradedTransportError` if frame processing fails.
    #[cfg(test)]
    pub fn process_frame(
        &mut self,
        frame: &FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
    ) -> Result<Option<ControlPlaneEnvelope>, DegradedTransportError> {
        self.process_frame_authenticated(
            frame,
            expected_zone_id,
            retention,
            &ZoneKey::from_bytes([0x44; 32]),
            CoreZoneKeyAlgorithm::ChaCha20Poly1305,
            &TailscaleNodeId::new("mesh-test-sender"),
        )
    }

    /// Process a frame without authenticated degraded transport.
    ///
    /// # Errors
    ///
    /// Always returns [`DegradedTransportError::SymbolCryptoUnavailable`] in
    /// non-test builds because callers must use
    /// [`Self::process_frame_authenticated`].
    #[cfg(not(test))]
    pub fn process_frame(
        &mut self,
        _frame: &FcpsFrame,
        _expected_zone_id: &ZoneId,
        _retention: RetentionClass,
    ) -> Result<Option<ControlPlaneEnvelope>, DegradedTransportError> {
        Err(DegradedTransportError::SymbolCryptoUnavailable)
    }

    /// Process a signed FCPS frame for degraded/bootstrap mode.
    ///
    /// Verifies signature before processing.
    ///
    /// # Errors
    ///
    /// Returns error if signature verification fails or frame processing fails.
    pub fn process_signed_frame_authenticated(
        &mut self,
        signed_frame: &HybridSignedFcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
        auth: &SignedDegradedFrameAuth<'_>,
    ) -> Result<Option<ControlPlaneEnvelope>, DegradedTransportError> {
        let frame = match verify_hybrid_signed_fcps_frame(
            signed_frame,
            auth.verifying_key,
            auth.pq_verifying_key,
            auth.signing_policy,
            usize::MAX,
        ) {
            Ok(frame) => frame,
            Err(err) => {
                warn!(
                    source_id = ?signed_frame.payload.source_id,
                    error = %err,
                    "degraded_mode: hybrid signature verification failed for signed FCPS frame"
                );
                return Err(DegradedTransportError::SignatureVerificationFailed);
            }
        };

        if signed_frame.object_type.as_str()
            != fcp_crypto::HybridSignedObjectKind::GossipFrame.as_str()
        {
            warn!(
                source_id = ?signed_frame.payload.source_id,
                "degraded_mode: hybrid envelope carried non-gossip object type"
            );
            return Err(DegradedTransportError::SignatureVerificationFailed);
        }

        debug!(
            object_id = %frame.header.object_id,
            source_id = ?signed_frame.payload.source_id,
            timestamp = signed_frame.payload.timestamp,
            policy = ?auth.signing_policy,
            "degraded_mode: hybrid signature verified for signed FCPS frame"
        );

        self.process_frame_authenticated(
            &frame,
            expected_zone_id,
            retention,
            auth.zone_key,
            auth.algorithm,
            &signed_frame.payload.source_id,
        )
    }

    /// Process a signed frame with the test-only static zone key.
    ///
    /// # Errors
    ///
    /// Returns `DegradedTransportError` if signature verification or frame
    /// processing fails.
    #[cfg(test)]
    pub fn process_signed_frame(
        &mut self,
        signed_frame: &HybridSignedFcpsFrame,
        verifying_key: &Ed25519VerifyingKey,
        pq_verifying_key: &MlDsa65VerifyingKey,
        signing_policy: PqSigningPolicy,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
    ) -> Result<Option<ControlPlaneEnvelope>, DegradedTransportError> {
        self.process_signed_frame_authenticated(
            signed_frame,
            expected_zone_id,
            retention,
            &SignedDegradedFrameAuth {
                verifying_key,
                pq_verifying_key,
                signing_policy,
                zone_key: &ZoneKey::from_bytes([0x44; 32]),
                algorithm: CoreZoneKeyAlgorithm::ChaCha20Poly1305,
            },
        )
    }

    /// Process a signed frame without authenticated degraded transport.
    ///
    /// # Errors
    ///
    /// Always returns [`DegradedTransportError::SymbolCryptoUnavailable`] in
    /// non-test builds because callers must use
    /// [`Self::process_signed_frame_authenticated`].
    #[cfg(not(test))]
    pub fn process_signed_frame(
        &mut self,
        _signed_frame: &HybridSignedFcpsFrame,
        _verifying_key: &Ed25519VerifyingKey,
        _pq_verifying_key: &MlDsa65VerifyingKey,
        _signing_policy: PqSigningPolicy,
        _expected_zone_id: &ZoneId,
        _retention: RetentionClass,
    ) -> Result<Option<ControlPlaneEnvelope>, DegradedTransportError> {
        Err(DegradedTransportError::SymbolCryptoUnavailable)
    }

    /// Get decode status for a pending object.
    #[must_use]
    pub fn get_status(&self, object_id: &ObjectId) -> Option<DecodeStatusInfo> {
        self.pending
            .iter()
            .filter(|(key, _)| key.matches_object_id(object_id))
            .map(|(_, pending)| DecodeStatusInfo {
                received: pending.decoder.received_count(),
                needed: pending.decoder.needed(),
                likely_complete: pending.decoder.likely_complete(),
            })
            .max_by(|left, right| {
                left.likely_complete
                    .cmp(&right.likely_complete)
                    .then(left.received.cmp(&right.received))
                    .then(right.needed.cmp(&left.needed))
            })
    }

    /// Clear all pending reconstructions for an object ID (e.g., on timeout).
    pub fn clear_pending(&mut self, object_id: &ObjectId) -> bool {
        let matching_keys: Vec<_> = self
            .pending
            .keys()
            .filter(|key| key.matches_object_id(object_id))
            .cloned()
            .collect();
        let cleared = !matching_keys.is_empty();
        for key in matching_keys {
            self.pending.remove(&key);
        }
        cleared
    }

    /// Get number of pending reconstructions.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    fn validate_control_plane_frame(
        &self,
        frame: &FcpsFrame,
        expected_zone_id: &ZoneId,
    ) -> Result<(), DegradedTransportError> {
        let expected_hash = expected_zone_id.hash();
        if frame.header.zone_id_hash != expected_hash {
            warn!(
                object_id = %frame.header.object_id,
                expected = %hex::encode(expected_hash.as_ref()),
                got = %hex::encode(frame.header.zone_id_hash.as_ref()),
                "degraded_mode: zone id hash mismatch"
            );
            return Err(DegradedTransportError::ZoneMismatch {
                expected: expected_hash,
                got: frame.header.zone_id_hash,
            });
        }
        if !frame.header.flags.contains(FrameFlags::CONTROL_PLANE) {
            warn!(
                object_id = %frame.header.object_id,
                "degraded_mode: received frame without CONTROL_PLANE flag"
            );
            return Err(DegradedTransportError::MissingControlPlaneFlag);
        }
        if frame.symbols.is_empty() {
            warn!(
                object_id = %frame.header.object_id,
                frame_seq = frame.header.frame_seq,
                "degraded_mode: received empty CONTROL_PLANE frame"
            );
            return Err(DegradedTransportError::EmptyControlPlaneFrame);
        }
        let expected_k = frame.symbols[0].k;
        if let Some((index, actual_k)) = frame
            .symbols
            .iter()
            .enumerate()
            .find_map(|(index, symbol)| (symbol.k != expected_k).then_some((index, symbol.k)))
        {
            warn!(
                object_id = %frame.header.object_id,
                frame_seq = frame.header.frame_seq,
                expected_k,
                actual_k,
                symbol_index = index,
                "degraded_mode: inconsistent source symbol count within CONTROL_PLANE frame"
            );
            return Err(DegradedTransportError::Decode(DecodeError::InvalidSymbol {
                reason: format!(
                    "control-plane frame mixes source symbol counts: first k={expected_k}, symbol[{index}] k={actual_k}"
                ),
            }));
        }
        Ok(())
    }

    fn new_pending_reconstruction(
        frame: &FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
        config: &RaptorQConfig,
    ) -> PendingReconstruction {
        let k = frame.symbols[0].k;
        let transfer_length = u64::from(k) * u64::from(frame.header.symbol_size);

        PendingReconstruction {
            decoder: RaptorQDecoder::with_expected_symbols(
                u32::from(k),
                transfer_length,
                frame.header.symbol_size,
                config,
            ),
            zone_id: expected_zone_id.clone(),
            zone_key_id: frame.header.zone_key_id.clone(),
            retention,
        }
    }

    fn decode_symbols(
        decoder: &mut RaptorQDecoder,
        frame: &FcpsFrame,
        zone_key: &AeadKey,
        algorithm: SymbolZoneKeyAlgorithm,
        source_id: &TailscaleNodeId,
    ) -> Result<Option<Vec<u8>>, DegradedTransportError> {
        for symbol in &frame.symbols {
            let context = symbol_context(
                frame.header.object_id.clone(),
                symbol.esi,
                symbol.k,
                frame.header.zone_id_hash,
                frame.header.zone_key_id,
                frame.header.epoch_id,
                source_id.clone(),
                frame.header.sender_instance_id,
                frame.header.frame_seq,
            );
            let plaintext = decrypt_symbol(
                zone_key,
                algorithm,
                &context,
                &symbol.data,
                &symbol.auth_tag,
            )
            .map_err(|source| DegradedTransportError::SymbolDecryptFailed {
                esi: symbol.esi,
                source,
            })?;
            if let Some(payload) = decoder.add_symbol(symbol.esi, plaintext)? {
                return Ok(Some(payload));
            }
        }
        Ok(None)
    }

    /// Finalize a completed RaptorQ reconstruction into an envelope.
    ///
    /// Content-address verification is deliberately deferred here
    /// (investigated under bead degraded-reconstruct-objectid-verify-qtmop):
    /// the reconstructed wire payload is `len ‖ schema_hash ‖ payload` with
    /// no `ObjectHeader`, and the decoder holds the zone AEAD key but never
    /// the zone `ObjectIdKey`, so `object_id == derive_id(...)` cannot be
    /// recomputed at this layer. The envelope's `object_id`/`schema_hash`
    /// are transport metadata: per-symbol AEAD context binding (object id,
    /// zone, epoch, sender) stops non-zone-members from forging them, and a
    /// zone-key holder gains nothing here because every trust decision
    /// happens downstream — gossip payloads are independently
    /// signature-verified at dispatch, and promotion into any object store
    /// must pass that store's injected `ObjectIdVerifier` (see
    /// `MeshNode::apply_gossip_fetch_payload`).
    fn finish_reconstruction(
        &mut self,
        pending_key: &PendingReconstructionKey,
        object_id: &ObjectId,
        frame: &FcpsFrame,
        payload: &[u8],
    ) -> Result<Option<ControlPlaneEnvelope>, DegradedTransportError> {
        let Some((schema_hash, object_payload)) =
            Self::parse_reconstructed_payload(object_id, payload)
        else {
            // Keep the pending decoder state so later repair symbols can recover
            // from a false-positive early decode candidate.
            return Ok(None);
        };
        let pending = self.pending.remove(pending_key).ok_or_else(|| {
            DegradedTransportError::Decode(DecodeError::Runtime {
                reason: format!(
                    "pending reconstruction missing during decode for object {object_id}"
                ),
            })
        })?;

        info!(
            object_id = %object_id,
            zone_id = %pending.zone_id,
            retention = ?pending.retention,
            payload_len = object_payload.len(),
            "degraded_mode: control-plane object reconstruction complete"
        );

        Ok(Some(ControlPlaneEnvelope {
            payload: object_payload,
            schema_hash,
            object_id: object_id.clone(),
            zone_id: pending.zone_id,
            zone_key_id: pending.zone_key_id,
            epoch_id: frame.header.epoch_id,
            retention: pending.retention,
        }))
    }

    fn parse_reconstructed_payload(
        object_id: &ObjectId,
        payload: &[u8],
    ) -> Option<([u8; 32], Vec<u8>)> {
        if payload.len() < 36 {
            warn!(
                object_id = %object_id,
                payload_len = payload.len(),
                "degraded_mode: reconstructed payload too short for header"
            );
            return None;
        }

        let payload_len =
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        let mut schema_hash = [0u8; 32];
        schema_hash.copy_from_slice(&payload[4..36]);

        if 36 + payload_len > payload.len() {
            warn!(
                object_id = %object_id,
                expected_len = payload_len,
                actual_len = payload.len().saturating_sub(36),
                "degraded_mode: payload length mismatch"
            );
            return None;
        }

        Some((schema_hash, payload[36..36 + payload_len].to_vec()))
    }
}

fn aead_key(zone_key: &ZoneKey) -> AeadKey {
    AeadKey::from_bytes(*zone_key.as_bytes())
}

fn protocol_zone_key_algorithm(algorithm: CoreZoneKeyAlgorithm) -> SymbolZoneKeyAlgorithm {
    match algorithm {
        CoreZoneKeyAlgorithm::ChaCha20Poly1305 => SymbolZoneKeyAlgorithm::ChaCha20Poly1305,
        CoreZoneKeyAlgorithm::XChaCha20Poly1305 => SymbolZoneKeyAlgorithm::XChaCha20Poly1305,
    }
}

#[allow(clippy::too_many_arguments)] // Context binds every field included in per-symbol AEAD authentication.
fn symbol_context(
    object_id: ObjectId,
    esi: u32,
    k: u16,
    zone_id_hash: ZoneIdHash,
    zone_key_id: ZoneKeyId,
    epoch_id: u64,
    sender_node_id: TailscaleNodeId,
    sender_instance_id: u64,
    frame_seq: u64,
) -> SymbolContext {
    SymbolContext {
        object_id,
        esi,
        k,
        zone_id_hash,
        zone_key_id,
        epoch_id,
        sender_node_id,
        sender_instance_id,
        frame_seq,
    }
}

/// Status information for a pending decode.
#[must_use]
#[derive(Debug, Clone, Copy)]
pub struct DecodeStatusInfo {
    /// Unique symbols received.
    pub received: u32,
    /// Approximate symbols needed (K').
    pub needed: u32,
    /// Whether reconstruction is likely possible.
    pub likely_complete: bool,
}

/// Handler trait for processed control-plane objects.
///
/// Implementations enforce retention policy and route objects appropriately.
pub trait ControlPlaneHandler: Send + Sync {
    /// Handle a reconstructed control-plane object.
    ///
    /// # Errors
    ///
    /// Returns error if the handler fails to process or store the object.
    fn handle(&self, envelope: ControlPlaneEnvelope) -> Result<(), DegradedTransportError>;
}

/// Simple in-memory handler that stores Required objects.
///
/// Test/replay fixture only: it indexes envelopes by their *claimed*
/// `object_id` without content-address verification (which is impossible at
/// this layer — see `DegradedModeDecoder::finish_reconstruction`). A
/// production handler that promotes reconstructed payloads into an object
/// store must route the write through a store with an injected
/// `ObjectIdVerifier` instead of trusting the envelope's id.
#[derive(Default)]
pub struct InMemoryControlPlaneHandler {
    state: std::sync::Mutex<InMemoryReplayState>,
}

#[derive(Default)]
struct InMemoryReplayState {
    stored: HashMap<ObjectId, ControlPlaneEnvelope>,
    epoch_index: HashMap<ZoneId, BTreeMap<u64, Vec<ObjectId>>>,
}

impl InMemoryControlPlaneHandler {
    /// Create a new in-memory handler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a stored object by ID.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get(&self, object_id: &ObjectId) -> Option<ControlPlaneEnvelope> {
        self.state.lock().unwrap().stored.get(object_id).cloned()
    }

    /// Get the number of stored objects.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn count(&self) -> usize {
        self.state.lock().unwrap().stored.len()
    }

    /// List epochs with stored Required objects for a zone.
    ///
    /// If `since_epoch` is provided, returns epochs strictly greater than that epoch.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn list_epochs(&self, zone_id: &ZoneId, since_epoch: Option<u64>) -> Vec<u64> {
        let state = self.state.lock().unwrap();
        let Some(zone_epochs) = state.epoch_index.get(zone_id) else {
            return Vec::new();
        };
        let epochs = zone_epochs
            .keys()
            .copied()
            .filter(|epoch| since_epoch.is_none_or(|since| *epoch > since))
            .collect();
        drop(state);
        epochs
    }

    /// Fetch all stored Required objects for a specific zone/epoch.
    ///
    /// Returns an empty vector if the epoch has no stored objects.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn fetch_epoch(&self, zone_id: &ZoneId, epoch_id: u64) -> Vec<ControlPlaneEnvelope> {
        let state = self.state.lock().unwrap();
        let Some(zone_epochs) = state.epoch_index.get(zone_id) else {
            return Vec::new();
        };
        let Some(object_ids) = zone_epochs.get(&epoch_id) else {
            return Vec::new();
        };
        let envelopes = object_ids
            .iter()
            .filter_map(|object_id| state.stored.get(object_id).cloned())
            .collect();
        drop(state);
        envelopes
    }
}

impl ControlPlaneHandler for InMemoryControlPlaneHandler {
    fn handle(&self, envelope: ControlPlaneEnvelope) -> Result<(), DegradedTransportError> {
        match envelope.retention {
            RetentionClass::Required => {
                // MUST store
                let object_id = envelope.object_id.clone();
                let zone_id = envelope.zone_id.clone();
                let epoch_id = envelope.epoch_id;
                info!(
                    object_id = %object_id,
                    zone_id = %zone_id,
                    epoch_id,
                    retention = "Required",
                    "degraded_mode: storing required control-plane object"
                );

                let mut state = self.state.lock().unwrap();

                if let Some(previous) = state.stored.insert(object_id.clone(), envelope) {
                    if let Some(zone_epochs) = state.epoch_index.get_mut(&previous.zone_id) {
                        if let Some(object_ids) = zone_epochs.get_mut(&previous.epoch_id) {
                            object_ids.retain(|id| id != &object_id);
                            if object_ids.is_empty() {
                                zone_epochs.remove(&previous.epoch_id);
                            }
                        }
                        if zone_epochs.is_empty() {
                            state.epoch_index.remove(&previous.zone_id);
                        }
                    }
                }

                let zone_epochs = state.epoch_index.entry(zone_id).or_default();
                let object_ids = zone_epochs.entry(epoch_id).or_default();
                if !object_ids.contains(&object_id) {
                    object_ids.push(object_id);
                }
                drop(state);
                Ok(())
            }
            RetentionClass::Ephemeral => {
                // MAY discard - we process but don't store
                debug!(
                    object_id = %envelope.object_id,
                    zone_id = %envelope.zone_id,
                    retention = "Ephemeral",
                    "degraded_mode: processed ephemeral object, not storing"
                );
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RaptorQConfig {
        RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        }
    }

    fn test_zone_id() -> ZoneId {
        "z:test".parse().expect("valid zone id")
    }

    fn test_zone_key() -> ZoneKey {
        ZoneKey::from_bytes([0x44; 32])
    }

    fn test_pq_signing_key() -> MlDsa65SigningKey {
        MlDsa65SigningKey::generate().expect("ML-DSA signing key")
    }

    const fn test_zone_algorithm() -> CoreZoneKeyAlgorithm {
        CoreZoneKeyAlgorithm::ChaCha20Poly1305
    }

    fn test_source_id() -> TailscaleNodeId {
        TailscaleNodeId::new("mesh-test-sender")
    }

    fn test_envelope() -> ControlPlaneEnvelope {
        ControlPlaneEnvelope {
            payload: vec![0x42; 256],
            schema_hash: [0xAA; 32],
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id: test_zone_id(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 0,
            retention: RetentionClass::Required,
        }
    }

    fn frame_with_symbols(frame: &FcpsFrame, symbols: Vec<SymbolRecord>) -> FcpsFrame {
        let total_payload_len = symbols
            .iter()
            .try_fold(0u32, |acc, symbol| {
                let wire_size =
                    u32::try_from(symbol.wire_size()).expect("symbol wire size should fit in u32");
                acc.checked_add(wire_size)
                    .ok_or("payload length should fit in u32")
            })
            .expect("payload length should fit in u32");

        let mut header = frame.header.clone();
        header.symbol_count = u32::try_from(symbols.len()).expect("symbol count should fit in u32");
        header.total_payload_len = total_payload_len;

        FcpsFrame { header, symbols }
    }

    fn seal_frame_symbols(frame: &FcpsFrame, source_id: &TailscaleNodeId) -> FcpsFrame {
        let zone_key = aead_key(&test_zone_key());
        let algorithm = protocol_zone_key_algorithm(test_zone_algorithm());
        let symbols = frame
            .symbols
            .iter()
            .map(|symbol| {
                let context = symbol_context(
                    frame.header.object_id.clone(),
                    symbol.esi,
                    symbol.k,
                    frame.header.zone_id_hash,
                    frame.header.zone_key_id,
                    frame.header.epoch_id,
                    source_id.clone(),
                    frame.header.sender_instance_id,
                    frame.header.frame_seq,
                );
                let (data, auth_tag) = encrypt_symbol(&zone_key, algorithm, &context, &symbol.data)
                    .expect("test symbol encryption should succeed");
                SymbolRecord {
                    esi: symbol.esi,
                    k: symbol.k,
                    data,
                    auth_tag,
                }
            })
            .collect();
        frame_with_symbols(frame, symbols)
    }

    #[test]
    fn encoder_creates_frames_with_control_plane_flag() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 0xDEAD_BEEF);

        let envelope = test_envelope();
        let frames = encoder
            .encode(&envelope, 1000)
            .expect("encode should succeed");

        assert!(!frames.is_empty());
        for frame in &frames {
            assert!(frame.header.flags.contains(FrameFlags::CONTROL_PLANE));
            assert!(frame.header.flags.contains(FrameFlags::ENCRYPTED));
            assert!(frame.header.flags.contains(FrameFlags::RAPTORQ));
        }
    }

    #[test]
    fn encoder_increments_frame_seq() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 123);

        let envelope = test_envelope();

        let frames1 = encoder.encode(&envelope, 1000).unwrap();
        let frames2 = encoder.encode(&envelope, 1000).unwrap();

        assert_eq!(frames1[0].header.frame_seq, 0);
        assert_eq!(frames2[0].header.frame_seq, 1);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 0xBEEF);
        let mut decoder = DegradedModeDecoder::new(config);

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();

        let frames = encoder.encode(&envelope, 2000).expect("encode");

        // Feed frames to decoder
        let mut result = None;
        for frame in &frames {
            if let Some(decoded) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .expect("decode")
            {
                result = Some(decoded);
                break;
            }
        }

        let decoded_envelope = result.expect("should have decoded");
        assert_eq!(decoded_envelope.payload, envelope.payload);
        assert_eq!(decoded_envelope.schema_hash, envelope.schema_hash);
        assert_eq!(decoded_envelope.object_id, envelope.object_id);
        assert_eq!(decoded_envelope.epoch_id, 2000);
    }

    #[test]
    fn decoder_rejects_non_control_plane_frame() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);

        let zone_id = test_zone_id();

        // Create a frame without CONTROL_PLANE flag (but with matching zone hash)
        let frame = FcpsFrame {
            header: FcpsFrameHeader {
                version: FCPS_VERSION,
                flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
                symbol_count: 0,
                total_payload_len: 0,
                object_id: ObjectId::from_bytes([0; 32]),
                symbol_size: 64,
                zone_key_id: ZoneKeyId::from_bytes([0; 8]),
                zone_id_hash: zone_id.hash(),
                epoch_id: 0,
                sender_instance_id: 0,
                frame_seq: 0,
            },
            symbols: vec![],
        };

        let result = decoder.process_frame(&frame, &zone_id, RetentionClass::Required);
        assert!(matches!(
            result,
            Err(DegradedTransportError::MissingControlPlaneFlag)
        ));
    }

    #[test]
    fn decoder_rejects_zone_mismatch() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);

        let zone_id = test_zone_id();
        let other_zone: ZoneId = "z:other".parse().expect("valid zone id");

        let frame = FcpsFrame {
            header: FcpsFrameHeader {
                version: FCPS_VERSION,
                flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE,
                symbol_count: 0,
                total_payload_len: 0,
                object_id: ObjectId::from_bytes([0; 32]),
                symbol_size: 64,
                zone_key_id: ZoneKeyId::from_bytes([0; 8]),
                zone_id_hash: zone_id.hash(),
                epoch_id: 0,
                sender_instance_id: 0,
                frame_seq: 0,
            },
            symbols: vec![],
        };

        let result = decoder.process_frame(&frame, &other_zone, RetentionClass::Required);
        assert!(matches!(
            result,
            Err(DegradedTransportError::ZoneMismatch { .. })
        ));
    }

    #[test]
    fn decoder_rejects_empty_control_plane_frame() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);
        let zone_id = test_zone_id();

        let frame = FcpsFrame {
            header: FcpsFrameHeader {
                version: FCPS_VERSION,
                flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE,
                symbol_count: 0,
                total_payload_len: 0,
                object_id: ObjectId::from_bytes([0xEE; 32]),
                symbol_size: 64,
                zone_key_id: ZoneKeyId::from_bytes([0; 8]),
                zone_id_hash: zone_id.hash(),
                epoch_id: 0,
                sender_instance_id: 0,
                frame_seq: 0,
            },
            symbols: vec![],
        };

        let result = decoder.process_frame(&frame, &zone_id, RetentionClass::Required);
        assert!(matches!(
            result,
            Err(DegradedTransportError::EmptyControlPlaneFrame)
        ));
        assert_eq!(decoder.pending_count(), 0);
    }

    #[test]
    fn hybrid_signed_frame_roundtrip() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 0xCAFE);
        let mut decoder = DegradedModeDecoder::new(config);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pq_signing_key = test_pq_signing_key();

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();
        let source_id = TailscaleNodeId::new("node-test");

        let signed_frames = encoder
            .encode_signed(
                &envelope,
                3000,
                &source_id,
                1_704_067_200,
                &signing_key,
                &pq_signing_key,
            )
            .expect("encode signed");

        let mut result = None;
        for signed_frame in &signed_frames {
            if let Some(decoded) = decoder
                .process_signed_frame(
                    signed_frame,
                    &verifying_key,
                    pq_signing_key.verifying_key(),
                    PqSigningPolicy::BothRequired,
                    &zone_id,
                    RetentionClass::Required,
                )
                .expect("decode")
            {
                result = Some(decoded);
                break;
            }
        }

        let decoded_envelope = result.expect("should have decoded");
        assert_eq!(decoded_envelope.payload, envelope.payload);
    }

    #[test]
    fn hybrid_signed_frame_rejects_wrong_key() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 0x1234);
        let mut decoder = DegradedModeDecoder::new(config);

        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();
        let source_id = TailscaleNodeId::new("node-wrong");

        let signed_frames = encoder
            .encode_signed(
                &envelope,
                4000,
                &source_id,
                1_704_067_200,
                &signing_key,
                &pq_signing_key,
            )
            .expect("encode");

        let result = decoder.process_signed_frame(
            &signed_frames[0],
            &wrong_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            &zone_id,
            RetentionClass::Required,
        );

        assert!(matches!(
            result,
            Err(DegradedTransportError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn handler_stores_required_objects() {
        let handler = InMemoryControlPlaneHandler::new();
        let envelope = test_envelope();
        let object_id = envelope.object_id.clone();

        handler.handle(envelope).expect("handle");

        assert_eq!(handler.count(), 1);
        assert!(handler.get(&object_id).is_some());
    }

    #[test]
    fn handler_list_epochs_and_fetch_epoch() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();

        let mut epoch_10_obj = test_envelope();
        epoch_10_obj.object_id = ObjectId::from_bytes([0x31; 32]);
        epoch_10_obj.zone_id = zone_id.clone();
        epoch_10_obj.epoch_id = 10;

        let mut epoch_11_obj = test_envelope();
        epoch_11_obj.object_id = ObjectId::from_bytes([0x32; 32]);
        epoch_11_obj.zone_id = zone_id.clone();
        epoch_11_obj.epoch_id = 11;

        let epoch_10_object_id = epoch_10_obj.object_id.clone();

        handler.handle(epoch_10_obj).expect("store epoch 10");
        handler.handle(epoch_11_obj).expect("store epoch 11");

        let all_epochs = handler.list_epochs(&zone_id, None);
        assert_eq!(all_epochs, vec![10, 11]);

        let newer_epochs = handler.list_epochs(&zone_id, Some(10));
        assert_eq!(newer_epochs, vec![11]);

        let epoch_10_objects = handler.fetch_epoch(&zone_id, 10);
        assert_eq!(epoch_10_objects.len(), 1);
        assert_eq!(epoch_10_objects[0].object_id, epoch_10_object_id);
        assert_eq!(epoch_10_objects[0].epoch_id, 10);

        assert!(handler.fetch_epoch(&zone_id, 99).is_empty());
    }

    #[test]
    fn handler_discards_ephemeral_objects() {
        let handler = InMemoryControlPlaneHandler::new();
        let mut envelope = test_envelope();
        envelope.retention = RetentionClass::Ephemeral;

        handler.handle(envelope).expect("handle");

        // Ephemeral objects are processed but not stored
        assert_eq!(handler.count(), 0);
    }

    #[test]
    fn decoder_tracks_pending_status() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 0x5678);
        let mut decoder = DegradedModeDecoder::new(config);

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();
        let object_id = envelope.object_id.clone();

        let frames = encoder.encode(&envelope, 5000).expect("encode");

        // Process first frame - should start pending
        let _ = decoder.process_frame(&frames[0], &zone_id, RetentionClass::Required);

        // Check status (may or may not be complete depending on symbol count)
        let _status = decoder.get_status(&object_id);
        // Note: status may be None if reconstruction already completed
    }

    #[test]
    fn decoder_clear_pending() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);

        let object_id = ObjectId::from_bytes([0xAB; 32]);

        // Nothing to clear initially
        assert!(!decoder.clear_pending(&object_id));
        assert_eq!(decoder.pending_count(), 0);
    }

    #[test]
    fn decoder_rejects_new_pending_beyond_cap() {
        // Defensive bound: with max_pending = 2, the decoder accepts only 2
        // distinct reconstructions. A third distinct object must be rejected
        // with PendingLimitExceeded rather than growing the pending map
        // without limit. Without this cap, an adversary sending FCPS frames
        // with unique object_id/epoch_id tuples could exhaust memory — each
        // pending entry holds a multi-KiB RaptorQ decoder.
        let config = test_config();
        let mut decoder = DegradedModeDecoder::with_max_pending(config, 2);
        let zone_id = test_zone_id();

        // Build three distinct single-symbol frames (each with a unique
        // object_id → unique PendingReconstructionKey). Each frame declares
        // K=4 but carries only 1 symbol, so reconstruction cannot complete
        // and the pending entry survives for the capacity check.
        let make_frame = |object_id_byte: u8| -> FcpsFrame {
            let symbol = SymbolRecord {
                esi: 0,
                k: 4,
                data: vec![0u8; 64],
                auth_tag: [0u8; 16],
            };
            let wire_size =
                u32::try_from(symbol.wire_size()).expect("symbol wire size fits in u32");
            FcpsFrame {
                header: FcpsFrameHeader {
                    version: FCPS_VERSION,
                    flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE,
                    symbol_count: 1,
                    total_payload_len: wire_size,
                    object_id: ObjectId::from_bytes([object_id_byte; 32]),
                    symbol_size: 64,
                    zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
                    zone_id_hash: zone_id.hash(),
                    epoch_id: u64::from(object_id_byte),
                    sender_instance_id: 0,
                    frame_seq: u64::from(object_id_byte),
                },
                symbols: vec![symbol],
            }
        };

        let frame_a = seal_frame_symbols(&make_frame(0xA0), &test_source_id());
        let frame_b = seal_frame_symbols(&make_frame(0xB0), &test_source_id());
        let frame_c = seal_frame_symbols(&make_frame(0xC0), &test_source_id());

        // First two distinct object_ids: accepted (new pending entries).
        assert!(
            decoder
                .process_frame(&frame_a, &zone_id, RetentionClass::Required)
                .is_ok(),
            "first distinct object must be admitted"
        );
        assert!(
            decoder
                .process_frame(&frame_b, &zone_id, RetentionClass::Required)
                .is_ok(),
            "second distinct object must be admitted"
        );
        assert_eq!(decoder.pending_count(), 2);

        // Third distinct object: rejected by the pending cap.
        let err = decoder
            .process_frame(&frame_c, &zone_id, RetentionClass::Required)
            .expect_err("third distinct object must trip the pending cap");
        match err {
            DegradedTransportError::PendingLimitExceeded { current, limit } => {
                assert_eq!(current, 2);
                assert_eq!(limit, 2);
            }
            other => panic!("expected PendingLimitExceeded, got {other:?}"),
        }

        // Additional symbols for an EXISTING reconstruction still flow
        // even when the map is at capacity (progress, not allocation).
        assert!(
            decoder
                .process_frame(&frame_a, &zone_id, RetentionClass::Required)
                .is_ok(),
            "adding symbols to an existing reconstruction must be allowed at cap"
        );
        assert_eq!(decoder.pending_count(), 2);
    }

    #[test]
    fn parse_reconstructed_payload_rejects_malformed_candidates_without_timeout() {
        let object_id = ObjectId::from_bytes([0x44; 32]);

        assert!(DegradedModeDecoder::parse_reconstructed_payload(&object_id, &[0u8; 12]).is_none());

        let mut oversized_claim = vec![0u8; 64];
        oversized_claim[..4].copy_from_slice(&512u32.to_be_bytes());
        oversized_claim[4..36].copy_from_slice(&[0xAB; 32]);
        assert!(
            DegradedModeDecoder::parse_reconstructed_payload(&object_id, &oversized_claim)
                .is_none()
        );
    }

    #[test]
    fn decoder_keeps_pending_state_for_invalid_reconstructed_payload_header() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);
        let zone_id = test_zone_id();
        let object_id = ObjectId::from_bytes([0x66; 32]);

        let mut malformed_payload = vec![0u8; 64];
        malformed_payload[..4].copy_from_slice(&512u32.to_be_bytes());
        malformed_payload[4..36].copy_from_slice(&[0xCD; 32]);

        let frame = seal_frame_symbols(
            &FcpsFrame {
                header: FcpsFrameHeader {
                    version: FCPS_VERSION,
                    flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE,
                    symbol_count: 1,
                    total_payload_len: u32::try_from(
                        SymbolRecord {
                            esi: 0,
                            k: 1,
                            data: malformed_payload.clone(),
                            auth_tag: [0u8; 16],
                        }
                        .wire_size(),
                    )
                    .expect("symbol wire size should fit in u32"),
                    object_id: object_id.clone(),
                    symbol_size: 64,
                    zone_key_id: ZoneKeyId::from_bytes([0x11; 8]),
                    zone_id_hash: zone_id.hash(),
                    epoch_id: 9,
                    sender_instance_id: 1,
                    frame_seq: 0,
                },
                symbols: vec![SymbolRecord {
                    esi: 0,
                    k: 1,
                    data: malformed_payload,
                    auth_tag: [0u8; 16],
                }],
            },
            &test_source_id(),
        );

        let result = decoder
            .process_frame(&frame, &zone_id, RetentionClass::Required)
            .expect("malformed reconstructed candidate should be treated as incomplete");
        assert!(result.is_none());
        assert_eq!(decoder.pending_count(), 1);

        let status = decoder
            .get_status(&object_id)
            .expect("pending decode status should be retained");
        assert_eq!(status.received, 1);
        assert!(status.needed >= 1);
        assert!(!status.likely_complete);
    }

    #[test]
    fn decoder_rejects_frame_with_mixed_source_symbol_counts() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);
        let zone_id = test_zone_id();

        let frame = seal_frame_symbols(
            &FcpsFrame {
                header: FcpsFrameHeader {
                    version: FCPS_VERSION,
                    flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE,
                    symbol_count: 2,
                    total_payload_len: u32::try_from(
                        SymbolRecord {
                            esi: 0,
                            k: 2,
                            data: vec![0x11; 64],
                            auth_tag: [0u8; 16],
                        }
                        .wire_size()
                            + SymbolRecord {
                                esi: 1,
                                k: 3,
                                data: vec![0x22; 64],
                                auth_tag: [0u8; 16],
                            }
                            .wire_size(),
                    )
                    .expect("symbol wire size should fit in u32"),
                    object_id: ObjectId::from_bytes([0x77; 32]),
                    symbol_size: 64,
                    zone_key_id: ZoneKeyId::from_bytes([0x33; 8]),
                    zone_id_hash: zone_id.hash(),
                    epoch_id: 10,
                    sender_instance_id: 2,
                    frame_seq: 7,
                },
                symbols: vec![
                    SymbolRecord {
                        esi: 0,
                        k: 2,
                        data: vec![0x11; 64],
                        auth_tag: [0u8; 16],
                    },
                    SymbolRecord {
                        esi: 1,
                        k: 3,
                        data: vec![0x22; 64],
                        auth_tag: [0u8; 16],
                    },
                ],
            },
            &test_source_id(),
        );

        let err = decoder
            .process_frame(&frame, &zone_id, RetentionClass::Required)
            .expect_err("mixed-k frame should be rejected");
        assert!(matches!(
            &err,
            DegradedTransportError::Decode(DecodeError::InvalidSymbol { reason })
                if reason.contains("mixes source symbol counts")
                    && reason.contains("k=2")
                    && reason.contains("k=3")
        ));
        assert_eq!(decoder.pending_count(), 0);
    }

    #[test]
    fn decoder_separates_pending_reconstructions_by_source_symbol_count() {
        let config = test_config();
        let mut decoder = DegradedModeDecoder::new(config);
        let zone_id = test_zone_id();
        let object_id = ObjectId::from_bytes([0x88; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x44; 8]);

        let frame_k2 = seal_frame_symbols(
            &FcpsFrame {
                header: FcpsFrameHeader {
                    version: FCPS_VERSION,
                    flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE,
                    symbol_count: 1,
                    total_payload_len: u32::try_from(
                        SymbolRecord {
                            esi: 0,
                            k: 2,
                            data: vec![0xAA; 64],
                            auth_tag: [0u8; 16],
                        }
                        .wire_size(),
                    )
                    .expect("symbol wire size should fit in u32"),
                    object_id: object_id.clone(),
                    symbol_size: 64,
                    zone_key_id: zone_key_id.clone(),
                    zone_id_hash: zone_id.hash(),
                    epoch_id: 12,
                    sender_instance_id: 3,
                    frame_seq: 11,
                },
                symbols: vec![SymbolRecord {
                    esi: 0,
                    k: 2,
                    data: vec![0xAA; 64],
                    auth_tag: [0u8; 16],
                }],
            },
            &test_source_id(),
        );
        let frame_k3 = frame_with_symbols(
            &FcpsFrame {
                header: FcpsFrameHeader {
                    frame_seq: 12,
                    ..frame_k2.header.clone()
                },
                symbols: vec![],
            },
            vec![SymbolRecord {
                esi: 0,
                k: 3,
                data: vec![0xBB; 64],
                auth_tag: [0u8; 16],
            }],
        );
        let frame_k3 = seal_frame_symbols(&frame_k3, &test_source_id());

        let result_k2 = decoder
            .process_frame(&frame_k2, &zone_id, RetentionClass::Required)
            .expect("first frame should start pending reconstruction");
        let result_k3 = decoder
            .process_frame(&frame_k3, &zone_id, RetentionClass::Required)
            .expect("different-k frame should not alias existing pending reconstruction");

        assert!(result_k2.is_none());
        assert!(result_k3.is_none());
        assert_eq!(decoder.pending_count(), 2);
        assert!(decoder.clear_pending(&object_id));
        assert_eq!(decoder.pending_count(), 0);
    }

    // --- New tests below ---

    #[test]
    fn retention_class_default_is_required() {
        assert_eq!(RetentionClass::default(), RetentionClass::Required);
    }

    #[test]
    fn retention_class_clone_and_eq() {
        let r = RetentionClass::Ephemeral;
        let r2 = r;
        assert_eq!(r, r2);
        assert_ne!(RetentionClass::Required, RetentionClass::Ephemeral);
    }

    #[test]
    fn retention_class_debug() {
        let s = format!("{:?}", RetentionClass::Required);
        assert!(s.contains("Required"));
        let s = format!("{:?}", RetentionClass::Ephemeral);
        assert!(s.contains("Ephemeral"));
    }

    #[test]
    fn control_plane_envelope_new_constructor() {
        let payload = vec![1, 2, 3];
        let schema_hash = [0xBB; 32];
        let object_id = ObjectId::from_bytes([0xCC; 32]);
        let zone_id = test_zone_id();
        let zone_key_id = ZoneKeyId::from_bytes([0xDD; 8]);

        let env = ControlPlaneEnvelope::new(
            payload.clone(),
            schema_hash,
            object_id.clone(),
            zone_id.clone(),
            zone_key_id.clone(),
            42,
            RetentionClass::Ephemeral,
        );

        assert_eq!(env.payload, payload);
        assert_eq!(env.schema_hash, schema_hash);
        assert_eq!(env.object_id, object_id);
        assert_eq!(env.zone_id, zone_id);
        assert_eq!(env.zone_key_id, zone_key_id);
        assert_eq!(env.epoch_id, 42);
        assert_eq!(env.retention, RetentionClass::Ephemeral);
    }

    #[test]
    fn control_plane_envelope_debug_and_clone() {
        let env = test_envelope();
        let cloned = env.clone();
        assert_eq!(cloned.payload, env.payload);
        assert_eq!(cloned.object_id, env.object_id);
        let s = format!("{env:?}");
        assert!(s.contains("ControlPlaneEnvelope"));
    }

    #[test]
    fn error_display_incomplete() {
        let e = DegradedTransportError::Incomplete {
            received: 5,
            needed: 10,
        };
        let s = e.to_string();
        assert!(s.contains('5'));
        assert!(s.contains("10"));
        assert!(s.contains("incomplete"));
    }

    #[test]
    fn error_display_schema_hash_mismatch() {
        let e = DegradedTransportError::SchemaHashMismatch {
            expected: [0xAA; 32],
            actual: [0xBB; 32],
        };
        let s = e.to_string();
        assert!(s.contains("schema hash mismatch"));
    }

    #[test]
    fn error_display_object_id_mismatch() {
        let e = DegradedTransportError::ObjectIdMismatch;
        assert!(e.to_string().contains("object ID mismatch"));
    }

    #[test]
    fn error_display_retention_violation() {
        let e = DegradedTransportError::RetentionViolation;
        assert!(e.to_string().contains("retention violation"));
    }

    #[test]
    fn error_display_missing_control_plane_flag() {
        let e = DegradedTransportError::MissingControlPlaneFlag;
        assert!(e.to_string().contains("CONTROL_PLANE"));
    }

    #[test]
    fn error_display_zone_mismatch() {
        let z1 = test_zone_id().hash();
        let z2: ZoneId = "z:other".parse().unwrap();
        let z2h = z2.hash();
        let e = DegradedTransportError::ZoneMismatch {
            expected: z1,
            got: z2h,
        };
        assert!(e.to_string().contains("zone id hash mismatch"));
    }

    #[test]
    fn error_display_signature_verification_failed() {
        let e = DegradedTransportError::SignatureVerificationFailed;
        assert!(e.to_string().contains("signature verification failed"));
    }

    #[test]
    fn error_debug_all_variants() {
        let errors: Vec<DegradedTransportError> = vec![
            DegradedTransportError::ObjectIdMismatch,
            DegradedTransportError::RetentionViolation,
            DegradedTransportError::MissingControlPlaneFlag,
            DegradedTransportError::EmptyControlPlaneFrame,
            DegradedTransportError::SignatureVerificationFailed,
            DegradedTransportError::Incomplete {
                received: 1,
                needed: 2,
            },
            DegradedTransportError::SchemaHashMismatch {
                expected: [0; 32],
                actual: [1; 32],
            },
        ];
        for e in &errors {
            let s = format!("{e:?}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn encoder_sets_sender_instance_id() {
        let config = test_config();
        let instance_id = 0x1234_5678_9ABC_DEF0;
        let mut encoder = DegradedModeEncoder::new(config, instance_id);

        let envelope = test_envelope();
        let frames = encoder.encode(&envelope, 100).unwrap();

        assert_eq!(frames[0].header.sender_instance_id, instance_id);
    }

    #[test]
    fn encoder_uses_requested_epoch_even_if_envelope_differs() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 1);

        let mut envelope = test_envelope();
        envelope.epoch_id = 7;

        let frames = encoder
            .encode(&envelope, 8)
            .expect("transport epoch should be authoritative");
        assert_eq!(frames[0].header.epoch_id, 8);
    }

    #[test]
    fn encoder_sets_epoch_id_in_header() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 1);

        let envelope = test_envelope();
        let frames = encoder.encode(&envelope, 7777).unwrap();

        assert_eq!(frames[0].header.epoch_id, 7777);
    }

    #[test]
    fn encoder_sets_object_id_in_header() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 1);

        let envelope = test_envelope();
        let frames = encoder.encode(&envelope, 1).unwrap();

        assert_eq!(frames[0].header.object_id, envelope.object_id);
    }

    #[test]
    fn encoder_symbols_have_correct_k() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 1);

        let envelope = test_envelope();
        let frames = encoder.encode(&envelope, 1).unwrap();

        // All symbols in a frame should have the same k value
        let frame = &frames[0];
        if frame.symbols.len() > 1 {
            let k = frame.symbols[0].k;
            for sym in &frame.symbols {
                assert_eq!(sym.k, k);
            }
        }
    }

    #[test]
    fn decode_roundtrip_preserves_zone_key_id() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();

        let frames = encoder.encode(&envelope, 1).unwrap();

        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.zone_key_id, envelope.zone_key_id);
        assert_eq!(output.zone_id, envelope.zone_id);
    }

    #[test]
    fn decode_roundtrip_with_ephemeral_retention() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let mut envelope = test_envelope();
        envelope.retention = RetentionClass::Ephemeral;
        let zone_id = envelope.zone_id.clone();

        let frames = encoder.encode(&envelope, 1).unwrap();

        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Ephemeral)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.retention, RetentionClass::Ephemeral);
    }

    #[test]
    fn decode_roundtrip_small_payload() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let mut envelope = test_envelope();
        envelope.payload = vec![0xFF; 8]; // very small payload
        let zone_id = envelope.zone_id.clone();

        let frames = encoder.encode(&envelope, 1).unwrap();
        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.payload, vec![0xFF; 8]);
    }

    #[test]
    fn decoder_pending_count_after_incomplete_frame() {
        let config = RaptorQConfig {
            symbol_size: 64,
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 64, // force chunking to get multiple symbols
            chunk_size: 64,
        };
        let mut decoder = DegradedModeDecoder::new(config);
        let zone_id = test_zone_id();

        // Manually create a frame with a single symbol (insufficient for decode)
        let frame = seal_frame_symbols(
            &FcpsFrame {
                header: FcpsFrameHeader {
                    version: FCPS_VERSION,
                    flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::CONTROL_PLANE,
                    symbol_count: 1,
                    total_payload_len: 100,
                    object_id: ObjectId::from_bytes([0x55; 32]),
                    symbol_size: 64,
                    zone_key_id: ZoneKeyId::from_bytes([0; 8]),
                    zone_id_hash: zone_id.hash(),
                    epoch_id: 0,
                    sender_instance_id: 0,
                    frame_seq: 0,
                },
                symbols: vec![SymbolRecord {
                    esi: 0,
                    k: 10, // claim 10 source symbols needed
                    data: vec![0u8; 64],
                    auth_tag: [0u8; 16],
                }],
            },
            &test_source_id(),
        );

        let result = decoder.process_frame(&frame, &zone_id, RetentionClass::Required);
        // Should be Ok(None) - incomplete
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Now should have 1 pending
        assert_eq!(decoder.pending_count(), 1);

        // get_status should return info
        let status = decoder
            .get_status(&ObjectId::from_bytes([0x55; 32]))
            .expect("should have status");
        assert_eq!(status.received, 1);
        assert!(!status.likely_complete);

        // clear_pending should work
        assert!(decoder.clear_pending(&ObjectId::from_bytes([0x55; 32])));
        assert_eq!(decoder.pending_count(), 0);
    }

    #[test]
    fn decoder_tracks_same_object_across_epochs_independently() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let envelope = test_envelope();
        let zone_id = envelope.zone_id.clone();

        let frame_epoch_10 = encoder.encode(&envelope, 10).unwrap().remove(0);
        let frame_epoch_11 = encoder.encode(&envelope, 11).unwrap().remove(0);

        assert!(
            frame_epoch_10.symbols.len() >= 2,
            "test requires multiple symbols to stay incomplete"
        );

        let partial_epoch_10 =
            frame_with_symbols(&frame_epoch_10, frame_epoch_10.symbols[..1].to_vec());
        let partial_epoch_11 =
            frame_with_symbols(&frame_epoch_11, frame_epoch_11.symbols[..1].to_vec());

        assert!(
            decoder
                .process_frame(&partial_epoch_10, &zone_id, RetentionClass::Required)
                .unwrap()
                .is_none()
        );
        assert!(
            decoder
                .process_frame(&partial_epoch_11, &zone_id, RetentionClass::Required)
                .unwrap()
                .is_none()
        );

        assert_eq!(decoder.pending_count(), 2);
        assert!(decoder.get_status(&envelope.object_id).is_some());
        assert!(decoder.clear_pending(&envelope.object_id));
        assert_eq!(decoder.pending_count(), 0);
    }

    #[test]
    fn decode_status_info_debug_and_clone() {
        let info = DecodeStatusInfo {
            received: 5,
            needed: 10,
            likely_complete: false,
        };
        let cloned = info;
        assert_eq!(cloned.received, 5);
        assert_eq!(cloned.needed, 10);
        assert!(!cloned.likely_complete);
        let s = format!("{info:?}");
        assert!(s.contains("DecodeStatusInfo"));
    }

    #[test]
    fn handler_unknown_zone_returns_empty_epochs() {
        let handler = InMemoryControlPlaneHandler::new();
        let unknown_zone: ZoneId = "z:unknown".parse().unwrap();
        assert!(handler.list_epochs(&unknown_zone, None).is_empty());
        assert!(handler.fetch_epoch(&unknown_zone, 0).is_empty());
    }

    #[test]
    fn handler_replaces_object_with_same_id() {
        let handler = InMemoryControlPlaneHandler::new();

        let mut env1 = test_envelope();
        env1.payload = vec![0x01; 100];
        env1.epoch_id = 1;
        let oid = env1.object_id.clone();

        handler.handle(env1).unwrap();
        assert_eq!(handler.count(), 1);

        // Replace same object_id with different payload/epoch
        let mut env2 = test_envelope();
        env2.payload = vec![0x02; 200];
        env2.epoch_id = 2;

        handler.handle(env2).unwrap();
        assert_eq!(handler.count(), 1); // still 1 object

        let stored = handler.get(&oid).unwrap();
        assert_eq!(stored.payload, vec![0x02; 200]);
        assert_eq!(stored.epoch_id, 2);

        // Old epoch should be cleaned up, new epoch should exist
        let zone_id = test_zone_id();
        let epochs = handler.list_epochs(&zone_id, None);
        assert!(!epochs.contains(&1)); // old epoch removed
        assert!(epochs.contains(&2));
    }

    #[test]
    fn handler_multiple_objects_same_epoch() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();

        let mut env1 = test_envelope();
        env1.object_id = ObjectId::from_bytes([0xA1; 32]);
        env1.epoch_id = 5;

        let mut env2 = test_envelope();
        env2.object_id = ObjectId::from_bytes([0xA2; 32]);
        env2.epoch_id = 5;

        handler.handle(env1).unwrap();
        handler.handle(env2).unwrap();

        assert_eq!(handler.count(), 2);
        let objects = handler.fetch_epoch(&zone_id, 5);
        assert_eq!(objects.len(), 2);
    }

    #[test]
    fn handler_list_epochs_since_filters_correctly() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();

        for epoch in [1, 3, 5, 7, 9] {
            let mut env = test_envelope();
            env.object_id = ObjectId::from_bytes([epoch as u8; 32]);
            env.epoch_id = epoch;
            handler.handle(env).unwrap();
        }

        // since_epoch=5 should return only 7 and 9
        let epochs = handler.list_epochs(&zone_id, Some(5));
        assert_eq!(epochs, vec![7, 9]);

        // since_epoch=0 should return all
        let epochs = handler.list_epochs(&zone_id, Some(0));
        assert_eq!(epochs, vec![1, 3, 5, 7, 9]);
    }

    // ── DegradedTransportError Display coverage ────────────────

    #[test]
    fn error_encode_display() {
        let err = DegradedTransportError::Incomplete {
            received: 5,
            needed: 10,
        };
        let s = err.to_string();
        assert!(s.contains('5'));
        assert!(s.contains("10"));
    }

    #[test]
    fn error_schema_hash_mismatch_fields() {
        let err = DegradedTransportError::SchemaHashMismatch {
            expected: [0xAA; 32],
            actual: [0xBB; 32],
        };
        let s = err.to_string();
        assert!(s.contains("schema hash mismatch"));
    }

    #[test]
    fn error_object_id_mismatch_display() {
        let err = DegradedTransportError::ObjectIdMismatch;
        assert!(err.to_string().contains("object ID mismatch"));
    }

    #[test]
    fn error_retention_violation_display() {
        let err = DegradedTransportError::RetentionViolation;
        assert!(err.to_string().contains("retention"));
    }

    #[test]
    fn error_zone_mismatch_fields() {
        let z1 = ZoneId::work().hash();
        let z2 = ZoneId::community().hash();
        let err = DegradedTransportError::ZoneMismatch {
            expected: z1,
            got: z2,
        };
        let s = err.to_string();
        assert!(s.contains("zone id hash mismatch"));
    }

    // ── ControlPlaneEnvelope field access ──────────────────────

    #[test]
    fn envelope_field_access() {
        let env = test_envelope();
        assert_eq!(env.payload, vec![0x42; 256]);
        assert_eq!(env.schema_hash, [0xAA; 32]);
        assert_eq!(env.epoch_id, 0);
        assert_eq!(env.retention, RetentionClass::Required);
    }

    #[test]
    fn envelope_ephemeral_retention() {
        let env = ControlPlaneEnvelope::new(
            b"eph-data".to_vec(),
            [0xDD; 32],
            ObjectId::from_bytes([0xEE; 32]),
            test_zone_id(),
            ZoneKeyId::from_bytes([0xBB; 8]),
            99,
            RetentionClass::Ephemeral,
        );
        assert_eq!(env.retention, RetentionClass::Ephemeral);
        assert_eq!(env.epoch_id, 99);
    }

    // ── Encoder additional tests ───────────────────────────────

    #[test]
    fn encoder_default_frame_seq_is_zero() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 42);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        assert_eq!(frames[0].header.frame_seq, 0);
    }

    #[test]
    fn encoder_multiple_encodes_increment_frame_seq() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 42);
        let env = test_envelope();
        let frames1 = encoder.encode(&env, 1).unwrap();
        let frames2 = encoder.encode(&env, 2).unwrap();
        assert_eq!(frames1[0].header.frame_seq, 0);
        assert_eq!(frames2[0].header.frame_seq, 1);
    }

    // ── Decoder additional tests ───────────────────────────────

    #[test]
    fn decoder_new_has_no_pending() {
        let decoder = DegradedModeDecoder::new(test_config());
        assert_eq!(decoder.pending_count(), 0);
    }

    // ── Handler additional tests ───────────────────────────────

    #[test]
    fn handler_list_epochs_none_filter_returns_all() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();
        for epoch in [2, 4, 6] {
            let mut env = test_envelope();
            env.object_id = ObjectId::from_bytes([epoch as u8; 32]);
            env.epoch_id = epoch;
            handler.handle(env).unwrap();
        }
        let epochs = handler.list_epochs(&zone_id, None);
        assert_eq!(epochs, vec![2, 4, 6]);
    }

    #[test]
    fn handler_fetch_epoch_empty_for_unknown() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();
        let objects = handler.fetch_epoch(&zone_id, 42);
        assert!(objects.is_empty());
    }

    #[test]
    fn handler_count_is_zero_initially() {
        let handler = InMemoryControlPlaneHandler::new();
        assert_eq!(handler.count(), 0);
    }

    // ── RetentionClass additional tests ──────────────────────────

    #[test]
    fn retention_class_copy_semantics() {
        let r = RetentionClass::Required;
        let r2 = r;
        let r3 = r;
        assert_eq!(r2, RetentionClass::Required);
        assert_eq!(r3, RetentionClass::Required);
    }

    #[test]
    fn retention_class_all_variants_distinct() {
        let required = RetentionClass::Required;
        let ephemeral = RetentionClass::Ephemeral;
        assert_ne!(required, ephemeral);
    }

    // ── ControlPlaneEnvelope edge cases ──────────────────────────

    #[test]
    fn envelope_empty_payload() {
        let env = ControlPlaneEnvelope::new(
            vec![],
            [0x00; 32],
            ObjectId::from_bytes([0x01; 32]),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x02; 8]),
            0,
            RetentionClass::Required,
        );
        assert!(env.payload.is_empty());
        assert_eq!(env.epoch_id, 0);
    }

    #[test]
    fn envelope_max_epoch_id() {
        let env = ControlPlaneEnvelope::new(
            vec![1],
            [0xFF; 32],
            ObjectId::from_bytes([0x01; 32]),
            test_zone_id(),
            ZoneKeyId::from_bytes([0x02; 8]),
            u64::MAX,
            RetentionClass::Ephemeral,
        );
        assert_eq!(env.epoch_id, u64::MAX);
    }

    #[test]
    fn envelope_clone_is_independent() {
        let env = test_envelope();
        let mut cloned = env.clone();
        cloned.payload.push(0xFF);
        assert_ne!(env.payload.len(), cloned.payload.len());
    }

    // ── DegradedModeEncoder edge cases ──────────────────────────

    #[test]
    fn encoder_zero_sender_instance_id() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 0);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        assert_eq!(frames[0].header.sender_instance_id, 0);
    }

    #[test]
    fn encoder_max_sender_instance_id() {
        let mut encoder = DegradedModeEncoder::new(test_config(), u64::MAX);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        assert_eq!(frames[0].header.sender_instance_id, u64::MAX);
    }

    #[test]
    fn encoder_epoch_zero() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 1);
        let env = test_envelope();
        let frames = encoder.encode(&env, 0).unwrap();
        assert_eq!(frames[0].header.epoch_id, 0);
    }

    #[test]
    fn encoder_large_epoch() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 1);
        let env = test_envelope();
        let frames = encoder.encode(&env, u64::MAX).unwrap();
        assert_eq!(frames[0].header.epoch_id, u64::MAX);
    }

    #[test]
    fn encoder_frame_seq_increments_across_many_calls() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 1);
        let env = test_envelope();

        for i in 0..10 {
            let frames = encoder.encode(&env, i).unwrap();
            assert_eq!(frames[0].header.frame_seq, i);
        }
    }

    #[test]
    fn encoder_frame_version_is_fcps_version() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 1);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        assert_eq!(frames[0].header.version, FCPS_VERSION);
    }

    #[test]
    fn encoder_frame_has_all_required_flags() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 1);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        let flags = frames[0].header.flags;
        assert!(flags.contains(FrameFlags::ENCRYPTED));
        assert!(flags.contains(FrameFlags::RAPTORQ));
        assert!(flags.contains(FrameFlags::CONTROL_PLANE));
    }

    #[test]
    fn encoder_symbol_records_not_empty() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 1);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        assert!(!frames[0].symbols.is_empty());
    }

    #[test]
    fn encoder_zone_id_hash_matches() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 1);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        assert_eq!(frames[0].header.zone_id_hash, env.zone_id.hash());
    }

    // ── DegradedModeDecoder edge cases ──────────────────────────

    #[test]
    fn decoder_get_status_nonexistent() {
        let decoder = DegradedModeDecoder::new(test_config());
        assert!(
            decoder
                .get_status(&ObjectId::from_bytes([0xFF; 32]))
                .is_none()
        );
    }

    #[test]
    fn decoder_clear_pending_nonexistent() {
        let mut decoder = DegradedModeDecoder::new(test_config());
        assert!(!decoder.clear_pending(&ObjectId::from_bytes([0xFF; 32])));
    }

    // ── Roundtrip with different payload sizes ──────────────────

    #[test]
    fn decode_roundtrip_single_byte_payload() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let mut env = test_envelope();
        env.payload = vec![0x42];
        let zone_id = env.zone_id.clone();

        let frames = encoder.encode(&env, 1).unwrap();
        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.payload, vec![0x42]);
    }

    #[test]
    fn decode_roundtrip_medium_payload() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let mut env = test_envelope();
        env.payload = vec![0xAB; 512];
        let zone_id = env.zone_id.clone();

        let frames = encoder.encode(&env, 1).unwrap();
        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.payload, vec![0xAB; 512]);
    }

    #[test]
    fn decode_roundtrip_preserves_schema_hash() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let mut env = test_envelope();
        env.schema_hash = [0x99; 32];
        let zone_id = env.zone_id.clone();

        let frames = encoder.encode(&env, 1).unwrap();
        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.schema_hash, [0x99; 32]);
    }

    #[test]
    fn decode_roundtrip_preserves_object_id() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let mut env = test_envelope();
        env.object_id = ObjectId::from_bytes([0x77; 32]);
        let zone_id = env.zone_id.clone();

        let frames = encoder.encode(&env, 1).unwrap();
        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.object_id, ObjectId::from_bytes([0x77; 32]));
    }

    // ── InMemoryControlPlaneHandler edge cases ──────────────────

    #[test]
    fn handler_get_nonexistent_returns_none() {
        let handler = InMemoryControlPlaneHandler::new();
        assert!(handler.get(&ObjectId::from_bytes([0xFF; 32])).is_none());
    }

    #[test]
    fn handler_default_is_empty() {
        let handler = InMemoryControlPlaneHandler::default();
        assert_eq!(handler.count(), 0);
    }

    #[test]
    fn handler_multiple_zones() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone1 = test_zone_id();
        let zone2: ZoneId = "z:other-zone".parse().unwrap();

        let mut env1 = test_envelope();
        env1.zone_id = zone1.clone();
        env1.epoch_id = 1;
        env1.object_id = ObjectId::from_bytes([0x01; 32]);

        let mut env2 = test_envelope();
        env2.zone_id = zone2.clone();
        env2.epoch_id = 1;
        env2.object_id = ObjectId::from_bytes([0x02; 32]);

        handler.handle(env1).unwrap();
        handler.handle(env2).unwrap();

        assert_eq!(handler.count(), 2);
        assert_eq!(handler.list_epochs(&zone1, None), vec![1]);
        assert_eq!(handler.list_epochs(&zone2, None), vec![1]);
    }

    #[test]
    fn handler_store_many_epochs() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();

        for epoch in 0..20 {
            let mut env = test_envelope();
            env.object_id = ObjectId::from_bytes([epoch as u8; 32]);
            env.epoch_id = epoch;
            handler.handle(env).unwrap();
        }

        assert_eq!(handler.count(), 20);
        let epochs = handler.list_epochs(&zone_id, None);
        assert_eq!(epochs.len(), 20);
        assert_eq!(*epochs.first().unwrap(), 0);
        assert_eq!(*epochs.last().unwrap(), 19);
    }

    #[test]
    fn handler_replace_updates_epoch_index() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();

        // Store object at epoch 5
        let mut env = test_envelope();
        env.epoch_id = 5;
        let oid = env.object_id.clone();
        handler.handle(env).unwrap();

        assert_eq!(handler.list_epochs(&zone_id, None), vec![5]);

        // Replace same object at epoch 10
        let mut env2 = test_envelope();
        env2.object_id = oid;
        env2.epoch_id = 10;
        handler.handle(env2).unwrap();

        assert_eq!(handler.count(), 1);
        let epochs = handler.list_epochs(&zone_id, None);
        // Epoch 5 should be gone (empty), epoch 10 should exist
        assert!(!epochs.contains(&5));
        assert!(epochs.contains(&10));
    }

    #[test]
    fn handler_list_epochs_since_max_returns_empty() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();

        let mut env = test_envelope();
        env.epoch_id = 100;
        handler.handle(env).unwrap();

        let epochs = handler.list_epochs(&zone_id, Some(100));
        assert!(epochs.is_empty());

        let epochs = handler.list_epochs(&zone_id, Some(u64::MAX));
        assert!(epochs.is_empty());
    }

    #[test]
    fn handler_ephemeral_not_in_epoch_index() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();

        let mut env = test_envelope();
        env.retention = RetentionClass::Ephemeral;
        env.epoch_id = 42;
        handler.handle(env).unwrap();

        assert_eq!(handler.count(), 0);
        assert!(handler.list_epochs(&zone_id, None).is_empty());
    }

    // ── DecodeStatusInfo edge cases ─────────────────────────────

    #[test]
    fn decode_status_info_likely_complete_true() {
        let info = DecodeStatusInfo {
            received: 10,
            needed: 10,
            likely_complete: true,
        };
        assert!(info.likely_complete);
        assert_eq!(info.received, 10);
    }

    #[test]
    fn decode_status_info_zero_values() {
        let info = DecodeStatusInfo {
            received: 0,
            needed: 0,
            likely_complete: false,
        };
        let s = format!("{info:?}");
        assert!(s.contains("received: 0"));
        assert!(s.contains("needed: 0"));
    }

    #[test]
    fn decode_status_info_copy_semantics() {
        let info = DecodeStatusInfo {
            received: 7,
            needed: 12,
            likely_complete: false,
        };
        let copied = info;
        let copied2 = info;
        assert_eq!(copied.received, 7);
        assert_eq!(copied2.needed, 12);
    }

    // ── DegradedTransportError additional coverage ──────────────

    #[test]
    fn error_incomplete_fields() {
        let e = DegradedTransportError::Incomplete {
            received: 0,
            needed: 100,
        };
        let s = e.to_string();
        assert!(s.contains('0'));
        assert!(s.contains("100"));
    }

    #[test]
    fn error_zone_mismatch_with_same_hash_different_zones() {
        let z1: ZoneId = "z:alpha".parse().unwrap();
        let z2: ZoneId = "z:beta".parse().unwrap();
        let e = DegradedTransportError::ZoneMismatch {
            expected: z1.hash(),
            got: z2.hash(),
        };
        let s = format!("{e:?}");
        assert!(s.contains("ZoneMismatch"));
    }

    #[test]
    fn error_schema_hash_mismatch_with_zeros() {
        let e = DegradedTransportError::SchemaHashMismatch {
            expected: [0u8; 32],
            actual: [0u8; 32],
        };
        let s = e.to_string();
        assert!(s.contains("schema hash mismatch"));
    }

    // ── Signed frame edge cases ─────────────────────────────────

    #[test]
    fn hybrid_signed_frame_timestamp_preserved() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 1);
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let env = test_envelope();
        let source_id = TailscaleNodeId::new("node-ts");

        let signed_frames = encoder
            .encode_signed(
                &env,
                1,
                &source_id,
                9_999_999,
                &signing_key,
                &pq_signing_key,
            )
            .unwrap();

        assert_eq!(signed_frames[0].payload.timestamp, 9_999_999);
    }

    #[test]
    fn hybrid_signed_frame_source_id_preserved() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 1);
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let env = test_envelope();
        let source_id = TailscaleNodeId::new("node-src-check");

        let signed_frames = encoder
            .encode_signed(&env, 1, &source_id, 1000, &signing_key, &pq_signing_key)
            .unwrap();

        assert_eq!(signed_frames[0].payload.source_id, source_id);
    }

    #[test]
    fn hybrid_signed_frame_uses_requested_epoch_even_if_envelope_differs() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config, 1);
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let mut env = test_envelope();
        env.epoch_id = 3;
        let source_id = TailscaleNodeId::new("node-epoch-mismatch");

        let signed_frames = encoder
            .encode_signed(&env, 4, &source_id, 1000, &signing_key, &pq_signing_key)
            .expect("transport epoch should be authoritative");
        let frame = signed_frames[0]
            .payload
            .decode_frame(usize::MAX)
            .expect("hybrid signed frame decodes");
        assert_eq!(frame.header.epoch_id, 4);
    }

    #[test]
    fn signed_encode_decode_preserves_epoch() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pq_signing_key = test_pq_signing_key();
        let env = test_envelope();
        let zone_id = env.zone_id.clone();
        let source_id = TailscaleNodeId::new("node-epoch");

        let signed_frames = encoder
            .encode_signed(&env, 12345, &source_id, 1000, &signing_key, &pq_signing_key)
            .unwrap();

        let mut result = None;
        for sf in &signed_frames {
            if let Some(d) = decoder
                .process_signed_frame(
                    sf,
                    &verifying_key,
                    pq_signing_key.verifying_key(),
                    PqSigningPolicy::BothRequired,
                    &zone_id,
                    RetentionClass::Required,
                )
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.epoch_id, 12345);
    }

    // ── Roundtrip with different schema hashes ──────────────────

    #[test]
    fn decode_roundtrip_zero_schema_hash() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let mut env = test_envelope();
        env.schema_hash = [0u8; 32];
        let zone_id = env.zone_id.clone();

        let frames = encoder.encode(&env, 1).unwrap();
        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.schema_hash, [0u8; 32]);
    }

    #[test]
    fn decode_roundtrip_max_schema_hash() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let mut env = test_envelope();
        env.schema_hash = [0xFF; 32];
        let zone_id = env.zone_id.clone();

        let frames = encoder.encode(&env, 1).unwrap();
        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.schema_hash, [0xFF; 32]);
    }

    // ── Handler replace with different zone ──────────────────────

    #[test]
    fn handler_objects_from_different_zones_independent() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone1 = test_zone_id();
        let zone2: ZoneId = "z:second".parse().unwrap();

        let mut env1 = test_envelope();
        env1.zone_id = zone1.clone();
        env1.epoch_id = 1;

        let mut env2 = test_envelope();
        env2.zone_id = zone2.clone();
        env2.object_id = ObjectId::from_bytes([0x33; 32]);
        env2.epoch_id = 2;

        handler.handle(env1).unwrap();
        handler.handle(env2).unwrap();

        assert_eq!(handler.list_epochs(&zone1, None), vec![1]);
        assert_eq!(handler.list_epochs(&zone2, None), vec![2]);
    }

    // ── Decoder multiple objects simultaneously ─────────────────

    #[test]
    fn decoder_handles_multiple_objects() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);
        let zone_id = test_zone_id();

        let mut env1 = test_envelope();
        env1.object_id = ObjectId::from_bytes([0xA1; 32]);
        env1.payload = vec![0x01; 100];

        let mut env2 = test_envelope();
        env2.object_id = ObjectId::from_bytes([0xA2; 32]);
        env2.payload = vec![0x02; 200];

        let frames1 = encoder.encode(&env1, 1).unwrap();
        let frames2 = encoder.encode(&env2, 2).unwrap();

        // Decode first object
        let mut result1 = None;
        for frame in &frames1 {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result1 = Some(d);
                break;
            }
        }

        // Decode second object
        let mut result2 = None;
        for frame in &frames2 {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result2 = Some(d);
                break;
            }
        }

        let out1 = result1.expect("should decode env1");
        assert_eq!(out1.payload, vec![0x01; 100]);
        assert_eq!(out1.object_id, ObjectId::from_bytes([0xA1; 32]));

        let out2 = result2.expect("should decode env2");
        assert_eq!(out2.payload, vec![0x02; 200]);
        assert_eq!(out2.object_id, ObjectId::from_bytes([0xA2; 32]));
    }

    // ── Encoder with various config symbol sizes ────────────────

    #[test]
    fn encoder_with_larger_symbol_size() {
        let config = RaptorQConfig {
            symbol_size: 128,
            repair_ratio_bps: 500,
            max_object_size: 1024 * 1024,
            decode_timeout: std::time::Duration::from_secs(30),
            max_chunk_threshold: 1024,
            chunk_size: 256,
        };
        let mut encoder = DegradedModeEncoder::new(config, 1);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        assert_eq!(frames[0].header.symbol_size, 128);
    }

    // ── InMemoryControlPlaneHandler thread safety ────────────────

    #[test]
    fn handler_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryControlPlaneHandler>();
    }

    // ── Error From conversions ──────────────────────────────────

    #[test]
    fn error_from_frame_error() {
        // FrameError should convert to DegradedTransportError::Frame
        let fe = FrameError::UnsupportedVersion { version: 99 };
        let dte: DegradedTransportError = fe.into();
        let s = dte.to_string();
        assert!(s.contains("frame error"));
    }

    // ── Envelope different zone_key_ids ─────────────────────────

    #[test]
    fn roundtrip_different_zone_key_ids() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let mut env = test_envelope();
        env.zone_key_id = ZoneKeyId::from_bytes([0xFF; 8]);
        let zone_id = env.zone_id.clone();

        let frames = encoder.encode(&env, 1).unwrap();
        let mut result = None;
        for frame in &frames {
            if let Some(d) = decoder
                .process_frame(frame, &zone_id, RetentionClass::Required)
                .unwrap()
            {
                result = Some(d);
                break;
            }
        }

        let output = result.expect("should decode");
        assert_eq!(output.zone_key_id, ZoneKeyId::from_bytes([0xFF; 8]));
    }

    // ── Handler fetch_epoch returns correct payloads ─────────────

    #[test]
    fn handler_fetch_epoch_payloads_match() {
        let handler = InMemoryControlPlaneHandler::new();
        let zone_id = test_zone_id();

        let mut env = test_envelope();
        env.payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        env.epoch_id = 42;
        let oid = env.object_id.clone();

        handler.handle(env).unwrap();

        let objects = handler.fetch_epoch(&zone_id, 42);
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].object_id, oid);
        assert_eq!(objects[0].payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // ── ControlPlaneHandler trait object ─────────────────────────

    #[test]
    fn handler_as_trait_object() {
        let handler: Box<dyn ControlPlaneHandler> = Box::new(InMemoryControlPlaneHandler::new());
        let env = test_envelope();
        handler.handle(env).unwrap();
    }

    // ── Encoder symbol_count in header ──────────────────────────

    #[test]
    fn encoder_header_symbol_count_matches_records() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 1);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        for frame in &frames {
            assert_eq!(frame.header.symbol_count, frame.symbols.len() as u32);
        }
    }

    // ── Encoder total_payload_len consistency ────────────────────

    #[test]
    fn encoder_total_payload_len_positive() {
        let mut encoder = DegradedModeEncoder::new(test_config(), 1);
        let env = test_envelope();
        let frames = encoder.encode(&env, 1).unwrap();
        assert!(frames[0].header.total_payload_len > 0);
    }

    // ── Decoder clear_pending after decode ──────────────────────

    #[test]
    fn decoder_pending_cleared_after_successful_decode() {
        let config = test_config();
        let mut encoder = DegradedModeEncoder::new(config.clone(), 1);
        let mut decoder = DegradedModeDecoder::new(config);

        let env = test_envelope();
        let zone_id = env.zone_id.clone();
        let object_id = env.object_id.clone();

        let frames = encoder.encode(&env, 1).unwrap();
        for frame in &frames {
            let _ = decoder.process_frame(frame, &zone_id, RetentionClass::Required);
        }

        // After successful decode, pending should be cleared for that object
        assert!(decoder.get_status(&object_id).is_none());
    }

    // ── Handler duplicate store is idempotent ───────────────────

    #[test]
    fn handler_store_same_object_twice_idempotent() {
        let handler = InMemoryControlPlaneHandler::new();
        let env = test_envelope();
        let oid = env.object_id.clone();

        handler.handle(env.clone()).unwrap();
        handler.handle(env).unwrap();

        assert_eq!(handler.count(), 1);
        assert!(handler.get(&oid).is_some());
    }
}
