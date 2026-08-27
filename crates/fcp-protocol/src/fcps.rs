//! FCPS (Flywheel Connector Protocol - Symbol) frame parsing and serialization.
//!
//! Implements the normative data-plane frame format defined in `FCP_Specification_V3.md`
//! §9.8.2 (FCPS Frame Format) and §9.8.3 (Frame Flags).
//!
//! # Wire Format
//!
//! ```text
//! FCPS FRAME FORMAT (Symbol-Native)
//!
//!   Bytes 0-3:    Magic (0x46 0x43 0x50 0x53 = "FCPS")
//!   Bytes 4-5:    Version (u16 LE)
//!   Bytes 6-7:    Flags (u16 LE)
//!   Bytes 8-11:   Symbol Count (u32 LE)
//!   Bytes 12-15:  Total Payload Length (u32 LE)
//!   Bytes 16-47:  Object ID (32 bytes)
//!   Bytes 48-49:  Symbol Size (u16 LE, default 1024)
//!   Bytes 50-57:  Zone Key ID (8 bytes, for rotation)
//!   Bytes 58-89:  Zone ID hash (32 bytes, BLAKE3; see section 3.4)
//!   Bytes 90-97:  Epoch ID (u64 LE)
//!   Bytes 98-105: Sender Instance ID (u64 LE, reboot-safety for nonces)
//!   Bytes 106-113: Frame Seq (u64 LE, per-sender monotonic)
//!   Bytes 114+:   Symbol payloads (concatenated)
//!
//!   Fixed header: 114 bytes
//!   Each symbol: 4 (ESI) + 2 (K) + N (data) + 16 (auth_tag)
//! ```

use bitflags::bitflags;
use fcp_crypto::{
    CryptoError, CryptoResult, Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey,
    HybridSignable, HybridSignedObjectKind, MlDsa65SigningKey, MlDsa65VerifyingKey,
    PqSigningPolicy, SignedEnvelope, signing_bytes_for_canonical_payload,
    verify_signable_with_policy,
};
use fcp_prelude::{ObjectHeader, ObjectId, TailscaleNodeId, ZoneId, ZoneIdHash, ZoneKeyId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// FCPS magic bytes: "FCPS"
pub const FCPS_MAGIC: [u8; 4] = [0x46, 0x43, 0x50, 0x53];

/// Current FCPS version.
pub const FCPS_VERSION: u16 = 1;

/// Fixed header length in bytes.
pub const FCPS_HEADER_LEN: usize = 114;

/// Default symbol size in bytes.
pub const DEFAULT_SYMBOL_SIZE: u16 = 1024;

/// Per-symbol overhead: ESI (4) + K (2) + `auth_tag` (16) = 22 bytes
pub const SYMBOL_RECORD_OVERHEAD: usize = 22;

bitflags! {
    /// FCPS frame flags (NORMATIVE).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FrameFlags: u16 {
        /// Requires acknowledgment from receiver.
        const REQUIRES_ACK      = 0b0000_0000_0001;
        /// Payload is zstd compressed.
        const COMPRESSED        = 0b0000_0000_0010;
        /// Symbols are zone-encrypted.
        const ENCRYPTED         = 0b0000_0000_0100;
        /// Response to a previous request.
        const RESPONSE          = 0b0000_0000_1000;
        /// Error response frame.
        const ERROR             = 0b0000_0001_0000;
        /// Part of a streaming transfer.
        const STREAMING         = 0b0000_0010_0000;
        /// Final frame in a stream.
        const STREAM_END        = 0b0000_0100_0000;
        /// Contains an embedded capability token.
        const HAS_CAP_TOKEN     = 0b0000_1000_0000;
        /// Frame crosses zone boundaries.
        const ZONE_CROSSING     = 0b0001_0000_0000;
        /// High priority frame.
        const PRIORITY          = 0b0010_0000_0000;
        /// RaptorQ encoded (default for fountain codes).
        const RAPTORQ           = 0b0100_0000_0000;
        /// Control plane object (routed differently).
        const CONTROL_PLANE     = 0b1000_0000_0000;
    }
}

impl Default for FrameFlags {
    fn default() -> Self {
        // Default: encrypted + RaptorQ encoded
        Self::ENCRYPTED | Self::RAPTORQ
    }
}

/// FCPS frame parsing and validation errors.
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame too short (len {len}, min {min})")]
    TooShort { len: usize, min: usize },

    #[error("frame exceeds MTU (len {len}, max {max})")]
    ExceedsMtu { len: usize, max: usize },

    #[error("invalid magic bytes (expected FCPS, got {got:?})")]
    InvalidMagic { got: [u8; 4] },

    #[error("unsupported version {version}")]
    UnsupportedVersion { version: u16 },

    #[error("payload length mismatch (claimed {claimed}, computed {computed})")]
    LengthMismatch { claimed: usize, computed: usize },

    #[error("frame size mismatch (header + payload != frame len)")]
    FrameSizeMismatch,

    #[error("symbol count overflow")]
    SymbolCountOverflow,

    #[error("invalid symbol size (must be > 0)")]
    InvalidSymbolSize,

    #[error("invalid flags: {reason}")]
    InvalidFlags { reason: String },

    #[error("invalid utf-8 string")]
    InvalidUtf8,

    #[error("source_id too long (len {len}, max {max})")]
    InvalidSourceIdLength { len: usize, max: usize },

    #[error("source_id must not be empty")]
    SourceIdEmpty,
}

/// Parsed FCPS frame header (114 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcpsFrameHeader {
    /// Protocol version (currently 1).
    pub version: u16,
    /// Frame flags.
    pub flags: FrameFlags,
    /// Number of symbol records in the payload.
    pub symbol_count: u32,
    /// Total payload length in bytes.
    pub total_payload_len: u32,
    /// Content-addressed object ID (32 bytes).
    pub object_id: ObjectId,
    /// Symbol size in bytes (default 1024).
    pub symbol_size: u16,
    /// Zone key ID for key rotation (8 bytes).
    pub zone_key_id: ZoneKeyId,
    /// Zone ID hash (32 bytes, BLAKE3).
    pub zone_id_hash: ZoneIdHash,
    /// Epoch ID for replay protection (u64 LE in wire format).
    pub epoch_id: u64,
    /// Sender instance ID (random u64 at startup, for reboot safety).
    pub sender_instance_id: u64,
    /// Per-sender monotonic frame sequence number.
    pub frame_seq: u64,
}

impl FcpsFrameHeader {
    /// Encode the header to bytes (114 bytes).
    #[inline]
    #[must_use]
    pub fn encode(&self) -> [u8; FCPS_HEADER_LEN] {
        let mut buf = [0u8; FCPS_HEADER_LEN];

        buf[0..4].copy_from_slice(&FCPS_MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.flags.bits().to_le_bytes());
        buf[8..12].copy_from_slice(&self.symbol_count.to_le_bytes());
        buf[12..16].copy_from_slice(&self.total_payload_len.to_le_bytes());
        buf[16..48].copy_from_slice(self.object_id.as_bytes());
        buf[48..50].copy_from_slice(&self.symbol_size.to_le_bytes());
        buf[50..58].copy_from_slice(self.zone_key_id.as_bytes());
        buf[58..90].copy_from_slice(self.zone_id_hash.as_bytes());
        buf[90..98].copy_from_slice(&self.epoch_id.to_le_bytes());
        buf[98..106].copy_from_slice(&self.sender_instance_id.to_le_bytes());
        buf[106..114].copy_from_slice(&self.frame_seq.to_le_bytes());

        buf
    }

    /// Decode a header from bytes.
    ///
    /// # Errors
    /// Returns `FrameError` if the header is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < FCPS_HEADER_LEN {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: FCPS_HEADER_LEN,
            });
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != FCPS_MAGIC {
            return Err(FrameError::InvalidMagic { got: magic });
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != FCPS_VERSION {
            return Err(FrameError::UnsupportedVersion { version });
        }

        let flags_bits = u16::from_le_bytes([bytes[6], bytes[7]]);
        let flags = FrameFlags::from_bits(flags_bits).ok_or_else(|| FrameError::InvalidFlags {
            reason: format!(
                "unknown flag bits 0x{:04x} outside known mask 0x{:04x}",
                flags_bits,
                FrameFlags::all().bits()
            ),
        })?;

        // Reject mutually exclusive flag combinations
        if flags.contains(FrameFlags::ERROR) && flags.contains(FrameFlags::RESPONSE) {
            return Err(FrameError::InvalidFlags {
                reason: "ERROR and RESPONSE are mutually exclusive".into(),
            });
        }
        if flags.contains(FrameFlags::STREAM_END) && !flags.contains(FrameFlags::STREAMING) {
            return Err(FrameError::InvalidFlags {
                reason: "STREAM_END requires STREAMING to be set".into(),
            });
        }

        // All slice accesses below are within 0..114 which is guaranteed
        // by the length check above. Use direct from_le_bytes to avoid
        // redundant try_into().map_err() error paths.
        let symbol_count = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let total_payload_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        let mut object_id_bytes = [0u8; 32];
        object_id_bytes.copy_from_slice(&bytes[16..48]);
        let object_id = ObjectId::from_bytes(object_id_bytes);

        let symbol_size = u16::from_le_bytes([bytes[48], bytes[49]]);
        if symbol_size == 0 {
            return Err(FrameError::InvalidSymbolSize);
        }

        let mut zone_key_id_bytes = [0u8; 8];
        zone_key_id_bytes.copy_from_slice(&bytes[50..58]);
        let zone_key_id = ZoneKeyId::from_bytes(zone_key_id_bytes);

        let mut zone_id_hash_bytes = [0u8; 32];
        zone_id_hash_bytes.copy_from_slice(&bytes[58..90]);
        let zone_id_hash = ZoneIdHash::from_bytes(zone_id_hash_bytes);

        let epoch_id = u64::from_le_bytes([
            bytes[90], bytes[91], bytes[92], bytes[93], bytes[94], bytes[95], bytes[96], bytes[97],
        ]);
        let sender_instance_id = u64::from_le_bytes([
            bytes[98], bytes[99], bytes[100], bytes[101], bytes[102], bytes[103], bytes[104],
            bytes[105],
        ]);
        let frame_seq = u64::from_le_bytes([
            bytes[106], bytes[107], bytes[108], bytes[109], bytes[110], bytes[111], bytes[112],
            bytes[113],
        ]);

        Ok(Self {
            version,
            flags,
            symbol_count,
            total_payload_len,
            object_id,
            symbol_size,
            zone_key_id,
            zone_id_hash,
            epoch_id,
            sender_instance_id,
            frame_seq,
        })
    }
}

/// Symbol record within an FCPS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolRecord {
    /// Encoding Symbol ID (position in fountain code).
    pub esi: u32,
    /// Total source symbols needed (K).
    pub k: u16,
    /// Encrypted symbol payload.
    pub data: Vec<u8>,
    /// AEAD authentication tag (16 bytes).
    pub auth_tag: [u8; 16],
}

impl SymbolRecord {
    /// Wire size of this record.
    #[inline]
    #[must_use]
    pub fn wire_size(&self) -> usize {
        SYMBOL_RECORD_OVERHEAD + self.data.len()
    }

    /// Encode the record to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        self.encode_to(&mut buf);
        buf
    }

    /// Encode the record directly into an existing buffer (zero per-symbol allocation).
    #[inline]
    pub fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.esi.to_le_bytes());
        buf.extend_from_slice(&self.k.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf.extend_from_slice(&self.auth_tag);
    }

    /// Decode a symbol record from bytes given the expected symbol size.
    ///
    /// # Errors
    /// Returns `FrameError::TooShort` if buffer is insufficient.
    #[inline]
    pub fn decode(bytes: &[u8], symbol_size: u16) -> Result<Self, FrameError> {
        let expected_len = SYMBOL_RECORD_OVERHEAD + symbol_size as usize;
        if bytes.len() < expected_len {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: expected_len,
            });
        }

        let esi_bytes: [u8; 4] = bytes[0..4].try_into().map_err(|_| FrameError::TooShort {
            len: bytes.len(),
            min: expected_len,
        })?;
        let k_bytes: [u8; 2] = bytes[4..6].try_into().map_err(|_| FrameError::TooShort {
            len: bytes.len(),
            min: expected_len,
        })?;
        let esi = u32::from_le_bytes(esi_bytes);
        let k = u16::from_le_bytes(k_bytes);

        let data_end = 6 + symbol_size as usize;
        let data = bytes[6..data_end].to_vec();

        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&bytes[data_end..data_end + 16]);

        Ok(Self {
            esi,
            k,
            data,
            auth_tag,
        })
    }
}

/// Borrowed view of a symbol record — zero allocation, borrows data from frame buffer.
///
/// Use this when decoding symbols for immediate processing (MAC verification,
/// forwarding) without needing to store the symbol data persistently.
#[derive(Debug, Clone)]
pub struct SymbolRecordRef<'a> {
    /// Encoding Symbol Identifier.
    pub esi: u32,
    /// Source block length K.
    pub k: u16,
    /// Symbol data (borrowed from frame buffer).
    pub data: &'a [u8],
    /// Per-symbol authentication tag.
    pub auth_tag: [u8; 16],
}

impl<'a> SymbolRecordRef<'a> {
    /// Decode a symbol record borrowing data from the frame buffer (zero allocation).
    ///
    /// # Errors
    /// Returns `FrameError::TooShort` if buffer is insufficient.
    #[inline]
    pub fn decode(bytes: &'a [u8], symbol_size: u16) -> Result<Self, FrameError> {
        let expected_len = SYMBOL_RECORD_OVERHEAD + symbol_size as usize;
        if bytes.len() < expected_len {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: expected_len,
            });
        }

        let esi = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let k = u16::from_le_bytes([bytes[4], bytes[5]]);

        let data_end = 6 + symbol_size as usize;
        let data = &bytes[6..data_end];

        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&bytes[data_end..data_end + 16]);

        Ok(Self {
            esi,
            k,
            data,
            auth_tag,
        })
    }

    /// Convert to owned `SymbolRecord` (allocates).
    #[must_use]
    pub fn to_owned(&self) -> SymbolRecord {
        SymbolRecord {
            esi: self.esi,
            k: self.k,
            data: self.data.to_vec(),
            auth_tag: self.auth_tag,
        }
    }
}

/// Complete FCPS frame (header + symbol records).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcpsFrame {
    /// Frame header.
    pub header: FcpsFrameHeader,
    /// Symbol records.
    pub symbols: Vec<SymbolRecord>,
}

impl FcpsFrame {
    /// Encode the complete frame to bytes.
    ///
    /// # Errors
    /// Returns `FrameError::LengthMismatch` if the header's `total_payload_len`
    /// does not match the actual computed payload size.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let header_bytes = self.header.encode();
        let payload_len: usize = self.symbols.iter().map(SymbolRecord::wire_size).sum();

        if self.header.total_payload_len as usize != payload_len {
            return Err(FrameError::LengthMismatch {
                claimed: self.header.total_payload_len as usize,
                computed: payload_len,
            });
        }

        let mut buf = Vec::with_capacity(FCPS_HEADER_LEN + payload_len);
        buf.extend_from_slice(&header_bytes);
        for symbol in &self.symbols {
            symbol.encode_to(&mut buf);
        }
        Ok(buf)
    }

    /// Decode a complete frame from bytes with MTU enforcement.
    ///
    /// # Errors
    /// Returns `FrameError` if the frame is malformed or exceeds MTU.
    pub fn decode(bytes: &[u8], max_datagram_bytes: usize) -> Result<Self, FrameError> {
        if bytes.len() > max_datagram_bytes {
            return Err(FrameError::ExceedsMtu {
                len: bytes.len(),
                max: max_datagram_bytes,
            });
        }

        if bytes.len() < FCPS_HEADER_LEN {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: FCPS_HEADER_LEN,
            });
        }

        let header = FcpsFrameHeader::decode(bytes)?;
        validate_frame_lengths(bytes, &header)?;

        let mut symbols = Vec::with_capacity(header.symbol_count as usize);
        let record_size = SYMBOL_RECORD_OVERHEAD + header.symbol_size as usize;
        let mut offset = FCPS_HEADER_LEN;

        for _ in 0..header.symbol_count {
            let record = SymbolRecord::decode(&bytes[offset..], header.symbol_size)?;
            symbols.push(record);
            offset += record_size;
        }

        Ok(Self { header, symbols })
    }
}

/// Result of zero-copy frame decode — header is owned, symbols borrow from frame buffer.
#[derive(Debug)]
pub struct FcpsFrameRefs<'a> {
    /// Frame header (decoded, owned — 114 bytes, no heap allocation).
    pub header: FcpsFrameHeader,
    /// Symbol records borrowing data from the frame buffer.
    pub symbols: Vec<SymbolRecordRef<'a>>,
}

impl<'a> FcpsFrameRefs<'a> {
    /// Zero-copy frame decode — symbol data borrows from the frame buffer.
    ///
    /// Use this for decode-and-forward, MAC verification, or any path where
    /// symbol data is read but not stored. Eliminates one `Vec<u8>` heap
    /// allocation per symbol record.
    ///
    /// # Errors
    /// Returns `FrameError` if the frame is malformed or exceeds MTU.
    pub fn decode(bytes: &'a [u8], max_datagram_bytes: usize) -> Result<Self, FrameError> {
        if bytes.len() > max_datagram_bytes {
            return Err(FrameError::ExceedsMtu {
                len: bytes.len(),
                max: max_datagram_bytes,
            });
        }

        if bytes.len() < FCPS_HEADER_LEN {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: FCPS_HEADER_LEN,
            });
        }

        let header = FcpsFrameHeader::decode(bytes)?;
        validate_frame_lengths(bytes, &header)?;

        let mut symbols = Vec::with_capacity(header.symbol_count as usize);
        let record_size = SYMBOL_RECORD_OVERHEAD + header.symbol_size as usize;
        let mut offset = FCPS_HEADER_LEN;

        for _ in 0..header.symbol_count {
            let record = SymbolRecordRef::decode(&bytes[offset..], header.symbol_size)?;
            symbols.push(record);
            offset += record_size;
        }

        Ok(Self { header, symbols })
    }
}

/// Validate FCPS frame lengths for `DoS` resistance (NORMATIVE).
///
/// # Errors
/// Returns `FrameError` if computed lengths do not match declared values.
#[inline]
pub fn validate_frame_lengths(bytes: &[u8], header: &FcpsFrameHeader) -> Result<(), FrameError> {
    // Check for overflow when computing expected payload
    let record_size = SYMBOL_RECORD_OVERHEAD
        .checked_add(header.symbol_size as usize)
        .ok_or(FrameError::SymbolCountOverflow)?;

    let expected_payload = (header.symbol_count as usize)
        .checked_mul(record_size)
        .ok_or(FrameError::SymbolCountOverflow)?;

    if header.total_payload_len as usize != expected_payload {
        return Err(FrameError::LengthMismatch {
            claimed: header.total_payload_len as usize,
            computed: expected_payload,
        });
    }

    let expected_total = FCPS_HEADER_LEN
        .checked_add(expected_payload)
        .ok_or(FrameError::SymbolCountOverflow)?;

    if bytes.len() != expected_total {
        return Err(FrameError::FrameSizeMismatch);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodeStatus - Flow Control Feedback (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of missing ESI hints allowed (bounded for `DoS` resistance).
pub const MAX_MISSING_HINT_ENTRIES: usize = 100;

/// Default limit for unauthenticated symbol requests (NORMATIVE).
pub const DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED: u32 = 32;

/// Decode status feedback for flow control (NORMATIVE).
///
/// Enables receivers to tell senders how many symbols have been received and
/// how many more are needed to complete decoding. This supports targeted repair
/// and flow control in the symbol distribution layer.
///
/// # Anti-Amplification Rule (NORMATIVE)
///
/// `MeshNodes` MUST NOT send more than N symbols in response to a request unless:
/// 1. The requester is authenticated (session MAC or node signature), AND
/// 2. The request includes a bounded `missing_hint` or comparable proof-of-need
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeStatus {
    /// Object header for context.
    pub header: ObjectHeader,
    /// Content-addressed object ID.
    pub object_id: ObjectId,
    /// Zone for the object.
    pub zone_id: ZoneId,
    /// Zone key ID (for key rotation).
    pub zone_key_id: ZoneKeyId,
    /// Epoch ID for replay protection.
    pub epoch_id: u64,
    /// Intended recipient node for this status update.
    pub recipient_node_id: TailscaleNodeId,
    /// Nonce unique to the symbol-request exchange this status belongs to.
    pub request_nonce: u64,
    /// Unique symbols received so far for this object.
    pub received_unique: u32,
    /// Target required to decode (K-prime).
    /// K-prime is approximately K × 1.002 for `RaptorQ`.
    pub needed: u32,
    /// Success flag: true if object has been fully decoded.
    pub complete: bool,
    /// Optional hint about missing ESIs for targeted repair.
    /// MUST be bounded (max `MAX_MISSING_HINT_ENTRIES` entries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_hint: Option<Vec<u32>>,
    /// Ed25519 signature by the receiving node over the status.
    pub signature: Ed25519Signature,
}

impl DecodeStatus {
    /// Compute the signature transcript bytes (signature excluded).
    #[must_use]
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"FCP2-DECODE-STATUS-V2");
        buf.extend_from_slice(self.object_id.as_bytes());

        let zone_bytes = self.zone_id.as_bytes();
        let zone_len = u32::try_from(zone_bytes.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&zone_len.to_le_bytes());
        buf.extend_from_slice(zone_bytes);

        buf.extend_from_slice(self.zone_key_id.as_bytes());
        buf.extend_from_slice(&self.epoch_id.to_le_bytes());
        let recipient_bytes = self.recipient_node_id.as_str().as_bytes();
        let recipient_len = u32::try_from(recipient_bytes.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&recipient_len.to_le_bytes());
        buf.extend_from_slice(recipient_bytes);
        buf.extend_from_slice(&self.request_nonce.to_le_bytes());
        buf.extend_from_slice(&self.received_unique.to_le_bytes());
        buf.extend_from_slice(&self.needed.to_le_bytes());
        buf.push(u8::from(self.complete));

        // Include missing_hint count and entries if present
        if let Some(ref hints) = self.missing_hint {
            let hint_len = u32::try_from(hints.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&hint_len.to_le_bytes());
            for esi in hints {
                buf.extend_from_slice(&esi.to_le_bytes());
            }
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        buf
    }

    /// Sign the decode status in-place.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) {
        let transcript = self.transcript_bytes();
        self.signature = signing_key.sign(&transcript);
    }

    /// Verify the decode status signature.
    ///
    /// Rejects oversized `missing_hint` payloads *before* allocating the
    /// transcript so an unauthenticated sender cannot force a receiver to
    /// materialize a multi-megabyte transcript on every `verify()`. The hint
    /// cap is already part of the NORMATIVE contract (see the struct-level
    /// "Anti-Amplification Rule") — so a legitimate signer would never emit
    /// a hint above `MAX_MISSING_HINT_ENTRIES`, and there is no interop
    /// fallout from collapsing an over-long hint into
    /// `SignatureVerificationFailed`.
    ///
    /// # Errors
    /// Returns `CryptoError::SignatureVerificationFailed` if the hint is
    /// oversized or the Ed25519 signature does not validate.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        if self.validate_hint_bounds().is_err() {
            return Err(CryptoError::SignatureVerificationFailed);
        }
        let transcript = self.transcript_bytes();
        verifying_key.verify(&transcript, &self.signature)
    }

    /// Validate that `missing_hint` is bounded (`DoS` resistance).
    ///
    /// # Errors
    /// Returns `FrameError::SymbolCountOverflow` if hint exceeds maximum entries.
    pub fn validate_hint_bounds(&self) -> Result<(), FrameError> {
        if let Some(ref hints) = self.missing_hint {
            if hints.len() > MAX_MISSING_HINT_ENTRIES {
                return Err(FrameError::SymbolCountOverflow);
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SymbolAck - Stop Condition (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Symbol acknowledgment for stop condition (NORMATIVE).
///
/// Sent by a receiver to tell the sender to stop transmitting symbols for
/// an object. This is typically sent when the object has been fully
/// reconstructed or when the receiver no longer needs the object.
///
/// # Wire Format
///
/// This is a control-plane object (ephemeral retention) sent via FCPC.
///
/// # Example
///
/// ```rust,ignore
/// use fcp_protocol::fcps::SymbolAck;
///
/// let ack = SymbolAck::new(
///     header,
///     object_id,
///     zone_id,
///     zone_key_id,
///     epoch_id,
///     recipient_node_id,
///     request_nonce,
///     reason,
/// );
/// ack.sign(&signing_key);
/// // Send via FCPC control plane
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolAck {
    /// Object header for context.
    pub header: ObjectHeader,
    /// Content-addressed object ID.
    pub object_id: ObjectId,
    /// Zone for the object.
    pub zone_id: ZoneId,
    /// Zone key ID (for key rotation).
    pub zone_key_id: ZoneKeyId,
    /// Epoch ID for replay protection.
    pub epoch_id: u64,
    /// Intended recipient node for this acknowledgment.
    pub recipient_node_id: TailscaleNodeId,
    /// Nonce unique to the symbol-request exchange this ack belongs to.
    pub request_nonce: u64,
    /// Reason for the acknowledgment.
    pub reason: SymbolAckReason,
    /// Final count of unique symbols received (for metrics).
    pub final_symbol_count: u32,
    /// Ed25519 signature by the receiving node.
    pub signature: Ed25519Signature,
}

/// Reason for symbol acknowledgment (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolAckReason {
    /// Object successfully reconstructed.
    Complete,
    /// Receiver no longer needs the object (cancelled).
    Cancelled,
    /// Receiver detected duplicate/redundant transmission.
    Duplicate,
    /// Receiver's decode budget exceeded.
    BudgetExceeded,
}

impl SymbolAck {
    /// Create a new symbol acknowledgment.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // Wire-message constructor mirrors the signed transcript fields.
    pub fn new(
        header: ObjectHeader,
        object_id: ObjectId,
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        epoch_id: u64,
        recipient_node_id: TailscaleNodeId,
        request_nonce: u64,
        reason: SymbolAckReason,
        final_symbol_count: u32,
    ) -> Self {
        Self {
            header,
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            recipient_node_id,
            request_nonce,
            reason,
            final_symbol_count,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        }
    }

    /// Compute the signature transcript bytes (signature excluded).
    #[must_use]
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"FCP2-SYMBOL-ACK-V2");
        buf.extend_from_slice(self.object_id.as_bytes());

        let zone_bytes = self.zone_id.as_bytes();
        let zone_len = u32::try_from(zone_bytes.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&zone_len.to_le_bytes());
        buf.extend_from_slice(zone_bytes);

        buf.extend_from_slice(self.zone_key_id.as_bytes());
        buf.extend_from_slice(&self.epoch_id.to_le_bytes());
        let recipient_bytes = self.recipient_node_id.as_str().as_bytes();
        let recipient_len = u32::try_from(recipient_bytes.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&recipient_len.to_le_bytes());
        buf.extend_from_slice(recipient_bytes);
        buf.extend_from_slice(&self.request_nonce.to_le_bytes());
        buf.push(self.reason as u8);
        buf.extend_from_slice(&self.final_symbol_count.to_le_bytes());
        buf
    }

    /// Sign the symbol acknowledgment in-place.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) {
        let transcript = self.transcript_bytes();
        self.signature = signing_key.sign(&transcript);
    }

    /// Verify the symbol acknowledgment signature.
    ///
    /// # Errors
    /// Returns `CryptoError` if signature verification fails.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        let transcript = self.transcript_bytes();
        verifying_key.verify(&transcript, &self.signature)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SymbolRequest - Bounded Request (NORMATIVE)
// ─────────────────────────────────────────────────────────────────────────────

/// Default maximum symbols for authenticated requests (NORMATIVE).
pub const DEFAULT_MAX_SYMBOLS_AUTHENTICATED: u32 = 1000;

/// Absolute hard cap on `SymbolRequest::max_symbols`.
///
/// Requests above this value should be rejected at the wire boundary regardless
/// of authentication or zone policy (NORMATIVE; br-7p8rd anti-amplification floor).
///
/// Sized to the `RaptorQ` decode-buffer headroom of one source-symbol plus
/// roughly the repair-tail capacity — see `max_symbols_with_headroom` in
/// fcp-raptorq's decoder. A request asking for more than this many symbols
/// cannot be satisfied by a single legitimate decode budget on the responder
/// side, so accepting one only burns the responder's CPU/Ed25519-verify
/// cycles and amplifies the attacker's payload.
///
/// Pre-fix, `SymbolRequest::new` accepted any caller-supplied `max_symbols`
/// (up to `u32::MAX`) and `verify()` only validated `missing_hint` size. A
/// peer with a valid signing key could mint and sign `max_symbols = u32::MAX`
/// requests; the deeper `validate_request` enforced the per-tier cap, but
/// that's defense in depth, not the primary gate. This cap closes the
/// SignedTranscript-side hole.
pub const MAX_SYMBOLS_HARD_CAP: u32 = 2001;

/// Bounded symbol request (NORMATIVE).
///
/// A requester MUST bound requests with `max_symbols` and/or `missing_hint`.
/// A responder MUST NOT send more than `max_symbols` symbols in response.
///
/// # Anti-Amplification Rule (NORMATIVE)
///
/// Unauthenticated requests MUST be capped tighter (default 32 symbols)
/// unless zone policy allows. Accounting: request processing counts against
/// the requester's `PeerBudget` (bytes + CPU + inflight decodes).
///
/// # Wire Format
///
/// This is a control-plane object sent via FCPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRequest {
    /// Object header for context.
    pub header: ObjectHeader,
    /// Content-addressed object ID being requested.
    pub object_id: ObjectId,
    /// Zone for the object.
    pub zone_id: ZoneId,
    /// Zone key ID (for key rotation).
    pub zone_key_id: ZoneKeyId,
    /// Epoch ID for replay protection.
    pub epoch_id: u64,
    /// Maximum symbols the requester wants (NORMATIVE bound).
    pub max_symbols: u32,
    /// Optional hint about specific ESIs needed (proof-of-need).
    /// MUST be bounded (max `MAX_MISSING_HINT_ENTRIES` entries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_hint: Option<Vec<u32>>,
    /// Current unique symbols the requester already has.
    pub current_symbols: u32,
    /// Ed25519 signature by the requesting node.
    pub signature: Ed25519Signature,
}

impl SymbolRequest {
    /// Create a new symbol request.
    ///
    /// **Note (br-7p8rd):** this constructor remains infallible for backward
    /// compatibility with the existing test/conformance fixtures that
    /// deliberately mint out-of-policy values to exercise rejection paths.
    /// Callers minting requests for **production transmission** should use
    /// [`Self::try_new`] instead, which enforces [`MAX_SYMBOLS_HARD_CAP`] at
    /// construction time and refuses to build a request that the receiver's
    /// `verify()` would reject anyway.
    #[must_use]
    pub fn new(
        header: ObjectHeader,
        object_id: ObjectId,
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        epoch_id: u64,
        max_symbols: u32,
        current_symbols: u32,
    ) -> Self {
        Self {
            header,
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            max_symbols,
            missing_hint: None,
            current_symbols,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        }
    }

    /// Fail-closed constructor that rejects out-of-policy `max_symbols` at
    /// build time (br-7p8rd).
    ///
    /// Use this for any caller minting a request intended to actually go on
    /// the wire — it refuses to build a request that the receiver's
    /// [`Self::verify`] would now reject. Returns
    /// [`FrameError::SymbolCountOverflow`] when `max_symbols` exceeds
    /// [`MAX_SYMBOLS_HARD_CAP`].
    ///
    /// # Errors
    /// Returns `FrameError::SymbolCountOverflow` if `max_symbols >
    /// MAX_SYMBOLS_HARD_CAP`.
    pub fn try_new(
        header: ObjectHeader,
        object_id: ObjectId,
        zone_id: ZoneId,
        zone_key_id: ZoneKeyId,
        epoch_id: u64,
        max_symbols: u32,
        current_symbols: u32,
    ) -> Result<Self, FrameError> {
        if max_symbols > MAX_SYMBOLS_HARD_CAP {
            return Err(FrameError::SymbolCountOverflow);
        }
        Ok(Self::new(
            header,
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            max_symbols,
            current_symbols,
        ))
    }

    /// Create a request with specific missing symbols (targeted repair).
    #[must_use]
    pub fn with_missing_hint(mut self, hint: Vec<u32>) -> Self {
        self.missing_hint = Some(hint);
        self
    }

    /// Compute the signature transcript bytes (signature excluded).
    #[must_use]
    pub fn transcript_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"FCP2-SYMBOL-REQ-V1");
        buf.extend_from_slice(self.object_id.as_bytes());

        let zone_bytes = self.zone_id.as_bytes();
        let zone_len = u32::try_from(zone_bytes.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&zone_len.to_le_bytes());
        buf.extend_from_slice(zone_bytes);

        buf.extend_from_slice(self.zone_key_id.as_bytes());
        buf.extend_from_slice(&self.epoch_id.to_le_bytes());
        buf.extend_from_slice(&self.max_symbols.to_le_bytes());
        buf.extend_from_slice(&self.current_symbols.to_le_bytes());

        // Include missing_hint count and entries if present
        if let Some(ref hints) = self.missing_hint {
            let hint_len = u32::try_from(hints.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&hint_len.to_le_bytes());
            for esi in hints {
                buf.extend_from_slice(&esi.to_le_bytes());
            }
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        buf
    }

    /// Sign the symbol request in-place.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) {
        let transcript = self.transcript_bytes();
        self.signature = signing_key.sign(&transcript);
    }

    /// Verify the symbol request signature.
    ///
    /// Rejects oversized `missing_hint` payloads AND oversized `max_symbols`
    /// (above [`MAX_SYMBOLS_HARD_CAP`]) *before* allocating the transcript so
    /// an attacker holding a valid peer-signing key cannot force a receiver
    /// to materialize a multi-megabyte transcript or burn an Ed25519-verify
    /// cycle on a request that would be rejected by deeper admission control
    /// anyway (br-7p8rd).
    ///
    /// The legitimate upper bound is already declared NORMATIVE via
    /// `validate_bounds`/`validate_hint_bounds` and the per-tier defaults
    /// (`DEFAULT_MAX_SYMBOLS_AUTHENTICATED` = 1000); no honest signer will
    /// ever produce a request above [`MAX_SYMBOLS_HARD_CAP`] = 2001.
    ///
    /// # Errors
    /// Returns `CryptoError::SignatureVerificationFailed` if the hint is
    /// oversized, `max_symbols` exceeds [`MAX_SYMBOLS_HARD_CAP`], or the
    /// Ed25519 signature does not validate.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        if self.validate_hint_bounds().is_err() {
            return Err(CryptoError::SignatureVerificationFailed);
        }
        if self.max_symbols > MAX_SYMBOLS_HARD_CAP {
            return Err(CryptoError::SignatureVerificationFailed);
        }
        let transcript = self.transcript_bytes();
        verifying_key.verify(&transcript, &self.signature)
    }

    /// Validate that `missing_hint` is bounded (`DoS` resistance).
    ///
    /// # Errors
    /// Returns `FrameError::SymbolCountOverflow` if hint exceeds maximum entries.
    pub fn validate_hint_bounds(&self) -> Result<(), FrameError> {
        if let Some(ref hints) = self.missing_hint {
            if hints.len() > MAX_MISSING_HINT_ENTRIES {
                return Err(FrameError::SymbolCountOverflow);
            }
        }
        Ok(())
    }

    /// Validate the request bounds (NORMATIVE).
    ///
    /// # Errors
    /// Returns `FrameError` if bounds are violated.
    pub fn validate_bounds(&self, is_authenticated: bool) -> Result<(), FrameError> {
        self.validate_hint_bounds()?;

        // Unauthenticated requests have stricter limits
        let max_allowed = if is_authenticated {
            DEFAULT_MAX_SYMBOLS_AUTHENTICATED
        } else {
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED
        };

        if self.max_symbols > max_allowed {
            return Err(FrameError::SymbolCountOverflow);
        }

        Ok(())
    }

    /// Check if the request has proof-of-need (`missing_hint` present).
    #[must_use]
    pub const fn has_proof_of_need(&self) -> bool {
        self.missing_hint.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HybridSignedFcpsFrame - Degraded/Bootstrap Mode (NORMATIVE when used)
// ─────────────────────────────────────────────────────────────────────────────

/// Payload carried by a hybrid-signed FCPS frame envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFcpsFramePayload {
    /// Source node ID (Tailscale node identifier).
    pub source_id: TailscaleNodeId,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Encoded FCPS frame bytes.
    pub frame_bytes: Vec<u8>,
}

impl SignedFcpsFramePayload {
    /// Build a hybrid-signable payload from an FCPS frame.
    ///
    /// # Errors
    /// Returns `CryptoError::SerializationError` if source validation or frame
    /// encoding fails.
    pub fn new(
        frame: &FcpsFrame,
        source_id: TailscaleNodeId,
        timestamp: u64,
    ) -> CryptoResult<Self> {
        SignedFcpsFrame::validate_source_id(&source_id).map_err(|err| {
            CryptoError::SerializationError(format!("invalid signed FCPS frame: {err}"))
        })?;
        let frame_bytes = frame.encode().map_err(|err| {
            CryptoError::SerializationError(format!("invalid signed FCPS frame: {err}"))
        })?;
        Ok(Self {
            source_id,
            timestamp,
            frame_bytes,
        })
    }

    /// Build a hybrid-signable payload from a frame and source metadata.
    ///
    /// # Errors
    /// Returns `CryptoError::SerializationError` if source validation or frame
    /// encoding fails.
    pub fn from_frame(
        frame: &FcpsFrame,
        source_id: TailscaleNodeId,
        timestamp: u64,
    ) -> CryptoResult<Self> {
        Self::new(frame, source_id, timestamp)
    }

    /// Decode the embedded FCPS frame.
    ///
    /// # Errors
    /// Returns `CryptoError::SerializationError` if the embedded frame bytes are invalid.
    pub fn decode_frame(&self, max_datagram_bytes: usize) -> CryptoResult<FcpsFrame> {
        FcpsFrame::decode(&self.frame_bytes, max_datagram_bytes).map_err(|err| {
            CryptoError::SerializationError(format!("invalid hybrid signed FCPS frame: {err}"))
        })
    }

    fn transcript_bytes(&self) -> Vec<u8> {
        SignedFcpsFrame::build_transcript(&self.source_id, self.timestamp, &self.frame_bytes)
    }
}

impl HybridSignable for SignedFcpsFramePayload {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::GossipFrame;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        Ok(signing_bytes_for_canonical_payload(
            Self::OBJECT_KIND,
            &self.transcript_bytes(),
        ))
    }
}

/// Hybrid-signed FCPS frame envelope.
pub type HybridSignedFcpsFrame = SignedEnvelope<SignedFcpsFramePayload>;

/// Signed FCPS frame for degraded/bootstrap mode (NORMATIVE when used).
///
/// New degraded/bootstrap call sites must use [`HybridSignedFcpsFrame`]
/// through [`SignedFcpsFrame::new_hybrid`] and
/// [`verify_hybrid_signed_fcps_frame`]. This legacy struct is kept only for
/// historical wire parsing and migration diagnostics.
///
/// The signature covers: `"FCP2-FRAME-SIG-V1" || source_id || timestamp || frame_bytes`
#[derive(Debug, Clone)]
pub struct SignedFcpsFrame {
    /// The FCPS frame.
    pub frame: FcpsFrame,
    /// Source node ID (Tailscale node identifier).
    pub source_id: TailscaleNodeId,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Ed25519 signature over the transcript.
    pub signature: Ed25519Signature,
}

impl SignedFcpsFrame {
    /// Domain separator for frame signatures.
    pub const SIGNATURE_DOMAIN: &'static [u8] = b"FCP2-FRAME-SIG-V1";

    fn validate_source_id(source_id: &TailscaleNodeId) -> Result<(), FrameError> {
        let source_id_len = source_id.as_str().len();
        if source_id_len == 0 {
            // Decode rejects source_id_len == 0 with FrameError::TooShort;
            // mirror that here so new/encode and decode agree — otherwise a
            // SignedFcpsFrame built from an empty source_id encodes
            // successfully but never roundtrips.
            return Err(FrameError::SourceIdEmpty);
        }
        if source_id_len > usize::from(u16::MAX) {
            return Err(FrameError::InvalidSourceIdLength {
                len: source_id_len,
                max: usize::from(u16::MAX),
            });
        }

        Ok(())
    }

    /// Create a legacy Ed25519-only signed frame.
    ///
    /// # Arguments
    ///
    /// * `frame` - The FCPS frame to sign
    /// * `source_id` - The source node's Tailscale ID
    /// * `timestamp` - Unix timestamp in seconds
    /// * `signing_key` - Ed25519 signing key
    /// # Errors
    /// Returns `FrameError` if the frame cannot be encoded (e.g. payload length mismatch).
    #[deprecated(
        since = "0.1.0",
        note = "use SignedFcpsFrame::new_hybrid so degraded/bootstrap FCPS frames carry Ed25519 and ML-DSA signatures"
    )]
    pub fn new(
        frame: FcpsFrame,
        source_id: TailscaleNodeId,
        timestamp: u64,
        signing_key: &Ed25519SigningKey,
    ) -> Result<Self, FrameError> {
        Self::validate_source_id(&source_id)?;
        let frame_bytes = frame.encode()?;
        let transcript = Self::build_transcript(&source_id, timestamp, &frame_bytes);
        let signature = signing_key.sign(&transcript);

        Ok(Self {
            frame,
            source_id,
            timestamp,
            signature,
        })
    }

    /// Create a new hybrid-signed frame envelope.
    ///
    /// # Errors
    /// Returns an error if the frame cannot be encoded, source validation
    /// fails, or either signing algorithm fails.
    pub fn new_hybrid(
        frame: &FcpsFrame,
        source_id: TailscaleNodeId,
        timestamp: u64,
        classical_signer: &Ed25519SigningKey,
        pq_signer: &MlDsa65SigningKey,
    ) -> CryptoResult<HybridSignedFcpsFrame> {
        let payload = SignedFcpsFramePayload::new(frame, source_id, timestamp)?;
        payload.sign_hybrid(classical_signer, pq_signer)
    }

    /// Convert an existing signed frame into its hybrid-signable payload.
    ///
    /// # Errors
    /// Returns an error if the frame cannot be encoded or the source ID is invalid.
    pub fn hybrid_payload(&self) -> CryptoResult<SignedFcpsFramePayload> {
        SignedFcpsFramePayload::new(&self.frame, self.source_id.clone(), self.timestamp)
    }

    /// Build the signature transcript.
    fn build_transcript(
        source_id: &TailscaleNodeId,
        timestamp: u64,
        frame_bytes: &[u8],
    ) -> Vec<u8> {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(Self::SIGNATURE_DOMAIN);

        let source_bytes = source_id.as_str().as_bytes();
        let source_len = u32::try_from(source_bytes.len()).unwrap_or(u32::MAX);
        transcript.extend_from_slice(&source_len.to_le_bytes());
        transcript.extend_from_slice(source_bytes);

        transcript.extend_from_slice(&timestamp.to_le_bytes());

        let frame_len = u32::try_from(frame_bytes.len()).unwrap_or(u32::MAX);
        transcript.extend_from_slice(&frame_len.to_le_bytes());
        transcript.extend_from_slice(frame_bytes);

        transcript
    }

    /// Verify a legacy Ed25519-only frame signature.
    ///
    /// # Errors
    /// Returns `CryptoError` if signature verification fails or the signed
    /// frame has been mutated into an invalid state.
    #[deprecated(
        since = "0.1.0",
        note = "use verify_hybrid_signed_fcps_frame with PqSigningPolicy instead"
    )]
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), CryptoError> {
        Self::validate_source_id(&self.source_id).map_err(|err| {
            CryptoError::SerializationError(format!("invalid signed FCPS frame: {err}"))
        })?;
        let frame_bytes = self.frame.encode().map_err(|err| {
            CryptoError::SerializationError(format!("invalid signed FCPS frame: {err}"))
        })?;
        let transcript = Self::build_transcript(&self.source_id, self.timestamp, &frame_bytes);
        verifying_key.verify(&transcript, &self.signature)
    }

    /// Encode a legacy Ed25519-only signed frame to bytes.
    ///
    /// Wire format:
    /// - `source_id` length (u16 LE)
    /// - `source_id` bytes
    /// - timestamp (u64 LE)
    /// - signature (64 bytes)
    /// - frame bytes
    ///
    /// # Errors
    /// Returns `FrameError` if the signed frame has been mutated into an
    /// invalid state after construction.
    #[deprecated(
        since = "0.1.0",
        note = "hybrid signed FCPS frames use SignedEnvelope serialization"
    )]
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        self.try_encode()
    }

    fn try_encode(&self) -> Result<Vec<u8>, FrameError> {
        let frame_bytes = self.frame.encode()?;
        Self::validate_source_id(&self.source_id)?;
        let source_id_bytes = self.source_id.as_str().as_bytes();

        let mut out = Vec::with_capacity(2 + source_id_bytes.len() + 8 + 64 + frame_bytes.len());

        let source_id_len = u16::try_from(source_id_bytes.len()).expect("validated source_id");
        out.extend_from_slice(&source_id_len.to_le_bytes());
        out.extend_from_slice(source_id_bytes);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(&frame_bytes);

        Ok(out)
    }

    /// Decode a legacy Ed25519-only signed frame from bytes.
    ///
    /// # Errors
    /// Returns `FrameError` if the frame is malformed.
    #[deprecated(
        since = "0.1.0",
        note = "hybrid signed FCPS frames use SignedEnvelope serialization"
    )]
    pub fn decode(bytes: &[u8], max_datagram_bytes: usize) -> Result<Self, FrameError> {
        // Minimum: 2 (source_id_len) + 1 (min source_id) + 8 (timestamp) + 64 (sig) + 114 (min frame)
        const MIN_LEN: usize = 2 + 1 + 8 + 64 + FCPS_HEADER_LEN;

        if bytes.len() > max_datagram_bytes {
            return Err(FrameError::ExceedsMtu {
                len: bytes.len(),
                max: max_datagram_bytes,
            });
        }

        if bytes.len() < MIN_LEN {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: MIN_LEN,
            });
        }

        let source_id_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if source_id_len == 0 || bytes.len() < 2 + source_id_len + 8 + 64 + FCPS_HEADER_LEN {
            return Err(FrameError::TooShort {
                len: bytes.len(),
                min: 2 + source_id_len + 8 + 64 + FCPS_HEADER_LEN,
            });
        }

        let source_id_end = 2 + source_id_len;
        let source_id_str =
            std::str::from_utf8(&bytes[2..source_id_end]).map_err(|_| FrameError::InvalidUtf8)?;
        let source_id = TailscaleNodeId::new(source_id_str);

        let timestamp_start = source_id_end;
        let timestamp_bytes: [u8; 8] = bytes[timestamp_start..timestamp_start + 8]
            .try_into()
            .map_err(|_| FrameError::TooShort {
                len: bytes.len(),
                min: timestamp_start + 8,
            })?;
        let timestamp = u64::from_le_bytes(timestamp_bytes);

        let sig_start = timestamp_start + 8;
        let signature =
            Ed25519Signature::from_bytes(bytes[sig_start..sig_start + 64].try_into().map_err(
                |_| FrameError::TooShort {
                    len: bytes.len(),
                    min: sig_start + 64,
                },
            )?);

        let frame_start = sig_start + 64;
        let frame = FcpsFrame::decode(&bytes[frame_start..], max_datagram_bytes)?;

        Ok(Self {
            frame,
            source_id,
            timestamp,
            signature,
        })
    }
}

/// Verify a hybrid signed FCPS frame and decode the enclosed frame.
///
/// # Errors
/// Returns a crypto error if the envelope fails policy verification or carries
/// invalid frame bytes.
pub fn verify_hybrid_signed_fcps_frame(
    envelope: &HybridSignedFcpsFrame,
    classical_key: &Ed25519VerifyingKey,
    pq_key: &MlDsa65VerifyingKey,
    policy: PqSigningPolicy,
    max_datagram_bytes: usize,
) -> Result<FcpsFrame, CryptoError> {
    verify_signable_with_policy(envelope, policy, Some(classical_key), Some(pq_key))?;
    envelope.payload.decode_frame(max_datagram_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> FcpsFrameHeader {
        FcpsFrameHeader {
            version: FCPS_VERSION,
            flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
            symbol_count: 2,
            total_payload_len: u32::try_from(2 * (SYMBOL_RECORD_OVERHEAD + 64))
                .expect("payload length fits in u32"),
            object_id: ObjectId::from_bytes([0x11; 32]),
            symbol_size: 64,
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            zone_id_hash: ZoneIdHash::from_bytes([0x33; 32]),
            epoch_id: 1000,
            sender_instance_id: 0xDEAD_BEEF,
            frame_seq: 42,
        }
    }

    fn test_symbol(esi: u32, symbol_size: u16) -> SymbolRecord {
        SymbolRecord {
            esi,
            k: 10,
            data: vec![0xAA; symbol_size as usize],
            auth_tag: [0xBB; 16],
        }
    }

    fn test_pq_signing_key() -> MlDsa65SigningKey {
        MlDsa65SigningKey::generate().expect("ML-DSA signing key")
    }

    #[test]
    fn header_encode_decode_round_trip() {
        let header = test_header();
        let encoded = header.encode();
        assert_eq!(encoded.len(), FCPS_HEADER_LEN);

        let decoded = FcpsFrameHeader::decode(&encoded).expect("decode");
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_magic_validation() {
        let mut bad = [0u8; FCPS_HEADER_LEN];
        bad[0..4].copy_from_slice(b"XXXX");
        let err = FcpsFrameHeader::decode(&bad).expect_err("should fail");
        assert!(matches!(err, FrameError::InvalidMagic { .. }));
    }

    #[test]
    fn header_version_validation() {
        let mut header = test_header();
        header.version = 99;
        let mut encoded = header.encode();
        encoded[4..6].copy_from_slice(&99u16.to_le_bytes());
        let err = FcpsFrameHeader::decode(&encoded).expect_err("should fail");
        assert!(matches!(
            err,
            FrameError::UnsupportedVersion { version: 99 }
        ));
    }

    #[test]
    fn header_decode_rejects_unknown_flag_bits() {
        let header = test_header();
        let mut encoded = header.encode();
        encoded[6..8].copy_from_slice(&0x8000_u16.to_le_bytes());

        let err = FcpsFrameHeader::decode(&encoded).expect_err("unknown flags");
        assert!(matches!(err, FrameError::InvalidFlags { .. }));
        assert!(err.to_string().contains("unknown flag bits 0x8000"));
    }

    #[test]
    fn symbol_record_encode_decode() {
        let record = test_symbol(5, 64);
        let encoded = record.encode();
        assert_eq!(encoded.len(), SYMBOL_RECORD_OVERHEAD + 64);

        let decoded = SymbolRecord::decode(&encoded, 64).expect("decode");
        assert_eq!(decoded, record);
    }

    #[test]
    fn frame_encode_decode_round_trip() {
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let encoded = frame.encode().expect("encode");
        let expected_len = FCPS_HEADER_LEN + 2 * (SYMBOL_RECORD_OVERHEAD + 64);
        assert_eq!(encoded.len(), expected_len);

        let decoded = FcpsFrame::decode(&encoded, 2000).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn frame_rejects_mtu_violation() {
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let encoded = frame.encode().expect("encode");

        let err = FcpsFrame::decode(&encoded, 100).expect_err("should fail");
        assert!(matches!(err, FrameError::ExceedsMtu { .. }));
    }

    #[test]
    fn frame_rejects_length_mismatch() {
        let mut header = test_header();
        header.total_payload_len = 999; // Wrong value
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let _frame = FcpsFrame {
            header: header.clone(),
            symbols,
        };

        // Build with correct payload but wrong header
        let mut buf = Vec::new();
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&test_symbol(0, 64).encode());
        buf.extend_from_slice(&test_symbol(1, 64).encode());

        let err = FcpsFrame::decode(&buf, 2000).expect_err("should fail");
        assert!(matches!(err, FrameError::LengthMismatch { .. }));
    }

    #[test]
    fn frame_flags_defaults() {
        let flags = FrameFlags::default();
        assert!(flags.contains(FrameFlags::ENCRYPTED));
        assert!(flags.contains(FrameFlags::RAPTORQ));
        assert!(!flags.contains(FrameFlags::CONTROL_PLANE));
    }

    #[test]
    fn frame_flags_all_bits() {
        let all = FrameFlags::all();
        assert!(all.contains(FrameFlags::REQUIRES_ACK));
        assert!(all.contains(FrameFlags::COMPRESSED));
        assert!(all.contains(FrameFlags::ENCRYPTED));
        assert!(all.contains(FrameFlags::RESPONSE));
        assert!(all.contains(FrameFlags::ERROR));
        assert!(all.contains(FrameFlags::STREAMING));
        assert!(all.contains(FrameFlags::STREAM_END));
        assert!(all.contains(FrameFlags::HAS_CAP_TOKEN));
        assert!(all.contains(FrameFlags::ZONE_CROSSING));
        assert!(all.contains(FrameFlags::PRIORITY));
        assert!(all.contains(FrameFlags::RAPTORQ));
        assert!(all.contains(FrameFlags::CONTROL_PLANE));
    }

    #[test]
    fn validate_frame_rejects_inconsistent_lengths() {
        // Test that mismatched header claims are rejected
        let mut header = test_header();
        header.symbol_count = u32::MAX;
        header.symbol_size = u16::MAX;

        let fake_bytes = [0u8; FCPS_HEADER_LEN];
        let err = validate_frame_lengths(&fake_bytes, &header).expect_err("should fail");
        // May fail with LengthMismatch or SymbolCountOverflow depending on platform
        assert!(
            matches!(err, FrameError::SymbolCountOverflow)
                || matches!(err, FrameError::LengthMismatch { .. })
                || matches!(err, FrameError::FrameSizeMismatch)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HybridSignedFcpsFrame Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn hybrid_signed_frame_sign_and_verify() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let source_id = TailscaleNodeId::new("node-test");
        let timestamp = 1_704_067_200;

        let signed = SignedFcpsFrame::new_hybrid(
            &frame,
            source_id,
            timestamp,
            &signing_key,
            &pq_signing_key,
        )
        .expect("sign");

        let verified = verify_hybrid_signed_fcps_frame(
            &signed,
            &signing_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            2000,
        )
        .expect("verify ok");
        assert_eq!(verified.header, frame.header);
    }

    #[test]
    fn hybrid_signed_frame_rejects_wrong_key() {
        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();

        let header = test_header();
        // Use 2 symbols to match header.symbol_count
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let source_id = TailscaleNodeId::new("node-wrong-key");
        let signed =
            SignedFcpsFrame::new_hybrid(&frame, source_id, 1000, &signing_key, &pq_signing_key)
                .expect("sign");

        let err = verify_hybrid_signed_fcps_frame(
            &signed,
            &wrong_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            2000,
        )
        .expect_err("wrong classical key should fail");
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    #[test]
    fn hybrid_signed_frame_json_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame {
            header: header.clone(),
            symbols,
        };

        let source_id = TailscaleNodeId::new("node-roundtrip");
        let timestamp = 1_704_067_200;

        let signed = SignedFcpsFrame::new_hybrid(
            &frame,
            source_id.clone(),
            timestamp,
            &signing_key,
            &pq_signing_key,
        )
        .expect("sign");
        let encoded = serde_json::to_vec(&signed).expect("encode");

        let decoded: HybridSignedFcpsFrame = serde_json::from_slice(&encoded).expect("decode ok");

        assert_eq!(decoded.payload.source_id.as_str(), source_id.as_str());
        assert_eq!(decoded.payload.timestamp, timestamp);

        let verified = verify_hybrid_signed_fcps_frame(
            &decoded,
            &signing_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            2000,
        )
        .expect("verify after decode");
        assert_eq!(verified.header, header);
        assert_eq!(verified.symbols.len(), 2);
    }

    #[test]
    fn hybrid_signed_frame_rejects_oversized_source_id() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let oversized = "n".repeat(usize::from(u16::MAX) + 1);

        let err = SignedFcpsFrame::new_hybrid(
            &frame,
            TailscaleNodeId::new(oversized),
            1_704_067_200,
            &signing_key,
            &pq_signing_key,
        )
        .expect_err("oversized source_id should fail");

        assert!(matches!(err, CryptoError::SerializationError(_)));
    }

    #[test]
    fn hybrid_signed_frame_new_rejects_empty_source_id() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let err = SignedFcpsFrame::new_hybrid(
            &frame,
            TailscaleNodeId::new(""),
            1_704_067_200,
            &signing_key,
            &pq_signing_key,
        )
        .expect_err("empty source_id must be rejected at new_hybrid()");
        assert!(
            matches!(err, CryptoError::SerializationError(_)),
            "expected serialization error, got {err:?}"
        );
    }

    #[test]
    fn hybrid_signed_frame_verify_rejects_mutated_empty_source_id() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let mut signed = SignedFcpsFrame::new_hybrid(
            &frame,
            TailscaleNodeId::new("node-x"),
            1_704_067_200,
            &signing_key,
            &pq_signing_key,
        )
        .expect("sign");

        // Simulate a mutated envelope that bypassed construction-time
        // validation; verification must fail before processing.
        signed.payload.source_id = TailscaleNodeId::new("");

        verify_hybrid_signed_fcps_frame(
            &signed,
            &signing_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            2000,
        )
        .expect_err("mutated empty source_id must fail verification");
    }

    #[test]
    fn hybrid_signed_frame_verify_rejects_mutated_oversized_source_id() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let mut signed = SignedFcpsFrame::new_hybrid(
            &frame,
            TailscaleNodeId::new("node-mutable"),
            1_704_067_200,
            &signing_key,
            &pq_signing_key,
        )
        .expect("sign");

        signed.payload.source_id = TailscaleNodeId::new("n".repeat(usize::from(u16::MAX) + 1));

        verify_hybrid_signed_fcps_frame(
            &signed,
            &signing_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            2000,
        )
        .expect_err("mutated oversized source_id should fail verification");
    }

    #[test]
    fn hybrid_signed_frame_decode_rejects_short_payload() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let payload = SignedFcpsFramePayload {
            frame_bytes: vec![0u8; 50],
            source_id: TailscaleNodeId::new("node-short"),
            timestamp: 1000,
        };
        let signed = payload
            .sign_hybrid(&signing_key, &pq_signing_key)
            .expect("sign malformed payload");
        let err = verify_hybrid_signed_fcps_frame(
            &signed,
            &signing_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            2000,
        )
        .expect_err("short payload should fail decode after signature verify");
        assert!(matches!(err, CryptoError::SerializationError(_)));
    }

    #[test]
    fn hybrid_signed_frame_verify_rejects_mutated_invalid_frame_without_panic() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let mut signed = SignedFcpsFrame::new_hybrid(
            &frame,
            TailscaleNodeId::new("node-invalid-frame"),
            1_704_067_200,
            &signing_key,
            &pq_signing_key,
        )
        .expect("sign");

        signed.payload.frame_bytes[0] ^= 0xFF;

        verify_hybrid_signed_fcps_frame(
            &signed,
            &signing_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            2000,
        )
        .expect_err("mutated frame should fail verification");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DecodeStatus Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn decode_status_sign_and_verify() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:test".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut status = DecodeStatus {
            header,
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1000,
            recipient_node_id: TailscaleNodeId::new("node-recipient"),
            request_nonce: 11,
            received_unique: 500,
            needed: 1003,
            complete: false,
            missing_hint: Some(vec![10, 20, 30]),
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        status.sign(&signing_key);
        status
            .verify(&signing_key.verifying_key())
            .expect("verify ok");
    }

    #[test]
    fn decode_status_rejects_wrong_key() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:test2".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut status = DecodeStatus {
            header,
            object_id: ObjectId::from_bytes([0x33; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x44; 8]),
            epoch_id: 2000,
            recipient_node_id: TailscaleNodeId::new("node-recipient"),
            request_nonce: 22,
            received_unique: 100,
            needed: 200,
            complete: true,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        status.sign(&signing_key);
        assert!(status.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn decode_status_validates_hint_bounds() {
        let zone_id: ZoneId = "z:bounds".parse().expect("zone parse");
        let status = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 0,
            recipient_node_id: TailscaleNodeId::new("node-recipient"),
            request_nonce: 0,
            received_unique: 0,
            needed: 100,
            complete: false,
            missing_hint: Some(vec![0; MAX_MISSING_HINT_ENTRIES]),
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        assert!(status.validate_hint_bounds().is_ok());
    }

    #[test]
    fn decode_status_hint_bounds_exceeded_alt() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let status = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-recipient"),
            request_nonce: 1,
            received_unique: 50,
            needed: 100,
            complete: false,
            missing_hint: Some(vec![0; MAX_MISSING_HINT_ENTRIES + 1]),
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        assert!(status.validate_hint_bounds().is_err());
    }

    #[test]
    fn decode_status_verify_rejects_oversized_hint_cheaply() {
        // Regression: DecodeStatus::verify() used to build transcript_bytes()
        // (allocating 4 × hint.len() bytes) before signature verification, so
        // a peer could amplify each sent message into O(hint.len()) work on
        // every receiver. verify() now short-circuits over the hint cap.
        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:amplify".parse().expect("zone parse");
        let mut status = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0xAB; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0xCD; 8]),
            epoch_id: 7,
            recipient_node_id: TailscaleNodeId::new("node-recipient"),
            request_nonce: 9,
            received_unique: 0,
            needed: 1,
            complete: false,
            // A legitimate signer would never exceed MAX_MISSING_HINT_ENTRIES;
            // signing one anyway proves verify() rejects it *before* building
            // the multi-entry transcript.
            missing_hint: Some(vec![0; MAX_MISSING_HINT_ENTRIES + 1]),
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        status.sign(&signing_key);

        let err = status
            .verify(&signing_key.verifying_key())
            .expect_err("oversized hint must not verify even with valid signature");
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    #[test]
    fn symbol_request_verify_rejects_oversized_hint_cheaply() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:amplify-req".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let mut request = SymbolRequest {
            header,
            object_id: ObjectId::from_bytes([0xEF; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x77; 8]),
            epoch_id: 3,
            max_symbols: u32::try_from(MAX_MISSING_HINT_ENTRIES + 1).unwrap_or(u32::MAX),
            missing_hint: Some(vec![0; MAX_MISSING_HINT_ENTRIES + 1]),
            current_symbols: 0,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        request.sign(&signing_key);

        let err = request
            .verify(&signing_key.verifying_key())
            .expect_err("oversized hint must not verify even with valid signature");
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    /// br-7p8rd: `verify()` must reject `max_symbols > MAX_SYMBOLS_HARD_CAP`
    /// BEFORE materializing the transcript or burning an Ed25519-verify
    /// cycle, even when the signature is otherwise valid. This closes the
    /// SignedTranscript-side anti-amplification hole the bead identified.
    #[test]
    fn symbol_request_verify_rejects_max_symbols_above_hard_cap() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:hard-cap".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let mut request = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0x33; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x44; 8]),
            7,
            MAX_SYMBOLS_HARD_CAP + 1, // one above the hard cap
            0,
        );
        request.sign(&signing_key);

        let err = request
            .verify(&signing_key.verifying_key())
            .expect_err("max_symbols above hard cap must not verify, even with a valid signature");
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    /// br-7p8rd: `verify()` must accept `max_symbols == MAX_SYMBOLS_HARD_CAP`
    /// (boundary inclusive). The cap is "above which", not "at or above".
    #[test]
    fn symbol_request_verify_accepts_max_symbols_at_hard_cap() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:hard-cap-edge".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let mut request = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0x55; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x66; 8]),
            8,
            MAX_SYMBOLS_HARD_CAP, // exactly at the cap
            0,
        );
        request.sign(&signing_key);
        request
            .verify(&signing_key.verifying_key())
            .expect("max_symbols == hard cap must verify");
    }

    /// br-7p8rd: the fail-closed `try_new` constructor must refuse to build
    /// a request that the receiver's `verify()` would now reject. Pairs with
    /// the verify-side gate so honest callers get an early failure instead
    /// of a deferred wire-time rejection.
    #[test]
    fn symbol_request_try_new_rejects_above_hard_cap() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:try-new-cap".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let err = SymbolRequest::try_new(
            header.clone(),
            ObjectId::from_bytes([0x77; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0x88; 8]),
            9,
            MAX_SYMBOLS_HARD_CAP + 1,
            0,
        )
        .expect_err("try_new must refuse max_symbols above the hard cap");
        assert!(matches!(err, FrameError::SymbolCountOverflow));

        // Boundary-inclusive: at the cap must succeed.
        SymbolRequest::try_new(
            header,
            ObjectId::from_bytes([0x99; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0xAA; 8]),
            10,
            MAX_SYMBOLS_HARD_CAP,
            0,
        )
        .expect("try_new must accept max_symbols at exactly the hard cap");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SymbolAck Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn symbol_ack_sign_and_verify() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:ack-test".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolAck", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut ack = SymbolAck::new(
            header,
            ObjectId::from_bytes([0x11; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            TailscaleNodeId::new("node-recipient"),
            11,
            SymbolAckReason::Complete,
            500,
        );

        ack.sign(&signing_key);
        ack.verify(&signing_key.verifying_key()).expect("verify ok");
    }

    #[test]
    fn symbol_ack_rejects_wrong_key() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:ack-wrong".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolAck", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut ack = SymbolAck::new(
            header,
            ObjectId::from_bytes([0x33; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x44; 8]),
            2000,
            TailscaleNodeId::new("node-recipient"),
            22,
            SymbolAckReason::Cancelled,
            250,
        );

        ack.sign(&signing_key);
        assert!(ack.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn symbol_ack_reason_variants() {
        // Ensure all reason variants map to distinct u8 values
        assert_ne!(
            SymbolAckReason::Complete as u8,
            SymbolAckReason::Cancelled as u8
        );
        assert_ne!(
            SymbolAckReason::Complete as u8,
            SymbolAckReason::Duplicate as u8
        );
        assert_ne!(
            SymbolAckReason::Complete as u8,
            SymbolAckReason::BudgetExceeded as u8
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SymbolRequest Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn symbol_request_sign_and_verify() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:req-test".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut request = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0x11; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            1000,
            100, // max_symbols
            50,  // current_symbols
        );

        request.sign(&signing_key);
        request
            .verify(&signing_key.verifying_key())
            .expect("verify ok");
    }

    #[test]
    fn symbol_request_with_missing_hint() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:req-hint".parse().expect("zone parse");

        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut request = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0x55; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x66; 8]),
            3000,
            50,
            25,
        )
        .with_missing_hint(vec![10, 20, 30, 40, 50]);

        assert!(request.has_proof_of_need());
        request.validate_hint_bounds().expect("within bounds");

        request.sign(&signing_key);
        request
            .verify(&signing_key.verifying_key())
            .expect("verify ok");
    }

    #[test]
    fn symbol_request_validates_hint_bounds() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:req-bounds".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        // Valid: exactly at limit
        let request_ok = SymbolRequest::new(
            header.clone(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            0,
            32,
            0,
        )
        .with_missing_hint(vec![0; MAX_MISSING_HINT_ENTRIES]);
        request_ok.validate_hint_bounds().expect("at limit ok");

        // Invalid: exceeds hint limit
        let request_bad = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            32,
            0,
        )
        .with_missing_hint(vec![0; MAX_MISSING_HINT_ENTRIES + 1]);
        assert!(request_bad.validate_hint_bounds().is_err());
    }

    #[test]
    fn symbol_request_validates_max_symbols_unauthenticated() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:req-unauth".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        // Valid for unauthenticated: at default limit
        let request_ok = SymbolRequest::new(
            header.clone(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            0,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED,
            0,
        );
        request_ok
            .validate_bounds(false)
            .expect("unauth at limit ok");

        // Invalid for unauthenticated: exceeds limit
        let request_bad = SymbolRequest::new(
            header.clone(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            0,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1,
            0,
        );
        assert!(request_bad.validate_bounds(false).is_err());

        // Valid for authenticated: higher limit allowed
        let request_auth = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            DEFAULT_MAX_SYMBOLS_AUTHENTICATED,
            0,
        );
        request_auth
            .validate_bounds(true)
            .expect("auth at limit ok");
    }

    #[test]
    fn symbol_request_proof_of_need_detection() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:req-pon".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        // No hint = no proof of need
        let request_no_hint = SymbolRequest::new(
            header.clone(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            0,
            32,
            0,
        );
        assert!(!request_no_hint.has_proof_of_need());

        // With hint = has proof of need
        let request_with_hint = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            32,
            0,
        )
        .with_missing_hint(vec![1, 2, 3]);
        assert!(request_with_hint.has_proof_of_need());
    }

    // ── Batch 2: SunnyMoose test expansion ──

    #[test]
    fn header_decode_too_short() {
        let short = [0u8; 50];
        let err = FcpsFrameHeader::decode(&short).expect_err("too short");
        assert!(matches!(err, FrameError::TooShort { len: 50, min: 114 }));
    }

    #[test]
    fn header_encode_exact_size() {
        let header = test_header();
        let encoded = header.encode();
        assert_eq!(encoded.len(), FCPS_HEADER_LEN);
        assert_eq!(FCPS_HEADER_LEN, 114);
    }

    #[test]
    fn symbol_record_wire_size_matches_overhead_plus_data() {
        let record = test_symbol(0, 128);
        assert_eq!(record.wire_size(), SYMBOL_RECORD_OVERHEAD + 128);
        assert_eq!(SYMBOL_RECORD_OVERHEAD, 22);
    }

    #[test]
    fn symbol_record_decode_too_short() {
        let short = [0u8; 10];
        let err = SymbolRecord::decode(&short, 64).expect_err("too short");
        assert!(matches!(err, FrameError::TooShort { .. }));
    }

    #[test]
    fn frame_zero_symbols() {
        let header = FcpsFrameHeader {
            version: FCPS_VERSION,
            flags: FrameFlags::default(),
            symbol_count: 0,
            total_payload_len: 0,
            object_id: ObjectId::from_bytes([0x11; 32]),
            symbol_size: 64,
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            zone_id_hash: ZoneIdHash::from_bytes([0x33; 32]),
            epoch_id: 1,
            sender_instance_id: 1,
            frame_seq: 1,
        };
        let frame = FcpsFrame {
            header,
            symbols: vec![],
        };
        let encoded = frame.encode().expect("encode");
        assert_eq!(encoded.len(), FCPS_HEADER_LEN);
        let decoded = FcpsFrame::decode(&encoded, 2000).expect("decode");
        assert_eq!(decoded.symbols.len(), 0);
    }

    #[test]
    fn frame_single_symbol() {
        let header = FcpsFrameHeader {
            version: FCPS_VERSION,
            flags: FrameFlags::default(),
            symbol_count: 1,
            total_payload_len: u32::try_from(SYMBOL_RECORD_OVERHEAD + 64).expect("payload fits"),
            object_id: ObjectId::from_bytes([0x11; 32]),
            symbol_size: 64,
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            zone_id_hash: ZoneIdHash::from_bytes([0x33; 32]),
            epoch_id: 1,
            sender_instance_id: 1,
            frame_seq: 1,
        };
        let frame = FcpsFrame {
            header,
            symbols: vec![test_symbol(0, 64)],
        };
        let encoded = frame.encode().expect("encode");
        let decoded = FcpsFrame::decode(&encoded, 2000).expect("decode");
        assert_eq!(decoded.symbols.len(), 1);
        assert_eq!(decoded.symbols[0].esi, 0);
    }

    #[test]
    fn frame_flags_individual_bits() {
        let cases = [
            (FrameFlags::REQUIRES_ACK, 0b0000_0000_0001),
            (FrameFlags::COMPRESSED, 0b0000_0000_0010),
            (FrameFlags::ENCRYPTED, 0b0000_0000_0100),
            (FrameFlags::RESPONSE, 0b0000_0000_1000),
            (FrameFlags::ERROR, 0b0000_0001_0000),
            (FrameFlags::STREAMING, 0b0000_0010_0000),
            (FrameFlags::STREAM_END, 0b0000_0100_0000),
            (FrameFlags::HAS_CAP_TOKEN, 0b0000_1000_0000),
            (FrameFlags::ZONE_CROSSING, 0b0001_0000_0000),
            (FrameFlags::PRIORITY, 0b0010_0000_0000),
            (FrameFlags::RAPTORQ, 0b0100_0000_0000),
            (FrameFlags::CONTROL_PLANE, 0b1000_0000_0000),
        ];
        for (flag, expected_bits) in cases {
            assert_eq!(flag.bits(), expected_bits, "flag {flag:?}");
        }
    }

    #[test]
    fn frame_flags_streaming_combinations() {
        // STREAMING without STREAM_END = mid-stream
        let mid = FrameFlags::STREAMING;
        assert!(mid.contains(FrameFlags::STREAMING));
        assert!(!mid.contains(FrameFlags::STREAM_END));
        // STREAMING | STREAM_END = final frame
        let fin = FrameFlags::STREAMING | FrameFlags::STREAM_END;
        assert!(fin.contains(FrameFlags::STREAMING));
        assert!(fin.contains(FrameFlags::STREAM_END));
    }

    #[test]
    fn header_rejects_zero_symbol_size() {
        let mut header = test_header();
        header.symbol_size = 0;
        let mut encoded = header.encode();
        // Overwrite symbol_size bytes at offset 48-49 with 0
        encoded[48..50].copy_from_slice(&0u16.to_le_bytes());
        let err = FcpsFrameHeader::decode(&encoded).expect_err("zero symbol size");
        assert!(matches!(err, FrameError::InvalidSymbolSize));
    }

    #[test]
    fn validate_frame_lengths_correct_frame() {
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let encoded = frame.encode().expect("encode");
        validate_frame_lengths(&encoded, &frame.header).expect("valid");
    }

    #[test]
    fn validate_frame_lengths_wrong_symbol_count() {
        let mut header = test_header();
        header.symbol_count = 99; // Claim 99 symbols but only have 2
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame {
            header: test_header(),
            symbols,
        };
        let encoded = frame.encode().expect("encode");
        let err = validate_frame_lengths(&encoded, &header).expect_err("mismatch");
        assert!(matches!(err, FrameError::LengthMismatch { .. }));
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            FrameError::TooShort { len: 5, min: 114 }.to_string(),
            "frame too short (len 5, min 114)"
        );
        assert_eq!(
            FrameError::ExceedsMtu {
                len: 2000,
                max: 1200
            }
            .to_string(),
            "frame exceeds MTU (len 2000, max 1200)"
        );
        assert_eq!(
            FrameError::InvalidMagic {
                got: [0x58, 0x58, 0x58, 0x58]
            }
            .to_string(),
            "invalid magic bytes (expected FCPS, got [88, 88, 88, 88])"
        );
        assert_eq!(
            FrameError::UnsupportedVersion { version: 42 }.to_string(),
            "unsupported version 42"
        );
        assert_eq!(
            FrameError::SymbolCountOverflow.to_string(),
            "symbol count overflow"
        );
        assert_eq!(
            FrameError::InvalidSymbolSize.to_string(),
            "invalid symbol size (must be > 0)"
        );
        assert_eq!(
            FrameError::FrameSizeMismatch.to_string(),
            "frame size mismatch (header + payload != frame len)"
        );
    }

    #[test]
    fn decode_status_transcript_deterministic() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:det-test".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let status = DecodeStatus {
            header,
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1000,
            recipient_node_id: TailscaleNodeId::new("node-det"),
            request_nonce: 1,
            received_unique: 50,
            needed: 100,
            complete: false,
            missing_hint: Some(vec![1, 2, 3]),
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        let a = status.transcript_bytes();
        let b = status.transcript_bytes();
        assert_eq!(a, b);
        assert!(a.starts_with(b"FCP2-DECODE-STATUS-V2"));
    }

    #[test]
    fn decode_status_no_hint_transcript_differs() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:no-hint".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "TestObject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let with_hint = DecodeStatus {
            header: header.clone(),
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-det"),
            request_nonce: 2,
            received_unique: 10,
            needed: 20,
            complete: false,
            missing_hint: Some(vec![5]),
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        let without_hint = DecodeStatus {
            header,
            object_id: ObjectId::from_bytes([0x11; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-det"),
            request_nonce: 2,
            received_unique: 10,
            needed: 20,
            complete: false,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        assert_ne!(
            with_hint.transcript_bytes(),
            without_hint.transcript_bytes()
        );
    }

    #[test]
    fn symbol_ack_all_reasons() {
        let reasons = [
            SymbolAckReason::Complete,
            SymbolAckReason::Cancelled,
            SymbolAckReason::Duplicate,
            SymbolAckReason::BudgetExceeded,
        ];
        let mut seen = std::collections::HashSet::new();
        for reason in reasons {
            assert!(seen.insert(reason as u8), "duplicate u8 for {reason:?}");
        }
    }

    #[test]
    fn symbol_ack_reason_serde_roundtrip() {
        let reasons = [
            SymbolAckReason::Complete,
            SymbolAckReason::Cancelled,
            SymbolAckReason::Duplicate,
            SymbolAckReason::BudgetExceeded,
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).expect("serialize");
            let back: SymbolAckReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, reason);
        }
    }

    #[test]
    fn symbol_request_validate_bounds_authenticated_exceeds() {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;

        let zone_id: ZoneId = "z:auth-exceed".parse().expect("zone parse");
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.protocol", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let request = SymbolRequest::new(
            header,
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            DEFAULT_MAX_SYMBOLS_AUTHENTICATED + 1,
            0,
        );
        assert!(request.validate_bounds(true).is_err());
    }

    #[test]
    fn hybrid_signed_frame_tampered_frame_fails_verify() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let source_id = TailscaleNodeId::new("node-tamper");
        let mut signed =
            SignedFcpsFrame::new_hybrid(&frame, source_id, 1000, &signing_key, &pq_signing_key)
                .expect("sign");
        signed.payload.frame_bytes[FCPS_HEADER_LEN] ^= 0xFF;
        assert!(
            verify_hybrid_signed_fcps_frame(
                &signed,
                &signing_key.verifying_key(),
                pq_signing_key.verifying_key(),
                PqSigningPolicy::BothRequired,
                2000,
            )
            .is_err()
        );
    }

    #[test]
    fn hybrid_signed_frame_tampered_timestamp_fails_verify() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let source_id = TailscaleNodeId::new("node-ts");
        let mut signed =
            SignedFcpsFrame::new_hybrid(&frame, source_id, 1000, &signing_key, &pq_signing_key)
                .expect("sign");
        signed.payload.timestamp += 1;
        assert!(
            verify_hybrid_signed_fcps_frame(
                &signed,
                &signing_key.verifying_key(),
                pq_signing_key.verifying_key(),
                PqSigningPolicy::BothRequired,
                2000,
            )
            .is_err()
        );
    }

    #[test]
    fn hybrid_signed_frame_tampered_source_id_fails_verify() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };

        let source_id = TailscaleNodeId::new("node-original");
        let mut signed =
            SignedFcpsFrame::new_hybrid(&frame, source_id, 1000, &signing_key, &pq_signing_key)
                .expect("sign");
        signed.payload.source_id = TailscaleNodeId::new("node-spoofed");
        assert!(
            verify_hybrid_signed_fcps_frame(
                &signed,
                &signing_key.verifying_key(),
                pq_signing_key.verifying_key(),
                PqSigningPolicy::BothRequired,
                2000,
            )
            .is_err()
        );
    }

    // ── FrameError display ─────────────────────────────────────────────

    #[test]
    fn frame_error_symbol_count_overflow_display() {
        let err = FrameError::SymbolCountOverflow;
        assert_eq!(err.to_string(), "symbol count overflow");
    }

    #[test]
    fn frame_error_invalid_symbol_size_display() {
        let err = FrameError::InvalidSymbolSize;
        assert_eq!(err.to_string(), "invalid symbol size (must be > 0)");
    }

    #[test]
    fn frame_error_invalid_utf8_display() {
        let err = FrameError::InvalidUtf8;
        assert_eq!(err.to_string(), "invalid utf-8 string");
    }

    #[test]
    fn frame_error_too_short_display() {
        let err = FrameError::TooShort { len: 10, min: 114 };
        assert!(err.to_string().contains("10"));
        assert!(err.to_string().contains("114"));
    }

    #[test]
    fn frame_error_exceeds_mtu_display() {
        let err = FrameError::ExceedsMtu {
            len: 2000,
            max: 1200,
        };
        assert!(err.to_string().contains("2000"));
        assert!(err.to_string().contains("1200"));
    }

    #[test]
    fn frame_error_invalid_magic_display() {
        let err = FrameError::InvalidMagic { got: [0, 0, 0, 0] };
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn frame_error_unsupported_version_display() {
        let err = FrameError::UnsupportedVersion { version: 99 };
        assert!(err.to_string().contains("99"));
    }

    #[test]
    fn frame_error_length_mismatch_display() {
        let err = FrameError::LengthMismatch {
            claimed: 100,
            computed: 200,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("200"));
    }

    #[test]
    fn frame_error_frame_size_mismatch_display() {
        let err = FrameError::FrameSizeMismatch;
        assert!(err.to_string().contains("mismatch"));
    }

    // ── SymbolAckReason serde names ───────────────────────────────────

    #[test]
    fn symbol_ack_reason_serialization_names() {
        assert_eq!(
            serde_json::to_string(&SymbolAckReason::Complete).unwrap(),
            "\"complete\""
        );
        assert_eq!(
            serde_json::to_string(&SymbolAckReason::Cancelled).unwrap(),
            "\"cancelled\""
        );
        assert_eq!(
            serde_json::to_string(&SymbolAckReason::Duplicate).unwrap(),
            "\"duplicate\""
        );
        assert_eq!(
            serde_json::to_string(&SymbolAckReason::BudgetExceeded).unwrap(),
            "\"budget_exceeded\""
        );
    }

    // ── FrameFlags defaults and operations ─────────────────────────────

    #[test]
    fn frame_flags_default() {
        let flags = FrameFlags::default();
        assert!(flags.contains(FrameFlags::ENCRYPTED));
        assert!(flags.contains(FrameFlags::RAPTORQ));
        assert!(!flags.contains(FrameFlags::COMPRESSED));
    }

    #[test]
    fn frame_flags_empty() {
        let flags = FrameFlags::empty();
        assert!(flags.is_empty());
    }

    #[test]
    fn frame_flags_combination() {
        let flags = FrameFlags::ENCRYPTED | FrameFlags::COMPRESSED | FrameFlags::STREAMING;
        assert!(flags.contains(FrameFlags::ENCRYPTED));
        assert!(flags.contains(FrameFlags::COMPRESSED));
        assert!(flags.contains(FrameFlags::STREAMING));
        assert!(!flags.contains(FrameFlags::PRIORITY));
    }

    // ── SymbolRecord encode/decode roundtrip ───────────────────────────

    #[test]
    fn symbol_record_encode_decode_roundtrip() {
        let record = SymbolRecord {
            esi: 42,
            k: 100,
            data: vec![0xAB; 64],
            auth_tag: [0xCC; 16],
        };
        let encoded = record.encode();
        let decoded = SymbolRecord::decode(&encoded, 64).unwrap();
        assert_eq!(decoded.esi, 42);
        assert_eq!(decoded.k, 100);
        assert_eq!(decoded.data, vec![0xAB; 64]);
        assert_eq!(decoded.auth_tag, [0xCC; 16]);
    }

    #[test]
    fn symbol_record_wire_size() {
        let record = SymbolRecord {
            esi: 0,
            k: 0,
            data: vec![0; 64],
            auth_tag: [0; 16],
        };
        assert_eq!(record.wire_size(), SYMBOL_RECORD_OVERHEAD + 64);
    }

    // ── DecodeStatus edge cases ────────────────────────────────────────

    fn make_test_object_header() -> ObjectHeader {
        use fcp_cbor::SchemaId;
        use fcp_prelude::Provenance;
        use semver::Version;
        let zone_id: ZoneId = "z:test".parse().unwrap();
        ObjectHeader {
            schema: SchemaId::new("fcp.test", "Testobject", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 1_704_067_200,
            provenance: Provenance::new(zone_id),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    #[test]
    fn decode_status_sign_and_verify_with_helper() {
        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let mut status = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-helper"),
            request_nonce: 1,
            received_unique: 100,
            needed: 100,
            complete: true,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        status.sign(&signing_key);
        assert!(status.verify(&signing_key.verifying_key()).is_ok());
    }

    #[test]
    fn decode_status_hint_bounds_at_max_ok() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let status = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-helper"),
            request_nonce: 1,
            received_unique: 50,
            needed: 100,
            complete: false,
            missing_hint: Some(vec![0; MAX_MISSING_HINT_ENTRIES]),
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        assert!(status.validate_hint_bounds().is_ok());
    }

    #[test]
    fn decode_status_hint_bounds_exceeded() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let status = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-helper"),
            request_nonce: 1,
            received_unique: 50,
            needed: 100,
            complete: false,
            missing_hint: Some(vec![0; MAX_MISSING_HINT_ENTRIES + 1]),
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        assert!(status.validate_hint_bounds().is_err());
    }

    // ── SymbolRequest builder ──────────────────────────────────────────

    #[test]
    fn symbol_request_builder_with_hint() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let request = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            100,
            50,
        )
        .with_missing_hint(vec![1, 2, 3]);
        assert_eq!(request.missing_hint, Some(vec![1, 2, 3]));
    }

    // ── Constants ──────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(FCPS_MAGIC, [0x46, 0x43, 0x50, 0x53]);
        assert_eq!(FCPS_VERSION, 1);
        assert_eq!(FCPS_HEADER_LEN, 114);
        assert_eq!(DEFAULT_SYMBOL_SIZE, 1024);
        assert_eq!(SYMBOL_RECORD_OVERHEAD, 22);
        assert_eq!(MAX_MISSING_HINT_ENTRIES, 100);
        assert_eq!(DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED, 32);
        assert_eq!(DEFAULT_MAX_SYMBOLS_AUTHENTICATED, 1000);
    }

    // ── Batch 3: SunnyMoose deep-coverage expansion ──

    #[test]
    fn magic_is_fcps_ascii() {
        assert_eq!(&FCPS_MAGIC, b"FCPS");
    }

    #[test]
    fn unknown_flag_bits_truncated() {
        let flags = FrameFlags::from_bits_truncate(0xFFFF);
        // Only the 12 defined bits survive
        assert_eq!(flags.bits(), 0b1111_1111_1111);
        assert_eq!(flags, FrameFlags::all());
    }

    #[test]
    fn header_decode_ignores_trailing_bytes() {
        let header = test_header();
        let encoded = header.encode();
        let mut extended = encoded.to_vec();
        extended.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let decoded = FcpsFrameHeader::decode(&extended).expect("trailing ok");
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_preserves_all_fields() {
        let header = FcpsFrameHeader {
            version: FCPS_VERSION,
            flags: FrameFlags::ENCRYPTED | FrameFlags::PRIORITY | FrameFlags::ZONE_CROSSING,
            symbol_count: 42,
            total_payload_len: 99999,
            object_id: ObjectId::from_bytes([0xAB; 32]),
            symbol_size: 2048,
            zone_key_id: ZoneKeyId::from_bytes([0xCD; 8]),
            zone_id_hash: ZoneIdHash::from_bytes([0xEF; 32]),
            epoch_id: 0xDEAD_BEEF_CAFE_1234,
            sender_instance_id: 0x1234_5678_9ABC_DEF0,
            frame_seq: u64::MAX,
        };
        let decoded = FcpsFrameHeader::decode(&header.encode()).expect("decode");
        assert_eq!(decoded.version, FCPS_VERSION);
        assert!(decoded.flags.contains(FrameFlags::ENCRYPTED));
        assert!(decoded.flags.contains(FrameFlags::PRIORITY));
        assert!(decoded.flags.contains(FrameFlags::ZONE_CROSSING));
        assert_eq!(decoded.symbol_count, 42);
        assert_eq!(decoded.total_payload_len, 99999);
        assert_eq!(decoded.symbol_size, 2048);
        assert_eq!(decoded.epoch_id, 0xDEAD_BEEF_CAFE_1234);
        assert_eq!(decoded.sender_instance_id, 0x1234_5678_9ABC_DEF0);
        assert_eq!(decoded.frame_seq, u64::MAX);
    }

    #[test]
    fn frame_clone_eq() {
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let cloned = frame.clone();
        assert_eq!(frame, cloned);
    }

    #[test]
    fn frame_many_symbols() {
        let symbol_count = 10;
        let header = FcpsFrameHeader {
            version: FCPS_VERSION,
            flags: FrameFlags::default(),
            symbol_count,
            total_payload_len: u32::try_from(
                (symbol_count as usize) * (SYMBOL_RECORD_OVERHEAD + 64),
            )
            .unwrap(),
            object_id: ObjectId::from_bytes([0x11; 32]),
            symbol_size: 64,
            zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
            zone_id_hash: ZoneIdHash::from_bytes([0x33; 32]),
            epoch_id: 1,
            sender_instance_id: 1,
            frame_seq: 1,
        };
        let symbols: Vec<_> = (0..symbol_count).map(|i| test_symbol(i, 64)).collect();
        let frame = FcpsFrame { header, symbols };
        let encoded = frame.encode().expect("encode");
        let decoded = FcpsFrame::decode(&encoded, 10000).expect("decode");
        assert_eq!(decoded.symbols.len(), 10);
        for (i, sym) in decoded.symbols.iter().enumerate() {
            assert_eq!(sym.esi, u32::try_from(i).expect("symbol index fits in u32"));
        }
    }

    #[test]
    fn frame_decode_empty_input() {
        let err = FcpsFrame::decode(&[], 2000).expect_err("empty");
        assert!(matches!(err, FrameError::TooShort { len: 0, .. }));
    }

    #[test]
    fn symbol_record_max_esi_and_k() {
        let record = SymbolRecord {
            esi: u32::MAX,
            k: u16::MAX,
            data: vec![0xFF; 32],
            auth_tag: [0xAA; 16],
        };
        let encoded = record.encode();
        let decoded = SymbolRecord::decode(&encoded, 32).expect("decode");
        assert_eq!(decoded.esi, u32::MAX);
        assert_eq!(decoded.k, u16::MAX);
    }

    #[test]
    fn symbol_ack_transcript_starts_with_domain() {
        let zone_id: ZoneId = "z:dom-test".parse().unwrap();
        let ack = SymbolAck::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            1,
            TailscaleNodeId::new("node-ack"),
            1,
            SymbolAckReason::Complete,
            100,
        );
        let transcript = ack.transcript_bytes();
        assert!(transcript.starts_with(b"FCP2-SYMBOL-ACK-V2"));
    }

    #[test]
    fn symbol_ack_transcript_deterministic() {
        let zone_id: ZoneId = "z:det".parse().unwrap();
        let ack = SymbolAck::new(
            make_test_object_header(),
            ObjectId::from_bytes([0x11; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x22; 8]),
            42,
            TailscaleNodeId::new("node-ack"),
            42,
            SymbolAckReason::Cancelled,
            200,
        );
        assert_eq!(ack.transcript_bytes(), ack.transcript_bytes());
    }

    #[test]
    fn symbol_request_transcript_starts_with_domain() {
        let zone_id: ZoneId = "z:req-dom".parse().unwrap();
        let request = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            1,
            10,
            5,
        );
        let transcript = request.transcript_bytes();
        assert!(transcript.starts_with(b"FCP2-SYMBOL-REQ-V1"));
    }

    #[test]
    fn symbol_request_transcript_with_and_without_hint_differ() {
        let zone_id: ZoneId = "z:req-diff".parse().unwrap();
        let no_hint = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            1,
            10,
            5,
        );
        let with_hint = no_hint.clone().with_missing_hint(vec![1, 2, 3]);
        assert_ne!(no_hint.transcript_bytes(), with_hint.transcript_bytes());
    }

    #[test]
    fn symbol_request_rejects_wrong_key() {
        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:req-wk".parse().unwrap();
        let mut request = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            1,
            10,
            0,
        );
        request.sign(&signing_key);
        assert!(request.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn symbol_ack_reason_debug_coverage() {
        let reasons = [
            SymbolAckReason::Complete,
            SymbolAckReason::Cancelled,
            SymbolAckReason::Duplicate,
            SymbolAckReason::BudgetExceeded,
        ];
        for reason in reasons {
            let dbg = format!("{reason:?}");
            assert_ne!(dbg, "");
        }
    }

    #[test]
    fn legacy_signed_frame_signature_domain_constant() {
        assert_eq!(SignedFcpsFrame::SIGNATURE_DOMAIN, b"FCP2-FRAME-SIG-V1");
    }

    #[test]
    fn frame_flags_hash_in_hashset() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FrameFlags::ENCRYPTED);
        set.insert(FrameFlags::RAPTORQ);
        set.insert(FrameFlags::ENCRYPTED); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn validate_frame_lengths_frame_size_mismatch() {
        // Header claims correct symbol_count and total_payload_len,
        // but actual bytes don't match expected total
        let header = test_header(); // 2 symbols, 64 bytes each
        // Provide a buffer that's too short (just the header)
        let just_header = header.encode();
        let err = validate_frame_lengths(&just_header, &header).expect_err("size mismatch");
        assert!(matches!(err, FrameError::FrameSizeMismatch));
    }

    #[test]
    fn decode_status_none_hint_passes_bounds() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let status = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 0,
            recipient_node_id: TailscaleNodeId::new("node-none"),
            request_nonce: 0,
            received_unique: 0,
            needed: 0,
            complete: true,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        status.validate_hint_bounds().expect("none hint ok");
    }

    #[test]
    fn symbol_request_no_hint_passes_bounds() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let request = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            10,
            0,
        );
        request.validate_hint_bounds().expect("no hint ok");
        request.validate_bounds(true).expect("authenticated ok");
    }

    // ── Batch 4: SunnyMoose deep-coverage expansion ──

    #[test]
    fn header_encode_decode_preserves_object_id() {
        let header = FcpsFrameHeader {
            version: FCPS_VERSION,
            flags: FrameFlags::default(),
            symbol_count: 0,
            total_payload_len: 0,
            object_id: ObjectId::from_bytes([0xAB; 32]),
            symbol_size: 128,
            zone_key_id: ZoneKeyId::from_bytes([0xCD; 8]),
            zone_id_hash: ZoneIdHash::from_bytes([0xEF; 32]),
            epoch_id: 0xDEAD_BEEF,
            sender_instance_id: 0xCAFE_BABE,
            frame_seq: 42,
        };
        let decoded = FcpsFrameHeader::decode(&header.encode()).expect("decode");
        assert_eq!(decoded.object_id, header.object_id);
        assert_eq!(decoded.zone_key_id, header.zone_key_id);
        assert_eq!(decoded.zone_id_hash, header.zone_id_hash);
    }

    #[test]
    fn frame_encode_decode_with_different_symbol_sizes() {
        for sym_size in [16u16, 32, 128, 256, 512, 1024] {
            let record_overhead = SYMBOL_RECORD_OVERHEAD + sym_size as usize;
            let header = FcpsFrameHeader {
                version: FCPS_VERSION,
                flags: FrameFlags::default(),
                symbol_count: 1,
                total_payload_len: u32::try_from(record_overhead).unwrap(),
                object_id: ObjectId::from_bytes([0x11; 32]),
                symbol_size: sym_size,
                zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
                zone_id_hash: ZoneIdHash::from_bytes([0x33; 32]),
                epoch_id: 1,
                sender_instance_id: 1,
                frame_seq: 1,
            };
            let symbols = vec![test_symbol(0, sym_size)];
            let frame = FcpsFrame { header, symbols };
            let encoded = frame.encode().expect("encode");
            let decoded = FcpsFrame::decode(&encoded, 100_000).expect("decode");
            assert_eq!(decoded.symbols.len(), 1);
            assert_eq!(decoded.symbols[0].data.len(), sym_size as usize);
        }
    }

    #[test]
    fn symbol_record_esi_zero_roundtrip() {
        let record = SymbolRecord {
            esi: 0,
            k: 0,
            data: vec![0; 8],
            auth_tag: [0; 16],
        };
        let encoded = record.encode();
        let decoded = SymbolRecord::decode(&encoded, 8).expect("decode");
        assert_eq!(decoded.esi, 0);
        assert_eq!(decoded.k, 0);
    }

    #[test]
    fn symbol_record_clone_eq() {
        let record = test_symbol(42, 64);
        let cloned = record.clone();
        assert_eq!(record, cloned);
    }

    #[test]
    fn frame_flags_debug_format() {
        let flags = FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ;
        let dbg = format!("{flags:?}");
        assert!(dbg.contains("ENCRYPTED"));
        assert!(dbg.contains("RAPTORQ"));
    }

    #[test]
    fn frame_header_debug_format() {
        let header = test_header();
        let dbg = format!("{header:?}");
        assert!(dbg.contains("FcpsFrameHeader"));
    }

    #[test]
    fn symbol_record_debug_format() {
        let record = test_symbol(5, 64);
        let dbg = format!("{record:?}");
        assert!(dbg.contains("SymbolRecord"));
    }

    #[test]
    fn frame_debug_format() {
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let dbg = format!("{frame:?}");
        assert!(dbg.contains("FcpsFrame"));
    }

    #[test]
    fn hybrid_signed_frame_debug_format() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let signed = SignedFcpsFrame::new_hybrid(
            &frame,
            TailscaleNodeId::new("dbg-node"),
            1000,
            &signing_key,
            &pq_signing_key,
        )
        .expect("sign");
        let dbg = format!("{signed:?}");
        assert!(dbg.contains("SignedEnvelope"));
    }

    #[test]
    fn decode_status_complete_flag_in_transcript() {
        let zone_id: ZoneId = "z:comp".parse().unwrap();
        let status_true = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-comp"),
            request_nonce: 1,
            received_unique: 10,
            needed: 10,
            complete: true,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        let status_false = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-comp"),
            request_nonce: 1,
            received_unique: 10,
            needed: 10,
            complete: false,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        assert_ne!(
            status_true.transcript_bytes(),
            status_false.transcript_bytes()
        );
    }

    #[test]
    fn symbol_ack_different_reasons_different_transcripts() {
        let zone_id: ZoneId = "z:ack-diff".parse().unwrap();
        let ack_complete = SymbolAck::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            1,
            TailscaleNodeId::new("node-ack-diff"),
            1,
            SymbolAckReason::Complete,
            100,
        );
        let ack_cancelled = SymbolAck::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            1,
            TailscaleNodeId::new("node-ack-diff"),
            1,
            SymbolAckReason::Cancelled,
            100,
        );
        assert_ne!(
            ack_complete.transcript_bytes(),
            ack_cancelled.transcript_bytes()
        );
    }

    #[test]
    fn symbol_ack_different_final_count_different_transcripts() {
        let zone_id: ZoneId = "z:ack-cnt".parse().unwrap();
        let ack_a = SymbolAck::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            1,
            TailscaleNodeId::new("node-ack-cnt"),
            1,
            SymbolAckReason::Complete,
            100,
        );
        let ack_b = SymbolAck::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            1,
            TailscaleNodeId::new("node-ack-cnt"),
            1,
            SymbolAckReason::Complete,
            200,
        );
        assert_ne!(ack_a.transcript_bytes(), ack_b.transcript_bytes());
    }

    #[test]
    fn symbol_request_transcript_deterministic() {
        let zone_id: ZoneId = "z:req-det".parse().unwrap();
        let request = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0x55; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x66; 8]),
            42,
            100,
            50,
        )
        .with_missing_hint(vec![1, 2, 3]);
        assert_eq!(request.transcript_bytes(), request.transcript_bytes());
    }

    #[test]
    fn symbol_request_different_max_symbols_different_transcripts() {
        let zone_id: ZoneId = "z:req-max".parse().unwrap();
        let a = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            1,
            10,
            0,
        );
        let b = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            1,
            20,
            0,
        );
        assert_ne!(a.transcript_bytes(), b.transcript_bytes());
    }

    #[test]
    fn symbol_ack_reason_copy_clone() {
        let reason = SymbolAckReason::Duplicate;
        let copy = reason;
        let cloned = reason;
        assert_eq!(copy, cloned);
        assert_eq!(copy, SymbolAckReason::Duplicate);
    }

    #[test]
    fn symbol_request_serde_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:req-serde".parse().unwrap();
        let mut request = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0x55; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0x66; 8]),
            42,
            100,
            50,
        )
        .with_missing_hint(vec![1, 2, 3]);
        request.sign(&signing_key);

        let json = serde_json::to_string(&request).expect("serialize");
        let back: SymbolRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.epoch_id, 42);
        assert_eq!(back.max_symbols, 100);
        assert_eq!(back.current_symbols, 50);
        assert_eq!(back.missing_hint, Some(vec![1, 2, 3]));
    }

    #[test]
    fn frame_error_debug_all_variants() {
        let variants: Vec<FrameError> = vec![
            FrameError::TooShort { len: 0, min: 114 },
            FrameError::ExceedsMtu {
                len: 2000,
                max: 1200,
            },
            FrameError::InvalidMagic { got: [0; 4] },
            FrameError::UnsupportedVersion { version: 99 },
            FrameError::LengthMismatch {
                claimed: 100,
                computed: 200,
            },
            FrameError::FrameSizeMismatch,
            FrameError::SymbolCountOverflow,
            FrameError::InvalidSymbolSize,
            FrameError::InvalidUtf8,
            FrameError::InvalidSourceIdLength {
                len: usize::from(u16::MAX) + 1,
                max: usize::from(u16::MAX),
            },
        ];
        for err in &variants {
            let dbg = format!("{err:?}");
            assert_ne!(dbg, "");
        }
    }

    #[test]
    fn hybrid_signed_frame_clone() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let signed = SignedFcpsFrame::new_hybrid(
            &frame,
            TailscaleNodeId::new("clone-test"),
            1000,
            &signing_key,
            &pq_signing_key,
        )
        .expect("sign");
        let cloned = signed.clone();
        assert_eq!(cloned.payload.timestamp, signed.payload.timestamp);
        assert_eq!(
            cloned.payload.source_id.as_str(),
            signed.payload.source_id.as_str()
        );
        assert_eq!(cloned.payload.frame_bytes, signed.payload.frame_bytes);
    }

    // ── Batch 5: SunnyMoose edge-case and integration tests ──

    #[test]
    fn header_min_symbol_size_one() {
        let mut header = test_header();
        header.symbol_size = 1;
        header.symbol_count = 1;
        header.total_payload_len = u32::try_from(SYMBOL_RECORD_OVERHEAD + 1).expect("fits");
        let symbols = vec![SymbolRecord {
            esi: 0,
            k: 1,
            data: vec![0xAA],
            auth_tag: [0xBB; 16],
        }];
        let frame = FcpsFrame { header, symbols };
        let encoded = frame.encode().expect("encode");
        let decoded = FcpsFrame::decode(&encoded, 10000).expect("decode");
        assert_eq!(decoded.symbols.len(), 1);
        assert_eq!(decoded.symbols[0].data.len(), 1);
    }

    #[test]
    fn header_max_symbol_size_roundtrip() {
        let header = FcpsFrameHeader {
            version: FCPS_VERSION,
            flags: FrameFlags::default(),
            symbol_count: 0,
            total_payload_len: 0,
            object_id: ObjectId::from_bytes([0; 32]),
            symbol_size: u16::MAX,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            zone_id_hash: ZoneIdHash::from_bytes([0; 32]),
            epoch_id: 0,
            sender_instance_id: 0,
            frame_seq: 0,
        };
        let decoded = FcpsFrameHeader::decode(&header.encode()).expect("decode");
        assert_eq!(decoded.symbol_size, u16::MAX);
    }

    #[test]
    fn symbol_record_wire_size_empty_data() {
        let record = SymbolRecord {
            esi: 0,
            k: 0,
            data: vec![],
            auth_tag: [0; 16],
        };
        assert_eq!(record.wire_size(), SYMBOL_RECORD_OVERHEAD);
    }

    #[test]
    fn decode_status_empty_hint_vec() {
        let zone_id: ZoneId = "z:empty-hint".parse().unwrap();
        let status = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 0,
            recipient_node_id: TailscaleNodeId::new("node-empty-hint"),
            request_nonce: 0,
            received_unique: 0,
            needed: 0,
            complete: false,
            missing_hint: Some(vec![]),
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        status.validate_hint_bounds().expect("empty vec ok");
        // Empty vec and None both produce zero-length hint data, so transcript is the same
        let status_none = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 0,
            recipient_node_id: TailscaleNodeId::new("node-empty-hint"),
            request_nonce: 0,
            received_unique: 0,
            needed: 0,
            complete: false,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        assert_eq!(status.transcript_bytes(), status_none.transcript_bytes());
        // But a non-empty vec differs from both
        let status_with = DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id,
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 0,
            recipient_node_id: TailscaleNodeId::new("node-empty-hint"),
            request_nonce: 0,
            received_unique: 0,
            needed: 0,
            complete: false,
            missing_hint: Some(vec![42]),
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        assert_ne!(status.transcript_bytes(), status_with.transcript_bytes());
    }

    #[test]
    fn symbol_request_validate_bounds_zero_max_symbols() {
        let zone_id: ZoneId = "z:zero-max".parse().unwrap();
        let request = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            0,
            0, // zero max_symbols
            0,
        );
        // Zero is within both authenticated and unauthenticated bounds
        request.validate_bounds(false).expect("zero unauth ok");
        request.validate_bounds(true).expect("zero auth ok");
    }

    #[test]
    fn symbol_ack_all_reasons_have_distinct_transcripts() {
        use std::collections::HashSet;
        let zone_id: ZoneId = "z:reason-trans".parse().unwrap();
        let reasons = [
            SymbolAckReason::Complete,
            SymbolAckReason::Cancelled,
            SymbolAckReason::Duplicate,
            SymbolAckReason::BudgetExceeded,
        ];
        let mut transcripts = HashSet::new();
        for reason in reasons {
            let ack = SymbolAck::new(
                make_test_object_header(),
                ObjectId::from_bytes([0; 32]),
                zone_id.clone(),
                ZoneKeyId::from_bytes([0; 8]),
                1,
                TailscaleNodeId::new("node-all-reasons"),
                1,
                reason,
                100,
            );
            transcripts.insert(ack.transcript_bytes());
        }
        assert_eq!(
            transcripts.len(),
            4,
            "all reasons should produce distinct transcripts"
        );
    }

    #[test]
    fn hybrid_signed_frame_zero_timestamp() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let signed = SignedFcpsFrame::new_hybrid(
            &frame,
            TailscaleNodeId::new("zero-ts"),
            0,
            &signing_key,
            &pq_signing_key,
        )
        .expect("sign");
        verify_hybrid_signed_fcps_frame(
            &signed,
            &signing_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            2000,
        )
        .expect("verify zero ts");
        assert_eq!(signed.payload.timestamp, 0);
    }

    #[test]
    fn hybrid_signed_frame_max_timestamp() {
        let signing_key = Ed25519SigningKey::generate();
        let pq_signing_key = test_pq_signing_key();
        let header = test_header();
        let symbols = vec![test_symbol(0, 64), test_symbol(1, 64)];
        let frame = FcpsFrame { header, symbols };
        let signed = SignedFcpsFrame::new_hybrid(
            &frame,
            TailscaleNodeId::new("max-ts"),
            u64::MAX,
            &signing_key,
            &pq_signing_key,
        )
        .expect("sign");
        verify_hybrid_signed_fcps_frame(
            &signed,
            &signing_key.verifying_key(),
            pq_signing_key.verifying_key(),
            PqSigningPolicy::BothRequired,
            2000,
        )
        .expect("verify max ts");
        assert_eq!(signed.payload.timestamp, u64::MAX);
    }

    #[test]
    fn frame_header_epoch_id_zero_and_max() {
        for epoch_id in [0u64, u64::MAX] {
            let header = FcpsFrameHeader {
                version: FCPS_VERSION,
                flags: FrameFlags::default(),
                symbol_count: 0,
                total_payload_len: 0,
                object_id: ObjectId::from_bytes([0; 32]),
                symbol_size: 64,
                zone_key_id: ZoneKeyId::from_bytes([0; 8]),
                zone_id_hash: ZoneIdHash::from_bytes([0; 32]),
                epoch_id,
                sender_instance_id: 0,
                frame_seq: 0,
            };
            let decoded = FcpsFrameHeader::decode(&header.encode()).expect("decode");
            assert_eq!(decoded.epoch_id, epoch_id);
        }
    }

    #[test]
    fn symbol_request_transcript_different_epoch_different_output() {
        let zone_id: ZoneId = "z:epoch-diff".parse().unwrap();
        let req_a = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            1,
            10,
            0,
        );
        let req_b = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            2,
            10,
            0,
        );
        assert_ne!(req_a.transcript_bytes(), req_b.transcript_bytes());
    }

    #[test]
    fn symbol_request_different_current_symbols_different_transcript() {
        let zone_id: ZoneId = "z:cur-sym".parse().unwrap();
        let req_a = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id.clone(),
            ZoneKeyId::from_bytes([0; 8]),
            1,
            10,
            5,
        );
        let req_b = SymbolRequest::new(
            make_test_object_header(),
            ObjectId::from_bytes([0; 32]),
            zone_id,
            ZoneKeyId::from_bytes([0; 8]),
            1,
            10,
            6,
        );
        assert_ne!(req_a.transcript_bytes(), req_b.transcript_bytes());
    }

    #[test]
    fn decode_status_different_received_unique_different_transcript() {
        let zone_id: ZoneId = "z:recv-uniq".parse().unwrap();
        let make_status = |received_unique| DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-diff"),
            request_nonce: 1,
            received_unique,
            needed: 100,
            complete: false,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        assert_ne!(
            make_status(50).transcript_bytes(),
            make_status(51).transcript_bytes()
        );
    }

    #[test]
    fn decode_status_different_needed_different_transcript() {
        let zone_id: ZoneId = "z:needed-diff".parse().unwrap();
        let make_status = |needed| DecodeStatus {
            header: make_test_object_header(),
            object_id: ObjectId::from_bytes([0; 32]),
            zone_id: zone_id.clone(),
            zone_key_id: ZoneKeyId::from_bytes([0; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-diff"),
            request_nonce: 1,
            received_unique: 50,
            needed,
            complete: false,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0; 64]),
        };
        assert_ne!(
            make_status(100).transcript_bytes(),
            make_status(101).transcript_bytes()
        );
    }

    #[test]
    fn frame_flags_remove_flag() {
        let mut flags = FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ | FrameFlags::COMPRESSED;
        flags.remove(FrameFlags::COMPRESSED);
        assert!(!flags.contains(FrameFlags::COMPRESSED));
        assert!(flags.contains(FrameFlags::ENCRYPTED));
        assert!(flags.contains(FrameFlags::RAPTORQ));
    }

    #[test]
    fn frame_flags_toggle_flag() {
        let mut flags = FrameFlags::ENCRYPTED;
        flags.toggle(FrameFlags::ENCRYPTED);
        assert!(!flags.contains(FrameFlags::ENCRYPTED));
        flags.toggle(FrameFlags::ENCRYPTED);
        assert!(flags.contains(FrameFlags::ENCRYPTED));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cross-message transcript domain-separation invariants
    //
    // Each signed control-plane message embeds a unique domain-separator
    // prefix ("FCP2-SYMBOL-ACK-V2", "FCP2-SYMBOL-REQ-V1",
    // "FCP2-DECODE-STATUS-V2") in its transcript. That prefix is what
    // prevents a signature produced for message type A from being replayed
    // as a valid signature for message type B when all other fields happen
    // to line up. These tests lock that invariant in so a refactor that
    // drops or homogenizes the prefix will fail here before shipping.
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn symbol_ack_signature_does_not_verify_as_decode_status() {
        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:cross".parse().expect("zone parse");
        let object_id = ObjectId::from_bytes([0x55; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x66; 8]);
        let epoch_id: u64 = 4242;
        let recipient = TailscaleNodeId::new("node-recipient");
        let request_nonce: u64 = 7;

        let mut ack = SymbolAck::new(
            make_test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            epoch_id,
            recipient.clone(),
            request_nonce,
            SymbolAckReason::Complete,
            100,
        );
        ack.sign(&signing_key);

        // Construct a DecodeStatus that shares every field covered by
        // SymbolAck's transcript. If the two transcripts did not carry
        // distinct domain separators, this signature would verify here —
        // enabling cross-message-type signature replay.
        let status = DecodeStatus {
            header: make_test_object_header(),
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            recipient_node_id: recipient,
            request_nonce,
            received_unique: 0,
            needed: 0,
            complete: false,
            missing_hint: None,
            signature: ack.signature,
        };

        assert!(
            status.verify(&signing_key.verifying_key()).is_err(),
            "SymbolAck signature must not verify as a DecodeStatus — \
             domain-separation invariant broken"
        );
    }

    #[test]
    fn symbol_request_signature_does_not_verify_as_decode_status() {
        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:cross-req".parse().expect("zone parse");
        let object_id = ObjectId::from_bytes([0x77; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0x88; 8]);
        let epoch_id: u64 = 9999;

        let mut request = SymbolRequest::new(
            make_test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            epoch_id,
            1000,
            0,
        );
        request.sign(&signing_key);

        // DecodeStatus and SymbolRequest share object_id / zone / epoch /
        // zone_key_id in their transcripts. The domain separator is the
        // only structural difference preventing replay across message
        // types that happen to use the same signing key.
        let status = DecodeStatus {
            header: make_test_object_header(),
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            recipient_node_id: TailscaleNodeId::new("node-r"),
            request_nonce: 0,
            received_unique: 0,
            needed: 0,
            complete: false,
            missing_hint: None,
            signature: request.signature,
        };

        assert!(
            status.verify(&signing_key.verifying_key()).is_err(),
            "SymbolRequest signature must not verify as a DecodeStatus — \
             domain-separation invariant broken"
        );
    }

    #[test]
    fn decode_status_signature_does_not_verify_as_symbol_ack() {
        let signing_key = Ed25519SigningKey::generate();
        let zone_id: ZoneId = "z:cross-back".parse().expect("zone parse");
        let object_id = ObjectId::from_bytes([0x99; 32]);
        let zone_key_id = ZoneKeyId::from_bytes([0xAA; 8]);
        let epoch_id: u64 = 555;
        let recipient = TailscaleNodeId::new("node-b");
        let request_nonce: u64 = 13;

        let mut status = DecodeStatus {
            header: make_test_object_header(),
            object_id,
            zone_id: zone_id.clone(),
            zone_key_id,
            epoch_id,
            recipient_node_id: recipient.clone(),
            request_nonce,
            received_unique: 0,
            needed: 0,
            complete: false,
            missing_hint: None,
            signature: Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        status.sign(&signing_key);

        let ack = SymbolAck {
            header: make_test_object_header(),
            object_id,
            zone_id,
            zone_key_id,
            epoch_id,
            recipient_node_id: recipient,
            request_nonce,
            reason: SymbolAckReason::Complete,
            final_symbol_count: 0,
            signature: status.signature,
        };

        assert!(
            ack.verify(&signing_key.verifying_key()).is_err(),
            "DecodeStatus signature must not verify as a SymbolAck — \
             domain-separation invariant broken"
        );
    }
}
