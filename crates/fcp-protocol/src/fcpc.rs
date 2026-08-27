//! FCPC (Flywheel Connector Protocol - Control) frame parsing and serialization.
//!
//! Implements the normative control-plane framing defined in `FCP_Specification_V3.md`
//! §9.2 (FCPC Design Requirements) and §9.3 (FCPC Envelope).
//! Frames are authenticated (and by default encrypted) with the session `k_ctx`.

use bitflags::bitflags;
use fcp_crypto::aead::{AEAD_TAG_SIZE, chacha20_decrypt, chacha20_encrypt};
use fcp_crypto::{AeadKey, ChaCha20Nonce, CryptoError};
use thiserror::Error;

use crate::{MeshSessionId, ReplayWindow, SessionDirection, SessionReplayPolicy};

/// FCPC magic bytes: "FCPC".
pub const FCPC_MAGIC: [u8; 4] = [0x46, 0x43, 0x50, 0x43];

/// Current FCPC version.
pub const FCPC_VERSION: u16 = 1;

/// Fixed FCPC header length in bytes.
pub const FCPC_HEADER_LEN: usize = 36;

/// Fixed AEAD tag length in bytes.
pub const FCPC_TAG_LEN: usize = AEAD_TAG_SIZE;

/// Default maximum payload size for control-plane frames (4 MiB).
pub const DEFAULT_MAX_FCPC_PAYLOAD_LEN: usize = 4 * 1024 * 1024;

bitflags! {
    /// FCPC frame flags (NORMATIVE bits may be added as the spec evolves).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FcpcFrameFlags: u16 {
        /// Payload is encrypted (AEAD) with `k_ctx`.
        const ENCRYPTED = 0b0000_0000_0000_0001;
        /// Payload is compressed (reserved).
        const COMPRESSED = 0b0000_0000_0000_0010;
    }
}

impl Default for FcpcFrameFlags {
    fn default() -> Self {
        Self::ENCRYPTED
    }
}

/// FCPC frame parsing/verification errors.
#[derive(Debug, Error)]
pub enum FcpcError {
    #[error("frame too short (len {len}, min {min})")]
    TooShort { len: usize, min: usize },

    #[error("invalid magic bytes (expected FCPC, got {got:?})")]
    InvalidMagic { got: [u8; 4] },

    #[error("unsupported version {version}")]
    UnsupportedVersion { version: u16 },

    #[error("invalid flags bits 0x{bits:04x} (known mask 0x{known:04x})")]
    InvalidFlags { bits: u16, known: u16 },

    #[error("payload length mismatch (claimed {claimed}, actual {actual})")]
    LengthMismatch { claimed: usize, actual: usize },

    #[error("payload too large (len {len} > max {max})")]
    PayloadTooLarge { len: usize, max: usize },

    #[error("replay rejected for seq {seq}")]
    ReplayRejected { seq: u64 },

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Parsed FCPC frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FcpcFrameHeader {
    /// Protocol version.
    pub version: u16,
    /// Mesh session identifier.
    pub session_id: MeshSessionId,
    /// Monotonic sequence number (per direction).
    pub seq: u64,
    /// Frame flags.
    pub flags: FcpcFrameFlags,
    /// Ciphertext length (bytes, excluding tag).
    pub len: u32,
}

impl FcpcFrameHeader {
    /// Encode the header to bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; FCPC_HEADER_LEN] {
        let mut buf = [0u8; FCPC_HEADER_LEN];
        buf[0..4].copy_from_slice(&FCPC_MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..22].copy_from_slice(self.session_id.as_bytes());
        buf[22..30].copy_from_slice(&self.seq.to_le_bytes());
        buf[30..32].copy_from_slice(&self.flags.bits().to_le_bytes());
        buf[32..36].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    /// Decode a header from bytes.
    ///
    /// # Errors
    /// Returns `FcpcError` if the header is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, FcpcError> {
        if bytes.len() < FCPC_HEADER_LEN {
            return Err(FcpcError::TooShort {
                len: bytes.len(),
                min: FCPC_HEADER_LEN,
            });
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        if magic != FCPC_MAGIC {
            return Err(FcpcError::InvalidMagic { got: magic });
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != FCPC_VERSION {
            return Err(FcpcError::UnsupportedVersion { version });
        }

        let mut session_bytes = [0u8; 16];
        session_bytes.copy_from_slice(&bytes[6..22]);
        let session_id = MeshSessionId(session_bytes);

        let seq_bytes: [u8; 8] = bytes[22..30].try_into().map_err(|_| FcpcError::TooShort {
            len: bytes.len(),
            min: FCPC_HEADER_LEN,
        })?;
        let seq = u64::from_le_bytes(seq_bytes);
        let flags_bits = u16::from_le_bytes([bytes[30], bytes[31]]);
        let flags = FcpcFrameFlags::from_bits(flags_bits).ok_or(FcpcError::InvalidFlags {
            bits: flags_bits,
            known: FcpcFrameFlags::all().bits(),
        })?;
        let len_bytes: [u8; 4] = bytes[32..36].try_into().map_err(|_| FcpcError::TooShort {
            len: bytes.len(),
            min: FCPC_HEADER_LEN,
        })?;
        let len = u32::from_le_bytes(len_bytes);

        Ok(Self {
            version,
            session_id,
            seq,
            flags,
            len,
        })
    }
}

/// FCPC frame with authenticated payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcpcFrame {
    pub header: FcpcFrameHeader,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; FCPC_TAG_LEN],
}

impl FcpcFrame {
    /// Build an authenticated (and encrypted) FCPC frame.
    ///
    /// # Errors
    /// Returns `FcpcError` if encryption fails.
    pub fn seal(
        session_id: MeshSessionId,
        seq: u64,
        direction: SessionDirection,
        mut flags: FcpcFrameFlags,
        plaintext: &[u8],
        k_ctx: &[u8; 32],
    ) -> Result<Self, FcpcError> {
        flags.insert(FcpcFrameFlags::ENCRYPTED);
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id,
            seq,
            flags,
            len: 0,
        };
        let aad = build_fcpc_aad(&header);
        let nonce = ChaCha20Nonce::from_counter_directional(seq, direction.as_u8());
        let key = AeadKey::from_bytes(*k_ctx);
        let mut ciphertext = chacha20_encrypt(&key, &nonce, plaintext, &aad)?;
        let tag = split_tag(&mut ciphertext);

        let len = u32::try_from(ciphertext.len()).map_err(|_| FcpcError::PayloadTooLarge {
            len: ciphertext.len(),
            max: u32::MAX as usize,
        })?;
        let header = FcpcFrameHeader { len, ..header };

        Ok(Self {
            header,
            ciphertext,
            tag,
        })
    }

    /// Encode the frame into bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FCPC_HEADER_LEN + self.ciphertext.len() + FCPC_TAG_LEN);
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(&self.tag);
        buf
    }

    /// Decode a frame from bytes with a payload length limit.
    ///
    /// # Errors
    /// Returns `FcpcError` if the frame is malformed or exceeds limits.
    pub fn decode_with_limit(bytes: &[u8], max_payload_len: usize) -> Result<Self, FcpcError> {
        if bytes.len() < FCPC_HEADER_LEN + FCPC_TAG_LEN {
            return Err(FcpcError::TooShort {
                len: bytes.len(),
                min: FCPC_HEADER_LEN + FCPC_TAG_LEN,
            });
        }

        let header = FcpcFrameHeader::decode(bytes)?;
        let claimed = header.len as usize;
        if claimed > max_payload_len {
            return Err(FcpcError::PayloadTooLarge {
                len: claimed,
                max: max_payload_len,
            });
        }

        // `FCPC_HEADER_LEN + claimed + FCPC_TAG_LEN` can overflow `usize`
        // on 32-bit targets (where `usize == u32`) when the caller
        // passes an unbounded `max_payload_len` and the header claims a
        // near-`u32::MAX` length. Use `checked_add` so a bad claim
        // fails closed with `PayloadTooLarge` instead of wrapping to a
        // small value and either panicking on the subsequent slice
        // indexing or silently accepting a mismatched frame. On 64-bit
        // targets this branch is unreachable — kept as belt-and-braces
        // for the 32-bit embedded mesh agents.
        let expected_len = FCPC_HEADER_LEN
            .checked_add(claimed)
            .and_then(|sum| sum.checked_add(FCPC_TAG_LEN))
            .ok_or(FcpcError::PayloadTooLarge {
                len: claimed,
                max: max_payload_len,
            })?;
        if bytes.len() != expected_len {
            return Err(FcpcError::LengthMismatch {
                claimed,
                actual: bytes.len() - FCPC_HEADER_LEN - FCPC_TAG_LEN,
            });
        }

        let cipher_start = FCPC_HEADER_LEN;
        let cipher_end = cipher_start + claimed;
        let mut tag = [0u8; FCPC_TAG_LEN];
        tag.copy_from_slice(&bytes[cipher_end..cipher_end + FCPC_TAG_LEN]);

        Ok(Self {
            header,
            ciphertext: bytes[cipher_start..cipher_end].to_vec(),
            tag,
        })
    }

    /// Decode a frame using the default payload limit.
    ///
    /// # Errors
    /// Returns `FcpcError` if the frame is malformed or exceeds limits.
    pub fn decode(bytes: &[u8]) -> Result<Self, FcpcError> {
        Self::decode_with_limit(bytes, DEFAULT_MAX_FCPC_PAYLOAD_LEN)
    }

    /// Decrypt the payload using `k_ctx` (AEAD).
    ///
    /// # Errors
    /// Returns `FcpcError` if decryption fails.
    pub fn open(
        &self,
        direction: SessionDirection,
        k_ctx: &[u8; 32],
    ) -> Result<Vec<u8>, FcpcError> {
        let aad = build_fcpc_aad(&self.header);
        let nonce = ChaCha20Nonce::from_counter_directional(self.header.seq, direction.as_u8());
        let key = AeadKey::from_bytes(*k_ctx);
        let mut combined = Vec::with_capacity(self.ciphertext.len() + FCPC_TAG_LEN);
        combined.extend_from_slice(&self.ciphertext);
        combined.extend_from_slice(&self.tag);
        Ok(chacha20_decrypt(&key, &nonce, &combined, &aad)?)
    }

    /// Check replay window before accepting a frame.
    ///
    /// # Errors
    /// Returns `FcpcError::ReplayRejected` if the sequence is rejected.
    pub fn check_replay(&self, window: &mut ReplayWindow) -> Result<(), FcpcError> {
        if window.check_and_update(self.header.seq) {
            Ok(())
        } else {
            Err(FcpcError::ReplayRejected {
                seq: self.header.seq,
            })
        }
    }
}

fn build_fcpc_aad(header: &FcpcFrameHeader) -> [u8; 26] {
    let mut aad = [0u8; 26];
    aad[0..16].copy_from_slice(header.session_id.as_bytes());
    aad[16..24].copy_from_slice(&header.seq.to_le_bytes());
    aad[24..26].copy_from_slice(&header.flags.bits().to_le_bytes());
    aad
}

fn split_tag(ciphertext: &mut Vec<u8>) -> [u8; FCPC_TAG_LEN] {
    let tag_offset = ciphertext.len().saturating_sub(FCPC_TAG_LEN);
    let tag_bytes = ciphertext.split_off(tag_offset);
    let mut tag = [0u8; FCPC_TAG_LEN];
    tag.copy_from_slice(&tag_bytes);
    tag
}

/// Helper to build a replay window with normative defaults.
#[must_use]
pub fn default_replay_window() -> ReplayWindow {
    ReplayWindow::new(SessionReplayPolicy::default().max_reorder_window)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION_ID_BYTES: [u8; 16] = [0xAA; 16];
    const K_CTX: [u8; 32] = [0x11; 32];

    #[test]
    fn seal_round_trip() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let plaintext = b"fcpc payload bytes";
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            42,
            dir,
            FcpcFrameFlags::default(),
            plaintext,
            &K_CTX,
        )
        .expect("seal should succeed");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode should succeed");
        let opened = decoded.open(dir, &K_CTX).expect("open should succeed");
        assert_eq!(opened, plaintext);
    }

    // Metamorphic: for every valid encoded frame, `decode(bytes).encode() ==
    // bytes` must hold exactly — no field reordering, no length recomputation
    // drift, no silent header normalization. This is strictly stronger than
    // `seal_round_trip` (which only checks plaintext recovery after open).
    #[test]
    fn encode_decode_encode_is_byte_stable_across_flags_and_sizes() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let flag_sets = [
            FcpcFrameFlags::default(),
            FcpcFrameFlags::ENCRYPTED,
            FcpcFrameFlags::all(),
        ];
        let payload_sizes = [0usize, 1, 15, 16, 17, 256, 4096];

        for flags in flag_sets {
            for &size in &payload_sizes {
                let plaintext: Vec<u8> = (0..size)
                    .map(|i| {
                        u8::try_from(i % 256)
                            .expect("modulo 256 keeps payload byte generation in range")
                            .wrapping_mul(31)
                    })
                    .collect();
                let frame =
                    FcpcFrame::seal(session_id, 0xDEAD_BEEF, dir, flags, &plaintext, &K_CTX)
                        .expect("seal should succeed");
                let encoded = frame.encode();
                let decoded = FcpcFrame::decode(&encoded).expect("decode should succeed");
                let re_encoded = decoded.encode();
                assert_eq!(
                    encoded, re_encoded,
                    "FcpcFrame encode must be byte-stable across decode roundtrip \
                     (flags={flags:?}, size={size})"
                );
                // Also assert the post-decode frame opens back to the original
                // plaintext — guards against decode succeeding on bytes that
                // would subsequently fail AEAD verification.
                let opened = decoded.open(dir, &K_CTX).expect("open should succeed");
                assert_eq!(opened, plaintext);
            }
        }
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(session_id, 1, dir, FcpcFrameFlags::default(), b"x", &K_CTX)
            .expect("seal should succeed");
        let mut bytes = frame.encode();
        bytes[0] = 0x00;
        let err = FcpcFrame::decode(&bytes).expect_err("bad magic should fail");
        assert!(matches!(err, FcpcError::InvalidMagic { .. }));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            2,
            dir,
            FcpcFrameFlags::default(),
            b"data",
            &K_CTX,
        )
        .expect("seal should succeed");
        let mut bytes = frame.encode();
        bytes.pop();
        let err = FcpcFrame::decode(&bytes).expect_err("length mismatch should fail");
        assert!(matches!(err, FcpcError::LengthMismatch { .. }));
    }

    #[test]
    fn replay_window_rejects_replay() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            7,
            dir,
            FcpcFrameFlags::default(),
            b"data",
            &K_CTX,
        )
        .expect("seal should succeed");
        let mut window = default_replay_window();
        frame.check_replay(&mut window).expect("first seen");
        let err = frame
            .check_replay(&mut window)
            .expect_err("replay rejected");
        assert!(matches!(err, FcpcError::ReplayRejected { .. }));
    }

    #[test]
    fn decode_rejects_payload_too_large() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            9,
            dir,
            FcpcFrameFlags::default(),
            b"data",
            &K_CTX,
        )
        .expect("seal should succeed");
        let bytes = frame.encode();
        let err = FcpcFrame::decode_with_limit(&bytes, 1).expect_err("payload too large");
        assert!(matches!(err, FcpcError::PayloadTooLarge { .. }));
    }

    // ── Batch 2: SunnyMoose test expansion ──

    #[test]
    fn header_encode_is_exactly_36_bytes() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id,
            seq: 0,
            flags: FcpcFrameFlags::default(),
            len: 0,
        };
        assert_eq!(header.encode().len(), FCPC_HEADER_LEN);
        assert_eq!(FCPC_HEADER_LEN, 36);
    }

    #[test]
    fn header_decode_too_short() {
        let short = [0u8; 10];
        let err = FcpcFrameHeader::decode(&short).expect_err("too short");
        assert!(matches!(err, FcpcError::TooShort { len: 10, min: 36 }));
    }

    #[test]
    fn header_decode_preserves_all_fields() {
        let session_id = MeshSessionId([0xAA; 16]);
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id,
            seq: 0xDEAD_BEEF_CAFE_0042,
            flags: FcpcFrameFlags::ENCRYPTED | FcpcFrameFlags::COMPRESSED,
            len: 12345,
        };
        let decoded = FcpcFrameHeader::decode(&header.encode()).expect("decode");
        assert_eq!(decoded.version, FCPC_VERSION);
        assert_eq!(decoded.session_id, session_id);
        assert_eq!(decoded.seq, 0xDEAD_BEEF_CAFE_0042);
        assert!(decoded.flags.contains(FcpcFrameFlags::ENCRYPTED));
        assert!(decoded.flags.contains(FcpcFrameFlags::COMPRESSED));
        assert_eq!(decoded.len, 12345);
    }

    #[test]
    fn header_decode_rejects_wrong_version() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id,
            seq: 0,
            flags: FcpcFrameFlags::default(),
            len: 0,
        };
        let mut bytes = header.encode();
        bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
        let err = FcpcFrameHeader::decode(&bytes).expect_err("wrong version");
        assert!(matches!(err, FcpcError::UnsupportedVersion { version: 99 }));
    }

    #[test]
    fn header_decode_rejects_unknown_flag_bits() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id,
            seq: 0,
            flags: FcpcFrameFlags::default(),
            len: 0,
        };
        let mut bytes = header.encode();
        bytes[30..32].copy_from_slice(&0x8000_u16.to_le_bytes());

        let err = FcpcFrameHeader::decode(&bytes).expect_err("unknown flags");
        assert!(matches!(
            err,
            FcpcError::InvalidFlags {
                bits: 0x8000,
                known: 0x0003
            }
        ));
    }

    #[test]
    fn seal_always_sets_encrypted_flag() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        // Pass empty flags — seal should add ENCRYPTED
        let frame = FcpcFrame::seal(session_id, 1, dir, FcpcFrameFlags::empty(), b"test", &K_CTX)
            .expect("seal ok");
        assert!(frame.header.flags.contains(FcpcFrameFlags::ENCRYPTED));
    }

    #[test]
    fn seal_different_directions_produce_different_ciphertext() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let plaintext = b"directional test";
        let frame_i2r = FcpcFrame::seal(
            session_id,
            1,
            SessionDirection::InitiatorToResponder,
            FcpcFrameFlags::default(),
            plaintext,
            &K_CTX,
        )
        .expect("seal i2r");
        let frame_r2i = FcpcFrame::seal(
            session_id,
            1,
            SessionDirection::ResponderToInitiator,
            FcpcFrameFlags::default(),
            plaintext,
            &K_CTX,
        )
        .expect("seal r2i");
        assert_ne!(frame_i2r.ciphertext, frame_r2i.ciphertext);
    }

    #[test]
    fn open_wrong_key_fails() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            5,
            dir,
            FcpcFrameFlags::default(),
            b"secret data",
            &K_CTX,
        )
        .expect("seal ok");
        let wrong_key = [0x22; 32];
        assert!(frame.open(dir, &wrong_key).is_err());
    }

    #[test]
    fn open_wrong_direction_fails() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let frame = FcpcFrame::seal(
            session_id,
            5,
            SessionDirection::InitiatorToResponder,
            FcpcFrameFlags::default(),
            b"direction matters",
            &K_CTX,
        )
        .expect("seal ok");
        // Try to open with the opposite direction
        assert!(
            frame
                .open(SessionDirection::ResponderToInitiator, &K_CTX)
                .is_err()
        );
    }

    #[test]
    fn tampered_ciphertext_fails_open() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let mut frame = FcpcFrame::seal(
            session_id,
            10,
            dir,
            FcpcFrameFlags::default(),
            b"integrity check",
            &K_CTX,
        )
        .expect("seal ok");
        if let Some(byte) = frame.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(frame.open(dir, &K_CTX).is_err());
    }

    #[test]
    fn tampered_tag_fails_open() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let mut frame = FcpcFrame::seal(
            session_id,
            11,
            dir,
            FcpcFrameFlags::default(),
            b"tag integrity",
            &K_CTX,
        )
        .expect("seal ok");
        frame.tag[0] ^= 0xFF;
        assert!(frame.open(dir, &K_CTX).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(session_id, 20, dir, FcpcFrameFlags::default(), b"", &K_CTX)
            .expect("seal empty ok");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode ok");
        let opened = decoded.open(dir, &K_CTX).expect("open ok");
        assert_eq!(opened, [] as [u8; 0]);
    }

    #[test]
    fn large_payload_roundtrip() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let payload = vec![0xAB; 4096];
        let frame = FcpcFrame::seal(
            session_id,
            30,
            dir,
            FcpcFrameFlags::default(),
            &payload,
            &K_CTX,
        )
        .expect("seal large ok");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode ok");
        let opened = decoded.open(dir, &K_CTX).expect("open ok");
        assert_eq!(opened, payload);
    }

    #[test]
    fn replay_window_accepts_different_seqs() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let mut window = default_replay_window();
        // Start at 1; seq 0 is pre-rejected by the replay window
        for seq in 1..10 {
            let frame = FcpcFrame::seal(
                session_id,
                seq,
                dir,
                FcpcFrameFlags::default(),
                b"x",
                &K_CTX,
            )
            .expect("seal ok");
            frame.check_replay(&mut window).expect("first seen");
        }
    }

    #[test]
    fn decode_with_limit_exact_boundary() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            50,
            dir,
            FcpcFrameFlags::default(),
            b"boundary",
            &K_CTX,
        )
        .expect("seal ok");
        let bytes = frame.encode();
        let ciphertext_len = frame.ciphertext.len();
        // Exact limit should succeed
        FcpcFrame::decode_with_limit(&bytes, ciphertext_len).expect("exact limit ok");
        // One byte under should fail
        let err =
            FcpcFrame::decode_with_limit(&bytes, ciphertext_len - 1).expect_err("under limit");
        assert!(matches!(err, FcpcError::PayloadTooLarge { .. }));
    }

    #[test]
    fn frame_decode_too_short_for_tag() {
        // A buffer that is long enough for the header but not the tag
        let mut bytes = [0u8; FCPC_HEADER_LEN + 5];
        bytes[0..4].copy_from_slice(&FCPC_MAGIC);
        bytes[4..6].copy_from_slice(&FCPC_VERSION.to_le_bytes());
        let err = FcpcFrame::decode(&bytes).expect_err("too short for tag");
        assert!(matches!(err, FcpcError::TooShort { .. }));
    }

    #[test]
    fn default_flags_is_encrypted() {
        let flags = FcpcFrameFlags::default();
        assert!(flags.contains(FcpcFrameFlags::ENCRYPTED));
        assert!(!flags.contains(FcpcFrameFlags::COMPRESSED));
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            FcpcError::TooShort { len: 5, min: 36 }.to_string(),
            "frame too short (len 5, min 36)"
        );
        assert_eq!(
            FcpcError::InvalidMagic { got: [0, 0, 0, 0] }.to_string(),
            "invalid magic bytes (expected FCPC, got [0, 0, 0, 0])"
        );
        assert_eq!(
            FcpcError::UnsupportedVersion { version: 42 }.to_string(),
            "unsupported version 42"
        );
        assert_eq!(
            FcpcError::InvalidFlags {
                bits: 0x8000,
                known: 0x0003
            }
            .to_string(),
            "invalid flags bits 0x8000 (known mask 0x0003)"
        );
        assert_eq!(
            FcpcError::LengthMismatch {
                claimed: 100,
                actual: 50
            }
            .to_string(),
            "payload length mismatch (claimed 100, actual 50)"
        );
        assert_eq!(
            FcpcError::PayloadTooLarge { len: 10, max: 5 }.to_string(),
            "payload too large (len 10 > max 5)"
        );
        assert_eq!(
            FcpcError::ReplayRejected { seq: 7 }.to_string(),
            "replay rejected for seq 7"
        );
    }

    #[test]
    fn seal_deterministic_same_inputs() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let a = FcpcFrame::seal(
            session_id,
            99,
            dir,
            FcpcFrameFlags::default(),
            b"deterministic",
            &K_CTX,
        )
        .expect("seal a");
        let b = FcpcFrame::seal(
            session_id,
            99,
            dir,
            FcpcFrameFlags::default(),
            b"deterministic",
            &K_CTX,
        )
        .expect("seal b");
        assert_eq!(a.ciphertext, b.ciphertext);
        assert_eq!(a.tag, b.tag);
    }

    #[test]
    fn different_seq_produces_different_ciphertext() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let a = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"same data",
            &K_CTX,
        )
        .expect("seal a");
        let b = FcpcFrame::seal(
            session_id,
            2,
            dir,
            FcpcFrameFlags::default(),
            b"same data",
            &K_CTX,
        )
        .expect("seal b");
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn different_session_id_produces_different_ciphertext() {
        let dir = SessionDirection::InitiatorToResponder;
        let a = FcpcFrame::seal(
            MeshSessionId([0xAA; 16]),
            1,
            dir,
            FcpcFrameFlags::default(),
            b"session test",
            &K_CTX,
        )
        .expect("seal a");
        let b = FcpcFrame::seal(
            MeshSessionId([0xBB; 16]),
            1,
            dir,
            FcpcFrameFlags::default(),
            b"session test",
            &K_CTX,
        )
        .expect("seal b");
        // Different session IDs lead to different AAD, so decryption should differ
        assert_ne!(a.encode(), b.encode());
    }

    #[test]
    fn frame_header_len_field_matches_ciphertext() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"length check",
            &K_CTX,
        )
        .expect("seal ok");
        assert_eq!(frame.header.len as usize, frame.ciphertext.len());
    }

    // ── Batch 3: SunnyMoose deep-coverage expansion ──

    #[test]
    fn magic_constant_is_fcpc_ascii() {
        assert_eq!(&FCPC_MAGIC, b"FCPC");
    }

    #[test]
    fn tag_len_matches_aead_tag_size() {
        assert_eq!(FCPC_TAG_LEN, AEAD_TAG_SIZE);
        assert_eq!(FCPC_TAG_LEN, 16);
    }

    #[test]
    fn default_max_payload_is_4mib() {
        assert_eq!(DEFAULT_MAX_FCPC_PAYLOAD_LEN, 4 * 1024 * 1024);
    }

    #[test]
    fn unknown_flag_bits_truncated() {
        let flags = FcpcFrameFlags::from_bits_truncate(0xFFFF);
        // Only the two defined bits survive
        assert!(flags.contains(FcpcFrameFlags::ENCRYPTED));
        assert!(flags.contains(FcpcFrameFlags::COMPRESSED));
        assert_eq!(flags.bits(), 0b0000_0000_0000_0011);
    }

    #[test]
    fn header_decode_ignores_trailing_bytes() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id,
            seq: 77,
            flags: FcpcFrameFlags::default(),
            len: 0,
        };
        let encoded = header.encode();
        // Append garbage after the 36-byte header
        let mut extended = encoded.to_vec();
        extended.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let decoded = FcpcFrameHeader::decode(&extended).expect("trailing bytes ok");
        assert_eq!(decoded.seq, 77);
    }

    #[test]
    fn decode_empty_slice_too_short() {
        let err = FcpcFrame::decode(&[]).expect_err("empty");
        assert!(matches!(err, FcpcError::TooShort { len: 0, .. }));
    }

    #[test]
    fn aad_is_26_bytes_with_expected_layout() {
        let session_id = MeshSessionId([0x01; 16]);
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id,
            seq: 0x0102_0304_0506_0708,
            flags: FcpcFrameFlags::ENCRYPTED,
            len: 0,
        };
        let aad = build_fcpc_aad(&header);
        assert_eq!(aad.len(), 26);
        // First 16 bytes: session_id
        assert_eq!(&aad[0..16], &[0x01; 16]);
        // Next 8 bytes: seq LE
        assert_eq!(&aad[16..24], &0x0102_0304_0506_0708u64.to_le_bytes());
        // Last 2 bytes: flags LE
        assert_eq!(
            &aad[24..26],
            &FcpcFrameFlags::ENCRYPTED.bits().to_le_bytes()
        );
    }

    #[test]
    fn frame_encode_decode_byte_identity() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            100,
            dir,
            FcpcFrameFlags::default(),
            b"identity roundtrip",
            &K_CTX,
        )
        .expect("seal ok");
        let bytes = frame.encode();
        let decoded = FcpcFrame::decode(&bytes).expect("decode ok");
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn seal_with_compressed_flag_roundtrips() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let flags = FcpcFrameFlags::ENCRYPTED | FcpcFrameFlags::COMPRESSED;
        let frame = FcpcFrame::seal(session_id, 200, dir, flags, b"compressed?", &K_CTX)
            .expect("seal with compressed");
        assert!(frame.header.flags.contains(FcpcFrameFlags::COMPRESSED));
        assert!(frame.header.flags.contains(FcpcFrameFlags::ENCRYPTED));
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode ok");
        let opened = decoded.open(dir, &K_CTX).expect("open ok");
        assert_eq!(opened, b"compressed?");
    }

    #[test]
    fn replay_window_out_of_order_acceptance() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let mut window = default_replay_window();
        // Accept seq 5 first
        let frame5 = FcpcFrame::seal(session_id, 5, dir, FcpcFrameFlags::default(), b"x", &K_CTX)
            .expect("seal");
        frame5.check_replay(&mut window).expect("seq 5 accepted");
        // Accept seq 3 (within window, out of order)
        let frame3 = FcpcFrame::seal(session_id, 3, dir, FcpcFrameFlags::default(), b"x", &K_CTX)
            .expect("seal");
        frame3.check_replay(&mut window).expect("seq 3 accepted");
        // Reject seq 3 again (replay)
        frame3
            .check_replay(&mut window)
            .expect_err("seq 3 replayed");
    }

    #[test]
    fn frame_debug_contains_type_name() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"dbg",
            &K_CTX,
        )
        .expect("seal");
        let dbg = format!("{frame:?}");
        assert!(dbg.contains("FcpcFrame"));
        assert!(dbg.contains("FcpcFrameHeader"));
    }

    #[test]
    fn frame_clone_eq() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(session_id, 1, dir, FcpcFrameFlags::default(), b"eq", &K_CTX)
            .expect("seal");
        let cloned = frame.clone();
        assert_eq!(frame, cloned);
    }

    #[test]
    fn header_clone_eq() {
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id: MeshSessionId(SESSION_ID_BYTES),
            seq: 42,
            flags: FcpcFrameFlags::default(),
            len: 10,
        };
        let cloned = header;
        assert_eq!(header, cloned);
    }

    #[test]
    fn error_debug_coverage() {
        let err = FcpcError::TooShort { len: 1, min: 36 };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("TooShort"));
    }

    #[test]
    fn flags_hash_impl() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FcpcFrameFlags::ENCRYPTED);
        set.insert(FcpcFrameFlags::COMPRESSED);
        set.insert(FcpcFrameFlags::ENCRYPTED);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn seal_seq_zero_works() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            0,
            dir,
            FcpcFrameFlags::default(),
            b"seq0",
            &K_CTX,
        )
        .expect("seal seq 0");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode ok");
        let opened = decoded.open(dir, &K_CTX).expect("open ok");
        assert_eq!(opened, b"seq0");
    }

    #[test]
    fn seal_max_seq_works() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            u64::MAX,
            dir,
            FcpcFrameFlags::default(),
            b"max seq",
            &K_CTX,
        )
        .expect("seal max seq");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode ok");
        assert_eq!(decoded.header.seq, u64::MAX);
        let opened = decoded.open(dir, &K_CTX).expect("open ok");
        assert_eq!(opened, b"max seq");
    }

    #[test]
    fn different_key_same_params_different_output() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let key_a = [0x11; 32];
        let key_b = [0x22; 32];
        let a = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"same",
            &key_a,
        )
        .expect("seal a");
        let b = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"same",
            &key_b,
        )
        .expect("seal b");
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.tag, b.tag);
    }

    #[test]
    fn encoded_frame_layout() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"layout test",
            &K_CTX,
        )
        .expect("seal");
        let bytes = frame.encode();
        // Total length = header + ciphertext + tag
        assert_eq!(
            bytes.len(),
            FCPC_HEADER_LEN + frame.ciphertext.len() + FCPC_TAG_LEN
        );
        // First 4 bytes are magic
        assert_eq!(&bytes[0..4], b"FCPC");
        // Last 16 bytes are the tag
        assert_eq!(&bytes[bytes.len() - FCPC_TAG_LEN..], &frame.tag);
    }

    // ── Batch 4: SunnyMoose deep-coverage expansion ──

    #[test]
    fn header_encode_magic_always_correct() {
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id: MeshSessionId([0xFF; 16]),
            seq: u64::MAX,
            flags: FcpcFrameFlags::ENCRYPTED | FcpcFrameFlags::COMPRESSED,
            len: u32::MAX,
        };
        let bytes = header.encode();
        assert_eq!(&bytes[0..4], b"FCPC");
    }

    #[test]
    fn header_version_field_encoding() {
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id: MeshSessionId([0; 16]),
            seq: 0,
            flags: FcpcFrameFlags::empty(),
            len: 0,
        };
        let bytes = header.encode();
        assert_eq!(&bytes[4..6], &FCPC_VERSION.to_le_bytes());
    }

    #[test]
    fn header_roundtrip_boundary_values() {
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id: MeshSessionId([0xFF; 16]),
            seq: u64::MAX,
            flags: FcpcFrameFlags::all(),
            len: u32::MAX,
        };
        let decoded = FcpcFrameHeader::decode(&header.encode()).expect("decode");
        assert_eq!(decoded.seq, u64::MAX);
        assert_eq!(decoded.len, u32::MAX);
        assert_eq!(decoded.session_id, MeshSessionId([0xFF; 16]));
    }

    #[test]
    fn seal_with_binary_payload() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let payload: Vec<u8> = (0..=255).collect();
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            &payload,
            &K_CTX,
        )
        .expect("seal binary");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode");
        let opened = decoded.open(dir, &K_CTX).expect("open");
        assert_eq!(opened, payload);
    }

    #[test]
    fn multiple_sequential_frames_decrypt_independently() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let mut window = default_replay_window();

        for seq in 1..=5u64 {
            let payload = format!("frame-{seq}");
            let frame = FcpcFrame::seal(
                session_id,
                seq,
                dir,
                FcpcFrameFlags::default(),
                payload.as_bytes(),
                &K_CTX,
            )
            .expect("seal");

            let encoded = frame.encode();
            let decoded = FcpcFrame::decode(&encoded).expect("decode");
            decoded.check_replay(&mut window).expect("replay ok");
            let opened = decoded.open(dir, &K_CTX).expect("open");
            assert_eq!(opened, payload.as_bytes());
        }
    }

    #[test]
    fn flags_empty_bits_is_zero() {
        assert_eq!(FcpcFrameFlags::empty().bits(), 0);
    }

    #[test]
    fn flags_all_has_both_defined() {
        let all = FcpcFrameFlags::all();
        assert!(all.contains(FcpcFrameFlags::ENCRYPTED));
        assert!(all.contains(FcpcFrameFlags::COMPRESSED));
        assert_eq!(all.bits(), 0b11);
    }

    #[test]
    fn header_decode_bad_magic_first_byte() {
        let mut bytes = [0u8; FCPC_HEADER_LEN];
        bytes[0..4].copy_from_slice(b"FCPS"); // wrong magic
        bytes[4..6].copy_from_slice(&FCPC_VERSION.to_le_bytes());
        let err = FcpcFrameHeader::decode(&bytes).expect_err("wrong magic");
        match err {
            FcpcError::InvalidMagic { got } => assert_eq!(&got, b"FCPS"),
            _ => panic!("expected InvalidMagic"),
        }
    }

    #[test]
    fn frame_decode_exact_header_plus_tag_no_payload() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(session_id, 1, dir, FcpcFrameFlags::default(), b"", &K_CTX)
            .expect("seal empty");
        let bytes = frame.encode();
        // Decode with exact limit
        let decoded = FcpcFrame::decode_with_limit(&bytes, 0).expect("empty payload, limit 0 ok");
        let opened = decoded.open(dir, &K_CTX).expect("open ok");
        assert_eq!(opened, [] as [u8; 0]);
    }

    #[test]
    fn replay_window_sequential_then_replay() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let mut window = default_replay_window();

        for seq in 1..=3u64 {
            let frame = FcpcFrame::seal(
                session_id,
                seq,
                dir,
                FcpcFrameFlags::default(),
                b"x",
                &K_CTX,
            )
            .expect("seal");
            frame.check_replay(&mut window).expect("accepted");
        }

        // Replay seq 2
        let replay = FcpcFrame::seal(session_id, 2, dir, FcpcFrameFlags::default(), b"x", &K_CTX)
            .expect("seal");
        let err = replay.check_replay(&mut window).expect_err("replay");
        assert!(matches!(err, FcpcError::ReplayRejected { seq: 2 }));
    }

    #[test]
    fn default_replay_window_function_returns_valid_window() {
        let window = default_replay_window();
        assert_eq!(window.highest_seq(), 0);
    }

    #[test]
    fn frame_header_seq_zero_roundtrip() {
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id: MeshSessionId([0; 16]),
            seq: 0,
            flags: FcpcFrameFlags::default(),
            len: 0,
        };
        let decoded = FcpcFrameHeader::decode(&header.encode()).expect("decode");
        assert_eq!(decoded.seq, 0);
    }

    #[test]
    fn error_crypto_variant_display() {
        // The Crypto variant wraps a CryptoError via #[from]
        let err = FcpcError::TooShort { len: 0, min: 52 };
        let dbg = format!("{err:?}");
        assert!(dbg.contains("TooShort"));
    }

    #[test]
    fn header_clone_copy_semantics() {
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id: MeshSessionId([0xBB; 16]),
            seq: 77,
            flags: FcpcFrameFlags::COMPRESSED,
            len: 42,
        };
        // Copy (it derives Copy)
        let copy = header;
        assert_eq!(copy.seq, header.seq);
        assert_eq!(copy.len, header.len);
        assert_eq!(copy.flags, header.flags);
    }

    #[test]
    fn frame_different_plaintext_different_ciphertext() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let a = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"alpha",
            &K_CTX,
        )
        .expect("seal a");
        let b = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"bravo",
            &K_CTX,
        )
        .expect("seal b");
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn seal_preserves_session_id_in_header() {
        let session_id = MeshSessionId([0xDE; 16]);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"test",
            &K_CTX,
        )
        .expect("seal");
        assert_eq!(frame.header.session_id, session_id);
    }

    #[test]
    fn seal_preserves_version() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"ver",
            &K_CTX,
        )
        .expect("seal");
        assert_eq!(frame.header.version, FCPC_VERSION);
    }

    #[test]
    fn seal_preserves_seq() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            12345,
            dir,
            FcpcFrameFlags::default(),
            b"seq",
            &K_CTX,
        )
        .expect("seal");
        assert_eq!(frame.header.seq, 12345);
    }

    #[test]
    fn frame_ne_different_tag() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"tag ne",
            &K_CTX,
        )
        .expect("seal");
        let mut modified = frame.clone();
        modified.tag[0] ^= 0xFF;
        assert_ne!(frame, modified);
    }

    // ── Batch 5: SunnyMoose edge-case and integration tests ──

    #[test]
    fn seal_then_decode_different_limit_succeeds_at_exact() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let plaintext = b"variable limit test";
        let frame = FcpcFrame::seal(
            session_id,
            77,
            dir,
            FcpcFrameFlags::default(),
            plaintext,
            &K_CTX,
        )
        .expect("seal ok");
        let encoded = frame.encode();
        let ct_len = frame.ciphertext.len();
        // Exact limit passes
        let decoded = FcpcFrame::decode_with_limit(&encoded, ct_len).expect("exact ok");
        let opened = decoded.open(dir, &K_CTX).expect("open ok");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn seal_responder_direction_roundtrip() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::ResponderToInitiator;
        let plaintext = b"responder payload";
        let frame = FcpcFrame::seal(
            session_id,
            42,
            dir,
            FcpcFrameFlags::default(),
            plaintext,
            &K_CTX,
        )
        .expect("seal");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode");
        let opened = decoded.open(dir, &K_CTX).expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn frame_ne_different_ciphertext() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"ciphertext ne",
            &K_CTX,
        )
        .expect("seal");
        let mut modified = frame.clone();
        if !modified.ciphertext.is_empty() {
            modified.ciphertext[0] ^= 0xFF;
        }
        assert_ne!(frame, modified);
    }

    #[test]
    fn frame_ne_different_seq() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame_a = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"same",
            &K_CTX,
        )
        .expect("seal a");
        let frame_b = FcpcFrame::seal(
            session_id,
            2,
            dir,
            FcpcFrameFlags::default(),
            b"same",
            &K_CTX,
        )
        .expect("seal b");
        assert_ne!(frame_a, frame_b);
    }

    #[test]
    fn replay_window_rejects_seq_zero() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            0,
            dir,
            FcpcFrameFlags::default(),
            b"zero",
            &K_CTX,
        )
        .expect("seal");
        let mut window = default_replay_window();
        // seq 0 is always rejected by ReplayWindow
        let err = frame.check_replay(&mut window).expect_err("seq 0 rejected");
        assert!(matches!(err, FcpcError::ReplayRejected { seq: 0 }));
    }

    #[test]
    fn header_encode_all_zeros() {
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id: MeshSessionId([0; 16]),
            seq: 0,
            flags: FcpcFrameFlags::empty(),
            len: 0,
        };
        let bytes = header.encode();
        // Magic is still "FCPC"
        assert_eq!(&bytes[0..4], b"FCPC");
        // Version is 1
        assert_eq!(&bytes[4..6], &1u16.to_le_bytes());
        // Session ID is all zeros
        assert_eq!(&bytes[6..22], &[0u8; 16]);
        // Seq is zero
        assert_eq!(&bytes[22..30], &0u64.to_le_bytes());
        // Flags are zero (empty)
        assert_eq!(&bytes[30..32], &0u16.to_le_bytes());
        // Len is zero
        assert_eq!(&bytes[32..36], &0u32.to_le_bytes());
    }

    #[test]
    fn multiple_replay_window_checks_with_gap() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let mut window = default_replay_window();

        // Accept seq 1
        let f1 = FcpcFrame::seal(session_id, 1, dir, FcpcFrameFlags::default(), b"x", &K_CTX)
            .expect("seal");
        f1.check_replay(&mut window).expect("seq 1");

        // Skip to seq 100
        let f100 = FcpcFrame::seal(
            session_id,
            100,
            dir,
            FcpcFrameFlags::default(),
            b"x",
            &K_CTX,
        )
        .expect("seal");
        f100.check_replay(&mut window).expect("seq 100");

        // seq 1 is now too old (gap > 128 window)
        let f1_replay =
            FcpcFrame::seal(session_id, 1, dir, FcpcFrameFlags::default(), b"x", &K_CTX)
                .expect("seal");
        f1_replay
            .check_replay(&mut window)
            .expect_err("seq 1 too old");
    }

    #[test]
    fn error_display_replay_rejected_with_specific_seq() {
        let err = FcpcError::ReplayRejected { seq: 42 };
        assert_eq!(err.to_string(), "replay rejected for seq 42");
    }

    #[test]
    fn header_flags_union_preserved_through_encode_decode() {
        let flags = FcpcFrameFlags::ENCRYPTED | FcpcFrameFlags::COMPRESSED;
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id: MeshSessionId([0; 16]),
            seq: 0,
            flags,
            len: 0,
        };
        let decoded = FcpcFrameHeader::decode(&header.encode()).expect("decode");
        assert!(decoded.flags.contains(FcpcFrameFlags::ENCRYPTED));
        assert!(decoded.flags.contains(FcpcFrameFlags::COMPRESSED));
        assert_eq!(decoded.flags.bits(), 0b11);
    }

    #[test]
    fn seal_unicode_payload_roundtrip() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let plaintext = "Hello \u{1F600} \u{4E16}\u{754C}".as_bytes();
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            plaintext,
            &K_CTX,
        )
        .expect("seal unicode");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode");
        let opened = decoded.open(dir, &K_CTX).expect("open");
        assert_eq!(opened, plaintext);
        let text = std::str::from_utf8(&opened).expect("valid utf8");
        assert!(text.contains('\u{1F600}'));
    }

    #[test]
    fn frame_decode_truncated_one_byte_short() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"truncation test",
            &K_CTX,
        )
        .expect("seal");
        let mut bytes = frame.encode();
        bytes.pop(); // remove last byte
        let err = FcpcFrame::decode(&bytes).expect_err("truncated");
        assert!(matches!(err, FcpcError::LengthMismatch { .. }));
    }

    #[test]
    fn frame_decode_with_extra_byte_fails() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            b"extra byte test",
            &K_CTX,
        )
        .expect("seal");
        let mut bytes = frame.encode();
        bytes.push(0xAA); // add extra byte
        let err = FcpcFrame::decode(&bytes).expect_err("extra byte");
        assert!(matches!(err, FcpcError::LengthMismatch { .. }));
    }

    #[test]
    fn header_session_id_all_ff() {
        let session_id = MeshSessionId([0xFF; 16]);
        let header = FcpcFrameHeader {
            version: FCPC_VERSION,
            session_id,
            seq: 0,
            flags: FcpcFrameFlags::default(),
            len: 0,
        };
        let decoded = FcpcFrameHeader::decode(&header.encode()).expect("decode");
        assert_eq!(decoded.session_id, session_id);
    }

    #[test]
    fn seal_one_byte_payload_roundtrip() {
        let session_id = MeshSessionId(SESSION_ID_BYTES);
        let dir = SessionDirection::InitiatorToResponder;
        let frame = FcpcFrame::seal(
            session_id,
            1,
            dir,
            FcpcFrameFlags::default(),
            &[0x42],
            &K_CTX,
        )
        .expect("seal");
        let encoded = frame.encode();
        let decoded = FcpcFrame::decode(&encoded).expect("decode");
        let opened = decoded.open(dir, &K_CTX).expect("open");
        assert_eq!(opened, &[0x42]);
    }

    #[test]
    fn default_replay_window_has_correct_initial_state() {
        let window = default_replay_window();
        assert_eq!(window.highest_seq(), 0);
        // The window should use SessionReplayPolicy default max_reorder_window
        let policy = SessionReplayPolicy::default();
        assert_eq!(policy.max_reorder_window, 128);
    }

    /// Regression: `decode_with_limit` must not wrap `usize` arithmetic
    /// when the caller passes a very large `max_payload_len` alongside
    /// a header whose declared length is close to `u32::MAX`. On
    /// 32-bit targets the old code did `FCPC_HEADER_LEN + claimed +
    /// FCPC_TAG_LEN`, which wraps to a small value and then either
    /// panics on subsequent slice indexing or silently admits a
    /// mismatched frame. With `checked_add` the overflow maps to
    /// `PayloadTooLarge`, failing closed. On 64-bit targets the branch
    /// is unreachable in practice; the test still documents the
    /// intended contract by driving a synthetic header through the
    /// check path.
    #[test]
    fn decode_with_limit_rejects_overflowing_claim() {
        // Craft a minimal-size input that starts with a valid header
        // whose `len` field is u32::MAX. A 64-bit build computes
        // `FCPC_HEADER_LEN + u32::MAX + FCPC_TAG_LEN` in usize space
        // cleanly (no overflow) and returns LengthMismatch because
        // bytes.len() is far smaller than the claimed total. A 32-bit
        // build would have wrapped before this fix; with `checked_add`
        // it returns PayloadTooLarge instead.
        let mut buf = vec![0u8; FCPC_HEADER_LEN + FCPC_TAG_LEN];
        buf[0..4].copy_from_slice(&FCPC_MAGIC);
        buf[4..6].copy_from_slice(&FCPC_VERSION.to_le_bytes());
        // bytes[6..22] = session_id (zero)
        // bytes[22..30] = seq (zero)
        // bytes[30..32] = flags (zero)
        buf[32..36].copy_from_slice(&u32::MAX.to_le_bytes());

        // Call with max_payload_len = usize::MAX so the caller-side
        // cap doesn't short-circuit us before the arithmetic runs.
        let err = FcpcFrame::decode_with_limit(&buf, usize::MAX).expect_err("must fail closed");
        match err {
            // 64-bit: arithmetic succeeds, LengthMismatch fires because
            // the buffer is much smaller than claimed total.
            FcpcError::LengthMismatch { claimed, actual: _ } => {
                assert_eq!(claimed, u32::MAX as usize);
            }
            // 32-bit: arithmetic overflows, PayloadTooLarge fires from
            // the checked_add fallback.
            FcpcError::PayloadTooLarge { len, .. } => {
                assert_eq!(len, u32::MAX as usize);
            }
            other => panic!(
                "expected LengthMismatch (64-bit) or PayloadTooLarge (32-bit), got {other:?}"
            ),
        }
    }
}
