//! ChaCha20-Poly1305 dispatch helpers.
//!
//! `RustCrypto` owns the low-level `ChaCha20` block-function dispatch. This module
//! gives FCP a stable backend-selection surface, failure taxonomy, and parity
//! test hooks without introducing unsafe code or changing the existing
//! `fcp-crypto` AEAD API.

use std::{env, error::Error, fmt};

use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};

use crate::cpuid::HwFeatureSet;

/// ChaCha20-Poly1305 key size in bytes.
pub const CHACHA20POLY1305_KEY_SIZE: usize = 32;
/// ChaCha20-Poly1305 nonce size in bytes.
pub const CHACHA20POLY1305_NONCE_SIZE: usize = 12;
/// Poly1305 tag size in bytes.
pub const CHACHA20POLY1305_TAG_SIZE: usize = 16;

/// FCP-facing ChaCha20-Poly1305 backend labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Chacha20Poly1305Backend {
    /// Portable scalar fallback.
    Scalar,
    /// x86 SSE3-capable backend label.
    X86Sse3,
    /// x86 AVX2-capable backend label.
    X86Avx2,
}

impl Chacha20Poly1305Backend {
    /// Stable string form for logs, docs, and JSON evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::X86Sse3 => "x86_sse3",
            Self::X86Avx2 => "x86_avx2",
        }
    }

    /// Parse an operator-facing backend label.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::UnknownBackend`] when `value` is not a
    /// supported backend label.
    pub fn parse(value: &str) -> Result<Self, Chacha20Poly1305Error> {
        match value {
            "scalar" | "portable" => Ok(Self::Scalar),
            "x86_sse3" | "sse3" => Ok(Self::X86Sse3),
            "x86_avx2" | "avx2" => Ok(Self::X86Avx2),
            other => Err(Chacha20Poly1305Error::UnknownBackend {
                value: other.to_owned(),
            }),
        }
    }
}

/// ChaCha20-Poly1305 dispatch and AEAD errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chacha20Poly1305Error {
    /// The requested backend label is unknown.
    UnknownBackend {
        /// Raw operator-provided backend name.
        value: String,
    },
    /// `FCP_CRYPTO_BACKEND` was present but not valid Unicode.
    InvalidOverrideUnicode,
    /// Encryption failed.
    EncryptFailed,
    /// Authentication failed while opening ciphertext.
    TagMismatch,
}

impl fmt::Display for Chacha20Poly1305Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBackend { value } => {
                write!(f, "unknown ChaCha20-Poly1305 backend override: {value}")
            }
            Self::InvalidOverrideUnicode => f.write_str("FCP_CRYPTO_BACKEND is not valid Unicode"),
            Self::EncryptFailed => f.write_str("ChaCha20-Poly1305 encryption failed"),
            Self::TagMismatch => f.write_str("ChaCha20-Poly1305 authentication tag mismatch"),
        }
    }
}

impl Error for Chacha20Poly1305Error {}

/// ChaCha20-Poly1305 dispatcher with an explicit selected backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chacha20Poly1305Dispatch {
    backend: Chacha20Poly1305Backend,
}

impl Chacha20Poly1305Dispatch {
    /// Build a dispatcher from detected hardware features.
    #[must_use]
    pub const fn from_features(features: HwFeatureSet) -> Self {
        Self {
            backend: select_chacha20_backend(features),
        }
    }

    /// Build a dispatcher from detected features and an optional override.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::UnknownBackend`] when `override_value`
    /// contains an unsupported backend label.
    pub fn from_features_with_override(
        features: HwFeatureSet,
        override_value: Option<&str>,
    ) -> Result<Self, Chacha20Poly1305Error> {
        let backend = match override_value {
            Some(value) if !value.trim().is_empty() => {
                Chacha20Poly1305Backend::parse(value.trim())?
            }
            _ => select_chacha20_backend(features),
        };
        Ok(Self { backend })
    }

    /// Build a dispatcher from detected features and `FCP_CRYPTO_BACKEND`.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::UnknownBackend`] when the environment
    /// value names an unsupported backend. Returns
    /// [`Chacha20Poly1305Error::InvalidOverrideUnicode`] when the environment
    /// variable is present but not valid Unicode.
    pub fn from_env(features: HwFeatureSet) -> Result<Self, Chacha20Poly1305Error> {
        match env::var("FCP_CRYPTO_BACKEND") {
            Ok(value) => Self::from_features_with_override(features, Some(&value)),
            Err(env::VarError::NotPresent) => Ok(Self::from_features(features)),
            Err(env::VarError::NotUnicode(_)) => Err(Chacha20Poly1305Error::InvalidOverrideUnicode),
        }
    }

    /// Build a dispatcher for an explicit backend.
    #[must_use]
    pub const fn with_backend(backend: Chacha20Poly1305Backend) -> Self {
        Self { backend }
    }

    /// Return the selected backend label.
    #[must_use]
    pub const fn backend(self) -> Chacha20Poly1305Backend {
        self.backend
    }

    /// Seal plaintext with associated data, returning ciphertext with tag.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::EncryptFailed`] if the AEAD layer
    /// rejects otherwise well-shaped inputs.
    pub fn seal(
        self,
        key: &[u8; CHACHA20POLY1305_KEY_SIZE],
        nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Chacha20Poly1305Error> {
        match self.backend {
            Chacha20Poly1305Backend::Scalar => seal_scalar(key, nonce, plaintext, aad),
            Chacha20Poly1305Backend::X86Sse3 => seal_sse3(key, nonce, plaintext, aad),
            Chacha20Poly1305Backend::X86Avx2 => seal_avx2(key, nonce, plaintext, aad),
        }
    }

    /// Open ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns [`Chacha20Poly1305Error::TagMismatch`] if authentication fails.
    pub fn open(
        self,
        key: &[u8; CHACHA20POLY1305_KEY_SIZE],
        nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Chacha20Poly1305Error> {
        match self.backend {
            Chacha20Poly1305Backend::Scalar => open_scalar(key, nonce, ciphertext, aad),
            Chacha20Poly1305Backend::X86Sse3 => open_sse3(key, nonce, ciphertext, aad),
            Chacha20Poly1305Backend::X86Avx2 => open_avx2(key, nonce, ciphertext, aad),
        }
    }

    /// Return every backend safe to exercise for a feature set.
    #[must_use]
    pub fn available_backends(features: HwFeatureSet) -> Vec<Chacha20Poly1305Backend> {
        let mut backends = vec![Chacha20Poly1305Backend::Scalar];
        if features.has_sse3 {
            backends.push(Chacha20Poly1305Backend::X86Sse3);
        }
        if features.has_avx2 {
            backends.push(Chacha20Poly1305Backend::X86Avx2);
        }
        backends
    }
}

/// Seal through the portable scalar RFC 8439 backend.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::EncryptFailed`] if encryption fails.
pub fn seal_scalar(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    Ok(seal_with_portable_scalar(key, nonce, plaintext, aad))
}

/// Open through the portable scalar RFC 8439 backend.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::TagMismatch`] if authentication fails.
pub fn open_scalar(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    open_with_portable_scalar(key, nonce, ciphertext, aad)
}

/// Seal through the SSE3 backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::EncryptFailed`] if encryption fails.
pub fn seal_sse3(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    seal_with_rustcrypto(key, nonce, plaintext, aad)
}

/// Open through the SSE3 backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::TagMismatch`] if authentication fails.
pub fn open_sse3(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    open_with_rustcrypto(key, nonce, ciphertext, aad)
}

/// Seal through the AVX2 backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::EncryptFailed`] if encryption fails.
pub fn seal_avx2(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    seal_with_rustcrypto(key, nonce, plaintext, aad)
}

/// Open through the AVX2 backend label.
///
/// # Errors
///
/// Returns [`Chacha20Poly1305Error::TagMismatch`] if authentication fails.
pub fn open_avx2(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    open_with_rustcrypto(key, nonce, ciphertext, aad)
}

const fn select_chacha20_backend(features: HwFeatureSet) -> Chacha20Poly1305Backend {
    if features.has_avx2 {
        Chacha20Poly1305Backend::X86Avx2
    } else if features.has_sse3 {
        Chacha20Poly1305Backend::X86Sse3
    } else {
        Chacha20Poly1305Backend::Scalar
    }
}

fn seal_with_rustcrypto(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Chacha20Poly1305Error::EncryptFailed)
}

fn open_with_rustcrypto(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Chacha20Poly1305Error::TagMismatch)
}

#[inline(never)]
fn quarter_round_scalar(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let mut sa = std::hint::black_box(state[a]);
    let mut sb = std::hint::black_box(state[b]);
    let mut sc = std::hint::black_box(state[c]);
    let mut sd = std::hint::black_box(state[d]);

    sa = sa.wrapping_add(sb);
    sd = (sd ^ sa).rotate_left(16);
    sc = sc.wrapping_add(sd);
    sb = (sb ^ sc).rotate_left(12);
    sa = sa.wrapping_add(sb);
    sd = (sd ^ sa).rotate_left(8);
    sc = sc.wrapping_add(sd);
    sb = (sb ^ sc).rotate_left(7);

    state[a] = std::hint::black_box(sa);
    state[b] = std::hint::black_box(sb);
    state[c] = std::hint::black_box(sc);
    state[d] = std::hint::black_box(sd);
}

#[inline(never)]
fn chacha20_block_scalar(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    counter: u32,
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[0] = 0x6170_7865;
    initial[1] = 0x3320_646e;
    initial[2] = 0x7962_2d32;
    initial[3] = 0x6b20_6574;

    for (idx, chunk) in key.chunks_exact(4).enumerate() {
        initial[4 + idx] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    initial[12] = counter;
    for (idx, chunk) in nonce.chunks_exact(4).enumerate() {
        initial[13 + idx] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let mut working = initial;
    for _ in 0..10 {
        quarter_round_scalar(&mut working, 0, 4, 8, 12);
        quarter_round_scalar(&mut working, 1, 5, 9, 13);
        quarter_round_scalar(&mut working, 2, 6, 10, 14);
        quarter_round_scalar(&mut working, 3, 7, 11, 15);
        quarter_round_scalar(&mut working, 0, 5, 10, 15);
        quarter_round_scalar(&mut working, 1, 6, 11, 12);
        quarter_round_scalar(&mut working, 2, 7, 8, 13);
        quarter_round_scalar(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (idx, (work_word, init_word)) in working.iter().zip(initial.iter()).enumerate() {
        let word = work_word.wrapping_add(*init_word).to_le_bytes();
        out[idx * 4..(idx + 1) * 4].copy_from_slice(&word);
    }
    out
}

fn chacha20_xor_scalar(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    initial_counter: u32,
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    input: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    for (block_idx, chunk) in input.chunks(64).enumerate() {
        let counter = initial_counter.wrapping_add(u32::try_from(block_idx).unwrap_or(0));
        let keystream = chacha20_block_scalar(key, counter, nonce);
        for (&in_byte, &ks_byte) in chunk.iter().zip(keystream.iter()) {
            output.push(in_byte ^ ks_byte);
        }
    }
    output
}

fn poly1305_accumulate_block(h_lo: &mut u128, h_hi: &mut u64, block: &[u8], r: u128) {
    let mut padded = [0u8; 17];
    padded[..block.len()].copy_from_slice(block);
    padded[block.len()] = 1;

    let mut lo_bytes = [0u8; 16];
    lo_bytes.copy_from_slice(&padded[..16]);
    let n_lo = u128::from_le_bytes(lo_bytes);
    let n_hi = u64::from(padded[16]);

    let (sum_lo, carry) = h_lo.overflowing_add(n_lo);
    let sum_hi = *h_hi + n_hi + u64::from(carry);

    let s0 = u128::from(sum_lo as u64);
    let s1 = sum_lo >> 64;
    let s2 = u128::from(sum_hi);

    let r0 = u128::from(r as u64);
    let r1 = r >> 64;

    let d0 = s0 * r0;
    let d1 = s0 * r1 + s1 * r0;
    let d2 = s1 * r1 + s2 * r0;
    let d3 = s2 * r1;

    let w0 = d0 as u64;
    let c0 = d0 >> 64;
    let t1 = d1 + c0;
    let w1 = t1 as u64;
    let c1 = t1 >> 64;
    let t2 = d2 + c1;
    let w2 = t2 as u64;
    let c2 = t2 >> 64;
    let t3 = d3 + c2;

    let l_lo = u128::from(w0) | (u128::from(w1) << 64);
    let l_hi = w2 & 3;
    let h_shifted = (u128::from(w2) >> 2) | (t3 << 62);

    let (m_lo, carry1) = l_lo.overflowing_add(h_shifted * 5);
    let m_hi = l_hi + u64::from(carry1);

    let extra = u128::from(m_hi >> 2) * 5;
    let (f_lo, carry2) = m_lo.overflowing_add(extra);
    *h_lo = f_lo;
    *h_hi = (m_hi & 3) + u64::from(carry2);
}

fn poly1305_feed_padded(h_lo: &mut u128, h_hi: &mut u64, data: &[u8], r: u128) {
    let full_chunks = data.len() / 16;
    for idx in 0..full_chunks {
        poly1305_accumulate_block(h_lo, h_hi, &data[idx * 16..(idx + 1) * 16], r);
    }
    let rem = data.len() % 16;
    if rem != 0 {
        let mut last = [0u8; 16];
        last[..rem].copy_from_slice(&data[full_chunks * 16..]);
        poly1305_accumulate_block(h_lo, h_hi, &last, r);
    }
}

fn poly1305_aead_tag_scalar(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&otk[..16]);
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;
    let r = u128::from_le_bytes(r_bytes);

    let mut s_bytes = [0u8; 16];
    s_bytes.copy_from_slice(&otk[16..32]);
    let s = u128::from_le_bytes(s_bytes);

    let mut h_lo = 0u128;
    let mut h_hi = 0u64;

    poly1305_feed_padded(&mut h_lo, &mut h_hi, aad, r);
    poly1305_feed_padded(&mut h_lo, &mut h_hi, ciphertext, r);

    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305_accumulate_block(&mut h_lo, &mut h_hi, &lengths, r);

    let (g_lo, carry) = h_lo.overflowing_add(5);
    let g_hi = h_hi + u64::from(carry);
    let final_lo = if g_hi >= 4 { g_lo } else { h_lo };

    final_lo.wrapping_add(s).to_le_bytes()
}

fn seal_with_portable_scalar(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let block0 = chacha20_block_scalar(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    let mut out = chacha20_xor_scalar(key, 1, nonce, plaintext);
    let tag = poly1305_aead_tag_scalar(&otk, aad, &out);
    out.extend_from_slice(&tag);
    out
}

fn open_with_portable_scalar(
    key: &[u8; CHACHA20POLY1305_KEY_SIZE],
    nonce: &[u8; CHACHA20POLY1305_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Chacha20Poly1305Error> {
    if ciphertext.len() < CHACHA20POLY1305_TAG_SIZE {
        return Err(Chacha20Poly1305Error::TagMismatch);
    }
    let body_len = ciphertext.len() - CHACHA20POLY1305_TAG_SIZE;
    let body = &ciphertext[..body_len];
    let provided_tag = &ciphertext[body_len..];

    let block0 = chacha20_block_scalar(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    let expected_tag = poly1305_aead_tag_scalar(&otk, aad, body);
    let mut diff = 0u8;
    for (&lhs, &rhs) in expected_tag.iter().zip(provided_tag.iter()) {
        diff |= lhs ^ rhs;
    }
    if diff != 0 {
        return Err(Chacha20Poly1305Error::TagMismatch);
    }

    Ok(chacha20_xor_scalar(key, 1, nonce, body))
}
