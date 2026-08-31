//! Threshold HPKE: t-of-n decapsulation over the FROST substrate.
//!
//! Bead `flywheel_connectors-angoc.11.6.1` (Phase Q.G). Spec:
//! `docs/architecture/threshold_hpke_kem.md`.
//!
//! # Design
//!
//! A FROST DKG over `frost-ed25519` yields per-participant scalars
//! `s_i` with group scalar `s = Σ λ_i s_i` for any Lagrange subset of
//! size `t`. The threshold KEM maps that structure onto X25519:
//!
//! - group X25519 key `X = to_montgomery(s·G_ed)` (pure point map of
//!   the FROST group public key),
//! - participant decap contribution `P_i = to_montgomery(s_i · E_ed)`
//!   for the encapsulated ephemeral point `E_ed = e·G_ed`,
//! - combiner: `to_montgomery(Σ λ_i P_i_ed) = to_montgomery(s·E_ed)`.
//!
//! All scalar algebra runs on the Edwards curve where `curve25519-dalek`
//! exposes unclamped `Scalar` multiplication; the Montgomery form is
//! derived only for the final DH bytes (the X25519 u-coordinate).
//!
//! # Deviations from the spec text
//!
//! 1. The spec's parenthetical "RFC 7748 + clamping" is NOT applied to
//!    the participant scalars: clamping is not additive
//!    (`clamp(a)+clamp(b) != clamp(a+b)`), so clamped scalars cannot be
//!    Lagrange-combined. The unclamped reduced FROST scalars with the
//!    standard Edwards→Montgomery point mapping are the only
//!    self-consistent reading for t-of-n combination.
//! 2. The ephemeral point is published in compressed Edwards form (not
//!    bare Montgomery u-coordinates) so participants can compute
//!    unclamped contributions; it is still exactly 32 bytes.
//! 3. The KEM/key schedule follows RFC 9180 DHKEM(X25519,
//!    HKDF-SHA256) + base-mode key schedule implemented explicitly so
//!    the combiner can inject the partially-assembled DH value; the
//!    `hpke` crate's context API cannot do that.
//!
//! # Byzantine tolerance
//!
//! Every [`DecapShare`] binds the digest of the ciphertext it was
//! computed against and the group key it was derived under.
//! `combine_decap` fails with
//! [`ThresholdHpkeError::InconsistentShares`] on mismatched bindings,
//! duplicate participants, or non-decomposable contributions, and with
//! [`ThresholdHpkeError::InsufficientShares`] below threshold. A
//! malicious participant submitting a well-formed share for the same
//! ciphertext is still possible; that fails closed at AEAD open.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher, CryptoError, CryptoResult, FrostKeyPackage,
    FrostPublicKeyPackage,
};

pub(crate) mod derive;

/// HPKE ciphersuite identifiers (RFC 9180): KEM=X25519 (0x0020),
/// KDF=HKDF-SHA256 (0x0001), AEAD=ChaCha20Poly1305 (0x0003).
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0003;
const N_SECRET: usize = 32;
const N_KEY: usize = 32;
const N_NONCE: usize = 12;
/// Compressed Edwards / Montgomery point size (RFC 7748).
const POINT_SIZE: usize = 32;
/// Maximum sealed body size, mirroring [`crate::hpke_seal`]'s cap.
const MAX_AEAD_BODY: usize = 64 * 1024;

/// Group X25519 public key of a threshold quorum (opaque).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdHpkePublicKey {
    group_ed: [u8; POINT_SIZE],
    group_x25519: [u8; POINT_SIZE],
}

impl std::fmt::Debug for ThresholdHpkePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdHpkePublicKey")
            .field("group_x25519", &self.group_x25519)
            .finish()
    }
}

impl ThresholdHpkePublicKey {
    /// The group X25519 u-coordinate (Montgomery image).
    #[must_use]
    pub fn as_bytes(&self) -> [u8; POINT_SIZE] {
        self.group_x25519
    }

    /// Derive the threshold public key from a FROST public key package.
    ///
    /// The group X25519 key is the Edwards→Montgomery image of the
    /// FROST group public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the group key bytes are not a decompressible
    /// Ed25519 point.
    pub fn from_frost_pkpkg(pkpkg: &FrostPublicKeyPackage) -> CryptoResult<Self> {
        let (group_ed, group_x25519) = derive::group_keypair(pkpkg)?;
        Ok(Self {
            group_ed,
            group_x25519,
        })
    }
}

/// A participant's decapsulation contribution for one ciphertext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecapShare {
    /// 1-based FROST participant index (Lagrange identifier).
    pub participant: u16,
    /// Compressed Edwards encoding of `s_i · E`.
    pub contribution: [u8; POINT_SIZE],
    /// The group X25519 key the share was derived under (needed by the
    /// combiner's KEM context).
    pub group_x25519: [u8; POINT_SIZE],
    /// BLAKE3 digest binding this share to one ciphertext + group key.
    pub binding: [u8; 32],
}

impl std::fmt::Debug for DecapShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecapShare")
            .field("participant", &self.participant)
            .field("contribution", &self.contribution)
            .field("group_x25519", &self.group_x25519)
            .field("binding", &hex_short(&self.binding))
            .finish()
    }
}

/// Threshold HPKE ciphertext: ephemeral point + AEAD body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdHpkeCiphertext {
    /// Compressed Edwards encoding of the ephemeral point `e·G`.
    pub ephemeral_pk: [u8; POINT_SIZE],
    /// ChaCha20-Poly1305 body (ciphertext + 16-byte tag).
    pub aead_body: Vec<u8>,
}

impl ThresholdHpkeCiphertext {
    /// Wire encoding: `ephemeral_pk || aead_body`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(POINT_SIZE + self.aead_body.len());
        out.extend_from_slice(&self.ephemeral_pk);
        out.extend_from_slice(&self.aead_body);
        out
    }

    /// Parse a wire encoding.
    ///
    /// # Errors
    ///
    /// Returns an error if shorter than the ephemeral point + tag or
    /// larger than the 64 KiB body cap.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < POINT_SIZE + 16 {
            return Err(CryptoError::HpkeFailed(
                "threshold ciphertext too short".into(),
            ));
        }
        if bytes.len() > POINT_SIZE + MAX_AEAD_BODY {
            return Err(CryptoError::HpkeFailed(
                "threshold ciphertext exceeds body cap".into(),
            ));
        }
        let mut ephemeral_pk = [0u8; POINT_SIZE];
        ephemeral_pk.copy_from_slice(&bytes[..POINT_SIZE]);
        Ok(Self {
            ephemeral_pk,
            aead_body: bytes[POINT_SIZE..].to_vec(),
        })
    }

    fn binding(&self, group_x25519: &[u8; POINT_SIZE]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.ephemeral_pk);
        hasher.update(group_x25519);
        hasher.update(&self.aead_body);
        *hasher.finalize().as_bytes()
    }
}

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// Threshold-HPKE specific failures, surfaced through
/// [`CryptoError::ThresholdHpke`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ThresholdHpkeError {
    /// Fewer decap shares than the threshold.
    #[error("insufficient decap shares: got {got}, need {required}")]
    InsufficientShares {
        /// Number of shares supplied.
        got: usize,
        /// Required threshold.
        required: usize,
    },
    /// Shares disagree on ciphertext binding, group key, or participant
    /// identity (byzantine participant or mixed quorums).
    #[error("inconsistent decap shares")]
    InconsistentShares,
    /// Low-level HPKE/KEM failure.
    #[error("threshold hpke primitive failure: {0}")]
    Primitive(String),
}

/// Compute a participant's decap share for `ct`.
///
/// # Errors
///
/// Returns an error if the wrapped signing share or the ciphertext's
/// ephemeral point is invalid.
pub fn decap_share(
    key_package: &FrostKeyPackage,
    ct: &ThresholdHpkeCiphertext,
) -> CryptoResult<DecapShare> {
    let participant_scalar = derive::participant_scalar(key_package.signing_share())?;
    let ephemeral = decompress_ephemeral(ct)?;
    let contribution_ed = ephemeral * &participant_scalar;
    let group_x25519 =
        derive::group_x25519_public_key_from_edwards_verifying_key(key_package.group_public_key())?;
    Ok(DecapShare {
        participant: key_package.participant(),
        contribution: contribution_ed.compress().to_bytes(),
        group_x25519,
        binding: ct.binding(&group_x25519),
    })
}

/// Combine t-of-n decap shares and open the ciphertext.
///
/// # Errors
///
/// - [`ThresholdHpkeError::InsufficientShares`] when
///   `shares.len() < threshold`.
/// - [`ThresholdHpkeError::InconsistentShares`] when shares disagree on
///   ciphertext binding, group key, duplicate a participant, or are not
///   decompressible curve points.
/// - AEAD open failure (wrong quorum composition, tampered share/body)
///   surfaces as [`CryptoError::HpkeFailed`].
pub fn combine_decap(
    shares: &[DecapShare],
    threshold: usize,
    ct: &ThresholdHpkeCiphertext,
    info: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    if shares.len() < threshold {
        return Err(ThresholdHpkeError::InsufficientShares {
            got: shares.len(),
            required: threshold,
        }
        .into());
    }

    // All shares must bind the same ciphertext + group key and come
    // from distinct participants.
    let group_x25519 = shares[0].group_x25519;
    if shares.iter().any(|share| {
        share.group_x25519 != group_x25519 || share.binding != ct.binding(&group_x25519)
    }) {
        return Err(ThresholdHpkeError::InconsistentShares.into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for share in shares {
        if !seen.insert(share.participant) {
            return Err(ThresholdHpkeError::InconsistentShares.into());
        }
    }

    // Lagrange-combine at zero on the Edwards curve:
    // Σ λ_i · (s_i · E) = s · E.
    let indices: Vec<u16> = shares.iter().map(|share| share.participant).collect();
    let coefficients = derive::lagrange_coefficients(&indices)?;
    let mut combined_ed: Option<curve25519_dalek::edwards::EdwardsPoint> = None;
    for (share, lambda) in shares.iter().zip(&coefficients) {
        let point = CompressedEdwardsY(share.contribution)
            .decompress()
            .ok_or(ThresholdHpkeError::InconsistentShares)?;
        let scaled = point * lambda;
        combined_ed = Some(match combined_ed {
            Some(accumulator) => accumulator + scaled,
            None => scaled,
        });
    }
    let combined_ed = combined_ed.expect("threshold >= 1 guarantees at least one share");

    // The DH u-coordinate matches X25519(s, E_m).
    let dh = combined_ed.to_montgomery().to_bytes();
    if dh == [0u8; POINT_SIZE] {
        return Err(CryptoError::HpkeFailed(
            "threshold dh collapsed to the identity u-coordinate".into(),
        ));
    }

    // RFC 9180 DHKEM ExtractAndExpand with kem_context = enc || pkX.
    let mut kem_context = Vec::with_capacity(2 * POINT_SIZE);
    kem_context.extend_from_slice(&ct.ephemeral_pk);
    kem_context.extend_from_slice(&group_x25519);
    let shared_secret = extract_and_expand(&dh, &kem_context);

    // RFC 9180 base-mode key schedule.
    let (key, base_nonce) = key_schedule(&shared_secret, info);
    let cipher = ChaCha20Poly1305Cipher::new(&AeadKey::from_bytes(key));
    cipher
        .decrypt(&ChaCha20Nonce::from_bytes(base_nonce), &ct.aead_body, aad)
        .map_err(|_| CryptoError::HpkeFailed("threshold aead open failed".into()))
}

/// Encrypt + encapsulate to the threshold quorum public key.
///
/// # Errors
///
/// Returns an error on RNG or AEAD failure.
pub fn encap(
    pk: &ThresholdHpkePublicKey,
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<ThresholdHpkeCiphertext> {
    let mut rng = rand::rngs::OsRng;
    encap_with_rng(pk, info, plaintext, aad, &mut rng)
}

/// [`encap`] with a caller-provided RNG (deterministic tests).
///
/// # Errors
///
/// Returns an error on RNG or AEAD failure.
pub fn encap_with_rng<R: CryptoRng + RngCore>(
    pk: &ThresholdHpkePublicKey,
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    rng: &mut R,
) -> CryptoResult<ThresholdHpkeCiphertext> {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let ephemeral_scalar = Scalar::from_bytes_mod_order(seed);
    let ephemeral_point = ED25519_BASEPOINT_POINT * &ephemeral_scalar;
    let ephemeral_pk = ephemeral_point.compress().to_bytes();

    // Sealer-side DH: e · X_ed, computed on the Edwards group public
    // key point (decompressed from the stored Edwards group key).
    let group_ed = CompressedEdwardsY(pk.group_ed)
        .decompress()
        .ok_or_else(|| CryptoError::HpkeFailed("threshold group key not decompressible".into()))?;
    let dh_ed = group_ed * &ephemeral_scalar;
    let dh = dh_ed.to_montgomery().to_bytes();
    if dh == [0u8; POINT_SIZE] {
        return Err(CryptoError::HpkeFailed(
            "threshold dh collapsed to the identity u-coordinate".into(),
        ));
    }

    let mut kem_context = Vec::with_capacity(2 * POINT_SIZE);
    kem_context.extend_from_slice(&ephemeral_pk);
    kem_context.extend_from_slice(&pk.group_x25519);
    let shared_secret = extract_and_expand(&dh, &kem_context);
    let (key, base_nonce) = key_schedule(&shared_secret, info);

    let aead = ChaCha20Poly1305::new((&key).into());
    let aead_body = aead
        .encrypt(
            Nonce::from_slice(&base_nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::HpkeFailed("threshold aead seal failed".into()))?;

    Ok(ThresholdHpkeCiphertext {
        ephemeral_pk,
        aead_body,
    })
}

fn decompress_ephemeral(
    ct: &ThresholdHpkeCiphertext,
) -> CryptoResult<curve25519_dalek::edwards::EdwardsPoint> {
    CompressedEdwardsY(ct.ephemeral_pk)
        .decompress()
        .ok_or_else(|| {
            CryptoError::HpkeFailed("threshold ephemeral point is not decompressible".into())
        })
}

fn group_pk_bytes(key_package: &FrostKeyPackage) -> CryptoResult<[u8; POINT_SIZE]> {
    derive::group_x25519_public_key_from_edwards_verifying_key(key_package.group_public_key())
}

/// RFC 9180 §4 DHKEM ExtractAndExpand: `prk = LabeledExtract("", suite,
/// "eae_prk", dh)`; `shared_secret = LabeledExpand(prk, suite,
/// "shared_secret", kem_context)`.
fn extract_and_expand(dh: &[u8; POINT_SIZE], kem_context: &[u8]) -> [u8; N_SECRET] {
    let mut suite = Vec::with_capacity(10);
    suite.extend_from_slice(b"KEM");
    suite.extend_from_slice(&KEM_ID.to_be_bytes());

    let eae_ikm = labeled_ikm(&suite, b"eae_prk", dh);
    let eae_prk = Hkdf::<Sha256>::from_prk(&hkdf_extract_to_prk_bytes(None, &eae_ikm))
        .expect("eae_prk is 32 bytes of Hash output");

    let mut shared_secret = [0u8; N_SECRET];
    let expand_info = labeled_expand_info::<N_SECRET>(&suite, b"shared_secret", kem_context);
    eae_prk
        .expand(&expand_info, &mut shared_secret)
        .expect("shared_secret within Hash output limit");
    shared_secret
}

/// RFC 9180 §5.1 base-mode key schedule for the threshold suite.
fn key_schedule(shared_secret: &[u8; N_SECRET], info: &[u8]) -> ([u8; N_KEY], [u8; N_NONCE]) {
    let mut suite = Vec::with_capacity(20);
    suite.extend_from_slice(b"HPKE");
    suite.extend_from_slice(&KEM_ID.to_be_bytes());
    suite.extend_from_slice(&KDF_ID.to_be_bytes());
    suite.extend_from_slice(&AEAD_ID.to_be_bytes());

    let psk_id_hash = labeled_extract_bytes(&suite, b"psk_id_hash", &[]);
    let info_hash = labeled_extract_bytes(&suite, b"info_hash", info);
    let mut context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    context.push(0x00); // mode_base
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);

    let secret = labeled_extract_bytes(&suite, b"secret", shared_secret);
    let secret_hk = Hkdf::<Sha256>::from_prk(&secret).expect("secret is 32 bytes of Hash output");

    let mut key = [0u8; N_KEY];
    let key_info = labeled_expand_info::<N_KEY>(&suite, b"key", &context);
    secret_hk
        .expand(&key_info, &mut key)
        .expect("key within Hash output limit");
    let mut base_nonce = [0u8; N_NONCE];
    let nonce_info = labeled_expand_info::<N_NONCE>(&suite, b"base_nonce", &context);
    secret_hk
        .expand(&nonce_info, &mut base_nonce)
        .expect("base_nonce within Hash output limit");
    (key, base_nonce)
}

/// RFC 9180 §4 LabeledExtract IKM:
/// `"HPKE-v1" || suite_id || I2OSP(len(label),1) || label || ikm`
/// under an empty salt.
fn labeled_ikm(suite_id: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + suite_id.len() + 1 + label.len() + ikm.len());
    out.extend_from_slice(b"HPKE-v1");
    out.extend_from_slice(suite_id);
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.extend_from_slice(ikm);
    out
}

/// HKDF-Extract output bytes for a labeled extract.
fn hkdf_extract_to_prk_bytes(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; N_SECRET] {
    let (prk_output, _): (sha2::digest::Output<Sha256>, _) = Hkdf::<Sha256>::extract(salt, ikm);
    let mut prk = [0u8; N_SECRET];
    prk.copy_from_slice(&prk_output);
    prk
}

/// RFC 9180 §4 LabeledExtract returning the PRK bytes.
fn labeled_extract_bytes(suite_id: &[u8], label: &[u8], ikm: &[u8]) -> [u8; N_SECRET] {
    hkdf_extract_to_prk_bytes(None, &labeled_ikm(suite_id, label, ikm))
}

/// RFC 9180 §4 LabeledExpand info:
/// `I2OSP(L,2) || "HPKE-v1" || suite_id || I2OSP(len(label),1) || label
/// || I2OSP(len(context),2) || context`.
fn labeled_expand_info<const N: usize>(suite_id: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 7 + suite_id.len() + 1 + label.len() + 2 + context.len());
    out.extend_from_slice(&(N as u16).to_be_bytes());
    out.extend_from_slice(b"HPKE-v1");
    out.extend_from_slice(suite_id);
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.extend_from_slice(&(context.len() as u16).to_be_bytes());
    out.extend_from_slice(context);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labeled_ikm_matches_rfc_layout_shape() {
        let ikm = labeled_ikm(b"KEM\x00\x20", b"eae_prk", &[0xAA]);
        assert!(ikm.starts_with(b"HPKE-v1KEM\x00\x20"));
        assert_eq!(ikm[7 + 5], 7); // "eae_prk".len()
        assert_eq!(*ikm.last().unwrap(), 0xAA);
    }

    #[test]
    fn labeled_expand_info_carries_output_length() {
        let info = labeled_expand_info::<32>(b"KEM\x00\x20", b"shared_secret", b"context");
        assert_eq!(&info[..2], &[0u8, 32]);
        assert!(info[2..].starts_with(b"HPKE-v1KEM\x00\x20"));
    }
}
