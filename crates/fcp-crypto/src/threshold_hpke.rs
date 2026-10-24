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
//! 3. The KEM HKDF and base-mode key schedule follow RFC 9180's labeled
//!    extraction/expansion, implemented explicitly so the combiner can
//!    inject the assembled DH value. The compressed Edwards ephemeral
//!    encoding and unclamped FROST scalars make this a THRESHOLD-SPECIFIC
//!    wire format, NOT interoperable with the standard RFC 9180
//!    DHKEM(X25519) ciphertext encoding (which uses a Montgomery point).
//!    Do not parse or advertise threshold ciphertexts as ordinary HPKE.
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
//!
//! # Point admission
//!
//! Group and ephemeral keys must be canonical, nonidentity prime-order
//! Edwards points before any unclamped secret-share multiplication. Merely
//! decompressing, rejecting small-order points, or checking the final DH
//! u-coordinate does not exclude mixed-order inputs. Decap contributions
//! must also be canonical and torsion-free; identity contributions remain
//! valid for zero-valued shares. These checks do not authenticate a participant
//! or replace a proof of correct decapsulation.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher, CryptoError, CryptoResult, FrostKeyPackage,
    FrostPublicKeyPackage,
};

pub(crate) mod derive;
pub use derive::group_x25519_public_key;

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
/// Maximum sealed body size, mirroring [`fn@crate::hpke_seal`]'s cap.
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
            .finish_non_exhaustive()
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
    /// Rejects noncanonical, identity, small-order and mixed-order group keys.
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
    use std::fmt::Write as _;
    let mut out = String::with_capacity(12);
    for b in bytes.iter().take(6) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Threshold-HPKE specific failures, surfaced through
/// [`CryptoError::ThresholdHpke`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ThresholdHpkeError {
    /// A threshold of zero does not designate any decapsulating quorum.
    #[error("threshold must be at least one")]
    InvalidThreshold,
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
/// Rejects invalid signing shares, noncanonical or non-prime-order public
/// points, identity keys, and ciphertext bodies outside the wire bounds.
pub fn decap_share(
    key_package: &FrostKeyPackage,
    ct: &ThresholdHpkeCiphertext,
) -> CryptoResult<DecapShare> {
    // Validate all public material before accessing the signing-share scalar.
    // Unclamped FROST scalars must never multiply a torsion-bearing input.
    let ephemeral = decompress_ephemeral(ct)?;
    let group_x25519 =
        derive::group_x25519_public_key_from_edwards_verifying_key(key_package.group_public_key())?;
    let participant_scalar = derive::participant_scalar(key_package.signing_share())?;
    let contribution_ed = ephemeral * &participant_scalar;
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
/// - [`ThresholdHpkeError::InvalidThreshold`] for a zero threshold.
/// - [`ThresholdHpkeError::InsufficientShares`] when
///   `shares.len() < threshold`.
/// - [`ThresholdHpkeError::InconsistentShares`] when shares disagree on
///   ciphertext binding, group key, duplicate a participant, or are not
///   canonical points in the prime-order subgroup.
/// - Invalid ephemeral keys or out-of-bounds bodies surface as
///   [`CryptoError::HpkeFailed`], including directly constructed/Serde values.
/// - AEAD open failure (wrong quorum composition, tampered share/body)
///   surfaces as [`CryptoError::HpkeFailed`].
pub fn combine_decap(
    shares: &[DecapShare],
    threshold: usize,
    ct: &ThresholdHpkeCiphertext,
    info: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    // Check before indexing shares[0], including when both inputs are empty.
    if threshold == 0 {
        return Err(ThresholdHpkeError::InvalidThreshold.into());
    }
    if shares.len() < threshold {
        return Err(ThresholdHpkeError::InsufficientShares {
            got: shares.len(),
            required: threshold,
        }
        .into());
    }

    // Preserve typed threshold/participant refusals before inspecting ciphertext
    // contents, and reject duplicates before allocating interpolation inputs.
    let mut seen = std::collections::BTreeSet::new();
    for share in shares {
        if share.participant == 0 || !seen.insert(share.participant) {
            return Err(ThresholdHpkeError::InconsistentShares.into());
        }
    }

    // Serde/public fields bypass from_bytes, so every crypto entry validates.
    // Bound the body before hashing it, and compute its binding only once.
    let _ = decompress_ephemeral(ct)?;
    let group_x25519 = shares[0].group_x25519;
    let binding = ct.binding(&group_x25519);
    if shares.iter().any(|share| {
        share.group_x25519 != group_x25519 || share.binding != binding
    }) {
        return Err(ThresholdHpkeError::InconsistentShares.into());
    }
    let points = shares
        .iter()
        .map(|share| {
            derive::subgroup_point(&share.contribution).map_err(|_| {
                CryptoError::ThresholdHpke(ThresholdHpkeError::InconsistentShares)
            })
        })
        .collect::<CryptoResult<Vec<_>>>()?;

    // Lagrange-combine at zero on the Edwards curve:
    // Σ λ_i · (s_i · E) = s · E.
    let indices: Vec<u16> = shares.iter().map(|share| share.participant).collect();
    let coefficients = derive::lagrange_coefficients(&indices)?;
    let mut combined_ed: Option<curve25519_dalek::edwards::EdwardsPoint> = None;
    for (point, lambda) in points.iter().zip(&coefficients) {
        let scaled = point * lambda;
        combined_ed = Some(combined_ed.map_or(scaled, |accumulator| accumulator + scaled));
    }
    let combined_ed = combined_ed.ok_or(ThresholdHpkeError::InsufficientShares {
        got: 0,
        required: threshold,
    })?;

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
/// Rejects invalid group keys, oversized plaintext, entropy failure, a zero
/// ephemeral scalar, or AEAD failure. No invalid-input retry is performed.
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
/// Rejects invalid group keys, oversized plaintext, entropy failure, a zero
/// ephemeral scalar, or AEAD failure. No invalid-input retry is performed.
pub fn encap_with_rng<R: CryptoRng + RngCore>(
    pk: &ThresholdHpkePublicKey,
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    rng: &mut R,
) -> CryptoResult<ThresholdHpkeCiphertext> {
    if plaintext.len() > MAX_AEAD_BODY - 16 {
        return Err(CryptoError::HpkeFailed(
            "threshold plaintext exceeds body cap".into(),
        ));
    }
    // Private fields can still be supplied via Deserialize. Bind the two public
    // representations and validate the point before drawing any secret entropy.
    let group_ed = derive::key_point(&pk.group_ed)?;
    if group_ed.to_montgomery().to_bytes() != pk.group_x25519 {
        return Err(CryptoError::InvalidPublicKey);
    }
    let mut seed = [0u8; 32];
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| CryptoError::HpkeFailed("threshold entropy unavailable".into()))?;
    let ephemeral_scalar = Scalar::from_bytes_mod_order(seed);
    if ephemeral_scalar == Scalar::ZERO {
        return Err(CryptoError::HpkeFailed(
            "threshold ephemeral scalar is zero".into(),
        ));
    }
    let ephemeral_point = ED25519_BASEPOINT_POINT * &ephemeral_scalar;
    let ephemeral_pk = ephemeral_point.compress().to_bytes();

    // Sealer-side DH: e · X_ed on the Edwards point already validated above.
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

    let cipher = ChaCha20Poly1305::new((&key).into());
    let aead_body = cipher
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
    if !(16..=MAX_AEAD_BODY).contains(&ct.aead_body.len()) {
        return Err(CryptoError::HpkeFailed(
            "threshold ciphertext body is outside wire bounds".into(),
        ));
    }
    derive::key_point(&ct.ephemeral_pk).map_err(|_| {
        CryptoError::HpkeFailed(
            "threshold ephemeral point must be canonical, nonidentity and prime-order".into(),
        )
    })
}

/// RFC 9180 §4 DHKEM `ExtractAndExpand`: `prk = LabeledExtract("", suite,
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

    // RFC 9180 §5.1: LabeledExtract(shared_secret, "secret", psk).
    // Base mode has an empty PSK; the DH-derived shared secret is the
    // EXTRACT SALT, not the input key material.
    let secret =
        hkdf_extract_to_prk_bytes(Some(shared_secret), &labeled_ikm(&suite, b"secret", &[]));
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

/// RFC 9180 §4 `LabeledExtract` input:
/// `"HPKE-v1" || suite_id || label || ikm`. No label-length byte.
fn labeled_ikm(suite_id: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    out.extend_from_slice(b"HPKE-v1");
    out.extend_from_slice(suite_id);
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

/// RFC 9180 §4 `LabeledExtract` returning the PRK bytes.
fn labeled_extract_bytes(suite_id: &[u8], label: &[u8], ikm: &[u8]) -> [u8; N_SECRET] {
    hkdf_extract_to_prk_bytes(None, &labeled_ikm(suite_id, label, ikm))
}

/// RFC 9180 §4 `LabeledExpand` info:
/// `I2OSP(L,2) || "HPKE-v1" || suite_id || label || info`.
/// Neither the label nor info is length-prefixed.
fn labeled_expand_info<const N: usize>(suite_id: &[u8], label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + context.len());
    out.extend_from_slice(
        &u16::try_from(N)
            .expect("HKDF output length fits in u16")
            .to_be_bytes(),
    );
    out.extend_from_slice(b"HPKE-v1");
    out.extend_from_slice(suite_id);
    out.extend_from_slice(label);
    out.extend_from_slice(context);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only RNG: any accidental use of the panicking infallible API fails
    // the test. Invalid public input must be rejected before requesting entropy.
    #[derive(Default)]
    struct ProbeRng {
        seed: [u8; 32],
        calls: usize,
        fail: bool,
    }

    impl RngCore for ProbeRng {
        fn next_u32(&mut self) -> u32 {
            panic!("encapsulation must request a complete seed");
        }

        fn next_u64(&mut self) -> u64 {
            panic!("encapsulation must request a complete seed");
        }

        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("encapsulation must use fallible entropy");
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand::Error> {
            self.calls += 1;
            if self.fail {
                return Err(rand::Error::new(std::io::Error::other(
                    "private entropy provider diagnostic",
                )));
            }
            destination.copy_from_slice(&self.seed);
            Ok(())
        }
    }

    impl CryptoRng for ProbeRng {}

    fn scalar_public_key(secret: Scalar) -> ThresholdHpkePublicKey {
        let point = ED25519_BASEPOINT_POINT * secret;
        ThresholdHpkePublicKey {
            group_ed: point.compress().to_bytes(),
            group_x25519: point.to_montgomery().to_bytes(),
        }
    }

    #[test]
    fn key_admission_rejects_small_and_mixed_order_points_without_normalizing_them() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        for torsion in &EIGHT_TORSION {
            assert!(derive::key_point(&torsion.compress().to_bytes()).is_err());
        }
        for torsion in EIGHT_TORSION.iter().skip(1) {
            let mixed = ED25519_BASEPOINT_POINT + torsion;
            assert!(!mixed.is_small_order(), "a low-order-only check is insufficient");
            assert!(derive::key_point(&mixed.compress().to_bytes()).is_err());
            assert!(derive::subgroup_point(&mixed.compress().to_bytes()).is_err());
            assert!(derive::subgroup_point(&torsion.compress().to_bytes()).is_err());
        }
    }

    #[test]
    fn canonical_prime_order_points_are_preserved_byte_for_byte() {
        for scalar in [1u64, 2, 17, 1024] {
            let encoded = (ED25519_BASEPOINT_POINT * Scalar::from(scalar))
                .compress()
                .to_bytes();
            assert_eq!(derive::key_point(&encoded).unwrap().compress().to_bytes(), encoded);
            assert_eq!(derive::subgroup_point(&encoded).unwrap().compress().to_bytes(), encoded);
        }
    }

    #[test]
    fn noncanonical_identity_encodings_are_not_accepted_as_zero_contributions() {
        let mut negative_zero = [0u8; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        // y = p + 1 represents the identity after field reduction but is not
        // its canonical field encoding. Neither alias can enter signed data.
        let mut unreduced_identity = [0xff; 32];
        unreduced_identity[0] = 0xee;
        unreduced_identity[31] = 0x7f;
        for alias in [negative_zero, unreduced_identity] {
            assert!(derive::subgroup_point(&alias).is_err());
            assert!(derive::key_point(&alias).is_err());
        }
    }

    #[test]
    fn deserialized_public_keys_are_validated_before_entropy_is_requested() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        let valid = scalar_public_key(Scalar::from(17u64));
        let mut bad_encodings = EIGHT_TORSION
            .iter()
            .map(|point| point.compress().to_bytes())
            .collect::<Vec<_>>();
        bad_encodings.extend(EIGHT_TORSION.iter().skip(1).map(|torsion| {
            (ED25519_BASEPOINT_POINT + torsion).compress().to_bytes()
        }));
        for encoded in bad_encodings {
            let key: ThresholdHpkePublicKey = serde_json::from_value(serde_json::json!({
                "group_ed": encoded,
                "group_x25519": valid.group_x25519,
            })).unwrap();
            let mut rng = ProbeRng::default();
            assert!(matches!(encap_with_rng(&key, b"", b"", b"", &mut rng),
                Err(CryptoError::InvalidPublicKey)));
            assert_eq!(rng.calls, 0);
        }
        let mut mismatched = valid;
        mismatched.group_x25519[0] ^= 1;
        let mut rng = ProbeRng::default();
        assert!(matches!(encap_with_rng(&mismatched, b"", b"", b"", &mut rng),
            Err(CryptoError::InvalidPublicKey)));
        assert_eq!(rng.calls, 0);
    }

    #[test]
    fn oversized_plaintext_is_rejected_before_entropy_or_encryption() {
        let key = scalar_public_key(Scalar::from(17u64));
        let mut rng = ProbeRng::default();
        let too_large = vec![0; MAX_AEAD_BODY - 16 + 1];
        assert!(matches!(encap_with_rng(&key, b"", &too_large, b"", &mut rng),
            Err(CryptoError::HpkeFailed(_))));
        assert_eq!(rng.calls, 0);
    }

    #[test]
    fn failed_entropy_and_reduced_zero_scalars_return_errors_without_retry() {
        let key = scalar_public_key(Scalar::from(17u64));
        let subgroup_order: [u8; 32] = hex::decode(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ).unwrap().try_into().unwrap();
        for seed in [[0; 32], subgroup_order] {
            let mut rng = ProbeRng { seed, ..ProbeRng::default() };
            assert!(matches!(encap_with_rng(&key, b"", b"", b"", &mut rng),
                Err(CryptoError::HpkeFailed(_))));
            assert_eq!(rng.calls, 1);
        }
        let mut rng = ProbeRng { fail: true, ..ProbeRng::default() };
        let error = encap_with_rng(&key, b"", b"", b"", &mut rng).unwrap_err();
        assert!(matches!(error, CryptoError::HpkeFailed(_)));
        assert!(!error.to_string().contains("private entropy provider diagnostic"));
        assert_eq!(rng.calls, 1);
    }

    #[test]
    fn torsion_contributions_fail_as_inconsistent_shares_before_interpolation() {
        use curve25519_dalek::constants::EIGHT_TORSION;

        let ct = ThresholdHpkeCiphertext {
            ephemeral_pk: ED25519_BASEPOINT_POINT.compress().to_bytes(),
            aead_body: vec![0; 16],
        };
        let group = scalar_public_key(Scalar::from(17u64)).group_x25519;
        for torsion in EIGHT_TORSION.iter().skip(1) {
            for point in [*torsion, ED25519_BASEPOINT_POINT + torsion] {
                let share = DecapShare {
                    participant: 1,
                    contribution: point.compress().to_bytes(),
                    group_x25519: group,
                    binding: ct.binding(&group),
                };
                assert!(matches!(combine_decap(&[share], 1, &ct, b"", b""),
                    Err(CryptoError::ThresholdHpke(ThresholdHpkeError::InconsistentShares))));
            }
        }
    }

    #[test]
    fn canonical_zero_share_is_allowed_but_zero_combined_dh_is_not() {
        // f(1) = 0, f(2) = -s gives f(0) = s under weights 2 and -1.
        // Rejecting every identity contribution would reject this valid algebra.
        let secret = Scalar::from(17u64);
        let key = scalar_public_key(secret);
        let mut rng = ProbeRng { seed: [42; 32], ..ProbeRng::default() };
        let ct = encap_with_rng(&key, b"zero-share", b"plaintext", b"aad", &mut rng).unwrap();
        // Independent affine-Edwards/HMAC-SHA256/ChaCha20-Poly1305 vector.
        // This is the threshold-specific wire format, not standard X25519 HPKE.
        assert_eq!(hex::encode(key.group_ed),
            "04be97ec9bfe6ccd01f9343b7288b117b79f91cc45c24af2f93e0060ca2b6d6f");
        assert_eq!(hex::encode(key.group_x25519),
            "8d1b2458343e882b5aa7f08c18e1726b64ed42f7a8e552c23bcdbdfb185b6354");
        assert_eq!(hex::encode(ct.ephemeral_pk),
            "5773c8a9afd05be894c5c02f1d35482fa8267bad86aba65a6713619dc55cb98f");
        assert_eq!(hex::encode(&ct.aead_body),
            "fe16b874629aacfd44ec797b74daea5a43c8778c9d301f5bd4");
        let ephemeral = decompress_ephemeral(&ct).unwrap();
        let identity = (ED25519_BASEPOINT_POINT * Scalar::ZERO).compress().to_bytes();
        let binding = ct.binding(&key.group_x25519);
        let first = DecapShare {
            participant: 1, contribution: identity,
            group_x25519: key.group_x25519, binding,
        };
        let mut second = DecapShare {
            participant: 2, contribution: (ephemeral * -secret).compress().to_bytes(),
            group_x25519: key.group_x25519, binding,
        };
        let opened = combine_decap(
            &[first.clone(), second.clone()], 2, &ct, b"zero-share", b"aad",
        ).unwrap();
        assert_eq!(opened.as_slice(), b"plaintext");
        second.contribution = identity;
        assert!(matches!(combine_decap(&[first, second], 2, &ct, b"zero-share", b"aad"),
            Err(CryptoError::HpkeFailed(_))));
    }

    #[test]
    fn labeled_extract_and_expand_have_exact_rfc_9180_layouts() {
        let ikm = labeled_ikm(b"KEM\x00\x20", b"eae_prk", &[0xaa]);
        assert_eq!(ikm, b"HPKE-v1KEM\x00\x20eae_prk\xaa");
        let info = labeled_expand_info::<32>(b"KEM\x00\x20", b"shared_secret", b"context");
        assert_eq!(info, b"\x00\x20HPKE-v1KEM\x00\x20shared_secretcontext");
    }

    #[test]
    fn independently_calculated_rfc_9180_schedule_intermediates() {
        // Expected values calculated independently with Python stdlib
        // HMAC-SHA256/HKDF (not using either Rust helper or seal/open).
        // DH = 00..1f, KEM context = 20..5f. The intermediate values
        // catch both extra-length-byte and reversed Extract-salt defects.
        let dh: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).unwrap());
        let kem_context: Vec<u8> = (32u8..96).collect();
        let kem_suite = b"KEM\x00\x20";
        let eae_prk = labeled_extract_bytes(kem_suite, b"eae_prk", &dh);
        assert_eq!(
            hex::encode(eae_prk),
            "09c24e50fe25c4d58d533b9e4ca2331ff60d3b2b97ec3c893014ab9b8ef2134b"
        );
        let shared_secret = extract_and_expand(&dh, &kem_context);
        assert_eq!(
            hex::encode(shared_secret),
            "38e81c116415c86566dc21f3d99d5a395acae6aa8e187fdc052d40502a581a7a"
        );

        let suite = b"HPKE\x00\x20\x00\x01\x00\x03";
        let info = b"FCP threshold HPKE independent RFC schedule test";
        let psk_id_hash = labeled_extract_bytes(suite, b"psk_id_hash", b"");
        assert_eq!(
            hex::encode(psk_id_hash),
            "431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5"
        );
        let info_hash = labeled_extract_bytes(suite, b"info_hash", info);
        assert_eq!(
            hex::encode(info_hash),
            "9e65c73cb8a26de07c5b5a304ae3441968d2be51ea1801a739b57e45bad390b4"
        );
        let secret =
            hkdf_extract_to_prk_bytes(Some(&shared_secret), &labeled_ikm(suite, b"secret", b""));
        assert_eq!(
            hex::encode(secret),
            "f42474629ca273df3c095c777df8229321002b0e565ba48fa7eb11fea41bfdea"
        );
        let (key, nonce) = key_schedule(&shared_secret, info);
        assert_eq!(
            hex::encode(key),
            "26e279a1f50e65bc6b82a27f0956f868a8a65bc2becdfb23eff898bb22ca20da"
        );
        assert_eq!(hex::encode(nonce), "d8e8964f71113d581648b346");
    }

    /// RFC 9180 Appendix A.2.1: `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`,
    /// `ChaCha20Poly1305`, base mode. Fed the RFC's own encapsulation (standard
    /// X25519 DH and Montgomery `enc`), the module's `ExtractAndExpand`, key
    /// schedule intermediates and AEAD reproduce the published values. Only the
    /// threshold ciphertext encoding differs from RFC 9180 (deviation 2 above).
    #[test]
    fn rfc_9180_appendix_a_2_1_base_vectors() {
        let unhex = |text: &str| hex::decode(text).expect("RFC vector hex");
        let array = |text: &str| -> [u8; 32] { unhex(text).try_into().expect("32 bytes") };
        let sk_e = array("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
        let pk_r = array("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let enc = array("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        assert_eq!(
            x25519_dalek::x25519(sk_e, x25519_dalek::X25519_BASEPOINT_BYTES),
            enc,
            "enc is the RFC ephemeral public key"
        );

        let dh = x25519_dalek::x25519(sk_e, pk_r);
        let mut kem_context = enc.to_vec();
        kem_context.extend_from_slice(&pk_r);
        let shared_secret = extract_and_expand(&dh, &kem_context);
        assert_eq!(
            hex::encode(shared_secret),
            "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7"
        );

        let suite = b"HPKE\x00\x20\x00\x01\x00\x03";
        let mut context = vec![0x00];
        context.extend_from_slice(&labeled_extract_bytes(suite, b"psk_id_hash", b""));
        context.extend_from_slice(&labeled_extract_bytes(suite, b"info_hash", &info));
        assert_eq!(
            hex::encode(&context),
            concat!(
                "00431df6cd95e11ff49d7013563baf7f11588c75a6611e",
                "e2a4404a49306ae4cfc5b69c5718a60cc5876c358d3f7fc31ddb598503f67be58ea1",
                "e798c0bb19eb9796"
            )
        );
        let secret =
            hkdf_extract_to_prk_bytes(Some(&shared_secret), &labeled_ikm(suite, b"secret", b""));
        assert_eq!(
            hex::encode(secret),
            "5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6"
        );
        let (key, base_nonce) = key_schedule(&shared_secret, &info);
        assert_eq!(
            hex::encode(key),
            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91"
        );
        assert_eq!(hex::encode(base_nonce), "5c4d98150661b848853b547f");

        // A.2.1.1 sequence 0: nonce = base_nonce, as the module seals and opens.
        let plaintext = unhex("4265617574792069732074727574682c20747275746820626561757479");
        let aad = unhex("436f756e742d30");
        let sealed = ChaCha20Poly1305::new((&key).into())
            .encrypt(
                Nonce::from_slice(&base_nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .expect("seal");
        assert_eq!(
            hex::encode(&sealed),
            concat!(
                "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db",
                "21993c62ce81883d2dd1b51a28"
            )
        );
        let opened = ChaCha20Poly1305Cipher::new(&AeadKey::from_bytes(key))
            .decrypt(&ChaCha20Nonce::from_bytes(base_nonce), &sealed, &aad)
            .expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn zero_threshold_and_empty_shares_fail_as_typed_errors_not_panics() {
        let ct = ThresholdHpkeCiphertext {
            ephemeral_pk: [0; POINT_SIZE],
            aead_body: vec![0; 16],
        };
        for threshold in [0, 1, 2] {
            let error = combine_decap(&[], threshold, &ct, b"", b"").unwrap_err();
            match threshold {
                0 => assert!(matches!(
                    error,
                    CryptoError::ThresholdHpke(ThresholdHpkeError::InvalidThreshold)
                )),
                n => assert!(matches!(
                    error,
                    CryptoError::ThresholdHpke(ThresholdHpkeError::InsufficientShares {
                        got: 0, required
                    }) if required == n
                )),
            }
        }
    }

    #[test]
    fn duplicate_and_zero_participant_ids_fail_closed() {
        let ct = ThresholdHpkeCiphertext {
            ephemeral_pk: [0; POINT_SIZE],
            aead_body: vec![0; 16],
        };
        let group = [3u8; POINT_SIZE];
        let mut share = DecapShare {
            participant: 1,
            contribution: [0; POINT_SIZE],
            group_x25519: group,
            binding: ct.binding(&group),
        };
        let error = combine_decap(&[share.clone(), share.clone()], 2, &ct, b"", b"").unwrap_err();
        assert!(matches!(
            error,
            CryptoError::ThresholdHpke(ThresholdHpkeError::InconsistentShares)
        ));
        share.participant = 0;
        let error = combine_decap(&[share], 1, &ct, b"", b"").unwrap_err();
        assert!(matches!(
            error,
            CryptoError::ThresholdHpke(ThresholdHpkeError::InconsistentShares)
        ));
    }

    #[test]
    fn malformed_ciphertext_boundaries_are_rejected() {
        assert!(ThresholdHpkeCiphertext::from_bytes(&[0; POINT_SIZE + 15]).is_err());
        assert!(
            ThresholdHpkeCiphertext::from_bytes(&vec![0; POINT_SIZE + MAX_AEAD_BODY + 1]).is_err()
        );
    }
}
