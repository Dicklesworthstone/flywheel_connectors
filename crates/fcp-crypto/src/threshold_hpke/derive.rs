//! FROST share → X25519 derivation for the threshold HPKE KEM.
//!
//! Per-participant X25519 public keys are the Edwards→Montgomery image
//! of their FROST verifying shares; the group X25519 key is the image
//! of the FROST group public key. Participant decap scalars are the raw
//! reduced FROST signing-share scalars (see the module-level deviation
//! note in [`crate::threshold_hpke`]: byte-level clamping would break
//! Lagrange combination and is therefore deliberately not applied).

use crate::{
    CryptoError, CryptoResult, Ed25519VerifyingKey, FrostPublicKeyPackage, FrostSigningShare,
};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};

/// Decompress an Ed25519 verifying key into its curve point.
fn edwards_point(
    verifying_key: &Ed25519VerifyingKey,
) -> CryptoResult<curve25519_dalek::edwards::EdwardsPoint> {
    CompressedEdwardsY(verifying_key.to_bytes())
        .decompress()
        .ok_or(CryptoError::InvalidPublicKey)
}

/// Group keypair images of a FROST public key package:
/// `(edwards_compressed, x25519_u_coordinate)`.
///
/// # Errors
///
/// Returns an error if the group key bytes are not decompressible.
pub fn group_keypair(pkpkg: &FrostPublicKeyPackage) -> CryptoResult<([u8; 32], [u8; 32])> {
    let ed = edwards_point(pkpkg.group_public_key())?;
    Ok((ed.compress().to_bytes(), ed.to_montgomery().to_bytes()))
}

/// Group X25519 public key of a FROST public key package.
///
/// # Errors
///
/// Returns an error if the group key bytes are not decompressible.
pub fn group_x25519_public_key(pkpkg: &FrostPublicKeyPackage) -> CryptoResult<[u8; 32]> {
    group_keypair(pkpkg).map(|(_, x25519)| x25519)
}

/// Group X25519 public key from a participant key package (same value
/// as [`group_x25519_public_key`], sourced from the key package).
///
/// # Errors
///
/// Returns an error if the group key bytes are not decompressible.
pub fn group_x25519_public_key_from_edwards_verifying_key(
    verifying_key: &Ed25519VerifyingKey,
) -> CryptoResult<[u8; 32]> {
    montgomery_from_verifying_key(verifying_key)
}

/// Montgomery image of an Ed25519 verifying key, as X25519 bytes.
pub(crate) fn montgomery_from_verifying_key(
    verifying_key: &Ed25519VerifyingKey,
) -> CryptoResult<[u8; 32]> {
    Ok(edwards_point(verifying_key)?.to_montgomery().to_bytes())
}

/// Participant decap scalar: the raw reduced FROST signing-share
/// scalar.
///
/// # Errors
///
/// Returns an error if the wrapped share bytes are not a valid
/// `frost-ed25519` signing share.
pub fn participant_scalar(signing_share: &FrostSigningShare) -> CryptoResult<Scalar> {
    Ok(signing_share.to_frost()?.to_scalar())
}

/// Lagrange coefficients `λ_i` at identifier `0` for the given 1-based
/// participant subset, in the same order as `subset`.
///
/// Valid only for the default contiguous FROST identifier numbering
/// (`1..=max_signers`), which is the model documented in
/// `crates/fcp-crypto/src/frost.rs`. Distinct identifiers guarantee a
/// nonzero denominator; `Scalar::invert` yields zero only for a zero
/// input, so a duplicated index would surface as an all-zero
/// coefficient rather than a panic.
///
/// # Errors
///
/// Never returns an error today; the signature is kept for symmetry
/// with the rest of the derivation API.
pub fn lagrange_coefficients(subset: &[u16]) -> CryptoResult<Vec<Scalar>> {
    let scalars: Vec<Scalar> = subset
        .iter()
        .map(|&index| Scalar::from(u64::from(index)))
        .collect();
    let mut coefficients = Vec::with_capacity(subset.len());
    for (i, subset_i) in subset.iter().enumerate() {
        let _ = subset_i;
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (j, subset_j) in subset.iter().enumerate() {
            if i == j {
                continue;
            }
            let _ = subset_j;
            let x_j_scalar = scalars[j];
            let x_i_scalar = scalars[i];
            numerator *= x_j_scalar;
            denominator *= x_j_scalar - x_i_scalar;
        }
        coefficients.push(numerator * denominator.invert());
    }
    Ok(coefficients)
}
