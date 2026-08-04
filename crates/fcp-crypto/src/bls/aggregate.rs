//! BLS12-381 keys, signature shares, and compact aggregate signatures.
//!
//! Aggregation follows the proof-of-possession multi-signature scheme:
//! shares over the **same message** sum in G2, public keys of the listed
//! signers sum in G1, and verification is a two-pairing check
//! `e(-g1, sig_agg) · e(apk, H(msg)) == 1`. Rogue-key defense is enforced
//! structurally: signer IDs resolve through a [`PopRegistry`], which only
//! contains keys whose proof of possession verified.

use std::collections::BTreeSet;
use std::time::Instant;

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar, multi_miller_loop,
};
use ff::Field;
use group::Curve;
use rand_core::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
// bls12_381 0.8's hash-to-curve is digest-0.9 based; `sha2_09` is the
// scoped digest-0.9 sha2 alias (see Cargo.toml).
use sha2_09::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::pop::{PopRegistry, ProofOfPossession};
use super::{
    BLS_POP_DST, BLS_PUBLIC_KEY_SIZE, BLS_SECRET_KEY_SIZE, BLS_SIG_DST, BLS_SIGNATURE_SIZE,
    BlsError,
};

/// Hash a message onto G2 with the given domain-separation tag.
pub(super) fn hash_to_g2(message: &[u8], dst: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, dst)
}

/// BLS12-381 secret key (scalar). Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlsSecretKey {
    scalar: Scalar,
}

impl std::fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsSecretKey")
            .field("scalar", &"[REDACTED]")
            .finish()
    }
}

impl BlsSecretKey {
    /// Generate a fresh random secret key from the OS RNG.
    ///
    /// # Panics
    ///
    /// Panics if the OS RNG fails to provide entropy (matches the behavior
    /// of the other key generators in this crate).
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        loop {
            let mut wide = [0u8; 64];
            rng.fill_bytes(&mut wide);
            let scalar = Scalar::from_bytes_wide(&wide);
            wide.zeroize();
            if !bool::from(scalar.is_zero()) {
                return Self { scalar };
            }
        }
    }

    /// Reconstruct a secret key from canonical little-endian scalar bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::InvalidLength`] on wrong length and
    /// [`BlsError::InvalidSecretKey`] if the bytes are non-canonical or
    /// encode the zero scalar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != BLS_SECRET_KEY_SIZE {
            return Err(BlsError::InvalidLength {
                field: "secret key",
                expected: BLS_SECRET_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; BLS_SECRET_KEY_SIZE];
        arr.copy_from_slice(bytes);
        let scalar = Option::<Scalar>::from(Scalar::from_bytes(&arr));
        arr.zeroize();
        let scalar = scalar.ok_or(BlsError::InvalidSecretKey)?;
        if bool::from(scalar.is_zero()) {
            return Err(BlsError::InvalidSecretKey);
        }
        Ok(Self { scalar })
    }

    /// Export the canonical little-endian scalar bytes.
    ///
    /// Handle with care: this is raw secret material. Callers own zeroizing
    /// the returned buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BLS_SECRET_KEY_SIZE] {
        self.scalar.to_bytes()
    }

    /// Derive the G1 public key `g1 * sk`.
    #[must_use]
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey {
            point: (G1Projective::generator() * self.scalar).to_affine(),
        }
    }

    /// Sign a message: `H_sig(message) * sk` in G2.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        BlsSignature {
            point: (hash_to_g2(message, BLS_SIG_DST) * self.scalar).to_affine(),
        }
    }

    /// Produce the proof of possession `H_pop(pk_compressed) * sk` in G2.
    #[must_use]
    pub fn prove_possession(&self) -> ProofOfPossession {
        let pk = self.public_key();
        ProofOfPossession::from_point(
            (hash_to_g2(&pk.to_bytes(), BLS_POP_DST) * self.scalar).to_affine(),
        )
    }
}

/// BLS12-381 public key (compressed G1, 48 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsPublicKey {
    point: G1Affine,
}

impl BlsPublicKey {
    /// Compressed G1 encoding (48 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BLS_PUBLIC_KEY_SIZE] {
        self.point.to_compressed()
    }

    /// Decode from compressed G1 bytes, rejecting invalid encodings and the
    /// identity point.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::InvalidLength`] on wrong length and
    /// [`BlsError::InvalidPoint`] for non-curve or identity encodings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != BLS_PUBLIC_KEY_SIZE {
            return Err(BlsError::InvalidLength {
                field: "public key",
                expected: BLS_PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; BLS_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        let point = Option::<G1Affine>::from(G1Affine::from_compressed(&arr)).ok_or(
            BlsError::InvalidPoint {
                field: "public key",
            },
        )?;
        if bool::from(point.is_identity()) {
            return Err(BlsError::InvalidPoint {
                field: "public key",
            });
        }
        Ok(Self { point })
    }

    /// Verify a single (non-aggregated) signature share over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::VerificationFailed`] if the pairing check fails.
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> Result<(), BlsError> {
        let hm = G2Prepared::from(hash_to_g2(message, BLS_SIG_DST).to_affine());
        let sig = G2Prepared::from(signature.point);
        let neg_g1 = -G1Affine::generator();
        let ok = multi_miller_loop(&[(&neg_g1, &sig), (&self.point, &hm)]).final_exponentiation()
            == bls12_381::Gt::identity();
        if ok {
            Ok(())
        } else {
            Err(BlsError::VerificationFailed)
        }
    }

    pub(super) const fn point(&self) -> &G1Affine {
        &self.point
    }

    /// Construct a public key directly from a G1 point. Test-only: the
    /// rogue-key regression synthesizes an attacker key
    /// `g1*sk_atk - pk_victim` that never came from a scalar.
    #[cfg(test)]
    pub(super) const fn from_point(point: G1Affine) -> Self {
        Self { point }
    }
}

impl Serialize for BlsPublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// BLS12-381 signature share or aggregate point (compressed G2, 96 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsSignature {
    point: G2Affine,
}

impl BlsSignature {
    /// Compressed G2 encoding (96 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BLS_SIGNATURE_SIZE] {
        self.point.to_compressed()
    }

    /// Decode from compressed G2 bytes, rejecting invalid encodings and the
    /// identity point.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::InvalidLength`] on wrong length and
    /// [`BlsError::InvalidPoint`] for non-curve or identity encodings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != BLS_SIGNATURE_SIZE {
            return Err(BlsError::InvalidLength {
                field: "signature",
                expected: BLS_SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; BLS_SIGNATURE_SIZE];
        arr.copy_from_slice(bytes);
        let point = Option::<G2Affine>::from(G2Affine::from_compressed(&arr))
            .ok_or(BlsError::InvalidPoint { field: "signature" })?;
        if bool::from(point.is_identity()) {
            return Err(BlsError::InvalidPoint { field: "signature" });
        }
        Ok(Self { point })
    }

    pub(super) const fn point(&self) -> &G2Affine {
        &self.point
    }
}

impl Serialize for BlsSignature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// A compact aggregate signature: one 96-byte G2 point plus the sorted set
/// of signer IDs it claims to cover.
///
/// The signer set is part of the object (and of anything hashed over it) so
/// a verifier can resolve the exact public keys through a [`PopRegistry`]
/// and a quorum policy can count distinct signers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateSignature {
    signature: BlsSignature,
    signers: BTreeSet<String>,
}

impl AggregateSignature {
    /// The aggregate G2 signature point.
    #[must_use]
    pub const fn signature(&self) -> &BlsSignature {
        &self.signature
    }

    /// Sorted set of signer IDs covered by this aggregate.
    #[must_use]
    pub const fn signers(&self) -> &BTreeSet<String> {
        &self.signers
    }

    /// Number of distinct signers in the aggregate.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }
}

/// Aggregate signature shares over the **same message** into one 96-byte
/// signature.
///
/// Every signer ID must have a PoP-verified key in `registry` — this is the
/// rogue-key gate: an attacker-chosen key that never proved possession
/// cannot be aggregated. Shares are NOT individually verified here (an
/// invalid share surfaces as an aggregate verification failure); callers
/// that need to attribute a bad share should [`BlsPublicKey::verify`] each
/// one before aggregating.
///
/// # Errors
///
/// - [`BlsError::EmptySigners`] for an empty input.
/// - [`BlsError::DuplicateSigner`] if a signer ID appears twice.
/// - [`BlsError::PopMissing`] if a signer has no PoP-verified key.
pub fn aggregate(
    shares: &[(String, BlsSignature)],
    registry: &PopRegistry,
) -> Result<AggregateSignature, BlsError> {
    if shares.is_empty() {
        return Err(BlsError::EmptySigners);
    }

    let mut signers = BTreeSet::new();
    let mut sum = G2Projective::identity();
    for (signer, share) in shares {
        if !signers.insert(signer.clone()) {
            return Err(BlsError::DuplicateSigner {
                signer: signer.clone(),
            });
        }
        if registry.get(signer).is_none() {
            return Err(BlsError::PopMissing {
                signer: signer.clone(),
            });
        }
        sum += share.point();
    }

    tracing::debug!(
        target: "fcp.crypto.bls",
        operation = "aggregate",
        n_signers = signers.len(),
        agg_size_bytes = BLS_SIGNATURE_SIZE,
        "aggregated BLS signature shares"
    );

    Ok(AggregateSignature {
        signature: BlsSignature {
            point: sum.to_affine(),
        },
        signers,
    })
}

/// Verify an aggregate signature over `message` against the PoP registry.
///
/// Resolves every listed signer to its PoP-verified key, sums the keys in
/// G1, and checks `e(-g1, sig_agg) · e(apk, H_sig(message)) == 1` (two
/// pairings regardless of signer count). Quorum-threshold counting is a
/// separate policy concern layered on top (see `fcp_mesh::quorum`).
///
/// # Errors
///
/// - [`BlsError::EmptySigners`] if the aggregate lists no signers.
/// - [`BlsError::PopMissing`] if any listed signer is not in the registry.
/// - [`BlsError::InvalidPoint`] if the aggregated public key degenerates to
///   the identity.
/// - [`BlsError::VerificationFailed`] if the pairing check fails.
pub fn verify_aggregate(
    aggregate: &AggregateSignature,
    message: &[u8],
    registry: &PopRegistry,
) -> Result<(), BlsError> {
    let started = Instant::now();
    if aggregate.signers.is_empty() {
        return Err(BlsError::EmptySigners);
    }

    let mut apk = G1Projective::identity();
    for signer in &aggregate.signers {
        let pk = registry.get(signer).ok_or_else(|| BlsError::PopMissing {
            signer: signer.clone(),
        })?;
        apk += pk.point();
    }
    let apk = apk.to_affine();
    if bool::from(apk.is_identity()) {
        return Err(BlsError::InvalidPoint {
            field: "aggregated public key",
        });
    }

    let hm = G2Prepared::from(hash_to_g2(message, BLS_SIG_DST).to_affine());
    let sig = G2Prepared::from(*aggregate.signature.point());
    let neg_g1 = -G1Affine::generator();
    let ok = multi_miller_loop(&[(&neg_g1, &sig), (&apk, &hm)]).final_exponentiation()
        == bls12_381::Gt::identity();

    let verify_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    tracing::debug!(
        target: "fcp.crypto.bls",
        operation = "verify_aggregate",
        n_signers = aggregate.signers.len(),
        agg_size_bytes = BLS_SIGNATURE_SIZE,
        verify_us,
        accepted = ok,
        "verified BLS aggregate signature"
    );

    if ok {
        Ok(())
    } else {
        Err(BlsError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered_signers(n: usize) -> (Vec<(String, BlsSecretKey)>, PopRegistry) {
        let mut registry = PopRegistry::new();
        let signers: Vec<(String, BlsSecretKey)> = (0..n)
            .map(|i| (format!("node-{i}"), BlsSecretKey::generate()))
            .collect();
        for (id, sk) in &signers {
            registry
                .register(id.clone(), sk.public_key(), &sk.prove_possession())
                .expect("registration with valid PoP succeeds");
        }
        (signers, registry)
    }

    fn shares_over(
        signers: &[(String, BlsSecretKey)],
        message: &[u8],
    ) -> Vec<(String, BlsSignature)> {
        signers
            .iter()
            .map(|(id, sk)| (id.clone(), sk.sign(message)))
            .collect()
    }

    #[test]
    fn test_bls_aggregate_signature_verifies() {
        // k=5 registered signers; a threshold subset of 3 aggregates and
        // verifies as a single 96-byte signature.
        let (signers, registry) = registered_signers(5);
        let message = b"zone admission: node-42 -> z:work";

        let shares = shares_over(&signers[..3], message);
        let agg = aggregate(&shares, &registry).expect("aggregation succeeds");

        assert_eq!(agg.signature().to_bytes().len(), 96);
        assert_eq!(agg.signer_count(), 3);
        verify_aggregate(&agg, message, &registry).expect("aggregate verifies");
    }

    #[test]
    fn test_pop_required_before_inclusion() {
        // A signer that never registered a PoP is rejected at the
        // aggregator even though its share is a perfectly valid signature.
        let (signers, registry) = registered_signers(3);
        let message = b"quorum decision";

        let outsider = BlsSecretKey::generate();
        let mut shares = shares_over(&signers, message);
        shares.push(("outsider".to_string(), outsider.sign(message)));

        let err = aggregate(&shares, &registry).expect_err("outsider must be rejected");
        assert_eq!(
            err,
            BlsError::PopMissing {
                signer: "outsider".to_string()
            }
        );
    }

    #[test]
    fn test_rogue_key_attack_blocked() {
        // Classic rogue-key attack: the attacker publishes
        // pk_rogue = g1*sk_atk - pk_victim, so that pk_victim + pk_rogue =
        // g1*sk_atk and the attacker alone can forge an "aggregate" that
        // implicates the victim. The PoP registry blocks the key at both
        // registration (no valid PoP can be produced without knowing the
        // discrete log) and aggregation/verification (PopMissing).
        let (signers, mut registry) = registered_signers(2);
        let victim_pk = signers[0].1.public_key();
        let message = b"forged quorum decision";

        let attacker = BlsSecretKey::generate();
        let rogue_point =
            (G1Projective::from(attacker.public_key().point()) - victim_pk.point()).to_affine();
        let rogue_pk = BlsPublicKey::from_point(rogue_point);

        // The attacker cannot produce a valid PoP for the rogue key (it
        // would require the rogue key's discrete log). A PoP made with the
        // attacker's own scalar fails registration.
        let bogus_pop = attacker.prove_possession();
        let err = registry
            .register("rogue".to_string(), rogue_pk, &bogus_pop)
            .expect_err("rogue key without valid PoP must not register");
        assert_eq!(
            err,
            BlsError::PopInvalid {
                signer: "rogue".to_string()
            }
        );

        // And a forged aggregate naming the victim + unregistered rogue key
        // is rejected before any pairing math runs.
        let forged_sig = (hash_to_g2(message, BLS_SIG_DST)
            * Scalar::from_bytes(&attacker.to_bytes()).unwrap())
        .to_affine();
        let shares = vec![
            (signers[0].0.clone(), BlsSignature { point: forged_sig }),
            (
                "rogue".to_string(),
                BlsSignature {
                    point: G2Affine::generator(),
                },
            ),
        ];
        let err = aggregate(&shares, &registry).expect_err("rogue signer must be rejected");
        assert_eq!(
            err,
            BlsError::PopMissing {
                signer: "rogue".to_string()
            }
        );
    }

    #[test]
    fn test_single_share_verify_and_wrong_message_fails() {
        let sk = BlsSecretKey::generate();
        let pk = sk.public_key();
        let sig = sk.sign(b"message A");
        pk.verify(b"message A", &sig).expect("valid share verifies");
        assert_eq!(
            pk.verify(b"message B", &sig),
            Err(BlsError::VerificationFailed)
        );
    }

    #[test]
    fn test_aggregate_wrong_message_fails() {
        let (signers, registry) = registered_signers(3);
        let agg = aggregate(&shares_over(&signers, b"right message"), &registry).unwrap();
        assert_eq!(
            verify_aggregate(&agg, b"wrong message", &registry),
            Err(BlsError::VerificationFailed)
        );
    }

    #[test]
    fn test_aggregate_with_corrupted_share_fails_verification() {
        // A syntactically valid but wrong share (signed a different
        // message) aggregates fine but fails the pairing check.
        let (signers, registry) = registered_signers(5);
        let message = b"quorum decision";
        let mut shares = shares_over(&signers, message);
        shares[2].1 = signers[2].1.sign(b"something else entirely");

        let agg = aggregate(&shares, &registry).unwrap();
        assert_eq!(
            verify_aggregate(&agg, message, &registry),
            Err(BlsError::VerificationFailed)
        );
    }

    #[test]
    fn test_duplicate_signer_rejected() {
        let (signers, registry) = registered_signers(2);
        let message = b"msg";
        let mut shares = shares_over(&signers, message);
        shares.push(shares[0].clone());
        let err = aggregate(&shares, &registry).expect_err("duplicate must be rejected");
        assert_eq!(
            err,
            BlsError::DuplicateSigner {
                signer: signers[0].0.clone()
            }
        );
    }

    #[test]
    fn test_empty_aggregation_rejected() {
        let registry = PopRegistry::new();
        assert_eq!(aggregate(&[], &registry), Err(BlsError::EmptySigners));
    }

    #[test]
    fn test_secret_key_roundtrip_and_invalid_bytes() {
        let sk = BlsSecretKey::generate();
        let restored = BlsSecretKey::from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(sk.public_key().to_bytes(), restored.public_key().to_bytes());

        // BlsSecretKey deliberately has no PartialEq (secret material), so
        // compare the error side only.
        assert_eq!(
            BlsSecretKey::from_bytes(&[0u8; 31]).unwrap_err(),
            BlsError::InvalidLength {
                field: "secret key",
                expected: 32,
                actual: 31
            }
        );
        assert_eq!(
            BlsSecretKey::from_bytes(&[0u8; 32]).unwrap_err(),
            BlsError::InvalidSecretKey
        );
        // Non-canonical: 0xFF.. is >= the field modulus.
        assert_eq!(
            BlsSecretKey::from_bytes(&[0xFF; 32]).unwrap_err(),
            BlsError::InvalidSecretKey
        );
    }

    #[test]
    fn test_public_key_bytes_roundtrip_and_length_invariance() {
        let pk = BlsSecretKey::generate().public_key();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 48);
        assert_eq!(BlsPublicKey::from_bytes(&bytes).unwrap(), pk);

        for len in [0usize, 47, 49, 96] {
            let err = BlsPublicKey::from_bytes(&vec![0u8; len]).unwrap_err();
            assert_eq!(
                err,
                BlsError::InvalidLength {
                    field: "public key",
                    expected: 48,
                    actual: len
                }
            );
        }

        // Identity encoding rejected (compressed identity = 0xC0 0x00...).
        let mut identity = [0u8; 48];
        identity[0] = 0xC0;
        assert_eq!(
            BlsPublicKey::from_bytes(&identity),
            Err(BlsError::InvalidPoint {
                field: "public key"
            })
        );
    }

    #[test]
    fn test_signature_bytes_roundtrip_and_length_invariance() {
        let sig = BlsSecretKey::generate().sign(b"m");
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 96);
        assert_eq!(BlsSignature::from_bytes(&bytes).unwrap(), sig);

        for len in [0usize, 48, 95, 97] {
            let err = BlsSignature::from_bytes(&vec![0u8; len]).unwrap_err();
            assert_eq!(
                err,
                BlsError::InvalidLength {
                    field: "signature",
                    expected: 96,
                    actual: len
                }
            );
        }
    }

    #[test]
    fn test_aggregate_serde_roundtrip() {
        let (signers, registry) = registered_signers(3);
        let message = b"serde roundtrip";
        let agg = aggregate(&shares_over(&signers, message), &registry).unwrap();

        let mut cbor = Vec::new();
        ciborium::into_writer(&agg, &mut cbor).unwrap();
        let restored: AggregateSignature = ciborium::from_reader(&cbor[..]).unwrap();
        assert_eq!(restored, agg);
        verify_aggregate(&restored, message, &registry).unwrap();
    }

    #[test]
    fn test_secret_key_debug_redacted() {
        let sk = BlsSecretKey::generate();
        let rendered = format!("{sk:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&hex::encode(sk.to_bytes())));
    }
}
