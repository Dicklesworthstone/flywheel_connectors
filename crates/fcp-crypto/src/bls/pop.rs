//! Proof of possession (PoP) and the PoP registry — the rogue-key gate.
//!
//! A BLS public key is only usable for aggregation after its owner proves
//! knowledge of the corresponding secret key by signing the key's own
//! compressed encoding under the dedicated [`BLS_POP_DST`] domain tag.
//! Verified keys live in a [`PopRegistry`]; the aggregation and
//! verification paths in [`mod@super::aggregate`] refuse any signer ID that is
//! not present, so an attacker-chosen key that never proved possession is
//! structurally unusable.

use std::collections::BTreeMap;

use bls12_381::{G1Affine, G2Affine, G2Prepared, multi_miller_loop};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::aggregate::{BlsPublicKey, hash_to_g2};
use super::{BLS_POP_DST, BLS_SIGNATURE_SIZE, BlsError};

/// Proof of possession: `H_pop(pk_compressed) * sk` in G2 (96 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofOfPossession {
    point: G2Affine,
}

impl ProofOfPossession {
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
                field: "proof of possession",
                expected: BLS_SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; BLS_SIGNATURE_SIZE];
        arr.copy_from_slice(bytes);
        let point = Option::<G2Affine>::from(G2Affine::from_compressed(&arr)).ok_or(
            BlsError::InvalidPoint {
                field: "proof of possession",
            },
        )?;
        if bool::from(point.is_identity()) {
            return Err(BlsError::InvalidPoint {
                field: "proof of possession",
            });
        }
        Ok(Self { point })
    }

    /// Verify this proof against a public key:
    /// `e(-g1, pop) · e(pk, H_pop(pk_compressed)) == 1`.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError::VerificationFailed`] if the pairing check fails.
    pub fn verify(&self, public_key: &BlsPublicKey) -> Result<(), BlsError> {
        let h = G2Prepared::from(hash_to_g2(&public_key.to_bytes(), BLS_POP_DST).to_affine());
        let pop = G2Prepared::from(self.point);
        let neg_g1 = -G1Affine::generator();
        let ok = multi_miller_loop(&[(&neg_g1, &pop), (public_key.point(), &h)])
            .final_exponentiation()
            == bls12_381::Gt::identity();
        if ok {
            Ok(())
        } else {
            Err(BlsError::VerificationFailed)
        }
    }

    pub(super) const fn from_point(point: G2Affine) -> Self {
        Self { point }
    }
}

impl Serialize for ProofOfPossession {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for ProofOfPossession {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Registry of PoP-verified public keys, keyed by signer ID.
///
/// This is the only pathway by which a key becomes usable for aggregation:
/// [`register`](Self::register) verifies the proof of possession before
/// admitting the key, and every aggregate/verify call resolves signer IDs
/// through [`get`](Self::get). Registration is idempotent for the same
/// `(signer, key)` pair and refuses to silently swap a signer's key.
#[derive(Debug, Clone, Default)]
pub struct PopRegistry {
    keys: BTreeMap<String, BlsPublicKey>,
}

impl PopRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a signer's public key after verifying its proof of
    /// possession.
    ///
    /// Re-registering the same key for the same signer is an idempotent
    /// no-op; changing a signer's key requires explicit
    /// [`remove`](Self::remove) first (key rotation must be a deliberate,
    /// auditable act).
    ///
    /// # Errors
    ///
    /// - [`BlsError::PopInvalid`] if the proof does not verify for the key.
    /// - [`BlsError::SignerAlreadyRegistered`] if the signer already has a
    ///   different key.
    pub fn register(
        &mut self,
        signer: impl Into<String>,
        public_key: BlsPublicKey,
        proof: &ProofOfPossession,
    ) -> Result<(), BlsError> {
        let signer = signer.into();
        let span = tracing::debug_span!(
            "fcp.crypto.bls.pop_register",
            signer = %signer,
            registry_size = self.keys.len(),
        );
        let _entered = span.enter();

        if let Some(existing) = self.keys.get(&signer) {
            if *existing == public_key {
                return Ok(());
            }
            return Err(BlsError::SignerAlreadyRegistered { signer });
        }

        // Defense-in-depth: reject a key already bound to a DIFFERENT signer
        // ID, so one key-holder cannot register the same key under two IDs
        // and thereby inflate a distinct-signer quorum count.
        if let Some((existing_signer, _)) = self.keys.iter().find(|(_, pk)| **pk == public_key) {
            return Err(BlsError::KeyAlreadyBound {
                existing_signer: existing_signer.clone(),
            });
        }

        if proof.verify(&public_key).is_err() {
            return Err(BlsError::PopInvalid { signer });
        }

        self.keys.insert(signer, public_key);
        // Observability hook: PoP registry size gauge.
        tracing::debug!(
            target: "fcp.crypto.bls",
            operation = "pop_register",
            registry_size = self.keys.len(),
            "registered PoP-verified BLS key"
        );
        Ok(())
    }

    /// Remove a signer's key (e.g. ahead of a deliberate key rotation).
    /// Returns the removed key, if any.
    pub fn remove(&mut self, signer: &str) -> Option<BlsPublicKey> {
        self.keys.remove(signer)
    }

    /// Look up a signer's PoP-verified key.
    #[must_use]
    pub fn get(&self, signer: &str) -> Option<&BlsPublicKey> {
        self.keys.get(signer)
    }

    /// Whether the signer has a PoP-verified key.
    #[must_use]
    pub fn contains(&self, signer: &str) -> bool {
        self.keys.contains_key(signer)
    }

    /// Number of registered signers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Iterate over `(signer, key)` pairs in sorted signer order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &BlsPublicKey)> {
        self.keys.iter().map(|(id, pk)| (id.as_str(), pk))
    }
}

#[cfg(test)]
mod tests {
    use super::super::aggregate::BlsSecretKey;
    use super::*;

    #[test]
    fn test_pop_roundtrip_verifies() {
        let sk = BlsSecretKey::generate();
        let pop = sk.prove_possession();
        pop.verify(&sk.public_key()).expect("valid PoP verifies");
    }

    #[test]
    fn test_pop_for_wrong_key_fails() {
        let sk_a = BlsSecretKey::generate();
        let sk_b = BlsSecretKey::generate();
        let pop_a = sk_a.prove_possession();
        assert_eq!(
            pop_a.verify(&sk_b.public_key()),
            Err(BlsError::VerificationFailed)
        );
    }

    #[test]
    fn test_pop_is_domain_separated_from_signatures() {
        // A message signature over the pk bytes must NOT function as a PoP:
        // the DSTs differ, so the hash points differ.
        let sk = BlsSecretKey::generate();
        let pk = sk.public_key();
        let sig_over_pk_bytes = sk.sign(&pk.to_bytes());
        let fake_pop = ProofOfPossession::from_bytes(&sig_over_pk_bytes.to_bytes()).unwrap();
        assert_eq!(fake_pop.verify(&pk), Err(BlsError::VerificationFailed));
    }

    #[test]
    fn test_registry_rejects_invalid_pop() {
        let sk = BlsSecretKey::generate();
        let other = BlsSecretKey::generate();
        let mut registry = PopRegistry::new();
        let err = registry
            .register("node-1", sk.public_key(), &other.prove_possession())
            .expect_err("mismatched PoP must be rejected");
        assert_eq!(
            err,
            BlsError::PopInvalid {
                signer: "node-1".to_string()
            }
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn test_registry_idempotent_and_key_swap_refused() {
        let sk = BlsSecretKey::generate();
        let mut registry = PopRegistry::new();
        registry
            .register("node-1", sk.public_key(), &sk.prove_possession())
            .unwrap();
        // Same (signer, key): idempotent.
        registry
            .register("node-1", sk.public_key(), &sk.prove_possession())
            .unwrap();
        assert_eq!(registry.len(), 1);

        // Different key for the same signer: refused even with a valid PoP.
        let replacement = BlsSecretKey::generate();
        let err = registry
            .register(
                "node-1",
                replacement.public_key(),
                &replacement.prove_possession(),
            )
            .expect_err("silent key swap must be refused");
        assert_eq!(
            err,
            BlsError::SignerAlreadyRegistered {
                signer: "node-1".to_string()
            }
        );

        // Deliberate rotation: remove, then register.
        registry.remove("node-1");
        registry
            .register(
                "node-1",
                replacement.public_key(),
                &replacement.prove_possession(),
            )
            .unwrap();
        assert_eq!(
            registry.get("node-1").unwrap().to_bytes(),
            replacement.public_key().to_bytes()
        );
    }

    #[test]
    fn test_same_key_under_two_ids_refused() {
        // One key-holder must not be able to register the same key under
        // two signer IDs (which would inflate a distinct-signer quorum
        // count from a single key).
        let sk = BlsSecretKey::generate();
        let mut registry = PopRegistry::new();
        registry
            .register("node-a", sk.public_key(), &sk.prove_possession())
            .unwrap();
        let err = registry
            .register("node-b", sk.public_key(), &sk.prove_possession())
            .expect_err("same key under a second ID must be rejected");
        assert_eq!(
            err,
            BlsError::KeyAlreadyBound {
                existing_signer: "node-a".to_string()
            }
        );
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_pop_bytes_length_invariance() {
        let pop = BlsSecretKey::generate().prove_possession();
        let bytes = pop.to_bytes();
        assert_eq!(bytes.len(), 96);
        assert_eq!(ProofOfPossession::from_bytes(&bytes).unwrap(), pop);

        for len in [0usize, 95, 97] {
            let err = ProofOfPossession::from_bytes(&vec![0u8; len]).unwrap_err();
            assert_eq!(
                err,
                BlsError::InvalidLength {
                    field: "proof of possession",
                    expected: 96,
                    actual: len
                }
            );
        }
    }
}
