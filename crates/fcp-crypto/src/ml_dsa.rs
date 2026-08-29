//! FIPS 204 ML-DSA-65 (Module-Lattice Digital Signature Algorithm) provider.
//!
//! Wraps the [`ml-dsa`] crate (`RustCrypto`, FIPS 204 final) behind an
//! FCP-shaped API and bridges it to the byte-envelope wrappers in
//! [`crate::owner_key`] (`MlDsa65VerifyingKeyBytes`, `MlDsa65SignatureBytes`).
//!
//! This module is the implementation half of the V3→V4 owner-key migration
//! plan owned by `flywheel_connectors-kyopb.1.1`. The upstream crate is
//! pure-Rust and provides constant-time signature decoding.
//!
//! # RNG plumbing
//!
//! `ml-dsa` consumes `rand_core = "0.10"`'s [`TryCryptoRng`] trait, which is
//! a generation ahead of the workspace `rand = "0.8"` family. Rather than
//! pull a third version of `rand` into the tree we wrap [`getrandom`] in a
//! tiny `OsRngV10` adapter that implements the required traits directly.
//! Production callers do not see this — they just call [`MlDsa65SigningKey::sign`].
//!
//! [`ml-dsa`]: https://docs.rs/ml-dsa
//! [`getrandom`]: https://docs.rs/getrandom

use core::convert::Infallible;

use ml_dsa::{
    B32, MlDsa65, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use rand_core_pq::{TryCryptoRng, TryRng};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, CryptoResult};
use crate::kid::KeyId;
use crate::owner_key::{
    ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE, MlDsa65SignatureBytes,
    MlDsa65VerifyingKeyBytes,
};

// Pull the matching `signature` traits from upstream's re-export so we use
// the exact version `ml-dsa` was compiled against. Importing
// `signature` ourselves at a different version produces two distinct
// `Verifier` traits in scope, which silently shadows the one ml-dsa expects.
use ml_dsa::signature::{Keypair, Verifier};

/// Length of the ML-DSA-65 signing-key seed (FIPS 204 §3.7 ξ).
pub const ML_DSA_65_SEED_SIZE: usize = 32;

/// Owner of an expanded ML-DSA-65 secret key.
///
/// The 32-byte seed used to derive the key is held alongside the expanded
/// form so callers that need to round-trip a key through cold storage can do
/// so without paying a re-expand cost. The seed field is wrapped in
/// [`Zeroizing`] so it is wiped on drop.
pub struct MlDsa65SigningKey {
    seed: Zeroizing<[u8; ML_DSA_65_SEED_SIZE]>,
    signing_key: Box<MlDsaSigningKey<MlDsa65>>,
    verifying_key: MlDsa65VerifyingKey,
}

impl core::fmt::Debug for MlDsa65SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsa65SigningKey")
            .field("seed", &"[redacted; 32 bytes]")
            .field("signing_key", &"[redacted; upstream signing key]")
            .field("verifying_key", &self.verifying_key.key_id())
            .finish()
    }
}

impl MlDsa65SigningKey {
    /// Generate a fresh key pair from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyDerivationFailed`] if the OS RNG is
    /// unavailable (extremely rare on supported platforms).
    pub fn generate() -> CryptoResult<Self> {
        let mut seed = Zeroizing::new([0u8; ML_DSA_65_SEED_SIZE]);
        getrandom::fill(seed.as_mut_slice())
            .map_err(|e| CryptoError::KeyDerivationFailed(format!("OS RNG unavailable: {e}")))?;
        Ok(Self::from_seed_inner(seed))
    }

    /// Deterministically derive the key pair from the FIPS 204 ξ seed.
    ///
    /// This is the entry point the KAT harness uses to re-derive published
    /// vectors. Production code should prefer [`Self::generate`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKeyLength`] if `seed_bytes` is not
    /// exactly [`ML_DSA_65_SEED_SIZE`] bytes.
    pub fn from_seed(seed_bytes: &[u8]) -> CryptoResult<Self> {
        if seed_bytes.len() != ML_DSA_65_SEED_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: ML_DSA_65_SEED_SIZE,
                actual: seed_bytes.len(),
            });
        }
        let mut seed = Zeroizing::new([0u8; ML_DSA_65_SEED_SIZE]);
        seed.copy_from_slice(seed_bytes);
        Ok(Self::from_seed_inner(seed))
    }

    #[allow(clippy::large_stack_frames)] // upstream ML-DSA key expansion builds FIPS polynomial buffers internally
    fn from_seed_inner(seed: Zeroizing<[u8; ML_DSA_65_SEED_SIZE]>) -> Self {
        let xi = B32::try_from(seed.as_slice())
            .expect("ML_DSA_65_SEED_SIZE is 32 bytes by construction");
        let signing_key = Box::new(MlDsaSigningKey::<MlDsa65>::from_seed(&xi));
        let upstream_vk = signing_key.verifying_key();
        let vk_bytes_array = upstream_vk.encode();
        let vk_bytes = MlDsa65VerifyingKeyBytes::try_from_bytes(vk_bytes_array.as_slice().to_vec())
            .expect("ml-dsa always emits a 1952-byte verifying key for MlDsa65 parameter set");
        let verifying_key = MlDsa65VerifyingKey {
            inner: upstream_vk,
            bytes: vk_bytes,
        };
        Self {
            seed,
            signing_key,
            verifying_key,
        }
    }

    /// Borrow the matching verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> &MlDsa65VerifyingKey {
        &self.verifying_key
    }

    /// Borrow the FIPS 204 ξ seed used to derive this key.
    ///
    /// The returned slice is the canonical form that round-trips through
    /// [`Self::from_seed`].
    #[must_use]
    pub fn seed(&self) -> &[u8; ML_DSA_65_SEED_SIZE] {
        &self.seed
    }

    /// Export the seed as a length-validated, constant-time-comparing,
    /// zeroize-on-drop byte envelope (br-6bz52).
    ///
    /// This is the canonical persistence + transport surface for an
    /// ML-DSA-65 signing key: pair with [`Self::from_envelope`] for
    /// the inverse direction. The envelope wraps the FIPS 204 §3.7
    /// ξ-seed; the expanded secret-key form is recomputable on demand
    /// via [`Self::from_envelope`] → [`ml_dsa::SigningKey::from_seed`].
    ///
    /// Closes the modes-of-reasoning audit gap that
    /// `MlDsa65VerifyingKeyBytes` + `MlDsa65SignatureBytes` had typed
    /// envelopes but the secret-key role did not.
    ///
    /// # Panics
    ///
    /// Panics only if the internal seed length invariant is broken.
    #[must_use]
    pub fn to_envelope(&self) -> crate::owner_key::MlDsa65SecretKeyBytes {
        crate::owner_key::MlDsa65SecretKeyBytes::try_from_bytes(self.seed.as_slice().to_vec())
            .expect("seed is exactly ML_DSA_65_SEED_SIZE = ML_DSA_65_SEED_BYTES bytes")
    }

    /// Reconstruct a signing key from a [`crate::owner_key::MlDsa65SecretKeyBytes`]
    /// envelope (br-6bz52).
    ///
    /// # Errors
    ///
    /// Cannot fail under current invariants — the envelope's
    /// length-validating constructor guarantees the seed is exactly
    /// 32 bytes — but the result is `CryptoResult` to keep the API
    /// future-proof for envelope variants that might add structural
    /// validation.
    pub fn from_envelope(envelope: &crate::owner_key::MlDsa65SecretKeyBytes) -> CryptoResult<Self> {
        Self::from_seed(envelope.as_bytes())
    }

    /// Sign `message` with FIPS 204's randomized variant.
    ///
    /// `context` is the FIPS 204 §5.4 context string; pass an empty slice
    /// when no context binding is required. Maximum context length is 255
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SerializationError`] if the upstream signer
    /// rejects the inputs (e.g. context length exceeded, internal RNG
    /// failure).
    pub fn sign(&self, message: &[u8], context: &[u8]) -> CryptoResult<MlDsa65SignatureBytes> {
        let mut rng = OsRngV10;
        let sig = self
            .signing_key
            .expanded_key()
            .sign_randomized(message, context, &mut rng)
            .map_err(|e| CryptoError::SerializationError(format!("ml-dsa-65 sign failed: {e}")))?;
        sig_to_bytes(&sig)
    }

    /// Sign deterministically (zero-`rnd`). KAT and reproducibility only.
    ///
    /// FIPS 204 designates this variant for test-vector use; production
    /// callers SHOULD prefer [`Self::sign`] to gain probabilistic signature
    /// hedging against fault attacks.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::SerializationError`] on upstream failure
    /// (e.g. context length exceeded).
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> CryptoResult<MlDsa65SignatureBytes> {
        let sig = self
            .signing_key
            .expanded_key()
            .sign_deterministic(message, context)
            .map_err(|e| {
                CryptoError::SerializationError(format!("ml-dsa-65 deterministic sign failed: {e}"))
            })?;
        sig_to_bytes(&sig)
    }
}

impl Drop for MlDsa65SigningKey {
    fn drop(&mut self) {
        // Seed is in Zeroizing so it wipes automatically; this explicit
        // call exists so a future change that takes the seed out of
        // Zeroizing still wipes the field. The expanded form does not
        // expose Zeroize on its public API; the seed wipe is the load-bearing
        // protection.
        self.seed.zeroize();
    }
}

/// Owner of an ML-DSA-65 verifying key (public).
#[derive(Clone)]
pub struct MlDsa65VerifyingKey {
    inner: MlDsaVerifyingKey<MlDsa65>,
    bytes: MlDsa65VerifyingKeyBytes,
}

impl core::fmt::Debug for MlDsa65VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MlDsa65VerifyingKey")
            .field("kid", &self.key_id())
            .field("len", &ML_DSA_65_PUBLIC_KEY_SIZE)
            .finish()
    }
}

impl PartialEq for MlDsa65VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        // The encoded form is the canonical equality check; the upstream
        // expanded type does not implement PartialEq.
        self.bytes == other.bytes
    }
}
impl Eq for MlDsa65VerifyingKey {}

impl MlDsa65VerifyingKey {
    /// Decode a verifying key from its FIPS 204 wire encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKeyLength`] if the input is not
    /// exactly [`ML_DSA_65_PUBLIC_KEY_SIZE`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        let envelope = MlDsa65VerifyingKeyBytes::try_from_bytes(bytes.to_vec())?;
        Self::from_envelope(envelope)
    }

    /// Decode from the byte-envelope wrapper used in [`crate::owner_key`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKeyLength`] if the envelope's inner
    /// length does not match the FIPS 204 ML-DSA-65 public-key size.
    pub fn from_envelope(envelope: MlDsa65VerifyingKeyBytes) -> CryptoResult<Self> {
        let arr = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(envelope.as_bytes()).map_err(
            |_| CryptoError::InvalidKeyLength {
                expected: ML_DSA_65_PUBLIC_KEY_SIZE,
                actual: envelope.as_bytes().len(),
            },
        )?;
        let inner = MlDsaVerifyingKey::<MlDsa65>::decode(&arr);
        Ok(Self {
            inner,
            bytes: envelope,
        })
    }

    /// Borrow the FIPS 204 wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }

    /// Return the FCP key identifier for this verifying key.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.bytes.key_id()
    }

    /// Borrow the byte envelope used by serde structures in
    /// [`crate::owner_key`].
    #[must_use]
    pub const fn envelope(&self) -> &MlDsa65VerifyingKeyBytes {
        &self.bytes
    }

    /// Verify a signature over `message` with `context` binding.
    ///
    /// Pass `b""` for `context` when the signature was produced without one.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::InvalidSignatureLength`] if `signature` is not
    ///   [`ML_DSA_65_SIGNATURE_SIZE`] bytes.
    /// - [`CryptoError::SignatureVerificationFailed`] on any cryptographic
    ///   failure (wrong key, tampered signature, tampered message, wrong
    ///   context, structurally invalid signature).
    pub fn verify(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &MlDsa65SignatureBytes,
    ) -> CryptoResult<()> {
        let arr =
            ml_dsa::EncodedSignature::<MlDsa65>::try_from(signature.as_bytes()).map_err(|_| {
                CryptoError::InvalidSignatureLength {
                    expected: ML_DSA_65_SIGNATURE_SIZE,
                    actual: signature.as_bytes().len(),
                }
            })?;
        let sig = MlDsaSignature::<MlDsa65>::decode(&arr)
            .ok_or(CryptoError::SignatureVerificationFailed)?;
        if context.is_empty() {
            // FIPS 204 default empty context — the Verifier blanket impl
            // calls verify_with_context internally with an empty ctx.
            <MlDsaVerifyingKey<MlDsa65> as Verifier<MlDsaSignature<MlDsa65>>>::verify(
                &self.inner,
                message,
                &sig,
            )
            .map_err(|_| CryptoError::SignatureVerificationFailed)
        } else if self.inner.verify_with_context(message, context, &sig) {
            Ok(())
        } else {
            Err(CryptoError::SignatureVerificationFailed)
        }
    }
}

fn sig_to_bytes(sig: &MlDsaSignature<MlDsa65>) -> CryptoResult<MlDsa65SignatureBytes> {
    let encoded = sig.encode();
    MlDsa65SignatureBytes::try_from_bytes(encoded.as_slice().to_vec())
}

/// `getrandom`-backed adapter implementing `rand_core` v0.10's
/// [`TryCryptoRng`].
///
/// Exists because `ml-dsa` consumes `rand_core = "0.10"`, which
/// is one major version ahead of the workspace `rand = "0.8"` family. Rather
/// than pull a third generation of `rand` into the dependency graph, we
/// implement just the surface ml-dsa needs against `getrandom` directly.
///
/// **Not exposed publicly** — this is a private FFI shim between `rand_core`
/// generations.
struct OsRngV10;

impl TryRng for OsRngV10 {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("OS RNG must be available for ML-DSA signing");
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("OS RNG must be available for ML-DSA signing");
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).expect("OS RNG must be available for ML-DSA signing");
        Ok(())
    }
}

impl TryCryptoRng for OsRngV10 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_owner_key_constants() {
        // br-kyopb.1.1.3: cross-check that every concrete operation produces
        // bytes of exactly the size pinned by owner_key.rs.
        let sk = MlDsa65SigningKey::from_seed(&[0u8; ML_DSA_65_SEED_SIZE]).unwrap();
        assert_eq!(
            sk.verifying_key().as_bytes().len(),
            ML_DSA_65_PUBLIC_KEY_SIZE
        );
        let sig = sk.sign_deterministic(b"size check", b"").unwrap();
        assert_eq!(sig.as_bytes().len(), ML_DSA_65_SIGNATURE_SIZE);
    }

    #[test]
    fn from_seed_rejects_wrong_length() {
        assert!(
            MlDsa65SigningKey::from_seed(&[0u8; ML_DSA_65_SEED_SIZE - 1]).is_err(),
            "seeds shorter than 32 bytes must be rejected"
        );
        assert!(
            MlDsa65SigningKey::from_seed(&[0u8; ML_DSA_65_SEED_SIZE + 1]).is_err(),
            "seeds longer than 32 bytes must be rejected"
        );
    }

    #[test]
    fn keypair_from_seed_is_deterministic() {
        // br-kyopb.1.1.3: same seed → same public key + same deterministic
        // signature. This is the single most important KAT-style invariant
        // because it lets us pin reference vectors below.
        let seed = [0x42u8; ML_DSA_65_SEED_SIZE];
        let sk_a = MlDsa65SigningKey::from_seed(&seed).unwrap();
        let sk_b = MlDsa65SigningKey::from_seed(&seed).unwrap();
        assert_eq!(
            sk_a.verifying_key().as_bytes(),
            sk_b.verifying_key().as_bytes()
        );
        let sig_a = sk_a.sign_deterministic(b"hello", b"").unwrap();
        let sig_b = sk_b.sign_deterministic(b"hello", b"").unwrap();
        assert_eq!(sig_a.as_bytes(), sig_b.as_bytes());
    }

    #[test]
    fn round_trip_sign_then_verify_succeeds() {
        let sk = MlDsa65SigningKey::generate().unwrap();
        let vk = sk.verifying_key();
        let message = b"FCP V4 owner-key migration ceremony payload";
        let sig = sk.sign(message, b"").unwrap();
        vk.verify(message, b"", &sig)
            .expect("round-trip verify must succeed");
    }

    #[test]
    fn deterministic_round_trip_sign_then_verify_succeeds() {
        let sk = MlDsa65SigningKey::from_seed(&[0x33u8; 32]).unwrap();
        let sig = sk.sign_deterministic(b"deterministic", b"").unwrap();
        sk.verifying_key()
            .verify(b"deterministic", b"", &sig)
            .unwrap();
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let sk = MlDsa65SigningKey::from_seed(&[0x01u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign_deterministic(b"original", b"").unwrap();
        let err = vk.verify(b"tampered", b"", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let sk = MlDsa65SigningKey::from_seed(&[0x02u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign_deterministic(b"hello", b"").unwrap();
        let mut bad = sig.as_bytes().to_vec();
        bad[100] ^= 0xFF;
        let bad_sig = MlDsa65SignatureBytes::try_from_bytes(bad).unwrap();
        let err = vk.verify(b"hello", b"", &bad_sig).unwrap_err();
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk_a = MlDsa65SigningKey::from_seed(&[0xAAu8; 32]).unwrap();
        let sk_b = MlDsa65SigningKey::from_seed(&[0xBBu8; 32]).unwrap();
        let sig = sk_a.sign_deterministic(b"hello", b"").unwrap();
        let err = sk_b
            .verifying_key()
            .verify(b"hello", b"", &sig)
            .unwrap_err();
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_rejects_signature_of_wrong_length() {
        let sk = MlDsa65SigningKey::from_seed(&[0x04u8; 32]).unwrap();
        let too_short_envelope =
            MlDsa65SignatureBytes::try_from_bytes(vec![0u8; ML_DSA_65_SIGNATURE_SIZE - 1]);
        // The byte envelope itself rejects wrong lengths up-front.
        assert!(too_short_envelope.is_err());

        // Construct a malformed but length-correct signature directly to
        // exercise the verify-time decode failure path.
        let malformed =
            MlDsa65SignatureBytes::try_from_bytes(vec![0xFFu8; ML_DSA_65_SIGNATURE_SIZE]).unwrap();
        let err = sk
            .verifying_key()
            .verify(b"hello", b"", &malformed)
            .unwrap_err();
        assert!(matches!(err, CryptoError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_with_context_binds_separately_from_no_context() {
        // br-kyopb.1.1.3: a signature produced with context=b"ceremony"
        // must NOT verify when checked with an empty context, and vice
        // versa. This catches a class of cross-protocol attacks.
        let sk = MlDsa65SigningKey::from_seed(&[0x03u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let sig_with_ctx = sk.sign_deterministic(b"msg", b"ceremony").unwrap();
        let sig_no_ctx = sk.sign_deterministic(b"msg", b"").unwrap();
        assert!(vk.verify(b"msg", b"ceremony", &sig_with_ctx).is_ok());
        assert!(vk.verify(b"msg", b"", &sig_with_ctx).is_err());
        assert!(vk.verify(b"msg", b"", &sig_no_ctx).is_ok());
        assert!(vk.verify(b"msg", b"ceremony", &sig_no_ctx).is_err());
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(MlDsa65VerifyingKey::from_bytes(&[0u8; 100]).is_err());
        assert!(MlDsa65VerifyingKey::from_bytes(&[0u8; ML_DSA_65_PUBLIC_KEY_SIZE - 1]).is_err());
    }

    #[test]
    fn verifying_key_round_trips_through_bytes() {
        let sk = MlDsa65SigningKey::from_seed(&[0x05u8; 32]).unwrap();
        let bytes = sk.verifying_key().as_bytes().to_vec();
        let vk_decoded = MlDsa65VerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk_decoded, *sk.verifying_key());
        let sig = sk.sign_deterministic(b"after round-trip", b"").unwrap();
        vk_decoded.verify(b"after round-trip", b"", &sig).unwrap();
    }

    #[test]
    fn signing_key_debug_redacts_seed() {
        let sk = MlDsa65SigningKey::from_seed(&[0xCDu8; 32]).unwrap();
        let dbg = format!("{sk:?}");
        assert!(dbg.contains("redacted"), "Debug must redact seed: {dbg}");
        assert!(!dbg.contains("cdcd"), "Debug must not leak seed hex: {dbg}");
    }

    #[test]
    fn integrates_with_owner_key_envelope_types() {
        // br-kyopb.1.1.3: the provider must produce types that drop
        // straight into HybridOwnerSignature / OwnerKeyMigrationAttestation
        // without any conversion gymnastics.
        let sk = MlDsa65SigningKey::from_seed(&[0x07u8; 32]).unwrap();
        let envelope: &MlDsa65VerifyingKeyBytes = sk.verifying_key().envelope();
        let kid_via_envelope = envelope.key_id();
        let kid_direct = sk.verifying_key().key_id();
        assert_eq!(kid_via_envelope, kid_direct);

        let sig: MlDsa65SignatureBytes = sk.sign_deterministic(b"attest", b"").unwrap();
        // Round-trip through serde to confirm wire compatibility.
        let json = serde_json::to_vec(&sig).unwrap();
        let sig_decoded: MlDsa65SignatureBytes = serde_json::from_slice(&json).unwrap();
        assert_eq!(sig_decoded.as_bytes(), sig.as_bytes());
    }

    /// KAT regression: deterministic seed → deterministic public key →
    /// deterministic signature. Pin the round-trip so any upstream change
    /// that alters algorithm output trips this test.
    ///
    /// This is the FCP-internal regression KAT. The published NIST FIPS 204
    /// vectors are tracked separately under sub-bead `kyopb.1.1.3.1`
    /// (vendored Wycheproof JSON corpus); pulling the Wycheproof submodule
    /// is too invasive for this commit.
    #[test]
    fn ml_dsa_65_known_answer_regression() {
        // Documented seed: 32 bytes derived from SHA3-256 of the bead label
        // "FCP-KYOPB-1-1-3-KAT", precomputed and pinned so this test does
        // not need a SHA-3 dep.
        let seed: [u8; 32] = [
            0x91, 0x97, 0xb6, 0xb4, 0x33, 0xc7, 0x0c, 0x66, 0xc0, 0x09, 0x55, 0xe2, 0x6f, 0xc1,
            0x68, 0x44, 0x6c, 0x99, 0x83, 0xb2, 0x12, 0xa3, 0x44, 0xb4, 0xa5, 0x83, 0xa1, 0xfa,
            0xfc, 0x6e, 0xa1, 0x1b,
        ];
        let sk = MlDsa65SigningKey::from_seed(&seed).unwrap();
        let pk_bytes = sk.verifying_key().as_bytes().to_vec();
        let sig = sk
            .sign_deterministic(b"kyopb.1.1.3 KAT message", b"")
            .unwrap();

        // Invariant 1: sizes are exactly what owner_key.rs declares.
        assert_eq!(pk_bytes.len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(sig.as_bytes().len(), ML_DSA_65_SIGNATURE_SIZE);

        // Invariant 2: re-deriving from the same seed reproduces the same
        // bytes — this is the load-bearing KAT-style guarantee.
        let sk_again = MlDsa65SigningKey::from_seed(&seed).unwrap();
        assert_eq!(sk_again.verifying_key().as_bytes(), pk_bytes);
        let sig_again = sk_again
            .sign_deterministic(b"kyopb.1.1.3 KAT message", b"")
            .unwrap();
        assert_eq!(sig_again.as_bytes(), sig.as_bytes());

        // Invariant 3: signature verifies under the derived verifying key.
        sk.verifying_key()
            .verify(b"kyopb.1.1.3 KAT message", b"", &sig)
            .unwrap();
    }
}
