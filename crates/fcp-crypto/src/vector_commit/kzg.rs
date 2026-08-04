//! KZG10 vector commitment over BLS12-381 (constant-size proofs).
//!
//! The vector is interpreted as evaluations of a polynomial `f` over the
//! `n`-th roots of unity: `values[i] = f(ω^i)`. Committing yields
//! `C = [f(τ)]₁` (one G1 element); an inclusion proof for slot `i` is the
//! KZG opening `π = [q(τ)]₁` of `f` at `ω^i`, where
//! `q(X) = (f(X) − values[i]) / (X − ω^i)`. Verification is the pairing
//! check `e(C − values[i]·[1]₁, [1]₂) = e(π, [τ]₂ − ω^i·[1]₂)` — two
//! pairings, independent of `n`.
//!
//! # Trusted setup
//!
//! KZG needs a structured reference string (SRS) of powers of a secret τ:
//! `[τ^0]₁ … [τ^{n−1}]₁` and `[1]₂, [τ]₂`. τ MUST be destroyed after the
//! ceremony; anyone who knows τ can forge openings. [`KzgSrs::from_ceremony`]
//! ingests a real powers-of-tau transcript. [`KzgSrs::insecure_deterministic`]
//! derives τ from a seed for tests and local development ONLY — it is
//! marked insecure precisely because τ is recoverable. Zones that cannot
//! accept a ceremony use the transparent [`super::ipa`] fallback instead.

use std::sync::Arc;

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};
use ff::{Field, PrimeField};
use group::Curve;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2_09::{Digest, Sha512};

use super::{SlotValue, VcError, VcScheme, VectorCommitmentScheme, check_domain};

/// Map a 32-byte slot value into the BLS12-381 scalar field.
///
/// The value is hashed (domain-separated SHA-512) before wide reduction,
/// rather than reduced directly. A direct `from_bytes_wide` of the raw
/// bytes reduces mod r (r < 2^255), so two distinct 32-byte values `X` and
/// `X + r` would map to the same scalar and a proof for one would verify
/// for the other — a value-binding gap. Hashing first makes the map
/// collision-resistant, so distinct 32-byte values map to distinct scalars
/// except with negligible probability, restoring byte-level binding.
fn slot_to_scalar(slot: &SlotValue) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"FCP-VC-KZG-SLOT-v1");
    hasher.update(slot);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_wide(&wide)
}

/// In-place iterative radix-2 number-theoretic transform.
///
/// Computes `out[k] = Σ_j in[j] · root^{jk}` in natural order (the
/// decimation-in-time bit-reversal is applied first). `root` must be a
/// primitive `n`-th root of unity; `n` must be a power of two.
#[allow(clippy::many_single_char_names)] // single chars mirror the NTT math
fn ntt_in_place(a: &mut [Scalar], root: Scalar) {
    let n = a.len();
    debug_assert!(n.is_power_of_two());

    // Bit-reversal permutation.
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }

    let mut len = 2usize;
    while len <= n {
        // w_len = root^(n/len): a primitive len-th root of unity.
        let w_len = root.pow_vartime(&[(n / len) as u64, 0, 0, 0]);
        let mut i = 0usize;
        while i < n {
            let mut w = Scalar::ONE;
            for k in 0..len / 2 {
                let u = a[i + k];
                let v = a[i + k + len / 2] * w;
                a[i + k] = u + v;
                a[i + k + len / 2] = u - v;
                w *= w_len;
            }
            i += len;
        }
        len <<= 1;
    }
}

/// Structured reference string: powers of τ.
#[derive(Debug, Clone)]
pub struct KzgSrs {
    /// `[τ^0]₁ … [τ^{n−1}]₁`.
    g1_powers: Vec<G1Projective>,
    /// `[1]₂`.
    g2_one: G2Affine,
    /// `[τ]₂`.
    g2_tau: G2Affine,
}

impl KzgSrs {
    /// Number of G1 powers available (max supported domain size).
    #[must_use]
    pub fn max_degree(&self) -> usize {
        self.g1_powers.len()
    }

    /// Build an SRS from a real powers-of-tau ceremony transcript.
    ///
    /// `g1_powers[j] = [τ^j]₁` and `g2_tau = [τ]₂`, with τ destroyed by the
    /// ceremony. The caller is responsible for verifying the transcript
    /// (consistency pairings) before trusting it.
    ///
    /// # Errors
    ///
    /// [`VcError::BadCommit`] if fewer than 2 powers are supplied, or if the
    /// zeroth power / `g2_one` are not the respective group generators
    /// (`verify` assumes `g1_powers[0] = [1]₁` and `g2_one = [1]₂`).
    pub fn from_ceremony(
        g1_powers: Vec<G1Projective>,
        g2_one: G2Affine,
        g2_tau: G2Affine,
    ) -> Result<Self, VcError> {
        let bad = || VcError::BadCommit {
            scheme: VcScheme::Kzg,
        };
        if g1_powers.len() < 2 {
            return Err(bad());
        }
        // `[τ^0]₁` must be the G1 generator and `[1]₂` the G2 generator;
        // otherwise the pairing check in `verify` (which hard-codes the
        // generators for the `v·[1]₁` and `z·[1]₂` terms) is inconsistent
        // with `commit`. This is a cheap structural guard, not a full
        // transcript verification (still the caller's responsibility).
        if g1_powers[0].to_affine() != G1Affine::generator() || g2_one != G2Affine::generator() {
            return Err(bad());
        }
        Ok(Self {
            g1_powers,
            g2_one,
            g2_tau,
        })
    }

    /// Derive an SRS deterministically from a seed. **Insecure**: τ is
    /// recoverable from the seed, so this is for tests and local
    /// development only — never for a zone that trusts KZG proofs.
    ///
    /// # Panics
    ///
    /// Never panics for `degree ≥ 1`.
    #[must_use]
    pub fn insecure_deterministic(degree: usize, seed: &[u8]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(b"FCP-VC-KZG-INSECURE-TAU");
        hasher.update(seed);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hasher.finalize());
        let tau = Scalar::from_bytes_wide(&wide);

        let g1 = G1Projective::generator();
        let mut powers = Vec::with_capacity(degree.max(1));
        let mut acc = Scalar::ONE;
        for _ in 0..degree.max(1) {
            powers.push(g1 * acc);
            acc *= tau;
        }

        Self {
            g1_powers: powers,
            g2_one: G2Affine::generator(),
            g2_tau: (G2Projective::generator() * tau).to_affine(),
        }
    }
}

/// Constant-size (single G1 element) commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KzgCommitment {
    point: G1Affine,
}

/// Constant-size (single G1 element) inclusion proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KzgProof {
    point: G1Affine,
}

macro_rules! g1_wrapper_serde {
    ($ty:ty, $field:literal) => {
        impl $ty {
            /// Compressed G1 encoding (48 bytes).
            #[must_use]
            pub fn to_bytes(&self) -> [u8; 48] {
                self.point.to_compressed()
            }

            /// Decode from compressed G1 bytes.
            ///
            /// # Errors
            ///
            /// [`VcError::BadCommit`] / [`VcError::BadProof`] on wrong length
            /// or an invalid point.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, VcError> {
                let arr: [u8; 48] = bytes.try_into().map_err(|_| $field)?;
                let point =
                    Option::<G1Affine>::from(G1Affine::from_compressed(&arr)).ok_or($field)?;
                Ok(Self { point })
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.to_bytes())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
                Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
            }
        }
    };
}

// The `?` in from_bytes converts the error branch into these VcError values.
impl From<&'static str> for VcError {
    fn from(field: &'static str) -> Self {
        match field {
            "commitment" => Self::BadCommit {
                scheme: VcScheme::Kzg,
            },
            _ => Self::BadProof {
                scheme: VcScheme::Kzg,
            },
        }
    }
}

g1_wrapper_serde!(KzgCommitment, "commitment");
g1_wrapper_serde!(KzgProof, "proof");

/// KZG vector commitment over a fixed power-of-two domain.
#[derive(Debug, Clone)]
pub struct KzgVectorCommitment {
    srs: Arc<KzgSrs>,
    domain: usize,
    /// Primitive `domain`-th root of unity ω.
    omega: Scalar,
    /// ω⁻¹ (for the inverse NTT).
    omega_inv: Scalar,
    /// domain⁻¹ in the scalar field (inverse-NTT scaling).
    inv_n: Scalar,
}

impl KzgVectorCommitment {
    /// Construct a KZG scheme for the given power-of-two `domain` using
    /// `srs` (which must provide at least `domain` powers).
    ///
    /// # Errors
    ///
    /// [`VcError::UnsupportedDomain`] if `domain` is not a power of two ≥ 2,
    /// or [`VcError::BadCommit`] if the SRS has too few powers.
    pub fn new(srs: Arc<KzgSrs>, domain: usize) -> Result<Self, VcError> {
        check_domain(domain)?;
        // The domain must not exceed the field's 2-adicity: ω is
        // `ROOT_OF_UNITY^(2^(S−k))` for `domain = 2^k`, which requires
        // `k ≤ S` (else the shift underflows and ω would not be a
        // primitive domain-th root). Unreachable in practice (needs a
        // 2^S-power SRS) but fail closed.
        if domain > (1usize << Scalar::S) {
            return Err(VcError::UnsupportedDomain { size: domain });
        }
        if srs.max_degree() < domain {
            return Err(VcError::BadCommit {
                scheme: VcScheme::Kzg,
            });
        }
        let k = domain.trailing_zeros();
        // ω = ROOT_OF_UNITY^(2^(S−k)) has order 2^k = domain.
        let omega = Scalar::ROOT_OF_UNITY.pow_vartime(&[1u64 << (Scalar::S - k), 0, 0, 0]);
        let omega_inv = omega.invert().expect("ω is nonzero");
        let inv_n = Scalar::from(domain as u64)
            .invert()
            .expect("domain is nonzero");
        Ok(Self {
            srs,
            domain,
            omega,
            omega_inv,
            inv_n,
        })
    }

    /// Interpolate the vector of evaluations into polynomial coefficients
    /// via inverse NTT.
    fn coefficients(&self, values: &[SlotValue]) -> Vec<Scalar> {
        let mut coeffs: Vec<Scalar> = values.iter().map(slot_to_scalar).collect();
        ntt_in_place(&mut coeffs, self.omega_inv);
        for c in &mut coeffs {
            *c *= self.inv_n;
        }
        coeffs
    }

    /// MSM `Σ scalars[j] · [τ^j]₁`.
    fn commit_coeffs(&self, coeffs: &[Scalar]) -> G1Projective {
        let mut acc = G1Projective::identity();
        for (c, p) in coeffs.iter().zip(self.srs.g1_powers.iter()) {
            acc += p * c;
        }
        acc
    }
}

impl VectorCommitmentScheme for KzgVectorCommitment {
    type Commitment = KzgCommitment;
    type Proof = KzgProof;

    fn scheme(&self) -> VcScheme {
        VcScheme::Kzg
    }

    fn domain_size(&self) -> usize {
        self.domain
    }

    fn commit(&self, values: &[SlotValue]) -> Result<Self::Commitment, VcError> {
        if values.len() != self.domain {
            return Err(VcError::LengthMismatch {
                expected: self.domain,
                actual: values.len(),
            });
        }
        let coeffs = self.coefficients(values);
        Ok(KzgCommitment {
            point: self.commit_coeffs(&coeffs).to_affine(),
        })
    }

    fn open(&self, values: &[SlotValue], index: usize) -> Result<Self::Proof, VcError> {
        if values.len() != self.domain {
            return Err(VcError::LengthMismatch {
                expected: self.domain,
                actual: values.len(),
            });
        }
        if index >= self.domain {
            return Err(VcError::IndexOutOfRange {
                index,
                domain: self.domain,
            });
        }

        let coeffs = self.coefficients(values);
        let z = self.omega.pow_vartime(&[index as u64, 0, 0, 0]);

        // Synthetic division of f(X) by (X − z): b_k = c_k + z·b_{k+1}.
        // q(X) has coefficients b_1..b_{n−1}; b_0 == f(z) = values[index].
        let n = coeffs.len();
        let mut quotient = vec![Scalar::ZERO; n - 1];
        let mut carry = Scalar::ZERO;
        for k in (0..n).rev() {
            let b = coeffs[k] + z * carry;
            if k >= 1 {
                quotient[k - 1] = b;
            }
            carry = b;
        }

        Ok(KzgProof {
            point: self.commit_coeffs(&quotient).to_affine(),
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        index: usize,
        value: &SlotValue,
        proof: &Self::Proof,
    ) -> Result<(), VcError> {
        if index >= self.domain {
            return Err(VcError::IndexOutOfRange {
                index,
                domain: self.domain,
            });
        }
        let v = slot_to_scalar(value);
        let z = self.omega.pow_vartime(&[index as u64, 0, 0, 0]);

        // A = C − v·[1]₁.
        let g1 = G1Projective::generator();
        let a = (G1Projective::from(commitment.point) - g1 * v).to_affine();

        // rhs_g2 = [τ]₂ − z·[1]₂.
        let rhs_g2 = (G2Projective::from(self.srs.g2_tau)
            - G2Projective::from(self.srs.g2_one) * z)
            .to_affine();

        // Check e(A, [1]₂) == e(π, rhs_g2) via
        // e(A, −[1]₂) · e(π, rhs_g2) == 1.
        let neg_g2_one = -self.srs.g2_one;
        let ok = bls12_381::multi_miller_loop(&[
            (&a, &G2Prepared::from(neg_g2_one)),
            (&proof.point, &G2Prepared::from(rhs_g2)),
        ])
        .final_exponentiation()
            == Gt::identity();

        if ok {
            Ok(())
        } else {
            Err(VcError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots(n: usize) -> Vec<SlotValue> {
        (0..n)
            .map(|i| {
                let mut s = [0u8; 32];
                let bytes = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes();
                s[..8].copy_from_slice(&bytes);
                s[8] = u8::try_from(i & 0xFF).expect("masked to one byte");
                s
            })
            .collect()
    }

    fn scheme(n: usize) -> KzgVectorCommitment {
        let srs = Arc::new(KzgSrs::insecure_deterministic(n, b"kzg-unit-test-seed"));
        KzgVectorCommitment::new(srs, n).unwrap()
    }

    #[test]
    fn test_ntt_roundtrip() {
        // INTT(NTT(coeffs)) == coeffs, validating the transform in isolation.
        let n = 16usize;
        let vc = scheme(n);
        let coeffs: Vec<Scalar> = (0..n).map(|i| Scalar::from(i as u64 + 1)).collect();

        let mut evals = coeffs.clone();
        ntt_in_place(&mut evals, vc.omega);

        let mut back = evals.clone();
        ntt_in_place(&mut back, vc.omega_inv);
        for c in &mut back {
            *c *= vc.inv_n;
        }
        assert_eq!(back, coeffs);

        // And the forward transform really evaluates at ω^i.
        for (i, ev) in evals.iter().enumerate() {
            let z = vc.omega.pow_vartime(&[i as u64, 0, 0, 0]);
            let mut acc = Scalar::ZERO;
            let mut zp = Scalar::ONE;
            for c in &coeffs {
                acc += c * zp;
                zp *= z;
            }
            assert_eq!(&acc, ev);
        }
    }

    #[test]
    fn test_kzg_commit_open_verify_roundtrip() {
        let n = 1024usize;
        let vc = scheme(n);
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();

        // Every slot opens and verifies against the same commitment.
        for &index in &[0usize, 1, 511, 512, 1000, n - 1] {
            let proof = vc.open(&values, index).unwrap();
            assert!(proof.to_bytes().len() == 48, "constant-size proof");
            vc.verify(&commitment, index, &values[index], &proof)
                .expect("valid inclusion proof verifies");
        }
    }

    #[test]
    fn test_kzg_wrong_index_fails() {
        let n = 1024usize;
        let vc = scheme(n);
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();

        // Proof for slot 42 must not verify claimed at slot 43...
        let proof = vc.open(&values, 42).unwrap();
        assert_eq!(
            vc.verify(&commitment, 43, &values[43], &proof),
            Err(VcError::VerificationFailed)
        );
        // ...nor with slot 42's index but slot 43's value.
        assert_eq!(
            vc.verify(&commitment, 42, &values[43], &proof),
            Err(VcError::VerificationFailed)
        );
    }

    #[test]
    fn test_kzg_wrong_value_fails() {
        let n = 256usize;
        let vc = scheme(n);
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();
        let proof = vc.open(&values, 7).unwrap();

        let mut bad_value = values[7];
        bad_value[0] ^= 0x01;
        assert_eq!(
            vc.verify(&commitment, 7, &bad_value, &proof),
            Err(VcError::VerificationFailed)
        );
    }

    #[test]
    fn test_kzg_serde_roundtrip() {
        let n = 64usize;
        let vc = scheme(n);
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();
        let proof = vc.open(&values, 9).unwrap();

        let mut c_bytes = Vec::new();
        ciborium::into_writer(&commitment, &mut c_bytes).unwrap();
        let c2: KzgCommitment = ciborium::from_reader(&c_bytes[..]).unwrap();
        let mut p_bytes = Vec::new();
        ciborium::into_writer(&proof, &mut p_bytes).unwrap();
        let p2: KzgProof = ciborium::from_reader(&p_bytes[..]).unwrap();

        vc.verify(&c2, 9, &values[9], &p2).unwrap();
    }

    #[test]
    fn test_kzg_bad_commit_decode() {
        assert_eq!(
            KzgCommitment::from_bytes(&[0u8; 10]),
            Err(VcError::BadCommit {
                scheme: VcScheme::Kzg
            })
        );
        // 48 bytes of 0xFF is not a valid compressed G1 point.
        assert_eq!(
            KzgCommitment::from_bytes(&[0xFFu8; 48]),
            Err(VcError::BadCommit {
                scheme: VcScheme::Kzg
            })
        );
    }

    #[test]
    fn test_kzg_length_mismatch() {
        let n = 32usize;
        let vc = scheme(n);
        let short = slots(n - 1);
        assert_eq!(
            vc.commit(&short),
            Err(VcError::LengthMismatch {
                expected: n,
                actual: n - 1
            })
        );
    }

    #[test]
    fn test_kzg_rejects_short_srs() {
        let srs = Arc::new(KzgSrs::insecure_deterministic(8, b"seed"));
        assert_eq!(
            KzgVectorCommitment::new(srs, 16).unwrap_err(),
            VcError::BadCommit {
                scheme: VcScheme::Kzg
            }
        );
    }
}
