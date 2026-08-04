//! Transparent (no trusted setup) vector commitment via a Bulletproofs
//! inner-product argument over ristretto255.
//!
//! This is the fallback for zones with a trusted-setup ban (the Halo2/IPA
//! path). A commitment is a single 32-byte ristretto point
//! `C = Σ values[i]·G_i`; an inclusion proof that slot `index` holds `y`
//! reduces to proving the inner product `⟨values, e_index⟩ = y`, argued in
//! `⌈log2 n⌉` folding rounds. The proof is `2·⌈log2 n⌉` 32-byte points
//! (the `L_j`/`R_j` per round) plus two final 32-byte scalars.
//!
//! Generators `G_i`, `H_i`, and `Q` are derived by hashing domain-separated
//! labels to ristretto points (nothing-up-my-sleeve), so there is no secret
//! and no ceremony. The argument follows Bünz–Bootle–Boneh–Poelstra–Wuille–
//! Maxwell, "Bulletproofs" (IEEE S&P 2018) §3; the same inner-product
//! argument underlies Halo2's polynomial commitment.

use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use curve25519_dalek::{RistrettoPoint, Scalar};
use serde::{Deserialize, Serialize};
use sha2_09::{Digest, Sha512};

use super::{SlotValue, VcError, VcScheme, VectorCommitmentScheme, check_domain};

/// Map a 32-byte slot value into the ristretto scalar field.
///
/// The value is hashed (domain-separated SHA-512) before wide reduction
/// rather than reduced directly: a direct reduction mod the group order `l`
/// (`l < 2^253`) would let two distinct 32-byte values `X` and `X + l` map
/// to the same scalar, so a proof for one would verify for the other.
/// Hashing first makes the map collision-resistant, restoring byte-level
/// binding.
fn slot_to_scalar(slot: &SlotValue) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"FCP-VC-IPA-SLOT-v1");
    hasher.update(slot);
    hash_to_scalar(hasher)
}

/// Derive generator `label[index]` by hashing to a ristretto point.
fn gen_point(label: &[u8], index: usize) -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"FCP-VC-IPA-GEN");
    hasher.update(label);
    hasher.update((index as u64).to_le_bytes());
    hash_to_point(hasher)
}

fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Square a scalar via multiplication (avoids `ff::Field::square` trait
/// ambiguity introduced by curve25519-dalek's `group` feature).
fn sq(s: Scalar) -> Scalar {
    s * s
}

/// Reduce a 64-byte hash to a ristretto scalar.
fn hash_to_scalar(hasher: Sha512) -> Scalar {
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Map a 64-byte hash to a ristretto point.
fn hash_to_point(hasher: Sha512) -> RistrettoPoint {
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Fiat-Shamir transcript: a SHA-512 hash chain over public values.
struct Transcript {
    state: Sha512,
}

impl Transcript {
    fn new(domain: usize, commitment: &RistrettoPoint, index: usize, value: &Scalar) -> Self {
        let mut state = Sha512::new();
        state.update(b"FCP-VC-IPA-v1");
        state.update((domain as u64).to_le_bytes());
        state.update(commitment.compress().to_bytes());
        state.update((index as u64).to_le_bytes());
        state.update(value.to_bytes());
        Self { state }
    }

    fn absorb_point(&mut self, point: &RistrettoPoint) {
        self.state.update(point.compress().to_bytes());
    }

    /// Squeeze a challenge scalar and re-key the transcript with it so
    /// subsequent absorbs chain.
    fn challenge(&mut self) -> Scalar {
        let challenge = hash_to_scalar(self.state.clone());
        // Re-key: fold the challenge back into the running state.
        self.state.update(b"challenge");
        self.state.update(challenge.to_bytes());
        challenge
    }
}

/// A ristretto Pedersen vector commitment (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpaCommitment {
    point: RistrettoPoint,
}

impl IpaCommitment {
    /// Compressed ristretto encoding (32 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Decode from compressed ristretto bytes.
    ///
    /// # Errors
    ///
    /// [`VcError::BadCommit`] on wrong length or an invalid point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VcError> {
        let point = decompress(bytes).ok_or(VcError::BadCommit {
            scheme: VcScheme::Ipa,
        })?;
        Ok(Self { point })
    }
}

impl Serialize for IpaCommitment {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for IpaCommitment {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

fn decompress(bytes: &[u8]) -> Option<RistrettoPoint> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    curve25519_dalek::ristretto::CompressedRistretto(arr).decompress()
}

/// A logarithmic-size inclusion proof: the per-round `L_j`/`R_j` points and
/// the two final folded scalars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpaProof {
    #[serde(with = "point_vec")]
    l_vec: Vec<RistrettoPoint>,
    #[serde(with = "point_vec")]
    r_vec: Vec<RistrettoPoint>,
    #[serde(with = "scalar_bytes")]
    a: Scalar,
    #[serde(with = "scalar_bytes")]
    b: Scalar,
}

impl IpaProof {
    /// Size in bytes of the logarithmic (round) part of the proof:
    /// `(|L| + |R|)·32`. This is the part that scales with the vector
    /// length; the full serialized proof adds a constant 64 bytes for the
    /// two final scalars.
    #[must_use]
    pub fn rounds_size_bytes(&self) -> usize {
        (self.l_vec.len() + self.r_vec.len()) * 32
    }

    /// Number of folding rounds (`⌈log2 n⌉`).
    #[must_use]
    pub fn rounds(&self) -> usize {
        self.l_vec.len()
    }
}

mod point_vec {
    use super::{RistrettoPoint, decompress};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        points: &[RistrettoPoint],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let raw: Vec<serde_bytes::ByteBuf> = points
            .iter()
            .map(|p| serde_bytes::ByteBuf::from(p.compress().to_bytes().to_vec()))
            .collect();
        raw.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<RistrettoPoint>, D::Error> {
        let raw: Vec<serde_bytes::ByteBuf> = Vec::deserialize(deserializer)?;
        raw.iter()
            .map(|b| {
                decompress(b).ok_or_else(|| serde::de::Error::custom("invalid ristretto point"))
            })
            .collect()
    }
}

mod scalar_bytes {
    use super::Scalar;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&scalar.to_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Scalar, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let arr: [u8; 32] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| serde::de::Error::custom("scalar must be 32 bytes"))?;
        Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
            .ok_or_else(|| serde::de::Error::custom("non-canonical scalar"))
    }
}

/// IPA vector commitment over a fixed power-of-two domain.
#[derive(Debug, Clone)]
pub struct IpaVectorCommitment {
    domain: usize,
    g_vec: Vec<RistrettoPoint>,
    h_vec: Vec<RistrettoPoint>,
    q: RistrettoPoint,
}

impl IpaVectorCommitment {
    /// Construct an IPA scheme for the given power-of-two `domain`. All
    /// generators are derived deterministically — no trusted setup.
    ///
    /// # Errors
    ///
    /// [`VcError::UnsupportedDomain`] if `domain` is not a power of two ≥ 2.
    pub fn new(domain: usize) -> Result<Self, VcError> {
        check_domain(domain)?;
        let g_vec = (0..domain).map(|i| gen_point(b"G", i)).collect();
        let h_vec = (0..domain).map(|i| gen_point(b"H", i)).collect();
        let q = gen_point(b"Q", 0);
        Ok(Self {
            domain,
            g_vec,
            h_vec,
            q,
        })
    }

    /// The statement point `P = C + H_index + y·Q` that both parties derive
    /// from public data.
    fn statement_point(
        &self,
        commitment: &RistrettoPoint,
        index: usize,
        y: &Scalar,
    ) -> RistrettoPoint {
        *commitment + self.h_vec[index] + self.q * y
    }
}

impl VectorCommitmentScheme for IpaVectorCommitment {
    type Commitment = IpaCommitment;
    type Proof = IpaProof;

    fn scheme(&self) -> VcScheme {
        VcScheme::Ipa
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
        let scalars: Vec<Scalar> = values.iter().map(slot_to_scalar).collect();
        let point = RistrettoPoint::vartime_multiscalar_mul(scalars.iter(), self.g_vec.iter());
        Ok(IpaCommitment { point })
    }

    #[allow(clippy::many_single_char_names)] // single chars mirror the Bulletproofs folding
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

        let mut a: Vec<Scalar> = values.iter().map(slot_to_scalar).collect();
        // b = e_index (unit vector); ⟨a, b⟩ = a[index] = the opened value.
        let mut b: Vec<Scalar> = vec![Scalar::ZERO; self.domain];
        b[index] = Scalar::ONE;
        let y = a[index];

        let commitment = RistrettoPoint::vartime_multiscalar_mul(a.iter(), self.g_vec.iter());
        let mut transcript = Transcript::new(self.domain, &commitment, index, &y);

        let mut g = self.g_vec.clone();
        let mut h = self.h_vec.clone();
        let mut n = self.domain;
        let lg_n = n.trailing_zeros() as usize;
        let mut l_vec = Vec::with_capacity(lg_n);
        let mut r_vec = Vec::with_capacity(lg_n);

        while n > 1 {
            let half = n / 2;
            let (a_lo, a_hi) = a.split_at(half);
            let (b_lo, b_hi) = b.split_at(half);
            let (g_lo, g_hi) = g.split_at(half);
            let (h_lo, h_hi) = h.split_at(half);

            let c_l = inner_product(a_lo, b_hi);
            let c_r = inner_product(a_hi, b_lo);

            // L = ⟨a_lo, G_hi⟩ + ⟨b_hi, H_lo⟩ + c_l·Q
            let l = RistrettoPoint::vartime_multiscalar_mul(
                a_lo.iter().chain(b_hi.iter()).chain(std::iter::once(&c_l)),
                g_hi.iter()
                    .chain(h_lo.iter())
                    .chain(std::iter::once(&self.q)),
            );
            // R = ⟨a_hi, G_lo⟩ + ⟨b_lo, H_hi⟩ + c_r·Q
            let r = RistrettoPoint::vartime_multiscalar_mul(
                a_hi.iter().chain(b_lo.iter()).chain(std::iter::once(&c_r)),
                g_lo.iter()
                    .chain(h_hi.iter())
                    .chain(std::iter::once(&self.q)),
            );

            transcript.absorb_point(&l);
            transcript.absorb_point(&r);
            let u = transcript.challenge();
            let u_inv = u.invert();

            // Fold. a' = a_lo·u + a_hi·u⁻¹; b' = b_lo·u⁻¹ + b_hi·u;
            //       G' = G_lo·u⁻¹ + G_hi·u; H' = H_lo·u + H_hi·u⁻¹.
            let mut a_next = Vec::with_capacity(half);
            let mut b_next = Vec::with_capacity(half);
            let mut g_next = Vec::with_capacity(half);
            let mut h_next = Vec::with_capacity(half);
            for i in 0..half {
                a_next.push(a_lo[i] * u + a_hi[i] * u_inv);
                b_next.push(b_lo[i] * u_inv + b_hi[i] * u);
                g_next.push(RistrettoPoint::vartime_multiscalar_mul(
                    [u_inv, u],
                    [g_lo[i], g_hi[i]],
                ));
                h_next.push(RistrettoPoint::vartime_multiscalar_mul(
                    [u, u_inv],
                    [h_lo[i], h_hi[i]],
                ));
            }
            a = a_next;
            b = b_next;
            g = g_next;
            h = h_next;
            n = half;
            l_vec.push(l);
            r_vec.push(r);
        }

        Ok(IpaProof {
            l_vec,
            r_vec,
            a: a[0],
            b: b[0],
        })
    }

    #[allow(clippy::many_single_char_names)] // single chars mirror the Bulletproofs verify
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
        let lg_n = self.domain.trailing_zeros() as usize;
        if proof.l_vec.len() != lg_n || proof.r_vec.len() != lg_n {
            return Err(VcError::BadProof {
                scheme: VcScheme::Ipa,
            });
        }

        let y = slot_to_scalar(value);
        let p = self.statement_point(&commitment.point, index, &y);
        let mut transcript = Transcript::new(self.domain, &commitment.point, index, &y);

        // Replay the transcript to recover the round challenges.
        let mut challenges = Vec::with_capacity(lg_n);
        for j in 0..lg_n {
            transcript.absorb_point(&proof.l_vec[j]);
            transcript.absorb_point(&proof.r_vec[j]);
            challenges.push(transcript.challenge());
        }
        let challenges_inv: Vec<Scalar> = challenges.iter().map(Scalar::invert).collect();

        // s[i] = Π_j u_j^{±1}; s[i]·s[n−1−i] = 1, so 1/s[i] = s[n−1−i].
        let all_inv: Scalar = challenges_inv.iter().product();
        let mut s = Vec::with_capacity(self.domain);
        s.push(all_inv);
        for i in 1..self.domain {
            let lg_i = usize::BITS as usize - 1 - (i.leading_zeros() as usize);
            let k = 1usize << lg_i;
            // The challenge for this bit level (rounds are recorded MSB-first).
            let u_sq = sq(challenges[(lg_n - 1) - lg_i]);
            s.push(s[i - k] * u_sq);
        }

        // Single MSM check that the folded relation holds:
        //   Σ (a·s_i) G_i + Σ (b·s_{n−1−i}) H_i + (a·b)·Q
        //   − P − Σ u_j² L_j − Σ u_j⁻² R_j  == 0,
        // where P = C + H_index + y·Q is subtracted whole (so H_index and
        // y·Q are NOT adjusted separately). s_i is the G-fold coefficient;
        // 1/s_i = s_{n−1−i} is the H-fold coefficient.
        let n = self.domain;
        let mut scalars: Vec<Scalar> = Vec::with_capacity(2 * n + 2 + 2 * lg_n);
        let mut points: Vec<RistrettoPoint> = Vec::with_capacity(2 * n + 2 + 2 * lg_n);

        // G coefficients: a·s_i. H coefficients: b·s_{n−1−i} = b·(1/s_i),
        // i.e. s iterated in reverse (paired with H in forward order).
        for (s_i, g_i) in s.iter().zip(self.g_vec.iter()) {
            scalars.push(proof.a * s_i);
            points.push(*g_i);
        }
        for (s_rev, h_i) in s.iter().rev().zip(self.h_vec.iter()) {
            scalars.push(proof.b * s_rev);
            points.push(*h_i);
        }
        scalars.push(proof.a * proof.b);
        points.push(self.q);
        scalars.push(-Scalar::ONE);
        points.push(p);
        for ((u, u_inv), (l, r)) in challenges
            .iter()
            .zip(challenges_inv.iter())
            .zip(proof.l_vec.iter().zip(proof.r_vec.iter()))
        {
            scalars.push(-sq(*u));
            points.push(*l);
            scalars.push(-sq(*u_inv));
            points.push(*r);
        }

        let check = RistrettoPoint::vartime_multiscalar_mul(scalars.iter(), points.iter());
        if check == RistrettoPoint::identity() {
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

    #[test]
    fn test_ipa_fallback_roundtrip() {
        let n = 1024usize;
        let vc = IpaVectorCommitment::new(n).unwrap();
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();

        for &index in &[0usize, 1, 500, 1023] {
            let proof = vc.open(&values, index).unwrap();
            // Round part is exactly 2·log2(n)·32 bytes (transparent — no
            // trusted setup was used anywhere in this path).
            let lg_n = n.trailing_zeros() as usize;
            assert_eq!(proof.rounds(), lg_n);
            assert!(proof.rounds_size_bytes() <= 2 * lg_n * 32);
            assert_eq!(proof.rounds_size_bytes(), 2 * lg_n * 32);
            vc.verify(&commitment, index, &values[index], &proof)
                .expect("valid IPA inclusion proof verifies");
        }
    }

    #[test]
    fn test_ipa_wrong_index_and_value_fail() {
        let n = 256usize;
        let vc = IpaVectorCommitment::new(n).unwrap();
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();
        let proof = vc.open(&values, 100).unwrap();

        assert_eq!(
            vc.verify(&commitment, 101, &values[101], &proof),
            Err(VcError::VerificationFailed)
        );
        let mut bad = values[100];
        bad[0] ^= 0xFF;
        assert_eq!(
            vc.verify(&commitment, 100, &bad, &proof),
            Err(VcError::VerificationFailed)
        );
    }

    #[test]
    fn test_ipa_serde_roundtrip() {
        let n = 128usize;
        let vc = IpaVectorCommitment::new(n).unwrap();
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();
        let proof = vc.open(&values, 63).unwrap();

        let mut c_bytes = Vec::new();
        ciborium::into_writer(&commitment, &mut c_bytes).unwrap();
        let c2: IpaCommitment = ciborium::from_reader(&c_bytes[..]).unwrap();
        let mut p_bytes = Vec::new();
        ciborium::into_writer(&proof, &mut p_bytes).unwrap();
        let p2: IpaProof = ciborium::from_reader(&p_bytes[..]).unwrap();

        vc.verify(&c2, 63, &values[63], &p2).unwrap();
    }

    #[test]
    fn test_ipa_tampered_proof_fails() {
        let n = 64usize;
        let vc = IpaVectorCommitment::new(n).unwrap();
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();
        let mut proof = vc.open(&values, 5).unwrap();

        proof.a += Scalar::ONE;
        assert_eq!(
            vc.verify(&commitment, 5, &values[5], &proof),
            Err(VcError::VerificationFailed)
        );
    }

    #[test]
    fn test_ipa_smallest_domain() {
        let n = 2usize;
        let vc = IpaVectorCommitment::new(n).unwrap();
        let values = slots(n);
        let commitment = vc.commit(&values).unwrap();
        for index in 0..n {
            let proof = vc.open(&values, index).unwrap();
            vc.verify(&commitment, index, &values[index], &proof)
                .unwrap();
        }
    }

    #[test]
    fn test_ipa_bad_commit_decode() {
        assert_eq!(
            IpaCommitment::from_bytes(&[0u8; 10]),
            Err(VcError::BadCommit {
                scheme: VcScheme::Ipa
            })
        );
    }
}
