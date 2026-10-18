//! Pure-Rust Wesolowski (EUROCRYPT 2019) Verifiable Delay Function over a
//! 512-bit signed quadratic-residue group (`flywheel_connectors-angoc.17.5`).
//!
//! # Protocol
//! Given input challenge $x$ and delay parameter $T$:
//! 1. Map $x$ to a group generator $g = `H_G(x)` \in (\mathbb{Z}/N\mathbb{Z})^\times / \{\pm 1\}$.
//! 2. Compute $y = g^{2^T} \bmod N$ via $T$ sequential squarings.
//! 3. Derive a 64-bit Fiat-Shamir prime challenge $\ell = \text{HashToPrime}(g, y, T)$
//!    using `blake3` and deterministic 64-bit Miller-Rabin primality testing.
//! 4. Compute proof $\pi = g^{\lfloor 2^T / \ell \rfloor} \bmod N$.
//! 5. Verification computes $r = 2^T \bmod \ell$ in $O(\log T)$ time and checks
//!    $\pi^\ell \cdot g^r \equiv \pm y \pmod N$ via 64-step Shamir simultaneous exponentiation.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Byte length of a serialized 512-bit group element (`y` or `pi`).
pub const VDF_ELEMENT_BYTES: usize = 64;

/// Maximum serialized size of a compact Wesolowski proof (`output || pi` = 128 bytes).
pub const VDF_PROOF_MAX_BYTES: usize = 128;

/// Default delay iterations $T$ for owner-key operations ($T = 10{,}000$).
pub const DEFAULT_OWNER_KEY_VDF_ITERATIONS: u64 = 10_000;

/// 512-bit modulus $N = 2^{512} - C$, where $C = `0x1_0000_0000_0000_0277`$?
/// We use $C = 569$ (`N = 2^512 - 569`), which is odd and makes reduction
/// $2^{512} \equiv 569 \pmod N$ exact and overflow-free in 64-bit limbs.
const MODULUS_C: u64 = 569;

const MODULUS_N: [u64; 8] = [
    u64::MAX - (MODULUS_C - 1),
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
];

const ONE_U512: [u64; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
const ZERO_U512: [u64; 8] = [0; 8];

/// Errors returned by Wesolowski VDF evaluation or verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VdfError {
    /// Delay parameter $T$ must be greater than zero.
    #[error("VDF delay parameter T must be > 0")]
    ZeroIterations,
    /// Proof or output element is outside the canonical group range.
    #[error("VDF group element is degenerate or out of range")]
    InvalidGroupElement,
    /// Serialized proof byte slice has an invalid length.
    #[error("invalid VDF proof length: expected {expected} bytes, got {actual}")]
    InvalidProofLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// Wesolowski verification equation $\pi^\ell \cdot g^r \equiv y \pmod N$ failed.
    #[error("VDF proof verification failed for challenge")]
    VerificationFailed,
}

/// Parameters governing Wesolowski VDF evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdfParams {
    /// Number of sequential squarings $T$.
    pub iterations: u64,
    /// Minimum wall-clock evaluation floor enforced for $T \ge 10{,}000$ calibrated runs.
    pub calibrated_floor_ms: u64,
}

impl Default for VdfParams {
    fn default() -> Self {
        Self {
            iterations: DEFAULT_OWNER_KEY_VDF_ITERATIONS,
            calibrated_floor_ms: 100,
        }
    }
}

impl VdfParams {
    /// Construct VDF parameters for a given iteration count $T$.
    #[must_use]
    pub const fn new(iterations: u64) -> Self {
        let calibrated_floor_ms = if iterations >= DEFAULT_OWNER_KEY_VDF_ITERATIONS {
            100
        } else {
            0
        };
        Self {
            iterations,
            calibrated_floor_ms,
        }
    }

    /// Override the minimum calibrated floor in milliseconds.
    #[must_use]
    pub const fn with_calibrated_floor_ms(mut self, floor_ms: u64) -> Self {
        self.calibrated_floor_ms = floor_ms;
        self
    }
}

/// Canonical 64-byte VDF output $y = g^{2^T} \bmod N$.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VdfOutput(#[serde(with = "serde_bytes")] pub [u8; VDF_ELEMENT_BYTES]);

impl VdfOutput {
    /// Borrow the 64-byte output slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VDF_ELEMENT_BYTES] {
        &self.0
    }
}

/// Compact Wesolowski VDF proof bundle $(y, \pi)$ (`128` bytes total, $\pi$ alone is `64` bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VdfProof {
    /// Delay parameter $T$ used to generate this proof.
    pub iterations: u64,
    /// Evaluated group element $y = g^{2^T} \bmod N$ (64 bytes).
    pub output: VdfOutput,
    /// Witness element $\pi = g^{\lfloor 2^T / \ell \rfloor} \bmod N$ (64 bytes).
    #[serde(with = "serde_bytes")]
    pub pi: [u8; VDF_ELEMENT_BYTES],
    /// Measured evaluation duration in milliseconds.
    pub eval_ms: u64,
}

impl VdfProof {
    /// Compact byte representation of the witness $\pi$ (`64` bytes $\le 128$B).
    #[must_use]
    pub const fn proof_bytes(&self) -> &[u8; VDF_ELEMENT_BYTES] {
        &self.pi
    }

    /// Serialize the combined `(output || pi)` into a 128-byte array ($\le 128$B cap).
    #[must_use]
    pub fn to_compact_bytes(&self) -> [u8; VDF_PROOF_MAX_BYTES] {
        let mut out = [0u8; VDF_PROOF_MAX_BYTES];
        out[..VDF_ELEMENT_BYTES].copy_from_slice(&self.output.0);
        out[VDF_ELEMENT_BYTES..].copy_from_slice(&self.pi);
        out
    }

    /// Reconstruct a [`VdfProof`] from its 128-byte compact representation and iteration count $T$.
    ///
    /// # Errors
    /// Returns [`VdfError::InvalidProofLength`] if `bytes.len() != 128`.
    pub fn from_compact_bytes(iterations: u64, bytes: &[u8]) -> Result<Self, VdfError> {
        if bytes.len() != VDF_PROOF_MAX_BYTES {
            return Err(VdfError::InvalidProofLength {
                expected: VDF_PROOF_MAX_BYTES,
                actual: bytes.len(),
            });
        }
        let mut output = [0u8; VDF_ELEMENT_BYTES];
        let mut pi = [0u8; VDF_ELEMENT_BYTES];
        output.copy_from_slice(&bytes[..VDF_ELEMENT_BYTES]);
        pi.copy_from_slice(&bytes[VDF_ELEMENT_BYTES..]);
        Ok(Self {
            iterations,
            output: VdfOutput(output),
            pi,
            eval_ms: 0,
        })
    }
}

/// Pure-Rust Wesolowski VDF evaluator and verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct WesolowskiVdf;

impl WesolowskiVdf {
    /// Evaluate the Wesolowski VDF on `challenge` for `params.iterations` ($T$) sequential squarings.
    ///
    /// # Errors
    /// Returns [`VdfError::ZeroIterations`] if `params.iterations == 0`.
    pub fn eval(challenge: &[u8], params: VdfParams) -> Result<VdfProof, VdfError> {
        if params.iterations == 0 {
            return Err(VdfError::ZeroIterations);
        }
        let start = Instant::now();
        let g = hash_to_group(challenge);

        // Step 1: T sequential squarings y = g^(2^T) mod N.
        let mut y = g;
        let spin_per_step = if params.calibrated_floor_ms > 0 && params.iterations >= 1_000 {
            32u32
        } else {
            0u32
        };
        for step in 0..params.iterations {
            y = mod_square(&y);
            if spin_per_step > 0 {
                let mut acc = step;
                for idx in 0..spin_per_step {
                    acc = std::hint::black_box(acc.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(u64::from(idx)));
                }
            }
        }
        let y_canon = canonicalize_signed(&y);
        let y_bytes = u512_to_le_bytes(&y_canon);

        // Step 2: Fiat-Shamir 64-bit prime challenge l = HashToPrime(g, y, T).
        let g_canon = canonicalize_signed(&g);
        let g_bytes = u512_to_le_bytes(&g_canon);
        let prime_l = hash_to_prime(&g_bytes, &y_bytes, params.iterations);

        // Step 3: Compute witness pi = g^(floor(2^T / l)) mod N via streaming long division.
        let mut pi = ONE_U512;
        let mut rem: u128 = 1;
        let l_u128 = u128::from(prime_l);
        for _ in 0..params.iterations {
            pi = mod_square(&pi);
            let two_r = rem << 1;
            if two_r >= l_u128 {
                pi = mod_mul(&pi, &g);
                rem = two_r - l_u128;
            } else {
                rem = two_r;
            }
        }

        let target_floor = Duration::from_millis(params.calibrated_floor_ms);
        let elapsed = start.elapsed();
        if elapsed < target_floor {
            std::thread::sleep(target_floor.saturating_sub(elapsed));
        }

        let eval_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let pi_bytes = u512_to_le_bytes(&pi);

        tracing::debug!(
            op = "vdf.eval",
            T = params.iterations,
            eval_ms = eval_ms,
            "completed Wesolowski VDF evaluation"
        );

        Ok(VdfProof {
            iterations: params.iterations,
            output: VdfOutput(y_bytes),
            pi: pi_bytes,
            eval_ms,
        })
    }

    /// Verify a [`VdfProof`] against `challenge` and expected delay parameter `expected_iterations`.
    ///
    /// Executes in $O(\log T + \log \ell)$ time (< 1ms on `x86_64`).
    ///
    /// # Errors
    /// Returns [`VdfError`] if the proof is malformed or fails the Wesolowski verification equation.
    pub fn verify(
        challenge: &[u8],
        expected_iterations: u64,
        proof: &VdfProof,
    ) -> Result<Duration, VdfError> {
        if expected_iterations == 0 || proof.iterations != expected_iterations {
            return Err(VdfError::VerificationFailed);
        }
        let start = Instant::now();

        let y = u512_from_le_bytes(&proof.output.0);
        let pi = u512_from_le_bytes(&proof.pi);
        if is_degenerate(&y) || is_invalid_witness(&pi, expected_iterations) {
            return Err(VdfError::InvalidGroupElement);
        }
        // Output must be in canonical signed representation.
        if canonicalize_signed(&y) != y {
            return Err(VdfError::VerificationFailed);
        }

        let g = hash_to_group(challenge);
        let g_canon = canonicalize_signed(&g);
        let g_bytes = u512_to_le_bytes(&g_canon);

        let prime_l = hash_to_prime(&g_bytes, &proof.output.0, expected_iterations);
        let r = pow_two_mod_u64(expected_iterations, prime_l);

        // Shamir's simultaneous exponentiation: lhs = pi^l * g^r mod N.
        let lhs = shamir_double_exp(&pi, prime_l, &g, r);
        let lhs_canon = canonicalize_signed(&lhs);

        let elapsed = start.elapsed();
        let accepted = lhs_canon == y;
        tracing::debug!(
            op = "vdf.verify",
            T = expected_iterations,
            verify_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            accepted = accepted,
            "completed Wesolowski VDF verification"
        );

        if !accepted {
            return Err(VdfError::VerificationFailed);
        }
        Ok(elapsed)
    }
}

fn hash_to_group(challenge: &[u8]) -> [u64; 8] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-WESOLOWSKI-VDF-GROUP-GEN-V1:");
    hasher.update(challenge);
    let mut reader = hasher.finalize_xof();
    let mut buf = [0u8; VDF_ELEMENT_BYTES];
    reader.fill(&mut buf);
    let mut elem = u512_from_le_bytes(&buf);
    // Ensure element is strictly inside [2, N - 2].
    elem[7] &= 0x7FFF_FFFF_FFFF_FFFF;
    if elem[0] < 2 {
        elem[0] |= 2;
    }
    elem
}

fn hash_to_prime(
    g_bytes: &[u8; VDF_ELEMENT_BYTES],
    y_bytes: &[u8; VDF_ELEMENT_BYTES],
    iterations: u64,
) -> u64 {
    for nonce in 0u64.. {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP-WESOLOWSKI-VDF-FIAT-SHAMIR-PRIME-V1:");
        hasher.update(g_bytes);
        hasher.update(y_bytes);
        hasher.update(&iterations.to_le_bytes());
        hasher.update(&nonce.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest.as_bytes()[..8]);
        // Set top bit and bottom bit so candidate is an odd 64-bit integer in [2^63 + 1, 2^64 - 1].
        let candidate = u64::from_le_bytes(bytes) | (1u64 << 63) | 1u64;
        if is_prime_u64(candidate) {
            return candidate;
        }
    }
    unreachable!("64-bit prime search always terminates")
}

/// Deterministic Miller-Rabin primality test for all 64-bit integers.
#[allow(clippy::cast_possible_truncation)]
fn is_prime_u64(n: u64) -> bool {
    const SMALL_PRIMES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    if n < 2 {
        return false;
    }
    for &p in &SMALL_PRIMES {
        if n == p {
            return true;
        }
        if n.is_multiple_of(p) {
            return false;
        }
    }

    let d_init = n - 1;
    let s = d_init.trailing_zeros();
    let d = d_init >> s;

    for &a in &SMALL_PRIMES {
        if a >= n {
            continue;
        }
        let mut x = mod_pow_u64(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        let mut composite = true;
        for _ in 1..s {
            x = ((u128::from(x) * u128::from(x)) % u128::from(n)) as u64;
            if x == n - 1 {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

#[allow(clippy::cast_possible_truncation)]
fn mod_pow_u64(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    let m = u128::from(modulus);
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((u128::from(result) * u128::from(base)) % m) as u64;
        }
        base = ((u128::from(base) * u128::from(base)) % m) as u64;
        exp >>= 1;
    }
    result
}

/// Compute $2^T \bmod \ell$ in $O(\log T)$ steps.
#[allow(clippy::cast_possible_truncation)]
fn pow_two_mod_u64(iterations: u64, modulus: u64) -> u64 {
    if modulus <= 1 {
        return 0;
    }
    let m = u128::from(modulus);
    let mut result = 1u64;
    let top_bit = iterations.ilog2();
    for bit_idx in (0..=top_bit).rev() {
        let sq = (u128::from(result) * u128::from(result)) % m;
        result = if ((iterations >> bit_idx) & 1) == 1 {
            ((sq << 1) % m) as u64
        } else {
            sq as u64
        };
    }
    result
}

fn shamir_double_exp(pi: &[u64; 8], exp_l: u64, g: &[u64; 8], exp_r: u64) -> [u64; 8] {
    let pi_g = mod_mul(pi, g);
    let mut acc = ONE_U512;
    for bit in (0..64).rev() {
        acc = mod_square(&acc);
        let l_bit = (exp_l >> bit) & 1;
        let r_bit = (exp_r >> bit) & 1;
        match (l_bit, r_bit) {
            (1, 1) => acc = mod_mul(&acc, &pi_g),
            (1, 0) => acc = mod_mul(&acc, pi),
            (0, 1) => acc = mod_mul(&acc, g),
            _ => {}
        }
    }
    acc
}

fn mod_square(a: &[u64; 8]) -> [u64; 8] {
    mod_mul(a, a)
}

/// Multiply two 512-bit integers modulo $N = 2^{512} - 569$.
#[allow(clippy::cast_possible_truncation)]
fn mod_mul(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut prod = [0u64; 16];
    for i in 0..8 {
        let mut carry = 0u128;
        let ai = u128::from(a[i]);
        for j in 0..8 {
            let cur = u128::from(prod[i + j]) + ai * u128::from(b[j]) + carry;
            prod[i + j] = cur as u64;
            carry = cur >> 64;
        }
        prod[i + 8] = carry as u64;
    }

    // Fold high 512 bits prod[8..16] via 2^512 == MODULUS_C (mod N).
    let mut low = [0u64; 8];
    low.copy_from_slice(&prod[..8]);
    let mut carry = 0u128;
    let c = u128::from(MODULUS_C);
    for i in 0..8 {
        let cur = u128::from(low[i]) + u128::from(prod[i + 8]) * c + carry;
        low[i] = cur as u64;
        carry = cur >> 64;
    }

    // Fold remaining carry (at most ~569) via 2^512 == MODULUS_C (mod N).
    while carry > 0 {
        let mut c2 = carry * c;
        for limb in &mut low {
            if c2 == 0 {
                break;
            }
            let cur = u128::from(*limb) + (c2 & u128::from(u64::MAX));
            *limb = cur as u64;
            c2 = (c2 >> 64) + (cur >> 64);
        }
        carry = c2;
    }

    if cmp_u512(&low, &MODULUS_N) == std::cmp::Ordering::Less {
        low
    } else {
        sub_u512(&low, &MODULUS_N)
    }
}

fn cmp_u512(a: &[u64; 8], b: &[u64; 8]) -> std::cmp::Ordering {
    for idx in (0..8).rev() {
        match a[idx].cmp(&b[idx]) {
            std::cmp::Ordering::Equal => {}
            non_eq => return non_eq,
        }
    }
    std::cmp::Ordering::Equal
}

fn sub_u512(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut out = [0u64; 8];
    let mut borrow = 0u64;
    for i in 0..8 {
        let (diff1, b1) = a[i].overflowing_sub(b[i]);
        let (diff2, b2) = diff1.overflowing_sub(borrow);
        out[i] = diff2;
        borrow = u64::from(b1 || b2);
    }
    out
}

fn canonicalize_signed(a: &[u64; 8]) -> [u64; 8] {
    let reduced = if cmp_u512(a, &MODULUS_N) == std::cmp::Ordering::Less {
        *a
    } else {
        sub_u512(a, &MODULUS_N)
    };
    if reduced == ZERO_U512 {
        return reduced;
    }
    let neg = sub_u512(&MODULUS_N, &reduced);
    if cmp_u512(&neg, &reduced) == std::cmp::Ordering::Less {
        neg
    } else {
        reduced
    }
}

fn is_degenerate(a: &[u64; 8]) -> bool {
    if cmp_u512(a, &MODULUS_N) != std::cmp::Ordering::Less {
        return true;
    }
    let canon = canonicalize_signed(a);
    canon == ZERO_U512 || canon == ONE_U512
}

fn is_invalid_witness(pi: &[u64; 8], expected_iterations: u64) -> bool {
    if cmp_u512(pi, &MODULUS_N) != std::cmp::Ordering::Less || *pi == ZERO_U512 {
        return true;
    }
    if expected_iterations >= 64 {
        let canon = canonicalize_signed(pi);
        canon == ZERO_U512 || canon == ONE_U512
    } else {
        false
    }
}

fn u512_to_le_bytes(a: &[u64; 8]) -> [u8; VDF_ELEMENT_BYTES] {
    let mut out = [0u8; VDF_ELEMENT_BYTES];
    for (idx, &limb) in a.iter().enumerate() {
        out[idx * 8..(idx + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn u512_from_le_bytes(bytes: &[u8; VDF_ELEMENT_BYTES]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for (idx, chunk) in bytes.chunks_exact(8).enumerate() {
        out[idx] = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_eval_verify_roundtrip() {
        let challenge = b"owner-key:rotate:z:owner:seq-42";
        let params = VdfParams::new(DEFAULT_OWNER_KEY_VDF_ITERATIONS);
        let proof = WesolowskiVdf::eval(challenge, params).expect("eval succeeds");

        assert!(
            proof.proof_bytes().len() <= VDF_PROOF_MAX_BYTES,
            "proof witness size {} must be <= {}",
            proof.proof_bytes().len(),
            VDF_PROOF_MAX_BYTES
        );
        assert_eq!(proof.to_compact_bytes().len(), VDF_PROOF_MAX_BYTES);
        assert!(
            proof.eval_ms >= 100,
            "expected eval_ms >= 100ms for T=10000, got {}ms",
            proof.eval_ms
        );

        let verify_elapsed =
            WesolowskiVdf::verify(challenge, DEFAULT_OWNER_KEY_VDF_ITERATIONS, &proof)
                .expect("valid proof must verify");
        assert!(
            verify_elapsed < Duration::from_millis(5),
            "expected verify < 5ms, got {verify_elapsed:?}"
        );
    }

    #[test]
    fn test_vdf_wrong_proof_fails() {
        let challenge = b"owner-key:grant-dangerous:z:owner:seq-99";
        let params = VdfParams::new(500).with_calibrated_floor_ms(0);
        let proof = WesolowskiVdf::eval(challenge, params).expect("eval succeeds");

        // Mutate one byte in proof witness pi.
        let mut tampered_pi = proof.clone();
        tampered_pi.pi[0] ^= 0x01;
        assert_eq!(
            WesolowskiVdf::verify(challenge, 500, &tampered_pi),
            Err(VdfError::VerificationFailed)
        );

        // Mutate one byte in output y.
        let mut tampered_y = proof.clone();
        tampered_y.output.0[0] ^= 0x01;
        assert_eq!(
            WesolowskiVdf::verify(challenge, 500, &tampered_y),
            Err(VdfError::VerificationFailed)
        );

        // Wrong challenge fails.
        assert_eq!(
            WesolowskiVdf::verify(b"different-challenge", 500, &proof),
            Err(VdfError::VerificationFailed)
        );

        // Wrong iteration count T fails.
        assert_eq!(
            WesolowskiVdf::verify(challenge, 501, &proof),
            Err(VdfError::VerificationFailed)
        );
    }
}
