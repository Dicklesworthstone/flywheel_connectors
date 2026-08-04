//! Vector commitments for `ConnectorStateRoot` slot inclusion proofs
//! (br-angoc.17.1).
//!
//! A zone commits to a vector of state slots and later proves that slot `i`
//! holds a specific value, in **O(1) proof size** (KZG) or **O(log n)**
//! (IPA), without revealing the rest of the vector.
//!
//! Two interchangeable schemes implement the [`VectorCommitmentScheme`]
//! trait:
//!
//! - [`kzg::KzgVectorCommitment`] — KZG10 over BLS12-381. Commitment and
//!   proof are each a single group element (constant size); verification is
//!   two pairings. **Requires a trusted setup** (powers-of-tau structured
//!   reference string). Use in zones that accept a one-time ceremony.
//! - [`ipa::IpaVectorCommitment`] — Bulletproofs inner-product argument
//!   over ristretto255. **Transparent — no trusted setup.** Proof is
//!   `2·⌈log2 n⌉` 32-byte points plus two scalars. Use in zones with a
//!   trusted-setup ban (the Halo2/IPA fallback).
//!
//! # Scheme-agnostic value model
//!
//! Both schemes commit to a vector of 32-byte slot values ([`SlotValue`],
//! typically a BLAKE3 hash of the slot contents). Each scheme deterministically
//! reduces a slot value into its own scalar field, so the same slot bytes are
//! committed consistently by prover and verifier. A commitment made under one
//! scheme does not verify under the other — a cross-scheme proof is a typed
//! rejection, and the holder re-proves under the verifier's scheme (see the
//! cross-tier conformance test).

pub mod ipa;
pub mod kzg;

pub use ipa::IpaVectorCommitment;
pub use kzg::KzgVectorCommitment;

/// A single state-slot value: a 32-byte hash of the slot contents.
pub type SlotValue = [u8; 32];

/// Which vector-commitment scheme produced a commitment or proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum VcScheme {
    /// KZG10 over BLS12-381 (constant-size proof, requires trusted setup).
    Kzg,
    /// Bulletproofs IPA over ristretto255 (log-size proof, transparent).
    Ipa,
}

impl VcScheme {
    /// Stable lowercase name for logging and doctor output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kzg => "kzg",
            Self::Ipa => "ipa",
        }
    }

    /// Whether this scheme needs a trusted setup ceremony.
    #[must_use]
    pub const fn requires_trusted_setup(self) -> bool {
        matches!(self, Self::Kzg)
    }
}

impl std::fmt::Display for VcScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors from vector-commitment operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VcError {
    /// The vector length does not match the committed domain size.
    #[error("vector length {actual} does not match domain size {expected}")]
    LengthMismatch {
        /// Expected domain size (from the scheme parameters).
        expected: usize,
        /// Actual vector length supplied.
        actual: usize,
    },

    /// The requested slot index is out of range for the domain.
    #[error("slot index {index} out of range for domain size {domain}")]
    IndexOutOfRange {
        /// The requested index.
        index: usize,
        /// The domain size.
        domain: usize,
    },

    /// The domain size is not a supported value (must be a power of two ≥ 2).
    #[error("unsupported domain size {size}: must be a power of two ≥ 2")]
    UnsupportedDomain {
        /// The rejected domain size.
        size: usize,
    },

    /// A commitment failed to decode (wrong length or invalid group element).
    ///
    /// This is the failure-injection signal: `state_root` falls back to
    /// per-slot Merkle proofs and emits an audit alert when it sees this.
    #[error("commitment did not decode to a valid {scheme} group element")]
    BadCommit {
        /// The scheme whose commitment failed to decode.
        scheme: VcScheme,
    },

    /// A proof failed to decode (wrong length, wrong element count, or an
    /// invalid group element).
    #[error("proof did not decode as a valid {scheme} proof")]
    BadProof {
        /// The scheme whose proof failed to decode.
        scheme: VcScheme,
    },

    /// A proof was presented to a verifier configured for a different
    /// scheme (KZG proof to an IPA-only zone or vice versa).
    #[error("proof scheme {proof_scheme:?} does not match verifier scheme {verifier_scheme:?}")]
    SchemeMismatch {
        /// Scheme the proof was produced under.
        proof_scheme: VcScheme,
        /// Scheme the verifier is configured for.
        verifier_scheme: VcScheme,
    },

    /// The proof did not verify against the commitment, index, and value.
    #[error("vector-commitment opening proof failed verification")]
    VerificationFailed,
}

/// A scheme that commits to a vector of slot values and proves single-slot
/// inclusion.
///
/// Implementors fix a domain size (power of two) at construction. `commit`
/// and `open` take the full vector; `verify` takes only the commitment,
/// index, claimed value, and proof.
pub trait VectorCommitmentScheme {
    /// The (serializable) commitment type.
    type Commitment;
    /// The (serializable) inclusion-proof type.
    type Proof;

    /// Which scheme this is.
    fn scheme(&self) -> VcScheme;

    /// The fixed domain size (number of slots).
    fn domain_size(&self) -> usize;

    /// Commit to a vector of slot values.
    ///
    /// # Errors
    ///
    /// [`VcError::LengthMismatch`] if `values.len()` != [`domain_size`].
    ///
    /// [`domain_size`]: VectorCommitmentScheme::domain_size
    fn commit(&self, values: &[SlotValue]) -> Result<Self::Commitment, VcError>;

    /// Produce an inclusion proof that slot `index` holds `values[index]`.
    ///
    /// # Errors
    ///
    /// [`VcError::LengthMismatch`] on a wrong-length vector or
    /// [`VcError::IndexOutOfRange`] on a bad index.
    fn open(&self, values: &[SlotValue], index: usize) -> Result<Self::Proof, VcError>;

    /// Verify an inclusion proof for slot `index` = `value`.
    ///
    /// # Errors
    ///
    /// [`VcError::IndexOutOfRange`] on a bad index or
    /// [`VcError::VerificationFailed`] if the proof does not verify.
    fn verify(
        &self,
        commitment: &Self::Commitment,
        index: usize,
        value: &SlotValue,
        proof: &Self::Proof,
    ) -> Result<(), VcError>;
}

/// Reject a domain size that is not a power of two ≥ 2.
pub(crate) const fn check_domain(size: usize) -> Result<(), VcError> {
    if size >= 2 && size.is_power_of_two() {
        Ok(())
    } else {
        Err(VcError::UnsupportedDomain { size })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_names_and_setup_flags() {
        assert_eq!(VcScheme::Kzg.as_str(), "kzg");
        assert_eq!(VcScheme::Ipa.as_str(), "ipa");
        assert!(VcScheme::Kzg.requires_trusted_setup());
        assert!(!VcScheme::Ipa.requires_trusted_setup());
    }

    #[test]
    fn domain_check_rejects_non_power_of_two() {
        assert!(check_domain(1024).is_ok());
        assert!(check_domain(4096).is_ok());
        assert_eq!(check_domain(0), Err(VcError::UnsupportedDomain { size: 0 }));
        assert_eq!(check_domain(1), Err(VcError::UnsupportedDomain { size: 1 }));
        assert_eq!(
            check_domain(1000),
            Err(VcError::UnsupportedDomain { size: 1000 })
        );
    }
}
