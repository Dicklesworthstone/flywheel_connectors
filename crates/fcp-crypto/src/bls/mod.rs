//! BLS12-381 threshold-aggregate quorum signatures with proof-of-possession
//! (PoP) rogue-key defense (br-angoc.17.4).
//!
//! Quorum decisions (zone admission, capability revocation) previously
//! required carrying one Ed25519 signature per signer. This module lets any
//! k-of-n subset of PoP-registered signers compress their decision into a
//! **single 96-byte signature** that verifies with two pairings, following
//! the multi-signature-with-proof-of-possession construction from
//! Boneh–Drijvers–Neven, "Compact Multi-Signatures for Smaller Blockchains"
//! (ASIACRYPT 2018) as profiled by draft-irtf-cfrg-bls-signature (the
//! `POP` ciphersuite).
//!
//! # Ciphersuite
//!
//! - Public keys live in G1 (48-byte compressed), signatures and PoPs live
//!   in G2 (96-byte compressed) — the "minimal-pubkey-size" variant.
//! - Message hashing: hash-to-curve XMD:SHA-256 SSWU RO with the standard
//!   DSTs [`BLS_SIG_DST`] and [`BLS_POP_DST`]. Distinct DSTs make a PoP
//!   useless as a message signature and vice versa.
//!
//! # Rogue-key defense
//!
//! Plain BLS aggregation is vulnerable to rogue-key attacks: an attacker who
//! publishes `pk' = pk_atk - pk_victim` can forge an "aggregate" that
//! implicates the victim. The defense here is mechanical: **a signer's key
//! can only enter a [`PopRegistry`] together with a valid proof of
//! possession**, and both aggregation and verification resolve signer IDs
//! through the registry. A key without a verified PoP is unusable —
//! [`aggregate`](aggregate::aggregate) and
//! [`verify_aggregate`](aggregate::verify_aggregate) return
//! [`BlsError::PopMissing`] instead of touching the unproven key.
//!
//! # Relationship to the Ed25519 quorum path
//!
//! This module does not replace [`fcp-core`'s per-node `SignatureSet`]
//! (the Ed25519 multisig path); it adds a compact alternative for
//! bandwidth-sensitive quorum objects. Callers that fail BLS verification
//! can (and should) fall back to the per-signer Ed25519 path — see
//! `fcp_mesh::quorum` and the conformance failure-injection test.
//!
//! # Example
//!
//! ```rust
//! use fcp_crypto::bls::{BlsSecretKey, PopRegistry, aggregate, verify_aggregate};
//!
//! let mut registry = PopRegistry::new();
//! let signers: Vec<(String, BlsSecretKey)> = (0..3)
//!     .map(|i| (format!("node-{i}"), BlsSecretKey::generate()))
//!     .collect();
//! for (id, sk) in &signers {
//!     registry
//!         .register(id.clone(), sk.public_key(), &sk.prove_possession())
//!         .unwrap();
//! }
//!
//! let message = b"zone admission: node-9 -> z:work";
//! let shares: Vec<(String, _)> = signers
//!     .iter()
//!     .map(|(id, sk)| (id.clone(), sk.sign(message)))
//!     .collect();
//!
//! let agg = aggregate(&shares, &registry).unwrap();
//! assert_eq!(agg.signature().to_bytes().len(), 96);
//! verify_aggregate(&agg, message, &registry).unwrap();
//! ```

// `PoP` (proof of possession) is a standard cryptographic abbreviation that
// appears throughout this module's prose; its mixed case would otherwise
// trip `doc_markdown` on every mention. Consistent with `fcp-mesh`, which
// allows the lint crate-wide.
#![allow(clippy::doc_markdown)]

pub mod aggregate;
pub mod pop;

pub use aggregate::{
    AggregateSignature, BlsPublicKey, BlsSecretKey, BlsSignature, aggregate, verify_aggregate,
};
pub use pop::{PopRegistry, ProofOfPossession};

/// Compressed G1 public-key size in bytes.
pub const BLS_PUBLIC_KEY_SIZE: usize = 48;

/// Compressed G2 signature size in bytes (also the PoP size).
pub const BLS_SIGNATURE_SIZE: usize = 96;

/// Secret-key scalar size in bytes (little-endian canonical).
pub const BLS_SECRET_KEY_SIZE: usize = 32;

/// Domain-separation tag for message signatures
/// (draft-irtf-cfrg-bls-signature `BLS_SIG_` ciphersuite, PoP scheme).
pub const BLS_SIG_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Domain-separation tag for proofs of possession
/// (draft-irtf-cfrg-bls-signature `BLS_POP_` ciphersuite, PoP scheme).
pub const BLS_POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Errors from BLS aggregate-signature operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlsError {
    /// The signer has no PoP-verified public key in the registry.
    ///
    /// Returned when an unregistered (and therefore unproven) key would be
    /// needed to aggregate or verify — the rogue-key defense.
    #[error("signer '{signer}' has no proof-of-possession-verified key registered")]
    PopMissing {
        /// Signer ID whose key lacks a verified proof of possession.
        signer: String,
    },

    /// The supplied proof of possession failed pairing verification.
    #[error("proof of possession for signer '{signer}' is invalid")]
    PopInvalid {
        /// Signer ID whose proof of possession failed verification.
        signer: String,
    },

    /// The signer ID is already registered with a different public key.
    #[error("signer '{signer}' is already registered with a different key")]
    SignerAlreadyRegistered {
        /// Signer ID that was already present in the registry.
        signer: String,
    },

    /// The same signer ID appears more than once in an aggregation input
    /// or aggregate signer set.
    #[error("duplicate signer '{signer}' in aggregation input")]
    DuplicateSigner {
        /// Signer ID that appeared more than once.
        signer: String,
    },

    /// The public key being registered is already bound to a different
    /// signer ID.
    ///
    /// Rejected so one key-holder cannot claim multiple signer slots (which
    /// would let a single key satisfy a t-of-n *distinct-signer* threshold).
    #[error("public key is already registered under signer '{existing_signer}'")]
    KeyAlreadyBound {
        /// The signer ID that already owns this public key.
        existing_signer: String,
    },

    /// An aggregation or verification was attempted over zero signers.
    #[error("aggregate operation requires at least one signer")]
    EmptySigners,

    /// A byte string had the wrong length for the target type.
    #[error("invalid {field} length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Name of the field or type being decoded.
        field: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Actual byte length supplied.
        actual: usize,
    },

    /// Bytes did not decode to a valid curve point (or decoded to the
    /// identity where the identity is forbidden).
    #[error("invalid {field}: not a valid non-identity curve point")]
    InvalidPoint {
        /// Name of the field or type being decoded.
        field: &'static str,
    },

    /// Bytes did not decode to a canonical non-zero scalar.
    #[error("invalid secret key: not a canonical non-zero scalar")]
    InvalidSecretKey,

    /// The aggregate signature failed the pairing check for the given
    /// message and signer set.
    #[error("aggregate signature verification failed")]
    VerificationFailed,
}
