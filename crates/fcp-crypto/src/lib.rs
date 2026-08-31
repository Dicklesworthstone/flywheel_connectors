//! FCP2 crypto primitives and helpers.
// nursery/pedantic style lints that newer nightlies fire on this unchanged code.
// Needed here rather than in Cargo.toml because this crate re-enables the groups
// with an inner attribute, which overrides the workspace lint table.
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::duration_suboptimal_units)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::significant_drop_tightening)]
//!
//! This crate provides the cryptographic building blocks used by zone key
//! distribution, capability tokens, sessions, receipts, and audit throughout
//! the FCP2 protocol.
//!
//! # Key Role Separation
//!
//! FCP uses distinct keys for:
//! - **Owner signing key** (Ed25519 public anchor; supports threshold signing)
//! - **Node signing key** (Ed25519)
//! - **Node encryption key** (X25519)
//! - **Node issuance key** (Ed25519) for token minting
//! - **Zone symmetric encryption keys** (ChaCha20-Poly1305 / XChaCha20-Poly1305)
//!
//! # Modules
//!
//! - [`bls`] - BLS12-381 threshold-aggregate quorum signatures with proof-of-possession rogue-key defense
//! - [`ed25519`] - Ed25519 signing and verification
//! - [`frost`] - FROST threshold signing and distributed key generation
//! - [`hybrid`] - Ed25519 + ML-DSA-65 signed envelopes
//! - [`x25519`] - X25519 ECDH key exchange
//! - [`hkdf`] - HKDF-SHA256 key derivation
//! - [`aead`] - ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD
//! - [`mac`] - BLAKE3 keyed MAC for session frames
//! - [`mod@hpke_seal`] - HPKE (RFC 9180) for sealed boxes
//! - [`cose`] - `COSE_Sign1/CWT` helpers for capability tokens
//! - [`kid`] - Key identifier (KID) types
//! - [`ml_dsa`] - FIPS 204 ML-DSA-65 (post-quantum signatures, owner-key V4)
//! - [`owner_key`] - owner-key migration traits and attestation envelopes
//! - [`shamir`] - Shamir secret sharing (split, seal, reconstruct) for owner-key distribution
//! - [`secret_fetch`] - secretless connector credential-fetch hook API
//! - [`canonicalize`] - Signature canonicalization helpers
//!
//! # Example: Signing and Verifying
//!
//! ```rust
//! use fcp_crypto::ed25519::Ed25519SigningKey;
//!
//! let sk = Ed25519SigningKey::generate();
//! let pk = sk.verifying_key();
//!
//! let message = b"important message";
//! let signature = sk.sign(message);
//!
//! assert!(pk.verify(message, &signature).is_ok());
//! ```
//!
//! # Example: HPKE Sealed Box
//!
//! ```rust
//! use fcp_crypto::x25519::X25519SecretKey;
//! use fcp_crypto::hpke_seal::{hpke_seal, hpke_open, Fcp2Aad};
//!
//! let recipient_secret_key = X25519SecretKey::generate();
//! let recipient_public_key = recipient_secret_key.public_key();
//!
//! let plaintext = b"secret zone key";
//! let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
//!
//! let sealed = hpke_seal(&recipient_public_key, plaintext, &aad).unwrap();
//! let opened = hpke_open(&recipient_secret_key, &sealed, &aad).unwrap();
//!
//! assert_eq!(opened, plaintext);
//! ```
//!
//! # Example: Capability Token (COSE/CWT)
//!
//! ```rust
//! use fcp_crypto::ed25519::Ed25519SigningKey;
//! use fcp_crypto::cose::{CapabilityTokenBuilder, CoseToken};
//! use chrono::{Duration, Utc};
//!
//! let issuance_key = Ed25519SigningKey::generate();
//!
//! let token = CapabilityTokenBuilder::new()
//!     .capability_id("cap:discord.send")
//!     .zone_id("z:work")
//!     .principal("agent:claude")
//!     .operations(&["discord.send_message"])
//!     .issuer("node:primary")
//!     .validity(Utc::now(), Utc::now() + Duration::hours(24))
//!     .sign(&issuance_key)
//!     .unwrap();
//!
//! let claims = token.verify(&issuance_key.verifying_key()).unwrap();
//! assert_eq!(claims.get_capability_id(), Some("cap:discord.send"));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod bls;
pub mod canonicalize;
pub mod cose;
pub mod ed25519;
pub mod error;
pub mod frost;
pub mod hkdf;
pub mod hpke_seal;
pub mod hybrid;
pub mod kid;
pub mod mac;
pub mod ml_dsa;
pub mod owner_key;
pub mod secret_fetch;
pub mod shamir;
pub mod threshold_hpke;
pub mod vector_commit;
pub mod x25519;
pub mod xwing;

// Re-export commonly used types at crate root
pub use aead::{
    AeadKey, ChaCha20Nonce, ChaCha20Poly1305Cipher, XChaCha20Nonce, XChaCha20Poly1305Cipher,
    chacha20_decrypt, chacha20_encrypt, xchacha20_decrypt, xchacha20_encrypt,
};
pub use bls::{
    AggregateSignature, BlsError, BlsPublicKey, BlsSecretKey, BlsSignature, PopRegistry,
    ProofOfPossession,
};
pub use canonicalize::{Signable, canonical_signing_bytes, schema_hash};
pub use cose::{CapabilityTokenBuilder, CoseToken, CwtClaims};
pub use ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, OwnerSigner};
pub use error::{CryptoError, CryptoResult};
pub use frost::{
    FrostDkgRound1Package, FrostDkgRound1SecretPackage, FrostDkgRound2Package,
    FrostDkgRound2SecretPackage, FrostKeyPackage, FrostLocalCoordinator, FrostPublicKeyPackage,
    FrostSignatureShare, FrostSigningCommitments, FrostSigningNonces, FrostSigningPackage,
    FrostSigningShare, aggregate, commit, commit_with_rng, dkg_part1, dkg_part1_with_rng,
    dkg_part2, dkg_part3, sign, signing_package,
};
pub use hkdf::{
    DerivedKey, Fcp2KeyDerivation, HkdfSha256, MacKeyPurpose, SessionDirection, hkdf_sha256,
    hkdf_sha256_array,
};
pub use hpke_seal::{Fcp2Aad, HpkeSealedBox, hpke_open, hpke_seal};
pub use hybrid::{
    EVENT_PQ_POLICY_DOWNGRADE, HYBRID_SIGNING_CONTEXT, HybridSignable, HybridSignedObjectKind,
    HybridVerifyReport, HybridVerifyWarning, PqPolicyDowngradeAudit, PqPolicyDowngradeAuthorizer,
    PqSigningPolicy, SignatureStatus, SignedEnvelope, downgrade_policy_to_either_ok,
    signing_bytes_for_canonical_payload, signing_bytes_for_payload, verify_signable,
    verify_signable_with_policy,
};
pub use kid::KeyId;
pub use mac::{Blake3Mac, MacKey, blake3_mac, blake3_mac_full, blake3_mac_verify};
pub use ml_dsa::{ML_DSA_65_SEED_SIZE, MlDsa65SigningKey, MlDsa65VerifyingKey};
pub use owner_key::{
    HybridOwnerKeyIds, HybridOwnerSignature, HybridOwnerSigner, ML_DSA_65_PUBLIC_KEY_SIZE,
    ML_DSA_65_SECRET_KEY_SIZE, ML_DSA_65_SEED_BYTES, ML_DSA_65_SIGNATURE_SIZE,
    MlDsa65SecretKeyBytes, MlDsa65SignatureBytes, MlDsa65VerifyingKeyBytes,
    OWNER_KEY_MIGRATION_ATTESTATION_SCHEMA, OWNER_KEY_MIGRATION_DOMAIN, OwnerKeyAlgorithm,
    OwnerKeyMigrationAttestation, OwnerKeyMigrationTranscript,
};
pub use secret_fetch::{
    AsyncSecretFetchHook, AsyncToSyncSecretFetchHook, CredentialIdHash, SecretFetchError,
    SecretFetchHook,
};
pub use shamir::{
    SealedShamirShare, ShamirError, ShamirResult, ShamirShare, ZeroizingSecret, open_share,
    reconstruct_secret, seal_share, split_and_seal, split_secret, split_secret_with_rng,
};
pub use threshold_hpke::{
    DecapShare, ThresholdHpkeCiphertext, ThresholdHpkeError, ThresholdHpkePublicKey, combine_decap,
    decap_share, encap, encap_with_rng,
};
pub use x25519::{X25519PublicKey, X25519SecretKey, X25519SharedSecret};
pub use xwing::{
    FCP4_AAD_VERSION, Fcp4Aad, MAX_V4_PAYLOAD_BYTES, XWING_AEAD_INFO, XWING_ENC_SIZE,
    XWING_ENCAPSULATION_RANDOMNESS_SIZE, XWING_MAX_CIPHERTEXT, XWING_PUBLIC_KEY_SIZE,
    XWING_SECRET_KEY_SIZE, XWING_SHARED_SECRET_SIZE, XWingKem, XWingProvider, XWingPublicKey,
    XWingSealedBox, XWingSecretKey, XWingStub, XWingWireSize,
};

/// Common crypto imports for connector and host code.
pub mod prelude {
    pub use crate::{
        AsyncSecretFetchHook, AsyncToSyncSecretFetchHook, CredentialIdHash, SecretFetchError,
        SecretFetchHook, ZeroizingSecret,
    };
}

/// Test-only crypto helpers.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    pub use crate::secret_fetch::InMemorySecretRegistry;

    use crate::ZeroizingSecret;

    /// Construct a zeroizing secret from static test bytes.
    ///
    /// This is intentionally named as an unsafe construction path because static
    /// bytes cannot themselves be wiped. Use only for golden vectors and tests
    /// where the fixture is already public.
    #[must_use]
    pub fn unsafe_construct_from_static_test_secret(bytes: &'static [u8]) -> ZeroizingSecret {
        ZeroizingSecret::new(bytes)
    }
}
