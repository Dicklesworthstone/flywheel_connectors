//! Error types for FCP2 cryptographic operations.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid key length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },

    /// Invalid signature length.
    #[error("invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        /// Expected signature length in bytes.
        expected: usize,
        /// Actual signature length provided.
        actual: usize,
    },

    /// Invalid signature.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Hybrid envelope is missing its required classical Ed25519 signature.
    #[error("classical Ed25519 signature missing")]
    ClassicalSignatureMissing,

    /// Hybrid envelope is missing its required post-quantum signature.
    #[error("post-quantum signature missing")]
    PqSignatureMissing,

    /// Invalid key ID format.
    #[error("invalid key ID: {0}")]
    InvalidKeyId(String),

    /// AEAD encryption failed.
    #[error("AEAD encryption failed")]
    AeadEncryptFailed,

    /// AEAD decryption failed (authentication failed or invalid ciphertext).
    #[error("AEAD decryption failed: authentication or decryption error")]
    AeadDecryptFailed,

    /// HPKE operation failed.
    #[error("HPKE operation failed: {0}")]
    HpkeFailed(String),

    /// COSE operation failed.
    #[error("COSE operation failed: {0}")]
    CoseFailed(String),

    /// Invalid nonce length.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length in bytes.
        expected: usize,
        /// Actual nonce length provided.
        actual: usize,
    },

    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid public key.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key.
    #[error("invalid secret key")]
    InvalidSecretKey,

    /// FROST threshold cryptography operation failed.
    #[error("FROST operation failed: {0}")]
    FrostFailed(String),

    /// Threshold HPKE failure (flywheel_connectors-angoc.11.6.1).
    #[error("threshold hpke: {0}")]
    ThresholdHpke(#[from] crate::threshold_hpke::ThresholdHpkeError),

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Untrusted encoded payload exceeded the pre-decode size bound.
    #[error("payload too large: observed {observed} bytes > max {max} bytes")]
    PayloadTooLarge {
        /// Observed payload length in bytes.
        observed: usize,
        /// Maximum accepted payload length in bytes.
        max: usize,
    },

    /// Token validation error.
    #[error("token validation error: {0}")]
    TokenValidationError(String),

    /// Token expired.
    #[error("token expired")]
    TokenExpired,

    /// Token not yet valid.
    #[error("token not yet valid")]
    TokenNotYetValid,

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// Missing Ed25519 signer for a hybrid signing policy that needs it.
    #[error("missing classical signer for hybrid signing policy {policy}")]
    MissingClassicalSigner {
        /// Policy that required the signer.
        policy: &'static str,
    },

    /// Missing ML-DSA signer for a hybrid signing policy that needs it.
    #[error("missing post-quantum signer for hybrid signing policy {policy}")]
    MissingPqSigner {
        /// Policy that required the signer.
        policy: &'static str,
    },

    /// Missing Ed25519 signature for a hybrid verification policy that needs it.
    #[error("missing classical signature for hybrid signing policy {policy}")]
    MissingClassicalSignature {
        /// Policy that required the signature.
        policy: &'static str,
    },

    /// Missing ML-DSA signature for a hybrid verification policy that needs it.
    #[error("missing post-quantum signature for hybrid signing policy {policy}")]
    MissingPqSignature {
        /// Policy that required the signature.
        policy: &'static str,
    },

    /// Missing Ed25519 verifier for a hybrid verification policy that needs it.
    #[error("missing classical verifier for hybrid signing policy {policy}")]
    MissingClassicalVerifier {
        /// Policy that required the verifier.
        policy: &'static str,
    },

    /// Missing ML-DSA verifier for a hybrid verification policy that needs it.
    #[error("missing post-quantum verifier for hybrid signing policy {policy}")]
    MissingPqVerifier {
        /// Policy that required the verifier.
        policy: &'static str,
    },

    /// Hybrid verification could not satisfy the requested signature policy.
    #[error("hybrid signing policy {policy} rejected envelope: {reason}")]
    HybridPolicyViolation {
        /// Policy that rejected the envelope.
        policy: &'static str,
        /// Human-readable rejection reason.
        reason: String,
    },

    /// COSE protected-header algorithm did not match what the verifier expects.
    #[error("algorithm mismatch: expected {expected}, got {got}")]
    AlgorithmMismatch {
        /// Expected algorithm description (e.g. `"EdDSA"`).
        expected: &'static str,
        /// Actual algorithm description from the protected header.
        got: String,
    },

    /// COSE protected header lists a critical header label this verifier
    /// does not understand (RFC 8152 §3.1 — message MUST be rejected).
    #[error("unsupported critical header: {0}")]
    UnsupportedCriticalHeader(String),

    /// COSE protected-header key ID did not match the verifying key used to
    /// authenticate the token.
    #[error("key ID mismatch: expected {expected}, got {got}")]
    KeyIdMismatch {
        /// Expected key ID derived from the verifying key.
        expected: String,
        /// Actual key ID carried in the protected header.
        got: String,
    },

    /// COSE header placement or cross-field policy violation.
    #[error("header policy violation: {0}")]
    HeaderPolicyViolation(String),

    /// A CBOR value carried a tag at a position where FCP canonical
    /// encoding forbids tags. Aligns fcp-crypto's CWT claims decode
    /// with `fcp_cbor::SerializationError::UnsupportedTag` so a token
    /// accepted by fcp-crypto is also decodable by fcp-cbor
    /// (flywheel_connectors-8azf9).
    #[error("invalid CBOR tag {tag} in CWT claims (tags are not permitted)")]
    InvalidCborTag {
        /// CBOR tag number that was encountered.
        tag: u64,
    },
}

impl CryptoError {
    /// Stable machine-readable reason code for crypto policy/audit surfaces.
    #[must_use]
    pub const fn reason_code(&self) -> Option<&'static str> {
        match self {
            Self::ClassicalSignatureMissing | Self::PqSignatureMissing => Some("DowngradeAttempt"),
            Self::MissingClassicalSignature { .. } | Self::MissingPqSignature { .. } => {
                Some("DowngradeAttempt")
            }
            Self::MissingClassicalVerifier { .. } | Self::MissingPqVerifier { .. } => {
                Some("MissingVerifier")
            }
            Self::HybridPolicyViolation { .. } => Some("HybridPolicyViolation"),
            _ => None,
        }
    }

    /// Stable reason code for hybrid-signing verification failures.
    ///
    /// This is intentionally narrower than `Display`: callers can use it for
    /// audit records, conformance assertions, and machine-readable downgrade
    /// handling without parsing a human-readable error string.
    #[must_use]
    pub const fn hybrid_reason_code(&self) -> Option<&'static str> {
        match self {
            Self::MissingClassicalSignature { .. } | Self::MissingPqSignature { .. } => {
                Some("DowngradeAttempt")
            }
            Self::MissingClassicalVerifier { .. } | Self::MissingPqVerifier { .. } => {
                Some("MissingVerifier")
            }
            Self::HybridPolicyViolation { .. } => Some("HybridPolicyViolation"),
            _ => None,
        }
    }
}

/// Result type alias for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_invalid_key_length() {
        let err = CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(err.to_string(), "invalid key length: expected 32, got 16");
    }

    #[test]
    fn error_display_invalid_signature_length() {
        let err = CryptoError::InvalidSignatureLength {
            expected: 64,
            actual: 32,
        };
        assert_eq!(
            err.to_string(),
            "invalid signature length: expected 64, got 32"
        );
    }

    #[test]
    fn error_display_signature_verification_failed() {
        let err = CryptoError::SignatureVerificationFailed;
        assert_eq!(err.to_string(), "signature verification failed");
    }

    #[test]
    fn error_display_invalid_key_id() {
        let err = CryptoError::InvalidKeyId("bad hex".to_string());
        assert_eq!(err.to_string(), "invalid key ID: bad hex");
    }

    #[test]
    fn error_display_aead_encrypt_failed() {
        let err = CryptoError::AeadEncryptFailed;
        assert_eq!(err.to_string(), "AEAD encryption failed");
    }

    #[test]
    fn error_display_aead_decrypt_failed() {
        let err = CryptoError::AeadDecryptFailed;
        assert_eq!(
            err.to_string(),
            "AEAD decryption failed: authentication or decryption error"
        );
    }

    #[test]
    fn error_display_hpke_failed() {
        let err = CryptoError::HpkeFailed("encap error".to_string());
        assert_eq!(err.to_string(), "HPKE operation failed: encap error");
    }

    #[test]
    fn error_display_cose_failed() {
        let err = CryptoError::CoseFailed("invalid header".to_string());
        assert_eq!(err.to_string(), "COSE operation failed: invalid header");
    }

    #[test]
    fn error_display_invalid_nonce_length() {
        let err = CryptoError::InvalidNonceLength {
            expected: 12,
            actual: 8,
        };
        assert_eq!(err.to_string(), "invalid nonce length: expected 12, got 8");
    }

    #[test]
    fn error_display_key_derivation_failed() {
        let err = CryptoError::KeyDerivationFailed("bad ikm".to_string());
        assert_eq!(err.to_string(), "key derivation failed: bad ikm");
    }

    #[test]
    fn error_display_invalid_public_key() {
        let err = CryptoError::InvalidPublicKey;
        assert_eq!(err.to_string(), "invalid public key");
    }

    #[test]
    fn error_display_invalid_secret_key() {
        let err = CryptoError::InvalidSecretKey;
        assert_eq!(err.to_string(), "invalid secret key");
    }

    #[test]
    fn error_display_frost_failed() {
        let err = CryptoError::FrostFailed("invalid identifier".to_string());
        assert_eq!(
            err.to_string(),
            "FROST operation failed: invalid identifier"
        );
    }

    #[test]
    fn error_display_serialization_error() {
        let err = CryptoError::SerializationError("bad cbor".to_string());
        assert_eq!(err.to_string(), "serialization error: bad cbor");
    }

    #[test]
    fn error_display_payload_too_large() {
        let err = CryptoError::PayloadTooLarge {
            observed: 65_537,
            max: 65_536,
        };
        assert_eq!(
            err.to_string(),
            "payload too large: observed 65537 bytes > max 65536 bytes"
        );
    }

    #[test]
    fn error_display_token_validation_error() {
        let err = CryptoError::TokenValidationError("missing field".to_string());
        assert_eq!(err.to_string(), "token validation error: missing field");
    }

    #[test]
    fn error_display_token_expired() {
        let err = CryptoError::TokenExpired;
        assert_eq!(err.to_string(), "token expired");
    }

    #[test]
    fn error_display_token_not_yet_valid() {
        let err = CryptoError::TokenNotYetValid;
        assert_eq!(err.to_string(), "token not yet valid");
    }

    #[test]
    fn error_display_missing_field() {
        let err = CryptoError::MissingField("issuer".to_string());
        assert_eq!(err.to_string(), "missing required field: issuer");
    }

    #[test]
    fn error_display_key_id_mismatch() {
        let err = CryptoError::KeyIdMismatch {
            expected: "0011223344556677".to_string(),
            got: "8899aabbccddeeff".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "key ID mismatch: expected 0011223344556677, got 8899aabbccddeeff"
        );
    }

    #[test]
    fn error_display_header_policy_violation() {
        let err = CryptoError::HeaderPolicyViolation("crit must be protected".to_string());
        assert_eq!(
            err.to_string(),
            "header policy violation: crit must be protected"
        );
    }

    // ---- Debug format ----

    #[test]
    fn error_debug_invalid_key_length() {
        let err = CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidKeyLength"));
        assert!(debug.contains("32"));
        assert!(debug.contains("16"));
    }

    #[test]
    fn error_debug_signature_verification_failed() {
        let err = CryptoError::SignatureVerificationFailed;
        let debug = format!("{err:?}");
        assert!(debug.contains("SignatureVerificationFailed"));
    }

    #[test]
    fn error_debug_key_id_mismatch() {
        let err = CryptoError::KeyIdMismatch {
            expected: "0011223344556677".to_string(),
            got: "8899aabbccddeeff".to_string(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("KeyIdMismatch"));
        assert!(debug.contains("0011223344556677"));
        assert!(debug.contains("8899aabbccddeeff"));
    }

    #[test]
    fn error_debug_header_policy_violation() {
        let err = CryptoError::HeaderPolicyViolation("kid must be protected".to_string());
        let debug = format!("{err:?}");
        assert!(debug.contains("HeaderPolicyViolation"));
        assert!(debug.contains("kid must be protected"));
    }

    #[test]
    fn error_debug_hpke_failed() {
        let err = CryptoError::HpkeFailed("test error".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("HpkeFailed"));
        assert!(debug.contains("test error"));
    }

    #[test]
    fn error_debug_frost_failed() {
        let err = CryptoError::FrostFailed("bad proof".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("FrostFailed"));
        assert!(debug.contains("bad proof"));
    }

    #[test]
    fn error_debug_token_expired() {
        let err = CryptoError::TokenExpired;
        let debug = format!("{err:?}");
        assert!(debug.contains("TokenExpired"));
    }

    #[test]
    fn error_debug_missing_field() {
        let err = CryptoError::MissingField("payload".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("MissingField"));
        assert!(debug.contains("payload"));
    }

    // ---- CryptoResult type alias ----

    #[test]
    fn crypto_result_ok() {
        let result: CryptoResult<u32> = Ok(42);
        match result {
            Ok(v) => assert_eq!(v, 42),
            Err(e) => panic!("expected Ok(42), got Err({e:?})"),
        }
    }

    #[test]
    fn crypto_result_err() {
        let result: CryptoResult<u32> = Err(CryptoError::InvalidPublicKey);
        assert!(result.is_err());
    }

    // ---- Error trait ----

    #[test]
    fn error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(CryptoError::AeadEncryptFailed);
        assert_eq!(err.to_string(), "AEAD encryption failed");
    }

    // ---- Error source chain ----

    #[test]
    fn error_source_is_none_for_leaf_variants() {
        use std::error::Error;
        let variants: Vec<CryptoError> = vec![
            CryptoError::SignatureVerificationFailed,
            CryptoError::AeadEncryptFailed,
            CryptoError::AeadDecryptFailed,
            CryptoError::InvalidPublicKey,
            CryptoError::InvalidSecretKey,
            CryptoError::FrostFailed("test".into()),
            CryptoError::TokenExpired,
            CryptoError::TokenNotYetValid,
        ];
        for variant in &variants {
            assert!(
                variant.source().is_none(),
                "expected no source for {variant:?}"
            );
        }
    }

    #[test]
    fn error_display_invalid_key_length_boundary_values() {
        let err = CryptoError::InvalidKeyLength {
            expected: 0,
            actual: 0,
        };
        assert_eq!(err.to_string(), "invalid key length: expected 0, got 0");
    }

    #[test]
    fn error_display_invalid_key_length_large_values() {
        let err = CryptoError::InvalidKeyLength {
            expected: usize::MAX,
            actual: usize::MAX,
        };
        let display = err.to_string();
        assert!(display.contains("expected"));
        assert!(display.contains("got"));
    }

    #[test]
    fn error_display_hpke_failed_empty_message() {
        let err = CryptoError::HpkeFailed(String::new());
        assert_eq!(err.to_string(), "HPKE operation failed: ");
    }

    #[test]
    fn error_display_cose_failed_unicode() {
        let err = CryptoError::CoseFailed("falló el token".to_string());
        assert!(err.to_string().contains("falló"));
    }

    #[test]
    fn error_display_missing_field_empty() {
        let err = CryptoError::MissingField(String::new());
        assert_eq!(err.to_string(), "missing required field: ");
    }

    #[test]
    fn error_debug_all_variants_contain_variant_name() {
        let variants: Vec<(&str, CryptoError)> = vec![
            (
                "InvalidKeyLength",
                CryptoError::InvalidKeyLength {
                    expected: 1,
                    actual: 2,
                },
            ),
            (
                "InvalidSignatureLength",
                CryptoError::InvalidSignatureLength {
                    expected: 3,
                    actual: 4,
                },
            ),
            (
                "SignatureVerificationFailed",
                CryptoError::SignatureVerificationFailed,
            ),
            ("InvalidKeyId", CryptoError::InvalidKeyId("x".into())),
            ("AeadEncryptFailed", CryptoError::AeadEncryptFailed),
            ("AeadDecryptFailed", CryptoError::AeadDecryptFailed),
            ("HpkeFailed", CryptoError::HpkeFailed("y".into())),
            ("CoseFailed", CryptoError::CoseFailed("z".into())),
            (
                "InvalidNonceLength",
                CryptoError::InvalidNonceLength {
                    expected: 5,
                    actual: 6,
                },
            ),
            (
                "KeyDerivationFailed",
                CryptoError::KeyDerivationFailed("w".into()),
            ),
            ("InvalidPublicKey", CryptoError::InvalidPublicKey),
            ("InvalidSecretKey", CryptoError::InvalidSecretKey),
            ("FrostFailed", CryptoError::FrostFailed("u".into())),
            (
                "SerializationError",
                CryptoError::SerializationError("s".into()),
            ),
            (
                "TokenValidationError",
                CryptoError::TokenValidationError("t".into()),
            ),
            ("TokenExpired", CryptoError::TokenExpired),
            ("TokenNotYetValid", CryptoError::TokenNotYetValid),
            ("MissingField", CryptoError::MissingField("f".into())),
        ];

        for (name, variant) in &variants {
            let debug = format!("{variant:?}");
            assert!(
                debug.contains(name),
                "Debug for {name} missing variant name: {debug}"
            );
        }
    }

    #[test]
    fn crypto_result_map_works() {
        let result: CryptoResult<u32> = Ok(10);
        let mapped = result.map(|v| v * 2);
        assert_eq!(mapped.unwrap(), 20);
    }

    #[test]
    fn crypto_result_err_downcast() {
        let err = CryptoError::TokenExpired;
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(boxed.to_string().contains("expired"));
    }

    #[test]
    fn error_display_all_variants_non_empty() {
        let variants: Vec<CryptoError> = vec![
            CryptoError::InvalidKeyLength {
                expected: 1,
                actual: 2,
            },
            CryptoError::InvalidSignatureLength {
                expected: 3,
                actual: 4,
            },
            CryptoError::SignatureVerificationFailed,
            CryptoError::InvalidKeyId("x".into()),
            CryptoError::AeadEncryptFailed,
            CryptoError::AeadDecryptFailed,
            CryptoError::HpkeFailed("y".into()),
            CryptoError::CoseFailed("z".into()),
            CryptoError::InvalidNonceLength {
                expected: 5,
                actual: 6,
            },
            CryptoError::KeyDerivationFailed("w".into()),
            CryptoError::InvalidPublicKey,
            CryptoError::InvalidSecretKey,
            CryptoError::FrostFailed("u".into()),
            CryptoError::SerializationError("s".into()),
            CryptoError::TokenValidationError("t".into()),
            CryptoError::TokenExpired,
            CryptoError::TokenNotYetValid,
            CryptoError::MissingField("f".into()),
        ];

        for variant in &variants {
            let display = variant.to_string();
            assert!(!display.is_empty(), "empty display for {variant:?}");
        }
    }
}
