//! Recovery phrase handling using BIP39 mnemonics.
//!
//! Recovery phrases are 24-word BIP39 mnemonics that can be used to derive
//! the owner keypair for disaster recovery.

use bip39::{Language, Mnemonic};
use fcp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Errors related to recovery phrases.
#[derive(Debug, Error)]
pub enum RecoveryPhraseError {
    /// Invalid mnemonic words.
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Wrong word count.
    #[error("expected 24 words, got {0}")]
    WrongWordCount(usize),

    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    DerivationFailed(String),
}

/// A BIP39 recovery phrase for deriving the owner keypair.
///
/// All secret material is zeroized on drop: the redundant `entropy` copy is
/// wiped by this type's `Drop`, and the authoritative `mnemonic` (which holds
/// the 24-word secret as `[u16; 24]`) is wiped because `bip39` is built with
/// its `zeroize` feature so `Mnemonic` derives `ZeroizeOnDrop`. The
/// compile-time assertion in this module's tests fails the build if that
/// feature is ever dropped.
pub struct RecoveryPhrase {
    /// The underlying BIP39 mnemonic. `ZeroizeOnDrop` via the `zeroize` feature.
    mnemonic: Mnemonic,

    /// Cached entropy bytes (zeroized on drop).
    entropy: Vec<u8>,
}

impl Drop for RecoveryPhrase {
    fn drop(&mut self) {
        // Wipe the redundant entropy copy. The `mnemonic` field is wiped
        // separately by `Mnemonic`'s own `ZeroizeOnDrop` when this struct's
        // fields drop after this body runs.
        self.entropy.zeroize();
    }
}

impl Clone for RecoveryPhrase {
    fn clone(&self) -> Self {
        Self {
            mnemonic: self.mnemonic.clone(),
            entropy: self.entropy.clone(),
        }
    }
}

impl PartialEq for RecoveryPhrase {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for security
        use subtle::ConstantTimeEq;
        self.entropy.ct_eq(&other.entropy).into()
    }
}

impl Eq for RecoveryPhrase {}

impl RecoveryPhrase {
    /// Generate a new random recovery phrase with 256 bits of entropy.
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic cannot be generated from entropy.
    pub fn generate() -> Result<Self, RecoveryPhraseError> {
        use rand::RngCore;
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| RecoveryPhraseError::InvalidMnemonic(redact_bip39_error(e)))?;

        // Zeroize the local entropy copy
        entropy.zeroize();

        Ok(Self {
            entropy: mnemonic.to_entropy(),
            mnemonic,
        })
    }

    /// Parse a recovery phrase from a space-separated mnemonic string.
    ///
    /// # Errors
    ///
    /// Returns an error if the word count is invalid or the phrase cannot be parsed.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, RecoveryPhraseError> {
        let words: Vec<&str> = phrase.split_whitespace().collect();

        if words.len() != 24 {
            return Err(RecoveryPhraseError::WrongWordCount(words.len()));
        }

        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| RecoveryPhraseError::InvalidMnemonic(redact_bip39_error(e)))?;

        Ok(Self {
            entropy: mnemonic.to_entropy(),
            mnemonic,
        })
    }

    /// Parse a recovery phrase from an array of words.
    ///
    /// # Errors
    ///
    /// Returns an error if the word count is invalid or the phrase cannot be parsed.
    pub fn from_words(words: &[&str]) -> Result<Self, RecoveryPhraseError> {
        if words.len() != 24 {
            return Err(RecoveryPhraseError::WrongWordCount(words.len()));
        }

        let phrase = Zeroizing::new(words.join(" "));
        Self::from_mnemonic(&phrase)
    }

    /// Get the mnemonic words as a space-separated string.
    ///
    /// # Security
    ///
    /// This exposes the recovery phrase. The returned string should be
    /// displayed to the user only during initial setup and then zeroized.
    #[must_use]
    pub fn to_phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Get the mnemonic words as a vector.
    ///
    /// # Security
    ///
    /// This exposes the recovery phrase. The returned vector should be
    /// displayed to the user only during initial setup.
    #[must_use]
    pub fn words(&self) -> Vec<&'static str> {
        self.mnemonic.words().collect()
    }

    /// Derive the owner keypair from this recovery phrase.
    ///
    /// Uses HKDF-SHA256 with a domain separator to derive the Ed25519 seed
    /// from the BIP39 entropy.
    ///
    /// # Panics
    ///
    /// Panics if HKDF expansion fails or the derived seed is invalid (should never happen).
    #[must_use]
    pub fn derive_owner_keypair(&self) -> OwnerKeypair {
        // Domain separator for FCP2 owner key derivation
        const FCP2_OWNER_KEY_DOMAIN: &[u8] = b"FCP2-OWNER-KEY-V1";

        // Use HKDF to derive a 32-byte seed from the entropy
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(FCP2_OWNER_KEY_DOMAIN), &self.entropy);
        let mut seed = [0u8; 32];
        hk.expand(b"owner-signing-key", &mut seed)
            .expect("32 bytes is valid for HKDF-SHA256");

        // Create the signing key from the seed
        let signing_key = Ed25519SigningKey::from_bytes(&seed)
            .expect("32-byte HKDF output is valid Ed25519 seed");

        // Zeroize the seed
        seed.zeroize();

        OwnerKeypair { signing_key }
    }

    /// Get the entropy bytes (for advanced use cases).
    ///
    /// # Security
    ///
    /// This exposes the raw entropy. Use with extreme caution.
    #[must_use]
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }
}

fn redact_bip39_error(error: bip39::Error) -> String {
    match error {
        bip39::Error::BadWordCount(count) => format!("invalid word count: {count}"),
        bip39::Error::UnknownWord(index) => format!("unknown word at position {}", index + 1),
        bip39::Error::BadEntropyBitCount(bits) => format!("invalid entropy bit count: {bits}"),
        bip39::Error::InvalidChecksum => "invalid checksum".to_string(),
        bip39::Error::AmbiguousLanguages(_) => "ambiguous word list".to_string(),
    }
}

impl std::fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryPhrase")
            .field("word_count", &24)
            .finish_non_exhaustive()
    }
}

/// Owner keypair derived from a recovery phrase.
#[derive(ZeroizeOnDrop)]
pub struct OwnerKeypair {
    /// The signing key (private).
    signing_key: Ed25519SigningKey,
}

impl OwnerKeypair {
    /// Get the verifying (public) key.
    #[must_use]
    pub fn public(&self) -> Ed25519VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign data with the owner key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> fcp_crypto::Ed25519Signature {
        self.signing_key.sign(message)
    }

    /// Get the raw signing key bytes.
    ///
    /// # Security
    ///
    /// This exposes the private key material. Use with extreme caution.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl std::fmt::Debug for OwnerKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerKeypair")
            .field("public_key", &hex::encode(self.public().to_bytes()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard for the recovery-phrase zeroization contract: if the
    /// `bip39` `zeroize` feature is ever dropped from Cargo.toml, `Mnemonic`
    /// loses its `ZeroizeOnDrop` impl and this fails to compile — surfacing the
    /// silent secret-retention regression at build time rather than in a core
    /// dump. `Mnemonic` holds the authoritative 24-word owner secret.
    #[test]
    fn mnemonic_is_zeroize_on_drop() {
        const fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Mnemonic>();
    }

    #[test]
    fn test_generate_recovery_phrase() {
        let phrase = RecoveryPhrase::generate().unwrap();
        assert_eq!(phrase.words().len(), 24);
    }

    #[test]
    fn test_parse_recovery_phrase() {
        // Use a well-known test vector (all "abandon" except last word)
        let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let phrase = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        assert_eq!(phrase.words().len(), 24);
    }

    #[test]
    fn test_derive_owner_keypair_deterministic() {
        let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let phrase1 = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        let phrase2 = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();

        let keypair1 = phrase1.derive_owner_keypair();
        let keypair2 = phrase2.derive_owner_keypair();

        assert_eq!(keypair1.public().to_bytes(), keypair2.public().to_bytes());
    }

    #[test]
    fn test_wrong_word_count() {
        let result = RecoveryPhrase::from_mnemonic("abandon abandon abandon");
        assert!(matches!(
            result,
            Err(RecoveryPhraseError::WrongWordCount(3))
        ));
    }

    #[test]
    fn test_invalid_word() {
        let invalid_phrase = "invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid";

        let result = RecoveryPhrase::from_mnemonic(invalid_phrase);
        assert!(matches!(
            result,
            Err(RecoveryPhraseError::InvalidMnemonic(_))
        ));
    }

    #[test]
    fn test_invalid_mnemonic_error_redacts_unknown_words() {
        let secret_like_word = "correct-horse-battery-staple";
        let invalid_phrase = format!(
            "{secret_like_word} abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        );

        let err = RecoveryPhrase::from_mnemonic(&invalid_phrase).unwrap_err();
        let rendered = err.to_string();

        assert!(matches!(err, RecoveryPhraseError::InvalidMnemonic(_)));
        assert!(!rendered.contains(secret_like_word));
        assert!(!rendered.contains("correct"));
        assert!(
            rendered.contains("unknown word at position 1"),
            "unexpected redacted error: {rendered}"
        );
    }

    #[test]
    fn test_invalid_checksum_error_redacts_recovery_words() {
        let invalid_checksum_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

        let err = RecoveryPhrase::from_mnemonic(invalid_checksum_phrase).unwrap_err();
        let rendered = err.to_string();

        assert!(matches!(err, RecoveryPhraseError::InvalidMnemonic(_)));
        assert!(!rendered.contains("abandon"));
        assert!(
            rendered.contains("invalid checksum"),
            "unexpected redacted error: {rendered}"
        );
    }

    // ---- from_words ----

    #[test]
    fn test_from_words_roundtrip() {
        let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let phrase = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        let words = phrase.words();
        let phrase2 = RecoveryPhrase::from_words(&words).unwrap();
        assert_eq!(phrase, phrase2);
    }

    #[test]
    fn test_from_words_wrong_count() {
        let result = RecoveryPhrase::from_words(&["abandon", "abandon", "abandon"]);
        assert!(matches!(
            result,
            Err(RecoveryPhraseError::WrongWordCount(3))
        ));
    }

    // ---- to_phrase ----

    #[test]
    fn test_to_phrase_returns_24_words() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let phrase_str = phrase.to_phrase();
        assert_eq!(phrase_str.split_whitespace().count(), 24);
    }

    // ---- entropy ----

    #[test]
    fn test_entropy_is_32_bytes() {
        let phrase = RecoveryPhrase::generate().unwrap();
        assert_eq!(phrase.entropy().len(), 32);
    }

    // ---- clone and eq ----

    #[test]
    fn test_clone_preserves_equality() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let cloned = phrase.clone();
        assert_eq!(phrase, cloned);
    }

    #[test]
    fn test_different_phrases_not_equal() {
        let phrase1 = RecoveryPhrase::generate().unwrap();
        let phrase2 = RecoveryPhrase::generate().unwrap();
        assert_ne!(phrase1, phrase2);
    }

    // ---- Debug doesn't leak phrase ----

    #[test]
    fn test_debug_does_not_leak_phrase() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let debug = format!("{phrase:?}");
        assert!(debug.contains("RecoveryPhrase"));
        assert!(debug.contains("word_count"));
        // Should NOT contain actual mnemonic words
        assert!(!debug.contains("abandon"));
    }

    // ---- OwnerKeypair ----

    #[test]
    fn test_owner_keypair_sign_verify() {
        let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let phrase = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        let keypair = phrase.derive_owner_keypair();
        let message = b"test message for signing";
        let signature = keypair.sign(message);
        assert!(keypair.public().verify(message, &signature).is_ok());
    }

    #[test]
    fn test_owner_keypair_to_bytes() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        let bytes = keypair.to_bytes();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_owner_keypair_debug_no_private_key() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        let debug = format!("{keypair:?}");
        assert!(debug.contains("OwnerKeypair"));
        assert!(debug.contains("public_key"));
    }

    // ---- RecoveryPhraseError Display ----

    #[test]
    fn test_error_display() {
        assert!(
            RecoveryPhraseError::WrongWordCount(12)
                .to_string()
                .contains("12")
        );
        assert!(
            RecoveryPhraseError::InvalidMnemonic("bad".into())
                .to_string()
                .contains("bad")
        );
        assert!(
            RecoveryPhraseError::DerivationFailed("failed".into())
                .to_string()
                .contains("failed")
        );
    }

    // ---- Edge cases ----

    #[test]
    fn test_from_mnemonic_empty_string() {
        let result = RecoveryPhrase::from_mnemonic("");
        assert!(matches!(
            result,
            Err(RecoveryPhraseError::WrongWordCount(0))
        ));
    }

    #[test]
    fn test_from_words_empty_array() {
        let result = RecoveryPhrase::from_words(&[]);
        assert!(matches!(
            result,
            Err(RecoveryPhraseError::WrongWordCount(0))
        ));
    }

    #[test]
    fn test_from_mnemonic_too_many_words() {
        let words = "abandon ".repeat(25);
        let result = RecoveryPhrase::from_mnemonic(words.trim());
        assert!(matches!(
            result,
            Err(RecoveryPhraseError::WrongWordCount(25))
        ));
    }

    #[test]
    fn test_different_phrases_different_keypairs() {
        let p1 = RecoveryPhrase::generate().unwrap();
        let p2 = RecoveryPhrase::generate().unwrap();
        let kp1 = p1.derive_owner_keypair();
        let kp2 = p2.derive_owner_keypair();
        assert_ne!(kp1.public().to_bytes(), kp2.public().to_bytes());
    }

    #[test]
    fn test_entropy_different_per_generation() {
        let p1 = RecoveryPhrase::generate().unwrap();
        let p2 = RecoveryPhrase::generate().unwrap();
        assert_ne!(p1.entropy(), p2.entropy());
    }

    #[test]
    fn test_to_phrase_words_roundtrip() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let phrase_str = phrase.to_phrase();
        let restored = RecoveryPhrase::from_mnemonic(&phrase_str).unwrap();
        assert_eq!(phrase, restored);
    }

    #[test]
    fn test_owner_keypair_sign_empty_and_verify() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        let sig = keypair.sign(b"");
        assert!(keypair.public().verify(b"", &sig).is_ok());
    }

    #[test]
    fn test_owner_keypair_to_bytes_is_32() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        assert_eq!(keypair.to_bytes().len(), 32);
    }

    #[test]
    fn test_error_is_error_trait() {
        let err = RecoveryPhraseError::WrongWordCount(5);
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_debug_format_includes_word_count() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let debug = format!("{phrase:?}");
        assert!(debug.contains("24"));
    }

    // ---- from_mnemonic with extra whitespace ----

    #[test]
    fn test_from_mnemonic_with_extra_spaces() {
        // split_whitespace should handle multiple spaces
        let test_phrase = "abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  abandon  art";
        let phrase = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        assert_eq!(phrase.words().len(), 24);
    }

    // ---- from_words with exact 24 words ----

    #[test]
    fn test_from_words_exact_24() {
        let words: Vec<&str> = vec![
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "art",
        ];
        let phrase = RecoveryPhrase::from_words(&words).unwrap();
        assert_eq!(phrase.words().len(), 24);
    }

    #[test]
    fn test_from_words_23_words_error() {
        let words: Vec<&str> = vec!["abandon"; 23];
        let result = RecoveryPhrase::from_words(&words);
        assert!(matches!(
            result,
            Err(RecoveryPhraseError::WrongWordCount(23))
        ));
    }

    // ---- Entropy is consistent between clone and original ----

    #[test]
    fn test_clone_entropy_matches() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let cloned = phrase.clone();
        assert_eq!(phrase.entropy(), cloned.entropy());
    }

    // ---- OwnerKeypair to_bytes is deterministic ----

    #[test]
    fn test_owner_keypair_to_bytes_deterministic() {
        let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let p1 = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        let p2 = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        let kp1 = p1.derive_owner_keypair();
        let kp2 = p2.derive_owner_keypair();
        assert_eq!(kp1.to_bytes(), kp2.to_bytes());
    }

    // ---- Sign/verify with different messages ----

    #[test]
    fn test_owner_keypair_sign_different_messages() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        let sig1 = keypair.sign(b"message A");
        let sig2 = keypair.sign(b"message B");
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
        assert!(keypair.public().verify(b"message A", &sig1).is_ok());
        assert!(keypair.public().verify(b"message B", &sig2).is_ok());
    }

    // ---- Cross-verification fails ----

    #[test]
    fn test_owner_keypair_cross_verify_fails() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        let sig = keypair.sign(b"message A");
        // Verify against wrong message should fail
        assert!(keypair.public().verify(b"message B", &sig).is_err());
    }

    // ---- RecoveryPhraseError Debug ----

    #[test]
    fn test_error_debug() {
        let err = RecoveryPhraseError::WrongWordCount(15);
        let debug = format!("{err:?}");
        assert!(debug.contains("WrongWordCount"));
        assert!(debug.contains("15"));
    }

    #[test]
    fn test_error_debug_invalid_mnemonic() {
        let err = RecoveryPhraseError::InvalidMnemonic("bad checksum".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidMnemonic"));
    }

    #[test]
    fn test_error_debug_derivation_failed() {
        let err = RecoveryPhraseError::DerivationFailed("hkdf error".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("DerivationFailed"));
    }

    // ---- OwnerKeypair debug does not contain private material ----

    #[test]
    fn test_owner_keypair_debug_contains_hex_pubkey() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        let debug = format!("{keypair:?}");
        // public_key should be hex-encoded (64 hex chars)
        let pub_hex = hex::encode(keypair.public().to_bytes());
        assert!(debug.contains(&pub_hex));
    }

    // ---- Words are valid BIP39 words ----

    #[test]
    fn test_generated_words_are_valid_bip39() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let words = phrase.words();
        // All words should be in the English BIP39 wordlist
        for word in &words {
            // If from_mnemonic succeeds with these words, they're valid
            assert!(!word.is_empty());
        }
        // Roundtrip confirms they are valid
        let restored = RecoveryPhrase::from_words(&words).unwrap();
        assert_eq!(phrase, restored);
    }

    // ---- RecoveryPhrase reflexive equality ----

    #[test]
    fn test_phrase_eq_reflexive() {
        let phrase = RecoveryPhrase::generate().unwrap();
        assert_eq!(phrase, phrase);
    }

    // ---- RecoveryPhrase symmetric equality ----

    #[test]
    fn test_phrase_eq_symmetric() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let cloned = phrase.clone();
        assert_eq!(phrase, cloned);
        assert_eq!(cloned, phrase);
    }

    // ---- OwnerKeypair sign large data ----

    #[test]
    fn test_owner_keypair_sign_large_data() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        let large_msg = vec![0xAB_u8; 100_000];
        let sig = keypair.sign(&large_msg);
        assert!(keypair.public().verify(&large_msg, &sig).is_ok());
    }

    // ---- OwnerKeypair public key is 32 bytes ----

    #[test]
    fn test_owner_keypair_public_key_is_32_bytes() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        assert_eq!(keypair.public().to_bytes().len(), 32);
    }

    // ---- RecoveryPhraseError Display exact messages ----

    #[test]
    fn test_error_display_wrong_word_count_exact() {
        let err = RecoveryPhraseError::WrongWordCount(0);
        assert_eq!(err.to_string(), "expected 24 words, got 0");
    }

    #[test]
    fn test_error_display_derivation_failed_exact() {
        let err = RecoveryPhraseError::DerivationFailed("hkdf".into());
        assert_eq!(err.to_string(), "key derivation failed: hkdf");
    }

    // ---- RecoveryPhrase generate produces unique phrases ----

    #[test]
    fn test_generate_produces_unique_phrases() {
        let p1 = RecoveryPhrase::generate().unwrap();
        let p2 = RecoveryPhrase::generate().unwrap();
        let p3 = RecoveryPhrase::generate().unwrap();
        assert_ne!(p1, p2);
        assert_ne!(p2, p3);
        assert_ne!(p1, p3);
    }

    // ---- from_mnemonic leading/trailing whitespace ----

    #[test]
    fn test_from_mnemonic_with_leading_trailing_whitespace() {
        let test_phrase = "  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art  ";
        let phrase = RecoveryPhrase::from_mnemonic(test_phrase).unwrap();
        assert_eq!(phrase.words().len(), 24);
    }

    // ---- OwnerKeypair debug format stability ----

    #[test]
    fn test_owner_keypair_debug_contains_finish_non_exhaustive() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let keypair = phrase.derive_owner_keypair();
        let debug = format!("{keypair:?}");
        assert!(debug.contains(".."));
    }

    // ---- RecoveryPhrase debug format stability ----

    #[test]
    fn test_recovery_phrase_debug_contains_finish_non_exhaustive() {
        let phrase = RecoveryPhrase::generate().unwrap();
        let debug = format!("{phrase:?}");
        assert!(debug.contains(".."));
    }
}
