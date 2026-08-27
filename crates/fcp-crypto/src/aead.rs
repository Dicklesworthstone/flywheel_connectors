//! AEAD encryption for FCP2 using ChaCha20-Poly1305.
//!
//! Provides authenticated encryption with associated data (AEAD) as used
//! by zone encryption, FCPS frames, and symbol envelopes.

use crate::error::{CryptoError, CryptoResult};
use chacha20poly1305::{
    ChaCha20Poly1305, XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::ZeroizeOnDrop;

/// ChaCha20-Poly1305 key size (256 bits).
pub const AEAD_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size (96 bits / 12 bytes).
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// XChaCha20-Poly1305 nonce size (192 bits / 24 bytes).
pub const XCHACHA20_NONCE_SIZE: usize = 24;

/// Poly1305 authentication tag size (128 bits / 16 bytes).
pub const AEAD_TAG_SIZE: usize = 16;

/// AEAD encryption key with zeroize semantics.
#[derive(Clone, ZeroizeOnDrop)]
pub struct AeadKey {
    bytes: [u8; AEAD_KEY_SIZE],
}

impl AeadKey {
    /// Create a new AEAD key from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; AEAD_KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Generate a random AEAD key.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; AEAD_KEY_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self { bytes }
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `AEAD_KEY_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != AEAD_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: AEAD_KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; AEAD_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Get the key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AEAD_KEY_SIZE] {
        &self.bytes
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKey").finish_non_exhaustive()
    }
}

/// ChaCha20-Poly1305 nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChaCha20Nonce([u8; CHACHA20_NONCE_SIZE]);

impl ChaCha20Nonce {
    /// Create from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHACHA20_NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create from a counter value.
    ///
    /// Useful for protocols with deterministic nonces.
    #[must_use]
    pub fn from_counter(counter: u64) -> Self {
        let mut bytes = [0u8; CHACHA20_NONCE_SIZE];
        bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        Self(bytes)
    }

    /// Create from a counter value and a direction byte.
    ///
    /// Useful for preventing nonce reuse in bidirectional streams using the same key.
    /// The direction byte is placed at index 0.
    #[must_use]
    pub fn from_counter_directional(counter: u64, direction: u8) -> Self {
        let mut bytes = [0u8; CHACHA20_NONCE_SIZE];
        bytes[0] = direction;
        bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        Self(bytes)
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `CHACHA20_NONCE_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != CHACHA20_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: CHACHA20_NONCE_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; CHACHA20_NONCE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHACHA20_NONCE_SIZE] {
        &self.0
    }
}

/// XChaCha20-Poly1305 nonce (extended nonce for random generation safety).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XChaCha20Nonce([u8; XCHACHA20_NONCE_SIZE]);

impl XChaCha20Nonce {
    /// Create from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; XCHACHA20_NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Generate a random nonce.
    ///
    /// `XChaCha20` uses a 192-bit nonce which is safe for random generation
    /// (birthday collision resistance up to ~2^80 messages).
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; XCHACHA20_NONCE_SIZE];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        Self(bytes)
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `XCHACHA20_NONCE_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != XCHACHA20_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: XCHACHA20_NONCE_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; XCHACHA20_NONCE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; XCHACHA20_NONCE_SIZE] {
        &self.0
    }
}

/// ChaCha20-Poly1305 AEAD cipher.
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new cipher from a key.
    #[must_use]
    pub fn new(key: &AeadKey) -> Self {
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        Self { cipher }
    }

    /// Encrypt plaintext with associated data.
    ///
    /// Returns ciphertext with appended authentication tag.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails (should not happen with valid inputs).
    pub fn encrypt(
        &self,
        nonce: &ChaCha20Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| CryptoError::AeadEncryptFailed)
    }

    /// Decrypt ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails (authentication failure or invalid ciphertext).
    pub fn decrypt(
        &self,
        nonce: &ChaCha20Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| CryptoError::AeadDecryptFailed)
    }
}

/// XChaCha20-Poly1305 AEAD cipher (extended nonce variant).
///
/// Preferred when nonces are generated randomly, as the 192-bit nonce
/// provides sufficient collision resistance for ~2^80 messages.
pub struct XChaCha20Poly1305Cipher {
    cipher: XChaCha20Poly1305,
}

impl XChaCha20Poly1305Cipher {
    /// Create a new cipher from a key.
    #[must_use]
    pub fn new(key: &AeadKey) -> Self {
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        Self { cipher }
    }

    /// Encrypt plaintext with associated data.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt(
        &self,
        nonce: &XChaCha20Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| CryptoError::AeadEncryptFailed)
    }

    /// Decrypt ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    pub fn decrypt(
        &self,
        nonce: &XChaCha20Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| CryptoError::AeadDecryptFailed)
    }

    /// Encrypt with a random nonce, returning (nonce || ciphertext).
    ///
    /// Convenience method for typical encryption workflows.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt_with_random_nonce(&self, plaintext: &[u8], aad: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce = XChaCha20Nonce::generate();
        let ciphertext = self.encrypt(&nonce, plaintext, aad)?;
        let mut result = Vec::with_capacity(XCHACHA20_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(nonce.as_bytes());
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt ciphertext that has a prepended nonce.
    ///
    /// Expects input format: (nonce || ciphertext).
    ///
    /// # Errors
    ///
    /// Returns an error if the input is too short or decryption fails.
    pub fn decrypt_with_prepended_nonce(
        &self,
        nonce_and_ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if nonce_and_ciphertext.len() < XCHACHA20_NONCE_SIZE + AEAD_TAG_SIZE {
            return Err(CryptoError::AeadDecryptFailed);
        }
        let nonce = XChaCha20Nonce::try_from_slice(&nonce_and_ciphertext[..XCHACHA20_NONCE_SIZE])?;
        let ciphertext = &nonce_and_ciphertext[XCHACHA20_NONCE_SIZE..];
        self.decrypt(&nonce, ciphertext, aad)
    }
}

/// Convenience function: encrypt with ChaCha20-Poly1305.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn chacha20_encrypt(
    key: &AeadKey,
    nonce: &ChaCha20Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305Cipher::new(key);
    cipher.encrypt(nonce, plaintext, aad)
}

/// Convenience function: decrypt with ChaCha20-Poly1305.
///
/// # Errors
///
/// Returns an error if decryption fails.
pub fn chacha20_decrypt(
    key: &AeadKey,
    nonce: &ChaCha20Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305Cipher::new(key);
    cipher.decrypt(nonce, ciphertext, aad)
}

/// Convenience function: encrypt with XChaCha20-Poly1305.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn xchacha20_encrypt(
    key: &AeadKey,
    nonce: &XChaCha20Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305Cipher::new(key);
    cipher.encrypt(nonce, plaintext, aad)
}

/// Convenience function: decrypt with XChaCha20-Poly1305.
///
/// # Errors
///
/// Returns an error if decryption fails.
pub fn xchacha20_decrypt(
    key: &AeadKey,
    nonce: &XChaCha20Nonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305Cipher::new(key);
    cipher.decrypt(nonce, ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn chacha20_roundtrip() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(1);
        let plaintext = b"hello world";
        let aad = b"additional data";

        let ciphertext = chacha20_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn xchacha20_roundtrip() {
        let key = AeadKey::generate();
        let nonce = XChaCha20Nonce::generate();
        let plaintext = b"hello world";
        let aad = b"additional data";

        let ciphertext = xchacha20_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = xchacha20_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn xchacha20_with_random_nonce_roundtrip() {
        let key = AeadKey::generate();
        let cipher = XChaCha20Poly1305Cipher::new(&key);

        let plaintext = b"secret message";
        let aad = b"context";

        let encrypted = cipher.encrypt_with_random_nonce(plaintext, aad).unwrap();
        let decrypted = cipher
            .decrypt_with_prepended_nonce(&encrypted, aad)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = AeadKey::generate();
        let key2 = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(2);

        let ciphertext = chacha20_encrypt(&key1, &nonce, b"secret", b"aad").unwrap();
        let result = chacha20_decrypt(&key2, &nonce, &ciphertext, b"aad");

        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn wrong_nonce_fails() {
        let key = AeadKey::generate();
        let nonce1 = ChaCha20Nonce::from_counter(3);
        let nonce2 = ChaCha20Nonce::from_counter(4);

        let ciphertext = chacha20_encrypt(&key, &nonce1, b"secret", b"aad").unwrap();
        let result = chacha20_decrypt(&key, &nonce2, &ciphertext, b"aad");

        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(5);

        let ciphertext = chacha20_encrypt(&key, &nonce, b"secret", b"aad1").unwrap();
        let result = chacha20_decrypt(&key, &nonce, &ciphertext, b"aad2");

        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(6);

        let mut ciphertext = chacha20_encrypt(&key, &nonce, b"secret", b"aad").unwrap();
        ciphertext[0] ^= 0xff; // Flip bits
        let result = chacha20_decrypt(&key, &nonce, &ciphertext, b"aad");

        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn empty_plaintext() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(7);

        let ciphertext = chacha20_encrypt(&key, &nonce, b"", b"aad").unwrap();
        assert_eq!(ciphertext.len(), AEAD_TAG_SIZE); // Tag only

        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext, b"aad").unwrap();
        assert_eq!(decrypted, [] as [u8; 0]);
    }

    #[test]
    fn empty_aad() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(8);
        let plaintext = b"secret";

        let ciphertext = chacha20_encrypt(&key, &nonce, plaintext, b"").unwrap();
        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn nonce_from_counter() {
        let n1 = ChaCha20Nonce::from_counter(0);
        let n2 = ChaCha20Nonce::from_counter(1);
        let n3 = ChaCha20Nonce::from_counter(0);

        assert_ne!(n1, n2);
        assert_eq!(n1, n3);
    }

    #[test]
    fn ciphertext_length() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(9);
        let plaintext = b"hello";

        let ciphertext = chacha20_encrypt(&key, &nonce, plaintext, b"").unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_SIZE);
    }

    #[test]
    fn golden_vector_chacha20poly1305() {
        // RFC 8439 test vector
        let key = AeadKey::from_bytes([
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ]);
        let nonce = ChaCha20Nonce::from_bytes([
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ]);
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let ciphertext = chacha20_encrypt(&key, &nonce, plaintext, &aad).unwrap();

        let expected = hex::decode(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        ).unwrap();

        assert_eq!(ciphertext, expected);

        // Verify decryption
        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aead_key_try_from_slice_valid() {
        let bytes = [0xAA; AEAD_KEY_SIZE];
        let key = AeadKey::try_from_slice(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn aead_key_try_from_slice_too_short() {
        let err = AeadKey::try_from_slice(&[0; 16]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            }
        ));
    }

    #[test]
    fn aead_key_try_from_slice_too_long() {
        let err = AeadKey::try_from_slice(&[0; 33]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 33
            }
        ));
    }

    #[test]
    fn aead_key_try_from_slice_empty() {
        let err = AeadKey::try_from_slice(&[]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 0
            }
        ));
    }

    #[test]
    fn aead_key_debug_redacted() {
        let key = AeadKey::generate();
        let debug = format!("{key:?}");
        assert_eq!(debug, "AeadKey { .. }");
        // Must NOT contain key material
        assert!(!debug.contains("0x"));
    }

    #[test]
    fn chacha20_nonce_try_from_slice_valid() {
        let bytes = [0xBB; CHACHA20_NONCE_SIZE];
        let nonce = ChaCha20Nonce::try_from_slice(&bytes).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn chacha20_nonce_try_from_slice_wrong_length() {
        let err = ChaCha20Nonce::try_from_slice(&[0; 8]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidNonceLength {
                expected: 12,
                actual: 8
            }
        ));
    }

    #[test]
    fn xchacha20_nonce_try_from_slice_valid() {
        let bytes = [0xCC; XCHACHA20_NONCE_SIZE];
        let nonce = XChaCha20Nonce::try_from_slice(&bytes).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn xchacha20_nonce_try_from_slice_wrong_length() {
        let err = XChaCha20Nonce::try_from_slice(&[0; 12]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidNonceLength {
                expected: 24,
                actual: 12
            }
        ));
    }

    #[test]
    fn nonce_from_counter_directional_different_directions() {
        let n1 = ChaCha20Nonce::from_counter_directional(1, 0);
        let n2 = ChaCha20Nonce::from_counter_directional(1, 1);
        assert_ne!(n1, n2);
        // Direction byte is at index 0
        assert_eq!(n1.as_bytes()[0], 0);
        assert_eq!(n2.as_bytes()[0], 1);
    }

    #[test]
    fn nonce_from_counter_directional_different_counters() {
        let n1 = ChaCha20Nonce::from_counter_directional(0, 0);
        let n2 = ChaCha20Nonce::from_counter_directional(1, 0);
        assert_ne!(n1, n2);
    }

    #[test]
    fn xchacha20_decrypt_with_prepended_nonce_too_short() {
        let key = AeadKey::generate();
        let cipher = XChaCha20Poly1305Cipher::new(&key);
        // Less than XCHACHA20_NONCE_SIZE + AEAD_TAG_SIZE = 40 bytes
        let short = [0u8; 39];
        let result = cipher.decrypt_with_prepended_nonce(&short, b"");
        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn xchacha20_decrypt_with_prepended_nonce_tampered() {
        let key = AeadKey::generate();
        let cipher = XChaCha20Poly1305Cipher::new(&key);
        let mut encrypted = cipher.encrypt_with_random_nonce(b"data", b"aad").unwrap();
        // Tamper with last byte (part of the tag)
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        let result = cipher.decrypt_with_prepended_nonce(&encrypted, b"aad");
        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(100);
        let plaintext = vec![0xAB; 64 * 1024]; // 64 KB

        let ciphertext = chacha20_encrypt(&key, &nonce, &plaintext, b"").unwrap();
        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext, b"").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ---- AeadKey clone ----

    #[test]
    fn aead_key_clone_preserves_bytes() {
        let key = AeadKey::from_bytes([0xAA; AEAD_KEY_SIZE]);
        let cloned = key.clone();
        assert_eq!(key.as_bytes(), cloned.as_bytes());
    }

    #[test]
    fn aead_key_clone_functional() {
        let key = AeadKey::generate();
        let cloned = key.clone();
        let nonce = ChaCha20Nonce::from_counter(42);
        let ct = chacha20_encrypt(&key, &nonce, b"test", b"").unwrap();
        let pt = chacha20_decrypt(&cloned, &nonce, &ct, b"").unwrap();
        assert_eq!(pt, b"test");
    }

    // ---- Nonce edge cases ----

    #[test]
    fn chacha20_nonce_from_counter_zero() {
        let nonce = ChaCha20Nonce::from_counter(0);
        // First 4 bytes should be zero, next 8 should be counter in LE
        let bytes = nonce.as_bytes();
        assert_eq!(&bytes[0..4], &[0, 0, 0, 0]);
        assert_eq!(&bytes[4..12], &0u64.to_le_bytes());
    }

    #[test]
    fn chacha20_nonce_from_counter_max() {
        let nonce = ChaCha20Nonce::from_counter(u64::MAX);
        let bytes = nonce.as_bytes();
        assert_eq!(&bytes[4..12], &u64::MAX.to_le_bytes());
    }

    #[test]
    fn chacha20_nonce_from_bytes_roundtrip() {
        let original = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let nonce = ChaCha20Nonce::from_bytes(original);
        assert_eq!(nonce.as_bytes(), &original);
    }

    #[test]
    fn xchacha20_nonce_from_bytes_roundtrip() {
        let original = [42u8; XCHACHA20_NONCE_SIZE];
        let nonce = XChaCha20Nonce::from_bytes(original);
        assert_eq!(nonce.as_bytes(), &original);
    }

    #[test]
    fn chacha20_nonce_try_from_slice_empty() {
        let err = ChaCha20Nonce::try_from_slice(&[]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidNonceLength {
                expected: 12,
                actual: 0
            }
        ));
    }

    #[test]
    fn xchacha20_nonce_try_from_slice_empty() {
        let err = XChaCha20Nonce::try_from_slice(&[]).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidNonceLength {
                expected: 24,
                actual: 0
            }
        ));
    }

    // ---- XChaCha20 specific tests ----

    #[test]
    fn xchacha20_convenience_functions_roundtrip() {
        let key = AeadKey::generate();
        let nonce = XChaCha20Nonce::generate();
        let plaintext = b"xchacha20 convenience";
        let aad = b"extra data";

        let ct = xchacha20_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let pt = xchacha20_decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn xchacha20_wrong_key_fails() {
        let key1 = AeadKey::generate();
        let key2 = AeadKey::generate();
        let nonce = XChaCha20Nonce::generate();

        let ct = xchacha20_encrypt(&key1, &nonce, b"data", b"").unwrap();
        let result = xchacha20_decrypt(&key2, &nonce, &ct, b"");
        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn xchacha20_wrong_nonce_fails() {
        let key = AeadKey::generate();
        let nonce1 = XChaCha20Nonce::from_bytes([1u8; XCHACHA20_NONCE_SIZE]);
        let nonce2 = XChaCha20Nonce::from_bytes([2u8; XCHACHA20_NONCE_SIZE]);

        let ct = xchacha20_encrypt(&key, &nonce1, b"data", b"").unwrap();
        let result = xchacha20_decrypt(&key, &nonce2, &ct, b"");
        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn xchacha20_empty_plaintext_roundtrip() {
        let key = AeadKey::generate();
        let nonce = XChaCha20Nonce::generate();

        let ct = xchacha20_encrypt(&key, &nonce, b"", b"aad").unwrap();
        assert_eq!(ct.len(), AEAD_TAG_SIZE);
        let pt = xchacha20_decrypt(&key, &nonce, &ct, b"aad").unwrap();
        assert_eq!(pt, [] as [u8; 0]);
    }

    #[test]
    fn xchacha20_ciphertext_length() {
        let key = AeadKey::generate();
        let nonce = XChaCha20Nonce::generate();
        let plaintext = b"measure this";

        let ct = xchacha20_encrypt(&key, &nonce, plaintext, b"").unwrap();
        assert_eq!(ct.len(), plaintext.len() + AEAD_TAG_SIZE);
    }

    // ---- Cipher struct direct usage ----

    #[test]
    fn chacha20_cipher_direct() {
        let key = AeadKey::generate();
        let cipher = ChaCha20Poly1305Cipher::new(&key);
        let nonce = ChaCha20Nonce::from_counter(99);

        let ct = cipher.encrypt(&nonce, b"direct", b"aad").unwrap();
        let pt = cipher.decrypt(&nonce, &ct, b"aad").unwrap();
        assert_eq!(pt, b"direct");
    }

    #[test]
    fn xchacha20_cipher_direct() {
        let key = AeadKey::generate();
        let cipher = XChaCha20Poly1305Cipher::new(&key);
        let nonce = XChaCha20Nonce::from_bytes([7u8; XCHACHA20_NONCE_SIZE]);

        let ct = cipher.encrypt(&nonce, b"direct xchacha", b"").unwrap();
        let pt = cipher.decrypt(&nonce, &ct, b"").unwrap();
        assert_eq!(pt, b"direct xchacha");
    }

    // ---- Constants ----

    #[test]
    fn aead_constants() {
        assert_eq!(AEAD_KEY_SIZE, 32);
        assert_eq!(CHACHA20_NONCE_SIZE, 12);
        assert_eq!(XCHACHA20_NONCE_SIZE, 24);
        assert_eq!(AEAD_TAG_SIZE, 16);
    }

    // ---- ChaCha20 nonce directional edge cases ----

    #[test]
    fn nonce_from_counter_directional_max_counter() {
        let n = ChaCha20Nonce::from_counter_directional(u64::MAX, 0xFF);
        assert_eq!(n.as_bytes()[0], 0xFF);
        assert_eq!(&n.as_bytes()[4..12], &u64::MAX.to_le_bytes());
    }

    #[test]
    fn nonce_from_counter_directional_zero_counter_zero_dir() {
        let n = ChaCha20Nonce::from_counter_directional(0, 0);
        assert_eq!(n.as_bytes(), &[0u8; 12]);
    }

    // ---- Decrypt with too-short ciphertext ----

    #[test]
    fn chacha20_decrypt_empty_ciphertext_fails() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(50);
        let result = chacha20_decrypt(&key, &nonce, &[], b"");
        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    #[test]
    fn xchacha20_decrypt_empty_ciphertext_fails() {
        let key = AeadKey::generate();
        let nonce = XChaCha20Nonce::from_bytes([0u8; XCHACHA20_NONCE_SIZE]);
        let result = xchacha20_decrypt(&key, &nonce, &[], b"");
        assert!(matches!(result, Err(CryptoError::AeadDecryptFailed)));
    }

    // ---- Prepended nonce exact minimum ----

    #[test]
    fn xchacha20_decrypt_with_prepended_nonce_exact_minimum() {
        let key = AeadKey::generate();
        let cipher = XChaCha20Poly1305Cipher::new(&key);
        // Exactly XCHACHA20_NONCE_SIZE + AEAD_TAG_SIZE = 40 bytes
        let min_input = [0u8; 40];
        // Should try to decrypt (will fail auth but won't panic)
        let result = cipher.decrypt_with_prepended_nonce(&min_input, b"");
        assert!(result.is_err());
    }

    // ---- AeadKey from_bytes ----

    #[test]
    fn aead_key_from_bytes_roundtrip() {
        let bytes = [0x42; AEAD_KEY_SIZE];
        let key = AeadKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    // ---- Encrypt-decrypt with large AAD ----

    #[test]
    fn chacha20_large_aad_roundtrip() {
        let key = AeadKey::generate();
        let nonce = ChaCha20Nonce::from_counter(200);
        let large_aad = vec![0xBB; 100_000];
        let plaintext = b"msg";

        let ct = chacha20_encrypt(&key, &nonce, plaintext, &large_aad).unwrap();
        let pt = chacha20_decrypt(&key, &nonce, &ct, &large_aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    // ---- Nonce clone/copy ----

    #[test]
    fn chacha20_nonce_copy_semantics() {
        let n1 = ChaCha20Nonce::from_counter(77);
        let n2 = n1;
        // Both usable after copy
        assert_eq!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn xchacha20_nonce_copy_semantics() {
        let n1 = XChaCha20Nonce::from_bytes([0x99; XCHACHA20_NONCE_SIZE]);
        let n2 = n1;
        assert_eq!(n1.as_bytes(), n2.as_bytes());
    }

    // ---- Nonce debug format ----

    #[test]
    fn chacha20_nonce_debug() {
        let n = ChaCha20Nonce::from_counter(1);
        let debug = format!("{n:?}");
        assert!(debug.contains("ChaCha20Nonce"));
    }

    #[test]
    fn xchacha20_nonce_debug() {
        let n = XChaCha20Nonce::from_bytes([0u8; XCHACHA20_NONCE_SIZE]);
        let debug = format!("{n:?}");
        assert!(debug.contains("XChaCha20Nonce"));
    }

    // ---- Multiple encrypt-decrypt with same key different nonces ----

    #[test]
    fn chacha20_multiple_messages_same_key() {
        let key = AeadKey::generate();
        for i in 0u64..10 {
            let nonce = ChaCha20Nonce::from_counter(i);
            let msg = format!("message {i}");
            let ct = chacha20_encrypt(&key, &nonce, msg.as_bytes(), b"").unwrap();
            let pt = chacha20_decrypt(&key, &nonce, &ct, b"").unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    // ── Metamorphic encrypt/decrypt proptests ────────────────────────
    //
    // AEAD identity relations lifted from single-case tests
    // (chacha20_roundtrip, xchacha20_roundtrip, tampered_ciphertext_fails,
    // wrong_aad_fails) into property-space. For both ChaCha20-Poly1305
    // and XChaCha20-Poly1305:
    //
    //   M1 identity        decrypt(encrypt(k, n, pt, aad), k, n, aad) == pt
    //   M2 ct tamper       flipping any byte in ciphertext|tag must fail
    //                      decryption (AEAD integrity guarantee)
    //   M3 aad tamper      changing aad on decrypt must fail
    //
    // Each property samples the full (key × nonce × plaintext × aad)
    // space — the nonce reuse concern doesn't apply here because each
    // trial generates a fresh (key, nonce) pair, so the tests never
    // reuse a nonce under the same key.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// M1 (ChaCha20-Poly1305): encrypt then decrypt is identity.
        #[test]
        fn chacha20_encrypt_then_decrypt_is_identity(
            key_bytes in any::<[u8; AEAD_KEY_SIZE]>(),
            nonce_bytes in any::<[u8; CHACHA20_NONCE_SIZE]>(),
            plaintext in prop::collection::vec(any::<u8>(), 0..1024),
            aad in prop::collection::vec(any::<u8>(), 0..128),
        ) {
            let key = AeadKey::from_bytes(key_bytes);
            let nonce = ChaCha20Nonce::from_bytes(nonce_bytes);
            let ct = chacha20_encrypt(&key, &nonce, &plaintext, &aad)
                .expect("encrypt must not fail on valid inputs");
            let pt = chacha20_decrypt(&key, &nonce, &ct, &aad)
                .expect("decrypt must succeed with matching k/n/aad");
            prop_assert_eq!(pt, plaintext);
        }

        /// M2 (ChaCha20-Poly1305): flipping any byte in the ciphertext
        /// (or the Poly1305 tag appended to it) must fail decrypt.
        #[test]
        fn chacha20_tampered_ciphertext_fails_decrypt(
            key_bytes in any::<[u8; AEAD_KEY_SIZE]>(),
            nonce_bytes in any::<[u8; CHACHA20_NONCE_SIZE]>(),
            plaintext in prop::collection::vec(any::<u8>(), 1..512),
            aad in prop::collection::vec(any::<u8>(), 0..64),
            flip_index in any::<usize>(),
        ) {
            let key = AeadKey::from_bytes(key_bytes);
            let nonce = ChaCha20Nonce::from_bytes(nonce_bytes);
            let mut ct = chacha20_encrypt(&key, &nonce, &plaintext, &aad).unwrap();
            let idx = flip_index % ct.len();
            ct[idx] ^= 0x01;
            let result = chacha20_decrypt(&key, &nonce, &ct, &aad);
            prop_assert!(
                matches!(result, Err(CryptoError::AeadDecryptFailed)),
                "M2 (ct tamper) broken: byte-flipped ciphertext must yield \
                 AeadDecryptFailed, got {:?}",
                result
            );
        }

        /// M3 (ChaCha20-Poly1305): decrypt with different aad must fail.
        /// `aad1 != aad2` is enforced via prop_assume.
        #[test]
        fn chacha20_different_aad_fails_decrypt(
            key_bytes in any::<[u8; AEAD_KEY_SIZE]>(),
            nonce_bytes in any::<[u8; CHACHA20_NONCE_SIZE]>(),
            plaintext in prop::collection::vec(any::<u8>(), 0..512),
            aad1 in prop::collection::vec(any::<u8>(), 0..64),
            aad2 in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assume!(aad1 != aad2);
            let key = AeadKey::from_bytes(key_bytes);
            let nonce = ChaCha20Nonce::from_bytes(nonce_bytes);
            let ct = chacha20_encrypt(&key, &nonce, &plaintext, &aad1).unwrap();
            let result = chacha20_decrypt(&key, &nonce, &ct, &aad2);
            prop_assert!(
                matches!(result, Err(CryptoError::AeadDecryptFailed)),
                "M3 (aad tamper) broken: decrypt with different aad must fail, \
                 got {:?}",
                result
            );
        }

        /// M1 (XChaCha20-Poly1305): encrypt then decrypt is identity.
        /// XChaCha20 takes a 24-byte nonce, safe for random generation.
        #[test]
        fn xchacha20_encrypt_then_decrypt_is_identity(
            key_bytes in any::<[u8; AEAD_KEY_SIZE]>(),
            nonce_bytes in any::<[u8; XCHACHA20_NONCE_SIZE]>(),
            plaintext in prop::collection::vec(any::<u8>(), 0..1024),
            aad in prop::collection::vec(any::<u8>(), 0..128),
        ) {
            let key = AeadKey::from_bytes(key_bytes);
            let nonce = XChaCha20Nonce::from_bytes(nonce_bytes);
            let ct = xchacha20_encrypt(&key, &nonce, &plaintext, &aad)
                .expect("xchacha20 encrypt must not fail on valid inputs");
            let pt = xchacha20_decrypt(&key, &nonce, &ct, &aad)
                .expect("xchacha20 decrypt must succeed with matching k/n/aad");
            prop_assert_eq!(pt, plaintext);
        }

        /// M2 (XChaCha20-Poly1305): byte-flip tamper rejection.
        #[test]
        fn xchacha20_tampered_ciphertext_fails_decrypt(
            key_bytes in any::<[u8; AEAD_KEY_SIZE]>(),
            nonce_bytes in any::<[u8; XCHACHA20_NONCE_SIZE]>(),
            plaintext in prop::collection::vec(any::<u8>(), 1..512),
            aad in prop::collection::vec(any::<u8>(), 0..64),
            flip_index in any::<usize>(),
        ) {
            let key = AeadKey::from_bytes(key_bytes);
            let nonce = XChaCha20Nonce::from_bytes(nonce_bytes);
            let mut ct = xchacha20_encrypt(&key, &nonce, &plaintext, &aad).unwrap();
            let idx = flip_index % ct.len();
            ct[idx] ^= 0x01;
            let result = xchacha20_decrypt(&key, &nonce, &ct, &aad);
            prop_assert!(
                matches!(result, Err(CryptoError::AeadDecryptFailed)),
                "M2 (xchacha20 ct tamper) broken, got {:?}",
                result
            );
        }
    }
}
