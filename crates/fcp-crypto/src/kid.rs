//! Key Identifier (KID) types for FCP.
//!
//! KIDs are 8-byte identifiers used to route signature verification and
//! decryption to the correct key. They are derived from the public key
//! using BLAKE3 truncation.

use crate::error::{CryptoError, CryptoResult};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Key identifier size in bytes.
pub const KID_SIZE: usize = 8;

/// Key Identifier - 8-byte truncated BLAKE3 hash of the public key.
///
/// KIDs are used in COSE headers to identify which key should be used
/// for verification or decryption without exposing the full public key.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct KeyId([u8; KID_SIZE]);

impl KeyId {
    /// Create a new KID from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Derive a KID from a public key using BLAKE3.
    ///
    /// The derivation uses a domain-separated BLAKE3 hash:
    /// `BLAKE3(b"fcp.kid.v2" || public_key_bytes)[0..8]`
    #[must_use]
    pub fn derive_from_public_key(public_key_bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fcp.kid.v2");
        hasher.update(public_key_bytes);
        let hash = hasher.finalize();
        let mut kid = [0u8; KID_SIZE];
        kid.copy_from_slice(&hash.as_bytes()[..KID_SIZE]);
        Self(kid)
    }

    /// Get the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KID_SIZE] {
        &self.0
    }

    /// Convert to a slice.
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Try to create from a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly `KID_SIZE` bytes.
    pub fn try_from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != KID_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: KID_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; KID_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Encode as lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid hex or wrong length.
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::InvalidKeyId(e.to_string()))?;
        Self::try_from_slice(&bytes)
    }
}

impl ConstantTimeEq for KeyId {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for KeyId {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for KeyId {}

// KIDs are public routing identifiers, not secret keys. Collection hashing and
// ordering use their exact canonical bytes; equality keeps its constant-time
// implementation. HashMap/BTreeMap lookup itself is not constant-time.
impl std::hash::Hash for KeyId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.0, state);
    }
}

impl Ord for KeyId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for KeyId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl std::fmt::Debug for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyId({})", self.to_hex())
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Zeroize for KeyId {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for KeyId {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn populated_key_maps_lookup_replace_and_remove_equivalent_ids() {
        use std::collections::{BTreeMap, HashMap};

        let mut hashed = HashMap::new();
        let mut ordered = BTreeMap::new();
        for byte in 0..=u8::MAX {
            let kid = KeyId::from_bytes([byte; KID_SIZE]);
            hashed.insert(kid.clone(), byte);
            ordered.insert(kid, byte);
        }
        assert_eq!(hashed.len(), 256);
        assert_eq!(ordered.len(), 256);
        for byte in 0..=u8::MAX {
            let probe = KeyId::from_hex(&hex::encode_upper([byte; KID_SIZE])).unwrap();
            assert_eq!(hashed.get(&probe), Some(&byte));
            assert_eq!(ordered.get(&probe), Some(&byte));
            assert_eq!(hashed.insert(probe.clone(), 0), Some(byte));
            assert_eq!(ordered.insert(probe.clone(), 0), Some(byte));
            assert_eq!(hashed.remove(&probe), Some(0));
            assert_eq!(ordered.remove(&probe), Some(0));
        }
        assert!(hashed.is_empty());
        assert!(ordered.is_empty());
    }

    #[test]
    fn key_order_matches_canonical_byte_order_in_every_position() {
        use std::cmp::Ordering;

        let mut keys = vec![KeyId::default()];
        for position in 0..KID_SIZE {
            for byte in [1, 0x80, u8::MAX] {
                let mut bytes = [0; KID_SIZE];
                bytes[position] = byte;
                keys.push(KeyId::from_bytes(bytes));
            }
        }
        for left in &keys {
            for right in &keys {
                assert_eq!(left.cmp(right), left.as_bytes().cmp(right.as_bytes()));
                assert_eq!(left.partial_cmp(right), Some(left.cmp(right)));
                assert_eq!(left.cmp(right) == Ordering::Equal, left == right);
                assert_eq!(left.cmp(right), right.cmp(left).reverse());
            }
        }
        keys.sort();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(keys.first().unwrap(), &KeyId::default());
        // The leading byte is most significant, independently of host endian.
        assert_eq!(keys.last().unwrap().as_bytes(), &[255, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn hash_uses_the_same_bytes_after_clone_hex_and_serde_round_trips() {
        use std::hash::{Hash, Hasher};

        #[derive(Default)]
        struct RecordedHash(Vec<u8>);
        impl Hasher for RecordedHash {
            fn finish(&self) -> u64 {
                0
            }
            fn write(&mut self, bytes: &[u8]) {
                self.0.extend_from_slice(bytes);
            }
        }

        let key = KeyId::from_bytes([1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let mut expected = RecordedHash::default();
        key.as_bytes().hash(&mut expected);
        let json = serde_json::to_string(&key).unwrap();
        for equivalent in [
            key.clone(),
            KeyId::from_hex("0123456789ABCDEF").unwrap(),
            serde_json::from_str::<KeyId>(&json).unwrap(),
        ] {
            let mut actual = RecordedHash::default();
            equivalent.hash(&mut actual);
            assert_eq!(actual.0, expected.0);
            assert_eq!(equivalent, key);
        }
    }

    #[test]
    fn wiping_a_lookup_key_does_not_change_owned_map_keys() {
        use std::collections::{BTreeMap, HashMap};

        let mut key = KeyId::from_bytes([0xff; KID_SIZE]);
        let hashed = HashMap::from([(key.clone(), "writer")]);
        let ordered = BTreeMap::from([(key.clone(), "writer")]);
        key.zeroize();
        assert!(!hashed.contains_key(&key));
        assert!(!ordered.contains_key(&key));
        let probe = KeyId::from_bytes([0xff; KID_SIZE]);
        assert_eq!(hashed.get(&probe), Some(&"writer"));
        assert_eq!(ordered.get(&probe), Some(&"writer"));
    }

    #[test]
    fn kid_derive_deterministic() {
        let pubkey = b"test public key bytes";
        let kid1 = KeyId::derive_from_public_key(pubkey);
        let kid2 = KeyId::derive_from_public_key(pubkey);
        assert_eq!(kid1, kid2);
    }

    #[test]
    fn kid_derive_different_keys() {
        let kid1 = KeyId::derive_from_public_key(b"key1");
        let kid2 = KeyId::derive_from_public_key(b"key2");
        assert_ne!(kid1, kid2);
    }

    #[test]
    fn kid_hex_roundtrip() {
        let kid = KeyId::derive_from_public_key(b"test key");
        let hex = kid.to_hex();
        let parsed = KeyId::from_hex(&hex).unwrap();
        assert_eq!(kid, parsed);
    }

    #[test]
    fn kid_from_bytes() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let kid = KeyId::from_bytes(bytes);
        assert_eq!(kid.as_bytes(), &bytes);
    }

    #[test]
    fn kid_try_from_slice_valid() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let kid = KeyId::try_from_slice(&bytes).unwrap();
        assert_eq!(kid.as_bytes(), &bytes);
    }

    #[test]
    fn kid_try_from_slice_invalid_length() {
        let result = KeyId::try_from_slice(&[1, 2, 3]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 8,
                actual: 3
            })
        ));
    }

    #[test]
    fn kid_golden_vector() {
        // Golden vector: BLAKE3("fcp.kid.v2" || pubkey)
        let pubkey = b"FCP2 test public key";
        let kid = KeyId::derive_from_public_key(pubkey);

        // Manual verification of the spec logic
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"fcp.kid.v2");
        hasher.update(pubkey);
        let hash = hasher.finalize();
        let expected = &hash.as_bytes()[..8];

        assert_eq!(kid.as_bytes(), expected);
    }

    #[test]
    fn kid_display_is_hex() {
        let kid = KeyId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        assert_eq!(kid.to_string(), "0123456789abcdef");
    }

    #[test]
    fn kid_debug_format() {
        let kid = KeyId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        assert_eq!(format!("{kid:?}"), "KeyId(0123456789abcdef)");
    }

    #[test]
    fn kid_from_hex_invalid_hex() {
        let err = KeyId::from_hex("not-hex").unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKeyId(_)));
    }

    #[test]
    fn kid_from_hex_wrong_length() {
        // Valid hex but wrong length (4 bytes instead of 8)
        let err = KeyId::from_hex("01234567").unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 8,
                actual: 4
            }
        ));
    }

    #[test]
    fn kid_as_slice() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let kid = KeyId::from_bytes(bytes);
        assert_eq!(kid.as_slice(), &bytes);
    }

    #[test]
    fn kid_default_is_zeroed() {
        let kid = KeyId::default();
        assert_eq!(kid.as_bytes(), &[0u8; KID_SIZE]);
    }

    #[test]
    fn kid_serde_roundtrip() {
        let kid = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let json = serde_json::to_string(&kid).unwrap();
        let decoded: KeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, kid);
    }

    #[test]
    fn kid_derive_empty_key() {
        let kid = KeyId::derive_from_public_key(b"");
        assert_eq!(kid.as_bytes().len(), KID_SIZE);
        // Should still be deterministic
        assert_eq!(kid, KeyId::derive_from_public_key(b""));
    }

    // ---- KeyId clone ----

    #[test]
    fn kid_clone() {
        let kid = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let cloned = kid.clone();
        assert_eq!(kid, cloned);
        // Use original after clone
        assert_eq!(kid.to_hex(), cloned.to_hex());
    }

    // ---- Hex edge cases ----

    #[test]
    fn kid_from_hex_empty_string() {
        let err = KeyId::from_hex("").unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 8,
                actual: 0
            }
        ));
    }

    #[test]
    fn kid_from_hex_odd_length() {
        let err = KeyId::from_hex("012345678abcdef").unwrap_err();
        // Odd hex string should fail to decode
        assert!(matches!(err, CryptoError::InvalidKeyId(_)));
    }

    #[test]
    fn kid_from_hex_uppercase() {
        let kid1 = KeyId::from_hex("0123456789abcdef").unwrap();
        let kid2 = KeyId::from_hex("0123456789ABCDEF").unwrap();
        assert_eq!(kid1, kid2);
    }

    // ---- Try from slice edge cases ----

    #[test]
    fn kid_try_from_slice_too_long() {
        let result = KeyId::try_from_slice(&[0u8; 16]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 8,
                actual: 16
            })
        ));
    }

    #[test]
    fn kid_try_from_slice_one_byte() {
        let result = KeyId::try_from_slice(&[0u8; 1]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 8,
                actual: 1
            })
        ));
    }

    // ---- Derive from large key ----

    #[test]
    fn kid_derive_from_large_key() {
        let large_key = vec![0xAB; 1024];
        let kid = KeyId::derive_from_public_key(&large_key);
        assert_eq!(kid.as_bytes().len(), KID_SIZE);
        // Deterministic
        assert_eq!(kid, KeyId::derive_from_public_key(&large_key));
    }

    // ---- Constant-time equality ----

    #[test]
    fn kid_constant_time_eq() {
        let kid1 = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let kid2 = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let kid3 = KeyId::from_bytes([8, 7, 6, 5, 4, 3, 2, 1]);

        assert!(bool::from(kid1.ct_eq(&kid2)));
        assert!(!bool::from(kid1.ct_eq(&kid3)));
    }

    // ---- Serde with specific values ----

    #[test]
    fn kid_serde_all_zeros() {
        let kid = KeyId::default();
        let json = serde_json::to_string(&kid).unwrap();
        let decoded: KeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, kid);
    }

    #[test]
    fn kid_serde_all_ones() {
        let kid = KeyId::from_bytes([0xFF; KID_SIZE]);
        let json = serde_json::to_string(&kid).unwrap();
        let decoded: KeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, kid);
    }

    // ---- KID_SIZE constant ----

    #[test]
    fn kid_size_constant() {
        assert_eq!(KID_SIZE, 8);
    }

    // ---- Display vs Debug consistency ----

    #[test]
    fn kid_display_vs_to_hex() {
        let kid = KeyId::from_bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(kid.to_string(), kid.to_hex());
    }

    // ---- Derive from unicode key ----

    #[test]
    fn kid_derive_from_unicode_public_key() {
        let kid = KeyId::derive_from_public_key("clé publique réseau".as_bytes());
        assert_eq!(kid.as_bytes().len(), KID_SIZE);
        // Deterministic for same input
        let kid2 = KeyId::derive_from_public_key("clé publique réseau".as_bytes());
        assert_eq!(kid, kid2);
    }

    // ---- Hex with mixed case ----

    #[test]
    fn kid_to_hex_is_lowercase() {
        let kid = KeyId::from_bytes([0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89]);
        let hex = kid.to_hex();
        assert_eq!(hex, hex.to_lowercase());
    }

    // ---- Zeroize semantics ----

    #[test]
    fn kid_zeroize_clears_bytes() {
        let mut kid = KeyId::from_bytes([0xFF; KID_SIZE]);
        kid.zeroize();
        assert_eq!(kid.as_bytes(), &[0u8; KID_SIZE]);
    }

    // ---- Eq reflexivity ----

    #[test]
    fn kid_eq_reflexive() {
        let kid = KeyId::derive_from_public_key(b"reflexive");
        assert_eq!(kid, kid);
    }

    // ---- Serde CBOR roundtrip ----

    #[test]
    fn kid_serde_cbor_roundtrip() {
        let kid = KeyId::from_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&kid, &mut cbor_bytes).unwrap();
        let decoded: KeyId = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(decoded, kid);
    }

    // ---- from_hex with too long valid hex ----

    #[test]
    fn kid_from_hex_too_long() {
        // 32 hex chars = 16 bytes, but KID expects 8
        let err = KeyId::from_hex("0123456789abcdef0123456789abcdef").unwrap_err();
        assert!(matches!(
            err,
            CryptoError::InvalidKeyLength {
                expected: 8,
                actual: 16
            }
        ));
    }

    #[test]
    fn kid_hash_and_ord_collections() {
        use std::collections::{BTreeMap, HashMap};

        let kid_a = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let kid_b = KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 9]);
        let kid_missing = KeyId::from_bytes([9, 9, 9, 9, 9, 9, 9, 9]);

        let mut hash_map = HashMap::new();
        hash_map.insert(kid_a.clone(), "alpha");
        hash_map.insert(kid_b.clone(), "beta");
        assert_eq!(hash_map.get(&kid_a), Some(&"alpha"));
        assert_eq!(hash_map.get(&kid_b), Some(&"beta"));
        assert_eq!(hash_map.get(&kid_missing), None);

        let mut btree_map = BTreeMap::new();
        btree_map.insert(kid_b.clone(), 2);
        btree_map.insert(kid_a.clone(), 1);
        let keys: Vec<KeyId> = btree_map.keys().cloned().collect();
        assert_eq!(keys, vec![kid_a, kid_b]);
        assert_eq!(btree_map.get(&kid_missing), None);
    }
}
