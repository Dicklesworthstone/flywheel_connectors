//! HPKE (Hybrid Public Key Encryption) for FCP.
//!
//! Implements RFC 9180 sealed boxes for distributing zone keys and shares
//! to node encryption keys.
//!
//! ## Baseline Profile (MUST implement)
//! - KEM: DHKEM(X25519, HKDF-SHA256)
//! - KDF: HKDF-SHA256
//! - AEAD: ChaCha20-Poly1305
//!
//! ## AAD Binding (NORMATIVE)
//! When sealing keys/shares, AAD MUST include:
//! - `zone_id_hash` (or `zone_id`)
//! - `recipient_node_id`
//! - purpose string (e.g., "FCP2-ZONE-KEY")
//! - `issued_at`

use crate::error::{CryptoError, CryptoResult};
use crate::x25519::{X25519PublicKey, X25519SecretKey};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use serde::{Deserialize, Serialize};

/// HPKE encapsulated key size for X25519.
pub const HPKE_ENC_SIZE: usize = 32;

/// HPKE authentication tag size.
pub const HPKE_TAG_SIZE: usize = 16;

/// Maximum accepted serialized HPKE sealed-box size.
///
/// This caps `HpkeSealedBox::from_bytes` before it clones attacker-controlled
/// ciphertext into memory or hands it to the HPKE open path.
pub const HPKE_MAX_CIPHERTEXT: usize = 64 * 1024;

/// FCP2 purpose strings for AAD binding.
pub mod purpose {
    /// Purpose string for zone encryption keys.
    pub const ZONE_KEY: &[u8] = b"FCP2-ZONE-KEY";
    /// Purpose string for `ObjectId` derivation keys.
    pub const OBJECTID_KEY: &[u8] = b"FCP2-OBJECTID-KEY";
    /// Purpose string for owner secret shares.
    pub const OWNER_SHARE: &[u8] = b"FCP2-OWNER-SHARE";
    /// Purpose string for generic secret shares.
    pub const SECRET_SHARE: &[u8] = b"FCP2-SECRET-SHARE";
}

/// HPKE sealed box containing encapsulated key and ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeSealedBox {
    /// Encapsulated key (ephemeral public key).
    #[serde(with = "hex::serde")]
    pub enc: Vec<u8>,
    /// Ciphertext with authentication tag.
    #[serde(with = "hex::serde")]
    pub ciphertext: Vec<u8>,
}

impl HpkeSealedBox {
    /// Encode to bytes: enc || ciphertext.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.enc.len() + self.ciphertext.len());
        bytes.extend_from_slice(&self.enc);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is too short or too large.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < HPKE_ENC_SIZE + HPKE_TAG_SIZE {
            return Err(CryptoError::HpkeFailed("sealed box too short".into()));
        }
        if bytes.len() > HPKE_MAX_CIPHERTEXT {
            return Err(CryptoError::HpkeFailed(format!(
                "sealed box too large: {} bytes exceeds {} byte limit",
                bytes.len(),
                HPKE_MAX_CIPHERTEXT
            )));
        }
        // enc must be exactly HPKE_ENC_SIZE, remainder is ciphertext
        let (enc_bytes, ciphertext_bytes) = bytes.split_at(HPKE_ENC_SIZE);
        Ok(Self {
            enc: enc_bytes.to_vec(),
            ciphertext: ciphertext_bytes.to_vec(),
        })
    }
}

/// FCP2 AAD (Additional Authenticated Data) for HPKE sealing.
///
/// Binds the sealed data to its intended context per the spec.
///
/// Serialized as deterministic CBOR to prevent canonicalization attacks.
#[derive(Clone, Debug, Serialize)]
pub struct Fcp2Aad {
    /// Zone identifier (or hash).
    #[serde(with = "serde_bytes")]
    pub zone_id: Vec<u8>,
    /// Recipient node identifier.
    #[serde(with = "serde_bytes")]
    pub recipient_node_id: Vec<u8>,
    /// Purpose string (e.g., `purpose::ZONE_KEY`).
    #[serde(with = "serde_bytes")]
    pub purpose: Vec<u8>,
    /// Issuance timestamp (Unix seconds).
    pub issued_at: u64,
}

impl Fcp2Aad {
    /// Create new AAD for zone key distribution.
    #[must_use]
    pub fn for_zone_key(zone_id: &[u8], recipient_node_id: &[u8], issued_at: u64) -> Self {
        Self {
            zone_id: zone_id.to_vec(),
            recipient_node_id: recipient_node_id.to_vec(),
            purpose: purpose::ZONE_KEY.to_vec(),
            issued_at,
        }
    }

    /// Create new AAD for `ObjectId` key distribution.
    #[must_use]
    pub fn for_objectid_key(zone_id: &[u8], recipient_node_id: &[u8], issued_at: u64) -> Self {
        Self {
            zone_id: zone_id.to_vec(),
            recipient_node_id: recipient_node_id.to_vec(),
            purpose: purpose::OBJECTID_KEY.to_vec(),
            issued_at,
        }
    }

    /// Create new AAD for secret share distribution.
    #[must_use]
    pub fn for_secret_share(zone_id: &[u8], recipient_node_id: &[u8], issued_at: u64) -> Self {
        Self {
            zone_id: zone_id.to_vec(),
            recipient_node_id: recipient_node_id.to_vec(),
            purpose: purpose::SECRET_SHARE.to_vec(),
            issued_at,
        }
    }

    /// Encode AAD to canonical CBOR bytes.
    ///
    /// This ensures a unique, non-malleable representation for the encryption context.
    ///
    /// # Errors
    ///
    /// Returns an error if CBOR serialization fails.
    pub fn encode(&self) -> CryptoResult<Vec<u8>> {
        // Typical AAD CBOR is ~120 bytes (32 zone + 32 node + 13-16 purpose + 8 timestamp + overhead).
        crate::canonicalize::to_deterministic_cbor_with_capacity(self, 128)
    }
}

/// Seal (encrypt) data to a recipient's public key using HPKE.
///
/// # Arguments
///
/// * `recip_pub` - Recipient's X25519 public key.
/// * `plaintext` - Data to encrypt.
/// * `aad` - Additional authenticated data (context binding).
///
/// # Errors
///
/// Returns an error if HPKE operations fail.
pub fn hpke_seal(
    recip_pub: &X25519PublicKey,
    plaintext: &[u8],
    aad: &Fcp2Aad,
) -> CryptoResult<HpkeSealedBox> {
    let mut rng = rand::rngs::OsRng;
    hpke_seal_with_rng(recip_pub, plaintext, aad, &mut rng)
}

/// Seal (encrypt) data to a recipient's public key using HPKE with caller-provided RNG.
///
/// This is intended for deterministic test vectors and fuzz harnesses.
///
/// # Errors
///
/// Returns an error if HPKE operations fail.
pub fn hpke_seal_with_rng<R: rand::CryptoRng + rand::RngCore>(
    recip_pub: &X25519PublicKey,
    plaintext: &[u8],
    aad: &Fcp2Aad,
    rng: &mut R,
) -> CryptoResult<HpkeSealedBox> {
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&recip_pub.to_bytes())
        .map_err(|e| CryptoError::HpkeFailed(format!("invalid recipient public key: {e}")))?;
    let (enc, mut sender_ctx) = hpke::setup_sender::<
        ChaCha20Poly1305Aead,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &pk, b"FCP2-HPKE", rng)
    .map_err(|e| CryptoError::HpkeFailed(format!("setup_sender failed: {e}")))?;

    let aad_bytes = aad.encode()?;
    let ciphertext = sender_ctx
        .seal(plaintext, &aad_bytes)
        .map_err(|e| CryptoError::HpkeFailed(format!("seal failed: {e}")))?;

    Ok(HpkeSealedBox {
        enc: enc.to_bytes().to_vec(),
        ciphertext,
    })
}

/// Open (decrypt) an HPKE sealed box.
///
/// # Arguments
///
/// * `recipient_sk` - Recipient's X25519 secret key.
/// * `sealed_box` - The sealed box to decrypt.
/// * `aad` - Additional authenticated data (must match what was used for sealing).
///
/// # Errors
///
/// Returns an error if decryption fails (wrong key, tampered data, or wrong AAD).
pub fn hpke_open(
    recipient_sk: &X25519SecretKey,
    sealed_box: &HpkeSealedBox,
    aad: &Fcp2Aad,
) -> CryptoResult<Vec<u8>> {
    let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&recipient_sk.to_bytes())
        .map_err(|e| CryptoError::HpkeFailed(format!("invalid secret key: {e}")))?;

    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&sealed_box.enc)
        .map_err(|e| CryptoError::HpkeFailed(format!("invalid encapsulated key: {e}")))?;

    let mut receiver_ctx =
        hpke::setup_receiver::<ChaCha20Poly1305Aead, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk,
            &enc,
            b"FCP2-HPKE",
        )
        .map_err(|e| CryptoError::HpkeFailed(format!("setup_receiver failed: {e}")))?;

    let aad_bytes = aad.encode()?;
    receiver_ctx
        .open(&sealed_box.ciphertext, &aad_bytes)
        .map_err(|e| CryptoError::HpkeFailed(format!("open failed: {e}")))
}

// Type alias for the AEAD used internally
type ChaCha20Poly1305Aead = hpke::aead::ChaCha20Poly1305;

/// Convenience function: seal zone key material to a node.
///
/// # Errors
///
/// Returns an error if sealing fails.
pub fn seal_zone_key(
    recip_pub: &X25519PublicKey,
    zone_key_material: &[u8],
    zone_id: &[u8],
    recipient_node_id: &[u8],
    issued_at: u64,
) -> CryptoResult<HpkeSealedBox> {
    let aad = Fcp2Aad::for_zone_key(zone_id, recipient_node_id, issued_at);
    hpke_seal(recip_pub, zone_key_material, &aad)
}

/// Convenience function: open zone key material.
///
/// # Errors
///
/// Returns an error if opening fails.
pub fn open_zone_key(
    recipient_sk: &X25519SecretKey,
    sealed_box: &HpkeSealedBox,
    zone_id: &[u8],
    recipient_node_id: &[u8],
    issued_at: u64,
) -> CryptoResult<Vec<u8>> {
    let aad = Fcp2Aad::for_zone_key(zone_id, recipient_node_id, issued_at);
    hpke_open(recipient_sk, sealed_box, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn hpke_roundtrip() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let plaintext = b"secret zone key material";
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, plaintext, &aad).unwrap();
        let opened = hpke_open(&recipient_secret_key, &sealed, &aad).unwrap();

        assert_eq!(opened, plaintext);
    }

    #[test]
    fn hpke_wrong_key_fails() {
        let sender_secret_key = X25519SecretKey::generate();
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad).unwrap();

        // Try to open with wrong key
        let result = hpke_open(&sender_secret_key, &sealed, &aad);
        assert!(result.is_err());
    }

    #[test]
    fn hpke_wrong_aad_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad1 = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let aad2 = Fcp2Aad::for_zone_key(b"z:private", b"node-123", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad1).unwrap();
        let result = hpke_open(&recipient_secret_key, &sealed, &aad2);

        assert!(result.is_err());
    }

    #[test]
    fn hpke_wrong_timestamp_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad1 = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let aad2 = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_891);

        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad1).unwrap();
        let result = hpke_open(&recipient_secret_key, &sealed, &aad2);

        assert!(result.is_err());
    }

    // Metamorphic: sealing the SAME plaintext under two different AADs
    // produces two boxes. Swapping the ciphertexts between them must
    // fail decryption in both directions — i.e. AAD binds ciphertext to
    // context, and no "compatible" ciphertext substitution exists.
    // Subsumes wrong_aad_fails with an additional cross-swap leg that a
    // regression in the AAD encoding could expose.
    #[test]
    fn hpke_cross_swap_of_ciphertexts_between_aads_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad_a = Fcp2Aad::for_zone_key(b"z:work", b"node-A", 1_234_567_890);
        let aad_b = Fcp2Aad::for_zone_key(b"z:work", b"node-B", 1_234_567_890);
        let plaintext = b"the same secret under two contexts";

        let sealed_a = hpke_seal(&recipient_public_key, plaintext, &aad_a).unwrap();
        let sealed_b = hpke_seal(&recipient_public_key, plaintext, &aad_b).unwrap();

        // Sanity: each box opens under its own AAD.
        assert_eq!(
            hpke_open(&recipient_secret_key, &sealed_a, &aad_a).unwrap(),
            plaintext
        );
        assert_eq!(
            hpke_open(&recipient_secret_key, &sealed_b, &aad_b).unwrap(),
            plaintext
        );

        // Swap ciphertexts while keeping the `enc` header consistent with
        // the original AAD — models an attacker that captures both sealed
        // boxes and tries to substitute ciphertext.
        let HpkeSealedBox {
            enc: enc_a,
            ciphertext: ciphertext_a,
        } = sealed_a;
        let HpkeSealedBox {
            enc: enc_b,
            ciphertext: ciphertext_b,
        } = sealed_b;
        let swapped_a = HpkeSealedBox {
            enc: enc_a,
            ciphertext: ciphertext_b,
        };
        let swapped_b = HpkeSealedBox {
            enc: enc_b,
            ciphertext: ciphertext_a,
        };

        assert!(
            hpke_open(&recipient_secret_key, &swapped_a, &aad_a).is_err(),
            "ciphertext from box_b must not open under box_a's enc + aad_a"
        );
        assert!(
            hpke_open(&recipient_secret_key, &swapped_b, &aad_b).is_err(),
            "ciphertext from box_a must not open under box_b's enc + aad_b"
        );
    }

    #[test]
    fn hpke_tampered_ciphertext_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let mut sealed = hpke_seal(&recipient_public_key, b"secret", &aad).unwrap();

        // Tamper with ciphertext
        if let Some(byte) = sealed.ciphertext.first_mut() {
            *byte ^= 0xff;
        }

        let result = hpke_open(&recipient_secret_key, &sealed, &aad);
        assert!(result.is_err());
    }

    #[test]
    fn hpke_sealed_box_bytes_roundtrip() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad).unwrap();

        let bytes = sealed.to_bytes();
        let parsed = HpkeSealedBox::from_bytes(&bytes).unwrap();

        assert_eq!(sealed.enc, parsed.enc);
        assert_eq!(sealed.ciphertext, parsed.ciphertext);
    }

    #[test]
    fn hpke_sealed_box_trailing_junk_included_in_ciphertext() {
        // from_bytes currently treats everything after HPKE_ENC_SIZE as ciphertext.
        // If there's junk, it's included, and opening will fail due to AEAD tag mismatch.
        let recipient_sk = X25519SecretKey::generate();
        let recip_pub = recipient_sk.public_key();
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-1", 100);
        let sealed = hpke_seal(&recip_pub, b"secret", &aad).unwrap();

        let mut bytes = sealed.to_bytes();
        bytes.push(0xff); // Trailing junk

        let parsed = HpkeSealedBox::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ciphertext.len(), sealed.ciphertext.len() + 1);

        // Opening must fail
        let result = hpke_open(&recipient_sk, &parsed, &aad);
        assert!(result.is_err());
    }

    #[test]
    fn seal_zone_key_convenience() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let zone_key_material = [42u8; 32];
        let zone_id = b"z:work";
        let node_id = b"node-abc";
        let issued_at = 1_700_000_000;

        let sealed = seal_zone_key(
            &recipient_public_key,
            &zone_key_material,
            zone_id,
            node_id,
            issued_at,
        )
        .unwrap();

        let opened =
            open_zone_key(&recipient_secret_key, &sealed, zone_id, node_id, issued_at).unwrap();

        assert_eq!(opened, zone_key_material);
    }

    #[test]
    fn different_purposes_produce_different_aad() {
        let aad1 = Fcp2Aad::for_zone_key(b"z:work", b"node", 1_234_567_890);
        let aad2 = Fcp2Aad::for_objectid_key(b"z:work", b"node", 1_234_567_890);
        let aad3 = Fcp2Aad::for_secret_share(b"z:work", b"node", 1_234_567_890);

        assert_ne!(aad1.encode().unwrap(), aad2.encode().unwrap());
        assert_ne!(aad1.encode().unwrap(), aad3.encode().unwrap());
        assert_ne!(aad2.encode().unwrap(), aad3.encode().unwrap());
    }

    #[test]
    fn hpke_empty_plaintext() {
        // HPKE should handle empty plaintext correctly
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let sealed = hpke_seal(&recipient_public_key, b"", &aad).unwrap();
        let opened = hpke_open(&recipient_secret_key, &sealed, &aad).unwrap();

        assert_eq!(opened, [] as [u8; 0]);
    }

    #[test]
    fn hpke_large_plaintext() {
        // Test with a larger payload
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let large_plaintext = vec![0x42u8; 4096];
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, &large_plaintext, &aad).unwrap();
        let opened = hpke_open(&recipient_secret_key, &sealed, &aad).unwrap();

        assert_eq!(opened, large_plaintext);
    }

    #[test]
    fn hpke_sealed_box_from_bytes_too_short() {
        // Test that from_bytes rejects input that's too short
        let short_input = vec![0u8; HPKE_ENC_SIZE + HPKE_TAG_SIZE - 1];
        let result = HpkeSealedBox::from_bytes(&short_input);
        assert!(result.is_err());
    }

    #[test]
    fn hpke_sealed_box_from_bytes_accepts_max_sized_input() {
        let max_input = vec![0u8; HPKE_MAX_CIPHERTEXT];
        let result = HpkeSealedBox::from_bytes(&max_input).unwrap();

        assert_eq!(result.enc.len(), HPKE_ENC_SIZE);
        assert_eq!(result.ciphertext.len(), HPKE_MAX_CIPHERTEXT - HPKE_ENC_SIZE);
    }

    #[test]
    fn hpke_sealed_box_from_bytes_rejects_oversized_input() {
        let oversized_input = vec![0u8; HPKE_MAX_CIPHERTEXT + 1];
        let error = HpkeSealedBox::from_bytes(&oversized_input).unwrap_err();

        assert!(
            error.to_string().contains("sealed box too large"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn hpke_ciphertext_length() {
        // Verify ciphertext length is plaintext + tag
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let plaintext = b"test message";
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, plaintext, &aad).unwrap();

        // enc should be 32 bytes
        assert_eq!(sealed.enc.len(), HPKE_ENC_SIZE);
        // ciphertext should be plaintext.len() + 16 (tag)
        assert_eq!(sealed.ciphertext.len(), plaintext.len() + HPKE_TAG_SIZE);
    }

    #[test]
    fn hpke_wrong_recipient_node_id_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad1 = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let aad2 = Fcp2Aad::for_zone_key(b"z:work", b"node-456", 1_234_567_890);

        let sealed = hpke_seal(&recipient_public_key, b"secret", &aad1).unwrap();
        let result = hpke_open(&recipient_secret_key, &sealed, &aad2);

        assert!(result.is_err());
    }

    #[test]
    fn hpke_tampered_enc_fails() {
        let recipient_secret_key = X25519SecretKey::generate();
        let recipient_public_key = recipient_secret_key.public_key();

        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_234_567_890);
        let mut sealed = hpke_seal(&recipient_public_key, b"secret", &aad).unwrap();

        // Tamper with the encapsulated key
        if let Some(byte) = sealed.enc.first_mut() {
            *byte ^= 0xff;
        }

        let result = hpke_open(&recipient_secret_key, &sealed, &aad);
        assert!(result.is_err());
    }

    #[test]
    fn aad_encode_format() {
        // Verify the AAD encoding format is canonical CBOR
        let zone_id = b"z:work";
        let node_id = b"node-123";
        let issued_at: u64 = 1_234_567_890;

        let aad = Fcp2Aad::for_zone_key(zone_id, node_id, issued_at);
        let encoded = aad.encode().unwrap();

        // Should be a CBOR map with 4 elements
        // 0xA4 = map(4)
        assert_eq!(encoded[0], 0xA4);

        // Parse back to Value to verify structure
        let value: ciborium::value::Value = ciborium::de::from_reader(&encoded[..]).unwrap();
        let map = value.as_map().unwrap();
        assert_eq!(map.len(), 4);

        // Verify "zone_id" field is present and is a byte string
        let (_, v) = map
            .iter()
            .find(|(k, _)| k.as_text().is_some_and(|s| s == "zone_id"))
            .unwrap();
        assert!(v.is_bytes()); // serde_bytes should make this a byte string
        assert_eq!(v.as_bytes().unwrap(), zone_id);
    }

    #[test]
    fn hpke_multiple_recipients() {
        // Test sealing to multiple recipients (different sealed boxes)
        let alice_secret = X25519SecretKey::generate();
        let alice_public = alice_secret.public_key();
        let bob_secret = X25519SecretKey::generate();
        let bob_public = bob_secret.public_key();

        let plaintext = b"shared secret";
        let aad_alice = Fcp2Aad::for_zone_key(b"z:work", b"node-alice", 1_234_567_890);
        let aad_bob = Fcp2Aad::for_zone_key(b"z:work", b"node-bob", 1_234_567_890);

        let sealed_for_alice = hpke_seal(&alice_public, plaintext, &aad_alice).unwrap();
        let sealed_for_bob = hpke_seal(&bob_public, plaintext, &aad_bob).unwrap();

        // Each recipient can open their own sealed box
        let opened_by_alice = hpke_open(&alice_secret, &sealed_for_alice, &aad_alice).unwrap();
        let opened_by_bob = hpke_open(&bob_secret, &sealed_for_bob, &aad_bob).unwrap();

        assert_eq!(opened_by_alice, plaintext);
        assert_eq!(opened_by_bob, plaintext);

        // Recipients cannot open each other's sealed boxes
        assert!(hpke_open(&alice_secret, &sealed_for_bob, &aad_bob).is_err());
        assert!(hpke_open(&bob_secret, &sealed_for_alice, &aad_alice).is_err());
    }

    #[test]
    fn fcp2_aad_purposes() {
        // Verify all purpose constants
        assert_eq!(purpose::ZONE_KEY, b"FCP2-ZONE-KEY");
        assert_eq!(purpose::OBJECTID_KEY, b"FCP2-OBJECTID-KEY");
        assert_eq!(purpose::OWNER_SHARE, b"FCP2-OWNER-SHARE");
        assert_eq!(purpose::SECRET_SHARE, b"FCP2-SECRET-SHARE");
    }

    // ---- Sealed box serde roundtrip ----

    #[test]
    fn hpke_sealed_box_serde_roundtrip() {
        let recipient_sk = X25519SecretKey::generate();
        let recip_pub = recipient_sk.public_key();
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-1", 100);
        let sealed = hpke_seal(&recip_pub, b"serde test", &aad).unwrap();

        let json = serde_json::to_string(&sealed).unwrap();
        let deserialized: HpkeSealedBox = serde_json::from_str(&json).unwrap();

        assert_eq!(sealed.enc, deserialized.enc);
        assert_eq!(sealed.ciphertext, deserialized.ciphertext);

        // Should still decrypt
        let opened = hpke_open(&recipient_sk, &deserialized, &aad).unwrap();
        assert_eq!(opened, b"serde test");
    }

    // ---- Sealed box clone ----

    #[test]
    fn hpke_sealed_box_clone() {
        let recipient_sk = X25519SecretKey::generate();
        let recip_pub = recipient_sk.public_key();
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-1", 200);
        let sealed = hpke_seal(&recip_pub, b"clone test", &aad).unwrap();

        let cloned = sealed.clone();
        assert_eq!(sealed.enc, cloned.enc);
        assert_eq!(sealed.ciphertext, cloned.ciphertext);
    }

    // ---- Sealed box debug ----

    #[test]
    fn hpke_sealed_box_debug() {
        let recipient_sk = X25519SecretKey::generate();
        let recip_pub = recipient_sk.public_key();
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-1", 300);
        let sealed = hpke_seal(&recip_pub, b"debug", &aad).unwrap();

        let debug = format!("{sealed:?}");
        assert!(debug.contains("HpkeSealedBox"));
    }

    // ---- AAD clone ----

    #[test]
    fn fcp2_aad_clone() {
        let aad = Fcp2Aad::for_zone_key(b"z:test", b"node-x", 999);
        let cloned = aad.clone();
        assert_eq!(aad.encode().unwrap(), cloned.encode().unwrap());
    }

    // ---- AAD debug ----

    #[test]
    fn fcp2_aad_debug() {
        let aad = Fcp2Aad::for_zone_key(b"z:test", b"node-x", 999);
        let debug = format!("{aad:?}");
        assert!(debug.contains("Fcp2Aad"));
    }

    // ---- Deterministic sealing with rng ----

    #[test]
    fn hpke_seal_with_rng_deterministic() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let recipient_sk = X25519SecretKey::from_bytes([42u8; 32]);
        let recip_pub = recipient_sk.public_key();
        let aad = Fcp2Aad::for_zone_key(b"z:det", b"node-det", 12345);

        let mut rng1 = ChaCha20Rng::from_seed([0xAA; 32]);
        let sealed1 = hpke_seal_with_rng(&recip_pub, b"deterministic", &aad, &mut rng1).unwrap();

        let mut rng2 = ChaCha20Rng::from_seed([0xAA; 32]);
        let sealed2 = hpke_seal_with_rng(&recip_pub, b"deterministic", &aad, &mut rng2).unwrap();

        assert_eq!(sealed1.enc, sealed2.enc);
        assert_eq!(sealed1.ciphertext, sealed2.ciphertext);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn hpke_encrypt_then_decrypt_identity_relation(
            plaintext in prop::collection::vec(any::<u8>(), 0..256),
            suffix in prop::collection::vec(any::<u8>(), 1..33),
            node_suffix in prop::collection::vec(any::<u8>(), 0..16),
            issued_at in any::<u64>(),
        ) {
            use rand::SeedableRng;
            use rand_chacha::ChaCha20Rng;

            let recipient_secret_key = X25519SecretKey::from_bytes([42u8; 32]);
            let recipient_public_key = recipient_secret_key.public_key();
            let mut recipient_node_id = b"node-meta-".to_vec();
            recipient_node_id.extend_from_slice(&node_suffix);
            let aad = Fcp2Aad::for_zone_key(b"z:meta", &recipient_node_id, issued_at);

            let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
            let sealed = hpke_seal_with_rng(&recipient_public_key, &plaintext, &aad, &mut rng)
                .expect("base seal should succeed");
            let opened = hpke_open(&recipient_secret_key, &sealed, &aad)
                .expect("base open should succeed");
            prop_assert_eq!(opened.as_slice(), plaintext.as_slice());

            let mut transformed_plaintext = plaintext.clone();
            transformed_plaintext.extend_from_slice(&suffix);

            let mut transformed_rng = ChaCha20Rng::from_seed([0x11; 32]);
            let transformed_sealed = hpke_seal_with_rng(
                &recipient_public_key,
                &transformed_plaintext,
                &aad,
                &mut transformed_rng,
            )
            .expect("transformed seal should succeed");
            let transformed_opened = hpke_open(
                &recipient_secret_key,
                &transformed_sealed,
                &aad,
            )
            .expect("transformed open should succeed");

            let mut expected_transformed = opened;
            expected_transformed.extend_from_slice(&suffix);

            // Holding the RNG seed constant keeps the encapsulated key stable,
            // so the only semantic change across the relation is the plaintext
            // transformation itself.
            prop_assert_eq!(sealed.enc, transformed_sealed.enc);
            prop_assert_ne!(sealed.ciphertext, transformed_sealed.ciphertext);
            prop_assert_eq!(transformed_opened.as_slice(), expected_transformed.as_slice());
        }
    }

    // ---- HPKE constants ----

    #[test]
    fn hpke_constants() {
        assert_eq!(HPKE_ENC_SIZE, 32);
        assert_eq!(HPKE_TAG_SIZE, 16);
        assert_eq!(HPKE_MAX_CIPHERTEXT, 64 * 1024);
    }

    // ---- Sealed box from_bytes then open ----

    #[test]
    fn hpke_sealed_box_bytes_roundtrip_then_open() {
        let recipient_sk = X25519SecretKey::generate();
        let recip_pub = recipient_sk.public_key();
        let aad = Fcp2Aad::for_zone_key(b"z:bytes", b"node-bytes", 42);
        let sealed = hpke_seal(&recip_pub, b"roundtrip open", &aad).unwrap();

        let bytes = sealed.to_bytes();
        let parsed = HpkeSealedBox::from_bytes(&bytes).unwrap();
        let opened = hpke_open(&recipient_sk, &parsed, &aad).unwrap();
        assert_eq!(opened, b"roundtrip open");
    }

    // ---- From bytes minimum valid size ----

    #[test]
    fn hpke_sealed_box_from_bytes_minimum_valid() {
        let min_bytes = vec![0u8; HPKE_ENC_SIZE + HPKE_TAG_SIZE];
        let result = HpkeSealedBox::from_bytes(&min_bytes);
        assert!(result.is_ok());
        let sb = result.unwrap();
        assert_eq!(sb.enc.len(), HPKE_ENC_SIZE);
        assert_eq!(sb.ciphertext.len(), HPKE_TAG_SIZE);
    }

    // ---- AAD for_objectid_key roundtrip ----

    #[test]
    fn hpke_objectid_key_roundtrip() {
        let recipient_sk = X25519SecretKey::generate();
        let recip_pub = recipient_sk.public_key();
        let aad = Fcp2Aad::for_objectid_key(b"z:oid", b"node-oid", 555);

        let sealed = hpke_seal(&recip_pub, b"objectid secret", &aad).unwrap();
        let opened = hpke_open(&recipient_sk, &sealed, &aad).unwrap();
        assert_eq!(opened, b"objectid secret");
    }

    // ---- AAD for_secret_share roundtrip ----

    #[test]
    fn hpke_secret_share_roundtrip() {
        let recipient_sk = X25519SecretKey::generate();
        let recip_pub = recipient_sk.public_key();
        let aad = Fcp2Aad::for_secret_share(b"z:share", b"node-share", 777);

        let sealed = hpke_seal(&recip_pub, b"share secret", &aad).unwrap();
        let opened = hpke_open(&recipient_sk, &sealed, &aad).unwrap();
        assert_eq!(opened, b"share secret");
    }

    // ---- AAD encode deterministic ----

    #[test]
    fn fcp2_aad_encode_deterministic() {
        let aad1 = Fcp2Aad::for_zone_key(b"z:det", b"node-det", 12345);
        let aad2 = Fcp2Aad::for_zone_key(b"z:det", b"node-det", 12345);
        assert_eq!(aad1.encode().unwrap(), aad2.encode().unwrap());
    }

    // ---- Sealed box from_bytes empty ----

    #[test]
    fn hpke_sealed_box_from_bytes_empty() {
        let result = HpkeSealedBox::from_bytes(&[]);
        assert!(result.is_err());
    }

    // ---- Wrong purpose AAD fails ----

    #[test]
    fn hpke_wrong_purpose_fails() {
        let recipient_sk = X25519SecretKey::generate();
        let recip_pub = recipient_sk.public_key();
        let aad_zone = Fcp2Aad::for_zone_key(b"z:test", b"node", 100);
        let aad_share = Fcp2Aad::for_secret_share(b"z:test", b"node", 100);

        let sealed = hpke_seal(&recip_pub, b"secret", &aad_zone).unwrap();
        let result = hpke_open(&recipient_sk, &sealed, &aad_share);
        assert!(result.is_err());
    }

    // ---- AAD fields ----

    #[test]
    fn fcp2_aad_for_zone_key_fields() {
        let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-1", 999);
        assert_eq!(aad.zone_id, b"z:work");
        assert_eq!(aad.recipient_node_id, b"node-1");
        assert_eq!(aad.purpose, purpose::ZONE_KEY);
        assert_eq!(aad.issued_at, 999);
    }

    #[test]
    fn fcp2_aad_for_objectid_key_fields() {
        let aad = Fcp2Aad::for_objectid_key(b"z:oid", b"node-2", 888);
        assert_eq!(aad.purpose, purpose::OBJECTID_KEY);
    }

    #[test]
    fn fcp2_aad_for_secret_share_fields() {
        let aad = Fcp2Aad::for_secret_share(b"z:share", b"node-3", 777);
        assert_eq!(aad.purpose, purpose::SECRET_SHARE);
    }
}
