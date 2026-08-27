//! Cross-module integration tests for `fcp-crypto`.
//!
//! Tests exercise real crypto pipelines that span multiple modules
//! (AEAD + HKDF, Ed25519 + COSE tokens, X25519 + HPKE, Shamir + HPKE,
//! canonicalization + signing) without mocks or stubs.

use fcp_crypto::aead::{AEAD_KEY_SIZE, AEAD_TAG_SIZE, CHACHA20_NONCE_SIZE, XCHACHA20_NONCE_SIZE};
use fcp_crypto::canonicalize::{
    NodeSignature, sort_node_signatures, verify_node_signature_order, verify_signature_order,
};
use fcp_crypto::mac::{BLAKE3_MAC_SIZE, IncrementalMac, MAC_KEY_SIZE, MAC_SIZE};
use fcp_crypto::{
    // AEAD
    AeadKey,
    // MAC
    Blake3Mac,
    // COSE
    CapabilityTokenBuilder,
    ChaCha20Nonce,
    ChaCha20Poly1305Cipher,
    CoseToken,
    // Errors
    CryptoError,
    CwtClaims,
    // HKDF
    DerivedKey,
    // Ed25519
    Ed25519Signature,
    Ed25519SigningKey,
    Ed25519VerifyingKey,
    // HPKE
    Fcp2Aad,
    Fcp2KeyDerivation,
    HkdfSha256,
    HpkeSealedBox,
    // KID
    KeyId,
    MacKey,
    MacKeyPurpose,
    SessionDirection,
    // Shamir
    ShamirShare,
    // X25519
    X25519PublicKey,
    X25519SecretKey,
    XChaCha20Nonce,
    XChaCha20Poly1305Cipher,
    blake3_mac,
    blake3_mac_full,
    blake3_mac_verify,
    // Canonicalize
    canonical_signing_bytes,
    chacha20_decrypt,
    chacha20_encrypt,
    hpke_open,
    hpke_seal,
    reconstruct_secret,
    schema_hash,
    split_secret,
    xchacha20_decrypt,
    xchacha20_encrypt,
};

use chrono::{Duration as ChronoDuration, Utc};

// ============================================================================
// 1. HKDF → AEAD: derive key, encrypt/decrypt
// ============================================================================

#[test]
fn hkdf_derived_key_used_as_aead_key() {
    let ikm = b"shared-secret-material-from-x25519";
    let info = b"FCP2-SESSION-send-session-001";
    let derived: DerivedKey<32> = DerivedKey::derive(None, ikm, info).unwrap();

    let key = AeadKey::from_bytes(*derived.as_bytes());
    let cipher = ChaCha20Poly1305Cipher::new(&key);
    let nonce = ChaCha20Nonce::from_counter(1);
    let plaintext = b"session data payload";

    let ct = cipher.encrypt(&nonce, plaintext, b"session-aad").unwrap();
    let pt = cipher.decrypt(&nonce, &ct, b"session-aad").unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn fcp2_session_key_derivation_directional() {
    let shared = b"diffie-hellman-shared-secret-val";
    let session_id = b"ses-42";

    let send_key =
        Fcp2KeyDerivation::derive_session_key(shared, session_id, SessionDirection::Send).unwrap();
    let recv_key =
        Fcp2KeyDerivation::derive_session_key(shared, session_id, SessionDirection::Recv).unwrap();

    // Directional keys must differ
    assert_ne!(send_key.as_bytes(), recv_key.as_bytes());

    // Both usable as AEAD keys
    let send_cipher = ChaCha20Poly1305Cipher::new(&AeadKey::from_bytes(*send_key.as_bytes()));
    let nonce = ChaCha20Nonce::from_counter(0);
    let ct = send_cipher.encrypt(&nonce, b"hello", b"").unwrap();

    let recv_cipher = ChaCha20Poly1305Cipher::new(&AeadKey::from_bytes(*recv_key.as_bytes()));
    // Decrypting with wrong key fails
    assert!(recv_cipher.decrypt(&nonce, &ct, b"").is_err());
}

// ============================================================================
// 2. HKDF → MAC: derive MAC key, compute/verify
// ============================================================================

#[test]
fn hkdf_derived_mac_key_roundtrip() {
    let session_key = b"session-key-bytes-for-mac-derivt";
    let mac_key_bytes =
        Fcp2KeyDerivation::derive_mac_key(session_key, MacKeyPurpose::Frame).unwrap();

    let mac_key = MacKey::from_bytes(*mac_key_bytes.as_bytes());
    let mac = Blake3Mac::new(&mac_key);
    let tag = mac.compute(b"frame-header-and-payload");
    mac.verify(b"frame-header-and-payload", &tag).unwrap();
}

#[test]
fn incremental_mac_matches_oneshot() {
    let key = MacKey::from_bytes([0x42; 32]);
    let message = b"incremental-vs-oneshot-test-data";

    let oneshot = blake3_mac(&key, message);

    let mut inc = IncrementalMac::new(&key);
    inc.update(&message[..15]);
    inc.update(&message[15..]);
    let incremental = inc.finalize();

    assert_eq!(oneshot, incremental);
}

// ============================================================================
// 3. X25519 → HKDF → AEAD: full key agreement pipeline
// ============================================================================

#[test]
fn x25519_key_agreement_to_aead_session() {
    let alice_secret = X25519SecretKey::generate();
    let bob_secret = X25519SecretKey::generate();

    let alice_public = alice_secret.public_key();
    let bob_public = bob_secret.public_key();

    // Both sides compute same shared secret
    let alice_shared = alice_secret.diffie_hellman(&bob_public).unwrap();
    let bob_shared = bob_secret.diffie_hellman(&alice_public).unwrap();
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());

    // Derive session key from shared secret
    let session_key = Fcp2KeyDerivation::derive_session_key(
        alice_shared.as_bytes(),
        b"sess-1",
        SessionDirection::Send,
    )
    .unwrap();

    let key = AeadKey::from_bytes(*session_key.as_bytes());
    let cipher = XChaCha20Poly1305Cipher::new(&key);
    let ct = cipher
        .encrypt_with_random_nonce(b"encrypted message", b"")
        .unwrap();
    let pt = cipher.decrypt_with_prepended_nonce(&ct, b"").unwrap();
    assert_eq!(pt, b"encrypted message");
}

// ============================================================================
// 4. Ed25519 → KID: key identity derivation
// ============================================================================

#[test]
fn ed25519_key_id_matches_manual_derivation() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let kid_from_signing = signing_key.key_id();
    let kid_from_verifying = verifying_key.key_id();
    let kid_manual = KeyId::derive_from_public_key(&verifying_key.to_bytes());

    assert_eq!(kid_from_signing, kid_from_verifying);
    assert_eq!(kid_from_signing, kid_manual);
}

#[test]
fn different_keys_have_different_kids() {
    let k1 = Ed25519SigningKey::generate();
    let k2 = Ed25519SigningKey::generate();
    assert_ne!(k1.key_id(), k2.key_id());
}

// ============================================================================
// 5. Ed25519 sign + verify with context
// ============================================================================

#[test]
fn ed25519_contextual_signatures_isolated() {
    let key = Ed25519SigningKey::generate();
    let vk = key.verifying_key();

    let sig_a = key.sign_with_context(b"context-A", b"message");
    let sig_b = key.sign_with_context(b"context-B", b"message");

    // Same message, different context → different signatures
    assert_ne!(sig_a.to_bytes(), sig_b.to_bytes());

    // Verify with correct context
    vk.verify_with_context(b"context-A", b"message", &sig_a)
        .unwrap();

    // Verify with wrong context fails
    assert!(
        vk.verify_with_context(b"context-B", b"message", &sig_a)
            .is_err()
    );
}

// ============================================================================
// 6. COSE token: Ed25519 + CWT claims
// ============================================================================

#[test]
fn cose_token_sign_verify_roundtrip() {
    let key = Ed25519SigningKey::generate();
    let vk = key.verifying_key();

    let claims = CwtClaims::new()
        .issuer("test-issuer")
        .subject("test-subject")
        .capability_id("cap:read")
        .zone_id("z:work");

    let token = CoseToken::sign(&key, &claims).unwrap();
    let verified = token.verify(&vk).unwrap();

    assert_eq!(verified.get_issuer(), Some("test-issuer"));
    assert_eq!(verified.get_subject(), Some("test-subject"));
    assert_eq!(verified.get_capability_id(), Some("cap:read"));
    assert_eq!(verified.get_zone_id(), Some("z:work"));
}

#[test]
fn cose_token_cbor_serialization_roundtrip() {
    let key = Ed25519SigningKey::generate();
    let vk = key.verifying_key();

    let claims = CwtClaims::new().issuer("cbor-test").zone_id("z:owner");
    let token = CoseToken::sign(&key, &claims).unwrap();

    let bytes = token.to_cbor().unwrap();
    let restored = CoseToken::from_cbor(&bytes).unwrap();
    let verified = restored.verify(&vk).unwrap();
    assert_eq!(verified.get_issuer(), Some("cbor-test"));
}

#[test]
fn cose_token_wrong_key_fails() {
    let key1 = Ed25519SigningKey::generate();
    let key2 = Ed25519SigningKey::generate();

    let claims = CwtClaims::new().issuer("key1");
    let token = CoseToken::sign(&key1, &claims).unwrap();

    assert!(token.verify(&key2.verifying_key()).is_err());
}

#[test]
fn cose_token_timing_validation() {
    let key = Ed25519SigningKey::generate();
    let now = Utc::now();

    let claims = CwtClaims::new()
        .issuer("timing-test")
        .not_before(now - ChronoDuration::hours(1))
        .expiration(now + ChronoDuration::hours(1));

    let token = CoseToken::sign(&key, &claims).unwrap();
    let verified = token.verify(&key.verifying_key()).unwrap();

    // Valid now
    CoseToken::validate_timing(&verified, now).unwrap();

    // Expired
    let future = now + ChronoDuration::hours(2);
    assert!(CoseToken::validate_timing(&verified, future).is_err());

    // Not yet valid
    let past = now - ChronoDuration::hours(2);
    assert!(CoseToken::validate_timing(&verified, past).is_err());
}

#[test]
fn capability_token_builder_pipeline() {
    let key = Ed25519SigningKey::generate();
    let now = Utc::now();

    let token = CapabilityTokenBuilder::new()
        .capability_id("cap:storage.read")
        .zone_id("z:work")
        .principal("agent-007")
        .operations(&["read", "list"])
        .issuing_node("node-alpha")
        .issuer("zone-authority")
        .validity(now, now + ChronoDuration::hours(8))
        .sign(&key)
        .unwrap();

    let claims = token.verify(&key.verifying_key()).unwrap();
    assert_eq!(claims.get_capability_id(), Some("cap:storage.read"));
    assert_eq!(claims.get_zone_id(), Some("z:work"));
    assert_eq!(claims.get_holder_node(), None); // not set
}

#[test]
fn cose_token_key_id_matches_signer() {
    let key = Ed25519SigningKey::generate();
    let kid = key.key_id();

    let claims = CwtClaims::new().issuer("kid-test");
    let token = CoseToken::sign(&key, &claims).unwrap();

    let token_kid = token.get_key_id().unwrap();
    assert_eq!(token_kid, kid.as_bytes());
}

// ============================================================================
// 7. X25519 → HPKE: sealed box roundtrip
// ============================================================================

#[test]
fn hpke_seal_open_roundtrip() {
    let recipient = X25519SecretKey::generate();
    let pk = recipient.public_key();

    let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-recipient", 1_700_000_000);
    let sealed = hpke_seal(&pk, b"zone-key-material", &aad).unwrap();

    let opened = hpke_open(&recipient, &sealed, &aad).unwrap();
    assert_eq!(opened, b"zone-key-material");
}

#[test]
fn hpke_wrong_recipient_fails() {
    let recipient = X25519SecretKey::generate();
    let wrong_key = X25519SecretKey::generate();
    let pk = recipient.public_key();

    let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-1", 1000);
    let sealed = hpke_seal(&pk, b"secret", &aad).unwrap();

    assert!(hpke_open(&wrong_key, &sealed, &aad).is_err());
}

#[test]
fn hpke_wrong_aad_fails() {
    let recipient = X25519SecretKey::generate();
    let pk = recipient.public_key();

    let aad1 = Fcp2Aad::for_zone_key(b"z:work", b"node-1", 1000);
    let aad2 = Fcp2Aad::for_zone_key(b"z:private", b"node-1", 1000);
    let sealed = hpke_seal(&pk, b"secret", &aad1).unwrap();

    assert!(hpke_open(&recipient, &sealed, &aad2).is_err());
}

#[test]
fn hpke_sealed_box_bytes_roundtrip() {
    let recipient = X25519SecretKey::generate();
    let pk = recipient.public_key();
    let aad = Fcp2Aad::for_objectid_key(b"z:work", b"node-1", 42);

    let sealed = hpke_seal(&pk, b"objectid-key", &aad).unwrap();
    let bytes = sealed.to_bytes();
    let restored = HpkeSealedBox::from_bytes(&bytes).unwrap();

    let opened = hpke_open(&recipient, &restored, &aad).unwrap();
    assert_eq!(opened, b"objectid-key");
}

// ============================================================================
// 8. Shamir → reconstruct
// ============================================================================

#[test]
fn shamir_split_reconstruct_roundtrip() {
    let secret = b"my-32-byte-zone-key-material!!!!";
    let shares = split_secret(secret, 3, 5).unwrap();
    assert_eq!(shares.len(), 5);

    // Any 3 shares should reconstruct
    let subset = &shares[0..3];
    let recovered = reconstruct_secret(subset).unwrap();
    assert!(recovered.ct_eq_bytes(secret));
}

#[test]
fn shamir_different_subsets_same_result() {
    let secret = b"deterministic-reconstruction-ok!";
    let shares = split_secret(secret, 3, 5).unwrap();

    let r1 =
        reconstruct_secret(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]).unwrap();
    let r2 =
        reconstruct_secret(&[shares[2].clone(), shares[3].clone(), shares[4].clone()]).unwrap();
    let r3 =
        reconstruct_secret(&[shares[0].clone(), shares[2].clone(), shares[4].clone()]).unwrap();

    assert!(r1.ct_eq_bytes(secret));
    assert!(r2.ct_eq_bytes(secret));
    assert!(r3.ct_eq_bytes(secret));
}

#[test]
fn shamir_insufficient_shares_gives_wrong_result() {
    let secret = b"need-threshold-shares-to-recover";
    let shares = split_secret(secret, 3, 5).unwrap();

    // Only 2 shares — reconstruction will produce garbage
    let wrong = reconstruct_secret(&shares[0..2]).unwrap();
    assert!(!wrong.ct_eq_bytes(secret));
}

// ============================================================================
// 9. Canonicalization + Ed25519 signing
// ============================================================================

#[test]
fn canonical_signing_bytes_deterministic() {
    let schema_id = "fcp2.zone_key_manifest.v1";
    let cbor = vec![0xA1, 0x01, 0x42, 0x48, 0x49]; // minimal CBOR

    let bytes1 = canonical_signing_bytes(schema_id, &cbor);
    let bytes2 = canonical_signing_bytes(schema_id, &cbor);
    assert_eq!(bytes1, bytes2);

    // Different schema → different signing bytes
    let bytes3 = canonical_signing_bytes("fcp2.other.v1", &cbor);
    assert_ne!(bytes1, bytes3);
}

#[test]
fn schema_hash_is_8_bytes() {
    let hash = schema_hash("fcp2.test.v1");
    assert_eq!(hash.len(), 8);
}

#[test]
fn schema_hash_deterministic() {
    assert_eq!(
        schema_hash("fcp2.manifest.v1"),
        schema_hash("fcp2.manifest.v1")
    );
}

#[test]
fn node_signature_sorting() {
    let mut sigs = vec![
        NodeSignature::new(vec![3, 3], vec![0xCC; 64]),
        NodeSignature::new(vec![1, 1], vec![0xAA; 64]),
        NodeSignature::new(vec![2, 2], vec![0xBB; 64]),
    ];

    sort_node_signatures(&mut sigs);
    assert_eq!(sigs[0].node_id, vec![1, 1]);
    assert_eq!(sigs[1].node_id, vec![2, 2]);
    assert_eq!(sigs[2].node_id, vec![3, 3]);

    verify_node_signature_order(&sigs).unwrap();
}

#[test]
fn signature_order_verification_unsorted_fails() {
    let ids: Vec<&[u8]> = vec![&[3], &[1], &[2]];
    assert!(verify_signature_order(&ids).is_err());
}

// ============================================================================
// 10. Full pipeline: sign canonical → verify
// ============================================================================

#[test]
fn sign_canonical_data_and_verify() {
    let key = Ed25519SigningKey::generate();
    let vk = key.verifying_key();

    let schema_id = "fcp2.test_message.v1";
    let cbor_data = vec![0xA2, 0x01, 0x02, 0x03, 0x04];

    let signing_bytes = canonical_signing_bytes(schema_id, &cbor_data);
    let signature = key.sign(&signing_bytes);

    vk.verify(&signing_bytes, &signature).unwrap();

    // Tampered data fails
    let mut tampered = cbor_data;
    tampered[2] = 0xFF;
    let tampered_bytes = canonical_signing_bytes(schema_id, &tampered);
    assert!(vk.verify(&tampered_bytes, &signature).is_err());
}

// ============================================================================
// 11. HKDF → zone key + objectid key derivation
// ============================================================================

#[test]
fn zone_key_and_objectid_key_differ() {
    let material = b"root-keying-material-for-zone!!";
    let zone_id = b"z:work";

    let zk = Fcp2KeyDerivation::derive_zone_key(material, zone_id).unwrap();
    let ok = Fcp2KeyDerivation::derive_objectid_key(material, zone_id).unwrap();

    assert_ne!(zk.as_bytes(), ok.as_bytes());
}

#[test]
fn zone_key_derivation_deterministic() {
    let material = b"same-material-same-result!!!!!!";
    let zone_id = b"z:owner";

    let k1 = Fcp2KeyDerivation::derive_zone_key(material, zone_id).unwrap();
    let k2 = Fcp2KeyDerivation::derive_zone_key(material, zone_id).unwrap();
    assert_eq!(k1.as_bytes(), k2.as_bytes());
}

#[test]
fn different_zones_different_keys() {
    let material = b"shared-material-across-zones!!!!";

    let k1 = Fcp2KeyDerivation::derive_zone_key(material, b"z:work").unwrap();
    let k2 = Fcp2KeyDerivation::derive_zone_key(material, b"z:private").unwrap();
    assert_ne!(k1.as_bytes(), k2.as_bytes());
}

// ============================================================================
// 12. AEAD free functions consistency
// ============================================================================

#[test]
fn chacha20_free_fn_matches_cipher_struct() {
    let key = AeadKey::generate();
    let nonce = ChaCha20Nonce::from_counter(42);
    let plaintext = b"consistency check between APIs";

    let ct_fn = chacha20_encrypt(&key, &nonce, plaintext, b"aad").unwrap();

    let cipher = ChaCha20Poly1305Cipher::new(&key);
    let ct_struct = cipher.encrypt(&nonce, plaintext, b"aad").unwrap();

    assert_eq!(ct_fn, ct_struct);

    let pt_fn = chacha20_decrypt(&key, &nonce, &ct_fn, b"aad").unwrap();
    assert_eq!(pt_fn, plaintext);
}

#[test]
fn xchacha20_free_fn_matches_cipher_struct() {
    let key = AeadKey::generate();
    let nonce = XChaCha20Nonce::generate();
    let plaintext = b"xchacha20 consistency";

    let ct_fn = xchacha20_encrypt(&key, &nonce, plaintext, b"").unwrap();

    let cipher = XChaCha20Poly1305Cipher::new(&key);
    let ct_struct = cipher.encrypt(&nonce, plaintext, b"").unwrap();

    assert_eq!(ct_fn, ct_struct);

    let pt_fn = xchacha20_decrypt(&key, &nonce, &ct_fn, b"").unwrap();
    assert_eq!(pt_fn, plaintext);
}

// ============================================================================
// 13. AEAD AAD binding
// ============================================================================

#[test]
fn aead_wrong_aad_decryption_fails() {
    let key = AeadKey::generate();
    let nonce = ChaCha20Nonce::from_counter(1);
    let ct = chacha20_encrypt(&key, &nonce, b"bound to AAD", b"correct-aad").unwrap();

    assert!(chacha20_decrypt(&key, &nonce, &ct, b"wrong-aad").is_err());
}

#[test]
fn aead_empty_plaintext_roundtrip() {
    let key = AeadKey::generate();
    let nonce = ChaCha20Nonce::from_counter(0);
    let ct = chacha20_encrypt(&key, &nonce, &[], b"empty-body").unwrap();
    assert_eq!(ct.len(), AEAD_TAG_SIZE); // only auth tag
    let pt = chacha20_decrypt(&key, &nonce, &ct, b"empty-body").unwrap();
    assert_eq!(pt, [] as [u8; 0]);
}

// ============================================================================
// 14. XChaCha20 prepended nonce
// ============================================================================

#[test]
fn xchacha20_prepended_nonce_roundtrip() {
    let key = AeadKey::generate();
    let cipher = XChaCha20Poly1305Cipher::new(&key);

    let ct = cipher
        .encrypt_with_random_nonce(b"prepended nonce test", b"aad")
        .unwrap();
    assert_eq!(ct.len(), XCHACHA20_NONCE_SIZE + 20 + AEAD_TAG_SIZE);

    let pt = cipher.decrypt_with_prepended_nonce(&ct, b"aad").unwrap();
    assert_eq!(pt, b"prepended nonce test");
}

// ============================================================================
// 15. MAC full vs truncated
// ============================================================================

#[test]
fn mac_full_and_truncated_consistent() {
    let key = MacKey::from_bytes([0x55; 32]);
    let msg = b"mac consistency test";

    let truncated = blake3_mac(&key, msg);
    let full = blake3_mac_full(&key, msg);

    assert_eq!(truncated.len(), MAC_SIZE);
    assert_eq!(full.len(), BLAKE3_MAC_SIZE);
    assert_eq!(&full[..MAC_SIZE], &truncated[..]);
}

#[test]
fn mac_verify_rejects_tampered() {
    let key = MacKey::from_bytes([0x77; 32]);
    let tag = blake3_mac(&key, b"original");
    assert!(blake3_mac_verify(&key, b"tampered", &tag).is_err());
}

// ============================================================================
// 16. KID hex roundtrip
// ============================================================================

#[test]
fn kid_hex_roundtrip() {
    let kid = KeyId::derive_from_public_key(b"some-public-key-bytes");
    let hex_str = kid.to_hex();
    let restored = KeyId::from_hex(&hex_str).unwrap();
    assert_eq!(kid, restored);
}

#[test]
fn kid_from_hex_invalid() {
    assert!(KeyId::from_hex("not-hex").is_err());
    assert!(KeyId::from_hex("AABB").is_err()); // too short
}

// ============================================================================
// 17. Ed25519 signature serde
// ============================================================================

#[test]
fn ed25519_signature_serde_roundtrip() {
    let key = Ed25519SigningKey::generate();
    let sig = key.sign(b"serde test");

    let json = serde_json::to_string(&sig).unwrap();
    let restored: Ed25519Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.to_bytes(), restored.to_bytes());
}

#[test]
fn ed25519_verifying_key_serde_roundtrip() {
    let key = Ed25519SigningKey::generate();
    let vk = key.verifying_key();

    let json = serde_json::to_string(&vk).unwrap();
    let restored: Ed25519VerifyingKey = serde_json::from_str(&json).unwrap();
    assert_eq!(vk.to_bytes(), restored.to_bytes());
}

// ============================================================================
// 18. X25519 public key serde
// ============================================================================

#[test]
fn x25519_public_key_serde_roundtrip() {
    let sk = X25519SecretKey::generate();
    let pk = sk.public_key();

    let json = serde_json::to_string(&pk).unwrap();
    let restored: X25519PublicKey = serde_json::from_str(&json).unwrap();
    assert_eq!(pk.to_bytes(), restored.to_bytes());
}

// ============================================================================
// 19. Directional nonce isolation
// ============================================================================

#[test]
fn directional_nonces_differ() {
    let n_send = ChaCha20Nonce::from_counter_directional(100, 0);
    let n_recv = ChaCha20Nonce::from_counter_directional(100, 1);
    assert_ne!(n_send.as_bytes(), n_recv.as_bytes());
}

// ============================================================================
// 20. Constants verification
// ============================================================================

#[test]
fn crypto_constants_correct() {
    assert_eq!(AEAD_KEY_SIZE, 32);
    assert_eq!(CHACHA20_NONCE_SIZE, 12);
    assert_eq!(XCHACHA20_NONCE_SIZE, 24);
    assert_eq!(AEAD_TAG_SIZE, 16);
    assert_eq!(MAC_SIZE, 16);
    assert_eq!(BLAKE3_MAC_SIZE, 32);
    assert_eq!(MAC_KEY_SIZE, 32);
}

// ============================================================================
// 21. Error types
// ============================================================================

#[test]
fn crypto_error_display_variants() {
    let err = CryptoError::InvalidKeyLength {
        expected: 32,
        actual: 16,
    };
    assert!(format!("{err}").contains("32"));

    let err = CryptoError::AeadEncryptFailed;
    assert_ne!(format!("{err}"), "");

    let err = CryptoError::TokenExpired;
    assert_ne!(format!("{err}"), "");
}

// ============================================================================
// 22. HKDF generic array output
// ============================================================================

#[test]
fn hkdf_expand_to_array_various_sizes() {
    let hkdf = HkdfSha256::new(None, b"keying-material");

    let out16: [u8; 16] = hkdf.expand_to_array(b"info-16").unwrap();
    let out32: [u8; 32] = hkdf.expand_to_array(b"info-32").unwrap();
    let out64: [u8; 64] = hkdf.expand_to_array(b"info-64").unwrap();

    assert_eq!(out16.len(), 16);
    assert_eq!(out32.len(), 32);
    assert_eq!(out64.len(), 64);

    // Different info → different output
    let other: [u8; 32] = hkdf.expand_to_array(b"other-info").unwrap();
    assert_ne!(out32, other);
}

// ============================================================================
// 23. Shamir share serialization
// ============================================================================

#[test]
fn shamir_share_bytes_roundtrip() {
    let share = ShamirShare::new(5, vec![10, 20, 30, 40]);
    let bytes = share.to_bytes();
    let restored = ShamirShare::from_bytes(&bytes).unwrap();
    assert_eq!(restored.index(), 5);
    assert_eq!(restored.data(), &[10, 20, 30, 40]);
}

// ============================================================================
// 24. Full pipeline: X25519 → HKDF → MAC for frame authentication
// ============================================================================

#[test]
fn full_frame_authentication_pipeline() {
    let alice = X25519SecretKey::generate();
    let bob = X25519SecretKey::generate();

    let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
    let session_key = Fcp2KeyDerivation::derive_session_key(
        shared.as_bytes(),
        b"frame-sess",
        SessionDirection::Send,
    )
    .unwrap();
    let mac_derived =
        Fcp2KeyDerivation::derive_mac_key(session_key.as_bytes(), MacKeyPurpose::Header).unwrap();

    let mac_key = MacKey::from_bytes(*mac_derived.as_bytes());

    // Authenticate a frame
    let frame_header = b"frame-seq:42|len:256";
    let frame_payload = b"actual payload data here";

    let mut inc = IncrementalMac::new(&mac_key);
    inc.update(frame_header);
    inc.update(frame_payload);
    let tag = inc.finalize();

    // Verify
    let mac = Blake3Mac::new(&mac_key);
    let mut verify_data = Vec::new();
    verify_data.extend_from_slice(frame_header);
    verify_data.extend_from_slice(frame_payload);
    mac.verify(&verify_data, &tag).unwrap();
}
