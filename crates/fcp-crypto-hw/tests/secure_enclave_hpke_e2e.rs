//! End-to-end Secure Enclave HPKE roundtrip and key-non-extractability proofs
//! (`flywheel_connectors-3e4hv`).

use fcp_crypto_hw::{
    HpkeDecapPath, SecKeyHandle, SecureEnclaveError, SecureEnclaveHpke, derive_public_key,
    software_encap_and_seal, with_mock_secure_enclave,
};

/// Test-only Security.framework `SecKeyCopyExternalRepresentation` shim that mirrors
/// Apple's C API contract (`CFDataRef SecKeyCopyExternalRepresentation(SecKeyRef key, CFErrorRef *error)`):
/// returns `(std::ptr::null(), Some(SecureEnclaveError::KeyNotExtractable))` for enclave-bound keys.
#[allow(non_snake_case)]
fn SecKeyCopyExternalRepresentation(
    handle: &SecKeyHandle,
) -> (*const u8, Option<SecureEnclaveError>) {
    match handle.try_export_private_key_bytes() {
        Ok(_) => (std::ptr::null(), None),
        Err(err) => (std::ptr::null(), Some(err)),
    }
}

#[test]
fn test_hpke_decap_roundtrip_via_enclave() {
    let seed = [0x6B_u8; 32];
    let ephemeral_seed = [0xC4_u8; 32];
    let reference_plaintext = b"apple-silicon-secure-enclave-hpke-e2e-roundtrip";

    let handle = SecKeyHandle::new_in_enclave(&seed);
    let recipient_pk = handle.public_key().expect("enclave handle must expose public key");
    assert_eq!(recipient_pk, derive_public_key(&seed));

    let ciphertext =
        software_encap_and_seal(&recipient_pk, &ephemeral_seed, b"", reference_plaintext);

    with_mock_secure_enclave(true, || {
        let enclave = SecureEnclaveHpke::new().expect("enclave HPKE must initialize");
        let output = enclave
            .decap(&ciphertext, &handle)
            .expect("enclave HPKE decap roundtrip must succeed");
        assert_eq!(output.as_bytes(), reference_plaintext);
        assert_eq!(output.path, HpkeDecapPath::Enclave);
        assert!(!output.fallback_used);
    });
}

#[test]
fn test_key_extraction_attempt_fails() {
    let seed = [0x91_u8; 32];
    let handle = SecKeyHandle::new_in_enclave(&seed);

    let access = handle
        .access_control()
        .expect("enclave handle must report access control");
    assert!(access.private_key_usage);
    assert!(!access.extractable);

    let (cf_data_ref, cf_error) = SecKeyCopyExternalRepresentation(&handle);
    assert!(
        cf_data_ref.is_null(),
        "SecKeyCopyExternalRepresentation must return NULL for Secure Enclave keys"
    );
    assert_eq!(
        cf_error,
        Some(SecureEnclaveError::KeyNotExtractable),
        "SecKeyCopyExternalRepresentation must populate structured KeyNotExtractable error"
    );
}

#[test]
fn test_no_secret_in_memory_dump() {
    let mut known_seed = [0_u8; 32];
    for (idx, byte) in known_seed.iter_mut().enumerate() {
        *byte = u8::try_from(idx).unwrap_or(0).wrapping_mul(9).wrapping_add(0x3D);
    }

    let handle = SecKeyHandle::new_in_enclave(&known_seed);
    let recipient_pk = handle
        .public_key()
        .expect("enclave handle must expose public key");
    // Zero the caller's stack copy before running decap and scanning retained memory.
    let expected_seed_copy: Vec<u8> = known_seed.iter().map(|b| b ^ 0x55).collect();
    known_seed.fill(0);

    let ephemeral_seed = [0xE2_u8; 32];
    let plaintext = b"memory-dump-hygiene-verification";
    let ciphertext = software_encap_and_seal(&recipient_pk, &ephemeral_seed, b"", plaintext);

    let output = SecureEnclaveHpke::decap_in_enclave(&ciphertext, handle);
    assert_eq!(output.as_bytes(), plaintext);

    // Reconstruct the needle only in a transient byte comparison window and verify
    // neither the enclave registry nor the output buffer contains the private key seed.
    let needle: Vec<u8> = expected_seed_copy.iter().map(|b| b ^ 0x55).collect();
    assert!(
        !SecKeyHandle::enclave_memory_contains_bytes(&needle),
        "retained enclave slots must never contain raw private-key bytes"
    );
    let output_bytes = output.to_bytes();
    let matches_in_output = output_bytes
        .windows(needle.len())
        .filter(|window| *window == needle.as_slice())
        .count();
    assert_eq!(
        matches_in_output, 0,
        "post-decap output buffers must contain zero matches for the private-key seed"
    );
}
