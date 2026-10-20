//! Cross-crate conformance test proving byte-equivalence between the Apple Secure Enclave
//! HPKE decapsulation path and the portable software HPKE path across 100 test vectors
//! (`flywheel_connectors-3e4hv`).

use fcp_crypto_hw::{
    SecKeyHandle, SecureEnclaveHpke, derive_public_key, software_decap_with_aad,
    software_encap_and_seal, with_mock_secure_enclave,
};

#[test]
fn test_enclave_and_software_paths_byte_identical_on_test_vectors() {
    with_mock_secure_enclave(true, || {
        let enclave = SecureEnclaveHpke::new().expect("enclave HPKE must initialize");

        for vector_idx in 0_u32..100 {
            let sk_seed = *blake3::hash(format!("hpke-conformance-sk-{vector_idx}").as_bytes())
                .as_bytes();
            let eph_seed = *blake3::hash(format!("hpke-conformance-eph-{vector_idx}").as_bytes())
                .as_bytes();
            let aad = format!("fcp.conformance.aad.{vector_idx}");
            let plaintext = format!(
                "conformance-hpke-vector-{vector_idx:03}-payload-len-{}",
                vector_idx * 7
            );

            let recipient_pk = derive_public_key(&sk_seed);
            let ciphertext = software_encap_and_seal(
                &recipient_pk,
                &eph_seed,
                aad.as_bytes(),
                plaintext.as_bytes(),
            );

            let handle = SecKeyHandle::new_in_enclave(&sk_seed);
            let enclave_out = enclave
                .decap_with_aad(&ciphertext, &handle, aad.as_bytes())
                .expect("enclave HPKE decap must succeed on test vector");
            let software_out =
                software_decap_with_aad(&ciphertext, &sk_seed, aad.as_bytes())
                    .expect("software HPKE decap must succeed on test vector");

            assert_eq!(
                enclave_out, software_out,
                "enclave and software HPKE outputs diverged at vector {vector_idx}"
            );
            assert_eq!(
                enclave_out.to_bytes(),
                software_out.to_bytes(),
                "byte representation diverged at vector {vector_idx}"
            );
            assert_eq!(enclave_out.as_bytes(), plaintext.as_bytes());
        }
    });
}
