//! Unit tests for Apple `CryptoKit` Secure Enclave `SecKeyHandle` lifecycle and fallback semantics
//! (`flywheel_connectors-3e4hv`).

#![allow(clippy::similar_names)]

use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use fcp_crypto_hw::{
    HpkeDecapPath, SecKeyHandle, SecureEnclaveError, SecureEnclaveHpke, derive_public_key,
    enclave_fallback_total, reset_enclave_telemetry_for_tests, software_decap,
    software_encap_and_seal, startup_unavailable_warn_count, with_mock_secure_enclave,
};

fn telemetry_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn test_handle_drop_releases_secref() {
    let release_counter = Arc::new(AtomicUsize::new(0));
    let seed = [0x42_u8; 32];
    {
        let handle = SecKeyHandle::with_release_counter(&seed, Some(Arc::clone(&release_counter)));
        assert_eq!(release_counter.load(Ordering::SeqCst), 0);
        assert!(handle.public_key().is_ok());
    }
    assert_eq!(
        release_counter.load(Ordering::SeqCst),
        1,
        "dropping SecKeyHandle must invoke CFRelease exactly once"
    );
}

#[test]
fn test_decap_returns_byte_equivalent_to_software_path() {
    let recipient_sk = [0x29_u8; 32];
    let ephemeral_seed = [0x71_u8; 32];
    let plaintext = b"flywheel-phase-t5-secure-enclave-hpke-vector";

    let recipient_pk = derive_public_key(&recipient_sk);
    let ciphertext = software_encap_and_seal(&recipient_pk, &ephemeral_seed, b"", plaintext);

    let software_out =
        software_decap(&ciphertext, &recipient_sk).expect("software HPKE decap must succeed");
    let handle = SecKeyHandle::new_in_enclave(&recipient_sk);
    let enclave_out = SecureEnclaveHpke::decap_in_enclave(&ciphertext, handle);

    assert_eq!(enclave_out, software_out);
    assert_eq!(enclave_out.to_bytes(), software_out.to_bytes());
    assert_eq!(enclave_out.as_bytes(), plaintext);
    assert_eq!(enclave_out.path, HpkeDecapPath::Enclave);
    assert!(!enclave_out.fallback_used);
}

#[test]
fn test_unsupported_hardware_returns_structured_error() {
    let _guard = telemetry_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset_enclave_telemetry_for_tests();

    with_mock_secure_enclave(false, || {
        let err = SecureEnclaveHpke::new()
            .expect_err("SecureEnclaveHpke::new must fail when enclave unavailable");
        assert_eq!(err, SecureEnclaveError::NotAvailable);
    });
}

#[test]
fn test_kerrsecauthfailed_falls_back_to_software() {
    let _guard = telemetry_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset_enclave_telemetry_for_tests();

    let recipient_sk = [0x5A_u8; 32];
    let ephemeral_seed = [0x9C_u8; 32];
    let plaintext = b"kErrSecAuthFailed fallback payload";
    let aad = b"fcp.zone.work";

    let recipient_pk = derive_public_key(&recipient_sk);
    let ciphertext = software_encap_and_seal(&recipient_pk, &ephemeral_seed, aad, plaintext);

    with_mock_secure_enclave(true, || {
        let engine = SecureEnclaveHpke::new().expect("mocked enclave must initialize");
        let handle = SecKeyHandle::new_in_enclave(&recipient_sk);
        handle
            .set_simulated_auth_failure(true)
            .expect("simulated auth failure flag must set");

        let direct_err = engine
            .decap_with_aad(&ciphertext, &handle, aad)
            .expect_err("direct enclave decap must surface EnclaveAuthFailed");
        assert_eq!(direct_err, SecureEnclaveError::EnclaveAuthFailed);

        let before_fallbacks = enclave_fallback_total();
        let fallback_out = engine
            .decap_or_software_fallback(&ciphertext, &handle, &recipient_sk, aad)
            .expect("caller fallback helper must recover via software HPKE");
        assert_eq!(fallback_out.as_bytes(), plaintext);
        assert_eq!(fallback_out.path, HpkeDecapPath::Software);
        assert!(fallback_out.fallback_used);
        assert_eq!(enclave_fallback_total(), before_fallbacks + 1);
    });
}

#[test]
fn test_enclave_unavailable_logs_once_and_uses_software() {
    let _guard = telemetry_test_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset_enclave_telemetry_for_tests();

    let recipient_sk = [0x13_u8; 32];
    let ephemeral_seed = [0x88_u8; 32];
    let plaintext = b"rate-limited warn once check";
    let recipient_pk = derive_public_key(&recipient_sk);
    let ciphertext = software_encap_and_seal(&recipient_pk, &ephemeral_seed, b"", plaintext);

    with_mock_secure_enclave(false, || {
        let engine = SecureEnclaveHpke::new_or_software_fallback();
        assert_eq!(engine.path(), HpkeDecapPath::Software);
        assert_eq!(
            startup_unavailable_warn_count(),
            1,
            "startup must emit exactly one WARN when Secure Enclave is unavailable"
        );

        let handle = SecKeyHandle::new_in_enclave(&recipient_sk);
        for _ in 0..5 {
            let out = engine
                .decap_or_software_fallback(&ciphertext, &handle, &recipient_sk, b"")
                .expect("software decap must succeed");
            assert_eq!(out.as_bytes(), plaintext);
        }
        let _second_engine = SecureEnclaveHpke::new_or_software_fallback();
        assert_eq!(
            startup_unavailable_warn_count(),
            1,
            "subsequent decaps and initializations must not emit duplicate startup WARN lines"
        );
    });
}
