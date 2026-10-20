//! Cryptographic hardware feature detection and dispatch.
//!
//! This crate owns the small, safe substrate that later acceleration beads use
//! for BLAKE3, AEAD, and lattice/NTT dispatch. It deliberately starts with
//! portable function pointers so unsupported or incorrectly detected hardware
//! always falls back to deterministic safe code.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod apple_se;
pub mod blake3;
pub mod cpuid;
pub mod dispatch;

pub use aead::{
    CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_NONCE_SIZE, CHACHA20POLY1305_TAG_SIZE,
    Chacha20Poly1305Backend, Chacha20Poly1305Dispatch, Chacha20Poly1305Error,
};
pub use apple_se::{
    HPKE_ENC_SIZE, HPKE_MIN_CIPHERTEXT_SIZE, HpkeDecapPath, HpkeOutput, HwAccelDoctorReport,
    SecAccessControl, SecKeyHandle, SecureEnclaveError, SecureEnclaveHpke,
    StartupEnclaveStatusLine, derive_public_key, doctor_hw_accel_report,
    doctor_hw_accel_report_for_features, enclave_fallback_total, has_secure_enclave,
    reset_enclave_telemetry_for_tests, software_decap, software_decap_with_aad,
    software_encap_and_seal, startup_unavailable_warn_count, with_mock_secure_enclave,
};
pub use blake3::{Blake3DispatchError, Blake3Hasher, Blake3Tier};
pub use cpuid::{HwFeatureSet, detect};
pub use dispatch::{
    AesGcmDispatch, Blake3Dispatch, DispatchTier, FunctionTable, NttDispatch, build_function_table,
    function_table,
};
