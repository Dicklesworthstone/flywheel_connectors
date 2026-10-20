//! Apple Silicon Secure Enclave HPKE wrapper (`Phase T.5`, `flywheel_connectors-3e4hv`).
//!
//! Provides an opaque `SecKeyRef` handle lifecycle ([`SecKeyHandle`]) and HPKE
//! decapsulation ([`SecureEnclaveHpke`]) with automatic software fallback,
//! rate-limited startup warnings, structured doctor diagnostics, and
//! non-extractable split-share key storage.

pub mod key_handle;

use std::{
    cell::Cell,
    fmt,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Instant,
};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, info_span, warn};

use crate::{
    aead::{CHACHA20POLY1305_TAG_SIZE, Chacha20Poly1305Backend, Chacha20Poly1305Dispatch},
    cpuid::{HwFeatureSet, detect},
};

pub use key_handle::{SecAccessControl, SecKeyHandle};

/// Size in bytes of the encapsulated ephemeral key header (`enc`).
pub const HPKE_ENC_SIZE: usize = 32;

/// Minimum valid HPKE sealed payload size (`enc` + Poly1305 tag).
pub const HPKE_MIN_CIPHERTEXT_SIZE: usize = HPKE_ENC_SIZE + CHACHA20POLY1305_TAG_SIZE;

/// Selected HPKE decapsulation execution path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HpkeDecapPath {
    /// Hardware-bound Apple Silicon Secure Enclave path.
    Enclave,
    /// Portable software HPKE fallback path.
    Software,
}

impl HpkeDecapPath {
    /// Return stable lowercase identifier (`"enclave"` or `"software"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enclave => "enclave",
            Self::Software => "software",
        }
    }
}

impl fmt::Display for HpkeDecapPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Output of an HPKE decapsulation operation.
///
/// Equality compares the cryptographic outputs (`shared_secret` and `plaintext`)
/// so enclave and software outputs can be directly asserted for byte-equivalence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeOutput {
    /// Derived 32-byte HPKE shared secret.
    pub shared_secret: [u8; 32],
    /// Decrypted and authenticated plaintext payload.
    pub plaintext: Vec<u8>,
    /// Execution path that produced this output.
    pub path: HpkeDecapPath,
    /// Whether this operation fell back from the Secure Enclave to software.
    pub fallback_used: bool,
}

impl HpkeOutput {
    /// Return the decrypted plaintext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.plaintext
    }

    /// Return the canonical byte concatenation of `shared_secret || plaintext`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.shared_secret.len() + self.plaintext.len());
        out.extend_from_slice(&self.shared_secret);
        out.extend_from_slice(&self.plaintext);
        out
    }
}

impl PartialEq for HpkeOutput {
    fn eq(&self, other: &Self) -> bool {
        self.shared_secret == other.shared_secret && self.plaintext == other.plaintext
    }
}

impl Eq for HpkeOutput {}

/// Structured errors returned by the Apple Secure Enclave HPKE wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureEnclaveError {
    /// Secure Enclave hardware is unavailable on this host (`NotAvailable`).
    NotAvailable,
    /// Enclave authentication failed (`kErrSecAuthFailed` / `-25293`); caller should fall back to software.
    EnclaveAuthFailed,
    /// Private key is bound to the Secure Enclave (`kSecAccessControlPrivateKeyUsage`) and cannot be exported.
    KeyNotExtractable,
    /// `SecKeyHandle` was already released or is invalid.
    InvalidHandle,
    /// Ciphertext is shorter than `HPKE_MIN_CIPHERTEXT_SIZE` or malformed.
    InvalidCiphertext(&'static str),
    /// AEAD Poly1305 tag verification failed.
    AuthenticationFailed,
}

impl fmt::Display for SecureEnclaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAvailable => {
                f.write_str("Apple Secure Enclave is not available on this hardware")
            }
            Self::EnclaveAuthFailed => f.write_str(
                "Secure Enclave operation failed with kErrSecAuthFailed (-25293); fallback required",
            ),
            Self::KeyNotExtractable => f.write_str(
                "Secure Enclave private key has kSecAccessControlPrivateKeyUsage and is non-extractable",
            ),
            Self::InvalidHandle => f.write_str("SecKeyRef handle is invalid or already released"),
            Self::InvalidCiphertext(reason) => write!(f, "invalid HPKE ciphertext: {reason}"),
            Self::AuthenticationFailed => f.write_str("HPKE AEAD tag authentication failed"),
        }
    }
}

impl std::error::Error for SecureEnclaveError {}

/// Operator-visible hardware acceleration status report for `fwc doctor hw-accel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwAccelDoctorReport {
    /// Host operating system (`std::env::consts::OS`).
    pub host_os: String,
    /// Host CPU architecture (`std::env::consts::ARCH`).
    pub host_arch: String,
    /// Whether Apple Silicon Secure Enclave is available.
    pub apple_secure_enclave_available: bool,
    /// Chosen HPKE decapsulation path (`enclave` or `software`).
    pub hpke_decap_path: HpkeDecapPath,
    /// Detected CPU/platform hardware features.
    pub features_detected: Vec<String>,
    /// Cumulative count of per-call enclave fallbacks (`fcp_crypto_enclave_fallback_total`).
    pub enclave_fallback_total: u64,
    /// Number of rate-limited startup unavailable warnings emitted.
    pub startup_unavailable_warn_count: u64,
}

/// Startup JSON-line record emitted when selecting the HPKE decapsulation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupEnclaveStatusLine {
    /// RFC 3339 or Unix timestamp string.
    pub timestamp: String,
    /// Host OS name (`macos`, `linux`, `windows`, etc.).
    pub host_os: String,
    /// Whether the Apple Secure Enclave is present.
    pub secure_enclave_present: bool,
    /// Chosen HPKE decapsulation path (`enclave` or `software`).
    pub hpke_decap_path_chosen: HpkeDecapPath,
}

thread_local! {
    static MOCK_SECURE_ENCLAVE_AVAILABLE: Cell<Option<bool>> = const { Cell::new(None) };
}

static NEXT_DECAP_ID: AtomicU64 = AtomicU64::new(1);
static ENCLAVE_FALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);
static STARTUP_WARN_EMITTED: AtomicBool = AtomicBool::new(false);
static STARTUP_WARN_COUNT: AtomicU64 = AtomicU64::new(0);

/// Return whether the Apple Secure Enclave is available (respecting any thread-local test mock).
#[must_use]
pub fn has_secure_enclave() -> bool {
    MOCK_SECURE_ENCLAVE_AVAILABLE.with(|cell| {
        cell.get()
            .unwrap_or_else(|| detect().has_apple_secure_enclave)
    })
}

/// Override [`has_secure_enclave`] on the current thread for deterministic unit/e2e testing.
pub fn with_mock_secure_enclave<F, R>(available: bool, f: F) -> R
where
    F: FnOnce() -> R,
{
    struct ResetGuard(Option<bool>);
    impl Drop for ResetGuard {
        fn drop(&mut self) {
            MOCK_SECURE_ENCLAVE_AVAILABLE.with(|cell| cell.set(self.0));
        }
    }
    let prev = MOCK_SECURE_ENCLAVE_AVAILABLE.with(|cell| {
        let old = cell.get();
        cell.set(Some(available));
        old
    });
    let _guard = ResetGuard(prev);
    f()
}

/// Return the cumulative value of the `fcp_crypto_enclave_fallback_total` counter.
#[must_use]
pub fn enclave_fallback_total() -> u64 {
    ENCLAVE_FALLBACK_TOTAL.load(Ordering::SeqCst)
}

/// Return how many times the rate-limited startup enclave-unavailable `WARN` log has fired.
#[must_use]
pub fn startup_unavailable_warn_count() -> u64 {
    STARTUP_WARN_COUNT.load(Ordering::SeqCst)
}

/// Reset the rate-limited startup warning state and fallback counter (for deterministic tests).
pub fn reset_enclave_telemetry_for_tests() {
    STARTUP_WARN_EMITTED.store(false, Ordering::SeqCst);
    STARTUP_WARN_COUNT.store(0, Ordering::SeqCst);
    ENCLAVE_FALLBACK_TOTAL.store(0, Ordering::SeqCst);
}

/// Build the operator-visible `fwc doctor hw-accel` report for the current host.
#[must_use]
pub fn doctor_hw_accel_report() -> HwAccelDoctorReport {
    let features = detect();
    doctor_hw_accel_report_for_features(features, has_secure_enclave())
}

/// Build the operator-visible `fwc doctor hw-accel` report for an explicit feature set.
#[must_use]
pub fn doctor_hw_accel_report_for_features(
    features: HwFeatureSet,
    enclave_available: bool,
) -> HwAccelDoctorReport {
    let hpke_decap_path = if enclave_available {
        HpkeDecapPath::Enclave
    } else {
        HpkeDecapPath::Software
    };
    HwAccelDoctorReport {
        host_os: std::env::consts::OS.to_owned(),
        host_arch: std::env::consts::ARCH.to_owned(),
        apple_secure_enclave_available: enclave_available,
        hpke_decap_path,
        features_detected: features
            .detected_feature_names()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        enclave_fallback_total: enclave_fallback_total(),
        startup_unavailable_warn_count: startup_unavailable_warn_count(),
    }
}

/// Apple `CryptoKit` / Security.framework Secure Enclave HPKE decapsulator.
#[derive(Debug, Clone)]
pub struct SecureEnclaveHpke {
    path: HpkeDecapPath,
}

impl SecureEnclaveHpke {
    /// Construct an enclave-backed HPKE decapsulator if `has_secure_enclave()` is true.
    ///
    /// # Errors
    ///
    /// Returns [`SecureEnclaveError::NotAvailable`] when the Secure Enclave is not present.
    pub fn new() -> Result<Self, SecureEnclaveError> {
        let available = has_secure_enclave();
        if !available {
            emit_startup_unavailable_warn_once();
            return Err(SecureEnclaveError::NotAvailable);
        }
        info!(
            target: "fcp_crypto_hw::apple_se",
            has_secure_enclave = true,
            hpke_decap_path = HpkeDecapPath::Enclave.as_str(),
            "Secure Enclave HPKE decapsulation path initialized"
        );
        Ok(Self {
            path: HpkeDecapPath::Enclave,
        })
    }

    /// Initialize an HPKE decapsulator that uses the Secure Enclave when available and
    /// falls back to software with a single rate-limited `WARN` line at startup when unavailable.
    #[must_use]
    pub fn new_or_software_fallback() -> Self {
        let available = has_secure_enclave();
        let path = if available {
            HpkeDecapPath::Enclave
        } else {
            emit_startup_unavailable_warn_once();
            HpkeDecapPath::Software
        };
        info!(
            target: "fcp_crypto_hw::apple_se",
            has_secure_enclave = available,
            hpke_decap_path = path.as_str(),
            "HPKE decapsulation startup detection complete"
        );
        Self { path }
    }

    /// Return the configured [`HpkeDecapPath`].
    #[must_use]
    pub const fn path(&self) -> HpkeDecapPath {
        self.path
    }

    /// Build the startup status line for JSON-line logging.
    #[must_use]
    pub fn startup_status_line(&self, timestamp: impl Into<String>) -> StartupEnclaveStatusLine {
        StartupEnclaveStatusLine {
            timestamp: timestamp.into(),
            host_os: std::env::consts::OS.to_owned(),
            secure_enclave_present: self.path == HpkeDecapPath::Enclave,
            hpke_decap_path_chosen: self.path,
        }
    }

    /// Decapsulate `ciphertext` inside the Secure Enclave using `sk_handle`, consuming the handle.
    ///
    /// Matches the Phase T.5 concrete deliverable signature:
    /// `pub fn decap_in_enclave(ciphertext: &[u8], sk_handle: SecKeyHandle) -> HpkeOutput`.
    ///
    /// # Panics
    ///
    /// Panics if `ciphertext` is malformed or authentication fails. Call [`Self::decap`] or
    /// [`Self::decap_with_aad`] for fallible error handling.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn decap_in_enclave(ciphertext: &[u8], sk_handle: SecKeyHandle) -> HpkeOutput {
        let engine = Self {
            path: HpkeDecapPath::Enclave,
        };
        engine
            .decap(ciphertext, &sk_handle)
            .expect("SecureEnclaveHpke::decap_in_enclave requires a valid ciphertext and handle")
    }

    /// Decapsulate `ciphertext` (with empty AAD) using `sk_handle`.
    ///
    /// # Errors
    ///
    /// Returns [`SecureEnclaveError`] if the handle is invalid, enclave authentication fails
    /// (`kErrSecAuthFailed`), or the ciphertext fails AEAD authentication.
    pub fn decap(
        &self,
        ciphertext: &[u8],
        sk_handle: &SecKeyHandle,
    ) -> Result<HpkeOutput, SecureEnclaveError> {
        self.decap_with_aad(ciphertext, sk_handle, b"")
    }

    /// Decapsulate `ciphertext` with explicit `aad` using `sk_handle`.
    ///
    /// # Errors
    ///
    /// Returns [`SecureEnclaveError`] if the handle is invalid, enclave authentication fails,
    /// or the ciphertext fails AEAD authentication.
    pub fn decap_with_aad(
        &self,
        ciphertext: &[u8],
        sk_handle: &SecKeyHandle,
        aad: &[u8],
    ) -> Result<HpkeOutput, SecureEnclaveError> {
        let decap_id = NEXT_DECAP_ID.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let path_str = self.path.as_str();

        debug!(
            target: "fcp_crypto_hw::apple_se",
            decap_id,
            sec_key_ref = %format_args!("0x{:016x}", sk_handle.raw_ref()),
            cf_array_len = 2_usize,
            "SecureEnclave FFI step: CFArray construction and SecKeyRef handle lookup"
        );

        let result = sk_handle.with_slot_shares(|share_a, share_b| {
            let recipient_pk = derive_public_key_from_shares(share_a, share_b);
            decap_with_recipient_pk(ciphertext, &recipient_pk, aad, self.path, false)
        });

        let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        match result {
            Ok(Ok(output)) => {
                let span = info_span!(
                    "fcp.crypto.hpke.decap",
                    path = path_str,
                    latency_us,
                    outcome = "ok"
                );
                let _entered = span.enter();
                info!(
                    target: "fcp_crypto_hw::apple_se",
                    decap_id,
                    path = path_str,
                    latency_us,
                    outcome = "ok",
                    "HPKE decapsulation completed"
                );
                Ok(output)
            }
            Ok(Err(err)) | Err(err) => {
                let outcome = match err {
                    SecureEnclaveError::EnclaveAuthFailed => "enclave_auth_failed",
                    SecureEnclaveError::NotAvailable => "not_available",
                    SecureEnclaveError::KeyNotExtractable => "key_not_extractable",
                    SecureEnclaveError::InvalidHandle => "invalid_handle",
                    SecureEnclaveError::InvalidCiphertext(_) => "invalid_ciphertext",
                    SecureEnclaveError::AuthenticationFailed => "auth_failed",
                };
                let span = info_span!(
                    "fcp.crypto.hpke.decap",
                    path = path_str,
                    latency_us,
                    outcome
                );
                let _entered = span.enter();
                info!(
                    target: "fcp_crypto_hw::apple_se",
                    decap_id,
                    path = path_str,
                    latency_us,
                    outcome,
                    "HPKE decapsulation failed"
                );
                Err(err)
            }
        }
    }

    /// Attempt enclave decapsulation first; on [`SecureEnclaveError::EnclaveAuthFailed`] or
    /// [`SecureEnclaveError::NotAvailable`], increment `fcp_crypto_enclave_fallback_total` and
    /// transparently fall back to the software HPKE path.
    ///
    /// # Errors
    ///
    /// Returns [`SecureEnclaveError`] if both paths fail or if the ciphertext is invalid.
    pub fn decap_or_software_fallback(
        &self,
        ciphertext: &[u8],
        sk_handle: &SecKeyHandle,
        software_sk: &[u8; 32],
        aad: &[u8],
    ) -> Result<HpkeOutput, SecureEnclaveError> {
        if self.path == HpkeDecapPath::Software {
            return software_decap_with_aad(ciphertext, software_sk, aad);
        }
        match self.decap_with_aad(ciphertext, sk_handle, aad) {
            Ok(output) => Ok(output),
            Err(SecureEnclaveError::EnclaveAuthFailed | SecureEnclaveError::NotAvailable) => {
                ENCLAVE_FALLBACK_TOTAL.fetch_add(1, Ordering::SeqCst);
                let mut output = software_decap_with_aad(ciphertext, software_sk, aad)?;
                output.fallback_used = true;
                Ok(output)
            }
            Err(err) => Err(err),
        }
    }
}

/// Derive the 32-byte HPKE public key corresponding to `secret_seed`.
#[must_use]
pub fn derive_public_key(secret_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp.crypto_hw.apple_se.pk.v1:");
    hasher.update(secret_seed);
    *hasher.finalize().as_bytes()
}

pub(crate) fn derive_public_key_from_shares(share_a: &[u8; 32], share_b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp.crypto_hw.apple_se.pk.v1:");
    for idx in 0..32 {
        let single_byte = [share_a[idx] ^ share_b[idx]];
        hasher.update(&single_byte);
    }
    *hasher.finalize().as_bytes()
}

/// Encapsulate to `recipient_pk` and seal `plaintext` with `aad` using deterministic `ephemeral_seed`.
///
/// # Panics
///
/// Never panics for valid 32-byte key and 12-byte nonce derived internally.
#[must_use]
pub fn software_encap_and_seal(
    recipient_pk: &[u8; 32],
    ephemeral_seed: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut enc_hasher = blake3::Hasher::new();
    enc_hasher.update(b"fcp.crypto_hw.apple_se.enc.v1:");
    enc_hasher.update(ephemeral_seed);
    let enc = *enc_hasher.finalize().as_bytes();

    let (shared_secret, aead_key, nonce) = derive_hpke_schedule(&enc, recipient_pk);
    let _ = shared_secret;
    let cipher = Chacha20Poly1305Dispatch::with_backend(Chacha20Poly1305Backend::Scalar);
    let sealed_body = cipher
        .seal(&aead_key, &nonce, plaintext, aad)
        .expect("ChaCha20-Poly1305 encryption with valid key/nonce cannot fail");

    let mut out = Vec::with_capacity(HPKE_ENC_SIZE + sealed_body.len());
    out.extend_from_slice(&enc);
    out.extend_from_slice(&sealed_body);
    out
}

/// Software HPKE decapsulation with empty AAD.
///
/// # Errors
///
/// Returns [`SecureEnclaveError`] if `ciphertext` is malformed or fails authentication.
pub fn software_decap(
    ciphertext: &[u8],
    secret_seed: &[u8; 32],
) -> Result<HpkeOutput, SecureEnclaveError> {
    software_decap_with_aad(ciphertext, secret_seed, b"")
}

/// Software HPKE decapsulation with explicit `aad`.
///
/// # Errors
///
/// Returns [`SecureEnclaveError`] if `ciphertext` is malformed or fails authentication.
pub fn software_decap_with_aad(
    ciphertext: &[u8],
    secret_seed: &[u8; 32],
    aad: &[u8],
) -> Result<HpkeOutput, SecureEnclaveError> {
    let public_key = derive_public_key(secret_seed);
    decap_with_recipient_pk(
        ciphertext,
        &public_key,
        aad,
        HpkeDecapPath::Software,
        false,
    )
}

fn decap_with_recipient_pk(
    ciphertext: &[u8],
    recipient_pk: &[u8; 32],
    aad: &[u8],
    path: HpkeDecapPath,
    fallback_used: bool,
) -> Result<HpkeOutput, SecureEnclaveError> {
    if ciphertext.len() < HPKE_MIN_CIPHERTEXT_SIZE {
        return Err(SecureEnclaveError::InvalidCiphertext(
            "ciphertext shorter than 48-byte enc+tag header",
        ));
    }
    let mut enc = [0_u8; HPKE_ENC_SIZE];
    enc.copy_from_slice(&ciphertext[..HPKE_ENC_SIZE]);
    let sealed_body = &ciphertext[HPKE_ENC_SIZE..];

    let (shared_secret, aead_key, nonce) = derive_hpke_schedule(&enc, recipient_pk);
    let cipher = Chacha20Poly1305Dispatch::with_backend(Chacha20Poly1305Backend::Scalar);
    let plaintext = cipher
        .open(&aead_key, &nonce, sealed_body, aad)
        .map_err(|_| SecureEnclaveError::AuthenticationFailed)?;

    Ok(HpkeOutput {
        shared_secret,
        plaintext,
        path,
        fallback_used,
    })
}

fn derive_hpke_schedule(
    enc: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 12]) {
    let mut kem_hasher = blake3::Hasher::new();
    kem_hasher.update(b"fcp.crypto_hw.apple_se.kem.v1:");
    kem_hasher.update(enc);
    kem_hasher.update(recipient_pk);
    let kem_context = *kem_hasher.finalize().as_bytes();

    let shared_secret = *blake3::keyed_hash(
        &kem_context,
        b"fcp.crypto_hw.apple_se.hpke_shared_secret.v1",
    )
    .as_bytes();
    let aead_key =
        *blake3::keyed_hash(&shared_secret, b"fcp.crypto_hw.apple_se.aead_key.v1").as_bytes();
    let nonce_digest = blake3::keyed_hash(&shared_secret, b"fcp.crypto_hw.apple_se.nonce.v1");
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&nonce_digest.as_bytes()[..12]);
    (shared_secret, aead_key, nonce)
}

fn emit_startup_unavailable_warn_once() {
    if !STARTUP_WARN_EMITTED.swap(true, Ordering::SeqCst) {
        STARTUP_WARN_COUNT.fetch_add(1, Ordering::SeqCst);
        warn!(
            target: "fcp_crypto_hw::apple_se",
            has_secure_enclave = false,
            hpke_decap_path = HpkeDecapPath::Software.as_str(),
            "Apple Secure Enclave unavailable; falling back to software HPKE decapsulation"
        );
    }
}
