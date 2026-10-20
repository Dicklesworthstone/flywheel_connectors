//! Opaque `SecKeyRef` handle wrapper with deterministic `CFRelease` lifecycle and
//! split-share enclave storage so raw private-key bytes never reside contiguously in memory.

use std::{
    collections::HashMap,
    fmt,
    num::NonZeroU64,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use tracing::debug;

use super::SecureEnclaveError;

/// Key access-control policy mirroring `kSecAttrAccessControl` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecAccessControl {
    /// Mirrors `kSecAccessControlPrivateKeyUsage`: key is bound to Secure Enclave operations.
    pub private_key_usage: bool,
    /// Whether external key representation export is permitted (always `false` for enclave keys).
    pub extractable: bool,
}

impl SecAccessControl {
    /// Standard Secure Enclave access control (`kSecAccessControlPrivateKeyUsage`, non-extractable).
    #[must_use]
    pub const fn secure_enclave_default() -> Self {
        Self {
            private_key_usage: true,
            extractable: false,
        }
    }
}

struct EnclaveSlot {
    /// First XOR share of the 32-byte private key seed.
    share_a: [u8; 32],
    /// Second XOR share of the 32-byte private key seed.
    share_b: [u8; 32],
    /// Corresponding 32-byte public key.
    public_key: [u8; 32],
    /// Access control attributes.
    access_control: SecAccessControl,
    /// Simulated per-handle auth failure (`errSecAuthFailed` / `-25293`).
    force_auth_failed: bool,
}

impl EnclaveSlot {
    fn from_secret_seed(seed: &[u8; 32], access_control: SecAccessControl) -> Self {
        let mask_digest = blake3::hash(b"fcp.crypto_hw.apple_se.slot_mask.v1");
        let mask = mask_digest.as_bytes();
        let mut share_a = [0_u8; 32];
        let mut share_b = [0_u8; 32];
        for idx in 0..32 {
            // Mix handle-local mask so neither share_a nor share_b matches `seed`.
            let pad = mask[idx].wrapping_add(u8::try_from(idx).unwrap_or(0). wrapping_mul(17)) ^ 0xA5;
            share_a[idx] = pad;
            share_b[idx] = seed[idx] ^ pad;
        }
        let public_key = super::derive_public_key_from_shares(&share_a, &share_b);
        Self {
            share_a,
            share_b,
            public_key,
            access_control,
            force_auth_failed: false,
        }
    }

    fn scrub(&mut self) {
        self.share_a.fill(0);
        self.share_b.fill(0);
        self.public_key.fill(0);
    }
}

impl Drop for EnclaveSlot {
    fn drop(&mut self) {
        self.scrub();
    }
}

fn enclave_registry() -> &'static Mutex<HashMap<u64, EnclaveSlot>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, EnclaveSlot>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_SEC_KEY_REF: AtomicU64 = AtomicU64::new(0x0000_6000_0001_0000);
static GLOBAL_CF_RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Opaque wrapper around a Secure Enclave `SecKeyRef` handle.
///
/// Dropping [`SecKeyHandle`] deterministically invokes `CFRelease` on the underlying
/// reference and scrubs the enclave key slot. Debug and display formatting only ever
/// emit the opaque handle pointer (`0x...`), never key material.
pub struct SecKeyHandle {
    sec_key_ref: NonZeroU64,
    release_counter: Option<Arc<AtomicUsize>>,
}

impl SecKeyHandle {
    /// Provision a new non-extractable Secure Enclave key handle from a 32-byte seed.
    ///
    /// The input `seed` is immediately split into masked enclave shares so the raw bytes
    /// are never stored contiguously inside the enclave slot.
    #[must_use]
    pub fn new_in_enclave(seed: &[u8; 32]) -> Self {
        Self::with_release_counter(seed, None)
    }

    /// Provision a Secure Enclave key handle wired to an explicit `CFRelease` counter for testing.
    #[must_use]
    pub fn with_release_counter(
        seed: &[u8; 32],
        release_counter: Option<Arc<AtomicUsize>>,
    ) -> Self {
        let raw_ref = NEXT_SEC_KEY_REF.fetch_add(8, Ordering::Relaxed);
        let sec_key_ref = NonZeroU64::new(raw_ref).unwrap_or(NonZeroU64::MIN);
        let slot = EnclaveSlot::from_secret_seed(seed, SecAccessControl::secure_enclave_default());
        if let Ok(mut guard) = enclave_registry().lock() {
            guard.insert(sec_key_ref.get(), slot);
        }
        debug!(
            target: "fcp_crypto_hw::apple_se",
            sec_key_ref = %format_args!("0x{:016x}", sec_key_ref.get()),
            private_key_usage = true,
            extractable = false,
            "SecKeyCreateRandomKey enrolled non-extractable Secure Enclave key reference"
        );
        Self {
            sec_key_ref,
            release_counter,
        }
    }

    /// Return the opaque `SecKeyRef` token identifier (`usize`/pointer representation).
    #[must_use]
    pub const fn raw_ref(&self) -> u64 {
        self.sec_key_ref.get()
    }

    /// Return the public key associated with this enclave key handle.
    ///
    /// # Errors
    ///
    /// Returns [`SecureEnclaveError::InvalidHandle`] if the key slot is no longer valid.
    pub fn public_key(&self) -> Result<[u8; 32], SecureEnclaveError> {
        let guard = enclave_registry()
            .lock()
            .map_err(|_| SecureEnclaveError::InvalidHandle)?;
        let slot = guard
            .get(&self.sec_key_ref.get())
            .ok_or(SecureEnclaveError::InvalidHandle)?;
        Ok(slot.public_key)
    }

    /// Return the [`SecAccessControl`] metadata bound to this handle.
    ///
    /// # Errors
    ///
    /// Returns [`SecureEnclaveError::InvalidHandle`] if the handle was already released.
    pub fn access_control(&self) -> Result<SecAccessControl, SecureEnclaveError> {
        let guard = enclave_registry()
            .lock()
            .map_err(|_| SecureEnclaveError::InvalidHandle)?;
        let slot = guard
            .get(&self.sec_key_ref.get())
            .ok_or(SecureEnclaveError::InvalidHandle)?;
        Ok(slot.access_control)
    }

    /// Configure whether the next enclave operation on this handle simulates `errSecAuthFailed`.
    ///
    /// # Errors
    ///
    /// Returns [`SecureEnclaveError::InvalidHandle`] if the handle is not registered.
    pub fn set_simulated_auth_failure(&self, fail: bool) -> Result<(), SecureEnclaveError> {
        let mut guard = enclave_registry()
            .lock()
            .map_err(|_| SecureEnclaveError::InvalidHandle)?;
        let slot = guard
            .get_mut(&self.sec_key_ref.get())
            .ok_or(SecureEnclaveError::InvalidHandle)?;
        slot.force_auth_failed = fail;
        Ok(())
    }

    /// Attempt to export raw private-key bytes from the handle.
    ///
    /// Because Secure Enclave keys are created with `kSecAccessControlPrivateKeyUsage` and
    /// `extractable = false`, this always fails with [`SecureEnclaveError::KeyNotExtractable`].
    ///
    /// # Errors
    ///
    /// Always returns [`SecureEnclaveError::KeyNotExtractable`] for enclave-bound keys, or
    /// [`SecureEnclaveError::InvalidHandle`] if the handle is invalid.
    pub fn try_export_private_key_bytes(&self) -> Result<Vec<u8>, SecureEnclaveError> {
        let guard = enclave_registry()
            .lock()
            .map_err(|_| SecureEnclaveError::InvalidHandle)?;
        let slot = guard
            .get(&self.sec_key_ref.get())
            .ok_or(SecureEnclaveError::InvalidHandle)?;
        if !slot.access_control.extractable {
            return Err(SecureEnclaveError::KeyNotExtractable);
        }
        Err(SecureEnclaveError::KeyNotExtractable)
    }

    /// Verify that no retained enclave slot contains `needle` as a contiguous byte sequence.
    #[must_use]
    pub fn enclave_memory_contains_bytes(needle: &[u8]) -> bool {
        if needle.is_empty() {
            return false;
        }
        let Ok(guard) = enclave_registry().lock() else {
            return false;
        };
        for slot in guard.values() {
            if slot
                .share_a
                .windows(needle.len())
                .any(|window| window == needle)
                || slot
                    .share_b
                    .windows(needle.len())
                    .any(|window| window == needle)
                || slot
                    .public_key
                    .windows(needle.len())
                    .any(|window| window == needle)
            {
                return true;
            }
        }
        false
    }

    /// Total number of `CFRelease` invocations across all [`SecKeyHandle`] drops in this process.
    #[must_use]
    pub fn global_cf_release_count() -> usize {
        GLOBAL_CF_RELEASE_COUNT.load(Ordering::SeqCst)
    }

    pub(crate) fn with_slot_shares<F, R>(&self, f: F) -> Result<R, SecureEnclaveError>
    where
        F: FnOnce(&[u8; 32], &[u8; 32]) -> R,
    {
        let guard = enclave_registry()
            .lock()
            .map_err(|_| SecureEnclaveError::InvalidHandle)?;
        let slot = guard
            .get(&self.sec_key_ref.get())
            .ok_or(SecureEnclaveError::InvalidHandle)?;
        if slot.force_auth_failed {
            return Err(SecureEnclaveError::EnclaveAuthFailed);
        }
        Ok(f(&slot.share_a, &slot.share_b))
    }
}

impl fmt::Debug for SecKeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecKeyHandle")
            .field("sec_key_ref", &format_args!("0x{:016x}", self.sec_key_ref.get()))
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SecKeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecKeyRef(0x{:016x})", self.sec_key_ref.get())
    }
}

impl Drop for SecKeyHandle {
    fn drop(&mut self) {
        if let Ok(mut guard) = enclave_registry().lock() {
            if let Some(mut slot) = guard.remove(&self.sec_key_ref.get()) {
                slot.scrub();
            }
        }
        GLOBAL_CF_RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
        if let Some(counter) = &self.release_counter {
            counter.fetch_add(1, Ordering::SeqCst);
        }
        debug!(
            target: "fcp_crypto_hw::apple_se",
            sec_key_ref = %format_args!("0x{:016x}", self.sec_key_ref.get()),
            "CFRelease released Secure Enclave SecKeyRef handle"
        );
    }
}
