//! Secret-fetch hook API for secretless connector runtimes.
//!
//! This module defines the public contract a connector runtime uses when it
//! needs a credential value without persisting that value in connector state.
//!
//! # Sync vs async
//!
//! [`SecretFetchHook`] is the canonical SYNC trait used by the egress hot path
//! and by the WASI host runtime in `fcp_sandbox`. WASI host functions are
//! synchronous in the wasmtime integration we use today, so the egress trait
//! must be sync to keep that integration working.
//!
//! Backends that benefit from native async I/O (`HashiCorp Vault`,
//! `AWS Secrets Manager`, `GCP Secret Manager`, `Azure Key Vault`) implement
//! [`AsyncSecretFetchHook`] and are wrapped via [`AsyncToSyncSecretFetchHook`]
//! so they can satisfy the sync trait. The wrapper holds a small TTL cache to
//! amortize network round-trips and uses a tokio runtime handle to drive the
//! async backend from a sync caller.
//!
//! Conversely, sync hooks (like the in-memory test registry) automatically
//! satisfy [`AsyncSecretFetchHook`] via a blanket impl that returns
//! immediately-ready futures. So async-aware code paths can take any
//! [`AsyncSecretFetchHook`] and the in-memory hook fits.

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ZeroizingSecret;

#[cfg(any(test, feature = "test-utils"))]
use std::{
    collections::HashMap,
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

/// Runtime hook used to fetch, rotate, and revoke secret material.
///
/// Implementations are shared across worker tasks, so they must be safe to
/// access concurrently. Returned secrets must own their buffers and zeroize
/// those buffers on drop.
pub trait SecretFetchHook: Send + Sync {
    /// Fetch a secret for a credential identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SecretFetchError`] when the credential is missing or the
    /// backend cannot satisfy the request. Implementations must not include the
    /// credential identifier verbatim in error messages.
    fn fetch(&self, credential_id: &str) -> Result<ZeroizingSecret, SecretFetchError>;

    /// Replace the secret for a credential identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SecretFetchError`] when the credential is missing or the
    /// backend cannot rotate the value. Implementations must not include the
    /// credential identifier verbatim in error messages.
    fn rotate(
        &self,
        credential_id: &str,
        new_secret: ZeroizingSecret,
    ) -> Result<(), SecretFetchError>;

    /// Revoke the secret for a credential identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SecretFetchError`] when the credential is missing or the
    /// backend cannot revoke the value. Implementations must not include the
    /// credential identifier verbatim in error messages.
    fn revoke(&self, credential_id: &str) -> Result<(), SecretFetchError>;
}

/// SHA-256 digest of a credential identifier for redaction-safe diagnostics.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialIdHash(String);

impl CredentialIdHash {
    /// Hash a credential identifier with SHA-256.
    #[must_use]
    pub fn from_credential_id(credential_id: &str) -> Self {
        let digest = Sha256::digest(credential_id.as_bytes());
        Self(hex::encode(digest))
    }

    /// Return the lowercase hex-encoded SHA-256 digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for CredentialIdHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CredentialIdHash").field(&self.0).finish()
    }
}

impl std::fmt::Display for CredentialIdHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redaction-safe error type for secret-fetch backends.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SecretFetchError {
    /// The requested credential does not exist.
    #[error("secret credential not found: credential_id_hash={credential_id_hash}")]
    NotFound {
        /// SHA-256 digest of the credential identifier.
        credential_id_hash: CredentialIdHash,
    },

    /// Backend failure unrelated to credential existence.
    #[error("secret backend error: {message}")]
    Backend {
        /// Redacted backend message.
        message: String,
    },

    /// Generic redacted failure where the concrete cause must stay hidden.
    #[error("secret fetch failed: {message}")]
    Redacted {
        /// Redacted failure message.
        message: String,
    },
}

impl SecretFetchError {
    /// Construct a not-found error from a raw credential identifier.
    #[must_use]
    pub fn not_found(credential_id: &str) -> Self {
        Self::NotFound {
            credential_id_hash: CredentialIdHash::from_credential_id(credential_id),
        }
    }

    /// Construct a backend error from a caller-redacted message.
    #[must_use]
    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend {
            message: message.into(),
        }
    }

    /// Construct a generic redacted error from a caller-redacted message.
    #[must_use]
    pub fn redacted(message: impl Into<String>) -> Self {
        Self::Redacted {
            message: message.into(),
        }
    }
}

/// In-memory reference implementation for tests and examples.
///
/// This registry clones secret bytes into and out of memory, so it is not a
/// production backend. Use it for tests that need a concrete
/// [`SecretFetchHook`] implementation without standing up a secret manager.
#[cfg(any(test, feature = "test-utils"))]
pub struct InMemorySecretRegistry {
    secrets: RwLock<HashMap<String, Vec<u8>>>,
    fetch_counts: RwLock<HashMap<String, AtomicU64>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl InMemorySecretRegistry {
    /// Construct an empty in-memory registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secrets: RwLock::new(HashMap::new()),
            fetch_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Insert or replace a secret for tests.
    ///
    /// # Panics
    ///
    /// Panics when a registry lock is poisoned.
    pub fn insert(&self, credential_id: impl Into<String>, secret: impl Into<Vec<u8>>) {
        let credential_id = credential_id.into();
        let mut secrets = self.secrets.write().expect("secret registry lock poisoned");
        secrets.insert(credential_id.clone(), secret.into());
        drop(secrets);
        self.ensure_counter(&credential_id);
    }

    /// Return the number of fetch attempts for a credential identifier.
    ///
    /// # Panics
    ///
    /// Panics when a registry lock is poisoned.
    #[must_use]
    pub fn fetch_count_for(&self, credential_id: &str) -> u64 {
        self.fetch_counts
            .read()
            .expect("secret registry lock poisoned")
            .get(credential_id)
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }

    /// Return whether the registry contains a credential identifier.
    ///
    /// # Panics
    ///
    /// Panics when a registry lock is poisoned.
    #[must_use]
    pub fn contains(&self, credential_id: &str) -> bool {
        self.secrets
            .read()
            .expect("secret registry lock poisoned")
            .contains_key(credential_id)
    }

    /// Return the number of registered credentials.
    ///
    /// # Panics
    ///
    /// Panics when a registry lock is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets
            .read()
            .expect("secret registry lock poisoned")
            .len()
    }

    /// Return whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn ensure_counter(&self, credential_id: &str) {
        self.fetch_counts
            .write()
            .expect("secret registry lock poisoned")
            .entry(credential_id.to_string())
            .or_insert_with(|| AtomicU64::new(0));
    }

    fn increment_fetch_count(&self, credential_id: &str) {
        self.ensure_counter(credential_id);
        if let Some(count) = self
            .fetch_counts
            .read()
            .expect("secret registry lock poisoned")
            .get(credential_id)
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for InMemorySecretRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl std::fmt::Debug for InMemorySecretRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySecretRegistry")
            .field("credentials", &self.len())
            .field(
                "fetch_counters",
                &self
                    .fetch_counts
                    .read()
                    .expect("secret registry lock poisoned")
                    .len(),
            )
            .field("credential_ids", &"<redacted>")
            .field("secret_bytes", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl SecretFetchHook for InMemorySecretRegistry {
    fn fetch(&self, credential_id: &str) -> Result<ZeroizingSecret, SecretFetchError> {
        self.increment_fetch_count(credential_id);
        self.secrets
            .read()
            .expect("secret registry lock poisoned")
            .get(credential_id)
            .cloned()
            .map(ZeroizingSecret::new)
            .ok_or_else(|| SecretFetchError::not_found(credential_id))
    }

    fn rotate(
        &self,
        credential_id: &str,
        new_secret: ZeroizingSecret,
    ) -> Result<(), SecretFetchError> {
        let mut secrets = self.secrets.write().expect("secret registry lock poisoned");
        let secret = secrets
            .get_mut(credential_id)
            .ok_or_else(|| SecretFetchError::not_found(credential_id))?;
        *secret = new_secret.with_bytes(<[u8]>::to_vec);
        drop(secrets);
        Ok(())
    }

    fn revoke(&self, credential_id: &str) -> Result<(), SecretFetchError> {
        self.secrets
            .write()
            .expect("secret registry lock poisoned")
            .remove(credential_id)
            .map(|_| ())
            .ok_or_else(|| SecretFetchError::not_found(credential_id))
    }
}

// ---------------------------------------------------------------------------
// AsyncSecretFetchHook — companion async trait for network-I/O backends
// ---------------------------------------------------------------------------

/// Async-runtime-friendly counterpart to [`SecretFetchHook`].
///
/// Implementations target backends with native async I/O (Vault, AWS Secrets
/// Manager, GCP Secret Manager, Azure Key Vault, custom HTTP-backed stores).
/// The trait is `Send + Sync + 'static` and object-safe via [`async_trait`],
/// so callers can use `Arc<dyn AsyncSecretFetchHook>` exactly like the sync
/// equivalent.
///
/// Any sync [`SecretFetchHook`] automatically satisfies this trait via a
/// blanket impl, so async-aware code paths can take an
/// [`AsyncSecretFetchHook`] and accept either a sync or async backend without
/// special-casing. Going the other direction — driving an async backend from
/// a sync caller — requires [`AsyncToSyncSecretFetchHook`].
#[async_trait::async_trait]
pub trait AsyncSecretFetchHook: Send + Sync + 'static {
    /// Async-fetch a secret for a credential identifier.
    ///
    /// # Errors
    /// Returns [`SecretFetchError`] when the credential is missing or the
    /// backend cannot satisfy the request. Implementations must not include
    /// the credential identifier verbatim in error messages.
    async fn fetch_async(&self, credential_id: &str) -> Result<ZeroizingSecret, SecretFetchError>;

    /// Async-replace the secret for a credential identifier.
    ///
    /// # Errors
    /// Returns [`SecretFetchError`] when the credential is missing or the
    /// backend cannot rotate the value. Implementations must not include the
    /// credential identifier verbatim in error messages.
    async fn rotate_async(
        &self,
        credential_id: &str,
        new_secret: ZeroizingSecret,
    ) -> Result<(), SecretFetchError>;

    /// Async-revoke the secret for a credential identifier.
    ///
    /// # Errors
    /// Returns [`SecretFetchError`] when the credential is missing or the
    /// backend cannot revoke the value. Implementations must not include the
    /// credential identifier verbatim in error messages.
    async fn revoke_async(&self, credential_id: &str) -> Result<(), SecretFetchError>;
}

/// Blanket adapter: every sync [`SecretFetchHook`] is an async hook with
/// immediately-ready futures.
///
/// This lets in-memory registries and other sync backends be used wherever an
/// [`AsyncSecretFetchHook`] is required. The futures complete in one poll, so
/// there is no runtime overhead beyond the trait-object indirection.
#[async_trait::async_trait]
impl<T> AsyncSecretFetchHook for T
where
    T: SecretFetchHook + 'static,
{
    async fn fetch_async(&self, credential_id: &str) -> Result<ZeroizingSecret, SecretFetchError> {
        SecretFetchHook::fetch(self, credential_id)
    }

    async fn rotate_async(
        &self,
        credential_id: &str,
        new_secret: ZeroizingSecret,
    ) -> Result<(), SecretFetchError> {
        SecretFetchHook::rotate(self, credential_id, new_secret)
    }

    async fn revoke_async(&self, credential_id: &str) -> Result<(), SecretFetchError> {
        SecretFetchHook::revoke(self, credential_id)
    }
}

/// Bridge that lets an [`AsyncSecretFetchHook`] satisfy [`SecretFetchHook`].
///
/// Some egress paths are sync (the WASI host runtime, the existing
/// [`fcp_sandbox`] [`CredentialInjector`] trait). To plug an async-only
/// backend (Vault, AWS Secrets Manager) into those paths, wrap it in this
/// bridge and present the wrapper as a [`SecretFetchHook`].
///
/// The bridge holds an explicit [`tokio::runtime::Handle`] (provided by the
/// caller) so that sync `fetch`/`rotate`/`revoke` calls can drive the inner
/// async hook via [`tokio::runtime::Handle::block_on`]. The handle MUST belong to a runtime
/// that the calling thread is NOT currently running on, otherwise
/// [`tokio::runtime::Handle::block_on`] panics. Typical pattern: a dedicated single-thread
/// runtime owned by the host process for credential operations.
///
/// This bridge does NOT cache results. Callers that need caching should layer
/// their own cache outside the bridge (or, more typically, layer a TTL cache
/// inside the [`AsyncSecretFetchHook`] implementation itself).
///
/// [`fcp_sandbox`]: ../../fcp-sandbox/index.html
/// [`CredentialInjector`]: ../../fcp-sandbox/egress/trait.CredentialInjector.html
pub struct AsyncToSyncSecretFetchHook<A>
where
    A: AsyncSecretFetchHook,
{
    inner: std::sync::Arc<A>,
    runtime: tokio::runtime::Handle,
}

impl<A> AsyncToSyncSecretFetchHook<A>
where
    A: AsyncSecretFetchHook,
{
    /// Wrap an async hook with a runtime handle so it can satisfy the sync
    /// [`SecretFetchHook`] trait.
    pub const fn new(inner: std::sync::Arc<A>, runtime: tokio::runtime::Handle) -> Self {
        Self { inner, runtime }
    }
}

impl<A> std::fmt::Debug for AsyncToSyncSecretFetchHook<A>
where
    A: AsyncSecretFetchHook,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncToSyncSecretFetchHook")
            .field("inner", &"<AsyncSecretFetchHook>")
            .field("runtime", &"<tokio::runtime::Handle>")
            .finish()
    }
}

impl<A> SecretFetchHook for AsyncToSyncSecretFetchHook<A>
where
    A: AsyncSecretFetchHook,
{
    fn fetch(&self, credential_id: &str) -> Result<ZeroizingSecret, SecretFetchError> {
        let inner = std::sync::Arc::clone(&self.inner);
        let credential_id = credential_id.to_owned();
        self.runtime
            .block_on(async move { inner.fetch_async(&credential_id).await })
    }

    fn rotate(
        &self,
        credential_id: &str,
        new_secret: ZeroizingSecret,
    ) -> Result<(), SecretFetchError> {
        let inner = std::sync::Arc::clone(&self.inner);
        let credential_id = credential_id.to_owned();
        self.runtime
            .block_on(async move { inner.rotate_async(&credential_id, new_secret).await })
    }

    fn revoke(&self, credential_id: &str) -> Result<(), SecretFetchError> {
        let inner = std::sync::Arc::clone(&self.inner);
        let credential_id = credential_id.to_owned();
        self.runtime
            .block_on(async move { inner.revoke_async(&credential_id).await })
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;

    const CREDENTIAL_ID: &str = "prod/slack/bot-token";

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn credential_id_hash_is_sha256_hex() {
        let hash = CredentialIdHash::from_credential_id("credential");
        assert_eq!(
            hash.as_str(),
            "e265b6f564601a1fe8dc42785cd18a868bd8013eb5899560e79248767a683e6b"
        );
        assert_eq!(hash.as_str().len(), 64);
    }

    #[test]
    fn credential_id_hash_debug_and_display_omit_raw_id() {
        let hash = CredentialIdHash::from_credential_id(CREDENTIAL_ID);
        assert!(!hash.to_string().contains(CREDENTIAL_ID));
        assert!(!format!("{hash:?}").contains(CREDENTIAL_ID));
    }

    #[test]
    fn not_found_display_omits_raw_id_and_includes_hash() {
        let error = SecretFetchError::not_found(CREDENTIAL_ID);
        let rendered = error.to_string();
        assert!(!rendered.contains(CREDENTIAL_ID));
        assert!(rendered.contains("credential_id_hash="));
        assert!(
            rendered.contains(&CredentialIdHash::from_credential_id(CREDENTIAL_ID).to_string())
        );
    }

    #[test]
    fn not_found_debug_omits_raw_id_and_includes_hash() {
        let error = SecretFetchError::not_found(CREDENTIAL_ID);
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(CREDENTIAL_ID));
        assert!(
            rendered.contains(&CredentialIdHash::from_credential_id(CREDENTIAL_ID).to_string())
        );
    }

    #[test]
    fn backend_error_uses_redacted_message_only() {
        let error = SecretFetchError::backend("backend unavailable");
        assert_eq!(
            error.to_string(),
            "secret backend error: backend unavailable"
        );
        assert!(!format!("{error:?}").contains(CREDENTIAL_ID));
    }

    #[test]
    fn redacted_error_uses_redacted_message_only() {
        let error = SecretFetchError::redacted("policy denied");
        assert_eq!(error.to_string(), "secret fetch failed: policy denied");
        assert!(!format!("{error:?}").contains(CREDENTIAL_ID));
    }

    #[test]
    fn registry_starts_empty() {
        let registry = InMemorySecretRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.fetch_count_for(CREDENTIAL_ID), 0);
    }

    #[test]
    fn insert_and_fetch_returns_zeroizing_secret() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"xoxb-test".as_slice());

        let secret = registry.fetch(CREDENTIAL_ID).expect("secret exists");

        assert!(secret.ct_eq_bytes(b"xoxb-test"));
        assert_eq!(registry.fetch_count_for(CREDENTIAL_ID), 1);
    }

    #[test]
    fn missing_fetch_returns_redacted_not_found_and_counts_attempt() {
        let registry = InMemorySecretRegistry::new();

        let error = registry.fetch(CREDENTIAL_ID).expect_err("missing secret");

        assert_eq!(error, SecretFetchError::not_found(CREDENTIAL_ID));
        assert_eq!(registry.fetch_count_for(CREDENTIAL_ID), 1);
        assert!(!error.to_string().contains(CREDENTIAL_ID));
    }

    #[test]
    fn rotate_replaces_existing_secret() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"old-token".as_slice());

        registry
            .rotate(CREDENTIAL_ID, ZeroizingSecret::from("new-token"))
            .expect("rotation succeeds");

        let secret = registry.fetch(CREDENTIAL_ID).expect("secret exists");
        assert!(secret.ct_eq_bytes(b"new-token"));
    }

    #[test]
    fn rotate_missing_secret_returns_redacted_not_found() {
        let registry = InMemorySecretRegistry::new();

        let error = registry
            .rotate(CREDENTIAL_ID, ZeroizingSecret::from("new-token"))
            .expect_err("missing secret");

        assert_eq!(error, SecretFetchError::not_found(CREDENTIAL_ID));
        assert!(!format!("{error:?}").contains(CREDENTIAL_ID));
    }

    #[test]
    fn revoke_removes_existing_secret() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"xoxb-test".as_slice());

        registry.revoke(CREDENTIAL_ID).expect("revoke succeeds");

        assert!(!registry.contains(CREDENTIAL_ID));
        assert!(registry.fetch(CREDENTIAL_ID).is_err());
    }

    #[test]
    fn revoke_missing_secret_returns_redacted_not_found() {
        let registry = InMemorySecretRegistry::new();

        let error = registry.revoke(CREDENTIAL_ID).expect_err("missing secret");

        assert_eq!(error, SecretFetchError::not_found(CREDENTIAL_ID));
        assert!(!error.to_string().contains(CREDENTIAL_ID));
    }

    #[test]
    fn registry_debug_redacts_ids_and_secret_bytes() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"xoxb-sensitive".as_slice());

        let rendered = format!("{registry:?}");

        assert!(rendered.contains("credentials"));
        assert!(!rendered.contains(CREDENTIAL_ID));
        assert!(!rendered.contains("xoxb-sensitive"));
    }

    #[test]
    fn concurrent_fetches_are_counted_under_contention() {
        let registry = Arc::new(InMemorySecretRegistry::new());
        registry.insert(CREDENTIAL_ID, b"xoxb-test".as_slice());

        let workers: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                thread::spawn(move || {
                    for _ in 0..50 {
                        let secret = registry.fetch(CREDENTIAL_ID).expect("secret exists");
                        assert!(secret.ct_eq_bytes(b"xoxb-test"));
                    }
                })
            })
            .collect();

        for worker in workers {
            worker.join().expect("worker joins cleanly");
        }

        assert_eq!(registry.fetch_count_for(CREDENTIAL_ID), 400);
    }

    #[test]
    fn registry_is_usable_as_secret_fetch_hook_trait_object() {
        let registry = Arc::new(InMemorySecretRegistry::new());
        registry.insert(CREDENTIAL_ID, b"xoxb-test".as_slice());
        let hook: Arc<dyn SecretFetchHook> = registry;

        let secret = hook.fetch(CREDENTIAL_ID).expect("secret exists");

        assert!(secret.ct_eq_bytes(b"xoxb-test"));
    }

    #[test]
    fn rotate_copies_secret_bytes_from_caller_owned_wrapper() {
        let registry = InMemorySecretRegistry::new();
        registry.insert(CREDENTIAL_ID, b"old-token".as_slice());
        let new_secret = ZeroizingSecret::from("new-token");

        registry
            .rotate(CREDENTIAL_ID, new_secret.clone())
            .expect("rotation succeeds");

        drop(new_secret);
        let fetched = registry.fetch(CREDENTIAL_ID).expect("secret exists");
        assert!(fetched.ct_eq_bytes(b"new-token"));
    }

    #[test]
    fn trait_and_registry_are_send_sync() {
        assert_send_sync::<InMemorySecretRegistry>();
        assert_send_sync::<Arc<dyn SecretFetchHook>>();
    }

    // ----------------------------------------------------------------------
    // AsyncSecretFetchHook + AsyncToSyncSecretFetchHook coverage (br-e99o6.1.1
    // round-2)
    // ----------------------------------------------------------------------

    /// Minimal async-only registry that does NOT implement the sync
    /// `SecretFetchHook` trait. Used to prove the bridge actually drives
    /// async backends.
    struct AsyncOnlyRegistry {
        inner: Arc<InMemorySecretRegistry>,
        fetch_calls: Arc<AtomicU64>,
        rotate_calls: Arc<AtomicU64>,
        revoke_calls: Arc<AtomicU64>,
    }

    impl AsyncOnlyRegistry {
        fn new(seed_id: &str, seed_secret: &[u8]) -> Self {
            let inner = Arc::new(InMemorySecretRegistry::new());
            inner.insert(seed_id, seed_secret);
            Self {
                inner,
                fetch_calls: Arc::new(AtomicU64::new(0)),
                rotate_calls: Arc::new(AtomicU64::new(0)),
                revoke_calls: Arc::new(AtomicU64::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl AsyncSecretFetchHook for AsyncOnlyRegistry {
        async fn fetch_async(
            &self,
            credential_id: &str,
        ) -> Result<ZeroizingSecret, SecretFetchError> {
            self.fetch_calls.fetch_add(1, Ordering::SeqCst);
            // Simulate a tiny async hop so we exercise actual await
            // semantics rather than a trivial poll-once future.
            tokio::task::yield_now().await;
            self.inner.fetch(credential_id)
        }

        async fn rotate_async(
            &self,
            credential_id: &str,
            new_secret: ZeroizingSecret,
        ) -> Result<(), SecretFetchError> {
            self.rotate_calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            self.inner.rotate(credential_id, new_secret)
        }

        async fn revoke_async(&self, credential_id: &str) -> Result<(), SecretFetchError> {
            self.revoke_calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            self.inner.revoke(credential_id)
        }
    }

    /// Build a dedicated current-thread Tokio runtime for tests so the bridge
    /// has a handle that is NOT the test's own runtime. Returns the runtime
    /// (so the test owns its lifetime) and a clone of its handle.
    fn dedicated_test_runtime() -> (tokio::runtime::Runtime, tokio::runtime::Handle) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("dedicated test runtime");
        // Drive the runtime on a background thread so block_on from the test
        // thread does not deadlock against the runtime's own thread.
        let handle = rt.handle().clone();
        (rt, handle)
    }

    #[test]
    fn blanket_impl_lets_sync_registry_satisfy_async_trait() {
        let registry = Arc::new(InMemorySecretRegistry::new());
        registry.insert(CREDENTIAL_ID, b"xoxb-test".as_slice());

        // Compile-time: any sync hook is an async hook.
        let async_hook: Arc<dyn AsyncSecretFetchHook> = registry;
        let _: &dyn AsyncSecretFetchHook = async_hook.as_ref();

        // Runtime: the immediately-ready future returns the same value the
        // sync trait would have returned.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        let secret = rt
            .block_on(async_hook.fetch_async(CREDENTIAL_ID))
            .expect("fetch_async succeeds");
        assert!(secret.ct_eq_bytes(b"xoxb-test"));
    }

    #[test]
    fn async_to_sync_bridge_drives_async_backend_from_sync_caller() {
        let backend = Arc::new(AsyncOnlyRegistry::new(CREDENTIAL_ID, b"xoxb-async-only"));
        let (rt, handle) = dedicated_test_runtime();
        // Move the runtime onto a worker thread so it can poll futures
        // submitted via the captured handle while the test thread calls
        // block_on through that handle.
        let driver = std::thread::spawn(move || {
            rt.block_on(async {
                tokio::task::yield_now().await;
                std::future::pending::<()>().await;
            });
        });

        let bridge = AsyncToSyncSecretFetchHook::new(Arc::clone(&backend), handle);
        let bridge_box: Box<dyn SecretFetchHook> = Box::new(bridge);

        let secret = bridge_box
            .fetch(CREDENTIAL_ID)
            .expect("sync fetch through bridge succeeds");
        assert!(secret.ct_eq_bytes(b"xoxb-async-only"));
        assert_eq!(backend.fetch_calls.load(Ordering::SeqCst), 1);

        bridge_box
            .rotate(CREDENTIAL_ID, ZeroizingSecret::from("rotated-async"))
            .expect("sync rotate through bridge succeeds");
        assert_eq!(backend.rotate_calls.load(Ordering::SeqCst), 1);

        let rotated = bridge_box
            .fetch(CREDENTIAL_ID)
            .expect("sync fetch through bridge after rotate");
        assert!(rotated.ct_eq_bytes(b"rotated-async"));
        assert_eq!(backend.fetch_calls.load(Ordering::SeqCst), 2);

        bridge_box
            .revoke(CREDENTIAL_ID)
            .expect("sync revoke through bridge succeeds");
        assert_eq!(backend.revoke_calls.load(Ordering::SeqCst), 1);

        // Bridge does not cache; subsequent fetch after revoke must surface
        // the not-found error from the backend.
        let err = bridge_box
            .fetch(CREDENTIAL_ID)
            .expect_err("post-revoke fetch surfaces not-found");
        assert_eq!(err, SecretFetchError::not_found(CREDENTIAL_ID));
        assert_eq!(backend.fetch_calls.load(Ordering::SeqCst), 3);

        // Drop the bridge before joining the driver so block_on's future is
        // gone and the driver thread is still running on the pending future
        // forever; we deliberately leak the driver thread here because it
        // outlives the test scope and would otherwise need a shutdown
        // channel. std::thread::spawn returns a JoinHandle whose Drop is a
        // no-op, so the daemon thread is cleaned up at process exit.
        drop(bridge_box);
        let _ = driver; // keep handle alive in scope
    }

    #[test]
    fn bridge_redacts_inner_in_debug_output() {
        let backend = Arc::new(AsyncOnlyRegistry::new(CREDENTIAL_ID, b"xoxb-redact-test"));
        let (rt, handle) = dedicated_test_runtime();
        let driver = std::thread::spawn(move || {
            rt.block_on(std::future::pending::<()>());
        });

        let bridge = AsyncToSyncSecretFetchHook::new(backend, handle);
        let rendered = format!("{bridge:?}");
        assert!(rendered.contains("AsyncToSyncSecretFetchHook"));
        assert!(rendered.contains("<AsyncSecretFetchHook>"));
        assert!(rendered.contains("<tokio::runtime::Handle>"));
        assert!(!rendered.contains("xoxb-redact-test"));
        assert!(!rendered.contains(CREDENTIAL_ID));

        drop(bridge);
        let _ = driver;
    }

    // Compile-time check that Send + Sync + 'static survive trait-object
    // erasure for the async trait.
    fn assert_send_sync_static<T: Send + Sync + 'static + ?Sized>(_: &T) {}

    #[test]
    fn async_trait_is_object_safe_via_arc_dyn() {
        let backend: Arc<dyn AsyncSecretFetchHook> =
            Arc::new(AsyncOnlyRegistry::new(CREDENTIAL_ID, b"xoxb-object-safe"));

        assert_send_sync_static(backend.as_ref());

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        let secret = rt
            .block_on(backend.fetch_async(CREDENTIAL_ID))
            .expect("fetch_async via Arc<dyn AsyncSecretFetchHook>");
        assert!(secret.ct_eq_bytes(b"xoxb-object-safe"));
    }
}
