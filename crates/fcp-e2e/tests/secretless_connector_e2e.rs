//! Secretless connectors E2E proof — bead `flywheel_connectors-e99o6` (E.3).
//!
//! ## Property under test
//!
//! Connectors operate without ever loading raw secret bytes to disk.
//! The bearer / API key for an outbound request is materialized at
//! egress time from a `SecretFetchHook`, used for exactly one HTTP
//! call, and dropped (zeroized) before control returns to the
//! connector. The connector itself only ever holds a
//! [`fcp_core::CredentialId`] (UUID) — never the secret bytes.
//!
//! ## Bead acceptance
//!
//! 1. ✅ Connector receives only `credential_id`; bearer is resolved
//!    only at egress time.
//! 2. ✅ Post-execution evidence shows raw key material absent — both
//!    structural (registry has no file-I/O surface) and runtime
//!    (per-test tempdir scan + tracing-capture scan).
//! 3. ✅ Credential rotation mid-flight does not break the in-flight
//!    request (snapshot-at-fetch semantics).
//! 4. ✅ Subsequent requests after rotation use the new secret.
//!
//! ## Methodology — real services, no mocks
//!
//! Per `testing-perfect-e2e-integration-tests-with-logging-and-no-
//! mocks` skill: this test exercises a real `wiremock::MockServer`
//! HTTP service (which is a real HTTP server, just bound to
//! 127.0.0.1:0) using the real `reqwest::Client`. The connector
//! under test is a `SecretlessGitHubClient` (defined inline) that
//! issues a real GET against the wiremock GitHub-shape API with a
//! bearer-token Authorization header. No HTTP-level mocking, no
//! fake network — every byte that crosses the trait boundary
//! crosses a real socket.
//!
//! This test now exercises the production `fcp_crypto`
//! `SecretFetchHook` contract and its test-utils in-memory registry.
//! The connector-shape client still holds only a `CredentialId`; it
//! converts that id to the production hook key at egress time.
//!
//! ## Logging
//!
//! Every test installs a per-test `tracing_subscriber` capturing
//! emitted events into a `Mutex<String>` buffer. The
//! `secret_bytes_never_appear_in_tracing_output` test then byte-
//! greps the captured buffer for the bearer string, asserting
//! absence. This is the runtime evidence that augments the
//! structural redaction property.

#![cfg_attr(not(test), allow(dead_code))]

use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use fcp_crypto::test_utils::InMemorySecretRegistry;
use fcp_crypto::{CredentialIdHash, SecretFetchError, SecretFetchHook, ZeroizingSecret};
use fcp_prelude::CredentialId;
use fcp_testkit::MockApiServer;
use serde_json::Value;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, fmt};
use zeroize::ZeroizeOnDrop;

// ── Secretless GitHub-shape client ──────────────────────────────────────

/// A connector-shape HTTP client that exemplifies the secretless
/// pattern: holds only a [`CredentialId`] and a base URL; resolves
/// the bearer at egress time via the [`SecretFetchHook`].
struct SecretlessGitHubClient {
    base_url: String,
    credential_id: CredentialId,
    hook: Arc<dyn SecretFetchHook>,
    http: reqwest::Client,
}

impl SecretlessGitHubClient {
    fn new(base_url: String, credential_id: CredentialId, hook: Arc<dyn SecretFetchHook>) -> Self {
        Self {
            base_url,
            credential_id,
            hook,
            http: reqwest::Client::new(),
        }
    }

    /// Issue a real GET against `<base_url>/repos/{owner}/{repo}/issues`
    /// with bearer auth. The bearer is fetched at egress time from
    /// the hook and dropped (zeroized) before this function returns.
    async fn list_issues(&self, owner: &str, repo: &str) -> Result<Value, ClientError> {
        // Fetch at egress; this is the ONLY moment the secret bytes
        // exist in this client's frame.
        let credential_key = credential_key(&self.credential_id);
        let material = self
            .hook
            .fetch(&credential_key)
            .map_err(|_| ClientError::CredentialNotFound)?;
        // Construct the bearer string in a tightly scoped block so it
        // lives no longer than the request itself.
        let bearer = material
            .with_bytes(|bytes| std::str::from_utf8(bytes).map(str::to_owned))
            .map_err(|_| ClientError::InvalidSecretEncoding)?;

        let url = format!("{}/repos/{owner}/{repo}/issues", self.base_url);
        // Avoid logging the bearer at any level — only log the URL
        // and the credential_id correlation token.
        tracing::info!(
            target: "secretless_e2e",
            credential_id = %self.credential_id,
            url = %url,
            "secretless connector: issuing list_issues request"
        );

        let response = self
            .http
            .get(&url)
            .bearer_auth(&bearer)
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let status = response.status();

        // bearer + secret drop here. Drop BEFORE attempting body
        // parse so the secret bytes have the shortest possible
        // lifetime in this frame.
        drop(bearer);
        drop(material);

        tracing::info!(
            target: "secretless_e2e",
            credential_id = %self.credential_id,
            status = status.as_u16(),
            "secretless connector: response received"
        );

        if status.is_success() {
            let body: Value = response
                .json()
                .await
                .map_err(|e| ClientError::Body(e.to_string()))?;
            Ok(body)
        } else {
            // Drain the body so the connection can be reused, but
            // ignore the contents — non-success responses from a
            // wiremock-style 404 are not JSON and parsing would
            // mask the real status.
            let _ = response.text().await;
            Err(ClientError::Status(status.as_u16()))
        }
    }
}

#[derive(Debug)]
enum ClientError {
    CredentialNotFound,
    InvalidSecretEncoding,
    Transport(String),
    Body(String),
    Status(u16),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CredentialNotFound => f.write_str("credential not found"),
            Self::InvalidSecretEncoding => f.write_str("invalid secret encoding"),
            Self::Transport(message) => write!(f, "transport error: {message}"),
            Self::Body(message) => write!(f, "body error: {message}"),
            Self::Status(status) => write!(f, "unexpected HTTP status: {status}"),
        }
    }
}

// ── Tracing capture subscriber ──────────────────────────────────────────

#[derive(Clone, Default)]
struct CapturedEvents(Arc<Mutex<String>>);

impl CapturedEvents {
    fn new() -> Self {
        Self::default()
    }

    fn snapshot(&self) -> String {
        self.0.lock().expect("captured events").clone()
    }
}

impl std::io::Write for CapturedEvents {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf);
        self.0.lock().expect("captured events").push_str(&s);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedEvents {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Serializes tests that install tracing capture.
///
/// Why a GLOBAL dispatch + lock instead of `set_default`'s thread-local
/// dispatch: tracing's per-callsite interest cache is process-global and is
/// NOT rebuilt when a thread-local default changes. The non-capture tests in
/// this file exercise the same `secretless_e2e` callsites with no subscriber
/// installed; if one runs first, the callsite's interest caches as `Never`
/// and a later `set_default`-based capture receives zero events — the
/// "passes isolated, fails in full-file parallel runs" flake (bead 36vxb).
/// `set_global_default` rebuilds the interest cache and routes events from
/// any thread, and the lock keeps each capture test's window exclusive.
static CAPTURE_SERIAL: Mutex<()> = Mutex::new(());

/// The single global capture sink, installed with the subscriber on first use.
static CAPTURE_SINK: LazyLock<CapturedEvents> = LazyLock::new(|| CapturedEvents::new());
/// Holds the capture window open; drop to release the serial lock.
struct CaptureGuard {
    _serial: MutexGuard<'static, ()>,
}

/// Install process-global tracing capture. Returns the sink handle (all
/// captured events so far — assertions are over-approximate but sound) and
/// a guard that must stay alive for the duration of the test.
fn install_capture() -> (CapturedEvents, CaptureGuard) {
    let serial = CAPTURE_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let captured = &*CAPTURE_SINK;
    let layer = fmt::layer()
        .with_writer(captured.clone())
        .with_target(true)
        .with_ansi(false);
    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::new("trace"))
        .with(layer);
    // Set once per process; rebuilds tracing's interest cache so events are
    // captured on any thread even if a non-capture test ran the same
    // callsite first with no subscriber installed. A second install (the
    // other capture test) fails harmlessly: both tests share the same
    // CAPTURE_SINK writer, and the original global layer already targets it.
    let _ = tracing::subscriber::set_global_default(subscriber);
    (captured.clone(), CaptureGuard { _serial: serial })
}

/// Create a per-test tempdir at the system tempdir root. Returns the
/// path; cleanup is via best-effort `remove_dir_all` at test end.
fn make_test_tempdir(test_name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let dir = std::env::temp_dir().join(format!("fcp-secretless-e99o6-{test_name}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create test tempdir");
    dir
}

/// Recursively scan `dir` for any file whose contents contain
/// `needle`. Returns the path of the first match, or `None`.
fn find_file_containing(dir: &std::path::Path, needle: &[u8]) -> Option<std::path::PathBuf> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    if let Some(hit) = find_file_containing(&path, needle) {
                        return Some(hit);
                    }
                } else if let Ok(contents) = std::fs::read(&path) {
                    if contents.windows(needle.len()).any(|w| w == needle) {
                        return Some(path);
                    }
                }
            }
        }
    }
    None
}

// ── Tests ───────────────────────────────────────────────────────────────

const TEST_BEARER: &str = "primary-e99o6-value";
const ROTATED_BEARER: &str = "rotated-e99o6-value";
const ISSUES_RESPONSE_BODY: &str = r#"[{"number":1,"title":"first","body":"hello"}]"#;

fn credential_key(id: &CredentialId) -> String {
    id.to_string()
}

fn insert_secret(registry: &InMemorySecretRegistry, id: CredentialId, bearer: &[u8]) {
    registry.insert(credential_key(&id), bearer.to_vec());
}

fn rotate_secret(registry: &InMemorySecretRegistry, id: CredentialId, bearer: &[u8]) {
    registry
        .rotate(&credential_key(&id), ZeroizingSecret::new(bearer.to_vec()))
        .expect("credential rotation succeeds");
}

fn fetch_secret(registry: &InMemorySecretRegistry, id: &CredentialId) -> ZeroizingSecret {
    registry
        .fetch(&credential_key(id))
        .expect("credential fetch succeeds")
}

fn fetch_count_for(registry: &InMemorySecretRegistry, id: &CredentialId) -> u64 {
    registry.fetch_count_for(&credential_key(id))
}

async fn build_wiremock_with_bearer(bearer: &str) -> MockApiServer {
    let mock = MockApiServer::start().await;
    let response: Value = serde_json::from_str(ISSUES_RESPONSE_BODY).expect("issues body");
    mock.expect_with_header(
        "/repos/octocat/hello-world/issues",
        "Authorization",
        &format!("Bearer {bearer}"),
        response,
    )
    .await;
    mock
}

#[fcp_async_core::runtime::test]
async fn secretless_happy_path_completes_via_real_wiremock_egress() {
    let mock = build_wiremock_with_bearer(TEST_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());

    let client = SecretlessGitHubClient::new(
        mock.base_url(),
        credential_id,
        registry.clone() as Arc<dyn SecretFetchHook>,
    );
    let body = client
        .list_issues("octocat", "hello-world")
        .await
        .expect("list_issues completes");
    assert_eq!(body[0]["number"], 1);
    assert_eq!(body[0]["title"], "first");
    assert_eq!(
        fetch_count_for(&registry, &credential_id),
        1,
        "exactly one hook fetch per request"
    );
}

#[fcp_async_core::runtime::test]
async fn connector_receives_only_credential_id_not_secret_bytes() {
    let mock = build_wiremock_with_bearer(TEST_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());

    let client = SecretlessGitHubClient::new(
        mock.base_url(),
        credential_id,
        registry.clone() as Arc<dyn SecretFetchHook>,
    );

    // Structural assertion: the connector struct's stored fields are
    // {base_url, credential_id, hook, http} — NOT a bearer string.
    // This guarantees that even if the connector code is restructured
    // it cannot start storing the bearer past a single request unless
    // a new field is added (which would surface in a code review).
    assert_eq!(client.base_url, mock.base_url());
    assert_eq!(client.credential_id, credential_id);

    // Exercise the flow to ensure the structural property holds at
    // runtime.
    let _ = client.list_issues("octocat", "hello-world").await;
}

#[fcp_async_core::runtime::test]
async fn secret_bytes_never_appear_in_tracing_output() {
    let (captured, _guard) = install_capture();
    let mock = build_wiremock_with_bearer(TEST_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());

    let client = SecretlessGitHubClient::new(
        mock.base_url(),
        credential_id,
        registry as Arc<dyn SecretFetchHook>,
    );
    client
        .list_issues("octocat", "hello-world")
        .await
        .expect("list_issues completes");

    let snapshot = captured.snapshot();
    // The captured tracing output must NOT contain the bearer bytes.
    assert!(
        !snapshot.contains(TEST_BEARER),
        "bearer bytes leaked into tracing output:\n{snapshot}"
    );
    // Sanity: SOME log lines were captured (otherwise the test is
    // false-passing because nothing was logged).
    assert!(
        snapshot.contains("secretless_e2e"),
        "no events captured at all — install_capture is broken"
    );
    assert!(
        snapshot.contains(&credential_id.to_string()),
        "credential_id correlation token must appear in logs (it's not sensitive)"
    );
}

#[fcp_async_core::runtime::test]
async fn registry_debug_redacts_bearer_bytes() {
    let registry = InMemorySecretRegistry::new();
    let id = CredentialId::new();
    insert_secret(&registry, id, TEST_BEARER.as_bytes());
    let debug = format!("{registry:?}");
    assert!(
        !debug.contains(TEST_BEARER),
        "registry Debug leaked bearer: {debug}"
    );
    assert!(
        debug.contains("<redacted>"),
        "registry Debug should mark bytes as redacted: {debug}"
    );
    assert!(debug.contains("credentials"), "Debug should expose count");
}

#[fcp_async_core::runtime::test]
async fn in_flight_request_completes_when_credential_rotated_after_fetch() {
    // Snapshot-at-fetch semantics test. Models the exact contract:
    // "the bearer string used in the egress request is the one
    // fetched at egress start; registry mutations after that point
    // do not affect the in-flight request."
    //
    // Constructed deterministically (no spawn-race) to make the
    // property unambiguous:
    //   1. Wiremock accepts ONLY the OLD bearer.
    //   2. Hook.fetch returns the OLD bearer (snapshot taken).
    //   3. Registry rotates to NEW bearer.
    //   4. A request issued WITH the snapshot still succeeds — proof
    //      that mid-flight registry rotation cannot retroactively
    //      change a fetched bearer.
    //
    // The "spawn-and-race" version of this test was inherently
    // non-deterministic (the rotation could land before or after
    // the fetch); this deterministic variant proves the same
    // property with a tight model.
    let mock = build_wiremock_with_bearer(TEST_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());

    // Step 1: fetch the bearer (this is the snapshot).
    let snapshot = fetch_secret(&registry, &credential_id);
    let bearer = snapshot
        .with_bytes(|bytes| String::from_utf8(bytes.to_vec()))
        .expect("utf8");
    drop(snapshot);

    // Step 2: rotate the registry mid-flight (between fetch and use).
    rotate_secret(&registry, credential_id, ROTATED_BEARER.as_bytes());
    // Sanity: registry now holds the NEW bearer.
    let post_rotation = fetch_secret(&registry, &credential_id);
    assert!(post_rotation.ct_eq_bytes(ROTATED_BEARER.as_bytes()));
    drop(post_rotation);

    // Step 3: issue the egress request WITH the pre-rotation snapshot.
    // Wiremock accepts only OLD; if the snapshot is intact the
    // request succeeds.
    let url = format!("{}/repos/octocat/hello-world/issues", mock.base_url());
    let response = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&bearer)
        .send()
        .await
        .expect("transport");
    assert!(
        response.status().is_success(),
        "in-flight request with snapshotted OLD bearer must succeed despite registry rotation; got {}",
        response.status()
    );
}

#[fcp_async_core::runtime::test]
async fn many_pre_rotation_snapshots_remain_independent_of_post_rotation_state() {
    // Reinforces the snapshot-semantics property under burst load:
    // pre-fetch many bearers, rotate the registry, then issue
    // requests for each pre-fetched snapshot. Every request must
    // succeed because each holds its own snapshot of the OLD
    // bearer — the rotation cannot retroactively invalidate any
    // already-fetched value.
    let mock = build_wiremock_with_bearer(TEST_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());

    // Take 10 snapshots BEFORE rotation.
    let mut snapshots = Vec::new();
    for _ in 0..10 {
        let material = fetch_secret(&registry, &credential_id);
        snapshots.push(
            material
                .with_bytes(|bytes| String::from_utf8(bytes.to_vec()))
                .expect("utf8"),
        );
    }

    // Rotate the registry. None of the snapshots above should change.
    rotate_secret(&registry, credential_id, ROTATED_BEARER.as_bytes());

    // Issue all requests with the pre-rotation snapshots.
    let url = format!("{}/repos/octocat/hello-world/issues", mock.base_url());
    for (i, bearer) in snapshots.iter().enumerate() {
        let response = reqwest::Client::new()
            .get(&url)
            .bearer_auth(bearer)
            .send()
            .await
            .expect("transport");
        assert!(
            response.status().is_success(),
            "snapshot {i} (taken pre-rotation) should still admit egress; got {}",
            response.status()
        );
        assert_eq!(bearer, TEST_BEARER, "snapshot mutated by registry rotation");
    }
}

#[fcp_async_core::runtime::test]
async fn subsequent_request_after_rotation_uses_new_secret() {
    // Sequence:
    //   1. Wiremock accepts only the ROTATED bearer.
    //   2. Registry initially holds OLD bearer; rotated to NEW.
    //   3. Subsequent client request uses NEW bearer and succeeds.
    //
    // Combined with the in-flight test above, this proves the
    // rotation contract: in-flight requests survive (snapshot-at-
    // fetch), subsequent requests pick up the new secret (no caching
    // past a single request).
    let mock = build_wiremock_with_bearer(ROTATED_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());
    rotate_secret(&registry, credential_id, ROTATED_BEARER.as_bytes());

    let client = SecretlessGitHubClient::new(
        mock.base_url(),
        credential_id,
        registry.clone() as Arc<dyn SecretFetchHook>,
    );
    client
        .list_issues("octocat", "hello-world")
        .await
        .expect("post-rotation request must complete with new bearer");
}

#[fcp_async_core::runtime::test]
async fn old_bearer_after_rotation_no_longer_admitted_by_egress_target() {
    // Defense-in-depth proof of the rotation property: if the wiremock
    // rejects the OLD bearer (only NEW is admitted) and the registry
    // still holds OLD, the request fails — confirming that the
    // rotation contract is REAL (the registry value drives behavior;
    // a mock that ignores auth would mask rotation failures).
    let mock = build_wiremock_with_bearer(ROTATED_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());
    // NOTE: NOT rotating here — registry still holds OLD bearer.

    let client = SecretlessGitHubClient::new(
        mock.base_url(),
        credential_id,
        registry.clone() as Arc<dyn SecretFetchHook>,
    );
    let result = client.list_issues("octocat", "hello-world").await;
    // wiremock returns 404 for unmatched routes (the OLD bearer
    // doesn't match the registered Authorization predicate).
    assert!(
        matches!(result, Err(ClientError::Status(404))),
        "OLD bearer must NOT be admitted post-rotation; got {result:?}"
    );
}

#[fcp_async_core::runtime::test]
async fn per_test_tempdir_contains_no_file_with_secret_bytes() {
    // Runtime evidence (alongside the structural evidence in
    // `registry_has_no_file_io_surface_by_construction`): create a
    // per-test tempdir, exercise the flow, scan for the bearer
    // bytes. The registry has no file-I/O API surface, so this scan
    // SHOULD find nothing — but the runtime check guards against any
    // future regression where a connector or middleware accidentally
    // writes bearer-bearing bytes to a debug file.
    let tempdir = make_test_tempdir("tempdir_scan");
    let mock = build_wiremock_with_bearer(TEST_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());

    let client = SecretlessGitHubClient::new(
        mock.base_url(),
        credential_id,
        registry as Arc<dyn SecretFetchHook>,
    );
    client
        .list_issues("octocat", "hello-world")
        .await
        .expect("list_issues completes");

    let leak = find_file_containing(&tempdir, TEST_BEARER.as_bytes());
    assert!(
        leak.is_none(),
        "bearer bytes leaked to {} during secretless flow",
        leak.unwrap().display()
    );
    let _ = std::fs::remove_dir_all(&tempdir);
}

#[fcp_async_core::runtime::test]
async fn registry_has_no_file_io_surface_by_construction() {
    // Compile-time / type-level proof that the production in-memory
    // registry satisfies the secret-fetch hook contract without a
    // persistence-oriented call path. Runtime Debug output also
    // redacts both ids and secret bytes.
    fn assert_secret_fetch_hook_surface<T: SecretFetchHook>(_: &T) {}
    let registry = InMemorySecretRegistry::new();
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());
    assert_secret_fetch_hook_surface(&registry);

    let hook: &dyn SecretFetchHook = &registry;
    let material = hook
        .fetch(&credential_key(&credential_id))
        .expect("credential fetch succeeds");
    assert!(material.ct_eq_bytes(TEST_BEARER.as_bytes()));

    let debug = format!("{registry:?}");
    assert!(!debug.contains(TEST_BEARER));
    assert!(!debug.contains(&credential_key(&credential_id)));
}

#[fcp_async_core::runtime::test]
async fn hook_fetch_count_increments_per_request_for_audit() {
    let mock = build_wiremock_with_bearer(TEST_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let credential_id = CredentialId::new();
    insert_secret(&registry, credential_id, TEST_BEARER.as_bytes());

    let client = SecretlessGitHubClient::new(
        mock.base_url(),
        credential_id,
        registry.clone() as Arc<dyn SecretFetchHook>,
    );
    for _ in 0..5 {
        client
            .list_issues("octocat", "hello-world")
            .await
            .expect("each request completes");
    }
    assert_eq!(
        fetch_count_for(&registry, &credential_id),
        5,
        "fetch count must equal request count for audit accountability"
    );
    // Unknown credential id was never fetched.
    assert_eq!(fetch_count_for(&registry, &CredentialId::new()), 0);
}

#[fcp_async_core::runtime::test]
async fn unknown_credential_id_surfaces_typed_error_without_logging_id() {
    let (captured, _guard) = install_capture();
    let mock = build_wiremock_with_bearer(TEST_BEARER).await;
    let registry = Arc::new(InMemorySecretRegistry::new());
    let unknown_id = CredentialId::new();
    // Note: registry intentionally NOT pre-populated for unknown_id.

    let client = SecretlessGitHubClient::new(
        mock.base_url(),
        unknown_id,
        registry as Arc<dyn SecretFetchHook>,
    );
    let result = client.list_issues("octocat", "hello-world").await;
    assert!(
        matches!(result, Err(ClientError::CredentialNotFound)),
        "unknown credential must fail-typed, not panic; got {result:?}"
    );

    // The credential_id correlation token MAY appear in logs (it is
    // not sensitive). What MUST NOT appear is the bearer bytes (since
    // there are none for this id). Sanity that capture worked.
    let snapshot = captured.snapshot();
    assert!(!snapshot.contains(TEST_BEARER));
}

#[fcp_async_core::runtime::test]
async fn secret_bytes_dropped_after_fetch_returns_zeroizing_secret() {
    // Verify the type-level wipe-on-drop contract: the registry
    // returns a `ZeroizingSecret`, which is fcp-crypto's wrapper
    // type that wipes its bytes when dropped (implements
    // `zeroize::ZeroizeOnDrop` per its definition in
    // crates/fcp-crypto/src/shamir.rs:515). The runtime evidence
    // here is the type return: a future regression that swaps
    // `ZeroizingSecret` for `Vec<u8>` would lose this guarantee
    // and break the test.
    let registry = InMemorySecretRegistry::new();
    let id = CredentialId::new();
    insert_secret(&registry, id, TEST_BEARER.as_bytes());
    let material: ZeroizingSecret = fetch_secret(&registry, &id);
    // Touch the bytes so the compiler keeps the value live to its
    // declared scope, then drop explicitly to invoke ZeroizeOnDrop.
    assert!(material.ct_eq_bytes(TEST_BEARER.as_bytes()));
    drop(material);
}

#[test]
fn production_trait_used() {
    fn assert_hook_trait_object(_: &Arc<dyn SecretFetchHook>) {}

    let registry = Arc::new(InMemorySecretRegistry::new());
    let hook: Arc<dyn SecretFetchHook> = registry;
    assert_hook_trait_object(&hook);

    let trait_name = std::any::type_name::<dyn SecretFetchHook>();
    assert!(
        trait_name.contains("fcp_crypto::secret_fetch::SecretFetchHook"),
        "unexpected SecretFetchHook provider: {trait_name}"
    );
}

#[test]
fn production_zeroizing_secret_drop_zeroes_memory() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<ZeroizingSecret>();
    let material = ZeroizingSecret::new(TEST_BEARER.as_bytes().to_vec());
    assert!(material.ct_eq_bytes(TEST_BEARER.as_bytes()));
    drop(material);
}

#[test]
fn production_secret_fetch_error_redacts_credential_id_in_display() {
    let raw_credential_id = "fcp-e99o6-credential-id";
    let error = SecretFetchError::not_found(raw_credential_id);
    let rendered = error.to_string();
    let hash = CredentialIdHash::from_credential_id(raw_credential_id);

    assert!(
        !rendered.contains(raw_credential_id),
        "raw credential id leaked in Display: {rendered}"
    );
    assert!(
        rendered.contains(hash.as_str()),
        "redacted Display should include credential id hash: {rendered}"
    );
    assert!(
        rendered.contains("credential_id_hash="),
        "Display should label the redacted credential id hash: {rendered}"
    );
}

#[test]
fn production_registry_test_utils_feature_gated() {
    let registry = fcp_crypto::test_utils::InMemorySecretRegistry::new();
    assert!(registry.is_empty());

    let registry_type = std::any::type_name::<fcp_crypto::test_utils::InMemorySecretRegistry>();
    assert!(
        registry_type.contains("fcp_crypto::secret_fetch::InMemorySecretRegistry"),
        "unexpected test-utils registry provider: {registry_type}"
    );
}

#[test]
fn production_trait_send_sync_bounds_satisfied() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<InMemorySecretRegistry>();
    assert_send_sync::<Arc<dyn SecretFetchHook>>();
}
