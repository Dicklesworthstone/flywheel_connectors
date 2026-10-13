//! Remote distribution of owner-signed mesh membership.
//!
//! A trusted local source file may contain a directory-source descriptor instead
//! of the signed document itself. The publisher supplies bytes, never trust:
//! the existing activation/reload verifier still checks independently pinned
//! owner keys, mesh identity, local identity, validity and durable succession.
//! Remote documents cannot redirect the source or downgrade it to a raw list.
//! Optional retained source storage permits offline startup and reload on transport
//! outages. It retains the last complete candidate, NOT cached authorization or a
//! last-good fallback that could conceal an invalid update or local revocation.

use std::path::PathBuf;
use std::time::Duration;

use fcp_mesh::peer_manifest::{MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES, SignedMeshPeerDirectory};
use serde::Deserialize;

use super::{HostResult, invalid, unix_now_ms};

mod retained;

const SOURCE_SCHEMA: &str = "fcp.mesh.directory-source.v1";
const MAX_SOURCE_BYTES: usize = 4096;
const MAX_URL_BYTES: usize = 2048;
const FETCH_DEADLINE: Duration = Duration::from_secs(3);
const CONNECT_DEADLINE: Duration = Duration::from_secs(1);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceDescriptor {
    schema_version: String,
    directory_url: String,
    #[serde(default)]
    retained_source_file: Option<PathBuf>,
}

struct Source {
    endpoint: url::Url,
    retained_source_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind { Local, Unavailable, Rejected }

struct FetchFailure {
    kind: FailureKind,
    detail: &'static str,
    status: Option<u16>,
}

type FetchResult = Result<String, FetchFailure>;

impl FetchFailure {
    const fn new(kind: FailureKind, detail: &'static str) -> Self {
        Self { kind, detail, status: None }
    }

    fn http(status: u16) -> Self {
        Self {
            kind: if status == 408 || status == 429 || (500..600).contains(&status) {
                FailureKind::Unavailable
            } else {
                FailureKind::Rejected
            },
            detail: "remote directory returned an unusable HTTP status",
            status: Some(status),
        }
    }

    fn into_error(self) -> crate::HostError {
        match self.status {
            Some(status) => invalid(&format!("remote directory returned HTTP {status}")),
            None => invalid(self.detail),
        }
    }
}

/// Resolve only an explicitly tagged reference from the trusted local file.
/// Inline signed documents and static lists keep their existing byte semantics.
///
/// This is synchronous startup/reload I/O, never a request-handler operation.
/// A separate, joined thread keeps the runtime bridge off an existing executor.
/// Both the HTTP exchange and the complete fetch have deadlines. No mesh token,
/// node signing key, owner secret, cookies or ambient proxy configuration is sent.
pub(super) fn resolve_file_source(json: String) -> HostResult<String> {
    resolve_with_fetch(json, fetch_remote)
}

fn resolve_with_fetch(json: String, fetch_source: impl FnOnce(url::Url) -> FetchResult) -> HostResult<String> {
    let Some(source) = parse_source(&json)? else {
        return Ok(json);
    };
    // Acquire and inspect local storage before any network work. Corrupt state
    // cannot silently become an empty cache merely because the publisher works.
    let mut cache = source.retained_source_file.as_deref()
        .map(|path| retained::SourceCache::open(path, &source.endpoint)).transpose()?;
    match fetch_source(source.endpoint) {
        Ok(document) => {
            if let Some(cache) = &mut cache {
                // Retain before the host can activate this candidate. The host
                // verifier, not the source reader, establishes its authority.
                cache.store(Some(document.clone()), unix_now_ms())?;
            }
            Ok(document)
        }
        Err(failure) => {
            if let Some(cache) = &mut cache {
                match failure.kind {
                    FailureKind::Unavailable => {
                        let document = cache.candidate(unix_now_ms())?;
                        tracing::warn!(
                            event = "mesh_membership_retained_source",
                            truth_source = "retained_source_requires_verification",
                            reason = "publisher_unavailable",
                            "using retained source bytes; signature, expiry and checkpoint checks still required"
                        );
                        return Ok(document);
                    }
                    FailureKind::Rejected => {
                        // A bad complete response must not be replaced by older
                        // cached membership, either now or after an outage/restart.
                        cache.store(None, unix_now_ms())?;
                    }
                    FailureKind::Local => {}
                }
            }
            Err(failure.into_error())
        }
    }
}

fn fetch_remote(endpoint: url::Url) -> FetchResult {
    let worker = std::thread::Builder::new()
        .name("fcp-mesh-directory-fetch".to_owned())
        .spawn(move || {
            fcp_async_core::runtime::block_on_sync(fetch(endpoint))
                .map_err(|_| FetchFailure::new(FailureKind::Local, "remote directory runtime is unavailable"))?
        })
        .map_err(|_| FetchFailure::new(FailureKind::Local, "remote directory fetch worker could not start"))?;
    worker.join()
        .map_err(|_| FetchFailure::new(FailureKind::Local, "remote directory fetch worker failed"))?
}

fn parse_source(json: &str) -> HostResult<Option<Source>> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Ok(None);
    };
    let is_reference = value.get("directory_url").is_some()
        || value.get("retained_source_file").is_some()
        || value.get("schema_version").and_then(serde_json::Value::as_str) == Some(SOURCE_SCHEMA);
    if !is_reference { return Ok(None); }
    if json.len() > MAX_SOURCE_BYTES {
        return Err(invalid("remote directory descriptor exceeds its byte limit"));
    }
    // Deserialize the original bytes: duplicate fields must fail.
    let source: SourceDescriptor = serde_json::from_str(json)
        .map_err(|_| invalid("malformed remote directory descriptor"))?;
    if source.schema_version != SOURCE_SCHEMA {
        return Err(invalid("unsupported remote directory descriptor schema"));
    }
    if let Some(path) = &source.retained_source_file { retained::validate_path(path)?; }
    Ok(Some(Source {
        endpoint: validate_endpoint(&source.directory_url)?,
        retained_source_file: source.retained_source_file,
    }))
}

#[cfg(test)]
fn source_endpoint(json: &str) -> HostResult<Option<url::Url>> {
    parse_source(json).map(|source| source.map(|source| source.endpoint))
}

fn validate_endpoint(raw: &str) -> HostResult<url::Url> {
    let refused = || invalid(
        "remote directory URL requires HTTPS (or literal loopback HTTP), without credentials, query, fragment or whitespace",
    );
    if raw.is_empty() || raw.len() > MAX_URL_BYTES || raw.chars().any(char::is_whitespace) {
        return Err(refused());
    }
    let endpoint = url::Url::parse(raw).map_err(|_| refused())?;
    if endpoint.host().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.port() == Some(0)
    { return Err(refused()); }
    let loopback_http = endpoint.scheme() == "http"
        && match endpoint.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
    if endpoint.scheme() != "https" && !loopback_http { return Err(refused()); }
    Ok(endpoint)
}

async fn fetch(endpoint: url::Url) -> FetchResult {
    fcp_async_core::time::timeout(FETCH_DEADLINE, fetch_document(endpoint))
        .await
        .map_err(|_| FetchFailure::new(FailureKind::Unavailable, "remote directory fetch deadline expired"))?
}

async fn fetch_document(endpoint: url::Url) -> FetchResult {
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_DEADLINE)
        .timeout(FETCH_DEADLINE)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .no_gzip().no_brotli().no_deflate().no_zstd()
        .build()
        .map_err(|_| FetchFailure::new(FailureKind::Local, "remote directory HTTP client is unavailable"))?;
    let mut response = client.get(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .send().await
        .map_err(|_| FetchFailure::new(FailureKind::Unavailable, "remote directory transport failed"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(FetchFailure::http(response.status().as_u16()));
    }
    if response.headers().get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|encoding| encoding.as_bytes() != b"identity")
    {
        return Err(FetchFailure::new(FailureKind::Rejected, "encoded remote directory response is not accepted"));
    }
    if response.content_length().is_some_and(|length| {
        length > u64::try_from(MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES).unwrap_or(u64::MAX)
    }) {
        return Err(FetchFailure::new(FailureKind::Rejected, "remote directory exceeds its byte limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await
        .map_err(|_| FetchFailure::new(FailureKind::Unavailable, "remote directory body read failed"))?
    {
        if chunk.len() > MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES.saturating_sub(bytes.len()) {
            return Err(FetchFailure::new(FailureKind::Rejected, "remote directory exceeds its byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    decode_document(bytes)
        .map_err(|_| FetchFailure::new(FailureKind::Rejected, "remote directory must contain a valid signed membership envelope"))
}

fn decode_document(bytes: Vec<u8>) -> HostResult<String> {
    if bytes.len() > MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES {
        return Err(invalid("remote directory exceeds its byte limit"));
    }
    let json = String::from_utf8(bytes).map_err(|_| invalid("remote directory is not UTF-8"))?;
    // Shape only: the existing caller owns independent verification and durable
    // acceptance. Neither a successful download nor a cache hit grants authority.
    SignedMeshPeerDirectory::from_json(&json)
        .map_err(|_| invalid("remote directory must contain a signed membership envelope"))?;
    Ok(json)
}

#[cfg(test)]
mod tests;

#[cfg(all(test, unix))]
mod retention_tests {
    use super::*;

    fn descriptor(path: &std::path::Path) -> String {
        serde_json::json!({
            "schema_version": SOURCE_SCHEMA,
            "directory_url": "https://source.example/members",
            "retained_source_file": path,
        }).to_string()
    }

    fn candidate() -> String {
        "{\"signer_public_key_hex\":\"00\",\"payload_json\":\"{}\",\"signature_hex\":\"00\"}".to_owned()
    }

    fn unavailable() -> FetchResult {
        Err(FetchFailure::new(FailureKind::Unavailable, "publisher unavailable"))
    }

    #[test]
    fn publisher_outage_uses_exact_retained_candidate_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let source = descriptor(&dir.path().join("retained"));
        assert!(resolve_with_fetch(source.clone(), |_| unavailable()).is_err());
        assert_eq!(resolve_with_fetch(source.clone(), |_| Ok(candidate())).unwrap(), candidate());
        assert_eq!(resolve_with_fetch(source, |_| unavailable()).unwrap(), candidate());
    }

    #[test]
    fn rejected_response_fences_fallback_until_a_complete_candidate_arrives() {
        let dir = tempfile::tempdir().unwrap();
        let source = descriptor(&dir.path().join("retained"));
        resolve_with_fetch(source.clone(), |_| Ok(candidate())).unwrap();
        assert!(resolve_with_fetch(source.clone(), |_| Err(FetchFailure::http(403))).is_err());
        assert!(resolve_with_fetch(source.clone(), |_| unavailable()).is_err());
        resolve_with_fetch(source.clone(), |_| Ok(candidate())).unwrap();
        assert_eq!(resolve_with_fetch(source, |_| unavailable()).unwrap(), candidate());
    }

    #[test]
    fn a_new_unverified_envelope_never_falls_back_to_the_old_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let source = descriptor(&dir.path().join("retained"));
        resolve_with_fetch(source.clone(), |_| Ok(candidate())).unwrap();
        let changed = candidate().replace("{}", "{\\\"generation\\\":99}");
        resolve_with_fetch(source.clone(), |_| Ok(changed.clone())).unwrap();
        // The host's owner verifier will reject these fake signatures. Retention
        // must not hide that rejection by substituting the earlier source.
        assert_eq!(resolve_with_fetch(source, |_| unavailable()).unwrap(), changed);
    }

    #[test]
    fn local_failures_do_not_masquerade_as_publisher_outages() {
        let dir = tempfile::tempdir().unwrap();
        let source = descriptor(&dir.path().join("retained"));
        resolve_with_fetch(source.clone(), |_| Ok(candidate())).unwrap();
        let error = resolve_with_fetch(source, |_| Err(FetchFailure::new(
            FailureKind::Local, "runtime unavailable",
        ))).unwrap_err();
        assert!(error.to_string().contains("runtime unavailable"));
    }

    #[test]
    fn local_corruption_and_invalid_paths_stop_before_fetching() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retained");
        let source = descriptor(&path);
        resolve_with_fetch(source.clone(), |_| Ok(candidate())).unwrap();
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(resolve_with_fetch(source, |_| panic!("must not contact publisher")).is_err());
        assert!(resolve_with_fetch(descriptor(std::path::Path::new("relative")),
            |_| panic!("must validate configuration first")).is_err());
    }

    #[test]
    fn only_transient_http_statuses_can_use_retained_source() {
        for status in [408, 429, 500, 502, 503, 504] {
            assert_eq!(FetchFailure::http(status).kind, FailureKind::Unavailable);
        }
        for status in [204, 206, 301, 304, 307, 308, 400, 401, 403, 404, 409] {
            assert_eq!(FetchFailure::http(status).kind, FailureKind::Rejected);
        }
    }
}
