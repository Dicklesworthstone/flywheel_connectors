//! Remote distribution of owner-signed mesh membership.
//!
//! A trusted local source file may contain a directory-source descriptor instead
//! of the signed document itself. The publisher supplies bytes, never trust:
//! the existing activation/reload verifier still checks independently pinned
//! owner keys, mesh identity, local identity, validity and durable succession.
//! Remote documents cannot redirect the source or downgrade it to a raw list.

use std::time::Duration;

use fcp_mesh::peer_manifest::{MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES, SignedMeshPeerDirectory};
use serde::Deserialize;

use super::{HostResult, invalid};

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
}

/// Resolve only an explicitly tagged reference from the trusted local file.
/// Inline signed documents and static lists keep their existing byte semantics.
///
/// This is synchronous startup/reload I/O, never a request-handler operation.
/// A separate, joined thread keeps the runtime bridge off an existing executor.
/// Both the HTTP exchange and the complete fetch have deadlines. No mesh token,
/// node signing key, owner secret, cookies or ambient proxy configuration is sent.
pub(super) fn resolve_file_source(json: String) -> HostResult<String> {
    let Some(endpoint) = source_endpoint(&json)? else {
        return Ok(json);
    };
    let worker = std::thread::Builder::new()
        .name("fcp-mesh-directory-fetch".to_owned())
        .spawn(move || {
            fcp_async_core::runtime::block_on_sync(fetch(endpoint))
                .map_err(|_| invalid("remote directory runtime is unavailable"))?
        })
        .map_err(|_| invalid("remote directory fetch worker could not start"))?;
    worker
        .join()
        .map_err(|_| invalid("remote directory fetch worker failed"))?
}

fn source_endpoint(json: &str) -> HostResult<Option<url::Url>> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        // Preserve the ordinary document parser's error behavior. Invalid JSON
        // cannot become a reference and therefore cannot initiate network I/O.
        return Ok(None);
    };
    let is_reference = value.get("directory_url").is_some()
        || value.get("schema_version").and_then(serde_json::Value::as_str)
            == Some(SOURCE_SCHEMA);
    if !is_reference {
        return Ok(None);
    }
    if json.len() > MAX_SOURCE_BYTES {
        return Err(invalid("remote directory descriptor exceeds its byte limit"));
    }
    // Deserialize the original bytes, not Value: duplicate fields must fail.
    let source: SourceDescriptor = serde_json::from_str(json)
        .map_err(|_| invalid("malformed remote directory descriptor"))?;
    if source.schema_version != SOURCE_SCHEMA {
        return Err(invalid("unsupported remote directory descriptor schema"));
    }
    validate_endpoint(&source.directory_url).map(Some)
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
    {
        return Err(refused());
    }
    let loopback_http = endpoint.scheme() == "http"
        && match endpoint.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
    if endpoint.scheme() != "https" && !loopback_http {
        return Err(refused());
    }
    Ok(endpoint)
}

async fn fetch(endpoint: url::Url) -> HostResult<String> {
    fcp_async_core::time::timeout(FETCH_DEADLINE, fetch_document(endpoint))
        .await
        .map_err(|_| invalid("remote directory fetch deadline expired"))?
}

async fn fetch_document(endpoint: url::Url) -> HostResult<String> {
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_DEADLINE)
        .timeout(FETCH_DEADLINE)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .build()
        .map_err(|_| invalid("remote directory HTTP client is unavailable"))?;
    let mut response = client
        .get(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .send()
        .await
        .map_err(|_| invalid("remote directory transport failed"))?;
    // A partial response or an unvalidated 304 is not a complete membership
    // document. Redirects must not move our trusted source to another endpoint.
    if response.status() != reqwest::StatusCode::OK {
        return Err(invalid(&format!(
            "remote directory returned HTTP {}",
            response.status().as_u16(),
        )));
    }
    if response.content_length().is_some_and(|length| {
        length > u64::try_from(MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES).unwrap_or(u64::MAX)
    }) {
        return Err(invalid("remote directory exceeds its byte limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid("remote directory body read failed"))?
    {
        if chunk.len() > MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES.saturating_sub(bytes.len()) {
            return Err(invalid("remote directory exceeds its byte limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    decode_document(bytes)
}

fn decode_document(bytes: Vec<u8>) -> HostResult<String> {
    if bytes.len() > MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES {
        return Err(invalid("remote directory exceeds its byte limit"));
    }
    let json = String::from_utf8(bytes)
        .map_err(|_| invalid("remote directory is not UTF-8"))?;
    // This checks the envelope shape ONLY. The existing caller is responsible
    // for owner verification and durable acceptance. In static configuration
    // mode the returned object cannot deserialize as Vec<MeshPeerConfig>, so a
    // reference cannot silently introduce unsigned remote membership.
    SignedMeshPeerDirectory::from_json(&json)
        .map_err(|_| invalid("remote directory must contain a signed membership envelope"))?;
    Ok(json)
}

#[cfg(test)]
mod tests;
