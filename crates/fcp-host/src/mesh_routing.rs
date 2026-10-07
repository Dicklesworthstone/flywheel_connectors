//! Host-side mesh-backed invoke routing (bridge plan Phase A.2).
//!
//! A host with a configured mesh peer directory stops being a dead end for
//! connectors it does not run. Routing is local-first: a connector installed
//! on this host always executes here (answer stamped `host-backed`). When a
//! request names a connector that is not installed locally, the host routes
//! it to the peer whose signed advertisement offers it (the HRW-elected holder
//! for `singleton_writer` connectors, an HRW-ranked advertiser otherwise),
//! forwards it in a signed [`MeshForwardEnvelope`], verifies the signed
//! [`MeshForwardReply`], and stamps the answer `mesh-backed` with the
//! executor's node id. A candidate that fails *before* the request could have
//! been delivered is skipped in favour of the next ranked advertiser; a
//! forward whose outcome is unknown is never retried elsewhere, so
//! non-idempotent operations cannot double-execute. Unsigned HTTP refusals
//! are also ambiguous: an intermediary can fail after execution, and a replay
//! refusal can mean an earlier delivery already executed.
//!
//! Configuration (all three are required together; a partial configuration
//! is a startup error rather than a silent single-host fallback):
//!
//! - `FCP_HOST_MESH_NODE_ID` — this node's mesh id (defaults to
//!   `FCP_HOST_HRW_LEASE_LOCAL_NODE` when that is set).
//! - `FCP_HOST_MESH_SIGNING_KEY_FILE` — file holding this node's hex-encoded
//!   32-byte Ed25519 secret key.
//! - `FCP_HOST_MESH_PEERS` or `FCP_HOST_MESH_PEERS_FILE` — JSON array of
//!   `{ "node_id", "endpoint", "public_key_hex" }` peer entries.
//! - `FCP_HOST_MESH_FORWARD_TIMEOUT_MS` (optional) — per-forward deadline.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_mesh::invoke_route::{
    AdvertisedConnector, DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS, DEFAULT_MESH_FORWARD_MAX_SKEW_MS,
    DEFAULT_MESH_FORWARD_REPLAY_CAPACITY, MeshForwardBody, MeshForwardEnvelope, MeshForwardError,
    MeshForwardReplayGuard, MeshForwardReply, MeshPeerAdvertisement, MeshPeerDirectory,
};
use futures_util::future::join_all;
use zeroize::Zeroizing;

use crate::{HostError, HostResult};

/// Env var naming this node's mesh id.
pub const MESH_NODE_ID_ENV: &str = "FCP_HOST_MESH_NODE_ID";
/// Env var naming the file that holds this node's mesh signing key.
pub const MESH_SIGNING_KEY_FILE_ENV: &str = "FCP_HOST_MESH_SIGNING_KEY_FILE";
/// Env var holding the peer directory JSON inline.
pub const MESH_PEERS_ENV: &str = "FCP_HOST_MESH_PEERS";
/// Env var naming a file holding the peer directory JSON.
pub const MESH_PEERS_FILE_ENV: &str = "FCP_HOST_MESH_PEERS_FILE";
/// Env var overriding the per-forward deadline in milliseconds.
pub const MESH_FORWARD_TIMEOUT_MS_ENV: &str = "FCP_HOST_MESH_FORWARD_TIMEOUT_MS";
/// HRW local-node env var reused as the default mesh node id.
const HRW_LOCAL_NODE_ENV: &str = "FCP_HOST_HRW_LEASE_LOCAL_NODE";

/// Peer-facing route accepting signed forward envelopes.
pub const MESH_FORWARD_ROUTE: &str = "/rpc/mesh/forward";
/// Peer-facing route serving this node's signed advertisement.
pub const MESH_ADVERTISEMENT_ROUTE: &str = "/rpc/mesh/advertisement";

const DEFAULT_FORWARD_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const ADVERTISEMENT_FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const ADVERTISEMENT_CACHE_TTL: Duration = Duration::from_secs(10);
const MAX_REPLY_BYTES: usize = 16 * 1024 * 1024;

/// Current Unix time in milliseconds.
#[must_use]
pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Parsed mesh routing configuration.
pub struct MeshRoutingSettings {
    /// This node's mesh id.
    pub node_id: TailscaleNodeId,
    /// This node's mesh signing key.
    pub signing_key: Ed25519SigningKey,
    /// Peer directory JSON.
    pub peers_json: String,
    /// Per-forward deadline.
    pub forward_timeout: Duration,
}

impl std::fmt::Debug for MeshRoutingSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshRoutingSettings")
            .field("node_id", &self.node_id)
            .field("signing_key", &"<redacted>")
            .field("forward_timeout", &self.forward_timeout)
            .finish_non_exhaustive()
    }
}

impl MeshRoutingSettings {
    /// Read settings from the process environment.
    ///
    /// # Errors
    ///
    /// See [`Self::from_lookup`].
    pub fn from_env() -> HostResult<Option<Self>> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Read settings through `lookup` (env-var name → value).
    ///
    /// Returns `Ok(None)` when none of the mesh variables are set (a
    /// host-first deployment).
    ///
    /// # Errors
    ///
    /// Returns [`HostError::InvalidFilter`] when the configuration is partial
    /// or any value is malformed, so a misconfigured mesh node refuses to
    /// start instead of silently serving host-first answers.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> HostResult<Option<Self>> {
        let read = |name: &str| {
            lookup(name)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let explicit_node = read(MESH_NODE_ID_ENV);
        let key_file = read(MESH_SIGNING_KEY_FILE_ENV);
        let peers_inline = read(MESH_PEERS_ENV);
        let peers_file = read(MESH_PEERS_FILE_ENV);
        let timeout_raw = read(MESH_FORWARD_TIMEOUT_MS_ENV);

        let any_mesh_setting = explicit_node.is_some()
            || key_file.is_some()
            || peers_inline.is_some()
            || peers_file.is_some()
            || timeout_raw.is_some();
        if !any_mesh_setting {
            return Ok(None);
        }
        let invalid = |message: String| HostError::InvalidFilter(message);

        let node_raw = explicit_node
            .or_else(|| read(HRW_LOCAL_NODE_ENV))
            .ok_or_else(|| {
                invalid(format!(
                    "mesh routing requires {MESH_NODE_ID_ENV} (or {HRW_LOCAL_NODE_ENV})"
                ))
            })?;
        let node_id = TailscaleNodeId::try_new(node_raw.clone()).map_err(|error| {
            invalid(format!("invalid {MESH_NODE_ID_ENV} `{node_raw}`: {error}"))
        })?;

        let key_file = key_file
            .ok_or_else(|| invalid(format!("mesh routing requires {MESH_SIGNING_KEY_FILE_ENV}")))?;
        let signing_key = read_signing_key_file(Path::new(&key_file))?;

        let peers_json = match (peers_inline, peers_file) {
            (Some(_), Some(_)) => {
                return Err(invalid(format!(
                    "set only one of {MESH_PEERS_ENV} and {MESH_PEERS_FILE_ENV}"
                )));
            }
            (Some(inline), None) => inline,
            (None, Some(path)) => std::fs::read_to_string(&path).map_err(|error| {
                invalid(format!(
                    "cannot read {MESH_PEERS_FILE_ENV} `{path}`: {error}"
                ))
            })?,
            (None, None) => {
                return Err(invalid(format!(
                    "mesh routing requires {MESH_PEERS_ENV} or {MESH_PEERS_FILE_ENV}"
                )));
            }
        };

        let forward_timeout = match timeout_raw {
            None => DEFAULT_FORWARD_TIMEOUT,
            Some(raw) => {
                let millis: u64 = raw.parse().map_err(|error| {
                    invalid(format!(
                        "invalid {MESH_FORWARD_TIMEOUT_MS_ENV} `{raw}`: {error}"
                    ))
                })?;
                if millis == 0 {
                    return Err(invalid(format!(
                        "{MESH_FORWARD_TIMEOUT_MS_ENV} must be > 0"
                    )));
                }
                Duration::from_millis(millis)
            }
        };

        Ok(Some(Self {
            node_id,
            signing_key,
            peers_json,
            forward_timeout,
        }))
    }
}

fn read_signing_key_file(path: &Path) -> HostResult<Ed25519SigningKey> {
    let contents = Zeroizing::new(std::fs::read_to_string(path).map_err(|error| {
        HostError::InvalidFilter(format!(
            "cannot read {MESH_SIGNING_KEY_FILE_ENV} `{}`: {error}",
            path.display()
        ))
    })?);
    let bytes = Zeroizing::new(hex::decode(contents.trim()).map_err(|_| {
        HostError::InvalidFilter(format!(
            "{MESH_SIGNING_KEY_FILE_ENV} `{}` must contain a hex-encoded 32-byte Ed25519 secret key",
            path.display()
        ))
    })?);
    let secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(bytes.as_slice().try_into().map_err(|_| {
            HostError::InvalidFilter(format!(
                "{MESH_SIGNING_KEY_FILE_ENV} `{}` must hold exactly 32 bytes, got {}",
                path.display(),
                bytes.len()
            ))
        })?);
    Ed25519SigningKey::from_bytes(&secret).map_err(|error| {
        HostError::InvalidFilter(format!(
            "{MESH_SIGNING_KEY_FILE_ENV} `{}` is not a valid Ed25519 key: {error}",
            path.display()
        ))
    })
}

/// Why a forward did not produce a verified reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshForwardFailure {
    /// The request never reached the peer (connect/build failure).
    NotDelivered {
        /// Target peer.
        peer: String,
        /// Redaction-safe detail.
        detail: String,
    },
    /// An unsigned HTTP response refused the forward. This does not prove
    /// that execution did not occur, so it must not permit failover.
    Rejected {
        /// Target peer.
        peer: String,
        /// HTTP status of the refusal.
        status: u16,
        /// Redaction-safe explanation, never the unsigned response body.
        detail: String,
    },
    /// The request may have reached the peer; its outcome is unknown.
    OutcomeUnknown {
        /// Target peer.
        peer: String,
        /// Redaction-safe detail.
        detail: String,
    },
    /// The peer answered, but the reply failed verification.
    InvalidReply {
        /// Target peer.
        peer: String,
        /// Verification failure.
        error: MeshForwardError,
    },
}

impl MeshForwardFailure {
    /// Whether nothing can have executed on the peer, so trying another
    /// candidate (or the local connector) cannot double-execute.
    ///
    /// Neither an unsigned HTTP status nor a request-level transport error
    /// establishes this. In particular, HTTP 409 can reject a replay of an
    /// already-executed request, and a proxy can return 5xx after execution.
    #[must_use]
    pub const fn safe_to_retry(&self) -> bool {
        matches!(self, Self::NotDelivered { .. })
    }

    /// Target peer.
    #[must_use]
    pub fn peer(&self) -> &str {
        match self {
            Self::NotDelivered { peer, .. }
            | Self::Rejected { peer, .. }
            | Self::OutcomeUnknown { peer, .. }
            | Self::InvalidReply { peer, .. } => peer,
        }
    }

    /// One-line operator summary.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::NotDelivered { peer, detail } => format!("{peer}: not delivered ({detail})"),
            Self::Rejected {
                peer,
                status,
                detail,
            } => format!("{peer}: unsigned HTTP {status}; outcome unknown ({detail})"),
            Self::OutcomeUnknown { peer, detail } => format!("{peer}: outcome unknown ({detail})"),
            Self::InvalidReply { peer, error } => format!("{peer}: invalid reply ({error})"),
        }
    }
}

struct CachedAdvertisement {
    fetched_at: Instant,
    advertisement: MeshPeerAdvertisement,
}

/// Mesh routing state shared by every host request.
pub struct MeshRouter {
    directory: MeshPeerDirectory,
    signing_key: Ed25519SigningKey,
    replay_guard: Mutex<MeshForwardReplayGuard>,
    advertisements: Mutex<HashMap<String, CachedAdvertisement>>,
    client: reqwest::Client,
}

impl std::fmt::Debug for MeshRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshRouter")
            .field("local_node", self.directory.local_node())
            .field("peer_count", &self.directory.len())
            .finish_non_exhaustive()
    }
}

impl MeshRouter {
    /// Build a router from parsed settings.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::InvalidFilter`] for an invalid peer directory or
    /// [`HostError::Internal`] when the HTTP client cannot be built.
    pub fn new(settings: MeshRoutingSettings) -> HostResult<Self> {
        let directory = MeshPeerDirectory::from_json(settings.node_id, &settings.peers_json)
            .map_err(|error| HostError::InvalidFilter(error.to_string()))?;
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(settings.forward_timeout)
            .redirect(reqwest::redirect::Policy::none())
            // Only the mesh layer may decide whether another delivery is safe.
            .retry(reqwest::retry::never())
            .build()
            .map_err(|error| {
                HostError::Internal(format!(
                    "mesh forward HTTP client could not be built: {error}"
                ))
            })?;
        Ok(Self {
            directory,
            signing_key: settings.signing_key,
            replay_guard: Mutex::new(MeshForwardReplayGuard::new(
                DEFAULT_MESH_FORWARD_MAX_SKEW_MS,
                DEFAULT_MESH_FORWARD_REPLAY_CAPACITY,
            )),
            advertisements: Mutex::new(HashMap::new()),
            client,
        })
    }

    /// Build a router from the process environment, if configured.
    ///
    /// # Errors
    ///
    /// See [`MeshRoutingSettings::from_env`] and [`Self::new`].
    pub fn from_env() -> HostResult<Option<Self>> {
        MeshRoutingSettings::from_env()?.map(Self::new).transpose()
    }

    /// This node's id.
    #[must_use]
    pub const fn local_node(&self) -> &TailscaleNodeId {
        self.directory.local_node()
    }

    /// The trusted peer directory.
    #[must_use]
    pub const fn directory(&self) -> &MeshPeerDirectory {
        &self.directory
    }

    /// Sign this node's advertisement.
    #[must_use]
    pub fn sign_advertisement(
        &self,
        connectors: Vec<AdvertisedConnector>,
    ) -> MeshPeerAdvertisement {
        MeshPeerAdvertisement::sign(
            &self.signing_key,
            self.local_node().clone(),
            unix_now_ms(),
            connectors,
        )
    }

    /// Verify an inbound envelope and consume its nonce.
    ///
    /// # Errors
    ///
    /// Returns the verification or replay error.
    pub fn accept_inbound(&self, envelope: &MeshForwardEnvelope) -> Result<(), MeshForwardError> {
        let now_ms = unix_now_ms();
        envelope.verify(&self.directory, now_ms, DEFAULT_MESH_FORWARD_MAX_SKEW_MS)?;
        self.replay_guard
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .check_and_record(envelope, now_ms)
    }

    /// Sign the reply to an accepted inbound envelope.
    #[must_use]
    pub fn sign_reply(
        &self,
        envelope: &MeshForwardEnvelope,
        status: u16,
        body_json: String,
    ) -> MeshForwardReply {
        MeshForwardReply::sign(
            &self.signing_key,
            self.local_node().clone(),
            envelope,
            status,
            body_json,
        )
    }

    /// Forward `body` to `target` and return its verified reply.
    ///
    /// # Errors
    ///
    /// Returns a [`MeshForwardFailure`] classifying whether the request may
    /// have executed on the peer.
    pub async fn forward(
        &self,
        target: &TailscaleNodeId,
        body: MeshForwardBody,
    ) -> Result<MeshForwardReply, MeshForwardFailure> {
        let peer_label = target.as_str().to_owned();
        let Some(peer) = self.directory.peer(target) else {
            return Err(MeshForwardFailure::NotDelivered {
                peer: peer_label,
                detail: "peer is not in the local mesh directory".to_owned(),
            });
        };
        let envelope = MeshForwardEnvelope::sign(
            &self.signing_key,
            self.local_node().clone(),
            target.clone(),
            unix_now_ms(),
            body,
        )
        .map_err(|error| MeshForwardFailure::NotDelivered {
            peer: peer_label.clone(),
            detail: error.to_string(),
        })?;
        let payload =
            serde_json::to_vec(&envelope).map_err(|error| MeshForwardFailure::NotDelivered {
                peer: peer_label.clone(),
                detail: format!("envelope serialization failed: {error}"),
            })?;
        let url = format!("{}{MESH_FORWARD_ROUTE}", peer.endpoint);
        let response = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|error| classify_send_error(&peer_label, &error))?;
        let status = response.status();
        if !status.is_success() {
            // HTTP status is not signed execution evidence. Even a 401/409/503
            // can come from an intermediary after the peer accepted the call.
            // Do not read or expose the untrusted body, and never fan out.
            return Err(MeshForwardFailure::Rejected {
                peer: peer_label,
                status: status.as_u16(),
                detail: "no authenticated proof of non-execution; failover refused".to_owned(),
            });
        }
        let bytes = read_bounded(response, MAX_REPLY_BYTES)
            .await
            .map_err(|detail| MeshForwardFailure::OutcomeUnknown {
                peer: peer_label.clone(),
                detail,
            })?;
        let reply: MeshForwardReply =
            serde_json::from_slice(&bytes).map_err(|error| MeshForwardFailure::InvalidReply {
                peer: peer_label.clone(),
                error: MeshForwardError::Malformed {
                    field: "reply",
                    detail: error.to_string(),
                },
            })?;
        reply
            .verify_for(&envelope, &self.directory)
            .map_err(|error| MeshForwardFailure::InvalidReply {
                peer: peer_label,
                error,
            })?;
        Ok(reply)
    }

    /// Verified advertisements from every reachable peer.
    ///
    /// Advertisements are cached for a few seconds; unreachable peers or
    /// advertisements that fail verification are skipped (and logged), so a
    /// single bad peer never blocks routing to the others.
    pub async fn peer_advertisements(&self) -> Vec<MeshPeerAdvertisement> {
        let mut fresh = Vec::new();
        let mut stale_peers = Vec::new();
        {
            let cache = self
                .advertisements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for peer in self.directory.peers() {
                match cache.get(peer.node_id.as_str()) {
                    Some(cached) if cached.fetched_at.elapsed() < ADVERTISEMENT_CACHE_TTL => {
                        fresh.push(cached.advertisement.clone());
                    }
                    _ => stale_peers.push(peer.clone()),
                }
            }
        }
        if stale_peers.is_empty() {
            return fresh;
        }
        let fetched = join_all(stale_peers.iter().map(|peer| async move {
            let result = self
                .fetch_advertisement(&peer.node_id, &peer.endpoint)
                .await;
            (peer.node_id.clone(), result)
        }))
        .await;
        let mut cache = self
            .advertisements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (node_id, result) in fetched {
            match result {
                Ok(advertisement) => {
                    cache.insert(
                        node_id.as_str().to_owned(),
                        CachedAdvertisement {
                            fetched_at: Instant::now(),
                            advertisement: advertisement.clone(),
                        },
                    );
                    fresh.push(advertisement);
                }
                Err(detail) => {
                    cache.remove(node_id.as_str());
                    tracing::warn!(
                        event = "mesh_advertisement_unavailable",
                        peer = node_id.as_str(),
                        detail = %detail,
                        "skipping mesh peer advertisement"
                    );
                }
            }
        }
        fresh
    }

    /// Drop cached advertisements so the next lookup refetches.
    pub fn invalidate_advertisements(&self) {
        self.advertisements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    async fn fetch_advertisement(
        &self,
        node_id: &TailscaleNodeId,
        endpoint: &str,
    ) -> Result<MeshPeerAdvertisement, String> {
        let url = format!("{endpoint}{MESH_ADVERTISEMENT_ROUTE}");
        let response = self
            .client
            .get(&url)
            .timeout(ADVERTISEMENT_FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|error| format!("advertisement fetch failed: {}", redact_reqwest(&error)))?;
        if !response.status().is_success() {
            return Err(format!(
                "advertisement fetch returned HTTP {}",
                response.status()
            ));
        }
        let bytes = read_bounded(response, MAX_REPLY_BYTES).await?;
        let advertisement: MeshPeerAdvertisement = serde_json::from_slice(&bytes)
            .map_err(|error| format!("advertisement is not valid JSON: {error}"))?;
        advertisement
            .verify(
                node_id,
                &self.directory,
                unix_now_ms(),
                DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS,
            )
            .map_err(|error| error.to_string())?;
        Ok(advertisement)
    }
}

fn redact_reqwest(error: &reqwest::Error) -> String {
    // reqwest errors embed the full URL; peers are operator-configured so the
    // URL is not secret, but strip it so logs key on the peer id instead.
    let text = error.to_string();
    match error.url() {
        Some(url) => text.replace(url.as_str(), "<peer>"),
        None => text,
    }
}

fn classify_send_error(peer: &str, error: &reqwest::Error) -> MeshForwardFailure {
    let detail = redact_reqwest(error);
    // is_request() includes failures while waiting for response headers after
    // the entire request was delivered. Only pre-send failures are retryable.
    if error.is_connect() || error.is_builder() {
        MeshForwardFailure::NotDelivered {
            peer: peer.to_owned(),
            detail,
        }
    } else {
        MeshForwardFailure::OutcomeUnknown {
            peer: peer.to_owned(),
            detail,
        }
    }
}

async fn read_bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    if let Some(length) = response.content_length()
        && usize::try_from(length).unwrap_or(usize::MAX) > limit
    {
        return Err(format!(
            "mesh reply of {length} bytes exceeds limit {limit}"
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("mesh reply body read failed: {}", redact_reqwest(&error)))?
    {
        if body.len() + chunk.len() > limit {
            return Err(format!("mesh reply exceeds limit {limit} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_key_file(dir: &tempfile::TempDir, key: &Ed25519SigningKey) -> String {
        let path = dir.path().join("mesh.key");
        std::fs::write(&path, hex::encode(key.to_bytes())).unwrap();
        path.display().to_string()
    }

    fn peers_json(entries: &[(&str, &Ed25519SigningKey)]) -> String {
        serde_json::to_string(
            &entries
                .iter()
                .enumerate()
                .map(|(index, (id, key))| {
                    serde_json::json!({
                        "node_id": id,
                        "endpoint": format!("http://127.0.0.1:{}", 19_000 + index),
                        "public_key_hex": hex::encode(key.verifying_key().to_bytes()),
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn unset_environment_means_host_first() {
        assert!(
            MeshRoutingSettings::from_lookup(|_| None)
                .unwrap()
                .is_none()
        );
        assert!(
            MeshRoutingSettings::from_lookup(
                |name| (name == HRW_LOCAL_NODE_ENV).then(|| "node-a".to_owned())
            )
            .unwrap()
            .is_none(),
            "HRW routing alone does not opt into mesh forwarding"
        );
    }

    #[test]
    fn partial_configuration_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let key = Ed25519SigningKey::generate();
        let key_file = write_key_file(&dir, &key);
        let peers = peers_json(&[("node-b", &Ed25519SigningKey::generate())]);

        let only_node = |name: &str| (name == MESH_NODE_ID_ENV).then(|| "node-a".to_owned());
        assert!(MeshRoutingSettings::from_lookup(only_node).is_err());

        let no_peers = |name: &str| match name {
            MESH_NODE_ID_ENV => Some("node-a".to_owned()),
            MESH_SIGNING_KEY_FILE_ENV => Some(key_file.clone()),
            _ => None,
        };
        assert!(MeshRoutingSettings::from_lookup(no_peers).is_err());

        let no_node = |name: &str| match name {
            MESH_SIGNING_KEY_FILE_ENV => Some(key_file.clone()),
            MESH_PEERS_ENV => Some(peers.clone()),
            _ => None,
        };
        assert!(MeshRoutingSettings::from_lookup(no_node).is_err());

        let both_peer_sources = |name: &str| match name {
            MESH_NODE_ID_ENV => Some("node-a".to_owned()),
            MESH_SIGNING_KEY_FILE_ENV => Some(key_file.clone()),
            MESH_PEERS_ENV | MESH_PEERS_FILE_ENV => Some(peers.clone()),
            _ => None,
        };
        assert!(MeshRoutingSettings::from_lookup(both_peer_sources).is_err());

        let zero_timeout = |name: &str| match name {
            MESH_NODE_ID_ENV => Some("node-a".to_owned()),
            MESH_SIGNING_KEY_FILE_ENV => Some(key_file.clone()),
            MESH_PEERS_ENV => Some(peers.clone()),
            MESH_FORWARD_TIMEOUT_MS_ENV => Some("0".to_owned()),
            _ => None,
        };
        assert!(MeshRoutingSettings::from_lookup(zero_timeout).is_err());
    }

    #[test]
    fn rejects_malformed_key_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        for contents in ["not hex", "abcd", ""] {
            std::fs::write(&path, contents).unwrap();
            assert!(
                read_signing_key_file(&path).is_err(),
                "{contents:?} must be rejected"
            );
        }
        assert!(read_signing_key_file(&dir.path().join("missing.key")).is_err());
    }

    #[test]
    fn full_configuration_builds_router_and_falls_back_to_hrw_node_id() {
        let dir = tempfile::tempdir().unwrap();
        let key = Ed25519SigningKey::generate();
        let key_file = write_key_file(&dir, &key);
        let peer_key = Ed25519SigningKey::generate();
        let peers = peers_json(&[("node-a", &key), ("node-b", &peer_key)]);
        let lookup = |name: &str| match name {
            HRW_LOCAL_NODE_ENV => Some("node-a".to_owned()),
            MESH_SIGNING_KEY_FILE_ENV => Some(key_file.clone()),
            MESH_PEERS_ENV => Some(peers.clone()),
            MESH_FORWARD_TIMEOUT_MS_ENV => Some("2500".to_owned()),
            _ => None,
        };
        let settings = MeshRoutingSettings::from_lookup(lookup).unwrap().unwrap();
        assert_eq!(settings.node_id.as_str(), "node-a");
        assert_eq!(settings.forward_timeout, Duration::from_millis(2500));
        assert!(!format!("{settings:?}").contains(&hex::encode(key.to_bytes())));
        let router = MeshRouter::new(settings).unwrap();
        assert_eq!(router.local_node().as_str(), "node-a");
        assert_eq!(
            router.directory().len(),
            1,
            "local node is not its own peer"
        );
    }

    #[test]
    fn inbound_acceptance_verifies_and_rejects_replays() {
        let dir = tempfile::tempdir().unwrap();
        let key_a = Ed25519SigningKey::generate();
        let key_b = Ed25519SigningKey::generate();
        let peers = peers_json(&[("node-a", &key_a), ("node-b", &key_b)]);
        let key_file = write_key_file(&dir, &key_b);
        let router = MeshRouter::new(
            MeshRoutingSettings::from_lookup(|name| match name {
                MESH_NODE_ID_ENV => Some("node-b".to_owned()),
                MESH_SIGNING_KEY_FILE_ENV => Some(key_file.clone()),
                MESH_PEERS_ENV => Some(peers.clone()),
                _ => None,
            })
            .unwrap()
            .unwrap(),
        )
        .unwrap();
        let envelope = MeshForwardEnvelope::sign(
            &key_a,
            TailscaleNodeId::new("node-a"),
            TailscaleNodeId::new("node-b"),
            unix_now_ms(),
            MeshForwardBody::Introspect {
                connector_id: "fcp.test:utility:1.0.0".to_owned(),
            },
        )
        .unwrap();
        router.accept_inbound(&envelope).unwrap();
        assert!(matches!(
            router.accept_inbound(&envelope),
            Err(MeshForwardError::Replayed { .. })
        ));
        let reply = router.sign_reply(&envelope, 200, "{}".to_owned());
        let origin_directory =
            MeshPeerDirectory::from_json(TailscaleNodeId::new("node-a"), &peers).unwrap();
        reply.verify_for(&envelope, &origin_directory).unwrap();
    }

    #[test]
    fn failure_classification_controls_retry() {
        let not_delivered = MeshForwardFailure::NotDelivered {
            peer: "node-b".to_owned(),
            detail: "connection refused".to_owned(),
        };
        let rejected = MeshForwardFailure::Rejected {
            peer: "node-b".to_owned(),
            status: 401,
            detail: "unsigned refusal".to_owned(),
        };
        let unknown = MeshForwardFailure::OutcomeUnknown {
            peer: "node-b".to_owned(),
            detail: "timeout".to_owned(),
        };
        assert!(not_delivered.safe_to_retry());
        assert!(!rejected.safe_to_retry());
        assert!(!unknown.safe_to_retry());
        assert!(rejected.summary().contains("outcome unknown"));
        assert!(unknown.summary().contains("outcome unknown"));
        assert_eq!(rejected.peer(), "node-b");
    }

    #[test]
    fn forward_to_unreachable_peer_is_not_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let key_a = Ed25519SigningKey::generate();
        // Bind and immediately drop a listener to get a closed local port.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let peers = serde_json::to_string(&serde_json::json!([{
            "node_id": "node-b",
            "endpoint": format!("http://127.0.0.1:{port}"),
            "public_key_hex": hex::encode(Ed25519SigningKey::generate().verifying_key().to_bytes()),
        }]))
        .unwrap();
        let key_file = write_key_file(&dir, &key_a);
        let router = MeshRouter::new(
            MeshRoutingSettings::from_lookup(|name| match name {
                MESH_NODE_ID_ENV => Some("node-a".to_owned()),
                MESH_SIGNING_KEY_FILE_ENV => Some(key_file.clone()),
                MESH_PEERS_ENV => Some(peers.clone()),
                _ => None,
            })
            .unwrap()
            .unwrap(),
        )
        .unwrap();
        let result = fcp_async_core::runtime::block_on_sync(router.forward(
            &TailscaleNodeId::new("node-b"),
            MeshForwardBody::Introspect {
                connector_id: "fcp.test:utility:1.0.0".to_owned(),
            },
        ))
        .expect("runtime");
        let failure = result.expect_err("closed port cannot answer");
        assert!(
            failure.safe_to_retry(),
            "connect failure must be retryable: {failure:?}"
        );
        let advertisements =
            fcp_async_core::runtime::block_on_sync(router.peer_advertisements()).expect("runtime");
        assert!(advertisements.is_empty());
        let unknown_peer = fcp_async_core::runtime::block_on_sync(router.forward(
            &TailscaleNodeId::new("node-z"),
            MeshForwardBody::Introspect {
                connector_id: "fcp.test:utility:1.0.0".to_owned(),
            },
        ))
        .expect("runtime");
        assert!(matches!(
            unknown_peer,
            Err(MeshForwardFailure::NotDelivered { .. })
        ));
    }

    // A real TCP peer reads the entire signed invoke before deciding how to
    // answer. This exercises reqwest's delivery classification, not a model
    // of it. Both accept and I/O are bounded so a regression cannot hang CI.
    fn forward_after_receipt(
        respond: impl FnOnce(MeshForwardEnvelope, Ed25519SigningKey) -> Option<(u16, String)>
        + Send
        + 'static,
    ) -> Result<MeshForwardReply, MeshForwardFailure> {
        use std::io::{BufRead, BufReader, Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let peer_key = Ed25519SigningKey::generate();
        let router = MeshRouter::new(MeshRoutingSettings {
            node_id: TailscaleNodeId::new("node-a"),
            signing_key: Ed25519SigningKey::generate(),
            peers_json: serde_json::json!([{
                "node_id": "node-b",
                "endpoint": endpoint,
                "public_key_hex": hex::encode(peer_key.verifying_key().to_bytes()),
            }])
            .to_string(),
            forward_timeout: Duration::from_secs(5),
        })
        .unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "forward never connected");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let envelope = {
                let mut reader = BufReader::new(&mut socket);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line, "POST /rpc/mesh/forward HTTP/1.1\r\n");
                let mut content_length = None;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    assert!(!line.is_empty(), "EOF in request headers");
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let length = content_length.expect("known-length signed envelope");
                assert!(length < 64 * 1024);
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                serde_json::from_slice::<MeshForwardEnvelope>(&bytes).unwrap()
            };
            assert!(matches!(&envelope.body, MeshForwardBody::Invoke { .. }));
            if let Some((status, body)) = respond(envelope, peer_key) {
                // Including Location pins redirect refusal as well as errors.
                let header = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nLocation: /must-not-retry\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(header.as_bytes()).unwrap();
                // The client may close without reading an unsigned error body.
                let _ = socket.write_all(body.as_bytes());
            }
        });
        let result = fcp_async_core::runtime::block_on_sync(router.forward(
            &TailscaleNodeId::new("node-b"),
            MeshForwardBody::Invoke {
                request_json: "{\"operation\":\"non_idempotent_write\"}".to_owned(),
                asserted_principal: Some("test-principal".to_owned()),
            },
        ))
        .expect("runtime");
        server.join().expect("peer must receive the complete invoke");
        result
    }

    #[test]
    fn forward_eof_after_request_receipt_is_not_retryable() {
        let failure = forward_after_receipt(|_, _| None).unwrap_err();
        assert!(matches!(failure, MeshForwardFailure::OutcomeUnknown { .. }));
        assert!(!failure.safe_to_retry(), "lost reply cannot justify fanout");
    }

    #[test]
    fn forward_unsigned_http_status_never_proves_non_execution() {
        for status in [301, 307, 400, 401, 403, 409, 421, 429, 500, 502, 503, 504] {
            let failure = forward_after_receipt(move |_, _| {
                Some((status, "secret-from-unsigned-error-body".to_owned()))
            })
            .unwrap_err();
            assert!(matches!(
                failure,
                MeshForwardFailure::Rejected { status: actual, .. } if actual == status
            ));
            assert!(!failure.safe_to_retry(), "HTTP {status} cannot justify fanout");
            assert!(!failure.summary().contains("secret-from-unsigned-error-body"));
        }
    }

    #[test]
    fn forward_malformed_success_reply_is_not_retryable() {
        let failure = forward_after_receipt(|_, _| Some((200, "not a signed reply".to_owned())))
            .unwrap_err();
        assert!(matches!(failure, MeshForwardFailure::InvalidReply { .. }));
        assert!(!failure.safe_to_retry());
    }

    #[test]
    fn forward_signed_executor_error_is_a_result_not_failover() {
        let reply = forward_after_receipt(|envelope, key| {
            let reply = MeshForwardReply::sign(
                &key,
                TailscaleNodeId::new("node-b"),
                &envelope,
                500,
                "{\"error\":\"operation failed after acceptance\"}".to_owned(),
            );
            Some((200, serde_json::to_string(&reply).unwrap()))
        })
        .unwrap();
        assert_eq!(reply.status, 500);
        assert_eq!(reply.served_by.as_str(), "node-b");
        assert!(reply.body_json.contains("operation failed after acceptance"));
    }

    #[test]
    fn forward_wrong_signer_reply_is_not_retryable() {
        let failure = forward_after_receipt(|envelope, _| {
            let reply = MeshForwardReply::sign(
                &Ed25519SigningKey::generate(),
                TailscaleNodeId::new("node-b"),
                &envelope,
                200,
                "{}".to_owned(),
            );
            Some((200, serde_json::to_string(&reply).unwrap()))
        })
        .unwrap_err();
        assert!(matches!(failure, MeshForwardFailure::InvalidReply { .. }));
        assert!(!failure.safe_to_retry());
    }
}
