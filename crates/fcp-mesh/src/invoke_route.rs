//! Mesh-backed invoke routing (bridge plan Phase A.2, `MeshInvokeTransport`).
//!
//! Host-first FCP executes every invoke on the host the client called. A
//! mesh-native deployment instead lets any node accept the request and routes
//! it to the node that should execute it:
//!
//! - `singleton_writer` connectors execute only on the HRW-elected lease
//!   holder for `(connector, zone)`. A non-holder used to refuse; with a peer
//!   directory it forwards to the holder instead.
//! - Connectors that are not installed locally execute on a peer whose signed
//!   [`MeshPeerAdvertisement`] lists them, picked deterministically by HRW so
//!   load spreads and retries are stable.
//!
//! This module is the transport-agnostic core of that path:
//!
//! - [`MeshPeerDirectory`] — the static trust roots: peer node id, endpoint,
//!   and the Ed25519 key that authenticates the peer's forwards and replies.
//! - [`MeshForwardEnvelope`] / [`MeshForwardReply`] — domain-separated,
//!   Ed25519-signed request and reply envelopes. The request body is carried
//!   as the exact JSON bytes the origin signed, so verification never depends
//!   on re-serialization being byte-stable.
//! - [`MeshForwardReplayGuard`] — freshness window plus nonce cache; fails
//!   closed when saturated instead of evicting unexpired nonces.
//! - [`decide_singleton_writer_route`] / [`decide_advertised_connector_route`]
//!   — pure routing rules producing an [`InvokeRouteDecision`] whose `code`
//!   is stamped into the response's route provenance.
//!
//! Forwarding is single-hop: [`MAX_MESH_FORWARD_HOPS`] is 1 and a request that
//! arrived over the mesh always executes locally, so routing loops are
//! impossible even when two nodes disagree about the eligible-node set.

use std::collections::{BTreeMap, HashMap, VecDeque};

use fcp_core::{ObjectId, TailscaleNodeId, ZoneId};
use fcp_crypto::ed25519::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::planner::{rank_lease_holders_by_hrw, select_lease_holder};

/// Schema tag carried by every forward envelope.
pub const MESH_FORWARD_SCHEMA_VERSION: &str = "fcp.mesh.forward.v1";
/// Schema tag carried by every forward reply.
pub const MESH_FORWARD_REPLY_SCHEMA_VERSION: &str = "fcp.mesh.forward-reply.v1";
/// Schema tag carried by every peer advertisement.
pub const MESH_PEER_ADVERTISEMENT_SCHEMA_VERSION: &str = "fcp.mesh.peer-advertisement.v1";

/// Maximum number of mesh hops between the entry node and the executor.
pub const MAX_MESH_FORWARD_HOPS: u8 = 1;
/// Default tolerated clock skew (and replay window) for forward envelopes.
pub const DEFAULT_MESH_FORWARD_MAX_SKEW_MS: u64 = 30_000;
/// Default number of unexpired nonces a replay guard tracks.
pub const DEFAULT_MESH_FORWARD_REPLAY_CAPACITY: usize = 16_384;
/// Maximum accepted age of a peer advertisement.
pub const DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS: u64 = 5 * 60_000;
/// Hard cap on the forwarded request body (bytes of JSON).
pub const MAX_MESH_FORWARD_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Hard cap on connectors listed in one advertisement.
pub const MAX_ADVERTISED_CONNECTORS: usize = 4096;

const FORWARD_SIGNING_CONTEXT: &[u8] = b"FCP-MESH-FORWARD-REQUEST-V1";
const REPLY_SIGNING_CONTEXT: &[u8] = b"FCP-MESH-FORWARD-REPLY-V1";
const ADVERTISEMENT_SIGNING_CONTEXT: &[u8] = b"FCP-MESH-PEER-ADVERTISEMENT-V1";
const ADVERTISED_ROUTE_SUBJECT_DOMAIN: &[u8] = b"FCP-MESH-ADVERTISED-CONNECTOR-ROUTE-V1";
const NONCE_BYTES: usize = 16;

/// Errors raised while building, verifying, or routing mesh forwards.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeshForwardError {
    /// The peer directory configuration is malformed.
    #[error("invalid mesh peer directory: {0}")]
    InvalidDirectory(String),
    /// The envelope names a schema this node does not speak.
    #[error("unsupported mesh forward schema `{actual}` (expected `{expected}`)")]
    SchemaMismatch {
        /// Schema the node expected.
        expected: &'static str,
        /// Schema the envelope carried.
        actual: String,
    },
    /// The envelope was addressed to a different node.
    #[error("mesh forward addressed to `{target}`, but this node is `{local}`")]
    WrongTarget {
        /// Node the envelope targeted.
        target: String,
        /// This node.
        local: String,
    },
    /// The signer is not in the peer directory.
    #[error("mesh peer `{0}` is not in the local peer directory")]
    UnknownPeer(String),
    /// The signature did not verify against the peer's directory key.
    #[error("mesh {what} signature from `{peer}` failed verification")]
    SignatureInvalid {
        /// Which artifact failed (`forward`, `reply`, `advertisement`).
        what: &'static str,
        /// Claimed signer.
        peer: String,
    },
    /// The signature or nonce field was not well-formed hex of the right size.
    #[error("malformed mesh {field}: {detail}")]
    Malformed {
        /// Field name.
        field: &'static str,
        /// What was wrong.
        detail: String,
    },
    /// The envelope exceeded the hop limit.
    #[error("mesh forward hop_count {hop_count} exceeds limit {limit}")]
    HopLimitExceeded {
        /// Hops claimed by the envelope.
        hop_count: u8,
        /// Configured limit.
        limit: u8,
    },
    /// The envelope timestamp is outside the freshness window.
    #[error(
        "mesh {what} issued_at {issued_at_ms} is outside the {window_ms} ms window around {now_ms}"
    )]
    Stale {
        /// Which artifact was stale.
        what: &'static str,
        /// Envelope timestamp.
        issued_at_ms: u64,
        /// Local clock.
        now_ms: u64,
        /// Accepted window.
        window_ms: u64,
    },
    /// The `(origin, nonce)` pair was already accepted.
    #[error("mesh forward nonce from `{origin}` was already accepted (replay)")]
    Replayed {
        /// Origin node of the replayed envelope.
        origin: String,
    },
    /// The replay cache is full of unexpired nonces; fail closed.
    #[error("mesh forward replay cache saturated ({capacity} unexpired nonces)")]
    ReplayCacheSaturated {
        /// Cache capacity.
        capacity: usize,
    },
    /// A reply did not bind to the request it claims to answer.
    #[error("mesh forward reply binding mismatch: {0}")]
    ReplyBindingMismatch(String),
    /// The body exceeded [`MAX_MESH_FORWARD_BODY_BYTES`].
    #[error("mesh forward body is {len} bytes (limit {limit})")]
    BodyTooLarge {
        /// Body length.
        len: usize,
        /// Limit.
        limit: usize,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer directory
// ─────────────────────────────────────────────────────────────────────────────

/// One trusted mesh peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPeer {
    /// Mesh node id (Tailscale node id in production).
    pub node_id: TailscaleNodeId,
    /// Base URL of the peer's host RPC surface (`http(s)://host:port`).
    pub endpoint: String,
    /// Key that authenticates the peer's forwards, replies, and advertisements.
    pub verifying_key: Ed25519VerifyingKey,
}

/// Wire shape of one peer in the directory configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshPeerConfig {
    /// Mesh node id.
    pub node_id: String,
    /// Base URL of the peer's host RPC surface.
    pub endpoint: String,
    /// Hex-encoded 32-byte Ed25519 verifying key.
    pub public_key_hex: String,
}

/// The set of peers this node trusts for mesh forwarding.
#[derive(Debug, Clone)]
pub struct MeshPeerDirectory {
    local_node: TailscaleNodeId,
    peers: BTreeMap<String, MeshPeer>,
}

impl MeshPeerDirectory {
    /// Build a directory from parsed peer configs.
    ///
    /// The local node may appear in the list (operators commonly ship one
    /// shared peer file to every node); it is skipped rather than treated as a
    /// forwarding target.
    ///
    /// # Errors
    ///
    /// Returns [`MeshForwardError::InvalidDirectory`] for invalid node ids,
    /// endpoints that are not `http`/`https` URLs, malformed keys, or
    /// duplicate node ids.
    pub fn from_configs(
        local_node: TailscaleNodeId,
        configs: &[MeshPeerConfig],
    ) -> Result<Self, MeshForwardError> {
        let mut peers = BTreeMap::new();
        for config in configs {
            let node_id = TailscaleNodeId::try_new(config.node_id.trim()).map_err(|error| {
                MeshForwardError::InvalidDirectory(format!(
                    "peer node id `{}` is invalid: {error}",
                    config.node_id
                ))
            })?;
            let endpoint = normalize_endpoint(&config.endpoint)?;
            let verifying_key =
                parse_verifying_key_hex(&config.public_key_hex).map_err(|detail| {
                    MeshForwardError::InvalidDirectory(format!(
                        "peer `{}` public_key_hex is invalid: {detail}",
                        node_id.as_str()
                    ))
                })?;
            if node_id == local_node {
                continue;
            }
            let key = node_id.as_str().to_owned();
            if peers.contains_key(&key) {
                return Err(MeshForwardError::InvalidDirectory(format!(
                    "peer `{key}` is listed more than once"
                )));
            }
            peers.insert(
                key,
                MeshPeer {
                    node_id,
                    endpoint,
                    verifying_key,
                },
            );
        }
        Ok(Self { local_node, peers })
    }

    /// Parse a JSON array of [`MeshPeerConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`MeshForwardError::InvalidDirectory`] for malformed JSON or
    /// any error from [`Self::from_configs`].
    pub fn from_json(local_node: TailscaleNodeId, json: &str) -> Result<Self, MeshForwardError> {
        let configs: Vec<MeshPeerConfig> = serde_json::from_str(json).map_err(|error| {
            MeshForwardError::InvalidDirectory(format!("peer list is not valid JSON: {error}"))
        })?;
        Self::from_configs(local_node, &configs)
    }

    /// This node's id.
    #[must_use]
    pub const fn local_node(&self) -> &TailscaleNodeId {
        &self.local_node
    }

    /// Look up a peer.
    #[must_use]
    pub fn peer(&self, node_id: &TailscaleNodeId) -> Option<&MeshPeer> {
        self.peers.get(node_id.as_str())
    }

    /// Iterate peers in node-id order.
    pub fn peers(&self) -> impl Iterator<Item = &MeshPeer> {
        self.peers.values()
    }

    /// Number of remote peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the directory has no remote peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    fn verifying_key(
        &self,
        node_id: &TailscaleNodeId,
    ) -> Result<&Ed25519VerifyingKey, MeshForwardError> {
        self.peer(node_id)
            .map(|peer| &peer.verifying_key)
            .ok_or_else(|| MeshForwardError::UnknownPeer(node_id.as_str().to_owned()))
    }
}

fn normalize_endpoint(raw: &str) -> Result<String, MeshForwardError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .ok_or_else(|| {
            MeshForwardError::InvalidDirectory(format!(
                "peer endpoint `{raw}` must start with http:// or https://"
            ))
        })?;
    if rest.is_empty() || rest.contains(['/', '?', '#', ' ', '@']) {
        return Err(MeshForwardError::InvalidDirectory(format!(
            "peer endpoint `{raw}` must be a bare scheme://host[:port] base URL"
        )));
    }
    Ok(trimmed.to_owned())
}

fn parse_verifying_key_hex(raw: &str) -> Result<Ed25519VerifyingKey, String> {
    let bytes = hex::decode(raw.trim()).map_err(|error| format!("not hex: {error}"))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 32 bytes, got {}", bytes.len()))?;
    Ed25519VerifyingKey::from_bytes(&array).map_err(|error| error.to_string())
}

fn decode_signature_hex(raw: &str) -> Result<Ed25519Signature, MeshForwardError> {
    let bytes = hex::decode(raw).map_err(|error| MeshForwardError::Malformed {
        field: "signature",
        detail: format!("not hex: {error}"),
    })?;
    Ed25519Signature::try_from_slice(&bytes).map_err(|error| MeshForwardError::Malformed {
        field: "signature",
        detail: error.to_string(),
    })
}

fn validate_nonce_hex(raw: &str) -> Result<(), MeshForwardError> {
    let bytes = hex::decode(raw).map_err(|error| MeshForwardError::Malformed {
        field: "nonce",
        detail: format!("not hex: {error}"),
    })?;
    if bytes.len() != NONCE_BYTES {
        return Err(MeshForwardError::Malformed {
            field: "nonce",
            detail: format!("expected {NONCE_BYTES} bytes, got {}", bytes.len()),
        });
    }
    Ok(())
}

/// Generate a fresh random forward nonce (hex of 16 random bytes).
#[must_use]
pub fn fresh_forward_nonce() -> String {
    hex::encode(rand::random::<[u8; NONCE_BYTES]>())
}

// Length-prefixed canonical encoder for signing payloads.
struct SigningBytes(Vec<u8>);

impl SigningBytes {
    const fn new() -> Self {
        Self(Vec::new())
    }

    fn field(&mut self, bytes: &[u8]) -> &mut Self {
        self.0
            .extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    fn opt_field(&mut self, bytes: Option<&[u8]>) -> &mut Self {
        if let Some(bytes) = bytes {
            self.0.push(1);
            self.field(bytes)
        } else {
            self.0.push(0);
            self
        }
    }

    fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

fn check_freshness(
    what: &'static str,
    issued_at_ms: u64,
    now_ms: u64,
    window_ms: u64,
) -> Result<(), MeshForwardError> {
    if issued_at_ms.abs_diff(now_ms) > window_ms {
        return Err(MeshForwardError::Stale {
            what,
            issued_at_ms,
            now_ms,
            window_ms,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Forward envelope
// ─────────────────────────────────────────────────────────────────────────────

/// The operation a forward asks the target node to perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum MeshForwardBody {
    /// Execute an `InvokeRequest`. `request_json` is the exact signed JSON.
    Invoke {
        /// JSON-encoded `InvokeRequest`, exactly as signed by the origin.
        request_json: String,
        /// Principal the client asserted to the entry node (`X-Principal`),
        /// re-checked against the capability token by the executor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        asserted_principal: Option<String>,
    },
    /// Evaluate the host preflight for a would-be invoke without executing.
    Preflight {
        /// JSON-encoded host preflight request, exactly as signed.
        request_json: String,
        /// Principal the client asserted to the entry node.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        asserted_principal: Option<String>,
    },
    /// Return the connector's introspection document.
    Introspect {
        /// Canonical connector id.
        connector_id: String,
    },
}

impl MeshForwardBody {
    /// Stable method label.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Invoke { .. } => "invoke",
            Self::Preflight { .. } => "preflight",
            Self::Introspect { .. } => "introspect",
        }
    }

    fn encode_into(&self, out: &mut SigningBytes) {
        out.field(self.method().as_bytes());
        match self {
            Self::Invoke {
                request_json,
                asserted_principal,
            }
            | Self::Preflight {
                request_json,
                asserted_principal,
            } => {
                out.field(request_json.as_bytes())
                    .opt_field(asserted_principal.as_deref().map(str::as_bytes));
            }
            Self::Introspect { connector_id } => {
                out.field(connector_id.as_bytes());
            }
        }
    }

    fn body_len(&self) -> usize {
        match self {
            Self::Invoke {
                request_json,
                asserted_principal,
            }
            | Self::Preflight {
                request_json,
                asserted_principal,
            } => request_json.len() + asserted_principal.as_ref().map_or(0, String::len),
            Self::Introspect { connector_id } => connector_id.len(),
        }
    }
}

/// A signed request from one mesh node asking another to execute an RPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshForwardEnvelope {
    /// Always [`MESH_FORWARD_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Node that accepted the client request and signed this envelope.
    pub origin_node: TailscaleNodeId,
    /// Node asked to execute the request.
    pub target_node: TailscaleNodeId,
    /// Hops taken so far (1 for a direct forward).
    pub hop_count: u8,
    /// Origin wall-clock time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// 16 random bytes, hex; `(origin_node, nonce)` is single-use.
    pub nonce: String,
    /// Requested operation.
    pub body: MeshForwardBody,
    /// Hex Ed25519 signature by `origin_node` over the canonical bytes.
    pub signature: String,
}

impl MeshForwardEnvelope {
    /// Sign a new single-hop forward from `directory.local_node()` to `target`.
    ///
    /// # Errors
    ///
    /// Returns [`MeshForwardError::BodyTooLarge`] when the body exceeds
    /// [`MAX_MESH_FORWARD_BODY_BYTES`].
    pub fn sign(
        signing_key: &Ed25519SigningKey,
        origin_node: TailscaleNodeId,
        target_node: TailscaleNodeId,
        issued_at_ms: u64,
        body: MeshForwardBody,
    ) -> Result<Self, MeshForwardError> {
        let len = body.body_len();
        if len > MAX_MESH_FORWARD_BODY_BYTES {
            return Err(MeshForwardError::BodyTooLarge {
                len,
                limit: MAX_MESH_FORWARD_BODY_BYTES,
            });
        }
        let mut envelope = Self {
            schema_version: MESH_FORWARD_SCHEMA_VERSION.to_owned(),
            origin_node,
            target_node,
            hop_count: 1,
            issued_at_ms,
            nonce: fresh_forward_nonce(),
            body,
            signature: String::new(),
        };
        envelope.signature = signing_key
            .sign_with_context(FORWARD_SIGNING_CONTEXT, &envelope.signing_bytes())
            .to_hex();
        Ok(envelope)
    }

    /// Canonical bytes covered by the signature.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = SigningBytes::new();
        out.field(self.schema_version.as_bytes())
            .field(self.origin_node.as_str().as_bytes())
            .field(self.target_node.as_str().as_bytes())
            .u64(u64::from(self.hop_count))
            .u64(self.issued_at_ms)
            .field(self.nonce.as_bytes());
        self.body.encode_into(&mut out);
        out.finish()
    }

    /// Verify the envelope as the receiving node: schema, addressing, hop
    /// limit, size, freshness, and the origin's signature. Replay is checked
    /// separately by [`MeshForwardReplayGuard`] so callers can verify before
    /// consuming a nonce slot.
    ///
    /// # Errors
    ///
    /// Returns the first [`MeshForwardError`] that applies.
    pub fn verify(
        &self,
        directory: &MeshPeerDirectory,
        now_ms: u64,
        max_skew_ms: u64,
    ) -> Result<(), MeshForwardError> {
        if self.schema_version != MESH_FORWARD_SCHEMA_VERSION {
            return Err(MeshForwardError::SchemaMismatch {
                expected: MESH_FORWARD_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if &self.target_node != directory.local_node() {
            return Err(MeshForwardError::WrongTarget {
                target: self.target_node.as_str().to_owned(),
                local: directory.local_node().as_str().to_owned(),
            });
        }
        if self.hop_count == 0 || self.hop_count > MAX_MESH_FORWARD_HOPS {
            return Err(MeshForwardError::HopLimitExceeded {
                hop_count: self.hop_count,
                limit: MAX_MESH_FORWARD_HOPS,
            });
        }
        let len = self.body.body_len();
        if len > MAX_MESH_FORWARD_BODY_BYTES {
            return Err(MeshForwardError::BodyTooLarge {
                len,
                limit: MAX_MESH_FORWARD_BODY_BYTES,
            });
        }
        validate_nonce_hex(&self.nonce)?;
        let key = directory.verifying_key(&self.origin_node)?;
        let signature = decode_signature_hex(&self.signature)?;
        key.verify_with_context(FORWARD_SIGNING_CONTEXT, &self.signing_bytes(), &signature)
            .map_err(|_| MeshForwardError::SignatureInvalid {
                what: "forward",
                peer: self.origin_node.as_str().to_owned(),
            })?;
        check_freshness("forward", self.issued_at_ms, now_ms, max_skew_ms)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Forward reply
// ─────────────────────────────────────────────────────────────────────────────

/// Signed answer from the executing node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshForwardReply {
    /// Always [`MESH_FORWARD_REPLY_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Node that executed the request.
    pub served_by: TailscaleNodeId,
    /// Origin node of the request being answered.
    pub origin_node: TailscaleNodeId,
    /// Nonce of the request being answered.
    pub request_nonce: String,
    /// HTTP-equivalent status of local execution on `served_by`.
    pub status: u16,
    /// JSON body: the `InvokeResponse`/introspection on success, or an error
    /// string on failure.
    pub body_json: String,
    /// Hex Ed25519 signature by `served_by` over the canonical bytes.
    pub signature: String,
}

impl MeshForwardReply {
    /// Sign a reply to `request`.
    #[must_use]
    pub fn sign(
        signing_key: &Ed25519SigningKey,
        served_by: TailscaleNodeId,
        request: &MeshForwardEnvelope,
        status: u16,
        body_json: String,
    ) -> Self {
        let mut reply = Self {
            schema_version: MESH_FORWARD_REPLY_SCHEMA_VERSION.to_owned(),
            served_by,
            origin_node: request.origin_node.clone(),
            request_nonce: request.nonce.clone(),
            status,
            body_json,
            signature: String::new(),
        };
        reply.signature = signing_key
            .sign_with_context(REPLY_SIGNING_CONTEXT, &reply.signing_bytes())
            .to_hex();
        reply
    }

    /// Canonical bytes covered by the signature.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        SigningBytes::new()
            .field(self.schema_version.as_bytes())
            .field(self.served_by.as_str().as_bytes())
            .field(self.origin_node.as_str().as_bytes())
            .field(self.request_nonce.as_bytes())
            .u64(u64::from(self.status))
            .field(self.body_json.as_bytes())
            .finish()
    }

    /// Verify the reply as the origin node: it must come from the node the
    /// request targeted, answer this exact request, and carry that node's
    /// signature.
    ///
    /// # Errors
    ///
    /// Returns [`MeshForwardError::ReplyBindingMismatch`] when the reply
    /// answers a different request or comes from a different node, or a
    /// signature/schema error.
    pub fn verify_for(
        &self,
        request: &MeshForwardEnvelope,
        directory: &MeshPeerDirectory,
    ) -> Result<(), MeshForwardError> {
        if self.schema_version != MESH_FORWARD_REPLY_SCHEMA_VERSION {
            return Err(MeshForwardError::SchemaMismatch {
                expected: MESH_FORWARD_REPLY_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if self.served_by != request.target_node {
            return Err(MeshForwardError::ReplyBindingMismatch(format!(
                "reply served_by `{}` but request targeted `{}`",
                self.served_by.as_str(),
                request.target_node.as_str()
            )));
        }
        let answers_origin = self.origin_node == request.origin_node;
        let answers_nonce = self.request_nonce == request.nonce;
        if !(answers_origin && answers_nonce) {
            return Err(MeshForwardError::ReplyBindingMismatch(
                "reply does not answer this request (origin/nonce differ)".to_owned(),
            ));
        }
        let key = directory.verifying_key(&self.served_by)?;
        let signature = decode_signature_hex(&self.signature)?;
        key.verify_with_context(REPLY_SIGNING_CONTEXT, &self.signing_bytes(), &signature)
            .map_err(|_| MeshForwardError::SignatureInvalid {
                what: "reply",
                peer: self.served_by.as_str().to_owned(),
            })
    }

    /// Whether the executor reported success.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay guard
// ─────────────────────────────────────────────────────────────────────────────

/// Freshness-window nonce cache for inbound forwards.
///
/// An envelope is accepted at most once per `(origin, nonce)`. Entries expire
/// once they fall outside the freshness window (after which the envelope
/// would be rejected as stale anyway). When the cache is full of unexpired
/// entries the guard fails closed rather than forgetting a live nonce.
#[derive(Debug)]
pub struct MeshForwardReplayGuard {
    window_ms: u64,
    capacity: usize,
    seen: HashMap<(String, String), u64>,
    order: VecDeque<(u64, String, String)>,
}

impl MeshForwardReplayGuard {
    /// Create a guard with the given window and capacity.
    #[must_use]
    pub fn new(window_ms: u64, capacity: usize) -> Self {
        Self {
            window_ms,
            capacity: capacity.max(1),
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Number of tracked nonces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the guard tracks no nonces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn evict_expired(&mut self, now_ms: u64) {
        // Entries are recorded with their local acceptance time, so the
        // deque is ordered and we can pop from the front.
        while let Some((accepted_at, _, _)) = self.order.front() {
            if now_ms.saturating_sub(*accepted_at) <= self.window_ms.saturating_mul(2) {
                break;
            }
            if let Some((_, origin, nonce)) = self.order.pop_front() {
                self.seen.remove(&(origin, nonce));
            }
        }
    }

    /// Record `envelope`'s nonce, rejecting replays.
    ///
    /// # Errors
    ///
    /// Returns [`MeshForwardError::Replayed`] for a repeated nonce or
    /// [`MeshForwardError::ReplayCacheSaturated`] when full.
    pub fn check_and_record(
        &mut self,
        envelope: &MeshForwardEnvelope,
        now_ms: u64,
    ) -> Result<(), MeshForwardError> {
        self.evict_expired(now_ms);
        let key = (
            envelope.origin_node.as_str().to_owned(),
            envelope.nonce.clone(),
        );
        if self.seen.contains_key(&key) {
            return Err(MeshForwardError::Replayed { origin: key.0 });
        }
        if self.seen.len() >= self.capacity {
            return Err(MeshForwardError::ReplayCacheSaturated {
                capacity: self.capacity,
            });
        }
        self.seen.insert(key.clone(), now_ms);
        self.order.push_back((now_ms, key.0, key.1));
        Ok(())
    }
}

impl Default for MeshForwardReplayGuard {
    fn default() -> Self {
        Self::new(
            DEFAULT_MESH_FORWARD_MAX_SKEW_MS,
            DEFAULT_MESH_FORWARD_REPLAY_CAPACITY,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer advertisements
// ─────────────────────────────────────────────────────────────────────────────

/// A connector a peer can execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvertisedConnector {
    /// Canonical connector id.
    pub connector_id: String,
    /// Zones the connector is bound to on that peer (`allowed_zones`).
    pub zones: Vec<String>,
    /// Whether the connector is a `singleton_writer`.
    #[serde(default)]
    pub singleton_writer: bool,
    /// Host discovery summary (`ConnectorSummary` JSON) so entry nodes can
    /// list peer-executed connectors in their own catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_json: Option<String>,
}

/// Signed inventory of the connectors a node can execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshPeerAdvertisement {
    /// Always [`MESH_PEER_ADVERTISEMENT_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Advertising node.
    pub node_id: TailscaleNodeId,
    /// Unix milliseconds when the advertisement was produced.
    pub issued_at_ms: u64,
    /// Connectors this node executes, sorted by id.
    pub connectors: Vec<AdvertisedConnector>,
    /// Hex Ed25519 signature by `node_id`.
    pub signature: String,
}

impl MeshPeerAdvertisement {
    /// Sign an advertisement for `node_id`. Connectors are sorted and their
    /// zone lists deduplicated so the signed bytes are canonical.
    #[must_use]
    pub fn sign(
        signing_key: &Ed25519SigningKey,
        node_id: TailscaleNodeId,
        issued_at_ms: u64,
        mut connectors: Vec<AdvertisedConnector>,
    ) -> Self {
        for connector in &mut connectors {
            connector.zones.sort();
            connector.zones.dedup();
        }
        connectors.sort_by(|left, right| left.connector_id.cmp(&right.connector_id));
        connectors.dedup_by(|left, right| left.connector_id == right.connector_id);
        connectors.truncate(MAX_ADVERTISED_CONNECTORS);
        let mut advertisement = Self {
            schema_version: MESH_PEER_ADVERTISEMENT_SCHEMA_VERSION.to_owned(),
            node_id,
            issued_at_ms,
            connectors,
            signature: String::new(),
        };
        advertisement.signature = signing_key
            .sign_with_context(
                ADVERTISEMENT_SIGNING_CONTEXT,
                &advertisement.signing_bytes(),
            )
            .to_hex();
        advertisement
    }

    /// Canonical bytes covered by the signature.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = SigningBytes::new();
        out.field(self.schema_version.as_bytes())
            .field(self.node_id.as_str().as_bytes())
            .u64(self.issued_at_ms)
            .u64(u64::try_from(self.connectors.len()).unwrap_or(u64::MAX));
        for connector in &self.connectors {
            out.field(connector.connector_id.as_bytes())
                .u64(u64::from(connector.singleton_writer))
                .u64(u64::try_from(connector.zones.len()).unwrap_or(u64::MAX));
            for zone in &connector.zones {
                out.field(zone.as_bytes());
            }
            out.opt_field(connector.summary_json.as_deref().map(str::as_bytes));
        }
        out.finish()
    }

    /// Verify an advertisement fetched from `expected_node`.
    ///
    /// # Errors
    ///
    /// Returns an error when the advertisement claims another node, is too
    /// old or from the future, lists too many connectors, or is not signed by
    /// the directory key of `expected_node`.
    pub fn verify(
        &self,
        expected_node: &TailscaleNodeId,
        directory: &MeshPeerDirectory,
        now_ms: u64,
        max_age_ms: u64,
    ) -> Result<(), MeshForwardError> {
        if self.schema_version != MESH_PEER_ADVERTISEMENT_SCHEMA_VERSION {
            return Err(MeshForwardError::SchemaMismatch {
                expected: MESH_PEER_ADVERTISEMENT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        if &self.node_id != expected_node {
            return Err(MeshForwardError::ReplyBindingMismatch(format!(
                "advertisement from `{}` claims node `{}`",
                expected_node.as_str(),
                self.node_id.as_str()
            )));
        }
        if self.connectors.len() > MAX_ADVERTISED_CONNECTORS {
            return Err(MeshForwardError::Malformed {
                field: "connectors",
                detail: format!(
                    "{} connectors exceeds limit {MAX_ADVERTISED_CONNECTORS}",
                    self.connectors.len()
                ),
            });
        }
        let key = directory.verifying_key(&self.node_id)?;
        let signature = decode_signature_hex(&self.signature)?;
        key.verify_with_context(
            ADVERTISEMENT_SIGNING_CONTEXT,
            &self.signing_bytes(),
            &signature,
        )
        .map_err(|_| MeshForwardError::SignatureInvalid {
            what: "advertisement",
            peer: self.node_id.as_str().to_owned(),
        })?;
        check_freshness("advertisement", self.issued_at_ms, now_ms, max_age_ms)
    }

    /// Whether this advertisement offers `connector_id` in `zone_id`.
    #[must_use]
    pub fn offers(&self, connector_id: &str, zone_id: &ZoneId) -> bool {
        self.connector(connector_id)
            .is_some_and(|connector| connector.zones.iter().any(|zone| zone == zone_id.as_str()))
    }

    /// The advertised entry for `connector_id`, if any.
    #[must_use]
    pub fn connector(&self, connector_id: &str) -> Option<&AdvertisedConnector> {
        self.connectors
            .iter()
            .find(|connector| connector.connector_id == connector_id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Routing decisions
// ─────────────────────────────────────────────────────────────────────────────

/// Stable decision codes stamped into route provenance.
pub mod decision_codes {
    /// Request arrived over the mesh; executors never re-forward.
    pub const ARRIVED_VIA_MESH: &str = "arrived_via_mesh";
    /// This node is the HRW-elected holder.
    pub const LOCAL_IS_HRW_HOLDER: &str = "local_is_hrw_holder";
    /// Forwarded to the HRW-elected holder.
    pub const HRW_HOLDER_FORWARD: &str = "hrw_holder_forward";
    /// The elected holder is not in the peer directory; execute locally
    /// (the host's HRW gate will refuse with the holder's identity).
    pub const HRW_HOLDER_NOT_IN_DIRECTORY: &str = "hrw_holder_not_in_directory";
    /// No eligible holder exists.
    pub const NO_ELIGIBLE_HOLDER: &str = "no_eligible_holder";
    /// The connector is installed locally and not singleton-scoped.
    pub const LOCAL_CONNECTOR: &str = "local_connector";
    /// Forwarded to an advertising peer.
    pub const ADVERTISED_PEER_FORWARD: &str = "advertised_peer_forward";
    /// No peer advertises the connector; execute locally (and fail there).
    pub const NO_ADVERTISING_PEER: &str = "no_advertising_peer";
}

/// Outcome of a routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvokeRouteDecision {
    /// Execute on this node.
    Local {
        /// Stable decision code (see [`decision_codes`]).
        code: &'static str,
    },
    /// Forward to `target`; on a pre-transmission failure the caller may try
    /// `alternates` in order (only when the rule allows alternates).
    Forward {
        /// First choice.
        target: TailscaleNodeId,
        /// Ordered fallbacks (empty for singleton writers: exactly one node
        /// may execute).
        alternates: Vec<TailscaleNodeId>,
        /// Stable decision code (see [`decision_codes`]).
        code: &'static str,
    },
}

impl InvokeRouteDecision {
    /// Decision code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Local { code } | Self::Forward { code, .. } => code,
        }
    }

    /// Whether the decision forwards.
    #[must_use]
    pub const fn is_forward(&self) -> bool {
        matches!(self, Self::Forward { .. })
    }
}

/// Route a `singleton_writer` request to its HRW-elected lease holder.
///
/// Uses the same election as the host's admission gate
/// ([`crate::planner::admit_lease_holder`]) so the forward target is exactly
/// the node that will admit the request. `arrived_hop_count > 0` means the
/// request came over the mesh and must execute locally.
#[must_use]
pub fn decide_singleton_writer_route(
    directory: &MeshPeerDirectory,
    zone_id: &ZoneId,
    subject_id: &ObjectId,
    eligible_nodes: &[TailscaleNodeId],
    arrived_hop_count: u8,
) -> InvokeRouteDecision {
    if arrived_hop_count > 0 {
        return InvokeRouteDecision::Local {
            code: decision_codes::ARRIVED_VIA_MESH,
        };
    }
    let Some(holder) = select_lease_holder(zone_id, subject_id, eligible_nodes) else {
        return InvokeRouteDecision::Local {
            code: decision_codes::NO_ELIGIBLE_HOLDER,
        };
    };
    if &holder == directory.local_node() {
        return InvokeRouteDecision::Local {
            code: decision_codes::LOCAL_IS_HRW_HOLDER,
        };
    }
    if directory.peer(&holder).is_none() {
        return InvokeRouteDecision::Local {
            code: decision_codes::HRW_HOLDER_NOT_IN_DIRECTORY,
        };
    }
    InvokeRouteDecision::Forward {
        target: holder,
        alternates: Vec::new(),
        code: decision_codes::HRW_HOLDER_FORWARD,
    }
}

/// Deterministic routing subject for a non-singleton connector.
#[must_use]
pub fn advertised_connector_route_subject(connector_id: &str, zone_id: &ZoneId) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ADVERTISED_ROUTE_SUBJECT_DOMAIN);
    hasher.update(
        &u64::try_from(connector_id.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(connector_id.as_bytes());
    hasher.update(
        &u64::try_from(zone_id.as_str().len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(zone_id.as_str().as_bytes());
    ObjectId::from_bytes(*hasher.finalize().as_bytes())
}

/// Route a request for a connector that is not installed locally to one of
/// the peers whose verified advertisement offers it.
///
/// With `zone_id` set only peers that bind the connector to that zone are
/// candidates; with `None` (zone-less RPCs such as introspection) any
/// advertising peer is. Candidates are ranked by HRW over
/// `(connector, zone)` so every entry node picks the same first choice and the
/// same retry order. When any matching advertisement marks the connector
/// `singleton_writer`, the decision carries no alternates: exactly one node
/// may execute, and the executor's own HRW admission gate is authoritative.
#[must_use]
pub fn decide_advertised_connector_route(
    directory: &MeshPeerDirectory,
    connector_id: &str,
    zone_id: Option<&ZoneId>,
    advertisements: &[MeshPeerAdvertisement],
    arrived_hop_count: u8,
) -> InvokeRouteDecision {
    if arrived_hop_count > 0 {
        return InvokeRouteDecision::Local {
            code: decision_codes::ARRIVED_VIA_MESH,
        };
    }
    let mut singleton_writer = false;
    let candidates: Vec<TailscaleNodeId> = advertisements
        .iter()
        .filter(|advertisement| directory.peer(&advertisement.node_id).is_some())
        .filter_map(|advertisement| {
            let connector = advertisement.connectors.iter().find(|connector| {
                connector.connector_id == connector_id
                    && zone_id.is_none_or(|zone| connector.zones.iter().any(|z| z == zone.as_str()))
            })?;
            singleton_writer |= connector.singleton_writer;
            Some(advertisement.node_id.clone())
        })
        .collect();
    let ranking_zone = zone_id.cloned().unwrap_or_else(ZoneId::owner);
    let subject = advertised_connector_route_subject(connector_id, &ranking_zone);
    let mut ranked = rank_lease_holders_by_hrw(&ranking_zone, &subject, &candidates).into_iter();
    let Some(target) = ranked.next() else {
        return InvokeRouteDecision::Local {
            code: decision_codes::NO_ADVERTISING_PEER,
        };
    };
    InvokeRouteDecision::Forward {
        target,
        alternates: if singleton_writer {
            Vec::new()
        } else {
            ranked.collect()
        },
        code: decision_codes::ADVERTISED_PEER_FORWARD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::LeasePurpose;

    fn key() -> Ed25519SigningKey {
        Ed25519SigningKey::generate()
    }

    fn node(id: &str) -> TailscaleNodeId {
        TailscaleNodeId::new(id)
    }

    struct Mesh {
        keys: BTreeMap<String, Ed25519SigningKey>,
    }

    impl Mesh {
        fn new(nodes: &[&str]) -> Self {
            Self {
                keys: nodes.iter().map(|id| ((*id).to_owned(), key())).collect(),
            }
        }

        fn key(&self, id: &str) -> &Ed25519SigningKey {
            &self.keys[id]
        }

        fn configs(&self) -> Vec<MeshPeerConfig> {
            self.keys
                .iter()
                .enumerate()
                .map(|(index, (id, key))| MeshPeerConfig {
                    node_id: id.clone(),
                    endpoint: format!("http://127.0.0.1:{}", 9000 + index),
                    public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                })
                .collect()
        }

        fn directory(&self, local: &str) -> MeshPeerDirectory {
            MeshPeerDirectory::from_configs(node(local), &self.configs()).expect("directory")
        }
    }

    fn invoke_body() -> MeshForwardBody {
        MeshForwardBody::Invoke {
            request_json: r#"{"type":"invoke","input":{"b":1,"a":2}}"#.to_owned(),
            asserted_principal: Some("agent:test".to_owned()),
        }
    }

    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn directory_skips_local_node_and_rejects_duplicates() {
        let mesh = Mesh::new(&["node-a", "node-b", "node-c"]);
        let directory = mesh.directory("node-a");
        assert_eq!(directory.len(), 2);
        assert!(directory.peer(&node("node-a")).is_none());
        assert!(directory.peer(&node("node-b")).is_some());

        let mut configs = mesh.configs();
        configs.push(configs[1].clone());
        let error = MeshPeerDirectory::from_configs(node("node-a"), &configs).unwrap_err();
        assert!(
            matches!(error, MeshForwardError::InvalidDirectory(message) if message.contains("more than once"))
        );
    }

    #[test]
    fn directory_rejects_bad_endpoints_keys_and_ids() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        for endpoint in ["ftp://x", "http://", "http://h/path", "http://u@h", "h:1"] {
            let mut configs = mesh.configs();
            configs[1].endpoint = endpoint.to_owned();
            assert!(
                MeshPeerDirectory::from_configs(node("node-a"), &configs).is_err(),
                "endpoint {endpoint} must be rejected"
            );
        }
        let mut configs = mesh.configs();
        configs[1].public_key_hex = "abcd".to_owned();
        assert!(MeshPeerDirectory::from_configs(node("node-a"), &configs).is_err());
        let mut configs = mesh.configs();
        configs[1].node_id = "Node B".to_owned();
        assert!(MeshPeerDirectory::from_configs(node("node-a"), &configs).is_err());
        assert!(MeshPeerDirectory::from_json(node("node-a"), "not json").is_err());
    }

    #[test]
    fn directory_normalizes_trailing_slash() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        let mut configs = mesh.configs();
        configs[1].endpoint = "https://peer.tailnet:7443/".to_owned();
        let directory = MeshPeerDirectory::from_configs(node("node-a"), &configs).unwrap();
        assert_eq!(
            directory.peer(&node("node-b")).unwrap().endpoint,
            "https://peer.tailnet:7443"
        );
    }

    #[test]
    fn forward_round_trip_verifies_and_survives_json() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        let envelope = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            invoke_body(),
        )
        .unwrap();
        let wire = serde_json::to_string(&envelope).unwrap();
        let decoded: MeshForwardEnvelope = serde_json::from_str(&wire).unwrap();
        decoded
            .verify(
                &mesh.directory("node-b"),
                NOW + 1_000,
                DEFAULT_MESH_FORWARD_MAX_SKEW_MS,
            )
            .expect("valid forward must verify");
    }

    #[test]
    fn forward_rejects_tampering_in_every_signed_field() {
        let mesh = Mesh::new(&["node-a", "node-b", "node-c"]);
        let directory = mesh.directory("node-b");
        let envelope = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            invoke_body(),
        )
        .unwrap();

        let mut tampered = envelope.clone();
        tampered.body = MeshForwardBody::Invoke {
            request_json: r#"{"type":"invoke","input":{"b":1,"a":3}}"#.to_owned(),
            asserted_principal: Some("agent:test".to_owned()),
        };
        assert!(matches!(
            tampered.verify(&directory, NOW, 30_000),
            Err(MeshForwardError::SignatureInvalid { .. })
        ));

        let mut tampered = envelope.clone();
        tampered.body = MeshForwardBody::Invoke {
            request_json: r#"{"type":"invoke","input":{"b":1,"a":2}}"#.to_owned(),
            asserted_principal: Some("agent:root".to_owned()),
        };
        assert!(matches!(
            tampered.verify(&directory, NOW, 30_000),
            Err(MeshForwardError::SignatureInvalid { .. })
        ));

        let mut tampered = envelope.clone();
        tampered.issued_at_ms += 1;
        assert!(tampered.verify(&directory, NOW, 30_000).is_err());

        let mut tampered = envelope.clone();
        tampered.nonce = fresh_forward_nonce();
        assert!(tampered.verify(&directory, NOW, 30_000).is_err());

        // Origin spoofing: node-c claims node-a's envelope.
        let mut tampered = envelope.clone();
        tampered.origin_node = node("node-c");
        assert!(matches!(
            tampered.verify(&directory, NOW, 30_000),
            Err(MeshForwardError::SignatureInvalid { .. })
        ));

        // Signed by a key outside the directory.
        let rogue =
            MeshForwardEnvelope::sign(&key(), node("node-a"), node("node-b"), NOW, invoke_body())
                .unwrap();
        assert!(matches!(
            rogue.verify(&directory, NOW, 30_000),
            Err(MeshForwardError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn forward_method_is_bound_into_the_signature() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        let envelope = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            MeshForwardBody::Preflight {
                request_json: "{}".to_owned(),
                asserted_principal: None,
            },
        )
        .unwrap();
        let mut escalated = envelope.clone();
        escalated.body = MeshForwardBody::Invoke {
            request_json: "{}".to_owned(),
            asserted_principal: None,
        };
        assert!(matches!(
            escalated.verify(&mesh.directory("node-b"), NOW, 30_000),
            Err(MeshForwardError::SignatureInvalid { .. })
        ));
        envelope
            .verify(&mesh.directory("node-b"), NOW, 30_000)
            .expect("untampered preflight forward verifies");
    }

    #[test]
    fn forward_rejects_wrong_target_unknown_peer_hops_and_staleness() {
        let mesh = Mesh::new(&["node-a", "node-b", "node-c"]);
        let envelope = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            invoke_body(),
        )
        .unwrap();
        assert!(matches!(
            envelope.verify(&mesh.directory("node-c"), NOW, 30_000),
            Err(MeshForwardError::WrongTarget { .. })
        ));

        let outsider =
            MeshForwardEnvelope::sign(&key(), node("node-z"), node("node-b"), NOW, invoke_body())
                .unwrap();
        assert!(matches!(
            outsider.verify(&mesh.directory("node-b"), NOW, 30_000),
            Err(MeshForwardError::UnknownPeer(peer)) if peer == "node-z"
        ));

        let mut hopped = envelope.clone();
        hopped.hop_count = 2;
        assert!(matches!(
            hopped.verify(&mesh.directory("node-b"), NOW, 30_000),
            Err(MeshForwardError::HopLimitExceeded { .. })
        ));
        let mut zero = envelope.clone();
        zero.hop_count = 0;
        assert!(zero.verify(&mesh.directory("node-b"), NOW, 30_000).is_err());

        assert!(matches!(
            envelope.verify(&mesh.directory("node-b"), NOW + 30_001, 30_000),
            Err(MeshForwardError::Stale { .. })
        ));
        assert!(matches!(
            envelope.verify(&mesh.directory("node-b"), NOW - 30_001, 30_000),
            Err(MeshForwardError::Stale { .. })
        ));
        envelope
            .verify(&mesh.directory("node-b"), NOW + 30_000, 30_000)
            .expect("boundary of the window is accepted");
    }

    #[test]
    fn forward_rejects_oversized_bodies() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        let body = MeshForwardBody::Invoke {
            request_json: "x".repeat(MAX_MESH_FORWARD_BODY_BYTES + 1),
            asserted_principal: None,
        };
        assert!(matches!(
            MeshForwardEnvelope::sign(
                mesh.key("node-a"),
                node("node-a"),
                node("node-b"),
                NOW,
                body
            ),
            Err(MeshForwardError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn forward_rejects_malformed_signature_and_nonce() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        let directory = mesh.directory("node-b");
        let envelope = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            invoke_body(),
        )
        .unwrap();
        let mut bad = envelope.clone();
        bad.signature = "zz".to_owned();
        assert!(matches!(
            bad.verify(&directory, NOW, 30_000),
            Err(MeshForwardError::Malformed {
                field: "signature",
                ..
            })
        ));
        let mut bad = envelope;
        bad.nonce = "00".to_owned();
        assert!(matches!(
            bad.verify(&directory, NOW, 30_000),
            Err(MeshForwardError::Malformed { field: "nonce", .. })
        ));
    }

    #[test]
    fn reply_binds_to_request_and_executor() {
        let mesh = Mesh::new(&["node-a", "node-b", "node-c"]);
        let request = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            invoke_body(),
        )
        .unwrap();
        let origin_directory = mesh.directory("node-a");
        let reply = MeshForwardReply::sign(
            mesh.key("node-b"),
            node("node-b"),
            &request,
            200,
            r#"{"type":"response"}"#.to_owned(),
        );
        reply
            .verify_for(&request, &origin_directory)
            .expect("reply verifies");
        assert!(reply.is_success());

        let mut tampered = reply.clone();
        tampered.body_json = r#"{"type":"forged"}"#.to_owned();
        assert!(matches!(
            tampered.verify_for(&request, &origin_directory),
            Err(MeshForwardError::SignatureInvalid { .. })
        ));

        let mut tampered = reply.clone();
        tampered.status = 500;
        assert!(tampered.verify_for(&request, &origin_directory).is_err());

        // A validly-signed reply from a different node does not answer a
        // request that targeted node-b.
        let impostor = MeshForwardReply::sign(
            mesh.key("node-c"),
            node("node-c"),
            &request,
            200,
            r#"{"type":"response"}"#.to_owned(),
        );
        assert!(matches!(
            impostor.verify_for(&request, &origin_directory),
            Err(MeshForwardError::ReplyBindingMismatch(_))
        ));

        // A reply to another request cannot be replayed onto this one.
        let other_request = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            invoke_body(),
        )
        .unwrap();
        assert!(matches!(
            reply.verify_for(&other_request, &origin_directory),
            Err(MeshForwardError::ReplyBindingMismatch(_))
        ));
    }

    #[test]
    fn replay_guard_rejects_duplicates_and_fails_closed_when_full() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        let mut guard = MeshForwardReplayGuard::new(30_000, 2);
        let first = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            invoke_body(),
        )
        .unwrap();
        guard.check_and_record(&first, NOW).unwrap();
        assert!(matches!(
            guard.check_and_record(&first, NOW + 1),
            Err(MeshForwardError::Replayed { .. })
        ));
        let second = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            invoke_body(),
        )
        .unwrap();
        guard.check_and_record(&second, NOW + 2).unwrap();
        let third = MeshForwardEnvelope::sign(
            mesh.key("node-a"),
            node("node-a"),
            node("node-b"),
            NOW,
            invoke_body(),
        )
        .unwrap();
        assert!(matches!(
            guard.check_and_record(&third, NOW + 3),
            Err(MeshForwardError::ReplayCacheSaturated { capacity: 2 })
        ));
        // Once the earlier nonces age out of twice the window they are
        // evicted; an envelope that old is already rejected as stale.
        guard.check_and_record(&third, NOW + 60_003).unwrap();
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn advertisement_round_trip_and_tamper_detection() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        let advertisement = MeshPeerAdvertisement::sign(
            mesh.key("node-b"),
            node("node-b"),
            NOW,
            vec![
                AdvertisedConnector {
                    connector_id: "fcp.zeta:utility:1.0.0".to_owned(),
                    zones: vec!["z:work".to_owned(), "z:work".to_owned()],
                    singleton_writer: false,
                    summary_json: None,
                },
                AdvertisedConnector {
                    connector_id: "fcp.alpha:utility:1.0.0".to_owned(),
                    zones: vec!["z:private".to_owned()],
                    singleton_writer: true,
                    summary_json: Some(r#"{"name":"alpha"}"#.to_owned()),
                },
            ],
        );
        assert_eq!(
            advertisement.connectors[0].connector_id,
            "fcp.alpha:utility:1.0.0"
        );
        assert_eq!(advertisement.connectors[1].zones, vec!["z:work".to_owned()]);
        let directory = mesh.directory("node-a");
        advertisement
            .verify(
                &node("node-b"),
                &directory,
                NOW + 10,
                DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS,
            )
            .unwrap();
        assert!(advertisement.offers("fcp.zeta:utility:1.0.0", &ZoneId::work()));
        assert!(!advertisement.offers("fcp.zeta:utility:1.0.0", &ZoneId::private()));

        let mut tampered = advertisement.clone();
        tampered.connectors[0].summary_json = Some(r#"{"name":"forged"}"#.to_owned());
        assert!(matches!(
            tampered.verify(&node("node-b"), &directory, NOW, 60_000),
            Err(MeshForwardError::SignatureInvalid { .. })
        ));

        let mut tampered = advertisement.clone();
        tampered.connectors[1].zones.push("z:owner".to_owned());
        assert!(matches!(
            tampered.verify(&node("node-b"), &directory, NOW, 60_000),
            Err(MeshForwardError::SignatureInvalid { .. })
        ));
        assert!(matches!(
            advertisement.verify(&node("node-c"), &directory, NOW, 60_000),
            Err(MeshForwardError::ReplyBindingMismatch(_))
        ));
        assert!(matches!(
            advertisement.verify(&node("node-b"), &directory, NOW + 60_001, 60_000),
            Err(MeshForwardError::Stale { .. })
        ));
    }

    #[test]
    fn singleton_route_forwards_to_the_same_holder_admission_elects() {
        let mesh = Mesh::new(&["node-a", "node-b", "node-c"]);
        let eligible = vec![node("node-a"), node("node-b"), node("node-c")];
        let zone = ZoneId::work();
        for seed in 0_u8..32 {
            let subject = ObjectId::from_bytes([seed; 32]);
            let holder = select_lease_holder(&zone, &subject, &eligible).unwrap();
            for local in ["node-a", "node-b", "node-c"] {
                let decision = decide_singleton_writer_route(
                    &mesh.directory(local),
                    &zone,
                    &subject,
                    &eligible,
                    0,
                );
                let admitted = crate::planner::admit_lease_holder(
                    &zone,
                    &subject,
                    LeasePurpose::ConnectorStateWrite,
                    &eligible,
                    &node(local),
                );
                if holder.as_str() == local {
                    assert_eq!(decision.code(), decision_codes::LOCAL_IS_HRW_HOLDER);
                    assert!(admitted.is_ok());
                } else {
                    assert!(admitted.is_err());
                    match decision {
                        InvokeRouteDecision::Forward {
                            target, alternates, ..
                        } => {
                            assert_eq!(target, holder);
                            assert!(alternates.is_empty(), "singleton writers never fan out");
                        }
                        InvokeRouteDecision::Local { code } => {
                            panic!("non-holder {local} must forward, got {code}")
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn singleton_route_never_reforwards_and_respects_directory() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        let eligible = vec![node("node-a"), node("node-b"), node("node-x")];
        let zone = ZoneId::work();
        let mut saw_missing_holder = false;
        for seed in 0_u8..64 {
            let subject = ObjectId::from_bytes([seed; 32]);
            assert_eq!(
                decide_singleton_writer_route(
                    &mesh.directory("node-a"),
                    &zone,
                    &subject,
                    &eligible,
                    1
                )
                .code(),
                decision_codes::ARRIVED_VIA_MESH
            );
            let holder = select_lease_holder(&zone, &subject, &eligible).unwrap();
            if holder.as_str() == "node-x" {
                saw_missing_holder = true;
                assert_eq!(
                    decide_singleton_writer_route(
                        &mesh.directory("node-a"),
                        &zone,
                        &subject,
                        &eligible,
                        0
                    )
                    .code(),
                    decision_codes::HRW_HOLDER_NOT_IN_DIRECTORY
                );
            }
        }
        assert!(
            saw_missing_holder,
            "64 subjects should elect node-x at least once"
        );
        assert_eq!(
            decide_singleton_writer_route(
                &mesh.directory("node-a"),
                &zone,
                &ObjectId::from_bytes([0; 32]),
                &[],
                0
            )
            .code(),
            decision_codes::NO_ELIGIBLE_HOLDER
        );
    }

    fn offering(
        mesh: &Mesh,
        id: &str,
        zones: &[&str],
        singleton_writer: bool,
    ) -> MeshPeerAdvertisement {
        MeshPeerAdvertisement::sign(
            mesh.key(id),
            node(id),
            NOW,
            vec![AdvertisedConnector {
                connector_id: "fcp.remote:utility:1.0.0".to_owned(),
                zones: zones.iter().map(|zone| (*zone).to_owned()).collect(),
                singleton_writer,
                summary_json: None,
            }],
        )
    }

    #[test]
    fn advertised_route_is_deterministic_across_entry_nodes() {
        let mesh = Mesh::new(&["node-a", "node-b", "node-c", "node-d"]);
        let advertisements = vec![
            offering(&mesh, "node-b", &["z:work"], false),
            offering(&mesh, "node-c", &["z:work"], false),
            offering(&mesh, "node-d", &["z:private"], false),
        ];
        let zone = ZoneId::work();
        let from_a = decide_advertised_connector_route(
            &mesh.directory("node-a"),
            "fcp.remote:utility:1.0.0",
            Some(&zone),
            &advertisements,
            0,
        );
        let InvokeRouteDecision::Forward {
            target,
            alternates,
            code,
        } = from_a.clone()
        else {
            panic!("expected forward, got {from_a:?}");
        };
        assert_eq!(code, decision_codes::ADVERTISED_PEER_FORWARD);
        let mut all = vec![target];
        all.extend(alternates.iter().cloned());
        all.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        assert_eq!(
            all,
            vec![node("node-b"), node("node-c")],
            "z:private-only peer excluded"
        );

        // node-d does not offer the connector in z:work but routes the same way.
        let from_d = decide_advertised_connector_route(
            &mesh.directory("node-d"),
            "fcp.remote:utility:1.0.0",
            Some(&zone),
            &advertisements,
            0,
        );
        assert_eq!(from_d, from_a);

        assert_eq!(
            decide_advertised_connector_route(
                &mesh.directory("node-a"),
                "fcp.unknown:utility:1.0.0",
                Some(&zone),
                &advertisements,
                0
            )
            .code(),
            decision_codes::NO_ADVERTISING_PEER
        );
        assert_eq!(
            decide_advertised_connector_route(
                &mesh.directory("node-a"),
                "fcp.remote:utility:1.0.0",
                Some(&zone),
                &advertisements,
                1
            )
            .code(),
            decision_codes::ARRIVED_VIA_MESH
        );
    }

    #[test]
    fn advertised_route_without_zone_considers_every_advertiser() {
        let mesh = Mesh::new(&["node-a", "node-b", "node-c"]);
        let advertisements = vec![
            offering(&mesh, "node-b", &["z:work"], false),
            offering(&mesh, "node-c", &["z:private"], false),
        ];
        let decision = decide_advertised_connector_route(
            &mesh.directory("node-a"),
            "fcp.remote:utility:1.0.0",
            None,
            &advertisements,
            0,
        );
        let InvokeRouteDecision::Forward {
            target, alternates, ..
        } = decision
        else {
            panic!("expected forward");
        };
        assert_eq!(alternates.len(), 1);
        assert_ne!(target, alternates[0]);
    }

    #[test]
    fn advertised_singleton_writer_route_never_fans_out() {
        let mesh = Mesh::new(&["node-a", "node-b", "node-c"]);
        let advertisements = vec![
            offering(&mesh, "node-b", &["z:work"], true),
            offering(&mesh, "node-c", &["z:work"], false),
        ];
        let decision = decide_advertised_connector_route(
            &mesh.directory("node-a"),
            "fcp.remote:utility:1.0.0",
            Some(&ZoneId::work()),
            &advertisements,
            0,
        );
        let InvokeRouteDecision::Forward { alternates, .. } = decision else {
            panic!("expected forward");
        };
        assert!(
            alternates.is_empty(),
            "singleton writers have exactly one executor"
        );
    }

    #[test]
    fn advertisements_from_peers_outside_the_directory_are_ignored() {
        let mesh = Mesh::new(&["node-a", "node-b"]);
        let outsider = Mesh::new(&["node-z"]);
        let advertisements = vec![offering(&outsider, "node-z", &["z:work"], false)];
        assert_eq!(
            decide_advertised_connector_route(
                &mesh.directory("node-a"),
                "fcp.remote:utility:1.0.0",
                Some(&ZoneId::work()),
                &advertisements,
                0
            )
            .code(),
            decision_codes::NO_ADVERTISING_PEER
        );
    }
}
