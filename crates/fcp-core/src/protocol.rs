//! Protocol types for FCP - wire format messages.
//!
//! Based on FCP Specification Section 9 (Wire Protocol).
//!
//! This module implements the canonical wire format as defined in the
//! FCP Specification V2. All types are designed to be serializable to
//! both JSON (for debugging) and CBOR (for production).

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crate::{
    ApprovalToken, CapabilityGrant, CapabilityId, CapabilityToken, ConnectorId, CorrelationId,
    EventAck, EventNack, FcpError, IdempotencyClass, InstanceId, ObjectId, OperationId, Provenance,
    ProvisioningProgress, ProvisioningRecipe, ProvisioningState, ProvisioningValidation, RecipeId,
    RiskLevel, SafetyTier, SessionId, SetupDescriptor, StepId, TailscaleNodeId, ZoneId,
};

// ─────────────────────────────────────────────────────────────────────────────
// Request ID (Wire Format)
// ─────────────────────────────────────────────────────────────────────────────

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Request identifier for correlation.
///
/// On the wire, this is a string like "`req_123`" or a UUID string.
/// The format is not prescribed; the Hub and connector just need to echo it back.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub String);

impl RequestId {
    /// Create a new request ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a new monotonic request ID.
    #[must_use]
    pub fn random() -> Self {
        let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        Self(format!("req_{sequence:020}"))
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<S: Into<String>> From<S> for RequestId {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

impl std::str::FromStr for RequestId {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host Fingerprint
// ─────────────────────────────────────────────────────────────────────────────

/// Stable host identity fingerprint.
///
/// The string form is `blake3:<64 lowercase hex chars>`, where the digest is a
/// BLAKE3 hash of host identity material under an FCP domain separator.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostFingerprint([u8; HOST_FINGERPRINT_DIGEST_LEN]);

const HOST_FINGERPRINT_DIGEST_LEN: usize = 32;

impl HostFingerprint {
    /// Algorithm prefix used in the human-facing fingerprint form.
    pub const PREFIX: &'static str = "blake3:";
    /// Digest length in bytes.
    pub const DIGEST_LEN: usize = HOST_FINGERPRINT_DIGEST_LEN;
    /// Digest length in lowercase hexadecimal characters.
    pub const HEX_LEN: usize = Self::DIGEST_LEN * 2;
    /// Full display length including the algorithm prefix.
    pub const DISPLAY_LEN: usize = Self::PREFIX.len() + Self::HEX_LEN;

    /// Construct a host fingerprint from raw digest bytes.
    #[must_use]
    pub const fn from_digest_bytes(bytes: [u8; Self::DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    /// Derive a host fingerprint from a host public key.
    #[must_use]
    pub fn from_host_public_key(host_public_key: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP-HOST-FINGERPRINT-V1");
        hasher.update(host_public_key);
        Self(*hasher.finalize().as_bytes())
    }

    /// Borrow the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::DIGEST_LEN] {
        &self.0
    }

    /// Parse a host fingerprint from its canonical string form.
    ///
    /// # Errors
    /// Returns [`HostFingerprintParseError`] when the prefix, hex length, case,
    /// or hex content is not canonical.
    pub fn parse(value: &str) -> Result<Self, HostFingerprintParseError> {
        let Some(hex_value) = value.strip_prefix(Self::PREFIX) else {
            return Err(HostFingerprintParseError::MissingPrefix);
        };

        if hex_value.len() != Self::HEX_LEN {
            return Err(HostFingerprintParseError::WrongLength {
                actual: hex_value.len(),
            });
        }

        if hex_value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(HostFingerprintParseError::UppercaseNotAllowed);
        }

        let bytes = hex::decode(hex_value).map_err(|_| HostFingerprintParseError::InvalidHex)?;
        let digest: [u8; Self::DIGEST_LEN] =
            bytes
                .try_into()
                .map_err(|bytes: Vec<u8>| HostFingerprintParseError::WrongLength {
                    actual: bytes.len() * 2,
                })?;
        Ok(Self(digest))
    }
}

impl fmt::Debug for HostFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HostFingerprint")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for HostFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", Self::PREFIX, hex::encode(self.0))
    }
}

impl std::str::FromStr for HostFingerprint {
    type Err = HostFingerprintParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for HostFingerprint {
    type Error = HostFingerprintParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<HostFingerprint> for String {
    fn from(fingerprint: HostFingerprint) -> Self {
        fingerprint.to_string()
    }
}

/// Parse failures for [`HostFingerprint`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostFingerprintParseError {
    /// The `blake3:` prefix is missing.
    #[error("host fingerprint must start with blake3:")]
    MissingPrefix,
    /// The hex digest has the wrong character length.
    #[error("host fingerprint hex digest must be 64 lowercase characters")]
    WrongLength {
        /// Actual hex character length after the prefix.
        actual: usize,
    },
    /// Uppercase hex is non-canonical.
    #[error("host fingerprint hex digest must be lowercase")]
    UppercaseNotAllowed,
    /// The digest contains non-hex characters.
    #[error("host fingerprint hex digest must be valid hex")]
    InvalidHex,
}

// ─────────────────────────────────────────────────────────────────────────────
// Handshake Messages (Section 9.10)
// ─────────────────────────────────────────────────────────────────────────────

/// Host information sent during handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// Host name (e.g., "flywheel-hub")
    pub name: String,

    /// Host version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Build identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
}

/// Transport capabilities for negotiation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportCaps {
    /// Supported compression algorithms (e.g., `zstd`, `lz4`)
    #[serde(default)]
    pub compression: Vec<String>,

    /// Maximum frame size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_frame_size: Option<u32>,
}

/// Documented default mesh heartbeat interval.
pub const DEFAULT_MESH_NODE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
/// Documented default maximum mesh peers.
pub const DEFAULT_MESH_NODE_MAX_PEERS: usize = 32;
/// Documented default mesh lease TTL.
pub const DEFAULT_MESH_NODE_LEASE_TTL: Duration = Duration::from_secs(300);

/// Shared mesh-node runtime configuration defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshNodeConfig {
    /// Interval between mesh-node heartbeats.
    pub heartbeat_interval: Duration,
    /// Maximum directly tracked peers for default mesh operations.
    pub max_peers: usize,
    /// Default lease time-to-live for mesh coordination.
    pub lease_ttl: Duration,
}

impl MeshNodeConfig {
    /// Create a config with the documented defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            heartbeat_interval: DEFAULT_MESH_NODE_HEARTBEAT_INTERVAL,
            max_peers: DEFAULT_MESH_NODE_MAX_PEERS,
            lease_ttl: DEFAULT_MESH_NODE_LEASE_TTL,
        }
    }
}

impl Default for MeshNodeConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Handshake request from hub to connector.
///
/// Per FCP Specification Section 9.10:
/// - `protocol_version`: Version string for compatibility
/// - `zone`: Zone this connector instance will be bound to
/// - `zone_dir`: Filesystem path for persistent storage (required for stateful connectors)
/// - `host_public_key`: Ed25519 public key for capability token verification
/// - `nonce`: 32-byte random nonce for replay protection
/// - `capabilities_requested`: Capabilities the hub wants to grant
/// - `host`: Optional host metadata
/// - `transport_caps`: Optional transport negotiation
/// - `requested_instance_id`: Optional preferred instance ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Protocol version (e.g., "1.0.0")
    pub protocol_version: String,

    /// Zone the connector will run in
    pub zone: ZoneId,

    /// Filesystem path for zone-scoped persistent storage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_dir: Option<String>,

    /// Host's Ed25519 public key for signing capability tokens
    pub host_public_key: [u8; 32],

    /// Nonce for replay protection (32 bytes per spec)
    pub nonce: [u8; 32],

    /// Capabilities the hub is requesting to grant
    #[serde(default)]
    pub capabilities_requested: Vec<CapabilityId>,

    /// Host metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostInfo>,

    /// Transport capabilities for negotiation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_caps: Option<TransportCaps>,

    /// Requested instance ID (hub may assign)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_instance_id: Option<InstanceId>,
}

/// Handshake response from connector to hub.
///
/// Per FCP Specification Section 9.10:
/// - `status`: "accepted" or error string
/// - `capabilities_granted`: Actual capabilities the connector will honor
/// - `session_id`: Unique session identifier for this connection
/// - `manifest_hash`: SHA256 hash of the connector manifest for integrity
/// - `nonce`: Echo back the 32-byte nonce to prove liveness
/// - `event_caps`: Event streaming capabilities (if supported)
/// - `auth_caps`: Authentication methods (if applicable)
/// - `op_catalog_hash`: Hash of operations list for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Status: "accepted" or error
    pub status: String,

    /// Capabilities actually granted
    pub capabilities_granted: Vec<CapabilityGrant>,

    /// Session ID for this connection
    pub session_id: SessionId,

    /// Hash of the connector's manifest (e.g., "sha256:abc123...")
    pub manifest_hash: String,

    /// Echo back the nonce (32 bytes per spec)
    pub nonce: [u8; 32],

    /// Event capabilities (streaming, replay, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_caps: Option<EventCaps>,

    /// Auth capabilities (OAuth, API key, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_caps: Option<AuthCaps>,

    /// Hash of the operation catalog for caching
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_catalog_hash: Option<String>,
}

/// Event capabilities advertised by a connector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventCaps {
    /// Whether streaming is supported
    #[serde(default)]
    pub streaming: bool,

    /// Whether event replay is supported
    #[serde(default)]
    pub replay: bool,

    /// Minimum events to buffer
    #[serde(default)]
    pub min_buffer_events: u32,

    /// Whether events require acknowledgment
    #[serde(default)]
    pub requires_ack: bool,
}

/// Authentication capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCaps {
    /// Supported auth methods
    pub methods: Vec<String>,

    /// OAuth configuration if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuthConfig>,
}

/// OAuth configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    pub authorize_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Invoke Messages
// ─────────────────────────────────────────────────────────────────────────────

/// Invoke context for locale, pagination, and distributed tracing.
///
/// Per FCP Specification, this context travels with requests for:
/// - Internationalization (locale)
/// - Pagination control
/// - Distributed tracing (`trace_id`, `request_tags`)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvokeContext {
    /// Locale for internationalization (e.g., "en-US")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Pagination parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<serde_json::Value>,

    /// Distributed trace identifier for request correlation across services.
    ///
    /// Format: W3C Trace Context trace-id (32 hex chars) or custom format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,

    /// Request tags for additional metadata and routing hints.
    ///
    /// Keys MUST be lowercase ASCII with dots/underscores.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub request_tags: HashMap<String, String>,
}

/// Holder proof for capability token binding (NORMATIVE).
///
/// When a capability token has `holder_node` set, the request MUST include
/// a `holder_proof` signature to prevent replay by non-holder nodes.
///
/// Signable bytes: `request_id || operation_id || token.jti`
/// Signature: Ed25519 by holder node signing key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolderProof {
    /// Ed25519 signature (64 bytes)
    #[serde(with = "crate::util::hex_or_bytes")]
    pub signature: [u8; 64],

    /// Node ID of the holder (must match token's `holder_node` claim)
    pub holder_node: TailscaleNodeId,
}

impl HolderProof {
    /// Create a new holder proof.
    #[must_use]
    pub const fn new(signature: [u8; 64], holder_node: TailscaleNodeId) -> Self {
        Self {
            signature,
            holder_node,
        }
    }

    /// Compute the signable bytes for holder proof.
    ///
    /// Format: `"FCP2-HOLDER-PROOF-V1" || len(request_id) || request_id || len(operation_id) || operation_id || len(token_jti) || token_jti`
    ///
    /// # Panics
    ///
    /// Panics if any input byte length exceeds `u32::MAX`.
    #[must_use]
    pub fn signable_bytes(
        request_id: &RequestId,
        operation_id: &OperationId,
        token_jti: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(b"FCP2-HOLDER-PROOF-V1");

        let req_bytes = request_id.0.as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(req_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(req_bytes);

        let op_bytes = operation_id.as_str().as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(op_bytes.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(op_bytes);

        bytes.extend_from_slice(
            &u32::try_from(token_jti.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(token_jti);

        bytes
    }
}

/// Response metadata for timing and caching.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseMetadata {
    /// Server processing time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_time_ms: Option<u64>,

    /// Cache TTL hint in seconds (0 = do not cache).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ttl_secs: Option<u32>,

    /// Whether the response came from cache.
    #[serde(default)]
    pub from_cache: bool,

    /// Retry-after hint in seconds (for rate-limited responses).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u32>,

    /// Where the operation actually executed (mesh-backed truth label).
    ///
    /// Stamped by mesh-aware hosts so the client can tell a peer-executed
    /// answer (`mesh-backed`) from one executed by the host it called
    /// (`host-backed`). Absent on responses from hosts without a mesh peer
    /// directory, which are host-backed by construction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<InvokeRouteProvenance>,
}

/// Which tier of the truth ladder produced an invoke answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InvokeTruthSource {
    /// A mesh peer (the HRW-elected holder or an advertising peer) executed
    /// the operation after a signed peer-to-peer forward.
    MeshBacked,
    /// The host that received the client request executed the operation.
    HostBacked,
}

impl InvokeTruthSource {
    /// Stable label used in JSON output and telemetry.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MeshBacked => "mesh-backed",
            Self::HostBacked => "host-backed",
        }
    }
}

/// Route provenance for one invoke: who executed it and why.
///
/// Node identifiers are the operator-assigned mesh node ids (Tailscale node
/// ids in production). `decision` is a stable machine-readable code naming
/// the routing rule that fired (for example `hrw_holder_forward`,
/// `local_is_hrw_holder`, `advertised_peer_forward`, `peer_unreachable_local_fallback`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvokeRouteProvenance {
    /// Truth tier that produced the answer.
    pub truth_source: InvokeTruthSource,
    /// Node that executed the operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served_by: Option<String>,
    /// Node that accepted the request from the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_node: Option<String>,
    /// Number of mesh forwarding hops between entry node and executor.
    #[serde(default)]
    pub hop_count: u8,
    /// Stable code naming the routing rule that selected the executor.
    pub decision: String,
    /// Peers that were attempted and failed before the executor answered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_attempts: Vec<String>,
}

impl InvokeRouteProvenance {
    /// Provenance for an answer executed by the host that received it.
    #[must_use]
    pub fn host_backed(node: Option<String>, decision: impl Into<String>) -> Self {
        Self {
            truth_source: InvokeTruthSource::HostBacked,
            served_by: node.clone(),
            entry_node: node,
            hop_count: 0,
            decision: decision.into(),
            failed_attempts: Vec::new(),
        }
    }

    /// Provenance for an answer executed by a mesh peer.
    #[must_use]
    pub fn mesh_backed(
        entry_node: String,
        served_by: String,
        hop_count: u8,
        decision: impl Into<String>,
    ) -> Self {
        Self {
            truth_source: InvokeTruthSource::MeshBacked,
            served_by: Some(served_by),
            entry_node: Some(entry_node),
            hop_count,
            decision: decision.into(),
            failed_attempts: Vec::new(),
        }
    }
}

/// Invoke response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvokeStatus {
    /// Request completed successfully.
    Ok,
    /// Request failed with an error.
    Error,
}

/// Request to invoke an operation (NORMATIVE).
///
/// Per FCP Specification Section 9.7:
/// - `type`: Always "invoke"
/// - `id`: Unique request ID for correlation
/// - `connector_id`: Target connector for this request
/// - `operation`: Operation to invoke (e.g., "gmail.search")
/// - `zone_id`: Zone context for the request
/// - `input`: JSON input parameters
/// - `capability_token`: FCT authorizing this request (`COSE_Sign1` bytes)
/// - `holder_proof`: Ed25519 signature when token has `holder_node` (REQUIRED if `holder_node` set)
/// - `context`: Optional locale, pagination, and trace context
/// - `idempotency_key`: Optional key for retry deduplication (REQUIRED for Risky/Dangerous ops)
/// - `lease_seq`: Optional lease sequence for `singleton_writer` connectors
/// - `deadline_ms`: Optional timeout deadline
/// - `correlation_id`: Optional tracing correlation
/// - `provenance`: Optional provenance for taint tracking
/// - `approval_tokens`: Approval tokens for elevation/declassification/execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeRequest {
    /// Message type (always "invoke")
    pub r#type: String,

    /// Unique request ID for correlation
    pub id: RequestId,

    /// Target connector for this request (NORMATIVE).
    ///
    /// Identifies which connector should handle this invocation.
    pub connector_id: ConnectorId,

    /// Operation to invoke
    pub operation: OperationId,

    /// Zone context for the request (NORMATIVE).
    ///
    /// The zone determines the security context and which zone key
    /// is used for cryptographic operations. The `capability_token`'s
    /// audience must be compatible with this zone.
    pub zone_id: ZoneId,

    /// Input parameters
    pub input: serde_json::Value,

    /// Capability token authorizing this request
    pub capability_token: CapabilityToken,

    /// Holder proof for token binding (NORMATIVE).
    ///
    /// REQUIRED when `capability_token` has `holder_node` claim set.
    /// The signature MUST bind: `request_id || operation_id || token.jti`
    /// and be signed by the holder node's signing key.
    ///
    /// This prevents replay attacks by non-holder nodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_proof: Option<HolderProof>,

    /// Request context (locale, pagination, `trace_id`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<InvokeContext>,

    /// Idempotency key for retries (max 128 bytes).
    ///
    /// REQUIRED for operations with `IdempotencyPolicy::Strict` or
    /// `SafetyTier::Risky`/`Dangerous`. Format is opaque string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,

    /// Lease sequence for `singleton_writer` connectors (NORMATIVE).
    ///
    /// REQUIRED when invoking operations on connectors with `singleton_writer`
    /// semantics. The connector MUST reject requests with stale `lease_seq`.
    ///
    /// This implements fencing token semantics for distributed coordination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_seq: Option<u64>,

    /// Deadline in milliseconds from now
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,

    /// Correlation ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,

    /// Provenance for taint tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,

    /// Approval tokens authorizing this request.
    ///
    /// These tokens can authorize:
    /// - Elevation: Allow integrity to flow upward
    /// - Declassification: Allow confidentiality to flow downward
    /// - Execution: Scope-limited approval for specific operations
    ///
    /// Per FCP Specification Section 7.4, approval tokens are first-class
    /// mesh objects that must be validated against the request context.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_tokens: Vec<ApprovalToken>,
}

/// Maximum length for idempotency keys (NORMATIVE).
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;

impl InvokeRequest {
    /// Validate the idempotency key format.
    ///
    /// # Errors
    /// Returns error if key exceeds `MAX_IDEMPOTENCY_KEY_LEN` bytes.
    pub fn validate_idempotency_key(&self) -> Result<(), InvokeValidationError> {
        if let Some(ref key) = self.idempotency_key {
            if key.len() > MAX_IDEMPOTENCY_KEY_LEN {
                return Err(InvokeValidationError::IdempotencyKeyTooLong {
                    len: key.len(),
                    max: MAX_IDEMPOTENCY_KEY_LEN,
                });
            }
        }
        Ok(())
    }
}

/// Validation errors for invoke requests.
#[derive(Debug, Clone, thiserror::Error)]
pub enum InvokeValidationError {
    /// Idempotency key exceeds maximum length.
    #[error("idempotency key too long ({len} bytes > {max} bytes)")]
    IdempotencyKeyTooLong { len: usize, max: usize },

    /// Holder proof required but missing.
    #[error("holder_proof required when token has holder_node claim")]
    HolderProofRequired,

    /// Holder proof signature invalid.
    #[error("holder_proof signature verification failed")]
    HolderProofInvalid,

    /// Holder node mismatch between token and proof.
    #[error("holder_proof node {proof_node} does not match token holder_node {token_node}")]
    HolderNodeMismatch {
        proof_node: String,
        token_node: String,
    },

    /// Idempotency key required for this operation.
    #[error("idempotency_key required for {safety_tier:?} operations")]
    IdempotencyKeyRequired { safety_tier: SafetyTier },

    /// Lease sequence required for `singleton_writer` connector.
    #[error("lease_seq required for singleton_writer connector")]
    LeaseSeqRequired,

    /// Lease sequence is stale (fencing token check failed).
    #[error("lease_seq {provided} is stale (current: {current})")]
    LeaseSeqStale { provided: u64, current: u64 },
}

/// Response from an operation invocation (NORMATIVE).
///
/// Per FCP Specification Section 9.7:
/// - `type`: Always "response"
/// - `id`: Request ID this is responding to
/// - `status`: Ok or Error
/// - `result`: JSON result data (on success)
/// - `error`: `FcpError` details (on failure)
/// - `receipt_id`: `OperationReceipt` `ObjectId` (for auditable operations)
/// - `audit_event_id`: `AuditEvent` `ObjectId` (for audit trail)
/// - `decision_receipt_id`: `DecisionReceipt` `ObjectId` (for denials)
/// - `resource_uris`: Canonical URIs for resources created/modified
/// - `next_cursor`: Pagination cursor for next page
/// - `response_metadata`: Timing, cache hints, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvokeResponse {
    /// Message type (always "response")
    pub r#type: String,

    /// Request ID this is responding to
    pub id: RequestId,

    /// Response status (Ok or Error)
    pub status: InvokeStatus,

    /// Result data (present when status is Ok)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// Error details (present when status is Error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<FcpError>,

    /// `OperationReceipt` `ObjectId` for exactly-once tracking.
    ///
    /// Present for operations that record receipts (typically
    /// operations with side effects or `IdempotencyClass::Strict`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<ObjectId>,

    /// `AuditEvent` `ObjectId` for audit trail.
    ///
    /// Present when the operation generates an audit event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_event_id: Option<ObjectId>,

    /// `DecisionReceipt` `ObjectId` for policy denials.
    ///
    /// Present when the request was denied by policy. Contains
    /// the reason codes and context for the denial.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_receipt_id: Option<ObjectId>,

    /// Resource URIs created/modified (e.g., `<fcp://fcp.gmail/message/17c9a...>`)
    #[serde(default)]
    pub resource_uris: Vec<String>,

    /// Cursor for pagination
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,

    /// Usage metrics for the operation (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_metrics: Option<Vec<UsageMetric>>,

    /// Response metadata (timing, cache hints).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_metadata: Option<ResponseMetadata>,
}

impl InvokeResponse {
    /// Create a successful response.
    #[must_use]
    pub fn ok(id: RequestId, result: serde_json::Value) -> Self {
        Self {
            r#type: "response".into(),
            id,
            status: InvokeStatus::Ok,
            result: Some(result),
            error: None,
            receipt_id: None,
            audit_event_id: None,
            decision_receipt_id: None,
            resource_uris: Vec::new(),
            next_cursor: None,
            usage_metrics: None,
            response_metadata: None,
        }
    }

    /// Create an error response.
    #[must_use]
    pub fn error(id: RequestId, error: FcpError) -> Self {
        Self {
            r#type: "response".into(),
            id,
            status: InvokeStatus::Error,
            result: None,
            error: Some(error),
            receipt_id: None,
            audit_event_id: None,
            decision_receipt_id: None,
            resource_uris: Vec::new(),
            next_cursor: None,
            usage_metrics: None,
            response_metadata: None,
        }
    }

    /// Set the receipt ID.
    #[must_use]
    pub const fn with_receipt_id(mut self, receipt_id: ObjectId) -> Self {
        self.receipt_id = Some(receipt_id);
        self
    }

    /// Set the audit event ID.
    #[must_use]
    pub const fn with_audit_event_id(mut self, audit_event_id: ObjectId) -> Self {
        self.audit_event_id = Some(audit_event_id);
        self
    }

    /// Set the decision receipt ID (for denials).
    #[must_use]
    pub const fn with_decision_receipt_id(mut self, decision_receipt_id: ObjectId) -> Self {
        self.decision_receipt_id = Some(decision_receipt_id);
        self
    }

    /// Set response metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: ResponseMetadata) -> Self {
        self.response_metadata = Some(metadata);
        self
    }

    /// Set usage metrics.
    #[must_use]
    pub fn with_usage_metrics(mut self, metrics: Vec<UsageMetric>) -> Self {
        self.usage_metrics = Some(metrics);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulate Messages (Section 9.4 - Preflight Checks)
// ─────────────────────────────────────────────────────────────────────────────

/// Simulate request for preflight checks (NORMATIVE).
///
/// Per FCP Specification Section 9.4:
/// Allows callers to check if an operation would succeed (capability check,
/// resource availability, cost estimation) without executing it.
///
/// **Hard Requirements:**
/// - **No side effects:** simulate MUST NOT perform external writes or mutate external state.
/// - **Policy-aware:** simulate must reflect capability/policy gating as closely as invoke.
/// - **Deterministic & bounded:** cost estimation and availability checks must be bounded
///   (timeouts, size limits) and deterministic given the same inputs.
///
/// Connectors SHOULD implement simulate for expensive or dangerous operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateRequest {
    /// Message type (always "simulate")
    pub r#type: String,

    /// Unique request ID for correlation
    pub id: RequestId,

    /// Target connector for this request (NORMATIVE).
    pub connector_id: ConnectorId,

    /// Operation to simulate
    pub operation: OperationId,

    /// Zone context for the request (NORMATIVE).
    pub zone_id: ZoneId,

    /// Input parameters
    pub input: serde_json::Value,

    /// Capability token authorizing this request
    pub capability_token: CapabilityToken,

    /// Request cost estimate.
    ///
    /// When true, the connector SHOULD populate `estimated_cost` in the response.
    #[serde(default)]
    pub estimate_cost: bool,

    /// Check resource availability.
    ///
    /// When true, the connector MAY check if the target resource exists
    /// and return rate limit headroom information.
    #[serde(default)]
    pub check_availability: bool,

    /// Request context (locale, pagination, `trace_id`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<InvokeContext>,

    /// Correlation ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,
}

impl SimulateRequest {
    /// Create a new simulate request.
    #[must_use]
    pub fn new(
        connector_id: ConnectorId,
        operation: OperationId,
        zone_id: ZoneId,
        input: serde_json::Value,
        capability_token: CapabilityToken,
    ) -> Self {
        Self {
            r#type: "simulate".into(),
            id: RequestId::random(),
            connector_id,
            operation,
            zone_id,
            input,
            capability_token,
            estimate_cost: false,
            check_availability: false,
            context: None,
            correlation_id: None,
        }
    }

    /// Enable cost estimation.
    #[must_use]
    pub const fn with_cost_estimate(mut self) -> Self {
        self.estimate_cost = true;
        self
    }

    /// Enable availability checking.
    #[must_use]
    pub const fn with_availability_check(mut self) -> Self {
        self.check_availability = true;
        self
    }

    /// Set the request context.
    #[must_use]
    pub fn with_context(mut self, context: InvokeContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Set the correlation ID.
    #[must_use]
    pub const fn with_correlation_id(mut self, correlation_id: CorrelationId) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }
}

/// Simulate response (NORMATIVE).
///
/// Per FCP Specification Section 9.4:
/// Contains the result of the preflight simulation including:
/// - Whether the operation would succeed
/// - Missing capabilities or policy denials
/// - Cost estimates (if requested)
/// - Resource availability (if requested)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateResponse {
    /// Message type (always `simulate_response`)
    pub r#type: String,

    /// Request ID this is responding to
    pub id: RequestId,

    /// Would the operation succeed with current capabilities/state?
    pub would_succeed: bool,

    /// If `would_succeed` is false, why not?
    ///
    /// This is a human-readable explanation. For machine-readable codes,
    /// use `denial_code`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,

    /// FCP error code if denied (e.g., "FCP-3001" for capability denied).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_code: Option<String>,

    /// Missing capabilities needed (if any).
    ///
    /// The list of capability IDs that would be required to execute
    /// this operation but are not present in the capability token.
    #[serde(default)]
    pub missing_capabilities: Vec<String>,

    /// Estimated cost (if `estimate_cost` was true in request).
    ///
    /// This is populated when the connector can provide usage estimates.
    /// Note: We do NOT embed pricing tables in connectors - this contains
    /// usage metrics (tokens, bytes, duration) not currency costs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost: Option<CostEstimate>,

    /// Resource availability check result (if `check_availability` was true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<ResourceAvailability>,

    /// Response metadata (timing, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_metadata: Option<ResponseMetadata>,
}

impl SimulateResponse {
    /// Create a successful simulation response (operation would succeed).
    #[must_use]
    pub fn allowed(id: RequestId) -> Self {
        Self {
            r#type: "simulate_response".into(),
            id,
            would_succeed: true,
            failure_reason: None,
            denial_code: None,
            missing_capabilities: Vec::new(),
            estimated_cost: None,
            availability: None,
            response_metadata: None,
        }
    }

    /// Create a denied simulation response (operation would fail).
    #[must_use]
    pub fn denied(
        id: RequestId,
        reason: impl Into<String>,
        denial_code: impl Into<String>,
    ) -> Self {
        Self {
            r#type: "simulate_response".into(),
            id,
            would_succeed: false,
            failure_reason: Some(reason.into()),
            denial_code: Some(denial_code.into()),
            missing_capabilities: Vec::new(),
            estimated_cost: None,
            availability: None,
            response_metadata: None,
        }
    }

    /// Add missing capabilities.
    #[must_use]
    pub fn with_missing_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.missing_capabilities = capabilities;
        self
    }

    /// Set the cost estimate.
    #[must_use]
    pub fn with_cost_estimate(mut self, cost: CostEstimate) -> Self {
        self.estimated_cost = Some(cost);
        self
    }

    /// Set the availability result.
    #[must_use]
    pub fn with_availability(mut self, availability: ResourceAvailability) -> Self {
        self.availability = Some(availability);
        self
    }

    /// Set response metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: ResponseMetadata) -> Self {
        self.response_metadata = Some(metadata);
        self
    }
}

/// Confidence label for cost estimates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostEstimateConfidence {
    /// Low confidence estimate (rough order-of-magnitude).
    Low,
    /// Medium confidence estimate (reasonable bounds).
    Medium,
    /// High confidence estimate (tight bounds, stable basis).
    High,
}

/// Cost estimate for simulation (NORMATIVE when present).
///
/// Per FCP Specification Section 9.4:
/// Contains usage estimates for an operation. We do NOT embed pricing tables
/// in connectors (pricing changes frequently). Connectors SHOULD populate
/// usage metrics (tokens/credits/bytes/duration) when they can.
///
/// `CurrencyCost` is OPTIONAL and should only be populated when the connector
/// has a stable, explicit currency basis that does not require volatile price tables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostEstimate {
    /// Estimated API credits/tokens consumed.
    ///
    /// The unit depends on the external service (e.g., LLM tokens,
    /// API credits, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_credits: Option<u64>,

    /// Estimated execution time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_duration_ms: Option<u64>,

    /// Estimated bytes transferred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_bytes: Option<u64>,

    /// Currency cost estimate (if applicable).
    ///
    /// OPTIONAL: Only populate when the connector has explicit, stable
    /// pricing information. Do NOT embed volatile price tables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<CurrencyCost>,

    /// Confidence label for the estimate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<CostEstimateConfidence>,
}

impl CostEstimate {
    /// Create a new cost estimate with API credits.
    #[must_use]
    pub const fn with_credits(credits: u64) -> Self {
        Self {
            api_credits: Some(credits),
            estimated_duration_ms: None,
            estimated_bytes: None,
            currency: None,
            confidence: None,
        }
    }

    /// Create a new cost estimate with duration.
    #[must_use]
    pub const fn with_duration_ms(duration_ms: u64) -> Self {
        Self {
            api_credits: None,
            estimated_duration_ms: Some(duration_ms),
            estimated_bytes: None,
            currency: None,
            confidence: None,
        }
    }

    /// Create a new cost estimate with bytes.
    #[must_use]
    pub const fn with_bytes(bytes: u64) -> Self {
        Self {
            api_credits: None,
            estimated_duration_ms: None,
            estimated_bytes: Some(bytes),
            currency: None,
            confidence: None,
        }
    }

    /// Add API credits to the estimate.
    #[must_use]
    pub const fn and_credits(mut self, credits: u64) -> Self {
        self.api_credits = Some(credits);
        self
    }

    /// Add duration to the estimate.
    #[must_use]
    pub const fn and_duration_ms(mut self, duration_ms: u64) -> Self {
        self.estimated_duration_ms = Some(duration_ms);
        self
    }

    /// Add bytes to the estimate.
    #[must_use]
    pub const fn and_bytes(mut self, bytes: u64) -> Self {
        self.estimated_bytes = Some(bytes);
        self
    }

    /// Add currency cost to the estimate.
    #[must_use]
    pub fn and_currency(mut self, currency: CurrencyCost) -> Self {
        self.currency = Some(currency);
        self
    }

    /// Add a confidence label to the estimate.
    #[must_use]
    pub const fn and_confidence(mut self, confidence: CostEstimateConfidence) -> Self {
        self.confidence = Some(confidence);
        self
    }
}

/// Currency cost for cost estimation.
///
/// Per FCP Specification Section 9.4:
/// Only populate when the connector has explicit, stable pricing information.
/// Do NOT embed volatile price tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrencyCost {
    /// Amount in smallest currency unit (e.g., cents for USD).
    pub amount_cents: u64,

    /// ISO 4217 currency code (e.g., "USD", "EUR").
    pub currency_code: String,
}

impl CurrencyCost {
    /// Create a new currency cost.
    #[must_use]
    pub fn new(amount_cents: u64, currency_code: impl Into<String>) -> Self {
        Self {
            amount_cents,
            currency_code: currency_code.into(),
        }
    }

    /// Create a USD currency cost from an amount in cents.
    #[must_use]
    pub fn usd_cents(amount_cents: u64) -> Self {
        Self::new(amount_cents, "USD")
    }
}

/// Canonical target for operator-facing connector logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoggingTarget {
    /// Connector stdout stream.
    Stdout,
    /// Connector stderr stream.
    Stderr,
    /// Host control-plane log stream.
    Host,
    /// Tamper-evident audit log stream.
    Audit,
}

impl LoggingTarget {
    /// Stable wire/display tag for this logging target.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Host => "host",
            Self::Audit => "audit",
        }
    }
}

impl fmt::Display for LoggingTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Usage metric kind for actual execution telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageMetricKind {
    /// API credits or tokens consumed.
    ApiCredits,
    /// Token usage (LLM tokens, etc.).
    Tokens,
    /// Bytes transferred.
    Bytes,
    /// Execution duration in milliseconds.
    DurationMs,
    /// Number of requests performed.
    Requests,
    /// Custom connector-specific metric.
    Custom,
}

impl UsageMetricKind {
    /// Stable string representation for signing and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiCredits => "api_credits",
            Self::Tokens => "tokens",
            Self::Bytes => "bytes",
            Self::DurationMs => "duration_ms",
            Self::Requests => "requests",
            Self::Custom => "custom",
        }
    }
}

/// Maximum metric-label length in bytes.
pub const MAX_METRIC_LABEL_LEN: usize = 128;

/// Canonical metric label validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MetricLabelValidationError {
    /// Label is empty.
    #[error("metric label must not be empty")]
    Empty,

    /// Label exceeds the maximum byte length.
    #[error("metric label too long ({len} bytes > {max} bytes)")]
    TooLong {
        /// Observed byte length.
        len: usize,
        /// Maximum accepted byte length.
        max: usize,
    },

    /// Label is not ASCII.
    #[error("metric label must be ASCII")]
    NonAscii,

    /// Label contains uppercase ASCII.
    #[error("metric label must be lowercase")]
    UppercaseNotAllowed,

    /// Label does not contain a namespace separator.
    #[error("metric label must use a dotted namespace")]
    MissingNamespaceSeparator,

    /// Label contains an empty namespace segment.
    #[error("metric label contains an empty namespace segment at byte {index}")]
    EmptySegment {
        /// Byte index of the empty segment boundary.
        index: usize,
    },

    /// Namespace segment starts with a disallowed character.
    #[error("metric label segment has invalid start character '{ch}' at byte {index}")]
    InvalidSegmentStart {
        /// Invalid character.
        ch: char,
        /// Byte index of the invalid character.
        index: usize,
    },

    /// Label contains a disallowed character.
    #[error("metric label has invalid character '{ch}' at byte {index}")]
    InvalidChar {
        /// Invalid character.
        ch: char,
        /// Byte index of the invalid character.
        index: usize,
    },
}

/// Lowercase dotted namespace for connector and host metrics.
///
/// The canonical format is ASCII, at most [`MAX_METRIC_LABEL_LEN`] bytes, and
/// made of lowercase namespace segments separated by dots. Each segment starts
/// with `a-z`; the rest of a segment may contain `a-z`, `0-9`, or `_`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MetricLabel(std::sync::Arc<str>);

impl MetricLabel {
    /// Create a canonical metric label.
    ///
    /// # Errors
    ///
    /// Returns an error when `label` is not lowercase, dotted, ASCII, within
    /// the length cap, or limited to the allowed character set.
    pub fn new(label: impl Into<String>) -> Result<Self, MetricLabelValidationError> {
        Self::try_from(label.into())
    }

    /// Create a metric label from a static string literal.
    ///
    /// # Panics
    ///
    /// Panics if the literal is not a canonical metric label.
    #[must_use]
    pub fn from_static(label: &'static str) -> Self {
        Self::new(label).expect("static metric label must be canonical")
    }

    /// Return the canonical label string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MetricLabel {
    type Error = MetricLabelValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_metric_label(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<MetricLabel> for String {
    fn from(value: MetricLabel) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for MetricLabel {
    type Err = MetricLabelValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl std::fmt::Display for MetricLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for MetricLabel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

fn validate_metric_label(label: &str) -> Result<(), MetricLabelValidationError> {
    if label.is_empty() {
        return Err(MetricLabelValidationError::Empty);
    }

    if label.len() > MAX_METRIC_LABEL_LEN {
        return Err(MetricLabelValidationError::TooLong {
            len: label.len(),
            max: MAX_METRIC_LABEL_LEN,
        });
    }

    if !label.is_ascii() {
        return Err(MetricLabelValidationError::NonAscii);
    }

    if label.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(MetricLabelValidationError::UppercaseNotAllowed);
    }

    if !label.contains('.') {
        return Err(MetricLabelValidationError::MissingNamespaceSeparator);
    }

    let mut segment_start = true;
    for (index, ch) in label.char_indices() {
        if ch == '.' {
            if segment_start {
                return Err(MetricLabelValidationError::EmptySegment { index });
            }
            segment_start = true;
            continue;
        }

        if segment_start {
            if !ch.is_ascii_lowercase() {
                return Err(MetricLabelValidationError::InvalidSegmentStart { ch, index });
            }
            segment_start = false;
            continue;
        }

        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_') {
            return Err(MetricLabelValidationError::InvalidChar { ch, index });
        }
    }

    if segment_start {
        return Err(MetricLabelValidationError::EmptySegment { index: label.len() });
    }

    Ok(())
}

/// Usage metric for actual execution (NORMATIVE when present).
///
/// Connectors SHOULD emit usage metrics when they can measure actual usage.
/// Host systems MAY aggregate these metrics per-zone for budget enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMetric {
    /// Metric kind.
    pub kind: UsageMetricKind,

    /// Measured usage amount.
    pub amount: u64,

    /// Optional unit label (for custom metrics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,

    /// Optional custom metric identifier (required when kind = Custom).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_id: Option<String>,
}

impl UsageMetric {
    /// Usage metric for API credits.
    #[must_use]
    pub const fn api_credits(amount: u64) -> Self {
        Self {
            kind: UsageMetricKind::ApiCredits,
            amount,
            unit: None,
            custom_id: None,
        }
    }

    /// Usage metric for tokens.
    #[must_use]
    pub const fn tokens(amount: u64) -> Self {
        Self {
            kind: UsageMetricKind::Tokens,
            amount,
            unit: None,
            custom_id: None,
        }
    }

    /// Usage metric for bytes.
    #[must_use]
    pub const fn bytes(amount: u64) -> Self {
        Self {
            kind: UsageMetricKind::Bytes,
            amount,
            unit: None,
            custom_id: None,
        }
    }

    /// Usage metric for duration in milliseconds.
    #[must_use]
    pub const fn duration_ms(amount: u64) -> Self {
        Self {
            kind: UsageMetricKind::DurationMs,
            amount,
            unit: None,
            custom_id: None,
        }
    }

    /// Usage metric for request counts.
    #[must_use]
    pub const fn requests(amount: u64) -> Self {
        Self {
            kind: UsageMetricKind::Requests,
            amount,
            unit: None,
            custom_id: None,
        }
    }

    /// Usage metric for custom connector-specific measurements.
    #[must_use]
    pub fn custom(custom_id: impl Into<String>, amount: u64, unit: Option<String>) -> Self {
        Self {
            kind: UsageMetricKind::Custom,
            amount,
            unit,
            custom_id: Some(custom_id.into()),
        }
    }

    /// Attach a unit label.
    #[must_use]
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }
}

/// Resource availability check result.
///
/// Per FCP Specification Section 9.4:
/// Reports resource existence and rate limit headroom. Availability checks
/// MUST be read-only, time-bounded, and avoid leaking secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAvailability {
    /// Is the resource available?
    pub available: bool,

    /// Rate limit headroom (remaining requests/tokens in current window).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_remaining: Option<u32>,

    /// When rate limit resets (Unix timestamp in seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_reset_at: Option<u64>,

    /// Additional availability details (connector-specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ResourceAvailability {
    /// Create an availability result indicating the resource is available.
    #[must_use]
    pub const fn available() -> Self {
        Self {
            available: true,
            rate_limit_remaining: None,
            rate_limit_reset_at: None,
            details: None,
        }
    }

    /// Create an availability result indicating the resource is unavailable.
    #[must_use]
    pub fn unavailable(details: impl Into<String>) -> Self {
        Self {
            available: false,
            rate_limit_remaining: None,
            rate_limit_reset_at: None,
            details: Some(details.into()),
        }
    }

    /// Add rate limit information.
    #[must_use]
    pub const fn with_rate_limit(mut self, remaining: u32, reset_at: Option<u64>) -> Self {
        self.rate_limit_remaining = Some(remaining);
        self.rate_limit_reset_at = reset_at;
        self
    }

    /// Add details.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Provisioning Payloads (Section 12.2)
// ─────────────────────────────────────────────────────────────────────────────

/// Provisioning session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProvisioningSessionId(pub String);

impl ProvisioningSessionId {
    /// Create a new provisioning session ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a random provisioning session ID.
    #[must_use]
    pub fn random() -> Self {
        Self(format!("prov_{}", uuid::Uuid::new_v4()))
    }

    /// Get the session ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProvisioningSessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<S: Into<String>> From<S> for ProvisioningSessionId {
    fn from(value: S) -> Self {
        Self(value.into())
    }
}

/// Input payload for `fcp.provision.start`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningStartInput {
    /// Optional recipe identifier (default recipe if omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipe_id: Option<RecipeId>,

    /// Optional connector-specific configuration hints (non-secret).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

/// Result payload for `fcp.provision.start`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningStartOutput {
    /// Provisioning session identifier (if the connector tracks sessions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ProvisioningSessionId>,

    /// Current provisioning state.
    pub state: ProvisioningState,

    /// Optional progress summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<ProvisioningProgress>,

    /// Optional recipe definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipe: Option<ProvisioningRecipe>,

    /// Optional setup descriptor for host UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup: Option<SetupDescriptor>,

    /// Connector-specific details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Input payload for `fcp.provision.poll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningPollInput {
    /// Provisioning session identifier (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ProvisioningSessionId>,
}

/// Result payload for `fcp.provision.poll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningPollOutput {
    /// Current provisioning state.
    pub state: ProvisioningState,

    /// Optional progress summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<ProvisioningProgress>,

    /// Connector-specific details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Input value for provisioning completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningInput {
    /// Step identifier that produced the value.
    pub step_id: StepId,

    /// User-provided value or redacted reference.
    ///
    /// Secrets SHOULD be represented as references (IDs) rather than raw bytes.
    pub value: serde_json::Value,
}

/// Input payload for `fcp.provision.complete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningCompleteInput {
    /// Provisioning session identifier (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ProvisioningSessionId>,

    /// Inputs collected from human prompts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<ProvisioningInput>,
}

/// Result payload for `fcp.provision.complete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningCompleteOutput {
    /// Current provisioning state.
    pub state: ProvisioningState,

    /// Validation result after completion.
    pub validation: ProvisioningValidation,

    /// Connector-specific details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Input payload for `fcp.provision.abort`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningAbortInput {
    /// Provisioning session identifier (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ProvisioningSessionId>,

    /// Optional reason for aborting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Result payload for `fcp.provision.abort`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningAbortOutput {
    /// Current provisioning state.
    pub state: ProvisioningState,
}

// ─────────────────────────────────────────────────────────────────────────────
// Subscribe Messages (Section 9.9)
// ─────────────────────────────────────────────────────────────────────────────

/// Request to subscribe to event topics.
///
/// Per FCP Specification Section 9.9:
/// - `type`: Always "subscribe"
/// - `id`: Unique request ID
/// - `topics`: List of topic patterns to subscribe to
/// - `since`: Cursor position for replay (if supported)
/// - `max_events_per_sec`: Backpressure limit
/// - `batch_ms`: Batching window in milliseconds
/// - `window_size`: Flow control window size
/// - `capability_token`: Optional auth token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeRequest {
    /// Message type (always "subscribe")
    pub r#type: String,

    /// Unique request ID
    pub id: RequestId,

    /// Topics to subscribe to
    pub topics: Vec<String>,

    /// Resume from cursor (for replay)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,

    /// Maximum events per second (backpressure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_events_per_sec: Option<u32>,

    /// Batching window in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_ms: Option<u32>,

    /// Flow control window size
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_size: Option<u32>,

    /// Optional capability token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,
}

/// Replay buffer information.
///
/// Per FCP Specification Section 9.9.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBufferInfo {
    /// Minimum events retained in buffer
    pub min_events: u32,

    /// Overflow policy (e.g., "stream.reset")
    pub overflow: String,
}

/// Response to subscription request.
///
/// Per FCP Specification Section 9.9.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResponse {
    /// Message type (always "response")
    pub r#type: String,

    /// Request ID this is responding to
    pub id: RequestId,

    /// Result containing subscription details
    pub result: SubscribeResult,
}

/// Subscription result details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeResult {
    /// Topics confirmed
    pub confirmed_topics: Vec<String>,

    /// Current cursors for each topic
    #[serde(default)]
    pub cursors: HashMap<String, String>,

    /// Whether replay is available
    pub replay_supported: bool,

    /// Buffer info (`min_events`, overflow policy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer: Option<ReplayBufferInfo>,
}

/// Request to unsubscribe from topics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    /// Message type (always "unsubscribe")
    pub r#type: String,

    /// Unique request ID
    pub id: RequestId,

    /// Topics to unsubscribe from
    pub topics: Vec<String>,

    /// Optional capability token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<CapabilityToken>,
}

/// Request to acknowledge delivered events.
///
/// Per FCP Specification Section 9.9:
/// - `type`: Always "ack"
/// - `id`: Unique request ID
/// - `ack`: Event acknowledgment payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAckRequest {
    /// Message type (always "ack")
    pub r#type: String,

    /// Unique request ID
    pub id: RequestId,

    /// Acknowledgment payload
    pub ack: EventAck,
}

/// Request to negatively acknowledge events (request redelivery).
///
/// Per FCP Specification Section 9.9:
/// - `type`: Always "nack"
/// - `id`: Unique request ID
/// - `nack`: Event negative acknowledgment payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventNackRequest {
    /// Message type (always "nack")
    pub r#type: String,

    /// Unique request ID
    pub id: RequestId,

    /// Negative acknowledgment payload
    pub nack: EventNack,
}

// ─────────────────────────────────────────────────────────────────────────────
// Shutdown Messages (Section 9.12)
// ─────────────────────────────────────────────────────────────────────────────

/// Request to shutdown the connector.
///
/// Per FCP Specification Section 9.12:
/// - `deadline_ms`: Maximum time to complete shutdown
/// - `drain`: Whether to flush pending events before terminating
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownRequest {
    /// Message type (always "shutdown")
    pub r#type: String,

    /// Maximum time to complete shutdown in milliseconds
    #[serde(default = "default_deadline")]
    pub deadline_ms: u64,

    /// Whether to flush pending events before terminating
    #[serde(default)]
    pub drain: bool,

    /// Optional reason for shutdown (for logging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

const fn default_deadline() -> u64 {
    10000 // 10 seconds default
}

/// Shutdown acknowledgment from connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownAck {
    /// Message type (always "`shutdown_ack`")
    pub r#type: String,

    /// Status of shutdown
    pub status: String,

    /// Number of events flushed (if drain was true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events_flushed: Option<u64>,

    /// Number of in-flight requests completed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests_completed: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Introspection
// ─────────────────────────────────────────────────────────────────────────────

/// Introspection data describing connector capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Introspection {
    /// Available operations
    pub operations: Vec<OperationInfo>,

    /// Available event topics
    #[serde(default)]
    pub events: Vec<EventInfo>,

    /// Resource types this connector manages
    #[serde(default)]
    pub resource_types: Vec<ResourceTypeInfo>,

    /// Auth capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_caps: Option<AuthCaps>,

    /// Event capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_caps: Option<EventCaps>,
}

/// Information about an operation.
///
/// Per FCP Specification Section 8.2 and 9.6:
/// - Operations MUST declare capability, `risk_level`, `safety_tier`, and `idempotency`
/// - `risk_level` is for UX/prioritization; `safety_tier` is normative enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationInfo {
    /// Operation ID (e.g., "gmail.search")
    pub id: OperationId,

    /// Human-readable summary
    pub summary: String,

    /// Detailed description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// JSON Schema for input
    pub input_schema: serde_json::Value,

    /// JSON Schema for output
    pub output_schema: serde_json::Value,

    /// Required capability
    pub capability: CapabilityId,

    /// Risk level (for UX/prioritization)
    pub risk_level: RiskLevel,

    /// Safety tier (normative enforcement)
    pub safety_tier: SafetyTier,

    /// Idempotency class
    pub idempotency: IdempotencyClass,

    /// AI agent hints
    pub ai_hints: AgentHint,

    /// Rate limit configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<crate::RateLimit>,

    /// Approval mode required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<ApprovalMode>,
}

/// Approval mode for operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// No approval needed
    None,
    /// Policy-based approval
    Policy,
    /// Interactive human approval
    Interactive,
    /// Elevation token required
    ElevationToken,
}

/// Hints for AI agents on how to use an operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentHint {
    /// When to use this operation
    pub when_to_use: String,

    /// Common mistakes to avoid
    #[serde(default)]
    pub common_mistakes: Vec<String>,

    /// Example invocations
    #[serde(default)]
    pub examples: Vec<String>,

    /// Related operations
    #[serde(default)]
    pub related: Vec<CapabilityId>,
}

/// Information about an event topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    /// Topic name
    pub topic: String,

    /// JSON Schema for event data
    pub schema: serde_json::Value,

    /// Whether acknowledgment is required
    pub requires_ack: bool,
}

/// Information about a resource type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceTypeInfo {
    /// Resource type name
    pub name: String,

    /// URI pattern
    pub uri_pattern: String,

    /// JSON Schema for resource
    pub schema: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityToken;
    use fcp_crypto::ed25519::{Ed25519Signature, Ed25519SigningKey};

    // ─────────────────────────────────────────────────────────────────────────
    // RequestId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn request_id_new() {
        let id = RequestId::new("req_123");
        assert_eq!(id.to_string(), "req_123");
    }

    #[test]
    fn request_id_random() {
        let id = RequestId::random();
        assert!(id.to_string().starts_with("req_"));
    }

    #[test]
    fn request_id_from_string() {
        let id: RequestId = "my-request".into();
        assert_eq!(id.0, "my-request");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Handshake Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn handshake_request_serialization_roundtrip() {
        let req = HandshakeRequest {
            protocol_version: "1.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: Some("/var/fcp/zones/work".into()),
            host_public_key: [0x42_u8; 32],
            nonce: [0xaa_u8; 32],
            capabilities_requested: vec!["cap.read".parse().unwrap()],
            host: Some(HostInfo {
                name: "flywheel-hub".into(),
                version: Some("2.0.0".into()),
                build: Some("abc123".into()),
            }),
            transport_caps: Some(TransportCaps {
                compression: vec!["zstd".into()],
                max_frame_size: Some(65536),
            }),
            requested_instance_id: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: HandshakeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.protocol_version, "1.0.0");
        assert_eq!(deserialized.zone.as_str(), "z:work");
        assert_eq!(deserialized.host_public_key, [0x42_u8; 32]);
        assert_eq!(deserialized.nonce, [0xaa_u8; 32]);
        assert_eq!(deserialized.capabilities_requested.len(), 1);
        assert!(deserialized.host.is_some());
        assert!(deserialized.transport_caps.is_some());
    }

    #[test]
    fn handshake_request_minimal() {
        let req = HandshakeRequest {
            protocol_version: "1.0.0".into(),
            zone: ZoneId::public(),
            zone_dir: None,
            host_public_key: [0_u8; 32],
            nonce: [0_u8; 32],
            capabilities_requested: vec![],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("zone_dir"));
        // Note: check for exact field name with colon to avoid matching host_public_key
        assert!(!json.contains("\"host\":"));
        assert!(!json.contains("transport_caps"));
    }

    #[test]
    fn handshake_response_serialization_roundtrip() {
        let resp = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: vec![crate::CapabilityGrant {
                capability: "cap.read".parse().unwrap(),
                operation: None,
            }],
            session_id: SessionId::new(),
            manifest_hash: "sha256:abc123".into(),
            nonce: [0xbb_u8; 32],
            event_caps: Some(EventCaps {
                streaming: true,
                replay: true,
                min_buffer_events: 1000,
                requires_ack: true,
            }),
            auth_caps: Some(AuthCaps {
                methods: vec!["oauth2".into()],
                oauth: Some(OAuthConfig {
                    authorize_url: "https://example.com/auth".into(),
                    token_url: "https://example.com/token".into(),
                    scopes: vec!["read".into(), "write".into()],
                }),
            }),
            op_catalog_hash: Some("sha256:def456".into()),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: HandshakeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, "accepted");
        assert_eq!(deserialized.capabilities_granted.len(), 1);
        assert!(deserialized.event_caps.is_some());
        assert!(deserialized.auth_caps.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Invoke Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn base_invoke_request() -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_base"),
            connector_id: ConnectorId::from_static("gmail:fcp2:1.0"),
            operation: "gmail.search".parse().unwrap(),
            zone_id: ZoneId::work(),
            input: serde_json::json!({}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    #[test]
    fn invoke_request_serialization_roundtrip() {
        let req = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("req_001"),
            connector_id: ConnectorId::from_static("gmail:fcp2:1.0"),
            operation: "gmail.search".parse().unwrap(),
            zone_id: ZoneId::work(),
            input: serde_json::json!({"query": "from:alice"}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: Some(InvokeContext {
                locale: Some("en-US".into()),
                pagination: Some(serde_json::json!({"page": 1, "size": 10})),
                trace_id: Some("0af7651916cd43dd8448eb211c80319c".into()),
                request_tags: std::iter::once(("priority".into(), "high".into())).collect(),
            }),
            idempotency_key: Some("idem_123".into()),
            lease_seq: None,
            deadline_ms: Some(30000),
            correlation_id: Some(CorrelationId::new()),
            provenance: Some(crate::Provenance::new(ZoneId::work())),
            approval_tokens: Vec::new(),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: InvokeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.r#type, "invoke");
        assert_eq!(deserialized.id.0, "req_001");
        assert_eq!(deserialized.connector_id.as_str(), "gmail:fcp2:1.0");
        assert_eq!(deserialized.operation.as_str(), "gmail.search");
        assert!(deserialized.context.is_some());
        let ctx = deserialized.context.unwrap();
        assert_eq!(
            ctx.trace_id,
            Some("0af7651916cd43dd8448eb211c80319c".into())
        );
        assert_eq!(ctx.request_tags.get("priority"), Some(&"high".into()));
        assert_eq!(deserialized.idempotency_key, Some("idem_123".into()));
        assert_eq!(deserialized.deadline_ms, Some(30000));
        assert!(deserialized.holder_proof.is_none());
        assert!(deserialized.lease_seq.is_none());
    }

    #[test]
    fn invoke_request_idempotency_key_length_ok() {
        let mut req = base_invoke_request();
        req.idempotency_key = Some("a".repeat(MAX_IDEMPOTENCY_KEY_LEN));
        assert!(req.validate_idempotency_key().is_ok());
    }

    #[test]
    fn invoke_request_idempotency_key_too_long() {
        let mut req = base_invoke_request();
        req.idempotency_key = Some("a".repeat(MAX_IDEMPOTENCY_KEY_LEN + 1));
        let err = req.validate_idempotency_key().unwrap_err();
        assert!(
            matches!(
                &err,
                InvokeValidationError::IdempotencyKeyTooLong { len, max }
                    if *len == MAX_IDEMPOTENCY_KEY_LEN + 1 && *max == MAX_IDEMPOTENCY_KEY_LEN
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn holder_proof_signable_bytes_binding() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let request_id = RequestId::new("req_holder");
        let operation_id: OperationId = "gmail.send".parse().unwrap();
        let token_jti = b"token-jti-123";

        let signable = HolderProof::signable_bytes(&request_id, &operation_id, token_jti);
        let signature = signing_key.sign(&signable);
        let holder_proof = HolderProof::new(signature.to_bytes(), TailscaleNodeId::new("node-123"));

        let proof_sig = Ed25519Signature::from_bytes(&holder_proof.signature);
        assert!(verifying_key.verify(&signable, &proof_sig).is_ok());

        let mismatched = HolderProof::signable_bytes(&request_id, &operation_id, b"other-jti");
        assert!(verifying_key.verify(&mismatched, &proof_sig).is_err());
    }

    #[test]
    fn invoke_response_serialization_roundtrip() {
        let resp = InvokeResponse {
            r#type: "response".into(),
            id: RequestId::new("req_001"),
            status: InvokeStatus::Ok,
            result: Some(serde_json::json!({"messages": []})),
            error: None,
            receipt_id: None,
            audit_event_id: None,
            decision_receipt_id: None,
            resource_uris: vec!["fcp://fcp.gmail/message/123".into()],
            next_cursor: Some("cursor_abc".into()),
            usage_metrics: Some(vec![
                UsageMetric::tokens(1200),
                UsageMetric::bytes(2048),
                UsageMetric::duration_ms(75),
            ]),
            response_metadata: Some(ResponseMetadata {
                processing_time_ms: Some(42),
                cache_ttl_secs: Some(300),
                from_cache: false,
                retry_after_secs: None,
                route: None,
            }),
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: InvokeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.r#type, "response");
        assert_eq!(deserialized.id.0, "req_001");
        assert_eq!(deserialized.status, InvokeStatus::Ok);
        assert!(deserialized.result.is_some());
        assert!(deserialized.error.is_none());
        assert_eq!(deserialized.resource_uris.len(), 1);
        assert_eq!(deserialized.next_cursor, Some("cursor_abc".into()));
        let usage = deserialized.usage_metrics.unwrap();
        assert_eq!(usage.len(), 3);
        assert!(matches!(usage[0].kind, UsageMetricKind::Tokens));
        assert_eq!(usage[0].amount, 1200);
        let meta = deserialized.response_metadata.unwrap();
        assert_eq!(meta.processing_time_ms, Some(42));
        assert!(!meta.from_cache);
    }

    #[test]
    fn invoke_response_error_case() {
        let resp = InvokeResponse::error(
            RequestId::new("req_002"),
            FcpError::CapabilityDenied {
                capability: "gmail.send".into(),
                reason: "Insufficient permissions".into(),
            },
        );

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: InvokeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, InvokeStatus::Error);
        assert!(deserialized.result.is_none());
        assert!(deserialized.error.is_some());
        assert!(
            matches!(
                &deserialized.error,
                Some(FcpError::CapabilityDenied { capability, .. }) if capability == "gmail.send"
            ),
            "Expected CapabilityDenied error, got {:?}",
            deserialized.error
        );
    }

    #[test]
    fn invoke_response_ok_helper() {
        let resp = InvokeResponse::ok(
            RequestId::new("req_003"),
            serde_json::json!({"data": "test"}),
        )
        .with_receipt_id(ObjectId::test_id("test_receipt"))
        .with_metadata(ResponseMetadata {
            processing_time_ms: Some(10),
            ..Default::default()
        });

        assert_eq!(resp.status, InvokeStatus::Ok);
        assert!(resp.result.is_some());
        assert!(resp.receipt_id.is_some());
        assert!(resp.response_metadata.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Subscribe Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn subscribe_request_serialization_roundtrip() {
        let req = SubscribeRequest {
            r#type: "subscribe".into(),
            id: RequestId::new("sub_001"),
            topics: vec!["messages.*".into(), "events.new".into()],
            since: Some("cursor_start".into()),
            max_events_per_sec: Some(100),
            batch_ms: Some(500),
            window_size: Some(10),
            capability_token: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: SubscribeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.r#type, "subscribe");
        assert_eq!(deserialized.topics.len(), 2);
        assert_eq!(deserialized.since, Some("cursor_start".into()));
        assert_eq!(deserialized.max_events_per_sec, Some(100));
    }

    #[test]
    fn subscribe_response_serialization_roundtrip() {
        let resp = SubscribeResponse {
            r#type: "response".into(),
            id: RequestId::new("sub_001"),
            result: SubscribeResult {
                confirmed_topics: vec!["messages.*".into()],
                cursors: std::iter::once(("messages.*".into(), "cursor_123".into())).collect(),
                replay_supported: true,
                buffer: Some(ReplayBufferInfo {
                    min_events: 1000,
                    overflow: "stream.reset".into(),
                }),
            },
        };

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: SubscribeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.result.confirmed_topics.len(), 1);
        assert!(deserialized.result.replay_supported);
        assert!(deserialized.result.buffer.is_some());
    }

    #[test]
    fn unsubscribe_request_serialization() {
        let req = UnsubscribeRequest {
            r#type: "unsubscribe".into(),
            id: RequestId::new("unsub_001"),
            topics: vec!["messages.*".into()],
            capability_token: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: UnsubscribeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.r#type, "unsubscribe");
        assert_eq!(deserialized.topics.len(), 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Shutdown Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn shutdown_request_defaults() {
        let json = r#"{"type":"shutdown"}"#;
        let req: ShutdownRequest = serde_json::from_str(json).unwrap();

        assert_eq!(req.r#type, "shutdown");
        assert_eq!(req.deadline_ms, 10000); // Default
        assert!(!req.drain);
    }

    #[test]
    fn shutdown_request_with_values() {
        let req = ShutdownRequest {
            r#type: "shutdown".into(),
            deadline_ms: 30000,
            drain: true,
            reason: Some("Maintenance".into()),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: ShutdownRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.deadline_ms, 30000);
        assert!(deserialized.drain);
        assert_eq!(deserialized.reason, Some("Maintenance".into()));
    }

    #[test]
    fn shutdown_ack_serialization() {
        let ack = ShutdownAck {
            r#type: "shutdown_ack".into(),
            status: "completed".into(),
            events_flushed: Some(100),
            requests_completed: Some(5),
        };

        let json = serde_json::to_string(&ack).unwrap();
        let deserialized: ShutdownAck = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.status, "completed");
        assert_eq!(deserialized.events_flushed, Some(100));
        assert_eq!(deserialized.requests_completed, Some(5));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Introspection Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operation_info_serialization_roundtrip() {
        let op = OperationInfo {
            id: "gmail.search".parse().unwrap(),
            summary: "Search emails".into(),
            description: Some("Searches Gmail using query syntax".into()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "array"}),
            capability: "cap.gmail.read".parse().unwrap(),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: AgentHint {
                when_to_use: "When user wants to find emails".into(),
                common_mistakes: vec!["Forgetting date range".into()],
                examples: vec!["gmail.search({query: 'from:alice'})".into()],
                related: vec!["cap.gmail.write".parse().unwrap()],
            },
            rate_limit: Some(crate::RateLimit {
                max: 100,
                per_ms: 60000,
                burst: Some(10),
                scope: Some("per_zone".into()),
                pool_name: None,
            }),
            requires_approval: Some(ApprovalMode::Policy),
        };

        let json = serde_json::to_string(&op).unwrap();
        let deserialized: OperationInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id.as_str(), "gmail.search");
        assert_eq!(deserialized.summary, "Search emails");
        assert!(matches!(deserialized.risk_level, RiskLevel::Low));
        assert!(matches!(deserialized.safety_tier, SafetyTier::Safe));
        assert!(matches!(deserialized.idempotency, IdempotencyClass::Strict));
    }

    #[test]
    fn risk_level_serialization() {
        let levels = [
            (RiskLevel::Low, "low"),
            (RiskLevel::Medium, "medium"),
            (RiskLevel::High, "high"),
            (RiskLevel::Critical, "critical"),
        ];

        for (level, expected) in levels {
            let json = serde_json::to_string(&level).unwrap();
            assert!(json.contains(expected));
            let deserialized: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, level);
        }
    }

    #[test]
    fn safety_tier_serialization() {
        let tiers = [
            (SafetyTier::Safe, "safe"),
            (SafetyTier::Risky, "risky"),
            (SafetyTier::Dangerous, "dangerous"),
            (SafetyTier::Forbidden, "forbidden"),
        ];

        for (tier, expected) in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            assert!(json.contains(expected));
            let deserialized: SafetyTier = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, tier);
        }
    }

    #[test]
    fn idempotency_class_serialization() {
        let classes = [
            (IdempotencyClass::None, "none"),
            (IdempotencyClass::BestEffort, "best_effort"),
            (IdempotencyClass::Strict, "strict"),
        ];

        for (class, expected) in classes {
            let json = serde_json::to_string(&class).unwrap();
            assert!(json.contains(expected));
            let deserialized: IdempotencyClass = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, class);
        }
    }

    #[test]
    fn approval_mode_serialization() {
        let modes = [
            (ApprovalMode::None, "none"),
            (ApprovalMode::Policy, "policy"),
            (ApprovalMode::Interactive, "interactive"),
            (ApprovalMode::ElevationToken, "elevation_token"),
        ];

        for (mode, expected) in modes {
            let json = serde_json::to_string(&mode).unwrap();
            assert!(json.contains(expected));
            let deserialized: ApprovalMode = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, mode);
        }
    }

    #[test]
    fn introspection_serialization() {
        let intro = Introspection {
            operations: vec![],
            events: vec![EventInfo {
                topic: "messages.new".into(),
                schema: serde_json::json!({"type": "object"}),
                requires_ack: true,
            }],
            resource_types: vec![ResourceTypeInfo {
                name: "Message".into(),
                uri_pattern: "fcp://fcp.gmail/message/{id}".into(),
                schema: serde_json::json!({"type": "object"}),
            }],
            auth_caps: None,
            event_caps: Some(EventCaps::default()),
        };

        let json = serde_json::to_string(&intro).unwrap();
        let deserialized: Introspection = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.events.len(), 1);
        assert_eq!(deserialized.resource_types.len(), 1);
        assert!(deserialized.event_caps.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Transport / Host Info Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_info_serialization() {
        let info = HostInfo {
            name: "test-hub".into(),
            version: Some("1.0.0".into()),
            build: Some("git-abc123".into()),
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: HostInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, "test-hub");
        assert_eq!(deserialized.version, Some("1.0.0".into()));
        assert_eq!(deserialized.build, Some("git-abc123".into()));
    }

    #[test]
    fn transport_caps_default() {
        let caps = TransportCaps::default();
        assert!(caps.compression.is_empty());
        assert!(caps.max_frame_size.is_none());
    }

    #[test]
    fn event_caps_default() {
        let caps = EventCaps::default();
        assert!(!caps.streaming);
        assert!(!caps.replay);
        assert_eq!(caps.min_buffer_events, 0);
        assert!(!caps.requires_ack);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SessionId and CorrelationId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn session_id_unique() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        assert_ne!(id1.0, id2.0);
    }

    #[test]
    fn session_id_display() {
        let id = SessionId::new();
        let display = id.to_string();
        assert!(!display.is_empty());
    }

    #[test]
    fn correlation_id_unique() {
        let id1 = CorrelationId::new();
        let id2 = CorrelationId::new();
        assert_ne!(id1.0, id2.0);
    }

    #[test]
    fn correlation_id_display() {
        let id = CorrelationId::new();
        let display = id.to_string();
        assert!(!display.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Simulate Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn base_simulate_request() -> SimulateRequest {
        SimulateRequest::new(
            ConnectorId::from_static("gmail:fcp2:1.0"),
            "gmail.search".parse().unwrap(),
            ZoneId::work(),
            serde_json::json!({"query": "from:alice"}),
            CapabilityToken::test_token(),
        )
    }

    #[test]
    fn simulate_request_new() {
        let req = base_simulate_request();
        assert_eq!(req.r#type, "simulate");
        assert_eq!(req.connector_id.as_str(), "gmail:fcp2:1.0");
        assert_eq!(req.operation.as_str(), "gmail.search");
        assert!(!req.estimate_cost);
        assert!(!req.check_availability);
    }

    #[test]
    fn simulate_request_with_options() {
        let req = base_simulate_request()
            .with_cost_estimate()
            .with_availability_check()
            .with_correlation_id(CorrelationId::new());

        assert!(req.estimate_cost);
        assert!(req.check_availability);
        assert!(req.correlation_id.is_some());
    }

    #[test]
    fn simulate_request_serialization_roundtrip() {
        let req = SimulateRequest {
            r#type: "simulate".into(),
            id: RequestId::new("sim_001"),
            connector_id: ConnectorId::from_static("gmail:fcp2:1.0"),
            operation: "gmail.search".parse().unwrap(),
            zone_id: ZoneId::work(),
            input: serde_json::json!({"query": "test"}),
            capability_token: CapabilityToken::test_token(),
            estimate_cost: true,
            check_availability: true,
            context: Some(InvokeContext {
                locale: Some("en-US".into()),
                pagination: None,
                trace_id: Some("trace-123".into()),
                request_tags: HashMap::default(),
            }),
            correlation_id: Some(CorrelationId::new()),
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: SimulateRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.r#type, "simulate");
        assert_eq!(deserialized.id.0, "sim_001");
        assert_eq!(deserialized.connector_id.as_str(), "gmail:fcp2:1.0");
        assert!(deserialized.estimate_cost);
        assert!(deserialized.check_availability);
        assert!(deserialized.context.is_some());
    }

    #[test]
    fn simulate_response_allowed() {
        let resp = SimulateResponse::allowed(RequestId::new("sim_001"));

        assert_eq!(resp.r#type, "simulate_response");
        assert_eq!(resp.id.0, "sim_001");
        assert!(resp.would_succeed);
        assert!(resp.failure_reason.is_none());
        assert!(resp.denial_code.is_none());
        assert!(resp.missing_capabilities.is_empty());
    }

    #[test]
    fn simulate_response_denied() {
        let resp = SimulateResponse::denied(
            RequestId::new("sim_002"),
            "Insufficient permissions",
            "FCP-3001",
        )
        .with_missing_capabilities(vec!["gmail.send".into()]);

        assert!(!resp.would_succeed);
        assert_eq!(resp.failure_reason, Some("Insufficient permissions".into()));
        assert_eq!(resp.denial_code, Some("FCP-3001".into()));
        assert_eq!(resp.missing_capabilities, vec!["gmail.send".to_string()]);
    }

    #[test]
    fn simulate_response_with_cost() {
        let cost = CostEstimate::with_credits(1000)
            .and_duration_ms(500)
            .and_bytes(4096);

        let resp = SimulateResponse::allowed(RequestId::new("sim_003")).with_cost_estimate(cost);

        assert!(resp.estimated_cost.is_some());
        let cost = resp.estimated_cost.unwrap();
        assert_eq!(cost.api_credits, Some(1000));
        assert_eq!(cost.estimated_duration_ms, Some(500));
        assert_eq!(cost.estimated_bytes, Some(4096));
    }

    #[test]
    fn simulate_response_with_availability() {
        let availability =
            ResourceAvailability::available().with_rate_limit(95, Some(1_700_000_000));

        let resp =
            SimulateResponse::allowed(RequestId::new("sim_004")).with_availability(availability);

        assert!(resp.availability.is_some());
        let avail = resp.availability.unwrap();
        assert!(avail.available);
        assert_eq!(avail.rate_limit_remaining, Some(95));
        assert_eq!(avail.rate_limit_reset_at, Some(1_700_000_000));
    }

    #[test]
    fn simulate_response_serialization_roundtrip() {
        let resp = SimulateResponse::allowed(RequestId::new("sim_005"))
            .with_cost_estimate(CostEstimate::with_credits(500))
            .with_availability(ResourceAvailability::available())
            .with_metadata(ResponseMetadata {
                processing_time_ms: Some(10),
                ..Default::default()
            });

        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: SimulateResponse = serde_json::from_str(&json).unwrap();

        assert!(deserialized.would_succeed);
        assert!(deserialized.estimated_cost.is_some());
        assert!(deserialized.availability.is_some());
        assert!(deserialized.response_metadata.is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CostEstimate Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cost_estimate_with_credits() {
        let cost = CostEstimate::with_credits(1000);
        assert_eq!(cost.api_credits, Some(1000));
        assert!(cost.estimated_duration_ms.is_none());
        assert!(cost.estimated_bytes.is_none());
        assert!(cost.currency.is_none());
        assert!(cost.confidence.is_none());
    }

    #[test]
    fn cost_estimate_with_duration() {
        let cost = CostEstimate::with_duration_ms(250);
        assert!(cost.api_credits.is_none());
        assert_eq!(cost.estimated_duration_ms, Some(250));
        assert!(cost.confidence.is_none());
    }

    #[test]
    fn cost_estimate_with_bytes() {
        let cost = CostEstimate::with_bytes(8192);
        assert_eq!(cost.estimated_bytes, Some(8192));
        assert!(cost.confidence.is_none());
    }

    #[test]
    fn cost_estimate_builder_chain() {
        let cost = CostEstimate::with_credits(100)
            .and_duration_ms(50)
            .and_bytes(1024)
            .and_currency(CurrencyCost::usd_cents(5))
            .and_confidence(CostEstimateConfidence::High);

        assert_eq!(cost.api_credits, Some(100));
        assert_eq!(cost.estimated_duration_ms, Some(50));
        assert_eq!(cost.estimated_bytes, Some(1024));
        assert!(cost.currency.is_some());
        assert_eq!(cost.confidence, Some(CostEstimateConfidence::High));
        let currency = cost.currency.unwrap();
        assert_eq!(currency.amount_cents, 5);
        assert_eq!(currency.currency_code, "USD");
    }

    #[test]
    fn cost_estimate_default() {
        let cost = CostEstimate::default();
        assert!(cost.api_credits.is_none());
        assert!(cost.estimated_duration_ms.is_none());
        assert!(cost.estimated_bytes.is_none());
        assert!(cost.currency.is_none());
        assert!(cost.confidence.is_none());
    }

    #[test]
    fn cost_estimate_serialization_roundtrip() {
        let cost = CostEstimate::with_credits(1500)
            .and_duration_ms(300)
            .and_bytes(2048)
            .and_currency(CurrencyCost::new(10, "EUR"))
            .and_confidence(CostEstimateConfidence::Medium);

        let json = serde_json::to_string(&cost).unwrap();
        let deserialized: CostEstimate = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.api_credits, Some(1500));
        assert_eq!(deserialized.estimated_duration_ms, Some(300));
        assert_eq!(deserialized.estimated_bytes, Some(2048));
        assert!(deserialized.currency.is_some());
        assert_eq!(
            deserialized.confidence,
            Some(CostEstimateConfidence::Medium)
        );
        let currency = deserialized.currency.unwrap();
        assert_eq!(currency.amount_cents, 10);
        assert_eq!(currency.currency_code, "EUR");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CurrencyCost Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn currency_cost_new() {
        let cost = CurrencyCost::new(500, "USD");
        assert_eq!(cost.amount_cents, 500);
        assert_eq!(cost.currency_code, "USD");
    }

    #[test]
    fn currency_cost_usd_cents() {
        let cost = CurrencyCost::usd_cents(1234);
        assert_eq!(cost.amount_cents, 1234);
        assert_eq!(cost.currency_code, "USD");
    }

    #[test]
    fn currency_cost_serialization_roundtrip() {
        let cost = CurrencyCost::new(9999, "GBP");

        let json = serde_json::to_string(&cost).unwrap();
        let deserialized: CurrencyCost = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.amount_cents, 9999);
        assert_eq!(deserialized.currency_code, "GBP");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ResourceAvailability Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn resource_availability_available() {
        let avail = ResourceAvailability::available();
        assert!(avail.available);
        assert!(avail.rate_limit_remaining.is_none());
        assert!(avail.rate_limit_reset_at.is_none());
        assert!(avail.details.is_none());
    }

    #[test]
    fn resource_availability_unavailable() {
        let avail = ResourceAvailability::unavailable("Resource deleted");
        assert!(!avail.available);
        assert_eq!(avail.details, Some("Resource deleted".into()));
    }

    #[test]
    fn resource_availability_with_rate_limit() {
        let avail = ResourceAvailability::available().with_rate_limit(50, Some(1_700_000_000));

        assert!(avail.available);
        assert_eq!(avail.rate_limit_remaining, Some(50));
        assert_eq!(avail.rate_limit_reset_at, Some(1_700_000_000));
    }

    #[test]
    fn resource_availability_with_details() {
        let avail = ResourceAvailability::available().with_details("Healthy");

        assert_eq!(avail.details, Some("Healthy".into()));
    }

    #[test]
    fn resource_availability_serialization_roundtrip() {
        let avail = ResourceAvailability::available()
            .with_rate_limit(100, Some(1_700_000_000))
            .with_details("Healthy");

        let json = serde_json::to_string(&avail).unwrap();
        let deserialized: ResourceAvailability = serde_json::from_str(&json).unwrap();

        assert!(deserialized.available);
        assert_eq!(deserialized.rate_limit_remaining, Some(100));
        assert_eq!(deserialized.rate_limit_reset_at, Some(1_700_000_000));
        assert_eq!(deserialized.details, Some("Healthy".into()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UsageMetricKind tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn usage_metric_kind_as_str_all_variants() {
        assert_eq!(UsageMetricKind::ApiCredits.as_str(), "api_credits");
        assert_eq!(UsageMetricKind::Tokens.as_str(), "tokens");
        assert_eq!(UsageMetricKind::Bytes.as_str(), "bytes");
        assert_eq!(UsageMetricKind::DurationMs.as_str(), "duration_ms");
        assert_eq!(UsageMetricKind::Requests.as_str(), "requests");
        assert_eq!(UsageMetricKind::Custom.as_str(), "custom");
    }

    #[test]
    fn usage_metric_kind_serde_roundtrip_all() {
        for kind in [
            UsageMetricKind::ApiCredits,
            UsageMetricKind::Tokens,
            UsageMetricKind::Bytes,
            UsageMetricKind::DurationMs,
            UsageMetricKind::Requests,
            UsageMetricKind::Custom,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: UsageMetricKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn usage_metric_kind_copy_clone() {
        let a = UsageMetricKind::Tokens;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UsageMetric factory methods
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn usage_metric_api_credits() {
        let m = UsageMetric::api_credits(500);
        assert!(matches!(m.kind, UsageMetricKind::ApiCredits));
        assert_eq!(m.amount, 500);
        assert!(m.unit.is_none());
        assert!(m.custom_id.is_none());
    }

    #[test]
    fn usage_metric_tokens() {
        let m = UsageMetric::tokens(1200);
        assert!(matches!(m.kind, UsageMetricKind::Tokens));
        assert_eq!(m.amount, 1200);
    }

    #[test]
    fn usage_metric_bytes_factory() {
        let m = UsageMetric::bytes(4096);
        assert!(matches!(m.kind, UsageMetricKind::Bytes));
        assert_eq!(m.amount, 4096);
    }

    #[test]
    fn usage_metric_duration_ms() {
        let m = UsageMetric::duration_ms(75);
        assert!(matches!(m.kind, UsageMetricKind::DurationMs));
        assert_eq!(m.amount, 75);
    }

    #[test]
    fn usage_metric_requests() {
        let m = UsageMetric::requests(10);
        assert!(matches!(m.kind, UsageMetricKind::Requests));
        assert_eq!(m.amount, 10);
    }

    #[test]
    fn usage_metric_custom() {
        let m = UsageMetric::custom("widgets", 99, Some("count".into()));
        assert!(matches!(m.kind, UsageMetricKind::Custom));
        assert_eq!(m.amount, 99);
        assert_eq!(m.custom_id, Some("widgets".into()));
        assert_eq!(m.unit, Some("count".into()));
    }

    #[test]
    fn usage_metric_with_unit() {
        let m = UsageMetric::tokens(100).with_unit("input_tokens");
        assert_eq!(m.unit, Some("input_tokens".into()));
        assert_eq!(m.amount, 100);
    }

    #[test]
    fn usage_metric_serde_roundtrip() {
        let m = UsageMetric::custom("widgets", 99, Some("count".into()));
        let json = serde_json::to_string(&m).unwrap();
        let back: UsageMetric = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.kind, UsageMetricKind::Custom));
        assert_eq!(back.amount, 99);
        assert_eq!(back.custom_id, Some("widgets".into()));
        assert_eq!(back.unit, Some("count".into()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // InvokeValidationError all variants
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn invoke_validation_error_holder_proof_required() {
        let err = InvokeValidationError::HolderProofRequired;
        let msg = err.to_string();
        assert!(msg.contains("holder_proof required"));
    }

    #[test]
    fn invoke_validation_error_holder_proof_invalid() {
        let err = InvokeValidationError::HolderProofInvalid;
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn invoke_validation_error_holder_node_mismatch() {
        let err = InvokeValidationError::HolderNodeMismatch {
            proof_node: "node-A".into(),
            token_node: "node-B".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("node-A"));
        assert!(msg.contains("node-B"));
    }

    #[test]
    fn invoke_validation_error_idempotency_key_required() {
        let err = InvokeValidationError::IdempotencyKeyRequired {
            safety_tier: SafetyTier::Dangerous,
        };
        assert!(err.to_string().contains("idempotency_key required"));
    }

    #[test]
    fn invoke_validation_error_lease_seq_required() {
        let err = InvokeValidationError::LeaseSeqRequired;
        assert!(err.to_string().contains("lease_seq required"));
    }

    #[test]
    fn invoke_validation_error_lease_seq_stale() {
        let err = InvokeValidationError::LeaseSeqStale {
            provided: 5,
            current: 10,
        };
        let msg = err.to_string();
        assert!(msg.contains('5'));
        assert!(msg.contains("10"));
    }

    #[test]
    fn invoke_validation_error_clone() {
        let err = InvokeValidationError::HolderProofRequired;
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // InvokeStatus trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn invoke_status_serde_roundtrip() {
        for status in [InvokeStatus::Ok, InvokeStatus::Error] {
            let json = serde_json::to_string(&status).unwrap();
            let back: InvokeStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn invoke_status_copy_clone() {
        let a = InvokeStatus::Ok;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // InvokeContext trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn invoke_context_default() {
        let ctx = InvokeContext::default();
        assert!(ctx.locale.is_none());
        assert!(ctx.pagination.is_none());
        assert!(ctx.trace_id.is_none());
        assert!(ctx.request_tags.is_empty());
    }

    #[test]
    fn invoke_context_clone() {
        let ctx = InvokeContext {
            locale: Some("ja-JP".into()),
            pagination: Some(serde_json::json!({"page": 2})),
            trace_id: Some("trace-abc".into()),
            request_tags: std::iter::once(("env".into(), "prod".into())).collect(),
        };
        let cloned = ctx;
        assert_eq!(cloned.locale, Some("ja-JP".into()));
        assert_eq!(cloned.request_tags.get("env"), Some(&"prod".into()));
    }

    #[test]
    fn invoke_context_serde_roundtrip() {
        let ctx = InvokeContext {
            locale: Some("de-DE".into()),
            pagination: None,
            trace_id: Some("trace-xyz".into()),
            request_tags: HashMap::new(),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: InvokeContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.locale, Some("de-DE".into()));
        assert_eq!(back.trace_id, Some("trace-xyz".into()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ResponseMetadata trait coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn response_metadata_default() {
        let meta = ResponseMetadata::default();
        assert!(meta.processing_time_ms.is_none());
        assert!(meta.cache_ttl_secs.is_none());
        assert!(!meta.from_cache);
        assert!(meta.retry_after_secs.is_none());
    }

    #[test]
    fn response_metadata_clone() {
        let meta = ResponseMetadata {
            processing_time_ms: Some(42),
            cache_ttl_secs: Some(300),
            from_cache: true,
            retry_after_secs: Some(60),
            route: None,
        };
        let cloned = meta;
        assert_eq!(cloned.processing_time_ms, Some(42));
        assert!(cloned.from_cache);
        assert_eq!(cloned.retry_after_secs, Some(60));
    }

    #[test]
    fn response_metadata_serde_roundtrip() {
        let meta = ResponseMetadata {
            processing_time_ms: Some(100),
            cache_ttl_secs: None,
            from_cache: false,
            retry_after_secs: Some(30),
            route: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: ResponseMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.processing_time_ms, Some(100));
        assert_eq!(back.retry_after_secs, Some(30));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AuthCaps / OAuthConfig / AgentHint / EventInfo / ResourceTypeInfo
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn auth_caps_clone_and_serde() {
        let caps = AuthCaps {
            methods: vec!["oauth2".into(), "api_key".into()],
            oauth: Some(OAuthConfig {
                authorize_url: "https://auth.example.com/authorize".into(),
                token_url: "https://auth.example.com/token".into(),
                scopes: vec!["read".into(), "write".into()],
            }),
        };
        let cloned = caps.clone();
        assert_eq!(cloned.methods.len(), 2);
        assert!(cloned.oauth.is_some());

        let json = serde_json::to_string(&caps).unwrap();
        let back: AuthCaps = serde_json::from_str(&json).unwrap();
        assert_eq!(back.methods, vec!["oauth2", "api_key"]);
        let oauth = back.oauth.unwrap();
        assert_eq!(oauth.scopes.len(), 2);
    }

    #[test]
    fn oauth_config_clone_and_serde() {
        let cfg = OAuthConfig {
            authorize_url: "https://a.test/auth".into(),
            token_url: "https://a.test/token".into(),
            scopes: vec!["admin".into()],
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.authorize_url, "https://a.test/auth");

        let json = serde_json::to_string(&cfg).unwrap();
        let back: OAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.token_url, "https://a.test/token");
        assert_eq!(back.scopes, vec!["admin"]);
    }

    #[test]
    fn agent_hint_default_and_serde() {
        let hint = AgentHint::default();
        assert!(hint.when_to_use.is_empty());
        assert!(hint.common_mistakes.is_empty());
        assert!(hint.examples.is_empty());
        assert!(hint.related.is_empty());

        let json = serde_json::to_string(&hint).unwrap();
        let back: AgentHint = serde_json::from_str(&json).unwrap();
        assert!(back.when_to_use.is_empty());
    }

    #[test]
    fn event_info_clone_and_serde() {
        let info = EventInfo {
            topic: "messages.new".into(),
            schema: serde_json::json!({"type": "object"}),
            requires_ack: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.topic, "messages.new");
        assert!(cloned.requires_ack);

        let json = serde_json::to_string(&info).unwrap();
        let back: EventInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.topic, "messages.new");
    }

    #[test]
    fn resource_type_info_clone_and_serde() {
        let info = ResourceTypeInfo {
            name: "Email".into(),
            uri_pattern: "fcp://fcp.gmail/message/{id}".into(),
            schema: serde_json::json!({"type": "object"}),
        };
        let cloned = info.clone();
        assert_eq!(cloned.name, "Email");

        let json = serde_json::to_string(&info).unwrap();
        let back: ResourceTypeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uri_pattern, "fcp://fcp.gmail/message/{id}");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ProvisioningSessionId
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provisioning_session_id_new_and_display() {
        let id = ProvisioningSessionId::new("prov-123");
        assert_eq!(id.as_str(), "prov-123");
        assert_eq!(id.to_string(), "prov-123");
    }

    #[test]
    fn provisioning_session_id_random_unique() {
        let a = ProvisioningSessionId::random();
        let b = ProvisioningSessionId::random();
        assert_ne!(a.as_str(), b.as_str());
        assert!(a.as_str().starts_with("prov_"));
    }

    #[test]
    fn provisioning_session_id_serde_roundtrip() {
        let id = ProvisioningSessionId::new("my-session");
        let json = serde_json::to_string(&id).unwrap();
        let back: ProvisioningSessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_str(), "my-session");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Provisioning payloads (zero-test types)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn provisioning_start_input_serde() {
        let input = ProvisioningStartInput {
            recipe_id: Some(RecipeId::new("default-recipe")),
            config: Some(serde_json::json!({"mode": "fast"})),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: ProvisioningStartInput = serde_json::from_str(&json).unwrap();
        assert!(back.recipe_id.is_some());
        assert!(back.config.is_some());
    }

    #[test]
    fn provisioning_poll_input_serde() {
        let input = ProvisioningPollInput {
            session_id: Some(ProvisioningSessionId::new("sess-1")),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: ProvisioningPollInput = serde_json::from_str(&json).unwrap();
        assert!(back.session_id.is_some());
    }

    #[test]
    fn provisioning_input_serde() {
        let input = ProvisioningInput {
            step_id: StepId::new("step-oauth"),
            value: serde_json::json!({"token": "abc123"}),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: ProvisioningInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.step_id.as_str(), "step-oauth");
    }

    #[test]
    fn provisioning_complete_input_serde() {
        let input = ProvisioningCompleteInput {
            session_id: Some(ProvisioningSessionId::new("sess-2")),
            inputs: vec![ProvisioningInput {
                step_id: StepId::new("step-1"),
                value: serde_json::json!("done"),
            }],
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: ProvisioningCompleteInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.inputs.len(), 1);
    }

    #[test]
    fn provisioning_abort_input_serde() {
        let input = ProvisioningAbortInput {
            session_id: None,
            reason: Some("User cancelled".into()),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: ProvisioningAbortInput = serde_json::from_str(&json).unwrap();
        assert!(back.session_id.is_none());
        assert_eq!(back.reason, Some("User cancelled".into()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ReplayBufferInfo / SubscribeResult / EventAckRequest / EventNackRequest
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn replay_buffer_info_clone_and_serde() {
        let info = ReplayBufferInfo {
            min_events: 5000,
            overflow: "stream.reset".into(),
        };
        let cloned = info.clone();
        assert_eq!(cloned.min_events, 5000);

        let json = serde_json::to_string(&info).unwrap();
        let back: ReplayBufferInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.overflow, "stream.reset");
    }

    #[test]
    fn subscribe_result_clone_and_serde() {
        let result = SubscribeResult {
            confirmed_topics: vec!["events.*".into()],
            cursors: std::iter::once(("events.*".into(), "cur-1".into())).collect(),
            replay_supported: false,
            buffer: None,
        };
        let cloned = result.clone();
        assert_eq!(cloned.confirmed_topics.len(), 1);
        assert!(!cloned.replay_supported);

        let json = serde_json::to_string(&result).unwrap();
        let back: SubscribeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cursors.get("events.*"), Some(&"cur-1".into()));
    }

    #[test]
    fn event_ack_request_serde() {
        let req = EventAckRequest {
            r#type: "ack".into(),
            id: RequestId::new("ack-1"),
            ack: EventAck {
                r#type: "ack".into(),
                topic: "messages.new".into(),
                seqs: vec![1, 2, 3],
                cursors: vec!["cur-1".into()],
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: EventAckRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.r#type, "ack");
        assert_eq!(back.ack.seqs.len(), 3);
    }

    #[test]
    fn event_nack_request_serde() {
        let req = EventNackRequest {
            r#type: "nack".into(),
            id: RequestId::new("nack-1"),
            nack: EventNack {
                r#type: "nack".into(),
                topic: "events.new".into(),
                seqs: vec![5],
                reason: "Processing failed".into(),
                delay_ms: Some(5000),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: EventNackRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.r#type, "nack");
        assert_eq!(back.nack.delay_ms, Some(5000));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // InvokeResponse builder coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn invoke_response_with_audit_event_id() {
        let resp = InvokeResponse::ok(RequestId::new("req-audit"), serde_json::json!({}))
            .with_audit_event_id(ObjectId::test_id("audit-1"));
        assert!(resp.audit_event_id.is_some());
    }

    #[test]
    fn invoke_response_with_decision_receipt_id() {
        let resp = InvokeResponse::error(
            RequestId::new("req-deny"),
            FcpError::CapabilityDenied {
                capability: "cap.write".into(),
                reason: "denied".into(),
            },
        )
        .with_decision_receipt_id(ObjectId::test_id("decision-1"));
        assert!(resp.decision_receipt_id.is_some());
    }

    #[test]
    fn invoke_response_with_usage_metrics() {
        let resp = InvokeResponse::ok(RequestId::new("req-usage"), serde_json::json!({}))
            .with_usage_metrics(vec![UsageMetric::tokens(500), UsageMetric::api_credits(10)]);
        let metrics = resp.usage_metrics.unwrap();
        assert_eq!(metrics.len(), 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RequestId Hash + Eq
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn request_id_eq_and_hash() {
        use std::collections::HashSet;
        let a = RequestId::new("r1");
        let b = RequestId::new("r1");
        let c = RequestId::new("r2");
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HostInfo optional fields
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn host_info_minimal() {
        let info = HostInfo {
            name: "hub".into(),
            version: None,
            build: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("version"));
        assert!(!json.contains("build"));
        let back: HostInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "hub");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EventCaps serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn event_caps_serde_roundtrip() {
        let caps = EventCaps {
            streaming: true,
            replay: true,
            min_buffer_events: 500,
            requires_ack: true,
        };
        let json = serde_json::to_string(&caps).unwrap();
        let back: EventCaps = serde_json::from_str(&json).unwrap();
        assert!(back.streaming);
        assert!(back.replay);
        assert_eq!(back.min_buffer_events, 500);
        assert!(back.requires_ack);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TransportCaps serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn transport_caps_serde_roundtrip() {
        let caps = TransportCaps {
            compression: vec!["zstd".into(), "lz4".into()],
            max_frame_size: Some(65536),
        };
        let json = serde_json::to_string(&caps).unwrap();
        let back: TransportCaps = serde_json::from_str(&json).unwrap();
        assert_eq!(back.compression.len(), 2);
        assert_eq!(back.max_frame_size, Some(65536));
    }
}
