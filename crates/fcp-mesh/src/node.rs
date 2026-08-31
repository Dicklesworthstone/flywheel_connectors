//! MeshNode orchestration glue for FCP2.
//!
//! This module ties together admission control, gossip, symbol requests,
//! degraded-mode control-plane transport, and execution planning into a
//! single cohesive node interface.
//!
//! The goal is to provide a safe, explicit surface for MeshNode behavior
//! without embedding transport specifics.

#![forbid(unsafe_code)]
#![allow(clippy::too_many_lines)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use fcp_cbor::CanonicalSerializer;
use fcp_crypto::{CryptoError, CwtClaims, Ed25519Signature, Ed25519VerifyingKey};
use fcp_prelude::{
    CapabilityVerifier, ConnectorStateChange, EvictionPolicy, FcpError, InvokeRequest,
    InvokeValidationError, Lease as CoreLease, LeaseValidationError as CoreLeaseValidationError,
    ObjectId, ObjectIdKey, OperationIntent, OperationReceipt, RevocationRegistry, StorageMeta,
    StoredObject, TailscaleNodeId, ZoneId, ZoneKey, ZoneKeyAlgorithm, ZoneTransportPolicy,
    validate_lease as validate_core_lease,
};
use fcp_protocol::{DecodeStatus, SymbolAck, SymbolRequest};
use fcp_raptorq::RaptorQConfig;
use fcp_store::{
    ConnectorStateStoreError, FcpStoreConnectorStateStore, ObjectStore, ObjectSymbolMeta,
    QuarantineStore, StoredSymbol, SymbolStore,
};
use fcp_tailscale::NodeId;
use fcp_telemetry::trace_capture::{
    AdmissionOutcome, CapturedTrace, GossipEvent, LeaseEvent, RoutingDecision, SessionEvent,
    TraceCapture, TraceCaptureConfig, TraceEvent, TraceExportFormat,
};
use fcp_telemetry::{TraceContext, metrics};
use hex::encode;
use thiserror::Error;
use tracing::{debug, warn};

use crate::admission::{
    AdmissionController, AdmissionError, AdmissionPolicy, ObjectAdmissionClass,
};
use crate::authority::{AuthorityView, ObservedLeaseAuthority};
use crate::degraded::{
    ControlPlaneEnvelope, ControlPlaneHandler, DegradedModeDecoder, DegradedModeEncoder,
    DegradedTransportError, RetentionClass,
};
use crate::device::DeviceProfile;
use crate::gossip::{
    GossipConfig, GossipMessage, GossipRequest, GossipResponse, GossipSummary, IbltPlaceholder,
    MAX_OBJECT_IDS_PER_REQUEST, MeshGossip, PeerCapabilityAdvertisement, PeerProtocolCapabilities,
    ReconcileRequest, ReconcileResponse, RevocationPushMessage,
};
use crate::planner::{
    BetaPosterior, CandidateNode, DecisionReason, ExecutionPlanner, HeldLease, LeasePurpose,
    NodeInfo, PlannerContext, PlannerInput, ResourcePoolClass, ThompsonChoice, ThompsonScheduler,
};
use crate::revocation::{
    RevocationFreshnessDecision, RevocationFreshnessFrontier, VersionVectorOrder,
};
use crate::session::MeshSession;
use crate::symbol_request::{
    SymbolRequestError, SymbolRequestHandler, SymbolRequestMetrics, SymbolRequestPolicy,
    SymbolResponse, SymbolResponseBuilder, TargetedRepairEngine, TransferKey, ValidatedRequest,
};
use crate::transport::{RankedPath, TransportPath, TransportSelector};

const DEFAULT_LEASE_PUBLICATION_REQUIRED_QUORUM_SIGNATURES: usize = 2;

/// MeshNode configuration (builder-style).
#[derive(Debug, Clone)]
pub struct MeshNodeConfig {
    /// Local node ID (Tailscale).
    pub node_id: String,
    /// Admission control policy.
    pub admission_policy: AdmissionPolicy,
    /// Gossip configuration.
    pub gossip_config: GossipConfig,
    /// Symbol request policy.
    pub symbol_request_policy: SymbolRequestPolicy,
    /// RaptorQ configuration for degraded control-plane transport.
    pub raptorq_config: RaptorQConfig,
    /// Sender instance ID for degraded-mode frames (reboot-safety).
    pub sender_instance_id: u64,
    /// Trace capture configuration.
    pub trace_capture: TraceCaptureConfig,
    /// Optional allowlist of zones to capture.
    pub trace_capture_zones: Option<HashSet<ZoneId>>,
}

impl MeshNodeConfig {
    /// Create a new config with defaults and a node ID.
    #[must_use]
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            admission_policy: AdmissionPolicy::default(),
            gossip_config: GossipConfig::default(),
            symbol_request_policy: SymbolRequestPolicy::default(),
            raptorq_config: RaptorQConfig::default(),
            sender_instance_id: rand::random::<u64>(),
            trace_capture: TraceCaptureConfig::default(),
            trace_capture_zones: None,
        }
    }

    /// Override admission policy.
    #[must_use]
    pub fn with_admission_policy(mut self, policy: AdmissionPolicy) -> Self {
        self.admission_policy = policy;
        self
    }

    /// Override gossip configuration.
    #[must_use]
    pub fn with_gossip_config(mut self, config: GossipConfig) -> Self {
        self.gossip_config = config;
        self
    }

    /// Override symbol request policy.
    #[must_use]
    pub fn with_symbol_request_policy(mut self, policy: SymbolRequestPolicy) -> Self {
        self.symbol_request_policy = policy;
        self
    }

    /// Override RaptorQ configuration.
    #[must_use]
    pub fn with_raptorq_config(mut self, config: RaptorQConfig) -> Self {
        self.raptorq_config = config;
        self
    }

    /// Override sender instance ID.
    #[must_use]
    pub const fn with_sender_instance_id(mut self, sender_instance_id: u64) -> Self {
        self.sender_instance_id = sender_instance_id;
        self
    }

    /// Override trace capture configuration.
    #[must_use]
    pub fn with_trace_capture_config(mut self, config: TraceCaptureConfig) -> Self {
        self.trace_capture = config;
        self
    }

    /// Override trace capture zone allowlist.
    #[must_use]
    pub fn with_trace_capture_zones<I>(mut self, zones: I) -> Self
    where
        I: IntoIterator<Item = ZoneId>,
    {
        self.trace_capture_zones = Some(zones.into_iter().collect());
        self
    }
}

/// MeshNode errors for orchestration surfaces.
#[derive(Debug, Error)]
pub enum MeshNodeError {
    /// Admission control rejected a request.
    #[error("admission rejected: {0}")]
    Admission(#[from] AdmissionError),

    /// Symbol request handling error.
    #[error("symbol request error: {0}")]
    SymbolRequest(#[from] SymbolRequestError),

    /// Object store error.
    #[error("object store error: {0}")]
    ObjectStore(#[from] fcp_store::ObjectStoreError),

    /// Symbol store error.
    #[error("symbol store error: {0}")]
    SymbolStore(#[from] fcp_store::SymbolStoreError),

    /// Quarantine error.
    #[error("quarantine error: {0}")]
    Quarantine(#[from] fcp_store::QuarantineError),

    /// Degraded-mode transport error.
    #[error("degraded transport error: {0}")]
    DegradedTransport(#[from] DegradedTransportError),

    /// Enforcement error.
    #[error("enforcement error: {0}")]
    Enforcement(#[from] MeshNodeEnforcementError),

    /// Durable lease object failed validation before mesh publication.
    #[error("lease validation error: {0}")]
    LeaseValidation(#[from] CoreLeaseValidationError),

    /// Durable lease quorum signing bytes could not be canonicalized.
    #[error("lease quorum signing bytes error: {0}")]
    LeaseQuorumSigningBytes(#[from] CryptoError),

    /// Required peer signing key is not registered.
    #[error("missing peer signing key for {peer}")]
    PeerSigningKeyMissing { peer: String },

    /// Control-plane peer signature verification failed.
    #[error("invalid {message_kind} signature from {peer}")]
    PeerSignatureInvalid {
        peer: String,
        message_kind: &'static str,
    },

    /// Control-plane message was signed for a different recipient node.
    #[error("{message_kind} recipient mismatch: expected {expected}, got {actual}")]
    RecipientMismatch {
        message_kind: &'static str,
        expected: String,
        actual: String,
    },

    /// Attached node signature is bound to the wrong node identifier.
    #[error("{message_kind} signature node mismatch: expected {expected}, got {actual}")]
    SignatureNodeMismatch {
        message_kind: &'static str,
        expected: String,
        actual: String,
    },

    /// Gossip control-plane message timestamp is outside the allowed freshness window.
    #[error("stale {message_kind} from {peer}")]
    StaleGossipMessage {
        peer: String,
        message_kind: &'static str,
    },

    /// Peer is not authorized for the requested zone.
    #[error("peer {peer} is not authorized for zone {zone_id}")]
    UnauthorizedZone { peer: String, zone_id: String },

    /// Peer protocol capabilities cannot satisfy the receiver policy.
    #[error("peer {peer} advertised {advertised:?}, but receiver policy requires v4")]
    PeerCapabilityRejected {
        peer: String,
        advertised: PeerProtocolCapabilities,
    },

    /// Peer has a registered signing key but no entry in `peers` — the
    /// attested handshake / enrollment step that populates zone
    /// membership hasn't completed yet. Control-plane messages cannot
    /// be accepted from peers in this state because the zone-policy
    /// gate has nothing to compare against.
    #[error("peer {peer} has no registered peer state (handshake/enrollment incomplete)")]
    UnknownPeer {
        /// Peer node identifier.
        peer: String,
        /// Control-plane message kind ("gossip summary" / "revocation push").
        message_kind: &'static str,
    },

    /// No zone-owner key is registered for the zone targeted by a
    /// revocation push. Pushes must be authorized by the zone owner's
    /// signature; a recipient that does not know the owner key cannot
    /// verify authorization and MUST reject the push (br-uxsnk).
    #[error("no zone-owner key registered for zone {zone_id} (revocation push)")]
    UnknownZoneOwner { zone_id: String },

    /// Revocation push is missing the zone-owner signature authorizing
    /// the revocation payload. The peer signature alone is insufficient
    /// — a compromised peer could forge arbitrary revocations without
    /// this check (br-uxsnk).
    #[error("revocation push from {peer} missing owner signature for zone {zone_id}")]
    MissingOwnerSignature { peer: String, zone_id: String },

    /// Revocation push owner-signature verification failed against the
    /// registered zone-owner key (br-uxsnk).
    #[error("revocation push from {peer} has invalid owner signature for zone {zone_id}")]
    InvalidOwnerSignature { peer: String, zone_id: String },

    /// Revocation push advertises a frontier already dominated by local state.
    #[error(
        "stale revocation frontier from {peer} for zone {zone_id}: incoming seq {incoming_seq} is behind local seq {local_seq}"
    )]
    StaleRevocationFrontier {
        /// Peer that forwarded the stale push.
        peer: String,
        /// Zone the push targeted.
        zone_id: String,
        /// Incoming revocation sequence from the push.
        incoming_seq: u64,
        /// Local effective sequence for the same zone.
        local_seq: u64,
    },

    /// Trace capture not enabled.
    #[error("trace capture not enabled")]
    TraceNotEnabled,

    /// Trace export error.
    #[error("trace export error: {0}")]
    TraceExport(#[from] fcp_telemetry::trace_capture::TraceError),

    /// Failed to decode a gossip payload received from the transport layer.
    #[error("gossip payload decode error: {0}")]
    GossipDecode(String),

    /// Gossip payload exceeded the pre-deserialize raw byte budget.
    #[error("gossip payload too large: {len} bytes exceeds max {max}")]
    GossipPayloadTooLarge { len: usize, max: usize },

    /// Connector-state root observation failed.
    #[error("connector-state store error: {0}")]
    ConnectorStateStore(#[from] ConnectorStateStoreError),

    /// Canonical object serialization failed.
    #[error("canonical serialization error: {0}")]
    Serialization(#[from] fcp_cbor::SerializationError),
}

/// Enforcement errors for control-plane requests.
#[derive(Debug, Error)]
pub enum MeshNodeEnforcementError {
    /// Invoke request validation error.
    #[error("invoke validation error: {0}")]
    InvokeValidation(#[from] InvokeValidationError),

    /// Capability token verification failed.
    #[error("capability verification failed: {0}")]
    CapabilityVerification(#[from] FcpError),

    /// Holder proof required for holder-bound token.
    #[error("holder proof required for holder node {holder_node}")]
    HolderProofRequired { holder_node: String },

    /// Holder proof node mismatch.
    #[error("holder proof node mismatch: expected {expected}, got {actual}")]
    HolderProofNodeMismatch { expected: String, actual: String },

    /// Holder proof verification failed.
    #[error("holder proof verification failed")]
    HolderProofInvalid,

    /// Holder proof key missing.
    #[error("holder proof key missing for holder node {holder_node}")]
    HolderKeyMissing { holder_node: String },

    /// Capability token missing JTI claim.
    #[error("capability token missing jti claim")]
    MissingTokenJti,

    /// Capability token revoked.
    #[error("capability token revoked: {token_id}")]
    TokenRevoked { token_id: ObjectId },

    /// Receipt validation error.
    #[error("receipt validation failed: {0}")]
    ReceiptValidation(#[from] fcp_core::OperationValidationError),
}

/// Per-peer state used for planning.
#[derive(Debug, Clone)]
pub struct PeerState {
    /// Device profile.
    pub profile: DeviceProfile,
    /// Symbols present on peer.
    pub local_symbols: HashSet<ObjectId>,
    /// Leases held by peer.
    pub held_leases: Vec<HeldLease>,
    /// Zones this peer is authorized for (populated by the transport layer
    /// after attestation verification via `update_peer_zones`). An empty
    /// set means "not yet populated", so symbol requests fail closed
    /// until attestation-driven zone membership lands. Once populated,
    /// requests for zones outside the set are rejected with
    /// `SymbolRequestError::UnauthorizedZone`.
    pub zones: HashSet<ZoneId>,
    /// Mesh protocol generations the peer advertised during V3 -> V4 migration.
    pub protocol_capabilities: PeerProtocolCapabilities,
    /// Last observed timestamp (ms since epoch).
    pub last_seen_ms: u64,
}

/// MeshNode metrics (coarse-grained).
#[derive(Debug, Default, Clone)]
pub struct MeshNodeMetrics {
    /// Symbol request metrics.
    pub symbol_requests: SymbolRequestMetrics,
    /// Gossip announcements emitted.
    pub gossip_announcements: u64,
    /// Gossip summaries processed.
    pub gossip_updates: u64,
    /// Peer updates applied.
    pub peer_updates: u64,
    /// HierVV revocation-frontier size observations recorded.
    pub revocation_hiervv_size_samples: u64,
    /// Last serialized HierVV revocation-frontier size in bytes.
    pub revocation_hiervv_size_last_bytes: u64,
}

/// Verified revocation push ready to apply to a revocation registry fetch path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRevocationPush {
    /// Source peer that authenticated the push.
    pub from: NodeId,
    /// Zone the revocation applies to.
    pub zone_id: ZoneId,
    /// Revoked object IDs advertised by the peer.
    pub revoked_ids: Vec<ObjectId>,
    /// Peer's advertised revocation head sequence.
    pub new_rev_seq: u64,
    /// Push timestamp.
    pub timestamp: u64,
    /// Hierarchical-vector freshness decision used before accepting the push.
    pub freshness: RevocationFreshnessDecision,
}

/// Outbound gossip request produced while handling an inbound control-plane message.
#[derive(Debug, Clone)]
pub struct GossipFollowupRequest {
    /// Peer the transport should send this request to.
    pub peer: TailscaleNodeId,
    /// Bounded request body to send.
    pub request: GossipRequest,
}

/// Verified peer availability that should be fetched by the transport layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipFetchPlan {
    /// Peer that advertised the available objects/symbols.
    pub peer: TailscaleNodeId,
    /// Zone the advertised objects/symbols belong to.
    pub zone_id: ZoneId,
    /// Missing objects this node should fetch from `peer`.
    pub object_ids: Vec<ObjectId>,
    /// Missing symbols this node should fetch from `peer`.
    pub symbols: Vec<(ObjectId, u32)>,
}

/// Symbol bytes fetched from a peer, paired with the object-level symbol metadata
/// needed to admit them into the local symbol store.
#[derive(Debug, Clone)]
pub struct GossipFetchedSymbol {
    /// Metadata for the object this symbol helps reconstruct.
    pub object_meta: ObjectSymbolMeta,
    /// Fetched symbol bytes.
    pub symbol: StoredSymbol,
}

/// Object and symbol bytes materialized for a verified gossip request.
#[must_use]
#[derive(Debug, Clone, Default)]
pub struct GossipFetchPayload {
    /// Object payloads available to transfer to the requester.
    pub objects: Vec<StoredObject>,
    /// Symbol payloads available to transfer to the requester.
    pub symbols: Vec<GossipFetchedSymbol>,
}

impl GossipFetchPayload {
    /// Whether the responder has no bytes to transfer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty() && self.symbols.is_empty()
    }
}

/// Availability response plus the matching bytes for transport handoff.
#[must_use]
#[derive(Debug, Clone)]
pub struct GossipFetchReply {
    /// Bounded availability response to return to the requester.
    pub response: GossipResponse,
    /// Stored bytes that match the advertised availability.
    pub payload: GossipFetchPayload,
}

/// Result of applying fetched gossip bytes to the local stores.
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GossipFetchApplyOutcome {
    /// Object payloads accepted into the local object store and announced.
    pub objects_applied: Vec<ObjectId>,
    /// Accepted object payloads that look like connector-state roots.
    ///
    /// The transport byte-application layer cannot validate connector/zone
    /// ownership because it does not know the caller's `ObjectIdKey` or
    /// connector id. Host/mesh adapters should pass these candidates to
    /// `observe_connector_state_root` with the appropriate
    /// `FcpStoreConnectorStateStore`.
    pub connector_state_root_candidates: Vec<ObjectId>,
    /// Symbol payloads accepted into the local symbol store and announced.
    pub symbols_applied: Vec<(ObjectId, u32)>,
}

impl GossipFetchApplyOutcome {
    /// Whether the fetched payload changed no local availability state.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects_applied.is_empty()
            && self.connector_state_root_candidates.is_empty()
            && self.symbols_applied.is_empty()
    }
}

/// Result of applying fetched gossip bytes and observing connector-state roots.
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GossipFetchApplyObserveOutcome {
    /// Store-application result for fetched object and symbol bytes.
    pub apply: GossipFetchApplyOutcome,
    /// Connector-state changes validated from fetched root candidates.
    pub connector_state_changes: Vec<ConnectorStateChange>,
}

impl GossipFetchApplyObserveOutcome {
    /// Whether the fetched payload changed no local availability or state-root state.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.apply.is_empty() && self.connector_state_changes.is_empty()
    }
}

/// Structured result of dispatching an inbound gossip message.
#[must_use]
#[derive(Debug, Clone, Default)]
pub struct GossipDispatchOutcome {
    /// Verified revocation push ready for registry application.
    pub revocation_push: Option<VerifiedRevocationPush>,
    /// Immediate response the transport should return to the requester.
    pub response: Option<GossipResponse>,
    /// Immediate reconcile response the transport should return to the requester.
    pub reconcile_response: Option<ReconcileResponse>,
    /// Follow-up request the transport should send to the selected peer.
    pub followup_request: Option<GossipFollowupRequest>,
    /// Verified availability that the transport should fetch from a peer.
    pub fetch_plan: Option<GossipFetchPlan>,
}

impl GossipDispatchOutcome {
    fn with_revocation_push(revocation_push: VerifiedRevocationPush) -> Self {
        Self {
            revocation_push: Some(revocation_push),
            response: None,
            reconcile_response: None,
            followup_request: None,
            fetch_plan: None,
        }
    }

    fn with_response(response: GossipResponse) -> Self {
        Self {
            revocation_push: None,
            response: Some(response),
            reconcile_response: None,
            followup_request: None,
            fetch_plan: None,
        }
    }

    fn with_reconcile_response(reconcile_response: ReconcileResponse) -> Self {
        Self {
            revocation_push: None,
            response: None,
            reconcile_response: Some(reconcile_response),
            followup_request: None,
            fetch_plan: None,
        }
    }

    fn with_followup_request(followup_request: GossipFollowupRequest) -> Self {
        Self {
            revocation_push: None,
            response: None,
            reconcile_response: None,
            followup_request: Some(followup_request),
            fetch_plan: None,
        }
    }

    fn with_fetch_plan(fetch_plan: GossipFetchPlan) -> Self {
        Self {
            revocation_push: None,
            response: None,
            reconcile_response: None,
            followup_request: None,
            fetch_plan: Some(fetch_plan),
        }
    }
}

/// Dispatch result for transports that want verified request bytes inline.
#[must_use]
#[derive(Debug, Clone, Default)]
pub struct GossipDispatchFetchOutcome {
    /// Standard dispatch result retained for existing transport behavior.
    pub dispatch: GossipDispatchOutcome,
    /// Materialized bytes for an inbound gossip request, when applicable.
    pub fetch_reply: Option<GossipFetchReply>,
}

impl GossipDispatchFetchOutcome {
    fn from_dispatch(dispatch: GossipDispatchOutcome) -> Self {
        Self {
            dispatch,
            fetch_reply: None,
        }
    }

    fn with_fetch_reply(fetch_reply: GossipFetchReply) -> Self {
        Self {
            dispatch: GossipDispatchOutcome::with_response(fetch_reply.response.clone()),
            fetch_reply: Some(fetch_reply),
        }
    }
}

/// MeshNode orchestration entrypoint.
pub struct MeshNode {
    local_node: NodeId,
    local_node_ts: TailscaleNodeId,
    admission: AdmissionController,
    gossip: MeshGossip,
    symbol_requests: SymbolRequestHandler,
    symbol_metrics: SymbolRequestMetrics,
    planner: ExecutionPlanner,
    thompson_scheduler: ThompsonScheduler,
    degraded_encoder: DegradedModeEncoder,
    degraded_decoder: DegradedModeDecoder,
    object_store: Arc<dyn ObjectStore>,
    symbol_store: Arc<dyn SymbolStore>,
    quarantine_store: Arc<QuarantineStore>,
    sessions: HashMap<NodeId, MeshSession>,
    peer_signing_keys: HashMap<NodeId, Ed25519VerifyingKey>,
    /// Registered zone-owner public keys, keyed by the zone they own.
    ///
    /// Used to verify `owner_signature` on priority revocation pushes
    /// (br-flywheel_connectors-uxsnk). A peer is allowed to forward a
    /// revocation push for a zone only if (a) the peer signature
    /// validates and (b) the owner signature on the revocation payload
    /// validates against the registered owner key for the zone. If no
    /// owner key is registered for a zone, pushes targeting that zone
    /// are rejected fail-closed rather than accepted on peer signature
    /// alone.
    zone_owner_keys: HashMap<ZoneId, Ed25519VerifyingKey>,
    revocation_frontier: RevocationFreshnessFrontier,
    peers: HashMap<NodeId, PeerState>,
    local_profile: Option<DeviceProfile>,
    /// Zones this node is authorized for, sourced from enrollment /
    /// MeshIdentity. Fed into `build_planner_input` so zone-policy
    /// filtering at the planner actually applies. Empty = "not yet
    /// populated".
    local_zones: HashSet<ZoneId>,
    local_symbols: HashSet<ObjectId>,
    local_leases: Vec<HeldLease>,
    sent_symbols: HashMap<TransferKey, (u64, HashSet<u32>)>,
    metrics: MeshNodeMetrics,
    trace_capture: Option<TraceCapture>,
    trace_capture_zones: Option<HashSet<ZoneId>>,
}

impl MeshNode {
    /// Create a new MeshNode with explicit stores.
    #[must_use]
    pub fn new(
        config: MeshNodeConfig,
        object_store: Arc<dyn ObjectStore>,
        symbol_store: Arc<dyn SymbolStore>,
        quarantine_store: Arc<QuarantineStore>,
    ) -> Self {
        let local_node = NodeId::new(config.node_id.clone());
        let local_node_ts = TailscaleNodeId::new(config.node_id.clone());
        let trace_capture = if config.trace_capture.enabled {
            let capture_id = encode(TraceContext::generate().trace_id);
            Some(
                TraceCapture::new(capture_id, config.trace_capture.clone())
                    .with_node(config.node_id.clone()),
            )
        } else {
            None
        };

        Self {
            admission: AdmissionController::new(config.admission_policy),
            gossip: MeshGossip::new(local_node_ts.clone(), config.gossip_config),
            symbol_requests: SymbolRequestHandler::new(config.symbol_request_policy),
            symbol_metrics: SymbolRequestMetrics::default(),
            planner: ExecutionPlanner::new(),
            thompson_scheduler: ThompsonScheduler::new(),
            degraded_encoder: DegradedModeEncoder::new(
                config.raptorq_config.clone(),
                config.sender_instance_id,
            ),
            degraded_decoder: DegradedModeDecoder::new(config.raptorq_config),
            object_store,
            symbol_store,
            quarantine_store,
            sessions: HashMap::new(),
            peer_signing_keys: HashMap::new(),
            zone_owner_keys: HashMap::new(),
            revocation_frontier: RevocationFreshnessFrontier::new(),
            local_node,
            local_node_ts,
            peers: HashMap::new(),
            local_profile: None,
            local_zones: HashSet::new(),
            local_symbols: HashSet::new(),
            local_leases: Vec::new(),
            sent_symbols: HashMap::new(),
            metrics: MeshNodeMetrics::default(),
            trace_capture,
            trace_capture_zones: config.trace_capture_zones,
        }
    }

    /// Local node ID (planner/admission).
    #[must_use]
    pub const fn local_node_id(&self) -> &NodeId {
        &self.local_node
    }

    /// Local node ID (gossip/FCPS).
    #[must_use]
    pub const fn local_tailscale_id(&self) -> &TailscaleNodeId {
        &self.local_node_ts
    }

    fn trace_id(&self) -> Option<String> {
        self.trace_capture
            .as_ref()
            .map(|capture| capture.trace_id().to_string())
    }

    fn trace_zone_enabled(&self, zone_id: Option<&ZoneId>) -> bool {
        let Some(zone_id) = zone_id else {
            return true;
        };

        match &self.trace_capture_zones {
            None => true,
            Some(zones) => zones.contains(zone_id),
        }
    }

    fn record_trace_event(&mut self, event: TraceEvent) {
        if let Some(capture) = self.trace_capture.as_mut() {
            if let Err(err) = capture.record(event) {
                debug!(error = %err, "trace capture dropped event");
            }
        }
    }

    fn record_admission_outcome(
        &mut self,
        peer: &NodeId,
        decision: &str,
        reason_code: Option<&str>,
        authenticated: bool,
        zone_id: Option<&ZoneId>,
        now_ms: u64,
    ) {
        if !self.trace_zone_enabled(zone_id) {
            return;
        }

        let Some(trace_id) = self.trace_id() else {
            return;
        };

        self.record_trace_event(TraceEvent::Admission(AdmissionOutcome {
            timestamp: now_ms,
            trace_id,
            peer_node: peer.as_str().to_string(),
            request_type: "symbol_request".to_string(),
            decision: decision.to_string(),
            reason_code: reason_code.map(str::to_string),
            budget_remaining: None,
            authenticated,
        }));
    }

    fn record_lease_deltas(
        &mut self,
        node_id: &NodeId,
        previous: &[HeldLease],
        next: &[HeldLease],
        now_ms: u64,
    ) {
        let Some(trace_id) = self.trace_id() else {
            return;
        };

        let mut previous_map = HashMap::new();
        for lease in previous {
            previous_map.insert((lease.subject_id, lease.purpose), lease.clone());
        }

        let mut next_map = HashMap::new();
        for lease in next {
            next_map.insert((lease.subject_id, lease.purpose), lease.clone());
        }

        for (key, next_lease) in next_map {
            let (subject_id, purpose) = key;
            match previous_map.remove(&key) {
                None => {
                    self.record_trace_event(TraceEvent::Lease(LeaseEvent {
                        timestamp: now_ms,
                        trace_id: trace_id.clone(),
                        operation: "acquire".to_string(),
                        subject_id: subject_id.to_string(),
                        purpose: purpose.to_string(),
                        node_id: node_id.as_str().to_string(),
                        success: true,
                        conflict_holder: None,
                    }));
                }
                Some(previous_lease)
                    if previous_lease.expires_at != next_lease.expires_at
                        || previous_lease.fencing_token != next_lease.fencing_token =>
                {
                    self.record_trace_event(TraceEvent::Lease(LeaseEvent {
                        timestamp: now_ms,
                        trace_id: trace_id.clone(),
                        operation: "renew".to_string(),
                        subject_id: subject_id.to_string(),
                        purpose: purpose.to_string(),
                        node_id: node_id.as_str().to_string(),
                        success: true,
                        conflict_holder: None,
                    }));
                }
                _ => {}
            }
        }

        for (key, _) in previous_map {
            let (subject_id, purpose) = key;
            self.record_trace_event(TraceEvent::Lease(LeaseEvent {
                timestamp: now_ms,
                trace_id: trace_id.clone(),
                operation: "release".to_string(),
                subject_id: subject_id.to_string(),
                purpose: purpose.to_string(),
                node_id: node_id.as_str().to_string(),
                success: true,
                conflict_holder: None,
            }));
        }
    }

    fn admission_reason_code(err: &AdmissionError) -> &'static str {
        match err {
            AdmissionError::ByteBudgetExceeded { .. } => "byte_budget_exceeded",
            AdmissionError::SymbolBudgetExceeded { .. } => "symbol_budget_exceeded",
            AdmissionError::AuthFailureBudgetExceeded { .. } => "auth_failure_budget_exceeded",
            AdmissionError::DecodeCapacityExceeded { .. } => "decode_capacity_exceeded",
            AdmissionError::DecodeCpuBudgetExceeded { .. } => "decode_cpu_budget_exceeded",
            AdmissionError::AmplificationViolation { .. } => "amplification_violation",
            AdmissionError::AuthenticationRequired => "authentication_required",
            AdmissionError::ProofOfNeedRequired => "proof_of_need_required",
            AdmissionError::ObjectQuarantined { .. } => "object_quarantined",
            AdmissionError::NotReachable { .. } => "not_reachable",
            AdmissionError::QuarantineQuotaExceeded { .. } => "quarantine_quota_exceeded",
            AdmissionError::TrackingTableFull { .. } => "tracking_table_full",
        }
    }

    fn symbol_request_reason_code(err: &SymbolRequestError) -> &'static str {
        match err {
            SymbolRequestError::InvalidRequest { .. } => "invalid_request",
            SymbolRequestError::BoundsExceeded { .. } => "bounds_exceeded",
            SymbolRequestError::HintTooLarge { .. } => "hint_too_large",
            SymbolRequestError::AdmissionRejected(admission) => {
                Self::admission_reason_code(admission)
            }
            SymbolRequestError::ObjectNotFound { .. } => "object_not_found",
            SymbolRequestError::SignatureInvalid => "signature_invalid",
            SymbolRequestError::AlreadyComplete { .. } => "already_complete",
            SymbolRequestError::UnauthorizedZone { .. } => "unauthorized_zone",
        }
    }

    fn observed_lease_authorities(&self) -> Vec<ObservedLeaseAuthority> {
        let mut observed = Vec::new();

        if self.local_profile.is_some() {
            for lease in &self.local_leases {
                observed.push(ObservedLeaseAuthority::new(
                    self.local_node_ts.clone(),
                    lease.clone(),
                ));
            }
        }

        for state in self.peers.values() {
            let holder = TailscaleNodeId::new(state.profile.node_id.as_str());
            for lease in &state.held_leases {
                observed.push(ObservedLeaseAuthority::new(holder.clone(), lease.clone()));
            }
        }

        observed
    }

    fn eligible_authority_nodes(&self) -> Vec<TailscaleNodeId> {
        let mut nodes = BTreeSet::new();

        if let Some(profile) = &self.local_profile {
            nodes.insert(profile.node_id.as_str().to_string());
        }

        for state in self.peers.values() {
            nodes.insert(state.profile.node_id.as_str().to_string());
        }

        nodes.into_iter().map(TailscaleNodeId::new).collect()
    }

    fn preferred_singleton_holder(
        &self,
        subject_id: Option<&ObjectId>,
        now_ms: u64,
    ) -> Option<String> {
        let now_secs = now_ms / 1000;
        let mut active = self
            .observed_lease_authorities()
            .into_iter()
            .filter(|entry| {
                entry.lease.purpose == LeasePurpose::SingletonWriter
                    && entry.lease.is_active(now_secs)
                    && match subject_id {
                        Some(subject_id) => entry.lease.subject_id == *subject_id,
                        None => true,
                    }
            })
            .collect::<Vec<_>>();

        active.sort_by(|left, right| {
            right
                .lease
                .fencing_token
                .cmp(&left.lease.fencing_token)
                .then_with(|| right.lease.expires_at.cmp(&left.lease.expires_at))
                .then_with(|| left.holder.as_str().cmp(right.holder.as_str()))
        });

        active
            .first()
            .map(|entry| entry.holder.as_str().to_string())
    }

    /// Build an inspectable authority view for one subject/purpose pair.
    #[must_use]
    pub fn authority_view(
        &self,
        zone_id: &ZoneId,
        subject_id: &ObjectId,
        purpose: LeasePurpose,
        now_ms: u64,
    ) -> AuthorityView {
        AuthorityView::from_observed(
            zone_id,
            subject_id,
            purpose,
            &self.eligible_authority_nodes(),
            &self.observed_lease_authorities(),
            now_ms / 1000,
            now_ms,
        )
    }

    /// Update local device profile and symbol/lease state.
    pub fn update_local_state(
        &mut self,
        profile: DeviceProfile,
        local_symbols: HashSet<ObjectId>,
        held_leases: Vec<HeldLease>,
    ) {
        let now_ms = current_time_ms();
        let previous_leases = self.local_leases.clone();
        let local_node = self.local_node.clone();
        self.record_lease_deltas(&local_node, &previous_leases, &held_leases, now_ms);
        self.local_profile = Some(profile);
        self.local_symbols = local_symbols;
        self.local_leases = held_leases;
    }

    /// Update or insert peer state.
    pub fn update_peer_state(
        &mut self,
        node_id: NodeId,
        profile: DeviceProfile,
        local_symbols: HashSet<ObjectId>,
        held_leases: Vec<HeldLease>,
        now_ms: u64,
    ) {
        let previous_leases = self
            .peers
            .get(&node_id)
            .map(|state| state.held_leases.clone())
            .unwrap_or_default();
        self.record_lease_deltas(&node_id, &previous_leases, &held_leases, now_ms);
        let existing_zones = self
            .peers
            .get(&node_id)
            .map(|state| state.zones.clone())
            .unwrap_or_default();
        let existing_protocol_capabilities = self
            .peers
            .get(&node_id)
            .map(|state| state.protocol_capabilities.clone())
            .unwrap_or_default();
        let state = PeerState {
            profile,
            local_symbols,
            held_leases,
            zones: existing_zones,
            protocol_capabilities: existing_protocol_capabilities,
            last_seen_ms: now_ms,
        };
        self.peers.insert(node_id, state);
        self.metrics.peer_updates += 1;
    }

    /// Replace the set of zones a peer is authorized for.
    ///
    /// Should be called by the transport layer after verifying the peer's
    /// attestation. Once populated, subsequent symbol requests targeting a
    /// zone outside `zones` are rejected with
    /// `SymbolRequestError::UnauthorizedZone`.
    pub fn update_peer_zones(&mut self, node_id: &NodeId, zones: HashSet<ZoneId>) {
        if let Some(state) = self.peers.get_mut(node_id) {
            state.zones = zones;
            return;
        }

        self.peers.insert(
            node_id.clone(),
            PeerState {
                profile: DeviceProfile::builder(node_id.clone()).build(),
                local_symbols: HashSet::new(),
                held_leases: Vec::new(),
                zones,
                protocol_capabilities: PeerProtocolCapabilities::default(),
                last_seen_ms: current_time_ms(),
            },
        );
        self.metrics.peer_updates += 1;
    }

    /// Replace the advertised protocol capabilities for a peer.
    ///
    /// Unknown peers get a conservative placeholder state with no zones; zone
    /// authorization still fails closed until enrollment populates membership.
    pub fn update_peer_protocol_capabilities(
        &mut self,
        node_id: &NodeId,
        protocol_capabilities: PeerProtocolCapabilities,
        now_ms: u64,
    ) {
        if let Some(state) = self.peers.get_mut(node_id) {
            state.protocol_capabilities = protocol_capabilities;
            state.last_seen_ms = now_ms;
        } else {
            self.peers.insert(
                node_id.clone(),
                PeerState {
                    profile: DeviceProfile::builder(node_id.clone()).build(),
                    local_symbols: HashSet::new(),
                    held_leases: Vec::new(),
                    zones: HashSet::new(),
                    protocol_capabilities,
                    last_seen_ms: now_ms,
                },
            );
        }
        self.metrics.peer_updates = self.metrics.peer_updates.saturating_add(1);
    }

    /// Return a peer's currently advertised mesh protocol capabilities.
    #[must_use]
    pub fn peer_protocol_capabilities(
        &self,
        node_id: &NodeId,
    ) -> Option<&PeerProtocolCapabilities> {
        self.peers
            .get(node_id)
            .map(|state| &state.protocol_capabilities)
    }

    /// Enforce a receiver policy that requires the remote peer to support V4.
    ///
    /// # Errors
    ///
    /// Returns [`MeshNodeError::PeerCapabilityRejected`] when the peer is
    /// enrolled but has advertised only V3 capability, and
    /// [`MeshNodeError::UnknownPeer`] when the peer has not completed
    /// enrollment.
    pub fn require_peer_v4_capability(&self, node_id: &NodeId) -> Result<(), MeshNodeError> {
        let state = self
            .peers
            .get(node_id)
            .ok_or_else(|| MeshNodeError::UnknownPeer {
                peer: node_id.as_str().to_string(),
                message_kind: "peer capability policy",
            })?;
        if state.protocol_capabilities.supports_v4() {
            return Ok(());
        }
        Err(MeshNodeError::PeerCapabilityRejected {
            peer: node_id.as_str().to_string(),
            advertised: state.protocol_capabilities.clone(),
        })
    }

    /// Replace the set of zones the local node is authorized for.
    ///
    /// Must be called by the enrollment / MeshIdentity layer after the
    /// node joins a zone (or is re-enrolled). Empty is interpreted as
    /// "zone membership not yet wired" — the planner's zone-policy
    /// filter treats such a candidate conservatively (see
    /// `planner::zone_policy_rejects_nodes_with_unknown_zones`).
    pub fn update_local_zones(&mut self, zones: HashSet<ZoneId>) {
        self.local_zones = zones;
    }

    /// Read-only view of the local node's authorized zones.
    #[must_use]
    pub fn local_zones(&self) -> &HashSet<ZoneId> {
        &self.local_zones
    }

    /// Remove a peer from tracking (also cleans up session and admission state).
    pub fn remove_peer(&mut self, node_id: &NodeId) {
        // Clean up session/admission state before removing peer data,
        // to prevent stale authentication surviving peer removal.
        let now_ms = self.peers.get(node_id).map_or(0, |p| p.last_seen_ms);
        if self.sessions.contains_key(node_id) {
            self.remove_session(node_id, now_ms);
        } else {
            // br-llfi4: clear admission auth state without allocating
            // a tracking entry for an untracked peer. The previous
            // `set_authenticated(_, false, _)` call would
            // `get_or_create_usage` and silently insert a fresh
            // PeerUsage entry on the cleanup path, which can fill
            // `policy.max_tracked_peers` and start rejecting real
            // peers with `TrackingTableFull` after enough
            // ghost-peer removals.
            self.admission.clear_authenticated(node_id);
        }
        self.peers.remove(node_id);
        self.peer_signing_keys.remove(node_id);
    }

    /// Register a peer's signing key for signature verification.
    pub fn register_peer_signing_key(&mut self, peer_id: NodeId, key: Ed25519VerifyingKey) {
        self.peer_signing_keys.insert(peer_id, key);
    }

    /// Remove a peer's signing key.
    pub fn remove_peer_signing_key(&mut self, peer_id: &NodeId) {
        self.peer_signing_keys.remove(peer_id);
    }

    /// Register the zone-owner public key used to authorize priority
    /// revocation pushes for `zone_id` (br-uxsnk). Pushes targeting a
    /// zone with no registered owner key are rejected.
    pub fn register_zone_owner_key(&mut self, zone_id: ZoneId, key: Ed25519VerifyingKey) {
        self.zone_owner_keys.insert(zone_id, key);
    }

    /// Remove the zone-owner key for `zone_id`. After removal, all
    /// priority revocation pushes for that zone will be rejected with
    /// `MeshNodeError::UnknownZoneOwner` until a new key is registered.
    pub fn remove_zone_owner_key(&mut self, zone_id: &ZoneId) {
        self.zone_owner_keys.remove(zone_id);
    }

    /// Observe a registry owner's current revocation head for `zone_id`.
    ///
    /// This lets the revocation registry owner seed the HierVV freshness
    /// frontier from its durable `RevocationRegistry` before mesh pushes or
    /// reconciliation traffic are evaluated.
    pub fn observe_revocation_registry_head(
        &mut self,
        zone_id: &ZoneId,
        registry: &RevocationRegistry,
    ) -> RevocationFreshnessDecision {
        self.observe_revocation_frontier(zone_id, registry.head_seq)
    }

    /// Observe a local revocation frontier update for `zone_id`.
    ///
    /// This lets registry/reconciliation callers seed the mesh node with the
    /// current effective revocation frontier before handling priority pushes.
    pub fn observe_revocation_frontier(
        &mut self,
        zone_id: &ZoneId,
        rev_seq: u64,
    ) -> RevocationFreshnessDecision {
        self.revocation_frontier.observe(zone_id.as_str(), rev_seq)
    }

    /// Effective local revocation frontier counter for `zone_id`.
    #[must_use]
    pub fn revocation_frontier_counter(&self, zone_id: &ZoneId) -> u64 {
        self.revocation_frontier.counter_for(zone_id.as_str())
    }

    /// Serializable snapshot of the current local revocation freshness frontier.
    ///
    /// Callers that own durable registry state can persist this value with their
    /// registry checkpoint and later pass it to
    /// [`Self::reconcile_revocation_frontier`] after restart.
    #[must_use]
    pub fn revocation_frontier_snapshot(&self) -> RevocationFreshnessFrontier {
        self.revocation_frontier.clone()
    }

    /// Reconcile a persisted or remote revocation freshness frontier.
    ///
    /// The merge is rollback-safe: if local state already dominates `frontier`,
    /// the local frontier is left unchanged and `VersionVectorOrder::DominatedBy`
    /// is returned. Equal, dominating, and concurrent frontiers are merged.
    pub fn reconcile_revocation_frontier(
        &mut self,
        frontier: &RevocationFreshnessFrontier,
    ) -> VersionVectorOrder {
        let order = self.revocation_frontier.reconcile(frontier);
        debug!(
            target: "fcp.mesh.revocation.freshness",
            hier_vv_status = order.as_str(),
            decision = if matches!(order, VersionVectorOrder::DominatedBy) {
                "reject_stale"
            } else {
                "accept"
            },
            "reconciled revocation freshness frontier"
        );
        order
    }

    /// Serialized size of the current local revocation freshness frontier.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical serialization of the HierVV frontier fails.
    pub fn revocation_frontier_size_bytes(&self) -> Result<usize, String> {
        self.revocation_frontier.canonical_len()
    }

    /// Current peer count (excluding local).
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Register an authenticated mesh session for a peer.
    pub fn register_session(&mut self, session: MeshSession, now_ms: u64) {
        self.admission
            .set_authenticated(&session.peer_id, true, now_ms);
        let peer_id = session.peer_id.clone();
        let session_id = encode(session.session_id.as_bytes());
        let suite = session.suite.as_str().to_string();
        self.sessions.insert(peer_id.clone(), session);

        let Some(trace_id) = self.trace_id() else {
            return;
        };
        self.record_trace_event(TraceEvent::Session(SessionEvent {
            timestamp: now_ms,
            trace_id,
            session_id,
            kind: "established".to_string(),
            peer_node: peer_id.as_str().to_string(),
            suite: Some(suite),
            failure_reason: None,
        }));
    }

    /// Remove a mesh session for a peer (marks unauthenticated).
    pub fn remove_session(&mut self, peer_id: &NodeId, now_ms: u64) {
        if let Some(session) = self.sessions.remove(peer_id) {
            if let Some(trace_id) = self.trace_id() {
                self.record_trace_event(TraceEvent::Session(SessionEvent {
                    timestamp: now_ms,
                    trace_id,
                    session_id: encode(session.session_id.as_bytes()),
                    kind: "closed".to_string(),
                    peer_node: peer_id.as_str().to_string(),
                    suite: Some(session.suite.as_str().to_string()),
                    failure_reason: None,
                }));
            }
        }
        // br-llfi4: same no-allocation discipline as remove_peer —
        // closing a non-existent session must not allocate an
        // admission entry just to flip is_authenticated.
        self.admission.clear_authenticated(peer_id);
    }

    /// Check whether a peer is authenticated.
    #[must_use]
    pub fn is_peer_authenticated(&self, peer_id: &NodeId) -> bool {
        self.sessions.contains_key(peer_id) || self.admission.is_authenticated(peer_id)
    }

    /// Build a planner input from current local + peer state.
    fn build_planner_input(&self, now_ms: u64) -> PlannerInput {
        let mut nodes = Vec::new();

        if let Some(profile) = &self.local_profile {
            nodes.push(NodeInfo {
                profile: profile.clone(),
                local_symbols: self.local_symbols.clone(),
                held_leases: self.local_leases.clone(),
                zones: self.local_zones.iter().cloned().collect(),
            });
        }

        for state in self.peers.values() {
            nodes.push(NodeInfo {
                profile: state.profile.clone(),
                local_symbols: state.local_symbols.clone(),
                held_leases: state.held_leases.clone(),
                zones: state.zones.iter().cloned().collect(),
            });
        }

        let mut input = PlannerInput::new(nodes, now_ms);
        if let Some(holder) = self.preferred_singleton_holder(None, now_ms) {
            input = input.with_singleton_holder(holder);
        }
        input
    }

    /// Plan execution candidates for a connector.
    #[must_use]
    pub fn plan_execution(&self, context: &PlannerContext, now_ms: u64) -> Vec<CandidateNode> {
        let mut rng = rand::thread_rng();
        self.plan_execution_with_rng(context, now_ms, &mut rng)
    }

    fn plan_execution_with_rng<R: rand::Rng + ?Sized>(
        &self,
        context: &PlannerContext,
        now_ms: u64,
        rng: &mut R,
    ) -> Vec<CandidateNode> {
        let mut input = self.build_planner_input(now_ms);
        if context.singleton_writer {
            // Do not apply singleton enforcement from an unrelated lease when the
            // caller has not bound the request to a specific leased subject.
            input.singleton_lease_holder = context
                .authority_subject
                .as_ref()
                .and_then(|subject_id| self.preferred_singleton_holder(Some(subject_id), now_ms));
        }
        let candidates = self.planner.plan(&input, context);
        self.apply_thompson_ranking(candidates, context, rng)
    }

    fn apply_thompson_ranking<R: rand::Rng + ?Sized>(
        &self,
        mut candidates: Vec<CandidateNode>,
        context: &PlannerContext,
        rng: &mut R,
    ) -> Vec<CandidateNode> {
        let Some(operation_class) = context.resource_pool_class else {
            return candidates;
        };
        if candidates.len() < 2 {
            return candidates;
        }

        let node_ids: Vec<_> = candidates
            .iter()
            .map(|candidate| candidate.node_id.clone())
            .collect();
        if !self
            .thompson_scheduler
            .has_evidence_for(&node_ids, operation_class)
        {
            return candidates;
        }

        let Some(choice) = self
            .thompson_scheduler
            .choose_with_rng(&node_ids, operation_class, rng)
        else {
            return candidates;
        };
        let Some(selected_index) = candidates
            .iter()
            .position(|candidate| candidate.node_id.as_str() == choice.node_id.as_str())
        else {
            return candidates;
        };

        if selected_index != 0 {
            let selected = candidates.remove(selected_index);
            candidates.insert(0, selected);
        }
        Self::rewrite_execution_ranks(&mut candidates, &choice);
        candidates
    }

    fn rewrite_execution_ranks(candidates: &mut [CandidateNode], choice: &ThompsonChoice) {
        for (rank, candidate) in candidates.iter_mut().enumerate() {
            candidate.decision_reasons.retain(|reason| {
                !matches!(
                    reason,
                    DecisionReason::SelectedAsBest { .. }
                        | DecisionReason::EligibleNotSelected { .. }
                )
            });

            if rank == 0 {
                candidate
                    .decision_reasons
                    .push(DecisionReason::SelectedAsBest { rank: 1 });
                candidate.decision_reasons.push(DecisionReason::Custom(format!(
                    "thompson_sample operation_class={:?} sample={:.6} posterior_mean={:.6} posterior_variance={:.6}",
                    choice.operation_class,
                    choice.sample,
                    choice.posterior_mean,
                    choice.posterior_variance
                )));
            } else {
                candidate
                    .decision_reasons
                    .push(DecisionReason::EligibleNotSelected {
                        rank: rank + 1,
                        better_count: rank,
                    });
            }
        }
    }

    /// Record the outcome of a routed execution for adaptive scheduling.
    pub fn record_execution_outcome(
        &mut self,
        node_id: NodeId,
        operation_class: ResourcePoolClass,
        success: bool,
    ) {
        self.thompson_scheduler
            .record_outcome(node_id, operation_class, success);
    }

    /// Return the current adaptive routing posterior for a node and operation class.
    #[must_use]
    pub fn execution_posterior(
        &self,
        node_id: &NodeId,
        operation_class: ResourcePoolClass,
    ) -> BetaPosterior {
        self.thompson_scheduler.posterior(node_id, operation_class)
    }

    /// Enforce capability, holder proof, and revocation checks for an invoke request.
    ///
    /// Returns the verified capability claims on success.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeEnforcementError` if idempotency validation, capability
    /// verification, holder proof checks, or revocation checks fail.
    pub fn enforce_invoke_request<F>(
        &self,
        request: &InvokeRequest,
        required_capability: &fcp_core::CapabilityId,
        verifier: &CapabilityVerifier,
        revocations: &RevocationRegistry,
        resource_uris: &[String],
        mut holder_key_lookup: F,
    ) -> Result<CwtClaims, MeshNodeEnforcementError>
    where
        F: FnMut(&TailscaleNodeId) -> Option<Ed25519VerifyingKey>,
    {
        request.validate_idempotency_key()?;

        // br-rp0ej: invoke is the mesh's gateway for executing an
        // operation on this concrete node instance. Per the jkcka
        // typestate design, execution requires a BoundVerified token —
        // i.e. the verifier MUST carry this node's instance_id and the
        // token's INSTANCE_ID claim MUST match.
        //
        // Calling `verify_bound` here rejects (a) forged tokens as
        // before, and (b) the legitimate-but-dangerous case of a caller
        // that constructed the verifier with
        // `CapabilityVerifier::without_instance_binding()` — that mode
        // used to bypass instance binding entirely through the deprecated
        // `verify()` ambiguity. Now: `verify_bound` returns
        // FcpError::Internal when `self.instance_id.is_none()`, which
        // bubbles as MeshNodeEnforcementError::CapabilityVerification and
        // fails the invoke closed.
        //
        // Unbound gateway-vantage verification (without instance
        // binding) belongs at the gateway → connector handoff (via
        // `verify_unbound` + `promote_with_instance`), NOT at the
        // terminal invoke boundary.
        let verified_token = verifier.verify_bound(
            request.capability_token.clone(),
            required_capability,
            &request.operation,
            resource_uris,
        )?;
        let claims = verified_token.claims();

        if let Some(holder_node) = claims.get_holder_node() {
            let proof = request.holder_proof.as_ref().ok_or_else(|| {
                MeshNodeEnforcementError::HolderProofRequired {
                    holder_node: holder_node.to_string(),
                }
            })?;

            if proof.holder_node.as_str() != holder_node {
                return Err(MeshNodeEnforcementError::HolderProofNodeMismatch {
                    expected: holder_node.to_string(),
                    actual: proof.holder_node.as_str().to_string(),
                });
            }

            let token_jti = claims
                .get_jti()
                .ok_or(MeshNodeEnforcementError::MissingTokenJti)?;
            let signable =
                fcp_core::HolderProof::signable_bytes(&request.id, &request.operation, token_jti);

            let key = holder_key_lookup(&proof.holder_node).ok_or_else(|| {
                MeshNodeEnforcementError::HolderKeyMissing {
                    holder_node: proof.holder_node.as_str().to_string(),
                }
            })?;

            let signature = Ed25519Signature::from_bytes(&proof.signature);
            if key.verify(&signable, &signature).is_err() {
                return Err(MeshNodeEnforcementError::HolderProofInvalid);
            }
        }

        let token_jti = claims
            .get_jti()
            .ok_or(MeshNodeEnforcementError::MissingTokenJti)?;
        let token_id = ObjectId::from_unscoped_bytes(token_jti);
        if revocations.is_revoked(&token_id) {
            return Err(MeshNodeEnforcementError::TokenRevoked { token_id });
        }

        Ok(claims.clone())
    }

    /// Validate that a receipt correctly references its intent.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeEnforcementError::ReceiptValidation` if binding fails.
    pub fn validate_receipt_binding(
        &self,
        receipt_id: ObjectId,
        receipt: &OperationReceipt,
        intent_id: ObjectId,
        intent: &OperationIntent,
    ) -> Result<(), MeshNodeEnforcementError> {
        fcp_core::validate_receipt_intent_binding(receipt_id, receipt, intent_id, intent)?;
        Ok(())
    }

    /// Announce an admitted object for gossip.
    pub fn announce_object(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        mut admission: ObjectAdmissionClass,
        now_ms: u64,
    ) -> bool {
        if self.quarantine_store.contains(object_id) {
            admission = ObjectAdmissionClass::Quarantined;
        }

        let added = self
            .gossip
            .announce_object(zone_id, object_id, admission, now_ms / 1000);
        if added {
            self.metrics.gossip_announcements += 1;
            if self.trace_zone_enabled(Some(zone_id)) {
                if let Some(trace_id) = self.trace_id() {
                    self.record_trace_event(TraceEvent::Gossip(GossipEvent {
                        timestamp: now_ms,
                        trace_id,
                        gossip_type: "announce_object".to_string(),
                        object_count: 1,
                        peer_node: None,
                        success: true,
                    }));
                }
            }
        }
        added
    }

    /// Observe a replicated connector-state root and announce it through gossip.
    ///
    /// `fcp-store` owns root validation and cache invalidation; `fcp-mesh`
    /// owns object availability gossip. This bridge keeps that dependency
    /// direction acyclic while making a validated root visible to peers after
    /// the object has arrived locally.
    ///
    /// # Errors
    /// Returns an error if the state store rejects the root object as missing,
    /// malformed, foreign to the connector+zone store, or referencing a missing
    /// head object.
    pub async fn observe_connector_state_root(
        &mut self,
        state_store: &FcpStoreConnectorStateStore,
        root_object_id: ObjectId,
        now_ms: u64,
    ) -> Result<ConnectorStateChange, ConnectorStateStoreError> {
        let change = state_store.observe_replicated_root(root_object_id).await?;
        self.announce_object(
            &change.zone_id,
            &root_object_id,
            ObjectAdmissionClass::Admitted,
            now_ms,
        );
        Ok(change)
    }

    /// Store a durable core lease object locally and announce it for gossip.
    ///
    /// The lease coordinator owns admission and fencing-token selection. This
    /// bridge validates the already-issued lease with the mesh default quorum
    /// before turning it into a content-addressed mesh object, so peers only
    /// fetch quorum-backed authority objects through the normal gossip path.
    ///
    /// # Errors
    /// Returns an error if canonical lease encoding or local object storage
    /// fails.
    pub async fn publish_signed_lease_object(
        &mut self,
        lease: &CoreLease,
        object_id_key: &ObjectIdKey,
        now_ms: u64,
    ) -> Result<ObjectId, MeshNodeError> {
        validate_core_lease(
            lease,
            &lease.subject_object_id,
            lease.zone_id(),
            lease.purpose,
            lease.lease_seq,
            now_ms / 1000,
            DEFAULT_LEASE_PUBLICATION_REQUIRED_QUORUM_SIGNATURES,
        )?;
        self.verify_lease_quorum_signatures(lease)?;

        let body = CanonicalSerializer::serialize(lease, &lease.header.schema)?;
        let object_id = StoredObject::derive_id(&lease.header, &body, object_id_key)?;
        let stored = StoredObject {
            object_id,
            header: lease.header.clone(),
            body,
            storage: StorageMeta {
                retention: EvictionPolicy::Lease {
                    expires_at: lease.exp,
                },
            },
        };

        match self.object_store.put(stored).await {
            Ok(()) | Err(fcp_store::ObjectStoreError::AlreadyExists(_)) => {}
            Err(err) => return Err(MeshNodeError::ObjectStore(err)),
        }
        self.announce_object(
            &lease.header.zone_id,
            &object_id,
            ObjectAdmissionClass::Admitted,
            now_ms,
        );
        Ok(object_id)
    }

    /// Announce a symbol for gossip (admitted objects only).
    pub fn announce_symbol(
        &mut self,
        zone_id: &ZoneId,
        object_id: &ObjectId,
        esi: u32,
        mut admission: ObjectAdmissionClass,
        now_ms: u64,
    ) -> bool {
        if self.quarantine_store.contains(object_id) {
            admission = ObjectAdmissionClass::Quarantined;
        }

        let added = self
            .gossip
            .announce_symbol(zone_id, object_id, esi, admission, now_ms / 1000);
        if added {
            self.metrics.gossip_announcements += 1;
            if self.trace_zone_enabled(Some(zone_id)) {
                if let Some(trace_id) = self.trace_id() {
                    self.record_trace_event(TraceEvent::Gossip(GossipEvent {
                        timestamp: now_ms,
                        trace_id,
                        gossip_type: "announce_symbol".to_string(),
                        object_count: 1,
                        peer_node: None,
                        success: true,
                    }));
                }
            }
        }
        added
    }

    /// Handle a symbol request using admission control and targeted repair.
    ///
    /// The `_is_authenticated` parameter is retained for ABI continuity
    /// but is **ignored**. Earlier revisions OR'd the caller's bool
    /// with `self.is_peer_authenticated(peer)` inside
    /// `validate_symbol_request`, which meant a caller passing `true`
    /// could elevate any peer past the unauthenticated tier without
    /// holding a real session — and the elevated state then stuck via
    /// `admission.set_authenticated(peer, true, ..)`. Authentication is
    /// a property of the cryptographic session only; callers that need
    /// the authenticated tier in tests should pre-mark the peer via
    /// <code>[MeshNode::admission_mut].set_authenticated(peer, true, now_ms)</code>
    /// or establish a real `MeshSession` via [`MeshNode::register_session`].
    /// Follow-up work (bead `flywheel_connectors-q92i7`) can delete the
    /// parameter once every call site has migrated.
    ///
    /// # Errors
    /// Returns `SymbolRequestError` on validation or store failures.
    pub async fn handle_symbol_request(
        &mut self,
        request: SymbolRequest,
        peer: &NodeId,
        _is_authenticated: bool,
        now_ms: u64,
    ) -> Result<SymbolResponse, SymbolRequestError> {
        let (validated, meta) = self.validate_symbol_request(&request, peer, now_ms).await?;

        let response = match self
            .build_symbol_response(&request, peer, &validated, &meta, now_ms)
            .await
        {
            Ok(response) => response,
            Err(err) => {
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::symbol_request_reason_code(&err)),
                    validated.is_authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(err);
            }
        };

        self.record_admission_outcome(
            peer,
            "admit",
            None,
            validated.is_authenticated,
            Some(&request.zone_id),
            now_ms,
        );
        Ok(response)
    }

    fn check_symbol_request_gate(
        &mut self,
        request: &SymbolRequest,
        peer: &NodeId,
        authenticated: bool,
        now_ms: u64,
    ) -> Result<(), SymbolRequestError> {
        if self.symbol_requests.should_stop(peer, &request.object_id) {
            self.record_admission_outcome(
                peer,
                "reject",
                Some(Self::symbol_request_reason_code(
                    &SymbolRequestError::AlreadyComplete {
                        object_id: request.object_id.to_string(),
                    },
                )),
                authenticated,
                Some(&request.zone_id),
                now_ms,
            );
            return Err(SymbolRequestError::AlreadyComplete {
                object_id: request.object_id.to_string(),
            });
        }

        if self.quarantine_store.contains(&request.object_id) {
            self.record_admission_outcome(
                peer,
                "reject",
                Some(Self::admission_reason_code(
                    &AdmissionError::ObjectQuarantined {
                        object_id: request.object_id.to_string(),
                    },
                )),
                authenticated,
                Some(&request.zone_id),
                now_ms,
            );
            return Err(SymbolRequestError::AdmissionRejected(
                AdmissionError::ObjectQuarantined {
                    object_id: request.object_id.to_string(),
                },
            ));
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)] // Validation is intentionally linear so each fail-closed gate stays visible.
    async fn validate_symbol_request(
        &mut self,
        request: &SymbolRequest,
        peer: &NodeId,
        now_ms: u64,
    ) -> Result<(ValidatedRequest, fcp_store::ObjectSymbolMeta), SymbolRequestError> {
        // Server-authoritative authentication only. See
        // `MeshNode::handle_symbol_request` docs for the q92i7 rationale
        // — the pre-fix `authenticated = caller_bool || local_state`
        // shape let any caller elevate an unsessioned peer past the
        // unauthenticated tier, and the resulting
        // `admission.set_authenticated(.., true, ..)` call made the
        // elevation stick for every subsequent request.
        let mut authenticated = self.is_peer_authenticated(peer);

        // Enforce the same fail-closed zone gate used by summary and
        // revocation verification. A peer with missing or empty
        // attested-zone state is not authorized to request symbols
        // from any zone until the transport calls `update_peer_zones`.
        let state = self
            .peers
            .get(peer)
            .ok_or_else(|| SymbolRequestError::UnauthorizedZone {
                peer: peer.as_str().to_string(),
                zone_id: request.zone_id.to_string(),
            })?;
        if !state.zones.contains(&request.zone_id) {
            return Err(SymbolRequestError::UnauthorizedZone {
                peer: peer.as_str().to_string(),
                zone_id: request.zone_id.to_string(),
            });
        }

        self.check_symbol_request_gate(request, peer, authenticated, now_ms)?;

        // Fetch metadata first to get accurate symbol size for admission control
        let meta = match self.load_symbol_meta(request).await {
            Ok(meta) => meta,
            Err(err) => {
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::symbol_request_reason_code(&err)),
                    authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(err);
            }
        };

        if !authenticated {
            authenticated = match self.verify_symbol_request_signature(peer, request) {
                Ok(is_authenticated) => is_authenticated,
                Err(err) => {
                    self.record_admission_outcome(
                        peer,
                        "reject",
                        Some(Self::symbol_request_reason_code(&err)),
                        authenticated,
                        Some(&request.zone_id),
                        now_ms,
                    );
                    return Err(err);
                }
            };
        }
        self.admission
            .set_authenticated(peer, authenticated, now_ms);

        let validated = match self.symbol_requests.validate_request(
            request,
            authenticated,
            &mut self.admission,
            peer,
            now_ms,
            meta.oti.symbol_size,
        ) {
            Ok(validated) => {
                self.symbol_metrics.record_validated();
                validated
            }
            Err(SymbolRequestError::BoundsExceeded {
                requested,
                max_allowed,
            }) => {
                self.symbol_metrics.record_bounds_rejection();
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::symbol_request_reason_code(
                        &SymbolRequestError::BoundsExceeded {
                            requested,
                            max_allowed,
                        },
                    )),
                    authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(SymbolRequestError::BoundsExceeded {
                    requested,
                    max_allowed,
                });
            }
            Err(SymbolRequestError::AdmissionRejected(err)) => {
                self.symbol_metrics.record_admission_rejection();
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::admission_reason_code(&err)),
                    authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(SymbolRequestError::AdmissionRejected(err));
            }
            Err(err) => {
                self.record_admission_outcome(
                    peer,
                    "reject",
                    Some(Self::symbol_request_reason_code(&err)),
                    authenticated,
                    Some(&request.zone_id),
                    now_ms,
                );
                return Err(err);
            }
        };

        Ok((validated, meta))
    }

    async fn build_symbol_response(
        &mut self,
        request: &SymbolRequest,
        peer: &NodeId,
        validated: &ValidatedRequest,
        meta: &fcp_store::ObjectSymbolMeta,
        now_ms: u64,
    ) -> Result<SymbolResponse, SymbolRequestError> {
        let symbols = self.symbol_store.get_all_symbols(&request.object_id).await;
        let mut available = HashSet::new();
        for symbol in symbols {
            available.insert(symbol.meta.esi);
        }

        if available.is_empty() {
            return Err(SymbolRequestError::ObjectNotFound {
                object_id: request.object_id.to_string(),
            });
        }

        let mut engine = TargetedRepairEngine::new();
        engine.register_available(request.object_id, available.iter().copied());

        let transfer_key = TransferKey::new(peer, &request.object_id);
        let sent_entry = self
            .sent_symbols
            .entry(transfer_key)
            .or_insert_with(|| (now_ms, HashSet::new()));

        sent_entry.0 = now_ms; // Update timestamp
        let already_sent = &mut sent_entry.1;
        let already_sent_count = already_sent.len();

        let builder = SymbolResponseBuilder::new(
            request.object_id,
            meta.zone_id.clone(),
            request.zone_key_id,
            validated.max_response_symbols,
        );

        let response = builder
            .add_from_repair_engine(&engine, validated, already_sent)
            .build(
                u32::try_from(available.len()).unwrap_or(u32::MAX),
                already_sent_count,
            );

        debug!(
            object_id = %response.object_id,
            symbols = response.symbol_esis.len(),
            was_bounded = response.was_bounded,
            "symbol request response prepared"
        );

        already_sent.extend(response.symbol_esis.iter().copied());
        self.symbol_requests.track_transfer(
            peer,
            request,
            response.symbol_esis.iter().copied(),
            now_ms,
        );
        self.symbol_metrics
            .record_symbols_sent(response.symbol_count(), request.missing_hint.is_some());

        Ok(response)
    }

    fn verify_symbol_request_signature(
        &self,
        peer: &NodeId,
        request: &SymbolRequest,
    ) -> Result<bool, SymbolRequestError> {
        let Some(key) = self.peer_signing_keys.get(peer) else {
            return Ok(false);
        };

        request
            .verify(key)
            .map(|()| true)
            .map_err(|_| SymbolRequestError::SignatureInvalid)
    }

    fn peer_signing_key(&self, peer: &NodeId) -> Result<&Ed25519VerifyingKey, MeshNodeError> {
        self.peer_signing_keys
            .get(peer)
            .ok_or_else(|| MeshNodeError::PeerSigningKeyMissing {
                peer: peer.as_str().to_string(),
            })
    }

    fn verify_lease_quorum_signatures(&self, lease: &CoreLease) -> Result<(), MeshNodeError> {
        let signing_bytes = lease.quorum_signing_bytes()?;
        for signature in lease.quorum_signatures.iter() {
            let peer = NodeId::new(signature.node_id.as_str());
            let key = self.peer_signing_key(&peer)?;
            let signature_bytes = Ed25519Signature::from_bytes(&signature.signature);
            key.verify(&signing_bytes, &signature_bytes).map_err(|_| {
                MeshNodeError::PeerSignatureInvalid {
                    peer: signature.node_id.as_str().to_string(),
                    message_kind: "lease quorum",
                }
            })?;
        }
        Ok(())
    }

    fn verify_summary_signature(&self, summary: &GossipSummary) -> Result<NodeId, MeshNodeError> {
        let signature =
            summary
                .signature
                .as_ref()
                .ok_or_else(|| MeshNodeError::PeerSignatureInvalid {
                    peer: summary.from.as_str().to_string(),
                    message_kind: "gossip summary",
                })?;
        if signature.node_id.as_str() != summary.from.as_str() {
            return Err(MeshNodeError::SignatureNodeMismatch {
                message_kind: "gossip summary",
                expected: summary.from.as_str().to_string(),
                actual: signature.node_id.as_str().to_string(),
            });
        }

        let peer = NodeId::new(summary.from.as_str());
        let key = self.peer_signing_keys.get(&peer).ok_or_else(|| {
            MeshNodeError::PeerSigningKeyMissing {
                peer: summary.from.as_str().to_string(),
            }
        })?;
        summary
            .verify_signature(key)
            .map_err(|_| MeshNodeError::PeerSignatureInvalid {
                peer: summary.from.as_str().to_string(),
                message_kind: "gossip summary",
            })?;

        // Enforce zone authorization (C2). Pre-opoux this block was
        // wrapped in `if let Some(state) = self.peers.get(&peer)` with
        // an inner `if !state.zones.is_empty() && ...`, so BOTH an
        // unknown peer AND a known peer with empty zone state would
        // silently bypass the gate and let a signed summary claim any
        // zone. Both fallthroughs are now hard refusals: an
        // authenticated peer must be in the enrollment map AND must
        // have the claimed zone in their attested set before the
        // summary is accepted. The signing-key registration in
        // `register_peer_signing_key` is independent of
        // `update_peer_state` so an attacker holding a valid key can
        // otherwise reach this path before enrollment lands.
        let state = self
            .peers
            .get(&peer)
            .ok_or_else(|| MeshNodeError::UnknownPeer {
                peer: peer.as_str().to_string(),
                message_kind: "gossip summary",
            })?;
        if !state.zones.contains(&summary.zone_id) {
            return Err(MeshNodeError::UnauthorizedZone {
                peer: peer.as_str().to_string(),
                zone_id: summary.zone_id.to_string(),
            });
        }

        Ok(peer)
    }

    fn verify_peer_capability_advertisement(
        &self,
        advertisement: &PeerCapabilityAdvertisement,
    ) -> Result<NodeId, MeshNodeError> {
        let signature = advertisement.signature.as_ref().ok_or_else(|| {
            MeshNodeError::PeerSignatureInvalid {
                peer: advertisement.from.as_str().to_string(),
                message_kind: "peer capability advertisement",
            }
        })?;
        if signature.node_id.as_str() != advertisement.from.as_str() {
            return Err(MeshNodeError::SignatureNodeMismatch {
                message_kind: "peer capability advertisement",
                expected: advertisement.from.as_str().to_string(),
                actual: signature.node_id.as_str().to_string(),
            });
        }

        let peer = NodeId::new(advertisement.from.as_str());
        let key = self.peer_signing_keys.get(&peer).ok_or_else(|| {
            MeshNodeError::PeerSigningKeyMissing {
                peer: advertisement.from.as_str().to_string(),
            }
        })?;
        advertisement
            .verify_signature(key)
            .map_err(|_| MeshNodeError::PeerSignatureInvalid {
                peer: advertisement.from.as_str().to_string(),
                message_kind: "peer capability advertisement",
            })?;

        if !self.peers.contains_key(&peer) {
            return Err(MeshNodeError::UnknownPeer {
                peer: peer.as_str().to_string(),
                message_kind: "peer capability advertisement",
            });
        }

        Ok(peer)
    }

    fn verify_revocation_push_signature(
        &self,
        push: &RevocationPushMessage,
    ) -> Result<NodeId, MeshNodeError> {
        let signature =
            push.signature
                .as_ref()
                .ok_or_else(|| MeshNodeError::PeerSignatureInvalid {
                    peer: push.from.as_str().to_string(),
                    message_kind: "revocation push",
                })?;
        if signature.node_id.as_str() != push.from.as_str() {
            return Err(MeshNodeError::SignatureNodeMismatch {
                message_kind: "revocation push",
                expected: push.from.as_str().to_string(),
                actual: signature.node_id.as_str().to_string(),
            });
        }

        let peer = NodeId::new(push.from.as_str());
        let key = self.peer_signing_keys.get(&peer).ok_or_else(|| {
            MeshNodeError::PeerSigningKeyMissing {
                peer: push.from.as_str().to_string(),
            }
        })?;
        push.verify_signature(key)
            .map_err(|_| MeshNodeError::PeerSignatureInvalid {
                peer: push.from.as_str().to_string(),
                message_kind: "revocation push",
            })?;

        // Enforce zone authorization (C2). See verify_summary_signature
        // above for the opoux rationale — same hard-refusal shape
        // applied to the revocation-push path. Pre-opoux, a peer who
        // held a signing key but whose enrollment hadn't completed
        // could push a revocation into any zone; the bypass is closed
        // here symmetrically.
        let state = self
            .peers
            .get(&peer)
            .ok_or_else(|| MeshNodeError::UnknownPeer {
                peer: peer.as_str().to_string(),
                message_kind: "revocation push",
            })?;
        if !state.zones.contains(&push.zone_id) {
            return Err(MeshNodeError::UnauthorizedZone {
                peer: peer.as_str().to_string(),
                zone_id: push.zone_id.to_string(),
            });
        }

        Ok(peer)
    }

    fn verify_gossip_request(
        &self,
        request: &GossipRequest,
        now_secs: u64,
    ) -> Result<NodeId, MeshNodeError> {
        let peer = NodeId::new(request.from.as_str());

        // `MeshGossip::create_request` currently emits unsigned
        // request envelopes, so production dispatch has to rely on the
        // transport-authenticated peer enrollment map here rather than
        // a per-message signature. Keep this path fail-closed: the
        // requester must already exist in peer state, be authorized
        // for the target zone, and stay within the normal gossip
        // freshness window.
        let state = self
            .peers
            .get(&peer)
            .ok_or_else(|| MeshNodeError::UnknownPeer {
                peer: peer.as_str().to_string(),
                message_kind: "gossip request",
            })?;
        if !state.zones.contains(&request.zone_id) {
            return Err(MeshNodeError::UnauthorizedZone {
                peer: peer.as_str().to_string(),
                zone_id: request.zone_id.to_string(),
            });
        }
        if crate::gossip::is_outside_freshness_window(
            request.timestamp,
            now_secs,
            self.gossip.summary_ttl_secs(),
            self.gossip.max_future_skew_secs(),
        ) {
            return Err(MeshNodeError::StaleGossipMessage {
                peer: peer.as_str().to_string(),
                message_kind: "gossip request",
            });
        }

        Ok(peer)
    }

    fn verify_gossip_response(
        &self,
        response: &GossipResponse,
        now_secs: u64,
    ) -> Result<NodeId, MeshNodeError> {
        if response.to != self.local_node_ts {
            return Err(MeshNodeError::RecipientMismatch {
                message_kind: "gossip response",
                expected: self.local_node_ts.as_str().to_string(),
                actual: response.to.as_str().to_string(),
            });
        }

        let peer = NodeId::new(response.from.as_str());
        let state = self
            .peers
            .get(&peer)
            .ok_or_else(|| MeshNodeError::UnknownPeer {
                peer: peer.as_str().to_string(),
                message_kind: "gossip response",
            })?;
        if !state.zones.contains(&response.zone_id) {
            return Err(MeshNodeError::UnauthorizedZone {
                peer: peer.as_str().to_string(),
                zone_id: response.zone_id.to_string(),
            });
        }

        let max_objects = self.gossip.max_objects_per_request();
        let max_symbols = self.gossip.max_symbols_per_request();
        if response.have_objects.len() > max_objects || response.have_symbols.len() > max_symbols {
            return Err(MeshNodeError::GossipDecode(format!(
                "gossip response from {} for zone {} exceeded availability budget: have_objects={}, have_symbols={}, max_objects={}, max_symbols={}",
                response.from.as_str(),
                response.zone_id,
                response.have_objects.len(),
                response.have_symbols.len(),
                max_objects,
                max_symbols
            )));
        }

        if crate::gossip::is_outside_freshness_window(
            response.timestamp,
            now_secs,
            self.gossip.summary_ttl_secs(),
            self.gossip.max_future_skew_secs(),
        ) {
            return Err(MeshNodeError::StaleGossipMessage {
                peer: peer.as_str().to_string(),
                message_kind: "gossip response",
            });
        }

        Ok(peer)
    }

    fn verify_reconcile_request(
        &self,
        request: &ReconcileRequest,
        now_secs: u64,
    ) -> Result<NodeId, MeshNodeError> {
        let peer = NodeId::new(request.from.as_str());

        let state = self
            .peers
            .get(&peer)
            .ok_or_else(|| MeshNodeError::UnknownPeer {
                peer: peer.as_str().to_string(),
                message_kind: "reconcile request",
            })?;
        if !state.zones.contains(&request.zone_id) {
            return Err(MeshNodeError::UnauthorizedZone {
                peer: peer.as_str().to_string(),
                zone_id: request.zone_id.to_string(),
            });
        }
        if crate::gossip::is_outside_freshness_window(
            request.timestamp,
            now_secs,
            self.gossip.summary_ttl_secs(),
            self.gossip.max_future_skew_secs(),
        ) {
            return Err(MeshNodeError::StaleGossipMessage {
                peer: peer.as_str().to_string(),
                message_kind: "reconcile request",
            });
        }

        Ok(peer)
    }

    fn verify_reconcile_response(
        &self,
        response: &ReconcileResponse,
        now_secs: u64,
    ) -> Result<NodeId, MeshNodeError> {
        let peer = NodeId::new(response.from.as_str());

        let state = self
            .peers
            .get(&peer)
            .ok_or_else(|| MeshNodeError::UnknownPeer {
                peer: peer.as_str().to_string(),
                message_kind: "reconcile response",
            })?;
        if !state.zones.contains(&response.zone_id) {
            return Err(MeshNodeError::UnauthorizedZone {
                peer: peer.as_str().to_string(),
                zone_id: response.zone_id.to_string(),
            });
        }
        if response.peer_missing_objects.len() > MAX_OBJECT_IDS_PER_REQUEST
            || response.we_missing_objects.len() > MAX_OBJECT_IDS_PER_REQUEST
        {
            return Err(MeshNodeError::GossipDecode(format!(
                "reconcile response from {} for zone {} exceeded object budget: peer_missing={}, we_missing={}, max={}",
                response.from.as_str(),
                response.zone_id,
                response.peer_missing_objects.len(),
                response.we_missing_objects.len(),
                MAX_OBJECT_IDS_PER_REQUEST
            )));
        }
        if crate::gossip::is_outside_freshness_window(
            response.timestamp,
            now_secs,
            self.gossip.summary_ttl_secs(),
            self.gossip.max_future_skew_secs(),
        ) {
            return Err(MeshNodeError::StaleGossipMessage {
                peer: peer.as_str().to_string(),
                message_kind: "reconcile response",
            });
        }

        Ok(peer)
    }

    async fn load_symbol_meta(
        &self,
        request: &SymbolRequest,
    ) -> Result<fcp_store::ObjectSymbolMeta, SymbolRequestError> {
        let meta = self
            .symbol_store
            .get_object_meta(&request.object_id)
            .await
            .map_err(|err| match err {
                fcp_store::SymbolStoreError::ObjectNotFound(_) => {
                    SymbolRequestError::ObjectNotFound {
                        object_id: request.object_id.to_string(),
                    }
                }
                other => SymbolRequestError::InvalidRequest {
                    reason: format!("symbol store error: {other}"),
                },
            })?;

        if meta.zone_id != request.zone_id {
            return Err(SymbolRequestError::InvalidRequest {
                reason: format!(
                    "request zone_id {} does not match stored object zone_id {}",
                    request.zone_id, meta.zone_id
                ),
            });
        }

        Ok(meta)
    }

    /// Apply a verified gossip summary from a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the summary is unsigned, bound to the wrong node
    /// ID, or fails signature verification against the registered peer key.
    pub fn handle_summary(
        &mut self,
        summary: GossipSummary,
        now_secs: u64,
    ) -> Result<(), MeshNodeError> {
        self.verify_summary_signature(&summary)?;
        if self.gossip.handle_summary(summary, now_secs) {
            self.metrics.gossip_updates = self.metrics.gossip_updates.saturating_add(1);
        }
        Ok(())
    }

    /// Verify and apply a peer V3/V4 capability advertisement.
    ///
    /// # Errors
    ///
    /// Returns an error if the advertisement is unsigned, stale, signed for a
    /// different node, fails verification, or arrives before peer enrollment.
    pub fn handle_peer_capability_advertisement(
        &mut self,
        advertisement: PeerCapabilityAdvertisement,
        now_secs: u64,
    ) -> Result<(), MeshNodeError> {
        let peer = self.verify_peer_capability_advertisement(&advertisement)?;
        if advertisement.is_stale(
            now_secs,
            self.gossip.summary_ttl_secs(),
            self.gossip.max_future_skew_secs(),
        ) {
            return Err(MeshNodeError::StaleGossipMessage {
                peer: advertisement.from.as_str().to_string(),
                message_kind: "peer capability advertisement",
            });
        }

        let now_ms = now_secs.saturating_mul(1_000);
        self.update_peer_protocol_capabilities(&peer, advertisement.capabilities, now_ms);
        self.metrics.gossip_updates = self.metrics.gossip_updates.saturating_add(1);
        Ok(())
    }

    /// Verify and dispatch a priority revocation push.
    ///
    /// The mesh node does not own a revocation registry, so this returns a
    /// verified push descriptor for the caller to apply or reconcile.
    ///
    /// # Errors
    ///
    /// Returns an error if the push is unsigned, stale, bound to the wrong
    /// node ID, or fails signature verification against the registered peer
    /// key.
    pub fn handle_revocation_push(
        &mut self,
        push: RevocationPushMessage,
        now_secs: u64,
    ) -> Result<VerifiedRevocationPush, MeshNodeError> {
        // Layer 1: peer/transport signature (who forwarded it + zone
        // membership at the sender). Insufficient on its own.
        self.verify_revocation_push_signature(&push)?;

        // Layer 2: zone-owner signature over the revocation payload
        // itself. This is the ONLY authority that grants the right to
        // revoke objects. A compromised peer holding a registered peer
        // signing key can pass layer 1 but cannot forge layer 2 without
        // the zone owner's private key (br-flywheel_connectors-uxsnk).
        //
        // Fail-closed: if we do not know an owner key for the target
        // zone, we cannot verify authority and MUST reject — pre-uxsnk
        // the absence of an owner key silently defaulted to "trust the
        // peer signature," which is exactly the bypass uxsnk closes.
        let owner_key = self.zone_owner_keys.get(&push.zone_id).ok_or_else(|| {
            MeshNodeError::UnknownZoneOwner {
                zone_id: push.zone_id.to_string(),
            }
        })?;
        if push.owner_signature.is_none() {
            return Err(MeshNodeError::MissingOwnerSignature {
                peer: push.from.as_str().to_string(),
                zone_id: push.zone_id.to_string(),
            });
        }
        push.verify_owner_signature(owner_key).map_err(|_| {
            MeshNodeError::InvalidOwnerSignature {
                peer: push.from.as_str().to_string(),
                zone_id: push.zone_id.to_string(),
            }
        })?;

        let freshness = self
            .revocation_frontier
            .evaluate(push.zone_id.as_str(), push.new_rev_seq);
        debug!(
            target: "fcp.mesh.revocation.freshness",
            hier_vv_status = freshness.hier_vv_status(),
            decision = freshness.decision_label(),
            zone_id = %push.zone_id,
            incoming_seq = freshness.incoming_counter,
            local_seq = freshness.local_counter,
            "evaluated revocation push freshness"
        );
        if !freshness.is_accepted() {
            self.record_revocation_hiervv_size(&push.zone_id, &freshness);
            return Err(MeshNodeError::StaleRevocationFrontier {
                peer: push.from.as_str().to_string(),
                zone_id: push.zone_id.to_string(),
                incoming_seq: freshness.incoming_counter,
                local_seq: freshness.local_counter,
            });
        }

        if crate::gossip::is_outside_freshness_window(
            push.timestamp,
            now_secs,
            self.gossip.summary_ttl_secs(),
            self.gossip.max_future_skew_secs(),
        ) {
            return Err(MeshNodeError::StaleGossipMessage {
                peer: push.from.as_str().to_string(),
                message_kind: "revocation push",
            });
        }
        let freshness = self
            .revocation_frontier
            .observe(push.zone_id.as_str(), push.new_rev_seq);
        self.record_revocation_hiervv_size(&push.zone_id, &freshness);
        self.metrics.gossip_updates = self.metrics.gossip_updates.saturating_add(1);
        Ok(VerifiedRevocationPush {
            from: NodeId::new(push.from.as_str()),
            zone_id: push.zone_id,
            revoked_ids: push.revoked_ids,
            new_rev_seq: push.new_rev_seq,
            timestamp: push.timestamp,
            freshness,
        })
    }

    fn record_revocation_hiervv_size(
        &mut self,
        zone_id: &ZoneId,
        freshness: &RevocationFreshnessDecision,
    ) {
        match self.revocation_frontier.canonical_len() {
            Ok(size_bytes) => {
                let size_bytes_u64 = u64::try_from(size_bytes).unwrap_or(u64::MAX);
                let histogram_value = f64::from(u32::try_from(size_bytes).unwrap_or(u32::MAX));
                self.metrics.revocation_hiervv_size_samples = self
                    .metrics
                    .revocation_hiervv_size_samples
                    .saturating_add(1);
                self.metrics.revocation_hiervv_size_last_bytes = size_bytes_u64;
                metrics::record_histogram(
                    metrics::REVOCATION_HIERVV_SIZE_BYTES_METRIC,
                    histogram_value,
                    &[
                        ("zone", zone_id.as_str()),
                        ("hier_vv_status", freshness.hier_vv_status()),
                        ("decision", freshness.decision_label()),
                    ],
                );
                debug!(
                    target: "fcp.mesh.revocation.freshness",
                    hier_vv_status = freshness.hier_vv_status(),
                    decision = freshness.decision_label(),
                    zone_id = %zone_id,
                    hier_vv_size_bytes = size_bytes_u64,
                    metric = metrics::REVOCATION_HIERVV_SIZE_BYTES_METRIC,
                    "recorded revocation HierVV size"
                );
            }
            Err(error) => {
                debug!(
                    target: "fcp.mesh.revocation.freshness",
                    zone_id = %zone_id,
                    error = %error,
                    metric = metrics::REVOCATION_HIERVV_SIZE_BYTES_METRIC,
                    "failed to record revocation HierVV size"
                );
            }
        }
    }

    /// Verify and answer a bounded gossip request.
    ///
    /// Requests currently authenticate via the enrolled transport peer
    /// state rather than a signed message transcript, so the claimed
    /// `from` node must already exist in `self.peers`, be authorized
    /// for the requested zone, and remain within the normal gossip
    /// freshness window before the request reaches `MeshGossip`.
    ///
    /// # Errors
    ///
    /// Returns an error when the requester is unknown, not authorized
    /// for the claimed zone, or the request timestamp is stale.
    #[allow(clippy::needless_pass_by_value)] // by-value API mirrors handle_summary/handle_revocation_push
    pub fn handle_gossip_request(
        &mut self,
        request: GossipRequest,
        now_secs: u64,
    ) -> Result<GossipResponse, MeshNodeError> {
        self.verify_gossip_request(&request, now_secs)?;
        Ok(self.gossip.handle_request(&request))
    }

    /// Verify a gossip request and materialize the advertised bytes.
    ///
    /// This is the transport-agnostic responder side of the fetch path: it
    /// reuses the same bounded availability response as
    /// [`Self::handle_gossip_request`], then loads matching object and symbol
    /// bytes from the local stores. The requester can feed `response` through
    /// [`Self::handle_gossip_response`] and pass `payload` into
    /// [`Self::apply_gossip_fetch_payload`].
    ///
    /// # Errors
    ///
    /// Returns request verification errors from [`Self::handle_gossip_request`]
    /// or store/validation errors if advertised bytes cannot be materialized.
    #[allow(clippy::needless_pass_by_value)] // by-value API mirrors handle_gossip_request
    pub async fn prepare_gossip_fetch_reply(
        &mut self,
        request: GossipRequest,
        now_secs: u64,
    ) -> Result<GossipFetchReply, MeshNodeError> {
        let response = self.handle_gossip_request(request, now_secs)?;
        let payload = self.gossip_fetch_payload_for_response(&response).await?;
        Ok(GossipFetchReply { response, payload })
    }

    async fn gossip_fetch_payload_for_response(
        &self,
        response: &GossipResponse,
    ) -> Result<GossipFetchPayload, MeshNodeError> {
        if response.from != self.local_node_ts {
            return Err(MeshNodeError::RecipientMismatch {
                message_kind: "gossip fetch payload",
                expected: self.local_node_ts.as_str().to_string(),
                actual: response.from.as_str().to_string(),
            });
        }

        let plan = GossipFetchPlan {
            peer: response.from.clone(),
            zone_id: response.zone_id.clone(),
            object_ids: response.have_objects.clone(),
            symbols: response.have_symbols.clone(),
        };
        let requested_objects: BTreeSet<_> = plan.object_ids.iter().copied().collect();
        let requested_symbols: BTreeSet<_> = plan.symbols.iter().copied().collect();
        let mut payload = GossipFetchPayload::default();

        for object_id in &response.have_objects {
            let object = self.object_store.get(object_id).await?;
            Self::validate_fetched_object(&plan, &requested_objects, &object)?;
            payload.objects.push(object);
        }

        for (object_id, esi) in &response.have_symbols {
            let fetched = GossipFetchedSymbol {
                object_meta: self.symbol_store.get_object_meta(object_id).await?,
                symbol: self.symbol_store.get_symbol(object_id, *esi).await?,
            };
            Self::validate_fetched_symbol(&plan, &requested_symbols, &fetched)?;
            payload.symbols.push(fetched);
        }

        Ok(payload)
    }

    /// Verify a bounded gossip response and surface missing fetch candidates.
    ///
    /// The response only advertises availability; the caller still owns the
    /// transport/storage fetch that moves object or symbol bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the response is for another recipient, the peer
    /// is unknown, the peer is not authorized for the zone, the timestamp is
    /// stale, or the advertised availability exceeds configured budgets.
    #[allow(clippy::needless_pass_by_value)] // by-value API mirrors handle_gossip_request
    pub fn handle_gossip_response(
        &mut self,
        response: GossipResponse,
        now_secs: u64,
    ) -> Result<Option<GossipFetchPlan>, MeshNodeError> {
        self.verify_gossip_response(&response, now_secs)?;

        let GossipResponse {
            from,
            to: _,
            zone_id,
            have_objects,
            have_symbols,
            timestamp: _,
        } = response;

        let object_ids: Vec<_> = have_objects
            .into_iter()
            .filter(|object_id| !self.gossip.has_object(&zone_id, object_id))
            .collect();
        let symbols: Vec<_> = have_symbols
            .into_iter()
            .filter(|(object_id, esi)| !self.gossip.has_symbol(&zone_id, object_id, *esi))
            .collect();

        if object_ids.is_empty() && symbols.is_empty() {
            return Ok(None);
        }

        Ok(Some(GossipFetchPlan {
            peer: from,
            zone_id,
            object_ids,
            symbols,
        }))
    }

    /// Apply object and symbol bytes fetched for a verified gossip fetch plan.
    ///
    /// The transport layer owns the actual peer I/O. This method owns the
    /// safety boundary after bytes arrive: it re-checks peer zone membership,
    /// rejects unsolicited payloads, validates zone/object/ESI bindings, stores
    /// accepted bytes locally, and announces the resulting local availability.
    ///
    /// Content-address enforcement (`object_id == derive_id(header, body,
    /// zone_key)`) is owned by the object store's injected
    /// [`ObjectIdVerifier`](fcp_store::ObjectIdVerifier): `MeshNode` holds no
    /// zone keys by design, so whoever constructs a live-network node MUST
    /// inject a store built with a `KeyedObjectIdVerifier` for every served
    /// zone (fails closed with `VerifierKeyMissing` on unknown zones).
    /// Without it, a hostile peer can bind attacker-controlled bytes to a
    /// legitimately requested object id — this method warns loudly when that
    /// invariant is not met (bead mesh-node-content-id-verifier-wiring-h3xmd).
    /// Trace-replay and test nodes replaying already-captured traces are the
    /// only legitimate verifier-less callers.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is no longer enrolled for the zone, if any
    /// payload does not match the fetch plan, or if the local stores reject the
    /// fetched bytes.
    pub async fn apply_gossip_fetch_payload(
        &mut self,
        plan: &GossipFetchPlan,
        objects: Vec<StoredObject>,
        symbols: Vec<GossipFetchedSymbol>,
        now_ms: u64,
    ) -> Result<GossipFetchApplyOutcome, MeshNodeError> {
        let peer = self.verify_gossip_fetch_plan_peer(plan)?;
        if !objects.is_empty() && !self.object_store.has_object_id_verifier() {
            warn!(
                peer = plan.peer.as_str(),
                zone_id = %plan.zone_id,
                object_count = objects.len(),
                "accepting peer-supplied objects into an object store without a \
                 content-id verifier; live-network nodes MUST install a \
                 KeyedObjectIdVerifier or a hostile peer can poison the cache \
                 (bead mesh-node-content-id-verifier-wiring-h3xmd)"
            );
        }
        let requested_objects: BTreeSet<_> = plan.object_ids.iter().copied().collect();
        let requested_symbols: BTreeSet<_> = plan.symbols.iter().copied().collect();
        let mut outcome = GossipFetchApplyOutcome::default();

        for object in objects {
            Self::validate_fetched_object(plan, &requested_objects, &object)?;
            self.validate_fetched_lease_object(&object, now_ms)?;
            let object_id = object.object_id;
            let is_connector_state_root =
                object.header.schema == fcp_store::FcpStoreConnectorStateStore::root_schema_id();
            match self.object_store.put(object).await {
                Ok(()) | Err(fcp_store::ObjectStoreError::AlreadyExists(_)) => {}
                Err(err) => return Err(MeshNodeError::ObjectStore(err)),
            }
            self.announce_object(
                &plan.zone_id,
                &object_id,
                ObjectAdmissionClass::Admitted,
                now_ms,
            );
            outcome.objects_applied.push(object_id);
            if is_connector_state_root {
                outcome.connector_state_root_candidates.push(object_id);
            }
        }

        for fetched in symbols {
            let (object_id, esi) =
                Self::validate_fetched_symbol(plan, &requested_symbols, &fetched)?;
            self.symbol_store
                .put_object_meta(fetched.object_meta)
                .await?;
            self.symbol_store.put_symbol(fetched.symbol).await?;
            self.announce_symbol(
                &plan.zone_id,
                &object_id,
                esi,
                ObjectAdmissionClass::Admitted,
                now_ms,
            );
            outcome.symbols_applied.push((object_id, esi));
        }

        debug!(
            peer = %peer.as_str(),
            zone_id = %plan.zone_id,
            objects = outcome.objects_applied.len(),
            symbols = outcome.symbols_applied.len(),
            "applied gossip fetch payload"
        );

        Ok(outcome)
    }

    /// Apply fetched gossip bytes and observe any connector-state root candidates.
    ///
    /// Use this from host/transport adapters that already know the appropriate
    /// connector-state store. It keeps the byte-admission and cache-invalidation
    /// handoff in one call: fetched objects/symbols are admitted first, then any
    /// fetched connector-state roots are validated by `fcp-store` and announced.
    ///
    /// # Errors
    ///
    /// Returns byte-application errors from [`Self::apply_gossip_fetch_payload`]
    /// or connector-state validation errors from `FcpStoreConnectorStateStore`.
    pub async fn apply_gossip_fetch_payload_and_observe_connector_state_roots(
        &mut self,
        state_store: &FcpStoreConnectorStateStore,
        plan: &GossipFetchPlan,
        objects: Vec<StoredObject>,
        symbols: Vec<GossipFetchedSymbol>,
        now_ms: u64,
    ) -> Result<GossipFetchApplyObserveOutcome, MeshNodeError> {
        let apply = self
            .apply_gossip_fetch_payload(plan, objects, symbols, now_ms)
            .await?;
        let connector_state_changes = self
            .observe_connector_state_root_candidates(
                state_store,
                &apply.connector_state_root_candidates,
                now_ms,
            )
            .await?;

        Ok(GossipFetchApplyObserveOutcome {
            apply,
            connector_state_changes,
        })
    }

    /// Observe already-admitted connector-state root candidates.
    ///
    /// `apply_gossip_fetch_payload` can only identify schema-level candidates.
    /// This helper performs the connector/zone/key-aware validation step and
    /// returns concrete cache-invalidation changes for every accepted root.
    ///
    /// # Errors
    ///
    /// Returns the first connector-state store validation error.
    pub async fn observe_connector_state_root_candidates(
        &mut self,
        state_store: &FcpStoreConnectorStateStore,
        root_object_ids: &[ObjectId],
        now_ms: u64,
    ) -> Result<Vec<ConnectorStateChange>, ConnectorStateStoreError> {
        let mut changes = Vec::with_capacity(root_object_ids.len());
        for root_object_id in root_object_ids {
            changes.push(
                self.observe_connector_state_root(state_store, *root_object_id, now_ms)
                    .await?,
            );
        }
        Ok(changes)
    }

    fn verify_gossip_fetch_plan_peer(
        &self,
        plan: &GossipFetchPlan,
    ) -> Result<NodeId, MeshNodeError> {
        let peer = NodeId::new(plan.peer.as_str());
        let peer_state = self
            .peers
            .get(&peer)
            .ok_or_else(|| MeshNodeError::UnknownPeer {
                peer: peer.as_str().to_string(),
                message_kind: "gossip fetch payload",
            })?;
        if !peer_state.zones.contains(&plan.zone_id) {
            return Err(MeshNodeError::UnauthorizedZone {
                peer: peer.as_str().to_string(),
                zone_id: plan.zone_id.to_string(),
            });
        }
        Ok(peer)
    }

    fn validate_fetched_object(
        plan: &GossipFetchPlan,
        requested_objects: &BTreeSet<ObjectId>,
        object: &StoredObject,
    ) -> Result<(), MeshNodeError> {
        if !requested_objects.contains(&object.object_id) {
            return Err(MeshNodeError::GossipDecode(format!(
                "fetched object {} from {} was not requested for zone {}",
                object.object_id,
                plan.peer.as_str(),
                plan.zone_id
            )));
        }
        if object.header.zone_id != plan.zone_id {
            return Err(MeshNodeError::GossipDecode(format!(
                "fetched object {} from {} has zone {}, expected {}",
                object.object_id,
                plan.peer.as_str(),
                object.header.zone_id,
                plan.zone_id
            )));
        }
        object.validate_structure().map_err(|err| {
            MeshNodeError::GossipDecode(format!(
                "fetched object {} from {} failed structural validation: {}",
                object.object_id,
                plan.peer.as_str(),
                err
            ))
        })
    }

    fn validate_fetched_lease_object(
        &self,
        object: &StoredObject,
        now_ms: u64,
    ) -> Result<(), MeshNodeError> {
        if object.header.schema != CoreLease::schema_id() {
            return Ok(());
        }

        let lease: CoreLease =
            CanonicalSerializer::deserialize(&object.body, &object.header.schema)?;
        validate_core_lease(
            &lease,
            &lease.subject_object_id,
            lease.zone_id(),
            lease.purpose,
            lease.lease_seq,
            now_ms / 1000,
            DEFAULT_LEASE_PUBLICATION_REQUIRED_QUORUM_SIGNATURES,
        )?;
        self.verify_lease_quorum_signatures(&lease)
    }

    fn validate_fetched_symbol(
        plan: &GossipFetchPlan,
        requested_symbols: &BTreeSet<(ObjectId, u32)>,
        fetched: &GossipFetchedSymbol,
    ) -> Result<(ObjectId, u32), MeshNodeError> {
        let object_id = fetched.symbol.meta.object_id;
        let esi = fetched.symbol.meta.esi;
        if !requested_symbols.contains(&(object_id, esi)) {
            return Err(MeshNodeError::GossipDecode(format!(
                "fetched symbol {}:{} from {} was not requested for zone {}",
                object_id,
                esi,
                plan.peer.as_str(),
                plan.zone_id
            )));
        }
        if fetched.object_meta.object_id != object_id {
            return Err(MeshNodeError::GossipDecode(format!(
                "fetched symbol {}:{} from {} carries object metadata for {}",
                object_id,
                esi,
                plan.peer.as_str(),
                fetched.object_meta.object_id
            )));
        }
        if fetched.object_meta.zone_id != plan.zone_id
            || fetched.symbol.meta.zone_id != plan.zone_id
        {
            return Err(MeshNodeError::GossipDecode(format!(
                "fetched symbol {}:{} from {} has zone metadata {}/{}, expected {}",
                object_id,
                esi,
                plan.peer.as_str(),
                fetched.object_meta.zone_id,
                fetched.symbol.meta.zone_id,
                plan.zone_id
            )));
        }
        Ok((object_id, esi))
    }

    /// Verify and answer a bounded IBLT reconcile request.
    ///
    /// # Errors
    ///
    /// Returns an error when the requester is unknown, not authorized for the
    /// claimed zone, stale, or sends an invalid/oversized IBLT payload.
    #[allow(clippy::needless_pass_by_value)] // by-value API mirrors handle_gossip_request
    pub fn handle_reconcile_request(
        &mut self,
        request: ReconcileRequest,
        now_secs: u64,
    ) -> Result<Option<ReconcileResponse>, MeshNodeError> {
        self.verify_reconcile_request(&request, now_secs)?;
        let peer_iblt = IbltPlaceholder::decode_with_limits(
            &request.iblt,
            self.gossip.reconciliation_batch_size(),
            self.gossip.max_iblt_bytes(),
        )
        .map_err(|err| {
            MeshNodeError::GossipDecode(format!(
                "reconcile request IBLT from {} for zone {} rejected: {}",
                request.from.as_str(),
                request.zone_id,
                err.reason_code()
            ))
        })?;

        Ok(self.gossip.reconcile_zone_iblt(
            &request.zone_id,
            &request.from,
            peer_iblt.as_iblt(),
            self.gossip.reconciliation_batch_size(),
            now_secs,
        ))
    }

    /// Verify a reconcile response and produce the next bounded object request.
    ///
    /// # Errors
    ///
    /// Returns an error when the responder is unknown, not authorized for the
    /// claimed zone, stale, or sends over-budget object lists.
    #[allow(clippy::needless_pass_by_value)] // by-value API mirrors handle_reconcile_request
    pub fn handle_reconcile_response(
        &mut self,
        response: ReconcileResponse,
        now_secs: u64,
    ) -> Result<Option<GossipFollowupRequest>, MeshNodeError> {
        self.verify_reconcile_response(&response, now_secs)?;

        let target_peer = response.from.clone();
        let zone_id = response.zone_id.clone();
        let missing_objects: Vec<_> = response
            .we_missing_objects
            .into_iter()
            .filter(|object_id| !self.gossip.has_object(&zone_id, object_id))
            .collect();

        if missing_objects.is_empty() {
            return Ok(None);
        }

        let request = self
            .gossip
            .create_request(&zone_id, missing_objects, now_secs);
        Ok(Some(GossipFollowupRequest {
            peer: target_peer,
            request,
        }))
    }

    /// Dispatch a gossip control-plane message through the verified node entrypoint.
    ///
    /// Returns any verified revocation push plus an immediate gossip
    /// response that the transport should return to the requester, or a
    /// bounded follow-up request the transport should send to a peer.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError` if summary, request, or revocation-push
    /// verification fails.
    pub fn handle_gossip_message(
        &mut self,
        message: GossipMessage,
        now_secs: u64,
    ) -> Result<GossipDispatchOutcome, MeshNodeError> {
        match message {
            GossipMessage::Summary(summary) => {
                self.handle_summary(summary, now_secs)?;
                Ok(GossipDispatchOutcome::default())
            }
            GossipMessage::PeerCapabilities(advertisement) => {
                self.handle_peer_capability_advertisement(advertisement, now_secs)?;
                Ok(GossipDispatchOutcome::default())
            }
            GossipMessage::RevocationPush(push) => self
                .handle_revocation_push(push, now_secs)
                .map(GossipDispatchOutcome::with_revocation_push),
            GossipMessage::Request(request) => self
                .handle_gossip_request(request, now_secs)
                .map(GossipDispatchOutcome::with_response),
            GossipMessage::Response(response) => self
                .handle_gossip_response(response, now_secs)
                .map(|fetch_plan| {
                    fetch_plan.map_or_else(
                        GossipDispatchOutcome::default,
                        GossipDispatchOutcome::with_fetch_plan,
                    )
                }),
            GossipMessage::ReconcileRequest(request) => self
                .handle_reconcile_request(request, now_secs)
                .map(|response| {
                    response.map_or_else(
                        GossipDispatchOutcome::default,
                        GossipDispatchOutcome::with_reconcile_response,
                    )
                }),
            GossipMessage::ReconcileResponse(response) => self
                .handle_reconcile_response(response, now_secs)
                .map(|followup| {
                    followup.map_or_else(
                        GossipDispatchOutcome::default,
                        GossipDispatchOutcome::with_followup_request,
                    )
                }),
        }
    }

    /// Dispatch a parsed gossip message and materialize request bytes when needed.
    ///
    /// Existing callers that only need control-plane actions should continue to
    /// use [`Self::handle_gossip_message`]. Transport adapters that can carry
    /// requested bytes inline can use this method to receive the same
    /// [`GossipDispatchOutcome`] plus a [`GossipFetchReply`] for inbound
    /// `GossipMessage::Request` payloads.
    ///
    /// # Errors
    ///
    /// Propagates verification errors from the underlying gossip handlers and
    /// store/validation errors from [`Self::prepare_gossip_fetch_reply`] when
    /// request bytes cannot be materialized.
    pub async fn handle_gossip_message_with_fetch_reply(
        &mut self,
        message: GossipMessage,
        now_secs: u64,
    ) -> Result<GossipDispatchFetchOutcome, MeshNodeError> {
        match message {
            GossipMessage::Request(request) => self
                .prepare_gossip_fetch_reply(request, now_secs)
                .await
                .map(GossipDispatchFetchOutcome::with_fetch_reply),
            other => self
                .handle_gossip_message(other, now_secs)
                .map(GossipDispatchFetchOutcome::from_dispatch),
        }
    }

    /// Decode a JSON-encoded `GossipMessage` received from the mesh
    /// transport layer and dispatch it through [`Self::handle_gossip_message`].
    ///
    /// This is the production entry point that closes the L3-02
    /// "RevocationPush dispatch gap": mesh transports MUST call this
    /// method whenever they receive an inbound gossip payload so that
    /// the signature verification, zone authorization, replay check,
    /// and revocation-registry update logic runs in a production code
    /// path (not only in tests and fuzzers).
    ///
    /// The current wire format is JSON because `GossipMessage` uses
    /// `#[serde(tag = "type")]` internal tagging, which has documented
    /// interop issues with deterministic CBOR implementations. A
    /// follow-up migration to canonical CBOR (tracked alongside L3-02)
    /// should move this to `fcp_cbor::serialize`/`deserialize` once the
    /// enum is refactored to an externally tagged or non-tagged layout
    /// that CBOR handles cleanly.
    ///
    /// # Errors
    ///
    /// Returns [`MeshNodeError::GossipPayloadTooLarge`] if the raw
    /// transport body exceeds the configured byte budget,
    /// [`MeshNodeError::GossipDecode`] if the payload does not
    /// deserialize to a [`GossipMessage`], or propagates any verification
    /// error surfaced by the underlying gossip handlers.
    pub fn dispatch_gossip_payload(
        &mut self,
        payload: &[u8],
        now_secs: u64,
    ) -> Result<GossipDispatchOutcome, MeshNodeError> {
        let max_payload = self.gossip.max_wire_payload_bytes();
        if payload.len() > max_payload {
            return Err(MeshNodeError::GossipPayloadTooLarge {
                len: payload.len(),
                max: max_payload,
            });
        }

        let message: GossipMessage = serde_json::from_slice(payload)
            .map_err(|e| MeshNodeError::GossipDecode(e.to_string()))?;
        self.handle_gossip_message(message, now_secs)
    }

    /// Decode and dispatch a raw gossip payload, materializing request bytes.
    ///
    /// This is the async counterpart to [`Self::dispatch_gossip_payload`] for
    /// transports that want a single verified request path that returns both
    /// the availability response and the bytes matching that availability.
    ///
    /// # Errors
    ///
    /// Returns the same decode and verification errors as
    /// [`Self::dispatch_gossip_payload`], plus store/validation errors if an
    /// inbound request advertises bytes that cannot be loaded safely.
    pub async fn dispatch_gossip_payload_with_fetch_reply(
        &mut self,
        payload: &[u8],
        now_secs: u64,
    ) -> Result<GossipDispatchFetchOutcome, MeshNodeError> {
        let max_payload = self.gossip.max_wire_payload_bytes();
        if payload.len() > max_payload {
            return Err(MeshNodeError::GossipPayloadTooLarge {
                len: payload.len(),
                max: max_payload,
            });
        }

        let message: GossipMessage = serde_json::from_slice(payload)
            .map_err(|e| MeshNodeError::GossipDecode(e.to_string()))?;
        self.handle_gossip_message_with_fetch_reply(message, now_secs)
            .await
    }

    /// Dispatch an already-parsed `GossipMessage` that was delivered
    /// through the mesh transport. Use this variant when the
    /// transport layer has already deserialized the wire payload.
    ///
    /// # Errors
    ///
    /// Propagates any verification error from the underlying gossip
    /// handlers (signature, replay, zone authorization, staleness).
    pub fn dispatch_gossip_message(
        &mut self,
        message: GossipMessage,
        now_secs: u64,
    ) -> Result<GossipDispatchOutcome, MeshNodeError> {
        self.handle_gossip_message(message, now_secs)
    }

    /// Decode a JSON-encoded `GossipMessage` payload carried inside a
    /// [`ControlPlaneEnvelope`] and dispatch it through the gossip
    /// handlers. Convenience wrapper over
    /// [`Self::dispatch_gossip_payload`] for transports that surface
    /// envelopes rather than raw bytes.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::dispatch_gossip_payload`].
    pub fn dispatch_gossip_envelope(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        now_secs: u64,
    ) -> Result<GossipDispatchOutcome, MeshNodeError> {
        self.dispatch_gossip_payload(&envelope.payload, now_secs)
    }

    /// Apply a decode status update (targeted repair feedback).
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError` if the status targets a different recipient or
    /// fails peer signature verification.
    pub fn handle_decode_status(
        &mut self,
        peer: &NodeId,
        status: &DecodeStatus,
        now_ms: u64,
    ) -> Result<(), MeshNodeError> {
        if status.recipient_node_id != self.local_node_ts {
            return Err(MeshNodeError::RecipientMismatch {
                message_kind: "decode status",
                expected: self.local_node_ts.as_str().to_string(),
                actual: status.recipient_node_id.as_str().to_string(),
            });
        }
        let key = self.peer_signing_key(peer)?;
        status
            .verify(key)
            .map_err(|_| MeshNodeError::PeerSignatureInvalid {
                peer: peer.as_str().to_string(),
                message_kind: "decode status",
            })?;
        self.symbol_requests
            .process_decode_status(peer, status, now_ms);
        Ok(())
    }

    /// Apply a SymbolAck and stop further sends.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError` if the ack targets a different recipient or
    /// fails peer signature verification.
    pub fn handle_symbol_ack(
        &mut self,
        peer: &NodeId,
        ack: &SymbolAck,
        now_ms: u64,
    ) -> Result<(), MeshNodeError> {
        if ack.recipient_node_id != self.local_node_ts {
            return Err(MeshNodeError::RecipientMismatch {
                message_kind: "symbol ack",
                expected: self.local_node_ts.as_str().to_string(),
                actual: ack.recipient_node_id.as_str().to_string(),
            });
        }
        let key = self.peer_signing_key(peer)?;
        ack.verify(key)
            .map_err(|_| MeshNodeError::PeerSignatureInvalid {
                peer: peer.as_str().to_string(),
                message_kind: "symbol ack",
            })?;
        self.symbol_requests.process_symbol_ack(peer, ack, now_ms);
        self.symbol_metrics.record_ack();
        self.sent_symbols
            .remove(&TransferKey::new(peer, &ack.object_id));
        Ok(())
    }

    /// Prune stale state (transfers, sent_symbols, admission peers, gossip
    /// peer_states). Returns total items pruned.
    pub fn prune_stale_state(&mut self, now_ms: u64) -> usize {
        let mut pruned = 0;

        // Prune symbol requests
        pruned += self.symbol_requests.prune_stale_state(now_ms);

        // Prune sent_symbols (using same TTL from policy)
        let ttl = self.symbol_requests.policy().transfer_state_ttl_ms;
        let expired_threshold = now_ms.saturating_sub(ttl);

        let initial_len = self.sent_symbols.len();
        self.sent_symbols
            .retain(|_, (ts, _)| *ts >= expired_threshold);
        pruned += initial_len - self.sent_symbols.len();

        // Prune stale admission peers (5 minutes threshold)
        let initial_peers = self.admission.peer_count();
        self.admission.gc_stale_peers(now_ms, 300_000);
        pruned += initial_peers.saturating_sub(self.admission.peer_count());

        // Prune stale gossip peer_states. Each handle_summary() call inserts
        // or refreshes a PeerGossipState entry for the summary's source
        // peer, so without a periodic prune the map grows with every new
        // peer we ever interact with. gossip uses seconds-scale timestamps
        // (summary_ttl_secs) internally, hence the /1000.
        pruned += self.gossip.prune_stale_peers(now_ms / 1000);

        if pruned > 0 {
            debug!(pruned, "pruned stale mesh node state");
        }
        pruned
    }

    /// Encode a control-plane envelope for degraded transport.
    /// `epoch_id` is the transport epoch written into the degraded FCPS frame
    /// headers.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::DegradedTransport` if encoding fails.
    pub fn encode_control_plane(
        &mut self,
        envelope: &ControlPlaneEnvelope,
        epoch_id: u64,
        zone_key: &ZoneKey,
        algorithm: ZoneKeyAlgorithm,
    ) -> Result<Vec<fcp_protocol::FcpsFrame>, MeshNodeError> {
        Ok(self.degraded_encoder.encode_authenticated(
            envelope,
            epoch_id,
            zone_key,
            algorithm,
            &self.local_node_ts,
        )?)
    }

    /// Decode a control-plane frame in degraded mode.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::DegradedTransport` if decoding fails.
    #[allow(clippy::too_many_arguments)] // Degraded decode must bind peer, frame, zone, retention, crypto, and time.
    pub fn decode_control_plane(
        &mut self,
        peer: &NodeId,
        frame: &fcp_protocol::FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
        zone_key: &ZoneKey,
        algorithm: ZoneKeyAlgorithm,
        now_ms: u64,
    ) -> Result<Option<ControlPlaneEnvelope>, MeshNodeError> {
        // Enforce per-peer concurrent decode limits (Admission Control)
        self.admission.try_acquire_decode(peer, now_ms)?;

        let sender_node_id = TailscaleNodeId::new(peer.as_str());
        let result = self.degraded_decoder.process_frame_authenticated(
            frame,
            expected_zone_id,
            retention,
            zone_key,
            algorithm,
            &sender_node_id,
        );

        // Release the decode slot immediately after processing the frame.
        // This bounds the active CPU time spent decoding for this peer.
        self.admission.release_decode(peer, now_ms);

        Ok(result?)
    }

    /// Decode a control-plane frame and enforce retention via handler.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError` if decoding fails or the handler rejects the
    /// envelope.
    #[allow(clippy::too_many_arguments)] // Frame processing adds the handler to the degraded decode context.
    pub fn process_control_plane_frame(
        &mut self,
        peer: &NodeId,
        frame: &fcp_protocol::FcpsFrame,
        expected_zone_id: &ZoneId,
        retention: RetentionClass,
        zone_key: &ZoneKey,
        algorithm: ZoneKeyAlgorithm,
        now_ms: u64,
        handler: &dyn ControlPlaneHandler,
    ) -> Result<Option<ControlPlaneEnvelope>, MeshNodeError> {
        let envelope = self.decode_control_plane(
            peer,
            frame,
            expected_zone_id,
            retention,
            zone_key,
            algorithm,
            now_ms,
        )?;
        if let Some(ref env) = envelope {
            handler.handle(env.clone())?;
        }
        Ok(envelope)
    }

    /// Snapshot metrics.
    #[must_use]
    pub fn metrics(&self) -> MeshNodeMetrics {
        let mut metrics = self.metrics.clone();
        metrics.symbol_requests = self.symbol_metrics.clone();
        metrics
    }

    /// Snapshot trace capture with redaction applied (if enabled).
    #[must_use]
    pub fn trace_snapshot(&self) -> Option<CapturedTrace> {
        self.trace_capture.as_ref().map(TraceCapture::snapshot)
    }

    /// Snapshot trace capture with redaction applied (if enabled).
    #[must_use]
    pub fn trace_redacted_snapshot(&self) -> Option<CapturedTrace> {
        self.trace_snapshot()
    }

    /// Snapshot trace capture without redaction for deterministic replay/debug flows.
    #[must_use]
    pub fn trace_debug_unredacted_snapshot(&self) -> Option<CapturedTrace> {
        self.trace_capture
            .as_ref()
            .map(TraceCapture::debug_unredacted_snapshot)
    }

    /// Export trace capture to a file with redaction applied.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::TraceNotEnabled` if capture is disabled or
    /// `MeshNodeError::TraceExport` if serialization/IO fails.
    pub fn export_trace_to_path<P: AsRef<Path>>(
        &self,
        path: P,
        format: TraceExportFormat,
    ) -> Result<(), MeshNodeError> {
        let Some(capture) = self.trace_capture.as_ref() else {
            return Err(MeshNodeError::TraceNotEnabled);
        };

        capture.export_to_path(path, format)?;
        Ok(())
    }

    /// Export unredacted trace capture for deterministic replay/debug flows.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::TraceNotEnabled` if capture is disabled or
    /// `MeshNodeError::TraceExport` if serialization/IO fails.
    pub fn debug_export_unredacted_trace_to_path<P: AsRef<Path>>(
        &self,
        path: P,
        format: TraceExportFormat,
    ) -> Result<(), MeshNodeError> {
        let Some(capture) = self.trace_capture.as_ref() else {
            return Err(MeshNodeError::TraceNotEnabled);
        };

        capture.debug_export_unredacted_to_path(path, format)?;
        Ok(())
    }

    /// Ingest a trace event into the node capture buffer for deterministic replay.
    ///
    /// This method is intended for offline replay/debug flows where a captured trace
    /// is fed back through a `MeshNode` to validate deterministic behavior.
    ///
    /// # Errors
    ///
    /// Returns `MeshNodeError::TraceNotEnabled` if trace capture is disabled or
    /// `MeshNodeError::TraceExport` when the capture buffer rejects the event.
    pub fn ingest_trace_event_for_replay(
        &mut self,
        event: TraceEvent,
    ) -> Result<(), MeshNodeError> {
        let Some(capture) = self.trace_capture.as_mut() else {
            return Err(MeshNodeError::TraceNotEnabled);
        };
        capture.record(event)?;
        Ok(())
    }

    /// Rank candidate transport paths according to zone policy.
    #[must_use]
    pub fn rank_transport_paths(
        &self,
        policy: &ZoneTransportPolicy,
        paths: &[TransportPath],
    ) -> Vec<RankedPath> {
        TransportSelector::rank_paths(paths, policy)
    }

    /// Select the best eligible transport path according to policy and priority.
    #[must_use]
    pub fn best_transport_path(
        &self,
        policy: &ZoneTransportPolicy,
        paths: &[TransportPath],
    ) -> Option<RankedPath> {
        TransportSelector::best_path(paths, policy)
    }

    /// Select deterministic multipath routes for a symbol.
    #[must_use]
    pub fn select_transport_paths(
        &mut self,
        policy: &ZoneTransportPolicy,
        paths: &[TransportPath],
        object_id: &ObjectId,
        symbol_index: u32,
        fanout: usize,
    ) -> Vec<TransportPath> {
        let selected =
            TransportSelector::select_multipath(paths, policy, object_id, symbol_index, fanout);

        if let Some(trace_id) = self.trace_id() {
            let now_ms = current_time_ms();
            if selected.is_empty() {
                self.record_trace_event(TraceEvent::Routing(RoutingDecision {
                    timestamp: now_ms,
                    trace_id,
                    source_node: self.local_node.as_str().to_string(),
                    target_node: None,
                    object_id: object_id.to_string(),
                    path_type: "none".to_string(),
                    decision: "dropped".to_string(),
                    reason: Some("no_eligible_path".to_string()),
                }));
            } else {
                for path in &selected {
                    self.record_trace_event(TraceEvent::Routing(RoutingDecision {
                        timestamp: now_ms,
                        trace_id: trace_id.clone(),
                        source_node: self.local_node.as_str().to_string(),
                        target_node: Some(path.peer.as_str().to_string()),
                        object_id: object_id.to_string(),
                        path_type: transport_path_kind_label(path.kind).to_string(),
                        decision: "routed".to_string(),
                        reason: None,
                    }));
                }
            }
        }

        selected
    }

    /// Access underlying gossip state (mutable).
    pub fn gossip_mut(&mut self) -> &mut MeshGossip {
        &mut self.gossip
    }

    /// Access admission controller (mutable).
    pub fn admission_mut(&mut self) -> &mut AdmissionController {
        &mut self.admission
    }

    /// Access object store.
    #[must_use]
    pub fn object_store(&self) -> &Arc<dyn ObjectStore> {
        &self.object_store
    }

    /// Access symbol store.
    #[must_use]
    pub fn symbol_store(&self) -> &Arc<dyn SymbolStore> {
        &self.symbol_store
    }

    /// Access quarantine store.
    #[must_use]
    pub fn quarantine_store(&self) -> &Arc<QuarantineStore> {
        &self.quarantine_store
    }
}

fn transport_path_kind_label(kind: crate::transport::TransportPathKind) -> &'static str {
    match kind {
        crate::transport::TransportPathKind::Direct => "direct",
        crate::transport::TransportPathKind::Mesh => "mesh",
        crate::transport::TransportPathKind::Derp => "derp",
        crate::transport::TransportPathKind::Funnel => "funnel",
    }
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeviceProfileBuilder, LeaseCoordinator, SignedLeaseIssueOutcome, SignedLeaseIssueRequest,
        TransportPathKind,
    };
    use bytes::Bytes;
    use fcp_core::{
        ConnectorId, ConnectorStateChangeKind, ConnectorStateModel, ConnectorStateRoot, EpochId,
        ObjectHeader, Provenance, ZoneKeyId,
    };
    use fcp_crypto::Ed25519SigningKey;
    use fcp_protocol::{
        DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED, MeshSessionId, SessionCryptoSuite, SessionKeys,
        SessionReplayPolicy, SymbolAckReason, TransportLimits,
    };
    use fcp_raptorq::ObjectTransmissionInformation;
    use fcp_store::{
        FcpStoreConnectorStateStore, MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore,
        MemorySymbolStoreConfig, ObjectAdmissionPolicy, ObjectSymbolMeta, QuarantineStore,
        QuarantinedObject, StoredSymbol, SymbolMeta,
    };

    fn test_node(name: &str) -> MeshNode {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
        MeshNode::new(
            MeshNodeConfig::new(name).with_sender_instance_id(42),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    fn test_node_with_trace(name: &str) -> MeshNode {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
        let trace_config = TraceCaptureConfig::new().enabled();
        MeshNode::new(
            MeshNodeConfig::new(name)
                .with_sender_instance_id(42)
                .with_trace_capture_config(trace_config),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    fn test_device_profile(node_name: &str) -> DeviceProfile {
        DeviceProfileBuilder::new(NodeId::new(node_name)).build()
    }

    fn zone_set(zone_id: ZoneId) -> HashSet<ZoneId> {
        HashSet::from([zone_id])
    }

    /// Attach a peer signature AND a zone-owner signature to `push`
    /// (br-uxsnk). Tests that exercise the happy path must sign both
    /// layers; tests that exercise forgery detection call only the
    /// peer-sign half.
    fn sign_push_with_owner(
        push: &mut RevocationPushMessage,
        peer_signing_key: &Ed25519SigningKey,
        owner_signing_key: &Ed25519SigningKey,
        now: u64,
    ) {
        push.signature = Some(fcp_core::NodeSignature::new(
            fcp_core::NodeId::new(push.from.as_str()),
            peer_signing_key.sign(&push.signing_bytes()).to_bytes(),
            now,
        ));
        push.owner_signature = Some(fcp_core::NodeSignature::new(
            fcp_core::NodeId::new("zone-owner"),
            owner_signing_key
                .sign(&push.owner_signing_bytes())
                .to_bytes(),
            now,
        ));
    }

    fn test_session(peer_name: &str) -> MeshSession {
        MeshSession::new(
            MeshSessionId::new(),
            NodeId::new(peer_name),
            SessionCryptoSuite::Suite1,
            SessionKeys {
                k_mac_i2r: [1u8; 32],
                k_mac_r2i: [2u8; 32],
                k_ctx: [3u8; 32],
            },
            TransportLimits::default(),
            true,
            1000,
            SessionReplayPolicy::default(),
        )
    }

    fn test_object_header() -> fcp_core::ObjectHeader {
        let zone_id = ZoneId::work();
        fcp_core::ObjectHeader {
            schema: fcp_cbor::SchemaId::new("fcp.test", "TestObj", semver::Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: fcp_core::Provenance::new(zone_id),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_object_id(name: &str) -> ObjectId {
        let hash = blake3::hash(name.as_bytes());
        ObjectId::from_bytes(*hash.as_bytes())
    }

    fn test_stored_object(zone_id: &ZoneId, name: &str, body: &[u8]) -> StoredObject {
        let schema =
            fcp_cbor::SchemaId::new("fcp.test", "FetchedObject", semver::Version::new(1, 0, 0));
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema,
            zone_id: zone_id.clone(),
            created_at: 1,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let mut keyed_body = name.as_bytes().to_vec();
        keyed_body.extend_from_slice(body);
        let object_id =
            StoredObject::derive_id(&header, &keyed_body, &ObjectIdKey::from_bytes([0x99; 32]))
                .expect("derive object id");
        StoredObject {
            object_id,
            header,
            body: keyed_body,
            storage: StorageMeta {
                retention: EvictionPolicy::Pinned,
            },
        }
    }

    fn test_connector_state_root_object(
        zone_id: &ZoneId,
        connector_id: ConnectorId,
        object_id_key: ObjectIdKey,
    ) -> StoredObject {
        let schema = FcpStoreConnectorStateStore::root_schema_id();
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: schema.clone(),
            zone_id: zone_id.clone(),
            created_at: 1,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let root = ConnectorStateRoot {
            header: header.clone(),
            connector_id,
            instance_id: None,
            zone_id: zone_id.clone(),
            model: ConnectorStateModel::SingletonWriter,
            head: None,
            state_schema_version: 1,
        };
        let body = CanonicalSerializer::serialize(&root, &schema).expect("serialize root");
        let object_id =
            StoredObject::derive_id(&header, &body, &object_id_key).expect("derive root id");
        StoredObject {
            object_id,
            header,
            body,
            storage: StorageMeta {
                retention: EvictionPolicy::Pinned,
            },
        }
    }

    fn test_core_lease(zone_id: &ZoneId, subject_object_id: ObjectId) -> fcp_prelude::Lease {
        let schema = fcp_cbor::SchemaId::new("fcp.lease", "lease", semver::Version::new(1, 0, 0));
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema,
            zone_id: zone_id.clone(),
            created_at: 10,
            provenance: Provenance::new(zone_id.clone()),
            refs: vec![subject_object_id],
            foreign_refs: Vec::new(),
            ttl_secs: Some(60),
            placement: None,
        };
        fcp_prelude::Lease {
            header,
            holder: TailscaleNodeId::new("node-1"),
            lease_seq: 7,
            exp: 70,
            subject_object_id,
            purpose: fcp_prelude::LeasePurpose::ConnectorStateWrite,
            quorum_signatures: test_signature_set(&["node-1", "node-2"]),
        }
    }

    fn test_signature_set(signers: &[&str]) -> fcp_core::SignatureSet {
        let mut signatures = fcp_core::SignatureSet::new();
        for (idx, signer) in signers.iter().enumerate() {
            let signature_byte = u8::try_from(idx).unwrap_or(u8::MAX);
            signatures.add(fcp_core::NodeSignature::new(
                fcp_core::NodeId::new(*signer),
                [signature_byte; 64],
                1_000 + u64::try_from(idx).unwrap_or(u64::MAX),
            ));
        }
        signatures
    }

    fn sign_lease_quorum(lease: &mut fcp_prelude::Lease, signers: &[(&str, &Ed25519SigningKey)]) {
        lease.quorum_signatures = fcp_core::SignatureSet::new();
        let signing_bytes = lease
            .quorum_signing_bytes()
            .expect("lease quorum signing bytes");
        let mut signatures = fcp_core::SignatureSet::new();
        for (idx, (node_id, signing_key)) in signers.iter().enumerate() {
            signatures.add(fcp_core::NodeSignature::new(
                fcp_core::NodeId::new(*node_id),
                signing_key.sign(&signing_bytes).to_bytes(),
                1_000 + u64::try_from(idx).unwrap_or(u64::MAX),
            ));
        }
        lease.quorum_signatures = signatures;
    }

    fn register_lease_signer_keys(node: &mut MeshNode, signers: &[(&str, &Ed25519SigningKey)]) {
        for (node_id, signing_key) in signers {
            node.register_peer_signing_key(NodeId::new(*node_id), signing_key.verifying_key());
        }
    }

    fn stored_lease_object(
        lease: &fcp_prelude::Lease,
        object_id_key: &ObjectIdKey,
    ) -> (ObjectId, StoredObject) {
        let body =
            CanonicalSerializer::serialize(lease, &lease.header.schema).expect("serialize lease");
        let object_id =
            StoredObject::derive_id(&lease.header, &body, object_id_key).expect("derive lease id");
        let stored = StoredObject {
            object_id,
            header: lease.header.clone(),
            body,
            storage: StorageMeta {
                retention: EvictionPolicy::Lease {
                    expires_at: lease.exp,
                },
            },
        };
        (object_id, stored)
    }

    fn test_object_symbol_meta(object_id: ObjectId, zone_id: &ZoneId) -> ObjectSymbolMeta {
        let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
        ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 2,
            first_symbol_at: 0,
        }
    }

    fn test_stored_symbol(
        object_id: ObjectId,
        zone_id: &ZoneId,
        esi: u32,
        fill: u8,
    ) -> StoredSymbol {
        StoredSymbol {
            meta: SymbolMeta {
                object_id,
                esi,
                zone_id: zone_id.clone(),
                source_node: Some(1),
                stored_at: 0,
            },
            data: Bytes::from(vec![fill; 64]),
        }
    }

    #[test]
    fn meshnode_transport_helpers_respect_policy() {
        let mut node = test_node("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        };

        let paths = vec![
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-1"),
                "direct",
                None,
            ),
            TransportPath::new(TransportPathKind::Derp, NodeId::new("peer-2"), "derp", None),
            TransportPath::new(
                TransportPathKind::Funnel,
                NodeId::new("peer-3"),
                "funnel",
                None,
            ),
        ];

        let ranked = node.rank_transport_paths(&policy, &paths);
        assert!(
            ranked
                .iter()
                .any(|entry| entry.path.kind == TransportPathKind::Direct)
        );
        assert!(
            ranked
                .iter()
                .any(|entry| entry.path.kind == TransportPathKind::Derp && !entry.eligible)
        );

        let object_id = test_object_id("meshnode-transport");
        let selection = node.select_transport_paths(&policy, &paths, &object_id, 1, 1);
        assert_eq!(selection.len(), 1);
        assert_eq!(selection[0].kind, TransportPathKind::Direct);
    }

    #[test]
    fn trace_capture_records_session_events() {
        let mut node = test_node_with_trace("node-1");
        let session = test_session("peer-1");
        let peer_id = session.peer_id.clone();

        node.register_session(session, 1000);
        node.remove_session(&peer_id, 2000);

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        assert_eq!(snapshot.events.len(), 2);
        assert!(matches!(snapshot.events[0], TraceEvent::Session(_)));
        assert!(matches!(snapshot.events[1], TraceEvent::Session(_)));
    }

    #[test]
    fn trace_capture_respects_zone_allowlist() {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
        let trace_config = TraceCaptureConfig::new().enabled();
        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1")
                .with_sender_instance_id(42)
                .with_trace_capture_config(trace_config)
                .with_trace_capture_zones([ZoneId::work()]),
            object_store,
            symbol_store,
            quarantine_store,
        );

        let object_id_work = test_object_id("trace-zone-work");
        let object_id_private = test_object_id("trace-zone-private");
        node.announce_object(
            &ZoneId::work(),
            &object_id_work,
            ObjectAdmissionClass::Admitted,
            10,
        );
        node.announce_object(
            &ZoneId::private(),
            &object_id_private,
            ObjectAdmissionClass::Admitted,
            20,
        );

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        assert_eq!(snapshot.events.len(), 1);
    }

    #[test]
    fn trace_capture_records_lease_deltas() {
        let mut node = test_node_with_trace("node-1");
        let lease = HeldLease {
            subject_id: test_object_id("lease-1"),
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 100,
            fencing_token: 1,
        };

        node.update_local_state(test_device_profile("node-1"), HashSet::new(), vec![lease]);

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| matches!(event, TraceEvent::Lease(_)))
        );
    }

    #[test]
    fn meshnode_best_transport_path_returns_none_when_forbidden() {
        let node = test_node("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };

        let paths = vec![TransportPath::new(
            TransportPathKind::Direct,
            NodeId::new("peer-1"),
            "direct",
            None,
        )];

        let best = node.best_transport_path(&policy, &paths);
        assert!(best.is_none());
    }

    // ---- Symbol request lifecycle tests ----

    #[test]
    fn prune_stale_state_clears_transfer_tracking() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([9u8; 8]);
        let object_id = test_object_id("meshnode-prune-state");
        let peer = NodeId::new("peer-1");
        node.update_peer_zones(&peer, zone_set(zone_id.clone()));
        // q92i7 migration: pre-mark the peer as authenticated via the
        // admission controller rather than passing `true` as the ignored
        // `_is_authenticated` arg to `handle_symbol_request`. The OR
        // bypass that let tests rely on the caller-supplied bool is
        // closed; the explicit pre-auth step documents that the peer
        // is intended to be in the authenticated tier for this test.
        node.admission_mut().set_authenticated(&peer, true, 0);

        let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 2,
            first_symbol_at: 0,
        };

        let request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        );

        fcp_async_core::runtime::block_on_sync(async {
            node.symbol_store
                .put_object_meta(meta)
                .await
                .expect("store meta");

            for esi in 0..2u32 {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi,
                        zone_id: zone_id.clone(),
                        source_node: Some(1),
                        stored_at: 0,
                    },
                    data: bytes::Bytes::from(vec![u8::try_from(esi).unwrap_or(0); 64]),
                };
                node.symbol_store
                    .put_symbol(symbol)
                    .await
                    .expect("store symbol");
            }

            let _ = node
                .handle_symbol_request(request, &peer, true, 0)
                .await
                .expect("symbol request");
        })
        .expect("runtime");

        let transfer_key = TransferKey::new(&peer, &object_id);
        assert_eq!(node.symbol_requests.active_transfer_count(), 1);
        assert!(node.sent_symbols.contains_key(&transfer_key));

        let ttl = node.symbol_requests.policy().transfer_state_ttl_ms;
        let pruned = node.prune_stale_state(ttl + 1);

        assert!(pruned > 0);
        assert_eq!(node.symbol_requests.active_transfer_count(), 0);
        assert!(!node.sent_symbols.contains_key(&transfer_key));
    }

    #[test]
    fn symbol_request_rejects_quarantined_object() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([10u8; 8]);
        let object_id = test_object_id("meshnode-quarantined-request");
        let peer = NodeId::new("peer-1");
        node.update_peer_zones(&peer, zone_set(zone_id.clone()));

        node.quarantine_store()
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -5,
            })
            .expect("quarantine");

        let request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let err = fcp_async_core::runtime::block_on_sync(async {
            node.handle_symbol_request(request, &peer, true, 0)
                .await
                .expect_err("quarantined request should fail")
        })
        .expect("runtime");

        assert!(matches!(
            err,
            SymbolRequestError::AdmissionRejected(AdmissionError::ObjectQuarantined { .. })
        ));
    }

    /// q92i7 regression: `handle_symbol_request` previously OR'd its
    /// caller-supplied `is_authenticated` bool with
    /// `self.is_peer_authenticated(peer)`, so a caller passing `true`
    /// could elevate an unsessioned peer past the unauthenticated
    /// tier — and the resulting
    /// `admission.set_authenticated(peer, true, ..)` made the bypass
    /// stick for every subsequent request. The parameter is now
    /// ignored; authentication is decided exclusively by server-side
    /// state (`self.is_peer_authenticated`, which consults
    /// `self.sessions` + `self.admission`). This test proves the bit
    /// is ignored: a peer without any admission or session setup that
    /// passes `true` and sends an unsigned request must be rejected
    /// with `AuthenticationRequired`.
    #[test]
    fn handle_symbol_request_ignores_caller_authenticated_flag() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([42u8; 8]);
        let object_id = test_object_id("q92i7-bypass-regression");
        let peer = NodeId::new("peer-attacker");

        assert!(
            !node.is_peer_authenticated(&peer),
            "precondition: peer must start unauthenticated"
        );
        node.update_peer_zones(&peer, zone_set(zone_id.clone()));

        let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 2,
            first_symbol_at: 0,
        };

        // Unsigned request — the signature fallback path at
        // `verify_symbol_request_signature` cannot rescue the peer.
        let request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let err = fcp_async_core::runtime::block_on_sync(async {
            node.symbol_store
                .put_object_meta(meta)
                .await
                .expect("store meta");
            node.handle_symbol_request(request, &peer, true, 0)
                .await
                .expect_err(
                    "caller-supplied is_authenticated=true MUST be ignored \
                     for an unsessioned, admission-unconfirmed peer",
                )
        })
        .expect("runtime");

        assert!(
            matches!(
                err,
                SymbolRequestError::AdmissionRejected(AdmissionError::AuthenticationRequired)
                    | SymbolRequestError::SignatureInvalid
            ),
            "expected an auth-required / signature-invalid refusal, got {err:?}"
        );
        // Crucially, the bypass also must NOT have persisted via
        // `admission.set_authenticated(peer, true, ..)`. After the
        // rejected call the peer must still look unauthenticated so
        // future requests cannot inherit the forged state.
        assert!(
            !node.is_peer_authenticated(&peer),
            "rejected bypass call must not leave the peer in the authenticated tier"
        );
    }

    #[test]
    fn symbol_request_accepts_signed_unauthenticated_peer() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([11u8; 8]);
        let object_id = test_object_id("meshnode-signed-unauth");
        let peer_id = NodeId::new("peer-1");

        let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 2,
            first_symbol_at: 0,
        };

        let mut request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 5,
            1,
        );

        let signing_key = Ed25519SigningKey::generate();
        request.sign(&signing_key);
        node.register_peer_signing_key(peer_id.clone(), signing_key.verifying_key());
        node.update_peer_zones(&peer_id, zone_set(zone_id.clone()));

        let result = fcp_async_core::runtime::block_on_sync(async {
            node.symbol_store
                .put_object_meta(meta)
                .await
                .expect("store meta");

            for esi in 0..2u32 {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi,
                        zone_id: zone_id.clone(),
                        source_node: Some(1),
                        stored_at: 0,
                    },
                    data: bytes::Bytes::from(vec![u8::try_from(esi).unwrap_or(0); 64]),
                };
                node.symbol_store
                    .put_symbol(symbol)
                    .await
                    .expect("store symbol");
            }

            node.handle_symbol_request(request, &peer_id, false, 0)
                .await
        })
        .expect("runtime");

        assert!(result.is_ok());
    }

    #[test]
    fn symbol_request_rejects_invalid_signature() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([12u8; 8]);
        let object_id = test_object_id("meshnode-bad-signature");
        let peer_id = NodeId::new("peer-1");

        let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 2,
            first_symbol_at: 0,
        };

        let mut request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 5,
            1,
        );

        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        request.sign(&wrong_key);
        node.register_peer_signing_key(peer_id.clone(), signing_key.verifying_key());
        node.update_peer_zones(&peer_id, zone_set(zone_id.clone()));

        let err = fcp_async_core::runtime::block_on_sync(async {
            node.symbol_store
                .put_object_meta(meta)
                .await
                .expect("store meta");

            for esi in 0..2u32 {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi,
                        zone_id: zone_id.clone(),
                        source_node: Some(1),
                        stored_at: 0,
                    },
                    data: bytes::Bytes::from(vec![u8::try_from(esi).unwrap_or(0); 64]),
                };
                node.symbol_store
                    .put_symbol(symbol)
                    .await
                    .expect("store symbol");
            }

            node.handle_symbol_request(request, &peer_id, false, 0)
                .await
        })
        .expect("runtime")
        .expect_err("invalid signature should fail");

        assert!(matches!(err, SymbolRequestError::SignatureInvalid));
    }

    #[test]
    fn symbol_request_rejects_peer_with_empty_zone_state() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([13u8; 8]);
        let object_id = test_object_id("meshnode-empty-zone-state");
        let peer_id = NodeId::new("peer-empty-zone");

        let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti,
            source_symbols: 2,
            first_symbol_at: 0,
        };

        let mut request = SymbolRequest::new(
            test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        );

        let signing_key = Ed25519SigningKey::generate();
        request.sign(&signing_key);
        node.register_peer_signing_key(peer_id.clone(), signing_key.verifying_key());

        let err = fcp_async_core::runtime::block_on_sync(async {
            node.symbol_store
                .put_object_meta(meta)
                .await
                .expect("store meta");

            for esi in 0..2u32 {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi,
                        zone_id: zone_id.clone(),
                        source_node: Some(1),
                        stored_at: 0,
                    },
                    data: bytes::Bytes::from(vec![u8::try_from(esi).unwrap_or(0); 64]),
                };
                node.symbol_store
                    .put_symbol(symbol)
                    .await
                    .expect("store symbol");
            }

            node.handle_symbol_request(request, &peer_id, false, 0)
                .await
                .expect_err("empty peer-zone state must fail closed")
        })
        .expect("runtime");

        assert!(matches!(err, SymbolRequestError::UnauthorizedZone { .. }));
    }

    // ---- MeshNodeConfig builder tests ----

    #[test]
    fn config_new_sets_node_id() {
        let config = MeshNodeConfig::new("test-node");
        assert_eq!(config.node_id, "test-node");
    }

    #[test]
    fn config_builder_methods_chain() {
        let policy = AdmissionPolicy::default();
        let gossip_config = GossipConfig::default();
        let sym_policy = SymbolRequestPolicy::default();
        let raptorq_config = RaptorQConfig::default();

        let config = MeshNodeConfig::new("node-1")
            .with_admission_policy(policy)
            .with_gossip_config(gossip_config)
            .with_symbol_request_policy(sym_policy)
            .with_raptorq_config(raptorq_config)
            .with_sender_instance_id(999);

        assert_eq!(config.node_id, "node-1");
        assert_eq!(config.sender_instance_id, 999);
    }

    // ---- Node identity tests ----

    #[test]
    fn local_node_id_matches_config() {
        let node = test_node("my-node");
        assert_eq!(node.local_node_id().as_str(), "my-node");
    }

    #[test]
    fn local_tailscale_id_matches_config() {
        let node = test_node("ts-node");
        assert_eq!(node.local_tailscale_id().as_str(), "ts-node");
    }

    // ---- Peer management tests ----

    #[test]
    fn initial_peer_count_is_zero() {
        let node = test_node("node-1");
        assert_eq!(node.peer_count(), 0);
    }

    #[test]
    fn update_peer_state_increments_count() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");

        node.update_peer_state(NodeId::new("peer-1"), profile, HashSet::new(), vec![], 1000);
        assert_eq!(node.peer_count(), 1);
    }

    #[test]
    fn update_same_peer_does_not_duplicate() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");

        node.update_peer_state(
            NodeId::new("peer-1"),
            profile.clone(),
            HashSet::new(),
            vec![],
            1000,
        );
        node.update_peer_state(NodeId::new("peer-1"), profile, HashSet::new(), vec![], 2000);
        assert_eq!(node.peer_count(), 1);
    }

    #[test]
    fn multiple_peers_tracked_independently() {
        let mut node = test_node("node-1");

        for i in 0..3 {
            let name = format!("peer-{i}");
            let profile = test_device_profile(&name);
            node.update_peer_state(NodeId::new(&name), profile, HashSet::new(), vec![], 1000);
        }
        assert_eq!(node.peer_count(), 3);
    }

    #[test]
    fn remove_peer_decrements_count() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");

        node.update_peer_state(NodeId::new("peer-1"), profile, HashSet::new(), vec![], 1000);
        assert_eq!(node.peer_count(), 1);

        node.remove_peer(&NodeId::new("peer-1"));
        assert_eq!(node.peer_count(), 0);
    }

    #[test]
    fn remove_nonexistent_peer_is_noop() {
        let mut node = test_node("node-1");
        node.remove_peer(&NodeId::new("ghost"));
        assert_eq!(node.peer_count(), 0);
    }

    #[test]
    fn remove_nonexistent_peer_does_not_allocate_admission_entry() {
        // br-llfi4: prior to the clear_authenticated fix,
        // remove_peer for an untracked peer hit the no-session
        // branch and called set_authenticated(_, false, _), which
        // allocated a fresh admission PeerUsage entry just to flip
        // is_authenticated. Repeating that call could fill
        // policy.max_tracked_peers and start rejecting real peers
        // with TrackingTableFull. The fix routes through
        // clear_authenticated which uses get_existing_usage and
        // returns without allocating when the peer is unknown.
        let mut node = test_node("node-1");
        let admission = node.admission_mut();
        // Establish baseline: empty admission table.
        assert!(admission.get_usage(&NodeId::new("ghost")).is_none());

        node.remove_peer(&NodeId::new("ghost"));

        // After removal of an untracked peer, the admission table
        // must still be empty — no ghost PeerUsage entry leaked.
        assert!(
            node.admission_mut()
                .get_usage(&NodeId::new("ghost"))
                .is_none(),
            "remove_peer must not allocate an admission entry for an untracked peer"
        );
    }

    #[test]
    fn remove_session_for_untracked_peer_does_not_allocate_admission_entry() {
        // br-llfi4: same no-allocation invariant for
        // MeshNode::remove_session — closing a non-existent
        // session must not allocate an admission entry.
        let mut node = test_node("node-1");
        let ghost = NodeId::new("ghost-session");
        assert!(node.admission_mut().get_usage(&ghost).is_none());

        node.remove_session(&ghost, 12_345);

        assert!(
            node.admission_mut().get_usage(&ghost).is_none(),
            "remove_session must not allocate an admission entry for an unknown peer"
        );
    }

    // ---- Local state tests ----

    #[test]
    fn update_local_state_sets_profile() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("node-1");

        node.update_local_state(profile, HashSet::new(), vec![]);
        assert!(node.local_profile.is_some());
    }

    // ---- Session management tests ----

    #[test]
    fn no_session_means_not_authenticated() {
        let node = test_node("node-1");
        assert!(!node.is_peer_authenticated(&NodeId::new("peer-1")));
    }

    #[test]
    fn register_session_authenticates_peer() {
        let mut node = test_node("node-1");
        let session = test_session("peer-1");

        node.register_session(session, 1000);
        assert!(node.is_peer_authenticated(&NodeId::new("peer-1")));
    }

    #[test]
    fn remove_session_deauthenticates_peer() {
        let mut node = test_node("node-1");
        let session = test_session("peer-1");

        node.register_session(session, 1000);
        assert!(node.is_peer_authenticated(&NodeId::new("peer-1")));

        node.remove_session(&NodeId::new("peer-1"), 2000);
        assert!(!node.is_peer_authenticated(&NodeId::new("peer-1")));
    }

    // ---- Gossip delegation tests ----

    #[test]
    fn announce_object_increments_metric() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x11; 32]);

        let added =
            node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1000);
        assert!(added);
        assert_eq!(node.metrics().gossip_announcements, 1);
    }

    #[test]
    fn observe_connector_state_root_announces_validated_root_for_gossip() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let connector_id = ConnectorId::from_static("fcp:test:1.0.0");
        let object_id_key = ObjectIdKey::from_bytes([0x42; 32]);
        let state_store = FcpStoreConnectorStateStore::new(
            Arc::clone(node.object_store()),
            object_id_key,
            connector_id.clone(),
            zone_id.clone(),
        );

        let schema = FcpStoreConnectorStateStore::root_schema_id();
        let header = ObjectHeader {
            encryption_kind: Default::default(),
            schema: schema.clone(),
            zone_id: zone_id.clone(),
            created_at: 42,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        };
        let root = ConnectorStateRoot {
            header: header.clone(),
            connector_id,
            instance_id: None,
            zone_id: zone_id.clone(),
            model: ConnectorStateModel::SingletonWriter,
            head: None,
            state_schema_version: 1,
        };
        let body = CanonicalSerializer::serialize(&root, &schema).expect("serialize root");
        let root_object_id =
            StoredObject::derive_id(&header, &body, &object_id_key).expect("derive root id");
        let stored = StoredObject {
            object_id: root_object_id,
            header,
            body,
            storage: StorageMeta {
                retention: EvictionPolicy::Pinned,
            },
        };

        fcp_async_core::runtime::block_on_sync(async {
            node.object_store().put(stored).await.expect("put root");
            let change = node
                .observe_connector_state_root(&state_store, root_object_id, 42_000)
                .await
                .expect("observe root");
            assert_eq!(change.kind, ConnectorStateChangeKind::RootUpdated);
            assert_eq!(change.object_id, Some(root_object_id));
            assert_eq!(change.zone_id, zone_id);
            assert_eq!(change.seq, None);
        })
        .expect("runtime");

        let peer = NodeId::new("peer-1");
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            Vec::new(),
            42_000,
        );
        node.update_peer_zones(&peer, zone_set(zone_id.clone()));

        let request = GossipRequest::for_objects(
            TailscaleNodeId::new("peer-1"),
            zone_id,
            vec![root_object_id],
            42,
        );
        let response = node
            .handle_gossip_request(request, 42)
            .expect("gossip request");
        assert_eq!(response.have_objects, vec![root_object_id]);
        assert_eq!(node.metrics().gossip_announcements, 1);
    }

    #[test]
    fn publish_signed_lease_object_stores_and_announces_gossip_object() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let subject_object_id = test_object_id("connector-state");
        let object_id_key = ObjectIdKey::from_bytes([0x42; 32]);
        let signer_a = Ed25519SigningKey::generate();
        let signer_b = Ed25519SigningKey::generate();
        let mut lease = test_core_lease(&zone_id, subject_object_id);
        sign_lease_quorum(&mut lease, &[("node-1", &signer_a), ("node-2", &signer_b)]);
        register_lease_signer_keys(&mut node, &[("node-1", &signer_a), ("node-2", &signer_b)]);

        let lease_object_id = fcp_async_core::runtime::block_on_sync(async {
            let lease_object_id = node
                .publish_signed_lease_object(&lease, &object_id_key, 50_000)
                .await
                .expect("publish lease");
            let stored_lease = node
                .object_store()
                .get(&lease_object_id)
                .await
                .expect("stored lease");
            assert_eq!(stored_lease.header.schema, lease.header.schema);
            assert_eq!(
                stored_lease.storage.retention,
                EvictionPolicy::Lease {
                    expires_at: lease.exp,
                }
            );
            let decoded: fcp_prelude::Lease =
                CanonicalSerializer::deserialize(&stored_lease.body, &stored_lease.header.schema)
                    .expect("decode lease");
            assert_eq!(decoded.holder, lease.holder);
            assert_eq!(decoded.lease_seq, lease.lease_seq);
            assert_eq!(decoded.subject_object_id, subject_object_id);
            assert_eq!(
                decoded.quorum_signatures.len(),
                DEFAULT_LEASE_PUBLICATION_REQUIRED_QUORUM_SIGNATURES
            );
            lease_object_id
        })
        .expect("runtime");

        let peer = NodeId::new("peer-1");
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            Vec::new(),
            50_000,
        );
        node.update_peer_zones(&peer, zone_set(zone_id.clone()));

        let request = GossipRequest::for_objects(
            TailscaleNodeId::new("peer-1"),
            zone_id,
            vec![lease_object_id],
            50,
        );
        let response = node
            .handle_gossip_request(request, 50)
            .expect("gossip request");
        assert_eq!(response.have_objects, vec![lease_object_id]);
        assert_eq!(node.metrics().gossip_announcements, 1);
    }

    #[test]
    fn publish_signed_lease_object_rejects_invalid_quorum_signature_before_gossip() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let subject_object_id = test_object_id("connector-state");
        let object_id_key = ObjectIdKey::from_bytes([0x42; 32]);
        let signer_a = Ed25519SigningKey::generate();
        let signer_b = Ed25519SigningKey::generate();
        let attacker = Ed25519SigningKey::generate();
        let mut lease = test_core_lease(&zone_id, subject_object_id);
        sign_lease_quorum(&mut lease, &[("node-1", &signer_a), ("node-2", &attacker)]);
        register_lease_signer_keys(&mut node, &[("node-1", &signer_a), ("node-2", &signer_b)]);

        let err = fcp_async_core::runtime::block_on_sync(async {
            node.publish_signed_lease_object(&lease, &object_id_key, 50_000)
                .await
                .expect_err("forged quorum signature must not publish")
        })
        .expect("runtime");

        assert!(matches!(
            err,
            MeshNodeError::PeerSignatureInvalid {
                peer,
                message_kind: "lease quorum",
            } if peer == "node-2"
        ));
        assert_eq!(node.metrics().gossip_announcements, 0);
    }

    #[test]
    fn publish_signed_lease_object_rejects_insufficient_quorum_before_gossip() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let subject_object_id = test_object_id("connector-state");
        let object_id_key = ObjectIdKey::from_bytes([0x42; 32]);
        let mut lease = test_core_lease(&zone_id, subject_object_id);
        lease.quorum_signatures = fcp_core::SignatureSet::new();

        let err = fcp_async_core::runtime::block_on_sync(async {
            node.publish_signed_lease_object(&lease, &object_id_key, 50_000)
                .await
                .expect_err("quorum-deficient lease must not publish")
        })
        .expect("runtime");

        assert!(matches!(
            err,
            MeshNodeError::LeaseValidation(CoreLeaseValidationError::InsufficientQuorum {
                required: DEFAULT_LEASE_PUBLICATION_REQUIRED_QUORUM_SIGNATURES,
                got: 0,
            })
        ));
        assert_eq!(node.metrics().gossip_announcements, 0);
    }

    #[test]
    fn apply_gossip_fetch_payload_rejects_invalid_lease_quorum_signature_before_admission() {
        let zone_id = ZoneId::work();
        let subject_object_id = test_object_id("connector-state-forged-lease");
        let object_id_key = ObjectIdKey::from_bytes([0x72; 32]);
        let signer_a = Ed25519SigningKey::generate();
        let signer_b = Ed25519SigningKey::generate();
        let attacker = Ed25519SigningKey::generate();
        let mut lease = test_core_lease(&zone_id, subject_object_id);
        sign_lease_quorum(&mut lease, &[("node-1", &signer_a), ("node-2", &attacker)]);
        let (lease_object_id, stored) = stored_lease_object(&lease, &object_id_key);

        let mut receiver = test_node("node-receiver");
        let issuer_peer = NodeId::new("node-issuer");
        receiver.update_peer_state(
            issuer_peer.clone(),
            test_device_profile("node-issuer"),
            HashSet::new(),
            Vec::new(),
            50_000,
        );
        receiver.update_peer_zones(&issuer_peer, zone_set(zone_id.clone()));
        register_lease_signer_keys(
            &mut receiver,
            &[("node-1", &signer_a), ("node-2", &signer_b)],
        );

        let plan = GossipFetchPlan {
            peer: TailscaleNodeId::new("node-issuer"),
            zone_id,
            object_ids: vec![lease_object_id],
            symbols: Vec::new(),
        };

        let err = fcp_async_core::runtime::block_on_sync(async {
            let err = receiver
                .apply_gossip_fetch_payload(&plan, vec![stored], Vec::new(), 50_001)
                .await
                .expect_err("forged fetched lease must not be admitted");
            assert!(
                receiver.object_store().get(&lease_object_id).await.is_err(),
                "forged lease object must not be stored before signature rejection"
            );
            err
        })
        .expect("runtime");

        assert!(matches!(
            err,
            MeshNodeError::PeerSignatureInvalid {
                peer,
                message_kind: "lease quorum",
            } if peer == "node-2"
        ));
    }

    fn test_node_with_verifier(name: &str, verifier: fcp_store::KeyedObjectIdVerifier) -> MeshNode {
        let object_store = Arc::new(
            MemoryObjectStore::new(MemoryObjectStoreConfig::default())
                .with_verifier(verifier.into_arc()),
        );
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
        MeshNode::new(
            MeshNodeConfig::new(name).with_sender_instance_id(42),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    fn enroll_fetch_peer(node: &mut MeshNode, peer_name: &str, zone_id: &ZoneId) -> NodeId {
        let peer = NodeId::new(peer_name);
        node.update_peer_state(
            peer.clone(),
            test_device_profile(peer_name),
            HashSet::new(),
            Vec::new(),
            50_000,
        );
        node.update_peer_zones(&peer, zone_set(zone_id.clone()));
        peer
    }

    #[test]
    fn apply_gossip_fetch_payload_with_verifier_store_enforces_content_ids() {
        // bead mesh-node-content-id-verifier-wiring-h3xmd: a live-network
        // node's object store must carry a KeyedObjectIdVerifier so a peer
        // cannot bind attacker-controlled bytes to a requested object id.
        let zone_id = ZoneId::work();
        // Same key test_stored_object derives ids under.
        let object_id_key = ObjectIdKey::from_bytes([0x99; 32]);
        let mut verifier = fcp_store::KeyedObjectIdVerifier::default();
        verifier.insert(zone_id.clone(), object_id_key);
        let mut node = test_node_with_verifier("node-verifier", verifier);
        assert!(node.object_store().has_object_id_verifier());
        enroll_fetch_peer(&mut node, "node-issuer", &zone_id);

        let genuine = test_stored_object(&zone_id, "verifier-genuine", b"payload");
        let genuine_id = genuine.object_id;
        let mut forged = test_stored_object(&zone_id, "verifier-forged", b"original");
        let forged_id = forged.object_id;
        forged.body = b"attacker-swapped-bytes".to_vec();

        fcp_async_core::runtime::block_on_sync(async {
            let plan = GossipFetchPlan {
                peer: TailscaleNodeId::new("node-issuer"),
                zone_id: zone_id.clone(),
                object_ids: vec![genuine_id],
                symbols: Vec::new(),
            };
            let outcome = node
                .apply_gossip_fetch_payload(&plan, vec![genuine], Vec::new(), 50_001)
                .await
                .expect("genuine content-addressed object must be admitted");
            assert_eq!(outcome.objects_applied, vec![genuine_id]);

            let plan = GossipFetchPlan {
                peer: TailscaleNodeId::new("node-issuer"),
                zone_id: zone_id.clone(),
                object_ids: vec![forged_id],
                symbols: Vec::new(),
            };
            let err = node
                .apply_gossip_fetch_payload(&plan, vec![forged], Vec::new(), 50_002)
                .await
                .expect_err("forged (id, bytes) binding must be refused");
            assert!(matches!(
                err,
                MeshNodeError::ObjectStore(fcp_store::ObjectStoreError::ContentIdMismatch { .. })
            ));
            assert!(
                node.object_store().get(&forged_id).await.is_err(),
                "forged object must not reach the store"
            );
        })
        .expect("runtime");
    }

    #[test]
    fn apply_gossip_fetch_payload_verifier_fails_closed_on_unknown_zone() {
        // The verifier must fail closed (VerifierKeyMissing) for zones it has
        // no ObjectIdKey for, instead of admitting unverifiable bytes.
        let zone_id = ZoneId::work();
        let other_zone: ZoneId = "z:private".parse().expect("zone id");
        let mut verifier = fcp_store::KeyedObjectIdVerifier::default();
        verifier.insert(other_zone, ObjectIdKey::from_bytes([0x99; 32]));
        let mut node = test_node_with_verifier("node-verifier-closed", verifier);
        enroll_fetch_peer(&mut node, "node-issuer", &zone_id);

        let object = test_stored_object(&zone_id, "verifier-unknown-zone", b"payload");
        let object_id = object.object_id;

        fcp_async_core::runtime::block_on_sync(async {
            let plan = GossipFetchPlan {
                peer: TailscaleNodeId::new("node-issuer"),
                zone_id: zone_id.clone(),
                object_ids: vec![object_id],
                symbols: Vec::new(),
            };
            let err = node
                .apply_gossip_fetch_payload(&plan, vec![object], Vec::new(), 50_001)
                .await
                .expect_err("objects for zones without a verifier key must be refused");
            assert!(matches!(
                err,
                MeshNodeError::ObjectStore(fcp_store::ObjectStoreError::VerifierKeyMissing { .. })
            ));
            assert!(node.object_store().get(&object_id).await.is_err());
        })
        .expect("runtime");
    }

    #[test]
    fn issued_signed_lease_gossips_fetches_and_validates_authority_object() {
        let zone_id = ZoneId::work();
        let subject_object_id = test_object_id("connector-state-lease-authority");
        let object_id_key = ObjectIdKey::from_bytes([0x9A; 32]);
        let eligible_nodes = vec![
            TailscaleNodeId::new("node-a"),
            TailscaleNodeId::new("node-b"),
            TailscaleNodeId::new("node-c"),
        ];
        let holder = fcp_prelude::select_coordinator(&zone_id, &subject_object_id, &eligible_nodes)
            .expect("three eligible nodes should produce an HRW holder");
        let mut coordinator = LeaseCoordinator::with_defaults();
        let request = SignedLeaseIssueRequest {
            params: fcp_core::LeaseParams {
                schema: fcp_cbor::SchemaId::new(
                    "fcp.lease",
                    "lease",
                    semver::Version::new(1, 0, 0),
                ),
                zone_id: zone_id.clone(),
                holder: holder.clone(),
                lease_seq: 0,
                ttl_secs: 300,
                subject_object_id,
                provenance: Provenance::new(zone_id.clone()),
                purpose: fcp_prelude::LeasePurpose::ConnectorStateWrite,
                quorum_signatures: test_signature_set(&["node-a", "node-b"]),
            },
            existing_leases: Vec::new(),
            eligible_nodes,
            required_signatures: DEFAULT_LEASE_PUBLICATION_REQUIRED_QUORUM_SIGNATURES,
            now_secs: 1_000,
        };
        let (outcome, timeline) = coordinator.issue_signed_lease(request);
        assert!(
            matches!(outcome, SignedLeaseIssueOutcome::Granted { .. }),
            "HRW-selected holder should issue a durable signed lease: {outcome:?}"
        );
        let SignedLeaseIssueOutcome::Granted { lease } = outcome else {
            return;
        };
        assert_eq!(lease.holder, holder);
        assert_eq!(lease.lease_seq, 1);
        assert_eq!(
            lease.quorum_signatures.len(),
            DEFAULT_LEASE_PUBLICATION_REQUIRED_QUORUM_SIGNATURES
        );
        assert!(
            timeline
                .iter()
                .any(|event| event.operation == "lease.acquired")
        );
        let signer_a = Ed25519SigningKey::generate();
        let signer_b = Ed25519SigningKey::generate();
        let mut lease = *lease;
        sign_lease_quorum(&mut lease, &[("node-a", &signer_a), ("node-b", &signer_b)]);

        let mut issuer = test_node(holder.as_str());
        register_lease_signer_keys(&mut issuer, &[("node-a", &signer_a), ("node-b", &signer_b)]);
        let mut receiver = test_node("node-receiver");
        register_lease_signer_keys(
            &mut receiver,
            &[("node-a", &signer_a), ("node-b", &signer_b)],
        );
        let receiver_peer = NodeId::new("node-receiver");
        let issuer_peer = NodeId::new(holder.as_str());
        issuer.update_peer_state(
            receiver_peer.clone(),
            test_device_profile("node-receiver"),
            HashSet::new(),
            Vec::new(),
            50_000,
        );
        issuer.update_peer_zones(&receiver_peer, zone_set(zone_id.clone()));
        receiver.update_peer_state(
            issuer_peer.clone(),
            test_device_profile(holder.as_str()),
            HashSet::new(),
            Vec::new(),
            50_000,
        );
        receiver.update_peer_zones(&issuer_peer, zone_set(zone_id.clone()));

        fcp_async_core::runtime::block_on_sync(async {
            let lease_object_id = issuer
                .publish_signed_lease_object(&lease, &object_id_key, 50_000)
                .await
                .expect("publisher stores and announces issued lease");

            let fetch_reply = issuer
                .prepare_gossip_fetch_reply(
                    GossipRequest::for_objects(
                        TailscaleNodeId::new("node-receiver"),
                        zone_id.clone(),
                        vec![lease_object_id],
                        50,
                    ),
                    50,
                )
                .await
                .expect("issuer prepares lease fetch payload");
            assert_eq!(fetch_reply.response.have_objects, vec![lease_object_id]);
            assert_eq!(fetch_reply.payload.objects.len(), 1);

            let plan = receiver
                .handle_gossip_response(fetch_reply.response, 50)
                .expect("receiver verifies gossip response")
                .expect("receiver should fetch missing lease object");
            assert_eq!(plan.object_ids, vec![lease_object_id]);
            let apply = receiver
                .apply_gossip_fetch_payload(&plan, fetch_reply.payload.objects, Vec::new(), 50_001)
                .await
                .expect("receiver applies fetched lease object");
            assert_eq!(apply.objects_applied, vec![lease_object_id]);

            let stored_lease = receiver
                .object_store()
                .get(&lease_object_id)
                .await
                .expect("receiver stored fetched lease object");
            let decoded: fcp_prelude::Lease =
                CanonicalSerializer::deserialize(&stored_lease.body, &stored_lease.header.schema)
                    .expect("decode fetched lease");
            assert_eq!(decoded.holder, holder);
            assert_eq!(decoded.lease_seq, 1);
            assert_eq!(decoded.subject_object_id, subject_object_id);
            coordinator
                .validate_signed_lease(
                    &decoded,
                    &subject_object_id,
                    &zone_id,
                    fcp_prelude::LeasePurpose::ConnectorStateWrite,
                    1,
                    1_001,
                    DEFAULT_LEASE_PUBLICATION_REQUIRED_QUORUM_SIGNATURES,
                )
                .expect("fetched lease should validate quorum and fencing authority");
            assert_eq!(receiver.metrics().gossip_announcements, 1);
        })
        .expect("runtime");
    }

    #[test]
    fn announce_symbol_increments_metric() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x22; 32]);

        let added = node.announce_symbol(
            &zone_id,
            &object_id,
            0,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        assert!(added);
        assert_eq!(node.metrics().gossip_announcements, 1);
    }

    #[test]
    fn quarantined_object_not_announced() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x33; 32]);

        let added = node.announce_object(
            &zone_id,
            &object_id,
            ObjectAdmissionClass::Quarantined,
            1000,
        );
        // Quarantined objects must not be gossiped (NORMATIVE)
        assert!(!added);
        assert_eq!(node.metrics().gossip_announcements, 0);
    }

    #[test]
    fn quarantine_store_overrides_admission() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x34; 32]);

        node.quarantine_store()
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -10,
            })
            .expect("quarantine");

        let added =
            node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1000);
        assert!(!added);
        assert_eq!(node.metrics().gossip_announcements, 0);
    }

    #[test]
    fn quarantine_store_overrides_symbol_admission() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x35; 32]);

        node.quarantine_store()
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -10,
            })
            .expect("quarantine");

        let added = node.announce_symbol(
            &zone_id,
            &object_id,
            0,
            ObjectAdmissionClass::Admitted,
            1000,
        );
        assert!(!added);
        assert_eq!(node.metrics().gossip_announcements, 0);
    }

    // ---- Decode status / ack delegation tests ----

    #[test]
    fn handle_decode_status_delegates_to_handler() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        let object_id = ObjectId::from_bytes([0x44; 32]);

        let mut status = DecodeStatus {
            header: test_object_header(),
            object_id,
            zone_id: ZoneId::work(),
            zone_key_id: ZoneKeyId::from_bytes([0x55; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-1"),
            request_nonce: 101,
            received_unique: 10,
            needed: 0,
            complete: true,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        status.sign(&signing_key);

        node.handle_decode_status(&peer, &status, 1000)
            .expect("status should verify");
    }

    #[test]
    fn handle_symbol_ack_increments_ack_metric() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        let object_id = ObjectId::from_bytes([0x66; 32]);

        let mut ack = SymbolAck::new(
            test_object_header(),
            object_id,
            ZoneId::work(),
            ZoneKeyId::from_bytes([0x77; 8]),
            1,
            TailscaleNodeId::new("node-1"),
            202,
            SymbolAckReason::Complete,
            5,
        );
        ack.sign(&signing_key);

        node.handle_symbol_ack(&peer, &ack, 1000)
            .expect("ack should verify");
        assert_eq!(node.metrics().symbol_requests.acks_received, 1);
    }

    #[test]
    fn handle_summary_requires_valid_signature() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        // Post-opoux: the zone gate requires the peer to be enrolled
        // with the claimed zone before ANY signed summary is accepted.
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let mut peer_gossip = MeshGossip::with_defaults(TailscaleNodeId::new("peer-1"));
        peer_gossip.announce_object(
            &ZoneId::work(),
            &test_object_id("summary-valid"),
            ObjectAdmissionClass::Admitted,
            1_000,
        );
        let template = peer_gossip
            .create_summary(&ZoneId::work(), EpochId::new("epoch-1"))
            .expect("summary should exist");
        let summary = GossipSummary {
            signature: Some(fcp_core::NodeSignature::new(
                fcp_core::NodeId::new(peer.as_str()),
                signing_key.sign(&template.signing_bytes()).to_bytes(),
                1_000,
            )),
            ..template
        };

        let _ = node
            .handle_gossip_message(GossipMessage::Summary(summary), 1_000)
            .expect("summary should verify");
        assert_eq!(node.metrics().gossip_updates, 1);
    }

    #[test]
    fn handle_summary_rejects_unknown_peer_without_peer_state() {
        // opoux regression: before the fix, `verify_summary_signature`
        // wrapped the zone check in `if let Some(state) = self.peers.get(..)`
        // so a peer whose signing key was registered but whose
        // enrollment hadn't completed (no entry in self.peers) would
        // silently bypass the zone gate. The attacker's signature is
        // valid; their bootstrap just hadn't happened. A zone claim
        // of any value would pass.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-unknown");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        // Deliberately skip update_peer_state — this is the bypass the
        // fix closes. Pre-fix, the summary below would verify and be
        // accepted.

        let template = GossipSummary {
            from: TailscaleNodeId::new("peer-unknown"),
            zone_id: ZoneId::work(),
            epoch_id: EpochId::new("epoch-1"),
            object_filter_digest: [0x11; 32],
            symbol_filter_digest: [0x22; 32],
            object_count: 0,
            symbol_count: 0,
            iblt: Vec::new(),
            timestamp: 1_000,
            signature: None,
        };
        let signature = fcp_core::NodeSignature::new(
            fcp_core::NodeId::new(peer.as_str()),
            signing_key.sign(&template.signing_bytes()).to_bytes(),
            1_000,
        );
        let summary = GossipSummary {
            signature: Some(signature),
            ..template
        };

        let err = node
            .handle_gossip_message(GossipMessage::Summary(summary), 1_000)
            .expect_err("unknown peer must be rejected");
        match err {
            MeshNodeError::UnknownPeer {
                peer: reported,
                message_kind,
            } => {
                assert_eq!(reported, "peer-unknown");
                assert_eq!(message_kind, "gossip summary");
            }
            other => panic!("expected UnknownPeer, got {other:?}"),
        }
        assert_eq!(
            node.metrics().gossip_updates,
            0,
            "gossip update must not be recorded for a rejected summary"
        );
    }

    #[test]
    fn handle_revocation_push_rejects_unknown_peer_without_peer_state() {
        // Symmetric opoux regression on the revocation-push path. A
        // peer with a valid signing key but no enrolled zone state
        // could previously push revocations into any zone.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-unknown");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-unknown"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xCD; 32])],
            7,
            1_000,
        );
        push.signature = Some(fcp_core::NodeSignature::new(
            fcp_core::NodeId::new(peer.as_str()),
            signing_key.sign(&push.signing_bytes()).to_bytes(),
            1_000,
        ));

        let err = node
            .handle_revocation_push(push, 1_000)
            .expect_err("unknown peer must be rejected");
        match err {
            MeshNodeError::UnknownPeer {
                peer: reported,
                message_kind,
            } => {
                assert_eq!(reported, "peer-unknown");
                assert_eq!(message_kind, "revocation push");
            }
            other => panic!("expected UnknownPeer, got {other:?}"),
        }
    }

    #[test]
    fn handle_summary_rejects_peer_with_empty_zone_state() {
        // opoux regression variant: before the fix, the zone check was
        // `if !state.zones.is_empty() && !state.zones.contains(..)` so
        // a peer enrolled with an empty zone set would ALSO bypass the
        // gate. Now an enrolled peer with zones = {} is treated as
        // "authorized for nothing" and must be rejected.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-empty");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-empty"),
            HashSet::new(),
            vec![],
            1_000,
        );
        // Deliberately do NOT call update_peer_zones — zone set stays empty.

        let template = GossipSummary {
            from: TailscaleNodeId::new("peer-empty"),
            zone_id: ZoneId::work(),
            epoch_id: EpochId::new("epoch-1"),
            object_filter_digest: [0x11; 32],
            symbol_filter_digest: [0x22; 32],
            object_count: 0,
            symbol_count: 0,
            iblt: Vec::new(),
            timestamp: 1_000,
            signature: None,
        };
        let signature = fcp_core::NodeSignature::new(
            fcp_core::NodeId::new(peer.as_str()),
            signing_key.sign(&template.signing_bytes()).to_bytes(),
            1_000,
        );
        let summary = GossipSummary {
            signature: Some(signature),
            ..template
        };

        let err = node
            .handle_gossip_message(GossipMessage::Summary(summary), 1_000)
            .expect_err("peer with empty zones must be rejected");
        match err {
            MeshNodeError::UnauthorizedZone {
                peer: reported,
                zone_id,
            } => {
                assert_eq!(reported, "peer-empty");
                assert_eq!(zone_id, ZoneId::work().to_string());
            }
            other => panic!("expected UnauthorizedZone, got {other:?}"),
        }
    }

    #[test]
    fn handle_summary_rejects_peer_claiming_unauthorized_zone() {
        // Positive-coverage test for the already-working branch: a
        // peer enrolled for z:work must not be able to ship a summary
        // tagged z:private.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-scoped");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-scoped"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let unauthorized_zone = ZoneId::private();
        let template = GossipSummary {
            from: TailscaleNodeId::new("peer-scoped"),
            zone_id: unauthorized_zone.clone(),
            epoch_id: EpochId::new("epoch-1"),
            object_filter_digest: [0x11; 32],
            symbol_filter_digest: [0x22; 32],
            object_count: 0,
            symbol_count: 0,
            iblt: Vec::new(),
            timestamp: 1_000,
            signature: None,
        };
        let signature = fcp_core::NodeSignature::new(
            fcp_core::NodeId::new(peer.as_str()),
            signing_key.sign(&template.signing_bytes()).to_bytes(),
            1_000,
        );
        let summary = GossipSummary {
            signature: Some(signature),
            ..template
        };

        let err = node
            .handle_gossip_message(GossipMessage::Summary(summary), 1_000)
            .expect_err("summary must be rejected for unauthorized zone");
        match err {
            MeshNodeError::UnauthorizedZone {
                peer: reported,
                zone_id,
            } => {
                assert_eq!(reported, "peer-scoped");
                assert_eq!(zone_id, unauthorized_zone.to_string());
            }
            other => panic!("expected UnauthorizedZone, got {other:?}"),
        }
    }

    #[test]
    fn handle_summary_rejects_missing_signature() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer, signing_key.verifying_key());

        let summary = GossipSummary {
            from: TailscaleNodeId::new("peer-1"),
            zone_id: ZoneId::work(),
            epoch_id: EpochId::new("epoch-1"),
            object_filter_digest: [0x11; 32],
            symbol_filter_digest: [0x22; 32],
            object_count: 3,
            symbol_count: 7,
            iblt: b"[]".to_vec(),
            timestamp: 1_000,
            signature: None,
        };

        let err = node
            .handle_gossip_message(GossipMessage::Summary(summary), 1_000)
            .expect_err("unsigned summary must be rejected");
        assert!(matches!(
            err,
            MeshNodeError::PeerSignatureInvalid {
                message_kind: "gossip summary",
                ..
            }
        ));
    }

    #[test]
    fn handle_summary_rejects_signature_node_mismatch() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let template = GossipSummary {
            from: TailscaleNodeId::new("peer-1"),
            zone_id: ZoneId::work(),
            epoch_id: EpochId::new("epoch-1"),
            object_filter_digest: [0x11; 32],
            symbol_filter_digest: [0x22; 32],
            object_count: 3,
            symbol_count: 7,
            iblt: b"[]".to_vec(),
            timestamp: 1_000,
            signature: None,
        };
        let summary = GossipSummary {
            signature: Some(fcp_core::NodeSignature::new(
                fcp_core::NodeId::new("peer-2"),
                signing_key.sign(&template.signing_bytes()).to_bytes(),
                1_000,
            )),
            ..template
        };

        let err = node
            .handle_gossip_message(GossipMessage::Summary(summary), 1_000)
            .expect_err("summary signature bound to a different node must be rejected");
        assert!(matches!(
            err,
            MeshNodeError::SignatureNodeMismatch {
                message_kind: "gossip summary",
                ..
            }
        ));
        assert_eq!(
            node.metrics().gossip_updates,
            0,
            "node-mismatched summary must not record a gossip update"
        );
    }

    #[test]
    fn handle_summary_rejects_older_signed_summary_when_newer_peer_state_exists() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let signed_summary = |timestamp: u64, object_names: &[&str]| {
            let mut peer_gossip = MeshGossip::with_defaults(TailscaleNodeId::new("peer-1"));
            for object_name in object_names {
                peer_gossip.announce_object(
                    &ZoneId::work(),
                    &test_object_id(object_name),
                    ObjectAdmissionClass::Admitted,
                    timestamp,
                );
            }
            let template = peer_gossip
                .create_summary(&ZoneId::work(), EpochId::new("epoch-1"))
                .expect("summary should exist");
            GossipSummary {
                signature: Some(fcp_core::NodeSignature::new(
                    fcp_core::NodeId::new(peer.as_str()),
                    signing_key.sign(&template.signing_bytes()).to_bytes(),
                    timestamp,
                )),
                ..template
            }
        };

        let newer_summary = signed_summary(2_000, &["newer-a", "newer-b"]);
        let _ = node
            .handle_gossip_message(GossipMessage::Summary(newer_summary), 2_000)
            .expect("newer summary should verify");
        assert_eq!(node.metrics().gossip_updates, 1);

        let older_summary = signed_summary(1_500, &["older-only"]);
        let _ = node
            .handle_gossip_message(GossipMessage::Summary(older_summary), 2_000)
            .expect("older-but-signed summary should be ignored, not fail verification");

        let accepted = node
            .gossip
            .peer_last_summary(&TailscaleNodeId::new("peer-1"))
            .expect("newer summary should remain recorded");
        assert_eq!(accepted.timestamp, 2_000);
        assert_eq!(accepted.object_count, 2);
        assert_eq!(accepted.symbol_count, 0);
        assert_eq!(
            node.metrics().gossip_updates,
            1,
            "older summary must not count as a fresh gossip update"
        );
    }

    #[test]
    fn peer_capability_advertisement_updates_peer_protocol_state() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-capable");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-capable"),
            HashSet::new(),
            vec![],
            1_000,
        );

        let template =
            PeerCapabilityAdvertisement::v3_v4(TailscaleNodeId::new("peer-capable"), 1_000);
        let signature = fcp_core::NodeSignature::new(
            fcp_core::NodeId::new(peer.as_str()),
            signing_key.sign(&template.signing_bytes()).to_bytes(),
            1_000,
        );
        let advertisement = template.with_signature(signature);

        let _ = node
            .handle_gossip_message(GossipMessage::PeerCapabilities(advertisement), 1_000)
            .expect("signed capability advertisement should verify");

        let capabilities = node
            .peer_protocol_capabilities(&peer)
            .expect("peer state should retain capabilities");
        assert!(capabilities.supports_v4());
        assert_eq!(node.metrics().gossip_updates, 1);
    }

    #[test]
    fn peer_capability_advertisement_rejects_unknown_peer() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-unenrolled");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());

        let template =
            PeerCapabilityAdvertisement::v3_v4(TailscaleNodeId::new("peer-unenrolled"), 1_000);
        let signature = fcp_core::NodeSignature::new(
            fcp_core::NodeId::new(peer.as_str()),
            signing_key.sign(&template.signing_bytes()).to_bytes(),
            1_000,
        );
        let advertisement = template.with_signature(signature);

        let err = node
            .handle_gossip_message(GossipMessage::PeerCapabilities(advertisement), 1_000)
            .expect_err("capability advertisement before enrollment must fail closed");
        assert!(matches!(
            err,
            MeshNodeError::UnknownPeer {
                message_kind: "peer capability advertisement",
                ..
            }
        ));
    }

    #[test]
    fn peer_capability_policy_rejects_v3_only_when_v4_required() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-v3-only");
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-v3-only"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_protocol_capabilities(&peer, PeerProtocolCapabilities::v3_only(), 1_000);

        let err = node
            .require_peer_v4_capability(&peer)
            .expect_err("receiver policy requiring V4 must reject V3-only peers");
        assert!(matches!(
            err,
            MeshNodeError::PeerCapabilityRejected { peer: reported, .. } if reported == "peer-v3-only"
        ));

        node.update_peer_protocol_capabilities(&peer, PeerProtocolCapabilities::v3_v4(), 2_000);
        node.require_peer_v4_capability(&peer)
            .expect("V3/V4 peer should satisfy V4-required policy");
    }

    #[test]
    fn revocation_frontier_snapshot_reconciles_after_restart_without_downgrade() {
        let mut original = test_node("node-1");
        original.observe_revocation_frontier(&ZoneId::work(), 42);
        let snapshot = original.revocation_frontier_snapshot();
        let encoded = serde_json::to_vec(&snapshot).expect("frontier snapshot serializes");
        let decoded: RevocationFreshnessFrontier =
            serde_json::from_slice(&encoded).expect("frontier snapshot deserializes");

        let mut restarted = test_node("node-2");
        assert_eq!(
            restarted.reconcile_revocation_frontier(&decoded),
            VersionVectorOrder::Dominates
        );
        assert_eq!(restarted.revocation_frontier_counter(&ZoneId::work()), 42);

        let stale = RevocationFreshnessFrontier::from_counter("z:work", 41);
        assert_eq!(
            restarted.reconcile_revocation_frontier(&stale),
            VersionVectorOrder::DominatedBy
        );
        assert_eq!(restarted.revocation_frontier_counter(&ZoneId::work()), 42);
    }

    #[test]
    fn observe_revocation_registry_head_seeds_hiervv_frontier() {
        let mut registry = RevocationRegistry::new();
        registry.update_head(ObjectId::from_bytes([0x77; 32]), 10, 1_000);

        let mut node = test_node("node-1");
        let decision = node.observe_revocation_registry_head(&ZoneId::work(), &registry);

        assert_eq!(decision.order, VersionVectorOrder::Dominates);
        assert_eq!(node.revocation_frontier_counter(&ZoneId::work()), 10);
        let team_a: ZoneId = "z:work:team-a".parse().unwrap();
        assert_eq!(node.revocation_frontier_counter(&team_a), 10);
    }

    #[test]
    fn handle_revocation_push_returns_verified_descriptor() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xAB; 32])],
            42,
            1_000,
        );
        sign_push_with_owner(&mut push, &signing_key, &owner_key, 1_000);

        let verified = node
            .handle_revocation_push(push, 1_000)
            .expect("push should verify");
        assert_eq!(verified.new_rev_seq, 42);
        assert_eq!(verified.revoked_ids.len(), 1);
        assert_eq!(
            verified.freshness.action,
            crate::RevocationFreshnessAction::Accept
        );
        assert_eq!(node.revocation_frontier_counter(&ZoneId::work()), 42);
        assert_eq!(node.metrics().revocation_hiervv_size_samples, 1);
        assert!(node.metrics().revocation_hiervv_size_last_bytes > 0);
        assert_eq!(
            u64::try_from(node.revocation_frontier_size_bytes().expect("size encodes"))
                .expect("size fits in u64"),
            node.metrics().revocation_hiervv_size_last_bytes
        );
    }

    #[test]
    fn handle_revocation_push_rejects_missing_owner_signature() {
        // Acceptance (br-flywheel_connectors-uxsnk): a peer holding a
        // valid peer signing key AND authorized for the zone cannot
        // revoke objects without a zone-owner signature. This is the
        // forgery path uxsnk closes — pre-fix the push would have been
        // accepted on the peer signature alone.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0x01; 32])],
            9,
            1_000,
        );
        // Only peer signature — no owner signature.
        push.signature = Some(fcp_core::NodeSignature::new(
            fcp_core::NodeId::new(peer.as_str()),
            signing_key.sign(&push.signing_bytes()).to_bytes(),
            1_000,
        ));

        let err = node
            .handle_revocation_push(push, 1_000)
            .expect_err("missing owner signature must be rejected");
        match err {
            MeshNodeError::MissingOwnerSignature {
                peer: reported,
                zone_id,
            } => {
                assert_eq!(reported, "peer-1");
                assert_eq!(zone_id, ZoneId::work().as_str());
            }
            other => panic!("expected MissingOwnerSignature, got {other:?}"),
        }
    }

    #[test]
    fn handle_revocation_push_rejects_forged_owner_signature() {
        // Acceptance (br-uxsnk): a peer that signs the owner-signing
        // transcript itself (as if it were the owner) must still be
        // rejected — only the real registered owner key verifies.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let real_owner_key = Ed25519SigningKey::generate();
        let forger_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), real_owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0x02; 32])],
            11,
            1_000,
        );
        // Peer signature valid, but owner signature is by a different key.
        sign_push_with_owner(&mut push, &signing_key, &forger_key, 1_000);

        let err = node
            .handle_revocation_push(push, 1_000)
            .expect_err("forged owner signature must be rejected");
        assert!(
            matches!(err, MeshNodeError::InvalidOwnerSignature { .. }),
            "expected InvalidOwnerSignature, got {err:?}"
        );
    }

    #[test]
    fn handle_revocation_push_rejects_signature_node_mismatch() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0x77; 32])],
            17,
            1_000,
        );
        sign_push_with_owner(&mut push, &signing_key, &owner_key, 1_000);
        push.signature = Some(fcp_core::NodeSignature::new(
            fcp_core::NodeId::new("peer-2"),
            signing_key.sign(&push.signing_bytes()).to_bytes(),
            1_000,
        ));

        let err = node
            .handle_revocation_push(push, 1_000)
            .expect_err("revocation push signature bound to a different node must be rejected");
        assert!(matches!(
            err,
            MeshNodeError::SignatureNodeMismatch {
                message_kind: "revocation push",
                ..
            }
        ));
        assert_eq!(
            node.metrics().gossip_updates,
            0,
            "node-mismatched push must not record a gossip update"
        );
    }

    #[test]
    fn handle_revocation_push_rejects_unregistered_zone_owner() {
        // Acceptance (br-uxsnk): fail-closed when no owner key is
        // registered for the target zone. Pre-fix there was no owner
        // check at all, so this state was silently "accept"; the new
        // contract is "if we don't know who the owner is, we cannot
        // verify authority and must reject."
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        // Note: no register_zone_owner_key call.
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0x03; 32])],
            13,
            1_000,
        );
        sign_push_with_owner(&mut push, &signing_key, &owner_key, 1_000);

        let err = node
            .handle_revocation_push(push, 1_000)
            .expect_err("unregistered owner must be rejected");
        assert!(
            matches!(err, MeshNodeError::UnknownZoneOwner { .. }),
            "expected UnknownZoneOwner, got {err:?}"
        );
    }

    #[test]
    fn handle_revocation_push_rejects_stale_message() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xCD; 32])],
            7,
            100,
        );
        sign_push_with_owner(&mut push, &signing_key, &owner_key, 100);

        let err = node
            .handle_revocation_push(push, 100 + GossipConfig::default().summary_ttl_secs + 1)
            .expect_err("stale push must be rejected");
        assert!(matches!(
            err,
            MeshNodeError::StaleGossipMessage {
                message_kind: "revocation push",
                ..
            }
        ));
    }

    #[test]
    fn handle_revocation_push_accepts_hiervv_parent_frontier_over_child_scopes() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let team_a: ZoneId = "z:work:team-a".parse().unwrap();
        let team_b: ZoneId = "z:work:team-b".parse().unwrap();
        node.observe_revocation_frontier(&team_a, 7);
        node.observe_revocation_frontier(&team_b, 9);

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xCE; 32])],
            10,
            1_000,
        );
        sign_push_with_owner(&mut push, &signing_key, &owner_key, 1_000);

        let verified = node
            .handle_revocation_push(push, 1_001)
            .expect("parent frontier should dominate child scopes despite receiver clock skew");

        assert_eq!(
            verified.freshness.order,
            crate::VersionVectorOrder::Dominates
        );
        assert_eq!(node.revocation_frontier_counter(&team_a), 10);
        assert_eq!(node.revocation_frontier_counter(&team_b), 10);
    }

    #[test]
    fn handle_revocation_push_rejects_dominated_hiervv_frontier() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));
        node.observe_revocation_frontier(&ZoneId::work(), 10);

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xCF; 32])],
            9,
            1_000,
        );
        sign_push_with_owner(&mut push, &signing_key, &owner_key, 1_000);

        let err = node
            .handle_revocation_push(push, 1_000)
            .expect_err("dominated revocation frontier must be rejected");

        assert!(matches!(
            err,
            MeshNodeError::StaleRevocationFrontier {
                incoming_seq: 9,
                local_seq: 10,
                ..
            }
        ));
        assert_eq!(node.revocation_frontier_counter(&ZoneId::work()), 10);
        assert_eq!(node.metrics().gossip_updates, 0);
        assert_eq!(node.metrics().revocation_hiervv_size_samples, 1);
        assert!(node.metrics().revocation_hiervv_size_last_bytes > 0);
    }

    #[test]
    fn handle_revocation_push_rejects_future_dated_message() {
        // Regression for br-flywheel_connectors-hawuq: a peer with a fast clock
        // (or an adversary) could emit a RevocationPushMessage whose timestamp
        // sits arbitrarily far in the future. Pre-fix, the freshness check
        // computed `now.saturating_sub(future)` which collapses to 0, so the
        // `age > ttl` gate trivially passed and let the push through after
        // peer/owner signature verification.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let now = 1_000u64;
        let future_skew = GossipConfig::default().max_future_skew_secs;
        let future_timestamp = now + future_skew + 1;
        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xCD; 32])],
            7,
            future_timestamp,
        );
        sign_push_with_owner(&mut push, &signing_key, &owner_key, future_timestamp);

        let err = node
            .handle_revocation_push(push, now)
            .expect_err("future-dated push must be rejected");
        assert!(matches!(
            err,
            MeshNodeError::StaleGossipMessage {
                message_kind: "revocation push",
                ..
            }
        ));
    }

    #[test]
    fn handle_gossip_request_rejects_future_dated_message() {
        // Regression for br-flywheel_connectors-hawuq, request side: an
        // attacker-supplied request with a future-dated timestamp must be
        // rejected by verify_gossip_request before the node enqueues a
        // GossipResponse. Without the future-skew bound, the saturating-sub
        // freshness check trivially passes for any future timestamp.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let now = 1_000u64;
        let future_skew = GossipConfig::default().max_future_skew_secs;
        let request = crate::gossip::GossipRequest::for_objects(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xAB; 32])],
            now + future_skew + 1,
        );

        let err = node
            .handle_gossip_request(request, now)
            .expect_err("future-dated gossip request must be rejected");
        assert!(matches!(
            err,
            MeshNodeError::StaleGossipMessage {
                message_kind: "gossip request",
                ..
            }
        ));
    }

    #[test]
    fn dispatch_gossip_payload_routes_revocation_push_to_registry() {
        // Regression test for L3-02 (gossip dispatch gap). Simulate
        // a transport delivery of a JSON-encoded RevocationPush and
        // verify MeshNode::dispatch_gossip_payload runs signature
        // verification and surfaces the verified descriptor, proving
        // the production dispatch path is wired.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xEF; 32])],
            99,
            1_000,
        );
        sign_push_with_owner(&mut push, &signing_key, &owner_key, 1_000);
        let message = GossipMessage::RevocationPush(push);

        let payload = serde_json::to_vec(&message).expect("JSON encode");

        let verified = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect("dispatch should succeed")
            .revocation_push
            .expect("revocation push must produce a verified descriptor");
        assert_eq!(verified.new_rev_seq, 99);
        assert_eq!(verified.revoked_ids.len(), 1);
    }

    #[test]
    fn dispatch_gossip_payload_routes_request_to_response() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let known_object = ObjectId::from_bytes([0x44; 32]);
        assert!(node.announce_object(
            &ZoneId::work(),
            &known_object,
            ObjectAdmissionClass::Admitted,
            1_000,
        ));

        let request = GossipRequest::for_objects(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![known_object, ObjectId::from_bytes([0x99; 32])],
            1_000,
        );
        let payload = serde_json::to_vec(&GossipMessage::Request(request)).expect("JSON encode");

        let outcome = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect("dispatch should succeed");
        assert!(outcome.revocation_push.is_none());
        let response = outcome
            .response
            .expect("request dispatch must surface an immediate response");
        assert_eq!(response.from, TailscaleNodeId::new("node-1"));
        assert_eq!(response.to, TailscaleNodeId::new("peer-1"));
        assert_eq!(response.zone_id, ZoneId::work());
        assert_eq!(response.have_objects, vec![known_object]);
        assert!(response.have_symbols.is_empty());
    }

    #[test]
    fn dispatch_gossip_payload_with_fetch_reply_materializes_request_bytes() {
        let mut responder = test_node("node-1");
        let mut requester = test_node("peer-1");
        let responder_peer = NodeId::new("node-1");
        let requester_peer = NodeId::new("peer-1");
        let zone_id = ZoneId::work();

        responder.update_peer_state(
            requester_peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        responder.update_peer_zones(&requester_peer, zone_set(zone_id.clone()));
        requester.update_peer_state(
            responder_peer.clone(),
            test_device_profile("node-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        requester.update_peer_zones(&responder_peer, zone_set(zone_id.clone()));

        let stored_object = test_stored_object(&zone_id, "dispatch-fetch-object", b"fetch-body");
        let object_id = stored_object.object_id;
        let symbol_object_id = test_object_id("dispatch-fetch-symbol-object");
        let symbol_meta = test_object_symbol_meta(symbol_object_id, &zone_id);
        let stored_symbol = test_stored_symbol(symbol_object_id, &zone_id, 5, 0xD5);

        assert!(responder.announce_object(
            &zone_id,
            &object_id,
            ObjectAdmissionClass::Admitted,
            1_000,
        ));
        assert!(responder.announce_symbol(
            &zone_id,
            &symbol_object_id,
            5,
            ObjectAdmissionClass::Admitted,
            1_000,
        ));

        fcp_async_core::runtime::block_on_sync(async {
            responder
                .object_store
                .put(stored_object.clone())
                .await
                .expect("responder stores object bytes");
            responder
                .symbol_store
                .put_object_meta(symbol_meta)
                .await
                .expect("responder stores symbol metadata");
            responder
                .symbol_store
                .put_symbol(stored_symbol.clone())
                .await
                .expect("responder stores symbol bytes");

            let request = GossipRequest {
                from: TailscaleNodeId::new("peer-1"),
                zone_id: zone_id.clone(),
                object_ids: vec![object_id],
                symbols: vec![(symbol_object_id, 5)],
                timestamp: 1_000,
                signature: None,
            };
            let payload =
                serde_json::to_vec(&GossipMessage::Request(request)).expect("JSON encode");

            let outcome = responder
                .dispatch_gossip_payload_with_fetch_reply(&payload, 1_000)
                .await
                .expect("dispatch should materialize fetch reply");
            let response = outcome
                .dispatch
                .response
                .expect("standard dispatch still carries availability response");
            assert_eq!(response.have_objects, vec![object_id]);
            assert_eq!(response.have_symbols, vec![(symbol_object_id, 5)]);
            let fetch_reply = outcome
                .fetch_reply
                .expect("request dispatch carries materialized bytes");
            assert_eq!(fetch_reply.response.have_objects, vec![object_id]);
            assert_eq!(fetch_reply.payload.objects.len(), 1);
            assert_eq!(fetch_reply.payload.symbols.len(), 1);

            let plan = requester
                .handle_gossip_response(fetch_reply.response, 1_000)
                .expect("requester verifies response")
                .expect("requester produces fetch plan");
            let apply = requester
                .apply_gossip_fetch_payload(
                    &plan,
                    fetch_reply.payload.objects,
                    fetch_reply.payload.symbols,
                    1_001,
                )
                .await
                .expect("requester applies materialized bytes");
            assert_eq!(apply.objects_applied, vec![object_id]);
            assert_eq!(apply.symbols_applied, vec![(symbol_object_id, 5)]);
            assert!(apply.connector_state_root_candidates.is_empty());

            let local_object = requester
                .object_store
                .get(&object_id)
                .await
                .expect("requester stores fetched object");
            assert_eq!(local_object.body, stored_object.body);
            let local_symbol = requester
                .symbol_store
                .get_symbol(&symbol_object_id, 5)
                .await
                .expect("requester stores fetched symbol");
            assert_eq!(local_symbol.data, stored_symbol.data);
        })
        .expect("runtime");
    }

    #[test]
    fn dispatch_gossip_payload_routes_response_to_fetch_plan() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let zone_id = ZoneId::work();
        let known_object = ObjectId::from_bytes([0x61; 32]);
        let missing_object = ObjectId::from_bytes([0x62; 32]);
        let known_symbol_object = ObjectId::from_bytes([0x63; 32]);
        let missing_symbol_object = ObjectId::from_bytes([0x64; 32]);
        assert!(node.announce_object(
            &zone_id,
            &known_object,
            ObjectAdmissionClass::Admitted,
            1_000,
        ));
        assert!(node.announce_symbol(
            &zone_id,
            &known_symbol_object,
            7,
            ObjectAdmissionClass::Admitted,
            1_000,
        ));

        let response = GossipResponse {
            from: TailscaleNodeId::new("peer-1"),
            to: TailscaleNodeId::new("node-1"),
            zone_id: zone_id.clone(),
            have_objects: vec![known_object, missing_object],
            have_symbols: vec![(known_symbol_object, 7), (missing_symbol_object, 3)],
            timestamp: 1_000,
        };
        let payload = serde_json::to_vec(&GossipMessage::Response(response)).expect("JSON encode");

        let outcome = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect("dispatch should succeed");
        assert!(outcome.revocation_push.is_none());
        assert!(outcome.response.is_none());
        assert!(outcome.reconcile_response.is_none());
        assert!(outcome.followup_request.is_none());
        let fetch_plan = outcome
            .fetch_plan
            .expect("response dispatch must surface missing fetch candidates");
        assert_eq!(fetch_plan.peer, TailscaleNodeId::new("peer-1"));
        assert_eq!(fetch_plan.zone_id, zone_id);
        assert_eq!(fetch_plan.object_ids, vec![missing_object]);
        assert_eq!(fetch_plan.symbols, vec![(missing_symbol_object, 3)]);
    }

    #[test]
    fn apply_gossip_fetch_payload_persists_peer_bytes_and_announces_availability() {
        let mut node = test_node("node-1");
        let peer_node = test_node("peer-1");
        let peer = NodeId::new("peer-1");
        let requester = NodeId::new("requester-1");
        let zone_id = ZoneId::work();

        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(zone_id.clone()));
        node.update_peer_state(
            requester.clone(),
            test_device_profile("requester-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&requester, zone_set(zone_id.clone()));

        let fetched_object = test_stored_object(&zone_id, "object-fetch", b"peer-object-bytes");
        let fetched_object_id = fetched_object.object_id;
        let symbol_object_id = test_object_id("symbol-fetch-object");
        let symbol_meta = test_object_symbol_meta(symbol_object_id, &zone_id);
        let fetched_symbol = test_stored_symbol(symbol_object_id, &zone_id, 7, 0xA7);

        fcp_async_core::runtime::block_on_sync(async {
            peer_node
                .object_store
                .put(fetched_object.clone())
                .await
                .expect("peer stores object bytes");
            peer_node
                .symbol_store
                .put_object_meta(symbol_meta.clone())
                .await
                .expect("peer stores symbol metadata");
            peer_node
                .symbol_store
                .put_symbol(fetched_symbol.clone())
                .await
                .expect("peer stores symbol bytes");

            let response = GossipResponse {
                from: TailscaleNodeId::new("peer-1"),
                to: TailscaleNodeId::new("node-1"),
                zone_id: zone_id.clone(),
                have_objects: vec![fetched_object_id],
                have_symbols: vec![(symbol_object_id, 7)],
                timestamp: 1_000,
            };
            let plan = node
                .handle_gossip_response(response, 1_000)
                .expect("verified response")
                .expect("fetch plan");

            let object_bytes = peer_node
                .object_store
                .get(&fetched_object_id)
                .await
                .expect("transport fetched object bytes");
            let symbol_bytes = GossipFetchedSymbol {
                object_meta: peer_node
                    .symbol_store
                    .get_object_meta(&symbol_object_id)
                    .await
                    .expect("transport fetched symbol metadata"),
                symbol: peer_node
                    .symbol_store
                    .get_symbol(&symbol_object_id, 7)
                    .await
                    .expect("transport fetched symbol bytes"),
            };

            let outcome = node
                .apply_gossip_fetch_payload(&plan, vec![object_bytes], vec![symbol_bytes], 1_000)
                .await
                .expect("apply fetched bytes");
            assert_eq!(outcome.objects_applied, vec![fetched_object_id]);
            assert!(outcome.connector_state_root_candidates.is_empty());
            assert_eq!(outcome.symbols_applied, vec![(symbol_object_id, 7)]);

            let local_object = node
                .object_store
                .get(&fetched_object_id)
                .await
                .expect("local object bytes stored");
            assert_eq!(local_object.body, fetched_object.body);
            let local_symbol = node
                .symbol_store
                .get_symbol(&symbol_object_id, 7)
                .await
                .expect("local symbol bytes stored");
            assert_eq!(local_symbol.data, fetched_symbol.data);
        })
        .expect("runtime");

        let request = GossipRequest {
            from: TailscaleNodeId::new("requester-1"),
            zone_id,
            object_ids: vec![fetched_object_id],
            symbols: vec![(symbol_object_id, 7)],
            timestamp: 1_000,
            signature: None,
        };
        let response = node
            .handle_gossip_request(request, 1_000)
            .expect("local node advertises applied bytes");
        assert_eq!(response.have_objects, vec![fetched_object_id]);
        assert_eq!(response.have_symbols, vec![(symbol_object_id, 7)]);
    }

    #[test]
    fn apply_gossip_fetch_payload_surfaces_connector_state_roots_for_observation() {
        let mut node = test_node("node-1");
        let peer_node = test_node("peer-1");
        let peer = NodeId::new("peer-1");
        let zone_id = ZoneId::work();
        let connector_id = ConnectorId::from_static("slack:chat:v1");
        let object_id_key = ObjectIdKey::from_bytes([0xB5; 32]);

        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(zone_id.clone()));

        let fetched_root =
            test_connector_state_root_object(&zone_id, connector_id.clone(), object_id_key);
        let fetched_root_id = fetched_root.object_id;

        fcp_async_core::runtime::block_on_sync(async {
            peer_node
                .object_store
                .put(fetched_root)
                .await
                .expect("peer stores connector-state root bytes");

            let response = GossipResponse {
                from: TailscaleNodeId::new("peer-1"),
                to: TailscaleNodeId::new("node-1"),
                zone_id: zone_id.clone(),
                have_objects: vec![fetched_root_id],
                have_symbols: vec![],
                timestamp: 1_000,
            };
            let plan = node
                .handle_gossip_response(response, 1_000)
                .expect("verified response")
                .expect("fetch plan");
            let object_bytes = peer_node
                .object_store
                .get(&fetched_root_id)
                .await
                .expect("transport fetched connector-state root bytes");

            let object_store = Arc::clone(node.object_store());
            let state_store = FcpStoreConnectorStateStore::new(
                object_store,
                object_id_key,
                connector_id,
                zone_id.clone(),
            );
            let outcome = node
                .apply_gossip_fetch_payload_and_observe_connector_state_roots(
                    &state_store,
                    &plan,
                    vec![object_bytes],
                    vec![],
                    1_001,
                )
                .await
                .expect("apply fetched connector-state root and observe candidate");
            assert_eq!(outcome.apply.objects_applied, vec![fetched_root_id]);
            assert_eq!(
                outcome.apply.connector_state_root_candidates,
                vec![fetched_root_id]
            );
            assert!(outcome.apply.symbols_applied.is_empty());
            assert_eq!(outcome.connector_state_changes.len(), 1);

            let change = &outcome.connector_state_changes[0];
            assert_eq!(change.kind, ConnectorStateChangeKind::RootUpdated);
            assert_eq!(change.object_id, Some(fetched_root_id));
            assert_eq!(change.zone_id, zone_id);
            assert_eq!(change.seq, None);
        })
        .expect("runtime");
    }

    #[test]
    fn prepare_gossip_fetch_reply_materializes_bytes_for_apply_and_observe() {
        let mut requester = test_node("node-1");
        let mut responder = test_node("peer-1");
        let requester_peer = NodeId::new("node-1");
        let responder_peer = NodeId::new("peer-1");
        let zone_id = ZoneId::work();
        let connector_id = ConnectorId::from_static("slack:chat:v1");
        let object_id_key = ObjectIdKey::from_bytes([0xB6; 32]);

        requester.update_peer_state(
            responder_peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        requester.update_peer_zones(&responder_peer, zone_set(zone_id.clone()));
        responder.update_peer_state(
            requester_peer.clone(),
            test_device_profile("node-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        responder.update_peer_zones(&requester_peer, zone_set(zone_id.clone()));

        let fetched_root =
            test_connector_state_root_object(&zone_id, connector_id.clone(), object_id_key);
        let fetched_root_id = fetched_root.object_id;
        let symbol_object_id = test_object_id("inline-fetch-symbol-object");
        let symbol_meta = test_object_symbol_meta(symbol_object_id, &zone_id);
        let fetched_symbol = test_stored_symbol(symbol_object_id, &zone_id, 11, 0xBC);

        assert!(responder.announce_object(
            &zone_id,
            &fetched_root_id,
            ObjectAdmissionClass::Admitted,
            1_000,
        ));
        assert!(responder.announce_symbol(
            &zone_id,
            &symbol_object_id,
            11,
            ObjectAdmissionClass::Admitted,
            1_000,
        ));

        fcp_async_core::runtime::block_on_sync(async {
            responder
                .object_store
                .put(fetched_root)
                .await
                .expect("responder stores connector-state root bytes");
            responder
                .symbol_store
                .put_object_meta(symbol_meta)
                .await
                .expect("responder stores symbol metadata");
            responder
                .symbol_store
                .put_symbol(fetched_symbol)
                .await
                .expect("responder stores symbol bytes");

            let request = GossipRequest {
                from: TailscaleNodeId::new("node-1"),
                zone_id: zone_id.clone(),
                object_ids: vec![fetched_root_id],
                symbols: vec![(symbol_object_id, 11)],
                timestamp: 1_000,
                signature: None,
            };
            let reply = responder
                .prepare_gossip_fetch_reply(request, 1_000)
                .await
                .expect("responder materializes fetch reply");
            assert_eq!(reply.response.have_objects, vec![fetched_root_id]);
            assert_eq!(reply.response.have_symbols, vec![(symbol_object_id, 11)]);
            assert_eq!(reply.payload.objects.len(), 1);
            assert_eq!(reply.payload.symbols.len(), 1);

            let plan = requester
                .handle_gossip_response(reply.response, 1_000)
                .expect("requester verifies availability response")
                .expect("requester produces fetch plan");
            let state_store = FcpStoreConnectorStateStore::new(
                Arc::clone(requester.object_store()),
                object_id_key,
                connector_id,
                zone_id.clone(),
            );
            let outcome = requester
                .apply_gossip_fetch_payload_and_observe_connector_state_roots(
                    &state_store,
                    &plan,
                    reply.payload.objects,
                    reply.payload.symbols,
                    1_001,
                )
                .await
                .expect("requester applies bytes and observes state root");

            assert_eq!(outcome.apply.objects_applied, vec![fetched_root_id]);
            assert_eq!(
                outcome.apply.connector_state_root_candidates,
                vec![fetched_root_id]
            );
            assert_eq!(outcome.apply.symbols_applied, vec![(symbol_object_id, 11)]);
            assert_eq!(outcome.connector_state_changes.len(), 1);
            assert_eq!(
                outcome.connector_state_changes[0].kind,
                ConnectorStateChangeKind::RootUpdated
            );
            assert_eq!(
                outcome.connector_state_changes[0].object_id,
                Some(fetched_root_id)
            );
        })
        .expect("runtime");
    }

    #[test]
    fn dispatch_gossip_payload_rejects_response_for_different_recipient() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let response = GossipResponse {
            from: TailscaleNodeId::new("peer-1"),
            to: TailscaleNodeId::new("node-2"),
            zone_id: ZoneId::work(),
            have_objects: vec![ObjectId::from_bytes([0x65; 32])],
            have_symbols: Vec::new(),
            timestamp: 1_000,
        };
        let payload = serde_json::to_vec(&GossipMessage::Response(response)).expect("JSON encode");

        let err = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect_err("response for another recipient must be rejected");
        assert!(matches!(
            err,
            MeshNodeError::RecipientMismatch {
                message_kind: "gossip response",
                ..
            }
        ));
    }

    #[test]
    fn dispatch_gossip_payload_routes_reconcile_request_to_response() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let zone_id = ZoneId::work();
        let shared = ObjectId::from_bytes([0x41; 32]);
        let local_only = ObjectId::from_bytes([0x42; 32]);
        let peer_only = ObjectId::from_bytes([0x43; 32]);
        assert!(node.announce_object(&zone_id, &shared, ObjectAdmissionClass::Admitted, 1_000,));
        assert!(
            node.announce_object(&zone_id, &local_only, ObjectAdmissionClass::Admitted, 1_000,)
        );

        let mut peer_sketch = IbltPlaceholder::with_mask(
            node.gossip.reconciliation_batch_size(),
            crate::iblt::IbltMask::for_zone(&zone_id),
        );
        peer_sketch.note_local_change(&shared, None);
        peer_sketch.note_local_change(&peer_only, None);
        let request = ReconcileRequest {
            from: TailscaleNodeId::new("peer-1"),
            zone_id: zone_id.clone(),
            iblt: peer_sketch.encode(),
            object_filter_digest: [0; 32],
            symbol_filter_digest: [0; 32],
            timestamp: 1_000,
        };
        let payload =
            serde_json::to_vec(&GossipMessage::ReconcileRequest(request)).expect("JSON encode");

        let outcome = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect("dispatch should succeed");
        assert!(outcome.revocation_push.is_none());
        assert!(outcome.response.is_none());
        let response = outcome
            .reconcile_response
            .expect("reconcile dispatch must surface an immediate response");
        assert_eq!(response.from, TailscaleNodeId::new("node-1"));
        assert_eq!(response.zone_id, zone_id);
        assert_eq!(response.timestamp, 1_000);
        assert_eq!(response.peer_missing_objects.len(), 1);
        assert!(response.peer_missing_objects.contains(&local_only));
        assert_eq!(response.we_missing_objects.len(), 1);
        assert!(response.we_missing_objects.contains(&peer_only));
    }

    #[test]
    fn dispatch_gossip_payload_routes_reconcile_response_to_followup_request() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let zone_id = ZoneId::work();
        let already_known = ObjectId::from_bytes([0x51; 32]);
        let missing = ObjectId::from_bytes([0x52; 32]);
        let peer_missing = ObjectId::from_bytes([0x53; 32]);
        assert!(node.announce_object(
            &zone_id,
            &already_known,
            ObjectAdmissionClass::Admitted,
            1_000,
        ));

        let response = ReconcileResponse {
            from: TailscaleNodeId::new("peer-1"),
            zone_id: zone_id.clone(),
            peer_missing_objects: vec![peer_missing],
            we_missing_objects: vec![already_known, missing],
            timestamp: 1_000,
        };
        let payload =
            serde_json::to_vec(&GossipMessage::ReconcileResponse(response)).expect("JSON encode");

        let outcome = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect("dispatch should succeed");
        assert!(outcome.revocation_push.is_none());
        assert!(outcome.response.is_none());
        assert!(outcome.reconcile_response.is_none());
        let followup = outcome
            .followup_request
            .expect("reconcile response must surface a follow-up request");
        assert_eq!(followup.peer, TailscaleNodeId::new("peer-1"));
        assert_eq!(followup.request.from, TailscaleNodeId::new("node-1"));
        assert_eq!(followup.request.zone_id, zone_id);
        assert_eq!(followup.request.object_ids, vec![missing]);
        assert!(followup.request.symbols.is_empty());
        assert_eq!(followup.request.timestamp, 1_000);
    }

    #[test]
    fn dispatch_gossip_payload_rejects_request_from_unknown_peer_without_peer_state() {
        let mut node = test_node("node-1");
        let request = GossipRequest::for_objects(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xAA; 32])],
            1_000,
        );
        let payload = serde_json::to_vec(&GossipMessage::Request(request)).expect("JSON encode");

        let err = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect_err("request dispatch must fail closed for unknown peers");
        assert!(matches!(
            err,
            MeshNodeError::UnknownPeer {
                message_kind: "gossip request",
                ..
            }
        ));
    }

    #[test]
    fn dispatch_gossip_message_routes_summary_to_handler() {
        // Covers the pre-parsed dispatch variant: a transport layer
        // that has already decoded bytes into a GossipMessage should
        // be able to hand it off via dispatch_gossip_message.
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        let owner_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        node.register_zone_owner_key(ZoneId::work(), owner_key.verifying_key());
        node.update_peer_state(
            peer.clone(),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![],
            1_000,
        );
        node.update_peer_zones(&peer, zone_set(ZoneId::work()));

        let mut push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0xAA; 32])],
            123,
            1_000,
        );
        sign_push_with_owner(&mut push, &signing_key, &owner_key, 1_000);

        let verified = node
            .dispatch_gossip_message(GossipMessage::RevocationPush(push), 1_000)
            .expect("dispatch should succeed")
            .revocation_push
            .expect("revocation push must produce a verified descriptor");
        assert_eq!(verified.new_rev_seq, 123);
    }

    #[test]
    fn dispatch_gossip_payload_rejects_malformed_bytes() {
        let mut node = test_node("node-1");
        let err = node
            .dispatch_gossip_payload(b"not a gossip message", 0)
            .expect_err("garbage bytes must not decode as a gossip message");
        assert!(matches!(err, MeshNodeError::GossipDecode(_)));
    }

    #[test]
    fn dispatch_gossip_payload_rejects_oversized_raw_json_before_deserialize() {
        let mut node = test_node("node-1");
        let max_payload = node.gossip.max_wire_payload_bytes();
        let iblt_len = max_payload / 4 + 8;
        let summary = GossipSummary {
            from: TailscaleNodeId::new("peer-1"),
            zone_id: ZoneId::work(),
            epoch_id: EpochId::new("epoch-too-large"),
            object_filter_digest: [0x11; 32],
            symbol_filter_digest: [0x22; 32],
            object_count: 0,
            symbol_count: 0,
            iblt: vec![255; iblt_len],
            timestamp: 1_000,
            signature: None,
        };

        let payload =
            serde_json::to_vec(&GossipMessage::Summary(summary)).expect("payload should encode");
        assert!(
            payload.len() > max_payload,
            "test payload must exceed the raw gossip cap"
        );

        let err = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect_err("oversized payload must fail before JSON decode");
        assert!(matches!(
            err,
            MeshNodeError::GossipPayloadTooLarge { len, max }
            if len == payload.len() && max == max_payload
        ));
    }

    #[test]
    fn dispatch_gossip_payload_rejects_summary_with_oversized_signature_field() {
        let mut node = test_node("node-1");
        let summary = GossipSummary {
            from: TailscaleNodeId::new("peer-1"),
            zone_id: ZoneId::work(),
            epoch_id: EpochId::new("epoch-oversized"),
            object_filter_digest: [0x11; 32],
            symbol_filter_digest: [0x22; 32],
            object_count: 0,
            symbol_count: 0,
            iblt: Vec::new(),
            timestamp: 1_000,
            signature: None,
        };
        let mut payload = serde_json::to_value(GossipMessage::Summary(summary))
            .expect("summary should serialize");
        payload["signature"] = serde_json::json!({
            "node_id": "peer-1",
            "signature": "ab".repeat(65),
            "signed_at": 1_000_u64
        });

        let payload = serde_json::to_vec(&payload).expect("payload should encode");
        let err = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect_err("oversized summary signature field must fail decode");
        assert!(matches!(err, MeshNodeError::GossipDecode(_)));
    }

    #[test]
    fn dispatch_gossip_payload_rejects_revocation_push_with_oversized_owner_signature_field() {
        let mut node = test_node("node-1");
        let push = RevocationPushMessage::new(
            TailscaleNodeId::new("peer-1"),
            ZoneId::work(),
            vec![ObjectId::from_bytes([0x55; 32])],
            9,
            1_000,
        );
        let mut payload = serde_json::to_value(GossipMessage::RevocationPush(push))
            .expect("revocation push should serialize");
        payload["owner_signature"] = serde_json::json!({
            "node_id": "peer-1",
            "signature": "cd".repeat(65),
            "signed_at": 1_000_u64
        });

        let payload = serde_json::to_vec(&payload).expect("payload should encode");
        let err = node
            .dispatch_gossip_payload(&payload, 1_000)
            .expect_err("oversized owner signature field must fail decode");
        assert!(matches!(err, MeshNodeError::GossipDecode(_)));
    }

    // ---- Metrics tests ----

    #[test]
    fn initial_metrics_are_zero() {
        let node = test_node("node-1");
        let m = node.metrics();
        assert_eq!(m.gossip_announcements, 0);
        assert_eq!(m.gossip_updates, 0);
        assert_eq!(m.peer_updates, 0);
        assert_eq!(m.symbol_requests.acks_received, 0);
    }

    #[test]
    fn peer_update_metric_increments() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");

        node.update_peer_state(NodeId::new("peer-1"), profile, HashSet::new(), vec![], 1000);
        assert_eq!(node.metrics().peer_updates, 1);
    }

    // ---- Planner integration tests ----

    #[test]
    fn build_planner_input_without_local_state_is_empty() {
        let node = test_node("node-1");
        let input = node.build_planner_input(1000);
        assert!(input.nodes.is_empty());
    }

    #[test]
    fn build_planner_input_includes_local_and_peers() {
        let mut node = test_node("node-1");
        let local_profile = test_device_profile("node-1");
        let peer_profile = test_device_profile("peer-1");

        node.update_local_state(local_profile, HashSet::new(), vec![]);
        node.update_peer_state(
            NodeId::new("peer-1"),
            peer_profile,
            HashSet::new(),
            vec![],
            1000,
        );

        let input = node.build_planner_input(2000);
        assert_eq!(input.nodes.len(), 2);
    }

    #[test]
    fn build_planner_input_includes_singleton_holder() {
        let mut node = test_node("node-1");
        let local_profile = test_device_profile("node-1");
        let obj_id = ObjectId::from_bytes([0xAA; 32]);

        let lease = HeldLease {
            subject_id: obj_id,
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 999_999, // Far future
            fencing_token: 7,
        };

        node.update_local_state(local_profile, HashSet::new(), vec![lease]);

        let input = node.build_planner_input(1000);
        assert_eq!(input.nodes.len(), 1);
        assert!(input.singleton_lease_holder.is_some());
    }

    #[test]
    fn plan_execution_returns_candidates() {
        use crate::device::{DeviceProfileBuilder, InstalledConnector};

        let mut node = test_node("node-1");
        let connector_id =
            fcp_core::ConnectorId::new("fcp.test", "test", "v1").expect("valid connector id");
        let installed = InstalledConnector::new(
            connector_id.clone(),
            "1.0.0",
            ObjectId::from_bytes([0xBB; 32]),
        );
        let local_profile = DeviceProfileBuilder::new(NodeId::new("node-1"))
            .add_connector(installed)
            .build();

        node.update_local_state(local_profile, HashSet::new(), vec![]);

        let context = PlannerContext::new(connector_id);
        let candidates = node.plan_execution(&context, 2000);
        // Node has the required connector installed, should be a candidate
        assert!(!candidates.is_empty());
    }

    #[test]
    fn plan_execution_uses_thompson_scheduler_after_recorded_outcomes() {
        use crate::device::{DeviceProfileBuilder, InstalledConnector};
        use rand::{SeedableRng, rngs::StdRng};

        let mut node = test_node("node-1");
        let connector_id =
            fcp_core::ConnectorId::new("fcp.test", "adaptive", "v1").expect("valid connector id");
        let installed = InstalledConnector::new(
            connector_id.clone(),
            "1.0.0",
            ObjectId::from_bytes([0xBC; 32]),
        );
        let peer_id = NodeId::new("peer-1");
        let operation_class = ResourcePoolClass::RequestResponse;

        let local_profile = DeviceProfileBuilder::new(NodeId::new("node-1"))
            .add_connector(installed.clone())
            .build();
        let peer_profile = DeviceProfileBuilder::new(peer_id.clone())
            .add_connector(installed)
            .build();

        node.update_local_state(local_profile, HashSet::new(), Vec::new());
        node.update_peer_state(
            peer_id.clone(),
            peer_profile,
            HashSet::new(),
            Vec::new(),
            1000,
        );

        for _ in 0..200 {
            node.record_execution_outcome(NodeId::new("node-1"), operation_class, false);
            node.record_execution_outcome(peer_id.clone(), operation_class, true);
        }

        let context = PlannerContext::new(connector_id).with_resource_pool_class(operation_class);
        let mut rng = StdRng::seed_from_u64(0xFC04_2004);
        let candidates = node.plan_execution_with_rng(&context, 2000, &mut rng);

        assert_eq!(candidates[0].node_id.as_str(), "peer-1");
        assert!(
            candidates[0].decision_reasons.iter().any(|reason| matches!(
                reason,
                DecisionReason::Custom(message) if message.contains("thompson_sample")
            )),
            "selected candidate should carry Thompson sampling evidence"
        );

        let posterior = node.execution_posterior(&peer_id, operation_class);
        assert_eq!(posterior.alpha(), 201);
        assert_eq!(posterior.beta(), 1);
    }

    // Regression for flywheel_connectors-fqzmp: build_planner_input used to
    // hardcode zones: Vec::new() for both the local node and every peer, so
    // the planner's zone-policy filter ran against universally-empty candidates
    // and could not enforce zone-affinity placement. Now that local_zones and
    // PeerState.zones flow through, a candidate's zones must match whatever
    // enrollment / update_peer_zones populated.
    #[test]
    fn plan_execution_populates_zones_from_local_and_peer_state() {
        use crate::device::{DeviceProfileBuilder, InstalledConnector};

        let mut node = test_node("node-1");
        let connector_id =
            fcp_core::ConnectorId::new("fcp.test", "zoned", "v1").expect("valid connector id");
        let installed = InstalledConnector::new(
            connector_id.clone(),
            "1.0.0",
            ObjectId::from_bytes([0xCC; 32]),
        );

        // Local node: install the connector and enroll into z:work.
        let local_profile = DeviceProfileBuilder::new(NodeId::new("node-1"))
            .add_connector(installed.clone())
            .build();
        node.update_local_state(local_profile, HashSet::new(), vec![]);
        let work_zone: ZoneId = "z:work".parse().expect("zone parse");
        let mut local_zones = HashSet::new();
        local_zones.insert(work_zone.clone());
        node.update_local_zones(local_zones);

        // Peer: install the connector, enroll into z:public via the
        // attestation-layer setter.
        let peer_id = NodeId::new("peer-1");
        let peer_profile = DeviceProfileBuilder::new(peer_id.clone())
            .add_connector(installed)
            .build();
        node.update_peer_state(peer_id.clone(), peer_profile, HashSet::new(), vec![], 1000);
        let public_zone: ZoneId = "z:public".parse().expect("zone parse");
        let mut peer_zones = HashSet::new();
        peer_zones.insert(public_zone.clone());
        node.update_peer_zones(&peer_id, peer_zones);

        let context = PlannerContext::new(connector_id);
        let candidates = node.plan_execution(&context, 2000);
        assert_eq!(
            candidates.len(),
            2,
            "both local and peer should be candidates"
        );

        let local_candidate = candidates
            .iter()
            .find(|c| c.node_id.as_str() == "node-1")
            .expect("local candidate present");
        assert!(
            local_candidate.zones.contains(&work_zone),
            "local candidate must carry its enrolled zone — got {:?}",
            local_candidate.zones
        );

        let peer_candidate = candidates
            .iter()
            .find(|c| c.node_id.as_str() == "peer-1")
            .expect("peer candidate present");
        assert!(
            peer_candidate.zones.contains(&public_zone),
            "peer candidate must carry its attested zone — got {:?}",
            peer_candidate.zones
        );
    }

    // ---- Store accessor tests ----

    #[test]
    fn store_accessors_return_valid_refs() {
        let node = test_node("node-1");
        // Just verify the accessors don't panic and return the stores
        let _ = node.object_store();
        let _ = node.symbol_store();
        let _ = node.quarantine_store();
    }

    // ---- Mutable accessor tests ----

    #[test]
    fn gossip_mut_and_admission_mut_accessible() {
        let mut node = test_node("node-1");
        // Should not panic - verifies mutable borrows work
        let _ = node.gossip_mut();
        let _ = node.admission_mut();
    }

    // ---- Error type coverage ----

    #[test]
    fn error_types_display_correctly() {
        let err = MeshNodeEnforcementError::HolderProofRequired {
            holder_node: "node-1".to_string(),
        };
        assert!(err.to_string().contains("holder proof required"));

        let err = MeshNodeEnforcementError::HolderProofNodeMismatch {
            expected: "node-1".to_string(),
            actual: "node-2".to_string(),
        };
        assert!(err.to_string().contains("node mismatch"));

        let err = MeshNodeEnforcementError::HolderProofInvalid;
        assert!(err.to_string().contains("verification failed"));

        let err = MeshNodeEnforcementError::HolderKeyMissing {
            holder_node: "node-1".to_string(),
        };
        assert!(err.to_string().contains("key missing"));

        let err = MeshNodeEnforcementError::MissingTokenJti;
        assert!(err.to_string().contains("missing jti"));

        let err = MeshNodeEnforcementError::TokenRevoked {
            token_id: ObjectId::from_bytes([0x00; 32]),
        };
        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn mesh_node_error_variants_display() {
        let admission_err = AdmissionError::ObjectQuarantined {
            object_id: "test".to_string(),
        };
        let err = MeshNodeError::Admission(admission_err);
        assert!(err.to_string().contains("admission rejected"));

        let sym_err = SymbolRequestError::AlreadyComplete {
            object_id: "test".to_string(),
        };
        let err = MeshNodeError::SymbolRequest(sym_err);
        assert!(err.to_string().contains("symbol request error"));
    }

    // ---- MeshNodeError additional variants ----

    #[test]
    fn mesh_node_error_trace_not_enabled() {
        let err = MeshNodeError::TraceNotEnabled;
        assert!(err.to_string().contains("trace capture not enabled"));
    }

    #[test]
    fn mesh_node_error_enforcement_variant() {
        let inner = MeshNodeEnforcementError::MissingTokenJti;
        let err = MeshNodeError::Enforcement(inner);
        assert!(err.to_string().contains("enforcement error"));
        assert!(err.to_string().contains("jti"));
    }

    // ---- MeshNodeEnforcementError additional ----

    #[test]
    fn enforcement_error_invoke_validation() {
        let inner = InvokeValidationError::HolderProofRequired;
        let err = MeshNodeEnforcementError::InvokeValidation(inner);
        assert!(err.to_string().contains("invoke validation error"));
    }

    #[test]
    fn enforcement_error_receipt_validation() {
        let inner = fcp_core::OperationValidationError::AlreadyCompleted {
            idempotency_key: "test-key".to_string(),
        };
        let err = MeshNodeEnforcementError::ReceiptValidation(inner);
        assert!(err.to_string().contains("receipt validation failed"));
    }

    // ---- Config trace capture builder ----

    #[test]
    fn config_with_trace_capture_config() {
        let trace_config = TraceCaptureConfig::new().enabled();
        let config = MeshNodeConfig::new("node-1").with_trace_capture_config(trace_config);
        assert!(config.trace_capture.enabled);
    }

    #[test]
    fn config_with_trace_capture_zones() {
        let config = MeshNodeConfig::new("node-1")
            .with_trace_capture_zones([ZoneId::work(), ZoneId::private()]);
        assert!(config.trace_capture_zones.is_some());
        assert_eq!(config.trace_capture_zones.unwrap().len(), 2);
    }

    #[test]
    fn config_default_trace_capture_disabled() {
        let config = MeshNodeConfig::new("node-1");
        assert!(!config.trace_capture.enabled);
        assert!(config.trace_capture_zones.is_none());
    }

    #[test]
    fn config_debug_format() {
        let config = MeshNodeConfig::new("node-1");
        let dbg = format!("{config:?}");
        assert!(dbg.contains("MeshNodeConfig"));
        assert!(dbg.contains("node-1"));
    }

    #[test]
    fn config_clone() {
        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(42);
        assert_eq!(config.node_id, "node-1");
        assert_eq!(config.sender_instance_id, 42);
    }

    // ---- Multiple session management ----

    #[test]
    fn register_multiple_sessions() {
        let mut node = test_node("node-1");
        let s1 = test_session("peer-1");
        let s2 = test_session("peer-2");
        let s3 = test_session("peer-3");

        node.register_session(s1, 1000);
        node.register_session(s2, 1001);
        node.register_session(s3, 1002);

        assert!(node.is_peer_authenticated(&NodeId::new("peer-1")));
        assert!(node.is_peer_authenticated(&NodeId::new("peer-2")));
        assert!(node.is_peer_authenticated(&NodeId::new("peer-3")));
    }

    #[test]
    fn remove_one_session_keeps_others() {
        let mut node = test_node("node-1");
        node.register_session(test_session("peer-1"), 1000);
        node.register_session(test_session("peer-2"), 1001);

        node.remove_session(&NodeId::new("peer-1"), 2000);
        assert!(!node.is_peer_authenticated(&NodeId::new("peer-1")));
        assert!(node.is_peer_authenticated(&NodeId::new("peer-2")));
    }

    #[test]
    fn remove_session_for_unknown_peer_is_noop() {
        let mut node = test_node("node-1");
        node.register_session(test_session("peer-1"), 1000);
        node.remove_session(&NodeId::new("ghost-peer"), 2000);
        assert!(node.is_peer_authenticated(&NodeId::new("peer-1")));
    }

    // ---- Peer state with symbols and leases ----

    #[test]
    fn peer_state_tracks_symbols() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");
        let mut symbols = HashSet::new();
        symbols.insert(ObjectId::from_bytes([0x11; 32]));
        symbols.insert(ObjectId::from_bytes([0x22; 32]));

        node.update_peer_state(NodeId::new("peer-1"), profile, symbols, vec![], 1000);
        assert_eq!(node.peer_count(), 1);
    }

    #[test]
    fn peer_state_tracks_leases() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("peer-1");
        let leases = vec![HeldLease {
            subject_id: ObjectId::from_bytes([0xCC; 32]),
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 999_999,
            fencing_token: 9,
        }];

        node.update_peer_state(NodeId::new("peer-1"), profile, HashSet::new(), leases, 1000);
        assert_eq!(node.peer_count(), 1);
    }

    // ---- Gossip metric accumulation ----

    #[test]
    fn multiple_gossip_announcements_accumulate() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();

        for i in 0..5_u8 {
            let object_id = ObjectId::from_bytes([i; 32]);
            node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1000);
        }
        assert_eq!(node.metrics().gossip_announcements, 5);
    }

    #[test]
    fn symbol_announcements_accumulate() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0xAA; 32]);

        for esi in 0..3_u32 {
            node.announce_symbol(
                &zone_id,
                &object_id,
                esi,
                ObjectAdmissionClass::Admitted,
                1000,
            );
        }
        assert_eq!(node.metrics().gossip_announcements, 3);
    }

    // ---- Metrics cloning ----

    #[test]
    fn mesh_node_metrics_default() {
        let m = MeshNodeMetrics::default();
        assert_eq!(m.gossip_announcements, 0);
        assert_eq!(m.gossip_updates, 0);
        assert_eq!(m.peer_updates, 0);
    }

    #[test]
    fn mesh_node_metrics_debug_clone() {
        let m = MeshNodeMetrics {
            gossip_announcements: 10,
            gossip_updates: 5,
            peer_updates: 3,
            ..Default::default()
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("MeshNodeMetrics"));
        assert_eq!(m.gossip_announcements, 10);
        assert_eq!(m.peer_updates, 3);
    }

    // ---- PeerState ----

    #[test]
    fn peer_state_debug_clone() {
        let state = PeerState {
            profile: test_device_profile("peer-1"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
            zones: HashSet::new(),
            protocol_capabilities: PeerProtocolCapabilities::default(),
            last_seen_ms: 5000,
        };
        let dbg = format!("{state:?}");
        assert!(dbg.contains("PeerState"));
        assert_eq!(state.last_seen_ms, 5000);
    }

    // ---- Planner input edge cases ----

    #[test]
    fn build_planner_input_with_only_peers_no_local() {
        let mut node = test_node("node-1");
        let peer_profile = test_device_profile("peer-1");
        node.update_peer_state(
            NodeId::new("peer-1"),
            peer_profile,
            HashSet::new(),
            vec![],
            1000,
        );

        let input = node.build_planner_input(2000);
        // Only peer included, no local
        assert_eq!(input.nodes.len(), 1);
    }

    #[test]
    fn build_planner_input_with_multiple_peers() {
        let mut node = test_node("node-1");
        let local_profile = test_device_profile("node-1");
        node.update_local_state(local_profile, HashSet::new(), vec![]);

        for i in 0..5 {
            let name = format!("peer-{i}");
            let profile = test_device_profile(&name);
            node.update_peer_state(NodeId::new(&name), profile, HashSet::new(), vec![], 1000);
        }

        let input = node.build_planner_input(2000);
        assert_eq!(input.nodes.len(), 6); // 1 local + 5 peers
    }

    // ---- Transport path selection ----

    #[test]
    fn rank_transport_all_allowed() {
        let node = test_node("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, NodeId::new("p1"), "d", None),
            TransportPath::new(TransportPathKind::Derp, NodeId::new("p2"), "r", None),
            TransportPath::new(TransportPathKind::Funnel, NodeId::new("p3"), "f", None),
        ];

        let ranked = node.rank_transport_paths(&policy, &paths);
        assert_eq!(ranked.len(), 3);
        assert!(ranked.iter().all(|r| r.eligible));
    }

    #[test]
    fn rank_transport_empty_paths() {
        let node = test_node("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let ranked = node.rank_transport_paths(&policy, &[]);
        assert!(ranked.is_empty());
    }

    // ---- Peer signing keys ----

    #[test]
    fn register_peer_signing_key() {
        let mut node = test_node("node-1");
        let key = Ed25519SigningKey::generate();
        let peer = NodeId::new("peer-1");

        node.register_peer_signing_key(peer, key.verifying_key());
        // No panic, key registered successfully
    }

    // ---- Trace snapshot without capture ----

    #[test]
    fn trace_snapshot_without_capture_returns_none() {
        let node = test_node("node-1"); // no trace capture
        assert!(node.trace_snapshot().is_none());
    }

    #[test]
    fn trace_snapshot_with_capture_returns_some() {
        let node = test_node_with_trace("node-1");
        let snapshot = node.trace_snapshot();
        assert!(snapshot.is_some());
        assert!(snapshot.unwrap().events.is_empty());
    }

    // ---- Local state symbols ----

    #[test]
    fn update_local_state_with_symbols() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("node-1");
        let mut symbols = HashSet::new();
        symbols.insert(ObjectId::from_bytes([0xAA; 32]));
        symbols.insert(ObjectId::from_bytes([0xBB; 32]));

        node.update_local_state(profile, symbols, vec![]);
        assert!(node.local_profile.is_some());
    }

    #[test]
    fn update_local_state_with_leases() {
        let mut node = test_node("node-1");
        let profile = test_device_profile("node-1");
        let leases = vec![
            HeldLease {
                subject_id: ObjectId::from_bytes([0xAA; 32]),
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 999_999,
                fencing_token: 3,
            },
            HeldLease {
                subject_id: ObjectId::from_bytes([0xBB; 32]),
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 999_999,
                fencing_token: 4,
            },
        ];

        node.update_local_state(profile, HashSet::new(), leases);
        assert!(node.local_profile.is_some());
    }

    // ---- Multiple acks accumulate ----

    #[test]
    fn multiple_acks_accumulate_metric() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        let zone_id = ZoneId::work();

        for i in 0..3_u8 {
            let object_id = ObjectId::from_bytes([i; 32]);
            let mut ack = SymbolAck::new(
                test_object_header(),
                object_id,
                zone_id.clone(),
                ZoneKeyId::from_bytes([i; 8]),
                1,
                TailscaleNodeId::new("node-1"),
                u64::from(i),
                SymbolAckReason::Complete,
                5,
            );
            ack.sign(&signing_key);
            node.handle_symbol_ack(&peer, &ack, 1000)
                .expect("ack should verify");
        }
        assert_eq!(node.metrics().symbol_requests.acks_received, 3);
    }

    // ---- Peer update metric accumulation ----

    #[test]
    fn multiple_peer_updates_accumulate() {
        let mut node = test_node("node-1");
        for i in 0..4 {
            let name = format!("peer-{i}");
            let profile = test_device_profile(&name);
            node.update_peer_state(NodeId::new(&name), profile, HashSet::new(), vec![], 1000);
        }
        assert_eq!(node.metrics().peer_updates, 4);
    }

    // ---- Signing key management ----

    #[test]
    fn register_and_remove_peer_signing_key() {
        let mut node = test_node("node-1");
        let key = Ed25519SigningKey::generate();
        let peer = NodeId::new("peer-1");
        node.register_peer_signing_key(peer.clone(), key.verifying_key());
        node.remove_peer_signing_key(&peer);
        // Removing again is a no-op
        node.remove_peer_signing_key(&peer);
    }

    #[test]
    fn remove_peer_clears_signing_key() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let key = Ed25519SigningKey::generate();
        let profile = test_device_profile("peer-1");

        node.register_peer_signing_key(peer.clone(), key.verifying_key());
        node.update_peer_state(peer.clone(), profile, HashSet::new(), vec![], 1000);
        assert_eq!(node.peer_count(), 1);

        node.remove_peer(&peer);
        assert_eq!(node.peer_count(), 0);
        // Signing key should also be gone (no panic on double remove)
        node.remove_peer_signing_key(&peer);
    }

    // ---- Session + peer removal interaction ----

    #[test]
    fn remove_peer_with_active_session_cleans_up() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let profile = test_device_profile("peer-1");
        let session = test_session("peer-1");

        node.update_peer_state(peer.clone(), profile, HashSet::new(), vec![], 1000);
        node.register_session(session, 1000);
        assert!(node.is_peer_authenticated(&peer));

        node.remove_peer(&peer);
        assert!(!node.is_peer_authenticated(&peer));
        assert_eq!(node.peer_count(), 0);
    }

    #[test]
    fn remove_peer_without_session_still_clears_auth() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let profile = test_device_profile("peer-1");

        node.update_peer_state(peer.clone(), profile, HashSet::new(), vec![], 1000);
        // No session registered
        node.remove_peer(&peer);
        assert_eq!(node.peer_count(), 0);
        assert!(!node.is_peer_authenticated(&peer));
    }

    // ---- Trace capture edge cases ----

    #[test]
    fn trace_redacted_snapshot_returns_none_without_capture() {
        let node = test_node("node-1");
        assert!(node.trace_redacted_snapshot().is_none());
    }

    #[test]
    fn trace_redacted_snapshot_returns_some_with_capture() {
        let node = test_node_with_trace("node-1");
        let snapshot = node.trace_redacted_snapshot();
        assert!(snapshot.is_some());
    }

    #[test]
    fn trace_capture_records_gossip_events() {
        let mut node = test_node_with_trace("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0xEE; 32]);

        node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1000);

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        let gossip_count = snapshot
            .events
            .iter()
            .filter(|e| matches!(e, TraceEvent::Gossip(_)))
            .count();
        assert_eq!(gossip_count, 1);
    }

    #[test]
    fn trace_capture_records_routing_decisions() {
        let mut node = test_node_with_trace("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![TransportPath::new(
            TransportPathKind::Direct,
            NodeId::new("peer-1"),
            "direct",
            None,
        )];
        let object_id = test_object_id("routing-test");

        let _ = node.select_transport_paths(&policy, &paths, &object_id, 0, 1);

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        let routing_count = snapshot
            .events
            .iter()
            .filter(|e| matches!(e, TraceEvent::Routing(_)))
            .count();
        assert!(routing_count > 0);
    }

    #[test]
    fn trace_capture_routing_no_path_records_dropped() {
        let mut node = test_node_with_trace("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        };
        let paths = vec![TransportPath::new(
            TransportPathKind::Derp,
            NodeId::new("peer-1"),
            "derp",
            None,
        )];
        let object_id = test_object_id("routing-dropped");

        let selected = node.select_transport_paths(&policy, &paths, &object_id, 0, 1);
        assert!(selected.is_empty());

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        let routing_count = snapshot
            .events
            .iter()
            .filter(|e| matches!(e, TraceEvent::Routing(_)))
            .count();
        assert!(routing_count > 0);
    }

    #[test]
    fn ingest_trace_event_fails_without_capture() {
        let mut node = test_node("node-1"); // no trace capture
        let event = TraceEvent::Session(SessionEvent {
            timestamp: 1000,
            trace_id: "test".to_string(),
            session_id: "sess-1".to_string(),
            kind: "established".to_string(),
            peer_node: "peer-1".to_string(),
            suite: None,
            failure_reason: None,
        });
        let result = node.ingest_trace_event_for_replay(event);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MeshNodeError::TraceNotEnabled
        ));
    }

    #[test]
    fn ingest_trace_event_succeeds_with_capture() {
        let mut node = test_node_with_trace("node-1");
        let event = TraceEvent::Session(SessionEvent {
            timestamp: 1000,
            trace_id: "test".to_string(),
            session_id: "sess-1".to_string(),
            kind: "established".to_string(),
            peer_node: "peer-1".to_string(),
            suite: None,
            failure_reason: None,
        });
        let result = node.ingest_trace_event_for_replay(event);
        assert!(result.is_ok());

        let snapshot = node.trace_snapshot().unwrap();
        assert_eq!(snapshot.events.len(), 1);
        assert!(snapshot.redacted);
        if let TraceEvent::Session(session) = &snapshot.events[0] {
            assert_eq!(session.session_id, "[REDACTED]");
        }
    }

    // ---- Export trace to path ----

    #[test]
    fn export_trace_fails_without_capture() {
        let node = test_node("node-1");
        let result = node.export_trace_to_path("/tmp/test.json", TraceExportFormat::Json);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MeshNodeError::TraceNotEnabled
        ));
    }

    #[test]
    fn export_trace_redacts_mesh_identifiers_by_default() {
        let mut node = test_node_with_trace("mesh-node-secret-lmp9l");
        let owner_public_key = "mesh-owner-public-key-cleartext-lmp9l";
        let signed_head_bytes = "mesh-signed-head-bytes-cleartext-lmp9l";
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fcp-mesh-lmp9l-default-{}-{nonce}.json",
            std::process::id()
        ));

        node.ingest_trace_event_for_replay(TraceEvent::Session(SessionEvent {
            timestamp: 1,
            trace_id: "mesh-trace-secret-lmp9l".to_string(),
            session_id: "mesh-session-secret-lmp9l".to_string(),
            kind: "established".to_string(),
            peer_node: "mesh-peer-secret-lmp9l".to_string(),
            suite: Some("suite-test".to_string()),
            failure_reason: None,
        }))
        .expect("record session trace event");
        node.ingest_trace_event_for_replay(TraceEvent::Policy(
            fcp_telemetry::trace_capture::PolicyDecision {
                timestamp: 2,
                trace_id: "mesh-trace-secret-lmp9l".to_string(),
                zone_id: "z:mesh-secret-lmp9l".to_string(),
                operation: "invoke".to_string(),
                connector_id: "mesh-connector-secret-lmp9l".to_string(),
                decision: "allow".to_string(),
                reason_code: "OK".to_string(),
                evidence: vec![owner_public_key.to_string(), signed_head_bytes.to_string()],
            },
        ))
        .expect("record policy trace event");

        node.export_trace_to_path(&path, TraceExportFormat::Json)
            .expect("export redacted mesh trace");

        let json = std::fs::read_to_string(&path).expect("read exported mesh trace");
        for leaked in [
            "mesh-node-secret-lmp9l",
            "mesh-peer-secret-lmp9l",
            "mesh-session-secret-lmp9l",
            "z:mesh-secret-lmp9l",
            "mesh-connector-secret-lmp9l",
            owner_public_key,
            signed_head_bytes,
        ] {
            assert!(!json.contains(leaked), "mesh trace export leaked {leaked}");
        }
        assert!(json.contains("[REDACTED]"));
    }

    // ---- Planner singleton holder from peer ----

    #[test]
    fn build_planner_input_detects_peer_singleton_holder() {
        let mut node = test_node("node-1");
        let local_profile = test_device_profile("node-1");
        node.update_local_state(local_profile, HashSet::new(), vec![]);

        let peer_profile = test_device_profile("peer-1");
        let lease = HeldLease {
            subject_id: ObjectId::from_bytes([0xDD; 32]),
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 999_999,
            fencing_token: 5,
        };
        node.update_peer_state(
            NodeId::new("peer-1"),
            peer_profile,
            HashSet::new(),
            vec![lease],
            1000,
        );

        let input = node.build_planner_input(1000);
        assert_eq!(input.nodes.len(), 2);
        assert!(input.singleton_lease_holder.is_some());
        assert_eq!(input.singleton_lease_holder.as_deref(), Some("peer-1"));
    }

    #[test]
    fn build_planner_input_expired_lease_no_singleton() {
        let mut node = test_node("node-1");
        let local_profile = test_device_profile("node-1");
        let lease = HeldLease {
            subject_id: ObjectId::from_bytes([0xCC; 32]),
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 0, // Already expired
            fencing_token: 2,
        };

        node.update_local_state(local_profile, HashSet::new(), vec![lease]);
        // now_ms = 5000 => lease expired at 0 secs, now_secs = 5
        let input = node.build_planner_input(5000);
        assert_eq!(input.nodes.len(), 1);
        assert!(input.singleton_lease_holder.is_none());
    }

    #[test]
    fn build_planner_input_prefers_highest_fencing_token_holder() {
        let mut node = test_node("node-1");
        let subject_id = ObjectId::from_bytes([0xEF; 32]);
        node.update_local_state(
            test_device_profile("node-1"),
            HashSet::new(),
            vec![HeldLease {
                subject_id,
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 999_999,
                fencing_token: 7,
            }],
        );
        node.update_peer_state(
            NodeId::new("peer-1"),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![HeldLease {
                subject_id,
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 999_999,
                fencing_token: 9,
            }],
            1000,
        );

        let input = node.build_planner_input(1000);
        assert_eq!(input.singleton_lease_holder.as_deref(), Some("peer-1"));
    }

    #[test]
    fn plan_execution_ignores_unrelated_singleton_leases_when_subject_bound() {
        use crate::device::{DeviceProfileBuilder, InstalledConnector};

        let mut node = test_node("node-1");
        let connector_id =
            fcp_core::ConnectorId::new("fcp.test", "test", "v1").expect("valid connector id");
        let installed = InstalledConnector::new(
            connector_id.clone(),
            "1.0.0",
            ObjectId::from_bytes([0xAB; 32]),
        );
        let target_subject = ObjectId::from_bytes([0xAC; 32]);
        let unrelated_subject = ObjectId::from_bytes([0xAD; 32]);

        let local_profile = DeviceProfileBuilder::new(NodeId::new("node-1"))
            .add_connector(installed.clone())
            .build();
        let peer_profile = DeviceProfileBuilder::new(NodeId::new("peer-1"))
            .add_connector(installed)
            .build();

        node.update_local_state(
            local_profile,
            HashSet::new(),
            vec![HeldLease {
                subject_id: target_subject,
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 999_999,
                fencing_token: 5,
            }],
        );
        node.update_peer_state(
            NodeId::new("peer-1"),
            peer_profile,
            HashSet::new(),
            vec![HeldLease {
                subject_id: unrelated_subject,
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 999_999,
                fencing_token: 99,
            }],
            1000,
        );

        let context = PlannerContext::new(connector_id)
            .with_singleton_writer()
            .with_authority_subject(target_subject);
        let candidates = node.plan_execution(&context, 1000);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-1");
    }

    #[test]
    fn authority_view_reports_records_and_timeline() {
        let mut node = test_node("node-1");
        let subject_id = ObjectId::from_bytes([0xAE; 32]);

        node.update_local_state(
            test_device_profile("node-1"),
            HashSet::new(),
            vec![HeldLease {
                subject_id,
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 999_999,
                fencing_token: 7,
            }],
        );
        node.update_peer_state(
            NodeId::new("peer-1"),
            test_device_profile("peer-1"),
            HashSet::new(),
            vec![HeldLease {
                subject_id,
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 999_999,
                fencing_token: 9,
            }],
            1_000,
        );

        let authority = node.authority_view(
            &ZoneId::work(),
            &subject_id,
            LeasePurpose::SingletonWriter,
            1_000,
        );

        assert_eq!(
            authority
                .active_holder
                .as_ref()
                .map(TailscaleNodeId::as_str),
            Some("peer-1")
        );
        assert_eq!(authority.active_fencing_token, Some(9));
        assert_eq!(authority.records.len(), 2);
        assert_eq!(
            authority.records[0].status,
            crate::authority::AuthorityStatus::Active
        );
        assert_eq!(
            authority.records[0].reason_code,
            crate::authority::AuthorityReasonCode::ActiveAuthority
        );
        assert_eq!(
            authority.records[1].status,
            crate::authority::AuthorityStatus::Superseded
        );
        assert_eq!(
            authority.records[1].reason_code,
            crate::authority::AuthorityReasonCode::SupersededByPreferredLease
        );
        assert_eq!(
            authority
                .timeline
                .iter()
                .map(|event| event.operation.as_str())
                .collect::<Vec<_>>(),
            vec![
                "coordinator_selected",
                "authority_active",
                "authority_superseded"
            ]
        );
        assert_eq!(
            authority.coordinator.as_ref(),
            authority.failover_order.first()
        );
    }

    #[test]
    fn plan_execution_requires_subject_for_singleton_enforcement() {
        use crate::device::{DeviceProfileBuilder, InstalledConnector};

        let mut node = test_node("node-1");
        let connector_id =
            fcp_core::ConnectorId::new("fcp.test", "test", "v1").expect("valid connector id");
        let installed = InstalledConnector::new(
            connector_id.clone(),
            "1.0.0",
            ObjectId::from_bytes([0xBA; 32]),
        );

        let local_profile = DeviceProfileBuilder::new(NodeId::new("node-1"))
            .add_connector(installed.clone())
            .build();
        let peer_profile = DeviceProfileBuilder::new(NodeId::new("peer-1"))
            .add_connector(installed)
            .build();

        node.update_local_state(local_profile, HashSet::new(), Vec::new());
        node.update_peer_state(
            NodeId::new("peer-1"),
            peer_profile,
            HashSet::new(),
            vec![HeldLease {
                subject_id: ObjectId::from_bytes([0xBB; 32]),
                purpose: LeasePurpose::SingletonWriter,
                expires_at: 999_999,
                fencing_token: 42,
            }],
            1_000,
        );

        let context = PlannerContext::new(connector_id).with_singleton_writer();
        let candidates = node.plan_execution(&context, 1_000);

        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.node_id.as_str() == "node-1"),
            "local node should remain eligible without a bound authority subject"
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.node_id.as_str() == "peer-1"),
            "peer node should remain eligible without a bound authority subject"
        );
    }

    // ---- Admission reason codes ----

    #[test]
    fn admission_reason_code_coverage() {
        assert_eq!(
            MeshNode::admission_reason_code(&AdmissionError::ByteBudgetExceeded {
                current: 100,
                limit: 50,
                retry_after: std::time::Duration::from_secs(30),
            }),
            "byte_budget_exceeded"
        );
        assert_eq!(
            MeshNode::admission_reason_code(&AdmissionError::SymbolBudgetExceeded {
                current: 10,
                limit: 5,
                retry_after: std::time::Duration::from_secs(30),
            }),
            "symbol_budget_exceeded"
        );
        assert_eq!(
            MeshNode::admission_reason_code(&AdmissionError::AuthenticationRequired),
            "authentication_required"
        );
        assert_eq!(
            MeshNode::admission_reason_code(&AdmissionError::ProofOfNeedRequired),
            "proof_of_need_required"
        );
        assert_eq!(
            MeshNode::admission_reason_code(&AdmissionError::ObjectQuarantined {
                object_id: "test".to_string(),
            }),
            "object_quarantined"
        );
    }

    #[test]
    fn symbol_request_reason_code_coverage() {
        assert_eq!(
            MeshNode::symbol_request_reason_code(&SymbolRequestError::InvalidRequest {
                reason: "bad".to_string(),
            }),
            "invalid_request"
        );
        assert_eq!(
            MeshNode::symbol_request_reason_code(&SymbolRequestError::BoundsExceeded {
                requested: 100,
                max_allowed: 50,
            }),
            "bounds_exceeded"
        );
        assert_eq!(
            MeshNode::symbol_request_reason_code(&SymbolRequestError::SignatureInvalid),
            "signature_invalid"
        );
        assert_eq!(
            MeshNode::symbol_request_reason_code(&SymbolRequestError::AlreadyComplete {
                object_id: "test".to_string(),
            }),
            "already_complete"
        );
        assert_eq!(
            MeshNode::symbol_request_reason_code(&SymbolRequestError::ObjectNotFound {
                object_id: "test".to_string(),
            }),
            "object_not_found"
        );
    }

    // ---- Trace zone filtering ----

    #[test]
    fn trace_zone_enabled_no_filter_always_true() {
        let node = test_node("node-1");
        assert!(node.trace_zone_enabled(None));
        assert!(node.trace_zone_enabled(Some(&ZoneId::work())));
        assert!(node.trace_zone_enabled(Some(&ZoneId::private())));
    }

    #[test]
    fn trace_zone_enabled_with_allowlist() {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
        let node = MeshNode::new(
            MeshNodeConfig::new("node-1")
                .with_sender_instance_id(42)
                .with_trace_capture_zones([ZoneId::work()]),
            object_store,
            symbol_store,
            quarantine_store,
        );

        assert!(node.trace_zone_enabled(None));
        assert!(node.trace_zone_enabled(Some(&ZoneId::work())));
        assert!(!node.trace_zone_enabled(Some(&ZoneId::private())));
    }

    // ---- Lease delta tracking ----

    #[test]
    fn trace_records_lease_release_on_removal() {
        let mut node = test_node_with_trace("node-1");
        let lease = HeldLease {
            subject_id: test_object_id("lease-release"),
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 100,
            fencing_token: 1,
        };

        // First add a lease
        node.update_local_state(test_device_profile("node-1"), HashSet::new(), vec![lease]);
        // Then remove it
        node.update_local_state(test_device_profile("node-1"), HashSet::new(), vec![]);

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        let lease_count = snapshot
            .events
            .iter()
            .filter(|e| matches!(e, TraceEvent::Lease(_)))
            .count();
        assert!(lease_count >= 2, "should have acquire + release");
    }

    #[test]
    fn trace_records_lease_renew_on_expiry_change() {
        let mut node = test_node_with_trace("node-1");
        let obj_id = test_object_id("lease-renew");

        let lease_v1 = HeldLease {
            subject_id: obj_id,
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 100,
            fencing_token: 1,
        };
        let lease_v2 = HeldLease {
            subject_id: obj_id,
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 200,
            fencing_token: 2,
        };

        node.update_local_state(
            test_device_profile("node-1"),
            HashSet::new(),
            vec![lease_v1],
        );
        node.update_local_state(
            test_device_profile("node-1"),
            HashSet::new(),
            vec![lease_v2],
        );

        let snapshot = node.trace_snapshot().expect("trace capture enabled");
        let lease_count = snapshot
            .events
            .iter()
            .filter(|e| matches!(e, TraceEvent::Lease(_)))
            .count();
        // Should have acquire + renew
        assert!(lease_count >= 2);
    }

    // ---- MeshNodeConfig clone ----

    #[test]
    fn config_clone_preserves_all_fields() {
        let config = MeshNodeConfig::new("node-clone")
            .with_sender_instance_id(12345)
            .with_trace_capture_config(TraceCaptureConfig::new().enabled())
            .with_trace_capture_zones([ZoneId::work()]);
        let cloned = config.clone();
        // Verify original
        assert_eq!(config.node_id, "node-clone");
        assert_eq!(config.sender_instance_id, 12345);
        // Verify clone
        assert_eq!(cloned.node_id, "node-clone");
        assert!(cloned.trace_capture.enabled);
        assert!(cloned.trace_capture_zones.is_some());
    }

    // ---- MeshNodeMetrics clone ----

    #[test]
    fn mesh_node_metrics_clone_preserves_values() {
        let m = MeshNodeMetrics {
            gossip_announcements: 42,
            gossip_updates: 7,
            peer_updates: 13,
            ..Default::default()
        };
        let cloned = m.clone();
        // Verify original
        assert_eq!(m.gossip_announcements, 42);
        assert_eq!(m.gossip_updates, 7);
        // Verify clone
        assert_eq!(cloned.gossip_announcements, 42);
        assert_eq!(cloned.peer_updates, 13);
    }

    // ---- PeerState clone ----

    #[test]
    fn peer_state_clone_preserves_fields() {
        let mut symbols = HashSet::new();
        symbols.insert(ObjectId::from_bytes([0x11; 32]));

        let leases = vec![HeldLease {
            subject_id: ObjectId::from_bytes([0x22; 32]),
            purpose: LeasePurpose::SingletonWriter,
            expires_at: 5000,
            fencing_token: 6,
        }];

        let state = PeerState {
            profile: test_device_profile("peer-1"),
            local_symbols: symbols,
            held_leases: leases,
            zones: HashSet::new(),
            protocol_capabilities: PeerProtocolCapabilities::default(),
            last_seen_ms: 3000,
        };
        let cloned = state.clone();
        // Verify original
        assert_eq!(state.last_seen_ms, 3000);
        assert_eq!(state.local_symbols.len(), 1);
        // Verify clone
        assert_eq!(cloned.held_leases.len(), 1);
        assert_eq!(cloned.profile.node_id.as_str(), "peer-1");
    }

    // ---- Best transport path ----

    #[test]
    fn best_transport_path_returns_best_eligible() {
        let node = test_node("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        };

        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, NodeId::new("p1"), "direct", None),
            TransportPath::new(TransportPathKind::Derp, NodeId::new("p2"), "derp", None),
            TransportPath::new(TransportPathKind::Funnel, NodeId::new("p3"), "funnel", None),
        ];

        let best = node.best_transport_path(&policy, &paths);
        assert!(best.is_some());
        // Direct should be preferred
        assert_eq!(best.unwrap().path.kind, TransportPathKind::Direct);
    }

    #[test]
    fn best_transport_path_empty_paths_returns_none() {
        let node = test_node("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let best = node.best_transport_path(&policy, &[]);
        assert!(best.is_none());
    }

    // ---- Select transport multipath ----

    #[test]
    fn select_transport_paths_fanout_multiple() {
        let mut node = test_node("node-1");
        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };
        let paths = vec![
            TransportPath::new(TransportPathKind::Direct, NodeId::new("p1"), "d", None),
            TransportPath::new(TransportPathKind::Mesh, NodeId::new("p2"), "m", None),
            TransportPath::new(TransportPathKind::Derp, NodeId::new("p3"), "r", None),
        ];
        let object_id = test_object_id("fanout-test");

        let selected = node.select_transport_paths(&policy, &paths, &object_id, 0, 3);
        // Should select up to 3 paths
        assert!(!selected.is_empty());
        assert!(selected.len() <= 3);
    }

    // ---- Decode status ----

    #[test]
    fn handle_decode_status_with_missing_hint() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());
        let object_id = ObjectId::from_bytes([0x55; 32]);

        let mut status = DecodeStatus {
            header: test_object_header(),
            object_id,
            zone_id: ZoneId::work(),
            zone_key_id: ZoneKeyId::from_bytes([0x66; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-1"),
            request_nonce: 303,
            received_unique: 5,
            needed: 3,
            complete: false,
            missing_hint: Some(vec![1, 2, 3]),
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        status.sign(&signing_key);

        node.handle_decode_status(&peer, &status, 2000)
            .expect("status should verify");
    }

    #[test]
    fn handle_decode_status_rejects_replay_to_different_recipient() {
        let mut node = test_node("node-2");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());

        let mut status = DecodeStatus {
            header: test_object_header(),
            object_id: ObjectId::from_bytes([0x88; 32]),
            zone_id: ZoneId::work(),
            zone_key_id: ZoneKeyId::from_bytes([0x89; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-1"),
            request_nonce: 404,
            received_unique: 1,
            needed: 2,
            complete: false,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        status.sign(&signing_key);

        let err = node
            .handle_decode_status(&peer, &status, 1000)
            .expect_err("replay to a different recipient should be rejected");
        assert!(matches!(
            err,
            MeshNodeError::RecipientMismatch {
                message_kind: "decode status",
                ..
            }
        ));
    }

    #[test]
    fn handle_symbol_ack_rejects_replay_to_different_recipient() {
        let mut node = test_node("node-2");
        let peer = NodeId::new("peer-1");
        let signing_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), signing_key.verifying_key());

        let mut ack = SymbolAck::new(
            test_object_header(),
            ObjectId::from_bytes([0x90; 32]),
            ZoneId::work(),
            ZoneKeyId::from_bytes([0x91; 8]),
            1,
            TailscaleNodeId::new("node-1"),
            505,
            SymbolAckReason::Complete,
            3,
        );
        ack.sign(&signing_key);

        let err = node
            .handle_symbol_ack(&peer, &ack, 1000)
            .expect_err("replay to a different recipient should be rejected");
        assert!(matches!(
            err,
            MeshNodeError::RecipientMismatch {
                message_kind: "symbol ack",
                ..
            }
        ));
    }

    // ---- Forged-signature rejection for DecodeStatus / SymbolAck ----
    //
    // These two handlers verify the inbound message against the
    // *registered* peer key before touching symbol-request state. The
    // existing positive-path and recipient-mismatch tests cover the
    // happy path and the recipient-rebinding replay; neither exercises
    // the case where a valid Ed25519 signature is produced by a key
    // *other* than the one the local node registered for that peer.
    // The memory-note audit that flagged these handlers as "unverified"
    // was stale: verification is in place (node.rs:1640, node.rs:1664),
    // but the forged-key path had no regression guard, so a
    // `verify()` call accidentally downgraded to `Ok(())` (e.g. during
    // a crypto refactor) would have gone undetected. These tests close
    // that coverage gap.

    #[test]
    fn handle_decode_status_rejects_forged_signature() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let registered_key = Ed25519SigningKey::generate();
        let attacker_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), registered_key.verifying_key());

        let mut status = DecodeStatus {
            header: test_object_header(),
            object_id: ObjectId::from_bytes([0xAA; 32]),
            zone_id: ZoneId::work(),
            zone_key_id: ZoneKeyId::from_bytes([0xAB; 8]),
            epoch_id: 1,
            recipient_node_id: TailscaleNodeId::new("node-1"),
            request_nonce: 606,
            received_unique: 4,
            needed: 1,
            complete: false,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };
        // Sign with a key that the local node NEVER registered for this
        // peer — the attacker's freshly-generated key. The local
        // `peer_signing_key(peer)` lookup resolves to `registered_key`,
        // and `verify()` must reject the forged signature.
        status.sign(&attacker_key);

        let err = node
            .handle_decode_status(&peer, &status, 1000)
            .expect_err("decode status signed by a non-registered key must be rejected");
        assert!(
            matches!(
                err,
                MeshNodeError::PeerSignatureInvalid {
                    message_kind: "decode status",
                    ..
                }
            ),
            "expected PeerSignatureInvalid for decode status, got {err:?}"
        );
        // Defensive: the handler must not have leaked the forged message
        // into `symbol_requests` state. A successful process_decode_status
        // would have observed `received_unique` on the request tracker;
        // here there is no request tracker entry at all, so the metric
        // we can safely assert on is that no decode-status-processed
        // side-effect ran — verified by the absence of an ack bump.
        assert_eq!(node.metrics().symbol_requests.acks_received, 0);
    }

    #[test]
    fn handle_symbol_ack_rejects_forged_signature() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");
        let registered_key = Ed25519SigningKey::generate();
        let attacker_key = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer.clone(), registered_key.verifying_key());

        let mut ack = SymbolAck::new(
            test_object_header(),
            ObjectId::from_bytes([0xBB; 32]),
            ZoneId::work(),
            ZoneKeyId::from_bytes([0xBC; 8]),
            1,
            TailscaleNodeId::new("node-1"),
            707,
            SymbolAckReason::Complete,
            6,
        );
        ack.sign(&attacker_key);

        let err = node
            .handle_symbol_ack(&peer, &ack, 1000)
            .expect_err("symbol ack signed by a non-registered key must be rejected");
        assert!(
            matches!(
                err,
                MeshNodeError::PeerSignatureInvalid {
                    message_kind: "symbol ack",
                    ..
                }
            ),
            "expected PeerSignatureInvalid for symbol ack, got {err:?}"
        );
        // The forged ack must not bump the ack metric nor clear
        // sent_symbols — a successful `handle_symbol_ack` would do both.
        assert_eq!(
            node.metrics().symbol_requests.acks_received,
            0,
            "forged ack must not increment acks_received"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Regression assembles full per-peer transfer state before and after ack.
    fn symbol_transfer_state_is_scoped_per_peer() {
        let mut node = test_node("node-ack");
        let peer_a = NodeId::new("peer-a");
        let peer_b = NodeId::new("peer-b");
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([0xCD; 8]);
        let object_id = ObjectId::from_bytes([0xCE; 32]);

        node.update_peer_zones(&peer_a, zone_set(zone_id.clone()));
        node.update_peer_zones(&peer_b, zone_set(zone_id.clone()));
        node.admission_mut().set_authenticated(&peer_a, true, 0);
        node.admission_mut().set_authenticated(&peer_b, true, 0);

        fcp_async_core::runtime::block_on_sync(async {
            let oti = ObjectTransmissionInformation::new(256, 64, 1, 1, 1);
            node.symbol_store
                .put_object_meta(ObjectSymbolMeta {
                    object_id,
                    zone_id: zone_id.clone(),
                    oti,
                    source_symbols: 4,
                    first_symbol_at: 0,
                })
                .await
                .expect("store meta");

            for esi in 0..4 {
                let symbol = StoredSymbol {
                    meta: SymbolMeta {
                        object_id,
                        esi,
                        zone_id: zone_id.clone(),
                        source_node: Some(1),
                        stored_at: 0,
                    },
                    data: bytes::Bytes::from(vec![u8::try_from(esi).unwrap_or(0); 64]),
                };
                node.symbol_store
                    .put_symbol(symbol)
                    .await
                    .expect("store symbol");
            }

            let request_a = SymbolRequest::new(
                test_object_header(),
                object_id,
                zone_id.clone(),
                zone_key_id,
                1,
                2,
                0,
            );
            let response_a = node
                .handle_symbol_request(request_a, &peer_a, true, 0)
                .await
                .expect("peer A request");

            let request_b = SymbolRequest::new(
                test_object_header(),
                object_id,
                zone_id.clone(),
                zone_key_id,
                1,
                2,
                0,
            );
            let response_b = node
                .handle_symbol_request(request_b, &peer_b, true, 1)
                .await
                .expect("peer B request");

            assert_eq!(
                response_b.symbol_esis, response_a.symbol_esis,
                "peer B must not inherit peer A's sent-symbol suppression"
            );
        })
        .expect("runtime");

        let signing_key_a = Ed25519SigningKey::generate();
        node.register_peer_signing_key(peer_a.clone(), signing_key_a.verifying_key());

        let mut ack = SymbolAck::new(
            test_object_header(),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            TailscaleNodeId::new("node-ack"),
            808,
            SymbolAckReason::Complete,
            2,
        );
        ack.sign(&signing_key_a);
        node.handle_symbol_ack(&peer_a, &ack, 2)
            .expect("peer A ack");

        assert!(
            node.symbol_requests.should_stop(&peer_a, &object_id),
            "ack must stop only peer A's transfer"
        );
        assert!(
            !node.symbol_requests.should_stop(&peer_b, &object_id),
            "peer B transfer must remain active"
        );

        let response_b_follow_up = fcp_async_core::runtime::block_on_sync(async {
            let request_b_follow_up = SymbolRequest::new(
                test_object_header(),
                object_id,
                zone_id,
                zone_key_id,
                1,
                2,
                2,
            );
            node.handle_symbol_request(request_b_follow_up, &peer_b, true, 3)
                .await
        })
        .expect("runtime")
        .expect("peer B follow-up request should still succeed");

        assert!(
            !response_b_follow_up.symbol_esis.is_empty(),
            "peer B should keep receiving symbols after peer A acked"
        );
    }

    // ---- Announce duplicate ----

    #[test]
    fn announce_same_object_twice_increments_both() {
        let mut node = test_node("node-1");
        let zone_id = ZoneId::work();
        let object_id = ObjectId::from_bytes([0x77; 32]);

        let first =
            node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1000);
        assert!(first);

        let second =
            node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1001);
        // Gossip tracks announcements even for previously announced objects
        if second {
            assert_eq!(node.metrics().gossip_announcements, 2);
        } else {
            assert_eq!(node.metrics().gossip_announcements, 1);
        }
    }

    // ---- transport_path_kind_label ----

    #[test]
    fn transport_path_kind_label_all_variants() {
        assert_eq!(
            transport_path_kind_label(TransportPathKind::Direct),
            "direct"
        );
        assert_eq!(transport_path_kind_label(TransportPathKind::Mesh), "mesh");
        assert_eq!(transport_path_kind_label(TransportPathKind::Derp), "derp");
        assert_eq!(
            transport_path_kind_label(TransportPathKind::Funnel),
            "funnel"
        );
    }

    // ---- MeshNodeError display ----

    #[test]
    fn mesh_node_error_degraded_transport_display() {
        let inner = DegradedTransportError::Incomplete {
            received: 5,
            needed: 10,
        };
        let err = MeshNodeError::DegradedTransport(inner);
        let display = err.to_string();
        assert!(display.contains("degraded transport error"));
    }

    // ---- Prune with no stale state ----

    #[test]
    fn prune_stale_state_returns_zero_when_clean() {
        let mut node = test_node("node-1");
        let pruned = node.prune_stale_state(100_000);
        assert_eq!(pruned, 0);
    }

    // ---- Additional MeshNodeError From conversions ----

    #[test]
    fn mesh_node_error_from_object_store_error() {
        let inner = fcp_store::ObjectStoreError::NotFound(ObjectId::from_bytes([0; 32]));
        let err = MeshNodeError::ObjectStore(inner);
        assert!(err.to_string().contains("object store error"));
    }

    #[test]
    fn mesh_node_error_from_symbol_store_error() {
        let inner = fcp_store::SymbolStoreError::ObjectNotFound(ObjectId::from_bytes([0; 32]));
        let err = MeshNodeError::SymbolStore(inner);
        assert!(err.to_string().contains("symbol store error"));
    }

    #[test]
    fn mesh_node_error_from_quarantine_error() {
        let inner = fcp_store::QuarantineError::QuotaExceeded { used: 100, max: 50 };
        let err = MeshNodeError::Quarantine(inner);
        assert!(err.to_string().contains("quarantine error"));
    }

    // ---- MeshNodeEnforcementError From conversions ----

    #[test]
    fn enforcement_error_from_invoke_validation() {
        let inner = InvokeValidationError::HolderProofRequired;
        let err: MeshNodeEnforcementError = inner.into();
        assert!(err.to_string().contains("invoke validation"));
    }

    #[test]
    fn enforcement_error_from_fcp_error() {
        let inner = FcpError::InvalidSignature;
        let err: MeshNodeEnforcementError = inner.into();
        assert!(err.to_string().contains("capability verification"));
    }

    // ---- Local state updates overwrite previous ----

    #[test]
    fn update_local_state_replaces_previous() {
        let mut node = test_node("node-1");
        let profile_v1 = DeviceProfileBuilder::new(NodeId::new("node-1"))
            .cpu_cores(4)
            .build();
        let profile_v2 = DeviceProfileBuilder::new(NodeId::new("node-1"))
            .cpu_cores(16)
            .build();

        node.update_local_state(profile_v1, HashSet::new(), vec![]);
        assert_eq!(node.local_profile.as_ref().unwrap().cpu_cores, 4);

        node.update_local_state(profile_v2, HashSet::new(), vec![]);
        assert_eq!(node.local_profile.as_ref().unwrap().cpu_cores, 16);
    }

    // ---- Peer update overwrites profile ----

    #[test]
    fn update_peer_state_replaces_profile() {
        let mut node = test_node("node-1");
        let peer = NodeId::new("peer-1");

        let profile_v1 = DeviceProfileBuilder::new(peer.clone()).cpu_cores(4).build();
        let profile_v2 = DeviceProfileBuilder::new(peer.clone())
            .cpu_cores(32)
            .build();

        node.update_peer_state(peer.clone(), profile_v1, HashSet::new(), vec![], 1000);
        node.update_peer_state(peer, profile_v2, HashSet::new(), vec![], 2000);

        assert_eq!(node.peer_count(), 1);
        assert_eq!(node.metrics().peer_updates, 2);
    }

    // ---- Trace capture not enabled -> no events ----

    #[test]
    fn session_events_not_traced_without_capture() {
        let mut node = test_node("node-1"); // no trace
        let session = test_session("peer-1");
        let peer_id = session.peer_id.clone();

        node.register_session(session, 1000);
        node.remove_session(&peer_id, 2000);

        // No trace capture, so trace_snapshot is None
        assert!(node.trace_snapshot().is_none());
    }

    // ---- Plan execution with no matching connector ----

    #[test]
    fn plan_execution_no_candidates_when_no_connector() {
        let mut node = test_node("node-1");
        let local_profile = test_device_profile("node-1"); // no connectors
        node.update_local_state(local_profile, HashSet::new(), vec![]);

        let ctx = PlannerContext::new(
            fcp_core::ConnectorId::new("fcp.test", "nonexistent", "v1")
                .expect("valid connector id"),
        );
        let candidates = node.plan_execution(&ctx, 2000);
        assert!(candidates.is_empty());
    }
}
