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
//! Discovery uses a shared refresh with bounded concurrency and a total
//! deadline. Failed peers are briefly negative-cached; inventories are always
//! authenticated and must remain within their signed freshness window.
//! Outbound RPCs share router-wide, per-peer, and serialized-request-byte
//! ceilings. Admission is fail-fast before network I/O, with no waiter queue;
//! cancellation releases reservations, including while reading a reply.
//! Environment-configured hosts sync accepted inbound nonces to a durable
//! journal before dispatch, preserving replay rejection across restarts.
//! Optional owner-signed membership pins the mesh identity and owner roots,
//! persists accepted generations, and refuses new mesh work after expiration.
//! File-backed signed membership hot-reloads complete peer snapshots, including
//! additions, removals, key rotations, and endpoint changes. Checkpoint commits
//! precede publication; replay journals and resource reservations are not reset.
//! A request crossing a membership generation change is conservatively refused.
//! Once network delivery may have occurred, that refusal is never retry-safe.
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
//! - `FCP_HOST_MESH_FORWARD_MAX_IN_FLIGHT` (optional, default 32).
//! - `FCP_HOST_MESH_FORWARD_MAX_PER_PEER` (optional, default 4).
//! - `FCP_HOST_MESH_FORWARD_MAX_REQUEST_BYTES` (optional, default 64 MiB).
//! - `FCP_HOST_MESH_REPLAY_JOURNAL` (optional) — persistent journal path;
//!   defaults to the signing-key filename with `.mesh-replay` appended.
//! - `FCP_HOST_MESH_ID`, `FCP_HOST_MESH_DIRECTORY_OWNER_KEYS`, and
//!   `FCP_HOST_MESH_DIRECTORY_STATE` select owner-signed membership together.
//!   The peer source then contains a signed directory rather than a raw array.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_mesh::invoke_route::{
    AdvertisedConnector, DEFAULT_MESH_FORWARD_MAX_SKEW_MS, DEFAULT_MESH_FORWARD_REPLAY_CAPACITY,
    MeshForwardBody, MeshForwardEnvelope, MeshForwardError, MeshForwardReplayGuard, MeshForwardReply,
    MeshPeer, MeshPeerAdvertisement, MeshPeerDirectory,
};
use zeroize::Zeroizing;

pub use crate::mesh_replay::MESH_REPLAY_JOURNAL_ENV;
use crate::mesh_replay::{
    DurableMeshReplayGuard, VerifiedMeshReplayNonce, companion, replay_unavailable,
};
use crate::{HostError, HostResult};

mod admission;
mod directory;
mod discovery;
mod inbound;

use inbound::InboundReplayWorker;

#[cfg(all(test, unix))]
mod inbound_tests;

use admission::{ForwardControl, LIMIT_ENV_KEYS};
pub use admission::{
    MESH_FORWARD_MAX_IN_FLIGHT_ENV, MESH_FORWARD_MAX_PER_PEER_ENV,
    MESH_FORWARD_MAX_REQUEST_BYTES_ENV, MeshForwardLimits, MeshForwardUsage,
};
use directory::{DIRECTORY_ENV_KEYS, DirectoryGuard};
pub use directory::{
    MESH_DIRECTORY_ID_ENV, MESH_DIRECTORY_OWNER_KEYS_ENV, MESH_DIRECTORY_STATE_ENV,
};
use discovery::PeerDiscovery;

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
            || timeout_raw.is_some()
            || LIMIT_ENV_KEYS.iter().any(|name| lookup(name).is_some())
            || DIRECTORY_ENV_KEYS.iter().any(|name| lookup(name).is_some())
            || lookup(MESH_REPLAY_JOURNAL_ENV).is_some();
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
            (None, Some(path)) => directory::read_peer_file(Path::new(&path))?,
            (None, None) => {
                return Err(invalid(format!(
                    "mesh routing requires {MESH_PEERS_ENV} or {MESH_PEERS_FILE_ENV}"
                )));
            }
        };
        if peers_json.len() > fcp_mesh::peer_manifest::MAX_SIGNED_MESH_PEER_DIRECTORY_BYTES {
            return Err(invalid(
                "peer directory source exceeds its byte limit".to_owned(),
            ));
        }

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
    /// The request never reached the peer (admission/connect/build failure).
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

/// Mesh routing state shared by every host request.
pub struct MeshRouter {
    // Static configuration and immutable local identity. Signed deployments
    // use the live directory guard for every routing/authentication decision.
    directory: Arc<MeshPeerDirectory>,
    empty_directory: Arc<MeshPeerDirectory>,
    signing_key: Ed25519SigningKey,
    replay_guard: Mutex<MeshForwardReplayGuard>,
    durable_replay: Option<Arc<Mutex<DurableMeshReplayGuard>>>,
    inbound_worker: Option<InboundReplayWorker>,
    advertisements: PeerDiscovery,
    forwards: ForwardControl,
    client: reqwest::Client,
    membership: Option<DirectoryGuard>,
}

impl std::fmt::Debug for MeshRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshRouter")
            .field("local_node", self.directory.local_node())
            .field("peer_count", &self.directory().len())
            .field("forward_limits", &self.forwards.limits())
            .field("durable_replay", &self.durable_replay.is_some())
            .field("owner_signed_membership", &self.membership.is_some())
            .finish_non_exhaustive()
    }
}

impl MeshRouter {
    /// Build an embedded router with default outbound resource ceilings.
    ///
    /// This constructor has process-local replay protection. Persistent hosts
    /// must use [`Self::from_env`] or [`Self::with_replay_journal`] instead.
    ///
    /// # Errors
    ///
    /// See [`Self::with_forward_limits`].
    pub fn new(settings: MeshRoutingSettings) -> HostResult<Self> {
        Self::with_forward_limits(settings, MeshForwardLimits::default())
    }

    /// Build an embedded router with explicit outbound ceilings and volatile replay state.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::InvalidFilter`] for invalid limits or a peer
    /// directory, or [`HostError::Internal`] when the HTTP client cannot be built.
    pub fn with_forward_limits(
        settings: MeshRoutingSettings,
        limits: MeshForwardLimits,
    ) -> HostResult<Self> {
        let forwards = ForwardControl::new(limits)?;
        let directory = MeshPeerDirectory::from_json(settings.node_id, &settings.peers_json)
            .map_err(|error| HostError::InvalidFilter(error.to_string()))?;
        let empty_directory = MeshPeerDirectory::from_configs(directory.local_node().clone(), &[])
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
            directory: Arc::new(directory),
            empty_directory: Arc::new(empty_directory),
            signing_key: settings.signing_key,
            replay_guard: Mutex::new(MeshForwardReplayGuard::new(
                DEFAULT_MESH_FORWARD_MAX_SKEW_MS,
                DEFAULT_MESH_FORWARD_REPLAY_CAPACITY,
            )),
            durable_replay: None,
            inbound_worker: None,
            advertisements: PeerDiscovery::new(),
            forwards,
            client,
            membership: None,
        })
    }

    /// Build a router whose inbound admission survives executor restarts.
    ///
    /// The journal is synced before an accepted envelope can reach dispatch.
    /// The path and its companion lock must remain on trusted persistent storage
    /// for the lifetime of the node identity; see [`DurableMeshReplayGuard`].
    ///
    /// # Errors
    ///
    /// Returns configuration, locking, recovery, or storage errors. Never falls
    /// back to volatile replay protection when persistent admission is unavailable.
    pub fn with_replay_journal(
        settings: MeshRoutingSettings,
        limits: MeshForwardLimits,
        path: &Path,
    ) -> HostResult<Self> {
        let mut router = Self::with_forward_limits(settings, limits)?;
        let replay = DurableMeshReplayGuard::open(
            path,
            router.local_node(),
            DEFAULT_MESH_FORWARD_MAX_SKEW_MS,
            DEFAULT_MESH_FORWARD_REPLAY_CAPACITY,
            unix_now_ms(),
        )?;
        let replay = Arc::new(Mutex::new(replay));
        router.inbound_worker = Some(InboundReplayWorker::spawn(Arc::clone(&replay))?);
        router.durable_replay = Some(replay);
        Ok(router)
    }

    /// Build a router from the process environment, if configured.
    ///
    /// # Errors
    ///
    /// See [`Self::from_lookup`].
    pub fn from_env() -> HostResult<Option<Self>> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Load routing, trust, admission, and durable replay settings through one view.
    ///
    /// Environment-configured hosts always use persistent replay protection. The
    /// default journal is adjacent to the signing key; an explicit path supports
    /// read-only secret mounts with a separate writable state volume.
    /// Signed membership additionally verifies independent owner roots, pins
    /// this node's signing key, and commits a generation checkpoint before use.
    ///
    /// # Errors
    ///
    /// Returns a startup error for partial routing configuration, malformed
    /// resource limits, or unavailable replay storage, never a silent fallback.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> HostResult<Option<Self>> {
        let limits = MeshForwardLimits::from_lookup(&lookup)?;
        let Some(mut settings) = MeshRoutingSettings::from_lookup(&lookup)? else {
            return Ok(None);
        };
        let prepared = directory::prepare(&lookup, &mut settings)?;
        let path = match lookup(MESH_REPLAY_JOURNAL_ENV) {
            Some(raw) => {
                let value = raw.trim();
                if value.is_empty() {
                    return Err(HostError::InvalidFilter(format!(
                        "{MESH_REPLAY_JOURNAL_ENV} must be a nonempty persistent file path"
                    )));
                }
                PathBuf::from(value)
            }
            None => {
                let key_file = lookup(MESH_SIGNING_KEY_FILE_ENV).ok_or_else(|| {
                    HostError::InvalidFilter(format!(
                        "mesh replay protection requires {MESH_SIGNING_KEY_FILE_ENV}"
                    ))
                })?;
                companion(Path::new(key_file.trim()), ".mesh-replay")
            }
        };
        let mut router = Self::with_replay_journal(settings, limits, &path)?;
        router.membership = prepared
            .map(directory::PreparedDirectory::activate)
            .transpose()?;
        Ok(Some(router))
    }

    /// Whether inbound admission uses a persistent, exclusively held journal.
    #[must_use]
    pub const fn has_durable_replay(&self) -> bool {
        self.durable_replay.is_some()
    }

    /// Whether this router enforces owner-signed, persistently checkpointed membership.
    ///
    /// This reports the configured trust mode, not current availability. An
    /// expired signed directory remains signed-mode and refuses new mesh work.
    #[must_use]
    pub const fn has_owner_signed_membership(&self) -> bool {
        self.membership.is_some()
    }

    fn ensure_membership_valid(&self) -> Result<(), MeshForwardError> {
        if let Some(membership) = &self.membership {
            membership.check()?;
        }
        Ok(())
    }

    fn trusted_directory(&self) -> Result<Arc<MeshPeerDirectory>, MeshForwardError> {
        match &self.membership {
            Some(membership) => membership.snapshot(),
            None => Ok(Arc::clone(&self.directory)),
        }
    }

    fn ensure_current_directory(
        &self,
        snapshot: &Arc<MeshPeerDirectory>,
    ) -> Result<(), MeshForwardError> {
        let current = self.trusted_directory()?;
        if !Arc::ptr_eq(&current, snapshot) {
            return Err(MeshForwardError::Malformed {
                field: "peer_directory",
                detail: "membership generation changed while the request was in flight".to_owned(),
            });
        }
        Ok(())
    }

    fn finish_inbound_admission(
        &self,
        envelope: &MeshForwardEnvelope,
        snapshot: &Arc<MeshPeerDirectory>,
    ) -> Result<(), MeshForwardError> {
        // Recheck after journal I/O without undoing a consumed nonce. Pointer
        // identity also fences removal followed by re-addition of the same key.
        envelope.verify(snapshot, unix_now_ms(), DEFAULT_MESH_FORWARD_MAX_SKEW_MS)?;
        self.ensure_current_directory(snapshot)
    }

    /// Effective outbound resource ceilings.
    #[must_use]
    pub const fn forward_limits(&self) -> MeshForwardLimits {
        self.forwards.limits()
    }

    /// Atomic snapshot of active forwards; no payload or credential contents.
    ///
    /// # Errors
    ///
    /// Returns an error if admission state is poisoned rather than reporting
    /// invented free capacity.
    pub fn forward_usage(&self) -> HostResult<MeshForwardUsage> {
        self.forwards.snapshot()
    }

    /// This node's id.
    #[must_use]
    pub fn local_node(&self) -> &TailscaleNodeId {
        self.directory.local_node()
    }

    /// Current routing snapshot, or an empty peer view while signed membership
    /// is unavailable. Existing snapshots never mutate or extend authority.
    /// Admission and forwarding independently check current membership, so
    /// retaining an old snapshot cannot authorize a removed peer.
    #[must_use]
    pub fn directory(&self) -> Arc<MeshPeerDirectory> {
        self.trusted_directory()
            .unwrap_or_else(|_| Arc::clone(&self.empty_directory))
    }

    /// Sign this node's advertisement, withdrawing inventory after membership expires.
    #[must_use]
    pub fn sign_advertisement(
        &self,
        connectors: Vec<AdvertisedConnector>,
    ) -> MeshPeerAdvertisement {
        let connectors = if self.ensure_membership_valid().is_ok() {
            connectors
        } else {
            Vec::new()
        };
        MeshPeerAdvertisement::sign(
            &self.signing_key,
            self.local_node().clone(),
            unix_now_ms(),
            connectors,
        )
    }

    /// Verify an inbound envelope and consume its nonce before dispatch.
    ///
    /// Persistent routers commit and sync the nonce before returning success.
    /// This synchronous API can block on disk I/O; async request handlers must
    /// use [`Self::accept_inbound_async`] to keep disk waits off their executor.
    /// The clock is sampled under the lock so concurrent callers cannot create
    /// apparent clock rollback by reaching admission in a different order.
    ///
    /// # Errors
    ///
    /// Returns the verification, replay, or persistent-admission error. Poisoned
    /// state fails closed rather than risking another dispatch of a consumed nonce.
    pub fn accept_inbound(&self, envelope: &MeshForwardEnvelope) -> Result<(), MeshForwardError> {
        self.ensure_membership_valid()?;
        if let Some(replay) = &self.durable_replay {
            let mut replay = replay
                .lock()
                .map_err(|_| replay_unavailable("state_poisoned"))?;
            let snapshot = self.trusted_directory()?;
            replay.accept(envelope, &snapshot, unix_now_ms())?;
            return self.finish_inbound_admission(envelope, &snapshot);
        }
        let mut replay = self
            .replay_guard
            .lock()
            .map_err(|_| replay_unavailable("state_poisoned"))?;
        let now_ms = unix_now_ms();
        let snapshot = self.trusted_directory()?;
        envelope.verify(&snapshot, now_ms, DEFAULT_MESH_FORWARD_MAX_SKEW_MS)?;
        replay.check_and_record(envelope, now_ms)?;
        self.finish_inbound_admission(envelope, &snapshot)
    }

    /// Authenticate and durably admit a forward without blocking on journal I/O.
    ///
    /// Only an opaque verified nonce identity enters the bounded worker queue;
    /// request bodies and credentials stay with the awaiting handler. A full
    /// queue fails immediately, and freshness is rechecked after all waits.
    /// Cancellation may consume a nonce without dispatching its operation. It
    /// never reverses an admission or permits another execution of that nonce.
    ///
    /// # Errors
    ///
    /// Returns authentication, freshness, replay, or admission-unavailable errors.
    /// Success is returned only after the journal has committed and synced.
    pub async fn accept_inbound_async(
        &self,
        envelope: &MeshForwardEnvelope,
    ) -> Result<(), MeshForwardError> {
        self.ensure_membership_valid()?;
        if let Some(worker) = &self.inbound_worker {
            let snapshot = self.trusted_directory()?;
            let identity = VerifiedMeshReplayNonce::verify(
                envelope,
                &snapshot,
                unix_now_ms(),
                DEFAULT_MESH_FORWARD_MAX_SKEW_MS,
            )?;
            worker.check(identity).await?;
            // A queue wait or durable sync may cross expiry or a key rotation.
            // Consuming a nonce without dispatch is safe; undoing it is not.
            return self.finish_inbound_admission(envelope, &snapshot);
        }
        if self.durable_replay.is_some() {
            // An internal wiring failure must not silently fall back to blocking
            // storage I/O or to the process-local replay guard.
            return Err(replay_unavailable("worker_not_configured"));
        }
        self.accept_inbound(envelope)
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
    /// Shared admission reserves a router slot, a peer slot, and the exact
    /// serialized request length before network I/O. Reservations remain held
    /// through reply verification and are released on completion or cancellation.
    ///
    /// # Errors
    ///
    /// Returns a [`MeshForwardFailure`] classifying whether the request may
    /// have executed on the peer. Admission refusals are never delivered.
    pub async fn forward(
        &self,
        target: &TailscaleNodeId,
        body: MeshForwardBody,
    ) -> Result<MeshForwardReply, MeshForwardFailure> {
        let peer_label = target.as_str().to_owned();
        let snapshot = self.trusted_directory()
            .map_err(|error| MeshForwardFailure::NotDelivered {
                peer: peer_label.clone(),
                detail: error.to_string(),
            })?;
        let Some(peer) = snapshot.peer(target) else {
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
        self.forwards
            .execute(&peer_label, payload.len(), || {
                self.forward_transport(peer, payload, &envelope, &snapshot)
            })
            .await
    }

    async fn forward_transport(
        &self,
        peer: &MeshPeer,
        payload: Vec<u8>,
        envelope: &MeshForwardEnvelope,
        snapshot: &Arc<MeshPeerDirectory>,
    ) -> Result<MeshForwardReply, MeshForwardFailure> {
        let peer_label = peer.node_id.as_str().to_owned();
        // Recheck after signing, serialization, and resource admission, before
        // constructing network work. No expired directory may initiate a send.
        self.ensure_current_directory(snapshot)
            .map_err(|error| MeshForwardFailure::NotDelivered {
                peer: peer_label.clone(),
                detail: error.to_string(),
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
            .verify_for(envelope, snapshot)
            .map_err(|error| MeshForwardFailure::InvalidReply {
                peer: peer_label.clone(),
                error,
            })?;
        // A request may already have executed when membership changes during I/O.
        // Refuse the result without ever reclassifying it as safe to replay.
        self.ensure_current_directory(snapshot)
            .map_err(|error| MeshForwardFailure::OutcomeUnknown {
                peer: peer_label,
                detail: error.to_string(),
            })?;
        Ok(reply)
    }

    /// Fresh, verified advertisements from reachable peers, in node-id order.
    ///
    /// Concurrent callers share one refresh. Discovery permits at most 16
    /// simultaneous peer fetches and has a five-second total deadline,
    /// including time waiting for another refresh. A deadline returns the
    /// completed, still-fresh inventories only; it never invents availability.
    pub async fn peer_advertisements(&self) -> Vec<MeshPeerAdvertisement> {
        let Ok(snapshot) = self.trusted_directory() else {
            self.advertisements.invalidate();
            return Vec::new();
        };
        let advertisements = self
            .advertisements
            .collect(&snapshot, |peer| async move {
                self.fetch_advertisement(&peer.endpoint).await
            })
            .await;
        if self.ensure_current_directory(&snapshot).is_err() {
            self.advertisements.invalidate();
            return Vec::new();
        }
        advertisements
    }

    /// Drop cached advertisements and fence pre-invalidation fetches.
    pub fn invalidate_advertisements(&self) {
        self.advertisements.invalidate();
    }

    async fn fetch_advertisement(&self, endpoint: &str) -> Result<MeshPeerAdvertisement, String> {
        self.ensure_membership_valid()
            .map_err(|error| error.to_string())?;
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
        self.ensure_membership_valid()
            .map_err(|error| error.to_string())?;
        // The discovery cache authenticates the result against the requested
        // node and directory before accepting it, including signed freshness.
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("advertisement is not valid JSON: {error}"))
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

    #[test]
    fn router_loads_admission_limits_without_ambient_environment() {
        assert!(MeshRouter::from_lookup(|_| None).unwrap().is_none());
        for variable in LIMIT_ENV_KEYS {
            assert!(MeshRouter::from_lookup(|name| {
                (name == variable).then(|| "8".to_owned())
            }).is_err(), "a limit alone must not silently disable mesh routing");
        }
        let dir = tempfile::tempdir().unwrap();
        let key_file = write_key_file(&dir, &Ed25519SigningKey::generate());
        let peers = peers_json(&[("node-b", &Ed25519SigningKey::generate())]);
        let router = MeshRouter::from_lookup(|name| match name {
            MESH_NODE_ID_ENV => Some("node-a".to_owned()),
            MESH_SIGNING_KEY_FILE_ENV => Some(key_file.clone()),
            MESH_PEERS_ENV => Some(peers.clone()),
            MESH_FORWARD_MAX_IN_FLIGHT_ENV => Some("8".to_owned()),
            MESH_FORWARD_MAX_PER_PEER_ENV => Some("2".to_owned()),
            MESH_FORWARD_MAX_REQUEST_BYTES_ENV => Some("4096".to_owned()),
            _ => None,
        }).unwrap().unwrap();
        assert_eq!(router.forward_limits(), MeshForwardLimits {
            max_in_flight: 8, max_per_peer: 2, max_request_bytes: 4096,
        });
        assert_eq!(router.forward_usage().unwrap(), MeshForwardUsage::default());
    }

    #[test]
    fn forward_byte_admission_refuses_without_connecting_to_the_peer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let router = MeshRouter::with_forward_limits(
            MeshRoutingSettings {
                node_id: TailscaleNodeId::new("node-a"),
                signing_key: Ed25519SigningKey::generate(),
                peers_json: serde_json::json!([{
                    "node_id": "node-b",
                    "endpoint": format!("http://{}", listener.local_addr().unwrap()),
                    "public_key_hex": hex::encode(Ed25519SigningKey::generate().verifying_key().to_bytes()),
                }]).to_string(),
                forward_timeout: Duration::from_secs(1),
            },
            MeshForwardLimits { max_in_flight: 1, max_per_peer: 1, max_request_bytes: 1 },
        ).unwrap();
        let failure = fcp_async_core::runtime::block_on_sync(router.forward(
            &TailscaleNodeId::new("node-b"),
            MeshForwardBody::Introspect { connector_id: "fcp.test:utility:1.0.0".to_owned() },
        )).unwrap().unwrap_err();
        assert!(failure.safe_to_retry());
        assert!(failure.summary().contains("request_byte_limit"));
        assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(router.forward_usage().unwrap(), MeshForwardUsage::default());
    }
}
