//! Connector-state persistence on top of the FCPS object store.
//!
//! The store treats mesh objects as canonical connector state. Local files can
//! cache these objects, but this module is the content-addressed storage seam
//! that host and SDK code can share as the mesh-native path lands.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ciborium::de::from_reader_with_recursion_limit;
use ciborium::value::Value as CborValue;
use fcp_async_core::channel::broadcast;
use fcp_cbor::{
    CanonicalSerializer, MAX_CANONICALIZATION_DEPTH, MAX_DESERIALIZATION_RECURSION_LIMIT, SchemaId,
    SerializationError,
};
use fcp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use fcp_prelude::{
    BackoffPolicy, ConnectorId, ConnectorStateAppendOutcome, ConnectorStateCanonicalStatus,
    ConnectorStateChange, ConnectorStateChangeKind, ConnectorStateChangeStream,
    ConnectorStateError, ConnectorStateModel, ConnectorStateObject, ConnectorStateRoot,
    ConnectorStateSnapshot, ConnectorStateStore, ConnectorStateWriteAuthorization, InstanceId,
    ObjectHeader, ObjectId, ObjectIdKey, RetentionClass, StorageMeta, StoredObject, ZoneId,
};
use futures_util::{lock::Mutex as AsyncMutex, stream};
use parking_lot::RwLock;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::{ObjectStore, ObjectStoreError, SymbolStore};

/// Marker file name written by host-local connector-state cache directories.
///
/// The object store does not create cache directories, but keeping the marker
/// name here gives host adapters one canonical spelling when they expose the
/// cache-vs-canonical distinction to operators.
pub const CONNECTOR_STATE_CACHE_MARKER: &str = ".fcp-cache-only";

/// Tracing target for connector-state storage events.
pub const CONNECTOR_STATE_TRACING_TARGET: &str = "fcp.connector_state";
/// Structured event name emitted for connector-state reads.
pub const CONNECTOR_STATE_READ_EVENT: &str = "fcp.connector_state.read";
/// Structured event name emitted for connector-state writes.
pub const CONNECTOR_STATE_WRITE_EVENT: &str = "fcp.connector_state.write";
/// Structured event name emitted when connector-state root writes are retried.
pub const CONNECTOR_STATE_WRITE_RETRY_EVENT: &str = "fcp.connector_state.write.retry";
/// Structured event name emitted for connector-state snapshots.
pub const CONNECTOR_STATE_SNAPSHOT_EVENT: &str = "fcp.connector_state.snapshot";
/// Structured event name emitted for connector-state compaction.
pub const CONNECTOR_STATE_COMPACT_EVENT: &str = "fcp.connector_state.compact";
/// Structured event name reserved for host cache fall-through paths.
pub const CONNECTOR_STATE_FALL_THROUGH_EVENT: &str = "fcp.connector_state.fall_through";
/// Counter for connector-state writes by result.
pub const CONNECTOR_STATE_WRITES_TOTAL_METRIC: &str = "fcp_connector_state_writes_total";
/// Counter for host-local connector-state cache hits.
pub const CONNECTOR_STATE_CACHE_HITS_TOTAL_METRIC: &str = "fcp_connector_state_cache_hits_total";
/// Counter for cache misses falling through to canonical storage.
pub const CONNECTOR_STATE_FALL_THROUGH_TOTAL_METRIC: &str =
    "fcp_connector_state_fall_through_total";
/// Histogram for connector-state operation latency in seconds.
pub const CONNECTOR_STATE_LATENCY_SECONDS_METRIC: &str = "fcp_connector_state_latency_seconds";
const CONNECTOR_STATE_CHANGE_BUFFER_CAPACITY: usize = 1_024;
const DEFAULT_SNAPSHOT_EVERY_SECS: u64 = 24 * 60 * 60;
const MAX_CONNECTOR_STATE_CBOR_BYTES: usize = 1024 * 1024;

/// Errors returned by [`FcpStoreConnectorStateStore`].
#[derive(Debug, Error)]
pub enum ConnectorStateStoreError {
    /// Object store operation failed.
    #[error("object store error: {0}")]
    ObjectStore(#[from] ObjectStoreError),

    /// Canonical serialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] SerializationError),

    /// Stored object used an unexpected schema.
    #[error("unexpected schema for {kind}: expected {expected}, got {got}")]
    UnexpectedSchema {
        /// Object kind being decoded.
        kind: &'static str,
        /// Expected schema.
        expected: String,
        /// Actual schema.
        got: String,
    },

    /// Decoded state belongs to a different identity than this store.
    #[error("connector state identity mismatch for {field}: expected {expected}, got {got}")]
    IdentityMismatch {
        /// Field that mismatched.
        field: &'static str,
        /// Expected value.
        expected: String,
        /// Actual value.
        got: String,
    },

    /// State-object header does not mirror its storage envelope.
    #[error("state object header does not match stored envelope")]
    HeaderBodyMismatch,

    /// Stored object id does not match the keyed content derivation.
    #[error("content-id mismatch: claimed {claimed}, computed {computed}")]
    ContentIdMismatch {
        /// Claimed object id.
        claimed: ObjectId,
        /// Computed object id.
        computed: ObjectId,
    },

    /// A state object omitted the lease object from its header refs.
    #[error("connector state object missing lease reference {0}")]
    MissingLeaseReference(ObjectId),

    /// A state object carries no canonical state bytes.
    #[error("connector state object has empty state_cbor")]
    EmptyStateCbor,

    /// A state object carries malformed or non-canonical CBOR state bytes.
    #[error("connector state object has invalid state_cbor: {0}")]
    InvalidStateCbor(SerializationError),

    /// A state object signature does not verify against the authorized writer.
    #[error("connector state object signature verification failed: {0}")]
    InvalidStateSignature(String),

    /// No configured snapshot signer can authenticate the covered state.
    #[error("connector state snapshot signing unavailable: {reason}")]
    SnapshotSigningUnavailable {
        /// Missing key or mismatch with the authenticated covered writer.
        reason: String,
    },

    /// A snapshot signature does not verify against the covered state writer.
    #[error("connector state snapshot signature verification failed: {0}")]
    InvalidSnapshotSignature(String),

    /// A snapshot does not contain the state declared by its covered head.
    #[error("connector state snapshot {field} does not match covered state {covers_head}")]
    SnapshotStateMismatch {
        /// Authenticated state object the snapshot claims to cover.
        covers_head: ObjectId,
        /// Projection field that differs from the covered state.
        field: &'static str,
    },

    /// The selected snapshot does not cover an ancestor of the exact root head.
    #[error(
        "connector state snapshot {snapshot_object_id} is not an ancestor of root {root_object_id}"
    )]
    SnapshotNotAncestor {
        /// Caller-selected root whose history must be recovered.
        root_object_id: ObjectId,
        /// Caller-selected snapshot that failed to join that history.
        snapshot_object_id: ObjectId,
    },

    /// Recovering the complete tail would exceed the caller's work budget.
    #[error("connector state snapshot replay exceeds tail limit {limit}")]
    ReplayLimitExceeded {
        /// Maximum number of state objects permitted after the snapshot.
        limit: usize,
    },

    /// A state object used a sequence number that does not follow the head.
    #[error("connector state sequence mismatch: expected {expected}, got {got}")]
    SequenceMismatch {
        /// Expected next sequence number.
        expected: u64,
        /// Incoming sequence number.
        got: u64,
    },

    /// A singleton writer's lease was superseded by the canonical head.
    #[error("connector state lease is stale: held {held_seq}, current {current_seq}")]
    StaleLease {
        /// Fencing token carried by the incoming state object.
        held_seq: u64,
        /// Fencing token on the canonical head.
        current_seq: u64,
    },

    /// Committed singleton roots have incomparable authenticated heads.
    #[error(
        "connector state fork detected: roots {root_a} and {root_b} have incompatible heads {head_a} and {head_b}"
    )]
    ForkDetected {
        /// First conflicting committed root.
        root_a: ObjectId,
        /// Second conflicting committed root.
        root_b: ObjectId,
        /// Authenticated head referenced by the first root.
        head_a: Box<ObjectId>,
        /// Authenticated head referenced by the second root.
        head_b: Box<ObjectId>,
    },

    /// The root points at an object that cannot be loaded.
    #[error("connector state root references missing state object {0}")]
    MissingHead(ObjectId),

    /// Sequence increment overflowed.
    #[error("connector state sequence overflow at {0}")]
    SequenceOverflow(u64),

    /// The canonical state chain loops back to an already visited object.
    #[error("connector state chain contains a cycle at {0}")]
    ChainCycle(ObjectId),

    /// A state object was signed by a writer key outside the trusted set.
    #[error("connector state writer key {writer_public_key} is not in the trusted writer set")]
    UntrustedWriterKey {
        /// Hex-encoded writer public key embedded in the rejected object.
        writer_public_key: String,
    },

    /// A replica exceeds its caller-supplied object count budget.
    #[error("connector state replica exceeds object limit {limit}")]
    ReplicaObjectLimitExceeded {
        /// Maximum number of objects, including the root.
        limit: usize,
    },

    /// A replica exceeds its caller-supplied canonical object byte budget.
    #[error("connector state replica exceeds canonical byte limit {limit}")]
    ReplicaByteLimitExceeded {
        /// Maximum sum of canonical object lengths.
        limit: usize,
    },

    /// A replica does not contain exactly one complete singleton state history.
    #[error("invalid connector state replica: {reason}")]
    InvalidReplica {
        /// Structural violation detected before publication.
        reason: String,
    },

    /// An existing content-addressed object has different bytes.
    #[error("stored object {object_id} conflicts with connector state replica")]
    ReplicaObjectConflict {
        /// Content-addressed object whose stored bytes differ.
        object_id: ObjectId,
    },
}

type Result<T> = std::result::Result<T, ConnectorStateStoreError>;

/// Caller-supplied bounds for one complete connector-state replica.
///
/// The object budget includes the root. The byte budget is the exact sum of
/// [`StoredObject::canonical_bytes`] lengths, including every object header
/// and body. Transport framing and the serialized bundle envelope are not
/// included; network callers must also bound received message bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorStateReplicaLimits {
    /// Maximum number of state objects plus the single root.
    pub max_objects: usize,
    /// Maximum sum of canonical object lengths in bytes.
    pub max_bytes: usize,
}

/// One immutable singleton-writer root and its complete signed state ancestry.
///
/// Objects are exported in ascending state sequence order, with the root last.
/// Import accepts any order, but rejects duplicate IDs, missing predecessors,
/// and objects outside that history. Lease objects, snapshots, and arbitrary
/// header references are not included: this bundle carries canonical state,
/// not a new append authorization or proof that a lease is currently valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorStateReplicaBundle {
    /// Exact content-addressed root being transferred.
    pub root_object_id: ObjectId,
    /// Exactly one root and all state objects back to sequence zero.
    pub objects: Vec<StoredObject>,
}

struct ReplicaBudget {
    limits: ConnectorStateReplicaLimits,
    objects: usize,
    bytes: usize,
}

impl ReplicaBudget {
    const fn new(limits: ConnectorStateReplicaLimits) -> Self {
        Self {
            limits,
            objects: 0,
            bytes: 0,
        }
    }

    fn check_next_object(&self) -> Result<()> {
        if self.objects >= self.limits.max_objects {
            return Err(ConnectorStateStoreError::ReplicaObjectLimitExceeded {
                limit: self.limits.max_objects,
            });
        }
        Ok(())
    }

    fn charge(&mut self, object: &StoredObject) -> Result<()> {
        self.check_next_object()?;
        let too_large = || ConnectorStateStoreError::ReplicaByteLimitExceeded {
            limit: self.limits.max_bytes,
        };
        // Reject an oversized body before allocating its canonical envelope.
        if object.body.len() > self.limits.max_bytes.saturating_sub(self.bytes) {
            return Err(too_large());
        }
        let object_bytes = StoredObject::canonical_bytes(&object.header, &object.body)?.len();
        let bytes = self.bytes.checked_add(object_bytes).ok_or_else(too_large)?;
        if bytes > self.limits.max_bytes {
            return Err(too_large());
        }
        self.bytes = bytes;
        self.objects += 1;
        Ok(())
    }
}

struct ValidatedReplica {
    root: ConnectorStateRoot,
    root_object: StoredObject,
    states: Vec<StoredObject>,
    head_seq: Option<u64>,
}

#[derive(Debug, Clone)]
struct CachedConnectorStateRoot {
    generation: u64,
    object_id: ObjectId,
    root: ConnectorStateRoot,
}

/// Canonical connector-state evidence collected immediately before yielding
/// a singleton-writer lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectorStateLeaseYieldFlush {
    /// Connector represented by this flush barrier.
    pub connector_id: ConnectorId,
    /// Optional connector instance represented by the root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,
    /// Zone that owns the canonical state.
    pub zone_id: ZoneId,
    /// Content-addressed root object that was verified, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_object_id: Option<ObjectId>,
    /// Current canonical state-object head, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_object_id: Option<ObjectId>,
    /// Last committed canonical sequence number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_canonical_seq: Option<u64>,
    /// Fencing token on the canonical head.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_seq: Option<u64>,
    /// Lease object authorizing the canonical head.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_object_id: Option<ObjectId>,
}

impl ConnectorStateLeaseYieldFlush {
    #[must_use]
    fn missing(store: &FcpStoreConnectorStateStore) -> Self {
        Self {
            connector_id: store.connector_id.clone(),
            instance_id: store.instance_id.clone(),
            zone_id: store.zone_id.clone(),
            root_object_id: None,
            head_object_id: None,
            last_canonical_seq: None,
            lease_seq: None,
            lease_object_id: None,
        }
    }
}

/// An authenticated snapshot and the complete state tail to one exact root.
///
/// Instances are produced by [`FcpStoreConnectorStateStore::replay_from_snapshot`].
/// The snapshot's covered state is retained separately because its signed writer
/// identity authenticates the snapshot. Tail entries are in ascending sequence
/// order and exclude that covered state.
///
/// This proves the selected history, not that its root is the latest root.
/// Selecting sufficiently fresh, trusted anchor IDs remains the caller's job.
#[derive(Debug, Clone)]
pub struct ConnectorStateReplay {
    root_object_id: ObjectId,
    root: ConnectorStateRoot,
    snapshot_object_id: ObjectId,
    snapshot: ConnectorStateSnapshot,
    covered_state: ConnectorStateObject,
    tail: Vec<(ObjectId, ConnectorStateObject)>,
}

impl ConnectorStateReplay {
    /// Exact root object requested by the caller.
    #[must_use]
    pub const fn root_object_id(&self) -> ObjectId {
        self.root_object_id
    }

    /// Verified root envelope and connector identity.
    #[must_use]
    pub const fn root(&self) -> &ConnectorStateRoot {
        &self.root
    }

    /// Exact snapshot object requested by the caller.
    #[must_use]
    pub const fn snapshot_object_id(&self) -> ObjectId {
        self.snapshot_object_id
    }

    /// Independently signed snapshot with its covered-state projection checked.
    #[must_use]
    pub const fn snapshot(&self) -> &ConnectorStateSnapshot {
        &self.snapshot
    }

    /// Authenticated boundary state; its predecessor need not remain available.
    #[must_use]
    pub const fn covered_head(&self) -> (ObjectId, &ConnectorStateObject) {
        (self.snapshot.covers_head, &self.covered_state)
    }

    /// Complete ascending tail after the snapshot, ending at the requested root.
    #[must_use]
    pub const fn tail(&self) -> &[(ObjectId, ConnectorStateObject)] {
        self.tail.as_slice()
    }

    /// Authenticated state at the requested root, including a snapshot-only root.
    #[must_use]
    pub fn head(&self) -> (ObjectId, &ConnectorStateObject) {
        self.tail.last().map_or_else(
            || self.covered_head(),
            |(object_id, state)| (*object_id, state),
        )
    }

    /// Consume the replay and return the state at the requested root.
    #[must_use]
    pub fn into_head(mut self) -> (ObjectId, ConnectorStateObject) {
        self.tail
            .pop()
            .unwrap_or((self.snapshot.covers_head, self.covered_state))
    }
}

/// Connector-state store backed by an [`ObjectStore`].
#[derive(Clone)]
pub struct FcpStoreConnectorStateStore {
    object_store: Arc<dyn ObjectStore>,
    object_id_key: ObjectIdKey,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    instance_id: Option<InstanceId>,
    state_model: ConnectorStateModel,
    retention: RetentionClass,
    snapshot_every_entries: u64,
    snapshot_every_secs: u64,
    state_object_write_retry_policy: BackoffPolicy,
    root_write_retry_policy: BackoffPolicy,
    change_bus: Arc<ConnectorStateChangeBus>,
    root_cache: Arc<RwLock<Option<CachedConnectorStateRoot>>>,
    trusted_writer_keys: Option<Arc<HashSet<[u8; 32]>>>,
    snapshot_signing_key: Option<Arc<Ed25519SigningKey>>,
}

impl FcpStoreConnectorStateStore {
    /// Create a connector-state store for one connector+zone identity.
    #[must_use]
    pub fn new(
        object_store: Arc<dyn ObjectStore>,
        object_id_key: ObjectIdKey,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        let change_bus = shared_change_bus(&object_store, &connector_id, &zone_id);
        Self {
            object_store,
            object_id_key,
            connector_id,
            zone_id,
            instance_id: None,
            state_model: ConnectorStateModel::SingletonWriter,
            retention: RetentionClass::Pinned,
            snapshot_every_entries: 1_000,
            snapshot_every_secs: DEFAULT_SNAPSHOT_EVERY_SECS,
            state_object_write_retry_policy: BackoffPolicy::new(
                0,
                Duration::ZERO,
                Duration::ZERO,
                1.0,
            ),
            root_write_retry_policy: BackoffPolicy::new(0, Duration::ZERO, Duration::ZERO, 1.0),
            change_bus,
            root_cache: Arc::new(RwLock::new(None)),
            trusted_writer_keys: None,
            snapshot_signing_key: None,
        }
    }

    /// Pin the writer public keys trusted on the canonical read path.
    ///
    /// The append boundary already binds each incoming state object's
    /// `writer_public_key` to a verified [`ConnectorStateWriteAuthorization`],
    /// but stored objects are otherwise verified only against their own
    /// embedded writer key. The keyed content-id blocks non-members, yet a
    /// zone member holding the shared [`ObjectIdKey`] could plant a
    /// self-signed chain for this connector and have it selected canonical.
    /// With a pin configured, every state object loaded on the read path must
    /// carry a writer key from this set; anything else fails closed with
    /// [`ConnectorStateStoreError::UntrustedWriterKey`]. Append authorizations
    /// whose writer key is outside the pin are refused at write time.
    #[must_use]
    pub fn with_trusted_writer_keys<I>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        self.trusted_writer_keys = Some(Arc::new(keys.into_iter().collect()));
        // A cloned adapter may already share a root accepted under different
        // writer trust. Revalidate under this policy without clearing its peers.
        self.root_cache = Arc::new(RwLock::new(None));
        self
    }

    /// Supply the private key used to sign canonical snapshots.
    ///
    /// The key must match the authenticated covered state writer and any
    /// configured writer pin. This does not grant append authorization.
    /// Readers need only the verified covered state, not this private key.
    ///
    /// Without a matching key, explicit snapshots return
    /// [`ConnectorStateStoreError::SnapshotSigningUnavailable`]. Automatic
    /// snapshots are skipped with a warning after the append has committed;
    /// a state-object signature is never reused as a snapshot signature.
    #[must_use]
    pub fn with_snapshot_signing_key(mut self, signing_key: Arc<Ed25519SigningKey>) -> Self {
        self.snapshot_signing_key = Some(signing_key);
        self
    }

    /// Scope the store to one connector instance.
    #[must_use]
    pub fn with_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
        self.root_cache = Arc::new(RwLock::new(None));
        self
    }

    /// Configure the state model used when append creates or advances a root.
    #[must_use]
    pub const fn with_state_model(mut self, state_model: ConnectorStateModel) -> Self {
        self.state_model = state_model;
        self
    }

    /// Override retention for newly stored root/state/snapshot objects.
    #[must_use]
    pub const fn with_retention(mut self, retention: RetentionClass) -> Self {
        self.retention = retention;
        self
    }

    /// Emit a snapshot every N committed state objects.
    ///
    /// Zero disables count-based snapshots but leaves the elapsed-time policy unchanged.
    #[must_use]
    pub const fn with_snapshot_every_entries(mut self, snapshot_every_entries: u64) -> Self {
        self.snapshot_every_entries = snapshot_every_entries;
        self
    }

    /// Emit a snapshot when the latest snapshot is older than N seconds.
    ///
    /// Zero disables elapsed-time snapshots but leaves the count-based policy unchanged.
    #[must_use]
    pub const fn with_snapshot_every_secs(mut self, snapshot_every_secs: u64) -> Self {
        self.snapshot_every_secs = snapshot_every_secs;
        self
    }

    /// Configure retries for transient canonical state-object writes.
    ///
    /// The default policy has zero retries so fail-closed storage errors stay
    /// bounded for hot-path callers. Hosts that can tolerate a short bounded
    /// retry window can opt in when the backing mesh/object store may recover
    /// quickly after a transient I/O outage before the root is written.
    #[must_use]
    pub const fn with_state_object_write_retry_policy(mut self, policy: BackoffPolicy) -> Self {
        self.state_object_write_retry_policy = policy;
        self
    }

    /// Configure retries for transient canonical root writes.
    ///
    /// The default policy has zero retries so fail-closed storage errors stay
    /// bounded for hot-path callers. Hosts that can tolerate a short bounded
    /// retry window can opt in when the backing mesh/object store may recover
    /// quickly after a transient I/O outage.
    #[must_use]
    pub const fn with_root_write_retry_policy(mut self, policy: BackoffPolicy) -> Self {
        self.root_write_retry_policy = policy;
        self
    }

    /// Schema used for canonical state-root objects.
    #[must_use]
    pub fn root_schema_id() -> SchemaId {
        SchemaId::new("fcp.connector_state", "state_root", Version::new(1, 0, 0))
    }

    /// Schema used for canonical state-chain objects.
    #[must_use]
    pub fn state_object_schema_id() -> SchemaId {
        SchemaId::new("fcp.connector_state", "state_object", Version::new(1, 0, 0))
    }

    /// Schema used for canonical state snapshots.
    #[must_use]
    pub fn snapshot_schema_id() -> SchemaId {
        SchemaId::new(
            "fcp.connector_state",
            "state_snapshot",
            Version::new(1, 0, 0),
        )
    }

    /// Return the latest state root for this connector, if present.
    ///
    /// # Errors
    /// Returns an error if a matching root object is malformed, its history
    /// fails authentication or sequence/fencing validation, or committed
    /// singleton roots describe incomparable histories.
    pub async fn read_root(&self) -> Result<Option<(ObjectId, ConnectorStateRoot)>> {
        let started = Instant::now();
        let result = self.read_root_inner().await;
        let telemetry_result = match &result {
            Ok(Some(_)) => "hit",
            Ok(None) => "miss",
            Err(_) => "error",
        };
        self.record_read_cache_telemetry("read", telemetry_result);
        self.record_operation_telemetry(
            CONNECTOR_STATE_READ_EVENT,
            "read",
            telemetry_result,
            started,
        );
        result
    }

    /// Observe a root object announcement from an external propagation layer.
    ///
    /// `FcpStoreConnectorStateStore` intentionally has no direct dependency on
    /// `fcp-mesh`, but mesh or host adapters can call this after a replicated
    /// `ConnectorStateRoot` object arrives locally. The root is loaded from the
    /// object store and validated before a cache-invalidation change is emitted.
    ///
    /// # Errors
    /// Returns an error if the root object is missing, malformed, foreign to
    /// this connector+zone store, or references a missing head object.
    pub async fn observe_replicated_root(
        &self,
        root_object_id: ObjectId,
    ) -> Result<ConnectorStateChange> {
        // A rejected announcement must not leave the previously cached branch
        // usable. Invalidate before any fallible object or history validation.
        self.change_bus.mark_root_updated();
        let stored = self.object_store.get(&root_object_id).await?;
        let root: ConnectorStateRoot =
            self.decode_stored(&stored, &Self::root_schema_id(), "connector state root")?;
        self.validate_stored_root(root_object_id, &stored, &root)?;
        let seq = self.root_head_seq(&root).await?;
        // Validate against every locally committed root. Authentication of the
        // announced head alone cannot establish that it extends this history.
        self.read_root().await?;

        Ok(self.publish_change(
            ConnectorStateChangeKind::RootUpdated,
            Some(root_object_id),
            seq,
        ))
    }

    /// Export one exact singleton root and its complete authenticated ancestry.
    ///
    /// The caller selects a root from a trusted checkpoint or canonical status.
    /// This method does not discover the latest root or establish its freshness.
    /// It walks only that immutable history and checks the count before each
    /// object fetch. A compacted prefix is an error: snapshot-based recovery is
    /// a separate API and cannot silently weaken full canonical-root validation.
    ///
    /// # Errors
    /// Returns an error for a missing or invalid object, unsupported state model,
    /// invalid signature or writer pin, discontinuous or stale-fenced history,
    /// or a complete replica that exceeds either caller-supplied budget.
    pub async fn export_replica(
        &self,
        root_object_id: ObjectId,
        limits: ConnectorStateReplicaLimits,
    ) -> Result<ConnectorStateReplicaBundle> {
        let mut budget = ReplicaBudget::new(limits);
        budget.check_next_object()?;
        let root_object = self.object_store.get(&root_object_id).await?;
        budget.charge(&root_object)?;
        let root: ConnectorStateRoot = self.decode_stored(
            &root_object,
            &Self::root_schema_id(),
            "connector state root",
        )?;
        self.validate_stored_root(root_object_id, &root_object, &root)?;
        self.validate_replica_model(&root)?;

        let mut objects = Vec::new();
        let mut visited = HashSet::new();
        let mut next = root.head;
        let mut newer: Option<ConnectorStateObject> = None;
        while let Some(object_id) = next {
            if !visited.insert(object_id) {
                return Err(ConnectorStateStoreError::ChainCycle(object_id));
            }
            budget.check_next_object()?;
            let stored = self.object_store.get(&object_id).await?;
            budget.charge(&stored)?;
            let state: ConnectorStateObject = self.decode_stored(
                &stored,
                &Self::state_object_schema_id(),
                "connector state object",
            )?;
            self.validate_stored_state_object(object_id, &stored, &state)?;
            if let Some(newer) = &newer {
                Self::validate_replay_transition(&root.model, &state, newer)?;
            }
            if state.prev.is_none() && state.seq != 0 {
                return Err(ConnectorStateStoreError::SequenceMismatch {
                    expected: 0,
                    got: state.seq,
                });
            }
            next = state.prev;
            newer = Some(state);
            objects.push(stored);
        }
        objects.reverse();
        objects.push(root_object);
        Ok(ConnectorStateReplicaBundle {
            root_object_id,
            objects,
        })
    }

    /// Validate and durably adopt a complete singleton-writer replica.
    ///
    /// Every incoming byte and the full lineage are validated before storage is
    /// changed. An uncached canonical read under the shared append gate rejects
    /// incomparable histories, including roots written without an announcement.
    /// Duplicate or older comparable roots return `None` without writes or change
    /// events, but refresh shared caches in case an announcement was missed.
    /// A newer comparable root returns its published change only after all state
    /// objects and the root have been persisted, in that order.
    ///
    /// Incoming retention metadata is replaced by this adapter's local policy.
    /// A storage failure may leave verified state objects without a new root;
    /// cancellation or an uncertain root write invalidates existing root caches.
    /// The backing store must provide immutable objects and read-after-write
    /// ordering, including when a put's response future is dropped.
    ///
    /// Limits bound the supplied bundle after deserialization; network callers
    /// must also bound message bytes. The existing local canonical history must
    /// validate and its fresh scan is not charged to the incoming bundle budget.
    /// This method does not repair a missing or corrupt local canonical prefix.
    ///
    /// This preserves the canonical read path's signature and optional writer
    /// pins. It grants no append authority or live lease validity; network callers
    /// must authorize state transfer and authenticate the chosen root separately.
    ///
    /// # Errors
    /// Returns an error for an over-budget or malformed bundle, an invalid signed
    /// history, a local fork or object conflict, or a storage failure. Validation
    /// before publication issues no puts, retention changes, or shared cache
    /// invalidations. A conflicting raw put during publication is a storage race.
    pub async fn import_replica(
        &self,
        bundle: ConnectorStateReplicaBundle,
        limits: ConnectorStateReplicaLimits,
    ) -> Result<Option<ConnectorStateChange>> {
        let replica = self.validate_replica(bundle, limits)?;
        let _append_guard = self.change_bus.append_guard.lock().await;

        // Do not invalidate other readers merely because an untrusted bundle
        // arrived. A private cache still forces a fresh scan at the commit gate.
        let mut canonical = self.clone();
        canonical.root_cache = Arc::new(RwLock::new(None));
        if let Some((current_id, current)) = canonical.read_root().await? {
            self.validate_replica_model(&current)?;
            let current_seq = canonical.root_head_seq(&current).await?;
            if replica.root.head == current.head {
                let newer = replica
                    .head_seq
                    .cmp(&current_seq)
                    .then(replica.root.header.created_at.cmp(&current.header.created_at))
                    .then(replica.root_object.object_id.cmp(&current_id))
                    .is_gt();
                if !newer {
                    self.change_bus.mark_root_updated();
                    return Ok(None);
                }
            } else if let Some(current_head) = current.head {
                let Some(incoming_head) = replica.root.head else {
                    self.change_bus.mark_root_updated();
                    return Ok(None);
                };
                if !replica
                    .states
                    .iter()
                    .any(|object| object.object_id == current_head)
                {
                    // A fully authenticated older prefix is a harmless no-op.
                    // Local canonical validation already checked this history;
                    // walk only far enough to establish the incoming boundary.
                    if replica.head_seq < current_seq {
                        let mut next = Some(current_head);
                        while let Some(object_id) = next {
                            if object_id == incoming_head {
                                self.change_bus.mark_root_updated();
                                return Ok(None);
                            }
                            let (_, state) = canonical.load_state_object(&object_id).await?;
                            if Some(state.seq) <= replica.head_seq {
                                break;
                            }
                            next = state.prev;
                        }
                    }
                    return Err(ConnectorStateStoreError::ForkDetected {
                        root_a: current_id,
                        root_b: replica.root_object.object_id,
                        head_a: Box::new(current_head),
                        head_b: Box::new(incoming_head),
                    });
                }
            }
        }

        // An AlreadyExists response is not proof that the stored bytes match.
        // Check every pre-existing dependency before the first mutation, then
        // recheck collisions during publication to cover a concurrent raw put.
        for object in replica
            .states
            .iter()
            .chain(std::iter::once(&replica.root_object))
        {
            match self.object_store.get(&object.object_id).await {
                Ok(existing) => Self::validate_replica_existing(object, &existing)?,
                Err(ObjectStoreError::NotFound(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        for object in &replica.states {
            self.put_replica_object(object).await?;
        }

        let mut root_write = PendingRootWrite::new(&self.change_bus);
        self.put_replica_object(&replica.root_object).await?;
        let change = self.publish_change(
            ConnectorStateChangeKind::RootUpdated,
            Some(replica.root_object.object_id),
            replica.head_seq,
        );
        root_write.committed = true;
        Ok(Some(change))
    }

    fn validate_replica_model(&self, root: &ConnectorStateRoot) -> Result<()> {
        if root.model != self.state_model {
            return Err(ConnectorStateStoreError::IdentityMismatch {
                field: "model",
                expected: self.state_model.to_string(),
                got: root.model.to_string(),
            });
        }
        if !root.model.is_singleton_writer() {
            return Err(ConnectorStateStoreError::InvalidReplica {
                reason: "replication requires singleton-writer state".to_string(),
            });
        }
        Ok(())
    }

    fn validate_replica(
        &self,
        bundle: ConnectorStateReplicaBundle,
        limits: ConnectorStateReplicaLimits,
    ) -> Result<ValidatedReplica> {
        if bundle.objects.len() > limits.max_objects {
            return Err(ConnectorStateStoreError::ReplicaObjectLimitExceeded {
                limit: limits.max_objects,
            });
        }
        let mut budget = ReplicaBudget::new(limits);
        let mut objects = HashMap::new();
        for object in bundle.objects {
            budget.charge(&object)?;
            let object_id = object.object_id;
            if objects.insert(object_id, object).is_some() {
                return Err(ConnectorStateStoreError::InvalidReplica {
                    reason: format!("duplicate object {object_id}"),
                });
            }
        }
        let root_object = objects.remove(&bundle.root_object_id).ok_or_else(|| {
            ConnectorStateStoreError::InvalidReplica {
                reason: "declared root is missing".to_string(),
            }
        })?;
        let root: ConnectorStateRoot = self.decode_stored(
            &root_object,
            &Self::root_schema_id(),
            "connector state root",
        )?;
        self.validate_stored_root(bundle.root_object_id, &root_object, &root)?;
        self.validate_replica_model(&root)?;

        let mut states = HashMap::new();
        for (object_id, stored) in &objects {
            let state: ConnectorStateObject = self.decode_stored(
                stored,
                &Self::state_object_schema_id(),
                "connector state object",
            )?;
            self.validate_stored_state_object(*object_id, stored, &state)?;
            states.insert(*object_id, state);
        }

        let mut order = Vec::new();
        let mut visited = HashSet::new();
        let mut next = root.head;
        let mut newer: Option<&ConnectorStateObject> = None;
        let mut head_seq = None;
        while let Some(object_id) = next {
            if !visited.insert(object_id) {
                return Err(ConnectorStateStoreError::ChainCycle(object_id));
            }
            let state = states
                .get(&object_id)
                .ok_or(ConnectorStateStoreError::MissingHead(object_id))?;
            if let Some(newer) = newer {
                Self::validate_replay_transition(&root.model, state, newer)?;
            } else {
                head_seq = Some(state.seq);
            }
            if state.prev.is_none() && state.seq != 0 {
                return Err(ConnectorStateStoreError::SequenceMismatch {
                    expected: 0,
                    got: state.seq,
                });
            }
            next = state.prev;
            newer = Some(state);
            order.push(object_id);
        }
        if order.len() != objects.len() {
            return Err(ConnectorStateStoreError::InvalidReplica {
                reason: "objects outside the declared root's state ancestry".to_string(),
            });
        }
        order.reverse();
        let states = order
            .into_iter()
            .map(|object_id| {
                objects
                    .remove(&object_id)
                    .ok_or(ConnectorStateStoreError::MissingHead(object_id))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ValidatedReplica {
            root,
            root_object,
            states,
            head_seq,
        })
    }

    fn validate_replica_existing(expected: &StoredObject, existing: &StoredObject) -> Result<()> {
        if existing.object_id != expected.object_id
            || existing.body != expected.body
            || !headers_match(&existing.header, &expected.header)?
        {
            return Err(ConnectorStateStoreError::ReplicaObjectConflict {
                object_id: expected.object_id,
            });
        }
        Ok(())
    }

    async fn put_replica_object(&self, expected: &StoredObject) -> Result<()> {
        let mut object = expected.clone();
        object.storage.retention = self.retention;
        match self.object_store.put(object).await {
            Ok(()) => Ok(()),
            Err(ObjectStoreError::AlreadyExists(_)) => {
                let existing = self.object_store.get(&expected.object_id).await?;
                Self::validate_replica_existing(expected, &existing)?;
                if existing.storage.retention != self.retention {
                    self.object_store
                        .set_retention(&expected.object_id, self.retention)
                        .await?;
                }
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn read_root_inner(&self) -> Result<Option<(ObjectId, ConnectorStateRoot)>> {
        if let Some((object_id, root)) = self.cached_root() {
            return Ok(Some((object_id, root)));
        }

        // Sample the change generation *before* scanning. A concurrent writer
        // bumps the generation only after the new root object is durably
        // stored (append_object_inner: store_root_with_retry then
        // publish_change(RootUpdated)). Caching under this pre-scan value means
        // any root update that races our scan advances the generation past it,
        // so the next read misses the cache and rescans rather than serving
        // this now-stale result as fresh.
        let generation = self.change_bus.generation();

        let mut best: Option<(ObjectId, ConnectorStateRoot, Option<u64>)> = None;
        let mut roots: Vec<(ObjectId, ConnectorStateRoot)> = Vec::new();

        for object_id in self.object_store.list_zone(&self.zone_id).await {
            let stored = self.object_store.get(&object_id).await?;
            if stored.header.schema != Self::root_schema_id() {
                continue;
            }

            let root: ConnectorStateRoot =
                self.decode_stored(&stored, &Self::root_schema_id(), "connector state root")?;
            if !self.root_belongs_to_store(&root) {
                continue;
            }
            self.validate_stored_root(object_id, &stored, &root)?;
            if let Some((_known_id, known_root)) = roots.first()
                && root.model != known_root.model
            {
                return Err(ConnectorStateStoreError::IdentityMismatch {
                    field: "model",
                    expected: format!("{:?}", known_root.model),
                    got: format!("{:?}", root.model),
                });
            }
            let head_seq = self.root_head_seq(&root).await?;
            roots.push((object_id, root.clone()));

            let replace = best
                .as_ref()
                .is_none_or(|(best_id, best_root, best_head_seq)| {
                    head_seq
                        .cmp(best_head_seq)
                        .then(root.header.created_at.cmp(&best_root.header.created_at))
                        .then(object_id.cmp(best_id))
                        .is_gt()
                });
            if replace {
                best = Some((object_id, root, head_seq));
            }
        }

        let root = best.map(|(object_id, root, _head_seq)| (object_id, root));
        if let Some((object_id, root)) = &root {
            self.validate_singleton_root_history(*object_id, root, &roots)
                .await?;
            self.cache_root(generation, *object_id, root.clone());
        }
        Ok(root)
    }

    async fn validate_singleton_root_history(
        &self,
        root_object_id: ObjectId,
        root: &ConnectorStateRoot,
        roots: &[(ObjectId, ConnectorStateRoot)],
    ) -> Result<()> {
        if !root.model.is_singleton_writer() {
            return Ok(());
        }
        let Some(head_object_id) = root.head else {
            return Ok(());
        };

        // Sequence/time ordering only selects a candidate to inspect. It does
        // not resolve a fork: every committed root must lie on this one fully
        // authenticated lineage before the candidate can enter the cache.
        let mut lineage = HashSet::new();
        let mut next = Some(head_object_id);
        let mut newer: Option<ConnectorStateObject> = None;
        while let Some(object_id) = next {
            if !lineage.insert(object_id) {
                return Err(ConnectorStateStoreError::ChainCycle(object_id));
            }
            let (_, state) = self.load_state_object(&object_id).await?;
            if let Some(newer) = &newer {
                Self::validate_replay_transition(&root.model, &state, newer)?;
            }
            if state.prev.is_none() && state.seq != 0 {
                return Err(ConnectorStateStoreError::SequenceMismatch {
                    expected: 0,
                    got: state.seq,
                });
            }
            next = state.prev;
            newer = Some(state);
        }

        // Choose a deterministic conflicting root only for the error evidence.
        // No conflicting branch is accepted based on timestamp, length or ID.
        let conflicting = roots
            .iter()
            .filter_map(|(other_id, other)| {
                other
                    .head
                    .and_then(|head| (!lineage.contains(&head)).then_some((*other_id, head)))
            })
            .min_by_key(|(other_id, _)| *other_id);
        if let Some((root_b, head_b)) = conflicting {
            tracing::error!(
                target: CONNECTOR_STATE_TRACING_TARGET,
                event_type = "fcp.connector_state.fork",
                connector_id = %self.connector_id,
                zone_id = %self.zone_id,
                root_a = %root_object_id,
                root_b = %root_b,
                head_a = %head_object_id,
                head_b = %head_b,
                "refusing canonical singleton state with competing committed histories"
            );
            return Err(ConnectorStateStoreError::ForkDetected {
                root_a: root_object_id,
                root_b,
                head_a: Box::new(head_object_id),
                head_b: Box::new(head_b),
            });
        }
        Ok(())
    }

    fn cached_root(&self) -> Option<(ObjectId, ConnectorStateRoot)> {
        let generation = self.change_bus.generation();
        self.root_cache
            .read()
            .as_ref()
            .filter(|cached| cached.generation == generation)
            .map(|cached| (cached.object_id, cached.root.clone()))
    }

    fn cache_root(&self, generation: u64, object_id: ObjectId, root: ConnectorStateRoot) {
        *self.root_cache.write() = Some(CachedConnectorStateRoot {
            generation,
            object_id,
            root,
        });
    }

    async fn root_head_seq(&self, root: &ConnectorStateRoot) -> Result<Option<u64>> {
        match root.head {
            Some(head_id) => self
                .load_state_object(&head_id)
                .await
                .map(|(_object_id, state)| Some(state.seq)),
            None => Ok(None),
        }
    }

    /// Store a state root and return its content-addressed object id.
    ///
    /// This is intentionally not part of the public store API. Canonical
    /// connector-state mutation must enter through [`ConnectorStateStore`],
    /// which requires a [`ConnectorStateWriteAuthorization`] witness.
    ///
    /// # Errors
    /// Returns an error when the root identity or schema does not match this store.
    async fn store_root(&self, root: ConnectorStateRoot) -> Result<ObjectId> {
        self.validate_root(&root)?;
        let stored = self.stored_object(&root.header, &root, self.retention)?;
        let object_id = stored.object_id;
        self.put_idempotent(stored).await?;
        Ok(object_id)
    }

    async fn store_root_with_retry(&self, root: ConnectorStateRoot) -> Result<ObjectId> {
        let mut delays = self.root_write_retry_policy.retry_delays();
        let mut retry_index = 0_u32;

        loop {
            match self.store_root(root.clone()).await {
                Ok(root_id) => return Ok(root_id),
                Err(err) if Self::is_retryable_write_error(&err) => {
                    let Some(delay) = delays.next() else {
                        return Err(err);
                    };
                    self.record_write_retry("write_root", retry_index, delay, &err);
                    retry_index = retry_index.saturating_add(1);
                    if !delay.is_zero() {
                        fcp_async_core::time::sleep(delay).await;
                    }
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Append a state object if its prev pointer matches the canonical head.
    ///
    /// This is the internal append primitive used after the public trait
    /// boundary verifies [`ConnectorStateWriteAuthorization`].
    ///
    /// # Errors
    /// Returns an error when the incoming object is malformed or storage fails.
    async fn append_object(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ConnectorStateAppendOutcome> {
        let started = Instant::now();
        let result = self.append_object_inner(state_obj).await;
        let telemetry_result = match &result {
            Ok(ConnectorStateAppendOutcome::Committed { .. }) => "committed",
            Ok(ConnectorStateAppendOutcome::Conflict { .. }) => "conflict",
            Err(_) => "error",
        };
        fcp_telemetry::metrics::increment_counter(
            CONNECTOR_STATE_WRITES_TOTAL_METRIC,
            &[("result", telemetry_result)],
        );
        self.record_operation_telemetry(
            CONNECTOR_STATE_WRITE_EVENT,
            "write",
            telemetry_result,
            started,
        );
        result
    }

    async fn append_object_inner(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ConnectorStateAppendOutcome> {
        self.validate_incoming_state_object(&state_obj)?;

        // Independently constructed adapters over the same object store must
        // share the compare-and-commit gate, not just cloned adapters. This is
        // local serialization; replicated stores still need distributed lease
        // validation and fork detection at their admission boundary.
        let _append_guard = self.change_bus.append_guard.lock().await;
        // Recheck storage at the mutation boundary even when an external
        // writer's root announcement has not reached this adapter yet.
        self.change_bus.mark_root_updated();
        let root = self.read_root().await?;
        if let Some((_root_id, root)) = &root
            && root.model != self.state_model
        {
            return Err(ConnectorStateStoreError::IdentityMismatch {
                field: "model",
                expected: format!("{:?}", root.model),
                got: format!("{:?}", self.state_model),
            });
        }
        let current = match root.and_then(|(_root_id, root)| root.head) {
            Some(head_id) => Some(self.load_state_object(&head_id).await?),
            None => None,
        };
        if self.state_model.is_singleton_writer()
            && let Some((_head_id, head)) = &current
            && state_obj.lease_seq < head.lease_seq
        {
            return Err(ConnectorStateStoreError::StaleLease {
                held_seq: state_obj.lease_seq,
                current_seq: head.lease_seq,
            });
        }
        let expected_prev = current.as_ref().map(|(object_id, _state)| *object_id);
        if state_obj.prev != expected_prev {
            return Ok(ConnectorStateAppendOutcome::Conflict {
                canonical_head: expected_prev,
                canonical_seq: current.as_ref().map(|(_object_id, state)| state.seq),
            });
        }

        let expected_seq = match current {
            Some((_object_id, state)) => state
                .seq
                .checked_add(1)
                .ok_or(ConnectorStateStoreError::SequenceOverflow(state.seq))?,
            None => 0,
        };
        if state_obj.seq != expected_seq {
            return Err(ConnectorStateStoreError::SequenceMismatch {
                expected: expected_seq,
                got: state_obj.seq,
            });
        }

        // A cancelled put can have become durable even if its result was not
        // observed. Invalidate every adapter's cache before releasing the gate
        // on such an exit, so the next append re-reads canonical storage. The
        // backing store must order reads after admitted writes, including when
        // a caller drops its response future.
        let mut root_write = PendingRootWrite::new(&self.change_bus);
        let object_id = self
            .store_state_object_with_retry(state_obj.clone())
            .await?;
        let root = self.root_for_head(&state_obj, object_id);
        let root_object_id = self.store_root_with_retry(root).await?;
        self.publish_change(
            ConnectorStateChangeKind::ObjectAppended,
            Some(object_id),
            Some(state_obj.seq),
        );
        self.publish_change(
            ConnectorStateChangeKind::RootUpdated,
            Some(root_object_id),
            Some(state_obj.seq),
        );
        root_write.committed = true;

        // Snapshot failure or cancellation must not hide a committed root
        // from readers and change subscribers.
        let snapshot_object_id = self
            .maybe_emit_snapshot_after_root_commit(object_id, &state_obj)
            .await;
        if let Some(snapshot_object_id) = snapshot_object_id {
            self.publish_change(
                ConnectorStateChangeKind::SnapshotEmitted,
                Some(snapshot_object_id),
                Some(state_obj.seq),
            );
        }

        Ok(ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq: state_obj.seq,
            snapshot_object_id,
        })
    }

    /// Read state objects in ascending sequence order.
    ///
    /// # Errors
    /// Returns an error if a state object for this connector is malformed.
    pub async fn read_chain(
        &self,
        after_seq: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(ObjectId, ConnectorStateObject)>> {
        let started = Instant::now();
        let result = self.read_chain_inner(after_seq, limit).await;
        let telemetry_result = match &result {
            Ok(states) if states.is_empty() => "miss",
            Ok(_) => "hit",
            Err(_) => "error",
        };
        self.record_read_cache_telemetry("read", telemetry_result);
        self.record_operation_telemetry(
            CONNECTOR_STATE_READ_EVENT,
            "read",
            telemetry_result,
            started,
        );
        result
    }

    async fn read_chain_inner(
        &self,
        after_seq: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(ObjectId, ConnectorStateObject)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let Some((_root_id, root)) = self.read_root().await? else {
            return Ok(Vec::new());
        };

        let mut states = Vec::new();
        let mut visited = HashSet::new();
        let mut next = root.head;
        while let Some(object_id) = next {
            if !visited.insert(object_id) {
                return Err(ConnectorStateStoreError::ChainCycle(object_id));
            }
            let (_loaded_id, state) = self.load_state_object(&object_id).await?;
            if let Some((_, newer)) = states.last() {
                Self::validate_replay_transition(&root.model, &state, newer)?;
            }
            if state.prev.is_none() && state.seq != 0 {
                return Err(ConnectorStateStoreError::SequenceMismatch {
                    expected: 0,
                    got: state.seq,
                });
            }
            next = state.prev;
            states.push((object_id, state));
        }

        states.reverse();
        states.retain(|(_object_id, state)| after_seq.is_none_or(|min_seq| state.seq > min_seq));
        states.truncate(limit);
        Ok(states)
    }

    /// Recover one exact root from an authenticated snapshot and its state tail.
    ///
    /// Both IDs must come from a checkpoint or other context the caller already
    /// trusts. This method does not discover the latest root, establish anchor
    /// freshness, update the canonical-root cache, or authorize a write. It
    /// verifies keyed content IDs, envelopes, identities, signatures, configured
    /// writer pins, sequence continuity, and singleton lease monotonicity.
    ///
    /// The covered state must remain available to authenticate the snapshot.
    /// Its predecessor is never loaded, so a collected prefix is permitted.
    /// At most `max_tail_entries` later states are loaded; exceeding that budget
    /// returns an error instead of a partial replay. Zero permits a root exactly
    /// at the snapshot boundary. Snapshot and boundary validation add fixed work.
    ///
    /// # Errors
    /// Returns an error if either anchor is missing or malformed, the snapshot
    /// is not an ancestor of the requested root, a retained transition fails
    /// validation, or the complete tail exceeds the caller's budget.
    pub async fn replay_from_snapshot(
        &self,
        root_object_id: ObjectId,
        snapshot_object_id: ObjectId,
        max_tail_entries: usize,
    ) -> Result<ConnectorStateReplay> {
        let started = Instant::now();
        let result = self
            .replay_from_snapshot_inner(root_object_id, snapshot_object_id, max_tail_entries)
            .await;
        self.record_operation_telemetry(
            CONNECTOR_STATE_READ_EVENT,
            "replay_from_snapshot",
            if result.is_ok() { "hit" } else { "error" },
            started,
        );
        result
    }

    async fn replay_from_snapshot_inner(
        &self,
        root_object_id: ObjectId,
        snapshot_object_id: ObjectId,
        max_tail_entries: usize,
    ) -> Result<ConnectorStateReplay> {
        let stored = self.object_store.get(&root_object_id).await?;
        let root: ConnectorStateRoot =
            self.decode_stored(&stored, &Self::root_schema_id(), "connector state root")?;
        self.validate_stored_root(root_object_id, &stored, &root)?;
        if root.model != self.state_model {
            return Err(ConnectorStateStoreError::IdentityMismatch {
                field: "state_model",
                expected: self.state_model.to_string(),
                got: root.model.to_string(),
            });
        }

        let boundary_error = || ConnectorStateStoreError::SnapshotNotAncestor {
            root_object_id,
            snapshot_object_id,
        };
        let mut next = root.head.ok_or_else(boundary_error)?;
        let snapshot = self.load_snapshot(&snapshot_object_id).await?;
        let (_covered_id, covered_state) = self.load_state_object(&snapshot.covers_head).await?;
        let mut tail = Vec::new();
        let mut visited = HashSet::new();

        loop {
            if next == snapshot.covers_head {
                if let Some((_newer_id, newer)) = tail.last() {
                    Self::validate_replay_transition(&root.model, &covered_state, newer)?;
                }
                break;
            }
            if tail.len() == max_tail_entries {
                return Err(ConnectorStateStoreError::ReplayLimitExceeded {
                    limit: max_tail_entries,
                });
            }
            if !visited.insert(next) {
                return Err(ConnectorStateStoreError::ChainCycle(next));
            }
            let (object_id, state) = self.load_state_object(&next).await?;
            if state.seq <= snapshot.covers_seq {
                return Err(boundary_error());
            }
            if let Some((_newer_id, newer)) = tail.last() {
                Self::validate_replay_transition(&root.model, &state, newer)?;
            }
            next = state.prev.ok_or_else(boundary_error)?;
            tail.push((object_id, state));
        }

        tail.reverse();
        Ok(ConnectorStateReplay {
            root_object_id,
            root,
            snapshot_object_id,
            snapshot,
            covered_state,
            tail,
        })
    }

    fn validate_replay_transition(
        model: &ConnectorStateModel,
        older: &ConnectorStateObject,
        newer: &ConnectorStateObject,
    ) -> Result<()> {
        let expected = older
            .seq
            .checked_add(1)
            .ok_or(ConnectorStateStoreError::SequenceOverflow(older.seq))?;
        if newer.seq != expected {
            return Err(ConnectorStateStoreError::SequenceMismatch {
                expected,
                got: newer.seq,
            });
        }
        if model.is_singleton_writer() && newer.lease_seq < older.lease_seq {
            return Err(ConnectorStateStoreError::StaleLease {
                held_seq: newer.lease_seq,
                current_seq: older.lease_seq,
            });
        }
        Ok(())
    }

    /// Return canonical root/head/sequence status for operator explain routes.
    ///
    /// When a symbol store is supplied, `mesh_replica_count` is derived from
    /// the root object's symbol distribution. Without that distribution, the
    /// field remains `None` rather than inventing a replica count from a
    /// placement policy target.
    ///
    /// # Errors
    /// Returns an error if the canonical root or head cannot be decoded.
    pub async fn canonical_status(
        &self,
        symbol_store: Option<&dyn SymbolStore>,
    ) -> Result<ConnectorStateCanonicalStatus> {
        let Some((root_id, root)) = self.read_root().await? else {
            return Ok(ConnectorStateCanonicalStatus::missing(
                self.connector_id.clone(),
            ));
        };

        let last_canonical_seq = match root.head {
            Some(head_id) => Some(self.load_state_object(&head_id).await?.1.seq),
            None => None,
        };
        let mesh_replica_count = match symbol_store {
            Some(symbol_store) => symbol_store
                .get_distribution(&root_id)
                .await
                .map(|distribution| distribution.distinct_nodes()),
            None => None,
        };

        Ok(ConnectorStateCanonicalStatus::from_root(
            Some(root_id),
            &root,
            last_canonical_seq,
            mesh_replica_count,
        ))
    }

    /// Verify the canonical connector-state root and head before yielding a
    /// singleton-writer lease.
    ///
    /// The store does not buffer connector-local writes, so callers must append
    /// any in-flight state object before invoking this barrier. This method is
    /// the fail-closed durability check used by host/supervisor adapters: it
    /// reloads the canonical root, verifies the referenced head object, returns
    /// the head sequence and fencing evidence, and emits lease flush telemetry.
    ///
    /// # Errors
    /// Returns an error if the canonical root or referenced head is malformed,
    /// missing, or fails content-id verification.
    pub async fn flush_before_lease_yield(&self) -> Result<ConnectorStateLeaseYieldFlush> {
        let result = self.flush_before_lease_yield_inner().await;
        let outcome = match &result {
            Ok(flush) if flush.root_object_id.is_some() => "success",
            Ok(_) => "no_state",
            Err(_) => "error",
        };
        fcp_telemetry::metrics::record_lease_flushed_on_yield("singleton_writer", outcome);
        result
    }

    async fn flush_before_lease_yield_inner(&self) -> Result<ConnectorStateLeaseYieldFlush> {
        let _append_guard = self.change_bus.append_guard.lock().await;
        self.change_bus.mark_root_updated();
        let Some((root_object_id, root)) = self.read_root().await? else {
            return Ok(ConnectorStateLeaseYieldFlush::missing(self));
        };

        let Some(head_object_id) = root.head else {
            return Ok(ConnectorStateLeaseYieldFlush {
                connector_id: root.connector_id,
                instance_id: root.instance_id,
                zone_id: root.zone_id,
                root_object_id: Some(root_object_id),
                head_object_id: None,
                last_canonical_seq: None,
                lease_seq: None,
                lease_object_id: None,
            });
        };
        let (_loaded_id, head) = self.load_state_object(&head_object_id).await?;

        Ok(ConnectorStateLeaseYieldFlush {
            connector_id: root.connector_id,
            instance_id: root.instance_id,
            zone_id: root.zone_id,
            root_object_id: Some(root_object_id),
            head_object_id: Some(head_object_id),
            last_canonical_seq: Some(head.seq),
            lease_seq: Some(head.lease_seq),
            lease_object_id: Some(head.lease_object_id),
        })
    }

    /// Emit a snapshot for the current head, if any.
    ///
    /// # Errors
    /// Returns an error if the head cannot be authenticated, no matching
    /// snapshot signing key is configured, or storage fails.
    pub async fn snapshot_head(&self) -> Result<Option<ObjectId>> {
        let _append_guard = self.change_bus.append_guard.lock().await;
        self.change_bus.mark_root_updated();
        let Some((head_id, head)) = self.current_head().await? else {
            return Ok(None);
        };
        let snapshot_id = self.emit_snapshot(head_id).await?;
        self.publish_change(
            ConnectorStateChangeKind::SnapshotEmitted,
            Some(snapshot_id),
            Some(head.seq),
        );
        Ok(Some(snapshot_id))
    }

    /// Return the latest snapshot for this connector, if any.
    ///
    /// # Errors
    /// Returns an error if a matching snapshot is malformed, its own signature
    /// is invalid, or its covered state cannot be authenticated. Legacy objects
    /// that copied a state signature are rejected.
    pub async fn latest_snapshot(&self) -> Result<Option<(ObjectId, ConnectorStateSnapshot)>> {
        let mut best: Option<(ObjectId, ConnectorStateSnapshot)> = None;

        for object_id in self.object_store.list_zone(&self.zone_id).await {
            let stored = self.object_store.get(&object_id).await?;
            if stored.header.schema != Self::snapshot_schema_id() {
                continue;
            }

            let snapshot: ConnectorStateSnapshot = self.decode_stored(
                &stored,
                &Self::snapshot_schema_id(),
                "connector state snapshot",
            )?;
            if !self.snapshot_belongs_to_store(&snapshot) {
                continue;
            }
            self.validate_stored_snapshot(object_id, &stored, &snapshot)
                .await?;

            let replace = best.as_ref().is_none_or(|(best_id, best_snapshot)| {
                snapshot
                    .covers_seq
                    .cmp(&best_snapshot.covers_seq)
                    .then(snapshot.snapshotted_at.cmp(&best_snapshot.snapshotted_at))
                    .then(object_id.cmp(best_id))
                    .is_gt()
            });
            if replace {
                best = Some((object_id, snapshot));
            }
        }

        Ok(best)
    }

    async fn load_snapshot(&self, object_id: &ObjectId) -> Result<ConnectorStateSnapshot> {
        let stored = self.object_store.get(object_id).await?;
        let snapshot = self.decode_stored(
            &stored,
            &Self::snapshot_schema_id(),
            "connector state snapshot",
        )?;
        self.validate_stored_snapshot(*object_id, &stored, &snapshot)
            .await?;
        Ok(snapshot)
    }

    /// Mark state objects older than `before_seq` as ephemeral for later GC.
    ///
    /// This method intentionally does not delete objects; it only relaxes
    /// retention on non-head chain entries so the GC layer can make the final
    /// reachability decision under its own policy. Retention is not relaxed for
    /// a retained snapshot's covered head, which authenticates that snapshot.
    ///
    /// # Errors
    /// Returns an error if state/snapshot validation or retention updates fail.
    pub async fn compact(&self, before_seq: u64) -> Result<usize> {
        let started = Instant::now();
        let result = self.compact_inner(before_seq).await;
        let telemetry_result = if result.is_ok() { "ok" } else { "error" };
        self.record_operation_telemetry(
            CONNECTOR_STATE_COMPACT_EVENT,
            "compact",
            telemetry_result,
            started,
        );
        if matches!(result, Ok(updated) if updated > 0) {
            self.publish_change(ConnectorStateChangeKind::Compacted, None, Some(before_seq));
        }
        result
    }

    async fn compact_inner(&self, before_seq: u64) -> Result<usize> {
        let _append_guard = self.change_bus.append_guard.lock().await;
        self.change_bus.mark_root_updated();
        // The current head is still referenced by the root, so relaxing its
        // retention would let a retention-only GC strand the live chain
        // (`read_root`/`current_head` would then fail with `MissingHead`).
        // Honor the documented "non-head chain entries" contract and never
        // touch the head, even when `before_seq` exceeds the head sequence.
        let head_object_id = match self.read_root().await? {
            Some((_root_id, root)) => root.head,
            None => return Ok(0),
        };
        let states = self.read_chain(None, usize::MAX).await?;
        let mut snapshot_heads = HashSet::new();
        for object_id in self.object_store.list_zone(&self.zone_id).await {
            let stored = self.object_store.get(&object_id).await?;
            if stored.header.schema != Self::snapshot_schema_id() {
                continue;
            }
            let snapshot: ConnectorStateSnapshot = self.decode_stored(
                &stored,
                &Self::snapshot_schema_id(),
                "connector state snapshot",
            )?;
            if !self.snapshot_belongs_to_store(&snapshot) {
                continue;
            }
            self.validate_stored_snapshot(object_id, &stored, &snapshot)
                .await?;
            snapshot_heads.insert(snapshot.covers_head);
        }

        let mut updated = 0;
        for (object_id, state) in states {
            // A retention-only sweep does not follow refs from every retained
            // object. Keep the covered state available for snapshot signature
            // and projection verification, even after newer heads commit.
            if head_object_id.as_ref() == Some(&object_id) || snapshot_heads.contains(&object_id) {
                continue;
            }
            if state.seq < before_seq {
                self.object_store
                    .set_retention(&object_id, RetentionClass::Ephemeral)
                    .await?;
                updated += 1;
            }
        }
        Ok(updated)
    }

    async fn current_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>> {
        let Some((_root_id, root)) = self.read_root().await? else {
            return Ok(None);
        };
        let Some(head_id) = root.head else {
            return Ok(None);
        };
        self.load_state_object(&head_id).await.map(Some)
    }

    async fn load_state_object(
        &self,
        object_id: &ObjectId,
    ) -> Result<(ObjectId, ConnectorStateObject)> {
        let stored = self
            .object_store
            .get(object_id)
            .await
            .map_err(|err| match err {
                ObjectStoreError::NotFound(_) => ConnectorStateStoreError::MissingHead(*object_id),
                other => ConnectorStateStoreError::ObjectStore(other),
            })?;
        let state = self.load_state_from_stored(*object_id, &stored)?;
        if !self.state_belongs_to_store(&state) {
            return Err(ConnectorStateStoreError::IdentityMismatch {
                field: "connector_id",
                expected: self.connector_id.to_string(),
                got: state.connector_id.to_string(),
            });
        }
        Ok((*object_id, state))
    }

    fn load_state_from_stored(
        &self,
        object_id: ObjectId,
        stored: &StoredObject,
    ) -> Result<ConnectorStateObject> {
        let state: ConnectorStateObject = self.decode_stored(
            stored,
            &Self::state_object_schema_id(),
            "connector state object",
        )?;
        self.validate_stored_state_object(object_id, stored, &state)?;
        Ok(state)
    }

    async fn store_state_object(&self, state_obj: ConnectorStateObject) -> Result<ObjectId> {
        let stored = self.stored_object(&state_obj.header, &state_obj, self.retention)?;
        let object_id = stored.object_id;
        self.put_idempotent(stored).await?;
        Ok(object_id)
    }

    async fn store_state_object_with_retry(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ObjectId> {
        let mut delays = self.state_object_write_retry_policy.retry_delays();
        let mut retry_index = 0_u32;

        loop {
            match self.store_state_object(state_obj.clone()).await {
                Ok(object_id) => return Ok(object_id),
                Err(err) if Self::is_retryable_write_error(&err) => {
                    let Some(delay) = delays.next() else {
                        return Err(err);
                    };
                    self.record_write_retry("write_state_object", retry_index, delay, &err);
                    retry_index = retry_index.saturating_add(1);
                    if !delay.is_zero() {
                        fcp_async_core::time::sleep(delay).await;
                    }
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn maybe_emit_snapshot(
        &self,
        object_id: ObjectId,
        state_obj: &ConnectorStateObject,
    ) -> Result<Option<ObjectId>> {
        let entries_due = self.snapshot_every_entries != 0
            && state_obj
                .seq
                .checked_add(1)
                .is_some_and(|entries| entries % self.snapshot_every_entries == 0);
        if !entries_due && !self.elapsed_snapshot_due(state_obj).await? {
            return Ok(None);
        }
        self.emit_snapshot(object_id).await.map(Some)
    }

    async fn maybe_emit_snapshot_after_root_commit(
        &self,
        object_id: ObjectId,
        state_obj: &ConnectorStateObject,
    ) -> Option<ObjectId> {
        match self.maybe_emit_snapshot(object_id, state_obj).await {
            Ok(snapshot_object_id) => snapshot_object_id,
            Err(err) => {
                tracing::warn!(
                    target: CONNECTOR_STATE_TRACING_TARGET,
                    event_type = CONNECTOR_STATE_SNAPSHOT_EVENT,
                    connector_id = %self.connector_id,
                    zone_id = %self.zone_id,
                    operation = "snapshot_after_root_commit",
                    result = "skipped_after_error",
                    seq = state_obj.seq,
                    error = %err,
                    "connector-state append already committed root; skipping failed snapshot emission"
                );
                None
            }
        }
    }

    async fn elapsed_snapshot_due(&self, state_obj: &ConnectorStateObject) -> Result<bool> {
        if self.snapshot_every_secs == 0 {
            return Ok(false);
        }
        let Some((_snapshot_id, latest)) = self.latest_snapshot().await? else {
            return Ok(false);
        };
        Ok(state_obj.seq > latest.covers_seq
            && state_obj.updated_at.saturating_sub(latest.snapshotted_at)
                >= self.snapshot_every_secs)
    }

    async fn emit_snapshot(&self, covers_head: ObjectId) -> Result<ObjectId> {
        let started = Instant::now();
        let result = self.emit_snapshot_inner(covers_head).await;
        let telemetry_result = if result.is_ok() { "emitted" } else { "error" };
        self.record_operation_telemetry(
            CONNECTOR_STATE_SNAPSHOT_EVENT,
            "snapshot",
            telemetry_result,
            started,
        );
        result
    }

    async fn emit_snapshot_inner(&self, covers_head: ObjectId) -> Result<ObjectId> {
        let signing_key = self.snapshot_signing_key.as_ref().ok_or_else(|| {
            ConnectorStateStoreError::SnapshotSigningUnavailable {
                reason: "configure with_snapshot_signing_key with the covered writer's key"
                    .to_string(),
            }
        })?;
        let (_head_id, state_obj) = self.load_state_object(&covers_head).await?;
        if signing_key.verifying_key().to_bytes() != state_obj.writer_public_key {
            return Err(ConnectorStateStoreError::SnapshotSigningUnavailable {
                reason: "configured snapshot key does not match the authenticated covered writer"
                    .to_string(),
            });
        }

        let mut header = self.derived_header(
            Self::snapshot_schema_id(),
            state_obj.header.created_at,
            state_obj.header.provenance.clone(),
        );
        header.refs.push(covers_head);
        header.placement.clone_from(&state_obj.header.placement);

        let mut snapshot = ConnectorStateSnapshot {
            header,
            connector_id: self.connector_id.clone(),
            instance_id: self.instance_id.clone(),
            zone_id: self.zone_id.clone(),
            covers_head,
            covers_seq: state_obj.seq,
            state_cbor: state_obj.state_cbor.clone(),
            snapshotted_at: state_obj.updated_at,
            signature: fcp_prelude::Signature::zero(),
        };

        self.validate_snapshot(&snapshot)?;
        snapshot.sign_with(signing_key)?;
        let stored = self.stored_object(&snapshot.header, &snapshot, self.retention)?;
        let object_id = stored.object_id;
        self.put_idempotent(stored).await?;
        Ok(object_id)
    }

    async fn put_idempotent(&self, stored: StoredObject) -> Result<()> {
        match self.object_store.put(stored).await {
            Ok(()) | Err(ObjectStoreError::AlreadyExists(_)) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    fn stored_object<T: Serialize>(
        &self,
        header: &ObjectHeader,
        value: &T,
        retention: RetentionClass,
    ) -> Result<StoredObject> {
        let body = CanonicalSerializer::serialize(value, &header.schema)?;
        let object_id = StoredObject::derive_id(header, &body, &self.object_id_key)?;
        Ok(StoredObject {
            object_id,
            header: header.clone(),
            body,
            storage: StorageMeta { retention },
        })
    }

    fn decode_stored<T: DeserializeOwned + Serialize>(
        &self,
        stored: &StoredObject,
        expected_schema: &SchemaId,
        kind: &'static str,
    ) -> Result<T> {
        if stored.header.schema != *expected_schema {
            return Err(ConnectorStateStoreError::UnexpectedSchema {
                kind,
                expected: format!("{expected_schema:?}"),
                got: format!("{:?}", stored.header.schema),
            });
        }

        let computed = StoredObject::derive_id(&stored.header, &stored.body, &self.object_id_key)?;
        if computed != stored.object_id {
            return Err(ConnectorStateStoreError::ContentIdMismatch {
                claimed: stored.object_id,
                computed,
            });
        }

        Ok(CanonicalSerializer::deserialize(
            &stored.body,
            expected_schema,
        )?)
    }

    fn validate_stored_root(
        &self,
        object_id: ObjectId,
        stored: &StoredObject,
        root: &ConnectorStateRoot,
    ) -> Result<()> {
        self.validate_root(root)?;
        if !headers_match(&stored.header, &root.header)? {
            return Err(ConnectorStateStoreError::HeaderBodyMismatch);
        }
        let computed = StoredObject::derive_id(&stored.header, &stored.body, &self.object_id_key)?;
        if computed != object_id {
            return Err(ConnectorStateStoreError::ContentIdMismatch {
                claimed: object_id,
                computed,
            });
        }
        Ok(())
    }

    fn validate_root(&self, root: &ConnectorStateRoot) -> Result<()> {
        Self::expect_schema(
            "connector state root",
            &root.header.schema,
            &Self::root_schema_id(),
        )?;
        self.expect_connector(&root.connector_id)?;
        self.expect_zone("root.zone_id", &root.zone_id)?;
        self.expect_zone("root.header.zone_id", &root.header.zone_id)?;
        self.expect_instance(root.instance_id.as_ref())?;
        if let Some(head) = root.head
            && !root.header.refs.contains(&head)
        {
            return Err(ConnectorStateStoreError::MissingHead(head));
        }
        Ok(())
    }

    fn validate_snapshot(&self, snapshot: &ConnectorStateSnapshot) -> Result<()> {
        Self::expect_schema(
            "connector state snapshot",
            &snapshot.header.schema,
            &Self::snapshot_schema_id(),
        )?;
        self.expect_connector(&snapshot.connector_id)?;
        self.expect_zone("snapshot.zone_id", &snapshot.zone_id)?;
        self.expect_zone("snapshot.header.zone_id", &snapshot.header.zone_id)?;
        self.expect_instance(snapshot.instance_id.as_ref())?;
        if !snapshot.header.refs.contains(&snapshot.covers_head) {
            return Err(ConnectorStateStoreError::MissingHead(snapshot.covers_head));
        }
        Ok(())
    }

    async fn validate_stored_snapshot(
        &self,
        object_id: ObjectId,
        stored: &StoredObject,
        snapshot: &ConnectorStateSnapshot,
    ) -> Result<()> {
        self.validate_snapshot(snapshot)?;
        if !headers_match(&stored.header, &snapshot.header)? {
            return Err(ConnectorStateStoreError::HeaderBodyMismatch);
        }
        let computed = StoredObject::derive_id(&stored.header, &stored.body, &self.object_id_key)?;
        if computed != object_id {
            return Err(ConnectorStateStoreError::ContentIdMismatch {
                claimed: object_id,
                computed,
            });
        }

        // The covered state supplies the authenticated writer key and passes
        // the same identity, canonical encoding, signature, and pin checks as
        // every other canonical state read.
        let (_head_id, covered) = self.load_state_object(&snapshot.covers_head).await?;
        if snapshot.covers_seq != covered.seq {
            return Err(ConnectorStateStoreError::SnapshotStateMismatch {
                covers_head: snapshot.covers_head,
                field: "covers_seq",
            });
        }
        if snapshot.state_cbor != covered.state_cbor {
            return Err(ConnectorStateStoreError::SnapshotStateMismatch {
                covers_head: snapshot.covers_head,
                field: "state_cbor",
            });
        }
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&covered.writer_public_key).map_err(|err| {
                ConnectorStateStoreError::InvalidSnapshotSignature(err.to_string())
            })?;
        snapshot
            .verify_signature_with(&verifying_key)
            .map_err(|err| ConnectorStateStoreError::InvalidSnapshotSignature(err.to_string()))
    }

    fn validate_incoming_state_object(&self, state: &ConnectorStateObject) -> Result<()> {
        Self::expect_schema(
            "connector state object",
            &state.header.schema,
            &Self::state_object_schema_id(),
        )?;
        self.expect_connector(&state.connector_id)?;
        self.expect_zone("state.zone_id", &state.zone_id)?;
        self.expect_zone("state.header.zone_id", &state.header.zone_id)?;
        self.expect_instance(state.instance_id.as_ref())?;
        if state.state_cbor.is_empty() {
            return Err(ConnectorStateStoreError::EmptyStateCbor);
        }
        Self::validate_state_cbor(&state.state_cbor)?;
        if !state.header.refs.contains(&state.lease_object_id) {
            return Err(ConnectorStateStoreError::MissingLeaseReference(
                state.lease_object_id,
            ));
        }
        Ok(())
    }

    fn verify_authorized_state_signature(
        state: &ConnectorStateObject,
        authorization: &ConnectorStateWriteAuthorization,
    ) -> Result<()> {
        if state.writer_public_key != authorization.writer_public_key() {
            return Err(ConnectorStateStoreError::InvalidStateSignature(
                "state writer key does not match append authorization".to_string(),
            ));
        }
        Self::verify_state_signature(state)
    }

    fn verify_state_signature(state: &ConnectorStateObject) -> Result<()> {
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&state.writer_public_key).map_err(|err| {
                ConnectorStateStoreError::InvalidStateSignature(format!(
                    "state writer key rejected: {err}"
                ))
            })?;
        state
            .verify_signature_with(&verifying_key)
            .map_err(|err| ConnectorStateStoreError::InvalidStateSignature(err.to_string()))
    }

    fn validate_state_cbor(state_cbor: &[u8]) -> Result<()> {
        if state_cbor.len() > MAX_CONNECTOR_STATE_CBOR_BYTES {
            return Err(ConnectorStateStoreError::InvalidStateCbor(
                SerializationError::PayloadTooLarge {
                    len: state_cbor.len(),
                    max: MAX_CONNECTOR_STATE_CBOR_BYTES,
                },
            ));
        }

        let mut reader = state_cbor;
        let value = from_reader_with_recursion_limit::<CborValue, _>(
            &mut reader,
            MAX_DESERIALIZATION_RECURSION_LIMIT,
        )
        .map_err(Self::invalid_state_cbor_decode)?;
        if !reader.is_empty() {
            return Err(ConnectorStateStoreError::InvalidStateCbor(
                SerializationError::TrailingBytes,
            ));
        }

        let canonical = fcp_cbor::to_canonical_cbor(&value)
            .map_err(ConnectorStateStoreError::InvalidStateCbor)?;
        if canonical != state_cbor {
            return Err(ConnectorStateStoreError::InvalidStateCbor(
                SerializationError::NonCanonicalEncoding,
            ));
        }

        Ok(())
    }

    fn invalid_state_cbor_decode(
        err: ciborium::de::Error<std::io::Error>,
    ) -> ConnectorStateStoreError {
        let err = match err {
            ciborium::de::Error::RecursionLimitExceeded => SerializationError::DepthExceeded {
                depth: MAX_DESERIALIZATION_RECURSION_LIMIT + 1,
                max: MAX_CANONICALIZATION_DEPTH,
            },
            other => SerializationError::CborDeserialize(other),
        };
        ConnectorStateStoreError::InvalidStateCbor(err)
    }

    fn validate_stored_state_object(
        &self,
        object_id: ObjectId,
        stored: &StoredObject,
        state: &ConnectorStateObject,
    ) -> Result<()> {
        self.validate_incoming_state_object(state)?;
        if !headers_match(&stored.header, &state.header)? {
            return Err(ConnectorStateStoreError::HeaderBodyMismatch);
        }
        let computed = StoredObject::derive_id(&stored.header, &stored.body, &self.object_id_key)?;
        if computed != object_id {
            return Err(ConnectorStateStoreError::ContentIdMismatch {
                claimed: object_id,
                computed,
            });
        }
        self.ensure_trusted_writer(state)?;
        Self::verify_state_signature(state)?;
        Ok(())
    }

    /// Enforce the read-path writer pin, when one is configured.
    ///
    /// Without a pin this is a no-op: the object is then only bound to its own
    /// embedded writer key by [`Self::verify_state_signature`], which keyed
    /// content-ids protect from non-members but not from zone insiders.
    fn ensure_trusted_writer(&self, state: &ConnectorStateObject) -> Result<()> {
        if let Some(trusted) = &self.trusted_writer_keys
            && !trusted.contains(&state.writer_public_key)
        {
            return Err(ConnectorStateStoreError::UntrustedWriterKey {
                writer_public_key: writer_key_hex(&state.writer_public_key),
            });
        }
        Ok(())
    }

    fn root_belongs_to_store(&self, root: &ConnectorStateRoot) -> bool {
        root.connector_id == self.connector_id
            && root.zone_id == self.zone_id
            && root.instance_id == self.instance_id
    }

    fn state_belongs_to_store(&self, state: &ConnectorStateObject) -> bool {
        state.connector_id == self.connector_id
            && state.zone_id == self.zone_id
            && state.instance_id == self.instance_id
    }

    fn snapshot_belongs_to_store(&self, snapshot: &ConnectorStateSnapshot) -> bool {
        snapshot.connector_id == self.connector_id
            && snapshot.zone_id == self.zone_id
            && snapshot.instance_id == self.instance_id
    }

    fn root_for_head(
        &self,
        state_obj: &ConnectorStateObject,
        head: ObjectId,
    ) -> ConnectorStateRoot {
        let mut header = self.derived_header(
            Self::root_schema_id(),
            state_obj.header.created_at,
            state_obj.header.provenance.clone(),
        );
        header.refs.push(head);
        header.placement.clone_from(&state_obj.header.placement);

        ConnectorStateRoot {
            header,
            connector_id: self.connector_id.clone(),
            instance_id: self.instance_id.clone(),
            zone_id: self.zone_id.clone(),
            model: self.state_model.clone(),
            head: Some(head),
            state_schema_version: 1,
        }
    }

    fn derived_header(
        &self,
        schema: SchemaId,
        created_at: u64,
        provenance: fcp_prelude::Provenance,
    ) -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema,
            zone_id: self.zone_id.clone(),
            created_at,
            provenance,
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn expect_schema(kind: &'static str, got: &SchemaId, expected: &SchemaId) -> Result<()> {
        if got == expected {
            return Ok(());
        }
        Err(ConnectorStateStoreError::UnexpectedSchema {
            kind,
            expected: format!("{expected:?}"),
            got: format!("{got:?}"),
        })
    }

    fn expect_connector(&self, got: &ConnectorId) -> Result<()> {
        if got == &self.connector_id {
            return Ok(());
        }
        Err(ConnectorStateStoreError::IdentityMismatch {
            field: "connector_id",
            expected: self.connector_id.to_string(),
            got: got.to_string(),
        })
    }

    fn expect_zone(&self, field: &'static str, got: &ZoneId) -> Result<()> {
        if got == &self.zone_id {
            return Ok(());
        }
        Err(ConnectorStateStoreError::IdentityMismatch {
            field,
            expected: self.zone_id.to_string(),
            got: got.to_string(),
        })
    }

    fn expect_instance(&self, got: Option<&InstanceId>) -> Result<()> {
        if got == self.instance_id.as_ref() {
            return Ok(());
        }
        Err(ConnectorStateStoreError::IdentityMismatch {
            field: "instance_id",
            expected: self
                .instance_id
                .as_ref()
                .map_or_else(|| "<none>".to_string(), ToString::to_string),
            got: got.map_or_else(|| "<none>".to_string(), ToString::to_string),
        })
    }

    fn ensure_requested_connector(
        &self,
        connector_id: &ConnectorId,
    ) -> std::result::Result<(), ConnectorStateError> {
        if connector_id == &self.connector_id {
            return Ok(());
        }
        Err(ConnectorStateError::MalformedState {
            connector_id: connector_id.clone(),
            reason: format!(
                "requested connector_id does not match store connector_id {}",
                self.connector_id
            ),
        })
    }

    fn ensure_write_authorized(
        &self,
        connector_id: &ConnectorId,
        authorization: &ConnectorStateWriteAuthorization,
    ) -> std::result::Result<(), ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        if authorization.connector_id() != connector_id {
            return Err(ConnectorStateError::AuthorizationDenied {
                connector_id: connector_id.clone(),
                reason: format!(
                    "authorization connector {} does not match append connector {}",
                    authorization.connector_id(),
                    connector_id
                ),
            });
        }
        if authorization.zone_id() != &self.zone_id {
            return Err(ConnectorStateError::AuthorizationDenied {
                connector_id: connector_id.clone(),
                reason: format!(
                    "authorization zone {} does not match store zone {}",
                    authorization.zone_id(),
                    self.zone_id
                ),
            });
        }
        if let Some(trusted) = &self.trusted_writer_keys
            && !trusted.contains(&authorization.writer_public_key())
        {
            return Err(ConnectorStateError::AuthorizationDenied {
                connector_id: connector_id.clone(),
                reason: format!(
                    "authorization writer key {} is not in the store's trusted writer set",
                    writer_key_hex(&authorization.writer_public_key())
                ),
            });
        }
        Ok(())
    }

    fn record_operation_telemetry(
        &self,
        event_type: &'static str,
        operation: &'static str,
        result: &'static str,
        started: Instant,
    ) {
        let latency_seconds = started.elapsed().as_secs_f64();
        fcp_telemetry::metrics::record_histogram(
            CONNECTOR_STATE_LATENCY_SECONDS_METRIC,
            latency_seconds,
            &[("operation", operation), ("result", result)],
        );
        tracing::info!(
            target: CONNECTOR_STATE_TRACING_TARGET,
            event_type,
            connector_id = %self.connector_id,
            zone_id = %self.zone_id,
            operation,
            result,
            latency_seconds,
            metric_name = CONNECTOR_STATE_LATENCY_SECONDS_METRIC,
        );
    }

    fn record_read_cache_telemetry(&self, operation: &'static str, result: &'static str) {
        let Some(metric_name) = Self::read_cache_metric_for_result(result) else {
            return;
        };
        fcp_telemetry::metrics::increment_counter(
            metric_name,
            &[("operation", operation), ("result", result)],
        );
        if metric_name == CONNECTOR_STATE_FALL_THROUGH_TOTAL_METRIC {
            tracing::info!(
                target: CONNECTOR_STATE_TRACING_TARGET,
                event_type = CONNECTOR_STATE_FALL_THROUGH_EVENT,
                connector_id = %self.connector_id,
                zone_id = %self.zone_id,
                operation,
                cache_result = result,
                canonical_storage = "mesh",
                result = "fcp-store-read",
                metric_name,
                "connector-state cache miss fell through to canonical fcp-store"
            );
        }
    }

    const fn read_cache_metric_for_result(result: &str) -> Option<&'static str> {
        match result.as_bytes() {
            b"hit" => Some(CONNECTOR_STATE_CACHE_HITS_TOTAL_METRIC),
            b"miss" => Some(CONNECTOR_STATE_FALL_THROUGH_TOTAL_METRIC),
            _ => None,
        }
    }

    fn record_write_retry(
        &self,
        operation: &'static str,
        retry_index: u32,
        delay: Duration,
        err: &ConnectorStateStoreError,
    ) {
        tracing::warn!(
            target: CONNECTOR_STATE_TRACING_TARGET,
            event_type = CONNECTOR_STATE_WRITE_RETRY_EVENT,
            connector_id = %self.connector_id,
            zone_id = %self.zone_id,
            operation,
            result = "retry",
            retry_index,
            retry_delay_ms = delay.as_millis(),
            reason = %err,
        );
    }

    const fn is_retryable_write_error(err: &ConnectorStateStoreError) -> bool {
        matches!(
            err,
            ConnectorStateStoreError::ObjectStore(ObjectStoreError::Io(_))
        )
    }

    fn publish_change(
        &self,
        kind: ConnectorStateChangeKind,
        object_id: Option<ObjectId>,
        seq: Option<u64>,
    ) -> ConnectorStateChange {
        if matches!(kind, ConnectorStateChangeKind::RootUpdated) {
            self.change_bus.mark_root_updated();
        }
        let change = ConnectorStateChange {
            connector_id: self.connector_id.clone(),
            instance_id: self.instance_id.clone(),
            zone_id: self.zone_id.clone(),
            kind,
            object_id,
            seq,
            observed_at: Self::now_unix_seconds(),
        };
        let _ = self.change_bus.sender.send(change.clone());
        change
    }

    fn now_unix_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }

    fn to_connector_state_error(&self, err: ConnectorStateStoreError) -> ConnectorStateError {
        match err {
            ConnectorStateStoreError::ObjectStore(err) => ConnectorStateError::StorageUnavailable {
                connector_id: self.connector_id.clone(),
                reason: err.to_string(),
            },
            ConnectorStateStoreError::ForkDetected {
                root_a,
                root_b,
                head_a,
                head_b,
            } => ConnectorStateError::ForkDetected {
                connector_id: self.connector_id.clone(),
                root_a,
                root_b,
                head_a,
                head_b,
            },
            ConnectorStateStoreError::MissingHead(head) => {
                ConnectorStateError::SnapshotUnavailable {
                    connector_id: self.connector_id.clone(),
                    reason: format!("root references missing state object {head}"),
                }
            }
            ConnectorStateStoreError::SnapshotSigningUnavailable { reason } => {
                ConnectorStateError::SnapshotUnavailable {
                    connector_id: self.connector_id.clone(),
                    reason,
                }
            }
            ConnectorStateStoreError::ReplayLimitExceeded { limit }
            | ConnectorStateStoreError::ReplicaObjectLimitExceeded { limit }
            | ConnectorStateStoreError::ReplicaByteLimitExceeded { limit } => {
                ConnectorStateError::InvalidLimit { limit }
            }
            ConnectorStateStoreError::StaleLease {
                held_seq,
                current_seq,
            } => ConnectorStateError::StaleLease {
                connector_id: self.connector_id.clone(),
                held_seq,
                current_seq,
            },
            ConnectorStateStoreError::UnexpectedSchema { .. }
            | ConnectorStateStoreError::IdentityMismatch { .. }
            | ConnectorStateStoreError::HeaderBodyMismatch
            | ConnectorStateStoreError::ContentIdMismatch { .. }
            | ConnectorStateStoreError::MissingLeaseReference(_)
            | ConnectorStateStoreError::EmptyStateCbor
            | ConnectorStateStoreError::InvalidStateCbor(_)
            | ConnectorStateStoreError::InvalidStateSignature(_)
            | ConnectorStateStoreError::InvalidSnapshotSignature(_)
            | ConnectorStateStoreError::SnapshotStateMismatch { .. }
            | ConnectorStateStoreError::SnapshotNotAncestor { .. }
            | ConnectorStateStoreError::SequenceMismatch { .. }
            | ConnectorStateStoreError::SequenceOverflow(_)
            | ConnectorStateStoreError::ChainCycle(_)
            | ConnectorStateStoreError::UntrustedWriterKey { .. }
            | ConnectorStateStoreError::InvalidReplica { .. }
            | ConnectorStateStoreError::ReplicaObjectConflict { .. }
            | ConnectorStateStoreError::Serialization(_) => ConnectorStateError::MalformedState {
                connector_id: self.connector_id.clone(),
                reason: err.to_string(),
            },
        }
    }
}

#[async_trait::async_trait]
impl ConnectorStateStore for FcpStoreConnectorStateStore {
    async fn read_root(
        &self,
        connector_id: &ConnectorId,
    ) -> std::result::Result<Option<ConnectorStateRoot>, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        Self::read_root(self)
            .await
            .map(|root| root.map(|(_object_id, root)| root))
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn append_object(
        &self,
        connector_id: &ConnectorId,
        authorization: &ConnectorStateWriteAuthorization,
        object: ConnectorStateObject,
    ) -> std::result::Result<ConnectorStateAppendOutcome, ConnectorStateError> {
        self.ensure_write_authorized(connector_id, authorization)?;
        self.validate_incoming_state_object(&object)
            .map_err(|err| self.to_connector_state_error(err))?;
        Self::verify_authorized_state_signature(&object, authorization)
            .map_err(|err| self.to_connector_state_error(err))?;
        Self::append_object(self, object)
            .await
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn read_chain(
        &self,
        connector_id: &ConnectorId,
        after_seq: Option<u64>,
        limit: usize,
    ) -> std::result::Result<Vec<ConnectorStateObject>, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        Self::read_chain(self, after_seq, limit)
            .await
            .map(|states| {
                states
                    .into_iter()
                    .map(|(_object_id, state)| state)
                    .collect()
            })
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn canonical_status(
        &self,
        connector_id: &ConnectorId,
    ) -> std::result::Result<ConnectorStateCanonicalStatus, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        Self::canonical_status(self, None)
            .await
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn snapshot(
        &self,
        connector_id: &ConnectorId,
    ) -> std::result::Result<ConnectorStateSnapshot, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        let snapshot_id = Self::snapshot_head(self)
            .await
            .map_err(|err| self.to_connector_state_error(err))?
            .ok_or_else(|| ConnectorStateError::SnapshotUnavailable {
                connector_id: connector_id.clone(),
                reason: "no connector state head exists".to_string(),
            })?;
        self.load_snapshot(&snapshot_id)
            .await
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn compact(
        &self,
        connector_id: &ConnectorId,
        before_seq: u64,
    ) -> std::result::Result<usize, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        Self::compact(self, before_seq)
            .await
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn subscribe_changes(
        &self,
        connector_id: &ConnectorId,
    ) -> std::result::Result<ConnectorStateChangeStream, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        let receiver = self.change_bus.sender.subscribe();
        let connector_id = self.connector_id.clone();
        Ok(Box::pin(stream::unfold(receiver, move |mut receiver| {
            let connector_id = connector_id.clone();
            async move {
                match receiver.recv().await {
                    Ok(change) => Some((Ok(change), receiver)),
                    Err(broadcast::error::RecvError::Lagged(skipped)) => Some((
                        Err(ConnectorStateError::SubscribeUnavailable {
                            connector_id,
                            reason: format!(
                                "connector-state change stream lagged by {skipped} messages"
                            ),
                        }),
                        receiver,
                    )),
                    Err(broadcast::error::RecvError::Closed) => None,
                }
            }
        })))
    }
}

#[derive(Debug)]
struct ConnectorStateChangeBus {
    sender: broadcast::Sender<ConnectorStateChange>,
    root_generation: AtomicU64,
    append_guard: AsyncMutex<()>,
}

impl ConnectorStateChangeBus {
    fn new() -> Self {
        let (sender, _receiver) = broadcast::channel(CONNECTOR_STATE_CHANGE_BUFFER_CAPACITY);
        Self {
            sender,
            root_generation: AtomicU64::new(0),
            append_guard: AsyncMutex::new(()),
        }
    }

    fn generation(&self) -> u64 {
        self.root_generation.load(Ordering::Acquire)
    }

    fn mark_root_updated(&self) {
        self.root_generation.fetch_add(1, Ordering::AcqRel);
    }
}

/// Invalidate a possibly committed root before an interrupted append releases
/// its serialization gate. This does not claim that a failed put committed;
/// it makes the next reader resolve that uncertainty from storage.
struct PendingRootWrite<'a> {
    change_bus: &'a ConnectorStateChangeBus,
    committed: bool,
}

impl<'a> PendingRootWrite<'a> {
    const fn new(change_bus: &'a ConnectorStateChangeBus) -> Self {
        Self {
            change_bus,
            committed: false,
        }
    }
}

impl Drop for PendingRootWrite<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.change_bus.mark_root_updated();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectorStateChangeBusKey {
    object_store_addr: usize,
    connector_id: String,
    zone_id: String,
}

type ConnectorStateChangeBusRegistry =
    parking_lot::Mutex<HashMap<ConnectorStateChangeBusKey, Weak<ConnectorStateChangeBus>>>;

fn change_bus_registry() -> &'static ConnectorStateChangeBusRegistry {
    static REGISTRY: OnceLock<ConnectorStateChangeBusRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

fn shared_change_bus(
    object_store: &Arc<dyn ObjectStore>,
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
) -> Arc<ConnectorStateChangeBus> {
    let key = ConnectorStateChangeBusKey {
        object_store_addr: Arc::as_ptr(object_store).cast::<()>() as usize,
        connector_id: connector_id.to_string(),
        zone_id: zone_id.as_str().to_owned(),
    };
    let mut registry = change_bus_registry().lock();
    if let Some(existing) = registry.get(&key).and_then(Weak::upgrade) {
        return existing;
    }

    let change_bus = Arc::new(ConnectorStateChangeBus::new());
    registry.insert(key, Arc::downgrade(&change_bus));
    registry.retain(|_, candidate| candidate.strong_count() > 0);
    change_bus
}

fn headers_match(left: &ObjectHeader, right: &ObjectHeader) -> Result<bool> {
    Ok(fcp_cbor::to_canonical_cbor(left)? == fcp_cbor::to_canonical_cbor(right)?)
}

fn writer_key_hex(key: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    key.iter().fold(String::with_capacity(64), |mut out, byte| {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
        out
    })
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use chrono::Duration;
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_prelude::{
        CONNECTOR_STATE_APPEND_OPERATION_ID, CONNECTOR_STATE_WRITE_CAPABILITY_ID,
        CapabilityConstraints, CapabilityToken, CapabilityVerifier, Provenance, Signature,
        connector_state_resource_uri,
    };
    use futures_util::StreamExt;

    use super::*;
    use crate::{
        DurableObjectStore, DurableObjectStoreConfig, MemoryObjectStore, MemoryObjectStoreConfig,
        MemorySymbolStore, MemorySymbolStoreConfig, ObjectSymbolMeta, ObjectTransmissionInfo,
        StoredSymbol, SymbolMeta,
    };

    fn run_async<F, T>(future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("runtime")
    }

    fn store() -> Arc<MemoryObjectStore> {
        Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()))
    }

    fn symbol_store() -> MemorySymbolStore {
        MemorySymbolStore::new(MemorySymbolStoreConfig::default())
    }

    fn object_id_key() -> ObjectIdKey {
        ObjectIdKey::from_bytes([42; 32])
    }

    fn connector_id() -> ConnectorId {
        ConnectorId::from_static("slack:chat:v1")
    }

    fn other_connector_id() -> ConnectorId {
        ConnectorId::from_static("github:request_response:v1")
    }

    fn zone_id() -> ZoneId {
        ZoneId::work()
    }

    fn other_zone_id() -> ZoneId {
        ZoneId::private()
    }

    fn lease_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    fn test_store(object_store: Arc<dyn ObjectStore>) -> FcpStoreConnectorStateStore {
        FcpStoreConnectorStateStore::new(object_store, object_id_key(), connector_id(), zone_id())
            .with_snapshot_signing_key(Arc::new(test_state_signing_key()))
    }

    fn store_snapshot_for_test(
        state_store: &FcpStoreConnectorStateStore,
        snapshot: &ConnectorStateSnapshot,
    ) -> ObjectId {
        let stored = state_store
            .stored_object(&snapshot.header, snapshot, RetentionClass::Pinned)
            .unwrap();
        let object_id = stored.object_id;
        run_async(state_store.object_store.put(stored)).unwrap();
        object_id
    }

    struct FailNthPutObjectStore {
        inner: Arc<dyn ObjectStore>,
        fail_on_put: usize,
        puts: AtomicUsize,
    }

    impl FailNthPutObjectStore {
        fn new(inner: Arc<dyn ObjectStore>, fail_on_put: usize) -> Self {
            Self {
                inner,
                fail_on_put,
                puts: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for FailNthPutObjectStore {
        async fn put(&self, object: StoredObject) -> std::result::Result<(), ObjectStoreError> {
            let put_number = self.puts.fetch_add(1, Ordering::SeqCst) + 1;
            if put_number == self.fail_on_put {
                return Err(ObjectStoreError::Io(
                    "simulated connector state put outage".to_string(),
                ));
            }
            self.inner.put(object).await
        }

        async fn get(&self, id: &ObjectId) -> std::result::Result<StoredObject, ObjectStoreError> {
            self.inner.get(id).await
        }

        async fn exists(&self, id: &ObjectId) -> bool {
            self.inner.exists(id).await
        }

        async fn delete(&self, id: &ObjectId) -> std::result::Result<(), ObjectStoreError> {
            self.inner.delete(id).await
        }

        async fn get_header(
            &self,
            id: &ObjectId,
        ) -> std::result::Result<ObjectHeader, ObjectStoreError> {
            self.inner.get_header(id).await
        }

        async fn get_storage_meta(
            &self,
            id: &ObjectId,
        ) -> std::result::Result<StorageMeta, ObjectStoreError> {
            self.inner.get_storage_meta(id).await
        }

        async fn set_retention(
            &self,
            id: &ObjectId,
            retention: RetentionClass,
        ) -> std::result::Result<(), ObjectStoreError> {
            self.inner.set_retention(id, retention).await
        }

        async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
            self.inner.list_zone(zone_id).await
        }

        async fn storage_used(&self) -> u64 {
            self.inner.storage_used().await
        }

        async fn storage_quota(&self) -> u64 {
            self.inner.storage_quota().await
        }
    }

    /// Hold one real memory-store put at a selected persistence boundary.
    /// Tests poll the competing operations explicitly, without sleep-based
    /// scheduling or an executor-specific task cancellation API.
    struct PausedPutObjectStore {
        inner: Arc<dyn ObjectStore>,
        pause_on_put: usize,
        pause_after_write: bool,
        pause_on_snapshot_get: bool,
        puts: AtomicUsize,
        snapshot_gets: AtomicUsize,
        release: parking_lot::Mutex<(bool, Option<std::task::Waker>)>,
    }

    impl PausedPutObjectStore {
        fn new(pause_on_put: usize, pause_after_write: bool) -> Self {
            Self {
                inner: store(),
                pause_on_put,
                pause_after_write,
                pause_on_snapshot_get: false,
                puts: AtomicUsize::new(0),
                snapshot_gets: AtomicUsize::new(0),
                release: parking_lot::Mutex::new((false, None)),
            }
        }

        fn pause_first_snapshot_get(mut self) -> Self {
            self.pause_on_snapshot_get = true;
            self
        }

        async fn pause(&self) {
            std::future::poll_fn(|cx| {
                let mut release = self.release.lock();
                if release.0 {
                    std::task::Poll::Ready(())
                } else {
                    release.1 = Some(cx.waker().clone());
                    std::task::Poll::Pending
                }
            })
            .await;
        }

        fn release(&self) {
            let waker = {
                let mut release = self.release.lock();
                release.0 = true;
                release.1.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for PausedPutObjectStore {
        async fn put(&self, object: StoredObject) -> std::result::Result<(), ObjectStoreError> {
            let put_number = self.puts.fetch_add(1, Ordering::SeqCst) + 1;
            if put_number == self.pause_on_put && !self.pause_after_write {
                self.pause().await;
            }
            self.inner.put(object).await?;
            if put_number == self.pause_on_put && self.pause_after_write {
                self.pause().await;
            }
            Ok(())
        }

        async fn get(&self, id: &ObjectId) -> std::result::Result<StoredObject, ObjectStoreError> {
            let stored = self.inner.get(id).await?;
            if self.pause_on_snapshot_get
                && stored.header.schema == FcpStoreConnectorStateStore::snapshot_schema_id()
                && self.snapshot_gets.fetch_add(1, Ordering::SeqCst) == 0
            {
                self.pause().await;
            }
            Ok(stored)
        }

        async fn exists(&self, id: &ObjectId) -> bool {
            self.inner.exists(id).await
        }

        async fn delete(&self, id: &ObjectId) -> std::result::Result<(), ObjectStoreError> {
            self.inner.delete(id).await
        }

        async fn get_header(
            &self,
            id: &ObjectId,
        ) -> std::result::Result<ObjectHeader, ObjectStoreError> {
            self.inner.get_header(id).await
        }

        async fn get_storage_meta(
            &self,
            id: &ObjectId,
        ) -> std::result::Result<StorageMeta, ObjectStoreError> {
            self.inner.get_storage_meta(id).await
        }

        async fn set_retention(
            &self,
            id: &ObjectId,
            retention: RetentionClass,
        ) -> std::result::Result<(), ObjectStoreError> {
            self.inner.set_retention(id, retention).await
        }

        async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
            self.inner.list_zone(zone_id).await
        }

        async fn storage_used(&self) -> u64 {
            self.inner.storage_used().await
        }

        async fn storage_quota(&self) -> u64 {
            self.inner.storage_quota().await
        }
    }

    fn capability_constraints_cbor(resource_allow: Vec<String>) -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow,
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).unwrap();
        cbor
    }

    fn write_authorization_with_key() -> (ConnectorStateWriteAuthorization, Ed25519SigningKey) {
        let connector_id = connector_id();
        let zone_id = zone_id();
        let instance_id = InstanceId::new();
        let signing_key = Ed25519SigningKey::generate();
        let now = fcp_prelude::Utc::now();
        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id(CONNECTOR_STATE_WRITE_CAPABILITY_ID)
                .zone_id(zone_id.as_str())
                .target_instance(instance_id.as_str())
                .principal("principal:test")
                .operations(&[CONNECTOR_STATE_APPEND_OPERATION_ID])
                .issuer("node:test")
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&capability_constraints_cbor(vec![
                    connector_state_resource_uri(&connector_id),
                ]))
                .unwrap()
                .sign(&signing_key)
                .unwrap(),
        );
        let verifier = CapabilityVerifier::new(
            signing_key.verifying_key().to_bytes(),
            zone_id.clone(),
            instance_id,
        );
        let authorization = ConnectorStateWriteAuthorization::verify_append_token(
            &verifier,
            token,
            &connector_id,
            &zone_id,
        )
        .unwrap();
        (authorization, signing_key)
    }

    fn write_authorization() -> ConnectorStateWriteAuthorization {
        write_authorization_with_key().0
    }

    fn header(schema: SchemaId, created_at: u64, lease: Option<ObjectId>) -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema,
            zone_id: zone_id(),
            created_at,
            provenance: Provenance::new(zone_id()),
            refs: lease.into_iter().collect(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_state_signing_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[0x5a; 32]).expect("fixed test signing key should parse")
    }

    fn state(seq: u64, prev: Option<ObjectId>, lease: ObjectId) -> ConnectorStateObject {
        let mut state = ConnectorStateObject {
            header: header(
                FcpStoreConnectorStateStore::state_object_schema_id(),
                1_700_000_000 + seq,
                Some(lease),
            ),
            connector_id: connector_id(),
            instance_id: None,
            zone_id: zone_id(),
            prev,
            seq,
            state_cbor: vec![0xa1, 0x61, b'n', seq as u8],
            updated_at: 1_700_000_000 + seq,
            lease_seq: seq + 10,
            lease_object_id: lease,
            writer_public_key: [0u8; 32],
            signature: Signature::zero(),
        };
        state
            .sign_with(&test_state_signing_key())
            .expect("test connector state should sign");
        state
    }

    fn signed_state(
        seq: u64,
        prev: Option<ObjectId>,
        lease: ObjectId,
        signing_key: &Ed25519SigningKey,
    ) -> ConnectorStateObject {
        let mut state = state(seq, prev, lease);
        state
            .sign_with(signing_key)
            .expect("test connector state should sign");
        state
    }

    fn root_with_head(head: Option<ObjectId>, created_at: u64) -> ConnectorStateRoot {
        let mut root_header = header(
            FcpStoreConnectorStateStore::root_schema_id(),
            created_at,
            None,
        );
        if let Some(head) = head {
            root_header.refs.push(head);
        }
        ConnectorStateRoot {
            header: root_header,
            connector_id: connector_id(),
            instance_id: None,
            zone_id: zone_id(),
            model: ConnectorStateModel::SingletonWriter,
            head,
            state_schema_version: 1,
        }
    }

    fn append_ok(
        state_store: &FcpStoreConnectorStateStore,
        state_obj: ConnectorStateObject,
    ) -> (ObjectId, Option<ObjectId>) {
        let outcome = run_async(state_store.append_object(state_obj)).unwrap();
        match outcome {
            ConnectorStateAppendOutcome::Committed {
                object_id,
                snapshot_object_id,
                ..
            } => (object_id, snapshot_object_id),
            ConnectorStateAppendOutcome::Conflict { .. } => {
                panic!("unexpected conflict");
            }
        }
    }

    fn store_replicated_state_and_root(
        state_store: &FcpStoreConnectorStateStore,
        state_obj: ConnectorStateObject,
    ) -> (ObjectId, ObjectId) {
        // Reproduce object replication: immutable objects can arrive without
        // passing through this adapter's local append or change bus.
        let head = run_async(state_store.store_state_object(state_obj.clone())).unwrap();
        let root = state_store.root_for_head(&state_obj, head);
        let root_id = run_async(state_store.store_root(root)).unwrap();
        (head, root_id)
    }

    fn store_root_symbols(symbol_store: &MemorySymbolStore, root_id: ObjectId) {
        let meta = ObjectSymbolMeta {
            object_id: root_id,
            zone_id: zone_id(),
            oti: ObjectTransmissionInfo {
                transfer_length: 8,
                symbol_size: 4,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 4,
                payload_hash: None,
            },
            source_symbols: 2,
            first_symbol_at: 1_700_000_000,
        };
        run_async(symbol_store.put_object_meta(meta)).unwrap();

        for (esi, source_node) in [(0, 10), (1, 20)] {
            run_async(symbol_store.put_symbol(StoredSymbol {
                meta: SymbolMeta {
                    object_id: root_id,
                    esi,
                    zone_id: zone_id(),
                    source_node: Some(source_node),
                    stored_at: 1_700_000_001 + u64::from(esi),
                },
                data: Bytes::from_static(b"root"),
            }))
            .unwrap();
        }
    }

    fn catches_unwind<F: FnOnce() + panic::UnwindSafe>(f: F) {
        let result = panic::catch_unwind(AssertUnwindSafe(f));
        assert!(result.is_err());
    }

    #[test]
    fn schema_ids_are_stable() {
        assert_eq!(
            FcpStoreConnectorStateStore::root_schema_id(),
            SchemaId::new("fcp.connector_state", "state_root", Version::new(1, 0, 0))
        );
        assert_eq!(
            FcpStoreConnectorStateStore::state_object_schema_id(),
            SchemaId::new("fcp.connector_state", "state_object", Version::new(1, 0, 0))
        );
        assert_eq!(
            FcpStoreConnectorStateStore::snapshot_schema_id(),
            SchemaId::new(
                "fcp.connector_state",
                "state_snapshot",
                Version::new(1, 0, 0)
            )
        );
    }

    #[test]
    fn cache_marker_name_is_canonical() {
        assert_eq!(CONNECTOR_STATE_CACHE_MARKER, ".fcp-cache-only");
    }

    #[test]
    fn telemetry_contract_names_match_connector_state_acceptance() {
        assert_eq!(CONNECTOR_STATE_READ_EVENT, "fcp.connector_state.read");
        assert_eq!(CONNECTOR_STATE_WRITE_EVENT, "fcp.connector_state.write");
        assert_eq!(
            CONNECTOR_STATE_SNAPSHOT_EVENT,
            "fcp.connector_state.snapshot"
        );
        assert_eq!(CONNECTOR_STATE_COMPACT_EVENT, "fcp.connector_state.compact");
        assert_eq!(
            CONNECTOR_STATE_FALL_THROUGH_EVENT,
            "fcp.connector_state.fall_through"
        );
        assert_eq!(
            CONNECTOR_STATE_WRITES_TOTAL_METRIC,
            "fcp_connector_state_writes_total"
        );
        assert_eq!(
            CONNECTOR_STATE_CACHE_HITS_TOTAL_METRIC,
            "fcp_connector_state_cache_hits_total"
        );
        assert_eq!(
            CONNECTOR_STATE_FALL_THROUGH_TOTAL_METRIC,
            "fcp_connector_state_fall_through_total"
        );
        assert_eq!(
            CONNECTOR_STATE_LATENCY_SECONDS_METRIC,
            "fcp_connector_state_latency_seconds"
        );
    }

    #[test]
    fn read_cache_metric_selection_matches_hit_miss_contract() {
        assert_eq!(
            FcpStoreConnectorStateStore::read_cache_metric_for_result("hit"),
            Some(CONNECTOR_STATE_CACHE_HITS_TOTAL_METRIC)
        );
        assert_eq!(
            FcpStoreConnectorStateStore::read_cache_metric_for_result("miss"),
            Some(CONNECTOR_STATE_FALL_THROUGH_TOTAL_METRIC)
        );
        assert_eq!(
            FcpStoreConnectorStateStore::read_cache_metric_for_result("error"),
            None
        );
    }

    #[test]
    fn read_cache_telemetry_records_hit_and_fall_through_without_panic() {
        let state_store = test_store(store());
        state_store.record_read_cache_telemetry("read", "hit");
        state_store.record_read_cache_telemetry("read", "miss");
        state_store.record_read_cache_telemetry("read", "error");
    }

    #[test]
    fn read_root_empty_store_returns_none() {
        let state_store = test_store(store());
        assert!(run_async(state_store.read_root()).unwrap().is_none());
    }

    #[test]
    fn canonical_status_empty_store_reports_missing_root() {
        let state_store = test_store(store());
        let status = run_async(state_store.canonical_status(None)).unwrap();

        assert_eq!(status.connector_id, connector_id());
        assert!(!status.root_present);
        assert!(status.root_object_id.is_none());
        assert!(status.head_object_id.is_none());
        assert!(status.last_canonical_seq.is_none());
        assert!(status.mesh_replica_count.is_none());
    }

    #[test]
    fn store_root_roundtrips() {
        let state_store = test_store(store());
        let root = root_with_head(None, 11);
        let root_id = run_async(state_store.store_root(root)).unwrap();
        let loaded = run_async(state_store.read_root()).unwrap().unwrap();
        assert_eq!(loaded.0, root_id);
        assert_eq!(loaded.1.head, None);
    }

    #[test]
    fn storing_same_root_is_idempotent() {
        let state_store = test_store(store());
        let root = root_with_head(None, 11);
        let first = run_async(state_store.store_root(root.clone())).unwrap();
        let second = run_async(state_store.store_root(root)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn append_genesis_commits_state_and_root() {
        let object_store = store();
        let state_store = test_store(object_store);
        let outcome = run_async(state_store.append_object(state(0, None, lease_id(1)))).unwrap();
        match outcome {
            ConnectorStateAppendOutcome::Committed { seq, .. } => assert_eq!(seq, 0),
            ConnectorStateAppendOutcome::Conflict { .. } => catches_unwind(|| {}),
        }
        let root = run_async(state_store.read_root()).unwrap().unwrap().1;
        assert!(root.head.is_some());
    }

    #[test]
    fn read_chain_returns_genesis() {
        let state_store = test_store(store());
        let (head, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let chain = run_async(state_store.read_chain(None, 10)).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].0, head);
        assert_eq!(chain[0].1.seq, 0);
    }

    #[test]
    fn read_chain_follows_committed_root_and_hides_unrooted_state() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let orphan = state(7, None, lease_id(7));
        let stored = state_store
            .stored_object(&orphan.header, &orphan, RetentionClass::Pinned)
            .unwrap();
        run_async(object_store.put(stored)).unwrap();

        assert!(run_async(state_store.read_root()).unwrap().is_none());
        assert!(
            run_async(state_store.read_chain(None, 10))
                .unwrap()
                .is_empty()
        );

        let (head, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let chain = run_async(state_store.read_chain(None, 10)).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].0, head);
        assert_eq!(chain[0].1.seq, 0);
        assert_ne!(chain[0].1.lease_object_id, lease_id(7));
    }

    #[test]
    fn read_root_rejects_stored_state_with_invalid_signature() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let mut bad_state = state(0, None, lease_id(1));
        bad_state.signature = Signature::zero();
        let stored = state_store
            .stored_object(&bad_state.header, &bad_state, RetentionClass::Pinned)
            .unwrap();
        let bad_head = stored.object_id;
        run_async(object_store.put(stored)).unwrap();
        run_async(state_store.store_root(root_with_head(Some(bad_head), 1_700_000_100))).unwrap();

        let err = run_async(state_store.read_root()).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::InvalidStateSignature(_)
        ));
    }

    #[test]
    fn pinned_read_accepts_trusted_writer_chain() {
        let object_store = store();
        let state_store = test_store(object_store)
            .with_trusted_writer_keys([test_state_signing_key().verifying_key().to_bytes()]);

        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));

        let root = run_async(state_store.read_root()).unwrap().unwrap().1;
        assert_eq!(root.head, Some(head1));
        let chain = run_async(state_store.read_chain(None, 10)).unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn pinned_read_rejects_state_from_untrusted_writer() {
        let object_store = store();
        let unpinned = test_store(object_store.clone());
        let (legit_head, _) = append_ok(&unpinned, state(0, None, lease_id(1)));

        // A zone insider holding the shared object-id key plants an otherwise
        // valid continuation: matching sequence and parent, valid content-id
        // and self-signature, but a foreign writer key.
        let insider_key = Ed25519SigningKey::from_bytes(&[0x77; 32]).unwrap();
        let forged = signed_state(1, Some(legit_head), lease_id(9), &insider_key);
        let stored = unpinned
            .stored_object(&forged.header, &forged, RetentionClass::Pinned)
            .unwrap();
        let forged_head = stored.object_id;
        run_async(object_store.put(stored)).unwrap();
        run_async(unpinned.store_root(root_with_head(Some(forged_head), 1_700_000_500))).unwrap();

        // Lineage validation cannot establish writer authority. Without a pin
        // this foreign writer's continuation is accepted; the pin closes that gap.
        let unpinned_root = run_async(unpinned.read_root()).unwrap().unwrap().1;
        assert_eq!(unpinned_root.head, Some(forged_head));
        assert_ne!(unpinned_root.head, Some(legit_head));

        // With the pin, reads fail closed on the untrusted writer key.
        let pinned = test_store(object_store)
            .with_trusted_writer_keys([test_state_signing_key().verifying_key().to_bytes()]);
        let err = run_async(pinned.read_root()).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::UntrustedWriterKey { .. }
        ));
        let err = run_async(pinned.read_chain(None, 10)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::UntrustedWriterKey { .. }
        ));
    }

    #[test]
    fn trait_append_rejects_authorization_writer_outside_pin() {
        let object_store = store();
        let (authorization, signing_key) = write_authorization_with_key();

        // Pin includes the authorization writer: append commits.
        let matching = test_store(object_store.clone())
            .with_trusted_writer_keys([signing_key.verifying_key().to_bytes()]);
        let outcome = run_async(
            <FcpStoreConnectorStateStore as ConnectorStateStore>::append_object(
                &matching,
                &connector_id(),
                &authorization,
                signed_state(0, None, lease_id(1), &signing_key),
            ),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            ConnectorStateAppendOutcome::Committed { .. }
        ));

        // Pin excludes the authorization writer: append is refused before any
        // object is validated or stored.
        let excluding = test_store(object_store).with_trusted_writer_keys([[0xEE_u8; 32]]);
        let err = run_async(
            <FcpStoreConnectorStateStore as ConnectorStateStore>::append_object(
                &excluding,
                &connector_id(),
                &authorization,
                signed_state(1, None, lease_id(2), &signing_key),
            ),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateError::AuthorizationDenied { .. }
        ));
    }

    #[test]
    fn append_second_object_links_to_previous_head() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let root = run_async(state_store.read_root()).unwrap().unwrap().1;
        assert_eq!(root.head, Some(head1));
    }

    #[test]
    fn append_serializes_shared_store_writers_and_lease_yield() {
        run_async(async {
            let object_store = Arc::new(PausedPutObjectStore::new(3, false));
            let first_store = test_store(object_store.clone());
            // Construct an independent adapter: sharing only a clone's lock
            // would not protect real SDK callers that create fresh adapters.
            let second_store = test_store(object_store.clone());
            let (authorization, signing_key) = write_authorization_with_key();
            let connector = connector_id();
            let base = ConnectorStateStore::append_object(
                &first_store,
                &connector,
                &authorization,
                signed_state(0, None, lease_id(1), &signing_key),
            )
            .await
            .unwrap();
            let ConnectorStateAppendOutcome::Committed {
                object_id: head0, ..
            } = base
            else {
                panic!("initial append must commit");
            };
            assert_eq!(
                second_store.read_root().await.unwrap().unwrap().1.head,
                Some(head0)
            );

            let mut first = Box::pin(ConnectorStateStore::append_object(
                &first_store,
                &connector,
                &authorization,
                signed_state(1, Some(head0), lease_id(2), &signing_key),
            ));
            assert!(futures_util::poll!(first.as_mut()).is_pending());
            assert_eq!(object_store.puts.load(Ordering::SeqCst), 3);

            let mut second = Box::pin(ConnectorStateStore::append_object(
                &second_store,
                &connector,
                &authorization,
                signed_state(1, Some(head0), lease_id(3), &signing_key),
            ));
            assert!(futures_util::poll!(second.as_mut()).is_pending());
            let mut flush = Box::pin(second_store.flush_before_lease_yield());
            assert!(futures_util::poll!(flush.as_mut()).is_pending());
            let mut compact = Box::pin(second_store.compact(u64::MAX));
            assert!(futures_util::poll!(compact.as_mut()).is_pending());
            assert_eq!(object_store.puts.load(Ordering::SeqCst), 3);

            object_store.release();
            let ConnectorStateAppendOutcome::Committed {
                object_id: head1, ..
            } = first.await.unwrap()
            else {
                panic!("first writer must commit");
            };
            assert_eq!(
                second.await.unwrap(),
                ConnectorStateAppendOutcome::Conflict {
                    canonical_head: Some(head1),
                    canonical_seq: Some(1),
                }
            );
            let flush = flush.await.unwrap();
            assert_eq!(flush.head_object_id, Some(head1));
            assert_eq!(flush.last_canonical_seq, Some(1));
            assert_eq!(compact.await.unwrap(), 1);
            assert_eq!(object_store.puts.load(Ordering::SeqCst), 4);
            assert_eq!(object_store.list_zone(&zone_id()).await.len(), 4);
            assert_eq!(
                object_store
                    .get_storage_meta(&head1)
                    .await
                    .unwrap()
                    .retention,
                RetentionClass::Pinned
            );
        });
    }

    #[test]
    fn cancelled_append_after_root_persistence_invalidates_shared_caches() {
        run_async(async {
            let object_store = Arc::new(PausedPutObjectStore::new(4, true));
            let first_store = test_store(object_store.clone());
            let second_store = test_store(object_store.clone());
            let initial = first_store
                .append_object(state(0, None, lease_id(1)))
                .await
                .unwrap();
            let ConnectorStateAppendOutcome::Committed {
                object_id: head0, ..
            } = initial
            else {
                panic!("initial append must commit");
            };
            // Both adapters cache the old root before the response to the
            // following durable root write is deliberately lost.
            assert_eq!(
                first_store.read_root().await.unwrap().unwrap().1.head,
                Some(head0)
            );
            assert_eq!(
                second_store.read_root().await.unwrap().unwrap().1.head,
                Some(head0)
            );
            let next = state(1, Some(head0), lease_id(2));
            let head1 = first_store
                .stored_object(&next.header, &next, RetentionClass::Pinned)
                .unwrap()
                .object_id;
            let mut interrupted = Box::pin(first_store.append_object(next));
            assert!(futures_util::poll!(interrupted.as_mut()).is_pending());
            assert_eq!(object_store.puts.load(Ordering::SeqCst), 4);
            drop(interrupted);

            let conflict = second_store
                .append_object(state(1, Some(head0), lease_id(3)))
                .await
                .unwrap();
            assert_eq!(
                conflict,
                ConnectorStateAppendOutcome::Conflict {
                    canonical_head: Some(head1),
                    canonical_seq: Some(1),
                }
            );
            assert_eq!(object_store.puts.load(Ordering::SeqCst), 4);
            assert_eq!(
                first_store.read_root().await.unwrap().unwrap().1.head,
                Some(head1)
            );
            assert!(matches!(
                second_store
                    .append_object(state(2, Some(head1), lease_id(3)))
                    .await
                    .unwrap(),
                ConnectorStateAppendOutcome::Committed { seq: 2, .. }
            ));
            assert_eq!(second_store.read_chain(None, 10).await.unwrap().len(), 3);
        });
    }

    #[test]
    fn append_publishes_committed_root_before_optional_snapshot_finishes() {
        run_async(async {
            let object_store = Arc::new(PausedPutObjectStore::new(5, false));
            let first_store = test_store(object_store.clone()).with_snapshot_every_entries(2);
            let second_store = test_store(object_store.clone());
            let initial = first_store
                .append_object(state(0, None, lease_id(1)))
                .await
                .unwrap();
            let ConnectorStateAppendOutcome::Committed {
                object_id: head0, ..
            } = initial
            else {
                panic!("initial append must commit");
            };
            assert_eq!(
                second_store.read_root().await.unwrap().unwrap().1.head,
                Some(head0)
            );
            let mut changes =
                ConnectorStateStore::subscribe_changes(&second_store, &connector_id())
                    .await
                    .unwrap();
            let mut next = Box::pin(first_store.append_object(state(1, Some(head0), lease_id(2))));
            assert!(futures_util::poll!(next.as_mut()).is_pending());
            assert_eq!(object_store.puts.load(Ordering::SeqCst), 5);

            for expected in [
                ConnectorStateChangeKind::ObjectAppended,
                ConnectorStateChangeKind::RootUpdated,
            ] {
                let std::task::Poll::Ready(Some(Ok(change))) = futures_util::poll!(changes.next())
                else {
                    panic!("committed root changes must be available while snapshot is pending");
                };
                assert_eq!(change.kind, expected);
                assert_eq!(change.seq, Some(1));
            }
            assert_eq!(
                second_store
                    .canonical_status(None)
                    .await
                    .unwrap()
                    .last_canonical_seq,
                Some(1)
            );
            drop(next);
            assert_eq!(
                second_store
                    .canonical_status(None)
                    .await
                    .unwrap()
                    .last_canonical_seq,
                Some(1)
            );
        });
    }

    #[fcp_async_core::runtime::test]
    async fn singleton_fencing_survives_wal_and_checkpoint_reopen() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let (authorization, signing_key) = write_authorization_with_key();
        let connector = connector_id();
        for checkpoint_after_ops in [0, 2] {
            let mut config = DurableObjectStoreConfig::new(
                temp_dir.path().join(checkpoint_after_ops.to_string()),
            );
            config.checkpoint_after_ops = checkpoint_after_ops;
            config.mac_key = Some([0x72; 32]);
            let head1 = {
                let state_store =
                    test_store(Arc::new(DurableObjectStore::open(config.clone()).unwrap()));
                let initial = ConnectorStateStore::append_object(
                    &state_store,
                    &connector,
                    &authorization,
                    signed_state(0, None, lease_id(1), &signing_key),
                )
                .await
                .unwrap();
                let ConnectorStateAppendOutcome::Committed {
                    object_id: head0, ..
                } = initial
                else {
                    panic!("initial append must commit");
                };
                let mut handoff = signed_state(1, Some(head0), lease_id(2), &signing_key);
                handoff.lease_seq = 50;
                handoff.sign_with(&signing_key).unwrap();
                let committed = ConnectorStateStore::append_object(
                    &state_store,
                    &connector,
                    &authorization,
                    handoff,
                )
                .await
                .unwrap();
                let ConnectorStateAppendOutcome::Committed { object_id, .. } = committed else {
                    panic!("new lease holder must commit");
                };
                object_id
            };

            let object_store = Arc::new(DurableObjectStore::open(config).unwrap());
            let state_store = test_store(object_store.clone());
            let mut stale = signed_state(2, Some(head1), lease_id(1), &signing_key);
            stale.lease_seq = 10;
            stale.sign_with(&signing_key).unwrap();
            let error =
                ConnectorStateStore::append_object(&state_store, &connector, &authorization, stale)
                    .await
                    .unwrap_err();
            assert_eq!(
                error,
                ConnectorStateError::StaleLease {
                    connector_id: connector.clone(),
                    held_seq: 10,
                    current_seq: 50,
                }
            );
            let serialized = serde_json::to_value(&error).unwrap();
            assert_eq!(serialized["error"], "stale_lease");
            assert_eq!(
                serde_json::from_value::<ConnectorStateError>(serialized).unwrap(),
                error
            );
            assert_eq!(object_store.list_zone(&zone_id()).await.len(), 4);
            assert_eq!(state_store.current_head().await.unwrap().unwrap().0, head1);

            // Renewing a lease can retain its fencing token while changing the
            // lease object's content id; that is not a stale writer.
            let mut renewed = signed_state(2, Some(head1), lease_id(3), &signing_key);
            renewed.lease_seq = 50;
            renewed.sign_with(&signing_key).unwrap();
            assert!(matches!(
                ConnectorStateStore::append_object(
                    &state_store,
                    &connector,
                    &authorization,
                    renewed
                )
                .await
                .unwrap(),
                ConnectorStateAppendOutcome::Committed { seq: 2, .. }
            ));
        }
    }

    #[test]
    fn singleton_fencing_cannot_be_disabled_by_changing_store_model() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let (head, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let crdt = ConnectorStateModel::Crdt {
            crdt_type: fcp_prelude::CrdtType::LwwMap,
        };
        let changed_model = test_store(object_store).with_state_model(crdt.clone());
        let mut stale = state(1, Some(head), lease_id(2));
        stale.lease_seq = 1;
        stale.sign_with(&test_state_signing_key()).unwrap();
        assert!(matches!(
            run_async(changed_model.append_object(stale)),
            Err(ConnectorStateStoreError::IdentityMismatch { field: "model", .. })
        ));

        let crdt_store = test_store(store()).with_state_model(crdt);
        let (crdt_head, _) = append_ok(&crdt_store, state(0, None, lease_id(1)));
        let mut independent_writer = state(1, Some(crdt_head), lease_id(2));
        independent_writer.lease_seq = 1;
        independent_writer
            .sign_with(&test_state_signing_key())
            .unwrap();
        assert!(matches!(
            run_async(crdt_store.append_object(independent_writer)).unwrap(),
            ConnectorStateAppendOutcome::Committed { seq: 1, .. }
        ));
    }

    #[test]
    fn append_retries_transient_state_object_write_with_policy() {
        let inner: Arc<dyn ObjectStore> = store();
        let object_store: Arc<dyn ObjectStore> = Arc::new(FailNthPutObjectStore::new(inner, 1));
        let state_store = test_store(object_store).with_state_object_write_retry_policy(
            BackoffPolicy::new(1, std::time::Duration::ZERO, std::time::Duration::ZERO, 1.0),
        );

        let (head, _) = append_ok(&state_store, state(0, None, lease_id(1)));

        let root = run_async(state_store.read_root()).unwrap().unwrap().1;
        assert_eq!(root.head, Some(head));
        let chain = run_async(state_store.read_chain(None, 10)).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].1.seq, 0);
        assert_eq!(chain[0].1.lease_object_id, lease_id(1));
    }

    #[test]
    fn append_commits_when_post_root_snapshot_write_fails() {
        let inner: Arc<dyn ObjectStore> = store();
        let object_store: Arc<dyn ObjectStore> = Arc::new(FailNthPutObjectStore::new(inner, 3));
        let state_store = test_store(object_store).with_snapshot_every_entries(1);

        let outcome = run_async(state_store.append_object(state(0, None, lease_id(1)))).unwrap();
        let ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq,
            snapshot_object_id,
        } = outcome
        else {
            panic!("post-root snapshot failure must not report a conflict");
        };

        assert_eq!(seq, 0);
        assert!(snapshot_object_id.is_none());
        let root = run_async(state_store.read_root()).unwrap().unwrap().1;
        assert_eq!(root.head, Some(object_id));
        assert!(root.header.refs.contains(&object_id));

        let stored_root = run_async(state_store.object_store.get(&root_object_id)).unwrap();
        assert_eq!(
            stored_root.header.schema,
            FcpStoreConnectorStateStore::root_schema_id()
        );

        let chain = run_async(state_store.read_chain(None, 10)).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].0, object_id);
        assert_eq!(chain[0].1.seq, 0);
        assert!(run_async(state_store.latest_snapshot()).unwrap().is_none());
    }

    #[test]
    fn read_root_prefers_highest_head_sequence_over_newer_stale_root() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        run_async(state_store.store_root(root_with_head(Some(head0), 9_999_999_999))).unwrap();

        let root = run_async(state_store.read_root()).unwrap().unwrap().1;
        assert_eq!(root.head, Some(head1));

        let chain = run_async(state_store.read_chain(None, 10)).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].1.seq, 0);
        assert_eq!(chain[1].1.seq, 1);
    }

    #[test]
    fn singleton_fork_blocks_public_reads_and_cached_append() {
        let object_store = store();
        let (authorization, signing_key) = write_authorization_with_key();
        let state_store = test_store(object_store.clone())
            .with_trusted_writer_keys([signing_key.verifying_key().to_bytes()])
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let connector = connector_id();
        let initial = run_async(ConnectorStateStore::append_object(
            &state_store,
            &connector,
            &authorization,
            signed_state(0, None, lease_id(1), &signing_key),
        ))
        .unwrap();
        let ConnectorStateAppendOutcome::Committed {
            object_id: head0, ..
        } = initial
        else {
            panic!("genesis must commit");
        };
        let committed = run_async(ConnectorStateStore::append_object(
            &state_store,
            &connector,
            &authorization,
            signed_state(1, Some(head0), lease_id(2), &signing_key),
        ))
        .unwrap();
        let ConnectorStateAppendOutcome::Committed {
            object_id: head1,
            root_object_id: root1,
            ..
        } = committed
        else {
            panic!("first branch must commit");
        };
        assert_eq!(
            run_async(state_store.read_root()).unwrap().unwrap().0,
            root1
        );

        let (other_head, other_root) = store_replicated_state_and_root(
            &state_store,
            signed_state(1, Some(head0), lease_id(3), &signing_key),
        );
        let object_count = run_async(object_store.list_zone(&zone_id())).len();

        // No announcement was delivered. The mutation boundary must bypass the
        // formerly valid cached root and discover the replicated competing root.
        let error = run_async(ConnectorStateStore::append_object(
            &state_store,
            &connector,
            &authorization,
            signed_state(2, Some(head1), lease_id(4), &signing_key),
        ))
        .unwrap_err();
        let ConnectorStateError::ForkDetected {
            root_a,
            root_b,
            head_a,
            head_b,
            ..
        } = &error
        else {
            panic!("expected a typed fork refusal, got {error:?}");
        };
        assert_eq!(
            HashSet::from([*root_a, *root_b]),
            HashSet::from([root1, other_root])
        );
        assert_eq!(
            HashSet::from([**head_a, **head_b]),
            HashSet::from([head1, other_head])
        );
        assert_eq!(
            run_async(object_store.list_zone(&zone_id())).len(),
            object_count
        );
        let json = serde_json::to_value(&error).unwrap();
        assert_eq!(json["error"], "fork_detected");
        assert_eq!(
            serde_json::from_value::<ConnectorStateError>(json).unwrap(),
            error
        );
        assert!(matches!(
            run_async(ConnectorStateStore::read_root(&state_store, &connector)),
            Err(ConnectorStateError::ForkDetected { .. })
        ));
        assert!(matches!(
            run_async(ConnectorStateStore::read_chain(
                &state_store,
                &connector,
                None,
                10
            )),
            Err(ConnectorStateError::ForkDetected { .. })
        ));
        assert!(matches!(
            run_async(state_store.canonical_status(None)),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
    }

    #[test]
    fn singleton_longer_higher_fence_branch_does_not_resolve_fork() {
        let state_store = test_store(store())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let (fork1, _) =
            store_replicated_state_and_root(&state_store, state(1, Some(head0), lease_id(3)));
        let mut longer = state(2, Some(fork1), lease_id(4));
        longer.lease_seq = 1_000;
        longer.sign_with(&test_state_signing_key()).unwrap();
        let (_, fork_root) = store_replicated_state_and_root(&state_store, longer);
        let error = run_async(state_store.observe_replicated_root(fork_root)).unwrap_err();
        assert!(matches!(
            error,
            ConnectorStateStoreError::ForkDetected { .. }
        ));
        assert!(matches!(
            run_async(state_store.flush_before_lease_yield()),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
        assert!(matches!(
            run_async(state_store.append_object(state(2, Some(head1), lease_id(5)))),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
    }

    #[test]
    fn singleton_distinct_genesis_roots_are_a_fork() {
        let object_store = store();
        let state_store = test_store(object_store.clone())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        append_ok(&state_store, state(0, None, lease_id(1)));
        store_replicated_state_and_root(&state_store, state(0, None, lease_id(2)));
        let reader = test_store(object_store);
        assert!(matches!(
            run_async(reader.read_root()),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
    }

    #[test]
    fn rejected_fork_announcement_invalidates_cached_branch() {
        let object_store = store();
        let writer = test_store(object_store.clone())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let reader = test_store(object_store);
        let (head0, _) = append_ok(&writer, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&writer, state(1, Some(head0), lease_id(2)));
        assert_eq!(
            run_async(reader.read_root()).unwrap().unwrap().1.head,
            Some(head1)
        );
        assert!(reader.cached_root().is_some());

        let (_, fork_root) =
            store_replicated_state_and_root(&writer, state(1, Some(head0), lease_id(3)));
        assert!(matches!(
            run_async(reader.observe_replicated_root(fork_root)),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
        assert!(reader.cached_root().is_none());
        assert!(matches!(
            run_async(reader.read_root()),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
        assert!(matches!(
            run_async(reader.snapshot_head()),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
        assert!(matches!(
            run_async(reader.compact(10)),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
    }

    #[test]
    fn singleton_restore_validates_sequences_and_lease_progression() {
        for sequence_gap in [true, false] {
            let object_store = store();
            let writer = test_store(object_store.clone())
                .with_snapshot_every_entries(0)
                .with_snapshot_every_secs(0);
            let (head0, _) = append_ok(&writer, state(0, None, lease_id(1)));
            let mut invalid = state(if sequence_gap { 2 } else { 1 }, Some(head0), lease_id(2));
            if !sequence_gap {
                invalid.lease_seq = 9;
                invalid.sign_with(&test_state_signing_key()).unwrap();
            }
            store_replicated_state_and_root(&writer, invalid);
            let reader = test_store(object_store);
            let error = run_async(reader.read_root()).unwrap_err();
            if sequence_gap {
                assert!(matches!(
                    error,
                    ConnectorStateStoreError::SequenceMismatch {
                        expected: 1,
                        got: 2
                    }
                ));
            } else {
                assert!(matches!(
                    error,
                    ConnectorStateStoreError::StaleLease {
                        held_seq: 9,
                        current_seq: 10
                    }
                ));
            }
            assert!(reader.cached_root().is_none());
        }
    }

    #[test]
    fn singleton_restore_rejects_nonzero_genesis() {
        let state_store = test_store(store());
        store_replicated_state_and_root(&state_store, state(3, None, lease_id(1)));
        assert!(matches!(
            run_async(state_store.read_root()),
            Err(ConnectorStateStoreError::SequenceMismatch {
                expected: 0,
                got: 3
            })
        ));
    }

    #[test]
    fn mixed_root_models_cannot_bypass_singleton_fork_validation() {
        let object_store = store();
        let singleton = test_store(object_store.clone())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        append_ok(&singleton, state(0, None, lease_id(1)));
        let crdt = test_store(object_store.clone()).with_state_model(ConnectorStateModel::Crdt {
            crdt_type: fcp_core::ConnectorCrdtType::LwwMap,
        });
        store_replicated_state_and_root(&crdt, state(0, None, lease_id(2)));
        let reader = test_store(object_store);
        assert!(matches!(
            run_async(reader.read_root()),
            Err(ConnectorStateStoreError::IdentityMismatch { field: "model", .. })
        ));
    }

    #[test]
    fn root_envelope_mismatch_invalidates_a_cached_reader() {
        let object_store = store();
        let state_store = test_store(object_store.clone())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let (head, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        run_async(state_store.read_root()).unwrap().unwrap();
        assert!(state_store.cached_root().is_some());
        let root = root_with_head(Some(head), 1_700_000_100);
        let mut envelope = root.header.clone();
        envelope.created_at += 1;
        let stored = state_store
            .stored_object(&envelope, &root, RetentionClass::Pinned)
            .unwrap();
        let root_id = stored.object_id;
        run_async(object_store.put(stored)).unwrap();

        assert!(matches!(
            run_async(state_store.observe_replicated_root(root_id)),
            Err(ConnectorStateStoreError::HeaderBodyMismatch)
        ));
        assert!(state_store.cached_root().is_none());
        assert!(matches!(
            run_async(state_store.read_root()),
            Err(ConnectorStateStoreError::HeaderBodyMismatch)
        ));
    }

    #[test]
    fn ordinary_crdt_chain_reads_reject_sequence_gaps_before_returning_a_prefix() {
        let state_store = test_store(store()).with_state_model(ConnectorStateModel::Crdt {
            crdt_type: fcp_core::ConnectorCrdtType::LwwMap,
        });
        let head0 = run_async(state_store.store_state_object(state(0, None, lease_id(1)))).unwrap();
        store_replicated_state_and_root(&state_store, state(2, Some(head0), lease_id(2)));
        // CRDT roots do not use the singleton fork validator; this exercises
        // the ordinary chain reader's own validation despite a one-item limit.
        assert!(run_async(state_store.read_root()).unwrap().is_some());
        assert!(matches!(
            run_async(state_store.read_chain(None, 1)),
            Err(ConnectorStateStoreError::SequenceMismatch {
                expected: 1,
                got: 2
            })
        ));
    }

    #[test]
    fn singleton_fork_refusal_survives_wal_and_checkpoint_reopen() {
        let temp = tempfile::TempDir::new().unwrap();
        for checkpoint_after_ops in [0, 2] {
            let mut config = DurableObjectStoreConfig::new(
                temp.path().join(format!("fork-{checkpoint_after_ops}")),
            );
            config.checkpoint_after_ops = checkpoint_after_ops;
            config.mac_key = Some([0x73; 32]);
            {
                let writer =
                    test_store(Arc::new(DurableObjectStore::open(config.clone()).unwrap()))
                        .with_snapshot_every_entries(0)
                        .with_snapshot_every_secs(0);
                let (head0, _) = append_ok(&writer, state(0, None, lease_id(1)));
                append_ok(&writer, state(1, Some(head0), lease_id(2)));
                store_replicated_state_and_root(&writer, state(1, Some(head0), lease_id(3)));
            }
            let restored = test_store(Arc::new(DurableObjectStore::open(config).unwrap()));
            assert!(matches!(
                run_async(ConnectorStateStore::read_root(&restored, &connector_id())),
                Err(ConnectorStateError::ForkDetected { .. })
            ));
            assert!(matches!(
                run_async(restored.flush_before_lease_yield()),
                Err(ConnectorStateStoreError::ForkDetected { .. })
            ));
        }
    }

    #[test]
    fn cloned_reader_revalidates_cached_root_after_trust_or_instance_changes() {
        let state_store = test_store(store())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let (head, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        assert_eq!(
            run_async(state_store.read_root()).unwrap().unwrap().1.head,
            Some(head)
        );

        let differently_pinned = state_store.clone().with_trusted_writer_keys([[0xee; 32]]);
        assert!(matches!(
            run_async(differently_pinned.read_root()),
            Err(ConnectorStateStoreError::UntrustedWriterKey { .. })
        ));
        let different_instance = state_store.clone().with_instance_id(InstanceId::new());
        assert!(run_async(different_instance.read_root()).unwrap().is_none());

        // Reconfiguring a clone does not discard the original adapter's valid
        // cache or change its trust and identity.
        assert!(state_store.cached_root().is_some());
        assert_eq!(
            run_async(state_store.read_root()).unwrap().unwrap().1.head,
            Some(head)
        );
    }

    #[test]
    fn canonical_status_reports_root_head_and_sequence() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let outcome =
            run_async(state_store.append_object(state(1, Some(head0), lease_id(2)))).unwrap();
        let (head1, root1, seq1) = match outcome {
            ConnectorStateAppendOutcome::Committed {
                object_id,
                root_object_id,
                seq,
                ..
            } => (object_id, root_object_id, seq),
            ConnectorStateAppendOutcome::Conflict { .. } => panic!("unexpected conflict"),
        };

        let status = run_async(state_store.canonical_status(None)).unwrap();

        assert!(status.root_present);
        assert_eq!(status.connector_id, connector_id());
        assert_eq!(status.zone_id, Some(zone_id()));
        assert_eq!(status.model, Some(ConnectorStateModel::SingletonWriter));
        assert_eq!(status.root_object_id, Some(root1));
        assert_eq!(status.head_object_id, Some(head1));
        assert_eq!(status.last_canonical_seq, Some(seq1));
        assert_eq!(status.state_schema_version, Some(1));
        assert_eq!(status.mesh_replica_count, None);
    }

    #[test]
    fn canonical_status_reports_proven_root_replica_count_from_symbols() {
        let state_store = test_store(store());
        let symbol_store = symbol_store();
        let outcome = run_async(state_store.append_object(state(0, None, lease_id(1)))).unwrap();
        let (head, root, seq) = match outcome {
            ConnectorStateAppendOutcome::Committed {
                object_id,
                root_object_id,
                seq,
                ..
            } => (object_id, root_object_id, seq),
            ConnectorStateAppendOutcome::Conflict { .. } => panic!("unexpected conflict"),
        };
        store_root_symbols(&symbol_store, root);

        let status = run_async(state_store.canonical_status(Some(&symbol_store))).unwrap();

        assert_eq!(status.root_object_id, Some(root));
        assert_eq!(status.head_object_id, Some(head));
        assert_eq!(status.last_canonical_seq, Some(seq));
        assert_eq!(status.mesh_replica_count, Some(2));
    }

    #[test]
    fn flush_before_lease_yield_reports_committed_root_head_and_fence() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let outcome =
            run_async(state_store.append_object(state(1, Some(head0), lease_id(2)))).unwrap();
        let (head1, root1) = match outcome {
            ConnectorStateAppendOutcome::Committed {
                object_id,
                root_object_id,
                ..
            } => (object_id, root_object_id),
            ConnectorStateAppendOutcome::Conflict { .. } => panic!("unexpected conflict"),
        };

        let flush = run_async(state_store.flush_before_lease_yield()).unwrap();

        assert_eq!(flush.connector_id, connector_id());
        assert_eq!(flush.instance_id, None);
        assert_eq!(flush.zone_id, zone_id());
        assert_eq!(flush.root_object_id, Some(root1));
        assert_eq!(flush.head_object_id, Some(head1));
        assert_eq!(flush.last_canonical_seq, Some(1));
        assert_eq!(flush.lease_seq, Some(11));
        assert_eq!(flush.lease_object_id, Some(lease_id(2)));
    }

    #[test]
    fn flush_before_lease_yield_reports_no_state_without_fabricating_root() {
        let state_store = test_store(store());

        let flush = run_async(state_store.flush_before_lease_yield()).unwrap();

        assert_eq!(flush.connector_id, connector_id());
        assert_eq!(flush.zone_id, zone_id());
        assert!(flush.root_object_id.is_none());
        assert!(flush.head_object_id.is_none());
        assert!(flush.last_canonical_seq.is_none());
        assert!(flush.lease_seq.is_none());
        assert!(flush.lease_object_id.is_none());
    }

    #[test]
    fn flush_before_lease_yield_fails_closed_on_missing_root_head() {
        let state_store = test_store(store());
        let missing_head = ObjectId::from_bytes([0xE7; 32]);
        run_async(state_store.store_root(root_with_head(Some(missing_head), 1_700_000_200)))
            .unwrap();

        let err = run_async(state_store.flush_before_lease_yield()).unwrap_err();

        assert!(matches!(err, ConnectorStateStoreError::MissingHead(id) if id == missing_head));
    }

    #[test]
    fn append_rejects_wrong_prev_as_conflict() {
        let state_store = test_store(store());
        append_ok(&state_store, state(0, None, lease_id(1)));
        let wrong_prev = ObjectId::from_bytes([99; 32]);
        let outcome =
            run_async(state_store.append_object(state(1, Some(wrong_prev), lease_id(2)))).unwrap();
        match outcome {
            ConnectorStateAppendOutcome::Conflict {
                canonical_head,
                canonical_seq,
            } => {
                assert!(canonical_head.is_some());
                assert_eq!(canonical_seq, Some(0));
            }
            ConnectorStateAppendOutcome::Committed { .. } => {
                panic!("expected conflict");
            }
        }
    }

    #[test]
    fn append_rejects_wrong_sequence() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let err =
            run_async(state_store.append_object(state(3, Some(head0), lease_id(2)))).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::SequenceMismatch {
                expected: 1,
                got: 3
            }
        ));
    }

    #[test]
    fn append_rejects_wrong_connector() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.connector_id = other_connector_id();
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::IdentityMismatch {
                field: "connector_id",
                ..
            }
        ));
    }

    #[test]
    fn append_rejects_wrong_zone() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.zone_id = other_zone_id();
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::IdentityMismatch {
                field: "state.zone_id",
                ..
            }
        ));
    }

    #[test]
    fn append_rejects_wrong_schema() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.header.schema = FcpStoreConnectorStateStore::root_schema_id();
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::UnexpectedSchema {
                kind: "connector state object",
                ..
            }
        ));
    }

    #[test]
    fn append_rejects_missing_lease_ref() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.header.refs.clear();
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::MissingLeaseReference(_)
        ));
    }

    #[test]
    fn append_rejects_empty_state_cbor() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.state_cbor.clear();
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(err, ConnectorStateStoreError::EmptyStateCbor));
    }

    #[test]
    fn append_rejects_invalid_state_cbor() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.state_cbor = vec![0xff];
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::InvalidStateCbor(SerializationError::CborDeserialize(_))
        ));
    }

    #[test]
    fn append_rejects_noncanonical_state_cbor() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.state_cbor = vec![0x18, 0x17];
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::InvalidStateCbor(SerializationError::NonCanonicalEncoding)
        ));
    }

    #[test]
    fn append_state_cbor_at_size_cap_reaches_parse_gate() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.state_cbor = vec![0xff; MAX_CONNECTOR_STATE_CBOR_BYTES];
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::InvalidStateCbor(SerializationError::CborDeserialize(_))
        ));
    }

    #[test]
    fn append_rejects_state_cbor_above_size_cap() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.state_cbor = vec![0xff; MAX_CONNECTOR_STATE_CBOR_BYTES + 1];
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::InvalidStateCbor(SerializationError::PayloadTooLarge {
                len,
                max: MAX_CONNECTOR_STATE_CBOR_BYTES,
            }) if len == MAX_CONNECTOR_STATE_CBOR_BYTES + 1
        ));
    }

    #[test]
    fn trait_append_maps_invalid_state_cbor_to_malformed_state() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.state_cbor = vec![0xff];

        let err = run_async(
            <FcpStoreConnectorStateStore as ConnectorStateStore>::append_object(
                &state_store,
                &connector_id(),
                &write_authorization(),
                incoming,
            ),
        )
        .unwrap_err();

        assert!(matches!(err, ConnectorStateError::MalformedState { .. }));
    }

    #[test]
    fn trait_append_rejects_state_writer_key_mismatch() {
        let state_store = test_store(store());
        let authorization = write_authorization();

        let err = run_async(
            <FcpStoreConnectorStateStore as ConnectorStateStore>::append_object(
                &state_store,
                &connector_id(),
                &authorization,
                state(0, None, lease_id(1)),
            ),
        )
        .unwrap_err();

        assert!(matches!(err, ConnectorStateError::MalformedState { .. }));
        assert!(run_async(state_store.read_root()).unwrap().is_none());
    }

    #[test]
    fn trait_append_rejects_invalid_state_signature() {
        let state_store = test_store(store());
        let (authorization, signing_key) = write_authorization_with_key();
        let mut incoming = signed_state(0, None, lease_id(1), &signing_key);
        incoming.signature = Signature::zero();

        let err = run_async(
            <FcpStoreConnectorStateStore as ConnectorStateStore>::append_object(
                &state_store,
                &connector_id(),
                &authorization,
                incoming,
            ),
        )
        .unwrap_err();

        assert!(matches!(err, ConnectorStateError::MalformedState { .. }));
        assert!(run_async(state_store.read_root()).unwrap().is_none());
    }

    #[test]
    fn trait_append_maps_quota_failure_to_storage_unavailable() {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig {
            max_bytes: 1,
        }));
        let state_store = test_store(object_store);
        let (authorization, signing_key) = write_authorization_with_key();

        let err = run_async(
            <FcpStoreConnectorStateStore as ConnectorStateStore>::append_object(
                &state_store,
                &connector_id(),
                &authorization,
                signed_state(0, None, lease_id(1), &signing_key),
            ),
        )
        .unwrap_err();

        match err {
            ConnectorStateError::StorageUnavailable {
                connector_id: got,
                reason,
            } => {
                assert_eq!(got, connector_id());
                assert!(reason.contains("quota"));
            }
            other => panic!("expected StorageUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn read_chain_sorts_by_sequence() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let (head2, _) = append_ok(&state_store, state(2, Some(head1), lease_id(3)));
        let chain = run_async(state_store.read_chain(None, 10)).unwrap();
        assert_eq!(
            chain.iter().map(|(_id, s)| s.seq).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(chain[2].0, head2);
    }

    #[test]
    fn read_chain_after_seq_filters_inclusive_boundary() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        append_ok(&state_store, state(2, Some(head1), lease_id(3)));
        let chain = run_async(state_store.read_chain(Some(1), 10)).unwrap();
        assert_eq!(
            chain.iter().map(|(_id, s)| s.seq).collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn read_chain_zero_limit_returns_empty() {
        let state_store = test_store(store());
        append_ok(&state_store, state(0, None, lease_id(1)));
        assert!(
            run_async(state_store.read_chain(None, 0))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn read_chain_limit_truncates() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        append_ok(&state_store, state(2, Some(head1), lease_id(3)));
        let chain = run_async(state_store.read_chain(None, 2)).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].1.seq, 1);
    }

    #[test]
    fn instance_scoped_store_ignores_other_instance_root() {
        let object_store = store();
        let instance = InstanceId::new();
        let scoped = test_store(object_store.clone()).with_instance_id(instance.clone());
        let unscoped = test_store(object_store);
        append_ok(&unscoped, state(0, None, lease_id(1)));
        assert!(run_async(scoped.read_root()).unwrap().is_none());
        let mut scoped_state = state(0, None, lease_id(2));
        scoped_state.instance_id = Some(instance);
        scoped_state
            .sign_with(&test_state_signing_key())
            .expect("instance-scoped test state should sign");
        append_ok(&scoped, scoped_state);
        assert!(run_async(scoped.read_root()).unwrap().is_some());
    }

    #[test]
    fn retention_override_applies_to_state_object() {
        let object_store = store();
        let state_store = test_store(object_store.clone())
            .with_retention(RetentionClass::Lease { expires_at: 77 });
        let (head, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let meta = run_async(object_store.get_storage_meta(&head)).unwrap();
        assert_eq!(meta.retention, RetentionClass::Lease { expires_at: 77 });
    }

    #[test]
    fn compact_marks_older_states_ephemeral() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let count = run_async(state_store.compact(1)).unwrap();
        assert_eq!(count, 1);
        let old_meta = run_async(object_store.get_storage_meta(&head0)).unwrap();
        let new_meta = run_async(object_store.get_storage_meta(&head1)).unwrap();
        assert_eq!(old_meta.retention, RetentionClass::Ephemeral);
        assert_eq!(new_meta.retention, RetentionClass::Pinned);
    }

    #[test]
    fn compact_never_marks_head_even_when_before_seq_exceeds_head() {
        // Per the documented contract, compact only relaxes retention on
        // non-head chain entries. A `before_seq` past the head sequence must
        // still leave the head Pinned, or a retention-only GC could delete the
        // live head and strand the root (MissingHead).
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));

        let count = run_async(state_store.compact(u64::MAX)).unwrap();

        // Only the non-head predecessor is relaxed; the head is preserved.
        assert_eq!(count, 1);
        let old_meta = run_async(object_store.get_storage_meta(&head0)).unwrap();
        let head_meta = run_async(object_store.get_storage_meta(&head1)).unwrap();
        assert_eq!(old_meta.retention, RetentionClass::Ephemeral);
        assert_eq!(
            head_meta.retention,
            RetentionClass::Pinned,
            "head must remain Pinned even when before_seq exceeds its sequence"
        );
        // The chain is still fully resolvable through the preserved head.
        assert!(run_async(state_store.read_root()).unwrap().is_some());
    }

    #[test]
    fn compact_boundary_does_not_mark_equal_sequence() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let count = run_async(state_store.compact(0)).unwrap();
        assert_eq!(count, 0);
        let meta = run_async(object_store.get_storage_meta(&head0)).unwrap();
        assert_eq!(meta.retention, RetentionClass::Pinned);
    }

    #[test]
    fn subscribe_changes_reports_append_root_and_snapshot() {
        let state_store = test_store(store()).with_snapshot_every_entries(1);
        let mut changes = run_async(state_store.subscribe_changes(&connector_id())).unwrap();
        let outcome = run_async(state_store.append_object(state(0, None, lease_id(1)))).unwrap();
        let ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq,
            snapshot_object_id,
        } = outcome
        else {
            panic!("unexpected conflict");
        };
        let snapshot_object_id = snapshot_object_id.expect("snapshot emitted");
        assert_eq!(seq, 0);

        let appended = run_async(changes.next()).unwrap().unwrap();
        assert_eq!(appended.kind, ConnectorStateChangeKind::ObjectAppended);
        assert_eq!(appended.connector_id, connector_id());
        assert_eq!(appended.zone_id, zone_id());
        assert_eq!(appended.object_id, Some(object_id));
        assert_eq!(appended.seq, Some(0));
        assert_ne!(appended.observed_at, 0);

        let root = run_async(changes.next()).unwrap().unwrap();
        assert_eq!(root.kind, ConnectorStateChangeKind::RootUpdated);
        assert_eq!(root.object_id, Some(root_object_id));
        assert_eq!(root.seq, Some(0));

        let snapshot = run_async(changes.next()).unwrap().unwrap();
        assert_eq!(snapshot.kind, ConnectorStateChangeKind::SnapshotEmitted);
        assert_eq!(snapshot.object_id, Some(snapshot_object_id));
        assert_eq!(snapshot.seq, Some(0));
    }

    #[test]
    fn subscribe_changes_reaches_independent_handles_for_same_store() {
        let object_store = store();
        let writer = test_store(object_store.clone())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let reader = test_store(object_store)
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let mut changes = run_async(reader.subscribe_changes(&connector_id())).unwrap();

        let outcome = run_async(writer.append_object(state(0, None, lease_id(1)))).unwrap();
        let ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq,
            snapshot_object_id,
        } = outcome
        else {
            panic!("unexpected conflict");
        };
        assert_eq!(seq, 0);
        assert_eq!(snapshot_object_id, None);

        let appended = run_async(changes.next()).unwrap().unwrap();
        assert_eq!(appended.kind, ConnectorStateChangeKind::ObjectAppended);
        assert_eq!(appended.object_id, Some(object_id));
        assert_eq!(appended.seq, Some(0));

        let root = run_async(changes.next()).unwrap().unwrap();
        assert_eq!(root.kind, ConnectorStateChangeKind::RootUpdated);
        assert_eq!(root.object_id, Some(root_object_id));
        assert_eq!(root.seq, Some(0));

        let reader_root = run_async(reader.read_root()).unwrap().expect("root");
        assert_eq!(reader_root.1.head, Some(object_id));
    }

    #[test]
    fn observed_replicated_root_invalidates_independent_change_bus() {
        let inner: Arc<dyn ObjectStore> = store();
        let writer_object_store: Arc<dyn ObjectStore> =
            Arc::new(FailNthPutObjectStore::new(Arc::clone(&inner), usize::MAX));
        let reader_object_store: Arc<dyn ObjectStore> =
            Arc::new(FailNthPutObjectStore::new(inner, usize::MAX));
        let writer = test_store(writer_object_store)
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let reader = test_store(reader_object_store)
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let mut changes = run_async(reader.subscribe_changes(&connector_id())).unwrap();

        let outcome = run_async(writer.append_object(state(0, None, lease_id(1)))).unwrap();
        let ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq,
            snapshot_object_id,
        } = outcome
        else {
            panic!("unexpected conflict");
        };
        assert_eq!(seq, 0);
        assert_eq!(snapshot_object_id, None);

        let observed = run_async(reader.observe_replicated_root(root_object_id)).unwrap();
        assert_eq!(observed.kind, ConnectorStateChangeKind::RootUpdated);
        assert_eq!(observed.object_id, Some(root_object_id));
        assert_eq!(observed.seq, Some(0));

        let delivered = run_async(changes.next()).unwrap().unwrap();
        assert_eq!(delivered, observed);

        let reader_root = run_async(reader.read_root()).unwrap().expect("root");
        assert_eq!(reader_root.1.head, Some(object_id));
    }

    #[test]
    fn subscribe_changes_reports_manual_snapshot() {
        let state_store = test_store(store()).with_snapshot_every_entries(0);
        append_ok(&state_store, state(0, None, lease_id(1)));
        let mut changes = run_async(state_store.subscribe_changes(&connector_id())).unwrap();
        let snapshot_id = run_async(state_store.snapshot_head()).unwrap().unwrap();

        let snapshot = run_async(changes.next()).unwrap().unwrap();
        assert_eq!(snapshot.kind, ConnectorStateChangeKind::SnapshotEmitted);
        assert_eq!(snapshot.object_id, Some(snapshot_id));
        assert_eq!(snapshot.seq, Some(0));
    }

    #[test]
    fn subscribe_changes_reports_compaction() {
        let object_store = store();
        let state_store = test_store(object_store);
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let mut changes = run_async(state_store.subscribe_changes(&connector_id())).unwrap();

        let count = run_async(state_store.compact(1)).unwrap();
        assert_eq!(count, 1);
        let compacted = run_async(changes.next()).unwrap().unwrap();
        assert_eq!(compacted.kind, ConnectorStateChangeKind::Compacted);
        assert_eq!(compacted.object_id, None);
        assert_eq!(compacted.seq, Some(1));
    }

    #[test]
    fn subscribe_changes_rejects_wrong_connector() {
        let state_store = test_store(store());
        let result = run_async(state_store.subscribe_changes(&other_connector_id()));
        assert!(matches!(
            result,
            Err(ConnectorStateError::MalformedState { .. })
        ));
    }

    #[test]
    fn missing_snapshot_signer_preserves_committed_append() {
        let object_store = store();
        let (authorization, signing_key) = write_authorization_with_key();
        let state_store = FcpStoreConnectorStateStore::new(
            object_store.clone(),
            object_id_key(),
            connector_id(),
            zone_id(),
        )
        .with_trusted_writer_keys([signing_key.verifying_key().to_bytes()])
        .with_snapshot_every_entries(1);
        let outcome = run_async(ConnectorStateStore::append_object(
            &state_store,
            &connector_id(),
            &authorization,
            signed_state(0, None, lease_id(1), &signing_key),
        ))
        .unwrap();
        let ConnectorStateAppendOutcome::Committed {
            object_id,
            snapshot_object_id,
            ..
        } = outcome
        else {
            panic!("authorized state must commit without a snapshot signer");
        };
        assert!(snapshot_object_id.is_none());
        assert_eq!(run_async(state_store.current_head()).unwrap().unwrap().0, object_id);
        assert_eq!(run_async(object_store.list_zone(&zone_id())).len(), 2);

        let err = run_async(state_store.snapshot_head()).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::SnapshotSigningUnavailable { .. }
        ));
        let err = run_async(ConnectorStateStore::snapshot(&state_store, &connector_id()))
            .unwrap_err();
        match err {
            ConnectorStateError::SnapshotUnavailable { reason, .. } => {
                assert!(reason.contains("with_snapshot_signing_key"));
            }
            other => panic!("unexpected snapshot error: {other}"),
        }
        assert_eq!(run_async(object_store.list_zone(&zone_id())).len(), 2);
    }

    #[test]
    fn snapshot_signer_must_match_authenticated_covered_writer() {
        let object_store = store();
        let (authorization, signing_key) = write_authorization_with_key();
        let state_store = test_store(object_store.clone())
            .with_trusted_writer_keys([signing_key.verifying_key().to_bytes()])
            .with_snapshot_every_entries(1);
        let outcome = run_async(ConnectorStateStore::append_object(
            &state_store,
            &connector_id(),
            &authorization,
            signed_state(0, None, lease_id(1), &signing_key),
        ))
        .unwrap();
        assert!(matches!(
            outcome,
            ConnectorStateAppendOutcome::Committed {
                snapshot_object_id: None,
                ..
            }
        ));
        match run_async(state_store.snapshot_head()).unwrap_err() {
            ConnectorStateStoreError::SnapshotSigningUnavailable { reason } => {
                assert!(reason.contains("does not match"));
            }
            other => panic!("unexpected snapshot error: {other}"),
        }
        assert_eq!(run_async(object_store.list_zone(&zone_id())).len(), 2);
    }

    #[test]
    fn snapshots_are_signed_and_readers_need_no_private_key() {
        let object_store = store();
        let state_store = test_store(object_store.clone()).with_snapshot_every_entries(0);
        let covered = state(0, None, lease_id(1));
        let (head, _) = append_ok(&state_store, covered.clone());
        let snapshot = run_async(ConnectorStateStore::snapshot(&state_store, &connector_id()))
            .unwrap();
        assert_eq!(snapshot.covers_head, head);
        assert_eq!(snapshot.state_cbor, covered.state_cbor);
        assert_ne!(snapshot.signature, covered.signature);
        snapshot
            .verify_signature_with(&test_state_signing_key().verifying_key())
            .unwrap();

        let reader = FcpStoreConnectorStateStore::new(
            object_store,
            object_id_key(),
            connector_id(),
            zone_id(),
        )
        .with_trusted_writer_keys([test_state_signing_key().verifying_key().to_bytes()]);
        let latest = run_async(reader.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.1.covers_head, head);

        // Creation metadata has its own signature and need not equal the
        // covered state's update time.
        let mut later = snapshot;
        later.header.created_at += 60;
        later.snapshotted_at += 60;
        later.sign_with(&test_state_signing_key()).unwrap();
        let later_id = store_snapshot_for_test(&state_store, &later);
        let latest = run_async(reader.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.0, later_id);
        assert_eq!(latest.1.snapshotted_at, covered.updated_at + 60);
    }

    #[test]
    fn snapshot_reads_reject_copied_state_signatures() {
        let state_store = test_store(store()).with_snapshot_every_entries(0);
        let covered = state(0, None, lease_id(1));
        append_ok(&state_store, covered.clone());
        let mut forged =
            run_async(ConnectorStateStore::snapshot(&state_store, &connector_id())).unwrap();
        forged.signature = covered.signature;
        let forged_id = store_snapshot_for_test(&state_store, &forged);

        assert!(matches!(
            run_async(state_store.load_snapshot(&forged_id)),
            Err(ConnectorStateStoreError::InvalidSnapshotSignature(_))
        ));
        assert!(matches!(
            run_async(state_store.latest_snapshot()),
            Err(ConnectorStateStoreError::InvalidSnapshotSignature(_))
        ));

        // An explicit new snapshot reloads its own authenticated object even
        // when a legacy copied-signature snapshot makes latest-scan fail closed.
        let repaired =
            run_async(ConnectorStateStore::snapshot(&state_store, &connector_id())).unwrap();
        repaired
            .verify_signature_with(&test_state_signing_key().verifying_key())
            .unwrap();
    }

    #[test]
    fn snapshot_reads_reject_signed_projection_mismatches() {
        for field in ["covers_seq", "state_cbor"] {
            let state_store = test_store(store()).with_snapshot_every_entries(0);
            append_ok(&state_store, state(0, None, lease_id(1)));
            let mut forged =
                run_async(ConnectorStateStore::snapshot(&state_store, &connector_id())).unwrap();
            match field {
                "covers_seq" => forged.covers_seq += 1,
                "state_cbor" => forged.state_cbor = vec![0x00],
                _ => unreachable!(),
            }
            forged.sign_with(&test_state_signing_key()).unwrap();
            let forged_id = store_snapshot_for_test(&state_store, &forged);
            for err in [
                run_async(state_store.load_snapshot(&forged_id)).unwrap_err(),
                run_async(state_store.latest_snapshot()).unwrap_err(),
            ] {
                assert!(
                    matches!(
                        err,
                        ConnectorStateStoreError::SnapshotStateMismatch {
                            field: rejected_field,
                            ..
                        } if rejected_field == field
                    ),
                    "signed {field} mismatch must fail covered-state validation"
                );
            }
        }
    }

    #[test]
    fn snapshot_reads_authenticate_creation_metadata() {
        for field in ["header.created_at", "snapshotted_at"] {
            let state_store = test_store(store()).with_snapshot_every_entries(0);
            append_ok(&state_store, state(0, None, lease_id(1)));
            let mut forged =
                run_async(ConnectorStateStore::snapshot(&state_store, &connector_id())).unwrap();
            match field {
                "header.created_at" => forged.header.created_at += 1,
                "snapshotted_at" => forged.snapshotted_at += 1,
                _ => unreachable!(),
            }
            store_snapshot_for_test(&state_store, &forged);
            assert!(matches!(
                run_async(state_store.latest_snapshot()),
                Err(ConnectorStateStoreError::InvalidSnapshotSignature(_))
            ));
        }
    }

    #[test]
    fn snapshot_reads_check_envelope_and_requested_id() {
        let object_store = store();
        let state_store = test_store(object_store.clone()).with_snapshot_every_entries(0);
        append_ok(&state_store, state(0, None, lease_id(1)));
        let snapshot =
            run_async(ConnectorStateStore::snapshot(&state_store, &connector_id())).unwrap();
        let mut stored = state_store
            .stored_object(&snapshot.header, &snapshot, RetentionClass::Pinned)
            .unwrap();
        let wrong_id = ObjectId::from_bytes([0xee; 32]);
        assert!(matches!(
            run_async(state_store.validate_stored_snapshot(wrong_id, &stored, &snapshot)),
            Err(ConnectorStateStoreError::ContentIdMismatch { claimed, .. })
                if claimed == wrong_id
        ));

        stored.header.created_at += 1;
        stored.object_id =
            StoredObject::derive_id(&stored.header, &stored.body, &object_id_key()).unwrap();
        let mismatched_id = stored.object_id;
        run_async(object_store.put(stored)).unwrap();
        assert!(matches!(
            run_async(state_store.load_snapshot(&mismatched_id)),
            Err(ConnectorStateStoreError::HeaderBodyMismatch)
        ));
        assert!(matches!(
            run_async(state_store.latest_snapshot()),
            Err(ConnectorStateStoreError::HeaderBodyMismatch)
        ));
    }

    #[test]
    fn snapshot_signer_does_not_bypass_covered_writer_pin() {
        let object_store = store();
        let state_store = test_store(object_store.clone()).with_snapshot_every_entries(0);
        append_ok(&state_store, state(0, None, lease_id(1)));
        run_async(state_store.snapshot_head()).unwrap().unwrap();

        let untrusted_reader = test_store(object_store)
            .with_trusted_writer_keys([Ed25519SigningKey::generate().verifying_key().to_bytes()]);
        assert!(matches!(
            run_async(untrusted_reader.latest_snapshot()),
            Err(ConnectorStateStoreError::UntrustedWriterKey { .. })
        ));
        assert!(matches!(
            run_async(untrusted_reader.snapshot_head()),
            Err(ConnectorStateStoreError::UntrustedWriterKey { .. })
        ));
    }

    #[test]
    fn compaction_preserves_retained_snapshot_authentication_state() {
        let object_store = store();
        let state_store = test_store(object_store.clone())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let snapshot_id = run_async(state_store.snapshot_head()).unwrap().unwrap();
        let (head2, _) = append_ok(&state_store, state(2, Some(head1), lease_id(3)));

        assert_eq!(run_async(state_store.compact(3)).unwrap(), 1);
        assert_eq!(
            run_async(object_store.get_storage_meta(&head0)).unwrap().retention,
            RetentionClass::Ephemeral
        );
        for protected in [head1, head2] {
            assert_eq!(
                run_async(object_store.get_storage_meta(&protected)).unwrap().retention,
                RetentionClass::Pinned
            );
        }

        let gc = crate::GarbageCollector::new(crate::GcConfig::default());
        let collected = run_async(gc.collect(
            &zone_id(),
            &crate::GcRoots::new(),
            object_store.as_ref(),
            1_800_000_000,
        ))
        .unwrap();
        assert_eq!(collected.evicted, 1);
        assert!(!run_async(object_store.exists(&head0)));
        let snapshot = run_async(state_store.load_snapshot(&snapshot_id)).unwrap();
        assert_eq!(snapshot.covers_head, head1);
        assert_eq!(
            run_async(state_store.latest_snapshot()).unwrap().unwrap().0,
            snapshot_id
        );
    }

    struct SnapshotReplayFixture {
        object_store: Arc<MemoryObjectStore>,
        state_store: FcpStoreConnectorStateStore,
        heads: Vec<ObjectId>,
        roots: Vec<ObjectId>,
        snapshot_id: ObjectId,
    }

    impl SnapshotReplayFixture {
        fn new() -> Self {
            let object_store = store();
            let state_store = test_store(object_store.clone())
                .with_trusted_writer_keys([test_state_signing_key().verifying_key().to_bytes()])
                .with_snapshot_every_entries(0)
                .with_snapshot_every_secs(0);
            let mut heads = Vec::new();
            let mut roots = Vec::new();
            let mut snapshot_id = None;
            for seq in 0_u64..=4 {
                let previous = heads.last().copied();
                let (head, _) = append_ok(
                    &state_store,
                    state(seq, previous, lease_id(u8::try_from(seq + 1).unwrap())),
                );
                heads.push(head);
                roots.push(run_async(state_store.read_root()).unwrap().unwrap().0);
                if seq == 2 {
                    snapshot_id = run_async(state_store.snapshot_head()).unwrap();
                }
            }
            Self {
                object_store,
                state_store,
                heads,
                roots,
                snapshot_id: snapshot_id.unwrap(),
            }
        }

        fn reader(&self) -> FcpStoreConnectorStateStore {
            FcpStoreConnectorStateStore::new(
                self.object_store.clone(),
                object_id_key(),
                connector_id(),
                zone_id(),
            )
            .with_trusted_writer_keys([test_state_signing_key().verifying_key().to_bytes()])
        }

        fn store_root_for(&self, head: ObjectId) -> ObjectId {
            run_async(
                self.state_store
                    .store_root(root_with_head(Some(head), 1_700_000_100)),
            )
            .unwrap()
        }
    }

    #[test]
    fn snapshot_replay_recovers_after_gc_without_promoting_an_anchor_to_latest() {
        let fixture = SnapshotReplayFixture::new();
        assert_eq!(run_async(fixture.state_store.compact(3)).unwrap(), 2);
        let collected = run_async(crate::GarbageCollector::new(crate::GcConfig::default()).collect(
            &zone_id(),
            &crate::GcRoots::new(),
            fixture.object_store.as_ref(),
            1_800_000_000,
        ))
        .unwrap();
        assert_eq!(collected.evicted, 2);
        for old_head in &fixture.heads[..2] {
            assert!(!run_async(fixture.object_store.exists(old_head)));
        }
        for retained_root in &fixture.roots {
            assert!(run_async(fixture.object_store.exists(retained_root)));
        }

        // A fresh adapter has no cached root. Historical roots still point at
        // the collected prefix, and general discovery must continue to fail.
        let reader = fixture.reader();
        assert!(matches!(
            run_async(reader.read_root()),
            Err(ConnectorStateStoreError::MissingHead(_))
        ));
        let replay = run_async(reader.replay_from_snapshot(
            fixture.roots[4],
            fixture.snapshot_id,
            2,
        ))
        .unwrap();
        assert_eq!(replay.root_object_id(), fixture.roots[4]);
        assert_eq!(replay.root().head, Some(fixture.heads[4]));
        assert_eq!(replay.snapshot_object_id(), fixture.snapshot_id);
        assert_eq!(replay.snapshot().covers_seq, 2);
        assert_eq!(replay.covered_head().0, fixture.heads[2]);
        assert_eq!(replay.covered_head().1.prev, Some(fixture.heads[1]));
        assert_eq!(
            replay
                .tail()
                .iter()
                .map(|(_, state)| state.seq)
                .collect::<Vec<_>>(),
            vec![3, 4],
        );
        assert_eq!(replay.head().0, fixture.heads[4]);
        assert_eq!(replay.head().1.seq, 4);
        assert!(matches!(
            run_async(reader.read_root()),
            Err(ConnectorStateStoreError::MissingHead(_))
        ));
        assert_eq!(replay.into_head().0, fixture.heads[4]);
    }

    #[test]
    fn snapshot_replay_requires_the_covered_state_and_every_retained_tail_object() {
        for removed_index in [2, 3] {
            let fixture = SnapshotReplayFixture::new();
            let missing = fixture.heads[removed_index];
            run_async(
                fixture
                    .object_store
                    .set_retention(&missing, RetentionClass::Ephemeral),
            )
            .unwrap();
            let collected = run_async(
                crate::GarbageCollector::new(crate::GcConfig::default()).collect(
                    &zone_id(),
                    &crate::GcRoots::new(),
                    fixture.object_store.as_ref(),
                    1_800_000_000,
                ),
            )
            .unwrap();
            assert_eq!(collected.evicted, 1);
            assert!(!run_async(fixture.object_store.exists(&missing)));
            assert!(matches!(
                run_async(fixture.reader().replay_from_snapshot(
                    fixture.roots[4],
                    fixture.snapshot_id,
                    2,
                )),
                Err(ConnectorStateStoreError::MissingHead(object_id)) if object_id == missing
            ));
        }
    }

    #[test]
    fn snapshot_replay_budget_is_complete_or_error_and_allows_zero_tail() {
        let fixture = SnapshotReplayFixture::new();
        let reader = fixture.reader();
        for limit in [0, 1] {
            assert!(matches!(
                run_async(reader.replay_from_snapshot(
                    fixture.roots[4],
                    fixture.snapshot_id,
                    limit,
                )),
                Err(ConnectorStateStoreError::ReplayLimitExceeded { limit: rejected })
                    if rejected == limit
            ));
        }
        let complete = run_async(reader.replay_from_snapshot(
            fixture.roots[4],
            fixture.snapshot_id,
            2,
        ))
        .unwrap();
        assert_eq!(complete.tail().len(), 2);
        let boundary = run_async(reader.replay_from_snapshot(
            fixture.roots[2],
            fixture.snapshot_id,
            0,
        ))
        .unwrap();
        assert!(boundary.tail().is_empty());
        assert_eq!(boundary.head().0, fixture.heads[2]);
        assert_eq!(boundary.into_head().1.seq, 2);
    }

    #[test]
    fn snapshot_replay_rejects_an_independently_signed_unrelated_snapshot() {
        let fixture = SnapshotReplayFixture::new();
        let alternate = state(2, Some(fixture.heads[1]), lease_id(99));
        let alternate_head = run_async(fixture.state_store.store_state_object(alternate)).unwrap();
        let unrelated = run_async(fixture.state_store.emit_snapshot(alternate_head)).unwrap();
        assert!(run_async(fixture.state_store.load_snapshot(&unrelated)).is_ok());

        let reader = fixture.reader();
        for (root_object_id, snapshot_object_id) in [
            (fixture.roots[4], unrelated),
            (fixture.roots[1], fixture.snapshot_id),
        ] {
            assert!(matches!(
                run_async(reader.replay_from_snapshot(root_object_id, snapshot_object_id, 5)),
                Err(ConnectorStateStoreError::SnapshotNotAncestor {
                    root_object_id: rejected_root,
                    snapshot_object_id: rejected_snapshot,
                }) if rejected_root == root_object_id && rejected_snapshot == snapshot_object_id
            ));
        }
    }

    #[test]
    fn snapshot_replay_rejects_tampered_snapshot_boundary_and_tail_signatures() {
        let fixture = SnapshotReplayFixture::new();
        let reader = fixture.reader();
        let snapshot =
            run_async(fixture.state_store.load_snapshot(&fixture.snapshot_id)).unwrap();

        let mut bad_snapshot = snapshot.clone();
        bad_snapshot.signature = Signature::zero();
        let bad_snapshot_id = store_snapshot_for_test(&fixture.state_store, &bad_snapshot);
        assert!(matches!(
            run_async(reader.replay_from_snapshot(fixture.roots[4], bad_snapshot_id, 2)),
            Err(ConnectorStateStoreError::InvalidSnapshotSignature(_))
        ));

        let mut bad_boundary = state(2, Some(fixture.heads[1]), lease_id(99));
        bad_boundary.signature = Signature::zero();
        let bad_boundary_id =
            run_async(fixture.state_store.store_state_object(bad_boundary)).unwrap();
        let mut signed_snapshot = snapshot;
        signed_snapshot.covers_head = bad_boundary_id;
        signed_snapshot.header.refs = vec![bad_boundary_id];
        signed_snapshot.sign_with(&test_state_signing_key()).unwrap();
        let signed_snapshot_id = store_snapshot_for_test(&fixture.state_store, &signed_snapshot);
        assert!(matches!(
            run_async(reader.replay_from_snapshot(fixture.roots[4], signed_snapshot_id, 2)),
            Err(ConnectorStateStoreError::InvalidStateSignature(_))
        ));

        let mut bad_tail = state(3, Some(fixture.heads[2]), lease_id(98));
        bad_tail.signature = Signature::zero();
        let bad_tail_id = run_async(fixture.state_store.store_state_object(bad_tail)).unwrap();
        let successor = state(4, Some(bad_tail_id), lease_id(97));
        let successor_id = run_async(fixture.state_store.store_state_object(successor)).unwrap();
        let bad_root = fixture.store_root_for(successor_id);
        assert!(matches!(
            run_async(reader.replay_from_snapshot(bad_root, fixture.snapshot_id, 2)),
            Err(ConnectorStateStoreError::InvalidStateSignature(_))
        ));
    }

    #[test]
    fn snapshot_replay_checks_signed_sequence_and_singleton_fencing_edges() {
        let fixture = SnapshotReplayFixture::new();
        let reader = fixture.reader();
        let gap = state(4, Some(fixture.heads[2]), lease_id(90));
        let gap_head = run_async(fixture.state_store.store_state_object(gap)).unwrap();
        let gap_root = fixture.store_root_for(gap_head);
        assert!(matches!(
            run_async(reader.replay_from_snapshot(gap_root, fixture.snapshot_id, 1)),
            Err(ConnectorStateStoreError::SequenceMismatch { expected: 3, got: 4 })
        ));

        let mut stale = state(3, Some(fixture.heads[2]), lease_id(91));
        stale.lease_seq = 11;
        stale.sign_with(&test_state_signing_key()).unwrap();
        let stale_head = run_async(fixture.state_store.store_state_object(stale)).unwrap();
        let stale_root = fixture.store_root_for(stale_head);
        assert!(matches!(
            run_async(reader.replay_from_snapshot(stale_root, fixture.snapshot_id, 1)),
            Err(ConnectorStateStoreError::StaleLease {
                held_seq: 11,
                current_seq: 12,
            })
        ));
    }

    #[test]
    fn snapshot_replay_applies_writer_pins_to_every_tail_object() {
        let fixture = SnapshotReplayFixture::new();
        let outsider_key = Ed25519SigningKey::from_bytes(&[0x77; 32]).unwrap();
        let outsider = signed_state(3, Some(fixture.heads[2]), lease_id(92), &outsider_key);
        let outsider_head = run_async(fixture.state_store.store_state_object(outsider)).unwrap();
        let outsider_root = fixture.store_root_for(outsider_head);
        assert!(matches!(
            run_async(fixture.reader().replay_from_snapshot(
                outsider_root,
                fixture.snapshot_id,
                1,
            )),
            Err(ConnectorStateStoreError::UntrustedWriterKey { .. })
        ));
    }

    #[test]
    fn snapshot_replay_checks_exact_root_envelope_and_model() {
        let fixture = SnapshotReplayFixture::new();
        let reader = fixture.reader();
        let root = root_with_head(Some(fixture.heads[4]), 1_700_000_200);
        let mut mismatched = fixture
            .state_store
            .stored_object(&root.header, &root, RetentionClass::Pinned)
            .unwrap();
        mismatched.header.created_at += 1;
        mismatched.object_id = StoredObject::derive_id(
            &mismatched.header,
            &mismatched.body,
            &object_id_key(),
        )
        .unwrap();
        let mismatched_id = mismatched.object_id;
        run_async(fixture.object_store.put(mismatched)).unwrap();
        assert!(matches!(
            run_async(reader.replay_from_snapshot(mismatched_id, fixture.snapshot_id, 2)),
            Err(ConnectorStateStoreError::HeaderBodyMismatch)
        ));

        let mut wrong_model = root;
        wrong_model.model = ConnectorStateModel::Stateless;
        let wrong_model_id = run_async(fixture.state_store.store_root(wrong_model)).unwrap();
        assert!(matches!(
            run_async(reader.replay_from_snapshot(wrong_model_id, fixture.snapshot_id, 2)),
            Err(ConnectorStateStoreError::IdentityMismatch { field: "state_model", .. })
        ));
    }

    #[test]
    fn snapshot_reloads_emitted_id_when_newer_snapshot_wins_race() {
        let object_store = Arc::new(
            PausedPutObjectStore::new(usize::MAX, false).pause_first_snapshot_get(),
        );
        let state_store = test_store(object_store.clone())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));

        run_async(async {
            let requested_connector = connector_id();
            let mut first_snapshot =
                ConnectorStateStore::snapshot(&state_store, &requested_connector);
            assert!(futures_util::poll!(first_snapshot.as_mut()).is_pending());
            assert_eq!(object_store.puts.load(Ordering::SeqCst), 3);
            assert_eq!(object_store.snapshot_gets.load(Ordering::SeqCst), 1);

            let outcome = state_store
                .append_object(state(1, Some(head0), lease_id(2)))
                .await
                .unwrap();
            let ConnectorStateAppendOutcome::Committed {
                object_id: head1, ..
            } = outcome
            else {
                panic!("concurrent append must commit");
            };
            let newer_id = state_store.snapshot_head().await.unwrap().unwrap();

            object_store.release();
            let requested = first_snapshot.await.unwrap();
            assert_eq!(requested.covers_head, head0);
            assert_eq!(requested.covers_seq, 0);
            requested
                .verify_signature_with(&test_state_signing_key().verifying_key())
                .unwrap();

            let latest = state_store.latest_snapshot().await.unwrap().unwrap();
            assert_eq!(latest.0, newer_id);
            assert_eq!(latest.1.covers_head, head1);
            assert_eq!(latest.1.covers_seq, 1);
        });
    }

    #[test]
    fn latest_snapshot_empty_store_returns_none() {
        let state_store = test_store(store());
        assert!(run_async(state_store.latest_snapshot()).unwrap().is_none());
    }

    #[test]
    fn snapshot_head_empty_store_returns_none() {
        let state_store = test_store(store());
        assert!(run_async(state_store.snapshot_head()).unwrap().is_none());
    }

    #[test]
    fn automatic_snapshot_emits_on_configured_interval() {
        let state_store = test_store(store()).with_snapshot_every_entries(2);
        let (head0, first_snapshot) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (_head1, second_snapshot) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        assert!(first_snapshot.is_none());
        assert!(second_snapshot.is_some());
        let latest = run_async(state_store.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.1.covers_seq, 1);
    }

    #[test]
    fn automatic_snapshot_emits_after_elapsed_interval() {
        let state_store = test_store(store()).with_snapshot_every_entries(0);
        let (head0, first_snapshot) = append_ok(&state_store, state(0, None, lease_id(1)));
        assert!(first_snapshot.is_none());
        let first_snapshot_id = run_async(state_store.snapshot_head()).unwrap().unwrap();
        let first_snapshot = run_async(state_store.latest_snapshot()).unwrap().unwrap();
        assert_eq!(first_snapshot.0, first_snapshot_id);
        assert_eq!(first_snapshot.1.covers_seq, 0);

        let mut stale_state = state(1, Some(head0), lease_id(2));
        stale_state.updated_at = first_snapshot.1.snapshotted_at + DEFAULT_SNAPSHOT_EVERY_SECS;
        stale_state.sign_with(&test_state_signing_key()).unwrap();
        let (_head1, second_snapshot) = append_ok(&state_store, stale_state);

        assert!(second_snapshot.is_some());
        let latest = run_async(state_store.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.1.covers_seq, 1);
    }

    #[test]
    fn elapsed_snapshot_policy_can_be_disabled() {
        let state_store = test_store(store())
            .with_snapshot_every_entries(0)
            .with_snapshot_every_secs(0);
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        run_async(state_store.snapshot_head()).unwrap().unwrap();

        let mut stale_state = state(1, Some(head0), lease_id(2));
        stale_state.updated_at += DEFAULT_SNAPSHOT_EVERY_SECS * 2;
        stale_state.sign_with(&test_state_signing_key()).unwrap();
        let (_head1, second_snapshot) = append_ok(&state_store, stale_state);

        assert!(second_snapshot.is_none());
        let latest = run_async(state_store.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.1.covers_seq, 0);
    }

    #[test]
    fn snapshot_head_uses_current_head() {
        let state_store = test_store(store()).with_snapshot_every_entries(0);
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let snapshot_id = run_async(state_store.snapshot_head()).unwrap().unwrap();
        let latest = run_async(state_store.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.0, snapshot_id);
        assert_eq!(latest.1.covers_head, head0);
    }

    #[test]
    fn snapshot_latest_prefers_highest_sequence() {
        let state_store = test_store(store()).with_snapshot_every_entries(1);
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let latest = run_async(state_store.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.1.covers_seq, 1);
    }

    #[test]
    fn read_root_detects_tampered_object_id() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let mut root = root_with_head(None, 11);
        let mut stored = state_store
            .stored_object(&root.header, &root, RetentionClass::Pinned)
            .unwrap();
        stored.object_id = ObjectId::from_bytes([7; 32]);
        root.header.created_at = 12;
        run_async(object_store.put(stored)).unwrap();
        let err = run_async(state_store.read_root()).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::ContentIdMismatch { .. }
        ));
    }

    #[test]
    fn read_chain_detects_header_body_mismatch() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let state_obj = state(0, None, lease_id(1));
        let mut stored = state_store
            .stored_object(&state_obj.header, &state_obj, RetentionClass::Pinned)
            .unwrap();
        stored.header.created_at += 1;
        stored.object_id =
            StoredObject::derive_id(&stored.header, &stored.body, &object_id_key()).unwrap();
        let tampered_state_id = stored.object_id;
        run_async(object_store.put(stored)).unwrap();
        run_async(state_store.store_root(root_with_head(Some(tampered_state_id), 11))).unwrap();
        let err = run_async(state_store.read_chain(None, 1)).unwrap_err();
        assert!(matches!(err, ConnectorStateStoreError::HeaderBodyMismatch));
    }

    #[test]
    fn root_requires_head_reference() {
        let state_store = test_store(store());
        let mut root = root_with_head(Some(ObjectId::from_bytes([5; 32])), 11);
        root.header.refs.clear();
        let err = run_async(state_store.store_root(root)).unwrap_err();
        assert!(matches!(err, ConnectorStateStoreError::MissingHead(_)));
    }

    fn replica_limits() -> ConnectorStateReplicaLimits {
        ConnectorStateReplicaLimits {
            max_objects: 64,
            max_bytes: 4 * 1024 * 1024,
        }
    }

    fn export_test_replica(
        state_store: &FcpStoreConnectorStateStore,
    ) -> ConnectorStateReplicaBundle {
        let root_id = run_async(state_store.read_root()).unwrap().unwrap().0;
        run_async(state_store.export_replica(root_id, replica_limits())).unwrap()
    }

    fn replica_with_states(states: &[ConnectorStateObject]) -> ConnectorStateReplicaBundle {
        let state_store = test_store(store());
        let mut objects: Vec<_> = states
            .iter()
            .map(|state| {
                state_store
                    .stored_object(&state.header, state, RetentionClass::Pinned)
                    .unwrap()
            })
            .collect();
        let head = objects.last().unwrap().object_id;
        let root = state_store.root_for_head(states.last().unwrap(), head);
        let root_object = state_store
            .stored_object(&root.header, &root, RetentionClass::Pinned)
            .unwrap();
        let root_object_id = root_object.object_id;
        objects.push(root_object);
        ConnectorStateReplicaBundle {
            root_object_id,
            objects,
        }
    }

    fn replica_bytes(bundle: &ConnectorStateReplicaBundle) -> usize {
        bundle
            .objects
            .iter()
            .map(|object| {
                StoredObject::canonical_bytes(&object.header, &object.body)
                    .unwrap()
                    .len()
            })
            .sum()
    }

    #[test]
    fn replica_moves_complete_state_between_independent_stores() {
        let source = test_store(store());
        let (head0, _) = append_ok(&source, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&source, state(1, Some(head0), lease_id(2)));
        let mut bundle = export_test_replica(&source);
        assert_eq!(bundle.objects.len(), 3);
        assert_eq!(bundle.objects[0].object_id, head0);
        assert_eq!(bundle.objects[1].object_id, head1);
        assert_eq!(bundle.objects[2].object_id, bundle.root_object_id);
        assert_eq!(
            serde_json::from_str::<ConnectorStateReplicaBundle>(
                &serde_json::to_string(&bundle).unwrap()
            )
            .unwrap(),
            bundle
        );

        let target_objects = store();
        let target = test_store(target_objects.clone());
        bundle.objects.reverse();
        let change = run_async(target.import_replica(bundle.clone(), replica_limits()))
            .unwrap()
            .unwrap();
        assert_eq!(change.kind, ConnectorStateChangeKind::RootUpdated);
        assert_eq!(change.object_id, Some(bundle.root_object_id));
        assert_eq!(change.seq, Some(1));
        assert_eq!(
            run_async(target.read_chain(None, 64)).unwrap(),
            run_async(source.read_chain(None, 64)).unwrap()
        );
        assert_eq!(run_async(target_objects.list_zone(&zone_id())).len(), 3);
        assert_eq!(
            run_async(target.canonical_status(None))
                .unwrap()
                .mesh_replica_count,
            None
        );
    }

    #[test]
    fn replica_extension_duplicate_and_older_prefix_preserve_one_history() {
        let source = test_store(store());
        let (head0, _) = append_ok(&source, state(0, None, lease_id(1)));
        let initial = export_test_replica(&source);
        let target_objects = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
        let target = test_store(target_objects.clone());
        run_async(target.import_replica(initial.clone(), replica_limits())).unwrap();
        let (head1, _) = append_ok(&source, state(1, Some(head0), lease_id(2)));
        let extension = export_test_replica(&source);
        run_async(target.import_replica(extension.clone(), replica_limits()))
            .unwrap()
            .unwrap();
        let puts = target_objects.puts.load(Ordering::SeqCst);
        let generation = target.change_bus.generation();
        assert!(
            run_async(target.import_replica(extension, replica_limits()))
                .unwrap()
                .is_none()
        );
        assert!(
            run_async(target.import_replica(initial, replica_limits()))
                .unwrap()
                .is_none()
        );
        assert_eq!(target_objects.puts.load(Ordering::SeqCst), puts);
        assert!(target.change_bus.generation() > generation);
        assert_eq!(
            run_async(target.read_root()).unwrap().unwrap().1.head,
            Some(head1)
        );

        // The receiver remains a normal fenced state store after catch-up.
        let (head2, _) = append_ok(&target, state(2, Some(head1), lease_id(3)));
        assert_eq!(
            run_async(target.read_root()).unwrap().unwrap().1.head,
            Some(head2)
        );
    }

    #[test]
    fn replica_rejects_content_signature_identity_and_writer_pin_before_puts() {
        let valid_state = state(0, None, lease_id(1));
        let valid = replica_with_states(std::slice::from_ref(&valid_state));
        let mut bad_content = valid.clone();
        bad_content.objects[0].body.push(0);
        let mut bad_signature = valid_state.clone();
        bad_signature.signature = Signature::zero();
        let mut wrong_connector = valid_state.clone();
        wrong_connector.connector_id = other_connector_id();
        wrong_connector.sign_with(&test_state_signing_key()).unwrap();
        let mut wrong_zone = valid_state;
        wrong_zone.zone_id = other_zone_id();
        wrong_zone.header.zone_id = other_zone_id();
        wrong_zone.sign_with(&test_state_signing_key()).unwrap();

        for bundle in [
            bad_content,
            replica_with_states(&[bad_signature]),
            replica_with_states(&[wrong_connector]),
            replica_with_states(&[wrong_zone]),
        ] {
            let objects = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
            let target = test_store(objects.clone());
            let generation = target.change_bus.generation();
            assert!(run_async(target.import_replica(bundle, replica_limits())).is_err());
            assert_eq!(objects.puts.load(Ordering::SeqCst), 0);
            assert_eq!(target.change_bus.generation(), generation);
            assert!(run_async(objects.list_zone(&zone_id())).is_empty());
        }

        let objects = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
        let target = test_store(objects.clone()).with_trusted_writer_keys([[0x91; 32]]);
        assert!(matches!(
            run_async(target.import_replica(valid, replica_limits())),
            Err(ConnectorStateStoreError::UntrustedWriterKey { .. })
        ));
        assert_eq!(objects.puts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn replica_rejects_missing_duplicate_and_unrelated_objects_before_puts() {
        let source = test_store(store());
        let (head0, _) = append_ok(&source, state(0, None, lease_id(1)));
        append_ok(&source, state(1, Some(head0), lease_id(2)));
        let valid = export_test_replica(&source);
        let mut missing = valid.clone();
        missing.objects.remove(0);
        let mut duplicate = valid.clone();
        duplicate.objects.push(duplicate.objects[0].clone());
        let mut extra = valid.clone();
        let extra_state = state(0, None, lease_id(99));
        extra.objects.push(
            source
                .stored_object(&extra_state.header, &extra_state, RetentionClass::Pinned)
                .unwrap(),
        );
        let mut missing_root = valid;
        missing_root.root_object_id = lease_id(88);
        for bundle in [missing, duplicate, extra, missing_root] {
            let objects = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
            let target = test_store(objects.clone());
            let generation = target.change_bus.generation();
            assert!(run_async(target.import_replica(bundle, replica_limits())).is_err());
            assert_eq!(objects.puts.load(Ordering::SeqCst), 0);
            assert_eq!(target.change_bus.generation(), generation);
        }
    }

    #[test]
    fn replica_requires_genesis_continuity_and_monotonic_fencing() {
        let genesis = state(0, None, lease_id(1));
        let genesis_id =
            replica_with_states(std::slice::from_ref(&genesis)).objects[0].object_id;
        let skipped = state(2, Some(genesis_id), lease_id(2));
        let mut stale = state(1, Some(genesis_id), lease_id(2));
        stale.lease_seq = 9;
        stale.sign_with(&test_state_signing_key()).unwrap();
        for states in [
            vec![state(3, None, lease_id(1))],
            vec![genesis.clone(), skipped],
            vec![genesis, stale],
        ] {
            let objects = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
            let target = test_store(objects.clone());
            let error = run_async(
                target.import_replica(replica_with_states(&states), replica_limits()),
            )
            .unwrap_err();
            assert!(matches!(
                error,
                ConnectorStateStoreError::SequenceMismatch { .. }
                    | ConnectorStateStoreError::StaleLease { .. }
            ));
            assert_eq!(objects.puts.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn replica_rejects_competing_branch_without_poisoning_canonical_root() {
        let target_objects = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
        let target = test_store(target_objects.clone());
        let (head, _) = append_ok(&target, state(0, None, lease_id(1)));
        let root = run_async(target.read_root()).unwrap().unwrap().0;
        let puts = target_objects.puts.load(Ordering::SeqCst);
        let generation = target.change_bus.generation();
        let competitor = replica_with_states(&[state(0, None, lease_id(2))]);
        assert!(matches!(
            run_async(target.import_replica(competitor, replica_limits())),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
        assert_eq!(target_objects.puts.load(Ordering::SeqCst), puts);
        assert_eq!(target.change_bus.generation(), generation);
        assert_eq!(run_async(target.read_root()).unwrap().unwrap().0, root);
        assert_eq!(run_async(target.read_chain(None, 10)).unwrap()[0].0, head);
    }

    #[test]
    fn replica_import_ignores_warmed_cache_and_detects_unannounced_fork() {
        let objects = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
        let target = test_store(objects.clone());
        let (head0, _) = append_ok(&target, state(0, None, lease_id(1)));
        let initial = export_test_replica(&target);
        assert_eq!(
            run_async(target.read_root()).unwrap().unwrap().1.head,
            Some(head0)
        );
        store_replicated_state_and_root(&target, state(0, None, lease_id(2)));
        let puts = objects.puts.load(Ordering::SeqCst);
        let generation = target.change_bus.generation();
        assert!(matches!(
            run_async(target.import_replica(initial, replica_limits())),
            Err(ConnectorStateStoreError::ForkDetected { .. })
        ));
        assert_eq!(objects.puts.load(Ordering::SeqCst), puts);
        assert_eq!(target.change_bus.generation(), generation);
    }

    #[test]
    fn replica_noop_refreshes_readers_after_a_missed_valid_root_announcement() {
        for import_latest in [false, true] {
            let objects = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
            let writer = test_store(objects.clone());
            let reader = test_store(objects.clone());
            let importer = test_store(objects.clone());
            let (head0, _) = append_ok(&writer, state(0, None, lease_id(1)));
            let initial = export_test_replica(&writer);
            assert_eq!(
                run_async(reader.read_root()).unwrap().unwrap().1.head,
                Some(head0)
            );
            let (head1, root1) =
                store_replicated_state_and_root(&writer, state(1, Some(head0), lease_id(2)));
            let bundle = if import_latest {
                run_async(writer.export_replica(root1, replica_limits())).unwrap()
            } else {
                initial
            };
            let puts = objects.puts.load(Ordering::SeqCst);
            assert!(
                run_async(importer.import_replica(bundle, replica_limits()))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(objects.puts.load(Ordering::SeqCst), puts);
            assert_eq!(
                run_async(reader.read_root()).unwrap().unwrap().1.head,
                Some(head1)
            );
        }
    }

    #[test]
    fn replica_bounds_include_root_and_exact_canonical_header_bytes() {
        let source = test_store(store());
        append_ok(&source, state(0, None, lease_id(1)));
        let bundle = export_test_replica(&source);
        let exact = ConnectorStateReplicaLimits {
            max_objects: bundle.objects.len(),
            max_bytes: replica_bytes(&bundle),
        };
        assert_eq!(
            run_async(source.export_replica(bundle.root_object_id, exact)).unwrap(),
            bundle
        );
        let target = test_store(store());
        run_async(target.import_replica(bundle.clone(), exact))
            .unwrap()
            .unwrap();

        for limits in [
            ConnectorStateReplicaLimits {
                max_objects: exact.max_objects - 1,
                ..exact
            },
            ConnectorStateReplicaLimits {
                max_bytes: exact.max_bytes - 1,
                ..exact
            },
            ConnectorStateReplicaLimits {
                max_objects: 0,
                ..exact
            },
            ConnectorStateReplicaLimits {
                max_bytes: 0,
                ..exact
            },
        ] {
            assert!(run_async(source.export_replica(bundle.root_object_id, limits)).is_err());
            let objects = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
            let target = test_store(objects.clone());
            assert!(run_async(target.import_replica(bundle.clone(), limits)).is_err());
            assert_eq!(objects.puts.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn replica_normalizes_retention_and_rejects_existing_corrupt_dependencies() {
        let source = test_store(store());
        append_ok(&source, state(0, None, lease_id(1)));
        let bundle = export_test_replica(&source);
        let mut ephemeral = bundle.clone();
        for object in &mut ephemeral.objects {
            object.storage.retention = RetentionClass::Ephemeral;
        }
        let target_objects = store();
        let target = test_store(target_objects.clone());
        run_async(target.import_replica(ephemeral, replica_limits())).unwrap();
        for object in &bundle.objects {
            assert_eq!(
                run_async(target_objects.get_storage_meta(&object.object_id))
                    .unwrap()
                    .retention,
                RetentionClass::Pinned
            );
        }

        let poisoned = Arc::new(FailNthPutObjectStore::new(store(), usize::MAX));
        let target = test_store(poisoned.clone());
        let mut forged = bundle.objects[0].clone();
        forged.body.push(0);
        run_async(poisoned.put(forged)).unwrap();
        let puts = poisoned.puts.load(Ordering::SeqCst);
        assert!(matches!(
            run_async(target.import_replica(bundle.clone(), replica_limits())),
            Err(ConnectorStateStoreError::ReplicaObjectConflict { .. })
        ));
        assert_eq!(poisoned.puts.load(Ordering::SeqCst), puts);
        assert!(!run_async(poisoned.exists(&bundle.root_object_id)));
        assert!(run_async(target.read_root()).unwrap().is_none());
    }

    #[test]
    fn replica_export_pins_old_root_and_refuses_compacted_prefix() {
        let source = test_store(store());
        let (head0, _) = append_ok(&source, state(0, None, lease_id(1)));
        let initial = export_test_replica(&source);
        append_ok(&source, state(1, Some(head0), lease_id(2)));
        assert_eq!(
            run_async(source.export_replica(initial.root_object_id, replica_limits())).unwrap(),
            initial
        );

        // A root/head without its predecessor is insufficient for this API,
        // even though checkpoint-directed snapshot recovery may be possible.
        let incomplete_objects = store();
        let incomplete = test_store(incomplete_objects.clone());
        let bundle = export_test_replica(&source);
        for object in bundle.objects.iter().skip(1) {
            run_async(incomplete_objects.put(object.clone())).unwrap();
        }
        assert!(
            run_async(incomplete.export_replica(bundle.root_object_id, replica_limits())).is_err()
        );
    }

    #[test]
    fn replica_empty_root_and_unsupported_models_have_explicit_behavior() {
        let source = test_store(store());
        let root_id = run_async(source.store_root(root_with_head(None, 12))).unwrap();
        let bundle = run_async(source.export_replica(root_id, replica_limits())).unwrap();
        assert_eq!(bundle.objects.len(), 1);
        let target = test_store(store());
        let change = run_async(target.import_replica(bundle.clone(), replica_limits()))
            .unwrap()
            .unwrap();
        assert_eq!(change.seq, None);
        assert_eq!(run_async(target.read_root()).unwrap().unwrap().0, root_id);
        assert!(
            run_async(target.import_replica(bundle, replica_limits()))
                .unwrap()
                .is_none()
        );

        let stateless = test_store(store()).with_state_model(ConnectorStateModel::Stateless);
        let mut root = root_with_head(None, 13);
        root.model = ConnectorStateModel::Stateless;
        let root_object = stateless
            .stored_object(&root.header, &root, RetentionClass::Pinned)
            .unwrap();
        let bundle = ConnectorStateReplicaBundle {
            root_object_id: root_object.object_id,
            objects: vec![root_object.clone()],
        };
        run_async(stateless.object_store.put(root_object)).unwrap();
        assert!(matches!(
            run_async(stateless.export_replica(bundle.root_object_id, replica_limits())),
            Err(ConnectorStateStoreError::InvalidReplica { .. })
        ));
        assert!(matches!(
            run_async(stateless.import_replica(bundle.clone(), replica_limits())),
            Err(ConnectorStateStoreError::InvalidReplica { .. })
        ));
        assert!(matches!(
            run_async(target.import_replica(bundle, replica_limits())),
            Err(ConnectorStateStoreError::IdentityMismatch { field: "model", .. })
        ));
    }

    #[test]
    fn replica_state_or_root_write_failure_preserves_previous_canonical_head() {
        let source = test_store(store());
        let (head0, _) = append_ok(&source, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&source, state(1, Some(head0), lease_id(2)));
        let bundle = export_test_replica(&source);
        // Two puts seed the receiver. Replica puts are the existing genesis,
        // the new state, and only then the new canonical root.
        for fail_on_put in [3, 4, 5] {
            let objects = Arc::new(FailNthPutObjectStore::new(store(), fail_on_put));
            let target = test_store(objects.clone());
            append_ok(&target, state(0, None, lease_id(1)));
            let previous = run_async(target.read_root()).unwrap().unwrap().0;
            assert!(matches!(
                run_async(target.import_replica(bundle.clone(), replica_limits())),
                Err(ConnectorStateStoreError::ObjectStore(ObjectStoreError::Io(_)))
            ));
            assert!(!run_async(objects.exists(&bundle.root_object_id)));
            assert_eq!(run_async(target.read_root()).unwrap().unwrap().0, previous);
            assert_eq!(run_async(target.read_chain(None, 10)).unwrap().len(), 1);
            // Verified immutable leftovers from a failed attempt are reusable.
            run_async(target.import_replica(bundle.clone(), replica_limits()))
                .unwrap()
                .unwrap();
            assert_eq!(
                run_async(target.read_root()).unwrap().unwrap().1.head,
                Some(head1)
            );
        }
    }

    #[test]
    fn replica_cancelled_after_root_persistence_invalidates_other_readers() {
        let source = test_store(store());
        let (head0, _) = append_ok(&source, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&source, state(1, Some(head0), lease_id(2)));
        let bundle = export_test_replica(&source);
        run_async(async {
            let objects = Arc::new(PausedPutObjectStore::new(5, true));
            let target = test_store(objects.clone());
            let reader = test_store(objects.clone());
            target
                .append_object(state(0, None, lease_id(1)))
                .await
                .unwrap();
            assert_eq!(
                reader.read_root().await.unwrap().unwrap().1.head,
                Some(head0)
            );
            let mut transfer =
                Box::pin(target.import_replica(bundle.clone(), replica_limits()));
            assert!(futures_util::poll!(transfer.as_mut()).is_pending());
            assert_eq!(objects.puts.load(Ordering::SeqCst), 5);
            assert!(objects.exists(&bundle.root_object_id).await);
            drop(transfer);
            assert_eq!(
                reader.read_root().await.unwrap().unwrap().1.head,
                Some(head1)
            );
            assert!(matches!(
                reader
                    .append_object(state(2, Some(head1), lease_id(3)))
                    .await
                    .unwrap(),
                ConnectorStateAppendOutcome::Committed { seq: 2, .. }
            ));
        });
    }

    #[test]
    fn replica_holds_append_gate_until_root_publication() {
        let source = test_store(store());
        let (head0, _) = append_ok(&source, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&source, state(1, Some(head0), lease_id(2)));
        let bundle = export_test_replica(&source);
        run_async(async {
            let objects = Arc::new(PausedPutObjectStore::new(3, false));
            let target = test_store(objects.clone());
            let competing_adapter = test_store(objects.clone());
            let mut transfer =
                Box::pin(target.import_replica(bundle.clone(), replica_limits()));
            assert!(futures_util::poll!(transfer.as_mut()).is_pending());
            assert!(!objects.exists(&bundle.root_object_id).await);

            let mut proposed = state(0, None, lease_id(9));
            proposed.lease_seq = 50;
            proposed.sign_with(&test_state_signing_key()).unwrap();
            let mut append = Box::pin(competing_adapter.append_object(proposed));
            assert!(futures_util::poll!(append.as_mut()).is_pending());
            assert_eq!(objects.puts.load(Ordering::SeqCst), 3);
            objects.release();
            transfer.await.unwrap().unwrap();
            assert!(matches!(
                append.await.unwrap(),
                ConnectorStateAppendOutcome::Conflict {
                    canonical_head: Some(head),
                    canonical_seq: Some(1),
                } if head == head1
            ));
            assert_eq!(objects.puts.load(Ordering::SeqCst), 3);
            assert_eq!(
                target.read_root().await.unwrap().unwrap().1.head,
                Some(head1)
            );
        });
    }

    #[test]
    fn replica_survives_independent_durable_store_reopen() {
        let directory = tempfile::TempDir::new().unwrap();
        for checkpoint_after_ops in [0, 2] {
            let mut source_config = DurableObjectStoreConfig::new(
                directory.path().join(format!("source-{checkpoint_after_ops}")),
            );
            source_config.checkpoint_after_ops = checkpoint_after_ops;
            source_config.mac_key = Some([0x31; 32]);
            let mut target_config = DurableObjectStoreConfig::new(
                directory.path().join(format!("target-{checkpoint_after_ops}")),
            );
            target_config.checkpoint_after_ops = checkpoint_after_ops;
            target_config.mac_key = Some([0x32; 32]);
            let (root_id, head1, bundle) = {
                let source = test_store(Arc::new(
                    DurableObjectStore::open(source_config.clone()).unwrap(),
                ));
                let (head0, _) = append_ok(&source, state(0, None, lease_id(1)));
                let (head1, _) = append_ok(&source, state(1, Some(head0), lease_id(2)));
                let bundle = export_test_replica(&source);
                let target = test_store(Arc::new(
                    DurableObjectStore::open(target_config.clone()).unwrap(),
                ));
                run_async(target.import_replica(bundle.clone(), replica_limits()))
                    .unwrap()
                    .unwrap();
                (bundle.root_object_id, head1, bundle)
            };
            let source =
                test_store(Arc::new(DurableObjectStore::open(source_config).unwrap()));
            let target =
                test_store(Arc::new(DurableObjectStore::open(target_config).unwrap()));
            assert_eq!(run_async(target.read_root()).unwrap().unwrap().0, root_id);
            assert_eq!(
                run_async(target.read_root()).unwrap().unwrap().1.head,
                Some(head1)
            );
            assert_eq!(
                run_async(source.export_replica(root_id, replica_limits())).unwrap(),
                bundle
            );
            assert!(
                run_async(target.import_replica(bundle, replica_limits()))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(run_async(target.read_chain(None, 64)).unwrap().len(), 2);
        }
    }
}
