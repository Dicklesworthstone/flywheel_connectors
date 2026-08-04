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
use fcp_crypto::Ed25519VerifyingKey;
use fcp_prelude::{
    BackoffPolicy, ConnectorId, ConnectorStateAppendOutcome, ConnectorStateCanonicalStatus,
    ConnectorStateChange, ConnectorStateChangeKind, ConnectorStateChangeStream,
    ConnectorStateError, ConnectorStateModel, ConnectorStateObject, ConnectorStateRoot,
    ConnectorStateSnapshot, ConnectorStateStore, ConnectorStateWriteAuthorization, InstanceId,
    ObjectHeader, ObjectId, ObjectIdKey, RetentionClass, StorageMeta, StoredObject, ZoneId,
};
use futures_util::stream;
use parking_lot::RwLock;
use semver::Version;
use serde::Serialize;
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

    /// A state object used a sequence number that does not follow the head.
    #[error("connector state sequence mismatch: expected {expected}, got {got}")]
    SequenceMismatch {
        /// Expected next sequence number.
        expected: u64,
        /// Incoming sequence number.
        got: u64,
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
}

type Result<T> = std::result::Result<T, ConnectorStateStoreError>;

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
        self
    }

    /// Scope the store to one connector instance.
    #[must_use]
    pub fn with_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
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
    /// Returns an error if a matching root object is malformed or fails
    /// content-id verification.
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
        let stored = self.object_store.get(&root_object_id).await?;
        let root: ConnectorStateRoot =
            self.decode_stored(&stored, &Self::root_schema_id(), "connector state root")?;
        self.validate_root(&root)?;
        let seq = self.root_head_seq(&root).await?;

        Ok(self.publish_change(
            ConnectorStateChangeKind::RootUpdated,
            Some(root_object_id),
            seq,
        ))
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
            self.validate_root(&root)?;
            let head_seq = self.root_head_seq(&root).await?;

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
            self.cache_root(generation, *object_id, root.clone());
        }
        Ok(root)
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

        let current = self.current_head().await?;
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

        let object_id = self
            .store_state_object_with_retry(state_obj.clone())
            .await?;
        let root = self.root_for_head(&state_obj, object_id);
        let root_object_id = self.store_root_with_retry(root).await?;
        let snapshot_object_id = self
            .maybe_emit_snapshot_after_root_commit(object_id, &state_obj)
            .await;

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
            next = state.prev;
            states.push((object_id, state));
        }

        states.reverse();
        states.retain(|(_object_id, state)| after_seq.is_none_or(|min_seq| state.seq > min_seq));
        states.truncate(limit);
        Ok(states)
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
    /// Returns an error if the root/head is missing or storage fails.
    pub async fn snapshot_head(&self) -> Result<Option<ObjectId>> {
        let Some((head_id, head)) = self.current_head().await? else {
            return Ok(None);
        };
        let snapshot_id = self.emit_snapshot(head_id, &head).await?;
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
    /// Returns an error if a matching snapshot is malformed.
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
            self.validate_snapshot(&snapshot)?;

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

    /// Mark state objects older than `before_seq` as ephemeral for later GC.
    ///
    /// This method intentionally does not delete objects; it only relaxes
    /// retention on non-head chain entries so the GC layer can make the final
    /// reachability decision under its own policy.
    ///
    /// # Errors
    /// Returns an error if state loading or retention updates fail.
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
        let mut updated = 0;
        for (object_id, state) in states {
            if head_object_id.as_ref() == Some(&object_id) {
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
        self.emit_snapshot(object_id, state_obj).await.map(Some)
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

    async fn emit_snapshot(
        &self,
        covers_head: ObjectId,
        state_obj: &ConnectorStateObject,
    ) -> Result<ObjectId> {
        let started = Instant::now();
        let result = self.emit_snapshot_inner(covers_head, state_obj).await;
        let telemetry_result = if result.is_ok() { "emitted" } else { "error" };
        self.record_operation_telemetry(
            CONNECTOR_STATE_SNAPSHOT_EVENT,
            "snapshot",
            telemetry_result,
            started,
        );
        result
    }

    async fn emit_snapshot_inner(
        &self,
        covers_head: ObjectId,
        state_obj: &ConnectorStateObject,
    ) -> Result<ObjectId> {
        let mut header = self.derived_header(
            Self::snapshot_schema_id(),
            state_obj.header.created_at,
            state_obj.header.provenance.clone(),
        );
        header.refs.push(covers_head);
        header.placement.clone_from(&state_obj.header.placement);

        let snapshot = ConnectorStateSnapshot {
            header,
            connector_id: self.connector_id.clone(),
            instance_id: self.instance_id.clone(),
            zone_id: self.zone_id.clone(),
            covers_head,
            covers_seq: state_obj.seq,
            state_cbor: state_obj.state_cbor.clone(),
            snapshotted_at: state_obj.updated_at,
            signature: state_obj.signature,
        };

        self.validate_snapshot(&snapshot)?;
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
            ConnectorStateStoreError::MissingHead(head) => {
                ConnectorStateError::SnapshotUnavailable {
                    connector_id: self.connector_id.clone(),
                    reason: format!("root references missing state object {head}"),
                }
            }
            ConnectorStateStoreError::UnexpectedSchema { .. }
            | ConnectorStateStoreError::IdentityMismatch { .. }
            | ConnectorStateStoreError::HeaderBodyMismatch
            | ConnectorStateStoreError::ContentIdMismatch { .. }
            | ConnectorStateStoreError::MissingLeaseReference(_)
            | ConnectorStateStoreError::EmptyStateCbor
            | ConnectorStateStoreError::InvalidStateCbor(_)
            | ConnectorStateStoreError::InvalidStateSignature(_)
            | ConnectorStateStoreError::SequenceMismatch { .. }
            | ConnectorStateStoreError::SequenceOverflow(_)
            | ConnectorStateStoreError::ChainCycle(_)
            | ConnectorStateStoreError::UntrustedWriterKey { .. }
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
        let Some((latest_id, snapshot)) = Self::latest_snapshot(self)
            .await
            .map_err(|err| self.to_connector_state_error(err))?
        else {
            return Err(ConnectorStateError::SnapshotUnavailable {
                connector_id: connector_id.clone(),
                reason: "snapshot was emitted but could not be reloaded".to_string(),
            });
        };
        if latest_id != snapshot_id {
            return Err(ConnectorStateError::SnapshotUnavailable {
                connector_id: connector_id.clone(),
                reason: format!("latest snapshot {latest_id} did not match emitted {snapshot_id}"),
            });
        }
        Ok(snapshot)
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
}

impl ConnectorStateChangeBus {
    fn new() -> Self {
        let (sender, _receiver) = broadcast::channel(CONNECTOR_STATE_CHANGE_BUFFER_CAPACITY);
        Self {
            sender,
            root_generation: AtomicU64::new(0),
        }
    }

    fn generation(&self) -> u64 {
        self.root_generation.load(Ordering::Acquire)
    }

    fn mark_root_updated(&self) {
        self.root_generation.fetch_add(1, Ordering::AcqRel);
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
        MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
        ObjectSymbolMeta, ObjectTransmissionInfo, StoredSymbol, SymbolMeta,
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

        // A zone insider holding the shared object-id key plants a
        // self-signed higher-seq chain: valid schema, valid content-id,
        // valid self-signature, but a foreign writer key.
        let insider_key = Ed25519SigningKey::from_bytes(&[0x77; 32]).unwrap();
        let forged = signed_state(5, None, lease_id(9), &insider_key);
        let stored = unpinned
            .stored_object(&forged.header, &forged, RetentionClass::Pinned)
            .unwrap();
        let forged_head = stored.object_id;
        run_async(object_store.put(stored)).unwrap();
        run_async(unpinned.store_root(root_with_head(Some(forged_head), 1_700_000_500))).unwrap();

        // Without a pin the forged chain outranks the legitimate head — this
        // is the nr4cq insider gap the pin exists to close.
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
}
