//! Object store interface for FCPS durable objects.
//!
//! Provides content-addressed storage for complete mesh objects.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::coverage::CoverageEvaluation;
use crate::error::LifecycleSnapshotError;
use crate::gc::GcRoots;
use crate::object_id_verifier::ObjectIdVerifier;
use crate::symbol_store::SymbolStore;
use fcp_prelude::{ObjectHeader, ObjectId, RetentionClass, StorageMeta, StoredObject, ZoneId};
use parking_lot::RwLock;

use crate::error::ObjectStoreError;

/// Root role recorded in a lifecycle snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleRootRole {
    Checkpoint,
    Pin,
}

impl LifecycleRootRole {
    const fn sort_key(self) -> u8 {
        match self {
            Self::Checkpoint => 0,
            Self::Pin => 1,
        }
    }
}

/// Validation state for a configured lifecycle root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleRootStatus {
    Valid,
    Missing,
    ForeignZone,
}

/// Deterministic observation of one configured root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleRootObservation {
    /// Root object id.
    pub object_id: ObjectId,
    /// Why this object is part of the root set.
    pub role: LifecycleRootRole,
    /// Whether the root resolves inside the requested zone snapshot.
    pub status: LifecycleRootStatus,
}

/// Lease state exposed in lifecycle snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectLeaseState {
    NotLeased,
    Active,
    Expired,
}

/// Deterministic object-level lifecycle state for one zone snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectLifecycleSnapshot {
    /// Object identifier.
    pub object_id: ObjectId,
    /// Root roles currently attached to this object.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_roles: Vec<LifecycleRootRole>,
    /// Whether the object is reachable from the valid root set.
    pub reachable_from_roots: bool,
    /// Current node-local retention class.
    pub retention: RetentionClass,
    /// Lease-state summary derived from retention and snapshot time.
    pub lease_state: ObjectLeaseState,
    /// Local schema-bound references in deterministic order.
    pub refs: Vec<ObjectId>,
    /// Cross-zone or foreign references in deterministic order.
    pub foreign_refs: Vec<ObjectId>,
    /// Optional TTL declared in the object header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Coverage evaluation when a symbol store was supplied and metadata exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CoverageEvaluation>,
    /// Whether current coverage satisfies the declared placement policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meets_placement_policy: Option<bool>,
    /// Whether the object is currently reconstructable from available symbols.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconstructable: Option<bool>,
}

/// Deterministic zone-level lifecycle snapshot for durable object debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneLifecycleSnapshot {
    /// Zone represented by this snapshot.
    pub zone_id: ZoneId,
    /// Snapshot time used for lease-state derivation.
    pub generated_at: u64,
    /// Configured checkpoint root, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_root: Option<ObjectId>,
    /// Validity of configured roots in deterministic order.
    pub roots: Vec<LifecycleRootObservation>,
    /// Total objects currently stored for the zone.
    pub object_count: usize,
    /// Objects reachable from the valid root set.
    pub reachable_count: usize,
    /// Objects currently unreachable from the valid root set.
    pub unreachable_count: usize,
    /// Reconstructable-object count when a symbol store was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconstructable_count: Option<usize>,
    /// Per-object lifecycle details in deterministic object-id order.
    pub objects: Vec<ObjectLifecycleSnapshot>,
}

async fn classify_root(
    object_id: ObjectId,
    zone_id: &ZoneId,
    store: &dyn ObjectStore,
) -> Result<LifecycleRootStatus, LifecycleSnapshotError> {
    match store.get_header(&object_id).await {
        Ok(header) if &header.zone_id == zone_id => Ok(LifecycleRootStatus::Valid),
        Ok(_) => Ok(LifecycleRootStatus::ForeignZone),
        Err(ObjectStoreError::NotFound(_)) => Ok(LifecycleRootStatus::Missing),
        Err(err) => Err(err.into()),
    }
}

/// Build a deterministic lifecycle snapshot for all objects in a zone.
///
/// The snapshot intentionally mirrors current durable-plane state rather than
/// predicting future GC or repair actions. Root validity is reported
/// explicitly so downstream tests can assert missing or foreign-zone roots
/// without having to reverse-engineer GC behavior.
///
/// # Errors
/// Returns an error if object or symbol metadata cannot be read.
#[allow(clippy::too_many_lines)]
pub async fn snapshot_zone_lifecycle(
    zone_id: &ZoneId,
    roots: &GcRoots,
    store: &dyn ObjectStore,
    symbol_store: Option<&dyn SymbolStore>,
    current_time: u64,
) -> Result<ZoneLifecycleSnapshot, LifecycleSnapshotError> {
    let mut root_observations = Vec::new();
    if let Some(checkpoint_root) = roots.zone_checkpoint {
        root_observations.push(LifecycleRootObservation {
            object_id: checkpoint_root,
            role: LifecycleRootRole::Checkpoint,
            status: classify_root(checkpoint_root, zone_id, store).await?,
        });
    }

    let mut pinned_roots: Vec<_> = roots.pinned.iter().copied().collect();
    pinned_roots.sort_unstable();
    for pinned_root in pinned_roots {
        root_observations.push(LifecycleRootObservation {
            object_id: pinned_root,
            role: LifecycleRootRole::Pin,
            status: classify_root(pinned_root, zone_id, store).await?,
        });
    }

    root_observations.sort_by(|left, right| {
        left.object_id
            .cmp(&right.object_id)
            .then(left.role.sort_key().cmp(&right.role.sort_key()))
    });

    let mut reachable = HashSet::new();
    let mut queue: VecDeque<_> = root_observations
        .iter()
        .filter(|root| root.status == LifecycleRootStatus::Valid)
        .map(|root| root.object_id)
        .collect();
    while let Some(object_id) = queue.pop_front() {
        if !reachable.insert(object_id) {
            continue;
        }

        let header = store.get_header(&object_id).await?;
        if &header.zone_id != zone_id {
            continue;
        }

        let mut refs = header.refs;
        refs.sort_unstable();
        queue.extend(refs);
    }

    let mut object_ids = store.list_zone(zone_id).await;
    object_ids.sort_unstable();

    let mut objects = Vec::with_capacity(object_ids.len());
    for object_id in object_ids {
        let object = store.get(&object_id).await?;

        let mut root_roles = Vec::new();
        if roots.zone_checkpoint == Some(object_id) {
            root_roles.push(LifecycleRootRole::Checkpoint);
        }
        if roots.pinned.contains(&object_id) {
            root_roles.push(LifecycleRootRole::Pin);
        }

        let lease_state = match object.storage.retention {
            RetentionClass::Pinned | RetentionClass::Ephemeral => ObjectLeaseState::NotLeased,
            RetentionClass::Lease { expires_at } if expires_at > current_time => {
                ObjectLeaseState::Active
            }
            RetentionClass::Lease { .. } => ObjectLeaseState::Expired,
        };

        let mut refs = object.header.refs.clone();
        refs.sort_unstable();
        let mut foreign_refs = object.header.foreign_refs.clone();
        foreign_refs.sort_unstable();

        let mut coverage = None;
        let mut meets_placement_policy = None;
        let mut reconstructable = None;
        if let Some(symbol_store) = symbol_store {
            if let Some(distribution) = symbol_store.get_distribution(&object_id).await {
                let evaluation = CoverageEvaluation::from_distribution(object_id, &distribution);
                if let Some(policy) = object.header.placement.as_ref() {
                    meets_placement_policy = Some(evaluation.meets_policy(policy));
                    // Use the evaluation we already built instead of re-querying
                    // the symbol store via can_reconstruct_with_policy — the second
                    // get_distribution call would acquire the write lock again and
                    // could see a different snapshot (TOCTOU).
                    reconstructable = Some(evaluation.meets_diversity_for_reconstruction(policy));
                } else {
                    reconstructable = Some(evaluation.is_available);
                }
                coverage = Some(evaluation);
            } else {
                if object.header.placement.is_some() {
                    meets_placement_policy = Some(false);
                }
                reconstructable = Some(false);
            }
        }

        objects.push(ObjectLifecycleSnapshot {
            object_id,
            root_roles,
            reachable_from_roots: reachable.contains(&object_id),
            retention: object.storage.retention,
            lease_state,
            refs,
            foreign_refs,
            ttl_secs: object.header.ttl_secs,
            coverage,
            meets_placement_policy,
            reconstructable,
        });
    }

    let reachable_count = objects
        .iter()
        .filter(|entry| entry.reachable_from_roots)
        .count();
    let object_count = objects.len();
    let reconstructable_count = symbol_store.map(|_| {
        objects
            .iter()
            .filter(|entry| entry.reconstructable == Some(true))
            .count()
    });

    Ok(ZoneLifecycleSnapshot {
        zone_id: zone_id.clone(),
        generated_at: current_time,
        checkpoint_root: roots.zone_checkpoint,
        roots: root_observations,
        object_count,
        reachable_count,
        unreachable_count: object_count.saturating_sub(reachable_count),
        reconstructable_count,
        objects,
    })
}

/// Object store interface (NORMATIVE).
///
/// Stores complete, content-addressed objects with retention policies.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Store an object.
    ///
    /// # Errors
    /// Returns error if object already exists or quota exceeded.
    async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError>;

    /// Retrieve an object by ID.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError>;

    /// Check if object exists.
    async fn exists(&self, id: &ObjectId) -> bool;

    /// Delete an object.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError>;

    /// Get object header without body.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError>;

    /// Get storage metadata.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError>;

    /// Update retention class for an object.
    ///
    /// # Errors
    /// Returns `NotFound` if object doesn't exist.
    async fn set_retention(
        &self,
        id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError>;

    /// List all object IDs in a zone.
    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId>;

    /// Get total storage used in bytes.
    async fn storage_used(&self) -> u64;

    /// Get storage quota in bytes.
    async fn storage_quota(&self) -> u64;

    /// Whether a content-id [`ObjectIdVerifier`] is installed on this store.
    ///
    /// Stores reachable from untrusted write paths (peer-supplied mesh
    /// objects) must have a verifier installed so `put` enforces
    /// `object_id == derive_id(header, body, zone_key)`; without one, a
    /// hostile peer can bind attacker-controlled bytes to a legitimately
    /// requested object id (cache poisoning). `MeshNode` uses this to
    /// surface verifier-less live-network ingestion loudly (bead
    /// mesh-node-content-id-verifier-wiring-h3xmd). Defaults to `false`
    /// for wrapper/test stores that do not manage a verifier.
    fn has_object_id_verifier(&self) -> bool {
        false
    }
}

/// Configuration for in-memory object store.
#[derive(Debug, Clone)]
pub struct MemoryObjectStoreConfig {
    /// Maximum storage in bytes.
    pub max_bytes: u64,
}

impl Default for MemoryObjectStoreConfig {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024, // 256MB
        }
    }
}

/// In-memory object store implementation.
///
/// Suitable for testing and single-node deployments.
pub struct MemoryObjectStore {
    objects: RwLock<HashMap<ObjectId, StoredObject>>,
    /// Secondary index: zone → set of object IDs in that zone.
    /// Maintained on `put()` and `delete()` for O(1) `list_zone()`.
    zone_index: RwLock<HashMap<ZoneId, Vec<ObjectId>>>,
    config: MemoryObjectStoreConfig,
    used_bytes: AtomicU64,
    /// Optional verifier invoked on every put. When present, enforces
    /// `object.object_id == derive_id(&object.header, &object.body, zone_key)`
    /// before the object reaches the in-memory map. Closes the
    /// attacker-chosen-id injection vector documented in
    /// bead flywheel_connectors-4g0qr.
    verifier: Option<Arc<dyn ObjectIdVerifier>>,
}

impl MemoryObjectStore {
    /// Create a new in-memory object store.
    #[must_use]
    pub fn new(config: MemoryObjectStoreConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            zone_index: RwLock::new(HashMap::new()),
            config,
            used_bytes: AtomicU64::new(0),
            verifier: None,
        }
    }

    /// Install a content-id verifier. When set, every `put` call
    /// recomputes `derive_id(header, body, zone_key)` and rejects
    /// mismatches with [`ObjectStoreError::ContentIdMismatch`].
    ///
    /// Callers that hold live zone-key material (the runtime layer —
    /// typically `MeshNode` or the bootstrap shim) should install a
    /// verifier in any store that's reachable from an untrusted write
    /// path.
    #[must_use]
    pub fn with_verifier(mut self, verifier: Arc<dyn ObjectIdVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Size accounted against `max_bytes` — the actual canonical
    /// encoding length of the object (magic prefix + canonical-CBOR
    /// header + body).
    ///
    /// Before br-fm746 this returned `body.len() + 512`, which under-
    /// counted header-heavy objects (large `refs` / `foreign_refs` /
    /// `placement`). An attacker could store many small-body,
    /// large-header objects and bypass `max_bytes` by orders of
    /// magnitude because the in-memory `ObjectHeader` footprint was
    /// pegged at a 512-byte estimate. Now we measure the real canonical
    /// size via [`StoredObject::canonical_bytes`] — the same encoding
    /// used for `ObjectId` derivation and the 64 MiB canonical cap.
    ///
    /// Fallibility: `canonical_bytes` can only fail on non-canonical-
    /// izable values (NaN / Infinity / duplicate-key maps) or oversized
    /// payloads. `put()` gates every incoming object through
    /// `validate_structure()` first, which runs the same pipeline — a
    /// value that fails here after passing `put()` would mean internal
    /// state corruption. Rather than panic in quota accounting, we fall
    /// back to the 64 MiB canonical ceiling so the accounting over-
    /// charges and fails closed. Quota overestimates are safe;
    /// underestimates are the bug we're fixing.
    pub(crate) fn object_size(obj: &StoredObject) -> u64 {
        // 64 MiB — matches fcp_cbor::MAX_CANONICAL_OBJECT_BYTES. We
        // can't import fcp-cbor as a regular dep (it lives under
        // dev-dependencies in this crate), and adding it would pull its
        // full transitive graph into every lib build. A local constant
        // is authoritative enough for a conservative fallback.
        const MAX_CANONICAL_FALLBACK: u64 = 64 * 1024 * 1024;

        match StoredObject::canonical_bytes(&obj.header, &obj.body) {
            Ok(bytes) => bytes.len() as u64,
            Err(_) => MAX_CANONICAL_FALLBACK,
        }
    }
}

#[async_trait]
impl ObjectStore for MemoryObjectStore {
    fn has_object_id_verifier(&self) -> bool {
        self.verifier.is_some()
    }

    async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError> {
        // Defense-in-depth: reject objects whose header cannot be
        // canonically encoded or whose total size exceeds
        // `fcp_cbor::MAX_CANONICAL_OBJECT_BYTES`. Prevents a malformed or
        // oversized object from being persisted at the runtime boundary,
        // mirroring the WAL/snapshot replay checks. Full content-ID
        // verification happens below via `self.verifier` when installed.
        object
            .validate_structure()
            .map_err(|err| ObjectStoreError::Io(format!("invalid object structure: {err}")))?;

        // When a verifier is installed, enforce the content-id binding
        // before the object reaches state. Closes the
        // attacker-chosen-id injection vector from bead
        // flywheel_connectors-4g0qr: a caller can no longer persist a
        // `StoredObject { object_id: H, header: H', body: B' }` where
        // `(H', B')` are not the canonical bytes behind `H`.
        if let Some(verifier) = self.verifier.as_ref() {
            verifier.verify(&object)?;
        }

        let mut objects = self.objects.write();

        if objects.contains_key(&object.object_id) {
            return Err(ObjectStoreError::AlreadyExists(object.object_id));
        }

        let size = Self::object_size(&object);
        let used = self.used_bytes.load(Ordering::SeqCst);
        if used.saturating_add(size) > self.config.max_bytes {
            return Err(ObjectStoreError::QuotaExceeded {
                used,
                max: self.config.max_bytes,
            });
        }

        let id = object.object_id;
        let zone_id = object.header.zone_id.clone();
        objects.insert(id, object);

        // Maintain zone index BEFORE releasing the objects lock so that
        // a concurrent delete() cannot create orphan zone_index entries.
        self.zone_index.write().entry(zone_id).or_default().push(id);

        // Commit the byte count BEFORE releasing the objects lock. If
        // `fetch_add` runs after `drop(objects)`, a concurrent `put` can
        // acquire `objects.write()`, observe the still-stale `used_bytes`
        // load, and pass its quota check despite the in-flight commit —
        // both inserts then succeed and `used_bytes` exceeds `max_bytes`.
        // `delete` already keeps its `fetch_update` inside the critical
        // section; mirror that here.
        self.used_bytes.fetch_add(size, Ordering::SeqCst);
        drop(objects);

        Ok(())
    }

    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
        self.objects
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn exists(&self, id: &ObjectId) -> bool {
        self.objects.read().contains_key(id)
    }

    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
        let mut objects = self.objects.write();
        let obj = objects.remove(id).ok_or(ObjectStoreError::NotFound(*id))?;

        let size = Self::object_size(&obj);
        let zone_id = &obj.header.zone_id;

        // Remove from zone index. When the deletion empties the zone,
        // drop the (zone_id, empty Vec) entry too — otherwise the
        // zone_index map grows monotonically with the cardinality of
        // ZoneIds ever seen, not currently-active zones. This is a
        // bounded but permanent leak on long-running hosts that cycle
        // zones in and out (br-A9 sweep).
        let mut zone_index = self.zone_index.write();
        if let Some(ids) = zone_index.get_mut(zone_id) {
            ids.retain(|oid| oid != id);
            if ids.is_empty() {
                zone_index.remove(zone_id);
            }
        }
        drop(zone_index);

        self.used_bytes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_sub(size))
            })
            .ok();

        Ok(())
    }

    async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError> {
        self.objects
            .read()
            .get(id)
            .map(|obj| obj.header.clone())
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError> {
        self.objects
            .read()
            .get(id)
            .map(|obj| obj.storage.clone())
            .ok_or_else(|| ObjectStoreError::NotFound(*id))
    }

    async fn set_retention(
        &self,
        id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError> {
        let mut objects = self.objects.write();
        let obj = objects.get_mut(id).ok_or(ObjectStoreError::NotFound(*id))?;

        obj.storage.retention = retention;
        Ok(())
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        // O(1) lookup via zone index instead of scanning all objects.
        self.zone_index
            .read()
            .get(zone_id)
            .cloned()
            .unwrap_or_default()
    }

    async fn storage_used(&self) -> u64 {
        self.used_bytes.load(Ordering::SeqCst)
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;

    use bytes::Bytes;
    use chrono::Utc;
    use fcp_cbor::SchemaId;
    use fcp_prelude::Provenance;
    use semver::Version;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::symbol_store::{MemorySymbolStore, MemorySymbolStoreConfig, SymbolMeta};

    #[derive(Default)]
    struct StoreLogData {
        object_id: Option<ObjectId>,
        object_size: Option<u64>,
        symbol_count: Option<u32>,
        coverage_bps: Option<u32>,
        nodes_holding: Option<Vec<String>>,
        details: Option<serde_json::Value>,
    }

    fn run_store_test<F, Fut>(test_name: &str, phase: &str, operation: &str, assertions: u32, f: F)
    where
        F: FnOnce() -> Fut + panic::UnwindSafe,
        Fut: std::future::Future<Output = StoreLogData>,
    {
        let start = Instant::now();
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            fcp_async_core::runtime::block_on_sync(f()).expect("runtime")
        }));
        let duration_us = start.elapsed().as_micros();

        let (passed, failed, outcome, data) = match &result {
            Ok(data) => (assertions, 0, "pass", Some(data)),
            Err(_) => (0, assertions, "fail", None),
        };

        let log = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "info",
            "test_name": test_name,
            "module": "fcp-store",
            "phase": phase,
            "operation": operation,
            "correlation_id": Uuid::new_v4().to_string(),
            "result": outcome,
            "duration_us": duration_us,
            "object_id": data.and_then(|d| d.object_id).map(|id| id.to_string()),
            "object_size": data.and_then(|d| d.object_size),
            "symbol_count": data.and_then(|d| d.symbol_count),
            "coverage_bps": data.and_then(|d| d.coverage_bps),
            "nodes_holding": data.and_then(|d| d.nodes_holding.clone()),
            "details": data.and_then(|d| d.details.clone()),
            "assertions": {
                "passed": passed,
                "failed": failed
            }
        });
        println!("{log}");

        if let Err(payload) = result {
            panic::resume_unwind(payload);
        }
    }

    fn test_zone() -> ZoneId {
        "z:test".parse().unwrap()
    }

    fn test_stored_object(id_byte: u8, body: &[u8]) -> StoredObject {
        StoredObject {
            object_id: ObjectId::from_bytes([id_byte; 32]),
            header: ObjectHeader {
                schema: SchemaId::new("fcp.test", "Test", Version::new(1, 0, 0)),
                zone_id: test_zone(),
                created_at: 1_000_000,
                provenance: Provenance::new(test_zone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            },
            body: body.to_vec(),
            storage: StorageMeta {
                retention: RetentionClass::Ephemeral,
            },
        }
    }

    fn test_foreign_zone_object(id_byte: u8, body: &[u8]) -> StoredObject {
        let mut object = test_stored_object(id_byte, body);
        object.header.zone_id = "z:foreign".parse().unwrap();
        object
    }

    #[test]
    fn put_and_get() {
        run_store_test("put_and_get", "verify", "write", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"test body");
            let id = obj.object_id;
            let size = obj.body.len() as u64;

            store.put(obj.clone()).await.unwrap();

            let retrieved = store.get(&id).await.unwrap();
            assert_eq!(retrieved.body, b"test body");

            StoreLogData {
                object_id: Some(id),
                object_size: Some(size),
                details: Some(json!({"zone_id": test_zone().to_string()})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_not_found() {
        run_store_test("get_not_found", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let id = ObjectId::from_bytes([99_u8; 32]);

            let result = store.get(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"error": "not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn put_duplicate_rejected() {
        run_store_test("put_duplicate_rejected", "verify", "write", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;

            store.put(obj.clone()).await.unwrap();
            let result = store.put(obj).await;
            assert!(matches!(result, Err(ObjectStoreError::AlreadyExists(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"error": "already_exists"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_object() {
        run_store_test("delete_object", "verify", "delete", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;
            let size = obj.body.len() as u64;

            store.put(obj).await.unwrap();
            assert!(store.exists(&id).await);

            store.delete(&id).await.unwrap();
            assert!(!store.exists(&id).await);

            StoreLogData {
                object_id: Some(id),
                object_size: Some(size),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quota_enforcement() {
        run_store_test("quota_enforcement", "verify", "write", 1, || async {
            let config = MemoryObjectStoreConfig { max_bytes: 1000 };
            let store = MemoryObjectStore::new(config);

            let obj = test_stored_object(1, &vec![0_u8; 1000]);
            let size = obj.body.len() as u64;

            let result = store.put(obj).await;
            assert!(matches!(
                result,
                Err(ObjectStoreError::QuotaExceeded { .. })
            ));

            StoreLogData {
                object_size: Some(size),
                details: Some(json!({"error": "quota_exceeded"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn duplicate_object_does_not_report_quota() {
        run_store_test(
            "duplicate_object_does_not_report_quota",
            "verify",
            "write",
            2,
            || async {
                let obj = test_stored_object(1, b"body");
                let size = MemoryObjectStore::object_size(&obj);
                let config = MemoryObjectStoreConfig { max_bytes: size };
                let store = MemoryObjectStore::new(config);

                store.put(obj.clone()).await.unwrap();

                let used_before = store.storage_used().await;
                let result = store.put(obj.clone()).await;
                assert!(matches!(result, Err(ObjectStoreError::AlreadyExists(_))));

                let used_after = store.storage_used().await;
                assert_eq!(used_before, used_after);

                StoreLogData {
                    object_id: Some(obj.object_id),
                    object_size: Some(obj.body.len() as u64),
                    details: Some(json!({
                        "used_bytes": used_after,
                        "duplicate_insert": "already_exists"
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn set_retention() {
        run_store_test("set_retention", "verify", "retention", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;

            store.put(obj).await.unwrap();

            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(meta.retention, RetentionClass::Ephemeral));

            store
                .set_retention(&id, RetentionClass::Pinned)
                .await
                .unwrap();

            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(meta.retention, RetentionClass::Pinned));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"retention": "Pinned"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone() {
        run_store_test("list_zone", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            store.put(test_stored_object(1, b"a")).await.unwrap();
            store.put(test_stored_object(2, b"b")).await.unwrap();
            store.put(test_stored_object(3, b"c")).await.unwrap();

            let ids = store.list_zone(&test_zone()).await;
            assert_eq!(ids.len(), 3);

            StoreLogData {
                details: Some(json!({"zone_id": test_zone().to_string(), "count": ids.len()})),
                ..StoreLogData::default()
            }
        });
    }

    // --- Additional object store tests ---

    #[test]
    fn get_header_success() {
        run_store_test("get_header_success", "verify", "read", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;
            let zone = obj.header.zone_id.clone();

            store.put(obj).await.unwrap();

            let header = store.get_header(&id).await.unwrap();
            assert_eq!(header.zone_id, zone);
            assert!(header.refs.is_empty());

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"header_zone": zone.to_string()})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_header_not_found() {
        run_store_test("get_header_not_found", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let id = ObjectId::from_bytes([77; 32]);

            let result = store.get_header(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"error": "not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_storage_meta_success() {
        run_store_test("get_storage_meta_success", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;

            store.put(obj).await.unwrap();

            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(meta.retention, RetentionClass::Ephemeral));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"retention": "Ephemeral"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_storage_meta_not_found() {
        run_store_test(
            "get_storage_meta_not_found",
            "verify",
            "read",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let id = ObjectId::from_bytes([88; 32]);

                let result = store.get_storage_meta(&id).await;
                assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"error": "not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn set_retention_not_found() {
        run_store_test(
            "set_retention_not_found",
            "verify",
            "retention",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let id = ObjectId::from_bytes([99; 32]);

                let result = store.set_retention(&id, RetentionClass::Pinned).await;
                assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"error": "not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_not_found() {
        run_store_test("delete_not_found", "verify", "delete", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let id = ObjectId::from_bytes([55; 32]);

            let result = store.delete(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"error": "not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone_empty() {
        run_store_test("list_zone_empty", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            let ids = store.list_zone(&test_zone()).await;
            assert!(ids.is_empty());

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone_filters_by_zone() {
        run_store_test("list_zone_filters_by_zone", "verify", "list", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            // Objects in z:test
            store.put(test_stored_object(1, b"a")).await.unwrap();
            store.put(test_stored_object(2, b"b")).await.unwrap();

            // Object in different zone
            let mut other_zone_obj = test_stored_object(3, b"c");
            other_zone_obj.header.zone_id = "z:other".parse().unwrap();
            store.put(other_zone_obj).await.unwrap();

            let test_ids = store.list_zone(&test_zone()).await;
            assert_eq!(test_ids.len(), 2);

            let other_ids = store.list_zone(&"z:other".parse().unwrap()).await;
            assert_eq!(other_ids.len(), 1);

            StoreLogData {
                details: Some(json!({"test_count": 2, "other_count": 1})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn storage_quota_returns_config_value() {
        run_store_test(
            "storage_quota_returns_config",
            "verify",
            "accounting",
            1,
            || async {
                let config = MemoryObjectStoreConfig { max_bytes: 42_000 };
                let store = MemoryObjectStore::new(config);

                assert_eq!(store.storage_quota().await, 42_000);

                StoreLogData {
                    details: Some(json!({"quota": 42_000})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn exists_returns_false_for_unknown() {
        run_store_test("exists_false_unknown", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let id = ObjectId::from_bytes([42; 32]);

            assert!(!store.exists(&id).await);

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"exists": false})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn set_retention_to_lease() {
        run_store_test(
            "set_retention_to_lease",
            "verify",
            "retention",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let obj = test_stored_object(1, b"body");
                let id = obj.object_id;

                store.put(obj).await.unwrap();

                store
                    .set_retention(&id, RetentionClass::Lease { expires_at: 5000 })
                    .await
                    .unwrap();

                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(matches!(
                    meta.retention,
                    RetentionClass::Lease { expires_at: 5000 }
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"retention": "Lease", "expires_at": 5000})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn config_default_values() {
        run_store_test("config_default_values", "verify", "config", 1, || async {
            let config = MemoryObjectStoreConfig::default();
            assert_eq!(config.max_bytes, 256 * 1024 * 1024);

            StoreLogData {
                details: Some(json!({"max_bytes": config.max_bytes})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn config_clone() {
        let config = MemoryObjectStoreConfig { max_bytes: 999 };
        let cloned = config.clone();
        assert_eq!(cloned.max_bytes, config.max_bytes);
    }

    #[test]
    fn config_debug() {
        let config = MemoryObjectStoreConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("MemoryObjectStoreConfig"));
    }

    #[test]
    fn storage_used_accumulates() {
        run_store_test(
            "storage_used_accumulates",
            "verify",
            "accounting",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

                let obj1 = test_stored_object(1, b"aaaa");
                let obj2 = test_stored_object(2, b"bbbb");

                store.put(obj1).await.unwrap();
                let used1 = store.storage_used().await;

                store.put(obj2).await.unwrap();
                let used2 = store.storage_used().await;

                assert!(used2 > used1);
                assert_eq!(used2, used1 * 2); // Same size objects

                StoreLogData {
                    details: Some(json!({"used1": used1, "used2": used2})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_after_delete_returns_not_found() {
        run_store_test("get_after_delete", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"data");
            let id = obj.object_id;

            store.put(obj).await.unwrap();
            store.delete(&id).await.unwrap();

            let result = store.get(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"get_after_delete": "not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn set_retention_from_pinned_to_ephemeral() {
        run_store_test(
            "retention_pinned_to_ephemeral",
            "verify",
            "retention",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let obj = test_stored_object(1, b"body");
                let id = obj.object_id;

                store.put(obj).await.unwrap();
                store
                    .set_retention(&id, RetentionClass::Pinned)
                    .await
                    .unwrap();

                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(matches!(meta.retention, RetentionClass::Pinned));

                store
                    .set_retention(&id, RetentionClass::Ephemeral)
                    .await
                    .unwrap();
                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(matches!(meta.retention, RetentionClass::Ephemeral));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"pinned_to_ephemeral": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn list_zone_non_matching_empty() {
        run_store_test("list_zone_non_matching", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            store.put(test_stored_object(1, b"a")).await.unwrap();

            let other_zone: ZoneId = "z:other".parse().unwrap();
            let ids = store.list_zone(&other_zone).await;
            assert!(ids.is_empty());

            StoreLogData {
                details: Some(json!({"non_matching": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn multiple_put_delete_storage_returns_zero() {
        run_store_test("put_delete_cycles", "verify", "accounting", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            for i in 1..=5 {
                let obj = test_stored_object(i, &[0_u8; 100]);
                store.put(obj).await.unwrap();
            }
            for i in 1..=5 {
                store.delete(&ObjectId::from_bytes([i; 32])).await.unwrap();
            }

            assert_eq!(store.storage_used().await, 0);

            StoreLogData {
                details: Some(json!({"cycles": 5, "final_used": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quota_exact_boundary() {
        run_store_test("quota_exact_boundary", "verify", "write", 2, || async {
            // Post-br-fm746: object_size is the canonical header size +
            // body length. Size the quota dynamically to the first
            // object's actual cost so the boundary check remains tight
            // regardless of how the canonical CBOR encoding evolves.
            let obj = test_stored_object(1, &vec![0_u8; 488]);
            let exact = MemoryObjectStore::object_size(&obj);
            let config = MemoryObjectStoreConfig { max_bytes: exact };
            let store = MemoryObjectStore::new(config);

            store.put(obj).await.unwrap(); // Exactly at quota

            // Second object should fail
            let obj2 = test_stored_object(2, b"x");
            let result = store.put(obj2).await;
            assert!(matches!(
                result,
                Err(ObjectStoreError::QuotaExceeded { .. })
            ));

            StoreLogData {
                details: Some(json!({"boundary": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_frees_storage() {
        run_store_test(
            "delete_frees_storage",
            "verify",
            "accounting",
            3,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

                let obj = test_stored_object(1, b"some body data here");
                let id = obj.object_id;

                store.put(obj).await.unwrap();
                let used_after_put = store.storage_used().await;
                assert!(used_after_put > 0);

                store.delete(&id).await.unwrap();
                let used_after_delete = store.storage_used().await;
                assert_eq!(used_after_delete, 0);

                // Can re-add after delete
                let obj2 = test_stored_object(1, b"new body");
                store.put(obj2).await.unwrap();

                StoreLogData {
                    object_id: Some(id),
                    details: Some(
                        json!({"used_after_put": used_after_put, "used_after_delete": used_after_delete}),
                    ),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn storage_accounting() {
        run_store_test("storage_accounting", "verify", "accounting", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            assert_eq!(store.storage_used().await, 0);

            let obj = test_stored_object(1, b"test body content");
            let id = obj.object_id;
            store.put(obj).await.unwrap();

            let used = store.storage_used().await;
            assert!(used > 0);

            store.delete(&id).await.unwrap();
            assert_eq!(store.storage_used().await, 0);

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"used_bytes": used})),
                ..StoreLogData::default()
            }
        });
    }

    // --- MemoryObjectStoreConfig tests ---

    #[test]
    fn memory_object_store_config_default_value() {
        let config = MemoryObjectStoreConfig::default();
        assert_eq!(config.max_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn memory_object_store_config_debug_format() {
        let config = MemoryObjectStoreConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("MemoryObjectStoreConfig"));
        assert!(dbg.contains("max_bytes"));
    }

    #[test]
    fn memory_object_store_config_clone_preserves() {
        let config = MemoryObjectStoreConfig { max_bytes: 42 };
        let cloned = config.clone();
        assert_eq!(config.max_bytes, cloned.max_bytes);
    }

    // --- Multiple object lifecycle tests ---

    #[test]
    fn put_multiple_get_each() {
        run_store_test("put_multiple_get_each", "verify", "read", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            store.put(test_stored_object(1, b"aaa")).await.unwrap();
            store.put(test_stored_object(2, b"bbb")).await.unwrap();
            store.put(test_stored_object(3, b"ccc")).await.unwrap();

            let a = store.get(&ObjectId::from_bytes([1; 32])).await.unwrap();
            assert_eq!(a.body, b"aaa");
            let b = store.get(&ObjectId::from_bytes([2; 32])).await.unwrap();
            assert_eq!(b.body, b"bbb");
            let c = store.get(&ObjectId::from_bytes([3; 32])).await.unwrap();
            assert_eq!(c.body, b"ccc");

            StoreLogData {
                details: Some(json!({"count": 3})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_then_get_returns_not_found() {
        run_store_test("delete_then_get", "verify", "delete", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            store.delete(&id).await.unwrap();

            let result = store.get(&id).await;
            assert!(matches!(result, Err(ObjectStoreError::NotFound(_))));

            StoreLogData {
                object_id: Some(id),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn storage_used_increases_with_puts() {
        run_store_test(
            "storage_used_accumulates",
            "verify",
            "accounting",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

                store.put(test_stored_object(1, b"aaaa")).await.unwrap();
                let used1 = store.storage_used().await;

                store.put(test_stored_object(2, b"bbbb")).await.unwrap();
                let used2 = store.storage_used().await;

                assert!(used2 > used1);
                assert!(used1 > 0);

                StoreLogData {
                    details: Some(json!({"used1": used1, "used2": used2})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn exists_returns_true_after_put() {
        run_store_test("exists_true_after_put", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            assert!(store.exists(&id).await);

            StoreLogData {
                object_id: Some(id),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn set_retention_ephemeral_to_pinned_to_lease() {
        run_store_test("retention_cycle", "verify", "retention", 3, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            let id = obj.object_id;
            store.put(obj).await.unwrap();

            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(meta.retention, RetentionClass::Ephemeral));

            store
                .set_retention(&id, RetentionClass::Pinned)
                .await
                .unwrap();
            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(meta.retention, RetentionClass::Pinned));

            store
                .set_retention(&id, RetentionClass::Lease { expires_at: 9999 })
                .await
                .unwrap();
            let meta = store.get_storage_meta(&id).await.unwrap();
            assert!(matches!(
                meta.retention,
                RetentionClass::Lease { expires_at: 9999 }
            ));

            StoreLogData {
                object_id: Some(id),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone_no_other_zone() {
        run_store_test("list_zone_no_other", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            store.put(test_stored_object(1, b"a")).await.unwrap();

            let ids = store.list_zone(&"z:nonexistent".parse().unwrap()).await;
            assert!(ids.is_empty());

            StoreLogData::default()
        });
    }

    #[test]
    fn quota_boundary_exact_fit() {
        run_store_test("quota_boundary_exact", "verify", "write", 1, || async {
            // Post-br-fm746: object_size is the canonical header size +
            // body length. Fit the quota to the object's actual cost so
            // the boundary test remains encoder-agnostic.
            let obj = test_stored_object(1, b"");
            let exact = MemoryObjectStore::object_size(&obj);
            let config = MemoryObjectStoreConfig { max_bytes: exact };
            let store = MemoryObjectStore::new(config);
            let result = store.put(obj).await;
            assert!(result.is_ok());

            StoreLogData::default()
        });
    }

    #[test]
    fn quota_boundary_one_byte_short() {
        run_store_test("quota_boundary_short", "verify", "write", 1, || async {
            // See quota_boundary_exact_fit: one byte below the object's
            // actual canonical-size cost must reject.
            let obj = test_stored_object(1, b"");
            let exact = MemoryObjectStore::object_size(&obj);
            let config = MemoryObjectStoreConfig {
                max_bytes: exact - 1,
            };
            let store = MemoryObjectStore::new(config);
            let result = store.put(obj).await;
            assert!(matches!(
                result,
                Err(ObjectStoreError::QuotaExceeded { .. })
            ));

            StoreLogData::default()
        });
    }

    #[test]
    fn get_header_zone_matches() {
        run_store_test("get_header_zone_matches", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(5, b"hello");
            let expected_zone = obj.header.zone_id.clone();
            store.put(obj).await.unwrap();

            let hdr = store
                .get_header(&ObjectId::from_bytes([5; 32]))
                .await
                .unwrap();
            assert_eq!(hdr.zone_id, expected_zone);

            StoreLogData::default()
        });
    }

    // --- Additional MemoryObjectStore edge case tests ---

    #[test]
    fn empty_body_object_stored_and_retrieved() {
        run_store_test("empty_body_object", "verify", "write", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"");
            let id = obj.object_id;
            store.put(obj).await.unwrap();

            let retrieved = store.get(&id).await.unwrap();
            assert!(retrieved.body.is_empty());
            assert!(store.exists(&id).await);

            StoreLogData::default()
        });
    }

    #[test]
    fn large_body_object_stored() {
        run_store_test("large_body_object", "verify", "write", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig {
                max_bytes: 10 * 1024 * 1024,
            });
            let body = vec![0xAB_u8; 8192];
            let obj = test_stored_object(1, &body);
            let id = obj.object_id;
            store.put(obj).await.unwrap();

            let retrieved = store.get(&id).await.unwrap();
            assert_eq!(retrieved.body.len(), 8192);

            StoreLogData::default()
        });
    }

    #[test]
    fn storage_used_zero_after_construction() {
        run_store_test(
            "storage_used_zero_init",
            "verify",
            "accounting",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                assert_eq!(store.storage_used().await, 0);
                StoreLogData::default()
            },
        );
    }

    #[test]
    fn delete_then_reinsert_same_id() {
        run_store_test("delete_then_reinsert", "verify", "write", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"original");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            store.delete(&id).await.unwrap();

            let obj2 = test_stored_object(1, b"replaced");
            store.put(obj2).await.unwrap();
            let retrieved = store.get(&id).await.unwrap();
            assert_eq!(retrieved.body, b"replaced");

            StoreLogData::default()
        });
    }

    #[test]
    fn exists_false_after_delete() {
        run_store_test("exists_false_after_delete", "verify", "read", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"data");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            assert!(store.exists(&id).await);
            store.delete(&id).await.unwrap();
            assert!(!store.exists(&id).await);

            StoreLogData::default()
        });
    }

    #[test]
    fn list_zone_after_delete() {
        run_store_test("list_zone_after_delete", "verify", "list", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            store.put(test_stored_object(1, b"a")).await.unwrap();
            store.put(test_stored_object(2, b"b")).await.unwrap();
            store.delete(&ObjectId::from_bytes([1; 32])).await.unwrap();

            let ids = store.list_zone(&test_zone()).await;
            assert_eq!(ids.len(), 1);

            StoreLogData::default()
        });
    }

    #[test]
    fn delete_last_object_in_zone_drops_zone_index_entry() {
        // br-A9 sweep: prior to the fix, deleting the last object in a
        // zone left the (zone_id, empty Vec) entry resident in
        // `zone_index`, so the map grew monotonically with the
        // cardinality of zones ever seen rather than currently-active
        // zones. The fix drops the entry once the Vec is empty.
        run_store_test(
            "delete_last_object_in_zone_drops_zone_index_entry",
            "verify",
            "delete",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let obj = test_stored_object(7, b"only");
                let id = obj.object_id;
                let zone = obj.header.zone_id.clone();

                store.put(obj).await.unwrap();
                assert!(
                    store.zone_index.read().contains_key(&zone),
                    "zone_index should hold the zone after first put",
                );

                store.delete(&id).await.unwrap();

                assert!(
                    !store.zone_index.read().contains_key(&zone),
                    "zone_index entry must be dropped once the zone has no objects",
                );

                // Re-inserting an object for the same zone must work
                // (regression guard against accidentally treating
                // the absent entry as "zone forever closed").
                store.put(test_stored_object(8, b"again")).await.unwrap();
                assert_eq!(store.list_zone(&zone).await.len(), 1);

                StoreLogData::default()
            },
        );
    }

    #[test]
    fn get_header_refs_empty() {
        run_store_test("get_header_refs_empty", "verify", "read", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"body");
            store.put(obj).await.unwrap();

            let hdr = store
                .get_header(&ObjectId::from_bytes([1; 32]))
                .await
                .unwrap();
            assert!(hdr.refs.is_empty());
            assert!(hdr.foreign_refs.is_empty());

            StoreLogData::default()
        });
    }

    #[test]
    fn config_custom_max_bytes() {
        let config = MemoryObjectStoreConfig { max_bytes: 42 };
        assert_eq!(config.max_bytes, 42);
    }

    #[test]
    fn storage_decreases_after_delete() {
        run_store_test("storage_decreases", "verify", "accounting", 1, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
            let obj = test_stored_object(1, b"some data");
            let id = obj.object_id;
            store.put(obj).await.unwrap();
            let used_before = store.storage_used().await;

            store.delete(&id).await.unwrap();
            let used_after = store.storage_used().await;
            assert!(used_after < used_before);

            StoreLogData::default()
        });
    }

    #[test]
    fn set_retention_lease_preserves_body() {
        run_store_test(
            "retention_preserves_body",
            "verify",
            "retention",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let obj = test_stored_object(1, b"important data");
                let id = obj.object_id;
                store.put(obj).await.unwrap();
                store
                    .set_retention(&id, RetentionClass::Lease { expires_at: 9999 })
                    .await
                    .unwrap();

                let retrieved = store.get(&id).await.unwrap();
                assert_eq!(retrieved.body, b"important data");

                StoreLogData::default()
            },
        );
    }

    // =========================================================================
    // Lease-to-lease retention update
    // =========================================================================

    #[test]
    fn set_retention_lease_to_lease_updates_expiry() {
        run_store_test(
            "retention_lease_update_expiry",
            "verify",
            "retention",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let mut obj = test_stored_object(1, b"data");
                obj.storage.retention = RetentionClass::Lease { expires_at: 1000 };
                let id = obj.object_id;
                store.put(obj).await.unwrap();

                store
                    .set_retention(&id, RetentionClass::Lease { expires_at: 5000 })
                    .await
                    .unwrap();

                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(
                    matches!(meta.retention, RetentionClass::Lease { expires_at } if expires_at == 5000)
                );

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"transition": "lease_1000_to_lease_5000"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Quota freed after delete allows new put
    // =========================================================================

    #[test]
    fn quota_freed_after_delete_allows_new_put() {
        run_store_test(
            "quota_freed_after_delete",
            "verify",
            "accounting",
            2,
            || async {
                let config = MemoryObjectStoreConfig { max_bytes: 1000 };
                let store = MemoryObjectStore::new(config);

                let obj1 = test_stored_object(1, &vec![0_u8; 488]);
                let id1 = obj1.object_id;
                store.put(obj1).await.unwrap();

                // Quota full — can't add another
                let obj2 = test_stored_object(2, &vec![0_u8; 488]);
                assert!(store.put(obj2).await.is_err());

                // Delete first, now second can fit
                store.delete(&id1).await.unwrap();
                let obj2b = test_stored_object(2, &vec![0_u8; 488]);
                store.put(obj2b).await.unwrap();
                assert!(store.exists(&ObjectId::from_bytes([2; 32])).await);

                StoreLogData {
                    details: Some(json!({"freed_and_reused": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Accumulation with mixed sizes
    // =========================================================================

    #[test]
    fn storage_used_accumulates_mixed_sizes() {
        run_store_test(
            "storage_accumulates_mixed",
            "verify",
            "accounting",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

                // Post-br-fm746: size = canonical-header bytes + body.
                // Compute each object's cost dynamically so the assertion
                // stays correct even if the canonical CBOR encoding of
                // test headers changes.
                let obj1 = test_stored_object(1, b"aaaa");
                let obj2 = test_stored_object(2, b"bb");
                let expected =
                    MemoryObjectStore::object_size(&obj1) + MemoryObjectStore::object_size(&obj2);
                store.put(obj1).await.unwrap();
                store.put(obj2).await.unwrap();

                let used = store.storage_used().await;
                assert_eq!(used, expected);

                StoreLogData {
                    details: Some(json!({"total_used": used})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Storage meta with initial pinned retention
    // =========================================================================

    #[test]
    fn get_storage_meta_returns_initial_pinned_retention() {
        run_store_test(
            "get_storage_meta_initial_pinned",
            "verify",
            "read",
            2,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let mut obj = test_stored_object(1, b"data");
                obj.storage.retention = RetentionClass::Pinned;
                let id = obj.object_id;
                store.put(obj).await.unwrap();

                let meta = store.get_storage_meta(&id).await.unwrap();
                assert!(matches!(meta.retention, RetentionClass::Pinned));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"retention": "pinned"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Header with refs
    // =========================================================================

    #[test]
    fn get_header_preserves_refs() {
        run_store_test("get_header_preserves_refs", "verify", "read", 2, || async {
            let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

            let ref_id = ObjectId::from_bytes([2; 32]);
            let mut obj = test_stored_object(1, b"data");
            obj.header.refs = vec![ref_id];
            let id = obj.object_id;
            store.put(obj).await.unwrap();

            let header = store.get_header(&id).await.unwrap();
            assert_eq!(header.refs.len(), 1);
            assert_eq!(header.refs[0], ref_id);

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"refs_count": 1})),
                ..StoreLogData::default()
            }
        });
    }

    // =========================================================================
    // Quota matches config
    // =========================================================================

    #[test]
    fn storage_quota_matches_custom_config() {
        run_store_test(
            "storage_quota_matches_custom",
            "verify",
            "accounting",
            1,
            || async {
                let config = MemoryObjectStoreConfig { max_bytes: 12345 };
                let store = MemoryObjectStore::new(config);
                assert_eq!(store.storage_quota().await, 12345);

                StoreLogData {
                    details: Some(json!({"quota": 12345})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Delete all returns zero storage
    // =========================================================================

    #[test]
    fn storage_zero_after_deleting_all_objects() {
        run_store_test(
            "storage_zero_after_delete_all",
            "verify",
            "accounting",
            1,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                store.put(test_stored_object(1, b"aaa")).await.unwrap();
                store.put(test_stored_object(2, b"bbb")).await.unwrap();

                store.delete(&ObjectId::from_bytes([1; 32])).await.unwrap();
                store.delete(&ObjectId::from_bytes([2; 32])).await.unwrap();

                assert_eq!(store.storage_used().await, 0);

                StoreLogData {
                    details: Some(json!({"all_deleted": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn snapshot_zone_lifecycle_reports_root_validity_and_reachability() {
        run_store_test(
            "snapshot_zone_lifecycle_roots",
            "verify",
            "lifecycle",
            10,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());

                let mut root = test_stored_object(1, b"root");
                root.header.refs = vec![ObjectId::from_bytes([2; 32])];
                let mut child = test_stored_object(2, b"child");
                child.header.refs = vec![ObjectId::from_bytes([3; 32])];
                let leaf = test_stored_object(3, b"leaf");
                let mut leased = test_stored_object(4, b"leased");
                leased.storage.retention = RetentionClass::Lease { expires_at: 50 };
                let foreign = test_foreign_zone_object(9, b"foreign");

                root.header.refs.sort_unstable();
                child.header.refs.sort_unstable();
                store.put(root.clone()).await.unwrap();
                store.put(child.clone()).await.unwrap();
                store.put(leaf.clone()).await.unwrap();
                store.put(leased.clone()).await.unwrap();
                store.put(foreign.clone()).await.unwrap();

                let mut roots = GcRoots::new();
                roots.set_checkpoint(root.object_id);
                roots.add_pin(ObjectId::from_bytes([8; 32]));
                roots.add_pin(foreign.object_id);

                let snapshot = snapshot_zone_lifecycle(&test_zone(), &roots, &store, None, 100)
                    .await
                    .unwrap();

                assert_eq!(snapshot.object_count, 4);
                assert_eq!(snapshot.reachable_count, 3);
                assert_eq!(snapshot.unreachable_count, 1);
                assert!(snapshot.reconstructable_count.is_none());
                assert_eq!(snapshot.roots.len(), 3);
                assert_eq!(snapshot.roots[0].object_id, root.object_id);
                assert_eq!(snapshot.roots[0].status, LifecycleRootStatus::Valid);
                assert_eq!(snapshot.roots[1].object_id, ObjectId::from_bytes([8; 32]));
                assert_eq!(snapshot.roots[1].status, LifecycleRootStatus::Missing);
                assert_eq!(snapshot.roots[2].object_id, foreign.object_id);
                assert_eq!(snapshot.roots[2].status, LifecycleRootStatus::ForeignZone);

                let leased_entry = snapshot
                    .objects
                    .iter()
                    .find(|entry| entry.object_id == leased.object_id)
                    .unwrap();
                assert!(!leased_entry.reachable_from_roots);
                assert_eq!(leased_entry.lease_state, ObjectLeaseState::Expired);

                let child_entry = snapshot
                    .objects
                    .iter()
                    .find(|entry| entry.object_id == child.object_id)
                    .unwrap();
                assert!(child_entry.reachable_from_roots);
                assert_eq!(child_entry.refs, vec![leaf.object_id]);

                StoreLogData {
                    object_id: Some(root.object_id),
                    details: Some(json!({
                        "root_statuses": snapshot.roots.iter().map(|root| {
                            json!({
                                "object_id": root.object_id.to_string(),
                                "role": root.role,
                                "status": root.status,
                            })
                        }).collect::<Vec<_>>(),
                        "reachable_count": snapshot.reachable_count,
                        "unreachable_count": snapshot.unreachable_count,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn snapshot_zone_lifecycle_includes_symbol_coverage_when_available() {
        run_store_test(
            "snapshot_zone_lifecycle_symbol_coverage",
            "verify",
            "lifecycle",
            8,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });

                let mut object = test_stored_object(6, b"symbol-backed");
                object.header.placement = Some(fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: Vec::new(),
                    excluded_devices: Vec::new(),
                    target_coverage_bps: 10_000,
                    min_source_diversity: 0,
                });
                let object_id = object.object_id;
                store.put(object).await.unwrap();

                symbol_store
                    .put_object_meta(crate::symbol_store::ObjectSymbolMeta {
                        object_id,
                        zone_id: test_zone(),
                        oti: crate::symbol_store::ObjectTransmissionInfo {
                            transfer_length: 128,
                            symbol_size: 64,
                            source_blocks: 1,
                            sub_blocks: 1,
                            alignment: 1,
                            payload_hash: None,
                        },
                        source_symbols: 2,
                        first_symbol_at: 1,
                    })
                    .await
                    .unwrap();
                for esi in 0..2 {
                    symbol_store
                        .put_symbol(crate::symbol_store::StoredSymbol {
                            meta: SymbolMeta {
                                object_id,
                                esi,
                                zone_id: test_zone(),
                                source_node: Some(u64::from(esi) + 1),
                                stored_at: 10 + u64::from(esi),
                            },
                            data: Bytes::from(vec![u8::try_from(esi).unwrap(); 64]),
                        })
                        .await
                        .unwrap();
                }

                let snapshot = snapshot_zone_lifecycle(
                    &test_zone(),
                    &GcRoots::new(),
                    &store,
                    Some(&symbol_store),
                    10,
                )
                .await
                .unwrap();

                assert_eq!(snapshot.reconstructable_count, Some(1));
                let entry = snapshot
                    .objects
                    .iter()
                    .find(|entry| entry.object_id == object_id)
                    .unwrap();
                assert_eq!(entry.reconstructable, Some(true));
                assert_eq!(entry.meets_placement_policy, Some(true));
                assert_eq!(entry.coverage.as_ref().unwrap().coverage_bps, 10_000);

                StoreLogData {
                    object_id: Some(object_id),
                    coverage_bps: Some(entry.coverage.as_ref().unwrap().coverage_bps),
                    details: Some(json!({
                        "reconstructable": entry.reconstructable,
                        "meets_policy": entry.meets_placement_policy,
                        "reconstructable_count": snapshot.reconstructable_count,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn snapshot_zone_lifecycle_marks_missing_symbol_distribution_as_not_meeting_policy() {
        run_store_test(
            "snapshot_zone_lifecycle_missing_symbol_distribution",
            "verify",
            "lifecycle",
            5,
            || async {
                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
                let symbol_store = MemorySymbolStore::new(MemorySymbolStoreConfig {
                    max_bytes: 1024 * 1024,
                    local_node_id: 1,
                });

                let mut object = test_stored_object(7, b"policy-without-symbols");
                object.header.placement = Some(fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: Vec::new(),
                    excluded_devices: Vec::new(),
                    target_coverage_bps: 10_000,
                    min_source_diversity: 0,
                });
                let object_id = object.object_id;
                store.put(object).await.unwrap();

                let snapshot = snapshot_zone_lifecycle(
                    &test_zone(),
                    &GcRoots::new(),
                    &store,
                    Some(&symbol_store),
                    10,
                )
                .await
                .unwrap();

                assert_eq!(snapshot.reconstructable_count, Some(0));
                let entry = snapshot
                    .objects
                    .iter()
                    .find(|entry| entry.object_id == object_id)
                    .unwrap();
                assert_eq!(entry.coverage, None);
                assert_eq!(entry.reconstructable, Some(false));
                assert_eq!(entry.meets_placement_policy, Some(false));

                StoreLogData {
                    object_id: Some(object_id),
                    details: Some(json!({
                        "coverage": entry.coverage,
                        "reconstructable": entry.reconstructable,
                        "meets_policy": entry.meets_placement_policy,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    /// Regression for br-fm746: a header-heavy object (tiny body, huge
    /// `refs` list) MUST have its canonical header cost counted against
    /// the store quota. Before the fix, `MemoryObjectStore` pegged header
    /// overhead at a flat 512-byte estimate regardless of actual
    /// canonical size, so an attacker could store many `refs`-heavy
    /// objects with ~0-byte bodies and drive in-memory footprint
    /// arbitrarily high while the quota accounting still reported plenty
    /// of headroom.
    #[test]
    fn put_counts_canonical_header_in_quota() {
        run_store_test(
            "put_counts_canonical_header_in_quota",
            "verify",
            "write",
            4,
            || async {
                // 512 ObjectId refs — each is a 32-byte content hash + CBOR
                // framing bytes, so the canonical header is ~17 KB. The body
                // is empty. Under the old 512-byte estimate this would count
                // as ~512 bytes; under the fix it must count as the real
                // ~17 KB.
                let mut header_heavy = test_stored_object(1, b"");
                header_heavy.header.refs = (0..512_u32)
                    .map(|i| ObjectId::from_bytes([i as u8; 32]))
                    .collect();

                let actual_size = MemoryObjectStore::object_size(&header_heavy);
                assert!(
                    actual_size > 4_096,
                    "canonical header-heavy object must cost > 4 KiB, got {actual_size}"
                );

                // Confirm the old 512-byte estimate would have drastically
                // undercounted — this pins the attack surface.
                #[allow(clippy::cast_possible_truncation)]
                let old_estimate = header_heavy.body.len() as u64 + 512;
                assert!(
                    actual_size > old_estimate * 8,
                    "new accounting must dominate the 512-byte estimate by >=8x to \
                     meaningfully close the DoS window; actual={actual_size} old={old_estimate}"
                );

                // Quota set below the real cost must reject the object.
                let config = MemoryObjectStoreConfig {
                    max_bytes: actual_size - 1,
                };
                let store = MemoryObjectStore::new(config);
                let result = store.put(header_heavy.clone()).await;
                assert!(
                    matches!(result, Err(ObjectStoreError::QuotaExceeded { .. })),
                    "header-heavy object must be rejected when quota < canonical cost, got {result:?}"
                );

                // Quota set at exactly the real cost must accept it.
                let exact_config = MemoryObjectStoreConfig {
                    max_bytes: actual_size,
                };
                let exact_store = MemoryObjectStore::new(exact_config);
                exact_store
                    .put(header_heavy)
                    .await
                    .expect("exact-fit quota must accept the object");

                StoreLogData {
                    details: Some(json!({
                        "canonical_size": actual_size,
                        "old_estimate": old_estimate,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    /// Regression test for `flywheel_connectors-sfunf`: the quota
    /// check in `MemoryObjectStore::put` previously read
    /// `used_bytes` inside the `objects.write()` critical section but
    /// deferred the `fetch_add` commit to after `drop(objects)`.
    /// Between the drop and the `fetch_add`, a concurrent `put` could
    /// acquire `objects.write()`, re-observe the pre-commit
    /// `used_bytes` value, and pass its own quota check despite the
    /// in-flight commit. Both puts would then succeed and
    /// `used_bytes` would end up above `max_bytes`.
    ///
    /// The fix (`object_store.rs:430`) moves the `fetch_add` inside
    /// the critical section so the quota read and the commit are
    /// serialized with the `objects.write()` lock. This test spins
    /// up many concurrent `put` tasks, each attempting to insert an
    /// object large enough that only a subset can fit under the
    /// quota, then asserts the final `storage_used()` never exceeds
    /// `max_bytes` regardless of scheduling.
    #[test]
    fn put_quota_holds_under_concurrent_inserts() {
        run_store_test(
            "put_quota_holds_under_concurrent_inserts",
            "verify",
            "write",
            2,
            || async {
                use std::sync::Arc;
                // Post-br-fm746: object_size = canonical header + body.
                // Size the quota to exactly `FIT_COUNT` objects' worth
                // so the concurrent-put scheduler has no ambiguity
                // about how many inserts should succeed.
                const BODY: usize = 500;
                const FIT_COUNT: u64 = 4;
                const TASKS: usize = 16;

                let probe = test_stored_object(0, &vec![0_u8; BODY]);
                let per_object = MemoryObjectStore::object_size(&probe);
                let max_bytes = per_object * FIT_COUNT; // exactly FIT_COUNT fit

                let config = MemoryObjectStoreConfig { max_bytes };
                let store = Arc::new(MemoryObjectStore::new(config));

                let mut handles = Vec::with_capacity(TASKS);
                for i in 0..TASKS {
                    let store = Arc::clone(&store);
                    // Each task targets a distinct object_id so the
                    // duplicate-key branch never short-circuits the
                    // quota path.
                    let obj = test_stored_object(i as u8 + 1, &vec![0_u8; BODY]);
                    handles.push(fcp_async_core::task::spawn(
                        async move { store.put(obj).await },
                    ));
                }

                let mut accepted = 0_u32;
                let mut rejected = 0_u32;
                for handle in handles {
                    let put_result: Result<(), ObjectStoreError> =
                        handle.await.expect("task did not panic or abort");
                    match put_result {
                        Ok(()) => accepted += 1,
                        Err(ObjectStoreError::QuotaExceeded { .. }) => rejected += 1,
                        Err(other) => panic!("unexpected error from put: {other:?}"),
                    }
                }

                let used_after = store.storage_used().await;
                assert!(
                    used_after <= max_bytes,
                    "quota violated under concurrent puts: used={used_after} max={max_bytes} accepted={accepted} rejected={rejected}"
                );
                assert_eq!(
                    accepted + rejected,
                    TASKS as u32,
                    "every task should resolve to either accept or quota-exceeded"
                );

                StoreLogData {
                    details: Some(json!({
                        "tasks": TASKS,
                        "accepted": accepted,
                        "rejected": rejected,
                        "used_after": used_after,
                        "max_bytes": max_bytes,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    /// Regression for bead flywheel_connectors-4g0qr: when a
    /// content-id verifier is installed, `put` MUST reject a
    /// `StoredObject` whose `object_id` field does not match
    /// `derive_id(&header, &body, zone_key)`, before the forged
    /// record reaches the in-memory map. Without the verifier, the
    /// existing `validate_structure` call would let the forged id
    /// through — so the test also asserts the explicit
    /// `ContentIdMismatch` variant to lock down the detection path.
    #[test]
    fn put_with_verifier_rejects_forged_object_id() {
        run_store_test(
            "put_with_verifier_rejects_forged_object_id",
            "verify",
            "write",
            2,
            || async {
                use crate::object_id_verifier::KeyedObjectIdVerifier;
                use fcp_prelude::ObjectIdKey;

                let zone = test_zone();
                let key = ObjectIdKey::from_bytes([0x5Au8; 32]);
                let mut verifier = KeyedObjectIdVerifier::default();
                verifier.insert(zone.clone(), key);

                let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default())
                    .with_verifier(verifier.into_arc());

                // Build a canonically-shaped object with a *wrong*
                // object_id. The header + body are legitimate; only
                // the claimed id is forged.
                let mut obj = test_stored_object(7, b"forged-body");
                let forged_id = ObjectId::from_bytes([0xABu8; 32]);
                obj.object_id = forged_id;

                let err = store
                    .put(obj)
                    .await
                    .expect_err("forged object_id must be rejected at put");
                assert!(
                    matches!(err, ObjectStoreError::ContentIdMismatch { claimed, .. } if claimed == forged_id),
                    "expected ContentIdMismatch with claimed={forged_id:?}, got {err:?}"
                );

                // The forged object must NOT have landed in the map.
                // `get` surfaces `NotFound`, and `storage_used` is 0.
                let get_result = store.get(&forged_id).await;
                assert!(
                    matches!(get_result, Err(ObjectStoreError::NotFound(_))),
                    "forged id must not be retrievable; got {get_result:?}"
                );
                let used = store.storage_used().await;
                assert_eq!(used, 0, "rejected put must not advance storage_used");

                StoreLogData {
                    details: Some(json!({
                        "forged_id": forged_id.to_string(),
                        "storage_used_after_reject": used,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }
}
