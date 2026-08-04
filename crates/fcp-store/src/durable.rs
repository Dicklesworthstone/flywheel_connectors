//! Crash-safe durable object and symbol stores backed by the filesystem.
//!
//! The durability contract is:
//! - every mutating operation is appended to a checksummed WAL and `sync_all()`ed
//!   before in-memory state changes become visible;
//! - checkpoints are written to a temp file in the target directory, `sync_all()`ed,
//!   atomically renamed into place, and the containing directory is fsynced on
//!   platforms that support directory sync;
//! - startup replays only checksum-valid WAL records and truncates any torn or
//!   corrupt tail so a partial append cannot poison later recovery.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use fcp_prelude::{ObjectId, ObjectPlacementPolicy, RetentionClass, StoredObject, ZoneId};
use parking_lot::{Mutex as ParkingMutex, RwLock as ParkingRwLock};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::coverage::SymbolDistribution;
use crate::error::{ObjectStoreError, SymbolStoreError};
use crate::object_id_verifier::ObjectIdVerifier;
use crate::object_store::{MemoryObjectStoreConfig, ObjectStore};
use crate::symbol_store::{
    MemorySymbolStoreConfig, ObjectSymbolMeta, StoredSymbol, SymbolMeta, SymbolStore,
    validate_source_symbols,
};

/// Legacy unkeyed envelope version. Reads accept it only when
/// `allow_legacy_unauth = true`. Writes use V1 only when no
/// `mac_key` is installed (preserving the pre-dgbtx call sites that
/// did not yet thread a per-store secret).
const SNAPSHOT_VERSION_V1: u32 = 1;
const WAL_VERSION_V1: u32 = 1;

/// Authenticated envelope version (bead flywheel_connectors-dgbtx).
/// V2 envelopes carry a keyed BLAKE3 MAC over `(version, seq, op)`
/// (or `(version, last_seq, payload)` for snapshots) instead of a
/// plain unkeyed BLAKE3 hash. A tamperer who can rewrite the on-disk
/// WAL/snapshot file can no longer forge a Delete/SetRetention record
/// without the per-store secret.
const SNAPSHOT_VERSION_V2: u32 = 2;
const WAL_VERSION_V2: u32 = 2;

const DEFAULT_CHECKPOINT_AFTER_OPS: u64 = 64;

/// Maximum bytes the WAL recovery loop will buffer for a single record.
///
/// The serialized envelope contains a `StoredObject` whose body is a raw
/// `Vec<u8>` (capped at `fcp_cbor::MAX_CANONICAL_OBJECT_BYTES` = 64 MiB).
/// `serde_json` emits `Vec<u8>` as a JSON array of integers (~3-5×
/// inflation), so a worst-case legitimate envelope can reach ~320 MiB
/// before encoding overhead. 512 MiB leaves headroom for envelope
/// metadata and future field additions while still bounding recovery
/// memory: a torn write or adversarial single-line WAL cannot exhaust
/// memory by withholding the trailing newline.
///
/// Records exceeding this cap are treated as torn (truncated and
/// discarded), matching the existing behavior for unparseable records.
const MAX_WAL_RECORD_BYTES: usize = 512 * 1024 * 1024;

/// Maximum bytes the snapshot recovery loop will load.
///
/// Same reasoning as `MAX_WAL_RECORD_BYTES` applied to a full
/// `ObjectSnapshot` / `SymbolSnapshot` payload, scaled for the typical
/// number of objects per checkpoint. Larger snapshots are rejected with
/// a clear error rather than OOM-killing the recovery process.
const MAX_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct DurableObjectStoreConfig {
    /// Directory containing the store snapshot and WAL files.
    pub root_dir: PathBuf,
    /// Maximum durable object bytes allowed in the store.
    pub max_bytes: u64,
    /// Number of durable mutations between automatic checkpoints.
    pub checkpoint_after_ops: u64,
    /// Per-store MAC key for authenticated WAL / snapshot envelopes
    /// (bead flywheel_connectors-dgbtx). When set, every appended WAL
    /// record and every checkpointed snapshot is written with a V2
    /// envelope carrying a keyed BLAKE3 MAC (cryptographically
    /// equivalent to HMAC-SHA256) over `(version, seq, op)` or
    /// `(version, last_seq, payload)`. When absent, writes fall back
    /// to the legacy V1 unkeyed-checksum envelope (preserved so
    /// existing call sites keep working without code change).
    ///
    /// Operators should derive this key from the zone owner key —
    /// typically `HKDF(owner_key, info = b"fcp-store/durable/v2")` —
    /// so a process with file-system access cannot forge entries
    /// without also compromising the owner key.
    pub mac_key: Option<[u8; 32]>,
    /// Whether legacy V1 unkeyed envelopes are accepted on read when
    /// a `mac_key` is installed (bead flywheel_connectors-dgbtx). This
    /// is a one-shot migration knob: setting `true` lets a node load
    /// pre-dgbtx data, after which a `checkpoint()` rewrites everything
    /// as V2. Default `false` — any V1 envelope encountered with a
    /// `mac_key` set is treated as a tampering signal.
    ///
    /// When `mac_key` is `None`, this flag has no effect (all envelopes
    /// are V1 by definition).
    pub allow_legacy_unauth: bool,
}

impl DurableObjectStoreConfig {
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
            max_bytes: MemoryObjectStoreConfig::default().max_bytes,
            checkpoint_after_ops: DEFAULT_CHECKPOINT_AFTER_OPS,
            mac_key: None,
            allow_legacy_unauth: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DurableSymbolStoreConfig {
    /// Directory containing the store snapshot and WAL files.
    pub root_dir: PathBuf,
    /// Maximum durable symbol bytes allowed in the store.
    pub max_bytes: u64,
    /// Local node ID used for coverage/distribution tracking.
    pub local_node_id: u64,
    /// Number of durable mutations between automatic checkpoints.
    pub checkpoint_after_ops: u64,
    /// Per-store MAC key for authenticated WAL / snapshot envelopes.
    /// See [`DurableObjectStoreConfig::mac_key`] for the threat model
    /// and key-derivation guidance — symbol-store WAL `DeleteObject` /
    /// `DeleteSymbol` records pose the same forgery risk as object-store
    /// `Delete` / `SetRetention` and inherit the same defence.
    pub mac_key: Option<[u8; 32]>,
    /// Whether legacy V1 unkeyed envelopes are accepted on read when
    /// `mac_key` is installed. See
    /// [`DurableObjectStoreConfig::allow_legacy_unauth`].
    pub allow_legacy_unauth: bool,
}

impl DurableSymbolStoreConfig {
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        let defaults = MemorySymbolStoreConfig::default();
        Self {
            root_dir: root_dir.into(),
            max_bytes: defaults.max_bytes,
            local_node_id: defaults.local_node_id,
            checkpoint_after_ops: DEFAULT_CHECKPOINT_AFTER_OPS,
            mac_key: None,
            allow_legacy_unauth: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotEnvelope<T> {
    version: u32,
    last_seq: u64,
    checksum: [u8; 32],
    payload: T,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalEnvelope<T> {
    version: u32,
    seq: u64,
    checksum: [u8; 32],
    op: T,
}

#[derive(Debug, Default)]
struct DurableObjectState {
    objects: HashMap<ObjectId, StoredObject>,
    zone_index: HashMap<ZoneId, Vec<ObjectId>>,
    used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectSnapshot {
    objects: Vec<StoredObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ObjectWalOp {
    Put(Box<StoredObject>),
    Delete {
        object_id: ObjectId,
    },
    SetRetention {
        object_id: ObjectId,
        retention: RetentionClass,
    },
}

pub struct DurableObjectStore {
    state: Mutex<DurableObjectState>,
    config: DurableObjectStoreConfig,
    write_guard: Mutex<()>,
    next_seq: AtomicU64,
    ops_since_checkpoint: AtomicU64,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
    /// Optional content-id verifier. When set, every runtime `put`,
    /// every WAL record replayed at startup, and every snapshot entry
    /// is routed through `verifier.verify(&object)` before touching
    /// in-memory state. Closes the attacker-chosen-id injection vector
    /// documented in bead flywheel_connectors-4g0qr.
    verifier: Option<Arc<dyn ObjectIdVerifier>>,
}

#[derive(Debug, Clone)]
struct DurableObjectSymbols {
    meta: ObjectSymbolMeta,
    symbols: HashMap<u32, StoredSymbol>,
}

#[derive(Debug, Default)]
struct DurableSymbolState {
    objects: HashMap<ObjectId, DurableObjectSymbols>,
    used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentStoredSymbol {
    meta: SymbolMeta,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SymbolSnapshotEntry {
    meta: ObjectSymbolMeta,
    symbols: Vec<PersistentStoredSymbol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SymbolSnapshot {
    objects: Vec<SymbolSnapshotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum SymbolWalOp {
    PutObjectMeta(ObjectSymbolMeta),
    PutSymbol(PersistentStoredSymbol),
    DeleteObject { object_id: ObjectId },
    DeleteSymbol { object_id: ObjectId, esi: u32 },
}

pub struct DurableSymbolStore {
    state: ParkingRwLock<DurableSymbolState>,
    config: DurableSymbolStoreConfig,
    write_guard: ParkingMutex<()>,
    next_seq: AtomicU64,
    ops_since_checkpoint: AtomicU64,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
}

impl DurableObjectState {
    fn object_size(object: &StoredObject) -> u64 {
        // Keep durable quota accounting aligned with the in-memory object
        // store: charge the exact canonical object bytes rather than the old
        // body-plus-512 estimate. Header-heavy objects can otherwise bypass
        // max_bytes by putting most of their payload in refs/placement.
        const MAX_CANONICAL_FALLBACK: u64 = 64 * 1024 * 1024;

        match StoredObject::canonical_bytes(&object.header, &object.body) {
            Ok(bytes) => bytes.len() as u64,
            Err(_) => MAX_CANONICAL_FALLBACK,
        }
    }

    fn from_snapshot(
        snapshot: ObjectSnapshot,
        verifier: Option<&dyn ObjectIdVerifier>,
    ) -> Result<Self, ObjectStoreError> {
        let mut state = Self::default();
        for object in snapshot.objects {
            // Defense-in-depth: reject snapshot entries whose header is
            // not canonically encodable or whose total size exceeds
            // `MAX_CANONICAL_OBJECT_BYTES`. A snapshot file is on-disk
            // attacker-reachable (compromised host, restored backup,
            // imported from another node), so the recovery path must
            // not implicitly trust per-object structure.
            object.validate_structure().map_err(|err| {
                ObjectStoreError::Io(format!(
                    "invalid object structure in snapshot for {}: {err}",
                    object.object_id
                ))
            })?;
            // When a verifier is installed, enforce the content-id
            // binding on every snapshot entry. A forged snapshot
            // (restored-from-tampered-backup, malicious import) must
            // NOT survive load — the forged record is refused here and
            // effectively dropped from the recovered state.
            if let Some(verifier) = verifier {
                verifier.verify(&object)?;
            }

            // `insert_loaded` is the sole `used_bytes` accounting site (it is
            // also what WAL replay uses via `apply_loaded_mutation`), so it
            // already charges this object's size. Adding it here as well
            // double-counted every snapshot-recovered object, inflating
            // `used_bytes` to 2× actual on restart and silently halving the
            // store's usable quota. `DurableSymbolState::from_snapshot` counts
            // once via `load_entry`; this now matches it.
            state.insert_loaded(object);
        }
        Ok(state)
    }

    fn to_snapshot(&self) -> ObjectSnapshot {
        let mut objects: Vec<_> = self.objects.values().cloned().collect();
        objects.sort_unstable_by_key(|object| object.object_id);
        ObjectSnapshot { objects }
    }

    fn insert_loaded(&mut self, object: StoredObject) {
        let object_id = object.object_id;
        let zone_id = object.header.zone_id.clone();
        self.used_bytes = self.used_bytes.saturating_add(Self::object_size(&object));
        self.zone_index.entry(zone_id).or_default().push(object_id);
        self.objects.insert(object_id, object);
    }

    fn validate_mutation(&self, op: &ObjectWalOp, max_bytes: u64) -> Result<(), ObjectStoreError> {
        match op {
            ObjectWalOp::Put(object) => {
                // Reject malformed or oversized objects before they reach
                // either the WAL or the in-memory map. Closes the gap that
                // bead flywheel_connectors-4g0qr documented: a peer (or
                // any process with WAL write access) could previously
                // smuggle in a `Put` whose `body` exceeds
                // `MAX_CANONICAL_OBJECT_BYTES` or whose `header` is not
                // canonically encodable. Full content-ID verification
                // requires the zone's `ObjectIdKey` and is the runtime
                // caller's responsibility.
                object.validate_structure().map_err(|err| {
                    ObjectStoreError::Io(format!("invalid object structure: {err}"))
                })?;
                if self.objects.contains_key(&object.object_id) {
                    return Err(ObjectStoreError::AlreadyExists(object.object_id));
                }
                let size = Self::object_size(object);
                if self.used_bytes.saturating_add(size) > max_bytes {
                    return Err(ObjectStoreError::QuotaExceeded {
                        used: self.used_bytes,
                        max: max_bytes,
                    });
                }
                Ok(())
            }
            ObjectWalOp::Delete { object_id } | ObjectWalOp::SetRetention { object_id, .. } => {
                if self.objects.contains_key(object_id) {
                    Ok(())
                } else {
                    Err(ObjectStoreError::NotFound(*object_id))
                }
            }
        }
    }

    fn apply_loaded_mutation(&mut self, op: ObjectWalOp) -> Result<(), ObjectStoreError> {
        match op {
            ObjectWalOp::Put(object) => {
                if self.objects.contains_key(&object.object_id) {
                    return Err(ObjectStoreError::AlreadyExists(object.object_id));
                }
                self.insert_loaded(*object);
                Ok(())
            }
            ObjectWalOp::Delete { object_id } => self.delete_unchecked(&object_id),
            ObjectWalOp::SetRetention {
                object_id,
                retention,
            } => self.set_retention_unchecked(&object_id, retention),
        }
    }

    fn delete_unchecked(&mut self, object_id: &ObjectId) -> Result<(), ObjectStoreError> {
        let object = self
            .objects
            .remove(object_id)
            .ok_or(ObjectStoreError::NotFound(*object_id))?;
        let zone_id = object.header.zone_id.clone();
        self.used_bytes = self.used_bytes.saturating_sub(Self::object_size(&object));
        let remove_zone_entry = if let Some(ids) = self.zone_index.get_mut(&zone_id) {
            ids.retain(|candidate| candidate != object_id);
            ids.is_empty()
        } else {
            false
        };
        if remove_zone_entry {
            self.zone_index.remove(&zone_id);
        }
        Ok(())
    }

    fn set_retention_unchecked(
        &mut self,
        object_id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError> {
        let object = self
            .objects
            .get_mut(object_id)
            .ok_or(ObjectStoreError::NotFound(*object_id))?;
        object.storage.retention = retention;
        Ok(())
    }
}

impl DurableSymbolState {
    const fn symbol_size(symbol: &StoredSymbol) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        let size = symbol.data.len() as u64 + 64;
        size
    }

    fn has_required_symbols(symbol_count: usize, source_symbols: u32) -> bool {
        u32::try_from(symbol_count).map_or(true, |count| count >= source_symbols)
    }

    fn symbol_matches_meta(meta: &ObjectSymbolMeta, symbol: &StoredSymbol) -> bool {
        symbol.meta.object_id == meta.object_id
            && symbol.meta.zone_id == meta.zone_id
            && symbol.data.len() == usize::from(meta.oti.symbol_size)
    }

    fn scrub_corrupt_symbols_locked(object: &mut DurableObjectSymbols) -> u64 {
        let mut removed_bytes = 0_u64;
        object.symbols.retain(|_, symbol| {
            let keep = Self::symbol_matches_meta(&object.meta, symbol);
            if !keep {
                removed_bytes = removed_bytes.saturating_add(Self::symbol_size(symbol));
            }
            keep
        });
        removed_bytes
    }

    fn scrub_corrupt_symbols(&mut self) -> u64 {
        let mut removed_bytes = 0_u64;
        for object in self.objects.values_mut() {
            removed_bytes =
                removed_bytes.saturating_add(Self::scrub_corrupt_symbols_locked(object));
        }
        self.used_bytes = self.used_bytes.saturating_sub(removed_bytes);
        removed_bytes
    }

    fn scrub_object_if_present(&mut self, object_id: &ObjectId) -> bool {
        let removed_bytes = {
            let Some(object) = self.objects.get_mut(object_id) else {
                return false;
            };
            Self::scrub_corrupt_symbols_locked(object)
        };

        // Keep the scrub and quota repair inside one state-lock scope so a
        // concurrent durable write cannot validate against stale `used_bytes`
        // after a read path removes corrupt symbols.
        if removed_bytes > 0 {
            self.used_bytes = self.used_bytes.saturating_sub(removed_bytes);
        }

        true
    }

    fn from_snapshot(snapshot: SymbolSnapshot) -> Result<Self, SymbolStoreError> {
        let mut state = Self::default();
        for entry in snapshot.objects {
            validate_source_symbols(&entry.meta)?;
            state.load_entry(entry);
        }
        state.scrub_corrupt_symbols();
        Ok(state)
    }

    fn to_snapshot(&self) -> SymbolSnapshot {
        let mut objects = self
            .objects
            .values()
            .map(|object| {
                let mut symbols: Vec<_> = object
                    .symbols
                    .values()
                    .map(|symbol| PersistentStoredSymbol {
                        meta: symbol.meta.clone(),
                        data: symbol.data.to_vec(),
                    })
                    .collect();
                symbols.sort_unstable_by_key(|symbol| symbol.meta.esi);
                SymbolSnapshotEntry {
                    meta: object.meta.clone(),
                    symbols,
                }
            })
            .collect::<Vec<_>>();
        objects.sort_unstable_by_key(|entry| entry.meta.object_id);
        SymbolSnapshot { objects }
    }

    fn load_entry(&mut self, entry: SymbolSnapshotEntry) {
        let mut symbols = HashMap::with_capacity(entry.symbols.len());
        let meta = entry.meta.clone();
        for symbol in entry.symbols {
            let stored = StoredSymbol {
                meta: symbol.meta,
                data: Bytes::from(symbol.data),
            };
            self.used_bytes = self.used_bytes.saturating_add(Self::symbol_size(&stored));
            symbols.insert(stored.meta.esi, stored);
        }
        self.objects
            .insert(meta.object_id, DurableObjectSymbols { meta, symbols });
    }

    fn validate_mutation(&self, op: &SymbolWalOp, max_bytes: u64) -> Result<(), SymbolStoreError> {
        match op {
            SymbolWalOp::PutObjectMeta(meta) => {
                validate_source_symbols(meta)?;
                if let Some(object) = self.objects.get(&meta.object_id) {
                    if object.meta != *meta {
                        return Err(SymbolStoreError::InvalidSymbol {
                            reason: format!("Metadata mismatch for object {}", meta.object_id),
                        });
                    }
                }
                Ok(())
            }
            SymbolWalOp::PutSymbol(symbol) => {
                let object = self
                    .objects
                    .get(&symbol.meta.object_id)
                    .ok_or(SymbolStoreError::ObjectNotFound(symbol.meta.object_id))?;
                let expected_size = usize::from(object.meta.oti.symbol_size);
                if symbol.data.len() != expected_size {
                    return Err(SymbolStoreError::InvalidSymbol {
                        reason: format!(
                            "Symbol size mismatch: expected {}, got {}",
                            expected_size,
                            symbol.data.len()
                        ),
                    });
                }
                if symbol.meta.zone_id != object.meta.zone_id {
                    return Err(SymbolStoreError::InvalidSymbol {
                        reason: format!(
                            "Symbol zone mismatch: expected {}, got {}",
                            object.meta.zone_id, symbol.meta.zone_id
                        ),
                    });
                }
                if let Some(existing) = object.symbols.get(&symbol.meta.esi) {
                    // Idempotent when bytes match; conflicting bytes signal a
                    // crafted-symbol forgery or on-wire corruption and must be
                    // surfaced instead of silently dropped (see symbol_store.rs
                    // put_symbol for the full threat model — silent drop would
                    // let a poisoned ESI block every honest later write and
                    // permanently deny repair).
                    if existing.data.as_ref() == symbol.data.as_slice() {
                        return Ok(());
                    }
                    return Err(SymbolStoreError::InvalidSymbol {
                        reason: format!(
                            "conflicting symbol for object {} esi {}: stored bytes differ from incoming",
                            symbol.meta.object_id, symbol.meta.esi
                        ),
                    });
                }
                let stored = StoredSymbol {
                    meta: symbol.meta.clone(),
                    data: Bytes::copy_from_slice(&symbol.data),
                };
                let size = Self::symbol_size(&stored);
                if self.used_bytes.saturating_add(size) > max_bytes {
                    return Err(SymbolStoreError::QuotaExceeded {
                        used: self.used_bytes,
                        max: max_bytes,
                    });
                }
                Ok(())
            }
            SymbolWalOp::DeleteObject { object_id } => {
                if self.objects.contains_key(object_id) {
                    Ok(())
                } else {
                    Err(SymbolStoreError::ObjectNotFound(*object_id))
                }
            }
            SymbolWalOp::DeleteSymbol { object_id, esi } => {
                let object = self
                    .objects
                    .get(object_id)
                    .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
                if object.symbols.contains_key(esi) {
                    Ok(())
                } else {
                    Err(SymbolStoreError::NotFound {
                        object_id: *object_id,
                        esi: *esi,
                    })
                }
            }
        }
    }

    fn apply_loaded_mutation(&mut self, op: SymbolWalOp) -> Result<(), SymbolStoreError> {
        match op {
            SymbolWalOp::PutObjectMeta(meta) => self.apply_put_object_meta(meta),
            SymbolWalOp::PutSymbol(symbol) => self.apply_put_symbol(symbol),
            SymbolWalOp::DeleteObject { object_id } => self.apply_delete_object(&object_id),
            SymbolWalOp::DeleteSymbol { object_id, esi } => {
                self.apply_delete_symbol(&object_id, esi)
            }
        }
    }

    fn apply_put_object_meta(&mut self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError> {
        validate_source_symbols(&meta)?;
        if let Some(existing) = self.objects.get(&meta.object_id) {
            if existing.meta != meta {
                return Err(SymbolStoreError::InvalidSymbol {
                    reason: format!("Metadata mismatch for object {}", meta.object_id),
                });
            }
            return Ok(());
        }

        let object_id = meta.object_id;
        let source_symbols = meta.source_symbols;
        self.objects.insert(
            object_id,
            DurableObjectSymbols {
                meta,
                symbols: HashMap::with_capacity(source_symbols as usize),
            },
        );
        Ok(())
    }

    fn apply_put_symbol(&mut self, symbol: PersistentStoredSymbol) -> Result<(), SymbolStoreError> {
        let object = self
            .objects
            .get_mut(&symbol.meta.object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(symbol.meta.object_id))?;
        if let Some(existing) = object.symbols.get(&symbol.meta.esi) {
            // Replay path: validate_mutation rejects conflicts before WAL
            // append, so a correctly-formed WAL only contains idempotent
            // duplicates. A bytewise mismatch here implies a replay against
            // a snapshot-plus-WAL sequence that contains corrupted or
            // tampered entries; treat as InvalidSymbol rather than silently
            // masking either the stored or the replayed payload.
            if existing.data.as_ref() == symbol.data.as_slice() {
                return Ok(());
            }
            return Err(SymbolStoreError::InvalidSymbol {
                reason: format!(
                    "conflicting symbol for object {} esi {} during replay",
                    symbol.meta.object_id, symbol.meta.esi
                ),
            });
        }
        let stored = StoredSymbol {
            meta: symbol.meta,
            data: Bytes::from(symbol.data),
        };
        self.used_bytes = self.used_bytes.saturating_add(Self::symbol_size(&stored));
        object.symbols.insert(stored.meta.esi, stored);
        Ok(())
    }

    fn apply_delete_object(&mut self, object_id: &ObjectId) -> Result<(), SymbolStoreError> {
        let object = self
            .objects
            .remove(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
        let total_size: u64 = object.symbols.values().map(Self::symbol_size).sum();
        self.used_bytes = self.used_bytes.saturating_sub(total_size);
        Ok(())
    }

    fn apply_delete_symbol(
        &mut self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<(), SymbolStoreError> {
        let object = self
            .objects
            .get_mut(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
        // Tolerate "symbol already absent": after `record_mutation`'s
        // read-locked validate, a concurrent reader can take the write
        // lock and run `scrub_object_if_present`, which removes any
        // size-mismatched (corrupt) symbol. If `esi` was that symbol,
        // the WAL entry is already on disk and apply must converge on
        // the requested post-condition (esi absent) instead of
        // returning NotFound. Public delete_symbol still surfaces
        // NotFound for symbols that never existed because validate
        // runs before WAL append. The same tolerance keeps WAL replay
        // robust against snapshots that already had the corrupt
        // symbol scrubbed at load time.
        if let Some(symbol) = object.symbols.remove(&esi) {
            self.used_bytes = self.used_bytes.saturating_sub(Self::symbol_size(&symbol));
        }
        Ok(())
    }
}

impl DurableObjectStore {
    /// Open or create a crash-safe durable object store.
    ///
    /// # Errors
    /// Returns an error if the snapshot/WAL cannot be read or synced.
    pub fn open(config: DurableObjectStoreConfig) -> Result<Self, ObjectStoreError> {
        Self::open_with_verifier(config, None)
    }

    /// Open the durable store with an installed content-id verifier.
    ///
    /// The verifier is applied to every snapshot entry and every WAL
    /// record during replay, and to every runtime `put` thereafter.
    /// Any `StoredObject` whose claimed `object_id` does not match
    /// `derive_id(&header, &body, zone_key)` is rejected at the
    /// boundary — before it reaches the in-memory map. This is the
    /// concrete defense against the attacker-chosen-id injection
    /// vector from bead flywheel_connectors-4g0qr, where a process
    /// with WAL write access could previously inject a forged record
    /// that `apply_loaded_mutation` accepted without verification.
    ///
    /// Pass `None` to preserve the legacy "structural checks only"
    /// behaviour (equivalent to calling [`Self::open`]).
    ///
    /// # Errors
    /// Returns an error if the snapshot/WAL cannot be read or synced,
    /// or if any replayed record fails verification.
    pub fn open_with_verifier(
        config: DurableObjectStoreConfig,
        verifier: Option<Arc<dyn ObjectIdVerifier>>,
    ) -> Result<Self, ObjectStoreError> {
        fs::create_dir_all(&config.root_dir).map_err(object_io)?;
        sync_parent_dir(&config.root_dir).map_err(object_io)?;

        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let wal_path = config.root_dir.join("objects.wal.jsonl");
        let (state, last_seq) = load_durable_object_state(
            &snapshot_path,
            &wal_path,
            verifier.as_deref(),
            config.mac_key.as_ref(),
            config.allow_legacy_unauth,
        )?;

        Ok(Self {
            state: Mutex::new(state),
            config,
            write_guard: Mutex::new(()),
            next_seq: AtomicU64::new(last_seq.saturating_add(1)),
            ops_since_checkpoint: AtomicU64::new(0),
            snapshot_path,
            wal_path,
            verifier,
        })
    }

    /// Force an immediate checkpoint and WAL compaction.
    ///
    /// # Errors
    /// Returns an error if the snapshot cannot be durably written.
    pub async fn checkpoint(&self) -> Result<(), ObjectStoreError> {
        let _guard = self.write_guard.lock().await;
        let last_seq = self.next_seq.load(Ordering::SeqCst).saturating_sub(1);
        self.checkpoint_locked(last_seq).await?;
        self.ops_since_checkpoint.store(0, Ordering::SeqCst);
        Ok(())
    }

    async fn checkpoint_locked(&self, last_seq: u64) -> Result<(), ObjectStoreError> {
        let snapshot = self.state.lock().await.to_snapshot();
        write_snapshot_blocking(
            self.snapshot_path.clone(),
            last_seq,
            snapshot,
            self.config.mac_key,
        )
        .await
        .map_err(object_io_durable)?;
        clear_wal_blocking(self.wal_path.clone())
            .await
            .map_err(object_io_durable)?;
        Ok(())
    }

    async fn record_mutation(&self, op: ObjectWalOp) -> Result<(), ObjectStoreError> {
        let _guard = self.write_guard.lock().await;
        {
            // When a verifier is installed, enforce the content-id
            // binding at the runtime write boundary BEFORE structural
            // or duplicate-id checks. A forged `object_id` from an
            // in-process caller must surface as `ContentIdMismatch`,
            // not as `AlreadyExists` when the id happens to collide
            // with a legit record (flywheel_connectors-4g0qr).
            if let (Some(verifier), ObjectWalOp::Put(object)) = (self.verifier.as_ref(), &op) {
                verifier.verify(object)?;
            }
            self.state
                .lock()
                .await
                .validate_mutation(&op, self.config.max_bytes)?;
            // Reserve the seq but do not publish until the WAL append succeeds.
            // Advancing next_seq on a failed append leaves an irrecoverable gap
            // in the WAL sequence (load_wal_records rejects the gap at startup).
            let seq = self.next_seq.load(Ordering::SeqCst);
            append_wal_record_blocking(self.wal_path.clone(), seq, op.clone(), self.config.mac_key)
                .await
                .map_err(object_io_durable)?;
            self.next_seq.store(seq.saturating_add(1), Ordering::SeqCst);
            self.state.lock().await.apply_loaded_mutation(op)?;

            if self.config.checkpoint_after_ops > 0 {
                let ops = self.ops_since_checkpoint.fetch_add(1, Ordering::SeqCst) + 1;
                if ops >= self.config.checkpoint_after_ops {
                    if let Err(error) = self.checkpoint_locked(seq).await {
                        tracing::warn!(error = %error, "durable object checkpoint failed after WAL sync");
                    } else {
                        self.ops_since_checkpoint.store(0, Ordering::SeqCst);
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ObjectStore for DurableObjectStore {
    fn has_object_id_verifier(&self) -> bool {
        self.verifier.is_some()
    }

    async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError> {
        self.record_mutation(ObjectWalOp::Put(Box::new(object)))
            .await
    }

    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
        self.state
            .lock()
            .await
            .objects
            .get(id)
            .cloned()
            .ok_or(ObjectStoreError::NotFound(*id))
    }

    async fn exists(&self, id: &ObjectId) -> bool {
        self.state.lock().await.objects.contains_key(id)
    }

    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
        self.record_mutation(ObjectWalOp::Delete { object_id: *id })
            .await
    }

    async fn get_header(&self, id: &ObjectId) -> Result<fcp_core::ObjectHeader, ObjectStoreError> {
        self.state
            .lock()
            .await
            .objects
            .get(id)
            .map(|object| object.header.clone())
            .ok_or(ObjectStoreError::NotFound(*id))
    }

    async fn get_storage_meta(
        &self,
        id: &ObjectId,
    ) -> Result<fcp_core::StorageMeta, ObjectStoreError> {
        self.state
            .lock()
            .await
            .objects
            .get(id)
            .map(|object| object.storage.clone())
            .ok_or(ObjectStoreError::NotFound(*id))
    }

    async fn set_retention(
        &self,
        id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError> {
        self.record_mutation(ObjectWalOp::SetRetention {
            object_id: *id,
            retention,
        })
        .await
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.state
            .lock()
            .await
            .zone_index
            .get(zone_id)
            .cloned()
            .unwrap_or_default()
    }

    async fn storage_used(&self) -> u64 {
        self.state.lock().await.used_bytes
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }
}

impl DurableSymbolStore {
    /// Open or create a crash-safe durable symbol store.
    ///
    /// # Errors
    /// Returns an error if the snapshot/WAL cannot be read or synced.
    pub fn open(config: DurableSymbolStoreConfig) -> Result<Self, SymbolStoreError> {
        fs::create_dir_all(&config.root_dir).map_err(symbol_io)?;
        sync_parent_dir(&config.root_dir).map_err(symbol_io)?;

        let snapshot_path = config.root_dir.join("symbols.snapshot.json");
        let wal_path = config.root_dir.join("symbols.wal.jsonl");
        let (state, last_seq) = load_durable_symbol_state(
            &snapshot_path,
            &wal_path,
            config.mac_key.as_ref(),
            config.allow_legacy_unauth,
        )?;

        Ok(Self {
            state: ParkingRwLock::new(state),
            config,
            write_guard: ParkingMutex::new(()),
            next_seq: AtomicU64::new(last_seq.saturating_add(1)),
            ops_since_checkpoint: AtomicU64::new(0),
            snapshot_path,
            wal_path,
        })
    }

    /// Force an immediate checkpoint and WAL compaction.
    ///
    /// # Errors
    /// Returns an error if the snapshot cannot be durably written.
    pub fn checkpoint(&self) -> Result<(), SymbolStoreError> {
        let _guard = self.write_guard.lock();
        let last_seq = self.next_seq.load(Ordering::SeqCst).saturating_sub(1);
        self.checkpoint_locked(last_seq)?;
        self.ops_since_checkpoint.store(0, Ordering::SeqCst);
        Ok(())
    }

    fn checkpoint_locked(&self, last_seq: u64) -> Result<(), SymbolStoreError> {
        let snapshot = self.state.read().to_snapshot();
        write_snapshot(
            &self.snapshot_path,
            last_seq,
            &snapshot,
            self.config.mac_key.as_ref(),
        )
        .map_err(symbol_io_durable)?;
        clear_wal(&self.wal_path).map_err(symbol_io)?;
        Ok(())
    }

    fn record_mutation(&self, op: SymbolWalOp) -> Result<(), SymbolStoreError> {
        let _guard = self.write_guard.lock();
        {
            let state = self.state.read();
            state.validate_mutation(&op, self.config.max_bytes)?;
        }

        {
            // Reserve the seq but do not publish until the WAL append succeeds.
            // Advancing next_seq on a failed append leaves an irrecoverable gap
            // in the WAL sequence (load_wal_records rejects the gap at startup).
            let seq = self.next_seq.load(Ordering::SeqCst);
            append_wal_record(&self.wal_path, seq, &op, self.config.mac_key.as_ref())
                .map_err(symbol_io_durable)?;
            self.next_seq.store(seq.saturating_add(1), Ordering::SeqCst);

            let mut state = self.state.write();
            state.apply_loaded_mutation(op)?;
            drop(state);

            if self.config.checkpoint_after_ops > 0 {
                let ops = self.ops_since_checkpoint.fetch_add(1, Ordering::SeqCst) + 1;
                if ops >= self.config.checkpoint_after_ops {
                    if let Err(error) = self.checkpoint_locked(seq) {
                        tracing::warn!(error = %error, "durable symbol checkpoint failed after WAL sync");
                    } else {
                        self.ops_since_checkpoint.store(0, Ordering::SeqCst);
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SymbolStore for DurableSymbolStore {
    async fn put_symbol(&self, symbol: StoredSymbol) -> Result<(), SymbolStoreError> {
        self.record_mutation(SymbolWalOp::PutSymbol(PersistentStoredSymbol {
            meta: symbol.meta,
            data: symbol.data.to_vec(),
        }))
    }

    async fn put_object_meta(&self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError> {
        self.record_mutation(SymbolWalOp::PutObjectMeta(meta))
    }

    async fn get_symbol(
        &self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<StoredSymbol, SymbolStoreError> {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return Err(SymbolStoreError::ObjectNotFound(*object_id));
        }
        let symbol = state
            .objects
            .get(object_id)
            .and_then(|object| object.symbols.get(&esi))
            .cloned();
        drop(state);

        symbol.ok_or(SymbolStoreError::NotFound {
            object_id: *object_id,
            esi,
        })
    }

    async fn get_object_meta(
        &self,
        object_id: &ObjectId,
    ) -> Result<ObjectSymbolMeta, SymbolStoreError> {
        self.state
            .read()
            .objects
            .get(object_id)
            .map(|object| object.meta.clone())
            .ok_or_else(|| SymbolStoreError::ObjectNotFound(*object_id))
    }

    async fn get_all_symbols(&self, object_id: &ObjectId) -> Vec<StoredSymbol> {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return Vec::new();
        }
        let mut symbols: Vec<_> = state
            .objects
            .get(object_id)
            .map(|object| object.symbols.values().cloned().collect())
            .unwrap_or_default();
        drop(state);

        symbols.sort_unstable_by_key(|symbol| symbol.meta.esi);
        symbols
    }

    async fn symbol_count(&self, object_id: &ObjectId) -> u32 {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return 0;
        }
        let count = state.objects.get(object_id).map_or(0, |object| {
            u32::try_from(object.symbols.len()).unwrap_or(u32::MAX)
        });
        drop(state);

        count
    }

    async fn delete_object(&self, object_id: &ObjectId) -> Result<(), SymbolStoreError> {
        self.record_mutation(SymbolWalOp::DeleteObject {
            object_id: *object_id,
        })
    }

    async fn delete_symbol(&self, object_id: &ObjectId, esi: u32) -> Result<(), SymbolStoreError> {
        self.record_mutation(SymbolWalOp::DeleteSymbol {
            object_id: *object_id,
            esi,
        })
    }

    async fn get_distribution(&self, object_id: &ObjectId) -> Option<SymbolDistribution> {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return None;
        }
        let object = state.objects.get(object_id)?;

        let mut distribution = SymbolDistribution::new(object.meta.source_symbols);
        for symbol in object.symbols.values() {
            let node_id = symbol.meta.source_node.unwrap_or(self.config.local_node_id);
            #[allow(clippy::cast_possible_truncation)]
            let size = symbol.data.len() as u64;
            distribution.add_symbol(node_id, size);
        }
        drop(state);

        Some(distribution)
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.state
            .read()
            .objects
            .values()
            .filter(|object| &object.meta.zone_id == zone_id)
            .map(|object| object.meta.object_id)
            .collect()
    }

    async fn storage_used(&self) -> u64 {
        self.state.read().used_bytes
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }

    async fn can_reconstruct(&self, object_id: &ObjectId) -> bool {
        let mut state = self.state.write();
        if !state.scrub_object_if_present(object_id) {
            return false;
        }
        let Some(object) = state.objects.get(object_id) else {
            return false;
        };
        let reconstructable = DurableSymbolState::has_required_symbols(
            object.symbols.len(),
            object.meta.source_symbols,
        );
        drop(state);

        reconstructable
    }

    async fn can_reconstruct_with_policy(
        &self,
        object_id: &ObjectId,
        policy: &ObjectPlacementPolicy,
    ) -> bool {
        if let Some(distribution) = self.get_distribution(object_id).await {
            let eval =
                crate::coverage::CoverageEvaluation::from_distribution(*object_id, &distribution);
            eval.meets_diversity_for_reconstruction(policy)
        } else {
            false
        }
    }
}

fn load_durable_object_state(
    snapshot_path: &Path,
    wal_path: &Path,
    verifier: Option<&dyn ObjectIdVerifier>,
    mac_key: Option<&[u8; 32]>,
    allow_legacy_unauth: bool,
) -> Result<(DurableObjectState, u64), ObjectStoreError> {
    let (mut state, last_snapshot_seq) =
        match read_snapshot::<ObjectSnapshot>(snapshot_path, mac_key, allow_legacy_unauth)
            .map_err(object_io_durable)?
        {
            Some((snapshot, seq)) => (DurableObjectState::from_snapshot(snapshot, verifier)?, seq),
            None => (DurableObjectState::default(), 0),
        };

    let records =
        read_wal_records::<ObjectWalOp>(wal_path, last_snapshot_seq, mac_key, allow_legacy_unauth)
            .map_err(object_io_durable)?;
    let mut last_seq = last_snapshot_seq;
    for record in records {
        last_seq = record.seq;
        // Mirror the runtime mutation path: validate the record's
        // structure (size cap + canonical-CBOR-encodable header) before
        // applying. Closes the WAL replay trust gap documented in bead
        // flywheel_connectors-4g0qr — `apply_loaded_mutation` alone
        // skips the structural check that `record_mutation` enforces
        // on the live write path.
        //
        // Order matters: run the content-id verifier BEFORE
        // `validate_mutation`'s duplicate-id check. A forged record
        // that happens to reuse a legit id would otherwise surface as
        // `AlreadyExists` (a correct but weaker signal) and hide the
        // real defect — the attacker substituted `(header, body)` for
        // the claimed id. The verifier failure is the more specific,
        // more actionable diagnosis.
        if let (Some(verifier), ObjectWalOp::Put(object)) = (verifier, &record.op) {
            verifier.verify(object)?;
        }
        state.validate_mutation(&record.op, u64::MAX)?;
        state.apply_loaded_mutation(record.op)?;
    }

    Ok((state, last_seq))
}

fn load_durable_symbol_state(
    snapshot_path: &Path,
    wal_path: &Path,
    mac_key: Option<&[u8; 32]>,
    allow_legacy_unauth: bool,
) -> Result<(DurableSymbolState, u64), SymbolStoreError> {
    let (mut state, last_snapshot_seq) =
        match read_snapshot::<SymbolSnapshot>(snapshot_path, mac_key, allow_legacy_unauth)
            .map_err(symbol_io_durable)?
        {
            Some((snapshot, seq)) => (DurableSymbolState::from_snapshot(snapshot)?, seq),
            None => (DurableSymbolState::default(), 0),
        };

    let records =
        read_wal_records::<SymbolWalOp>(wal_path, last_snapshot_seq, mac_key, allow_legacy_unauth)
            .map_err(symbol_io_durable)?;
    let mut last_seq = last_snapshot_seq;
    for record in records {
        last_seq = record.seq;
        // A WAL checksum only proves the record was not torn mid-write. It
        // does not prove the symbol payload still matches the object metadata,
        // so replay must re-run semantic validation before mutating state.
        state.validate_mutation(&record.op, u64::MAX)?;
        state.apply_loaded_mutation(record.op)?;
    }

    Ok((state, last_seq))
}

/// Bounded analogue of `BufRead::read_until` for the WAL recovery loop.
///
/// Reads bytes from `reader` into `buf` until `delim` is encountered
/// OR `max_bytes` would be exceeded. Returns `(bytes_read, hit_cap)`:
/// - `(n, false)` — record terminated naturally with `delim` (or EOF
///   before `delim` for `n > 0` — caller still treats as torn via the
///   parse step, since the envelope will not deserialize)
/// - `(n, true)` — `max_bytes` was reached without seeing `delim`;
///   caller should treat the record as torn and stop scanning
/// - `(0, false)` — clean EOF, no more records
fn read_until_bounded<R: BufRead>(
    reader: &mut R,
    delim: u8,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> std::io::Result<(usize, bool)> {
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((total, false));
        }
        let available_len = available.len();
        let remaining = max_bytes.saturating_sub(total);
        if remaining == 0 {
            return Ok((total, true));
        }
        let scan_len = available_len.min(remaining);
        if let Some(pos) = available[..scan_len].iter().position(|&b| b == delim) {
            let take = pos + 1;
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            total = total.saturating_add(take);
            return Ok((total, false));
        }
        buf.extend_from_slice(&available[..scan_len]);
        reader.consume(scan_len);
        total = total.saturating_add(scan_len);
        if scan_len < available_len {
            // We exhausted the cap before the buffered window, but the
            // delimiter wasn't found in the inspected prefix. Signal cap.
            return Ok((total, true));
        }
    }
}

/// Internal IO error type for the durable WAL/snapshot layer.
///
/// Distinguishes a tampering signal (`TamperedAuditEnvelope`-shaped)
/// from a generic IO error so the surrounding store-error mappers
/// can preserve the typed `TamperedAuditEnvelope` variant
/// (bead flywheel_connectors-dgbtx).
#[derive(Debug)]
enum DurableIoError {
    Tampered { path: String, reason: String },
    Other(String),
}

impl From<String> for DurableIoError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

#[allow(clippy::needless_pass_by_value)]
fn object_io_durable(error: DurableIoError) -> ObjectStoreError {
    match error {
        DurableIoError::Tampered { path, reason } => {
            ObjectStoreError::TamperedAuditEnvelope { path, reason }
        }
        DurableIoError::Other(s) => ObjectStoreError::Io(s),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn symbol_io_durable(error: DurableIoError) -> SymbolStoreError {
    match error {
        DurableIoError::Tampered { path, reason } => {
            SymbolStoreError::TamperedAuditEnvelope { path, reason }
        }
        DurableIoError::Other(s) => SymbolStoreError::Io(s),
    }
}

fn read_snapshot<T>(
    path: &Path,
    mac_key: Option<&[u8; 32]>,
    allow_legacy_unauth: bool,
) -> Result<Option<(T, u64)>, DurableIoError>
where
    T: Serialize + DeserializeOwned,
{
    if !path.exists() {
        return Ok(None);
    }

    // Reject snapshot files larger than `MAX_SNAPSHOT_BYTES` before
    // allocating to avoid OOM on a corrupted or adversarial file.
    let metadata =
        fs::metadata(path).map_err(|error| format!("stat snapshot {}: {error}", path.display()))?;
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(DurableIoError::Other(format!(
            "snapshot {} exceeds {} bytes (got {})",
            path.display(),
            MAX_SNAPSHOT_BYTES,
            metadata.len()
        )));
    }

    let bytes =
        fs::read(path).map_err(|error| format!("read snapshot {}: {error}", path.display()))?;
    let envelope: SnapshotEnvelope<T> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse snapshot {}: {error}", path.display()))?;

    match envelope.version {
        v if v == SNAPSHOT_VERSION_V2 => {
            // V2 envelope. Authenticate via keyed MAC. A V2 envelope
            // without an installed `mac_key` cannot be verified — fail
            // closed with TamperedAuditEnvelope rather than silently
            // accept an unverifiable record.
            let Some(key) = mac_key else {
                return Err(DurableIoError::Tampered {
                    path: path.display().to_string(),
                    reason: "snapshot has V2 envelope but no mac_key configured".to_owned(),
                });
            };
            let expected = keyed_mac_json(
                key,
                &(envelope.version, envelope.last_seq, &envelope.payload),
            )
            .map_err(|error| format!("compute snapshot mac {}: {error}", path.display()))?;
            if !macs_equal(&expected, &envelope.checksum) {
                return Err(DurableIoError::Tampered {
                    path: path.display().to_string(),
                    reason: "snapshot V2 keyed MAC mismatch".to_owned(),
                });
            }
            Ok(Some((envelope.payload, envelope.last_seq)))
        }
        v if v == SNAPSHOT_VERSION_V1 => {
            // V1 unkeyed envelope. Reject when a `mac_key` is installed
            // unless `allow_legacy_unauth` is set — otherwise an
            // attacker who can write to the directory could downgrade
            // a V2 envelope to a forged V1 with a recomputed checksum.
            if mac_key.is_some() && !allow_legacy_unauth {
                return Err(DurableIoError::Tampered {
                    path: path.display().to_string(),
                    reason: "snapshot V1 unkeyed envelope present with mac_key set \
                             and allow_legacy_unauth=false"
                        .to_owned(),
                });
            }
            let expected = checksum_json(&(envelope.version, envelope.last_seq, &envelope.payload))
                .map_err(|error| format!("checksum snapshot {}: {error}", path.display()))?;
            if expected != envelope.checksum {
                return Err(DurableIoError::Tampered {
                    path: path.display().to_string(),
                    reason: "snapshot V1 checksum mismatch".to_owned(),
                });
            }
            Ok(Some((envelope.payload, envelope.last_seq)))
        }
        other => Err(DurableIoError::Other(format!(
            "unsupported snapshot version {other} for {}",
            path.display()
        ))),
    }
}

#[allow(clippy::too_many_lines)]
fn read_wal_records<T>(
    path: &Path,
    min_seq: u64,
    mac_key: Option<&[u8; 32]>,
    allow_legacy_unauth: bool,
) -> Result<Vec<WalEnvelope<T>>, DurableIoError>
where
    T: Serialize + DeserializeOwned,
{
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path).map_err(|error| format!("open wal {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut raw = Vec::new();
    let mut valid_prefix_len = 0_u64;
    let mut last_seq_in_file = 0_u64;
    let mut expected_next_seq = min_seq.saturating_add(1);
    let mut records = Vec::new();
    let mut truncated = false;

    loop {
        raw.clear();
        let (bytes_read, hit_cap) =
            read_until_bounded(&mut reader, b'\n', &mut raw, MAX_WAL_RECORD_BYTES)
                .map_err(|error| format!("read wal {}: {error}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        if hit_cap {
            // Adversarial or torn record larger than `MAX_WAL_RECORD_BYTES`
            // — treat as a truncation point so recovery cannot be made to
            // OOM by a single oversized line. The on-disk file is then
            // truncated to the prior valid prefix, mirroring the behavior
            // for unparseable records.
            truncated = true;
            break;
        }

        let Ok(envelope) = serde_json::from_slice::<WalEnvelope<T>>(&raw) else {
            truncated = true;
            break;
        };

        // Version-aware authentication. Mismatches (V1 with mac_key
        // set + legacy not allowed; V2 without mac_key; bad MAC; bad
        // checksum) are tampering signals — surface them as a typed
        // error rather than silently truncating. Truncating tampered
        // tails would let an attacker DoS later writes by cutting the
        // WAL after their own forged record.
        let auth_result: Result<(), DurableIoError> = match envelope.version {
            v if v == WAL_VERSION_V2 => match mac_key {
                Some(key) => {
                    let expected =
                        keyed_mac_json(key, &(envelope.version, envelope.seq, &envelope.op))
                            .map_err(|error| {
                                format!("compute wal mac {}: {error}", path.display())
                            })?;
                    if macs_equal(&expected, &envelope.checksum) {
                        Ok(())
                    } else {
                        Err(DurableIoError::Tampered {
                            path: path.display().to_string(),
                            reason: format!("wal V2 keyed MAC mismatch at seq {}", envelope.seq),
                        })
                    }
                }
                None => Err(DurableIoError::Tampered {
                    path: path.display().to_string(),
                    reason: format!(
                        "wal V2 envelope at seq {} but no mac_key configured",
                        envelope.seq
                    ),
                }),
            },
            v if v == WAL_VERSION_V1 => {
                if mac_key.is_some() && !allow_legacy_unauth {
                    Err(DurableIoError::Tampered {
                        path: path.display().to_string(),
                        reason: format!(
                            "wal V1 unkeyed envelope at seq {} with mac_key set \
                             and allow_legacy_unauth=false",
                            envelope.seq
                        ),
                    })
                } else {
                    let expected =
                        checksum_json(&(envelope.version, envelope.seq, &envelope.op))
                            .map_err(|error| format!("checksum wal {}: {error}", path.display()))?;
                    if expected == envelope.checksum {
                        Ok(())
                    } else {
                        // V1 mismatch is treated as a torn-tail signal
                        // (legacy behaviour) only when no mac_key is set
                        // — otherwise it is a tampering signal.
                        if mac_key.is_some() {
                            Err(DurableIoError::Tampered {
                                path: path.display().to_string(),
                                reason: format!("wal V1 checksum mismatch at seq {}", envelope.seq),
                            })
                        } else {
                            // Fall through to torn-tail truncation below.
                            truncated = true;
                            break;
                        }
                    }
                }
            }
            _ => {
                // Unknown version: torn or adversarial. Treat as
                // torn-tail under the legacy-unauth rules; under V2
                // surface as tampering.
                if mac_key.is_some() {
                    Err(DurableIoError::Tampered {
                        path: path.display().to_string(),
                        reason: format!(
                            "wal unknown envelope version {} at seq {}",
                            envelope.version, envelope.seq
                        ),
                    })
                } else {
                    truncated = true;
                    break;
                }
            }
        };
        auth_result?;

        if envelope.seq <= last_seq_in_file {
            // Out-of-order seq with valid MAC: treat as tampering when
            // V2/keyed; treat as torn-tail when V1/unkeyed. An attacker
            // replaying an old keyed record at a lower seq fails this
            // check.
            if mac_key.is_some() {
                return Err(DurableIoError::Tampered {
                    path: path.display().to_string(),
                    reason: format!(
                        "wal seq regression: {} <= last seen {}",
                        envelope.seq, last_seq_in_file
                    ),
                });
            }
            truncated = true;
            break;
        }

        last_seq_in_file = envelope.seq;
        valid_prefix_len = valid_prefix_len.saturating_add(bytes_read as u64);

        if envelope.seq > min_seq {
            if envelope.seq != expected_next_seq {
                return Err(DurableIoError::Other(format!(
                    "wal sequence gap in {}: expected {}, found {}",
                    path.display(),
                    expected_next_seq,
                    envelope.seq
                )));
            }
            records.push(envelope);
            expected_next_seq = expected_next_seq.saturating_add(1);
        }
    }

    if truncated {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|error| format!("open wal for truncation {}: {error}", path.display()))?;
        file.set_len(valid_prefix_len)
            .map_err(|error| format!("truncate wal {}: {error}", path.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync truncated wal {}: {error}", path.display()))?;
        sync_parent_dir(path)
            .map_err(|error| format!("sync wal dir {}: {error}", path.display()))?;
    }

    Ok(records)
}

fn append_wal_record<T>(
    path: &Path,
    seq: u64,
    op: &T,
    mac_key: Option<&[u8; 32]>,
) -> Result<(), DurableIoError>
where
    T: Serialize,
{
    let (version, checksum) = if let Some(key) = mac_key {
        let mac = keyed_mac_json(key, &(WAL_VERSION_V2, seq, op))
            .map_err(|error| format!("serialize wal mac {}: {error}", path.display()))?;
        (WAL_VERSION_V2, mac)
    } else {
        let cs = checksum_json(&(WAL_VERSION_V1, seq, op))
            .map_err(|error| format!("serialize wal checksum {}: {error}", path.display()))?;
        (WAL_VERSION_V1, cs)
    };
    let envelope = WalEnvelope {
        version,
        seq,
        checksum,
        op,
    };
    let mut bytes = serde_json::to_vec(&envelope)
        .map_err(|error| format!("serialize wal {}: {error}", path.display()))?;
    bytes.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("open wal {}: {error}", path.display()))?;
    file.write_all(&bytes)
        .map_err(|error| format!("write wal {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync wal {}: {error}", path.display()))?;
    sync_parent_dir(path).map_err(|error| format!("sync wal dir {}: {error}", path.display()))?;
    Ok(())
}

async fn append_wal_record_blocking<T>(
    path: PathBuf,
    seq: u64,
    op: T,
    mac_key: Option<[u8; 32]>,
) -> Result<(), DurableIoError>
where
    T: Serialize + Send + 'static,
{
    run_blocking_io("append durable object WAL record", move || {
        append_wal_record(&path, seq, &op, mac_key.as_ref())
    })
    .await
}

fn write_snapshot<T>(
    path: &Path,
    last_seq: u64,
    payload: &T,
    mac_key: Option<&[u8; 32]>,
) -> Result<(), DurableIoError>
where
    T: Serialize + Clone,
{
    let (version, checksum) = if let Some(key) = mac_key {
        let mac = keyed_mac_json(key, &(SNAPSHOT_VERSION_V2, last_seq, payload))
            .map_err(|error| format!("serialize snapshot mac {}: {error}", path.display()))?;
        (SNAPSHOT_VERSION_V2, mac)
    } else {
        let cs = checksum_json(&(SNAPSHOT_VERSION_V1, last_seq, payload))
            .map_err(|error| format!("serialize snapshot checksum {}: {error}", path.display()))?;
        (SNAPSHOT_VERSION_V1, cs)
    };
    let envelope = SnapshotEnvelope {
        version,
        last_seq,
        checksum,
        payload: payload.clone(),
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| format!("serialize snapshot {}: {error}", path.display()))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid snapshot path {}", path.display()))?;
    let temp_file_name = format!("{file_name}.tmp.{}.{}", std::process::id(), last_seq);
    let (temp_path, mut file) =
        open_unique_snapshot_temp_file(path, &temp_file_name).map_err(DurableIoError::Other)?;
    file.write_all(&bytes)
        .map_err(|error| format!("write temp snapshot {}: {error}", temp_path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync temp snapshot {}: {error}", temp_path.display()))?;
    drop(file);

    fs::rename(&temp_path, path).map_err(|error| {
        format!(
            "rename snapshot {} -> {}: {error}",
            temp_path.display(),
            path.display()
        )
    })?;
    sync_parent_dir(path)
        .map_err(|error| format!("sync snapshot dir {}: {error}", path.display()))?;
    Ok(())
}

async fn write_snapshot_blocking<T>(
    path: PathBuf,
    last_seq: u64,
    payload: T,
    mac_key: Option<[u8; 32]>,
) -> Result<(), DurableIoError>
where
    T: Serialize + Clone + Send + 'static,
{
    run_blocking_io("write durable object snapshot", move || {
        write_snapshot(&path, last_seq, &payload, mac_key.as_ref())
    })
    .await
}

fn open_unique_snapshot_temp_file(path: &Path, base_name: &str) -> Result<(PathBuf, File), String> {
    const MAX_TEMP_FILE_RETRIES: u32 = 32;

    for suffix in 0..=MAX_TEMP_FILE_RETRIES {
        let candidate = if suffix == 0 {
            path.with_file_name(base_name)
        } else {
            path.with_file_name(format!("{base_name}.{suffix}"))
        };

        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((candidate, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "create temp snapshot {}: {error}",
                    candidate.display()
                ));
            }
        }
    }

    Err(format!(
        "create temp snapshot {}: exhausted unique-name retries for {base_name}",
        path.display()
    ))
}

fn clear_wal(path: &Path) -> Result<(), String> {
    let file =
        File::create(path).map_err(|error| format!("truncate wal {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync cleared wal {}: {error}", path.display()))?;
    sync_parent_dir(path).map_err(|error| format!("sync wal dir {}: {error}", path.display()))?;
    Ok(())
}

async fn clear_wal_blocking(path: PathBuf) -> Result<(), DurableIoError> {
    run_blocking_io("clear durable object WAL", move || {
        clear_wal(&path).map_err(DurableIoError::Other)
    })
    .await
}

async fn run_blocking_io<T, E, F>(operation: &'static str, f: F) -> Result<T, E>
where
    T: Send + 'static,
    E: From<String> + Send + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|error| E::from(format!("{operation} task failed: {error}")))?
}

fn checksum_json<T: Serialize>(value: &T) -> Result<[u8; 32], serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Compute a keyed BLAKE3 MAC over the JSON serialization of `value`
/// using `mac_key` as the secret. This is the V2 envelope authenticator
/// for `(version, seq, op)` (WAL) and `(version, last_seq, payload)`
/// (snapshot) tuples. BLAKE3's keyed mode is a PRF with the same
/// security properties as HMAC-SHA256 (32-byte key, 32-byte tag,
/// pseudo-random under the standard model) but is the workspace's
/// existing primitive — no new dependency required.
///
/// Bead: flywheel_connectors-dgbtx.
fn keyed_mac_json<T: Serialize>(
    mac_key: &[u8; 32],
    value: &T,
) -> Result<[u8; 32], serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(*blake3::keyed_hash(mac_key, &bytes).as_bytes())
}

/// Constant-time MAC comparison. Prevents an attacker who can observe
/// timing on the verification path from learning the MAC byte-by-byte.
fn macs_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(not(windows))]
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_parent_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn object_io(error: impl ToString) -> ObjectStoreError {
    ObjectStoreError::Io(error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn symbol_io(error: impl ToString) -> SymbolStoreError {
    SymbolStoreError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::symbol_store::ObjectTransmissionInfo;
    use fcp_prelude::{ObjectHeader, Provenance, StorageMeta};
    use tempfile::TempDir;

    fn test_zone() -> ZoneId {
        ZoneId::work()
    }

    const fn test_object_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    fn test_schema() -> fcp_cbor::SchemaId {
        fcp_cbor::SchemaId::new(
            "fcp.test",
            "DurableStoreObject",
            semver::Version::new(1, 0, 0),
        )
    }

    fn test_object(seed: u8) -> StoredObject {
        let zone = test_zone();
        StoredObject {
            object_id: test_object_id(seed),
            header: ObjectHeader {
                schema: test_schema(),
                zone_id: zone.clone(),
                created_at: 42,
                provenance: Provenance::new(zone),
                refs: Vec::new(),
                foreign_refs: Vec::new(),
                ttl_secs: None,
                placement: None,
            },
            body: vec![seed; 96],
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        }
    }

    fn test_symbol_meta(seed: u8) -> ObjectSymbolMeta {
        ObjectSymbolMeta {
            object_id: test_object_id(seed),
            zone_id: test_zone(),
            oti: ObjectTransmissionInfo {
                transfer_length: 2048,
                symbol_size: 128,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
                payload_hash: None,
            },
            source_symbols: 4,
            first_symbol_at: 100,
        }
    }

    fn test_symbol(seed: u8, esi: u32, source_node: u64) -> StoredSymbol {
        StoredSymbol {
            meta: SymbolMeta {
                object_id: test_object_id(seed),
                esi,
                zone_id: test_zone(),
                source_node: Some(source_node),
                stored_at: 100 + u64::from(esi),
            },
            data: Bytes::from(vec![seed.wrapping_add(esi as u8); 128]),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_recovers_after_restart() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path().join("objects"));
        config.checkpoint_after_ops = 64;

        let store = DurableObjectStore::open(config.clone()).expect("open store");
        let object_id = test_object_id(1);
        store.put(test_object(1)).await.expect("put object");
        store
            .set_retention(&object_id, RetentionClass::Lease { expires_at: 777 })
            .await
            .expect("set retention");
        store.put(test_object(2)).await.expect("put second object");
        store
            .delete(&test_object_id(2))
            .await
            .expect("delete second object");
        drop(store);

        let reopened = DurableObjectStore::open(config).expect("reopen store");
        let recovered = reopened.get(&object_id).await.expect("get recovered");
        assert_eq!(recovered.body, test_object(1).body);
        assert!(matches!(
            recovered.storage.retention,
            RetentionClass::Lease { expires_at: 777 }
        ));
        assert!(matches!(
            reopened.get(&test_object_id(2)).await,
            Err(ObjectStoreError::NotFound(_))
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_snapshot_reload_does_not_double_count_used_bytes() {
        // Regression: `from_snapshot` charged each object's size once manually
        // AND again via `insert_loaded`, so `used_bytes` recovered as 2× actual
        // after a restart that went through a checkpoint — silently halving the
        // usable quota. `checkpoint_after_ops = 1` forces the snapshot recovery
        // path (from_snapshot) rather than WAL replay.
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path().join("objects"));
        config.checkpoint_after_ops = 1;

        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(1)).await.expect("put object 1");
        store.put(test_object(2)).await.expect("put object 2");
        let used_before = store.storage_used().await;
        assert!(used_before > 0, "sanity: stored objects consume bytes");
        drop(store);

        // Recovery must go through the snapshot, not WAL replay.
        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        assert!(
            snapshot_path.exists(),
            "snapshot should exist so recovery uses from_snapshot"
        );

        let reopened = DurableObjectStore::open(config).expect("reopen store");
        assert_eq!(
            reopened.storage_used().await,
            used_before,
            "snapshot recovery must not double-count used_bytes"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_counts_canonical_header_in_quota() {
        // Durable quota accounting must mirror MemoryObjectStore. The old
        // body-plus-512 estimate let tiny-body objects with large ref lists
        // bypass max_bytes by moving their cost into the canonical header.
        let temp_dir = TempDir::new().expect("temp dir");
        let mut header_heavy = test_object(9);
        header_heavy.body.clear();
        header_heavy.header.refs = (0_u8..=u8::MAX)
            .cycle()
            .take(512)
            .map(|seed| ObjectId::from_bytes([seed; 32]))
            .collect();

        let actual_size = DurableObjectState::object_size(&header_heavy);
        assert!(
            actual_size > 4_096,
            "canonical header-heavy object must cost > 4 KiB, got {actual_size}"
        );

        #[allow(clippy::cast_possible_truncation)]
        let old_estimate = header_heavy.body.len() as u64 + 512;
        assert!(
            actual_size > old_estimate * 8,
            "canonical accounting must dominate the old 512-byte estimate; actual={actual_size} old={old_estimate}"
        );

        let mut rejected_config = DurableObjectStoreConfig::new(temp_dir.path().join("reject"));
        rejected_config.max_bytes = actual_size - 1;
        let rejected_store = DurableObjectStore::open(rejected_config).expect("open reject store");
        let result = rejected_store.put(header_heavy.clone()).await;
        assert!(
            matches!(result, Err(ObjectStoreError::QuotaExceeded { .. })),
            "header-heavy object must be rejected when quota < canonical cost, got {result:?}"
        );

        let mut exact_config = DurableObjectStoreConfig::new(temp_dir.path().join("exact"));
        exact_config.max_bytes = actual_size;
        let exact_store = DurableObjectStore::open(exact_config).expect("open exact store");
        exact_store
            .put(header_heavy)
            .await
            .expect("exact-fit quota must accept the object");
    }

    #[fcp_async_core::runtime::test]
    async fn wal_replay_rejects_oversized_object_body() {
        // Regression for flywheel_connectors-4g0qr: WAL replay used to call
        // `apply_loaded_mutation` directly without `validate_mutation`, so
        // a forged WAL record with `body.len() > MAX_CANONICAL_OBJECT_BYTES`
        // would be admitted into the in-memory map. After the fix,
        // recovery must reject the forged record (the WAL is then truncated
        // by the surrounding torn-WAL handling).
        use std::io::Write;

        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path());
        config.max_bytes = u64::MAX;

        // 1) Open + put a legitimate object so we have a valid WAL prefix.
        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(1)).await.expect("put legit object");
        drop(store);

        // 2) Construct a forged StoredObject whose body exceeds the
        //    canonical-bytes cap. `validate_structure` must reject this.
        let mut forged = test_object(2);
        forged.body = vec![0u8; fcp_cbor::MAX_CANONICAL_OBJECT_BYTES + 1];
        assert!(
            forged.validate_structure().is_err(),
            "structural check must reject oversized body"
        );

        // 3) Append the forged record to the object WAL with the correct
        //    checksum so the bytes-on-disk look authentic.
        let wal_path = temp_dir.path().join("objects.wal.jsonl");
        let op = ObjectWalOp::Put(Box::new(forged));
        let checksum =
            checksum_json(&(WAL_VERSION_V1, 2u64, &op)).expect("compute forged checksum");
        let envelope = WalEnvelope {
            version: WAL_VERSION_V1,
            seq: 2u64,
            checksum,
            op: &op,
        };
        let mut bytes = serde_json::to_vec(&envelope).expect("serialize forged envelope");
        bytes.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        file.write_all(&bytes).expect("append forged record");
        drop(file);

        // 4) Reopen. The fix must reject the forged record at recovery.
        match DurableObjectStore::open(config) {
            Ok(store) => {
                // If recovery succeeded (e.g. WAL truncation discarded the
                // bad tail), the forged object MUST NOT be present.
                assert!(
                    matches!(
                        store.get(&test_object_id(2)).await,
                        Err(ObjectStoreError::NotFound(_))
                    ),
                    "forged oversized object must not be recovered"
                );
            }
            Err(ObjectStoreError::Io(msg)) => {
                assert!(
                    msg.contains("invalid object structure"),
                    "expected structural-validation error, got: {msg}"
                );
            }
            Err(other) => panic!("unexpected error during recovery: {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn wal_replay_with_verifier_rejects_forged_object_id() {
        // Regression for flywheel_connectors-4g0qr: a process with
        // WAL write access can append an `ObjectWalOp::Put(StoredObject {
        // object_id: H, header: H', body: B' })` where `(H', B')` are
        // NOT the canonical bytes behind `H`. The WAL checksum covers
        // only the outer `(version, seq, op)` tuple, so the on-disk
        // integrity check accepts the forged bytes. Without the
        // content-id verifier, `load_durable_object_state` would
        // `insert_loaded` the forged record and any subsequent
        // `get(H)` would return attacker-controlled `(H', B')`.
        // With a verifier installed, reopen must fail closed on the
        // forged record.
        use std::io::Write;

        use crate::object_id_verifier::KeyedObjectIdVerifier;
        use fcp_prelude::ObjectIdKey;

        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path());
        config.max_bytes = u64::MAX;

        // Zone key material the verifier will use.
        let zone = test_zone();
        let zone_key = ObjectIdKey::from_bytes([0xC3u8; 32]);

        // Helper: build a StoredObject whose object_id is the canonical
        // derive_id(header, body, zone_key) — i.e. a record that WOULD
        // verify cleanly if replayed under the matching verifier.
        let genuine = |seed: u8, body: &[u8]| -> StoredObject {
            let header = ObjectHeader {
                schema: test_schema(),
                zone_id: zone.clone(),
                created_at: 100,
                provenance: Provenance::new(zone.clone()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            };
            let id = StoredObject::derive_id(&header, body, &zone_key).expect("derive id");
            let _ = seed; // only here to let callers pass distinct bodies
            StoredObject {
                object_id: id,
                header,
                body: body.to_vec(),
                storage: StorageMeta {
                    retention: RetentionClass::Pinned,
                },
            }
        };

        // 1) Open without a verifier and write one legitimate record so
        //    the WAL has a valid seq-1 prefix and the dir layout is
        //    initialized.
        let store = DurableObjectStore::open(config.clone()).expect("open store");
        let legit = genuine(1, b"legit-body");
        store.put(legit.clone()).await.expect("put legit");
        drop(store);

        // 2) Construct a forged WAL record: claim `object_id =
        //    legit.object_id` but ship a different body. A verifier
        //    for `zone_key` will compute `derive_id(header, B',
        //    zone_key)` != `legit.object_id` and reject.
        let mut forged = genuine(2, b"attacker-body");
        let legit_id = legit.object_id;
        forged.object_id = legit_id;

        let wal_path = temp_dir.path().join("objects.wal.jsonl");
        let op = ObjectWalOp::Put(Box::new(forged));
        let checksum =
            checksum_json(&(WAL_VERSION_V1, 2u64, &op)).expect("compute forged checksum");
        let envelope = WalEnvelope {
            version: WAL_VERSION_V1,
            seq: 2u64,
            checksum,
            op: &op,
        };
        let mut bytes = serde_json::to_vec(&envelope).expect("serialize forged envelope");
        bytes.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        file.write_all(&bytes).expect("append forged record");
        drop(file);

        // 3) Reopen WITH the verifier. Must fail on the forged record.
        let mut verifier = KeyedObjectIdVerifier::default();
        verifier.insert(zone.clone(), zone_key);
        let result =
            DurableObjectStore::open_with_verifier(config.clone(), Some(verifier.into_arc()));
        match result {
            Err(ObjectStoreError::ContentIdMismatch { claimed, computed }) => {
                assert_eq!(claimed, legit_id, "forged record claimed the legit id");
                assert_ne!(
                    computed, legit_id,
                    "computed id over forged body must differ from claimed id"
                );
            }
            Err(ObjectStoreError::AlreadyExists(id)) => {
                // Defense-in-depth: `apply_loaded_mutation` rejects a
                // duplicate id. That path ALSO prevents the forged
                // record from overwriting the legit one, but it is NOT
                // the content-id defense — this branch fails the test
                // to force the verifier to be the detection path.
                panic!(
                    "forged record was caught only by dup-detection ({id}), \
                     verifier did not reject first as expected"
                );
            }
            Err(other) => panic!("unexpected error on recovery: {other:?}"),
            Ok(_) => panic!("forged WAL record was accepted despite verifier"),
        }

        // 4) Sanity: reopen WITHOUT the verifier to confirm the WAL
        //    record really is on disk (i.e., step 2 wrote bytes that
        //    the legacy code path would have admitted). The dup
        //    check still rejects since the legit seq-1 record holds
        //    the id — which is exactly why the bead notes the attack
        //    is more effective when the attacker deletes the
        //    legitimate record or starts from a pristine store.
        let _ = DurableObjectStore::open(config);
    }

    #[test]
    fn read_until_bounded_caps_oversized_record_without_oom() {
        // Regression for flywheel_connectors-yhmwv: WAL recovery used
        // `BufRead::read_until` which has no upper bound on buffer growth.
        // A torn write or adversarial WAL containing a single line larger
        // than `MAX_WAL_RECORD_BYTES` would allocate the entire line into
        // memory before the parse step rejected it. The bounded reader
        // must signal `hit_cap = true` and stop without growing past the
        // cap.
        use std::io::Cursor;

        let cap = 64usize;

        // Case 1: input has a newline within the cap → returns the record
        // and `hit_cap = false`.
        let normal = b"hello\nworld\n".to_vec();
        let mut reader = Cursor::new(normal);
        let mut buf = Vec::new();
        let (n, capped) =
            read_until_bounded(&mut reader, b'\n', &mut buf, cap).expect("read normal");
        assert_eq!(n, 6);
        assert!(!capped);
        assert_eq!(buf, b"hello\n");

        // Case 2: single record larger than cap, no newline within first
        // `cap` bytes → returns `hit_cap = true` and `buf.len() <= cap`.
        let oversized: Vec<u8> = std::iter::repeat_n(b'A', cap * 4).collect();
        let mut reader = Cursor::new(oversized);
        let mut buf = Vec::new();
        let (n, capped) =
            read_until_bounded(&mut reader, b'\n', &mut buf, cap).expect("read oversized");
        assert!(capped, "oversized record must signal hit_cap");
        assert!(
            buf.len() <= cap,
            "buffer must not grow past cap (got {})",
            buf.len()
        );
        assert_eq!(n, buf.len());

        // Case 3: empty input → clean EOF, no cap signal.
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut buf = Vec::new();
        let (n, capped) =
            read_until_bounded(&mut reader, b'\n', &mut buf, cap).expect("read empty");
        assert_eq!(n, 0);
        assert!(!capped);
        assert!(buf.is_empty());

        // Case 4: record EXACTLY at the cap including the delimiter is
        // accepted as a normal record, not capped.
        let mut exact = vec![b'X'; cap - 1];
        exact.push(b'\n');
        let mut reader = Cursor::new(exact);
        let mut buf = Vec::new();
        let (n, capped) =
            read_until_bounded(&mut reader, b'\n', &mut buf, cap).expect("read exact-cap");
        assert!(!capped, "record exactly at cap must not be flagged");
        assert_eq!(n, cap);
        assert_eq!(buf.len(), cap);
        assert_eq!(buf.last(), Some(&b'\n'));
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_truncates_torn_wal_tail() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path().join("objects"));
        config.checkpoint_after_ops = 0;

        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(7)).await.expect("put object");
        drop(store);

        let wal_path = config.root_dir.join("objects.wal.jsonl");
        let valid_len = fs::metadata(&wal_path).expect("wal metadata").len();
        let mut wal = OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        wal.write_all(br#"{"version":1,"seq":"broken"#)
            .expect("append torn tail");
        wal.sync_all().expect("sync torn tail");
        drop(wal);

        let reopened = DurableObjectStore::open(config).expect("reopen store");
        assert!(reopened.exists(&test_object_id(7)).await);
        let truncated_len = fs::metadata(&wal_path)
            .expect("wal metadata after reopen")
            .len();
        assert_eq!(truncated_len, valid_len, "corrupt tail should be truncated");
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_auto_checkpoint_compacts_wal() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path().join("objects"));
        config.checkpoint_after_ops = 1;

        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(3)).await.expect("put object");
        drop(store);

        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let wal_path = config.root_dir.join("objects.wal.jsonl");
        assert!(
            snapshot_path.exists(),
            "snapshot should exist after checkpoint"
        );
        assert_eq!(
            fs::metadata(&wal_path).expect("wal metadata").len(),
            0,
            "checkpoint should compact wal"
        );

        let reopened = DurableObjectStore::open(config).expect("reopen store");
        assert!(reopened.exists(&test_object_id(3)).await);
    }

    #[fcp_async_core::runtime::test]
    async fn durable_object_store_checkpoint_retries_past_stale_snapshot_temp_file() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableObjectStoreConfig::new(temp_dir.path().join("objects"));
        config.checkpoint_after_ops = 0;

        let store = DurableObjectStore::open(config.clone()).expect("open store");
        let object = test_object(13);
        let object_id = object.object_id;
        store.put(object.clone()).await.expect("put object");

        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let stale_temp = snapshot_path.with_file_name(format!(
            "objects.snapshot.json.tmp.{}.1",
            std::process::id()
        ));
        fs::write(&stale_temp, b"stale snapshot temp").expect("write stale temp");

        store
            .checkpoint()
            .await
            .expect("checkpoint should ignore orphaned temp file names");
        assert!(
            snapshot_path.exists(),
            "checkpoint should still materialize the durable snapshot"
        );

        let reopened = DurableObjectStore::open(config).expect("reopen store");
        let recovered = reopened.get(&object_id).await.expect("recover object");
        assert_eq!(recovered.body, object.body);
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_rejects_conflicting_esi() {
        // Regression: silent first-write-wins on ESI let a crafted symbol
        // block all later honest writes and permanently deny repair for
        // the target object. Durable validate_mutation + apply_put_symbol
        // must reject bytewise conflicts before touching the WAL.
        let temp_dir = TempDir::new().expect("temp dir");
        let config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        let store = DurableSymbolStore::open(config).expect("open symbol store");
        store
            .put_object_meta(test_symbol_meta(9))
            .await
            .expect("put meta");
        let honest = test_symbol(9, 0, 2);
        store.put_symbol(honest.clone()).await.expect("put honest");

        // Idempotent resubmission.
        store
            .put_symbol(honest.clone())
            .await
            .expect("identical resubmission must remain idempotent");

        // Conflict → InvalidSymbol, not silent drop.
        let forged = StoredSymbol {
            meta: honest.meta.clone(),
            data: Bytes::from(vec![0xAA_u8; 128]),
        };
        let result = store.put_symbol(forged).await;
        assert!(
            matches!(&result, Err(SymbolStoreError::InvalidSymbol { reason }) if reason.contains("conflicting")),
            "expected InvalidSymbol with conflicting reason, got {result:?}"
        );

        let fetched = store
            .get_symbol(&test_object_id(9), 0)
            .await
            .expect("fetch honest");
        assert_eq!(fetched.data, honest.data);
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_rejects_oversized_source_symbols() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        let store = DurableSymbolStore::open(config).expect("open symbol store");

        let mut poisoned = test_symbol_meta(12);
        poisoned.source_symbols = u32::MAX;
        let result = store.put_object_meta(poisoned).await;
        assert!(
            matches!(result, Err(SymbolStoreError::InvalidSymbol { .. })),
            "durable meta writes must reject oversized source_symbols before allocation, got {result:?}"
        );

        let mut zero = test_symbol_meta(13);
        zero.source_symbols = 0;
        let result = store.put_object_meta(zero).await;
        assert!(
            matches!(result, Err(SymbolStoreError::InvalidSymbol { .. })),
            "durable meta writes must reject zero source_symbols, got {result:?}"
        );

        assert!(
            store.list_zone(&test_zone()).await.is_empty(),
            "rejected metadata must not create durable symbol objects"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_rejects_invalid_snapshot_source_symbols() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        fs::create_dir_all(&config.root_dir).expect("create root dir");
        let snapshot_path = config.root_dir.join("symbols.snapshot.json");

        let mut invalid_meta = test_symbol_meta(14);
        invalid_meta.source_symbols = 0;
        let snapshot = SymbolSnapshot {
            objects: vec![SymbolSnapshotEntry {
                meta: invalid_meta,
                symbols: Vec::new(),
            }],
        };
        write_snapshot(&snapshot_path, 1, &snapshot, None).expect("write invalid snapshot");

        match DurableSymbolStore::open(config) {
            Err(SymbolStoreError::InvalidSymbol { .. }) => {}
            Err(other) => {
                panic!("expected InvalidSymbol for invalid source_symbols, got {other:?}")
            }
            Ok(_) => panic!("expected recovery to reject invalid source_symbols"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_rejects_semantically_invalid_wal_on_recovery() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        config.checkpoint_after_ops = 0;

        let store = DurableSymbolStore::open(config.clone()).expect("open symbol store");
        store
            .put_object_meta(test_symbol_meta(10))
            .await
            .expect("put meta");
        drop(store);

        let wal_path = config.root_dir.join("symbols.wal.jsonl");
        let forged = PersistentStoredSymbol {
            meta: test_symbol(10, 0, 5).meta,
            data: vec![0xAB; 7],
        };
        append_wal_record(&wal_path, 2, &SymbolWalOp::PutSymbol(forged), None).expect("append wal");

        match DurableSymbolStore::open(config) {
            Err(SymbolStoreError::InvalidSymbol { reason }) => {
                assert!(
                    reason.contains("Symbol size mismatch"),
                    "expected size mismatch, got {reason}"
                );
            }
            Err(other) => panic!("expected InvalidSymbol, got {other:?}"),
            Ok(_) => panic!("expected reopen to fail on invalid replayed symbol"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_open_scrubs_invalid_snapshot_symbols_before_quota_checks() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        config.max_bytes = 256;
        config.checkpoint_after_ops = 0;

        fs::create_dir_all(&config.root_dir).expect("create root dir");
        let snapshot_path = config.root_dir.join("symbols.snapshot.json");
        let wal_path = config.root_dir.join("symbols.wal.jsonl");
        clear_wal(&wal_path).expect("clear wal");

        let object_meta = test_symbol_meta(11);
        let invalid_symbol = PersistentStoredSymbol {
            meta: SymbolMeta {
                object_id: object_meta.object_id,
                esi: 0,
                zone_id: object_meta.zone_id.clone(),
                source_node: Some(7),
                stored_at: 100,
            },
            data: vec![0xCD; 200],
        };
        let snapshot = SymbolSnapshot {
            objects: vec![SymbolSnapshotEntry {
                meta: object_meta,
                symbols: vec![invalid_symbol],
            }],
        };
        write_snapshot(&snapshot_path, 0, &snapshot, None).expect("write snapshot");

        let reopened = DurableSymbolStore::open(config).expect("open symbol store");
        assert_eq!(
            reopened.storage_used().await,
            0,
            "invalid snapshot symbol should be scrubbed"
        );

        reopened
            .put_symbol(test_symbol(11, 0, 7))
            .await
            .expect("honest symbol should fit once invalid bytes are scrubbed");
        assert_eq!(reopened.symbol_count(&test_object_id(11)).await, 1);
    }

    #[test]
    fn durable_symbol_state_scrub_repairs_used_bytes_in_same_lock_scope() {
        let meta = test_symbol_meta(12);
        let valid = test_symbol(12, 0, 9);
        let valid_size = DurableSymbolState::symbol_size(&valid);

        let mut state = DurableSymbolState::default();
        state
            .apply_put_object_meta(meta.clone())
            .expect("object meta should load");
        state
            .apply_put_symbol(PersistentStoredSymbol {
                meta: valid.meta.clone(),
                data: valid.data.to_vec(),
            })
            .expect("valid symbol should load");

        let corrupt = StoredSymbol {
            meta: SymbolMeta {
                object_id: meta.object_id,
                esi: 99,
                zone_id: meta.zone_id.clone(),
                source_node: Some(99),
                stored_at: 99,
            },
            data: Bytes::from(vec![0xAB; usize::from(meta.oti.symbol_size) - 1]),
        };
        let corrupt_size = DurableSymbolState::symbol_size(&corrupt);
        state.used_bytes = state.used_bytes.saturating_add(corrupt_size);
        state
            .objects
            .get_mut(&meta.object_id)
            .expect("object must exist")
            .symbols
            .insert(corrupt.meta.esi, corrupt);

        assert_eq!(
            state.used_bytes,
            valid_size + corrupt_size,
            "setup should include the invalid symbol in used_bytes"
        );

        assert!(
            state.scrub_object_if_present(&meta.object_id),
            "object should still be present"
        );
        assert_eq!(
            state.used_bytes, valid_size,
            "scrub must repair quota accounting before releasing the state lock"
        );
        assert_eq!(
            state
                .objects
                .get(&meta.object_id)
                .expect("object should remain")
                .symbols
                .len(),
            1,
            "corrupt symbol should be removed"
        );
    }

    /// `record_mutation` validates under a read lock, releases the lock for
    /// the WAL append, then reacquires the write lock to call
    /// `apply_loaded_mutation`. A concurrent reader can take the write lock
    /// in that gap and run `scrub_object_if_present`, which removes any
    /// corrupt (size-mismatched) symbol. If the in-flight WAL op is
    /// `DeleteSymbol{esi}` for that exact corrupt symbol, the WAL entry is
    /// already on disk; `apply_delete_symbol` MUST converge on the
    /// requested post-condition (esi absent) instead of returning `NotFound`,
    /// otherwise the WAL replay path also fails on every restart.
    #[test]
    fn apply_delete_symbol_tolerates_already_scrubbed_target() {
        let meta = test_symbol_meta(13);
        let valid = test_symbol(13, 0, 9);
        let valid_size = DurableSymbolState::symbol_size(&valid);

        let mut state = DurableSymbolState::default();
        state
            .apply_put_object_meta(meta.clone())
            .expect("object meta should load");
        state
            .apply_put_symbol(PersistentStoredSymbol {
                meta: valid.meta.clone(),
                data: valid.data.to_vec(),
            })
            .expect("valid symbol should load");

        // Inject a corrupt symbol that scrub will remove on the next read.
        let corrupt_esi = 77;
        let corrupt = StoredSymbol {
            meta: SymbolMeta {
                object_id: meta.object_id,
                esi: corrupt_esi,
                zone_id: meta.zone_id.clone(),
                source_node: Some(77),
                stored_at: 77,
            },
            data: Bytes::from(vec![0xCD; usize::from(meta.oti.symbol_size) - 1]),
        };
        let corrupt_size = DurableSymbolState::symbol_size(&corrupt);
        state.used_bytes = state.used_bytes.saturating_add(corrupt_size);
        state
            .objects
            .get_mut(&meta.object_id)
            .expect("object must exist")
            .symbols
            .insert(corrupt.meta.esi, corrupt);

        // Simulate the validate→scrub→apply race: the read-locked validate
        // saw the corrupt symbol present, then a concurrent reader scrubbed
        // it, and now apply runs against the scrubbed state.
        assert!(state.scrub_object_if_present(&meta.object_id));
        assert!(
            !state
                .objects
                .get(&meta.object_id)
                .expect("object should remain")
                .symbols
                .contains_key(&corrupt_esi),
            "scrub must have removed the corrupt symbol before apply runs"
        );

        // Apply MUST succeed even though the symbol is no longer present.
        state
            .apply_loaded_mutation(SymbolWalOp::DeleteSymbol {
                object_id: meta.object_id,
                esi: corrupt_esi,
            })
            .expect("apply_delete_symbol must tolerate scrub-removed targets");

        // The valid symbol is unchanged and quota accounting is consistent.
        assert_eq!(
            state.used_bytes, valid_size,
            "used_bytes must reflect only the valid symbol after the tolerated apply"
        );
        assert_eq!(
            state
                .objects
                .get(&meta.object_id)
                .expect("object should remain")
                .symbols
                .len(),
            1,
            "valid symbol must remain after the tolerated apply"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_recovers_after_restart() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        config.checkpoint_after_ops = 64;
        config.local_node_id = 9;

        let store = DurableSymbolStore::open(config.clone()).expect("open symbol store");
        let object_id = test_object_id(5);
        store
            .put_object_meta(test_symbol_meta(5))
            .await
            .expect("put meta");
        store
            .put_symbol(test_symbol(5, 0, 2))
            .await
            .expect("put symbol 0");
        store
            .put_symbol(test_symbol(5, 1, 3))
            .await
            .expect("put symbol 1");
        drop(store);

        let reopened = DurableSymbolStore::open(config).expect("reopen symbol store");
        let meta = reopened
            .get_object_meta(&object_id)
            .await
            .expect("get meta");
        assert_eq!(meta.source_symbols, 4);
        assert_eq!(reopened.symbol_count(&object_id).await, 2);
        let distribution = reopened
            .get_distribution(&object_id)
            .await
            .expect("distribution");
        assert_eq!(distribution.total_symbols, 2);
        assert_eq!(distribution.distinct_nodes(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn durable_symbol_store_truncates_torn_wal_tail() {
        let temp_dir = TempDir::new().expect("temp dir");
        let mut config = DurableSymbolStoreConfig::new(temp_dir.path().join("symbols"));
        config.checkpoint_after_ops = 0;

        let store = DurableSymbolStore::open(config.clone()).expect("open symbol store");
        store
            .put_object_meta(test_symbol_meta(8))
            .await
            .expect("put meta");
        store
            .put_symbol(test_symbol(8, 0, 4))
            .await
            .expect("put symbol");
        drop(store);

        let wal_path = config.root_dir.join("symbols.wal.jsonl");
        let valid_len = fs::metadata(&wal_path).expect("wal metadata").len();
        let mut wal = OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        wal.write_all(br#"{"version":1,"seq":999"#)
            .expect("append torn tail");
        wal.sync_all().expect("sync torn tail");
        drop(wal);

        let reopened = DurableSymbolStore::open(config).expect("reopen symbol store");
        assert_eq!(reopened.symbol_count(&test_object_id(8)).await, 1);
        let truncated_len = fs::metadata(&wal_path)
            .expect("wal metadata after reopen")
            .len();
        assert_eq!(truncated_len, valid_len, "corrupt tail should be truncated");
    }

    // ─────────────────────────────────────────────────────────────────
    // dgbtx: V2 keyed-MAC envelope regression tests.
    //
    // SilverFox's gamma audit observed that the pre-dgbtx WAL/snapshot
    // checksums were unkeyed BLAKE3, so a tamperer with file-system
    // access could:
    //   - forge `Delete` / `SetRetention` / `DeleteSymbol` records by
    //     recomputing the unkeyed checksum,
    //   - rewrite a snapshot to omit objects (advancing `last_seq` past
    //     them) and then reattach a forged WAL prefix,
    //   - replay an old keyed record at a lower seq.
    // The V2 envelope authenticates `(version, seq, op)` with a per-
    // store secret key; these tests pin the verifier behaviour.
    // ─────────────────────────────────────────────────────────────────

    const TEST_MAC_KEY: [u8; 32] = [0xA5; 32];
    const OTHER_MAC_KEY: [u8; 32] = [0x5A; 32];

    fn dgbtx_object_config(
        path: &Path,
        mac_key: Option<[u8; 32]>,
        allow_legacy_unauth: bool,
    ) -> DurableObjectStoreConfig {
        let mut config = DurableObjectStoreConfig::new(path);
        config.checkpoint_after_ops = 0;
        config.mac_key = mac_key;
        config.allow_legacy_unauth = allow_legacy_unauth;
        config
    }

    fn dgbtx_symbol_config(
        path: &Path,
        mac_key: Option<[u8; 32]>,
        allow_legacy_unauth: bool,
    ) -> DurableSymbolStoreConfig {
        let mut config = DurableSymbolStoreConfig::new(path);
        config.checkpoint_after_ops = 0;
        config.mac_key = mac_key;
        config.allow_legacy_unauth = allow_legacy_unauth;
        config
    }

    /// Forge a Delete record with a recomputed unkeyed checksum. Without
    /// dgbtx, the V1 checksum collapses to `BLAKE3(serde_json(op))` and
    /// the attacker only needs the on-disk seq position. With dgbtx, the
    /// MAC key is required and the forgery fails.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_forged_delete_record_with_recomputed_checksum_rejected_under_v2() {
        let temp_dir = TempDir::new().expect("temp dir");
        // Open with V2 enabled (mac_key set).
        let config =
            dgbtx_object_config(&temp_dir.path().join("objects"), Some(TEST_MAC_KEY), false);
        let store = DurableObjectStore::open(config.clone()).expect("open V2 store");
        store.put(test_object(1)).await.expect("put legit");
        // Force a checkpoint so the WAL is empty and the legit record is
        // inside the snapshot. The forged WAL append below thus targets
        // seq=2 cleanly.
        store.checkpoint().await.expect("checkpoint");
        drop(store);

        // Attacker recomputes a V1 unkeyed checksum and appends a Delete.
        let wal_path = config.root_dir.join("objects.wal.jsonl");
        let op = ObjectWalOp::Delete {
            object_id: test_object_id(1),
        };
        let checksum = checksum_json(&(WAL_VERSION_V1, 2u64, &op)).expect("compute checksum");
        let envelope = WalEnvelope {
            version: WAL_VERSION_V1,
            seq: 2u64,
            checksum,
            op: &op,
        };
        let mut bytes = serde_json::to_vec(&envelope).expect("serialize");
        bytes.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        file.write_all(&bytes).expect("append forged");
        drop(file);

        // Reopen MUST refuse the V1 envelope when V2 is configured and
        // legacy is disallowed.
        match DurableObjectStore::open(config) {
            Err(ObjectStoreError::TamperedAuditEnvelope { reason, .. }) => {
                assert!(
                    reason.contains("V1 unkeyed envelope"),
                    "expected V1-rejection reason, got: {reason}"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("forged V1 Delete must not be accepted under V2 mode"),
        }
    }

    /// A V2 envelope written under one MAC key MUST be rejected when
    /// a different (or no) MAC key is presented at read time.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_v2_envelope_with_wrong_mac_key_rejected() {
        let temp_dir = TempDir::new().expect("temp dir");
        let write_config =
            dgbtx_object_config(&temp_dir.path().join("objects"), Some(TEST_MAC_KEY), false);
        let store = DurableObjectStore::open(write_config.clone()).expect("open store");
        store.put(test_object(2)).await.expect("put legit");
        drop(store);

        // Same root dir, different mac_key: the V2 MAC will not verify.
        let read_config = dgbtx_object_config(&write_config.root_dir, Some(OTHER_MAC_KEY), false);
        match DurableObjectStore::open(read_config) {
            Err(ObjectStoreError::TamperedAuditEnvelope { reason, .. }) => {
                assert!(
                    reason.contains("V2 keyed MAC mismatch"),
                    "expected V2 MAC mismatch, got: {reason}"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("wrong mac_key MUST NOT decrypt a V2 envelope"),
        }
    }

    /// Tampering the `op` field of a V2 WAL envelope (without
    /// recomputing the MAC, which the attacker can't do) MUST be
    /// rejected as a tampered envelope.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_v2_wal_byte_flip_in_op_rejected() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config =
            dgbtx_object_config(&temp_dir.path().join("objects"), Some(TEST_MAC_KEY), false);
        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(3)).await.expect("put legit");
        drop(store);

        // Read the WAL, flip a byte in the body of the op, write back.
        let wal_path = config.root_dir.join("objects.wal.jsonl");
        let mut bytes = fs::read(&wal_path).expect("read wal");
        // Find a likely body byte (the seed byte 3 repeats 96 times in
        // the body; the JSON body field is `[3,3,3,...]`).
        let needle: &[u8] = b"\"body\":[";
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("body field present");
        // Flip the first body integer's high bit by appending a digit.
        // Specifically replace the leading "3" with "4" to corrupt the
        // first body byte's value without changing structure.
        bytes[pos + needle.len()] = b'4';
        fs::write(&wal_path, &bytes).expect("write tampered wal");

        match DurableObjectStore::open(config) {
            Err(ObjectStoreError::TamperedAuditEnvelope { reason, .. }) => {
                assert!(
                    reason.contains("V2 keyed MAC mismatch"),
                    "expected MAC mismatch on body tampering, got: {reason}"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("byte-flipped V2 WAL envelope MUST NOT be accepted"),
        }
    }

    /// Tampering the snapshot `payload` field of a V2 envelope (e.g.
    /// omitting an object to silently drop it) MUST be rejected.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_v2_snapshot_byte_flip_in_payload_rejected() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config =
            dgbtx_object_config(&temp_dir.path().join("objects"), Some(TEST_MAC_KEY), false);
        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(4)).await.expect("put legit");
        store.checkpoint().await.expect("checkpoint");
        drop(store);

        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let mut bytes = fs::read(&snapshot_path).expect("read snapshot");
        // Flip a byte inside the payload. Find the body array marker.
        // test_object(4) has body = vec![4; 96] → JSON `[4,4,...]`. Replace
        // the first body byte's digit with `9` so the post-deserialize
        // payload differs from the MAC-covered original.
        let needle: &[u8] = b"\"body\":[";
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("body present");
        bytes[pos + needle.len()] = b'9';
        fs::write(&snapshot_path, &bytes).expect("write tampered snapshot");

        match DurableObjectStore::open(config) {
            Err(ObjectStoreError::TamperedAuditEnvelope { reason, .. }) => {
                assert!(
                    reason.contains("V2 keyed MAC mismatch"),
                    "expected snapshot MAC mismatch, got: {reason}"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("tampered V2 snapshot MUST NOT be accepted"),
        }
    }

    /// `allow_legacy_unauth = true` is the migration knob — V1
    /// envelopes load successfully when set, so a node can ingest
    /// pre-dgbtx data and rewrite it as V2 on the next checkpoint.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_v1_envelope_loads_under_legacy_flag() {
        let temp_dir = TempDir::new().expect("temp dir");
        // First, write data with no mac_key (V1 envelopes on disk).
        let v1_config = dgbtx_object_config(&temp_dir.path().join("objects"), None, false);
        let store = DurableObjectStore::open(v1_config.clone()).expect("open V1 store");
        store.put(test_object(5)).await.expect("put");
        drop(store);

        // Reopen with V2 mac_key set + allow_legacy_unauth=true. The V1
        // tail must load.
        let migration_config = dgbtx_object_config(&v1_config.root_dir, Some(TEST_MAC_KEY), true);
        let migrated =
            DurableObjectStore::open(migration_config.clone()).expect("migration must load V1");
        assert!(migrated.exists(&test_object_id(5)).await);

        // After a checkpoint, the snapshot is written as V2 — reopening
        // without the legacy flag now succeeds (V1 WAL was cleared by
        // checkpoint, V2 snapshot verifies under mac_key).
        migrated.checkpoint().await.expect("checkpoint to V2");
        drop(migrated);

        let strict_config = dgbtx_object_config(&v1_config.root_dir, Some(TEST_MAC_KEY), false);
        let strict = DurableObjectStore::open(strict_config).expect("V2 reopen after checkpoint");
        assert!(strict.exists(&test_object_id(5)).await);
    }

    /// Snapshot-omission attack: rewrite the snapshot to drop an object
    /// (advancing `last_seq` so WAL replay starts after the dropped
    /// record). Under V1 unkeyed mode, an attacker who recomputes the
    /// checksum can do this; under V2 the MAC is unforgeable.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_v2_snapshot_omission_rejected() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config =
            dgbtx_object_config(&temp_dir.path().join("objects"), Some(TEST_MAC_KEY), false);
        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(6)).await.expect("put 6");
        store.put(test_object(7)).await.expect("put 7");
        store.checkpoint().await.expect("checkpoint");
        drop(store);

        // Read the V2 snapshot, drop one of the objects from the
        // payload, and write back. The MAC over the original payload
        // is left untouched — but it no longer matches the modified
        // payload so verification fails.
        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let mut bytes = fs::read(&snapshot_path).expect("read snapshot");
        // Locate the second object's body (a run of 7s) and overwrite
        // a digit. (Easier than parsing JSON to delete the object.)
        let needle: &[u8] = b"7,7,7,7,7,7,7,7,7,7";
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("seed-7 body present");
        bytes[pos] = b'9';
        fs::write(&snapshot_path, &bytes).expect("write tampered snapshot");

        match DurableObjectStore::open(config) {
            Err(ObjectStoreError::TamperedAuditEnvelope { reason, .. }) => {
                assert!(
                    reason.contains("V2 keyed MAC mismatch"),
                    "expected MAC mismatch on snapshot omission, got: {reason}"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("snapshot omission MUST NOT survive V2 verification"),
        }
    }

    /// Symbol-store equivalent: forged `DeleteSymbol` with recomputed
    /// V1 checksum is rejected under V2.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_symbol_forged_delete_with_recomputed_checksum_rejected_under_v2() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config =
            dgbtx_symbol_config(&temp_dir.path().join("symbols"), Some(TEST_MAC_KEY), false);
        let store = DurableSymbolStore::open(config.clone()).expect("open V2 symbol store");
        store
            .put_object_meta(test_symbol_meta(8))
            .await
            .expect("put meta");
        store
            .put_symbol(test_symbol(8, 0, 1))
            .await
            .expect("put sym");
        store.checkpoint().expect("checkpoint");
        drop(store);

        let wal_path = config.root_dir.join("symbols.wal.jsonl");
        let op = SymbolWalOp::DeleteSymbol {
            object_id: test_object_id(8),
            esi: 0,
        };
        let checksum = checksum_json(&(WAL_VERSION_V1, 3u64, &op)).expect("compute checksum");
        let envelope = WalEnvelope {
            version: WAL_VERSION_V1,
            seq: 3u64,
            checksum,
            op: &op,
        };
        let mut bytes = serde_json::to_vec(&envelope).expect("serialize");
        bytes.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .expect("open wal");
        file.write_all(&bytes).expect("append forged");
        drop(file);

        match DurableSymbolStore::open(config) {
            Err(SymbolStoreError::TamperedAuditEnvelope { reason, .. }) => {
                assert!(
                    reason.contains("V1 unkeyed envelope"),
                    "expected V1-rejection reason, got: {reason}"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("forged V1 DeleteSymbol must not be accepted under V2 mode"),
        }
    }

    /// Replay attack: take a legitimate V2 record from the WAL and
    /// re-append it at the same seq (or lower). The seq-regression check
    /// fires before MAC verification can be tricked.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_v2_seq_regression_rejected() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config =
            dgbtx_object_config(&temp_dir.path().join("objects"), Some(TEST_MAC_KEY), false);
        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(9)).await.expect("put 9");
        store.put(test_object(10)).await.expect("put 10");
        drop(store);

        // Read the WAL — duplicate the first record (seq=1) by appending
        // it after the seq=2 record. Both lines carry valid V2 MACs but
        // the seq sequence regresses (3 -> 1 if we replay).
        let wal_path = config.root_dir.join("objects.wal.jsonl");
        let original = fs::read(&wal_path).expect("read wal");
        // The WAL is two newline-terminated lines. Find the first.
        let first_newline = original
            .iter()
            .position(|&b| b == b'\n')
            .expect("first newline");
        let first_line = &original[..=first_newline];
        let mut tampered = original.clone();
        tampered.extend_from_slice(first_line);
        fs::write(&wal_path, &tampered).expect("write replay tail");

        match DurableObjectStore::open(config) {
            Err(ObjectStoreError::TamperedAuditEnvelope { reason, .. }) => {
                assert!(
                    reason.contains("seq regression"),
                    "expected seq regression diagnosis, got: {reason}"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("seq replay MUST be rejected under V2"),
        }
    }

    /// Snapshot written under V2 cannot be downgraded to a forged V1
    /// snapshot — a tamperer who replaces the snapshot envelope's
    /// `version` field (and recomputes the V1 checksum) is rejected
    /// when V2 is configured and legacy is disallowed.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_v2_snapshot_downgrade_to_v1_rejected() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config =
            dgbtx_object_config(&temp_dir.path().join("objects"), Some(TEST_MAC_KEY), false);
        let store = DurableObjectStore::open(config.clone()).expect("open store");
        store.put(test_object(11)).await.expect("put 11");
        store.checkpoint().await.expect("checkpoint");
        drop(store);

        // Build a forged V1 snapshot with an unkeyed checksum that
        // covers a different payload (omitting object 11).
        let snapshot_path = config.root_dir.join("objects.snapshot.json");
        let empty_snapshot = ObjectSnapshot { objects: vec![] };
        write_snapshot(&snapshot_path, 1, &empty_snapshot, None).expect("write forged V1 snapshot");

        match DurableObjectStore::open(config) {
            Err(ObjectStoreError::TamperedAuditEnvelope { reason, .. }) => {
                assert!(
                    reason.contains("V1 unkeyed envelope"),
                    "expected V1-downgrade rejection, got: {reason}"
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("V2-to-V1 snapshot downgrade MUST be rejected"),
        }
    }

    /// Sanity check: V2 round-trip works end-to-end. Write V2, reopen
    /// with the same key, verify state survives.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_v2_round_trip_preserves_state() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config =
            dgbtx_object_config(&temp_dir.path().join("objects"), Some(TEST_MAC_KEY), false);
        let store = DurableObjectStore::open(config.clone()).expect("open V2 store");
        store.put(test_object(12)).await.expect("put 12");
        store
            .set_retention(
                &test_object_id(12),
                RetentionClass::Lease { expires_at: 99 },
            )
            .await
            .expect("set retention");
        store.put(test_object(13)).await.expect("put 13");
        store.checkpoint().await.expect("checkpoint");
        store.put(test_object(14)).await.expect("put 14");
        drop(store);

        let reopened = DurableObjectStore::open(config).expect("reopen V2");
        assert!(reopened.exists(&test_object_id(12)).await);
        assert!(reopened.exists(&test_object_id(13)).await);
        assert!(reopened.exists(&test_object_id(14)).await);
        let recovered = reopened.get(&test_object_id(12)).await.expect("get 12");
        assert!(matches!(
            recovered.storage.retention,
            RetentionClass::Lease { expires_at: 99 }
        ));
    }

    /// Symbol-store V2 round-trip sanity check.
    #[fcp_async_core::runtime::test]
    async fn dgbtx_symbol_v2_round_trip_preserves_state() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config =
            dgbtx_symbol_config(&temp_dir.path().join("symbols"), Some(TEST_MAC_KEY), false);
        let store = DurableSymbolStore::open(config.clone()).expect("open V2 symbol store");
        store
            .put_object_meta(test_symbol_meta(15))
            .await
            .expect("put meta");
        store
            .put_symbol(test_symbol(15, 0, 1))
            .await
            .expect("put sym 0");
        store.checkpoint().expect("checkpoint");
        store
            .put_symbol(test_symbol(15, 1, 2))
            .await
            .expect("put sym 1");
        drop(store);

        let reopened = DurableSymbolStore::open(config).expect("reopen V2 symbol store");
        assert_eq!(reopened.symbol_count(&test_object_id(15)).await, 2);
    }
}
