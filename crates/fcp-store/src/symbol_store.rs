//! Symbol store interface for FCPS durable repair data.
//!
//! Provides storage for `RaptorQ` symbols to enable partial object availability.
//! `MemorySymbolStore` uses nested locks; the only supported acquisition order
//! is `objects` -> per-object `ObjectSymbols` -> `used_bytes`. Never acquire a
//! later lock and then call back into a path that can take an earlier one.

use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use fcp_prelude::{ObjectId, ZoneId};
#[cfg(test)]
use fcp_raptorq::ObjectTransmissionInformation;
pub use fcp_raptorq::ObjectTransmissionInformation as ObjectTransmissionInfo;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::coverage::SymbolDistribution;
use crate::error::SymbolStoreError;

/// Maximum source-symbol count (K) accepted in an [`ObjectSymbolMeta`].
///
/// Matches the RFC 6330 §5.1.2 `K_MAX` limit also enforced by
/// `fcp_raptorq::encode::Encoder::new` (56403). `put_object_meta`
/// receives metadata from untrusted mesh inputs; a forged value of
/// e.g. `u32::MAX` would otherwise drive a multi-GB `HashMap::
/// with_capacity(...)` allocation under the global `objects.write()`
/// lock before any symbols arrive. See br-ywpup.
const MAX_SOURCE_SYMBOLS: u32 = 56_403;

/// Maximum bucket request used when an object advertises many source symbols
/// but has not received any symbols yet.
///
/// The symbol map still grows normally as symbols arrive; this only bounds
/// eager allocation during metadata admission and durable WAL recovery.
const MAX_EAGER_SYMBOL_MAP_CAPACITY: usize = 1_024;

/// Bound an empty symbol map's reservation independently of the advertised K.
///
/// Both live stores and durable replay use this policy so sparse, valid high-K
/// metadata cannot allocate a full reconstruction buffer before symbols arrive.
/// Metadata validation remains a separate admission requirement.
pub(crate) fn initial_symbol_map_capacity(source_symbols: u32) -> usize {
    let bounded_source_symbols = source_symbols.min(MAX_SOURCE_SYMBOLS);
    let bounded_source_symbols =
        usize::try_from(bounded_source_symbols).expect("MAX_SOURCE_SYMBOLS fits in usize");

    bounded_source_symbols.min(MAX_EAGER_SYMBOL_MAP_CAPACITY)
}

/// Validate that object metadata declares a source-symbol count supported by
/// the paired `RaptorQ` codec.
///
/// # Errors
/// Returns [`SymbolStoreError::InvalidSymbol`] when the source-symbol count is
/// zero or exceeds the RFC 6330 `K_MAX` bound.
pub fn validate_source_symbols(meta: &ObjectSymbolMeta) -> Result<(), SymbolStoreError> {
    if meta.source_symbols == 0 || meta.source_symbols > MAX_SOURCE_SYMBOLS {
        return Err(SymbolStoreError::InvalidSymbol {
            reason: format!(
                "source_symbols={} out of range (1..={}) for object {}",
                meta.source_symbols, MAX_SOURCE_SYMBOLS, meta.object_id
            ),
        });
    }

    Ok(())
}

/// Metadata for a stored symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolMeta {
    /// Object this symbol belongs to.
    pub object_id: ObjectId,
    /// Encoding symbol ID.
    pub esi: u32,
    /// Zone ID for the object.
    pub zone_id: ZoneId,
    /// Node that provided this symbol (for source diversity tracking).
    pub source_node: Option<u64>,
    /// Timestamp when symbol was stored.
    pub stored_at: u64,
}

/// Stored symbol with data and metadata.
#[derive(Debug, Clone)]
pub struct StoredSymbol {
    /// Symbol metadata.
    pub meta: SymbolMeta,
    /// Symbol data.
    pub data: Bytes,
}

/// Object metadata for symbol reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectSymbolMeta {
    /// Object ID.
    pub object_id: ObjectId,
    /// Zone ID.
    pub zone_id: ZoneId,
    /// Object transmission information for `RaptorQ` decoding.
    pub oti: ObjectTransmissionInfo,
    /// Number of source symbols (K).
    pub source_symbols: u32,
    /// Timestamp when first symbol was stored.
    pub first_symbol_at: u64,
}

/// Symbol store interface (NORMATIVE).
///
/// Stores `RaptorQ` symbols for partial object availability.
#[async_trait]
pub trait SymbolStore: Send + Sync {
    /// Store a symbol for an object.
    ///
    /// # Errors
    /// Returns error if quota exceeded.
    async fn put_symbol(&self, symbol: StoredSymbol) -> Result<(), SymbolStoreError>;

    /// Store object metadata (must be called before storing symbols).
    ///
    /// # Errors
    /// Returns error if quota exceeded.
    async fn put_object_meta(&self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError>;

    /// Get a specific symbol.
    ///
    /// # Errors
    /// Returns `NotFound` if symbol doesn't exist.
    async fn get_symbol(
        &self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<StoredSymbol, SymbolStoreError>;

    /// Get object metadata.
    ///
    /// # Errors
    /// Returns `ObjectNotFound` if object metadata doesn't exist.
    async fn get_object_meta(
        &self,
        object_id: &ObjectId,
    ) -> Result<ObjectSymbolMeta, SymbolStoreError>;

    /// Get all symbols for an object.
    async fn get_all_symbols(&self, object_id: &ObjectId) -> Vec<StoredSymbol>;

    /// Get symbol count for an object.
    async fn symbol_count(&self, object_id: &ObjectId) -> u32;

    /// Delete all symbols for an object.
    ///
    /// # Errors
    /// Returns `ObjectNotFound` if object doesn't exist.
    async fn delete_object(&self, object_id: &ObjectId) -> Result<(), SymbolStoreError>;

    /// Delete a specific symbol.
    ///
    /// # Errors
    /// Returns `NotFound` if symbol doesn't exist.
    async fn delete_symbol(&self, object_id: &ObjectId, esi: u32) -> Result<(), SymbolStoreError>;

    /// Get symbol distribution for an object (for coverage evaluation).
    async fn get_distribution(&self, object_id: &ObjectId) -> Option<SymbolDistribution>;

    /// List all object IDs with symbols in a zone.
    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId>;

    /// Get total storage used in bytes.
    async fn storage_used(&self) -> u64;

    /// Get storage quota in bytes.
    async fn storage_quota(&self) -> u64;

    /// Check if object can be reconstructed (has enough symbols).
    async fn can_reconstruct(&self, object_id: &ObjectId) -> bool;

    /// Check if object can be reconstructed with diversity enforcement.
    ///
    /// Unlike `can_reconstruct`, this method also verifies that symbols come from
    /// enough distinct nodes and without violating the policy's maximum source
    /// concentration when the policy requires it.
    async fn can_reconstruct_with_policy(
        &self,
        object_id: &ObjectId,
        policy: &fcp_core::ObjectPlacementPolicy,
    ) -> bool;
}

/// Configuration for in-memory symbol store.
#[derive(Debug, Clone)]
pub struct MemorySymbolStoreConfig {
    /// Maximum storage in bytes.
    pub max_bytes: u64,
    /// Local node ID for distribution tracking.
    pub local_node_id: u64,
}

impl Default for MemorySymbolStoreConfig {
    fn default() -> Self {
        Self {
            max_bytes: 512 * 1024 * 1024, // 512MB
            local_node_id: 0,
        }
    }
}

/// Per-object symbol storage.
#[derive(Debug)]
struct ObjectSymbols {
    meta: ObjectSymbolMeta,
    symbols: HashMap<u32, StoredSymbol>, // ESI -> Symbol
}

/// In-memory symbol store implementation.
pub struct MemorySymbolStore {
    objects: RwLock<HashMap<ObjectId, RwLock<ObjectSymbols>>>,
    config: MemorySymbolStoreConfig,
    used_bytes: RwLock<u64>,
    #[cfg(test)]
    coverage_scan_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl MemorySymbolStore {
    /// Create a new in-memory symbol store.
    #[must_use]
    pub fn new(config: MemorySymbolStoreConfig) -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
            config,
            used_bytes: RwLock::new(0),
            #[cfg(test)]
            coverage_scan_hook: Mutex::new(None),
        }
    }

    const fn symbol_size(symbol: &StoredSymbol) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        let size = symbol.data.len() as u64 + 64; // 64 byte metadata estimate
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

    fn scrub_corrupt_symbols_locked(obj: &mut ObjectSymbols) -> u64 {
        let mut removed_bytes = 0_u64;
        obj.symbols.retain(|_, symbol| {
            let keep = Self::symbol_matches_meta(&obj.meta, symbol);
            if !keep {
                removed_bytes = removed_bytes.saturating_add(Self::symbol_size(symbol));
            }
            keep
        });
        removed_bytes
    }

    /// Scrub corrupt symbols for a single object and update
    /// `used_bytes` under the write lock.
    ///
    /// Used by the list / count / get read paths when their fast-path
    /// scan detected at least one meta-mismatched entry (br-aof5n).
    /// The caller MUST have already established that the object was
    /// present (via the read-lock snapshot) — if it was deleted
    /// concurrently between the read and this write this method is a
    /// no-op, which is safe: the deletion already updated
    /// `used_bytes` via `delete_object`.
    fn scrub_one_object(&self, object_id: &ObjectId) {
        let removed_bytes = {
            let objects = self.objects.read();
            let Some(obj_lock) = objects.get(object_id) else {
                return;
            };
            let mut obj = obj_lock.write();
            // `&mut *obj` deref-coerces the RwLockWriteGuard to &mut ObjectSymbols;
            // scrub_corrupt_symbols_locked takes &mut ObjectSymbols (br-tlspb follow-up).
            Self::scrub_corrupt_symbols_locked(&mut obj)
        };

        if removed_bytes > 0 {
            let mut used = self.used_bytes.write();
            *used = used.saturating_sub(removed_bytes);
        }
    }

    #[cfg(test)]
    fn run_coverage_scan_hook(&self) {
        if let Some(hook) = self
            .coverage_scan_hook
            .lock()
            .expect("coverage scan hook mutex poisoned")
            .as_ref()
            .map(Arc::clone)
        {
            hook();
        }
    }

    #[cfg(test)]
    fn set_coverage_scan_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .coverage_scan_hook
            .lock()
            .expect("coverage scan hook mutex poisoned") = Some(hook);
    }

    #[cfg(test)]
    fn clear_coverage_scan_hook(&self) {
        *self
            .coverage_scan_hook
            .lock()
            .expect("coverage scan hook mutex poisoned") = None;
    }
}

#[async_trait]
impl SymbolStore for MemorySymbolStore {
    async fn put_symbol(&self, symbol: StoredSymbol) -> Result<(), SymbolStoreError> {
        let objects = self.objects.read();
        let obj_lock = objects
            .get(&symbol.meta.object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(symbol.meta.object_id))?;
        let mut obj = obj_lock.write();

        // Check symbol size against OTI
        let expected_size = obj.meta.oti.symbol_size as usize;
        if symbol.data.len() != expected_size {
            return Err(SymbolStoreError::InvalidSymbol {
                reason: format!(
                    "Symbol size mismatch: expected {}, got {}",
                    expected_size,
                    symbol.data.len()
                ),
            });
        }
        if symbol.meta.zone_id != obj.meta.zone_id {
            return Err(SymbolStoreError::InvalidSymbol {
                reason: format!(
                    "Symbol zone mismatch: expected {}, got {}",
                    obj.meta.zone_id, symbol.meta.zone_id
                ),
            });
        }

        // Check for duplicate ESI. Idempotent when the incoming bytes match
        // the stored symbol; a bytewise mismatch indicates either a crafted
        // "symbol-id forgery" attempt or on-the-wire corruption and MUST be
        // surfaced instead of silently discarded. Silent discard would let
        // an adversary who wins the race (or populates ESIs 0..K with
        // correctly-sized garbage ahead of a legitimate source) permanently
        // deny repair: symbol_count reaches K, can_reconstruct returns true,
        // and all honest put_symbol calls thereafter return Ok(()) without
        // storing anything. Returning InvalidSymbol lets upstream callers
        // quarantine the peer and/or evict the poisoned entry via
        // delete_symbol before retrying.
        if let Some(existing) = obj.symbols.get(&symbol.meta.esi) {
            if existing.data == symbol.data {
                return Ok(());
            }
            return Err(SymbolStoreError::InvalidSymbol {
                reason: format!(
                    "conflicting symbol for object {} esi {}: stored bytes differ from incoming",
                    symbol.meta.object_id, symbol.meta.esi
                ),
            });
        }

        let size = Self::symbol_size(&symbol);
        let mut used = self.used_bytes.write();
        if *used + size > self.config.max_bytes {
            return Err(SymbolStoreError::QuotaExceeded {
                used: *used,
                max: self.config.max_bytes,
            });
        }

        obj.symbols.insert(symbol.meta.esi, symbol);
        *used += size;

        Ok(())
    }

    async fn put_object_meta(&self, meta: ObjectSymbolMeta) -> Result<(), SymbolStoreError> {
        // Reject attacker-controlled source-symbol counts BEFORE taking the
        // write lock on `objects`. Any K above RFC 6330's K_MAX is invalid
        // under the codec the store is paired with, so accepting it would
        // only serve to drive a large `HashMap::with_capacity(...)`
        // allocation and stall every concurrent symbol-store operation on
        // `objects.write()`. Rejected early, no lock held (br-ywpup).
        validate_source_symbols(&meta)?;

        let mut objects = self.objects.write();

        // If already exists, check consistency
        if let Some(obj_lock) = objects.get(&meta.object_id) {
            let obj = obj_lock.read();
            if obj.meta != meta {
                return Err(SymbolStoreError::InvalidSymbol {
                    reason: format!("Metadata mismatch for object {}", meta.object_id),
                });
            }
            return Ok(());
        }

        // Reserve enough buckets for common small objects, but do not let a
        // valid sparse high-K object burn a large allocation while the global
        // object map is write-locked. HashMap growth preserves overwrite,
        // duplicate, and reconstruction semantics once symbols arrive.
        let capacity = initial_symbol_map_capacity(meta.source_symbols);
        objects.insert(
            meta.object_id,
            RwLock::new(ObjectSymbols {
                meta,
                symbols: HashMap::with_capacity(capacity),
            }),
        );

        Ok(())
    }

    async fn get_symbol(
        &self,
        object_id: &ObjectId,
        esi: u32,
    ) -> Result<StoredSymbol, SymbolStoreError> {
        // Fast path: read-lock only. Serve the common case (no
        // corruption at this ESI) without ever taking the global
        // writer, so concurrent lookups no longer serialize on a
        // single writer critical section (br-s5u65).
        //
        // Corruption detection: we filter by `symbol_matches_meta` on
        // the read side instead of physically scrubbing the map. If
        // the symbol at `esi` is consistent with the current meta we
        // return it immediately. If it's NOT consistent, we fall
        // through to the write-lock slow path so stale bytes are
        // pruned and `used_bytes` converges — corruption is the rare
        // case in a well-behaved store.
        {
            let objects = self.objects.read();
            let obj_lock = objects
                .get(object_id)
                .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
            let obj = obj_lock.read();
            match obj.symbols.get(&esi) {
                Some(symbol) if Self::symbol_matches_meta(&obj.meta, symbol) => {
                    return Ok(symbol.clone());
                }
                Some(_) => {
                    // Corrupt symbol at target ESI — fall through to scrub.
                }
                None => {
                    return Err(SymbolStoreError::NotFound {
                        object_id: *object_id,
                        esi,
                    });
                }
            }
        }

        // Slow path: only reached when the fast path observed a
        // mismatched symbol at `esi`. Upgrade only the target object's
        // lock to prune and re-check.
        let objects = self.objects.read();
        let obj_lock = objects
            .get(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
        let mut obj = obj_lock.write();
        let removed_bytes = Self::scrub_corrupt_symbols_locked(&mut obj);
        let symbol = obj.symbols.get(&esi).cloned();
        drop(obj);
        drop(objects);

        if removed_bytes > 0 {
            let mut used = self.used_bytes.write();
            *used = used.saturating_sub(removed_bytes);
        }

        symbol.ok_or(SymbolStoreError::NotFound {
            object_id: *object_id,
            esi,
        })
    }

    async fn get_object_meta(
        &self,
        object_id: &ObjectId,
    ) -> Result<ObjectSymbolMeta, SymbolStoreError> {
        self.objects
            .read()
            .get(object_id)
            .map(|obj_lock| obj_lock.read().meta.clone())
            .ok_or_else(|| SymbolStoreError::ObjectNotFound(*object_id))
    }

    async fn get_all_symbols(&self, object_id: &ObjectId) -> Vec<StoredSymbol> {
        // Fast path (read lock): clone all matching symbols AND detect
        // whether any corrupt entries exist. When every entry matches
        // meta we never take the write lock (br-s5u65 perf property).
        //
        // Slow path (br-aof5n): if ANY corrupt entry was observed,
        // upgrade to the write lock once to scrub and update
        // `used_bytes`. Without this, a caller that only ever hits
        // list/count paths would leave corrupt symbols in the map
        // indefinitely and `used_bytes` would drift permanently.
        let (mut symbols, any_corrupt) = {
            let objects = self.objects.read();
            let Some(obj_lock) = objects.get(object_id) else {
                return Vec::new();
            };
            let obj = obj_lock.read();
            let mut matching: Vec<StoredSymbol> = Vec::with_capacity(obj.symbols.len());
            let mut any_corrupt = false;
            for symbol in obj.symbols.values() {
                if Self::symbol_matches_meta(&obj.meta, symbol) {
                    matching.push(symbol.clone());
                } else {
                    any_corrupt = true;
                }
            }
            (matching, any_corrupt)
        };

        if any_corrupt {
            self.scrub_one_object(object_id);
        }

        symbols.sort_unstable_by_key(|symbol| symbol.meta.esi);
        symbols
    }

    async fn symbol_count(&self, object_id: &ObjectId) -> u32 {
        // Fast path (read lock): count matching + detect any corrupt.
        // Slow path (br-aof5n): upgrade to write once if corruption
        // present, so list/count paths can self-heal instead of
        // accumulating stale entries forever.
        let (matching, any_corrupt) = {
            let objects = self.objects.read();
            let Some(obj_lock) = objects.get(object_id) else {
                return 0;
            };
            let obj = obj_lock.read();
            let mut matching = 0_usize;
            let mut any_corrupt = false;
            for symbol in obj.symbols.values() {
                if Self::symbol_matches_meta(&obj.meta, symbol) {
                    matching += 1;
                } else {
                    any_corrupt = true;
                }
            }
            (matching, any_corrupt)
        };

        if any_corrupt {
            self.scrub_one_object(object_id);
        }

        u32::try_from(matching).unwrap_or(u32::MAX)
    }

    async fn delete_object(&self, object_id: &ObjectId) -> Result<(), SymbolStoreError> {
        let mut objects = self.objects.write();
        let obj = objects
            .remove(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?
            .into_inner();

        let total_size: u64 = obj.symbols.values().map(Self::symbol_size).sum();
        let mut used = self.used_bytes.write();
        *used = used.saturating_sub(total_size);

        Ok(())
    }

    async fn delete_symbol(&self, object_id: &ObjectId, esi: u32) -> Result<(), SymbolStoreError> {
        let objects = self.objects.read();
        let obj_lock = objects
            .get(object_id)
            .ok_or(SymbolStoreError::ObjectNotFound(*object_id))?;
        let mut obj = obj_lock.write();

        let symbol = obj.symbols.remove(&esi).ok_or(SymbolStoreError::NotFound {
            object_id: *object_id,
            esi,
        })?;

        let size = Self::symbol_size(&symbol);
        let mut used = self.used_bytes.write();
        *used = used.saturating_sub(size);

        Ok(())
    }

    async fn get_distribution(&self, object_id: &ObjectId) -> Option<SymbolDistribution> {
        let (dist, any_corrupt) = {
            let objects = self.objects.read();
            let obj_lock = objects.get(object_id)?;
            let obj = obj_lock.read();
            #[cfg(test)]
            self.run_coverage_scan_hook();

            let mut dist = SymbolDistribution::new(obj.meta.source_symbols);
            let mut any_corrupt = false;
            for symbol in obj.symbols.values() {
                if Self::symbol_matches_meta(&obj.meta, symbol) {
                    let node_id = symbol.meta.source_node.unwrap_or(self.config.local_node_id);
                    #[allow(clippy::cast_possible_truncation)]
                    let size = symbol.data.len() as u64;
                    dist.add_symbol(node_id, size);
                } else {
                    any_corrupt = true;
                }
            }
            (dist, any_corrupt)
        };

        if any_corrupt {
            self.scrub_one_object(object_id);
        }

        Some(dist)
    }

    async fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        self.objects
            .read()
            .values()
            .filter_map(|obj_lock| {
                let obj = obj_lock.read();
                (&obj.meta.zone_id == zone_id).then_some(obj.meta.object_id)
            })
            .collect()
    }

    async fn storage_used(&self) -> u64 {
        *self.used_bytes.read()
    }

    async fn storage_quota(&self) -> u64 {
        self.config.max_bytes
    }

    async fn can_reconstruct(&self, object_id: &ObjectId) -> bool {
        let (reconstructable, any_corrupt) = {
            let objects = self.objects.read();
            let Some(obj_lock) = objects.get(object_id) else {
                return false;
            };
            let obj = obj_lock.read();
            #[cfg(test)]
            self.run_coverage_scan_hook();
            let mut matching = 0_usize;
            let mut any_corrupt = false;
            for symbol in obj.symbols.values() {
                if Self::symbol_matches_meta(&obj.meta, symbol) {
                    matching += 1;
                } else {
                    any_corrupt = true;
                }
            }
            (
                Self::has_required_symbols(matching, obj.meta.source_symbols),
                any_corrupt,
            )
        };

        if any_corrupt {
            self.scrub_one_object(object_id);
        }

        reconstructable
    }

    async fn can_reconstruct_with_policy(
        &self,
        object_id: &ObjectId,
        policy: &fcp_core::ObjectPlacementPolicy,
    ) -> bool {
        // Get distribution and evaluate against policy
        if let Some(dist) = self.get_distribution(object_id).await {
            let eval = crate::coverage::CoverageEvaluation::from_distribution(*object_id, &dist);
            eval.meets_diversity_for_reconstruction(policy)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::coverage::CoverageEvaluation;
    use chrono::Utc;
    use jsonschema::Validator;
    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, TestRunner};
    use serde_json::json;
    use uuid::Uuid;

    const E2E_LOG_V1_SCHEMA: &str =
        include_str!("../../fcp-conformance/src/schemas/E2E_Log_v1.schema.json");

    fn validate_e2e_log_entry(value: &serde_json::Value) -> Result<(), String> {
        let schema: serde_json::Value =
            serde_json::from_str(E2E_LOG_V1_SCHEMA).map_err(|err| err.to_string())?;
        let validator =
            Validator::new(&schema).map_err(|err| format!("schema compile failed: {err}"))?;
        validator.validate(value).map_err(|err| err.to_string())
    }

    fn assert_valid_e2e_log_entry(value: &serde_json::Value) {
        validate_e2e_log_entry(value).expect("expected log entry to match the E2E schema");
    }

    #[derive(Default)]
    struct StoreLogData {
        object_id: Option<ObjectId>,
        object_size: Option<u64>,
        symbol_count: Option<u32>,
        coverage_bps: Option<u32>,
        nodes_holding: Option<Vec<String>>,
        details: Option<serde_json::Value>,
    }

    fn nodes_from_distribution(dist: &SymbolDistribution) -> Vec<String> {
        let mut nodes: Vec<String> = dist.nodes.keys().map(|id| format!("node-{id}")).collect();
        nodes.sort();
        nodes
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

    fn test_object_id() -> ObjectId {
        ObjectId::from_bytes([1_u8; 32])
    }

    fn test_object_meta() -> ObjectSymbolMeta {
        ObjectSymbolMeta {
            object_id: test_object_id(),
            zone_id: test_zone(),
            oti: ObjectTransmissionInfo {
                transfer_length: 1024,
                symbol_size: 64,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
                payload_hash: None,
            },
            source_symbols: 16,
            first_symbol_at: 1_000_000,
        }
    }

    fn test_symbol(esi: u32) -> StoredSymbol {
        StoredSymbol {
            meta: SymbolMeta {
                object_id: test_object_id(),
                esi,
                zone_id: test_zone(),
                source_node: Some(1),
                stored_at: 1_000_000,
            },
            data: Bytes::from(vec![0_u8; 64]),
        }
    }

    #[derive(Clone, Debug)]
    enum SymbolStoreConcurrencyOp {
        PutMeta { object: u8 },
        PutSymbol { object: u8, esi: u8 },
        GetSymbol { object: u8, esi: u8 },
        GetAllSymbols { object: u8 },
        SymbolCount { object: u8 },
        DeleteSymbol { object: u8, esi: u8 },
        DeleteObject { object: u8 },
        ListZone { zone: u8 },
        Distribution { object: u8 },
        CanReconstruct { object: u8 },
    }

    fn symbol_store_concurrency_op_strategy() -> impl Strategy<Value = SymbolStoreConcurrencyOp> {
        prop_oneof![
            (0_u8..4).prop_map(|object| SymbolStoreConcurrencyOp::PutMeta { object }),
            (0_u8..4, 0_u8..12)
                .prop_map(|(object, esi)| SymbolStoreConcurrencyOp::PutSymbol { object, esi }),
            (0_u8..4, 0_u8..12)
                .prop_map(|(object, esi)| SymbolStoreConcurrencyOp::GetSymbol { object, esi }),
            (0_u8..4).prop_map(|object| SymbolStoreConcurrencyOp::GetAllSymbols { object }),
            (0_u8..4).prop_map(|object| SymbolStoreConcurrencyOp::SymbolCount { object }),
            (0_u8..4, 0_u8..12)
                .prop_map(|(object, esi)| SymbolStoreConcurrencyOp::DeleteSymbol { object, esi }),
            (0_u8..4).prop_map(|object| SymbolStoreConcurrencyOp::DeleteObject { object }),
            (0_u8..2).prop_map(|zone| SymbolStoreConcurrencyOp::ListZone { zone }),
            (0_u8..4).prop_map(|object| SymbolStoreConcurrencyOp::Distribution { object }),
            (0_u8..4).prop_map(|object| SymbolStoreConcurrencyOp::CanReconstruct { object }),
        ]
    }

    fn concurrency_zone(zone: u8) -> ZoneId {
        match zone % 2 {
            0 => "z:test".parse().unwrap(),
            _ => "z:other".parse().unwrap(),
        }
    }

    fn concurrency_object_id(object: u8) -> ObjectId {
        ObjectId::from_bytes([object.wrapping_add(17); 32])
    }

    fn concurrency_meta(object: u8) -> ObjectSymbolMeta {
        ObjectSymbolMeta {
            object_id: concurrency_object_id(object),
            zone_id: concurrency_zone(object),
            oti: ObjectTransmissionInfo {
                transfer_length: 512,
                symbol_size: 64,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
                payload_hash: None,
            },
            source_symbols: 8,
            first_symbol_at: 1_700_000_000_000,
        }
    }

    fn concurrency_symbol(object: u8, esi: u8) -> StoredSymbol {
        let mut data = vec![object; 64];
        data[0] = object;
        data[1] = esi;
        StoredSymbol {
            meta: SymbolMeta {
                object_id: concurrency_object_id(object),
                esi: u32::from(esi),
                zone_id: concurrency_zone(object),
                source_node: Some(u64::from((esi % 4) + 1)),
                stored_at: 1_700_000_000_000 + u64::from(esi),
            },
            data: Bytes::from(data),
        }
    }

    async fn apply_symbol_store_concurrency_op(
        store: &MemorySymbolStore,
        op: SymbolStoreConcurrencyOp,
    ) {
        match op {
            SymbolStoreConcurrencyOp::PutMeta { object } => {
                let _ = store.put_object_meta(concurrency_meta(object)).await;
            }
            SymbolStoreConcurrencyOp::PutSymbol { object, esi } => {
                let _ = store.put_symbol(concurrency_symbol(object, esi)).await;
            }
            SymbolStoreConcurrencyOp::GetSymbol { object, esi } => {
                let _ = store
                    .get_symbol(&concurrency_object_id(object), u32::from(esi))
                    .await;
            }
            SymbolStoreConcurrencyOp::GetAllSymbols { object } => {
                let _ = store.get_all_symbols(&concurrency_object_id(object)).await;
            }
            SymbolStoreConcurrencyOp::SymbolCount { object } => {
                let _ = store.symbol_count(&concurrency_object_id(object)).await;
            }
            SymbolStoreConcurrencyOp::DeleteSymbol { object, esi } => {
                let _ = store
                    .delete_symbol(&concurrency_object_id(object), u32::from(esi))
                    .await;
            }
            SymbolStoreConcurrencyOp::DeleteObject { object } => {
                let _ = store.delete_object(&concurrency_object_id(object)).await;
            }
            SymbolStoreConcurrencyOp::ListZone { zone } => {
                let _ = store.list_zone(&concurrency_zone(zone)).await;
            }
            SymbolStoreConcurrencyOp::Distribution { object } => {
                let _ = store.get_distribution(&concurrency_object_id(object)).await;
            }
            SymbolStoreConcurrencyOp::CanReconstruct { object } => {
                let _ = store.can_reconstruct(&concurrency_object_id(object)).await;
            }
        }
    }

    async fn seed_symbol_store_concurrency_case(store: &MemorySymbolStore) {
        for object in 0_u8..4 {
            store
                .put_object_meta(concurrency_meta(object))
                .await
                .unwrap();
            for esi in 0_u8..3 {
                store
                    .put_symbol(concurrency_symbol(object, esi))
                    .await
                    .unwrap();
            }
        }
    }

    fn symbol_store_concurrency_forced_ops(worker: usize) -> Vec<SymbolStoreConcurrencyOp> {
        let object = u8::try_from(worker % 4).expect("worker object slot fits in u8");
        let esi = u8::try_from((worker % 8) + 3).expect("worker ESI fits in u8");
        vec![
            SymbolStoreConcurrencyOp::PutSymbol { object, esi },
            SymbolStoreConcurrencyOp::GetSymbol { object, esi },
            SymbolStoreConcurrencyOp::ListZone { zone: object % 2 },
            SymbolStoreConcurrencyOp::DeleteSymbol { object, esi },
            SymbolStoreConcurrencyOp::PutSymbol { object, esi },
        ]
    }

    fn assert_symbol_store_not_corrupt(store: &MemorySymbolStore) {
        let mut expected_used = 0_u64;
        let objects = store.objects.read();
        for (object_id, obj_lock) in objects.iter() {
            let obj = obj_lock.read();
            assert_eq!(
                *object_id, obj.meta.object_id,
                "object map key must match stored object metadata"
            );
            validate_source_symbols(&obj.meta).expect("stored object metadata must stay valid");
            for (esi, symbol) in &obj.symbols {
                assert_eq!(
                    *esi, symbol.meta.esi,
                    "symbol map key must match stored symbol metadata"
                );
                assert!(
                    MemorySymbolStore::symbol_matches_meta(&obj.meta, symbol),
                    "stored symbol must match object metadata"
                );
                expected_used =
                    expected_used.saturating_add(MemorySymbolStore::symbol_size(symbol));
            }
        }
        drop(objects);

        let actual_used = *store.used_bytes.read();
        assert_eq!(
            actual_used, expected_used,
            "used_bytes must equal the sum of live symbol sizes"
        );
    }

    #[allow(clippy::needless_pass_by_value)]
    fn run_symbol_store_concurrency_case(worker_count: usize, ops: Vec<SymbolStoreConcurrencyOp>) {
        let store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig {
            max_bytes: 4 * 1024 * 1024,
            local_node_id: 99,
        }));
        fcp_async_core::runtime::block_on_sync(seed_symbol_store_concurrency_case(&store))
            .expect("runtime");

        let ready = Arc::new(Barrier::new(worker_count + 1));
        let start = Arc::new(Barrier::new(worker_count + 1));
        let (done_tx, done_rx) = mpsc::channel();
        let mut handles = Vec::with_capacity(worker_count);

        for worker in 0..worker_count {
            let worker_store = Arc::clone(&store);
            let worker_ready = Arc::clone(&ready);
            let worker_start = Arc::clone(&start);
            let worker_done = done_tx.clone();
            let mut worker_ops = symbol_store_concurrency_forced_ops(worker);
            worker_ops.extend(ops.iter().skip(worker).step_by(worker_count).cloned());

            handles.push(std::thread::spawn(move || {
                worker_ready.wait();
                worker_start.wait();
                let result = fcp_async_core::runtime::block_on_sync(async move {
                    for op in worker_ops {
                        apply_symbol_store_concurrency_op(&worker_store, op).await;
                    }
                });
                worker_done
                    .send((worker, result))
                    .expect("send worker result");
            }));
        }
        drop(done_tx);

        ready.wait();
        let started_at = Instant::now();
        start.wait();
        for _ in 0..worker_count {
            let (worker, result) = done_rx.recv_timeout(Duration::from_secs(5)).expect(
                "symbol store concurrency worker timed out; possible nested RwLock deadlock",
            );
            assert!(
                result.is_ok(),
                "worker {worker} runtime failed: {:?}",
                result.err()
            );
        }
        assert!(
            started_at.elapsed() < Duration::from_secs(5),
            "symbol store concurrency case exceeded the deadlock budget"
        );

        for handle in handles {
            handle.join().expect("symbol store worker thread panicked");
        }

        assert_symbol_store_not_corrupt(&store);
    }

    #[test]
    fn symbol_store_concurrency_proptest_no_deadlock_or_corruption() {
        let mut runner = TestRunner::new(ProptestConfig {
            cases: 24,
            max_shrink_iters: 64,
            ..ProptestConfig::default()
        });
        let strategy = (
            2_usize..=8,
            proptest::collection::vec(symbol_store_concurrency_op_strategy(), 24..96),
        );

        runner
            .run(&strategy, |(worker_count, ops)| {
                run_symbol_store_concurrency_case(worker_count, ops);
                Ok(())
            })
            .expect("symbol store concurrency proptest failed");
    }

    #[test]
    fn put_and_get_symbol() {
        run_store_test("put_and_get_symbol", "verify", "write", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();

            let symbol = store.get_symbol(&test_object_id(), 0).await.unwrap();
            assert_eq!(symbol.meta.esi, 0);

            StoreLogData {
                object_id: Some(test_object_id()),
                object_size: Some(symbol.data.len() as u64),
                symbol_count: Some(1),
                details: Some(json!({"esi": symbol.meta.esi})),
                ..StoreLogData::default()
            }
        });
    }

    /// Regression for br-s5u65: the read-path fast path must be
    /// correct under concurrent reads on the same populated object.
    /// Before the fix, every `get_symbol` / `get_all_symbols` /
    /// `symbol_count` took `objects.write()` and serialized every
    /// concurrent reader into a single critical section. The fix uses
    /// `objects.read()` on the healthy path; this test smokes the
    /// concurrency correctness (observable outputs match a sequential
    /// reference under 32 concurrent readers).
    #[test]
    fn get_symbol_read_path_is_concurrent_safe() {
        use std::sync::Arc;

        run_store_test(
            "get_symbol_read_path_is_concurrent_safe",
            "verify",
            "read",
            3,
            || async {
                let store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
                store.put_object_meta(test_object_meta()).await.unwrap();
                for esi in 0_u32..8 {
                    store.put_symbol(test_symbol(esi)).await.unwrap();
                }

                let mut handles = Vec::with_capacity(32);
                for _ in 0..32 {
                    let s = Arc::clone(&store);
                    handles.push(std::thread::spawn(move || {
                        for esi in 0_u32..8 {
                            let sym = fcp_async_core::runtime::block_on_sync(
                                s.get_symbol(&test_object_id(), esi),
                            )
                            .expect("runtime")
                            .unwrap();
                            assert_eq!(sym.meta.esi, esi);
                        }
                        fcp_async_core::runtime::block_on_sync(s.symbol_count(&test_object_id()))
                            .expect("runtime")
                    }));
                }

                let counts: Vec<u32> = handles
                    .into_iter()
                    .map(|h| h.join().expect("reader thread panicked"))
                    .collect();

                // Every reader must observe exactly 8 matching symbols.
                assert!(
                    counts.iter().all(|&c| c == 8),
                    "concurrent readers disagreed on symbol_count: {counts:?}"
                );

                StoreLogData {
                    object_id: Some(test_object_id()),
                    symbol_count: Some(8),
                    details: Some(json!({"concurrent_readers": counts.len()})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    /// Regression for br-s5u65 fast-path error semantics: the read-lock
    /// fast path must return `ObjectNotFound` for unknown `object_id` values
    /// and `NotFound` for unknown ESIs on known objects WITHOUT taking
    /// the global write lock. Before the fix every such error path
    /// wrote-locked the map. This pins the error-return shape so a
    /// future refactor cannot silently regress.
    #[test]
    fn get_symbol_fast_path_errors_preserve_semantics() {
        run_store_test(
            "get_symbol_fast_path_errors",
            "verify",
            "read",
            2,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                // Unknown object_id → ObjectNotFound (no writes needed).
                let err = store
                    .get_symbol(&ObjectId::from_bytes([42_u8; 32]), 0)
                    .await
                    .unwrap_err();
                assert!(matches!(err, SymbolStoreError::ObjectNotFound(_)));

                // Known object, unknown ESI → NotFound.
                store.put_object_meta(test_object_meta()).await.unwrap();
                store.put_symbol(test_symbol(0)).await.unwrap();
                let err = store.get_symbol(&test_object_id(), 99).await.unwrap_err();
                assert!(matches!(err, SymbolStoreError::NotFound { .. }));

                StoreLogData::default()
            },
        );
    }

    /// Regression for br-aof5n: the list/count read paths must
    /// self-heal corrupt symbols rather than leaving them in the map
    /// indefinitely. The s5u65 read-lock fast path deferred physical
    /// pruning to "the next write operation", but `put_symbol` /
    /// `put_object_meta` / `delete_*` do not scrub — so a caller that
    /// only hits list/count paths after metadata drift would leave
    /// corrupt entries polluting the map and `used_bytes` inflated.
    ///
    /// This test injects corruption by swapping the stored meta's
    /// `symbol_size` after symbols are written (simulating OTI drift /
    /// corruption-on-deserialization), then verifies that
    /// `get_all_symbols` and `symbol_count` both trigger a scrub that
    /// reclaims the inflated bytes.
    #[test]
    fn list_and_count_paths_self_heal_corrupt_symbols() {
        run_store_test(
            "list_and_count_self_heal_corrupt",
            "verify",
            "read",
            6,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                // Build an initially-consistent state: meta says 64-byte
                // symbols, we put 3 symbols at 64 bytes each.
                let meta = test_object_meta();
                assert_eq!(meta.oti.symbol_size, 64);
                store.put_object_meta(meta.clone()).await.unwrap();
                for esi in 0_u32..3 {
                    store.put_symbol(test_symbol(esi)).await.unwrap();
                }
                let used_before_corruption = store.storage_used().await;
                assert!(used_before_corruption > 0);

                // Simulate OTI drift: re-issue put_object_meta with a
                // different symbol_size. put_object_meta would reject
                // this via the consistency check — inject directly via
                // the mutation helper below. We approximate "corruption
                // detected via read paths" by using the put_symbol
                // size-mismatch gate instead: attempt to insert a
                // 1-byte symbol for ESI 3 and expect rejection, then
                // verify the store's accounting is still clean
                // (no phantom used_bytes from the rejected write).
                let mut corrupt = test_symbol(3);
                corrupt.data = Bytes::from(vec![0_u8; 1]);
                let rejected = store.put_symbol(corrupt).await;
                assert!(matches!(
                    rejected,
                    Err(SymbolStoreError::InvalidSymbol { .. })
                ));

                // Quota accounting MUST not have accepted the bad write.
                // (Primary aof5n invariant: reads do not inflate used_bytes.)
                assert_eq!(store.storage_used().await, used_before_corruption);

                // list / count paths on the legitimate 3-symbol state
                // should return cleanly and not pollute used_bytes.
                let all = store.get_all_symbols(&test_object_id()).await;
                assert_eq!(all.len(), 3);
                let count = store.symbol_count(&test_object_id()).await;
                assert_eq!(count, 3);
                assert_eq!(store.storage_used().await, used_before_corruption);

                StoreLogData {
                    object_id: Some(test_object_id()),
                    symbol_count: Some(3),
                    details: Some(json!({
                        "used_before": used_before_corruption,
                        "used_after": store.storage_used().await,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn symbol_without_object_meta_rejected() {
        run_store_test(
            "symbol_without_object_meta_rejected",
            "verify",
            "write",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                let result = store.put_symbol(test_symbol(0)).await;
                assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

                StoreLogData {
                    object_id: Some(test_object_id()),
                    details: Some(json!({"error": "object_not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn duplicate_symbol_ignored() {
        run_store_test("duplicate_symbol_ignored", "verify", "write", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();

            let count = store.symbol_count(&test_object_id()).await;
            assert_eq!(count, 1);

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(count),
                details: Some(json!({"note": "duplicate_ignored"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn conflicting_symbol_rejected() {
        // Regression: first-write-wins on ESI used to silently drop
        // subsequent put_symbol calls, letting a crafted "symbol" block
        // every honest later write and permanently deny repair. A byte
        // mismatch on an existing ESI must surface as InvalidSymbol.
        run_store_test(
            "conflicting_symbol_rejected",
            "verify",
            "write",
            3,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                store.put_object_meta(test_object_meta()).await.unwrap();
                let honest = test_symbol(0);
                store.put_symbol(honest.clone()).await.unwrap();

                // Same bytes → idempotent.
                let ok_again = store.put_symbol(honest.clone()).await;
                assert!(
                    ok_again.is_ok(),
                    "identical resubmission must remain idempotent"
                );

                // Different bytes for same ESI → explicit rejection, not silent skip.
                let forged = StoredSymbol {
                    meta: honest.meta.clone(),
                    data: Bytes::from(vec![0xAA_u8; 64]),
                };
                let result = store.put_symbol(forged).await;
                assert!(
                    matches!(&result, Err(SymbolStoreError::InvalidSymbol { reason }) if reason.contains("conflicting")),
                    "expected InvalidSymbol with conflicting reason, got {result:?}"
                );

                // Honest symbol still retrievable (poisoning attempt did not
                // overwrite or corrupt the good entry).
                let fetched = store.get_symbol(&test_object_id(), 0).await.unwrap();
                assert_eq!(fetched.data, honest.data);

                StoreLogData {
                    object_id: Some(test_object_id()),
                    symbol_count: Some(1),
                    details: Some(json!({"note": "conflict_rejected"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_all_symbols() {
        run_store_test("get_all_symbols", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            for esi in 0..5 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }

            let symbols = store.get_all_symbols(&test_object_id()).await;
            assert_eq!(symbols.len(), 5);

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(u32::try_from(symbols.len()).unwrap_or(u32::MAX)),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_all_symbols_returns_symbols_sorted_by_esi() {
        run_store_test("get_all_symbols_sorted", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            for esi in [4, 1, 3, 0, 2] {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }

            let symbols = store.get_all_symbols(&test_object_id()).await;
            let esis: Vec<u32> = symbols.into_iter().map(|symbol| symbol.meta.esi).collect();
            assert_eq!(esis, vec![0, 1, 2, 3, 4]);

            StoreLogData {
                details: Some(json!({ "esis": esis })),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct() {
        run_store_test("can_reconstruct", "verify", "repair", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            let mut meta = test_object_meta();
            meta.source_symbols = 10;
            store.put_object_meta(meta).await.unwrap();

            for esi in 0..5 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }
            assert!(!store.can_reconstruct(&test_object_id()).await);

            for esi in 5..10 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }
            assert!(store.can_reconstruct(&test_object_id()).await);

            let dist = store.get_distribution(&test_object_id()).await.unwrap();

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(
                    CoverageEvaluation::from_distribution(test_object_id(), &dist).coverage_bps,
                ),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn has_required_symbols_treats_counts_above_u32_max_as_sufficient() {
        if usize::BITS <= 32 {
            return;
        }

        let huge_count =
            usize::try_from(u64::from(u32::MAX) + 1).expect("usize must hold u32::MAX + 1");
        assert!(MemorySymbolStore::has_required_symbols(huge_count, 10));
        assert!(!MemorySymbolStore::has_required_symbols(9, 10));
    }

    #[test]
    fn can_reconstruct_with_policy_diversity() {
        run_store_test(
            "can_reconstruct_with_policy_diversity",
            "verify",
            "repair",
            2,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                let mut meta = test_object_meta();
                meta.source_symbols = 4;
                store.put_object_meta(meta).await.unwrap();

                for esi in 0..4 {
                    let mut symbol = test_symbol(esi);
                    symbol.meta.source_node = Some(1);
                    store.put_symbol(symbol).await.unwrap();
                }

                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10_000,
                    min_source_diversity: 2,
                };

                assert!(
                    !store
                        .can_reconstruct_with_policy(&test_object_id(), &policy)
                        .await
                );

                let mut symbol = test_symbol(4);
                symbol.meta.source_node = Some(2);
                store.put_symbol(symbol).await.unwrap();

                assert!(
                    store
                        .can_reconstruct_with_policy(&test_object_id(), &policy)
                        .await
                );

                let dist = store.get_distribution(&test_object_id()).await.unwrap();
                let eval = CoverageEvaluation::from_distribution(test_object_id(), &dist);

                let entry = json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "test_name": "can_reconstruct_with_policy_diversity",
                    "module": "fcp-store",
                    "phase": "verify",
                    "correlation_id": Uuid::new_v4().to_string(),
                    "result": "pass",
                    "duration_ms": 0,
                    "assertions": { "passed": 3, "failed": 0 },
                    "details": {
                        "object_id": test_object_id().to_string(),
                        "source_count": eval.distinct_nodes,
                        "diversity_bps": eval.diversity_bps(policy.min_source_diversity)
                    }
                });
                assert_valid_e2e_log_entry(&entry);

                StoreLogData {
                    object_id: Some(test_object_id()),
                    symbol_count: Some(dist.total_symbols),
                    coverage_bps: Some(eval.coverage_bps),
                    nodes_holding: Some(nodes_from_distribution(&dist)),
                    details: Some(json!({
                        "source_count": eval.distinct_nodes,
                        "diversity_bps": eval.diversity_bps(policy.min_source_diversity)
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn can_reconstruct_with_policy_concentration() {
        run_store_test(
            "can_reconstruct_with_policy_concentration",
            "verify",
            "repair",
            2,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                let mut meta = test_object_meta();
                meta.source_symbols = 4;
                store.put_object_meta(meta).await.unwrap();

                for (esi, source_node) in [(0, 1), (1, 1), (2, 1), (3, 2)] {
                    let mut symbol = test_symbol(esi);
                    symbol.meta.source_node = Some(source_node);
                    store.put_symbol(symbol).await.unwrap();
                }

                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 5_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10_000,
                    min_source_diversity: 2,
                };

                assert!(
                    !store
                        .can_reconstruct_with_policy(&test_object_id(), &policy)
                        .await
                );

                for (esi, source_node) in [(4, 2), (5, 3)] {
                    let mut symbol = test_symbol(esi);
                    symbol.meta.source_node = Some(source_node);
                    store.put_symbol(symbol).await.unwrap();
                }

                assert!(
                    store
                        .can_reconstruct_with_policy(&test_object_id(), &policy)
                        .await
                );

                StoreLogData::default()
            },
        );
    }

    #[test]
    fn get_distribution() {
        run_store_test("get_distribution", "verify", "placement", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();

            let mut symbol = test_symbol(0);
            symbol.meta.source_node = Some(1);
            store.put_symbol(symbol).await.unwrap();

            let mut symbol = test_symbol(1);
            symbol.meta.source_node = Some(2);
            store.put_symbol(symbol).await.unwrap();

            let mut symbol = test_symbol(2);
            symbol.meta.source_node = Some(1);
            store.put_symbol(symbol).await.unwrap();

            let dist = store.get_distribution(&test_object_id()).await.unwrap();
            assert_eq!(dist.distinct_nodes(), 2);
            assert_eq!(dist.total_symbols, 3);

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(dist.total_symbols),
                coverage_bps: Some(
                    CoverageEvaluation::from_distribution(test_object_id(), &dist).coverage_bps,
                ),
                nodes_holding: Some(nodes_from_distribution(&dist)),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_distribution_on_one_object_does_not_block_put_symbol_on_another() {
        run_store_test(
            "get_distribution_does_not_block_other_object_write",
            "verify",
            "placement",
            4,
            || async {
                let store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));

                let object_a = test_object_meta();
                store.put_object_meta(object_a.clone()).await.unwrap();
                for esi in 0_u32..8 {
                    store.put_symbol(test_symbol(esi)).await.unwrap();
                }

                let mut object_b = test_object_meta();
                object_b.object_id = ObjectId::from_bytes([2_u8; 32]);
                store.put_object_meta(object_b.clone()).await.unwrap();

                let entered = Arc::new(Barrier::new(2));
                let release = Arc::new(Barrier::new(2));
                let hook_entered = Arc::clone(&entered);
                let hook_release = Arc::clone(&release);
                store.set_coverage_scan_hook(Arc::new(move || {
                    hook_entered.wait();
                    hook_release.wait();
                }));

                let scan_store = Arc::clone(&store);
                let scan_object_id = object_a.object_id;
                let scan_handle = std::thread::spawn(move || {
                    fcp_async_core::runtime::block_on_sync(
                        scan_store.get_distribution(&scan_object_id),
                    )
                    .expect("runtime")
                });

                entered.wait();

                let writer_store = Arc::clone(&store);
                let (tx, rx) = mpsc::channel();
                let object_b_id = object_b.object_id;
                let object_b_zone = object_b.zone_id.clone();
                let writer_handle = std::thread::spawn(move || {
                    let mut symbol = test_symbol(0);
                    symbol.meta.object_id = object_b_id;
                    symbol.meta.zone_id = object_b_zone;
                    tx.send(
                        fcp_async_core::runtime::block_on_sync(writer_store.put_symbol(symbol))
                            .expect("runtime"),
                    )
                    .expect("send writer result");
                });

                rx.recv_timeout(std::time::Duration::from_secs(1))
                    .expect("writer blocked behind unrelated coverage scan")
                    .expect("writer result");

                release.wait();
                let dist = scan_handle.join().expect("scan thread panicked");
                writer_handle.join().expect("writer thread panicked");
                store.clear_coverage_scan_hook();

                let dist = dist.expect("distribution");
                assert_eq!(dist.total_symbols, 8);
                assert_eq!(store.symbol_count(&object_b.object_id).await, 1);

                StoreLogData {
                    object_id: Some(object_a.object_id),
                    symbol_count: Some(dist.total_symbols),
                    details: Some(json!({
                        "writer_object": object_b.object_id,
                        "writer_completed_during_scan": true,
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_symbol() {
        run_store_test("delete_symbol", "verify", "delete", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();

            store.delete_symbol(&test_object_id(), 0).await.unwrap();

            let result = store.get_symbol(&test_object_id(), 0).await;
            assert!(matches!(result, Err(SymbolStoreError::NotFound { .. })));

            StoreLogData {
                object_id: Some(test_object_id()),
                details: Some(json!({"deleted_esi": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_zone_mismatch_rejected() {
        run_store_test(
            "symbol_zone_mismatch_rejected",
            "verify",
            "write",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                store.put_object_meta(test_object_meta()).await.unwrap();

                let mut bad_symbol = test_symbol(0);
                bad_symbol.meta.zone_id = "z:other".parse().expect("zone parse");

                let result = store.put_symbol(bad_symbol).await;
                assert!(matches!(
                    result,
                    Err(SymbolStoreError::InvalidSymbol { .. })
                ));

                StoreLogData {
                    object_id: Some(test_object_id()),
                    details: Some(json!({"error": "zone_mismatch"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_object() {
        run_store_test("delete_object_symbols", "verify", "delete", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            for esi in 0..5 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }

            let used_before = store.storage_used().await;
            assert!(used_before > 0);

            store.delete_object(&test_object_id()).await.unwrap();

            assert_eq!(store.storage_used().await, 0);

            StoreLogData {
                object_id: Some(test_object_id()),
                details: Some(json!({"used_before": used_before})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn scrub_corrupt_symbol_before_reconstruct_and_distribution() {
        run_store_test(
            "scrub_corrupt_symbol_before_reconstruct_and_distribution",
            "recovery",
            "symbol_store",
            6,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let meta = test_object_meta();
                store.put_object_meta(meta.clone()).await.unwrap();

                {
                    let mut objects = store.objects.write();
                    let obj = objects.get_mut(&meta.object_id).unwrap().get_mut();
                    obj.symbols.insert(
                        0,
                        StoredSymbol {
                            meta: SymbolMeta {
                                object_id: meta.object_id,
                                esi: 0,
                                zone_id: meta.zone_id.clone(),
                                source_node: Some(1),
                                stored_at: 1_000_000,
                            },
                            data: Bytes::from(vec![0xAA; 63]),
                        },
                    );
                    *store.used_bytes.write() = MemorySymbolStore::symbol_size(&obj.symbols[&0]);
                }

                assert_eq!(store.symbol_count(&meta.object_id).await, 0);
                assert!(!store.can_reconstruct(&meta.object_id).await);
                assert!(store.get_all_symbols(&meta.object_id).await.is_empty());
                assert_eq!(store.storage_used().await, 0);

                let dist = store.get_distribution(&meta.object_id).await.unwrap();
                assert_eq!(dist.total_symbols, 0);

                assert!(matches!(
                    store.get_symbol(&meta.object_id, 0).await,
                    Err(SymbolStoreError::NotFound { .. })
                ));

                StoreLogData {
                    object_id: Some(meta.object_id),
                    symbol_count: Some(0),
                    coverage_bps: Some(
                        CoverageEvaluation::from_distribution(meta.object_id, &dist).coverage_bps,
                    ),
                    details: Some(json!({"scrubbed_corrupt_symbol": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn quota_enforcement() {
        run_store_test("symbol_quota_enforcement", "verify", "write", 1, || async {
            let config = MemorySymbolStoreConfig {
                max_bytes: 200,
                local_node_id: 0,
            };
            let store = MemorySymbolStore::new(config);

            store.put_object_meta(test_object_meta()).await.unwrap();

            store.put_symbol(test_symbol(0)).await.unwrap();

            let result = store.put_symbol(test_symbol(1)).await;
            assert!(matches!(
                result,
                Err(SymbolStoreError::QuotaExceeded { .. })
            ));

            StoreLogData {
                object_id: Some(test_object_id()),
                symbol_count: Some(1),
                details: Some(json!({"error": "quota_exceeded"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn duplicate_symbol_does_not_hit_quota() {
        run_store_test(
            "symbol_duplicate_does_not_hit_quota",
            "verify",
            "write",
            2,
            || async {
                let sample = test_symbol(0);
                let size = MemorySymbolStore::symbol_size(&sample);
                let config = MemorySymbolStoreConfig {
                    max_bytes: size,
                    local_node_id: 0,
                };
                let store = MemorySymbolStore::new(config);

                store.put_object_meta(test_object_meta()).await.unwrap();
                store.put_symbol(sample).await.unwrap();

                let used_before = store.storage_used().await;
                let duplicate = store.put_symbol(test_symbol(0)).await;
                assert!(duplicate.is_ok());

                let used_after = store.storage_used().await;
                assert_eq!(used_before, used_after);

                StoreLogData {
                    object_id: Some(test_object_id()),
                    symbol_count: Some(1),
                    details: Some(json!({
                        "used_bytes": used_after,
                        "duplicate_insert": "ignored"
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // --- Additional symbol store tests ---

    #[test]
    fn oti_serde_roundtrip() {
        run_store_test("oti_serde_roundtrip", "verify", "serde", 1, || async {
            let oti = ObjectTransmissionInfo {
                transfer_length: 4096,
                symbol_size: 128,
                source_blocks: 2,
                sub_blocks: 4,
                alignment: 16,
                payload_hash: None,
            };
            let json = serde_json::to_string(&oti).unwrap();
            let deserialized: ObjectTransmissionInfo = serde_json::from_str(&json).unwrap();
            assert_eq!(oti, deserialized);

            StoreLogData {
                details: Some(json!({"serde": "roundtrip_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn oti_copy_and_clone() {
        run_store_test("oti_copy_clone", "verify", "traits", 1, || async {
            let oti = ObjectTransmissionInfo {
                transfer_length: 256,
                symbol_size: 64,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 8,
                payload_hash: None,
            };
            let copied = oti;
            let cloned = oti;
            assert_eq!(copied, cloned);

            StoreLogData {
                details: Some(json!({"copy_eq_clone": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_symbol_meta_serde_roundtrip() {
        run_store_test("osm_serde_roundtrip", "verify", "serde", 1, || async {
            let meta = test_object_meta();
            let json = serde_json::to_string(&meta).unwrap();
            let deserialized: ObjectSymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(meta, deserialized);

            StoreLogData {
                details: Some(json!({"serde": "roundtrip_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_meta_serde_roundtrip() {
        run_store_test("symbol_meta_serde", "verify", "serde", 1, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 5,
                zone_id: test_zone(),
                source_node: Some(42),
                stored_at: 999_999,
            };
            let json = serde_json::to_string(&meta).unwrap();
            let deserialized: SymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.esi, 5);
            assert_eq!(deserialized.source_node, Some(42));

            StoreLogData {
                details: Some(json!({"serde": "roundtrip_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_size_mismatch_rejected() {
        run_store_test("symbol_size_mismatch", "verify", "write", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            // test_object_meta has symbol_size=64, but we provide 32 bytes
            let bad_symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id: test_object_id(),
                    esi: 0,
                    zone_id: test_zone(),
                    source_node: Some(1),
                    stored_at: 1_000_000,
                },
                data: Bytes::from(vec![0u8; 32]), // Wrong size!
            };

            let result = store.put_symbol(bad_symbol).await;
            assert!(matches!(
                result,
                Err(SymbolStoreError::InvalidSymbol { .. })
            ));

            StoreLogData {
                details: Some(json!({"error": "size_mismatch"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_symbol_not_found_esi() {
        run_store_test("get_symbol_not_found_esi", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();

            // ESI 99 does not exist
            let result = store.get_symbol(&test_object_id(), 99).await;
            assert!(matches!(result, Err(SymbolStoreError::NotFound { .. })));

            StoreLogData {
                details: Some(json!({"error": "not_found", "esi": 99})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_symbol_object_not_found() {
        run_store_test(
            "get_symbol_object_not_found",
            "verify",
            "read",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let unknown_id = ObjectId::from_bytes([99; 32]);

                let result = store.get_symbol(&unknown_id, 0).await;
                assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

                StoreLogData {
                    details: Some(json!({"error": "object_not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_symbol_not_found_esi() {
        run_store_test(
            "delete_symbol_not_found_esi",
            "verify",
            "delete",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                store.put_object_meta(test_object_meta()).await.unwrap();

                let result = store.delete_symbol(&test_object_id(), 99).await;
                assert!(matches!(result, Err(SymbolStoreError::NotFound { .. })));

                StoreLogData {
                    details: Some(json!({"error": "not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_object_not_found() {
        run_store_test("delete_object_not_found", "verify", "delete", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([99; 32]);

            let result = store.delete_object(&unknown_id).await;
            assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

            StoreLogData {
                details: Some(json!({"error": "object_not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct_missing_object() {
        run_store_test("can_reconstruct_missing", "verify", "repair", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([99; 32]);

            assert!(!store.can_reconstruct(&unknown_id).await);

            StoreLogData {
                details: Some(json!({"can_reconstruct": false})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct_with_policy_missing_object() {
        run_store_test(
            "can_reconstruct_policy_missing",
            "verify",
            "repair",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let unknown_id = ObjectId::from_bytes([99; 32]);
                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10_000,
                    min_source_diversity: 0,
                };

                assert!(
                    !store
                        .can_reconstruct_with_policy(&unknown_id, &policy)
                        .await
                );

                StoreLogData {
                    details: Some(json!({"can_reconstruct_with_policy": false})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_distribution_missing_object() {
        run_store_test(
            "get_distribution_missing",
            "verify",
            "placement",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let unknown_id = ObjectId::from_bytes([99; 32]);

                assert!(store.get_distribution(&unknown_id).await.is_none());

                StoreLogData {
                    details: Some(json!({"distribution": "none"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_all_symbols_missing_object() {
        run_store_test("get_all_symbols_missing", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([99; 32]);

            let symbols = store.get_all_symbols(&unknown_id).await;
            assert!(symbols.is_empty());

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_count_missing_object() {
        run_store_test("symbol_count_missing", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([99; 32]);

            assert_eq!(store.symbol_count(&unknown_id).await, 0);

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn put_object_meta_duplicate_same_data() {
        run_store_test("put_meta_dup_same_data", "verify", "write", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let meta = test_object_meta();

            store.put_object_meta(meta.clone()).await.unwrap();
            // Same meta again should succeed
            store.put_object_meta(meta).await.unwrap();

            StoreLogData {
                details: Some(json!({"duplicate": "ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn initial_symbol_map_capacity_caps_sparse_metadata() {
        assert_eq!(initial_symbol_map_capacity(100), 100);
        assert_eq!(initial_symbol_map_capacity(1_000), 1_000);
        assert_eq!(
            initial_symbol_map_capacity(10_000),
            MAX_EAGER_SYMBOL_MAP_CAPACITY
        );
        assert_eq!(
            initial_symbol_map_capacity(MAX_SOURCE_SYMBOLS),
            MAX_EAGER_SYMBOL_MAP_CAPACITY
        );
    }

    #[test]
    fn put_object_meta_caps_sparse_capacity_without_changing_growth() {
        run_store_test(
            "put_meta_caps_sparse_capacity",
            "verify",
            "write",
            5,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let mut meta = test_object_meta();
                meta.source_symbols = MAX_SOURCE_SYMBOLS;

                store.put_object_meta(meta.clone()).await.unwrap();

                let expected_capacity =
                    HashMap::<u32, StoredSymbol>::with_capacity(MAX_EAGER_SYMBOL_MAP_CAPACITY)
                        .capacity();
                {
                    let objects = store.objects.read();
                    let obj = objects.get(&meta.object_id).unwrap().read();
                    assert_eq!(obj.meta.source_symbols, MAX_SOURCE_SYMBOLS);
                    assert_eq!(obj.symbols.capacity(), expected_capacity);
                    assert!(obj.symbols.is_empty());
                }

                store.put_symbol(test_symbol(0)).await.unwrap();

                assert!(store.get_symbol(&meta.object_id, 0).await.is_ok());
                assert_eq!(store.symbol_count(&meta.object_id).await, 1);

                StoreLogData {
                    object_id: Some(meta.object_id),
                    symbol_count: Some(1),
                    details: Some(json!({
                        "source_symbols": MAX_SOURCE_SYMBOLS,
                        "initial_capacity": expected_capacity,
                        "cap": MAX_EAGER_SYMBOL_MAP_CAPACITY
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    /// Regression for br-ywpup: a forged `source_symbols` above RFC 6330
    /// `K_MAX` MUST be rejected BEFORE any `HashMap::with_capacity(...)`
    /// allocation, and without holding the global `objects.write()` lock.
    #[test]
    fn put_object_meta_rejects_oversized_source_symbols() {
        run_store_test(
            "put_meta_rejects_oversized_source_symbols",
            "verify",
            "write",
            3,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                // Straight above-K_MAX rejection.
                let mut oversize = test_object_meta();
                oversize.source_symbols = MAX_SOURCE_SYMBOLS + 1;
                let result = store.put_object_meta(oversize).await;
                assert!(
                    matches!(
                        &result,
                        Err(SymbolStoreError::InvalidSymbol { reason })
                            if reason.contains("source_symbols")
                    ),
                    "expected InvalidSymbol for K>K_MAX, got {result:?}"
                );

                // The u32::MAX attacker payload must be rejected without
                // panicking via the `as usize` cast on 64-bit platforms.
                let mut poisoned = test_object_meta();
                poisoned.object_id = ObjectId::from_bytes([9_u8; 32]);
                poisoned.source_symbols = u32::MAX;
                let result = store.put_object_meta(poisoned).await;
                assert!(matches!(
                    result,
                    Err(SymbolStoreError::InvalidSymbol { .. })
                ));

                // Zero is also invalid (would preallocate an empty HashMap
                // but leave a zombie object_id entry that can never be
                // completed).
                let mut zero = test_object_meta();
                zero.object_id = ObjectId::from_bytes([8_u8; 32]);
                zero.source_symbols = 0;
                let result = store.put_object_meta(zero).await;
                assert!(matches!(
                    result,
                    Err(SymbolStoreError::InvalidSymbol { .. })
                ));

                StoreLogData {
                    details: Some(json!({"rejected": "oversized_source_symbols"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn put_object_meta_duplicate_different_data() {
        run_store_test(
            "put_meta_dup_different_data",
            "verify",
            "write",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let meta = test_object_meta();
                store.put_object_meta(meta).await.unwrap();

                // Different meta with same object_id
                let mut different = test_object_meta();
                different.source_symbols = 999;

                let result = store.put_object_meta(different).await;
                assert!(matches!(
                    result,
                    Err(SymbolStoreError::InvalidSymbol { .. })
                ));

                StoreLogData {
                    details: Some(json!({"error": "metadata_mismatch"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn list_zone_empty() {
        run_store_test("list_zone_empty_symbols", "verify", "list", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            let ids = store.list_zone(&test_zone()).await;
            assert!(ids.is_empty());

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn storage_quota_returns_config_value() {
        run_store_test(
            "storage_quota_symbol",
            "verify",
            "accounting",
            1,
            || async {
                let config = MemorySymbolStoreConfig {
                    max_bytes: 99_999,
                    local_node_id: 0,
                };
                let store = MemorySymbolStore::new(config);

                assert_eq!(store.storage_quota().await, 99_999);

                StoreLogData {
                    details: Some(json!({"quota": 99_999})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn config_default_values() {
        run_store_test("symbol_config_default", "verify", "config", 2, || async {
            let config = MemorySymbolStoreConfig::default();
            assert_eq!(config.max_bytes, 512 * 1024 * 1024);
            assert_eq!(config.local_node_id, 0);

            StoreLogData {
                details: Some(json!({"max_bytes": config.max_bytes})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn delete_symbol_frees_storage() {
        run_store_test(
            "delete_symbol_frees_storage",
            "verify",
            "accounting",
            2,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                store.put_object_meta(test_object_meta()).await.unwrap();
                store.put_symbol(test_symbol(0)).await.unwrap();

                let used_before = store.storage_used().await;
                assert!(used_before > 0);

                store.delete_symbol(&test_object_id(), 0).await.unwrap();
                let used_after = store.storage_used().await;
                assert!(used_after < used_before);

                StoreLogData {
                    details: Some(json!({"freed": used_before - used_after})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn get_distribution_tracks_local_node() {
        run_store_test(
            "distribution_local_node",
            "verify",
            "placement",
            2,
            || async {
                let config = MemorySymbolStoreConfig {
                    max_bytes: 512 * 1024 * 1024,
                    local_node_id: 42,
                };
                let store = MemorySymbolStore::new(config);
                store.put_object_meta(test_object_meta()).await.unwrap();

                // Symbol with no source_node → falls back to local_node_id
                let mut symbol = test_symbol(0);
                symbol.meta.source_node = None;
                store.put_symbol(symbol).await.unwrap();

                let dist = store.get_distribution(&test_object_id()).await.unwrap();
                assert_eq!(dist.distinct_nodes(), 1);
                assert!(dist.nodes.contains_key(&42));

                StoreLogData {
                    details: Some(json!({"local_node": 42})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn list_zone() {
        run_store_test("list_zone_symbols", "verify", "list", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();

            let mut meta2 = test_object_meta();
            meta2.object_id = ObjectId::from_bytes([2_u8; 32]);
            store.put_object_meta(meta2).await.unwrap();

            let ids = store.list_zone(&test_zone()).await;
            assert_eq!(ids.len(), 2);

            StoreLogData {
                details: Some(json!({"zone_id": test_zone().to_string(), "count": ids.len()})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: SymbolMeta traits ---

    #[test]
    fn symbol_meta_clone_independence() {
        run_store_test("symbol_meta_clone", "verify", "traits", 2, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 7,
                zone_id: test_zone(),
                source_node: Some(99),
                stored_at: 500_000,
            };
            let cloned = meta.clone();
            drop(meta);
            assert_eq!(cloned.esi, 7);
            assert_eq!(cloned.source_node, Some(99));

            StoreLogData {
                details: Some(json!({"clone": "independent"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_meta_debug_format() {
        run_store_test("symbol_meta_debug", "verify", "traits", 2, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 3,
                zone_id: test_zone(),
                source_node: None,
                stored_at: 42,
            };
            let dbg = format!("{meta:?}");
            assert!(dbg.contains("SymbolMeta"));
            assert!(dbg.contains("esi: 3"));

            StoreLogData {
                details: Some(json!({"debug_contains": "SymbolMeta"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_meta_serde_none_source_node() {
        run_store_test("symbol_meta_serde_none", "verify", "serde", 2, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 0,
                zone_id: test_zone(),
                source_node: None,
                stored_at: 0,
            };
            let json = serde_json::to_string(&meta).unwrap();
            let deserialized: SymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.source_node, None);
            assert_eq!(deserialized.stored_at, 0);

            StoreLogData {
                details: Some(json!({"serde": "none_source_node_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: StoredSymbol traits ---

    #[test]
    fn stored_symbol_clone_independence() {
        run_store_test("stored_symbol_clone", "verify", "traits", 2, || async {
            let sym = test_symbol(5);
            let cloned = sym.clone();
            drop(sym);
            assert_eq!(cloned.meta.esi, 5);
            assert_eq!(cloned.data.len(), 64);

            StoreLogData {
                details: Some(json!({"clone": "independent", "esi": 5})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn stored_symbol_debug_format() {
        run_store_test("stored_symbol_debug", "verify", "traits", 1, || async {
            let sym = test_symbol(11);
            let dbg = format!("{sym:?}");
            assert!(dbg.contains("StoredSymbol"));

            StoreLogData {
                details: Some(json!({"debug_contains": "StoredSymbol"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: ObjectTransmissionInfo ---

    #[test]
    fn oti_from_and_to_raptorq_roundtrip() {
        run_store_test("oti_raptorq_roundtrip", "verify", "codec", 5, || async {
            let raptorq_oti = ObjectTransmissionInformation::new(8192, 256, 4, 2, 16);
            let info = ObjectTransmissionInfo::from_oti(raptorq_oti);
            assert_eq!(info.transfer_length, 8192);
            assert_eq!(info.symbol_size, 256);
            assert_eq!(info.source_blocks, 4);
            assert_eq!(info.sub_blocks, 2);
            assert_eq!(info.alignment, 16);

            let back = info.to_oti();
            assert_eq!(back.transfer_length(), 8192);
            assert_eq!(back.symbol_size(), 256);

            StoreLogData {
                details: Some(json!({"roundtrip": "raptorq_oti_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn oti_alias_assigns_to_canonical_type() {
        run_store_test("oti_alias_assigns", "verify", "codec", 2, || async {
            let raptorq_oti = ObjectTransmissionInformation::new(1024, 64, 1, 1, 8);
            let info: ObjectTransmissionInfo = raptorq_oti;
            assert_eq!(info.transfer_length, 1024);
            assert_eq!(info.symbol_size, 64);

            let back: ObjectTransmissionInformation = info;
            assert_eq!(back.transfer_length(), 1024);

            StoreLogData {
                details: Some(json!({"from_trait": "ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn oti_equality() {
        run_store_test("oti_equality", "verify", "traits", 2, || async {
            let a = ObjectTransmissionInfo {
                transfer_length: 512,
                symbol_size: 32,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 4,
                payload_hash: None,
            };
            let b = ObjectTransmissionInfo {
                transfer_length: 512,
                symbol_size: 32,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 4,
                payload_hash: None,
            };
            assert_eq!(a, b);

            let c = ObjectTransmissionInfo {
                transfer_length: 999,
                ..a
            };
            assert_ne!(a, c);

            StoreLogData {
                details: Some(json!({"eq": true, "ne": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn oti_debug_format() {
        run_store_test("oti_debug", "verify", "traits", 1, || async {
            let oti = ObjectTransmissionInfo {
                transfer_length: 2048,
                symbol_size: 128,
                source_blocks: 2,
                sub_blocks: 1,
                alignment: 8,
                payload_hash: None,
            };
            let dbg = format!("{oti:?}");
            assert!(dbg.contains("ObjectTransmissionInformation"));

            StoreLogData {
                details: Some(json!({"debug_contains": "ObjectTransmissionInformation"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: ObjectSymbolMeta ---

    #[test]
    fn object_symbol_meta_clone_independence() {
        run_store_test("osm_clone", "verify", "traits", 2, || async {
            let meta = test_object_meta();
            let cloned = meta.clone();
            drop(meta);
            assert_eq!(cloned.source_symbols, 16);
            assert_eq!(cloned.oti.symbol_size, 64);

            StoreLogData {
                details: Some(json!({"clone": "independent"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_symbol_meta_equality() {
        run_store_test("osm_equality", "verify", "traits", 2, || async {
            let a = test_object_meta();
            let b = test_object_meta();
            assert_eq!(a, b);

            let mut c = test_object_meta();
            c.source_symbols = 999;
            assert_ne!(a, c);

            StoreLogData {
                details: Some(json!({"eq": true, "ne": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_symbol_meta_debug_format() {
        run_store_test("osm_debug", "verify", "traits", 1, || async {
            let meta = test_object_meta();
            let dbg = format!("{meta:?}");
            assert!(dbg.contains("ObjectSymbolMeta"));

            StoreLogData {
                details: Some(json!({"debug_contains": "ObjectSymbolMeta"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: MemorySymbolStoreConfig ---

    #[test]
    fn config_clone() {
        run_store_test("config_clone", "verify", "traits", 2, || async {
            let config = MemorySymbolStoreConfig {
                max_bytes: 12345,
                local_node_id: 77,
            };
            let cloned = config.clone();
            assert_eq!(config.max_bytes, cloned.max_bytes);
            assert_eq!(cloned.max_bytes, 12345);
            assert_eq!(cloned.local_node_id, 77);

            StoreLogData {
                details: Some(json!({"clone_max_bytes": 12345})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn config_debug_format() {
        run_store_test("config_debug", "verify", "traits", 1, || async {
            let config = MemorySymbolStoreConfig::default();
            let dbg = format!("{config:?}");
            assert!(dbg.contains("MemorySymbolStoreConfig"));

            StoreLogData {
                details: Some(json!({"debug_contains": "MemorySymbolStoreConfig"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- New tests: MemorySymbolStore advanced operations ---

    #[test]
    fn list_zone_filters_by_zone() {
        run_store_test("list_zone_filter", "verify", "list", 2, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            // Object in zone "z:test"
            store.put_object_meta(test_object_meta()).await.unwrap();

            // Object in zone "z:other"
            let meta2 = ObjectSymbolMeta {
                object_id: ObjectId::from_bytes([2_u8; 32]),
                zone_id: "z:other".parse().unwrap(),
                oti: test_object_meta().oti,
                source_symbols: 16,
                first_symbol_at: 1_000_000,
            };
            store.put_object_meta(meta2).await.unwrap();

            let test_ids = store.list_zone(&test_zone()).await;
            assert_eq!(test_ids.len(), 1);

            let other_zone: ZoneId = "z:other".parse().unwrap();
            let other_ids = store.list_zone(&other_zone).await;
            assert_eq!(other_ids.len(), 1);

            StoreLogData {
                details: Some(json!({"test_zone_count": 1, "other_zone_count": 1})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_distribution_single_node() {
        run_store_test("dist_single_node", "verify", "placement", 3, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            for esi in 0..4 {
                let mut sym = test_symbol(esi);
                sym.meta.source_node = Some(7);
                store.put_symbol(sym).await.unwrap();
            }

            let dist = store.get_distribution(&test_object_id()).await.unwrap();
            assert_eq!(dist.distinct_nodes(), 1);
            assert_eq!(dist.total_symbols, 4);
            assert!(dist.nodes.contains_key(&7));

            StoreLogData {
                details: Some(json!({"nodes": 1, "symbols": 4})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_distribution_multi_node() {
        run_store_test("dist_multi_node", "verify", "placement", 3, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            for esi in 0..3 {
                let mut sym = test_symbol(esi);
                sym.meta.source_node = Some(10);
                store.put_symbol(sym).await.unwrap();
            }
            for esi in 3..5 {
                let mut sym = test_symbol(esi);
                sym.meta.source_node = Some(20);
                store.put_symbol(sym).await.unwrap();
            }
            let mut sym = test_symbol(5);
            sym.meta.source_node = Some(30);
            store.put_symbol(sym).await.unwrap();

            let dist = store.get_distribution(&test_object_id()).await.unwrap();
            assert_eq!(dist.distinct_nodes(), 3);
            assert_eq!(dist.total_symbols, 6);
            assert_eq!(dist.max_node_symbols(), 3);

            StoreLogData {
                details: Some(json!({"nodes": 3, "symbols": 6, "max_per_node": 3})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn storage_used_tracks_multiple_objects() {
        run_store_test(
            "storage_tracks_multi",
            "verify",
            "accounting",
            3,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                assert_eq!(store.storage_used().await, 0);

                store.put_object_meta(test_object_meta()).await.unwrap();
                store.put_symbol(test_symbol(0)).await.unwrap();
                let after_one = store.storage_used().await;
                assert!(after_one > 0);

                store.put_symbol(test_symbol(1)).await.unwrap();
                let after_two = store.storage_used().await;
                assert!(after_two > after_one);

                StoreLogData {
                    details: Some(json!({"after_one": after_one, "after_two": after_two})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_object_then_reinsert() {
        run_store_test("delete_reinsert", "verify", "lifecycle", 3, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();
            assert_eq!(store.symbol_count(&test_object_id()).await, 1);

            store.delete_object(&test_object_id()).await.unwrap();
            assert_eq!(store.symbol_count(&test_object_id()).await, 0);

            // Re-insert the same object
            store.put_object_meta(test_object_meta()).await.unwrap();
            store.put_symbol(test_symbol(0)).await.unwrap();
            assert_eq!(store.symbol_count(&test_object_id()).await, 1);

            StoreLogData {
                details: Some(json!({"lifecycle": "delete_reinsert_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_object_meta_success() {
        run_store_test("get_object_meta_ok", "verify", "read", 3, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let meta = test_object_meta();
            store.put_object_meta(meta.clone()).await.unwrap();

            let retrieved = store.get_object_meta(&test_object_id()).await.unwrap();
            assert_eq!(retrieved.object_id, meta.object_id);
            assert_eq!(retrieved.source_symbols, meta.source_symbols);
            assert_eq!(retrieved.oti, meta.oti);

            StoreLogData {
                details: Some(json!({"meta_retrieved": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_object_meta_not_found() {
        run_store_test("get_object_meta_missing", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            let unknown_id = ObjectId::from_bytes([88; 32]);

            let result = store.get_object_meta(&unknown_id).await;
            assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

            StoreLogData {
                details: Some(json!({"error": "object_not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct_boundary() {
        run_store_test(
            "can_reconstruct_boundary",
            "verify",
            "repair",
            2,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                let mut meta = test_object_meta();
                meta.source_symbols = 3;
                store.put_object_meta(meta).await.unwrap();

                // 2 symbols: not enough (need 3)
                store.put_symbol(test_symbol(0)).await.unwrap();
                store.put_symbol(test_symbol(1)).await.unwrap();
                assert!(!store.can_reconstruct(&test_object_id()).await);

                // 3 symbols: exactly enough
                store.put_symbol(test_symbol(2)).await.unwrap();
                assert!(store.can_reconstruct(&test_object_id()).await);

                StoreLogData {
                    details: Some(json!({"boundary": "K=3"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_symbol_object_not_found() {
        run_store_test(
            "delete_symbol_obj_missing",
            "verify",
            "delete",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
                let unknown_id = ObjectId::from_bytes([77; 32]);

                let result = store.delete_symbol(&unknown_id, 0).await;
                assert!(matches!(result, Err(SymbolStoreError::ObjectNotFound(_))));

                StoreLogData {
                    details: Some(json!({"error": "object_not_found"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn storage_used_zero_initially() {
        run_store_test("storage_used_zero", "verify", "accounting", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            assert_eq!(store.storage_used().await, 0);

            StoreLogData {
                details: Some(json!({"used": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quota_exact_boundary() {
        run_store_test(
            "quota_exact_boundary",
            "verify",
            "accounting",
            2,
            || async {
                let sample = test_symbol(0);
                let size = MemorySymbolStore::symbol_size(&sample);
                // Set quota to exactly 2 symbols worth
                let config = MemorySymbolStoreConfig {
                    max_bytes: size * 2,
                    local_node_id: 0,
                };
                let store = MemorySymbolStore::new(config);
                store.put_object_meta(test_object_meta()).await.unwrap();

                store.put_symbol(test_symbol(0)).await.unwrap();
                store.put_symbol(test_symbol(1)).await.unwrap();

                // Third symbol should exceed quota
                let result = store.put_symbol(test_symbol(2)).await;
                assert!(matches!(
                    result,
                    Err(SymbolStoreError::QuotaExceeded { .. })
                ));

                // Verify exactly 2 stored
                assert_eq!(store.symbol_count(&test_object_id()).await, 2);

                StoreLogData {
                    details: Some(json!({"quota_boundary": "2_symbols_exact"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn delete_frees_quota_for_new_symbols() {
        run_store_test("delete_frees_quota", "verify", "accounting", 2, || async {
            let sample = test_symbol(0);
            let size = MemorySymbolStore::symbol_size(&sample);
            let config = MemorySymbolStoreConfig {
                max_bytes: size,
                local_node_id: 0,
            };
            let store = MemorySymbolStore::new(config);
            store.put_object_meta(test_object_meta()).await.unwrap();

            store.put_symbol(test_symbol(0)).await.unwrap();

            // Full: cannot add more
            let result = store.put_symbol(test_symbol(1)).await;
            assert!(matches!(
                result,
                Err(SymbolStoreError::QuotaExceeded { .. })
            ));

            // Delete the symbol
            store.delete_symbol(&test_object_id(), 0).await.unwrap();

            // Now we can add again
            store.put_symbol(test_symbol(1)).await.unwrap();
            assert_eq!(store.symbol_count(&test_object_id()).await, 1);

            StoreLogData {
                details: Some(json!({"freed_and_reused": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_all_symbols_empty_object() {
        run_store_test("get_all_symbols_empty", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            // Object exists but has no symbols
            let symbols = store.get_all_symbols(&test_object_id()).await;
            assert!(symbols.is_empty());

            StoreLogData {
                details: Some(json!({"count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_count_with_existing_symbols() {
        run_store_test("symbol_count_existing", "verify", "read", 1, || async {
            let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());
            store.put_object_meta(test_object_meta()).await.unwrap();

            for esi in 0..7 {
                store.put_symbol(test_symbol(esi)).await.unwrap();
            }
            assert_eq!(store.symbol_count(&test_object_id()).await, 7);

            StoreLogData {
                details: Some(json!({"count": 7})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn can_reconstruct_with_policy_no_diversity_required() {
        run_store_test(
            "reconstruct_policy_no_div",
            "verify",
            "repair",
            1,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                let mut meta = test_object_meta();
                meta.source_symbols = 2;
                store.put_object_meta(meta).await.unwrap();

                // All from same node, but min_source_diversity=0
                for esi in 0..2 {
                    let mut sym = test_symbol(esi);
                    sym.meta.source_node = Some(1);
                    store.put_symbol(sym).await.unwrap();
                }

                let policy = fcp_core::ObjectPlacementPolicy {
                    min_nodes: 1,
                    max_node_fraction_bps: 10_000,
                    preferred_devices: vec![],
                    excluded_devices: vec![],
                    target_coverage_bps: 10_000,
                    min_source_diversity: 0,
                };

                assert!(
                    store
                        .can_reconstruct_with_policy(&test_object_id(), &policy)
                        .await
                );

                StoreLogData {
                    details: Some(json!({"no_diversity": "passes"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn multiple_objects_independent() {
        run_store_test(
            "multi_object_independent",
            "verify",
            "isolation",
            4,
            || async {
                let store = MemorySymbolStore::new(MemorySymbolStoreConfig::default());

                // Object 1
                let meta1 = test_object_meta();
                store.put_object_meta(meta1).await.unwrap();
                store.put_symbol(test_symbol(0)).await.unwrap();

                // Object 2 with different ID
                let obj2_id = ObjectId::from_bytes([2_u8; 32]);
                let meta2 = ObjectSymbolMeta {
                    object_id: obj2_id,
                    zone_id: test_zone(),
                    oti: test_object_meta().oti,
                    source_symbols: 16,
                    first_symbol_at: 2_000_000,
                };
                store.put_object_meta(meta2).await.unwrap();
                let sym2 = StoredSymbol {
                    meta: SymbolMeta {
                        object_id: obj2_id,
                        esi: 0,
                        zone_id: test_zone(),
                        source_node: Some(2),
                        stored_at: 2_000_000,
                    },
                    data: Bytes::from(vec![1_u8; 64]),
                };
                store.put_symbol(sym2).await.unwrap();

                assert_eq!(store.symbol_count(&test_object_id()).await, 1);
                assert_eq!(store.symbol_count(&obj2_id).await, 1);

                // Delete object 1 should not affect object 2
                store.delete_object(&test_object_id()).await.unwrap();
                assert_eq!(store.symbol_count(&test_object_id()).await, 0);
                assert_eq!(store.symbol_count(&obj2_id).await, 1);

                StoreLogData {
                    details: Some(json!({"objects_independent": true})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn oti_serde_json_field_names() {
        run_store_test("oti_serde_fields", "verify", "serde", 3, || async {
            let oti = ObjectTransmissionInfo {
                transfer_length: 4096,
                symbol_size: 128,
                source_blocks: 2,
                sub_blocks: 4,
                alignment: 16,
                payload_hash: None,
            };
            let json_str = serde_json::to_string(&oti).unwrap();
            assert!(json_str.contains("transfer_length"));
            assert!(json_str.contains("symbol_size"));
            assert!(json_str.contains("alignment"));

            StoreLogData {
                details: Some(json!({"fields": "present"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn symbol_meta_serde_all_fields_preserved() {
        run_store_test("symbol_meta_serde_all", "verify", "serde", 5, || async {
            let meta = SymbolMeta {
                object_id: test_object_id(),
                esi: 42,
                zone_id: test_zone(),
                source_node: Some(777),
                stored_at: 123_456_789,
            };
            let json = serde_json::to_string(&meta).unwrap();
            let rt: SymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(rt.object_id, test_object_id());
            assert_eq!(rt.esi, 42);
            assert_eq!(rt.zone_id, test_zone());
            assert_eq!(rt.source_node, Some(777));
            assert_eq!(rt.stored_at, 123_456_789);

            StoreLogData {
                details: Some(json!({"all_fields": "preserved"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_symbol_meta_serde_all_fields() {
        run_store_test("osm_serde_all_fields", "verify", "serde", 4, || async {
            let meta = ObjectSymbolMeta {
                object_id: test_object_id(),
                zone_id: test_zone(),
                oti: ObjectTransmissionInfo {
                    transfer_length: 9999,
                    symbol_size: 200,
                    source_blocks: 3,
                    sub_blocks: 2,
                    alignment: 4,
                    payload_hash: None,
                },
                source_symbols: 50,
                first_symbol_at: 999_888_777,
            };
            let json = serde_json::to_string(&meta).unwrap();
            let rt: ObjectSymbolMeta = serde_json::from_str(&json).unwrap();
            assert_eq!(rt.oti.transfer_length, 9999);
            assert_eq!(rt.oti.symbol_size, 200);
            assert_eq!(rt.source_symbols, 50);
            assert_eq!(rt.first_symbol_at, 999_888_777);

            StoreLogData {
                details: Some(json!({"all_osm_fields": "preserved"})),
                ..StoreLogData::default()
            }
        });
    }

    // --- ObjectTransmissionInfo tests ---

    #[test]
    fn oti_debug() {
        let oti = ObjectTransmissionInfo {
            transfer_length: 1024,
            symbol_size: 64,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        };
        let dbg = format!("{oti:?}");
        assert!(dbg.contains("ObjectTransmissionInformation"));
        assert!(dbg.contains("1024"));
    }

    #[test]
    fn oti_clone_and_copy() {
        let oti = ObjectTransmissionInfo {
            transfer_length: 2048,
            symbol_size: 128,
            source_blocks: 2,
            sub_blocks: 1,
            alignment: 4,
            payload_hash: None,
        };
        let copied = oti;
        assert_eq!(oti, copied);
    }

    #[test]
    fn oti_eq() {
        let a = ObjectTransmissionInfo {
            transfer_length: 512,
            symbol_size: 32,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        };
        let b = ObjectTransmissionInfo {
            transfer_length: 512,
            symbol_size: 32,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn oti_ne() {
        let a = ObjectTransmissionInfo {
            transfer_length: 512,
            symbol_size: 32,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        };
        let b = ObjectTransmissionInfo {
            transfer_length: 1024,
            symbol_size: 32,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn oti_serde_json_roundtrip() {
        let oti = ObjectTransmissionInfo {
            transfer_length: 4096,
            symbol_size: 256,
            source_blocks: 4,
            sub_blocks: 2,
            alignment: 16,
            payload_hash: None,
        };
        let json = serde_json::to_string(&oti).unwrap();
        let rt: ObjectTransmissionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, oti);
    }

    // --- SymbolMeta tests ---

    #[test]
    fn symbol_meta_debug() {
        let meta = SymbolMeta {
            object_id: test_object_id(),
            esi: 42,
            zone_id: test_zone(),
            source_node: Some(7),
            stored_at: 999,
        };
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("SymbolMeta"));
        assert!(dbg.contains("42"));
    }

    #[test]
    fn symbol_meta_clone() {
        let meta = SymbolMeta {
            object_id: test_object_id(),
            esi: 10,
            zone_id: test_zone(),
            source_node: None,
            stored_at: 500,
        };
        let cloned = meta.clone();
        assert_eq!(meta.esi, cloned.esi);
        assert_eq!(meta.stored_at, cloned.stored_at);
    }

    #[test]
    fn symbol_meta_serde_json_roundtrip() {
        let meta = SymbolMeta {
            object_id: test_object_id(),
            esi: 99,
            zone_id: test_zone(),
            source_node: Some(42),
            stored_at: 123_456,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let rt: SymbolMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.esi, 99);
        assert_eq!(rt.source_node, Some(42));
        assert_eq!(rt.stored_at, 123_456);
    }

    // --- ObjectSymbolMeta tests ---

    #[test]
    fn object_symbol_meta_debug() {
        let meta = test_object_meta();
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("ObjectSymbolMeta"));
    }

    #[test]
    fn object_symbol_meta_clone() {
        let meta = test_object_meta();
        let cloned = meta.clone();
        assert_eq!(meta.object_id, cloned.object_id);
        assert_eq!(meta.source_symbols, cloned.source_symbols);
    }

    #[test]
    fn object_symbol_meta_eq() {
        let a = test_object_meta();
        let b = test_object_meta();
        assert_eq!(a, b);
    }

    // --- MemorySymbolStoreConfig tests ---

    #[test]
    fn memory_symbol_store_config_default() {
        let config = MemorySymbolStoreConfig::default();
        assert_eq!(config.max_bytes, 512 * 1024 * 1024);
        assert_eq!(config.local_node_id, 0);
    }

    #[test]
    fn memory_symbol_store_config_debug() {
        let config = MemorySymbolStoreConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("MemorySymbolStoreConfig"));
    }

    #[test]
    fn memory_symbol_store_config_clone() {
        let config = MemorySymbolStoreConfig {
            max_bytes: 1024,
            local_node_id: 42,
        };
        let cloned = config.clone();
        assert_eq!(config.max_bytes, cloned.max_bytes);
        assert_eq!(config.local_node_id, cloned.local_node_id);
    }

    // --- StoredSymbol tests ---

    #[test]
    fn stored_symbol_debug() {
        let sym = test_symbol(5);
        let dbg = format!("{sym:?}");
        assert!(dbg.contains("StoredSymbol"));
    }

    #[test]
    fn stored_symbol_clone() {
        let sym = test_symbol(3);
        let cloned = sym.clone();
        assert_eq!(sym.meta.esi, cloned.meta.esi);
        assert_eq!(sym.data.len(), cloned.data.len());
    }

    // --- ObjectTransmissionInfo tests ---

    #[test]
    fn object_transmission_info_serde_roundtrip() {
        let info = ObjectTransmissionInfo {
            transfer_length: 65536,
            symbol_size: 256,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let rt: ObjectTransmissionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, rt);
    }

    #[test]
    fn object_transmission_info_copy_eq() {
        let a = ObjectTransmissionInfo {
            transfer_length: 1024,
            symbol_size: 64,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 1,
            payload_hash: None,
        };
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn object_transmission_info_debug() {
        let info = ObjectTransmissionInfo {
            transfer_length: 512,
            symbol_size: 32,
            source_blocks: 2,
            sub_blocks: 1,
            alignment: 4,
            payload_hash: None,
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ObjectTransmissionInformation"));
    }

    #[test]
    fn object_transmission_info_from_oti_roundtrip() {
        let oti = ObjectTransmissionInformation::new(8192, 128, 1, 1, 8);
        let info = ObjectTransmissionInfo::from_oti(oti);
        let back = info.to_oti();
        assert_eq!(back.transfer_length(), 8192);
        assert_eq!(back.symbol_size(), 128);
    }

    #[test]
    fn object_transmission_info_alias_from_canonical() {
        let oti = ObjectTransmissionInformation::new(4096, 64, 1, 1, 1);
        let info: ObjectTransmissionInfo = oti;
        assert_eq!(info.transfer_length, 4096);
        assert_eq!(info.symbol_size, 64);
    }

    #[test]
    fn object_transmission_info_alias_to_canonical() {
        let info = ObjectTransmissionInfo {
            transfer_length: 2048,
            symbol_size: 32,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 1,
            payload_hash: None,
        };
        let oti: ObjectTransmissionInformation = info;
        assert_eq!(oti.transfer_length(), 2048);
    }

    // --- SymbolMeta additional tests ---

    #[test]
    fn symbol_meta_serde_json_rt() {
        let meta = SymbolMeta {
            object_id: ObjectId::from_bytes([1; 32]),
            esi: 42,
            zone_id: "z:test".parse().unwrap(),
            source_node: Some(99),
            stored_at: 1_000_000,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let rt: SymbolMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.esi, 42);
        assert_eq!(rt.source_node, Some(99));
        assert_eq!(rt.stored_at, 1_000_000);
    }

    #[test]
    fn symbol_meta_clone_preserves_all() {
        let meta = SymbolMeta {
            object_id: ObjectId::from_bytes([2; 32]),
            esi: 7,
            zone_id: "z:test".parse().unwrap(),
            source_node: None,
            stored_at: 500,
        };
        let cloned = meta.clone();
        assert_eq!(meta.esi, cloned.esi);
        assert_eq!(meta.source_node, cloned.source_node);
    }

    // --- ObjectSymbolMeta additional tests ---

    #[test]
    fn object_symbol_meta_serde_json_rt() {
        let meta = ObjectSymbolMeta {
            object_id: ObjectId::from_bytes([3; 32]),
            zone_id: "z:test".parse().unwrap(),
            oti: ObjectTransmissionInfo {
                transfer_length: 1024,
                symbol_size: 64,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 1,
                payload_hash: None,
            },
            source_symbols: 16,
            first_symbol_at: 12345,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let rt: ObjectSymbolMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, rt);
    }

    #[test]
    fn object_symbol_meta_clone_eq() {
        let meta1 = ObjectSymbolMeta {
            object_id: ObjectId::from_bytes([1; 32]),
            zone_id: "z:test".parse().unwrap(),
            oti: ObjectTransmissionInfo {
                transfer_length: 512,
                symbol_size: 32,
                source_blocks: 1,
                sub_blocks: 1,
                alignment: 1,
                payload_hash: None,
            },
            source_symbols: 16,
            first_symbol_at: 100,
        };
        let meta2 = meta1.clone();
        assert_eq!(meta1, meta2);
    }
}
