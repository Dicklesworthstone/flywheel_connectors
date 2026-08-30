//! Quarantine store for untrusted/unreferenced objects (NORMATIVE).
//!
//! Implements the object admission pipeline from `FCP_Specification_V3.md` §11.7.2
//! (Unreferenced Object Quarantine) and §9.8.5 (Symbol-Plane Admission Control).

use std::collections::{BTreeSet, HashMap};

use bytes::Bytes;
use fcp_prelude::{ObjectId, ZoneId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::QuarantineError;

/// Object admission classification (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectAdmissionClass {
    /// Unknown provenance, bounded retention, not gossiped.
    Quarantined,
    /// Verified reachable, normal retention, gossiped.
    Admitted,
}

/// Reason for promoting an object from quarantine (NORMATIVE).
///
/// Per FCP Specification §8.4.1, promotion from quarantine is allowed only if
/// one of these conditions is met.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionReason {
    /// Object became reachable from the zone's pinned `ZoneCheckpoint`.
    ReachableFromCheckpoint {
        /// The checkpoint object ID that makes this object reachable.
        checkpoint_id: ObjectId,
    },
    /// Object was explicitly requested by an authenticated peer.
    AuthenticatedPeerRequest {
        /// The peer that requested the object.
        peer_id: u64,
        /// Request signature or token (opaque bytes for validation).
        request_token: Vec<u8>,
    },
    /// Object was explicitly pinned by local user action or policy.
    LocalPin {
        /// Reason for the pin (audit trail).
        reason: String,
    },
}

/// Object admission policy (NORMATIVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAdmissionPolicy {
    /// Maximum quarantine storage per zone (default: 256MB).
    pub max_quarantine_bytes_per_zone: u64,
    /// Maximum quarantined objects per zone (default: 100,000).
    pub max_quarantine_objects_per_zone: u32,
    /// TTL for quarantined objects before eviction (default: 3600s).
    pub quarantine_ttl_secs: u64,
    /// Whether to require schema validation on promotion (default: true).
    pub require_schema_validation: bool,
}

impl Default for ObjectAdmissionPolicy {
    fn default() -> Self {
        Self {
            max_quarantine_bytes_per_zone: 256 * 1024 * 1024, // 256MB
            max_quarantine_objects_per_zone: 100_000,
            quarantine_ttl_secs: 3600,
            require_schema_validation: true,
        }
    }
}

/// Quarantined object entry.
#[derive(Debug, Clone)]
pub struct QuarantinedObject {
    /// Object ID.
    pub object_id: ObjectId,
    /// Zone this object belongs to.
    pub zone_id: ZoneId,
    /// Raw object data (symbols or reconstructed body).
    pub data: Bytes,
    /// Peer that sent this object.
    pub source_peer: Option<u64>,
    /// Timestamp when received.
    pub received_at: u64,
    /// Peer reputation score at time of receipt (lower = worse).
    pub peer_reputation: i32,
}

/// Entry for eviction priority queue.
#[derive(Debug, Clone, Eq, PartialEq)]
struct EvictionEntry {
    object_id: ObjectId,
    received_at: u64,
    peer_reputation: i32,
    size: u64,
}

impl Ord for EvictionEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Priority order: oldest first, then lowest reputation, then largest
        // We order such that the "worst" items (to be evicted) are smallest (Min),
        // so we can efficiently pop_first() from BTreeSet.

        // Oldest (smallest timestamp) is min -> evict first
        self.received_at
            .cmp(&other.received_at)
            // Lowest reputation (smallest value) is min -> evict first
            .then_with(|| self.peer_reputation.cmp(&other.peer_reputation))
            // Largest size is min -> evict first (so we reverse compare)
            .then_with(|| other.size.cmp(&self.size))
            // Tie-breaker to ensure unique entries in Set
            .then_with(|| self.object_id.as_bytes().cmp(other.object_id.as_bytes()))
    }
}

impl PartialOrd for EvictionEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Per-zone quarantine state.
#[derive(Debug)]
struct ZoneQuarantine {
    objects: HashMap<ObjectId, QuarantinedObject>,
    used_bytes: u64,
    eviction_queue: BTreeSet<EvictionEntry>,
}

impl ZoneQuarantine {
    fn new() -> Self {
        Self {
            objects: HashMap::new(),
            used_bytes: 0,
            eviction_queue: BTreeSet::new(),
        }
    }
}

/// Quarantine store for untrusted objects (NORMATIVE).
///
/// Implements bounded admission with per-zone quotas and TTL eviction.
pub struct QuarantineStore {
    zones: RwLock<HashMap<ZoneId, ZoneQuarantine>>,
    policy: ObjectAdmissionPolicy,
}

impl QuarantineStore {
    /// Create a new quarantine store with the given policy.
    #[must_use]
    pub fn new(policy: ObjectAdmissionPolicy) -> Self {
        Self {
            zones: RwLock::new(HashMap::new()),
            policy,
        }
    }

    /// Add an object to quarantine.
    ///
    /// If quotas are exceeded, evicts objects according to policy.
    /// Also performs an in-band TTL sweep using the incoming object's
    /// receipt time so expired entries do not persist indefinitely without
    /// a dedicated background sweeper.
    ///
    /// # Errors
    /// Returns error if the object cannot be quarantined even after eviction.
    pub fn quarantine(&self, obj: QuarantinedObject) -> Result<(), QuarantineError> {
        self.evict_expired(obj.received_at);

        #[allow(clippy::cast_possible_truncation)]
        let obj_size = obj.data.len() as u64;

        let mut zones = self.zones.write();
        let zone = zones
            .entry(obj.zone_id.clone())
            .or_insert_with(ZoneQuarantine::new);

        // Check if already quarantined
        if zone.objects.contains_key(&obj.object_id) {
            return Ok(()); // Already in quarantine
        }

        // Convert defensively so quota comparisons remain well-defined on any target.
        let max_objects =
            usize::try_from(self.policy.max_quarantine_objects_per_zone).unwrap_or(usize::MAX);

        // Evict if necessary to make room
        while zone.objects.len() >= max_objects
            || zone.used_bytes + obj_size > self.policy.max_quarantine_bytes_per_zone
        {
            if let Some(entry) = zone.eviction_queue.pop_first() {
                if let Some(evicted) = zone.objects.remove(&entry.object_id) {
                    #[allow(clippy::cast_possible_truncation)]
                    let evicted_size = evicted.data.len() as u64;
                    zone.used_bytes = zone.used_bytes.saturating_sub(evicted_size);
                    tracing::debug!(
                        object_id = %entry.object_id,
                        "Evicted quarantined object"
                    );
                }
            } else {
                // No more objects to evict
                return Err(QuarantineError::QuotaExceeded {
                    used: zone.used_bytes,
                    max: self.policy.max_quarantine_bytes_per_zone,
                });
            }
        }

        // Add eviction entry
        zone.eviction_queue.insert(EvictionEntry {
            object_id: obj.object_id,
            received_at: obj.received_at,
            peer_reputation: obj.peer_reputation,
            size: obj_size,
        });

        zone.used_bytes += obj_size;
        zone.objects.insert(obj.object_id, obj);

        Ok(())
    }

    /// Get a quarantined object (unfiltered).
    ///
    /// Returns the entry regardless of its `quarantine_ttl_secs`
    /// freshness. Intended for internal admin/eviction paths that need to
    /// inspect stale records. **Callers consulting quarantine state for
    /// liveness MUST use [`Self::get_fresh`] instead** — otherwise an object
    /// whose TTL has expired but that `evict_expired` has not yet swept will
    /// continue to appear "in quarantine," leaking stale admission state.
    /// See bead flywheel_connectors-dzhhq for the drift this closes.
    pub fn get(&self, object_id: &ObjectId) -> Option<QuarantinedObject> {
        let zones = self.zones.read();
        for zone in zones.values() {
            if let Some(obj) = zone.objects.get(object_id) {
                return Some(obj.clone());
            }
        }
        None
    }

    /// Get a quarantined object, filtering out TTL-expired entries.
    ///
    /// Returns `None` for any record whose `received_at` is older than the
    /// policy's `quarantine_ttl_secs` relative to `current_time`, even if
    /// [`Self::evict_expired`] has not yet swept it. Uses the same
    /// `current_time.saturating_sub(received_at) > ttl` rule as
    /// `evict_expired` so read-path freshness and sweep-path eviction
    /// agree on which entries are live.
    ///
    /// This is the canonical liveness check — any caller that wants to
    /// answer "is this object currently quarantined?" MUST use this
    /// variant, not [`Self::get`]. Closes bead flywheel_connectors-dzhhq
    /// (TTL enforcement used to be sweep-only, letting stale entries
    /// survive indefinitely if the sweep never ran).
    #[must_use]
    pub fn get_fresh(&self, object_id: &ObjectId, current_time: u64) -> Option<QuarantinedObject> {
        let ttl = self.policy.quarantine_ttl_secs;
        let zones = self.zones.read();
        for zone in zones.values() {
            if let Some(obj) = zone.objects.get(object_id) {
                if current_time.saturating_sub(obj.received_at) > ttl {
                    return None;
                }
                return Some(obj.clone());
            }
        }
        None
    }

    /// Remove an object from quarantine (internal, no validation).
    ///
    /// # Errors
    /// Returns `NotFound` if object is not in quarantine.
    pub fn remove(&self, object_id: &ObjectId) -> Result<QuarantinedObject, QuarantineError> {
        let mut zones = self.zones.write();
        for zone in zones.values_mut() {
            if let Some(obj) = zone.objects.remove(object_id) {
                #[allow(clippy::cast_possible_truncation)]
                let obj_size = obj.data.len() as u64;

                // Construct entry to remove from set
                let entry = EvictionEntry {
                    object_id: *object_id,
                    received_at: obj.received_at,
                    peer_reputation: obj.peer_reputation,
                    size: obj_size,
                };
                zone.eviction_queue.remove(&entry);

                zone.used_bytes = zone.used_bytes.saturating_sub(obj_size);
                return Ok(obj);
            }
        }
        Err(QuarantineError::NotFound(*object_id))
    }

    /// Promote an object from quarantine to admitted status (NORMATIVE).
    ///
    /// Per FCP Specification §8.4.1, promotion requires:
    /// 1. A valid promotion reason (checkpoint reachability, peer request, or local pin)
    /// 2. Successful reconstruction (caller must verify object can be reconstructed)
    /// 3. Schema validation (if policy requires it)
    ///
    /// # Arguments
    /// * `object_id` - The object to promote
    /// * `reason` - The reason for promotion (must be valid)
    /// * `schema_valid` - Whether schema validation passed (caller must verify)
    ///
    /// # Errors
    /// Returns `NotFound` if object is not in quarantine.
    /// Returns `PromotionDenied` if promotion rules are not satisfied.
    /// Returns `SchemaValidationFailed` if schema validation is required but failed.
    pub fn promote(
        &self,
        object_id: &ObjectId,
        reason: &PromotionReason,
        schema_valid: bool,
    ) -> Result<QuarantinedObject, QuarantineError> {
        // Early exit: NotFound takes precedence over all other errors so
        // callers always learn "object absent" before "bad reason/schema".
        // The race between this check and remove() is benign — if another
        // thread removes the object in between, remove() itself returns
        // NotFound atomically under its write lock.
        if !self.contains(object_id) {
            return Err(QuarantineError::NotFound(*object_id));
        }

        // Validate promotion reason (does not require lock).
        self.validate_promotion_reason(object_id, reason)?;

        // Check schema validation if required.
        if self.policy.require_schema_validation && !schema_valid {
            return Err(QuarantineError::SchemaValidationFailed {
                reason: "Schema validation is required but object failed validation".into(),
            });
        }

        self.remove(object_id)
    }

    /// Validate that a promotion reason is acceptable (NORMATIVE).
    ///
    /// This method enforces the promotion rules from FCP Specification §8.4.1.
    /// Takes `&self` for future extensibility (e.g., checking object presence).
    #[allow(clippy::unused_self)]
    fn validate_promotion_reason(
        &self,
        object_id: &ObjectId,
        reason: &PromotionReason,
    ) -> Result<(), QuarantineError> {
        match reason {
            PromotionReason::ReachableFromCheckpoint { checkpoint_id } => {
                // Caller must have verified reachability from checkpoint
                // We just validate the checkpoint_id is not the same as the object
                // (can't reach yourself from yourself)
                if checkpoint_id == object_id {
                    return Err(QuarantineError::PromotionDenied {
                        reason: "Object cannot be reachable from itself".into(),
                    });
                }
            }
            PromotionReason::AuthenticatedPeerRequest {
                peer_id,
                request_token,
            } => {
                // Validate peer request has non-empty token
                if request_token.is_empty() {
                    return Err(QuarantineError::PromotionDenied {
                        reason: "Authenticated peer request requires a valid request token".into(),
                    });
                }
                // Validate peer_id is non-zero (0 typically means unknown/invalid)
                if *peer_id == 0 {
                    return Err(QuarantineError::PromotionDenied {
                        reason: "Invalid peer ID".into(),
                    });
                }
            }
            PromotionReason::LocalPin { reason: pin_reason } => {
                // Local pin must have a non-empty reason for audit trail
                if pin_reason.is_empty() {
                    return Err(QuarantineError::PromotionDenied {
                        reason: "Local pin requires a reason for audit trail".into(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Check if an object is in quarantine (unfiltered).
    ///
    /// Returns `true` for any entry regardless of freshness. Intended for
    /// internal admin/eviction paths. **Callers consulting quarantine
    /// state for liveness MUST use [`Self::contains_fresh`]** — see
    /// [`Self::get`] for the drift rationale.
    #[must_use]
    pub fn contains(&self, object_id: &ObjectId) -> bool {
        let zones = self.zones.read();
        zones.values().any(|z| z.objects.contains_key(object_id))
    }

    /// Check if an object is in quarantine, filtering out TTL-expired
    /// entries by `current_time`.
    ///
    /// Returns `false` for any record whose `received_at` is older than
    /// the policy's `quarantine_ttl_secs` relative to `current_time`,
    /// even if [`Self::evict_expired`] has not yet swept it. This is the
    /// canonical liveness check — any caller that wants to answer "is
    /// this object currently quarantined?" MUST use this variant, not
    /// [`Self::contains`]. Closes bead flywheel_connectors-dzhhq.
    #[must_use]
    pub fn contains_fresh(&self, object_id: &ObjectId, current_time: u64) -> bool {
        let ttl = self.policy.quarantine_ttl_secs;
        let zones = self.zones.read();
        zones.values().any(|z| {
            z.objects
                .get(object_id)
                .is_some_and(|obj| current_time.saturating_sub(obj.received_at) <= ttl)
        })
    }

    /// Evict objects older than TTL.
    ///
    /// Returns the number of objects evicted.
    pub fn evict_expired(&self, current_time: u64) -> usize {
        let ttl = self.policy.quarantine_ttl_secs;
        let mut evicted = 0;

        let mut zones = self.zones.write();
        for zone in zones.values_mut() {
            let expired: Vec<ObjectId> = zone
                .objects
                .iter()
                .filter(|(_, obj)| current_time.saturating_sub(obj.received_at) > ttl)
                .map(|(id, _)| *id)
                .collect();

            for id in expired {
                if let Some(obj) = zone.objects.remove(&id) {
                    #[allow(clippy::cast_possible_truncation)]
                    let obj_size = obj.data.len() as u64;

                    let entry = EvictionEntry {
                        object_id: id,
                        received_at: obj.received_at,
                        peer_reputation: obj.peer_reputation,
                        size: obj_size,
                    };
                    zone.eviction_queue.remove(&entry);

                    zone.used_bytes = zone.used_bytes.saturating_sub(obj_size);
                    evicted += 1;
                }
            }
        }

        evicted
    }

    /// Get quarantine statistics for a zone.
    #[must_use]
    pub fn zone_stats(&self, zone_id: &ZoneId) -> QuarantineStats {
        let zones = self.zones.read();
        if let Some(zone) = zones.get(zone_id) {
            QuarantineStats {
                object_count: u32::try_from(zone.objects.len()).unwrap_or(u32::MAX),
                used_bytes: zone.used_bytes,
                max_bytes: self.policy.max_quarantine_bytes_per_zone,
                max_objects: self.policy.max_quarantine_objects_per_zone,
            }
        } else {
            QuarantineStats {
                object_count: 0,
                used_bytes: 0,
                max_bytes: self.policy.max_quarantine_bytes_per_zone,
                max_objects: self.policy.max_quarantine_objects_per_zone,
            }
        }
    }

    /// List all quarantined objects in a zone.
    pub fn list_zone(&self, zone_id: &ZoneId) -> Vec<ObjectId> {
        let zones = self.zones.read();
        zones
            .get(zone_id)
            .map(|z| z.objects.keys().copied().collect())
            .unwrap_or_default()
    }
}

/// Quarantine statistics for a zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineStats {
    /// Number of quarantined objects.
    pub object_count: u32,
    /// Bytes used by quarantined objects.
    pub used_bytes: u64,
    /// Maximum bytes allowed.
    pub max_bytes: u64,
    /// Maximum objects allowed.
    pub max_objects: u32,
}

impl QuarantineStats {
    /// Check if quarantine is near capacity.
    #[must_use]
    pub fn is_near_capacity(&self, threshold_pct: u8) -> bool {
        let threshold = u64::from(threshold_pct);
        let bytes_pct = self.used_bytes * 100 / self.max_bytes.max(1);
        let objects_pct = u64::from(self.object_count) * 100 / u64::from(self.max_objects.max(1));
        bytes_pct >= threshold || objects_pct >= threshold
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::time::Instant;

    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    #[derive(Default)]
    struct StoreLogData {
        object_id: Option<ObjectId>,
        object_size: Option<u64>,
        symbol_count: Option<u32>,
        coverage_bps: Option<u32>,
        nodes_holding: Option<Vec<String>>,
        details: Option<serde_json::Value>,
    }

    fn run_store_test<F>(test_name: &str, phase: &str, operation: &str, assertions: u32, f: F)
    where
        F: FnOnce() -> StoreLogData + panic::UnwindSafe,
    {
        let start = Instant::now();
        let result = panic::catch_unwind(AssertUnwindSafe(f));
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

    fn test_object(id: u8, size: usize, received_at: u64) -> QuarantinedObject {
        QuarantinedObject {
            object_id: ObjectId::from_bytes([id; 32]),
            zone_id: test_zone(),
            data: Bytes::from(vec![0_u8; size]),
            source_peer: Some(1),
            received_at,
            peer_reputation: 50,
        }
    }

    #[test]
    fn quarantine_and_get() {
        run_store_test("quarantine_and_get", "verify", "quarantine", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let obj = test_object(1, 100, 1000);

            store.quarantine(obj.clone()).unwrap();

            let retrieved = store.get(&obj.object_id).unwrap();
            assert_eq!(retrieved.object_id, obj.object_id);

            StoreLogData {
                object_id: Some(obj.object_id),
                object_size: Some(obj.data.len() as u64),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quarantine_duplicate_ignored() {
        run_store_test(
            "quarantine_duplicate_ignored",
            "verify",
            "quarantine",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);

                store.quarantine(obj.clone()).unwrap();
                store.quarantine(obj).unwrap();

                let stats = store.zone_stats(&test_zone());
                assert_eq!(stats.object_count, 1);

                StoreLogData {
                    details: Some(json!({"object_count": stats.object_count})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn remove_from_quarantine() {
        run_store_test("remove_from_quarantine", "verify", "quarantine", 2, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let obj = test_object(1, 100, 1000);
            let id = obj.object_id;

            store.quarantine(obj).unwrap();
            assert!(store.contains(&id));

            store.remove(&id).unwrap();
            assert!(!store.contains(&id));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"removed": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn evict_oldest_on_object_quota() {
        run_store_test(
            "evict_oldest_on_object_quota",
            "verify",
            "quarantine",
            3,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 3,
                    max_quarantine_bytes_per_zone: 1024 * 1024,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                store.quarantine(test_object(1, 100, 1000)).unwrap();
                store.quarantine(test_object(2, 100, 2000)).unwrap();
                store.quarantine(test_object(3, 100, 3000)).unwrap();

                store.quarantine(test_object(4, 100, 4000)).unwrap();

                let stats = store.zone_stats(&test_zone());
                assert_eq!(stats.object_count, 3);
                assert!(!store.contains(&ObjectId::from_bytes([1; 32])));
                assert!(store.contains(&ObjectId::from_bytes([4; 32])));

                StoreLogData {
                    details: Some(json!({"object_count": stats.object_count, "evicted": "oldest"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn evict_on_byte_quota() {
        run_store_test("evict_on_byte_quota", "verify", "quarantine", 1, || {
            let policy = ObjectAdmissionPolicy {
                max_quarantine_objects_per_zone: 100,
                max_quarantine_bytes_per_zone: 300,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 100, 2000)).unwrap();
            store.quarantine(test_object(3, 100, 3000)).unwrap();

            store.quarantine(test_object(4, 100, 4000)).unwrap();

            assert!(!store.contains(&ObjectId::from_bytes([1; 32])));

            StoreLogData {
                details: Some(json!({"evicted": "byte_quota"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn evict_expired() {
        run_store_test("evict_expired", "verify", "quarantine", 2, || {
            let policy = ObjectAdmissionPolicy {
                quarantine_ttl_secs: 100,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            // `quarantine()` triggers an in-band sweep at `obj.received_at`
            // (added in commit 0f1f4478a). Pack the first two `received_at`s
            // within the TTL window of each other so neither is expired at
            // the moment the third is quarantined; otherwise the in-band
            // sweep would silently pre-empt what the explicit
            // `evict_expired` call below is meant to count.
            //
            // ttl=100, packing within 100s of each other:
            //   id=1 received_at=1000
            //   id=2 received_at=1050   (1050-1000=50 ≤ 100, id=1 not yet expired)
            //   id=3 received_at=1100   (1100-1000=100  ≤ 100, id=1 not yet expired)
            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 100, 1050)).unwrap();
            store.quarantine(test_object(3, 100, 1100)).unwrap();

            // Advance to a time at which id=1 and id=2 are expired
            // (1200-1000=200 > ttl=100, 1200-1050=150 > 100) but id=3 is
            // not (1200-1100=100, NOT strictly > 100).
            let evicted = store.evict_expired(1200);
            assert_eq!(evicted, 2);

            let stats = store.zone_stats(&test_zone());
            assert_eq!(stats.object_count, 1);
            assert!(store.contains(&ObjectId::from_bytes([3; 32])));

            StoreLogData {
                details: Some(json!({"evicted": evicted, "remaining": stats.object_count})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quarantine_admission_sweeps_expired_entries_in_band() {
        run_store_test(
            "quarantine_admission_sweeps_expired_entries_in_band",
            "verify",
            "quarantine",
            2,
            || {
                let policy = ObjectAdmissionPolicy {
                    quarantine_ttl_secs: 1,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);
                let expired_id = ObjectId::from_bytes([1; 32]);
                let fresh_id = ObjectId::from_bytes([2; 32]);

                store.quarantine(test_object(1, 100, 1000)).unwrap();
                store.quarantine(test_object(2, 100, 1002)).unwrap();

                assert!(!store.contains(&expired_id));
                assert!(store.contains(&fresh_id));

                StoreLogData {
                    details: Some(json!({"expired_removed": expired_id, "fresh_kept": fresh_id})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn evict_expired_wall_clock_ttl() {
        run_store_test(
            "evict_expired_wall_clock_ttl",
            "verify",
            "quarantine",
            2,
            || {
                let policy = ObjectAdmissionPolicy {
                    quarantine_ttl_secs: 1,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let obj = test_object(1, 100, now);
                let object_id = obj.object_id;

                store.quarantine(obj).unwrap();
                std::thread::sleep(std::time::Duration::from_secs(2));

                let evicted = store.evict_expired(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );

                assert_eq!(evicted, 1);
                assert!(store.get(&object_id).is_none());
                assert!(!store.contains(&object_id));

                StoreLogData {
                    object_id: Some(object_id),
                    details: Some(json!({"evicted": evicted, "ttl_secs": 1})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn eviction_prefers_lower_reputation_before_larger_object_when_age_ties() {
        run_store_test(
            "eviction_prefers_lower_reputation_before_larger_object_when_age_ties",
            "verify",
            "quarantine",
            3,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 2,
                    max_quarantine_bytes_per_zone: 1024 * 1024,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                let mut smaller_low_rep = test_object(1, 100, 1000);
                smaller_low_rep.peer_reputation = 0;

                let mut larger_better_rep = test_object(2, 250, 1000);
                larger_better_rep.peer_reputation = 50;

                store.quarantine(smaller_low_rep).unwrap();
                store.quarantine(larger_better_rep).unwrap();
                store.quarantine(test_object(3, 100, 2000)).unwrap();

                assert!(!store.contains(&ObjectId::from_bytes([1; 32])));
                assert!(store.contains(&ObjectId::from_bytes([2; 32])));
                assert!(store.contains(&ObjectId::from_bytes([3; 32])));

                StoreLogData {
                    details: Some(json!({"evicted": "lowest_reputation_on_age_tie"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn zone_stats() {
        run_store_test("zone_stats", "verify", "quarantine", 2, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 200, 2000)).unwrap();

            let stats = store.zone_stats(&test_zone());
            assert_eq!(stats.object_count, 2);
            assert_eq!(stats.used_bytes, 300);

            StoreLogData {
                details: Some(json!({
                    "object_count": stats.object_count,
                    "used_bytes": stats.used_bytes
                })),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn is_near_capacity() {
        run_store_test("is_near_capacity", "verify", "quarantine", 2, || {
            let stats = QuarantineStats {
                object_count: 85,
                used_bytes: 200,
                max_bytes: 1000,
                max_objects: 100,
            };

            assert!(stats.is_near_capacity(80));
            assert!(!stats.is_near_capacity(90));

            StoreLogData {
                details: Some(json!({"object_pct": 85, "bytes_pct": 20})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone() {
        run_store_test("quarantine_list_zone", "verify", "list", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 100, 2000)).unwrap();

            let ids = store.list_zone(&test_zone());
            assert_eq!(ids.len(), 2);

            StoreLogData {
                details: Some(json!({"zone_id": test_zone().to_string(), "count": ids.len()})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn eviction_priority_order() {
        run_store_test("eviction_priority_order", "verify", "quarantine", 3, || {
            let policy = ObjectAdmissionPolicy {
                max_quarantine_objects_per_zone: 2,
                max_quarantine_bytes_per_zone: 1024 * 1024,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            let mut obj1 = test_object(1, 100, 2000);
            obj1.peer_reputation = 50;

            let mut obj2 = test_object(2, 100, 1000);
            obj2.peer_reputation = 50;

            store.quarantine(obj1).unwrap();
            store.quarantine(obj2).unwrap();

            store.quarantine(test_object(3, 100, 3000)).unwrap();

            assert!(store.contains(&ObjectId::from_bytes([1; 32])));
            assert!(!store.contains(&ObjectId::from_bytes([2; 32])));
            assert!(store.contains(&ObjectId::from_bytes([3; 32])));

            StoreLogData {
                details: Some(json!({"evicted": "oldest"})),
                ..StoreLogData::default()
            }
        });
    }

    // =========================================================================
    // Promotion validation tests (NORMATIVE)
    // =========================================================================

    #[test]
    fn promote_with_checkpoint_reachability() {
        run_store_test(
            "promote_with_checkpoint_reachability",
            "verify",
            "promotion",
            2,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();
                assert!(store.contains(&id));

                let checkpoint_id = ObjectId::from_bytes([99; 32]);
                let reason = PromotionReason::ReachableFromCheckpoint { checkpoint_id };

                let promoted = store.promote(&id, &reason, true).unwrap();
                assert_eq!(promoted.object_id, id);
                assert!(!store.contains(&id));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"promotion_reason": "checkpoint_reachability"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_with_authenticated_peer_request() {
        run_store_test(
            "promote_with_authenticated_peer_request",
            "verify",
            "promotion",
            2,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::AuthenticatedPeerRequest {
                    peer_id: 42,
                    request_token: vec![1, 2, 3, 4],
                };

                let promoted = store.promote(&id, &reason, true).unwrap();
                assert_eq!(promoted.object_id, id);
                assert!(!store.contains(&id));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"promotion_reason": "authenticated_peer"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_with_local_pin() {
        run_store_test("promote_with_local_pin", "verify", "promotion", 2, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let obj = test_object(1, 100, 1000);
            let id = obj.object_id;

            store.quarantine(obj).unwrap();

            let reason = PromotionReason::LocalPin {
                reason: "User explicitly requested this object".into(),
            };

            let promoted = store.promote(&id, &reason, true).unwrap();
            assert_eq!(promoted.object_id, id);
            assert!(!store.contains(&id));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"promotion_reason": "local_pin"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn promote_denied_self_referential_checkpoint() {
        run_store_test(
            "promote_denied_self_referential_checkpoint",
            "verify",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                // Try to promote with self as checkpoint (invalid)
                let reason = PromotionReason::ReachableFromCheckpoint { checkpoint_id: id };

                let result = store.promote(&id, &reason, true);
                assert!(matches!(
                    result,
                    Err(QuarantineError::PromotionDenied { .. })
                ));
                assert!(store.contains(&id)); // Still in quarantine

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "self_referential"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_denied_empty_request_token() {
        run_store_test(
            "promote_denied_empty_request_token",
            "verify",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::AuthenticatedPeerRequest {
                    peer_id: 42,
                    request_token: vec![], // Empty token
                };

                let result = store.promote(&id, &reason, true);
                assert!(matches!(
                    result,
                    Err(QuarantineError::PromotionDenied { .. })
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "empty_token"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_denied_invalid_peer_id() {
        run_store_test(
            "promote_denied_invalid_peer_id",
            "verify",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::AuthenticatedPeerRequest {
                    peer_id: 0, // Invalid peer ID
                    request_token: vec![1, 2, 3],
                };

                let result = store.promote(&id, &reason, true);
                assert!(matches!(
                    result,
                    Err(QuarantineError::PromotionDenied { .. })
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "invalid_peer_id"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_denied_empty_pin_reason() {
        run_store_test(
            "promote_denied_empty_pin_reason",
            "verify",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::LocalPin {
                    reason: String::new(), // Empty reason
                };

                let result = store.promote(&id, &reason, true);
                assert!(matches!(
                    result,
                    Err(QuarantineError::PromotionDenied { .. })
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "empty_pin_reason"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_denied_schema_validation_required() {
        run_store_test(
            "promote_denied_schema_validation_required",
            "verify",
            "promotion",
            1,
            || {
                let policy = ObjectAdmissionPolicy {
                    require_schema_validation: true,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::LocalPin {
                    reason: "User request".into(),
                };

                // schema_valid = false should fail
                let result = store.promote(&id, &reason, false);
                assert!(matches!(
                    result,
                    Err(QuarantineError::SchemaValidationFailed { .. })
                ));

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"denied_reason": "schema_validation_failed"})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn promote_succeeds_without_schema_validation_when_not_required() {
        run_store_test(
            "promote_succeeds_without_schema_validation",
            "verify",
            "promotion",
            1,
            || {
                let policy = ObjectAdmissionPolicy {
                    require_schema_validation: false, // Not required
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                let reason = PromotionReason::LocalPin {
                    reason: "User request".into(),
                };

                // schema_valid = false should succeed when not required
                let promoted = store.promote(&id, &reason, false).unwrap();
                assert_eq!(promoted.object_id, id);

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({"schema_validation_required": false})),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Adversarial tests (attack scenarios)
    // =========================================================================

    #[test]
    fn adversarial_rapid_quota_exhaustion_attempt() {
        run_store_test(
            "adversarial_rapid_quota_exhaustion",
            "adversarial",
            "quarantine",
            2,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 10,
                    max_quarantine_bytes_per_zone: 1000,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                // Attacker tries to flood quarantine with many objects
                for i in 0..100 {
                    let obj = test_object(i, 50, u64::from(i));
                    let _ = store.quarantine(obj);
                }

                // Quota should be enforced
                let stats = store.zone_stats(&test_zone());
                assert!(stats.object_count <= 10);
                assert!(stats.used_bytes <= 1000);

                StoreLogData {
                    details: Some(json!({
                        "attack": "rapid_quota_exhaustion",
                        "objects_after": stats.object_count,
                        "bytes_after": stats.used_bytes,
                        "quota_enforced": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn adversarial_large_object_injection() {
        run_store_test(
            "adversarial_large_object_injection",
            "adversarial",
            "quarantine",
            1,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_bytes_per_zone: 500,
                    max_quarantine_objects_per_zone: 100,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                // Attacker tries to inject an object larger than quota
                let large_obj = QuarantinedObject {
                    object_id: ObjectId::from_bytes([1; 32]),
                    zone_id: test_zone(),
                    data: Bytes::from(vec![0_u8; 600]), // Larger than quota
                    source_peer: Some(1),
                    received_at: 1000,
                    peer_reputation: 50,
                };

                let result = store.quarantine(large_obj);
                // Should fail because no room can be made
                assert!(matches!(result, Err(QuarantineError::QuotaExceeded { .. })));

                StoreLogData {
                    details: Some(json!({
                        "attack": "large_object_injection",
                        "object_size": 600,
                        "quota": 500,
                        "rejected": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn adversarial_promotion_without_valid_reason() {
        run_store_test(
            "adversarial_promotion_without_valid_reason",
            "adversarial",
            "promotion",
            3,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;

                store.quarantine(obj).unwrap();

                // Attacker tries various invalid promotion attempts
                let invalid_reasons = vec![
                    PromotionReason::ReachableFromCheckpoint { checkpoint_id: id }, // Self-ref
                    PromotionReason::AuthenticatedPeerRequest {
                        peer_id: 0,
                        request_token: vec![1],
                    },
                    PromotionReason::AuthenticatedPeerRequest {
                        peer_id: 1,
                        request_token: vec![],
                    },
                    PromotionReason::LocalPin {
                        reason: String::new(),
                    },
                ];

                let mut all_denied = true;
                for reason in &invalid_reasons {
                    if store.promote(&id, reason, true).is_ok() {
                        all_denied = false;
                        break;
                    }
                }

                assert!(all_denied);
                assert!(store.contains(&id)); // Still in quarantine

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({
                        "attack": "invalid_promotion_attempts",
                        "attempts": invalid_reasons.len(),
                        "all_denied": all_denied
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn adversarial_promotion_not_in_quarantine() {
        run_store_test(
            "adversarial_promotion_not_in_quarantine",
            "adversarial",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

                // Attacker tries to promote an object that was never quarantined
                let fake_id = ObjectId::from_bytes([99; 32]);
                let reason = PromotionReason::LocalPin {
                    reason: "Fake promotion".into(),
                };

                let result = store.promote(&fake_id, &reason, true);
                assert!(matches!(result, Err(QuarantineError::NotFound(_))));

                StoreLogData {
                    object_id: Some(fake_id),
                    details: Some(json!({
                        "attack": "promote_non_existent",
                        "rejected": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn adversarial_promotion_invalid_reason_still_reports_not_found_for_missing_object() {
        run_store_test(
            "adversarial_promotion_invalid_reason_missing_object",
            "adversarial",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let fake_id = ObjectId::from_bytes([98; 32]);
                let reason = PromotionReason::ReachableFromCheckpoint {
                    checkpoint_id: fake_id,
                };

                let result = store.promote(&fake_id, &reason, true);
                assert!(matches!(result, Err(QuarantineError::NotFound(id)) if id == fake_id));

                StoreLogData {
                    object_id: Some(fake_id),
                    details: Some(json!({
                        "attack": "promote_missing_invalid_reason",
                        "rejected_as": "not_found"
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn adversarial_promotion_missing_object_reports_not_found_before_schema_failure() {
        run_store_test(
            "adversarial_promotion_missing_object_schema_precedence",
            "adversarial",
            "promotion",
            1,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
                let fake_id = ObjectId::from_bytes([97; 32]);
                let reason = PromotionReason::LocalPin {
                    reason: "operator requested object".into(),
                };

                let result = store.promote(&fake_id, &reason, false);
                assert!(matches!(result, Err(QuarantineError::NotFound(id)) if id == fake_id));

                StoreLogData {
                    object_id: Some(fake_id),
                    details: Some(json!({
                        "attack": "promote_missing_schema_invalid",
                        "rejected_as": "not_found"
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // --- New edge case tests ---

    #[test]
    fn object_admission_class_serde_roundtrip() {
        run_store_test("admission_class_serde", "verify", "serde", 2, || {
            for &class in &[
                ObjectAdmissionClass::Quarantined,
                ObjectAdmissionClass::Admitted,
            ] {
                let json = serde_json::to_string(&class).unwrap();
                let deserialized: ObjectAdmissionClass = serde_json::from_str(&json).unwrap();
                assert_eq!(class, deserialized);
            }

            StoreLogData {
                details: Some(json!({"serde": "all_variants_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn promotion_reason_serde_roundtrip() {
        run_store_test("promotion_reason_serde", "verify", "serde", 3, || {
            let reasons = vec![
                PromotionReason::ReachableFromCheckpoint {
                    checkpoint_id: ObjectId::from_bytes([1; 32]),
                },
                PromotionReason::AuthenticatedPeerRequest {
                    peer_id: 42,
                    request_token: vec![1, 2, 3],
                },
                PromotionReason::LocalPin {
                    reason: "test pin".into(),
                },
            ];

            for reason in &reasons {
                let json = serde_json::to_string(reason).unwrap();
                let deserialized: PromotionReason = serde_json::from_str(&json).unwrap();
                assert_eq!(*reason, deserialized);
            }

            StoreLogData {
                details: Some(json!({"serde": "all_variants_ok", "count": 3})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_admission_policy_default_values() {
        run_store_test("policy_defaults", "verify", "config", 4, || {
            let policy = ObjectAdmissionPolicy::default();
            assert_eq!(policy.max_quarantine_bytes_per_zone, 256 * 1024 * 1024);
            assert_eq!(policy.max_quarantine_objects_per_zone, 100_000);
            assert_eq!(policy.quarantine_ttl_secs, 3600);
            assert!(policy.require_schema_validation);

            StoreLogData {
                details: Some(json!({"defaults_verified": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quarantine_stats_serde_roundtrip() {
        run_store_test("quarantine_stats_serde", "verify", "serde", 1, || {
            let stats = QuarantineStats {
                object_count: 5,
                used_bytes: 1024,
                max_bytes: 65536,
                max_objects: 100,
            };
            let json = serde_json::to_string(&stats).unwrap();
            let deserialized: QuarantineStats = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.object_count, 5);
            assert_eq!(deserialized.used_bytes, 1024);

            StoreLogData {
                details: Some(json!({"serde": "roundtrip_ok"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn remove_not_found() {
        run_store_test("remove_not_found", "verify", "quarantine", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let unknown_id = ObjectId::from_bytes([99; 32]);

            let result = store.remove(&unknown_id);
            assert!(matches!(result, Err(QuarantineError::NotFound(_))));

            StoreLogData {
                object_id: Some(unknown_id),
                details: Some(json!({"error": "not_found"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn contains_empty_store() {
        run_store_test("contains_empty_store", "verify", "quarantine", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let id = ObjectId::from_bytes([1; 32]);
            assert!(!store.contains(&id));

            StoreLogData {
                details: Some(json!({"contains": false})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn get_empty_store() {
        run_store_test("get_empty_store", "verify", "quarantine", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let id = ObjectId::from_bytes([1; 32]);
            assert!(store.get(&id).is_none());

            StoreLogData {
                details: Some(json!({"get": "none"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn evict_expired_none_expired() {
        run_store_test("evict_expired_none", "verify", "quarantine", 1, || {
            let policy = ObjectAdmissionPolicy {
                quarantine_ttl_secs: 3600,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 100, 2000)).unwrap();

            // Current time still within TTL
            let evicted = store.evict_expired(2000);
            assert_eq!(evicted, 0);

            StoreLogData {
                details: Some(json!({"evicted": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone_unknown_zone() {
        run_store_test("list_zone_unknown", "verify", "list", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let unknown_zone: ZoneId = "z:unknown".parse().unwrap();

            let ids = store.list_zone(&unknown_zone);
            assert!(ids.is_empty());

            StoreLogData {
                details: Some(json!({"zone": "z:unknown", "count": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn zone_stats_unknown_zone() {
        run_store_test("zone_stats_unknown", "verify", "quarantine", 2, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let unknown_zone: ZoneId = "z:unknown".parse().unwrap();

            let stats = store.zone_stats(&unknown_zone);
            assert_eq!(stats.object_count, 0);
            assert_eq!(stats.used_bytes, 0);

            StoreLogData {
                details: Some(json!({"zone": "z:unknown", "empty": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn is_near_capacity_by_bytes() {
        run_store_test("is_near_capacity_bytes", "verify", "quarantine", 2, || {
            let stats = QuarantineStats {
                object_count: 1,
                used_bytes: 900,
                max_bytes: 1000,
                max_objects: 1000,
            };

            assert!(stats.is_near_capacity(90));
            assert!(!stats.is_near_capacity(95));

            StoreLogData {
                details: Some(json!({"bytes_pct": 90})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quarantine_remove_frees_bytes() {
        run_store_test("remove_frees_bytes", "verify", "quarantine", 2, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let obj = test_object(1, 200, 1000);
            let id = obj.object_id;

            store.quarantine(obj).unwrap();
            let stats_before = store.zone_stats(&test_zone());
            assert_eq!(stats_before.used_bytes, 200);

            store.remove(&id).unwrap();
            let stats_after = store.zone_stats(&test_zone());
            assert_eq!(stats_after.used_bytes, 0);

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({"bytes_before": 200, "bytes_after": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn object_admission_class_copy_eq() {
        let a = ObjectAdmissionClass::Quarantined;
        let b = a; // Copy
        assert_eq!(a, b);

        let c = ObjectAdmissionClass::Admitted;
        assert_ne!(a, c);
    }

    #[test]
    fn object_admission_policy_serde_roundtrip() {
        run_store_test("policy_serde", "verify", "serde", 1, || {
            let policy = ObjectAdmissionPolicy {
                max_quarantine_bytes_per_zone: 1024,
                max_quarantine_objects_per_zone: 50,
                quarantine_ttl_secs: 7200,
                require_schema_validation: false,
            };
            let json = serde_json::to_string(&policy).unwrap();
            let deserialized: ObjectAdmissionPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(
                deserialized.max_quarantine_bytes_per_zone,
                policy.max_quarantine_bytes_per_zone
            );
            assert_eq!(
                deserialized.max_quarantine_objects_per_zone,
                policy.max_quarantine_objects_per_zone
            );
            assert_eq!(deserialized.quarantine_ttl_secs, 7200);
            assert!(!deserialized.require_schema_validation);

            StoreLogData {
                details: Some(json!({"serde": "policy_roundtrip"})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quarantined_object_clone() {
        run_store_test("quarantined_obj_clone", "verify", "traits", 2, || {
            let obj = test_object(1, 100, 1000);
            let cloned = obj.clone();
            assert_eq!(cloned.object_id, obj.object_id);
            assert_eq!(cloned.data.len(), obj.data.len());

            StoreLogData {
                object_id: Some(obj.object_id),
                details: Some(json!({"clone": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn quarantined_object_debug() {
        let obj = test_object(1, 50, 1000);
        let dbg = format!("{obj:?}");
        assert!(dbg.contains("QuarantinedObject"));
    }

    #[test]
    fn multiple_zones_isolation() {
        run_store_test("multiple_zones", "verify", "quarantine", 3, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

            let mut obj1 = test_object(1, 100, 1000);
            obj1.zone_id = "z:alpha".parse().unwrap();

            let mut obj2 = test_object(2, 100, 2000);
            obj2.zone_id = "z:beta".parse().unwrap();

            store.quarantine(obj1).unwrap();
            store.quarantine(obj2).unwrap();

            let alpha: ZoneId = "z:alpha".parse().unwrap();
            let beta: ZoneId = "z:beta".parse().unwrap();

            assert_eq!(store.zone_stats(&alpha).object_count, 1);
            assert_eq!(store.zone_stats(&beta).object_count, 1);
            assert_eq!(store.list_zone(&alpha).len(), 1);

            StoreLogData {
                details: Some(json!({"zones": 2})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn evict_expired_empty_store() {
        run_store_test("evict_empty", "verify", "quarantine", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());
            let evicted = store.evict_expired(999_999);
            assert_eq!(evicted, 0);

            StoreLogData {
                details: Some(json!({"evicted": 0})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn evict_expired_all_expired() {
        run_store_test("evict_all_expired", "verify", "quarantine", 2, || {
            let policy = ObjectAdmissionPolicy {
                quarantine_ttl_secs: 100,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            // Pack `received_at`s within the TTL window so the in-band
            // sweep performed by `quarantine()` (commit 0f1f4478a) cannot
            // expire any prior object before the next is admitted —
            // otherwise the explicit `evict_expired(500)` below sees a
            // smaller residual than expected.
            store.quarantine(test_object(1, 100, 100)).unwrap();
            store.quarantine(test_object(2, 100, 150)).unwrap();
            store.quarantine(test_object(3, 100, 200)).unwrap();

            // All three older than TTL at current_time=500:
            //   500-100=400 > 100, 500-150=350 > 100, 500-200=300 > 100.
            let evicted = store.evict_expired(500);
            assert_eq!(evicted, 3);

            let stats = store.zone_stats(&test_zone());
            assert_eq!(stats.object_count, 0);

            StoreLogData {
                details: Some(json!({"evicted": 3})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn is_near_capacity_zero_max() {
        // Edge case: max_bytes=0, max_objects=0
        let stats = QuarantineStats {
            object_count: 0,
            used_bytes: 0,
            max_bytes: 0,
            max_objects: 0,
        };
        // Should not panic (uses .max(1) internally)
        let _result = stats.is_near_capacity(90);
    }

    #[test]
    fn quarantine_stats_clone() {
        let stats = QuarantineStats {
            object_count: 3,
            used_bytes: 500,
            max_bytes: 1000,
            max_objects: 100,
        };
        let cloned = stats.clone();
        assert_eq!(cloned.object_count, stats.object_count);
        assert_eq!(cloned.used_bytes, stats.used_bytes);
    }

    #[test]
    fn quarantine_stats_debug() {
        let stats = QuarantineStats {
            object_count: 1,
            used_bytes: 100,
            max_bytes: 1000,
            max_objects: 10,
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("QuarantineStats"));
    }

    #[test]
    fn promotion_reason_clone() {
        let reason = PromotionReason::LocalPin {
            reason: "test".into(),
        };
        let cloned = reason.clone();
        assert_eq!(reason, cloned);
    }

    #[test]
    fn object_admission_policy_clone() {
        let policy = ObjectAdmissionPolicy::default();
        let cloned = policy.clone();
        assert_eq!(
            cloned.max_quarantine_bytes_per_zone,
            policy.max_quarantine_bytes_per_zone
        );
    }

    #[test]
    fn object_admission_policy_debug() {
        let policy = ObjectAdmissionPolicy::default();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("ObjectAdmissionPolicy"));
    }

    #[test]
    fn get_returns_correct_data() {
        run_store_test("get_correct_data", "verify", "quarantine", 2, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

            let mut obj = test_object(1, 100, 1000);
            obj.source_peer = Some(42);
            obj.peer_reputation = 75;

            store.quarantine(obj).unwrap();

            let retrieved = store.get(&ObjectId::from_bytes([1; 32])).unwrap();
            assert_eq!(retrieved.source_peer, Some(42));
            assert_eq!(retrieved.peer_reputation, 75);

            StoreLogData {
                details: Some(json!({"correct_data": true})),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn eviction_entry_ord_oldest_first() {
        // EvictionEntry is private, but we test indirectly through quarantine behavior
        // Objects with oldest timestamps should be evicted first
        run_store_test("eviction_oldest_first", "verify", "quarantine", 2, || {
            let policy = ObjectAdmissionPolicy {
                max_quarantine_objects_per_zone: 2,
                max_quarantine_bytes_per_zone: 1024 * 1024,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            // Newer first, then older
            store.quarantine(test_object(1, 100, 5000)).unwrap();
            store.quarantine(test_object(2, 100, 1000)).unwrap();

            // Trigger eviction - oldest (2, received_at=1000) should be evicted
            store.quarantine(test_object(3, 100, 6000)).unwrap();

            assert!(!store.contains(&ObjectId::from_bytes([2; 32])));
            assert!(store.contains(&ObjectId::from_bytes([1; 32])));

            StoreLogData {
                details: Some(json!({"evicted_oldest": true})),
                ..StoreLogData::default()
            }
        });
    }

    // --- ObjectAdmissionClass serde tests ---

    #[test]
    fn admission_class_serde_quarantined() {
        let json = serde_json::to_string(&ObjectAdmissionClass::Quarantined).unwrap();
        let rt: ObjectAdmissionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, ObjectAdmissionClass::Quarantined);
    }

    #[test]
    fn admission_class_serde_admitted() {
        let json = serde_json::to_string(&ObjectAdmissionClass::Admitted).unwrap();
        let rt: ObjectAdmissionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, ObjectAdmissionClass::Admitted);
    }

    #[test]
    fn admission_class_debug() {
        let dbg = format!("{:?}", ObjectAdmissionClass::Quarantined);
        assert!(dbg.contains("Quarantined"));
    }

    #[test]
    fn admission_class_clone_and_copy() {
        let a = ObjectAdmissionClass::Admitted;
        let b = a;
        assert_eq!(a, b);
    }

    // --- PromotionReason serde tests ---

    #[test]
    fn promotion_reason_serde_reachable() {
        let reason = PromotionReason::ReachableFromCheckpoint {
            checkpoint_id: ObjectId::from_bytes([5; 32]),
        };
        let json = serde_json::to_string(&reason).unwrap();
        let rt: PromotionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, reason);
    }

    #[test]
    fn promotion_reason_serde_peer_request() {
        let reason = PromotionReason::AuthenticatedPeerRequest {
            peer_id: 42,
            request_token: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&reason).unwrap();
        let rt: PromotionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, reason);
    }

    #[test]
    fn promotion_reason_serde_local_pin() {
        let reason = PromotionReason::LocalPin {
            reason: "test pin".into(),
        };
        let json = serde_json::to_string(&reason).unwrap();
        let rt: PromotionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, reason);
    }

    #[test]
    fn promotion_reason_debug() {
        let reason = PromotionReason::LocalPin {
            reason: "testing".into(),
        };
        let dbg = format!("{reason:?}");
        assert!(dbg.contains("LocalPin"));
    }

    #[test]
    fn promotion_reason_clone_preserves_fields() {
        let reason = PromotionReason::AuthenticatedPeerRequest {
            peer_id: 10,
            request_token: vec![9, 8, 7],
        };
        let cloned = reason.clone();
        assert_eq!(reason, cloned);
    }

    // --- ObjectAdmissionPolicy tests ---

    #[test]
    fn admission_policy_default() {
        let policy = ObjectAdmissionPolicy::default();
        assert_eq!(policy.max_quarantine_bytes_per_zone, 256 * 1024 * 1024);
        assert_eq!(policy.max_quarantine_objects_per_zone, 100_000);
        assert_eq!(policy.quarantine_ttl_secs, 3600);
        assert!(policy.require_schema_validation);
    }

    #[test]
    fn admission_policy_serde_roundtrip() {
        let policy = ObjectAdmissionPolicy {
            max_quarantine_bytes_per_zone: 1024,
            max_quarantine_objects_per_zone: 50,
            quarantine_ttl_secs: 120,
            require_schema_validation: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let rt: ObjectAdmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.max_quarantine_bytes_per_zone, 1024);
        assert_eq!(rt.max_quarantine_objects_per_zone, 50);
        assert_eq!(rt.quarantine_ttl_secs, 120);
        assert!(!rt.require_schema_validation);
    }

    #[test]
    fn admission_policy_debug() {
        let policy = ObjectAdmissionPolicy::default();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("ObjectAdmissionPolicy"));
    }

    // --- QuarantineStats tests ---

    #[test]
    fn quarantine_stats_serde_json_roundtrip() {
        let stats = QuarantineStats {
            object_count: 10,
            used_bytes: 5000,
            max_bytes: 10_000,
            max_objects: 100,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let rt: QuarantineStats = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.object_count, 10);
        assert_eq!(rt.used_bytes, 5000);
    }

    #[test]
    fn quarantine_stats_debug_format() {
        let stats = QuarantineStats {
            object_count: 0,
            used_bytes: 0,
            max_bytes: 1000,
            max_objects: 10,
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("QuarantineStats"));
    }

    #[test]
    fn quarantine_stats_clone_preserves_fields() {
        let stats = QuarantineStats {
            object_count: 5,
            used_bytes: 2500,
            max_bytes: 5000,
            max_objects: 50,
        };
        let cloned = stats.clone();
        assert_eq!(stats.object_count, cloned.object_count);
        assert_eq!(stats.used_bytes, cloned.used_bytes);
    }

    #[test]
    fn quarantine_stats_near_capacity_bytes() {
        let stats = QuarantineStats {
            object_count: 1,
            used_bytes: 90,
            max_bytes: 100,
            max_objects: 1000,
        };
        assert!(stats.is_near_capacity(90));
        assert!(!stats.is_near_capacity(95));
    }

    #[test]
    fn quarantine_stats_near_capacity_objects() {
        let stats = QuarantineStats {
            object_count: 95,
            used_bytes: 10,
            max_bytes: 100_000,
            max_objects: 100,
        };
        assert!(stats.is_near_capacity(90));
    }

    #[test]
    fn quarantine_stats_not_near_capacity() {
        let stats = QuarantineStats {
            object_count: 1,
            used_bytes: 10,
            max_bytes: 100_000,
            max_objects: 100,
        };
        assert!(!stats.is_near_capacity(90));
    }

    // --- QuarantineStats additional tests ---

    #[test]
    fn quarantine_stats_serde_all_fields_rt() {
        let stats = QuarantineStats {
            object_count: 42,
            used_bytes: 1024,
            max_bytes: 4096,
            max_objects: 100,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let rt: QuarantineStats = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.object_count, 42);
        assert_eq!(rt.used_bytes, 1024);
        assert_eq!(rt.max_bytes, 4096);
        assert_eq!(rt.max_objects, 100);
    }

    #[test]
    fn quarantine_stats_debug_contains_fields() {
        let stats = QuarantineStats {
            object_count: 0,
            used_bytes: 0,
            max_bytes: 1000,
            max_objects: 50,
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("QuarantineStats"));
    }

    #[test]
    fn quarantine_stats_clone_all_fields() {
        let stats = QuarantineStats {
            object_count: 5,
            used_bytes: 500,
            max_bytes: 1000,
            max_objects: 10,
        };
        let cloned = stats.clone();
        assert_eq!(stats.object_count, cloned.object_count);
        assert_eq!(stats.used_bytes, cloned.used_bytes);
    }

    // --- ObjectAdmissionClass additional tests ---

    #[test]
    fn object_admission_class_serde_both_variants() {
        let q = ObjectAdmissionClass::Quarantined;
        let json = serde_json::to_string(&q).unwrap();
        let rt: ObjectAdmissionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, ObjectAdmissionClass::Quarantined);

        let a = ObjectAdmissionClass::Admitted;
        let json = serde_json::to_string(&a).unwrap();
        let rt: ObjectAdmissionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, ObjectAdmissionClass::Admitted);
    }

    #[test]
    fn object_admission_class_copy_and_ne() {
        let a = ObjectAdmissionClass::Quarantined;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, ObjectAdmissionClass::Admitted);
    }

    #[test]
    fn object_admission_class_debug_fmt() {
        let dbg = format!("{:?}", ObjectAdmissionClass::Quarantined);
        assert!(dbg.contains("Quarantined"));
    }

    // --- PromotionReason additional tests ---

    #[test]
    fn promotion_reason_local_pin_json_rt() {
        let reason = PromotionReason::LocalPin {
            reason: "test pin".into(),
        };
        let json = serde_json::to_string(&reason).unwrap();
        let rt: PromotionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, rt);
    }

    #[test]
    fn promotion_reason_checkpoint_json_rt() {
        let reason = PromotionReason::ReachableFromCheckpoint {
            checkpoint_id: ObjectId::from_bytes([5; 32]),
        };
        let json = serde_json::to_string(&reason).unwrap();
        let rt: PromotionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, rt);
    }

    #[test]
    fn promotion_reason_debug_peer_request() {
        let reason = PromotionReason::AuthenticatedPeerRequest {
            peer_id: 42,
            request_token: vec![1, 2, 3],
        };
        let dbg = format!("{reason:?}");
        assert!(dbg.contains("AuthenticatedPeerRequest"));
        assert!(dbg.contains("42"));
    }

    // --- ObjectAdmissionPolicy additional tests ---

    #[test]
    fn object_admission_policy_default_field_values() {
        let policy = ObjectAdmissionPolicy::default();
        assert_eq!(policy.max_quarantine_bytes_per_zone, 256 * 1024 * 1024);
        assert_eq!(policy.max_quarantine_objects_per_zone, 100_000);
        assert_eq!(policy.quarantine_ttl_secs, 3600);
        assert!(policy.require_schema_validation);
    }

    #[test]
    fn object_admission_policy_serde_json_rt() {
        let policy = ObjectAdmissionPolicy {
            max_quarantine_bytes_per_zone: 512,
            max_quarantine_objects_per_zone: 10,
            quarantine_ttl_secs: 60,
            require_schema_validation: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let rt: ObjectAdmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.max_quarantine_bytes_per_zone, 512);
        assert!(!rt.require_schema_validation);
    }

    #[test]
    fn quarantine_stats_is_near_capacity_by_bytes() {
        let stats = QuarantineStats {
            object_count: 1,
            used_bytes: 95,
            max_bytes: 100,
            max_objects: 1000,
        };
        assert!(stats.is_near_capacity(90));
    }

    // =========================================================================
    // Eviction edge cases
    // =========================================================================

    #[test]
    fn eviction_identical_age_and_reputation_uses_size_tiebreak() {
        run_store_test(
            "eviction_identical_age_reputation_size_tiebreak",
            "verify",
            "quarantine",
            3,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 2,
                    max_quarantine_bytes_per_zone: 1024 * 1024,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                // All same age (1000) and same reputation (50)
                let mut obj1 = test_object(1, 50, 1000); // smaller
                obj1.peer_reputation = 50;

                let mut obj2 = test_object(2, 200, 1000); // larger → evicted first on tie
                obj2.peer_reputation = 50;

                store.quarantine(obj1).unwrap();
                store.quarantine(obj2).unwrap();

                // Third object triggers eviction
                store.quarantine(test_object(3, 100, 2000)).unwrap();

                // Largest object (obj2) should be evicted when age+rep tie
                assert!(store.contains(&ObjectId::from_bytes([1; 32])));
                assert!(!store.contains(&ObjectId::from_bytes([2; 32])));
                assert!(store.contains(&ObjectId::from_bytes([3; 32])));

                StoreLogData {
                    details: Some(json!({
                        "tiebreak": "size",
                        "largest_evicted": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn eviction_with_max_objects_one_always_replaces() {
        run_store_test(
            "eviction_max_objects_one",
            "verify",
            "quarantine",
            3,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 1,
                    max_quarantine_bytes_per_zone: 1024 * 1024,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                store.quarantine(test_object(1, 100, 1000)).unwrap();
                assert!(store.contains(&ObjectId::from_bytes([1; 32])));

                store.quarantine(test_object(2, 100, 2000)).unwrap();
                assert!(!store.contains(&ObjectId::from_bytes([1; 32])));
                assert!(store.contains(&ObjectId::from_bytes([2; 32])));

                store.quarantine(test_object(3, 100, 3000)).unwrap();
                assert!(!store.contains(&ObjectId::from_bytes([2; 32])));
                assert!(store.contains(&ObjectId::from_bytes([3; 32])));

                StoreLogData {
                    details: Some(json!({
                        "max_objects": 1,
                        "always_replaces": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn eviction_with_zero_byte_quota_rejects_all() {
        run_store_test(
            "eviction_zero_byte_quota",
            "adversarial",
            "quarantine",
            1,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 100,
                    max_quarantine_bytes_per_zone: 0,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                // Zero-byte quota means nothing can ever fit (data > 0 bytes)
                let result = store.quarantine(test_object(1, 100, 1000));
                assert!(matches!(result, Err(QuarantineError::QuotaExceeded { .. })));

                StoreLogData {
                    details: Some(json!({
                        "quota": 0,
                        "rejected": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Zone isolation tests
    // =========================================================================

    #[test]
    fn quarantine_objects_in_different_zones_independent() {
        run_store_test(
            "quarantine_zone_isolation",
            "verify",
            "quarantine",
            4,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 2,
                    max_quarantine_bytes_per_zone: 1024 * 1024,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                let zone_a: ZoneId = "z:project:alpha".parse().unwrap();
                let zone_b: ZoneId = "z:project:beta".parse().unwrap();

                // 2 objects in zone A (at max)
                let mut obj1 = test_object(1, 100, 1000);
                obj1.zone_id = zone_a.clone();
                store.quarantine(obj1).unwrap();

                let mut obj2 = test_object(2, 100, 2000);
                obj2.zone_id = zone_a;
                store.quarantine(obj2).unwrap();

                // 2 objects in zone B (independent quota)
                let mut obj3 = test_object(3, 100, 1000);
                obj3.zone_id = zone_b.clone();
                store.quarantine(obj3).unwrap();

                let mut obj4 = test_object(4, 100, 2000);
                obj4.zone_id = zone_b;
                store.quarantine(obj4).unwrap();

                // All 4 objects should exist — zones have independent quotas
                assert!(store.contains(&ObjectId::from_bytes([1; 32])));
                assert!(store.contains(&ObjectId::from_bytes([2; 32])));
                assert!(store.contains(&ObjectId::from_bytes([3; 32])));
                assert!(store.contains(&ObjectId::from_bytes([4; 32])));

                StoreLogData {
                    details: Some(json!({
                        "zone_a_count": 2,
                        "zone_b_count": 2,
                        "independent": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn quarantine_zone_quota_does_not_spill_across_zones() {
        run_store_test(
            "quarantine_no_quota_spillover",
            "verify",
            "quarantine",
            3,
            || {
                let policy = ObjectAdmissionPolicy {
                    max_quarantine_objects_per_zone: 1,
                    max_quarantine_bytes_per_zone: 1024 * 1024,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                let zone_a: ZoneId = "z:project:alpha".parse().unwrap();
                let zone_b: ZoneId = "z:project:beta".parse().unwrap();

                // Fill zone A to capacity
                let mut obj1 = test_object(1, 100, 1000);
                obj1.zone_id = zone_a.clone();
                store.quarantine(obj1).unwrap();

                // Zone B should still accept objects (independent)
                let mut obj2 = test_object(2, 100, 2000);
                obj2.zone_id = zone_b;
                store.quarantine(obj2).unwrap();

                assert!(store.contains(&ObjectId::from_bytes([1; 32])));
                assert!(store.contains(&ObjectId::from_bytes([2; 32])));

                // Adding to zone A should evict from zone A only
                let mut obj3 = test_object(3, 100, 3000);
                obj3.zone_id = zone_a;
                store.quarantine(obj3).unwrap();

                assert!(!store.contains(&ObjectId::from_bytes([1; 32]))); // evicted from A
                assert!(store.contains(&ObjectId::from_bytes([2; 32]))); // zone B unaffected
                assert!(store.contains(&ObjectId::from_bytes([3; 32])));

                StoreLogData {
                    details: Some(json!({
                        "zone_a_evicted": true,
                        "zone_b_unaffected": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    // =========================================================================
    // Promotion edge cases
    // =========================================================================

    #[test]
    fn promote_without_schema_validation_succeeds_when_policy_disabled() {
        run_store_test("promote_schema_disabled", "verify", "promotion", 2, || {
            let policy = ObjectAdmissionPolicy {
                require_schema_validation: false,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            let obj = test_object(1, 100, 1000);
            let id = obj.object_id;
            store.quarantine(obj).unwrap();

            // schema_valid=false but policy doesn't require it
            let reason = PromotionReason::LocalPin {
                reason: "operator override".into(),
            };
            let promoted = store.promote(&id, &reason, false).unwrap();
            assert_eq!(promoted.object_id, id);
            assert!(!store.contains(&id));

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({
                    "schema_disabled": true,
                    "promoted": true
                })),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn promote_fails_schema_when_policy_requires_it() {
        run_store_test(
            "promote_schema_required_fails",
            "verify",
            "promotion",
            2,
            || {
                let policy = ObjectAdmissionPolicy {
                    require_schema_validation: true,
                    ..Default::default()
                };
                let store = QuarantineStore::new(policy);

                let obj = test_object(1, 100, 1000);
                let id = obj.object_id;
                store.quarantine(obj).unwrap();

                let reason = PromotionReason::LocalPin {
                    reason: "operator override".into(),
                };
                let result = store.promote(&id, &reason, false);
                assert!(matches!(
                    result,
                    Err(QuarantineError::SchemaValidationFailed { .. })
                ));
                assert!(store.contains(&id)); // still quarantined

                StoreLogData {
                    object_id: Some(id),
                    details: Some(json!({
                        "schema_required": true,
                        "denied": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn remove_updates_zone_byte_count_correctly() {
        run_store_test("remove_updates_bytes", "verify", "quarantine", 3, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 200, 2000)).unwrap();

            let stats_before = store.zone_stats(&test_zone());
            assert_eq!(stats_before.used_bytes, 300);

            store.remove(&ObjectId::from_bytes([1; 32])).unwrap();

            let stats_after = store.zone_stats(&test_zone());
            assert_eq!(stats_after.used_bytes, 200);
            assert_eq!(stats_after.object_count, 1);

            StoreLogData {
                details: Some(json!({
                    "bytes_before": 300,
                    "bytes_after": 200,
                    "correctly_decremented": true
                })),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn duplicate_quarantine_is_idempotent() {
        run_store_test(
            "duplicate_quarantine_idempotent",
            "verify",
            "quarantine",
            3,
            || {
                let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

                let obj = test_object(1, 100, 1000);
                store.quarantine(obj.clone()).unwrap();
                store.quarantine(obj).unwrap(); // duplicate

                let stats = store.zone_stats(&test_zone());
                assert_eq!(stats.object_count, 1); // not double-counted
                assert_eq!(stats.used_bytes, 100); // not double-counted

                StoreLogData {
                    details: Some(json!({
                        "duplicate_handled": true,
                        "idempotent": true
                    })),
                    ..StoreLogData::default()
                }
            },
        );
    }

    #[test]
    fn evict_expired_returns_zero_when_all_fresh() {
        run_store_test("evict_expired_all_fresh", "verify", "quarantine", 2, || {
            let policy = ObjectAdmissionPolicy {
                quarantine_ttl_secs: 100,
                ..Default::default()
            };
            let store = QuarantineStore::new(policy);

            store.quarantine(test_object(1, 100, 1000)).unwrap();
            store.quarantine(test_object(2, 100, 1050)).unwrap();

            // Check at time 1099 — both are within TTL
            let evicted = store.evict_expired(1099);
            assert_eq!(evicted, 0);

            let stats = store.zone_stats(&test_zone());
            assert_eq!(stats.object_count, 2);

            StoreLogData {
                details: Some(json!({
                    "all_fresh": true,
                    "evicted": 0
                })),
                ..StoreLogData::default()
            }
        });
    }

    #[test]
    fn list_zone_returns_empty_for_unknown_zone() {
        run_store_test("list_zone_unknown", "verify", "quarantine", 1, || {
            let store = QuarantineStore::new(ObjectAdmissionPolicy::default());

            let unknown_zone: ZoneId = "z:project:nonexistent".parse().unwrap();
            let ids = store.list_zone(&unknown_zone);
            assert!(ids.is_empty());

            StoreLogData {
                details: Some(json!({
                    "unknown_zone": true,
                    "empty_list": true
                })),
                ..StoreLogData::default()
            }
        });
    }

    /// Regression for bead flywheel_connectors-dzhhq.
    ///
    /// `QuarantineStore::get` / `::contains` used to return expired
    /// entries indefinitely if `evict_expired` was never called — which
    /// in practice was always, because no production caller invoked it.
    /// The new `get_fresh` / `contains_fresh` helpers close that drift
    /// by filtering TTL-expired entries at read time using the same
    /// `current_time.saturating_sub(received_at) > ttl` rule as the
    /// sweep path.
    #[test]
    fn get_fresh_and_contains_fresh_filter_ttl_expired_entries() {
        run_store_test("get_fresh_ttl_filter", "verify", "quarantine", 6, || {
            // 10-second TTL makes the test cheap to reason about.
            let policy = ObjectAdmissionPolicy {
                quarantine_ttl_secs: 10,
                ..ObjectAdmissionPolicy::default()
            };
            let store = QuarantineStore::new(policy);
            // Object received at t=1000; TTL expires at t=1010.
            let obj = test_object(1, 64, 1000);
            let id = obj.object_id;
            store.quarantine(obj).unwrap();

            // Within TTL window (same second): fresh helpers see it.
            assert!(
                store.get_fresh(&id, 1000).is_some(),
                "get_fresh must return the object at received_at exactly"
            );
            assert!(
                store.contains_fresh(&id, 1005),
                "contains_fresh must return true inside TTL window"
            );

            // Exactly at the TTL boundary (current - received == ttl):
            // NOT expired, because the rule is strictly greater-than.
            assert!(
                store.get_fresh(&id, 1010).is_some(),
                "get_fresh MUST NOT expire at the TTL boundary (rule is >, not >=)"
            );

            // Past the TTL: fresh helpers refuse the entry even though
            // the sweep has not run. The unfiltered `get`/`contains`
            // still return it — that's the intentional split that the
            // admin/eviction paths rely on.
            assert!(
                store.get_fresh(&id, 1011).is_none(),
                "get_fresh MUST treat an entry past TTL as absent"
            );
            assert!(
                !store.contains_fresh(&id, 1011),
                "contains_fresh MUST treat an entry past TTL as absent"
            );
            assert!(
                store.contains(&id),
                "unfiltered contains() MUST still return true until evict_expired runs"
            );

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({
                    "ttl_secs": 10,
                    "received_at": 1000,
                    "fresh_cutoff": 1010
                })),
                ..StoreLogData::default()
            }
        });
    }

    /// Paired invariant: after `evict_expired` runs, *both* the fresh
    /// helpers AND the unfiltered ones MUST agree that the entry is
    /// gone. Prevents a future regression where `evict_expired` only
    /// tears down half of the state (e.g. removes from `objects` but
    /// not from `eviction_queue`).
    #[test]
    fn evict_expired_aligns_with_fresh_helpers() {
        run_store_test("evict_expired_aligns", "verify", "quarantine", 4, || {
            let policy = ObjectAdmissionPolicy {
                quarantine_ttl_secs: 5,
                ..ObjectAdmissionPolicy::default()
            };
            let store = QuarantineStore::new(policy);
            let obj = test_object(2, 64, 100);
            let id = obj.object_id;
            store.quarantine(obj).unwrap();

            // Past TTL, pre-sweep: fresh helpers already say "gone".
            assert!(
                store.get_fresh(&id, 200).is_none(),
                "get_fresh must reject expired entry before sweep"
            );

            // Sweep must agree — at least one eviction and no lingering
            // entries under either helper afterwards.
            let evicted = store.evict_expired(200);
            assert_eq!(evicted, 1, "evict_expired must sweep exactly 1 entry");
            assert!(
                store.get_fresh(&id, 200).is_none(),
                "get_fresh still absent after sweep"
            );
            assert!(
                !store.contains(&id),
                "unfiltered contains() must agree after sweep"
            );

            StoreLogData {
                object_id: Some(id),
                details: Some(json!({
                    "evicted": evicted,
                    "ttl_secs": 5,
                })),
                ..StoreLogData::default()
            }
        });
    }
}
