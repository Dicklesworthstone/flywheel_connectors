//! Optional content-id verification at store boundaries.
//!
//! # Why
//!
//! `StoredObject::object_id` is a *keyed* BLAKE3 hash of
//! `b"FCP2-OBJECT-V1" || canonical_cbor(header) || body` under the
//! zone's [`fcp_core::ObjectIdKey`]. The storage layer therefore cannot
//! verify the invariant
//!
//! ```text
//!     object.object_id == derive_id(&object.header, &object.body, zone_key)
//! ```
//!
//! without access to the zone key material, which lives outside the
//! store (in `ZoneKeyMaterial`). The runtime-API layer is the natural
//! owner of those keys.
//!
//! Bead flywheel_connectors-4g0qr documented a concrete attack:
//!
//!   1. An attacker with write access to the durable WAL file appends
//!      a forged `Put(StoredObject { object_id: H, header: H', body: B' })`
//!      where `H` is a previously-seen legitimate id but `(H', B')` are
//!      attacker-controlled bytes. The WAL envelope checksum covers the
//!      outer `(version, seq, op)` tuple, so the on-disk integrity
//!      check accepts the forged record.
//!   2. On restart, `load_durable_object_state` replays the WAL and
//!      calls `apply_loaded_mutation` → `insert_loaded` — neither of
//!      which verifies the inner `object_id → (header, body)` binding.
//!      The forged record lands in the in-memory map indexed by `H`.
//!   3. Subsequent reads for `H` return the attacker's `(H', B')`.
//!
//! # How this module closes the gap
//!
//! This module exposes a trait and one concrete implementation that
//! together let the runtime (which owns zone keys) install a verifier
//! on [`crate::MemoryObjectStore`] and [`crate::DurableObjectStore`].
//! When a verifier is installed, every put (runtime write path),
//! every replayed WAL record, and every snapshot entry routes through
//! it before reaching in-memory state. Missing keys fail closed:
//! [`ObjectStoreError::VerifierKeyMissing`] rather than silently
//! allowing the object through.
//!
//! No verifier installed → existing behaviour preserved (single-node
//! tests, callers that intentionally operate below the zone-keyed
//! layer). Stores intended to survive a restore from backup or an
//! imported snapshot SHOULD install a verifier.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use fcp_prelude::{ObjectIdKey, StoredObject, ZoneId};

use crate::error::ObjectStoreError;

/// Verifies that a [`StoredObject`]'s claimed `object_id` is consistent
/// with its `(header, body)` under the zone-specific `ObjectIdKey`.
///
/// Implementations must be `Send + Sync + Debug` so they can be held
/// in `Arc` across the store's thread-safe `put` / replay paths.
pub trait ObjectIdVerifier: Send + Sync + Debug {
    /// Verify the object. Implementations MUST fail closed on unknown
    /// zones (i.e., return [`ObjectStoreError::VerifierKeyMissing`])
    /// rather than skipping the check.
    ///
    /// # Errors
    /// Returns [`ObjectStoreError::ContentIdMismatch`] when the claimed
    /// id does not match the derived id. Returns
    /// [`ObjectStoreError::VerifierKeyMissing`] when the zone is unknown.
    /// Returns [`ObjectStoreError::Io`] if the canonical encoding
    /// itself fails (e.g., non-canonicalisable header).
    fn verify(&self, object: &StoredObject) -> Result<(), ObjectStoreError>;
}

/// A verifier backed by an explicit `HashMap<ZoneId, ObjectIdKey>`.
///
/// Callers that hold live `ZoneKeyMaterial` in the runtime layer
/// (typically `MeshNode` or the runtime bootstrap shim) construct this
/// with the set of zones they serve and pass it to the store.
#[derive(Debug, Clone, Default)]
pub struct KeyedObjectIdVerifier {
    keys: HashMap<ZoneId, ObjectIdKey>,
}

impl KeyedObjectIdVerifier {
    /// Construct a verifier from an initial zone → key mapping.
    #[must_use]
    pub const fn new(keys: HashMap<ZoneId, ObjectIdKey>) -> Self {
        Self { keys }
    }

    /// Install or replace the `ObjectIdKey` for a zone. Useful when
    /// a node dynamically learns additional zones after construction.
    pub fn insert(&mut self, zone: ZoneId, key: ObjectIdKey) {
        self.keys.insert(zone, key);
    }

    /// Wrap `self` in an `Arc<dyn ObjectIdVerifier>` for installation
    /// on a store.
    #[must_use]
    pub fn into_arc(self) -> Arc<dyn ObjectIdVerifier> {
        Arc::new(self)
    }
}

impl ObjectIdVerifier for KeyedObjectIdVerifier {
    fn verify(&self, object: &StoredObject) -> Result<(), ObjectStoreError> {
        let key = self.keys.get(&object.header.zone_id).ok_or_else(|| {
            ObjectStoreError::VerifierKeyMissing {
                zone: object.header.zone_id.clone(),
            }
        })?;
        let computed =
            StoredObject::derive_id(&object.header, &object.body, key).map_err(|err| {
                ObjectStoreError::Io(format!("content-id verifier encoding failed: {err}"))
            })?;
        if computed != object.object_id {
            return Err(ObjectStoreError::ContentIdMismatch {
                claimed: object.object_id,
                computed,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_cbor::SchemaId;
    use fcp_prelude::{ObjectHeader, ObjectId, Provenance, RetentionClass, StorageMeta};

    fn test_key() -> ObjectIdKey {
        ObjectIdKey::from_bytes([7u8; 32])
    }

    fn test_schema() -> SchemaId {
        SchemaId::new("fcp.test", "VerifierObject", semver::Version::new(1, 0, 0))
    }

    fn test_header(zone: &ZoneId) -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: test_schema(),
            zone_id: zone.clone(),
            created_at: 0,
            provenance: Provenance::new(zone.clone()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn genuine_object(zone: &ZoneId, body: &[u8], key: &ObjectIdKey) -> StoredObject {
        let header = test_header(zone);
        let id = StoredObject::derive_id(&header, body, key).expect("derive id");
        StoredObject {
            object_id: id,
            header,
            body: body.to_vec(),
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        }
    }

    #[test]
    fn accepts_genuine_object_with_correct_content_id() {
        let zone = ZoneId::work();
        let key = test_key();
        let obj = genuine_object(&zone, b"hello-world", &key);

        let mut verifier = KeyedObjectIdVerifier::default();
        verifier.insert(zone, key);

        verifier.verify(&obj).expect("genuine object must verify");
    }

    #[test]
    fn rejects_forged_object_id_even_with_correct_header_and_body() {
        // Attacker swaps object_id on an otherwise-legitimate object.
        let zone = ZoneId::work();
        let key = test_key();
        let mut obj = genuine_object(&zone, b"payload-v1", &key);
        let genuine_id = obj.object_id;
        obj.object_id = ObjectId::from_bytes([0xFFu8; 32]);

        let mut verifier = KeyedObjectIdVerifier::default();
        verifier.insert(zone, key);

        let err = verifier
            .verify(&obj)
            .expect_err("forged object_id must be rejected");
        match err {
            ObjectStoreError::ContentIdMismatch { claimed, computed } => {
                assert_eq!(claimed, ObjectId::from_bytes([0xFFu8; 32]));
                assert_eq!(computed, genuine_id);
            }
            other => panic!("expected ContentIdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_tampered_body_with_preserved_id() {
        // Attacker keeps `object_id` pointing at the legitimate id but
        // swaps `body` under it. Computed id over tampered bytes must
        // no longer match.
        let zone = ZoneId::work();
        let key = test_key();
        let mut obj = genuine_object(&zone, b"legit-payload", &key);
        let genuine_id = obj.object_id;
        obj.body = b"attacker-payload".to_vec();

        let mut verifier = KeyedObjectIdVerifier::default();
        verifier.insert(zone, key);

        let err = verifier
            .verify(&obj)
            .expect_err("tampered body must be rejected");
        assert!(
            matches!(err, ObjectStoreError::ContentIdMismatch { claimed, .. } if claimed == genuine_id),
            "expected ContentIdMismatch keyed on the legit id, got {err:?}"
        );
    }

    #[test]
    fn unknown_zone_fails_closed_with_verifier_key_missing() {
        // The verifier has no key for zone_id. MUST fail closed — not
        // pass the object through.
        let key = test_key();
        let unknown_zone = ZoneId::work();
        let obj = genuine_object(&unknown_zone, b"body", &key);

        let verifier = KeyedObjectIdVerifier::default(); // no keys

        let err = verifier
            .verify(&obj)
            .expect_err("unknown zone must fail closed");
        assert!(
            matches!(err, ObjectStoreError::VerifierKeyMissing { .. }),
            "expected VerifierKeyMissing, got {err:?}"
        );
    }
}
