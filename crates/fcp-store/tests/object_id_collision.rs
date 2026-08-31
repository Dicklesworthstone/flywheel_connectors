//! Pin `ObjectId` collision detection on `MemoryObjectStore`
//! (flywheel_connectors-mt6ac).
//!
//! `MemoryObjectStore::put` uses the claimed `object_id` as the key in
//! its in-memory map. The collision-detection contract is:
//!
//!   1. **Forged-collision rejection**: a second `put` whose
//!      `object_id` matches an existing entry MUST fail with
//!      [`ObjectStoreError::AlreadyExists(id)`], regardless of whether
//!      the `(header, body)` match the existing entry.
//!   2. **First-writer-wins dedup**: a second put with the SAME
//!      `(object_id, header, body)` is also rejected with
//!      `AlreadyExists` and MUST NOT mutate stored state — `get(id)`
//!      still returns the original.
//!   3. **Error payload identifies the conflict**: the `AlreadyExists`

#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::needless_update)]

//! Distinct `object_id`s for distinct content remain insertable in the
//! same store — the collision check is keyed on `object_id` alone.
//!
//! Background: `MemoryObjectStore::put` (`object_store.rs:474`) and the
//! `ObjectStoreError::AlreadyExists` Display format
//! (`"object already exists: {0}"`, error.rs:13) are NORMATIVE.

use fcp_async_core::runtime;
use fcp_cbor::SchemaId;
use fcp_prelude::{
    ObjectHeader, ObjectId, Provenance, RetentionClass, StorageMeta, StoredObject, ZoneId,
};
use fcp_store::{MemoryObjectStore, MemoryObjectStoreConfig, ObjectStore, ObjectStoreError};
use semver::Version;

fn test_zone() -> ZoneId {
    ZoneId::work()
}

fn make_object(id: ObjectId, body: &[u8]) -> StoredObject {
    StoredObject {
        object_id: id,
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.test", "CollisionTest", Version::new(1, 0, 0)),
            zone_id: test_zone(),
            created_at: 1_700_000_000,
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

#[runtime::test]
async fn forged_collision_with_different_body_is_rejected() {
    // Two objects share the same claimed object_id but have different
    // bodies — a "forged collision" that the in-memory store MUST
    // reject on second put.
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let id = ObjectId::from_bytes([0x42; 32]);

    let original = make_object(id, b"original body");
    let conflicting = make_object(id, b"attacker-controlled body");

    store
        .put(original.clone())
        .await
        .expect("first put must succeed");

    let result = store.put(conflicting).await;
    match result {
        Err(ObjectStoreError::AlreadyExists(returned_id)) => {
            assert_eq!(
                returned_id, id,
                "AlreadyExists payload MUST carry the conflicting object_id"
            );
        }
        other => panic!(
            "second put with same id, different body returned {other:?}; \
             expected AlreadyExists({id})"
        ),
    }

    // State is unchanged: the store still holds the ORIGINAL body.
    let stored = store
        .get(&id)
        .await
        .expect("original must still be present");
    assert_eq!(
        stored.body, original.body,
        "forged collision MUST NOT overwrite the original body"
    );
}

#[runtime::test]
async fn forged_collision_with_different_header_is_rejected() {
    // Same object_id, identical body, but the second put advertises a
    // different header (created_at). Still a collision — `put` does
    // NOT inspect the header to decide whether to overwrite.
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let id = ObjectId::from_bytes([0x43; 32]);

    let original = make_object(id, b"shared body");
    let mut conflicting = make_object(id, b"shared body");
    conflicting.header.created_at = 9_999_999_999;

    store.put(original.clone()).await.expect("first put");
    let result = store.put(conflicting).await;

    match result {
        Err(ObjectStoreError::AlreadyExists(returned_id)) => {
            assert_eq!(returned_id, id);
        }
        other => panic!(
            "second put with same id, different header returned {other:?}; \
             expected AlreadyExists"
        ),
    }

    let stored = store.get(&id).await.expect("original still present");
    assert_eq!(
        stored.header.created_at, original.header.created_at,
        "forged collision MUST NOT overwrite the header"
    );
}

#[runtime::test]
async fn identical_object_dedup_returns_already_exists() {
    // Putting the EXACT same object twice is the dedup case. The
    // contract is "first writer wins" — the second put returns
    // AlreadyExists and the state is unchanged. There is no silent
    // success branch.
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let id = ObjectId::from_bytes([0x44; 32]);

    let object = make_object(id, b"identical body");
    store
        .put(object.clone())
        .await
        .expect("first put must succeed");

    // Second identical put → AlreadyExists.
    let result = store.put(object.clone()).await;
    match result {
        Err(ObjectStoreError::AlreadyExists(returned_id)) => {
            assert_eq!(
                returned_id, id,
                "dedup AlreadyExists payload MUST carry the same object_id"
            );
        }
        other => panic!("identical re-put returned {other:?}; expected AlreadyExists ({id})"),
    }

    // State unchanged: get still works, body matches the original.
    let stored = store
        .get(&id)
        .await
        .expect("object still present after dedup");
    assert_eq!(stored.body, object.body, "dedup must not mutate body");
}

#[runtime::test]
async fn already_exists_display_message_identifies_object() {
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let id = ObjectId::from_bytes([0x45; 32]);

    store
        .put(make_object(id, b"first"))
        .await
        .expect("first put");

    let err = store
        .put(make_object(id, b"second"))
        .await
        .expect_err("second put MUST be a collision");

    let display = err.to_string();
    // Format pinned by error.rs:13 is `"object already exists: {0}"`.
    assert!(
        display.contains("object already exists"),
        "display message MUST mark the error as a collision: {display:?}"
    );
    let id_string = format!("{id}");
    assert!(
        display.contains(&id_string),
        "display message MUST include the conflicting object_id ({id_string}): {display:?}"
    );

    // Debug also clearly identifies the variant for log analysis.
    let debug = format!("{err:?}");
    assert!(
        debug.contains("AlreadyExists"),
        "debug formatting MUST mark the variant: {debug:?}"
    );
}

#[runtime::test]
async fn distinct_object_ids_in_same_zone_coexist() {
    // The collision check is keyed on object_id ONLY. Two objects with
    // distinct ids in the same zone — even with identical bodies —
    // both insert successfully.
    let store = MemoryObjectStore::new(MemoryObjectStoreConfig::default());
    let id_a = ObjectId::from_bytes([0xA0; 32]);
    let id_b = ObjectId::from_bytes([0xB0; 32]);

    store
        .put(make_object(id_a, b"shared body"))
        .await
        .expect("put A");
    store
        .put(make_object(id_b, b"shared body"))
        .await
        .expect("put B with distinct id must coexist with A");

    assert!(store.exists(&id_a).await, "A must be present");
    assert!(store.exists(&id_b).await, "B must be present");
}

#[runtime::test]
async fn collision_does_not_consume_quota_a_second_time() {
    // The defense is depth-in-depth: even with quota tightening,
    // once an id is taken, a forged-collision put is rejected before
    // it can grow `used_bytes`.
    let small_quota = MemoryObjectStoreConfig {
        max_bytes: 4096,
        ..MemoryObjectStoreConfig::default()
    };
    let store = MemoryObjectStore::new(small_quota);
    let id = ObjectId::from_bytes([0xCD; 32]);

    let original = make_object(id, b"a");
    store.put(original.clone()).await.expect("first put");

    let used_before_collision = store.storage_used().await;

    let _ = store.put(make_object(id, b"different body")).await;

    let used_after_collision = store.storage_used().await;
    assert_eq!(
        used_before_collision, used_after_collision,
        "rejected collision MUST NOT advance used_bytes"
    );
}
