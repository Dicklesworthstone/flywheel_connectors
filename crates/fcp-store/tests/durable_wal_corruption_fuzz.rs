//! Property-based fuzz harness for `DurableObjectStore` WAL replay
//! under arbitrary on-disk corruption.
//!
//! The dgbtx commit (6d8682334) added 11 adversarial regressions for
//! V2-envelope tampering with hand-built corruption patterns. This
//! harness complements them with a *value-space sweep*: write a
//! valid V1 WAL with N records, then mutate a small set of random
//! bytes at random offsets, then re-open and assert four
//! contracts the recovery loop must satisfy for *any* corruption
//! shape:
//!
//! 1. **Open never panics** — the recovery loop tolerates arbitrary
//!    byte sequences. A regression that introduced an `unwrap` over
//!    parsed-from-disk values would surface here as a panic.
//!

#![allow(unused_imports)]
#![allow(clippy::cast_possible_truncation)]

use fcp_prelude::{
    ObjectHeader, ObjectId, Provenance, RetentionClass, StorageMeta, StoredObject, ZoneId,
};
use fcp_store::{DurableObjectStore, DurableObjectStoreConfig, ObjectStore};
use proptest::prelude::*;
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::PathBuf;

const NUM_OBJECTS: usize = 6;

fn block_on<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime");
    runtime.block_on(f)
}

fn test_zone() -> ZoneId {
    ZoneId::work()
}

const fn test_object_id(seed: u8) -> ObjectId {
    ObjectId::from_bytes([seed; 32])
}

fn test_object(seed: u8) -> StoredObject {
    let zone = test_zone();
    StoredObject {
        object_id: test_object_id(seed),
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: fcp_cbor::SchemaId::new(
                "fcp.test",
                "WalFuzzObject",
                semver::Version::new(1, 0, 0),
            ),
            zone_id: zone.clone(),
            created_at: 1_700_000_000,
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

/// Build a clean WAL with `NUM_OBJECTS` valid records inside `dir`.
/// Returns the wal-file path and the original ordered (`object_id`,
/// seq) pairs the test should compare against post-corruption
/// recovery.
fn seed_clean_wal(root_dir: &PathBuf) -> (PathBuf, Vec<ObjectId>) {
    block_on(async {
        let config = DurableObjectStoreConfig::new(root_dir);
        let store = DurableObjectStore::open(config).expect("open clean store");
        let mut original = Vec::with_capacity(NUM_OBJECTS);
        for i in 0..NUM_OBJECTS {
            let obj = test_object(i as u8 + 1);
            original.push(obj.object_id);
            store.put(obj).await.expect("put must succeed");
        }
        (root_dir.join("objects.wal.jsonl"), original)
    })
}

/// Apply `mutations` byte-flips to the WAL file at random offsets.
fn apply_byte_flips(wal_path: &PathBuf, mutations: &[(u32, u8)]) {
    let mut bytes = std::fs::read(wal_path).expect("read wal");
    if bytes.is_empty() {
        return;
    }
    for (offset, value) in mutations {
        let idx = (*offset as usize) % bytes.len();
        bytes[idx] = *value;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(wal_path)
        .expect("open wal for write");
    file.write_all(&bytes).expect("write tampered wal");
    file.sync_all().expect("sync tampered wal");
}

/// Append `extra` random bytes to the end of the WAL — exercises the
/// torn-tail truncation path with arbitrary trailing content.
fn append_random_tail(wal_path: &PathBuf, tail: &[u8]) {
    if tail.is_empty() {
        return;
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(wal_path)
        .expect("open wal for append");
    file.write_all(tail).expect("append tail");
    file.sync_all().expect("sync tail");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Property 1+2+3+4 in one sweep: arbitrary WAL byte mutations
    /// MUST satisfy: no panic, typed result, monotone recovery,
    /// fixed-point on re-open.
    #[test]
    fn fuzz_wal_replay_under_arbitrary_byte_mutations(
        // Up to 16 byte flips at random offsets.
        mutations in proptest::collection::vec((any::<u32>(), any::<u8>()), 0..=16),
        // Random trailing bytes (0-256 bytes) for the torn-tail path.
        tail in proptest::collection::vec(any::<u8>(), 0..=256),
    ) {
        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let root_dir = temp_dir.path().to_path_buf();

        // Seed a clean WAL with NUM_OBJECTS valid records.
        let (wal_path, original_ids) = seed_clean_wal(&root_dir);
        let original_set: HashSet<_> = original_ids.iter().copied().collect();

        // Apply byte flips + append random tail.
        apply_byte_flips(&wal_path, &mutations);
        append_random_tail(&wal_path, &tail);

        // Property 1+2: open returns a typed result (not a panic).
        let result = std::panic::catch_unwind(|| {
            block_on(async {
                let config = DurableObjectStoreConfig::new(&root_dir);
                DurableObjectStore::open(config)
            })
        });
        let Ok(recovery) = result else {
            prop_assert!(
                false,
                "br-fuzz: WAL recovery panicked under random corruption — \
                 unwrap on parsed-from-disk values escaped",
            );
            unreachable!("prop_assert! returns above");
        };

        // At minimum, recovery must yield a valid valid segment stream.
        let store = match recovery {
            Ok(store) => store,
            Err(_typed_err) => {
                // Typed error path — recovery refused to admit
                // corruption. Nothing more to assert.
                return Ok(());
            }
        };

        // Property 3: monotone recovery — recovered set is a prefix
        // of the original record set under seq order.
        let recovered_objects = block_on(async {
            let mut found = Vec::new();
            for id in &original_ids {
                if store.exists(id).await {
                    found.push(*id);
                }
            }
            found
        });
        let recovered_set: HashSet<_> = recovered_objects.iter().copied().collect();

        // The recovered set MUST be a subset of the original set —
        // no fabricated object ids ever surface from corruption.
        for id in &recovered_set {
            prop_assert!(
                original_set.contains(id),
                "br-fuzz: recovered an object id not present in the original WAL — \
                 corruption invented a new id",
            );
        }

        // Recovered prefix is contiguous from the start under the
        // original insertion order. Find the longest leading run of
        // original_ids that survived; everything AFTER that run must
        // be absent (otherwise corruption resurrected a later
        // record).
        let mut longest_leading_prefix = 0;
        for id in &original_ids {
            if recovered_set.contains(id) {
                longest_leading_prefix += 1;
            } else {
                break;
            }
        }
        for id in &original_ids[longest_leading_prefix..] {
            prop_assert!(
                !recovered_set.contains(id),
                "br-fuzz: corruption resurrected a non-prefix record — \
                 recovered ids: {:?} prefix_len: {}",
                recovered_objects,
                longest_leading_prefix,
            );
        }

        // Property 4: re-open is fixed-point — closing and re-opening
        // the recovered store loads the SAME set.
        drop(store);
        let reopened_set: HashSet<_> = block_on(async {
            let config = DurableObjectStoreConfig::new(&root_dir);
            let store = DurableObjectStore::open(config)
                .expect("recovered store must reopen cleanly (fixed-point)");
            let mut found = HashSet::new();
            for id in &original_ids {
                if store.exists(id).await {
                    found.insert(*id);
                }
            }
            found
        });

        prop_assert_eq!(
            reopened_set,
            recovered_set,
            "br-fuzz: WAL truncation is not fixed-point — second open changed the \
             recovered object set",
        );
    }
}

/// Targeted regression: a brand-new fresh WAL (no objects yet) with
/// random trailing bytes opens cleanly with empty state — pre-fix
/// the recovery loop on a non-existent file followed by random
/// content was an edge case.
#[test]
fn empty_wal_with_random_trailing_garbage_reopens_empty() {
    let temp_dir = tempfile::TempDir::new().expect("temp dir");
    let root_dir = temp_dir.path().to_path_buf();
    // Open + drop to materialize the directory layout.
    let config = DurableObjectStoreConfig::new(&root_dir);
    let store = DurableObjectStore::open(config).expect("first open");
    drop(store);

    // Inject random trailing garbage.
    let wal_path = root_dir.join("objects.wal.jsonl");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&wal_path)
        .and_then(|mut f| f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF, b'\n', 0x00, 0xFF, b'{', b'!']));

    // Re-open. Either a typed error or success-with-empty-state is
    // acceptable; what is NOT acceptable is a panic.
    block_on(async {
        let config = DurableObjectStoreConfig::new(&root_dir);
        match DurableObjectStore::open(config) {
            Ok(store) => {
                // Recovery succeeded after truncation — store must
                // be empty since no valid records were ever written.
                assert_eq!(store.storage_used().await, 0);
            }
            Err(_typed) => {
                // Typed error is also acceptable — the recovery loop
                // refused to admit garbage.
            }
        }
    });
}
