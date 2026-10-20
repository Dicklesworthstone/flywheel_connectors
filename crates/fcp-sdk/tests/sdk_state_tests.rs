//! SDK State Model Tests
//!
//! Tests for connector state model types including:
//! - State model discriminants (Stateless, `SingletonWriter`, Crdt)
//! - CRDT type handling
//! - State model serialization
//! - Archetype associations

use std::sync::Arc;

#[cfg(feature = "cursor-store-object-store")]
use chrono::{Duration, Utc};
use fcp_cbor::SchemaId;
#[cfg(feature = "cursor-store-object-store")]
use fcp_crypto::{CapabilityTokenBuilder, Ed25519SigningKey};
use fcp_prelude::{ObjectHeader, Signature};

#[cfg(feature = "cursor-store-object-store")]
use fcp_prelude::{
    CONNECTOR_STATE_APPEND_OPERATION_ID, CONNECTOR_STATE_WRITE_CAPABILITY_ID,
    CapabilityConstraints, CapabilityToken, CapabilityVerifier, ConnectorStateObject,
    ConnectorStateWriteAuthorization, ObjectIdKey, RetentionClass, StorageMeta, StoredObject,
    connector_state_resource_uri,
};
use fcp_sdk::prelude::*;
use semver::Version;

#[cfg(feature = "cursor-store-object-store")]
use fcp_sdk::runtime::ObjectStoreCursorBackend;
#[cfg(feature = "cursor-store-object-store")]
use fcp_store::{MemoryObjectStore, MemoryObjectStoreConfig, ObjectStore};

// ─────────────────────────────────────────────────────────────────────────────
// ConnectorStateModel Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_state_model_stateless() {
    let model = ConnectorStateModel::Stateless;

    assert!(matches!(model, ConnectorStateModel::Stateless));
}

#[test]
fn test_state_model_singleton_writer() {
    let model = ConnectorStateModel::SingletonWriter;

    assert!(matches!(model, ConnectorStateModel::SingletonWriter));
}

#[test]
fn test_state_model_crdt() {
    let model = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };

    assert!(matches!(model, ConnectorStateModel::Crdt { .. }));
}

// ─────────────────────────────────────────────────────────────────────────────
// State Model Display Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_state_model_debug_stateless() {
    let model = ConnectorStateModel::Stateless;
    let debug = format!("{model:?}");
    assert!(debug.contains("Stateless"));
}

#[test]
fn test_state_model_debug_singleton_writer() {
    let model = ConnectorStateModel::SingletonWriter;
    let debug = format!("{model:?}");
    assert!(debug.contains("SingletonWriter"));
}

#[test]
fn test_state_model_debug_crdt() {
    let model = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };
    let debug = format!("{model:?}");
    assert!(debug.contains("Crdt"));
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Type Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_crdt_type_as_str() {
    assert_eq!(ConnectorCrdtType::LwwMap.as_str(), "lww_map");
    assert_eq!(ConnectorCrdtType::OrSet.as_str(), "or_set");
    assert_eq!(ConnectorCrdtType::GCounter.as_str(), "g_counter");
    assert_eq!(ConnectorCrdtType::PnCounter.as_str(), "pn_counter");
}

#[test]
fn test_crdt_type_variants() {
    let lww = ConnectorCrdtType::LwwMap;
    let or_set = ConnectorCrdtType::OrSet;
    let g_counter = ConnectorCrdtType::GCounter;
    let pn_counter = ConnectorCrdtType::PnCounter;

    assert!(matches!(lww, ConnectorCrdtType::LwwMap));
    assert!(matches!(or_set, ConnectorCrdtType::OrSet));
    assert!(matches!(g_counter, ConnectorCrdtType::GCounter));
    assert!(matches!(pn_counter, ConnectorCrdtType::PnCounter));
}

// ─────────────────────────────────────────────────────────────────────────────
// State Model Serialization Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_state_model_serialize_stateless() {
    let model = ConnectorStateModel::Stateless;
    let json = serde_json::to_value(model).expect("serialize should work");

    assert_eq!(json["type"], "stateless");
}

#[test]
fn test_state_model_serialize_singleton_writer() {
    let model = ConnectorStateModel::SingletonWriter;
    let json = serde_json::to_value(model).expect("serialize should work");

    assert_eq!(json["type"], "singleton_writer");
}

#[test]
fn test_state_model_serialize_crdt() {
    let model = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };
    let json = serde_json::to_value(model).expect("serialize should work");

    assert_eq!(json["type"], "crdt");
    assert_eq!(json["crdt_type"], "lww_map");
}

// ─────────────────────────────────────────────────────────────────────────────
// CursorStore Tests
// ─────────────────────────────────────────────────────────────────────────────

fn test_header(created_at: u64) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: fcp_core::ObjectEncryptionKind::default(),
        schema: SchemaId::new("fcp.test", "ConnectorStateObject", Version::new(1, 0, 0)),
        zone_id: ZoneId::work(),
        created_at,
        provenance: Provenance {
            origin_zone: ZoneId::work(),
            chain: Vec::new(),
            taint: TaintLevel::Untainted,
            elevated: false,
            elevation_token: None,
        },
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

#[cfg(feature = "cursor-store-object-store")]
fn object_store_header(created_at: u64, zone_id: ZoneId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.connector_state", "state_object", Version::new(1, 0, 0)),
        zone_id: zone_id.clone(),
        created_at,
        provenance: Provenance {
            origin_zone: zone_id,
            chain: Vec::new(),
            taint: TaintLevel::Untainted,
            elevated: false,
            elevation_token: None,
        },
        refs: Vec::new(),
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

#[cfg(feature = "cursor-store-object-store")]
fn capability_constraints_cbor(resource_allow: Vec<String>) -> Vec<u8> {
    let constraints = CapabilityConstraints {
        resource_allow,
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should encode");
    cbor
}

#[cfg(feature = "cursor-store-object-store")]
fn connector_state_write_authorization_with_key(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
) -> (ConnectorStateWriteAuthorization, Ed25519SigningKey) {
    let instance_id = InstanceId::new();
    let signing_key = Ed25519SigningKey::generate();
    let now = Utc::now();
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
                connector_state_resource_uri(connector_id),
            ]))
            .expect("constraints should be accepted")
            .sign(&signing_key)
            .expect("token should sign"),
    );
    let verifier = CapabilityVerifier::new(
        signing_key.verifying_key().to_bytes(),
        zone_id.clone(),
        instance_id,
    );
    let authorization = ConnectorStateWriteAuthorization::verify_append_token(
        &verifier,
        token,
        connector_id,
        zone_id,
    )
    .expect("connector-state append token should authorize");
    (authorization, signing_key)
}

#[cfg(feature = "cursor-store-object-store")]
fn signature_for_object_store_cursor_commit(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    mut header: ObjectHeader,
    lease: CursorLease,
    cursor: &CursorState,
    signing_key: &Ed25519SigningKey,
) -> Signature {
    if !header.refs.contains(&lease.lease_object_id) {
        header.refs.push(lease.lease_object_id);
    }
    let state_cbor = cursor.to_cbor().expect("cursor state should encode");
    let mut state = ConnectorStateObject {
        updated_at: header.created_at,
        header,
        connector_id: connector_id.clone(),
        instance_id: None,
        zone_id: zone_id.clone(),
        prev: None,
        seq: 0,
        state_cbor,
        lease_seq: lease.lease_seq,
        lease_object_id: lease.lease_object_id,
        writer_public_key: [0u8; 32],
        signature: Signature::zero(),
    };
    state
        .sign_with(signing_key)
        .expect("connector state should sign");
    state.signature
}

#[test]
fn cursor_store_commit_and_load() {
    let backend = InMemoryCursorStoreBackend::new();
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    let cursor = CursorState {
        offset: Some(10),
        last_seen_id: Some("id-10".to_string()),
        watermark: Some(100),
    };

    let lease = CursorLease {
        lease_seq: 1,
        lease_object_id: ObjectId::from_bytes([0x11; 32]),
    };

    let object_id = store
        .commit_cursor(
            cursor.clone(),
            test_header(1_700_000_000),
            lease,
            Signature::zero(),
        )
        .expect("commit should succeed");

    assert_eq!(store.head(), Some(object_id));

    let loaded = store
        .load_cursor()
        .expect("load should succeed")
        .expect("cursor should exist");
    assert_eq!(loaded, cursor);
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_store_object_store_roundtrip() {
    let object_store: Arc<dyn ObjectStore> =
        Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let object_id_key = ObjectIdKey::from_bytes([0xA5; 32]);
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();

    let backend = ObjectStoreCursorBackend::new(
        object_store,
        object_id_key,
        connector_id.clone(),
        zone_id.clone(),
    );
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    let cursor = CursorState {
        offset: Some(42),
        last_seen_id: Some("id-42".to_string()),
        watermark: Some(420),
    };

    let lease = CursorLease {
        lease_seq: 1,
        lease_object_id: ObjectId::from_bytes([0x11; 32]),
    };

    let object_id = store
        .commit_cursor(
            cursor.clone(),
            object_store_header(1_700_100_000, ZoneId::work()),
            lease,
            Signature::zero(),
        )
        .expect("commit should succeed");

    assert_eq!(store.head(), Some(object_id));

    let loaded = store
        .load_cursor()
        .expect("load should succeed")
        .expect("cursor should exist");
    assert_eq!(loaded, cursor);
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_store_object_store_authorized_commit_advances_canonical_root() {
    let object_store: Arc<dyn ObjectStore> =
        Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let object_id_key = ObjectIdKey::from_bytes([0xA7; 32]);
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let (authorization, signing_key) =
        connector_state_write_authorization_with_key(&connector_id, &zone_id);

    let backend = ObjectStoreCursorBackend::new(
        Arc::clone(&object_store),
        object_id_key,
        connector_id.clone(),
        zone_id.clone(),
    )
    .with_write_authorization(authorization);
    let mut store = CursorStore::new(backend, connector_id.clone(), zone_id.clone())
        .with_writer_public_key(signing_key.verifying_key().to_bytes());

    let cursor = CursorState {
        offset: Some(64),
        last_seen_id: Some("id-64".to_string()),
        watermark: Some(640),
    };
    let lease = CursorLease {
        lease_seq: 1,
        lease_object_id: ObjectId::from_bytes([0x12; 32]),
    };
    let header = object_store_header(1_700_150_000, zone_id.clone());
    let signature = signature_for_object_store_cursor_commit(
        &connector_id,
        &zone_id,
        header.clone(),
        lease,
        &cursor,
        &signing_key,
    );

    let object_id = store
        .commit_cursor(cursor.clone(), header, lease, signature)
        .expect("authorized commit should succeed");

    let canonical_store = fcp_store::FcpStoreConnectorStateStore::new(
        object_store,
        object_id_key,
        connector_id,
        zone_id,
    );
    let root = fcp_async_core::runtime::block_on_sync(canonical_store.read_root());
    let (_root_id, root) = root
        .expect("runtime should be available")
        .expect("canonical read should succeed")
        .expect("canonical root should exist");
    assert_eq!(root.head, Some(object_id));
    assert_eq!(root.state_schema_version, 1);

    let loaded = store
        .load_cursor()
        .expect("load should succeed")
        .expect("cursor should exist");
    assert_eq!(loaded, cursor);
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_store_forwards_explicit_snapshot_signer_after_canonical_commit() {
    for configure_snapshot_signer in [false, true] {
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let object_id_key = ObjectIdKey::from_bytes([0xA8; 32]);
        let connector_id = ConnectorId::from_static("test:operational:1.0");
        let zone_id = ZoneId::work();
        let (authorization, signing_key) =
            connector_state_write_authorization_with_key(&connector_id, &zone_id);
        let signing_key = Arc::new(signing_key);
        let mut backend = ObjectStoreCursorBackend::new(
            Arc::clone(&object_store),
            object_id_key,
            connector_id.clone(),
            zone_id.clone(),
        )
        .with_write_authorization(authorization);
        if configure_snapshot_signer {
            backend = backend.with_snapshot_signing_key(Arc::clone(&signing_key));
        }
        let mut cursor_store = CursorStore::new(backend, connector_id.clone(), zone_id.clone())
            .with_writer_public_key(signing_key.verifying_key().to_bytes());
        let lease = CursorLease {
            lease_seq: 1,
            lease_object_id: ObjectId::from_bytes([0x13; 32]),
        };
        let initial_cursor = CursorState {
            offset: Some(1),
            last_seen_id: Some("id-1".to_string()),
            watermark: Some(100),
        };
        let initial_header = object_store_header(1_700_150_000, zone_id.clone());
        let signature = signature_for_object_store_cursor_commit(
            &connector_id,
            &zone_id,
            initial_header.clone(),
            lease,
            &initial_cursor,
            &signing_key,
        );
        let initial_head = cursor_store
            .commit_cursor(initial_cursor, initial_header, lease, signature)
            .expect("initial authorized cursor should commit");

        // Seed a valid snapshot, then exercise the SDK's normal elapsed-time
        // policy with one later commit instead of generating 1,000 writes.
        let canonical_store = fcp_store::FcpStoreConnectorStateStore::new(
            object_store,
            object_id_key,
            connector_id.clone(),
            zone_id.clone(),
        )
        .with_trusted_writer_keys([signing_key.verifying_key().to_bytes()])
        .with_snapshot_signing_key(Arc::clone(&signing_key));
        fcp_async_core::runtime::block_on_sync(canonical_store.snapshot_head())
            .expect("runtime")
            .expect("initial snapshot should sign")
            .expect("initial head exists");

        let later_cursor = CursorState {
            offset: Some(2),
            last_seen_id: Some("id-2".to_string()),
            watermark: Some(200),
        };
        let mut later_header = object_store_header(1_700_150_000 + 86_400, zone_id.clone());
        later_header.refs.push(lease.lease_object_id);
        let mut later_state = ConnectorStateObject {
            header: later_header.clone(),
            connector_id,
            instance_id: None,
            zone_id,
            prev: Some(initial_head),
            seq: 1,
            state_cbor: later_cursor.to_cbor().expect("later cursor should encode"),
            updated_at: later_header.created_at,
            lease_seq: lease.lease_seq,
            lease_object_id: lease.lease_object_id,
            writer_public_key: signing_key.verifying_key().to_bytes(),
            signature: Signature::zero(),
        };
        later_state
            .sign_with(&signing_key)
            .expect("later state should sign");
        let later_head = cursor_store
            .commit_cursor(
                later_cursor.clone(),
                later_header,
                lease,
                later_state.signature,
            )
            .expect("later cursor must commit with or without a snapshot key");
        assert_eq!(cursor_store.head(), Some(later_head));
        assert_eq!(cursor_store.load_cursor().unwrap(), Some(later_cursor));

        let (_snapshot_id, latest) =
            fcp_async_core::runtime::block_on_sync(canonical_store.latest_snapshot())
                .expect("runtime")
                .expect("snapshot read should authenticate")
                .expect("snapshot exists");
        latest
            .verify_signature_with(&signing_key.verifying_key())
            .expect("snapshot must carry its own signature");
        assert_eq!(
            latest.covers_seq,
            u64::from(configure_snapshot_signer),
            "the SDK must forward only an explicitly configured snapshot key"
        );
        assert_eq!(
            latest.covers_head,
            if configure_snapshot_signer {
                later_head
            } else {
                initial_head
            }
        );
    }
}

#[cfg(feature = "cursor-store-object-store")]
fn commit_snapshot_recovery_cursor(
    store: &mut CursorStore<ObjectStoreCursorBackend>,
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
    signing_key: &Ed25519SigningKey,
    seq: u64,
    cursor: &CursorState,
) -> ObjectId {
    let lease = CursorLease {
        lease_seq: seq + 10,
        lease_object_id: ObjectId::from_bytes([u8::try_from(seq + 0x30).unwrap(); 32]),
    };
    let mut header = object_store_header(1_700_200_000 + seq, zone_id.clone());
    header.refs.push(lease.lease_object_id);
    let mut state = ConnectorStateObject {
        header: header.clone(),
        connector_id: connector_id.clone(),
        instance_id: None,
        zone_id: zone_id.clone(),
        prev: store.head(),
        seq,
        state_cbor: cursor.to_cbor().unwrap(),
        updated_at: header.created_at,
        lease_seq: lease.lease_seq,
        lease_object_id: lease.lease_object_id,
        writer_public_key: signing_key.verifying_key().to_bytes(),
        signature: Signature::zero(),
    };
    state.sign_with(signing_key).unwrap();
    store
        .commit_cursor(cursor.clone(), header, lease, state.signature)
        .unwrap()
}

#[cfg(feature = "cursor-store-object-store")]
struct CursorSnapshotReplayFixture {
    object_store: Arc<dyn ObjectStore>,
    backend: ObjectStoreCursorBackend,
    canonical: fcp_store::FcpStoreConnectorStateStore,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    signing_key: Arc<Ed25519SigningKey>,
    heads: Vec<ObjectId>,
    roots: Vec<ObjectId>,
    cursors: Vec<CursorState>,
    snapshot_id: ObjectId,
}

#[cfg(feature = "cursor-store-object-store")]
impl CursorSnapshotReplayFixture {
    fn new() -> Self {
        let object_store: Arc<dyn ObjectStore> =
            Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let object_id_key = ObjectIdKey::from_bytes([0xB7; 32]);
        let connector_id = ConnectorId::from_static("test:recovery:1.0");
        let zone_id = ZoneId::work();
        let (authorization, signing_key) =
            connector_state_write_authorization_with_key(&connector_id, &zone_id);
        let signing_key = Arc::new(signing_key);
        let backend = ObjectStoreCursorBackend::new(
            Arc::clone(&object_store),
            object_id_key,
            connector_id.clone(),
            zone_id.clone(),
        )
        .with_write_authorization(authorization);
        let canonical = fcp_store::FcpStoreConnectorStateStore::new(
            Arc::clone(&object_store),
            object_id_key,
            connector_id.clone(),
            zone_id.clone(),
        )
        .with_trusted_writer_keys([signing_key.verifying_key().to_bytes()])
        .with_snapshot_signing_key(Arc::clone(&signing_key))
        .with_snapshot_every_entries(0)
        .with_snapshot_every_secs(0);
        let mut writer = CursorStore::new(backend.clone(), connector_id.clone(), zone_id.clone())
            .with_writer_public_key(signing_key.verifying_key().to_bytes());
        let mut heads = Vec::new();
        let mut roots = Vec::new();
        let mut cursors = Vec::new();
        let mut snapshot_id = None;
        for seq in 0_u64..4 {
            let cursor = CursorState {
                offset: Some(i64::try_from(seq + 1).unwrap() * 10),
                last_seen_id: Some(format!("event-{}", seq + 1)),
                watermark: Some((seq + 1) * 100),
            };
            heads.push(commit_snapshot_recovery_cursor(
                &mut writer,
                &connector_id,
                &zone_id,
                &signing_key,
                seq,
                &cursor,
            ));
            roots.push(
                fcp_async_core::runtime::block_on_sync(canonical.read_root())
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .0,
            );
            cursors.push(cursor);
            if seq == 1 {
                snapshot_id = fcp_async_core::runtime::block_on_sync(canonical.snapshot_head())
                    .unwrap()
                    .unwrap();
            }
        }
        Self {
            object_store,
            backend,
            canonical,
            connector_id,
            zone_id,
            signing_key,
            heads,
            roots,
            cursors,
            snapshot_id: snapshot_id.unwrap(),
        }
    }

    fn reader(&self) -> CursorStore<ObjectStoreCursorBackend> {
        CursorStore::new(
            self.backend.clone(),
            self.connector_id.clone(),
            self.zone_id.clone(),
        )
        .with_writer_public_key(self.signing_key.verifying_key().to_bytes())
    }
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_snapshot_recovery_restores_progress_after_collected_prefix() {
    let fixture = CursorSnapshotReplayFixture::new();
    assert_eq!(
        fcp_async_core::runtime::block_on_sync(fixture.canonical.compact(2))
            .unwrap()
            .unwrap(),
        1,
    );
    let collected = fcp_async_core::runtime::block_on_sync(
        fcp_store::GarbageCollector::new(fcp_store::GcConfig::default()).collect(
            &fixture.zone_id,
            &fcp_store::GcRoots::new(),
            fixture.object_store.as_ref(),
            1_800_000_000,
        ),
    )
    .unwrap()
    .unwrap();
    assert_eq!(collected.evicted, 1);
    assert!(
        !fcp_async_core::runtime::block_on_sync(fixture.object_store.exists(&fixture.heads[0]))
            .unwrap()
    );

    let mut reader = fixture.reader();
    assert!(reader.load_cursor().is_err());
    assert_eq!(reader.head(), None);
    let recovered = reader
        .recover_cursor_from_snapshot(fixture.roots[3], fixture.snapshot_id, 2)
        .unwrap();
    assert_eq!(recovered, fixture.cursors[3]);
    assert_eq!(reader.head(), Some(fixture.heads[3]));
    let replay = fixture
        .backend
        .replay_from_snapshot(fixture.roots[3], fixture.snapshot_id, 2)
        .unwrap();
    assert_eq!(replay.covered_head().0, fixture.heads[1]);
    assert_eq!(
        replay
            .tail()
            .iter()
            .map(|(_, state)| state.seq)
            .collect::<Vec<_>>(),
        vec![2, 3],
    );

    // Explicit recovery does not make this old, selected root authoritative
    // for normal latest-root discovery.
    assert!(fixture.reader().load_cursor().is_err());
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_snapshot_recovery_preserves_loaded_state_on_budget_or_rollback_failure() {
    let fixture = CursorSnapshotReplayFixture::new();
    let mut reader = fixture.reader();
    reader
        .recover_cursor_from_snapshot(fixture.roots[2], fixture.snapshot_id, 1)
        .unwrap();
    assert_eq!(reader.head(), Some(fixture.heads[2]));

    assert!(
        reader
            .recover_cursor_from_snapshot(fixture.roots[3], fixture.snapshot_id, 1)
            .is_err()
    );
    assert_eq!(reader.head(), Some(fixture.heads[2]));
    assert_eq!(
        reader
            .recover_cursor_from_snapshot(fixture.roots[2], fixture.snapshot_id, 1)
            .unwrap(),
        fixture.cursors[2],
    );

    reader
        .recover_cursor_from_snapshot(fixture.roots[3], fixture.snapshot_id, 2)
        .unwrap();
    assert!(
        reader
            .recover_cursor_from_snapshot(fixture.roots[1], fixture.snapshot_id, 0)
            .is_err()
    );
    assert_eq!(reader.head(), Some(fixture.heads[3]));
    assert_eq!(
        reader
            .recover_cursor_from_snapshot(fixture.roots[3], fixture.snapshot_id, 2)
            .unwrap(),
        fixture.cursors[3],
    );
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_snapshot_recovery_refuses_progress_erasure_without_changing_loaded_fields() {
    for field in ["offset", "watermark"] {
        let fixture = CursorSnapshotReplayFixture::new();
        let mut reader = fixture.reader();
        reader
            .recover_cursor_from_snapshot(fixture.roots[3], fixture.snapshot_id, 2)
            .unwrap();
        let mut writer = fixture.reader();
        writer.load_cursor().unwrap().unwrap();
        let mut erased = fixture.cursors[3].clone();
        match field {
            "offset" => erased.offset = None,
            "watermark" => erased.watermark = None,
            _ => unreachable!(),
        }
        commit_snapshot_recovery_cursor(
            &mut writer,
            &fixture.connector_id,
            &fixture.zone_id,
            &fixture.signing_key,
            4,
            &erased,
        );
        let root = fcp_async_core::runtime::block_on_sync(fixture.canonical.read_root())
            .unwrap()
            .unwrap()
            .unwrap()
            .0;
        let error = reader
            .recover_cursor_from_snapshot(root, fixture.snapshot_id, 3)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("clear the loaded cursor {field}")),
            "unexpected recovery failure: {error}",
        );
        assert_eq!(reader.head(), Some(fixture.heads[3]));
        // Reapplying the original root also checks the private sequence,
        // lease and cursor fields: none may have advanced on the failed read.
        assert_eq!(
            reader
                .recover_cursor_from_snapshot(fixture.roots[3], fixture.snapshot_id, 2)
                .unwrap(),
            fixture.cursors[3],
        );
    }
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_snapshot_recovery_rejects_a_signed_fork_of_loaded_history() {
    let fixture = CursorSnapshotReplayFixture::new();
    let mut reader = fixture.reader();
    reader
        .recover_cursor_from_snapshot(fixture.roots[2], fixture.snapshot_id, 1)
        .unwrap();

    // A trusted writer can sign two histories. Signature validity alone must
    // not replace this reader's already loaded state at sequence two.
    let object_id_key = ObjectIdKey::from_bytes([0xB7; 32]);
    let mut fork_head = fixture.heads[1];
    for seq in 2_u64..=3 {
        let lease_id = ObjectId::from_bytes([u8::try_from(seq + 0x60).unwrap(); 32]);
        let mut header = object_store_header(1_700_200_100 + seq, fixture.zone_id.clone());
        header.refs.push(lease_id);
        let mut state = ConnectorStateObject {
            updated_at: header.created_at,
            header,
            connector_id: fixture.connector_id.clone(),
            instance_id: None,
            zone_id: fixture.zone_id.clone(),
            prev: Some(fork_head),
            seq,
            state_cbor: CursorState {
                offset: Some(i64::try_from(seq).unwrap() * 100),
                last_seen_id: Some(format!("fork-{seq}")),
                watermark: Some(seq * 1_000),
            }
            .to_cbor()
            .unwrap(),
            lease_seq: seq + 10,
            lease_object_id: lease_id,
            writer_public_key: fixture.signing_key.verifying_key().to_bytes(),
            signature: Signature::zero(),
        };
        state.sign_with(&fixture.signing_key).unwrap();
        let body = fcp_cbor::CanonicalSerializer::serialize(&state, &state.header.schema).unwrap();
        fork_head = StoredObject::derive_id(&state.header, &body, &object_id_key).unwrap();
        fcp_async_core::runtime::block_on_sync(fixture.object_store.put(StoredObject {
            object_id: fork_head,
            header: state.header,
            body,
            storage: StorageMeta {
                retention: RetentionClass::Pinned,
            },
        }))
        .unwrap()
        .unwrap();
    }
    let mut root = fcp_async_core::runtime::block_on_sync(fixture.canonical.read_root())
        .unwrap()
        .unwrap()
        .unwrap()
        .1;
    root.head = Some(fork_head);
    root.header.refs = vec![fork_head];
    let body = fcp_cbor::CanonicalSerializer::serialize(&root, &root.header.schema).unwrap();
    let fork_root = StoredObject::derive_id(&root.header, &body, &object_id_key).unwrap();
    fcp_async_core::runtime::block_on_sync(fixture.object_store.put(StoredObject {
        object_id: fork_root,
        header: root.header,
        body,
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }))
    .unwrap()
    .unwrap();

    // Ordinary canonical restore cannot choose either committed branch, even
    // for a new reader that has never cached a cursor. An already loaded reader
    // must preserve its previous fields when that restore is refused.
    let mut fresh_reader = fixture.reader();
    let fresh_error = fresh_reader.load_cursor().unwrap_err();
    assert!(fresh_error.to_string().contains("fork detected"));
    assert_eq!(fresh_reader.head(), None);
    let loaded_error = reader.load_cursor().unwrap_err();
    assert!(loaded_error.to_string().contains("fork detected"));
    assert_eq!(reader.head(), Some(fixture.heads[2]));

    fixture
        .backend
        .replay_from_snapshot(fork_root, fixture.snapshot_id, 2)
        .expect("explicit recovery still authenticates the selected alternate history");
    let error = reader
        .recover_cursor_from_snapshot(fork_root, fixture.snapshot_id, 2)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("conflicts with the loaded cursor history")
    );
    assert_eq!(reader.head(), Some(fixture.heads[2]));
    assert_eq!(
        reader
            .recover_cursor_from_snapshot(fixture.roots[2], fixture.snapshot_id, 1)
            .unwrap(),
        fixture.cursors[2],
    );
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn canonical_cursor_restore_refuses_a_signed_sequence_gap_without_replacing_loaded_state() {
    let fixture = CursorSnapshotReplayFixture::new();
    let mut reader = fixture.reader();
    assert_eq!(
        reader.load_cursor().unwrap(),
        Some(fixture.cursors[3].clone())
    );
    let retained_head = reader.head();

    let stored_head =
        fcp_async_core::runtime::block_on_sync(fixture.object_store.get(&fixture.heads[3]))
            .unwrap()
            .unwrap();
    let mut state: ConnectorStateObject =
        fcp_cbor::CanonicalSerializer::deserialize(&stored_head.body, &stored_head.header.schema)
            .unwrap();
    state.prev = Some(fixture.heads[3]);
    state.seq = 5;
    state.updated_at += 1;
    state.header.created_at += 1;
    state.sign_with(&fixture.signing_key).unwrap();
    let object_id_key = ObjectIdKey::from_bytes([0xB7; 32]);
    let body = fcp_cbor::CanonicalSerializer::serialize(&state, &state.header.schema).unwrap();
    let invalid_head = StoredObject::derive_id(&state.header, &body, &object_id_key).unwrap();
    fcp_async_core::runtime::block_on_sync(fixture.object_store.put(StoredObject {
        object_id: invalid_head,
        header: state.header,
        body,
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }))
    .unwrap()
    .unwrap();

    let mut root = fcp_async_core::runtime::block_on_sync(fixture.canonical.read_root())
        .unwrap()
        .unwrap()
        .unwrap()
        .1;
    root.head = Some(invalid_head);
    root.header.refs = vec![invalid_head];
    let body = fcp_cbor::CanonicalSerializer::serialize(&root, &root.header.schema).unwrap();
    let invalid_root = StoredObject::derive_id(&root.header, &body, &object_id_key).unwrap();
    fcp_async_core::runtime::block_on_sync(fixture.object_store.put(StoredObject {
        object_id: invalid_root,
        header: root.header,
        body,
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }))
    .unwrap()
    .unwrap();

    let error = reader.load_cursor().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("sequence mismatch: expected 4, got 5")
    );
    assert_eq!(reader.head(), retained_head);
    let mut fresh_reader = fixture.reader();
    assert!(fresh_reader.load_cursor().is_err());
    assert_eq!(fresh_reader.head(), None);

    // A deliberate recovery from the existing trusted anchors remains useful
    // for inspection and must not promote the malformed root to canonical.
    assert_eq!(
        reader
            .recover_cursor_from_snapshot(fixture.roots[3], fixture.snapshot_id, 2)
            .unwrap(),
        fixture.cursors[3],
    );
    assert!(reader.load_cursor().is_err());
    assert_eq!(reader.head(), retained_head);
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_snapshot_recovery_requires_explicit_verified_writer_trust() {
    let fixture = CursorSnapshotReplayFixture::new();
    let raw_backend = ObjectStoreCursorBackend::new(
        Arc::clone(&fixture.object_store),
        ObjectIdKey::from_bytes([0xB7; 32]),
        fixture.connector_id,
        fixture.zone_id,
    );
    let error = raw_backend
        .replay_from_snapshot(fixture.roots[3], fixture.snapshot_id, 2)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("verified canonical writer authorization")
    );
}

#[cfg(feature = "cursor-store-object-store")]
#[test]
fn cursor_store_object_store_rejects_tampered_recovery_state() {
    let object_store: Arc<dyn ObjectStore> =
        Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let object_id_key = ObjectIdKey::from_bytes([0xA6; 32]);
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let lease_object_id = ObjectId::from_bytes([0x51; 32]);

    let backend = ObjectStoreCursorBackend::new(
        Arc::clone(&object_store),
        object_id_key,
        connector_id.clone(),
        zone_id.clone(),
    );
    let mut store = CursorStore::new(backend, connector_id.clone(), zone_id.clone());

    let mut header = object_store_header(1_700_200_000, zone_id.clone());
    header.refs.push(lease_object_id);

    let clean_state = ConnectorStateObject {
        header: header.clone(),
        connector_id,
        instance_id: None,
        zone_id,
        prev: None,
        seq: 1,
        state_cbor: CursorState {
            offset: Some(10),
            last_seen_id: Some("clean".to_string()),
            watermark: Some(100),
        }
        .to_cbor()
        .expect("clean cursor should encode"),
        updated_at: header.created_at,
        lease_seq: 1,
        lease_object_id,
        writer_public_key: [0u8; 32],
        signature: Signature::zero(),
    };
    let clean_body =
        fcp_cbor::CanonicalSerializer::serialize(&clean_state, &clean_state.header.schema)
            .expect("clean state should serialize");
    let clean_object_id = StoredObject::derive_id(&clean_state.header, &clean_body, &object_id_key)
        .expect("clean object id");

    let tampered_state = ConnectorStateObject {
        seq: 99,
        state_cbor: CursorState {
            offset: Some(999),
            last_seen_id: Some("tampered".to_string()),
            watermark: Some(999),
        }
        .to_cbor()
        .expect("tampered cursor should encode"),
        ..clean_state
    };
    let tampered_body =
        fcp_cbor::CanonicalSerializer::serialize(&tampered_state, &tampered_state.header.schema)
            .expect("tampered state should serialize");

    fcp_async_core::runtime::block_on_sync(async {
        object_store
            .put(StoredObject {
                object_id: clean_object_id,
                header,
                body: tampered_body,
                storage: StorageMeta {
                    retention: RetentionClass::Pinned,
                },
            })
            .await
    })
    .expect("runtime should be available")
    .expect("tampered object should be inserted");

    assert!(
        store.load_cursor().expect("load should succeed").is_none(),
        "tampered recovery state should be ignored"
    );
}

#[test]
fn cursor_store_rejects_offset_regression() {
    let backend = InMemoryCursorStoreBackend::new();
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    let lease = CursorLease {
        lease_seq: 1,
        lease_object_id: ObjectId::from_bytes([0x22; 32]),
    };

    let cursor = CursorState {
        offset: Some(10),
        last_seen_id: Some("id-10".to_string()),
        watermark: Some(100),
    };

    store
        .commit_cursor(cursor, test_header(1_700_000_001), lease, Signature::zero())
        .expect("initial commit should succeed");

    let regressed = CursorState {
        offset: Some(9),
        last_seen_id: Some("id-9".to_string()),
        watermark: Some(100),
    };

    let err = store
        .commit_cursor(
            regressed,
            test_header(1_700_000_002),
            CursorLease {
                lease_seq: 2,
                lease_object_id: ObjectId::from_bytes([0x23; 32]),
            },
            Signature::zero(),
        )
        .expect_err("offset regression should be rejected");

    assert!(matches!(err, CursorStoreError::OffsetRegression { .. }));
}

#[test]
fn cursor_store_rejects_stale_lease_seq() {
    let backend = InMemoryCursorStoreBackend::new();
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    store
        .commit_cursor(
            CursorState {
                offset: Some(1),
                last_seen_id: None,
                watermark: None,
            },
            test_header(1_700_000_010),
            CursorLease {
                lease_seq: 5,
                lease_object_id: ObjectId::from_bytes([0x33; 32]),
            },
            Signature::zero(),
        )
        .expect("initial commit should succeed");

    let err = store
        .commit_cursor(
            CursorState {
                offset: Some(2),
                last_seen_id: None,
                watermark: None,
            },
            test_header(1_700_000_011),
            CursorLease {
                lease_seq: 4,
                lease_object_id: ObjectId::from_bytes([0x34; 32]),
            },
            Signature::zero(),
        )
        .expect_err("stale lease_seq should be rejected");

    assert!(matches!(err, CursorStoreError::StaleLeaseSeq { .. }));
}

#[test]
fn cursor_store_rejects_watermark_regression() {
    let backend = InMemoryCursorStoreBackend::new();
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store = CursorStore::new(backend, connector_id, zone_id);

    store
        .commit_cursor(
            CursorState {
                offset: Some(10),
                last_seen_id: None,
                watermark: Some(200),
            },
            test_header(1_700_000_020),
            CursorLease {
                lease_seq: 1,
                lease_object_id: ObjectId::from_bytes([0x35; 32]),
            },
            Signature::zero(),
        )
        .expect("initial commit should succeed");

    let err = store
        .commit_cursor(
            CursorState {
                offset: Some(11),
                last_seen_id: None,
                watermark: Some(100),
            },
            test_header(1_700_000_021),
            CursorLease {
                lease_seq: 2,
                lease_object_id: ObjectId::from_bytes([0x36; 32]),
            },
            Signature::zero(),
        )
        .expect_err("watermark regression should be rejected");

    assert!(matches!(err, CursorStoreError::WatermarkRegression { .. }));
}

#[test]
fn cursor_store_failover_rejects_stale_writer() {
    let backend = Arc::new(InMemoryCursorStoreBackend::new());
    let connector_id = ConnectorId::from_static("test:operational:1.0");
    let zone_id = ZoneId::work();
    let mut store_a = CursorStore::new(Arc::clone(&backend), connector_id.clone(), zone_id.clone());
    let mut store_b = CursorStore::new(Arc::clone(&backend), connector_id, zone_id);

    store_a
        .commit_cursor(
            CursorState {
                offset: Some(1),
                last_seen_id: None,
                watermark: Some(10),
            },
            test_header(1_700_000_030),
            CursorLease {
                lease_seq: 1,
                lease_object_id: ObjectId::from_bytes([0x41; 32]),
            },
            Signature::zero(),
        )
        .expect("first writer commit should succeed");

    let loaded = store_b
        .load_cursor()
        .expect("second writer should load cursor")
        .expect("cursor should be present");
    assert_eq!(loaded.offset, Some(1));

    store_b
        .commit_cursor(
            CursorState {
                offset: Some(2),
                last_seen_id: None,
                watermark: Some(20),
            },
            test_header(1_700_000_031),
            CursorLease {
                lease_seq: 2,
                lease_object_id: ObjectId::from_bytes([0x42; 32]),
            },
            Signature::zero(),
        )
        .expect("second writer commit should succeed");

    let refreshed = store_a
        .load_cursor()
        .expect("first writer reload should succeed")
        .expect("cursor should be present");
    assert_eq!(refreshed.offset, Some(2));

    let err = store_a
        .commit_cursor(
            CursorState {
                offset: Some(3),
                last_seen_id: None,
                watermark: Some(30),
            },
            test_header(1_700_000_032),
            CursorLease {
                lease_seq: 1,
                lease_object_id: ObjectId::from_bytes([0x43; 32]),
            },
            Signature::zero(),
        )
        .expect_err("stale lease after failover should be rejected");

    assert!(matches!(err, CursorStoreError::StaleLeaseSeq { .. }));
}

#[test]
fn test_state_model_deserialize_stateless() {
    let json = r#"{"type": "stateless"}"#;
    let model: ConnectorStateModel = serde_json::from_str(json).expect("deserialize should work");

    assert!(matches!(model, ConnectorStateModel::Stateless));
}

#[test]
fn test_state_model_deserialize_singleton_writer() {
    let json = r#"{"type": "singleton_writer"}"#;
    let model: ConnectorStateModel = serde_json::from_str(json).expect("deserialize should work");

    assert!(matches!(model, ConnectorStateModel::SingletonWriter));
}

#[test]
fn test_state_model_deserialize_crdt() {
    let json = r#"{"type": "crdt", "crdt_type": "lww_map"}"#;
    let model: ConnectorStateModel = serde_json::from_str(json).expect("deserialize should work");

    assert!(matches!(model, ConnectorStateModel::Crdt { .. }));
}

#[test]
fn test_state_model_roundtrip() {
    let models = vec![
        ConnectorStateModel::Stateless,
        ConnectorStateModel::SingletonWriter,
        ConnectorStateModel::Crdt {
            crdt_type: ConnectorCrdtType::LwwMap,
        },
    ];

    for model in models {
        let json = serde_json::to_string(&model).expect("serialize should work");
        let recovered: ConnectorStateModel =
            serde_json::from_str(&json).expect("deserialize should work");
        assert_eq!(model, recovered);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Type Serialization Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_crdt_type_serialize() {
    assert_eq!(
        serde_json::to_value(ConnectorCrdtType::LwwMap).unwrap(),
        "lww_map"
    );
    assert_eq!(
        serde_json::to_value(ConnectorCrdtType::OrSet).unwrap(),
        "or_set"
    );
    assert_eq!(
        serde_json::to_value(ConnectorCrdtType::GCounter).unwrap(),
        "g_counter"
    );
    assert_eq!(
        serde_json::to_value(ConnectorCrdtType::PnCounter).unwrap(),
        "pn_counter"
    );
}

#[test]
fn test_crdt_type_deserialize() {
    let types = [
        ("\"lww_map\"", ConnectorCrdtType::LwwMap),
        ("\"or_set\"", ConnectorCrdtType::OrSet),
        ("\"g_counter\"", ConnectorCrdtType::GCounter),
        ("\"pn_counter\"", ConnectorCrdtType::PnCounter),
    ];

    for (json, expected) in types {
        let crdt_type: ConnectorCrdtType =
            serde_json::from_str(json).expect("deserialize should work");
        assert_eq!(crdt_type, expected);
    }
}

#[test]
fn test_crdt_type_roundtrip() {
    let types = vec![
        ConnectorCrdtType::LwwMap,
        ConnectorCrdtType::OrSet,
        ConnectorCrdtType::GCounter,
        ConnectorCrdtType::PnCounter,
    ];

    for crdt_type in types {
        let json = serde_json::to_string(&crdt_type).expect("serialize should work");
        let recovered: ConnectorCrdtType =
            serde_json::from_str(&json).expect("deserialize should work");
        assert_eq!(crdt_type, recovered);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connector Archetype Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_archetype_bidirectional() {
    let archetype = ConnectorArchetype::Bidirectional;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "bidirectional");
}

#[test]
fn test_archetype_streaming() {
    let archetype = ConnectorArchetype::Streaming;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "streaming");
}

#[test]
fn test_archetype_operational() {
    let archetype = ConnectorArchetype::Operational;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "operational");
}

#[test]
fn test_archetype_storage() {
    let archetype = ConnectorArchetype::Storage;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "storage");
}

#[test]
fn test_archetype_knowledge() {
    let archetype = ConnectorArchetype::Knowledge;
    let json = serde_json::to_value(archetype).expect("serialize should work");
    assert_eq!(json, "knowledge");
}

#[test]
fn test_archetype_deserialize() {
    let archetypes = [
        ("\"bidirectional\"", ConnectorArchetype::Bidirectional),
        ("\"streaming\"", ConnectorArchetype::Streaming),
        ("\"operational\"", ConnectorArchetype::Operational),
        ("\"storage\"", ConnectorArchetype::Storage),
        ("\"knowledge\"", ConnectorArchetype::Knowledge),
    ];

    for (json, expected) in archetypes {
        let archetype: ConnectorArchetype =
            serde_json::from_str(json).expect("deserialize should work");
        assert_eq!(archetype, expected);
    }
}

#[test]
fn test_archetype_roundtrip() {
    let archetypes = vec![
        ConnectorArchetype::Bidirectional,
        ConnectorArchetype::Streaming,
        ConnectorArchetype::Operational,
        ConnectorArchetype::Storage,
        ConnectorArchetype::Knowledge,
    ];

    for archetype in archetypes {
        let json = serde_json::to_string(&archetype).expect("serialize should work");
        let recovered: ConnectorArchetype =
            serde_json::from_str(&json).expect("deserialize should work");
        assert_eq!(archetype, recovered);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime Format Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_runtime_format_native() {
    let format = ConnectorRuntimeFormat::Native;
    let json = serde_json::to_value(format).expect("serialize should work");
    assert_eq!(json, "native");
}

#[test]
fn test_runtime_format_wasi() {
    let format = ConnectorRuntimeFormat::Wasi;
    let json = serde_json::to_value(format).expect("serialize should work");
    assert_eq!(json, "wasi");
}

#[test]
fn test_runtime_format_deserialize() {
    let formats = [
        ("\"native\"", ConnectorRuntimeFormat::Native),
        ("\"wasi\"", ConnectorRuntimeFormat::Wasi),
    ];

    for (json, expected) in formats {
        let format: ConnectorRuntimeFormat =
            serde_json::from_str(json).expect("deserialize should work");
        assert_eq!(format, expected);
    }
}

#[test]
fn test_runtime_format_roundtrip() {
    let formats = vec![ConnectorRuntimeFormat::Native, ConnectorRuntimeFormat::Wasi];

    for format in formats {
        let json = serde_json::to_string(&format).expect("serialize should work");
        let recovered: ConnectorRuntimeFormat =
            serde_json::from_str(&json).expect("deserialize should work");
        assert_eq!(format, recovered);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// State Model Equality Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_state_model_equality() {
    let stateless1 = ConnectorStateModel::Stateless;
    let stateless2 = ConnectorStateModel::Stateless;
    assert_eq!(stateless1, stateless2);

    let singleton1 = ConnectorStateModel::SingletonWriter;
    let singleton2 = ConnectorStateModel::SingletonWriter;
    assert_eq!(singleton1, singleton2);

    let crdt1 = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };
    let crdt2 = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };
    assert_eq!(crdt1, crdt2);
}

#[test]
fn test_state_model_not_equal_different_variants() {
    let stateless = ConnectorStateModel::Stateless;
    let singleton = ConnectorStateModel::SingletonWriter;
    let crdt = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };

    assert_ne!(stateless, singleton);
    assert_ne!(stateless, crdt);
    assert_ne!(singleton, crdt);
}

// ─────────────────────────────────────────────────────────────────────────────
// CRDT Type Equality and Hash Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_crdt_type_equality() {
    assert_eq!(ConnectorCrdtType::LwwMap, ConnectorCrdtType::LwwMap);
    assert_eq!(ConnectorCrdtType::OrSet, ConnectorCrdtType::OrSet);
    assert_eq!(ConnectorCrdtType::GCounter, ConnectorCrdtType::GCounter);
    assert_eq!(ConnectorCrdtType::PnCounter, ConnectorCrdtType::PnCounter);
}

#[test]
fn test_crdt_type_not_equal() {
    assert_ne!(ConnectorCrdtType::LwwMap, ConnectorCrdtType::OrSet);
    assert_ne!(ConnectorCrdtType::GCounter, ConnectorCrdtType::PnCounter);
}

#[test]
fn test_crdt_type_hashable() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(ConnectorCrdtType::LwwMap);
    set.insert(ConnectorCrdtType::OrSet);
    set.insert(ConnectorCrdtType::GCounter);
    set.insert(ConnectorCrdtType::PnCounter);

    assert_eq!(set.len(), 4);
    assert!(set.contains(&ConnectorCrdtType::LwwMap));
    assert!(set.contains(&ConnectorCrdtType::OrSet));
}

// ─────────────────────────────────────────────────────────────────────────────
// Clone and Copy Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[allow(clippy::clone_on_copy)] // Explicitly testing clone behavior
fn test_state_model_clone() {
    let model = ConnectorStateModel::Crdt {
        crdt_type: ConnectorCrdtType::LwwMap,
    };

    let cloned = model.clone();
    assert_eq!(model, cloned);
}

#[test]
fn test_state_model_copy() {
    let model = ConnectorStateModel::Stateless;
    let copied = model;
    assert_eq!(model, copied);
}

#[test]
fn test_crdt_type_copy() {
    let crdt = ConnectorCrdtType::LwwMap;
    let copied = crdt;
    assert_eq!(crdt, copied);
}

#[test]
fn test_archetype_copy() {
    let archetype = ConnectorArchetype::Operational;
    let copied = archetype;
    assert_eq!(archetype, copied);
}

#[test]
fn test_runtime_format_copy() {
    let format = ConnectorRuntimeFormat::Native;
    let copied = format;
    assert_eq!(format, copied);
}
