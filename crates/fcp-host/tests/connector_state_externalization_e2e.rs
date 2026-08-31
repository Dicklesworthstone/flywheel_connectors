use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, Utc};
use fcp_cbor::CanonicalSerializer;
use fcp_core::{
    BackoffPolicy, CONNECTOR_STATE_APPEND_OPERATION_ID, CONNECTOR_STATE_WRITE_CAPABILITY_ID,
    CapabilityConstraints, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorStateAppendOutcome, ConnectorStateError, ConnectorStateModel, ConnectorStateObject,
    ConnectorStateRoot, ConnectorStateStore, ConnectorStateWriteAuthorization, InstanceId,
    ObjectHeader, ObjectId, ObjectIdKey, Provenance, RetentionClass, Signature, StorageMeta,
    StoredObject, ZoneId, connector_state_resource_uri,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_store::{
    CONNECTOR_STATE_CACHE_MARKER, FcpStoreConnectorStateStore, MemoryObjectStore,
    MemoryObjectStoreConfig, ObjectStore, ObjectStoreError,
};
use serde::Serialize;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    fcp_async_core::runtime::block_on_sync(future).expect("test runtime should start")
}

fn memory_object_store() -> Arc<dyn ObjectStore> {
    Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()))
}

fn memory_object_store_with_quota(max_bytes: u64) -> Arc<dyn ObjectStore> {
    Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig {
        max_bytes,
    }))
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

#[async_trait]
impl ObjectStore for FailNthPutObjectStore {
    async fn put(&self, object: StoredObject) -> Result<(), ObjectStoreError> {
        let put_number = self.puts.fetch_add(1, Ordering::SeqCst) + 1;
        if put_number == self.fail_on_put {
            return Err(ObjectStoreError::Io(
                "simulated connector state root write outage".to_string(),
            ));
        }
        self.inner.put(object).await
    }

    async fn get(&self, id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
        self.inner.get(id).await
    }

    async fn exists(&self, id: &ObjectId) -> bool {
        self.inner.exists(id).await
    }

    async fn delete(&self, id: &ObjectId) -> Result<(), ObjectStoreError> {
        self.inner.delete(id).await
    }

    async fn get_header(&self, id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError> {
        self.inner.get_header(id).await
    }

    async fn get_storage_meta(&self, id: &ObjectId) -> Result<StorageMeta, ObjectStoreError> {
        self.inner.get_storage_meta(id).await
    }

    async fn set_retention(
        &self,
        id: &ObjectId,
        retention: RetentionClass,
    ) -> Result<(), ObjectStoreError> {
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

struct ReadUnavailableObjectStore {
    listed_root: ObjectId,
}

impl ReadUnavailableObjectStore {
    const fn new(listed_root: ObjectId) -> Self {
        Self { listed_root }
    }

    fn unavailable_error() -> ObjectStoreError {
        ObjectStoreError::Io("simulated connector state read outage".to_string())
    }
}

#[async_trait]
impl ObjectStore for ReadUnavailableObjectStore {
    async fn put(&self, _object: StoredObject) -> Result<(), ObjectStoreError> {
        Err(Self::unavailable_error())
    }

    async fn get(&self, _id: &ObjectId) -> Result<StoredObject, ObjectStoreError> {
        Err(Self::unavailable_error())
    }

    async fn exists(&self, _id: &ObjectId) -> bool {
        false
    }

    async fn delete(&self, _id: &ObjectId) -> Result<(), ObjectStoreError> {
        Err(Self::unavailable_error())
    }

    async fn get_header(&self, _id: &ObjectId) -> Result<ObjectHeader, ObjectStoreError> {
        Err(Self::unavailable_error())
    }

    async fn get_storage_meta(&self, _id: &ObjectId) -> Result<StorageMeta, ObjectStoreError> {
        Err(Self::unavailable_error())
    }

    async fn set_retention(
        &self,
        _id: &ObjectId,
        _retention: RetentionClass,
    ) -> Result<(), ObjectStoreError> {
        Err(Self::unavailable_error())
    }

    async fn list_zone(&self, _zone_id: &ZoneId) -> Vec<ObjectId> {
        vec![self.listed_root]
    }

    async fn storage_used(&self) -> u64 {
        0
    }

    async fn storage_quota(&self) -> u64 {
        0
    }
}

fn object_id_key() -> ObjectIdKey {
    ObjectIdKey::from_bytes([0xA2; 32])
}

fn connector_id() -> ConnectorId {
    ConnectorId::from_static("slack:chat:v1")
}

fn other_connector_id() -> ConnectorId {
    ConnectorId::from_static("github:issue:v1")
}

fn zone_id() -> ZoneId {
    ZoneId::work()
}

fn connector_state_authorization_for(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
) -> ConnectorStateWriteAuthorization {
    connector_state_authorization_for_with_key(connector_id, zone_id).0
}

fn connector_state_authorization_for_with_key(
    connector_id: &ConnectorId,
    zone_id: &ZoneId,
) -> (ConnectorStateWriteAuthorization, Ed25519SigningKey) {
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let constraints = CapabilityConstraints {
        resource_allow: vec![connector_state_resource_uri(connector_id)],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
    let now = Utc::now();
    let token = CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(CONNECTOR_STATE_WRITE_CAPABILITY_ID)
            .zone_id(zone_id.as_str())
            .target_instance(instance_id.as_str())
            .principal("principal:test")
            .operations(&[CONNECTOR_STATE_APPEND_OPERATION_ID])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
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
        connector_id,
        zone_id,
    )
    .expect("connector-state write token should authorize append");
    (authorization, signing_key)
}

fn connector_state_authorization() -> ConnectorStateWriteAuthorization {
    connector_state_authorization_for(&connector_id(), &zone_id())
}

fn lease_id(seed: u8) -> ObjectId {
    ObjectId::from_bytes([seed; 32])
}

fn host_state_store(object_store: Arc<dyn ObjectStore>) -> FcpStoreConnectorStateStore {
    FcpStoreConnectorStateStore::new(object_store, object_id_key(), connector_id(), zone_id())
        .with_snapshot_every_entries(0)
        .with_snapshot_every_secs(0)
}

fn state_cbor(seq: u64) -> Vec<u8> {
    let seq_byte = u8::try_from(seq).expect("test sequence should fit in one CBOR byte");
    Vec::from([0xa1, 0x61, b'n', seq_byte])
}

fn state_header(seq: u64, lease: ObjectId) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: FcpStoreConnectorStateStore::state_object_schema_id(),
        zone_id: zone_id(),
        created_at: 1_800_000_000 + seq,
        provenance: Provenance::new(zone_id()),
        refs: vec![lease],
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

fn state(seq: u64, prev: Option<ObjectId>, lease: ObjectId) -> ConnectorStateObject {
    ConnectorStateObject {
        header: state_header(seq, lease),
        connector_id: connector_id(),
        instance_id: None,
        zone_id: zone_id(),
        prev,
        seq,
        state_cbor: state_cbor(seq),
        updated_at: 1_800_000_000 + seq,
        lease_seq: seq + 10,
        lease_object_id: lease,
        writer_public_key: [0u8; 32],
        signature: Signature::zero(),
    }
}

fn sign_state(
    mut state: ConnectorStateObject,
    signing_key: &Ed25519SigningKey,
) -> ConnectorStateObject {
    state
        .sign_with(signing_key)
        .expect("test connector state should sign");
    state
}

fn stored_object_for<T: Serialize>(header: &ObjectHeader, value: &T) -> StoredObject {
    let body =
        CanonicalSerializer::serialize(value, &header.schema).expect("test object should encode");
    let object_id =
        StoredObject::derive_id(header, &body, &object_id_key()).expect("test object id");
    StoredObject {
        object_id,
        header: header.clone(),
        body,
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }
}

fn root_with_head(head: ObjectId, created_at: u64) -> ConnectorStateRoot {
    ConnectorStateRoot {
        header: ObjectHeader {
            encryption_kind: Default::default(),
            schema: FcpStoreConnectorStateStore::root_schema_id(),
            zone_id: zone_id(),
            created_at,
            provenance: Provenance::new(zone_id()),
            refs: vec![head],
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        connector_id: connector_id(),
        instance_id: None,
        zone_id: zone_id(),
        model: ConnectorStateModel::SingletonWriter,
        head: Some(head),
        state_schema_version: 1,
    }
}

fn append_committed(
    store: &FcpStoreConnectorStateStore,
    state_obj: ConnectorStateObject,
) -> Result<(ObjectId, ObjectId, u64), ConnectorStateError> {
    let connector_id = connector_id();
    let (authorization, signing_key) =
        connector_state_authorization_for_with_key(&connector_id, &zone_id());
    let state_obj = sign_state(state_obj, &signing_key);
    match block_on(ConnectorStateStore::append_object(
        store,
        &connector_id,
        &authorization,
        state_obj,
    ))? {
        ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq,
            snapshot_object_id,
        } => {
            assert_eq!(snapshot_object_id, None);
            Ok((object_id, root_object_id, seq))
        }
        ConnectorStateAppendOutcome::Conflict {
            canonical_head,
            canonical_seq,
        } => panic!(
            "expected committed state object, got conflict at {canonical_head:?} seq {canonical_seq:?}"
        ),
    }
}

fn read_root(
    store: &FcpStoreConnectorStateStore,
) -> Result<ConnectorStateRoot, ConnectorStateError> {
    let connector_id = connector_id();
    block_on(ConnectorStateStore::read_root(store, &connector_id))?.ok_or_else(|| {
        ConnectorStateError::SnapshotUnavailable {
            connector_id,
            reason: "connector state root missing in test".to_string(),
        }
    })
}

fn read_chain(
    store: &FcpStoreConnectorStateStore,
    after_seq: Option<u64>,
    limit: usize,
) -> Result<Vec<ConnectorStateObject>, ConnectorStateError> {
    let connector_id = connector_id();
    block_on(ConnectorStateStore::read_chain(
        store,
        &connector_id,
        after_seq,
        limit,
    ))
}

fn p50_latency(mut samples: Vec<Duration>) -> Duration {
    assert!(!samples.is_empty(), "latency sample set must not be empty");
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[test]
fn connector_state_externalization_restores_from_store_after_restart() -> TestResult {
    let object_store = memory_object_store();
    let host_a = host_state_store(Arc::clone(&object_store));
    let cache_root = tempfile::tempdir()?;
    let cache_dir = cache_root.path().join("slack_chat_v1").join("z_work");
    std::fs::create_dir_all(&cache_dir)?;
    let cache_marker_path = cache_dir.join(CONNECTOR_STATE_CACHE_MARKER);
    std::fs::write(
        &cache_marker_path,
        "cache-only: canonical connector state is stored through fcp-store\n",
    )?;
    assert!(cache_marker_path.is_file());

    let (head_0, _root_0, seq_0) = append_committed(&host_a, state(0, None, lease_id(1)))?;
    assert_eq!(seq_0, 0);

    let host_after_restart = host_state_store(Arc::clone(&object_store));
    let restored_root = read_root(&host_after_restart)?;
    assert_eq!(restored_root.head, Some(head_0));

    let restored_chain = read_chain(&host_after_restart, None, 10)?;
    assert_eq!(restored_chain.len(), 1);
    assert_eq!(restored_chain[0].seq, 0);
    assert_eq!(restored_chain[0].state_cbor, state_cbor(0));

    let (head_1, _root_1, seq_1) =
        append_committed(&host_after_restart, state(1, Some(head_0), lease_id(2)))?;
    assert_eq!(seq_1, 1);

    let host_after_second_restart = host_state_store(Arc::clone(&object_store));
    let restored_root = read_root(&host_after_second_restart)?;
    assert_eq!(restored_root.head, Some(head_1));

    let restored_chain = read_chain(&host_after_second_restart, None, 10)?;
    let restored_seqs = restored_chain
        .iter()
        .map(|state| state.seq)
        .collect::<Vec<_>>();
    assert_eq!(restored_seqs, [0, 1]);

    let connector_id = connector_id();
    let snapshot = block_on(ConnectorStateStore::snapshot(
        &host_after_second_restart,
        &connector_id,
    ))?;
    assert_eq!(snapshot.covers_head, head_1);
    assert_eq!(snapshot.covers_seq, 1);
    assert_eq!(snapshot.state_cbor, state_cbor(1));

    Ok(())
}

#[test]
fn connector_state_externalization_latency_budget_matrix() -> TestResult {
    const ITERATIONS: usize = 33;

    let object_store = memory_object_store();
    let host = host_state_store(Arc::clone(&object_store));
    let (head_0, _root_0, _seq_0) = append_committed(&host, state(0, None, lease_id(1)))?;

    let same_handle_read_p50 = block_on(async {
        let mut samples = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let started = Instant::now();
            let root = ConnectorStateStore::read_root(&host, &connector_id())
                .await?
                .ok_or_else(|| ConnectorStateError::SnapshotUnavailable {
                    connector_id: connector_id(),
                    reason: "connector state root missing in latency test".to_string(),
                })?;
            assert_eq!(root.head, Some(head_0));
            samples.push(started.elapsed());
        }
        Ok::<Duration, ConnectorStateError>(p50_latency(samples))
    })?;

    let fresh_handle_fall_through_p50 = block_on(async {
        let mut samples = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let fresh_host = host_state_store(Arc::clone(&object_store));
            let started = Instant::now();
            let root = ConnectorStateStore::read_root(&fresh_host, &connector_id())
                .await?
                .ok_or_else(|| ConnectorStateError::SnapshotUnavailable {
                    connector_id: connector_id(),
                    reason: "connector state root missing in latency test".to_string(),
                })?;
            assert_eq!(root.head, Some(head_0));
            samples.push(started.elapsed());
        }
        Ok::<Duration, ConnectorStateError>(p50_latency(samples))
    })?;

    let fail_closed_p50 = block_on(async {
        let mut samples = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let unavailable_store: Arc<dyn ObjectStore> =
                Arc::new(ReadUnavailableObjectStore::new(lease_id(200)));
            let unavailable = host_state_store(unavailable_store);
            let connector_id = connector_id();
            let started = Instant::now();
            let result = ConnectorStateStore::read_root(&unavailable, &connector_id).await;
            match result {
                Err(ConnectorStateError::StorageUnavailable {
                    connector_id: failed_connector_id,
                    reason,
                }) => {
                    assert_eq!(failed_connector_id, connector_id);
                    assert!(!reason.is_empty());
                }
                other => panic!("expected typed storage-unavailable failure, got {other:?}"),
            }
            samples.push(started.elapsed());
        }
        Ok::<Duration, ConnectorStateError>(p50_latency(samples))
    })?;

    eprintln!(
        "connector-state p50 matrix: same-handle={same_handle_read_p50:?}, fresh-handle-fall-through={fresh_handle_fall_through_p50:?}, fail-closed={fail_closed_p50:?}"
    );

    assert!(
        same_handle_read_p50 < Duration::from_millis(2),
        "same-handle canonical connector-state read p50 {same_handle_read_p50:?} exceeded 2ms"
    );
    assert!(
        fresh_handle_fall_through_p50 < Duration::from_millis(20),
        "fresh-handle fcp-store fall-through read p50 {fresh_handle_fall_through_p50:?} exceeded 20ms"
    );
    assert!(
        fail_closed_p50 < Duration::from_millis(5),
        "fail-closed storage-unavailable path p50 {fail_closed_p50:?} exceeded 5ms"
    );

    Ok(())
}

#[test]
fn connector_state_externalization_conflicts_on_stale_prev_pointer() -> TestResult {
    let object_store = memory_object_store();
    let host_a = host_state_store(Arc::clone(&object_store));
    let host_b = host_state_store(Arc::clone(&object_store));

    let (head_0, _root_0, _seq_0) = append_committed(&host_a, state(0, None, lease_id(1)))?;
    let (head_1, _root_1, _seq_1) = append_committed(&host_a, state(1, Some(head_0), lease_id(2)))?;

    let connector_id = connector_id();
    let (authorization, signing_key) =
        connector_state_authorization_for_with_key(&connector_id, &zone_id());
    let stale_outcome = block_on(ConnectorStateStore::append_object(
        &host_b,
        &connector_id,
        &authorization,
        sign_state(state(1, Some(head_0), lease_id(3)), &signing_key),
    ))?;
    match stale_outcome {
        ConnectorStateAppendOutcome::Conflict {
            canonical_head,
            canonical_seq,
        } => {
            assert_eq!(canonical_head, Some(head_1));
            assert_eq!(canonical_seq, Some(1));
        }
        ConnectorStateAppendOutcome::Committed { .. } => {
            panic!("stale prev-pointer append unexpectedly committed")
        }
    }

    let chain_after_conflict = read_chain(&host_b, None, 10)?;
    assert_eq!(chain_after_conflict.len(), 2);
    assert!(
        chain_after_conflict
            .iter()
            .all(|state| state.lease_object_id != lease_id(3))
    );

    Ok(())
}

#[test]
fn connector_state_externalization_rejects_authorization_for_other_connector() -> TestResult {
    let object_store = memory_object_store();
    let host = host_state_store(object_store);
    let connector_id = connector_id();
    let authorization = connector_state_authorization_for(&other_connector_id(), &zone_id());

    let result = block_on(ConnectorStateStore::append_object(
        &host,
        &connector_id,
        &authorization,
        state(0, None, lease_id(1)),
    ));

    match result {
        Err(ConnectorStateError::AuthorizationDenied {
            connector_id: failed_connector_id,
            reason,
        }) => {
            assert_eq!(failed_connector_id, connector_id);
            assert!(reason.contains("authorization connector"));
        }
        other => panic!("expected authorization denial, got {other:?}"),
    }
    assert!(block_on(ConnectorStateStore::read_root(&host, &connector_id))?.is_none());

    Ok(())
}

#[test]
fn connector_state_externalization_rejects_invalid_state_signature() -> TestResult {
    let object_store = memory_object_store();
    let host = host_state_store(object_store);
    let connector_id = connector_id();
    let authorization = connector_state_authorization();

    let result = block_on(ConnectorStateStore::append_object(
        &host,
        &connector_id,
        &authorization,
        state(0, None, lease_id(1)),
    ));

    match result {
        Err(ConnectorStateError::MalformedState {
            connector_id: failed_connector_id,
            reason,
        }) => {
            assert_eq!(failed_connector_id, connector_id);
            assert!(
                reason.contains("signature"),
                "malformed-state reason should mention signature, got `{reason}`"
            );
        }
        other => panic!("expected malformed-state rejection for invalid signature, got {other:?}"),
    }
    assert!(block_on(ConnectorStateStore::read_root(&host, &connector_id))?.is_none());

    Ok(())
}

#[test]
fn connector_state_externalization_rejects_persisted_invalid_signature_on_read() -> TestResult {
    let object_store = memory_object_store();
    let host = host_state_store(Arc::clone(&object_store));
    let connector_id = connector_id();
    let (_authorization, signing_key) =
        connector_state_authorization_for_with_key(&connector_id, &zone_id());

    let mut bad_state = sign_state(state(0, None, lease_id(1)), &signing_key);
    bad_state.signature = Signature::zero();
    let bad_state_object = stored_object_for(&bad_state.header, &bad_state);
    let bad_head = bad_state_object.object_id;
    block_on(object_store.put(bad_state_object))?;

    let root = root_with_head(bad_head, 1_800_001_000);
    let root_object = stored_object_for(&root.header, &root);
    block_on(object_store.put(root_object))?;

    let read_root_result = block_on(ConnectorStateStore::read_root(&host, &connector_id));
    match read_root_result {
        Err(ConnectorStateError::MalformedState {
            connector_id: failed_connector_id,
            reason,
        }) => {
            assert_eq!(failed_connector_id, connector_id);
            assert!(
                reason.contains("signature"),
                "read-boundary rejection should mention signature, got `{reason}`"
            );
        }
        other => panic!("expected read-boundary malformed-state rejection, got {other:?}"),
    }

    let read_chain_result = block_on(ConnectorStateStore::read_chain(
        &host,
        &connector_id,
        None,
        10,
    ));
    assert!(
        matches!(
            read_chain_result,
            Err(ConnectorStateError::MalformedState { .. })
        ),
        "invalid persisted state must not be exposed through read_chain"
    );

    Ok(())
}

#[test]
fn connector_state_externalization_rejects_malformed_payload_boundaries() -> TestResult {
    let object_store = memory_object_store();
    let host = host_state_store(object_store);
    let connector_id = connector_id();
    let authorization = connector_state_authorization();

    let cases: [(&str, Vec<u8>, &str); 4] = [
        ("empty", Vec::new(), "empty state_cbor"),
        ("invalid", vec![0xff], "invalid state_cbor"),
        ("noncanonical", vec![0x18, 0x17], "non-canonical"),
        (
            "too_large",
            vec![0xff; 1024 * 1024 + 1],
            "payload too large",
        ),
    ];

    for (case, state_cbor, expected_reason) in cases {
        let mut incoming = state(0, None, lease_id(1));
        incoming.state_cbor = state_cbor;

        let result = block_on(ConnectorStateStore::append_object(
            &host,
            &connector_id,
            &authorization,
            incoming,
        ));

        match result {
            Err(ConnectorStateError::MalformedState {
                connector_id: failed_connector_id,
                reason,
            }) => {
                assert_eq!(failed_connector_id, connector_id, "{case}");
                assert!(
                    reason.contains(expected_reason),
                    "{case} reason should include `{expected_reason}`, got `{reason}`"
                );
            }
            other => panic!("expected malformed-state rejection for {case}, got {other:?}"),
        }
        assert!(
            block_on(ConnectorStateStore::read_root(&host, &connector_id))?.is_none(),
            "{case} append must not create a canonical root"
        );
    }

    Ok(())
}

#[test]
fn connector_state_externalization_retries_cleanly_after_root_write_failure() -> TestResult {
    let inner = memory_object_store();
    let object_store: Arc<dyn ObjectStore> =
        Arc::new(FailNthPutObjectStore::new(Arc::clone(&inner), 2));
    let host = host_state_store(object_store);
    let connector_id = connector_id();
    let (authorization, signing_key) =
        connector_state_authorization_for_with_key(&connector_id, &zone_id());

    let first_attempt = block_on(ConnectorStateStore::append_object(
        &host,
        &connector_id,
        &authorization,
        sign_state(state(0, None, lease_id(1)), &signing_key),
    ));
    match first_attempt {
        Err(ConnectorStateError::StorageUnavailable {
            connector_id: failed_connector_id,
            reason,
        }) => {
            assert_eq!(failed_connector_id, connector_id);
            assert!(reason.contains("simulated connector state root write outage"));
        }
        other => panic!("expected simulated root-write outage, got {other:?}"),
    }

    assert!(block_on(ConnectorStateStore::read_root(&host, &connector_id))?.is_none());
    assert!(
        read_chain(&host, None, 10)?.is_empty(),
        "unrooted state object from failed append must not be exposed as canonical chain"
    );

    let (head_0, _root_0, seq_0) = append_committed(&host, state(0, None, lease_id(1)))?;
    assert_eq!(seq_0, 0);
    let root = read_root(&host)?;
    assert_eq!(root.head, Some(head_0));
    let chain = read_chain(&host, None, 10)?;
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].seq, 0);
    assert_eq!(chain[0].lease_object_id, lease_id(1));

    Ok(())
}

#[test]
fn connector_state_externalization_retries_transient_root_write_with_policy() -> TestResult {
    let inner = memory_object_store();
    let object_store: Arc<dyn ObjectStore> =
        Arc::new(FailNthPutObjectStore::new(Arc::clone(&inner), 2));
    let host = host_state_store(object_store).with_root_write_retry_policy(BackoffPolicy::new(
        1,
        Duration::ZERO,
        Duration::ZERO,
        1.0,
    ));

    let (head_0, _root_0, seq_0) = append_committed(&host, state(0, None, lease_id(1)))?;
    assert_eq!(seq_0, 0);

    let root = read_root(&host)?;
    assert_eq!(root.head, Some(head_0));
    let chain = read_chain(&host, None, 10)?;
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].seq, 0);
    assert_eq!(chain[0].lease_object_id, lease_id(1));

    Ok(())
}

#[test]
fn connector_state_externalization_fails_closed_when_store_is_unavailable() {
    let object_store = memory_object_store_with_quota(1);
    let host = host_state_store(object_store);
    let connector_id = connector_id();
    let (authorization, signing_key) =
        connector_state_authorization_for_with_key(&connector_id, &zone_id());

    let started = Instant::now();
    let append_result = block_on(ConnectorStateStore::append_object(
        &host,
        &connector_id,
        &authorization,
        sign_state(state(0, None, lease_id(1)), &signing_key),
    ));
    let elapsed = started.elapsed();

    match append_result {
        Err(ConnectorStateError::StorageUnavailable {
            connector_id: failed_connector_id,
            reason,
        }) => {
            assert_eq!(failed_connector_id, connector_id);
            assert!(!reason.is_empty());
        }
        other => panic!("expected typed storage-unavailable failure, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_millis(50),
        "fail-closed path took {elapsed:?}"
    );
}
