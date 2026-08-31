use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{
    CONNECTOR_STATE_APPEND_OPERATION_ID, CONNECTOR_STATE_WRITE_CAPABILITY_ID,
    CapabilityConstraints, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorStateAppendOutcome, ConnectorStateChangeKind, ConnectorStateError,
    ConnectorStateObject, ConnectorStateRoot, ConnectorStateStore,
    ConnectorStateWriteAuthorization, InstanceId, ObjectHeader, ObjectId, ObjectIdKey, Provenance,
    Signature, TailscaleNodeId, ZoneId, connector_state_resource_uri,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_mesh::{DeviceProfile, GossipMessage, MeshNode, MeshNodeConfig, ObjectAdmissionClass};
use fcp_store::{
    FcpStoreConnectorStateStore, MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore,
    MemorySymbolStoreConfig, ObjectAdmissionPolicy, ObjectStore, QuarantineStore,
};
use fcp_tailscale::NodeId;
use futures_util::StreamExt;

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

fn object_id_key() -> ObjectIdKey {
    ObjectIdKey::from_bytes([0xA3; 32])
}

fn connector_id() -> ConnectorId {
    ConnectorId::from_static("slack:chat:v1")
}

fn zone_id() -> ZoneId {
    ZoneId::work()
}

fn connector_state_authorization_with_key() -> (ConnectorStateWriteAuthorization, Ed25519SigningKey)
{
    let connector_id = connector_id();
    let zone_id = zone_id();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let constraints = CapabilityConstraints {
        resource_allow: vec![connector_state_resource_uri(&connector_id)],
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
        &connector_id,
        &zone_id,
    )
    .expect("connector-state write token should authorize append");
    (authorization, signing_key)
}

fn lease_id(seed: u8) -> ObjectId {
    ObjectId::from_bytes([seed; 32])
}

fn host_state_store(object_store: Arc<dyn ObjectStore>) -> FcpStoreConnectorStateStore {
    FcpStoreConnectorStateStore::new(object_store, object_id_key(), connector_id(), zone_id())
        .with_snapshot_every_entries(0)
        .with_snapshot_every_secs(0)
}

fn mesh_node(name: &str, object_store: Arc<dyn ObjectStore>) -> MeshNode {
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
    let symbol_store: Arc<dyn fcp_store::SymbolStore> = symbol_store;
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
    MeshNode::new(
        MeshNodeConfig::new(name).with_sender_instance_id(42),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fn mesh_device_profile(node_id: &str) -> DeviceProfile {
    DeviceProfile::builder(NodeId::new(node_id)).build()
}

fn zone_set(zone: ZoneId) -> HashSet<ZoneId> {
    HashSet::from([zone])
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
        created_at: 1_800_100_000 + seq,
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
        updated_at: 1_800_100_000 + seq,
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

fn append_committed(
    store: &FcpStoreConnectorStateStore,
    state_obj: ConnectorStateObject,
) -> Result<(ObjectId, ObjectId, u64), ConnectorStateError> {
    let connector_id = connector_id();
    let (authorization, signing_key) = connector_state_authorization_with_key();
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

#[test]
fn connector_state_subscribe_invalidates_second_host_handle() -> TestResult {
    let object_store = memory_object_store();
    let host_a = host_state_store(Arc::clone(&object_store));
    let host_b = host_state_store(Arc::clone(&object_store));
    let mut host_b_changes = block_on(ConnectorStateStore::subscribe_changes(
        &host_b,
        &connector_id(),
    ))?;

    let started = Instant::now();
    let (head_0, root_0, seq_0) = append_committed(&host_a, state(0, None, lease_id(1)))?;
    assert_eq!(seq_0, 0);

    let appended = block_on(host_b_changes.next())
        .expect("second host handle should observe object append")?;
    assert_eq!(appended.kind, ConnectorStateChangeKind::ObjectAppended);
    assert_eq!(appended.object_id, Some(head_0));
    assert_eq!(appended.seq, Some(0));

    let root =
        block_on(host_b_changes.next()).expect("second host handle should observe root update")?;
    assert_eq!(root.kind, ConnectorStateChangeKind::RootUpdated);
    assert_eq!(root.object_id, Some(root_0));
    assert_eq!(root.seq, Some(0));

    let propagation = started.elapsed();
    assert!(
        propagation < Duration::from_millis(100),
        "same-store connector state invalidation took {propagation:?}"
    );

    let host_b_root = read_root(&host_b)?;
    assert_eq!(host_b_root.head, Some(head_0));

    Ok(())
}

#[test]
fn connector_state_subscribe_observes_mesh_gossip_replicated_root() -> TestResult {
    const HOST_A: &str = "host-a";
    const HOST_B: &str = "host-b";
    const NOW_SECS: u64 = 1_800_200_000;
    const NOW_MS: u64 = NOW_SECS * 1000;

    let store_a = memory_object_store();
    let store_b = memory_object_store();
    let host_a = host_state_store(Arc::clone(&store_a));
    let host_b = host_state_store(Arc::clone(&store_b));
    let mut host_b_changes = block_on(ConnectorStateStore::subscribe_changes(
        &host_b,
        &connector_id(),
    ))?;

    let mut node_a = mesh_node(HOST_A, Arc::clone(&store_a));
    let mut node_b = mesh_node(HOST_B, Arc::clone(&store_b));
    let host_a_peer = NodeId::new(HOST_A);
    let host_b_peer = NodeId::new(HOST_B);
    node_a.update_peer_state(
        host_b_peer.clone(),
        mesh_device_profile(HOST_B),
        HashSet::new(),
        vec![],
        NOW_MS,
    );
    node_a.update_peer_zones(&host_b_peer, zone_set(zone_id()));
    node_b.update_peer_state(
        host_a_peer.clone(),
        mesh_device_profile(HOST_A),
        HashSet::new(),
        vec![],
        NOW_MS,
    );
    node_b.update_peer_zones(&host_a_peer, zone_set(zone_id()));

    let started = Instant::now();
    let (head_0, root_0, seq_0) = append_committed(&host_a, state(0, None, lease_id(2)))?;
    assert_eq!(seq_0, 0);
    assert!(node_a.announce_object(&zone_id(), &head_0, ObjectAdmissionClass::Admitted, NOW_MS,));
    assert!(node_a.announce_object(&zone_id(), &root_0, ObjectAdmissionClass::Admitted, NOW_MS,));

    let request = fcp_mesh::GossipRequest {
        from: TailscaleNodeId::new(HOST_B),
        zone_id: zone_id(),
        object_ids: vec![head_0, root_0],
        symbols: vec![],
        timestamp: NOW_SECS,
        signature: None,
    };
    let request_payload = serde_json::to_vec(&GossipMessage::Request(request))?;

    block_on(async {
        let outcome = node_a
            .dispatch_gossip_payload_with_fetch_reply(&request_payload, NOW_SECS)
            .await?;
        let response = outcome
            .dispatch
            .response
            .as_ref()
            .expect("standard dispatch response should be preserved");
        assert_eq!(response.from, TailscaleNodeId::new(HOST_A));
        assert_eq!(response.to, TailscaleNodeId::new(HOST_B));
        assert_eq!(response.have_objects, vec![head_0, root_0]);

        let fetch_reply = outcome
            .fetch_reply
            .expect("mesh request dispatch should include fetched bytes");
        assert_eq!(fetch_reply.payload.objects.len(), 2);
        assert!(fetch_reply.payload.symbols.is_empty());
        let plan = node_b
            .handle_gossip_response(fetch_reply.response, NOW_SECS)?
            .expect("host B should produce a fetch plan for missing state objects");
        let applied = node_b
            .apply_gossip_fetch_payload_and_observe_connector_state_roots(
                &host_b,
                &plan,
                fetch_reply.payload.objects,
                fetch_reply.payload.symbols,
                NOW_MS,
            )
            .await?;
        assert_eq!(applied.apply.objects_applied, vec![head_0, root_0]);
        assert_eq!(applied.apply.connector_state_root_candidates, vec![root_0]);
        assert_eq!(applied.connector_state_changes.len(), 1);
        assert_eq!(
            applied.connector_state_changes[0].kind,
            ConnectorStateChangeKind::RootUpdated
        );
        assert_eq!(applied.connector_state_changes[0].object_id, Some(root_0));
        assert_eq!(applied.connector_state_changes[0].seq, Some(0));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    let root_update = block_on(host_b_changes.next())
        .expect("host B subscriber should observe replicated root update")?;
    assert_eq!(root_update.kind, ConnectorStateChangeKind::RootUpdated);
    assert_eq!(root_update.object_id, Some(root_0));
    assert_eq!(root_update.seq, Some(0));

    let propagation = started.elapsed();
    assert!(
        propagation < Duration::from_millis(250),
        "mesh-backed connector state invalidation took {propagation:?}"
    );

    let host_b_root = read_root(&host_b)?;
    assert_eq!(host_b_root.head, Some(head_0));

    Ok(())
}
