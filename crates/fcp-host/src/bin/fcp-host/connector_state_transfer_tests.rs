//! Real mesh transport, admin admission and durable replica recovery regressions.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use fcp_cbor::{CanonicalSerializer, SchemaId};
use fcp_crypto::Ed25519SigningKey;
use fcp_evidence::{ObjectHeader, RetentionClass, StorageMeta};
use fcp_host::ConnectorStateTransferLimits;
use fcp_host::mesh_routing::{MESH_FORWARD_ROUTE, MeshRoutingSettings};
use fcp_kernel::{ConnectorStateObject, ConnectorStateRoot};
use fcp_mesh::invoke_route::MeshForwardEnvelope;
use fcp_prelude::Signature;

use super::*;

const CONNECTOR: &str = "fcp.test.state-transfer:utility:1.0.0";
const GRANT: &str = "restore-exact-connector-state";
const PULL_ROUTE: &str = "/rpc/admin/connectors/{connector_id}/state/pull";
const STORE_QUOTA: u64 = 2 * 1024 * 1024;

fn signing_key(seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[seed; 32]).expect("fixture signing key")
}

fn writer_pin() -> [u8; 32] {
    signing_key(0x51).verifying_key().to_bytes()
}

fn object_key() -> ObjectIdKey {
    ObjectIdKey::from_bytes([0x42; 32])
}

fn transfer_scope() -> ConnectorStateTransferScope {
    ConnectorStateTransferScope {
        connector_id: ConnectorId::from_static(CONNECTOR),
        zone_id: ZoneId::work(),
        instance_id: None,
    }
}

fn transfer_limits() -> ConnectorStateTransferLimits {
    ConnectorStateTransferLimits {
        max_objects: 16,
        max_canonical_bytes: 64 * 1024,
        max_wire_bytes: 128 * 1024,
    }
}

fn private_bind() -> BindTarget {
    BindTarget::Tcp("127.0.0.1:0".parse().expect("loopback bind"))
}

fn grant(
    direction: ConnectorStateTransferDirection,
    peer: &str,
    root: ObjectId,
) -> ConnectorStateTransferGrant {
    ConnectorStateTransferGrant {
        grant_id: GRANT.to_owned(),
        direction,
        peer_node: peer.to_owned(),
        scope: transfer_scope(),
        root_object_id: root,
        expires_at: Utc::now() + chrono::Duration::hours(1),
        limits: transfer_limits(),
    }
}

fn store_config(
    source: Option<PathBuf>,
    retain_replica: bool,
    writer: [u8; 32],
) -> TransferStoreConfig {
    TransferStoreConfig {
        scope: transfer_scope(),
        object_id_key_hex: hex::encode(object_key().as_bytes()),
        trusted_writer_keys_hex: vec![hex::encode(writer)],
        source_objects_dir: source,
        source_mac_key_hex: None,
        retain_replica,
        max_store_bytes: STORE_QUOTA,
    }
}

fn recipient_config(root_dir: &StdPath, root: ObjectId, writer: [u8; 32]) -> TransferConfig {
    TransferConfig {
        replica_root: Some(root_dir.to_path_buf()),
        stores: vec![store_config(None, true, writer)],
        grants: vec![grant(
            ConnectorStateTransferDirection::Import,
            "donor",
            root,
        )],
    }
}

fn header(schema: SchemaId, refs: Vec<ObjectId>, created_at: u64) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema,
        zone_id: transfer_scope().zone_id,
        created_at,
        provenance: Provenance::new(transfer_scope().zone_id),
        refs,
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

fn stored(header: &ObjectHeader, value: &impl Serialize) -> StoredObject {
    let body = CanonicalSerializer::serialize(value, &header.schema).expect("canonical fixture");
    StoredObject {
        object_id: StoredObject::derive_id(header, &body, &object_key()).expect("keyed object ID"),
        header: header.clone(),
        body,
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }
}

async fn seed_source(objects: &DurableObjectStore) -> (ObjectId, Vec<ObjectId>) {
    let writer = signing_key(0x51);
    let lease_id = ObjectId::from_bytes([0x17; 32]);
    let mut ancestry = Vec::new();
    for seq in 0..2_u8 {
        let prev = ancestry.last().copied();
        let mut refs = vec![lease_id];
        refs.extend(prev);
        let mut state = ConnectorStateObject {
            header: header(
                FcpStoreConnectorStateStore::state_object_schema_id(),
                refs,
                1_800_200_000 + u64::from(seq),
            ),
            connector_id: transfer_scope().connector_id,
            instance_id: None,
            zone_id: transfer_scope().zone_id,
            prev,
            seq: u64::from(seq),
            state_cbor: vec![0xa1, 0x61, b'n', seq],
            updated_at: 1_800_200_000 + u64::from(seq),
            lease_seq: 17,
            lease_object_id: lease_id,
            writer_public_key: [0; 32],
            signature: Signature::zero(),
        };
        state.sign_with(&writer).expect("signed canonical state");
        let object = stored(&state.header, &state);
        ancestry.push(object.object_id);
        objects.put(object).await.expect("persist source state");
    }
    let head = *ancestry.last().expect("source head");
    let root = ConnectorStateRoot {
        header: header(
            FcpStoreConnectorStateStore::root_schema_id(),
            vec![head],
            1_800_200_002,
        ),
        connector_id: transfer_scope().connector_id,
        instance_id: None,
        zone_id: transfer_scope().zone_id,
        model: ConnectorStateModel::SingletonWriter,
        head: Some(head),
        state_schema_version: 1,
    };
    let root = stored(&root.header, &root);
    let root_id = root.object_id;
    objects.put(root).await.expect("persist source root last");
    (root_id, ancestry)
}

fn directory_bytes(path: &StdPath) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(path)
        .expect("fixture store directory")
        .map(|entry| {
            let entry = entry.expect("store directory entry");
            assert!(entry.file_type().expect("store file type").is_file());
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).expect("store file bytes"),
            )
        })
        .collect()
}

fn pull_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            PULL_ROUTE,
            post(pull_handler).layer(axum::extract::DefaultBodyLimit::max(PULL_REQUEST_MAX_BYTES)),
        )
        .route_layer(from_fn_with_state(
            Arc::clone(&state),
            admin_auth_middleware,
        ))
        .with_state(state)
}

async fn request_pull(
    state: Arc<AppState>,
    request: &ConnectorStatePullRequest,
    authorization: Option<&str>,
    zone: Option<&str>,
) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/rpc/admin/connectors/{CONNECTOR}/state/pull"))
        .header(axum::http::header::CONTENT_TYPE, "application/json");
    if let Some(authorization) = authorization {
        builder = builder.header(axum::http::header::AUTHORIZATION, authorization);
    }
    if let Some(zone) = zone {
        builder = builder.header(ADMIN_ZONE_HEADER, zone);
    }
    pull_app(state)
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(request).expect("pull JSON")))
                .expect("admin request"),
        )
        .await
        .expect("infallible admin router")
}

async fn successful_pull(
    state: Arc<AppState>,
    request: &ConnectorStatePullRequest,
) -> ConnectorStatePullResponse {
    let response = request_pull(state, request, Some("Bearer topsecret"), Some("z:owner")).await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("bounded admin response");
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).expect("typed replica result")
}

struct LiveTransfer {
    // Keep the real canonical writer alive while the donor observes it.
    source: Arc<DurableObjectStore>,
    source_dir: PathBuf,
    replica_root: PathBuf,
    recipient: Arc<AppState>,
    recipient_writer: [u8; 32],
    request: ConnectorStatePullRequest,
    ancestry: Vec<ObjectId>,
    donor_endpoint: String,
    mesh_requests: Arc<AtomicU64>,
    shutdown: fcp_async_core::channel::watch::Sender<bool>,
    server: JoinHandle<HostResult<()>>,
    _directory: tempfile::TempDir,
}

impl LiveTransfer {
    async fn start(recipient_writer: [u8; 32]) -> Self {
        let directory = tempfile::tempdir().expect("durable transfer fixture");
        let source_dir = directory.path().join("canonical-objects");
        let replica_root = directory.path().join("host-state");
        let source = Arc::new(
            DurableObjectStore::open(DurableObjectStoreConfig::new(&source_dir))
                .expect("canonical writer"),
        );
        let (root, ancestry) = seed_source(&source).await;
        let donor_service = open_service(
            TransferConfig {
                replica_root: None,
                stores: vec![store_config(Some(source_dir.clone()), false, writer_pin())],
                grants: vec![grant(
                    ConnectorStateTransferDirection::Export,
                    "recipient",
                    root,
                )],
            },
            &private_bind(),
        )
        .expect("read-only donor alongside canonical writer");
        let recipient_service = open_service(
            recipient_config(&replica_root, root, recipient_writer),
            &private_bind(),
        )
        .expect("exclusive retained replica");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("donor listener");
        let donor_endpoint = format!("http://{}", listener.local_addr().expect("donor address"));
        let donor = Arc::new(AppState {
            connector_state_replication: Some(Arc::new(donor_service)),
            mesh: Some(Arc::new(
                MeshRouter::new(MeshRoutingSettings {
                    node_id: TailscaleNodeId::new("donor"),
                    signing_key: signing_key(0xd1),
                    peers_json: json!([
                        {
                            "node_id": "recipient",
                            "endpoint": "http://127.0.0.1:1",
                            "public_key_hex": hex::encode(signing_key(0xc1).verifying_key().to_bytes()),
                        },
                        {
                            // Mesh membership alone does not grant disclosure.
                            "node_id": "ungranted-recipient",
                            "endpoint": "http://127.0.0.1:2",
                            "public_key_hex": hex::encode(signing_key(0xc2).verifying_key().to_bytes()),
                        }
                    ])
                    .to_string(),
                    forward_timeout: Duration::from_secs(5),
                })
                .expect("authenticating donor router"),
            )),
            ..(*crate::tests::cancel_route_test_state()).clone()
        });
        let mesh_requests = Arc::new(AtomicU64::new(0));
        let observed_requests = Arc::clone(&mesh_requests);
        let app = Router::new()
            .route(
                MESH_FORWARD_ROUTE,
                post(
                    move |state: State<Arc<AppState>>, envelope: Json<MeshForwardEnvelope>| {
                        observed_requests.fetch_add(1, Ordering::SeqCst);
                        // Exercise production signature/nonce admission and export
                        // dispatch. This fixture never fabricates a signed reply.
                        mesh_forward_handler(state, envelope)
                    },
                ),
            )
            .with_state(donor);
        let (shutdown, shutdown_rx) = fcp_async_core::channel::watch::channel(false);
        let server = task::spawn(async move { serve_tcp(listener, app, shutdown_rx).await });
        let recipient = Arc::new(AppState {
            connector_state_replication: Some(Arc::new(recipient_service)),
            mesh: Some(Self::recipient_router("recipient", 0xc1, &donor_endpoint)),
            ..(*crate::tests::cancel_route_test_state()).clone()
        });
        Self {
            source,
            source_dir,
            replica_root,
            recipient,
            recipient_writer,
            request: ConnectorStatePullRequest {
                peer_node: "donor".to_owned(),
                request: ConnectorStateExportRequest {
                    grant_id: GRANT.to_owned(),
                    scope: transfer_scope(),
                    root_object_id: root,
                    limits: transfer_limits(),
                },
            },
            ancestry,
            donor_endpoint,
            mesh_requests,
            shutdown,
            server,
            _directory: directory,
        }
    }

    fn recipient_router(node: &str, key: u8, endpoint: &str) -> Arc<MeshRouter> {
        Arc::new(
            MeshRouter::new(MeshRoutingSettings {
                node_id: TailscaleNodeId::new(node),
                signing_key: signing_key(key),
                peers_json: json!([{
                    "node_id": "donor",
                    "endpoint": endpoint,
                    "public_key_hex": hex::encode(signing_key(0xd1).verifying_key().to_bytes()),
                }])
                .to_string(),
                forward_timeout: Duration::from_secs(5),
            })
            .expect("recipient mesh router"),
        )
    }

    fn replica_dir(&self) -> PathBuf {
        replica_objects_dir(&self.replica_root, &transfer_scope()).expect("replica namespace")
    }

    fn replica_reader(&self) -> Arc<FcpStoreConnectorStateStore> {
        let mut config = DurableObjectStoreConfig::new(self.replica_dir());
        config.max_bytes = STORE_QUOTA;
        config.mac_key = Some(blake3::derive_key(
            "fcp.host.connector-state-replica.wal.v1",
            object_key().as_bytes(),
        ));
        adapter(
            Arc::new(DurableObjectStore::open_read_only(config).expect("durable replica observer")),
            object_key(),
            &transfer_scope(),
            &[self.recipient_writer],
        )
    }

    async fn assert_ancestry(&self) {
        let reader = self.replica_reader();
        let (id, root) = reader
            .read_root()
            .await
            .expect("authenticated root")
            .expect("retained root");
        assert_eq!(id, self.request.request.root_object_id);
        assert_eq!(root.head, self.ancestry.last().copied());
        let chain = reader
            .read_chain(None, 8)
            .await
            .expect("authenticated complete ancestry");
        assert_eq!(
            chain.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            self.ancestry
        );
        assert_eq!(
            chain.iter().map(|(_, state)| state.seq).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(chain[1].1.prev, Some(chain[0].0));
        for (_, state) in chain {
            assert_eq!(state.writer_public_key, writer_pin());
            state
                .verify_signature_with(&signing_key(0x51).verifying_key())
                .expect("persisted writer signature");
        }
    }

    fn restart_recipient(&mut self) {
        // The admin router is per request, so replacing this sole state drops
        // every replica writer before opening the persistent namespace again.
        self.recipient = Arc::new(AppState {
            mesh: self.recipient.mesh.clone(),
            ..(*crate::tests::cancel_route_test_state()).clone()
        });
        let service = open_service(
            recipient_config(
                &self.replica_root,
                self.request.request.root_object_id,
                self.recipient_writer,
            ),
            &private_bind(),
        )
        .expect("recover retained replica after service restart");
        Arc::get_mut(&mut self.recipient)
            .expect("sole recipient state")
            .connector_state_replication = Some(Arc::new(service));
    }

    async fn stop(self) {
        self.shutdown.send(true).expect("stop donor listener");
        self.server
            .await
            .expect("donor task")
            .expect("donor shutdown");
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn exact_root_pull_uses_signed_mesh_and_retains_ancestry_across_restart() {
    let mut fixture = LiveTransfer::start(writer_pin()).await;
    let source_before = directory_bytes(&fixture.source_dir);
    let empty_replica = directory_bytes(&fixture.replica_dir());

    for (authorization, zone) in [
        (None, None),
        (Some("Bearer wrong-token"), Some("z:owner")),
        (Some("Bearer topsecret"), None),
        (Some("Bearer topsecret"), Some("z:work")),
    ] {
        let response = request_pull(
            Arc::clone(&fixture.recipient),
            &fixture.request,
            authorization,
            zone,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(
        fixture.mesh_requests.load(Ordering::SeqCst),
        0,
        "admin denial must precede all mesh work"
    );
    assert_eq!(directory_bytes(&fixture.replica_dir()), empty_replica);

    let response = successful_pull(Arc::clone(&fixture.recipient), &fixture.request).await;
    assert_eq!(
        response.root_object_id,
        fixture.request.request.root_object_id
    );
    assert_eq!(response.scope, transfer_scope());
    assert_eq!(response.object_count, 3, "root and two signed ancestors");
    assert!(response.replica_root_published);
    assert!(response.replica_only);
    assert!(response.canonical_bytes > 0);
    assert!(response.wire_bytes <= transfer_limits().max_wire_bytes);
    assert_eq!(fixture.mesh_requests.load(Ordering::SeqCst), 1);
    assert!(
        fixture.recipient.registry.inventory().await.is_empty(),
        "replication cannot launch a connector"
    );
    fixture.assert_ancestry().await;
    assert_eq!(
        directory_bytes(&fixture.source_dir),
        source_before,
        "donor must never repair or mutate the canonical store"
    );
    assert!(
        fixture
            .source
            .get(&fixture.request.request.root_object_id)
            .await
            .is_ok()
    );
    assert!(
        DurableObjectStore::open(DurableObjectStoreConfig::new(&fixture.source_dir)).is_err(),
        "donor export must preserve the canonical writer's ownership"
    );

    let retained = directory_bytes(&fixture.replica_dir());
    let mut wrong_root = fixture.request.clone();
    wrong_root.request.root_object_id = ObjectId::from_bytes([0xee; 32]);
    let mut wrong_zone = fixture.request.clone();
    wrong_zone.request.scope.zone_id = ZoneId::owner();
    let mut wrong_instance = fixture.request.clone();
    wrong_instance.request.scope.instance_id = Some(InstanceId::new());
    let mut wrong_peer = fixture.request.clone();
    wrong_peer.peer_node = "unconfigured-donor".to_owned();
    for request in [wrong_root, wrong_zone, wrong_instance, wrong_peer] {
        let response = request_pull(
            Arc::clone(&fixture.recipient),
            &request,
            Some("Bearer topsecret"),
            Some("z:owner"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(directory_bytes(&fixture.replica_dir()), retained);
    }
    assert_eq!(
        fixture.mesh_requests.load(Ordering::SeqCst),
        1,
        "local exact grant rejection must not contact a donor"
    );

    let ungranted = Arc::new(AppState {
        mesh: Some(LiveTransfer::recipient_router(
            "ungranted-recipient",
            0xc2,
            &fixture.donor_endpoint,
        )),
        ..(*fixture.recipient).clone()
    });
    let response = request_pull(
        ungranted,
        &fixture.request,
        Some("Bearer topsecret"),
        Some("z:owner"),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "an authenticated mesh member still needs its own export grant"
    );
    assert_eq!(fixture.mesh_requests.load(Ordering::SeqCst), 2);
    assert_eq!(directory_bytes(&fixture.replica_dir()), retained);

    let mut too_small = fixture.request.clone();
    too_small.request.limits.max_objects = 1;
    let response = request_pull(
        Arc::clone(&fixture.recipient),
        &too_small,
        Some("Bearer topsecret"),
        Some("z:owner"),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "incomplete ancestry is never a successful bounded export"
    );
    assert_eq!(fixture.mesh_requests.load(Ordering::SeqCst), 3);
    assert_eq!(directory_bytes(&fixture.replica_dir()), retained);

    fixture.restart_recipient();
    fixture.assert_ancestry().await;
    assert_eq!(directory_bytes(&fixture.replica_dir()), retained);
    let response = successful_pull(Arc::clone(&fixture.recipient), &fixture.request).await;
    assert!(
        !response.replica_root_published,
        "retry after restart must recognize the already retained exact root"
    );
    assert!(response.replica_only);
    assert_eq!(directory_bytes(&fixture.replica_dir()), retained);
    assert_eq!(directory_bytes(&fixture.source_dir), source_before);
    fixture.stop().await;
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn signed_mesh_reply_cannot_override_replica_writer_pins() {
    let wrong_writer = signing_key(0x52).verifying_key().to_bytes();
    let mut fixture = LiveTransfer::start(wrong_writer).await;
    let empty_replica = directory_bytes(&fixture.replica_dir());
    let source_before = directory_bytes(&fixture.source_dir);
    let response = request_pull(
        Arc::clone(&fixture.recipient),
        &fixture.request,
        Some("Bearer topsecret"),
        Some("z:owner"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        fixture.mesh_requests.load(Ordering::SeqCst),
        1,
        "validate the writer pins after a real authenticated donor response"
    );
    assert_eq!(
        directory_bytes(&fixture.replica_dir()),
        empty_replica,
        "untrusted state must not persist even before root publication"
    );
    assert!(
        fixture
            .replica_reader()
            .read_root()
            .await
            .expect("empty replica remains readable")
            .is_none()
    );
    assert_eq!(directory_bytes(&fixture.source_dir), source_before);

    // An operator may correct the pins on restart; a rejected transfer must
    // neither poison durable recovery nor install a conflicting partial root.
    fixture.recipient_writer = writer_pin();
    fixture.restart_recipient();
    let response = successful_pull(Arc::clone(&fixture.recipient), &fixture.request).await;
    assert!(response.replica_root_published);
    fixture.assert_ancestry().await;
    fixture.stop().await;
}

#[test]
fn state_transfer_refuses_public_plaintext_before_creating_replica_storage() {
    let directory = tempfile::tempdir().expect("ingress fixture");
    let replica_root = directory.path().join("must-not-be-created");
    for address in ["0.0.0.0:8750", "[::]:8750", "100.64.0.2:8750"] {
        let config = recipient_config(
            &replica_root,
            ObjectId::from_bytes([0x33; 32]),
            writer_pin(),
        );
        let error = open_service(
            config,
            &BindTarget::Tcp(address.parse().expect("public bind")),
        )
        .err()
        .expect("public plaintext listener must be rejected");
        assert!(error.to_string().contains("loopback or Unix-socket"));
        assert!(
            !replica_root.exists(),
            "ingress refusal must precede persistent side effects"
        );
    }
    assert!(require_private_ingress(&private_bind()).is_ok());
    assert!(
        require_private_ingress(&BindTarget::Tcp("[::1]:0".parse().expect("IPv6 loopback")))
            .is_ok()
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn state_transfer_refuses_remote_plaintext_even_with_a_valid_local_grant() {
    let fixture = LiveTransfer::start(writer_pin()).await;
    let empty_replica = directory_bytes(&fixture.replica_dir());
    for endpoint in [
        "http://100.64.0.2:8750",
        "http://localhost:8750",
        "http://donor.example:8750",
    ] {
        let recipient = Arc::new(AppState {
            mesh: Some(LiveTransfer::recipient_router("recipient", 0xc1, endpoint)),
            ..(*fixture.recipient).clone()
        });
        let response = request_pull(
            recipient,
            &fixture.request,
            Some("Bearer topsecret"),
            Some("z:owner"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(directory_bytes(&fixture.replica_dir()), empty_replica);
    }
    assert_eq!(fixture.mesh_requests.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}
