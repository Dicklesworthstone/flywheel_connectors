//! Consumer HTTP regressions with real capability signatures, policy checks,
//! and the production durable journal. The dormant dispatcher asserts that
//! delivery and acknowledgements never wait for a connector RPC.

use super::*;
use axum::body::Body;
use axum::http::Request;
use base64::Engine as _;
use fcp_core::{EventData, EventEnvelope, InstanceId, Principal, TrustLevel};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_host::mesh_routing::MeshRouter;
use fcp_mesh::invoke_route::MeshPeerConfig;
use fcp_mesh::peer_manifest::{
    MESH_PEER_DIRECTORY_SCHEMA, MeshPeerDirectoryPayload, SignedMeshPeerDirectory,
};
use tower::util::ServiceExt;

#[path = "native_event_mesh_tests.rs"]
mod mesh_tests;

const CONNECTOR: &str = "fcp.test.native-events:streaming:1.0.0";
const CAPABILITY: &str = "events.read";
const OPERATION: &str = "events.subscribe";
const TOPIC: &str = "test.message";
const RESOURCE: &str = "event:test.message";
const STREAM: &str = "retained-test-stream";
const REQUEST_ID: &str = "consumer-request-1";
const HOLDER: &str = "event-holder";

// Both local and relayed consumers use the production owner-signed directory
// and reload worker. A transport peer's signature is never a holder proof.
struct SignedEventMembership {
    root: std::path::PathBuf,
    owner: Ed25519SigningKey,
    payload: MeshPeerDirectoryPayload,
}

impl SignedEventMembership {
    fn new(root: std::path::PathBuf, peers: Vec<MeshPeerConfig>) -> Self {
        std::fs::create_dir(&root).unwrap();
        let now = fcp_host::mesh_routing::unix_now_ms();
        let membership = Self {
            root,
            owner: Ed25519SigningKey::generate(),
            payload: MeshPeerDirectoryPayload {
                schema_version: MESH_PEER_DIRECTORY_SCHEMA.to_owned(),
                mesh_id: "native-event-holder-tests".to_owned(),
                generation: 1,
                issued_at_ms: now.saturating_sub(1000),
                expires_at_ms: now + 300_000,
                peers,
            },
        };
        membership.publish();
        membership
    }

    fn publish(&self) {
        let document = SignedMeshPeerDirectory::sign(&self.owner, &self.payload).unwrap();
        let next = self.root.join("peers.next");
        private_write(&next, &serde_json::to_vec(&document).unwrap());
        std::fs::rename(next, self.root.join("peers.json")).unwrap();
    }

    fn router(&self, node_id: &str, key: &Ed25519SigningKey) -> MeshRouter {
        use fcp_host::mesh_routing::{
            MESH_DIRECTORY_ID_ENV, MESH_DIRECTORY_OWNER_KEYS_ENV, MESH_DIRECTORY_STATE_ENV,
            MESH_NODE_ID_ENV, MESH_PEERS_FILE_ENV, MESH_SIGNING_KEY_FILE_ENV,
        };
        let directory = self.root.join(node_id);
        std::fs::create_dir(&directory).unwrap();
        let key_path = directory.join("node.key");
        private_write(&key_path, hex::encode(key.to_bytes()).as_bytes());
        let config = HashMap::from([
            (MESH_NODE_ID_ENV, node_id.to_owned()),
            (MESH_SIGNING_KEY_FILE_ENV, key_path.display().to_string()),
            (MESH_DIRECTORY_ID_ENV, self.payload.mesh_id.clone()),
            (
                MESH_DIRECTORY_OWNER_KEYS_ENV,
                json!([hex::encode(self.owner.verifying_key().to_bytes())]).to_string(),
            ),
            (
                MESH_DIRECTORY_STATE_ENV,
                directory.join("membership").display().to_string(),
            ),
            (
                MESH_PEERS_FILE_ENV,
                self.root.join("peers.json").display().to_string(),
            ),
        ]);
        MeshRouter::from_lookup(|name| config.get(name).cloned())
            .unwrap()
            .unwrap()
    }

    async fn withdraw(&mut self, node: &str, router: &MeshRouter) {
        self.payload.generation += 1;
        self.payload.peers.retain(|peer| peer.node_id != node);
        self.publish();
        let deadline = Instant::now() + Duration::from_secs(5);
        while router
            .directory()
            .peer(&TailscaleNodeId::new(node))
            .is_some()
        {
            assert!(
                Instant::now() < deadline,
                "signed membership did not reload"
            );
            fcp_async_core::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn private_write(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn member(node_id: &str, endpoint: &str, key: &Ed25519SigningKey) -> MeshPeerConfig {
    MeshPeerConfig {
        node_id: node_id.to_owned(),
        endpoint: endpoint.to_owned(),
        public_key_hex: hex::encode(key.verifying_key().to_bytes()),
    }
}

struct Fixture {
    host: Arc<AppState>,
    journal: Arc<NativeEventJournal>,
    key: fcp_crypto::ed25519::Ed25519SigningKey,
    calls: Arc<AtomicU64>,
    _directory: tempfile::TempDir,
}

fn instance() -> InstanceId {
    "inst_native_http_fixture".parse().unwrap()
}

fn owner_binding() -> NativeEventBinding {
    NativeEventBinding {
        principal: "agent:alice".to_owned(),
        connector_id: ConnectorId::from_static(CONNECTOR),
        zone_id: ZoneId::work(),
        topic: TOPIC.to_owned(),
    }
}

fn event() -> EventEnvelope {
    EventEnvelope::new(
        TOPIC,
        EventData::new(
            ConnectorId::from_static(CONNECTOR),
            instance(),
            ZoneId::work(),
            Principal {
                kind: "provider_user".to_owned(),
                id: "source-1".to_owned(),
                trust: TrustLevel::Untrusted,
                display: None,
            },
            json!({"text":"private-native-event-sentinel"}),
        ),
    )
    .with_seq(7)
    .with_cursor("provider-cursor-7")
    .requiring_ack()
}

async fn fixture() -> Fixture {
    let calls = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&calls);
    let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(4);
    let runner_task = task::spawn(async move {
        while let Some(request) = runner_rx.recv().await {
            observed.fetch_add(1, Ordering::SeqCst);
            let _ = request.response_tx.send(Err(std::io::Error::other(
                "consumer routes must not issue connector RPCs",
            )));
        }
    });
    let connector = crate::tests::dispatcher_test_connector(CONNECTOR, runner_tx, runner_task);
    let mut config = crate::tests::dispatcher_test_config(CONNECTOR);
    config.allowed_operations = vec![OPERATION.to_owned()];
    config.enforce_empty_allow_lists = true;
    let registry = crate::tests::dispatcher_registry_with_connector(CONNECTOR, connector, config);
    {
        let mut state = registry.state.write().await;
        let entry = state
            .connectors
            .get_mut(&ConnectorId::from_static(CONNECTOR))
            .unwrap();
        entry.manifest_constraints.event_authorities.insert(
            TOPIC.to_owned(),
            fcp_manifest::EventSection {
                description: "Private fixture messages".to_owned(),
                streaming: true,
                replay: false,
                topic: Some(TOPIC.to_owned()),
                requires_ack: true,
                capability: Some(CAPABILITY.to_owned()),
                subscribe_operation: Some(OPERATION.to_owned()),
                resource_uri: Some(RESOURCE.to_owned()),
                schema: None,
            },
        );
    }
    let key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
    let host = crate::tests::dispatcher_app_state(
        registry,
        Arc::new(HostAdminStateStore::new()),
        Some(key.verifying_key()),
        HashMap::from([(ZoneId::work(), host_runtime_policy(ZoneId::work()))]),
    );
    let directory = tempfile::tempdir().unwrap();
    let journal = Arc::new(NativeEventJournal::open(directory.path().join("events.json")).unwrap());
    journal
        .register(STREAM, owner_binding(), 1, instance())
        .unwrap();
    journal
        .ingest(
            STREAM,
            &ConnectorId::from_static(CONNECTOR),
            &ZoneId::work(),
            event(),
        )
        .unwrap();
    let host = Arc::new(AppState {
        native_events: Arc::new(EventService::new(Some(Arc::clone(&journal)))),
        ..(*host).clone()
    });
    Fixture {
        host,
        journal,
        key,
        calls,
        _directory: directory,
    }
}

fn issuance(principal: &str) -> fcp_host::CapabilityIssuanceRequest {
    fcp_host::CapabilityIssuanceRequest {
        connector_id: CONNECTOR.to_owned(),
        capability_id: CAPABILITY.to_owned(),
        zone_id: ZoneId::work().to_string(),
        instance_id: Some(instance()),
        principal_id: principal.to_owned(),
        operations: vec![OPERATION.to_owned()],
        ttl_secs: 3600,
        not_before_delay_secs: None,
        holder_node: None,
        max_delegation_depth: 0,
        resource_allow: vec![RESOURCE.to_owned()],
        resource_deny: Vec::new(),
        max_calls: None,
        max_bytes: None,
        credential_allow: Vec::new(),
        dry_run: false,
    }
}

async fn issue(
    fixture: &Fixture,
    request: fcp_host::CapabilityIssuanceRequest,
) -> (fcp_core::CapabilityToken, String) {
    let issued = fixture
        .host
        .lifecycle
        .issue_capability_token(&request, &fixture.key)
        .await
        .unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(issued.token_cbor_b64.unwrap())
        .unwrap();
    (
        fcp_core::CapabilityToken::from_raw(
            fcp_crypto::cose::CoseToken::from_cbor(&bytes).unwrap(),
        ),
        issued.token_id,
    )
}

fn auth(token: &fcp_core::CapabilityToken) -> Value {
    json!({
        "request_id":REQUEST_ID,
        "connector_id":CONNECTOR,
        "zone_id":ZoneId::work(),
        "topic":TOPIC,
        "capability_token":token,
    })
}

fn holder_auth(token: &fcp_core::CapabilityToken, key: &Ed25519SigningKey) -> Value {
    let claims = token.raw().claims_unverified().unwrap();
    let proof = fcp_core::HolderProof::new(
        key.sign(&fcp_core::HolderProof::signable_bytes(
            &RequestId::new(REQUEST_ID),
            &OperationId::from_static(OPERATION),
            claims.get_jti().unwrap(),
        ))
        .to_bytes(),
        TailscaleNodeId::new(claims.get_holder_node().unwrap()),
    );
    let mut auth = auth(token);
    auth["holder_proof"] = json!(proof);
    auth
}

fn install_holder_membership(fixture: &mut Fixture) -> (SignedEventMembership, Ed25519SigningKey) {
    let local = Ed25519SigningKey::generate();
    let holder = Ed25519SigningKey::generate();
    let membership = SignedEventMembership::new(
        fixture._directory.path().join("holder-membership"),
        vec![
            member("event-local", "http://127.0.0.1:19001", &local),
            member(HOLDER, "http://127.0.0.1:19002", &holder),
        ],
    );
    fixture.host = Arc::new(AppState {
        mesh: Some(Arc::new(membership.router("event-local", &local))),
        ..(*fixture.host).clone()
    });
    (membership, holder)
}

fn acknowledgement() -> EventAck {
    EventAck::new(TOPIC, vec![7]).with_cursors(vec!["provider-cursor-7".to_owned()])
}

fn app(fixture: &Fixture) -> Router {
    routes(Arc::clone(&fixture.host)).with_state(Arc::clone(&fixture.host))
}

async fn send(app: Router, path: &str, body: Value) -> (StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        // A caller-asserted owner header must not substitute for signed identity.
        .header("x-principal", "agent:alice")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn signed_consumer_polls_and_commits_ack_without_connector_rpc() {
    let fixture = fixture().await;
    let (token, _) = issue(&fixture, issuance("agent:alice")).await;
    let app = app(&fixture);
    for _ in 0..2 {
        let (status, body) = send(
            app.clone(),
            "/rpc/streams/poll",
            json!({"auth":auth(&token),"stream_id":STREAM,"limit":1}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let batch: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(batch["events"][0]["seq"], 7);
        assert_eq!(batch["events"][0]["cursor"], "provider-cursor-7");
        assert_eq!(batch["stream"]["pending_events"], 1);
        assert_eq!(batch["stream"]["durable"], true);
    }
    for _ in 0..2 {
        let (status, body) = send(
            app.clone(),
            "/rpc/streams/ack",
            json!({"auth":auth(&token),"stream_id":STREAM,"ack":acknowledgement()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let ack: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(ack["acknowledged"], true);
        assert_eq!(
            ack["upstream_notified"], false,
            "offline source is explicit"
        );
        assert_eq!(ack["stream"]["pending_events"], 0);
        assert_eq!(ack["stream"]["acknowledged_events"], 1);
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        fixture
            .journal
            .ingest(
                STREAM,
                &ConnectorId::from_static(CONNECTOR),
                &ZoneId::work(),
                event()
            )
            .unwrap(),
        NativeEventAdmission::AlreadyAcknowledged(_)
    ));
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn signed_holder_reads_acknowledges_and_closes_without_connector_rpc() {
    let mut fixture = fixture().await;
    let (_membership, holder) = install_holder_membership(&mut fixture);
    let mut request = issuance("agent:alice");
    request.holder_node = Some(HOLDER.to_owned());
    let (token, _) = issue(&fixture, request).await;
    let authority = holder_auth(&token, &holder);
    let app = app(&fixture);
    let (status, body) = send(
        app.clone(),
        "/rpc/streams/poll",
        json!({"auth":authority,"stream_id":STREAM}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("private-native-event-sentinel"));
    for route in ["ack", "close"] {
        let mut request = json!({"auth":authority,"stream_id":STREAM});
        if route == "ack" {
            request["ack"] = json!(acknowledgement());
        }
        let (status, body) = send(app.clone(), &format!("/rpc/streams/{route}"), request).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!body.contains("capability_token"));
        assert!(!body.contains("holder_proof"));
    }
    let retained = fixture.journal.describe(STREAM).unwrap();
    assert_eq!(retained.pending_events, 0);
    assert_eq!(retained.acknowledged_events, 1);
    assert!(retained.closed);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn holder_proof_binds_request_subscription_operation_token_and_member_key() {
    let mut fixture = fixture().await;
    let (_membership, holder) = install_holder_membership(&mut fixture);
    let mut request = issuance("agent:alice");
    request.holder_node = Some(HOLDER.to_owned());
    let (token, _) = issue(&fixture, request.clone()).await;
    let (renewed, _) = issue(&fixture, request).await;
    let valid = holder_auth(&token, &holder);
    let mut wrong_request = valid.clone();
    wrong_request["request_id"] = json!("different-consumer-request");
    let mut wrong_operation = valid.clone();
    wrong_operation["holder_proof"] = json!(fcp_core::HolderProof::new(
        holder
            .sign(&fcp_core::HolderProof::signable_bytes(
                &RequestId::new(REQUEST_ID),
                &OperationId::from_static("events.other"),
                token.raw().claims_unverified().unwrap().get_jti().unwrap(),
            ))
            .to_bytes(),
        TailscaleNodeId::new(HOLDER),
    ));
    let mut wrong_jti = valid.clone();
    wrong_jti["capability_token"] = json!(renewed);
    let mut wrong_node = valid.clone();
    wrong_node["holder_proof"]["holder_node"] = json!("event-local");
    let wrong_key = holder_auth(&token, &Ed25519SigningKey::generate());
    fixture
        .journal
        .poll(STREAM, &owner_binding(), &instance(), 1)
        .unwrap();
    let app = app(&fixture);
    for authority in [
        auth(&token),
        wrong_request,
        wrong_operation,
        wrong_jti,
        wrong_node,
        wrong_key,
    ] {
        for route in ["poll", "ack", "close"] {
            let mut request = json!({"auth":authority,"stream_id":STREAM});
            if route == "ack" {
                request["ack"] = json!(acknowledgement());
            }
            let (status, body) = send(app.clone(), &format!("/rpc/streams/{route}"), request).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
            assert!(!body.contains("private-native-event-sentinel"));
            assert!(
                !body.contains("signature"),
                "holder proof errors are redacted"
            );
        }
    }
    let retained = fixture.journal.describe(STREAM).unwrap();
    assert_eq!(retained.pending_events, 1);
    assert_eq!(retained.acknowledged_events, 0);
    assert!(!retained.closed);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn owner_membership_withdrawal_blocks_holder_reads_and_custody_changes() {
    let mut fixture = fixture().await;
    let (mut membership, holder) = install_holder_membership(&mut fixture);
    let mut request = issuance("agent:alice");
    request.holder_node = Some(HOLDER.to_owned());
    let (token, _) = issue(&fixture, request).await;
    let authority: StreamAuthority = serde_json::from_value(holder_auth(&token, &holder)).unwrap();
    let admission = fixture
        .host
        .native_events
        .authorize(&fixture.host, &authority)
        .await
        .unwrap();
    fixture
        .journal
        .poll(STREAM, &owner_binding(), &instance(), 1)
        .unwrap();
    membership
        .withdraw(HOLDER, fixture.host.mesh.as_ref().unwrap())
        .await;
    assert!(
        fixture
            .host
            .native_events
            .authorize_retained(&fixture.host, &authority, &admission, STREAM,)
            .is_err(),
        "already admitted authority must refresh after a wait"
    );
    let app = app(&fixture);
    for route in ["poll", "ack", "close"] {
        let mut request = json!({"auth":authority,"stream_id":STREAM});
        if route == "ack" {
            request["ack"] = json!(acknowledgement());
        }
        let (status, body) = send(app.clone(), &format!("/rpc/streams/{route}"), request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
        assert!(!body.contains("private-native-event-sentinel"));
    }
    let retained = fixture.journal.describe(STREAM).unwrap();
    assert_eq!(retained.pending_events, 1);
    assert_eq!(retained.acknowledged_events, 0);
    assert!(!retained.closed);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn holder_withdrawal_during_native_rpc_queue_wait_blocks_stream_open() {
    let mut fixture = fixture().await;
    let (mut membership, holder) = install_holder_membership(&mut fixture);
    let mut request = issuance("agent:alice");
    request.holder_node = Some(HOLDER.to_owned());
    let (token, _) = issue(&fixture, request).await;
    let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(4);
    let (queued_tx, queued_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let selected = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&selected);
    let runner_task = task::spawn(async move {
        let call = runner_rx.recv().await.unwrap();
        assert_eq!(call.method, "health");
        queued_tx.send(()).unwrap();
        release_rx.await.unwrap();
        if call.rpc.try_begin() {
            observed.fetch_add(1, Ordering::SeqCst);
            let _ = call.response_tx.send(Err(std::io::Error::other(
                "withdrawn holder must not reach the native process",
            )));
        } else {
            let _ = call.response_tx.send(Err(call.rpc.stop_error()));
        }
    });
    fixture
        .host
        .registry
        .state
        .write()
        .await
        .connectors
        .get_mut(&ConnectorId::from_static(CONNECTOR))
        .unwrap()
        .connector = ConnectorRuntime::Native(crate::tests::dispatcher_test_connector(
        CONNECTOR,
        runner_tx,
        runner_task,
    ));
    let app = app(&fixture);
    let request = json!({"auth":holder_auth(&token, &holder),"stream_id":STREAM});
    let pending = task::spawn(async move { send(app, "/rpc/streams/open", request).await });
    fcp_async_core::time::timeout(Duration::from_secs(5), queued_rx)
        .await
        .unwrap()
        .unwrap();
    membership
        .withdraw(HOLDER, fixture.host.mesh.as_ref().unwrap())
        .await;
    release_tx.send(()).unwrap();
    let (status, body) = pending.await.unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(selected.load(Ordering::SeqCst), 0);
    let retained = fixture.journal.describe(STREAM).unwrap();
    assert_eq!(retained.pending_events, 1);
    assert_eq!(retained.acknowledged_events, 0);
    assert!(!retained.closed);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn another_signed_subject_cannot_read_ack_or_close_retained_consumer_stream() {
    let fixture = fixture().await;
    let (bob, _) = issue(&fixture, issuance("agent:bob")).await;
    let app = app(&fixture);
    for (route, body) in [
        ("poll", json!({"auth":auth(&bob),"stream_id":STREAM})),
        (
            "ack",
            json!({"auth":auth(&bob),"stream_id":STREAM,"ack":acknowledgement()}),
        ),
        ("close", json!({"auth":auth(&bob),"stream_id":STREAM})),
    ] {
        let (status, body) = send(app.clone(), &format!("/rpc/streams/{route}"), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(!body.contains("private-native-event-sentinel"));
    }
    let retained = fixture.journal.describe(STREAM).unwrap();
    assert_eq!(retained.pending_events, 1);
    assert_eq!(retained.acknowledged_events, 0);
    assert!(!retained.closed);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wrong_grant_zone_resource_holder_or_signature_cannot_read_events() {
    let fixture = fixture().await;
    let mut wrong_capability = issuance("agent:alice");
    wrong_capability.capability_id = "events.write".to_owned();
    let mut wrong_operation = issuance("agent:alice");
    wrong_operation.operations = vec!["events.other".to_owned()];
    let mut wrong_zone = issuance("agent:alice");
    wrong_zone.zone_id = ZoneId::owner().to_string();
    let mut narrower_resource = issuance("agent:alice");
    narrower_resource.resource_allow = vec!["telegram:chat:123".to_owned()];
    let mut holder_bound = issuance("agent:alice");
    holder_bound.holder_node = Some("node:holder".to_owned());
    let mut future = issuance("agent:alice");
    future.not_before_delay_secs = Some(600);
    let mut tokens = Vec::new();
    for request in [
        wrong_capability,
        wrong_operation,
        wrong_zone,
        narrower_resource,
        holder_bound,
        future,
    ] {
        tokens.push(issue(&fixture, request).await.0);
    }
    let other_fixture = self::fixture().await;
    tokens.push(issue(&other_fixture, issuance("agent:alice")).await.0);
    let app = app(&fixture);
    for token in tokens {
        let (status, body) = send(
            app.clone(),
            "/rpc/streams/poll",
            json!({"auth":auth(&token),"stream_id":STREAM}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(!body.contains("private-native-event-sentinel"));
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.journal.describe(STREAM).unwrap().pending_events, 1);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn persisted_revocation_blocks_poll_and_ack_before_custody_changes() {
    let fixture = fixture().await;
    let (token, token_id) = issue(&fixture, issuance("agent:alice")).await;
    fixture
        .journal
        .poll(STREAM, &owner_binding(), &instance(), 1)
        .unwrap();
    fixture
        .host
        .lifecycle
        .revoke_token(&fcp_host::TokenRevocationRequest {
            token_id,
            reason: Some("event consumer revoked".to_owned()),
        })
        .await
        .unwrap();
    let app = app(&fixture);
    for (route, body) in [
        ("poll", json!({"auth":auth(&token),"stream_id":STREAM})),
        (
            "ack",
            json!({"auth":auth(&token),"stream_id":STREAM,"ack":acknowledgement()}),
        ),
    ] {
        let (status, body) = send(app.clone(), &format!("/rpc/streams/{route}"), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
    assert_eq!(fixture.journal.describe(STREAM).unwrap().pending_events, 1);
    assert_eq!(
        fixture
            .journal
            .describe(STREAM)
            .unwrap()
            .acknowledged_events,
        0
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn pinned_manifest_and_current_zone_policy_gate_every_consumer_read() {
    let fixture = fixture().await;
    let (token, _) = issue(&fixture, issuance("agent:alice")).await;
    let app = app(&fixture);
    fixture.host.zone_policies.write().await.clear();
    let request = json!({"auth":auth(&token),"stream_id":STREAM});
    let (status, body) = send(app.clone(), "/rpc/streams/poll", request.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    fixture
        .host
        .zone_policies
        .write()
        .await
        .insert(ZoneId::work(), host_runtime_policy(ZoneId::work()));
    {
        let mut registry = fixture.host.registry.state.write().await;
        registry
            .connectors
            .get_mut(&ConnectorId::from_static(CONNECTOR))
            .unwrap()
            .manifest_constraints
            .event_authorities
            .clear();
    }
    let (status, body) = send(app.clone(), "/rpc/streams/poll", request.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("manifest"));
    {
        let mut registry = fixture.host.registry.state.write().await;
        registry
            .connectors
            .get_mut(&ConnectorId::from_static(CONNECTOR))
            .unwrap()
            .config
            .allowed_zones
            .clear();
    }
    let (status, body) = send(app, "/rpc/streams/poll", request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.journal.describe(STREAM).unwrap().pending_events, 1);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn missing_capability_and_oversized_body_never_reach_custody_or_connector() {
    let fixture = fixture().await;
    let (token, _) = issue(&fixture, issuance("agent:alice")).await;
    let app = app(&fixture);
    let mut no_token = auth(&token);
    no_token.as_object_mut().unwrap().remove("capability_token");
    let (status, _) = send(
        app.clone(),
        "/rpc/streams/poll",
        json!({"auth":no_token,"stream_id":STREAM}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = send(
        app,
        "/rpc/streams/poll",
        json!({
            "auth":auth(&token),"stream_id":"x".repeat(REQUEST_BYTES + 1),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.journal.describe(STREAM).unwrap().pending_events, 1);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn instance_bound_consumer_token_is_checked_against_durable_current_instance() {
    let fixture = fixture().await;
    let (original, _) = issue(&fixture, issuance("agent:alice")).await;
    let replacement = InstanceId::new();
    let mut replacement_request = issuance("agent:alice");
    replacement_request.instance_id = Some(replacement.clone());
    let (replacement_token, _) = issue(&fixture, replacement_request).await;
    let app = app(&fixture);
    let read = |token: &fcp_core::CapabilityToken| json!({"auth":auth(token),"stream_id":STREAM});
    let mut unbound_request = issuance("agent:alice");
    unbound_request.instance_id = None;
    let (unbound, _) = issue(&fixture, unbound_request).await;
    let (status, body) = send(app.clone(), "/rpc/streams/poll", read(&unbound)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(app.clone(), "/rpc/streams/poll", read(&original)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(app.clone(), "/rpc/streams/poll", read(&replacement_token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    fixture
        .journal
        .register(STREAM, owner_binding(), 1, replacement)
        .unwrap();
    let (status, body) = send(app.clone(), "/rpc/streams/poll", read(&original)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(app, "/rpc/streams/poll", read(&replacement_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let replay: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        replay["events"][0]["data"]["instance_id"],
        instance().as_str()
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}
