//! Two-host stream delivery through the production signed relay and journal.

use super::*;
use axum::response::IntoResponse;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_host::mesh_routing::{MESH_FORWARD_ROUTE, MeshRouter, MeshRoutingSettings, unix_now_ms};
use fcp_mesh::invoke_route::{MeshForwardBody, MeshForwardEnvelope};

const EXECUTOR: &str = "event-executor";
const ORIGIN: &str = "event-origin";
const DROP_OPEN_REPLY: u64 = 1;
const DROP_ACK_REPLY: u64 = 2;
const WRONG_SIGNED_EXECUTOR: u64 = 4;

struct MeshFixture {
    origin: Arc<AppState>,
    executor: Arc<AppState>,
    origin_key: Ed25519SigningKey,
    faults: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    shutdown: fcp_async_core::channel::watch::Sender<bool>,
    server: JoinHandle<HostResult<()>>,
}

impl MeshFixture {
    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        self.server.await.unwrap().unwrap();
    }
}

async fn mesh_fixture(fixture: &Fixture) -> MeshFixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let origin_key = Ed25519SigningKey::from_bytes(&[41; 32]).unwrap();
    let executor_key = Ed25519SigningKey::from_bytes(&[42; 32]).unwrap();
    let origin_router = Arc::new(
        MeshRouter::new(MeshRoutingSettings {
            node_id: TailscaleNodeId::new(ORIGIN),
            signing_key: Ed25519SigningKey::from_bytes(&origin_key.to_bytes()).unwrap(),
            peers_json: json!([{
                "node_id":EXECUTOR, "endpoint":endpoint,
                "public_key_hex":hex::encode(executor_key.verifying_key().to_bytes()),
            }])
            .to_string(),
            forward_timeout: Duration::from_secs(5),
        })
        .unwrap(),
    );
    let executor_router = Arc::new(
        MeshRouter::new(MeshRoutingSettings {
            node_id: TailscaleNodeId::new(EXECUTOR),
            signing_key: executor_key,
            peers_json: json!([{
                "node_id":ORIGIN, "endpoint":"http://127.0.0.1:1",
                "public_key_hex":hex::encode(origin_key.verifying_key().to_bytes()),
            }])
            .to_string(),
            forward_timeout: Duration::from_secs(5),
        })
        .unwrap(),
    );
    let empty = crate::tests::cancel_route_test_state();
    let origin = Arc::new(AppState {
        mesh: Some(origin_router),
        ..(*empty).clone()
    });
    let executor = Arc::new(AppState {
        mesh: Some(executor_router),
        ..(*fixture.host).clone()
    });
    let faults = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let observed_faults = Arc::clone(&faults);
    let observed_requests = Arc::clone(&received);
    let app = Router::new()
        .route(
            MESH_FORWARD_ROUTE,
            post(
                move |state: State<Arc<AppState>>, envelope: Json<MeshForwardEnvelope>| {
                    let faults = Arc::clone(&observed_faults);
                    let received = Arc::clone(&observed_requests);
                    async move {
                        received.fetch_add(1, Ordering::SeqCst);
                        let fault = match &envelope.0.body {
                            MeshForwardBody::StreamOpen { .. } => DROP_OPEN_REPLY,
                            MeshForwardBody::StreamAck { .. } => DROP_ACK_REPLY,
                            _ => 0,
                        };
                        let request = envelope.0.clone();
                        let host = Arc::clone(&state.0);
                        let result = crate::mesh_forward_handler(state, envelope).await;
                        if fault != 0 && faults.fetch_and(!fault, Ordering::SeqCst) & fault != 0 {
                            // Execution and durable custody completed; an intermediary
                            // loses the authenticated reply. It cannot prove rollback.
                            return StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        if faults.fetch_and(!WRONG_SIGNED_EXECUTOR, Ordering::SeqCst)
                            & WRONG_SIGNED_EXECUTOR
                            != 0
                        {
                            let Json(reply) = result.unwrap();
                            let mut body: Value = serde_json::from_str(&reply.body_json).unwrap();
                            body["executor_node"] = json!("another-executor");
                            return Json(host.mesh.as_ref().unwrap().sign_reply(
                                &request,
                                reply.status,
                                body.to_string(),
                            ))
                            .into_response();
                        }
                        result.into_response()
                    }
                },
            ),
        )
        .with_state(Arc::clone(&executor));
    let (shutdown, shutdown_rx) = fcp_async_core::channel::watch::channel(false);
    let server = task::spawn(async move { crate::serve_tcp(listener, app, shutdown_rx).await });
    MeshFixture {
        origin,
        executor,
        origin_key,
        faults,
        received,
        shutdown,
        server,
    }
}

fn relay_app(mesh: &MeshFixture) -> Router {
    routes(Arc::clone(&mesh.origin)).with_state(Arc::clone(&mesh.origin))
}

fn pinned(token: &fcp_core::CapabilityToken) -> Value {
    json!({"auth":auth(token),"executor_node":EXECUTOR,"stream_id":STREAM})
}

async fn install_native_source(fixture: &mut Fixture) {
    // Fixed JSON replies keep the fixture independent of a system Python or
    // JSON executable. All requests still traverse the production dispatcher,
    // continuous stdout reader and native ACK writer.
    let script = r#"
IFS= read -r request || exit 1
case "$request" in *'"method":"health"'*) ;; *) exit 2 ;; esac
printf '%s\n' "$HEALTH_REPLY"
IFS= read -r request || exit 1
case "$request" in *'"method":"subscribe"'*) ;; *) exit 3 ;; esac
printf '{"jsonrpc":"2.0","id":"0:1","result":%s}\n' "$SUBSCRIBE_RESULT"
printf '%s\n' "$PROVIDER_EVENT"
sequence=2
while IFS= read -r request; do
    case "$request" in
      *'"method":"subscribe"'*)
        printf '{"jsonrpc":"2.0","id":"0:%s","result":%s}\n' "$sequence" "$SUBSCRIBE_RESULT"
        sequence=$((sequence + 1)) ;;
      *'"method":"ack"'*|*'"method":"stream_close"'*) ;;
      *) exit 4 ;;
    esac
done
"#;
    let env = BTreeMap::from([
        (
            "HEALTH_REPLY".to_owned(),
            json!({
                "jsonrpc":"2.0", "id":"0:0", "result":{
                    "status":{"state":"ready"}, "uptime_ms":0,
                    "details":{"configured":true,"handshaken":true,"instance_id":instance()},
                },
            })
            .to_string(),
        ),
        (
            "SUBSCRIBE_RESULT".to_owned(),
            json!({
                "type":"response", "id":STREAM,
                "result":{"confirmed_topics":[TOPIC],"replay_supported":true},
            })
            .to_string(),
        ),
        (
            "PROVIDER_EVENT".to_owned(),
            json!({
                "jsonrpc":"2.0", "method":"event",
                "params":{"stream_id":STREAM,"event":event()},
            })
            .to_string(),
        ),
    ]);
    let runner =
        ConnectorProcessRunner::spawn("/bin/sh", &["-c".to_owned(), script.to_owned()], &env)
            .await
            .unwrap();
    let transport = runner.event_transport.clone();
    let (tx, rx) = mpsc::channel(CONNECTOR_RPC_QUEUE_CAPACITY);
    let task = task::spawn(native_rpc::run_dispatcher(runner, rx));
    let mut connector = crate::tests::dispatcher_test_connector(CONNECTOR, tx, task);
    Arc::get_mut(&mut connector).unwrap().event_transport = Some(transport);
    fixture
        .host
        .registry
        .state
        .write()
        .await
        .connectors
        .get_mut(&ConnectorId::from_static(CONNECTOR))
        .unwrap()
        .connector = ConnectorRuntime::Native(connector);
    let journal = Arc::new(
        NativeEventJournal::open(fixture._directory.path().join("native-source.sqlite")).unwrap(),
    );
    fixture.host = Arc::new(AppState {
        native_events: Arc::new(EventService::new(Some(Arc::clone(&journal)))),
        ..(*fixture.host).clone()
    });
    fixture.journal = journal;
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn remote_open_resume_poll_ack_and_close_preserve_custody_after_lost_replies() {
    let mut fixture = fixture().await;
    install_native_source(&mut fixture).await;
    let (alice, _) = issue(&fixture, issuance("agent:alice")).await;
    let mesh = mesh_fixture(&fixture).await;
    assert!(
        mesh.origin
            .registry
            .state
            .read()
            .await
            .connectors
            .is_empty()
    );
    assert!(mesh.origin.native_events.journal.is_none());
    assert!(mesh.origin.capability_verifying_key.is_none());
    let app = relay_app(&mesh);
    mesh.faults
        .store(DROP_OPEN_REPLY | DROP_ACK_REPLY, Ordering::SeqCst);
    let open = pinned(&alice);
    let (status, _) = send(app.clone(), "/rpc/streams/open", open.clone()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        mesh.received.load(Ordering::SeqCst),
        1,
        "uncertain open must not be retried automatically"
    );
    let (status, body) = send(app.clone(), "/rpc/streams/open", open).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let opened: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(opened["executor_node"], EXECUTOR);
    assert_eq!(opened["stream"]["stream_id"], STREAM);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let (status, body) = send(app.clone(), "/rpc/streams/poll", pinned(&alice)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let batch: Value = serde_json::from_str(&body).unwrap();
        if !batch["events"].as_array().unwrap().is_empty() {
            assert_eq!(batch["events"][0]["cursor"], "provider-cursor-7");
            assert_eq!(batch["events"][0]["seq"], 7);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "native source did not reach executor custody"
        );
        fcp_async_core::time::sleep(Duration::from_millis(10)).await;
    }
    let mut ack = pinned(&alice);
    ack["ack"] = json!(acknowledgement());
    let before_ack = mesh.received.load(Ordering::SeqCst);
    let (status, _) = send(app.clone(), "/rpc/streams/ack", ack.clone()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(mesh.received.load(Ordering::SeqCst), before_ack + 1);
    assert_eq!(fixture.journal.describe(STREAM).unwrap().pending_events, 0);
    assert_eq!(
        fixture
            .journal
            .describe(STREAM)
            .unwrap()
            .acknowledged_events,
        1
    );
    let (status, body) = send(app.clone(), "/rpc/streams/ack", ack).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let receipt: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(receipt["upstream_notified"], true);
    assert_eq!(receipt["stream"]["acknowledged_events"], 1);
    let (status, body) = send(app, "/rpc/streams/close", pinned(&alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let closed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(closed["stream"]["closed"], true);
    assert_eq!(closed["executor_node"], EXECUTOR);
    mesh.stop().await;
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn remote_consumer_still_needs_current_scope_owner_and_instance_authority() {
    let fixture = fixture().await;
    let (alice, token_id) = issue(&fixture, issuance("agent:alice")).await;
    let (bob, _) = issue(&fixture, issuance("agent:bob")).await;
    let mesh = mesh_fixture(&fixture).await;
    let app = relay_app(&mesh);
    for method in ["poll", "ack", "close"] {
        let mut body = pinned(&bob);
        if method == "ack" {
            body["ack"] = json!(acknowledgement());
        }
        let (status, body) = send(app.clone(), &format!("/rpc/streams/{method}"), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(!body.contains("private-native-event-sentinel"));
    }
    let (status, body) = send(app.clone(), "/rpc/streams/poll", pinned(&alice)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    fixture
        .host
        .lifecycle
        .revoke_token(&fcp_host::TokenRevocationRequest {
            token_id,
            reason: None,
        })
        .await
        .unwrap();
    for method in ["poll", "ack", "close"] {
        let mut body = pinned(&alice);
        if method == "ack" {
            body["ack"] = json!(acknowledgement());
        }
        let (status, body) = send(app.clone(), &format!("/rpc/streams/{method}"), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let retained = fixture.journal.describe(STREAM).unwrap();
    assert_eq!(retained.pending_events, 1);
    assert_eq!(retained.acknowledged_events, 0);
    assert!(!retained.closed);
    mesh.stop().await;
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn peer_signature_replay_and_executor_pin_are_checked_before_stream_execution() {
    let fixture = fixture().await;
    let (alice, _) = issue(&fixture, issuance("agent:alice")).await;
    let mesh = mesh_fixture(&fixture).await;
    let signed = |body: Value| {
        MeshForwardEnvelope::sign(
            &mesh.origin_key,
            TailscaleNodeId::new(ORIGIN),
            TailscaleNodeId::new(EXECUTOR),
            unix_now_ms(),
            MeshForwardBody::StreamPoll {
                request_json: body.to_string(),
            },
        )
        .unwrap()
    };
    let envelope = signed(pinned(&alice));
    let mut forged = envelope.clone();
    forged.body = MeshForwardBody::StreamClose {
        request_json: pinned(&alice).to_string(),
    };
    let rejected = crate::mesh_forward_handler(State(Arc::clone(&mesh.executor)), Json(forged))
        .await
        .unwrap_err();
    assert_eq!(rejected.0, StatusCode::UNAUTHORIZED);
    let Json(reply) =
        crate::mesh_forward_handler(State(Arc::clone(&mesh.executor)), Json(envelope.clone()))
            .await
            .unwrap();
    assert_eq!(reply.status, 200);
    let rejected = crate::mesh_forward_handler(State(Arc::clone(&mesh.executor)), Json(envelope))
        .await
        .unwrap_err();
    assert_eq!(rejected.0, StatusCode::CONFLICT);
    for (pin, expected) in [(Some("third-node"), 421), (None, 400)] {
        let mut body = pinned(&alice);
        if let Some(pin) = pin {
            body["executor_node"] = json!(pin);
        } else {
            body.as_object_mut().unwrap().remove("executor_node");
        }
        let Json(reply) =
            crate::mesh_forward_handler(State(Arc::clone(&mesh.executor)), Json(signed(body)))
                .await
                .unwrap();
        assert_eq!(reply.status, expected);
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.journal.describe(STREAM).unwrap().pending_events, 1);
    assert!(!fixture.journal.describe(STREAM).unwrap().closed);
    mesh.stop().await;
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn relay_rejects_signed_reply_for_another_executor_without_releasing_credit() {
    let fixture = fixture().await;
    let (alice, _) = issue(&fixture, issuance("agent:alice")).await;
    let mesh = mesh_fixture(&fixture).await;
    mesh.faults.store(WRONG_SIGNED_EXECUTOR, Ordering::SeqCst);
    let (status, body) = send(relay_app(&mesh), "/rpc/streams/poll", pinned(&alice)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(!body.contains("private-native-event-sentinel"));
    assert_eq!(mesh.received.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.journal.describe(STREAM).unwrap().pending_events, 1);
    assert_eq!(
        fixture
            .journal
            .describe(STREAM)
            .unwrap()
            .acknowledged_events,
        0
    );
    mesh.stop().await;
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn explicit_executor_without_mesh_fails_before_local_custody() {
    let fixture = fixture().await;
    let (alice, _) = issue(&fixture, issuance("agent:alice")).await;
    let (status, body) = send(app(&fixture), "/rpc/streams/poll", pinned(&alice)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.journal.describe(STREAM).unwrap().pending_events, 1);
}
