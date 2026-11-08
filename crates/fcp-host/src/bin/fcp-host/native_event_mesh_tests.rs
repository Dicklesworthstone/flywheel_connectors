//! Two-host stream delivery through the production signed relay and journal.

use super::*;
use axum::response::IntoResponse;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_host::mesh_routing::{MESH_FORWARD_ROUTE, unix_now_ms};
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
    holder_key: Ed25519SigningKey,
    membership: SignedEventMembership,
    faults: Arc<AtomicU64>,
    injected_faults: Arc<AtomicU64>,
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
    let holder_key = Ed25519SigningKey::from_bytes(&[43; 32]).unwrap();
    let membership = SignedEventMembership::new(
        fixture._directory.path().join("relay-membership"),
        vec![
            member(ORIGIN, "http://127.0.0.1:1", &origin_key),
            member(EXECUTOR, &endpoint, &executor_key),
            member(HOLDER, "http://127.0.0.1:19003", &holder_key),
        ],
    );
    let origin_router = Arc::new(membership.router(ORIGIN, &origin_key));
    let executor_router = Arc::new(membership.router(EXECUTOR, &executor_key));
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
    let injected_faults = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let observed_faults = Arc::clone(&faults);
    let observed_injections = Arc::clone(&injected_faults);
    let observed_requests = Arc::clone(&received);
    let reply_directory = origin.mesh.as_ref().unwrap().directory();
    let app = Router::new()
        .route(
            MESH_FORWARD_ROUTE,
            post(
                move |state: State<Arc<AppState>>, envelope: Json<MeshForwardEnvelope>| {
                    let faults = Arc::clone(&observed_faults);
                    let injected = Arc::clone(&observed_injections);
                    let received = Arc::clone(&observed_requests);
                    let reply_directory = Arc::clone(&reply_directory);
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
                            let Json(reply) = result
                                .as_ref()
                                .expect("loss injection needs a signed production reply");
                            reply
                                .verify_for(&request, &reply_directory)
                                .expect("production reply must authenticate before loss injection");
                            assert_eq!(
                                reply.status,
                                StatusCode::OK.as_u16(),
                                "loss injection requires successful execution: {}",
                                reply.body_json
                            );
                            injected.fetch_or(fault, Ordering::SeqCst);
                            // Execution and durable custody completed; an intermediary
                            // loses the authenticated reply. It cannot prove rollback.
                            return StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        if faults.fetch_and(!WRONG_SIGNED_EXECUTOR, Ordering::SeqCst)
                            & WRONG_SIGNED_EXECUTOR
                            != 0
                        {
                            let Json(reply) = result.unwrap();
                            reply.verify_for(&request, &reply_directory).expect(
                                "production reply must authenticate before identity tampering",
                            );
                            assert_eq!(
                                reply.status,
                                StatusCode::OK.as_u16(),
                                "identity tampering requires successful execution: {}",
                                reply.body_json
                            );
                            let mut body: Value = serde_json::from_str(&reply.body_json).unwrap();
                            body["executor_node"] = json!("another-executor");
                            injected.fetch_or(WRONG_SIGNED_EXECUTOR, Ordering::SeqCst);
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
        holder_key,
        membership,
        faults,
        injected_faults,
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

fn pinned_holder(token: &fcp_core::CapabilityToken, holder: &Ed25519SigningKey) -> Value {
    json!({"auth":holder_auth(token, holder),"executor_node":EXECUTOR,"stream_id":STREAM})
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
                "type":"response", "id":REQUEST_ID,
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
async fn remote_holder_open_resume_poll_ack_and_close_preserve_custody_after_lost_replies() {
    let mut fixture = fixture().await;
    install_native_source(&mut fixture).await;
    let mut issuance = issuance("agent:alice");
    issuance.holder_node = Some(HOLDER.to_owned());
    let (alice, _) = issue(&fixture, issuance).await;
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
    let open = pinned_holder(&alice, &mesh.holder_key);
    let (status, _) = send(app.clone(), "/rpc/streams/open", open.clone()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        mesh.injected_faults.load(Ordering::SeqCst),
        DROP_OPEN_REPLY,
        "the lost open must have completed successfully at the executor"
    );
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
        let (status, body) = send(
            app.clone(),
            "/rpc/streams/poll",
            pinned_holder(&alice, &mesh.holder_key),
        )
        .await;
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
    let mut ack = pinned_holder(&alice, &mesh.holder_key);
    ack["ack"] = json!(acknowledgement());
    let before_ack = mesh.received.load(Ordering::SeqCst);
    let (status, _) = send(app.clone(), "/rpc/streams/ack", ack.clone()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        mesh.injected_faults.load(Ordering::SeqCst),
        DROP_OPEN_REPLY | DROP_ACK_REPLY,
        "both lost replies must follow authenticated successful execution"
    );
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
    let (status, body) = send(
        app,
        "/rpc/streams/close",
        pinned_holder(&alice, &mesh.holder_key),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let closed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(closed["stream"]["closed"], true);
    assert_eq!(closed["executor_node"], EXECUTOR);
    mesh.stop().await;
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn signed_relay_cannot_replace_holder_proof_or_withdrawn_holder_membership() {
    let fixture = fixture().await;
    let mut issuance = issuance("agent:alice");
    issuance.holder_node = Some(HOLDER.to_owned());
    let (token, _) = issue(&fixture, issuance).await;
    let mut mesh = mesh_fixture(&fixture).await;
    let app = relay_app(&mesh);
    // The envelope is signed by an authenticated relay in both cases. The
    // retained consumer must still prove the separate token holder's key.
    for request in [pinned(&token), pinned_holder(&token, &mesh.origin_key)] {
        let (status, body) = send(app.clone(), "/rpc/streams/poll", request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(!body.contains("private-native-event-sentinel"));
    }
    let (status, body) = send(
        app.clone(),
        "/rpc/streams/poll",
        pinned_holder(&token, &mesh.holder_key),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    mesh.membership
        .withdraw(HOLDER, mesh.executor.mesh.as_ref().unwrap())
        .await;
    for route in ["poll", "ack", "close"] {
        let mut request = pinned_holder(&token, &mesh.holder_key);
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
    assert_eq!(
        mesh.injected_faults.load(Ordering::SeqCst),
        WRONG_SIGNED_EXECUTOR
    );
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
