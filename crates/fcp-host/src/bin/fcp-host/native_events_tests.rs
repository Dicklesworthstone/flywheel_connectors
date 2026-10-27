//! Consumer HTTP regressions with real capability signatures, policy checks,
//! and the production durable journal. The dormant dispatcher asserts that
//! delivery and acknowledgements never wait for a connector RPC.

use super::*;
use axum::body::Body;
use axum::http::Request;
use base64::Engine as _;
use fcp_core::{EventData, EventEnvelope, InstanceId, Principal, TrustLevel};
use tower::util::ServiceExt;

const CONNECTOR: &str = "fcp.test.native-events:streaming:1.0.0";
const CAPABILITY: &str = "events.read";
const OPERATION: &str = "events.subscribe";
const TOPIC: &str = "test.message";
const RESOURCE: &str = "event:test.message";
const STREAM: &str = "retained-test-stream";

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
        "request_id":"consumer-request-1",
        "connector_id":CONNECTOR,
        "zone_id":ZoneId::work(),
        "topic":TOPIC,
        "capability_token":token,
    })
}

fn acknowledgement() -> EventAck {
    EventAck::new(TOPIC, vec![7]).with_cursors(vec!["provider-cursor-7".to_owned()])
}

fn app(fixture: &Fixture) -> Router {
    routes(
        Arc::clone(&fixture.host),
        Some(Arc::clone(&fixture.journal)),
    )
    .with_state(Arc::clone(&fixture.host))
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
