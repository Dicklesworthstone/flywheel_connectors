//! Native session preparation and negotiation tests. A small fake dispatcher
//! drives the production SubprocessConnector path, not a second implementation.

use std::sync::atomic::{AtomicBool, Ordering};
use fcp_core::{AgentHint, CapabilityGrant, IdempotencyClass, OperationInfo, RiskLevel, SessionId};

use super::*;

fn operation(id: &'static str, capability: &'static str) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id), summary: id.into(), description: None,
        input_schema: json!({"type": "object"}), output_schema: json!({"type": "object"}),
        capability: CapabilityId::from_static(capability), risk_level: RiskLevel::Low,
        safety_tier: SafetyTier::Safe, idempotency: IdempotencyClass::None,
        ai_hints: AgentHint::default(), rate_limit: None, requires_approval: None,
    }
}

fn catalog() -> Introspection {
    Introspection {
        operations: vec![
            operation("fixture.get", "fixture.read"),
            operation("fixture.list", "fixture.read"),
            operation("fixture.put", "fixture.write"),
        ],
        events: Vec::new(), resource_types: Vec::new(), auth_caps: None, event_caps: None,
    }
}

fn handshake() -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "2.0.0".into(), zone: ZoneId::work(), zone_dir: None,
        host_public_key: [1; 32], nonce: [9; 32],
        capabilities_requested: requested_capabilities(&catalog()).unwrap(),
        host: None, transport_caps: None, requested_instance_id: None,
    }
}

fn reply(request: &HandshakeRequest) -> HandshakeResponse {
    HandshakeResponse {
        status: "accepted".into(),
        capabilities_granted: request.capabilities_requested.iter().cloned()
            .map(|capability| CapabilityGrant { capability, operation: None }).collect(),
        session_id: SessionId::new(), manifest_hash: "sha256:fixture".into(),
        nonce: request.nonce, event_caps: None, auth_caps: None, op_catalog_hash: None,
    }
}

fn health_value() -> Value {
    let instance = InstanceId::new();
    json!({
        "status": {"state": "ready"}, "uptime_ms": 10,
        "configured": true, "handshaken": true, "instance_id": instance,
        "details": {"configured": true, "handshaken": true, "instance_id": instance},
    })
}

fn prepare(value: Value) -> Result<PreparedSession, HttpFailure> {
    prepared_from_health(ConnectorId::from_static("fcp.fixture"), ZoneId::work(), value)
}

#[test]
fn capabilities_are_complete_deduplicated_and_stably_ordered() {
    let mut c = catalog();
    let expected = vec![
        CapabilityId::from_static("fixture.read"), CapabilityId::from_static("fixture.write"),
    ];
    assert_eq!(requested_capabilities(&c).unwrap(), expected);
    c.operations.reverse();
    assert_eq!(requested_capabilities(&c).unwrap(), expected);
    c.operations.clear();
    assert!(requested_capabilities(&c).is_err());
    c.operations = vec![
        operation("fixture.get", "fixture.read"), operation("fixture.get", "fixture.write"),
    ];
    assert!(requested_capabilities(&c).is_err());
}

#[test]
fn negotiation_refuses_extra_capabilities_and_forged_operation_scopes() {
    let request = handshake();
    let mut response = reply(&request);
    response.capabilities_granted.truncate(1);
    validate_negotiated_grants(&request, &response, &catalog()).unwrap();
    response.capabilities_granted.push(CapabilityGrant {
        capability: CapabilityId::from_static("fixture.admin"), operation: None,
    });
    assert!(validate_negotiated_grants(&request, &response, &catalog()).is_err());
    response.capabilities_granted.pop();
    response.capabilities_granted[0].operation = Some(OperationId::from_static("fixture.put"));
    assert!(validate_negotiated_grants(&request, &response, &catalog()).is_err());
}

#[test]
fn preparation_is_exactly_zone_scoped() {
    let work = ZoneId::work();
    require_zone(&["z:work".into()], &work).unwrap();
    for allowed in [
        vec![], vec!["*".into()], vec!["z:private".into()], vec![" z:work ".into()],
    ] {
        assert_eq!(require_zone(&allowed, &work).unwrap_err().0, StatusCode::FORBIDDEN);
    }
    serde_json::from_value::<PrepareSessionRequest>(json!({"zone_id": "z:work"})).unwrap();
    for field in ["instance_id", "host_public_key", "protocol_version", "allowed_zones"] {
        let mut value = json!({"zone_id": "z:work"});
        value[field] = json!("caller-controlled");
        assert!(serde_json::from_value::<PrepareSessionRequest>(value).is_err());
    }
}

#[test]
fn returns_actual_healthy_instance_not_a_token_or_guess() {
    let health = health_value();
    let expected = health["details"]["instance_id"].clone();
    let response = serde_json::to_value(prepare(health).unwrap()).unwrap();
    assert_eq!(response["instance_id"], expected);
    assert_eq!(response["zone_id"], "z:work");
    assert_eq!(response["protocol_version"], "2.0");
    assert!(response.get("capability_token").is_none());
}

#[test]
fn refuses_fabricated_readiness_legacy_health_and_conflicting_identity() {
    for state in [
        json!({"state": "starting"}), json!({"state": "stopping"}),
        json!({"state": "degraded", "reason": "not ready"}), json!("healthy"),
    ] {
        let mut health = health_value();
        health["status"] = state;
        assert_eq!(prepare(health).unwrap_err().0, StatusCode::BAD_GATEWAY);
    }
    for details in [
        Value::Null, json!({}), json!({"configured": true}),
        json!({"configured": true, "handshaken": false, "instance_id": InstanceId::new()}),
    ] {
        let mut health = health_value();
        health["details"] = details;
        assert!(prepare(health).is_err());
    }
    let mut health = health_value();
    health["instance_id"] = json!(InstanceId::new());
    assert!(prepare(health).is_err());
}

#[test]
fn malformed_identity_and_contradictory_authority_fail_without_payload_echo() {
    for id in [Value::Null, json!(42), json!(""), json!("not an instance"), json!({})] {
        let mut health = health_value();
        health["details"]["instance_id"] = id;
        assert!(prepare(health).is_err());
    }
    for field in ["configured", "handshaken"] {
        let mut health = health_value();
        health[field] = json!(false);
        assert!(prepare(health).is_err());
    }
    let error = prepare(json!({
        "status": "private-provider-marker", "details": {"token": "private-token"},
    })).unwrap_err();
    assert!(!error.1.contains("private-provider-marker"));
    assert!(!error.1.contains("private-token"));
}

struct Dispatcher {
    connector: SubprocessConnector,
    calls: Arc<StdMutex<Vec<(String, Value)>>>,
    reject_handshake: Arc<AtomicBool>,
    reject_configure: Arc<AtomicBool>,
    _state_dir: tempfile::TempDir,
}

fn dispatcher() -> Dispatcher {
    let (runner_tx, mut runner_rx) = mpsc::channel::<ConnectorRpcRequest>(16);
    let calls = Arc::new(StdMutex::new(Vec::new()));
    let reject_handshake = Arc::new(AtomicBool::new(false));
    let reject_configure = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&calls);
    let reject_h = Arc::clone(&reject_handshake);
    let reject_c = Arc::clone(&reject_configure);
    let runner_task = task::spawn(async move {
        while let Some(request) = runner_rx.recv().await {
            seen.lock().unwrap().push((request.method.clone(), request.params.clone()));
            let result = match request.method.as_str() {
                "introspect" => serde_json::to_value(catalog()).unwrap(),
                "handshake" if !reject_h.load(Ordering::SeqCst) => {
                    let value: HandshakeRequest = serde_json::from_value(request.params).unwrap();
                    serde_json::to_value(reply(&value)).unwrap()
                }
                "health" => health_value(),
                "configure" if !reject_c.load(Ordering::SeqCst) => json!({}),
                _ => {
                    let _ = request.response_tx.send(Ok(json!({
                        "error": {"message": "fixture rejection"}
                    })));
                    continue;
                }
            };
            let _ = request.response_tx.send(Ok(json!({"result": result})));
        }
    });
    let summary = ConnectorSummary {
        id: ConnectorId::from_static("fcp.fixture"), name: "fixture".into(), description: None,
        version: semver::Version::new(1, 0, 0), categories: vec![], tool_count: 3,
        max_safety_tier: SafetyTier::Safe, enabled: true, health: ConnectorHealth::healthy(),
        last_health_check: None,
    };
    let resilience = Arc::new(ResilienceLayer::default());
    resilience.ensure_connector(&summary.id);
    let state_dir = tempfile::tempdir().unwrap();
    let connector = SubprocessConnector {
        summary, runner_tx, _runner_task: runner_task, resilience,
        capability_verifying_key: Some([1; PUBLIC_KEY_SIZE]),
        state_root: Some(state_dir.path().to_owned()),
        handshaken_zone: futures_util::lock::Mutex::new(None),
    };
    Dispatcher { connector, calls, reject_handshake, reject_configure, _state_dir: state_dir }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn handshake_requests_v2_explicit_caps_only_once_per_zone() {
    let fixture = dispatcher();
    fixture.connector.ensure_handshake(&ZoneId::work()).await.unwrap();
    fixture.connector.ensure_handshake(&ZoneId::work()).await.unwrap();
    let calls = fixture.calls.lock().unwrap();
    assert_eq!(calls.iter().map(|(method, _)| method.as_str()).collect::<Vec<_>>(),
        vec!["introspect", "handshake"]);
    assert_eq!(calls[1].1["protocol_version"], "2.0.0");
    assert_eq!(calls[1].1["capabilities_requested"], json!(["fixture.read", "fixture.write"]));
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn failed_rehandshake_revokes_cached_authority() {
    let fixture = dispatcher();
    fixture.connector.ensure_handshake(&ZoneId::work()).await.unwrap();
    fixture.reject_handshake.store(true, Ordering::SeqCst);
    assert!(fixture.connector.ensure_handshake(&ZoneId::private()).await.is_err());
    assert!(fixture.connector.handshaken_zone.lock().await.is_none());
    fixture.reject_handshake.store(false, Ordering::SeqCst);
    fixture.connector.ensure_handshake(&ZoneId::work()).await.unwrap();
    assert_eq!(fixture.calls.lock().unwrap().iter()
        .filter(|(method, _)| method == "handshake").count(), 3);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn failed_reconfigure_revokes_cached_authority() {
    let fixture = dispatcher();
    fixture.connector.ensure_handshake(&ZoneId::work()).await.unwrap();
    fixture.reject_configure.store(true, Ordering::SeqCst);
    assert!(fixture.connector.configure(json!({})).await.is_err());
    assert!(fixture.connector.handshaken_zone.lock().await.is_none());
    fixture.connector.ensure_handshake(&ZoneId::work()).await.unwrap();
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn prepare_only_performs_introspection_handshake_and_health() {
    let fixture = dispatcher();
    let response = fixture.connector.rpc_in_handshaken_zone(
        &ZoneId::work(), "health", json!({}),
    ).await.unwrap();
    prepare(response).unwrap();
    assert_eq!(fixture.calls.lock().unwrap().iter()
        .map(|(method, _)| method.as_str()).collect::<Vec<_>>(),
        vec!["introspect", "handshake", "health"]);
}
