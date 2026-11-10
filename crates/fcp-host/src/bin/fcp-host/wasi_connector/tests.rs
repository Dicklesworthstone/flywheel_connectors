//! A real component implements the FCP dispatch ABI; no host callback supplies
//! its operation result, instance identity, or retained invocation counter.

use fcp_core::{AgentHint, CapabilityId, FcpError, IdempotencyClass, RiskLevel};
use fcp_crypto::ed25519::Ed25519SigningKey;

use super::*;

const CONNECTOR: &str = "fcp.test.wasi-session:utility:1.0.0";
const ECHO: &str = "test.echo";
const OTHER: &str = "test.other";
const CAPABILITY: &str = "cap.test.echo";

fn split_fragment<'a>(bytes: &'a [u8], marker: &[u8]) -> (&'a [u8], &'a [u8]) {
    let offsets = bytes
        .windows(marker.len())
        .enumerate()
        .filter_map(|(offset, value)| (value == marker).then_some(offset))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 1, "fixture marker must occur exactly once");
    let offset = offsets[0];
    (&bytes[..offset], &bytes[offset + marker.len()..])
}

fn insert_fragment(component: &mut String, name: &str, bytes: &[u8]) {
    assert!(
        bytes.len() <= 1024,
        "fixture data segments must not overlap"
    );
    let escaped = bytes
        .iter()
        .map(|byte| format!("\\{byte:02x}"))
        .collect::<String>();
    *component = component
        .replace(&format!("{{{{{name}}}}}"), &escaped)
        .replace(&format!("{{{{{name}_LEN}}}}"), &bytes.len().to_string());
}

fn component_fixture() -> String {
    let mut component = include_str!("component.wat").to_owned();
    insert_fragment(
        &mut component,
        "CONFIG",
        &encode(&json!({"status": "configured"})).unwrap(),
    );

    let nonce = [0_u8; 32];
    let handshake: HandshakeResponse = serde_json::from_value(json!({
        "status": "accepted",
        "capabilities_granted": [{"capability": CAPABILITY}],
        "session_id": "00000000-0000-4000-8000-000000000001",
        "manifest_hash": "sha256:fixture",
        "nonce": nonce,
    }))
    .unwrap();
    let handshake = encode(&handshake).unwrap();
    let (prefix, suffix) = split_fragment(&handshake, &encode(&nonce).unwrap());
    insert_fragment(&mut component, "HANDSHAKE_PREFIX", prefix);
    insert_fragment(&mut component, "HANDSHAKE_SUFFIX", suffix);

    let instance = "inst_fixture_placeholder";
    let health = encode(&json!({
        "status": {"state": "ready"}, "uptime_ms": 0,
        "details": {"configured": true, "handshaken": true, "instance_id": instance},
    }))
    .unwrap();
    let (prefix, suffix) = split_fragment(&health, &encode(&instance).unwrap());
    insert_fragment(&mut component, "HEALTH_PREFIX", prefix);
    insert_fragment(&mut component, "HEALTH_SUFFIX", suffix);

    let id = RequestId("fixture-request-placeholder".into());
    let result = json!("fixture-result-placeholder");
    let response = encode(&InvokeResponse::ok(id.clone(), result.clone())).unwrap();
    let (prefix, rest) = split_fragment(&response, &encode(&id).unwrap());
    let (middle, suffix) = split_fragment(rest, &encode(&result).unwrap());
    insert_fragment(&mut component, "INVOKE_PREFIX", prefix);
    insert_fragment(&mut component, "INVOKE_MIDDLE", middle);
    insert_fragment(&mut component, "INVOKE_SUFFIX", suffix);

    let error = encode(&InvokeResponse::error(
        id.clone(),
        FcpError::InvalidRequest {
            code: 1002,
            message: "guest rejected input".into(),
        },
    ))
    .unwrap();
    let (prefix, suffix) = split_fragment(&error, &encode(&id).unwrap());
    insert_fragment(&mut component, "ERROR_PREFIX", prefix);
    insert_fragment(&mut component, "ERROR_SUFFIX", suffix);
    assert!(
        !component.contains("{{"),
        "all component fragments must be populated"
    );
    component
}

pub(super) fn write_fixture(directory: &StdPath, connector_id: &'static str) -> ConnectorConfig {
    let component_path = directory.join("connector.wat");
    let manifest_path = directory.join("manifest.toml");
    std::fs::write(&component_path, component_fixture()).expect("write actual FCP component");
    let raw = crate::tests::state_policy_test_manifest_for(connector_id, Some("stateless"), false);
    let mut manifest = ConnectorManifest::parse_str(&raw).expect("validated fixture manifest");
    let mut operation = manifest
        .provides
        .operations
        .values()
        .next()
        .unwrap()
        .clone();
    operation.description = "Echo the request input inside a retained WASI guest".into();
    operation.capability = CapabilityId::from_static(CAPABILITY);
    operation.risk_level = RiskLevel::Low;
    operation.safety_tier = SafetyTier::Safe;
    operation.requires_approval = fcp_manifest::ManifestApprovalMode::None;
    operation.idempotency = IdempotencyClass::None;
    operation.input_schema = json!({"type": "object"});
    operation.output_schema = json!({"type": "object"});
    operation.network_constraints = None;
    operation.ai_hints = AgentHint::default();
    operation.rate_limit = None;
    manifest.provides.operations.clear();
    manifest
        .provides
        .operations
        .insert(ECHO.into(), operation.clone());
    manifest.provides.operations.insert(OTHER.into(), operation);
    manifest.provides.events.clear();
    manifest
        .capabilities
        .optional
        .push(CapabilityId::from_static(CAPABILITY));
    manifest.sandbox.fs_readonly_paths.clear();
    manifest.sandbox.fs_writable_paths.clear();
    manifest.sandbox.wall_clock_timeout_ms = 10_000;
    manifest.manifest.interface_hash = manifest.compute_interface_hash().unwrap();
    let raw = toml::to_string(&manifest).unwrap();
    ConnectorManifest::parse_str(&raw).expect("complete fixture remains valid");
    std::fs::write(&manifest_path, raw).unwrap();

    let mut config = crate::tests::dispatcher_test_config(connector_id);
    config.binary = component_path.to_string_lossy().into_owned();
    config.manifest_path = Some(manifest_path.to_string_lossy().into_owned());
    config.runtime_network_enforcement = RuntimeNetworkEnforcement::WasiSandbox;
    config.allowed_zones = vec![ZoneId::work().to_string(), ZoneId::private().to_string()];
    config.allowed_operations = vec![ECHO.into(), OTHER.into()];
    config.env.insert(
        "FCP_REQUEST_ID".into(),
        "must-not-survive-preparation".into(),
    );
    for operation in [ECHO, OTHER] {
        config.operation_network_constraints.insert(
            operation.into(),
            serde_json::from_value(json!({
                "host_allow": [], "port_allow": [], "require_sni": true,
            }))
            .unwrap(),
        );
    }
    config
}

struct Fixture {
    _directory: tempfile::TempDir,
    host: Arc<AppState>,
    connector: Arc<WasiConnector>,
    key: Ed25519SigningKey,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_zones(vec![ZoneId::work(), ZoneId::private()]).await
    }

    async fn with_zones(zones: Vec<ZoneId>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = write_fixture(directory.path(), CONNECTOR);
        config.allowed_zones = zones.iter().map(ToString::to_string).collect();
        let key = Ed25519SigningKey::generate();
        let registry = Arc::new(
            SubprocessRegistry::from_configs(vec![config], Some(key.verifying_key().to_bytes()))
                .await
                .expect("normal inventory admits explicit deny-all compute policy"),
        );
        let connector = {
            let state = registry.state.read().await;
            let entry = state
                .connectors
                .get(&ConnectorId::from_static(CONNECTOR))
                .unwrap();
            let ConnectorRuntime::Wasi(connector) = &entry.connector else {
                panic!("WASI runtime selected")
            };
            Arc::clone(connector)
        };
        let policies = zones
            .into_iter()
            .map(|zone| (zone.clone(), host_runtime_policy(zone)))
            .collect();
        let mut host = crate::tests::dispatcher_app_state(
            registry,
            Arc::new(HostAdminStateStore::new()),
            Some(key.verifying_key()),
            policies,
        );
        Arc::get_mut(&mut host).unwrap().admin_bearer_token = Some(Arc::from("wasi-fixture-admin"));
        Self {
            _directory: directory,
            host,
            connector,
            key,
        }
    }

    async fn prepare(&self, zone: ZoneId, operation: &'static str) -> session::PreparedSession {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wasi-fixture-admin"),
        );
        let (headers, Json(prepared)) = session::prepare_handler(
            State(Arc::clone(&self.host)),
            Path(CONNECTOR.to_string()),
            headers,
            Json(
                serde_json::from_value(json!({"zone_id": zone, "operation_id": operation}))
                    .unwrap(),
            ),
        )
        .await
        .expect("explicit session preparation");
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(
            prepared.operation_id,
            Some(OperationId::from_static(operation))
        );
        prepared
    }

    fn request(
        &self,
        instance: &InstanceId,
        zone: ZoneId,
        operation: &'static str,
        input: Value,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::random(),
            connector_id: ConnectorId::from_static(CONNECTOR),
            operation: OperationId::from_static(operation),
            capability_token: crate::tests::test_capability_token_for_instance(
                &self.key,
                CAPABILITY,
                operation,
                zone.as_str(),
                instance,
            ),
            zone_id: zone,
            input,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: Some(10_000),
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        }
    }

    async fn invoke(&self, request: InvokeRequest) -> HostResult<InvokeResponse> {
        self.connector
            .invoke_prepared(request, None, None, None)
            .await
    }

    async fn retire(
        &self,
        zone: ZoneId,
        operation: &'static str,
        expected: &InstanceId,
    ) -> Result<session::RetiredSession, (StatusCode, String)> {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wasi-fixture-admin"),
        );
        let (headers, Json(retired)) = session::retire_handler(
            State(Arc::clone(&self.host)),
            Path(CONNECTOR.to_string()),
            headers,
            Json(
                serde_json::from_value(json!({
                    "zone_id": zone, "operation_id": operation, "expected_instance_id": expected,
                }))
                .unwrap(),
            ),
        )
        .await?;
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        Ok(retired)
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_conditional_retirement_preserves_other_sessions_and_replacements() {
    let fixture = Fixture::new().await;
    let echo = fixture.prepare(ZoneId::work(), ECHO).await;
    let other = fixture.prepare(ZoneId::work(), OTHER).await;
    let unauthorized = session::retire_handler(
        State(Arc::clone(&fixture.host)),
        Path(CONNECTOR.to_string()),
        HeaderMap::new(),
        Json(
            serde_json::from_value(json!({
                "zone_id": "z:work", "operation_id": ECHO, "expected_instance_id": echo.instance_id,
            }))
            .unwrap(),
        ),
    )
    .await;
    assert!(unauthorized.is_err());
    assert!(
        fixture
            .retire(ZoneId::public(), ECHO, &echo.instance_id)
            .await
            .is_err()
    );
    assert!(
        fixture
            .retire(ZoneId::work(), "test.undeclared", &echo.instance_id)
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .retire(ZoneId::work(), ECHO, &InstanceId::new())
            .await
            .unwrap_err()
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
        echo.instance_id,
        "rejected retirement must preserve the exact guest"
    );

    let retired = fixture
        .retire(ZoneId::work(), ECHO, &echo.instance_id)
        .await
        .unwrap();
    assert!(retired.retired);
    assert_eq!(retired.retired_instance_id, Some(echo.instance_id.clone()));
    let absent = fixture
        .retire(ZoneId::work(), ECHO, &echo.instance_id)
        .await
        .unwrap();
    assert!(!absent.retired);
    assert!(absent.retired_instance_id.is_none());
    assert!(
        fixture
            .invoke(fixture.request(&echo.instance_id, ZoneId::work(), ECHO, json!({})))
            .await
            .is_err()
    );
    let unaffected = fixture
        .invoke(fixture.request(
            &other.instance_id,
            ZoneId::work(),
            OTHER,
            json!({"unaffected": true}),
        ))
        .await
        .unwrap();
    assert_eq!(unaffected.result.unwrap()["calls"], 1);

    let replacement = fixture.prepare(ZoneId::work(), ECHO).await;
    assert_ne!(replacement.instance_id, echo.instance_id);
    assert_eq!(
        fixture
            .retire(ZoneId::work(), ECHO, &echo.instance_id)
            .await
            .unwrap_err()
            .0,
        StatusCode::CONFLICT,
        "lost-response retry must never destroy a replacement"
    );
    assert!(
        fixture
            .invoke(fixture.request(&echo.instance_id, ZoneId::work(), ECHO, json!({})))
            .await
            .is_err()
    );
    let response = fixture
        .invoke(fixture.request(
            &replacement.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"fresh": true}),
        ))
        .await
        .unwrap();
    assert_eq!(response.result.unwrap()["calls"], 1);
    let never_prepared = fixture
        .retire(ZoneId::private(), ECHO, &InstanceId::new())
        .await
        .unwrap();
    assert!(!never_prepared.retired);
    assert!(
        fixture
            .connector
            .sessions
            .existing_slot(&ZoneId::private(), &OperationId::from_static(ECHO))
            .unwrap()
            .is_none(),
        "retirement must not create a slot or guest"
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn queued_wasi_retirement_cancellation_and_inventory_change_leave_guest_intact() {
    for cancel in [true, false] {
        let fixture = Fixture::new().await;
        let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
        let slot = fixture
            .connector
            .sessions
            .existing_slot(&ZoneId::work(), &OperationId::from_static(ECHO))
            .unwrap()
            .unwrap();
        let owner = slot.guest.lock().await;
        let mut retirement = Box::pin(fixture.retire(ZoneId::work(), ECHO, &prepared.instance_id));
        assert!(futures_util::poll!(retirement.as_mut()).is_pending());
        if cancel {
            drop(retirement);
            drop(owner);
        } else {
            fixture.host.registry.version.fetch_add(1, Ordering::SeqCst);
            drop(owner);
            assert!(
                retirement.await.is_err(),
                "inventory changed while waiting for the selected runtime"
            );
        }
        let generation = fixture.host.registry.version.load(Ordering::SeqCst);
        let fence = fixture.host.registry.inventory_fence(generation);
        assert!(
            fixture
                .connector
                .retire_session(
                    &ZoneId::work(),
                    &OperationId::from_static(ECHO),
                    &prepared.instance_id,
                    &fence,
                    Instant::now()
                )
                .await
                .is_err(),
            "an expired retirement must not select a guest even when the lock is ready"
        );
        let response = fixture
            .invoke(fixture.request(
                &prepared.instance_id,
                ZoneId::work(),
                ECHO,
                json!({"still_alive": true}),
            ))
            .await
            .unwrap();
        assert_eq!(response.result.unwrap()["calls"], 1);
        assert_eq!(
            fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
            prepared.instance_id
        );
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn retiring_wasi_session_reclaims_capacity_only_after_existing_owners_release_slot() {
    let zones = vec![
        ZoneId::work(),
        ZoneId::private(),
        "z:retire-a".parse().unwrap(),
        "z:retire-b".parse().unwrap(),
        "z:retire-c".parse().unwrap(),
    ];
    let fixture = Fixture::with_zones(zones.clone()).await;
    let mut prepared = Vec::new();
    for zone in &zones[..4] {
        for operation in [ECHO, OTHER] {
            prepared.push(fixture.prepare(zone.clone(), operation).await);
        }
    }
    let extra = OperationId::from_static(ECHO);
    assert!(
        fixture
            .connector
            .prepare_session(&zones[4], &extra)
            .await
            .is_err()
    );
    let pinned = fixture
        .connector
        .sessions
        .existing_slot(&zones[0], &extra)
        .unwrap()
        .unwrap();
    assert!(
        fixture
            .retire(zones[0].clone(), ECHO, &prepared[0].instance_id)
            .await
            .unwrap()
            .retired
    );
    let current = fixture
        .connector
        .sessions
        .existing_slot(&zones[0], &extra)
        .unwrap()
        .unwrap();
    assert!(
        Arc::ptr_eq(&pinned, &current),
        "retirement must preserve the lock referenced by existing callers"
    );
    drop(current);
    assert!(
        fixture
            .connector
            .prepare_session(&zones[4], &extra)
            .await
            .is_err(),
        "an empty slot with an existing owner is not available for reclamation"
    );
    drop(pinned);
    fixture.prepare(zones[4].clone(), ECHO).await;
    assert_eq!(
        fixture.connector.sessions.slots.lock().unwrap().len(),
        MAX_RESIDENT_SESSIONS
    );
    assert!(
        fixture
            .connector
            .sessions
            .existing_slot(&zones[0], &extra)
            .unwrap()
            .is_none()
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn prepared_wasi_dispatches_real_input_through_live_host_and_reuses_instance() {
    let fixture = Fixture::new().await;
    assert!(!fixture.connector.sessions.has_ready_session());
    let unprepared = fixture.request(&InstanceId::new(), ZoneId::work(), ECHO, json!({}));
    assert!(fixture.invoke(unprepared).await.is_err());

    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let env = fixture.connector.wasi_env_for_operation(
        &OperationId::from_static(ECHO),
        "later-request",
        &ZoneId::work(),
    );
    assert!(!env.contains_key("FCP_REQUEST_ID"));
    let (runner, config) = fixture
        .connector
        .runner_for_operation(&OperationId::from_static(ECHO), "", &ZoneId::work())
        .unwrap();
    assert!(config.block_direct_network);
    assert!(
        runner
            .validate_http_access("https://example.com/data", "GET")
            .is_err()
    );
    assert!(
        runner
            .validate_tcp_access("example.com", 443, true)
            .is_err()
    );

    for (calls, input) in [
        (1, json!({"message": "first", "nested": [1, true]})),
        (2, json!({"message": "second"})),
    ] {
        let request = fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, input.clone());
        assert!(
            evaluate_live_preflight(fixture.host.as_ref(), &request, None)
                .await
                .allowed
        );
        let id = request.id.clone();
        let response = route_invoke(&fixture.host, request, None)
            .await
            .expect("full host admission and actual guest dispatch");
        assert_eq!(response.id, id);
        assert_eq!(response.status, fcp_kernel::InvokeStatus::Ok);
        assert_eq!(
            response.result,
            Some(json!({"echo": input, "calls": calls}))
        );
        let again = fixture.prepare(ZoneId::work(), ECHO).await;
        assert_eq!(
            again.instance_id, prepared.instance_id,
            "preparation must not silently rehandshake a live guest"
        );
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_live_outcomes_distinguish_refusal_from_possible_guest_effects() {
    let fixture = Fixture::new().await;
    let unprepared = fixture.request(&InstanceId::new(), ZoneId::work(), ECHO, json!({}));
    let unprepared_id = unprepared.id.to_string();
    assert!(route_invoke(&fixture.host, unprepared, None).await.is_err());
    if let Some(record) = fixture
        .host
        .lifecycle
        .invocation_record(&unprepared_id, None)
        .await
    {
        assert_eq!(
            record.terminal.unwrap().outcome,
            fcp_host::InvocationOutcome::HostError
        );
    }

    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let stale = fixture.request(
        &InstanceId::new(),
        ZoneId::work(),
        ECHO,
        json!({"must_not_run": true}),
    );
    let stale_id = stale.id.to_string();
    assert!(
        evaluate_live_preflight(fixture.host.as_ref(), &stale, None)
            .await
            .allowed,
        "gateway admission is unbound; the selected guest must enforce instance identity"
    );
    assert!(route_invoke(&fixture.host, stale, None).await.is_err());
    let record = fixture
        .host
        .lifecycle
        .invocation_record(&stale_id, None)
        .await
        .unwrap();
    assert_eq!(
        record.terminal.unwrap().outcome,
        fcp_host::InvocationOutcome::HostError,
        "the selected guest refused before its effect marker"
    );
    assert_eq!(
        fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
        prepared.instance_id
    );

    let business = fixture.request(
        &prepared.instance_id,
        ZoneId::work(),
        ECHO,
        json!({"mode": "error"}),
    );
    let business_id = business.id.to_string();
    assert_eq!(
        route_invoke(&fixture.host, business, None)
            .await
            .unwrap()
            .status,
        fcp_kernel::InvokeStatus::Error
    );
    assert_eq!(
        fixture
            .host
            .lifecycle
            .invocation_record(&business_id, None)
            .await
            .unwrap()
            .terminal
            .unwrap()
            .outcome,
        fcp_host::InvocationOutcome::ConnectorError
    );

    for mode in ["trap", "malformed"] {
        let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
        let request = fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"mode": mode}),
        );
        let id = request.id.to_string();
        assert!(route_invoke(&fixture.host, request, None).await.is_err());
        let record = fixture
            .host
            .lifecycle
            .invocation_record(&id, None)
            .await
            .unwrap();
        assert_eq!(
            record.terminal.unwrap().outcome,
            fcp_host::InvocationOutcome::OutcomeUnknown,
            "{mode}: a dispatch refusal marker cannot erase a previously selected effect"
        );
        assert!(!fixture.connector.sessions.has_ready_session());
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_session_queue_rechecks_live_authority_without_entering_guest() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let request = fixture.request(
        &prepared.instance_id,
        ZoneId::work(),
        ECHO,
        json!({"queued": true}),
    );
    let guard = live_authority::LiveAuthorityDispatchGuard::new(
        fixture.host.as_ref(),
        &request,
        fixture.host.lifecycle.capability_revocation_fence(),
        Some(
            fixture
                .host
                .lifecycle
                .connector_execution_fence(&request.connector_id)
                .await
                .unwrap(),
        ),
    )
    .unwrap();
    let slot = fixture
        .connector
        .sessions
        .slot(&ZoneId::work(), &OperationId::from_static(ECHO), false)
        .unwrap();
    let owner = slot.guest.lock().await;
    let mut queued = Box::pin(
        fixture
            .connector
            .invoke_prepared(request, None, None, Some(&guard)),
    );
    assert!(futures_util::poll!(queued.as_mut()).is_pending());
    fixture
        .host
        .lifecycle
        .revoke_token(&fcp_host::TokenRevocationRequest {
            token_id: "revocation-during-wasi-session-wait".into(),
            reason: None,
        })
        .await
        .unwrap();
    drop(owner);
    assert!(matches!(queued.await, Err(HostError::PreflightFailed(_))));
    assert!(guard.refused_before_effect());
    let response = fixture
        .invoke(fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"fresh": true}),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.result.unwrap()["calls"],
        1,
        "queued refusal must not enter or retire the ready guest"
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_business_error_preserves_session_but_invalid_replies_retire_it() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let error = fixture
        .invoke(fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"mode": "error"}),
        ))
        .await
        .unwrap();
    assert_eq!(error.status, fcp_kernel::InvokeStatus::Error);
    assert!(matches!(
        error.error,
        Some(FcpError::InvalidRequest { code: 1002, .. })
    ));
    assert_eq!(
        fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
        prepared.instance_id
    );
    let next = fixture
        .invoke(fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"after": "business error"}),
        ))
        .await
        .unwrap();
    assert_eq!(next.result.unwrap()["calls"], 1);

    for mode in ["malformed", "wrong_id", "trap"] {
        let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
        let failed = fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"mode": mode}),
        );
        assert!(fixture.invoke(failed).await.is_err());
        assert!(!fixture.connector.sessions.has_ready_session());
        let previous = fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"after": mode}),
        );
        assert!(
            fixture.invoke(previous.clone()).await.is_err(),
            "invocation must not implicitly recreate a guest"
        );
        let replacement = fixture.prepare(ZoneId::work(), ECHO).await;
        assert_ne!(replacement.instance_id, prepared.instance_id);
        assert!(
            fixture.invoke(previous).await.is_err(),
            "old signed instance authority cannot select its replacement"
        );
        let response = fixture
            .invoke(fixture.request(
                &replacement.instance_id,
                ZoneId::work(),
                ECHO,
                json!({"fresh": mode}),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.result.unwrap()["calls"],
            1,
            "rejected stale token must not execute the replacement"
        );
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_instance_authority_cannot_cross_operation_or_zone_sessions() {
    let fixture = Fixture::new().await;
    let echo = fixture.prepare(ZoneId::work(), ECHO).await;
    let other = fixture.prepare(ZoneId::work(), OTHER).await;
    let private = fixture.prepare(ZoneId::private(), ECHO).await;
    assert_ne!(echo.instance_id, other.instance_id);
    assert_ne!(echo.instance_id, private.instance_id);

    // These tokens deliberately authorize the selected operation and zone;
    // only their stale/different instance binding must prevent dispatch.
    assert!(
        fixture
            .invoke(fixture.request(&echo.instance_id, ZoneId::work(), OTHER, json!({})))
            .await
            .is_err()
    );
    assert!(
        fixture
            .invoke(fixture.request(&echo.instance_id, ZoneId::private(), ECHO, json!({})))
            .await
            .is_err()
    );
    let mut bearer = fixture.request(&echo.instance_id, ZoneId::work(), ECHO, json!({}));
    bearer.capability_token =
        crate::tests::test_capability_token(&fixture.key, CAPABILITY, ECHO, "z:work");
    assert!(
        fixture.invoke(bearer).await.is_err(),
        "actual instance authority is mandatory"
    );
    for (prepared, zone, operation) in [
        (echo, ZoneId::work(), ECHO),
        (other, ZoneId::work(), OTHER),
        (private, ZoneId::private(), ECHO),
    ] {
        let response = fixture
            .invoke(fixture.request(
                &prepared.instance_id,
                zone,
                operation,
                json!({"correct": true}),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.result.unwrap()["calls"],
            1,
            "wrong session selection must perform no guest operation"
        );
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn cancelling_wasi_guest_retires_only_that_operation_session() {
    let fixture = Fixture::new().await;
    let echo = fixture.prepare(ZoneId::work(), ECHO).await;
    let other = fixture.prepare(ZoneId::work(), OTHER).await;
    let request = fixture.request(
        &echo.instance_id,
        ZoneId::work(),
        ECHO,
        json!({"mode": "spin"}),
    );
    let mut invocation = Box::pin(fixture.invoke(request));
    assert!(
        futures_util::poll!(invocation.as_mut()).is_pending(),
        "fuel-yielding guest must be cancellable"
    );
    drop(invocation);
    assert!(
        fixture
            .invoke(fixture.request(&echo.instance_id, ZoneId::work(), ECHO, json!({})))
            .await
            .is_err()
    );
    let response = fixture
        .invoke(fixture.request(
            &other.instance_id,
            ZoneId::work(),
            OTHER,
            json!({"survived": true}),
        ))
        .await
        .unwrap();
    assert_eq!(response.result.unwrap()["calls"], 1);
    assert_eq!(
        fixture.prepare(ZoneId::work(), OTHER).await.instance_id,
        other.instance_id
    );
    assert_ne!(
        fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
        echo.instance_id
    );
}

#[test]
fn wasi_response_codec_rejects_noncanonical_and_trailing_cbor() {
    assert!(
        decode::<Value>(&[0x18, 0x01]).is_err(),
        "non-minimal integer"
    );
    assert!(decode::<Value>(&[0xa0, 0xa0]).is_err(), "second message");
    assert!(
        decode::<Value>(&[0xa2, 0x61, b'a', 1, 0x61, b'a', 2]).is_err(),
        "duplicate keys"
    );
    assert_eq!(
        decode::<Value>(&encode(&json!({"a": [1, true, null]})).unwrap()).unwrap(),
        json!({"a": [1, true, null]})
    );
}

#[test]
fn wasi_session_slots_are_bounded_without_evicting_active_owners() {
    let sessions = WasiSessions::default();
    let mut owners = Vec::new();
    for index in 0..MAX_RESIDENT_SESSIONS {
        let operation = OperationId::new(format!("test.op{index}")).unwrap();
        owners.push(sessions.slot(&ZoneId::work(), &operation, true).unwrap());
    }
    let extra = OperationId::from_static("test.extra");
    assert!(sessions.slot(&ZoneId::work(), &extra, true).is_err());
    owners.pop();
    assert!(
        sessions.slot(&ZoneId::work(), &extra, true).is_ok(),
        "unowned empty slot can be reclaimed"
    );
}
