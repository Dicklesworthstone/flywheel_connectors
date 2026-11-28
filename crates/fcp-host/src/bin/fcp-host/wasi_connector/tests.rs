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

    let credits = 1_987_654_321_u64;
    let cost = fcp_core::CostEstimate::with_credits(credits);
    let availability = ResourceAvailability::available();
    let simulation = SimulateResponse::allowed(id.clone())
        .with_cost_estimate(cost.clone())
        .with_availability(availability.clone());
    let response = encode(&simulation).unwrap();
    let (prefix, rest) = split_fragment(&response, &encode(&id).unwrap());
    let (after_id, rest) = split_fragment(rest, &encode(&availability).unwrap());
    let (after_availability, suffix) = split_fragment(rest, &encode(&cost).unwrap());
    insert_fragment(&mut component, "SIMULATE_PREFIX", prefix);
    insert_fragment(&mut component, "SIMULATE_AFTER_ID", after_id);
    insert_fragment(
        &mut component,
        "SIMULATE_AFTER_AVAILABILITY",
        after_availability,
    );
    insert_fragment(&mut component, "SIMULATE_SUFFIX", suffix);
    insert_fragment(
        &mut component,
        "SIMULATE_AVAILABILITY",
        &encode(&availability).unwrap(),
    );
    let cost = encode(&cost).unwrap();
    let (prefix, suffix) = split_fragment(&cost, &encode(&credits).unwrap());
    insert_fragment(&mut component, "SIMULATE_COST_PREFIX", prefix);
    insert_fragment(&mut component, "SIMULATE_COST_SUFFIX", suffix);

    let denied = encode(&SimulateResponse::denied(
        id.clone(),
        "guest rejected simulation",
        "FCP-1002",
    ))
    .unwrap();
    let (prefix, suffix) = split_fragment(&denied, &encode(&id).unwrap());
    insert_fragment(&mut component, "SIMULATE_DENIED_PREFIX", prefix);
    insert_fragment(&mut component, "SIMULATE_DENIED_SUFFIX", suffix);
    let mut wrong_type = SimulateResponse::allowed(id.clone());
    wrong_type.r#type = "response".into();
    let wrong_type = encode(&wrong_type).unwrap();
    let (prefix, suffix) = split_fragment(&wrong_type, &encode(&id).unwrap());
    insert_fragment(&mut component, "SIMULATE_WRONG_TYPE_PREFIX", prefix);
    insert_fragment(&mut component, "SIMULATE_WRONG_TYPE_SUFFIX", suffix);
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

    fn simulation(request: InvokeRequest) -> HostSimulateRequest {
        serde_json::from_value(json!({
            "connector_id": request.connector_id,
            "operation": request.operation,
            "request_id": request.id,
            "zone_id": request.zone_id,
            "input": request.input,
            "capability_token": request.capability_token,
            "estimate_cost": true,
            "check_availability": true,
            "deadline_ms": request.deadline_ms.unwrap_or(10_000),
        }))
        .unwrap()
    }

    async fn simulate(&self, request: &HostSimulateRequest) -> HostResult<SimulateResponse> {
        self.connector
            .simulate(simulate_request_from_host(request)?)
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

#[test]
fn wasi_component_admission_bounds_sources_and_captures_exact_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("component.wat");
    let mut config = crate::tests::dispatcher_test_config(CONNECTOR);
    config.binary = path.to_string_lossy().into_owned();

    assert!(AdmittedWasiComponent::capture(&config).is_err());
    std::fs::write(&path, b"").unwrap();
    assert!(AdmittedWasiComponent::capture(&config).is_err());
    std::fs::write(&path, b"not a WebAssembly component").unwrap();
    assert!(AdmittedWasiComponent::capture(&config).is_err());
    let original = format!("{}\n;; first\n", component_fixture());
    std::fs::write(&path, &original).unwrap();
    let admitted = AdmittedWasiComponent::capture(&config).unwrap();
    assert!(admitted.source_matches(&config).unwrap());

    std::fs::write(&path, original.replace(";; first", ";; other")).unwrap();
    assert!(
        !admitted.source_matches(&config).unwrap(),
        "same-length source replacements must be detected"
    );
    assert_eq!(admitted.bytes.as_slice(), original.as_bytes());
    std::fs::write(&path, b"a longer replacement").unwrap();
    assert!(!admitted.source_matches(&config).unwrap());
    std::fs::File::create(&path)
        .unwrap()
        .set_len(MAX_COMPONENT_BYTES + 1)
        .unwrap();
    assert!(AdmittedWasiComponent::capture(&config).is_err());
    assert!(admitted.source_matches(&config).is_err());
    assert_eq!(admitted.bytes.as_slice(), original.as_bytes());

    config.binary = directory.path().to_string_lossy().into_owned();
    assert!(AdmittedWasiComponent::capture(&config).is_err());
}

#[cfg(unix)]
#[test]
fn wasi_component_admission_rejects_fifo_and_device_sources() {
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("component.fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("create FIFO source")
            .success()
    );
    let mut config = crate::tests::dispatcher_test_config(CONNECTOR);
    config.binary = fifo.to_string_lossy().into_owned();
    assert!(AdmittedWasiComponent::capture(&config).is_err());
    config.binary = "/dev/null".into();
    assert!(AdmittedWasiComponent::capture(&config).is_err());
}

#[test]
fn pinned_wasi_admission_verifies_exact_bytes_and_retained_lifecycle_snapshot() {
    use sha2::Digest as _;

    let directory = tempfile::tempdir().unwrap();
    let mut config = write_fixture(directory.path(), CONNECTOR);
    let original = std::fs::read(&config.binary).unwrap();
    config.binary_sha256 = Some(hex::encode(sha2::Sha256::digest(&original)));
    let admitted = validate_registry_config(&config).unwrap();
    let connector = WasiConnector::new(
        config.clone(),
        admitted.state_policy,
        admitted.manifest_constraints.clone(),
        None,
        None,
    )
    .unwrap();
    assert_eq!(connector.component.bytes.as_ref(), &original);
    assert!(!connector.sessions.has_ready_session());

    std::fs::write(&config.binary, b"tampered component").unwrap();
    let restarted = WasiConnector::new(
        config.clone(),
        admitted.state_policy,
        admitted.manifest_constraints.clone(),
        None,
        Some(connector.component.clone()),
    )
    .expect("lifecycle restart retains the exact verified deployment bytes");
    assert!(Arc::ptr_eq(
        &connector.component.bytes,
        &restarted.component.bytes
    ));
    assert!(
        WasiConnector::new(
            config.clone(),
            admitted.state_policy,
            admitted.manifest_constraints.clone(),
            None,
            None,
        )
        .err()
        .unwrap()
        .to_string()
        .contains("binary_sha256"),
        "a fresh admission must reject the changed component source"
    );

    config.binary_sha256 = Some("00".repeat(32));
    assert!(
        WasiConnector::new(
            config,
            admitted.state_policy,
            admitted.manifest_constraints,
            None,
            Some(connector.component.clone()),
        )
        .err()
        .unwrap()
        .to_string()
        .contains("binary_sha256"),
        "retained snapshots must not bypass a different requested pin"
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_component_admission_precedes_every_first_guest() {
    let fixture = Fixture::new().await;
    assert!(!fixture.connector.sessions.has_ready_session());
    std::fs::write(
        &fixture.connector.config.binary,
        b"this replacement is not a WebAssembly component",
    )
    .unwrap();

    for (zone, operation) in [(ZoneId::work(), ECHO), (ZoneId::private(), OTHER)] {
        let prepared = fixture.prepare(zone.clone(), operation).await;
        let input = json!({"admitted": operation});
        let response = fixture
            .invoke(fixture.request(&prepared.instance_id, zone, operation, input.clone()))
            .await
            .unwrap();
        assert_eq!(response.result, Some(json!({"echo": input, "calls": 1})));
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_component_incompatible_updates_preserve_the_live_deployment() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let config = fixture.connector.config.clone();
    let generation = fixture.host.registry.version();
    let fence = fixture.host.registry.inventory_fence(generation);
    let incompatible_dispatch = r#"
        (component
            (core module $m (func (export "dispatch")))
            (core instance $i (instantiate $m))
            (func (export "fcp-dispatch") (canon lift (core func $i "dispatch")))
        )
    "#;
    let unsupported_import = component_fixture().replacen(
        "(component\n",
        "(component\n  (import \"unavailable-host-call\" (func))\n",
        1,
    );
    for (index, candidate) in [
        "not a WebAssembly component",
        "(component)",
        incompatible_dispatch,
        unsupported_import.as_str(),
    ]
    .into_iter()
    .enumerate()
    {
        std::fs::write(&config.binary, candidate).unwrap();
        let error = fixture
            .host
            .registry
            .apply_configs_with_lifecycle(vec![config.clone()], &fixture.host.lifecycle)
            .await
            .expect_err("incompatible bytes must not replace the admitted runtime");
        assert!(
            error.to_string().contains("failed executable admission"),
            "{error}"
        );
        assert_eq!(fixture.host.registry.version(), generation);
        fence.require_current().unwrap();
        assert!(Arc::ptr_eq(
            &fixture.connector,
            &registered_runtime(&fixture).await
        ));
        assert_eq!(
            fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
            prepared.instance_id,
            "a rejected update must preserve the actual guest identity"
        );
        let response = fixture
            .invoke(fixture.request(
                &prepared.instance_id,
                ZoneId::work(),
                ECHO,
                json!({"rejected_update": index}),
            ))
            .await
            .unwrap();
        assert_eq!(response.result.unwrap()["calls"], index + 1);
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_component_inventory_apply_observes_same_path_replacements() {
    let fixture = Fixture::new().await;
    let config = fixture.connector.config.clone();
    let generation = fixture.host.registry.version();
    let fence = fixture.host.registry.inventory_fence(generation);
    let replacement = format!(
        "{}\n;; explicitly selected component\n",
        component_fixture()
    );
    std::fs::write(&config.binary, &replacement).unwrap();

    let preview = fixture
        .host
        .registry
        .preview_configs_with_lifecycle(vec![config.clone()], &fixture.host.lifecycle)
        .await
        .unwrap();
    assert_eq!(preview.updated, vec![CONNECTOR.to_owned()]);
    assert!(preview.unchanged.is_empty());
    assert_eq!(fixture.host.registry.version(), generation);
    assert!(Arc::ptr_eq(
        &fixture.connector,
        &registered_runtime(&fixture).await
    ));
    assert!(!fixture.connector.sessions.has_ready_session());
    fence.require_current().unwrap();

    let applied = fixture
        .host
        .registry
        .apply_configs_with_lifecycle(vec![config.clone()], &fixture.host.lifecycle)
        .await
        .unwrap();
    assert_eq!(applied.updated, vec![CONNECTOR.to_owned()]);
    assert_eq!(applied.registry_version, generation + 1);
    assert!(fence.require_current().is_err());
    let current = registered_runtime(&fixture).await;
    assert!(!Arc::ptr_eq(&fixture.connector, &current));
    assert_ne!(fixture.connector.component.digest, current.component.digest);
    assert_eq!(current.component.bytes.as_slice(), replacement.as_bytes());
    assert!(!current.sessions.has_ready_session());

    let unchanged = fixture
        .host
        .registry
        .apply_configs_with_lifecycle(vec![config.clone()], &fixture.host.lifecycle)
        .await
        .unwrap();
    assert_eq!(unchanged.unchanged, vec![CONNECTOR.to_owned()]);
    assert_eq!(unchanged.registry_version, generation + 1);
    assert!(Arc::ptr_eq(&current, &registered_runtime(&fixture).await));

    std::fs::rename(
        &config.binary,
        fixture._directory.path().join("retained-source.wat"),
    )
    .unwrap();
    assert!(
        fixture
            .host
            .registry
            .apply_configs_with_lifecycle(vec![config], &fixture.host.lifecycle)
            .await
            .is_err(),
        "an unavailable source cannot publish replacement inventory"
    );
    assert_eq!(fixture.host.registry.version(), generation + 1);
    assert!(Arc::ptr_eq(&current, &registered_runtime(&fixture).await));
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let response = current
        .invoke_prepared(
            fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, json!({})),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.result.unwrap()["calls"], 1);
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
async fn wasi_simulation_reaches_real_guest_and_preserves_invocation_state() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let before = fixture
        .invoke(fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, json!({})))
        .await
        .unwrap();
    assert_eq!(before.result.unwrap()["calls"], 1);

    for (estimate_cost, check_availability, credits) in [
        (false, false, 3),
        (true, false, 17),
        (false, true, 29),
        (true, true, 71),
    ] {
        let mut request = Fixture::simulation(fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"credits": credits}),
        ));
        request.estimate_cost = estimate_cost;
        request.check_availability = check_availability;
        let expected_id = request.request_id.clone();
        let response = simulate_handler(
            State(Arc::clone(&fixture.host)),
            HeaderMap::new(),
            Json(request),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(response.request_id, expected_id);
        assert_eq!(response.phase, SimulatePhase::ConnectorReached);
        assert!(response.preflight_allowed && response.would_succeed);
        assert_eq!(
            response.cost_estimate.and_then(|cost| cost.api_credits),
            estimate_cost.then_some(credits),
        );
        assert_eq!(response.availability.is_some(), check_availability);
        assert!(
            response
                .availability
                .is_none_or(|availability| availability.available)
        );
        assert_eq!(response.receipt.phase, SimulatePhase::ConnectorReached);
        assert!(response.receipt.would_succeed);
    }

    let denied = Fixture::simulation(fixture.request(
        &prepared.instance_id,
        ZoneId::work(),
        ECHO,
        json!({"mode": "error"}),
    ));
    let denied = local_simulate(&fixture.host, &denied, None).await.unwrap();
    assert_eq!(denied.phase, SimulatePhase::ConnectorReached);
    assert!(!denied.would_succeed);
    assert_eq!(denied.denial_code.as_deref(), Some("FCP-1002"));
    assert_eq!(
        denied.failure_reason.as_deref(),
        Some("guest rejected simulation")
    );
    assert_eq!(
        fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
        prepared.instance_id
    );
    let after = fixture
        .invoke(fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, json!({})))
        .await
        .unwrap();
    assert_eq!(
        after.result.unwrap()["calls"],
        2,
        "simulation must never call invoke"
    );
    let receipts = fixture
        .host
        .lifecycle
        .query_simulate_receipts(&SimulateReceiptQueryRequest {
            connector_id: CONNECTOR.into(),
            operation: Some(ECHO.into()),
            after: None,
            limit: 10,
        })
        .await;
    assert_eq!(receipts.total_receipts, 5);
    assert!(
        receipts
            .receipts
            .iter()
            .all(|receipt| receipt.phase == SimulatePhase::ConnectorReached)
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_simulation_requires_exact_prepared_instance_and_scope() {
    let fixture = Fixture::new().await;
    let unprepared =
        Fixture::simulation(fixture.request(&InstanceId::new(), ZoneId::work(), ECHO, json!({})));
    assert!(fixture.simulate(&unprepared).await.is_err());
    assert!(!fixture.connector.sessions.has_ready_session());

    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let other = fixture.prepare(ZoneId::work(), OTHER).await;
    let private = fixture.prepare(ZoneId::private(), ECHO).await;
    for (zone, operation) in [(ZoneId::work(), OTHER), (ZoneId::private(), ECHO)] {
        let mismatched =
            Fixture::simulation(fixture.request(&prepared.instance_id, zone, operation, json!({})));
        assert!(fixture.simulate(&mismatched).await.is_err());
    }
    let mut unbound = Fixture::simulation(fixture.request(
        &prepared.instance_id,
        ZoneId::work(),
        ECHO,
        json!({}),
    ));
    unbound.capability_token = Some(crate::tests::test_capability_token(
        &fixture.key,
        CAPABILITY,
        ECHO,
        "z:work",
    ));
    assert!(fixture.simulate(&unbound).await.is_err());
    for (instance, zone, operation) in [
        (&prepared.instance_id, ZoneId::work(), ECHO),
        (&other.instance_id, ZoneId::work(), OTHER),
        (&private.instance_id, ZoneId::private(), ECHO),
    ] {
        let response = fixture
            .invoke(fixture.request(instance, zone, operation, json!({})))
            .await
            .unwrap();
        assert_eq!(response.result.unwrap()["calls"], 1);
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_simulation_invalid_responses_retire_only_selected_guest() {
    let fixture = Fixture::new().await;
    let unaffected = fixture.prepare(ZoneId::work(), OTHER).await;
    for mode in [
        "trap",
        "malformed",
        "wrong_id",
        "wrong_type",
        "noncanonical",
        "trailing",
        "oversized",
    ] {
        let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
        let request = Fixture::simulation(fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"mode": mode}),
        ));
        assert!(fixture.simulate(&request).await.is_err(), "{mode}");
        assert!(
            fixture.simulate(&request).await.is_err(),
            "{mode} must require explicit preparation"
        );
        let replacement = fixture.prepare(ZoneId::work(), ECHO).await;
        assert_ne!(prepared.instance_id, replacement.instance_id);
        assert!(
            fixture.simulate(&request).await.is_err(),
            "{mode}: stale token must not select replacement"
        );
        let response = fixture
            .invoke(fixture.request(&replacement.instance_id, ZoneId::work(), ECHO, json!({})))
            .await
            .unwrap();
        assert_eq!(response.result.unwrap()["calls"], 1);
    }
    assert_eq!(
        fixture.prepare(ZoneId::work(), OTHER).await.instance_id,
        unaffected.instance_id
    );
    let response = fixture
        .invoke(fixture.request(&unaffected.instance_id, ZoneId::work(), OTHER, json!({})))
        .await
        .unwrap();
    assert_eq!(response.result.unwrap()["calls"], 1);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_simulation_queue_rechecks_inventory_revocation_and_lifecycle() {
    for change in ["inventory", "revocation", "lifecycle"] {
        let fixture = Fixture::new().await;
        let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
        let request = Fixture::simulation(fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({}),
        ));
        let admission = invoke_request_from_simulate(&request).unwrap();
        let guards = SimulationDispatchGuards::admit(
            &fixture.host,
            &admission,
            None,
            Instant::now() + Duration::from_secs(10),
        )
        .await
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
                .simulate_prepared(simulate_request_from_host(&request).unwrap(), Some(&guards)),
        );
        assert!(futures_util::poll!(queued.as_mut()).is_pending());
        match change {
            "inventory" => {
                fixture.host.registry.version.fetch_add(1, Ordering::SeqCst);
            }
            "revocation" => {
                fixture
                    .host
                    .lifecycle
                    .revoke_token(&fcp_host::TokenRevocationRequest {
                        token_id: "simulation-queued-revocation".into(),
                        reason: None,
                    })
                    .await
                    .unwrap();
            }
            _ => {
                let connector_id = ConnectorId::from_static(CONNECTOR);
                fixture
                    .host
                    .lifecycle
                    .set_desired_state(&connector_id, fcp_host::DesiredRuntimeState::Disabled, None)
                    .await
                    .unwrap();
                fixture
                    .host
                    .lifecycle
                    .set_desired_state(&connector_id, fcp_host::DesiredRuntimeState::Enabled, None)
                    .await
                    .unwrap();
            }
        }
        drop(owner);
        assert!(queued.await.is_err(), "{change}");
        assert_eq!(
            fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
            prepared.instance_id
        );
        let response = fixture
            .invoke(fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, json!({})))
            .await
            .unwrap();
        assert_eq!(
            response.result.unwrap()["calls"],
            1,
            "{change} refusal must preserve an unused guest"
        );
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_simulation_cancellation_and_deadline_preserve_queued_guest() {
    for cancel in [false, true] {
        let fixture = Fixture::new().await;
        let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
        let mut request = Fixture::simulation(fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({}),
        ));
        request.deadline_ms = if cancel { 10_000 } else { 100 };
        let slot = fixture
            .connector
            .sessions
            .slot(&ZoneId::work(), &OperationId::from_static(ECHO), false)
            .unwrap();
        let owner = slot.guest.lock().await;
        let mut queued = Box::pin(local_simulate(&fixture.host, &request, None));
        // Admission itself has async lookups. Wait for the exact logical
        // registration instead of assuming the first poll reaches the queue.
        for _ in 0..100 {
            assert!(futures_util::poll!(queued.as_mut()).is_pending());
            if fixture.host.cancellation.tracked_count() == 1 {
                break;
            }
            fcp_async_core::task::yield_now().await;
        }
        assert_eq!(fixture.host.cancellation.tracked_count(), 1);
        if cancel {
            fixture
                .host
                .cancellation
                .cancel(
                    &CancellationRequest {
                        operation_id: request.request_id.clone(),
                        reason: fcp_host::CancelReason::UserRequested,
                        cleanup: fcp_host::CleanupBehavior::default(),
                        return_partial: false,
                        capability_token: None,
                    },
                    Some("user:test"),
                    Utc::now(),
                )
                .unwrap();
            assert!(queued.await.is_err());
        } else {
            let response = queued.await.unwrap();
            assert_eq!(response.phase, SimulatePhase::TimedOut);
            assert!(!response.would_succeed);
        }
        drop(owner);
        assert_eq!(
            fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
            prepared.instance_id
        );
        // Completion must release the cancellation registration for this ID.
        fixture
            .host
            .cancellation
            .track_operation(
                &request.request_id,
                Some("user:test"),
                CancellationScope::new(CONNECTOR, ConnectorArchetype::RequestResponse),
            )
            .unwrap();
        let response = fixture
            .invoke(fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, json!({})))
            .await
            .unwrap();
        assert_eq!(response.result.unwrap()["calls"], 1);
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_simulation_dropped_during_guest_execution_retires_its_instance() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let other = fixture.prepare(ZoneId::work(), OTHER).await;
    let request = Fixture::simulation(fixture.request(
        &prepared.instance_id,
        ZoneId::work(),
        ECHO,
        json!({"mode": "spin"}),
    ));
    let mut running = Box::pin(fixture.simulate(&request));
    assert!(futures_util::poll!(running.as_mut()).is_pending());
    drop(running);
    assert!(fixture.simulate(&request).await.is_err());
    assert_ne!(
        fixture.prepare(ZoneId::work(), ECHO).await.instance_id,
        prepared.instance_id
    );
    assert_eq!(
        fixture.prepare(ZoneId::work(), OTHER).await.instance_id,
        other.instance_id
    );
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
        None,
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

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn runtime_retirement_drains_every_zone_and_operation_and_seals_retained_references() {
    let fixture = Fixture::new().await;
    let mut prepared = Vec::new();
    for zone in [ZoneId::work(), ZoneId::private()] {
        for operation in [ECHO, OTHER] {
            let instance = fixture.prepare(zone.clone(), operation).await;
            prepared.push((zone.clone(), operation, instance.instance_id));
        }
    }
    assert!(fixture.connector.sessions.has_ready_session());
    fixture
        .connector
        .retire_runtime(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert!(!fixture.connector.sessions.has_ready_session());
    for (zone, operation, instance) in prepared {
        let slot = fixture
            .connector
            .sessions
            .existing_slot(&zone, &OperationId::from_static(operation))
            .unwrap()
            .unwrap();
        assert!(slot.guest.lock().await.is_none());
        assert!(!slot.ready.load(Ordering::Acquire));
        assert!(
            fixture
                .connector
                .prepare_session(&zone, &OperationId::from_static(operation))
                .await
                .is_err(),
            "a retained runtime cannot recreate a retired guest"
        );
        assert!(
            fixture
                .invoke(fixture.request(&instance, zone, operation, json!({})))
                .await
                .is_err()
        );
    }
    fixture
        .connector
        .retire_runtime(Instant::now() + Duration::from_secs(1))
        .await
        .expect("retirement remains idempotent through retained references");
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn runtime_retirement_fences_preparation_and_invocation_already_waiting_for_a_guest() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let zone = ZoneId::work();
    let operation = OperationId::from_static(ECHO);
    let slot = fixture
        .connector
        .sessions
        .existing_slot(&zone, &operation)
        .unwrap()
        .unwrap();
    let owner = slot.guest.lock().await;
    let mut prepare = Box::pin(fixture.connector.prepare_session(&zone, &operation));
    let mut invoke = Box::pin(fixture.invoke(fixture.request(
        &prepared.instance_id,
        zone.clone(),
        ECHO,
        json!({"must_not_run": true}),
    )));
    assert!(futures_util::poll!(prepare.as_mut()).is_pending());
    assert!(futures_util::poll!(invoke.as_mut()).is_pending());
    let mut retire = Box::pin(
        fixture
            .connector
            .retire_runtime(Instant::now() + Duration::from_secs(5)),
    );
    assert!(futures_util::poll!(retire.as_mut()).is_pending());
    assert!(fixture.connector.sessions.require_open().is_err());
    drop(owner);
    assert!(prepare.await.is_err());
    assert!(invoke.await.is_err());
    retire.await.unwrap();
    assert!(slot.guest.lock().await.is_none());
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn runtime_retirement_preserves_the_result_of_an_already_executing_guest() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let input = json!({"mode": "yield", "complete_once": true});
    let request = fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, input.clone());
    let request_id = request.id.clone();
    let mut invocation = Box::pin(fixture.invoke(request));
    assert!(
        futures_util::poll!(invocation.as_mut()).is_pending(),
        "finite guest work must yield while retaining its actual Store"
    );
    let mut retirement = Box::pin(
        fixture
            .connector
            .retire_runtime(Instant::now() + Duration::from_secs(5)),
    );
    assert!(futures_util::poll!(retirement.as_mut()).is_pending());
    let (response, retired) = futures_util::future::join(invocation, retirement).await;
    let response = response.expect("selected guest finishes with its real response during drain");
    retired.expect("retirement waits until the selected invocation released its Store");
    assert_eq!(response.id, request_id);
    let result = response.result.unwrap();
    assert_eq!(result["calls"], 1);
    assert_eq!(result["echo"], input);
    let slot = fixture
        .connector
        .sessions
        .existing_slot(&ZoneId::work(), &OperationId::from_static(ECHO))
        .unwrap()
        .unwrap();
    assert!(slot.guest.lock().await.is_none());
    assert!(
        fixture
            .invoke(fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, json!({})))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn timed_out_or_cancelled_runtime_retirement_keeps_admission_closed_until_replacement() {
    for cancel_waiter in [false, true] {
        let fixture = Fixture::new().await;
        let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
        let mut invocation = Box::pin(fixture.invoke(fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"mode": "spin"}),
        )));
        assert!(futures_util::poll!(invocation.as_mut()).is_pending());
        let started = Instant::now();
        let mut retirement = Box::pin(
            fixture
                .connector
                .retire_runtime(started + Duration::from_millis(30)),
        );
        assert!(futures_util::poll!(retirement.as_mut()).is_pending());
        if cancel_waiter {
            drop(retirement);
        } else {
            assert!(retirement.await.is_err());
            assert!(started.elapsed() < Duration::from_secs(2));
        }
        assert!(fixture.connector.sessions.require_open().is_err());
        assert!(
            fixture
                .connector
                .prepare_session(&ZoneId::private(), &OperationId::from_static(OTHER))
                .await
                .is_err(),
            "partial retirement must never admit another operation or zone"
        );
        // The active call was never replayed or replaced by retirement. Its
        // owner still controls cancellation, which drops the exact guest Store.
        drop(invocation);
        fixture
            .connector
            .retire_runtime(Instant::now() + Duration::from_secs(5))
            .await
            .expect("a retry drains the same sealed runtime after its owner exits");
        let slots: Vec<_> = fixture
            .connector
            .sessions
            .slots
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for slot in slots {
            assert!(slot.guest.lock().await.is_none());
        }
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn expired_runtime_retirement_cannot_seal_a_live_guest() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    assert!(
        fixture
            .connector
            .retire_runtime(Instant::now())
            .await
            .is_err()
    );
    let response = fixture
        .invoke(fixture.request(
            &prepared.instance_id,
            ZoneId::work(),
            ECHO,
            json!({"unchanged": true}),
        ))
        .await
        .unwrap();
    assert_eq!(response.result.unwrap()["calls"], 1);
}

async fn registered_runtime(fixture: &Fixture) -> Arc<WasiConnector> {
    let state = fixture.host.registry.state.read().await;
    let entry = &state.connectors[&ConnectorId::from_static(CONNECTOR)];
    let ConnectorRuntime::Wasi(runtime) = &entry.connector else {
        panic!("expected an enabled WASI runtime")
    };
    Arc::clone(runtime)
}

fn lifecycle_request(action: fcp_host::LifecycleAction) -> LifecycleTransitionRequest {
    LifecycleTransitionRequest {
        action,
        reason: Some("WASI runtime lifecycle regression".into()),
        initiated_by: Some("test".into()),
        dry_run: false,
    }
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn wasi_component_dormant_apply_binds_replacement_bytes_and_manifest() {
    use fcp_host::{DesiredRuntimeState, LifecycleAction};

    let fixture = Fixture::new().await;
    let connector_id = ConnectorId::from_static(CONNECTOR);
    fixture
        .host
        .lifecycle
        .reconcile_registered_connectors(&fixture.host.registry.list().await)
        .await
        .unwrap();
    fixture
        .host
        .lifecycle
        .set_desired_state(&connector_id, DesiredRuntimeState::Enabled, None)
        .await
        .unwrap();
    lifecycle_runtime::transition(
        &fixture.host,
        &connector_id,
        &lifecycle_request(LifecycleAction::Disable),
    )
    .await
    .unwrap();

    let config = fixture.connector.config.clone();
    let disabled_generation = fixture.host.registry.version();
    std::fs::write(&config.binary, b"incompatible dormant replacement").unwrap();
    let error = fixture
        .host
        .registry
        .apply_configs_with_lifecycle(vec![config.clone()], &fixture.host.lifecycle)
        .await
        .expect_err("dormant updates must validate bytes before replacing retained authority");
    assert!(error.to_string().contains("failed executable admission"));
    assert_eq!(fixture.host.registry.version(), disabled_generation);
    {
        let state = fixture.host.registry.state.read().await;
        let entry = &state.connectors[&connector_id];
        assert!(matches!(&entry.connector, ConnectorRuntime::Dormant(_)));
        assert!(Arc::ptr_eq(
            &fixture.connector.component.bytes,
            &entry.admitted_wasi_component().unwrap().bytes
        ));
    }
    let replacement = format!(
        "{}\n;; dormant inventory replacement\n",
        component_fixture()
    );
    std::fs::write(&config.binary, &replacement).unwrap();
    let manifest_path = config.manifest_path.as_ref().unwrap();
    let manifest = std::fs::read_to_string(manifest_path).unwrap();
    std::fs::write(
        manifest_path,
        format!("{manifest}\n# explicitly selected manifest\n"),
    )
    .unwrap();
    let generation = fixture.host.registry.version();
    for dry_run in [true, false] {
        let mut request = lifecycle_request(LifecycleAction::Enable);
        request.dry_run = dry_run;
        let error = lifecycle_runtime::transition(&fixture.host, &connector_id, &request)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("manifest changed after state admission"),
            "{error}"
        );
    }
    assert_eq!(fixture.host.registry.version(), generation);
    assert_eq!(
        fixture
            .host
            .lifecycle
            .connector_status(&connector_id)
            .await
            .unwrap()
            .desired_state,
        DesiredRuntimeState::Disabled
    );

    let preview = fixture
        .host
        .registry
        .preview_configs_with_lifecycle(vec![config.clone()], &fixture.host.lifecycle)
        .await
        .unwrap();
    assert_eq!(preview.updated, vec![CONNECTOR.to_owned()]);
    {
        let state = fixture.host.registry.state.read().await;
        let entry = &state.connectors[&connector_id];
        assert!(matches!(&entry.connector, ConnectorRuntime::Dormant(_)));
        assert!(Arc::ptr_eq(
            &fixture.connector.component.bytes,
            &entry.admitted_wasi_component().unwrap().bytes
        ));
    }
    assert_eq!(fixture.host.registry.version(), generation);

    let applied = fixture
        .host
        .registry
        .apply_configs_with_lifecycle(vec![config.clone()], &fixture.host.lifecycle)
        .await
        .unwrap();
    assert_eq!(applied.updated, vec![CONNECTOR.to_owned()]);
    let admitted_component = {
        let state = fixture.host.registry.state.read().await;
        let entry = &state.connectors[&connector_id];
        assert!(matches!(&entry.connector, ConnectorRuntime::Dormant(_)));
        let component = entry.admitted_wasi_component().unwrap().clone();
        assert_eq!(component.bytes.as_slice(), replacement.as_bytes());
        assert_ne!(component.digest, fixture.connector.component.digest);
        component
    };
    std::fs::write(&config.binary, b"changed after dormant inventory apply").unwrap();

    lifecycle_runtime::transition(
        &fixture.host,
        &connector_id,
        &lifecycle_request(LifecycleAction::Enable),
    )
    .await
    .unwrap();
    let current = registered_runtime(&fixture).await;
    assert!(Arc::ptr_eq(
        &admitted_component.bytes,
        &current.component.bytes
    ));
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let response = current
        .invoke_prepared(
            fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, json!({})),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.result.unwrap()["calls"], 1);
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn lifecycle_disable_enable_restart_and_uninstall_control_all_wasi_guests() {
    use fcp_host::{DesiredRuntimeState, LifecycleAction, ObservedRuntimeState};

    let fixture = Fixture::new().await;
    let first = fixture.prepare(ZoneId::work(), ECHO).await;
    fixture.prepare(ZoneId::private(), OTHER).await;
    let admitted_component = fixture.connector.component.clone();
    std::fs::write(
        &fixture.connector.config.binary,
        b"lifecycle transitions must never reopen this replacement",
    )
    .unwrap();
    let connector_id = ConnectorId::from_static(CONNECTOR);
    fixture
        .host
        .lifecycle
        .reconcile_registered_connectors(&fixture.host.registry.list().await)
        .await
        .unwrap();
    fixture
        .host
        .lifecycle
        .set_desired_state(&connector_id, DesiredRuntimeState::Enabled, None)
        .await
        .unwrap();
    let old_inventory = fixture
        .host
        .registry
        .inventory_fence(fixture.host.registry.version());
    let mut dry_run = lifecycle_request(LifecycleAction::Disable);
    dry_run.dry_run = true;
    lifecycle_runtime::transition(&fixture.host, &connector_id, &dry_run)
        .await
        .unwrap();
    assert!(fixture.connector.sessions.has_ready_session());
    old_inventory.require_current().unwrap();

    let disabled = lifecycle_runtime::transition(
        &fixture.host,
        &connector_id,
        &lifecycle_request(LifecycleAction::Disable),
    )
    .await
    .unwrap();
    assert_eq!(
        disabled.current_desired_state,
        DesiredRuntimeState::Disabled
    );
    assert_eq!(disabled.observed_state, ObservedRuntimeState::Stopped);
    assert!(
        !fixture
            .host
            .registry
            .get(&connector_id)
            .await
            .unwrap()
            .enabled
    );
    assert!(old_inventory.require_current().is_err());
    assert!(fixture.connector.sessions.require_open().is_err());
    assert!(
        fixture
            .invoke(fixture.request(&first.instance_id, ZoneId::work(), ECHO, json!({})))
            .await
            .is_err()
    );

    for action in [LifecycleAction::Enable, LifecycleAction::Restart] {
        let previous = if action == LifecycleAction::Enable {
            Arc::clone(&fixture.connector)
        } else {
            registered_runtime(&fixture).await
        };
        let enabled =
            lifecycle_runtime::transition(&fixture.host, &connector_id, &lifecycle_request(action))
                .await
                .unwrap();
        assert_eq!(enabled.current_desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(
            enabled.observed_state,
            ObservedRuntimeState::Degraded,
            "fresh WASI runtime must not claim readiness before explicit session preparation"
        );
        let current = registered_runtime(&fixture).await;
        assert!(!Arc::ptr_eq(&previous, &current));
        assert!(Arc::ptr_eq(
            &admitted_component.bytes,
            &current.component.bytes
        ));
        assert!(previous.sessions.require_open().is_err());
        assert!(!current.sessions.has_ready_session());
        let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
        assert_ne!(prepared.instance_id, first.instance_id);
        assert!(
            current
                .invoke_prepared(
                    fixture.request(&first.instance_id, ZoneId::work(), ECHO, json!({})),
                    None,
                    None,
                    None,
                )
                .await
                .is_err(),
            "replacement cannot inherit a capability for a retired guest"
        );
        let response = current
            .invoke_prepared(
                fixture.request(&prepared.instance_id, ZoneId::work(), ECHO, json!({})),
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(response.result.unwrap()["calls"], 1);
    }
    let retained = registered_runtime(&fixture).await;
    let uninstalled = lifecycle_runtime::transition(
        &fixture.host,
        &connector_id,
        &lifecycle_request(LifecycleAction::Uninstall),
    )
    .await
    .unwrap();
    assert_eq!(
        uninstalled.current_desired_state,
        DesiredRuntimeState::Uninstalled
    );
    assert_eq!(uninstalled.observed_state, ObservedRuntimeState::Missing);
    assert!(retained.sessions.require_open().is_err());
    assert!(
        !fixture
            .host
            .registry
            .get(&connector_id)
            .await
            .unwrap()
            .enabled
    );
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn abandoned_wasi_disable_preserves_durable_denial_and_enable_finishes_retirement() {
    use fcp_host::{DesiredRuntimeState, LifecycleAction, ObservedRuntimeState};

    let fixture = Fixture::new().await;
    let prepared = fixture.prepare(ZoneId::work(), ECHO).await;
    let connector_id = ConnectorId::from_static(CONNECTOR);
    fixture
        .host
        .lifecycle
        .reconcile_registered_connectors(&fixture.host.registry.list().await)
        .await
        .unwrap();
    fixture
        .host
        .lifecycle
        .set_desired_state(&connector_id, DesiredRuntimeState::Enabled, None)
        .await
        .unwrap();
    let generation = fixture.host.registry.version();
    let mut invocation = Box::pin(fixture.invoke(fixture.request(
        &prepared.instance_id,
        ZoneId::work(),
        ECHO,
        json!({"mode": "spin"}),
    )));
    assert!(futures_util::poll!(invocation.as_mut()).is_pending());
    let request = lifecycle_request(LifecycleAction::Disable);
    let mut disable = Box::pin(lifecycle_runtime::transition(
        &fixture.host,
        &connector_id,
        &request,
    ));
    assert!(futures_util::poll!(disable.as_mut()).is_pending());
    assert!(fixture.connector.sessions.require_open().is_err());
    drop(disable);
    let status = fixture
        .host
        .lifecycle
        .connector_status(&connector_id)
        .await
        .unwrap();
    assert_eq!(status.desired_state, DesiredRuntimeState::Disabled);
    assert_ne!(status.observed_state, ObservedRuntimeState::Stopped);
    assert_eq!(fixture.host.registry.version(), generation);
    assert!(
        fixture
            .host
            .lifecycle
            .connector_execution_fence(&connector_id)
            .await
            .is_err()
    );
    drop(invocation);
    lifecycle_runtime::transition(
        &fixture.host,
        &connector_id,
        &lifecycle_request(LifecycleAction::Enable),
    )
    .await
    .expect("enable must finish the retained runtime's retirement before replacement");
    let replacement = registered_runtime(&fixture).await;
    assert!(!Arc::ptr_eq(&fixture.connector, &replacement));
    assert!(fixture.connector.sessions.require_open().is_err());
    let fresh = fixture.prepare(ZoneId::work(), ECHO).await;
    assert_ne!(fresh.instance_id, prepared.instance_id);
    let response = replacement
        .invoke_prepared(
            fixture.request(&fresh.instance_id, ZoneId::work(), ECHO, json!({})),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.result.unwrap()["calls"], 1);
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
