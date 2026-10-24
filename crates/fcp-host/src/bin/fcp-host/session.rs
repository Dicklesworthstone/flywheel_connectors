//! Native connector authority preparation for instance-bound capability tokens.
//!
//! This endpoint is a control-plane read/negotiation, NOT token issuance.
//! The ordinary invoke path continues to enforce signatures, policy, leases,
//! approval, revocation and admission independently.

use super::*;
use fcp_core::CapabilityId;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrepareSessionRequest {
    zone_id: ZoneId,
}

#[derive(Debug, Serialize)]
pub(super) struct PreparedSession {
    connector_id: ConnectorId,
    zone_id: ZoneId,
    instance_id: InstanceId,
    protocol_version: &'static str,
}

type HttpFailure = (StatusCode, String);

// One budget for registry admission, session-lock admission, all negotiation
// RPCs, health validation, and the final runtime-identity check. Per-RPC IO
// timeouts alone do not bound a caller waiting to acquire the session lock.
const PREPARATION_TIMEOUT: Duration = CONNECTOR_RPC_IO_TIMEOUT;

fn preparation_timed_out() -> HttpFailure {
    failure(
        StatusCode::GATEWAY_TIMEOUT,
        "connector session preparation deadline expired; no instance authority was returned",
    )
}

async fn within_preparation_deadline<T>(
    started: Instant,
    budget: Duration,
    preparation: impl std::future::Future<Output = Result<T, HttpFailure>>,
) -> Result<T, HttpFailure> {
    let remaining = budget.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(preparation_timed_out());
    }
    let result = fcp_async_core::time::timeout(remaining, preparation)
        .await
        .map_err(|_| preparation_timed_out())?;
    // A ready future can consume the remaining budget without yielding back
    // to the timer. Never return authority obtained after the total deadline.
    if started.elapsed() >= budget {
        return Err(preparation_timed_out());
    }
    result
}

/// Request precisely the deduplicated capabilities declared by introspection.
/// A valid handshake is never a substitute for a signed invoke token.
pub(super) fn requested_capabilities(catalog: &Introspection) -> HostResult<Vec<CapabilityId>> {
    if catalog.operations.is_empty() {
        return Err(HostError::RegistryError(
            "connector declared no operations for handshake".into(),
        ));
    }
    let mut operations = BTreeMap::new();
    let mut capabilities = BTreeMap::new();
    for operation in &catalog.operations {
        if operations
            .insert(operation.id.as_str(), operation.capability.as_str())
            .is_some()
        {
            return Err(HostError::RegistryError(
                "connector declared duplicate operation IDs".into(),
            ));
        }
        capabilities.insert(
            operation.capability.as_str().to_owned(),
            operation.capability.clone(),
        );
    }
    Ok(capabilities.into_values().collect())
}

/// No grant may exceed the requested capabilities or claim an operation whose
/// catalog entry names another capability. A narrower grant is permitted.
pub(super) fn validate_negotiated_grants(
    request: &HandshakeRequest,
    response: &HandshakeResponse,
    catalog: &Introspection,
) -> HostResult<()> {
    if response.capabilities_granted.iter().any(|grant| {
        !request.capabilities_requested.contains(&grant.capability)
            || grant.operation.as_ref().is_some_and(|id| {
                !catalog.operations.iter().any(|operation| {
                    operation.id == *id && operation.capability == grant.capability
                })
            })
    }) {
        return Err(HostError::RegistryError(
            "connector returned unrequested capability grants".into(),
        ));
    }
    Ok(())
}

fn failure(status: StatusCode, message: &str) -> HttpFailure {
    (status, message.to_owned())
}

fn require_zone(allowed: &[String], zone: &ZoneId) -> Result<(), HttpFailure> {
    if !allowed.iter().any(|entry| entry == zone.as_str()) {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "connector is not bound to the requested zone",
        ));
    }
    Ok(())
}

/// Accept only the typed, ready health of the actual negotiated process,
/// not an instance ID supplied by an API caller or guessed by the host.
fn prepared_from_health(
    connector_id: ConnectorId,
    zone_id: ZoneId,
    value: Value,
) -> Result<PreparedSession, HttpFailure> {
    let invalid = || {
        failure(
            StatusCode::BAD_GATEWAY,
            "connector did not report a ready, authenticated native instance",
        )
    };
    let snapshot: HealthSnapshot = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if !snapshot.is_ready() {
        return Err(invalid());
    }
    let details = snapshot.details.as_ref().ok_or_else(invalid)?;
    if details.get("configured").and_then(Value::as_bool) != Some(true)
        || details.get("handshaken").and_then(Value::as_bool) != Some(true)
    {
        return Err(invalid());
    }
    let instance_id: InstanceId =
        serde_json::from_value(details.get("instance_id").cloned().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    if let Some(flat) = value.get("instance_id") {
        let flat: InstanceId = serde_json::from_value(flat.clone()).map_err(|_| invalid())?;
        if flat != instance_id {
            return Err(invalid());
        }
    }
    for field in ["configured", "handshaken"] {
        if value
            .get(field)
            .is_some_and(|flag| flag.as_bool() != Some(true))
        {
            return Err(invalid());
        }
    }
    Ok(PreparedSession {
        connector_id,
        zone_id,
        instance_id,
        protocol_version: "2.0",
    })
}

/// POST /rpc/admin/connectors/{connector_id}/session
///
/// Uses the on-demand native executor, not a warm-pool control process.
/// Instance identity is a snapshot, not a lease: reconfiguration or process
/// replacement can invalidate it before the issuer signs its token.
/// One end-to-end deadline includes registry and session admission. Expiration
/// drops only this preparation future, preserving per-command cancellation and
/// process-custody rules; it never aborts a shared runner by connector ID.
/// Negotiation may already have changed connector state before a timeout. No
/// authority is returned, and the host neither retries nor rolls those changes back.
pub(super) async fn prepare_handler(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PrepareSessionRequest>,
) -> Result<(HeaderMap, Json<PreparedSession>), HttpFailure> {
    let started = Instant::now();
    validate_admin_authorization(state.as_ref(), &headers).map_err(map_host_error)?;
    let connector_id = parse_connector_id(&connector_id)?;
    within_preparation_deadline(
        started,
        PREPARATION_TIMEOUT,
        prepare_session(state.as_ref(), connector_id, request.zone_id),
    )
    .await
}

async fn prepare_session(
    state: &AppState,
    connector_id: ConnectorId,
    zone_id: ZoneId,
) -> Result<(HeaderMap, Json<PreparedSession>), HttpFailure> {
    let connector = {
        let registry = state.registry.state.read().await;
        let entry = registry
            .connectors
            .get(&connector_id)
            .ok_or_else(|| failure(StatusCode::NOT_FOUND, "connector is not registered"))?;
        require_zone(&entry.config.allowed_zones, &zone_id)?;
        match &entry.connector {
            ConnectorRuntime::Native(native) => Arc::clone(native),
            _ => {
                return Err(failure(
                    StatusCode::CONFLICT,
                    "on-demand native connector required; warm-pool and WASI sessions unsupported",
                ));
            }
        }
    };
    if connector.capability_verifying_key.is_none() {
        return Err(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "host capability verification is not configured",
        ));
    }
    // This holds the same connector session lock through handshake + health.
    // Failed or cancelled preparation cannot publish cached authority.
    let health = connector
        .rpc_in_handshaken_zone(&zone_id, "health", json!({}))
        .await
        .map_err(|_| {
            failure(
                StatusCode::BAD_GATEWAY,
                "connector session preparation failed; no instance authority was returned",
            )
        })?;
    let prepared = prepared_from_health(connector_id.clone(), zone_id.clone(), health)?;
    // Ensure the process wasn't replaced during I/O. No registry lock is
    // held across subprocess I/O, and no snapshot can guarantee future life.
    {
        let registry = state.registry.state.read().await;
        let entry = registry.connectors.get(&connector_id).ok_or_else(|| {
            failure(
                StatusCode::CONFLICT,
                "connector changed during session preparation",
            )
        })?;
        require_zone(&entry.config.allowed_zones, &zone_id)?;
        if !matches!(&entry.connector, ConnectorRuntime::Native(current)
            if Arc::ptr_eq(current, &connector))
        {
            return Err(failure(
                StatusCode::CONFLICT,
                "connector changed during session preparation",
            ));
        }
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((response_headers, Json(prepared)))
}

#[cfg(test)]
#[path = "session/tests.rs"]
mod tests;

#[cfg(test)]
mod deadline_tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn expired_preparation_drops_unpolled_work_without_starting_it() {
        let polled = AtomicBool::new(false);
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropProbe(Arc::clone(&dropped));
        let budget = Duration::from_secs(1);
        let result = within_preparation_deadline(
            Instant::now() - budget,
            budget,
            async {
                let _guard = guard;
                polled.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert_eq!(result.unwrap_err(), preparation_timed_out());
        assert!(!polled.load(Ordering::SeqCst));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[fcp_async_core::runtime::test]
    async fn ready_results_and_early_failures_keep_their_original_meaning() {
        let value = json!({"instance_id": "fixture-instance"});
        assert_eq!(
            within_preparation_deadline(Instant::now(), PREPARATION_TIMEOUT, async {
                Ok(value.clone())
            })
            .await
            .unwrap(),
            value,
        );
        let denied = failure(StatusCode::FORBIDDEN, "fixture denial");
        let result = within_preparation_deadline::<()>(
            Instant::now(),
            PREPARATION_TIMEOUT,
            std::future::ready(Err(denied.clone())),
        )
        .await;
        assert_eq!(result.unwrap_err(), denied);
    }

    #[fcp_async_core::runtime::test]
    async fn ready_but_late_preparation_cannot_publish_authority() {
        let budget = Duration::from_millis(500);
        let polled = AtomicBool::new(false);
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropProbe(Arc::clone(&dropped));
        let result = within_preparation_deadline(Instant::now(), budget, async {
            let _guard = guard;
            polled.store(true, Ordering::SeqCst);
            // Deliberately do not yield: the outer timer cannot preempt a ready
            // synchronous stage. The post-completion deadline fence must win.
            std::thread::sleep(budget + Duration::from_millis(50));
            Ok(json!({"instance_id": "must-not-be-published"}))
        })
        .await;
        assert!(polled.load(Ordering::SeqCst));
        assert_eq!(result.unwrap_err(), preparation_timed_out());
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[fcp_async_core::runtime::test]
    async fn admission_timeout_preserves_the_current_session_owner() {
        let session = futures_util::lock::Mutex::new(None::<ZoneId>);
        let owner = session.lock().await;
        let entered = AtomicBool::new(false);
        let result = within_preparation_deadline(
            Instant::now(),
            Duration::from_millis(25),
            async {
                let mut zone = session.lock().await;
                entered.store(true, Ordering::SeqCst);
                *zone = Some(ZoneId::work());
                Ok(())
            },
        )
        .await;
        assert_eq!(result.unwrap_err(), preparation_timed_out());
        assert!(!entered.load(Ordering::SeqCst));
        assert!(session.try_lock().is_none(), "waiter must not unlock its owner");
        assert!(owner.is_none());
        drop(owner);
        within_preparation_deadline(Instant::now(), PREPARATION_TIMEOUT, async {
            *session.lock().await = Some(ZoneId::work());
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(*session.lock().await, Some(ZoneId::work()));
    }

    #[fcp_async_core::runtime::test]
    async fn abandoned_preparation_revokes_only_its_queued_rpc() {
        let (sender, mut receiver) = mpsc::channel::<ConnectorRpcRequest>(1);
        let rpc = NativeRpc::for_io();
        let waiter = rpc.waiter();
        let (response_tx, response_rx) = oneshot::channel();
        sender
            .send(ConnectorRpcRequest {
                method: "health".into(),
                params: json!({}),
                response_tx,
                rpc: rpc.clone(),
            })
            .await
            .unwrap();
        let mut preparation = Box::pin(within_preparation_deadline(
            Instant::now(),
            PREPARATION_TIMEOUT,
            async move {
                let _waiter = waiter;
                response_rx
                    .await
                    .map_err(|_| failure(StatusCode::BAD_GATEWAY, "reply channel closed"))?
                    .map_err(|_| failure(StatusCode::BAD_GATEWAY, "RPC failed"))
            },
        ));
        assert!(futures_util::poll!(preparation.as_mut()).is_pending());
        drop(preparation);
        assert!(rpc.is_settled());
        let discarded = receiver.recv().await.unwrap();
        assert!(!discarded.rpc.try_begin(), "abandoned preparation must not execute later");
        let next = NativeRpc::for_io();
        assert!(next.try_begin());
        rpc.cancel();
        assert!(!next.is_cancelled());
        assert!(next.try_settle_reply());
    }

    #[test]
    fn preparation_deadline_preserves_send_for_handler_composition() {
        fn assert_send<T: Send>(_: T) {}
        assert_send(within_preparation_deadline(
            Instant::now(),
            PREPARATION_TIMEOUT,
            std::future::ready(Ok::<_, HttpFailure>(HeaderMap::new())),
        ));
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn preparation_timeout_retires_a_selected_real_native_process() {
        let runner = ConnectorProcessRunner::spawn(
            "/bin/sh",
            &["-c".into(), "IFS= read -r request || exit 1; exec sleep 30".into()],
            &BTreeMap::new(),
        )
        .await
        .unwrap();
        let (sender, receiver) = mpsc::channel::<ConnectorRpcRequest>(1);
        let actor = task::try_spawn(native_rpc::run_dispatcher(runner, receiver)).unwrap();
        let rpc = NativeRpc::for_io();
        let waiter = rpc.waiter();
        let (response_tx, response_rx) = oneshot::channel();
        sender
            .send(ConnectorRpcRequest {
                method: "health".into(),
                params: json!({}),
                response_tx,
                rpc: rpc.clone(),
            })
            .await
            .unwrap();
        fcp_async_core::time::timeout(Duration::from_secs(2), async {
            while !rpc.is_active() {
                fcp_async_core::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("production dispatcher must select the blocked health RPC");
        let result = within_preparation_deadline(
            Instant::now(),
            Duration::from_millis(25),
            async move {
                let _waiter = waiter;
                response_rx
                    .await
                    .map_err(|_| failure(StatusCode::BAD_GATEWAY, "reply channel closed"))?
                    .map_err(|_| failure(StatusCode::BAD_GATEWAY, "RPC failed"))
            },
        )
        .await;
        assert_eq!(result.unwrap_err(), preparation_timed_out());
        fcp_async_core::time::timeout(Duration::from_secs(3), async {
            while !rpc.is_settled() {
                fcp_async_core::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("deadline must revoke the waiter and retain custody until observed child exit");
        assert!(rpc.transport_retired());
        fcp_async_core::time::timeout(Duration::from_secs(2), actor)
            .await
            .unwrap()
            .unwrap();
        assert!(sender.is_closed());
    }
}
