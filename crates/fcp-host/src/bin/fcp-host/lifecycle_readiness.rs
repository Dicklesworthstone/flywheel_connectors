//! Record explicit readiness for authorized runtime owners after reconciliation.
//!
//! Passive custody reconciliation remains safe for denied or dormant entries.
//! Startup and successful inventory/lifecycle mutations additionally retain the
//! existing health observation behavior for enabled runtimes, without invoking
//! introspection or starting a WASI guest merely to learn readiness.

use fcp_host::{
    ConnectorExecutionFence, ConnectorRuntimeObservation, DesiredRuntimeState,
    ObservedRuntimeState, RuntimeStateObservation,
};

use super::*;

fn observation_error(error: HostError) -> LifecycleError {
    LifecycleError::Persistence {
        reason: error.to_string(),
    }
}

fn require_current(
    registry: &SubprocessRegistry,
    generation: u64,
    fences: &[ConnectorExecutionFence],
) -> Result<(), LifecycleError> {
    registry
        .require_generation(generation)
        .map_err(observation_error)?;
    for fence in fences {
        fence.require_current().map_err(observation_error)?;
    }
    Ok(())
}

async fn observe_enabled(
    registry: &SubprocessRegistry,
    lifecycle: &HostAdminStateStore,
    entry: &RegistryEntry,
    generation: u64,
) -> Result<Option<(ConnectorRuntimeObservation, ConnectorExecutionFence)>, LifecycleError> {
    if matches!(
        &entry.connector,
        ConnectorRuntime::Dormant(_) | ConnectorRuntime::UnavailableNativeProxyOnly(_)
    ) {
        return Ok(None);
    }
    let mut summary = entry.connector.static_summary();
    let status = lifecycle.connector_status(&summary.id).await?;
    if status.desired_state != DesiredRuntimeState::Enabled {
        return Ok(None);
    }
    let fence = match lifecycle.connector_execution_fence(&summary.id).await {
        Ok(fence) => fence,
        // Pending checkpoint custody independently denies execution even when
        // an older desired-state projection still says Enabled.
        Err(HostError::PreflightFailed(_)) => return Ok(None),
        Err(error) => return Err(observation_error(error)),
    };
    require_current(registry, generation, std::slice::from_ref(&fence))?;
    let health = match require_allowed_zones_configured(&summary.id, &entry.config.allowed_zones) {
        Err(error) => ConnectorHealth::unavailable(error.to_string()),
        Ok(()) => match &entry.connector {
            ConnectorRuntime::Native(native) => match native.health().await {
                Ok(snapshot) => merge_connector_health(
                    ConnectorHealth::from(&snapshot.status),
                    native.resilience.connector_health(&summary.id),
                ),
                Err(error) => ConnectorHealth::unavailable(format!("health check failed: {error}")),
            },
            ConnectorRuntime::NativeWarmPool(pool) => {
                match pool.runtime_retirement.require_open() {
                    Err(error) => ConnectorHealth::unavailable(error.to_string()),
                    Ok(()) => match pool.control.health().await {
                        Ok(snapshot) => merge_connector_health(
                            ConnectorHealth::from(&snapshot.status),
                            pool.control.resilience.connector_health(&summary.id),
                        ),
                        Err(error) => {
                            ConnectorHealth::unavailable(format!("health check failed: {error}"))
                        }
                    },
                }
            }
            ConnectorRuntime::Wasi(wasi) => {
                if wasi.sessions.has_ready_session() {
                    ConnectorHealth::healthy()
                } else {
                    ConnectorHealth::unavailable("WASI operation session has not been prepared")
                }
            }
            ConnectorRuntime::Dormant(_) | ConnectorRuntime::UnavailableNativeProxyOnly(_) => {
                unreachable!("dormant and unavailable owners are reconciled without health probes")
            }
        },
    };
    require_current(registry, generation, std::slice::from_ref(&fence))?;
    let observed = match &health {
        ConnectorHealth::Healthy => ObservedRuntimeState::Running,
        ConnectorHealth::Degraded { .. } | ConnectorHealth::Unavailable { .. } => {
            ObservedRuntimeState::Degraded
        }
    };
    summary.health = health;
    summary.last_health_check = Some(Utc::now());
    Ok(Some((
        ConnectorRuntimeObservation {
            summary,
            observed_state: RuntimeStateObservation::Observed(observed),
        },
        fence,
    )))
}

/// Reconcile inventory, then record readiness only for enabled exact owners.
/// The caller retains the inventory transaction, or has not started serving.
pub(super) async fn full(
    registry: &SubprocessRegistry,
    lifecycle: &HostAdminStateStore,
) -> Result<StartupReconciliationReport, LifecycleError> {
    let initial = registry.reconcile_lifecycle(lifecycle).await?;
    let (generation, entries, mut observations) = {
        let state = registry.state.read().await;
        let generation = registry.version.load(Ordering::SeqCst);
        let owners = registry
            .observation_owners
            .lock()
            .expect("runtime observation owner cache lock");
        let entries = state.connectors.values().cloned().collect::<Vec<_>>();
        let observations = entries
            .iter()
            .map(|entry| {
                let id = &entry.connector.static_summary().id;
                entry.connector.runtime_observation(owners.get(id))
            })
            .collect::<Vec<_>>();
        (generation, entries, observations)
    };
    let mut fences = Vec::new();
    for (entry, observation) in entries.iter().zip(&mut observations) {
        if let Some((readiness, fence)) =
            observe_enabled(registry, lifecycle, entry, generation).await?
        {
            *observation = readiness;
            fences.push(fence);
        }
    }
    let mut report = lifecycle
        .reconcile_runtime_observations_guarded(&observations, || {
            require_current(registry, generation, &fences)
        })
        .await?;
    let initial_entries = initial
        .entries
        .into_iter()
        .map(|entry| (entry.connector_id.clone(), entry))
        .collect::<HashMap<_, _>>();
    report.observed_updates = 0;
    for entry in &mut report.entries {
        let mut observed_changed = entry.observed_state_before != entry.observed_state_after;
        if let Some(before) = initial_entries.get(&entry.connector_id) {
            observed_changed |= before.observed_state_before != before.observed_state_after;
            entry.created_admin_state |= before.created_admin_state;
            entry.observed_state_before = before.observed_state_before;
            entry.updated |= before.updated;
        }
        report.observed_updates += usize::from(observed_changed);
    }
    report.created_connectors = report
        .entries
        .iter()
        .filter(|entry| entry.created_admin_state)
        .count();
    Ok(report)
}

/// Observe one lifecycle result without changing unrelated connector rows.
/// The caller retains the inventory transaction through this operation.
pub(super) async fn selected(
    registry: &SubprocessRegistry,
    lifecycle: &HostAdminStateStore,
    connector_id: &ConnectorId,
) -> Result<ConnectorAdminStatus, LifecycleError> {
    registry
        .reconcile_connector_lifecycle(lifecycle, connector_id)
        .await?;
    let (generation, entry) = {
        let state = registry.state.read().await;
        let generation = registry.version.load(Ordering::SeqCst);
        let entry = state.connectors.get(connector_id).cloned().ok_or_else(|| {
            LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            }
        })?;
        (generation, entry)
    };
    let Some((observation, fence)) =
        observe_enabled(registry, lifecycle, &entry, generation).await?
    else {
        // Authority may have changed while reading the selected owner. Return
        // the current committed denial, never the earlier enabled projection.
        return registry
            .reconcile_connector_lifecycle(lifecycle, connector_id)
            .await;
    };
    lifecycle
        .reconcile_runtime_observation_guarded(&observation, || {
            require_current(registry, generation, std::slice::from_ref(&fence))
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn readiness_probes_health_only_for_enabled_owners_without_pending_custody() {
        const CONNECTOR: &str = "fcp.telegram";
        let calls = Arc::new(AtomicU64::new(0));
        let fail_health = Arc::new(AtomicBool::new(false));
        let actor_calls = Arc::clone(&calls);
        let actor_failure = Arc::clone(&fail_health);
        let (sender, mut receiver) = mpsc::channel::<ConnectorRpcRequest>(4);
        let actor = task::spawn(async move {
            while let Some(request) = receiver.recv().await {
                actor_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.method, "health", "readiness never introspects");
                assert!(request.rpc.try_begin());
                let response = if actor_failure.load(Ordering::SeqCst) {
                    Err(std::io::Error::other("health transport refused"))
                } else {
                    Ok(json!({
                        "result": { "status": { "state": "ready" }, "uptime_ms": 0 }
                    }))
                };
                assert!(request.rpc.try_settle_reply());
                let _ = request.response_tx.send(response);
            }
        });
        let native = crate::tests::dispatcher_test_connector(CONNECTOR, sender, actor);
        let registry = crate::tests::dispatcher_registry_with_connector(
            CONNECTOR,
            native,
            crate::tests::dispatcher_test_config(CONNECTOR),
        );
        let directory = tempfile::tempdir().unwrap();
        let lifecycle =
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap();
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let _transaction = registry.inventory_transaction.lock().await;
        let report = full(&registry, &lifecycle).await.unwrap();
        assert_eq!(report.created_connectors, 1);
        assert_eq!(report.drifted_connectors, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            lifecycle
                .connector_status(&connector_id)
                .await
                .unwrap()
                .observed_state,
            ObservedRuntimeState::Running,
        );

        for desired in [
            DesiredRuntimeState::Disabled,
            DesiredRuntimeState::Uninstalled,
        ] {
            lifecycle
                .set_desired_state(&connector_id, desired, None)
                .await
                .unwrap();
            full(&registry, &lifecycle).await.unwrap();
            let status = selected(&registry, &lifecycle, &connector_id)
                .await
                .unwrap();
            assert_eq!(status.desired_state, desired);
            assert_eq!(status.observed_state, ObservedRuntimeState::Running);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }

        lifecycle
            .set_desired_state(&connector_id, DesiredRuntimeState::Enabled, None)
            .await
            .unwrap();
        fail_health.store(true, Ordering::SeqCst);
        let unavailable = selected(&registry, &lifecycle, &connector_id)
            .await
            .unwrap();
        assert_eq!(unavailable.observed_state, ObservedRuntimeState::Degraded);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let preparation = lifecycle
            .prepare_telegram_polling_restart(&connector_id)
            .await
            .unwrap();
        lifecycle
            .begin_telegram_polling_restart(
                &connector_id,
                &preparation,
                fcp_host::TelegramPollingRestartBinding {
                    config_digest: "11".repeat(32),
                    manifest_digest: "22".repeat(32),
                    binary_sha256: "33".repeat(32),
                    zone_id: "z:work".to_owned(),
                    bot_id: "123456".to_owned(),
                    state_root: "/fixture/telegram-state".to_owned(),
                },
            )
            .await
            .unwrap();
        full(&registry, &lifecycle).await.unwrap();
        let pending = selected(&registry, &lifecycle, &connector_id)
            .await
            .unwrap();
        assert_eq!(pending.desired_state, DesiredRuntimeState::Disabled);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            lifecycle
                .connector_execution_fence(&connector_id)
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn revocation_during_readiness_refuses_a_late_running_observation() {
        const CONNECTOR: &str = "fcp.test.readiness-revocation";
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (sender, mut receiver) = mpsc::channel::<ConnectorRpcRequest>(1);
        let actor = task::spawn(async move {
            let request = receiver.recv().await.unwrap();
            assert_eq!(request.method, "health");
            assert!(request.rpc.try_begin());
            let _ = started_tx.send(());
            release_rx.await.unwrap();
            assert!(request.rpc.try_settle_reply());
            let _ = request.response_tx.send(Ok(json!({
                "result": { "status": { "state": "ready" }, "uptime_ms": 0 }
            })));
        });
        let native = crate::tests::dispatcher_test_connector(CONNECTOR, sender, actor);
        let registry = crate::tests::dispatcher_registry_with_connector(
            CONNECTOR,
            native,
            crate::tests::dispatcher_test_config(CONNECTOR),
        );
        let lifecycle = Arc::new(HostAdminStateStore::new());
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let selected_registry = Arc::clone(&registry);
        let selected_lifecycle = Arc::clone(&lifecycle);
        let selected_id = connector_id.clone();
        let observation = task::spawn(async move {
            let _transaction = selected_registry.inventory_transaction.lock().await;
            selected(&selected_registry, &selected_lifecycle, &selected_id).await
        });
        started_rx.await.unwrap();
        lifecycle
            .set_desired_state(&connector_id, DesiredRuntimeState::Disabled, None)
            .await
            .unwrap();
        release_tx.send(()).unwrap();
        assert!(observation.await.unwrap().is_err());
        let current = lifecycle.connector_status(&connector_id).await.unwrap();
        assert_eq!(current.desired_state, DesiredRuntimeState::Disabled);
        assert_eq!(current.observed_state, ObservedRuntimeState::Unknown);
        assert!(
            lifecycle
                .connector_execution_fence(&connector_id)
                .await
                .is_err()
        );
    }
}
