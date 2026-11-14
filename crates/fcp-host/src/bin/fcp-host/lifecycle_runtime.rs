//! Apply persisted lifecycle intent to actual connector runtime ownership.
//!
//! Dormant entries retain their managed configuration and admitted manifest but
//! never start a process or prepare a guest. Native retirement uses the exact
//! process owner, not a PID lookup or a replacement with the same connector ID.
//! WASI retirement seals the exact runtime and drains all retained guest stores.
//! Warm-pool retirement seals creation and drains every admitted physical child.

use fcp_host::{
    ConnectorExecutionFence, DesiredRuntimeState, LifecycleAction, ObservedRuntimeState,
};

use super::*;

const TRANSITION_TIMEOUT: Duration = Duration::from_secs(30);

fn require_deadline(deadline: Instant) -> HostResult<()> {
    if Instant::now() >= deadline {
        return Err(HostError::Unavailable(
            "lifecycle runtime transition exceeded its deadline; inspect desired and observed state before retrying"
                .to_owned(),
        ));
    }
    Ok(())
}

const fn denies_execution(desired: DesiredRuntimeState) -> bool {
    matches!(
        desired,
        DesiredRuntimeState::Disabled | DesiredRuntimeState::Uninstalled
    )
}

pub(super) struct DormantConnector {
    summary: ConnectorSummary,
    desired: DesiredRuntimeState,
}

impl DormantConnector {
    fn new(config: &ConnectorConfig, desired: DesiredRuntimeState) -> HostResult<Self> {
        let mut summary = connector_summary_from_config(config)?;
        summary.enabled = false;
        summary.health = ConnectorHealth::unavailable(
            "connector runtime is dormant under persisted lifecycle authority",
        );
        Ok(Self { summary, desired })
    }

    pub(super) fn summary(&self) -> ConnectorSummary {
        self.summary.clone()
    }

    pub(super) fn refusal(&self) -> HostError {
        HostError::PreflightFailed(format!(
            "connector `{}` has no active runtime under persisted {:?} lifecycle intent; explicitly enable it before preparing a session or invoking it",
            self.summary.id, self.desired
        ))
    }

    pub(super) fn self_check(&self) -> SelfCheckReport {
        SelfCheckReport::degraded("lifecycle_dormant", self.refusal().to_string())
    }
}

/// A fresh authority capture belongs to preparation, and is checked again at
/// publication. Inventory reload never turns a disabled record into authority.
pub(super) enum LaunchAuthority {
    Permitted(ConnectorExecutionFence),
    Dormant(DesiredRuntimeState),
}

impl LaunchAuthority {
    pub(super) async fn capture(
        lifecycle: &HostAdminStateStore,
        connector_id: &ConnectorId,
    ) -> HostResult<Self> {
        let desired = lifecycle
            .connector_state(connector_id)
            .await
            .map_or(DesiredRuntimeState::Unspecified, |state| {
                state.desired_state
            });
        if denies_execution(desired) {
            Ok(Self::Dormant(desired))
        } else {
            lifecycle
                .connector_execution_fence(connector_id)
                .await
                .map(Self::Permitted)
        }
    }

    pub(super) fn into_fence(self) -> Option<ConnectorExecutionFence> {
        match self {
            Self::Permitted(fence) => Some(fence),
            Self::Dormant(_) => None,
        }
    }
}

/// Keep inventory visibility separate from mesh execution advertisements. A
/// failed stop can leave a retained native actor, but durable denial still
/// removes it from routing without probing or starting any runtime.
pub(super) async fn advertised_connectors(
    registry: &SubprocessRegistry,
    lifecycle: &HostAdminStateStore,
) -> Vec<fcp_mesh::invoke_route::AdvertisedConnector> {
    let mut admitted = Vec::new();
    for connector in registry.advertised_connectors().await {
        let Ok(connector_id) = connector.connector_id.parse::<ConnectorId>() else {
            continue;
        };
        if let Ok(fence) = lifecycle.connector_execution_fence(&connector_id).await {
            admitted.push((connector, fence));
        }
    }
    admitted
        .into_iter()
        .filter_map(|(connector, fence)| fence.require_current().is_ok().then_some(connector))
        .collect()
}

pub(super) fn dormant_entry(
    config: ConnectorConfig,
    admitted: ValidatedConnectorConfig,
    desired: DesiredRuntimeState,
) -> HostResult<RegistryEntry> {
    let connector = ConnectorRuntime::Dormant(Arc::new(DormantConnector::new(&config, desired)?));
    Ok(RegistryEntry {
        config,
        connector,
        manifest_constraints: admitted.manifest_constraints,
        state_policy: admitted.state_policy,
    })
}

pub(super) async fn prepare_entry(
    config: ConnectorConfig,
    admitted: ValidatedConnectorConfig,
    resilience: Arc<ResilienceLayer>,
    capability_verifying_key: Option<[u8; PUBLIC_KEY_SIZE]>,
    authority: LaunchAuthority,
) -> HostResult<(RegistryEntry, Option<ConnectorExecutionFence>)> {
    match authority {
        LaunchAuthority::Dormant(desired) => Ok((dormant_entry(config, admitted, desired)?, None)),
        LaunchAuthority::Permitted(fence) => {
            fence.require_current()?;
            let entry = build_registry_entry_with_admission(
                config,
                admitted,
                resilience,
                capability_verifying_key,
            )
            .await?;
            fence.require_current()?;
            Ok((entry, Some(fence)))
        }
    }
}

/// A reload may retain a dormant configuration. It must not silently drop a
/// live runtime merely because the durable desired state changed elsewhere.
pub(super) fn require_dormant_replacement(current: Option<&RegistryEntry>) -> HostResult<()> {
    if current.is_some_and(|entry| {
        !matches!(
            &entry.connector,
            ConnectorRuntime::Dormant(_) | ConnectorRuntime::UnavailableNativeProxyOnly(_)
        )
    }) {
        return Err(HostError::Unavailable(
            "disabled connector still owns a runtime; complete its lifecycle disable before replacing managed configuration"
                .to_owned(),
        ));
    }
    Ok(())
}

fn stateless_retirement_supported(entry: &RegistryEntry) -> HostResult<()> {
    if matches!(
        &entry.connector,
        ConnectorRuntime::Dormant(_) | ConnectorRuntime::UnavailableNativeProxyOnly(_)
    ) {
        return Ok(());
    }
    if !matches!(
        &entry.connector,
        ConnectorRuntime::Native(_)
            | ConnectorRuntime::NativeWarmPool(_)
            | ConnectorRuntime::Wasi(_)
    ) || entry.state_policy.model != ConnectorStateKind::Stateless
        || entry.state_policy.manifest_digest.is_none()
    {
        return Err(HostError::Unavailable(
            "runtime retirement requires an admitted stateless native or WASI connector; canonical state handoff is not available"
                .to_owned(),
        ));
    }
    entry.state_policy.require_admitted_manifest(&entry.config)
}

fn restart_supported(entry: &RegistryEntry) -> HostResult<()> {
    if entry.state_policy.model != ConnectorStateKind::Stateless
        || entry.state_policy.manifest_digest.is_none()
        || !matches!(
            entry.config.prewarm.strategy,
            PrewarmStrategy::OnDemand | PrewarmStrategy::WarmPool
        )
        || !matches!(
            &entry.connector,
            ConnectorRuntime::Native(_)
                | ConnectorRuntime::NativeWarmPool(_)
                | ConnectorRuntime::Wasi(_)
                | ConnectorRuntime::Dormant(_)
        )
    {
        return Err(HostError::Unavailable(
            "live restart requires an admitted stateless native or WASI connector with a supported prewarm strategy; canonical state handoff is not available"
                .to_owned(),
        ));
    }
    entry.state_policy.require_admitted_manifest(&entry.config)
}

async fn selected_entry(
    registry: &SubprocessRegistry,
    connector_id: &ConnectorId,
) -> HostResult<(RegistryEntry, u64)> {
    let state = registry.state.read().await;
    let entry = state
        .connectors
        .get(connector_id)
        .cloned()
        .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
    Ok((entry, registry.version.load(Ordering::SeqCst)))
}

/// The caller holds the inventory transaction through preparation, durable
/// intent changes, retirement and this publication. The generation check also
/// protects against direct registry users outside the administrative handlers.
async fn publish_entry(
    registry: &SubprocessRegistry,
    connector_id: &ConnectorId,
    entry: RegistryEntry,
    generation: u64,
    execution_fence: Option<&ConnectorExecutionFence>,
    deadline: Instant,
) -> HostResult<u64> {
    let next_generation = generation.checked_add(1).ok_or_else(|| {
        HostError::Unavailable("connector inventory generation is exhausted".to_owned())
    })?;
    let mut state = registry.state.write().await;
    require_deadline(deadline)?;
    registry.require_generation(generation)?;
    if let Some(fence) = execution_fence {
        fence.require_current()?;
    }
    if !state.connectors.contains_key(connector_id) {
        return Err(HostError::ConnectorNotFound(connector_id.to_string()));
    }
    registry.version.store(next_generation, Ordering::SeqCst);
    let retired = state.connectors.insert(connector_id.clone(), entry);
    drop(state);
    drop(retired);
    Ok(next_generation)
}

async fn observe_transition(
    state: &AppState,
    connector_id: &ConnectorId,
    mut response: LifecycleTransitionResponse,
) -> HostResult<LifecycleTransitionResponse> {
    let summary = state
        .registry
        .get(connector_id)
        .await
        .ok_or_else(|| HostError::ConnectorNotFound(connector_id.to_string()))?;
    let observed = if !summary.enabled {
        ObservedRuntimeState::Stopped
    } else {
        match summary.health {
            ConnectorHealth::Healthy => ObservedRuntimeState::Running,
            ConnectorHealth::Degraded { .. } => ObservedRuntimeState::Degraded,
            // A failed health RPC is not proof that a native child or a guest
            // stopped. Only publishing a dormant entry confirms retirement.
            ConnectorHealth::Unavailable { .. } => ObservedRuntimeState::Degraded,
        }
    };
    state
        .lifecycle
        .set_observed_state(connector_id, observed, Some("runtime-lifecycle".to_owned()))
        .await
        .map_err(map_lifecycle_host_error)?;
    let status = state
        .lifecycle
        .connector_status(connector_id)
        .await
        .map_err(map_lifecycle_host_error)?;
    response.observed_state = status.observed_state;
    response.journal_sequence = status.last_journal_sequence;
    Ok(response)
}

async fn retire_selected(
    registry: &SubprocessRegistry,
    connector_id: &ConnectorId,
    entry: &RegistryEntry,
    generation: u64,
    desired: DesiredRuntimeState,
    deadline: Instant,
) -> HostResult<u64> {
    require_deadline(deadline)?;
    generation.checked_add(1).ok_or_else(|| {
        HostError::Unavailable("connector inventory generation is exhausted".to_owned())
    })?;
    registry.require_generation(generation)?;
    stateless_retirement_supported(entry)?;
    match &entry.connector {
        ConnectorRuntime::Native(native) => native.retire_runtime(deadline).await?,
        ConnectorRuntime::NativeWarmPool(pool) => pool.retire_runtime(deadline).await?,
        ConnectorRuntime::Wasi(wasi) => wasi.retire_runtime(deadline).await?,
        ConnectorRuntime::Dormant(_) | ConnectorRuntime::UnavailableNativeProxyOnly(_) => {}
    }
    let dormant = dormant_entry(
        entry.config.clone(),
        ValidatedConnectorConfig {
            manifest_constraints: entry.manifest_constraints.clone(),
            state_policy: entry.state_policy,
        },
        desired,
    )?;
    publish_entry(registry, connector_id, dormant, generation, None, deadline).await
}

async fn activate_selected(
    state: &AppState,
    connector_id: &ConnectorId,
    entry: &RegistryEntry,
    generation: u64,
    request: &LifecycleTransitionRequest,
    deadline: Instant,
) -> HostResult<LifecycleTransitionResponse> {
    require_deadline(deadline)?;
    generation.checked_add(1).ok_or_else(|| {
        HostError::Unavailable("connector inventory generation is exhausted".to_owned())
    })?;
    state.registry.require_generation(generation)?;
    let admitted = validate_registry_config(&entry.config)?;
    validate_state_policy_replacement(connector_id, entry, admitted.state_policy)?;
    // Explicit Enable/Restart authorizes preparation while durable dispatch
    // authority remains disabled. Preparation failure drops the candidate and
    // cannot make ordinary invokes eligible against the dormant registry.
    require_deadline(deadline)?;
    let replacement = build_registry_entry_with_admission(
        entry.config.clone(),
        admitted,
        Arc::clone(&state.registry.resilience),
        state.registry.capability_verifying_key,
    )
    .await?;
    if matches!(
        &replacement.connector,
        ConnectorRuntime::UnavailableNativeProxyOnly(_)
    ) {
        return Err(HostError::Unavailable(
            "connector runtime cannot be enabled because its required native sandbox is unavailable"
                .to_owned(),
        ));
    }
    replacement
        .state_policy
        .require_admitted_manifest(&replacement.config)?;
    require_deadline(deadline)?;
    state.registry.require_generation(generation)?;
    let response = state
        .lifecycle
        .execute_lifecycle_transition(connector_id, request)
        .await
        .map_err(map_lifecycle_host_error)?;
    let fence = state
        .lifecycle
        .connector_execution_fence(connector_id)
        .await?;
    publish_entry(
        &state.registry,
        connector_id,
        replacement,
        generation,
        Some(&fence),
        deadline,
    )
    .await?;
    observe_transition(state, connector_id, response).await
}

pub(super) async fn transition(
    state: &AppState,
    connector_id: &ConnectorId,
    request: &LifecycleTransitionRequest,
) -> HostResult<LifecycleTransitionResponse> {
    let deadline = Instant::now() + TRANSITION_TIMEOUT;
    let result = fcp_async_core::time::timeout(
        TRANSITION_TIMEOUT,
        transition_before(state, connector_id, request, deadline),
    )
    .await
    .map_err(|_| {
        HostError::Unavailable(
            "lifecycle runtime transition exceeded its deadline; inspect desired and observed state before retrying"
                .to_owned(),
        )
    })?;
    require_deadline(deadline)?;
    result
}

async fn transition_before(
    state: &AppState,
    connector_id: &ConnectorId,
    request: &LifecycleTransitionRequest,
    deadline: Instant,
) -> HostResult<LifecycleTransitionResponse> {
    let _transaction = state.registry.inventory_transaction.lock().await;
    require_deadline(deadline)?;
    let (entry, generation) = selected_entry(&state.registry, connector_id).await?;
    let previous = state
        .lifecycle
        .connector_status(connector_id)
        .await
        .map_err(map_lifecycle_host_error)?;

    if request.action == LifecycleAction::Reload {
        return Err(HostError::Unavailable(
            "in-place connector reload is unavailable; apply managed configuration or explicitly restart a stateless native or WASI connector"
                .to_owned(),
        ));
    }
    if request.action == LifecycleAction::Restart {
        restart_supported(&entry)?;
    }
    let dormant = matches!(&entry.connector, ConnectorRuntime::Dormant(_));
    if request.action == LifecycleAction::Promote
        && (dormant || denies_execution(previous.desired_state))
    {
        return Err(HostError::Unavailable(
            "enable the disabled connector before promoting its deployment".to_owned(),
        ));
    }
    if request.action == LifecycleAction::Enable
        && matches!(
            &entry.connector,
            ConnectorRuntime::UnavailableNativeProxyOnly(_)
        )
    {
        return Err(HostError::Unavailable(
            "connector runtime cannot be enabled because its required native sandbox is unavailable"
                .to_owned(),
        ));
    }
    // A previously denied but retained runtime may be poisoned or still
    // draining after an earlier failure. Never reauthorize that actor in place.
    let recover_retained = request.action == LifecycleAction::Enable
        && denies_execution(previous.desired_state)
        && !dormant;
    if recover_retained {
        restart_supported(&entry)?;
    }
    if request.dry_run {
        if matches!(
            request.action,
            LifecycleAction::Disable | LifecycleAction::Uninstall
        ) {
            stateless_retirement_supported(&entry)?;
        }
        if request.action == LifecycleAction::Enable {
            let admitted = validate_registry_config(&entry.config)?;
            if dormant {
                validate_state_policy_replacement(connector_id, &entry, admitted.state_policy)?;
            }
        }
        return state
            .lifecycle
            .execute_lifecycle_transition(connector_id, request)
            .await
            .map_err(map_lifecycle_host_error);
    }

    require_deadline(deadline)?;
    match request.action {
        LifecycleAction::Disable | LifecycleAction::Uninstall => {
            // Deny new/queued effects durably before waiting for a process. An
            // unsupported or timed-out retirement must never lift this denial.
            let response = state
                .lifecycle
                .execute_lifecycle_transition(connector_id, request)
                .await
                .map_err(map_lifecycle_host_error)?;
            retire_selected(
                &state.registry,
                connector_id,
                &entry,
                generation,
                response.current_desired_state,
                deadline,
            )
            .await?;
            observe_transition(state, connector_id, response).await
        }
        LifecycleAction::Restart | LifecycleAction::Enable
            if recover_retained || request.action == LifecycleAction::Restart =>
        {
            state
                .lifecycle
                .set_desired_state(
                    connector_id,
                    DesiredRuntimeState::Disabled,
                    request.initiated_by.clone(),
                )
                .await
                .map_err(map_lifecycle_host_error)?;
            let generation = retire_selected(
                &state.registry,
                connector_id,
                &entry,
                generation,
                DesiredRuntimeState::Disabled,
                deadline,
            )
            .await?;
            state
                .lifecycle
                .set_observed_state(
                    connector_id,
                    ObservedRuntimeState::Stopped,
                    Some("runtime-lifecycle".to_owned()),
                )
                .await
                .map_err(map_lifecycle_host_error)?;
            let (dormant, _) = selected_entry(&state.registry, connector_id).await?;
            let mut response =
                activate_selected(state, connector_id, &dormant, generation, request, deadline)
                    .await?;
            response.previous_desired_state = previous.desired_state;
            Ok(response)
        }
        LifecycleAction::Enable if dormant => {
            activate_selected(state, connector_id, &entry, generation, request, deadline).await
        }
        LifecycleAction::Enable | LifecycleAction::Promote => {
            let response = state
                .lifecycle
                .execute_lifecycle_transition(connector_id, request)
                .await
                .map_err(map_lifecycle_host_error)?;
            observe_transition(state, connector_id, response).await
        }
        LifecycleAction::Restart => unreachable!("restart always selects runtime replacement"),
        LifecycleAction::Reload => unreachable!("reload is refused before lifecycle mutation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECTOR: &str = "fcp.test.lifecycle";

    fn request(action: LifecycleAction) -> LifecycleTransitionRequest {
        LifecycleTransitionRequest {
            action,
            reason: Some("lifecycle runtime regression".to_owned()),
            initiated_by: Some("test".to_owned()),
            dry_run: false,
        }
    }

    fn native_config(directory: &StdPath, model: &str) -> ConnectorConfig {
        let path = directory.join("manifest.toml");
        std::fs::write(
            &path,
            crate::tests::state_policy_test_manifest_for(CONNECTOR, Some(model), false),
        )
        .expect("write admitted state manifest");
        let mut config = crate::tests::subprocess_test_connector_config(CONNECTOR);
        config.manifest_path = Some(path.to_string_lossy().into_owned());
        config
    }

    #[cfg(unix)]
    fn shell_warm_pool_config(directory: &StdPath) -> ConnectorConfig {
        let manifest = directory.join("manifest.toml");
        std::fs::write(
            &manifest,
            crate::tests::state_policy_test_manifest_for(CONNECTOR, Some("stateless"), false),
        )
        .expect("write admitted warm-pool manifest");
        let mut config = crate::tests::dispatcher_test_config(CONNECTOR);
        config.binary = "/bin/sh".to_owned();
        config.args = vec![
            "-c".to_owned(),
            r#"while IFS= read -r request; do
  id=$(printf '%s' "$request" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  case "$request" in
    *'"method":"health"'*)
      result='{"status":{"state":"ready"},"uptime_ms":0,"details":{"configured":true}}' ;;
    *'"method":"introspect"'*)
      result='{"operations":[],"events":[],"resource_types":[]}' ;;
    *) result='{}' ;;
  esac
  printf '{"jsonrpc":"2.0","id":"%s","result":%s}\n' "$id" "$result"
done"#
                .to_owned(),
        ];
        config.config = Some(json!({}));
        config.manifest_path = Some(manifest.to_string_lossy().into_owned());
        config.prewarm = fcp_host::ConnectorPrewarmConfig::warm_pool(
            2,
            2,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        config
    }

    async fn app(config: ConnectorConfig, desired: DesiredRuntimeState) -> Arc<AppState> {
        let connector_id = config.id.parse().expect("connector id");
        let lifecycle = Arc::new(HostAdminStateStore::new());
        lifecycle
            .set_desired_state(&connector_id, desired, None)
            .await
            .expect("persist initial intent");
        let registry = Arc::new(
            SubprocessRegistry::from_configs_with_lifecycle(vec![config], None, &lifecycle)
                .await
                .expect("construct lifecycle-aware registry"),
        );
        lifecycle
            .reconcile_registered_connectors(&registry.list().await)
            .await
            .expect("observe initial runtime");
        crate::tests::dispatcher_app_state(registry, lifecycle, None, HashMap::new())
    }

    async fn native(state: &AppState, connector_id: &ConnectorId) -> Arc<SubprocessConnector> {
        let (entry, _) = selected_entry(&state.registry, connector_id)
            .await
            .expect("retained inventory");
        let ConnectorRuntime::Native(native) = entry.connector else {
            panic!("expected an active on-demand native runtime");
        };
        native
    }

    #[cfg(unix)]
    async fn warm_pool(
        state: &AppState,
        connector_id: &ConnectorId,
    ) -> Arc<NativeWarmPoolConnector> {
        let (entry, _) = selected_entry(&state.registry, connector_id)
            .await
            .expect("retained warm-pool inventory");
        let ConnectorRuntime::NativeWarmPool(pool) = entry.connector else {
            panic!("expected an active native warm pool");
        };
        pool
    }

    #[cfg(unix)]
    async fn retained_pool_processes(
        pool: &NativeWarmPoolConnector,
    ) -> Vec<Arc<SubprocessConnector>> {
        let entries = pool.entries.lock().await;
        assert_eq!(entries.len(), 2, "fixture starts two real idle workers");
        std::iter::once(Arc::clone(&pool.control))
            .chain(entries.iter().map(|entry| Arc::clone(&entry.connector)))
            .collect()
    }

    async fn assert_dormant(state: &AppState, connector_id: &ConnectorId) {
        let (entry, _) = selected_entry(&state.registry, connector_id).await.unwrap();
        assert!(matches!(entry.connector, ConnectorRuntime::Dormant(_)));
        assert!(!state.registry.get(connector_id).await.unwrap().enabled);
        assert!(
            state
                .registry
                .get_introspection(connector_id)
                .await
                .is_none()
        );
        assert!(
            advertised_connectors(&state.registry, &state.lifecycle)
                .await
                .is_empty()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn persisted_disabled_and_uninstalled_inventory_never_launches_on_startup_or_reload() {
        for desired in [
            DesiredRuntimeState::Disabled,
            DesiredRuntimeState::Uninstalled,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let state_path = directory.path().join("admin.json");
            let connector_id = ConnectorId::from_static(CONNECTOR);
            let lifecycle = HostAdminStateStore::with_state_path(state_path.clone()).unwrap();
            lifecycle
                .set_desired_state(&connector_id, desired, None)
                .await
                .unwrap();
            drop(lifecycle);
            let lifecycle = Arc::new(HostAdminStateStore::with_state_path(state_path).unwrap());
            let mut config = crate::tests::dispatcher_test_config(CONNECTOR);
            config.binary = directory
                .path()
                .join("missing-connector")
                .display()
                .to_string();
            let registry = Arc::new(
                SubprocessRegistry::from_configs_with_lifecycle(
                    vec![config.clone()],
                    None,
                    &lifecycle,
                )
                .await
                .expect("persisted denial must suppress even attempted executable launch"),
            );
            lifecycle
                .reconcile_registered_connectors(&registry.list().await)
                .await
                .unwrap();
            let state =
                crate::tests::dispatcher_app_state(registry, lifecycle, None, HashMap::new());
            assert_dormant(&state, &connector_id).await;
            config.description = Some("updated dormant inventory".to_owned());
            state
                .registry
                .preview_configs_with_lifecycle(vec![config.clone()], &state.lifecycle)
                .await
                .expect("dormant managed preview does not require a runnable binary");
            state
                .registry
                .apply_configs_with_lifecycle(vec![config.clone()], &state.lifecycle)
                .await
                .expect("managed reload retains dormant runtime authority");
            assert_dormant(&state, &connector_id).await;
            assert_eq!(
                selected_entry(&state.registry, &connector_id)
                    .await
                    .unwrap()
                    .0
                    .config,
                config
            );
            let status = state
                .lifecycle
                .connector_status(&connector_id)
                .await
                .unwrap();
            assert_eq!(status.desired_state, desired);
            assert_eq!(status.observed_state, ObservedRuntimeState::Stopped);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn enable_preview_and_failed_launch_leave_dormant_authority_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::tests::dispatcher_test_config(CONNECTOR);
        config.binary = directory
            .path()
            .join("missing-connector")
            .display()
            .to_string();
        let state = app(config, DesiredRuntimeState::Disabled).await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let generation = state.registry.version();
        let before = state
            .lifecycle
            .connector_status(&connector_id)
            .await
            .unwrap();
        let mut preview = request(LifecycleAction::Enable);
        preview.dry_run = true;
        let response = transition(&state, &connector_id, &preview).await.unwrap();
        assert!(response.dry_run);
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
        for action in [
            LifecycleAction::Enable,
            LifecycleAction::Reload,
            LifecycleAction::Promote,
        ] {
            assert!(
                transition(&state, &connector_id, &request(action))
                    .await
                    .is_err()
            );
        }
        assert_dormant(&state, &connector_id).await;
        let after = state
            .lifecycle
            .connector_status(&connector_id)
            .await
            .unwrap();
        assert_eq!(after.desired_state, DesiredRuntimeState::Disabled);
        assert_eq!(after.last_journal_sequence, before.last_journal_sequence);
        assert_eq!(state.registry.version(), generation);
        assert!(
            state
                .lifecycle
                .connector_execution_fence(&connector_id)
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn enable_disable_restart_and_uninstall_control_exact_native_runtime() {
        let directory = tempfile::tempdir().unwrap();
        let state = app(
            native_config(directory.path(), "stateless"),
            DesiredRuntimeState::Disabled,
        )
        .await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        assert_dormant(&state, &connector_id).await;

        let enabled = transition(&state, &connector_id, &request(LifecycleAction::Enable))
            .await
            .unwrap();
        assert_eq!(enabled.current_desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(enabled.observed_state, ObservedRuntimeState::Running);
        let first = native(&state, &connector_id).await;
        assert_eq!(
            first.health().await.unwrap().details.unwrap()["configured"],
            true
        );
        assert_eq!(
            advertised_connectors(&state.registry, &state.lifecycle)
                .await
                .len(),
            1
        );
        let first_inventory = state.registry.inventory_fence(state.registry.version());

        let disabled = transition(&state, &connector_id, &request(LifecycleAction::Disable))
            .await
            .unwrap();
        assert_eq!(
            disabled.current_desired_state,
            DesiredRuntimeState::Disabled
        );
        assert_eq!(disabled.observed_state, ObservedRuntimeState::Stopped);
        assert!(first.runtime_retirement.is_exited());
        assert!(
            first.health().await.is_err(),
            "retained Arc cannot revive a retired actor"
        );
        assert!(first_inventory.require_current().is_err());
        assert_dormant(&state, &connector_id).await;

        transition(&state, &connector_id, &request(LifecycleAction::Enable))
            .await
            .unwrap();
        let second = native(&state, &connector_id).await;
        assert!(!Arc::ptr_eq(&first, &second));
        let restarted = transition(&state, &connector_id, &request(LifecycleAction::Restart))
            .await
            .unwrap();
        assert_eq!(
            restarted.previous_desired_state,
            DesiredRuntimeState::Enabled
        );
        assert_eq!(restarted.observed_state, ObservedRuntimeState::Running);
        let third = native(&state, &connector_id).await;
        assert!(!Arc::ptr_eq(&second, &third));
        assert!(second.runtime_retirement.is_exited());
        assert!(second.health().await.is_err());

        let uninstalled = transition(&state, &connector_id, &request(LifecycleAction::Uninstall))
            .await
            .unwrap();
        assert_eq!(
            uninstalled.current_desired_state,
            DesiredRuntimeState::Uninstalled
        );
        assert_eq!(uninstalled.observed_state, ObservedRuntimeState::Stopped);
        assert!(third.runtime_retirement.is_exited());
        assert_dormant(&state, &connector_id).await;
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn warm_pool_lifecycle_retires_control_idle_and_checked_out_processes_before_replacement()
    {
        let directory = tempfile::tempdir().unwrap();
        let state = app(
            shell_warm_pool_config(directory.path()),
            DesiredRuntimeState::Disabled,
        )
        .await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        assert_dormant(&state, &connector_id).await;

        let enabled = transition(&state, &connector_id, &request(LifecycleAction::Enable))
            .await
            .expect("enable launches a real stateless warm pool");
        assert_eq!(enabled.observed_state, ObservedRuntimeState::Running);
        let first = warm_pool(&state, &connector_id).await;
        let first_processes = retained_pool_processes(&first).await;
        for process in &first_processes {
            assert!(!process.runtime_retirement.is_exited());
        }
        let checked_out = first.checkout(&ZoneId::work()).await.unwrap();
        assert!(checked_out.warm_checkout);
        assert!(
            first_processes
                .iter()
                .any(|process| Arc::ptr_eq(process, &checked_out.entry.connector))
        );
        let first_generation = state.registry.inventory_fence(state.registry.version());

        let mut preview = request(LifecycleAction::Disable);
        preview.dry_run = true;
        transition(&state, &connector_id, &preview).await.unwrap();
        first_generation.require_current().unwrap();
        first.runtime_retirement.require_open().unwrap();
        for process in &first_processes {
            assert!(!process.runtime_retirement.is_exited());
        }

        let disabled = transition(&state, &connector_id, &request(LifecycleAction::Disable))
            .await
            .expect("disable waits for every exact child, including checked-out workers");
        assert_eq!(
            disabled.current_desired_state,
            DesiredRuntimeState::Disabled
        );
        assert_eq!(disabled.observed_state, ObservedRuntimeState::Stopped);
        for process in &first_processes {
            assert!(process.runtime_retirement.is_exited());
        }
        assert!(checked_out.entry.connector.runtime_retirement.is_exited());
        assert!(first_generation.require_current().is_err());
        assert!(first.runtime_retirement.require_open().is_err());
        assert!(first.checkout(&ZoneId::work()).await.is_err());
        assert!(first.maintain_min_idle().await.is_err());
        assert_dormant(&state, &connector_id).await;
        drop(checked_out);

        transition(&state, &connector_id, &request(LifecycleAction::Enable))
            .await
            .expect("enable starts a replacement instead of reopening retired workers");
        let second = warm_pool(&state, &connector_id).await;
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first.control, &second.control));
        let second_processes = retained_pool_processes(&second).await;
        for process in &second_processes {
            assert!(!process.runtime_retirement.is_exited());
        }
        assert_eq!(
            second.control.health().await.unwrap().details.unwrap()["configured"],
            true
        );

        let restarted = transition(&state, &connector_id, &request(LifecycleAction::Restart))
            .await
            .expect("restart drains every old process before enabling its replacement");
        assert_eq!(
            restarted.previous_desired_state,
            DesiredRuntimeState::Enabled
        );
        assert_eq!(restarted.observed_state, ObservedRuntimeState::Running);
        let third = warm_pool(&state, &connector_id).await;
        assert!(!Arc::ptr_eq(&second, &third));
        assert!(!Arc::ptr_eq(&second.control, &third.control));
        for process in &second_processes {
            assert!(process.runtime_retirement.is_exited());
        }
        assert!(second.runtime_retirement.require_open().is_err());
        assert!(second.checkout(&ZoneId::work()).await.is_err());
        let third_processes = retained_pool_processes(&third).await;
        for process in &third_processes {
            assert!(!process.runtime_retirement.is_exited());
        }

        let uninstalled = transition(&state, &connector_id, &request(LifecycleAction::Uninstall))
            .await
            .expect("uninstall retires the complete replacement pool");
        assert_eq!(
            uninstalled.current_desired_state,
            DesiredRuntimeState::Uninstalled
        );
        assert_eq!(uninstalled.observed_state, ObservedRuntimeState::Stopped);
        for process in &third_processes {
            assert!(process.runtime_retirement.is_exited());
        }
        assert!(third.runtime_retirement.require_open().is_err());
        assert_dormant(&state, &connector_id).await;
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn restart_and_reenable_recover_a_closed_native_dispatcher() {
        let directory = tempfile::tempdir().unwrap();
        let state = app(
            native_config(directory.path(), "stateless"),
            DesiredRuntimeState::Enabled,
        )
        .await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        for action in [LifecycleAction::Restart, LifecycleAction::Enable] {
            let poisoned = native(&state, &connector_id).await;
            poisoned._runner_task.abort();
            poisoned
                .runtime_retirement
                .wait_for_exit(Instant::now() + Duration::from_secs(5))
                .await
                .expect("aborting the actor retains exact child exit evidence");
            if action == LifecycleAction::Enable {
                state
                    .lifecycle
                    .set_desired_state(&connector_id, DesiredRuntimeState::Disabled, None)
                    .await
                    .unwrap();
                assert!(
                    advertised_connectors(&state.registry, &state.lifecycle)
                        .await
                        .is_empty()
                );
            }
            let response = transition(&state, &connector_id, &request(action))
                .await
                .unwrap();
            assert_eq!(response.observed_state, ObservedRuntimeState::Running);
            let replacement = native(&state, &connector_id).await;
            assert!(!Arc::ptr_eq(&poisoned, &replacement));
            assert!(poisoned.health().await.is_err());
            replacement
                .health()
                .await
                .expect("replacement dispatcher is usable");
        }
        transition(&state, &connector_id, &request(LifecycleAction::Disable))
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn stateful_restart_refuses_and_incomplete_disable_never_claims_stopped() {
        let directory = tempfile::tempdir().unwrap();
        let state = app(
            native_config(directory.path(), "crdt"),
            DesiredRuntimeState::Enabled,
        )
        .await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let retained = native(&state, &connector_id).await;
        let generation = state.registry.version();
        let before = state
            .lifecycle
            .connector_status(&connector_id)
            .await
            .unwrap();
        assert!(
            transition(&state, &connector_id, &request(LifecycleAction::Restart))
                .await
                .is_err()
        );
        let unchanged = state
            .lifecycle
            .connector_status(&connector_id)
            .await
            .unwrap();
        assert_eq!(unchanged.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(
            unchanged.last_journal_sequence,
            before.last_journal_sequence
        );

        assert!(
            transition(&state, &connector_id, &request(LifecycleAction::Disable))
                .await
                .is_err()
        );
        let denied = state
            .lifecycle
            .connector_status(&connector_id)
            .await
            .unwrap();
        assert_eq!(denied.desired_state, DesiredRuntimeState::Disabled);
        assert_eq!(denied.observed_state, ObservedRuntimeState::Running);
        assert_eq!(state.registry.version(), generation);
        assert!(!retained.runtime_retirement.is_exited());
        assert!(
            advertised_connectors(&state.registry, &state.lifecycle)
                .await
                .is_empty()
        );
        assert!(
            transition(&state, &connector_id, &request(LifecycleAction::Enable))
                .await
                .is_err()
        );
        assert!(
            state
                .lifecycle
                .connector_execution_fence(&connector_id)
                .await
                .is_err()
        );
        retained
            .health()
            .await
            .expect("unsupported handoff retains the actual writer");
    }

    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn lifecycle_revocation_between_prepare_and_publish_retires_unpublished_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let config = native_config(directory.path(), "stateless");
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let lifecycle = HostAdminStateStore::new();
        let registry =
            SubprocessRegistry::from_configs_with_lifecycle(Vec::new(), None, &lifecycle)
                .await
                .unwrap();
        let prepared = registry
            .prepare_configs_with_lifecycle(vec![config], &lifecycle)
            .await
            .unwrap();
        let ConnectorRuntime::Native(candidate) =
            &prepared.replacement_entries[&connector_id].connector
        else {
            panic!("prepared native candidate");
        };
        let retirement = candidate.runtime_retirement.clone();
        lifecycle
            .set_desired_state(&connector_id, DesiredRuntimeState::Disabled, None)
            .await
            .unwrap();
        assert!(registry.publish_configs(prepared).await.is_err());
        assert!(registry.get(&connector_id).await.is_none());
        assert_eq!(registry.version(), 1);
        retirement
            .wait_for_exit(Instant::now() + Duration::from_secs(5))
            .await
            .expect("unpublished candidate cancellation retires the actual child");
    }
}
