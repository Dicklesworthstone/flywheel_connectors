//! Restore an explicitly supplied, pinned stateless deployment.
//!
//! Verification and preparation precede durable denial. Once ownership changes
//! begin, failures before finalization remain denied across restart. Only a fully
//! published target can finalize the lifecycle record and lift our own denial.
//! A lost response after finalization requires inspecting persisted state.

use fcp_host::{
    ConnectorPinnedRollbackRequest, ConnectorPinnedRollbackResponse, DesiredRuntimeState,
};

use super::*;

const ROLLBACK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_REASON_BYTES: usize = 4096;

fn require_deadline(deadline: Instant) -> HostResult<()> {
    if Instant::now() >= deadline {
        return Err(timeout_error());
    }
    Ok(())
}

fn timeout_error() -> HostError {
    HostError::Unavailable(
        "verified rollback exceeded its deadline; inspect persisted lifecycle and inventory before retrying"
            .to_owned(),
    )
}

fn invalid(message: &str) -> HostError {
    HostError::InvalidFilter(message.to_owned())
}

fn canonical_zones(zones: &[String]) -> HostResult<Vec<ZoneId>> {
    let mut parsed = zones
        .iter()
        .map(|zone| {
            zone.parse::<ZoneId>()
                .map_err(|_| invalid("verified rollback inventory contains an invalid zone"))
        })
        .collect::<HostResult<Vec<_>>>()?;
    parsed.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    parsed.dedup();
    Ok(parsed)
}

/// Read the exact manifest whose version and operation authority we admit.
/// No later validation is allowed to select another manifest from this path.
fn target_manifest(
    config: &ConnectorConfig,
    version: &semver::Version,
) -> HostResult<ManifestOperationConstraintCatalog> {
    let path = config
        .manifest_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
        .ok_or_else(|| invalid("verified rollback requires a versioned connector manifest"))?;
    let source_error = || {
        invalid(
            "verified rollback manifest must be a readable regular UTF-8 file no larger than 2 MiB",
        )
    };
    let metadata = std::fs::metadata(path).map_err(|_| source_error())?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(source_error());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| source_error())?;
    let metadata = file.metadata().map_err(|_| source_error())?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(source_error());
    }
    let mut raw = String::new();
    std::io::Read::read_to_string(
        &mut std::io::Read::take(file, MAX_MANIFEST_BYTES + 1),
        &mut raw,
    )
    .map_err(|_| source_error())?;
    if raw.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(source_error());
    }
    let manifest = ConnectorManifest::parse_str(&raw)
        .map_err(|error| invalid(&format!("invalid verified rollback manifest: {error}")))?;
    if manifest.connector.id.as_str() != config.id || manifest.connector.version != *version {
        return Err(invalid(
            "verified rollback manifest identity and version must match the requested target",
        ));
    }
    let mut catalog = ManifestOperationConstraintCatalog::from_manifest(&manifest, path)?;
    catalog.manifest_digest = Some(*blake3::hash(raw.as_bytes()).as_bytes());
    catalog.manifest_bytes = raw.len() as u64;
    Ok(catalog)
}

fn validate_target(
    request: &ConnectorPinnedRollbackRequest,
    connector_id: &ConnectorId,
    activate: bool,
) -> HostResult<ValidatedConnectorConfig> {
    if request.connector.id != connector_id.as_str() {
        return Err(invalid(
            "verified rollback inventory names a different connector",
        ));
    }
    let version = request.connector.version.as_deref().ok_or_else(|| {
        invalid("verified rollback requires an explicit target inventory version")
    })?;
    if semver::Version::parse(version)
        .map_err(|_| invalid("verified rollback inventory version is invalid"))?
        != request.to_version
    {
        return Err(invalid(
            "verified rollback inventory version does not match the requested target",
        ));
    }
    let pin = request
        .connector
        .binary_sha256
        .as_deref()
        .ok_or_else(|| invalid("verified rollback requires binary_sha256"))?;
    ExecutableDigest::parse(pin).map_err(|error| invalid(&error.to_string()))?;
    validate_registry_config_settings(&request.connector)?;
    require_allowed_zones_configured(connector_id, &request.connector.allowed_zones)?;
    let manifest = target_manifest(&request.connector, &request.to_version)?;
    let mut admitted =
        validate_registry_config_with_manifest(&request.connector, manifest, activate)?;
    if admitted.state_policy.model != ConnectorStateKind::Stateless {
        return Err(invalid(
            "verified rollback requires a stateless target; canonical state handoff is unavailable",
        ));
    }
    // Even a dormant rollback verifies and retains immutable bytes. A later
    // explicit Enable must not select another image from the source path.
    if request.connector.runtime_network_enforcement == RuntimeNetworkEnforcement::WasiSandbox {
        admitted.wasi_component = Some(wasi_connector::AdmittedWasiComponent::capture(
            &request.connector,
        )?);
    } else {
        admitted.native_executable =
            native_artifact::AdmittedNativeExecutable::capture_for_platform(&request.connector)?;
        if admitted.native_executable.is_none() {
            return Err(HostError::Unavailable(
                "verified rollback requires immutable native executable admission on this platform"
                    .to_owned(),
            ));
        }
    }
    admitted
        .state_policy
        .require_admitted_manifest(&request.connector)?;
    Ok(admitted)
}

async fn verify_prepared_catalog(
    entry: &RegistryEntry,
    connector_id: &ConnectorId,
) -> HostResult<()> {
    let introspection = entry.connector.introspect().await?;
    let mut names = std::collections::HashSet::new();
    for operation in &introspection.operations {
        let tool = ToolDescriptor::from(operation);
        if !names.insert(tool.name.clone()) {
            return Err(invalid(
                "verified rollback target has an ambiguous operation catalog",
            ));
        }
        entry
            .manifest_constraints
            .enforce_tool_authority(connector_id, &tool)?;
    }
    if names.len() != entry.manifest_constraints.operation_authorities.len() {
        return Err(invalid(
            "verified rollback executable does not expose its complete admitted manifest catalog",
        ));
    }
    Ok(())
}

/// Inventory's rename must be durable before lifecycle finalization can enable
/// it. Otherwise a power loss could restore the failed inventory under a new pin.
fn persist_target_inventory(path: &StdPath, configs: &[ConnectorConfig]) -> HostResult<()> {
    write_connector_configs_file(path, configs)?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| StdPath::new("."));
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| {
            HostError::Unavailable(
                "rollback inventory directory could not be synchronized; execution remains denied"
                    .to_owned(),
            )
        })
}

pub(super) async fn execute(
    state: &AppState,
    request: ConnectorPinnedRollbackRequest,
) -> HostResult<ConnectorPinnedRollbackResponse> {
    if !cfg!(unix) {
        return Err(HostError::Unavailable(
            "verified rollback requires supported inventory directory synchronization".to_owned(),
        ));
    }
    if request
        .reason
        .as_ref()
        .is_some_and(|reason| reason.len() > MAX_REASON_BYTES)
    {
        return Err(invalid("verified rollback reason exceeds 4096 bytes"));
    }
    let deadline = Instant::now() + ROLLBACK_TIMEOUT;
    fcp_async_core::time::timeout(ROLLBACK_TIMEOUT, execute_before(state, request, deadline))
        .await
        .map_err(|_| timeout_error())?
}

async fn execute_before(
    state: &AppState,
    request: ConnectorPinnedRollbackRequest,
    deadline: Instant,
) -> HostResult<ConnectorPinnedRollbackResponse> {
    let connector_id = request
        .connector_id
        .parse::<ConnectorId>()
        .map_err(|_| invalid("verified rollback connector identifier is invalid"))?;
    let _transaction = state.registry.inventory_transaction.lock().await;
    require_deadline(deadline)?;
    let inventory_path = state.connectors_file.as_ref().ok_or_else(|| {
        HostError::Unavailable("verified rollback requires a managed connectors file".to_owned())
    })?;
    let previous_configs = read_connector_configs_file(inventory_path)?;
    let (current, generation) =
        lifecycle_runtime::selected_entry(&state.registry, &connector_id).await?;
    generation.checked_add(2).ok_or_else(|| {
        HostError::Unavailable("connector inventory generation is exhausted".to_owned())
    })?;
    if current.state_policy.model != ConnectorStateKind::Stateless
        || current.state_policy.manifest_digest.is_none()
    {
        return Err(invalid(
            "verified rollback requires an admitted stateless current deployment; canonical state handoff is unavailable",
        ));
    }
    lifecycle_runtime::stateless_retirement_supported(&current)?;
    let index = previous_configs
        .iter()
        .position(|config| config.id == request.connector_id)
        .ok_or_else(|| HostError::ConnectorNotFound(request.connector_id.clone()))?;
    if previous_configs[index] != current.config {
        return Err(HostError::Unavailable(
            "managed inventory differs from the admitted deployment; reconcile it before rollback"
                .to_owned(),
        ));
    }
    let preparation = state
        .lifecycle
        .validate_runtime_rollback(&connector_id, &request.to_version)
        .await
        .map_err(map_lifecycle_host_error)?;
    if connector_summary_from_config(&current.config)?.version != *preparation.from_version() {
        return Err(invalid(
            "current rollout version does not identify the admitted executable inventory",
        ));
    }
    if canonical_zones(&request.connector.allowed_zones)?
        != canonical_zones(&current.config.allowed_zones)?
    {
        return Err(invalid(
            "verified rollback must preserve the current connector zone envelope",
        ));
    }
    let admitted = validate_target(&request, &connector_id, preparation.should_activate())?;
    require_deadline(deadline)?;
    let target = if preparation.should_activate() {
        let target = build_registry_entry_with_admission(
            request.connector.clone(),
            admitted,
            Arc::clone(&state.registry.resilience),
            state.registry.capability_verifying_key,
        )
        .await?;
        if matches!(
            &target.connector,
            ConnectorRuntime::UnavailableNativeProxyOnly(_)
        ) {
            return Err(HostError::Unavailable(
                "verified rollback target cannot enforce its requested runtime sandbox".to_owned(),
            ));
        }
        verify_prepared_catalog(&target, &connector_id).await?;
        target
    } else {
        lifecycle_runtime::dormant_entry(
            request.connector.clone(),
            admitted,
            preparation.original_desired_state(),
        )?
    };
    target
        .state_policy
        .require_admitted_manifest(&target.config)?;
    require_deadline(deadline)?;
    state.registry.require_generation(generation)?;

    // Until finalization, an incomplete operation must stay durably denied.
    // No settings rollback or cancellation path may resurrect the old actor.
    let guard = state
        .lifecycle
        .begin_runtime_rollback(&preparation, request.reason)
        .await
        .map_err(map_lifecycle_host_error)?;
    let generation = lifecycle_runtime::retire_selected(
        &state.registry,
        &connector_id,
        &current,
        generation,
        DesiredRuntimeState::Disabled,
        deadline,
    )
    .await?;
    require_deadline(deadline)?;
    if read_connector_configs_file(inventory_path)? != previous_configs {
        return Err(HostError::Unavailable(
            "managed inventory changed during rollback; execution remains denied".to_owned(),
        ));
    }
    target
        .state_policy
        .require_admitted_manifest(&target.config)?;
    let mut next_configs = previous_configs;
    next_configs[index] = request.connector;
    persist_target_inventory(inventory_path, &next_configs)?;
    let registry_version = lifecycle_runtime::publish_entry(
        &state.registry,
        &connector_id,
        target,
        generation,
        None,
        deadline,
    )
    .await?;

    // Keep dispatch and direct registry writers outside finalization. Lifting
    // the durable gate must expose the same target whose generation we checked.
    let published = state.registry.state.write().await;
    require_deadline(deadline)?;
    state.registry.require_generation(registry_version)?;
    let record = state
        .lifecycle
        .finalize_runtime_rollback(&guard)
        .await
        .map_err(map_lifecycle_host_error)?;
    drop(published);
    let desired_state = if guard.should_activate() {
        DesiredRuntimeState::Enabled
    } else {
        guard.original_desired_state()
    };
    tracing::info!(
        event = "verified_runtime_rollback_completed", connector_id = %connector_id,
        from_version = %guard.from_version(), to_version = %record.version,
        registry_version, desired_state = ?desired_state,
        "verified connector deployment restored"
    );
    Ok(ConnectorPinnedRollbackResponse {
        connector_id: connector_id.to_string(), state: record.state,
        from_version: guard.from_version().clone(), to_version: record.version,
        message: "Verified target executable and managed inventory restored; inspect health before resuming rollout promotion".to_owned(),
        registry_version, runtime_restored: true, desired_state,
    })
}
