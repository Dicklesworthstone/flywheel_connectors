//! Stop or restart one admitted Telegram polling writer without losing its cursor.
//!
//! This is deliberately narrower than generic stateful replacement. The durable
//! admin-state custody record denies execution through every asynchronous phase.
//! Only a committed checkpoint and an observed exit of the exact source permit
//! a replacement. Disable instead retains that checkpoint in a dormant runtime.
//! A later Enable restores it before registry publication and the guarded,
//! durable grant of execution authority.

use fcp_host::{
    DesiredRuntimeState, HostTelegramPollingCheckpoint, LifecycleAction, ObservedRuntimeState,
    TelegramPollingRestartBinding, TelegramPollingRestartCustody,
    TelegramPollingRestartPreparation,
};

use super::*;

const CONNECTOR: &str = "fcp.telegram";
const CHECKPOINT_DEADLINE_MAX_MS: u64 = 30_000;

fn unavailable(reason: &str) -> HostError {
    HostError::Unavailable(reason.to_owned())
}

fn require_current(
    registry: &SubprocessRegistry,
    generation: u64,
    deadline: Instant,
) -> HostResult<()> {
    if Instant::now() >= deadline {
        return Err(unavailable(
            "Telegram polling restart exceeded its original lifecycle deadline; execution remains denied",
        ));
    }
    registry.require_generation(generation)
}

fn binding_for_config(
    config: &ConnectorConfig,
    state_policy: ConnectorStatePolicy,
) -> HostResult<TelegramPollingRestartBinding> {
    if config.id != CONNECTOR
        || state_policy.model != ConnectorStateKind::SingletonWriter
        || config.prewarm.strategy != PrewarmStrategy::OnDemand
        || config.allowed_zones.len() != 1
        || config.runtime_network_enforcement == RuntimeNetworkEnforcement::WasiSandbox
    {
        return Err(unavailable(
            "Telegram polling restart requires an on-demand singleton native deployment in exactly one zone",
        ));
    }
    let manifest_digest = state_policy.manifest_digest.ok_or_else(|| {
        unavailable("Telegram polling restart requires an admitted manifest digest")
    })?;
    let pin = config.binary_sha256.as_deref().ok_or_else(|| {
        unavailable("Telegram polling restart requires an explicit binary_sha256 pin")
    })?;
    if pin.len() != 64 || !pin.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(unavailable(
            "Telegram polling restart requires an exact 64-digit SHA-256 binary pin",
        ));
    }
    let zone: ZoneId = config.allowed_zones[0]
        .parse()
        .map_err(|_| unavailable("Telegram polling restart has an invalid zone"))?;
    let payload = config
        .config
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| {
            unavailable("Telegram polling restart requires explicit polling credentials")
        })?;
    if payload
        .get("receive_mode")
        .is_some_and(|mode| mode.as_str() != Some("polling"))
        || payload.get("credential_id").is_some_and(|id| !id.is_null())
    {
        return Err(unavailable(
            "Telegram polling restart supports inline credentials and polling mode only",
        ));
    }
    let (bot_id, secret) = payload
        .get("credential")
        .and_then(Value::as_str)
        .map(str::trim)
        .and_then(|token| token.split_once(':'))
        .ok_or_else(|| unavailable("Telegram polling restart requires an inline bot token"))?;
    if bot_id.len() < 6
        || bot_id.len() > 20
        || !bot_id.bytes().all(|byte| byte.is_ascii_digit())
        || secret.is_empty()
    {
        return Err(unavailable(
            "Telegram polling restart requires a numeric bot identity",
        ));
    }
    let state_root = config
        .env
        .get(CONNECTOR_STATE_DIR_ENV)
        .map(String::as_str)
        .map(str::trim)
        .filter(|root| !root.is_empty() && StdPath::new(root).is_absolute())
        .ok_or_else(|| {
            unavailable(
                "Telegram polling restart requires an explicit absolute FCP_CONNECTOR_STATE",
            )
        })?;
    // Bind all operator-managed settings, including credentials, arguments and
    // egress policy. Persist only this digest, never the credential-bearing JSON.
    let config_value = serde_json::to_value(config)
        .map_err(|_| unavailable("Telegram polling restart configuration could not be encoded"))?;
    let config_cbor = to_deterministic_cbor(&config_value).map_err(|_| {
        unavailable("Telegram polling restart configuration could not be canonicalized")
    })?;
    let binding = TelegramPollingRestartBinding {
        config_digest: blake3::hash(&config_cbor).to_hex().to_string(),
        manifest_digest: hex::encode(manifest_digest),
        binary_sha256: pin.to_ascii_lowercase(),
        zone_id: zone.to_string(),
        bot_id: bot_id.to_owned(),
        state_root: state_root.to_owned(),
    };
    binding.validate().map_err(map_lifecycle_host_error)?;
    Ok(binding)
}

fn validate_admission(
    state: &AppState,
    entry: &RegistryEntry,
    preparation: &TelegramPollingRestartPreparation,
    action: LifecycleAction,
) -> HostResult<(TelegramPollingRestartBinding, ValidatedConnectorConfig)> {
    if !cfg!(target_os = "linux")
        || state.registry.capability_verifying_key.is_none()
        || !matches!(
            &entry.connector,
            ConnectorRuntime::Native(_) | ConnectorRuntime::Dormant(_)
        )
    {
        return Err(unavailable(
            "Telegram polling restart requires a Linux native runtime with host capability verification",
        ));
    }
    let binding = binding_for_config(&entry.config, entry.state_policy)?;
    validate_recovery(
        matches!(&entry.connector, ConnectorRuntime::Dormant(_)),
        action,
        preparation,
        &binding,
    )?;
    entry
        .state_policy
        .require_admitted_manifest(&entry.config)?;
    let mut admitted = lifecycle_runtime::validate_activation(entry)?;
    if let Some(executable) = entry.admitted_native_executable() {
        executable.require_pin(&entry.config)?;
    } else if matches!(&entry.connector, ConnectorRuntime::Dormant(_)) {
        // Startup retains disabled configuration but no executable image.
        // Only the validated, unambiguous durable recovery phase above may
        // re-admit bytes, and capture verifies the exact SHA-256 before sealing.
        admitted.native_executable =
            native_artifact::AdmittedNativeExecutable::capture_for_platform(&entry.config)?;
        admitted
            .native_executable
            .as_ref()
            .ok_or_else(|| unavailable("Telegram recovery could not admit an immutable image"))?
            .require_pin(&entry.config)?;
    } else {
        return Err(unavailable(
            "Telegram polling restart requires the retained immutable native image",
        ));
    }
    // A mutable manifest path must not pair a newly captured executable with
    // a different catalog than the one bound to durable checkpoint custody.
    admitted.manifest_constraints = entry.manifest_constraints.clone();
    admitted.state_policy = entry.state_policy;
    entry
        .state_policy
        .require_admitted_manifest(&entry.config)?;
    Ok((binding, admitted))
}

fn validate_recovery(
    dormant: bool,
    action: LifecycleAction,
    preparation: &TelegramPollingRestartPreparation,
    binding: &TelegramPollingRestartBinding,
) -> HostResult<()> {
    if !matches!(
        action,
        LifecycleAction::Restart | LifecycleAction::Enable | LifecycleAction::Disable
    ) || (action == LifecycleAction::Enable && preparation.pending.is_none())
    {
        return Err(unavailable(
            "Telegram polling recovery requires an existing restart custody record",
        ));
    }
    if let Some(custody) = &preparation.pending {
        if custody.binding != *binding {
            return Err(unavailable(
                "pending Telegram checkpoint belongs to a different deployment or polling scope",
            ));
        }
        if custody.source_exited && custody.checkpoint.is_none()
            || custody.candidate_may_exist && !custody.source_exited
        {
            return Err(unavailable(
                "Telegram polling restart has inconsistent process custody",
            ));
        }
    }
    if dormant
        && !preparation.pending.as_ref().is_some_and(|custody| {
            custody.checkpoint.is_some() && custody.source_exited && !custody.candidate_may_exist
        })
    {
        // A host restart or dropped candidate does not prove physical exit.
        // Refuse reconstruction when no retained exact child can settle it.
        return Err(unavailable(
            "dormant Telegram recovery requires a committed checkpoint, proven source exit, and no unresolved replacement process",
        ));
    }
    Ok(())
}

async fn require_custody(
    state: &AppState,
    connector_id: &ConnectorId,
    entry: &RegistryEntry,
    custody: &TelegramPollingRestartCustody,
    generation: u64,
    deadline: Instant,
) -> HostResult<()> {
    require_current(&state.registry, generation, deadline)?;
    state
        .lifecycle
        .require_telegram_polling_restart(connector_id, custody)
        .await
        .map_err(map_lifecycle_host_error)?;
    require_current(&state.registry, generation, deadline)?;
    entry.state_policy.require_admitted_manifest(&entry.config)
}

fn validate_restore_ack(
    acknowledgement: &Value,
    checkpoint: &HostTelegramPollingCheckpoint,
) -> HostResult<()> {
    let Some(object) = acknowledgement.as_object() else {
        return Err(unavailable(
            "Telegram restore acknowledgement is not an object",
        ));
    };
    let expected_offset = json!(checkpoint.state.offset);
    if object.len() != 3
        || object.get("status").and_then(Value::as_str) != Some("restored")
        || object.get("checkpoint_id").and_then(Value::as_str)
            != Some(checkpoint.checkpoint_id.as_str())
        || object.get("offset") != Some(&expected_offset)
    {
        // In particular, a missing offset must not match an explicit null cursor.
        return Err(unavailable(
            "Telegram restore did not acknowledge the exact committed checkpoint and cursor",
        ));
    }
    Ok(())
}

async fn settle_unpublished_candidate(
    state: &AppState,
    connector_id: &ConnectorId,
    candidate: &SubprocessConnector,
    custody: &TelegramPollingRestartCustody,
    generation: u64,
    deadline: Instant,
) {
    // Even a superseded attempt owns this unpublished child and should stop it.
    // Only confirmed physical exit under current custody may clear the marker.
    // Cancellation or an exhausted deadline leaves the durable marker in place.
    if candidate.retire_runtime(deadline).await.is_ok()
        && candidate.runtime_retirement.is_exited()
        && require_current(&state.registry, generation, deadline).is_ok()
    {
        let _ = state
            .lifecycle
            .mark_telegram_polling_candidate_exited(connector_id, custody)
            .await;
    }
}

/// Called only while the registry inventory transaction is held. Generic
/// stateful replacement/removal guards remain unchanged.
#[allow(clippy::too_many_arguments)]
pub(super) async fn transition_selected(
    state: &AppState,
    connector_id: &ConnectorId,
    entry: &RegistryEntry,
    generation: u64,
    previous: &ConnectorAdminStatus,
    request: &LifecycleTransitionRequest,
    deadline: Instant,
) -> HostResult<LifecycleTransitionResponse> {
    let preparation = state
        .lifecycle
        .prepare_telegram_polling_restart(connector_id)
        .await
        .map_err(map_lifecycle_host_error)?;
    require_current(&state.registry, generation, deadline)?;
    if preparation.expected_journal_sequence != previous.last_journal_sequence
        || preparation.previous_desired_state != previous.desired_state
    {
        return Err(unavailable(
            "Telegram lifecycle intent changed before restart admission; retry the explicit action",
        ));
    }
    let (binding, admitted) = validate_admission(state, entry, &preparation, request.action)?;
    let stop_only = request.action == LifecycleAction::Disable;
    // Disable publishes only the dormant source; restart also publishes the
    // restored replacement. Reserve the full generation range before quiescing.
    generation
        .checked_add(if stop_only { 1 } else { 2 })
        .ok_or_else(|| unavailable("connector inventory generation is exhausted"))?;
    let mut response = LifecycleTransitionResponse {
        connector_id: connector_id.to_string(),
        action: request.action,
        dry_run: request.dry_run,
        previous_desired_state: preparation.previous_desired_state,
        current_desired_state: if stop_only {
            DesiredRuntimeState::Disabled
        } else {
            DesiredRuntimeState::Enabled
        },
        observed_state: previous.observed_state,
        lifecycle_status: previous.lifecycle.clone(),
        journal_sequence: preparation.expected_journal_sequence,
        transitioned_at: Utc::now(),
    };
    require_current(&state.registry, generation, deadline)?;
    if request.dry_run {
        return Ok(response);
    }
    let mut custody = state
        .lifecycle
        .begin_telegram_polling_restart(connector_id, &preparation, binding)
        .await
        .map_err(map_lifecycle_host_error)?;
    let mut generation = generation;
    let termination = NativeInvocationTermination::new(deadline);
    let zone: ZoneId = custody
        .binding
        .zone_id
        .parse()
        .map_err(|_| unavailable("Telegram polling restart custody has an invalid zone"))?;

    if let ConnectorRuntime::Native(native) = &entry.connector {
        require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
        if custody.candidate_may_exist {
            // This is a previously published, still-denied replacement. It
            // cannot be reused: a cancelled restore/session may be poisoned.
            native.retire_runtime(deadline).await?;
            require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
            if !native.runtime_retirement.is_exited() {
                return Err(unavailable(
                    "Telegram replacement process exit is unconfirmed",
                ));
            }
            custody = state
                .lifecycle
                .mark_telegram_polling_candidate_exited(connector_id, &custody)
                .await
                .map_err(map_lifecycle_host_error)?;
        } else {
            if custody.checkpoint.is_none() {
                let remaining_ms = u64::try_from(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                )
                .unwrap_or(CHECKPOINT_DEADLINE_MAX_MS)
                .min(CHECKPOINT_DEADLINE_MAX_MS);
                if remaining_ms == 0 {
                    return Err(unavailable(
                        "Telegram checkpoint has no remaining lifecycle budget",
                    ));
                }
                // The connector quiesces polling, waits for the ACK boundary,
                // persists the cursor, and retains its exclusive writer lock.
                let exported = native
                    .rpc_in_handshaken_zone_with_termination(
                        &zone,
                        "state.checkpoint",
                        json!({ "deadline_ms": remaining_ms }),
                        Some(&termination),
                    )
                    .await?;
                let checkpoint =
                    HostTelegramPollingCheckpoint::from_value(exported, &custody.binding)
                        .map_err(map_lifecycle_host_error)?;
                require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
                custody = state
                    .lifecycle
                    .record_telegram_polling_checkpoint(connector_id, &custody, checkpoint)
                    .await
                    .map_err(map_lifecycle_host_error)?;
            }
            require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
            // No explicit source retirement occurs before checkpoint commit.
            native.retire_runtime(deadline).await?;
            require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
            if !native.runtime_retirement.is_exited() {
                return Err(unavailable("Telegram source process exit is unconfirmed"));
            }
            if !custody.source_exited {
                custody = state
                    .lifecycle
                    .mark_telegram_polling_source_exited(connector_id, &custody)
                    .await
                    .map_err(map_lifecycle_host_error)?;
            }
        }
        require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
        generation = lifecycle_runtime::publish_entry(
            &state.registry,
            connector_id,
            lifecycle_runtime::dormant_entry(
                entry.config.clone(),
                admitted.clone(),
                DesiredRuntimeState::Disabled,
            )?,
            generation,
            None,
            deadline,
        )
        .await?;
    }

    require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
    if stop_only {
        // A source exit proof alone is not enough: publish the dormant runtime
        // first, then durably report Stopped without discarding restore custody.
        let (published, published_generation) =
            lifecycle_runtime::selected_entry(&state.registry, connector_id).await?;
        if published_generation != generation
            || !matches!(&published.connector, ConnectorRuntime::Dormant(_))
        {
            return Err(unavailable(
                "Telegram polling stop has no current dormant runtime",
            ));
        }
        let sequence = state
            .lifecycle
            .record_telegram_polling_stop_guarded(connector_id, &custody, || {
                require_current(&state.registry, generation, deadline).map_err(|error| {
                    LifecycleError::Persistence {
                        reason: error.to_string(),
                    }
                })?;
                entry
                    .state_policy
                    .require_admitted_manifest(&entry.config)
                    .map_err(|error| LifecycleError::Persistence {
                        reason: error.to_string(),
                    })
            })
            .await
            .map_err(map_lifecycle_host_error)?;
        response.observed_state = ObservedRuntimeState::Stopped;
        response.journal_sequence = sequence;
        response.transitioned_at = Utc::now();
        return Ok(response);
    }
    let checkpoint = custody
        .checkpoint
        .clone()
        .ok_or_else(|| unavailable("Telegram polling restart has no committed checkpoint"))?;
    custody = state
        .lifecycle
        .mark_telegram_polling_candidate_starting(connector_id, &custody)
        .await
        .map_err(map_lifecycle_host_error)?;
    require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
    // A failed/cancelled factory may have launched a process before returning.
    // The marker therefore precedes the factory and cannot be cleared by Drop.
    let candidate = build_registry_entry_with_admission(
        entry.config.clone(),
        admitted,
        Arc::clone(&state.registry.resilience),
        state.registry.capability_verifying_key,
    )
    .await?;
    let ConnectorRuntime::Native(native) = &candidate.connector else {
        return Err(unavailable(
            "Telegram replacement did not produce a native runtime",
        ));
    };
    let restored = async {
        require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
        let acknowledgement = native
            .rpc_in_handshaken_zone_with_termination(
                &zone,
                "state.restore",
                json!({ "checkpoint": &checkpoint }),
                Some(&termination),
            )
            .await?;
        validate_restore_ack(&acknowledgement, &checkpoint)?;
        require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
        Ok::<(), HostError>(())
    }
    .await;
    if let Err(error) = restored {
        settle_unpublished_candidate(state, connector_id, native, &custody, generation, deadline)
            .await;
        return Err(error);
    }

    // Publish only the restored runtime, while the pending marker independently
    // denies every execution fence. Keep an exact handle for failed publication.
    let retained_candidate = Arc::clone(native);
    let published = lifecycle_runtime::publish_entry(
        &state.registry,
        connector_id,
        candidate,
        generation,
        None,
        deadline,
    )
    .await;
    generation = match published {
        Ok(generation) => generation,
        Err(error) => {
            settle_unpublished_candidate(
                state,
                connector_id,
                &retained_candidate,
                &custody,
                generation,
                deadline,
            )
            .await;
            return Err(error);
        }
    };
    require_custody(state, connector_id, entry, &custody, generation, deadline).await?;
    let (published_entry, published_generation) =
        lifecycle_runtime::selected_entry(&state.registry, connector_id).await?;
    if published_generation != generation
        || !matches!(
            &published_entry.connector,
            ConnectorRuntime::Native(current) if Arc::ptr_eq(current, &retained_candidate)
        )
    {
        return Err(unavailable(
            "Telegram replacement identity changed before activation",
        ));
    }
    let journal_sequence = state
        .lifecycle
        .complete_telegram_polling_restart_guarded(connector_id, &custody, || {
            // The inventory transaction serializes production writers through
            // this synchronous, durable mutation. Recheck after acquiring the
            // admin write lock as well, including the original deadline.
            require_current(&state.registry, generation, deadline).map_err(|error| {
                LifecycleError::Persistence {
                    reason: error.to_string(),
                }
            })?;
            // Every registry replacement advances generation, so the check
            // above also preserves the exact Arc verified after publication.
            if retained_candidate.runtime_retirement.is_exited() {
                return Err(LifecycleError::Persistence {
                    reason: "Telegram replacement exited before activation".to_owned(),
                });
            }
            entry
                .state_policy
                .require_admitted_manifest(&entry.config)
                .map_err(|error| LifecycleError::Persistence {
                    reason: error.to_string(),
                })
        })
        .await
        .map_err(map_lifecycle_host_error)?;
    // Do not add an asynchronous health query after authority is committed.
    response.observed_state = ObservedRuntimeState::Degraded;
    response.journal_sequence = journal_sequence;
    response.transitioned_at = Utc::now();
    Ok(response)
}

#[cfg(test)]
mod tests {
    use fcp_host::HostTelegramPollingCheckpointState;
    use sha2::{Digest, Sha256};

    use super::*;

    fn checkpoint(offset: Option<i64>) -> HostTelegramPollingCheckpoint {
        let state = HostTelegramPollingCheckpointState {
            version: 1,
            connector_id: CONNECTOR.to_owned(),
            zone_id: ZoneId::work().to_string(),
            bot_id: "123456".to_owned(),
            offset,
            last_poll_count: u64::from(offset.is_some()),
            updated_at: 1_780_000_000,
        };
        let mut digest = Sha256::new();
        digest.update(b"fcp.telegram.polling-checkpoint.v1\0");
        digest.update(serde_json::to_vec(&state).unwrap());
        HostTelegramPollingCheckpoint {
            checkpoint_id: format!("sha256:{}", hex::encode(digest.finalize())),
            state,
        }
    }

    fn scoped_config() -> ConnectorConfig {
        let mut config = crate::tests::dispatcher_test_config(CONNECTOR);
        config.binary_sha256 = Some("ab".repeat(32));
        config.env.insert(
            CONNECTOR_STATE_DIR_ENV.to_owned(),
            std::env::temp_dir()
                .join("fcp-telegram-restart-scope")
                .display()
                .to_string(),
        );
        config.config = Some(json!({
            "credential": "123456:abcdefghijklmnopqrstuvwxyz0123456789",
            "receive_mode": "polling",
        }));
        config
    }

    fn singleton_policy() -> ConnectorStatePolicy {
        ConnectorStatePolicy {
            model: ConnectorStateKind::SingletonWriter,
            manifest_digest: Some([7; 32]),
            manifest_bytes: 1,
        }
    }

    #[test]
    fn polling_binding_covers_secret_and_launch_configuration_without_storing_secrets() {
        let original = scoped_config();
        let binding = binding_for_config(&original, singleton_policy()).unwrap();
        assert_eq!(binding.bot_id, "123456");
        assert_eq!(binding.binary_sha256, "ab".repeat(32));
        assert!(
            !serde_json::to_string(&binding)
                .unwrap()
                .contains("abcdefghijklmnopqrstuvwxyz")
        );
        for changed in [
            {
                let mut changed = original.clone();
                changed.config.as_mut().unwrap()["credential"] =
                    json!("123456:zyxwvutsrqponmlkjihgfedcba0123456789");
                changed
            },
            {
                let mut changed = original.clone();
                changed.args.push("--changed".to_owned());
                changed
            },
            {
                let mut changed = original.clone();
                changed
                    .env
                    .insert("EXTRA_SETTING".to_owned(), "changed".to_owned());
                changed
            },
        ] {
            assert_ne!(
                binding.config_digest,
                binding_for_config(&changed, singleton_policy())
                    .unwrap()
                    .config_digest,
            );
        }
        for invalid in [
            {
                let mut changed = original.clone();
                changed.config.as_mut().unwrap()["receive_mode"] = json!("webhook");
                changed
            },
            {
                let mut changed = original.clone();
                changed.allowed_zones.push("z:private".to_owned());
                changed
            },
            {
                let mut changed = original.clone();
                changed.binary_sha256 = None;
                changed
            },
            {
                let mut changed = original.clone();
                changed
                    .env
                    .insert(CONNECTOR_STATE_DIR_ENV.to_owned(), "relative".to_owned());
                changed
            },
            {
                let mut changed = original.clone();
                changed.config.as_mut().unwrap()["credential_id"] = json!("external-secret");
                changed
            },
        ] {
            assert!(binding_for_config(&invalid, singleton_policy()).is_err());
        }
        assert!(
            binding_for_config(
                &original,
                ConnectorStatePolicy {
                    model: ConnectorStateKind::Crdt,
                    ..singleton_policy()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn restore_ack_requires_exact_cursor_and_explicit_null() {
        for offset in [None, Some(1001)] {
            let checkpoint = checkpoint(offset);
            let valid = json!({
                "status": "restored",
                "checkpoint_id": checkpoint.checkpoint_id,
                "offset": offset,
            });
            validate_restore_ack(&valid, &checkpoint).unwrap();
            for invalid in [
                {
                    let mut value = valid.clone();
                    value.as_object_mut().unwrap().remove("offset");
                    value
                },
                {
                    let mut value = valid.clone();
                    value["offset"] = json!(offset.map_or(0, |value| value + 1));
                    value
                },
                {
                    let mut value = valid.clone();
                    value["checkpoint_id"] = json!("sha256:wrong");
                    value
                },
                {
                    let mut value = valid.clone();
                    value["status"] = json!("accepted");
                    value
                },
                {
                    let mut value = valid.clone();
                    value["unexpected"] = json!(true);
                    value
                },
            ] {
                assert!(validate_restore_ack(&invalid, &checkpoint).is_err());
            }
        }
    }

    #[test]
    fn dormant_recovery_requires_both_exit_proofs_and_matching_scope() {
        let binding = binding_for_config(&scoped_config(), singleton_policy()).unwrap();
        let mut preparation = TelegramPollingRestartPreparation {
            expected_journal_sequence: 5,
            previous_desired_state: DesiredRuntimeState::Disabled,
            pending: Some(TelegramPollingRestartCustody {
                custody_id: 1,
                binding: binding.clone(),
                checkpoint: Some(checkpoint(Some(1001))),
                source_exited: true,
                candidate_may_exist: false,
                intent_revoked: true,
            }),
        };
        // A later explicit request can authorize a fresh attempt, but cannot
        // manufacture a process-exit proof lost across host restart.
        validate_recovery(true, LifecycleAction::Enable, &preparation, &binding).unwrap();
        preparation.pending.as_mut().unwrap().source_exited = false;
        assert!(validate_recovery(true, LifecycleAction::Enable, &preparation, &binding).is_err());
        preparation.pending.as_mut().unwrap().source_exited = true;
        preparation.pending.as_mut().unwrap().candidate_may_exist = true;
        assert!(validate_recovery(true, LifecycleAction::Enable, &preparation, &binding).is_err());
        validate_recovery(false, LifecycleAction::Enable, &preparation, &binding).unwrap();
        preparation.pending.as_mut().unwrap().binding.config_digest = "ff".repeat(32);
        assert!(validate_recovery(false, LifecycleAction::Enable, &preparation, &binding).is_err());
    }

    #[cfg(target_os = "linux")]
    type PollingFixture = (
        tempfile::TempDir,
        Arc<AppState>,
        Arc<SubprocessConnector>,
        HostTelegramPollingCheckpoint,
        TestHrwLeaseRoutingOverrideGuard,
    );

    #[cfg(target_os = "linux")]
    async fn fixture() -> PollingFixture {
        fixture_with_checkpoint(None).await
    }

    #[cfg(target_os = "linux")]
    async fn fixture_with_checkpoint(checkpoint_override: Option<Value>) -> PollingFixture {
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let eligible_nodes = vec![
            TailscaleNodeId::new("telegram-restart-a"),
            TailscaleNodeId::new("telegram-restart-b"),
            TailscaleNodeId::new("telegram-restart-c"),
        ];
        let subject = singleton_writer_connector_lease_subject_id(&connector_id, &ZoneId::work());
        let local_node =
            fcp_mesh::planner::select_lease_holder(&ZoneId::work(), &subject, &eligible_nodes)
                .expect("fixture selects its actual singleton writer");
        let routing = set_test_hrw_lease_routing_override(Some(HrwLeaseRoutingConfig {
            local_node,
            eligible_nodes,
            current_lease_seq: Some(42),
        }));
        let directory = tempfile::tempdir().unwrap();
        let checkpoint = checkpoint(Some(1001));
        let mut config = crate::tests::subprocess_test_connector_config(CONNECTOR);
        config.binary_sha256 = Some(hex::encode(Sha256::digest(
            std::fs::read(&config.binary).expect("read exact fixture executable"),
        )));
        let manifest = directory.path().join("manifest.toml");
        std::fs::write(
            &manifest,
            crate::tests::state_policy_test_manifest_for(
                CONNECTOR,
                Some("singleton_writer"),
                false,
            ),
        )
        .unwrap();
        config.manifest_path = Some(manifest.display().to_string());
        config.config = scoped_config().config;
        for (key, value) in [
            (
                CONNECTOR_STATE_DIR_ENV,
                directory.path().join("state").display().to_string(),
            ),
            (
                "FCP_TEST_CONNECTOR_TELEGRAM_CHECKPOINT",
                checkpoint_override
                    .unwrap_or_else(|| serde_json::to_value(&checkpoint).unwrap())
                    .to_string(),
            ),
            (
                "FCP_TEST_CONNECTOR_RESTORE_READY",
                directory.path().join("restore-ready").display().to_string(),
            ),
            (
                "FCP_TEST_CONNECTOR_RESTORE_RELEASE",
                directory
                    .path()
                    .join("restore-release")
                    .display()
                    .to_string(),
            ),
        ] {
            config.env.insert(key.to_owned(), value);
        }
        let lifecycle = Arc::new(
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap(),
        );
        lifecycle
            .set_desired_state(&connector_id, DesiredRuntimeState::Enabled, None)
            .await
            .unwrap();
        let signing_key = fcp_crypto::ed25519::Ed25519SigningKey::generate();
        let registry = Arc::new(
            SubprocessRegistry::from_configs_with_lifecycle(
                vec![config],
                Some(signing_key.verifying_key().to_bytes()),
                &lifecycle,
            )
            .await
            .expect("launch pinned native polling fixture"),
        );
        lifecycle
            .reconcile_registered_connectors(&registry.list().await)
            .await
            .unwrap();
        let (entry, _) = lifecycle_runtime::selected_entry(&registry, &connector_id)
            .await
            .unwrap();
        let ConnectorRuntime::Native(source) = entry.connector else {
            panic!("fixture must own a real native child");
        };
        let state = crate::tests::dispatcher_app_state(
            registry,
            lifecycle,
            Some(signing_key.verifying_key()),
            HashMap::new(),
        );
        (directory, state, source, checkpoint, routing)
    }

    fn request(action: LifecycleAction) -> LifecycleTransitionRequest {
        LifecycleTransitionRequest {
            action,
            reason: Some("Telegram polling custody regression".to_owned()),
            initiated_by: Some("test".to_owned()),
            dry_run: false,
        }
    }

    #[cfg(target_os = "linux")]
    fn start_transition(
        state: &Arc<AppState>,
        action: LifecycleAction,
    ) -> JoinHandle<HostResult<LifecycleTransitionResponse>> {
        let state = Arc::clone(state);
        task::spawn(async move {
            lifecycle_runtime::transition(
                &state,
                &ConnectorId::from_static(CONNECTOR),
                &request(action),
            )
            .await
        })
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_restore(directory: &StdPath) {
        fcp_async_core::time::timeout(Duration::from_secs(5), async {
            while !directory.join("restore-ready").exists() {
                fcp_async_core::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("replacement must reach the controlled restore boundary");
    }

    #[cfg(target_os = "linux")]
    async fn assert_restore_is_denied(
        state: &AppState,
        source: &SubprocessConnector,
        checkpoint: &HostTelegramPollingCheckpoint,
    ) {
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let record = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap();
        let custody = record.telegram_polling_restart.as_ref().unwrap();
        assert_eq!(record.desired_state, DesiredRuntimeState::Disabled);
        assert_eq!(custody.checkpoint.as_ref(), Some(checkpoint));
        assert!(custody.source_exited && custody.candidate_may_exist);
        assert!(source.runtime_retirement.is_exited());
        assert!(
            state
                .lifecycle
                .connector_execution_fence(&connector_id)
                .await
                .is_err()
        );
        let (entry, _) = lifecycle_runtime::selected_entry(&state.registry, &connector_id)
            .await
            .unwrap();
        assert!(matches!(entry.connector, ConnectorRuntime::Dormant(_)));
    }

    #[cfg(target_os = "linux")]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn real_native_disable_retains_checkpoint_until_explicit_enable_restores() {
        let (directory, state, source, checkpoint, _routing) = fixture().await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let generation = state.registry.version();
        let original = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap();
        let mut preview = request(LifecycleAction::Disable);
        preview.dry_run = true;
        let preview_response = lifecycle_runtime::transition(&state, &connector_id, &preview)
            .await
            .unwrap();
        assert_eq!(
            preview_response.current_desired_state,
            DesiredRuntimeState::Disabled
        );
        assert_eq!(state.registry.version(), generation);
        assert!(!source.runtime_retirement.is_exited());
        let unchanged = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap();
        assert_eq!(
            unchanged.last_journal_sequence,
            original.last_journal_sequence
        );
        assert!(unchanged.telegram_polling_restart.is_none());

        let response = lifecycle_runtime::transition(
            &state,
            &connector_id,
            &request(LifecycleAction::Disable),
        )
        .await
        .unwrap();
        assert_eq!(response.action, LifecycleAction::Disable);
        assert_eq!(
            response.previous_desired_state,
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            response.current_desired_state,
            DesiredRuntimeState::Disabled
        );
        assert_eq!(response.observed_state, ObservedRuntimeState::Stopped);
        assert_eq!(state.registry.version(), generation + 1);
        assert!(source.runtime_retirement.is_exited());
        assert!(!directory.path().join("restore-ready").exists());

        let stopped = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap();
        let custody = stopped.telegram_polling_restart.as_ref().unwrap();
        assert_eq!(custody.checkpoint.as_ref(), Some(&checkpoint));
        assert!(custody.source_exited && !custody.candidate_may_exist);
        assert!(!custody.intent_revoked);
        assert_eq!(stopped.observed_state, ObservedRuntimeState::Stopped);
        assert_eq!(stopped.last_journal_sequence, response.journal_sequence);
        assert!(
            state
                .lifecycle
                .connector_execution_fence(&connector_id)
                .await
                .is_err()
        );
        let (dormant, _) = lifecycle_runtime::selected_entry(&state.registry, &connector_id)
            .await
            .unwrap();
        assert!(matches!(dormant.connector, ConnectorRuntime::Dormant(_)));

        // Repeated Disable uses the ordinary dormant path. It revokes the old
        // attempt but must preserve the checkpoint for a later explicit Enable.
        let repeated = lifecycle_runtime::transition(
            &state,
            &connector_id,
            &request(LifecycleAction::Disable),
        )
        .await
        .unwrap();
        assert_eq!(
            repeated.current_desired_state,
            DesiredRuntimeState::Disabled
        );
        assert_eq!(repeated.observed_state, ObservedRuntimeState::Stopped);
        let repeated_custody = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap()
            .telegram_polling_restart
            .unwrap();
        assert_eq!(repeated_custody.custody_id, custody.custody_id);
        assert_eq!(repeated_custody.checkpoint.as_ref(), Some(&checkpoint));
        assert!(repeated_custody.source_exited && !repeated_custody.candidate_may_exist);
        assert!(repeated_custody.intent_revoked);
        assert!(!directory.path().join("restore-ready").exists());

        let enable = start_transition(&state, LifecycleAction::Enable);
        wait_for_restore(directory.path()).await;
        assert_restore_is_denied(&state, &source, &checkpoint).await;
        std::fs::write(directory.path().join("restore-release"), b"continue").unwrap();
        let enabled = enable.await.unwrap().unwrap();
        assert_eq!(enabled.current_desired_state, DesiredRuntimeState::Enabled);
        assert!(
            state
                .lifecycle
                .connector_state(&connector_id)
                .await
                .unwrap()
                .telegram_polling_restart
                .is_none()
        );
        state
            .lifecycle
            .connector_execution_fence(&connector_id)
            .await
            .unwrap();
        let (entry, _) = lifecycle_runtime::selected_entry(&state.registry, &connector_id)
            .await
            .unwrap();
        let ConnectorRuntime::Native(replacement) = entry.connector else {
            panic!("Enable must publish the restored native runtime");
        };
        assert!(!Arc::ptr_eq(&source, &replacement));
        state
            .registry
            .shutdown(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn native_disable_failure_keeps_authority_denied_without_claiming_stop() {
        for reject_checkpoint in [true, false] {
            let mut invalid = serde_json::to_value(checkpoint(Some(1001))).unwrap();
            invalid["checkpoint_id"] = json!("sha256:invalid");
            let (directory, state, source, _checkpoint, _routing) =
                fixture_with_checkpoint(reject_checkpoint.then_some(invalid)).await;
            if !reject_checkpoint {
                std::fs::write(directory.path().join("manifest.toml"), b"invalid manifest")
                    .unwrap();
            }
            let connector_id = ConnectorId::from_static(CONNECTOR);
            let generation = state.registry.version();
            let result = lifecycle_runtime::transition(
                &state,
                &connector_id,
                &request(LifecycleAction::Disable),
            )
            .await;
            assert!(result.is_err());
            assert_eq!(state.registry.version(), generation);
            assert!(!source.runtime_retirement.is_exited());
            assert!(!directory.path().join("restore-ready").exists());
            let denied = state
                .lifecycle
                .connector_state(&connector_id)
                .await
                .unwrap();
            assert_eq!(denied.desired_state, DesiredRuntimeState::Disabled);
            if reject_checkpoint {
                let custody = denied.telegram_polling_restart.as_ref().unwrap();
                assert!(custody.checkpoint.is_none());
                assert!(!custody.source_exited && !custody.candidate_may_exist);
            } else {
                assert!(denied.telegram_polling_restart.is_none());
            }
            assert!(
                state
                    .lifecycle
                    .connector_execution_fence(&connector_id)
                    .await
                    .is_err()
            );
            state
                .registry
                .shutdown(Instant::now() + Duration::from_secs(3))
                .await
                .unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn real_native_restart_commits_cursor_and_exit_before_restore_and_activation() {
        let (directory, state, source, checkpoint, _routing) = fixture().await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let mut preview = request(LifecycleAction::Restart);
        preview.dry_run = true;
        let generation = state.registry.version();
        lifecycle_runtime::transition(&state, &connector_id, &preview)
            .await
            .unwrap();
        assert_eq!(state.registry.version(), generation);
        assert!(
            state
                .lifecycle
                .connector_state(&connector_id)
                .await
                .unwrap()
                .telegram_polling_restart
                .is_none()
        );
        assert!(!source.runtime_retirement.is_exited());

        let restart = start_transition(&state, LifecycleAction::Restart);
        wait_for_restore(directory.path()).await;
        assert_restore_is_denied(&state, &source, &checkpoint).await;
        let reopened =
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap();
        let durable = reopened.connector_state(&connector_id).await.unwrap();
        assert!(
            durable
                .telegram_polling_restart
                .unwrap()
                .candidate_may_exist
        );
        assert!(
            reopened
                .connector_execution_fence(&connector_id)
                .await
                .is_err()
        );
        std::fs::write(directory.path().join("restore-release"), b"continue").unwrap();

        let response = restart.await.unwrap().unwrap();
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
        let record = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap();
        assert!(record.telegram_polling_restart.is_none());
        state
            .lifecycle
            .connector_execution_fence(&connector_id)
            .await
            .unwrap();
        let (entry, _) = lifecycle_runtime::selected_entry(&state.registry, &connector_id)
            .await
            .unwrap();
        let ConnectorRuntime::Native(replacement) = entry.connector else {
            panic!("restored runtime must be published");
        };
        assert!(!Arc::ptr_eq(&source, &replacement));
        assert!(source.runtime_retirement.is_exited());
        state
            .registry
            .shutdown(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn concurrent_disable_handler_revokes_pending_restore_before_inventory_gate() {
        let (directory, state, source, checkpoint, _routing) = fixture().await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let restart = start_transition(&state, LifecycleAction::Restart);
        wait_for_restore(directory.path()).await;
        assert_restore_is_denied(&state, &source, &checkpoint).await;

        // Exercise the lifecycle handler itself: it must persist the newer
        // denial while Restart still owns the inventory transaction.
        let disable = start_transition(&state, LifecycleAction::Disable);
        fcp_async_core::time::timeout(Duration::from_secs(3), async {
            loop {
                let record = state
                    .lifecycle
                    .connector_state(&connector_id)
                    .await
                    .unwrap();
                if record
                    .telegram_polling_restart
                    .as_ref()
                    .unwrap()
                    .intent_revoked
                {
                    break;
                }
                fcp_async_core::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("Disable must revoke custody without waiting for the inventory gate");
        std::fs::write(directory.path().join("restore-release"), b"continue").unwrap();
        assert!(restart.await.unwrap().is_err());
        let response = disable.await.unwrap().unwrap();
        assert_eq!(
            response.current_desired_state,
            DesiredRuntimeState::Disabled
        );
        assert!(
            state
                .lifecycle
                .connector_execution_fence(&connector_id)
                .await
                .is_err()
        );
        let record = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap();
        assert!(record.telegram_polling_restart.unwrap().intent_revoked);
        let (entry, _) = lifecycle_runtime::selected_entry(&state.registry, &connector_id)
            .await
            .unwrap();
        assert!(matches!(entry.connector, ConnectorRuntime::Dormant(_)));
    }

    #[cfg(target_os = "linux")]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn durable_source_exit_recovers_after_host_reopen_without_a_retained_image() {
        let (directory, state, source, expected_checkpoint, _routing) = fixture().await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let (entry, _) = lifecycle_runtime::selected_entry(&state.registry, &connector_id)
            .await
            .unwrap();
        let config = entry.config.clone();
        let stopped = lifecycle_runtime::transition(
            &state,
            &connector_id,
            &request(LifecycleAction::Disable),
        )
        .await
        .unwrap();
        assert_eq!(stopped.observed_state, ObservedRuntimeState::Stopped);
        assert!(source.runtime_retirement.is_exited());
        let retained = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap()
            .telegram_polling_restart
            .unwrap();
        assert_eq!(retained.checkpoint, Some(expected_checkpoint));
        assert!(retained.source_exited && !retained.candidate_may_exist);
        state
            .registry
            .shutdown(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        let verifying_key = state.capability_verifying_key.clone();
        let key_bytes = state.registry.capability_verifying_key;
        drop(state);
        drop(source);

        let reopened = Arc::new(
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap(),
        );
        let registry = Arc::new(
            SubprocessRegistry::from_configs_with_lifecycle(vec![config], key_bytes, &reopened)
                .await
                .unwrap(),
        );
        let (dormant, _) = lifecycle_runtime::selected_entry(&registry, &connector_id)
            .await
            .unwrap();
        assert!(matches!(&dormant.connector, ConnectorRuntime::Dormant(_)));
        assert!(dormant.admitted_native_executable().is_none());
        let recovered =
            crate::tests::dispatcher_app_state(registry, reopened, verifying_key, HashMap::new());
        std::fs::write(directory.path().join("restore-release"), b"continue").unwrap();
        let response = lifecycle_runtime::transition(
            &recovered,
            &connector_id,
            &request(LifecycleAction::Enable),
        )
        .await
        .unwrap();
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
        let (entry, _) = lifecycle_runtime::selected_entry(&recovered.registry, &connector_id)
            .await
            .unwrap();
        assert!(entry.admitted_native_executable().is_some());
        assert!(matches!(entry.connector, ConnectorRuntime::Native(_)));
        let record = recovered
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap();
        assert!(record.telegram_polling_restart.is_none());
        recovered
            .registry
            .shutdown(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[fcp_async_core::runtime::test(flavor = "multi_thread")]
    async fn cancelled_unpublished_candidate_cannot_be_reconstructed_from_dormant_inventory() {
        let (directory, state, source, checkpoint, _routing) = fixture().await;
        let connector_id = ConnectorId::from_static(CONNECTOR);
        let restart = start_transition(&state, LifecycleAction::Restart);
        wait_for_restore(directory.path()).await;
        assert_restore_is_denied(&state, &source, &checkpoint).await;
        restart.abort();
        let _ = restart.await;
        std::fs::write(
            directory.path().join("restore-release"),
            b"finish cancelled fixture",
        )
        .unwrap();
        let before = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap();
        assert!(
            before
                .telegram_polling_restart
                .as_ref()
                .unwrap()
                .candidate_may_exist
        );
        let generation = state.registry.version();
        assert!(lifecycle_runtime::transition(
            &state,
            &connector_id,
            &request(LifecycleAction::Enable),
        ).await.is_err());
        let after = state
            .lifecycle
            .connector_state(&connector_id)
            .await
            .unwrap();
        assert_eq!(
            after.telegram_polling_restart,
            before.telegram_polling_restart
        );
        assert_eq!(state.registry.version(), generation);
        assert!(
            state
                .lifecycle
                .connector_execution_fence(&connector_id)
                .await
                .is_err()
        );
    }
}
