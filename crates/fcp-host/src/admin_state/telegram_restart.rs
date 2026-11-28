//! Durable custody for local Telegram polling restart and checkpointed stop.
//!
//! This is not a generic connector state handoff. The host keeps a validated
//! native Telegram checkpoint while ordinary execution is independently denied.

use sha2::{Digest, Sha256};

use super::*;

/// Native Telegram rejects checkpoint requests larger than this bound.
pub const TELEGRAM_POLLING_CHECKPOINT_MAX_BYTES: usize = 8192;
const CONNECTOR: &str = "fcp.telegram";

/// Immutable deployment and polling identity selected by a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramPollingRestartBinding {
    /// Digest of the complete managed configuration, including credentials.
    pub config_digest: String,
    /// Frozen admitted manifest digest.
    pub manifest_digest: String,
    /// Explicit SHA-256 pin of the retained immutable native image.
    pub binary_sha256: String,
    /// The single admitted polling zone.
    pub zone_id: String,
    /// Numeric inline bot identity; the token itself is never persisted here.
    pub bot_id: String,
    /// Explicit absolute host-owned state root.
    pub state_root: String,
}

impl TelegramPollingRestartBinding {
    /// Validate bounded, non-secret checkpoint binding metadata.
    ///
    /// # Errors
    /// Refuses malformed digests, polling identities or state roots.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !digest(&self.config_digest)
            || !digest(&self.manifest_digest)
            || !digest(&self.binary_sha256)
            || self.zone_id.len() > 256
            || self.zone_id.parse::<fcp_core::ZoneId>().is_err()
            || self.bot_id.is_empty()
            || self.bot_id.len() > 20
            || !self.bot_id.bytes().all(|byte| byte.is_ascii_digit())
            || self.state_root.len() > 4096
            || !Path::new(&self.state_root).is_absolute()
        {
            return Err(invalid("invalid Telegram polling restart binding"));
        }
        Ok(())
    }
}

/// The exact native Telegram polling checkpoint envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostTelegramPollingCheckpoint {
    /// Domain-separated content digest supplied by the connector.
    pub checkpoint_id: String,
    /// Cursor payload whose field order matches the native digest contract.
    pub state: HostTelegramPollingCheckpointState,
}

/// Version-one native Telegram cursor state.
///
/// Keep serialization order synchronized with TelegramPollingCheckpointState:
/// the connector hashes this JSON representation, not a generic JSON map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostTelegramPollingCheckpointState {
    /// Native polling checkpoint schema version.
    pub version: u8,
    /// Exact connector identity.
    pub connector_id: String,
    /// Handshaken zone.
    pub zone_id: String,
    /// Inline bot identity.
    pub bot_id: String,
    /// First provider update still eligible for delivery.
    pub offset: Option<i64>,
    /// Number of updates in the last committed poll, bounded by Telegram to 100.
    pub last_poll_count: u64,
    /// Native cursor timestamp in Unix seconds.
    pub updated_at: u64,
}

impl HostTelegramPollingCheckpoint {
    fn content_id(&self) -> Result<String, LifecycleError> {
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|_| invalid("could not encode Telegram polling checkpoint"))?;
        let mut digest = Sha256::new();
        digest.update(b"fcp.telegram.polling-checkpoint.v1\0");
        digest.update(bytes);
        Ok(format!("sha256:{}", hex::encode(digest.finalize())))
    }

    /// Decode the bounded native envelope and validate its complete identity.
    ///
    /// # Errors
    /// Refuses oversized, unknown-field, corrupt or mismatched checkpoints.
    pub fn from_value(
        value: Value,
        binding: &TelegramPollingRestartBinding,
    ) -> Result<Self, LifecycleError> {
        let bytes = serde_json::to_vec(&value)
            .map_err(|_| invalid("could not encode Telegram polling checkpoint"))?;
        if bytes.len() > TELEGRAM_POLLING_CHECKPOINT_MAX_BYTES {
            return Err(invalid(
                "Telegram polling checkpoint exceeded its byte limit",
            ));
        }
        let checkpoint: Self = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid Telegram polling checkpoint envelope"))?;
        checkpoint.validate(binding)?;
        Ok(checkpoint)
    }

    /// Validate the connector's digest and the deployment's zone and bot scope.
    ///
    /// # Errors
    /// Refuses malformed or incompatible polling state.
    pub fn validate(&self, binding: &TelegramPollingRestartBinding) -> Result<(), LifecycleError> {
        binding.validate()?;
        if self.state.version != 1
            || self.state.connector_id != CONNECTOR
            || self.state.zone_id != binding.zone_id
            || self.state.bot_id != binding.bot_id
            || self.state.offset.is_some_and(|offset| offset < 0)
            || self.state.last_poll_count > 100
            || self.checkpoint_id != self.content_id()?
        {
            return Err(invalid(
                "Telegram polling checkpoint integrity or scope mismatch",
            ));
        }
        Ok(())
    }
}

/// Persisted interruption evidence. Its presence independently denies dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramPollingRestartCustody {
    /// Fresh journal sequence for this explicit operator attempt.
    pub custody_id: u64,
    /// Exact denied intent held throughout checkpoint and process custody.
    /// Older snapshots held Disabled; preserve that authority instead of
    /// inferring intent from the mutable lifecycle record.
    #[serde(default = "default_custody_desired_state")]
    pub desired_state: DesiredRuntimeState,
    /// Immutable deployment and polling scope.
    pub binding: TelegramPollingRestartBinding,
    /// Validated native state, retained across every failure after capture.
    pub checkpoint: Option<HostTelegramPollingCheckpoint>,
    /// The original exact child was observed exited after checkpoint custody.
    pub source_exited: bool,
    /// A replacement may exist; a dormant inventory is not evidence of its exit.
    pub candidate_may_exist: bool,
    /// A newer operator or configuration mutation revoked this attempt.
    pub intent_revoked: bool,
}

const fn default_custody_desired_state() -> DesiredRuntimeState {
    DesiredRuntimeState::Disabled
}

/// Operator-visible restart evidence without configuration or cursor payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramPollingRestartStatus {
    /// Identity of the current explicit restart attempt.
    pub custody_id: u64,
    /// Content identity of the checkpoint in durable custody, when captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    /// The exact source child was observed exited after checkpoint custody.
    pub source_exited: bool,
    /// A replacement may exist and still needs confirmed retirement or activation.
    pub candidate_may_exist: bool,
    /// A newer operator or configuration mutation revoked this attempt.
    pub intent_revoked: bool,
}

impl From<&TelegramPollingRestartCustody> for TelegramPollingRestartStatus {
    fn from(custody: &TelegramPollingRestartCustody) -> Self {
        Self {
            custody_id: custody.custody_id,
            checkpoint_id: custody
                .checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.checkpoint_id.clone()),
            source_exited: custody.source_exited,
            candidate_may_exist: custody.candidate_may_exist,
            intent_revoked: custody.intent_revoked,
        }
    }
}

/// Read-only preparation captured before any asynchronous restart work.
#[derive(Debug, Clone)]
pub struct TelegramPollingRestartPreparation {
    /// Journal revision that begin must still observe.
    pub expected_journal_sequence: u64,
    /// Desired state reported to the caller before restart.
    pub previous_desired_state: DesiredRuntimeState,
    /// Previously retained immutable custody, including revoked attempts.
    pub pending: Option<TelegramPollingRestartCustody>,
}

fn invalid(message: &str) -> LifecycleError {
    invocation_state_error(message)
}

fn require_connector(connector_id: &ConnectorId) -> Result<(), LifecycleError> {
    if connector_id.as_str() != CONNECTOR {
        return Err(invalid(
            "polling restart custody is available only for fcp.telegram",
        ));
    }
    Ok(())
}

fn require_sequence(snapshot: &HostAdminStateSnapshot) -> Result<(), LifecycleError> {
    if snapshot.next_journal_sequence == 0 || snapshot.next_journal_sequence >= u64::MAX - 1 {
        return Err(invalid("Telegram polling restart journal is exhausted"));
    }
    Ok(())
}

fn require_custody(
    snapshot: &HostAdminStateSnapshot,
    connector_id: &ConnectorId,
    custody: &TelegramPollingRestartCustody,
) -> Result<(), LifecycleError> {
    let state = snapshot
        .connectors
        .get(connector_id)
        .ok_or_else(|| invalid("Telegram polling restart state is missing"))?;
    if custody.intent_revoked
        || !matches!(
            custody.desired_state,
            DesiredRuntimeState::Disabled | DesiredRuntimeState::Uninstalled
        )
        || state.desired_state != custody.desired_state
        || state.telegram_polling_restart.as_ref() != Some(custody)
    {
        return Err(invalid(
            "Telegram polling restart intent changed; prepare a new explicit attempt",
        ));
    }
    Ok(())
}

pub(super) fn validate_persisted_restarts(snapshot: &HostAdminStateSnapshot) -> HostResult<()> {
    for (connector_id, state) in &snapshot.connectors {
        let Some(custody) = &state.telegram_polling_restart else {
            continue;
        };
        let valid = (|| {
            require_connector(connector_id)?;
            custody.binding.validate()?;
            if custody.custody_id == 0
                || custody.custody_id >= snapshot.next_journal_sequence
                || desired_state_allows_execution(state.desired_state)
                || !matches!(
                    custody.desired_state,
                    DesiredRuntimeState::Disabled | DesiredRuntimeState::Uninstalled
                )
                || (!custody.intent_revoked && state.desired_state != custody.desired_state)
                || (custody.source_exited && custody.checkpoint.is_none())
                || (custody.candidate_may_exist && !custody.source_exited)
            {
                return Err(invalid("invalid persisted Telegram polling restart phase"));
            }
            if let Some(checkpoint) = &custody.checkpoint {
                checkpoint.validate(&custody.binding)?;
            }
            Ok(())
        })();
        valid.map_err(|_: LifecycleError| {
            HostError::Unavailable(
                "persisted Telegram polling restart custody is invalid".to_owned(),
            )
        })?;
    }
    Ok(())
}

/// Cover every admin mutation path, including repeated Disable and config ABA.
/// Routine observed-health updates do not revoke a restart. A lifecycle record
/// save with a changed version/state does. The restart's own phase mutations
/// carry their own exact-custody checks and do not enter this list.
pub(super) fn revoke_changed_restart_intent(
    previous: &HostAdminStateSnapshot,
    next: &mut HostAdminStateSnapshot,
) {
    let mut revoked = HashSet::new();
    for entry in next.journal.iter().skip(previous.journal.len()) {
        let changes_intent = match &entry.mutation {
            AdminStateMutation::ObservedStateSet { .. }
            | AdminStateMutation::TelegramPollingRestartStarted { .. }
            | AdminStateMutation::TelegramPollingRestartCheckpointed { .. }
            | AdminStateMutation::TelegramPollingRestartSourceExited
            | AdminStateMutation::TelegramPollingRestartCandidateStarting
            | AdminStateMutation::TelegramPollingRestartCandidateExited
            | AdminStateMutation::TelegramPollingRestartCompleted { .. } => false,
            AdminStateMutation::LifecycleRecordSaved { version, state } => previous
                .connectors
                .get(&entry.connector_id)
                .and_then(|record| record.lifecycle.as_ref())
                .is_none_or(|record| record.version != *version || record.state != *state),
            _ => true,
        };
        if changes_intent {
            revoked.insert(entry.connector_id.clone());
        }
    }
    for connector_id in revoked {
        if let Some(custody) = next
            .connectors
            .get_mut(&connector_id)
            .and_then(|state| state.telegram_polling_restart.as_mut())
        {
            custody.intent_revoked = true;
        }
    }
}

impl HostAdminStateStore {
    fn require_telegram_restart_persistence(&self) -> Result<(), LifecycleError> {
        if self.state_path.is_none() || !cfg!(unix) {
            return Err(invalid(
                "Telegram polling restart requires synced persistent admin state",
            ));
        }
        if self.persistence_failed.load(Ordering::Acquire) {
            return Err(invalid(
                "Telegram polling restart is fenced after a persistence failure",
            ));
        }
        Ok(())
    }

    /// Disable or uninstall Telegram and return the exact committed denial revision.
    ///
    /// The caller captures the prior revision before waiting on any runtime.
    /// An early denial may follow normal phase progress in the same unrevoked
    /// custody, but cannot follow a new operator/configuration intent. Unlike a
    /// read after mutation, this receipt cannot attribute a later edit to the
    /// older stop request.
    /// Denial remains available even when persistent checkpoint custody cannot
    /// be admitted; attempting a stop never restores execution authority.
    ///
    /// # Errors
    /// Refuses a different connector, dry-run/non-stop request, a downgrade of
    /// uninstall intent, superseded revision, exhausted journal or failed persistence.
    pub async fn deny_telegram_polling_stop(
        &self,
        connector_id: &ConnectorId,
        expected_journal_sequence: u64,
        expected_custody: Option<&TelegramPollingRestartCustody>,
        request: &LifecycleTransitionRequest,
    ) -> Result<LifecycleTransitionResponse, LifecycleError> {
        require_connector(connector_id)?;
        if request.dry_run
            || !matches!(
                request.action,
                LifecycleAction::Disable | LifecycleAction::Uninstall
            )
        {
            return Err(invalid(
                "Telegram stop denial requires a live Disable or Uninstall request",
            ));
        }
        let desired_state = match request.action {
            LifecycleAction::Uninstall => DesiredRuntimeState::Uninstalled,
            _ => DesiredRuntimeState::Disabled,
        };
        self.apply_mutation(|snapshot| {
            let state = snapshot
                .connectors
                .get(connector_id)
                .ok_or_else(|| invalid("Telegram polling stop state is missing"))?;
            if state.desired_state == DesiredRuntimeState::Uninstalled
                && desired_state != DesiredRuntimeState::Uninstalled
            {
                return Err(invalid(
                    "an uninstalled Telegram connector cannot be downgraded to Disabled",
                ));
            }
            let same_custody = expected_custody.is_some_and(|expected| {
                state
                    .telegram_polling_restart
                    .as_ref()
                    .is_some_and(|current| {
                        current.custody_id == expected.custody_id
                            && current.binding == expected.binding
                            && current.desired_state == expected.desired_state
                    })
            });
            if expected_custody.is_some() && !same_custody {
                return Err(invalid("Telegram stop custody was superseded"));
            }
            if state.last_journal_sequence != expected_journal_sequence {
                let phase_progress_only = same_custody
                    && state.last_journal_sequence > expected_journal_sequence
                    && expected_custody.is_some_and(|expected| {
                        state.desired_state == expected.desired_state
                            && !expected.intent_revoked
                            && expected_journal_sequence >= expected.custody_id
                    })
                    && state
                        .telegram_polling_restart
                        .as_ref()
                        .is_some_and(|current| !current.intent_revoked);
                if !phase_progress_only {
                    return Err(invalid("Telegram stop denial was superseded"));
                }
            }
            let now = Utc::now();
            let previous = connector_admin_status_from_state(connector_id, state, now);
            require_sequence(snapshot)?;
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::DesiredStateSet { desired_state },
                request
                    .initiated_by
                    .clone()
                    .or_else(|| Some("admin-api".to_owned())),
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.desired_state = desired_state;
            state.last_journal_sequence = sequence;
            Ok(LifecycleTransitionResponse {
                connector_id: connector_id.to_string(),
                action: request.action,
                dry_run: false,
                previous_desired_state: previous.desired_state,
                current_desired_state: desired_state,
                observed_state: previous.observed_state,
                lifecycle_status: previous.lifecycle,
                journal_sequence: sequence,
                transitioned_at: now,
            })
        })
        .await
    }

    /// Revalidate an early stop receipt after waiting for runtime ownership.
    ///
    /// The same revoked custody may have settled an already-owned candidate's
    /// physical exit while the stop waited for the inventory transaction. Only
    /// that monotone settlement and observed-state updates may follow this exact
    /// denial; a repeated denial, configuration edit or new attempt supersedes it.
    ///
    /// # Errors
    /// Refuses an invalid receipt, missing/pruned journal evidence, changed
    /// denied intent or custody identity, or any later authority mutation.
    pub async fn require_telegram_polling_stop_denial(
        &self,
        connector_id: &ConnectorId,
        custody_id: u64,
        denial: &LifecycleTransitionResponse,
    ) -> Result<ConnectorAdminStatus, LifecycleError> {
        require_connector(connector_id)?;
        self.require_telegram_restart_persistence()?;
        let desired_state = match denial.action {
            LifecycleAction::Disable => DesiredRuntimeState::Disabled,
            LifecycleAction::Uninstall => DesiredRuntimeState::Uninstalled,
            _ => return Err(invalid("Telegram stop receipt has no denied intent")),
        };
        if denial.dry_run
            || denial.connector_id != connector_id.as_str()
            || denial.current_desired_state != desired_state
            || custody_id == 0
            || custody_id >= denial.journal_sequence
        {
            return Err(invalid("Telegram stop receipt does not bind this custody"));
        }
        let snapshot = self.state.read().await;
        self.require_telegram_restart_persistence()?;
        let state = snapshot
            .connectors
            .get(connector_id)
            .ok_or_else(|| invalid("Telegram polling stop state is missing"))?;
        let custody = state
            .telegram_polling_restart
            .as_ref()
            .ok_or_else(|| invalid("Telegram polling stop custody is missing"))?;
        if state.desired_state != desired_state
            || custody.custody_id != custody_id
            || !custody.intent_revoked
        {
            return Err(invalid("Telegram stop denial was superseded"));
        }
        let receipt = snapshot
            .journal
            .iter()
            .find(|entry| {
                entry.sequence == denial.journal_sequence && entry.connector_id == *connector_id
            })
            .ok_or_else(|| invalid("Telegram stop denial journal evidence is unavailable"))?;
        if !matches!(
            &receipt.mutation,
            AdminStateMutation::DesiredStateSet { desired_state: recorded }
                if *recorded == desired_state
        ) {
            return Err(invalid(
                "Telegram stop receipt does not match durable denial",
            ));
        }
        let mut last_sequence = denial.journal_sequence;
        for entry in snapshot.journal.iter().filter(|entry| {
            entry.connector_id == *connector_id && entry.sequence > denial.journal_sequence
        }) {
            if !matches!(
                &entry.mutation,
                AdminStateMutation::ObservedStateSet { .. }
                    | AdminStateMutation::TelegramPollingRestartCandidateExited
            ) {
                return Err(invalid("Telegram stop denial was superseded"));
            }
            last_sequence = entry.sequence;
        }
        if state.last_journal_sequence != last_sequence {
            return Err(invalid(
                "Telegram stop denial journal continuity is unavailable",
            ));
        }
        Ok(connector_admin_status_from_state(
            connector_id,
            state,
            Utc::now(),
        ))
    }

    /// Capture operator intent before inspecting or quiescing the runtime.
    ///
    /// # Errors
    /// Refuses missing durability, an uninstalled connector or corrupt custody.
    pub async fn prepare_telegram_polling_restart(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<TelegramPollingRestartPreparation, LifecycleError> {
        self.prepare_telegram_polling_custody(connector_id, DesiredRuntimeState::Disabled)
            .await
    }

    /// Capture a checkpointed uninstall without granting restart authority.
    ///
    /// Preparation is read-only, including for a dry run before denial. Beginning
    /// the custody attempt requires that Uninstalled is already durable.
    ///
    /// # Errors
    /// Refuses missing durability, the wrong connector or exhausted journal.
    pub async fn prepare_telegram_polling_uninstall(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<TelegramPollingRestartPreparation, LifecycleError> {
        self.prepare_telegram_polling_custody(connector_id, DesiredRuntimeState::Uninstalled)
            .await
    }

    async fn prepare_telegram_polling_custody(
        &self,
        connector_id: &ConnectorId,
        desired_state: DesiredRuntimeState,
    ) -> Result<TelegramPollingRestartPreparation, LifecycleError> {
        let snapshot = self.state.read().await;
        self.require_telegram_restart_persistence()?;
        require_connector(connector_id)?;
        require_sequence(&snapshot)?;
        let state = snapshot
            .connectors
            .get(connector_id)
            .ok_or_else(|| invalid("Telegram polling restart state is missing"))?;
        if desired_state != DesiredRuntimeState::Uninstalled
            && (state.desired_state == DesiredRuntimeState::Uninstalled
                || state
                    .telegram_polling_restart
                    .as_ref()
                    .is_some_and(|custody| {
                        custody.desired_state == DesiredRuntimeState::Uninstalled
                    }))
        {
            return Err(invalid(
                "an uninstalled Telegram connector cannot resume polling",
            ));
        }
        Ok(TelegramPollingRestartPreparation {
            expected_journal_sequence: state.last_journal_sequence,
            previous_desired_state: state.desired_state,
            pending: state.telegram_polling_restart.clone(),
        })
    }

    /// Atomically deny execution and start a new explicitly requested attempt.
    ///
    /// Existing checkpoint and process evidence are preserved. The preparation
    /// revision prevents an older request from superseding an intervening
    /// Disable, including one that leaves the desired state Disabled.
    ///
    /// # Errors
    /// Refuses changed intent, changed deployment, exhausted journal or failed sync.
    pub async fn begin_telegram_polling_restart(
        &self,
        connector_id: &ConnectorId,
        preparation: &TelegramPollingRestartPreparation,
        binding: TelegramPollingRestartBinding,
    ) -> Result<TelegramPollingRestartCustody, LifecycleError> {
        self.begin_telegram_polling_custody(
            connector_id,
            preparation,
            binding,
            DesiredRuntimeState::Disabled,
        )
        .await
    }

    /// Begin an uninstall after its execution denial was durably committed.
    ///
    /// Prior checkpoints and unresolved child ownership survive the new attempt.
    /// This custody can settle process exit but cannot start or enable a replacement.
    ///
    /// # Errors
    /// Refuses missing Uninstalled intent, changed revision/deployment, exhausted
    /// journal or failed persistence.
    pub async fn begin_telegram_polling_uninstall(
        &self,
        connector_id: &ConnectorId,
        preparation: &TelegramPollingRestartPreparation,
        binding: TelegramPollingRestartBinding,
    ) -> Result<TelegramPollingRestartCustody, LifecycleError> {
        self.begin_telegram_polling_custody(
            connector_id,
            preparation,
            binding,
            DesiredRuntimeState::Uninstalled,
        )
        .await
    }

    async fn begin_telegram_polling_custody(
        &self,
        connector_id: &ConnectorId,
        preparation: &TelegramPollingRestartPreparation,
        binding: TelegramPollingRestartBinding,
        desired_state: DesiredRuntimeState,
    ) -> Result<TelegramPollingRestartCustody, LifecycleError> {
        self.require_telegram_restart_persistence()?;
        require_connector(connector_id)?;
        binding.validate()?;
        self.apply_mutation(|snapshot| {
            require_sequence(snapshot)?;
            let state = snapshot
                .connectors
                .get(connector_id)
                .ok_or_else(|| invalid("Telegram polling restart state is missing"))?;
            if state.last_journal_sequence != preparation.expected_journal_sequence
                || state.desired_state != preparation.previous_desired_state
                || state.telegram_polling_restart != preparation.pending
                || (desired_state == DesiredRuntimeState::Disabled
                    && (state.desired_state == DesiredRuntimeState::Uninstalled
                        || preparation.pending.as_ref().is_some_and(|custody| {
                            custody.desired_state == DesiredRuntimeState::Uninstalled
                        })))
                || (desired_state == DesiredRuntimeState::Uninstalled
                    && state.desired_state != DesiredRuntimeState::Uninstalled)
            {
                return Err(invalid(
                    "Telegram polling restart preparation was superseded",
                ));
            }
            if preparation
                .pending
                .as_ref()
                .is_some_and(|pending| pending.binding != binding)
            {
                return Err(invalid(
                    "pending Telegram checkpoint belongs to another deployment",
                ));
            }
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::TelegramPollingRestartStarted {
                    config_digest: binding.config_digest.clone(),
                },
                Some("telegram-polling-restart".to_owned()),
            );
            let custody = TelegramPollingRestartCustody {
                custody_id: sequence,
                desired_state,
                binding,
                checkpoint: preparation
                    .pending
                    .as_ref()
                    .and_then(|old| old.checkpoint.clone()),
                source_exited: preparation
                    .pending
                    .as_ref()
                    .is_some_and(|old| old.source_exited),
                candidate_may_exist: preparation
                    .pending
                    .as_ref()
                    .is_some_and(|old| old.candidate_may_exist),
                intent_revoked: false,
            };
            let state = snapshot.connector_state_mut(connector_id);
            state.desired_state = desired_state;
            state.telegram_polling_restart = Some(custody.clone());
            state.last_journal_sequence = sequence;
            Ok(custody)
        })
        .await
    }

    /// Persist verified state before any retirement of the source child.
    ///
    /// # Errors
    /// Refuses changed intent, a different checkpoint, invalid payload or failed sync.
    pub async fn record_telegram_polling_checkpoint(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
        checkpoint: HostTelegramPollingCheckpoint,
    ) -> Result<TelegramPollingRestartCustody, LifecycleError> {
        self.require_telegram_restart_persistence()?;
        checkpoint.validate(&custody.binding)?;
        self.apply_mutation(|snapshot| {
            require_custody(snapshot, connector_id, custody)?;
            if let Some(existing) = &custody.checkpoint {
                return if existing == &checkpoint {
                    Ok(custody.clone())
                } else {
                    Err(invalid("pending Telegram checkpoint cannot be replaced"))
                };
            }
            require_sequence(snapshot)?;
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::TelegramPollingRestartCheckpointed {
                    checkpoint_id: checkpoint.checkpoint_id.clone(),
                },
                Some("telegram-polling-restart".to_owned()),
            );
            let mut updated = custody.clone();
            updated.checkpoint = Some(checkpoint);
            let state = snapshot.connector_state_mut(connector_id);
            state.telegram_polling_restart = Some(updated.clone());
            state.last_journal_sequence = sequence;
            Ok(updated)
        })
        .await
    }

    async fn change_telegram_polling_phase(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
        mutation: AdminStateMutation,
        source_exited: bool,
        candidate_may_exist: bool,
    ) -> Result<TelegramPollingRestartCustody, LifecycleError> {
        self.require_telegram_restart_persistence()?;
        if custody.checkpoint.is_none() || (candidate_may_exist && !source_exited) {
            return Err(invalid(
                "Telegram polling restart has no durable checkpoint",
            ));
        }
        self.apply_mutation(|snapshot| {
            require_custody(snapshot, connector_id, custody)?;
            require_sequence(snapshot)?;
            let sequence = snapshot.append_journal(
                connector_id,
                mutation,
                Some("telegram-polling-restart".to_owned()),
            );
            let mut updated = custody.clone();
            updated.source_exited = source_exited;
            updated.candidate_may_exist = candidate_may_exist;
            let state = snapshot.connector_state_mut(connector_id);
            state.telegram_polling_restart = Some(updated.clone());
            state.last_journal_sequence = sequence;
            Ok(updated)
        })
        .await
    }

    /// Record observed exit of the exact source child after durable checkpoint.
    ///
    /// # Errors
    /// Refuses missing checkpoint, changed intent or failed persistence.
    pub async fn mark_telegram_polling_source_exited(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
    ) -> Result<TelegramPollingRestartCustody, LifecycleError> {
        if custody.candidate_may_exist {
            return Err(invalid(
                "retire the retained Telegram candidate before changing source evidence",
            ));
        }
        self.change_telegram_polling_phase(
            connector_id,
            custody,
            AdminStateMutation::TelegramPollingRestartSourceExited,
            true,
            false,
        )
        .await
    }

    /// Record possible replacement ownership before spawning any new process.
    ///
    /// # Errors
    /// Refuses unresolved ownership, changed intent or failed persistence.
    pub async fn mark_telegram_polling_candidate_starting(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
    ) -> Result<TelegramPollingRestartCustody, LifecycleError> {
        if custody.desired_state != DesiredRuntimeState::Disabled {
            return Err(invalid(
                "Telegram uninstall custody cannot start a replacement",
            ));
        }
        if !custody.source_exited || custody.candidate_may_exist {
            return Err(invalid("Telegram polling process ownership is unresolved"));
        }
        self.change_telegram_polling_phase(
            connector_id,
            custody,
            AdminStateMutation::TelegramPollingRestartCandidateStarting,
            true,
            true,
        )
        .await
    }

    /// Record observed exit of the exact retained replacement child.
    ///
    /// # Errors
    /// Refuses inconsistent phase, changed intent or failed persistence.
    pub async fn mark_telegram_polling_candidate_exited(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
    ) -> Result<TelegramPollingRestartCustody, LifecycleError> {
        if !custody.source_exited || !custody.candidate_may_exist {
            return Err(invalid(
                "Telegram polling replacement ownership is unresolved",
            ));
        }
        self.change_telegram_polling_phase(
            connector_id,
            custody,
            AdminStateMutation::TelegramPollingRestartCandidateExited,
            true,
            false,
        )
        .await
    }

    /// Settle the observed exit of an unpublished candidate after newer denial.
    ///
    /// The caller must own the exact child and observe its physical exit. Only
    /// the replacement-ownership bit may change. A concurrent Disable or
    /// Uninstall may revoke the same custody; this settlement preserves that
    /// revocation, the desired state and every checkpoint/deployment binding.
    /// It never permits starting a child or completing a restart.
    ///
    /// # Errors
    /// Refuses a newer custody attempt, changed checkpoint/process phase,
    /// execution-enabled state, exhausted journal or failed persistence.
    pub async fn settle_telegram_polling_candidate_exited(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
    ) -> Result<TelegramPollingRestartCustody, LifecycleError> {
        self.require_telegram_restart_persistence()?;
        require_connector(connector_id)?;
        if !custody.source_exited || !custody.candidate_may_exist {
            return Err(invalid(
                "Telegram candidate settlement requires unresolved replacement ownership",
            ));
        }
        custody
            .checkpoint
            .as_ref()
            .ok_or_else(|| invalid("Telegram candidate settlement has no checkpoint"))?
            .validate(&custody.binding)?;
        self.apply_mutation(|snapshot| {
            let state = snapshot
                .connectors
                .get(connector_id)
                .ok_or_else(|| invalid("Telegram polling restart state is missing"))?;
            let current = state
                .telegram_polling_restart
                .as_ref()
                .ok_or_else(|| invalid("Telegram candidate custody is missing"))?;
            let mut expected = custody.clone();
            expected.intent_revoked = current.intent_revoked;
            if !matches!(
                state.desired_state,
                DesiredRuntimeState::Disabled | DesiredRuntimeState::Uninstalled
            ) || !matches!(
                current.desired_state,
                DesiredRuntimeState::Disabled | DesiredRuntimeState::Uninstalled
            ) || current != &expected
                || (custody.intent_revoked && !current.intent_revoked)
                || (!current.intent_revoked && state.desired_state != current.desired_state)
            {
                return Err(invalid(
                    "Telegram candidate settlement custody was superseded",
                ));
            }
            let mut updated = current.clone();
            updated.candidate_may_exist = false;
            require_sequence(snapshot)?;
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::TelegramPollingRestartCandidateExited,
                Some("telegram-polling-candidate-settled".to_owned()),
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.telegram_polling_restart = Some(updated.clone());
            state.last_journal_sequence = sequence;
            Ok(updated)
        })
        .await
    }

    /// Recheck exact operator intent before continuing an asynchronous phase.
    ///
    /// # Errors
    /// Refuses changed/revoked custody or uncertain persistence.
    pub async fn require_telegram_polling_restart(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
    ) -> Result<(), LifecycleError> {
        let snapshot = self.state.read().await;
        self.require_telegram_restart_persistence()?;
        require_custody(&snapshot, connector_id, custody)
    }

    /// Record a checkpointed stop after the caller publishes a dormant runtime.
    ///
    /// Custody and its exact denied intent remain durable. Disabled custody may
    /// be restored only by an explicit Enable or Restart. Uninstalled custody
    /// remains ineligible for restart and reports Missing after physical exit.
    /// The callback must prove dormant publication under the inventory lock and
    /// the original deadline; merely requesting shutdown is not an exit proof.
    ///
    /// # Errors
    /// Refuses missing checkpoint/exit evidence, unresolved replacement custody,
    /// changed intent, failed runtime guard or failed durable persistence.
    pub async fn record_telegram_polling_stop_guarded<F>(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
        validate: F,
    ) -> Result<u64, LifecycleError>
    where
        F: FnOnce() -> Result<(), LifecycleError>,
    {
        self.require_telegram_restart_persistence()?;
        custody
            .checkpoint
            .as_ref()
            .ok_or_else(|| invalid("Telegram polling stop has no durable checkpoint"))?
            .validate(&custody.binding)?;
        if !custody.source_exited || custody.candidate_may_exist {
            return Err(invalid(
                "Telegram polling stop has unresolved process ownership",
            ));
        }
        self.apply_mutation(|snapshot| {
            require_custody(snapshot, connector_id, custody)?;
            validate()?;
            require_sequence(snapshot)?;
            let observed_state = match custody.desired_state {
                DesiredRuntimeState::Uninstalled => ObservedRuntimeState::Missing,
                _ => ObservedRuntimeState::Stopped,
            };
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::ObservedStateSet { observed_state },
                Some("telegram-polling-stop".to_owned()),
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.observed_state = observed_state;
            state.last_journal_sequence = sequence;
            Ok(sequence)
        })
        .await
    }

    /// Enable the already-published, successfully restored replacement.
    ///
    /// # Errors
    /// Refuses incomplete process/checkpoint evidence, newer intent or failed sync.
    pub async fn complete_telegram_polling_restart(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
    ) -> Result<u64, LifecycleError> {
        self.complete_telegram_polling_restart_guarded(connector_id, custody, || Ok(()))
            .await
    }

    /// Finalize after rechecking the runtime's inventory and deadline guard.
    ///
    /// The callback runs after acquiring the admin-state write lock and before
    /// its non-cancellable persist/commit section. The host must also retain its
    /// inventory transaction through this call to serialize runtime writers.
    ///
    /// # Errors
    /// Refuses incomplete evidence, changed intent, failed guard or failed sync.
    pub async fn complete_telegram_polling_restart_guarded<F>(
        &self,
        connector_id: &ConnectorId,
        custody: &TelegramPollingRestartCustody,
        validate: F,
    ) -> Result<u64, LifecycleError>
    where
        F: FnOnce() -> Result<(), LifecycleError>,
    {
        self.require_telegram_restart_persistence()?;
        if custody.desired_state != DesiredRuntimeState::Disabled {
            return Err(invalid(
                "Telegram uninstall custody cannot enable a replacement",
            ));
        }
        let checkpoint = custody
            .checkpoint
            .as_ref()
            .ok_or_else(|| invalid("Telegram polling restart has no durable checkpoint"))?;
        checkpoint.validate(&custody.binding)?;
        if !custody.source_exited || !custody.candidate_may_exist {
            return Err(invalid(
                "Telegram polling restart has no restored replacement phase",
            ));
        }
        self.apply_mutation(|snapshot| {
            require_custody(snapshot, connector_id, custody)?;
            validate()?;
            require_sequence(snapshot)?;
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::TelegramPollingRestartCompleted {
                    checkpoint_id: checkpoint.checkpoint_id.clone(),
                },
                Some("telegram-polling-restart".to_owned()),
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.telegram_polling_restart = None;
            state.desired_state = DesiredRuntimeState::Enabled;
            state.observed_state = ObservedRuntimeState::Degraded;
            state.last_journal_sequence = sequence;
            Ok(sequence)
        })
        .await
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn connector_id() -> ConnectorId {
        ConnectorId::from_static(CONNECTOR)
    }

    fn binding() -> TelegramPollingRestartBinding {
        TelegramPollingRestartBinding {
            config_digest: "11".repeat(32),
            manifest_digest: "22".repeat(32),
            binary_sha256: "33".repeat(32),
            zone_id: "z:work".to_owned(),
            bot_id: "123456".to_owned(),
            state_root: "/fixture/telegram-state".to_owned(),
        }
    }

    fn checkpoint() -> HostTelegramPollingCheckpoint {
        let mut checkpoint = HostTelegramPollingCheckpoint {
            checkpoint_id: String::new(),
            state: HostTelegramPollingCheckpointState {
                version: 1,
                connector_id: CONNECTOR.to_owned(),
                zone_id: "z:work".to_owned(),
                bot_id: "123456".to_owned(),
                offset: Some(2003),
                last_poll_count: 3,
                updated_at: 1_700_000_000,
            },
        };
        checkpoint.checkpoint_id = checkpoint.content_id().unwrap();
        checkpoint
    }

    async fn persistent_store() -> (tempfile::TempDir, HostAdminStateStore) {
        let directory = tempfile::tempdir().unwrap();
        let store =
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap();
        store
            .set_desired_state(&connector_id(), DesiredRuntimeState::Enabled, None)
            .await
            .unwrap();
        (directory, store)
    }

    async fn begin(store: &HostAdminStateStore) -> TelegramPollingRestartCustody {
        let preparation = store
            .prepare_telegram_polling_restart(&connector_id())
            .await
            .unwrap();
        store
            .begin_telegram_polling_restart(&connector_id(), &preparation, binding())
            .await
            .unwrap()
    }

    async fn checkpointed(store: &HostAdminStateStore) -> TelegramPollingRestartCustody {
        let custody = begin(store).await;
        store
            .record_telegram_polling_checkpoint(&connector_id(), &custody, checkpoint())
            .await
            .unwrap()
    }

    async fn candidate(store: &HostAdminStateStore) -> TelegramPollingRestartCustody {
        let custody = checkpointed(store).await;
        let custody = store
            .mark_telegram_polling_source_exited(&connector_id(), &custody)
            .await
            .unwrap();
        store
            .mark_telegram_polling_candidate_starting(&connector_id(), &custody)
            .await
            .unwrap()
    }

    fn uninstall_request() -> LifecycleTransitionRequest {
        LifecycleTransitionRequest {
            action: LifecycleAction::Uninstall,
            reason: Some("checkpointed uninstall".to_owned()),
            initiated_by: Some("test-uninstall".to_owned()),
            dry_run: false,
        }
    }

    #[fcp_async_core::runtime::test]
    async fn uninstall_custody_keeps_exact_denial_and_checkpoint_across_reopen() {
        let (directory, store) = persistent_store().await;
        let connector = connector_id();
        let previous = store.connector_status(&connector).await.unwrap();
        let denial = store
            .deny_telegram_polling_stop(
                &connector,
                previous.last_journal_sequence,
                None,
                &uninstall_request(),
            )
            .await
            .unwrap();
        assert_eq!(denial.action, LifecycleAction::Uninstall);
        assert_eq!(
            denial.current_desired_state,
            DesiredRuntimeState::Uninstalled
        );
        let preparation = store
            .prepare_telegram_polling_uninstall(&connector)
            .await
            .unwrap();
        assert_eq!(
            preparation.expected_journal_sequence,
            denial.journal_sequence
        );
        let custody = store
            .begin_telegram_polling_uninstall(&connector, &preparation, binding())
            .await
            .unwrap();
        assert_eq!(custody.desired_state, DesiredRuntimeState::Uninstalled);
        assert!(store.connector_execution_fence(&connector).await.is_err());
        let custody = store
            .record_telegram_polling_checkpoint(&connector, &custody, checkpoint())
            .await
            .unwrap();
        let custody = store
            .mark_telegram_polling_source_exited(&connector, &custody)
            .await
            .unwrap();
        assert!(
            store
                .mark_telegram_polling_candidate_starting(&connector, &custody)
                .await
                .is_err()
        );
        let sequence = store
            .record_telegram_polling_stop_guarded(&connector, &custody, || Ok(()))
            .await
            .unwrap();
        let status = store.connector_status(&connector).await.unwrap();
        assert_eq!(status.desired_state, DesiredRuntimeState::Uninstalled);
        assert_eq!(status.observed_state, ObservedRuntimeState::Missing);
        assert_eq!(status.last_journal_sequence, sequence);
        drop(store);

        let reopened =
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap();
        let record = reopened.connector_state(&connector).await.unwrap();
        assert_eq!(record.desired_state, DesiredRuntimeState::Uninstalled);
        assert_eq!(record.observed_state, ObservedRuntimeState::Missing);
        assert_eq!(record.telegram_polling_restart.as_ref(), Some(&custody));
        assert!(
            reopened
                .connector_execution_fence(&connector)
                .await
                .is_err()
        );
        assert!(
            reopened
                .prepare_telegram_polling_restart(&connector)
                .await
                .is_err()
        );
        let retry = reopened
            .prepare_telegram_polling_uninstall(&connector)
            .await
            .unwrap();
        assert!(
            reopened
                .begin_telegram_polling_restart(&connector, &retry, binding())
                .await
                .is_err()
        );
        let retried = reopened
            .begin_telegram_polling_uninstall(&connector, &retry, binding())
            .await
            .unwrap();
        assert!(retried.custody_id > custody.custody_id);
        assert_eq!(retried.checkpoint, custody.checkpoint);
        assert!(retried.source_exited && !retried.candidate_may_exist);
        assert!(
            reopened
                .record_telegram_polling_stop_guarded(&connector, &custody, || Ok(()))
                .await
                .is_err(),
            "an older completion cannot settle a newer uninstall attempt"
        );
        reopened
            .record_telegram_polling_stop_guarded(&connector, &retried, || Ok(()))
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn uninstall_custody_requires_prior_denial_and_cannot_be_downgraded() {
        let (_directory, store) = persistent_store().await;
        let connector = connector_id();
        let preview = store
            .prepare_telegram_polling_uninstall(&connector)
            .await
            .unwrap();
        assert!(
            store
                .begin_telegram_polling_uninstall(&connector, &preview, binding())
                .await
                .is_err(),
            "read-only preparation cannot substitute for durable uninstall denial"
        );
        assert_eq!(
            store
                .connector_state(&connector)
                .await
                .unwrap()
                .desired_state,
            DesiredRuntimeState::Enabled
        );
        let denial = store
            .deny_telegram_polling_stop(
                &connector,
                preview.expected_journal_sequence,
                None,
                &uninstall_request(),
            )
            .await
            .unwrap();
        assert!(
            store
                .begin_telegram_polling_uninstall(&connector, &preview, binding())
                .await
                .is_err(),
            "the pre-denial revision is stale"
        );
        let preparation = store
            .prepare_telegram_polling_uninstall(&connector)
            .await
            .unwrap();
        let custody = store
            .begin_telegram_polling_uninstall(&connector, &preparation, binding())
            .await
            .unwrap();
        let mut forged = custody.clone();
        forged.desired_state = DesiredRuntimeState::Disabled;
        assert!(
            store
                .require_telegram_polling_restart(&connector, &forged)
                .await
                .is_err()
        );
        let current = store.connector_status(&connector).await.unwrap();
        assert!(current.last_journal_sequence > denial.journal_sequence);
        let mut disable = uninstall_request();
        disable.action = LifecycleAction::Disable;
        assert!(
            store
                .deny_telegram_polling_stop(
                    &connector,
                    current.last_journal_sequence,
                    Some(&custody),
                    &disable,
                )
                .await
                .is_err(),
            "Disable must not make retained uninstall custody restartable"
        );
        assert_eq!(
            store
                .connector_state(&connector)
                .await
                .unwrap()
                .desired_state,
            DesiredRuntimeState::Uninstalled
        );
        store
            .set_desired_state(&connector, DesiredRuntimeState::Uninstalled, None)
            .await
            .unwrap();
        assert!(
            store
                .require_telegram_polling_restart(&connector, &custody)
                .await
                .is_err(),
            "a repeated operator denial must revoke the old attempt"
        );
        let stale = store
            .begin_telegram_polling_uninstall(&connector, &preparation, binding())
            .await;
        assert!(stale.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn generic_desired_state_edit_cannot_convert_uninstall_custody_into_restart() {
        let (_directory, store) = persistent_store().await;
        let connector = connector_id();
        let previous = store.connector_status(&connector).await.unwrap();
        store
            .deny_telegram_polling_stop(
                &connector,
                previous.last_journal_sequence,
                None,
                &uninstall_request(),
            )
            .await
            .unwrap();
        let preparation = store
            .prepare_telegram_polling_uninstall(&connector)
            .await
            .unwrap();
        store
            .begin_telegram_polling_uninstall(&connector, &preparation, binding())
            .await
            .unwrap();
        store
            .set_desired_state(&connector, DesiredRuntimeState::Disabled, None)
            .await
            .unwrap();
        let state = store.connector_state(&connector).await.unwrap();
        assert!(
            state
                .telegram_polling_restart
                .as_ref()
                .unwrap()
                .intent_revoked
        );
        assert!(
            store
                .prepare_telegram_polling_restart(&connector)
                .await
                .is_err()
        );
        let forged = TelegramPollingRestartPreparation {
            expected_journal_sequence: state.last_journal_sequence,
            previous_desired_state: state.desired_state,
            pending: state.telegram_polling_restart,
        };
        assert!(
            store
                .begin_telegram_polling_restart(&connector, &forged, binding())
                .await
                .is_err()
        );
        assert!(store.connector_execution_fence(&connector).await.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn candidate_exit_settlement_preserves_concurrent_uninstall_revocation() {
        let (_directory, store) = persistent_store().await;
        let connector = connector_id();
        let pending = candidate(&store).await;
        let revision = store
            .connector_status(&connector)
            .await
            .unwrap()
            .last_journal_sequence;
        store
            .deny_telegram_polling_stop(&connector, revision, Some(&pending), &uninstall_request())
            .await
            .unwrap();
        assert!(
            store
                .mark_telegram_polling_candidate_exited(&connector, &pending)
                .await
                .is_err(),
            "ordinary phase progress cannot cross a newer denial"
        );
        let settled = store
            .settle_telegram_polling_candidate_exited(&connector, &pending)
            .await
            .unwrap();
        assert!(settled.intent_revoked && settled.source_exited);
        assert!(!settled.candidate_may_exist);
        assert_eq!(settled.desired_state, DesiredRuntimeState::Disabled);
        assert_eq!(settled.checkpoint, pending.checkpoint);
        assert_eq!(
            store
                .connector_state(&connector)
                .await
                .unwrap()
                .desired_state,
            DesiredRuntimeState::Uninstalled
        );
        assert!(
            store
                .complete_telegram_polling_restart(&connector, &settled)
                .await
                .is_err()
        );
        let preparation = store
            .prepare_telegram_polling_uninstall(&connector)
            .await
            .unwrap();
        let fresh = store
            .begin_telegram_polling_uninstall(&connector, &preparation, binding())
            .await
            .unwrap();
        assert_eq!(fresh.desired_state, DesiredRuntimeState::Uninstalled);
        assert_eq!(fresh.checkpoint, pending.checkpoint);
        assert!(fresh.source_exited && !fresh.candidate_may_exist);
        assert!(
            store
                .settle_telegram_polling_candidate_exited(&connector, &pending)
                .await
                .is_err(),
            "old child ownership cannot mutate a fresh attempt"
        );
        store
            .record_telegram_polling_stop_guarded(&connector, &fresh, || Ok(()))
            .await
            .unwrap();
        assert_eq!(
            store
                .connector_status(&connector)
                .await
                .unwrap()
                .observed_state,
            ObservedRuntimeState::Missing
        );
    }

    #[fcp_async_core::runtime::test]
    async fn uninstall_custody_with_retained_candidate_cannot_complete_restart() {
        let (_directory, store) = persistent_store().await;
        let connector = connector_id();
        let pending = candidate(&store).await;
        let revision = store
            .connector_status(&connector)
            .await
            .unwrap()
            .last_journal_sequence;
        store
            .deny_telegram_polling_stop(&connector, revision, Some(&pending), &uninstall_request())
            .await
            .unwrap();
        let preparation = store
            .prepare_telegram_polling_uninstall(&connector)
            .await
            .unwrap();
        let uninstall = store
            .begin_telegram_polling_uninstall(&connector, &preparation, binding())
            .await
            .unwrap();
        assert!(uninstall.source_exited && uninstall.candidate_may_exist);
        assert!(
            store
                .complete_telegram_polling_restart_guarded(&connector, &uninstall, || Ok(()))
                .await
                .is_err(),
            "complete process evidence cannot grant execution under uninstall intent"
        );
        assert!(
            store
                .record_telegram_polling_stop_guarded(&connector, &uninstall, || Ok(()))
                .await
                .is_err(),
            "unresolved candidate ownership cannot be reported Missing"
        );
        let exited = store
            .mark_telegram_polling_candidate_exited(&connector, &uninstall)
            .await
            .unwrap();
        store
            .record_telegram_polling_stop_guarded(&connector, &exited, || Ok(()))
            .await
            .unwrap();
        assert!(store.connector_execution_fence(&connector).await.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn stop_denial_receipt_allows_exit_settlement_but_rejects_new_authority() {
        for action in [LifecycleAction::Disable, LifecycleAction::Uninstall] {
            let (_directory, store) = persistent_store().await;
            let connector = connector_id();
            let pending = candidate(&store).await;
            let revision = store
                .connector_status(&connector)
                .await
                .unwrap()
                .last_journal_sequence;
            let mut request = uninstall_request();
            request.action = action;
            let denial = store
                .deny_telegram_polling_stop(&connector, revision, Some(&pending), &request)
                .await
                .unwrap();
            store
                .require_telegram_polling_stop_denial(&connector, pending.custody_id, &denial)
                .await
                .unwrap();
            store
                .settle_telegram_polling_candidate_exited(&connector, &pending)
                .await
                .unwrap();
            store
                .set_observed_state(&connector, ObservedRuntimeState::Degraded, None)
                .await
                .unwrap();
            let current = store
                .require_telegram_polling_stop_denial(&connector, pending.custody_id, &denial)
                .await
                .unwrap();
            assert!(current.last_journal_sequence > denial.journal_sequence);
            assert_eq!(current.desired_state, denial.current_desired_state);
            store
                .set_desired_state(
                    &ConnectorId::from_static("fcp.other"),
                    DesiredRuntimeState::Disabled,
                    None,
                )
                .await
                .unwrap();
            store
                .require_telegram_polling_stop_denial(&connector, pending.custody_id, &denial)
                .await
                .unwrap();

            let mut forged = denial.clone();
            forged.journal_sequence = current.last_journal_sequence;
            assert!(
                store
                    .require_telegram_polling_stop_denial(&connector, pending.custody_id, &forged)
                    .await
                    .is_err(),
                "an observed-state update cannot masquerade as a stop receipt"
            );
            store
                .set_desired_state(&connector, denial.current_desired_state, None)
                .await
                .unwrap();
            assert!(
                store
                    .require_telegram_polling_stop_denial(&connector, pending.custody_id, &denial)
                    .await
                    .is_err(),
                "even the same desired value is a newer operator decision"
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn interrupted_uninstall_preserves_unsettled_process_evidence_after_reopen() {
        let (directory, store) = persistent_store().await;
        let connector = connector_id();
        let previous = store.connector_status(&connector).await.unwrap();
        store
            .deny_telegram_polling_stop(
                &connector,
                previous.last_journal_sequence,
                None,
                &uninstall_request(),
            )
            .await
            .unwrap();
        let preparation = store
            .prepare_telegram_polling_uninstall(&connector)
            .await
            .unwrap();
        let custody = store
            .begin_telegram_polling_uninstall(&connector, &preparation, binding())
            .await
            .unwrap();
        let custody = store
            .record_telegram_polling_checkpoint(&connector, &custody, checkpoint())
            .await
            .unwrap();
        drop(store);

        let reopened =
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap();
        let record = reopened.connector_state(&connector).await.unwrap();
        assert_eq!(record.desired_state, DesiredRuntimeState::Uninstalled);
        assert_eq!(record.telegram_polling_restart.as_ref(), Some(&custody));
        assert!(!custody.source_exited && !custody.candidate_may_exist);
        assert!(
            reopened
                .record_telegram_polling_stop_guarded(&connector, &custody, || Ok(()))
                .await
                .is_err(),
            "a host restart cannot establish source process exit"
        );
        assert!(
            reopened
                .prepare_telegram_polling_restart(&connector)
                .await
                .is_err()
        );
        let preparation = reopened
            .prepare_telegram_polling_uninstall(&connector)
            .await
            .unwrap();
        let retry = reopened
            .begin_telegram_polling_uninstall(&connector, &preparation, binding())
            .await
            .unwrap();
        assert_eq!(retry.checkpoint, custody.checkpoint);
        assert!(!retry.source_exited && !retry.candidate_may_exist);
        assert!(
            reopened
                .connector_execution_fence(&connector)
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn custody_target_deserialization_preserves_old_disabled_records_and_rejects_unsafe_targets()
     {
        let (_directory, store) = persistent_store().await;
        let custody = begin(&store).await;
        let mut encoded = serde_json::to_value(&custody).unwrap();
        encoded.as_object_mut().unwrap().remove("desired_state");
        let decoded: TelegramPollingRestartCustody = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, custody);
        let snapshot = store.state.read().await.clone();
        for target in [
            DesiredRuntimeState::Enabled,
            DesiredRuntimeState::Unspecified,
        ] {
            let mut invalid_snapshot = snapshot.clone();
            invalid_snapshot
                .connectors
                .get_mut(&connector_id())
                .unwrap()
                .telegram_polling_restart
                .as_mut()
                .unwrap()
                .desired_state = target;
            assert!(validate_persisted_restarts(&invalid_snapshot).is_err());
        }
        let mut mismatched = snapshot;
        mismatched
            .connectors
            .get_mut(&connector_id())
            .unwrap()
            .telegram_polling_restart
            .as_mut()
            .unwrap()
            .desired_state = DesiredRuntimeState::Uninstalled;
        assert!(validate_persisted_restarts(&mismatched).is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn stop_denial_returns_its_own_revision_and_rejects_superseded_admission() {
        let (_directory, store) = persistent_store().await;
        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Disable,
            reason: None,
            initiated_by: Some("test-stop".to_owned()),
            dry_run: false,
        };
        let previous = store.connector_status(&connector_id()).await.unwrap();
        let denial = store
            .deny_telegram_polling_stop(
                &connector_id(),
                previous.last_journal_sequence,
                None,
                &request,
            )
            .await
            .unwrap();
        assert_eq!(denial.previous_desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(denial.current_desired_state, DesiredRuntimeState::Disabled);
        let preparation = store
            .prepare_telegram_polling_restart(&connector_id())
            .await
            .unwrap();
        assert_eq!(
            preparation.expected_journal_sequence,
            denial.journal_sequence
        );

        store
            .append_config_revision(
                &connector_id(),
                serde_json::json!({"poll_interval_ms": 25}),
                None,
                None,
            )
            .await
            .unwrap();
        let changed = store.connector_status(&connector_id()).await.unwrap();
        assert!(changed.last_journal_sequence > denial.journal_sequence);
        assert!(
            store
                .begin_telegram_polling_restart(&connector_id(), &preparation, binding())
                .await
                .is_err(),
            "a newer config cannot become part of an older stop admission"
        );
        assert!(
            store
                .deny_telegram_polling_stop(
                    &connector_id(),
                    denial.journal_sequence,
                    None,
                    &request,
                )
                .await
                .is_err()
        );

        let fresh = store
            .prepare_telegram_polling_restart(&connector_id())
            .await
            .unwrap();
        store
            .set_desired_state(&connector_id(), DesiredRuntimeState::Uninstalled, None)
            .await
            .unwrap();
        assert!(
            store
                .deny_telegram_polling_stop(
                    &connector_id(),
                    fresh.expected_journal_sequence,
                    None,
                    &request,
                )
                .await
                .is_err(),
            "a stale Disable cannot replace a newer Uninstall"
        );
        let final_state = store.connector_state(&connector_id()).await.unwrap();
        assert_eq!(final_state.desired_state, DesiredRuntimeState::Uninstalled);
        assert!(final_state.telegram_polling_restart.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn early_stop_denial_follows_phase_progress_but_not_new_intent() {
        for source_exited in [false, true] {
            let (_directory, store) = persistent_store().await;
            let expected = begin(&store).await;
            let expected_sequence = store
                .connector_state(&connector_id())
                .await
                .unwrap()
                .last_journal_sequence;
            let progressed = store
                .record_telegram_polling_checkpoint(&connector_id(), &expected, checkpoint())
                .await
                .unwrap();
            if source_exited {
                store
                    .mark_telegram_polling_source_exited(&connector_id(), &progressed)
                    .await
                    .unwrap();
            }
            let request = LifecycleTransitionRequest {
                action: LifecycleAction::Disable,
                reason: None,
                initiated_by: None,
                dry_run: false,
            };
            let denial = store
                .deny_telegram_polling_stop(
                    &connector_id(),
                    expected_sequence,
                    Some(&expected),
                    &request,
                )
                .await
                .unwrap();
            let denied = store.connector_state(&connector_id()).await.unwrap();
            assert_eq!(denied.last_journal_sequence, denial.journal_sequence);
            assert_eq!(denied.desired_state, DesiredRuntimeState::Disabled);
            let custody = denied.telegram_polling_restart.unwrap();
            assert_eq!(custody.custody_id, expected.custody_id);
            assert_eq!(custody.checkpoint, Some(checkpoint()));
            assert_eq!(custody.source_exited, source_exited);
            assert!(custody.intent_revoked);
        }

        for rotate_custody in [false, true] {
            let (_directory, store) = persistent_store().await;
            let expected = begin(&store).await;
            let expected_sequence = store
                .connector_state(&connector_id())
                .await
                .unwrap()
                .last_journal_sequence;
            if rotate_custody {
                let next = begin(&store).await;
                assert_ne!(next.custody_id, expected.custody_id);
            } else {
                store
                    .append_config_revision(
                        &connector_id(),
                        serde_json::json!({"poll_interval_ms": 25}),
                        None,
                        None,
                    )
                    .await
                    .unwrap();
            }
            let current = store.connector_state(&connector_id()).await.unwrap();
            let request = LifecycleTransitionRequest {
                action: LifecycleAction::Disable,
                reason: None,
                initiated_by: None,
                dry_run: false,
            };
            assert!(
                store
                    .deny_telegram_polling_stop(
                        &connector_id(),
                        expected_sequence,
                        Some(&expected),
                        &request,
                    )
                    .await
                    .is_err(),
                "normal phase progress must not hide a new config or restart intent"
            );
            let unchanged = store.connector_state(&connector_id()).await.unwrap();
            assert_eq!(
                unchanged.last_journal_sequence,
                current.last_journal_sequence
            );
            assert_eq!(
                unchanged.telegram_polling_restart,
                current.telegram_polling_restart
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn checkpointed_stop_requires_exit_and_preserves_custody_across_reopen() {
        let (directory, store) = persistent_store().await;
        let custody = begin(&store).await;
        assert!(
            store
                .record_telegram_polling_stop_guarded(&connector_id(), &custody, || Ok(()))
                .await
                .is_err(),
            "a stop needs a committed checkpoint"
        );
        let custody = store
            .record_telegram_polling_checkpoint(&connector_id(), &custody, checkpoint())
            .await
            .unwrap();
        assert!(
            store
                .record_telegram_polling_stop_guarded(&connector_id(), &custody, || Ok(()))
                .await
                .is_err()
        );
        let custody = store
            .mark_telegram_polling_source_exited(&connector_id(), &custody)
            .await
            .unwrap();
        let before = store.connector_state(&connector_id()).await.unwrap();
        assert!(
            store
                .record_telegram_polling_stop_guarded(&connector_id(), &custody, || {
                    Err(invalid("dormant runtime was not published"))
                })
                .await
                .is_err()
        );
        let unchanged = store.connector_state(&connector_id()).await.unwrap();
        assert_eq!(
            unchanged.last_journal_sequence,
            before.last_journal_sequence
        );
        assert_eq!(unchanged.telegram_polling_restart, Some(custody.clone()));
        let sequence = store
            .record_telegram_polling_stop_guarded(&connector_id(), &custody, || Ok(()))
            .await
            .unwrap();
        assert!(sequence > before.last_journal_sequence);

        let reopened =
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap();
        let stopped = reopened.connector_state(&connector_id()).await.unwrap();
        assert_eq!(stopped.desired_state, DesiredRuntimeState::Disabled);
        assert_eq!(stopped.observed_state, ObservedRuntimeState::Stopped);
        assert_eq!(stopped.telegram_polling_restart, Some(custody.clone()));
        reopened
            .require_telegram_polling_restart(&connector_id(), &custody)
            .await
            .unwrap();
        assert!(
            reopened
                .connector_execution_fence(&connector_id())
                .await
                .is_err()
        );
        assert!(
            reopened
                .set_desired_state(&connector_id(), DesiredRuntimeState::Enabled, None)
                .await
                .is_err(),
            "Enable cannot bypass the retained restore boundary"
        );
        let preparation = reopened
            .prepare_telegram_polling_restart(&connector_id())
            .await
            .unwrap();
        let resumed = reopened
            .begin_telegram_polling_restart(&connector_id(), &preparation, binding())
            .await
            .unwrap();
        assert_eq!(resumed.checkpoint, Some(checkpoint()));
        assert!(resumed.source_exited && !resumed.candidate_may_exist);
    }

    #[fcp_async_core::runtime::test]
    async fn checkpointed_stop_rejects_unresolved_replacement_and_revoked_intent() {
        let (_directory, store) = persistent_store().await;
        let custody = candidate(&store).await;
        let before = store.connector_state(&connector_id()).await.unwrap();
        assert!(
            store
                .record_telegram_polling_stop_guarded(&connector_id(), &custody, || Ok(()))
                .await
                .is_err()
        );
        assert_eq!(
            store
                .connector_state(&connector_id())
                .await
                .unwrap()
                .last_journal_sequence,
            before.last_journal_sequence
        );
        let custody = store
            .mark_telegram_polling_candidate_exited(&connector_id(), &custody)
            .await
            .unwrap();
        store
            .set_desired_state(&connector_id(), DesiredRuntimeState::Disabled, None)
            .await
            .unwrap();
        assert!(
            store
                .record_telegram_polling_stop_guarded(&connector_id(), &custody, || Ok(()))
                .await
                .is_err(),
            "a newer Disable invalidates the old stop attempt"
        );
        let revoked = store
            .connector_state(&connector_id())
            .await
            .unwrap()
            .telegram_polling_restart
            .unwrap();
        assert!(revoked.intent_revoked);
        assert!(
            store
                .record_telegram_polling_stop_guarded(&connector_id(), &revoked, || Ok(()))
                .await
                .is_err(),
            "current but revoked custody does not authorize finalization"
        );
    }

    #[test]
    fn native_checkpoint_schema_identity_digest_and_bounds_are_enforced() {
        let original = checkpoint();
        assert_eq!(
            original.checkpoint_id,
            "sha256:a0eed791222be2d510844d5eefdb2e29258d9125b477f528462694136025cc42",
        );
        let value = serde_json::to_value(&original).unwrap();
        assert_eq!(
            HostTelegramPollingCheckpoint::from_value(value.clone(), &binding()).unwrap(),
            original,
        );
        assert_eq!(
            serde_json::to_string(&original.state).unwrap(),
            r#"{"version":1,"connector_id":"fcp.telegram","zone_id":"z:work","bot_id":"123456","offset":2003,"last_poll_count":3,"updated_at":1700000000}"#,
        );
        for field in [
            "version",
            "connector_id",
            "zone_id",
            "bot_id",
            "offset",
            "last_poll_count",
        ] {
            let mut invalid = value.clone();
            invalid["state"][field] = match field {
                "version" => serde_json::json!(2),
                "connector_id" => serde_json::json!("fcp.other"),
                "zone_id" => serde_json::json!("z:other"),
                "bot_id" => serde_json::json!("987654"),
                "offset" => serde_json::json!(-1),
                _ => serde_json::json!(101),
            };
            assert!(HostTelegramPollingCheckpoint::from_value(invalid, &binding()).is_err());
        }
        let mut corrupt = original.clone();
        corrupt.state.offset = Some(2004);
        assert!(corrupt.validate(&binding()).is_err());
        let mut unknown = value.clone();
        unknown["state"]["path"] = serde_json::json!("/untrusted");
        assert!(HostTelegramPollingCheckpoint::from_value(unknown, &binding()).is_err());
        let mut oversized = value;
        oversized["padding"] = serde_json::json!("x".repeat(TELEGRAM_POLLING_CHECKPOINT_MAX_BYTES));
        assert!(HostTelegramPollingCheckpoint::from_value(oversized, &binding()).is_err());
        let mut changed_binding = binding();
        changed_binding.bot_id = "654321".to_owned();
        assert!(original.validate(&changed_binding).is_err());
        changed_binding = binding();
        changed_binding.state_root = "relative/path".to_owned();
        assert!(changed_binding.validate().is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn checkpoint_custody_survives_reopen_and_requires_every_ownership_phase() {
        let (directory, store) = persistent_store().await;
        let old_fence = store
            .connector_execution_fence(&connector_id())
            .await
            .unwrap();
        let custody = begin(&store).await;
        let pending = store
            .connector_status(&connector_id())
            .await
            .unwrap()
            .telegram_polling_restart
            .unwrap();
        assert_eq!(pending.custody_id, custody.custody_id);
        assert!(pending.checkpoint_id.is_none());
        assert!(!pending.source_exited && !pending.candidate_may_exist && !pending.intent_revoked);
        assert!(old_fence.require_current().is_err());
        assert!(
            store
                .complete_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        assert!(
            store
                .mark_telegram_polling_source_exited(&connector_id(), &custody)
                .await
                .is_err()
        );
        let custody = store
            .record_telegram_polling_checkpoint(&connector_id(), &custody, checkpoint())
            .await
            .unwrap();
        let checkpointed_status = store.connector_status(&connector_id()).await.unwrap();
        assert_eq!(
            serde_json::to_value(&checkpointed_status).unwrap()["telegram_polling_restart"],
            serde_json::json!({
                "custody_id": custody.custody_id,
                "checkpoint_id": checkpoint().checkpoint_id,
                "source_exited": false,
                "candidate_may_exist": false,
                "intent_revoked": false,
            }),
            "status must expose only restart evidence, without binding or cursor payloads",
        );
        assert!(
            store
                .mark_telegram_polling_candidate_starting(&connector_id(), &custody)
                .await
                .is_err()
        );
        assert!(
            store
                .complete_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        drop(store);
        let store =
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap();
        assert_eq!(
            store
                .connector_state(&connector_id())
                .await
                .unwrap()
                .telegram_polling_restart,
            Some(custody.clone())
        );
        assert!(
            store
                .connector_execution_fence(&connector_id())
                .await
                .is_err()
        );
        let custody = store
            .mark_telegram_polling_source_exited(&connector_id(), &custody)
            .await
            .unwrap();
        assert!(
            store
                .complete_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        let custody = store
            .mark_telegram_polling_candidate_starting(&connector_id(), &custody)
            .await
            .unwrap();
        let pending = store
            .connector_status(&connector_id())
            .await
            .unwrap()
            .telegram_polling_restart
            .unwrap();
        assert_eq!(pending.custody_id, custody.custody_id);
        assert_eq!(pending.checkpoint_id, Some(checkpoint().checkpoint_id));
        assert!(pending.source_exited && pending.candidate_may_exist && !pending.intent_revoked);
        assert!(
            store
                .mark_telegram_polling_candidate_starting(&connector_id(), &custody)
                .await
                .is_err()
        );
        drop(store);
        let store =
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap();
        assert_eq!(
            store
                .connector_status(&connector_id())
                .await
                .unwrap()
                .telegram_polling_restart,
            Some(pending),
            "status must preserve process evidence after reopening durable custody",
        );
        let preparation = store
            .prepare_telegram_polling_restart(&connector_id())
            .await
            .unwrap();
        let replacement = store
            .begin_telegram_polling_restart(&connector_id(), &preparation, binding())
            .await
            .unwrap();
        assert!(replacement.custody_id > custody.custody_id);
        assert!(
            replacement.candidate_may_exist,
            "reopening does not invent exact-child exit"
        );
        assert!(
            store
                .require_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        let retired = store
            .mark_telegram_polling_candidate_exited(&connector_id(), &replacement)
            .await
            .unwrap();
        assert!(!retired.candidate_may_exist);
        assert_eq!(retired.checkpoint, Some(checkpoint()));
        let ready = store
            .mark_telegram_polling_candidate_starting(&connector_id(), &retired)
            .await
            .unwrap();
        store
            .complete_telegram_polling_restart(&connector_id(), &ready)
            .await
            .unwrap();
        let completed_status = store.connector_status(&connector_id()).await.unwrap();
        assert!(completed_status.telegram_polling_restart.is_none());
        assert!(
            serde_json::to_value(&completed_status)
                .unwrap()
                .get("telegram_polling_restart")
                .is_none()
        );
        assert!(
            store
                .connector_state(&connector_id())
                .await
                .unwrap()
                .telegram_polling_restart
                .is_none()
        );
        store
            .connector_execution_fence(&connector_id())
            .await
            .unwrap()
            .require_current()
            .unwrap();
        assert!(old_fence.require_current().is_err());
        drop(store);
        let reopened =
            HostAdminStateStore::with_state_path(directory.path().join("admin.json")).unwrap();
        assert!(
            reopened
                .connector_status(&connector_id())
                .await
                .unwrap()
                .telegram_polling_restart
                .is_none()
        );
        reopened
            .connector_execution_fence(&connector_id())
            .await
            .unwrap()
            .require_current()
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn repeated_disable_fences_preparation_and_every_prior_attempt() {
        let (_directory, store) = persistent_store().await;
        let preparation = store
            .prepare_telegram_polling_restart(&connector_id())
            .await
            .unwrap();
        store
            .set_desired_state(&connector_id(), DesiredRuntimeState::Disabled, None)
            .await
            .unwrap();
        assert!(
            store
                .begin_telegram_polling_restart(&connector_id(), &preparation, binding())
                .await
                .is_err()
        );

        let custody = candidate(&store).await;
        let preparation = store
            .prepare_telegram_polling_restart(&connector_id())
            .await
            .unwrap();
        store
            .set_desired_state(&connector_id(), DesiredRuntimeState::Disabled, None)
            .await
            .unwrap();
        assert!(
            store
                .begin_telegram_polling_restart(&connector_id(), &preparation, binding())
                .await
                .is_err()
        );
        assert!(
            store
                .require_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        assert!(
            store
                .complete_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        let revoked = store
            .connector_state(&connector_id())
            .await
            .unwrap()
            .telegram_polling_restart
            .unwrap();
        assert!(revoked.intent_revoked);
        assert!(
            store
                .connector_status(&connector_id())
                .await
                .unwrap()
                .telegram_polling_restart
                .unwrap()
                .intent_revoked
        );
        assert_eq!(revoked.checkpoint, custody.checkpoint);

        let fresh = begin(&store).await;
        assert!(!fresh.intent_revoked);
        assert!(fresh.custody_id > custody.custody_id);
        assert!(fresh.source_exited && fresh.candidate_may_exist);
        assert_eq!(fresh.checkpoint, custody.checkpoint);
        assert!(
            store
                .complete_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        assert!(
            store
                .set_desired_state(&connector_id(), DesiredRuntimeState::Enabled, None)
                .await
                .is_err()
        );
        store
            .require_telegram_polling_restart(&connector_id(), &fresh)
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn configuration_aba_revokes_attempt_but_observations_do_not() {
        let (_directory, store) = persistent_store().await;
        let custody = candidate(&store).await;
        store
            .set_observed_state(&connector_id(), ObservedRuntimeState::Stopped, None)
            .await
            .unwrap();
        store
            .set_desired_state(
                &ConnectorId::from_static("fcp.other"),
                DesiredRuntimeState::Disabled,
                None,
            )
            .await
            .unwrap();
        store
            .require_telegram_polling_restart(&connector_id(), &custody)
            .await
            .unwrap();
        for value in ["first", "other", "first"] {
            store
                .append_config_revision(
                    &connector_id(),
                    serde_json::json!({"credential_id": value}),
                    None,
                    None,
                )
                .await
                .unwrap();
        }
        assert!(
            store
                .require_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        assert!(
            store
                .complete_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        let preserved = store
            .connector_state(&connector_id())
            .await
            .unwrap()
            .telegram_polling_restart
            .unwrap();
        assert!(preserved.intent_revoked);
        assert_eq!(preserved.checkpoint, custody.checkpoint);
        assert!(preserved.source_exited && preserved.candidate_may_exist);
    }

    #[fcp_async_core::runtime::test]
    async fn pending_marker_denies_dispatch_independently_and_uninstall_cannot_resume() {
        let (_directory, store) = persistent_store().await;
        let custody = checkpointed(&store).await;
        // Exercise defense in depth against a legacy path changing only desired state.
        store
            .apply_mutation(|snapshot| {
                snapshot.connector_state_mut(&connector_id()).desired_state =
                    DesiredRuntimeState::Enabled;
                Ok(())
            })
            .await
            .unwrap();
        assert!(
            store
                .connector_execution_fence(&connector_id())
                .await
                .is_err()
        );
        assert!(
            store
                .complete_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        store
            .set_desired_state(&connector_id(), DesiredRuntimeState::Uninstalled, None)
            .await
            .unwrap();
        assert!(
            store
                .prepare_telegram_polling_restart(&connector_id())
                .await
                .is_err()
        );
        assert!(
            store
                .set_desired_state(&connector_id(), DesiredRuntimeState::Enabled, None)
                .await
                .is_err()
        );
        let pending = store
            .connector_state(&connector_id())
            .await
            .unwrap()
            .telegram_polling_restart
            .unwrap();
        assert!(pending.intent_revoked);
        assert_eq!(pending.checkpoint, custody.checkpoint);
    }

    #[fcp_async_core::runtime::test]
    async fn deployment_and_checkpoint_replacement_are_refused_without_losing_custody() {
        let (_directory, store) = persistent_store().await;
        let custody = checkpointed(&store).await;
        let preparation = store
            .prepare_telegram_polling_restart(&connector_id())
            .await
            .unwrap();
        let mut changed = binding();
        changed.config_digest = "44".repeat(32);
        assert!(
            store
                .begin_telegram_polling_restart(&connector_id(), &preparation, changed)
                .await
                .is_err()
        );
        let mut different = checkpoint();
        different.state.offset = Some(2004);
        different.checkpoint_id = different.content_id().unwrap();
        assert!(
            store
                .record_telegram_polling_checkpoint(&connector_id(), &custody, different)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .connector_state(&connector_id())
                .await
                .unwrap()
                .telegram_polling_restart,
            Some(custody)
        );
    }

    #[fcp_async_core::runtime::test]
    async fn missing_or_failed_durability_never_clears_custody_or_enables_dispatch() {
        assert!(
            HostAdminStateStore::new()
                .prepare_telegram_polling_restart(&connector_id())
                .await
                .is_err()
        );
        let (directory, mut store) = persistent_store().await;
        let custody = candidate(&store).await;
        let durable_path = directory.path().join("admin.json");
        let obstruction = directory.path().join("not-a-directory");
        std::fs::write(&obstruction, b"cannot create a snapshot below a file").unwrap();
        store.state_path = Some(obstruction.join("admin.json"));
        assert!(
            store
                .complete_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .connector_state(&connector_id())
                .await
                .unwrap()
                .telegram_polling_restart,
            Some(custody.clone())
        );
        assert!(
            store
                .connector_execution_fence(&connector_id())
                .await
                .is_err()
        );
        assert!(
            store
                .require_telegram_polling_restart(&connector_id(), &custody)
                .await
                .is_err()
        );
        let reopened = HostAdminStateStore::with_state_path(durable_path).unwrap();
        assert_eq!(
            reopened
                .connector_state(&connector_id())
                .await
                .unwrap()
                .telegram_polling_restart,
            Some(custody)
        );
        assert!(
            reopened
                .connector_execution_fence(&connector_id())
                .await
                .is_err()
        );
    }

    #[fcp_async_core::runtime::test]
    async fn corrupt_checkpoint_or_impossible_ownership_fails_closed_after_reopen() {
        let (directory, store) = persistent_store().await;
        checkpointed(&store).await;
        let path = directory.path().join("admin.json");
        let original = std::fs::read(&path).unwrap();
        drop(store);
        for corrupt in ["offset", "ownership", "enabled"] {
            let mut snapshot: Value = serde_json::from_slice(&original).unwrap();
            let state = &mut snapshot["connectors"][CONNECTOR];
            match corrupt {
                "offset" => {
                    state["telegram_polling_restart"]["checkpoint"]["state"]["offset"] =
                        serde_json::json!(9999)
                }
                "ownership" => {
                    state["telegram_polling_restart"]["candidate_may_exist"] =
                        serde_json::json!(true)
                }
                "enabled" => state["desired_state"] = serde_json::json!("enabled"),
                _ => unreachable!(),
            }
            std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
            assert!(
                HostAdminStateStore::with_state_path(path.clone()).is_err(),
                "{corrupt}"
            );
        }
    }
    #[fcp_async_core::runtime::test]
    async fn final_inventory_guard_failure_preserves_checkpoint_and_execution_denial() {
        let (_directory, store) = persistent_store().await;
        let custody = candidate(&store).await;
        let before = store
            .connector_state(&connector_id())
            .await
            .unwrap()
            .last_journal_sequence;
        let invoked = AtomicBool::new(false);
        let result = store
            .complete_telegram_polling_restart_guarded(&connector_id(), &custody, || {
                invoked.store(true, Ordering::Release);
                Err(invalid("inventory changed while awaiting admin-state lock"))
            })
            .await;
        assert!(invoked.load(Ordering::Acquire));
        assert!(result.is_err());
        let after = store.connector_state(&connector_id()).await.unwrap();
        assert_eq!(after.last_journal_sequence, before);
        assert_eq!(after.telegram_polling_restart, Some(custody));
        assert_eq!(after.desired_state, DesiredRuntimeState::Disabled);
        assert!(
            store
                .connector_execution_fence(&connector_id())
                .await
                .is_err()
        );
    }
}
